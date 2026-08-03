//! Deadlines for the supervision loop: when a phase has run too long,
//! when a backoff has elapsed, and how long the loop may sleep.
//!
//! Split out from the loop itself because it is the part that can be
//! tested. The loop's I/O — polling a pidfd, draining a batch, writing
//! a ping — needs a live VPP; deciding *when* those should happen is
//! arithmetic over an injected clock, exactly like [`crate::supervisor`]
//! and [`crate::liveness`].
//!
//! **Every field here is paired with the one observation allowed to
//! change it.** That rule is not stylistic: the recurring defect in
//! this subsystem has been state recorded at the moment an effect was
//! *requested* rather than when it was *observed* — steering cleared on
//! emitting `Unsteer`, convergence cleared on a partial failure,
//! termination assumed on issuing `Kill`. A loop is nothing but
//! requests whose completion arrives later, so anything without an
//! observer does not get a field.
//!
//! | Field | Observer |
//! |---|---|
//! | `phase_deadline` | a supervisor state change, via [`Schedule::arm_phase`] |
//! | `backoff_until` | `Action::ArmBackoff`, via [`Schedule::arm_backoff`] |
//!
//! The ping deadline deliberately is NOT a field here — it belongs to
//! [`crate::liveness::WedgeDetector`], whose observation is a pong.
//! Duplicating it would create two answers to one question.

use std::time::{Duration, Instant};

use crate::supervisor::{Event, PhaseKind};

/// Armed deadlines for the current supervisor state.
#[derive(Debug, Default, Clone)]
pub struct Schedule {
    /// When the current phase stops being merely slow and becomes hung.
    ///
    /// Armed from `Supervisor::phase()` on every state change; a state
    /// with no budget (`Ready`, `Steered`, `Stopped`) disarms it.
    phase_deadline: Option<Instant>,
    /// Which phase `phase_deadline` belongs to, so transitions *within*
    /// a phase keep one deadline instead of restarting the clock.
    phase_kind: Option<PhaseKind>,
    /// When the restart backoff expires.
    ///
    /// Survives elapsing: see [`Schedule::fired`]. Cleared only when the
    /// restart it authorises is actually permitted and reported — the
    /// observer is "the retry may proceed", not "time passed".
    backoff_until: Option<Instant>,
}

impl Schedule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-arm the phase deadline for a (possibly new) state.
    ///
    /// Call on **every** transition, passing `Supervisor::phase()` —
    /// including when it returns `None`, which disarms. Arming only on
    /// entry to a timed state would leave a stale deadline behind after
    /// leaving one, and it would fire against a state it does not
    /// describe.
    ///
    /// A transition *within* the same [`PhaseKind`] keeps the existing
    /// deadline. `CONVERGENCE_BUDGET` bounds a resync **plus** verify, so
    /// `Syncing → Verifying` must not restart it: doing so would let the
    /// resync spend nearly the whole budget and then hand verification a
    /// fresh one, making the effective bound twice the documented number.
    pub fn arm_phase(&mut self, now: Instant, phase: Option<(PhaseKind, Duration)>) {
        match phase {
            None => {
                self.phase_deadline = None;
                self.phase_kind = None;
            }
            Some((kind, budget)) => {
                let continuing = self.phase_kind == Some(kind) && self.phase_deadline.is_some();
                if !continuing {
                    self.phase_deadline = Some(now + budget);
                    self.phase_kind = Some(kind);
                }
            }
        }
    }

    /// Arm the restart backoff, from `Action::ArmBackoff`.
    ///
    /// Also disarms the phase deadline: the backoff states have no phase
    /// budget, so a surviving deadline could only fire a `PhaseTimedOut`
    /// describing a phase we already left. The supervisor would ignore
    /// it, but an event that means nothing is still noise in a log
    /// somebody reads during an outage.
    pub fn arm_backoff(&mut self, now: Instant, delay: Duration) {
        self.backoff_until = Some(now + delay);
        self.phase_deadline = None;
        self.phase_kind = None;
    }

    /// Clear everything. For a clean stop, where no deadline applies.
    pub fn disarm(&mut self) {
        self.phase_deadline = None;
        self.phase_kind = None;
        self.backoff_until = None;
    }

    pub fn phase_deadline(&self) -> Option<Instant> {
        self.phase_deadline
    }

    pub fn backoff_until(&self) -> Option<Instant> {
        self.backoff_until
    }

    /// Events whose deadlines have elapsed by `now`.
    ///
    /// `may_restart` is `Supervisor::may_restart()`. It gates the backoff
    /// because **an elapsed backoff must survive being un-actionable.**
    /// A restart can be forbidden when the deadline expires — an aborted
    /// convergence still unwinding, or a killed process that has not
    /// died — and the supervisor deliberately has no other retry
    /// trigger. Reporting `BackoffElapsed` for the caller to discard
    /// would consume the only one and strand the supervisor in `Backoff`
    /// forever. So the deadline stays armed until the retry is actually
    /// permitted, and fires on the first tick after
    /// `ConvergenceStopped` or `ProcessExited` clears the block.
    ///
    /// The phase deadline is unconditional, so it is consumed on firing.
    /// Both are consumed exactly once: left armed, they would re-emit
    /// every tick, and since both route through the supervisor's failure
    /// path that is a teardown-restart spin rather than one recovery.
    pub fn fired(&mut self, now: Instant, may_restart: bool) -> Vec<Event> {
        let mut out = Vec::new();
        if let Some(d) = self.phase_deadline {
            if now >= d {
                self.phase_deadline = None;
                self.phase_kind = None;
                out.push(Event::PhaseTimedOut);
            }
        }
        if let Some(d) = self.backoff_until {
            if now >= d && may_restart {
                self.backoff_until = None;
                out.push(Event::BackoffElapsed);
            }
        }
        out
    }

    /// How long the loop may sleep before something needs attention.
    ///
    /// `None` = nothing needs a timer, so the loop may block on its fds
    /// indefinitely. `Some(ZERO)` = something is already due, so tick
    /// again immediately — not a busy loop, because [`Self::fired`]
    /// consumes what it reports.
    ///
    /// An **elapsed but blocked** backoff is excluded, and that is the
    /// subtle half: it stays armed by design, so counting it would ask
    /// for an immediate tick on every pass and spin a core until the
    /// block cleared. What unblocks it is an event on an fd, not the
    /// passage of time, so there is nothing to wake up *for*.
    ///
    /// `ping_due_at` comes from
    /// [`crate::liveness::WedgeDetector::next_ping_at`] and is passed in
    /// rather than stored, so there is exactly one owner of that
    /// deadline.
    pub fn next_wakeup(
        &self,
        now: Instant,
        ping_due_at: Option<Instant>,
        may_restart: bool,
    ) -> Option<Duration> {
        let backoff = self.backoff_until.filter(|d| *d > now || may_restart);
        [self.phase_deadline, backoff, ping_due_at]
            .into_iter()
            .flatten()
            .map(|d| d.saturating_duration_since(now))
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::{API_STARTUP_BUDGET, CONVERGENCE_BUDGET};

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    // ---- Firing, and firing once ----

    /// The invariant that keeps a single timeout from becoming a loop.
    /// Both events route through the supervisor's failure path, so a
    /// deadline that re-fires every tick is a teardown-restart spin.
    #[test]
    fn a_deadline_fires_exactly_once() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some((PhaseKind::Convergence, Duration::from_secs(10))));

        assert!(s.fired(at(t0, 9_999), true).is_empty(), "not yet");
        assert_eq!(s.fired(at(t0, 10_000), true), vec![Event::PhaseTimedOut]);
        assert!(
            s.fired(at(t0, 10_001), true).is_empty(),
            "a fired deadline must be consumed"
        );
        assert!(s.fired(at(t0, 60_000), true).is_empty());
    }

    #[test]
    fn backoff_fires_once_too() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_backoff(t0, Duration::from_millis(250));

        assert!(s.fired(at(t0, 249), true).is_empty());
        assert_eq!(s.fired(at(t0, 250), true), vec![Event::BackoffElapsed]);
        assert!(s.fired(at(t0, 500), true).is_empty());
    }

    /// Re-arming on every transition is what stops a deadline from
    /// outliving the phase it describes.
    #[test]
    fn a_state_with_no_budget_disarms_the_phase_deadline() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some((PhaseKind::Startup, API_STARTUP_BUDGET)));
        assert!(s.phase_deadline().is_some());

        // Ready/Steered/Stopped report no budget.
        s.arm_phase(at(t0, 100), None);
        assert!(s.phase_deadline().is_none());
        assert!(s.fired(at(t0, 999_999), true).is_empty());
    }

    /// Moving between timed phases restarts the clock rather than
    /// carrying the previous phase's remaining time.
    #[test]
    fn re_arming_replaces_rather_than_keeps_the_earlier_deadline() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some((PhaseKind::Startup, API_STARTUP_BUDGET)));

        // 59 s later the API comes up; the convergence budget starts now.
        let t1 = at(t0, 59_000);
        s.arm_phase(t1, Some((PhaseKind::Convergence, CONVERGENCE_BUDGET)));
        assert!(
            s.fired(at(t0, 60_001), true).is_empty(),
            "the startup budget must not still fire after the phase changed"
        );
        assert_eq!(s.phase_deadline(), Some(t1 + CONVERGENCE_BUDGET));
    }

    /// Entering backoff drops the phase deadline: it could only fire an
    /// event describing a phase already left.
    #[test]
    fn arming_backoff_drops_a_stale_phase_deadline() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some((PhaseKind::Convergence, Duration::from_secs(1))));
        s.arm_backoff(t0, Duration::from_secs(30));

        assert!(s.phase_deadline().is_none());
        assert!(
            !s.fired(at(t0, 2_000), true).contains(&Event::PhaseTimedOut),
            "no event for a phase we are no longer in"
        );
    }

    #[test]
    fn disarm_clears_everything() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some((PhaseKind::Convergence, Duration::from_secs(1))));
        s.arm_backoff(t0, Duration::from_secs(1));
        s.disarm();
        assert!(s.fired(at(t0, 10_000), true).is_empty());
        assert_eq!(s.next_wakeup(t0, None, true), None);
    }

    // ---- An elapsed backoff must survive being un-actionable ----

    /// The supervisor has exactly one retry trigger. If the backoff
    /// elapses while a restart is forbidden — an aborted convergence
    /// still unwinding, or a killed process that has not died —
    /// reporting it for the caller to discard would consume that
    /// trigger and strand the supervisor in `Backoff` forever.
    #[test]
    fn an_elapsed_backoff_is_withheld_not_consumed_while_blocked() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_backoff(t0, Duration::from_millis(250));

        // Elapsed, but a restart is not permitted yet.
        assert!(
            s.fired(at(t0, 300), false).is_empty(),
            "must not report a retry that cannot be taken"
        );
        assert!(
            s.backoff_until().is_some(),
            "and must not lose it either — this is the only trigger"
        );
        // Still blocked several ticks later.
        assert!(s.fired(at(t0, 5_000), false).is_empty());
        assert!(s.backoff_until().is_some());

        // ConvergenceStopped / ProcessExited unblocks it; now it fires.
        assert_eq!(s.fired(at(t0, 5_001), true), vec![Event::BackoffElapsed]);
        assert!(s.backoff_until().is_none(), "consumed once taken");
        assert!(s.fired(at(t0, 6_000), true).is_empty());
    }

    /// The other half: a withheld backoff must not ask for an immediate
    /// tick on every pass. What unblocks it arrives on an fd, not from
    /// the clock, so there is nothing to wake up for — and asking would
    /// spin a core until the block cleared.
    #[test]
    fn a_withheld_backoff_does_not_request_a_busy_tick() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_backoff(t0, Duration::from_millis(250));
        let late = at(t0, 5_000);

        assert!(s.fired(late, false).is_empty());
        assert_eq!(
            s.next_wakeup(late, None, false),
            None,
            "blocked: sleep on the fds instead of spinning"
        );
        // Once permitted, it is due immediately.
        assert_eq!(
            s.next_wakeup(late, None, true),
            Some(Duration::ZERO),
            "unblocked: tick now"
        );
    }

    /// A backoff still in the future is scheduled normally whether or
    /// not a restart is currently permitted — by the time it elapses the
    /// block may well be gone.
    #[test]
    fn a_future_backoff_is_scheduled_regardless_of_the_block() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_backoff(t0, Duration::from_secs(30));
        assert_eq!(
            s.next_wakeup(t0, None, false),
            Some(Duration::from_secs(30))
        );
    }

    // ---- One budget across the convergence cycle ----

    /// `CONVERGENCE_BUDGET` bounds a resync PLUS verify. Re-arming on
    /// the `Syncing → Verifying` transition would let the resync spend
    /// nearly all of it and hand verification a fresh one, making the
    /// real bound twice the documented number.
    #[test]
    fn moving_between_convergence_substates_keeps_one_deadline() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some((PhaseKind::Convergence, CONVERGENCE_BUDGET)));
        let armed = s.phase_deadline().expect("armed");

        // 119 s of resync, then SyncComplete → Verifying, same kind.
        let t1 = at(t0, 119_000);
        s.arm_phase(t1, Some((PhaseKind::Convergence, CONVERGENCE_BUDGET)));
        assert_eq!(
            s.phase_deadline(),
            Some(armed),
            "the cycle's deadline must not restart for the verify"
        );
        assert_eq!(
            s.fired(at(t0, 120_001), true),
            vec![Event::PhaseTimedOut],
            "the whole cycle is bounded, not each substate"
        );
    }

    /// But entering convergence from startup DOES start a fresh clock —
    /// they are different phases with different budgets.
    #[test]
    fn entering_convergence_from_startup_restarts_the_clock() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some((PhaseKind::Startup, API_STARTUP_BUDGET)));
        let t1 = at(t0, 30_000);
        s.arm_phase(t1, Some((PhaseKind::Convergence, CONVERGENCE_BUDGET)));
        assert_eq!(s.phase_deadline(), Some(t1 + CONVERGENCE_BUDGET));
    }

    /// And a cycle that ended and began again gets a fresh deadline,
    /// rather than inheriting the previous attempt's remaining time.
    #[test]
    fn a_new_convergence_after_a_gap_starts_fresh() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some((PhaseKind::Convergence, CONVERGENCE_BUDGET)));
        // Failure → Backoff (no phase), then a new attempt.
        s.arm_phase(at(t0, 10_000), None);
        let t2 = at(t0, 20_000);
        s.arm_phase(t2, Some((PhaseKind::Convergence, CONVERGENCE_BUDGET)));
        assert_eq!(s.phase_deadline(), Some(t2 + CONVERGENCE_BUDGET));
    }

    /// The supervisor is the source of the grouping, so check the real
    /// states agree rather than only the enum.
    #[test]
    fn the_supervisors_convergence_states_share_a_kind() {
        use crate::supervisor::{Event as E, Supervisor};
        let mut sup = Supervisor::new();
        sup.on(E::StartRequested);
        assert_eq!(sup.phase().map(|(k, _)| k), Some(PhaseKind::Startup));
        sup.on(E::ApiUp);
        let syncing = sup.phase();
        assert_eq!(syncing.map(|(k, _)| k), Some(PhaseKind::Convergence));
        sup.on(E::SyncComplete);
        assert_eq!(
            sup.phase(),
            syncing,
            "Syncing and Verifying must report the same phase and budget"
        );
        sup.on(E::VerifyPassed);
        assert_eq!(sup.phase(), None, "Ready has no deadline");
    }

    // ---- Sleeping: never miss, never spin ----

    /// Nothing armed and no ping pending means the loop may block on
    /// its fds. Returning `Some(ZERO)` here would spin a core for
    /// nothing — the failure mode that matters on a box where every
    /// core is accounted for.
    #[test]
    fn an_idle_schedule_permits_blocking_indefinitely() {
        let t0 = Instant::now();
        assert_eq!(Schedule::new().next_wakeup(t0, None, true), None);
    }

    /// The wakeup must be the EARLIEST deadline. Sleeping past any
    /// armed one would delay a timeout by however long the others had
    /// left to run.
    #[test]
    fn the_wakeup_is_the_earliest_of_every_deadline() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some((PhaseKind::Convergence, Duration::from_secs(120))));
        s.arm_backoff(t0, Duration::from_secs(30));
        // Ping is soonest of the three.
        let ping = at(t0, 500);

        assert_eq!(
            s.next_wakeup(t0, Some(ping), true),
            Some(Duration::from_millis(500))
        );
        // Without the ping, the backoff is next.
        assert_eq!(s.next_wakeup(t0, None, true), Some(Duration::from_secs(30)));
    }

    /// An already-elapsed deadline asks for an immediate tick, and that
    /// does not spin because `fired` consumes it.
    #[test]
    fn an_elapsed_deadline_asks_for_an_immediate_tick_then_stops() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_backoff(t0, Duration::from_millis(100));

        let late = at(t0, 5_000);
        assert_eq!(s.next_wakeup(late, None, true), Some(Duration::ZERO));
        assert_eq!(s.fired(late, true), vec![Event::BackoffElapsed]);
        assert_eq!(
            s.next_wakeup(late, None, true),
            None,
            "consuming the deadline must end the immediate-tick request"
        );
    }

    /// A ping deadline alone is enough to schedule a wakeup, so a
    /// steady-state loop with no timers still pings on interval.
    #[test]
    fn a_ping_alone_schedules_a_wakeup() {
        let t0 = Instant::now();
        let s = Schedule::new();
        assert_eq!(
            s.next_wakeup(t0, Some(at(t0, 500)), true),
            Some(Duration::from_millis(500))
        );
    }

    // ---- Composed with the wedge detector ----

    /// The ping deadline has exactly one owner. Reading it back through
    /// the detector rather than storing a copy is what keeps the two
    /// from disagreeing.
    #[test]
    fn the_ping_deadline_comes_from_the_detector() {
        use crate::liveness::{WedgeDetector, PING_INTERVAL};
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        let s = Schedule::new();

        assert_eq!(
            s.next_wakeup(t0, Some(d.next_ping_at()), true),
            Some(PING_INTERVAL)
        );

        // After a ping goes out, the next one is an interval later.
        d.on_ping_sent(at(t0, 500));
        assert_eq!(
            s.next_wakeup(at(t0, 500), Some(d.next_ping_at()), true),
            Some(PING_INTERVAL)
        );
    }

    /// The steady-state loop wakes on the ping interval, which is well
    /// inside the published wedge-detection bound — the scheduler must
    /// not be what makes that number miss.
    #[test]
    fn steady_state_wakeups_are_frequent_enough_for_the_wedge_bound() {
        use crate::liveness::{worst_case_detection, WedgeDetector, PING_BUDGET};
        let t0 = Instant::now();
        let d = WedgeDetector::started(t0);
        let s = Schedule::new();
        let sleep = s.next_wakeup(t0, Some(d.next_ping_at()), true).unwrap();
        assert!(
            sleep < worst_case_detection(PING_BUDGET),
            "sleeping {sleep:?} would blow the detection bound"
        );
    }
}
