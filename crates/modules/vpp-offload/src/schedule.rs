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

use crate::supervisor::Event;

/// Armed deadlines for the current supervisor state.
#[derive(Debug, Default, Clone)]
pub struct Schedule {
    /// When the current phase stops being merely slow and becomes hung.
    ///
    /// Armed from `Supervisor::phase_budget()` on every state change; a
    /// state with no budget (`Ready`, `Steered`, `Stopped`) disarms it.
    phase_deadline: Option<Instant>,
    /// When the restart backoff expires.
    backoff_until: Option<Instant>,
}

impl Schedule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Re-arm the phase deadline for a (possibly new) state.
    ///
    /// Call on **every** transition, passing `Supervisor::phase_budget()`
    /// — including when it returns `None`, which disarms. Arming only on
    /// entry to a timed state would leave a stale deadline behind after
    /// leaving one, and it would fire against a state it does not
    /// describe.
    pub fn arm_phase(&mut self, now: Instant, budget: Option<Duration>) {
        self.phase_deadline = budget.map(|b| now + b);
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
    }

    /// Clear everything. For a clean stop, where no deadline applies.
    pub fn disarm(&mut self) {
        self.phase_deadline = None;
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
    /// **Consuming**: each deadline fires at most once. A deadline left
    /// armed after firing would produce the same event on every tick,
    /// and since both events route through the supervisor's failure
    /// path, that is a spin through teardown-and-restart rather than a
    /// single recovery.
    pub fn fired(&mut self, now: Instant) -> Vec<Event> {
        let mut out = Vec::new();
        if let Some(d) = self.phase_deadline {
            if now >= d {
                self.phase_deadline = None;
                out.push(Event::PhaseTimedOut);
            }
        }
        if let Some(d) = self.backoff_until {
            if now >= d {
                self.backoff_until = None;
                out.push(Event::BackoffElapsed);
            }
        }
        out
    }

    /// How long the loop may sleep before something needs attention.
    ///
    /// `None` = nothing is armed, so the loop may block on its fds
    /// indefinitely. `Some(ZERO)` = something is already due, so tick
    /// again immediately — which is not a busy loop precisely because
    /// [`Self::fired`] consumes what it reports.
    ///
    /// `ping_due_at` comes from
    /// [`crate::liveness::WedgeDetector::next_ping_at`] and is passed in
    /// rather than stored, so there is exactly one owner of that
    /// deadline.
    pub fn next_wakeup(&self, now: Instant, ping_due_at: Option<Instant>) -> Option<Duration> {
        [self.phase_deadline, self.backoff_until, ping_due_at]
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
        s.arm_phase(t0, Some(Duration::from_secs(10)));

        assert!(s.fired(at(t0, 9_999)).is_empty(), "not yet");
        assert_eq!(s.fired(at(t0, 10_000)), vec![Event::PhaseTimedOut]);
        assert!(
            s.fired(at(t0, 10_001)).is_empty(),
            "a fired deadline must be consumed"
        );
        assert!(s.fired(at(t0, 60_000)).is_empty());
    }

    #[test]
    fn backoff_fires_once_too() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_backoff(t0, Duration::from_millis(250));

        assert!(s.fired(at(t0, 249)).is_empty());
        assert_eq!(s.fired(at(t0, 250)), vec![Event::BackoffElapsed]);
        assert!(s.fired(at(t0, 500)).is_empty());
    }

    /// Re-arming on every transition is what stops a deadline from
    /// outliving the phase it describes.
    #[test]
    fn a_state_with_no_budget_disarms_the_phase_deadline() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some(API_STARTUP_BUDGET));
        assert!(s.phase_deadline().is_some());

        // Ready/Steered/Stopped report no budget.
        s.arm_phase(at(t0, 100), None);
        assert!(s.phase_deadline().is_none());
        assert!(s.fired(at(t0, 999_999)).is_empty());
    }

    /// Moving between timed phases restarts the clock rather than
    /// carrying the previous phase's remaining time.
    #[test]
    fn re_arming_replaces_rather_than_keeps_the_earlier_deadline() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some(API_STARTUP_BUDGET));

        // 59 s later the API comes up; the convergence budget starts now.
        let t1 = at(t0, 59_000);
        s.arm_phase(t1, Some(CONVERGENCE_BUDGET));
        assert!(
            s.fired(at(t0, 60_001)).is_empty(),
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
        s.arm_phase(t0, Some(Duration::from_secs(1)));
        s.arm_backoff(t0, Duration::from_secs(30));

        assert!(s.phase_deadline().is_none());
        assert!(
            !s.fired(at(t0, 2_000)).contains(&Event::PhaseTimedOut),
            "no event for a phase we are no longer in"
        );
    }

    #[test]
    fn disarm_clears_everything() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some(Duration::from_secs(1)));
        s.arm_backoff(t0, Duration::from_secs(1));
        s.disarm();
        assert!(s.fired(at(t0, 10_000)).is_empty());
        assert_eq!(s.next_wakeup(t0, None), None);
    }

    // ---- Sleeping: never miss, never spin ----

    /// Nothing armed and no ping pending means the loop may block on
    /// its fds. Returning `Some(ZERO)` here would spin a core for
    /// nothing — the failure mode that matters on a box where every
    /// core is accounted for.
    #[test]
    fn an_idle_schedule_permits_blocking_indefinitely() {
        let t0 = Instant::now();
        assert_eq!(Schedule::new().next_wakeup(t0, None), None);
    }

    /// The wakeup must be the EARLIEST deadline. Sleeping past any
    /// armed one would delay a timeout by however long the others had
    /// left to run.
    #[test]
    fn the_wakeup_is_the_earliest_of_every_deadline() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_phase(t0, Some(Duration::from_secs(120)));
        s.arm_backoff(t0, Duration::from_secs(30));
        // Ping is soonest of the three.
        let ping = at(t0, 500);

        assert_eq!(
            s.next_wakeup(t0, Some(ping)),
            Some(Duration::from_millis(500))
        );
        // Without the ping, the backoff is next.
        assert_eq!(s.next_wakeup(t0, None), Some(Duration::from_secs(30)));
    }

    /// An already-elapsed deadline asks for an immediate tick, and that
    /// does not spin because `fired` consumes it.
    #[test]
    fn an_elapsed_deadline_asks_for_an_immediate_tick_then_stops() {
        let t0 = Instant::now();
        let mut s = Schedule::new();
        s.arm_backoff(t0, Duration::from_millis(100));

        let late = at(t0, 5_000);
        assert_eq!(s.next_wakeup(late, None), Some(Duration::ZERO));
        assert_eq!(s.fired(late), vec![Event::BackoffElapsed]);
        assert_eq!(
            s.next_wakeup(late, None),
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
            s.next_wakeup(t0, Some(at(t0, 500))),
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
            s.next_wakeup(t0, Some(d.next_ping_at())),
            Some(PING_INTERVAL)
        );

        // After a ping goes out, the next one is an interval later.
        d.on_ping_sent(at(t0, 500));
        assert_eq!(
            s.next_wakeup(at(t0, 500), Some(d.next_ping_at())),
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
        let sleep = s.next_wakeup(t0, Some(d.next_ping_at())).unwrap();
        assert!(
            sleep < worst_case_detection(PING_BUDGET),
            "sleeping {sleep:?} would blow the detection bound"
        );
    }
}
