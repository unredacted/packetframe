//! Wedge detection: is VPP's binary API still answering?
//!
//! A crash is easy — the pidfd fires (see [`crate::process`]). The
//! nastier failure is a VPP that is *alive and not forwarding*: a
//! worker stuck in a driver call, a deadlocked main thread, a barrier
//! that never lifts. `ps` says healthy, the pidfd stays quiet, and
//! traffic disappears. A wedged forwarder drops exactly as thoroughly
//! as a dead one, which is why the supervisor treats [`Event::Wedged`]
//! and `ProcessExited` the same way.
//!
//! [`Event::Wedged`]: crate::supervisor::Event::Wedged
//!
//! "Answering" means answering ANYTHING: a pong, or a reply to a route
//! batch or a verify probe. The ping is how the detector asks when the
//! loop has nothing else to ask; it is not the only thing that can prove
//! the main thread is scheduling requests. See
//! [`WedgeDetector::on_answer`].
//!
//! Like [`crate::supervisor`], this is pure logic with the clock passed
//! in. Timing code that calls `Instant::now()` internally can only be
//! tested by sleeping, which makes for slow tests that are flaky under
//! CI load — and a detector whose whole job is timing deserves tests
//! that pin exact boundaries instead of hoping the scheduler cooperates.

use std::time::{Duration, Instant};

/// How often we send an API ping.
pub const PING_INTERVAL: Duration = Duration::from_millis(500);

/// How long the API may stay silent in steady state before we call it
/// wedged.
///
/// This trades two costs against each other. Too long and a blackhole
/// persists; too short and ordinary jitter triggers a restart, which
/// costs a real outage (the recovery budget is ≤ 90 s) to cure a
/// problem that did not exist. 1.5 s tolerates two missed pings — a
/// scheduling hiccup — while keeping worst-case detection inside the
/// published 2 s. See [`worst_case_detection`].
pub const PING_BUDGET: Duration = Duration::from_millis(1_500);

/// The relaxed budget for a resync on a dataplane that is **not**
/// carrying traffic.
///
/// VPP answers the binary API on its **main** thread, which is the
/// same thread executing our route batches, so under load a ping can
/// queue behind a batch without anything being wrong. Applying the
/// steady budget to a first-attach resync would make every large load
/// look like a wedge and restart-loop the box while it does the most
/// work — and nothing is lost by waiting, because no traffic is
/// steered yet.
///
/// **This budget must never be used while steering is up.** Pick it
/// with [`budget_for`], not by asking "am I resyncing". See that
/// function for why the distinction is load-bearing.
pub const SYNC_PING_BUDGET: Duration = Duration::from_secs(10);

/// Choose the silence budget from what is actually at stake.
///
/// The decision is **"is traffic currently steered into VPP"**, not
/// "am I resyncing". Those look interchangeable and are not: the
/// adopted path (`AdoptedResyncing`) resyncs a VPP that never stopped
/// forwarding, which is the entire point of adoption. Selecting the
/// relaxed budget there would let a wedged, *steered* VPP blackhole
/// traffic for up to `SYNC_PING_BUDGET + PING_INTERVAL` — 10.5 s
/// against a published promise of 2 s.
///
/// So: whenever packets are on VPP, the published number governs, and
/// the risk moves to the other side of the trade — a busy adopted
/// resync is now more likely to trip a restart. That is the correct
/// direction to be wrong in. A restart unsteers first and recovers
/// within the 90 s budget; a silent 10 s blackhole just drops traffic.
/// It is also less likely than it looks: the drainer holds at most
/// [`crate::fib_sync::DEFAULT_WINDOW`] requests in flight, so a ping
/// queues behind ~256 route ops, not behind the whole table.
pub const fn budget_for(steered: bool, converging: bool) -> Duration {
    if steered {
        PING_BUDGET
    } else if converging {
        SYNC_PING_BUDGET
    } else {
        PING_BUDGET
    }
}

/// Worst-case time from "VPP wedges" to "we notice", for a given
/// silence budget, measured on a supervision loop that is running.
///
/// The bad case is a wedge that starts immediately after a successful
/// pong: the budget must elapse, and we only observe it on the next
/// scheduled ping, so the interval adds on top.
///
/// After a stall of the loop itself (see [`WedgeDetector::on_loop_gap`])
/// the same bound runs from the RESUME, not from the last pong: nothing
/// that happened while the loop was not asking is evidence about VPP. A
/// stall therefore delays the verdict on a VPP that hung during it by at
/// most the stall itself — the time no detector running on that loop
/// could have acted in anyway.
pub const fn worst_case_detection(budget: Duration) -> Duration {
    budget.saturating_add(PING_INTERVAL)
}

/// How many unanswered probes `budget` absorbs as jitter: one fewer than
/// fit in it. Two for [`PING_BUDGET`] — the "two missed pings" its doc
/// promises to tolerate.
///
/// Also the limit on forgiving the loop's own stalls (see
/// [`WedgeDetector::on_loop_gap`]): once VPP has missed more probes than
/// jitter explains, the silence is VPP's, and a stall that follows does
/// not erase it.
pub const fn tolerated_misses(budget: Duration) -> u32 {
    let fit = budget.as_millis() / PING_INTERVAL.as_millis();
    (fit as u32).saturating_sub(1)
}

/// What one gap between supervision passes meant to the detector. See
/// [`WedgeDetector::on_loop_gap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopGap {
    /// Inside the budget: ordinary cadence, counted as silence as always.
    Ordinary,
    /// The loop itself was away for longer than the budget. Silence
    /// before this instant is no longer evidence; the window restarts.
    Excused,
    /// The loop was away for longer than the budget, but VPP had already
    /// missed `unanswered` probes before it — more than jitter explains —
    /// so the silence stands.
    Unexcused { unanswered: u32 },
}

/// Why a wedge was called, for the journal and the event log.
///
/// "Since the last answer" below means VPP's last reply of any kind, a
/// pong or anything else ([`WedgeDetector::on_answer`]).
///
/// The incident this exists for (2026-10-07) tore down a steered VPP
/// with nothing in the journal but the teardown itself: no failed ping,
/// no silence figure, no hint whether VPP or the host had gone quiet.
/// Every field here answers one of those.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WedgeReport {
    /// Since the last answer, on the wall clock.
    pub silent_for: Duration,
    /// The part the verdict counted: since the last answer or the last
    /// excused stall, whichever is later.
    pub counted: Duration,
    /// The budget in force.
    pub budget: Duration,
    /// Whether traffic was steered into VPP — which budget applied.
    pub steered: bool,
    /// Probes sent since the last answer and not answered.
    pub unanswered: u32,
    /// The last probe's error, verbatim.
    pub last_error: Option<String>,
    /// The longest the loop was away between passes, not counting time
    /// spent waiting on VPP's socket, since the last answer. Large here
    /// and small `vpp_wait` = the host or PacketFrame stalled; the
    /// reverse = VPP stopped answering.
    pub worst_loop_gap: Duration,
    /// Loop stalls excused since the last answer.
    pub stalls_excused: u32,
    /// Time spent blocked on VPP's API socket since the last answer.
    pub vpp_wait: Duration,
}

/// Tracks API liveness from ping/pong timestamps, and from every other
/// answer VPP gives ([`Self::on_answer`]).
///
/// Deliberately does NOT own the transport. The detector decides
/// *when* to ask and *what the silence means*; the caller owns the
/// socket and can pipeline the ping alongside real work.
///
/// ## Silence is evidence only while the loop is listening
///
/// The detector lives on the supervision loop, and that loop also
/// makes kernel calls — ethtool ioctls for the steering audit, netlink
/// dumps for the hand-back path — that wait on `rtnl_lock`. When the
/// kernel holds that lock (a bridge flushing a million routes appears
/// to have held it for ~40 s on 2026-10-07) the loop sends no pings,
/// and the silence clock used to run on regardless: the first probe
/// after the loop resumed was judged against 40 s of "silence", so one
/// unanswered probe was a wedge with none of the tolerance
/// [`PING_BUDGET`] promises. A teardown on a steered gateway costs the
/// eBPF tier carrying everything until the route mirror reloads —
/// minutes.
///
/// So a pass that arrives longer than the budget after the previous
/// one, *not counting time spent blocked on VPP's own socket*, restarts
/// the evidence window ([`Self::on_loop_gap`]). The exclusion is what
/// keeps this from excusing a hung VPP: a ping to one blocks the loop
/// for the full socket deadline, and that wait is VPP's silence, not
/// the loop's.
#[derive(Debug, Clone)]
pub struct WedgeDetector {
    /// Last time the API actually answered.
    last_ok: Instant,
    /// Last time we sent a ping — tracked separately so a ping that
    /// never answers does not also suppress the next attempt.
    last_attempt: Instant,
    /// Last time VPP answered ANYTHING — a pong, or a reply to a route
    /// batch, a verify probe, any request on the API. What silence is
    /// measured from. Kept apart from `last_ok` because the probe gates
    /// ([`Self::answered_last_probe`], [`Self::answered_since`]) ask
    /// about pings specifically, and a reply to something else must not
    /// pass for the answer to a ping that failed.
    last_alive: Instant,
    /// Where the evidence window starts if later than `last_alive`: the
    /// resume after the loop's last excused stall.
    evidence_from: Instant,
    /// Probes sent since the last answer that went unanswered.
    unanswered: u32,
    /// Diagnostics since the last answer; see [`WedgeReport`].
    last_error: Option<String>,
    worst_loop_gap: Duration,
    stalls_excused: u32,
}

impl WedgeDetector {
    /// Start the clock. Called when the API first answers, not when
    /// the process spawns: VPP takes a while to open its socket, and
    /// counting that startup as silence would declare a wedge before
    /// it ever had a chance to reply.
    pub fn started(now: Instant) -> Self {
        Self {
            last_ok: now,
            last_attempt: now,
            last_alive: now,
            evidence_from: now,
            unanswered: 0,
            last_error: None,
            worst_loop_gap: Duration::ZERO,
            stalls_excused: 0,
        }
    }

    /// Time to send another ping?
    pub fn ping_due(&self, now: Instant) -> bool {
        now.duration_since(self.last_attempt) >= PING_INTERVAL
    }

    /// When the next ping is due, for a caller computing how long it
    /// may sleep. Without this the loop would have to poll to discover
    /// that [`Self::ping_due`] became true, which is the busy-wait the
    /// scheduler exists to avoid.
    pub fn next_ping_at(&self) -> Instant {
        self.last_attempt + PING_INTERVAL
    }

    pub fn on_ping_sent(&mut self, now: Instant) {
        self.last_attempt = now;
        // Counted as unanswered until the pong says otherwise.
        self.unanswered = self.unanswered.saturating_add(1);
    }

    pub fn on_pong(&mut self, now: Instant) {
        self.last_ok = now;
        // A pong is also proof the attempt landed; without this a
        // reply arriving faster than the interval would leave
        // `last_attempt` stale and immediately re-arm `ping_due`.
        if now > self.last_attempt {
            self.last_attempt = now;
        }
        self.on_answer(now);
    }

    /// VPP answered something other than a ping no earlier than `at`: a
    /// route batch, a verify probe, any reply on the API.
    ///
    /// Proof of life, because the thread that answers those is the one a
    /// ping exists to prove is scheduling. A ping can queue behind work
    /// VPP is visibly getting through — on 2026-10-07 a burst of next-hop
    /// flaps re-queued every route through each re-resolved IX next hop —
    /// and calling that VPP wedged tears down a dataplane that was
    /// answering to the end. Silence is measured from the last answer of
    /// ANY kind; a VPP that answers nothing is held to the same budget as
    /// before.
    ///
    /// `at` must not be later than the answer: the caller passes a clock
    /// reading from before it, never after. Not a pong: the probe gates
    /// still need one.
    pub fn on_answer(&mut self, at: Instant) {
        if at > self.last_alive {
            self.last_alive = at;
        }
        // An answer older than the latest probe says nothing about that
        // probe, and must not erase its failure.
        if at >= self.last_attempt {
            self.unanswered = 0;
            self.last_error = None;
            self.worst_loop_gap = Duration::ZERO;
            self.stalls_excused = 0;
        }
    }

    /// Why the last probe failed — kept for [`WedgeReport`] only.
    pub fn on_probe_failed(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
    }

    /// The supervision loop is back after `loop_gap` away, NOT counting
    /// time it spent blocked on VPP's socket (the caller subtracts that;
    /// see [`crate::driver::Observe::api_wait`]).
    ///
    /// A gap longer than `budget` means the loop could not have asked
    /// VPP anything for longer than the whole budget, for reasons of its
    /// own: a kernel call waiting on `rtnl_lock`, a host too starved to
    /// schedule it. Silence that accrued then says nothing about VPP, so
    /// the window restarts here — and [`Self::is_wedged`] then needs a
    /// probe sent from now on AND the full budget measured from now.
    ///
    /// Not excused once VPP has missed more probes than `budget`
    /// tolerates as jitter ([`tolerated_misses`]): that silence was
    /// earned while the loop was listening. Without this limit a loop
    /// that stalls on every pass would restart the window every pass
    /// and never call a hung VPP wedged; with it, at most
    /// `tolerated_misses + 1` stalls are forgiven per silence.
    pub fn on_loop_gap(&mut self, now: Instant, loop_gap: Duration, budget: Duration) -> LoopGap {
        self.worst_loop_gap = self.worst_loop_gap.max(loop_gap);
        if loop_gap <= budget {
            return LoopGap::Ordinary;
        }
        if self.unanswered > tolerated_misses(budget) {
            return LoopGap::Unexcused {
                unanswered: self.unanswered,
            };
        }
        self.evidence_from = now;
        self.stalls_excused = self.stalls_excused.saturating_add(1);
        LoopGap::Excused
    }

    /// How long the API has been silent: the age of its last answer of
    /// any kind ([`Self::on_answer`]), on the wall clock. What status
    /// reports; NOT what the verdict counts — see
    /// [`Self::counted_silence`].
    pub fn silent_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_alive)
    }

    /// The silence the verdict counts: since the last answer or the last
    /// excused loop stall, whichever is later.
    pub fn counted_silence(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_alive.max(self.evidence_from))
    }

    /// Has it been silent past `budget`? Get `budget` from
    /// [`budget_for`] rather than picking a constant directly — the
    /// choice depends on whether traffic is steered, and getting it
    /// from "am I resyncing" is the bug [`budget_for`] documents.
    ///
    /// Two conditions, and the second is not implied by the first: the
    /// counted silence is past the budget, AND a probe has gone out
    /// since the window last restarted. Silence nobody asked about is
    /// not an answer.
    pub fn is_wedged(&self, now: Instant, budget: Duration) -> bool {
        self.counted_silence(now) > budget && self.last_attempt >= self.evidence_from
    }

    /// The evidence behind a verdict, for the journal and the event log.
    /// `steered` and `vpp_wait` are the caller's to know.
    pub fn report(
        &self,
        now: Instant,
        budget: Duration,
        steered: bool,
        vpp_wait: Duration,
    ) -> WedgeReport {
        WedgeReport {
            silent_for: self.silent_for(now),
            counted: self.counted_silence(now),
            budget,
            steered,
            unanswered: self.unanswered,
            last_error: self.last_error.clone(),
            worst_loop_gap: self.worst_loop_gap,
            stalls_excused: self.stalls_excused,
            vpp_wait,
        }
    }

    /// Did the most recent probe get an answer?
    ///
    /// A **different question** from [`Self::is_wedged`], and the gap
    /// between them is the point. The budget exists so ordinary jitter
    /// does not cost a restart, so two unanswered pings are deliberately
    /// tolerated — which is right for deciding whether to TEAR DOWN a
    /// dataplane carrying traffic, and wrong for deciding to start
    /// diverting traffic INTO one. Steering into that tolerated window
    /// puts packets on a VF whose VPP has already stopped answering,
    /// and nothing takes them off again until the budget expires.
    ///
    /// So: no clock, no constant, no tolerance. The API answered the
    /// last thing we asked it, or it did not.
    pub fn answered_last_probe(&self) -> bool {
        self.last_ok >= self.last_attempt
    }

    /// Has the API answered strictly AFTER `t`?
    ///
    /// For a decision that needs evidence from after some event — the
    /// resume of a convergence step that lost the API. The clock's
    /// starting point counts as an answer everywhere else (it IS one:
    /// the handshake), and strictness is what keeps a detector started
    /// at the same instant as the event from passing for a pong that
    /// never came.
    pub fn answered_since(&self, t: Instant) -> bool {
        self.last_ok > t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    /// The published failover number is "blackhole-wedge ≤ 2 s". That
    /// promise is the sum of two constants, so assert the sum here —
    /// otherwise someone raises PING_BUDGET for a good local reason
    /// and silently invalidates a number in the runbook.
    #[test]
    fn steady_state_detection_stays_inside_the_published_two_seconds() {
        assert!(
            worst_case_detection(PING_BUDGET) <= Duration::from_secs(2),
            "worst case {:?} exceeds the published 2 s",
            worst_case_detection(PING_BUDGET)
        );
    }

    #[test]
    fn only_an_answer_after_the_instant_counts_as_one_since_it() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        assert!(
            !d.answered_since(t0),
            "the start is not evidence about itself"
        );
        d.on_ping_sent(at(t0, 500));
        assert!(!d.answered_since(t0), "a ping is not an answer");
        d.on_pong(at(t0, 520));
        assert!(d.answered_since(t0));
        assert!(!d.answered_since(at(t0, 520)));
    }

    #[test]
    fn a_healthy_api_is_never_wedged() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        for ms in (0..5_000).step_by(400) {
            d.on_pong(at(t0, ms));
            assert!(!d.is_wedged(at(t0, ms), PING_BUDGET));
        }
    }

    #[test]
    fn silence_past_the_budget_is_a_wedge() {
        let t0 = Instant::now();
        let d = WedgeDetector::started(t0);
        assert!(
            !d.is_wedged(at(t0, 1_500), PING_BUDGET),
            "exactly at budget"
        );
        assert!(d.is_wedged(at(t0, 1_501), PING_BUDGET));
    }

    /// The false-positive guard: two missed pings must NOT trip it.
    /// A needless restart costs a real outage to cure nothing.
    #[test]
    fn two_missed_pings_are_tolerated() {
        let t0 = Instant::now();
        let d = WedgeDetector::started(t0);
        // Pings at 500 and 1000 both go unanswered.
        assert!(!d.is_wedged(at(t0, 500), PING_BUDGET));
        assert!(!d.is_wedged(at(t0, 1_000), PING_BUDGET));
    }

    /// The published ≤2 s must hold whenever packets are on VPP —
    /// including the adopted path, which resyncs a VPP that never
    /// stopped forwarding. Choosing the budget by "am I resyncing"
    /// would let a wedged, steered VPP blackhole for 10.5 s.
    #[test]
    fn a_steered_resync_keeps_the_published_budget() {
        assert_eq!(
            budget_for(true, true),
            PING_BUDGET,
            "steered + converging (adoption) must not get the relaxed budget"
        );
        assert!(
            worst_case_detection(budget_for(true, true)) <= Duration::from_secs(2),
            "a steered dataplane must stay inside the published 2 s"
        );
    }

    /// The relaxed budget is only for a dataplane carrying no traffic.
    #[test]
    fn only_an_unsteered_resync_gets_the_relaxed_budget() {
        assert_eq!(budget_for(false, true), SYNC_PING_BUDGET);
        assert_eq!(budget_for(false, false), PING_BUDGET);
        assert_eq!(budget_for(true, false), PING_BUDGET);
    }

    /// A slow resync must not read as a wedge — this is the one that
    /// would restart-loop the box during a full-table load.
    #[test]
    fn a_busy_resync_is_not_a_wedge_under_the_sync_budget() {
        let t0 = Instant::now();
        let d = WedgeDetector::started(t0);
        let five_s = at(t0, 5_000);
        assert!(
            d.is_wedged(five_s, PING_BUDGET),
            "steady budget would call this wedged"
        );
        assert!(
            !d.is_wedged(five_s, SYNC_PING_BUDGET),
            "the sync budget must tolerate a busy main thread"
        );
    }

    #[test]
    fn pings_are_due_on_the_interval_not_continuously() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        assert!(!d.ping_due(at(t0, 499)));
        assert!(d.ping_due(at(t0, 500)));
        d.on_ping_sent(at(t0, 500));
        assert!(!d.ping_due(at(t0, 999)));
        assert!(d.ping_due(at(t0, 1_000)));
    }

    /// An unanswered ping must not suppress the next attempt — if it
    /// did, one dropped ping would stretch detection without bound.
    #[test]
    fn an_unanswered_ping_still_lets_the_next_one_fire() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        d.on_ping_sent(at(t0, 500)); // never answered
        assert!(d.ping_due(at(t0, 1_000)));
        assert!(d.is_wedged(at(t0, 1_600), PING_BUDGET));
    }

    /// A pong arriving sooner than the interval must not immediately
    /// re-arm the next ping; otherwise a fast VPP gets pinged in a
    /// tight loop.
    #[test]
    fn a_fast_pong_does_not_rearm_the_ping_immediately() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        d.on_ping_sent(at(t0, 500));
        d.on_pong(at(t0, 510));
        assert!(!d.ping_due(at(t0, 900)));
        assert!(d.ping_due(at(t0, 1_010)));
    }

    /// The stall rule and the budget's own promise are one number: the
    /// steady budget tolerates exactly two missed pings, and a stall is
    /// forgiven only while no more than that have been missed.
    #[test]
    fn the_steady_budget_tolerates_two_missed_pings() {
        assert_eq!(tolerated_misses(PING_BUDGET), 2);
        assert!(tolerated_misses(SYNC_PING_BUDGET) > tolerated_misses(PING_BUDGET));
    }

    /// The 2026-10-07 shape on the detector alone. The last pong lands,
    /// the loop is held in the kernel for 40 s, and the first probe after
    /// it goes unanswered. Silence since the last pong is 40 s, but none
    /// of it was asked about: the window restarts at the resume, and a
    /// wedge needs the full budget from there.
    #[test]
    fn a_loop_stall_restarts_the_evidence_window() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        let resume = at(t0, 40_000);

        assert_eq!(
            d.on_loop_gap(resume, Duration::from_secs(40), PING_BUDGET),
            LoopGap::Excused
        );
        d.on_ping_sent(resume);
        d.on_probe_failed("socket I/O: Resource temporarily unavailable");
        assert!(
            !d.is_wedged(resume, PING_BUDGET),
            "one unanswered probe after a stall is not a wedge"
        );
        assert_eq!(
            d.silent_for(resume),
            Duration::from_secs(40),
            "status still sees the age"
        );
        assert!(
            !d.is_wedged(resume + PING_BUDGET, PING_BUDGET),
            "exactly at budget"
        );
        assert!(d.is_wedged(resume + PING_BUDGET + Duration::from_millis(1), PING_BUDGET));
    }

    /// The window restarts, but a verdict still needs a probe sent inside
    /// it. Unreachable from the driver today — a gap past the budget
    /// always leaves a ping due — so this pins the detector's own rule
    /// rather than the driver's ordering.
    #[test]
    fn silence_nobody_asked_about_is_not_a_wedge() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        let resume = at(t0, 40_000);
        d.on_loop_gap(resume, Duration::from_secs(40), PING_BUDGET);
        assert!(
            !d.is_wedged(resume + Duration::from_secs(5), PING_BUDGET),
            "no probe since the resume"
        );
        d.on_ping_sent(resume + Duration::from_secs(5));
        assert!(d.is_wedged(resume + Duration::from_secs(5), PING_BUDGET));
    }

    /// A gap inside the budget is ordinary cadence: counted, not excused.
    #[test]
    fn a_gap_inside_the_budget_is_counted() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        assert_eq!(
            d.on_loop_gap(at(t0, 1_500), PING_BUDGET, PING_BUDGET),
            LoopGap::Ordinary
        );
        d.on_ping_sent(at(t0, 1_500));
        assert!(!d.is_wedged(at(t0, 1_500), PING_BUDGET));
        assert!(
            d.is_wedged(at(t0, 1_501), PING_BUDGET),
            "measured from the pong"
        );
    }

    /// Silence VPP earned while the loop WAS listening is not erased by a
    /// stall that follows it. Without this, a loop stalling on every pass
    /// would restart the window every pass and never call a hung VPP
    /// wedged.
    #[test]
    fn a_stall_does_not_excuse_silence_vpp_already_earned() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        for ms in [500, 1_000, 1_400] {
            d.on_ping_sent(at(t0, ms));
        }
        assert_eq!(
            d.on_loop_gap(at(t0, 30_000), Duration::from_secs(28), PING_BUDGET),
            LoopGap::Unexcused { unanswered: 3 }
        );
        d.on_ping_sent(at(t0, 30_000));
        assert!(d.is_wedged(at(t0, 30_000), PING_BUDGET));
    }

    /// The tolerance is per silence: a pong resets it, and the next
    /// stall is forgiven again.
    #[test]
    fn a_pong_resets_what_a_stall_may_forgive() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        for ms in [500, 1_000, 1_400] {
            d.on_ping_sent(at(t0, ms));
        }
        d.on_pong(at(t0, 1_400));
        assert_eq!(
            d.on_loop_gap(at(t0, 30_000), Duration::from_secs(28), PING_BUDGET),
            LoopGap::Excused
        );
    }

    /// The report says what the verdict saw — including what the loop
    /// did — and a pong clears the episode's diagnostics.
    #[test]
    fn the_report_names_the_silence_the_probe_and_the_loop() {
        let t0 = Instant::now();
        let mut d = WedgeDetector::started(t0);
        d.on_loop_gap(at(t0, 400), Duration::from_millis(400), PING_BUDGET);
        d.on_ping_sent(at(t0, 500));
        d.on_probe_failed("no answer");
        let r = d.report(
            at(t0, 2_000),
            PING_BUDGET,
            true,
            Duration::from_millis(1_500),
        );
        assert_eq!(
            r,
            WedgeReport {
                silent_for: Duration::from_millis(2_000),
                counted: Duration::from_millis(2_000),
                budget: PING_BUDGET,
                steered: true,
                unanswered: 1,
                last_error: Some("no answer".into()),
                worst_loop_gap: Duration::from_millis(400),
                stalls_excused: 0,
                vpp_wait: Duration::from_millis(1_500),
            }
        );
        d.on_pong(at(t0, 2_100));
        let r = d.report(at(t0, 2_100), PING_BUDGET, true, Duration::ZERO);
        assert_eq!(
            (r.unanswered, r.last_error, r.worst_loop_gap),
            (0, None, Duration::ZERO)
        );
    }
}
