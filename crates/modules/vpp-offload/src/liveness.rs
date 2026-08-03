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

/// The relaxed budget to use while a full FIB resync is in flight.
///
/// VPP answers the binary API on its **main** thread, which is the
/// same thread executing our route batches. Under a full-table load
/// (~1.05M routes) it is legitimately busy, and a ping can queue
/// behind a batch without anything being wrong. Applying the steady
/// budget there would make every large resync look like a wedge and
/// restart-loop the box precisely when it is doing the most work.
///
/// This is deliberately far above the steady budget: during resync we
/// are not yet forwarding through VPP, so a slow answer costs latency
/// in coming back, not dropped traffic.
pub const SYNC_PING_BUDGET: Duration = Duration::from_secs(10);

/// Worst-case time from "VPP wedges" to "we notice", for a given
/// silence budget.
///
/// The bad case is a wedge that starts immediately after a successful
/// pong: the budget must elapse, and we only observe it on the next
/// scheduled ping, so the interval adds on top.
pub const fn worst_case_detection(budget: Duration) -> Duration {
    budget.saturating_add(PING_INTERVAL)
}

/// Tracks API liveness from ping/pong timestamps.
///
/// Deliberately does NOT own the transport. The detector decides
/// *when* to ask and *what the silence means*; the caller owns the
/// socket and can pipeline the ping alongside real work.
#[derive(Debug, Clone)]
pub struct WedgeDetector {
    /// Last time the API actually answered.
    last_ok: Instant,
    /// Last time we sent a ping — tracked separately so a ping that
    /// never answers does not also suppress the next attempt.
    last_attempt: Instant,
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
        }
    }

    /// Time to send another ping?
    pub fn ping_due(&self, now: Instant) -> bool {
        now.duration_since(self.last_attempt) >= PING_INTERVAL
    }

    pub fn on_ping_sent(&mut self, now: Instant) {
        self.last_attempt = now;
    }

    pub fn on_pong(&mut self, now: Instant) {
        self.last_ok = now;
        // A pong is also proof the attempt landed; without this a
        // reply arriving faster than the interval would leave
        // `last_attempt` stale and immediately re-arm `ping_due`.
        if now > self.last_attempt {
            self.last_attempt = now;
        }
    }

    /// How long the API has been silent.
    pub fn silent_for(&self, now: Instant) -> Duration {
        now.duration_since(self.last_ok)
    }

    /// Has it been silent past `budget`? Pass [`PING_BUDGET`] in
    /// steady state and [`SYNC_PING_BUDGET`] while resyncing.
    pub fn is_wedged(&self, now: Instant, budget: Duration) -> bool {
        self.silent_for(now) > budget
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
}
