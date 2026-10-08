//! Recovery from lost netlink notifications. Portable.
//!
//! The kernel drops a multicast notification its subscriber's receive
//! buffer has no room for, and says so once, as `ENOBUFS` on the next
//! read; netlink-proto hands that up as `NetlinkPayload::Overrun`. Which
//! notifications were lost cannot be known, and none of them is ever
//! sent again, so everything the subscription feeds — link state, own
//! addresses, the kernel neighbour mirror — is re-read from dumps
//! instead. This is the schedule and the bookkeeping; the engine does
//! the reading.

use std::time::{Duration, Instant};

use crate::snapshot::{NetlinkSnapshot, ResyncOutcome};

/// The least time between two re-reads. Overruns come in bursts — the
/// churn that overflowed the buffer once keeps arriving — and each
/// re-read dumps every neighbour on the box, so a burst shares re-reads
/// rather than paying one per overrun.
pub const RESYNC_MIN_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
pub struct Resync {
    overruns: u64,
    outcomes: [u64; ResyncOutcome::COUNT],
    /// Notifications were lost after the last re-read started (or no
    /// re-read has run yet).
    pending: bool,
    /// A re-read is under way: what it covers is still owed until it ends.
    running: bool,
    last_attempt: Option<Instant>,
    last_error: Option<String>,
}

impl Resync {
    /// The kernel reported lost notifications. `true` when nothing was
    /// owed before, so the caller logs an episode once, not every report.
    pub fn overrun(&mut self) -> bool {
        self.overruns += 1;
        !std::mem::replace(&mut self.pending, true)
    }

    /// Whether a re-read should start now.
    pub fn due(&self, now: Instant) -> bool {
        self.pending
            && self
                .last_attempt
                .is_none_or(|t| now.saturating_duration_since(t) >= RESYNC_MIN_INTERVAL)
    }

    /// A re-read is starting. It covers every loss reported until now.
    /// Completed, it also replaces the subscription, dropping the old one
    /// with all it still held — including messages queued before a loss,
    /// which replayed after the dumps would undo them — so a loss reported
    /// from here on comes from the fresh subscription, may postdate the
    /// dumps, and is owed a re-read of its own. A failed one leaves the
    /// old subscription and is owed again ([`Self::finish`]).
    pub fn start(&mut self, now: Instant) {
        self.last_attempt = Some(now);
        self.pending = false;
        self.running = true;
    }

    /// The re-read ended. A failed one leaves everything it was meant to
    /// cover still owed.
    pub fn finish(&mut self, result: Result<(), String>) {
        self.running = false;
        match result {
            Ok(()) => {
                self.outcomes[ResyncOutcome::Ok.index()] += 1;
                self.last_error = None;
            }
            Err(e) => {
                self.outcomes[ResyncOutcome::Failed.index()] += 1;
                self.pending = true;
                self.last_error = Some(e);
            }
        }
    }

    /// Owed means owed until a re-read *ends*: one still running has not
    /// made the mirror current yet, so the snapshot published while it
    /// runs must not read as recovered.
    pub fn snapshot(&self) -> NetlinkSnapshot {
        NetlinkSnapshot {
            overruns: self.overruns,
            resyncs: self.outcomes,
            resync_pending: self.pending || self.running,
            last_error: self.last_error.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_due_until_an_overrun() {
        let r = Resync::default();
        assert!(!r.due(Instant::now()));
        assert_eq!(r.snapshot(), NetlinkSnapshot::default());
    }

    #[test]
    fn the_first_overrun_is_due_at_once_and_a_burst_is_one_episode() {
        let mut r = Resync::default();
        let t0 = Instant::now();
        assert!(r.overrun(), "opens an episode");
        assert!(!r.overrun(), "same episode");
        assert!(r.due(t0));
        let s = r.snapshot();
        assert_eq!(s.overruns, 2);
        assert!(s.resync_pending);
    }

    #[test]
    fn a_completed_re_read_clears_what_it_covered() {
        let mut r = Resync::default();
        let t0 = Instant::now();
        r.overrun();
        r.start(t0);
        assert!(!r.due(t0 + RESYNC_MIN_INTERVAL), "nothing owed");
        // Still owed while it runs: what is published meanwhile must not
        // read as recovered.
        assert!(r.snapshot().resync_pending, "owed until the re-read ends");
        r.finish(Ok(()));
        let s = r.snapshot();
        assert!(!s.resync_pending);
        assert_eq!(s.resyncs[ResyncOutcome::Ok.index()], 1);
        assert_eq!(s.last_error, None);
    }

    /// A loss reported while a re-read is running is not covered by it:
    /// owed again, but paced from the attempt so a burst cannot turn
    /// into back-to-back full dumps.
    #[test]
    fn an_overrun_during_a_re_read_is_owed_again_after_the_interval() {
        let mut r = Resync::default();
        let t0 = Instant::now();
        r.overrun();
        r.start(t0);
        assert!(
            r.overrun(),
            "a new episode: the running re-read cannot cover it"
        );
        r.finish(Ok(()));
        assert!(r.snapshot().resync_pending);
        assert!(!r.due(t0 + Duration::from_secs(1)));
        assert!(r.due(t0 + RESYNC_MIN_INTERVAL));
    }

    #[test]
    fn a_failed_re_read_stays_owed_and_says_why() {
        let mut r = Resync::default();
        let t0 = Instant::now();
        r.overrun();
        r.start(t0);
        r.finish(Err("neighbour dump: no reply within 30s".into()));
        let s = r.snapshot();
        assert!(s.resync_pending, "a failure covers nothing");
        assert_eq!(s.resyncs[ResyncOutcome::Failed.index()], 1);
        assert_eq!(
            s.last_error.as_deref(),
            Some("neighbour dump: no reply within 30s")
        );
        assert!(!r.due(t0 + Duration::from_secs(1)), "paced");
        assert!(r.due(t0 + RESYNC_MIN_INTERVAL), "retried");
        r.start(t0 + RESYNC_MIN_INTERVAL);
        r.finish(Ok(()));
        let s = r.snapshot();
        assert!(!s.resync_pending);
        assert_eq!(s.last_error, None, "a success clears the reason");
    }
}
