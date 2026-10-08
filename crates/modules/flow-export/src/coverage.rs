//! Whether a port's samples represent its traffic, judged per 5 s window
//! from what can be observed: samples delivered, samples lost, and the
//! packets the port counted.
//!
//! Pessimistic by design, because a later consumer (the DDoS mitigation's
//! withdrawal hold) acts on it: loss is visible at once, recovery takes
//! three clean windows, and a busy port that yields no samples at all is
//! uncovered rather than quiet.

use std::time::{Duration, Instant};

pub const WINDOW: Duration = Duration::from_secs(5);
/// Before this, a port is `Starting` rather than judged covered.
pub const STARTUP_GRACE: Duration = Duration::from_secs(30);
/// Clean windows that end a degradation.
pub const RECOVERY_WINDOWS: u32 = 3;
/// Windows losing more than [`HEAVY_LOSS_PER_MILLE`] that make a port
/// uncovered.
pub const HEAVY_LOSS_WINDOWS: u32 = 3;
pub const HEAVY_LOSS_PER_MILLE: u64 = 10;
/// A port that counted this many sampling gaps' worth of packets in a
/// window and yielded no sample is not being sampled. Generous, because
/// the kernel counts wire packets while the programs can see GRO
/// aggregates of up to 64.
pub const SILENT_GAPS: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Starting,
    Covered,
    Degraded(String),
    Uncovered(String),
}

impl State {
    pub fn name(&self) -> &'static str {
        match self {
            State::Starting => "starting",
            State::Covered => "covered",
            State::Degraded(_) => "degraded",
            State::Uncovered(_) => "uncovered",
        }
    }

    /// For the coverage gauge: higher is better.
    pub fn level(&self) -> u8 {
        match self {
            State::Uncovered(_) => 0,
            State::Degraded(_) => 1,
            State::Starting => 2,
            State::Covered => 3,
        }
    }
}

/// What one window showed for a port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Window {
    /// Samples from this port delivered to the exporter.
    pub samples: u64,
    /// Samples lost on this port's path (its rings are shared, so loss
    /// cannot be told apart by port).
    pub lost: u64,
    /// Packets the port counted.
    pub packets: u64,
    /// The rate the port was sampled at.
    pub rate: u32,
}

#[derive(Debug, Clone)]
pub struct PortCoverage {
    since: Instant,
    clean_run: u32,
    heavy_run: u32,
    state: State,
}

impl PortCoverage {
    pub fn new(now: Instant) -> Self {
        Self {
            since: now,
            clean_run: 0,
            heavy_run: 0,
            state: State::Starting,
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    /// Judge a window that ended at `now`.
    pub fn judge(&mut self, now: Instant, w: Window) -> &State {
        let starting = now.saturating_duration_since(self.since) < STARTUP_GRACE;
        let silent = w.samples == 0
            && w.lost == 0
            && w.packets >= SILENT_GAPS.saturating_mul(u64::from(w.rate.max(1)));
        if w.lost > 0 {
            self.clean_run = 0;
            let heavy = w.lost * 1000 > (w.samples + w.lost) * HEAVY_LOSS_PER_MILLE;
            self.heavy_run = if heavy { self.heavy_run + 1 } else { 0 };
            self.state = if self.heavy_run >= HEAVY_LOSS_WINDOWS {
                State::Uncovered(format!(
                    "losing more than {}% of samples for {} windows",
                    HEAVY_LOSS_PER_MILLE / 10,
                    self.heavy_run
                ))
            } else {
                State::Degraded(format!(
                    "{} samples lost in the last {} s",
                    w.lost,
                    WINDOW.as_secs()
                ))
            };
        } else if silent && !starting {
            self.clean_run = 0;
            self.state = State::Uncovered(format!(
                "{} packets and no sample in {} s: nothing is sampling this port",
                w.packets,
                WINDOW.as_secs()
            ));
        } else {
            self.heavy_run = 0;
            self.clean_run += 1;
            self.state = match &self.state {
                State::Starting if starting => State::Starting,
                State::Starting | State::Covered => State::Covered,
                _ if self.clean_run >= RECOVERY_WINDOWS => State::Covered,
                other => other.clone(),
            };
        }
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(samples: u64, lost: u64, packets: u64) -> Window {
        Window {
            samples,
            lost,
            packets,
            rate: 1000,
        }
    }

    #[test]
    fn starting_then_covered_after_the_grace() {
        let t0 = Instant::now();
        let mut c = PortCoverage::new(t0);
        assert_eq!(c.judge(t0 + WINDOW, w(5, 0, 5000)), &State::Starting);
        assert_eq!(c.judge(t0 + STARTUP_GRACE, w(5, 0, 5000)), &State::Covered);
    }

    #[test]
    fn loss_degrades_at_once_and_recovery_takes_three_clean_windows() {
        let t0 = Instant::now();
        let mut c = PortCoverage::new(t0);
        let t = t0 + STARTUP_GRACE;
        c.judge(t, w(100, 0, 0));
        assert!(matches!(c.judge(t, w(100, 1, 0)), State::Degraded(_)));
        assert!(matches!(c.judge(t, w(100, 0, 0)), State::Degraded(_)));
        assert!(matches!(c.judge(t, w(100, 0, 0)), State::Degraded(_)));
        assert_eq!(c.judge(t, w(100, 0, 0)), &State::Covered);
    }

    #[test]
    fn heavy_loss_for_three_windows_uncovers() {
        let t0 = Instant::now();
        let mut c = PortCoverage::new(t0);
        let t = t0 + STARTUP_GRACE;
        assert!(matches!(c.judge(t, w(90, 10, 0)), State::Degraded(_)));
        assert!(matches!(c.judge(t, w(90, 10, 0)), State::Degraded(_)));
        assert!(matches!(c.judge(t, w(90, 10, 0)), State::Uncovered(_)));
        // Light loss breaks the run: degraded, not uncovered.
        assert!(matches!(c.judge(t, w(1000, 1, 0)), State::Degraded(_)));
    }

    #[test]
    fn a_busy_port_with_no_samples_is_uncovered_but_an_idle_one_is_not() {
        let t0 = Instant::now();
        let mut c = PortCoverage::new(t0);
        let t = t0 + STARTUP_GRACE;
        assert_eq!(c.judge(t, w(0, 0, 1000)), &State::Covered, "idle enough");
        assert!(matches!(
            c.judge(t, w(0, 0, SILENT_GAPS * 1000)),
            State::Uncovered(ref why) if why.contains("nothing is sampling")
        ));
        // Not judged silent while starting.
        let mut s = PortCoverage::new(t0);
        assert_eq!(
            s.judge(t0 + WINDOW, w(0, 0, SILENT_GAPS * 1000)),
            &State::Starting
        );
    }
}
