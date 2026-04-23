//! Circuit breaker (SPEC.md §4.9, §8.3).
//!
//! A sampler thread polls the pinned STATS map every `window` seconds
//! and computes the ratio of "bad" outcomes (`drop_unreachable +
//! err_fib_other`) to matched traffic (`matched_v4 + matched_v6`) over
//! the interval since the previous sample. If the ratio exceeds the
//! configured drop-ratio for `threshold` consecutive samples, the
//! breaker trips: writes a sticky flag under the state directory and
//! raises SIGUSR1 so the main loop can detach the module.
//!
//! The state-dir flag survives a kernel reboot — that's deliberate.
//! A tripped breaker refuses to re-attach on subsequent `packetframe
//! run` invocations until an operator clears it. This matches SPEC
//! §8.3's "sticky detach" requirement.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use packetframe_common::config::CircuitBreakerSpec;

use crate::MODULE_NAME;

/// Discriminants from `bpf/src/maps.rs::StatIdx`. Wire format is
/// append-only, so these indexes are stable once v0.1 ships.
const STAT_MATCHED_V4: usize = 1;
const STAT_MATCHED_V6: usize = 2;
const STAT_DROP_UNREACHABLE: usize = 13;
const STAT_ERR_FIB_OTHER: usize = 15;

pub fn trip_flag_path(state_dir: &Path) -> PathBuf {
    state_dir.join(format!("breaker-tripped-{MODULE_NAME}.flag"))
}

pub fn is_tripped(state_dir: &Path) -> bool {
    trip_flag_path(state_dir).exists()
}

/// Write the sticky trip flag. Best-effort: if the write fails,
/// the main-loop detach still proceeds; the worst case is that the
/// next restart re-attaches a breaker whose condition may have
/// cleared — operator sees the same trip again.
pub fn write_trip_flag(
    state_dir: &Path,
    ratio: f64,
    window_drops: u64,
    window_matched: u64,
    spec: &CircuitBreakerSpec,
) -> std::io::Result<()> {
    let path = trip_flag_path(state_dir);
    let body = format!(
        "module: {MODULE_NAME}\n\
         tripped_at: {:?}\n\
         observed_ratio: {ratio}\n\
         threshold_ratio: {}\n\
         window_drops: {window_drops}\n\
         window_matched: {window_matched}\n\
         consecutive_samples_over: {}\n",
        SystemTime::now(),
        spec.drop_ratio,
        spec.threshold,
    );
    std::fs::write(path, body)
}

/// What the sampler observed, minus I/O on STATS itself.
#[derive(Debug)]
pub enum Decision {
    /// No matched traffic since last sample — can't divide.
    NoData,
    /// Under threshold.
    Ok { ratio: f64 },
    /// Over threshold but streak hasn't reached `threshold` samples yet.
    Bad { ratio: f64, streak: u32 },
    /// Streak reached `threshold` — trip.
    Trip {
        ratio: f64,
        window_drops: u64,
        window_matched: u64,
    },
}

/// Stateful sliding-window evaluator. One instance per module. Owned
/// by the sampler thread.
pub struct CircuitBreaker {
    spec: CircuitBreakerSpec,
    prev_matched: u64,
    prev_drops: u64,
    consecutive_bad: u32,
    primed: bool,
}

impl CircuitBreaker {
    pub fn new(spec: CircuitBreakerSpec) -> Self {
        Self {
            spec,
            prev_matched: 0,
            prev_drops: 0,
            consecutive_bad: 0,
            primed: false,
        }
    }

    /// Feed one STATS snapshot. Returns the sampler's verdict. The
    /// first call primes the deltas but returns `NoData`.
    pub fn sample(&mut self, stats: &[u64]) -> Decision {
        assert!(
            stats.len() > STAT_ERR_FIB_OTHER,
            "STATS vec too short ({})",
            stats.len()
        );
        let matched_total = stats[STAT_MATCHED_V4] + stats[STAT_MATCHED_V6];
        let drops_total = stats[STAT_DROP_UNREACHABLE] + stats[STAT_ERR_FIB_OTHER];

        if !self.primed {
            self.prev_matched = matched_total;
            self.prev_drops = drops_total;
            self.primed = true;
            return Decision::NoData;
        }

        let matched_delta = matched_total.saturating_sub(self.prev_matched);
        let drops_delta = drops_total.saturating_sub(self.prev_drops);
        self.prev_matched = matched_total;
        self.prev_drops = drops_total;

        if matched_delta == 0 {
            // Keep the streak counter as-is; no matched traffic means
            // we can't judge. Don't reset it to 0 (that would let
            // a sustained bad period "escape" by alternating busy
            // and idle windows).
            return Decision::NoData;
        }

        let ratio = drops_delta as f64 / matched_delta as f64;
        if ratio > self.spec.drop_ratio {
            self.consecutive_bad += 1;
            if self.consecutive_bad >= self.spec.threshold {
                return Decision::Trip {
                    ratio,
                    window_drops: drops_delta,
                    window_matched: matched_delta,
                };
            }
            Decision::Bad {
                ratio,
                streak: self.consecutive_bad,
            }
        } else {
            self.consecutive_bad = 0;
            Decision::Ok { ratio }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn spec(ratio: f64, threshold: u32) -> CircuitBreakerSpec {
        CircuitBreakerSpec {
            drop_ratio: ratio,
            denominator: packetframe_common::config::CircuitBreakerDenominator::Matched,
            window: Duration::from_secs(5),
            threshold,
        }
    }

    fn stats(matched_v4: u64, drops: u64) -> Vec<u64> {
        // Matches STATS_COUNT in bpf/src/maps.rs (32 after the Option F
        // Phase 1 additions). Was 19 pre-Phase-1 — that was already
        // off-by-one against the 20-variant StatIdx enum; fixed in
        // passing by the custom-FIB work that bumped STATS_COUNT.
        let mut s = vec![0u64; crate::metrics::COUNTER_NAMES.len()];
        s[STAT_MATCHED_V4] = matched_v4;
        s[STAT_DROP_UNREACHABLE] = drops;
        s
    }

    #[test]
    fn first_sample_primes_then_returns_no_data() {
        let mut b = CircuitBreaker::new(spec(0.01, 3));
        assert!(matches!(b.sample(&stats(100, 0)), Decision::NoData));
    }

    #[test]
    fn healthy_traffic_reports_ok() {
        let mut b = CircuitBreaker::new(spec(0.01, 3));
        let _ = b.sample(&stats(100, 0));
        let d = b.sample(&stats(200, 0));
        assert!(matches!(d, Decision::Ok { .. }));
    }

    #[test]
    fn trip_after_threshold_consecutive_bad() {
        let mut b = CircuitBreaker::new(spec(0.01, 3));
        // Prime.
        let _ = b.sample(&stats(100, 0));
        // Each sample: +1000 matched, +50 drops → ratio=0.05 > 0.01.
        assert!(matches!(
            b.sample(&stats(1100, 50)),
            Decision::Bad { streak: 1, .. }
        ));
        assert!(matches!(
            b.sample(&stats(2100, 100)),
            Decision::Bad { streak: 2, .. }
        ));
        assert!(matches!(b.sample(&stats(3100, 150)), Decision::Trip { .. }));
    }

    #[test]
    fn one_good_sample_resets_streak() {
        let mut b = CircuitBreaker::new(spec(0.01, 3));
        let _ = b.sample(&stats(100, 0));
        let _ = b.sample(&stats(1100, 50)); // bad 1
        let _ = b.sample(&stats(2100, 100)); // bad 2
        let _ = b.sample(&stats(3100, 100)); // good (no new drops)
                                             // Streak reset; one more bad should only be streak=1.
        assert!(matches!(
            b.sample(&stats(4100, 150)),
            Decision::Bad { streak: 1, .. }
        ));
    }

    #[test]
    fn zero_matched_is_no_data_not_ok() {
        let mut b = CircuitBreaker::new(spec(0.01, 3));
        let _ = b.sample(&stats(100, 0));
        // Drops happen but no matched traffic since prime.
        assert!(matches!(b.sample(&stats(100, 10)), Decision::NoData));
    }
}
