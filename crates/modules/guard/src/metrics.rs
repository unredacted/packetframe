//! Prometheus rendering for the guard's counter block. Portable (no
//! cfg gates) so name/index tests run on macOS.

use std::fmt::Write as _;

/// The BPF map value is `[u64; STATS_BLOCK_LEN]`; slots beyond
/// [`COUNTER_COUNT`] are append-only headroom. **Single userspace
/// mirror of `GUARD_STATS_COUNT` in bpf/src/maps.rs** — fast-path's
/// counter list drifted from its BPF twin three separate times before
/// the mirror was centralized; keep this one in one place.
pub const STATS_BLOCK_LEN: usize = 32;

/// Index-aligned mirror of the BPF `GuardStatIdx` enum. Append-only;
/// renaming breaks operator dashboards.
pub const COUNTER_NAMES: [&str; 20] = [
    "total_egress",    // 0
    "pass_no_cfg",     // 1
    "pass_no_match",   // 2
    "err_parse_l2",    // 3
    "err_parse_vlan",  // 4
    "err_parse_arp",   // 5
    "err_parse_ns",    // 6
    "foreign_drop",    // 7
    "lldp_drop",       // 8
    "lldp_monitor",    // 9
    "arp_pass",        // 10
    "arp_drop",        // 11
    "arp_monitor",     // 12
    "ns_pass",         // 13
    "ns_drop",         // 14
    "ns_monitor",      // 15
    "mcast_pass",      // 16
    "mcast_drop",      // 17
    "mcast_monitor",   // 18
    "foreign_monitor", // 19
];

pub const COUNTER_COUNT: usize = COUNTER_NAMES.len();

// Named counters must fit inside the BPF block (headroom is fine,
// overflow is silent truncation).
const _: () = assert!(COUNTER_COUNT <= STATS_BLOCK_LEN);

/// The class/verdict labeling for the twelve rule-outcome counters.
/// `(index, class, verdict)`; everything not listed here renders as a
/// standalone `packetframe_guard_<name>_total` bookkeeping counter.
const FRAME_LABELS: [(usize, &str, &str); 12] = [
    (7, "foreign_src", "dropped"),
    (19, "foreign_src", "monitored"),
    (8, "lldp", "dropped"),
    (9, "lldp", "monitored"),
    (10, "arp", "passed"),
    (11, "arp", "dropped"),
    (12, "arp", "monitored"),
    (13, "ns", "passed"),
    (14, "ns", "dropped"),
    (15, "ns", "monitored"),
    (16, "bcast_mcast", "passed"),
    (17, "bcast_mcast", "dropped"),
];

/// Index 18 belongs in [`FRAME_LABELS`] too; split out only because
/// const arrays are fixed-length and a 13th entry reads worse than
/// this note. Kept adjacent so nobody "fixes" the count.
const FRAME_LABEL_MCAST_MONITOR: (usize, &str, &str) = (18, "bcast_mcast", "monitored");

/// Render the guard counter block as Prometheus text, appended to
/// `out` (the loader's module-gauges slot).
///
/// Two families:
/// - `packetframe_guard_frames_total{class=...,verdict=...}` — the
///   rule outcomes, one series per (class, verdict);
/// - `packetframe_guard_<name>_total` — bookkeeping (total egress,
///   fail-open passes, parse errors).
pub fn render_textfile(stats: &[u64], out: &mut String) {
    let _ = writeln!(
        out,
        "# HELP packetframe_guard_frames_total egress frames per guard class and verdict"
    );
    let _ = writeln!(out, "# TYPE packetframe_guard_frames_total counter");
    for (idx, class, verdict) in FRAME_LABELS.iter().chain([&FRAME_LABEL_MCAST_MONITOR]) {
        let value = stats.get(*idx).copied().unwrap_or(0);
        let _ = writeln!(
            out,
            "packetframe_guard_frames_total{{module=\"guard\",class=\"{class}\",verdict=\"{verdict}\"}} {value}"
        );
    }
    for (idx, name) in COUNTER_NAMES.iter().enumerate() {
        if FRAME_LABELS.iter().any(|(i, _, _)| *i == idx) || idx == FRAME_LABEL_MCAST_MONITOR.0 {
            continue;
        }
        let value = stats.get(idx).copied().unwrap_or(0);
        let metric = format!("packetframe_guard_{name}_total");
        let _ = writeln!(out, "# HELP {metric} guard bookkeeping counter");
        let _ = writeln!(out, "# TYPE {metric} counter");
        let _ = writeln!(out, "{metric}{{module=\"guard\"}} {value}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every named counter renders exactly once — either as a labeled
    /// frames_total series or as a bookkeeping counter — so a future
    /// appended counter that misses both families fails here instead
    /// of silently vanishing from dashboards.
    #[test]
    fn every_counter_renders_exactly_once() {
        let labeled: Vec<usize> = FRAME_LABELS
            .iter()
            .map(|(i, _, _)| *i)
            .chain([FRAME_LABEL_MCAST_MONITOR.0])
            .collect();
        for idx in &labeled {
            assert!(*idx < COUNTER_COUNT, "label index {idx} out of range");
        }
        let mut seen = labeled.clone();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), labeled.len(), "duplicate label index");

        let stats: Vec<u64> = (0..COUNTER_COUNT as u64).map(|i| i + 1).collect();
        let mut out = String::new();
        render_textfile(&stats, &mut out);
        // 13 labeled series + one series line per bookkeeping counter.
        let series_lines = out
            .lines()
            .filter(|l| l.starts_with("packetframe_guard_"))
            .count();
        assert_eq!(series_lines, 13 + (COUNTER_COUNT - 13));
        // Spot-check one of each family, with the index's value.
        assert!(out.contains(
            "packetframe_guard_frames_total{module=\"guard\",class=\"arp\",verdict=\"dropped\"} 12"
        ));
        assert!(out.contains("packetframe_guard_total_egress_total{module=\"guard\"} 1"));
    }
}
