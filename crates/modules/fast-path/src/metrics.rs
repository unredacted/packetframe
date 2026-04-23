//! Prometheus textfile rendering for the fast-path STATS map
//! (SPEC.md §7.3, §4.6).
//!
//! Counter names mirror the `StatIdx` discriminants in
//! `bpf/src/maps.rs`. The order is append-only once v0.1 ships —
//! renumbering `StatIdx` would break operator dashboards — so this
//! table is implicitly ordered by discriminant. Runtime formatting
//! depends on both lists matching: the zipping loop in
//! `render_textfile` assumes `NAMES` and `stats` line up.

use std::fmt::Write as _;

/// Wire-format counter names, index-aligned with `StatIdx` in
/// `bpf/src/maps.rs`. These become the `packetframe_<name>_total`
/// metric names; changing any value changes the operator-facing
/// metric name. Append-only — renumbering breaks dashboards.
///
/// Phase 1 (Option F custom FIB): length grew from 19 → 32. The
/// pre-existing 19 was already off-by-one (`err_head_shift` at
/// index 19 silently dropped); fixed in passing. Indices 20-31 are
/// the new custom-FIB counters.
pub const COUNTER_NAMES: [&str; 32] = [
    "rx_total",
    "matched_v4",
    "matched_v6",
    "matched_src_only",
    "matched_dst_only",
    "matched_both",
    "fwd_ok",
    "fwd_dry_run",
    "pass_fragment",
    "pass_low_ttl",
    "pass_no_neigh",
    "pass_not_ip",
    "pass_frag_needed",
    "drop_unreachable",
    "err_parse",
    "err_fib_other",
    "err_vlan",
    "pass_not_in_devmap",
    "pass_complex_header",
    "err_head_shift",
    // --- Custom FIB (Option F, Phase 1) ---
    "custom_fib_hit",
    "custom_fib_miss",
    "custom_fib_no_neigh",
    "compare_agree",
    "compare_disagree",
    "ecmp_hash_v4",
    "ecmp_hash_v6",
    "ecmp_dead_leg_fallback",
    "route_source_resync",
    "neigh_cache_miss",
    "nexthop_seq_retry",
    "bmp_peer_down",
];

/// Render a Prometheus textfile body from stat values + module uptime.
/// Every counter gets `# TYPE` and `# HELP` headers so Prometheus's
/// textfile collector categorizes it correctly. Counter names that
/// already end in `_total` (e.g. `rx_total`) get emitted as-is —
/// Prometheus convention requires one `_total` suffix, not two.
pub fn render_textfile(stats: &[u64], uptime_seconds: u64) -> String {
    let mut out = String::with_capacity(4096);
    for (name, value) in COUNTER_NAMES.iter().zip(stats.iter()) {
        let metric = if name.ends_with("_total") {
            format!("packetframe_{name}")
        } else {
            format!("packetframe_{name}_total")
        };
        let _ = writeln!(out, "# HELP {metric} fast-path §4.6 counter");
        let _ = writeln!(out, "# TYPE {metric} counter");
        let _ = writeln!(out, "{metric}{{module=\"fast-path\"}} {value}");
    }
    let _ = writeln!(
        out,
        "# HELP packetframe_uptime_seconds seconds since the fast-path module attached"
    );
    let _ = writeln!(out, "# TYPE packetframe_uptime_seconds gauge");
    let _ = writeln!(
        out,
        "packetframe_uptime_seconds{{module=\"fast-path\"}} {uptime_seconds}"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_names_match_stats_count() {
        // Mirror of `STATS_COUNT` from `bpf/src/maps.rs`. If these
        // drift, the zip() in render_textfile silently truncates —
        // this test catches that at unit-test time.
        assert_eq!(COUNTER_NAMES.len(), 32);
    }

    #[test]
    fn rendered_output_contains_every_counter() {
        let stats = vec![0u64; COUNTER_NAMES.len()];
        let body = render_textfile(&stats, 42);
        for name in COUNTER_NAMES {
            let metric = if name.ends_with("_total") {
                format!("packetframe_{name}")
            } else {
                format!("packetframe_{name}_total")
            };
            let line = format!("{metric}{{module=\"fast-path\"}} 0");
            assert!(body.contains(&line), "missing line: {line}");
        }
        assert!(body.contains("packetframe_uptime_seconds{module=\"fast-path\"} 42"));
    }

    #[test]
    fn counter_names_ending_in_total_are_not_double_suffixed() {
        let stats = vec![0u64; COUNTER_NAMES.len()];
        let body = render_textfile(&stats, 0);
        assert!(body.contains("packetframe_rx_total{module=\"fast-path\"}"));
        assert!(!body.contains("packetframe_rx_total_total"));
    }

    #[test]
    fn rendered_output_has_type_header_per_counter() {
        let stats = vec![1u64; COUNTER_NAMES.len()];
        let body = render_textfile(&stats, 0);
        let type_lines = body.lines().filter(|l| l.starts_with("# TYPE")).count();
        // COUNTER_NAMES.len() counters + 1 uptime gauge.
        assert_eq!(type_lines, COUNTER_NAMES.len() + 1);
    }
}
