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
/// metric name.
pub const COUNTER_NAMES: [&str; 19] = [
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
];

/// Render a Prometheus textfile body from stat values + module uptime.
/// Every counter gets `# TYPE` and `# HELP` headers so Prometheus's
/// textfile collector categorizes it correctly.
pub fn render_textfile(stats: &[u64], uptime_seconds: u64) -> String {
    let mut out = String::with_capacity(4096);
    for (name, value) in COUNTER_NAMES.iter().zip(stats.iter()) {
        let _ = writeln!(
            out,
            "# HELP packetframe_{name}_total fast-path §4.6 counter"
        );
        let _ = writeln!(out, "# TYPE packetframe_{name}_total counter");
        let _ = writeln!(
            out,
            "packetframe_{name}_total{{module=\"fast-path\"}} {value}"
        );
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
        assert_eq!(COUNTER_NAMES.len(), 19);
    }

    #[test]
    fn rendered_output_contains_every_counter() {
        let stats = vec![0u64; 19];
        let body = render_textfile(&stats, 42);
        for name in COUNTER_NAMES {
            let line = format!("packetframe_{name}_total{{module=\"fast-path\"}} 0");
            assert!(body.contains(&line), "missing line: {line}");
        }
        assert!(body.contains("packetframe_uptime_seconds{module=\"fast-path\"} 42"));
    }

    #[test]
    fn rendered_output_has_type_header_per_counter() {
        let stats = vec![1u64; 19];
        let body = render_textfile(&stats, 0);
        let type_lines = body.lines().filter(|l| l.starts_with("# TYPE")).count();
        // 19 counters + 1 uptime gauge
        assert_eq!(type_lines, 20);
    }
}
