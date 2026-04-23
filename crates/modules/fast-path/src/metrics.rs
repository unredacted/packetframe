//! Prometheus textfile rendering for the fast-path STATS map
//! (SPEC.md §7.3, §4.6).
//!
//! Counter names mirror the `StatIdx` discriminants in
//! `bpf/src/maps.rs`. The order is append-only once v0.1 ships —
//! renumbering `StatIdx` would break operator dashboards — so this
//! table is implicitly ordered by discriminant. Runtime formatting
//! depends on both lists matching: the zipping loop in
//! `render_textfile` assumes `NAMES` and `stats` line up.
//!
//! Phase 3.8 adds a sibling `render_fib_gauges` for custom-FIB
//! occupancy. Those are gauges (not counters), rendered in a separate
//! body so the primary counters surface stays independent of whether
//! the FIB pins are readable.

#[cfg(target_os = "linux")]
use crate::FibStatusSnapshot;
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

/// Render custom-FIB occupancy metrics as Prometheus gauges
/// (Option F, Phase 3.8).
///
/// Output mirrors what `packetframe status` prints in its FIB block,
/// but as a textfile-collector-scrapeable format. `forwarding_mode`
/// is encoded as a one-hot label so PromQL can still aggregate /
/// alert on mode transitions (`packetframe_fib_forwarding_mode{mode="custom-fib"} 1`).
///
/// When the pins aren't readable, `snap` carries its default values
/// (zeroes + `forwarding_mode = None`); rendering proceeds and the
/// scraper sees a consistent set of gauges with zero occupancy.
#[cfg(target_os = "linux")]
pub fn render_fib_gauges(snap: &FibStatusSnapshot) -> String {
    let mut out = String::with_capacity(1024);

    // forwarding_mode one-hot
    let _ = writeln!(
        out,
        "# HELP packetframe_fib_forwarding_mode 1 for the active forwarding mode, 0 otherwise"
    );
    let _ = writeln!(out, "# TYPE packetframe_fib_forwarding_mode gauge");
    for mode in ["kernel-fib", "custom-fib", "compare"] {
        let active = snap.forwarding_mode == Some(mode);
        let _ = writeln!(
            out,
            "packetframe_fib_forwarding_mode{{module=\"fast-path\",mode=\"{mode}\"}} {}",
            u8::from(active),
        );
    }

    // default hash mode (present only when the CFG pin is readable)
    if let Some(mode) = snap.default_hash_mode {
        let _ = writeln!(
            out,
            "# HELP packetframe_fib_default_hash_mode ECMP default hash mode (3/4/5-tuple)"
        );
        let _ = writeln!(out, "# TYPE packetframe_fib_default_hash_mode gauge");
        let _ = writeln!(
            out,
            "packetframe_fib_default_hash_mode{{module=\"fast-path\"}} {mode}"
        );
    }

    // NEXTHOPS state buckets
    let _ = writeln!(
        out,
        "# HELP packetframe_nexthops nexthop-entry count per state bucket"
    );
    let _ = writeln!(out, "# TYPE packetframe_nexthops gauge");
    let _ = writeln!(
        out,
        "packetframe_nexthops{{module=\"fast-path\",state=\"resolved\"}} {}",
        snap.nh_resolved
    );
    let _ = writeln!(
        out,
        "packetframe_nexthops{{module=\"fast-path\",state=\"failed\"}} {}",
        snap.nh_failed
    );
    let _ = writeln!(
        out,
        "packetframe_nexthops{{module=\"fast-path\",state=\"stale\"}} {}",
        snap.nh_stale
    );
    let _ = writeln!(
        out,
        "packetframe_nexthops{{module=\"fast-path\",state=\"unwritten_or_incomplete\"}} {}",
        snap.nh_unwritten_or_incomplete
    );
    let _ = writeln!(
        out,
        "# HELP packetframe_nexthops_max configured NEXTHOPS map capacity"
    );
    let _ = writeln!(out, "# TYPE packetframe_nexthops_max gauge");
    let _ = writeln!(
        out,
        "packetframe_nexthops_max{{module=\"fast-path\"}} {}",
        snap.nh_max_entries
    );

    // ECMP groups
    let _ = writeln!(
        out,
        "# HELP packetframe_ecmp_groups_active ECMP groups with nh_count > 0"
    );
    let _ = writeln!(out, "# TYPE packetframe_ecmp_groups_active gauge");
    let _ = writeln!(
        out,
        "packetframe_ecmp_groups_active{{module=\"fast-path\"}} {}",
        snap.ecmp_active
    );
    let _ = writeln!(
        out,
        "# HELP packetframe_ecmp_groups_max configured ECMP_GROUPS map capacity"
    );
    let _ = writeln!(out, "# TYPE packetframe_ecmp_groups_max gauge");
    let _ = writeln!(
        out,
        "packetframe_ecmp_groups_max{{module=\"fast-path\"}} {}",
        snap.ecmp_max_entries
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

    #[cfg(target_os = "linux")]
    #[test]
    fn fib_gauges_emit_forwarding_mode_onehot() {
        let snap = FibStatusSnapshot {
            forwarding_mode: Some("custom-fib"),
            default_hash_mode: Some(5),
            nh_resolved: 12,
            nh_failed: 1,
            nh_stale: 0,
            nh_unwritten_or_incomplete: 8179,
            nh_max_entries: 8192,
            ecmp_active: 3,
            ecmp_max_entries: 1024,
        };
        let body = render_fib_gauges(&snap);
        assert!(body.contains(
            "packetframe_fib_forwarding_mode{module=\"fast-path\",mode=\"custom-fib\"} 1"
        ));
        assert!(body.contains(
            "packetframe_fib_forwarding_mode{module=\"fast-path\",mode=\"kernel-fib\"} 0"
        ));
        assert!(body
            .contains("packetframe_fib_forwarding_mode{module=\"fast-path\",mode=\"compare\"} 0"));
        assert!(body.contains("packetframe_fib_default_hash_mode{module=\"fast-path\"} 5"));
        assert!(body.contains("packetframe_nexthops{module=\"fast-path\",state=\"resolved\"} 12"));
        assert!(body.contains("packetframe_nexthops{module=\"fast-path\",state=\"failed\"} 1"));
        assert!(body.contains("packetframe_nexthops_max{module=\"fast-path\"} 8192"));
        assert!(body.contains("packetframe_ecmp_groups_active{module=\"fast-path\"} 3"));
        assert!(body.contains("packetframe_ecmp_groups_max{module=\"fast-path\"} 1024"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fib_gauges_handle_unreadable_pins() {
        // All zeroes / None is what fib_status_from_pin returns when
        // the pins aren't there (e.g., kernel-fib mode or first boot).
        let snap = FibStatusSnapshot {
            forwarding_mode: None,
            default_hash_mode: None,
            nh_resolved: 0,
            nh_failed: 0,
            nh_stale: 0,
            nh_unwritten_or_incomplete: 0,
            nh_max_entries: 0,
            ecmp_active: 0,
            ecmp_max_entries: 0,
        };
        let body = render_fib_gauges(&snap);
        // With `forwarding_mode: None`, no mode is "active" — every
        // one-hot emits 0.
        assert!(body.contains(
            "packetframe_fib_forwarding_mode{module=\"fast-path\",mode=\"custom-fib\"} 0"
        ));
        assert!(body.contains(
            "packetframe_fib_forwarding_mode{module=\"fast-path\",mode=\"kernel-fib\"} 0"
        ));
        // default_hash_mode absent when the CFG pin isn't readable —
        // scrapers see the metric simply not emitted.
        assert!(!body.contains("packetframe_fib_default_hash_mode"));
        assert!(body.contains("packetframe_nexthops_max{module=\"fast-path\"} 0"));
    }
}
