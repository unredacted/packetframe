//! Prometheus rendering of a [`Snapshot`], appended to the loader's
//! module-gauges slot via `Module::sample_metrics`. Portable.
//!
//! Every counter array in [`Counters`] renders as one labelled family;
//! the test below asserts the series count equals the sum of the
//! array lengths plus the scalars, so a counter added to an enum
//! cannot vanish from dashboards.

use std::fmt::Write as _;

use crate::frame::{Reject, Source};
use crate::snapshot::{
    Counters, CoverageState, GateOutcome, InstallOutcome, LearnOutcome, LinkEvent, LinkState,
    PersistOutcome, SeedOutcome, Snapshot,
};
use crate::table::FilterReject;

const NS: &str = "packetframe_neigh_snoop";

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {NS}_{name} {help}");
    let _ = writeln!(out, "# TYPE {NS}_{name} {kind}");
}

/// Escape an operator-supplied label value for the text exposition
/// format. Interface names may contain `"` (the kernel allows it and
/// `validate_iface_name` follows the kernel); one unbalanced quote
/// makes the textfile collector reject the whole file, every module's
/// metrics included.
fn label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn labelled(out: &mut String, name: &str, iface: &str, label_name: &str, values: &[(&str, u64)]) {
    let iface = label(iface);
    for (v, n) in values {
        let _ = writeln!(
            out,
            "{NS}_{name}{{module=\"neigh-snoop\",iface=\"{iface}\",{label_name}=\"{v}\"}} {n}"
        );
    }
}

fn scalar(out: &mut String, name: &str, iface: &str, value: impl std::fmt::Display) {
    let iface = label(iface);
    let _ = writeln!(
        out,
        "{NS}_{name}{{module=\"neigh-snoop\",iface=\"{iface}\"}} {value}"
    );
}

fn pairs<'a>(labels: &'a [&'a str], values: &'a [u64]) -> Vec<(&'a str, u64)> {
    labels.iter().copied().zip(values.iter().copied()).collect()
}

/// The counter families, in render order. Kept as data so the test
/// and the renderer cannot disagree about what exists.
struct Family {
    name: &'static str,
    label: &'static str,
    help: &'static str,
    labels: &'static [&'static str],
    pick: fn(&Counters) -> &[u64],
}

const FAMILIES: [Family; 8] = [
    Family {
        name: "frames_total",
        label: "kind",
        help: "learnable frames parsed, by frame type",
        labels: &Source::LABELS,
        pick: |c| &c.frames,
    },
    Family {
        name: "learn_total",
        label: "outcome",
        help: "learned-table outcomes",
        labels: &LearnOutcome::LABELS,
        pick: |c| &c.learn,
    },
    Family {
        name: "filter_rejects_total",
        label: "reason",
        help: "pairs refused by the admission filter",
        labels: &FilterReject::LABELS,
        pick: |c| &c.filter_rejects,
    },
    Family {
        name: "parse_rejects_total",
        label: "reason",
        help: "frames refused by the parser",
        labels: &Reject::LABELS,
        pick: |c| &c.parse_rejects,
    },
    Family {
        name: "install_total",
        label: "outcome",
        help: "kernel neighbour install decisions and results (confirmed = RTM_NEWNEIGH echo seen)",
        labels: &InstallOutcome::LABELS,
        pick: |c| &c.installs,
    },
    Family {
        name: "seed_total",
        label: "outcome",
        help: "persisted-table seeding outcomes",
        labels: &SeedOutcome::LABELS,
        pick: |c| &c.seeds,
    },
    Family {
        name: "persist_total",
        label: "outcome",
        help: "learned-table file writes",
        labels: &PersistOutcome::LABELS,
        pick: |c| &c.persist,
    },
    Family {
        name: "link_events_total",
        label: "kind",
        help: "bridge link events seen by name",
        labels: &LinkEvent::LABELS,
        pick: |c| &c.link_events,
    },
];

/// A counter without a label dimension.
struct ScalarCounter {
    name: &'static str,
    help: &'static str,
    pick: fn(&Counters) -> u64,
}

const SCALAR_COUNTERS: [ScalarCounter; 3] = [
    ScalarCounter {
        name: "socket_errors_total",
        help: "capture socket errors",
        pick: |c| c.socket_errors,
    },
    ScalarCounter {
        name: "frames_outgoing_dropped_total",
        help: "outgoing frames that reached userspace despite the filter",
        pick: |c| c.frames_outgoing_dropped,
    },
    ScalarCounter {
        name: "frames_backpressure_dropped_total",
        help: "frames dropped because the engine channel was full",
        pick: |c| c.frames_backpressure_dropped,
    },
];

/// Render `snapshot` into `out`. Emits nothing for an empty snapshot,
/// so an unattached module publishes no series (never zeros that read
/// as healthy-idle).
pub fn render_textfile(snapshot: &Snapshot, out: &mut String) {
    if snapshot.bridges.is_empty() {
        return;
    }
    for f in &FAMILIES {
        family(out, f.name, "counter", f.help);
        for b in &snapshot.bridges {
            labelled(
                out,
                f.name,
                &b.name,
                f.label,
                &pairs(f.labels, (f.pick)(&b.counters)),
            );
        }
    }
    for sc in &SCALAR_COUNTERS {
        family(out, sc.name, "counter", sc.help);
        for b in &snapshot.bridges {
            scalar(out, sc.name, &b.name, (sc.pick)(&b.counters));
        }
    }

    family(
        out,
        "table_entries",
        "gauge",
        "learned pairs held per bridge",
    );
    for b in &snapshot.bridges {
        scalar(out, "table_entries", &b.name, b.table_entries);
    }
    family(
        out,
        "link_up",
        "gauge",
        "1 when the bridge exists and is up",
    );
    for b in &snapshot.bridges {
        scalar(out, "link_up", &b.name, u8::from(b.link == LinkState::Up));
    }
    family(
        out,
        "promisc_confirmed",
        "gauge",
        "1 when the kernel echoed IFF_PROMISC for the bridge after our membership request",
    );
    for b in &snapshot.bridges {
        scalar(
            out,
            "promisc_confirmed",
            &b.name,
            u8::from(b.promisc_confirmed),
        );
    }
    family(
        out,
        "install_backlog",
        "gauge",
        "installs queued behind the rate limiter",
    );
    for b in &snapshot.bridges {
        scalar(out, "install_backlog", &b.name, b.install_backlog);
    }
    family(
        out,
        "peers",
        "gauge",
        "configured peer addresses by whether they have been heard",
    );
    for b in &snapshot.bridges {
        let never = b.never_heard.len() as u64;
        labelled(
            out,
            "peers",
            &b.name,
            "state",
            &[
                ("heard", b.peers_total.saturating_sub(never)),
                ("never_heard", never),
            ],
        );
    }
    family(
        out,
        "participant_addresses",
        "gauge",
        "learned addresses by whether their kernel entry currently resolves",
    );
    for b in &snapshot.bridges {
        let r = b.participant_coverage;
        labelled(
            out,
            "participant_addresses",
            &b.name,
            "state",
            &[
                ("resolved", r.resolved),
                ("unresolved", r.total.saturating_sub(r.resolved)),
            ],
        );
    }
    family(
        out,
        "route_nexthops",
        "gauge",
        "distinct next-hops of kernel routes via the bridge, by resolution (absent until measured)",
    );
    for b in &snapshot.bridges {
        if let CoverageState::Measured(c) = &b.route_coverage {
            labelled(
                out,
                "route_nexthops",
                &b.name,
                "state",
                &[
                    ("resolved", c.nexthops.resolved),
                    (
                        "unresolved",
                        c.nexthops.total.saturating_sub(c.nexthops.resolved),
                    ),
                ],
            );
        }
    }
    family(
        out,
        "nexthop_objects",
        "gauge",
        "kernel nexthop objects seen via the bridge",
    );
    family(
        out,
        "coverage_dump_ms",
        "gauge",
        "wall time of the last coverage dump",
    );
    family(
        out,
        "coverage_age_seconds",
        "gauge",
        "age of the last coverage sample",
    );
    for b in &snapshot.bridges {
        if let CoverageState::Measured(c) = &b.route_coverage {
            scalar(out, "nexthop_objects", &b.name, c.nexthop_objects);
            scalar(out, "coverage_dump_ms", &b.name, c.dump_ms);
            scalar(out, "coverage_age_seconds", &b.name, c.age_secs);
        }
    }

    if let Some(g) = &snapshot.gate {
        let gauge = |out: &mut String, name: &str, v: u64| {
            let _ = writeln!(out, "{NS}_{name}{{module=\"neigh-snoop\"}} {v}");
        };
        family(
            out,
            "gate_reconcile_total",
            "counter",
            "FRR next-hop gate reconcile ticks by outcome",
        );
        for (label, v) in GateOutcome::LABELS.iter().zip(g.outcomes.iter()) {
            let _ = writeln!(
                out,
                "{NS}_gate_reconcile_total{{module=\"neigh-snoop\",outcome=\"{label}\"}} {v}"
            );
        }
        family(
            out,
            "gate_permitted_nexthops",
            "gauge",
            "runtime entries currently in the gate lists",
        );
        for (fam, v) in [("v4", g.permitted_v4), ("v6", g.permitted_v6)] {
            let _ = writeln!(
                out,
                "{NS}_gate_permitted_nexthops{{module=\"neigh-snoop\",family=\"{fam}\"}} {v}"
            );
        }
        family(
            out,
            "gate_pending_removals",
            "gauge",
            "listed addresses unresolved but inside the removal hysteresis",
        );
        gauge(out, "gate_pending_removals", g.pending_removals);
        family(
            out,
            "gate_lists_present",
            "gauge",
            "1 when both gate prefix-lists exist in FRR",
        );
        gauge(out, "gate_lists_present", u64::from(g.lists_present));
        family(
            out,
            "gate_vtysh_ms",
            "gauge",
            "wall time of the last reconcile tick",
        );
        gauge(out, "gate_vtysh_ms", g.vtysh_ms);
        family(
            out,
            "gate_consecutive_failures",
            "gauge",
            "reconcile ticks failed in a row",
        );
        gauge(
            out,
            "gate_consecutive_failures",
            u64::from(g.consecutive_failures),
        );
    }

    if !snapshot.rs.is_empty() {
        let rs_gauge = |out: &mut String, name: &str, rs: &str, iface: &str, v: u64| {
            let _ = writeln!(
                out,
                "{NS}_{name}{{module=\"neigh-snoop\",iface=\"{iface}\",rs=\"{rs}\"}} {v}"
            );
        };
        family(
            out,
            "rs_received_prefixes",
            "gauge",
            "prefixes received from the route server",
        );
        family(
            out,
            "rs_received_nexthops",
            "gauge",
            "distinct next-hops among them",
        );
        family(
            out,
            "rs_unresolved_nexthops",
            "gauge",
            "next-hops neither bilateral nor resolved",
        );
        family(
            out,
            "rs_demoted_prefixes",
            "gauge",
            "received prefixes the gate keeps below transit",
        );
        family(
            out,
            "rs_dump_ms",
            "gauge",
            "wall time of the last received-routes dump",
        );
        family(out, "rs_dump_ok", "gauge", "1 when the last dump parsed");
        for r in &snapshot.rs {
            let rs = r.rs.to_string();
            rs_gauge(
                out,
                "rs_received_prefixes",
                &rs,
                &r.bridge,
                r.received_prefixes,
            );
            rs_gauge(
                out,
                "rs_received_nexthops",
                &rs,
                &r.bridge,
                r.nexthops.total,
            );
            rs_gauge(
                out,
                "rs_unresolved_nexthops",
                &rs,
                &r.bridge,
                r.nexthops.total.saturating_sub(r.nexthops.resolved),
            );
            rs_gauge(
                out,
                "rs_demoted_prefixes",
                &rs,
                &r.bridge,
                r.demoted_prefixes,
            );
            rs_gauge(out, "rs_dump_ms", &rs, &r.bridge, r.dump_ms);
            rs_gauge(
                out,
                "rs_dump_ok",
                &rs,
                &r.bridge,
                u64::from(r.error.is_none()),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{Coverage, IfaceSnapshot, Ratio};

    fn dense_counters() -> Counters {
        let mut c = Counters::default();
        let mut v = 1u64;
        for f in &FAMILIES {
            let n = (f.pick)(&c).len();
            // Fill through the mutable arrays by name.
            let arr: &mut [u64] = match f.name {
                "frames_total" => &mut c.frames,
                "learn_total" => &mut c.learn,
                "filter_rejects_total" => &mut c.filter_rejects,
                "parse_rejects_total" => &mut c.parse_rejects,
                "install_total" => &mut c.installs,
                "seed_total" => &mut c.seeds,
                "persist_total" => &mut c.persist,
                "link_events_total" => &mut c.link_events,
                other => panic!("unlisted family {other}"),
            };
            assert_eq!(arr.len(), n);
            for slot in arr.iter_mut() {
                *slot = v;
                v += 1;
            }
        }
        c.socket_errors = v;
        c.frames_outgoing_dropped = v + 1;
        c.frames_backpressure_dropped = v + 2;
        c
    }

    /// Every counter renders exactly once, as a labelled or scalar
    /// series, and every family's label list matches its array length.
    #[test]
    fn every_counter_renders_exactly_once() {
        let counters = dense_counters();
        let snap = Snapshot {
            bridges: vec![IfaceSnapshot {
                name: "br0".into(),
                link: LinkState::Up,
                table_entries: 7,
                counters: counters.clone(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut out = String::new();
        render_textfile(&snap, &mut out);

        let mut expected_counter_series = 0usize;
        for f in &FAMILIES {
            assert_eq!(f.labels.len(), (f.pick)(&counters).len(), "{}", f.name);
            expected_counter_series += f.labels.len();
        }
        expected_counter_series += SCALAR_COUNTERS.len();
        let counter_lines = out
            .lines()
            .filter(|l| l.starts_with(NS) && l.contains("_total{"))
            .count();
        assert_eq!(counter_lines, expected_counter_series);

        // Values are distinct, so a duplicated or misindexed slot
        // shows up as a repeated number.
        let mut values: Vec<u64> = out
            .lines()
            .filter(|l| l.starts_with(NS) && l.contains("_total{"))
            .map(|l| l.rsplit(' ').next().unwrap().parse().unwrap())
            .collect();
        values.sort_unstable();
        values.dedup();
        assert_eq!(values.len(), expected_counter_series);

        assert!(out.contains(
            "packetframe_neigh_snoop_frames_total{module=\"neigh-snoop\",iface=\"br0\",kind=\"arp_request\"} 1"
        ));
        assert!(out.contains(
            "packetframe_neigh_snoop_install_total{module=\"neigh-snoop\",iface=\"br0\",outcome=\"mac_conflict\"}"
        ));
        assert!(out.contains(
            "packetframe_neigh_snoop_table_entries{module=\"neigh-snoop\",iface=\"br0\"} 7"
        ));
        assert!(
            out.contains("packetframe_neigh_snoop_link_up{module=\"neigh-snoop\",iface=\"br0\"} 1")
        );
        // Pending coverage renders no route_nexthops series.
        assert!(!out.contains("route_nexthops{"));
    }

    #[test]
    fn interface_names_are_escaped_and_quotes_stay_balanced() {
        assert_eq!(label("br0"), "br0");
        assert_eq!(label("br\"0"), "br\\\"0");
        assert_eq!(label("a\\b"), "a\\\\b");
        let snap = Snapshot {
            bridges: vec![IfaceSnapshot {
                name: "br\"0".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut out = String::new();
        render_textfile(&snap, &mut out);
        assert!(out.contains(r#"iface="br\"0""#), "{out}");
        for line in out.lines().filter(|l| !l.starts_with('#')) {
            let unescaped = line
                .char_indices()
                .filter(|(i, c)| *c == '"' && (*i == 0 || line.as_bytes()[i - 1] != b'\\'))
                .count();
            assert_eq!(unescaped % 2, 0, "unbalanced quotes in: {line}");
        }
    }

    #[test]
    fn gate_and_rs_render_when_present() {
        use crate::snapshot::{GateSnapshot, RsCoverageSnapshot};
        let mut outcomes = [0u64; GateOutcome::COUNT];
        outcomes[GateOutcome::Changed.index()] = 3;
        let snap = Snapshot {
            bridges: vec![IfaceSnapshot {
                name: "br0".into(),
                ..Default::default()
            }],
            gate: Some(GateSnapshot {
                lists_present: true,
                permitted_v4: 12,
                permitted_v6: 4,
                pending_removals: 1,
                outcomes,
                ..Default::default()
            }),
            rs: vec![RsCoverageSnapshot {
                rs: "192.0.2.2".parse().unwrap(),
                bridge: "br0".into(),
                received_prefixes: 100,
                nexthops: Ratio {
                    resolved: 8,
                    total: 10,
                },
                unresolved_nexthops: vec![],
                demoted_prefixes: 7,
                dump_ms: 900,
                age_secs: 0,
                error: None,
            }],
        };
        let mut out = String::new();
        render_textfile(&snap, &mut out);
        assert!(out.contains("gate_reconcile_total{module=\"neigh-snoop\",outcome=\"changed\"} 3"));
        assert!(out.contains("gate_permitted_nexthops{module=\"neigh-snoop\",family=\"v4\"} 12"));
        assert!(out.contains("gate_pending_removals{module=\"neigh-snoop\"} 1"));
        assert!(out.contains(
            "rs_demoted_prefixes{module=\"neigh-snoop\",iface=\"br0\",rs=\"192.0.2.2\"} 7"
        ));
        assert!(out.contains(
            "rs_unresolved_nexthops{module=\"neigh-snoop\",iface=\"br0\",rs=\"192.0.2.2\"} 2"
        ));
        assert!(out.contains("rs_dump_ok{module=\"neigh-snoop\",iface=\"br0\",rs=\"192.0.2.2\"} 1"));
    }

    #[test]
    fn empty_snapshot_renders_nothing() {
        let mut out = String::new();
        render_textfile(&Snapshot::default(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn measured_coverage_and_peers_render() {
        let snap = Snapshot {
            bridges: vec![IfaceSnapshot {
                name: "br1".into(),
                peers_total: 3,
                never_heard: vec!["192.0.2.9".parse().unwrap()],
                participant_coverage: Ratio {
                    resolved: 10,
                    total: 12,
                },
                route_coverage: CoverageState::Measured(Coverage {
                    nexthops: Ratio {
                        resolved: 4,
                        total: 5,
                    },
                    nexthop_objects: 9,
                    dump_ms: 31,
                    age_secs: 2,
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut out = String::new();
        render_textfile(&snap, &mut out);
        assert!(out.contains("peers{module=\"neigh-snoop\",iface=\"br1\",state=\"heard\"} 2"));
        assert!(out.contains("peers{module=\"neigh-snoop\",iface=\"br1\",state=\"never_heard\"} 1"));
        assert!(out.contains(
            "participant_addresses{module=\"neigh-snoop\",iface=\"br1\",state=\"unresolved\"} 2"
        ));
        assert!(out
            .contains("route_nexthops{module=\"neigh-snoop\",iface=\"br1\",state=\"resolved\"} 4"));
        assert!(out.contains(
            "route_nexthops{module=\"neigh-snoop\",iface=\"br1\",state=\"unresolved\"} 1"
        ));
        assert!(out.contains("nexthop_objects{module=\"neigh-snoop\",iface=\"br1\"} 9"));
        assert!(out.contains("coverage_dump_ms{module=\"neigh-snoop\",iface=\"br1\"} 31"));
    }
}
