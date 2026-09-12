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
    Counters, CoverageState, InstallOutcome, LearnOutcome, LinkEvent, LinkState, PersistOutcome,
    SeedOutcome, Snapshot,
};
use crate::table::FilterReject;

const NS: &str = "packetframe_neigh_snoop";

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {NS}_{name} {help}");
    let _ = writeln!(out, "# TYPE {NS}_{name} {kind}");
}

fn labelled(out: &mut String, name: &str, iface: &str, label: &str, values: &[(&str, u64)]) {
    for (v, n) in values {
        let _ = writeln!(
            out,
            "{NS}_{name}{{module=\"neigh-snoop\",iface=\"{iface}\",{label}=\"{v}\"}} {n}"
        );
    }
}

fn scalar(out: &mut String, name: &str, iface: &str, value: impl std::fmt::Display) {
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
