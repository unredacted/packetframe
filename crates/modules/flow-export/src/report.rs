//! Health rows and metrics, from the worker's snapshot and heartbeat.

use std::fmt::Write as _;
use std::time::Duration;

use packetframe_common::module::{HealthReport, HealthState, SubsystemHealth};

use packetframe_sampler_shm::coverage::Coverage;

use crate::coverage::State;
use crate::worker::{Path, Published};

/// A worker that has not ticked for this long has stopped: nothing is
/// exported, and every port is uncovered.
pub const STALL_AFTER: Duration = Duration::from_secs(1);

/// A Prometheus label value: backslash, double quote and newline escaped,
/// as the text format requires.
fn escape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for ch in v.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

fn row(name: impl Into<String>, state: HealthState, message: String) -> SubsystemHealth {
    SubsystemHealth {
        name: name.into(),
        state,
        message: Some(message),
        last_success_age_seconds: None,
    }
}

/// `panicked`: why the worker panicked, if it did; it has stopped the
/// samplers, and nothing is exported until a restart.
pub fn health(p: &Published, heartbeat_age: Duration, panicked: Option<&str>) -> HealthReport {
    let stalled = panicked.is_some() || heartbeat_age > STALL_AFTER;
    let mut rows = Vec::new();
    if let Some(why) = panicked {
        rows.push(row(
            "worker",
            HealthState::Unhealthy,
            format!(
                "the export worker panicked ({why}): sampling is stopped and nothing is \
                 exported; restart the daemon to resume"
            ),
        ));
    } else if stalled {
        rows.push(row(
            "worker",
            HealthState::Unhealthy,
            format!(
                "the export worker has not run for {} ms: nothing is exported and every \
                 port is uncovered",
                heartbeat_age.as_millis()
            ),
        ));
    }

    rows.push(match &p.source_error {
        // A failed reload changed nothing: the sampler runs as before, and
        // the ports' rows say whether that still covers them.
        Some(e) => row(
            "sampling",
            HealthState::Degraded,
            format!(
                "{e}; 1:{}, {} header bytes, generation {} stays applied",
                p.rate, p.header_bytes, p.generation
            ),
        ),
        None if p.over_budget => row(
            "sampling",
            HealthState::Degraded,
            format!(
                "over budget: 1:{} is denser than the 1:{} the sampler's cost is \
                 qualified at",
                p.rate,
                packetframe_common::config::FLOW_BUDGET_RATE
            ),
        ),
        None => row(
            "sampling",
            HealthState::Healthy,
            format!(
                "1:{}, {} header bytes, generation {}",
                p.rate, p.header_bytes, p.generation
            ),
        ),
    });

    for path in Path::ALL {
        let ports: Vec<_> = p.ports.iter().filter(|r| r.path == path).collect();
        let mut worst = HealthState::Healthy;
        let mut parts = Vec::new();
        if path == Path::Vpp {
            let Some(v) = &p.vpp else { continue };
            let epoch = v
                .epoch
                .map_or_else(String::new, |e| format!("; epoch {e:016x}"));
            let generations = match (v.applied, v.written) {
                (Some(a), Some(w)) => format!(", generation {a} applied of {w} asked"),
                (None, Some(w)) => format!(", generation {w} asked"),
                _ => String::new(),
            };
            parts.push(format!(
                "sampler {}: {}{epoch}{generations}",
                v.coverage.name(),
                v.why
            ));
            // The plugin's own state bounds the row, whatever its ports
            // show: a port still in its startup grace is no evidence the
            // sampler works.
            if !v.coverage.is_healthy() {
                worst = match v.coverage {
                    Coverage::Incompatible => HealthState::Unhealthy,
                    _ => HealthState::Degraded,
                };
            }
        } else if ports.is_empty() {
            continue;
        }
        for r in &ports {
            let (state, label) = if stalled {
                (
                    HealthState::Unhealthy,
                    "uncovered (worker stopped)".to_string(),
                )
            } else {
                match &r.state {
                    State::Covered => (HealthState::Healthy, "covered".into()),
                    State::Starting => (HealthState::Healthy, "starting".into()),
                    State::Degraded(why) => (HealthState::Degraded, format!("degraded: {why}")),
                    State::Uncovered(why) => (HealthState::Unhealthy, format!("uncovered: {why}")),
                }
            };
            worst = worst.worse_of(state);
            parts.push(format!("{} {label} ({} samples)", r.name, r.samples));
        }
        rows.push(row(path.name(), worst, parts.join("; ")));
    }
    if let Some(e) = &p.ports_error {
        rows.push(row(
            "ports",
            HealthState::Degraded,
            format!("fast-path's port list could not be read (the last one stands): {e}"),
        ));
    }

    for c in &p.collectors {
        let kind = match c.kind {
            packetframe_common::config::CollectorKind::Stats => "stats",
            packetframe_common::config::CollectorKind::Ddos => "ddos",
        };
        rows.push(match &c.failing {
            Some(why) => row(
                format!("collector {}", c.name),
                HealthState::Degraded,
                format!("sflow to {} ({kind}): {why}", c.addr),
            ),
            None => row(
                format!("collector {}", c.name),
                HealthState::Healthy,
                format!(
                    "sflow to {} ({kind}): {} datagrams submitted; receipt is the \
                     collector's to confirm",
                    c.addr, c.datagrams
                ),
            ),
        });
    }

    HealthReport {
        overall: rows
            .iter()
            .fold(HealthState::Healthy, |w, r| w.worse_of(r.state)),
        subsystems: rows,
    }
}

/// Prometheus text, every name under `packetframe_flow_export_`.
pub fn metrics(p: &Published, out: &mut String) {
    let mut counter = |name: &str, help: &str, rows: &[(String, u64)]| {
        let _ = writeln!(out, "# HELP packetframe_flow_export_{name} {help}");
        let _ = writeln!(out, "# TYPE packetframe_flow_export_{name} counter");
        for (labels, v) in rows {
            let _ = writeln!(out, "packetframe_flow_export_{name}{labels} {v}");
        }
    };
    counter(
        "samples_total",
        "samples exported, by path",
        &Path::ALL
            .iter()
            .map(|path| {
                (
                    format!("{{path=\"{}\"}}", path.name()),
                    p.samples_total.get(path).copied().unwrap_or(0),
                )
            })
            .collect::<Vec<_>>(),
    );
    counter(
        "samples_lost_total",
        "samples selected but never exported, by where they were lost",
        &[
            ("{where=\"sampler\"}".into(), p.lost_total),
            ("{where=\"vpp\"}".into(), p.vpp_lost_total),
            ("{where=\"unmapped\"}".into(), p.unmapped_total),
            ("{where=\"undecodable\"}".into(), p.undecodable_total),
            ("{where=\"unencodable\"}".into(), p.unencodable_total),
        ],
    );
    counter(
        "ring_lost_total",
        "samples the perf rings reported lost (a subset of the sampler's loss)",
        &[(String::new(), p.ring_lost_total)],
    );
    let per_collector = |f: fn(&crate::worker::CollectorReport) -> u64| {
        p.collectors
            .iter()
            .map(|c| (format!("{{collector=\"{}\"}}", escape(&c.name)), f(c)))
            .collect::<Vec<_>>()
    };
    counter(
        "datagrams_total",
        "datagrams submitted to a collector (receipt unverified)",
        &per_collector(|c| c.datagrams),
    );
    counter(
        "send_errors_total",
        "datagrams a collector's send refused",
        &per_collector(|c| c.send_errors),
    );
    counter(
        "send_budget_drops_total",
        "datagrams not sent because a tick's budget was spent",
        &per_collector(|c| c.budget_drops),
    );
    let _ = writeln!(
        out,
        "# HELP packetframe_flow_export_coverage per port: 3 covered, 2 starting, 1 degraded, 0 uncovered"
    );
    let _ = writeln!(out, "# TYPE packetframe_flow_export_coverage gauge");
    for r in &p.ports {
        let _ = writeln!(
            out,
            "packetframe_flow_export_coverage{{iface=\"{}\",path=\"{}\"}} {}",
            escape(&r.name),
            r.path.name(),
            r.state.level()
        );
    }
    if let Some(v) = &p.vpp {
        let _ = writeln!(
            out,
            "# HELP packetframe_flow_export_vpp_sampler_healthy 1 while VPP's sampler \
             samples as asked and loses nothing"
        );
        let _ = writeln!(
            out,
            "# TYPE packetframe_flow_export_vpp_sampler_healthy gauge"
        );
        let _ = writeln!(
            out,
            "packetframe_flow_export_vpp_sampler_healthy {}",
            u8::from(v.coverage.is_healthy())
        );
    }
    for (name, help, v) in [
        ("rate", "the sampling rate, 1 in N", u64::from(p.rate)),
        (
            "over_budget",
            "1 while the rate is denser than the qualified budget",
            u64::from(p.over_budget),
        ),
    ] {
        let _ = writeln!(out, "# HELP packetframe_flow_export_{name} {help}");
        let _ = writeln!(out, "# TYPE packetframe_flow_export_{name} gauge");
        let _ = writeln!(out, "packetframe_flow_export_{name} {v}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::{CollectorReport, PortReport};
    use packetframe_common::config::CollectorKind;

    fn published() -> Published {
        Published {
            rate: 1000,
            header_bytes: 128,
            generation: 1,
            ports: vec![
                PortReport {
                    name: "eth0".into(),
                    ifindex: 2,
                    path: Path::Xdp,
                    state: State::Covered,
                    samples: 10,
                    pool: 10_000,
                },
                PortReport {
                    name: "eth1".into(),
                    ifindex: 3,
                    path: Path::Xdp,
                    state: State::Degraded("2 samples lost in the last 5 s".into()),
                    samples: 4,
                    pool: 4_000,
                },
            ],
            collectors: vec![CollectorReport {
                name: "fnm".into(),
                addr: "198.51.100.10:6343".parse().unwrap(),
                kind: CollectorKind::Ddos,
                datagrams: 3,
                send_errors: 0,
                budget_drops: 0,
                failing: None,
            }],
            samples_total: [(Path::Xdp, 14)].into(),
            ..Published::default()
        }
    }

    fn vpp(coverage: Coverage, why: &str) -> crate::vpp::VppHealth {
        crate::vpp::VppHealth {
            coverage,
            why: why.into(),
            epoch: Some(7),
            applied: Some(3),
            written: Some(3),
            missing: Default::default(),
        }
    }

    #[test]
    fn a_panicked_worker_says_why_and_uncovers_everything() {
        let h = health(&published(), Duration::ZERO, Some("index out of bounds"));
        let w = h.subsystems.iter().find(|r| r.name == "worker").unwrap();
        assert_eq!(w.state, HealthState::Unhealthy);
        assert!(
            w.message
                .as_deref()
                .unwrap()
                .contains("panicked (index out of bounds)"),
            "{:?}",
            w.message
        );
        let xdp = h.subsystems.iter().find(|r| r.name == "xdp").unwrap();
        assert_eq!(xdp.state, HealthState::Unhealthy);
    }

    #[test]
    fn the_vpp_row_shows_the_sampler_with_or_without_ports() {
        let mut p = published();
        p.ports.truncate(1);
        let vpp_row = |p: &Published| {
            health(p, Duration::ZERO, None)
                .subsystems
                .into_iter()
                .find(|r| r.name == "vpp")
        };
        assert!(vpp_row(&p).is_none(), "no vpp-offload, no row");
        p.vpp = Some(vpp(Coverage::Unavailable, "no VPP ports attached yet"));
        let r = vpp_row(&p).unwrap();
        assert_eq!(r.state, HealthState::Degraded);
        assert!(r
            .message
            .unwrap()
            .contains("sampler unavailable: no VPP ports"));
        p.vpp = Some(vpp(Coverage::Healthy, "sampling as configured"));
        p.ports.push(PortReport {
            name: "eth3".into(),
            ifindex: 5,
            path: Path::Vpp,
            state: State::Uncovered("VPP has no interface octeon1/0".into()),
            samples: 0,
            pool: 0,
        });
        let r = vpp_row(&p).unwrap();
        assert_eq!(r.state, HealthState::Unhealthy);
        let m = r.message.unwrap();
        assert!(
            m.contains("epoch 0000000000000007, generation 3 applied of 3 asked")
                && m.contains("eth3 uncovered"),
            "{m}"
        );
        let mut out = String::new();
        metrics(&p, &mut out);
        assert!(
            out.contains("packetframe_flow_export_vpp_sampler_healthy 1")
                && out.contains("coverage{iface=\"eth3\",path=\"vpp\"} 0"),
            "{out}"
        );
        // A port in its startup grace does not make a broken sampler's row
        // healthy.
        p.ports.last_mut().unwrap().state = State::Starting;
        p.vpp = Some(vpp(Coverage::Unavailable, "heartbeat 2000 ms old"));
        assert_eq!(vpp_row(&p).unwrap().state, HealthState::Degraded);
    }

    #[test]
    fn a_path_reads_as_its_worst_port_and_names_each() {
        let h = health(&published(), Duration::ZERO, None);
        let xdp = h.subsystems.iter().find(|r| r.name == "xdp").unwrap();
        assert_eq!(xdp.state, HealthState::Degraded);
        let m = xdp.message.as_deref().unwrap();
        assert!(
            m.contains("eth0 covered (10 samples)") && m.contains("eth1 degraded"),
            "{m}"
        );
        assert!(
            h.subsystems.iter().all(|r| r.name != "tc"),
            "no tc ports, no row"
        );
        let c = h
            .subsystems
            .iter()
            .find(|r| r.name == "collector fnm")
            .unwrap();
        assert!(c
            .message
            .as_deref()
            .unwrap()
            .contains("receipt is the collector's to confirm"));
        assert_eq!(h.overall, HealthState::Degraded);
    }

    #[test]
    fn a_stalled_worker_uncovers_everything() {
        let h = health(&published(), STALL_AFTER + Duration::from_millis(1), None);
        assert_eq!(h.overall, HealthState::Unhealthy);
        assert!(h.subsystems.iter().any(|r| r.name == "worker"));
        let xdp = h.subsystems.iter().find(|r| r.name == "xdp").unwrap();
        assert_eq!(xdp.state, HealthState::Unhealthy);
    }

    #[test]
    fn over_budget_and_failing_sends_degrade() {
        let mut p = published();
        p.ports.truncate(1);
        p.over_budget = true;
        p.rate = 100;
        p.collectors[0].failing = Some("Network is unreachable".into());
        let h = health(&p, Duration::ZERO, None);
        let s = h.subsystems.iter().find(|r| r.name == "sampling").unwrap();
        assert_eq!(s.state, HealthState::Degraded);
        assert!(s.message.as_deref().unwrap().contains("over budget"));
        let c = h
            .subsystems
            .iter()
            .find(|r| r.name == "collector fnm")
            .unwrap();
        assert_eq!(c.state, HealthState::Degraded);
    }

    #[test]
    fn a_reload_that_failed_degrades_and_names_what_stays() {
        let mut p = published();
        p.source_error =
            Some("a reload to 1:100 with 128 header bytes could not be applied: no".into());
        let h = health(&p, Duration::ZERO, None);
        let s = h.subsystems.iter().find(|r| r.name == "sampling").unwrap();
        assert_eq!(s.state, HealthState::Degraded);
        assert!(
            s.message
                .as_deref()
                .unwrap()
                .contains("1:1000, 128 header bytes, generation 1 stays"),
            "{:?}",
            s.message
        );
    }

    #[test]
    fn label_values_are_escaped() {
        let mut p = published();
        p.ports[0].name = "a\\b\"c\nd".into();
        p.collectors[0].name = "f\"nm".into();
        let mut out = String::new();
        metrics(&p, &mut out);
        assert!(
            out.contains("coverage{iface=\"a\\\\b\\\"c\\nd\",path=\"xdp\"} 3"),
            "{out}"
        );
        assert!(
            out.contains("datagrams_total{collector=\"f\\\"nm\"} 3"),
            "{out}"
        );
        assert_eq!(out.lines().count(), {
            let mut plain = String::new();
            metrics(&published(), &mut plain);
            plain.lines().count()
        });
    }

    #[test]
    fn metrics_name_every_series() {
        let mut out = String::new();
        metrics(&published(), &mut out);
        for line in [
            "packetframe_flow_export_samples_total{path=\"xdp\"} 14",
            "packetframe_flow_export_samples_total{path=\"tc\"} 0",
            "packetframe_flow_export_datagrams_total{collector=\"fnm\"} 3",
            "packetframe_flow_export_coverage{iface=\"eth1\",path=\"xdp\"} 1",
            "packetframe_flow_export_rate 1000",
            "packetframe_flow_export_over_budget 0",
        ] {
            assert!(out.contains(line), "missing {line}:\n{out}");
        }
    }
}
