//! Health rows derived from a [`Snapshot`]. Portable.
//!
//! Rows: `snoop:<bridge>` per configured bridge, `coverage`, `peers`.
//! Overall is the worst row, never cheerier than any subsystem.

use packetframe_common::module::{HealthReport, HealthState, SubsystemHealth};

use crate::snapshot::{CoverageState, LinkState, Snapshot};

/// A bridge on a peering LAN always has ARP chatter; this long with
/// nothing learnable is a capture problem, not a quiet fabric.
pub const HEALTH_SILENCE_SECS: u64 = 300;
/// Route next-hop coverage below this is Degraded.
pub const ROUTE_COVERAGE_DEGRADED_BELOW: f64 = 0.90;
/// Participant coverage (learned addresses whose kernel entry
/// resolves) must reach this to be Healthy.
pub const PARTICIPANT_COVERAGE_HEALTHY_AT: f64 = 0.98;
/// How many never-heard peers to list before "+N more".
pub const NEVER_HEARD_LIST_MAX: usize = 10;
/// Consecutive failed reconcile ticks before the gate row is Unhealthy.
pub const GATE_UNHEALTHY_AFTER: u32 = 10;

fn row(name: String, state: HealthState, message: String, age: Option<u64>) -> SubsystemHealth {
    SubsystemHealth {
        name,
        state,
        message: Some(message),
        last_success_age_seconds: age,
    }
}

pub fn health(s: &Snapshot) -> HealthReport {
    let mut subsystems = Vec::new();

    for b in &s.bridges {
        let name = format!("snoop:{}", b.name);
        let r = if let Some(e) = &b.socket_error {
            row(
                name,
                HealthState::Unhealthy,
                format!("socket error: {e}"),
                None,
            )
        } else {
            match b.link {
                LinkState::Absent => row(
                    name,
                    HealthState::Degraded,
                    "link absent; waiting for RTM_NEWLINK by name".into(),
                    None,
                ),
                LinkState::Down => row(
                    name,
                    HealthState::Degraded,
                    "link down; will re-seed when it comes up".into(),
                    None,
                ),
                LinkState::Up => match b.silent_secs {
                    Some(secs) if secs > HEALTH_SILENCE_SECS => row(
                        name,
                        HealthState::Degraded,
                        format!(
                            "link up but no learnable frame for {secs}s ({} entries held)",
                            b.table_entries
                        ),
                        Some(secs),
                    ),
                    // Broadcast ARP and multicast NS reach a non-promiscuous
                    // tap anyway, so frames keep arriving while unicast
                    // replies and advertisements are silently missed.
                    // Not Healthy until the kernel reports promiscuity.
                    secs if !b.promisc_confirmed => row(
                        name,
                        HealthState::Degraded,
                        format!(
                            "capturing without confirmed promiscuous mode, {} entries; unicast ND/ARP replies may be missed",
                            b.table_entries
                        ),
                        secs,
                    ),
                    secs => row(
                        name,
                        HealthState::Healthy,
                        format!("capturing, {} entries", b.table_entries),
                        secs,
                    ),
                },
            }
        };
        subsystems.push(r);
    }

    // Coverage: one row across bridges that are up.
    {
        let mut state = HealthState::Healthy;
        let mut parts = Vec::new();
        let mut age = None;
        for b in s.bridges.iter().filter(|b| b.link == LinkState::Up) {
            let pc = b.participant_coverage;
            let mut piece = format!("{} participants={}/{}", b.name, pc.resolved, pc.total);
            if let Some(f) = pc.fraction() {
                if f < PARTICIPANT_COVERAGE_HEALTHY_AT {
                    state = state.worse_of(HealthState::Degraded);
                }
            }
            match &b.route_coverage {
                CoverageState::Pending => piece.push_str(" routes=pending"),
                CoverageState::Unavailable(why) => {
                    state = state.worse_of(HealthState::Degraded);
                    piece.push_str(&format!(" routes=unknown ({why})"));
                }
                CoverageState::Measured(c) => {
                    piece.push_str(&format!(
                        " routes={}/{}",
                        c.nexthops.resolved, c.nexthops.total
                    ));
                    if let Some(f) = c.nexthops.fraction() {
                        if f < ROUTE_COVERAGE_DEGRADED_BELOW {
                            state = state.worse_of(HealthState::Degraded);
                        }
                    }
                    if !c.unresolved_sample.is_empty() {
                        let shown: Vec<String> = c
                            .unresolved_sample
                            .iter()
                            .take(NEVER_HEARD_LIST_MAX)
                            .map(|a| a.to_string())
                            .collect();
                        piece.push_str(&format!(" unresolved=[{}]", shown.join(",")));
                    }
                    age = Some(age.map_or(c.age_secs, |a: u64| a.max(c.age_secs)));
                }
            }
            parts.push(piece);
        }
        let message = if parts.is_empty() {
            "no bridge up".to_string()
        } else {
            parts.join("; ")
        };
        subsystems.push(row("coverage".into(), state, message, age));
    }

    // Peers: never-heard configured addresses across bridges.
    {
        let never: Vec<String> = s
            .bridges
            .iter()
            .flat_map(|b| b.never_heard.iter().map(move |a| format!("{}:{a}", b.name)))
            .collect();
        let total: u64 = s.bridges.iter().map(|b| b.peers_total).sum();
        let r = if never.is_empty() {
            row(
                "peers".into(),
                HealthState::Healthy,
                format!("{total} configured peer addresses, all heard"),
                None,
            )
        } else {
            let shown = never
                .iter()
                .take(NEVER_HEARD_LIST_MAX)
                .cloned()
                .collect::<Vec<_>>();
            let more = never.len().saturating_sub(shown.len());
            let mut msg = format!(
                "{} of {total} never heard: {}",
                never.len(),
                shown.join(", ")
            );
            if more > 0 {
                msg.push_str(&format!(" +{more} more"));
            }
            row("peers".into(), HealthState::Degraded, msg, None)
        };
        subsystems.push(r);
    }

    if let Some(g) = &s.gate {
        // A vtysh that is missing or failing is checked before the
        // lists' presence: the lists read as absent precisely because
        // nothing could read them, and that failure must escalate.
        let r = if let Some(e) = &g.last_error {
            let state = if g.consecutive_failures >= GATE_UNHEALTHY_AFTER {
                HealthState::Unhealthy
            } else {
                HealthState::Degraded
            };
            row(
                "frr-gate".into(),
                state,
                format!("{} consecutive failures: {e}", g.consecutive_failures),
                g.last_change_age_secs,
            )
        } else if !g.lists_present {
            row(
                "frr-gate".into(),
                HealthState::Degraded,
                "prefix-lists absent; waiting for the static FRR configuration".into(),
                None,
            )
        } else {
            let pending = if g.pending_removals > 0 {
                format!(", {} removals pending", g.pending_removals)
            } else {
                String::new()
            };
            row(
                "frr-gate".into(),
                HealthState::Healthy,
                format!(
                    "reconciled, {} v4 + {} v6 permitted{pending}",
                    g.permitted_v4, g.permitted_v6
                ),
                g.last_change_age_secs,
            )
        };
        subsystems.push(r);
    }

    if !s.rs.is_empty() {
        let mut state = HealthState::Healthy;
        let mut parts = Vec::new();
        for r in &s.rs {
            match &r.error {
                Some(e) => {
                    state = state.worse_of(HealthState::Degraded);
                    parts.push(format!("{}: unknown ({e})", r.rs));
                }
                None => {
                    if r.demoted_prefixes > 0 || r.unparsed_prefixes > 0 {
                        state = state.worse_of(HealthState::Degraded);
                    }
                    let shown: Vec<String> = r
                        .unresolved_nexthops
                        .iter()
                        .take(NEVER_HEARD_LIST_MAX)
                        .map(|a| a.to_string())
                        .collect();
                    let unparsed = if r.unparsed_prefixes > 0 {
                        format!(", {} without a parsable next-hop", r.unparsed_prefixes)
                    } else {
                        String::new()
                    };
                    parts.push(format!(
                        "{}: {} demoted of {} received{unparsed}, unresolved next-hops [{}]",
                        r.rs,
                        r.demoted_prefixes,
                        r.received_prefixes,
                        shown.join(",")
                    ));
                }
            }
        }
        subsystems.push(row("rs-coverage".into(), state, parts.join("; "), None));
    }

    let overall = subsystems
        .iter()
        .fold(HealthState::Healthy, |acc, r| acc.worse_of(r.state));
    HealthReport {
        overall,
        subsystems,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{Coverage, IfaceSnapshot, Ratio};

    fn up(name: &str) -> IfaceSnapshot {
        IfaceSnapshot {
            name: name.into(),
            ifindex: Some(3),
            link: LinkState::Up,
            promisc_confirmed: true,
            silent_secs: Some(1),
            table_entries: 100,
            peers_total: 2,
            participant_coverage: Ratio {
                resolved: 100,
                total: 100,
            },
            route_coverage: CoverageState::Measured(Coverage {
                nexthops: Ratio {
                    resolved: 20,
                    total: 20,
                },
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn state_of<'a>(r: &'a HealthReport, name: &str) -> &'a SubsystemHealth {
        r.subsystems.iter().find(|s| s.name == name).unwrap()
    }

    #[test]
    fn gate_and_rs_rows() {
        use crate::snapshot::{GateSnapshot, RsCoverageSnapshot};
        let mut snap = Snapshot {
            bridges: vec![up("br0")],
            gate: Some(GateSnapshot {
                lists_present: true,
                permitted_v4: 3,
                permitted_v6: 1,
                ..Default::default()
            }),
            rs: vec![],
        };
        let r = health(&snap);
        assert_eq!(state_of(&r, "frr-gate").state, HealthState::Healthy);
        assert!(state_of(&r, "frr-gate")
            .message
            .as_deref()
            .unwrap()
            .contains("3 v4 + 1 v6"));
        assert!(r.subsystems.iter().all(|s| s.name != "rs-coverage"));

        snap.gate.as_mut().unwrap().lists_present = false;
        let r = health(&snap);
        assert_eq!(state_of(&r, "frr-gate").state, HealthState::Degraded);

        snap.gate.as_mut().unwrap().lists_present = true;
        snap.gate.as_mut().unwrap().last_error = Some("vtysh timed out".into());
        snap.gate.as_mut().unwrap().consecutive_failures = 2;
        let r = health(&snap);
        assert_eq!(state_of(&r, "frr-gate").state, HealthState::Degraded);
        snap.gate.as_mut().unwrap().consecutive_failures = GATE_UNHEALTHY_AFTER;
        let r = health(&snap);
        assert_eq!(state_of(&r, "frr-gate").state, HealthState::Unhealthy);

        snap.gate.as_mut().unwrap().last_error = None;
        snap.rs = vec![RsCoverageSnapshot {
            rs: "192.0.2.2".parse().unwrap(),
            bridge: "br0".into(),
            received_prefixes: 50,
            unparsed_prefixes: 0,
            nexthops: Ratio {
                resolved: 4,
                total: 5,
            },
            unresolved_nexthops: vec!["192.0.2.90".parse().unwrap()],
            demoted_prefixes: 3,
            dump_ms: 10,
            age_secs: 1,
            error: None,
        }];
        let r = health(&snap);
        let rs = state_of(&r, "rs-coverage");
        assert_eq!(rs.state, HealthState::Degraded);
        assert!(rs
            .message
            .as_deref()
            .unwrap()
            .contains("3 demoted of 50 received, unresolved next-hops [192.0.2.90]"));
        snap.rs[0].demoted_prefixes = 0;
        snap.rs[0].unresolved_nexthops.clear();
        let r = health(&snap);
        assert_eq!(state_of(&r, "rs-coverage").state, HealthState::Healthy);
        snap.rs[0].error = Some("vtysh exited 1".into());
        let r = health(&snap);
        assert!(state_of(&r, "rs-coverage")
            .message
            .as_deref()
            .unwrap()
            .contains("unknown"));
    }

    #[test]
    fn all_good_is_healthy() {
        let r = health(&Snapshot {
            bridges: vec![up("br0")],
            ..Default::default()
        });
        assert_eq!(r.overall, HealthState::Healthy);
        assert_eq!(r.subsystems.len(), 3);
        assert!(state_of(&r, "snoop:br0")
            .message
            .as_deref()
            .unwrap()
            .starts_with("capturing, 100"));
    }

    #[test]
    fn link_states_degrade() {
        let mut b = up("br0");
        b.link = LinkState::Absent;
        let r = health(&Snapshot {
            bridges: vec![b],
            ..Default::default()
        });
        assert_eq!(state_of(&r, "snoop:br0").state, HealthState::Degraded);
        assert!(state_of(&r, "snoop:br0")
            .message
            .as_deref()
            .unwrap()
            .contains("link absent"));
        assert_eq!(r.overall, HealthState::Degraded);
        // Coverage skips bridges that are not up.
        assert_eq!(
            state_of(&r, "coverage").message.as_deref(),
            Some("no bridge up")
        );
    }

    #[test]
    fn unconfirmed_promisc_degrades() {
        let mut b = up("br0");
        b.promisc_confirmed = false;
        let r = health(&Snapshot {
            bridges: vec![b],
            ..Default::default()
        });
        let s = state_of(&r, "snoop:br0");
        assert_eq!(s.state, HealthState::Degraded);
        assert!(s
            .message
            .as_deref()
            .unwrap()
            .contains("without confirmed promiscuous mode"));
    }

    #[test]
    fn socket_error_is_unhealthy() {
        let mut b = up("br0");
        b.socket_error = Some("EPERM".into());
        let r = health(&Snapshot {
            bridges: vec![b],
            ..Default::default()
        });
        assert_eq!(state_of(&r, "snoop:br0").state, HealthState::Unhealthy);
        assert_eq!(r.overall, HealthState::Unhealthy);
    }

    #[test]
    fn long_silence_degrades() {
        let mut b = up("br0");
        b.silent_secs = Some(HEALTH_SILENCE_SECS + 1);
        let r = health(&Snapshot {
            bridges: vec![b],
            ..Default::default()
        });
        assert_eq!(state_of(&r, "snoop:br0").state, HealthState::Degraded);
        let mut b = up("br0");
        b.silent_secs = Some(HEALTH_SILENCE_SECS);
        let r = health(&Snapshot {
            bridges: vec![b],
            ..Default::default()
        });
        assert_eq!(state_of(&r, "snoop:br0").state, HealthState::Healthy);
    }

    #[test]
    fn coverage_thresholds() {
        let mut b = up("br0");
        b.route_coverage = CoverageState::Measured(Coverage {
            nexthops: Ratio {
                resolved: 8,
                total: 10,
            },
            unresolved_sample: vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()],
            ..Default::default()
        });
        let r = health(&Snapshot {
            bridges: vec![b],
            ..Default::default()
        });
        let c = state_of(&r, "coverage");
        assert_eq!(c.state, HealthState::Degraded);
        assert!(c
            .message
            .as_deref()
            .unwrap()
            .contains("routes=8/10 unresolved=[192.0.2.1,192.0.2.2]"));

        let mut b = up("br0");
        b.participant_coverage = Ratio {
            resolved: 90,
            total: 100,
        };
        let r = health(&Snapshot {
            bridges: vec![b],
            ..Default::default()
        });
        assert_eq!(state_of(&r, "coverage").state, HealthState::Degraded);

        let mut b = up("br0");
        b.route_coverage = CoverageState::Unavailable("strict check unsupported".into());
        let r = health(&Snapshot {
            bridges: vec![b],
            ..Default::default()
        });
        assert_eq!(state_of(&r, "coverage").state, HealthState::Degraded);
        assert!(state_of(&r, "coverage")
            .message
            .as_deref()
            .unwrap()
            .contains("routes=unknown"));

        let mut b = up("br0");
        b.route_coverage = CoverageState::Pending;
        let r = health(&Snapshot {
            bridges: vec![b],
            ..Default::default()
        });
        assert_eq!(state_of(&r, "coverage").state, HealthState::Healthy);
        assert!(state_of(&r, "coverage")
            .message
            .as_deref()
            .unwrap()
            .contains("routes=pending"));
    }

    #[test]
    fn never_heard_peers_degrade_and_list() {
        let mut b = up("br0");
        b.peers_total = 14;
        b.never_heard = (1..=12)
            .map(|i| format!("192.0.2.{i}").parse().unwrap())
            .collect();
        let r = health(&Snapshot {
            bridges: vec![b],
            ..Default::default()
        });
        let p = state_of(&r, "peers");
        assert_eq!(p.state, HealthState::Degraded);
        let m = p.message.as_deref().unwrap();
        assert!(m.starts_with("12 of 14 never heard: br0:192.0.2.1"), "{m}");
        assert!(m.ends_with("+2 more"), "{m}");
    }
}
