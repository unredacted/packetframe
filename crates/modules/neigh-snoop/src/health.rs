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
                    secs => row(
                        name,
                        HealthState::Healthy,
                        format!(
                            "capturing, {} entries{}",
                            b.table_entries,
                            if b.promisc_confirmed {
                                ""
                            } else {
                                ", promisc not yet confirmed"
                            }
                        ),
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
    fn all_good_is_healthy() {
        let r = health(&Snapshot {
            bridges: vec![up("br0")],
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
        let r = health(&Snapshot { bridges: vec![b] });
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
    fn socket_error_is_unhealthy() {
        let mut b = up("br0");
        b.socket_error = Some("EPERM".into());
        let r = health(&Snapshot { bridges: vec![b] });
        assert_eq!(state_of(&r, "snoop:br0").state, HealthState::Unhealthy);
        assert_eq!(r.overall, HealthState::Unhealthy);
    }

    #[test]
    fn long_silence_degrades() {
        let mut b = up("br0");
        b.silent_secs = Some(HEALTH_SILENCE_SECS + 1);
        let r = health(&Snapshot { bridges: vec![b] });
        assert_eq!(state_of(&r, "snoop:br0").state, HealthState::Degraded);
        let mut b = up("br0");
        b.silent_secs = Some(HEALTH_SILENCE_SECS);
        let r = health(&Snapshot { bridges: vec![b] });
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
        let r = health(&Snapshot { bridges: vec![b] });
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
        let r = health(&Snapshot { bridges: vec![b] });
        assert_eq!(state_of(&r, "coverage").state, HealthState::Degraded);

        let mut b = up("br0");
        b.route_coverage = CoverageState::Unavailable("strict check unsupported".into());
        let r = health(&Snapshot { bridges: vec![b] });
        assert_eq!(state_of(&r, "coverage").state, HealthState::Degraded);
        assert!(state_of(&r, "coverage")
            .message
            .as_deref()
            .unwrap()
            .contains("routes=unknown"));

        let mut b = up("br0");
        b.route_coverage = CoverageState::Pending;
        let r = health(&Snapshot { bridges: vec![b] });
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
        let r = health(&Snapshot { bridges: vec![b] });
        let p = state_of(&r, "peers");
        assert_eq!(p.state, HealthState::Degraded);
        let m = p.message.as_deref().unwrap();
        assert!(m.starts_with("12 of 14 never heard: br0:192.0.2.1"), "{m}");
        assert!(m.ends_with("+2 more"), "{m}");
    }
}
