//! What a reader may conclude about sampling coverage.
//!
//! Every consumer of the sampler judges coverage the same way, from what
//! it can observe: the status snapshot, the heartbeat's age, what
//! `desired.conf` asks for, and whether packets were counted. The states
//! are deliberately pessimistic: nothing is called healthy that a reader
//! cannot see is working, and a stopped plugin is never mistaken for a
//! quiet network.

use crate::desired::ErrorKind;
use crate::status::{reason, State, Status};

/// A heartbeat older than this means the plugin (or VPP) has stopped: it
/// beats every 100 ms whether or not packets flow.
pub const HEARTBEAT_DEADLINE_NS: u64 = 1_000_000_000;
/// An interface may stay unresolved this long (PacketFrame creates
/// interfaces after VPP starts) before coverage is partial.
pub const UNRESOLVED_GRACE_NS: u64 = 30_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// Sampling as configured, and packets were counted.
    Healthy,
    /// Sampling as configured; no packets arrived. Healthy coverage of an
    /// idle network.
    ZeroTraffic,
    /// Sampling, but a configured interface has been missing past the
    /// grace period.
    Partial,
    /// Sampling under a configuration other than the one asked for: the
    /// current `desired.conf` was refused, or not yet applied.
    Degraded,
    /// The plugin is up and sampling nothing, by configuration.
    Disabled,
    /// No sampler to be seen: no epoch, a stale heartbeat, or an
    /// unreadable status.
    Unavailable,
    /// The sampler speaks a layout this reader cannot read.
    Incompatible,
}

impl Coverage {
    pub fn name(self) -> &'static str {
        match self {
            Coverage::Healthy => "healthy",
            Coverage::ZeroTraffic => "zero-traffic",
            Coverage::Partial => "partial",
            Coverage::Degraded => "degraded",
            Coverage::Disabled => "disabled",
            Coverage::Unavailable => "unavailable",
            Coverage::Incompatible => "incompatible",
        }
    }

    /// Whether the samples represent what was asked for.
    pub fn is_healthy(self) -> bool {
        matches!(self, Coverage::Healthy | Coverage::ZeroTraffic)
    }
}

/// Why no status could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoStatus {
    pub incompatible: bool,
    pub why: String,
}

/// Everything coverage is judged from.
#[derive(Debug, Clone)]
pub struct Observation<'a> {
    pub status: Result<&'a Status, NoStatus>,
    /// CLOCK_MONOTONIC now, less the last heartbeat.
    pub heartbeat_age_ns: u64,
    /// The generation `desired.conf` asks for; `None` when there is no
    /// readable file.
    pub desired_generation: Option<u64>,
    pub now_realtime_ns: u64,
    /// Whether any configured interface's packet count rose in the window.
    pub traffic: bool,
}

/// The coverage an observation shows, and why.
pub fn assess(o: &Observation<'_>) -> (Coverage, String) {
    let s = match &o.status {
        Ok(s) => s,
        Err(e) if e.incompatible => return (Coverage::Incompatible, e.why.clone()),
        Err(e) => return (Coverage::Unavailable, e.why.clone()),
    };
    if o.heartbeat_age_ns > HEARTBEAT_DEADLINE_NS {
        return (
            Coverage::Unavailable,
            format!("heartbeat {} ms old", o.heartbeat_age_ns / 1_000_000),
        );
    }
    match s.state {
        State::Initializing => return (Coverage::Unavailable, "plugin initialising".into()),
        State::Disabled => return (Coverage::Disabled, reason::describe(s.reason).into()),
        State::Enabled => {}
    }
    if s.rejected_reason != 0 {
        let kind =
            ErrorKind::from_code(s.rejected_reason).map_or("unknown reason", ErrorKind::describe);
        return (
            Coverage::Degraded,
            format!(
                "desired.conf generation {} refused ({kind}, line {}); generation {} still applied",
                s.rejected_generation, s.rejected_line, s.applied_generation
            ),
        );
    }
    match o.desired_generation {
        None => {
            return (
                Coverage::Degraded,
                format!(
                    "no desired.conf, but generation {} is still applied",
                    s.applied_generation
                ),
            )
        }
        Some(g) if g != s.applied_generation => {
            return (
                Coverage::Degraded,
                format!("desired generation {g}, applied {}", s.applied_generation),
            )
        }
        Some(_) => {}
    }
    let missing: Vec<&str> = s
        .interfaces
        .iter()
        .filter(|i| {
            i.sw_if_index.is_none()
                && o.now_realtime_ns.saturating_sub(i.unresolved_since_ns) > UNRESOLVED_GRACE_NS
        })
        .map(|i| i.name.as_str())
        .collect();
    if !missing.is_empty() {
        return (
            Coverage::Partial,
            format!("unresolved for over 30 s: {}", missing.join(", ")),
        );
    }
    if o.traffic {
        (Coverage::Healthy, "sampling as configured".into())
    } else {
        (
            Coverage::ZeroTraffic,
            "sampling as configured; no packets".into(),
        )
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::status::Interface;
    use crate::Class;

    const NOW: u64 = 1_790_000_000_000_000_000;

    fn status() -> Status {
        Status {
            state: State::Enabled,
            applied_generation: 4,
            rate: 1000,
            header_bytes: 128,
            classes: Class::Ingress.bit(),
            interfaces: vec![Interface {
                name: "octeon1/0".into(),
                sw_if_index: Some(2),
                pool_index: 0,
                unresolved_since_ns: 0,
            }],
            ..Status::default()
        }
    }

    fn obs(s: &Status) -> Observation<'_> {
        Observation {
            status: Ok(s),
            heartbeat_age_ns: 50_000_000,
            desired_generation: Some(4),
            now_realtime_ns: NOW,
            traffic: true,
        }
    }

    fn judge(o: Observation<'_>) -> Coverage {
        assess(&o).0
    }

    #[test]
    fn a_working_sampler_is_healthy_traffic_or_not() {
        let s = status();
        assert_eq!(judge(obs(&s)), Coverage::Healthy);
        assert_eq!(
            judge(Observation {
                traffic: false,
                ..obs(&s)
            }),
            Coverage::ZeroTraffic
        );
        assert!(Coverage::ZeroTraffic.is_healthy());
    }

    #[test]
    fn silence_is_never_healthy() {
        let s = status();
        let stale = Observation {
            heartbeat_age_ns: HEARTBEAT_DEADLINE_NS + 1,
            traffic: false,
            ..obs(&s)
        };
        assert_eq!(judge(stale), Coverage::Unavailable);
        let none = Observation {
            status: Err(NoStatus {
                incompatible: false,
                why: "no epoch".into(),
            }),
            ..obs(&s)
        };
        assert_eq!(judge(none), Coverage::Unavailable);
        let other = Observation {
            status: Err(NoStatus {
                incompatible: true,
                why: "layout 2".into(),
            }),
            ..obs(&s)
        };
        assert_eq!(judge(other), Coverage::Incompatible);
    }

    #[test]
    fn configuration_trouble_is_degraded_or_disabled() {
        let mut s = status();
        assert_eq!(
            judge(Observation {
                desired_generation: Some(5),
                ..obs(&s)
            }),
            Coverage::Degraded,
            "not applied yet"
        );
        assert_eq!(
            judge(Observation {
                desired_generation: None,
                ..obs(&s)
            }),
            Coverage::Degraded
        );
        s.rejected_generation = 5;
        s.rejected_reason = ErrorKind::Checksum.code();
        let (c, why) = assess(&obs(&s));
        assert_eq!(c, Coverage::Degraded);
        assert!(why.contains("checksum"), "{why}");

        let mut s = status();
        s.state = State::Disabled;
        s.reason = reason::NO_INTERFACES;
        assert_eq!(judge(obs(&s)), Coverage::Disabled);
        s.state = State::Initializing;
        assert_eq!(judge(obs(&s)), Coverage::Unavailable);
    }

    #[test]
    fn a_missing_interface_is_partial_only_after_the_grace() {
        let mut s = status();
        s.interfaces.push(Interface {
            name: "octeon0/0".into(),
            sw_if_index: None,
            pool_index: 1,
            unresolved_since_ns: NOW - UNRESOLVED_GRACE_NS + 1,
        });
        assert_eq!(judge(obs(&s)), Coverage::Healthy, "within the grace");
        s.interfaces[1].unresolved_since_ns = NOW - UNRESOLVED_GRACE_NS - 1;
        let (c, why) = assess(&obs(&s));
        assert_eq!(c, Coverage::Partial);
        assert!(why.contains("octeon0/0"));
    }
}
