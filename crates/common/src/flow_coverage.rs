//! What flow export can vouch for: per port and path, whether its samples
//! represent the traffic, and per collector, whether datagrams are being
//! submitted. Published by flow-export every tick for a consumer that
//! acts on telemetry, the DDoS mitigation's withdrawal hold first: a
//! collector that cannot tell silence from calm needs to know when the
//! silence is PacketFrame's.
//!
//! Pessimistic by construction. A snapshot older than [`STALE_AFTER`]
//! reads as none, so a worker that stopped or panicked vouches for
//! nothing; and a collector's state is local submission only, never
//! receipt ([`Receipt::Unverified`]).

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::config::CollectorKind;

/// A snapshot older than this says nothing about now: flow-export's
/// worker publishes one every 100 ms.
pub const STALE_AFTER: Duration = Duration::from_secs(1);

/// How far a port's samples on one path represent its traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathState {
    /// Within its startup grace: not yet judged.
    Starting,
    Covered,
    /// Samples lost or the sampler not as asked: counts are low by an
    /// unknown amount.
    Degraded(String),
    /// Not represented at all.
    Uncovered(String),
}

impl PathState {
    /// Whether a consumer may read the samples as the traffic.
    pub fn is_covered(&self) -> bool {
        *self == PathState::Covered
    }
}

/// One port on one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCoverage {
    /// The kernel port.
    pub port: String,
    pub ifindex: u32,
    /// `xdp`, `tc` or `vpp`.
    pub path: &'static str,
    pub state: PathState,
    /// Samples exported, and packets the path could have sampled, since
    /// flow export started.
    pub samples: u64,
    pub pool: u64,
}

/// What PacketFrame can know of a datagram it sent: the send succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Receipt {
    /// Whether the collector received it is the collector's to know.
    Unverified,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorSubmission {
    pub name: String,
    pub addr: SocketAddr,
    pub kind: CollectorKind,
    pub datagrams: u64,
    /// Why sends are failing or being dropped, if they are.
    pub failing: Option<String>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone)]
pub struct CoverageSnapshot {
    pub taken: Instant,
    /// 1 in N.
    pub rate: u32,
    pub paths: Vec<PathCoverage>,
    pub collectors: Vec<CollectorSubmission>,
}

/// The latest snapshot, `None` before flow-export's first tick and after
/// it stops.
#[derive(Debug, Default)]
pub struct FlowCoverage {
    current: RwLock<Option<Arc<CoverageSnapshot>>>,
}

impl FlowCoverage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&self, snapshot: CoverageSnapshot) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(snapshot));
    }

    /// Flow export stopped: it vouches for nothing.
    pub fn withdraw(&self) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// The latest snapshot, if it is fresh at `now`.
    pub fn current(&self, now: Instant) -> Option<Arc<CoverageSnapshot>> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .filter(|s| now.saturating_duration_since(s.taken) <= STALE_AFTER)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(taken: Instant) -> CoverageSnapshot {
        CoverageSnapshot {
            taken,
            rate: 1000,
            paths: vec![PathCoverage {
                port: "eth0".into(),
                ifindex: 2,
                path: "xdp",
                state: PathState::Covered,
                samples: 10,
                pool: 10_000,
            }],
            collectors: vec![CollectorSubmission {
                name: "fnm".into(),
                addr: "198.51.100.10:6343".parse().unwrap(),
                kind: CollectorKind::Ddos,
                datagrams: 3,
                failing: None,
                receipt: Receipt::Unverified,
            }],
        }
    }

    #[test]
    fn a_snapshot_vouches_only_while_fresh_and_until_withdrawn() {
        let h = FlowCoverage::new();
        let t0 = Instant::now();
        assert!(h.current(t0).is_none(), "nothing before the first tick");
        h.publish(snapshot(t0));
        assert!(h.current(t0 + STALE_AFTER).unwrap().paths[0]
            .state
            .is_covered());
        assert!(
            h.current(t0 + STALE_AFTER + Duration::from_millis(1))
                .is_none(),
            "a stopped worker vouches for nothing"
        );
        h.publish(snapshot(t0));
        h.withdraw();
        assert!(h.current(t0).is_none());
    }

    #[test]
    fn only_covered_is_covered() {
        for s in [
            PathState::Starting,
            PathState::Degraded("loss".into()),
            PathState::Uncovered("gone".into()),
        ] {
            assert!(!s.is_covered(), "{s:?}");
        }
    }
}
