//! The resolver's synthesized routes, applied without holding the
//! resolver.
//!
//! ## Why
//!
//! The neighbour resolver makes routes of its own: a `/32` or `/128` for
//! each host it learns inside a `local-prefix`, the `fallback-default`
//! `0.0.0.0/0`, and a `PeerDown` when a link goes. Each is a command to
//! the [`FibProgrammer`](super::programmer), and the programmer takes no
//! command while it applies a route-ledger seed or a walk: no route event
//! may overtake either. The resolver used to await each one, so the first
//! such route at start parked it behind the whole seed. It answered no
//! resolve request meanwhile, and every next hop the seed registered sat
//! unresolved until the seed ended. On edge1-mci1 after the 6.0.17
//! upgrade (2026-11-12) that was 73 s, with 1.1M routes behind one
//! transit next hop the resolver never got to (`nexthop_resolve_slow`,
//! `not-served`).
//!
//! ## What it does
//!
//! The resolver hands each synthesized route to a [`RouteApplier`] and
//! goes on serving. The applier is a task of its own that applies them
//! one at a time, in the order they were handed over, awaiting each answer
//! as the resolver did: the programmer sees the same sequence, only the
//! resolver no longer waits for it. Its queue is unbounded, so the
//! resolver never blocks on it, and the programmer's own command queue,
//! which the BGP feed fills during a seed, is waited on here instead.
//!
//! The applier does not hold the resolver's "waiting on the
//! FibProgrammer" marker: that marker excuses the resolver's own stall
//! detector, and a backlog of routes here, expected while a seed applies,
//! must not hide a resolver that has really stopped. The backlog is in
//! the resolver's stats line instead (`synth_routes_pending`).

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use packetframe_common::fib::RouteEvent;

use super::programmer::FibProgrammerHandle;

/// What a route is, for its counter and its log line.
#[derive(Debug, Clone)]
pub enum RouteKind {
    /// A `local-prefix` host route for `ip`.
    HostAdd { ip: IpAddr },
    /// Its withdrawal.
    HostDel { ip: IpAddr },
    /// The `fallback-default` `/0` via `nexthop` on `iface`; `resend` when
    /// the same ifindex was already handed over.
    Fallback {
        iface: String,
        ifindex: u32,
        nexthop: IpAddr,
        resend: bool,
    },
    /// A departed link's `PeerDown`.
    PeerDown {
        ifindex: u32,
        carried_fallback: bool,
    },
}

/// What the applier has done, for the resolver's stats line.
#[derive(Debug, Default)]
pub struct ApplierStats {
    pub host_v4_added: AtomicU64,
    pub host_v4_removed: AtomicU64,
    pub host_v6_added: AtomicU64,
    pub host_v6_removed: AtomicU64,
    /// Handed over and not yet answered.
    pub pending: AtomicU64,
    pub failed: AtomicU64,
}

/// The resolver's side: hand a route over and carry on.
pub struct RouteApplier {
    tx: mpsc::UnboundedSender<(RouteEvent, RouteKind)>,
    stats: Arc<ApplierStats>,
}

impl RouteApplier {
    /// Start the applier task on the current runtime.
    pub fn spawn(prog: FibProgrammerHandle) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<(RouteEvent, RouteKind)>();
        let stats = Arc::new(ApplierStats::default());
        let counts = stats.clone();
        tokio::spawn(async move {
            while let Some((event, kind)) = rx.recv().await {
                let result = prog.apply_route_event(event).await;
                counts.pending.fetch_sub(1, Ordering::Relaxed);
                settle(&counts, &kind, result);
            }
        });
        Self { tx, stats }
    }

    /// Queue `event` behind every route handed over before it. Never
    /// waits. A closed applier (the runtime shutting down) drops it.
    pub fn submit(&self, event: RouteEvent, kind: RouteKind) {
        self.stats.pending.fetch_add(1, Ordering::Relaxed);
        if self.tx.send((event, kind)).is_err() {
            self.stats.pending.fetch_sub(1, Ordering::Relaxed);
            debug!("route applier closed; a synthesized route was dropped at shutdown");
        }
    }

    pub fn stats(&self) -> &ApplierStats {
        &self.stats
    }
}

fn settle(
    counts: &ApplierStats,
    kind: &RouteKind,
    result: Result<(), super::programmer::ProgrammerError>,
) {
    match (kind, result) {
        (RouteKind::HostAdd { ip }, Ok(())) => {
            let c = if ip.is_ipv4() {
                &counts.host_v4_added
            } else {
                &counts.host_v6_added
            };
            c.fetch_add(1, Ordering::Relaxed);
        }
        (RouteKind::HostDel { ip }, Ok(())) => {
            let c = if ip.is_ipv4() {
                &counts.host_v4_removed
            } else {
                &counts.host_v6_removed
            };
            c.fetch_add(1, Ordering::Relaxed);
        }
        (
            RouteKind::Fallback {
                iface,
                ifindex,
                nexthop,
                resend,
            },
            Ok(()),
        ) => {
            if *resend {
                debug!(%iface, ifindex, "fallback-default 0.0.0.0/0 re-sent on RTM_NEWLINK");
            } else {
                info!(%iface, ifindex, %nexthop, "v0.2.1 fallback-default 0.0.0.0/0 injected");
            }
        }
        (
            RouteKind::PeerDown {
                ifindex,
                carried_fallback: true,
            },
            Ok(()),
        ) => info!(
            ifindex,
            "fallback-default iface deleted; 0.0.0.0/0 withdrawn until its RTM_NEWLINK"
        ),
        (RouteKind::PeerDown { .. }, Ok(())) => {}
        (kind, Err(e)) => {
            counts.failed.fetch_add(1, Ordering::Relaxed);
            match kind {
                RouteKind::HostAdd { ip } => {
                    warn!(?ip, error = %e, "local-prefix RouteEvent::Add dispatch failed")
                }
                RouteKind::HostDel { ip } => {
                    warn!(?ip, error = %e, "local-prefix RouteEvent::Del dispatch failed")
                }
                RouteKind::Fallback { iface, ifindex, .. } => {
                    warn!(%iface, ifindex, error = %e, "fallback-default injection failed")
                }
                RouteKind::PeerDown { ifindex, .. } => {
                    warn!(ifindex, error = %e, "local_arp RouteEvent::PeerDown dispatch failed")
                }
            }
        }
    }
}
