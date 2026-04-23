//! Netlink-backed `NeighborResolver` (Option F, Phase 2).
//!
//! Subscribes to `RTM_NEWNEIGH` / `RTM_DELNEIGH` / `RTM_NEWLINK` /
//! `RTM_DELLINK` multicast via rtnetlink's `new_multicast_connection`,
//! translates kernel neighbor-state into [`NeighEvent`], and exposes a
//! cloneable [`NeighborResolveHandle`] for proactive-resolve requests.
//!
//! Lifecycle:
//!   1. [`NetlinkNeighborResolver::new`] returns (resolver, events_rx, handle).
//!   2. `run()` (async) opens the multicast-subscribed netlink
//!      connection, spawns the rtnetlink connection task, then drives
//!      a `select!` loop that fans netlink packets → [`NeighEvent`]s.
//!   3. A [`CancellationToken`] shuts the loop down cooperatively.
//!
//! **Proactive resolve is a Phase 3 item.** The handle accepts
//! requests and logs them; the actual `ip neigh add ... nud none`
//! path needs a routing-table lookup first to discover the egress
//! ifindex for a given nexthop IP, which couples this module to
//! `rtnetlink::RouteHandle`. First-packet kernel ARP/ND already
//! triggers resolution on its own, so skipping proactive kicks only
//! adds a single-packet latency — not a correctness concern.
//!
//! No direct BPF-map writes happen here — the
//! [`FibProgrammer`](super::programmer) consumes `NeighEvent` and
//! owns the `NEXTHOPS` seqlock write path.

#![cfg(target_os = "linux")]

use std::net::IpAddr;

use futures::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
    RouteNetlinkMessage,
};
use rtnetlink::{new_multicast_connection, MulticastGroup};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use packetframe_common::fib::{NeighError, NeighEvent};

/// Outbound `NeighEvent` queue capacity. Sized to absorb a full-table
/// neighbor-churn storm without blocking the netlink reader. If the
/// programmer can't drain fast enough we apply backpressure, which is
/// fine — the kernel re-broadcasts neighbor state on the next event
/// and the programmer catches up.
const EVENTS_CAPACITY: usize = 8192;

/// Proactive-resolve request queue capacity. Every new route with an
/// unresolved nexthop queues one request; 1024 is ample for any
/// realistic Phase 3 convergence burst.
const RESOLVE_QUEUE_CAPACITY: usize = 1024;

/// Handle used by the [`FibProgrammer`](super::programmer) (and anyone
/// else holding a clone) to kick off proactive kernel-driven ARP/ND.
/// Fire-and-forget; if the internal queue is full, the request is
/// dropped with a warning.
#[derive(Clone)]
pub struct NeighborResolveHandle {
    resolve_tx: mpsc::Sender<IpAddr>,
}

impl NeighborResolveHandle {
    /// Request proactive resolution of `ip`. Non-blocking.
    pub fn request_resolve(&self, ip: IpAddr) {
        if let Err(e) = self.resolve_tx.try_send(ip) {
            warn!(
                ?ip,
                error = %e,
                "proactive resolve queue saturated; dropping request \
                 (kernel resolves on first real packet anyway)"
            );
        }
    }
}

pub struct NetlinkNeighborResolver {
    events_tx: mpsc::Sender<NeighEvent>,
    resolve_rx: mpsc::Receiver<IpAddr>,
    shutdown: CancellationToken,
}

impl NetlinkNeighborResolver {
    /// Construct the resolver. Returns:
    /// - the resolver itself (consume via [`run`](Self::run)),
    /// - the receiver end of the `NeighEvent` channel (hand to the
    ///   FibProgrammer),
    /// - a cloneable [`NeighborResolveHandle`] for proactive resolve.
    pub fn new(
        shutdown: CancellationToken,
    ) -> (Self, mpsc::Receiver<NeighEvent>, NeighborResolveHandle) {
        let (events_tx, events_rx) = mpsc::channel(EVENTS_CAPACITY);
        let (resolve_tx, resolve_rx) = mpsc::channel(RESOLVE_QUEUE_CAPACITY);
        (
            Self {
                events_tx,
                resolve_rx,
                shutdown,
            },
            events_rx,
            NeighborResolveHandle { resolve_tx },
        )
    }

    /// Main event loop. Runs until shutdown is signaled or the netlink
    /// stream closes unexpectedly.
    pub async fn run(mut self) -> Result<(), NeighError> {
        let groups = [MulticastGroup::Neigh, MulticastGroup::Link];
        let (connection, _handle, mut messages) = new_multicast_connection(&groups)
            .map_err(|e| NeighError::new(format!("new_multicast_connection: {e}")))?;
        tokio::spawn(connection);
        info!(
            groups = ?groups,
            "NeighborResolver netlink multicast subscription live"
        );

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("NeighborResolver shutdown requested");
                    return Ok(());
                }
                next = messages.next() => {
                    match next {
                        Some((packet, _)) => self.handle_packet(packet).await,
                        None => {
                            warn!("netlink multicast stream closed");
                            return Err(NeighError::new("netlink multicast stream closed"));
                        }
                    }
                }
                req = self.resolve_rx.recv() => {
                    match req {
                        Some(ip) => {
                            // Phase 3: full proactive resolve (route lookup
                            // → ifindex → `ip neigh add ... nud none`). For
                            // now log and rely on first-packet kernel ARP.
                            debug!(
                                ?ip,
                                "proactive resolve request queued (Phase 3 TODO; \
                                 kernel will resolve on first matching packet)"
                            );
                        }
                        None => {
                            // All NeighborResolveHandle clones dropped; continue
                            // draining neighbor events until shutdown fires.
                            debug!("resolve request channel closed");
                        }
                    }
                }
            }
        }
    }

    /// Translate one incoming netlink packet into zero or more
    /// [`NeighEvent`]s and push them into the events channel. Send
    /// errors (programmer too slow) log at debug because backpressure
    /// is expected during convergence bursts, not a bug.
    async fn handle_packet(&self, packet: NetlinkMessage<RouteNetlinkMessage>) {
        match packet.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(msg)) => {
                if let Some(evt) = parse_neighbour_add(&msg) {
                    if let Err(e) = self.events_tx.send(evt).await {
                        debug!(error = %e, "NeighEvent::Learned send failed");
                    }
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(msg)) => {
                if let Some(evt) = parse_neighbour_del(&msg) {
                    if let Err(e) = self.events_tx.send(evt).await {
                        debug!(error = %e, "NeighEvent::Gone send failed");
                    }
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(msg)) => {
                // Link-down ⇒ every neighbor on that iface is implicitly
                // gone. RTM_DELNEIGH events usually accompany it; Phase 2
                // relies on those. Tracking per-ifindex neighbor sets to
                // evict proactively lands in Phase 3 alongside route
                // scoping.
                debug!(ifindex = msg.header.index, "RTM_DELLINK observed");
            }
            NetlinkPayload::Error(err) => {
                warn!(?err, "netlink error message");
            }
            _ => {}
        }
    }
}

/// Build a [`NeighEvent`] from an RTM_NEWNEIGH message. Returns
/// `None` for transient or uninteresting states (`Incomplete` / `None`
/// — no MAC yet; `Other` — unknown variant).
fn parse_neighbour_add(msg: &NeighbourMessage) -> Option<NeighEvent> {
    let ip = extract_ip(&msg.attributes)?;

    match msg.header.state {
        NeighbourState::Failed => Some(NeighEvent::Failed {
            ip,
            reason: "kernel marked NUD_FAILED".into(),
        }),
        NeighbourState::Reachable
        | NeighbourState::Permanent
        | NeighbourState::Stale
        | NeighbourState::Delay
        | NeighbourState::Probe
        | NeighbourState::Noarp => {
            // States with a valid MAC. We forward using whatever the
            // kernel most recently confirmed; STALE still has an
            // actionable MAC, the kernel just hasn't re-validated it
            // recently.
            let mac = extract_mac(&msg.attributes)?;
            Some(NeighEvent::Learned {
                ip,
                mac,
                ifindex: msg.header.ifindex,
            })
        }
        // Incomplete / None: resolution in progress, no MAC yet. The
        // kernel will re-broadcast with a resolved state when ARP/ND
        // completes; we'll emit Learned then.
        _ => None,
    }
}

/// RTM_DELNEIGH → [`NeighEvent::Gone`].
fn parse_neighbour_del(msg: &NeighbourMessage) -> Option<NeighEvent> {
    extract_ip(&msg.attributes).map(|ip| NeighEvent::Gone { ip })
}

fn extract_ip(attrs: &[NeighbourAttribute]) -> Option<IpAddr> {
    for attr in attrs {
        if let NeighbourAttribute::Destination(addr) = attr {
            return match addr {
                NeighbourAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
                NeighbourAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
                // Non-IP families (MPLS, bridge FDB) aren't relevant
                // to IP-plane forwarding.
                _ => None,
            };
        }
    }
    None
}

fn extract_mac(attrs: &[NeighbourAttribute]) -> Option<[u8; 6]> {
    for attr in attrs {
        if let NeighbourAttribute::LinkLayerAddress(bytes) = attr {
            if bytes.len() == 6 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(bytes);
                return Some(mac);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn msg_with(state: NeighbourState, attrs: Vec<NeighbourAttribute>) -> NeighbourMessage {
        let mut m = NeighbourMessage::default();
        m.header.state = state;
        m.header.ifindex = 42;
        m.attributes = attrs;
        m
    }

    #[test]
    fn learned_from_reachable() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let msg = msg_with(
            NeighbourState::Reachable,
            vec![
                NeighbourAttribute::Destination(NeighbourAddress::Inet(ip)),
                NeighbourAttribute::LinkLayerAddress(vec![0xaa, 0, 0, 0, 0, 1]),
            ],
        );
        match parse_neighbour_add(&msg) {
            Some(NeighEvent::Learned {
                ip: got_ip,
                mac,
                ifindex,
            }) => {
                assert_eq!(got_ip, IpAddr::V4(ip));
                assert_eq!(mac, [0xaa, 0, 0, 0, 0, 1]);
                assert_eq!(ifindex, 42);
            }
            other => panic!("expected Learned, got {other:?}"),
        }
    }

    #[test]
    fn failed_from_nud_failed() {
        let ip = Ipv4Addr::new(10, 0, 0, 2);
        let msg = msg_with(
            NeighbourState::Failed,
            vec![NeighbourAttribute::Destination(NeighbourAddress::Inet(ip))],
        );
        assert!(matches!(
            parse_neighbour_add(&msg),
            Some(NeighEvent::Failed { .. })
        ));
    }

    #[test]
    fn incomplete_yields_no_event() {
        let ip = Ipv4Addr::new(10, 0, 0, 3);
        let msg = msg_with(
            NeighbourState::Incomplete,
            vec![NeighbourAttribute::Destination(NeighbourAddress::Inet(ip))],
        );
        assert!(parse_neighbour_add(&msg).is_none());
    }

    #[test]
    fn reachable_without_mac_is_skipped() {
        // Shouldn't happen from a real kernel, but be defensive.
        let ip = Ipv4Addr::new(10, 0, 0, 4);
        let msg = msg_with(
            NeighbourState::Reachable,
            vec![NeighbourAttribute::Destination(NeighbourAddress::Inet(ip))],
        );
        assert!(parse_neighbour_add(&msg).is_none());
    }

    #[test]
    fn del_always_emits_gone() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        let msg = msg_with(
            NeighbourState::Permanent,
            vec![NeighbourAttribute::Destination(NeighbourAddress::Inet(ip))],
        );
        assert!(matches!(
            parse_neighbour_del(&msg),
            Some(NeighEvent::Gone { .. })
        ));
    }
}
