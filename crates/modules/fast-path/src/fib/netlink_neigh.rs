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

use std::collections::HashMap;

use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::{
    link::{LinkAttribute, LinkMessage},
    neighbour::{NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState},
    route::RouteAttribute,
    RouteNetlinkMessage,
};
use rtnetlink::{
    new_connection, new_multicast_connection, Handle, MulticastGroup, RouteMessageBuilder,
};
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
    /// Cache mapping ifindex → egress MAC. Populated at startup via
    /// a single `RTM_GETLINK` dump; maintained by `RTM_NEWLINK` /
    /// `RTM_DELLINK` multicast events. Used to attach `src_mac` to
    /// `NeighEvent::Learned` so the FibProgrammer writes the correct
    /// Ethernet source address into `NEXTHOPS[id].src_mac`.
    iface_mac: HashMap<u32, [u8; 6]>,
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
                iface_mac: HashMap::new(),
            },
            events_rx,
            NeighborResolveHandle { resolve_tx },
        )
    }

    /// Main event loop. Runs until shutdown is signaled or the netlink
    /// stream closes unexpectedly.
    pub async fn run(mut self) -> Result<(), NeighError> {
        // Seed the ifindex→MAC cache from an RTM_GETLINK dump BEFORE
        // we start listening to the multicast stream. Otherwise a
        // NEWNEIGH arriving in the first few microseconds after
        // subscription would emit src_mac=[0;6] because we hadn't
        // discovered the egress iface yet.
        //
        // The dump uses a separate unicast netlink connection; the
        // multicast one below is dedicated to the event stream
        // (RTM_NEWNEIGH/DELNEIGH/NEWLINK/DELLINK) so dump traffic
        // doesn't compete with live events.
        match dump_link_macs().await {
            Ok(macs) => {
                self.iface_mac = macs;
                info!(
                    count = self.iface_mac.len(),
                    "ifindex→MAC cache seeded from RTM_GETLINK dump"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "RTM_GETLINK dump failed; src_mac will be [0;6] until RTM_NEWLINK events arrive"
                );
            }
        }

        let groups = [MulticastGroup::Neigh, MulticastGroup::Link];
        let (connection, handle, mut messages) = new_multicast_connection(&groups)
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
                            // Best-effort proactive resolve. If the route
                            // lookup or neighbor add fails, log at debug
                            // and fall back to first-packet kernel ARP.
                            issue_proactive_resolve(&handle, ip).await;
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
    ///
    /// Also maintains the `iface_mac` cache in response to RTM_NEWLINK
    /// / RTM_DELLINK so `src_mac` on subsequent `NeighEvent::Learned`
    /// reflects current egress MACs.
    async fn handle_packet(&mut self, packet: NetlinkMessage<RouteNetlinkMessage>) {
        match packet.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(msg)) => {
                let src_mac = self
                    .iface_mac
                    .get(&msg.header.ifindex)
                    .copied()
                    .unwrap_or([0; 6]);
                if let Some(evt) = parse_neighbour_add(&msg, src_mac) {
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
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(msg)) => {
                if let Some(mac) = extract_link_mac(&msg) {
                    let ifindex = msg.header.index;
                    let prev = self.iface_mac.insert(ifindex, mac);
                    if prev != Some(mac) {
                        debug!(
                            ifindex,
                            mac = format_args!(
                                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                            ),
                            "iface MAC cached"
                        );
                    }
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(msg)) => {
                let ifindex = msg.header.index;
                self.iface_mac.remove(&ifindex);
                debug!(ifindex, "RTM_DELLINK observed; MAC cache entry purged");
            }
            NetlinkPayload::Error(err) => {
                warn!(?err, "netlink error message");
            }
            _ => {}
        }
    }
}

/// Proactively kick kernel ARP/ND for `ip`. Looks up the route to
/// find the egress ifindex, then issues `RTM_NEWNEIGH` with
/// `state = NUD_NONE`. The kernel responds by starting resolution;
/// the eventual `RTM_NEWNEIGH` with a resolved state arrives via the
/// multicast subscription and turns into `NeighEvent::Learned` through
/// the normal path.
///
/// Best-effort. If the route lookup can't find an egress (dest
/// unroutable, or kernel's NETLINK_GET_STRICT_CHK doesn't accept our
/// message shape), or the neighbor add fails (EEXIST because the
/// neighbor already exists, permission issues, etc.), we log at debug
/// and return. The fallback is "kernel resolves when real traffic
/// arrives" — exactly what we'd get without proactive resolve, so
/// the only cost of a proactive-resolve failure is one-packet latency
/// on first forward.
async fn issue_proactive_resolve(handle: &Handle, ip: IpAddr) {
    let (oif, plen) = match ip {
        IpAddr::V4(v4) => {
            let req = RouteMessageBuilder::<IpAddr>::new()
                .destination_prefix(IpAddr::V4(v4), 32)
                .unwrap_or_else(|_| RouteMessageBuilder::<IpAddr>::new())
                .build();
            (lookup_oif(handle, req).await, 32u8)
        }
        IpAddr::V6(v6) => {
            let req = RouteMessageBuilder::<IpAddr>::new()
                .destination_prefix(IpAddr::V6(v6), 128)
                .unwrap_or_else(|_| RouteMessageBuilder::<IpAddr>::new())
                .build();
            (lookup_oif(handle, req).await, 128u8)
        }
    };
    let _ = plen; // retained for future per-family path divergence if needed
    let oif = match oif {
        Some(i) => i,
        None => {
            debug!(
                ?ip,
                "proactive resolve: route lookup returned no OIF; skipping"
            );
            return;
        }
    };
    // Issue the RTM_NEWNEIGH with NUD_NONE. The kernel interprets
    // "state NONE + no lladdr" as "initialize this neighbor and start
    // resolving." Replace lets the call be idempotent — if the
    // neighbor already exists, we quietly succeed.
    match handle
        .neighbours()
        .add(oif, ip)
        .state(NeighbourState::None)
        .replace()
        .execute()
        .await
    {
        Ok(()) => debug!(?ip, oif, "proactive resolve kicked"),
        Err(e) => debug!(?ip, oif, error = %e, "proactive resolve failed"),
    }
}

/// Query the main routing table for `msg`, return the OIF of the
/// first route returned. Kernel answers via a stream; we only care
/// about the first entry — subsequent entries for multipath routes
/// are handled at the programmer level via ECMP groups.
async fn lookup_oif(
    handle: &Handle,
    msg: netlink_packet_route::route::RouteMessage,
) -> Option<u32> {
    let mut routes = handle.route().get(msg).execute();
    match routes.try_next().await {
        Ok(Some(route)) => {
            for attr in route.attributes {
                if let RouteAttribute::Oif(idx) = attr {
                    return Some(idx);
                }
            }
            None
        }
        _ => None,
    }
}

/// Dump every link on the box via a single RTM_GETLINK-dump request;
/// return a fresh ifindex→MAC map. Uses a dedicated unicast netlink
/// connection — the main multicast one is owned by the select! loop.
///
/// Links without a usable MAC (e.g., tunnels, loopback, bridge masters
/// before an attachment) are skipped silently; they'll show up in a
/// later RTM_NEWLINK when their hardware address is set.
async fn dump_link_macs() -> Result<HashMap<u32, [u8; 6]>, NeighError> {
    let (connection, handle, _) =
        new_connection().map_err(|e| NeighError::new(format!("new_connection: {e}")))?;
    tokio::spawn(connection);

    let mut macs: HashMap<u32, [u8; 6]> = HashMap::new();
    let mut links = handle.link().get().execute();
    while let Some(msg) = links
        .try_next()
        .await
        .map_err(|e| NeighError::new(format!("link dump: {e}")))?
    {
        if let Some(mac) = extract_link_mac(&msg) {
            macs.insert(msg.header.index, mac);
        }
    }
    Ok(macs)
}

/// Pull the `Address` (IFLA_ADDRESS) attribute out of a LinkMessage
/// if it's a plausible Ethernet MAC. Returns None for non-Ethernet
/// links — tunnels encode the peer address in `Address` with varying
/// widths, and a 6-byte address on a tunnel isn't semantically what
/// we want as src_mac anyway.
fn extract_link_mac(msg: &LinkMessage) -> Option<[u8; 6]> {
    for attr in &msg.attributes {
        if let LinkAttribute::Address(bytes) = attr {
            if bytes.len() == 6 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(bytes);
                // Skip the all-zero MAC some virtual ifaces present
                // before they're configured — that would be worse than
                // not providing one (looks like a real address).
                if mac != [0; 6] {
                    return Some(mac);
                }
            }
        }
    }
    None
}

/// Build a [`NeighEvent`] from an RTM_NEWNEIGH message. Returns
/// `None` for transient or uninteresting states (`Incomplete` / `None`
/// — no MAC yet; `Other` — unknown variant). `src_mac` is the cached
/// egress iface MAC (Phase 3.6); `[0; 6]` when the cache hasn't been
/// populated for this ifindex yet.
fn parse_neighbour_add(msg: &NeighbourMessage, src_mac: [u8; 6]) -> Option<NeighEvent> {
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
                src_mac,
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

    const TEST_SRC_MAC: [u8; 6] = [0xbb, 0xbb, 0xbb, 0, 0, 42];

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
        match parse_neighbour_add(&msg, TEST_SRC_MAC) {
            Some(NeighEvent::Learned {
                ip: got_ip,
                mac,
                ifindex,
                src_mac,
            }) => {
                assert_eq!(got_ip, IpAddr::V4(ip));
                assert_eq!(mac, [0xaa, 0, 0, 0, 0, 1]);
                assert_eq!(ifindex, 42);
                assert_eq!(src_mac, TEST_SRC_MAC);
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
            parse_neighbour_add(&msg, TEST_SRC_MAC),
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
        assert!(parse_neighbour_add(&msg, TEST_SRC_MAC).is_none());
    }

    #[test]
    fn reachable_without_mac_is_skipped() {
        // Shouldn't happen from a real kernel, but be defensive.
        let ip = Ipv4Addr::new(10, 0, 0, 4);
        let msg = msg_with(
            NeighbourState::Reachable,
            vec![NeighbourAttribute::Destination(NeighbourAddress::Inet(ip))],
        );
        assert!(parse_neighbour_add(&msg, TEST_SRC_MAC).is_none());
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
