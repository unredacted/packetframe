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

use std::net::{IpAddr, Ipv4Addr};

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

use packetframe_common::fib::{IpPrefix, NeighError, NeighEvent, PeerId, RouteEvent};

use crate::fib::programmer::FibProgrammerHandle;

/// Operator-declared local prefix (v0.2.1 connected fast-path). The
/// resolver walks the kernel ARP table for IPs falling in `cidr` that
/// are reachable via `iface`, and synthesizes per-/32 `RouteEvent::Add`s
/// into FibProgrammer so inbound traffic to those hosts fast-paths
/// through XDP redirect instead of falling to kernel slow path. See
/// [`packetframe_common::config::ModuleDirective::LocalPrefix`] for the
/// config-side surface.
#[derive(Debug, Clone)]
pub struct LocalPrefixSpec {
    /// Network address (host bits zeroed) of the prefix.
    pub addr: Ipv4Addr,
    /// Prefix length in bits, 0..=32.
    pub prefix_len: u8,
    /// The kernel iface name (e.g., `br1337`). Resolved to ifindex
    /// once at resolver startup via the RTM_GETLINK dump; if the iface
    /// doesn't exist at startup, the spec is logged and dropped (the
    /// resolver doesn't gate startup on it because operators may stage
    /// config before the iface comes up).
    pub iface: String,
}

impl LocalPrefixSpec {
    /// True iff `ip` falls within this prefix.
    fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let mask: u32 = (!0u32) << (32 - self.prefix_len as u32);
        let net = u32::from(self.addr) & mask;
        u32::from(ip) & mask == net
    }
}

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
    /// Diagnostic counters (Phase 3.9 debug). Logged periodically so
    /// the operator can see whether register_nexthop calls are
    /// landing on cache hits or fanning out to proactive probes.
    synth_learned_emitted: u64,
    cache_misses: u64,
    /// v0.2.1: count of /32 RouteEvents emitted for local-prefix hosts,
    /// split by add and remove. Logged in the same periodic stats line
    /// as the resolver counters above so operators can see at a glance
    /// whether the local-prefix sweep is doing useful work.
    local_arp_routes_added: u64,
    local_arp_routes_removed: u64,
    /// Cache mapping ifindex → egress MAC. Populated at startup via
    /// a single `RTM_GETLINK` dump; maintained by `RTM_NEWLINK` /
    /// `RTM_DELLINK` multicast events. Used to attach `src_mac` to
    /// `NeighEvent::Learned` so the FibProgrammer writes the correct
    /// Ethernet source address into `NEXTHOPS[id].src_mac`.
    iface_mac: HashMap<u32, [u8; 6]>,
    /// v0.2.1: name → ifindex map populated alongside `iface_mac` from
    /// the same RTM_GETLINK dump. Used to resolve user-facing iface
    /// names in `LocalPrefixSpec` to kernel ifindices once at startup
    /// (and re-resolve on RTM_NEWLINK if a previously-missing iface
    /// appears).
    iface_to_ifindex: HashMap<String, u32>,
    /// Cache of the kernel's neighbour table. Populated at startup via
    /// a single `RTM_GETNEIGH` dump; maintained by `RTM_NEWNEIGH` /
    /// `RTM_DELNEIGH` multicast events.
    ///
    /// **Why we need this** (Phase 3.9 fix): if the kernel already
    /// has a stable `REACHABLE` entry for a BGP nexthop when
    /// packetframe starts, the multicast subscription will never see
    /// it — multicast only fires on state *transitions*. Without this
    /// cache, `request_resolve(ip)` would issue an `RTM_NEWNEIGH
    /// NUD_NONE` probe for an entry the kernel already has, which
    /// the kernel correctly treats as a no-op and produces no event,
    /// leaving the nexthop forever `incomplete` in our NEXTHOPS map.
    /// Now `issue_proactive_resolve` consults this cache first and
    /// synthesizes a `Learned` event for any pre-existing entry,
    /// recovering the ~22 % of nexthops that would otherwise be
    /// stuck.
    neigh_cache: HashMap<IpAddr, (u32, [u8; 6])>,
    /// v0.2.1: operator-declared local prefixes. Empty when the feature
    /// is unused; non-empty enables the per-/32 fast-path emission
    /// path. Each spec is matched against (ip, ifindex) of every
    /// kernel neighbour event (and the startup dump) to decide whether
    /// to synthesize a `RouteEvent::Add` for the FibProgrammer.
    local_prefixes: Vec<LocalPrefixSpec>,
    /// v0.2.1: handle to the FibProgrammer for local-prefix /32
    /// emission. `None` when no local-prefix is configured (or when
    /// running under a test harness that doesn't drive a programmer
    /// — e.g., the existing netns ARP-walk tests).
    prog_handle: Option<FibProgrammerHandle>,
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
                iface_to_ifindex: HashMap::new(),
                neigh_cache: HashMap::new(),
                synth_learned_emitted: 0,
                cache_misses: 0,
                local_arp_routes_added: 0,
                local_arp_routes_removed: 0,
                local_prefixes: Vec::new(),
                prog_handle: None,
            },
            events_rx,
            NeighborResolveHandle { resolve_tx },
        )
    }

    /// Enable the v0.2.1 connected fast-path. `local_prefixes` are the
    /// operator-declared CIDRs from `local-prefix <cidr> via <iface>`
    /// config directives. `prog_handle` is the FibProgrammer handle
    /// the resolver uses to inject synthesized per-/32
    /// `RouteEvent::Add`/`Del`/`PeerDown` events.
    ///
    /// Pass an empty `local_prefixes` and the fast-path is a no-op
    /// (no extra netlink work, no event emission). Builder-style so
    /// the existing 1-arg `new()` callers (test harnesses, the
    /// kernel-fib-only path) keep compiling unchanged.
    pub fn with_local_prefixes(
        mut self,
        local_prefixes: Vec<LocalPrefixSpec>,
        prog_handle: FibProgrammerHandle,
    ) -> Self {
        self.local_prefixes = local_prefixes;
        self.prog_handle = Some(prog_handle);
        self
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
        match dump_link_info().await {
            Ok((macs, names)) => {
                self.iface_mac = macs;
                self.iface_to_ifindex = names;
                info!(
                    macs = self.iface_mac.len(),
                    names = self.iface_to_ifindex.len(),
                    "iface caches seeded from RTM_GETLINK dump"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "RTM_GETLINK dump failed; src_mac will be [0;6] until RTM_NEWLINK events arrive, \
                     and any configured local-prefix directives won't resolve until then"
                );
            }
        }

        // Phase 3.9 fix: seed the kernel-neighbour cache so
        // request_resolve(ip) for an already-REACHABLE entry can be
        // satisfied synchronously instead of relying on a multicast
        // event that won't fire (kernel only multicasts state
        // *transitions*, not steady state). Without this, BGP nexthops
        // ARP'd before packetframe started never get a Learned event.
        match dump_neighbours().await {
            Ok(neighs) => {
                self.neigh_cache = neighs;
                info!(
                    count = self.neigh_cache.len(),
                    "kernel neighbour cache seeded from RTM_GETNEIGH dump"
                );
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "RTM_GETNEIGH dump failed; pre-existing kernel neighbour entries \
                     won't be visible until they transition (degraded perf only — first-packet \
                     ARP is the fallback)"
                );
            }
        }

        // v0.2.1: seed the FibProgrammer with one /32 RouteEvent::Add
        // per kernel ARP entry that lives within an operator-declared
        // local-prefix CIDR + iface. The /32 wins in LPM over the /24
        // bird's iBGP exports (with state=Incomplete from the v0.2.1-A
        // listen-addr fallback), so inbound traffic to those hosts
        // fast-paths via XDP redirect. Without local-prefix configured
        // (`local_prefixes` empty), this loop is a no-op.
        //
        // The neigh_cache lookup inside FibProgrammer's register_nexthop
        // ↔ NeighborResolver ↔ programmer feedback path does the heavy
        // lifting once the route lands: registering nexthop=host_ip
        // calls request_resolve, which (post-rc4) consults this same
        // neigh_cache and synthesizes a Learned event back to the
        // programmer with the kernel-cached MAC. State flips Resolved.
        // Clone the handle so the &self borrow on `prog_handle` is
        // released before the call below takes &mut self for counter
        // updates. FibProgrammerHandle is `Clone` (cheap mpsc sender
        // wrapper); this is the documented usage pattern.
        if let Some(prog) = self.prog_handle.clone() {
            self.seed_local_prefix_routes(&prog).await;
        } else if !self.local_prefixes.is_empty() {
            warn!(
                count = self.local_prefixes.len(),
                "local-prefix directives configured but no FibProgrammer handle wired through; \
                 connected fast-path will not be enabled — file a bug if you see this on a \
                 production deploy"
            );
        }

        let groups = [MulticastGroup::Neigh, MulticastGroup::Link];
        let (connection, handle, mut messages) = new_multicast_connection(&groups)
            .map_err(|e| NeighError::new(format!("new_multicast_connection: {e}")))?;
        tokio::spawn(connection);
        info!(
            groups = ?groups,
            "NeighborResolver netlink multicast subscription live"
        );

        // Phase 3.9 diagnostic: periodic stats so we can see whether
        // synthetic Learned events are firing for most BGP nexthops or
        // not. Cheap (single info log every 10 s).
        let mut stats_tick = tokio::time::interval(std::time::Duration::from_secs(10));
        stats_tick.tick().await; // skip immediate fire

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
                            // Phase 3.9: synchronously resolve from
                            // the seeded cache first. If kernel already
                            // has a usable entry, emit Learned right
                            // here so the FibProgrammer flips the
                            // nexthop to Resolved immediately, no
                            // multicast wait. Falls through to the
                            // proactive RTM_NEWNEIGH NUD_NONE probe
                            // when the cache misses (kernel doesn't
                            // know the IP yet → first-packet ARP
                            // remains the safety net).
                            if let Some(&(ifindex, mac)) = self.neigh_cache.get(&ip) {
                                let src_mac = self
                                    .iface_mac
                                    .get(&ifindex)
                                    .copied()
                                    .unwrap_or([0; 6]);
                                let evt = NeighEvent::Learned { ip, mac, ifindex, src_mac };
                                match self.events_tx.send(evt).await {
                                    Ok(()) => {
                                        self.synth_learned_emitted += 1;
                                    }
                                    Err(e) => {
                                        warn!(?ip, error = %e, "synthetic Learned send failed");
                                    }
                                }
                            } else {
                                self.cache_misses += 1;
                                if self.cache_misses <= 20 {
                                    // First few misses — log explicitly so
                                    // the operator can see *which* IPs the
                                    // dump didn't capture.
                                    info!(?ip, "neighbour cache miss; proactive probe");
                                }
                                // Best-effort proactive resolve. If the route
                                // lookup or neighbor add fails, log at debug
                                // and fall back to first-packet kernel ARP.
                                issue_proactive_resolve(&handle, ip).await;
                            }
                        }
                        None => {
                            // All NeighborResolveHandle clones dropped; continue
                            // draining neighbor events until shutdown fires.
                            debug!("resolve request channel closed");
                        }
                    }
                }
                _ = stats_tick.tick() => {
                    // Periodic resolver stats. Helps diagnose whether
                    // register_nexthop calls are landing on cache hits
                    // (good — synthetic Learned fired) or misses (kernel
                    // didn't have an ARP entry; relying on proactive
                    // probe).
                    info!(
                        cache_size = self.neigh_cache.len(),
                        synth_learned_emitted = self.synth_learned_emitted,
                        cache_misses = self.cache_misses,
                        local_arp_routes_added = self.local_arp_routes_added,
                        local_arp_routes_removed = self.local_arp_routes_removed,
                        "neighbour resolver stats"
                    );
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
                    // Mirror Learned events into the local cache so
                    // a later request_resolve for the same IP hits
                    // synchronously (Phase 3.9 fix). Cache misses on
                    // Failed/Gone — those don't carry a usable MAC.
                    if let NeighEvent::Learned {
                        ip, mac, ifindex, ..
                    } = &evt
                    {
                        self.neigh_cache.insert(*ip, (*ifindex, *mac));
                        // v0.2.1: if this neighbour falls in a configured
                        // local-prefix and is reachable via the matching
                        // iface, emit a /32 RouteEvent::Add. The
                        // FibProgrammer takes it from there; we don't
                        // need to track per-/32 state ourselves —
                        // RouteEvent::Del on RTM_DELNEIGH is the symmetric
                        // cleanup, and PeerDown on RTM_DELLINK handles
                        // the iface-disappears case.
                        self.maybe_emit_local_arp_add(*ip, *ifindex).await;
                    }
                    if let Err(e) = self.events_tx.send(evt).await {
                        debug!(error = %e, "NeighEvent::Learned send failed");
                    }
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(msg)) => {
                // Capture ifindex before we move msg into parse_neighbour_del.
                let ifindex = msg.header.ifindex;
                if let Some(evt) = parse_neighbour_del(&msg) {
                    if let NeighEvent::Gone { ip } = &evt {
                        self.neigh_cache.remove(ip);
                        // v0.2.1 symmetric: withdraw the /32 if the
                        // departing neighbour was registered under a
                        // local-prefix.
                        self.maybe_emit_local_arp_del(*ip, ifindex).await;
                    }
                    if let Err(e) = self.events_tx.send(evt).await {
                        debug!(error = %e, "NeighEvent::Gone send failed");
                    }
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(msg)) => {
                let ifindex = msg.header.index;
                if let Some(mac) = extract_link_mac(&msg) {
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
                // v0.2.1: keep iface_to_ifindex current. An iface that
                // came up after packetframe started — covered by a
                // local-prefix that the operator staged in config —
                // becomes resolvable now.
                if let Some(name) = extract_link_name(&msg) {
                    self.iface_to_ifindex.insert(name, ifindex);
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(msg)) => {
                let ifindex = msg.header.index;
                self.iface_mac.remove(&ifindex);
                // Drop the name→ifindex mapping for this iface (single
                // pass; rare event).
                self.iface_to_ifindex.retain(|_, &mut v| v != ifindex);
                // v0.2.1: if this iface backed a local-prefix, withdraw
                // every /32 we registered for it. Cheap PeerDown event
                // to FibProgrammer; FibProgrammer's existing peer-walk
                // does the table sweep.
                self.maybe_emit_local_arp_peerdown(ifindex).await;
                debug!(ifindex, "RTM_DELLINK observed; iface caches purged");
            }
            NetlinkPayload::Error(err) => {
                warn!(?err, "netlink error message");
            }
            _ => {}
        }
    }

    /// Walk the seeded `neigh_cache` once at startup and emit a
    /// `RouteEvent::Add` for each entry that falls in a configured
    /// local-prefix CIDR + ifindex pair. v0.2.1.
    async fn seed_local_prefix_routes(&mut self, prog: &FibProgrammerHandle) {
        // Snapshot the cache under a copy so the iteration doesn't
        // borrow self while we call &mut self below for counter
        // updates. Cache is small (low thousands at most on the
        // reference EFG); allocation cost is irrelevant against the
        // single-shot startup work.
        let snapshot: Vec<(IpAddr, u32)> = self
            .neigh_cache
            .iter()
            .map(|(ip, (ifindex, _mac))| (*ip, *ifindex))
            .collect();
        let mut emitted = 0usize;
        for (ip, ifindex) in snapshot {
            let IpAddr::V4(v4) = ip else { continue };
            if let Some(peer_id) = self.match_local_prefix(v4, ifindex) {
                if let Err(e) = prog
                    .apply_route_event(RouteEvent::Add {
                        peer_id,
                        prefix: IpPrefix::V4 {
                            addr: v4.octets(),
                            prefix_len: 32,
                        },
                        nexthops: vec![ip],
                    })
                    .await
                {
                    warn!(?ip, error = %e, "local-prefix seed RouteEvent::Add dispatch failed");
                } else {
                    emitted += 1;
                    self.local_arp_routes_added += 1;
                }
            }
        }
        info!(
            emitted,
            local_prefixes = self.local_prefixes.len(),
            "local-prefix /32 seed complete"
        );
    }

    /// Same as [`Self::seed_local_prefix_routes`] but for a single
    /// (ip, ifindex) pair — called from the multicast event handler
    /// on RTM_NEWNEIGH. Idempotent against the FibProgrammer side
    /// (multiple Adds for the same /32 just bump a refcount).
    async fn maybe_emit_local_arp_add(&mut self, ip: IpAddr, ifindex: u32) {
        let IpAddr::V4(v4) = ip else { return };
        let Some(peer_id) = self.match_local_prefix(v4, ifindex) else {
            return;
        };
        // Clone to release the &self borrow on prog_handle before the
        // mutable counter update below — same pattern as
        // seed_local_prefix_routes. FibProgrammerHandle is cheap to
        // clone (mpsc Sender wrapper).
        let Some(prog) = self.prog_handle.clone() else {
            return;
        };
        if let Err(e) = prog
            .apply_route_event(RouteEvent::Add {
                peer_id,
                prefix: IpPrefix::V4 {
                    addr: v4.octets(),
                    prefix_len: 32,
                },
                nexthops: vec![ip],
            })
            .await
        {
            warn!(?ip, error = %e, "local-prefix RouteEvent::Add dispatch failed");
        } else {
            self.local_arp_routes_added += 1;
        }
    }

    /// Symmetric withdrawal for a single (ip, ifindex) on RTM_DELNEIGH.
    async fn maybe_emit_local_arp_del(&mut self, ip: IpAddr, ifindex: u32) {
        let IpAddr::V4(v4) = ip else { return };
        let Some(peer_id) = self.match_local_prefix(v4, ifindex) else {
            return;
        };
        let Some(prog) = self.prog_handle.clone() else {
            return;
        };
        if let Err(e) = prog
            .apply_route_event(RouteEvent::Del {
                peer_id,
                prefix: IpPrefix::V4 {
                    addr: v4.octets(),
                    prefix_len: 32,
                },
            })
            .await
        {
            warn!(?ip, error = %e, "local-prefix RouteEvent::Del dispatch failed");
        } else {
            self.local_arp_routes_removed += 1;
        }
    }

    /// On RTM_DELLINK for any iface that backed at least one
    /// local-prefix, send a single PeerDown to the FibProgrammer.
    /// Cheaper than walking the cache to emit per-/32 Dels and
    /// matches the existing semantics for BGP peer departure.
    async fn maybe_emit_local_arp_peerdown(&mut self, ifindex: u32) {
        // Only interesting if at least one local-prefix names this iface.
        let was_local = self.local_prefixes.iter().any(|spec| {
            self.iface_to_ifindex
                .get(&spec.iface)
                .copied()
                .map(|i| i == ifindex)
                .unwrap_or(false)
        });
        // After the iface_to_ifindex purge above, we may have already
        // lost the entry — fall back to comparing against any cached
        // matching done in seed time. For now the simpler heuristic is
        // "always emit a PeerDown if local-prefixes are configured at
        // all" — wasteful for ifaces that weren't local-prefix targets,
        // but safe (programmer's PeerDown handler is a HashMap walk
        // that does nothing for an unknown peer_id).
        if !was_local && self.local_prefixes.is_empty() {
            return;
        }
        let Some(prog) = self.prog_handle.clone() else {
            return;
        };
        let peer_id = PeerId::local_arp(ifindex);
        if let Err(e) = prog
            .apply_route_event(RouteEvent::PeerDown { peer_id })
            .await
        {
            warn!(ifindex, error = %e, "local-prefix RouteEvent::PeerDown dispatch failed");
        }
    }

    /// Match `(ip, ifindex)` against the configured `local_prefixes`.
    /// Returns the per-iface PeerId if one matches; `None` otherwise.
    /// Linear scan; the operator-declared list is small (handful at
    /// most on the reference EFG) so this is cheap on every neighbour
    /// event.
    fn match_local_prefix(&self, ip: Ipv4Addr, ifindex: u32) -> Option<PeerId> {
        for spec in &self.local_prefixes {
            if !spec.contains(ip) {
                continue;
            }
            if self.iface_to_ifindex.get(&spec.iface).copied() != Some(ifindex) {
                continue;
            }
            return Some(PeerId::local_arp(ifindex));
        }
        None
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
/// return both an `ifindex → MAC` map and a `name → ifindex` map.
/// Uses a dedicated unicast netlink connection — the main multicast
/// one is owned by the select! loop.
///
/// Links without a usable MAC (e.g., tunnels, loopback, bridge masters
/// before an attachment) are skipped silently in the MAC map; they'll
/// show up in a later RTM_NEWLINK when their hardware address is set.
/// The name map captures every iface regardless (every link has an
/// `IFNAME` attribute), so the v0.2.1 local-prefix path can resolve
/// iface names to ifindices for ifaces that don't have a MAC.
async fn dump_link_info() -> Result<(HashMap<u32, [u8; 6]>, HashMap<String, u32>), NeighError> {
    let (connection, handle, _) =
        new_connection().map_err(|e| NeighError::new(format!("new_connection: {e}")))?;
    tokio::spawn(connection);

    let mut macs: HashMap<u32, [u8; 6]> = HashMap::new();
    let mut names: HashMap<String, u32> = HashMap::new();
    let mut links = handle.link().get().execute();
    while let Some(msg) = links
        .try_next()
        .await
        .map_err(|e| NeighError::new(format!("link dump: {e}")))?
    {
        let ifindex = msg.header.index;
        if let Some(mac) = extract_link_mac(&msg) {
            macs.insert(ifindex, mac);
        }
        if let Some(name) = extract_link_name(&msg) {
            names.insert(name, ifindex);
        }
    }
    Ok((macs, names))
}

/// Pull the `IfName` (IFLA_IFNAME) attribute out of a `LinkMessage`.
/// Returns `None` if the attribute is absent (rare — the kernel sets
/// it on every iface) or non-UTF-8 (effectively never on Linux).
fn extract_link_name(msg: &LinkMessage) -> Option<String> {
    for attr in &msg.attributes {
        if let LinkAttribute::IfName(name) = attr {
            return Some(name.clone());
        }
    }
    None
}

/// Dump every neighbour in the kernel's table via a single
/// `RTM_GETNEIGH` dump and return an `IpAddr → (ifindex, mac)` map.
///
/// **Why this exists** (Phase 3.9): the multicast subscription only
/// observes neighbour state *transitions*, not the steady state at
/// the moment we subscribe. If the kernel already has REACHABLE
/// entries for BGP peers when packetframe starts (typical — bird's
/// been ARPing them for hours), we'd never see them. This dump
/// gives us a one-time snapshot to seed the cache, and the
/// multicast subscription keeps it current from then on.
///
/// Skips entries whose state isn't usable for forwarding
/// (Incomplete/None/Failed) and entries without a Link-Layer
/// Address attribute. STALE/DELAY/PROBE are kept — same policy as
/// `parse_neighbour_add` for the multicast path.
async fn dump_neighbours() -> Result<HashMap<IpAddr, (u32, [u8; 6])>, NeighError> {
    let (connection, handle, _) =
        new_connection().map_err(|e| NeighError::new(format!("new_connection: {e}")))?;
    tokio::spawn(connection);

    let mut out: HashMap<IpAddr, (u32, [u8; 6])> = HashMap::new();
    let mut neighs = handle.neighbours().get().execute();
    while let Some(msg) = neighs
        .try_next()
        .await
        .map_err(|e| NeighError::new(format!("neighbour dump: {e}")))?
    {
        // Use the same parser the multicast path uses so dump-time
        // and live-time behavior agree on what counts as resolved.
        // src_mac is filled in by the cache lookup at consumption
        // time; we only need (ip, mac, ifindex) here.
        if let Some(NeighEvent::Learned {
            ip, mac, ifindex, ..
        }) = parse_neighbour_add(&msg, [0; 6])
        {
            out.insert(ip, (ifindex, mac));
        }
    }
    Ok(out)
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

    // --- v0.2.1 LocalPrefixSpec --------------------------------------------

    #[test]
    fn local_prefix_contains_basic_ipv4() {
        let spec = LocalPrefixSpec {
            addr: "23.191.200.0".parse().unwrap(),
            prefix_len: 24,
            iface: "br1337".into(),
        };
        assert!(spec.contains("23.191.200.0".parse().unwrap()));
        assert!(spec.contains("23.191.200.10".parse().unwrap()));
        assert!(spec.contains("23.191.200.255".parse().unwrap()));
        assert!(!spec.contains("23.191.201.0".parse().unwrap()));
        assert!(!spec.contains("23.191.199.255".parse().unwrap()));
    }

    #[test]
    fn local_prefix_contains_handles_slash32() {
        let spec = LocalPrefixSpec {
            addr: "10.10.1.2".parse().unwrap(),
            prefix_len: 32,
            iface: "honeypot0".into(),
        };
        assert!(spec.contains("10.10.1.2".parse().unwrap()));
        assert!(!spec.contains("10.10.1.3".parse().unwrap()));
        assert!(!spec.contains("10.10.1.0".parse().unwrap()));
    }

    #[test]
    fn local_prefix_contains_handles_slash0() {
        // Edge case: 0.0.0.0/0 matches everything. Exercising the
        // overflow-guard path in `contains` (a 32-bit shift-by-32
        // would wrap; the guard short-circuits to true).
        let spec = LocalPrefixSpec {
            addr: "0.0.0.0".parse().unwrap(),
            prefix_len: 0,
            iface: "any".into(),
        };
        assert!(spec.contains("1.2.3.4".parse().unwrap()));
        assert!(spec.contains("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn local_prefix_contains_misalignment_is_treated_as_aligned() {
        // Operator wrote `local-prefix 23.191.200.5/24` (host bits
        // set). The mask logic ignores host bits when comparing —
        // semantically the prefix is still 23.191.200.0/24.
        let spec = LocalPrefixSpec {
            addr: "23.191.200.5".parse().unwrap(),
            prefix_len: 24,
            iface: "br1337".into(),
        };
        assert!(spec.contains("23.191.200.10".parse().unwrap()));
    }
}
