//! Netlink-backed `NeighborResolver` (Option F, Phase 2).
//!
//! Subscribes to `RTM_NEWNEIGH` / `RTM_DELNEIGH` / `RTM_NEWLINK` /
//! `RTM_DELLINK` multicast via rtnetlink's `new_multicast_connection`,
//! translates kernel neighbor-state into [`NeighEvent`], and exposes a
//! cloneable [`NeighborResolveHandle`] for proactive-resolve requests.
//!
//! Lifecycle:
//!   1. [`NetlinkNeighborResolver::new`] returns (resolver, events_rx, handle).
//!   2. `run()` (async) supervises the resolver: it runs one
//!      *incarnation* at a time — subscribe to the multicast groups,
//!      read the kernel's links and neighbours, then a `select!` loop
//!      that fans netlink packets → [`NeighEvent`]s — and replaces an
//!      incarnation that exits or stops making progress.
//!   3. A [`CancellationToken`] shuts the loop down cooperatively.
//!
//! **Two sockets.** The multicast connection only ever listens. Every
//! request the loop makes — route lookups, neighbour kicks, read-backs,
//! dumps — goes over a separate unicast *request socket*, each bounded by
//! [`REQUEST_TIMEOUT`] or [`DUMP_TIMEOUT`]. On 2026-10-07 they shared the
//! multicast connection, unbounded: its receive buffer overflowed during
//! a link flush, the kernel dropped a request's reply along with the
//! notifications, and the loop waited for it forever. See
//! [`super::neigh_supervision`] for the whole incident and the rules
//! that answer it.
//!
//! **One request socket, and never a second while one is stuck.** This
//! is this module's policy, and it is stricter than "replace a socket
//! that timed out" for a reason particular to where it runs. A netlink
//! request is processed inside the sender's `sendmsg`, and neighbour
//! writes, single-entry gets and (on 5.15) dumps take `rtnl_lock` there,
//! so a request waiting on the lock blocks the *thread* polling its
//! connection — an abort cannot interrupt it. The resolver shares a
//! two-worker runtime with the FIB programmer and the route source: a
//! second socket blocked the same way would take the other worker, and
//! with it the programmer and the BGP session's keepalives. So a request
//! that times out retires its socket, and requests that cannot wait
//! ([`ProbeOutcome`]) are skipped until that socket's task has actually
//! exited; the programmer re-probes them, and is nudged when requests can
//! go out again. Reads of the kernel wait at most [`RETIRED_GRACE`] for it,
//! stop asking anything once their socket is retired mid-read (later
//! requests on it would queue behind the stuck one), and are retried by
//! the resync schedule. A reply the kernel dropped
//! costs one [`REQUEST_TIMEOUT`]; `rtnl_lock` held for a minute costs a
//! minute of skipped probes, never a stalled runtime.
//!
//! **Overruns are resyncs.** A full multicast socket loses notifications
//! (`ENOBUFS`, surfaced as `NLMSG_OVERRUN`). The loop answers one by
//! re-reading the kernel's links, neighbours and bridge FDB and
//! announcing the difference to its own view — the same code an
//! incarnation's startup runs — over a fresh subscription opened before
//! the dumps, because what the overflowed socket still holds is older
//! than what it dropped (see [`NetlinkNeighborResolver::resync_now`]).
//! An entry a dump does not list is confirmed gone with a single-entry
//! get before it is acted on, since a dump can skip a live entry.
//!
//! **Ownership across incarnations.** Everything an incarnation needs to
//! outlive it — the programmer's event channel, the resolve queue, the
//! view of what has been announced — lives in the resolver, which an
//! incarnation only borrows. Dropping a stuck incarnation therefore
//! drops its sockets and nothing else, and the next one continues on the
//! same channels from the same view.
//!
//! **Proactive resolve is a Phase 3 item.** The handle accepts
//! requests and logs them; the actual `ip neigh add ... nud none`
//! path needs a routing-table lookup first to discover the egress
//! ifindex for a given nexthop IP, which couples this module to
//! `rtnetlink::RouteHandle`. First-packet kernel ARP/ND already
//! triggers resolution on its own, so skipping proactive kicks only
//! adds a single-packet latency, not a correctness concern.
//!
//! No direct BPF-map writes happen here, the
//! [`FibProgrammer`](super::programmer) consumes `NeighEvent` and
//! owns the `NEXTHOPS` seqlock write path.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};

use std::collections::{HashMap, HashSet};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_REQUEST};
use netlink_packet_route::{
    link::{LinkAttribute, LinkMessage},
    neighbour::{
        NeighbourAddress, NeighbourAttribute, NeighbourFlags, NeighbourMessage, NeighbourState,
    },
    route::{RouteAttribute, RouteType},
    AddressFamily, RouteNetlinkMessage,
};
use rtnetlink::{
    new_connection, new_multicast_connection, Handle, MulticastGroup, RouteMessageBuilder,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use packetframe_common::config::{is_harvestable_v6, Ipv4Prefix, Ipv6Prefix};
use packetframe_common::events::{kind, Event};
use packetframe_common::fib::{IpPrefix, NeighError, NeighEvent, PeerId, RouteEvent};

use crate::fib::neigh_supervision::{
    reconcile_links, reconcile_neighbours, ExitCause, LinkObs, LogLimiter, OwedCause, OwedResync,
    Phase, RestartBackoff, RestartRecord, ResyncSchedule, SharedResolverStatus, StallWatch,
    SupervisionTiming, DUMP_TIMEOUT, REQUEST_TIMEOUT,
};
use crate::fib::programmer::FibProgrammerHandle;

/// Operator-declared local prefix (v0.2.1 connected fast-path). The
/// resolver walks the kernel neighbour table for IPs falling in `cidr`
/// that are reachable via `iface`, and synthesizes per-host
/// `RouteEvent::Add`s (a /32 for IPv4, a /128 for IPv6) into
/// FibProgrammer so inbound traffic to those hosts fast-paths through
/// XDP redirect instead of falling to kernel slow path. See
/// [`packetframe_common::config::ModuleDirective::LocalPrefix`] and
/// [`packetframe_common::config::ModuleDirective::LocalPrefix6`] for the
/// config-side surfaces.
///
/// Both families share this one type so the emission path
/// ([`NetlinkNeighborResolver::seed_local_prefix_routes`],
/// `maybe_emit_local_arp_add`/`_del`, `match_local_prefix`) is written
/// once rather than duplicated per family.
#[derive(Debug, Clone)]
pub struct LocalPrefixSpec {
    /// Network address of the prefix. Host bits need not be zeroed;
    /// containment ignores them.
    pub addr: IpAddr,
    /// Prefix length in bits: 0..=32 for v4, 0..=128 for v6.
    pub prefix_len: u8,
    /// The kernel iface name (e.g., `br1337`). Resolved to ifindex
    /// once at resolver startup via the RTM_GETLINK dump; if the iface
    /// doesn't exist at startup, the spec is logged and dropped (the
    /// resolver doesn't gate startup on it because operators may stage
    /// config before the iface comes up).
    pub iface: String,
    /// v0.2.1: when true, the resolver issues an ARP probe for every
    /// IP in the prefix at startup (capped to /22 = ≤ 1024 hosts to
    /// avoid kernel `gc_thresh3` overflow + ARP storms). Useful for
    /// quiet LANs (storage networks like Ceph) where hosts don't
    /// communicate L3 with the gateway and therefore never appear in
    /// `ip neigh show <iface>`. Off by default, generates noticeable
    /// ARP traffic during startup.
    ///
    /// **IPv4 only.** The config parser rejects `arp-scavenge` on
    /// `local-prefix6`, so this is always `false` for a v6 spec; see
    /// [`packetframe_common::config::ModuleDirective::LocalPrefix6`] for
    /// why there is no v6 equivalent.
    pub arp_scavenge: bool,
}

/// Operator-declared synthetic IPv4 default route (v0.2.1, issue #31).
/// The resolver injects a single `RouteEvent::Add { 0.0.0.0/0,
/// nexthops: [nexthop] }` under `iface`'s `local_arp` peer, at startup
/// and again whenever the iface appears (its `RTM_NEWLINK`), so the
/// PacketFrame FIB has a catch-all for destinations bird's iBGP feed
/// doesn't cover (RFC 1918,
/// CGNAT, test-net, anything not in DFZ). Otherwise those packets
/// miss LPM, fall to slow-path through netfilter / conntrack, and
/// get dropped upstream anyway. With this directive they XDP-redirect
/// to upstream, same upstream behavior, conntrack stays out of it.
///
/// `iface` is validated at startup against `/sys/class/net` (same
/// as `attach`/`local-prefix`); `nexthop` is the IPv4 address of an
/// existing reachable upstream peer (kernel ARP must already know it
/// or the resolver's existing proactive-resolve fires for it).
#[derive(Debug, Clone)]
pub struct FallbackDefaultSpec {
    pub iface: String,
    pub nexthop: Ipv4Addr,
}

impl LocalPrefixSpec {
    /// True iff `ip` falls within this prefix.
    ///
    /// A family mismatch is `false`, not an error: a v4 spec must never
    /// match a v6 neighbour and vice versa, and the resolver walks one
    /// mixed-family list against every neighbour event.
    ///
    /// Mask arithmetic (including the `/0` and `/max` shift-overflow
    /// guards) lives in the shared prefix helpers in `common` so it has
    /// exactly one implementation.
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => Ipv4Prefix {
                addr: net,
                prefix_len: self.prefix_len,
            }
            .contains_addr(ip),
            (IpAddr::V6(net), IpAddr::V6(ip)) => Ipv6Prefix {
                addr: net,
                prefix_len: self.prefix_len,
            }
            .contains_addr(ip),
            _ => false,
        }
    }
}

/// The single-host prefix we synthesize for a connected neighbour: a /32
/// for IPv4, a /128 for IPv6. Being maximally specific is the whole
/// point — it wins the LPM walk over any covering route from the BGP
/// feed, which is what routes the packet to this host's own MAC rather
/// than to an upstream nexthop.
fn host_prefix(ip: IpAddr) -> IpPrefix {
    match ip {
        IpAddr::V4(v4) => IpPrefix::V4 {
            addr: v4.octets(),
            prefix_len: 32,
        },
        IpAddr::V6(v6) => IpPrefix::V6 {
            addr: v6.octets(),
            prefix_len: 128,
        },
    }
}

/// Whether a neighbour address may be synthesized into a host route.
///
/// v4 is unconditional: the ARP table holds only unicast entries, and
/// the scavenge sweep already skips network and broadcast addresses.
///
/// v6 needs a real gate. The kernel's neighbour table carries
/// `NUD_NOARP` entries for multicast groups with a derived `33:33:xx`
/// MAC, which are indistinguishable from resolved unicast neighbours at
/// this layer, plus link-local addresses that are ambiguous across
/// interfaces. See [`is_harvestable_v6`] for the full reasoning.
///
/// Applied symmetrically on add **and** delete: an asymmetric filter
/// would leak routes that were installed before a config change.
fn may_synthesize(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(_) => true,
        IpAddr::V6(v6) => is_harvestable_v6(v6),
    }
}

/// Outbound `NeighEvent` queue capacity. Sized to absorb a full-table
/// neighbor-churn storm without blocking the netlink reader. If the
/// programmer can't drain fast enough we apply backpressure, which is
/// fine, the kernel re-broadcasts neighbor state on the next event
/// and the programmer catches up.
const EVENTS_CAPACITY: usize = 8192;

/// Proactive-resolve request queue capacity. Every new route with an
/// unresolved nexthop queues one request; 1024 is ample for any
/// realistic Phase 3 convergence burst.
const RESOLVE_QUEUE_CAPACITY: usize = 1024;

/// Receive buffer asked for on the multicast socket. The kernel default
/// (`net.core.rmem_default`, ~208 KiB) holds a few hundred notifications,
/// each charged at its skb's full size, and a link toggle on an IX bridge
/// flushes every neighbour and FDB entry behind it at once — the
/// 2026-10-07 socket dropped 40,401. 16 MiB is memory the kernel only
/// charges while a burst is queued. It makes an overrun rarer; it is not
/// what makes one harmless — the resync is.
pub const MULTICAST_RCVBUF: usize = 16 << 20;

/// The loop's housekeeping cadence: retire a request socket whose task
/// has exited, run a resync that has come due, re-send a re-probe nudge
/// the programmer could not take. Also what an idle loop's progress is
/// made of, so it bounds how stale [`SharedResolverStatus`] can look on a
/// healthy, quiet box.
const HOUSEKEEPING_EVERY: Duration = Duration::from_secs(1);

/// How long a read of the kernel (a resync, an incarnation's startup, a
/// single-link lookup) waits for a retired request socket to exit before
/// giving up and being retried. Long enough for an idle task's abort to
/// land; deliberately not long enough to wait out a socket blocked in the
/// kernel, which would leave the loop deaf to notifications for as long
/// — the resync's retry timer paces the attempts instead.
const RETIRED_GRACE: Duration = Duration::from_millis(100);

/// The most one read of the kernel spends confirming entries its dumps
/// did not list, past which the rest are deferred to the next resync.
/// A confirmation is one single-entry get, normally ~100 µs, so 2 s is
/// tens of thousands of them — more than any table — when the kernel is
/// answering. When it is answering slowly (`rtnl_lock` taken and released
/// over and over, each get waiting under its bound), this is what keeps a
/// thousand slow gets from holding the loop away from notifications and
/// resolve requests for minutes. A time budget, not a count, because the
/// cost of one get is exactly what is unknown.
const CONFIRM_BUDGET: Duration = Duration::from_secs(2);

/// Handle used by the [`FibProgrammer`](super::programmer) (and anyone
/// else holding a clone) to kick off proactive kernel-driven ARP/ND.
/// Fire-and-forget; if the internal queue is full, the request is
/// dropped with a warning.
#[derive(Clone)]
pub struct NeighborResolveHandle {
    resolve_tx: mpsc::Sender<IpAddr>,
}

impl NeighborResolveHandle {
    /// A handle with no resolver behind it, plus the receiving end of
    /// its queue. For harnesses that drive a `FibProgrammer` and want
    /// to observe *what* it asks to have resolved (and when) without
    /// running netlink; production always gets its handle from
    /// [`NetlinkNeighborResolver::new`].
    pub fn detached() -> (Self, mpsc::Receiver<IpAddr>) {
        let (resolve_tx, resolve_rx) = mpsc::channel(RESOLVE_QUEUE_CAPACITY);
        (Self { resolve_tx }, resolve_rx)
    }

    /// Request proactive resolution of `ip`. Non-blocking. Returns
    /// whether the request was enqueued: `false` means the bounded
    /// queue is full and nothing was asked, so the caller must not
    /// treat it as a probe that happened (the programmer's re-probe
    /// scheduler leaves the entry due and retries next tick).
    pub fn request_resolve(&self, ip: IpAddr) -> bool {
        match self.resolve_tx.try_send(ip) {
            Ok(()) => true,
            Err(e) => {
                debug!(
                    ?ip,
                    error = %e,
                    "proactive resolve queue saturated; request not enqueued"
                );
                false
            }
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
    /// Same, for `local-prefix6` /128s resolved via NDP. Kept separate
    /// from the ARP counters rather than summed: the runbook points
    /// operators at `local_arp_routes_added` as the "is it working"
    /// signal, and merging the families would make both numbers
    /// unreadable on a dual-stack segment.
    local_nd_routes_added: u64,
    local_nd_routes_removed: u64,
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
    /// it, multicast only fires on state *transitions*. Without this
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
    /// e.g., the existing netns ARP-walk tests).
    prog_handle: Option<FibProgrammerHandle>,
    /// v0.2.1 issue #31: optional synthetic 0.0.0.0/0 catch-all.
    /// `None` = no fallback (default). `Some(spec)` = a /0
    /// RouteEvent::Add under the iface's `local_arp` peer while the
    /// iface exists: injected at startup and on its RTM_NEWLINK,
    /// withdrawn with that peer on its RTM_DELLINK.
    fallback_default: Option<FallbackDefaultSpec>,
    /// The ifindex the fallback /0 was last acknowledged under by the
    /// programmer; cleared by that iface's RTM_DELLINK. Picks the log
    /// level only, never whether the Add is sent: the re-send every
    /// RTM_NEWLINK for the iface causes logs at debug, while the first
    /// injection, or the first after a failure or a recreate, logs at
    /// info.
    fallback_injected_on: Option<u32>,
    /// v0.2.9 FDB-pin chains: neighbor-bearing bridge ifindex (e.g.
    /// br1337) → (underlying bridge whose FDB decides the member port,
    /// e.g. switch0, egress VID). Snapshot from discovery at attach;
    /// empty = feature off (`fdb-pin off`, or no qualifying topology).
    /// Attach-time-bound like `local_prefixes` — topology changes need
    /// a restart, documented in the runbook.
    pin_chains: HashMap<u32, (u32, u16)>,
    /// v0.2.9: bridge FDB view, `(fdb bridge ifindex, MAC)` → member
    /// port ifindex. Seeded by an AF_BRIDGE RTM_GETNEIGH dump,
    /// maintained by AF_BRIDGE RTM_NEWNEIGH/RTM_DELNEIGH multicasts
    /// (which arrive on the same RTNLGRP_NEIGH group as ARP events).
    /// Only masters present in `pin_chains` values are tracked.
    fdb: HashMap<(u32, [u8; 6]), u32>,
    /// v0.2.9 diagnostic: pins sent / cleared, in the periodic stats.
    fdb_pins_sent: u64,
    fdb_pins_cleared: u64,
    /// v0.2.9: latest desired pin state per nexthop IP that the
    /// programmer has NOT accepted yet (bounded command queue full).
    /// Retried on every stats tick. This exists because unpins are
    /// one-shot: an FDB age-out produces a single `None` transition
    /// with no later event to regenerate it, so dropping one would
    /// strand a nexthop pinned to an expired port. Keyed by IP with
    /// last-write-wins, so churn collapses instead of accumulating.
    pending_pins: HashMap<IpAddr, Option<(u32, u16)>>,
    /// Interfaces in "IX mode" (the neigh-snoop module's `bridge <x>
    /// ix-mode`): on these the proactive `NUD_NONE` kick is never
    /// issued, because the kernel's resulting broadcast ARP / multicast
    /// NS is dropped by an upstream ACL and every attempt is a wasted
    /// frame; the snooper seeds these neighbours instead. Held by
    /// *name* and resolved to ifindex at check time through
    /// `iface_to_ifindex`, since the platform recreates bridges with
    /// new ifindexes and a stale ifindex would silently re-enable the
    /// kick.
    ix_interfaces: HashSet<String>,
    /// How many cache misses the IX-mode rule turned into no-ops.
    /// Shared so a test (or a future metrics reader) can observe it
    /// while the resolver owns itself inside `run()`.
    ix_probe_suppressed: Arc<AtomicU64>,

    // --- Supervision, resync, and the request socket ---
    /// What the resolver publishes about itself: progress, restarts,
    /// overruns, timeouts. Read by the `neigh-resolver` health row and
    /// the textfile metrics; written here and by the supervisor in
    /// [`Self::run`].
    status: SharedResolverStatus,
    timing: SupervisionTiming,
    /// Receive buffer to ask for on the multicast socket.
    multicast_rcvbuf: usize,
    /// The unicast socket every request and dump goes over. Never the
    /// multicast one; see the module docs.
    requester: Requester,
    resync: ResyncSchedule,
    /// 1 for the first incarnation, +1 per restart.
    incarnation: u64,
    /// The programmer to tell, after this resolver re-reads the kernel
    /// (a resync, or a restarted incarnation), to re-probe every
    /// nexthop it holds unresolved now rather than at its backoff — up
    /// to a minute away. Separate from `prog_handle`, whose presence
    /// switches on the local-prefix, fallback-default and FDB-pin
    /// features.
    reprobe_target: Option<FibProgrammerHandle>,
    /// A nudge the programmer's full command queue refused; re-sent by
    /// housekeeping.
    reprobe_owed: bool,
    /// Every resolve handle was dropped: the queue is closed for good,
    /// and its arm must stop being polled (a closed `recv` is always
    /// ready, so leaving it in the `select!` spins the loop).
    resolve_closed: bool,
    timeout_log: LogLimiter,
    overrun_log: LogLimiter,
    skip_log: LogLimiter,
    open_log: LogLimiter,
    resync_fail_log: LogLimiter,
    /// Fault injection for the tests; all off in production. See
    /// [`TestFaults`].
    faults: TestFaults,
    /// A probe was skipped for want of a request socket since one was
    /// last available; the next one to become available nudges the
    /// programmer (see [`Self::retired_socket_exited`]).
    probes_skipped_since_socket: bool,
    /// The multicast subscription the loop reads. Owned here, not by the
    /// loop, because a resync replaces it (see [`Self::resync_now`]);
    /// `None` between incarnations.
    subscription: Option<Subscription>,
}

/// **Fault injection, for the resolver's tests only.** Each field makes
/// one failure that the real kernel produces only under load or by
/// timing certain, so a netns test can assert what the resolver does
/// about it. [`Default`] is no fault at all, which is what production
/// runs; nothing outside the tests sets one.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
pub struct TestFaults {
    /// The first incarnation, serving a resolve request for this address,
    /// waits forever without making progress — the 2026-10-07 shape — so
    /// a test can watch the supervisor drop it and start one that
    /// recovers. Later incarnations serve the address normally.
    pub hang_on_resolve: Option<IpAddr>,
    /// Resync the moment an overrun is read, before the loop reads one
    /// more notification, so the overflowed socket's backlog is certainly
    /// still queued when the dump is taken. Production waits
    /// [`crate::fib::neigh_supervision::RESYNC_SETTLE`] and reads the
    /// backlog meanwhile, so whether any is left at the dump is timing.
    pub resync_at_overrun: bool,
    /// The next this-many request sockets are opened with nothing reading
    /// them, so every request on them waits for a reply that never comes:
    /// the 2026-10-07 request, now bounded.
    pub hang_request_sockets: u32,
    /// Neighbour dumps that announce (a resync, a restarted incarnation)
    /// leave these addresses out, as a dump that resumed past a concurrent
    /// deletion skips a live entry.
    pub dump_skips: Vec<IpAddr>,
    /// `RTM_NEWNEIGH` notifications for these addresses are dropped, as
    /// an overrun drops them, without the overrun that would trigger a
    /// resync — so the view misses the entry until something asks.
    pub lose_notifications_for: Vec<IpAddr>,
}

/// A read of the kernel that did not complete.
struct ReadFailure {
    error: String,
    /// Some of it was applied to the view (at least the link dump), so
    /// the view now reflects a dump newer than anything still queued on
    /// the subscription that was live before it.
    applied: bool,
}

impl ReadFailure {
    fn nothing_applied(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            applied: false,
        }
    }

    fn applied(incomplete: Vec<String>) -> Self {
        Self {
            error: incomplete.join("; "),
            applied: true,
        }
    }
}

/// A neighbour as a single-entry get finds it.
#[derive(Debug)]
enum NeighbourNow {
    /// Usable: `(ifindex, mac)`.
    Usable(u32, [u8; 6]),
    /// Held `NUD_FAILED` on this ifindex.
    Failed(u32),
}

/// What a single-entry get says about an entry a dump did not list.
enum Still<T> {
    Gone,
    /// It exists after all — the dump skipped it — and this is it now.
    Present(T),
    /// The get failed or timed out: unverifiable, so not acted on.
    Unknown(String),
}

/// Entries missing from a dump that could not be confirmed gone, and so
/// were left as they were. A non-empty one makes the read incomplete.
#[derive(Default)]
struct Unconfirmed {
    count: usize,
    first: Option<String>,
}

impl Unconfirmed {
    fn add(&mut self, error: String) {
        self.count += 1;
        self.first.get_or_insert(error);
    }

    fn into_result(self, what: &str) -> Result<(), String> {
        match self.first {
            None => Ok(()),
            Some(e) => Err(format!(
                "{} {what} missing from the dump could not be confirmed gone and were left as \
                 they were (first: {e})",
                self.count
            )),
        }
    }
}

/// One multicast subscription: the notifications in arrival order, and
/// the connection task that reads them off the socket. Dropping it
/// closes the socket and everything still queued on it.
struct Subscription {
    messages: futures::stream::BoxStream<'static, NetlinkMessage<RouteNetlinkMessage>>,
    _task: AbortOnDrop,
}

/// The request socket's lifecycle.
enum Requester {
    /// None open: the next request opens one.
    Closed,
    Open {
        handle: Handle,
        task: JoinHandle<()>,
    },
    /// A request on it timed out, so its task was aborted. No new socket
    /// is opened until that task has actually exited: a request blocked
    /// on `rtnl_lock` holds the worker thread its connection runs on
    /// until the kernel lets go (an abort cannot interrupt a syscall),
    /// and a second socket whose first request blocked the same way
    /// would take the runtime's other worker — and with it the
    /// programmer and the route source.
    Retired { task: JoinHandle<()> },
}

/// Aborts a spawned task when dropped: a multicast connection that is
/// being replaced or dropped must not outlive its [`Subscription`],
/// still subscribed and filling a socket nobody reads.
struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// `if_nametoindex(3)`: one ioctl, no netlink round trip. `None` when
/// the kernel has no interface by that name (or the name is not a
/// valid C string).
fn ifindex_by_name(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated string for the call's
    // duration; if_nametoindex reads it and returns 0 on failure.
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (idx != 0).then_some(idx)
}

/// What `issue_proactive_resolve` did with one cache miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// `RTM_NEWNEIGH NTF_USE` was accepted for the neighbour on `oif`;
    /// the kernel is soliciting (or already had it, see `read_back`).
    Kicked { oif: u32 },
    /// The neighbour write failed (logged at debug; first-packet ARP
    /// remains the fallback).
    Failed,
    /// The route lookup found no unicast egress.
    NoRoute,
    /// Unspecified nexthop: nothing to resolve.
    Unspecified,
    /// The egress, `oif`, is an IX-mode interface: deliberately not
    /// kicked (the entry is still read back; see `read_back`).
    Suppressed { oif: u32 },
    /// A request hit [`REQUEST_TIMEOUT`] at `stage`. The nexthop is left
    /// for the programmer's next re-probe and the request socket retired.
    TimedOut { stage: &'static str },
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
                local_nd_routes_added: 0,
                local_nd_routes_removed: 0,
                local_prefixes: Vec::new(),
                prog_handle: None,
                fallback_default: None,
                fallback_injected_on: None,
                pin_chains: HashMap::new(),
                fdb: HashMap::new(),
                fdb_pins_sent: 0,
                fdb_pins_cleared: 0,
                pending_pins: HashMap::new(),
                ix_interfaces: HashSet::new(),
                ix_probe_suppressed: Arc::new(AtomicU64::new(0)),
                status: SharedResolverStatus::new(SupervisionTiming::default().stall_after),
                timing: SupervisionTiming::default(),
                multicast_rcvbuf: MULTICAST_RCVBUF,
                requester: Requester::Closed,
                resync: ResyncSchedule::default(),
                incarnation: 0,
                reprobe_target: None,
                reprobe_owed: false,
                resolve_closed: false,
                timeout_log: LogLimiter::default(),
                overrun_log: LogLimiter::default(),
                skip_log: LogLimiter::default(),
                open_log: LogLimiter::default(),
                resync_fail_log: LogLimiter::default(),
                faults: TestFaults::default(),
                probes_skipped_since_socket: false,
                subscription: None,
            },
            events_rx,
            NeighborResolveHandle { resolve_tx },
        )
    }

    /// The status the resolver publishes, for the health row and the
    /// metrics. Take it before `run()` consumes the resolver.
    pub fn status(&self) -> SharedResolverStatus {
        self.status.clone()
    }

    /// The programmer to nudge into re-probing its unresolved nexthops
    /// after every resync and every restarted incarnation. Production
    /// always sets it; a harness without a programmer leaves it unset.
    pub fn with_reprobe_target(mut self, prog: FibProgrammerHandle) -> Self {
        self.reprobe_target = Some(prog);
        self
    }

    /// Replace the supervision timing. Production keeps the default;
    /// the tests shorten it so a stall is observable in seconds.
    pub fn with_supervision_timing(mut self, timing: SupervisionTiming) -> Self {
        self.timing = timing;
        self.status.update(|s| s.stall_after = timing.stall_after);
        self
    }

    /// Ask for a different multicast receive buffer than
    /// [`MULTICAST_RCVBUF`]. The tests ask for a tiny one, to make an
    /// overrun certain.
    pub fn with_multicast_rcvbuf(mut self, bytes: usize) -> Self {
        self.multicast_rcvbuf = bytes;
        self
    }

    /// **Fault injection, for the resolver's tests only.** See
    /// [`TestFaults`]; production never calls this.
    #[doc(hidden)]
    pub fn with_test_faults(mut self, faults: TestFaults) -> Self {
        self.faults = faults;
        self
    }

    /// Declare the IX-mode interfaces (by name). On a cache miss for a
    /// nexthop whose route egresses one of them, the proactive
    /// `NUD_NONE` kick is skipped and counted instead of sent: the
    /// kernel's broadcast/multicast resolution is dropped upstream on
    /// those links, so the kick could only ever cost frames. Empty =
    /// today's behaviour everywhere. Builder-style like the others.
    pub fn with_ix_interfaces(mut self, names: Vec<String>) -> Self {
        self.ix_interfaces = names.into_iter().collect();
        self
    }

    /// The suppressed-kick counter, readable after `run()` has taken
    /// ownership of the resolver.
    pub fn ix_probe_suppressed_counter(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.ix_probe_suppressed)
    }

    /// The current ifindexes of the IX-mode interfaces. Recomputed per
    /// miss (a handful of names) so a recreated bridge is honoured as
    /// soon as its RTM_NEWLINK has been seen.
    ///
    /// A name missing from the cache is asked of the kernel directly:
    /// the startup link dump can fail (`run()` continues without it)
    /// and a stable interface never emits a later RTM_NEWLINK, so a
    /// cache miss must not become a broadcast the operator promised
    /// the fabric would never see. A name the kernel does not know has
    /// no routes, so nothing is lost by leaving it out.
    fn ix_oifs(&self) -> HashSet<u32> {
        self.ix_interfaces
            .iter()
            .filter_map(|n| {
                self.iface_to_ifindex
                    .get(n)
                    .copied()
                    .or_else(|| ifindex_by_name(n))
            })
            .collect()
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

    /// v0.2.1 issue #31. Set the synthetic IPv4 default route. The
    /// resolver also needs a `prog_handle` to emit RouteEvents; if
    /// `with_local_prefixes` was already called the same handle is
    /// reused, otherwise the caller passes one here.
    pub fn with_fallback_default(
        mut self,
        spec: FallbackDefaultSpec,
        prog_handle: FibProgrammerHandle,
    ) -> Self {
        self.fallback_default = Some(spec);
        if self.prog_handle.is_none() {
            self.prog_handle = Some(prog_handle);
        }
        self
    }

    /// v0.2.9: enable FDB-pinned direct-to-port egress. `pin_chains`
    /// maps a neighbor-bearing bridge ifindex to `(fdb bridge ifindex,
    /// egress VID)` — the discovery side (linux_impl) derives it from
    /// the same collapsed chains that feed `VLAN_RESOLVE`, restricted
    /// to chains whose underlying device is itself a bridge. Empty map
    /// = no-op. Builder-style like `with_local_prefixes`.
    pub fn with_fdb_pin(
        mut self,
        pin_chains: HashMap<u32, (u32, u16)>,
        prog_handle: FibProgrammerHandle,
    ) -> Self {
        self.pin_chains = pin_chains;
        if self.prog_handle.is_none() {
            self.prog_handle = Some(prog_handle);
        }
        self
    }

    /// Run until shutdown, supervising: one incarnation at a time (see
    /// [`Self::run_once`]), replaced when it returns an error or makes no
    /// progress for [`SupervisionTiming::stall_after`] outside a wait on
    /// the programmer ([`StallWatch`]). A restart backs off
    /// ([`RestartBackoff`]), is counted, logged at error, recorded as a
    /// `neigh_resolver_restarted` event, and shown on the
    /// `neigh-resolver` health row.
    ///
    /// The incarnation is polled here, in this task, rather than
    /// spawned. It borrows the resolver, so dropping it — the only way to
    /// end one stuck in an await — releases the borrow and leaves the
    /// event sender, the resolve receiver and the announced view intact
    /// for the next. A spawned incarnation would own them and take them
    /// with it when aborted, closing the programmer's event channel.
    ///
    /// A panic is not handled here. The release profile aborts on panic,
    /// so one ends the whole daemon, and that does **not** recover by
    /// itself: the unit's `Restart=on-failure` start fails over the bpffs
    /// pins the dead daemon left (fast-path refuses to start over them),
    /// the start limit then marks the unit failed, and XDP keeps
    /// forwarding on the frozen maps until an operator runs the teardown
    /// in `crates/cli/debian/packetframe.service`'s header. That holds for
    /// a panic anywhere in the daemon; nothing here can catch one. What
    /// this covers is what keeps the daemon up with the resolver down: an
    /// error exit, or a stall.
    pub async fn run(mut self) {
        let status = self.status.clone();
        let shutdown = self.shutdown.clone();
        let timing = self.timing;
        let mut backoff = RestartBackoff::new(&timing);
        loop {
            let started = Instant::now();
            let cause = {
                let incarnation = self.run_once();
                tokio::pin!(incarnation);
                let mut watch = StallWatch::new(&timing);
                let mut check = tokio::time::interval(timing.check_every);
                loop {
                    tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => break None,
                        r = &mut incarnation => break Some(match r {
                            Ok(()) => ExitCause::Returned,
                            Err(e) => ExitCause::Failed(e.to_string()),
                        }),
                        _ = check.tick() => {
                            let (progress, waiting) = status.progress();
                            if let Some(silent) = watch.observe(Instant::now(), progress, waiting) {
                                break Some(ExitCause::Stalled { silent });
                            }
                        }
                    }
                }
            };
            // The incarnation is gone; its subscription must not linger
            // through the backoff, subscribed and filling a socket nobody
            // reads. The next incarnation subscribes afresh.
            self.subscription = None;
            // `None` is a shutdown, and so is an incarnation that returned
            // because of one: its own shutdown arm can win the race above.
            let Some(cause) = cause.filter(|_| !shutdown.is_cancelled()) else {
                status.update(|s| s.phase = Phase::Stopped);
                info!("NeighborResolver shutdown requested");
                return;
            };
            let ran_for = started.elapsed();
            let delay = backoff.delay_after(ran_for);
            let now = Instant::now();
            let restarts = status.update(|s| {
                s.counters.restarts += 1;
                s.last_restart = Some(RestartRecord {
                    at: now,
                    cause: cause.clone(),
                    ran_for,
                });
                s.phase = Phase::Restarting { until: now + delay };
                s.counters.restarts
            });
            error!(
                cause = %cause,
                restart = restarts,
                ran_for_s = ran_for.as_secs(),
                restart_in_ms = delay.as_millis() as u64,
                "neighbour resolver stopped working; restarting it — until the new one has read \
                 the kernel, nexthops neither resolve nor re-resolve and their traffic takes the \
                 kernel path"
            );
            let mut ev = Event::warn(crate::MODULE_NAME, kind::NEIGH_RESOLVER_RESTARTED)
                .field("cause", cause.code())
                .field("restarts", restarts)
                .field("ran_for_s", ran_for.as_secs())
                .field("backoff_ms", delay.as_millis() as u64)
                .detail(cause.to_string());
            if let ExitCause::Stalled { silent } = &cause {
                ev = ev.field("silent_ms", silent.as_millis() as u64);
            }
            ev.emit();
            tokio::select! {
                _ = shutdown.cancelled() => {
                    status.update(|s| s.phase = Phase::Stopped);
                    info!("NeighborResolver shutdown requested");
                    return;
                }
                _ = tokio::time::sleep(delay) => {}
            }
        }
    }

    /// One incarnation: subscribe, read the kernel, then serve
    /// notifications and resolve requests until shutdown (`Ok`) or until
    /// the multicast stream ends (`Err`). The supervisor in [`Self::run`]
    /// may also drop it mid-await. Everything that must survive that
    /// lives in `self`, and the view is updated only once the programmer
    /// has been told (see [`Self::learn`]), so a dropped incarnation
    /// leaves a view the next one's reconcile can trust.
    async fn run_once(&mut self) -> Result<(), NeighError> {
        self.incarnation += 1;
        let incarnation = self.incarnation;
        let first = incarnation == 1;
        self.status.update(|s| {
            s.phase = Phase::Starting;
            s.incarnation = incarnation;
        });
        self.status.beat();
        self.resync = ResyncSchedule::default();
        // The request socket carries over. Every request on it is bounded,
        // so a socket the previous incarnation could have been stuck on was
        // already retired by its timeout, and an open one is healthy (one
        // whose connection ended is replaced by `requester`). Retiring it
        // here would only make this incarnation's first read race the
        // abort's landing against `RETIRED_GRACE` on a loaded runtime.

        // Subscribe FIRST, then read the tables. Notifications raised while
        // the dumps run queue in the socket and are applied once the loop
        // starts, so nothing changes unseen between a dump and the
        // subscription (the FDB seed always relied on this order; the link
        // and neighbour reads now do too). Everything on the new socket is
        // no older than the subscription, so replaying it after the dump
        // only moves an entry forward: a notification the dump already
        // reflected is an idempotent re-announcement. Nothing is
        // *processed* before the link dump fills the MAC cache, so no
        // Learned goes out with a zeroed src_mac. The resync does the same
        // (see `resync_now`).
        self.subscription = Some(self.subscribe("startup")?);

        // The first incarnation fills its view silently, as startup always
        // has: nothing has been announced to the programmer yet, and it asks
        // for what it needs through the resolve queue. A later one
        // reconciles against the view the previous one announced and
        // announces the difference — what it missed while stuck or down.
        match self.read_kernel(!first).await {
            // A whole read answers any resync the last incarnation still
            // owed (its schedule did not survive it).
            Ok(()) => self.status.update(|s| {
                s.resync_owed = None;
                s.last_resync_error = None;
            }),
            Err(failure) => {
                warn!(
                    error = %failure.error,
                    incarnation,
                    "reading the kernel's links and neighbours failed; retrying as a resync — \
                     until then, entries that do not change are invisible here (first-packet \
                     ARP is the fallback)"
                );
                self.owe_resync(failure.error);
            }
        }

        if first {
            // v0.2.1: seed the FibProgrammer with one host route (/32 for
            // v4, /128 for v6) per kernel neighbour entry that lives within
            // an operator-declared local-prefix CIDR + iface. The host route
            // wins in LPM over the covering prefix from bird's iBGP exports
            // (with state=Incomplete from the v0.2.1-A listen-addr
            // fallback), so inbound traffic to those hosts fast-paths via
            // XDP redirect. Without local-prefix configured
            // (`local_prefixes` empty), this loop is a no-op.
            //
            // Each Add is followed by a synthetic Learned emitted directly
            // from the dump snapshot, so seeding does not depend on the
            // bounded resolve queue — which nothing drains until the select
            // loop below starts; see seed_local_prefix_routes for the full
            // rationale.
            //
            // Only once: a later incarnation's reconcile already announced
            // every host whose /32 the previous one had not (`learn`), and
            // the ARP scavenge inside the seed is a one-time sweep.
            if let Some(prog) = self.prog_handle.clone() {
                self.seed_local_prefix_routes(&prog).await;
            } else if !self.local_prefixes.is_empty() || self.fallback_default.is_some() {
                warn!(
                    local_prefixes = self.local_prefixes.len(),
                    has_fallback = self.fallback_default.is_some(),
                    "v0.2.1 directives configured but no FibProgrammer handle wired through; \
                     fast-path features will not be enabled, file a bug if you see this on a \
                     production deploy"
                );
            }
        }

        // v0.2.1 issue #31: inject the synthetic 0.0.0.0/0 if the operator
        // declared `fallback-default`. Order matters: the /0 goes in
        // *after* the per-/32 seed so ECMP-group dedup signatures don't
        // accidentally collapse the catch-all with a real route. Bird's
        // actual /0 (if any) wins via peer_id scoping inside FibProgrammer.
        //
        // After the subscription: an iface missing here is then certain to
        // reach handle_packet's RTM_NEWLINK arm when it appears, which is
        // the only other place the /0 is injected. Every incarnation, since
        // the programmer absorbs an unchanged Add and a dropped incarnation
        // may have been mid-injection.
        self.seed_fallback_default().await;

        // A restarted incarnation has just re-read the kernel: whatever the
        // programmer holds unresolved may now be resolvable, and its
        // re-probes may be backed off to a minute.
        if !first {
            self.nudge_reprobe();
        }
        self.status.update(|s| s.phase = Phase::Running);

        // Phase 3.9 diagnostic: periodic stats so we can see whether
        // synthetic Learned events are firing for most BGP nexthops or not.
        // Cheap (single info log every 10 s).
        let mut stats_tick = tokio::time::interval(Duration::from_secs(10));
        stats_tick.tick().await; // skip immediate fire
        let mut housekeeping = tokio::time::interval(HOUSEKEEPING_EVERY);
        // After a long arm (a resync, a wait on the programmer), one pass
        // is enough; a burst of missed ticks would repeat it for nothing.
        housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        housekeeping.tick().await;

        loop {
            // Re-borrowed every pass: a resync swaps the subscription.
            let messages = &mut self
                .subscription
                .as_mut()
                .expect("an incarnation subscribes before its loop")
                .messages;
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    return Ok(());
                }
                next = messages.next() => {
                    match next {
                        Some(packet) => self.handle_packet(packet).await,
                        None => {
                            warn!("netlink multicast stream closed");
                            return Err(NeighError::new("netlink multicast stream closed"));
                        }
                    }
                }
                req = self.resolve_rx.recv(), if !self.resolve_closed => {
                    match req {
                        Some(ip) => self.on_resolve_request(ip).await,
                        None => {
                            // All NeighborResolveHandle clones dropped; keep
                            // draining neighbour events until shutdown.
                            debug!("resolve request channel closed");
                            self.resolve_closed = true;
                        }
                    }
                }
                _ = housekeeping.tick() => self.housekeeping().await,
                _ = stats_tick.tick() => {
                    self.log_stats();
                    // Unpins are one-shot; a dropped one would strand a
                    // nexthop on an expired port. Retry here rather than
                    // relying on a future event that may never come.
                    self.retry_pending_pins();
                }
            }
            self.status.beat();
        }
    }

    /// One proactive-resolve request from the programmer.
    async fn on_resolve_request(&mut self, ip: IpAddr) {
        if self.incarnation == 1 && self.faults.hang_on_resolve == Some(ip) {
            std::future::pending::<()>().await;
        }
        // Phase 3.9: synchronously resolve from the seeded cache first. If
        // the kernel already has a usable entry, emit Learned right here so
        // the FibProgrammer flips the nexthop to Resolved immediately, no
        // multicast wait. Falls through to the proactive RTM_NEWNEIGH
        // NUD_NONE probe when the cache misses (kernel doesn't know the IP
        // yet → first-packet ARP remains the safety net).
        if let Some(&(ifindex, mac)) = self.neigh_cache.get(&ip) {
            // v0.2.9: pin state must reach the programmer before (or with)
            // the Learned that triggers the entry write; the pins map is
            // consulted at write time, so send it first.
            self.maybe_send_pin(ip, ifindex, mac);
            if self.send_learned(ip, ifindex, mac).await {
                self.synth_learned_emitted += 1;
            }
            return;
        }
        self.cache_misses += 1;
        if self.cache_misses <= 20 {
            // First few misses, log explicitly so the operator can see
            // *which* IPs the dump didn't capture.
            info!(?ip, "neighbour cache miss; proactive probe");
        }
        // Best-effort proactive resolve. If the route lookup or neighbor
        // add fails, log at debug and fall back to first-packet kernel ARP.
        let Some(handle) = self.requester(Duration::ZERO).await else {
            self.probe_skipped(ip);
            return;
        };
        let ix_oifs = self.ix_oifs();
        let outcome = issue_proactive_resolve(&handle, ip, &ix_oifs).await;
        self.status.beat();
        match outcome {
            ProbeOutcome::Suppressed { oif } => {
                let n = self.ix_probe_suppressed.fetch_add(1, Ordering::Relaxed) + 1;
                if n <= 20 {
                    info!(
                        ?ip,
                        "neighbour cache miss on an ix-mode interface; proactive probe \
                         suppressed (the snooper seeds it)"
                    );
                } else {
                    debug!(?ip, "proactive probe suppressed (ix-mode)");
                }
                // No kick, but still a read: a single-entry get is unicast
                // to the kernel and puts nothing on the fabric. Without it,
                // an entry the snooper installed that this view missed (an
                // overrun dropped its notification) would wait for the
                // kernel to next change it — which on an IX link, where
                // nothing solicits, may be never.
                self.read_back(&handle, ip, oif).await;
            }
            ProbeOutcome::Kicked { oif } => {
                self.read_back(&handle, ip, oif).await;
            }
            ProbeOutcome::TimedOut { stage } => self.request_timed_out(stage),
            ProbeOutcome::Failed | ProbeOutcome::NoRoute | ProbeOutcome::Unspecified => {}
        }
    }

    /// Housekeeping, every [`HOUSEKEEPING_EVERY`].
    async fn housekeeping(&mut self) {
        self.reap_requester();
        if self.resync.due().is_some_and(|due| due <= Instant::now()) {
            self.resync_now().await;
        }
        if self.reprobe_owed {
            self.nudge_reprobe();
        }
    }

    /// Periodic resolver stats. Helps diagnose whether register_nexthop
    /// calls are landing on cache hits (good, synthetic Learned fired) or
    /// misses (kernel didn't have an ARP entry; relying on proactive
    /// probe), and whether notifications are being lost. Its absence from
    /// the journal for more than a few seconds was the 2026-10-07
    /// fingerprint; the `neigh-resolver` health row now says so itself.
    fn log_stats(&self) {
        let c = self.status.snapshot().counters;
        info!(
            cache_size = self.neigh_cache.len(),
            synth_learned_emitted = self.synth_learned_emitted,
            cache_misses = self.cache_misses,
            local_arp_routes_added = self.local_arp_routes_added,
            local_arp_routes_removed = self.local_arp_routes_removed,
            local_nd_routes_added = self.local_nd_routes_added,
            local_nd_routes_removed = self.local_nd_routes_removed,
            fdb_entries = self.fdb.len(),
            fdb_pins_sent = self.fdb_pins_sent,
            fdb_pins_cleared = self.fdb_pins_cleared,
            fdb_pins_pending = self.pending_pins.len(),
            ix_probe_suppressed = self.ix_probe_suppressed.load(Ordering::Relaxed),
            incarnation = self.incarnation,
            overruns = c.overruns,
            resyncs = c.resyncs,
            resync_failures = c.resync_failures,
            request_timeouts = c.request_timeouts,
            probes_skipped = c.probes_skipped,
            restarts = c.restarts,
            "neighbour resolver stats"
        );
    }

    // --- The request socket ------------------------------------------------

    /// The request socket's handle, opening one if none is open. While a
    /// timed-out socket's task has not exited, waits up to `wait` for it
    /// (see [`Requester::Retired`]) and answers `None` if it is still
    /// there — as it does when a socket cannot be opened.
    async fn requester(&mut self, wait: Duration) -> Option<Handle> {
        if let Requester::Retired { task } = &mut self.requester {
            if !task.is_finished() && !wait.is_zero() {
                let _ = tokio::time::timeout(wait, &mut *task).await;
            }
            if !task.is_finished() {
                return None;
            }
            self.retired_socket_exited();
        }
        if let Requester::Open { handle, task } = &self.requester {
            // A connection whose task ended (its socket failed) would fail
            // every request from here on: open a fresh one instead.
            if !task.is_finished() {
                return Some(handle.clone());
            }
            debug!("netlink request socket's connection ended; opening a new one");
            self.requester = Requester::Closed;
        }
        match new_connection() {
            Ok((connection, handle, _unsolicited)) => {
                let task = if self.faults.hang_request_sockets > 0 {
                    // Fault injection: a connection nobody polls, so every
                    // request on it waits forever for its reply.
                    self.faults.hang_request_sockets -= 1;
                    tokio::spawn(async move {
                        let _held = connection;
                        std::future::pending::<()>().await;
                    })
                } else {
                    tokio::spawn(connection)
                };
                self.requester = Requester::Open {
                    handle: handle.clone(),
                    task,
                };
                // Probes skipped for want of a socket were still counted
                // as attempts by the programmer's backoff.
                if std::mem::take(&mut self.probes_skipped_since_socket) {
                    self.nudge_reprobe();
                }
                Some(handle)
            }
            Err(e) => {
                // Asked for on every probe, so rate-limited like the skips
                // it causes.
                if let Some(suppressed) = self.open_log.admit(Instant::now()) {
                    warn!(error = %e, suppressed, "netlink request socket could not be opened");
                }
                None
            }
        }
    }

    /// Abort the open request socket without waiting for it to exit; the
    /// next [`Self::requester`] does the waiting.
    fn retire_requester(&mut self) {
        if let Requester::Open { task, .. } =
            std::mem::replace(&mut self.requester, Requester::Closed)
        {
            task.abort();
            self.requester = Requester::Retired { task };
            self.status
                .update(|s| s.request_socket_stuck_since = Some(Instant::now()));
        }
    }

    /// Forget a retired socket whose task has exited.
    fn reap_requester(&mut self) {
        if let Requester::Retired { task } = &self.requester {
            if task.is_finished() {
                self.retired_socket_exited();
            }
        }
    }

    /// A retired socket's task has exited: requests can go out again. The
    /// programmer counted every probe skipped meanwhile as an attempt and
    /// backed it off accordingly — after a long `rtnl_lock` hold, to
    /// half a minute or more for probes never sent — so it is nudged to
    /// ask again now.
    fn retired_socket_exited(&mut self) {
        self.requester = Requester::Closed;
        self.status.update(|s| s.request_socket_stuck_since = None);
        if std::mem::take(&mut self.probes_skipped_since_socket) {
            self.nudge_reprobe();
        }
    }

    /// A request or a dump hit its bound. Counted, logged (rate-limited),
    /// and the socket retired: its reply may still come, or never — a
    /// reply the kernel dropped leaves the request pending inside
    /// netlink-proto for as long as the connection lives — so the next
    /// request gets a fresh socket. Whatever the request was for is left
    /// to its normal retry: a nexthop to the programmer's next re-probe,
    /// a dump to the resync schedule.
    fn request_timed_out(&mut self, what: &'static str) {
        let now = Instant::now();
        let total = self.status.update(|s| {
            s.counters.request_timeouts += 1;
            s.counters.request_timeouts
        });
        if let Some(suppressed) = self.timeout_log.admit(now) {
            warn!(
                what,
                timeouts_total = total,
                suppressed,
                request_timeout_s = REQUEST_TIMEOUT.as_secs(),
                dump_timeout_s = DUMP_TIMEOUT.as_secs(),
                "netlink request timed out; abandoned and its socket retired (the kernel was \
                 holding rtnl_lock, or dropped the reply)"
            );
        }
        self.retire_requester();
    }

    /// A proactive probe that could not be issued for want of a request
    /// socket. The programmer re-probes the nexthop at its next backoff.
    fn probe_skipped(&mut self, ip: IpAddr) {
        self.probes_skipped_since_socket = true;
        let total = self.status.update(|s| {
            s.counters.probes_skipped += 1;
            s.counters.probes_skipped
        });
        if let Some(suppressed) = self.skip_log.admit(Instant::now()) {
            warn!(
                ?ip,
                skipped_total = total,
                suppressed,
                "proactive probe skipped: no request socket (a timed-out request's socket is \
                 still held by the kernel, or a new one could not be opened); the programmer \
                 re-probes it later"
            );
        } else {
            debug!(?ip, "proactive probe skipped: no request socket");
        }
    }

    // --- Overruns and resyncs ----------------------------------------------

    /// The multicast socket overflowed: the kernel dropped notifications
    /// we will never see. Schedules a resync (coalesced, see
    /// [`ResyncSchedule`]).
    fn on_overrun(&mut self) {
        let now = Instant::now();
        self.resync.on_overrun(now);
        let total = self.status.update(|s| {
            s.counters.overruns += 1;
            s.resync_owed.get_or_insert(OwedResync {
                since: now,
                cause: OwedCause::Overrun,
            });
            s.counters.overruns
        });
        if let Some(suppressed) = self.overrun_log.admit(now) {
            warn!(
                overruns_total = total,
                suppressed,
                "neighbour/link notifications lost: the multicast socket's receive buffer \
                 overflowed; resyncing from a dump"
            );
        }
    }

    /// A read of the kernel did not complete: it is owed as a resync. An
    /// overrun already owed keeps its cause; the error says why the read
    /// meant to answer it did not.
    fn owe_resync(&mut self, error: String) {
        let now = Instant::now();
        self.resync.failed(now);
        self.status.update(|s| {
            s.counters.resync_failures += 1;
            s.resync_owed.get_or_insert(OwedResync {
                since: now,
                cause: OwedCause::ReadIncomplete,
            });
            s.last_resync_error = Some(error);
        });
    }

    /// Re-read the kernel and announce what the lost notifications would
    /// have, then nudge the programmer to re-probe what it holds
    /// unresolved.
    ///
    /// **Over a fresh subscription, opened before the dumps.** After an
    /// overflow the kernel reports `ENOBUFS` once and then hands over
    /// what it had queued *before* the drop — the oldest notifications,
    /// older than the ones it dropped. Dump on the same socket while that
    /// backlog is still queued (it drains a batch at a time, between the
    /// loop's other arms), and the rest of it replays *after* the dump: a
    /// `NEWNEIGH` whose `DELNEIGH` was dropped re-learns a dead neighbour
    /// as resolved, a `DELNEIGH` whose re-learn was dropped takes a live
    /// nexthop off the fast path, a stale `NEWLINK` re-adds a deleted
    /// link. So the dump is taken with a new socket already subscribed,
    /// and the loop then reads only that one: everything it holds is no
    /// older than its subscription, so applying it after the reconcile
    /// only moves entries forward, while everything left on the old one
    /// predates the dump and is dropped with it.
    ///
    /// The swap happens once any part of the read was applied, complete
    /// or not: the old backlog is older than that part, and what the read
    /// left unreconciled is owed and retried. A read that failed before
    /// applying anything (no request socket while a retired one is stuck
    /// on `rtnl_lock`, or a link dump that timed out) keeps the old
    /// subscription: with no dump to supersede it, its queue — including
    /// whatever arrived since the overrun — is still the freshest account
    /// there is, and dropping it every retry for the length of an `rtnl`
    /// hold would throw that away for nothing.
    async fn resync_now(&mut self) {
        let started = Instant::now();
        self.resync.start(started);
        let fresh = match self.subscribe("resync") {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "resync deferred: no fresh multicast subscription");
                self.owe_resync(e.to_string());
                return;
            }
        };
        let read = self.read_kernel(true).await;
        if read.as_ref().map_or_else(|f| f.applied, |()| true) {
            self.subscription = Some(fresh);
        }
        match read.map_err(|f| f.error) {
            Ok(()) => {
                let total = self.status.update(|s| {
                    s.counters.resyncs += 1;
                    s.resync_owed = None;
                    s.last_resync = Some(Instant::now());
                    s.last_resync_error = None;
                    s.counters.resyncs
                });
                info!(
                    resyncs_total = total,
                    took_ms = started.elapsed().as_millis() as u64,
                    "resynced links and neighbours from the kernel; the programmer re-probes its \
                     unresolved nexthops now"
                );
                self.nudge_reprobe();
            }
            Err(e) => {
                // Every RESYNC_RETRY for as long as the cause lasts (an
                // `rtnl` hold, a device the kernel will not answer for), so
                // rate-limited; the row and the counters carry the rest.
                if let Some(suppressed) = self.resync_fail_log.admit(Instant::now()) {
                    warn!(
                        error = %e,
                        suppressed,
                        retry_in_s = crate::fib::neigh_supervision::RESYNC_RETRY.as_secs(),
                        "resync failed; retrying"
                    );
                }
                self.owe_resync(e);
            }
        }
    }

    /// Subscribe to the neighbour and link groups on a new socket, with
    /// its receive buffer raised. The connection's request handle is
    /// dropped on the spot: nothing is ever asked of a multicast socket,
    /// whose replies an overrun can drop.
    fn subscribe(&self, why: &'static str) -> Result<Subscription, NeighError> {
        let groups = [MulticastGroup::Neigh, MulticastGroup::Link];
        let (mut connection, _, messages) = new_multicast_connection(&groups)
            .map_err(|e| NeighError::new(format!("new_multicast_connection: {e}")))?;
        match set_rcvbuf(connection.socket_mut().as_raw_fd(), self.multicast_rcvbuf) {
            Ok((granted, how)) if why == "startup" => info!(
                groups = ?groups,
                incarnation = self.incarnation,
                rcvbuf_bytes = granted,
                how,
                "NeighborResolver netlink multicast subscription live"
            ),
            Ok((granted, how)) => debug!(
                why,
                rcvbuf_bytes = granted,
                how,
                "NeighborResolver netlink multicast subscription opened"
            ),
            Err(e) => warn!(
                groups = ?groups,
                why,
                error = %e,
                "NeighborResolver netlink multicast subscription live, but its receive buffer \
                 could not be raised: overruns (and resyncs) will be more frequent"
            ),
        }
        Ok(Subscription {
            messages: messages.map(|(m, _)| m).boxed(),
            _task: AbortOnDrop(tokio::spawn(connection)),
        })
    }

    /// Ask the programmer to re-probe every nexthop it holds unresolved
    /// now. Re-sent from housekeeping while its queue is full.
    fn nudge_reprobe(&mut self) {
        let Some(prog) = self.reprobe_target.as_ref() else {
            return;
        };
        self.reprobe_owed = !prog.reprobe_unresolved_now();
    }

    /// Read the kernel's links, neighbours and (with FDB pins) bridge FDB,
    /// and bring the view in line with them. With `announce` every
    /// difference becomes an event — the `RTM_NEWLINK`/`RTM_DELLINK`
    /// effects for links, `Learned`/`Gone` for neighbours — exactly as if
    /// the lost notifications had arrived; without it (an incarnation's
    /// first read, when nothing has been announced) the view is just
    /// filled. The one implementation of the startup seed, a restart's
    /// reconcile and an overrun's resync.
    ///
    /// `Err` when any part did not complete — a dump failed, or an entry
    /// missing from a dump was not confirmed gone — after applying every
    /// part that did; the caller owes a resync for the rest, and learns
    /// from [`ReadFailure::applied`] whether anything was applied at all.
    ///
    /// Nothing more is asked of the request socket once it has been
    /// retired mid-read: a request that timed out on `rtnl_lock` leaves
    /// its connection alive in a task the kernel holds, and every later
    /// request on that handle would queue behind it and wait out its own
    /// bound — the loop deaf to notifications for as long as the lock is
    /// held. The rest of the read is owed instead.
    async fn read_kernel(&mut self, announce: bool) -> Result<(), ReadFailure> {
        let Some(handle) = self.requester(RETIRED_GRACE).await else {
            return Err(ReadFailure::nothing_applied(
                "no request socket: a timed-out request's socket is still held by the kernel, or \
                 a new one could not be opened",
            ));
        };
        let links = self
            .dump("link dump", dump_link_info(&handle))
            .await
            .map_err(ReadFailure::nothing_applied)?;
        let deadline = Instant::now() + CONFIRM_BUDGET;
        let mut incomplete: Vec<String> = Vec::new();
        incomplete.extend(
            self.apply_links(&handle, links, announce, deadline)
                .await
                .err(),
        );
        if !self.request_socket_open() {
            incomplete
                .push("the request socket was retired: neighbour and FDB dumps deferred".into());
            return Err(ReadFailure::applied(incomplete));
        }
        let mut neighbours = match self.dump("neighbour dump", dump_neighbours(&handle)).await {
            Ok(n) => n,
            Err(e) => {
                incomplete.push(e);
                return Err(ReadFailure::applied(incomplete));
            }
        };
        if announce && !self.faults.dump_skips.is_empty() {
            neighbours.retain(|(ip, _, _)| !self.faults.dump_skips.contains(ip));
        }
        incomplete.extend(
            self.apply_neighbours(&handle, neighbours, announce, deadline)
                .await
                .err(),
        );
        if !self.pin_chains.is_empty() && !self.request_socket_open() {
            incomplete.push("the request socket was retired: FDB dump deferred".into());
            return Err(ReadFailure::applied(incomplete));
        }
        incomplete.extend(self.refresh_fdb(&handle).await.err());
        if incomplete.is_empty() {
            Ok(())
        } else {
            Err(ReadFailure::applied(incomplete))
        }
    }

    /// Whether the request socket is open — not retired by a timeout since
    /// a read took its handle. See [`Self::read_kernel`].
    fn request_socket_open(&self) -> bool {
        matches!(self.requester, Requester::Open { .. })
    }

    /// Why one entry missing from a dump is not being confirmed now, or
    /// `None` when it can be: the request socket was retired mid-read, or
    /// the read's confirmation budget is spent.
    fn confirm_deferred(&self, deadline: Instant) -> Option<String> {
        if !self.request_socket_open() {
            Some("deferred: the request socket was retired".into())
        } else if Instant::now() >= deadline {
            Some(format!(
                "deferred: this read's {} s confirmation budget is spent",
                CONFIRM_BUDGET.as_secs()
            ))
        } else {
            None
        }
    }

    /// Await one dump, bounded by [`DUMP_TIMEOUT`].
    async fn dump<T>(
        &mut self,
        what: &'static str,
        fut: impl std::future::Future<Output = Result<T, NeighError>>,
    ) -> Result<T, String> {
        let result = match tokio::time::timeout(DUMP_TIMEOUT, fut).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(format!("{what}: {e}")),
            Err(_) => {
                self.request_timed_out(what);
                Err(format!(
                    "{what} timed out after {} s",
                    DUMP_TIMEOUT.as_secs()
                ))
            }
        };
        self.status.beat();
        result
    }

    /// Bring the link caches in line with a dump. See [`Self::read_kernel`].
    ///
    /// A link the dump does not list is not taken as deleted on that
    /// alone: a dump resumes from a position, and a deletion ahead of it
    /// between two of its chunks can skip a live entry. Acting on a
    /// skipped link would withdraw its local-prefix routes and its
    /// fallback default and forget its MAC, so every later `Learned` on it
    /// would carry a zeroed source MAC. Each is confirmed with a
    /// single-link get first ([`Self::confirm_link`]); one that is not
    /// confirmed (the get failed, or was deferred: see
    /// [`Self::confirm_deferred`]) is left as it is, and the read reported
    /// incomplete. Missing links go before changed ones, so a name a
    /// recreated bridge took over is withdrawn under the old index first.
    async fn apply_links(
        &mut self,
        handle: &Handle,
        links: Vec<LinkObs>,
        announce: bool,
        deadline: Instant,
    ) -> Result<(), String> {
        if !announce {
            // Seeded BEFORE any notification is processed: otherwise a
            // NEWNEIGH handled first would emit src_mac=[0;6] because the
            // egress iface had not been discovered yet.
            for l in links {
                if let Some(mac) = l.mac {
                    self.iface_mac.insert(l.ifindex, mac);
                }
                if let Some(name) = l.name {
                    self.iface_to_ifindex.insert(name, l.ifindex);
                }
            }
            info!(
                macs = self.iface_mac.len(),
                names = self.iface_to_ifindex.len(),
                "iface caches seeded from RTM_GETLINK dump"
            );
            return Ok(());
        }
        let delta = reconcile_links(&self.iface_mac, &self.iface_to_ifindex, &links);
        if delta.changed.is_empty() && delta.gone.is_empty() {
            return Ok(());
        }
        info!(
            changed = delta.changed.len(),
            missing = delta.gone.len(),
            "links reconciled against a dump; applying what the missed notifications would have"
        );
        let mut unconfirmed = Unconfirmed::default();
        for ifindex in delta.gone {
            if let Some(why) = self.confirm_deferred(deadline) {
                unconfirmed.add(why);
                continue;
            }
            match self.confirm_link(handle, ifindex).await {
                Still::Gone => self.on_link_gone(ifindex).await,
                // Skipped by the dump; what the get returned is current.
                Still::Present(link) => self.on_link(link).await,
                Still::Unknown(e) => unconfirmed.add(e),
            }
        }
        for link in delta.changed {
            self.on_link(link).await;
        }
        unconfirmed.into_result("link(s)")
    }

    /// Bring the neighbour view in line with a dump. See
    /// [`Self::read_kernel`] and [`reconcile_neighbours`].
    ///
    /// What the dump lists is applied first: those are the entries that
    /// put nexthops back on the fast path, and they need no further
    /// question of the kernel. Only then is each neighbour the dump does
    /// not list confirmed gone with a single-entry get before it is lost,
    /// for the reason [`Self::apply_links`] gives — a skipped live
    /// neighbour would otherwise take its nexthop off the fast path — and
    /// within the same deferral rules.
    async fn apply_neighbours(
        &mut self,
        handle: &Handle,
        dump: Vec<(IpAddr, u32, [u8; 6])>,
        announce: bool,
        deadline: Instant,
    ) -> Result<(), String> {
        let delta = reconcile_neighbours(&self.neigh_cache, &dump);
        if !announce {
            // Phase 3.9 fix: seed the kernel-neighbour cache so
            // request_resolve(ip) for an already-REACHABLE entry can be
            // satisfied synchronously instead of relying on a multicast
            // event that won't fire (kernel only multicasts state
            // *transitions*, not steady state). Without this, BGP nexthops
            // ARP'd before packetframe started never get a Learned event.
            for (ip, _) in &delta.lost {
                self.neigh_cache.remove(ip);
            }
            for &(ip, ifindex, mac) in &delta.learned {
                self.neigh_cache.insert(ip, (ifindex, mac));
            }
            info!(
                count = self.neigh_cache.len(),
                "kernel neighbour cache seeded from RTM_GETNEIGH dump"
            );
            return Ok(());
        }
        if delta.learned.is_empty() && delta.lost.is_empty() {
            return Ok(());
        }
        info!(
            learned = delta.learned.len(),
            missing = delta.lost.len(),
            "neighbours reconciled against a dump; announcing what the missed notifications \
             would have"
        );
        for (ip, ifindex, mac) in delta.learned {
            self.learn(ip, ifindex, mac).await;
        }
        let mut unconfirmed = Unconfirmed::default();
        for (ip, ifindex) in delta.lost {
            if let Some(why) = self.confirm_deferred(deadline) {
                unconfirmed.add(why);
                continue;
            }
            match self.confirm_neighbour(handle, ip, ifindex).await {
                Still::Gone => self.lose(ip, ifindex).await,
                Still::Present(NeighbourNow::Usable(now_if, mac)) => {
                    // Skipped by the dump. Announced only if it differs
                    // from what the view already holds.
                    if self.neigh_cache.get(&ip) != Some(&(now_if, mac)) {
                        self.learn(ip, now_if, mac).await;
                    }
                }
                // The dump leaves NUD_FAILED entries out; the kernel still
                // holds this one, failed. Announced as its notification
                // would have been: `Failed`, not `Gone` — the nexthop is
                // written Failed and its local-prefix route stays.
                Still::Present(NeighbourNow::Failed(on)) => {
                    self.fail(ip, on, "kernel marked NUD_FAILED".into()).await;
                }
                Still::Unknown(e) => unconfirmed.add(e),
            }
        }
        unconfirmed.into_result("neighbour(s)")
    }

    /// Whether a link a dump did not list is really gone: one non-dump
    /// `RTM_GETLINK` by index, bounded by [`REQUEST_TIMEOUT`]. `ENODEV` is
    /// gone; a reply is the link as it is now.
    async fn confirm_link(&mut self, handle: &Handle, ifindex: u32) -> Still<LinkObs> {
        let mut links = handle.link().get().match_index(ifindex).execute();
        let reply = tokio::time::timeout(REQUEST_TIMEOUT, links.try_next()).await;
        self.status.beat();
        match reply {
            Err(_) => {
                self.request_timed_out("link confirm");
                Still::Unknown(format!("link {ifindex}: timed out"))
            }
            Ok(Ok(Some(msg))) => Still::Present(link_obs(&msg)),
            Ok(Err(rtnetlink::Error::NetlinkError(e))) if e.raw_code() == -libc::ENODEV => {
                Still::Gone
            }
            Ok(Ok(None)) => Still::Unknown(format!("link {ifindex}: no reply")),
            Ok(Err(e)) => Still::Unknown(format!("link {ifindex}: {e}")),
        }
    }

    /// Whether a neighbour a dump did not list is really gone: one
    /// non-dump `RTM_GETNEIGH` for `(ifindex, ip)`, bounded by
    /// [`REQUEST_TIMEOUT`]. `ENOENT` is gone, and so is `ENODEV` — the
    /// device itself no longer exists, so neither can a neighbour on it;
    /// `neigh_get` answers that for an index the platform deleted (a
    /// recreated bridge), and reading it as "unknown" would owe a resync
    /// that can never be paid. An entry the kernel holds `NUD_FAILED` is
    /// reported as such ([`NeighbourNow::Failed`]), since the dump leaves
    /// those out as unusable but a notification would have announced it
    /// `Failed`, not lost; one in another state with no MAC (incomplete,
    /// none) is gone, as nothing usable is there. A kernel without
    /// single-entry gets (before 5.1, `EOPNOTSUPP`) cannot be asked, and
    /// there the dump's word is all there is.
    async fn confirm_neighbour(
        &mut self,
        handle: &Handle,
        ip: IpAddr,
        ifindex: u32,
    ) -> Still<NeighbourNow> {
        let mut h = handle.clone();
        let mut replies = match h.request(neigh_get_request(ip, ifindex)) {
            Ok(r) => r,
            Err(e) => return Still::Unknown(format!("{ip}: {e}")),
        };
        let first = tokio::time::timeout(REQUEST_TIMEOUT, async move {
            while let Some(msg) = replies.next().await {
                match msg.payload {
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(n)) => {
                        return Some(Ok(n));
                    }
                    NetlinkPayload::Error(e) => return Some(Err(e.raw_code())),
                    _ => {}
                }
            }
            None
        })
        .await;
        self.status.beat();
        match first {
            Err(_) => {
                self.request_timed_out("neighbour confirm");
                Still::Unknown(format!("{ip}: timed out"))
            }
            Ok(Some(Ok(n))) => match parse_neighbour_add(&n, [0; 6]) {
                Some(NeighEvent::Learned { ifindex, mac, .. }) => {
                    Still::Present(NeighbourNow::Usable(ifindex, mac))
                }
                Some(NeighEvent::Failed { ifindex, .. }) => {
                    Still::Present(NeighbourNow::Failed(ifindex))
                }
                Some(NeighEvent::Gone { .. }) | None => Still::Gone,
            },
            Ok(Some(Err(code)))
                if code == -libc::ENOENT || code == -libc::ENODEV || code == -libc::EOPNOTSUPP =>
            {
                Still::Gone
            }
            Ok(Some(Err(code))) => Still::Unknown(format!(
                "{ip}: {}",
                std::io::Error::from_raw_os_error(-code)
            )),
            Ok(None) => Still::Unknown(format!("{ip}: no reply")),
        }
    }

    /// v0.2.9 FDB-pin: (re-)read the bridge FDB view and re-derive the pin
    /// of every known neighbour on a pin chain.
    ///
    /// ORDERING IS LOAD-BEARING: this runs with the multicast
    /// subscription already live (an incarnation subscribes before it
    /// reads anything). Dumping first would leave a window in which an
    /// FDB entry can move or age out between the snapshot and the
    /// subscription — we would then publish the pre-move port and never
    /// see the event that corrected it, leaving traffic pinned to the
    /// wrong member port indefinitely. With the socket already open,
    /// events raised during the dump queue in the socket buffer and the
    /// select loop applies them afterwards, so the window closes at the
    /// cost of replaying a few redundant updates (handle_fdb_update is
    /// idempotent last-write-wins).
    ///
    /// Dump failure keeps the last view (empty at startup: "no pins
    /// yet"); the read is retried as a resync, the multicast maintenance
    /// rebuilds the view as entries refresh meanwhile, and unpinned
    /// traffic keeps taking the bridge path.
    async fn refresh_fdb(&mut self, handle: &Handle) -> Result<(), String> {
        if self.pin_chains.is_empty() {
            return Ok(());
        }
        let parents: HashSet<u32> = self
            .pin_chains
            .values()
            .map(|&(parent, _)| parent)
            .collect();
        let result = match self
            .dump("AF_BRIDGE neighbour dump", dump_fdb(handle, &parents))
            .await
        {
            Ok(fdb) => {
                info!(
                    entries = fdb.len(),
                    chains = self.pin_chains.len(),
                    "bridge FDB view seeded (AF_BRIDGE RTM_GETNEIGH dump)"
                );
                self.fdb = fdb;
                Ok(())
            }
            Err(e) => {
                warn!(error = %e, "AF_BRIDGE FDB dump failed; FDB pins follow the last view");
                Err(e)
            }
        };
        let known: Vec<(IpAddr, u32, [u8; 6])> = self
            .neigh_cache
            .iter()
            .map(|(ip, &(ifindex, mac))| (*ip, ifindex, mac))
            .collect();
        for (ip, ifindex, mac) in known {
            self.maybe_send_pin(ip, ifindex, mac);
        }
        result
    }

    // --- Applying what the kernel says -------------------------------------

    /// Translate one incoming netlink packet into zero or more
    /// [`NeighEvent`]s and push them into the events channel, and keep
    /// the link caches current. An overrun schedules a resync.
    async fn handle_packet(&mut self, packet: NetlinkMessage<RouteNetlinkMessage>) {
        match packet.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(msg)) => {
                // v0.2.9: AF_BRIDGE RTM_NEWNEIGH is an FDB entry, not
                // an ARP/ND neighbour — it carries a MAC + port but no
                // IP, so it must divert before parse_neighbour_add.
                if msg.header.family == AddressFamily::Bridge {
                    self.handle_fdb_update(&msg, true);
                    return;
                }
                match parse_neighbour_add(&msg, [0; 6]) {
                    Some(NeighEvent::Learned { ip, .. })
                        if self.faults.lose_notifications_for.contains(&ip) => {}
                    Some(NeighEvent::Learned {
                        ip, mac, ifindex, ..
                    }) => {
                        self.learn(ip, ifindex, mac).await;
                    }
                    Some(NeighEvent::Failed {
                        ip,
                        ifindex,
                        reason,
                    }) => self.fail(ip, ifindex, reason).await,
                    // Incomplete / None: resolution in progress, no MAC yet.
                    _ => {}
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(msg)) => {
                // v0.2.9: AF_BRIDGE FDB removal (age-out, port change,
                // flush). Unpins affected nexthops → they fall back to
                // the bridge path until the FDB relearns.
                if msg.header.family == AddressFamily::Bridge {
                    self.handle_fdb_update(&msg, false);
                    return;
                }
                if let Some(NeighEvent::Gone { ip, ifindex }) = parse_neighbour_del(&msg) {
                    self.lose(ip, ifindex).await;
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(msg)) => {
                self.on_link(link_obs(&msg)).await;
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(msg)) => {
                self.on_link_gone(msg.header.index).await;
            }
            NetlinkPayload::Overrun(_) => {
                self.on_overrun();
                if self.faults.resync_at_overrun {
                    self.resync_now().await;
                }
            }
            NetlinkPayload::Error(err) => {
                warn!(?err, "netlink error message");
            }
            _ => {}
        }
    }

    /// A usable neighbour the view does not hold, or holds differently —
    /// from a notification, a read-back, or a reconcile. The one place
    /// the view gains an entry, so all three agree on what announcing one
    /// means: the FDB pin first (the programmer consults pins at write
    /// time), the local-prefix host route, then the `Learned`.
    ///
    /// The view is written **after** the `Learned` is handed over, not
    /// before. It records what the programmer has been told, and a
    /// supervisor can drop this future at any await: written first, a
    /// dropped send would leave the view claiming an announcement that
    /// never happened, and the next reconcile would find nothing to fix.
    /// Mirroring it lets a later `request_resolve` for the same IP hit
    /// synchronously (Phase 3.9 fix). Returns whether the event was
    /// handed over.
    async fn learn(&mut self, ip: IpAddr, ifindex: u32, mac: [u8; 6]) -> bool {
        // v0.2.9: (re-)derive this neighbor's FDB pin — a MAC change
        // lands here and must move or clear the pin before the Learned
        // write races stale pin state.
        self.maybe_send_pin(ip, ifindex, mac);
        // v0.2.1: if this neighbour falls in a configured local-prefix and
        // is reachable via the matching iface, emit a /32 RouteEvent::Add.
        // RouteEvent::Del on loss is the symmetric cleanup, and PeerDown on
        // RTM_DELLINK handles the iface-disappears case.
        self.maybe_emit_local_arp_add(ip, ifindex).await;
        let sent = self.send_learned(ip, ifindex, mac).await;
        self.neigh_cache.insert(ip, (ifindex, mac));
        sent
    }

    /// A neighbour the kernel deleted, or a reconcile no longer finds:
    /// withdraw its local-prefix host route, announce `Gone`, then drop
    /// it from the view (after, for the reason [`Self::learn`] gives).
    async fn lose(&mut self, ip: IpAddr, ifindex: u32) {
        // v0.2.1 symmetric: withdraw the /32 if the departing neighbour
        // was registered under a local-prefix.
        self.maybe_emit_local_arp_del(ip, ifindex).await;
        self.send_event(NeighEvent::Gone { ip, ifindex }).await;
        self.forget(ip, ifindex);
    }

    /// The kernel declared a neighbour `NUD_FAILED`.
    async fn fail(&mut self, ip: IpAddr, ifindex: u32, reason: String) {
        self.send_event(NeighEvent::Failed {
            ip,
            ifindex,
            reason,
        })
        .await;
        // The cache must not outlive the kernel's verdict: the programmer
        // re-probes a failed nexthop through `request_resolve`, and a cache
        // hit there synthesizes a Learned from the stored MAC — the one the
        // kernel just declared unreachable.
        self.forget(ip, ifindex);
    }

    /// Drop `ip` from the view if the view has it on `ifindex`.
    /// Device-keyed like the kernel table: the same address can be
    /// deleted, or fail, on an interface we never resolved it through
    /// while the cached entry stays valid.
    fn forget(&mut self, ip: IpAddr, ifindex: u32) {
        if self
            .neigh_cache
            .get(&ip)
            .is_some_and(|&(cached_if, _)| cached_if == ifindex)
        {
            self.neigh_cache.remove(&ip);
        }
    }

    /// Hand the programmer a `Learned` for `(ip, ifindex, mac)`, with the
    /// egress interface's MAC as `src_mac` (zeroed for a MAC-less iface).
    async fn send_learned(&mut self, ip: IpAddr, ifindex: u32, mac: [u8; 6]) -> bool {
        let src_mac = self.iface_mac.get(&ifindex).copied().unwrap_or([0; 6]);
        self.send_event(NeighEvent::Learned {
            ip,
            mac,
            ifindex,
            src_mac,
        })
        .await
    }

    /// Hand one event to the programmer. Waits while its bounded channel
    /// is full — backpressure during a convergence burst, which the
    /// supervisor must not mistake for a stall, hence the wait marker. A
    /// failure means the programmer is gone (shutdown): logged at debug.
    // `&mut self`, not `&self`: a shared borrow held across the await
    // would need the resolver to be `Sync`, and the subscription it owns
    // is a `Send`-only stream.
    async fn send_event(&mut self, evt: NeighEvent) -> bool {
        let _wait = self.status.programmer_wait();
        match self.events_tx.send(evt).await {
            Ok(()) => true,
            Err(e) => {
                debug!(error = %e, "NeighEvent send failed");
                false
            }
        }
    }

    /// Apply one synthesized route (a local-prefix host route, the
    /// fallback default, a link's PeerDown) and wait for the programmer's
    /// answer — which, while it applies a route-ledger seed or a
    /// full-table burst, can be a long wait and is marked as one, for
    /// the reason [`Self::send_event`] gives.
    async fn apply_route(
        &mut self,
        prog: &FibProgrammerHandle,
        event: RouteEvent,
    ) -> Result<(), crate::fib::programmer::ProgrammerError> {
        let _wait = self.status.programmer_wait();
        prog.apply_route_event(event).await
    }

    /// An `RTM_NEWLINK`, or a link a reconcile found new or changed.
    /// Keeps `iface_mac` current, so `src_mac` on later Learned events
    /// reflects current egress MACs, and `iface_to_ifindex`, so an iface
    /// that came up after packetframe started — covered by a local-prefix
    /// the operator staged in config — becomes resolvable now.
    async fn on_link(&mut self, link: LinkObs) {
        let ifindex = link.ifindex;
        if let Some(mac) = link.mac {
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
        if let Some(name) = link.name {
            let is_fallback = self
                .fallback_default
                .as_ref()
                .is_some_and(|spec| spec.iface == name);
            self.iface_to_ifindex.insert(name, ifindex);
            // v0.2.1 issue #31: the fallback-default /0 follows its iface.
            // Absent at startup, or recreated after the RTM_DELLINK arm
            // withdrew it, the iface gets its /0 here. Every other
            // RTM_NEWLINK for it (flags, carrier, MTU) re-sends the same
            // Add, which the programmer's unchanged-nexthop shortcut
            // absorbs.
            if is_fallback {
                self.inject_fallback_default(ifindex).await;
            }
        }
    }

    /// An `RTM_DELLINK`, or a link a reconcile no longer finds.
    async fn on_link_gone(&mut self, ifindex: u32) {
        // Read before the purge below drops the name.
        let carried_fallback = self
            .fallback_default
            .as_ref()
            .is_some_and(|spec| self.iface_to_ifindex.get(&spec.iface).copied() == Some(ifindex));
        if self.fallback_injected_on == Some(ifindex) {
            self.fallback_injected_on = None;
        }
        self.iface_mac.remove(&ifindex);
        // Drop the name→ifindex mapping for this iface (single pass; rare
        // event).
        self.iface_to_ifindex.retain(|_, &mut v| v != ifindex);
        // v0.2.1: if this iface backed a local-prefix or the
        // fallback-default, withdraw every route we registered for it.
        // Cheap PeerDown event to FibProgrammer; FibProgrammer's existing
        // peer-walk does the table sweep.
        self.maybe_emit_local_arp_peerdown(ifindex, carried_fallback)
            .await;
        // The kernel flushed every neighbour on the device as it went. Its
        // RTM_DELNEIGHs normally arrived first and left nothing here, but
        // if they were lost (an overrun, or an incarnation stuck while the
        // platform recreated a bridge) the view would keep those entries
        // with nothing left to correct it: no dump lists them, no
        // single-entry get can find them (the device is gone), and no
        // notification will ever come. Lose them now, as the deletions
        // would have. Their local-prefix routes went with the PeerDown.
        let orphaned: Vec<IpAddr> = self
            .neigh_cache
            .iter()
            .filter(|(_, &(on, _))| on == ifindex)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in orphaned {
            self.lose(ip, ifindex).await;
        }
        debug!(ifindex, "RTM_DELLINK observed; iface caches purged");
    }

    /// After a kick the kernel accepted, or a kick suppressed on an
    /// IX-mode interface, read the entry back.
    ///
    /// `NTF_USE` is a no-op on a REACHABLE or PERMANENT neighbour. So
    /// when the kernel already knew the answer and only our cache did
    /// not — the startup dump failed, or the same address on another
    /// device displaced this one in the IP-keyed cache — no
    /// `RTM_NEWNEIGH` follows the kick, and the nexthop would sit
    /// `Incomplete`, re-probed on backoff, until some unrelated state
    /// change (never, for a permanent entry). One non-dump
    /// `RTM_GETNEIGH` for `(oif, ip)` closes that: a usable MAC in the
    /// reply is learned exactly as a notification would have been
    /// (review finding on #220).
    ///
    /// Best-effort, and bounded by [`REQUEST_TIMEOUT`]. `ENOENT` means
    /// nothing is there yet and the solicitation is in flight; a kernel
    /// without `neigh_get` (pre-5.1) answers `EOPNOTSUPP`. Both fall
    /// through to the multicast path, which is where the answer arrives
    /// in the common case anyway.
    async fn read_back(&mut self, handle: &Handle, ip: IpAddr, oif: u32) {
        let mut h = handle.clone();
        let mut replies = match h.request(neigh_get_request(ip, oif)) {
            Ok(r) => r,
            Err(e) => {
                debug!(?ip, oif, error = %e, "neighbour read-back request failed");
                return;
            }
        };
        let first = tokio::time::timeout(REQUEST_TIMEOUT, async move {
            while let Some(msg) = replies.next().await {
                match msg.payload {
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(n)) => {
                        return Some(Ok(n));
                    }
                    NetlinkPayload::Error(e) => return Some(Err(e.code)),
                    _ => {}
                }
            }
            None
        })
        .await;
        self.status.beat();
        match first {
            Err(_) => self.request_timed_out("neighbour read-back"),
            Ok(Some(Ok(n))) => {
                if let Some(NeighEvent::Learned {
                    ip: got,
                    mac,
                    ifindex,
                    ..
                }) = parse_neighbour_add(&n, [0; 6])
                {
                    if self.learn(got, ifindex, mac).await {
                        self.synth_learned_emitted += 1;
                        debug!(
                            ?got,
                            ifindex,
                            "kernel already held a usable neighbour; Learned synthesized from \
                             read-back"
                        );
                    }
                }
            }
            Ok(Some(Err(code))) => {
                debug!(
                    ?ip,
                    oif,
                    ?code,
                    "neighbour read-back: no entry yet (solicitation in flight) or neigh_get \
                     unsupported"
                );
            }
            Ok(None) => {}
        }
    }

    /// v0.2.9: derive and send the FDB pin for one neighbor. No-op
    /// unless `ifindex` is a pin-chain bridge. Sends `Some((port,
    /// vid))` when the underlying bridge's FDB places `mac` behind a
    /// member port, `None` (explicit un-pin) otherwise — the explicit
    /// clear matters when a neighbor's MAC changes or its FDB entry
    /// ages out, so a stale pin can never outlive the evidence for it.
    /// Idempotent by construction; the programmer absorbs repeats.
    fn maybe_send_pin(&mut self, ip: IpAddr, ifindex: u32, mac: [u8; 6]) {
        if self.prog_handle.is_none() {
            return;
        }
        let Some(&(parent, vid)) = self.pin_chains.get(&ifindex) else {
            // The nexthop is NOT on a pin chain — but it may have been
            // a moment ago. The programmer deliberately retains pins
            // across Gone/unregister/re-register, so returning early
            // here would let a later Learned event on the new
            // interface consult the OLD pin and write the new MAC with
            // the previous bridge member's port and VID. Routing moving
            // a nexthop off a pinned bridge is exactly the case. Send
            // an explicit clear instead; the programmer absorbs the
            // no-op when nothing was pinned.
            self.queue_pin(ip, None);
            return;
        };
        let pin = self.fdb.get(&(parent, mac)).map(|&port| (port, vid));
        if pin.is_some() {
            self.fdb_pins_sent += 1;
        } else {
            self.fdb_pins_cleared += 1;
        }
        self.queue_pin(ip, pin);
    }

    /// Send a pin transition, retaining it for retry if the
    /// programmer's bounded queue rejected it. See `pending_pins`.
    fn queue_pin(&mut self, ip: IpAddr, pin: Option<(u32, u16)>) {
        let accepted = match self.prog_handle.as_ref() {
            Some(prog) => prog.set_nexthop_pin_nowait(ip, pin),
            None => return,
        };
        if accepted {
            self.pending_pins.remove(&ip);
        } else {
            self.pending_pins.insert(ip, pin);
        }
    }

    /// Re-send pin transitions the programmer could not accept.
    /// Driven from the stats tick so retries are bounded and cheap.
    fn retry_pending_pins(&mut self) {
        if self.pending_pins.is_empty() {
            return;
        }
        let retry: Vec<(IpAddr, Option<(u32, u16)>)> =
            self.pending_pins.iter().map(|(ip, p)| (*ip, *p)).collect();
        let before = retry.len();
        for (ip, pin) in retry {
            self.queue_pin(ip, pin);
        }
        let still = self.pending_pins.len();
        if still > 0 {
            warn!(
                retried = before,
                still_pending = still,
                "FDB-pin retries still blocked; programmer queue remains saturated"
            );
        } else {
            info!(retried = before, "FDB-pin retries drained");
        }
    }

    /// v0.2.9: apply one AF_BRIDGE FDB event (`added == true` for
    /// RTM_NEWNEIGH, false for RTM_DELNEIGH) and re-derive the pin of
    /// every cached neighbor whose MAC + chain matches. FDB events
    /// carry `(port ifindex, MAC, master)`; entries whose master isn't
    /// a pin-chain parent are ignored (dockers, unrelated bridges).
    /// Events without an NDA_MASTER/Controller attribute are skipped —
    /// port-local (`self`) FDB entries, which never describe a path
    /// through the bridge.
    fn handle_fdb_update(&mut self, msg: &NeighbourMessage, added: bool) {
        if self.pin_chains.is_empty() {
            return;
        }
        let Some(master) = extract_fdb_master(&msg.attributes) else {
            return;
        };
        let parents: std::collections::HashSet<u32> =
            self.pin_chains.values().map(|&(p, _)| p).collect();
        if !parents.contains(&master) {
            return;
        }
        // Defence in depth on FDB keying. `discover_fdb_pin_chains`
        // refuses VLAN-filtering underlying bridges precisely because
        // their FDB is keyed by (MAC, VID) while this cache is keyed
        // by (master, MAC). If a VLAN-tagged FDB entry reaches us
        // anyway — filtering flipped on after attach, or a kernel that
        // reports a VID regardless — ignoring it is the safe answer:
        // the nexthop stays unpinned on the bridge path rather than
        // being pinned from a key we cannot disambiguate.
        if msg
            .attributes
            .iter()
            .any(|a| matches!(a, NeighbourAttribute::Vlan(v) if *v != 0))
        {
            return;
        }
        let Some(mac) = extract_mac(&msg.attributes) else {
            return;
        };
        let port = msg.header.ifindex;
        let changed = if added {
            self.fdb.insert((master, mac), port) != Some(port)
        } else {
            // Only forget the mapping the delete describes: an age-out
            // notification for the OLD port must not clobber a newer
            // entry from a MAC move that already arrived.
            match self.fdb.get(&(master, mac)) {
                Some(&cur) if cur == port => {
                    self.fdb.remove(&(master, mac));
                    true
                }
                _ => false,
            }
        };
        if !changed {
            return;
        }
        // Re-derive pins for every cached neighbor with this MAC on a
        // chain over this master. Neighbor counts are small (hundreds)
        // and FDB churn for *nexthop* MACs is rare; a linear scan is
        // simpler than a reverse index and cheap at this rate.
        let affected: Vec<(IpAddr, u32, [u8; 6])> = self
            .neigh_cache
            .iter()
            .filter(|(_, &(nifidx, nmac))| {
                nmac == mac
                    && self
                        .pin_chains
                        .get(&nifidx)
                        .is_some_and(|&(p, _)| p == master)
            })
            .map(|(ip, &(nifidx, nmac))| (*ip, nifidx, nmac))
            .collect();
        for (ip, nifidx, nmac) in affected {
            self.maybe_send_pin(ip, nifidx, nmac);
        }
    }

    /// Walk the seeded `neigh_cache` once at startup and, for each
    /// entry that falls in a configured local-prefix CIDR + ifindex
    /// pair, emit a `RouteEvent::Add` followed directly by a synthetic
    /// `NeighEvent::Learned` carrying the cached MAC. v0.2.1.
    ///
    /// The direct `Learned` is load-bearing, not an optimization. The
    /// Add makes the programmer register the nexthop, which fires a
    /// `request_resolve` into the bounded resolve queue
    /// (`RESOLVE_QUEUE_CAPACITY` = 1024, `try_send`) — but this method
    /// runs *before* `run()` enters its select loop, so nothing drains
    /// that queue while we seed. Past 1024 matching neighbours the
    /// overflow requests would drop silently, and since these are
    /// already-stable cached entries that may emit no further
    /// multicast event, their host routes would sit `Incomplete`
    /// (slow-path fallback) until NUD churn happened to touch them.
    /// Emitting the `Learned` here uses the MAC we already hold from
    /// the dump, mirrors what the resolve queue's cache-hit arm would
    /// have done, and scales to any snapshot size: `events_tx` applies
    /// backpressure and the programmer drains it concurrently. The
    /// queued resolve requests that do survive become harmless
    /// duplicate cache-hits once the select loop starts.
    async fn seed_local_prefix_routes(&mut self, prog: &FibProgrammerHandle) {
        // Snapshot the cache under a copy so the iteration doesn't
        // borrow self while we call &mut self below for counter
        // updates. Cache is small (low thousands at most on the
        // reference EFG); allocation cost is irrelevant against the
        // single-shot startup work.
        let snapshot: Vec<(IpAddr, u32, [u8; 6])> = self
            .neigh_cache
            .iter()
            .map(|(ip, (ifindex, mac))| (*ip, *ifindex, *mac))
            .collect();
        let mut emitted_v4 = 0usize;
        let mut emitted_v6 = 0usize;
        for (ip, ifindex, mac) in snapshot {
            if !may_synthesize(ip) {
                continue;
            }
            if let Some(peer_id) = self.match_local_prefix(ip, ifindex) {
                let add = RouteEvent::Add {
                    peer_id,
                    prefix: host_prefix(ip),
                    nexthops: vec![ip],
                    path_id: None,
                    local_pref: None,
                    origin_asn: None,
                };
                if let Err(e) = self.apply_route(prog, add).await {
                    warn!(?ip, error = %e, "local-prefix seed RouteEvent::Add dispatch failed");
                    continue;
                }
                if ip.is_ipv4() {
                    emitted_v4 += 1;
                    self.local_arp_routes_added += 1;
                } else {
                    emitted_v6 += 1;
                    self.local_nd_routes_added += 1;
                }
                // Same construction as the resolve queue's cache-hit
                // arm, including the zeroed src_mac fallback for
                // MAC-less ifaces.
                if self.send_learned(ip, ifindex, mac).await {
                    self.synth_learned_emitted += 1;
                } else {
                    warn!(?ip, "seed synthetic Learned send failed");
                }
            }
        }
        info!(
            emitted_v4,
            emitted_v6,
            local_prefixes = self.local_prefixes.len(),
            "local-prefix host-route seed complete (/32 for v4, /128 for v6)"
        );

        // v0.2.1 issue #32: ARP-scavenge any prefix the operator
        // flagged. For each IP in the CIDR (excluding network and
        // broadcast), call NeighborResolveHandle::request_resolve via
        // the resolve_tx channel, the proactive-resolve path then
        // issues an RTM_NEWNEIGH NUD_NONE which the kernel turns into
        // an ARP request. Hosts that respond land in the L3 ARP cache,
        // RTM_NEWNEIGH multicasts back to us, and our existing
        // multicast handler emits the per-/32 RouteEvent::Add.
        //
        // For the in-resolver path we directly enqueue the IPs into
        // resolve_tx. This bypasses the NeighborResolveHandle's
        // try_send overflow handling, but the queue is bounded by
        // RESOLVE_QUEUE_CAPACITY (1024) which is exactly the cap we
        // require for arp-scavenge prefixes anyway.
        self.scavenge_local_prefix_arp().await;
    }

    /// v0.2.1 issue #32, with v0.2.2 broadcast-storm safety (#34).
    /// For every `local-prefix` flagged with `arp-scavenge`, ARP-probe
    /// every host IP in the CIDR via the **operator-declared iface**
    /// (NOT the kernel's routing-table OIF, see safety rationale below).
    /// Capped at /22 (1024 hosts) per config-parse validation.
    ///
    /// **Safety: why we use the operator's declared iface, not the
    /// kernel's OIF.** Pre-v0.2.2 this method called `issue_arp_probe`
    /// which looked up the kernel's egress for each target IP. On a
    /// box with multi-VID bridges (the reference EFG's `switch0`
    /// carries customer VID 1337 alongside IX VIDs 3998/SIX, 3999/KCIX,
    /// etc.), a misconfigured `local-prefix` whose CIDR happened to
    /// resolve via an IX VID's bridge subif would broadcast 1024 ARP
    /// requests onto that IX bridge. That violates IX route-server
    /// policies (anti-DoS, MANRS) and could trigger session shutdown
    /// or peer-side complaints.
    ///
    /// The fix: pass the operator's declared iface (resolved to ifindex
    /// at startup via `iface_to_ifindex`) directly to
    /// `handle.neighbours().add(oif, ip)`. The kernel issues ARP only
    /// on that iface, regardless of what the routing table says. If
    /// the operator's iface and the kernel's view disagree, probes
    /// are sent but no responses come back; the entries time out
    /// harmlessly. ARP traffic CANNOT escape the operator-declared
    /// iface's L2 broadcast domain.
    async fn scavenge_local_prefix_arp(&mut self) {
        // Snapshot the specs (filter to arp-scavenge enabled) AND
        // resolve each spec's iface to ifindex up-front. If an iface
        // doesn't resolve, we refuse the sweep entirely, that's
        // safer than falling back to kernel-OIF behavior.
        let specs: Vec<(LocalPrefixSpec, u32)> = self
            .local_prefixes
            .iter()
            .filter(|s| s.arp_scavenge)
            .filter(|s| {
                // A sweep is hundreds of broadcast ARP requests; on an
                // IX-mode interface every one is dropped upstream, so
                // the sweep can only cost frames and switch counters.
                let ix = self.ix_interfaces.contains(&s.iface);
                if ix {
                    warn!(
                        iface = %s.iface,
                        cidr = %format_args!("{}/{}", s.addr, s.prefix_len),
                        "arp-scavenge on an ix-mode interface refused; its broadcasts are \
                         dropped upstream and the snooper learns these neighbours instead"
                    );
                }
                !ix
            })
            .filter_map(|s| match self.iface_to_ifindex.get(&s.iface).copied() {
                Some(ifindex) => Some((s.clone(), ifindex)),
                None => {
                    warn!(
                        iface = %s.iface,
                        cidr = %format_args!("{}/{}", s.addr, s.prefix_len),
                        "arp-scavenge: iface not resolvable to ifindex; refusing sweep \
                         (will retry if iface comes up later via RTM_NEWLINK)"
                    );
                    None
                }
            })
            .collect();
        if specs.is_empty() {
            return;
        }
        let mut total_probed = 0usize;
        for (spec, oif) in specs {
            // Belt-and-braces: the config parser rejects `arp-scavenge`
            // on `local-prefix6`, so a v6 spec can never have the flag
            // set and this is unreachable. It guards against a future
            // caller constructing LocalPrefixSpec directly — sweeping a
            // v6 prefix is not merely unsupported but unrepresentable
            // (a /64 is 2^64 addresses).
            let IpAddr::V4(net_v4) = spec.addr else {
                warn!(
                    iface = %spec.iface,
                    cidr = %format_args!("{}/{}", spec.addr, spec.prefix_len),
                    "arp-scavenge is IPv4-only and should have been rejected at config \
                     parse; ignoring this spec"
                );
                continue;
            };
            let net_u32 = u32::from(net_v4);
            let plen = spec.prefix_len;
            // Number of host bits + the host range.
            let host_bits = 32u8.saturating_sub(plen) as u32;
            let host_count = if host_bits >= 32 {
                u32::MAX
            } else {
                1u32 << host_bits
            };
            // Mask off any host bits the operator left set in the
            // declared CIDR, treat 192.0.2.5/24 as 192.0.2.0/24.
            let mask: u32 = if plen == 0 {
                0
            } else {
                (!0u32) << (32 - plen as u32)
            };
            let net_aligned = net_u32 & mask;
            // Skip the network and broadcast addresses for /24 and shorter.
            // For /32 (single host), probe just that. For /31, probe both.
            let (start_host, end_host) = match plen {
                32 => (0u32, 1u32),
                31 => (0u32, 2u32),
                _ => (1u32, host_count.saturating_sub(1)),
            };
            let mut probed = 0u32;
            for offset in start_host..end_host {
                let ip = Ipv4Addr::from(net_aligned + offset);
                // v0.2.2: pass the operator's iface ifindex. ARP only
                // goes out the iface the operator declared.
                self.issue_arp_probe(IpAddr::V4(ip), oif).await;
                probed += 1;
                // Rate-limit at ~500 probes/sec (50 per 100ms). Without
                // pacing, a /22 sweep (1024 hosts) issues 1024 ARP
                // requests in milliseconds, saturates the kernel
                // neighbour queue and triggers `Neighbour table
                // overflow` warnings. 500/s is comfortably under the
                // default `gc_thresh3` (1024) replenishment rate and
                // matches typical NIC ARP-handling capacity.
                if probed.is_multiple_of(50) {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
            total_probed += probed as usize;
            info!(
                cidr = %format_args!("{}/{}", spec.addr, spec.prefix_len),
                iface = %spec.iface,
                ifindex = oif,
                probed,
                "arp-scavenge sweep complete (scoped to operator-declared iface)"
            );
        }
        info!(
            total_probed,
            "arp-scavenge total probes issued; live hosts will land in L3 ARP cache \
             and trigger RTM_NEWNEIGH → /32 fast-path within seconds"
        );
    }

    /// One-shot ARP probe issued on a caller-specified iface (v0.2.2:
    /// previously used kernel route lookup, which created the IX
    /// broadcast-storm risk documented in `scavenge_local_prefix_arp`).
    /// Over the request socket and bounded like every other request; a
    /// probe that cannot be sent is skipped, as the sweep is best-effort.
    async fn issue_arp_probe(&mut self, ip: IpAddr, oif: u32) {
        let Some(handle) = self.requester(Duration::ZERO).await else {
            self.probe_skipped(ip);
            return;
        };
        // NTF_USE for the same reason as `issue_proactive_resolve`:
        // without it the kernel creates a silent NUD_NONE entry and no
        // ARP leaves the box.
        let probe = handle
            .neighbours()
            .add(oif, ip)
            .state(NeighbourState::None)
            .flags(NeighbourFlags::Use)
            .replace()
            .execute();
        match tokio::time::timeout(REQUEST_TIMEOUT, probe).await {
            Ok(Ok(())) => debug!(?ip, oif, "scavenge probe issued"),
            Ok(Err(e)) => debug!(?ip, oif, error = %e, "scavenge probe failed"),
            Err(_) => self.request_timed_out("scavenge probe"),
        }
        self.status.beat();
    }

    /// v0.2.1 issue #31. Inject the synthetic IPv4 default route at
    /// startup if the operator declared `fallback-default` and its
    /// iface exists. An iface that does not exist yet gets its /0 from
    /// its RTM_NEWLINK instead (see `handle_packet`), which is why
    /// `run()` calls this only once the multicast subscription is live.
    async fn seed_fallback_default(&mut self) {
        let Some(iface) = self
            .fallback_default
            .as_ref()
            .map(|spec| spec.iface.clone())
        else {
            return;
        };
        let ifindex = match self.iface_to_ifindex.get(&iface).copied() {
            Some(ifindex) => ifindex,
            // The RTM_GETLINK dump can have failed, or predate an iface
            // created since, and a stable iface never sends another
            // RTM_NEWLINK; ask the kernel for this one link. Both caches
            // are filled from the reply, as the dump and RTM_NEWLINK fill
            // them: the name so the iface's RTM_DELLINK is recognised as
            // carrying the /0, and the MAC because every Learned on an
            // uncached iface carries a zeroed src_mac, which the
            // programmer writes as Resolved — the /0 would then forward
            // frames with no source address (review finding on #319).
            None => match self.link_by_name(&iface).await {
                Ok(Some((ifindex, mac))) => {
                    if let Some(mac) = mac {
                        self.iface_mac.insert(ifindex, mac);
                    }
                    self.iface_to_ifindex.insert(iface, ifindex);
                    ifindex
                }
                Ok(None) => {
                    warn!(
                        iface = %iface,
                        "fallback-default iface does not exist; 0.0.0.0/0 will be injected \
                         when its RTM_NEWLINK arrives"
                    );
                    return;
                }
                // Neither the ifindex nor the MAC is established, so
                // nothing is injected rather than a /0 with a zeroed
                // source address.
                Err(e) => {
                    warn!(
                        iface = %iface,
                        error = %e,
                        "fallback-default iface lookup failed; 0.0.0.0/0 waits for the iface's \
                         next RTM_NEWLINK"
                    );
                    return;
                }
            },
        };
        self.inject_fallback_default(ifindex).await;
    }

    /// [`get_link_by_name`] over the request socket, bounded by
    /// [`REQUEST_TIMEOUT`].
    async fn link_by_name(&mut self, name: &str) -> Result<Option<(u32, Option<[u8; 6]>)>, String> {
        let Some(handle) = self.requester(RETIRED_GRACE).await else {
            return Err("no request socket".into());
        };
        let looked_up =
            match tokio::time::timeout(REQUEST_TIMEOUT, get_link_by_name(&handle, name)).await {
                Ok(r) => r.map_err(|e| e.to_string()),
                Err(_) => {
                    self.request_timed_out("link lookup");
                    Err(format!("timed out after {} s", REQUEST_TIMEOUT.as_secs()))
                }
            };
        self.status.beat();
        looked_up
    }

    /// Send the fallback-default /0 to the FibProgrammer under
    /// `ifindex`'s `local_arp` peer, the same per-iface scope the
    /// local-prefix /32s use, so the iface's RTM_DELLINK PeerDown
    /// withdraws it with them. The only place the event is built,
    /// shared by the startup seed and the RTM_NEWLINK arm.
    async fn inject_fallback_default(&mut self, ifindex: u32) {
        let Some(spec) = self.fallback_default.clone() else {
            return;
        };
        let Some(prog) = self.prog_handle.clone() else {
            return;
        };
        let event = RouteEvent::Add {
            peer_id: PeerId::local_arp(ifindex),
            prefix: IpPrefix::V4 {
                addr: [0, 0, 0, 0],
                prefix_len: 0,
            },
            nexthops: vec![IpAddr::V4(spec.nexthop)],
            path_id: None,
            local_pref: None,
            origin_asn: None,
        };
        match self.apply_route(&prog, event).await {
            Ok(()) => {
                // A re-send under the ifindex already acknowledged is a
                // no-op in the programmer; a flag or carrier change
                // must not read as a new injection.
                if self.fallback_injected_on.replace(ifindex) == Some(ifindex) {
                    debug!(
                        iface = %spec.iface,
                        ifindex,
                        "fallback-default 0.0.0.0/0 re-sent on RTM_NEWLINK"
                    );
                } else {
                    info!(
                        iface = %spec.iface,
                        ifindex,
                        nexthop = %spec.nexthop,
                        "v0.2.1 fallback-default 0.0.0.0/0 injected"
                    );
                }
            }
            Err(e) => warn!(
                iface = %spec.iface,
                ifindex,
                error = %e,
                "fallback-default injection failed"
            ),
        }
    }

    /// Same as [`Self::seed_local_prefix_routes`] but for a single
    /// (ip, ifindex) pair, called from the multicast event handler
    /// on RTM_NEWNEIGH.
    ///
    /// Idempotent against the FibProgrammer side: a repeated Add for an
    /// unchanged nexthop set short-circuits in `recompute_fib_entry`
    /// before any map write, so there is no churn and nothing to leak.
    /// (This is a no-change comparison, not a refcount bump; refcounting
    /// only engages when the nexthop set actually changes.) IPv6
    /// exercises this path harder than v4 because SLAAC hosts hold
    /// several addresses that go stale and get re-probed independently.
    async fn maybe_emit_local_arp_add(&mut self, ip: IpAddr, ifindex: u32) {
        if !may_synthesize(ip) {
            return;
        }
        let Some(peer_id) = self.match_local_prefix(ip, ifindex) else {
            return;
        };
        // Clone to release the &self borrow on prog_handle before the
        // mutable counter update below, same pattern as
        // seed_local_prefix_routes. FibProgrammerHandle is cheap to
        // clone (mpsc Sender wrapper).
        let Some(prog) = self.prog_handle.clone() else {
            return;
        };
        let add = RouteEvent::Add {
            peer_id,
            prefix: host_prefix(ip),
            nexthops: vec![ip],
            path_id: None,
            local_pref: None,
            origin_asn: None,
        };
        if let Err(e) = self.apply_route(&prog, add).await {
            warn!(?ip, error = %e, "local-prefix RouteEvent::Add dispatch failed");
        } else if ip.is_ipv4() {
            self.local_arp_routes_added += 1;
        } else {
            self.local_nd_routes_added += 1;
        }
    }

    /// Symmetric withdrawal for a single (ip, ifindex) on RTM_DELNEIGH.
    ///
    /// The `may_synthesize` gate must match the add path exactly. An
    /// asymmetric filter would strand host routes that were installed
    /// before the gate changed, with no path to withdraw them.
    async fn maybe_emit_local_arp_del(&mut self, ip: IpAddr, ifindex: u32) {
        if !may_synthesize(ip) {
            return;
        }
        let Some(peer_id) = self.match_local_prefix(ip, ifindex) else {
            return;
        };
        let Some(prog) = self.prog_handle.clone() else {
            return;
        };
        let del = RouteEvent::Del {
            peer_id,
            prefix: host_prefix(ip),
            path_id: None,
        };
        if let Err(e) = self.apply_route(&prog, del).await {
            warn!(?ip, error = %e, "local-prefix RouteEvent::Del dispatch failed");
        } else if ip.is_ipv4() {
            self.local_arp_routes_removed += 1;
        } else {
            self.local_nd_routes_removed += 1;
        }
    }

    /// On RTM_DELLINK, send a single PeerDown for the departed iface's
    /// `local_arp` peer, withdrawing everything injected under it: its
    /// local-prefix host routes and, if it was the fallback-default
    /// iface, the /0. Cheaper than walking the cache to emit per-/32
    /// Dels and matches the existing semantics for BGP peer departure.
    ///
    /// With any local-prefix configured this fires for every iface: the
    /// caller has already purged the departed name from
    /// `iface_to_ifindex`, so which iface backed a local-prefix is not
    /// recoverable here. Wasteful for ifaces that weren't local-prefix
    /// targets, but safe (programmer's PeerDown handler is a HashMap
    /// walk that does nothing for an unknown peer_id).
    ///
    /// `carried_fallback`, read by the caller before that purge, covers
    /// a fallback-default with no local-prefix beside it; when the
    /// iface returns, its RTM_NEWLINK re-injects the /0 under the new
    /// ifindex's peer.
    async fn maybe_emit_local_arp_peerdown(&mut self, ifindex: u32, carried_fallback: bool) {
        if self.local_prefixes.is_empty() && !carried_fallback {
            return;
        }
        let Some(prog) = self.prog_handle.clone() else {
            return;
        };
        let peer_id = PeerId::local_arp(ifindex);
        match self
            .apply_route(&prog, RouteEvent::PeerDown { peer_id })
            .await
        {
            Ok(()) if carried_fallback => info!(
                ifindex,
                "fallback-default iface deleted; 0.0.0.0/0 withdrawn until its RTM_NEWLINK"
            ),
            Ok(()) => {}
            Err(e) => {
                warn!(ifindex, error = %e, "local_arp RouteEvent::PeerDown dispatch failed")
            }
        }
    }

    /// Match `(ip, ifindex)` against the configured `local_prefixes`.
    /// Returns the per-iface PeerId if one matches; `None` otherwise.
    /// Linear scan; the operator-declared list is small (handful at
    /// most on the reference EFG) so this is cheap on every neighbour
    /// event.
    ///
    /// The list holds both families and `LocalPrefixSpec::contains`
    /// returns `false` on a family mismatch, so a v6 neighbour can only
    /// ever match a `local-prefix6` spec.
    ///
    /// The returned `PeerId` is keyed on ifindex alone, deliberately
    /// **not** on family: a v4 and a v6 local-prefix on the same
    /// interface share one peer, so a single `RouteEvent::PeerDown` on
    /// `RTM_DELLINK` withdraws both families' host routes in one sweep.
    /// `FibProgrammer` keeps them distinct internally because
    /// `prefix_peer_key` discriminates on an `is_v4` flag.
    fn match_local_prefix(&self, ip: IpAddr, ifindex: u32) -> Option<PeerId> {
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
/// arrives", exactly what we'd get without proactive resolve, so
/// the only cost of a proactive-resolve failure is one-packet latency
/// on first forward.
///
/// `ix_oifs` are the current ifindexes of the IX-mode interfaces: a
/// nexthop whose unicast route egresses one of them is reported as
/// [`ProbeOutcome::Suppressed`] and nothing is written — the kernel's
/// resolution on that link is dropped upstream, and the neigh-snoop
/// module seeds the entry from the fabric's own traffic instead. The
/// check sits *after* the route lookup on purpose: it is the egress
/// device that is IX-mode, not the address.
///
/// `handle` is the request socket's, never the multicast one's, and
/// both requests are bounded by [`REQUEST_TIMEOUT`]: a reply that does
/// not come is [`ProbeOutcome::TimedOut`], not a wait that ends the
/// resolver.
async fn issue_proactive_resolve(
    handle: &Handle,
    ip: IpAddr,
    ix_oifs: &HashSet<u32>,
) -> ProbeOutcome {
    // An unspecified nexthop (0.0.0.0 / ::) means "the route is
    // self-originated" in every BGP dialect that emits it (FRR does,
    // for locally-originated networks over iBGP). There is no
    // neighbor to resolve, and the route lookup below would resolve
    // it to the loopback local route — see the RTN_UNICAST guard.
    if ip.is_unspecified() {
        debug!(?ip, "proactive resolve: unspecified nexthop; skipping");
        return ProbeOutcome::Unspecified;
    }
    let (req, plen) = match ip {
        IpAddr::V4(v4) => (
            RouteMessageBuilder::<IpAddr>::new()
                .destination_prefix(IpAddr::V4(v4), 32)
                .unwrap_or_else(|_| RouteMessageBuilder::<IpAddr>::new())
                .build(),
            32u8,
        ),
        IpAddr::V6(v6) => (
            RouteMessageBuilder::<IpAddr>::new()
                .destination_prefix(IpAddr::V6(v6), 128)
                .unwrap_or_else(|_| RouteMessageBuilder::<IpAddr>::new())
                .build(),
            128u8,
        ),
    };
    let _ = plen; // retained for future per-family path divergence if needed
    let Ok(oif) = tokio::time::timeout(REQUEST_TIMEOUT, lookup_oif(handle, req)).await else {
        return ProbeOutcome::TimedOut {
            stage: "route lookup",
        };
    };
    let oif = match oif {
        Some(i) => i,
        None => {
            debug!(
                ?ip,
                "proactive resolve: route lookup returned no OIF; skipping"
            );
            return ProbeOutcome::NoRoute;
        }
    };
    if ix_oifs.contains(&oif) {
        debug!(?ip, oif, "proactive resolve: egress is ix-mode; not kicked");
        return ProbeOutcome::Suppressed { oif };
    }
    // Issue the RTM_NEWNEIGH with NTF_USE. The flag is what makes the
    // kernel *do* something: `neigh_add` routes an NTF_USE request to
    // `neigh_event_send`, which takes a NONE/FAILED entry to INCOMPLETE
    // and transmits the first ARP/NS immediately, walks a STALE one
    // through DELAY/PROBE, and is a no-op on REACHABLE. Without it the
    // request is a plain `__neigh_update` to `NUD_NONE`: the entry is
    // created or reset with no timer and no solicitation, and nothing
    // resolves it until the kernel itself sends to that address —
    // which, for a nexthop whose traffic is XDP-redirected, it never
    // does. That gap is why the re-probe schedule in the programmer
    // could otherwise back off forever (review finding on #220).
    // `state` is ignored on the NTF_USE path; it is set so a kernel
    // that ever fell back to the update path would still not write a
    // bogus VALID state. Replace keeps the call idempotent when the
    // entry already exists.
    let kick = handle
        .neighbours()
        .add(oif, ip)
        .state(NeighbourState::None)
        .flags(NeighbourFlags::Use)
        .replace()
        .execute();
    match tokio::time::timeout(REQUEST_TIMEOUT, kick).await {
        Ok(Ok(())) => {
            debug!(?ip, oif, "proactive resolve kicked");
            ProbeOutcome::Kicked { oif }
        }
        Ok(Err(e)) => {
            debug!(?ip, oif, error = %e, "proactive resolve failed");
            ProbeOutcome::Failed
        }
        Err(_) => ProbeOutcome::TimedOut {
            stage: "neighbour kick",
        },
    }
}

/// A non-dump `RTM_GETNEIGH` for one `(device, address)` pair — the
/// kernel's `neigh_get` (5.1+). `NLM_F_REQUEST` only: with `NLM_F_DUMP`
/// this would be the whole table, which is what the startup seed does
/// and what a per-kick read-back must not.
pub fn neigh_get_request(ip: IpAddr, oif: u32) -> NetlinkMessage<RouteNetlinkMessage> {
    let mut nm = NeighbourMessage::default();
    nm.header.ifindex = oif;
    nm.header.family = match ip {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    nm.attributes
        .push(NeighbourAttribute::Destination(match ip {
            IpAddr::V4(a) => NeighbourAddress::Inet(a),
            IpAddr::V6(a) => NeighbourAddress::Inet6(a),
        }));
    let mut req = NetlinkMessage::from(RouteNetlinkMessage::GetNeighbour(nm));
    req.header.flags = NLM_F_REQUEST;
    req
}

/// Query the main routing table for `msg`, return the OIF of the
/// first route returned. Kernel answers via a stream; we only care
/// about the first entry, subsequent entries for multipath routes
/// are handled at the programmer level via ECMP groups.
///
/// Only an `RTN_UNICAST` result qualifies. Any other kind — local,
/// broadcast, anycast — means the "nexthop" is an address this box
/// itself answers for, so there is no neighbor to resolve and the
/// OIF the kernel reports is `lo`. Writing an `RTM_NEWNEIGH
/// NUD_NONE` there is not merely useless: it replaces the kernel's
/// implicit NUD_NOARP handling for that key on the loopback device,
/// queueing all subsequent local delivery for that address behind an
/// ARP that can never resolve (2026-08-20 edge1-mci1 incident — the
/// FRR feed carries nexthop 0.0.0.0 / update-source for
/// self-originated routes, and each probe of one poisoned `lo`).
async fn lookup_oif(
    handle: &Handle,
    msg: netlink_packet_route::route::RouteMessage,
) -> Option<u32> {
    let mut routes = handle.route().get(msg).execute();
    match routes.try_next().await {
        Ok(Some(route)) => {
            if route.header.kind != RouteType::Unicast {
                debug!(
                    kind = ?route.header.kind,
                    "proactive resolve: route is not unicast; no neighbor to resolve"
                );
                return None;
            }
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

/// Dump every link on the box via a single RTM_GETLINK-dump request
/// over the request socket (the multicast one only listens), as one
/// [`LinkObs`] per link.
///
/// Links without a usable MAC (e.g., tunnels, loopback, bridge masters
/// before an attachment) carry `mac: None`; they'll show up in a later
/// RTM_NEWLINK when their hardware address is set. The name is carried
/// regardless (every link has an `IFNAME` attribute), so the v0.2.1
/// local-prefix path can resolve iface names to ifindices for ifaces
/// that don't have a MAC.
async fn dump_link_info(handle: &Handle) -> Result<Vec<LinkObs>, NeighError> {
    let mut out = Vec::new();
    let mut links = handle.link().get().execute();
    while let Some(msg) = links
        .try_next()
        .await
        .map_err(|e| NeighError::new(format!("link dump: {e}")))?
    {
        out.push(link_obs(&msg));
    }
    Ok(out)
}

/// What a link message says about the link, in the shape the caches
/// and the reconcile take.
fn link_obs(msg: &LinkMessage) -> LinkObs {
    LinkObs {
        ifindex: msg.header.index,
        name: extract_link_name(msg),
        mac: extract_link_mac(msg),
    }
}

/// One link's `(ifindex, MAC)` by name: a single non-dump RTM_GETLINK,
/// answered with the same message the dump and RTM_NEWLINK deliver, so
/// a caller fills both caches from one observation. `Ok(None)` means
/// the kernel has no link by that name (`ENODEV`). The MAC is `None`
/// for a link without a hardware address, exactly as the dump records
/// it.
async fn get_link_by_name(
    handle: &Handle,
    name: &str,
) -> Result<Option<(u32, Option<[u8; 6]>)>, NeighError> {
    let mut links = handle.link().get().match_name(name).execute();
    match links.try_next().await {
        Ok(Some(msg)) => Ok(Some((msg.header.index, extract_link_mac(&msg)))),
        Ok(None) => Ok(None),
        Err(rtnetlink::Error::NetlinkError(e)) if e.raw_code() == -libc::ENODEV => Ok(None),
        Err(e) => Err(NeighError::new(format!("link get {name}: {e}"))),
    }
}

/// Pull the `IfName` (IFLA_IFNAME) attribute out of a `LinkMessage`.
/// Returns `None` if the attribute is absent (rare, the kernel sets
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
/// `RTM_GETNEIGH` dump over the request socket and return every usable
/// entry as `(ip, ifindex, mac)`, in dump order. The kernel keys
/// `(device, address)`, so one address can appear more than once;
/// [`reconcile_neighbours`] decides which the view keeps.
///
/// **Why this exists** (Phase 3.9): the multicast subscription only
/// observes neighbour state *transitions*, not the steady state at
/// the moment we subscribe. If the kernel already has REACHABLE
/// entries for BGP peers when packetframe starts (typical, bird's
/// been ARPing them for hours), we'd never see them. This dump
/// gives us a snapshot to seed the cache, and the multicast
/// subscription keeps it current from then on — until it overruns,
/// when this dump is the resync.
///
/// Skips entries whose state isn't usable for forwarding
/// (Incomplete/None/Failed) and entries without a Link-Layer
/// Address attribute. STALE/DELAY/PROBE are kept, same policy as
/// `parse_neighbour_add` for the multicast path.
async fn dump_neighbours(handle: &Handle) -> Result<Vec<(IpAddr, u32, [u8; 6])>, NeighError> {
    let mut out = Vec::new();
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
            out.push((ip, ifindex, mac));
        }
    }
    Ok(out)
}

/// Ask for `bytes` of receive buffer on a socket: `SO_RCVBUFFORCE`
/// first, which may exceed `net.core.rmem_max` and needs
/// `CAP_NET_ADMIN` (the daemon has it), then `SO_RCVBUF`, which the
/// kernel caps at `rmem_max`. Returns what the kernel granted (it
/// doubles the request for bookkeeping) and which option took.
fn set_rcvbuf(fd: RawFd, bytes: usize) -> std::io::Result<(usize, &'static str)> {
    let val = libc::c_int::try_from(bytes).unwrap_or(libc::c_int::MAX / 2);
    let set = |opt: libc::c_int| {
        // SAFETY: `fd` is an open socket for the call's duration and
        // `val` outlives it; the kernel reads exactly `sizeof(int)`.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                (&val as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    let how = match set(libc::SO_RCVBUFFORCE) {
        Ok(()) => "SO_RCVBUFFORCE",
        Err(_) => {
            set(libc::SO_RCVBUF)?;
            "SO_RCVBUF (capped by net.core.rmem_max: no CAP_NET_ADMIN)"
        }
    };
    let mut granted: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: as above; `granted` and `len` are valid for the write.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&mut granted as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((usize::try_from(granted).unwrap_or(0), how))
}

/// Pull the `Address` (IFLA_ADDRESS) attribute out of a LinkMessage
/// if it's a plausible Ethernet MAC. Returns None for non-Ethernet
/// links, tunnels encode the peer address in `Address` with varying
/// widths, and a 6-byte address on a tunnel isn't semantically what
/// we want as src_mac anyway.
fn extract_link_mac(msg: &LinkMessage) -> Option<[u8; 6]> {
    for attr in &msg.attributes {
        if let LinkAttribute::Address(bytes) = attr {
            if bytes.len() == 6 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(bytes);
                // Skip the all-zero MAC some virtual ifaces present
                // before they're configured, that would be worse than
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
/// no MAC yet; `Other`, unknown variant). `src_mac` is the cached
/// egress iface MAC (Phase 3.6); `[0; 6]` when the cache hasn't been
/// populated for this ifindex yet.
fn parse_neighbour_add(msg: &NeighbourMessage, src_mac: [u8; 6]) -> Option<NeighEvent> {
    let ip = extract_ip(&msg.attributes)?;

    match msg.header.state {
        NeighbourState::Failed => Some(NeighEvent::Failed {
            ip,
            ifindex: msg.header.ifindex,
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

/// RTM_DELNEIGH → [`NeighEvent::Gone`]. Carries the device the entry
/// was deleted from: the kernel keys neighbours `(device, address)`,
/// and the consumer must not treat a deletion on one interface as
/// the loss of the same address on another.
fn parse_neighbour_del(msg: &NeighbourMessage) -> Option<NeighEvent> {
    extract_ip(&msg.attributes).map(|ip| NeighEvent::Gone {
        ip,
        ifindex: msg.header.ifindex,
    })
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

/// v0.2.9: pull the bridge-master ifindex out of an AF_BRIDGE FDB
/// message. netlink-packet-route 0.30 decodes NDA_MASTER as
/// `Controller` (the crate's rename of the master terminology).
fn extract_fdb_master(attrs: &[NeighbourAttribute]) -> Option<u32> {
    for attr in attrs {
        if let NeighbourAttribute::Controller(ifindex) = attr {
            return Some(*ifindex);
        }
    }
    None
}

/// v0.2.9: AF_BRIDGE RTM_GETNEIGH dump — the bridge FDB. Returns
/// `(master, MAC) → port ifindex` for masters in `parents`. Over the
/// request socket, like [`dump_neighbours`].
async fn dump_fdb(
    handle: &Handle,
    parents: &std::collections::HashSet<u32>,
) -> Result<HashMap<(u32, [u8; 6]), u32>, NeighError> {
    let mut out: HashMap<(u32, [u8; 6]), u32> = HashMap::new();
    let mut entries = handle
        .neighbours()
        .get()
        .set_address_family(AddressFamily::Bridge)
        .execute();
    while let Some(msg) = entries
        .try_next()
        .await
        .map_err(|e| NeighError::new(format!("AF_BRIDGE neighbour dump: {e}")))?
    {
        let Some(master) = extract_fdb_master(&msg.attributes) else {
            continue; // port-local (self) entry; not a bridge path
        };
        if !parents.contains(&master) {
            continue;
        }
        let Some(mac) = extract_mac(&msg.attributes) else {
            continue;
        };
        out.insert((master, mac), msg.header.ifindex);
    }
    Ok(out)
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
        match parse_neighbour_add(&msg, TEST_SRC_MAC) {
            Some(NeighEvent::Failed {
                ip: got_ip,
                ifindex,
                ..
            }) => {
                assert_eq!(got_ip, IpAddr::V4(ip));
                // The device is part of the kernel's key; a consumer
                // filtering by it needs the message's own ifindex.
                assert_eq!(ifindex, 42);
            }
            other => panic!("expected Failed, got {other:?}"),
        }
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
        match parse_neighbour_del(&msg) {
            Some(NeighEvent::Gone {
                ip: got_ip,
                ifindex,
            }) => {
                assert_eq!(got_ip, IpAddr::V4(ip));
                assert_eq!(ifindex, 42);
            }
            other => panic!("expected Gone, got {other:?}"),
        }
    }

    // --- v0.2.1 LocalPrefixSpec --------------------------------------------

    #[test]
    fn local_prefix_contains_basic_ipv4() {
        let spec = LocalPrefixSpec {
            addr: "192.0.2.64".parse().unwrap(),
            prefix_len: 26,
            iface: "br1337".into(),
            arp_scavenge: false,
        };
        assert!(spec.contains("192.0.2.64".parse().unwrap()));
        assert!(spec.contains("192.0.2.74".parse().unwrap()));
        assert!(spec.contains("192.0.2.127".parse().unwrap()));
        assert!(!spec.contains("192.0.2.128".parse().unwrap()));
        assert!(!spec.contains("192.0.2.63".parse().unwrap()));
    }

    #[test]
    fn local_prefix_contains_handles_slash32() {
        let spec = LocalPrefixSpec {
            addr: "10.10.1.2".parse().unwrap(),
            prefix_len: 32,
            iface: "honeypot0".into(),
            arp_scavenge: false,
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
            arp_scavenge: false,
        };
        assert!(spec.contains("1.2.3.4".parse().unwrap()));
        assert!(spec.contains("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn local_prefix_contains_misalignment_is_treated_as_aligned() {
        // Operator wrote `local-prefix 192.0.2.5/24` (host bits
        // set). The mask logic ignores host bits when comparing
        // semantically the prefix is still 192.0.2.0/24.
        let spec = LocalPrefixSpec {
            addr: "192.0.2.5".parse().unwrap(),
            prefix_len: 24,
            iface: "br1337".into(),
            arp_scavenge: false,
        };
        assert!(spec.contains("192.0.2.10".parse().unwrap()));
    }

    // --- local-prefix6 (IPv6 connected fast-path) ------------------------

    fn spec6(cidr: &str, prefix_len: u8, iface: &str) -> LocalPrefixSpec {
        LocalPrefixSpec {
            addr: cidr.parse().unwrap(),
            prefix_len,
            iface: iface.into(),
            arp_scavenge: false,
        }
    }

    #[test]
    fn local_prefix6_contains_basic() {
        let spec = spec6("2001:db8:0:1337::", 64, "br1337");
        assert!(spec.contains("2001:db8:0:1337::1".parse().unwrap()));
        assert!(spec.contains("2001:db8:0:1337:dead:beef::42".parse().unwrap()));
        assert!(!spec.contains("2001:db8:0:1338::1".parse().unwrap()));
        // The adjacent /48 must not match: 2001:db8:1:: is a different
        // allocation, not part of this segment.
        assert!(!spec.contains("2001:db8:1::1".parse().unwrap()));
    }

    #[test]
    fn local_prefix6_contains_handles_slash128() {
        let spec = spec6("2001:db8::2", 128, "br0");
        assert!(spec.contains("2001:db8::2".parse().unwrap()));
        assert!(!spec.contains("2001:db8::3".parse().unwrap()));
    }

    #[test]
    fn local_prefix6_contains_handles_slash0() {
        // Guards the u128 shift-by-128. In release that shift silently
        // yields !0, which would make ::/0 match only :: — the
        // directive would quietly do nothing rather than panic.
        let spec = spec6("::", 0, "br0");
        assert!(spec.contains("2001:db8::1".parse().unwrap()));
        assert!(spec.contains("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
    }

    #[test]
    fn local_prefix6_contains_misalignment_is_treated_as_aligned() {
        let spec = spec6("2001:db8:0:1337::5", 64, "br1337");
        assert!(spec.contains("2001:db8:0:1337::10".parse().unwrap()));
    }

    /// A spec must never match across families. The resolver walks one
    /// mixed-family list against every neighbour event, so a v4 spec
    /// seeing a v6 neighbour (and vice versa) is the normal case, not an
    /// error case.
    #[test]
    fn local_prefix_contains_rejects_family_mismatch_both_ways() {
        let v4 = LocalPrefixSpec {
            addr: "192.0.2.0".parse().unwrap(),
            prefix_len: 24,
            iface: "br1337".into(),
            arp_scavenge: false,
        };
        assert!(!v4.contains("2001:db8:0:1337::1".parse().unwrap()));

        let v6 = spec6("2001:db8:0:1337::", 64, "br1337");
        assert!(!v6.contains("192.0.2.10".parse().unwrap()));

        // A v6 /0 spec still must not swallow v4 addresses, even though
        // its mask matches everything within its own family.
        let v6_default = spec6("::", 0, "br0");
        assert!(!v6_default.contains("192.0.2.10".parse().unwrap()));
    }

    #[test]
    fn host_prefix_is_maximally_specific_per_family() {
        match host_prefix("192.0.2.7".parse().unwrap()) {
            IpPrefix::V4 { addr, prefix_len } => {
                assert_eq!(prefix_len, 32);
                assert_eq!(addr, [192, 0, 2, 7]);
            }
            other => panic!("expected V4, got {other:?}"),
        }
        match host_prefix("2001:db8:0:1337::7".parse().unwrap()) {
            IpPrefix::V6 { addr, prefix_len } => {
                assert_eq!(prefix_len, 128);
                assert_eq!(
                    addr,
                    "2001:db8:0:1337::7"
                        .parse::<std::net::Ipv6Addr>()
                        .unwrap()
                        .octets()
                );
            }
            other => panic!("expected V6, got {other:?}"),
        }
    }

    /// The emission gate. v4 is unconditional; v6 rejects the classes
    /// the kernel keeps in its neighbour table that must never become
    /// forwarding entries.
    #[test]
    fn may_synthesize_gates_v6_but_never_v4() {
        // Every v4 address is fair game, including ones that look odd.
        for a in ["192.0.2.7", "0.0.0.0", "255.255.255.255", "127.0.0.1"] {
            assert!(may_synthesize(a.parse().unwrap()), "v4 {a}");
        }
        // v6 classes that must be filtered.
        for a in [
            "ff02::1",
            "ff02::1:ff00:1", // solicited-node, NUD_NOARP with a 33:33 MAC
            "fe80::1",
            "::",
            "::1",
            "::ffff:192.0.2.1",
        ] {
            assert!(!may_synthesize(a.parse().unwrap()), "v6 {a}");
        }
        // v6 addresses that are legitimate connected hosts.
        for a in [
            "2001:db8:0:1337::42",
            "2001:db8:0:1337::", // subnet-router anycast
            "fd00:1::1",         // unique-local
        ] {
            assert!(may_synthesize(a.parse().unwrap()), "v6 {a}");
        }
    }

    // --- match_local_prefix ---------------------------------------------
    //
    // Previously untested at any family. Needs a resolver with a
    // populated `iface_to_ifindex`, which is why it had no coverage.

    fn resolver_with(
        specs: Vec<LocalPrefixSpec>,
        ifaces: &[(&str, u32)],
    ) -> NetlinkNeighborResolver {
        let (mut r, _rx, _h) = NetlinkNeighborResolver::new(CancellationToken::new());
        r.local_prefixes = specs;
        for (name, idx) in ifaces {
            r.iface_to_ifindex.insert((*name).to_string(), *idx);
        }
        r
    }

    #[test]
    fn match_local_prefix_requires_prefix_and_ifindex_to_agree() {
        let r = resolver_with(
            vec![spec6("2001:db8:0:1337::", 64, "br1337")],
            &[("br1337", 33)],
        );
        let inside: IpAddr = "2001:db8:0:1337::7".parse().unwrap();
        let outside: IpAddr = "2001:db8:0:9999::7".parse().unwrap();

        assert_eq!(
            r.match_local_prefix(inside, 33),
            Some(PeerId::local_arp(33)),
            "right prefix + right ifindex must match"
        );
        assert_eq!(
            r.match_local_prefix(inside, 34),
            None,
            "right prefix on the wrong iface must not match"
        );
        assert_eq!(
            r.match_local_prefix(outside, 33),
            None,
            "wrong prefix on the right iface must not match"
        );
    }

    #[test]
    fn match_local_prefix_returns_none_when_iface_unresolvable() {
        // Operator staged config before the bridge existed: the spec is
        // kept but cannot match until RTM_NEWLINK fills in the ifindex.
        let r = resolver_with(vec![spec6("2001:db8:0:1337::", 64, "br-later")], &[]);
        assert_eq!(
            r.match_local_prefix("2001:db8:0:1337::7".parse().unwrap(), 33),
            None
        );
    }

    /// Pins the design decision: one PeerId per ifindex, shared across
    /// families, so a single PeerDown on RTM_DELLINK withdraws both the
    /// v4 /32s and the v6 /128s behind that interface. Do not "fix" this
    /// into a per-family PeerId.
    #[test]
    fn match_local_prefix_shares_peer_id_across_families_on_one_iface() {
        let r = resolver_with(
            vec![
                LocalPrefixSpec {
                    addr: "192.0.2.0".parse().unwrap(),
                    prefix_len: 24,
                    iface: "br1337".into(),
                    arp_scavenge: false,
                },
                spec6("2001:db8:0:1337::", 64, "br1337"),
            ],
            &[("br1337", 33)],
        );
        let v4 = r.match_local_prefix("192.0.2.7".parse().unwrap(), 33);
        let v6 = r.match_local_prefix("2001:db8:0:1337::7".parse().unwrap(), 33);
        assert_eq!(v4, Some(PeerId::local_arp(33)));
        assert_eq!(v6, Some(PeerId::local_arp(33)));
        assert_eq!(v4, v6, "both families must resolve to the same peer");
    }
}

#[cfg(test)]
mod read_back_tests {
    use super::*;

    #[test]
    fn neigh_get_request_is_a_single_entry_lookup_not_a_dump() {
        use netlink_packet_core::NLM_F_DUMP;
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        let req = neigh_get_request(ip, 17);
        assert_eq!(
            req.header.flags & NLM_F_DUMP,
            0,
            "a dump would walk the whole table per kick"
        );
        assert_ne!(req.header.flags & NLM_F_REQUEST, 0);
        match req.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::GetNeighbour(nm)) => {
                assert_eq!(
                    nm.header.ifindex, 17,
                    "keyed by device like the kernel table"
                );
                assert_eq!(nm.header.family, AddressFamily::Inet);
                assert!(matches!(
                    nm.attributes.as_slice(),
                    [NeighbourAttribute::Destination(NeighbourAddress::Inet(a))] if *a == Ipv4Addr::new(192, 0, 2, 9)
                ));
            }
            other => panic!("expected GetNeighbour, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod link_lookup_tests {
    use super::*;

    /// `get_link_by_name` returns the ifindex AND the MAC from one
    /// reply, which is what lets the fallback-default seed fill both
    /// caches; an absent name is `Ok(None)` (`ENODEV`), not an error,
    /// because the two lead to different log lines.
    #[test]
    #[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
    fn get_link_by_name_reads_ifindex_and_mac_from_one_reply() {
        std::thread::scope(|s| {
            s.spawn(|| {
                // Only this thread moves, and its namespace goes with it.
                let rc = unsafe { libc::unshare(libc::CLONE_NEWNET) };
                assert_eq!(rc, 0, "unshare: {}", std::io::Error::last_os_error());
                let st = std::process::Command::new("ip")
                    .args([
                        "link",
                        "add",
                        "pfgl0",
                        "address",
                        "02:00:00:00:fd:02",
                        "type",
                        "dummy",
                    ])
                    .status()
                    .expect("spawn ip");
                assert!(st.success(), "ip link add");
                let ifindex = ifindex_by_name("pfgl0").expect("the dummy exists");
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("current-thread runtime");
                rt.block_on(async {
                    let (connection, handle, _) = new_connection().expect("netlink socket");
                    tokio::spawn(connection);
                    assert_eq!(
                        get_link_by_name(&handle, "pfgl0").await.expect("lookup"),
                        Some((ifindex, Some([0x02, 0, 0, 0, 0xfd, 0x02])))
                    );
                    assert_eq!(
                        get_link_by_name(&handle, "pfgl-absent")
                            .await
                            .expect("an absent link is not a lookup failure"),
                        None
                    );
                });
            });
        });
    }
}

#[cfg(test)]
mod request_socket_tests {
    use super::*;
    use crate::fib::programmer::recording_handle;

    const M: [u8; 6] = [0x02, 0, 0, 0, 0x09, 0x01];

    /// A request socket stuck in the kernel, as one whose request blocked
    /// on `rtnl_lock` is: its connection alive and unread, held by a task
    /// an abort cannot stop. Every request on `handle` waits until the
    /// returned sender releases it.
    fn stuck_socket() -> (Handle, JoinHandle<()>, tokio::sync::oneshot::Sender<()>) {
        let (connection, handle, _) = new_connection().expect("netlink socket");
        let (release, held) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::task::spawn_blocking(move || {
            let _connection = connection;
            let _ = held.blocking_recv();
        });
        (handle, task, release)
    }

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    /// The programmer counts every probe it hands over as an attempt and
    /// backs it off, whether or not the resolver could send it. Probes
    /// skipped while a retired socket is stuck in the kernel must be
    /// asked for again once one can go out — not at a backoff the skips
    /// pushed out to half a minute.
    #[tokio::test]
    async fn skipped_probes_nudge_the_programmer_once_requests_can_go_out() {
        let (prog, log) = recording_handle();
        let (r, _events, _resolve) = NetlinkNeighborResolver::new(CancellationToken::new());
        let mut r = r.with_reprobe_target(prog);
        let (_handle, task, release) = stuck_socket();
        r.requester = Requester::Retired { task };

        // A cache miss with no socket to send its probe on.
        r.on_resolve_request(v4(50)).await;
        assert_eq!(
            r.status.snapshot().counters.probes_skipped,
            1,
            "the fixture must skip a probe"
        );
        r.housekeeping().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(log.reprobe_nudges(), 0, "nothing can go out yet");

        // The kernel lets go.
        release.send(()).expect("release the stuck socket");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !matches!(&r.requester, Requester::Retired { task } if task.is_finished()) {
            assert!(Instant::now() < deadline, "the stuck task never exited");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        r.housekeeping().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            log.reprobe_nudges(),
            1,
            "requests can go out again: the programmer must be told to ask now"
        );
    }

    /// The 2026-10-07 shape inside a resync: the first confirmation blocks
    /// on `rtnl_lock` and times out. What the dump listed — the entries
    /// that put nexthops back on the fast path — must already be
    /// announced by then, and the remaining confirmations must not each
    /// wait out their own bound on a socket that is known to be stuck
    /// (the loop is deaf to notifications meanwhile); they are owed.
    #[tokio::test]
    async fn a_stuck_socket_defers_the_rest_of_the_confirmations_after_the_dump_is_applied() {
        let (r, mut events, _resolve) = NetlinkNeighborResolver::new(CancellationToken::new());
        let mut r = r;
        let (a, b, c) = (v4(10), v4(11), v4(30));
        // In the view, and not in the dump: each needs confirming.
        r.neigh_cache.insert(a, (7, M));
        r.neigh_cache.insert(b, (7, M));
        let (handle, task, release) = stuck_socket();
        r.requester = Requester::Open {
            handle: handle.clone(),
            task,
        };

        let started = Instant::now();
        let deadline = started + CONFIRM_BUDGET;
        let (result, first) = tokio::join!(
            r.apply_neighbours(&handle, vec![(c, 7, M)], true, deadline),
            tokio::time::timeout(Duration::from_secs(1), events.recv())
        );
        let took = started.elapsed();
        release.send(()).expect("release the stuck socket");

        assert!(
            matches!(first, Ok(Some(NeighEvent::Learned { ip, .. })) if ip == c),
            "what the dump listed must be announced before any confirmation is asked: {first:?}"
        );
        let err = result.expect_err("unconfirmed entries leave the read incomplete");
        assert!(err.contains("2 neighbour(s)"), "both are owed: {err}");
        assert!(
            took < REQUEST_TIMEOUT + Duration::from_secs(2),
            "one confirmation may wait out its bound, the rest must not ({took:?})"
        );
        assert_eq!(r.status.snapshot().counters.request_timeouts, 1);
        assert!(
            r.neigh_cache.contains_key(&a) && r.neigh_cache.contains_key(&b),
            "unconfirmed entries are left as they were"
        );
        while let Ok(e) = events.try_recv() {
            assert!(
                !matches!(e, NeighEvent::Gone { .. }),
                "nothing unconfirmed may be announced gone: {e:?}"
            );
        }
    }

    /// `neigh_get` answers `ENODEV` for an interface index that no longer
    /// exists. A neighbour on a deleted device is gone; reading the answer
    /// as "unknown" owes a resync that can never be paid, every 5 s,
    /// forever.
    #[test]
    #[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
    fn a_neighbour_on_a_deleted_device_is_confirmed_gone() {
        std::thread::scope(|s| {
            s.spawn(|| {
                let rc = unsafe { libc::unshare(libc::CLONE_NEWNET) };
                assert_eq!(rc, 0, "unshare: {}", std::io::Error::last_os_error());
                let ip = |args: &[&str]| {
                    let st = std::process::Command::new("ip")
                        .args(args)
                        .status()
                        .expect("spawn ip");
                    assert!(st.success(), "ip {args:?}");
                };
                ip(&["link", "add", "pfnd0", "type", "dummy"]);
                let gone_ifindex = ifindex_by_name("pfnd0").expect("the dummy exists");
                ip(&["link", "del", "pfnd0"]);
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("current-thread runtime");
                rt.block_on(async {
                    let (r, _events, _resolve) =
                        NetlinkNeighborResolver::new(CancellationToken::new());
                    let mut r = r;
                    let (connection, handle, _) = new_connection().expect("netlink socket");
                    tokio::spawn(connection);
                    let verdict = match r.confirm_neighbour(&handle, v4(40), gone_ifindex).await {
                        Still::Gone => "gone".to_string(),
                        Still::Present(p) => format!("present {p:?}"),
                        Still::Unknown(e) => format!("unknown: {e}"),
                    };
                    assert_eq!(verdict, "gone");
                });
            });
        });
    }
}
