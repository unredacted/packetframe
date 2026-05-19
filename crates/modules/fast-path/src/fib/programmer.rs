//! FibProgrammer — owns the BPF FIB write path (NEXTHOPS seqlock,
//! FIB_V4 / FIB_V6 LPM tries, ECMP_GROUPS dedup) and the userspace
//! mirror state.
//!
//! **Phase 3 scope: full route ingestion.** Phase 2 built the
//! neighbor side: register nexthop IPs, seqlock-write `NEXTHOPS[id]`
//! on `NeighEvent`. Phase 3 adds route ingestion from
//! [`RouteEvent`]s:
//!   - `Add` / `Del`: write / remove FIB_V4 / FIB_V6 entries,
//!     allocating nexthop IDs and ECMP groups as needed.
//!   - `PeerUp` / `PeerDown`: track which peer announced which
//!     routes; withdraw everything on `PeerDown`.
//!   - `Resync`: mark every mirrored route "not-seen-this-session";
//!     live `Add` events clear the mark as they re-arrive.
//!   - `InitiationComplete`: GC every still-unmarked route
//!     (they were in the BPF maps from before the reconnect but
//!     bird didn't re-announce → stale).
//!
//! ECMP groups are deduplicated by a sorted-NH-id signature so one
//! set of upstream transits announcing 200K prefixes allocates one
//! group, not 200K.
//!
//! Default-route (0.0.0.0/0 and ::/0) replacement is handled specially:
//! allocate the new value first, atomically overwrite the trie entry
//! (8 bytes, single `Array::set` syscall), then reclaim the old
//! nexthop / group IDs after a 100 ms grace period that covers any
//! in-flight XDP program invocation holding a stale pointer.
//!
//! Lifecycle:
//!   1. [`FibProgrammer::open_nexthops`] etc. open each map from its
//!      bpffs pin (independent kernel-map references from the
//!      loader's `aya::Ebpf` instance; both point at the same
//!      kernel objects).
//!   2. [`FibProgrammer::new`] constructs the programmer with all
//!      three map handles + the NeighEvent input channel, returns a
//!      [`FibProgrammerHandle`] for out-of-band commands.
//!   3. [`FibProgrammer::run`] is the async task: `select!`s over
//!      NeighEvents, Commands, the default-route reclaim tick, and
//!      shutdown.
//!
//! All mirror state lives inside the run task — no mutex on the hot
//! path. Commands are serialized through a command mpsc; replies
//! travel back via oneshot channels.

#![cfg(target_os = "linux")]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use aya::maps::{lpm_trie::Key as LpmKey, Array, LpmTrie, Map, MapData};
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use packetframe_common::fib::{IpPrefix, NeighEvent, PeerId, RouteEvent};

use crate::fib::netlink_neigh::NeighborResolveHandle;
use crate::fib::types::{
    EcmpGroup, FibValue, NexthopEntry, ECMP_NH_UNUSED, FIB_KIND_ECMP, MAX_ECMP_PATHS, NH_FAMILY_V4,
    NH_FAMILY_V6, NH_STATE_FAILED, NH_STATE_INCOMPLETE, NH_STATE_RESOLVED,
};
use crate::pin;

/// Command queue capacity. Route events dominate: one per prefix
/// add/del during a BGP convergence storm. 8192 absorbs 8 K-route
/// bursts without backpressure; sustained bursts apply backpressure
/// to the BMP reader which is correct.
const COMMAND_CAPACITY: usize = 8_192;

/// Capped by `NEXTHOPS_MAX_ENTRIES` in bpf/src/maps.rs. Keep in sync
/// if either side changes.
pub const NEXTHOPS_CAP: u32 = 8_192;

/// Capped by `FIB_V4_MAX_ENTRIES` in bpf/src/maps.rs.
pub const FIB_V4_CAP: u32 = 2_097_152;

/// Capped by `FIB_V6_MAX_ENTRIES` in bpf/src/maps.rs.
pub const FIB_V6_CAP: u32 = 1_048_576;

/// Capped by `ECMP_GROUPS_MAX_ENTRIES` in bpf/src/maps.rs.
pub const ECMP_GROUPS_CAP: u32 = 1_024;

/// Default-route (0.0.0.0/0 and ::/0) ID-reclaim grace period. An
/// atomic `FibValue` overwrite is instantaneous from the BPF
/// program's perspective, but a program invocation in flight at the
/// overwrite moment may still be reading the old nexthop / ECMP
/// group. 100 ms is 4 orders of magnitude longer than any realistic
/// XDP pass, short enough that the free-list doesn't starve under
/// flap. Enforced via the reclaim queue drained every tick inside
/// the run loop.
pub const DEFAULT_ROUTE_GRACE: Duration = Duration::from_millis(100);

/// How often the run loop checks the reclaim queue. Tight enough
/// to free IDs promptly after the grace period; loose enough not to
/// burn CPU. The select!'s other arms will still drive progress;
/// this is just a backstop.
const RECLAIM_TICK: Duration = Duration::from_millis(50);

/// `NexthopId` is an index into the `NEXTHOPS` BPF array. Stable
/// once assigned (via refcount/free-list recycling) so FIB_V4 / FIB_V6
/// LPM trie values can reference it without cascading updates on
/// neighbor changes.
pub type NexthopId = u32;

/// `EcmpGroupId` is an index into the `ECMP_GROUPS` BPF array.
/// Allocated with refcount + free-list + signature-based dedup so
/// N prefixes sharing the same nexthop set + hash mode all point
/// at one group.
pub type EcmpGroupId = u32;

/// Errors surfaced through the programmer's command replies.
#[derive(Debug, thiserror::Error)]
pub enum ProgrammerError {
    #[error("nexthop table full (cap {0}); cannot allocate")]
    Full(u32),
    #[error("FIB_V4 table full (cap {0}); dropping prefix")]
    FibV4Full(u32),
    #[error("FIB_V6 table full (cap {0}); dropping prefix")]
    FibV6Full(u32),
    #[error("ECMP group table full (cap {0}); dropping multi-path route")]
    EcmpGroupsFull(u32),
    #[error("ECMP group would exceed MAX_ECMP_PATHS ({0})")]
    EcmpGroupTooWide(usize),
    #[error("BPF map write failed: {0}")]
    MapWrite(String),
    #[error("BPF map open failed: {0}")]
    MapOpen(String),
    #[error("programmer task has shut down")]
    Shutdown,
}

/// Cloneable handle for issuing commands to a running programmer.
/// Held by test harnesses in Phase 2 and by the RouteSource +
/// RouteController in Phase 3+.
#[derive(Clone)]
pub struct FibProgrammerHandle {
    tx: mpsc::Sender<Command>,
}

impl FibProgrammerHandle {
    /// Register a nexthop IP. Returns the [`NexthopId`] the FIB
    /// trie should point at. If the same IP is already registered,
    /// returns the existing ID and bumps its refcount so the caller
    /// can `unregister` at its own cadence.
    ///
    /// Non-`Send` callers use the blocking `_sync` variant below.
    pub async fn register_nexthop(&self, ip: IpAddr) -> Result<NexthopId, ProgrammerError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::RegisterNexthop { ip, reply: tx })
            .await
            .map_err(|_| ProgrammerError::Shutdown)?;
        rx.await.map_err(|_| ProgrammerError::Shutdown)?
    }

    /// Blocking variant for callers not already on the tokio runtime
    /// (e.g., integration tests driving the programmer from a sync
    /// thread). Panics if called from within a tokio context — use
    /// `register_nexthop` there instead.
    pub fn register_nexthop_blocking(&self, ip: IpAddr) -> Result<NexthopId, ProgrammerError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .blocking_send(Command::RegisterNexthop { ip, reply: tx })
            .map_err(|_| ProgrammerError::Shutdown)?;
        rx.blocking_recv().map_err(|_| ProgrammerError::Shutdown)?
    }

    /// Decrement the refcount on `ip`. Frees the ID when refcount
    /// hits zero (marked `Failed` in the BPF map so any stale
    /// lookups bail out with `CustomFibNoNeigh`).
    pub async fn unregister_nexthop(&self, ip: IpAddr) -> Result<(), ProgrammerError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::UnregisterNexthop { ip, reply: tx })
            .await
            .map_err(|_| ProgrammerError::Shutdown)?;
        rx.await.map_err(|_| ProgrammerError::Shutdown)?
    }

    /// Apply a [`RouteEvent`] from the RouteSource. Issues the
    /// corresponding writes to FIB_V4 / FIB_V6 / NEXTHOPS /
    /// ECMP_GROUPS and updates the userspace mirror. Awaits
    /// completion; errors surface through the reply channel.
    pub async fn apply_route_event(&self, event: RouteEvent) -> Result<(), ProgrammerError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::ApplyRouteEvent { event, reply: tx })
            .await
            .map_err(|_| ProgrammerError::Shutdown)?;
        rx.await.map_err(|_| ProgrammerError::Shutdown)?
    }

    /// Return the current `(v4, v6)` route mirror counts. Used by the
    /// integrity checker to diff against bird's `show route count`.
    /// Reads the programmer's in-memory mirror, not the BPF maps —
    /// the mirror is the authoritative record of what the programmer
    /// believes it has written.
    pub async fn mirror_counts(&self) -> Result<(usize, usize), ProgrammerError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Command::MirrorCounts { reply: tx })
            .await
            .map_err(|_| ProgrammerError::Shutdown)?;
        rx.await.map_err(|_| ProgrammerError::Shutdown)
    }
}

enum Command {
    RegisterNexthop {
        ip: IpAddr,
        reply: oneshot::Sender<Result<NexthopId, ProgrammerError>>,
    },
    UnregisterNexthop {
        ip: IpAddr,
        reply: oneshot::Sender<Result<(), ProgrammerError>>,
    },
    /// Apply a [`RouteEvent`] from the RouteSource. The reply fires
    /// after the FIB / NEXTHOPS / ECMP_GROUPS writes complete; on
    /// capacity / map-write failures the error surfaces through it.
    ApplyRouteEvent {
        event: RouteEvent,
        reply: oneshot::Sender<Result<(), ProgrammerError>>,
    },
    /// Report `(routes_v4.len(), routes_v6.len())` from the
    /// programmer's mirror state. Used by the integrity checker.
    MirrorCounts {
        reply: oneshot::Sender<(usize, usize)>,
    },
}

/// Per-nexthop state tracked in userspace. Refcount lets multiple
/// routes share a single NexthopId without duplicating BPF-map slots.
struct NexthopRecord {
    id: NexthopId,
    refcount: u32,
    /// Latest known MAC + ifindex from the kernel. `None` until the
    /// first `NeighEvent::Learned` arrives for `ip`.
    resolved: Option<(u32, [u8; 6])>,
}

/// Per-route state tracked in userspace. The `fib_value` lets
/// us unwind the BPF map entry on Del without a read-modify-write
/// dance; `nexthop_ips` lets us decrement refcounts on the right
/// nexthops; the advertisements map lets PeerDown identify all of a
/// peer's contributions to this prefix without scanning every
/// advertisement on the system.
///
/// The aggregated model: a prefix can carry contributions from
/// multiple `(peer_id, path_id)` advertisements simultaneously. The
/// installed FIB entry is recomputed as the union of next-hops
/// across all advertisements after each mutation, and dedup'd via
/// `alloc_ecmp_group`'s signature index.
#[derive(Debug)]
struct RouteRecord {
    /// Per-advertisement nexthop, keyed by `(peer_id, path_id)`. A
    /// non-ADD-PATH source contributes one entry with `path_id =
    /// None`; an ADD-PATH-negotiated source contributes one entry
    /// per `path_id` the peer transmitted. `BTreeMap` gives stable
    /// iteration order so deterministic union computation feeds a
    /// stable ECMP-group signature.
    advertisements: BTreeMap<(PeerId, Option<u32>), Advertisement>,
    /// Currently-installed FibValue in the BPF FIB map; mirrors
    /// what the data plane is reading.
    fib_value: FibValue,
    /// Currently-installed nexthop IPs (sorted, deduplicated).
    /// Mirrors what `fib_value` points at. Used to release refcounts
    /// when the union changes or the prefix is torn down.
    nexthop_ips: Vec<IpAddr>,
}

/// A single advertisement contributing to a prefix's FIB entry.
///
/// One `RouteEvent::Add` produces one `Advertisement`; the
/// per-advertisement nexthop set may be multi-element when the
/// source is the legacy multi-NH `RouteEvent::Add` shape (e.g.,
/// netlink-injected ECMP), but ADD-PATH sources emit one NH per
/// advertisement and let the per-prefix union recompose the ECMP
/// group.
#[derive(Debug, Clone)]
struct Advertisement {
    nexthops: Vec<IpAddr>,
    /// Resync-reconcile bookkeeping: true when this advertisement
    /// was freshly Add'd (or refreshed) after the most recent
    /// Resync; false when it was inherited from a prior session and
    /// hasn't been re-announced. `InitiationComplete` GCs
    /// advertisements whose flag is still false; the prefix's FIB
    /// entry is then recomputed.
    seen_this_session: bool,
}

/// Per-ECMP-group state. Refcount lets many prefixes share one
/// group. The `id` is always the HashMap key we found this record
/// under; no separate `id` field since we only ever look it up by
/// that key.
#[derive(Debug)]
struct EcmpRecord {
    refcount: u32,
    /// Sorted `NexthopId`s + hash_mode. Sorting gives a canonical
    /// signature so `{NH1, NH2}` and `{NH2, NH1}` dedup to the same
    /// group regardless of BGP announcement order.
    nh_ids_sorted: Vec<NexthopId>,
    hash_mode: u8,
}

/// Canonical ECMP dedup key. `Vec<NexthopId>` is already sorted
/// by construction in `compute_signature`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EcmpSignature {
    nh_ids_sorted: Vec<NexthopId>,
    hash_mode: u8,
}

/// Reclaim queue entry for the default-route replace-by-swap path.
/// `release_at` is the earliest instant at which it's safe to free
/// the ID — an in-flight XDP program invocation may have read the
/// old FibValue and be about to dereference this nexthop / group.
#[derive(Debug)]
struct PendingReclaim {
    release_at: Instant,
    kind: ReclaimKind,
}

#[derive(Debug)]
enum ReclaimKind {
    /// Free a nexthop ID. Triggers `unregister` logic (refcount
    /// decrement; slot tombstoned + ID freed when refcount hits 0).
    Nexthop(IpAddr),
    /// Free an ECMP group ID. Decrements refcount; frees slot when 0.
    Ecmp(EcmpGroupId),
}

pub struct FibProgrammer {
    nexthops: Array<MapData, NexthopEntry>,
    fib_v4: LpmTrie<MapData, [u8; 4], FibValue>,
    fib_v6: LpmTrie<MapData, [u8; 16], FibValue>,
    ecmp_groups: Array<MapData, EcmpGroup>,

    events_rx: mpsc::Receiver<NeighEvent>,
    cmd_rx: mpsc::Receiver<Command>,
    shutdown: CancellationToken,

    // --- Nexthop state (Phase 2) ---
    by_ip: HashMap<IpAddr, NexthopRecord>,
    /// Reverse index: NexthopId → IpAddr. Held separately so
    /// NeighEvent → NexthopId lookup is O(1) instead of scanning
    /// every record.
    by_id: HashMap<NexthopId, IpAddr>,
    /// Latest seq value written per ID. Seqlock discipline requires
    /// each write to go odd-then-even from the current value.
    seq_by_id: HashMap<NexthopId, u32>,
    free_ids: Vec<NexthopId>,
    next_id: NexthopId,

    // --- Route state (Phase 3) ---
    /// Prefix → route record. Separate v4 / v6 maps so the key is
    /// the raw `(addr, prefix_len)` tuple (which is `Hash`) rather
    /// than the enum wrapper.
    routes_v4: HashMap<([u8; 4], u8), RouteRecord>,
    routes_v6: HashMap<([u8; 16], u8), RouteRecord>,
    /// Per-peer index for O(1) PeerDown traversal. Values are keys
    /// into `routes_v4` / `routes_v6` — the bool discriminates.
    /// `true` = v4, `false` = v6.
    routes_by_peer: HashMap<PeerId, HashSet<(bool, [u8; 16], u8)>>,

    // --- ECMP state (Phase 3) ---
    /// Dedup map: signature → group ID.
    ecmp_by_signature: HashMap<EcmpSignature, EcmpGroupId>,
    /// Per-group record: refcount, canonical NH set, hash mode.
    ecmp_by_id: HashMap<EcmpGroupId, EcmpRecord>,
    free_ecmp_ids: Vec<EcmpGroupId>,
    next_ecmp_id: EcmpGroupId,

    // --- Default-route reclaim queue (Phase 3) ---
    reclaim_queue: VecDeque<PendingReclaim>,

    // --- Proactive resolve (Phase 3.9 fix) ---
    /// Handle to the NeighborResolver. Every newly-allocated nexthop
    /// fires `request_resolve(ip)`. The resolver consults its seeded
    /// kernel-ARP cache and either emits a synthetic Learned event
    /// (typical case post-rc2) or falls through to an
    /// `RTM_NEWNEIGH NUD_NONE` proactive probe.
    ///
    /// Without this call, nexthops only resolve when the kernel
    /// happens to multicast a state transition, which doesn't fire
    /// for stable REACHABLE entries. That bug left ~95 % of BGP
    /// nexthops stuck in `incomplete` in pre-rc4 builds.
    /// `Option` so test harnesses can pass `None`.
    neigh_handle: Option<NeighborResolveHandle>,
}

impl FibProgrammer {
    /// Open the `NEXTHOPS` map from the bpffs pin and return a
    /// typed `Array` handle. Must be called after the loader has
    /// attached and pinned the map.
    pub fn open_nexthops(
        bpffs_root: &Path,
    ) -> Result<Array<MapData, NexthopEntry>, ProgrammerError> {
        let pin_path = pin::map_path(bpffs_root, "NEXTHOPS");
        let map_data = MapData::from_pin(&pin_path)
            .map_err(|e| ProgrammerError::MapOpen(format!("NEXTHOPS pin open: {e}")))?;
        let map = Map::Array(map_data);
        Array::try_from(map)
            .map_err(|e| ProgrammerError::MapOpen(format!("Array::try_from(NEXTHOPS): {e}")))
    }

    /// Open the `FIB_V4` LPM trie from its bpffs pin.
    pub fn open_fib_v4(
        bpffs_root: &Path,
    ) -> Result<LpmTrie<MapData, [u8; 4], FibValue>, ProgrammerError> {
        let pin_path = pin::map_path(bpffs_root, "FIB_V4");
        let map_data = MapData::from_pin(&pin_path)
            .map_err(|e| ProgrammerError::MapOpen(format!("FIB_V4 pin open: {e}")))?;
        let map = Map::LpmTrie(map_data);
        LpmTrie::try_from(map)
            .map_err(|e| ProgrammerError::MapOpen(format!("LpmTrie::try_from(FIB_V4): {e}")))
    }

    /// Open the `FIB_V6` LPM trie from its bpffs pin.
    pub fn open_fib_v6(
        bpffs_root: &Path,
    ) -> Result<LpmTrie<MapData, [u8; 16], FibValue>, ProgrammerError> {
        let pin_path = pin::map_path(bpffs_root, "FIB_V6");
        let map_data = MapData::from_pin(&pin_path)
            .map_err(|e| ProgrammerError::MapOpen(format!("FIB_V6 pin open: {e}")))?;
        let map = Map::LpmTrie(map_data);
        LpmTrie::try_from(map)
            .map_err(|e| ProgrammerError::MapOpen(format!("LpmTrie::try_from(FIB_V6): {e}")))
    }

    /// Open the `ECMP_GROUPS` array from its bpffs pin.
    pub fn open_ecmp_groups(
        bpffs_root: &Path,
    ) -> Result<Array<MapData, EcmpGroup>, ProgrammerError> {
        let pin_path = pin::map_path(bpffs_root, "ECMP_GROUPS");
        let map_data = MapData::from_pin(&pin_path)
            .map_err(|e| ProgrammerError::MapOpen(format!("ECMP_GROUPS pin open: {e}")))?;
        let map = Map::Array(map_data);
        Array::try_from(map)
            .map_err(|e| ProgrammerError::MapOpen(format!("Array::try_from(ECMP_GROUPS): {e}")))
    }

    /// Construct the programmer with all four BPF map handles. Opens
    /// are done by the caller (via [`open_nexthops`](Self::open_nexthops) etc.)
    /// so test harnesses can pass synthetic maps. `events_rx` is the
    /// NeighborResolver's output channel.
    pub fn new(
        nexthops: Array<MapData, NexthopEntry>,
        fib_v4: LpmTrie<MapData, [u8; 4], FibValue>,
        fib_v6: LpmTrie<MapData, [u8; 16], FibValue>,
        ecmp_groups: Array<MapData, EcmpGroup>,
        events_rx: mpsc::Receiver<NeighEvent>,
        shutdown: CancellationToken,
    ) -> (Self, FibProgrammerHandle) {
        Self::new_with_resolver(
            nexthops,
            fib_v4,
            fib_v6,
            ecmp_groups,
            events_rx,
            shutdown,
            None,
        )
    }

    /// Variant that wires in a [`NeighborResolveHandle`] so each
    /// newly-allocated nexthop triggers proactive resolution. The
    /// `new()` shortcut above (which test harnesses use) defers to
    /// this with `None`, leaving resolution to multicast events
    /// only. Production callers (RouteController) MUST pass `Some`
    /// or BGP nexthops will not resolve cleanly.
    pub fn new_with_resolver(
        nexthops: Array<MapData, NexthopEntry>,
        fib_v4: LpmTrie<MapData, [u8; 4], FibValue>,
        fib_v6: LpmTrie<MapData, [u8; 16], FibValue>,
        ecmp_groups: Array<MapData, EcmpGroup>,
        events_rx: mpsc::Receiver<NeighEvent>,
        shutdown: CancellationToken,
        neigh_handle: Option<NeighborResolveHandle>,
    ) -> (Self, FibProgrammerHandle) {
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CAPACITY);
        (
            Self {
                nexthops,
                fib_v4,
                fib_v6,
                ecmp_groups,
                events_rx,
                cmd_rx,
                shutdown,
                by_ip: HashMap::new(),
                by_id: HashMap::new(),
                seq_by_id: HashMap::new(),
                free_ids: Vec::new(),
                next_id: 0,
                routes_v4: HashMap::new(),
                routes_v6: HashMap::new(),
                routes_by_peer: HashMap::new(),
                ecmp_by_signature: HashMap::new(),
                ecmp_by_id: HashMap::new(),
                free_ecmp_ids: Vec::new(),
                next_ecmp_id: 0,
                reclaim_queue: VecDeque::new(),
                neigh_handle,
            },
            FibProgrammerHandle { tx: cmd_tx },
        )
    }

    /// Main event loop. Drains NeighEvents + Commands + the reclaim
    /// queue tick until shutdown.
    pub async fn run(mut self) {
        info!("FibProgrammer running");
        let mut reclaim_tick = interval(RECLAIM_TICK);
        // `interval`'s first tick fires immediately; skip it so the
        // first reclaim check lands one full period after startup.
        reclaim_tick.tick().await;

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("FibProgrammer shutdown requested");
                    return;
                }
                evt = self.events_rx.recv() => {
                    match evt {
                        Some(e) => self.on_neigh_event(e),
                        None => {
                            debug!("NeighEvent channel closed");
                        }
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(c) => self.on_command(c),
                        None => {
                            debug!("Command channel closed");
                        }
                    }
                }
                _ = reclaim_tick.tick() => {
                    self.drain_reclaim_queue();
                }
            }
        }
    }

    fn on_command(&mut self, cmd: Command) {
        match cmd {
            Command::RegisterNexthop { ip, reply } => {
                let _ = reply.send(self.register(ip));
            }
            Command::UnregisterNexthop { ip, reply } => {
                let _ = reply.send(self.unregister(ip));
            }
            Command::ApplyRouteEvent { event, reply } => {
                let _ = reply.send(self.on_route_event(event));
            }
            Command::MirrorCounts { reply } => {
                let _ = reply.send((self.routes_v4.len(), self.routes_v6.len()));
            }
        }
    }

    fn register(&mut self, ip: IpAddr) -> Result<NexthopId, ProgrammerError> {
        if let Some(rec) = self.by_ip.get_mut(&ip) {
            rec.refcount += 1;
            return Ok(rec.id);
        }
        let id = match self.free_ids.pop() {
            Some(id) => id,
            None => {
                if self.next_id >= NEXTHOPS_CAP {
                    return Err(ProgrammerError::Full(NEXTHOPS_CAP));
                }
                let id = self.next_id;
                self.next_id += 1;
                id
            }
        };

        // Seed the BPF slot with an Incomplete entry so XDP returning
        // NoNeigh is deterministic until the kernel resolves.
        let family = match ip {
            IpAddr::V4(_) => NH_FAMILY_V4,
            IpAddr::V6(_) => NH_FAMILY_V6,
        };
        let seed = NexthopEntry {
            seq: 0,
            ifindex: 0,
            dst_mac: [0; 6],
            _pad0: [0; 2],
            src_mac: [0; 6],
            _pad1: [0; 2],
            state: NH_STATE_INCOMPLETE,
            family,
            bmp_peer_hint: [0; 2],
        };
        if let Err(e) = self.write_seqlock(id, seed) {
            warn!(?ip, id, error = %e, "NEXTHOPS seed write failed");
            // Keep the ID reserved so we don't hand the same one to
            // another IP; reclaim on a later explicit unregister.
            self.free_ids.push(id);
            return Err(e);
        }

        self.by_ip.insert(
            ip,
            NexthopRecord {
                id,
                refcount: 1,
                resolved: None,
            },
        );
        self.by_id.insert(id, ip);
        debug!(?ip, id, "NexthopId allocated");

        // Phase 3.9 fix: kick the NeighborResolver so this nexthop
        // gets resolved promptly. The resolver consults its kernel-
        // ARP cache (seeded at startup); on hit it synthesizes a
        // Learned event and our `events_rx` arm flips state to
        // Resolved. On miss it falls back to RTM_NEWNEIGH NUD_NONE
        // (proactive probe). Without this call, the only thing that
        // resolves a nexthop is a kernel ARP state-transition
        // multicast — which never fires for entries that are
        // already-stable REACHABLE. Pre-fix, ~95 % of BGP nexthops
        // stayed `incomplete` forever and forwarding silently fell
        // back to XDP_PASS for those routes.
        if let Some(h) = &self.neigh_handle {
            h.request_resolve(ip);
        }

        Ok(id)
    }

    fn unregister(&mut self, ip: IpAddr) -> Result<(), ProgrammerError> {
        let rec = match self.by_ip.get_mut(&ip) {
            Some(r) => r,
            None => return Ok(()), // idempotent: unknown IP is already gone
        };
        rec.refcount = rec.refcount.saturating_sub(1);
        if rec.refcount > 0 {
            return Ok(());
        }
        let id = rec.id;
        self.by_ip.remove(&ip);
        self.by_id.remove(&id);
        self.seq_by_id.remove(&id);
        self.free_ids.push(id);

        // Leave the NEXTHOPS slot marked Failed so any stale FIB
        // pointer still producing lookups gets CustomFibNoNeigh
        // rather than forwarding to a recycled MAC.
        let marker = NexthopEntry {
            seq: 0,
            ifindex: 0,
            dst_mac: [0; 6],
            _pad0: [0; 2],
            src_mac: [0; 6],
            _pad1: [0; 2],
            state: NH_STATE_FAILED,
            family: 0,
            bmp_peer_hint: [0; 2],
        };
        if let Err(e) = self.write_seqlock(id, marker) {
            warn!(?ip, id, error = %e, "NEXTHOPS tombstone write failed");
            // Non-fatal; the BPF program will skip this slot on the
            // state check anyway.
        }
        debug!(?ip, id, "NexthopId freed");
        Ok(())
    }

    fn on_neigh_event(&mut self, evt: NeighEvent) {
        let ip = match &evt {
            NeighEvent::Learned { ip, .. } => *ip,
            NeighEvent::Failed { ip, .. } => *ip,
            NeighEvent::Gone { ip } => *ip,
        };
        // We only care about neigh events for IPs we've actually
        // registered as nexthops. Every other kernel neighbor update
        // is noise at this layer.
        let (id, family) = match self.by_ip.get(&ip) {
            Some(rec) => (
                rec.id,
                match ip {
                    IpAddr::V4(_) => NH_FAMILY_V4,
                    IpAddr::V6(_) => NH_FAMILY_V6,
                },
            ),
            None => return,
        };

        let entry = match evt {
            NeighEvent::Learned {
                mac,
                ifindex,
                src_mac,
                ..
            } => {
                // Remember the MAC so later Failed/Gone → revert-to-Incomplete
                // preserves the last-known-good for diagnostic use if we
                // ever expose it. Actual forwarding uses the live state only.
                if let Some(rec) = self.by_ip.get_mut(&ip) {
                    rec.resolved = Some((ifindex, mac));
                }
                NexthopEntry {
                    seq: 0,
                    ifindex,
                    dst_mac: mac,
                    _pad0: [0; 2],
                    // src_mac is now provided by the resolver (Phase 3.6).
                    // Falls back to [0; 6] if the resolver hasn't yet
                    // cached the egress iface's MAC (link came up after
                    // startup and we haven't seen its RTM_NEWLINK).
                    src_mac,
                    _pad1: [0; 2],
                    state: NH_STATE_RESOLVED,
                    family,
                    bmp_peer_hint: [0; 2],
                }
            }
            NeighEvent::Failed { .. } => NexthopEntry {
                seq: 0,
                ifindex: 0,
                dst_mac: [0; 6],
                _pad0: [0; 2],
                src_mac: [0; 6],
                _pad1: [0; 2],
                state: NH_STATE_FAILED,
                family,
                bmp_peer_hint: [0; 2],
            },
            NeighEvent::Gone { .. } => NexthopEntry {
                seq: 0,
                ifindex: 0,
                dst_mac: [0; 6],
                _pad0: [0; 2],
                src_mac: [0; 6],
                _pad1: [0; 2],
                state: NH_STATE_INCOMPLETE,
                family,
                bmp_peer_hint: [0; 2],
            },
        };

        if let Err(e) = self.write_seqlock(id, entry) {
            warn!(?ip, id, error = %e, "NEXTHOPS update failed");
        }
    }

    /// Write `entry` into `NEXTHOPS[id]` under the seqlock discipline:
    /// bump seq to odd (write in progress), push entry, bump to even
    /// (stable). The XDP reader retries on odd-seq observations and
    /// on `seq_before != seq_after` mismatches.
    ///
    /// Each call performs two `Array::set` syscalls. At Phase 3's
    /// target of ~tens of neigh updates/sec this is inexpensive; the
    /// hot path is reading, not writing.
    fn write_seqlock(
        &mut self,
        id: NexthopId,
        mut entry: NexthopEntry,
    ) -> Result<(), ProgrammerError> {
        let prev = *self.seq_by_id.get(&id).unwrap_or(&0);
        // From even `prev`, go to `prev+1` (odd, in progress) then
        // `prev+2` (even, stable). If `prev` is odd (shouldn't happen
        // from our own writes; robustness against external pokes), go
        // to `prev+0` would collide; force-round to the next odd.
        let odd = if prev & 1 == 0 {
            prev.wrapping_add(1)
        } else {
            prev.wrapping_add(2)
        };
        let even = odd.wrapping_add(1);

        entry.seq = odd;
        self.nexthops
            .set(id, entry, 0)
            .map_err(|e| ProgrammerError::MapWrite(format!("seqlock odd-phase id={id}: {e}")))?;
        entry.seq = even;
        self.nexthops
            .set(id, entry, 0)
            .map_err(|e| ProgrammerError::MapWrite(format!("seqlock even-phase id={id}: {e}")))?;
        self.seq_by_id.insert(id, even);
        Ok(())
    }

    // --- Route event handling (Phase 3, RFC 7911 aggregation) ----------

    fn on_route_event(&mut self, event: RouteEvent) -> Result<(), ProgrammerError> {
        match event {
            RouteEvent::PeerUp { peer_id, .. } => {
                // Informational. Per-peer state is initialized lazily
                // when the first advertisement from `peer_id` arrives.
                debug!(?peer_id, "PeerUp received");
                Ok(())
            }
            RouteEvent::PeerDown { peer_id } => self.drop_routes_for_peer(peer_id),
            RouteEvent::Add {
                peer_id,
                prefix,
                nexthops,
                path_id,
            } => self.add_route(peer_id, prefix, nexthops, path_id),
            RouteEvent::Del {
                peer_id,
                prefix,
                path_id,
            } => self.del_route(peer_id, prefix, path_id),
            RouteEvent::Resync => {
                self.mark_all_unseen();
                info!("Resync: all advertisements marked not-seen-this-session");
                Ok(())
            }
            RouteEvent::InitiationComplete => {
                let gc_count = self.gc_unseen()?;
                info!(
                    gc_count,
                    "InitiationComplete: garbage-collected unseen advertisements"
                );
                Ok(())
            }
        }
    }

    fn add_route(
        &mut self,
        peer_id: PeerId,
        prefix: IpPrefix,
        nexthops: Vec<IpAddr>,
        path_id: Option<u32>,
    ) -> Result<(), ProgrammerError> {
        if nexthops.is_empty() {
            // Defensive. An empty announce should arrive as Del.
            return Ok(());
        }
        self.upsert_advertisement(peer_id, prefix, path_id, nexthops);
        self.recompute_fib_entry(prefix)
    }

    fn del_route(
        &mut self,
        peer_id: PeerId,
        prefix: IpPrefix,
        path_id: Option<u32>,
    ) -> Result<(), ProgrammerError> {
        if !self.remove_advertisement(peer_id, &prefix, path_id) {
            // Idempotent: nothing was advertised under this key.
            return Ok(());
        }
        self.recompute_fib_entry(prefix)
    }

    /// Drop every advertisement contributed by `peer_id`. Called on
    /// `PeerDown`. Each affected prefix is recomputed; prefixes whose
    /// only remaining advertisements were from this peer are torn
    /// down entirely. Prefixes still carrying advertisements from
    /// other peers keep their FIB entries, possibly with a narrowed
    /// NH set.
    fn drop_routes_for_peer(&mut self, peer_id: PeerId) -> Result<(), ProgrammerError> {
        let prefixes_for_peer = match self.routes_by_peer.remove(&peer_id) {
            Some(set) => set,
            None => return Ok(()),
        };
        let prefix_count = prefixes_for_peer.len();
        for (is_v4, addr, plen) in prefixes_for_peer {
            let prefix = if is_v4 {
                let mut a = [0u8; 4];
                a.copy_from_slice(&addr[..4]);
                IpPrefix::V4 {
                    addr: a,
                    prefix_len: plen,
                }
            } else {
                IpPrefix::V6 {
                    addr,
                    prefix_len: plen,
                }
            };
            let drained = self.drain_peer_advertisements(peer_id, &prefix);
            if drained == 0 {
                continue;
            }
            if let Err(e) = self.recompute_fib_entry(prefix) {
                warn!(?peer_id, ?prefix, error = %e, "recompute after PeerDown failed");
            }
        }
        info!(
            ?peer_id,
            prefix_count, "PeerDown: withdrew peer's advertisements"
        );
        Ok(())
    }

    /// Mark every advertisement as `seen_this_session = false`. Live
    /// `Add` events clear the mark; `InitiationComplete` GCs what's
    /// left.
    fn mark_all_unseen(&mut self) {
        for rec in self.routes_v4.values_mut() {
            for adv in rec.advertisements.values_mut() {
                adv.seen_this_session = false;
            }
        }
        for rec in self.routes_v6.values_mut() {
            for adv in rec.advertisements.values_mut() {
                adv.seen_this_session = false;
            }
        }
    }

    /// GC advertisements still marked `seen_this_session = false`
    /// after an InitiationComplete. Returns the count of
    /// advertisements (not prefixes) removed. Affected prefixes are
    /// recomputed; those whose every advertisement was unseen are
    /// torn down entirely.
    fn gc_unseen(&mut self) -> Result<usize, ProgrammerError> {
        // Collect victims out-of-band so the borrow checker is happy
        // while we mutate during recompute.
        let mut victims: Vec<(IpPrefix, (PeerId, Option<u32>))> = Vec::new();
        for ((addr, prefix_len), rec) in &self.routes_v4 {
            for (key, adv) in &rec.advertisements {
                if !adv.seen_this_session {
                    victims.push((
                        IpPrefix::V4 {
                            addr: *addr,
                            prefix_len: *prefix_len,
                        },
                        *key,
                    ));
                }
            }
        }
        for ((addr, prefix_len), rec) in &self.routes_v6 {
            for (key, adv) in &rec.advertisements {
                if !adv.seen_this_session {
                    victims.push((
                        IpPrefix::V6 {
                            addr: *addr,
                            prefix_len: *prefix_len,
                        },
                        *key,
                    ));
                }
            }
        }
        let count = victims.len();
        let mut touched: HashSet<IpPrefix> = HashSet::new();
        for (prefix, (peer_id, path_id)) in victims {
            if self.remove_advertisement(peer_id, &prefix, path_id) {
                touched.insert(prefix);
            }
        }
        for prefix in touched {
            self.recompute_fib_entry(prefix)?;
        }
        Ok(count)
    }

    // --- Advertisement bookkeeping (slice 4) ---

    /// Insert or replace `advertisements[(peer_id, path_id)]` on
    /// `prefix`'s record, creating the record if absent. Keeps the
    /// `routes_by_peer` index in sync. Recompute is the caller's
    /// responsibility.
    fn upsert_advertisement(
        &mut self,
        peer_id: PeerId,
        prefix: IpPrefix,
        path_id: Option<u32>,
        nexthops: Vec<IpAddr>,
    ) {
        let key = (peer_id, path_id);
        let adv = Advertisement {
            nexthops,
            seen_this_session: true,
        };
        let rec = self.upsert_empty_record(prefix);
        rec.advertisements.insert(key, adv);
        self.routes_by_peer
            .entry(peer_id)
            .or_default()
            .insert(prefix_peer_key(&prefix));
    }

    /// Remove a single advertisement. Returns `true` when an entry
    /// existed. Clears the per-peer index if the peer has no more
    /// advertisements on this prefix. Recompute is the caller's
    /// responsibility.
    fn remove_advertisement(
        &mut self,
        peer_id: PeerId,
        prefix: &IpPrefix,
        path_id: Option<u32>,
    ) -> bool {
        let removed = match self.lookup_mirror_mut(prefix) {
            Some(rec) => rec.advertisements.remove(&(peer_id, path_id)).is_some(),
            None => false,
        };
        if removed {
            self.maybe_clear_peer_index(peer_id, prefix);
        }
        removed
    }

    /// Remove every advertisement on `prefix` that originated from
    /// `peer_id`. Returns the number removed. `routes_by_peer`
    /// cleanup is the caller's responsibility (typically a bulk
    /// `drop_routes_for_peer`).
    fn drain_peer_advertisements(&mut self, peer_id: PeerId, prefix: &IpPrefix) -> usize {
        match self.lookup_mirror_mut(prefix) {
            Some(rec) => {
                let before = rec.advertisements.len();
                rec.advertisements.retain(|(p, _), _| *p != peer_id);
                before - rec.advertisements.len()
            }
            None => 0,
        }
    }

    /// Drop `prefix` from `routes_by_peer[peer_id]` when the peer has
    /// no remaining advertisements for it; also drops the per-peer
    /// entry when the peer's set is empty.
    fn maybe_clear_peer_index(&mut self, peer_id: PeerId, prefix: &IpPrefix) {
        let peer_still_has_prefix = self
            .lookup_mirror(prefix)
            .map(|r| r.advertisements.keys().any(|(p, _)| *p == peer_id))
            .unwrap_or(false);
        if peer_still_has_prefix {
            return;
        }
        if let Some(set) = self.routes_by_peer.get_mut(&peer_id) {
            set.remove(&prefix_peer_key(prefix));
            if set.is_empty() {
                self.routes_by_peer.remove(&peer_id);
            }
        }
    }

    /// Recompute the FIB entry for `prefix` from its current
    /// advertisements. Empty advertisements tear the prefix down.
    /// Otherwise the union of next-hops across all advertisements
    /// determines the new FibValue (single when one NH, ECMP when
    /// many); writes through to the BPF FIB map only when the
    /// installed NH set actually changes. Prior resources are
    /// reclaimed via the grace-deferred queue so concurrent XDP reads
    /// stay safe across the transition; full tear-downs free
    /// immediately because the BPF LPM entry is gone and no new
    /// lookup can land on the prior IDs.
    fn recompute_fib_entry(&mut self, prefix: IpPrefix) -> Result<(), ProgrammerError> {
        // 1. Compute the desired sorted, deduplicated NH set.
        let desired_nhs: Vec<IpAddr> = match self.lookup_mirror(&prefix) {
            Some(rec) => {
                let mut set: BTreeSet<IpAddr> = BTreeSet::new();
                for adv in rec.advertisements.values() {
                    for nh in &adv.nexthops {
                        set.insert(*nh);
                    }
                }
                set.into_iter().collect()
            }
            None => Vec::new(),
        };

        // 2. Empty desired set: tear the prefix down.
        if desired_nhs.is_empty() {
            let rec = match self.remove_mirror_direct(&prefix) {
                Some(r) => r,
                None => return Ok(()),
            };
            self.delete_fib_entry(&prefix)?;
            self.reclaim_immediate(rec.fib_value, rec.nexthop_ips);
            return Ok(());
        }

        // 3. No-change shortcut: identical NH set already installed.
        let prior_state = self
            .lookup_mirror(&prefix)
            .map(|r| (r.fib_value, r.nexthop_ips.clone()));
        let unchanged = matches!(&prior_state, Some((_, ips)) if *ips == desired_nhs);
        if unchanged {
            return Ok(());
        }

        // 4. Allocate the new FibValue.
        let mut nh_ids: Vec<NexthopId> = Vec::with_capacity(desired_nhs.len());
        let mut allocated_ips: Vec<IpAddr> = Vec::with_capacity(desired_nhs.len());
        for ip in &desired_nhs {
            match self.register(*ip) {
                Ok(id) => {
                    nh_ids.push(id);
                    allocated_ips.push(*ip);
                }
                Err(e) => {
                    for done in &allocated_ips {
                        let _ = self.unregister(*done);
                    }
                    return Err(e);
                }
            }
        }
        let new_fib_value = if nh_ids.len() == 1 {
            FibValue::single(nh_ids[0])
        } else {
            // Mode 5 (5-tuple) — default from FIB_CONFIG. Per-group
            // override is a future refinement.
            let hash_mode = 5;
            match self.alloc_ecmp_group(&nh_ids, hash_mode) {
                Ok(id) => FibValue::ecmp(id),
                Err(e) => {
                    for ip in &allocated_ips {
                        let _ = self.unregister(*ip);
                    }
                    return Err(e);
                }
            }
        };

        // 5. Write through; unwind the new allocation if the write
        // fails so the error path leaves no lingering refcounts.
        if let Err(e) = self.write_fib_entry(&prefix, new_fib_value) {
            if new_fib_value.kind == FIB_KIND_ECMP {
                self.free_ecmp_group(new_fib_value.idx);
            }
            for ip in &allocated_ips {
                let _ = self.unregister(*ip);
            }
            return Err(e);
        }

        // 6. Commit the swap in the mirror and reclaim prior
        // resources with the grace queue.
        let (prior_fib, prior_nh_ips) = match prior_state {
            Some((fv, ips)) => (Some(fv), ips),
            None => (None, Vec::new()),
        };
        {
            let rec = self
                .lookup_mirror_mut(&prefix)
                .expect("record present after upsert");
            rec.fib_value = new_fib_value;
            rec.nexthop_ips = allocated_ips;
        }
        self.reclaim_prior(prior_fib, prior_nh_ips);
        Ok(())
    }

    /// Reclaim the prior FibValue and NH set after a FIB-entry
    /// in-place rewrite. Routes through the grace queue so
    /// concurrent XDP reads can finish dereferencing the old IDs.
    fn reclaim_prior(&mut self, prior_fib: Option<FibValue>, prior_nh_ips: Vec<IpAddr>) {
        let release_at = Instant::now() + DEFAULT_ROUTE_GRACE;
        if let Some(fv) = prior_fib {
            if fv.kind == FIB_KIND_ECMP {
                self.reclaim_queue.push_back(PendingReclaim {
                    release_at,
                    kind: ReclaimKind::Ecmp(fv.idx),
                });
            }
        }
        for ip in prior_nh_ips {
            self.reclaim_queue.push_back(PendingReclaim {
                release_at,
                kind: ReclaimKind::Nexthop(ip),
            });
        }
    }

    /// Free a torn-down prefix's resources immediately. Safe because
    /// the BPF LPM entry has already been removed; lookups return
    /// no-match right away, so no in-flight reader can dereference
    /// these IDs after the deletion.
    fn reclaim_immediate(&mut self, fib: FibValue, nh_ips: Vec<IpAddr>) {
        if fib.kind == FIB_KIND_ECMP {
            self.free_ecmp_group(fib.idx);
        }
        for ip in nh_ips {
            let _ = self.unregister(ip);
        }
    }

    // --- Mirror ops ---

    fn lookup_mirror(&self, prefix: &IpPrefix) -> Option<&RouteRecord> {
        match prefix {
            IpPrefix::V4 { addr, prefix_len } => self.routes_v4.get(&(*addr, *prefix_len)),
            IpPrefix::V6 { addr, prefix_len } => self.routes_v6.get(&(*addr, *prefix_len)),
        }
    }

    fn lookup_mirror_mut(&mut self, prefix: &IpPrefix) -> Option<&mut RouteRecord> {
        match prefix {
            IpPrefix::V4 { addr, prefix_len } => self.routes_v4.get_mut(&(*addr, *prefix_len)),
            IpPrefix::V6 { addr, prefix_len } => self.routes_v6.get_mut(&(*addr, *prefix_len)),
        }
    }

    /// Get-or-insert an empty record for `prefix`. The placeholder
    /// FibValue and `nexthop_ips` are populated by the subsequent
    /// `recompute_fib_entry`; nothing reads them between insertion
    /// and recompute.
    fn upsert_empty_record(&mut self, prefix: IpPrefix) -> &mut RouteRecord {
        match prefix {
            IpPrefix::V4 { addr, prefix_len } => self
                .routes_v4
                .entry((addr, prefix_len))
                .or_insert_with(|| RouteRecord {
                    advertisements: BTreeMap::new(),
                    fib_value: FibValue::single(0),
                    nexthop_ips: Vec::new(),
                }),
            IpPrefix::V6 { addr, prefix_len } => self
                .routes_v6
                .entry((addr, prefix_len))
                .or_insert_with(|| RouteRecord {
                    advertisements: BTreeMap::new(),
                    fib_value: FibValue::single(0),
                    nexthop_ips: Vec::new(),
                }),
        }
    }

    fn remove_mirror_direct(&mut self, prefix: &IpPrefix) -> Option<RouteRecord> {
        let rec = match prefix {
            IpPrefix::V4 { addr, prefix_len } => self.routes_v4.remove(&(*addr, *prefix_len))?,
            IpPrefix::V6 { addr, prefix_len } => self.routes_v6.remove(&(*addr, *prefix_len))?,
        };
        // Clean the per-peer index for every peer that contributed to
        // this prefix. Dedup by peer with a BTreeSet so we touch each
        // peer's bucket once.
        let peers: BTreeSet<PeerId> = rec.advertisements.keys().map(|(p, _)| *p).collect();
        let key = prefix_peer_key(prefix);
        for peer in peers {
            if let Some(set) = self.routes_by_peer.get_mut(&peer) {
                set.remove(&key);
                if set.is_empty() {
                    self.routes_by_peer.remove(&peer);
                }
            }
        }
        Some(rec)
    }

    // --- FIB map ops ---

    fn write_fib_entry(
        &mut self,
        prefix: &IpPrefix,
        value: FibValue,
    ) -> Result<(), ProgrammerError> {
        match prefix {
            IpPrefix::V4 { addr, prefix_len } => {
                if self.routes_v4.len() as u32 >= FIB_V4_CAP
                    && !self.routes_v4.contains_key(&(*addr, *prefix_len))
                {
                    return Err(ProgrammerError::FibV4Full(FIB_V4_CAP));
                }
                let key = LpmKey::new(u32::from(*prefix_len), *addr);
                self.fib_v4
                    .insert(&key, value, 0)
                    .map_err(|e| ProgrammerError::MapWrite(format!("FIB_V4 insert: {e}")))
            }
            IpPrefix::V6 { addr, prefix_len } => {
                if self.routes_v6.len() as u32 >= FIB_V6_CAP
                    && !self.routes_v6.contains_key(&(*addr, *prefix_len))
                {
                    return Err(ProgrammerError::FibV6Full(FIB_V6_CAP));
                }
                let key = LpmKey::new(u32::from(*prefix_len), *addr);
                self.fib_v6
                    .insert(&key, value, 0)
                    .map_err(|e| ProgrammerError::MapWrite(format!("FIB_V6 insert: {e}")))
            }
        }
    }

    fn delete_fib_entry(&mut self, prefix: &IpPrefix) -> Result<(), ProgrammerError> {
        match prefix {
            IpPrefix::V4 { addr, prefix_len } => {
                let key = LpmKey::new(u32::from(*prefix_len), *addr);
                self.fib_v4
                    .remove(&key)
                    .map_err(|e| ProgrammerError::MapWrite(format!("FIB_V4 remove: {e}")))
            }
            IpPrefix::V6 { addr, prefix_len } => {
                let key = LpmKey::new(u32::from(*prefix_len), *addr);
                self.fib_v6
                    .remove(&key)
                    .map_err(|e| ProgrammerError::MapWrite(format!("FIB_V6 remove: {e}")))
            }
        }
    }

    // --- ECMP group ops ---

    fn alloc_ecmp_group(
        &mut self,
        nh_ids: &[NexthopId],
        hash_mode: u8,
    ) -> Result<EcmpGroupId, ProgrammerError> {
        if nh_ids.len() > MAX_ECMP_PATHS {
            return Err(ProgrammerError::EcmpGroupTooWide(nh_ids.len()));
        }
        let signature = Self::compute_signature(nh_ids, hash_mode);
        if let Some(existing) = self.ecmp_by_signature.get(&signature) {
            let id = *existing;
            if let Some(rec) = self.ecmp_by_id.get_mut(&id) {
                rec.refcount += 1;
            }
            return Ok(id);
        }
        // Allocate a fresh group ID.
        let id = match self.free_ecmp_ids.pop() {
            Some(id) => id,
            None => {
                if self.next_ecmp_id >= ECMP_GROUPS_CAP {
                    return Err(ProgrammerError::EcmpGroupsFull(ECMP_GROUPS_CAP));
                }
                let id = self.next_ecmp_id;
                self.next_ecmp_id += 1;
                id
            }
        };
        // Write into the BPF map.
        let mut nh_idx = [ECMP_NH_UNUSED; MAX_ECMP_PATHS];
        for (i, nh_id) in signature.nh_ids_sorted.iter().enumerate() {
            nh_idx[i] = *nh_id;
        }
        let group = EcmpGroup {
            hash_mode,
            nh_count: signature.nh_ids_sorted.len() as u8,
            _pad: [0; 2],
            nh_idx,
        };
        if let Err(e) = self.ecmp_groups.set(id, group, 0) {
            // Return ID to free-list and surface the error.
            self.free_ecmp_ids.push(id);
            return Err(ProgrammerError::MapWrite(format!(
                "ECMP_GROUPS set id={id}: {e}"
            )));
        }
        // Record in mirror.
        self.ecmp_by_signature.insert(signature.clone(), id);
        self.ecmp_by_id.insert(
            id,
            EcmpRecord {
                refcount: 1,
                nh_ids_sorted: signature.nh_ids_sorted,
                hash_mode,
            },
        );
        Ok(id)
    }

    fn free_ecmp_group(&mut self, id: EcmpGroupId) {
        let rec = match self.ecmp_by_id.get_mut(&id) {
            Some(r) => r,
            None => return,
        };
        rec.refcount = rec.refcount.saturating_sub(1);
        if rec.refcount > 0 {
            return;
        }
        // Fully freed — remove from mirror, push ID to free-list,
        // tombstone the BPF slot.
        let signature = EcmpSignature {
            nh_ids_sorted: rec.nh_ids_sorted.clone(),
            hash_mode: rec.hash_mode,
        };
        self.ecmp_by_signature.remove(&signature);
        self.ecmp_by_id.remove(&id);
        self.free_ecmp_ids.push(id);
        let tombstone = EcmpGroup {
            hash_mode: 0,
            nh_count: 0,
            _pad: [0; 2],
            nh_idx: [ECMP_NH_UNUSED; MAX_ECMP_PATHS],
        };
        if let Err(e) = self.ecmp_groups.set(id, tombstone, 0) {
            warn!(id, error = %e, "ECMP_GROUPS tombstone write failed");
        }
    }

    fn compute_signature(nh_ids: &[NexthopId], hash_mode: u8) -> EcmpSignature {
        let mut sorted = nh_ids.to_vec();
        sorted.sort_unstable();
        EcmpSignature {
            nh_ids_sorted: sorted,
            hash_mode,
        }
    }

    // --- Reclaim queue drain (grace-period release) ---

    fn drain_reclaim_queue(&mut self) {
        let now = Instant::now();
        while let Some(entry) = self.reclaim_queue.front() {
            if entry.release_at > now {
                break;
            }
            let entry = self.reclaim_queue.pop_front().unwrap();
            match entry.kind {
                ReclaimKind::Nexthop(ip) => {
                    let _ = self.unregister(ip);
                }
                ReclaimKind::Ecmp(id) => {
                    self.free_ecmp_group(id);
                }
            }
        }
    }
}

/// Encode an `IpPrefix` to the `(is_v4, addr-padded-to-16, plen)`
/// shape used by `routes_by_peer`. The 16-byte addr buffer holds the
/// 4-byte v4 address in the low octets (high 12 are zero) so both
/// families share the same `HashSet` key type.
fn prefix_peer_key(prefix: &IpPrefix) -> (bool, [u8; 16], u8) {
    match prefix {
        IpPrefix::V4 { addr, prefix_len } => {
            let mut padded = [0u8; 16];
            padded[..4].copy_from_slice(addr);
            (true, padded, *prefix_len)
        }
        IpPrefix::V6 { addr, prefix_len } => (false, *addr, *prefix_len),
    }
}
