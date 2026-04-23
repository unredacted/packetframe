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

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use aya::maps::{lpm_trie::Key as LpmKey, Array, LpmTrie, Map, MapData};
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use packetframe_common::fib::{IpPrefix, NeighEvent, PeerId, RouteEvent};

use crate::fib::types::{
    EcmpGroup, FibValue, NexthopEntry, ECMP_NH_UNUSED, MAX_ECMP_PATHS, NH_FAMILY_V4, NH_FAMILY_V6,
    NH_STATE_FAILED, NH_STATE_INCOMPLETE, NH_STATE_RESOLVED,
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
/// nexthops; `peer_id` lets PeerDown walk by peer.
#[derive(Debug)]
struct RouteRecord {
    peer_id: PeerId,
    fib_value: FibValue,
    /// Nexthop IPs this route references. On Del we unregister each
    /// (decrement refcount, free NexthopId when it hits zero).
    nexthop_ips: Vec<IpAddr>,
    /// Resync-reconcile bookkeeping: true when this route was
    /// freshly Add'd (or refreshed) after the most recent Resync;
    /// false when it was inherited from a prior session and hasn't
    /// been re-announced yet. InitiationComplete GCs routes whose
    /// flag is still false.
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

    // --- Route event handling (Phase 3) ---------------------------------

    fn on_route_event(&mut self, event: RouteEvent) -> Result<(), ProgrammerError> {
        match event {
            RouteEvent::PeerUp { peer_id, .. } => {
                // PeerUp is informational for the programmer; we start
                // tracking routes by peer_id as soon as the first
                // RouteEvent::Add { peer_id } arrives. Nothing to do
                // until then.
                debug!(?peer_id, "PeerUp received");
                Ok(())
            }
            RouteEvent::PeerDown { peer_id } => self.drop_routes_for_peer(peer_id),
            RouteEvent::Add {
                peer_id,
                prefix,
                nexthops,
            } => self.add_route(peer_id, prefix, nexthops),
            RouteEvent::Del { peer_id: _, prefix } => self.del_route(prefix),
            RouteEvent::Resync => {
                self.mark_all_unseen();
                info!("Resync: all routes marked not-seen-this-session");
                Ok(())
            }
            RouteEvent::InitiationComplete => {
                let gc_count = self.gc_unseen();
                info!(
                    gc_count,
                    "InitiationComplete: garbage-collected unseen routes"
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
    ) -> Result<(), ProgrammerError> {
        if nexthops.is_empty() {
            // Empty nexthop set ⇒ refuse. BMP should never surface
            // this for a non-withdraw; defensive.
            return Ok(());
        }

        // Allocate nexthop IDs (bumps refcount on existing IPs).
        let mut nh_ids: Vec<NexthopId> = Vec::with_capacity(nexthops.len());
        let mut allocated_ips: Vec<IpAddr> = Vec::with_capacity(nexthops.len());
        for ip in &nexthops {
            match self.register(*ip) {
                Ok(id) => {
                    nh_ids.push(id);
                    allocated_ips.push(*ip);
                }
                Err(e) => {
                    // Unwind partial allocations so the error leaves
                    // no lingering refcount state.
                    for done in &allocated_ips {
                        let _ = self.unregister(*done);
                    }
                    return Err(e);
                }
            }
        }

        let fib_value = if nh_ids.len() == 1 {
            FibValue::single(nh_ids[0])
        } else {
            // ECMP group. hash_mode comes from FIB_CONFIG's default
            // for now; per-group override is a Phase 3+ refinement
            // once bird surfaces per-peer hash policy via community
            // or similar.
            let hash_mode = 5; // Mode 5 (5-tuple) — default from FIB_CONFIG.
            match self.alloc_ecmp_group(&nh_ids, hash_mode) {
                Ok(id) => FibValue::ecmp(id),
                Err(e) => {
                    // Unwind allocated nexthop refcounts.
                    for ip in &allocated_ips {
                        let _ = self.unregister(*ip);
                    }
                    return Err(e);
                }
            }
        };

        // Detect default-route replace: if a prior entry exists at
        // this prefix, swap with grace-period reclaim. Otherwise,
        // straight write + mirror insert.
        let replace = self.lookup_mirror(&prefix).is_some();
        if replace {
            let old = self.remove_mirror(&prefix);
            self.write_fib_entry(&prefix, fib_value)?;
            if let Some(old_rec) = old {
                self.enqueue_reclaim(old_rec);
            }
        } else {
            self.write_fib_entry(&prefix, fib_value)?;
        }

        // Record in mirror.
        let record = RouteRecord {
            peer_id,
            fib_value,
            nexthop_ips: nexthops,
            seen_this_session: true,
        };
        self.insert_mirror(prefix, record);
        Ok(())
    }

    fn del_route(&mut self, prefix: IpPrefix) -> Result<(), ProgrammerError> {
        let old = match self.remove_mirror(&prefix) {
            Some(r) => r,
            None => return Ok(()), // idempotent
        };
        self.delete_fib_entry(&prefix)?;
        self.release_route_record(old);
        Ok(())
    }

    /// Drop every route mirrored under `peer_id`. Called on PeerDown.
    fn drop_routes_for_peer(&mut self, peer_id: PeerId) -> Result<(), ProgrammerError> {
        let prefixes = match self.routes_by_peer.remove(&peer_id) {
            Some(s) => s,
            None => return Ok(()),
        };
        let count = prefixes.len();
        for (is_v4, addr, plen) in prefixes {
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
            let rec = match self.remove_mirror_direct(&prefix) {
                Some(r) => r,
                None => continue,
            };
            if let Err(e) = self.delete_fib_entry(&prefix) {
                warn!(?peer_id, ?prefix, error = %e, "FIB delete during PeerDown failed");
            }
            self.release_route_record(rec);
        }
        info!(?peer_id, count, "PeerDown: withdrew routes");
        Ok(())
    }

    /// Mark every mirrored route as `seen_this_session = false`. Live
    /// `Add` events clear the mark; `InitiationComplete` GCs what's
    /// left.
    fn mark_all_unseen(&mut self) {
        for rec in self.routes_v4.values_mut() {
            rec.seen_this_session = false;
        }
        for rec in self.routes_v6.values_mut() {
            rec.seen_this_session = false;
        }
    }

    /// GC routes still marked `seen_this_session = false` after an
    /// InitiationComplete. Returns the count removed.
    fn gc_unseen(&mut self) -> usize {
        let mut unseen_v4: Vec<([u8; 4], u8)> = Vec::new();
        for (k, r) in &self.routes_v4 {
            if !r.seen_this_session {
                unseen_v4.push(*k);
            }
        }
        let mut unseen_v6: Vec<([u8; 16], u8)> = Vec::new();
        for (k, r) in &self.routes_v6 {
            if !r.seen_this_session {
                unseen_v6.push(*k);
            }
        }
        let count = unseen_v4.len() + unseen_v6.len();
        for (addr, plen) in unseen_v4 {
            let p = IpPrefix::V4 {
                addr,
                prefix_len: plen,
            };
            let _ = self.del_route(p);
        }
        for (addr, plen) in unseen_v6 {
            let p = IpPrefix::V6 {
                addr,
                prefix_len: plen,
            };
            let _ = self.del_route(p);
        }
        count
    }

    // --- Mirror ops ---

    fn lookup_mirror(&self, prefix: &IpPrefix) -> Option<&RouteRecord> {
        match prefix {
            IpPrefix::V4 { addr, prefix_len } => self.routes_v4.get(&(*addr, *prefix_len)),
            IpPrefix::V6 { addr, prefix_len } => self.routes_v6.get(&(*addr, *prefix_len)),
        }
    }

    fn insert_mirror(&mut self, prefix: IpPrefix, record: RouteRecord) {
        let peer_id = record.peer_id;
        match prefix {
            IpPrefix::V4 { addr, prefix_len } => {
                self.routes_v4.insert((addr, prefix_len), record);
                let mut padded = [0u8; 16];
                padded[..4].copy_from_slice(&addr);
                self.routes_by_peer
                    .entry(peer_id)
                    .or_default()
                    .insert((true, padded, prefix_len));
            }
            IpPrefix::V6 { addr, prefix_len } => {
                self.routes_v6.insert((addr, prefix_len), record);
                self.routes_by_peer
                    .entry(peer_id)
                    .or_default()
                    .insert((false, addr, prefix_len));
            }
        }
    }

    fn remove_mirror(&mut self, prefix: &IpPrefix) -> Option<RouteRecord> {
        self.remove_mirror_direct(prefix)
    }

    fn remove_mirror_direct(&mut self, prefix: &IpPrefix) -> Option<RouteRecord> {
        let (rec, peer_key) = match prefix {
            IpPrefix::V4 { addr, prefix_len } => {
                let rec = self.routes_v4.remove(&(*addr, *prefix_len))?;
                let mut padded = [0u8; 16];
                padded[..4].copy_from_slice(addr);
                (rec, (true, padded, *prefix_len))
            }
            IpPrefix::V6 { addr, prefix_len } => {
                let rec = self.routes_v6.remove(&(*addr, *prefix_len))?;
                (rec, (false, *addr, *prefix_len))
            }
        };
        if let Some(set) = self.routes_by_peer.get_mut(&rec.peer_id) {
            set.remove(&peer_key);
            if set.is_empty() {
                self.routes_by_peer.remove(&rec.peer_id);
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

    // --- Reclaim queue (default-route grace period) ---

    fn enqueue_reclaim(&mut self, rec: RouteRecord) {
        let release_at = Instant::now() + DEFAULT_ROUTE_GRACE;
        match rec.fib_value.kind {
            k if k == crate::fib::types::FIB_KIND_SINGLE => {
                // Single nexthop: reclaim the nexthop IP after grace.
                for ip in rec.nexthop_ips {
                    self.reclaim_queue.push_back(PendingReclaim {
                        release_at,
                        kind: ReclaimKind::Nexthop(ip),
                    });
                }
            }
            k if k == crate::fib::types::FIB_KIND_ECMP => {
                // ECMP: reclaim the group (which cascades to its NHs
                // when refcount hits zero) plus the explicit NH IPs.
                self.reclaim_queue.push_back(PendingReclaim {
                    release_at,
                    kind: ReclaimKind::Ecmp(rec.fib_value.idx),
                });
                for ip in rec.nexthop_ips {
                    self.reclaim_queue.push_back(PendingReclaim {
                        release_at,
                        kind: ReclaimKind::Nexthop(ip),
                    });
                }
            }
            _ => {}
        }
    }

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

    /// Release the resources a RouteRecord refs: for non-default
    /// prefixes, unwind immediately; for default routes, enqueue
    /// a grace-delayed reclaim. Called from del_route +
    /// drop_routes_for_peer.
    fn release_route_record(&mut self, rec: RouteRecord) {
        // For default-route replaces we route through enqueue_reclaim
        // at the call site (add_route path). For straight deletes we
        // can free immediately because the BPF LPM entry is already
        // gone and no new lookup can land on these IDs.
        match rec.fib_value.kind {
            k if k == crate::fib::types::FIB_KIND_ECMP => {
                self.free_ecmp_group(rec.fib_value.idx);
            }
            _ => {}
        }
        for ip in rec.nexthop_ips {
            let _ = self.unregister(ip);
        }
    }
}
