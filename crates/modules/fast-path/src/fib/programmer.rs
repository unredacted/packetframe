//! FibProgrammer — owns the `NEXTHOPS` seqlock write path and the
//! userspace-side IP-to-NexthopId mapping.
//!
//! **Phase 2 scope: neighbor side only.** The programmer registers
//! nexthop IPs (via [`FibProgrammerHandle::register_nexthop`]),
//! allocates `NexthopId`s with refcount + free-list recycling, and
//! writes `NEXTHOPS[id]` under the seqlock discipline whenever a
//! [`NeighEvent`] arrives. Route ingestion (FIB_V4 / FIB_V6 writes,
//! ECMP group dedup, PeerUp/PeerDown, Resync / InitiationComplete)
//! lands in Phase 3 when the BMP station joins.
//!
//! Lifecycle:
//!   1. [`FibProgrammer::open`] opens `NEXTHOPS` from the bpffs pin
//!      (independent kernel-map reference from the loader's `Ebpf`
//!      instance; both point at the same kernel object).
//!   2. [`FibProgrammer::new`] constructs the programmer with the
//!      NeighEvent input channel and returns a
//!      [`FibProgrammerHandle`] for out-of-band commands.
//!   3. [`FibProgrammer::run`] is the async task: `select!`s over
//!      NeighEvents, Commands, and shutdown.
//!
//! All state lives inside the run task — no mutex on the hot path.
//! Commands are serialized through a command mpsc; replies travel
//! back via oneshot channels.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use aya::maps::{Array, Map, MapData};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use packetframe_common::fib::NeighEvent;

use crate::fib::types::{NexthopEntry, NH_FAMILY_V4, NH_FAMILY_V6, NH_STATE_FAILED,
    NH_STATE_INCOMPLETE, NH_STATE_RESOLVED};
use crate::pin;

/// Command queue capacity. Commands are rare (one per route add/del
/// in Phase 3; test harness in Phase 2); 256 is generous.
const COMMAND_CAPACITY: usize = 256;

/// Capped by `NEXTHOPS_MAX_ENTRIES` in bpf/src/maps.rs. Keep in sync
/// if either side changes.
pub const NEXTHOPS_CAP: u32 = 8_192;

/// `NexthopId` is an index into the `NEXTHOPS` BPF array. Stable
/// once assigned (via refcount/free-list recycling) so FIB_V4 / FIB_V6
/// LPM trie values can reference it without cascading updates on
/// neighbor changes.
pub type NexthopId = u32;

/// Errors surfaced through the programmer's command replies.
#[derive(Debug, thiserror::Error)]
pub enum ProgrammerError {
    #[error("nexthop table full (cap {0}); cannot allocate")]
    Full(u32),
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
    pub fn register_nexthop_blocking(
        &self,
        ip: IpAddr,
    ) -> Result<NexthopId, ProgrammerError> {
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

pub struct FibProgrammer {
    nexthops: Array<MapData, NexthopEntry>,
    events_rx: mpsc::Receiver<NeighEvent>,
    cmd_rx: mpsc::Receiver<Command>,
    shutdown: CancellationToken,

    // State owned by the run task — no locking needed.
    by_ip: HashMap<IpAddr, NexthopRecord>,
    /// Reverse index: NexthopId → IpAddr. Rebuild-able by walking
    /// `by_ip`; held separately so NeighEvent → NexthopId lookup is
    /// O(1) instead of scanning every record.
    by_id: HashMap<NexthopId, IpAddr>,
    /// Latest seq value written per ID. Seqlock discipline requires
    /// each write to go odd-then-even from the current value.
    seq_by_id: HashMap<NexthopId, u32>,
    free_ids: Vec<NexthopId>,
    next_id: NexthopId,
}

impl FibProgrammer {
    /// Open the `NEXTHOPS` map from the bpffs pin and return a
    /// typed `Array` handle. Must be called after the loader has
    /// attached and pinned the map.
    pub fn open_nexthops(bpffs_root: &Path) -> Result<Array<MapData, NexthopEntry>, ProgrammerError> {
        let pin_path = pin::map_path(bpffs_root, "NEXTHOPS");
        let map_data = MapData::from_pin(&pin_path)
            .map_err(|e| ProgrammerError::MapOpen(format!("NEXTHOPS pin open: {e}")))?;
        let map = Map::Array(map_data);
        Array::try_from(map)
            .map_err(|e| ProgrammerError::MapOpen(format!("Array::try_from(NEXTHOPS): {e}")))
    }

    /// Construct the programmer. `events_rx` is the receiver half of
    /// the channel the `NetlinkNeighborResolver` writes into; the
    /// returned handle is what the route ingestion layer (Phase 3)
    /// or a test harness (Phase 2) uses to register nexthop IPs.
    pub fn new(
        nexthops: Array<MapData, NexthopEntry>,
        events_rx: mpsc::Receiver<NeighEvent>,
        shutdown: CancellationToken,
    ) -> (Self, FibProgrammerHandle) {
        let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_CAPACITY);
        (
            Self {
                nexthops,
                events_rx,
                cmd_rx,
                shutdown,
                by_ip: HashMap::new(),
                by_id: HashMap::new(),
                seq_by_id: HashMap::new(),
                free_ids: Vec::new(),
                next_id: 0,
            },
            FibProgrammerHandle { tx: cmd_tx },
        )
    }

    /// Main event loop. Drains NeighEvents + Commands until shutdown.
    pub async fn run(mut self) {
        info!("FibProgrammer running");
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
                            // Resolver closed its sender; no more neigh
                            // events will arrive. Continue to drain
                            // commands until shutdown.
                            debug!("NeighEvent channel closed");
                        }
                    }
                }
                cmd = self.cmd_rx.recv() => {
                    match cmd {
                        Some(c) => self.on_command(c),
                        None => {
                            // All handle clones dropped. Nothing will
                            // issue new commands. Continue to drain
                            // events until shutdown.
                            debug!("Command channel closed");
                        }
                    }
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
                mac, ifindex, ..
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
                    // src_mac unresolved in Phase 2 — we don't yet
                    // query the egress iface's MAC via netlink. Phase 3
                    // fills this in alongside BMP peer tracking; for
                    // Phase 2 tests the src MAC stays zero, which is
                    // fine because the XDP program just writes
                    // whatever it finds and the test harness observes
                    // the dst MAC. Flagged for follow-up.
                    src_mac: [0; 6],
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
}
