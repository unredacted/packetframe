//! Keeps the redirect-target maps, and the VLAN resolution they depend
//! on, in step with the kernel's link table for the life of the attach.
//!
//! `REDIRECT_DEVMAP` (XDP) and `TC_REDIRECT_TARGETS` (tc) are the
//! datapath's pre-check that a FIB-resolved egress is a device it may
//! redirect to (SPEC.md §4.4 step 9d). Both were filled once at attach
//! from `/sys/class/net` and again only on SIGHUP. Any Ethernet link
//! that appeared in between — the platform re-creates bridges and VLAN
//! sub-interfaces on every provisioning pass, with new ifindexes — was
//! not a valid target, so every packet the FIB resolved to it took
//! XDP_PASS into the kernel path and counted `pass_not_in_devmap`. On
//! 2026-09-15 that was 5 % of the primary's traffic over the old
//! daemon's life.
//!
//! `VLAN_RESOLVE` is the other half of the same fact: a recreated
//! sub-interface or bridge admitted as a redirect target *without* its
//! translation to physical port + VID would be redirected to the
//! virtual device itself — which is a slower path under generic XDP
//! and a dropped frame under native (no `ndo_xdp_xmit`). So the
//! translation is written first and the target admitted after.
//!
//! This watcher subscribes to `RTNLGRP_LINK` on its own thread. Link
//! events are debounced for a quarter second (provisioning re-creates
//! dozens of links in a burst) into one *topology refresh*: recompute
//! the desired `VLAN_RESOLVE` from the same rule the SIGHUP reconcile
//! uses, apply the diff, set the `VLAN_PRESENT` gate, and only then
//! admit the redirect targets that came up. Deletions leave the
//! redirect maps immediately. One refresh runs right after the
//! subscription is live so nothing slips between the attach-time fill
//! and the first event. Everything is opened from the bpffs pins like
//! the rest of the control plane, and it runs in every forwarding mode:
//! the pre-check is the same under kernel-fib and packetframe-fib.
//!
//! The same refresh keeps `RX_MACS` — the destination MACs each
//! attached port receives on — in step with the link table: a bridge
//! takes a new MAC when its lowest-addressed member changes, and a VLAN
//! device follows its lower's, and each arrives as an `RTM_NEWLINK`.
//! Written through `linux_impl::sync_rx_macs`, the one writer attach
//! and the SIGHUP reconcile use too.
//!
//! Membership policy is the one the SIGHUP reconcile already applies:
//! an Ethernet link becomes a target when the kernel reports it oper-up
//! (or `unknown`, which virtual devices report for lack of carrier
//! detection) and stays one until the kernel deletes it. Going
//! oper-down does not remove it — the kernel refuses a redirect to a
//! down device and the frame is counted, which is the conservative
//! failure and identical to what the attach-time fill would have left.
//!
//! Link notifications the kernel drops on a full receive buffer
//! (reported once, as an overrun) are never resent, so an overrun
//! re-reads the link table instead: every link that qualifies is queued
//! for admission exactly as its `RTM_NEWLINK` would have been, and every
//! ifindex the maps hold that the kernel no longer knows is evicted.
//!
//! The maps hold 64 links each. A link a map refuses with `E2BIG` (it
//! is full) is warned about once and offered again only when an
//! eviction makes room: no timer can fix a full map. An insert that
//! fails any other way (the devmap allocates atomically and can return
//! a transient `ENOMEM`) is retried every few seconds instead. Both are
//! reported on every refresh, apart from any overrun. The watcher's
//! state — running or stopped, overruns, re-reads, links left out and
//! why — is the `redirect-watch` status row ([`WatchStatus`]).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use aya::maps::{xdp::DevMapHash, Array, HashMap as AyaHashMap, Map, MapData};
use futures::{StreamExt, TryStreamExt};
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::link::{LinkAttribute, LinkLayerType, LinkMessage, State};
use netlink_packet_route::RouteNetlinkMessage;
use packetframe_common::config::ModuleDirective;
use rtnetlink::sys::AsyncSocket;
use rtnetlink::{new_multicast_connection, MulticastGroup};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::linux_impl::{
    enumerate_redirect_targets, set_cfg_flag_in, sync_rx_macs, FpCfg, RxMacKey, VlanResolve,
    FP_CFG_FLAG_VLAN_PRESENT,
};
use crate::netlink_bounds::{raise_rcvbuf, NETLINK_EXCHANGE_TIMEOUT};
use crate::pin;
use crate::reconcile::{apply_vlan_resolve, desired_vlan_resolve, ifindex_exists};
pub use crate::redirect_watch_status::WatchStatus;

/// How long after the last link event the topology refresh runs.
/// Long enough to fold a provisioning burst into one pass, short
/// enough that a single new link is forwarding within the time its
/// neighbours resolve.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// What the subscription asks for as its receive buffer. A provisioning
/// pass re-creates dozens of bridges and VLAN devices, each announced by
/// several `RTM_NEWLINK`s of a few KiB, while the softirq load around it
/// can keep this thread from draining; the default (about 200 KiB) holds
/// a few dozen. This holds hundreds more. It makes an overrun rarer;
/// the re-read is what makes one harmless.
const LINK_RCVBUF: usize = 2 << 20;

/// The least time between two failed link-table re-reads, so a dump that
/// keeps failing is retried rather than hammered every debounce.
const RESYNC_RETRY: Duration = Duration::from_secs(5);

/// Handle on the running watcher. Owned by `ActiveState`; `detach`
/// calls [`shutdown`](Self::shutdown) before it removes the pins the
/// watcher's map handles were opened from.
pub struct RedirectTargetWatcher {
    shutdown: CancellationToken,
    thread: Option<JoinHandle<()>>,
    directives: Arc<Mutex<Vec<ModuleDirective>>>,
    /// Wakes the watcher for a refresh that no link event caused: a
    /// SIGHUP handed over new directives.
    refresh_now: Arc<tokio::sync::Notify>,
    /// Written by the watcher thread, read by the status row.
    status: Arc<Mutex<WatchStatus>>,
    /// Test hook, see [`Self::stall_reader`].
    stall: tokio::sync::mpsc::UnboundedSender<Stall>,
}

/// How long to block the watcher's thread, and where to say it has begun.
type Stall = (Duration, std::sync::mpsc::SyncSender<()>);

impl RedirectTargetWatcher {
    /// Spawn the watcher thread. `directives` are the module's, for
    /// the `bridge-resolve` rule the VLAN derivation consults; a SIGHUP
    /// that changes them hands the new set over via
    /// [`set_directives`](Self::set_directives). `rx_ports` are the
    /// XDP-attached `(iface, ifindex)` pairs whose `RX_MACS` entries the
    /// refresh keeps current; fixed for the life of the attach, since a
    /// SIGHUP never changes the attach set.
    ///
    /// `Err` only when the thread itself cannot be created. A netlink
    /// or map failure *inside* the thread is logged and ends it: attach
    /// stays up and the SIGHUP reconcile remains the fallback refresh,
    /// exactly as before this existed, and the `redirect-watch` status
    /// row says so ([`Self::status`]).
    pub fn start(
        bpffs_root: &Path,
        directives: Vec<ModuleDirective>,
        rx_ports: Vec<(String, u32)>,
    ) -> std::io::Result<Self> {
        Self::start_with_rcvbuf(bpffs_root, directives, rx_ports, LINK_RCVBUF)
    }

    /// [`Self::start`] with the subscription's receive buffer chosen by
    /// the caller. For tests, which shrink it to force an overrun on
    /// demand.
    #[doc(hidden)]
    pub fn start_with_rcvbuf(
        bpffs_root: &Path,
        directives: Vec<ModuleDirective>,
        rx_ports: Vec<(String, u32)>,
        rcvbuf: usize,
    ) -> std::io::Result<Self> {
        let shutdown = CancellationToken::new();
        let token = shutdown.clone();
        let root = bpffs_root.to_path_buf();
        let directives = Arc::new(Mutex::new(directives));
        let shared = Arc::clone(&directives);
        let refresh_now = Arc::new(tokio::sync::Notify::new());
        let wake = Arc::clone(&refresh_now);
        let status = Arc::new(Mutex::new(WatchStatus::default()));
        let theirs = Arc::clone(&status);
        let (stall, stalls) = tokio::sync::mpsc::unbounded_channel();
        let thread = std::thread::Builder::new()
            .name("pf-redirect-watch".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        stopped(&theirs, format!("runtime build failed: {e}"));
                        return;
                    }
                };
                rt.block_on(run(
                    root, token, shared, wake, rx_ports, rcvbuf, theirs, stalls,
                ));
            })?;
        Ok(Self {
            shutdown,
            thread: Some(thread),
            directives,
            refresh_now,
            status,
            stall,
        })
    }

    /// Test hook: block the watcher's thread for `d`, returning once the
    /// block has begun. The thread also drives the subscription's socket,
    /// so nothing reads it meanwhile, and link changes made inside the
    /// window overrun a shrunk buffer deterministically. Panics if the
    /// watcher is not running.
    #[doc(hidden)]
    pub fn stall_reader(&self, d: Duration) {
        let (began, wait) = std::sync::mpsc::sync_channel(1);
        self.stall
            .send((d, began))
            .expect("the watcher is not running");
        wait.recv_timeout(Duration::from_secs(10))
            .expect("the watcher did not take the stall");
    }

    /// A watcher whose thread could not be spawned. Nothing follows the
    /// link table, and holding this instead of nothing keeps the status
    /// row saying so rather than going silent.
    pub fn not_started(why: String) -> Self {
        Self {
            shutdown: CancellationToken::new(),
            thread: None,
            directives: Arc::new(Mutex::new(Vec::new())),
            refresh_now: Arc::new(tokio::sync::Notify::new()),
            status: Arc::new(Mutex::new(WatchStatus {
                stopped: Some(why),
                ..WatchStatus::default()
            })),
            stall: tokio::sync::mpsc::unbounded_channel().0,
        }
    }

    /// The `redirect-watch` status: the thread's own account, or — when
    /// the thread has ended without giving one, which only a panic does
    /// (it otherwise ends only when [`Self::shutdown`] consumes this
    /// handle) — that it exited.
    pub fn status(&self) -> WatchStatus {
        let mut s = self
            .status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let exited = self.thread.as_ref().is_some_and(JoinHandle::is_finished);
        if exited && s.stopped.is_none() {
            s.stopped = Some("the watcher thread exited unexpectedly".into());
        }
        s
    }

    /// Replace the directives the topology refresh derives
    /// `VLAN_RESOLVE` from, and schedule a refresh with them. Called by
    /// the SIGHUP reconcile after it has applied the same directives
    /// itself. The scheduled refresh is what makes the hand-over
    /// converge: a refresh already running on the watcher thread may
    /// have cloned the OLD directives and will finish after the
    /// reload, writing the old bridge mapping back; the refresh queued
    /// here runs after it, with the new ones, and undoes that (review
    /// finding). `Notify` stores the wake-up if the watcher is not
    /// waiting yet, so it cannot be lost.
    pub fn set_directives(&self, directives: Vec<ModuleDirective>) {
        if let Ok(mut d) = self.directives.lock() {
            *d = directives;
        }
        self.refresh_now.notify_one();
    }

    /// Stop the thread and wait for it. The map handles it holds are
    /// closed on return, so the caller may remove the pins afterwards.
    pub fn shutdown(mut self) {
        self.shutdown.cancel();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for RedirectTargetWatcher {
    fn drop(&mut self) {
        // A drop without `shutdown` (error unwinding in attach) must
        // not leave the thread running against pins that are about to
        // vanish. Cancel and let it exit on its own; joining inside
        // Drop would block whichever path dropped us.
        self.shutdown.cancel();
    }
}

/// The maps the watcher writes plus what it believes each holds.
///
/// Membership is tracked **per map**: a failed insert into one must
/// not mark the ifindex done for the other, or the failed side would
/// never be retried (every later `RTM_NEWLINK` would short-circuit on
/// the shared set) and the tc datapath would leak `pass_not_in_devmap`
/// until a SIGHUP (review finding).
struct Targets {
    devmap: DevMapHash<MapData>,
    tc: AyaHashMap<MapData, u32, u32>,
    vlan: AyaHashMap<MapData, u32, VlanResolve>,
    cfg: Array<MapData, FpCfg>,
    in_devmap: HashSet<u32>,
    in_tc: HashSet<u32>,
    rx: AyaHashMap<MapData, RxMacKey, u8>,
    rx_ports: Vec<(String, u32)>,
    /// Ports whose receive MACs the last refresh could not read.
    rx_unknown: HashSet<u32>,
    /// Links a redirect map refused with `E2BIG`: it is full (64 links
    /// each). No retry can fix that, so each is warned about once and
    /// offered again only when an eviction makes room.
    full: HashSet<u32>,
    /// Links whose insert failed any other way, with the errno (0 when
    /// none could be read): `REDIRECT_DEVMAP` allocates its entries
    /// atomically and can fail with a transient `ENOMEM`. These may pass
    /// on their own, so they are retried on [`RESYNC_RETRY`]'s pace, and
    /// warned about when first seen or when the errno changes.
    failing: std::collections::HashMap<u32, i32>,
}

/// Why one insert into a redirect map failed, as far as what to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InsertFailure {
    /// `E2BIG`: the map is full. Only room made by an eviction helps.
    Full,
    /// Anything else, with its errno when there is one: retried.
    Failing(Option<i32>),
}

impl InsertFailure {
    fn of(e: &(dyn std::error::Error + 'static)) -> Self {
        // aya's map errors are transparent down to the syscall's
        // `io::Error`, so the errno is found by walking the sources.
        let mut cur = Some(e);
        let mut errno = None;
        while let Some(err) = cur {
            if let Some(io) = err.downcast_ref::<std::io::Error>() {
                errno = io.raw_os_error();
                break;
            }
            cur = err.source();
        }
        match errno {
            Some(libc::E2BIG) => Self::Full,
            other => Self::Failing(other),
        }
    }
}

impl Targets {
    fn open(root: &Path, rx_ports: Vec<(String, u32)>) -> Result<Self, String> {
        let dm = MapData::from_pin(pin::map_path(root, "REDIRECT_DEVMAP"))
            .map_err(|e| format!("REDIRECT_DEVMAP pin open: {e}"))?;
        let devmap = DevMapHash::try_from(Map::DevMapHash(dm))
            .map_err(|e| format!("REDIRECT_DEVMAP try_from: {e}"))?;
        let tm = MapData::from_pin(pin::map_path(root, "TC_REDIRECT_TARGETS"))
            .map_err(|e| format!("TC_REDIRECT_TARGETS pin open: {e}"))?;
        let tc = AyaHashMap::try_from(Map::HashMap(tm))
            .map_err(|e| format!("TC_REDIRECT_TARGETS try_from: {e}"))?;
        let vm = MapData::from_pin(pin::map_path(root, "VLAN_RESOLVE"))
            .map_err(|e| format!("VLAN_RESOLVE pin open: {e}"))?;
        let vlan = AyaHashMap::try_from(Map::HashMap(vm))
            .map_err(|e| format!("VLAN_RESOLVE try_from: {e}"))?;
        let cm = MapData::from_pin(pin::map_path(root, "CFG"))
            .map_err(|e| format!("CFG pin open: {e}"))?;
        let cfg = Array::try_from(Map::Array(cm)).map_err(|e| format!("CFG try_from: {e}"))?;
        let rm = MapData::from_pin(pin::map_path(root, "RX_MACS"))
            .map_err(|e| format!("RX_MACS pin open: {e}"))?;
        let rx =
            AyaHashMap::try_from(Map::HashMap(rm)).map_err(|e| format!("RX_MACS try_from: {e}"))?;
        // Seed membership from what attach (or a previous SIGHUP) put
        // in each map.
        let in_devmap = devmap.keys().filter_map(Result::ok).collect();
        let in_tc = tc.keys().filter_map(Result::ok).collect();
        Ok(Self {
            devmap,
            tc,
            vlan,
            cfg,
            in_devmap,
            in_tc,
            rx,
            rx_ports,
            rx_unknown: HashSet::new(),
            full: HashSet::new(),
            failing: std::collections::HashMap::new(),
        })
    }

    /// Bring `RX_MACS` to what the attached ports receive on now.
    /// Independent of the VLAN refresh: a topology read failure there
    /// must not hold back a MAC change here.
    ///
    /// Returns whether to retry: some port that still exists could not
    /// be read. The event that announced its change has been consumed,
    /// and another may never come, so the caller re-arms the debounce
    /// exactly as it does for a failed VLAN read. A port whose ifindex is
    /// gone is not retried (its XDP link went with it). Each unknown port
    /// is warned about once, and its recovery logged.
    fn refresh_rx_macs(&mut self) -> bool {
        let sync = sync_rx_macs(&mut self.rx, &self.rx_ports, &self.rx_unknown);
        if sync.added > 0 || sync.removed > 0 {
            info!(
                added = sync.added,
                removed = sync.removed,
                "RX_MACS refreshed from link events"
            );
        }
        let now: HashSet<u32> = sync.unknown.iter().map(|(_, i)| *i).collect();
        for (iface, ifindex) in &self.rx_ports {
            if self.rx_unknown.contains(ifindex) && !now.contains(ifindex) {
                info!(iface = %iface, ifindex, "receive MACs readable again; RX_MACS current");
            }
        }
        self.rx_unknown = now;
        self.rx_unknown.iter().any(|i| ifindex_exists(*i))
    }

    fn admit(&mut self, ifindex: u32, why: &'static str) {
        let mut changed = false;
        let mut failures: Vec<(&str, InsertFailure, String)> = Vec::new();
        if !self.in_devmap.contains(&ifindex) {
            match self.devmap.insert(ifindex, ifindex, None, 0) {
                Ok(()) => {
                    self.in_devmap.insert(ifindex);
                    changed = true;
                }
                Err(e) => failures.push(("REDIRECT_DEVMAP", InsertFailure::of(&e), e.to_string())),
            }
        }
        if !self.in_tc.contains(&ifindex) {
            match self.tc.insert(ifindex, ifindex, 0) {
                Ok(()) => {
                    self.in_tc.insert(ifindex);
                    changed = true;
                }
                Err(e) => {
                    failures.push(("TC_REDIRECT_TARGETS", InsertFailure::of(&e), e.to_string()))
                }
            }
        }
        if changed {
            info!(ifindex, why, "redirect target added");
        }
        let errors = || {
            failures
                .iter()
                .map(|(map, _, e)| format!("{map}: {e}"))
                .collect::<Vec<_>>()
                .join("; ")
        };
        // A failure that might pass wins over a full map: it is retried,
        // and a retry that then meets only E2BIG moves it to `full`.
        let failing = failures.iter().find_map(|(_, f, _)| match f {
            InsertFailure::Failing(errno) => Some(errno.unwrap_or(0)),
            InsertFailure::Full => None,
        });
        if let Some(errno) = failing {
            self.full.remove(&ifindex);
            if self.failing.insert(ifindex, errno) != Some(errno) {
                warn!(
                    ifindex,
                    errno,
                    errors = %errors(),
                    "redirect target insert failed; retried every {}s, its traffic on the \
                     kernel path meanwhile",
                    RESYNC_RETRY.as_secs()
                );
            } else {
                debug!(ifindex, errno, errors = %errors(), "redirect target insert still failing");
            }
        } else if !failures.is_empty() {
            self.failing.remove(&ifindex);
            if self.full.insert(ifindex) {
                warn!(
                    ifindex,
                    errors = %errors(),
                    "redirect target refused: the maps are full (64 links each); its traffic \
                     takes the kernel path until an eviction makes room"
                );
            } else {
                debug!(ifindex, errors = %errors(), "redirect target still refused, maps full");
            }
        } else {
            self.full.remove(&ifindex);
            self.failing.remove(&ifindex);
        }
    }

    /// Room was made in the maps: offer every link a full map refused.
    fn offer_full(&self, pending: &mut Pending) {
        if self.full.is_empty() {
            return;
        }
        for &ifindex in &self.full {
            if !pending.admit.contains(&ifindex) {
                pending.admit.push(ifindex);
            }
        }
        pending.touch();
    }

    /// Queue the links whose insert failed other than on a full map for
    /// another attempt, on the failed re-read's pace.
    fn retry_failing(&self, pending: &mut Pending) {
        if self.failing.is_empty() {
            return;
        }
        for &ifindex in self.failing.keys() {
            if !pending.admit.contains(&ifindex) {
                pending.admit.push(ifindex);
            }
        }
        pending.due_by(Instant::now() + RESYNC_RETRY);
    }

    /// Forget unadmitted links the kernel no longer knows.
    fn prune_unadmitted(&mut self) {
        self.full.retain(|i| ifindex_exists(*i));
        self.failing.retain(|i, _| ifindex_exists(*i));
    }

    /// Returns whether anything left either map, which makes room.
    fn evict(&mut self, ifindex: u32, why: &'static str) -> bool {
        self.full.remove(&ifindex);
        self.failing.remove(&ifindex);
        let mut changed = false;
        if self.in_devmap.remove(&ifindex) {
            changed = true;
            if let Err(e) = self.devmap.remove(ifindex) {
                warn!(ifindex, error = %e, "REDIRECT_DEVMAP remove failed");
            }
        }
        if self.in_tc.remove(&ifindex) {
            changed = true;
            if let Err(e) = self.tc.remove(&ifindex) {
                warn!(ifindex, error = %e, "TC_REDIRECT_TARGETS remove failed");
            }
        }
        if changed {
            info!(ifindex, why, "redirect target removed");
        }
        changed
    }

    /// Bring `VLAN_RESOLVE` and its gate bit to what the topology says
    /// right now. `Err` means the topology could not be read; nothing
    /// was written and the caller must hold off admitting targets.
    /// `Ok` carries the ifindexes whose translation is REQUIRED but not
    /// in the map after this pass (insert failed, map full): admitting
    /// one of those would redirect to the untranslated virtual device,
    /// which is what this ordering exists to prevent, so the caller
    /// holds them too.
    fn refresh_vlan(&mut self, directives: &[ModuleDirective]) -> Result<HashSet<u32>, String> {
        let want = desired_vlan_resolve(directives).map_err(|e| e.to_string())?;
        let (delta, untranslated) = apply_vlan_resolve(&mut self.vlan, &want);
        let present = !(want.subifs.is_empty() && want.bridges.is_empty());
        // Serialized against the SIGHUP path's CFG writes by
        // `CFG_WRITE_LOCK` inside `set_cfg_flag_in`.
        if let Err(e) = set_cfg_flag_in(&mut self.cfg, FP_CFG_FLAG_VLAN_PRESENT, present) {
            warn!(error = %e, "VLAN_PRESENT gate write failed");
        }
        if delta.added > 0 || delta.removed > 0 {
            info!(
                added = delta.added,
                removed = delta.removed,
                present,
                "VLAN_RESOLVE refreshed from link events"
            );
        }
        Ok(untranslated)
    }

    /// Start-up pass: what `/sys/class/net` says versus what the maps
    /// hold — add what came up since the attach-time fill, purge what
    /// the kernel no longer knows. Same two rules as the SIGHUP
    /// reconcile.
    fn reconcile_targets(&mut self) {
        let desired: HashSet<u32> = enumerate_redirect_targets()
            .into_iter()
            .map(|(_, ifindex)| ifindex)
            .collect();
        let known: HashSet<u32> = self.in_devmap.union(&self.in_tc).copied().collect();
        let stale: Vec<u32> = known
            .difference(&desired)
            .copied()
            .filter(|i| !ifindex_exists(*i))
            .collect();
        // Stale first, so what they held is room for the admits.
        for ifindex in stale {
            self.evict(ifindex, "gone before watcher start");
        }
        // Every desired ifindex goes through `admit`, whose per-map
        // checks fill whichever side is missing: an interface attach
        // put in one map but failed to insert into the other is still
        // repaired here, where a `missing = desired − known` diff would
        // have skipped it (review finding). Already-complete entries
        // cost two set lookups and no syscall.
        let mut desired_sorted: Vec<u32> = desired.into_iter().collect();
        desired_sorted.sort_unstable();
        for ifindex in desired_sorted {
            self.admit(ifindex, "present at watcher start");
        }
    }
}

/// The filter `enumerate_redirect_targets` applies to `/sys/class/net`,
/// applied to one `RTM_NEWLINK` instead: Ethernet-type and oper-up (or
/// `unknown`). Returns the ifindex when the link qualifies.
pub fn viable_target(link: &LinkMessage) -> Option<u32> {
    if link.header.link_layer_type != LinkLayerType::Ether {
        return None;
    }
    let oper = link.attributes.iter().find_map(|a| match a {
        LinkAttribute::OperState(s) => Some(s),
        _ => None,
    });
    match oper {
        Some(State::Up | State::Unknown) => Some(link.header.index),
        _ => None,
    }
}

/// Everything the debounced refresh needs to know about the events
/// since the last one.
#[derive(Default)]
struct Pending {
    /// Links that qualified as redirect targets, admitted only after
    /// `VLAN_RESOLVE` has been refreshed for them.
    admit: Vec<u32>,
    /// When the refresh is due; `None` when nothing changed.
    due: Option<Instant>,
    /// Link notifications were lost: the refresh re-reads the link table
    /// first.
    resync: bool,
    /// A failed re-read is not retried before this.
    resync_not_before: Option<Instant>,
    /// A re-read has completed but the refresh that applies it — the
    /// admissions it queued, after `VLAN_RESOLVE` — has not yet got past
    /// the topology read. Reading the table is half of a recovery;
    /// attempting what it found is the other half. Whether an attempted
    /// admission landed is a separate fact ([`Targets::full`],
    /// [`Targets::failing`]), tracked whatever the overrun history.
    recovering: bool,
}

impl Pending {
    fn touch(&mut self) {
        self.due = Some(Instant::now() + DEBOUNCE);
    }

    /// The kernel reported lost notifications. Debounced like any event,
    /// so a burst of overruns costs one re-read.
    fn overrun(&mut self) {
        self.resync = true;
        self.touch();
    }

    fn resync_due(&self, now: Instant) -> bool {
        self.resync && self.resync_not_before.is_none_or(|t| now >= t)
    }

    /// Make sure the refresh comes round again by `at`.
    fn due_by(&mut self, at: Instant) {
        self.due = Some(self.due.map_or(at, |d| d.min(at)));
    }
}

/// What a link-table re-read changes: the links to queue for admission
/// (each qualifying link, as its `RTM_NEWLINK` would have queued it) and
/// the ifindexes the maps hold that the dump does not (each a lost
/// `RTM_DELLINK`, evicted once the kernel confirms the ifindex is gone).
#[derive(Debug, Default, PartialEq, Eq)]
struct ResyncPlan {
    admit: Vec<u32>,
    gone: Vec<u32>,
}

fn resync_plan(links: &[LinkMessage], known: &HashSet<u32>) -> ResyncPlan {
    let mut admit: Vec<u32> = links.iter().filter_map(viable_target).collect();
    admit.sort_unstable();
    let present: HashSet<u32> = links.iter().map(|l| l.header.index).collect();
    let mut gone: Vec<u32> = known.difference(&present).copied().collect();
    gone.sort_unstable();
    ResyncPlan { admit, gone }
}

/// One `RTM_GETLINK` dump on a fresh connection, bounded. Abandoning a
/// timed-out dump drops the connection with it, so nothing is left
/// waiting on a reply that will not come.
async fn dump_links() -> Result<Vec<LinkMessage>, String> {
    let (conn, handle, _) =
        rtnetlink::new_connection().map_err(|e| format!("netlink connection: {e}"))?;
    tokio::spawn(conn);
    let dump = handle.link().get().execute().try_collect::<Vec<_>>();
    match tokio::time::timeout(NETLINK_EXCHANGE_TIMEOUT, dump).await {
        Ok(r) => r.map_err(|e| format!("link dump: {e}")),
        Err(_) => Err(format!(
            "link dump: no reply within {}s",
            NETLINK_EXCHANGE_TIMEOUT.as_secs()
        )),
    }
}

/// Re-read the link table after lost notifications (see the module
/// docs). Returns how many links qualify (each queued; admission skips
/// what is already in) and how many were evicted.
async fn resync(targets: &mut Targets, pending: &mut Pending) -> Result<(usize, usize), String> {
    let links = dump_links().await?;
    let known: HashSet<u32> = targets.in_devmap.union(&targets.in_tc).copied().collect();
    let plan = resync_plan(&links, &known);
    for &ifindex in &plan.admit {
        if !pending.admit.contains(&ifindex) {
            pending.admit.push(ifindex);
        }
    }
    let mut evicted = 0;
    for ifindex in plan.gone {
        // A link created after the dump is not in it; only an ifindex
        // the kernel no longer knows is a lost delete.
        if !ifindex_exists(ifindex) {
            pending.admit.retain(|i| *i != ifindex);
            if targets.evict(ifindex, "absent from the link re-read") {
                evicted += 1;
            }
        }
    }
    if evicted > 0 {
        targets.offer_full(pending);
    }
    Ok((plan.admit.len(), evicted))
}

/// The kernel dropped link notifications on the full buffer (netlink-
/// proto's rendering of ENOBUFS). None is resent, so the link table is
/// re-read at the next refresh.
fn on_overrun(pending: &mut Pending, status: &Mutex<WatchStatus>) {
    pending.overrun();
    let mut s = status.lock().unwrap_or_else(PoisonError::into_inner);
    s.overruns += 1;
    if !std::mem::replace(&mut s.resync_pending, true) {
        warn!(
            "redirect-target watcher: link notifications lost (receive buffer overrun); \
             re-reading the link table"
        );
    }
}

async fn run_resync(targets: &mut Targets, pending: &mut Pending, status: &Mutex<WatchStatus>) {
    // This re-read covers every loss reported until now. One reported
    // from here on arrives as another overrun, after it, and is owed a
    // re-read of its own.
    pending.resync = false;
    let result = resync(targets, pending).await;
    let mut s = status.lock().unwrap_or_else(PoisonError::into_inner);
    match result {
        Ok((viable, evicted)) => {
            pending.resync_not_before = None;
            info!(
                viable,
                evicted, "redirect-target watcher: link table re-read after lost notifications"
            );
            // Counted as a recovery once the refresh that follows has
            // attempted what it queued ([`settle_recovery`]).
            pending.recovering = true;
        }
        Err(e) => {
            s.resyncs_failed += 1;
            warn!(error = %e, "redirect-target watcher: link table re-read failed; retrying");
            s.last_resync_error = Some(e);
            pending.resync = true;
            pending.resync_not_before = Some(Instant::now() + RESYNC_RETRY);
        }
    }
    s.resync_pending = pending.resync || pending.recovering;
}

/// After a refresh: a completed re-read is a completed recovery once the
/// refresh got past the topology read, i.e. attempted every admission
/// the re-read queued. One whose insert failed is not a recovery failure
/// — its notification would have met the same insert — and is reported
/// as such on every refresh ([`publish_unadmitted`]). A topology read that
/// failed is: the refresh retries it within a quarter second, and the
/// row says why until then.
fn settle_recovery(
    pending: &mut Pending,
    refreshed: &Result<(), String>,
    status: &Mutex<WatchStatus>,
) {
    if !pending.recovering {
        return;
    }
    let mut s = status.lock().unwrap_or_else(PoisonError::into_inner);
    match refreshed {
        Ok(()) => {
            pending.recovering = false;
            s.resyncs_ok += 1;
            s.last_resync_error = None;
        }
        Err(e) => {
            s.last_resync_error = Some(format!("the link topology could not be read: {e}"));
        }
    }
    s.resync_pending = pending.resync || pending.recovering;
}

/// The qualifying links not in the maps, as the status row reports them:
/// those a full map refused, apart from those whose insert is failing
/// some other way (and is being retried).
fn publish_unadmitted(targets: &mut Targets, status: &Mutex<WatchStatus>) {
    targets.prune_unadmitted();
    let mut s = status.lock().unwrap_or_else(PoisonError::into_inner);
    s.map_full = targets.full.len() as u64;
    s.insert_failing = targets.failing.len() as u64;
    s.insert_errno = targets.failing.values().copied().max();
}

/// Record why the watcher ended, for the status row, and log it.
fn stopped(status: &Mutex<WatchStatus>, why: String) {
    warn!(
        reason = %why,
        "redirect-target watcher stopped; REDIRECT_DEVMAP refreshes only on SIGHUP"
    );
    status
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .stopped = Some(why);
}

// The thread's whole state arrives here once, from `start_with_rcvbuf`.
#[allow(clippy::too_many_arguments)]
async fn run(
    root: PathBuf,
    shutdown: CancellationToken,
    directives: Arc<Mutex<Vec<ModuleDirective>>>,
    refresh_now: Arc<tokio::sync::Notify>,
    rx_ports: Vec<(String, u32)>,
    rcvbuf: usize,
    status: Arc<Mutex<WatchStatus>>,
    mut stalls: tokio::sync::mpsc::UnboundedReceiver<Stall>,
) {
    // Subscribe BEFORE the reconcile so a link that changes during the
    // reconcile is replayed from the socket buffer afterwards instead
    // of being missed (same ordering argument as the resolver's FDB
    // seed).
    let (mut conn, _handle, mut messages) = match new_multicast_connection(&[MulticastGroup::Link])
    {
        Ok(c) => c,
        Err(e) => {
            stopped(&status, format!("RTNLGRP_LINK subscription failed: {e}"));
            return;
        }
    };
    // Not fatal: the default buffer works, and an overrun is recovered
    // from either way; a bigger one overruns less often.
    match raise_rcvbuf(conn.socket_mut().socket_mut(), rcvbuf) {
        Ok(granted) => debug!(granted, "redirect-target watcher: receive buffer"),
        Err(e) => warn!(error = %e, "redirect-target watcher: could not raise the receive buffer"),
    }
    tokio::spawn(conn);

    let mut targets = match Targets::open(&root, rx_ports) {
        Ok(t) => t,
        Err(e) => {
            stopped(&status, format!("map open failed: {e}"));
            return;
        }
    };
    let mut pending = Pending::default();
    // First refresh right away: the attach-time fill is what the maps
    // hold, and this closes whatever moved between it and now.
    // A topology read failure here re-arms the debounce like any other.
    let _ = refresh(&mut targets, &mut pending, &directives);
    targets.reconcile_targets();
    publish_unadmitted(&mut targets, &status);
    targets.retry_failing(&mut pending);
    info!(
        devmap = targets.in_devmap.len(),
        tc = targets.in_tc.len(),
        "redirect-target watcher live (RTNLGRP_LINK)"
    );

    loop {
        // The debounce arm exists only while something is pending.
        let due = pending.due;
        tokio::select! {
            _ = shutdown.cancelled() => {
                debug!("redirect-target watcher shutdown");
                return;
            }
            next = messages.next() => match next {
                Some((msg, _)) => {
                    if matches!(msg.payload, NetlinkPayload::Overrun(_)) {
                        on_overrun(&mut pending, &status);
                    } else {
                        handle(&mut targets, &mut pending, msg);
                    }
                }
                None => {
                    stopped(&status, "netlink stream closed".into());
                    return;
                }
            },
            _ = async { tokio::time::sleep_until(due.unwrap_or_else(Instant::now)).await }, if due.is_some() => {
                if pending.resync_due(Instant::now()) {
                    // The one await here that can be long (a dump, up to
                    // its 30 s bound): `detach` joins this thread before it
                    // removes the pins, inside its budget.
                    tokio::select! {
                        biased;
                        _ = shutdown.cancelled() => {
                            debug!("redirect-target watcher shutdown during a re-read");
                            return;
                        }
                        _ = run_resync(&mut targets, &mut pending, &status) => {}
                    }
                }
                let refreshed = refresh(&mut targets, &mut pending, &directives);
                settle_recovery(&mut pending, &refreshed, &status);
                publish_unadmitted(&mut targets, &status);
                targets.retry_failing(&mut pending);
                if pending.resync {
                    // Owed but not yet retried (it failed, or is paced):
                    // keep the refresh coming round for it.
                    let at = pending.resync_not_before.unwrap_or_else(Instant::now);
                    pending.due_by(at);
                }
            }
            _ = refresh_now.notified() => {
                // A SIGHUP changed the directives; converge on them
                // after whatever refresh may just have run. Its own
                // reconcile may have made room, too.
                targets.offer_full(&mut pending);
                pending.touch();
            }
            Some((d, began)) = stalls.recv() => {
                // Test hook (`stall_reader`): block the whole thread, the
                // subscription's socket reader with it.
                let _ = began.send(());
                std::thread::sleep(d);
            }
        }
    }
}

/// The debounced pass: `RX_MACS`, then `VLAN_RESOLVE`, then the admits
/// it was holding back. A topology read failure keeps every admit pending and
/// re-arms the debounce; a translation that could not be written keeps
/// THAT admit pending the same way, and so does a port whose receive
/// MACs could not be read. Either way a transient failure costs a
/// retry, never a redirect to an untranslated sub-interface or a MAC
/// change left unapplied until some later event. `Err` is the topology
/// read failure: nothing was admitted.
fn refresh(
    targets: &mut Targets,
    pending: &mut Pending,
    directives: &Arc<Mutex<Vec<ModuleDirective>>>,
) -> Result<(), String> {
    let rx_retry = targets.refresh_rx_macs();
    let snapshot: Vec<ModuleDirective> = match directives.lock() {
        Ok(d) => d.clone(),
        Err(_) => Vec::new(),
    };
    let untranslated = match targets.refresh_vlan(&snapshot) {
        Ok(u) => u,
        Err(e) => {
            warn!(error = %e, "topology read failed; redirect admits held for retry");
            pending.touch();
            return Err(e);
        }
    };
    pending.due = None;
    let mut held = Vec::new();
    for ifindex in std::mem::take(&mut pending.admit) {
        // The link may have gone away again inside the debounce window.
        if !ifindex_exists(ifindex) {
            continue;
        }
        if untranslated.contains(&ifindex) {
            warn!(
                ifindex,
                "VLAN translation for this link is not in VLAN_RESOLVE (insert failed or map \
                 full); not admitted as a redirect target — its traffic stays on the kernel \
                 path until the entry lands"
            );
            held.push(ifindex);
            continue;
        }
        targets.admit(ifindex, "RTM_NEWLINK");
    }
    if !held.is_empty() {
        pending.admit = held;
        pending.touch();
    }
    if rx_retry {
        pending.touch();
    }
    Ok(())
}

fn handle(targets: &mut Targets, pending: &mut Pending, msg: NetlinkMessage<RouteNetlinkMessage>) {
    match msg.payload {
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(link)) => {
            // Every NEWLINK can change the topology VLAN_RESOLVE is
            // derived from (a VLAN sub-interface, a bridge, a member
            // joining one), so it always schedules a refresh; only a
            // qualifying link is also queued for admission.
            if let Some(ifindex) = viable_target(&link) {
                if !pending.admit.contains(&ifindex) {
                    pending.admit.push(ifindex);
                }
            }
            pending.touch();
        }
        NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(link)) => {
            let ifindex = link.header.index;
            pending.admit.retain(|i| *i != ifindex);
            if targets.evict(ifindex, "RTM_DELLINK") {
                // Room was made: what a full map refused gets its turn.
                targets.offer_full(pending);
            }
            pending.touch();
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(index: u32, kind: LinkLayerType, oper: Option<State>) -> LinkMessage {
        let mut m = LinkMessage::default();
        m.header.index = index;
        m.header.link_layer_type = kind;
        if let Some(s) = oper {
            m.attributes.push(LinkAttribute::OperState(s));
        }
        m
    }

    #[test]
    fn ethernet_up_or_unknown_is_a_target() {
        assert_eq!(
            viable_target(&link(7, LinkLayerType::Ether, Some(State::Up))),
            Some(7)
        );
        // Bridges and veths without carrier detection report `unknown`;
        // the attach-time fill accepts them, so this must too.
        assert_eq!(
            viable_target(&link(8, LinkLayerType::Ether, Some(State::Unknown))),
            Some(8)
        );
    }

    #[test]
    fn down_or_non_ethernet_is_not() {
        // Created-but-down: it becomes a target on the NEWLINK that
        // brings it up, not before.
        assert_eq!(
            viable_target(&link(9, LinkLayerType::Ether, Some(State::Down))),
            None
        );
        assert_eq!(
            viable_target(&link(10, LinkLayerType::Ether, Some(State::LowerLayerDown))),
            None
        );
        // No operstate attribute at all: not enough evidence to redirect.
        assert_eq!(viable_target(&link(11, LinkLayerType::Ether, None)), None);
        // Loopback (ARPHRD_LOOPBACK) and tunnels are never targets.
        assert_eq!(
            viable_target(&link(1, LinkLayerType::Loopback, Some(State::Unknown))),
            None
        );
    }

    /// A re-read stands in for every notification that was lost: what
    /// qualifies is queued as its `RTM_NEWLINK` would have been, what the
    /// maps hold and the kernel no longer lists is a lost `RTM_DELLINK`,
    /// and a link that merely went down stays (the membership policy).
    #[test]
    fn a_re_read_plans_the_lost_adds_and_deletes() {
        let links = [
            link(7, LinkLayerType::Ether, Some(State::Up)),
            link(8, LinkLayerType::Ether, Some(State::Unknown)),
            link(9, LinkLayerType::Ether, Some(State::Down)),
            link(1, LinkLayerType::Loopback, Some(State::Unknown)),
        ];
        let known: HashSet<u32> = [7, 9, 12].into_iter().collect();
        assert_eq!(
            resync_plan(&links, &known),
            ResyncPlan {
                admit: vec![7, 8],
                gone: vec![12],
            }
        );
        assert_eq!(resync_plan(&[], &HashSet::new()), ResyncPlan::default());
    }

    /// Only `E2BIG` means a map is full; anything else, the devmap's
    /// transient `ENOMEM` above all, is a failure a retry may get past.
    /// Read through aya's own error types, as the inserts return them.
    #[test]
    fn only_e2big_is_a_full_map() {
        use aya::maps::{xdp::XdpMapError, MapError};
        use aya::sys::SyscallError;
        let map_err = |errno| {
            MapError::SyscallError(SyscallError {
                call: "bpf_map_update_elem",
                io_error: std::io::Error::from_raw_os_error(errno),
            })
        };
        // TC_REDIRECT_TARGETS: a plain hash, `MapError`.
        assert_eq!(
            InsertFailure::of(&map_err(libc::E2BIG)),
            InsertFailure::Full
        );
        assert_eq!(
            InsertFailure::of(&map_err(libc::ENOMEM)),
            InsertFailure::Failing(Some(libc::ENOMEM))
        );
        // REDIRECT_DEVMAP: a devmap hash, `XdpMapError` wrapping it.
        assert_eq!(
            InsertFailure::of(&XdpMapError::MapError(map_err(libc::E2BIG))),
            InsertFailure::Full
        );
        assert_eq!(
            InsertFailure::of(&XdpMapError::MapError(map_err(libc::ENOMEM))),
            InsertFailure::Failing(Some(libc::ENOMEM))
        );
        // No errno to be had: not evidence of a full map either.
        assert_eq!(
            InsertFailure::of(&XdpMapError::ChainedProgramNotSupported),
            InsertFailure::Failing(None)
        );
    }

    /// A completed re-read is a completed recovery once the refresh after
    /// it got past the topology read; a refresh that could not read it
    /// keeps the recovery open and says why. Nothing else does: what the
    /// maps refused is reported on its own.
    #[test]
    fn a_recovery_completes_when_its_admissions_were_attempted() {
        let status = Mutex::new(WatchStatus {
            overruns: 1,
            resync_pending: true,
            ..WatchStatus::default()
        });
        let mut p = Pending {
            recovering: true,
            ..Pending::default()
        };
        settle_recovery(&mut p, &Err("vlan config unreadable".into()), &status);
        let s = status.lock().unwrap().clone();
        assert!(p.recovering && s.resync_pending, "{s:?}");
        assert_eq!(s.resyncs_ok, 0);
        assert!(s
            .last_resync_error
            .as_deref()
            .is_some_and(|e| e.contains("vlan config unreadable")));

        settle_recovery(&mut p, &Ok(()), &status);
        let s = status.lock().unwrap().clone();
        assert!(!p.recovering && !s.resync_pending, "{s:?}");
        assert_eq!((s.resyncs_ok, s.last_resync_error), (1, None));

        // Nothing owed: a refresh changes nothing.
        settle_recovery(&mut p, &Ok(()), &status);
        assert_eq!(status.lock().unwrap().resyncs_ok, 1);

        // A loss reported meanwhile keeps the row pending.
        p.recovering = true;
        p.resync = true;
        settle_recovery(&mut p, &Ok(()), &status);
        assert!(status.lock().unwrap().resync_pending);
    }

    /// A watcher that never ran is reported as stopped, not left out.
    #[test]
    fn a_watcher_that_never_started_reports_it() {
        use packetframe_common::module::HealthState;
        let w = RedirectTargetWatcher::not_started("thread could not be spawned: EAGAIN".into());
        let h = w.status().subsystem_health();
        assert_eq!(h.state, HealthState::Degraded);
        assert!(h.message.unwrap().contains("EAGAIN"));
        w.shutdown();
    }

    /// An overrun schedules the re-read through the same debounce as any
    /// event, so a burst of them costs one; a failed one is paced.
    #[test]
    fn an_overrun_schedules_a_paced_re_read() {
        let mut p = Pending::default();
        let now = Instant::now();
        assert!(!p.resync_due(now));
        p.overrun();
        assert!(p.resync && p.due.is_some());
        assert!(p.resync_due(now));
        p.resync_not_before = Some(now + RESYNC_RETRY);
        assert!(!p.resync_due(now));
        assert!(p.resync_due(now + RESYNC_RETRY));
        p.due = None;
        p.due_by(now + RESYNC_RETRY);
        assert_eq!(p.due, Some(now + RESYNC_RETRY));
        p.due_by(now);
        assert_eq!(p.due, Some(now), "never later than already due");
    }
}
