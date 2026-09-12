//! The engine: one `select!` loop owning every piece of mutable state,
//! fed by I/O pumps over bounded channels.
//!
//! Tasks on the module's own tokio runtime:
//! - the **engine loop** (this file): netlink multicast events, frames,
//!   the paced installer feed, housekeeping, reconfiguration;
//! - one **capture** pump per bridge with a bound socket
//!   ([`crate::capture::pump`]);
//! - the **installer**: one unicast rtnetlink handle, one write per job,
//!   errors reported back — success is *not* reported, the kernel's
//!   `RTM_NEWNEIGH` echo on the multicast group is the confirmation;
//! - the **persister**: write-then-rename on the blocking pool;
//! - the **coverage** sampler on its own strict-check connection.
//!
//! Every counter that claims an effect is recorded when the effect is
//! *observed* (the echo, the persist result), not when it is requested.

#![cfg(target_os = "linux")]

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime};

use futures::StreamExt;
use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
use netlink_packet_route::RouteNetlinkMessage;
use rtnetlink::{new_connection, new_multicast_connection, Handle, MulticastGroup};
use tokio::runtime::Runtime;
use tokio::sync::{mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::capture;
use crate::cfg::{BridgeCfg, HotConfig, SnoopConfig};
use crate::coverage::{self, CoverageSample};
use crate::frame::{self, Reject};
use crate::netlink::{self, LinkInfo, Messages};
use crate::persist::{self, LoadOutcome};
use crate::snapshot::{
    Counters, Coverage, CoverageState, IfaceSnapshot, InstallOutcome, LearnOutcome, LinkEvent,
    LinkState, PersistOutcome, SeedOutcome, Snapshot,
};
use crate::table::{
    admit, install_decision, Decision, FilterReject, KernelMirror, LearnedTable, Observe,
    DEFAULT_HOLDDOWN,
};

pub type SharedSnapshot = Arc<RwLock<Snapshot>>;

const FRAME_CHANNEL: usize = 1024;
const INSTALL_CHANNEL: usize = 256;
const PERSIST_CHANNEL: usize = 16;
/// First change to a table starts this timer; the write happens when
/// it expires, coalescing everything in between.
const PERSIST_DEBOUNCE: Duration = Duration::from_secs(3);
/// An install with no echo after this long counts as unconfirmed.
const CONFIRM_WINDOW: Duration = Duration::from_secs(5);
const HOUSEKEEPING: Duration = Duration::from_secs(1);
const STATS_EVERY_TICKS: u64 = 10;
const UNRESOLVED_SAMPLE_MAX: usize = 32;
/// The per-message log budget before a noisy class drops to debug.
const LOG_BUDGET: u64 = 20;
/// `Module::detach` must *return* within 1 s; joins get this much.
const SHUTDOWN_JOIN: Duration = Duration::from_millis(700);
/// `sll_pkttype` for frames we sent.
const PACKET_OUTGOING: u8 = 4;

/// Everything the engine loop reacts to besides netlink.
#[derive(Debug)]
pub enum EngineMsg {
    Frame {
        bridge_idx: usize,
        ifindex: u32,
        pkt_type: u8,
        bytes: Vec<u8>,
    },
    /// A capture pump exited; `error` is `None` on cancellation.
    CaptureEnded {
        bridge_idx: usize,
        ifindex: u32,
        error: Option<String>,
    },
    InstallFailed {
        bridge_idx: usize,
        ip: IpAddr,
        error: String,
    },
    PersistDone {
        bridge_idx: usize,
        result: Result<(), String>,
    },
    Coverage {
        bridge_idx: usize,
        ifindex: u32,
        result: Result<CoverageSample, String>,
    },
    Reconfigure(SnoopConfig),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    Learn,
    Seed,
    Derived,
}

#[derive(Debug, Clone)]
struct InstallJob {
    bridge_idx: usize,
    ifindex: u32,
    ip: IpAddr,
    mac: [u8; 6],
    origin: Origin,
}

struct PersistJob {
    bridge_idx: usize,
    path: PathBuf,
    json: String,
}

#[derive(Debug, Clone, Default)]
struct CoverageParams {
    /// `(bridge index, ifindex)` for every bridge that is up.
    bridges: Vec<(usize, u32)>,
    interval: Duration,
}

struct InFlight {
    mac: [u8; 6],
    origin: Origin,
    since: Instant,
}

struct IfaceState {
    cfg: BridgeCfg,
    ifindex: Option<u32>,
    up: bool,
    own_mac: Option<[u8; 6]>,
    own_addrs: HashSet<IpAddr>,
    table: LearnedTable,
    capture: Option<(u32, AbortHandle)>,
    socket_error: Option<String>,
    promisc_confirmed: bool,
    heard_peers: HashSet<IpAddr>,
    pending: VecDeque<InstallJob>,
    queued: HashSet<IpAddr>,
    in_flight: HashMap<IpAddr, InFlight>,
    /// Holddown bookkeeping for addresses installed by derivation,
    /// which are not in the learned table.
    derived_last_install: HashMap<IpAddr, Instant>,
    dirty_since: Option<Instant>,
    last_frame: Option<Instant>,
    up_since: Option<Instant>,
    route_coverage: CoverageState,
    coverage_at: Option<Instant>,
    counters: Counters,
    backpressure: Arc<AtomicU64>,
    mac_mismatch_logged: u64,
    install_failures_logged: u64,
}

impl IfaceState {
    fn new(cfg: BridgeCfg, cap: usize) -> Self {
        Self {
            cfg,
            ifindex: None,
            up: false,
            own_mac: None,
            own_addrs: HashSet::new(),
            table: LearnedTable::new(cap),
            capture: None,
            socket_error: None,
            promisc_confirmed: false,
            heard_peers: HashSet::new(),
            pending: VecDeque::new(),
            queued: HashSet::new(),
            in_flight: HashMap::new(),
            derived_last_install: HashMap::new(),
            dirty_since: None,
            last_frame: None,
            up_since: None,
            route_coverage: CoverageState::Pending,
            coverage_at: None,
            counters: Counters::default(),
            backpressure: Arc::new(AtomicU64::new(0)),
            mac_mismatch_logged: 0,
            install_failures_logged: 0,
        }
    }

    fn mark_dirty(&mut self, now: Instant) {
        if self.dirty_since.is_none() {
            self.dirty_since = Some(now);
        }
    }
}

struct Engine {
    persist_dir: PathBuf,
    deny_macs: Vec<[u8; 6]>,
    hot: HotConfig,
    bridges: Vec<IfaceState>,
    mirror: KernelMirror,
    unicast: Handle,
    frame_tx: mpsc::Sender<EngineMsg>,
    install_tx: mpsc::Sender<InstallJob>,
    persist_tx: mpsc::Sender<PersistJob>,
    cov_tx: watch::Sender<CoverageParams>,
    snapshot: SharedSnapshot,
    cancel: CancellationToken,
    rr: usize,
    ticks: u64,
}

/// The running engine, as the module sees it.
pub struct EngineHandle {
    runtime: Option<Runtime>,
    cancel: CancellationToken,
    tasks: Vec<JoinHandle<()>>,
    snapshot: SharedSnapshot,
    ctl_tx: mpsc::UnboundedSender<EngineMsg>,
}

impl EngineHandle {
    /// Build the runtime, run the startup sequence to completion (so a
    /// netlink or socket failure is an attach error, not a log line),
    /// then spawn the pumps and the loop.
    pub fn start(config: SnoopConfig, persist_dir: PathBuf) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("packetframe-snoop")
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;
        let cancel = CancellationToken::new();
        let snapshot: SharedSnapshot = Arc::new(RwLock::new(Snapshot::default()));
        let (frame_tx, frame_rx) = mpsc::channel(FRAME_CHANNEL);
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let (install_tx, install_rx) = mpsc::channel(INSTALL_CHANNEL);
        let (persist_tx, persist_rx) = mpsc::channel(PERSIST_CHANNEL);
        let (cov_tx, cov_rx) = watch::channel(CoverageParams {
            bridges: Vec::new(),
            interval: config.hot.coverage_interval,
        });

        let (engine, messages) = runtime.block_on(Engine::init(
            config,
            persist_dir,
            snapshot.clone(),
            frame_tx,
            install_tx,
            persist_tx,
            cov_tx,
            cancel.clone(),
        ))?;
        let unicast = engine.unicast.clone();
        let tasks = vec![
            runtime.spawn(installer(unicast, install_rx, ctl_tx.clone())),
            runtime.spawn(persister(persist_rx, ctl_tx.clone())),
            runtime.spawn(coverage_task(cov_rx, ctl_tx.clone(), cancel.clone())),
            runtime.spawn(engine.run(messages, frame_rx, ctl_rx)),
        ];
        Ok(Self {
            runtime: Some(runtime),
            cancel,
            tasks,
            snapshot,
            ctl_tx,
        })
    }

    /// The last published snapshot (published every housekeeping tick).
    /// If the engine task has exited while the handle is still live
    /// (a panic, or an exit path that published nothing), every bridge
    /// is reported with a terminal error rather than the frozen last
    /// tick: nothing is being captured, installed or re-seeded.
    pub fn snapshot(&self) -> Snapshot {
        let mut s = self.snapshot.read().map(|s| s.clone()).unwrap_or_default();
        if self.runtime.is_some() && !self.cancel.is_cancelled() && self.engine_task_finished() {
            for b in &mut s.bridges {
                b.socket_error
                    .get_or_insert_with(|| "engine task exited unexpectedly".to_string());
            }
        }
        s
    }

    fn engine_task_finished(&self) -> bool {
        // The engine loop is the last task spawned in `start`.
        self.tasks.last().is_some_and(JoinHandle::is_finished)
    }

    /// Apply the hot-reloadable parts of a new configuration.
    pub fn reconfigure(&self, new: SnoopConfig) {
        let _ = self.ctl_tx.send(EngineMsg::Reconfigure(new));
    }

    /// Stop everything within the detach budget. Kernel STALE entries
    /// and the JSON cache are left in place by design.
    pub fn shutdown(mut self) {
        self.stop(SHUTDOWN_JOIN);
    }

    fn stop(&mut self, join_budget: Duration) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        self.cancel.cancel();
        let deadline = Instant::now() + join_budget;
        runtime.block_on(async {
            for t in self.tasks.drain(..) {
                let left = deadline.saturating_duration_since(Instant::now());
                if tokio::time::timeout(left, t).await.is_err() {
                    warn!("neigh-snoop task did not finish inside the detach budget");
                }
            }
        });
        runtime.shutdown_timeout(Duration::from_millis(200));
    }
}

/// The preserve-attach exit (SIGTERM) drops modules without `detach`,
/// so the final persist and the socket close must happen here too.
impl Drop for EngineHandle {
    fn drop(&mut self) {
        if self.runtime.is_some() {
            self.stop(Duration::from_millis(500));
        }
    }
}

impl Engine {
    #[allow(clippy::too_many_arguments)]
    async fn init(
        config: SnoopConfig,
        persist_dir: PathBuf,
        snapshot: SharedSnapshot,
        frame_tx: mpsc::Sender<EngineMsg>,
        install_tx: mpsc::Sender<InstallJob>,
        persist_tx: mpsc::Sender<PersistJob>,
        cov_tx: watch::Sender<CoverageParams>,
        cancel: CancellationToken,
    ) -> Result<(Self, Messages), String> {
        let now = Instant::now();
        let wall = SystemTime::now();
        let cap = config.hot.table_max as usize;
        let mut bridges: Vec<IfaceState> = config
            .bridges
            .iter()
            .cloned()
            .map(|b| IfaceState::new(b, cap))
            .collect();

        // 1. Persisted tables (the seed source), age-filtered.
        for b in &mut bridges {
            let path = persist::file_path(&persist_dir, &b.cfg.name);
            match persist::load(&path, &b.cfg.name, wall, now, config.hot.seed_max_age) {
                LoadOutcome::Loaded {
                    entries,
                    expired,
                    bad_entries,
                    written_at,
                } => {
                    let n = entries.len();
                    for (ip, e) in entries {
                        if b.table.insert_restored(ip, e).is_some() {
                            b.counters.learn(LearnOutcome::Evicted);
                        }
                    }
                    for _ in 0..expired {
                        b.counters.seed(SeedOutcome::Expired);
                    }
                    for _ in 0..bad_entries {
                        b.counters.seed(SeedOutcome::BadEntry);
                    }
                    if expired > 0 || bad_entries > 0 {
                        b.mark_dirty(now);
                    }
                    info!(
                        bridge = %b.cfg.name,
                        entries = n,
                        expired,
                        bad_entries,
                        age_secs = wall.duration_since(written_at).map(|d| d.as_secs()).unwrap_or(0),
                        "persisted neighbour table loaded"
                    );
                }
                LoadOutcome::Missing => {
                    info!(bridge = %b.cfg.name, "no persisted neighbour table; starting empty");
                }
                LoadOutcome::Unusable(why) => {
                    warn!(bridge = %b.cfg.name, %why, "persisted neighbour table ignored");
                }
            }
        }

        // 2. Subscribe BEFORE dumping: events raised during the dumps
        //    queue on the socket and replay through the loop, and every
        //    handler is last-write-wins, so nothing is lost in between.
        //    Route groups are deliberately absent (1M-route churn).
        let groups = [
            MulticastGroup::Link,
            MulticastGroup::Neigh,
            MulticastGroup::Ipv4Ifaddr,
            MulticastGroup::Ipv6Ifaddr,
        ];
        let (mconn, _mhandle, messages) = new_multicast_connection(&groups)
            .map_err(|e| format!("netlink multicast subscription: {e}"))?;
        tokio::spawn(mconn);
        let (uconn, unicast, _) =
            new_connection().map_err(|e| format!("netlink unicast connection: {e}"))?;
        tokio::spawn(uconn);

        let mut engine = Engine {
            persist_dir,
            deny_macs: config.deny_macs.clone(),
            hot: config.hot.clone(),
            bridges,
            mirror: KernelMirror::default(),
            unicast,
            frame_tx,
            install_tx,
            persist_tx,
            cov_tx,
            snapshot,
            cancel,
            rr: 0,
            ticks: 0,
        };

        // 3. Links: which configured bridges exist, their MACs, state.
        let links = netlink::dump_links(&engine.unicast).await?;
        let mut present: Vec<(usize, LinkInfo)> = Vec::new();
        for l in links {
            if let Some(name) = &l.name {
                if let Some(bi) = engine.bridges.iter().position(|b| b.cfg.name == *name) {
                    let b = &mut engine.bridges[bi];
                    b.ifindex = Some(l.ifindex);
                    b.own_mac = l.mac;
                    b.promisc_confirmed = l.promisc;
                    present.push((bi, l));
                }
            }
        }
        // 4. Own addresses and 5. neighbours for the tracked ifindexes.
        engine.refresh_addrs_and_neighs(None).await?;

        // 6. Capture + seed for every bridge that is up.
        for (bi, l) in present {
            if l.up {
                engine.bring_up(bi, now).await;
            } else {
                info!(bridge = %l.name.unwrap_or_default(), "bridge present but down; waiting");
            }
        }
        for b in &engine.bridges {
            if b.ifindex.is_none() {
                info!(bridge = %b.cfg.name, "bridge absent; waiting for RTM_NEWLINK by name");
            }
        }
        // A bridge that is present and up but has no capture socket is
        // an attach failure (missing CAP_NET_RAW, membership refused),
        // not a health row: the startup contract is "attached means
        // capturing". Failures after attach keep the retry path.
        if let Some(b) = engine.bridges.iter().find(|b| b.up && b.capture.is_none()) {
            return Err(format!(
                "capture socket on {}: {}",
                b.cfg.name,
                b.socket_error.as_deref().unwrap_or("not open")
            ));
        }
        engine.publish_coverage_params();
        engine.publish_snapshot(now);
        Ok((engine, messages))
    }

    /// Re-dump addresses and neighbours; `only` restricts the refresh
    /// to one ifindex (a recreated or newly-up bridge).
    async fn refresh_addrs_and_neighs(&mut self, only: Option<u32>) -> Result<(), String> {
        let tracked: HashMap<u32, usize> = self
            .bridges
            .iter()
            .enumerate()
            .filter_map(|(i, b)| b.ifindex.map(|ifi| (ifi, i)))
            .filter(|(ifi, _)| only.is_none_or(|o| o == *ifi))
            .collect();
        if tracked.is_empty() {
            return Ok(());
        }
        for (ifindex, ip) in netlink::dump_addrs(&self.unicast).await? {
            if let Some(&bi) = tracked.get(&ifindex) {
                self.bridges[bi].own_addrs.insert(ip);
            }
        }
        for (ifindex, ip, entry) in netlink::dump_neighs(&self.unicast).await? {
            if tracked.contains_key(&ifindex) {
                self.mirror.upsert(ifindex, ip, entry);
            }
        }
        Ok(())
    }

    fn publish_coverage_params(&self) {
        let bridges = self
            .bridges
            .iter()
            .enumerate()
            .filter(|(_, b)| b.up)
            .filter_map(|(i, b)| b.ifindex.map(|ifi| (i, ifi)))
            .collect();
        self.cov_tx.send_replace(CoverageParams {
            bridges,
            interval: self.hot.coverage_interval,
        });
    }

    async fn run(
        mut self,
        mut messages: Messages,
        mut frame_rx: mpsc::Receiver<EngineMsg>,
        mut ctl_rx: mpsc::UnboundedReceiver<EngineMsg>,
    ) {
        let mut install_tick = tokio::time::interval(self.hot.install_period());
        install_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut housekeeping = tokio::time::interval(HOUSEKEEPING);
        housekeeping.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => {
                    self.shutdown();
                    return;
                }
                next = messages.next() => match next {
                    Some((pkt, _)) => self.on_netlink(pkt).await,
                    None => {
                        warn!("netlink multicast stream closed; neigh-snoop engine stopping");
                        self.fail_terminal("netlink multicast stream closed; engine stopped");
                        self.shutdown();
                        return;
                    }
                },
                Some(msg) = frame_rx.recv() => self.on_msg(msg).await,
                Some(msg) = ctl_rx.recv() => {
                    let before = self.hot.install_period();
                    self.on_msg(msg).await;
                    if self.hot.install_period() != before {
                        install_tick = tokio::time::interval(self.hot.install_period());
                        install_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
                    }
                }
                _ = install_tick.tick() => self.install_one(),
                _ = housekeeping.tick() => self.housekeeping().await,
            }
        }
    }

    // --- netlink events --------------------------------------------------

    async fn on_netlink(&mut self, pkt: NetlinkMessage<RouteNetlinkMessage>) {
        match pkt.payload {
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m)) => {
                self.on_link(netlink::link_info(&m)).await;
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(m)) => {
                self.on_link_gone(m.header.index);
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(m)) => {
                if let Some((ifindex, ip, entry)) = netlink::neigh_of(&m) {
                    self.on_neigh(ifindex, ip, Some(entry));
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelNeighbour(m)) => {
                if let Some((ifindex, ip, _)) = netlink::neigh_of(&m) {
                    self.on_neigh(ifindex, ip, None);
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(m)) => {
                if let Some((ifindex, ip)) = netlink::addr_of(&m) {
                    if let Some(b) = self.bridges.iter_mut().find(|b| b.ifindex == Some(ifindex)) {
                        b.own_addrs.insert(ip);
                    }
                }
            }
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(m)) => {
                if let Some((ifindex, ip)) = netlink::addr_of(&m) {
                    if let Some(b) = self.bridges.iter_mut().find(|b| b.ifindex == Some(ifindex)) {
                        b.own_addrs.remove(&ip);
                    }
                }
            }
            NetlinkPayload::Error(e) => warn!(?e, "netlink error on the multicast socket"),
            _ => {}
        }
    }

    async fn on_link(&mut self, info: LinkInfo) {
        let Some(name) = info.name.as_deref() else {
            return;
        };
        let Some(bi) = self.bridges.iter().position(|b| b.cfg.name == name) else {
            return;
        };
        let now = Instant::now();
        let b = &mut self.bridges[bi];
        match b.ifindex {
            Some(old) if old != info.ifindex => {
                // Destroyed and recreated under the same name: the old
                // socket receives nothing, and every kernel row for the
                // old ifindex is gone.
                info!(bridge = %name, old, new = info.ifindex, "bridge recreated");
                b.counters.link_event(LinkEvent::Recreated);
                self.close_capture(bi);
                self.mirror.purge_ifindex(old);
                let b = &mut self.bridges[bi];
                b.own_addrs.clear();
                b.in_flight.clear();
                // Rate-limited jobs still queued target the dead ifindex
                // and would also block the re-seed's enqueue by dedup.
                b.pending.clear();
                b.queued.clear();
                b.ifindex = Some(info.ifindex);
                b.own_mac = info.mac;
                b.promisc_confirmed = info.promisc;
                b.up = false;
                b.up_since = None;
                if info.up {
                    self.bring_up(bi, now).await;
                }
                self.publish_coverage_params();
            }
            Some(_) => {
                if info.mac.is_some() {
                    b.own_mac = info.mac;
                }
                b.promisc_confirmed = info.promisc;
                if !b.up && info.up {
                    self.bring_up(bi, now).await;
                    self.publish_coverage_params();
                } else if b.up && !info.up {
                    info!(bridge = %name, "bridge down");
                    b.up = false;
                    b.up_since = None;
                    b.counters.link_event(LinkEvent::Down);
                    self.publish_coverage_params();
                }
            }
            None => {
                info!(bridge = %name, ifindex = info.ifindex, "bridge appeared");
                b.ifindex = Some(info.ifindex);
                b.own_mac = info.mac;
                b.promisc_confirmed = info.promisc;
                if info.up {
                    self.bring_up(bi, now).await;
                    self.publish_coverage_params();
                }
            }
        }
    }

    fn on_link_gone(&mut self, ifindex: u32) {
        let Some(bi) = self.bridges.iter().position(|b| b.ifindex == Some(ifindex)) else {
            return;
        };
        info!(bridge = %self.bridges[bi].cfg.name, ifindex, "bridge deleted; keeping the learned table");
        self.close_capture(bi);
        self.mirror.purge_ifindex(ifindex);
        let b = &mut self.bridges[bi];
        b.ifindex = None;
        b.up = false;
        b.up_since = None;
        b.own_addrs.clear();
        b.in_flight.clear();
        b.pending.clear();
        b.queued.clear();
        b.counters.link_event(LinkEvent::Down);
        self.publish_coverage_params();
    }

    /// The bridge is (now) up: refresh its kernel state, open the
    /// capture if none is bound to this ifindex, seed from the table.
    async fn bring_up(&mut self, bi: usize, now: Instant) {
        let ifindex = match self.bridges[bi].ifindex {
            Some(i) => i,
            None => return,
        };
        {
            let b = &mut self.bridges[bi];
            b.up = true;
            b.up_since = Some(now);
            b.counters.link_event(LinkEvent::Up);
        }
        if let Err(e) = self.refresh_addrs_and_neighs(Some(ifindex)).await {
            warn!(bridge = %self.bridges[bi].cfg.name, error = %e, "kernel state refresh failed");
        }
        self.open_capture(bi);
        self.seed(bi, now);
        info!(
            bridge = %self.bridges[bi].cfg.name,
            ifindex,
            entries = self.bridges[bi].table.len(),
            queued = self.bridges[bi].pending.len(),
            "bridge up; capture open and seed queued"
        );
    }

    fn open_capture(&mut self, bi: usize) {
        let Some(ifindex) = self.bridges[bi].ifindex else {
            return;
        };
        if matches!(self.bridges[bi].capture, Some((i, _)) if i == ifindex) {
            return;
        }
        self.close_capture(bi);
        match capture::open_capture(ifindex) {
            Ok(fd) => {
                let b = &mut self.bridges[bi];
                let task = tokio::spawn(run_pump(
                    fd,
                    bi,
                    ifindex,
                    self.frame_tx.clone(),
                    b.backpressure.clone(),
                    self.cancel.clone(),
                ));
                b.capture = Some((ifindex, task.abort_handle()));
                b.socket_error = None;
            }
            Err(e) => {
                let b = &mut self.bridges[bi];
                let msg = e.to_string();
                if b.socket_error.as_deref() != Some(&msg) {
                    warn!(bridge = %b.cfg.name, ifindex, error = %msg, "capture socket failed");
                }
                b.socket_error = Some(msg);
                b.counters.socket_errors += 1;
            }
        }
    }

    fn close_capture(&mut self, bi: usize) {
        if let Some((_, abort)) = self.bridges[bi].capture.take() {
            abort.abort();
        }
    }

    fn seed(&mut self, bi: usize, now: Instant) {
        self.purge_inadmissible(bi, now);
        let entries: Vec<(IpAddr, [u8; 6])> = self.bridges[bi]
            .table
            .iter()
            .map(|(ip, e)| (*ip, e.mac))
            .collect();
        for (ip, mac) in entries {
            self.consider_install(bi, ip, mac, Origin::Seed, now);
        }
    }

    /// Drop learned entries the current admission policy rejects. The
    /// table outlives the policy (persisted across restarts, kept across
    /// hot reloads), so a narrowed prefix or a new deny-mac must apply
    /// to what is already held before any of it is re-seeded.
    fn purge_inadmissible(&mut self, bi: usize, now: Instant) {
        let b = &mut self.bridges[bi];
        let rejected: Vec<(IpAddr, FilterReject)> = b
            .table
            .iter()
            .filter_map(|(ip, e)| {
                admit(
                    *ip,
                    e.mac,
                    &b.cfg.prefixes,
                    &b.own_addrs,
                    b.own_mac,
                    &self.deny_macs,
                )
                .err()
                .map(|why| (*ip, why))
            })
            .collect();
        if rejected.is_empty() {
            return;
        }
        for (ip, why) in &rejected {
            b.table.remove(ip);
            b.counters.filter_reject(*why);
        }
        b.mark_dirty(now);
        info!(
            bridge = %b.cfg.name,
            dropped = rejected.len(),
            "learned entries outside the current admission policy dropped"
        );
    }

    fn on_neigh(&mut self, ifindex: u32, ip: IpAddr, entry: Option<crate::table::MirrorEntry>) {
        let Some(bi) = self.bridges.iter().position(|b| b.ifindex == Some(ifindex)) else {
            return;
        };
        match entry {
            None => {
                self.mirror.remove(ifindex, &ip);
            }
            Some(e) => {
                self.mirror.upsert(ifindex, ip, e);
                let b = &mut self.bridges[bi];
                if let Some(p) = b.in_flight.remove(&ip) {
                    match e.mac {
                        Some(m) if m == p.mac => match p.origin {
                            Origin::Seed => b.counters.seed(SeedOutcome::Confirmed),
                            Origin::Learn | Origin::Derived => {
                                b.counters.install(InstallOutcome::Confirmed)
                            }
                        },
                        Some(_) => b.counters.install(InstallOutcome::Overridden),
                        // An echo without a link-layer address: not ours;
                        // keep waiting for the real one.
                        None => {
                            b.in_flight.insert(ip, p);
                        }
                    }
                }
            }
        }
    }

    // --- engine messages -------------------------------------------------

    async fn on_msg(&mut self, msg: EngineMsg) {
        match msg {
            EngineMsg::Frame {
                bridge_idx,
                ifindex,
                pkt_type,
                bytes,
            } => self.on_frame(bridge_idx, ifindex, pkt_type, &bytes),
            EngineMsg::CaptureEnded {
                bridge_idx,
                ifindex,
                error,
            } => {
                let Some(b) = self.bridges.get_mut(bridge_idx) else {
                    return;
                };
                if !matches!(b.capture, Some((i, _)) if i == ifindex) {
                    return; // an old pump; already replaced
                }
                b.capture = None;
                if let Some(e) = error {
                    warn!(bridge = %b.cfg.name, ifindex, error = %e, "capture ended with error");
                    b.socket_error = Some(e);
                    b.counters.socket_errors += 1;
                }
            }
            EngineMsg::InstallFailed {
                bridge_idx,
                ip,
                error,
            } => {
                let Some(b) = self.bridges.get_mut(bridge_idx) else {
                    return;
                };
                match b.in_flight.remove(&ip).map(|p| p.origin) {
                    Some(Origin::Seed) => b.counters.seed(SeedOutcome::Failed),
                    _ => b.counters.install(InstallOutcome::Failed),
                }
                b.install_failures_logged += 1;
                if b.install_failures_logged <= LOG_BUDGET {
                    warn!(bridge = %b.cfg.name, %ip, error = %error, "neighbour install failed");
                } else {
                    debug!(bridge = %b.cfg.name, %ip, error = %error, "neighbour install failed");
                }
            }
            EngineMsg::PersistDone { bridge_idx, result } => {
                let Some(b) = self.bridges.get_mut(bridge_idx) else {
                    return;
                };
                match result {
                    Ok(()) => b.counters.persist(PersistOutcome::Written),
                    Err(e) => {
                        b.counters.persist(PersistOutcome::Failed);
                        warn!(bridge = %b.cfg.name, error = %e, "persist failed; will retry on next change");
                        b.mark_dirty(Instant::now());
                    }
                }
            }
            EngineMsg::Coverage {
                bridge_idx,
                ifindex,
                result,
            } => {
                let Some(b) = self.bridges.get(bridge_idx) else {
                    return;
                };
                if b.ifindex != Some(ifindex) {
                    return; // sampled a device that has since gone
                }
                let now = Instant::now();
                let state = match result {
                    // A route naming a nexthop id the object dump did not
                    // return means the two dumps raced; reporting the
                    // remaining set as coverage would read as complete.
                    Ok(sample) if sample.unknown_ids > 0 => CoverageState::Unavailable(format!(
                        "{} routes reference nexthop ids missing from the object dump; retrying next tick",
                        sample.unknown_ids
                    )),
                    Ok(sample) => {
                        let (ratio, unresolved) = coverage::join_coverage(
                            &sample.nexthops,
                            ifindex,
                            &self.mirror,
                            UNRESOLVED_SAMPLE_MAX,
                        );
                        debug!(
                            bridge = %b.cfg.name,
                            nexthops = ratio.total,
                            resolved = ratio.resolved,
                            objects = sample.nexthop_objects,
                            routes = sample.routes_seen,
                            unknown_ids = sample.unknown_ids,
                            dump_ms = sample.dump_ms,
                            "coverage sample"
                        );
                        CoverageState::Measured(Coverage {
                            nexthops: ratio,
                            unresolved_sample: unresolved,
                            nexthop_objects: sample.nexthop_objects,
                            routes_seen: sample.routes_seen,
                            dump_ms: sample.dump_ms,
                            age_secs: 0,
                        })
                    }
                    Err(e) => CoverageState::Unavailable(e),
                };
                let b = &mut self.bridges[bridge_idx];
                b.route_coverage = state;
                b.coverage_at = Some(now);
            }
            EngineMsg::Reconfigure(new) => self.reconfigure(new),
        }
    }

    fn on_frame(&mut self, bi: usize, ifindex: u32, pkt_type: u8, bytes: &[u8]) {
        let now = Instant::now();
        let wall = SystemTime::now();
        let Some(b) = self.bridges.get_mut(bi) else {
            return;
        };
        if b.ifindex != Some(ifindex) {
            return; // from a socket bound to a device that is gone
        }
        if pkt_type == PACKET_OUTGOING {
            b.counters.frames_outgoing_dropped += 1;
            return;
        }
        let pairs = match frame::parse_frame(bytes) {
            Ok(p) => p,
            Err(r) => {
                b.counters.parse_reject(&r);
                // Both are the spoof-shaped reject: the one field a
                // participant can forge past the fabric's source-MAC
                // port security. Worth a bounded WARN, not just a counter.
                let which = match r {
                    Reject::ShaMismatch => Some("ARP sender MAC"),
                    Reject::LlaoMismatch => Some("ND link-layer option"),
                    _ => None,
                };
                if let Some(which) = which {
                    b.mac_mismatch_logged += 1;
                    if b.mac_mismatch_logged <= LOG_BUDGET {
                        warn!(bridge = %b.cfg.name, "{which} disagrees with the Ethernet source; frame dropped");
                    }
                }
                return;
            }
        };
        b.last_frame = Some(now);
        b.counters.frame(pairs[0].source);
        for l in pairs {
            let b = &mut self.bridges[bi];
            if let Err(why) = admit(
                l.ip,
                l.mac,
                &b.cfg.prefixes,
                &b.own_addrs,
                b.own_mac,
                &self.deny_macs,
            ) {
                b.counters.filter_reject(why);
                continue;
            }
            let (outcome, evicted) = b.table.observe(l.ip, l.mac, l.source, wall, now);
            if evicted.is_some() {
                b.counters.learn(LearnOutcome::Evicted);
            }
            // Any admitted observation counts as hearing a peer: a peer
            // restored from disk refreshes rather than appears, and a
            // peer added by hot reload may already be in the table.
            if b.cfg.peer_addrs().any(|a| a == l.ip) && b.heard_peers.insert(l.ip) {
                info!(bridge = %b.cfg.name, ip = %l.ip, "configured peer first heard");
            }
            match outcome {
                Observe::New => {
                    b.counters.learn(LearnOutcome::New);
                    b.mark_dirty(now);
                }
                Observe::Refreshed => {
                    b.counters.learn(LearnOutcome::Refreshed);
                    b.mark_dirty(now);
                }
                Observe::MacChanged { old } => {
                    b.counters.learn(LearnOutcome::MacChanged);
                    b.mark_dirty(now);
                    info!(
                        bridge = %b.cfg.name,
                        ip = %l.ip,
                        old = %packetframe_common::config::format_mac(old),
                        new = %packetframe_common::config::format_mac(l.mac),
                        "learned MAC changed"
                    );
                }
            }
            self.consider_install(bi, l.ip, l.mac, Origin::Learn, now);
            // One MAC per member port: a MAC learned for one address of
            // a declared router applies to its other addresses too.
            let siblings: Vec<IpAddr> = self.bridges[bi]
                .cfg
                .siblings_of(&l.ip)
                .map(|s| s.iter().copied().filter(|s| *s != l.ip).collect())
                .unwrap_or_default();
            for s in siblings {
                if self.consider_install(bi, s, l.mac, Origin::Derived, now) {
                    self.bridges[bi].counters.learn(LearnOutcome::Derived);
                }
            }
        }
    }

    /// Run the install decision and queue the job if it says install.
    /// Returns whether a job was queued.
    fn consider_install(
        &mut self,
        bi: usize,
        ip: IpAddr,
        mac: [u8; 6],
        origin: Origin,
        now: Instant,
    ) -> bool {
        let b = &mut self.bridges[bi];
        let Some(ifindex) = b.ifindex else {
            return false;
        };
        if !b.up {
            return false;
        }
        let last_install = match origin {
            Origin::Derived => b.derived_last_install.get(&ip).copied(),
            _ => b.table.get(&ip).and_then(|e| e.last_install),
        };
        let kernel = self.mirror.get(ifindex, &ip);
        match install_decision(kernel, mac, last_install, now, DEFAULT_HOLDDOWN) {
            Decision::Install(_) => {
                if b.queued.insert(ip) {
                    b.pending.push_back(InstallJob {
                        bridge_idx: bi,
                        ifindex,
                        ip,
                        mac,
                        origin,
                    });
                }
                true
            }
            Decision::Skip(reason) => {
                b.counters.install(InstallOutcome::Skipped(reason));
                false
            }
        }
    }

    /// One paced install: round-robin across bridges so a seed on one
    /// bridge cannot starve live learns on another.
    ///
    /// A job can sit in `pending` for a while under the rate limit, so
    /// the decision is taken again at dispatch against the *current*
    /// table MAC and mirror state: a MAC learned after the enqueue
    /// replaces the queued one, and a kernel entry that became
    /// REACHABLE, PERMANENT or NOARP meanwhile is left alone. Jobs whose
    /// device is gone are dropped. Skipped jobs cost no netlink write,
    /// so the scan continues to the next dispatchable job.
    fn install_one(&mut self) {
        let n = self.bridges.len();
        if n == 0 {
            return;
        }
        let now = Instant::now();
        for k in 0..n {
            let bi = (self.rr + k) % n;
            let job = loop {
                let Some(mut job) = self.bridges[bi].pending.pop_front() else {
                    break None;
                };
                let b = &mut self.bridges[bi];
                b.queued.remove(&job.ip);
                if !b.up || b.ifindex != Some(job.ifindex) {
                    continue; // enqueued for a device that is gone
                }
                if let Some(e) = b.table.get(&job.ip) {
                    job.mac = e.mac;
                }
                let last_install = match job.origin {
                    Origin::Derived => b.derived_last_install.get(&job.ip).copied(),
                    _ => b.table.get(&job.ip).and_then(|e| e.last_install),
                };
                let kernel = self.mirror.get(job.ifindex, &job.ip);
                match install_decision(kernel, job.mac, last_install, now, DEFAULT_HOLDDOWN) {
                    Decision::Install(_) => break Some(job),
                    Decision::Skip(reason) => {
                        b.counters.install(InstallOutcome::Skipped(reason));
                    }
                }
            };
            let Some(job) = job else {
                continue;
            };
            self.rr = (bi + 1) % n;
            match self.install_tx.try_send(job.clone()) {
                Ok(()) => {
                    let b = &mut self.bridges[bi];
                    b.in_flight.insert(
                        job.ip,
                        InFlight {
                            mac: job.mac,
                            origin: job.origin,
                            since: now,
                        },
                    );
                    match job.origin {
                        Origin::Seed => b.counters.seed(SeedOutcome::Requested),
                        Origin::Learn | Origin::Derived => {
                            b.counters.install(InstallOutcome::Requested)
                        }
                    }
                    match job.origin {
                        Origin::Derived => {
                            b.derived_last_install.insert(job.ip, now);
                        }
                        _ => {
                            if let Some(e) = b.table.get_mut(&job.ip) {
                                e.last_install = Some(now);
                            }
                        }
                    }
                }
                Err(mpsc::error::TrySendError::Full(job)) => {
                    // Hand-off buffer full: keep the job at the head.
                    let b = &mut self.bridges[bi];
                    b.queued.insert(job.ip);
                    b.pending.push_front(job);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {}
            }
            return;
        }
    }

    // --- housekeeping ----------------------------------------------------

    async fn housekeeping(&mut self) {
        let now = Instant::now();
        self.ticks += 1;
        for bi in 0..self.bridges.len() {
            let b = &mut self.bridges[bi];
            let expired: Vec<IpAddr> = b
                .in_flight
                .iter()
                .filter(|(_, p)| now.duration_since(p.since) > CONFIRM_WINDOW)
                .map(|(ip, _)| *ip)
                .collect();
            for ip in expired {
                if let Some(p) = b.in_flight.remove(&ip) {
                    match p.origin {
                        Origin::Seed => b.counters.seed(SeedOutcome::Unconfirmed),
                        Origin::Learn | Origin::Derived => {
                            b.counters.install(InstallOutcome::Unconfirmed)
                        }
                    }
                }
            }
            if b.dirty_since
                .is_some_and(|t| now.duration_since(t) >= PERSIST_DEBOUNCE)
            {
                self.request_persist(bi, now);
            }
            let b = &self.bridges[bi];
            if b.up && b.capture.is_none() && b.ifindex.is_some() {
                self.open_capture(bi);
            }
        }
        // Raising promiscuity through a socket membership changes the
        // device flags without an RTM_NEWLINK, so the echo never comes;
        // confirm it from a link dump instead, once per bridge until seen.
        if self
            .bridges
            .iter()
            .any(|b| b.up && b.capture.is_some() && !b.promisc_confirmed)
        {
            if let Ok(links) = netlink::dump_links(&self.unicast).await {
                for l in links {
                    if let Some(b) = self
                        .bridges
                        .iter_mut()
                        .find(|b| b.ifindex == Some(l.ifindex))
                    {
                        b.promisc_confirmed = l.promisc;
                    }
                }
            }
        }
        self.publish_snapshot(now);
        if self.ticks % STATS_EVERY_TICKS == 0 {
            for b in &self.bridges {
                let confirmed = b.counters.installs[InstallOutcome::Confirmed.index()]
                    + b.counters.seeds[SeedOutcome::Confirmed.index()];
                info!(
                    bridge = %b.cfg.name,
                    link = b.link_state().label(),
                    entries = b.table.len(),
                    installs_confirmed = confirmed,
                    mac_conflicts = b.counters.installs
                        [InstallOutcome::Skipped(crate::table::SkipReason::MacConflict).index()],
                    backlog = b.pending.len(),
                    in_flight = b.in_flight.len(),
                    never_heard = b.cfg.peer_addrs().filter(|a| !b.heard_peers.contains(a)).count(),
                    "neigh-snoop stats"
                );
            }
        }
    }

    fn request_persist(&mut self, bi: usize, now: Instant) {
        let b = &mut self.bridges[bi];
        let json = persist::to_json(&b.table, &b.cfg.name, SystemTime::now());
        let job = PersistJob {
            bridge_idx: bi,
            path: persist::file_path(&self.persist_dir, &b.cfg.name),
            json,
        };
        match self.persist_tx.try_send(job) {
            Ok(()) => b.dirty_since = None,
            Err(mpsc::error::TrySendError::Full(_)) => b.dirty_since = Some(now),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                b.counters.persist(PersistOutcome::Failed);
                b.dirty_since = None;
            }
        }
    }

    fn reconfigure(&mut self, new: SnoopConfig) {
        let now = Instant::now();
        for nb in &new.bridges {
            if let Some(b) = self.bridges.iter_mut().find(|b| b.cfg.name == nb.name) {
                b.cfg.prefixes = nb.prefixes.clone();
                b.cfg.peers = nb.peers.clone();
            }
        }
        self.deny_macs = new.deny_macs.clone();
        for bi in 0..self.bridges.len() {
            self.purge_inadmissible(bi, now);
        }
        if new.hot.table_max != self.hot.table_max {
            for b in &mut self.bridges {
                let evicted = b.table.set_cap(new.hot.table_max as usize);
                for _ in &evicted {
                    b.counters.learn(LearnOutcome::Evicted);
                }
                if !evicted.is_empty() {
                    b.mark_dirty(now);
                }
            }
        }
        self.hot = new.hot.clone();
        self.publish_coverage_params();
        info!("neigh-snoop hot configuration applied");
    }

    fn publish_snapshot(&mut self, now: Instant) {
        let bridges = self
            .bridges
            .iter()
            .map(|b| {
                let mut counters = b.counters.clone();
                counters.frames_backpressure_dropped = b.backpressure.load(Ordering::Relaxed);
                // Silence is measured from the later of the last frame
                // and the last bring-up, so time spent down does not
                // count against a bridge that just came back.
                let silent_secs = if b.up {
                    match (b.last_frame, b.up_since) {
                        (Some(f), Some(u)) => Some(f.max(u)),
                        (f, u) => f.or(u),
                    }
                    .map(|t| now.duration_since(t).as_secs())
                } else {
                    None
                };
                let mut route_coverage = b.route_coverage.clone();
                if let (CoverageState::Measured(c), Some(at)) = (&mut route_coverage, b.coverage_at)
                {
                    c.age_secs = now.duration_since(at).as_secs();
                }
                let participant_coverage = match b.ifindex {
                    Some(ifi) => coverage::participant_coverage(&b.table, ifi, &self.mirror),
                    None => crate::snapshot::Ratio {
                        resolved: 0,
                        total: b.table.len() as u64,
                    },
                };
                let mut never_heard: Vec<IpAddr> = b
                    .cfg
                    .peer_addrs()
                    .filter(|a| !b.heard_peers.contains(a))
                    .collect();
                never_heard.sort();
                IfaceSnapshot {
                    name: b.cfg.name.clone(),
                    ifindex: b.ifindex,
                    link: b.link_state(),
                    promisc_confirmed: b.promisc_confirmed,
                    socket_error: b.socket_error.clone(),
                    silent_secs,
                    table_entries: b.table.len() as u64,
                    install_backlog: b.pending.len() as u64,
                    peers_total: b.cfg.peer_addrs().count() as u64,
                    never_heard,
                    route_coverage,
                    participant_coverage,
                    counters,
                }
            })
            .collect();
        if let Ok(mut s) = self.snapshot.write() {
            *s = Snapshot { bridges };
        }
    }

    /// The engine is exiting for a reason other than detach: stamp
    /// every bridge with the error so the last published snapshot reads
    /// Unhealthy instead of freezing on "capturing".
    fn fail_terminal(&mut self, why: &str) {
        for b in &mut self.bridges {
            b.socket_error = Some(why.to_string());
            b.counters.socket_errors += 1;
        }
    }

    /// Cancelled: close every socket, write every dirty table now
    /// (synchronously; shutdown is cold), publish the last snapshot.
    fn shutdown(&mut self) {
        for bi in 0..self.bridges.len() {
            self.close_capture(bi);
        }
        for b in &mut self.bridges {
            if b.dirty_since.is_some() {
                let path = persist::file_path(&self.persist_dir, &b.cfg.name);
                let json = persist::to_json(&b.table, &b.cfg.name, SystemTime::now());
                match persist::save(&path, &json) {
                    Ok(()) => b.counters.persist(PersistOutcome::Written),
                    Err(e) => {
                        b.counters.persist(PersistOutcome::Failed);
                        warn!(bridge = %b.cfg.name, error = %e, "final persist failed");
                    }
                }
                b.dirty_since = None;
            }
        }
        self.publish_snapshot(Instant::now());
        info!("neigh-snoop engine stopped; kernel STALE entries and the cache are left in place");
    }
}

impl IfaceState {
    fn link_state(&self) -> LinkState {
        match (self.ifindex, self.up) {
            (None, _) => LinkState::Absent,
            (Some(_), false) => LinkState::Down,
            (Some(_), true) => LinkState::Up,
        }
    }
}

/// Wrapper so the pump's exit reaches the engine as a message.
async fn run_pump(
    fd: std::os::fd::OwnedFd,
    bridge_idx: usize,
    ifindex: u32,
    tx: mpsc::Sender<EngineMsg>,
    dropped: Arc<AtomicU64>,
    cancel: CancellationToken,
) {
    let result = capture::pump(fd, bridge_idx, ifindex, tx.clone(), dropped, cancel).await;
    let _ = tx
        .send(EngineMsg::CaptureEnded {
            bridge_idx,
            ifindex,
            error: result.err(),
        })
        .await;
}

async fn installer(
    handle: Handle,
    mut rx: mpsc::Receiver<InstallJob>,
    ctl: mpsc::UnboundedSender<EngineMsg>,
) {
    while let Some(job) = rx.recv().await {
        if let Err(e) = netlink::install_stale(&handle, job.ifindex, job.ip, job.mac).await {
            let _ = ctl.send(EngineMsg::InstallFailed {
                bridge_idx: job.bridge_idx,
                ip: job.ip,
                error: e,
            });
        }
    }
}

async fn persister(mut rx: mpsc::Receiver<PersistJob>, ctl: mpsc::UnboundedSender<EngineMsg>) {
    while let Some(job) = rx.recv().await {
        let PersistJob {
            bridge_idx,
            path,
            json,
        } = job;
        let result = tokio::task::spawn_blocking(move || persist::save(&path, &json))
            .await
            .map_err(|e| format!("persist task: {e}"))
            .and_then(|r| r.map_err(|e| e.to_string()));
        let _ = ctl.send(EngineMsg::PersistDone { bridge_idx, result });
    }
}

async fn coverage_task(
    mut params: watch::Receiver<CoverageParams>,
    ctl: mpsc::UnboundedSender<EngineMsg>,
    cancel: CancellationToken,
) {
    // Strict check is what makes the RTA_OIF filter real. Without it
    // the dump is the whole table, so refuse to sample rather than
    // dump a million routes every tick.
    let strict = match netlink::new_strict_connection() {
        Ok((conn, handle, _)) => {
            tokio::spawn(conn);
            Ok(handle)
        }
        Err(e) => {
            warn!(error = %e, "strict-check netlink unavailable; route coverage disabled");
            Err(format!("strict-check netlink unavailable: {e}"))
        }
    };
    loop {
        let p = params.borrow_and_update().clone();
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(p.interval) => {}
            changed = params.changed() => {
                if changed.is_err() {
                    return;
                }
                continue;
            }
        }
        for (bi, ifindex) in p.bridges {
            let result = match &strict {
                Ok(h) => coverage::sample(h, ifindex).await,
                Err(e) => Err(e.clone()),
            };
            if ctl
                .send(EngineMsg::Coverage {
                    bridge_idx: bi,
                    ifindex,
                    result,
                })
                .is_err()
            {
                return;
            }
        }
    }
}
