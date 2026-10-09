//! The export loop: one [`Worker::tick`] every [`TICK`], on the module's
//! own thread. A reload, the ports and their pools, the samples, the
//! datagrams, coverage, and the snapshot health and metrics read.
//!
//! Every outside effect goes through a trait ([`SampleSource`], [`Ports`],
//! [`Transport`], [`VppDir`]), so the loop runs the same against fakes in
//! the tests as against the fast-path maps, sysfs, VPP's sampler
//! directory and a socket on a router.
//!
//! Each port is one sFlow data source, whichever paths sample it: one
//! sequence, and one pool counting what every path could have sampled
//! (rx_packets for its XDP or tc program, VPP's own count for the VPP
//! path, disjoint because steered ingress never reaches the kernel's
//! counter). Coverage is judged per path, a *lane*.

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use packetframe_common::flow_coverage::{
    CollectorSubmission, CoverageSnapshot, FlowCoverage, PathCoverage, PathState, Receipt,
};
use packetframe_fast_path::sample::{self, Disposition, SampleCfg};
use packetframe_sampler_shm::coverage::Coverage;

use crate::cfg::FlowExportConfig;
use crate::collector::{reconcile, send_all, send_until, CollectorState, Transport};
use crate::coverage::{PortCoverage, State, Window, WINDOW};
use crate::flows::{self, Domain, FlowCache, Now, Sampled};
use crate::ipfix_out::{IpfixOut, Privacy, RECORDS_PER_TICK};
use crate::pool::Accumulator;
use crate::sflow_out::{wire_frame, Exporter, Ready, FCS};
use crate::vpp::{NoVpp, Taken, VppDir, VppHealth, VppSide};
use packetframe_common::config::CollectorFormat;
use packetframe_common::fib::asn::AsnTable;
use packetframe_common::fib::IpPrefix;

pub const TICK: Duration = Duration::from_millis(100);
/// How often the port list and the pools are re-read.
pub const PORTS_EVERY: Duration = Duration::from_secs(1);
/// A VPP lane's startup grace: its interfaces appear only once VPP is up
/// and vpp-offload has attached them.
pub const VPP_STARTUP_GRACE: Duration = Duration::from_secs(60);
/// Flows the cache exports for a timeout in one tick, at most.
pub const EXPIRE_BUDGET: usize = 4096;
/// A sample is dated at most this far back. Further is no backlog (the
/// worker counts as stalled after a second), but a step of the wall clock
/// VPP's sample times are on, which must not date flows far back.
pub const MAX_SAMPLE_AGE: Duration = Duration::from_secs(10);
/// What stopping spends sending the flows still counting, within the
/// second a module's detach has: the samplers are stopped after it.
pub const STOP_FLUSH_WITHIN: Duration = Duration::from_millis(500);

/// The path a port's samples come by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Path {
    Xdp,
    Tc,
    Vpp,
    /// flow-export's kernel sampler, on a `kernel-sample` interface.
    Kernel,
}

impl Path {
    pub const ALL: [Path; 4] = [Path::Xdp, Path::Tc, Path::Vpp, Path::Kernel];

    pub fn name(self) -> &'static str {
        match self {
            Path::Xdp => "xdp",
            Path::Tc => "tc",
            Path::Vpp => "vpp",
            Path::Kernel => "kernel",
        }
    }
}

/// A fast-path port and the program on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    pub ifindex: u32,
    pub path: Path,
}

/// fast-path's sampler: its configuration map and its rings.
pub trait SampleSource {
    /// Apply the sampler's configuration (rate 0 is off).
    fn configure(&mut self, cfg: SampleCfg) -> Result<(), String>;
    /// Make the rings hold a few ticks of samples at `rate`. Their size
    /// is also what bounds one tick's work: a drain takes what they hold,
    /// and a burst beyond it is lost in them, which coverage reports.
    ///
    /// Rings being replaced leave the map first and are drained into
    /// `left`, so no sample is lost uncounted: each is either in `left` or
    /// a failed output the program counts. `left` is filled even when this
    /// fails.
    fn ensure_capacity(&mut self, rate: u32, left: &mut Leftover) -> Result<(), String>;
    /// Hand every sample event published since the last drain to `f`;
    /// return the samples the rings reported lost.
    fn drain(&mut self, f: &mut dyn FnMut(&[u8])) -> u64;
    /// The programs' cumulative count of samples they could not output
    /// (STATS `sample_emit_failed`), when it can be read.
    fn emit_failed(&mut self) -> Option<u64>;
    /// The clock the events' `ktime_ns` is on (`bpf_ktime_get_ns`:
    /// CLOCK_MONOTONIC), read now.
    fn clock_ns(&self) -> u64;
}

/// What replacing the rings left: the events the old ones held, and the
/// samples they reported lost.
#[derive(Debug, Default)]
pub struct Leftover {
    pub events: Vec<Vec<u8>>,
    pub lost: u64,
}

/// A reload for the worker to apply, and where it answers whether it did.
pub struct Reload {
    pub cfg: FlowExportConfig,
    pub done: std::sync::mpsc::Sender<Result<(), String>>,
}

/// How long `reconfigure` waits for the worker to answer a reload: ten of
/// its ticks.
pub const RELOAD_WAIT: Duration = Duration::from_secs(1);

/// The ports fast-path has attached, and what each counted.
pub trait Ports {
    fn ports(&mut self) -> Result<Vec<Port>, String>;
    /// The port's kernel `rx_packets`, `None` when unreadable.
    fn rx_packets(&mut self, port: &Port) -> Option<u64>;
}

/// What health and metrics read: written by the worker, copied out by
/// the loader's poll, so a busy worker never blocks a status read.
#[derive(Debug, Clone, Default)]
pub struct Published {
    pub rate: u32,
    pub header_bytes: u32,
    pub generation: u32,
    pub over_budget: bool,
    pub expanded: bool,
    /// One per port and path.
    pub ports: Vec<PortReport>,
    pub collectors: Vec<CollectorReport>,
    /// Samples exported, by path.
    pub samples_total: BTreeMap<Path, u64>,
    /// Samples fast-path's programs could not output, or its rings
    /// reported lost when that count cannot be read.
    pub lost_total: u64,
    pub ring_lost_total: u64,
    /// Samples lost on the way from VPP's plugin: its rings full or
    /// unreadable, or left in an epoch that ended.
    pub vpp_lost_total: u64,
    /// Samples from an interface no port stands for.
    pub unmapped_total: u64,
    pub undecodable_total: u64,
    pub unencodable_total: u64,
    pub datagrams_total: u64,
    /// Why the sampler's configuration could not be applied, if so.
    pub source_error: Option<String>,
    /// Why the port list could not be read, if so.
    pub ports_error: Option<String>,
    /// VPP's sampler, when vpp-offload is configured.
    pub vpp: Option<VppHealth>,
    /// The IPFIX flow cache, while a collector takes IPFIX.
    pub flows: Option<FlowsReport>,
    pub ipfix_messages_total: u64,
    /// Samples with no IP packet in them: in sFlow, not in a flow record.
    pub not_ip_total: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FlowsReport {
    pub active: usize,
    pub counts: flows::Counts,
    pub announcements: u64,
    pub records: u64,
}

#[derive(Debug, Clone)]
pub struct PortReport {
    pub name: String,
    pub ifindex: u32,
    pub path: Path,
    pub state: State,
    pub samples: u64,
    /// What this path could have sampled on the port.
    pub pool: u64,
}

#[derive(Debug, Clone)]
pub struct CollectorReport {
    pub name: String,
    pub addr: std::net::SocketAddr,
    pub kind: packetframe_common::config::CollectorKind,
    pub format: CollectorFormat,
    pub datagrams: u64,
    pub send_errors: u64,
    pub budget_drops: u64,
    pub failing: Option<String>,
}

/// The handles the module keeps: a reload to apply, the snapshot, the
/// heartbeat (milliseconds since `epoch`), why the worker panicked, if it
/// did, and the coverage published for consumers outside the module.
#[derive(Clone)]
pub struct Shared {
    pub epoch: Instant,
    pub heartbeat_ms: Arc<AtomicU64>,
    pub published: Arc<Mutex<Published>>,
    pub reload: Arc<Mutex<Option<Reload>>>,
    pub panicked: Arc<Mutex<Option<String>>>,
    pub coverage: Arc<FlowCoverage>,
}

impl Shared {
    pub fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            heartbeat_ms: Arc::new(AtomicU64::new(0)),
            published: Arc::default(),
            reload: Arc::default(),
            panicked: Arc::default(),
            coverage: Arc::default(),
        }
    }

    /// Time since the worker last ticked.
    pub fn heartbeat_age(&self, now: Instant) -> Duration {
        let at = Duration::from_millis(self.heartbeat_ms.load(Ordering::Relaxed));
        now.saturating_duration_since(self.epoch).saturating_sub(at)
    }

    /// Hand the worker a reload and wait for it to say whether it applied
    /// it, so a SIGHUP is reported applied only once it is. A worker that
    /// does not answer in time never sees it: the reload is withdrawn.
    pub fn request_reload(&self, cfg: FlowExportConfig, wait: Duration) -> Result<(), String> {
        let (done, answer) = std::sync::mpsc::channel();
        *self.reload.lock().unwrap_or_else(|e| e.into_inner()) = Some(Reload { cfg, done });
        match answer.recv_timeout(wait) {
            Ok(r) => r,
            Err(_) => {
                let withdrawn = self
                    .reload
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take()
                    .is_some();
                Err(if withdrawn {
                    format!(
                        "the export worker did not take the reload within {} ms: is it \
                         running? (the `worker` row says)",
                        wait.as_millis()
                    )
                } else {
                    "the export worker took the reload but did not answer in time".into()
                })
            }
        }
    }

    pub fn snapshot(&self) -> Published {
        self.published
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Why the worker panicked, if it did.
    pub fn panicked(&self) -> Option<String> {
        self.panicked
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// A port as sFlow's data source.
struct Source {
    name: String,
    sequence: u32,
    drops: u32,
    /// Its kernel `rx_packets`, read while a fast-path program is on it.
    kernel: Accumulator,
    /// What VPP's sampler counted on it.
    vpp: u64,
    lanes: BTreeMap<Path, Lane>,
}

impl Source {
    fn new(name: String) -> Self {
        Self {
            name,
            sequence: 0,
            drops: 0,
            kernel: Accumulator::default(),
            vpp: 0,
            lanes: BTreeMap::new(),
        }
    }

    /// The sFlow pool: what every path could have sampled.
    fn pool(&self) -> u64 {
        self.kernel.total().wrapping_add(self.vpp)
    }

    fn lane_pool(&self, path: Path) -> u64 {
        match path {
            Path::Vpp => self.vpp,
            Path::Xdp | Path::Tc | Path::Kernel => self.kernel.total(),
        }
    }
}

/// A lane a port should have: its path, and VPP's name for the port on
/// a VPP lane.
type LaneSpec = (Path, Option<String>);

/// One path on one port: its coverage and its window.
struct Lane {
    coverage: PortCoverage,
    /// VPP's name for the port, on a VPP lane.
    vpp_name: Option<String>,
    window_samples: u64,
    window_base: u64,
    samples: u64,
}

pub struct Worker<S, P, T, V = NoVpp> {
    cfg: FlowExportConfig,
    generation: u32,
    source: S,
    ports: P,
    transport: T,
    vpp: Option<VppSide<V>>,
    exporter: Exporter,
    collectors: Vec<CollectorState>,
    /// fast-path's ports, as last read.
    fast: Vec<Port>,
    sources: BTreeMap<u32, Source>,
    shared: Shared,
    next_ports: Instant,
    next_window: Instant,
    window_lost: u64,
    vpp_window_lost: u64,
    last_emit_failed: Option<u64>,
    /// Loss not yet carried by a sample, for the next one's `drops`: by
    /// fast-path's programs, and by VPP's plugin.
    pending_drops: u32,
    vpp_pending_drops: u32,
    /// What the last ring replacement left, for the next tick to export.
    leftover: Leftover,
    /// The IPFIX flow cache and its exporters, while a collector takes
    /// IPFIX.
    flows: Option<Flows>,
    /// Origin ASes, when fast-path's route source publishes them.
    asn: Option<Arc<AsnTable>>,
    /// The wall clock at `shared.epoch`, in Unix milliseconds: the times
    /// flow records carry.
    wall_epoch_ms: u64,
    p: Published,
}

/// The flow cache, and an exporter for each privacy profile an IPFIX
/// collector takes: one cache, so each profile sends the same flows.
struct Flows {
    cache: FlowCache,
    outs: Vec<IpfixOut>,
    /// Which pending domain a tick's budget goes to first, turn about: a
    /// domain with a standing backlog cannot starve the others.
    turn: usize,
}

impl Flows {
    fn new(cfg: &FlowExportConfig) -> Option<Self> {
        let profiles = cfg.ipfix_profiles();
        (!profiles.is_empty()).then(|| Self {
            cache: FlowCache::new(cfg.cache),
            outs: profiles.into_iter().map(IpfixOut::new).collect(),
            turn: 0,
        })
    }
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

impl<S: SampleSource, P: Ports, T: Transport> Worker<S, P, T, NoVpp> {
    /// Configure the sampler at generation 1: a failure here fails the
    /// attach.
    pub fn new(
        cfg: FlowExportConfig,
        mut source: S,
        ports: P,
        transport: T,
        shared: Shared,
        now: Instant,
    ) -> Result<Self, String> {
        source.ensure_capacity(cfg.rate, &mut Leftover::default())?;
        source.configure(SampleCfg::new(cfg.rate, cfg.header_bytes, 1))?;
        let collectors = cfg
            .collectors
            .iter()
            .cloned()
            .map(CollectorState::new)
            .collect();
        let flows = Flows::new(&cfg);
        let wall_epoch_ms = wall_ms()
            .saturating_sub(now.saturating_duration_since(shared.epoch).as_millis() as u64);
        Ok(Self {
            flows,
            asn: None,
            wall_epoch_ms,
            exporter: Exporter::new(cfg.source),
            cfg,
            generation: 1,
            source,
            ports,
            transport,
            vpp: None,
            collectors,
            fast: Vec::new(),
            sources: BTreeMap::new(),
            shared,
            next_ports: now,
            next_window: now + WINDOW,
            window_lost: 0,
            vpp_window_lost: 0,
            last_emit_failed: None,
            pending_drops: 0,
            vpp_pending_drops: 0,
            leftover: Leftover::default(),
            p: Published::default(),
        })
    }

    /// Sample VPP's ports too, through its sampler plugin.
    pub fn with_vpp<W: VppDir>(self, vpp: VppSide<W>) -> Worker<S, P, T, W> {
        Worker {
            cfg: self.cfg,
            generation: self.generation,
            source: self.source,
            ports: self.ports,
            transport: self.transport,
            vpp: Some(vpp),
            exporter: self.exporter,
            collectors: self.collectors,
            fast: self.fast,
            sources: self.sources,
            shared: self.shared,
            next_ports: self.next_ports,
            next_window: self.next_window,
            window_lost: self.window_lost,
            vpp_window_lost: self.vpp_window_lost,
            last_emit_failed: self.last_emit_failed,
            pending_drops: self.pending_drops,
            vpp_pending_drops: self.vpp_pending_drops,
            leftover: self.leftover,
            flows: self.flows,
            asn: self.asn,
            wall_epoch_ms: self.wall_epoch_ms,
            p: self.p,
        }
    }
}

impl<S: SampleSource, P: Ports, T: Transport, V: VppDir> Worker<S, P, T, V> {
    /// Fill flow records' AS fields from `asn`.
    pub fn with_asn(mut self, asn: Option<Arc<AsnTable>>) -> Self {
        self.asn = asn;
        self
    }

    pub fn tick(&mut self, now: Instant) {
        let reload = self
            .shared
            .reload
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(Reload { cfg, done }) = reload {
            let _ = done.send(self.apply(now, cfg));
        }
        let taken = self
            .vpp
            .as_mut()
            .map(|v| v.tick(now, self.cfg.rate, self.cfg.header_bytes));
        // A VPP port first seen is a lane at once, not a second later.
        let new_vpp_port = self.vpp.as_ref().is_some_and(|v| {
            v.ports().any(|p| {
                self.sources
                    .get(&p.ifindex)
                    .is_none_or(|s| !s.lanes.contains_key(&Path::Vpp))
            })
        });
        if now >= self.next_ports || new_vpp_port {
            self.refresh_ports(now);
            self.next_ports = now + PORTS_EVERY;
        }
        let mut ready = self.take_samples();
        if let Some(t) = taken {
            self.take_vpp(t, &mut ready);
        }
        let sflow = self
            .collectors
            .iter()
            .any(|c| c.cfg.format == CollectorFormat::Sflow);
        if sflow && !ready.is_empty() {
            let mut datagrams = Vec::new();
            let uptime_ms = now.saturating_duration_since(self.shared.epoch).as_millis() as u32;
            self.p.unencodable_total +=
                self.exporter.encode(&ready, uptime_ms, &mut datagrams) as u64;
            self.p.datagrams_total += datagrams.len() as u64;
            send_all(
                &self.transport,
                &mut self.collectors,
                |c| c.format == CollectorFormat::Sflow,
                &datagrams,
                now,
            );
        }
        self.export_ipfix(&ready, now);
        if now >= self.next_window {
            self.judge(now);
            self.next_window = now + WINDOW;
        }
        self.publish(now);
        let ms = now.saturating_duration_since(self.shared.epoch).as_millis() as u64;
        self.shared.heartbeat_ms.store(ms, Ordering::Relaxed);
    }

    /// The tick's samples into the flow cache, by observation domain;
    /// flows past a timeout out of it, as IPFIX for its collectors.
    fn export_ipfix(&mut self, ready: &[Ready], now: Instant) {
        let Some(flows) = &mut self.flows else {
            return;
        };
        let cache = &mut flows.cache;
        let ms = now.saturating_duration_since(self.shared.epoch).as_millis() as u64;
        let at = Now {
            ms,
            wall_ms: self.wall_epoch_ms + ms,
        };
        let mut batches: BTreeMap<Domain, Vec<Sampled>> = BTreeMap::new();
        for r in ready {
            let Some(packet) = flows::parse(&r.header) else {
                self.p.not_ip_total += 1;
                continue;
            };
            let domain = match r.path {
                Path::Vpp => Domain::Vpp,
                Path::Xdp | Path::Tc => Domain::FastPath,
                Path::Kernel => Domain::Kernel,
            };
            batches.entry(domain).or_default().push(Sampled {
                packet,
                generation: r.generation,
                rate: r.rate,
                input_if: r.source_if,
                output_if: r.output_if,
                at: Now {
                    ms: at.ms.saturating_sub(r.age_ms),
                    wall_ms: at.wall_ms.saturating_sub(r.age_ms),
                },
            });
        }
        for (domain, batch) in &batches {
            cache.ingest(*domain, batch);
        }
        cache.expire(at, EXPIRE_BUDGET);
        self.send_flows(now, at, RECORDS_PER_TICK, None);
    }

    /// The local prefixes: the section's, else fast-path's allowlist as
    /// this configuration took it.
    fn local(&self) -> Vec<IpPrefix> {
        if self.cfg.local.is_empty() {
            self.cfg.local_default.clone()
        } else {
            self.cfg.local.clone()
        }
    }

    /// Up to `max` of the cache's exports, through each profile's
    /// exporter to that profile's collectors: within each collector's
    /// per-tick budget, or with `until` (a stop), past it until then. The
    /// datagrams a deadline left unsent.
    fn send_flows(&mut self, now: Instant, at: Now, max: usize, until: Option<Instant>) -> usize {
        let local = self.local();
        let Some(flows) = &mut self.flows else {
            return 0;
        };
        let privacy = Privacy {
            local: &local,
            asn: self.asn.as_deref(),
        };
        let mut pending = flows.cache.pending();
        if !pending.is_empty() {
            let n = pending.len();
            pending.rotate_left(flows.turn % n);
            flows.turn = flows.turn.wrapping_add(1);
        }
        let mut left = max;
        let mut unsent = 0;
        for domain in pending {
            if left == 0 {
                break;
            }
            let items = flows.cache.take(domain, left);
            left -= items.len();
            for out in &mut flows.outs {
                let mut messages = Vec::new();
                out.encode(
                    domain,
                    &items,
                    &privacy,
                    now,
                    (at.wall_ms / 1000) as u32,
                    &mut messages,
                );
                self.p.ipfix_messages_total += messages.len() as u64;
                let profile = out.profile();
                let to = |c: &crate::cfg::Collector| {
                    c.format == CollectorFormat::Ipfix && c.profile == profile
                };
                match until {
                    None => send_all(&self.transport, &mut self.collectors, to, &messages, now),
                    Some(deadline) => {
                        unsent += send_until(
                            &self.transport,
                            &mut self.collectors,
                            to,
                            &messages,
                            deadline,
                        )
                    }
                }
            }
        }
        unsent
    }

    /// Stop sampling: fast-path's programs (rate 0) and VPP's plugin (its
    /// `desired.conf` removed), each tried whatever became of the other.
    /// The flows still counting go to the IPFIX collectors first, past the
    /// per-tick send budget, for up to [`STOP_FLUSH_WITHIN`]: a tick's
    /// worth of records at a time, so a full cache is never encoded at
    /// once.
    pub fn stop(&mut self) -> Result<(), String> {
        if let Some(flows) = &mut self.flows {
            let now = Instant::now();
            let deadline = now + STOP_FLUSH_WITHIN;
            let ms = now.saturating_duration_since(self.shared.epoch).as_millis() as u64;
            flows.cache.drain();
            let at = Now {
                ms,
                wall_ms: self.wall_epoch_ms + ms,
            };
            let mut unsent = 0;
            while self
                .flows
                .as_ref()
                .is_some_and(|f| !f.cache.pending().is_empty())
                && Instant::now() < deadline
            {
                unsent += self.send_flows(now, at, RECORDS_PER_TICK, Some(deadline));
            }
            let unencoded = self.flows.as_ref().map_or(0, |f| f.cache.queued());
            if unsent > 0 || unencoded > 0 {
                tracing::warn!(
                    unsent_messages = unsent,
                    unencoded_records = unencoded,
                    "flow-export: stopping ran out of time to send every flow still counting"
                );
            }
        }
        let fast = self.source.configure(SampleCfg::new(
            0,
            self.cfg.header_bytes,
            self.generation + 1,
        ));
        let vpp = self.vpp.as_mut().map_or(Ok(()), VppSide::stop);
        match (fast, vpp) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) | (Ok(()), Err(e)) => Err(e),
            (Err(a), Err(b)) => Err(format!("{a}; {b}")),
        }
    }

    /// Apply a reload, or none of it: on a failure the sampler, the
    /// collectors and what is published stay as they were, so the same
    /// reload retried is tried again rather than taken as applied. VPP's
    /// plugin takes the new rate from the next tick's `desired.conf`, and
    /// its row says once it has.
    fn apply(&mut self, now: Instant, new: FlowExportConfig) -> Result<(), String> {
        if (new.rate, new.header_bytes) != (self.cfg.rate, self.cfg.header_bytes) {
            let generation = self.generation + 1;
            let r = self
                .source
                .ensure_capacity(new.rate, &mut self.leftover)
                .and_then(|()| {
                    self.source
                        .configure(SampleCfg::new(new.rate, new.header_bytes, generation))
                });
            if let Err(e) = r {
                let e = format!(
                    "a reload to 1:{} with {} header bytes could not be applied: {e}",
                    new.rate, new.header_bytes
                );
                self.p.source_error = Some(e.clone());
                return Err(e);
            }
            // The window so far was drawn at the old rate: judge it at that
            // rate, and start the next at the new one.
            self.judge(now);
            self.next_window = now + WINDOW;
            self.generation = generation;
            self.p.source_error = None;
        }
        match (&mut self.flows, new.ipfix()) {
            (None, true) => self.flows = Flows::new(&new),
            // No one to send flows to: what the cache held goes with it.
            (Some(_), false) => self.flows = None,
            (Some(flows), true) => {
                flows.cache.set_limits(new.cache);
                // A profile's exporter keeps its sequence numbers while it
                // has a collector; a collector new to it has seen no
                // template.
                let profiles = new.ipfix_profiles();
                flows.outs.retain(|o| profiles.contains(&o.profile()));
                for p in profiles {
                    let joined = new.collectors.iter().any(|c| {
                        c.format == CollectorFormat::Ipfix
                            && c.profile == p
                            && !self.cfg.collectors.contains(c)
                    });
                    match flows.outs.iter_mut().find(|o| o.profile() == p) {
                        Some(o) if joined => o.reannounce(),
                        Some(_) => {}
                        None => flows.outs.push(IpfixOut::new(p)),
                    }
                }
            }
            (None, false) => {}
        }
        self.collectors = reconcile(std::mem::take(&mut self.collectors), &new.collectors);
        self.cfg = new;
        Ok(())
    }

    fn refresh_ports(&mut self, now: Instant) {
        match self.ports.ports() {
            Ok(list) => {
                self.p.ports_error = None;
                self.fast = list;
            }
            // The last list stands: an unreadable registry is not a port
            // that went away.
            Err(e) => self.p.ports_error = Some(e),
        }
        // Each port's lanes: its fast-path program, and VPP when it is a
        // VPP member port. A port whose name changed is another port.
        let mut want: BTreeMap<u32, (String, Vec<LaneSpec>)> = BTreeMap::new();
        for p in &self.fast {
            want.entry(p.ifindex)
                .or_insert_with(|| (p.name.clone(), Vec::new()))
                .1
                .push((p.path, None));
        }
        if let Some(v) = &self.vpp {
            for p in v.ports() {
                want.entry(p.ifindex)
                    .or_insert_with(|| (p.port.clone(), Vec::new()))
                    .1
                    .push((Path::Vpp, Some(p.vpp_name.clone())));
            }
        }
        self.sources
            .retain(|i, s| want.get(i).is_some_and(|(name, _)| *name == s.name));
        for (ifindex, (name, lanes)) in want {
            let s = self
                .sources
                .entry(ifindex)
                .or_insert_with(|| Source::new(name));
            s.lanes
                .retain(|path, _| lanes.iter().any(|(p, _)| p == path));
            for (path, vpp_name) in lanes {
                let base = s.lane_pool(path);
                s.lanes.entry(path).or_insert_with(|| Lane {
                    coverage: PortCoverage::with_grace(
                        now,
                        match path {
                            Path::Vpp => VPP_STARTUP_GRACE,
                            Path::Xdp | Path::Tc | Path::Kernel => crate::coverage::STARTUP_GRACE,
                        },
                    ),
                    vpp_name,
                    window_samples: 0,
                    window_base: base,
                    samples: 0,
                });
            }
        }
        for port in &self.fast {
            if let Some(rx) = self.ports.rx_packets(port) {
                if let Some(s) = self.sources.get_mut(&port.ifindex) {
                    s.kernel.observe(rx);
                }
            }
        }
    }

    fn take_samples(&mut self) -> Vec<Ready> {
        let mut ready = Vec::new();
        let left = std::mem::take(&mut self.leftover);
        let clock = self.source.clock_ns();
        let (sources, p, pending) = (&mut self.sources, &mut self.p, &mut self.pending_drops);
        for e in &left.events {
            ingest(e, clock, sources, p, pending, &mut ready);
        }
        let ring_lost = left.lost
            + self
                .source
                .drain(&mut |e| ingest(e, clock, sources, p, pending, &mut ready));
        self.p.ring_lost_total += ring_lost;
        // The programs' own count covers both a full ring and a CPU with
        // none; the rings' count is a full ring only, and the same
        // samples. One or the other, never both. A tick it cannot be read
        // ends its baseline: the next reading starts a new one rather than
        // counting the gap's losses a second time.
        let emit_failed = self.source.emit_failed();
        let lost = match (emit_failed, self.last_emit_failed) {
            (Some(now), Some(before)) => now.saturating_sub(before),
            (Some(_), None) => 0,
            (None, _) => ring_lost,
        };
        self.last_emit_failed = emit_failed;
        self.window_lost += lost;
        self.p.lost_total += lost;
        self.pending_drops = self.pending_drops.wrapping_add(lost as u32);
        ready
    }

    /// VPP's tick: its pools first, so its samples carry them.
    fn take_vpp(&mut self, t: Taken, ready: &mut Vec<Ready>) {
        for (ifindex, n) in t.pools {
            if let Some(s) = self.sources.get_mut(&ifindex) {
                s.vpp = s.vpp.wrapping_add(n);
            }
        }
        // A sample that cannot be read is lost to the collectors as surely
        // as one a full ring dropped: VPP's lanes and its next sample's
        // drops count both.
        let lost = t.lost + t.unmapped;
        self.vpp_window_lost += lost;
        self.p.vpp_lost_total += t.lost;
        self.p.unmapped_total += t.unmapped;
        self.vpp_pending_drops = self.vpp_pending_drops.wrapping_add(lost as u32);
        for s in t.samples {
            let Some(src) = self.sources.get_mut(&s.ifindex) else {
                self.p.unmapped_total += 1;
                self.vpp_window_lost += 1;
                self.vpp_pending_drops = self.vpp_pending_drops.wrapping_add(1);
                continue;
            };
            src.sequence = src.sequence.wrapping_add(1);
            src.drops = src
                .drops
                .wrapping_add(std::mem::take(&mut self.vpp_pending_drops));
            if let Some(l) = src.lanes.get_mut(&Path::Vpp) {
                l.window_samples += 1;
                l.samples += 1;
            }
            *self.p.samples_total.entry(Path::Vpp).or_default() += 1;
            ready.push(Ready {
                sequence: src.sequence,
                source_if: s.ifindex,
                rate: s.rate,
                pool: src.pool() as u32,
                drops: src.drops,
                // VPP's sampler sees ingress; the output is not known.
                output_if: 0,
                frame_length: s.frame_len + FCS,
                header: s.header,
                path: Path::Vpp,
                generation: s.generation,
                age_ms: age_ms(t.now_realtime_ns, s.time_ns),
            });
        }
    }

    fn judge(&mut self, now: Instant) {
        for s in self.sources.values_mut() {
            let (vpp, kernel) = (s.vpp, s.kernel.total());
            for (path, lane) in s.lanes.iter_mut() {
                let pool = match path {
                    Path::Vpp => vpp,
                    Path::Xdp | Path::Tc | Path::Kernel => kernel,
                };
                lane.coverage.judge(
                    now,
                    Window {
                        samples: lane.window_samples,
                        lost: match path {
                            Path::Vpp => self.vpp_window_lost,
                            Path::Xdp | Path::Tc | Path::Kernel => self.window_lost,
                        },
                        packets: pool.saturating_sub(lane.window_base),
                        rate: self.cfg.rate,
                    },
                );
                lane.window_samples = 0;
                lane.window_base = pool;
            }
        }
        self.window_lost = 0;
        self.vpp_window_lost = 0;
        if let Some(v) = &mut self.vpp {
            v.end_window();
        }
    }

    fn publish(&mut self, now: Instant) {
        self.p.rate = self.cfg.rate;
        self.p.header_bytes = self.cfg.header_bytes;
        self.p.generation = self.generation;
        self.p.over_budget = self.cfg.over_budget();
        self.p.expanded = self.exporter.expanded();
        let vpp = self.vpp.as_ref().map(|v| v.health().clone());
        self.p.ports = self
            .sources
            .iter()
            .flat_map(|(ifindex, s)| {
                let vpp = vpp.as_ref();
                s.lanes.iter().map(move |(path, lane)| PortReport {
                    name: s.name.clone(),
                    ifindex: *ifindex,
                    path: *path,
                    state: match path {
                        Path::Vpp => held_to(lane.coverage.state(), vpp, lane.vpp_name.as_deref()),
                        Path::Xdp | Path::Tc | Path::Kernel => lane.coverage.state().clone(),
                    },
                    samples: lane.samples,
                    pool: s.lane_pool(*path),
                })
            })
            .collect();
        self.p.vpp = vpp;
        self.p.flows = self.flows.as_ref().map(|f| FlowsReport {
            active: f.cache.active(),
            counts: f.cache.counts,
            announcements: f.outs.iter().map(|o| o.announcements).sum(),
            records: f.outs.iter().map(|o| o.records).sum(),
        });
        self.p.collectors = self
            .collectors
            .iter()
            .map(|c| CollectorReport {
                name: c.cfg.name.clone(),
                addr: c.cfg.addr,
                kind: c.cfg.kind,
                format: c.cfg.format,
                datagrams: c.datagrams,
                send_errors: c.send_errors,
                budget_drops: c.budget_drops,
                failing: c.failing(now),
            })
            .collect();
        self.shared.coverage.publish(coverage_of(&self.p, now));
        *self
            .shared
            .published
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = self.p.clone();
    }
}

/// What the published snapshot vouches for, as consumers outside the
/// module read it.
fn coverage_of(p: &Published, now: Instant) -> CoverageSnapshot {
    CoverageSnapshot {
        taken: now,
        rate: p.rate,
        paths: p
            .ports
            .iter()
            .map(|r| PathCoverage {
                port: r.name.clone(),
                ifindex: r.ifindex,
                path: r.path.name(),
                state: match &r.state {
                    State::Starting => PathState::Starting,
                    State::Covered => PathState::Covered,
                    State::Degraded(why) => PathState::Degraded(why.clone()),
                    State::Uncovered(why) => PathState::Uncovered(why.clone()),
                },
                samples: r.samples,
                pool: r.pool,
            })
            .collect(),
        collectors: p
            .collectors
            .iter()
            .map(|c| CollectorSubmission {
                name: c.name.clone(),
                addr: c.addr,
                kind: c.kind,
                datagrams: c.datagrams,
                failing: c.failing.clone(),
                receipt: Receipt::Unverified,
            })
            .collect(),
    }
}

/// A VPP lane's state, held to what the plugin as a whole shows: a lane
/// that saw nothing wrong in its own samples is still uncovered while the
/// plugin is gone, or its interface missing from VPP.
fn held_to(lane: &State, vpp: Option<&VppHealth>, vpp_name: Option<&str>) -> State {
    let Some(h) = vpp else {
        return lane.clone();
    };
    if *lane == State::Starting {
        return State::Starting;
    }
    let held = match h.coverage {
        Coverage::Healthy | Coverage::ZeroTraffic | Coverage::Partial => vpp_name
            .filter(|n| h.missing.contains(*n))
            .map(|n| State::Uncovered(format!("VPP has no interface {n}"))),
        Coverage::Degraded => Some(State::Degraded(format!("VPP's sampler: {}", h.why))),
        Coverage::Disabled | Coverage::Unavailable | Coverage::Incompatible => Some(
            State::Uncovered(format!("VPP's sampler is {}: {}", h.coverage.name(), h.why)),
        ),
    };
    match held {
        Some(h) if h.level() < lane.level() => h,
        _ => lane.clone(),
    }
}

/// How long before `now_ns` a sample taken at `at_ns` on the same clock
/// was, in milliseconds, within [`MAX_SAMPLE_AGE`].
fn age_ms(now_ns: u64, at_ns: u64) -> u64 {
    let age = Duration::from_nanos(now_ns.saturating_sub(at_ns)).min(MAX_SAMPLE_AGE);
    age.as_millis() as u64
}

/// One fast-path sample event: its port's sequence, drops and window, and
/// the sample as sFlow will carry it. `clock_ns`: the programs' clock now.
fn ingest(
    event: &[u8],
    clock_ns: u64,
    sources: &mut BTreeMap<u32, Source>,
    p: &mut Published,
    pending: &mut u32,
    ready: &mut Vec<Ready>,
) {
    let s = match sample::parse(event) {
        Ok(s) => s,
        Err(_) => {
            p.undecodable_total += 1;
            return;
        }
    };
    let Some(src) = sources.get_mut(&s.ingress_ifindex) else {
        p.unmapped_total += 1;
        return;
    };
    let path = match s.path {
        sample::Path::Xdp => Path::Xdp,
        sample::Path::Tc => Path::Tc,
        sample::Path::Kernel => Path::Kernel,
    };
    src.sequence = src.sequence.wrapping_add(1);
    src.drops = src.drops.wrapping_add(std::mem::take(pending));
    if let Some(l) = src.lanes.get_mut(&path) {
        l.window_samples += 1;
        l.samples += 1;
    }
    *p.samples_total.entry(path).or_default() += 1;
    let (header, frame_length) = wire_frame(&s);
    ready.push(Ready {
        sequence: src.sequence,
        source_if: s.ingress_ifindex,
        rate: s.rate,
        pool: src.pool() as u32,
        drops: src.drops,
        output_if: match s.disposition {
            Disposition::Redirect => s.egress_ifindex,
            _ => 0,
        },
        frame_length,
        header,
        path,
        generation: u64::from(s.generation),
        age_ms: age_ms(clock_ns, s.ktime_ns),
    });
}

/// The worker thread's loop: a tick every [`TICK`] until `stop`, then the
/// samplers stopped. A panic ends it the same way, except that a worker
/// that panicked is not trusted to stop anything: it is dropped (its
/// locks and rings with it), `after_panic` stops the samplers from
/// outside, and the `worker` row says why.
pub fn run<S, P, T, V>(
    mut worker: Worker<S, P, T, V>,
    stop: &AtomicBool,
    after_panic: impl FnOnce(),
) where
    S: SampleSource,
    P: Ports,
    T: Transport,
    V: VppDir,
{
    let shared = worker.shared.clone();
    let r = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut next = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            worker.tick(Instant::now());
            next += TICK;
            let now = Instant::now();
            match next.checked_duration_since(now) {
                Some(d) => std::thread::sleep(d),
                None => next = now,
            }
        }
        if let Err(e) = worker.stop() {
            tracing::warn!(error = %e, "flow-export: stopping the samplers failed");
        }
    }));
    // Stopped either way: nothing it published holds any longer.
    shared.coverage.withdraw();
    if let Err(payload) = r {
        let why = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "a panic with no message".into());
        tracing::error!(panic = %why, "flow-export: the export worker panicked; sampling is stopped");
        *shared.panicked.lock().unwrap_or_else(|e| e.into_inner()) = Some(why);
        drop(worker);
        after_panic();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::Collector;
    use packetframe_common::config::CollectorKind;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::rc::Rc;

    #[derive(Default)]
    struct FakeSource {
        cfgs: Rc<RefCell<Vec<SampleCfg>>>,
        events: Rc<RefCell<VecDeque<Vec<u8>>>>,
        ring_lost: Rc<RefCell<u64>>,
        emit_failed: Rc<RefCell<Option<u64>>>,
        refuse: bool,
        /// The next ring replacement fails.
        capacity_fails: Rc<RefCell<bool>>,
        /// What the replaced rings held.
        held: Rc<RefCell<Vec<Vec<u8>>>>,
        /// The next drain panics.
        panics: Rc<RefCell<bool>>,
        /// The programs' clock; the events are sampled at 7 ns.
        clock_ns: Rc<RefCell<u64>>,
    }

    impl SampleSource for FakeSource {
        fn configure(&mut self, cfg: SampleCfg) -> Result<(), String> {
            if self.refuse {
                return Err("SAMPLE_CFG: EPERM".into());
            }
            self.cfgs.borrow_mut().push(cfg);
            Ok(())
        }
        fn ensure_capacity(&mut self, _: u32, left: &mut Leftover) -> Result<(), String> {
            left.events.append(&mut self.held.borrow_mut());
            if *self.capacity_fails.borrow() {
                return Err("perf rings: ENOMEM".into());
            }
            Ok(())
        }
        fn drain(&mut self, f: &mut dyn FnMut(&[u8])) -> u64 {
            if *self.panics.borrow() {
                panic!("ring fault");
            }
            let mut q = self.events.borrow_mut();
            while let Some(e) = q.pop_front() {
                f(&e);
            }
            std::mem::take(&mut *self.ring_lost.borrow_mut())
        }
        fn emit_failed(&mut self) -> Option<u64> {
            *self.emit_failed.borrow()
        }
        fn clock_ns(&self) -> u64 {
            *self.clock_ns.borrow()
        }
    }

    #[derive(Default)]
    struct FakePorts {
        list: Rc<RefCell<Vec<Port>>>,
        rx: Rc<RefCell<BTreeMap<u32, u64>>>,
    }

    impl Ports for FakePorts {
        fn ports(&mut self) -> Result<Vec<Port>, String> {
            Ok(self.list.borrow().clone())
        }
        fn rx_packets(&mut self, p: &Port) -> Option<u64> {
            self.rx.borrow().get(&p.ifindex).copied()
        }
    }

    type Sent = Rc<RefCell<Vec<(SocketAddr, Vec<u8>)>>>;

    #[derive(Default, Clone)]
    struct FakeNet {
        sent: Sent,
    }

    impl Transport for FakeNet {
        fn send_to(&self, buf: &[u8], to: SocketAddr) -> std::io::Result<usize> {
            self.sent.borrow_mut().push((to, buf.to_vec()));
            Ok(buf.len())
        }
    }

    /// A sample event as fast-path's program emits it.
    fn event(ingress: u32, egress: u32, disposition: u32, rate: u32, generation: u32) -> Vec<u8> {
        event_with(ingress, egress, disposition, rate, generation, &[0x5a; 64])
    }

    /// A sample of an Ethernet + IPv4 + TCP frame to `dport`.
    fn ip_event(ingress: u32, dport: u16, rate: u32, generation: u32) -> Vec<u8> {
        let mut f = vec![0x02; 12];
        f.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0x03, 0xda, 0, 0, 0, 0, 64, 6, 0, 0]);
        f.extend_from_slice(&[192, 0, 2, 7, 198, 51, 100, 9]);
        f.extend_from_slice(&40000u16.to_be_bytes());
        f.extend_from_slice(&dport.to_be_bytes());
        f.resize(64, 0);
        event_with(ingress, 0, 0, rate, generation, &f)
    }

    fn event_with(
        ingress: u32,
        egress: u32,
        disposition: u32,
        rate: u32,
        generation: u32,
        header: &[u8],
    ) -> Vec<u8> {
        let mut e = 7u64.to_ne_bytes().to_vec();
        for w in [
            generation,
            rate,
            ingress,
            egress,
            1500,
            header.len() as u32,
            1 | disposition << 8,
            0,
        ] {
            e.extend_from_slice(&w.to_ne_bytes());
        }
        e.extend_from_slice(header);
        e
    }

    fn cfg(rate: u32) -> FlowExportConfig {
        FlowExportConfig {
            source: "192.0.2.1".parse().unwrap(),
            rate,
            header_bytes: 64,
            collectors: vec![Collector {
                name: "fnm".into(),
                addr: "198.51.100.10:6343".parse().unwrap(),
                kind: CollectorKind::Ddos,
                format: CollectorFormat::Sflow,
                profile: Default::default(),
            }],
            cache: flows::Limits::default(),
            local: Vec::new(),
            kernel: Vec::new(),
            local_default: Vec::new(),
        }
    }

    struct Rig<V: VppDir = NoVpp> {
        w: Worker<FakeSource, FakePorts, FakeNet, V>,
        src: FakeSource,
        ports: FakePorts,
        net: FakeNet,
        shared: Shared,
        t0: Instant,
    }

    fn rig(rate: u32) -> Rig {
        let t0 = Instant::now();
        let src = FakeSource::default();
        let ports = FakePorts::default();
        ports.list.borrow_mut().push(Port {
            name: "eth0".into(),
            ifindex: 3,
            path: Path::Xdp,
        });
        ports.rx.borrow_mut().insert(3, 1_000);
        let net = FakeNet::default();
        let shared = Shared::new(t0);
        let w = Worker::new(
            cfg(rate),
            FakeSource {
                cfgs: src.cfgs.clone(),
                events: src.events.clone(),
                ring_lost: src.ring_lost.clone(),
                emit_failed: src.emit_failed.clone(),
                refuse: false,
                capacity_fails: src.capacity_fails.clone(),
                held: src.held.clone(),
                panics: src.panics.clone(),
                clock_ns: src.clock_ns.clone(),
            },
            FakePorts {
                list: ports.list.clone(),
                rx: ports.rx.clone(),
            },
            net.clone(),
            shared.clone(),
            t0,
        )
        .unwrap();
        Rig {
            w,
            src,
            ports,
            net,
            shared,
            t0,
        }
    }

    fn reload(
        shared: &Shared,
        c: FlowExportConfig,
    ) -> std::sync::mpsc::Receiver<Result<(), String>> {
        let (done, answer) = std::sync::mpsc::channel();
        *shared.reload.lock().unwrap() = Some(Reload { cfg: c, done });
        answer
    }

    fn word(d: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(d[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn samples_reach_every_collector_as_sflow_with_their_pool_and_sequence() {
        let mut r = rig(1000);
        assert_eq!(r.src.cfgs.borrow()[0], SampleCfg::new(1000, 64, 1));
        r.w.tick(r.t0);
        r.ports.rx.borrow_mut().insert(3, 6_000);
        r.w.tick(r.t0 + PORTS_EVERY);
        r.src.events.borrow_mut().extend([
            event(3, 9, 2, 1000, 1),
            event(3, 0, 0, 1000, 1),
            event(77, 0, 0, 1000, 1),
        ]);
        r.w.tick(r.t0 + PORTS_EVERY + TICK);
        let sent = r.net.sent.borrow();
        assert_eq!(sent.len(), 1);
        let (to, d) = &sent[0];
        assert_eq!(to.to_string(), "198.51.100.10:6343");
        assert_eq!(word(d, 24), 2, "two samples; the unknown port's is not one");
        // First flow sample: format 1 (compact), then its fields.
        let s = 28;
        assert_eq!(word(d, s), 1);
        assert_eq!(word(d, s + 8), 1, "sequence");
        assert_eq!(word(d, s + 12), 3, "source ifIndex");
        assert_eq!(word(d, s + 16), 1000, "rate");
        assert_eq!(
            word(d, s + 20),
            5_000,
            "pool: rx_packets since the first reading"
        );
        assert_eq!(word(d, s + 28), 3, "input");
        assert_eq!(word(d, s + 32), 9, "output: the redirect's egress");
        let p = r.shared.snapshot();
        assert_eq!((p.samples_total[&Path::Xdp], p.unmapped_total), (2, 1));
        assert_eq!(p.ports[0].samples, 2);
        assert_eq!(p.collectors[0].datagrams, 1);
    }

    #[test]
    fn a_rate_change_is_a_new_generation_and_keeps_the_collectors() {
        let mut r = rig(1000);
        r.w.tick(r.t0);
        let answer = reload(&r.shared, cfg(4000));
        r.w.tick(r.t0 + TICK);
        assert_eq!(answer.try_recv().unwrap(), Ok(()));
        assert_eq!(
            r.src.cfgs.borrow().last(),
            Some(&SampleCfg::new(4000, 64, 2))
        );
        let p = r.shared.snapshot();
        assert_eq!((p.rate, p.generation), (4000, 2));
        // A collector-only change is no new generation.
        let mut c = cfg(4000);
        c.collectors[0].addr = "198.51.100.11:6343".parse().unwrap();
        let _ = reload(&r.shared, c);
        r.w.tick(r.t0 + 2 * TICK);
        assert_eq!(r.src.cfgs.borrow().len(), 2);
        assert_eq!(r.shared.snapshot().collectors[0].addr.port(), 6343);
    }

    #[test]
    fn loss_is_counted_once_and_degrades_every_port() {
        let mut r = rig(1000);
        *r.src.emit_failed.borrow_mut() = Some(10);
        r.w.tick(r.t0);
        // The program failed 5 more outputs, and the ring reported 5 lost:
        // the same samples.
        *r.src.emit_failed.borrow_mut() = Some(15);
        *r.src.ring_lost.borrow_mut() = 5;
        r.w.tick(r.t0 + TICK);
        let p = r.shared.snapshot();
        assert_eq!((p.lost_total, p.ring_lost_total), (5, 5));
        r.w.tick(r.t0 + WINDOW);
        assert!(matches!(
            r.shared.snapshot().ports[0].state,
            State::Degraded(_)
        ));
        // The next sample carries the loss in its drops.
        r.src.events.borrow_mut().push_back(event(3, 0, 0, 1000, 1));
        r.w.tick(r.t0 + WINDOW + TICK);
        let d = &r.net.sent.borrow()[0].1;
        assert_eq!(word(d, 28 + 24), 5, "drops");
    }

    #[test]
    fn a_reload_that_cannot_be_applied_changes_nothing_and_is_tried_again() {
        let mut r = rig(1000);
        r.w.tick(r.t0);
        *r.src.capacity_fails.borrow_mut() = true;
        let answer = reload(&r.shared, cfg(100));
        r.w.tick(r.t0 + TICK);
        let e = answer.try_recv().unwrap().unwrap_err();
        assert!(e.contains("1:100") && e.contains("ENOMEM"), "{e}");
        let p = r.shared.snapshot();
        assert_eq!(
            (p.rate, p.generation),
            (1000, 1),
            "still what the kernel has"
        );
        assert!(p.source_error.is_some());
        assert_eq!(r.src.cfgs.borrow().len(), 1, "SAMPLE_CFG untouched");
        // The same reload again, now that it can be applied: not mistaken
        // for the configuration already in place.
        *r.src.capacity_fails.borrow_mut() = false;
        let answer = reload(&r.shared, cfg(100));
        r.w.tick(r.t0 + 2 * TICK);
        assert_eq!(answer.try_recv().unwrap(), Ok(()));
        let p = r.shared.snapshot();
        assert_eq!((p.rate, p.generation), (100, 2));
        assert!(p.source_error.is_none());
    }

    #[test]
    fn samples_left_in_replaced_rings_are_exported() {
        let mut r = rig(1000);
        r.w.tick(r.t0);
        r.src.held.borrow_mut().push(event(3, 0, 0, 1000, 1));
        let _ = reload(&r.shared, cfg(100));
        r.w.tick(r.t0 + TICK);
        assert_eq!(r.shared.snapshot().samples_total[&Path::Xdp], 1);
        assert_eq!(r.net.sent.borrow().len(), 1);
    }

    #[test]
    fn a_rate_change_judges_the_window_so_far_at_the_old_rate() {
        let mut r = rig(1_000_000);
        r.w.tick(r.t0);
        let t = r.t0 + crate::coverage::STARTUP_GRACE + Duration::from_secs(1);
        r.w.tick(t);
        assert_eq!(r.shared.snapshot().ports[0].state, State::Covered);
        // 30 000 packets, no sample: nothing at 1:1000000, but silent at
        // 1:100.
        r.ports.rx.borrow_mut().insert(3, 31_000);
        r.w.tick(t + PORTS_EVERY);
        let answer = reload(&r.shared, cfg(100));
        r.w.tick(t + PORTS_EVERY + TICK);
        assert_eq!(answer.try_recv().unwrap(), Ok(()));
        assert_eq!(r.shared.snapshot().ports[0].state, State::Covered);
        // The next window starts at the reload and holds none of them.
        r.w.tick(t + PORTS_EVERY + TICK + WINDOW);
        assert_eq!(r.shared.snapshot().ports[0].state, State::Covered);
    }

    #[test]
    fn an_unreadable_loss_counter_starts_a_new_baseline() {
        let mut r = rig(1000);
        *r.src.emit_failed.borrow_mut() = Some(10);
        r.w.tick(r.t0);
        // Unreadable for a tick: the rings' count stands in.
        *r.src.emit_failed.borrow_mut() = None;
        *r.src.ring_lost.borrow_mut() = 3;
        r.w.tick(r.t0 + TICK);
        // Readable again, having counted those 3 and 7 before: a new
        // baseline, not 10 more.
        *r.src.emit_failed.borrow_mut() = Some(20);
        r.w.tick(r.t0 + 2 * TICK);
        assert_eq!(r.shared.snapshot().lost_total, 3);
        *r.src.emit_failed.borrow_mut() = Some(21);
        r.w.tick(r.t0 + 3 * TICK);
        assert_eq!(r.shared.snapshot().lost_total, 4);
    }

    #[test]
    fn a_reload_no_worker_takes_is_withdrawn() {
        let shared = Shared::new(Instant::now());
        let e = shared
            .request_reload(cfg(2000), Duration::from_millis(20))
            .unwrap_err();
        assert!(e.contains("did not take the reload"), "{e}");
        assert!(shared.reload.lock().unwrap().is_none());
    }

    #[test]
    fn a_sampler_that_will_not_take_its_configuration_fails_the_attach() {
        let r = Worker::new(
            cfg(1000),
            FakeSource {
                refuse: true,
                ..FakeSource::default()
            },
            FakePorts::default(),
            FakeNet::default(),
            Shared::new(Instant::now()),
            Instant::now(),
        );
        assert!(r.err().unwrap().contains("EPERM"));
    }

    use crate::vpp::tests::{applied, instance, rings, sample, FakeDir, Plugin, NOW_NS};
    use crate::vpp::EpochSwitch;
    use packetframe_common::sampler_ports::{SampledPort, VppPortsSnapshot, VppSamplerPorts};

    /// `rig` with VPP up as pid 10 on epoch 7: eth0 (also fast-path's) is
    /// its `octeon0/0`, index 1, and eth9 (VPP's alone) its `octeon1/0`,
    /// index 2.
    fn vpp_rig() -> (Rig<FakeDir>, Rc<RefCell<Plugin>>) {
        let r = rig(1000);
        let dir = FakeDir::default();
        let plugin = dir.0.clone();
        {
            let mut p = plugin.borrow_mut();
            p.switch = Some(EpochSwitch {
                from: None,
                to: 7,
                abandoned: 0,
            });
            p.epoch = Some(7);
            p.created_ns = NOW_NS;
            p.mappers.insert(7, 10);
            p.rings = rings(&[], 0);
        }
        let ports = Arc::new(VppSamplerPorts::new());
        let port = |port: &str, ifindex, vpp_name: &str, sw_if_index| SampledPort {
            port: port.into(),
            ifindex: Some(ifindex),
            vpp_name: vpp_name.into(),
            sw_if_index,
        };
        ports.publish(VppPortsSnapshot {
            instance: instance(10),
            ports: vec![
                port("eth0", 3, "octeon0/0", 1),
                port("eth9", 9, "octeon1/0", 2),
            ],
        });
        let side = VppSide::new(dir, ports, r.t0, NOW_NS - 1);
        let rig = Rig {
            w: r.w.with_vpp(side),
            src: r.src,
            ports: r.ports,
            net: r.net,
            shared: r.shared,
            t0: r.t0,
        };
        (rig, plugin)
    }

    fn lane(p: &Published, name: &str, path: Path) -> PortReport {
        p.ports
            .iter()
            .find(|r| r.name == name && r.path == path)
            .unwrap_or_else(|| panic!("no {name} {path:?} in {:?}", p.ports))
            .clone()
    }

    #[test]
    fn a_vpp_ports_samples_join_its_xdp_data_source() {
        let (mut r, plugin) = vpp_rig();
        r.w.tick(r.t0);
        assert_eq!(plugin.borrow().desired.as_ref().unwrap().generation, 1);
        {
            let mut p = plugin.borrow_mut();
            p.status = Some(applied(1, 1, 2));
            p.rings = rings(&[2000, 0], 0);
            p.queued = vec![sample(1, 1)];
        }
        r.ports.rx.borrow_mut().insert(3, 6_000);
        r.src.events.borrow_mut().push_back(event(3, 0, 0, 1000, 1));
        r.w.tick(r.t0 + PORTS_EVERY);
        let sent = r.net.sent.borrow();
        let d = &sent[0].1;
        assert_eq!(word(d, 24), 2);
        let (a, b) = (28, 28 + 8 + word(d, 32) as usize);
        assert_eq!(
            (word(d, a + 8), word(d, a + 12), word(d, a + 20)),
            (1, 3, 5_000),
            "XDP's sample: sequence 1, eth0, the kernel's pool"
        );
        assert_eq!(
            (word(d, b + 8), word(d, b + 12), word(d, b + 20)),
            (2, 3, 7_000),
            "VPP's: the same source's next sequence, and both paths' pool"
        );
        assert_eq!(word(d, b + 32), 0, "no output known");
        assert_eq!(word(d, b + 40 + 12), 1504, "frame length counts the FCS");
        let p = r.shared.snapshot();
        assert_eq!(
            (p.samples_total[&Path::Xdp], p.samples_total[&Path::Vpp]),
            (1, 1)
        );
        // As a consumer outside the module reads it.
        let c = r.shared.coverage.current(r.t0 + PORTS_EVERY).unwrap();
        let eth9 = c.paths.iter().find(|p| p.port == "eth9").unwrap();
        assert_eq!(
            (eth9.path, &eth9.state, eth9.ifindex),
            ("vpp", &PathState::Starting, 9)
        );
        assert_eq!(c.collectors[0].receipt, Receipt::Unverified);
        assert_eq!(c.collectors[0].datagrams, 1);
        assert_eq!(lane(&p, "eth0", Path::Vpp).pool, 2_000);
        assert_eq!(lane(&p, "eth0", Path::Xdp).pool, 5_000);
        assert_eq!(lane(&p, "eth9", Path::Vpp).state, State::Starting);
        assert!(p
            .ports
            .iter()
            .all(|l| !(l.name == "eth9" && l.path == Path::Xdp)));
    }

    #[test]
    fn a_vpp_lane_answers_to_the_sampler_as_a_whole() {
        let (mut r, plugin) = vpp_rig();
        r.w.tick(r.t0);
        plugin.borrow_mut().status = Some(applied(1, 1, 2));
        r.w.tick(r.t0 + TICK);
        assert!(r.shared.snapshot().vpp.unwrap().coverage.is_healthy());
        // The plugin stopped beating; nothing on the ports looks wrong.
        plugin.borrow_mut().heartbeat_age_ns = 2_000_000_000;
        let t = r.t0 + VPP_STARTUP_GRACE + Duration::from_secs(1);
        r.w.tick(t);
        let p = r.shared.snapshot();
        assert_eq!(lane(&p, "eth0", Path::Xdp).state, State::Covered);
        let State::Uncovered(why) = lane(&p, "eth9", Path::Vpp).state else {
            panic!("{:?}", lane(&p, "eth9", Path::Vpp));
        };
        assert!(why.contains("VPP's sampler is unavailable"), "{why}");
        assert_eq!(p.vpp.unwrap().coverage, Coverage::Unavailable);
    }

    #[test]
    fn vpp_loss_degrades_vpp_lanes_and_rides_the_next_vpp_sample() {
        let (mut r, plugin) = vpp_rig();
        r.w.tick(r.t0);
        plugin.borrow_mut().status = Some(applied(1, 1, 2));
        let t = r.t0 + VPP_STARTUP_GRACE;
        r.w.tick(t);
        assert!(r.shared.snapshot().vpp.unwrap().coverage.is_healthy());
        plugin.borrow_mut().rings = rings(&[], 7);
        r.w.tick(t + TICK);
        r.w.tick(t + WINDOW);
        let p = r.shared.snapshot();
        assert_eq!(p.vpp_lost_total, 7);
        assert!(matches!(
            lane(&p, "eth9", Path::Vpp).state,
            State::Degraded(_)
        ));
        assert_eq!(
            lane(&p, "eth0", Path::Xdp).state,
            State::Covered,
            "fast-path lost nothing"
        );
        r.src.events.borrow_mut().push_back(event(3, 0, 0, 1000, 1));
        plugin.borrow_mut().queued = vec![sample(1, 2)];
        r.w.tick(t + WINDOW + TICK);
        let d = &r.net.sent.borrow()[0].1;
        let b = 28 + 8 + word(d, 32) as usize;
        assert_eq!(word(d, 28 + 24), 0, "XDP's sample carries none of it");
        assert_eq!(
            (word(d, b + 12), word(d, b + 24)),
            (9, 7),
            "VPP's carries it"
        );
    }

    #[test]
    fn vpp_samples_that_cannot_be_read_degrade_vpp_lanes() {
        let (mut r, plugin) = vpp_rig();
        r.w.tick(r.t0);
        plugin.borrow_mut().status = Some(applied(1, 1, 2));
        let t = r.t0 + VPP_STARTUP_GRACE;
        r.w.tick(t);
        // An index generation 1's binding does not know.
        plugin.borrow_mut().queued = vec![sample(1, 99); 3];
        r.w.tick(t + TICK);
        r.w.tick(t + WINDOW);
        let p = r.shared.snapshot();
        assert_eq!(p.unmapped_total, 3);
        assert!(matches!(
            lane(&p, "eth9", Path::Vpp).state,
            State::Degraded(_)
        ));
        assert_eq!(lane(&p, "eth0", Path::Xdp).state, State::Covered);
    }

    #[test]
    fn stopping_stops_both_samplers() {
        let (mut r, plugin) = vpp_rig();
        r.w.tick(r.t0);
        r.w.stop().unwrap();
        assert_eq!(
            r.src.cfgs.borrow().last().unwrap().rate_generation as u32,
            0
        );
        assert!(plugin.borrow().removed);
    }

    #[test]
    fn a_worker_that_panics_stops_from_outside_and_says_why() {
        let r = rig(1000);
        *r.src.panics.borrow_mut() = true;
        let released = std::cell::Cell::new(false);
        r.shared
            .coverage
            .publish(coverage_of(&Published::default(), r.t0));
        run(r.w, &AtomicBool::new(false), || released.set(true));
        assert!(released.get(), "the samplers stopped after the panic");
        assert_eq!(r.shared.panicked().as_deref(), Some("ring fault"));
        assert!(
            r.shared.coverage.current(r.t0).is_none(),
            "it vouches for nothing now"
        );
    }

    fn with_ipfix(mut c: FlowExportConfig) -> FlowExportConfig {
        c.collectors.push(Collector {
            name: "akv".into(),
            addr: "198.51.100.11:4739".parse().unwrap(),
            kind: CollectorKind::Stats,
            format: CollectorFormat::Ipfix,
            profile: Default::default(),
        });
        c
    }

    #[test]
    fn each_collector_gets_its_own_format() {
        let mut r = rig(1000);
        let _ = reload(&r.shared, with_ipfix(cfg(1000)));
        r.w.tick(r.t0);
        r.src.events.borrow_mut().extend([
            ip_event(3, 443, 1000, 1),
            ip_event(3, 443, 1000, 1),
            event(3, 0, 0, 1000, 1),
        ]);
        r.w.tick(r.t0 + TICK);
        {
            let sent = r.net.sent.borrow();
            assert_eq!(sent.len(), 1, "sFlow at once; the flow is still counting");
            assert_eq!(sent[0].0.port(), 6343);
            assert_eq!(word(&sent[0].1, 24), 3, "every sample, IP or not");
        }
        let p = r.shared.snapshot();
        assert_eq!((p.flows.unwrap().active, p.not_ip_total), (1, 1));

        r.w.tick(r.t0 + TICK + Duration::from_secs(15));
        let sent = r.net.sent.borrow();
        let (to, d) = &sent[1];
        assert_eq!(
            to.port(),
            4739,
            "the flow record to the IPFIX collector only"
        );
        assert_eq!(sent.len(), 2);
        assert_eq!(u16::from_be_bytes([d[0], d[1]]), 10, "IPFIX");
        assert_eq!(word(d, 12), Domain::FastPath.id());
        let p = r.shared.snapshot();
        let f = p.flows.unwrap();
        assert_eq!((f.active, f.records, f.counts.expired_inactive), (0, 1, 1));
        assert_eq!(p.collectors[1].datagrams, 1);
        assert_eq!(p.collectors[0].datagrams, 1);
    }

    #[test]
    fn stopping_sends_the_flows_still_counting() {
        let mut r = rig(1000);
        let _ = reload(&r.shared, with_ipfix(cfg(1000)));
        r.w.tick(r.t0);
        r.src
            .events
            .borrow_mut()
            .push_back(ip_event(3, 443, 1000, 1));
        r.w.tick(r.t0 + TICK);
        r.w.stop().unwrap();
        let sent = r.net.sent.borrow();
        assert_eq!(sent.last().unwrap().0.port(), 4739, "{sent:?}");
    }

    /// More flows than one tick's send budget carries all go out at a
    /// stop: none is dropped by the budget as the worker exits.
    #[test]
    fn stopping_sends_every_flow_past_the_send_budget() {
        let mut r = rig(1000);
        let _ = reload(&r.shared, with_ipfix(cfg(1000)));
        r.w.tick(r.t0);
        let flows = 20_000u16;
        r.src
            .events
            .borrow_mut()
            .extend((0..flows).map(|port| ip_event(3, port, 1000, 1)));
        r.w.tick(r.t0 + TICK);
        assert_eq!(
            r.shared.snapshot().flows.unwrap().active,
            usize::from(flows)
        );
        r.w.stop().unwrap();
        let ipfix = r
            .net
            .sent
            .borrow()
            .iter()
            .filter(|(to, _)| to.port() == 4739)
            .count();
        assert!(ipfix > crate::collector::SEND_BUDGET, "{ipfix} messages");
        let out = &r.w.flows.as_ref().unwrap().outs[0];
        assert_eq!(out.records, u64::from(flows));
        assert_eq!(r.w.collectors[1].datagrams, ipfix as u64);
        assert_eq!(r.w.collectors[1].budget_drops, 0);
    }

    /// A sample the worker reads late counts at the time it was taken:
    /// its flow times out from then.
    #[test]
    fn a_late_read_sample_keeps_its_time() {
        let mut r = rig(1000);
        let _ = reload(&r.shared, with_ipfix(cfg(1000)));
        r.w.tick(r.t0);
        // Read 3 s after the program took it (at 7 ns).
        *r.src.clock_ns.borrow_mut() = 7 + 3_000_000_000;
        r.src
            .events
            .borrow_mut()
            .push_back(ip_event(3, 443, 1000, 1));
        r.w.tick(r.t0 + Duration::from_secs(10));
        let ipfix = |r: &Rig| {
            r.net
                .sent
                .borrow()
                .iter()
                .filter(|(to, _)| to.port() == 4739)
                .count()
        };
        r.w.tick(r.t0 + Duration::from_millis(21_900));
        assert_eq!(ipfix(&r), 0, "idle 14.9 s since it was taken");
        r.w.tick(r.t0 + Duration::from_secs(22));
        assert_eq!(
            ipfix(&r),
            1,
            "15 s after it was taken, not after it was read"
        );
    }

    /// One domain's standing backlog cannot starve another's exports: a
    /// tick's budget goes to the domains turn about.
    #[test]
    fn domains_take_the_send_budget_turn_about() {
        let mut r = rig(1000);
        let _ = reload(&r.shared, with_ipfix(cfg(1000)));
        r.w.tick(r.t0);
        let at = Now {
            ms: 0,
            wall_ms: 1_790_000_000_000,
        };
        {
            let f = r.w.flows.as_mut().unwrap();
            for domain in [Domain::FastPath, Domain::Vpp] {
                let batch: Vec<Sampled> = (0..4u16)
                    .map(|port| Sampled {
                        packet: flows::Packet {
                            src: "192.0.2.1".parse().unwrap(),
                            dst: "198.51.100.2".parse().unwrap(),
                            protocol: 6,
                            src_port: 40000,
                            dst_port: port,
                            ip_len: 986,
                        },
                        generation: 1,
                        rate: 1000,
                        input_if: 3,
                        output_if: 0,
                        at,
                    })
                    .collect();
                f.cache.ingest(domain, &batch);
            }
            f.cache.expire(
                Now {
                    ms: 15_000,
                    wall_ms: at.wall_ms + 15_000,
                },
                100,
            );
        }
        // Two exports a tick: the rate and one record.
        let domains = |r: &mut Rig| {
            let before = r.net.sent.borrow().len();
            r.w.send_flows(r.t0, at, 2, None);
            r.net.sent.borrow()[before..]
                .iter()
                .map(|(_, d)| word(d, 12))
                .collect::<Vec<_>>()
        };
        assert_eq!(domains(&mut r), vec![Domain::FastPath.id()]);
        assert_eq!(
            domains(&mut r),
            vec![Domain::Vpp.id()],
            "VPP first this time, though fast-path still has records"
        );
        assert_eq!(domains(&mut r), vec![Domain::FastPath.id()]);
    }

    /// The privacy profiles' local prefixes move only with a reload the
    /// worker applied: the allowlist the module took then, unless the
    /// section names its own.
    #[test]
    fn the_local_prefixes_are_the_configurations() {
        let mut r = rig(1000);
        r.w.tick(r.t0);
        assert!(r.w.local().is_empty());
        let allowlist = vec![IpPrefix::V4 {
            addr: [203, 0, 113, 0],
            prefix_len: 24,
        }];
        let mut c = cfg(1000);
        c.local_default = allowlist.clone();
        let _ = reload(&r.shared, c.clone());
        r.w.tick(r.t0 + TICK);
        assert_eq!(r.w.local(), allowlist);
        let own = vec![IpPrefix::V4 {
            addr: [192, 0, 2, 0],
            prefix_len: 24,
        }];
        c.local = own.clone();
        let _ = reload(&r.shared, c);
        r.w.tick(r.t0 + 2 * TICK);
        assert_eq!(r.w.local(), own, "the section's own win");
    }

    #[test]
    fn a_reload_starts_and_ends_the_flow_cache() {
        let mut r = rig(1000);
        r.w.tick(r.t0);
        assert!(r.shared.snapshot().flows.is_none(), "no IPFIX collector");
        let _ = reload(&r.shared, with_ipfix(cfg(1000)));
        r.w.tick(r.t0 + TICK);
        assert!(r.shared.snapshot().flows.is_some());
        let mut smaller = with_ipfix(cfg(1000));
        smaller.cache.entries = 1024;
        let answer = reload(&r.shared, smaller);
        r.w.tick(r.t0 + 2 * TICK);
        assert_eq!(answer.try_recv().unwrap(), Ok(()));
        let _ = reload(&r.shared, cfg(1000));
        r.w.tick(r.t0 + 3 * TICK);
        assert!(r.shared.snapshot().flows.is_none());
    }

    #[test]
    fn the_heartbeat_tells_a_stalled_worker() {
        let mut r = rig(1000);
        r.w.tick(r.t0 + TICK);
        assert_eq!(r.shared.heartbeat_age(r.t0 + TICK), Duration::ZERO);
        assert_eq!(
            r.shared.heartbeat_age(r.t0 + Duration::from_secs(3)),
            Duration::from_millis(2900)
        );
    }
}
