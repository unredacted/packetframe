//! The export loop: one [`Worker::tick`] every [`TICK`], on the module's
//! own thread. A reload, the ports and their pools, the samples, the
//! datagrams, coverage, and the snapshot health and metrics read.
//!
//! Every outside effect goes through a trait ([`SampleSource`], [`Ports`],
//! [`Transport`]), so the loop runs the same against fakes in the tests as
//! against the fast-path maps, sysfs and a socket on a router.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use packetframe_fast_path::sample::{self, Disposition, SampleCfg};

use crate::cfg::FlowExportConfig;
use crate::collector::{reconcile, send_all, CollectorState, Transport};
use crate::coverage::{PortCoverage, State, Window, WINDOW};
use crate::pool::Accumulator;
use crate::sflow_out::{wire_frame, Exporter, Ready};

pub const TICK: Duration = Duration::from_millis(100);
/// How often the port list and the pools are re-read.
pub const PORTS_EVERY: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Hook {
    Xdp,
    Tc,
}

impl Hook {
    pub fn name(self) -> &'static str {
        match self {
            Hook::Xdp => "xdp",
            Hook::Tc => "tc",
        }
    }
}

/// A fast-path port and the program on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    pub ifindex: u32,
    pub hook: Hook,
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
    pub ports: Vec<PortReport>,
    pub collectors: Vec<CollectorReport>,
    pub samples_total: u64,
    /// Samples the programs could not output, or the rings reported lost
    /// when that count cannot be read.
    pub lost_total: u64,
    pub ring_lost_total: u64,
    /// Samples from an interface not among fast-path's ports.
    pub unmapped_total: u64,
    pub undecodable_total: u64,
    pub unencodable_total: u64,
    pub datagrams_total: u64,
    /// Why the sampler's configuration could not be applied, if so.
    pub source_error: Option<String>,
    /// Why the port list could not be read, if so.
    pub ports_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PortReport {
    pub name: String,
    pub ifindex: u32,
    pub hook: Hook,
    pub state: State,
    pub samples: u64,
    pub pool: u64,
}

#[derive(Debug, Clone)]
pub struct CollectorReport {
    pub name: String,
    pub addr: std::net::SocketAddr,
    pub kind: packetframe_common::config::CollectorKind,
    pub datagrams: u64,
    pub send_errors: u64,
    pub budget_drops: u64,
    pub failing: Option<String>,
}

/// The handles the module keeps: a reload to apply, the snapshot, and
/// the heartbeat (milliseconds since `epoch`).
#[derive(Clone)]
pub struct Shared {
    pub epoch: Instant,
    pub heartbeat_ms: Arc<AtomicU64>,
    pub published: Arc<Mutex<Published>>,
    pub reload: Arc<Mutex<Option<Reload>>>,
}

impl Shared {
    pub fn new(epoch: Instant) -> Self {
        Self {
            epoch,
            heartbeat_ms: Arc::new(AtomicU64::new(0)),
            published: Arc::default(),
            reload: Arc::default(),
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
}

struct Source {
    port: Port,
    sequence: u32,
    drops: u32,
    pool: Accumulator,
    coverage: PortCoverage,
    window_samples: u64,
    window_pool: u64,
    samples: u64,
}

pub struct Worker<S, P, T> {
    cfg: FlowExportConfig,
    generation: u32,
    source: S,
    ports: P,
    transport: T,
    exporter: Exporter,
    collectors: Vec<CollectorState>,
    sources: BTreeMap<u32, Source>,
    shared: Shared,
    next_ports: Instant,
    next_window: Instant,
    window_lost: u64,
    last_emit_failed: Option<u64>,
    /// Loss not yet carried by a sample, for the next one's `drops`.
    pending_drops: u32,
    /// What the last ring replacement left, for the next tick to export.
    leftover: Leftover,
    p: Published,
}

impl<S: SampleSource, P: Ports, T: Transport> Worker<S, P, T> {
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
        Ok(Self {
            exporter: Exporter::new(cfg.source),
            cfg,
            generation: 1,
            source,
            ports,
            transport,
            collectors,
            sources: BTreeMap::new(),
            shared,
            next_ports: now,
            next_window: now + WINDOW,
            window_lost: 0,
            last_emit_failed: None,
            pending_drops: 0,
            leftover: Leftover::default(),
            p: Published::default(),
        })
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
        if now >= self.next_ports {
            self.refresh_ports(now);
            self.next_ports = now + PORTS_EVERY;
        }
        let ready = self.take_samples();
        if !ready.is_empty() {
            let mut datagrams = Vec::new();
            let uptime_ms = now.saturating_duration_since(self.shared.epoch).as_millis() as u32;
            self.p.unencodable_total +=
                self.exporter.encode(&ready, uptime_ms, &mut datagrams) as u64;
            self.p.datagrams_total += datagrams.len() as u64;
            send_all(&self.transport, &mut self.collectors, &datagrams, now);
        }
        if now >= self.next_window {
            self.judge(now);
            self.next_window = now + WINDOW;
        }
        self.publish(now);
        let ms = now.saturating_duration_since(self.shared.epoch).as_millis() as u64;
        self.shared.heartbeat_ms.store(ms, Ordering::Relaxed);
    }

    /// Stop sampling: rate 0. For detach, after the last tick.
    pub fn stop(&mut self) -> Result<(), String> {
        self.source.configure(SampleCfg::new(
            0,
            self.cfg.header_bytes,
            self.generation + 1,
        ))
    }

    /// Apply a reload, or none of it: on a failure the sampler, the
    /// collectors and what is published stay as they were, so the same
    /// reload retried is tried again rather than taken as applied.
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
        self.collectors = reconcile(std::mem::take(&mut self.collectors), &new.collectors);
        self.cfg = new;
        Ok(())
    }

    fn refresh_ports(&mut self, now: Instant) {
        match self.ports.ports() {
            Ok(list) => {
                self.p.ports_error = None;
                self.sources.retain(|i, s| {
                    list.iter()
                        .any(|p| p.ifindex == *i && p.name == s.port.name)
                });
                for port in list {
                    self.sources.entry(port.ifindex).or_insert_with(|| Source {
                        port,
                        sequence: 0,
                        drops: 0,
                        pool: Accumulator::default(),
                        coverage: PortCoverage::new(now),
                        window_samples: 0,
                        window_pool: 0,
                        samples: 0,
                    });
                }
            }
            // The last list stands: an unreadable registry is not a port
            // that went away.
            Err(e) => self.p.ports_error = Some(e),
        }
        for s in self.sources.values_mut() {
            if let Some(rx) = self.ports.rx_packets(&s.port) {
                s.pool.observe(rx);
            }
        }
    }

    fn take_samples(&mut self) -> Vec<Ready> {
        let mut ready = Vec::new();
        let left = std::mem::take(&mut self.leftover);
        let (sources, p, pending) = (&mut self.sources, &mut self.p, &mut self.pending_drops);
        for e in &left.events {
            ingest(e, sources, p, pending, &mut ready);
        }
        let ring_lost = left.lost
            + self
                .source
                .drain(&mut |e| ingest(e, sources, p, pending, &mut ready));
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

    fn judge(&mut self, now: Instant) {
        for s in self.sources.values_mut() {
            let packets = s.pool.total().saturating_sub(s.window_pool);
            s.coverage.judge(
                now,
                Window {
                    samples: s.window_samples,
                    lost: self.window_lost,
                    packets,
                    rate: self.cfg.rate,
                },
            );
            s.window_samples = 0;
            s.window_pool = s.pool.total();
        }
        self.window_lost = 0;
    }

    fn publish(&mut self, now: Instant) {
        self.p.rate = self.cfg.rate;
        self.p.header_bytes = self.cfg.header_bytes;
        self.p.generation = self.generation;
        self.p.over_budget = self.cfg.over_budget();
        self.p.expanded = self.exporter.expanded();
        self.p.ports = self
            .sources
            .values()
            .map(|s| PortReport {
                name: s.port.name.clone(),
                ifindex: s.port.ifindex,
                hook: s.port.hook,
                state: s.coverage.state().clone(),
                samples: s.samples,
                pool: s.pool.total(),
            })
            .collect();
        self.p.collectors = self
            .collectors
            .iter()
            .map(|c| CollectorReport {
                name: c.cfg.name.clone(),
                addr: c.cfg.addr,
                kind: c.cfg.kind,
                datagrams: c.datagrams,
                send_errors: c.send_errors,
                budget_drops: c.budget_drops,
                failing: c.failing(now),
            })
            .collect();
        *self
            .shared
            .published
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = self.p.clone();
    }
}

/// One sample event: its port's sequence, drops and window, and the
/// sample as sFlow will carry it.
fn ingest(
    event: &[u8],
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
    src.sequence = src.sequence.wrapping_add(1);
    src.drops = src.drops.wrapping_add(std::mem::take(pending));
    src.window_samples += 1;
    src.samples += 1;
    p.samples_total += 1;
    let (header, frame_length) = wire_frame(&s);
    ready.push(Ready {
        sequence: src.sequence,
        source_if: s.ingress_ifindex,
        rate: s.rate,
        pool: src.pool.total() as u32,
        drops: src.drops,
        output_if: match s.disposition {
            Disposition::Redirect => s.egress_ifindex,
            _ => 0,
        },
        frame_length,
        header,
    });
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
            let mut q = self.events.borrow_mut();
            while let Some(e) = q.pop_front() {
                f(&e);
            }
            std::mem::take(&mut *self.ring_lost.borrow_mut())
        }
        fn emit_failed(&mut self) -> Option<u64> {
            *self.emit_failed.borrow()
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
        let mut e = 7u64.to_ne_bytes().to_vec();
        let header = [0x5a; 64];
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
        e.extend_from_slice(&header);
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
            }],
        }
    }

    struct Rig {
        w: Worker<FakeSource, FakePorts, FakeNet>,
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
            hook: Hook::Xdp,
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
        assert_eq!((p.samples_total, p.unmapped_total), (2, 1));
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
        assert_eq!(r.shared.snapshot().samples_total, 1);
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
