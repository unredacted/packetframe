//! `packetframe sampler`: the VPP sampler's lab reader (flow export, plan
//! step 0.4).
//!
//! - `status`: one read-only look. Never takes the consumer lock, never
//!   drains, done in well under a second.
//! - `watch`: the one consumer. Takes `consumer.lock`, follows the sampler
//!   across VPP restarts, drains every ring each `--poll`, and reports each
//!   `--interval`: per-stage counts, what was lost and where, sample-to-
//!   receipt latency, coverage, and decoded samples.
//! - `configure` / `clear`: write or remove `desired.conf`, under
//!   `desired.lock`, refused while another writer holds it.
//!
//! Ahead of the flow-export module (Phase 1), which will consume the same
//! rings through the same `Follower` and judge coverage with the same
//! `assess`.

#![cfg(all(target_os = "linux", feature = "vpp-offload"))]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use packetframe_sampler_shm::coverage::{assess, Coverage, NoStatus, Observation};
use packetframe_sampler_shm::desired::Desired;
use packetframe_sampler_shm::follow::{self, Follower};
use packetframe_sampler_shm::fs::{
    clear_desired, usage, write_atomic, Lock, Opened, DEFAULT_DIR, DESIRED, DESIRED_LOCK, ENV_DIR,
};
use packetframe_sampler_shm::ring::{self, Counters, Drained, Sample};
use packetframe_sampler_shm::status::{Interface, Status};
use packetframe_sampler_shm::{valid_interface_name, Class};

use crate::{parse_duration, EXIT_OK, EXIT_RUNTIME_ERROR, EXIT_STARTUP_ERROR};

#[derive(Subcommand)]
pub enum SamplerOp {
    /// One read-only look at the sampler: coverage, status, counters.
    /// Never drains. Exits 0 when coverage is healthy, 2 otherwise.
    Status {
        /// The sampler directory (default: $PF_SAMPLER_DIR, else
        /// /run/packetframe/vpp/sampler).
        #[arg(long)]
        dir: Option<PathBuf>,
    },
    /// Consume the samples and report on them: the one consumer (takes
    /// consumer.lock; refused while another holds it).
    Watch {
        #[arg(long)]
        dir: Option<PathBuf>,
        /// How often to report.
        #[arg(long, default_value = "1s", value_parser = parse_duration)]
        interval: Duration,
        /// How often to drain the rings.
        #[arg(long, default_value = "10ms", value_parser = parse_duration)]
        poll: Duration,
        /// Stop after this long (default: until interrupted).
        #[arg(long, value_parser = parse_duration)]
        duration: Option<Duration>,
        /// Decode and print up to this many samples in each report.
        #[arg(long, default_value_t = 0)]
        show_samples: usize,
    },
    /// Write desired.conf, then wait (2 s at most) to see the plugin apply
    /// or refuse it.
    Configure {
        #[arg(long)]
        dir: Option<PathBuf>,
        /// A VPP interface name to sample; repeat for more. None samples
        /// nothing.
        #[arg(long = "interface")]
        interfaces: Vec<String>,
        /// Sample 1 in this many packets.
        #[arg(long)]
        rate: u32,
        /// Leading packet bytes to copy into each sample.
        #[arg(long, default_value_t = 128)]
        header_bytes: u32,
        /// The configuration's generation (default: one past every
        /// generation the file and the status show).
        #[arg(long)]
        generation: Option<u64>,
    },
    /// Remove desired.conf: the plugin stops sampling.
    Clear {
        #[arg(long)]
        dir: Option<PathBuf>,
    },
}

pub fn run(op: SamplerOp) -> ExitCode {
    match op {
        SamplerOp::Status { dir } => status(&dir_or_default(dir)),
        SamplerOp::Watch {
            dir,
            interval,
            poll,
            duration,
            show_samples,
        } => watch(&dir_or_default(dir), interval, poll, duration, show_samples),
        SamplerOp::Configure {
            dir,
            interfaces,
            rate,
            header_bytes,
            generation,
        } => configure(
            &dir_or_default(dir),
            interfaces,
            rate,
            header_bytes,
            generation,
        ),
        SamplerOp::Clear { dir } => clear(&dir_or_default(dir)),
    }
}

fn dir_or_default(dir: Option<PathBuf>) -> PathBuf {
    dir.or_else(|| std::env::var_os(ENV_DIR).map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_DIR))
}

fn realtime_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// CLOCK_MONOTONIC, the clock the plugin's heartbeat is in.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn desired_generation(dir: &Path) -> Option<u64> {
    std::fs::read_to_string(dir.join(DESIRED))
        .ok()
        .and_then(|t| Desired::parse(&t).ok())
        .map(|d| d.generation)
}

fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
}

fn ms(ns: u64) -> String {
    format!("{:.1} ms", ns as f64 / 1e6)
}

/// Coverage as a reader sees it now. `traffic`: whether packets were
/// counted over whatever window the caller judges; `lost`: the samples
/// lost on the way to the reader over it.
struct Seen {
    coverage: Coverage,
    why: String,
    status: Option<Status>,
    heartbeat_age_ns: u64,
}

fn observe(f: &Follower, traffic: bool, lost: u64) -> Seen {
    let rings = f.opened().map(counters).unwrap_or_default();
    let base = |status, heartbeat_age_ns| Observation {
        status,
        heartbeat_age_ns,
        desired_generation: desired_generation(f.dir()),
        now_realtime_ns: realtime_ns(),
        traffic,
        lost,
        backlog: rings.iter().map(follow::queued).sum(),
        capacity: f.opened().map_or(0, |o| {
            (o.layout().workers as u64).saturating_mul(o.layout().slots as u64)
        }),
    };
    let no_status = |incompatible, why| NoStatus { incompatible, why };
    let Some(o) = f.opened().filter(|_| !f.incompatible()) else {
        let why = f
            .error()
            .map_or_else(|| "no epoch".into(), |e| e.to_string());
        let (coverage, why) = assess(&base(Err(no_status(f.incompatible(), why)), 0));
        return Seen {
            coverage,
            why,
            status: None,
            heartbeat_age_ns: 0,
        };
    };
    let age = monotonic_ns().saturating_sub(o.status().heartbeat());
    let read = o.status().read();
    let status = read.as_ref().map_err(|e| no_status(false, e.to_string()));
    let (coverage, why) = assess(&base(status, age));
    Seen {
        coverage,
        why,
        status: read.ok(),
        heartbeat_age_ns: age,
    }
}

fn counters(o: &Opened) -> Vec<Counters> {
    (0..o.layout().workers)
        .map(|r| ring::counters(o.layout(), o.file(), r))
        .collect()
}

fn ingress(c: &Counters, pool: usize) -> u64 {
    c.pool[pool][Class::Ingress.index()]
}

/// How long `status` watches the rings for loss.
const STATUS_LOSS_WINDOW: Duration = Duration::from_millis(250);

fn status(dir: &Path) -> ExitCode {
    let mut f = Follower::observer(dir);
    f.refresh();
    let tmpfs = usage(dir).map_or_else(
        |e| format!("unreadable: {e}"),
        |(u, t)| format!("{} of {}", mib(u), mib(t)),
    );
    println!("directory {} (tmpfs {tmpfs})", dir.display());
    // Traffic is judged over the epoch's whole life; loss over a moment,
    // so a burst long past does not read as losing samples now.
    let before = f.opened().map(counters).unwrap_or_default();
    std::thread::sleep(STATUS_LOSS_WINDOW);
    let c = f.opened().map(counters).unwrap_or_default();
    let traffic = c.iter().any(|c| c.pool.iter().flatten().any(|&n| n > 0));
    let lost = c
        .iter()
        .zip(&before)
        .map(|(now, then)| now.dropped_full.saturating_sub(then.dropped_full))
        .sum();
    let seen = observe(&f, traffic, lost);
    println!(
        "coverage {}: {} (traffic judged since the epoch began, loss over {} ms)",
        seen.coverage.name(),
        seen.why,
        STATUS_LOSS_WINDOW.as_millis()
    );
    if let Some(o) = f.opened() {
        let h = &o.header;
        println!(
            "epoch {:016x}: {} rings x {} slots, {} header bytes; {}; created {} s ago",
            h.epoch,
            h.layout.workers,
            h.layout.slots,
            h.layout.header_capacity,
            h.build,
            realtime_ns().saturating_sub(h.created_ns) / 1_000_000_000
        );
        println!("heartbeat {} ago", ms(seen.heartbeat_age_ns));
    }
    if let Some(s) = &seen.status {
        println!(
            "state {:?}; applied generation {} (desired {}), rate 1:{}, header {} bytes",
            s.state,
            s.applied_generation,
            desired_generation(dir).map_or("none".into(), |g| g.to_string()),
            s.rate,
            s.header_bytes
        );
        for i in &s.interfaces {
            let packets: u64 = c
                .iter()
                .map(|c| ingress(c, usize::from(i.pool_index)))
                .sum();
            let at = match i.sw_if_index {
                Some(sw) => format!("sw_if_index {sw}"),
                None => format!(
                    "unresolved for {} s",
                    realtime_ns().saturating_sub(i.unresolved_since_ns) / 1_000_000_000
                ),
            };
            println!("  {} ({at}): {packets} packets", i.name);
        }
    }
    for (r, c) in c.iter().enumerate() {
        println!(
            "ring {r}: selected {} written {} dropped-full {} queued {}",
            c.selected,
            c.written,
            c.dropped_full,
            follow::queued(c)
        );
    }
    if seen.coverage.is_healthy() {
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_RUNTIME_ERROR)
    }
}

/// What one report window collected.
struct Window {
    start: Instant,
    /// The open epoch's counters when the window (or the epoch) began.
    base: Vec<Counters>,
    drained: Vec<u64>,
    corrupt: u64,
    skipped: u64,
    latency: Latency,
    shown: Vec<(usize, Sample)>,
    /// What epochs left during the window counted after its start:
    /// pool, selected, written, dropped-full, drained.
    carried: [u64; 5],
    /// Every name each pool index stood for in the open epoch during the
    /// window, and each generation applied: a configuration change
    /// mid-window must not hand what one interface counted to another.
    names: BTreeMap<u8, Vec<String>>,
    generations: Vec<u64>,
}

/// Pool, selected, written and dropped-full counted between `base` and
/// `now`, over every ring of one epoch.
fn growth(now: &[Counters], base: &[Counters]) -> [u64; 4] {
    let mut g = [0; 4];
    for (r, c) in now.iter().enumerate() {
        let b = base.get(r);
        let d = |get: &dyn Fn(&Counters) -> u64| get(c).wrapping_sub(b.map_or(0, get));
        g[0] += (0..c.pool.len())
            .map(|p| d(&|c| ingress(c, p)))
            .sum::<u64>();
        g[1] += d(&|c| c.selected);
        g[2] += d(&|c| c.written);
        g[3] += d(&|c| c.dropped_full);
    }
    g
}

impl Window {
    fn new(f: &Follower) -> Self {
        Self::from(f.opened().map(counters).unwrap_or_default())
    }

    /// A window counting from `base`: the previous report's own snapshot,
    /// so nothing counted between two windows falls between them.
    fn from(base: Vec<Counters>) -> Self {
        Self {
            start: Instant::now(),
            drained: vec![0; base.len()],
            base,
            corrupt: 0,
            skipped: 0,
            latency: Latency::default(),
            shown: Vec::new(),
            carried: [0; 5],
            names: BTreeMap::new(),
            generations: Vec::new(),
        }
    }

    /// The epoch changed: keep what the one left (`last`, its counters
    /// just before the switch) counted in this window, and count the new
    /// one from zero when it is `fresh` (made after this run began, so all
    /// it counted before the switch was noticed is this run's), else from
    /// now.
    fn rebase(&mut self, f: &Follower, last: Option<&[Counters]>, fresh: bool) {
        if let Some(last) = last {
            let g = growth(last, &self.base);
            for (c, v) in self.carried.iter_mut().zip(g) {
                *c += v;
            }
        }
        self.carried[4] += self.drained.iter().sum::<u64>();
        self.base = match f.opened() {
            Some(o) if !fresh => counters(o),
            _ => Vec::new(),
        };
        self.drained = vec![0; f.opened().map_or(0, |o| o.layout().workers)];
        // The new epoch's pool indexes are its own plugin's.
        self.names.clear();
        self.generations.clear();
    }

    fn note(&mut self, s: &Status) {
        for i in &s.interfaces {
            let names = self.names.entry(i.pool_index).or_default();
            if !names.contains(&i.name) {
                names.push(i.name.clone());
            }
        }
        if self.generations.last() != Some(&s.applied_generation) {
            self.generations.push(s.applied_generation);
        }
    }

    fn take(&mut self, r: usize, d: Drained, out: &mut Vec<Sample>, now_ns: u64, show: usize) {
        if let Some(n) = self.drained.get_mut(r) {
            *n += d.taken as u64;
        }
        self.corrupt += d.corrupt;
        self.skipped += d.skipped;
        for s in out.drain(..) {
            self.latency.add(now_ns.saturating_sub(s.meta.time_ns));
            if self.shown.len() < show {
                self.shown.push((r, s));
            }
        }
    }
}

#[derive(Default)]
struct Totals {
    pool: u64,
    selected: u64,
    written: u64,
    dropped_full: u64,
    drained: u64,
    corrupt: u64,
    skipped: u64,
    switches: u64,
    abandoned: u64,
}

/// Buckets per power of two in [`Latency`], as a shift.
const LATENCY_SUB: u32 = 3;
const LATENCY_BUCKETS: usize = 64 << LATENCY_SUB;

/// Sample-to-receipt latencies in a log-linear histogram: 8 buckets to
/// each power of two, so a quantile is within 12.5% and a window holds 4
/// KiB however many samples it drains (1:1 sampling drains millions).
struct Latency {
    counts: Vec<u64>,
    n: u64,
    max: u64,
}

impl Default for Latency {
    fn default() -> Self {
        Self {
            counts: vec![0; LATENCY_BUCKETS],
            n: 0,
            max: 0,
        }
    }
}

impl Latency {
    fn bucket(ns: u64) -> usize {
        if ns < 1 << LATENCY_SUB {
            return ns as usize;
        }
        let octave = 63 - ns.leading_zeros();
        let sub = (ns >> (octave - LATENCY_SUB)) & ((1 << LATENCY_SUB) - 1);
        ((u64::from(octave - LATENCY_SUB + 1) << LATENCY_SUB) | sub) as usize
    }

    /// The smallest value bucket `b` holds.
    fn floor(b: usize) -> u64 {
        let b = b as u64;
        if b < 1 << LATENCY_SUB {
            return b;
        }
        let octave = (b >> LATENCY_SUB) as u32 + LATENCY_SUB - 1;
        ((1 << LATENCY_SUB) | (b & ((1 << LATENCY_SUB) - 1))) << (octave - LATENCY_SUB)
    }

    fn add(&mut self, ns: u64) {
        self.counts[Self::bucket(ns)] += 1;
        self.n += 1;
        self.max = self.max.max(ns);
    }

    /// The `p` quantile, as the floor of the bucket it falls in.
    fn quantile(&self, p: f64) -> u64 {
        let rank = ((self.n as f64 * p).ceil() as u64).max(1);
        let mut seen = 0;
        for (b, &c) in self.counts.iter().enumerate() {
            seen += c;
            if seen >= rank {
                return Self::floor(b);
            }
        }
        self.max
    }
}

/// Each configured interface's packets in the window, and every pool that
/// counted in it: an interface configured earlier in the window still
/// shows, under the names its pool had.
fn interface_lines(
    current: &[Interface],
    pools: &BTreeMap<u8, u64>,
    names: &BTreeMap<u8, Vec<String>>,
) -> Vec<String> {
    let mut out = Vec::new();
    for i in current {
        let at = match i.sw_if_index {
            Some(sw) => format!("sw_if_index {sw}"),
            None => "UNRESOLVED".into(),
        };
        let before: Vec<&str> = names
            .get(&i.pool_index)
            .into_iter()
            .flatten()
            .filter(|n| **n != i.name)
            .map(String::as_str)
            .collect();
        let shared = if before.is_empty() {
            String::new()
        } else {
            format!(
                " (its pool also counted {} in this window)",
                before.join(", ")
            )
        };
        out.push(format!(
            "  {} ({at}): +{} packets{shared}",
            i.name,
            pools.get(&i.pool_index).copied().unwrap_or(0)
        ));
    }
    for (p, n) in pools {
        if current.iter().any(|i| i.pool_index == *p) {
            continue;
        }
        let who = names
            .get(p)
            .map_or_else(|| format!("pool {p}"), |names| names.join(", "));
        out.push(format!("  {who} (no longer configured): +{n} packets"));
    }
    out
}

/// Prints the window's report; returns the counter snapshot it was taken
/// at, where the next window starts.
fn report(
    w: &mut Window,
    f: &Follower,
    run_start: Instant,
    poll: Duration,
    t: &mut Totals,
) -> Vec<Counters> {
    let now = f.opened().map(counters).unwrap_or_default();
    let window = w.start.elapsed();
    let mut pools: BTreeMap<u8, u64> = BTreeMap::new();
    let (mut pool, mut selected, mut written, mut full) = (0, 0, 0, 0);
    let mut ring_lines = Vec::new();
    for (r, c) in now.iter().enumerate() {
        // Counters only grow within an epoch; the base is this epoch's.
        let delta =
            |get: &dyn Fn(&Counters) -> u64| get(c).wrapping_sub(w.base.get(r).map_or(0, get));
        let mut ring_pool = 0;
        for p in 0..c.pool.len() {
            let d = delta(&|c| ingress(c, p));
            if d > 0 {
                *pools.entry(p as u8).or_default() += d;
                ring_pool += d;
            }
        }
        let (s, wr, df) = (
            delta(&|c| c.selected),
            delta(&|c| c.written),
            delta(&|c| c.dropped_full),
        );
        let drained = w.drained.get(r).copied().unwrap_or(0);
        if ring_pool + s + drained > 0 {
            ring_lines.push(format!(
                "  ring {r}: pool +{ring_pool} selected +{s} written +{wr} dropped-full +{df} drained {drained}"
            ));
        }
        pool += ring_pool;
        selected += s;
        written += wr;
        full += df;
    }
    let c = w.carried;
    if c.iter().any(|&v| v > 0) {
        ring_lines.push(format!(
            "  in the epoch left this window: pool +{} selected +{} written +{} dropped-full +{} drained {}",
            c[0], c[1], c[2], c[3], c[4]
        ));
    }
    pool += c[0];
    selected += c[1];
    written += c[2];
    full += c[3];
    let drained: u64 = w.drained.iter().sum::<u64>() + c[4];
    let seen = observe(f, pool > 0, full + w.corrupt + w.skipped);
    let epoch = f
        .opened()
        .map_or("none".into(), |o| format!("{:016x}", o.header.epoch));
    println!(
        "[{:>7.1} s] window {:.3} s (heartbeat 100 ms, poll {} ms) epoch {epoch} coverage {}: {}; heartbeat {} ago",
        run_start.elapsed().as_secs_f64(),
        window.as_secs_f64(),
        poll.as_millis(),
        seen.coverage.name(),
        seen.why,
        ms(seen.heartbeat_age_ns),
    );
    if let Some(s) = &seen.status {
        w.note(s);
        println!(
            "  generation applied {} desired {}, rate 1:{}, header {} bytes",
            s.applied_generation,
            desired_generation(f.dir()).map_or("none".into(), |g| g.to_string()),
            s.rate,
            s.header_bytes
        );
    }
    if w.generations.len() > 1 {
        let g: Vec<String> = w.generations.iter().map(u64::to_string).collect();
        println!(
            "  generation changed in this window ({}): each count below spans the change",
            g.join(" -> ")
        );
    }
    let current = seen.status.as_ref().map_or(&[][..], |s| &s.interfaces[..]);
    interface_lines(current, &pools, &w.names)
        .iter()
        .for_each(|l| println!("{l}"));
    ring_lines.iter().for_each(|l| println!("{l}"));
    let effective = if selected > 0 {
        format!("1:{:.0}", pool as f64 / selected as f64)
    } else {
        "none selected".into()
    };
    println!(
        "  total: pool +{pool} selected +{selected} ({effective}) written +{written} drained {drained}; \
         lost: ring full {full}, corrupt {}, skipped {}",
        w.corrupt, w.skipped
    );
    let l = &w.latency;
    if l.n > 0 {
        println!(
            "  sample-to-receipt: p50 {} p99 {} max {} over {} samples",
            ms(l.quantile(0.5)),
            ms(l.quantile(0.99)),
            ms(l.max),
            l.n
        );
    }
    if let Ok((u, total)) = usage(f.dir()) {
        println!("  tmpfs {} of {}", mib(u), mib(total));
    }
    for (r, s) in &w.shown {
        println!(
            "  sample ring {r} seq {} sw_if_index {} gen {} len {}: {}",
            s.seq,
            s.meta.sw_if_index,
            s.meta.generation,
            s.meta.frame_len,
            describe_packet(&s.header)
        );
    }
    t.pool += pool;
    t.selected += selected;
    t.written += written;
    t.dropped_full += full;
    t.drained += drained;
    t.corrupt += w.corrupt;
    t.skipped += w.skipped;
    now
}

fn watch(
    dir: &Path,
    interval: Duration,
    poll: Duration,
    duration: Option<Duration>,
    show: usize,
) -> ExitCode {
    let mut f = match Follower::consumer(dir) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("sampler watch: {}: {e}", dir.display());
            return ExitCode::from(EXIT_STARTUP_ERROR);
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    for sig in [libc::SIGINT, libc::SIGTERM] {
        if let Err(e) = signal_hook::flag::register(sig, Arc::clone(&stop)) {
            eprintln!("sampler watch: signal handler: {e}");
            return ExitCode::from(EXIT_STARTUP_ERROR);
        }
    }
    let run_start = Instant::now();
    let run_start_ns = realtime_ns();
    let refresh_every = Duration::from_millis(100);
    let mut next_refresh = run_start;
    let mut w = Window::new(&f);
    let mut t = Totals::default();
    let mut buf = Vec::new();
    loop {
        let now = Instant::now();
        if now >= next_refresh {
            let last = f.opened().map(counters);
            if let Some(sw) = f.refresh() {
                match sw.from {
                    None => println!("following epoch {:016x}", sw.to),
                    Some(from) => {
                        println!(
                            "epoch {from:016x} -> {:016x} (VPP restarted): {} queued samples \
                             abandoned with the old one",
                            sw.to, sw.abandoned
                        );
                        t.switches += 1;
                        t.abandoned += sw.abandoned;
                    }
                }
                let fresh = sw.from.is_some()
                    || f.opened()
                        .is_some_and(|o| o.header.created_ns >= run_start_ns);
                w.rebase(&f, last.as_deref(), fresh);
            }
            if let Some(s) = f.opened().and_then(|o| o.status().read().ok()) {
                w.note(&s);
            }
            next_refresh = now + refresh_every;
        }
        if let Some(o) = f.opened() {
            let now_ns = realtime_ns();
            for r in 0..o.layout().workers {
                if let Some(ring) = o.ring(r) {
                    let d = ring.drain(&mut buf, usize::MAX);
                    w.take(r, d, &mut buf, now_ns, show);
                }
            }
        }
        let done =
            stop.load(Ordering::Relaxed) || duration.is_some_and(|d| run_start.elapsed() >= d);
        if w.start.elapsed() >= interval || done {
            w = Window::from(report(&mut w, &f, run_start, poll, &mut t));
        }
        if done {
            println!(
                "summary over {:.1} s: pool {} selected {} written {} drained {}; lost: ring full {}, \
                 corrupt {}, skipped {}, abandoned at {} epoch switches {}",
                run_start.elapsed().as_secs_f64(),
                t.pool,
                t.selected,
                t.written,
                t.drained,
                t.dropped_full,
                t.corrupt,
                t.skipped,
                t.switches,
                t.abandoned
            );
            return ExitCode::from(EXIT_OK);
        }
        std::thread::sleep(poll);
    }
}

/// The newest generation in sight: the file's, and what the plugin last
/// applied or refused.
fn newest_generation(dir: &Path) -> Option<u64> {
    let mut f = Follower::observer(dir);
    f.refresh();
    let status = f.opened().and_then(|o| o.status().read().ok());
    [
        desired_generation(dir),
        status.as_ref().map(|s| s.applied_generation),
        status.as_ref().map(|s| s.rejected_generation),
    ]
    .into_iter()
    .flatten()
    .max()
}

/// The generation to write: one past the newest in sight by default; an
/// explicit one must be past it too, or the status already showing it
/// would read as this configuration applied (or refused) before the plugin
/// has even read the file.
fn pick_generation(explicit: Option<u64>, newest: Option<u64>) -> Result<u64, String> {
    match (explicit, newest) {
        (None, n) => Ok(n.map_or(1, |n| n + 1)),
        (Some(g), Some(n)) if g <= n => Err(format!(
            "generation {g} is not past {n}, the newest the file and the plugin show"
        )),
        (Some(g), _) => Ok(g),
    }
}

fn take_desired_lock(dir: &Path) -> Result<Lock, ExitCode> {
    match Lock::try_exclusive(&dir.join(DESIRED_LOCK)) {
        Ok(Some(l)) => Ok(l),
        Ok(None) => {
            eprintln!(
                "sampler: desired.lock is held: another writer (PacketFrame's flow export?) owns desired.conf"
            );
            Err(ExitCode::from(EXIT_STARTUP_ERROR))
        }
        Err(e) => {
            eprintln!("sampler: {}: {e}", dir.join(DESIRED_LOCK).display());
            Err(ExitCode::from(EXIT_STARTUP_ERROR))
        }
    }
}

fn configure(
    dir: &Path,
    interfaces: Vec<String>,
    rate: u32,
    header_bytes: u32,
    generation: Option<u64>,
) -> ExitCode {
    if let Some(bad) = interfaces.iter().find(|i| !valid_interface_name(i)) {
        eprintln!("sampler configure: `{bad}` is not a VPP interface name");
        return ExitCode::from(EXIT_STARTUP_ERROR);
    }
    let _lock = match take_desired_lock(dir) {
        Ok(l) => l,
        Err(code) => return code,
    };
    let generation = match pick_generation(generation, newest_generation(dir)) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("sampler configure: {e}");
            return ExitCode::from(EXIT_STARTUP_ERROR);
        }
    };
    let d = Desired {
        generation,
        rate,
        header_bytes,
        classes: Class::Ingress.bit(),
        interfaces,
    };
    let text = d.render();
    // The plugin applies exactly this check; refuse here what it would.
    if let Err(e) = Desired::parse(&text) {
        eprintln!("sampler configure: {e}");
        return ExitCode::from(EXIT_STARTUP_ERROR);
    }
    if let Err(e) = write_atomic(dir, DESIRED, text.as_bytes()) {
        eprintln!("sampler configure: {}: {e}", dir.join(DESIRED).display());
        return ExitCode::from(EXIT_RUNTIME_ERROR);
    }
    println!("desired.conf generation {generation} written");
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut f = Follower::observer(dir);
    while Instant::now() < deadline {
        f.refresh();
        if let Some(s) = f.opened().and_then(|o| o.status().read().ok()) {
            if s.applied_generation == generation {
                let missing: Vec<&str> = s
                    .interfaces
                    .iter()
                    .filter(|i| i.sw_if_index.is_none())
                    .map(|i| i.name.as_str())
                    .collect();
                if missing.is_empty() {
                    println!("applied");
                } else {
                    println!("applied; not (yet) in VPP: {}", missing.join(", "));
                }
                return ExitCode::from(EXIT_OK);
            }
            if s.rejected_generation == generation && s.rejected_reason != 0 {
                let kind =
                    packetframe_sampler_shm::desired::ErrorKind::from_code(s.rejected_reason)
                        .map_or("unknown reason", |k| k.describe());
                println!("refused by the plugin: {kind} (line {})", s.rejected_line);
                return ExitCode::from(EXIT_RUNTIME_ERROR);
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    println!("not applied within 2 s: is VPP running with the sampler plugin? (`sampler status`)");
    ExitCode::from(EXIT_RUNTIME_ERROR)
}

fn clear(dir: &Path) -> ExitCode {
    match clear_desired(dir) {
        Ok(Some(true)) => println!("desired.conf removed: the plugin stops sampling"),
        Ok(Some(false)) => println!("no desired.conf"),
        Ok(None) => {
            eprintln!(
                "sampler: desired.lock is held: another writer (PacketFrame's flow export?) owns desired.conf"
            );
            return ExitCode::from(EXIT_STARTUP_ERROR);
        }
        Err(e) => {
            eprintln!("sampler clear: {e}");
            return ExitCode::from(EXIT_RUNTIME_ERROR);
        }
    }
    ExitCode::from(EXIT_OK)
}

/// A sampled header as a person reads it: VLANs, then the 5-tuple.
fn describe_packet(h: &[u8]) -> String {
    let mut at = 12;
    let mut vlans = Vec::new();
    loop {
        let Some(et) = h.get(at..at + 2) else {
            return format!("{} bytes, too short for Ethernet", h.len());
        };
        let et = u16::from_be_bytes([et[0], et[1]]);
        if et == 0x8100 || et == 0x88a8 {
            let Some(tci) = h.get(at + 2..at + 4) else {
                return "VLAN tag cut short".into();
            };
            vlans.push((u16::from_be_bytes([tci[0], tci[1]]) & 0x0fff).to_string());
            at += 4;
            continue;
        }
        let l3 = &h[at + 2..];
        let body = match et {
            0x0800 => ipv4(l3),
            0x86dd => ipv6(l3),
            0x0806 => "arp".into(),
            _ => format!("ethertype {et:#06x}"),
        };
        return if vlans.is_empty() {
            body
        } else {
            format!("vlan {} {body}", vlans.join("."))
        };
    }
}

fn ipv4(p: &[u8]) -> String {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return "ipv4, header cut short".into();
    }
    let ihl = usize::from(p[0] & 0x0f) * 4;
    let src = Ipv4Addr::new(p[12], p[13], p[14], p[15]);
    let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
    let fragment = u16::from_be_bytes([p[6], p[7]]) & 0x1fff != 0;
    let l4 = if fragment {
        &[][..]
    } else {
        p.get(ihl..).unwrap_or(&[])
    };
    transport(p[9], IpAddr::V4(src), IpAddr::V4(dst), l4)
}

fn ipv6(p: &[u8]) -> String {
    if p.len() < 40 || p[0] >> 4 != 6 {
        return "ipv6, header cut short".into();
    }
    let addr = |b: &[u8]| Ipv6Addr::from(<[u8; 16]>::try_from(b).expect("16 bytes"));
    let (src, dst) = (IpAddr::V6(addr(&p[8..24])), IpAddr::V6(addr(&p[24..40])));
    let cut = || format!("ipv6 {src} -> {dst}, extension headers cut short");
    // Extension headers chain from the fixed header to the transport's.
    let (mut next, mut at) = (p[6], 40);
    for _ in 0..8 {
        let len = match next {
            // Hop-by-Hop, Routing, Destination Options, Mobility, HIP,
            // Shim6: a length in 8-byte units, not counting the first 8.
            0 | 43 | 60 | 135 | 139 | 140 => p.get(at + 1).map(|&l| (usize::from(l) + 1) * 8),
            // AH counts 4-byte units, not counting the first 8 bytes.
            51 => p.get(at + 1).map(|&l| (usize::from(l) + 2) * 4),
            44 => {
                let Some(frag) = p.get(at..at + 8) else {
                    return cut();
                };
                // Only the first fragment carries the transport header.
                if u16::from_be_bytes([frag[2], frag[3]]) >> 3 != 0 {
                    return transport(frag[0], src, dst, &[]);
                }
                Some(8)
            }
            _ => break,
        };
        let (Some(len), Some(&n)) = (len, p.get(at)) else {
            return cut();
        };
        next = n;
        at += len;
    }
    transport(next, src, dst, p.get(at..).unwrap_or(&[]))
}

fn transport(proto: u8, src: IpAddr, dst: IpAddr, l4: &[u8]) -> String {
    let with_port = |a: IpAddr, port: u16| match a {
        IpAddr::V6(a) => format!("[{a}]:{port}"),
        a => format!("{a}:{port}"),
    };
    let name = match proto {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmp6",
        _ => return format!("proto {proto} {src} -> {dst}"),
    };
    match (proto, l4.get(0..4)) {
        (6 | 17, Some(ports)) => format!(
            "{name} {} -> {}",
            with_port(src, u16::from_be_bytes([ports[0], ports[1]])),
            with_port(dst, u16::from_be_bytes([ports[2], ports[3]]))
        ),
        _ => format!("{name} {src} -> {dst}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(et: u16) -> Vec<u8> {
        let mut h = vec![0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1];
        h.extend_from_slice(&et.to_be_bytes());
        h
    }

    fn udp4() -> Vec<u8> {
        let mut h = eth(0x0800);
        h.extend_from_slice(&[0x45, 0, 0, 50, 0, 0, 0x40, 0, 64, 17, 0, 0]);
        h.extend_from_slice(&[192, 0, 2, 1, 198, 51, 100, 1]);
        h.extend_from_slice(&[0x04, 0x00, 0x00, 0x35, 0, 30, 0, 0]);
        h
    }

    #[test]
    fn five_tuples_decode() {
        assert_eq!(
            describe_packet(&udp4()),
            "udp 192.0.2.1:1024 -> 198.51.100.1:53"
        );

        let mut frag = udp4();
        frag[14 + 6] = 0x20;
        frag[14 + 7] = 0x10; // a non-first fragment: no ports to read
        assert_eq!(describe_packet(&frag), "udp 192.0.2.1 -> 198.51.100.1");

        let mut v6 = eth(0x8100);
        v6.extend_from_slice(&[0x00, 0x64, 0x86, 0xdd]); // VLAN 100, then IPv6
        v6.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, 6, 64]);
        v6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&[0x01, 0xbb, 0xc3, 0x50]);
        assert_eq!(
            describe_packet(&v6),
            "vlan 100 tcp [2001:db8::1]:443 -> [2001:db8::2]:50000"
        );
    }

    fn udp6(next: u8, ext: &[u8]) -> Vec<u8> {
        let mut h = eth(0x86dd);
        h.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, next, 64]);
        h.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        h.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        h.extend_from_slice(ext);
        h.extend_from_slice(&[0x04, 0x00, 0x00, 0x35, 0, 12, 0, 0]);
        h
    }

    #[test]
    fn ipv6_extension_headers_are_walked_to_the_ports() {
        let want = "udp [2001:db8::1]:1024 -> [2001:db8::2]:53";
        // Hop-by-Hop (8 bytes), then a Destination Options of 16.
        let mut ext = vec![60, 0, 1, 4, 0, 0, 0, 0];
        ext.extend_from_slice(&[17, 1]);
        ext.extend_from_slice(&[0; 14]);
        assert_eq!(describe_packet(&udp6(0, &ext)), want);
        // A first fragment carries the ports; a later one does not.
        assert_eq!(describe_packet(&udp6(44, &[17, 0, 0, 1, 0, 0, 0, 7])), want);
        assert_eq!(
            describe_packet(&udp6(44, &[17, 0, 0x05, 0x01, 0, 0, 0, 7])),
            "udp 2001:db8::1 -> 2001:db8::2"
        );
        // AH: (2 + 2) * 4 = 16 bytes.
        let mut ah = vec![17, 2];
        ah.extend_from_slice(&[0; 14]);
        assert_eq!(describe_packet(&udp6(51, &ah)), want);
        // A chain the copied header ends inside.
        let mut short = udp6(0, &[]);
        short.truncate(14 + 40);
        assert!(describe_packet(&short).contains("cut short"));
    }

    #[test]
    fn short_and_unknown_headers_say_so() {
        assert!(describe_packet(&[0; 10]).contains("too short"));
        assert_eq!(describe_packet(&eth(0x0806)), "arp");
        assert_eq!(describe_packet(&eth(0x88cc)), "ethertype 0x88cc");
        assert!(describe_packet(&eth(0x0800)).contains("cut short"));
        let mut icmp = udp4();
        icmp[14 + 9] = 1;
        assert_eq!(describe_packet(&icmp), "icmp 192.0.2.1 -> 198.51.100.1");
    }

    #[test]
    fn growth_sums_every_ring_and_interface_of_an_epoch() {
        let c = |pool0: u64, pool1: u64, selected: u64| Counters {
            head: selected,
            tail: 0,
            selected,
            written: selected,
            dropped_full: 0,
            pool: vec![[pool0, 9, 9], [pool1, 0, 0]],
        };
        let base = [c(100, 0, 1), c(0, 0, 0)];
        let now = [c(1100, 50, 11), c(0, 200, 2)];
        // Only ingress pools count; egress and drop are not sampled.
        assert_eq!(growth(&now, &base), [1000 + 50 + 200, 12, 12, 0]);
        assert_eq!(
            growth(&now, &[]),
            [1350, 13, 13, 0],
            "a new epoch counts from zero"
        );
    }

    #[test]
    fn a_new_epoch_counts_from_its_own_start() {
        use packetframe_sampler_shm::fs::{
            create_epoch, ensure_dir, publish_current, random_epoch,
        };
        use packetframe_sampler_shm::layout::Layout;
        use packetframe_sampler_shm::ring::RingWriter;
        let d = std::env::temp_dir().join(format!("pf-cli-rebase-{}", random_epoch()));
        ensure_dir(&d).unwrap();
        let l = Layout::new(1, 8, 16).unwrap();
        let m1 = create_epoch(&d, &l, 1, realtime_ns(), 0, "t").unwrap();
        publish_current(&d, 1, &l).unwrap();
        let mut f = Follower::consumer(&d).unwrap();
        let mut w = Window::new(&f);
        f.refresh().unwrap();
        w.rebase(&f, None, false);
        RingWriter::new(&l, m1.words(), 0).add_pool(0, Class::Ingress, 5);
        // VPP restarts; its epoch counts 7 before the switch is noticed.
        let last = f.opened().map(counters);
        let m2 = create_epoch(&d, &l, 2, realtime_ns(), 0, "t").unwrap();
        publish_current(&d, 2, &l).unwrap();
        RingWriter::new(&l, m2.words(), 0).add_pool(0, Class::Ingress, 7);
        let sw = f.refresh().unwrap();
        w.rebase(&f, last.as_deref(), sw.from.is_some());
        let now = counters(f.opened().unwrap());
        assert_eq!(growth(&now, &w.base)[0] + w.carried[0], 5 + 7);
        assert_eq!(
            w.drained.len(),
            1,
            "the new epoch's rings drain into the window"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_config_change_mid_window_keeps_each_interface_its_packets() {
        let iface = |name: &str, pool| Interface {
            name: name.into(),
            sw_if_index: Some(1),
            pool_index: pool,
            unresolved_since_ns: 0,
        };
        let mut w = Window::from(Vec::new());
        let before = Status {
            applied_generation: 4,
            interfaces: vec![iface("octeon0/0", 0), iface("octeon1/0", 1)],
            ..Status::default()
        };
        // octeon0/0 is dropped; pool 1 later goes to a new interface.
        let after = Status {
            applied_generation: 5,
            interfaces: vec![iface("octeon2/0", 1)],
            ..Status::default()
        };
        w.note(&before);
        w.note(&after);
        assert_eq!(w.generations, [4, 5]);
        let pools = BTreeMap::from([(0, 30), (1, 70)]);
        assert_eq!(
            interface_lines(&after.interfaces, &pools, &w.names),
            [
                "  octeon2/0 (sw_if_index 1): +70 packets (its pool also counted octeon1/0 in this window)",
                "  octeon0/0 (no longer configured): +30 packets",
            ]
        );
    }

    #[test]
    fn an_explicit_generation_must_be_past_every_one_in_sight() {
        assert_eq!(pick_generation(None, None), Ok(1));
        assert_eq!(pick_generation(None, Some(4)), Ok(5));
        assert_eq!(pick_generation(Some(9), Some(4)), Ok(9));
        assert_eq!(pick_generation(Some(9), None), Ok(9));
        assert!(
            pick_generation(Some(4), Some(4)).is_err(),
            "already applied"
        );
        assert!(pick_generation(Some(3), Some(4)).is_err());
    }

    #[test]
    fn latency_quantiles_are_within_an_eighth_in_fixed_memory() {
        // Every bucket's floor maps back to that bucket, in order.
        for b in 0..Latency::bucket(u64::MAX) {
            assert_eq!(Latency::bucket(Latency::floor(b)), b);
            assert!(Latency::floor(b) < Latency::floor(b + 1));
        }
        assert!(Latency::bucket(u64::MAX) < LATENCY_BUCKETS);
        let mut l = Latency::default();
        for ns in 1..=100_000u64 {
            l.add(ns * 1000);
        }
        for (p, exact) in [(0.5, 50_000_000u64), (0.99, 99_000_000)] {
            let q = l.quantile(p);
            assert!(q <= exact && exact - q <= exact / 8, "p{p}: {q} vs {exact}");
        }
        assert_eq!(l.max, 100_000_000);
        assert_eq!(
            l.counts.len(),
            LATENCY_BUCKETS,
            "the same 4 KiB at any count"
        );
        assert_eq!(Latency::default().quantile(0.5), 0);
    }
}
