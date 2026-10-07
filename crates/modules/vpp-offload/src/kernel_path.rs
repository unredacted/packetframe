//! The kernel path a steered port's EXEMPT traffic takes, and what keeps
//! it fed.
//!
//! A keep rule ([`crate::steer::RuleAction::Keep`]) hands its traffic
//! back to the PF instead of diverting it to VPP, and that traffic is no
//! longer control-plane trickle: on a production gateway the exemptions
//! cover the WAN /31s (the return path of every NAT'd flow), whole LAN
//! subnets, the IX LANs, another site's /24 and a CGNAT /10. Until 0.6.0
//! every keep delivered to PF queue 0, every port's queue-0 IRQ sat on
//! cpu0, and on 2026-10-07 that one core ran at 99% softirq while the
//! others idled — rx drops in the thousands per second, a directly
//! connected next hop losing 30% of pings, transit BGP falling on
//! hold-timer expiry, and a WAN monitor flapping the uplink, which
//! emptied conntrack and loaded the core further. Moving the queue-0
//! IRQs by hand to CPUs of their own cleared it within seconds.
//!
//! Three layers answer it, and this module holds the last two:
//!
//! 1. **RSS keeps** ([`crate::ntuple::KeepForm::Rss`]): keep traffic is
//!    spread over the PF's queues like unsteered traffic. The fix.
//! 2. **Queue-0 IRQ placement** ([`KernelPath::reconcile_queue0`]):
//!    while a port's keeps pin to queue 0 — its driver declined RSS — its
//!    queue-0 IRQ goes to a CPU of its own
//!    ([`crate::cores::plan_queue0_irqs`]), the prior affinity is
//!    recorded BEFORE the write, and it is put back when the keeps no
//!    longer need it: a steer that leaves the port on RSS or unsteered,
//!    the module's own teardown, or `packetframe detach`. The
//!    "apply, persist prior, restore" discipline of fast-path's
//!    `coalesce` directive, applied to an IRQ.
//! 3. **Visibility** ([`Meter`], [`PortReport`]): per steered port, the
//!    queue-0 and total receive frames and the PF's `rx_drops`, sampled
//!    from `ethtool -S`, exported as metrics, and a Degraded `kernel-path`
//!    row with the port named when that path is dropping.
//!
//! ## Unlike the attach-time IRQ moves
//!
//! [`crate::cores::move_irqs_off`] is deliberately never undone: the
//! mask it replaces was the kernel's default spread, and a reboot
//! re-spreads anyway. A queue-0 placement is different — it exists only
//! while a port's keeps need it, so it is restored the moment they stop.
//! It is also only as durable as the driver lets it be: the otx2 PF
//! re-applies its own affinity hint whenever it re-opens a port (a ring
//! resize, a link bounce, a provisioning push), which resets queue 0 to
//! cpu0. The `kernel-path` row shows where the IRQ is delivered now, and
//! the next steer (`packetframe reconfigure`) places it again. A record
//! whose IRQ no longer holds the CPU this module wrote is dropped on
//! restore WITHOUT a write — something else has moved it since, and
//! putting back a value from before that would undo their change.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::cores::{self, Queue0Choice};
use crate::ntuple::{KeepForm, KeepVerdict};

/// The placement record under `state-dir`, beside the module's state
/// file and outliving it: a `--keep-vpp` restart leaves the keeps (and
/// so the placement) in force for the next daemon, which must restore
/// the ORIGINAL affinity on its teardown, not the one it found.
pub const RECORD_FILE: &str = "vpp-queue0-irqs.json";

/// A steered port's PF dropping at least this many frames a second is
/// the kernel path failing to keep up — the condition the `kernel-path`
/// row degrades on.
///
/// While VPP holds a member's VF the PF's `rx_drops` legitimately sits
/// near zero (the runbook's bridge-member entry: the flood the kernel
/// used to receive-and-drop goes to the VF instead), so a sustained
/// hundred a second is not background. The incident ran at 1,600 and
/// 3,900.
pub const DROPS_DEGRADED_PER_SEC: f64 = 100.0;

/// How often the kernel-path counters are read. Three ioctls per steered
/// port; the rates are averaged over this window.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(10);

/// With RSS keeps, queue 0 taking at least this share of a busy port's
/// receive is worth saying: spread over 18 queues it should sit near
/// 1/18. One elephant flow can do it legitimately, so it is said, never
/// degraded — but it is also exactly what a driver that echoes the RSS
/// flag on readback without programming the action would look like,
/// which no readback can catch.
pub const RSS_SUSPECT_SHARE: f64 = 0.5;

/// ... and "busy" means at least this many frames a second, so an idle
/// port's handful of frames cannot trip it.
pub const RSS_SUSPECT_MIN_FPS: f64 = 1_000.0;

/// At most one `kernel_path_dropping` event per port this often while
/// the condition persists; the transition back is always recorded.
pub const DROP_EVENT_EVERY: Duration = Duration::from_secs(600);

/// The counters one port's driver exports for its kernel receive path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueCounters {
    /// `rxq0: frames` — what receive queue 0 has taken.
    pub queue0_frames: u64,
    /// Every `rxq<N>: frames`, summed: the PF's whole receive.
    pub rx_frames: u64,
    /// `rx_drops`: frames the PF's receive dropped, port-wide (the
    /// driver keeps no per-queue drop count).
    pub rx_drops: u64,
    /// How many `rxq<N>` queues the driver reported.
    pub queues: u32,
}

/// [`QueueCounters`] from an `ethtool -S` listing.
///
/// The names are the otx2 driver's: `rxq<N>: frames` per receive queue
/// and `rx_drops` for the port. Queues are counted from the names, never
/// from `ethtool -l`, which this driver reports as `Combined: 0`. A
/// listing without `rxq0: frames` or `rx_drops` is another driver's, and
/// is reported as such rather than read as zero.
pub fn parse_counters(stats: &[(String, u64)]) -> Result<QueueCounters, String> {
    let mut c = QueueCounters::default();
    let (mut q0, mut drops) = (false, false);
    for (name, value) in stats {
        if name == "rx_drops" {
            c.rx_drops = *value;
            drops = true;
            continue;
        }
        let Some(rest) = name.strip_prefix("rxq") else {
            continue;
        };
        let Some((n, field)) = rest.split_once(": ") else {
            continue;
        };
        if field != "frames" {
            continue;
        }
        let Ok(n) = n.parse::<u32>() else {
            continue;
        };
        c.rx_frames = c.rx_frames.saturating_add(*value);
        c.queues += 1;
        if n == 0 {
            c.queue0_frames = *value;
            q0 = true;
        }
    }
    match (q0, drops) {
        (true, true) => Ok(c),
        (false, _) => Err("the driver exports no `rxq0: frames` statistic".into()),
        (_, false) => Err("the driver exports no `rx_drops` statistic".into()),
    }
}

/// Per-second rates over one sampling window.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rates {
    pub queue0_fps: f64,
    pub rx_fps: f64,
    pub drops_ps: f64,
}

impl Rates {
    /// Queue 0's share of the PF's receive, 0..=1, or `None` with
    /// nothing received. With RSS keeps it sits near `1 / queues`; with
    /// queue-0 keeps carrying the bulk it approaches 1.
    pub fn queue0_share(&self) -> Option<f64> {
        (self.rx_fps > 0.0).then(|| (self.queue0_fps / self.rx_fps).min(1.0))
    }
}

/// One port's counter history: enough for rates.
#[derive(Debug, Default, Clone)]
pub struct Meter {
    last: Option<(Instant, QueueCounters)>,
    /// The latest window's rates; `None` until two samples exist.
    pub rates: Option<Rates>,
}

impl Meter {
    /// Take a sample. A counter that went BACKWARDS (a driver reset, a
    /// port re-created) restarts the baseline rather than producing a
    /// huge or negative rate.
    pub fn observe(&mut self, at: Instant, now: QueueCounters) -> Option<Rates> {
        let prev = self.last.replace((at, now));
        self.rates = prev.and_then(|(then, was)| {
            let secs = at.checked_duration_since(then)?.as_secs_f64();
            if secs <= 0.0
                || now.queue0_frames < was.queue0_frames
                || now.rx_frames < was.rx_frames
                || now.rx_drops < was.rx_drops
            {
                return None;
            }
            Some(Rates {
                queue0_fps: (now.queue0_frames - was.queue0_frames) as f64 / secs,
                rx_fps: (now.rx_frames - was.rx_frames) as f64 / secs,
                drops_ps: (now.rx_drops - was.rx_drops) as f64 / secs,
            })
        });
        self.rates
    }

    /// A sample could not be taken. The window that ended at the last
    /// good sample is no longer CURRENT, so its rates go — left in
    /// place, a drop rate measured before the read started failing kept
    /// the port reported as dropping (or a stale zero kept it reported
    /// as quiet) for as long as the counters stayed unreadable (review
    /// finding). The last good counters stay as the baseline: the next
    /// sample that succeeds rates the whole gap, which is an average
    /// over a longer window, not a wrong one.
    pub fn sample_failed(&mut self) {
        self.rates = None;
    }

    /// The last sample's raw counters.
    pub fn counters(&self) -> Option<QueueCounters> {
        self.last.map(|(_, c)| c)
    }
}

/// Where one port's queue-0 IRQ is, as far as this module is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Queue0Irq {
    /// Placed by this module on `cpu`; `prior` is what it restores.
    Placed { irq: u32, cpu: u16, prior: String },
    /// Wanted, and not placed — the reason names why.
    Unplaced { why: String },
}

/// Everything `packetframe status` reports about one steered port's
/// kernel path.
#[derive(Debug, Clone, PartialEq)]
pub struct PortReport {
    pub iface: String,
    /// The form this process installed the port's keeps in, and why it
    /// fell back if it did. `None` for keeps inherited and not yet
    /// re-installed.
    pub verdict: Option<KeepVerdict>,
    /// Keeps the last steering audit read back in each form.
    pub observed_rss: usize,
    pub observed_queue0: usize,
    pub irq: Option<Queue0Irq>,
    /// Where the queue-0 IRQ is delivered right now
    /// (`effective_affinity_list`), when it could be read.
    pub irq_delivered_on: Option<String>,
    pub counters: Option<QueueCounters>,
    pub rates: Option<Rates>,
    /// Why the counters could not be read, if they could not.
    pub unreadable: Option<String>,
}

impl PortReport {
    /// The kernel path on this port is dropping at the degraded rate.
    pub fn dropping(&self) -> bool {
        self.rates
            .is_some_and(|r| r.drops_ps >= DROPS_DEGRADED_PER_SEC)
    }

    /// The port's keeps were installed as RSS keeps, yet queue 0 takes
    /// most of a busy receive: see [`RSS_SUSPECT_SHARE`].
    pub fn rss_suspect(&self) -> bool {
        let rss = self
            .verdict
            .as_ref()
            .is_some_and(|v| v.form == KeepForm::Rss);
        rss && self.rates.is_some_and(|r| {
            r.rx_fps >= RSS_SUSPECT_MIN_FPS
                && r.queue0_share().is_some_and(|s| s >= RSS_SUSPECT_SHARE)
        })
    }

    /// Whether this port's keeps deliver to queue 0, by the best
    /// evidence available: the form this process installed, else what
    /// the audit read back.
    pub fn pins_queue0(&self) -> bool {
        match &self.verdict {
            Some(v) => v.form == KeepForm::Queue0,
            None => self.observed_queue0 > 0,
        }
    }
}

/// When a port's drop condition is worth an event: on entering it, at
/// most once per [`DROP_EVENT_EVERY`] while it lasts, and on leaving it.
#[derive(Debug, Default, Clone)]
pub struct DropWatch {
    dropping: bool,
    last_event: Option<Instant>,
}

impl DropWatch {
    /// The event to record for this observation, if any: `Some(true)`
    /// dropping, `Some(false)` recovered.
    pub fn observe(&mut self, now: Instant, dropping: bool) -> Option<bool> {
        let was = std::mem::replace(&mut self.dropping, dropping);
        match (was, dropping) {
            (false, false) => None,
            (true, false) => Some(false),
            (_, true) => {
                let due = self
                    .last_event
                    .is_none_or(|t| now.saturating_duration_since(t) >= DROP_EVENT_EVERY);
                due.then(|| {
                    self.last_event = Some(now);
                    true
                })
            }
        }
    }
}

/// What the runtime has observed of the kernel path, per steered port:
/// counter history, read failures, the drop condition's event pacing,
/// and the keep forms the last steering audit read back.
#[derive(Debug, Default)]
pub struct KernelWatch {
    meters: Vec<(String, Meter)>,
    unreadable: Vec<(String, String)>,
    delivered: Vec<(String, String)>,
    drops: Vec<(String, DropWatch)>,
    /// From the last steering audit
    /// ([`crate::runtime::SteeringAudit::keeps_observed`]).
    pub keeps_observed: Vec<(String, KeepForm)>,
    last_sample: Option<Instant>,
}

impl KernelWatch {
    /// Nothing is steered: forget every port.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Sample `ports` if [`SAMPLE_EVERY`] has passed, update the rates,
    /// and record the drop condition's transitions — a journal line and
    /// a paced `kernel_path_dropping` event.
    pub fn tick(
        &mut self,
        now: Instant,
        ports: &[String],
        kp: &mut dyn KernelPath,
        keeps: &[crate::ntuple::KeepPort],
    ) {
        let due = self
            .last_sample
            .is_none_or(|t| now.saturating_duration_since(t) >= SAMPLE_EVERY);
        if !due {
            return;
        }
        self.last_sample = Some(now);
        self.meters.retain(|(i, _)| ports.contains(i));
        self.drops.retain(|(i, _)| ports.contains(i));
        self.unreadable.clear();
        self.delivered.clear();
        for iface in ports {
            if let Some(on) = kp.queue0_delivery(iface) {
                self.delivered.push((iface.clone(), on));
            }
            let counters = match kp.counters(iface) {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(iface = %iface, error = %e, "kernel-path counters unreadable");
                    // The last window is not current any more: nothing
                    // may go on reporting it as though it were.
                    if let Some((_, m)) = self.meters.iter_mut().find(|(i, _)| i == iface) {
                        m.sample_failed();
                    }
                    self.unreadable.push((iface.clone(), e));
                    continue;
                }
            };
            let k = match self.meters.iter().position(|(i, _)| i == iface) {
                Some(k) => k,
                None => {
                    self.meters.push((iface.clone(), Meter::default()));
                    self.meters.len() - 1
                }
            };
            let rates = self.meters[k].1.observe(now, counters);
            let dropping = rates.is_some_and(|r| r.drops_ps >= DROPS_DEGRADED_PER_SEC);
            let d = match self.drops.iter().position(|(i, _)| i == iface) {
                Some(d) => d,
                None => {
                    self.drops.push((iface.clone(), DropWatch::default()));
                    self.drops.len() - 1
                }
            };
            let Some(event) = self.drops[d].1.observe(now, dropping) else {
                continue;
            };
            let form = keeps
                .iter()
                .find(|p| p.iface == *iface)
                .and_then(|p| p.verdict.as_ref())
                .map_or("unknown", |v| v.form.label());
            let (drops_ps, share) = rates.map_or((0.0, None), |r| (r.drops_ps, r.queue0_share()));
            let share_s = share.map_or("n/a".to_string(), |s| format!("{:.0}%", s * 100.0));
            let ev = if event {
                tracing::warn!(
                    iface = %iface,
                    drops_per_second = drops_ps.round() as u64,
                    queue0_share = %share_s,
                    keep_form = form,
                    "the kernel path on a steered port is dropping frames: exempt traffic is \
                     arriving faster than the CPU its queue's IRQ is on can take it. \
                     `packetframe status`, row kernel-path, names the port"
                );
                packetframe_common::events::Event::warn(
                    crate::MODULE_NAME,
                    packetframe_common::events::kind::KERNEL_PATH_DROPPING,
                )
            } else {
                tracing::info!(iface = %iface, "the kernel path on this port stopped dropping");
                packetframe_common::events::Event::info(
                    crate::MODULE_NAME,
                    packetframe_common::events::kind::KERNEL_PATH_DROPPING,
                )
            };
            ev.field("port", iface.as_str())
                .field("dropping", event)
                .field("drops_per_second", drops_ps.round() as u64)
                .field("queue0_share", share_s)
                .field("keep_form", form)
                .emit();
        }
    }

    /// One [`PortReport`] per port with keeps or a sample.
    pub fn report(
        &self,
        keeps: &[crate::ntuple::KeepPort],
        irqs: &[(String, Queue0Irq)],
    ) -> Vec<PortReport> {
        let mut ifaces: Vec<String> = keeps.iter().map(|p| p.iface.clone()).collect();
        ifaces.extend(self.meters.iter().map(|(i, _)| i.clone()));
        ifaces.extend(self.unreadable.iter().map(|(i, _)| i.clone()));
        ifaces.extend(self.keeps_observed.iter().map(|(i, _)| i.clone()));
        ifaces.sort();
        ifaces.dedup();
        ifaces
            .into_iter()
            .map(|iface| {
                let meter = self
                    .meters
                    .iter()
                    .find(|(i, _)| *i == iface)
                    .map(|(_, m)| m);
                let seen = |f: KeepForm| {
                    self.keeps_observed
                        .iter()
                        .filter(|(i, form)| *i == iface && *form == f)
                        .count()
                };
                let unreadable = self
                    .unreadable
                    .iter()
                    .find(|(i, _)| *i == iface)
                    .map(|(_, e)| e.clone());
                // Nothing from the last good sample is published while
                // the counters cannot be read: the cumulative gauges are
                // absent rather than frozen, as the rates are.
                let meter = meter.filter(|_| unreadable.is_none());
                PortReport {
                    verdict: keeps
                        .iter()
                        .find(|p| p.iface == iface)
                        .and_then(|p| p.verdict.clone()),
                    observed_rss: seen(KeepForm::Rss),
                    observed_queue0: seen(KeepForm::Queue0),
                    irq: irqs
                        .iter()
                        .find(|(i, _)| *i == iface)
                        .map(|(_, q)| q.clone()),
                    irq_delivered_on: self
                        .delivered
                        .iter()
                        .find(|(i, _)| *i == iface)
                        .map(|(_, d)| d.clone()),
                    counters: meter.and_then(Meter::counters),
                    rates: meter.and_then(|m| m.rates),
                    unreadable,
                    iface,
                }
            })
            .collect()
    }
}

/// The host side of the kernel path: queue-0 IRQ placement and the
/// receive counters. A seam so the runtime's use of it is testable with
/// a recording fake, and so non-Linux builds never pretend.
pub trait KernelPath {
    /// Bring the queue-0 IRQ placements in line with the keeps: place
    /// the queue-0 IRQ of every port in `want` (keeps known to pin queue
    /// 0), leave every placement for a port in `hold` exactly as it is
    /// (keeps of unknown form — inherited, not yet re-installed), and
    /// restore every other recorded placement. Never fails: every
    /// outcome is a log line, and what could not be done shows in
    /// [`Self::queue0_irqs`].
    fn reconcile_queue0(&mut self, want: &[String], hold: &[String]);
    /// The placement state per port, as of the last reconcile.
    fn queue0_irqs(&self) -> Vec<(String, Queue0Irq)>;
    /// Where `iface`'s queue-0 IRQ is delivered now, if it can be read.
    fn queue0_delivery(&self, iface: &str) -> Option<String>;
    /// `iface`'s kernel receive counters.
    fn counters(&mut self, iface: &str) -> Result<QueueCounters, String>;
}

/// No kernel path installed: tests and non-Linux. Silent, like
/// [`crate::runtime::NoKick`] — a production attach log without the
/// placement lines means the wiring is missing, visibly.
#[derive(Debug, Default)]
pub struct NoKernelPath;

impl KernelPath for NoKernelPath {
    fn reconcile_queue0(&mut self, _want: &[String], _hold: &[String]) {}
    fn queue0_irqs(&self) -> Vec<(String, Queue0Irq)> {
        Vec::new()
    }
    fn queue0_delivery(&self, _iface: &str) -> Option<String> {
        None
    }
    fn counters(&mut self, _iface: &str) -> Result<QueueCounters, String> {
        Err("no kernel-path reader is installed".into())
    }
}

/// The placement record: what each placed IRQ held before, and what
/// this module wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Queue0File {
    /// `/proc/sys/kernel/random/boot_id` when written. A reboot resets
    /// every IRQ to the driver's spread, so another boot's records
    /// describe nothing and are dropped unrestored. Empty when
    /// unreadable; treated as this boot.
    pub boot_id: String,
    pub irqs: Vec<Queue0Record>,
}

/// One placed IRQ.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Queue0Record {
    pub iface: String,
    pub irq: u32,
    /// `smp_affinity_list` before this module first wrote it — kept
    /// across re-placements and across daemons, so a restore always puts
    /// back what was there before PacketFrame touched it.
    pub prior: String,
    /// The CPU written. A restore writes `prior` only while the IRQ
    /// still holds exactly this.
    pub placed: u16,
}

fn record_path(state_dir: &Path) -> PathBuf {
    state_dir.join(RECORD_FILE)
}

// Same no-follow discipline as fast-path's coalesce record: the daemon
// is root and `state-dir` may be writable by someone who is not.
#[cfg(target_os = "linux")]
fn write_record(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    packetframe_common::statefile::write_atomic(path, contents)
}

#[cfg(not(target_os = "linux"))]
fn write_record(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
}

#[cfg(target_os = "linux")]
fn read_record(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    packetframe_common::statefile::read_no_follow(path)
}

#[cfg(not(target_os = "linux"))]
fn read_record(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(r) => Ok(Some(r)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn remove_record(path: &Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    let r = packetframe_common::statefile::remove_state_record(path);
    #[cfg(not(target_os = "linux"))]
    let r = std::fs::remove_file(path);
    match r {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

/// Load the record. `Ok(empty)` when there is none.
pub fn load(state_dir: &Path) -> Result<Queue0File, String> {
    let path = record_path(state_dir);
    match read_record(&path) {
        Ok(None) => Ok(Queue0File::default()),
        Ok(Some(raw)) => {
            serde_json::from_slice(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
        }
        Err(e) => Err(format!("read {}: {e}", path.display())),
    }
}

/// Save the record, or remove it when it holds nothing.
pub fn save(state_dir: &Path, file: &Queue0File) -> Result<(), String> {
    let path = record_path(state_dir);
    if file.irqs.is_empty() {
        return remove_record(&path).map_err(|e| format!("remove {}: {e}", path.display()));
    }
    let json = serde_json::to_vec_pretty(file).expect("the record serializes");
    write_record(&path, &json).map_err(|e| format!("write {}: {e}", path.display()))
}

/// The running kernel's boot id; empty when unreadable.
pub fn current_boot_id() -> String {
    crate::process::boot_id().unwrap_or_default()
}

fn same_boot(recorded: &str, now: &str) -> bool {
    recorded.is_empty() || now.is_empty() || recorded == now
}

fn affinity_path(proc_irq: &Path, irq: u32) -> PathBuf {
    proc_irq.join(irq.to_string()).join("smp_affinity_list")
}

fn read_affinity(proc_irq: &Path, irq: u32) -> Result<String, String> {
    let p = affinity_path(proc_irq, irq);
    std::fs::read_to_string(&p)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("read {}: {e}", p.display()))
}

fn write_affinity(proc_irq: &Path, irq: u32, cpus: &str) -> Result<(), String> {
    let p = affinity_path(proc_irq, irq);
    std::fs::write(&p, format!("{cpus}\n")).map_err(|e| format!("write {}: {e}", p.display()))
}

/// What restoring one record did.
#[derive(Debug, PartialEq, Eq)]
enum Restore {
    /// `prior` written back.
    Restored,
    /// Nothing written: the IRQ no longer holds what this module put
    /// there (moved since — a port re-open resets it — or gone).
    Moved,
    /// The write failed; the record stays for the next attempt.
    Failed(String),
}

fn restore_one(proc_irq: &Path, rec: &Queue0Record) -> Restore {
    let now = match read_affinity(proc_irq, rec.irq) {
        Ok(s) => s,
        // The IRQ is gone (its port released it), so there is nothing to
        // hold a value of ours.
        Err(_) => return Restore::Moved,
    };
    if cores::parse_cpu_list(&now).ok() != Some(vec![rec.placed]) {
        return Restore::Moved;
    }
    match write_affinity(proc_irq, rec.irq, &rec.prior) {
        Ok(()) => Restore::Restored,
        Err(e) => Restore::Failed(e),
    }
}

/// Restore every recorded placement — `packetframe detach`'s half, run
/// with no daemon. Returns how many were written back; `Err` names the
/// ones whose write failed, which stay recorded for the next detach.
pub fn restore_recorded(state_dir: &Path, proc_irq: &Path, boot_id: &str) -> Result<usize, String> {
    let file = load(state_dir)?;
    if file.irqs.is_empty() {
        return Ok(0);
    }
    if !same_boot(&file.boot_id, boot_id) {
        tracing::info!(
            "the queue-0 IRQ record is from a previous boot; the reboot already reset those IRQs"
        );
        save(state_dir, &Queue0File::default())?;
        return Ok(0);
    }
    let mut restored = 0;
    let mut failed = Vec::new();
    let mut kept = Vec::new();
    for rec in file.irqs {
        match restore_one(proc_irq, &rec) {
            Restore::Restored => {
                tracing::info!(
                    iface = %rec.iface,
                    irq = rec.irq,
                    from = rec.placed,
                    to = %rec.prior,
                    "queue-0 IRQ affinity restored"
                );
                restored += 1;
            }
            Restore::Moved => tracing::info!(
                iface = %rec.iface,
                irq = rec.irq,
                "queue-0 IRQ no longer on the CPU PacketFrame placed it on; left as it is"
            ),
            Restore::Failed(e) => {
                failed.push(format!("{} irq {}: {e}", rec.iface, rec.irq));
                kept.push(rec);
            }
        }
    }
    save(
        state_dir,
        &Queue0File {
            boot_id: file.boot_id,
            irqs: kept,
        },
    )?;
    if failed.is_empty() {
        Ok(restored)
    } else {
        Err(format!(
            "could not restore {} queue-0 IRQ affinit(ies): {}; by hand: `echo <cpus> > \
             /proc/irq/<irq>/smp_affinity_list` with the `prior` in {}",
            failed.len(),
            failed.join(", "),
            record_path(state_dir).display()
        ))
    }
}

/// `ethtool -S` for one interface: `(name, value)` in the driver's order.
type StatsReader = Box<dyn FnMut(&str) -> std::io::Result<Vec<(String, u64)>>>;

/// The real [`KernelPath`]: `/proc/irq`, sysfs and `SIOCETHTOOL`.
pub struct LiveKernelPath {
    sysfs_net: PathBuf,
    proc_irq: PathBuf,
    sysfs_cpu: PathBuf,
    state_dir: PathBuf,
    /// Every CPU VPP is on (main and workers, derived or observed).
    vpp_cores: Vec<u16>,
    /// The published control-plane CPUs: a last resort.
    avoid: Vec<u16>,
    boot_id: String,
    /// `ethtool -S`, a seam for tests.
    stats: StatsReader,
    unplaced: Vec<(String, String)>,
    placed: Vec<Queue0Record>,
    /// Why the record could not be read, if it could not. Placement is
    /// then off for this daemon: rewriting the file would erase priors
    /// nothing else knows, and a placement whose prior cannot be
    /// recorded is not made.
    frozen: Option<String>,
}

impl LiveKernelPath {
    pub fn new(
        sysfs_net: PathBuf,
        proc_irq: PathBuf,
        sysfs_cpu: PathBuf,
        state_dir: PathBuf,
        vpp_cores: Vec<u16>,
        avoid: Vec<u16>,
    ) -> Self {
        Self::with_seams(
            [sysfs_net, proc_irq, sysfs_cpu, state_dir],
            vpp_cores,
            avoid,
            current_boot_id(),
            Box::new(packetframe_common::ethtool::read_stats),
        )
    }

    /// [`Self::new`] with the boot id and the stats reader chosen by the
    /// caller. The record is loaded HERE, once, against that boot id —
    /// a constructor that loaded against the running kernel's first and
    /// was re-pointed afterwards would already have dropped a record as
    /// another boot's (a test on Linux found that).
    fn with_seams(
        [sysfs_net, proc_irq, sysfs_cpu, state_dir]: [PathBuf; 4],
        vpp_cores: Vec<u16>,
        avoid: Vec<u16>,
        boot_id: String,
        stats: StatsReader,
    ) -> Self {
        let mut me = Self {
            sysfs_net,
            proc_irq,
            sysfs_cpu,
            state_dir,
            vpp_cores,
            avoid,
            boot_id,
            stats,
            unplaced: Vec::new(),
            placed: Vec::new(),
            frozen: None,
        };
        me.load_current();
        me
    }

    /// The record as this boot sees it: another boot's is dropped, an
    /// unreadable one freezes placement.
    fn load_current(&mut self) {
        self.frozen = None;
        self.placed = match load(&self.state_dir) {
            Ok(f) if same_boot(&f.boot_id, &self.boot_id) => f.irqs,
            Ok(f) => {
                if !f.irqs.is_empty() {
                    tracing::info!(
                        "the queue-0 IRQ record is from a previous boot; the reboot already \
                         reset those IRQs"
                    );
                    if let Err(e) = save(&self.state_dir, &Queue0File::default()) {
                        tracing::warn!(error = %e, "could not clear the stale queue-0 IRQ record");
                    }
                }
                Vec::new()
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "the queue-0 IRQ record is unreadable; left for inspection, and queue-0 \
                     IRQ placement is off for this daemon"
                );
                self.frozen = Some(e);
                Vec::new()
            }
        };
    }

    fn persist(&self) -> Result<(), String> {
        if let Some(why) = &self.frozen {
            return Err(format!("the record is unreadable ({why})"));
        }
        save(
            &self.state_dir,
            &Queue0File {
                boot_id: self.boot_id.clone(),
                irqs: self.placed.clone(),
            },
        )
    }

    fn restore(&mut self, keep: impl Fn(&Queue0Record) -> bool) {
        let mut kept = Vec::new();
        for rec in std::mem::take(&mut self.placed) {
            if keep(&rec) {
                kept.push(rec);
                continue;
            }
            match restore_one(&self.proc_irq, &rec) {
                Restore::Restored => tracing::info!(
                    iface = %rec.iface,
                    irq = rec.irq,
                    from = rec.placed,
                    to = %rec.prior,
                    "queue-0 IRQ affinity restored: this port's keeps no longer pin to queue 0"
                ),
                Restore::Moved => tracing::info!(
                    iface = %rec.iface,
                    irq = rec.irq,
                    "queue-0 IRQ no longer on the CPU PacketFrame placed it on (a port re-open \
                     resets it); left as it is"
                ),
                Restore::Failed(e) => {
                    tracing::warn!(
                        iface = %rec.iface,
                        irq = rec.irq,
                        error = %e,
                        "could not restore the queue-0 IRQ affinity; kept on record for the \
                         next attempt"
                    );
                    kept.push(rec);
                }
            }
        }
        self.placed = kept;
    }
}

impl KernelPath for LiveKernelPath {
    fn reconcile_queue0(&mut self, want: &[String], hold: &[String]) {
        self.unplaced.clear();
        if let Some(why) = &self.frozen {
            self.unplaced = want
                .iter()
                .map(|i| {
                    (
                        i.clone(),
                        format!("the placement record is unreadable ({why}), so nothing is moved"),
                    )
                })
                .collect();
            self.log_unplaced();
            return;
        }
        // Restore first: a port leaving the set frees its CPU for the
        // plan below.
        self.restore(|r| want.contains(&r.iface) || hold.contains(&r.iface));

        let mut wanted: Vec<(String, u32)> = Vec::new();
        for iface in want {
            match cores::queue0_irq(&self.sysfs_net, &self.proc_irq, iface) {
                Ok(Some(irq)) => wanted.push((iface.clone(), irq)),
                Ok(None) => self.unplaced.push((
                    iface.clone(),
                    format!(
                        "no IRQ named `{iface}-rxtx-0` among the port's MSI vectors, so queue 0's \
                         cannot be told apart"
                    ),
                )),
                Err(e) => self.unplaced.push((iface.clone(), e)),
            }
        }
        // A port whose queue-0 vector changed (re-probed driver) is a
        // stale record: restore it before placing the new one.
        let stale_irq =
            |r: &Queue0Record| wanted.iter().any(|(i, irq)| *i == r.iface && *irq != r.irq);
        if self.placed.iter().any(stale_irq) {
            let wanted_now = wanted.clone();
            self.restore(move |r| {
                !wanted_now
                    .iter()
                    .any(|(i, irq)| *i == r.iface && *irq != r.irq)
            });
        }
        if wanted.is_empty() {
            if let Err(e) = self.persist() {
                tracing::warn!(error = %e, "could not write the queue-0 IRQ record");
            }
            self.log_unplaced();
            return;
        }
        let topology = cores::read_cpu_topology(&self.sysfs_cpu);
        let irq_map = cores::nic_irq_map(&self.sysfs_net, &self.proc_irq);
        let (online, isolated, irq_map) = match (topology, irq_map) {
            (Ok((o, i)), Ok(m)) => (o, i, m),
            (Err(e), _) | (_, Err(e)) => {
                for (iface, _) in &wanted {
                    self.unplaced
                        .push((iface.clone(), format!("reading the host: {e}")));
                }
                self.log_unplaced();
                return;
            }
        };
        let current: Vec<Queue0Choice> = self
            .placed
            .iter()
            .map(|r| Queue0Choice {
                iface: r.iface.clone(),
                irq: r.irq,
                cpu: r.placed,
            })
            .collect();
        let plan = cores::plan_queue0_irqs(
            &online,
            &isolated,
            &self.vpp_cores,
            &self.avoid,
            &irq_map,
            &current,
            &wanted,
        );
        for (iface, _) in &plan.unplaced {
            self.unplaced.push((
                iface.clone(),
                format!(
                    "no CPU outside VPP's cores ({}), the isolated set and cpu0 can take it",
                    cores::format_cpu_list(&self.vpp_cores)
                ),
            ));
        }
        for choice in plan.choices {
            self.place(choice);
        }
        if let Err(e) = self.persist() {
            tracing::warn!(error = %e, "could not write the queue-0 IRQ record");
        }
        self.log_unplaced();
    }

    fn queue0_irqs(&self) -> Vec<(String, Queue0Irq)> {
        let mut out: Vec<(String, Queue0Irq)> = self
            .placed
            .iter()
            .map(|r| {
                (
                    r.iface.clone(),
                    Queue0Irq::Placed {
                        irq: r.irq,
                        cpu: r.placed,
                        prior: r.prior.clone(),
                    },
                )
            })
            .collect();
        out.extend(
            self.unplaced
                .iter()
                .map(|(i, why)| (i.clone(), Queue0Irq::Unplaced { why: why.clone() })),
        );
        out
    }

    fn queue0_delivery(&self, iface: &str) -> Option<String> {
        let irq = cores::queue0_irq(&self.sysfs_net, &self.proc_irq, iface).ok()??;
        let dir = self.proc_irq.join(irq.to_string());
        std::fs::read_to_string(dir.join("effective_affinity_list"))
            .or_else(|_| std::fs::read_to_string(dir.join("smp_affinity_list")))
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn counters(&mut self, iface: &str) -> Result<QueueCounters, String> {
        let stats = (self.stats)(iface).map_err(|e| format!("ethtool -S {iface}: {e}"))?;
        parse_counters(&stats).map_err(|e| format!("{iface}: {e}"))
    }
}

impl LiveKernelPath {
    /// Write one placement, recording the prior affinity FIRST.
    fn place(&mut self, choice: Queue0Choice) {
        let existing = self
            .placed
            .iter()
            .position(|r| r.iface == choice.iface && r.irq == choice.irq);
        let now = match read_affinity(&self.proc_irq, choice.irq) {
            Ok(s) => s,
            Err(e) => {
                self.unplaced.push((choice.iface, e));
                return;
            }
        };
        if let Some(k) = existing {
            if self.placed[k].placed == choice.cpu
                && cores::parse_cpu_list(&now).ok() == Some(vec![choice.cpu])
            {
                return; // already where it should be
            }
        }
        // The prior survives a re-placement and a daemon restart: it is
        // what was there before PacketFrame first wrote, not what the
        // last placement left.
        let prior = existing.map_or(now.clone(), |k| self.placed[k].prior.clone());
        let rec = Queue0Record {
            iface: choice.iface.clone(),
            irq: choice.irq,
            prior,
            placed: choice.cpu,
        };
        match existing {
            Some(k) => self.placed[k] = rec,
            None => self.placed.push(rec),
        }
        // Recorded BEFORE the write: a crash between the two would
        // otherwise leave a change nothing knows how to undo.
        if let Err(e) = self.persist() {
            tracing::warn!(
                iface = %choice.iface,
                error = %e,
                "could not record the queue-0 IRQ's prior affinity, so it is not moved: a \
                 placement that cannot be restored is not made"
            );
            self.placed
                .retain(|r| !(r.iface == choice.iface && r.irq == choice.irq));
            self.unplaced
                .push((choice.iface, format!("recording it: {e}")));
            return;
        }
        match write_affinity(&self.proc_irq, choice.irq, &choice.cpu.to_string()) {
            Ok(()) => tracing::info!(
                iface = %choice.iface,
                irq = choice.irq,
                was = %now,
                now = choice.cpu,
                "queue-0 IRQ placed on a CPU of its own: this port's keep rules deliver to \
                 queue 0, and every exempt frame on it is handled where this IRQ fires"
            ),
            Err(e) => {
                tracing::warn!(
                    iface = %choice.iface,
                    irq = choice.irq,
                    error = %e,
                    "could not place the queue-0 IRQ; it stays where it was"
                );
                // Nothing was written: the record must not claim a
                // placement, or a later restore would compare against a
                // CPU this module never set.
                match existing {
                    Some(_) => {} // the previous placement record still stands
                    None => self
                        .placed
                        .retain(|r| !(r.iface == choice.iface && r.irq == choice.irq)),
                }
                self.unplaced.push((choice.iface, e));
            }
        }
    }

    fn log_unplaced(&self) {
        for (iface, why) in &self.unplaced {
            tracing::warn!(
                iface,
                reason = %why,
                "this port's keep rules deliver to queue 0 and its queue-0 IRQ could not be \
                 given a CPU of its own; all its exempt traffic is handled on one core. Move it \
                 by hand if that core saturates (docs/runbooks/vpp-offload.md, \"The kernel \
                 path for exempt traffic\")"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(pairs: &[(&str, u64)]) -> Vec<(String, u64)> {
        pairs.iter().map(|(n, v)| (n.to_string(), *v)).collect()
    }

    /// The otx2 names: per-queue `rxq<N>: frames` (and `bytes`, ignored),
    /// the port's `rx_drops`, and nothing taken from a lookalike.
    #[test]
    fn counters_come_from_the_otx2_statistic_names() {
        let c = parse_counters(&stats(&[
            ("rx_bytes", 1),
            ("rx_drops", 7),
            ("rxq0: bytes", 900),
            ("rxq0: frames", 100),
            ("rxq1: frames", 20),
            ("rxq17: frames", 30),
            ("txq0: frames", 5000),
            ("rxq_extra: frames", 4),
        ]))
        .expect("parses");
        assert_eq!(
            c,
            QueueCounters {
                queue0_frames: 100,
                rx_frames: 150,
                rx_drops: 7,
                queues: 3,
            }
        );
        assert!(parse_counters(&stats(&[("rx_drops", 1)]))
            .unwrap_err()
            .contains("rxq0: frames"));
        assert!(parse_counters(&stats(&[("rxq0: frames", 1)]))
            .unwrap_err()
            .contains("rx_drops"));
    }

    /// Rates over the window, the queue-0 share, and a counter reset
    /// restarting the baseline instead of producing a rate.
    #[test]
    fn the_meter_rates_a_window_and_survives_a_reset() {
        let t0 = Instant::now();
        let mut m = Meter::default();
        let c = |q0, rx, d| QueueCounters {
            queue0_frames: q0,
            rx_frames: rx,
            rx_drops: d,
            queues: 18,
        };
        assert_eq!(m.observe(t0, c(0, 0, 0)), None, "one sample is no rate");
        let r = m
            .observe(t0 + Duration::from_secs(10), c(58_000, 60_000, 39_000))
            .expect("a window");
        assert_eq!(r.queue0_fps, 5_800.0);
        assert_eq!(r.drops_ps, 3_900.0);
        assert!((r.queue0_share().unwrap() - 58.0 / 60.0).abs() < 1e-9);
        assert_eq!(
            m.observe(t0 + Duration::from_secs(20), c(1, 1, 1)),
            None,
            "counters went backwards: a reset, not a negative rate"
        );
        assert!(m
            .observe(t0 + Duration::from_secs(30), c(11, 11, 1))
            .is_some());
    }

    #[test]
    fn a_port_is_dropping_at_the_degraded_rate_and_not_below() {
        let mut p = PortReport {
            iface: "eth9".into(),
            verdict: None,
            observed_rss: 0,
            observed_queue0: 0,
            irq: None,
            irq_delivered_on: None,
            counters: None,
            rates: None,
            unreadable: None,
        };
        assert!(!p.dropping(), "no rates, no verdict");
        p.rates = Some(Rates {
            queue0_fps: 0.0,
            rx_fps: 0.0,
            drops_ps: DROPS_DEGRADED_PER_SEC - 1.0,
        });
        assert!(!p.dropping());
        p.rates = Some(Rates {
            queue0_fps: 0.0,
            rx_fps: 0.0,
            drops_ps: DROPS_DEGRADED_PER_SEC,
        });
        assert!(p.dropping());
    }

    /// Counters from a script: each `counters` call takes the next entry.
    struct ScriptedCounters(std::collections::VecDeque<Result<QueueCounters, String>>);

    impl KernelPath for ScriptedCounters {
        fn reconcile_queue0(&mut self, _: &[String], _: &[String]) {}
        fn queue0_irqs(&self) -> Vec<(String, Queue0Irq)> {
            Vec::new()
        }
        fn queue0_delivery(&self, _: &str) -> Option<String> {
            None
        }
        fn counters(&mut self, _: &str) -> Result<QueueCounters, String> {
            self.0.pop_front().expect("scripted")
        }
    }

    /// A port that was dropping, whose counters then stop reading, is
    /// NOT still dropping: the window it was measured over has ended.
    /// No rates, no cumulative counters, no `dropping()` — the report
    /// says unreadable and nothing else — and the next good sample
    /// rates the whole gap from the last good baseline.
    #[test]
    fn a_failed_sample_retires_the_last_window() {
        let c = |q0, rx, d| QueueCounters {
            queue0_frames: q0,
            rx_frames: rx,
            rx_drops: d,
            queues: 18,
        };
        let mut kp = ScriptedCounters(
            [
                Ok(c(0, 0, 0)),
                Ok(c(10_000, 20_000, 39_000)),
                Err("ethtool -S eth2: Operation not supported".to_string()),
                Ok(c(10_000, 20_000, 39_000)),
            ]
            .into_iter()
            .collect(),
        );
        let ports = vec!["eth2".to_string()];
        let t0 = Instant::now();
        let mut w = KernelWatch::default();
        let report = |w: &KernelWatch| w.report(&[], &[]).pop().expect("one port");
        w.tick(t0, &ports, &mut kp, &[]);
        w.tick(t0 + SAMPLE_EVERY, &ports, &mut kp, &[]);
        assert!(report(&w).dropping(), "3,900/s over the first window");

        w.tick(t0 + SAMPLE_EVERY * 2, &ports, &mut kp, &[]);
        let r = report(&w);
        assert!(r.unreadable.is_some());
        assert_eq!(r.rates, None, "the old window is not current");
        assert_eq!(r.counters, None, "nor are its cumulative counters");
        assert!(
            !r.dropping(),
            "a port whose counters stopped is not still dropping"
        );

        w.tick(t0 + SAMPLE_EVERY * 3, &ports, &mut kp, &[]);
        let r = report(&w);
        assert_eq!(r.unreadable, None);
        let rates = r.rates.expect("rated against the last good baseline");
        assert_eq!(rates.drops_ps, 0.0, "nothing dropped across the gap");
        assert!(!r.dropping());
    }

    /// A throwaway host: `sysfs_net/<iface>/device/msi_irqs/<irq>`,
    /// `proc_irq/<irq>/{smp,effective}_affinity_list` and the handler
    /// directory that names queue 0, plus `sysfs_cpu/{online,isolated}`.
    struct Host {
        base: PathBuf,
    }

    impl Host {
        fn new(tag: &str) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!("pf-kpath-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            std::fs::create_dir_all(base.join("cpu")).unwrap();
            std::fs::write(base.join("cpu/online"), "0-17\n").unwrap();
            std::fs::write(base.join("cpu/isolated"), "12\n").unwrap();
            std::fs::create_dir_all(base.join("state")).unwrap();
            Self { base }
        }
        fn net(&self) -> PathBuf {
            self.base.join("net")
        }
        fn irq(&self) -> PathBuf {
            self.base.join("irq")
        }
        fn state(&self) -> PathBuf {
            self.base.join("state")
        }
        /// A port whose queue N is IRQ `first + N`, delivered on CPU N.
        fn port(&self, iface: &str, first: u32, queues: u32) {
            let msi = self.net().join(iface).join("device/msi_irqs");
            std::fs::create_dir_all(&msi).unwrap();
            for q in 0..queues {
                let irq = first + q;
                std::fs::write(msi.join(irq.to_string()), "").unwrap();
                let d = self.irq().join(irq.to_string());
                std::fs::create_dir_all(d.join(format!("{iface}-rxtx-{q}"))).unwrap();
                std::fs::write(d.join("smp_affinity_list"), format!("{q}\n")).unwrap();
            }
        }
        fn affinity(&self, irq: u32) -> String {
            std::fs::read_to_string(self.irq().join(irq.to_string()).join("smp_affinity_list"))
                .unwrap()
                .trim()
                .to_string()
        }
        fn set_affinity(&self, irq: u32, v: &str) {
            std::fs::write(
                self.irq().join(irq.to_string()).join("smp_affinity_list"),
                format!("{v}\n"),
            )
            .unwrap();
        }
        /// A daemon of boot "boot-a" on this host.
        fn path(&self, vpp: Vec<u16>) -> LiveKernelPath {
            LiveKernelPath::with_seams(
                [self.net(), self.irq(), self.base.join("cpu"), self.state()],
                vpp,
                Vec::new(),
                "boot-a".into(),
                Box::new(|_| Ok(Vec::new())),
            )
        }
    }

    impl Drop for Host {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    /// The incident layout: three ports, queue N on CPU N, VPP on the
    /// high cores, cpu12 isolated. Each port's queue-0 IRQ leaves cpu0
    /// for a CPU of its own, none of them VPP's or isolated; the prior
    /// is recorded; and taking the ports out of `want` restores exactly
    /// the prior.
    #[test]
    fn queue0_irqs_get_their_own_cpus_and_come_back_on_restore() {
        let h = Host::new("place");
        h.port("eth2", 100, 18);
        h.port("eth3", 200, 18);
        h.port("eth5", 300, 18);
        let vpp: Vec<u16> = vec![13, 14, 15, 16, 17];
        let mut kp = h.path(vpp.clone());
        let want: Vec<String> = vec!["eth2".into(), "eth3".into(), "eth5".into()];
        kp.reconcile_queue0(&want, &[]);

        let cpus: Vec<u16> = [100, 200, 300]
            .iter()
            .map(|irq| h.affinity(*irq).parse().unwrap())
            .collect();
        for cpu in &cpus {
            assert_ne!(*cpu, 0, "off cpu0: {cpus:?}");
            assert_ne!(*cpu, 12, "never the isolated CPU: {cpus:?}");
            assert!(!vpp.contains(cpu), "never VPP's: {cpus:?}");
        }
        let mut distinct = cpus.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), 3, "each port its own CPU: {cpus:?}");
        let file = load(&h.state()).unwrap();
        assert_eq!(file.irqs.len(), 3);
        assert!(file.irqs.iter().all(|r| r.prior == "0"), "{file:?}");

        // Unchanged inputs move nothing.
        kp.reconcile_queue0(&want, &[]);
        let again: Vec<u16> = [100, 200, 300]
            .iter()
            .map(|irq| h.affinity(*irq).parse().unwrap())
            .collect();
        assert_eq!(again, cpus, "a re-steer never moves a placed IRQ");

        // `hold` keeps eth3's placement through a reconcile that wants
        // only eth2; eth5 is restored.
        kp.reconcile_queue0(&want[..1], &want[1..2]);
        assert_eq!(h.affinity(300), "0", "eth5 restored to its prior");
        assert_eq!(h.affinity(200), cpus[1].to_string(), "eth3 held");

        kp.reconcile_queue0(&[], &[]);
        assert_eq!(h.affinity(100), "0");
        assert_eq!(h.affinity(200), "0");
        assert!(
            !record_path(&h.state()).exists(),
            "nothing placed, nothing recorded"
        );
    }

    /// The record outlives the daemon: a second process placing the same
    /// IRQ keeps the FIRST prior, and the detach path restores it with
    /// no daemon at all.
    #[test]
    fn the_prior_survives_a_restart_and_detach_restores_it() {
        let h = Host::new("restart");
        h.port("eth2", 100, 4);
        h.set_affinity(100, "0-3");
        let want = vec!["eth2".to_string()];
        h.path(vec![3]).reconcile_queue0(&want, &[]);
        let placed = h.affinity(100);
        assert_ne!(placed, "0-3");

        // The next daemon finds the IRQ already placed.
        let mut next = h.path(vec![3]);
        next.reconcile_queue0(&want, &[]);
        assert_eq!(load(&h.state()).unwrap().irqs[0].prior, "0-3");
        drop(next);

        assert_eq!(restore_recorded(&h.state(), &h.irq(), "boot-a"), Ok(1));
        assert_eq!(h.affinity(100), "0-3", "the ORIGINAL prior");
        assert!(!record_path(&h.state()).exists());
    }

    /// Something moved the IRQ after PacketFrame placed it — a port
    /// re-open resets it to the driver's hint, or an operator chose
    /// another CPU. Restore leaves their value alone.
    #[test]
    fn a_placement_moved_by_someone_else_is_not_restored_over() {
        let h = Host::new("moved");
        h.port("eth2", 100, 4);
        let mut kp = h.path(vec![3]);
        kp.reconcile_queue0(&["eth2".to_string()], &[]);
        h.set_affinity(100, "2");
        if load(&h.state()).unwrap().irqs[0].placed == 2 {
            h.set_affinity(100, "1");
        }
        let theirs = h.affinity(100);
        kp.reconcile_queue0(&[], &[]);
        assert_eq!(h.affinity(100), theirs);
        assert!(!record_path(&h.state()).exists(), "the record is dropped");
    }

    /// No eligible CPU: everything is VPP's, isolated or cpu0. The IRQ
    /// is left where it is and the port is reported unplaced, named.
    #[test]
    fn no_free_cpu_leaves_the_irq_and_names_the_port() {
        let h = Host::new("full");
        h.port("eth2", 100, 4);
        let vpp: Vec<u16> = (1..=17).filter(|c| *c != 12).collect();
        let mut kp = h.path(vpp);
        kp.reconcile_queue0(&["eth2".to_string()], &[]);
        assert_eq!(h.affinity(100), "0", "untouched");
        let irqs = kp.queue0_irqs();
        assert!(
            matches!(&irqs[..], [(i, Queue0Irq::Unplaced { why })]
                if i == "eth2" && why.contains("no CPU outside VPP's cores")),
            "{irqs:?}"
        );
        assert!(!record_path(&h.state()).exists());
    }

    /// Another boot's record describes IRQs the reboot already reset:
    /// dropped without a write, by the daemon and by detach alike.
    #[test]
    fn a_record_from_another_boot_is_never_restored() {
        let h = Host::new("boot");
        h.port("eth2", 100, 4);
        h.path(vec![3]).reconcile_queue0(&["eth2".to_string()], &[]);
        let placed = h.affinity(100);
        assert_eq!(restore_recorded(&h.state(), &h.irq(), "boot-b"), Ok(0));
        assert_eq!(h.affinity(100), placed, "nothing written");
        assert!(!record_path(&h.state()).exists());

        // A daemon of the next boot drops it on load the same way, and
        // so does not take the stale placement as its prior.
        h.path(vec![3]).reconcile_queue0(&["eth2".to_string()], &[]);
        let next = LiveKernelPath::with_seams(
            [h.net(), h.irq(), h.base.join("cpu"), h.state()],
            vec![3],
            Vec::new(),
            "boot-b".into(),
            Box::new(|_| Ok(Vec::new())),
        );
        assert!(next.queue0_irqs().is_empty());
        assert!(!record_path(&h.state()).exists());
        assert_eq!(h.affinity(100), placed, "still nothing written");
    }

    /// An unreadable record holds priors nothing else knows: it is left
    /// for inspection, and no placement is made that could not be
    /// recorded beside them.
    #[test]
    fn an_unreadable_record_freezes_placement_and_is_left_alone() {
        let h = Host::new("frozen");
        h.port("eth2", 100, 4);
        std::fs::write(record_path(&h.state()), b"{ not json").unwrap();
        let mut kp = h.path(vec![3]);
        kp.reconcile_queue0(&["eth2".to_string()], &[]);
        assert_eq!(h.affinity(100), "0", "nothing moved");
        assert_eq!(
            std::fs::read(record_path(&h.state())).unwrap(),
            b"{ not json",
            "left for inspection"
        );
        assert!(matches!(
            &kp.queue0_irqs()[..],
            [(_, Queue0Irq::Unplaced { why })] if why.contains("unreadable")
        ));
        assert!(restore_recorded(&h.state(), &h.irq(), "boot-a").is_err());
    }

    /// A port with no `-rxtx-0` vector cannot have queue 0 told apart:
    /// reported unplaced rather than guessing a vector.
    #[test]
    fn a_port_without_a_named_queue0_vector_is_not_guessed() {
        let h = Host::new("noname");
        let msi = h.net().join("eth7/device/msi_irqs");
        std::fs::create_dir_all(&msi).unwrap();
        std::fs::write(msi.join("50"), "").unwrap();
        std::fs::create_dir_all(h.irq().join("50")).unwrap();
        std::fs::write(h.irq().join("50/smp_affinity_list"), "0\n").unwrap();
        let mut kp = h.path(vec![3]);
        kp.reconcile_queue0(&["eth7".to_string()], &[]);
        assert_eq!(h.affinity(50), "0");
        assert!(matches!(
            &kp.queue0_irqs()[..],
            [(_, Queue0Irq::Unplaced { why })] if why.contains("eth7-rxtx-0")
        ));
    }
}
