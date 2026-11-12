//! The core fence: other userland kept off VPP's cores while a fresh VPP
//! takes its table.
//!
//! ## Why
//!
//! A fresh VPP's first route load runs on its **main thread**, at 100% for
//! the whole load, and nothing else bounds it: on the lab rig (2026-11-12)
//! a million routes took about 30 s idle, and the load slowed in
//! proportion to the main core VPP lost — half with one equal-priority
//! competitor, 4× with six nice -20 hogs on the main core. On a gateway
//! that boots into full traffic every core is busy, and the UniFi daemons
//! that keep it busy (`ubios-udapi-server` runs at nice -15, VPP's own
//! priority) are scheduled wherever they like, VPP's cores included. So
//! edge1-mci1's fresh load took about 3.5 min after an upgrade, against
//! about 35 s idle. RT priority would fix it and is not available: the
//! service's cgroup has no RT budget (`chrt` returns EPERM).
//!
//! ## What it does
//!
//! From VPP's spawn until it leaves `Syncing`, every **top-level cgroup
//! except `system.slice`** is given a `cpuset.cpus` of the online CPUs
//! minus VPP's main and worker cores ([`SKIP`]). Those are the systemd
//! slices (`os.slice`, `uos.slice`, `app.slice`, `user.slice`,
//! `init.scope`) and the cgroups UniFi makes for itself at the root
//! (`bgpd`, `zebra`, `dpi`, `udm-v2`, …): everything that competes with
//! VPP on a UniFi gateway, as measured on 6.0.17. Kernel threads and IRQs
//! are not in any of them; attach moves the IRQs (`cores::clear_irqs_off`).
//!
//! **Why not `system.slice`, and why not systemd's `AllowedCPUs`.**
//! VPP and this daemon live in `system.slice/packetframe.service`, and a
//! child's CPUs must sit inside its parent's, so fencing the slice fences
//! VPP. Fencing the slice's *other* units would need the cpuset controller
//! enabled inside `system.slice`, and enabling a controller migrates every
//! task below it to a new cpuset — which on kernel 5.15 resets each task's
//! CPU affinity to the cpuset's, unpinning VPP's main and worker threads
//! from the cores they were started on. The root already has the cpuset
//! controller enabled (UniFi's own cgroups use it), so writing a top-level
//! cgroup's `cpuset.cpus` migrates nothing. What `system.slice` holds on
//! a UniFi gateway is small (ulcmd, tailscaled, dbus).
//!
//! **Pinned threads are put back.** On kernel 5.15 a change to a cpuset's
//! CPUs sets the affinity of every task in it to the cpuset's CPUs, and
//! widening it again does not restore what a task had asked for. UniFi
//! pins threads: rabbitmq's eighteen schedulers one per CPU, unifi-core's
//! every thread to one CPU. So before a cgroup is fenced, every thread in
//! its subtree whose affinity is narrower than the online set is recorded
//! — by thread id and start time, so a recycled id is never touched — and
//! on release each one still running gets its affinity back. A thread that
//! pins itself DURING the fence is not known to have, and is left with
//! the full set the release gives it.
//!
//! ## Release, in every case
//!
//! The record is written to `state-dir` ([`RECORD_FILE`]) before each
//! cgroup is changed, and the release undoes exactly what it lists:
//! - VPP leaves `Syncing` — loaded, or down (Backoff, Stopped);
//! - [`FENCE_MAX`] after the fence began, whatever VPP is doing;
//! - the module stops;
//! - and at the next attach or `packetframe detach`, a record left by a
//!   daemon that died fenced ([`release_stale`]). A record from an earlier
//!   boot is only deleted: the cgroups it names were rebuilt by that boot.
//!
//! While fenced, a top-level cgroup created after the fence began is
//! fenced too, and one whose CPUs were changed back (systemd re-realising
//! a slice) is fenced again ([`REFRESH_EVERY`]).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cores::{format_cpu_list, parse_cpu_list};

/// The record of what the fence changed, under `state-dir`.
pub const RECORD_FILE: &str = "vpp-core-fence.json";

/// The longest a fence is held. A fresh load on a saturated gateway took
/// about 3.5 min unfenced (edge1-mci1, 2026-11-05); past this the fence is
/// costing the box more than it can be buying VPP.
pub const FENCE_MAX: Duration = Duration::from_secs(600);

/// How often a held fence looks for new top-level cgroups and CPUs that
/// were changed back.
pub const REFRESH_EVERY: Duration = Duration::from_secs(2);

/// Top-level cgroups never fenced: VPP's own, and this daemon's, parent.
pub const SKIP: &[&str] = &["system.slice"];

/// One fenced cgroup and what its `cpuset.cpus` held before.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FencedCgroup {
    /// The top-level cgroup's name, e.g. `os.slice`.
    pub name: String,
    /// Its `cpuset.cpus` before the fence, trimmed; empty means "inherit".
    pub previous: String,
}

/// A thread whose affinity the fence will have reset, and what it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedThread {
    pub tid: i32,
    /// `/proc/<tid>/stat` field 22, so a recycled id is never touched.
    pub start_ticks: u64,
    /// Its CPU list before the fence.
    pub cpus: String,
}

/// What the fence changed, persisted before each change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FenceRecord {
    /// The boot this was written in. A record from another boot names
    /// cgroups that boot rebuilt, so it is deleted rather than undone.
    pub boot_id: String,
    /// When the fence began, Unix seconds.
    pub since_unix: u64,
    /// The CPUs the fenced cgroups were given.
    pub allowed: String,
    /// The online CPUs when the fence began: what an empty `cpuset.cpus`
    /// inherited, and what one is put back as when the kernel refuses an
    /// empty list for a cgroup with tasks in it (5.15: `ENOSPC`).
    pub online: String,
    /// VPP's main and worker cores, kept clear.
    pub vpp_cores: Vec<u16>,
    pub cgroups: Vec<FencedCgroup>,
    pub threads: Vec<PinnedThread>,
}

/// What a release did, for its event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Released {
    pub cgroups: Vec<String>,
    pub threads_restored: usize,
    /// Recorded threads that had exited, or whose id now belongs to
    /// another thread.
    pub threads_gone: usize,
    /// What could not be put back, by cgroup or thread.
    pub failures: Vec<String>,
}

/// What the fence changes on the host: a cgroup's `cpuset.cpus` and a
/// thread's affinity. Behind a trait so the bookkeeping is testable
/// against fixture directories, including the kernel's refusals.
pub trait FenceOps {
    /// Write `cpus` (a CPU list, or empty) to a `cpuset.cpus` file.
    fn write_cpuset(&self, file: &Path, cpus: &str) -> std::io::Result<()> {
        std::fs::write(file, format!("{cpus}\n"))
    }
    fn set_affinity(&self, tid: i32, cpus: &[u16]) -> std::io::Result<()>;
}

/// The live host: the cgroup files, and `sched_setaffinity(2)`.
pub struct LiveOps;

impl FenceOps for LiveOps {
    #[cfg(target_os = "linux")]
    fn set_affinity(&self, tid: i32, cpus: &[u16]) -> std::io::Result<()> {
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for &c in cpus {
            unsafe { libc::CPU_SET(c as usize, &mut set) };
        }
        let rc =
            unsafe { libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &set) };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn set_affinity(&self, _tid: i32, _cpus: &[u16]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "thread affinity is Linux-only",
        ))
    }
}

/// Where the fence reads and writes.
pub struct FencePaths {
    /// The cgroup v2 mount, `/sys/fs/cgroup`.
    pub cgroup_root: PathBuf,
    /// `/proc`.
    pub proc_root: PathBuf,
    /// The record's directory: `state-dir`.
    pub state_dir: PathBuf,
}

impl FencePaths {
    pub fn live(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            cgroup_root: "/sys/fs/cgroup".into(),
            proc_root: "/proc".into(),
            state_dir: state_dir.into(),
        }
    }

    fn record(&self) -> PathBuf {
        self.state_dir.join(RECORD_FILE)
    }
}

/// A held fence, or none.
pub struct CoreFence {
    paths: FencePaths,
    ops: Box<dyn FenceOps>,
    boot_id: String,
    vpp_cores: Vec<u16>,
    held: Option<Held>,
}

struct Held {
    record: FenceRecord,
    allowed: Vec<u16>,
    online: Vec<u16>,
    since: Instant,
    last_refresh: Instant,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_trim(p: &Path) -> std::io::Result<String> {
    Ok(std::fs::read_to_string(p)?.trim().to_string())
}

/// A thread's start time, field 22 of its `stat`.
fn start_ticks(proc_root: &Path, tid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(proc_root.join(tid.to_string()).join("stat")).ok()?;
    crate::process::parse_start_ticks(&stat)
}

/// A thread's `Cpus_allowed_list`.
fn thread_cpus(proc_root: &Path, tid: i32) -> Option<Vec<u16>> {
    let status = std::fs::read_to_string(proc_root.join(tid.to_string()).join("status")).ok()?;
    let line = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))?;
    parse_cpu_list(line.trim()).ok()
}

/// Every thread in `dir` and the cgroups below it.
fn subtree_threads(dir: &Path, out: &mut Vec<i32>) {
    if let Ok(s) = std::fs::read_to_string(dir.join("cgroup.threads")) {
        out.extend(s.lines().filter_map(|l| l.trim().parse::<i32>().ok()));
    }
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                subtree_threads(&e.path(), out);
            }
        }
    }
}

impl CoreFence {
    /// A fence for VPP on `vpp_cores` (main and workers). Holds nothing
    /// until [`Self::engage`].
    pub fn new(
        paths: FencePaths,
        ops: Box<dyn FenceOps>,
        boot_id: impl Into<String>,
        vpp_cores: Vec<u16>,
    ) -> Self {
        let mut vpp_cores = vpp_cores;
        vpp_cores.sort_unstable();
        vpp_cores.dedup();
        Self {
            paths,
            ops,
            boot_id: boot_id.into(),
            vpp_cores,
            held: None,
        }
    }

    pub fn is_held(&self) -> bool {
        self.held.is_some()
    }

    /// How long the current fence has been held.
    pub fn held_for(&self, now: Instant) -> Option<Duration> {
        self.held
            .as_ref()
            .map(|h| now.saturating_duration_since(h.since))
    }

    /// The fence's record while held.
    pub fn record(&self) -> Option<&FenceRecord> {
        self.held.as_ref().map(|h| &h.record)
    }

    /// Fence every top-level cgroup but [`SKIP`] off VPP's cores.
    /// Already held: a refresh. `Err` leaves nothing changed that the
    /// record does not list, and the caller carries on unfenced.
    pub fn engage(&mut self, now: Instant) -> Result<(), String> {
        if self.held.is_some() {
            self.refresh(now, true);
            return Ok(());
        }
        let root = &self.paths.cgroup_root;
        let controllers = read_trim(&root.join("cgroup.subtree_control")).map_err(|e| {
            format!(
                "read {}: {e}",
                root.join("cgroup.subtree_control").display()
            )
        })?;
        if !controllers.split_whitespace().any(|c| c == "cpuset") {
            return Err(format!(
                "the cpuset controller is not enabled at the cgroup root ({}: `{controllers}`); \
                 enabling it would migrate every task on the host, so the fence is skipped",
                root.display()
            ));
        }
        let online = parse_cpu_list(
            &read_trim(&root.join("cpuset.cpus.effective"))
                .map_err(|e| format!("read the root's cpuset.cpus.effective: {e}"))?,
        )?;
        let allowed: Vec<u16> = online
            .iter()
            .copied()
            .filter(|c| !self.vpp_cores.contains(c))
            .collect();
        if allowed.is_empty() {
            return Err(format!(
                "VPP's cores {} are every online CPU; nothing would be left to fence onto",
                format_cpu_list(&self.vpp_cores)
            ));
        }
        let held = Held {
            record: FenceRecord {
                boot_id: self.boot_id.clone(),
                since_unix: now_unix(),
                allowed: format_cpu_list(&allowed),
                online: format_cpu_list(&online),
                vpp_cores: self.vpp_cores.clone(),
                cgroups: Vec::new(),
                threads: Vec::new(),
            },
            allowed,
            online,
            since: now,
            last_refresh: now,
        };
        self.held = Some(held);
        self.persist()?;
        self.refresh(now, true);
        Ok(())
    }

    /// While held: fence top-level cgroups that appeared since, and put
    /// back the fence on any whose CPUs were changed back. Paced by
    /// [`REFRESH_EVERY`] unless `force`.
    pub fn refresh(&mut self, now: Instant, force: bool) {
        let Some(h) = self.held.as_mut() else {
            return;
        };
        if !force && now.saturating_duration_since(h.last_refresh) < REFRESH_EVERY {
            return;
        }
        h.last_refresh = now;
        let Ok(entries) = std::fs::read_dir(&self.paths.cgroup_root) else {
            return;
        };
        let mut names: Vec<String> = entries
            .flatten()
            .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !SKIP.contains(&n.as_str()))
            .collect();
        names.sort_unstable();
        let allowed = format_cpu_list(&h.allowed);
        for name in names {
            let cpus = self.paths.cgroup_root.join(&name).join("cpuset.cpus");
            let Ok(now_cpus) = read_trim(&cpus) else {
                // No cpuset in this cgroup: nothing to fence with.
                continue;
            };
            let known = self
                .held
                .as_ref()
                .is_some_and(|h| h.record.cgroups.iter().any(|c| c.name == name));
            if known {
                if now_cpus != allowed {
                    tracing::info!(cgroup = %name, cpus = %now_cpus, "a fenced cgroup's CPUs were changed back; fencing it again");
                    if let Err(e) = self.ops.write_cpuset(&cpus, &allowed) {
                        tracing::warn!(cgroup = %name, error = %e, "could not fence a cgroup again");
                    }
                }
                continue;
            }
            if let Err(e) = self.fence_one(&name, now_cpus) {
                tracing::warn!(cgroup = %name, error = %e, "could not fence a cgroup off VPP's cores");
            }
        }
    }

    /// Record `name` and its pinned threads, persist, then fence it.
    fn fence_one(&mut self, name: &str, previous: String) -> Result<(), String> {
        let dir = self.paths.cgroup_root.join(name);
        let (online, allowed) = match self.held.as_ref() {
            Some(h) => (h.online.clone(), format_cpu_list(&h.allowed)),
            None => return Ok(()),
        };
        let mut tids = Vec::new();
        subtree_threads(&dir, &mut tids);
        let mut pinned = Vec::new();
        for tid in tids {
            let Some(cpus) = thread_cpus(&self.paths.proc_root, tid) else {
                continue;
            };
            if cpus == online {
                continue;
            }
            let Some(start) = start_ticks(&self.paths.proc_root, tid) else {
                continue;
            };
            pinned.push(PinnedThread {
                tid,
                start_ticks: start,
                cpus: format_cpu_list(&cpus),
            });
        }
        if let Some(h) = self.held.as_mut() {
            h.record.cgroups.push(FencedCgroup {
                name: name.to_string(),
                previous,
            });
            h.record.threads.extend(pinned);
        }
        // Write-ahead: the record lists this cgroup before it changes, so
        // a daemon that dies between the two leaves something to undo
        // rather than a fence nobody knows about.
        self.persist()?;
        self.ops
            .write_cpuset(&dir.join("cpuset.cpus"), &allowed)
            .map_err(|e| format!("write {}: {e}", dir.join("cpuset.cpus").display()))
    }

    fn persist(&self) -> Result<(), String> {
        let Some(h) = self.held.as_ref() else {
            return Ok(());
        };
        write_record(&self.paths.record(), &h.record)
    }

    /// Undo everything the record lists and delete it. A no-op when
    /// nothing is held.
    pub fn release(&mut self) -> Option<Released> {
        let h = self.held.take()?;
        let released = undo(&self.paths, self.ops.as_ref(), &h.record);
        if let Err(e) = std::fs::remove_file(self.paths.record()) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(error = %e, "could not delete the core fence's record");
            }
        }
        Some(released)
    }
}

fn write_record(path: &Path, record: &FenceRecord) -> Result<(), String> {
    let body =
        serde_json::to_vec_pretty(record).map_err(|e| format!("encode fence record: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename to {}: {e}", path.display()))
}

/// Put back each cgroup's CPUs, then each recorded thread's affinity. The
/// cgroups first: restoring a thread to a CPU its cgroup still excludes
/// would fail.
fn undo(paths: &FencePaths, ops: &dyn FenceOps, record: &FenceRecord) -> Released {
    let mut out = Released::default();
    for c in &record.cgroups {
        let cpus = paths.cgroup_root.join(&c.name).join("cpuset.cpus");
        if !cpus.exists() {
            // Gone with whatever ran in it: nothing left to undo.
            continue;
        }
        let r = match ops.write_cpuset(&cpus, &c.previous) {
            // Kernel 5.15 refuses an empty list for a cgroup with tasks in
            // it (`ENOSPC`), though an empty one is what a new cgroup
            // starts with. The online CPUs are what that empty list
            // inherited: the same CPUs, written out.
            Err(e)
                if c.previous.is_empty()
                    && e.raw_os_error() == Some(libc::ENOSPC)
                    && !record.online.is_empty() =>
            {
                ops.write_cpuset(&cpus, &record.online)
            }
            r => r,
        };
        match r {
            Ok(()) => out.cgroups.push(c.name.clone()),
            Err(e) => out.failures.push(format!("{}: {e}", c.name)),
        }
    }
    let mut seen = BTreeSet::new();
    for t in &record.threads {
        if !seen.insert(t.tid) {
            continue;
        }
        if start_ticks(&paths.proc_root, t.tid) != Some(t.start_ticks) {
            out.threads_gone += 1;
            continue;
        }
        let Ok(cpus) = parse_cpu_list(&t.cpus) else {
            continue;
        };
        match ops.set_affinity(t.tid, &cpus) {
            Ok(()) => out.threads_restored += 1,
            // Exited between the check and the call.
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => out.threads_gone += 1,
            Err(e) => out.failures.push(format!("thread {}: {e}", t.tid)),
        }
    }
    out
}

/// Log a release and record `cores_released`.
pub fn report(reason: &str, held: Duration, r: &Released) {
    use packetframe_common::events::{self as event_log, kind as event_kind};
    let event = if r.failures.is_empty() {
        event_log::Event::info
    } else {
        event_log::Event::warn
    };
    if r.failures.is_empty() {
        tracing::info!(
            reason,
            held_ms = held.as_millis() as u64,
            cgroups = r.cgroups.len(),
            threads_restored = r.threads_restored,
            "let the core fence go"
        );
    } else {
        tracing::warn!(
            reason,
            failures = %r.failures.join("; "),
            "let the core fence go, but could not put everything back"
        );
    }
    event(crate::MODULE_NAME, event_kind::CORES_RELEASED)
        .field("reason", reason.to_string())
        .field("held_ms", held.as_millis() as u64)
        .field("cgroups", r.cgroups.join(","))
        .field("threads_restored", r.threads_restored as u64)
        .field("threads_gone", r.threads_gone as u64)
        .field("failures", r.failures.len() as u64)
        .field("failed", r.failures.join("; "))
        .emit();
}

/// [`release_stale`] against the live host, reported as `stale`. For
/// attach and `packetframe detach`.
pub fn release_stale_live(state_dir: &Path) {
    let boot = crate::process::boot_id().unwrap_or_default();
    match release_stale(&FencePaths::live(state_dir), &LiveOps, &boot) {
        None => {}
        Some(Ok((r, since_unix))) => {
            let held = Duration::from_secs(now_unix().saturating_sub(since_unix));
            report("stale", held, &r);
        }
        Some(Err(e)) => tracing::warn!(error = %e, "could not release a stale core fence"),
    }
}

/// Release a fence a previous daemon left: at attach, before this one can
/// fence, and from `packetframe detach`. A record from another boot is
/// only deleted. `None` when there was no record; otherwise what was put
/// back, and when the fence began (Unix seconds).
pub fn release_stale(
    paths: &FencePaths,
    ops: &dyn FenceOps,
    boot_id: &str,
) -> Option<Result<(Released, u64), String>> {
    let path = paths.record();
    let raw = match std::fs::read(&path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(Err(format!("read {}: {e}", path.display()))),
    };
    let result = match serde_json::from_slice::<FenceRecord>(&raw) {
        Ok(record) if record.boot_id == boot_id => {
            Ok((undo(paths, ops, &record), record.since_unix))
        }
        Ok(record) => Ok((Released::default(), record.since_unix)),
        Err(e) => Err(format!(
            "{} is unreadable ({e}); deleted, and any cgroup it fenced keeps its CPUs until \
             reboot",
            path.display()
        )),
    };
    let _ = std::fs::remove_file(&path);
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Each `set` call: the thread and the CPUs it was given.
    type Calls = Rc<RefCell<Vec<(i32, Vec<u16>)>>>;

    #[derive(Clone, Default)]
    struct FakeAffinity(Calls);

    impl FenceOps for FakeAffinity {
        /// As kernel 5.15 does: an empty list is refused for a cgroup
        /// with threads in it.
        fn write_cpuset(&self, file: &Path, cpus: &str) -> std::io::Result<()> {
            let threads = file.with_file_name("cgroup.threads");
            let populated = std::fs::read_to_string(threads)
                .map(|t| !t.trim().is_empty())
                .unwrap_or(false);
            if cpus.is_empty() && populated {
                return Err(std::io::Error::from_raw_os_error(libc::ENOSPC));
            }
            std::fs::write(file, format!("{cpus}\n"))
        }

        fn set_affinity(&self, tid: i32, cpus: &[u16]) -> std::io::Result<()> {
            self.0.borrow_mut().push((tid, cpus.to_vec()));
            Ok(())
        }
    }

    struct Fixture {
        base: PathBuf,
        paths: FencePaths,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!("pf-fence-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            let cg = base.join("cgroup");
            std::fs::create_dir_all(&cg).unwrap();
            std::fs::write(
                cg.join("cgroup.subtree_control"),
                "cpuset cpu io memory pids\n",
            )
            .unwrap();
            std::fs::write(cg.join("cpuset.cpus.effective"), "0-17\n").unwrap();
            std::fs::create_dir_all(base.join("proc")).unwrap();
            std::fs::create_dir_all(base.join("state")).unwrap();
            let paths = FencePaths {
                cgroup_root: cg,
                proc_root: base.join("proc"),
                state_dir: base.join("state"),
            };
            Self { base, paths }
        }

        fn paths(&self) -> FencePaths {
            FencePaths {
                cgroup_root: self.paths.cgroup_root.clone(),
                proc_root: self.paths.proc_root.clone(),
                state_dir: self.paths.state_dir.clone(),
            }
        }

        /// A top-level cgroup, with an optional child, and the threads in
        /// each.
        fn cgroup(&self, name: &str, cpus: &str, threads: &[i32], child: &[i32]) {
            let d = self.paths.cgroup_root.join(name);
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("cpuset.cpus"), format!("{cpus}\n")).unwrap();
            let list = |t: &[i32]| t.iter().map(|t| format!("{t}\n")).collect::<String>();
            std::fs::write(d.join("cgroup.threads"), list(threads)).unwrap();
            if !child.is_empty() {
                let c = d.join("unit.service");
                std::fs::create_dir_all(&c).unwrap();
                std::fs::write(c.join("cgroup.threads"), list(child)).unwrap();
            }
        }

        fn thread(&self, tid: i32, start: u64, cpus: &str) {
            let d = self.paths.proc_root.join(tid.to_string());
            std::fs::create_dir_all(&d).unwrap();
            // Field 22 is the start time; `comm` may hold spaces.
            let mut fields = vec!["S".to_string(); 19];
            fields.push(start.to_string());
            std::fs::write(
                d.join("stat"),
                format!("{tid} (a b) {}\n", fields.join(" ")),
            )
            .unwrap();
            std::fs::write(
                d.join("status"),
                format!("Name:\ta\nCpus_allowed_list:\t{cpus}\n"),
            )
            .unwrap();
        }

        fn cpus(&self, name: &str) -> String {
            read_trim(&self.paths.cgroup_root.join(name).join("cpuset.cpus")).unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn fence(fx: &Fixture, aff: &FakeAffinity) -> CoreFence {
        CoreFence::new(
            fx.paths(),
            Box::new(aff.clone()),
            "boot-a",
            vec![17, 15, 16],
        )
    }

    #[test]
    fn every_top_level_cgroup_but_system_slice_is_fenced_and_put_back() {
        let fx = Fixture::new("basic");
        fx.cgroup("os.slice", "", &[100], &[101]);
        fx.cgroup("bgpd", "", &[200], &[]);
        fx.cgroup("system.slice", "", &[300], &[]);
        fx.cgroup("pinned", "2-3", &[], &[]);
        for t in [100, 101, 200, 300] {
            fx.thread(t, 1000 + t as u64, "0-17");
        }
        let aff = FakeAffinity::default();
        let mut f = fence(&fx, &aff);
        f.engage(Instant::now()).unwrap();

        assert_eq!(fx.cpus("os.slice"), "0-14");
        assert_eq!(fx.cpus("bgpd"), "0-14");
        assert_eq!(fx.cpus("pinned"), "0-14");
        assert_eq!(fx.cpus("system.slice"), "", "VPP's parent is never fenced");
        assert!(fx.paths.state_dir.join(RECORD_FILE).exists());

        let r = f.release().unwrap();
        assert!(r.failures.is_empty(), "{:?}", r.failures);
        assert_eq!(
            fx.cpus("os.slice"),
            "0-17",
            "an empty list with tasks in the cgroup is refused, so the CPUs it inherited are written"
        );
        assert_eq!(fx.cpus("system.slice"), "");
        assert_eq!(
            fx.cpus("pinned"),
            "2-3",
            "a cgroup's own CPUs come back exactly"
        );
        assert_eq!(r.cgroups.len(), 3);
        assert!(!fx.paths.state_dir.join(RECORD_FILE).exists());
        assert!(aff.0.borrow().is_empty(), "no thread was pinned");
    }

    #[test]
    fn pinned_threads_get_their_affinity_back_and_a_recycled_id_is_left_alone() {
        let fx = Fixture::new("pinned");
        fx.cgroup("uos.slice", "", &[10], &[11, 12]);
        fx.thread(10, 500, "12");
        fx.thread(11, 501, "0-17");
        fx.thread(12, 502, "16");
        let aff = FakeAffinity::default();
        let mut f = fence(&fx, &aff);
        f.engage(Instant::now()).unwrap();
        let rec = f.record().unwrap().clone();
        assert_eq!(
            rec.threads.len(),
            2,
            "only threads narrower than the online set"
        );

        // Thread 12 exits and its id is reused by a new thread.
        fx.thread(12, 9999, "0-14");
        let r = f.release().unwrap();
        assert_eq!(*aff.0.borrow(), vec![(10, vec![12])]);
        assert_eq!(r.threads_restored, 1);
        assert_eq!(r.threads_gone, 1);
    }

    #[test]
    fn a_cgroup_that_appears_or_is_changed_back_while_held_is_fenced() {
        let fx = Fixture::new("refresh");
        fx.cgroup("app.slice", "", &[], &[]);
        let aff = FakeAffinity::default();
        let mut f = fence(&fx, &aff);
        let t0 = Instant::now();
        f.engage(t0).unwrap();
        fx.cgroup("dpi", "", &[], &[]);
        std::fs::write(fx.paths.cgroup_root.join("app.slice/cpuset.cpus"), "\n").unwrap();

        f.refresh(t0 + Duration::from_millis(100), false);
        assert_eq!(fx.cpus("dpi"), "", "paced");
        f.refresh(t0 + REFRESH_EVERY, false);
        assert_eq!(fx.cpus("dpi"), "0-14");
        assert_eq!(fx.cpus("app.slice"), "0-14");
        f.release().unwrap();
        assert_eq!(fx.cpus("dpi"), "");
    }

    #[test]
    fn no_cpuset_at_the_root_is_a_skip_not_a_change() {
        let fx = Fixture::new("nocpuset");
        std::fs::write(
            fx.paths.cgroup_root.join("cgroup.subtree_control"),
            "memory pids\n",
        )
        .unwrap();
        fx.cgroup("os.slice", "", &[], &[]);
        let aff = FakeAffinity::default();
        let mut f = fence(&fx, &aff);
        let e = f.engage(Instant::now()).unwrap_err();
        assert!(e.contains("not enabled at the cgroup root"), "{e}");
        assert!(!f.is_held());
        assert_eq!(fx.cpus("os.slice"), "");
        assert!(!fx.paths.state_dir.join(RECORD_FILE).exists());
    }

    #[test]
    fn a_record_left_by_a_dead_daemon_is_undone_and_one_from_another_boot_only_deleted() {
        let fx = Fixture::new("stale");
        fx.cgroup("os.slice", "", &[10], &[]);
        fx.thread(10, 77, "12");
        let aff = FakeAffinity::default();
        {
            let mut f = fence(&fx, &aff);
            f.engage(Instant::now()).unwrap();
            // The daemon dies here: no release.
            std::mem::forget(f);
        }
        assert_eq!(fx.cpus("os.slice"), "0-14");
        let (r, _) = release_stale(&fx.paths(), &aff, "boot-a").unwrap().unwrap();
        assert_eq!(fx.cpus("os.slice"), "0-17", "the online CPUs it inherited");
        assert_eq!(r.threads_restored, 1);
        assert!(
            release_stale(&fx.paths(), &aff, "boot-a").is_none(),
            "deleted"
        );

        // Another boot's record: deleted, nothing written.
        let mut f = fence(&fx, &aff);
        f.engage(Instant::now()).unwrap();
        std::mem::forget(f);
        let before = aff.0.borrow().len();
        let (r, _) = release_stale(&fx.paths(), &aff, "boot-b").unwrap().unwrap();
        assert!(r.cgroups.is_empty());
        assert_eq!(aff.0.borrow().len(), before);
        assert_eq!(
            fx.cpus("os.slice"),
            "0-14",
            "left for the reboot that already rebuilt it"
        );
        assert!(!fx.paths.state_dir.join(RECORD_FILE).exists());
    }
}
