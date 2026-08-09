//! CPU placement for VPP's main and worker threads.
//!
//! The config grammar promises `cores <n>` per port and nothing more: it
//! says *how many* workers, never *which* CPUs. `startup_conf::render`
//! needs the second — plan v5 is explicit that the operator's `cores`
//! promise is honoured by rendering an explicit `corelist-workers`
//! rather than trusting VPP's round-robin default. So the map is derived
//! here, from what the host reports about itself, by a pure function
//! whose whole behaviour is unit-testable on a dev laptop.
//!
//! ## The policy, and why each exclusion is in it
//!
//! Workers are taken from the **highest-numbered usable CPUs,
//! descending**, and the main thread takes the next one below them.
//!
//! - **CPU 0 is never used.** It carries the boot processor's timers and
//!   unbound workqueues on every kernel this runs on. A poll-mode worker
//!   there starves them at 100% duty cycle.
//! - **Isolated CPUs are never used.** On the reference fleet
//!   `isolcpus=12` exists and belongs to `unifi-core`, not to us
//!   (`docs/runbooks/` platform notes). Isolation means "reserved for
//!   somebody's latency-sensitive workload"; the one thing you must not
//!   do with a CPU somebody else reserved is put a busy-poll thread on
//!   it.
//! - **Descending** because the low end is where the exclusions and the
//!   default IRQ/RPS spread cluster, so counting down keeps the map
//!   stable as `cores` grows — adding a worker does not renumber the
//!   ones already placed, and an operator's IRQ-affinity work therefore
//!   survives a config bump.
//!
//! ## What this deliberately does not solve
//!
//! On the reference NIC all 18 CPUs carry an rx-queue IRQ 1:1 (18 cores
//! = 18 queues, no idle silicon), so **no** map avoids sharing a CPU
//! with a PF interrupt. That is an operator action — move the PF IRQs
//! off the derived worker set — not something this function can do, and
//! it is why the derived map is logged at attach: the log line is the
//! input to that work. Plan v5's "explicit core map" (set A for PF
//! IRQs, set B for workers, C for housekeeping) is the target state;
//! this is the half of it that does not require new config grammar, and
//! a `cpu-map` directive that lets the operator state set B directly
//! remains the honest end point.

/// VPP's thread placement, ready for `startup_conf::render`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreMap {
    /// `main-core`: VPP's main thread. Answers the binary API, executes
    /// our route batches, and is NOT a poll-mode thread — so it shares
    /// a CPU far more gracefully than a worker does.
    pub main: u16,
    /// `corelist-workers`, in ascending order for a readable config
    /// (placement is a set; the descending walk is only how it is
    /// chosen).
    pub workers: Vec<u16>,
}

/// Derive the map from the host's own CPU accounting.
///
/// `online` and `isolated` are the parsed contents of
/// `/sys/devices/system/cpu/{online,isolated}`. `workers` is
/// `VppOffloadConfig::total_workers()`.
///
/// Errors rather than degrading: a map that quietly drops a worker would
/// hand VPP fewer threads than the sizing arithmetic reserved a stats
/// segment for, and `render` asserts the two agree precisely because
/// that mismatch surfaces hours later as an OOM abort mid-resync.
pub fn derive_core_map(online: &[u16], isolated: &[u16], workers: u32) -> Result<CoreMap, String> {
    let mut usable: Vec<u16> = online
        .iter()
        .copied()
        .filter(|c| *c != 0 && !isolated.contains(c))
        .collect();
    usable.sort_unstable();
    usable.dedup();

    // One main thread plus every worker, all from distinct CPUs.
    let needed = workers as usize + 1;
    if usable.len() < needed {
        return Err(format!(
            "{} usable CPU(s) after excluding cpu0 and the isolated set {isolated:?}, but \
             {} worker(s) plus VPP's main thread need {needed}; reduce the `cores` totals \
             or free an isolated CPU",
            usable.len(),
            workers,
        ));
    }

    // Workers off the top, main immediately below them.
    let split = usable.len() - workers as usize;
    let mut chosen: Vec<u16> = usable[split..].to_vec();
    chosen.sort_unstable();
    Ok(CoreMap {
        main: usable[split - 1],
        workers: chosen,
    })
}

/// Parse a kernel CPU list: comma-separated singles and `a-b` ranges,
/// as written by every file under `/sys/devices/system/cpu/`.
///
/// An empty or whitespace-only string is an empty list, which is the
/// normal content of `isolated` on a host with no `isolcpus=`. A
/// malformed list is an error rather than a silently-shorter list:
/// treating an unparseable `isolated` as empty would place a worker on
/// the CPU somebody reserved.
pub fn parse_cpu_list(s: &str) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    let s = s.trim();
    if s.is_empty() {
        return Ok(out);
    }
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            return Err(format!("empty element in CPU list {s:?}"));
        }
        match part.split_once('-') {
            Some((lo, hi)) => {
                let lo: u16 = lo
                    .trim()
                    .parse()
                    .map_err(|e| format!("bad CPU range start {lo:?} in {s:?}: {e}"))?;
                let hi: u16 = hi
                    .trim()
                    .parse()
                    .map_err(|e| format!("bad CPU range end {hi:?} in {s:?}: {e}"))?;
                if hi < lo {
                    return Err(format!("inverted CPU range {part:?} in {s:?}"));
                }
                out.extend(lo..=hi);
            }
            None => out.push(
                part.parse()
                    .map_err(|e| format!("bad CPU {part:?} in {s:?}: {e}"))?,
            ),
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Read the host's map inputs from sysfs and derive the placement.
///
/// `online` missing is fatal — without it there is no CPU set to choose
/// from, and guessing `0..nproc` would ignore offline CPUs. `isolated`
/// missing is not: the file only exists on kernels built with
/// `CONFIG_CPU_ISOLATION`, and its absence genuinely means "nothing is
/// isolated". A *read error* on a file that exists is still fatal, for
/// the reason `parse_cpu_list` refuses malformed input.
pub fn derive_from_sysfs(sysfs_cpu: &std::path::Path, workers: u32) -> Result<CoreMap, String> {
    let online_path = sysfs_cpu.join("online");
    let online = std::fs::read_to_string(&online_path)
        .map_err(|e| format!("read {}: {e}", online_path.display()))?;
    let online = parse_cpu_list(&online)?;

    let isolated_path = sysfs_cpu.join("isolated");
    let isolated = match std::fs::read_to_string(&isolated_path) {
        Ok(s) => parse_cpu_list(&s)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("read {}: {e}", isolated_path.display())),
    };

    derive_core_map(&online, &isolated, workers)
}

/// Where the CPU topology lives on a running kernel.
pub const SYSFS_CPU: &str = "/sys/devices/system/cpu";

/// A thread's start time, for the identity check in
/// the rescan loop's `seen` set. `None` when the thread has already
/// exited or its stat line cannot be parsed — both of which make it
/// unprocessable rather than a fault.
#[cfg(target_os = "linux")]
fn thread_start_ticks(tid: libc::pid_t) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
    crate::process::parse_start_ticks(&stat)
}

/// Whether a `sched_getaffinity`/`setaffinity` failure means this host
/// has more CPUs than a fixed `cpu_set_t` can express.
///
/// The kernel answers `EINVAL` when the supplied mask is smaller than
/// its own cpumask. Treating that like a vanished thread — which the
/// first version did — made every TID "skip", returned `Ok(0)`, and let
/// attach log that the daemon had been restricted while it remained
/// free to run on VPP's cores: a claim recorded because the effect was
/// requested rather than observed. Named and refused instead (review
/// finding).
#[cfg(target_os = "linux")]
fn mask_too_small(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::EINVAL)
}

/// Keep every thread of THIS daemon off VPP's cores — by SUBTRACTING
/// them from each thread's current mask, never by rebuilding one.
///
/// The missing half of the plan's "cpuset + SCHED_FIFO" promise, found
/// by a week of drills (shadow, 2026-08-08): a resync burst scheduled
/// onto the worker's core preempts the poll loop, the 1024-descriptor
/// rx ring overflows in ~2 s, and the drops happen at the NIC where no
/// VPP counter sees them — a constant ~5.4 s of loss at every adopted
/// release, invariant under three correct FIB-side fixes.
///
/// Subtract-only is load-bearing three ways (all review findings on
/// the first version, which built a host-wide mask from a CPU COUNT):
/// an operator's narrower `CPUAffinity=`/taskset policy survives,
/// because bits they cleared stay cleared; non-contiguous online CPU
/// IDs need no enumeration at all, because the kernel's own answer per
/// thread is the starting point; and the worst possible outcome of
/// running with no VPP is the loss of exactly VPP's cores, not
/// collapse onto CPU 0. A thread whose mask would become EMPTY — the
/// operator pinned the daemon precisely onto VPP's cores — is left
/// untouched and warned about, because an unprotected worker degrades
/// while an unschedulable daemon thread stops.
///
/// Applied to every task in `/proc/self/task`; threads spawned later
/// inherit their creator's mask.
#[cfg(target_os = "linux")]
pub fn restrict_daemon_from(vpp_cores: &[u16]) -> Result<usize, String> {
    let mut edited = 0usize;
    let mut errors: Vec<String> = Vec::new();
    // Rescan until a whole pass finds nothing new.
    //
    // One pass is not enough, and the gap is reachable rather than
    // theoretical: the fast-path runtime is already live before VPP
    // attaches, and its integrity checker uses `spawn_blocking`
    // (`fast-path/src/fib/integrity.rs`). A thread created DURING the
    // walk, by a creator we have not visited yet, inherits an
    // unrestricted mask and may never appear in the directory batch we
    // already read — leaving it free to run on VPP's cores forever,
    // which is precisely the interference this function exists to stop
    // (review finding).
    //
    // Once a pass adds nothing, every thread alive is restricted, so
    // anything created after can only inherit a restricted mask. The
    // cap bounds a daemon that spawns continuously; hitting it means
    // protection is partial and says so, rather than looping.
    const MAX_PASSES: u32 = 8;
    let mut passes = 0u32;
    // Identities already processed, so the loop terminates and a thread
    // is not restricted twice. Keyed on `(tid, start_ticks)` rather
    // than the tid alone: Linux reuses tids, and a reused one names a
    // different thread that has not been visited.
    let mut seen: Vec<(libc::pid_t, u64)> = Vec::new();
    loop {
        passes += 1;
        let mut found_new = 0usize;
        let tasks =
            std::fs::read_dir("/proc/self/task").map_err(|e| format!("/proc/self/task: {e}"))?;
        for entry in tasks.flatten() {
            let Some(tid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<libc::pid_t>().ok())
            else {
                continue;
            };
            // Identity first, so an already-processed thread costs one
            // stat and nothing else — and so a tid reused mid-loop is
            // treated as the new thread it is.
            let Some(started) = thread_start_ticks(tid) else {
                continue; // exited between readdir and here
            };
            if seen.iter().any(|(t, st)| *t == tid && *st == started) {
                continue;
            }
            seen.push((tid, started));
            found_new += 1;
            let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::sched_getaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mut mask)
            };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if mask_too_small(&err) {
                    return Err(format!(
                        "this host's CPU mask is wider than a fixed cpu_set_t ({} CPUs) can \
                     express, so the daemon cannot be kept off VPP's cores from inside the \
                     process: {err}. Pin it externally instead (systemd `CPUAffinity=`), or \
                     expect resync bursts to preempt the VPP worker",
                        libc::CPU_SETSIZE
                    ));
                }
                // Threads exit between readdir and here; a vanished tid is
                // not a fault.
                continue;
            }
            for cpu in vpp_cores {
                unsafe { libc::CPU_CLR(*cpu as usize, &mut mask) };
            }
            if unsafe { libc::CPU_COUNT(&mask) } == 0 {
                tracing::warn!(
                    tid,
                    "this thread's whole mask IS VPP's cores; leaving it untouched — an \
                 unschedulable thread is worse than an unprotected worker"
                );
                continue;
            }
            let rc = unsafe {
                libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mask)
            };
            if rc == 0 {
                edited += 1;
            } else {
                errors.push(format!("tid {tid}: {}", std::io::Error::last_os_error()));
            }
        }
        if found_new == 0 {
            break;
        }
        if passes >= MAX_PASSES {
            tracing::warn!(
                passes,
                "threads are still appearing after {passes} affinity passes; some may remain \
                 eligible for VPP's cores"
            );
            break;
        }
    }
    // Not an error even when nothing was restricted: degraded
    // protection is a warning, and the caller reports it — see
    // `bring_up`, where zero edits is explicitly not logged as success.
    if !errors.is_empty() {
        tracing::warn!(
            edited,
            failed = errors.len(),
            "some threads kept their old affinity: {}",
            errors.join("; ")
        );
    }
    Ok(edited)
}

/// A thread pinned to at most this many CPUs is *placement*; anything
/// wider is a scheduling pool. One CPU is VPP's own shape — it pins its
/// main thread to `main-core` and each worker to its `corelist-workers`
/// CPU (vlib/threads.c, `pthread_setaffinity_np`) — and two tolerates
/// an operator pairing a thread with a sibling. VPP's helper threads
/// either inherit the main thread's pin (counted, harmlessly, as
/// main-core again) or run unpinned across the host, and treating a
/// wide inherited mask as placement would vacate the daemon from
/// everywhere.
#[cfg(target_os = "linux")]
const PINNED_WIDTH_MAX: i32 = 2;

/// The CPUs a running VPP's pinned threads occupy, observed from
/// `/proc/<pid>/task` — never remembered from a record.
///
/// This is how an ADOPTED VPP's cores are learned. Observation rather
/// than a state-file record is load-bearing, not a style choice: the
/// recorded placement this replaced produced a review finding for
/// every lifecycle that could outdate it (stale after a supervised
/// respawn, wrong across an upgrade from a file predating the field,
/// and an upgrade guard whose refusal left the box an unsupervised
/// VPP as its only forwarding tier). The live masks cannot go stale
/// and survive an operator retuning the process by hand.
///
/// Affinity is a per-thread attribute and `sched_getaffinity` reads
/// any tid's mask (the getter carries no privilege gate, and this
/// daemon is root regardless). An empty answer means no thread is
/// pinned narrowly enough to be placement; an `Err` means the process
/// could not be inspected at all — or turned out mid-scan not to be
/// the process asked about. The caller must treat both as "observe
/// failed, fall back to the derived map with a warning" — never as
/// "pinned nowhere, nothing to vacate".
///
/// `start_ticks` is the identity the pid must still carry, and it is
/// re-verified AFTER the walk, which covers the walk: if the process
/// at `pid` still has the adopted start time when the scan is done,
/// then it had it throughout — a pid does not return to a process
/// that lost it. Without this, a VPP that exits after adoption and
/// has its LEADER pid recycled rebinds the whole `/proc/<pid>/task`
/// path to the replacement process, and the per-tid membership check
/// below then vouches for every one of the stranger's threads
/// (review finding — the same identity rule as adoption itself,
/// `(pid, start_ticks)`, applied to the read side).
#[cfg(target_os = "linux")]
pub fn observed_placement(pid: i32, start_ticks: u64) -> Result<Vec<u16>, String> {
    let task_dir = format!("/proc/{pid}/task");
    let tasks = std::fs::read_dir(&task_dir).map_err(|e| format!("{task_dir}: {e}"))?;
    let mut cores: Vec<u16> = Vec::new();
    for entry in tasks.flatten() {
        let Some(tid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::sched_getaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mut mask)
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if mask_too_small(&err) {
                return Err(format!(
                    "this host's CPU mask is wider than a fixed cpu_set_t ({} CPUs) can \
                     express, so the adopted VPP's placement cannot be read: {err}",
                    libc::CPU_SETSIZE
                ));
            }
            continue; // thread exited between readdir and here
        }
        if unsafe { libc::CPU_COUNT(&mask) } > PINNED_WIDTH_MAX {
            continue;
        }
        // The tid must still be VPP's AFTER the read, not just at
        // readdir: `sched_getaffinity` addresses tids globally, so a
        // VPP thread that exited in between can have its tid recycled
        // by an unrelated process, whose narrow mask would then be
        // subtracted from every daemon thread as if it were placement —
        // and the restriction is one-way, so wrongly for good. A task
        // directory lists only its own thread group's tids, so this
        // existence check fails for a tid that migrated to a foreign
        // process, while a reuse WITHIN VPP names a VPP thread anyway.
        // Same identity discipline as `restrict_daemon_from`'s
        // `(tid, start_ticks)` set, shaped for a foreign process
        // (review finding).
        if !std::path::Path::new(&task_dir)
            .join(tid.to_string())
            .exists()
        {
            continue;
        }
        for cpu in 0..libc::CPU_SETSIZE as usize {
            if unsafe { libc::CPU_ISSET(cpu, &mask) } && !cores.contains(&(cpu as u16)) {
                cores.push(cpu as u16);
            }
        }
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| format!("pid {pid} vanished during the placement scan: {e}"))?;
    if crate::process::parse_start_ticks(&stat) != Some(start_ticks) {
        return Err(format!(
            "the process now at pid {pid} is not the adopted VPP (start-time cookie \
             changed during the scan), so the masks just read belong to a stranger"
        ));
    }
    cores.sort_unstable();
    Ok(cores)
}

#[cfg(not(target_os = "linux"))]
pub fn observed_placement(_pid: i32, _start_ticks: u64) -> Result<Vec<u16>, String> {
    // Non-Linux never has a VPP to observe.
    Err("thread affinity is not readable on this platform".into())
}

// There is deliberately **no** inverse of `restrict_daemon_from`.
//
// A CPU affinity mask is per-process state, and every path that stops
// this daemon protecting a VPP also ends the process: `Module::detach`
// has exactly two callers in the loader — the startup-unwind macro,
// which returns `Err` and exits, and the breaker-trip arm, which runs
// after the loop has already ended — and `packetframe detach --all` is
// a different process that never touches live modules. So the
// restriction dies with the daemon that made it, and there is nothing
// for a restore to restore.
//
// Worth stating because the restore path existed for several revisions
// and produced a review finding on every one of them: how to undo an
// edit for a thread born mid-epoch, for a reused tid, for a thread an
// operator retuned meanwhile, for one discovered on a later scan pass.
// Each answer was a guess about state we never observed — and the whole
// question was moot, because the process holding the state is on its
// way out in every case that would ask it. Restriction is one-way by
// design, not by omission.

#[cfg(not(target_os = "linux"))]
pub fn restrict_daemon_from(_vpp_cores: &[u16]) -> Result<usize, String> {
    // Non-Linux never attaches a VPP; there is nothing to protect.
    Ok(0)
}
#[cfg(all(test, target_os = "linux"))]
mod affinity_tests {
    use super::*;

    /// Serialises the tests in this module, because what they exercise
    /// is **process-wide**: `restrict_daemon_from` walks
    /// `/proc/self/task` and edits every TID — including the harness
    /// thread running the *other* test. Under the default parallel
    /// harness each test therefore rewrites the other's mask mid-
    /// assertion, which passes alone and with `--test-threads=1` and
    /// fails when both run together (review finding).
    ///
    /// Poisoning is absorbed deliberately: a panicking test leaves the
    /// mask it was mid-way through changing, the next test restores the
    /// mask itself, and refusing to run after an unrelated failure
    /// would just hide the second result behind the first.
    static AFFINITY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_affinity() -> std::sync::MutexGuard<'static, ()> {
        AFFINITY_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn current_mask() -> libc::cpu_set_t {
        let mut got: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc =
            unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut got) };
        assert_eq!(rc, 0);
        got
    }

    fn set_mask(cpus: &[usize]) {
        let mut m: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for &c in cpus {
            unsafe { libc::CPU_SET(c, &mut m) };
        }
        let rc = unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &m) };
        assert_eq!(rc, 0);
    }

    fn isset(cpu: usize) -> bool {
        unsafe { libc::CPU_ISSET(cpu, &current_mask()) }
    }

    /// Restriction SUBTRACTS VPP's cores and touches nothing else.
    ///
    /// Asserting the syscall's effect via readback, not the intent. CPU
    /// ids come from this process's own allowed mask rather than being
    /// synthesised from a count, so a container whose cpuset excludes
    /// low ids does not fail the harness before the implementation
    /// (review finding).
    #[test]
    fn restriction_subtracts_vpps_cores_and_preserves_the_rest() {
        let _serialised = lock_affinity();
        let before = current_mask();
        let allowed: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
            .filter(|&c| unsafe { libc::CPU_ISSET(c, &before) })
            .collect();
        if allowed.len() < 3 {
            return; // cannot express "narrower than allowed" here
        }
        let (a, b, c) = (allowed[0], allowed[1], allowed[2]);
        let vpp = [b as u16];

        // Operator narrowed the daemon to {a, b}; VPP takes b. Their
        // exclusion of c must survive: subtract, never rebuild.
        set_mask(&[a, b]);
        let edited = restrict_daemon_from(&vpp).expect("restrict");
        assert!(edited >= 1, "at least this thread was edited");
        assert!(!isset(b), "VPP's core is excluded");
        assert!(isset(a), "the rest of the policy is kept");
        assert!(!isset(c), "a core the operator excluded is not added");

        // A mask that IS VPP's cores is skipped, not emptied: an
        // unschedulable thread is worse than an unprotected worker.
        set_mask(&[b]);
        restrict_daemon_from(&vpp).expect("skip tolerated");
        assert!(isset(b), "the only usable core is left in place");

        let rc =
            unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &before) };
        assert_eq!(rc, 0);
    }

    /// Observation reads placement from the threads themselves: a
    /// narrowly pinned thread's CPU is reported, a wide default mask
    /// is not. Exercised against this very process, which is exactly
    /// how production reads an adopted VPP — same procfs walk, same
    /// syscall, different pid.
    #[test]
    fn observed_placement_reports_pinned_threads_and_ignores_wide_ones() {
        use std::sync::mpsc::channel;

        let _serialised = lock_affinity();
        let before = current_mask();
        let allowed: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
            .filter(|&c| unsafe { libc::CPU_ISSET(c, &before) })
            .collect();
        if allowed.len() < 4 {
            return; // every mask here would read as "pinned"
        }
        let (a, b) = (allowed[0], allowed[1]);

        let (pinned_tx, pinned_rx) = channel();
        let (done_tx, done_rx) = channel();
        let child = std::thread::spawn(move || {
            set_mask(&[a]); // pid 0: this thread only
            pinned_tx.send(()).expect("announce the pin");
            done_rx.recv().expect("hold the pin until observed");
        });
        pinned_rx.recv().expect("child pinned before observing");

        let own_pid = std::process::id() as i32;
        let own_ticks = crate::process::parse_start_ticks(
            &std::fs::read_to_string(format!("/proc/{own_pid}/stat")).expect("own stat"),
        )
        .expect("own start ticks");
        let observed = observed_placement(own_pid, own_ticks).expect("observe self");
        done_tx.send(()).expect("release the child");
        child.join().expect("child joined");

        assert!(
            observed.contains(&(a as u16)),
            "the pinned thread's CPU is the placement: {observed:?}"
        );
        assert!(
            !observed.contains(&(b as u16)),
            "a CPU held only by wide-mask threads is not placement: {observed:?}"
        );

        // A pid wearing the wrong start-time cookie is a stranger, and
        // a stranger's masks must be refused, not returned.
        assert!(
            observed_placement(own_pid, own_ticks ^ 1).is_err(),
            "an identity mismatch must refuse the observation"
        );
    }

    /// A thread created while the scan is running is still restricted.
    ///
    /// One pass is not enough and the gap is reachable: the fast-path
    /// runtime is live before VPP attaches and spawns blocking threads,
    /// so a thread born mid-scan from an unvisited parent would inherit
    /// an unrestricted mask and never be seen — free to preempt VPP's
    /// worker forever, which is the whole fault this prevents. The scan
    /// rescans until a pass finds nothing new; this asserts the
    /// consequence for a thread that exists by the final pass.
    #[test]
    fn a_thread_alive_during_the_scan_ends_up_restricted() {
        use std::sync::mpsc::channel;

        let _serialised = lock_affinity();
        let before = current_mask();
        let allowed: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
            .filter(|&c| unsafe { libc::CPU_ISSET(c, &before) })
            .collect();
        if allowed.len() < 2 {
            return;
        }
        let (a, b) = (allowed[0], allowed[1]);
        set_mask(&[a, b]);
        let vpp = [b as u16];

        let (born_tx, born_rx) = channel();
        let (go_tx, go_rx) = channel();
        let (got_tx, got_rx) = channel();
        let child = std::thread::spawn(move || {
            born_tx.send(()).expect("announce");
            go_rx.recv().expect("wait for the scan");
            let mut m: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut m)
            };
            assert_eq!(rc, 0);
            got_tx
                .send(unsafe { libc::CPU_ISSET(b, &m) })
                .expect("report");
        });
        born_rx.recv().expect("child exists before the scan");

        restrict_daemon_from(&vpp).expect("restrict");
        go_tx.send(()).expect("let the child read its mask");
        let child_on_vpp_core = got_rx.recv().expect("child reported");
        child.join().expect("child joined");

        assert!(
            !child_on_vpp_core,
            "a thread alive during the scan must not stay eligible for VPP's core"
        );

        let rc =
            unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &before) };
        assert_eq!(rc, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference fleet: 18 cores, `isolcpus=12` owned by
    /// unifi-core, four member ports at one worker each.
    #[test]
    fn the_reference_fleet_places_four_workers_off_the_top() {
        let online: Vec<u16> = (0..18).collect();
        let map = derive_core_map(&online, &[12], 4).unwrap();
        assert_eq!(map.workers, vec![14, 15, 16, 17]);
        assert_eq!(map.main, 13);
    }

    /// cpu0 and the isolated set are not merely deprioritised; they are
    /// unreachable. A map that lands on either is the bug this function
    /// exists to prevent, so assert it at the size where the walk would
    /// otherwise have to reach them.
    #[test]
    fn cpu0_and_isolated_cpus_are_never_chosen() {
        let online: Vec<u16> = (0..6).collect();
        // Usable: 1,2,4,5 → four CPUs, so 3 workers + main is the
        // tightest fit that still succeeds.
        let map = derive_core_map(&online, &[3], 3).unwrap();
        assert_eq!(map.main, 1);
        assert_eq!(map.workers, vec![2, 4, 5]);
        assert!(!map.workers.contains(&0) && map.main != 0);
        assert!(!map.workers.contains(&3) && map.main != 3);
    }

    /// Growing `cores` must not renumber the workers already placed —
    /// that is the whole reason the walk is descending, and an operator
    /// who affinitised PF IRQs away from the old set would otherwise
    /// find their work silently invalidated by a config bump.
    #[test]
    fn adding_a_worker_extends_the_set_downward_instead_of_renumbering() {
        let online: Vec<u16> = (0..18).collect();
        let two = derive_core_map(&online, &[12], 2).unwrap();
        let three = derive_core_map(&online, &[12], 3).unwrap();
        assert_eq!(two.workers, vec![16, 17]);
        assert_eq!(three.workers, vec![15, 16, 17]);
        for c in &two.workers {
            assert!(three.workers.contains(c), "worker {c} was renumbered");
        }
    }

    /// Offline CPUs are not placeable. `online` is the input precisely
    /// so a sparse set is respected rather than assumed contiguous.
    #[test]
    fn offline_cpus_are_not_placeable() {
        let map = derive_core_map(&[0, 1, 2, 7, 8], &[], 2).unwrap();
        assert_eq!(map.workers, vec![7, 8]);
        assert_eq!(map.main, 2);
    }

    /// Refusing beats degrading: `render` asserts that the worker count
    /// matches the count the stats segment was sized for, so a map that
    /// dropped a worker would either trip that assert or (if the two
    /// were derived from the same short list) undersize the segment and
    /// abort VPP mid-resync.
    #[test]
    fn an_impossible_request_is_refused_rather_than_shortened() {
        let e = derive_core_map(&[0, 1, 2], &[2], 2).unwrap_err();
        assert!(e.contains("need 3"), "{e}");
        // The exact boundary: two usable CPUs serve one worker, not two.
        assert!(derive_core_map(&[0, 1, 2], &[], 1).is_ok());
        assert!(derive_core_map(&[0, 1, 2], &[], 2).is_err());
    }

    /// A zero-worker config is legal (`cores 0` on every port) and must
    /// still place the main thread — VPP's main thread answers the
    /// binary API, so a map without one has nothing to converge.
    #[test]
    fn zero_workers_still_places_the_main_thread() {
        let map = derive_core_map(&[0, 1, 2, 3], &[], 0).unwrap();
        assert_eq!(map.main, 3);
        assert!(map.workers.is_empty());
    }

    #[test]
    fn cpu_lists_parse_in_every_shape_sysfs_writes() {
        assert_eq!(
            parse_cpu_list("0-17\n").unwrap(),
            (0..18).collect::<Vec<_>>()
        );
        assert_eq!(parse_cpu_list("12").unwrap(), vec![12]);
        assert_eq!(parse_cpu_list("0-1,4,6-7").unwrap(), vec![0, 1, 4, 6, 7]);
        // The normal content of `isolated` with no isolcpus=.
        assert_eq!(parse_cpu_list("\n").unwrap(), Vec::<u16>::new());
        assert_eq!(parse_cpu_list("").unwrap(), Vec::<u16>::new());
        // Duplicates collapse; a hand-edited overlap is not an error.
        assert_eq!(parse_cpu_list("2,2-3").unwrap(), vec![2, 3]);
    }

    /// Malformed input must not read as an empty list. An unparseable
    /// `isolated` that returned `vec![]` would place a poll-mode worker
    /// on the CPU somebody else reserved — silently, and only on the
    /// hosts whose format we failed to anticipate.
    #[test]
    fn a_malformed_cpu_list_is_an_error_not_an_empty_set() {
        for bad in ["x", "1-", "-1", "3-1", "1,,2", "1,x"] {
            assert!(parse_cpu_list(bad).is_err(), "{bad:?} parsed");
        }
    }

    /// The sysfs reader: `isolated` absent means nothing is isolated
    /// (the file only exists with CONFIG_CPU_ISOLATION), while `online`
    /// absent is fatal.
    #[test]
    fn a_missing_isolated_file_means_nothing_is_isolated() {
        let dir = std::env::temp_dir().join(format!("pf-cores-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("online"), "0-3\n").unwrap();
        let map = derive_from_sysfs(&dir, 2).unwrap();
        assert_eq!(map.workers, vec![2, 3]);
        assert_eq!(map.main, 1);

        std::fs::write(dir.join("isolated"), "3\n").unwrap();
        let map = derive_from_sysfs(&dir, 1).unwrap();
        assert_eq!(map.workers, vec![2], "isolated cpu3 was still used");
        assert_eq!(map.main, 1);

        std::fs::remove_file(dir.join("online")).unwrap();
        assert!(
            derive_from_sysfs(&dir, 1).is_err(),
            "missing online tolerated"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
