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
/// [`AffinitySnapshot`]. `None` when the thread has already exited or
/// its stat line cannot be parsed — both of which make it un-restorable
/// rather than a fault.
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
pub fn restrict_daemon_from(map: &CoreMap) -> Result<(usize, AffinitySnapshot), String> {
    let mut edited = 0usize;
    // `restorable` starts as all of VPP's cores and is narrowed by every
    // thread we observe, ending as the intersection: the cores a thread
    // born later can be given back without guessing at its creator's
    // policy.
    let mut saved = AffinitySnapshot {
        restorable: std::iter::once(map.main)
            .chain(map.workers.iter().copied())
            .collect(),
        ..Default::default()
    };
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
    // Loop bookkeeping, deliberately SEPARATE from `saved.masks`.
    //
    // Only the first pass sees threads in their pre-restriction state,
    // so only the first pass may contribute to the restoration record.
    // A thread discovered later was created by an already-restricted
    // parent, so the mask it carries is one WE caused — treating it as
    // that thread's original policy would intersect `restorable` down
    // to nothing (poisoning restoration for every post-attach thread)
    // and record it as having nothing to give back, leaving it narrowed
    // until the daemon restarts (review finding, caused by the rescan
    // added one commit earlier). Later passes therefore restrict but do
    // not record, which puts those threads on release's descendant path
    // where `restorable` is the right answer for them.
    let mut seen: Vec<(libc::pid_t, u64)> = Vec::new();
    loop {
        passes += 1;
        let first_pass = passes == 1;
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
            let before = mask;
            // Narrow the intersection with this thread's ORIGINAL
            // policy — first pass only, since that is the only pass
            // whose masks predate our own edits.
            if first_pass {
                saved
                    .restorable
                    .retain(|cpu| unsafe { libc::CPU_ISSET(*cpu as usize, &before) });
            }
            // Exactly the VPP cores this thread actually held — the set
            // release will put back, and nothing more.
            let mut removed: Vec<u16> = Vec::new();
            for cpu in std::iter::once(map.main).chain(map.workers.iter().copied()) {
                if unsafe { libc::CPU_ISSET(cpu as usize, &mask) } {
                    unsafe { libc::CPU_CLR(cpu as usize, &mut mask) };
                    removed.push(cpu);
                }
            }
            if unsafe { libc::CPU_COUNT(&mask) } == 0 {
                tracing::warn!(
                    tid,
                    "this thread's whole mask IS VPP's cores; leaving it untouched — an \
                 unschedulable thread is worse than an unprotected worker"
                );
                // Observed with nothing removed. Recorded ONLY on the
                // first pass, where it proves the thread is not a
                // post-attach stranger and release must leave it alone;
                // a later-pass thread belongs on the descendant path
                // instead.
                if first_pass {
                    saved.masks.push((tid, started, Vec::new()));
                }
                continue;
            }
            let rc = unsafe {
                libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mask)
            };
            if rc == 0 {
                edited += 1;
                if first_pass {
                    saved.masks.push((tid, started, removed));
                }
            } else {
                // The change did not land, so nothing was removed from
                // this thread — but it was observed, and (on the first
                // pass) release must know that.
                if first_pass {
                    saved.masks.push((tid, started, Vec::new()));
                }
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
    // Not an error even when nothing was restricted: the snapshot still
    // names every pre-existing thread, which is what keeps a later
    // release from unioning cores onto a thread that was never touched.
    // Degraded protection is a warning; discarding the snapshot via `Err`
    // (the caller falls back to an empty one) is what actually caused the
    // broadening.
    if !errors.is_empty() {
        tracing::warn!(
            edited,
            failed = errors.len(),
            "some threads kept their old affinity: {}",
            errors.join("; ")
        );
    }
    Ok((edited, saved))
}

/// What this attachment removed from each thread, so release is the
/// exact inverse of the restriction and nothing else.
///
/// Storing the whole pre-attach mask was the previous design and review
/// rejected it rightly: restoring it verbatim discards any change the
/// operator made WHILE VPP was attached (a `taskset` mid-attachment),
/// re-enabling CPUs they had since excluded. Restriction only ever
/// clears VPP-core bits, so its inverse is to set exactly those bits
/// back on whatever the thread's mask is at release time — every other
/// bit, however it got that way, is left alone.
///
/// Recording the removed set per thread also subsumes two earlier
/// findings for free: a thread whose policy already excluded a VPP core
/// has that core in nobody's removed set, so it can never gain it; and
/// a thread we observed but skipped (its mask would have emptied) or
/// failed to set has an EMPTY removed set, so release leaves it exactly
/// as found while still proving it is not a post-attach stranger.
///
/// Only threads seen on the FIRST scan pass appear here. Later passes
/// exist to catch threads spawned mid-scan, and those carry a mask this
/// function already narrowed — recording that as their "original" would
/// both empty `restorable` and promise them nothing back. They belong
/// on the descendant path, which `restorable` answers correctly.
///
/// A thread born DURING the restricted epoch has no capture, and no
/// exact inverse exists for it — we never saw its creator's original
/// mask, only the restricted one it inherited. So it gets
/// [`Self::restorable`] rather than every VPP core: the cores that
/// EVERY observed thread originally held. Whatever ancestor the new
/// thread descends from was one of those threads, so each core in that
/// intersection was demonstrably in its inherited policy and adding it
/// back cannot broaden anything. Cores held by only some pre-existing
/// threads stay off — under-restoring a new thread until the daemon's
/// next start, which is the safe direction and the one the operator
/// can reason about.
#[derive(Default, Clone)]
pub struct AffinitySnapshot {
    /// `(tid, start_ticks, the VPP cores THIS attachment removed)`.
    ///
    /// The start time is what makes the tid an IDENTITY rather than a
    /// number. A thread can exit during a long attachment and Linux can
    /// reuse its tid; restoring the dead thread's mask onto its
    /// namesake would hand a live thread a policy that was never its
    /// own (review finding). This is the same identity-must-be-whole
    /// rule [`crate::process`] applies to an adopted VPP — pid alone is
    /// never enough — and it reuses that module's `/proc` stat parser
    /// rather than growing a second one.
    #[cfg(target_os = "linux")]
    masks: Vec<(libc::pid_t, u64, Vec<u16>)>,
    /// VPP cores present in the original mask of every observed thread.
    /// See the type docs: the only cores a post-attach thread can be
    /// given back without guessing.
    ///
    /// Read only by the Linux `release_daemon_to`; the non-Linux stubs
    /// never restrict, so nothing there consults it. Gated to match
    /// `masks` rather than `allow(dead_code)`, so a genuinely unread
    /// field on Linux would still be caught.
    #[cfg(target_os = "linux")]
    restorable: Vec<u16>,
}

impl std::fmt::Debug for AffinitySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(target_os = "linux")]
        return write!(f, "AffinitySnapshot({} threads)", self.masks.len());
        #[cfg(not(target_os = "linux"))]
        write!(f, "AffinitySnapshot")
    }
}

/// The inverse of [`restrict_daemon_from`], for the paths where no VPP
/// is left to protect — a bring-up that rolled back cleanly, and a
/// detach whose teardown completed (including one that settles late,
/// after `detach` itself returned).
///
/// Single-pass, deliberately, where restriction rescans to a fixpoint.
/// The asymmetry follows the consequence: a thread missed by
/// RESTRICTION can run on VPP's cores and preempt the poll loop, which
/// is the fault this whole mechanism exists to prevent; a thread missed
/// by RELEASE merely keeps a narrower mask than it might, costing
/// scheduling breadth on a daemon that no longer has a VPP to protect,
/// and correcting itself at the next daemon start.
///
/// Takes only the snapshot: it carries both the per-thread originals
/// and the `restorable` set, so the [`CoreMap`] is not needed here and
/// is not accepted — a parameter nothing reads is a parameter that can
/// disagree with the one restriction used.
#[cfg(target_os = "linux")]
pub fn release_daemon_to(saved: &AffinitySnapshot) -> Result<usize, String> {
    let mut edited = 0usize;
    let mut errors: Vec<String> = Vec::new();
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
        // The tid must match AND be the same thread: a reused tid names
        // a stranger, whose mask is none of our business to restore.
        let started = thread_start_ticks(tid);
        // Read the CURRENT mask either way: release edits what the
        // thread has now, so an operator's mid-attachment `taskset`
        // survives (review finding).
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::sched_getaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mut mask)
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if mask_too_small(&err) {
                return Err(format!(
                    "this host's CPU mask is wider than a fixed cpu_set_t can express: {err}"
                ));
            }
            continue; // vanished between readdir and here
        }
        let give_back: &[u16] = match saved
            .masks
            .iter()
            .find(|(t, s, _)| *t == tid && Some(*s) == started)
        {
            // A surviving thread gets back exactly the cores THIS
            // attachment took from it — never a whole stale mask.
            Some((_, _, removed)) => removed,
            // Born during the restricted epoch (or a reused tid, which
            // is the same thing from here): no per-thread record
            // applies, so only the cores EVERY pre-existing thread held
            // go back — see `AffinitySnapshot`.
            None => &saved.restorable,
        };
        for cpu in give_back {
            unsafe { libc::CPU_SET(*cpu as usize, &mut mask) };
        }
        let rc =
            unsafe { libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mask) };
        if rc == 0 {
            edited += 1;
        } else {
            errors.push(format!("tid {tid}: {}", std::io::Error::last_os_error()));
        }
    }
    if edited == 0 && !errors.is_empty() {
        return Err(format!(
            "no thread accepted its affinity change: {}",
            errors.join("; ")
        ));
    }
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

#[cfg(not(target_os = "linux"))]
pub fn restrict_daemon_from(_map: &CoreMap) -> Result<(usize, AffinitySnapshot), String> {
    // Non-Linux never attaches a VPP; there is nothing to protect.
    Ok((0, AffinitySnapshot::default()))
}

#[cfg(not(target_os = "linux"))]
pub fn release_daemon_to(_saved: &AffinitySnapshot) -> Result<usize, String> {
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
    /// fails when both run together (review finding; CI had been
    /// getting away with it on timing).
    ///
    /// Held for the whole snapshot-to-restoration interval, not just
    /// the syscall: the window that must be exclusive is "my mask is
    /// modified", which spans every assertion between them.
    ///
    /// Poisoning is absorbed deliberately. A panicking test leaves the
    /// masks it was mid-way through restoring, and the next test's
    /// first act is to capture and later restore them itself — so the
    /// lock's job is mutual exclusion, not integrity, and refusing to
    /// run after an unrelated failure would just hide the second
    /// result behind the first.
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

    /// Asserting the SYSCALL's effect via readback, not the intent.
    /// CPU ids come from THIS process's allowed mask, not from ids
    /// synthesized off a count — a container whose cpuset excludes low
    /// ids would otherwise fail the harness before the implementation
    /// (review finding).
    #[test]
    fn restriction_subtracts_and_release_restores_the_saved_masks() {
        let _serialised = lock_affinity();
        let before = current_mask();
        let allowed: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
            .filter(|&c| unsafe { libc::CPU_ISSET(c, &before) })
            .collect();
        if allowed.len() < 3 {
            return; // cannot express "narrower than allowed" here
        }
        let (a, b, c) = (allowed[0], allowed[1], allowed[2]);
        let map = CoreMap {
            main: b as u16,
            workers: vec![],
        };

        // Operator narrowed the daemon to {a, b}; VPP takes b; the
        // operator's exclusion of c must survive every step.
        set_mask(&[a, b]);
        let (n, snap) = restrict_daemon_from(&map).expect("restrict");
        assert!(n >= 1);
        assert!(!isset(b), "VPP's core excluded");
        assert!(isset(a), "the rest kept");
        assert!(!isset(c), "subtract, never rebuild");

        // An operator retunes the daemon WHILE VPP is attached: c is
        // added, and that change must survive release. Restoring a
        // whole pre-attach mask would silently discard it (review
        // finding); adding back only what was removed cannot.
        set_mask(&[a, c]);
        release_daemon_to(&snap).expect("release");
        assert!(isset(b), "the core this attachment removed came back");
        assert!(
            isset(c),
            "an affinity change made during the attachment must survive release"
        );

        // The finding that killed union-on-release: an operator mask
        // that ALREADY excluded VPP's core must not gain it back.
        set_mask(&[a]);
        let (_, snap2) = restrict_daemon_from(&map).expect("restrict2");
        release_daemon_to(&snap2).expect("release2");
        assert!(
            !isset(b),
            "a mask that never held VPP's core must not acquire it on release"
        );

        // A mask that IS VPP's cores is skipped, not emptied — AND the
        // skipped thread must still be recorded, so release restores its
        // original verbatim rather than unioning (which here would be a
        // no-op, but the recording is what makes a DIFFERENT skipped
        // thread safe). Narrow to {a, b}, exclude c, so a broadening
        // union would be visible as c appearing.
        set_mask(&[b]);
        let (_, snap3) = restrict_daemon_from(&map).expect("skip tolerated");
        assert!(isset(b), "unschedulable is worse than unprotected");
        release_daemon_to(&snap3).expect("release3");
        assert!(
            isset(b) && !isset(a) && !isset(c),
            "a skipped thread's original mask is restored verbatim, never unioned"
        );

        let rc =
            unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &before) };
        assert_eq!(rc, 0);
    }

    /// A thread born during the restricted epoch must never be handed a
    /// core its creator's policy excluded.
    ///
    /// No exact inverse exists for such a thread — we never saw its
    /// creator's original mask — so release adds only the VPP cores
    /// EVERY observed thread held. Here the calling thread's policy
    /// excludes VPP's core, so that intersection is empty and the child
    /// must come back with nothing added. Unioning all of VPP's cores
    /// (the previous behaviour) hands it a core the operator never
    /// allowed; that is what this pins.
    #[test]
    fn a_thread_born_after_restriction_gains_only_universally_held_cores() {
        use std::sync::mpsc::channel;

        let _serialised = lock_affinity();
        let before = current_mask();
        let allowed: Vec<usize> = (0..libc::CPU_SETSIZE as usize)
            .filter(|&c| unsafe { libc::CPU_ISSET(c, &before) })
            .collect();
        if allowed.len() < 3 {
            return;
        }
        let (a, b, c) = (allowed[0], allowed[1], allowed[2]);

        // VPP takes b; this thread's policy is {a, c} — b excluded, so
        // b is NOT universally held.
        set_mask(&[a, c]);
        let map = CoreMap {
            main: b as u16,
            workers: vec![],
        };
        let (_, snap) = restrict_daemon_from(&map).expect("restrict");

        let (born_tx, born_rx) = channel();
        let (go_tx, go_rx) = channel();
        let (got_tx, got_rx) = channel();
        let child = std::thread::spawn(move || {
            born_tx.send(()).expect("announce");
            go_rx.recv().expect("wait for release");
            let mut m: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut m)
            };
            assert_eq!(rc, 0);
            got_tx
                .send(unsafe { libc::CPU_ISSET(b, &m) })
                .expect("report");
        });
        born_rx.recv().expect("child exists before release");

        release_daemon_to(&snap).expect("release");
        go_tx.send(()).expect("let the child read its mask");
        let child_has_vpp_core = got_rx.recv().expect("child reported");
        child.join().expect("child joined");

        assert!(
            !child_has_vpp_core,
            "a thread born after restriction must not gain a core its creator's \
             policy excluded"
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
