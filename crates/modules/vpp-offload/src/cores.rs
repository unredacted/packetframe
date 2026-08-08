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
    let mut saved = AffinitySnapshot::default();
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
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::sched_getaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mut mask)
        };
        if rc != 0 {
            // Threads exit between readdir and here; a vanished tid is
            // not a fault.
            continue;
        }
        let before = mask;
        // Record EVERY thread we observed, with its original mask —
        // before deciding whether to change it. Release keys on this:
        // a tid present here restores its original verbatim (a no-op for
        // the ones we leave untouched below), and only a tid ABSENT is
        // treated as born-after-restriction and unioned. Recording just
        // the successfully-restricted threads was the bug (review
        // finding): a thread skipped for an empty mask, or one whose
        // setaffinity failed, would then be missing from the snapshot
        // and wrongly unioned VPP's cores on release, broadening a
        // policy it never had restricted.
        saved.masks.push((tid, before));
        for cpu in std::iter::once(map.main).chain(map.workers.iter().copied()) {
            unsafe { libc::CPU_CLR(cpu as usize, &mut mask) };
        }
        if unsafe { libc::CPU_COUNT(&mask) } == 0 {
            tracing::warn!(
                tid,
                "this thread's whole mask IS VPP's cores; leaving it untouched — an \
                 unschedulable thread is worse than an unprotected worker"
            );
            continue;
        }
        let rc =
            unsafe { libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mask) };
        if rc == 0 {
            edited += 1;
        } else {
            errors.push(format!("tid {tid}: {}", std::io::Error::last_os_error()));
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

/// The masks each thread held BEFORE restriction, so release restores
/// the operator's policy exactly rather than approximating it.
///
/// Union-on-release was the first design and review rejected it
/// rightly: an operator mask that itself excluded one of VPP's cores
/// would gain it back on rollback or detach, widening the daemon onto
/// silicon the operator reserved. Surviving threads restore their
/// captured mask verbatim; threads born during the restricted epoch
/// (no capture) fall back to union, which is exact for them — they
/// inherited a restricted mask whose only edit was ours.
#[derive(Default, Clone)]
pub struct AffinitySnapshot {
    #[cfg(target_os = "linux")]
    masks: Vec<(libc::pid_t, libc::cpu_set_t)>,
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
#[cfg(target_os = "linux")]
pub fn release_daemon_to(map: &CoreMap, saved: &AffinitySnapshot) -> Result<usize, String> {
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
        let mask = match saved.masks.iter().find(|(t, _)| *t == tid) {
            // A surviving thread gets its pre-restriction mask back,
            // verbatim — including any exclusion of VPP's cores the
            // operator had already made.
            Some((_, m)) => *m,
            // Born during the restricted epoch: its inherited mask is a
            // restricted one whose only edit was ours, so the union is
            // exact.
            None => {
                let mut m: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                let rc = unsafe {
                    libc::sched_getaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mut m)
                };
                if rc != 0 {
                    continue; // vanished between readdir and here
                }
                for cpu in std::iter::once(map.main).chain(map.workers.iter().copied()) {
                    unsafe { libc::CPU_SET(cpu as usize, &mut m) };
                }
                m
            }
        };
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
pub fn release_daemon_to(_map: &CoreMap, _saved: &AffinitySnapshot) -> Result<usize, String> {
    Ok(0)
}

#[cfg(all(test, target_os = "linux"))]
mod affinity_tests {
    use super::*;

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

        release_daemon_to(&map, &snap).expect("release");
        assert!(isset(b), "the saved mask gave VPP's core back");
        assert!(!isset(c), "and added nothing the operator excluded");

        // The finding that killed union-on-release: an operator mask
        // that ALREADY excluded VPP's core must not gain it back.
        set_mask(&[a]);
        let (_, snap2) = restrict_daemon_from(&map).expect("restrict2");
        release_daemon_to(&map, &snap2).expect("release2");
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
        release_daemon_to(&map, &snap3).expect("release3");
        assert!(
            isset(b) && !isset(a) && !isset(c),
            "a skipped thread's original mask is restored verbatim, never unioned"
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
