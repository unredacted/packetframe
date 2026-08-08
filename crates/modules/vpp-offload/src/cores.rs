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

/// Keep every thread of THIS daemon off VPP's cores.
///
/// The missing half of the plan's "cpuset + SCHED_FIFO" promise, found
/// by a week of drills (shadow, 2026-08-08). VPP's worker polls its rx
/// ring from a dedicated core, but `isolcpus` on this fleet belongs to
/// unifi-core and nothing constrained the daemon: at every adopted
/// resync's release, `begin_resync` walks a 1.3M-entry mirror and the
/// first drain batches encode thousands of routes — seconds of
/// memory-heavy burst that the scheduler was free to place on the
/// worker's core. A preempted poll loop overflows a 1024-descriptor rx
/// ring in ~2 s at the drill rate, and the drops happen at the NIC,
/// invisible to every VPP error counter — which is how three correct
/// fixes to the FIB-side work at the release instant each left the
/// measured ~5.4 s gap unmoved.
///
/// Applied to every task in `/proc/self/task` at attach; threads
/// spawned afterwards inherit their creator's mask. Errors are
/// collected, not fatal: a cgroup cpuset that refuses us is a reason to
/// warn, and refusing to attach over it would fail deployments that
/// merely share cores gracefully today.
#[cfg(target_os = "linux")]
pub fn restrict_daemon_from(map: &CoreMap) -> Result<usize, String> {
    let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if online <= 0 {
        return Err("cannot determine online CPU count".into());
    }
    let mut kept = 0usize;
    for cpu in 0..online as u16 {
        if cpu == map.main || map.workers.contains(&cpu) {
            continue;
        }
        unsafe { libc::CPU_SET(cpu as usize, &mut mask) };
        kept += 1;
    }
    if kept == 0 {
        return Err("the core map claims every online CPU; refusing an empty mask".into());
    }
    let mut set = 0usize;
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
        let rc =
            unsafe { libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mask) };
        if rc == 0 {
            set += 1;
        } else {
            errors.push(format!("tid {tid}: {}", std::io::Error::last_os_error()));
        }
    }
    if set == 0 {
        return Err(format!(
            "no thread accepted the affinity mask: {}",
            errors.join("; ")
        ));
    }
    if !errors.is_empty() {
        tracing::warn!(
            set,
            failed = errors.len(),
            "some threads kept their old affinity: {}",
            errors.join("; ")
        );
    }
    Ok(set)
}

#[cfg(not(target_os = "linux"))]
pub fn restrict_daemon_from(_map: &CoreMap) -> Result<usize, String> {
    // Non-Linux never attaches a VPP; there is nothing to protect.
    Ok(0)
}

#[cfg(all(test, target_os = "linux"))]
mod affinity_tests {
    use super::*;

    /// The mask really lands on the calling process: after restriction,
    /// the current thread's affinity excludes VPP's cores and includes
    /// at least one other. Read back via sched_getaffinity — asserting
    /// the syscall's effect, not our intent to make it.
    #[test]
    fn restriction_excludes_vpp_cores_and_keeps_the_rest() {
        let online = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if online < 2 {
            // A single-CPU runner cannot express "everything but".
            return;
        }
        let map = CoreMap {
            main: (online - 1) as u16,
            workers: vec![],
        };
        let set = restrict_daemon_from(&map).expect("restriction");
        assert!(set >= 1, "at least this thread's mask was set");

        let mut got: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc =
            unsafe { libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut got) };
        assert_eq!(rc, 0);
        assert!(
            !unsafe { libc::CPU_ISSET((online - 1) as usize, &got) },
            "VPP's core must be excluded"
        );
        assert!(
            unsafe { libc::CPU_ISSET(0, &got) },
            "the remaining cores must stay usable"
        );

        // Restore a full mask so later tests in this process are not
        // constrained by this one.
        let mut all: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for cpu in 0..online as usize {
            unsafe { libc::CPU_SET(cpu, &mut all) };
        }
        unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &all) };
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
