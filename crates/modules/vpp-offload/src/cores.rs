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

/// One rx queue's worker.
///
/// `worker_id` is VPP's 0-based WORKER number, not a CPU and not a
/// thread index: worker N runs on the N-th CPU of `corelist-workers`,
/// which [`CoreMap::workers`] renders ascending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RxPlacement {
    pub queue_id: u32,
    pub worker_id: u32,
}

/// The order ports are created in VPP: every port with dedicated
/// `cores`, in config order, then every `cores 0` port.
///
/// This order IS the placement mechanism. The octeon driver runs on
/// VPP's `vnet_dev` framework, which hands rx queues to workers
/// round-robin as ports are created — one global counter from worker 0,
/// wrapping after the last — and never registers them with the generic
/// rx-placement machinery, so `sw_interface_set_rx_placement` refuses
/// every octeon queue ("unknown queue 0", measured on the rig
/// 2026-09-24; `vnet_dev_port_if_create`, VPP v26.06). Creating the
/// dedicated ports first gives them consecutive workers from 0, and the
/// first `cores 0` port then lands on the shared worker
/// `VppOffloadConfig::total_workers` adds after them.
///
/// Indices into `ports`.
pub fn creation_order(ports: &[(&str, u16)]) -> Vec<usize> {
    let dedicated = (0..ports.len()).filter(|&i| ports[i].1 > 0);
    let shared = (0..ports.len()).filter(|&i| ports[i].1 == 0);
    dedicated.chain(shared).collect()
}

/// Where VPP will poll each port's rx queues, per port, in
/// [`creation_order`] — a prediction of `vnet_dev`'s round-robin, for
/// the attach log, since nothing can set it.
///
/// A port with `cores c >= 1` gets queues `0..c` on consecutive
/// workers from worker 0 in config order. The first `cores 0` port gets
/// the shared worker, the last one. **A second `cores 0` port does
/// not**: the counter has wrapped, so its queue lands on worker 0, the
/// third's on worker 1, and so on — egress-only queues joining dedicated
/// workers. That costs those workers one near-empty poll per loop (an
/// egress-only port receives only what the NIC leaks to its VF, ~2 pps
/// measured), and it is what this VPP can express.
pub fn rx_placement_plan(ports: &[(&str, u16)]) -> Vec<(String, Vec<RxPlacement>)> {
    let workers = packetframe_common::config::vpp_worker_count(ports.iter().map(|(_, c)| *c));
    let mut next = 0u32;
    creation_order(ports)
        .into_iter()
        .map(|i| {
            let (iface, cores) = ports[i];
            let queues = (0..u32::from(cores.max(1)))
                .map(|q| {
                    let p = RxPlacement {
                        queue_id: q,
                        worker_id: next,
                    };
                    next = (next + 1) % workers.max(1);
                    p
                })
                .collect();
            (iface.to_string(), queues)
        })
        .collect()
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
    let (online, isolated) = read_cpu_topology(sysfs_cpu)?;
    derive_core_map(&online, &isolated, workers)
}

/// `(online, isolated)` from `/sys/devices/system/cpu`, with the
/// missing-file rules [`derive_from_sysfs`] documents.
///
/// Separate so the IRQ mover reads the same sets the core derivation
/// did: a mover that computed "CPUs that are not VPP's" from a different
/// reading could place an IRQ on an isolated CPU the derivation had
/// carefully kept VPP off.
pub fn read_cpu_topology(sysfs_cpu: &std::path::Path) -> Result<(Vec<u16>, Vec<u16>), String> {
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
    Ok((online, isolated))
}

/// Render a CPU set the way the kernel writes one: ascending, runs
/// collapsed to `a-b`, comma-separated. The inverse of
/// [`parse_cpu_list`], and what `smp_affinity_list` accepts.
pub fn format_cpu_list(cpus: &[u16]) -> String {
    let mut v: Vec<u16> = cpus.to_vec();
    v.sort_unstable();
    v.dedup();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < v.len() {
        let start = v[i];
        let mut end = start;
        while i + 1 < v.len() && v[i + 1] == end + 1 {
            i += 1;
            end = v[i];
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        i += 1;
    }
    out.join(",")
}

/// The CPUs a member-port IRQ may be moved onto: online, not one of
/// VPP's, and not isolated.
///
/// Isolated CPUs are excluded for the reason the core derivation
/// excludes them — whoever set `isolcpus=` meant nothing should run
/// there, and an IRQ is something. cpu0 is NOT excluded: the derivation
/// keeps VPP off it because it carries housekeeping, which is exactly
/// why it is an ordinary home for an interrupt.
pub fn irq_safe_cpus(online: &[u16], isolated: &[u16], vpp_cores: &[u16]) -> Vec<u16> {
    let mut v: Vec<u16> = online
        .iter()
        .copied()
        .filter(|c| !isolated.contains(c) && !vpp_cores.contains(c))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// One IRQ this module re-pinned, for the attach log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrqMove {
    pub iface: String,
    pub irq: u32,
    /// `smp_affinity_list` before the write.
    pub was: String,
    /// What was written.
    pub now: String,
}

/// Re-pin each conflicting IRQ onto `safe`, keeping as much of its
/// existing permitted mask as survives.
///
/// **Why this module writes affinities at all.** The refusal it
/// replaces told the operator to do exactly this by hand, and on the
/// fleet a hand-written affinity is gone at the next reboot, provision
/// cycle or ring resize. Every one of those left vpp-offload refusing —
/// and until the loader learned to degrade, taking the fast-path down
/// with it (primary, 2026-08-14: fifteen refusals under systemd
/// auto-restart after a ring resize). There is no durable place for
/// the setting on UniFi except the thing that needs it.
///
/// **Narrowing, not replacing.** The new mask is the current mask minus
/// VPP's cores and the isolated set — an operator who spread an IRQ over
/// 1-6 keeps it on 1-6.
///
/// **A mask that leaves nothing gets ONE CPU, and consecutive ones get
/// different CPUs.** The first version wrote the whole safe set for
/// each, but an interrupt controller given a mask picks one target from
/// it rather than balancing — so the queue IRQs pinned one-per-core that
/// the kernel's default spread produces (every one of VPP's cores
/// carries one) would all have landed on the same, lowest safe CPU:
/// cpu0, the housekeeping core. Rotated instead, with cpu0 last in the
/// rotation so it takes an IRQ only once every other safe CPU has one
/// (review finding, PR #238).
///
/// **Not restored on detach, deliberately.** Putting an IRQ back on a
/// CPU VPP no longer uses would re-create the conflict for the next
/// attach and buy nothing: the pre-attach mask was the kernel's default
/// spread, not a choice anyone made, and a reboot re-spreads anyway.
///
/// Writes only; whether the kernel then DELIVERS elsewhere is the
/// caller's to check, by running [`nic_irq_conflicts`] again — the
/// written mask is permission, the effective CPU is the fact.
pub fn move_irqs_off(
    proc_irq: &std::path::Path,
    conflicts: &[IrqConflict],
    safe: &[u16],
) -> Result<Vec<IrqMove>, String> {
    if safe.is_empty() {
        return Err("no CPU is left for NIC IRQs outside VPP's cores and the isolated set".into());
    }
    // cpu0 last: it is safe, but it is also the housekeeping core.
    let rotation: Vec<u16> = safe
        .iter()
        .copied()
        .filter(|c| *c != 0)
        .chain(safe.iter().copied().filter(|c| *c == 0))
        .collect();
    let mut next = 0usize;
    let mut moved = Vec::new();
    let mut failed = Vec::new();
    for c in conflicts {
        let path = proc_irq.join(c.irq.to_string()).join("smp_affinity_list");
        let was = std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let kept: Vec<u16> = parse_cpu_list(&was)
            .unwrap_or_default()
            .into_iter()
            .filter(|cpu| safe.contains(cpu))
            .collect();
        let now = if kept.is_empty() {
            let cpu = rotation[next % rotation.len()];
            next += 1;
            cpu.to_string()
        } else {
            format_cpu_list(&kept)
        };
        match std::fs::write(&path, format!("{now}\n")) {
            Ok(()) => moved.push(IrqMove {
                iface: c.iface.clone(),
                irq: c.irq,
                was,
                now,
            }),
            Err(e) => failed.push(format!("{} irq {}: {e}", c.iface, c.irq)),
        }
    }
    if !failed.is_empty() {
        return Err(format!(
            "could not re-pin {} NIC IRQ(s): {}",
            failed.len(),
            failed.join(", ")
        ));
    }
    Ok(moved)
}

/// What [`clear_irqs_off`] did and what it could not.
#[derive(Debug, Default)]
pub struct IrqClearing {
    /// What was re-pinned, for the attach log.
    pub moved: Vec<IrqMove>,
    /// The set moves drew from. Empty when nothing conflicted.
    pub safe: Vec<u16>,
    /// What still fires on the busy cores after the move — re-read, not
    /// inferred from the writes having succeeded.
    pub still: Vec<IrqConflict>,
}

/// Find `ifaces`' queue IRQs delivering on `busy`, move them off, and
/// read delivery back.
///
/// One routine for both passes bring-up makes: before VPP exists,
/// against the derived map, and again after adopting a surviving VPP
/// whose threads are observed on cores the derived map does not name.
/// The caller decides what a non-empty `still` means, because the two
/// passes answer it differently.
pub fn clear_irqs_off(
    sysfs_net: &std::path::Path,
    proc_irq: &std::path::Path,
    sysfs_cpu: &std::path::Path,
    ifaces: &[String],
    busy: &[u16],
) -> Result<IrqClearing, String> {
    let conflicts = nic_irq_conflicts(sysfs_net, proc_irq, ifaces, busy)?;
    if conflicts.is_empty() {
        return Ok(IrqClearing::default());
    }
    let (online, isolated) = read_cpu_topology(sysfs_cpu)?;
    let safe = irq_safe_cpus(&online, &isolated, busy);
    let moved = move_irqs_off(proc_irq, &conflicts, &safe)?;
    let still = nic_irq_conflicts(sysfs_net, proc_irq, ifaces, busy)?;
    Ok(IrqClearing { moved, safe, still })
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

/// A NIC queue interrupt that currently fires on a CPU VPP is about to
/// occupy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrqConflict {
    pub iface: String,
    pub irq: u32,
    /// The overlapping CPUs — the intersection of the IRQ's effective
    /// affinity with VPP's derived cores.
    pub cpus: Vec<u16>,
}

/// Every NIC queue IRQ of `ifaces` whose *effective* affinity lands on
/// one of `vpp_cores`.
///
/// This is the module-doc's "operator action" (move the PF IRQs off the
/// derived worker set) turned into a checkable precondition. The first
/// primary attach (2026-08-13) ran without it: NIC queue IRQs were
/// pinned one-per-core across all 18 CPUs, six poll-mode workers landed
/// on seven of them, and production softirq fought the pollers — load
/// 10, management ssh dropped, birdc past its budget, and VPP itself
/// starved into a supervisor restart loop. The attach log's advice line
/// was printed and nothing enforced it.
///
/// `effective_affinity_list` rather than `smp_affinity_list`, because
/// the question is where the IRQ **fires today**, not where it is
/// permitted to fire: a 0-17 wildcard mask still delivers to exactly
/// one CPU, and that CPU either is or is not about to become a hot
/// poller. Falls back to `smp_affinity_list` on kernels that don't
/// expose the effective file.
///
/// A port without an `msi_irqs` directory contributes nothing — that is
/// the fixture-sysfs case and any non-MSI device, where there is no
/// queue IRQ to conflict with. Unreadable affinity files skip the one
/// IRQ (it may have been freed between the listing and the read);
/// unreadable directories fail loudly.
pub fn nic_irq_conflicts(
    sysfs_net: &std::path::Path,
    proc_irq: &std::path::Path,
    ifaces: &[String],
    vpp_cores: &[u16],
) -> Result<Vec<IrqConflict>, String> {
    let mut conflicts = Vec::new();
    for iface in ifaces {
        let dir = sysfs_net.join(iface).join("device").join("msi_irqs");
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("read {}: {e}", dir.display())),
        };
        let mut irqs: Vec<u32> = entries
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
            .collect();
        irqs.sort_unstable();
        for irq in irqs {
            let eff = proc_irq
                .join(irq.to_string())
                .join("effective_affinity_list");
            let raw = match std::fs::read_to_string(&eff) {
                Ok(s) => s,
                Err(_) => {
                    let smp = proc_irq.join(irq.to_string()).join("smp_affinity_list");
                    match std::fs::read_to_string(&smp) {
                        Ok(s) => s,
                        Err(_) => continue,
                    }
                }
            };
            let cpus = match parse_cpu_list(raw.trim()) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let overlap: Vec<u16> = cpus.into_iter().filter(|c| vpp_cores.contains(c)).collect();
            if !overlap.is_empty() {
                conflicts.push(IrqConflict {
                    iface: iface.clone(),
                    irq,
                    cpus: overlap,
                });
            }
        }
    }
    Ok(conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture for the IRQ-overlap check: a sysfs-net with msi_irqs
    /// entries and a proc-irq with affinity files, in a throwaway dir.
    fn irq_fixture(tag: &str, irqs: &[(u32, &str)]) -> (std::path::PathBuf, std::path::PathBuf) {
        let mut base = std::env::temp_dir();
        base.push(format!("pf-irq-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let net = base.join("net");
        let proc_irq = base.join("proc_irq");
        let msi = net.join("eth9").join("device").join("msi_irqs");
        std::fs::create_dir_all(&msi).unwrap();
        for (irq, aff) in irqs {
            std::fs::write(msi.join(irq.to_string()), "").unwrap();
            let d = proc_irq.join(irq.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("effective_affinity_list"), format!("{aff}\n")).unwrap();
        }
        (net, proc_irq)
    }

    /// Like [`irq_fixture`], but with `smp_affinity_list` and NO
    /// effective file — so `nic_irq_conflicts` falls back to the mask
    /// and a write is visible to the next read, the way a kernel that
    /// honours the mask behaves.
    fn irq_fixture_smp(
        tag: &str,
        irqs: &[(u32, &str)],
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        let mut base = std::env::temp_dir();
        base.push(format!("pf-irqsmp-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let net = base.join("net");
        let proc_irq = base.join("proc_irq");
        let msi = net.join("eth9").join("device").join("msi_irqs");
        std::fs::create_dir_all(&msi).unwrap();
        for (irq, aff) in irqs {
            std::fs::write(msi.join(irq.to_string()), "").unwrap();
            let d = proc_irq.join(irq.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("smp_affinity_list"), format!("{aff}\n")).unwrap();
        }
        (net, proc_irq)
    }

    fn rp(queue_id: u32, worker_id: u32) -> RxPlacement {
        RxPlacement {
            queue_id,
            worker_id,
        }
    }

    /// The reference primary's shape: dedicated ports first on their own
    /// workers, the one egress-only port on the shared worker after them.
    #[test]
    fn a_single_cores_zero_port_lands_on_the_shared_worker() {
        let ports = [
            ("eth0", 0),
            ("eth2", 1),
            ("eth3", 1),
            ("eth4", 1),
            ("eth5", 1),
        ];
        assert_eq!(creation_order(&ports), vec![1, 2, 3, 4, 0]);
        assert_eq!(
            rx_placement_plan(&ports),
            vec![
                ("eth2".to_string(), vec![rp(0, 0)]),
                ("eth3".to_string(), vec![rp(0, 1)]),
                ("eth4".to_string(), vec![rp(0, 2)]),
                ("eth5".to_string(), vec![rp(0, 3)]),
                ("eth0".to_string(), vec![rp(0, 4)]),
            ]
        );
    }

    /// Round-robin wraps: only the first `cores 0` port gets the shared
    /// worker, the rest join dedicated workers in turn. Predicted, not
    /// wished for — this is what `vnet_dev` does.
    #[test]
    fn further_cores_zero_ports_wrap_onto_dedicated_workers() {
        let plan = rx_placement_plan(&[("eth2", 0), ("eth3", 1), ("eth4", 0), ("eth5", 0)]);
        assert_eq!(
            plan,
            vec![
                ("eth3".to_string(), vec![rp(0, 0)]),
                ("eth2".to_string(), vec![rp(0, 1)]),
                ("eth4".to_string(), vec![rp(0, 0)]),
                ("eth5".to_string(), vec![rp(0, 1)]),
            ]
        );
    }

    /// Nothing dedicated: one worker polls everything.
    #[test]
    fn placement_with_only_cores_zero_ports_uses_worker_zero() {
        let plan = rx_placement_plan(&[("eth2", 0), ("eth3", 0)]);
        assert_eq!(
            plan,
            vec![
                ("eth2".to_string(), vec![rp(0, 0)]),
                ("eth3".to_string(), vec![rp(0, 0)]),
            ]
        );
    }

    /// Multi-core ports get one queue per worker, consecutive and
    /// distinct, in config order; the shared worker follows the last
    /// dedicated one. Without `cores 0` ports nothing is reordered.
    #[test]
    fn placement_gives_multi_core_ports_distinct_consecutive_workers() {
        let plan = rx_placement_plan(&[("eth2", 2), ("eth3", 0), ("eth4", 3)]);
        assert_eq!(
            plan,
            vec![
                ("eth2".to_string(), vec![rp(0, 0), rp(1, 1)]),
                ("eth4".to_string(), vec![rp(0, 2), rp(1, 3), rp(2, 4)]),
                ("eth3".to_string(), vec![rp(0, 5)]),
            ]
        );
        let ports = [("eth2", 1), ("eth3", 2)];
        assert_eq!(creation_order(&ports), vec![0, 1], "config order kept");
        assert_eq!(
            rx_placement_plan(&ports),
            vec![
                ("eth2".to_string(), vec![rp(0, 0)]),
                ("eth3".to_string(), vec![rp(0, 1), rp(1, 2)]),
            ]
        );
    }

    /// Every worker the plan names exists: the highest id is
    /// `total_workers() - 1`, and every worker is used.
    #[test]
    fn placement_names_exactly_the_workers_total_workers_sizes() {
        for ports in [
            vec![("a", 1u16), ("b", 0), ("c", 0)],
            vec![("a", 0)],
            vec![("a", 2), ("b", 1)],
            vec![("a", 0), ("b", 3), ("c", 0), ("d", 1)],
        ] {
            let total = packetframe_common::config::vpp_worker_count(ports.iter().map(|(_, c)| *c));
            let mut used: Vec<u32> = rx_placement_plan(&ports)
                .into_iter()
                .flat_map(|(_, q)| q.into_iter().map(|p| p.worker_id))
                .collect();
            used.sort_unstable();
            used.dedup();
            assert_eq!(used, (0..total).collect::<Vec<_>>(), "{ports:?}");
        }
    }

    #[test]
    fn cpu_lists_render_the_way_the_kernel_writes_them() {
        assert_eq!(format_cpu_list(&[0, 1, 2, 3, 5, 7, 8, 9]), "0-3,5,7-9");
        assert_eq!(format_cpu_list(&[4]), "4");
        assert_eq!(
            format_cpu_list(&[9, 3, 3, 4]),
            "3-4,9",
            "sorted and deduplicated"
        );
        assert_eq!(format_cpu_list(&[]), "");
        // And it round-trips through the parser it mirrors.
        assert_eq!(parse_cpu_list("0-11,13,14").unwrap(), {
            let v: Vec<u16> = (0..=11).chain([13, 14]).collect();
            v
        });
    }

    /// The rig's topology: 18 CPUs, cpu12 isolated, VPP on 15-17.
    #[test]
    fn the_safe_set_excludes_vpp_and_isolated_cpus_but_not_cpu0() {
        let online: Vec<u16> = (0..18).collect();
        let safe = irq_safe_cpus(&online, &[12], &[15, 16, 17]);
        assert_eq!(format_cpu_list(&safe), "0-11,13-14");
    }

    /// The rig repro, as a unit: eth3's IRQ 602 on cpu15, VPP's main
    /// core. Moved, and the next read agrees it no longer conflicts.
    #[test]
    fn a_conflicting_irq_is_moved_and_the_conflict_clears() {
        let (net, proc_irq) = irq_fixture_smp("move", &[(602, "15")]);
        let vpp = [15, 16, 17];
        let before = nic_irq_conflicts(&net, &proc_irq, &["eth9".into()], &vpp).unwrap();
        assert_eq!(before.len(), 1);

        let online: Vec<u16> = (0..18).collect();
        let safe = irq_safe_cpus(&online, &[12], &vpp);
        let moved = move_irqs_off(&proc_irq, &before, &safe).unwrap();
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].was, "15");
        assert_eq!(
            moved[0].now, "1",
            "nothing of the old mask survived: one CPU, and not cpu0"
        );

        let after = nic_irq_conflicts(&net, &proc_irq, &["eth9".into()], &vpp).unwrap();
        assert!(after.is_empty(), "{after:?}");
    }

    /// Narrowing, not replacing: what survives of an operator's mask is
    /// kept, and only an empty survivor falls back to the whole set.
    #[test]
    fn an_existing_mask_is_narrowed_not_replaced() {
        let (net, proc_irq) = irq_fixture_smp("narrow", &[(700, "10-16"), (701, "15-17")]);
        let vpp = [15, 16, 17];
        let c = nic_irq_conflicts(&net, &proc_irq, &["eth9".into()], &vpp).unwrap();
        let online: Vec<u16> = (0..18).collect();
        let moved = move_irqs_off(&proc_irq, &c, &irq_safe_cpus(&online, &[12], &vpp)).unwrap();
        let by_irq = |i: u32| moved.iter().find(|m| m.irq == i).unwrap().now.clone();
        assert_eq!(
            by_irq(700),
            "10-11,13-14",
            "the operator's 10-16, minus VPP and isolated"
        );
        assert_eq!(
            by_irq(701),
            "1",
            "nothing survived, so one CPU from the rotation"
        );
    }

    /// The default spread's shape — one queue IRQ per core, several on
    /// VPP's — must not pile every moved IRQ onto one CPU, least of all
    /// cpu0: a controller handed a mask delivers to one target in it.
    #[test]
    fn emptied_masks_are_spread_across_the_safe_cpus_with_cpu0_last() {
        let (net, proc_irq) = irq_fixture_smp(
            "spread",
            &[(900, "15"), (901, "16"), (902, "17"), (903, "15")],
        );
        let vpp = [15, 16, 17];
        let c = nic_irq_conflicts(&net, &proc_irq, &["eth9".into()], &vpp).unwrap();
        let online: Vec<u16> = (0..18).collect();
        let moved = move_irqs_off(&proc_irq, &c, &irq_safe_cpus(&online, &[12], &vpp)).unwrap();
        let mut targets: Vec<String> = moved.iter().map(|m| m.now.clone()).collect();
        targets.sort();
        assert_eq!(targets, ["1", "2", "3", "4"], "four IRQs, four CPUs");

        // And cpu0 is used only once the rest of the rotation is.
        let (net, proc_irq) = irq_fixture_smp("spread0", &[(910, "2"), (911, "2"), (912, "2")]);
        let c = nic_irq_conflicts(&net, &proc_irq, &["eth9".into()], &[2]).unwrap();
        let moved = move_irqs_off(&proc_irq, &c, &[0, 1]).unwrap();
        let mut targets: Vec<String> = moved.iter().map(|m| m.now.clone()).collect();
        targets.sort();
        assert_eq!(targets, ["0", "1", "1"], "1 first, then 0, then around");
    }

    /// The post-adoption pass: an adopted VPP observed on cpu5, outside
    /// the derived 15-17. An IRQ there is moved off, and so is one the
    /// FIRST pass put on cpu5 because it only knew the derived map.
    #[test]
    fn clearing_against_observed_cores_moves_irqs_off_them_too() {
        let (net, proc_irq) = irq_fixture_smp("observed", &[(920, "5"), (921, "1-5")]);
        let cpu = net.parent().unwrap().join("cpu");
        std::fs::create_dir_all(&cpu).unwrap();
        std::fs::write(cpu.join("online"), "0-17\n").unwrap();
        std::fs::write(cpu.join("isolated"), "12\n").unwrap();
        let ifaces = ["eth9".to_string()];

        let first = clear_irqs_off(&net, &proc_irq, &cpu, &ifaces, &[15, 16, 17]).unwrap();
        assert!(first.moved.is_empty(), "nothing on the derived cores");

        let busy = [5, 15, 16, 17];
        let second = clear_irqs_off(&net, &proc_irq, &cpu, &ifaces, &busy).unwrap();
        assert!(second.still.is_empty(), "{:?}", second.still);
        let by_irq = |i: u32| {
            second
                .moved
                .iter()
                .find(|m| m.irq == i)
                .unwrap()
                .now
                .clone()
        };
        assert_eq!(by_irq(920), "1", "emptied, so one CPU from the rotation");
        assert_eq!(
            by_irq(921),
            "1-4",
            "narrowed: the observed core is taken out"
        );
        assert!(!second.safe.contains(&5));
    }

    /// Nowhere to put it is a refusal, not a silent no-op.
    #[test]
    fn an_empty_safe_set_is_an_error() {
        let (_, proc_irq) = irq_fixture_smp("empty", &[(800, "15")]);
        let c = vec![IrqConflict {
            iface: "eth9".into(),
            irq: 800,
            cpus: vec![15],
        }];
        let e = move_irqs_off(&proc_irq, &c, &[]).unwrap_err();
        assert!(e.contains("no CPU is left"), "{e}");
    }

    /// The incident shape (primary, 2026-08-13): queue IRQs pinned
    /// one-per-core, some landing exactly on the derived VPP cores.
    /// Those — and only those — are conflicts.
    #[test]
    fn irq_on_a_vpp_core_is_a_conflict_and_others_are_not() {
        let (net, proc_irq) = irq_fixture("overlap", &[(270, "11"), (261, "2"), (275, "16")]);
        let got = nic_irq_conflicts(&net, &proc_irq, &["eth9".into()], &[10, 11, 16]).unwrap();
        assert_eq!(
            got,
            vec![
                IrqConflict {
                    iface: "eth9".into(),
                    irq: 270,
                    cpus: vec![11]
                },
                IrqConflict {
                    iface: "eth9".into(),
                    irq: 275,
                    cpus: vec![16]
                },
            ]
        );
    }

    /// A wildcard mask whose EFFECTIVE affinity is off the VPP cores is
    /// not a conflict — the check asks where the IRQ fires, not where
    /// it is permitted to.
    #[test]
    fn effective_affinity_decides_not_the_permitted_mask() {
        let (net, proc_irq) = irq_fixture("effective", &[(300, "0")]);
        let got = nic_irq_conflicts(&net, &proc_irq, &["eth9".into()], &[10, 11]).unwrap();
        assert!(got.is_empty(), "{got:?}");
    }

    /// A port with no msi_irqs directory (fixture sysfs, non-MSI
    /// device) contributes nothing rather than failing the attach.
    #[test]
    fn a_port_without_msi_irqs_is_skipped() {
        let (net, proc_irq) = irq_fixture("absent", &[]);
        let got = nic_irq_conflicts(&net, &proc_irq, &["eth-nonexistent".into()], &[1, 2]).unwrap();
        assert!(got.is_empty());
    }

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
