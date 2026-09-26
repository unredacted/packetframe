//! Where the daemon's own control-plane threads run.
//!
//! A process-wide slot holding the CPU set those threads are placed on,
//! and the two ways a thread gets there. The set is DERIVED by the
//! module that knows the host's interrupt layout — vpp-offload's attach
//! (`cores::control_plane_cpus`), because moving NIC queue IRQs off
//! VPP's cores is what concentrates them on the CPUs that remain — and
//! lives here only because the threads it places belong to several
//! crates.
//!
//! - [`publish`] stores the set, then places every thread that already
//!   exists under a [`CONTROL_PLANE_THREADS`] name. The fast-path
//!   runtime is up long before vpp-offload attaches, so its workers are
//!   found by name rather than waiting for a restart.
//! - [`join`] places the calling thread, if a set has been published.
//!   Called at the top of each control-plane thread and from the
//!   fast-path runtime's `on_thread_start`, so a blocking-pool thread
//!   born after the publish is placed whichever thread spawned it.
//!
//! **Placement intersects, never rebuilds**: a thread's new mask is its
//! current mask ∩ the set, for the reason `restrict_daemon_from` in
//! vpp-offload subtracts — an operator's `CPUAffinity=` survives, and
//! the daemon can never be moved onto a CPU it was not already allowed.
//! A thread whose intersection is EMPTY is left alone: an operator who
//! pinned the daemon away from the set chose that, and the setting is
//! also the opt-out.
//!
//! One-way, like `restrict_daemon_from` and for its reason: every path
//! that ends vpp-offload also ends the process, so there is nothing a
//! restore would ever run for.

/// Thread names placed by [`publish`]. As the kernel keeps them — `comm`
/// is truncated to 15 bytes, which both 15-character names fit exactly.
/// Threads these spawn inherit the placement (the supervision loop's
/// FDB mirror, for one), so they need no entry.
pub const CONTROL_PLANE_THREADS: &[&str] = &["packetframe-fib", "vpp-supervision", "pf-drift-scan"];

/// What [`publish`] did to the threads that already existed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Placed {
    /// Threads whose mask now lies within the set.
    pub placed: usize,
    /// Threads left alone because their mask shares no CPU with the set.
    pub disjoint: usize,
    /// Threads whose mask could not be changed, with why.
    pub failed: Vec<String>,
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Placed, CONTROL_PLANE_THREADS};
    use std::sync::Mutex;

    static SET: Mutex<Option<Vec<u16>>> = Mutex::new(None);

    /// One thread's placement.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Outcome {
        Placed,
        /// The thread's mask shares no CPU with the set; untouched.
        Disjoint,
    }

    /// `tid`'s mask narrowed to `cpus` (0 = the calling thread).
    pub(super) fn place(tid: libc::pid_t, cpus: &[u16]) -> std::io::Result<Outcome> {
        let size = std::mem::size_of::<libc::cpu_set_t>();
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sched_getaffinity(tid, size, &mut mask) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut narrowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for &cpu in cpus {
            let cpu = cpu as usize;
            // A CPU past a fixed cpu_set_t cannot be expressed; indexing
            // it would panic, and it cannot be in `mask` anyway.
            if cpu < libc::CPU_SETSIZE as usize && unsafe { libc::CPU_ISSET(cpu, &mask) } {
                unsafe { libc::CPU_SET(cpu, &mut narrowed) };
            }
        }
        if unsafe { libc::CPU_COUNT(&narrowed) } == 0 {
            return Ok(Outcome::Disjoint);
        }
        if unsafe { libc::sched_setaffinity(tid, size, &narrowed) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Outcome::Placed)
    }

    pub fn publish(cpus: &[u16]) -> Result<Placed, String> {
        // Stored BEFORE the walk: a thread starting concurrently either
        // sees the set in `join`, or already exists when the walk reads
        // the task directory. Placing one twice is idempotent.
        *SET.lock().unwrap_or_else(|e| e.into_inner()) = Some(cpus.to_vec());
        let tasks =
            std::fs::read_dir("/proc/self/task").map_err(|e| format!("/proc/self/task: {e}"))?;
        let mut out = Placed::default();
        for entry in tasks.flatten() {
            let Some(tid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<libc::pid_t>().ok())
            else {
                continue;
            };
            let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) else {
                continue; // exited between readdir and here
            };
            if !CONTROL_PLANE_THREADS.contains(&comm.trim_end()) {
                continue;
            }
            match place(tid, cpus) {
                Ok(Outcome::Placed) => out.placed += 1,
                Ok(Outcome::Disjoint) => out.disjoint += 1,
                // Exited between the name read and the syscall.
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => out
                    .failed
                    .push(format!("tid {tid} ({}): {e}", comm.trim_end())),
            }
        }
        Ok(out)
    }

    pub fn join() {
        let Some(cpus) = SET.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
            return;
        };
        match place(0, &cpus) {
            Ok(Outcome::Placed) => {}
            Ok(Outcome::Disjoint) => tracing::debug!(
                "this thread's affinity shares no CPU with the control-plane set; left alone"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                "could not place this thread on the control-plane CPUs"
            ),
        }
    }

    pub fn unplaced_mask() -> Option<libc::cpu_set_t> {
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let leader = std::process::id() as libc::pid_t;
        let rc = unsafe {
            libc::sched_getaffinity(leader, std::mem::size_of::<libc::cpu_set_t>(), &mut mask)
        };
        (rc == 0).then_some(mask)
    }
}

/// Store `cpus` as the control-plane set and place every existing
/// [`CONTROL_PLANE_THREADS`] thread on it. `Err` only when the thread
/// list cannot be read at all; per-thread failures are in the report.
#[cfg(target_os = "linux")]
pub fn publish(cpus: &[u16]) -> Result<Placed, String> {
    imp::publish(cpus)
}

/// Place the calling thread on the published set. A no-op before
/// anything is published, and on failure it warns rather than failing
/// the thread: placement is an optimisation, never a precondition.
#[cfg(target_os = "linux")]
pub fn join() {
    imp::join()
}

/// The thread-group leader's mask, for a child process spawned from a
/// placed thread to start from instead of inheriting the placement.
///
/// The leader is the daemon's main thread, which is never placed, so
/// its mask is what every thread had before [`join`]. A child that
/// inherited the placement instead would carry a mask of one or two
/// CPUs into every thread it does not pin itself — and for VPP, whose
/// placement vpp-offload OBSERVES from exactly such narrow masks, that
/// would read the control-plane CPUs back as VPP's own at the next
/// adoption.
#[cfg(target_os = "linux")]
pub fn unplaced_mask() -> Option<libc::cpu_set_t> {
    imp::unplaced_mask()
}

#[cfg(not(target_os = "linux"))]
pub fn publish(_cpus: &[u16]) -> Result<Placed, String> {
    // Non-Linux has no thread affinity to set; nothing is placed.
    Ok(Placed::default())
}

#[cfg(not(target_os = "linux"))]
pub fn join() {}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::imp::{place, Outcome};
    use super::*;

    fn mask_of(tid: libc::pid_t) -> Vec<usize> {
        let mut m: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc =
            unsafe { libc::sched_getaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &mut m) };
        assert_eq!(rc, 0);
        (0..libc::CPU_SETSIZE as usize)
            .filter(|&c| unsafe { libc::CPU_ISSET(c, &m) })
            .collect()
    }

    fn gettid() -> libc::pid_t {
        unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t }
    }

    /// Runs `f` on a fresh thread named `name`, so the process-wide
    /// effects stay off the harness's threads.
    fn on_thread<T: Send + 'static>(name: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .name(name.into())
            .spawn(f)
            .expect("spawn")
            .join()
            .expect("join")
    }

    /// Narrowing keeps only what the thread was already allowed, and a
    /// set it shares nothing with leaves it untouched rather than
    /// emptied or widened.
    #[test]
    fn placement_intersects_and_leaves_a_disjoint_thread_alone() {
        let allowed = mask_of(0);
        if allowed.len() < 2 {
            return; // cannot express "narrower than allowed" here
        }
        let (a, b) = (allowed[0] as u16, allowed[1] as u16);
        on_thread("pf-test-place", move || {
            let past = libc::CPU_SETSIZE as u16 + 7;
            assert_eq!(place(0, &[a, past]).unwrap(), Outcome::Placed);
            assert_eq!(mask_of(0), vec![a as usize], "narrowed to the overlap");

            assert_eq!(place(0, &[b]).unwrap(), Outcome::Disjoint);
            assert_eq!(mask_of(0), vec![a as usize], "never widened onto b");
        });
    }

    /// `publish` places the named threads that already exist and no
    /// others; `join` places a thread that starts after it.
    #[test]
    fn publish_places_named_threads_and_join_places_later_ones() {
        use std::sync::mpsc::channel;

        let allowed = mask_of(0);
        if allowed.len() < 2 {
            return;
        }
        let a = allowed[0] as u16;

        let (tid_tx, tid_rx) = channel();
        let (done_tx, done_rx) = channel::<()>();
        let named = std::thread::Builder::new()
            .name("packetframe-fib".into())
            .spawn(move || {
                tid_tx.send(gettid()).unwrap();
                done_rx.recv().unwrap();
            })
            .unwrap();
        let named_tid = tid_rx.recv().unwrap();
        let (other_tx, other_rx) = channel();
        let (other_done_tx, other_done_rx) = channel::<()>();
        let other = std::thread::Builder::new()
            .name("pf-test-other".into())
            .spawn(move || {
                other_tx.send(gettid()).unwrap();
                other_done_rx.recv().unwrap();
            })
            .unwrap();
        let other_tid = other_rx.recv().unwrap();

        let report = publish(&[a]).expect("publish");
        assert!(report.placed >= 1, "{report:?}");
        assert_eq!(mask_of(named_tid), vec![a as usize]);
        assert_eq!(
            mask_of(other_tid),
            allowed,
            "an unnamed thread is untouched"
        );
        done_tx.send(()).unwrap();
        other_done_tx.send(()).unwrap();
        named.join().unwrap();
        other.join().unwrap();

        let joined = on_thread("pf-test-join", move || {
            join();
            mask_of(0)
        });
        assert_eq!(joined, vec![a as usize]);
    }
}
