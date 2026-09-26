//! Where the daemon's own control-plane threads run.
//!
//! A process-wide slot holding the CPU set those threads are placed on,
//! and the ways a thread gets there. The set is DERIVED by the module
//! that knows the host's interrupt layout — vpp-offload's attach
//! (`cores::control_plane_cpus`), because moving NIC queue IRQs off
//! VPP's cores is what concentrates them on the CPUs that remain — and
//! lives here only because the threads it places belong to several
//! crates.
//!
//! - [`publish`] stores the set, then places every thread of this
//!   process that exists under a [`CONTROL_PLANE_THREADS`] name. It runs
//!   once vpp-offload's attach has succeeded, when every one of them is
//!   already running.
//! - [`join`] places the calling thread, if a set has been published —
//!   the fast-path runtime's `on_thread_start`, so a blocking-pool thread
//!   born after the publish is placed whichever thread spawned it.
//! - [`unplaced`] runs a closure with the calling thread widened back to
//!   the daemon's unplaced mask, for spawning a child process that must
//!   not inherit the placement.
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
//! that ends vpp-offload after its attach succeeded also ends the
//! process, so there is nothing a restore would ever run for.

/// Thread names placed by [`publish`], as the kernel keeps them —
/// `comm` is truncated to 15 bytes, which both 15-character names fit
/// exactly. The last two are spawned by the supervision loop.
pub const CONTROL_PLANE_THREADS: &[&str] = &[
    "packetframe-fib",
    "vpp-supervision",
    "pf-drift-scan",
    "pf-vpp-fdb",
];

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

/// The start time (field 22) of a `/proc/.../stat` line, or `None` when
/// the line does not parse. Anchored on the LAST `)`, since `comm` may
/// itself contain spaces and parentheses.
#[cfg(any(target_os = "linux", test))]
fn start_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // Fields after `comm` start at field 3 (state); starttime is 22.
    rest.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{start_ticks, Placed, CONTROL_PLANE_THREADS};
    use std::sync::Mutex;

    static SET: Mutex<Option<Vec<u16>>> = Mutex::new(None);

    const MASK: usize = std::mem::size_of::<libc::cpu_set_t>();

    /// One thread's placement.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Outcome {
        Placed,
        /// The thread's mask shares no CPU with the set; untouched.
        Disjoint,
    }

    fn get(tid: libc::pid_t) -> std::io::Result<libc::cpu_set_t> {
        let mut mask: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sched_getaffinity(tid, MASK, &mut mask) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(mask)
    }

    fn set(tid: libc::pid_t, mask: &libc::cpu_set_t) -> std::io::Result<()> {
        if unsafe { libc::sched_setaffinity(tid, MASK, mask) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// `mask` ∩ `cpus`, or `None` when that is empty.
    fn narrowed(mask: &libc::cpu_set_t, cpus: &[u16]) -> Option<libc::cpu_set_t> {
        let mut out: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for &cpu in cpus {
            let cpu = cpu as usize;
            // A CPU past a fixed cpu_set_t cannot be expressed; indexing
            // it would panic, and it cannot be in `mask` anyway.
            if cpu < libc::CPU_SETSIZE as usize && unsafe { libc::CPU_ISSET(cpu, mask) } {
                unsafe { libc::CPU_SET(cpu, &mut out) };
            }
        }
        (unsafe { libc::CPU_COUNT(&out) } > 0).then_some(out)
    }

    /// The calling thread narrowed to `cpus`.
    pub(super) fn place_self(cpus: &[u16]) -> std::io::Result<Outcome> {
        match narrowed(&get(0)?, cpus) {
            Some(m) => set(0, &m).map(|()| Outcome::Placed),
            None => Ok(Outcome::Disjoint),
        }
    }

    /// Start time of `tid` as a thread of THIS process, or `None` once
    /// it is not one: `/proc/self/task` lists only our own thread group.
    fn own_thread_started(tid: libc::pid_t) -> Option<u64> {
        let stat = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).ok()?;
        start_ticks(&stat)
    }

    /// Another thread of this process, identified by `(tid, started)`,
    /// narrowed to `cpus`.
    ///
    /// `sched_setaffinity` addresses tids host-wide, and a tid freed by
    /// an exiting thread can be handed to an unrelated process — which
    /// this daemon, being root, would then narrow for good (review
    /// finding). So identity is checked twice: immediately before the
    /// read-modify-write, and after it. The after-check is what makes
    /// the claim: a tid does not return to a thread that lost it, so if
    /// `(tid, started)` is still one of ours afterwards, it was ours
    /// throughout and the write landed on our thread. If it is not, the
    /// thread exited somewhere in the window — the likely reading is
    /// that the write failed or hit the thread just before its exit; a
    /// stranger would need the tid space to wrap within that window.
    /// It is reported as a failure rather than "undone", because the
    /// mask to restore would be a guess about a process we never saw.
    pub(super) fn place_thread(
        tid: libc::pid_t,
        started: u64,
        cpus: &[u16],
    ) -> std::io::Result<Outcome> {
        let ours = || own_thread_started(tid) == Some(started);
        if !ours() {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
        let Some(m) = narrowed(&get(tid)?, cpus) else {
            return Ok(Outcome::Disjoint);
        };
        let wrote = set(tid, &m);
        if !ours() {
            return Err(std::io::Error::other(
                "the thread exited while its affinity was being set; the tid may \
                 now name another process",
            ));
        }
        wrote.map(|()| Outcome::Placed)
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
            // Identity before name, so the name read belongs to the
            // thread `place_thread` then re-verifies.
            let Some(started) = own_thread_started(tid) else {
                continue; // exited between readdir and here
            };
            let Ok(comm) = std::fs::read_to_string(entry.path().join("comm")) else {
                continue;
            };
            let comm = comm.trim_end();
            if !CONTROL_PLANE_THREADS.contains(&comm) {
                continue;
            }
            match place_thread(tid, started, cpus) {
                Ok(Outcome::Placed) => out.placed += 1,
                Ok(Outcome::Disjoint) => out.disjoint += 1,
                // Exited before the write: nothing was touched.
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => {}
                Err(e) => out.failed.push(format!("tid {tid} ({comm}): {e}")),
            }
        }
        Ok(out)
    }

    pub fn join() {
        let Some(cpus) = SET.lock().unwrap_or_else(|e| e.into_inner()).clone() else {
            return;
        };
        match place_self(&cpus) {
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

    pub fn published() -> Option<Vec<u16>> {
        SET.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Puts the calling thread's mask back when dropped.
    struct Restore(libc::cpu_set_t);

    impl Drop for Restore {
        fn drop(&mut self) {
            if let Err(e) = set(0, &self.0) {
                tracing::warn!(error = %e, "could not restore this thread's affinity");
            }
        }
    }

    pub fn unplaced<T>(f: impl FnOnce() -> T) -> T {
        let leader = std::process::id() as libc::pid_t;
        let restore = match (get(0), get(leader)) {
            (Ok(own), Ok(wide)) => match set(0, &wide) {
                Ok(()) => Some(Restore(own)),
                Err(e) => {
                    tracing::warn!(error = %e, "could not widen this thread for a spawn");
                    None
                }
            },
            // Unreadable: the child inherits whatever this thread has.
            _ => None,
        };
        let out = f();
        drop(restore);
        out
    }
}

/// Store `cpus` as the control-plane set and place every existing
/// [`CONTROL_PLANE_THREADS`] thread of this process on it. `Err` only
/// when the thread list cannot be read at all; per-thread failures are
/// in the report.
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

/// The published set, if any.
#[cfg(target_os = "linux")]
pub fn published() -> Option<Vec<u16>> {
    imp::published()
}

/// Run `f` with the calling thread's affinity widened to the
/// thread-group leader's, then put it back — for spawning a child
/// process from a placed thread.
///
/// A child inherits its spawning thread's mask. From a placed thread
/// that would be a mask of one or two CPUs, carried into every thread
/// the child does not pin itself — and for VPP, whose placement
/// vpp-offload OBSERVES from exactly such narrow masks, it would read
/// the control-plane CPUs back as VPP's own at the next adoption. The
/// leader is the daemon's main thread, never placed, so its mask is what
/// every thread had before placement.
///
/// Done in the parent rather than in the child after `fork`: a
/// `pre_exec` hook moves std onto its fork/exec path, whose exec falls
/// back to `/bin/sh` on `ENOEXEC` — so an executable that is not a
/// program would be run as a shell script instead of failing to spawn
/// (review finding).
#[cfg(target_os = "linux")]
pub fn unplaced<T>(f: impl FnOnce() -> T) -> T {
    imp::unplaced(f)
}

#[cfg(not(target_os = "linux"))]
pub fn publish(_cpus: &[u16]) -> Result<Placed, String> {
    // Non-Linux has no thread affinity to set; nothing is placed.
    Ok(Placed::default())
}

#[cfg(not(target_os = "linux"))]
pub fn join() {}

#[cfg(not(target_os = "linux"))]
pub fn published() -> Option<Vec<u16>> {
    None
}

#[cfg(not(target_os = "linux"))]
pub fn unplaced<T>(f: impl FnOnce() -> T) -> T {
    f()
}

#[cfg(test)]
mod parse_tests {
    use super::start_ticks;

    /// Field 22, anchored on the last `)` so a `comm` with spaces or
    /// parentheses does not shift it.
    #[test]
    fn start_ticks_reads_field_22_past_any_comm() {
        let tail = "S 1 42 42 0 -1 4194560 12 0 0 0 1 2 0 0 20 0 3 0 987654 1 2";
        assert_eq!(
            start_ticks(&format!("42 (pf-drift-scan) {tail}")),
            Some(987_654)
        );
        assert_eq!(start_ticks(&format!("42 (a (b) c) {tail}")), Some(987_654));
        assert_eq!(start_ticks("42 (x) S 1 2"), None, "truncated");
        assert_eq!(start_ticks("no parens"), None);
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::imp::{place_self, place_thread, Outcome};
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

    fn started(tid: libc::pid_t) -> u64 {
        start_ticks(&std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")).unwrap())
            .unwrap()
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

    /// A parked thread, released when the returned sender drops.
    fn parked(
        name: &str,
    ) -> (
        libc::pid_t,
        std::sync::mpsc::Sender<()>,
        std::thread::JoinHandle<()>,
    ) {
        let (tid_tx, tid_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let h = std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                tid_tx.send(gettid()).unwrap();
                let _ = done_rx.recv();
            })
            .unwrap();
        (tid_rx.recv().unwrap(), done_tx, h)
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
            assert_eq!(place_self(&[a, past]).unwrap(), Outcome::Placed);
            assert_eq!(mask_of(0), vec![a as usize], "narrowed to the overlap");

            assert_eq!(place_self(&[b]).unwrap(), Outcome::Disjoint);
            assert_eq!(mask_of(0), vec![a as usize], "never widened onto b");
        });
    }

    /// A thread is only written while it is still the one that was
    /// named: a stale start time — a tid that has been reused — is
    /// refused without touching whatever holds it now, and a thread
    /// that has exited is refused too.
    #[test]
    fn a_thread_whose_identity_changed_is_not_touched() {
        let allowed = mask_of(0);
        if allowed.len() < 2 {
            return;
        }
        let a = allowed[0] as u16;
        let (tid, done, h) = parked("pf-test-ident");
        let before = mask_of(tid);
        let e = place_thread(tid, started(tid) ^ 1, &[a]).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ESRCH), "{e}");
        assert_eq!(mask_of(tid), before, "a stale identity writes nothing");

        let real = started(tid);
        assert_eq!(place_thread(tid, real, &[a]).unwrap(), Outcome::Placed);
        assert_eq!(mask_of(tid), vec![a as usize]);

        drop(done);
        h.join().unwrap();
        // `join` returns on the exit futex wake, which can precede the
        // kernel releasing the task: for a moment its /proc entry, and
        // its start time, are still there. Wait (bounded) for it to go
        // before asserting the exited-thread refusal.
        let gone = std::path::PathBuf::from(format!("/proc/self/task/{tid}"));
        for _ in 0..200 {
            if !gone.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!gone.exists(), "task {tid} never left /proc");
        let e = place_thread(tid, real, &[a]).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ESRCH), "{e}");
    }

    /// `publish` places the named threads that already exist and no
    /// others; `join` places a thread that starts after it.
    #[test]
    fn publish_places_named_threads_and_join_places_later_ones() {
        let allowed = mask_of(0);
        if allowed.len() < 2 {
            return;
        }
        let a = allowed[0] as u16;

        let (named_tid, named_done, named) = parked("packetframe-fib");
        let (other_tid, other_done, other) = parked("pf-test-other");

        let report = publish(&[a]).expect("publish");
        assert!(report.placed >= 1, "{report:?}");
        assert_eq!(published(), Some(vec![a]));
        assert_eq!(mask_of(named_tid), vec![a as usize]);
        assert_eq!(
            mask_of(other_tid),
            allowed,
            "an unnamed thread is untouched"
        );
        drop((named_done, other_done));
        named.join().unwrap();
        other.join().unwrap();

        let joined = on_thread("pf-test-join", move || {
            join();
            mask_of(0)
        });
        assert_eq!(joined, vec![a as usize]);
    }

    /// `unplaced` widens the calling thread to the leader's mask for the
    /// closure and restores it afterwards.
    #[test]
    fn unplaced_widens_for_the_closure_and_restores_after() {
        let leader = mask_of(std::process::id() as libc::pid_t);
        if leader.len() < 2 {
            return;
        }
        let a = leader[0] as u16;
        on_thread("pf-test-unplace", move || {
            assert_eq!(place_self(&[a]).unwrap(), Outcome::Placed);
            let inside = unplaced(|| mask_of(0));
            assert_eq!(inside, leader, "widened to the leader's mask");
            assert_eq!(mask_of(0), vec![a as usize], "restored after");
        });
    }
}
