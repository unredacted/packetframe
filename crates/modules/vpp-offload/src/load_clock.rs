//! Where a fresh load's time went: on CPU, or waiting for one, for the two
//! threads that move it.
//!
//! A fresh VPP's first load is VPP's main thread installing routes as fast
//! as this daemon's sending thread hands them over. On the lab, idle, the
//! main thread was the limit (about 33,000 routes/s). On the reference
//! deployment after the 6.0.17 upgrade (2026-11-12) the load ran at about
//! 8,000 routes/s with VPP's cores fenced, and nothing said which side was
//! short. This reads each thread's `/proc/<pid>/task/<tid>/schedstat`
//! (time on CPU and time runnable but waiting for one, in ns) when the load
//! starts and when it is done, and `fresh_hold_released` carries the
//! differences:
//!
//! - `vpp_main_cpu_ms` near `load_ms`: VPP's main thread was the limit;
//! - `sender_cpu_ms` near `load_ms`: this daemon's sender was;
//! - a large `*_wait_ms`: that thread was starved of CPU, not slow.

use std::path::{Path, PathBuf};

/// One thread's schedstat when the load began.
struct ThreadClock {
    path: PathBuf,
    on_cpu: u64,
    waiting: u64,
}

/// `(on_cpu_ns, waiting_ns)` from a schedstat file.
fn read_schedstat(path: &Path) -> Option<(u64, u64)> {
    let raw = std::fs::read_to_string(path).ok()?;
    let mut it = raw.split_whitespace();
    let on_cpu = it.next()?.parse().ok()?;
    let waiting = it.next()?.parse().ok()?;
    Some((on_cpu, waiting))
}

impl ThreadClock {
    fn start(proc_root: &Path, pid: i32, tid: i32) -> Option<Self> {
        let path = proc_root
            .join(pid.to_string())
            .join("task")
            .join(tid.to_string())
            .join("schedstat");
        let (on_cpu, waiting) = read_schedstat(&path)?;
        Some(Self {
            path,
            on_cpu,
            waiting,
        })
    }

    /// `(on_cpu_ms, waiting_ms)` since the start, or `None` if the thread
    /// is gone (VPP restarted mid-load).
    fn since(&self) -> Option<(u64, u64)> {
        let (on_cpu, waiting) = read_schedstat(&self.path)?;
        Some((
            on_cpu.saturating_sub(self.on_cpu) / 1_000_000,
            waiting.saturating_sub(self.waiting) / 1_000_000,
        ))
    }
}

/// Both threads' clocks, from the load's start.
pub struct LoadClock {
    vpp_main: Option<ThreadClock>,
    sender: Option<ThreadClock>,
}

/// What [`LoadClock::read`] found. `None` where a thread could not be read.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LoadCpu {
    pub vpp_main_cpu_ms: Option<u64>,
    pub vpp_main_wait_ms: Option<u64>,
    pub sender_cpu_ms: Option<u64>,
    pub sender_wait_ms: Option<u64>,
}

impl LoadClock {
    /// Start both clocks: VPP's main thread (its thread id is its pid) and
    /// the calling thread, which is the one that drains routes to VPP.
    pub fn start(vpp_pid: Option<i32>) -> Self {
        Self::start_at(Path::new("/proc"), vpp_pid, own_ids())
    }

    fn start_at(proc_root: &Path, vpp_pid: Option<i32>, own: Option<(i32, i32)>) -> Self {
        Self {
            vpp_main: vpp_pid.and_then(|p| ThreadClock::start(proc_root, p, p)),
            sender: own.and_then(|(pid, tid)| ThreadClock::start(proc_root, pid, tid)),
        }
    }

    pub fn read(&self) -> LoadCpu {
        let v = self.vpp_main.as_ref().and_then(ThreadClock::since);
        let s = self.sender.as_ref().and_then(ThreadClock::since);
        LoadCpu {
            vpp_main_cpu_ms: v.map(|x| x.0),
            vpp_main_wait_ms: v.map(|x| x.1),
            sender_cpu_ms: s.map(|x| x.0),
            sender_wait_ms: s.map(|x| x.1),
        }
    }
}

/// How long [`SenderWatch`] watches before it judges.
pub const SENDER_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// Waiting for a CPU below this in a window is not starvation, whatever
/// VPP's main thread did.
pub const SENDER_WAIT_FLOOR_MS: u64 = 200;

/// Whether the sender would load faster on VPP's main core.
///
/// Sharing that core, the sender waits for VPP's main thread's turns, so
/// the move costs it about the main thread's CPU time. It pays when the
/// sender already waits longer than that for a CPU on its own cores: over
/// a [`SENDER_WINDOW`], `sender_wait` above `vpp_main_cpu` (and above
/// [`SENDER_WAIT_FLOOR_MS`]). On the lab, idle, the sender waited 16 ms in
/// a 7.5 s load; with every other core in softirq it waited 32 s of 37 s
/// while VPP's main thread ran 7 s, and moved, the load took 14 s; with
/// CPU hogs at nice -15 it waited 4.1 s while VPP ran 5.8 s, and the load
/// took 8.5 s where it would have taken 12 s moved.
pub struct SenderWatch {
    clock: LoadClock,
    last: Option<(std::time::Instant, LoadCpu)>,
}

impl SenderWatch {
    /// Watch VPP's main thread (`vpp_pid`) and the calling thread.
    pub fn start(vpp_pid: Option<i32>) -> Self {
        Self {
            clock: LoadClock::start(vpp_pid),
            last: None,
        }
    }

    /// `true` when the window that ended at `now` shows the sender
    /// starved. At most one judgement per window.
    pub fn starved(&mut self, now: std::time::Instant) -> bool {
        let cpu = self.clock.read();
        judge(&mut self.last, now, cpu)
    }
}

fn judge(
    last: &mut Option<(std::time::Instant, LoadCpu)>,
    now: std::time::Instant,
    cpu: LoadCpu,
) -> bool {
    let Some((at, prev)) = *last else {
        *last = Some((now, cpu));
        return false;
    };
    if now.saturating_duration_since(at) < SENDER_WINDOW {
        return false;
    }
    *last = Some((now, cpu));
    let delta = |a: Option<u64>, b: Option<u64>| a.zip(b).map(|(a, b)| a.saturating_sub(b));
    match (
        delta(cpu.sender_wait_ms, prev.sender_wait_ms),
        delta(cpu.vpp_main_cpu_ms, prev.vpp_main_cpu_ms),
    ) {
        (Some(wait), Some(vpp)) => wait >= SENDER_WAIT_FLOOR_MS && wait > vpp,
        _ => false,
    }
}

/// This process's pid and the calling thread's tid.
#[cfg(target_os = "linux")]
fn own_ids() -> Option<(i32, i32)> {
    let pid = std::process::id() as i32;
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as i32;
    Some((pid, tid))
}

#[cfg(not(target_os = "linux"))]
fn own_ids() -> Option<(i32, i32)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(tag: &str) -> PathBuf {
        let mut base = std::env::temp_dir();
        base.push(format!("pf-loadclock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        base
    }

    fn schedstat(root: &Path, pid: i32, tid: i32, on_cpu: u64, waiting: u64) {
        let d = root
            .join(pid.to_string())
            .join("task")
            .join(tid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("schedstat"), format!("{on_cpu} {waiting} 42\n")).unwrap();
    }

    #[test]
    fn the_differences_since_the_start_are_reported_in_ms() {
        let root = fixture("delta");
        schedstat(&root, 700, 700, 5_000_000_000, 1_000_000_000);
        schedstat(&root, 10, 11, 2_000_000_000, 0);
        let c = LoadClock::start_at(&root, Some(700), Some((10, 11)));
        schedstat(&root, 700, 700, 7_500_000_000, 1_250_000_000);
        schedstat(&root, 10, 11, 2_400_000_000, 3_000_000_000);
        assert_eq!(
            c.read(),
            LoadCpu {
                vpp_main_cpu_ms: Some(2_500),
                vpp_main_wait_ms: Some(250),
                sender_cpu_ms: Some(400),
                sender_wait_ms: Some(3_000),
            }
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn reading(sender_wait: u64, vpp_cpu: u64) -> LoadCpu {
        LoadCpu {
            vpp_main_cpu_ms: Some(vpp_cpu),
            vpp_main_wait_ms: Some(0),
            sender_cpu_ms: Some(0),
            sender_wait_ms: Some(sender_wait),
        }
    }

    #[test]
    fn a_sender_waiting_longer_than_vpp_runs_is_starved_once_a_window_shows_it() {
        let t0 = std::time::Instant::now();
        let mut last = None;
        assert!(
            !judge(&mut last, t0, reading(0, 0)),
            "the first reading only starts the window"
        );
        let half = t0 + SENDER_WINDOW / 2;
        assert!(
            !judge(&mut last, half, reading(5_000, 100)),
            "not before the window is up"
        );
        // Softirq on every other core: 1.7 s waiting, VPP 0.4 s on CPU.
        assert!(judge(&mut last, t0 + SENDER_WINDOW, reading(1_700, 400)));
        // CPU hogs at nice -15: 1 s waiting, VPP 1.4 s on CPU.
        let t1 = t0 + SENDER_WINDOW * 2;
        assert!(!judge(&mut last, t1, reading(2_700, 1_800)));
        // Idle VPP and a sender that barely waits: under the floor.
        let t2 = t0 + SENDER_WINDOW * 3;
        assert!(!judge(&mut last, t2, reading(2_850, 1_800)));
    }

    #[test]
    fn a_thread_that_cannot_be_read_is_never_judged_starved() {
        let t0 = std::time::Instant::now();
        let mut last = None;
        let unknown = LoadCpu {
            vpp_main_cpu_ms: None,
            ..reading(0, 0)
        };
        judge(&mut last, t0, unknown);
        assert!(!judge(
            &mut last,
            t0 + SENDER_WINDOW,
            LoadCpu {
                vpp_main_cpu_ms: None,
                ..reading(9_000, 0)
            }
        ));
    }

    #[test]
    fn a_thread_that_is_gone_or_never_was_reads_as_unknown() {
        let root = fixture("gone");
        schedstat(&root, 700, 700, 1, 1);
        let c = LoadClock::start_at(&root, Some(700), None);
        std::fs::remove_dir_all(root.join("700")).unwrap();
        assert_eq!(c.read(), LoadCpu::default());
        let _ = std::fs::remove_dir_all(&root);
    }
}
