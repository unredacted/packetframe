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
