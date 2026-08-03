//! Process handle for VPP: spawn, adopt, signal, exit-notify — all via
//! pidfd (SPEC.md §4.8; phase-4 plan, slice 4).
//!
//! **Why pidfd and not SIGCHLD.** Adoption is a first-class case here:
//! packetframe restarts while VPP keeps forwarding, and the surviving
//! VPP is *not* our child — it was reparented to init the moment its
//! original parent died. `SIGCHLD` and `waitpid()` are therefore
//! structurally unavailable for exactly the process we most need to
//! watch. A pidfd works the same for a child we just forked and for a
//! stranger we adopted, which collapses two supervision paths into one.
//!
//! **Why a pidfd rather than the bare pid.** Signalling a pid races
//! PID reuse: between deciding "pid 4242 is wedged" and `kill(4242)`,
//! the real VPP can exit and the kernel can hand 4242 to something
//! else — and we send it SIGKILL as root. A pidfd is bound to one
//! process for its whole lifetime, so `pidfd_send_signal` cannot be
//! misdelivered no matter how long the fd sits idle.
//!
//! The state file's `(vpp_pid, vpp_start_ticks)` pair (slice 2) is the
//! bootstrap identity: it survives our own death, where an fd cannot.
//! [`VppProcess::adopt`] turns that pair back into a pidfd and refuses
//! if the pid now belongs to someone else.

use std::io;
use std::path::Path;
use std::time::Duration;

/// Field 22 of `/proc/<pid>/stat` — process start time in clock ticks
/// since boot. Paired with the pid it is a stable process identity
/// across a PID-space wrap.
///
/// Parsing this is fiddlier than it looks, which is why it is a free
/// function with its own tests: `comm` (field 2) is the executable
/// name in parentheses, and it may contain **both spaces and closing
/// parens** — a binary called `vpp (test)` is legal and would break
/// any `split_whitespace().nth(21)`. The only robust anchor is the
/// LAST `)` in the line; every field after it is whitespace-free.
///
/// Returns `None` on any shape we do not recognise rather than
/// guessing, because a wrong start-time makes adoption either falsely
/// refuse (harmless) or falsely accept (SIGKILL to a stranger).
pub fn parse_start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    // Fields after `comm` begin at field 3 (state), so field 22
    // (starttime) sits at index 19 of this tail.
    stat[close + 1..].split_whitespace().nth(19)?.parse().ok()
}

/// How a process handle was obtained. Adopted processes cannot be
/// reaped (they are init's children, not ours), so their exit status
/// is unavailable — the supervisor's `ProcessExited { status }` is an
/// `Option` for exactly this reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Spawned,
    Adopted,
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{parse_start_ticks, Origin};
    use std::fs;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// How long to wait for a process to die after SIGKILL before
    /// declaring it stuck. Long enough that ordinary scheduling delay
    /// never trips it, short enough that detach fails loudly instead
    /// of hanging.
    const SIGKILL_BUDGET: Duration = Duration::from_secs(2);

    /// `pidfd_open(2)`. Present since 5.3; the fleet is 5.15.
    fn pidfd_open(pid: i32) -> io::Result<OwnedFd> {
        // SAFETY: pidfd_open takes (pid_t, unsigned int) and returns a
        // new fd or -1. No pointers are involved.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the syscall returned a fresh, owned fd.
        Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
    }

    /// `pidfd_send_signal(2)`. Present since 5.1.
    fn pidfd_send_signal(fd: RawFd, sig: i32) -> io::Result<()> {
        // SAFETY: passing a NULL siginfo asks the kernel to synthesise
        // one, which is the documented equivalent of kill(2).
        let r = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd,
                sig,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn read_start_ticks(pid: i32) -> io::Result<u64> {
        let raw = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        parse_start_ticks(&raw).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("/proc/{pid}/stat: no parsable starttime field"),
            )
        })
    }

    /// A live VPP process we are supervising.
    #[derive(Debug)]
    pub struct VppProcess {
        pid: i32,
        start_ticks: u64,
        pidfd: OwnedFd,
        origin: Origin,
        /// Present only when we forked it. Kept so the zombie is
        /// reaped and the exit status recovered; an adopted process
        /// has neither.
        child: Option<Child>,
    }

    impl VppProcess {
        /// Fork/exec VPP against a rendered startup.conf.
        ///
        /// The conf sets `nodaemon`, so this child *is* the dataplane
        /// rather than a launcher that exits — without that, the pidfd
        /// would signal "exited" immediately and the supervisor would
        /// restart-loop a perfectly healthy VPP.
        pub fn spawn(binary: &Path, conf: &Path) -> io::Result<Self> {
            let child = Command::new(binary)
                .arg("-c")
                .arg(conf)
                // VPP's own `log` stanza owns its output. Inheriting
                // our stdout would interleave dataplane chatter into
                // packetframe's structured log.
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            let pid = child.id() as i32;

            // Open the pidfd before anything else can reap the child.
            // `child` is still owned here, so even if VPP died during
            // exec it is a zombie, not gone, and pidfd_open succeeds.
            let pidfd = pidfd_open(pid)?;
            let start_ticks = read_start_ticks(pid)?;
            Ok(Self {
                pid,
                start_ticks,
                pidfd,
                origin: Origin::Spawned,
                child: Some(child),
            })
        }

        /// Re-acquire a VPP that outlived us, from the state file's
        /// `(pid, start_ticks)` pair.
        ///
        /// `Ok(None)` means "nothing of ours is running" — either the
        /// pid is gone, or it now belongs to an unrelated process.
        /// Both are ordinary fresh-attach outcomes, not errors.
        ///
        /// Order matters: **open the pidfd first, verify identity
        /// second.** The pidfd pins one process for its lifetime, so
        /// once it is open no later reuse can change what we hold; the
        /// start-time check then rules out a reuse that happened
        /// *before* the open. Verifying first and opening second would
        /// leave exactly the window this is meant to close.
        pub fn adopt(pid: i32, start_ticks: u64) -> io::Result<Option<Self>> {
            let pidfd = match pidfd_open(pid) {
                Ok(fd) => fd,
                // No such process: the normal "VPP died while we were
                // down" case.
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
                Err(e) => return Err(e),
            };
            match read_start_ticks(pid) {
                Ok(actual) if actual == start_ticks => Ok(Some(Self {
                    pid,
                    start_ticks,
                    pidfd,
                    origin: Origin::Adopted,
                    child: None,
                })),
                // Recycled pid, or it exited between the two calls.
                // Refusing costs one restart; accepting would aim
                // SIGKILL at a stranger.
                Ok(_) => Ok(None),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e),
            }
        }

        pub fn pid(&self) -> i32 {
            self.pid
        }

        pub fn start_ticks(&self) -> u64 {
            self.start_ticks
        }

        pub fn origin(&self) -> Origin {
            self.origin
        }

        /// The pidfd, for a caller that wants to park it in its own
        /// epoll set alongside the API socket rather than call
        /// [`Self::poll_exit`].
        pub fn as_raw_fd(&self) -> RawFd {
            self.pidfd.as_raw_fd()
        }

        /// Has it exited? `Ok(None)` = still running.
        ///
        /// A pidfd becomes readable exactly once, when the process
        /// terminates, so this is level-triggered and safe to call
        /// repeatedly.
        pub fn poll_exit(&mut self, timeout: Duration) -> io::Result<Option<Option<i32>>> {
            let mut pfd = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
            // SAFETY: one initialised pollfd, count matches.
            let r = unsafe { libc::poll(&mut pfd, 1, ms) };
            if r < 0 {
                let e = io::Error::last_os_error();
                // A signal during the wait is not an exit.
                if e.kind() == io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(e);
            }
            if r == 0 {
                return Ok(None);
            }
            Ok(Some(self.reap()))
        }

        /// Collect the exit status if we can. Adopted processes return
        /// `None`: init reaped them, and no status is recoverable.
        fn reap(&mut self) -> Option<i32> {
            let child = self.child.as_mut()?;
            match child.wait() {
                Ok(status) => status.code(),
                Err(_) => None,
            }
        }

        /// Send a signal, race-free.
        ///
        /// Signalling a dead-but-not-yet-noticed process is `ESRCH`,
        /// which is success for every caller here: the goal is "not
        /// running", and it is not running.
        pub fn signal(&self, sig: i32) -> io::Result<()> {
            match pidfd_send_signal(self.pidfd.as_raw_fd(), sig) {
                Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(()),
                other => other,
            }
        }

        /// SIGTERM, wait up to `grace`, then SIGKILL and wait again.
        ///
        /// This is the teardown half of the `<1 s` detach contract, so
        /// `grace` is a budget the caller sets rather than a constant
        /// here — the module's own deadline covers N VFs plus this.
        pub fn terminate(&mut self, grace: Duration) -> io::Result<Option<i32>> {
            self.signal(libc::SIGTERM)?;
            if let Some(status) = self.wait_until(grace)? {
                return Ok(status);
            }
            self.signal(libc::SIGKILL)?;
            // SIGKILL cannot be refused, but it also cannot interrupt an
            // uninterruptible sleep: a process parked in a driver call
            // stays alive until that call returns. That is not
            // hypothetical here — VPP sits on VFIO and DMA, which is
            // exactly where D-state waits come from. So bound this and
            // report honestly; an unbounded loop would hang detach
            // forever rather than miss its deadline out loud.
            match self.wait_until(SIGKILL_BUDGET)? {
                Some(status) => Ok(status),
                None => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "pid {} still alive {:?} after SIGKILL (uninterruptible?); \
                         VF/hugepage teardown must not proceed while it may still DMA",
                        self.pid, SIGKILL_BUDGET
                    ),
                )),
            }
        }

        /// Wait for exit within `budget`. `Ok(None)` = still running
        /// when the budget ran out.
        fn wait_until(&mut self, budget: Duration) -> io::Result<Option<Option<i32>>> {
            let deadline = Instant::now() + budget;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if let Some(status) = self.poll_exit(left)? {
                    return Ok(Some(status));
                }
                if left.is_zero() {
                    return Ok(None);
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    //! Non-Linux stub per the platform-gate policy: the macOS dev loop
    //! must compile and test, and every entry point fails loudly as
    //! unsupported rather than pretending to supervise something.
    //!
    //! `ErrorKind::Unsupported` rather than a literal ENOSYS because
    //! this crate scopes its `libc` dependency to Linux targets, and
    //! pulling libc onto every platform for one constant is a worse
    //! trade than using the portable spelling of the same idea.
    use super::Origin;
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    fn unsupported<T>() -> io::Result<T> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "VPP process supervision is Linux-only (pidfd)",
        ))
    }

    #[derive(Debug)]
    pub struct VppProcess {
        _priv: (),
    }

    impl VppProcess {
        pub fn spawn(_binary: &Path, _conf: &Path) -> io::Result<Self> {
            unsupported()
        }
        pub fn adopt(_pid: i32, _start_ticks: u64) -> io::Result<Option<Self>> {
            unsupported()
        }
        pub fn pid(&self) -> i32 {
            0
        }
        pub fn start_ticks(&self) -> u64 {
            0
        }
        pub fn origin(&self) -> Origin {
            Origin::Spawned
        }
        pub fn as_raw_fd(&self) -> std::os::fd::RawFd {
            -1
        }
        pub fn poll_exit(&mut self, _timeout: Duration) -> io::Result<Option<Option<i32>>> {
            unsupported()
        }
        pub fn signal(&self, _sig: i32) -> io::Result<()> {
            unsupported()
        }
        pub fn terminate(&mut self, _grace: Duration) -> io::Result<Option<i32>> {
            unsupported()
        }
    }
}

pub use imp::VppProcess;

/// Convenience for the supervisor's start path: adopt if the state
/// file still describes a live VPP, otherwise spawn a fresh one.
///
/// Returns the handle and whether it was adopted, because the two
/// drive different supervisor events — adoption must NOT unsteer, and
/// that distinction is the difference between a seamless packetframe
/// restart and a self-inflicted blackhole.
pub fn adopt_or_spawn(
    prior: Option<(i32, u64)>,
    binary: &Path,
    conf: &Path,
) -> io::Result<(VppProcess, bool)> {
    if let Some((pid, ticks)) = prior {
        if let Some(p) = VppProcess::adopt(pid, ticks)? {
            return Ok((p, true));
        }
    }
    Ok((VppProcess::spawn(binary, conf)?, false))
}

/// Best-effort teardown used on paths that must not fail, such as
/// detach unwinding: log-and-continue rather than propagate.
pub fn terminate_quietly(p: &mut VppProcess, grace: Duration) {
    if let Err(e) = p.terminate(grace) {
        tracing::warn!(pid = p.pid(), error = %e, "VPP termination did not complete cleanly");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ordinary shape.
    #[test]
    fn start_ticks_is_field_22() {
        let stat = "4242 (vpp) S 1 4242 4242 0 -1 4194560 1234 0 0 0 10 20 0 0 20 0 8 0 987654 \
                    123456789 456 18446744073709551615";
        assert_eq!(parse_start_ticks(stat), Some(987_654));
    }

    /// `comm` with a space in it. A `split_whitespace().nth(21)` parse
    /// reads one field short here and silently returns the wrong
    /// number — which would make adoption compare a bogus identity.
    #[test]
    fn a_comm_containing_a_space_does_not_shift_the_fields() {
        let stat = "4242 (vpp worker) S 1 4242 4242 0 -1 4194560 1234 0 0 0 10 20 0 0 20 0 8 0 \
                    987654 123456789 456";
        assert_eq!(parse_start_ticks(stat), Some(987_654));
    }

    /// `comm` containing its own parens: the anchor has to be the LAST
    /// `)`, not the first.
    #[test]
    fn a_comm_containing_parens_anchors_on_the_last_one() {
        let stat = "4242 (vpp (test)) S 1 4242 4242 0 -1 4194560 1234 0 0 0 10 20 0 0 20 0 8 0 \
                    987654 123456789 456";
        assert_eq!(parse_start_ticks(stat), Some(987_654));
    }

    /// Truncated or foreign input must not produce a number. A wrong
    /// start-time that happens to parse is the one failure mode that
    /// could aim SIGKILL at an unrelated process.
    #[test]
    fn unrecognisable_input_returns_none_rather_than_guessing() {
        assert_eq!(parse_start_ticks(""), None);
        assert_eq!(parse_start_ticks("4242 (vpp) S 1 2 3"), None);
        assert_eq!(parse_start_ticks("no parens here at all"), None);
        // Field 22 present but not a number.
        let bad = "4242 (vpp) S 1 4242 4242 0 -1 4194560 1234 0 0 0 10 20 0 0 20 0 8 0 xxx 1 2";
        assert_eq!(parse_start_ticks(bad), None);
    }

    /// Real kernels emit a trailing newline.
    #[test]
    fn a_trailing_newline_is_tolerated() {
        let stat = "4242 (vpp) S 1 4242 4242 0 -1 4194560 1234 0 0 0 10 20 0 0 20 0 8 0 987654 \
                    123456789 456\n";
        assert_eq!(parse_start_ticks(stat), Some(987_654));
    }
}
