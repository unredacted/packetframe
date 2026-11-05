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
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The directory under `state-dir` that holds what each VPP this daemon
/// spawns leaves behind: its stdout and stderr, one file per start, and
/// any core it dumps.
///
/// Until 2026-11-05 VPP's stdout and stderr went to `/dev/null`, so its
/// crash backtrace reached only syslog (a RAM journal on the reference
/// gateway, rotated within minutes under boot load), and no core could
/// be written. A fresh VPP died twice with SIGABRT while syncing under
/// load and left nothing to say why. VPP prints a panic, an assertion
/// or an allocation failure to stderr before it aborts, its fatal-signal
/// handler's `received signal` line and backtrace reach stderr too (VPP
/// opens syslog with `LOG_PERROR`), and `state-dir` survives a reboot.
///
/// It is also VPP's runtime directory (`unix { runtime-dir … }`), because
/// VPP `chdir`s into that unconditionally at start: a relative
/// `core_pattern` drops a core in the process's working directory, which
/// is therefore here and not `/run/vpp`, a tmpfs gone at the next boot.
/// Only a directory [`open_diagnostics_dir`] trusts is used for either.
pub const DIAG_DIR_NAME: &str = "vpp-diag";

/// Output files kept, the newest start's included; older ones are
/// removed after each successful spawn. A start's file is small (VPP is
/// quiet on stderr unless something is wrong), so this is a few starts of
/// history, enough to hold the crash and the start before it.
pub const DIAG_LOGS_KEPT: usize = 5;

/// Core files kept. With the hugetlb bits cleared from VPP's
/// `coredump_filter` ([`CORE_FILTER`]) a core is hundreds of megabytes,
/// not gigabytes, and still holds every thread's stack.
pub const DIAG_CORES_KEPT: usize = 2;

/// What a spawned VPP's core may hold, written to its
/// `/proc/<pid>/coredump_filter` (proc(5)): anonymous private and shared
/// memory and the ELF headers. Not file-backed memory, and not hugetlb,
/// private or shared: the kernel's default (0x33) includes private
/// hugetlb, and VPP's heap and buffers live on hugepages, which would make
/// a core the size of the heap. Leaving `full-coredump` out of the
/// rendered stanza is not enough on its own.
pub const CORE_FILTER: &str = "0x13";

/// The entries of a diagnostics directory a pruning removes: output files
/// beyond the newest [`DIAG_LOGS_KEPT`], and cores beyond the newest
/// [`DIAG_CORES_KEPT`]. Output files are `vpp-<unix seconds>.log`,
/// ordered by name; cores are anything named `core*`, ordered by
/// modification time, whatever the kernel's `core_pattern` appended.
/// Anything else is left alone: VPP's own runtime files live here too.
pub fn stale_diagnostics(entries: &[(String, std::time::SystemTime)]) -> Vec<String> {
    let mut logs: Vec<&String> = entries
        .iter()
        .map(|(n, _)| n)
        .filter(|n| n.starts_with("vpp-") && n.ends_with(".log"))
        .collect();
    logs.sort_unstable_by(|a, b| b.cmp(a));
    let mut cores: Vec<&(String, std::time::SystemTime)> = entries
        .iter()
        .filter(|(n, _)| n.starts_with("core"))
        .collect();
    cores.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));
    logs.into_iter()
        .skip(DIAG_LOGS_KEPT)
        .chain(cores.into_iter().skip(DIAG_CORES_KEPT).map(|(n, _)| n))
        .cloned()
        .collect()
}

/// The fatal signal VPP's own handler logged, from its output: the last
/// `received signal <NAME>` line. VPP catches SIGSEGV, SIGBUS, SIGILL,
/// SIGFPE and the rest, logs them, and ends with `os_exit(1)`, which
/// calls `abort()`: the wait status reads SIGABRT whatever the fault, so
/// this is where the original signal survives.
pub fn received_signal(output: &str) -> Option<String> {
    let at = output.rfind("received signal ")?;
    let name: String = output[at + "received signal ".len()..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// A signal's name, for the operator: the ones a crashing or killed VPP
/// dies of by name, anything else by number.
pub fn signal_name(sig: i32) -> String {
    match sig {
        libc::SIGABRT => "SIGABRT".into(),
        libc::SIGSEGV => "SIGSEGV".into(),
        libc::SIGBUS => "SIGBUS".into(),
        libc::SIGILL => "SIGILL".into(),
        libc::SIGFPE => "SIGFPE".into(),
        libc::SIGKILL => "SIGKILL".into(),
        libc::SIGTERM => "SIGTERM".into(),
        other => format!("signal {other}"),
    }
}

/// A diagnostics directory this root daemon may hand to VPP, held open.
///
/// `state-dir` may be a directory an unprivileged user can write
/// ([`packetframe_common::statefile`]), so a pathname checked once and
/// used again could be swapped for a link between the two (review
/// finding, PR #381). The directory is therefore reached by the
/// state-dir writers' component-wise no-follow walk and used through the
/// descriptor: listing, pruning and creating the output file are all
/// relative to it.
///
/// VPP itself is given the path (`runtime-dir`), and resolves it again
/// as root. So the path must also be one no other account can change:
/// every directory from `/` down to this one owned by root or this
/// daemon's user, and none writable by anyone else unless it is sticky
/// and the entry under it is ours (a sticky directory's entries can be
/// renamed or removed only by their owner). A path like that stays the
/// same directory for as long as only root and this user change it,
/// which is why attach checks it once and the spawns that follow reuse
/// it. Anything else is refused, and VPP runs without diagnostics.
#[cfg(target_os = "linux")]
pub struct DiagDir {
    fd: std::fs::File,
    path: PathBuf,
}

/// Open [`DiagDir`] at `dir` (absolute), creating it owner-only, or say
/// why it is not trusted.
#[cfg(target_os = "linux")]
pub fn open_diagnostics_dir(dir: &Path) -> io::Result<DiagDir> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    let untrusted = |why: String| io::Error::new(io::ErrorKind::PermissionDenied, why);
    // SAFETY: geteuid cannot fail.
    let euid = unsafe { libc::geteuid() };
    let trusted = |uid: u32| uid == 0 || uid == euid;
    // Created (0755, then 0700 below) before the path is judged: the walk
    // follows no link, so the worst it does in an untrusted place is make
    // a directory this function then refuses to use.
    let fd = packetframe_common::statefile::create_and_open_dir_no_follow(dir)?;
    // SAFETY: fchmod on a descriptor this function owns.
    if unsafe { libc::fchmod(fd.as_raw_fd(), 0o700) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut chain = vec![PathBuf::from("/")];
    for comp in dir.components() {
        if let std::path::Component::Normal(n) = comp {
            let next = chain.last().expect("starts with the root").join(n);
            chain.push(next);
        }
    }
    for pair in chain.windows(2) {
        let (parent, child) = (&pair[0], &pair[1]);
        let pm = std::fs::symlink_metadata(parent)?;
        let cm = std::fs::symlink_metadata(child)?;
        let others_write = pm.mode() & 0o022 != 0;
        let sticky = pm.mode() & libc::S_ISVTX != 0;
        if !trusted(pm.uid()) || (others_write && !(sticky && trusted(cm.uid()))) {
            return Err(untrusted(format!(
                "{} can be changed by an account other than root or this daemon's user \
                 (owner uid {}, mode {:o})",
                parent.display(),
                pm.uid(),
                pm.mode() & 0o7777
            )));
        }
    }
    let at_path = std::fs::symlink_metadata(dir)?;
    let held = fd.metadata()?;
    if !trusted(held.uid()) {
        return Err(untrusted(format!(
            "{} is owned by uid {}, not root or this daemon's user",
            dir.display(),
            held.uid()
        )));
    }
    if (at_path.dev(), at_path.ino()) != (held.dev(), held.ino()) {
        return Err(untrusted(format!(
            "{} changed while it was being checked",
            dir.display()
        )));
    }
    Ok(DiagDir {
        fd,
        path: dir.to_path_buf(),
    })
}

/// The diagnostics directory under `state_dir` ([`DIAG_DIR_NAME`]), if
/// [`open_diagnostics_dir`] trusts it; otherwise `None`, with a warning
/// saying why. Attach calls this once: the answer decides both the
/// rendered `unix` stanza (`runtime-dir`, `coredump-size`) and where each
/// spawn's output goes, so the two always agree.
pub fn trusted_diagnostics_dir(state_dir: &Path) -> Option<PathBuf> {
    let dir = state_dir.join(DIAG_DIR_NAME);
    #[cfg(target_os = "linux")]
    {
        // VPP reads `runtime-dir` as one word (`unformat` `%s`).
        if dir.to_str().is_none_or(|d| d.contains(char::is_whitespace)) {
            tracing::warn!(
                dir = %dir.display(),
                "VPP's diagnostics directory is not a UTF-8 path without spaces, which VPP \
                 needs; VPP runs without one: its stdout and stderr go nowhere and it dumps \
                 no core"
            );
            return None;
        }
        match open_diagnostics_dir(&dir) {
            Ok(_) => Some(dir),
            Err(e) => {
                tracing::warn!(
                    dir = %dir.display(),
                    error = %e,
                    "VPP's diagnostics directory is not one this daemon can trust; VPP runs \
                     without one: its stdout and stderr go nowhere and it dumps no core"
                );
                None
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dir;
        None
    }
}

/// Run `f` (a spawn) with this process's `coredump_filter` set to
/// [`CORE_FILTER`], then put the old value back. A child inherits the
/// filter at fork and keeps it across exec (proc(5)), so VPP starts with
/// it and no crash, however early, dumps the hugepage heap. Set in the
/// parent rather than in the child after fork for the reason
/// `packetframe_common::placement::unplaced` gives. A filter that cannot
/// be set is a warning: the core may then be the heap's size.
#[cfg(target_os = "linux")]
fn with_core_filter<T>(f: impl FnOnce() -> T) -> T {
    const SELF: &str = "/proc/self/coredump_filter";
    let old = std::fs::read_to_string(SELF).ok();
    if let Err(e) = std::fs::write(SELF, CORE_FILTER) {
        tracing::warn!(
            error = %e,
            "could not set the core filter VPP inherits; a core it dumps may include its \
             hugepage heap"
        );
    }
    let out = f();
    if let Some(old) = old {
        // The file reads as bare hex (`00000033`) and is written back
        // through a base-detecting parse, which takes a leading 0 for
        // octal: unprefixed, 0x33 would come back as 0x1b.
        let _ = std::fs::write(SELF, format!("0x{}", old.trim()));
    }
    out
}

#[cfg(target_os = "linux")]
impl DiagDir {
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn c_name(name: &str) -> io::Result<std::ffi::CString> {
        if name.contains('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a file name",
            ));
        }
        std::ffi::CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a file name"))
    }

    /// Open `vpp-<now_secs>.log` for append, owner-only, relative to the
    /// directory and never through a link. The name with it. Opened for
    /// reading too: the reaper reads VPP's last lines from a clone
    /// ([`received_signal`]).
    pub fn create_log(&self, now_secs: u64) -> io::Result<(std::fs::File, String)> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = format!("vpp-{now_secs}.log");
        let c = Self::c_name(&name)?;
        // SAFETY: openat on a directory descriptor we own, with a
        // NUL-terminated single-component name; the result is a fresh fd.
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: freshly opened above and owned by nothing else.
        Ok((unsafe { std::fs::File::from_raw_fd(fd) }, name))
    }

    /// Remove `name` if it is empty: the file of a spawn that failed,
    /// which would otherwise take a slot from one that holds something
    /// (review finding, PR #381: a binary that cannot run, retried with
    /// backoff, made a file a second until the crash's was pruned).
    pub fn remove_if_empty(&self, name: &str) {
        if self.stat(name).is_some_and(|st| st.st_size == 0) {
            self.unlink(name);
        }
    }

    /// Remove what [`stale_diagnostics`] names. After a spawn succeeds,
    /// never before: only a VPP that started takes a slot.
    pub fn prune(&self) {
        let Ok(read) = std::fs::read_dir(format!("/proc/self/fd/{}", {
            use std::os::fd::AsRawFd;
            self.fd.as_raw_fd()
        })) else {
            return;
        };
        let entries: Vec<(String, std::time::SystemTime)> = read
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                let st = self.stat(&name)?;
                if st.st_mode & libc::S_IFMT != libc::S_IFREG {
                    return None;
                }
                let mtime = std::time::UNIX_EPOCH
                    + Duration::from_secs(u64::try_from(st.st_mtime).unwrap_or(0));
                Some((name, mtime))
            })
            .collect();
        for name in stale_diagnostics(&entries) {
            self.unlink(&name);
        }
    }

    fn stat(&self, name: &str) -> Option<libc::stat> {
        use std::os::fd::AsRawFd;
        let c = Self::c_name(name).ok()?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstatat into a zeroed stat, not following a final link.
        let r = unsafe {
            libc::fstatat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        (r == 0).then_some(st)
    }

    fn unlink(&self, name: &str) {
        use std::os::fd::AsRawFd;
        if let Ok(c) = Self::c_name(name) {
            // SAFETY: unlinkat of one name relative to our descriptor.
            unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) };
        }
    }
}

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

/// Identity of the running kernel, from
/// `/proc/sys/kernel/random/boot_id`.
///
/// **Load-bearing for adoption, not diagnostics.** `start_ticks` is
/// measured in clock ticks *since boot*, and the state file outlives a
/// reboot (the default state dir is under `/var/lib`). After a reboot
/// the tick counter restarts, so an unrelated process can legitimately
/// land on the recorded pid at the recorded tick and satisfy a
/// `(pid, start_ticks)` equality check. We would then hold a pidfd for
/// a stranger and later send it SIGTERM and SIGKILL as root.
///
/// The boot id makes the pair meaningful again: it changes on every
/// boot, so a state file from a previous boot can never match.
pub fn boot_id() -> std::io::Result<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let id = raw.trim().to_string();
    if id.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "/proc/sys/kernel/random/boot_id is empty",
        ));
    }
    Ok(id)
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

    /// VPP's command line and environment.
    pub(super) fn command(binary: &Path, conf: &Path) -> Command {
        let mut cmd = Command::new(binary);
        cmd.arg("-c")
            .arg(conf)
            // The sampler plugin follows `PF_SAMPLER_DIR` when it is set.
            // An inherited one would point it at a directory nothing
            // prepared; without it, the plugin uses its default, which is
            // the one vpp-offload mounts (`crate::sampler`).
            .env_remove(packetframe_sampler_shm::fs::ENV_DIR)
            // VPP's own `log` stanza owns its output. Inheriting our
            // stdout would interleave dataplane chatter into
            // packetframe's structured log.
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }
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

    /// Kill and reap a child we spawned but could not take ownership
    /// of, then return the original error with that noted.
    ///
    /// Signalling by pid rather than pidfd is safe *here specifically*:
    /// we hold the unreaped `Child`, so the pid cannot have been
    /// recycled yet — it is at worst our own zombie.
    fn orphan_cleanup(mut child: Child, pid: i32, cause: io::Error) -> io::Error {
        // SAFETY: kill(2) on a pid we own and have not reaped.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        // Reap so it does not linger as a zombie holding the pid.
        let reaped = child.wait().is_ok();
        io::Error::new(
            cause.kind(),
            format!(
                "spawned VPP (pid {pid}) but could not take ownership of it: {cause}; \
                 the child was killed{} to avoid an untracked VPP holding the VF",
                if reaped { " and reaped" } else { "" }
            ),
        )
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
        /// Where its stdout and stderr go, when we forked it with a
        /// diagnostics directory ([`super::DIAG_DIR_NAME`]).
        output: Option<Output>,
    }

    /// A spawned VPP's output file: its path, for the operator, and a
    /// descriptor on it, so the reaper reads the last lines without
    /// resolving the path again.
    #[derive(Debug)]
    struct Output {
        path: std::path::PathBuf,
        file: fs::File,
    }

    /// The most of a dead VPP's output read for its handler's line: its
    /// last words, not a whole long-lived file.
    const OUTPUT_TAIL: u64 = 64 * 1024;

    impl Output {
        fn tail(&self) -> String {
            use std::os::unix::fs::FileExt;
            let len = self.file.metadata().map_or(0, |m| m.len());
            let from = len.saturating_sub(OUTPUT_TAIL);
            let mut buf = vec![0u8; (len - from) as usize];
            let n = self.file.read_at(&mut buf, from).unwrap_or(0);
            buf.truncate(n);
            String::from_utf8_lossy(&buf).into_owned()
        }
    }

    impl VppProcess {
        /// Fork/exec VPP against a rendered startup.conf.
        ///
        /// The conf sets `nodaemon`, so this child *is* the dataplane
        /// rather than a launcher that exits — without that, the pidfd
        /// would signal "exited" immediately and the supervisor would
        /// restart-loop a perfectly healthy VPP.
        pub fn spawn(binary: &Path, conf: &Path) -> io::Result<Self> {
            Self::spawn_with(binary, conf, None)
        }

        /// [`Self::spawn`], with its stdout and stderr in a fresh file in
        /// `diag`, a directory [`super::trusted_diagnostics_dir`] accepted
        /// at attach ([`super::DIAG_DIR_NAME`]). Its working directory is
        /// VPP's own business: the rendered `runtime-dir` puts it in the
        /// same directory, where a relative `core_pattern` drops a core.
        /// Best effort: a directory that cannot be opened costs the
        /// output, never the spawn.
        pub fn spawn_with(binary: &Path, conf: &Path, diag: Option<&Path>) -> io::Result<Self> {
            let mut cmd = command(binary, conf);
            let mut opened = None;
            if let Some(dir) = diag {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let ready = super::open_diagnostics_dir(dir).and_then(|d| {
                    let (file, name) = d.create_log(now)?;
                    let (out, err) = (file.try_clone()?, file.try_clone()?);
                    Ok((d, name, file, out, err))
                });
                match ready {
                    Ok((d, name, file, out, err)) => {
                        cmd.stdout(out).stderr(err);
                        opened = Some((d, name, file));
                    }
                    Err(e) => tracing::warn!(
                        dir = %dir.display(),
                        error = %e,
                        "VPP's diagnostics directory could not be opened; this VPP's stdout \
                         and stderr go nowhere"
                    ),
                }
            }
            // This runs on the supervision thread, which may be placed
            // on the control-plane CPUs; VPP must start from the
            // daemon's unplaced mask instead (`placement::unplaced` has
            // why, and why this is not a `pre_exec` hook).
            // The filter goes with the rendered core limit, which a
            // diagnostics directory brings, not with whether this spawn's
            // output file opened: an unlimited limit with the default
            // filter would dump the hugepage heap.
            let spawned = if diag.is_some() {
                super::with_core_filter(|| packetframe_common::placement::unplaced(|| cmd.spawn()))
            } else {
                packetframe_common::placement::unplaced(|| cmd.spawn())
            };
            // The Command holds the child's copies of the output file;
            // drop them so the directory is the only thing left open.
            drop(cmd);
            let child = match spawned {
                Ok(c) => c,
                Err(e) => {
                    if let Some((d, name, _)) = &opened {
                        d.remove_if_empty(name);
                    }
                    return Err(e);
                }
            };
            let output = opened.map(|(d, name, file)| {
                d.prune();
                Output {
                    path: d.path().join(name),
                    file,
                }
            });
            let pid = child.id() as i32;

            // Open the pidfd before anything else can reap the child.
            // `child` is still owned here, so even if VPP died during
            // exec it is a zombie, not gone, and pidfd_open succeeds.
            //
            // Both of these can fail on a healthy, RUNNING child — an
            // fd-limit hit on `pidfd_open`, a procfs read error on the
            // stat. Propagating with `?` would drop `child` and leave
            // that VPP alive and untracked: still holding the VF and
            // the API socket, invisible to the pidfd we never got, and
            // the `SpawnFailed` retry would then start a SECOND VPP on
            // the same resources. Kill what we started before giving up.
            let pidfd = match pidfd_open(pid) {
                Ok(fd) => fd,
                Err(e) => return Err(orphan_cleanup(child, pid, e)),
            };
            let start_ticks = match read_start_ticks(pid) {
                Ok(t) => t,
                Err(e) => return Err(orphan_cleanup(child, pid, e)),
            };
            Ok(Self {
                pid,
                start_ticks,
                pidfd,
                origin: Origin::Spawned,
                child: Some(child),
                output,
            })
        }

        /// Re-acquire a VPP that outlived us, from the state file's
        /// `(pid, start_ticks, boot_id)` triple.
        ///
        /// `Ok(None)` means "nothing of ours is running" — the pid is
        /// gone, it now belongs to an unrelated process, or the state
        /// file is from a previous boot. All three are ordinary
        /// fresh-attach outcomes, not errors.
        ///
        /// **`recorded_boot_id` is not optional in spirit.** Passing
        /// `None` (an old state file that predates the field) refuses
        /// adoption, because `start_ticks` counts from boot and the
        /// state file outlives a reboot: without a boot id, a fresh
        /// unrelated process can match the recorded pid at the recorded
        /// tick, and we would SIGKILL it as root. One needless restart
        /// is the correct price.
        ///
        /// Order matters: **open the pidfd first, verify identity
        /// second.** The pidfd pins one process for its lifetime, so
        /// once it is open no later reuse can change what we hold; the
        /// start-time check then rules out a reuse that happened
        /// *before* the open. Verifying first and opening second would
        /// leave exactly the window this is meant to close.
        pub fn adopt(
            pid: i32,
            start_ticks: u64,
            recorded_boot_id: Option<&str>,
        ) -> io::Result<Option<Self>> {
            // Cheapest and most decisive check, before we touch a pid
            // that may not be ours at all.
            match (recorded_boot_id, super::boot_id()) {
                (Some(recorded), Ok(current)) if recorded == current => {}
                // Different boot: the state file's pid/tick pair refers
                // to a process that cannot still exist.
                (Some(_), Ok(_)) => return Ok(None),
                // No recorded boot id: cannot establish identity.
                (None, _) => return Ok(None),
                // Cannot read our own boot id — refuse rather than
                // adopt on an unverifiable identity.
                (_, Err(e)) => return Err(e),
            }
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
                    output: None,
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
        ///
        /// A death by signal is reported here, with the signal and
        /// whether a core was dumped. The supervisor's
        /// `ProcessExited { status }` carries the exit code only, which a
        /// signal death does not have: on 2026-11-05 a fresh VPP's
        /// `status: None` was all that was left of a SIGABRT.
        fn reap(&mut self) -> Option<i32> {
            let child = self.child.as_mut()?;
            match child.wait() {
                Ok(status) => {
                    use std::os::unix::process::ExitStatusExt;
                    if let Some(sig) = status.signal() {
                        self.report_signal_death(sig, status.core_dumped());
                    }
                    status.code()
                }
                Err(_) => None,
            }
        }

        /// `signal` is the signal the process died of. For a VPP fault
        /// that is SIGABRT whatever the fault was: VPP's handler catches
        /// SIGSEGV, SIGBUS and the rest, logs `received signal …`, and
        /// exits through `abort()` (review finding, PR #381). So the
        /// signal VPP's handler caught is read back from its output,
        /// `vpp_signal`, and is `none` when there is no such line (a
        /// kill, or no output file to read).
        fn report_signal_death(&self, sig: i32, core_dumped: bool) {
            let signal = super::signal_name(sig);
            let output = self.output.as_ref().map_or_else(
                || "none (no diagnostics directory)".to_string(),
                |o| o.path.display().to_string(),
            );
            let vpp_signal = self
                .output
                .as_ref()
                .and_then(|o| super::received_signal(&o.tail()))
                .unwrap_or_else(|| "none".to_string());
            tracing::warn!(
                pid = self.pid,
                signal = %signal,
                vpp_signal = %vpp_signal,
                core_dumped,
                output = %output,
                "VPP died of a signal; vpp_signal is the fault its own handler caught, if \
                 it logged one. Its last output is in the file named, and a core, if one was \
                 dumped, in the same directory unless the kernel's core_pattern sends it \
                 elsewhere"
            );
            packetframe_common::events::Event::warn(
                crate::MODULE_NAME,
                packetframe_common::events::kind::VPP_KILLED,
            )
            .field("pid", i64::from(self.pid))
            .field("signal", signal)
            .field("vpp_signal", vpp_signal)
            .field("core_dumped", core_dumped)
            .field("output", output)
            .emit();
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
        pub fn spawn_with(_binary: &Path, _conf: &Path, _diag: Option<&Path>) -> io::Result<Self> {
            unsupported()
        }
        pub fn adopt(
            _pid: i32,
            _start_ticks: u64,
            _recorded_boot_id: Option<&str>,
        ) -> io::Result<Option<Self>> {
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
    prior: Option<(i32, u64, Option<String>)>,
    binary: &Path,
    conf: &Path,
) -> io::Result<(VppProcess, bool)> {
    if let Some((pid, ticks, boot)) = prior {
        if let Some(p) = VppProcess::adopt(pid, ticks, boot.as_deref())? {
            return Ok((p, true));
        }
    }
    Ok((VppProcess::spawn(binary, conf)?, false))
}

/// Whether the caller may release the resources VPP was using.
///
/// The distinction is the whole point of [`VppProcess::terminate`]'s
/// bounded SIGKILL wait, so it must survive into the teardown path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Disposition {
    /// The process is gone. VF unbind, numvfs=0, and hugepage release
    /// are safe.
    SafeToRelease,
    /// The process may still be alive and DMA-capable. Resources MUST
    /// be leaked rather than released.
    MustLeak,
}

/// Teardown for paths that cannot propagate an error, such as detach
/// unwinding — but which still must not release resources under a live
/// process.
///
/// Returns a [`Disposition`] instead of swallowing the outcome. An
/// earlier version logged the failure and returned `()`, which handed
/// the caller no way to distinguish "VPP is gone" from "VPP survived
/// SIGKILL and may still be writing into the buffers you are about to
/// hand back to the kernel". Unbinding a VF or dropping hugepages under
/// a process that can still DMA into them is memory corruption with a
/// warning line in the log as its only trace — leaking a VF is
/// dramatically cheaper, and it is visible in `packetframe status`.
pub fn terminate_or_leak(p: &mut VppProcess, grace: Duration) -> Disposition {
    match p.terminate(grace) {
        Ok(_) => Disposition::SafeToRelease,
        Err(e) => {
            tracing::error!(
                pid = p.pid(),
                error = %e,
                "VPP did not die; LEAKING its VF and hugepages rather than \
                 releasing resources a live process may still DMA into"
            );
            Disposition::MustLeak
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// VPP never inherits a sampler directory: the plugin must use the
    /// default, the one vpp-offload mounts.
    #[cfg(target_os = "linux")]
    #[test]
    fn vpp_is_spawned_without_a_sampler_directory_override() {
        let cmd = imp::command(Path::new("/usr/bin/vpp"), Path::new("/run/vpp.conf"));
        assert!(
            cmd.get_envs()
                .any(|(k, v)| k == packetframe_sampler_shm::fs::ENV_DIR && v.is_none()),
            "{:?}",
            cmd.get_envs().collect::<Vec<_>>()
        );
        assert_eq!(
            crate::acquire::SAMPLER_DIR,
            packetframe_sampler_shm::fs::DEFAULT_DIR,
            "vpp-offload mounts where the plugin looks by default"
        );
    }

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

    /// Adoption across a reboot is the case that could aim SIGKILL at
    /// a stranger: `start_ticks` counts from boot and resets, while the
    /// state file under `/var/lib` does not. A state file with no
    /// recorded boot id therefore cannot establish identity at all, and
    /// must be refused rather than trusted.
    #[test]
    fn adoption_without_a_recorded_boot_id_is_refused() {
        // Our own pid is certainly alive, so this isolates the boot-id
        // check from every other reason adoption can decline.
        let me = std::process::id() as i32;
        let ticks = 12345;
        match VppProcess::adopt(me, ticks, None) {
            Ok(None) => {} // refused, as required
            Ok(Some(_)) => panic!("adopted a process on an unverifiable identity"),
            // Non-Linux stubs return Unsupported; that is also "did not
            // adopt", which is the property under test.
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Unsupported, "{e}"),
        }
    }

    /// A boot id from a different boot must not match.
    #[test]
    fn adoption_from_a_previous_boot_is_refused() {
        let me = std::process::id() as i32;
        match VppProcess::adopt(me, 12345, Some("not-the-current-boot-id")) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("adopted across a reboot"),
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::Unsupported, "{e}"),
        }
    }

    /// `Disposition` is the signal that stops teardown from releasing
    /// a VF under a process that may still DMA into it. It must be
    /// impossible to ignore by accident.
    #[test]
    fn disposition_distinguishes_safe_from_must_leak() {
        assert_ne!(Disposition::SafeToRelease, Disposition::MustLeak);
    }

    /// Real kernels emit a trailing newline.
    #[test]
    fn a_trailing_newline_is_tolerated() {
        let stat = "4242 (vpp) S 1 4242 4242 0 -1 4194560 1234 0 0 0 10 20 0 0 20 0 8 0 987654 \
                    123456789 456\n";
        assert_eq!(parse_start_ticks(stat), Some(987_654));
    }

    /// A VPP spawned from a placed thread starts from the daemon's
    /// unplaced mask, not the thread's. `sh -c <conf>` stands in for
    /// `vpp -c <conf>`, so the "conf" is the command it runs.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_spawn_from_a_placed_thread_does_not_inherit_the_placement() {
        fn allowed(status: &str) -> Vec<u16> {
            let line = status
                .lines()
                .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
                .expect("Cpus_allowed_list");
            crate::cores::parse_cpu_list(line.trim()).expect("cpu list")
        }
        // Serialised with the tests that edit every thread's mask,
        // the leader's included.
        let _serialised = crate::cores::affinity_tests::lock_affinity();
        let leader = allowed(&std::fs::read_to_string("/proc/self/status").unwrap());
        if leader.len() < 2 {
            return; // a placement would be indistinguishable
        }
        let child_mask = std::thread::spawn(move || {
            let mut one: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            unsafe { libc::CPU_SET(leader[0] as usize, &mut one) };
            let rc =
                unsafe { libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &one) };
            assert_eq!(rc, 0);
            let mut p = VppProcess::spawn(Path::new("/bin/sh"), Path::new("sleep 30"))
                .expect("spawn a stand-in");
            let status = std::fs::read_to_string(format!("/proc/{}/status", p.pid()));
            p.signal(libc::SIGKILL).expect("kill the stand-in");
            p.poll_exit(Duration::from_secs(5)).expect("reap");
            let own = allowed(&std::fs::read_to_string("/proc/thread-self/status").unwrap());
            assert_eq!(
                own,
                vec![leader[0]],
                "the spawning thread's placement is restored"
            );
            allowed(&status.expect("child status"))
        })
        .join()
        .expect("spawning thread");
        let leader = allowed(&std::fs::read_to_string("/proc/self/status").unwrap());
        assert_eq!(child_mask, leader, "the child took the leader's mask");
    }

    /// An executable that is not a program fails to SPAWN rather than
    /// being run as a shell script — the `/bin/sh` fallback a `pre_exec`
    /// hook would have enabled (review finding). The bring-up tests'
    /// stand-in VPP binary relies on exactly this.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_executable_that_is_not_a_program_fails_to_spawn() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pf-noexec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("vpp");
        std::fs::write(&bin, "not really vpp").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let got = VppProcess::spawn(&bin, Path::new("/dev/null"));
        let _ = std::fs::remove_dir_all(&dir);
        let e = got.expect_err("a text file must not spawn");
        assert_eq!(e.raw_os_error(), Some(libc::ENOEXEC), "{e}");
    }

    #[cfg(target_os = "linux")]
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pf-vppdiag-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// A pruning keeps the newest output files and the newest cores, by
    /// name and by age respectively, and touches nothing else in the
    /// directory (VPP's own runtime files live there too).
    #[test]
    fn a_pruning_keeps_the_newest_output_and_cores_and_nothing_else() {
        let t = |s| std::time::UNIX_EPOCH + Duration::from_secs(s);
        let mut entries: Vec<(String, std::time::SystemTime)> = (0..7)
            .map(|i| (format!("vpp-179000000{i}.log"), t(i)))
            .collect();
        entries.push(("core.4242".into(), t(100)));
        entries.push(("core.4243".into(), t(300)));
        entries.push(("core".into(), t(200)));
        entries.push(("notes.txt".into(), t(0)));
        entries.push(("stats.sock".into(), t(0)));
        let mut gone = stale_diagnostics(&entries);
        gone.sort();
        assert_eq!(
            gone,
            vec![
                "core.4242".to_string(),
                "vpp-1790000000.log".into(),
                "vpp-1790000001.log".into(),
            ],
            "five newest logs kept, the spawn's own among them; two newest cores"
        );
        assert!(stale_diagnostics(&entries[..2]).is_empty());
    }

    /// VPP's fatal-signal handler line, as it reaches stderr through
    /// syslog's `LOG_PERROR`: the last one wins, and output without one
    /// (a panic's own text, a kill) names nothing.
    #[test]
    fn the_signal_vpp_caught_is_read_from_its_last_handler_line() {
        let out = "vpp[812]: unix_config:507: couldn't open log '/x'\n\
                   vpp[812]: received signal SIGBUS, PC 0x7f00, faulting address 0x0\n\
                   vpp[812]: #0  0x0000ffff8a1c unix_signal_handler + 0x2a4\n\
                   vpp[812]: received signal SIGSEGV, PC 0xffff, faulting address 0x10\n\
                   vpp[812]: #0  0x0000ffff8a1c unix_signal_handler + 0x2a4\n";
        assert_eq!(received_signal(out).as_deref(), Some("SIGSEGV"));
        assert_eq!(
            received_signal("vpp[9]: received signal SIGABRT, PC 0x1\n").as_deref(),
            Some("SIGABRT")
        );
        assert_eq!(received_signal("panic: out of memory\n"), None);
        assert_eq!(received_signal("received signal \n"), None);
        assert_eq!(received_signal(""), None);
    }

    #[test]
    fn a_signal_is_named_when_it_is_a_crash_or_a_kill() {
        assert_eq!(signal_name(libc::SIGABRT), "SIGABRT");
        assert_eq!(signal_name(libc::SIGKILL), "SIGKILL");
        assert_eq!(signal_name(libc::SIGSEGV), "SIGSEGV");
        assert_eq!(signal_name(64), "signal 64");
    }

    /// The directory is made owner-only and used through its descriptor:
    /// the output file is owner-only and opened for append (a second
    /// spawn in the same second adds to it), an empty one is removed and
    /// a full one kept, and the pruning works on disk.
    #[cfg(target_os = "linux")]
    #[test]
    fn diagnostics_are_owner_only_and_used_through_the_directory() {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("prep");
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join(DIAG_DIR_NAME);
        let d = open_diagnostics_dir(&dir).expect("trusted");
        assert_eq!(d.path(), dir);
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{mode:o}");
        let (mut f, name) = d.create_log(1_790_000_000).expect("create");
        assert_eq!(name, "vpp-1790000000.log");
        f.write_all(b"one\n").unwrap();
        let path = dir.join(&name);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
        let (mut g, again) = d.create_log(1_790_000_000).expect("again");
        assert_eq!(again, name);
        g.write_all(b"two\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\n");

        d.remove_if_empty(&name);
        assert!(path.exists(), "a file with output in it is kept");
        let (_, empty) = d.create_log(1_790_000_001).expect("empty");
        d.remove_if_empty(&empty);
        assert!(!dir.join(&empty).exists(), "an empty one is removed");

        for i in 2..8 {
            std::fs::write(dir.join(format!("vpp-179000000{i}.log")), b"x").unwrap();
        }
        std::fs::write(dir.join("stats.sock"), b"").unwrap();
        d.prune();
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "stats.sock".to_string(),
                "vpp-1790000003.log".into(),
                "vpp-1790000004.log".into(),
                "vpp-1790000005.log".into(),
                "vpp-1790000006.log".into(),
                "vpp-1790000007.log".into(),
            ]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Only a path no other account can change is used: a symlink where
    /// the directory should be is refused rather than followed, and so
    /// is a parent group or others can write. A sticky one (`/tmp`) is
    /// fine when the entry under it is ours, which is how these tests
    /// run.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_untrusted_diagnostics_path_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("trust");
        std::fs::create_dir_all(&root).unwrap();
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = root.join("linked");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(open_diagnostics_dir(&link.join(DIAG_DIR_NAME)).is_err());
        assert!(
            !real.join(DIAG_DIR_NAME).exists(),
            "nothing made through the link"
        );

        let open = root.join("open");
        std::fs::create_dir_all(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = open_diagnostics_dir(&open.join(DIAG_DIR_NAME))
            .err()
            .expect("refused");
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert!(trusted_diagnostics_dir(&open).is_none());

        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            trusted_diagnostics_dir(&open),
            Some(open.join(DIAG_DIR_NAME)),
            "the same place, closed to others, is used"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The point of the directory: what a dying VPP prints before it
    /// aborts survives it, the signal its handler logged can be read
    /// back, and it starts with the core filter that leaves its hugepage
    /// heap out, while the daemon's own filter is put back. A stand-in
    /// shell plays VPP. A spawn prunes only once it has succeeded, and a
    /// failed one leaves no file behind.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_spawned_process_writes_its_output_into_the_diagnostics_directory() {
        let root = scratch("spawn");
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join(DIAG_DIR_NAME);
        std::fs::create_dir_all(&dir).unwrap();
        for i in 0..6 {
            std::fs::write(dir.join(format!("vpp-100000000{i}.log")), b"old").unwrap();
        }
        let logs = || -> Vec<String> {
            let mut v: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .filter(|n| n.ends_with(".log"))
                .collect();
            v.sort();
            v
        };

        let e = VppProcess::spawn_with(Path::new("/nonexistent/vpp"), Path::new("x"), Some(&dir))
            .expect_err("no such binary");
        assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
        assert_eq!(
            logs().len(),
            6,
            "a failed spawn neither adds a file nor prunes"
        );

        let filter = || std::fs::read_to_string("/proc/self/coredump_filter").unwrap();
        let ours = filter();
        let mut p = VppProcess::spawn_with(
            Path::new("/bin/sh"),
            Path::new(
                "echo panic: out of memory >&2; \
                 echo 'vpp[1]: received signal SIGSEGV, PC 0x1' >&2; \
                 cat /proc/self/coredump_filter; kill -ABRT $$",
            ),
            Some(&dir),
        )
        .expect("spawn a stand-in");
        assert_eq!(filter(), ours, "the daemon's own filter is put back");
        let exited = p.poll_exit(Duration::from_secs(10)).expect("poll");
        assert_eq!(exited, Some(None), "a signal death has no exit code");

        let now = logs();
        assert_eq!(now.len(), DIAG_LOGS_KEPT, "{now:?}");
        assert!(!now.contains(&"vpp-1000000000.log".to_string()), "{now:?}");
        let newest = now.last().unwrap();
        let out = std::fs::read_to_string(dir.join(newest)).unwrap();
        assert!(out.contains("panic: out of memory"), "stderr: {out}");
        assert_eq!(received_signal(&out).as_deref(), Some("SIGSEGV"));
        assert!(
            out.lines().any(|l| l.trim() == "00000013"),
            "VPP starts with the core filter {CORE_FILTER}: {out}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
