//! Symlink-safe state-directory I/O for root writers.
//!
//! `state-dir` can be a pre-existing directory an unprivileged user can
//! write, so every privileged write, rename, unlink and read in it goes
//! through a component-wise no-follow directory walk plus
//! `openat`/`renameat`/`unlinkat` relative to the walked descriptor.
//! `std::fs::write` would follow a planted symlink and truncate whatever
//! it points at (review findings, P1, on the CLI's state records and
//! again on fast-path's `coalesce.json`).
//!
//! Lives in the common crate so a module's own state file (fast-path's
//! coalescing record) uses the same primitive as the CLI's pid file,
//! identity sidecar and textfiles — a second implementation of "write
//! without following" is how one of them ends up without it.
//!
//! `create_excl_no_follow` — the pathname O_NOFOLLOW|O_EXCL primitive
//! from the May 2026 audit — is gone for the same reason: O_NOFOLLOW on
//! the final component never guarded the intermediate ones.
//!
//! One walk serves both policies: the strict one the state files use,
//! and the event log's, which also follows a symlinked directory only
//! root could have made ([`open_dir_trusted_links`]).

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

/// Open an ABSOLUTE directory path one component at a time, each step
/// `openat(O_DIRECTORY | O_NOFOLLOW)` relative to the descriptor of the
/// previous one, creating missing components (0755) on the way.
///
/// Why a walk and not one `open`: `O_NOFOLLOW` guards only the FINAL
/// component. The state-dir writes and the umask chmod used to resolve
/// the whole path at once, so a symlink at an intermediate component —
/// `/tmp/plant/state` with `plant` attacker-controlled — carried this
/// root process wherever the attacker pointed, and the descriptor
/// "verified" at the end belonged to a directory of their choosing
/// (review finding, P1; the reader was already refusing such paths via
/// canonicalize-equality, and the privileged writer must be at least as
/// suspicious as the reader). Every component is opened without
/// following; a symlink ANYWHERE fails with `ELOOP` and the write is
/// refused.
///
/// `..` is refused outright — a state dir has no business being
/// specified through parent traversal, and accepting it would make the
/// walk's guarantees path-dependent.
pub fn create_and_open_dir_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    walk_dir(path, true, Links::Refuse)
}

/// The non-creating walk, for operations that have no business making
/// directories — removal in particular: if the walk cannot reach the
/// directory, there is nothing there this process is entitled to touch.
pub fn open_dir_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    walk_dir(path, false, Links::Refuse)
}

/// The same walk, except that a symlinked directory component is
/// followed when nobody but root could have created or replaced it: the
/// link is owned by root, and so is the directory holding it, which
/// group and others cannot write. Any other symlink is refused as by
/// [`create_and_open_dir_no_follow`], with the reason and a pointer at
/// `setting` (the config directive that named `path`).
///
/// For the event log, whose natural location on some appliances is a
/// persistent-storage path that is itself a root-owned symlink (`/data`
/// pointing into the storage mount, say): refusing it lost the log for
/// the obvious config. Following such a link does what root configuring
/// the resolved path would have done — only root could have put it
/// there — so it hands no unprivileged user a way to redirect the write.
/// The state-file writers keep the strict walk: `state-dir` is not
/// normally reached through a link, so for the pid file and records the
/// narrower rule costs nothing.
///
/// "Root" is uid 0 or this process's euid. In the daemon, which runs as
/// root, that is uid 0 alone. A non-root reader (`packetframe events` run
/// by a user) also trusts its own links, which reach nothing that user
/// could not open anyway — and that is what lets the tests exercise the
/// rule without root.
///
/// A link's target is walked under the same rule, `..` in it steps back
/// along the directories actually opened, and at most [`MAX_LINKS`] are
/// followed per walk, so a loop is refused rather than spun on. The walk
/// yields a directory: the caller's final component (the file itself)
/// is still opened `O_NOFOLLOW` relative to it, never through a link.
pub fn open_dir_trusted_links(
    path: &Path,
    create: bool,
    setting: &str,
) -> std::io::Result<std::fs::File> {
    let euid = unsafe { libc::geteuid() };
    walk_dir(
        path,
        create,
        Links::FollowTrusted {
            trusted: &[0, euid],
            setting,
        },
    )
}

/// Symlinks followed per [`open_dir_trusted_links`] walk.
pub const MAX_LINKS: usize = 8;

#[derive(Clone, Copy)]
enum Links<'a> {
    Refuse,
    FollowTrusted {
        /// Owners whose links, and link-holding directories, are trusted.
        trusted: &'a [libc::uid_t],
        setting: &'a str,
    },
}

enum Step {
    Name(std::ffi::OsString),
    Parent,
}

fn walk_dir(path: &Path, create: bool, links: Links) -> std::io::Result<std::fs::File> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("state paths must be absolute: {}", path.display()),
        ));
    }
    let mut pending = std::collections::VecDeque::new();
    for comp in path.components() {
        match comp {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(n) => pending.push_back(Step::Name(n.to_owned())),
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("refusing path component {other:?} in {}", path.display()),
                ))
            }
        }
    }
    // The directories opened so far, root first: `..` in a followed
    // link's target steps back along this chain.
    let mut chain = vec![std::fs::File::open("/")?];
    let mut followed = 0;
    while let Some(step) = pending.pop_front() {
        let name = match step {
            Step::Parent => {
                if chain.len() > 1 {
                    chain.pop();
                }
                continue;
            }
            Step::Name(n) => n,
        };
        let dir = chain.last().expect("the root is never popped");
        let c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path component")
        })?;
        let e = match open_component(dir, &c, create) {
            Ok(fd) => {
                // SAFETY: `fd` was just returned by openat and is owned
                // by nothing else.
                chain.push(unsafe { std::fs::File::from_raw_fd(fd) });
                continue;
            }
            Err(e) => e,
        };
        if let Links::FollowTrusted { trusted, setting } = links {
            let at = LinkAt {
                dir,
                c: &c,
                name: &name,
                path,
                trusted,
                setting,
            };
            if let Some(target) = at.trusted_target(&mut followed)? {
                if target.is_absolute() {
                    chain.truncate(1);
                }
                for comp in target.components().rev() {
                    match comp {
                        std::path::Component::Normal(n) => {
                            pending.push_front(Step::Name(n.to_owned()))
                        }
                        std::path::Component::ParentDir => pending.push_front(Step::Parent),
                        _ => {}
                    }
                }
                continue;
            }
        }
        return Err(std::io::Error::new(
            e.kind(),
            format!(
                "open component {name:?} of {}: {e} (a symlink here is refused)",
                path.display()
            ),
        ));
    }
    Ok(chain.pop().expect("the root is never popped"))
}

/// `openat(O_DIRECTORY | O_NOFOLLOW)` one component relative to `dir`,
/// creating it (0755) first when asked and missing.
fn open_component(
    dir: &std::fs::File,
    c: &std::ffi::CStr,
    create: bool,
) -> std::io::Result<std::os::fd::RawFd> {
    use std::os::fd::AsRawFd;
    let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_CLOEXEC;
    let mut fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
    if create && fd < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
        // Create it and re-open. A concurrent creator making this
        // mkdirat lose with EEXIST is fine — the reopen decides.
        unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o755) };
        fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
    }
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// A component that did not open as a directory, with what the
/// trusted-links walk needs to decide whether it is a link to follow.
struct LinkAt<'a> {
    dir: &'a std::fs::File,
    c: &'a std::ffi::CStr,
    name: &'a std::ffi::OsStr,
    path: &'a Path,
    trusted: &'a [libc::uid_t],
    setting: &'a str,
}

impl LinkAt<'_> {
    /// The link's target if the component is a symlink that is safe to
    /// follow; `None` if it is not a symlink (the open's own error
    /// stands); an error naming the reason if it is one that is not safe.
    ///
    /// No re-check is needed between the `fstatat` and the `readlinkat`:
    /// the holding directory is examined through the descriptor already
    /// open, and once it is owned by a trusted uid and closed to group
    /// and others, nothing untrusted can swap the link in between.
    fn trusted_target(&self, followed: &mut usize) -> std::io::Result<Option<PathBuf>> {
        use std::os::fd::AsRawFd;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::MetadataExt;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                self.c.as_ptr(),
                &mut st,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 || st.st_mode & libc::S_IFMT != libc::S_IFLNK {
            return Ok(None);
        }
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let n = unsafe {
            libc::readlinkat(
                self.dir.as_raw_fd(),
                self.c.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        buf.truncate(n as usize);
        let target = PathBuf::from(std::ffi::OsString::from_vec(buf));

        *followed += 1;
        if *followed > MAX_LINKS {
            return Err(self.refused(
                std::io::Error::from_raw_os_error(libc::ELOOP).kind(),
                &target,
                format!("more than {MAX_LINKS} symlinks in the path (a loop?)"),
            ));
        }
        if !self.trusted.contains(&st.st_uid) {
            return Err(self.refused(
                std::io::ErrorKind::PermissionDenied,
                &target,
                format!("the link is owned by uid {}, not root", st.st_uid),
            ));
        }
        let meta = self.dir.metadata()?;
        if !self.trusted.contains(&meta.uid()) {
            return Err(self.refused(
                std::io::ErrorKind::PermissionDenied,
                &target,
                format!(
                    "the directory holding it is owned by uid {}, not root",
                    meta.uid()
                ),
            ));
        }
        if meta.mode() & 0o022 != 0 {
            return Err(self.refused(
                std::io::ErrorKind::PermissionDenied,
                &target,
                format!(
                    "the directory holding it is writable by group or others (mode {:04o})",
                    meta.mode() & 0o7777
                ),
            ));
        }
        Ok(Some(target))
    }

    fn refused(&self, kind: std::io::ErrorKind, target: &Path, why: String) -> std::io::Error {
        std::io::Error::new(
            kind,
            format!(
                "component {:?} of {} is a symlink (to {}) that is not followed: {why}. Only a \
                 root-owned symlink in a root-owned directory that group and others cannot \
                 write is followed; point `{}` at the resolved path instead",
                self.name,
                self.path.display(),
                target.display(),
                self.setting
            ),
        )
    }
}

/// `O_CREAT|O_EXCL|O_NOFOLLOW` a file RELATIVE to an already-walked
/// directory descriptor, mode 0600, for writers that must not
/// re-resolve the directory path between verifying it and using it.
fn openat_excl_no_follow(dir: &std::fs::File, name: &str) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name"))?;
    let flags = libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_WRONLY | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Same shape but with one stale-`.tmp` retry, dirfd-relative
/// throughout. The retry runs only when the create returns
/// `AlreadyExists` and the existing entry is a regular file (a leftover
/// from a crashed run), checked with `fstatat(AT_SYMLINK_NOFOLLOW)` so
/// an attacker's symlink is not misclassified as a file. A second
/// `EEXIST` is a real race between competing writers and errors out.
pub fn openat_excl_with_retry(dir: &std::fs::File, name: &str) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    match openat_excl_no_follow(dir, name) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let c = std::ffi::CString::new(name).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name")
            })?;
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    c.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if st.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(e);
            }
            if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            openat_excl_no_follow(dir, name)
        }
        Err(e) => Err(e),
    }
}

/// Remove a state record through the same component-wise no-follow
/// walk the writers use — never by resolving the pathname whole.
///
/// `std::fs::remove_file` does not follow a symlink at the FINAL
/// component, but it follows every intermediate one, so the identity
/// cleanup on a failed write could be pointed at another instance's
/// state directory and have this root daemon delete THAT instance's
/// sidecar — disabling its identity-based status and reconfigure
/// (review finding, P1; the writes had just been converted to
/// descriptor-relative operations while this cleanup stayed
/// pathname-based). If the walk cannot reach the directory, nothing is
/// removed: a path this process refuses to write through is a path it
/// must refuse to delete through.
pub fn remove_state_record(path: &Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = file_name(path)?;
    let dir = open_dir_no_follow(parent)?;
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name"))?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `renameat` within one already-walked directory descriptor.
pub fn renameat_within(dir: &std::fs::File, from: &str, to: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let (f, t) = (std::ffi::CString::new(from), std::ffi::CString::new(to));
    let (f, t) = (
        f.map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in name"))?,
        t.map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in name"))?,
    );
    if unsafe { libc::renameat(dir.as_raw_fd(), f.as_ptr(), dir.as_raw_fd(), t.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Write-then-rename `contents` to `path`, entirely relative to one
/// walked directory descriptor: the temp file is opened
/// `O_CREAT|O_EXCL|O_NOFOLLOW` and renamed within that same directory,
/// so neither a symlink at `<name>.tmp`, at `<name>`, nor at any
/// intermediate component can redirect the write. A symlink planted at
/// `<name>` is replaced by the rename, never written through.
pub fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = file_name(path)?;
    let dir = create_and_open_dir_no_follow(parent)?;
    let tmp = format!("{name}.tmp");
    {
        let mut f = openat_excl_with_retry(&dir, &tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    renameat_within(&dir, &tmp, name)
}

/// Why [`read_owned_no_follow`] returned no contents.
#[derive(Debug)]
pub enum OwnedReadError {
    /// Someone other than this process's effective uid could have
    /// written the file or put it there: it, or the directory holding
    /// it, is owned by another uid or writable by group or others, or an
    /// ancestor directory lets a third account rename what it holds.
    /// Also a final component that is not a regular file.
    Untrusted(String),
    /// Larger than the caller's bound; nothing was read.
    TooLarge { len: u64, max: u64 },
    /// Anything else: an I/O error, or a symlink at any component.
    Io(std::io::Error),
}

impl std::fmt::Display for OwnedReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OwnedReadError::Untrusted(why) => write!(f, "{why}"),
            OwnedReadError::TooLarge { len, max } => {
                write!(f, "{len} bytes, past the {max}-byte bound")
            }
            OwnedReadError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl From<std::io::Error> for OwnedReadError {
    fn from(e: std::io::Error) -> Self {
        OwnedReadError::Io(e)
    }
}

/// Read `path` as [`read_no_follow`] does, but only a file this process
/// can vouch for, and never more than `max_len` bytes.
///
/// For records whose contents the reader ACTS on as root — routes to
/// install, say — where "no symlink" is not enough: if another account
/// can write `state-dir`, it can create the file outright. Checked on
/// descriptors, never by path, so what is checked is what is read:
///
/// - the file: a regular file, owned by this process's euid, not
///   writable by group or others;
/// - the directory holding it: owned by the euid, not writable by group
///   or others — otherwise its contents are whoever-can-write's choice,
///   whoever owns the files (a writable directory also lets `rename`
///   bring in a root-owned file written for another purpose);
/// - every ancestor, to `/`: owned by root or the euid, and either not
///   writable by group or others or sticky. Under a parent a third
///   account can write, two root-owned directories can have their names
///   exchanged without a byte of either changing (the same rule
///   `daemon_presence`'s `dir_is_authentic` applies to the pid file, for
///   the same review finding).
///
/// Only then is the size compared with `max_len` (from `fstat`, before
/// any read) and the file read through a reader that stops one byte past
/// it, so a file that grows after the `fstat` is refused too. The open
/// is `O_NONBLOCK`, so a FIFO at the name is refused rather than waited
/// on.
///
/// `Ok(None)` when the file or a directory on the way does not exist.
pub fn read_owned_no_follow(path: &Path, max_len: u64) -> Result<Option<Vec<u8>>, OwnedReadError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let euid = unsafe { libc::geteuid() };
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = file_name(path)?;
    let dir = match open_owned_dir(parent, euid) {
        Ok(d) => d,
        Err(OwnedReadError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name"))?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(e.into());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nothing
    // else.
    let f = unsafe { std::fs::File::from_raw_fd(fd) };
    let meta = f.metadata()?;
    let ft = meta.file_type();
    if !ft.is_file() {
        let kind = if ft.is_fifo() {
            "a FIFO"
        } else if ft.is_dir() {
            "a directory"
        } else {
            "not a regular file"
        };
        return Err(OwnedReadError::Untrusted(format!(
            "{} is {kind}",
            path.display()
        )));
    }
    if meta.uid() != euid {
        return Err(OwnedReadError::Untrusted(format!(
            "{} is owned by uid {}, not this process's uid {euid}",
            path.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(OwnedReadError::Untrusted(format!(
            "{} is writable by group or others (mode {:04o})",
            path.display(),
            meta.mode() & 0o7777
        )));
    }
    if meta.len() > max_len {
        return Err(OwnedReadError::TooLarge {
            len: meta.len(),
            max: max_len,
        });
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    (&f).take(max_len.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > max_len {
        return Err(OwnedReadError::TooLarge {
            len: buf.len() as u64,
            max: max_len,
        });
    }
    Ok(Some(buf))
}

/// The non-creating no-follow walk of [`open_dir_no_follow`], judging
/// every directory on the way by its descriptor: each ancestor (root
/// included) owned by root or `euid` and either closed to group and
/// others or sticky, and the final directory owned by `euid` and closed
/// to group and others. See [`read_owned_no_follow`].
fn open_owned_dir(path: &Path, euid: libc::uid_t) -> Result<std::fs::File, OwnedReadError> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("state paths must be absolute: {}", path.display()),
        )
        .into());
    }
    let mut names = Vec::new();
    for comp in path.components() {
        match comp {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::Normal(n) => names.push(n.to_owned()),
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("refusing path component {other:?} in {}", path.display()),
                )
                .into())
            }
        }
    }
    let judge = |dir: &std::fs::File, shown: &Path, last: bool| -> Result<(), OwnedReadError> {
        let meta = dir.metadata()?;
        let (uid, mode) = (meta.uid(), meta.mode());
        if last {
            if uid != euid {
                return Err(OwnedReadError::Untrusted(format!(
                    "the directory {} is owned by uid {uid}, not this process's uid {euid}",
                    shown.display()
                )));
            }
            if mode & 0o022 != 0 {
                return Err(OwnedReadError::Untrusted(format!(
                    "the directory {} is writable by group or others (mode {:04o})",
                    shown.display(),
                    mode & 0o7777
                )));
            }
        } else {
            if uid != 0 && uid != euid {
                return Err(OwnedReadError::Untrusted(format!(
                    "its ancestor {} is owned by uid {uid}, not root",
                    shown.display()
                )));
            }
            // 0o1000: the sticky bit, under which only an entry's owner
            // may rename or remove it.
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(OwnedReadError::Untrusted(format!(
                    "its ancestor {} is writable by group or others and not sticky (mode \
                     {:04o}), so another account could rename the directories under it",
                    shown.display(),
                    mode & 0o7777
                )));
            }
        }
        Ok(())
    };
    let mut dir = std::fs::File::open("/")?;
    let mut shown = PathBuf::from("/");
    judge(&dir, &shown, names.is_empty())?;
    for (i, name) in names.iter().enumerate() {
        let c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path component")
        })?;
        let fd = open_component(&dir, &c, false).map_err(|e: std::io::Error| {
            std::io::Error::new(
                e.kind(),
                format!(
                    "open component {name:?} of {}: {e} (a symlink here is refused)",
                    path.display()
                ),
            )
        })?;
        // SAFETY: `fd` was just returned by openat and is owned by
        // nothing else.
        dir = unsafe { std::fs::File::from_raw_fd(fd) };
        shown.push(name);
        judge(&dir, &shown, i + 1 == names.len())?;
    }
    Ok(dir)
}

/// Read `path` without following a symlink at any component. `Ok(None)`
/// when the file (or its directory) does not exist; a symlink anywhere
/// is an error (`ELOOP`), not a read of its target.
pub fn read_no_follow(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = file_name(path)?;
    let dir = match open_dir_no_follow(parent) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name"))?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(e);
    }
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    Ok(Some(buf))
}

fn file_name(path: &Path) -> std::io::Result<&str> {
    path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("pf-statefile-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_planted_symlink_is_replaced_not_written_through() {
        let dir = tmpdir("plant");
        let victim = dir.join("victim");
        std::fs::write(&victim, "do not truncate me").unwrap();
        let rec = dir.join("record.json");
        std::os::unix::fs::symlink(&victim, &rec).unwrap();
        // And one at the temp name, which the O_EXCL open must refuse
        // to follow (the retry only unlinks regular files).
        let tmp = dir.join("record.json.tmp");
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        assert!(write_atomic(&rec, b"{}").is_err(), "symlinked .tmp refused");
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "do not truncate me"
        );

        std::fs::remove_file(&tmp).unwrap();
        write_atomic(&rec, b"{}").expect("write");
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "do not truncate me"
        );
        assert_eq!(std::fs::read(&rec).unwrap(), b"{}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_refuse_symlinks_and_absence_is_none() {
        let dir = tmpdir("read");
        let victim = dir.join("victim");
        std::fs::write(&victim, "secret").unwrap();
        let rec = dir.join("record.json");
        assert!(read_no_follow(&rec).unwrap().is_none());
        assert!(read_no_follow(&dir.join("missing-dir/record.json"))
            .unwrap()
            .is_none());
        std::os::unix::fs::symlink(&victim, &rec).unwrap();
        assert!(
            read_no_follow(&rec).is_err(),
            "symlink is ELOOP, not a read"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_intermediate_symlink_is_refused() {
        let dir = tmpdir("mid");
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let hop = dir.join("hop");
        std::os::unix::fs::symlink(&real, &hop).unwrap();
        assert!(write_atomic(&hop.join("record.json"), b"{}").is_err());
        assert!(!real.join("record.json").exists());
        // The state files stay strict even for a link the event log's
        // walk would follow.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(open_dir_trusted_links(&hop, false, "event-log").is_ok());
        assert!(create_and_open_dir_no_follow(&hop).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A temp dir that group and others cannot write, as a root-owned
    /// appliance directory would be.
    fn closed_tmpdir(tag: &str) -> std::path::PathBuf {
        let d = tmpdir(tag);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        d
    }

    fn follow(path: &Path, create: bool) -> std::io::Result<std::fs::File> {
        open_dir_trusted_links(path, create, "event-log")
    }

    fn same_dir(f: &std::fs::File, p: &Path) -> bool {
        use std::os::unix::fs::MetadataExt;
        let (a, b) = (f.metadata().unwrap(), std::fs::metadata(p).unwrap());
        (a.dev(), a.ino()) == (b.dev(), b.ino())
    }

    fn refusal(r: std::io::Result<std::fs::File>) -> String {
        let msg = r.expect_err("the walk should refuse").to_string();
        assert!(
            msg.contains("point `event-log` at the resolved path"),
            "no hint in: {msg}"
        );
        msg
    }

    #[test]
    fn a_trusted_symlinked_directory_is_followed() {
        let dir = closed_tmpdir("trusted");
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        // Absolute, as an appliance's persistent-storage link is.
        let persist = dir.join("persist");
        std::os::unix::fs::symlink(&real, &persist).unwrap();
        let f = follow(&persist.join("packetframe"), true).expect("followed");
        assert!(
            same_dir(&f, &real.join("packetframe")),
            "created in the target"
        );

        // Relative, and `..` in a target stepping back out of `sub`.
        std::os::unix::fs::symlink("real", dir.join("rel")).unwrap();
        let f = follow(&dir.join("rel/packetframe"), false).expect("relative");
        assert!(same_dir(&f, &real.join("packetframe")));
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("../real", sub.join("up")).unwrap();
        let f = follow(&sub.join("up/packetframe"), false).expect("dot-dot");
        assert!(same_dir(&f, &real.join("packetframe")));

        // A link to a link: each hop is judged by the same rule.
        std::os::unix::fs::symlink(&persist, dir.join("again")).unwrap();
        let f = follow(&dir.join("again/packetframe"), false).expect("chained");
        assert!(same_dir(&f, &real.join("packetframe")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlink_owned_by_an_untrusted_uid_is_refused() {
        let dir = closed_tmpdir("owner");
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, dir.join("persist")).unwrap();
        // Everything here is ours; trust some other uid only, so the
        // link reads as another user's. (Root is only implicitly trusted
        // by `open_dir_trusted_links`, not by this set.)
        let other = unsafe { libc::geteuid() }.wrapping_add(1);
        let msg = refusal(walk_dir(
            &dir.join("persist/packetframe"),
            true,
            Links::FollowTrusted {
                trusted: &[other],
                setting: "event-log",
            },
        ));
        assert!(msg.contains("the link is owned by uid"), "{msg}");
        assert!(!real.join("packetframe").exists(), "nothing created");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Ownership that only root can arrange; skipped for other users.
    #[test]
    fn foreign_ownership_is_refused_when_running_as_root() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root to chown");
            return;
        }
        const NOBODY: u32 = 65534;
        let dir = closed_tmpdir("chown");
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = dir.join("persist");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        std::os::unix::fs::lchown(&link, Some(NOBODY), None).unwrap();
        let msg = refusal(follow(&link.join("packetframe"), true));
        assert!(msg.contains("the link is owned by uid 65534"), "{msg}");

        std::os::unix::fs::lchown(&link, Some(0), None).unwrap();
        std::os::unix::fs::chown(&dir, Some(NOBODY), None).unwrap();
        let msg = refusal(follow(&link.join("packetframe"), true));
        assert!(msg.contains("holding it is owned by uid 65534"), "{msg}");
        assert!(!real.join("packetframe").exists(), "nothing created");

        std::os::unix::fs::chown(&dir, Some(0), None).unwrap();
        assert!(follow(&link.join("packetframe"), true).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlink_in_a_group_or_world_writable_directory_is_refused() {
        let dir = closed_tmpdir("writable");
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, dir.join("persist")).unwrap();
        for mode in [0o775, 0o757, 0o1777] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let msg = refusal(follow(&dir.join("persist/packetframe"), true));
            assert!(
                msg.contains("writable by group or others"),
                "{mode:o}: {msg}"
            );
            assert!(
                !real.join("packetframe").exists(),
                "{mode:o}: nothing created"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn link_chains_are_bounded_and_loops_refused() {
        let dir = closed_tmpdir("loop");
        std::os::unix::fs::symlink("b", dir.join("a")).unwrap();
        std::os::unix::fs::symlink("a", dir.join("b")).unwrap();
        let msg = refusal(follow(&dir.join("a/packetframe"), true));
        assert!(msg.contains("more than 8 symlinks"), "{msg}");

        // Exactly MAX_LINKS hops are followed; one more is refused.
        std::fs::create_dir(dir.join("real")).unwrap();
        std::os::unix::fs::symlink("real", dir.join("l1")).unwrap();
        for i in 2..=MAX_LINKS + 1 {
            std::os::unix::fs::symlink(format!("l{}", i - 1), dir.join(format!("l{i}"))).unwrap();
        }
        assert!(follow(&dir.join(format!("l{MAX_LINKS}")), false).is_ok());
        let msg = refusal(follow(&dir.join(format!("l{}", MAX_LINKS + 1)), false));
        assert!(msg.contains("more than 8 symlinks"), "{msg}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn untrusted(r: Result<Option<Vec<u8>>, OwnedReadError>) -> String {
        match r {
            Err(OwnedReadError::Untrusted(why)) => why,
            other => panic!("expected an untrusted refusal, got {other:?}"),
        }
    }

    /// What `write_atomic` leaves is read back; absence is `None`; a
    /// symlink is still an I/O refusal, not a read.
    #[test]
    fn an_owned_read_returns_what_this_process_wrote() {
        let dir = closed_tmpdir("owned");
        let rec = dir.join("record.bin");
        assert!(read_owned_no_follow(&rec, 64).unwrap().is_none());
        assert!(read_owned_no_follow(&dir.join("missing/record.bin"), 64)
            .unwrap()
            .is_none());
        write_atomic(&rec, b"payload").unwrap();
        assert_eq!(
            read_owned_no_follow(&rec, 64).unwrap().as_deref(),
            Some(&b"payload"[..])
        );
        // Exactly at the bound is fine.
        assert!(read_owned_no_follow(&rec, 7).unwrap().is_some());
        std::fs::remove_file(&rec).unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), &rec).unwrap();
        assert!(matches!(
            read_owned_no_follow(&rec, 64),
            Err(OwnedReadError::Io(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The size is judged from `fstat`, before any read: a sparse file
    /// claiming 64 GiB is refused without a byte of it read (were it read,
    /// this test would try to allocate all of it).
    #[test]
    fn an_owned_read_refuses_a_file_past_its_bound_before_reading() {
        let dir = closed_tmpdir("owned-big");
        let rec = dir.join("record.bin");
        write_atomic(&rec, b"12345678").unwrap();
        match read_owned_no_follow(&rec, 7) {
            Err(OwnedReadError::TooLarge { len: 8, max: 7 }) => {}
            other => panic!("{other:?}"),
        }
        let f = std::fs::OpenOptions::new().write(true).open(&rec).unwrap();
        f.set_len(1 << 36).unwrap();
        drop(f);
        match read_owned_no_follow(&rec, 1 << 20) {
            Err(OwnedReadError::TooLarge { len, max }) => {
                assert_eq!((len, max), (1 << 36, 1 << 20));
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Group- or world-writable: the file, or the directory holding it.
    /// Any uid can run this half (it only chmods its own files).
    #[test]
    fn an_owned_read_refuses_writable_files_and_directories() {
        let dir = closed_tmpdir("owned-perm");
        let rec = dir.join("record.bin");
        write_atomic(&rec, b"payload").unwrap();
        for mode in [0o620, 0o602, 0o666] {
            std::fs::set_permissions(&rec, std::fs::Permissions::from_mode(mode)).unwrap();
            let why = untrusted(read_owned_no_follow(&rec, 64));
            assert!(
                why.contains("writable by group or others"),
                "{mode:o}: {why}"
            );
        }
        std::fs::set_permissions(&rec, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_owned_no_follow(&rec, 64).unwrap().is_some());
        // Readable by others is not a write: 0644 is fine.
        std::fs::set_permissions(&rec, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_owned_no_follow(&rec, 64).unwrap().is_some());

        for mode in [0o775, 0o757, 0o1777] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let why = untrusted(read_owned_no_follow(&rec, 64));
            assert!(
                why.contains("the directory") && why.contains("writable by group or others"),
                "{mode:o}: {why}"
            );
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        // An ancestor others can write lets them rename this directory
        // away and another into its place — unless it is sticky.
        let inner = dir.join("state");
        std::fs::create_dir(&inner).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rec = inner.join("record.bin");
        write_atomic(&rec, b"payload").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let why = untrusted(read_owned_no_follow(&rec, 64));
        assert!(why.contains("its ancestor"), "{why}");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(read_owned_no_follow(&rec, 64).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A FIFO at the name is refused, not waited on: the open is
    /// non-blocking and the type is checked before any read.
    #[test]
    fn an_owned_read_refuses_a_fifo_without_blocking() {
        let dir = closed_tmpdir("owned-fifo");
        let rec = dir.join("record.bin");
        let c = std::ffi::CString::new(rec.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let why = untrusted(read_owned_no_follow(&rec, 64));
        assert!(why.contains("FIFO"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Owned by another uid: the file, the directory holding it, or an
    /// ancestor. Needs root to chown.
    #[test]
    fn an_owned_read_refuses_foreign_ownership_when_running_as_root() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root to chown");
            return;
        }
        const NOBODY: u32 = 65534;
        let dir = closed_tmpdir("owned-chown");
        let inner = dir.join("state");
        std::fs::create_dir(&inner).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o755)).unwrap();
        let rec = inner.join("record.bin");
        write_atomic(&rec, b"payload").unwrap();
        assert!(read_owned_no_follow(&rec, 64).unwrap().is_some());

        std::os::unix::fs::chown(&rec, Some(NOBODY), None).unwrap();
        let why = untrusted(read_owned_no_follow(&rec, 64));
        assert!(why.contains("owned by uid 65534"), "{why}");
        std::os::unix::fs::chown(&rec, Some(0), None).unwrap();

        std::os::unix::fs::chown(&inner, Some(NOBODY), None).unwrap();
        let why = untrusted(read_owned_no_follow(&rec, 64));
        assert!(
            why.contains("the directory") && why.contains("owned by uid 65534"),
            "{why}"
        );
        std::os::unix::fs::chown(&inner, Some(0), None).unwrap();

        std::os::unix::fs::chown(&dir, Some(NOBODY), None).unwrap();
        let why = untrusted(read_owned_no_follow(&rec, 64));
        assert!(
            why.contains("its ancestor") && why.contains("owned by uid 65534"),
            "{why}"
        );
        std::os::unix::fs::chown(&dir, Some(0), None).unwrap();
        assert!(read_owned_no_follow(&rec, 64).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
