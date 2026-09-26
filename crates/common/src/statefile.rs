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

use std::io::{Read as _, Write as _};
use std::path::Path;

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
    walk_dir_no_follow(path, true)
}

/// The non-creating walk, for operations that have no business making
/// directories — removal in particular: if the walk cannot reach the
/// directory, there is nothing there this process is entitled to touch.
pub fn open_dir_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    walk_dir_no_follow(path, false)
}

fn walk_dir_no_follow(path: &Path, create: bool) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("state paths must be absolute: {}", path.display()),
        ));
    }
    let mut dir = std::fs::File::open("/")?;
    for comp in path.components() {
        let name = match comp {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(n) => n,
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("refusing path component {other:?} in {}", path.display()),
                ))
            }
        };
        let c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path component")
        })?;
        let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_CLOEXEC;
        let mut fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
        if create
            && fd < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
        {
            // Create it and re-open. A concurrent creator making this
            // mkdirat lose with EEXIST is fine — the reopen decides.
            unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o755) };
            fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
        }
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return Err(std::io::Error::new(
                e.kind(),
                format!(
                    "open component {name:?} of {}: {e} (a symlink here is refused)",
                    path.display()
                ),
            ));
        }
        dir = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    Ok(dir)
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
        let _ = std::fs::remove_dir_all(&dir);
    }
}
