//! The sampler directory's files (Linux).
//!
//! - The plugin calls [`check_dir`], [`reclaim`] (keeping the epoch
//!   `current` names), [`create_epoch`] and [`publish_current`], in that
//!   order, once per VPP run.
//! - The consumer takes [`CONSUMER_LOCK`] with [`Lock::try_exclusive`] and
//!   keeps it across epochs, then [`open_epoch`]s whatever `current` names.
//! - PacketFrame writes `desired.conf` with [`write_atomic`] while holding
//!   [`DESIRED_LOCK`].
//!
//! The directory must be the root of its own tmpfs mount with an explicit
//! `size=`: an unlinked epoch file stays allocated for as long as anyone
//! maps it, so only a filesystem-wide limit bounds the memory a stuck
//! reader can pin. The plugin refuses any other directory.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

use crate::current::{epoch_file_name, is_epoch_file_name, Current, CurrentError};
use crate::layout::{self, Header, Layout, LayoutError};
use crate::ring::RingReader;
use crate::status::{Status, StatusReader, StatusWriter};
use crate::sync::AtomicU64;

/// Where the plugin looks when [`ENV_DIR`] is unset.
pub const DEFAULT_DIR: &str = "/run/packetframe/vpp/sampler";
/// The environment variable PacketFrame sets for VPP to move the directory.
pub const ENV_DIR: &str = "PF_SAMPLER_DIR";
pub const DESIRED: &str = "desired.conf";
pub const DESIRED_LOCK: &str = "desired.lock";
pub const CURRENT: &str = "current";
pub const CONSUMER_LOCK: &str = "consumer.lock";

const TMPFS_MAGIC: i64 = 0x0102_1994;

#[derive(Debug, thiserror::Error)]
pub enum DirError {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("{0} is not an absolute path")]
    Relative(PathBuf),
    #[error("{0} is not a directory")]
    NotDir(PathBuf),
    #[error("{0} has mode {1:04o}; it must be 0700")]
    Mode(PathBuf, u32),
    #[error("{0} is not on a tmpfs")]
    NotTmpfs(PathBuf),
    #[error("{0} is not the root of a tmpfs mounted with an explicit size=")]
    NotSizeLimited(PathBuf),
}

/// Checks that `dir` can hold epoch files; returns the tmpfs size in bytes.
pub fn check_dir(dir: &Path) -> Result<u64, DirError> {
    let io = |source| DirError::Io {
        path: dir.to_owned(),
        source,
    };
    if !dir.is_absolute() {
        return Err(DirError::Relative(dir.to_owned()));
    }
    let real = fs::canonicalize(dir).map_err(io)?;
    let meta = fs::metadata(&real).map_err(io)?;
    if !meta.is_dir() {
        return Err(DirError::NotDir(dir.to_owned()));
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode != 0o700 {
        return Err(DirError::Mode(dir.to_owned(), mode));
    }
    let c = std::ffi::CString::new(real.as_os_str().as_bytes())
        .map_err(|_| DirError::NotDir(dir.to_owned()))?;
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut st) } != 0 {
        return Err(io(io::Error::last_os_error()));
    }
    // `f_type` is `__fsword_t` (i64) on glibc but `c_ulong` on musl.
    #[allow(clippy::unnecessary_cast)]
    if st.f_type as i64 != TMPFS_MAGIC {
        return Err(DirError::NotTmpfs(dir.to_owned()));
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").map_err(io)?;
    if !size_limited_tmpfs_root(&mountinfo, &real) {
        return Err(DirError::NotSizeLimited(dir.to_owned()));
    }
    #[allow(clippy::unnecessary_cast)]
    Ok(st.f_blocks as u64 * st.f_bsize as u64)
}

/// Whether the topmost mount at exactly `dir` is a tmpfs with `size=` in
/// its superblock options. tmpfs prints `size=` only when it is not the
/// default (half of RAM), so its presence means someone chose a limit.
fn size_limited_tmpfs_root(mountinfo: &str, dir: &Path) -> bool {
    let want = dir.as_os_str().as_bytes();
    let mut found = None;
    for line in mountinfo.lines() {
        // id parent major:minor root mount-point options [optional...] - fstype source super-options
        let Some((pre, post)) = line.split_once(" - ") else {
            continue;
        };
        let Some(mount_point) = pre.split(' ').nth(4) else {
            continue;
        };
        if unescape_octal(mount_point) != want {
            continue;
        }
        let mut f = post.split(' ');
        let (fstype, _source, opts) = (f.next(), f.next(), f.next().unwrap_or(""));
        // Later lines are mounted over earlier ones at the same point.
        found = Some(fstype == Some("tmpfs") && opts.split(',').any(|o| o.starts_with("size=")));
    }
    found == Some(true)
}

/// mountinfo escapes space, tab, newline and backslash as `\ooo`.
fn unescape_octal(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 4 <= b.len()
            && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c))
        {
            out.push((b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0'));
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// A shared mapping of (part of) a file, as words. Unmapped on drop.
pub struct Mapping {
    ptr: NonNull<libc::c_void>,
    len: usize,
}

// The mapping is plain shared memory, accessed only through atomics.
unsafe impl Send for Mapping {}
unsafe impl Sync for Mapping {}

impl Mapping {
    /// Maps `len` bytes of `file` from `offset` (a multiple of the page
    /// size), shared, read-only or read-write; `populate` faults every page
    /// in now rather than on first touch.
    pub fn map(
        file: &File,
        offset: usize,
        len: usize,
        writable: bool,
        populate: bool,
    ) -> io::Result<Self> {
        if len == 0 || !len.is_multiple_of(layout::WORD) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "length is not a positive multiple of 8",
            ));
        }
        let prot = libc::PROT_READ | if writable { libc::PROT_WRITE } else { 0 };
        let flags = libc::MAP_SHARED | if populate { libc::MAP_POPULATE } else { 0 };
        let off = libc::off_t::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset"))?;
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                prot,
                flags,
                file.as_raw_fd(),
                off,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            ptr: NonNull::new(p).expect("mmap returned NULL"),
            len,
        })
    }

    /// The mapping as words. Page alignment satisfies `AtomicU64`'s, and
    /// the slice cannot outlive the mapping.
    pub fn words(&self) -> &[AtomicU64] {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast(), self.len / layout::WORD) }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr.as_ptr(), self.len) };
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EpochError {
    #[error("the sampler tmpfs has no room for a {0}-byte epoch file: its budget is used up")]
    Budget(usize),
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

/// A random epoch identifier.
pub fn random_epoch() -> u64 {
    let mut b = [0u8; 8];
    let n = unsafe { libc::getrandom(b.as_mut_ptr().cast(), b.len(), 0) };
    if n != 8 {
        // getrandom cannot fail for 8 bytes once the pool is seeded; fall
        // back to the clock rather than a constant if it ever does.
        return std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
    }
    u64::from_ne_bytes(b)
}

/// Creates, sizes, maps and initialises a new epoch file: header, an
/// [`crate::status::State::Initializing`] status and a first heartbeat,
/// then marks it ready. It is not yet named by `current`
/// ([`publish_current`]). On any failure the partial file is removed.
pub fn create_epoch(
    dir: &Path,
    layout: &Layout,
    epoch: u64,
    created_ns: u64,
    monotonic_ns: u64,
    build: &str,
) -> Result<Mapping, EpochError> {
    let path = dir.join(epoch_file_name(epoch));
    let fail = |source: io::Error| {
        let _ = fs::remove_file(&path);
        EpochError::Io {
            path: path.clone(),
            source,
        }
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|source| EpochError::Io {
            path: path.clone(),
            source,
        })?;
    let len = layout.file_len();
    // fallocate, not just ftruncate: a sparse file would pass here and
    // then SIGBUS a VPP worker on first touch once the tmpfs is full.
    let r = unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, len as libc::off_t) };
    if r != 0 {
        let e = io::Error::last_os_error();
        let _ = fs::remove_file(&path);
        return Err(if e.raw_os_error() == Some(libc::ENOSPC) {
            EpochError::Budget(len)
        } else {
            EpochError::Io {
                path: path.clone(),
                source: e,
            }
        });
    }
    let map = Mapping::map(&file, 0, len, true, true).map_err(fail)?;
    let w = map.words();
    layout.write_header(w, epoch, created_ns, build);
    let status = StatusWriter::new(layout.status(w));
    status.publish(&Status {
        changed_ns: created_ns,
        ..Status::default()
    });
    status.beat(monotonic_ns);
    layout::mark_ready(w);
    Ok(map)
}

/// Writes `contents` to `dir/name` by rename, so readers see the old file
/// or the new one, never part of either.
pub fn write_atomic(dir: &Path, name: &str, contents: &[u8]) -> io::Result<()> {
    let tmp = dir.join(format!(".{name}.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let written = f.write_all(contents).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, dir.join(name))) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Names `epoch` as the one to read.
pub fn publish_current(dir: &Path, epoch: u64, layout: &Layout) -> io::Result<()> {
    let c = Current {
        epoch,
        layout: layout::VERSION,
        size: layout.file_len() as u64,
    };
    write_atomic(dir, CURRENT, c.render().as_bytes())
}

/// Unlinks every epoch file not named in `keep`, including partial ones
/// `current` never named; returns the names removed. Memory comes back
/// when the last process mapping each one unmaps it.
pub fn reclaim(dir: &Path, keep: &[u64]) -> io::Result<Vec<String>> {
    let keep: Vec<String> = keep.iter().map(|&e| epoch_file_name(e)).collect();
    let mut removed = Vec::new();
    for entry in fs::read_dir(dir)? {
        let name = entry?.file_name();
        let Some(name) = name.to_str() else { continue };
        if is_epoch_file_name(name) && !keep.iter().any(|k| k == name) {
            fs::remove_file(dir.join(name))?;
            removed.push(name.to_owned());
        }
    }
    Ok(removed)
}

/// An exclusive `flock` on a file that is never removed: released when
/// dropped or when the holding process dies, so a crashed holder can be
/// replaced.
pub struct Lock {
    _file: File,
}

impl Lock {
    /// `Ok(None)` when another open of the file holds it.
    pub fn try_exclusive(path: &Path) -> io::Result<Option<Self>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = io::Error::last_os_error();
            return match e.raw_os_error() {
                Some(libc::EWOULDBLOCK) => Ok(None),
                _ => Err(e),
            };
        }
        Ok(Some(Self { _file: file }))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("no epoch is published (`current` is missing)")]
    NoCurrent,
    #[error(transparent)]
    Current(#[from] CurrentError),
    #[error("`current` names layout version {0}; this build reads version {v}", v = layout::VERSION)]
    Incompatible(u64),
    #[error(transparent)]
    Layout(#[from] LayoutError),
    #[error("{0}")]
    Mismatch(&'static str),
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
}

/// An epoch file as a reader holds it: all of it read-only, and the
/// consumer region also writable when opened to consume.
pub struct Opened {
    pub current: Current,
    pub header: Header,
    file: Mapping,
    consumer: Option<Mapping>,
}

impl Opened {
    pub fn layout(&self) -> &Layout {
        &self.header.layout
    }

    pub fn file(&self) -> &[AtomicU64] {
        self.file.words()
    }

    pub fn status(&self) -> StatusReader<'_> {
        StatusReader::new(self.layout().status(self.file()))
    }

    /// Ring `ring`'s consumer end; `None` when opened only to observe.
    pub fn ring(&self, ring: usize) -> Option<RingReader<'_>> {
        let consumer = self.consumer.as_ref()?;
        Some(RingReader::new(
            self.layout(),
            self.file(),
            consumer.words(),
            ring,
        ))
    }
}

/// Opens the epoch `current` names in `dir`. With `consume`, the consumer
/// region is also mapped writable: the caller must hold [`CONSUMER_LOCK`].
pub fn open_epoch(dir: &Path, consume: bool) -> Result<Opened, OpenError> {
    let cur_path = dir.join(CURRENT);
    let text = match fs::read_to_string(&cur_path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(OpenError::NoCurrent),
        Err(source) => {
            return Err(OpenError::Io {
                path: cur_path,
                source,
            })
        }
    };
    let current = Current::parse(&text)?;
    if !current.readable() {
        return Err(OpenError::Incompatible(current.layout));
    }
    let path = dir.join(current.file_name());
    let io = |source| OpenError::Io {
        path: path.clone(),
        source,
    };
    let file = OpenOptions::new()
        .read(true)
        .write(consume)
        .open(&path)
        .map_err(io)?;
    let len = file.metadata().map_err(io)?.len();
    if len != current.size {
        return Err(OpenError::Mismatch(
            "the epoch file's size differs from `current`",
        ));
    }
    let len = usize::try_from(len).map_err(|_| OpenError::Mismatch("size"))?;
    if !(layout::hdr::WORDS * layout::WORD..=layout::MAX_FILE_BYTES).contains(&len) {
        return Err(OpenError::Mismatch("the epoch file's size is implausible"));
    }
    let whole = Mapping::map(&file, 0, len, false, false).map_err(io)?;
    let header = layout::read_header(whole.words())?;
    if header.epoch != current.epoch {
        return Err(OpenError::Mismatch(
            "the epoch file's header names another epoch",
        ));
    }
    let consumer = if consume {
        let l = &header.layout;
        Some(Mapping::map(&file, l.consumer_offset(), l.consumer_len(), true, false).map_err(io)?)
    } else {
        None
    };
    Ok(Opened {
        current,
        header,
        file: whole,
        consumer,
    })
}

/// Creates `dir` with mode 0700 if it does not exist (for tests and lab
/// tools; in production PacketFrame mounts the tmpfs there).
pub fn ensure_dir(dir: &Path) -> io::Result<()> {
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::Layout;
    use crate::ring::{RingWriter, SampleMeta};
    use crate::status::State;
    use crate::Class;

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pf-shm-{tag}-{}-{}",
            std::process::id(),
            random_epoch()
        ));
        ensure_dir(&d).unwrap();
        d
    }

    #[test]
    fn mountinfo_lookup_wants_the_topmost_size_limited_tmpfs() {
        let mi = "\
22 1 0:21 / /run rw,nosuid shared:5 - tmpfs tmpfs rw,size=1600000k,mode=755\n\
40 22 0:40 / /run/pf\\040x rw - tmpfs tmpfs rw,size=4096k,mode=700\n\
41 22 0:41 / /run/pf rw - tmpfs tmpfs rw,mode=700\n\
42 22 0:42 / /run/pf2 rw - tmpfs tmpfs rw,size=1m\n\
43 42 0:43 / /run/pf2 rw - ext4 /dev/sda1 rw\n";
        assert!(size_limited_tmpfs_root(mi, Path::new("/run")));
        assert!(size_limited_tmpfs_root(mi, Path::new("/run/pf x")));
        assert!(
            !size_limited_tmpfs_root(mi, Path::new("/run/pf")),
            "default size"
        );
        assert!(
            !size_limited_tmpfs_root(mi, Path::new("/run/pf2")),
            "covered by ext4"
        );
        assert!(
            !size_limited_tmpfs_root(mi, Path::new("/run/other")),
            "not a mount point"
        );
    }

    #[test]
    fn check_dir_refuses_what_is_not_a_private_tmpfs_root() {
        let d = tempdir("check");
        assert!(matches!(
            check_dir(Path::new("relative")),
            Err(DirError::Relative(_))
        ));
        fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(check_dir(&d), Err(DirError::Mode(_, 0o755))));
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        // A temp dir is not the root of its own size-limited tmpfs, whatever
        // filesystem it is on.
        assert!(matches!(
            check_dir(&d),
            Err(DirError::NotTmpfs(_) | DirError::NotSizeLimited(_))
        ));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn an_epoch_is_created_once_published_and_reopened() {
        let d = tempdir("epoch");
        let l = Layout::new(2, 64, 128).unwrap();
        let map = create_epoch(&d, &l, 0xabc, 5, 6, "test build").unwrap();
        assert!(
            matches!(
                create_epoch(&d, &l, 0xabc, 5, 6, "again"),
                Err(EpochError::Io { .. })
            ),
            "O_EXCL"
        );
        assert!(matches!(open_epoch(&d, false), Err(OpenError::NoCurrent)));
        publish_current(&d, 0xabc, &l).unwrap();

        let w = RingWriter::new(&l, map.words(), 1);
        let m = SampleMeta {
            generation: 1,
            time_ns: 2,
            sw_if_index: 3,
            class: Class::Ingress,
            pool_index: 0,
            rate: 100,
            frame_len: 60,
        };
        assert!(w.push(&m, &[7; 60]));

        let o = open_epoch(&d, true).unwrap();
        assert_eq!(o.header.epoch, 0xabc);
        assert_eq!(o.header.build, "test build");
        let st = o.status().read().unwrap();
        assert_eq!(st.state, State::Initializing);
        assert_eq!(o.status().heartbeat(), 6);
        let mut out = Vec::new();
        assert_eq!(o.ring(1).unwrap().drain(&mut out, 8).taken, 1);
        assert_eq!(out[0].header, [7; 60]);
        // The consumer's tail went through its own writable mapping, and
        // the producer sees it.
        assert_eq!(crate::ring::counters(&l, map.words(), 1).tail, 1);
        assert!(
            open_epoch(&d, false).unwrap().ring(0).is_none(),
            "observer cannot drain"
        );
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_pointer_that_disagrees_with_its_file_is_refused() {
        let d = tempdir("mismatch");
        let l = Layout::new(1, 8, 0).unwrap();
        let _map = create_epoch(&d, &l, 1, 0, 0, "").unwrap();
        let wrong_size = Current {
            epoch: 1,
            layout: layout::VERSION,
            size: 8,
        };
        write_atomic(&d, CURRENT, wrong_size.render().as_bytes()).unwrap();
        assert!(matches!(open_epoch(&d, false), Err(OpenError::Mismatch(_))));
        let wrong_layout = Current {
            layout: 99,
            size: l.file_len() as u64,
            ..wrong_size
        };
        write_atomic(&d, CURRENT, wrong_layout.render().as_bytes()).unwrap();
        assert!(matches!(
            open_epoch(&d, false),
            Err(OpenError::Incompatible(99))
        ));
        write_atomic(&d, CURRENT, b"garbage").unwrap();
        assert!(matches!(open_epoch(&d, false), Err(OpenError::Current(_))));
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn reclaim_keeps_what_it_is_told_and_nothing_else() {
        let d = tempdir("reclaim");
        let l = Layout::new(1, 8, 0).unwrap();
        for e in [1, 2, 3] {
            drop(create_epoch(&d, &l, e, 0, 0, "").unwrap());
        }
        fs::write(d.join("desired.conf"), "x").unwrap();
        fs::write(d.join("epoch-notanepoch.shm"), "x").unwrap();
        let mut removed = reclaim(&d, &[2, 3]).unwrap();
        removed.sort();
        assert_eq!(removed, [epoch_file_name(1)]);
        assert!(d.join(epoch_file_name(3)).exists());
        assert!(d.join("desired.conf").exists());
        assert!(d.join("epoch-notanepoch.shm").exists());
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn write_atomic_replaces_and_leaves_no_temporaries() {
        let d = tempdir("atomic");
        write_atomic(&d, "f", b"one").unwrap();
        write_atomic(&d, "f", b"two").unwrap();
        assert_eq!(fs::read(d.join("f")).unwrap(), b"two");
        let names: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, ["f"]);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_lock_is_exclusive_per_open_and_released_on_drop() {
        let d = tempdir("lock");
        let p = d.join(CONSUMER_LOCK);
        let first = Lock::try_exclusive(&p).unwrap();
        assert!(first.is_some());
        assert!(Lock::try_exclusive(&p).unwrap().is_none());
        drop(first);
        assert!(Lock::try_exclusive(&p).unwrap().is_some());
        fs::remove_dir_all(&d).unwrap();
    }
}
