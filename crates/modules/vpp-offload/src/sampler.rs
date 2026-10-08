//! The VPP sampler's directory (flow export): the size-limited tmpfs the
//! plugin refuses to work without (`packetframe_sampler_shm::fs::
//! check_dir`), prepared at attach, before VPP can start.
//!
//! Never fatal. VPP forwards the same with or without the sampler, so a
//! directory that cannot be prepared is the `sampler-dir` status row and
//! nothing else; flow export reports VPP coverage as uncovered, giving
//! the row's reason.
//!
//! **Ownership is a marker, not a flag.** A mount PacketFrame makes gets
//! an empty file `.packetframe-mount-<token>` at its root, and the token
//! is recorded beside the state file ([`MOUNT_RECORD`]). Only the mount
//! that still carries the recorded token is PacketFrame's, to reuse as its
//! own or to unmount: one an operator put there after ours went is someone
//! else's, whatever the record says. The record is a file of its own, not
//! a field of the state file, because an older build rewrites the state
//! file without the fields it does not know; losing ownership that way
//! would strand the mount until reboot, where an unknown file in the state
//! directory is simply left alone.
//!
//! A mount that is not PacketFrame's is used when it passes the plugin's
//! own check with room for three epochs beside whatever else it holds,
//! and is never unmounted; PacketFrame never mounts over one.
//!
//! Attach also removes a `desired.conf` left behind: with no flow export
//! configured to own it, the plugin stays off even in a reused directory
//! or an adopted VPP.

// The decision serves the Linux preparation only, but builds everywhere
// so its tests run on any host.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;
use std::path::Path;

use packetframe_common::module::{HealthState, SubsystemHealth};

/// Where the plugin is installed; startup.conf `add-path`s it.
pub const PLUGIN_DIR: &str = "/usr/lib/packetframe/vpp_plugins";

/// The status row's name.
pub const SUBSYS_SAMPLER_DIR: &str = "sampler-dir";

/// The record of PacketFrame's mount, in the state directory: its
/// marker's token, in hex.
pub const MOUNT_RECORD: &str = "vpp-sampler-mount";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamplerDir {
    /// Usable: a tmpfs of `bytes`, PacketFrame's own mount or not.
    Ready { bytes: u64, owned: bool },
    /// Not usable, and why.
    Unavailable(String),
}

impl SamplerDir {
    /// The `sampler-dir` row. Degraded when unavailable, but never folded
    /// into the module's overall health: forwarding does not depend on it.
    pub fn health(&self, dir: &Path) -> SubsystemHealth {
        let (state, message) = match self {
            Self::Ready { bytes, owned } => (
                HealthState::Healthy,
                format!(
                    "{}: tmpfs of {} KiB, {}",
                    dir.display(),
                    bytes >> 10,
                    if *owned {
                        "mounted by PacketFrame"
                    } else {
                        "an existing mount"
                    }
                ),
            ),
            Self::Unavailable(why) => (
                HealthState::Degraded,
                format!("unavailable, so VPP cannot sample (forwarding is unaffected): {why}"),
            ),
        };
        SubsystemHealth {
            name: SUBSYS_SAMPLER_DIR.into(),
            state,
            message: Some(message),
            last_success_age_seconds: None,
        }
    }
}

/// What the sampler needs of its tmpfs (`packetframe_sampler_core::
/// driver::dir_budget`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Need {
    /// The whole budget: three epochs and the small files.
    pub total: u64,
    /// The three epochs alone, which must fit beside anything else a
    /// mount that is not ours holds.
    pub epochs: u64,
}

/// The directory operations, a trait so the decisions are testable
/// without root.
pub(crate) trait DirOps {
    /// Create `dir` (mode 0700) if it does not exist; leave it if it does.
    fn ensure_dir(&self, dir: &Path) -> io::Result<()>;
    fn is_mount_point(&self, dir: &Path) -> io::Result<bool>;
    /// The plugin's own check: the tmpfs size, or why it would refuse.
    fn check(&self, dir: &Path) -> Result<u64, String>;
    /// Bytes in use on the tmpfs by anything but epoch files, which the
    /// plugin reclaims or counts in its budget.
    fn other_bytes(&self, dir: &Path) -> io::Result<u64>;
    fn has_marker(&self, dir: &Path, token: u64) -> bool;
    fn mount(&self, dir: &Path, bytes: u64) -> io::Result<()>;
    fn make_marker(&self, dir: &Path, token: u64) -> io::Result<()>;
    fn unmount(&self, dir: &Path) -> io::Result<()>;
}

/// Make `dir` usable for the sampler. `recorded`: the token recorded for
/// PacketFrame's mount; `fresh`: the token a new mount gets. Returns the
/// outcome and the token of PacketFrame's mount at `dir` afterwards.
pub(crate) fn prepare(
    ops: &dyn DirOps,
    dir: &Path,
    need: Need,
    recorded: Option<u64>,
    fresh: u64,
) -> (SamplerDir, Option<u64>) {
    let shown = dir.display();
    if let Err(e) = ops.ensure_dir(dir) {
        return (SamplerDir::Unavailable(format!("{shown}: {e}")), None);
    }
    match ops.is_mount_point(dir) {
        // Unknown: the record stands as it is.
        Err(e) => (
            SamplerDir::Unavailable(format!("{shown}: reading the mount table: {e}")),
            recorded,
        ),
        Ok(true) => {
            // Ours only if it still carries our marker.
            let ours = recorded.filter(|&t| ops.has_marker(dir, t));
            let total = match ops.check(dir) {
                Ok(t) => t,
                Err(e) => {
                    return (
                        SamplerDir::Unavailable(format!(
                            "{e}; PacketFrame does not mount over {}",
                            whose(ours)
                        )),
                        ours,
                    )
                }
            };
            if total < need.total {
                return (
                    SamplerDir::Unavailable(format!(
                        "{shown} holds {total} bytes and this VPP's sampler needs {}; \
                         PacketFrame does not mount over {}",
                        need.total,
                        whose(ours)
                    )),
                    ours,
                );
            }
            if ours.is_none() {
                // Sized by someone else and maybe holding their files: the
                // epochs must fit beside what is already there.
                match ops.other_bytes(dir) {
                    Ok(other) if other > total - need.epochs => {
                        return (
                            SamplerDir::Unavailable(format!(
                                "{shown} is {total} bytes, {other} of them held by other \
                                 files, leaving less than the sampler's {} bytes of epochs",
                                need.epochs
                            )),
                            None,
                        )
                    }
                    Err(e) => {
                        return (
                            SamplerDir::Unavailable(format!("{shown}: measuring its use: {e}")),
                            None,
                        )
                    }
                    Ok(_) => {}
                }
            }
            (
                SamplerDir::Ready {
                    bytes: total,
                    owned: ours.is_some(),
                },
                ours,
            )
        }
        // Nothing mounted (a record of one means ours was unmounted under
        // us): mount ours.
        Ok(false) => {
            if let Err(e) = ops.mount(dir, need.total) {
                return (
                    SamplerDir::Unavailable(format!("mounting a tmpfs at {shown}: {e}")),
                    None,
                );
            }
            if let Err(e) = ops.make_marker(dir, fresh) {
                // Unmarked, it could never be told from someone else's.
                let _ = ops.unmount(dir);
                return (
                    SamplerDir::Unavailable(format!("marking the mount at {shown}: {e}")),
                    None,
                );
            }
            match ops.check(dir) {
                Ok(total) => (
                    SamplerDir::Ready {
                        bytes: total,
                        owned: true,
                    },
                    Some(fresh),
                ),
                // Ours all the same: released with the rest.
                Err(e) => (SamplerDir::Unavailable(e), Some(fresh)),
            }
        }
    }
}

fn whose(ours: Option<u64>) -> &'static str {
    if ours.is_some() {
        "its own earlier mount"
    } else {
        "a mount it did not make"
    }
}

/// Unmount PacketFrame's mount at `dir`, if the one there carries the
/// recorded marker, and drop the record. A mount without it is someone
/// else's and stays.
pub(crate) fn release(ops: &dyn DirOps, dir: &Path, state_dir: &Path) -> Result<(), String> {
    let Some(token) = read_record(state_dir) else {
        return Ok(());
    };
    let shown = dir.display();
    match ops.is_mount_point(dir) {
        Err(e) => return Err(format!("{shown}: reading the mount table: {e}")),
        Ok(true) if ops.has_marker(dir, token) => match ops.unmount(dir) {
            Ok(()) => {}
            Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOENT)) => {}
            Err(e) => return Err(format!("unmount {shown}: {e}")),
        },
        Ok(_) => {}
    }
    remove_record(state_dir).map_err(|e| format!("removing the sampler mount record: {e}"))
}

fn marker_name(token: u64) -> String {
    format!(".packetframe-mount-{token:016x}")
}

/// The recorded token. The record decides what root unmounts, so it is
/// read only if this daemon's uid could have written it, and never past a
/// few bytes (`statefile::read_owned_no_follow`, as for the route ledger).
/// Unreadable, untrusted or malformed reads as no record: the safe
/// direction, since without one nothing is ever unmounted.
pub(crate) fn read_record(state_dir: &Path) -> Option<u64> {
    let bytes = match read_record_bytes(&state_dir.join(MOUNT_RECORD)) {
        Ok(b) => b?,
        Err(e) => {
            tracing::warn!(error = %e, "the VPP sampler's mount record is unreadable or untrusted; treated as absent");
            return None;
        }
    };
    u64::from_str_radix(std::str::from_utf8(&bytes).ok()?.trim(), 16).ok()
}

/// A token in hex and a newline, with room to spare.
const RECORD_MAX: u64 = 64;

// The state-dir primitives are Linux-only (they are `openat` walks); the
// dev-laptop build gets plain `std::fs`, the split ledger_record makes.
// Nothing privileged runs off Linux.
#[cfg(target_os = "linux")]
fn read_record_bytes(path: &Path) -> Result<Option<Vec<u8>>, String> {
    packetframe_common::statefile::read_owned_no_follow(path, RECORD_MAX).map_err(|e| e.to_string())
}

#[cfg(not(target_os = "linux"))]
fn read_record_bytes(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(b) if b.len() as u64 > RECORD_MAX => Err(format!("{} bytes", b.len())),
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(target_os = "linux")]
fn write_record(state_dir: &Path, token: u64) -> io::Result<()> {
    packetframe_common::statefile::write_atomic(
        &state_dir.join(MOUNT_RECORD),
        format!("{token:016x}\n").as_bytes(),
    )
}

#[cfg(not(target_os = "linux"))]
fn write_record(state_dir: &Path, token: u64) -> io::Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let tmp = state_dir.join(format!("{MOUNT_RECORD}.tmp"));
    std::fs::write(&tmp, format!("{token:016x}\n"))?;
    std::fs::rename(&tmp, state_dir.join(MOUNT_RECORD))
}

fn remove_record(state_dir: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    let r = packetframe_common::statefile::remove_state_record(&state_dir.join(MOUNT_RECORD));
    #[cfg(not(target_os = "linux"))]
    let r = std::fs::remove_file(state_dir.join(MOUNT_RECORD));
    match r {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// [`prepare`] for real, keeping the record true: a mount whose token
/// cannot be recorded is taken back down, since nothing would ever release
/// it. Then removes a stale `desired.conf`.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_recorded(dir: &Path, threads: usize, state_dir: &Path) -> SamplerDir {
    use packetframe_sampler_core::driver::{dir_budget, epoch_len};
    let need = match (dir_budget(threads), epoch_len(threads)) {
        (Ok(total), Ok(epoch)) => Need {
            total,
            epochs: 3 * epoch,
        },
        (Err(e), _) | (_, Err(e)) => return SamplerDir::Unavailable(e),
    };
    let recorded = read_record(state_dir);
    let fresh = packetframe_sampler_shm::fs::random_epoch();
    let (mut outcome, ours) = prepare(&Live, dir, need, recorded, fresh);
    if ours != recorded {
        let r = match ours {
            Some(t) => write_record(state_dir, t),
            None => remove_record(state_dir),
        };
        match r {
            Ok(()) => {}
            // A mount made just now that nothing could release.
            Err(e) if ours.is_some() => {
                let _ = Live.unmount(dir);
                outcome = SamplerDir::Unavailable(format!("recording the sampler mount: {e}"));
            }
            // A stale record names a marker that is gone: harmless.
            Err(e) => tracing::warn!(error = %e, "could not remove a stale sampler mount record"),
        }
    }
    if matches!(outcome, SamplerDir::Ready { .. }) {
        match packetframe_sampler_shm::fs::clear_desired(dir) {
            Ok(Some(true)) => tracing::info!(
                dir = %dir.display(),
                "removed a desired.conf no flow export owns: the VPP sampler stays off"
            ),
            Ok(Some(false)) => {}
            Ok(None) => tracing::warn!(
                dir = %dir.display(),
                "desired.lock is held by another writer; its desired.conf is left in place"
            ),
            Err(e) => tracing::warn!(
                dir = %dir.display(),
                error = %e,
                "could not remove a stale desired.conf"
            ),
        }
    }
    outcome
}

/// Release PacketFrame's sampler mount ([`release`]), after VPP is gone.
#[cfg(target_os = "linux")]
pub(crate) fn release_recorded(dir: &Path, state_dir: &Path) -> Result<(), String> {
    release(&Live, dir, state_dir)
}

/// No mounts off Linux, so nothing to release.
#[cfg(not(target_os = "linux"))]
pub(crate) fn release_recorded(_dir: &Path, _state_dir: &Path) -> Result<(), String> {
    Ok(())
}

/// A kernel port's ifindex, `None` when it has none (gone, renamed).
pub(crate) fn kernel_ifindex(port: &str) -> Option<u32> {
    let name = std::ffi::CString::new(port).ok()?;
    // SAFETY: a NUL-terminated name that outlives the call.
    let i = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (i != 0).then_some(i)
}

#[cfg(target_os = "linux")]
struct Live;

#[cfg(target_os = "linux")]
impl DirOps for Live {
    fn ensure_dir(&self, dir: &Path) -> io::Result<()> {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if dir.exists() {
            return Ok(());
        }
        packetframe_sampler_shm::fs::ensure_dir(dir)
    }
    fn is_mount_point(&self, dir: &Path) -> io::Result<bool> {
        packetframe_sampler_shm::fs::is_mount_point(dir)
    }
    fn check(&self, dir: &Path) -> Result<u64, String> {
        packetframe_sampler_shm::fs::check_dir(dir).map_err(|e| e.to_string())
    }
    fn other_bytes(&self, dir: &Path) -> io::Result<u64> {
        use packetframe_sampler_shm::current::is_epoch_file_name;
        use std::os::unix::fs::MetadataExt as _;
        let (used, _) = packetframe_sampler_shm::fs::usage(dir)?;
        let mut epochs = 0u64;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_name().to_str().is_some_and(is_epoch_file_name) {
                epochs += entry.metadata()?.blocks() * 512;
            }
        }
        Ok(used.saturating_sub(epochs))
    }
    fn has_marker(&self, dir: &Path, token: u64) -> bool {
        std::fs::symlink_metadata(dir.join(marker_name(token))).is_ok_and(|m| m.is_file())
    }
    fn mount(&self, dir: &Path, bytes: u64) -> io::Result<()> {
        packetframe_sampler_shm::fs::mount_tmpfs(dir, bytes)
    }
    fn make_marker(&self, dir: &Path, token: u64) -> io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(marker_name(token)))
            .map(drop)
    }
    fn unmount(&self, dir: &Path) -> io::Result<()> {
        packetframe_sampler_shm::fs::unmount(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A directory and whatever is mounted on it.
    #[derive(Default)]
    struct Fake {
        /// `None`: a plain directory. Else the mount: its size (or why the
        /// plugin would refuse it), its other files' bytes, its markers.
        mounted: RefCell<Option<Mount>>,
        refuse_mount: bool,
        refuse_marker: bool,
        mounts: RefCell<Vec<u64>>,
        unmounts: RefCell<usize>,
    }

    #[derive(Clone)]
    struct Mount {
        check: Result<u64, String>,
        other: u64,
        markers: Vec<u64>,
    }

    impl Fake {
        fn with(check: Result<u64, String>, other: u64, markers: Vec<u64>) -> Self {
            let f = Self::default();
            *f.mounted.borrow_mut() = Some(Mount {
                check,
                other,
                markers,
            });
            f
        }
    }

    impl DirOps for Fake {
        fn ensure_dir(&self, _: &Path) -> io::Result<()> {
            Ok(())
        }
        fn is_mount_point(&self, _: &Path) -> io::Result<bool> {
            Ok(self.mounted.borrow().is_some())
        }
        fn check(&self, _: &Path) -> Result<u64, String> {
            self.mounted.borrow().as_ref().unwrap().check.clone()
        }
        fn other_bytes(&self, _: &Path) -> io::Result<u64> {
            Ok(self.mounted.borrow().as_ref().unwrap().other)
        }
        fn has_marker(&self, _: &Path, token: u64) -> bool {
            self.mounted
                .borrow()
                .as_ref()
                .is_some_and(|m| m.markers.contains(&token))
        }
        fn mount(&self, _: &Path, bytes: u64) -> io::Result<()> {
            if self.refuse_mount {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            self.mounts.borrow_mut().push(bytes);
            *self.mounted.borrow_mut() = Some(Mount {
                check: Ok(bytes),
                other: 0,
                markers: Vec::new(),
            });
            Ok(())
        }
        fn make_marker(&self, _: &Path, token: u64) -> io::Result<()> {
            if self.refuse_marker {
                return Err(io::Error::from_raw_os_error(libc::ENOSPC));
            }
            self.mounted
                .borrow_mut()
                .as_mut()
                .unwrap()
                .markers
                .push(token);
            Ok(())
        }
        fn unmount(&self, _: &Path) -> io::Result<()> {
            *self.unmounts.borrow_mut() += 1;
            *self.mounted.borrow_mut() = None;
            Ok(())
        }
    }

    const DIR: &str = "/run/packetframe/vpp/sampler";
    const NEED: Need = Need {
        total: 1000,
        epochs: 900,
    };

    fn dir() -> &'static Path {
        Path::new(DIR)
    }

    #[test]
    fn a_plain_directory_gets_a_marked_mount_of_the_budget() {
        let f = Fake::default();
        let (out, ours) = prepare(&f, dir(), NEED, None, 7);
        assert_eq!(
            out,
            SamplerDir::Ready {
                bytes: 1000,
                owned: true
            }
        );
        assert_eq!(ours, Some(7));
        assert_eq!(*f.mounts.borrow(), [1000]);
        assert!(f.has_marker(dir(), 7));
    }

    #[test]
    fn a_mount_is_ours_only_while_it_carries_the_recorded_marker() {
        let ours = Fake::with(Ok(1000), 0, vec![7]);
        assert_eq!(
            prepare(&ours, dir(), NEED, Some(7), 8),
            (
                SamplerDir::Ready {
                    bytes: 1000,
                    owned: true
                },
                Some(7)
            )
        );
        // Ours went and an operator mounted another there: whatever the
        // record says, it is not ours, so the record goes.
        let replaced = Fake::with(Ok(4000), 0, vec![]);
        assert_eq!(
            prepare(&replaced, dir(), NEED, Some(7), 8),
            (
                SamplerDir::Ready {
                    bytes: 4000,
                    owned: false
                },
                None
            )
        );
        assert!(replaced.mounts.borrow().is_empty());
    }

    #[test]
    fn someone_elses_mount_needs_room_for_the_epochs_beside_its_files() {
        // Big enough in total, and nothing else on it.
        let roomy = Fake::with(Ok(4000), 100, vec![]);
        assert!(matches!(
            prepare(&roomy, dir(), NEED, None, 7).0,
            SamplerDir::Ready { owned: false, .. }
        ));
        // Big enough in total, but other files leave less than the epochs.
        let full = Fake::with(Ok(4000), 3101, vec![]);
        let (out, ours) = prepare(&full, dir(), NEED, None, 7);
        assert!(
            matches!(out, SamplerDir::Unavailable(ref w) if w.contains("3101 of them held by other files")),
            "{out:?}"
        );
        assert_eq!(ours, None);
        // Too small, or refused by the plugin's check: never mounted over.
        for f in [
            Fake::with(Ok(500), 0, vec![]),
            Fake::with(Err("not size-limited".into()), 0, vec![]),
        ] {
            assert!(matches!(
                prepare(&f, dir(), NEED, None, 7).0,
                SamplerDir::Unavailable(_)
            ));
            assert!(f.mounts.borrow().is_empty());
        }
    }

    #[test]
    fn our_own_mount_is_not_held_to_the_free_space_test() {
        // A running VPP's epochs and a stalled reader's are the budget's.
        let f = Fake::with(Ok(1000), 999, vec![7]);
        assert!(matches!(
            prepare(&f, dir(), NEED, Some(7), 8).0,
            SamplerDir::Ready { owned: true, .. }
        ));
    }

    #[test]
    fn a_mount_that_cannot_be_marked_is_taken_down() {
        let f = Fake {
            refuse_marker: true,
            ..Fake::default()
        };
        let (out, ours) = prepare(&f, dir(), NEED, None, 7);
        assert!(matches!(out, SamplerDir::Unavailable(ref w) if w.contains("marking")));
        assert_eq!(ours, None);
        assert_eq!(*f.unmounts.borrow(), 1);

        let refused = Fake {
            refuse_mount: true,
            ..Fake::default()
        };
        assert_eq!(prepare(&refused, dir(), NEED, Some(7), 8).1, None);
    }

    fn state_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pf-sampler-record-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        // The owned reader refuses a directory others can write, as any
        // umask could leave it.
        std::fs::set_permissions(&d, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        d
    }

    #[test]
    fn the_record_round_trips_and_unreadable_reads_as_none() {
        let d = state_dir("rt");
        assert_eq!(read_record(&d), None);
        write_record(&d, 0xfeed).unwrap();
        assert_eq!(read_record(&d), Some(0xfeed));
        std::fs::write(d.join(MOUNT_RECORD), "not hex").unwrap();
        assert_eq!(read_record(&d), None);
        remove_record(&d).unwrap();
        remove_record(&d).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The record decides what root unmounts, so one this daemon cannot
    /// vouch for reads as none: writable by others, or a link.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_record_others_could_have_written_reads_as_none() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = state_dir("trust");
        write_record(&d, 7).unwrap();
        assert_eq!(read_record(&d), Some(7));
        let rec = d.join(MOUNT_RECORD);
        std::fs::set_permissions(&rec, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(read_record(&d), None, "group/world-writable");
        std::fs::remove_file(&rec).unwrap();
        let real = d.join("elsewhere");
        std::fs::write(&real, "0000000000000007\n").unwrap();
        std::os::unix::fs::symlink(&real, &rec).unwrap();
        assert_eq!(read_record(&d), None, "a symlink at the record's name");
        // And with no trusted record, release unmounts nothing.
        let marked = Fake::with(Ok(1000), 0, vec![7]);
        release(&marked, dir(), &d).unwrap();
        assert_eq!(*marked.unmounts.borrow(), 0);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn release_unmounts_only_the_mount_that_carries_the_marker() {
        let d = state_dir("rel");
        write_record(&d, 7).unwrap();
        let ours = Fake::with(Ok(1000), 0, vec![7]);
        release(&ours, dir(), &d).unwrap();
        assert_eq!(*ours.unmounts.borrow(), 1);
        assert_eq!(read_record(&d), None, "the record goes with it");

        write_record(&d, 7).unwrap();
        let replaced = Fake::with(Ok(1000), 0, vec![]);
        release(&replaced, dir(), &d).unwrap();
        assert_eq!(*replaced.unmounts.borrow(), 0, "someone else's stays");
        assert_eq!(read_record(&d), None);

        // No record: nothing is ours.
        let unrecorded = Fake::with(Ok(1000), 0, vec![7]);
        release(&unrecorded, dir(), &d).unwrap();
        assert_eq!(*unrecorded.unmounts.borrow(), 0);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The real thing: mount, mark and record; reused as ours across a
    /// daemon restart; released; and someone else's crowded mount refused
    /// and left in place.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs root to mount a tmpfs"]
    fn the_live_mount_round_trips() {
        let base = state_dir("live");
        let (d, st) = (base.join("sampler"), base.join("state"));
        let out = prepare_recorded(&d, 2, &st);
        assert!(
            matches!(out, SamplerDir::Ready { owned: true, .. }),
            "{out:?}"
        );
        let token = read_record(&st).expect("recorded");
        assert!(Live.has_marker(&d, token));
        assert!(
            Live.check(&d).unwrap() >= packetframe_sampler_core::driver::dir_budget(2).unwrap()
        );
        assert!(matches!(
            prepare_recorded(&d, 2, &st),
            SamplerDir::Ready { owned: true, .. }
        ));
        assert_eq!(read_record(&st), Some(token), "the same mount, still ours");
        release_recorded(&d, &st).unwrap();
        assert!(!Live.is_mount_point(&d).unwrap());
        assert_eq!(read_record(&st), None);

        let budget = packetframe_sampler_core::driver::dir_budget(2).unwrap();
        packetframe_sampler_shm::fs::mount_tmpfs(&d, budget).unwrap();
        std::fs::write(d.join("someone-elses"), vec![1u8; 1 << 20]).unwrap();
        let out = prepare_recorded(&d, 2, &st);
        assert!(
            matches!(out, SamplerDir::Unavailable(ref w) if w.contains("held by other files")),
            "{out:?}"
        );
        release_recorded(&d, &st).unwrap();
        assert!(Live.is_mount_point(&d).unwrap(), "someone else's stays");
        Live.unmount(&d).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_row_never_reads_worse_than_degraded() {
        let ok = SamplerDir::Ready {
            bytes: 18 << 20,
            owned: true,
        }
        .health(dir());
        assert_eq!(ok.state, HealthState::Healthy);
        assert!(ok
            .message
            .unwrap()
            .contains("18432 KiB, mounted by PacketFrame"));
        let bad = SamplerDir::Unavailable("why".into()).health(dir());
        assert_eq!(bad.state, HealthState::Degraded);
        assert!(bad.message.unwrap().ends_with("why"));
    }
}
