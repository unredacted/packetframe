//! The VPP sampler's directory (flow export): the size-limited tmpfs the
//! plugin refuses to work without (`packetframe_sampler_shm::fs::
//! check_dir`), prepared at attach, before VPP can start.
//!
//! Never fatal. VPP forwards the same with or without the sampler, so a
//! directory that cannot be prepared is the `sampler-dir` status row and
//! nothing else; flow export reports VPP coverage as uncovered, giving
//! the row's reason.
//!
//! A mount PacketFrame makes is recorded in the state file
//! ([`crate::resources::ResourceState::sampler_mount`]) and unmounted when the resources
//! are released, after VPP is gone. A mount that was there already is
//! used when it passes the plugin's own check with room enough, and is
//! never unmounted; PacketFrame never mounts over one.
//!
//! Attach also removes a `desired.conf` left behind: with no flow export
//! configured to own it, the plugin stays off even in a reused directory
//! or an adopted VPP.

// The decision serves the Linux preparation only, but builds everywhere
// so its tests run on any host.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::Path;

use packetframe_common::module::{HealthState, SubsystemHealth};

/// Where the plugin is installed; startup.conf `add-path`s it.
pub const PLUGIN_DIR: &str = "/usr/lib/packetframe/vpp_plugins";

/// The status row's name.
pub const SUBSYS_SAMPLER_DIR: &str = "sampler-dir";

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

/// The directory operations, a trait so the decision is testable without
/// root.
pub(crate) trait DirOps {
    /// Create `dir` (mode 0700) if it does not exist; leave it if it does.
    fn ensure_dir(&self, dir: &Path) -> std::io::Result<()>;
    fn is_mount_point(&self, dir: &Path) -> std::io::Result<bool>;
    /// The plugin's own check: the tmpfs size, or why it would refuse.
    fn check(&self, dir: &Path) -> Result<u64, String>;
    fn mount(&self, dir: &Path, bytes: u64) -> std::io::Result<()>;
}

/// Make `dir` usable for a sampler needing `required` bytes. `recorded`:
/// the state file says PacketFrame mounted it. Returns the outcome and
/// whether a mount of PacketFrame's is at `dir` afterwards.
pub(crate) fn prepare(
    ops: &dyn DirOps,
    dir: &Path,
    required: u64,
    recorded: bool,
) -> (SamplerDir, bool) {
    let shown = dir.display();
    if let Err(e) = ops.ensure_dir(dir) {
        return (SamplerDir::Unavailable(format!("{shown}: {e}")), false);
    }
    match ops.is_mount_point(dir) {
        // Unknown: the record stands as it is.
        Err(e) => (
            SamplerDir::Unavailable(format!("{shown}: reading the mount table: {e}")),
            recorded,
        ),
        Ok(true) => match ops.check(dir) {
            Ok(bytes) if bytes >= required => (
                SamplerDir::Ready {
                    bytes,
                    owned: recorded,
                },
                recorded,
            ),
            Ok(bytes) => (
                SamplerDir::Unavailable(format!(
                    "{shown} holds {bytes} bytes and this VPP's sampler needs {required}; \
                     PacketFrame does not mount over {}",
                    whose(recorded)
                )),
                recorded,
            ),
            Err(e) => (
                SamplerDir::Unavailable(format!(
                    "{e}; PacketFrame does not mount over {}",
                    whose(recorded)
                )),
                recorded,
            ),
        },
        // Nothing mounted (a record of one means it was unmounted under
        // us): mount ours.
        Ok(false) => match ops.mount(dir, required) {
            Err(e) => (
                SamplerDir::Unavailable(format!("mounting a tmpfs at {shown}: {e}")),
                false,
            ),
            Ok(()) => match ops.check(dir) {
                Ok(bytes) => (SamplerDir::Ready { bytes, owned: true }, true),
                // Ours all the same: released with the rest.
                Err(e) => (SamplerDir::Unavailable(e), true),
            },
        },
    }
}

fn whose(recorded: bool) -> &'static str {
    if recorded {
        "its own earlier mount"
    } else {
        "a mount it did not make"
    }
}

/// [`prepare`] for real, keeping `state`'s record of the mount true: a
/// mount the record cannot be saved for is taken back down, since nothing
/// would ever release it. Then removes a stale `desired.conf`.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_recorded(
    dir: &Path,
    threads: usize,
    state: &mut crate::resources::ResourceState,
    state_dir: &Path,
) -> SamplerDir {
    let required = match packetframe_sampler_core::driver::dir_budget(threads) {
        Ok(b) => b,
        Err(e) => return SamplerDir::Unavailable(e),
    };
    let (mut outcome, ours) = prepare(&Live, dir, required, state.sampler_mount);
    if ours != state.sampler_mount {
        state.sampler_mount = ours;
        if let Err(e) = state.save(state_dir) {
            if ours {
                let _ = packetframe_sampler_shm::fs::unmount(dir);
                state.sampler_mount = false;
            }
            outcome = SamplerDir::Unavailable(format!("recording the sampler mount: {e}"));
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

/// Unmount the sampler's tmpfs that the state file records as
/// PacketFrame's. Already gone counts as released.
#[cfg(target_os = "linux")]
pub(crate) fn release_mount(dir: &Path) -> Result<(), String> {
    match packetframe_sampler_shm::fs::unmount(dir) {
        Ok(()) => Ok(()),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EINVAL) | Some(libc::ENOENT)) => Ok(()),
        Err(e) => Err(format!("unmount {}: {e}", dir.display())),
    }
}

/// No mounts off Linux, so nothing to release.
#[cfg(not(target_os = "linux"))]
pub(crate) fn release_mount(_dir: &Path) -> Result<(), String> {
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
    fn ensure_dir(&self, dir: &Path) -> std::io::Result<()> {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if dir.exists() {
            return Ok(());
        }
        packetframe_sampler_shm::fs::ensure_dir(dir)
    }
    fn is_mount_point(&self, dir: &Path) -> std::io::Result<bool> {
        packetframe_sampler_shm::fs::is_mount_point(dir)
    }
    fn check(&self, dir: &Path) -> Result<u64, String> {
        packetframe_sampler_shm::fs::check_dir(dir).map_err(|e| e.to_string())
    }
    fn mount(&self, dir: &Path, bytes: u64) -> std::io::Result<()> {
        packetframe_sampler_shm::fs::mount_tmpfs(dir, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A directory with what is mounted on it: `None` for a plain one.
    struct Fake {
        mounted: RefCell<Option<Result<u64, String>>>,
        refuse_mount: bool,
        mounts: RefCell<Vec<u64>>,
    }

    impl Fake {
        fn plain() -> Self {
            Self {
                mounted: RefCell::new(None),
                refuse_mount: false,
                mounts: RefCell::new(Vec::new()),
            }
        }
        fn with(m: Result<u64, String>) -> Self {
            let f = Self::plain();
            *f.mounted.borrow_mut() = Some(m);
            f
        }
    }

    impl DirOps for Fake {
        fn ensure_dir(&self, _: &Path) -> std::io::Result<()> {
            Ok(())
        }
        fn is_mount_point(&self, _: &Path) -> std::io::Result<bool> {
            Ok(self.mounted.borrow().is_some())
        }
        fn check(&self, _: &Path) -> Result<u64, String> {
            self.mounted.borrow().clone().unwrap()
        }
        fn mount(&self, _: &Path, bytes: u64) -> std::io::Result<()> {
            if self.refuse_mount {
                return Err(std::io::Error::from_raw_os_error(1));
            }
            self.mounts.borrow_mut().push(bytes);
            *self.mounted.borrow_mut() = Some(Ok(bytes));
            Ok(())
        }
    }

    const DIR: &str = "/run/packetframe/vpp/sampler";

    #[test]
    fn a_plain_directory_gets_a_mount_of_the_budget() {
        let f = Fake::plain();
        let (out, ours) = prepare(&f, Path::new(DIR), 1000, false);
        assert_eq!(
            out,
            SamplerDir::Ready {
                bytes: 1000,
                owned: true
            }
        );
        assert!(ours);
        assert_eq!(*f.mounts.borrow(), [1000]);
    }

    #[test]
    fn an_existing_mount_is_used_only_when_it_passes_with_room() {
        let f = Fake::with(Ok(4000));
        assert_eq!(
            prepare(&f, Path::new(DIR), 1000, false),
            (
                SamplerDir::Ready {
                    bytes: 4000,
                    owned: false
                },
                false
            )
        );
        // Our own, from an earlier attach this boot: still ours.
        assert!(
            prepare(&f, Path::new(DIR), 1000, true).1,
            "the record stands"
        );

        let small = Fake::with(Ok(500));
        let (out, ours) = prepare(&small, Path::new(DIR), 1000, false);
        assert!(matches!(out, SamplerDir::Unavailable(ref w) if w.contains("500 bytes")));
        assert!(!ours);
        assert!(small.mounts.borrow().is_empty(), "never mounted over");

        let foreign = Fake::with(Err("not size-limited".into()));
        let (out, _) = prepare(&foreign, Path::new(DIR), 1000, false);
        assert!(
            matches!(out, SamplerDir::Unavailable(ref w) if w.contains("did not make")),
            "{out:?}"
        );
        assert!(foreign.mounts.borrow().is_empty());
    }

    #[test]
    fn a_recorded_mount_that_vanished_is_replaced_and_a_refused_mount_is_not_ours() {
        let f = Fake::plain();
        assert!(prepare(&f, Path::new(DIR), 1000, true).1);

        let refused = Fake {
            refuse_mount: true,
            ..Fake::plain()
        };
        let (out, ours) = prepare(&refused, Path::new(DIR), 1000, true);
        assert!(matches!(out, SamplerDir::Unavailable(ref w) if w.contains("mounting")));
        assert!(!ours, "the record is corrected: nothing of ours is there");
    }

    #[test]
    fn the_row_never_reads_worse_than_degraded() {
        let d = Path::new(DIR);
        let ok = SamplerDir::Ready {
            bytes: 18 << 20,
            owned: true,
        }
        .health(d);
        assert_eq!(ok.state, HealthState::Healthy);
        assert!(ok
            .message
            .unwrap()
            .contains("18432 KiB, mounted by PacketFrame"));
        let bad = SamplerDir::Unavailable("why".into()).health(d);
        assert_eq!(bad.state, HealthState::Degraded);
        assert!(bad.message.unwrap().ends_with("why"));
    }
}
