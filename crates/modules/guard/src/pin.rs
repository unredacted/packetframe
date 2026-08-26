//! bpffs pin path construction + lifecycle helpers for the guard.
//!
//! Mirror of fast-path's `pin.rs`; when one is updated, the other
//! likely needs the same change. Separate file (not a shared helper)
//! because each module hardcodes its own `MODULE_NAME`, map list, and
//! program list. Two deliberate divergences:
//!
//! - **No `links/` directory.** tc cls_bpf filters cannot be pinned as
//!   bpf_links (their lifetime is the clsact qdisc's); the guard's
//!   attach state lives in `guard-tc-links.json` instead. Only
//!   programs and maps are pinned here.
//! - **No paced removal.** Removing a tc filter does not bounce the
//!   link the way an XDP detach does on rvu-nicpf, so the bridge-
//!   member pacing fast-path needs on detach does not apply.
//!
//! v0.1 semantics are shared: startup refuses when pins already exist
//! from a prior invocation; `packetframe detach --all` is the recovery
//! path.

use std::path::{Path, PathBuf};

use crate::MODULE_NAME;

/// Every guard map that gets pinned. Order is not significant.
/// Append-only; new maps go at the end.
pub const MAP_NAMES: [&str; 4] = [
    "GUARD_CFG",
    "GUARD_NDP_BUCKETS",
    "GUARD_MCAST_BUCKETS",
    "GUARD_STATS",
];

/// The guard's tc-egress classifier program basename.
pub const PROGRAM_NAME: &str = "guard_egress";

/// All pinned program basenames in this module. Append-only.
pub const PROGRAM_NAMES: [&str; 1] = [PROGRAM_NAME];

pub fn module_root(bpffs_root: &Path) -> PathBuf {
    bpffs_root.join(MODULE_NAME)
}

pub fn progs_dir(bpffs_root: &Path) -> PathBuf {
    module_root(bpffs_root).join("progs")
}

pub fn maps_dir(bpffs_root: &Path) -> PathBuf {
    module_root(bpffs_root).join("maps")
}

pub fn program_path(bpffs_root: &Path) -> PathBuf {
    progs_dir(bpffs_root).join(PROGRAM_NAME)
}

pub fn map_path(bpffs_root: &Path, name: &str) -> PathBuf {
    maps_dir(bpffs_root).join(name)
}

/// Create the module's pin subdirectories if missing. The bpffs root
/// itself must already be mounted; [`packetframe_common::probe`]'s
/// `bpffs` probe checks that.
pub fn ensure_dirs(bpffs_root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(progs_dir(bpffs_root))?;
    std::fs::create_dir_all(maps_dir(bpffs_root))?;
    Ok(())
}

/// True when any pinned object exists under the module's pin root.
/// Startup checks this before fresh-loading; pinned state from a prior
/// invocation must be cleaned via `packetframe detach --all` first.
pub fn has_existing_pins(bpffs_root: &Path) -> bool {
    for sub in [progs_dir(bpffs_root), maps_dir(bpffs_root)] {
        let entries = match std::fs::read_dir(&sub) {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entries.flatten().next().is_some() {
            return true;
        }
    }
    false
}

/// Remove every pin under the module's pin root. Called by
/// `packetframe detach`. Missing files and missing directories are
/// not errors; the post-condition is "no pins", regardless of
/// starting state. No kernel-attach side effects here — the tc
/// filters are torn down separately from `guard-tc-links.json`.
pub fn remove_all(bpffs_root: &Path) -> std::io::Result<()> {
    for sub in [maps_dir(bpffs_root), progs_dir(bpffs_root)] {
        let entries = match std::fs::read_dir(&sub) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        for entry in entries.flatten() {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_shape() {
        let root = Path::new("/sys/fs/bpf/packetframe");
        assert_eq!(
            module_root(root),
            Path::new("/sys/fs/bpf/packetframe/guard")
        );
        assert_eq!(
            program_path(root),
            Path::new("/sys/fs/bpf/packetframe/guard/progs/guard_egress")
        );
        assert_eq!(
            map_path(root, "GUARD_STATS"),
            Path::new("/sys/fs/bpf/packetframe/guard/maps/GUARD_STATS")
        );
    }

    #[test]
    fn has_existing_pins_false_when_empty() {
        let dir = tempdir();
        ensure_dirs(&dir).unwrap();
        assert!(!has_existing_pins(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn has_existing_pins_true_when_program_pinned() {
        let dir = tempdir();
        ensure_dirs(&dir).unwrap();
        std::fs::write(program_path(&dir), b"fake").unwrap();
        assert!(has_existing_pins(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_all_cleans_every_subdir_and_is_idempotent() {
        let dir = tempdir();
        ensure_dirs(&dir).unwrap();
        std::fs::write(program_path(&dir), b"fake").unwrap();
        std::fs::write(map_path(&dir, "GUARD_STATS"), b"fake").unwrap();
        remove_all(&dir).unwrap();
        assert!(!has_existing_pins(&dir));
        remove_all(&dir).unwrap(); // second removal is a no-op
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "pf-guard-pin-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
