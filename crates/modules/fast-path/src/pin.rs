//! bpffs pin path construction + lifecycle helpers (SPEC.md §8.2, §8.5).
//!
//! Pins live under `<bpffs-root>/<module-name>/{progs,maps,links}/`. The
//! XDP program, every §4.5 map, and every per-iface link are pinned at
//! attach time. This does two things:
//!
//! - `packetframe status` and `packetframe detach` can reach the kernel
//!   state from a separate process (neither has an active loader).
//! - The kernel-side XDP attachment outlives the loader. Dropping a
//!   `PinnedLink` closes the userspace FD, but the bpffs inode keeps
//!   the kernel reference alive until the pin path is unlinked. This
//!   is what SPEC.md §8.5 "exit without detach" actually means in
//!   concrete terms.
//!
//! v0.1 refuses startup when pins already exist from a prior
//! invocation. Full adoption (zero-disruption daemon restart) is
//! deferred — the operator runs `packetframe detach --all` to clean
//! up before restarting.

use std::path::{Path, PathBuf};

use crate::MODULE_NAME;

/// Every §4.5 map that gets pinned. Order is not significant.
pub const MAP_NAMES: [&str; 12] = [
    "ALLOW_V4",
    "ALLOW_V6",
    "CFG",
    "STATS",
    "REDIRECT_DEVMAP",
    "VLAN_RESOLVE",
    "LOG",
    // --- Custom-FIB maps (Option F, Phase 1) ---
    // Pinned even when `forwarding-mode` is `kernel-fib`; they're
    // present in the ELF regardless and pinning them keeps detach
    // teardown uniform across modes.
    "FIB_V4",
    "FIB_V6",
    "NEXTHOPS",
    "ECMP_GROUPS",
    "FIB_CONFIG",
];

/// The XDP program's pinned basename.
pub const PROGRAM_NAME: &str = "fast_path";

pub fn module_root(bpffs_root: &Path) -> PathBuf {
    bpffs_root.join(MODULE_NAME)
}

pub fn progs_dir(bpffs_root: &Path) -> PathBuf {
    module_root(bpffs_root).join("progs")
}

pub fn maps_dir(bpffs_root: &Path) -> PathBuf {
    module_root(bpffs_root).join("maps")
}

pub fn links_dir(bpffs_root: &Path) -> PathBuf {
    module_root(bpffs_root).join("links")
}

pub fn program_path(bpffs_root: &Path) -> PathBuf {
    progs_dir(bpffs_root).join(PROGRAM_NAME)
}

pub fn map_path(bpffs_root: &Path, name: &str) -> PathBuf {
    maps_dir(bpffs_root).join(name)
}

pub fn link_path(bpffs_root: &Path, iface: &str) -> PathBuf {
    links_dir(bpffs_root).join(iface)
}

/// Create the module's pin subdirectories if missing. The bpffs root
/// itself must already be mounted — [`packetframe_common::probe`]'s
/// `bpffs` probe checks that.
pub fn ensure_dirs(bpffs_root: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(progs_dir(bpffs_root))?;
    std::fs::create_dir_all(maps_dir(bpffs_root))?;
    std::fs::create_dir_all(links_dir(bpffs_root))?;
    Ok(())
}

/// True when any pinned object exists under the module's pin root.
/// Startup checks this before fresh-loading — pinned state from a prior
/// invocation must be cleaned via `packetframe detach --all` first.
pub fn has_existing_pins(bpffs_root: &Path) -> bool {
    for sub in [
        progs_dir(bpffs_root),
        maps_dir(bpffs_root),
        links_dir(bpffs_root),
    ] {
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
/// not errors — the post-condition is "no pins", regardless of
/// starting state.
///
/// Removing a link pin causes the kernel to detach the XDP program
/// from the iface. Removing the program and map pins is housekeeping
/// — their kernel-side objects disappear once no FDs or links
/// reference them.
pub fn remove_all(bpffs_root: &Path) -> std::io::Result<()> {
    // Remove links first so the kernel-side attach is gone before the
    // program is unreferenced. Order is defensive — the kernel copes
    // with reverse order too.
    for sub in [
        links_dir(bpffs_root),
        maps_dir(bpffs_root),
        progs_dir(bpffs_root),
    ] {
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
            Path::new("/sys/fs/bpf/packetframe/fast-path")
        );
        assert_eq!(
            program_path(root),
            Path::new("/sys/fs/bpf/packetframe/fast-path/progs/fast_path")
        );
        assert_eq!(
            map_path(root, "STATS"),
            Path::new("/sys/fs/bpf/packetframe/fast-path/maps/STATS")
        );
        assert_eq!(
            link_path(root, "eth0.1337"),
            Path::new("/sys/fs/bpf/packetframe/fast-path/links/eth0.1337")
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
    fn has_existing_pins_true_when_map_pinned() {
        let dir = tempdir();
        ensure_dirs(&dir).unwrap();
        std::fs::write(map_path(&dir, "STATS"), b"fake").unwrap();
        assert!(has_existing_pins(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_all_cleans_every_subdir() {
        let dir = tempdir();
        ensure_dirs(&dir).unwrap();
        std::fs::write(program_path(&dir), b"fake").unwrap();
        std::fs::write(map_path(&dir, "STATS"), b"fake").unwrap();
        std::fs::write(link_path(&dir, "eth0"), b"fake").unwrap();
        remove_all(&dir).unwrap();
        assert!(!has_existing_pins(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_all_idempotent() {
        let dir = tempdir();
        remove_all(&dir).unwrap();
        remove_all(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "pf-pin-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
