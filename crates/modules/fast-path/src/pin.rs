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
    remove_all_paced(bpffs_root, std::time::Duration::ZERO)
}

/// Variant of [`remove_all`] that paces link-pin removal by `settle_time`
/// when two or more attached interfaces share a bridge master.
///
/// **Why this exists.** Removing a link pin causes the kernel to
/// detach the XDP program from the iface. On certain drivers (rvu-
/// nicpf in particular — observed during Phase 4 cutover testing),
/// detach briefly bounces the link, which the bridge stack treats as
/// a port-state change. Bouncing multiple bridge members inside one
/// STP/RSTP reconvergence window can wedge the bridge into a brief
/// L2-loop state. On the reference EFG hardware that translates to
/// a kernel panic + full reboot.
///
/// SPEC.md §11.8 documents this for the attach side. The detach side
/// is symmetric and was missing — pre-rc5 `pin::remove_all` deleted
/// every link inode in a tight loop with no spacing. This function
/// fixes that by sleeping `settle_time` between consecutive bridge-
/// member detaches.
///
/// `settle_time = ZERO` reverts to the pre-rc5 fast-path (used by
/// tests and by the cli `detach --all` path when no config provides
/// a settle time). Production callers (linux_impl::detach) pass the
/// config's `attach_settle_time`.
pub fn remove_all_paced(
    bpffs_root: &Path,
    settle_time: std::time::Duration,
) -> std::io::Result<()> {
    // Remove links first so the kernel-side attach is gone before the
    // program is unreferenced. Order is defensive — the kernel copes
    // with reverse order too.
    let links = links_dir(bpffs_root);
    let link_files: Vec<std::path::PathBuf> = match std::fs::read_dir(&links) {
        Ok(e) => e.flatten().map(|entry| entry.path()).collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e),
    };

    // Identify which link-pin filenames are bridge members. The pin
    // filename is the iface name; we read /sys/class/net/<iface>/master
    // to see if it's bridged. Pace iff settle_time > 0 AND ≥ 2 members
    // share a master.
    let bridged_count = if settle_time.is_zero() {
        0
    } else {
        count_shared_bridge_masters(&link_files)
    };

    for (idx, path) in link_files.iter().enumerate() {
        if idx > 0 && bridged_count >= 2 && !settle_time.is_zero() {
            // Only pace once we've removed at least one — the first
            // removal doesn't need a preceding sleep.
            std::thread::sleep(settle_time);
        }
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }

    // Maps + progs are housekeeping. No kernel-link side effects, no
    // pacing needed.
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

/// Count how many of the given link-pin paths refer to interfaces
/// that share a bridge master. Returns 0 if none are bridged, the
/// total count of bridge members otherwise. Used to gate detach
/// pacing — paying the per-iface settle cost only matters when a
/// bridge is actually involved.
fn count_shared_bridge_masters(link_files: &[std::path::PathBuf]) -> usize {
    use std::collections::HashMap;
    let mut by_master: HashMap<String, usize> = HashMap::new();
    for path in link_files {
        let Some(iface) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let master_link = format!("/sys/class/net/{iface}/master");
        let Ok(target) = std::fs::read_link(&master_link) else {
            continue;
        };
        let Some(master) = target.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        *by_master.entry(master.to_string()).or_insert(0) += 1;
    }
    by_master.values().filter(|&&n| n >= 2).sum()
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

    #[test]
    fn remove_all_paced_zero_duration_matches_unpaced() {
        // settle_time=ZERO must behave identically to remove_all —
        // tests rely on this and the cli `detach --all` without
        // config defaults to the standard 2 s, but should still
        // function with zero in unit-test context.
        let dir = tempdir();
        ensure_dirs(&dir).unwrap();
        std::fs::write(program_path(&dir), b"fake").unwrap();
        std::fs::write(map_path(&dir, "STATS"), b"fake").unwrap();
        std::fs::write(link_path(&dir, "eth0"), b"fake").unwrap();
        std::fs::write(link_path(&dir, "eth1"), b"fake").unwrap();
        remove_all_paced(&dir, std::time::Duration::ZERO).unwrap();
        assert!(!has_existing_pins(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_all_paced_skips_pacing_when_no_bridge_detected() {
        // /sys/class/net lookups will fail for our fake "eth0"
        // pin (it's not a real interface), so `count_shared_bridge_masters`
        // returns 0 and pacing is skipped. The point of this test is
        // to confirm pacing-when-no-bridge doesn't slow tests down —
        // a 5 s settle must NOT be slept here.
        let dir = tempdir();
        ensure_dirs(&dir).unwrap();
        std::fs::write(link_path(&dir, "eth-test-fake-1"), b"fake").unwrap();
        std::fs::write(link_path(&dir, "eth-test-fake-2"), b"fake").unwrap();
        let start = std::time::Instant::now();
        remove_all_paced(&dir, std::time::Duration::from_secs(5)).unwrap();
        let elapsed = start.elapsed();
        // Should complete near-instantly. 1 s is generous headroom.
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "remove_all_paced unexpectedly slept (elapsed={elapsed:?}); \
             this means count_shared_bridge_masters incorrectly \
             reported a bridge for non-existent ifaces"
        );
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
