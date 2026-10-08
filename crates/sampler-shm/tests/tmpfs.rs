//! The sampler directory on a real tmpfs: needs root to mount one, so it
//! runs in CI's sudo step (`--ignored`).
#![cfg(all(target_os = "linux", not(loom)))]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use packetframe_sampler_shm::fs::{
    check_dir, clear_desired, create_epoch, ensure_dir, is_mount_point, mount_tmpfs as mount,
    random_epoch, reclaim, unmount, write_atomic, DirError, EpochError, DESIRED,
};
use packetframe_sampler_shm::layout::Layout;

fn mount_tmpfs(dir: &Path, opts: &str) {
    let c = |s: &[u8]| CString::new(s).unwrap();
    let rc = unsafe {
        libc::mount(
            c(b"tmpfs").as_ptr(),
            c(dir.as_os_str().as_bytes()).as_ptr(),
            c(b"tmpfs").as_ptr(),
            0,
            c(opts.as_bytes()).as_ptr().cast(),
        )
    };
    assert_eq!(rc, 0, "mount: {}", std::io::Error::last_os_error());
}

fn umount(dir: &Path) {
    let c = CString::new(dir.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::umount(c.as_ptr()) }, 0);
}

fn tempdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("pf-shm-tmpfs-{}", random_epoch()));
    ensure_dir(&d).unwrap();
    d
}

/// A size-limited tmpfs root is accepted and its limit is the budget: an
/// epoch that does not fit is refused as `Budget` (fallocate, so never a
/// SIGBUS later), and reclaiming an unmapped epoch frees its room.
#[test]
#[ignore = "needs root to mount a tmpfs"]
fn a_size_limited_tmpfs_root_is_the_budget() {
    let d = tempdir();
    mount_tmpfs(&d, "size=4m,mode=0700");
    assert_eq!(check_dir(&d).unwrap(), 4 << 20);

    let big = Layout::new(1, 8192, 256).unwrap(); // about 2.6 MiB
    assert!(big.file_len() > 2 << 20 && big.file_len() < 4 << 20);
    let first = create_epoch(&d, &big, 1, 0, 0, "").unwrap();
    match create_epoch(&d, &big, 2, 0, 0, "") {
        Err(EpochError::Budget(n)) => assert_eq!(n, big.file_len()),
        Err(e) => panic!("expected Budget, got {e}"),
        Ok(_) => panic!("expected Budget, got an epoch"),
    }
    assert!(
        !d.join("epoch-0000000000000002.shm").exists(),
        "partial file removed"
    );

    drop(first);
    reclaim(&d, &[]).unwrap();
    drop(create_epoch(&d, &big, 3, 0, 0, "").unwrap());
    umount(&d);
    std::fs::remove_dir(&d).unwrap();
}

/// A tmpfs without an explicit size= (half of RAM) is not a budget.
#[test]
#[ignore = "needs root to mount a tmpfs"]
fn a_default_size_tmpfs_is_refused() {
    let d = tempdir();
    mount_tmpfs(&d, "mode=0700");
    assert!(matches!(check_dir(&d), Err(DirError::NotSizeLimited(_))));
    umount(&d);
    std::fs::remove_dir(&d).unwrap();
}

/// What PacketFrame mounts for the plugin: a directory `check_dir`
/// accepts, with at least the budget asked for, gone again after
/// `unmount` even while a file on it is open.
#[test]
#[ignore = "needs root to mount a tmpfs"]
fn the_mount_packetframe_makes_is_one_the_plugin_accepts() {
    let d = tempdir();
    assert!(!is_mount_point(&d).unwrap());
    assert!(
        !is_mount_point(&d.join("absent")).unwrap(),
        "nothing on a missing directory"
    );
    assert!(matches!(
        check_dir(&d),
        Err(DirError::NotTmpfs(_)) | Err(DirError::NotSizeLimited(_))
    ));
    let want = 5 * 1024 * 1024 + 123;
    mount(&d, want).unwrap();
    assert!(is_mount_point(&d).unwrap());
    let size = check_dir(&d).unwrap();
    assert!(size >= want && size < want + 64 * 1024, "{size}");

    write_atomic(&d, DESIRED, b"x").unwrap();
    assert_eq!(clear_desired(&d).unwrap(), Some(true));
    assert_eq!(clear_desired(&d).unwrap(), Some(false));

    let held = std::fs::File::create(d.join("held")).unwrap();
    unmount(&d).unwrap();
    assert!(!is_mount_point(&d).unwrap());
    drop(held);
    assert!(unmount(&d).is_err(), "nothing is mounted any more");
    std::fs::remove_dir(&d).unwrap();
}

/// A writer holding `desired.lock` keeps `desired.conf`.
#[test]
fn a_held_lock_keeps_desired() {
    let d = tempdir();
    write_atomic(&d, DESIRED, b"x").unwrap();
    let lock = packetframe_sampler_shm::fs::Lock::try_exclusive(
        &d.join(packetframe_sampler_shm::fs::DESIRED_LOCK),
    )
    .unwrap()
    .unwrap();
    assert_eq!(clear_desired(&d).unwrap(), None);
    assert!(d.join(DESIRED).exists());
    drop(lock);
    assert_eq!(clear_desired(&d).unwrap(), Some(true));
    std::fs::remove_dir_all(&d).unwrap();
}
