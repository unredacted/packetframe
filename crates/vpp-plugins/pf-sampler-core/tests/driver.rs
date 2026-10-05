//! The control loop against real files. The full runs mount a size-limited
//! tmpfs, so they need root (CI's sudo step, `--ignored`).
#![cfg(target_os = "linux")]

use std::collections::{BTreeSet, HashMap};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use packetframe_sampler_core::control::{Vpp, WorkerConfig};
use packetframe_sampler_core::driver::{DesiredWatch, Driver, Epoch, Host};
use packetframe_sampler_shm::current::epoch_file_name;
use packetframe_sampler_shm::desired::Desired;
use packetframe_sampler_shm::fs::{ensure_dir, open_epoch, random_epoch, write_atomic, DESIRED};
use packetframe_sampler_shm::status::{reason, State};
use packetframe_sampler_shm::Class;

fn tempdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("pf-sampler-{tag}-{}", random_epoch()));
    ensure_dir(&d).unwrap();
    d
}

#[test]
fn the_watch_reports_every_kind_of_change_once() {
    let d = tempdir("watch");
    let p = d.join(DESIRED);
    let mut w = DesiredWatch::default();
    assert_eq!(w.poll(&p), Some(None), "first poll reports the absence");
    assert_eq!(w.poll(&p), None);
    write_atomic(&d, DESIRED, b"one").unwrap();
    assert_eq!(w.poll(&p), Some(Some("one".into())));
    assert_eq!(w.poll(&p), None);
    write_atomic(&d, DESIRED, b"one").unwrap();
    assert_eq!(
        w.poll(&p),
        Some(Some("one".into())),
        "a replacement is a change"
    );
    std::fs::remove_file(&p).unwrap();
    assert_eq!(w.poll(&p), Some(None));

    // There but unreadable (here, a directory): not reported as gone, and
    // read again on every poll until it can be.
    std::fs::create_dir(&p).unwrap();
    assert_eq!(w.poll(&p), None);
    assert_eq!(w.poll(&p), None);
    std::fs::remove_dir(&p).unwrap();
    write_atomic(&d, DESIRED, b"two").unwrap();
    assert_eq!(w.poll(&p), Some(Some("two".into())));
    std::fs::remove_dir_all(&d).unwrap();
}

#[derive(Default)]
struct FakeHost {
    names: HashMap<String, u32>,
    enabled: BTreeSet<u32>,
    worker: WorkerConfig,
    epochs: Vec<u64>,
}

impl Vpp for FakeHost {
    fn resolve(&mut self, name: &str) -> Option<u32> {
        self.names.get(name).copied()
    }
    fn sampling_enabled(&mut self, i: u32) -> bool {
        self.enabled.contains(&i)
    }
    fn sampling_disabled(&mut self, i: u32) -> bool {
        !self.enabled.contains(&i)
    }
    fn apply(&mut self, cfg: &WorkerConfig, enable: &[u32], disable: &[u32]) {
        for i in disable {
            self.enabled.remove(i);
        }
        self.enabled.extend(enable);
        self.worker = cfg.clone();
    }
}

impl Host for FakeHost {
    fn publish_epoch(&mut self, epoch: &'static Epoch) {
        self.epochs.push(epoch.id);
    }
}

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
    assert_eq!(unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) }, 0);
}

const S: u64 = 1_000_000_000;

#[test]
fn a_directory_that_is_not_a_tmpfs_root_never_gets_an_epoch() {
    let d = tempdir("nottmpfs");
    let mut h = FakeHost::default();
    let mut drv = Driver::new(d.clone(), 2, "test".into());
    drv.tick(&mut h, 1, 0);
    assert!(h.epochs.is_empty());
    assert!(
        drv.describe()[1].starts_with("no epoch: "),
        "{:?}",
        drv.describe()
    );
    assert!(
        std::fs::read_dir(&d).unwrap().next().is_none(),
        "nothing written"
    );
    std::fs::remove_dir_all(&d).unwrap();
}

/// VPP's whole life as the plugin sees it: an epoch, a configuration that
/// arrives, names that resolve late, a status the reader can read, and
/// restarts that leave only the newest two epoch files.
#[test]
#[ignore = "needs root to mount a tmpfs"]
fn a_vpp_run_from_epoch_to_status() {
    let d = tempdir("run");
    mount_tmpfs(&d, "size=64m,mode=0700");
    let mut h = FakeHost::default();
    let mut drv = Driver::new(d.clone(), 3, "test build".into());

    drv.tick(&mut h, 100, 0);
    assert_eq!(h.epochs.len(), 1);
    let o = open_epoch(&d, false).unwrap();
    assert_eq!(o.header.epoch, h.epochs[0]);
    assert_eq!(o.layout().workers, 3);
    let s = o.status().read().unwrap();
    assert_eq!((s.state, s.reason), (State::Disabled, reason::NO_CONFIG));
    assert_eq!(o.status().heartbeat(), 0);

    let desired = Desired {
        generation: 9,
        rate: 1000,
        header_bytes: 128,
        classes: Class::Ingress.bit(),
        interfaces: vec!["pg0".into(), "pg1".into()],
    };
    write_atomic(&d, DESIRED, desired.render().as_bytes()).unwrap();
    h.names.insert("pg0".into(), 1);
    drv.tick(&mut h, 200, S / 10);
    let s = o.status().read().unwrap();
    assert_eq!(
        (s.state, s.applied_generation, s.rate),
        (State::Enabled, 9, 1000)
    );
    assert_eq!(s.interfaces[0].sw_if_index, Some(1));
    assert_eq!(s.interfaces[1].sw_if_index, None);
    assert_eq!(h.enabled, BTreeSet::from([1]));
    assert_eq!(h.worker.pool_of(1), 0);
    assert_eq!(o.status().heartbeat(), S / 10);

    // pg1 appears; the next reconcile (1 s later) picks it up, not before.
    h.names.insert("pg1".into(), 2);
    drv.tick(&mut h, 300, S / 2);
    assert_eq!(h.enabled, BTreeSet::from([1]));
    drv.tick(&mut h, 400, S + S / 10);
    assert_eq!(h.enabled, BTreeSet::from([1, 2]));
    assert_eq!(
        o.status().read().unwrap().interfaces[1].sw_if_index,
        Some(2)
    );

    // Two VPP restarts: each makes a new epoch, keeps the one before, and
    // removes the rest.
    let first = h.epochs[0];
    drop(o);
    for _ in 0..2 {
        let mut drv = Driver::new(d.clone(), 3, "test build".into());
        drv.tick(&mut h, 500, 0);
    }
    assert_eq!(h.epochs.len(), 3);
    assert!(!d.join(epoch_file_name(first)).exists(), "oldest reclaimed");
    for e in &h.epochs[1..] {
        assert!(d.join(epoch_file_name(*e)).exists());
    }
    assert_eq!(open_epoch(&d, false).unwrap().header.epoch, h.epochs[2]);
    umount(&d);
    std::fs::remove_dir(&d).unwrap();
}

/// A tmpfs the epoch fills exactly: `current` cannot be written, and the
/// unpublished epoch file is removed rather than left holding the budget
/// against every retry.
#[test]
#[ignore = "needs root to mount a tmpfs"]
fn an_epoch_that_cannot_be_published_is_not_left_behind() {
    use packetframe_sampler_core::driver::{HEADER_CAPACITY, SLOTS_PER_RING};
    use packetframe_sampler_shm::current::is_epoch_file_name;
    use packetframe_sampler_shm::layout::Layout;
    let d = tempdir("publish");
    let size = Layout::new(2, SLOTS_PER_RING, HEADER_CAPACITY)
        .unwrap()
        .file_len();
    mount_tmpfs(&d, &format!("size={size},mode=0700"));
    let mut h = FakeHost::default();
    let mut drv = Driver::new(d.clone(), 2, "test".into());
    drv.tick(&mut h, 1, 0);
    assert!(h.epochs.is_empty());
    assert!(
        drv.describe()[1].contains("current"),
        "{:?}",
        drv.describe()
    );
    let left: Vec<String> = std::fs::read_dir(&d)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| is_epoch_file_name(n))
        .collect();
    assert!(left.is_empty(), "orphaned: {left:?}");
    umount(&d);
    std::fs::remove_dir(&d).unwrap();
}

/// A restart needs room for two epochs, the previous and the new: what
/// `current` no longer names goes before the new file is made, so a tmpfs
/// of twice an epoch takes any number of restarts while no reader pins an
/// older one.
#[test]
#[ignore = "needs root to mount a tmpfs"]
fn a_restart_needs_room_for_two_epochs() {
    use packetframe_sampler_core::driver::{HEADER_CAPACITY, SLOTS_PER_RING};
    use packetframe_sampler_shm::current::is_epoch_file_name;
    use packetframe_sampler_shm::layout::Layout;
    let d = tempdir("two");
    let len = Layout::new(2, SLOTS_PER_RING, HEADER_CAPACITY)
        .unwrap()
        .file_len();
    // The slack is `current` and its temporary, at 64 KiB pages.
    mount_tmpfs(&d, &format!("size={},mode=0700", 2 * len + (256 << 10)));
    for run in 0..4u64 {
        // Each run's epoch is dropped (unmapped) as its VPP exits.
        drop(Epoch::create(&d, 2, "test", run, run).unwrap_or_else(|e| panic!("run {run}: {e}")));
    }
    let left = std::fs::read_dir(&d)
        .unwrap()
        .filter(|e| is_epoch_file_name(e.as_ref().unwrap().file_name().to_str().unwrap()))
        .count();
    assert_eq!(left, 2);
    umount(&d);
    std::fs::remove_dir(&d).unwrap();
}

/// A full budget: no epoch, VPP untouched, retried every 5 s, and the
/// first retry after room appears succeeds.
#[test]
#[ignore = "needs root to mount a tmpfs"]
fn a_full_budget_is_retried_until_it_fits() {
    let d = tempdir("budget");
    mount_tmpfs(&d, "size=1m,mode=0700");
    let mut h = FakeHost::default();
    let mut drv = Driver::new(d.clone(), 2, "test".into());
    drv.tick(&mut h, 1, 0);
    assert!(h.epochs.is_empty());
    assert!(drv.describe()[1].contains("budget"), "{:?}", drv.describe());
    assert!(h.enabled.is_empty());
    // Room appears (a bigger mount over the same point); not retried
    // before 5 s, retried at 5 s.
    mount_tmpfs(&d, "size=64m,mode=0700");
    drv.tick(&mut h, 2, 4 * S);
    assert!(h.epochs.is_empty());
    drv.tick(&mut h, 3, 5 * S);
    assert_eq!(h.epochs.len(), 1);
    umount(&d);
    umount(&d);
    std::fs::remove_dir(&d).unwrap();
}

/// The tmpfs `dir_budget` sizes takes every restart even while a stalled
/// reader pins an epoch the plugin has already unlinked: three epochs and
/// the small files.
#[test]
#[ignore = "needs root to mount a tmpfs"]
fn the_budget_survives_restarts_under_a_stalled_reader() {
    use packetframe_sampler_core::driver::dir_budget;
    let d = tempdir("budget");
    mount_tmpfs(&d, &format!("size={},mode=0700", dir_budget(2).unwrap()));
    drop(Epoch::create(&d, 2, "test", 0, 0).unwrap());
    let stalled = open_epoch(&d, false).unwrap();
    for run in 1..5u64 {
        drop(Epoch::create(&d, 2, "test", run, run).unwrap_or_else(|e| panic!("run {run}: {e}")));
    }
    drop(stalled);
    umount(&d);
    std::fs::remove_dir(&d).unwrap();
}
