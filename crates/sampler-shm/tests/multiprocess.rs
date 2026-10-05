//! Two processes on one epoch file, as the plugin and PacketFrame are.
//!
//! The other process is this test binary re-run on one `#[ignore]`d test
//! that does nothing unless its environment says it is a child. Sample
//! counts default low; `PF_SHM_STRESS_N` raises them (the arm64 CI job).
#![cfg(all(target_os = "linux", not(loom)))]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use packetframe_sampler_shm::fs::{
    create_epoch, ensure_dir, open_epoch, publish_current, random_epoch, Lock, Mapping,
    CONSUMER_LOCK,
};
use packetframe_sampler_shm::layout::{read_header, Layout};
use packetframe_sampler_shm::ring::{RingWriter, Sample, SampleMeta};
use packetframe_sampler_shm::Class;

const CHILD_ROLE: &str = "PF_SHM_CHILD_ROLE";
const CHILD_DIR: &str = "PF_SHM_CHILD_DIR";
const CHILD_N: &str = "PF_SHM_CHILD_N";

fn stress_n() -> u64 {
    std::env::var("PF_SHM_STRESS_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200_000)
}

fn tempdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "pf-shm-mp-{tag}-{}-{}",
        std::process::id(),
        random_epoch()
    ));
    ensure_dir(&d).unwrap();
    d
}

fn spawn_child(test: &str, role: &str, dir: &Path, n: u64) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            test,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ROLE, role)
        .env(CHILD_DIR, dir)
        .env(CHILD_N, n.to_string())
        .stdout(Stdio::null())
        .spawn()
        .unwrap()
}

/// The sample `g`'s header: its generation's bytes, repeated, so a torn
/// copy shows as disagreement within one sample.
fn header_of(g: u64) -> [u8; 64] {
    let mut h = [0u8; 64];
    for c in h.chunks_mut(8) {
        c.copy_from_slice(&g.to_le_bytes());
    }
    h
}

/// Child: produce `n` samples into ring 0 of the published epoch as fast
/// as the ring takes them, dropping (and counting) when it is full.
#[test]
#[ignore = "runs only as the child of producer_and_consumer_in_two_processes"]
fn child_producer() {
    if std::env::var(CHILD_ROLE).as_deref() != Ok("producer") {
        return;
    }
    let dir = PathBuf::from(std::env::var(CHILD_DIR).unwrap());
    let n: u64 = std::env::var(CHILD_N).unwrap().parse().unwrap();
    let current = std::fs::read_to_string(dir.join("current")).unwrap();
    let cur = packetframe_sampler_shm::current::Current::parse(&current).unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.join(cur.file_name()))
        .unwrap();
    let len = file.metadata().unwrap().len() as usize;
    let map = Mapping::map(&file, 0, len, true, true).unwrap();
    let layout = read_header(map.words()).unwrap().layout;
    let w = RingWriter::new(&layout, map.words(), 0);
    for g in 1..=n {
        w.add_pool(0, Class::Ingress, 1);
        w.add_selected(1);
        let m = SampleMeta {
            generation: g,
            time_ns: g,
            sw_if_index: 7,
            class: Class::Ingress,
            pool_index: 0,
            rate: 1,
            frame_len: 64,
        };
        w.push(&m, &header_of(g));
    }
}

/// The plugin and PacketFrame, two processes: every sample the consumer
/// gets is whole and in order, and every one the producer made is either
/// delivered or counted as dropped.
#[test]
fn producer_and_consumer_in_two_processes() {
    let dir = tempdir("pc");
    let layout = Layout::new(1, 64, 64).unwrap();
    let epoch = random_epoch();
    let _creator = create_epoch(&dir, &layout, epoch, 0, 0, "mp").unwrap();
    publish_current(&dir, epoch, &layout).unwrap();

    let _lock = Lock::try_exclusive(&dir.join(CONSUMER_LOCK))
        .unwrap()
        .unwrap();
    let opened = open_epoch(&dir, true).unwrap();
    let ring = opened.ring(0).unwrap();
    let n = stress_n();
    let mut child = spawn_child("child_producer", "producer", &dir, n);

    let (mut delivered, mut last_g, mut next_seq) = (0u64, 0u64, 0u64);
    let mut out = Vec::with_capacity(1024);
    let mut check = |out: &mut Vec<Sample>| {
        for s in out.drain(..) {
            assert_eq!(s.seq, next_seq, "sequence gap");
            assert!(s.meta.generation > last_g, "out of order");
            assert_eq!(
                s.header,
                header_of(s.meta.generation),
                "torn sample {}",
                s.seq
            );
            assert_eq!((s.meta.sw_if_index, s.meta.frame_len), (7, 64));
            next_seq += 1;
            last_g = s.meta.generation;
            delivered += 1;
        }
    };
    loop {
        let done = child.try_wait().unwrap();
        let d = ring.drain(&mut out, 1024);
        assert_eq!((d.corrupt, d.skipped), (0, 0));
        check(&mut out);
        if let Some(status) = done {
            assert!(status.success());
            // One more pass: the child may have pushed after our drain.
            ring.drain(&mut out, usize::MAX);
            check(&mut out);
            break;
        }
    }
    let c = ring.counters();
    assert_eq!(c.selected, n);
    assert_eq!(c.pool[0][Class::Ingress.index()], n);
    assert_eq!(c.written, delivered);
    assert_eq!(
        delivered + c.dropped_full,
        n,
        "every sample delivered or counted"
    );
    eprintln!(
        "{n} samples: {delivered} delivered, {} dropped full",
        c.dropped_full
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Child: take the consumer lock, say so with a marker file (libtest
/// captures a child's stdout), then hold it until killed.
#[test]
#[ignore = "runs only as the child of the_consumer_lock_dies_with_its_holder"]
fn child_lock_holder() {
    if std::env::var(CHILD_ROLE).as_deref() != Ok("lock") {
        return;
    }
    let dir = PathBuf::from(std::env::var(CHILD_DIR).unwrap());
    let _lock = Lock::try_exclusive(&dir.join(CONSUMER_LOCK))
        .unwrap()
        .unwrap();
    std::fs::write(dir.join("locked"), "").unwrap();
    std::thread::sleep(Duration::from_secs(120));
}

/// A second consumer is refused while the first lives, and the lock is
/// free the moment its holder dies — however it died.
#[test]
fn the_consumer_lock_dies_with_its_holder() {
    let dir = tempdir("lock");
    let mut child = spawn_child("child_lock_holder", "lock", &dir, 0);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !dir.join("locked").exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "child exited before locking"
        );
        assert!(Instant::now() < deadline, "child never locked");
        std::thread::sleep(Duration::from_millis(10));
    }
    let p = dir.join(CONSUMER_LOCK);
    assert!(
        Lock::try_exclusive(&p).unwrap().is_none(),
        "second consumer refused"
    );
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        Lock::try_exclusive(&p).unwrap().is_some(),
        "free after SIGKILL"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
