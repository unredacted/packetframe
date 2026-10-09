//! VPP's sampler directory for real: `packetframe_sampler_shm`'s locks,
//! follower and files, `/proc` for which process maps an epoch, and the
//! generation record in `state-dir`.

use std::io;
use std::path::{Path, PathBuf};

use packetframe_common::sampler_ports::VppInstance;
use packetframe_common::statefile::{read_owned_no_follow, write_atomic as write_state};
use packetframe_sampler_shm::coverage::NoStatus;
use packetframe_sampler_shm::current::epoch_file_name;
use packetframe_sampler_shm::desired::Desired;
use packetframe_sampler_shm::follow::Follower;
use packetframe_sampler_shm::fs::{
    check_dir, clear_desired, write_atomic, Lock, CONSUMER_LOCK, DESIRED, DESIRED_LOCK,
};
use packetframe_sampler_shm::ring::{self, Drained, Sample};
use serde::{Deserialize, Serialize};

use crate::vpp::{EpochSwitch, Look, VppDir};

/// In `state-dir`: one VPP process's newest generation, so the file
/// names at most one and needs no cleanup.
const GENERATION_RECORD: &str = "flow-export-vpp-generation.json";
const MAX_RECORD_BYTES: u64 = 4096;

#[derive(Debug, Serialize, Deserialize)]
struct GenerationRecord {
    pid: i32,
    start_ticks: u64,
    boot_id: Option<String>,
    generation: u64,
}

pub struct LiveVppDir {
    dir: PathBuf,
    record: PathBuf,
    lock: Option<Lock>,
    follower: Option<Follower>,
}

impl LiveVppDir {
    pub fn new(dir: &Path, state_dir: &Path) -> Self {
        Self {
            dir: dir.to_owned(),
            record: state_dir.join(GENERATION_RECORD),
            lock: None,
            follower: None,
        }
    }
}

impl VppDir for LiveVppDir {
    fn claim(&mut self) -> Result<(), String> {
        // A directory the plugin would refuse is not where it is: never a
        // plain directory a tmpfs may yet be mounted over.
        check_dir(&self.dir).map_err(|e| e.to_string())?;
        if self.lock.is_none() {
            let path = self.dir.join(DESIRED_LOCK);
            let lock = Lock::try_exclusive(&path)
                .map_err(|e| format!("{}: {e}", path.display()))?
                .ok_or(
                    "desired.lock is held by another writer (a `packetframe sampler configure`?)",
                )?;
            self.lock = Some(lock);
        }
        let f = Follower::consumer(&self.dir).map_err(|e| match e.kind() {
            io::ErrorKind::WouldBlock => {
                "consumer.lock is held by another reader (a `packetframe sampler watch`?)".into()
            }
            _ => format!("{}: {e}", self.dir.join(CONSUMER_LOCK).display()),
        })?;
        self.follower = Some(f);
        Ok(())
    }

    fn write(&mut self, d: &Desired) -> Result<(), String> {
        write_atomic(&self.dir, DESIRED, d.render().as_bytes())
            .map_err(|e| format!("{}: {e}", self.dir.join(DESIRED).display()))
    }

    fn remove(&mut self) -> Result<(), String> {
        match std::fs::remove_file(self.dir.join(DESIRED)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{}: {e}", self.dir.join(DESIRED).display())),
        }
    }

    fn refresh(&mut self) -> Option<EpochSwitch> {
        self.follower.as_mut()?.refresh().map(|s| EpochSwitch {
            from: s.from,
            to: s.to,
            abandoned: s.abandoned,
        })
    }

    fn look(&mut self) -> Look {
        let now_realtime_ns = realtime_ns();
        let desired_generation = std::fs::read_to_string(self.dir.join(DESIRED))
            .ok()
            .and_then(|t| Desired::parse(&t).ok())
            .map(|d| d.generation);
        let f = self.follower.as_ref();
        let incompatible = f.is_some_and(Follower::incompatible);
        let Some(o) = f.and_then(Follower::opened).filter(|_| !incompatible) else {
            let why = f
                .and_then(Follower::error)
                .map_or_else(|| "no epoch".into(), |e| e.to_string());
            return Look {
                epoch: None,
                created_ns: 0,
                status: Err(NoStatus { incompatible, why }),
                heartbeat_age_ns: 0,
                rings: Vec::new(),
                capacity: 0,
                desired_generation,
                now_realtime_ns,
            };
        };
        let l = o.layout();
        Look {
            epoch: Some(o.header.epoch),
            created_ns: o.header.created_ns,
            status: o.status().read().map_err(|e| NoStatus {
                incompatible: false,
                why: e.to_string(),
            }),
            heartbeat_age_ns: monotonic_ns().saturating_sub(o.status().heartbeat()),
            rings: (0..l.workers)
                .map(|r| ring::counters(l, o.file(), r))
                .collect(),
            capacity: (l.workers as u64).saturating_mul(l.slots as u64),
            desired_generation,
            now_realtime_ns,
        }
    }

    fn drain(&mut self, out: &mut Vec<Sample>) -> Drained {
        let mut all = Drained::default();
        let Some(o) = self.follower.as_ref().and_then(Follower::opened) else {
            return all;
        };
        for r in 0..o.layout().workers {
            if let Some(ring) = o.ring(r) {
                // A ring holds a bounded number of slots: a tick's work is
                // bounded with it.
                let d = ring.drain(out, usize::MAX);
                all.taken += d.taken;
                all.corrupt += d.corrupt;
                all.skipped += d.skipped;
            }
        }
        all
    }

    fn maps_epoch(&mut self, instance: &VppInstance, epoch: u64) -> bool {
        start_ticks(instance.pid) == Some(instance.start_ticks)
            && maps_file(instance.pid, &epoch_file_name(epoch))
    }

    fn recorded(&mut self, instance: &VppInstance) -> Result<Option<u64>, String> {
        let at = |e: &dyn std::fmt::Display| format!("{}: {e}", self.record.display());
        let Some(raw) = read_owned_no_follow(&self.record, MAX_RECORD_BYTES).map_err(|e| at(&e))?
        else {
            return Ok(None);
        };
        let r: GenerationRecord = serde_json::from_slice(&raw).map_err(|e| at(&e))?;
        let of = VppInstance {
            pid: r.pid,
            start_ticks: r.start_ticks,
            boot_id: r.boot_id,
        };
        Ok((of == *instance).then_some(r.generation))
    }

    fn record(&mut self, instance: &VppInstance, generation: u64) -> Result<(), String> {
        let r = GenerationRecord {
            pid: instance.pid,
            start_ticks: instance.start_ticks,
            boot_id: instance.boot_id.clone(),
            generation,
        };
        let json = serde_json::to_vec(&r).map_err(|e| e.to_string())?;
        write_state(&self.record, &json).map_err(|e| format!("{}: {e}", self.record.display()))
    }
}

/// Remove a `desired.conf` from a directory the plugin could use, under
/// its lock: what `detach --all` and a release after a failed start do,
/// with no module running.
pub fn release(dir: &Path) -> Result<(), String> {
    if check_dir(dir).is_err() {
        return Ok(());
    }
    match clear_desired(dir) {
        Ok(Some(_)) => Ok(()),
        // Someone else's sampling, or a worker of this daemon's that did
        // not stop: either way, not removed here.
        Ok(None) => Err(format!(
            "{}: desired.lock is held, so VPP's sampler may still be sampling; \
             `packetframe sampler clear` once its holder is gone",
            dir.display()
        )),
        Err(e) => Err(format!("{}: {e}", dir.join(DESIRED).display())),
    }
}

/// Field 22 of `/proc/<pid>/stat`: when the process started, in clock
/// ticks after boot.
fn start_ticks(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name may hold anything but ends at the last `)`; field 3
    // is the first after it.
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(22 - 3)?.parse().ok()
}

/// Whether `pid` maps a file named `name`.
fn maps_file(pid: i32, name: &str) -> bool {
    let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
        return false;
    };
    let suffix = format!("/{name}");
    maps.lines().any(|l| l.ends_with(&suffix))
}

fn realtime_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

/// CLOCK_MONOTONIC: the clock the plugin's heartbeat is in, and the one
/// `bpf_ktime_get_ns` reads.
pub(crate) fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and out-pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

/// The realtime clock, for a [`crate::vpp::VppSide`]'s start.
pub fn now_realtime_ns() -> u64 {
    realtime_ns()
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_sampler_shm::fs::{create_epoch, ensure_dir, publish_current, random_epoch};
    use packetframe_sampler_shm::layout::Layout;
    use packetframe_sampler_shm::ring::{RingWriter, SampleMeta};
    use packetframe_sampler_shm::Class;

    #[test]
    fn this_process_is_found_by_its_start_and_its_mappings() {
        let me = std::process::id() as i32;
        let ticks = start_ticks(me).expect("our own stat");
        let d = std::env::temp_dir().join(format!("pf-flow-vpp-{}", random_epoch()));
        ensure_dir(&d).unwrap();
        let epoch = random_epoch();
        let l = Layout::new(1, 8, 64).unwrap();
        let _m = create_epoch(&d, &l, epoch, 0, 0, "test").unwrap();
        let mut dir = LiveVppDir::new(&d, &d);
        let us = VppInstance {
            pid: me,
            start_ticks: ticks,
            boot_id: None,
        };
        assert!(dir.maps_epoch(&us, epoch), "we map it while _m lives");
        assert!(!dir.maps_epoch(&us, epoch ^ 1));
        let recycled = VppInstance {
            start_ticks: ticks + 1,
            ..us
        };
        assert!(
            !dir.maps_epoch(&recycled, epoch),
            "another start, another process"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The follower's view, without the tmpfs a claim needs: what a look
    /// and a drain read from a real epoch file.
    #[test]
    fn a_look_and_a_drain_read_a_real_epoch() {
        let d = std::env::temp_dir().join(format!("pf-flow-vpp-{}", random_epoch()));
        ensure_dir(&d).unwrap();
        let l = Layout::new(2, 8, 64).unwrap();
        let m = create_epoch(&d, &l, 9, 1234, 0, "test").unwrap();
        publish_current(&d, 9, &l).unwrap();
        let mut dir = LiveVppDir::new(&d, &d);
        dir.follower = Some(Follower::consumer(&d).unwrap());
        let sw = dir.refresh().unwrap();
        assert_eq!((sw.from, sw.to), (None, 9));
        let w = RingWriter::new(&l, m.words(), 1);
        w.add_pool(3, Class::Ingress, 1000);
        let meta = SampleMeta {
            generation: 2,
            time_ns: 1,
            sw_if_index: 5,
            class: Class::Ingress,
            pool_index: 3,
            rate: 1000,
            frame_len: 1500,
        };
        assert!(w.push(&meta, &[0xab; 64]));
        let look = dir.look();
        assert_eq!(
            (look.epoch, look.created_ns, look.capacity),
            (Some(9), 1234, 16)
        );
        assert_eq!(look.rings[1].pool[3][Class::Ingress.index()], 1000);
        assert_eq!(look.rings[1].head - look.rings[1].tail, 1, "queued");
        let mut out = Vec::new();
        assert_eq!(dir.drain(&mut out).taken, 1);
        assert_eq!(out[0].meta, meta);
        // desired.conf as written, read back by the next look.
        let desired = Desired {
            generation: 4,
            rate: 1000,
            header_bytes: 128,
            classes: Class::Ingress.bit(),
            interfaces: vec!["octeon0/0".into()],
        };
        dir.write(&desired).unwrap();
        assert_eq!(dir.look().desired_generation, Some(4));
        dir.remove().unwrap();
        dir.remove().unwrap();
        assert_eq!(dir.look().desired_generation, None);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn the_generation_record_outlives_a_run_for_its_process_only() {
        let d = std::env::temp_dir().join(format!("pf-flow-vpp-{}", random_epoch()));
        let state = d.join("state");
        let vpp = VppInstance {
            pid: 10,
            start_ticks: 100,
            boot_id: Some("b".into()),
        };
        let mut dir = LiveVppDir::new(&d, &state);
        assert_eq!(dir.recorded(&vpp), Ok(None), "no state-dir yet");
        dir.record(&vpp, 3).unwrap();
        let mut next_run = LiveVppDir::new(&d, &state);
        assert_eq!(next_run.recorded(&vpp), Ok(Some(3)));
        let restarted = VppInstance {
            start_ticks: 101,
            ..vpp.clone()
        };
        assert_eq!(next_run.recorded(&restarted), Ok(None));
        next_run.record(&restarted, 1).unwrap();
        assert_eq!(next_run.recorded(&vpp), Ok(None), "one process's at a time");

        std::fs::write(state.join(GENERATION_RECORD), "x").unwrap();
        assert!(next_run.recorded(&vpp).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn release_leaves_a_directory_the_plugin_could_not_use() {
        let d = std::env::temp_dir().join(format!("pf-flow-vpp-{}", random_epoch()));
        ensure_dir(&d).unwrap();
        std::fs::write(d.join(DESIRED), "x").unwrap();
        release(&d).unwrap();
        assert!(d.join(DESIRED).exists(), "not a tmpfs: not the sampler's");
        release(Path::new("/nonexistent/pf-sampler")).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }
}
