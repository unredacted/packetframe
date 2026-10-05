//! The plugin's control loop, minus VPP: the epoch file, `desired.conf`,
//! the heartbeat and the status, driven by one [`Driver::tick`] every
//! 100 ms on VPP's main thread.
//!
//! Nothing here can stop VPP forwarding. A directory that is not a
//! size-limited tmpfs, a full budget or any I/O error leaves the sampler
//! without an epoch, retried every 5 s and shown by `show pf-sampler`;
//! without an epoch no interface has the sampling feature enabled, so the
//! workers never see the sampler at all.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use packetframe_sampler_shm::current::Current;
use packetframe_sampler_shm::desired::ErrorKind;
use packetframe_sampler_shm::fs::{
    check_dir, create_epoch, publish_current, random_epoch, reclaim, Mapping, CURRENT, DEFAULT_DIR,
    DESIRED, ENV_DIR,
};
use packetframe_sampler_shm::layout::Layout;
use packetframe_sampler_shm::ring;
use packetframe_sampler_shm::status::{reason, StatusWriter};
use packetframe_sampler_shm::Class;

use crate::control::{Controller, Vpp};

/// Slots per ring: 4096 samples is about 0.4 s of a 10 Mpps worker at
/// 1-in-1000, against a reader that drains every few milliseconds.
pub const SLOTS_PER_RING: usize = 4096;
/// Packet bytes one sample can carry.
pub const HEADER_CAPACITY: usize = 256;
/// The classes this plugin samples.
pub const IMPLEMENTED: u64 = 1 << Class::Ingress as u64;

const TICK_NS: u64 = 100_000_000;
const RECONCILE_NS: u64 = 1_000_000_000;
const EPOCH_RETRY_NS: u64 = 5_000_000_000;

/// The sampler directory: `PF_SAMPLER_DIR`, or the default when unset.
pub fn sampler_dir() -> Result<PathBuf, String> {
    match std::env::var(ENV_DIR) {
        Err(std::env::VarError::NotPresent) => Ok(PathBuf::from(DEFAULT_DIR)),
        Err(e) => Err(format!("{ENV_DIR}: {e}")),
        Ok(v) if v.starts_with('/') => Ok(PathBuf::from(v)),
        Ok(v) => Err(format!("{ENV_DIR}={v:?} is not an absolute path")),
    }
}

/// This VPP run's epoch file, mapped for as long as the process lives.
pub struct Epoch {
    pub id: u64,
    pub layout: Layout,
    pub map: Mapping,
}

impl Epoch {
    /// Creates the epoch file for `workers` rings, names it in `current`,
    /// and unlinks every other epoch file but the one `current` named
    /// before (a reader may still be switching away from it).
    pub fn create(
        dir: &Path,
        workers: usize,
        build: &str,
        realtime_ns: u64,
        monotonic_ns: u64,
    ) -> Result<Self, String> {
        check_dir(dir).map_err(|e| e.to_string())?;
        let layout =
            Layout::new(workers, SLOTS_PER_RING, HEADER_CAPACITY).map_err(|e| e.to_string())?;
        let previous = fs::read_to_string(dir.join(CURRENT))
            .ok()
            .and_then(|t| Current::parse(&t).ok())
            .map(|c| c.epoch);
        let id = loop {
            let e = random_epoch();
            if e != 0 && Some(e) != previous {
                break e;
            }
        };
        let map = create_epoch(dir, &layout, id, realtime_ns, monotonic_ns, build)
            .map_err(|e| e.to_string())?;
        publish_current(dir, id, &layout).map_err(|e| format!("{CURRENT}: {e}"))?;
        let keep: Vec<u64> = std::iter::once(id).chain(previous).collect();
        // A leftover that cannot be removed costs budget, not correctness.
        let _ = reclaim(dir, &keep);
        Ok(Self { id, layout, map })
    }

    pub fn status(&self) -> StatusWriter<'_> {
        StatusWriter::new(self.layout.status(self.map.words()))
    }
}

/// What the plugin's host must provide beyond [`Vpp`].
pub trait Host: Vpp {
    /// Under VPP's barrier: hand the workers their rings in `epoch`.
    fn publish_epoch(&mut self, epoch: &'static Epoch);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    mtime: i64,
    mtime_nsec: i64,
    size: u64,
}

/// Reports `desired.conf` when it changed: replaced (a new inode), edited,
/// created or removed.
#[derive(Debug, Default)]
pub struct DesiredWatch {
    /// `None` until the first poll.
    last: Option<Option<Stamp>>,
}

impl DesiredWatch {
    /// `Some(contents)` when the file changed since the last poll
    /// (`Some(None)`: it is gone), `None` when it did not.
    pub fn poll(&mut self, path: &Path) -> Option<Option<String>> {
        let stamp = fs::metadata(path).ok().map(|m| Stamp {
            dev: m.dev(),
            ino: m.ino(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
            size: m.size(),
        });
        if self.last == Some(stamp) {
            return None;
        }
        self.last = Some(stamp);
        // A file that vanished between the two calls reads as gone; the
        // next poll sees whatever replaced it.
        Some(stamp.and_then(|_| fs::read_to_string(path).ok()))
    }
}

pub struct Driver {
    dir: PathBuf,
    workers: usize,
    build: String,
    epoch: Option<&'static Epoch>,
    epoch_error: Option<String>,
    next_epoch_try_ns: u64,
    watch: DesiredWatch,
    ctl: Controller,
    next_reconcile_ns: u64,
}

impl Driver {
    pub fn new(dir: PathBuf, workers: usize, build: String) -> Self {
        Self {
            dir,
            workers,
            build,
            epoch: None,
            epoch_error: None,
            next_epoch_try_ns: 0,
            watch: DesiredWatch::default(),
            ctl: Controller::new(HEADER_CAPACITY, IMPLEMENTED),
            next_reconcile_ns: 0,
        }
    }

    /// How long to wait before the next tick.
    pub const TICK: std::time::Duration = std::time::Duration::from_nanos(TICK_NS);

    /// One pass of the control loop.
    pub fn tick(&mut self, host: &mut impl Host, realtime_ns: u64, monotonic_ns: u64) {
        if self.epoch.is_none() && monotonic_ns >= self.next_epoch_try_ns {
            match Epoch::create(
                &self.dir,
                self.workers,
                &self.build,
                realtime_ns,
                monotonic_ns,
            ) {
                Ok(e) => {
                    // One epoch per VPP process: the workers write into it
                    // until VPP exits, so it is never unmapped.
                    let e: &'static Epoch = Box::leak(Box::new(e));
                    host.publish_epoch(e);
                    self.epoch = Some(e);
                    self.epoch_error = None;
                }
                Err(why) => {
                    self.epoch_error = Some(why);
                    self.next_epoch_try_ns = monotonic_ns + EPOCH_RETRY_NS;
                }
            }
        }
        let Some(epoch) = self.epoch else {
            return;
        };
        let status = epoch.status();
        status.beat(monotonic_ns);
        let mut reconcile = monotonic_ns >= self.next_reconcile_ns;
        if let Some(text) = self.watch.poll(&self.dir.join(DESIRED)) {
            self.ctl.desired(text.as_deref(), realtime_ns);
            reconcile = true;
        }
        if reconcile {
            self.ctl.reconcile(host, realtime_ns);
            self.next_reconcile_ns = monotonic_ns + RECONCILE_NS;
        }
        if self.ctl.take_changed() {
            status.publish(&self.ctl.status());
        }
    }

    pub fn controller(&self) -> &Controller {
        &self.ctl
    }

    /// `show pf-sampler`'s body.
    pub fn describe(&self) -> Vec<String> {
        let mut out = vec![format!("directory {}", self.dir.display())];
        let Some(epoch) = self.epoch else {
            out.push(format!(
                "no epoch: {} (retrying every 5 s; VPP forwards unsampled)",
                self.epoch_error.as_deref().unwrap_or("not created yet")
            ));
            return out;
        };
        let l = &epoch.layout;
        out.push(format!(
            "epoch {:016x}: {} rings of {} slots, {} header bytes",
            epoch.id, l.workers, l.slots, l.header_capacity
        ));
        let s = self.ctl.status();
        out.push(format!(
            "state {:?} ({}); applied generation {}, rate 1:{}, header {} bytes",
            s.state,
            reason::describe(s.reason),
            s.applied_generation,
            s.rate,
            s.header_bytes
        ));
        if let Some(e) = self.ctl.rejection() {
            out.push(format!(
                "rejected generation {}: {e}",
                s.rejected_generation
            ));
        } else if s.rejected_reason != 0 {
            let kind = ErrorKind::from_code(s.rejected_reason).map_or("?", ErrorKind::describe);
            out.push(format!("rejected: {kind}"));
        }
        for i in &s.interfaces {
            let at = match i.sw_if_index {
                Some(sw) => format!("sw_if_index {sw}"),
                None => format!("unresolved since {} ns", i.unresolved_since_ns),
            };
            out.push(format!("  {} ({at}), pool {}", i.name, i.pool_index));
        }
        for r in 0..l.workers {
            let c = ring::counters(l, epoch.map.words(), r);
            out.push(format!(
                "ring {r}: selected {} written {} dropped-full {} queued {}",
                c.selected,
                c.written,
                c.dropped_full,
                c.head.wrapping_sub(c.tail)
            ));
        }
        out
    }
}
