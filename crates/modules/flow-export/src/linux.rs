//! The live pieces: fast-path's pinned sampler maps and perf rings, its
//! port registry and sysfs counters, the collectors' socket, and the
//! worker's thread.

use std::net::UdpSocket;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use aya::maps::{Array, Map, MapData};
use packetframe_common::module::HookType;
use packetframe_fast_path::sample::SampleCfg;
use packetframe_fast_path::sample_rings::SampleRings;
use packetframe_fast_path::{pin, registry};

use crate::cfg::FlowExportConfig;
use crate::worker::{Hook, Port, Ports, SampleSource, Shared, Worker, TICK};
use crate::THREAD_NAME;

/// The busiest a single CPU forwards, for sizing its ring.
const PEAK_PPS_PER_CPU: u64 = 2_000_000;
/// How much a ring must hold: two worker ticks.
const RING_HOLDS: Duration = Duration::from_millis(200);
/// The largest event a sample makes: perf's header and size word, the
/// record, the most bytes `header-bytes` allows, and padding.
const EVENT_BYTES: u64 = 8 + 4 + 40 + 256 + 4;

/// Ring pages per CPU for `rate`: a power of two.
fn pages_for(rate: u32) -> usize {
    let samples = PEAK_PPS_PER_CPU * RING_HOLDS.as_millis() as u64 / 1000 / u64::from(rate.max(1));
    // SAFETY: no preconditions.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u64;
    ((samples.max(1) * EVENT_BYTES).div_ceil(page) as usize).next_power_of_two()
}

fn open_cfg(bpffs_root: &Path) -> Result<Array<MapData, SampleCfg>, String> {
    let path = pin::map_path(bpffs_root, "SAMPLE_CFG");
    let md = MapData::from_pin(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    Array::try_from(Map::Array(md)).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn release_sampler(bpffs_root: &Path) -> Result<(), String> {
    if !pin::map_path(bpffs_root, "SAMPLE_CFG").exists() {
        return Ok(());
    }
    open_cfg(bpffs_root)?
        .set(0, SampleCfg::default(), 0)
        .map_err(|e| format!("SAMPLE_CFG: {e}"))
}

struct LiveSource {
    cfg: Array<MapData, SampleCfg>,
    samples: MapData,
    rings: Option<SampleRings>,
    pages: usize,
    cpus: Vec<u32>,
    bpffs_root: PathBuf,
    emit_failed_at: usize,
}

impl LiveSource {
    fn open(bpffs_root: &Path) -> Result<Self, String> {
        let samples_path = pin::map_path(bpffs_root, "SAMPLES");
        let samples = MapData::from_pin(&samples_path)
            .map_err(|e| format!("{}: {e}", samples_path.display()))?;
        let cpus = aya::util::online_cpus().map_err(|(what, e)| format!("{what}: {e}"))?;
        let emit_failed_at = packetframe_fast_path::metrics::COUNTER_NAMES
            .iter()
            .position(|n| *n == "sample_emit_failed")
            .ok_or("fast-path has no sample_emit_failed counter")?;
        Ok(Self {
            cfg: open_cfg(bpffs_root)?,
            samples,
            rings: None,
            pages: 0,
            cpus,
            bpffs_root: bpffs_root.to_owned(),
            emit_failed_at,
        })
    }
}

impl SampleSource for LiveSource {
    fn configure(&mut self, cfg: SampleCfg) -> Result<(), String> {
        self.cfg
            .set(0, cfg, 0)
            .map_err(|e| format!("SAMPLE_CFG: {e}"))
    }

    fn ensure_capacity(&mut self, rate: u32) -> Result<(), String> {
        let want = pages_for(rate);
        if self.rings.is_some() && self.pages >= want {
            return Ok(());
        }
        // The old rings leave the map before the new ones go in; samples
        // in between fail to output and are counted.
        self.rings = None;
        self.rings = Some(
            SampleRings::open(self.samples.fd().as_fd(), &self.cpus, want)
                .map_err(|e| format!("perf rings ({want} pages per CPU): {e}"))?,
        );
        self.pages = want;
        Ok(())
    }

    fn drain(&mut self, f: &mut dyn FnMut(&[u8])) -> u64 {
        match &mut self.rings {
            Some(r) => r.drain(|_, e| f(e)),
            None => 0,
        }
    }

    fn emit_failed(&mut self) -> Option<u64> {
        packetframe_fast_path::stats_from_pin(&self.bpffs_root)
            .ok()
            .and_then(|v| v.get(self.emit_failed_at).copied())
    }
}

struct LivePorts {
    state_dir: PathBuf,
}

impl Ports for LivePorts {
    fn ports(&mut self) -> Result<Vec<Port>, String> {
        let Some(reg) = registry::load(&self.state_dir).map_err(|e| e.to_string())? else {
            return Ok(Vec::new());
        };
        Ok(reg
            .attachments
            .into_iter()
            .filter_map(|a| {
                let hook = match HookType::from(a.hook) {
                    HookType::NativeXdp | HookType::GenericXdp => Hook::Xdp,
                    HookType::TcIngress => Hook::Tc,
                    HookType::TcEgress => return None,
                };
                let name = std::ffi::CString::new(a.iface.as_str()).ok()?;
                // SAFETY: a NUL-terminated name that outlives the call.
                let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
                (ifindex != 0).then_some(Port {
                    name: a.iface,
                    ifindex,
                    hook,
                })
            })
            .collect())
    }

    fn rx_packets(&mut self, port: &Port) -> Option<u64> {
        std::fs::read_to_string(format!(
            "/sys/class/net/{}/statistics/rx_packets",
            port.name
        ))
        .ok()?
        .trim()
        .parse()
        .ok()
    }
}

pub struct Running {
    pub shared: Shared,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    bpffs_root: PathBuf,
}

impl Running {
    pub fn start(
        cfg: FlowExportConfig,
        bpffs_root: &Path,
        state_dir: &Path,
    ) -> Result<Self, String> {
        let epoch = Instant::now();
        let shared = Shared::new(epoch);
        let source = LiveSource::open(bpffs_root)?;
        let socket = UdpSocket::bind((cfg.source, 0))
            .map_err(|e| format!("a socket at source-address {}: {e}", cfg.source))?;
        // A full socket buffer drops a datagram, never stalls the worker.
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("socket: {e}"))?;
        let ports = LivePorts {
            state_dir: state_dir.to_owned(),
        };
        let mut worker = Worker::new(cfg, source, ports, socket, shared.clone(), epoch)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name(THREAD_NAME.into())
            .spawn(move || {
                // Placed with the control plane whenever it starts.
                packetframe_common::placement::join();
                let mut next = Instant::now();
                while !stopping.load(Ordering::Relaxed) {
                    worker.tick(Instant::now());
                    next += TICK;
                    let now = Instant::now();
                    match next.checked_duration_since(now) {
                        Some(d) => std::thread::sleep(d),
                        None => next = now,
                    }
                }
                if let Err(e) = worker.stop() {
                    tracing::warn!(error = %e, "flow-export: stopping the sampler failed");
                }
            })
            .map_err(|e| format!("spawn {THREAD_NAME}: {e}"))?;
        Ok(Self {
            shared,
            stop,
            thread: Some(thread),
            bpffs_root: bpffs_root.to_owned(),
        })
    }

    pub fn reload(&self, cfg: FlowExportConfig) {
        *self.shared.reload.lock().unwrap_or_else(|e| e.into_inner()) = Some(cfg);
    }

    /// Stop the worker, within the second a module's detach has, and the
    /// sampler with it, whatever became of the worker.
    pub fn stop(mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_millis(900);
        if let Some(t) = self.thread.take() {
            while !t.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            if t.is_finished() {
                if t.join().is_err() {
                    tracing::error!("flow-export: the worker had panicked");
                }
            } else {
                tracing::warn!("flow-export: the worker did not stop within its deadline");
            }
        }
        release_sampler(&self.bpffs_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rings_hold_two_ticks_at_the_rate_and_are_a_power_of_two() {
        let p = pages_for(1000);
        assert!(p.is_power_of_two());
        assert!(
            pages_for(100) >= p * 8,
            "ten times the rate, about ten times the ring"
        );
        assert!(pages_for(1 << 24).is_power_of_two());
    }
}
