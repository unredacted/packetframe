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
use crate::kernel;
use crate::vpp::VppSide;
use crate::vpp_live::{self, LiveVppDir};
use crate::worker::{self, Leftover, Path as Lane, Port, Ports, SampleSource, Shared, Worker};
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

pub fn release_sampler(
    bpffs_root: &Path,
    state_dir: &Path,
    vpp_dir: Option<&Path>,
) -> Result<(), String> {
    let fast = if pin::map_path(bpffs_root, "SAMPLE_CFG").exists() {
        open_cfg(bpffs_root).and_then(|mut c| {
            c.set(0, SampleCfg::default(), 0)
                .map_err(|e| format!("SAMPLE_CFG: {e}"))
        })
    } else {
        Ok(())
    };
    let kernel = kernel::detach_from_state_dir(state_dir).map(|_| ());
    let vpp = vpp_dir.map_or(Ok(()), vpp_live::release);
    let errors: Vec<String> = [fast, kernel, vpp]
        .into_iter()
        .filter_map(Result::err)
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// A sampler's programs' count of samples they could not output.
type LossCounter = Box<dyn FnMut() -> Option<u64> + Send>;

/// One sampler's configuration map and rings: fast-path's, or the
/// kernel sampler's.
struct LiveSource {
    /// The configuration map's name, for errors.
    cfg_name: &'static str,
    cfg: Array<MapData, SampleCfg>,
    samples: MapData,
    rings: Option<SampleRings>,
    /// Rings a reload replaced, and when: drained with the new ones for a
    /// tick more, for a program that found them in the map just before
    /// they left it.
    retired: Option<(Instant, SampleRings)>,
    pages: usize,
    cpus: Vec<u32>,
    loss: LossCounter,
}

impl LiveSource {
    /// fast-path's sampler, through its pinned maps.
    fn fast_path(bpffs_root: &Path) -> Result<Self, String> {
        let samples_path = pin::map_path(bpffs_root, "SAMPLES");
        let samples = MapData::from_pin(&samples_path)
            .map_err(|e| format!("{}: {e}", samples_path.display()))?;
        let at = packetframe_fast_path::metrics::COUNTER_NAMES
            .iter()
            .position(|n| *n == "sample_emit_failed")
            .ok_or("fast-path has no sample_emit_failed counter")?;
        let root = bpffs_root.to_owned();
        Ok(Self {
            cfg_name: "SAMPLE_CFG",
            cfg: open_cfg(bpffs_root)?,
            samples,
            rings: None,
            retired: None,
            pages: 0,
            cpus: online_cpus()?,
            loss: Box::new(move || {
                packetframe_fast_path::stats_from_pin(&root)
                    .ok()
                    .and_then(|v| v.get(at).copied())
            }),
        })
    }

    /// The kernel sampler, through the maps its attach took.
    fn kernel(k: kernel::KernelSampler) -> Result<Self, String> {
        let kernel::KernelSampler {
            ebpf,
            cfg,
            samples,
            state,
            ..
        } = k;
        Ok(Self {
            cfg_name: "KSAMPLE_CFG",
            cfg,
            samples,
            rings: None,
            retired: None,
            pages: 0,
            cpus: online_cpus()?,
            loss: Box::new(move || {
                // The object whose program the filters hold lives as long
                // as this source.
                let _ = &ebpf;
                kernel::emit_failed(&state)
            }),
        })
    }
}

fn online_cpus() -> Result<Vec<u32>, String> {
    aya::util::online_cpus().map_err(|(what, e)| format!("{what}: {e}"))
}

impl SampleSource for LiveSource {
    fn configure(&mut self, cfg: SampleCfg) -> Result<(), String> {
        self.cfg
            .set(0, cfg, 0)
            .map_err(|e| format!("{}: {e}", self.cfg_name))
    }

    fn ensure_capacity(&mut self, rate: u32, left: &mut Leftover) -> Result<(), String> {
        let want = pages_for(rate);
        if self.rings.is_some() && self.pages >= want {
            return Ok(());
        }
        // Out of the map first: from then on a sample is either in the old
        // rings, drained here, or a failed output the program counts.
        if let Some((_, mut older)) = self.retired.take() {
            left.lost += older.drain(|_, e| left.events.push(e.to_vec()));
        }
        if let Some(mut old) = self.rings.take() {
            old.uninstall();
            left.lost += old.drain(|_, e| left.events.push(e.to_vec()));
            self.retired = Some((Instant::now(), old));
        }
        let fd = self.samples.fd().as_fd();
        match SampleRings::open(fd, &self.cpus, want) {
            Ok(r) => {
                self.rings = Some(r);
                self.pages = want;
                Ok(())
            }
            Err(e) => {
                let e = format!("perf rings ({want} pages per CPU): {e}");
                // Rings of the size that worked, so export carries on at
                // the rate the kernel still has.
                if self.pages > 0 {
                    match SampleRings::open(fd, &self.cpus, self.pages) {
                        Ok(r) => self.rings = Some(r),
                        Err(again) => {
                            return Err(format!(
                                "{e}; and the old ones could not be put back: {again}"
                            ))
                        }
                    }
                }
                Err(e)
            }
        }
    }

    fn drain(&mut self, f: &mut dyn FnMut(&[u8])) -> u64 {
        let mut lost = 0;
        if let Some((at, old)) = &mut self.retired {
            lost += old.drain(|_, e| f(e));
            if at.elapsed() >= worker::TICK {
                self.retired = None;
            }
        }
        if let Some(r) = &mut self.rings {
            lost += r.drain(|_, e| f(e));
        }
        lost
    }

    fn emit_failed(&mut self) -> Option<u64> {
        (self.loss)()
    }

    fn clock_ns(&self) -> u64 {
        crate::vpp_live::monotonic_ns()
    }
}

/// fast-path's sampler and, with `kernel-sample` lines, the kernel
/// sampler, driven as one: the same configuration, generation and rate,
/// and their rings drained together.
struct Sources {
    fast: LiveSource,
    kernel: Option<LiveSource>,
}

impl SampleSource for Sources {
    fn configure(&mut self, cfg: SampleCfg) -> Result<(), String> {
        let fast = self.fast.configure(cfg);
        let kernel = self.kernel.as_mut().map_or(Ok(()), |k| k.configure(cfg));
        fast.and(kernel)
    }

    fn ensure_capacity(&mut self, rate: u32, left: &mut Leftover) -> Result<(), String> {
        let fast = self.fast.ensure_capacity(rate, left);
        let kernel = self
            .kernel
            .as_mut()
            .map_or(Ok(()), |k| k.ensure_capacity(rate, left));
        fast.and(kernel)
    }

    fn drain(&mut self, f: &mut dyn FnMut(&[u8])) -> u64 {
        self.fast.drain(f) + self.kernel.as_mut().map_or(0, |k| k.drain(f))
    }

    fn emit_failed(&mut self) -> Option<u64> {
        let fast = self.fast.emit_failed()?;
        match &mut self.kernel {
            Some(k) => Some(fast + k.emit_failed()?),
            None => Some(fast),
        }
    }

    /// Both programs stamp `bpf_ktime_get_ns`: one clock.
    fn clock_ns(&self) -> u64 {
        self.fast.clock_ns()
    }
}

struct LivePorts {
    state_dir: PathBuf,
    /// The kernel sampler's interfaces, as attached.
    kernel: Vec<(String, u32)>,
}

impl Ports for LivePorts {
    fn ports(&mut self) -> Result<Vec<Port>, String> {
        // fast-path saves it at its attach, before this module's: gone now
        // is an inventory lost, not a fast-path with no ports.
        let Some(reg) = registry::load(&self.state_dir).map_err(|e| e.to_string())? else {
            return Err(format!(
                "fast-path's attachment registry is missing from {}",
                self.state_dir.display()
            ));
        };
        let mut ports: Vec<Port> = reg
            .attachments
            .into_iter()
            .filter_map(|a| {
                let path = match HookType::from(a.hook) {
                    HookType::NativeXdp | HookType::GenericXdp => Lane::Xdp,
                    HookType::TcIngress => Lane::Tc,
                    HookType::TcEgress => return None,
                };
                let name = std::ffi::CString::new(a.iface.as_str()).ok()?;
                // SAFETY: a NUL-terminated name that outlives the call.
                let ifindex = unsafe { libc::if_nametoindex(name.as_ptr()) };
                (ifindex != 0).then_some(Port {
                    name: a.iface,
                    ifindex,
                    path,
                })
            })
            .collect();
        ports.extend(self.kernel.iter().map(|(name, ifindex)| Port {
            name: name.clone(),
            ifindex: *ifindex,
            path: Lane::Kernel,
        }));
        Ok(ports)
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
    state_dir: PathBuf,
    vpp_dir: Option<PathBuf>,
}

impl Running {
    pub fn start(
        cfg: FlowExportConfig,
        bpffs_root: &Path,
        state_dir: &Path,
        handles: crate::Handles,
    ) -> Result<Self, String> {
        let crate::Handles { vpp, coverage, asn } = handles;
        let epoch = Instant::now();
        let mut shared = Shared::new(epoch);
        shared.coverage = coverage;
        let fast = LiveSource::fast_path(bpffs_root)?;
        let socket = UdpSocket::bind((cfg.source, 0))
            .map_err(|e| format!("a socket at source-address {}: {e}", cfg.source))?;
        // A full socket buffer drops a datagram, never stalls the worker.
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("socket: {e}"))?;
        // The kernel sampler last: everything after it that fails takes
        // its filters back down.
        let (kernel_source, kernel_ports) = if cfg.kernel.is_empty() {
            (None, Vec::new())
        } else {
            let sampled = sampled_ports(state_dir, vpp.as_ref().map(|(p, _)| p.as_ref()));
            let k = kernel::attach(state_dir, &cfg.kernel, &sampled)?;
            let attached = k.attached.clone();
            (Some(LiveSource::kernel(k)?), attached)
        };
        let ports = LivePorts {
            state_dir: state_dir.to_owned(),
            kernel: kernel_ports,
        };
        let source = Sources {
            fast,
            kernel: kernel_source,
        };
        let worker = match Worker::new(cfg, source, ports, socket, shared.clone(), epoch) {
            Ok(w) => w.with_asn(asn),
            Err(e) => {
                let _ = kernel::detach_from_state_dir(state_dir);
                return Err(e);
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let vpp_dir = vpp.as_ref().map(|(_, d)| d.clone());
        let (bpffs, state, dir) = (bpffs_root.to_owned(), state_dir.to_owned(), vpp_dir.clone());
        // A worker that panicked stops nothing itself.
        let after_panic = move || {
            if let Err(e) = release_sampler(&bpffs, &state, dir.as_deref()) {
                tracing::error!(error = %e, "flow-export: stopping the samplers after a panic failed");
            }
        };
        let thread = std::thread::Builder::new()
            .name(THREAD_NAME.into())
            .spawn(move || {
                // Placed with the control plane whenever it starts.
                packetframe_common::placement::join();
                match vpp {
                    // The sampler directory's mappings never leave this
                    // thread.
                    Some((ports, dir)) => {
                        let side = VppSide::new(
                            LiveVppDir::new(&dir),
                            ports,
                            Instant::now(),
                            vpp_live::now_realtime_ns(),
                        );
                        worker::run(worker.with_vpp(side), &stopping, after_panic);
                    }
                    None => worker::run(worker, &stopping, after_panic),
                }
            })
            .map_err(|e| format!("spawn {THREAD_NAME}: {e}"))?;
        Ok(Self {
            shared,
            stop,
            thread: Some(thread),
            bpffs_root: bpffs_root.to_owned(),
            state_dir: state_dir.to_owned(),
            vpp_dir,
        })
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
        release_sampler(&self.bpffs_root, &self.state_dir, self.vpp_dir.as_deref())
    }
}

/// The ports fast-path's programs and VPP sample: a device stacked on one
/// is not the kernel sampler's to sample.
fn sampled_ports(
    state_dir: &Path,
    vpp: Option<&packetframe_common::sampler_ports::VppSamplerPorts>,
) -> Vec<String> {
    let mut out: Vec<String> = registry::load(state_dir)
        .ok()
        .flatten()
        .map(|r| r.attachments.into_iter().map(|a| a.iface).collect())
        .unwrap_or_default();
    if let Some(s) = vpp.and_then(|v| v.current()) {
        out.extend(s.ports.iter().map(|p| p.port.clone()));
    }
    out
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
