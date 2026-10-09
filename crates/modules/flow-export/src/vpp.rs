//! VPP's sampler as a source of samples: the plugin's rings, status and
//! per-interface pools (`packetframe_sampler_shm`), and the `desired.conf`
//! this module owns while it runs.
//!
//! **Ownership.** The module holds `desired.lock` for as long as it runs,
//! so the lab's `packetframe sampler configure` and `clear` are refused
//! meanwhile, and `consumer.lock` through its follower. vpp-offload,
//! listed before it, removed any `desired.conf` a crashed daemon left at
//! its attach; this module removes its own when it stops.
//!
//! **Interpretation.** A sample names its interface by `sw_if_index`,
//! which means something only to the VPP that wrote it. Each generation
//! written is bound to the port snapshot of one VPP process
//! (`packetframe_common::sampler_ports`), and a sample is read through
//! its own generation's binding, and only when its epoch is that
//! process's: the process maps the epoch file. Anything else is counted
//! unmapped, never attributed to a port by guess.
//!
//! **Pools** are the plugin's per-interface packet counts, summed over
//! its rings and attributed to a port by the name the status gives each
//! pool index. An index that changes hands starts its count again
//! (`pf-sampler-core`'s `pools`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use packetframe_common::sampler_ports::{VppInstance, VppSamplerPorts};
use packetframe_sampler_shm::coverage::{
    assess, Coverage, NoStatus, Observation, UNRESOLVED_GRACE_NS,
};
use packetframe_sampler_shm::desired::Desired;
use packetframe_sampler_shm::ring::{Counters, Drained, Sample};
use packetframe_sampler_shm::status::Status;
use packetframe_sampler_shm::Class;

/// How often a directory that could not be claimed, a `desired.conf`
/// that could not be written, or an epoch whose process is not yet known
/// is tried again.
pub const RETRY: Duration = Duration::from_secs(1);

/// Generations whose bindings are kept: samples queued under any of them
/// stay readable.
const BINDINGS_KEPT: usize = 8;

/// An epoch change the follower saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSwitch {
    pub from: Option<u64>,
    pub to: u64,
    /// Samples left queued in the epoch it left.
    pub abandoned: u64,
}

/// One look at the open epoch.
#[derive(Debug, Clone)]
pub struct Look {
    pub epoch: Option<u64>,
    /// Realtime nanoseconds the epoch was created.
    pub created_ns: u64,
    pub status: Result<Status, NoStatus>,
    pub heartbeat_age_ns: u64,
    /// Each ring's counters.
    pub rings: Vec<Counters>,
    /// What the rings hold in all.
    pub capacity: u64,
    /// The generation `desired.conf` holds, if it is readable.
    pub desired_generation: Option<u64>,
    pub now_realtime_ns: u64,
}

/// The sampler directory, behind a trait for the tests.
pub trait VppDir {
    /// Take `desired.lock` and `consumer.lock`, once the directory passes
    /// the plugin's own check. An error says why not yet; it is tried
    /// again.
    fn claim(&mut self) -> Result<(), String>;
    /// Replace `desired.conf` (the lock is held).
    fn write(&mut self, d: &Desired) -> Result<(), String>;
    /// Remove `desired.conf` (the lock is held): the plugin stops.
    fn remove(&mut self) -> Result<(), String>;
    /// Follow `current` to the epoch it names.
    fn refresh(&mut self) -> Option<EpochSwitch>;
    fn look(&mut self) -> Look;
    /// Every ring's queued samples, appended to `out`.
    fn drain(&mut self, out: &mut Vec<Sample>) -> Drained;
    /// Whether `instance` is the process that maps `epoch`'s file.
    fn maps_epoch(&mut self, instance: &VppInstance, epoch: u64) -> bool;
}

/// No VPP: the worker's sampler side when vpp-offload is not configured.
pub enum NoVpp {}

impl VppDir for NoVpp {
    fn claim(&mut self) -> Result<(), String> {
        match *self {}
    }
    fn write(&mut self, _: &Desired) -> Result<(), String> {
        match *self {}
    }
    fn remove(&mut self) -> Result<(), String> {
        match *self {}
    }
    fn refresh(&mut self) -> Option<EpochSwitch> {
        match *self {}
    }
    fn look(&mut self) -> Look {
        match *self {}
    }
    fn drain(&mut self, _: &mut Vec<Sample>) -> Drained {
        match *self {}
    }
    fn maps_epoch(&mut self, _: &VppInstance, _: u64) -> bool {
        match *self {}
    }
}

/// A member port as flow export reports it: VPP's name for it, and the
/// kernel port and ifindex it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VppPort {
    pub vpp_name: String,
    pub port: String,
    pub ifindex: u32,
}

/// A generation written, and the process whose interface indices it was
/// written for.
struct Binding {
    instance: VppInstance,
    by_index: BTreeMap<u32, u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Written {
    generation: u64,
    rate: u32,
    header_bytes: u32,
    instance: VppInstance,
    names: Vec<String>,
}

/// A pool index's count as last read, and the interface holding it then.
struct PoolTrack {
    name: String,
    last: u64,
}

/// A sample read through its binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VppSample {
    pub ifindex: u32,
    pub rate: u32,
    pub frame_len: u32,
    pub header: Vec<u8>,
}

/// What one tick took from the sampler.
#[derive(Debug, Default)]
pub struct Taken {
    pub samples: Vec<VppSample>,
    /// Packets each kernel ifindex's interface counted since the last
    /// tick.
    pub pools: BTreeMap<u32, u64>,
    /// Samples lost on the way: rings full, slots unreadable, or left
    /// queued in an epoch that ended.
    pub lost: u64,
    /// Samples no binding could read.
    pub unmapped: u64,
}

/// The plugin as a whole: the `vpp` row, and what every VPP lane is held
/// to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VppHealth {
    pub coverage: Coverage,
    pub why: String,
    pub epoch: Option<u64>,
    pub applied: Option<u64>,
    pub written: Option<u64>,
    /// VPP names the plugin has not found past its grace.
    pub missing: BTreeSet<String>,
}

impl VppHealth {
    fn unavailable(why: impl Into<String>) -> Self {
        Self {
            coverage: Coverage::Unavailable,
            why: why.into(),
            epoch: None,
            applied: None,
            written: None,
            missing: BTreeSet::new(),
        }
    }
}

pub struct VppSide<D> {
    dir: D,
    ports: Arc<VppSamplerPorts>,
    claimed: bool,
    next_claim: Instant,
    /// Every member port seen, by VPP name: the last snapshot's, kept
    /// while no VPP is up so its ports still read as uncovered.
    known: BTreeMap<String, VppPort>,
    written: Option<Written>,
    write_error: Option<String>,
    next_write: Instant,
    bindings: BTreeMap<u64, Binding>,
    epoch: Option<u64>,
    owner: Option<VppInstance>,
    next_owner_check: Instant,
    /// Ring counters at the last look of this epoch; `None` before its
    /// first.
    base: Option<Vec<Counters>>,
    /// The open epoch began after this module did: everything it counted
    /// is new.
    fresh: bool,
    pools: BTreeMap<u8, PoolTrack>,
    /// The open epoch's status has been read: a pool index first seen
    /// after that was handed out since, and counts from zero.
    seeded: bool,
    started_ns: u64,
    window_lost: u64,
    /// Samples no binding could read in the window: lost to the
    /// collectors as surely as a full ring's.
    window_unmapped: u64,
    window_traffic: bool,
    health: VppHealth,
    buf: Vec<Sample>,
}

impl<D: VppDir> VppSide<D> {
    pub fn new(dir: D, ports: Arc<VppSamplerPorts>, now: Instant, now_realtime_ns: u64) -> Self {
        Self {
            dir,
            ports,
            claimed: false,
            next_claim: now,
            known: BTreeMap::new(),
            written: None,
            write_error: None,
            next_write: now,
            bindings: BTreeMap::new(),
            epoch: None,
            owner: None,
            next_owner_check: now,
            base: None,
            fresh: false,
            pools: BTreeMap::new(),
            seeded: false,
            started_ns: now_realtime_ns,
            window_lost: 0,
            window_unmapped: 0,
            window_traffic: false,
            health: VppHealth::unavailable("the sampler directory has not been looked at yet"),
            buf: Vec::new(),
        }
    }

    pub fn health(&self) -> &VppHealth {
        &self.health
    }

    /// Every member port seen.
    pub fn ports(&self) -> impl Iterator<Item = &VppPort> {
        self.known.values()
    }

    /// A coverage window ended.
    pub fn end_window(&mut self) {
        self.window_lost = 0;
        self.window_unmapped = 0;
        self.window_traffic = false;
    }

    /// Stop the plugin sampling: what this module wrote goes.
    pub fn stop(&mut self) -> Result<(), String> {
        if self.claimed && self.written.take().is_some() {
            self.dir.remove()?;
        }
        Ok(())
    }

    pub fn tick(&mut self, now: Instant, rate: u32, header_bytes: u32) -> Taken {
        let mut t = Taken::default();
        let snapshot = self.ports.current();
        if let Some(s) = &snapshot {
            for p in &s.ports {
                if let Some(ifindex) = p.ifindex {
                    self.known.insert(
                        p.vpp_name.clone(),
                        VppPort {
                            vpp_name: p.vpp_name.clone(),
                            port: p.port.clone(),
                            ifindex,
                        },
                    );
                }
            }
        }
        if !self.claimed {
            if now < self.next_claim {
                return t;
            }
            self.next_claim = now + RETRY;
            match self.dir.claim() {
                Ok(()) => self.claimed = true,
                Err(e) => {
                    self.health = VppHealth::unavailable(format!("sampler directory: {e}"));
                    return t;
                }
            }
        }

        if let Some(sw) = self.dir.refresh() {
            t.lost += sw.abandoned;
            self.epoch = Some(sw.to);
            self.owner = None;
            self.next_owner_check = now;
            self.base = None;
            self.fresh = sw.from.is_some();
            self.pools.clear();
            self.seeded = false;
        }
        let look = self.dir.look();
        let first = self.base.is_none();
        if first && look.epoch.is_some() {
            self.fresh |= look.created_ns >= self.started_ns;
        }
        let status = look.status.as_ref().ok();

        // desired.conf: what VPP's ports and the rate call for, bound to
        // the process whose indices it names.
        let target = match &snapshot {
            Some(s) => {
                // A port with no kernel ifindex could be sampled but never
                // reported: not asked for.
                let mut names: Vec<String> = s
                    .ports
                    .iter()
                    .filter(|p| p.ifindex.is_some())
                    .map(|p| p.vpp_name.clone())
                    .collect();
                names.sort();
                let by_index = s
                    .ports
                    .iter()
                    .filter_map(|p| Some((p.sw_if_index, p.ifindex?)))
                    .collect();
                Some((s.instance.clone(), names, by_index))
            }
            // No VPP up: a rate change still goes to the file, under the
            // last process's binding.
            None => self.written.as_ref().and_then(|w| {
                let b = self.bindings.get(&w.generation)?;
                Some((w.instance.clone(), w.names.clone(), b.by_index.clone()))
            }),
        };
        if let Some((instance, names, by_index)) = target {
            let stale = self.written.as_ref().is_none_or(|w| {
                w.instance != instance
                    || w.names != names
                    || (w.rate, w.header_bytes) != (rate, header_bytes)
                    || look.desired_generation != Some(w.generation)
            });
            if stale && now >= self.next_write {
                let newest = [
                    look.desired_generation,
                    status.map(|s| s.applied_generation),
                    status.map(|s| s.rejected_generation),
                    self.written.as_ref().map(|w| w.generation),
                    self.bindings.keys().next_back().copied(),
                ]
                .into_iter()
                .flatten()
                .max()
                .unwrap_or(0);
                let written = match newest.checked_add(1) {
                    // Only a hand-written generation gets here; the
                    // plugin's status keeps it until VPP restarts.
                    None => Err(format!(
                        "generation {newest} is in sight and none can follow it: VPP's \
                         sampler needs a restart with no desired.conf"
                    )),
                    Some(generation) => {
                        let d = Desired {
                            generation,
                            rate,
                            header_bytes,
                            classes: Class::Ingress.bit(),
                            interfaces: names.clone(),
                        };
                        self.dir.write(&d).map(|()| d)
                    }
                };
                match written {
                    Ok(d) => {
                        self.bindings.insert(
                            d.generation,
                            Binding {
                                instance: instance.clone(),
                                by_index,
                            },
                        );
                        while self.bindings.len() > BINDINGS_KEPT {
                            self.bindings.pop_first();
                        }
                        self.written = Some(Written {
                            generation: d.generation,
                            rate,
                            header_bytes,
                            instance,
                            names,
                        });
                        self.write_error = None;
                    }
                    Err(e) => {
                        self.write_error = Some(e);
                        self.next_write = now + RETRY;
                    }
                }
            }
        }

        // Whose epoch this is: until known, its samples are unmapped.
        if let (Some(epoch), Some(s)) = (look.epoch, &snapshot) {
            if self.owner.as_ref() != Some(&s.instance) && now >= self.next_owner_check {
                self.next_owner_check = now + RETRY;
                if self.dir.maps_epoch(&s.instance, epoch) {
                    self.owner = Some(s.instance.clone());
                }
            }
        }

        let d = self.dir.drain(&mut self.buf);
        t.lost += d.corrupt + d.skipped;
        for s in self.buf.drain(..) {
            let ifindex = self
                .bindings
                .get(&s.meta.generation)
                .filter(|b| self.owner.as_ref() == Some(&b.instance))
                .and_then(|b| b.by_index.get(&s.meta.sw_if_index));
            match ifindex {
                Some(&ifindex) => t.samples.push(VppSample {
                    ifindex,
                    rate: s.meta.rate,
                    frame_len: s.meta.frame_len,
                    header: s.header,
                }),
                None => t.unmapped += 1,
            }
        }

        // The rings' loss and the interfaces' pools since the last look.
        let zero = |c: &Counters| Counters {
            head: 0,
            tail: 0,
            selected: 0,
            written: 0,
            dropped_full: 0,
            pool: vec![[0; packetframe_sampler_shm::layout::CLASSES]; c.pool.len()],
        };
        let base = match self.base.take() {
            Some(b) if b.len() == look.rings.len() => b,
            _ if self.fresh || !first => look.rings.iter().map(zero).collect(),
            _ => look.rings.clone(),
        };
        for (now_c, before) in look.rings.iter().zip(&base) {
            t.lost += now_c.dropped_full.saturating_sub(before.dropped_full);
        }
        if let Some(s) = status {
            let count_all = self.fresh || self.seeded;
            for i in &s.interfaces {
                let pi = usize::from(i.pool_index);
                let reading: u64 = look
                    .rings
                    .iter()
                    .map(|c| c.pool.get(pi).map_or(0, |p| p[Class::Ingress.index()]))
                    .sum();
                let delta = match self.pools.get(&i.pool_index) {
                    Some(p) if p.name == i.name => reading.saturating_sub(p.last),
                    // Changed hands: what it holds is the last holder's.
                    Some(_) => 0,
                    None if count_all => reading,
                    None => 0,
                };
                self.pools.insert(
                    i.pool_index,
                    PoolTrack {
                        name: i.name.clone(),
                        last: reading,
                    },
                );
                if delta > 0 {
                    if let Some(p) = self.known.get(&i.name) {
                        *t.pools.entry(p.ifindex).or_default() += delta;
                    }
                }
            }
            self.seeded = true;
        }
        if look.epoch.is_some() {
            self.base = Some(look.rings.clone());
        }

        self.window_lost += t.lost;
        self.window_unmapped += t.unmapped;
        self.window_traffic |= !t.pools.is_empty();
        self.health = self.judge(&look);
        t
    }

    fn judge(&self, look: &Look) -> VppHealth {
        let status = look.status.as_ref().ok();
        let missing = status
            .map(|s| {
                s.interfaces
                    .iter()
                    .filter(|i| {
                        i.sw_if_index.is_none()
                            && look.now_realtime_ns.saturating_sub(i.unresolved_since_ns)
                                > UNRESOLVED_GRACE_NS
                    })
                    .map(|i| i.name.clone())
                    .collect()
            })
            .unwrap_or_default();
        let (coverage, why) = if let Some(e) = &self.write_error {
            (
                // Nothing asked of the plugin yet, or an older ask stands.
                if self.written.is_none() {
                    Coverage::Unavailable
                } else {
                    Coverage::Degraded
                },
                format!("desired.conf could not be written: {e}"),
            )
        } else if self.written.is_none() {
            (
                Coverage::Unavailable,
                "no VPP ports attached yet, so nothing is asked of the sampler".to_string(),
            )
        } else {
            assess(&Observation {
                status: look.status.as_ref().map_err(Clone::clone),
                heartbeat_age_ns: look.heartbeat_age_ns,
                desired_generation: look.desired_generation,
                now_realtime_ns: look.now_realtime_ns,
                traffic: self.window_traffic,
                lost: self.window_lost,
                backlog: look
                    .rings
                    .iter()
                    .map(|c| c.head.saturating_sub(c.tail))
                    .sum(),
                capacity: look.capacity,
            })
        };
        // A sampler that samples as asked still covers nothing whose
        // samples cannot be read: say so, unless something worse is wrong.
        let (coverage, why) = if coverage.is_healthy() && self.window_unmapped > 0 {
            (
                Coverage::Degraded,
                format!(
                    "{} samples could not be read: their VPP process's ports are not \
                     published, its epoch is not known to be its, or their generation \
                     is not one this module wrote",
                    self.window_unmapped
                ),
            )
        } else {
            (coverage, why)
        };
        VppHealth {
            coverage,
            why,
            epoch: look.epoch,
            applied: status.map(|s| s.applied_generation),
            written: self.written.as_ref().map(|w| w.generation),
            missing,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use packetframe_common::sampler_ports::{SampledPort, VppPortsSnapshot};
    use packetframe_sampler_shm::ring::SampleMeta;
    use packetframe_sampler_shm::status::{Interface, State};
    use std::cell::RefCell;
    use std::rc::Rc;

    pub const NOW_NS: u64 = 1_790_000_000_000_000_000;

    /// The plugin and its directory, as the tests drive them.
    #[derive(Default)]
    pub struct Plugin {
        pub claim_error: Option<String>,
        pub write_error: Option<String>,
        pub desired: Option<Desired>,
        pub removed: bool,
        pub switch: Option<EpochSwitch>,
        pub epoch: Option<u64>,
        pub created_ns: u64,
        pub status: Option<Status>,
        pub heartbeat_age_ns: u64,
        pub rings: Vec<Counters>,
        pub queued: Vec<Sample>,
        pub corrupt: u64,
        /// The processes found to map each epoch.
        pub mappers: BTreeMap<u64, i32>,
    }

    #[derive(Clone, Default)]
    pub struct FakeDir(pub Rc<RefCell<Plugin>>);

    impl VppDir for FakeDir {
        fn claim(&mut self) -> Result<(), String> {
            self.0.borrow().claim_error.clone().map_or(Ok(()), Err)
        }
        fn write(&mut self, d: &Desired) -> Result<(), String> {
            let mut p = self.0.borrow_mut();
            if let Some(e) = &p.write_error {
                return Err(e.clone());
            }
            p.desired = Some(d.clone());
            Ok(())
        }
        fn remove(&mut self) -> Result<(), String> {
            let mut p = self.0.borrow_mut();
            p.desired = None;
            p.removed = true;
            Ok(())
        }
        fn refresh(&mut self) -> Option<EpochSwitch> {
            self.0.borrow_mut().switch.take()
        }
        fn look(&mut self) -> Look {
            let p = self.0.borrow();
            Look {
                epoch: p.epoch,
                created_ns: p.created_ns,
                status: p.status.clone().ok_or(NoStatus {
                    incompatible: false,
                    why: "no epoch".into(),
                }),
                heartbeat_age_ns: p.heartbeat_age_ns,
                rings: p.rings.clone(),
                capacity: 8192,
                desired_generation: p.desired.as_ref().map(|d| d.generation),
                now_realtime_ns: NOW_NS,
            }
        }
        fn drain(&mut self, out: &mut Vec<Sample>) -> Drained {
            let mut p = self.0.borrow_mut();
            let taken = p.queued.len();
            out.append(&mut p.queued);
            Drained {
                taken,
                corrupt: std::mem::take(&mut p.corrupt),
                skipped: 0,
            }
        }
        fn maps_epoch(&mut self, instance: &VppInstance, epoch: u64) -> bool {
            self.0.borrow().mappers.get(&epoch) == Some(&instance.pid)
        }
    }

    pub fn instance(pid: i32) -> VppInstance {
        VppInstance {
            pid,
            start_ticks: 100,
            boot_id: None,
        }
    }

    /// A VPP with `eth2` as `octeon0/0` and `eth3` as `octeon1/0`.
    pub fn snapshot(pid: i32, sw_eth2: u32, sw_eth3: u32) -> VppPortsSnapshot {
        let port = |port: &str, ifindex, vpp_name: &str, sw_if_index| SampledPort {
            port: port.into(),
            ifindex: Some(ifindex),
            vpp_name: vpp_name.into(),
            sw_if_index,
        };
        VppPortsSnapshot {
            instance: instance(pid),
            ports: vec![
                port("eth2", 4, "octeon0/0", sw_eth2),
                port("eth3", 5, "octeon1/0", sw_eth3),
            ],
        }
    }

    pub fn rings(pools: &[u64], dropped_full: u64) -> Vec<Counters> {
        let mut pool = vec![[0; packetframe_sampler_shm::layout::CLASSES]; 64];
        for (i, &n) in pools.iter().enumerate() {
            pool[i][Class::Ingress.index()] = n;
        }
        vec![Counters {
            head: 0,
            tail: 0,
            selected: 0,
            written: 0,
            dropped_full,
            pool,
        }]
    }

    /// The plugin's status once it applied `generation`: octeon0/0 at pool
    /// index 0, octeon1/0 at 1.
    pub fn applied(generation: u64, sw_eth2: u32, sw_eth3: u32) -> Status {
        let i = |name: &str, sw, pool_index| Interface {
            name: name.into(),
            sw_if_index: Some(sw),
            pool_index,
            unresolved_since_ns: 0,
        };
        Status {
            state: State::Enabled,
            applied_generation: generation,
            rate: 1000,
            header_bytes: 128,
            classes: Class::Ingress.bit(),
            interfaces: vec![i("octeon0/0", sw_eth2, 0), i("octeon1/0", sw_eth3, 1)],
            ..Status::default()
        }
    }

    pub fn sample(generation: u64, sw_if_index: u32) -> Sample {
        Sample {
            seq: 0,
            meta: SampleMeta {
                generation,
                time_ns: NOW_NS,
                sw_if_index,
                class: Class::Ingress,
                pool_index: 0,
                rate: 1000,
                frame_len: 1500,
            },
            header: vec![0x5a; 64],
        }
    }

    struct Rig {
        side: VppSide<FakeDir>,
        plugin: Rc<RefCell<Plugin>>,
        ports: Arc<VppSamplerPorts>,
        t0: Instant,
    }

    /// VPP pid 10 up with its epoch 7, which began after the module.
    fn rig() -> Rig {
        let dir = FakeDir::default();
        let plugin = dir.0.clone();
        {
            let mut p = plugin.borrow_mut();
            p.switch = Some(EpochSwitch {
                from: None,
                to: 7,
                abandoned: 0,
            });
            p.epoch = Some(7);
            p.created_ns = NOW_NS;
            p.mappers.insert(7, 10);
            p.rings = rings(&[], 0);
        }
        let ports = Arc::new(VppSamplerPorts::new());
        ports.publish(snapshot(10, 1, 2));
        let t0 = Instant::now();
        let side = VppSide::new(dir, ports.clone(), t0, NOW_NS - 1);
        Rig {
            side,
            plugin,
            ports,
            t0,
        }
    }

    #[test]
    fn the_first_tick_asks_for_every_vpp_port_and_reads_its_samples() {
        let mut r = rig();
        let t = r.side.tick(r.t0, 1000, 128);
        let d = r.plugin.borrow().desired.clone().unwrap();
        assert_eq!(d.generation, 1);
        assert_eq!(d.interfaces, vec!["octeon0/0", "octeon1/0"]);
        assert_eq!((d.rate, d.header_bytes), (1000, 128));
        assert!(t.samples.is_empty());

        {
            let mut p = r.plugin.borrow_mut();
            p.status = Some(applied(1, 1, 2));
            p.queued = vec![sample(1, 2), sample(1, 1), sample(1, 99)];
            p.rings = rings(&[3000, 500], 0);
        }
        let t = r.side.tick(r.t0 + crate::worker::TICK, 1000, 128);
        let at: Vec<u32> = t.samples.iter().map(|s| s.ifindex).collect();
        assert_eq!(at, vec![5, 4], "through generation 1's binding");
        assert_eq!(t.unmapped, 1, "an index the binding does not know");
        assert_eq!(
            t.pools,
            BTreeMap::from([(4, 3000), (5, 500)]),
            "an epoch that began after the module: all of it is new"
        );
        assert_eq!(
            r.side.health().coverage,
            Coverage::Degraded,
            "the unknown index's sample is lost"
        );
        r.side.end_window();
        r.side.tick(r.t0 + 2 * crate::worker::TICK, 1000, 128);
        assert!(r.side.health().coverage.is_healthy(), "a window without");
    }

    #[test]
    fn an_epoch_that_was_running_before_counts_from_the_first_look() {
        let mut r = rig();
        r.plugin.borrow_mut().created_ns = NOW_NS - 10;
        r.plugin.borrow_mut().status = Some(applied(1, 1, 2));
        r.plugin.borrow_mut().rings = rings(&[3000, 500], 40);
        let t = r.side.tick(r.t0, 1000, 128);
        assert!(t.pools.is_empty() && t.lost == 0, "{t:?}");
        r.plugin.borrow_mut().rings = rings(&[3100, 500], 42);
        let t = r.side.tick(r.t0 + crate::worker::TICK, 1000, 128);
        assert_eq!(t.pools, BTreeMap::from([(4, 100)]));
        assert_eq!(t.lost, 2, "the rings filled twice");
    }

    #[test]
    fn a_restarted_vpp_is_read_only_through_its_own_binding() {
        let mut r = rig();
        r.side.tick(r.t0, 1000, 128);
        // VPP restarts as pid 11, numbering the ports the other way round.
        // Its epoch shows before vpp-offload publishes its ports, with a
        // sample taken under the old generation.
        {
            let mut p = r.plugin.borrow_mut();
            p.switch = Some(EpochSwitch {
                from: Some(7),
                to: 8,
                abandoned: 4,
            });
            p.epoch = Some(8);
            p.mappers.insert(8, 11);
            p.status = Some(applied(1, 2, 1));
            p.queued = vec![sample(1, 2)];
        }
        r.ports.withdraw();
        let t = r.side.tick(r.t0 + RETRY, 1000, 128);
        assert_eq!(t.lost, 4, "abandoned with the old epoch");
        assert_eq!(t.unmapped, 1, "generation 1 named pid 10's indices");
        assert!(t.samples.is_empty());

        r.ports.publish(snapshot(11, 2, 1));
        r.plugin.borrow_mut().queued = vec![sample(1, 2)];
        let t = r.side.tick(r.t0 + 2 * RETRY, 1000, 128);
        assert_eq!(
            r.plugin.borrow().desired.as_ref().unwrap().generation,
            2,
            "rewritten for the new process"
        );
        assert_eq!(t.unmapped, 1, "still generation 1's: never guessed");
        r.plugin.borrow_mut().queued = vec![sample(2, 2)];
        let t = r.side.tick(r.t0 + 3 * RETRY, 1000, 128);
        assert_eq!(t.samples[0].ifindex, 4, "pid 11's index 2 is eth2");
    }

    #[test]
    fn a_pool_index_that_changes_hands_starts_again() {
        let mut r = rig();
        r.plugin.borrow_mut().created_ns = NOW_NS - 10;
        r.plugin.borrow_mut().status = Some(applied(1, 1, 2));
        r.plugin.borrow_mut().rings = rings(&[3000, 500], 0);
        r.side.tick(r.t0, 1000, 128);
        // octeon1/0 now counts at index 0.
        let mut s = applied(1, 1, 2);
        s.interfaces.remove(0);
        s.interfaces[0].pool_index = 0;
        r.plugin.borrow_mut().status = Some(s);
        r.plugin.borrow_mut().rings = rings(&[3010, 500], 0);
        let t = r.side.tick(r.t0 + crate::worker::TICK, 1000, 128);
        assert!(t.pools.is_empty(), "octeon0/0's count is not eth3's");
        r.plugin.borrow_mut().rings = rings(&[3020, 500], 0);
        let t = r.side.tick(r.t0 + 2 * crate::worker::TICK, 1000, 128);
        assert_eq!(t.pools, BTreeMap::from([(5, 10)]));
    }

    #[test]
    fn a_rate_change_is_a_new_generation_even_with_no_vpp_up() {
        let mut r = rig();
        r.side.tick(r.t0, 1000, 128);
        r.ports.withdraw();
        r.side.tick(r.t0 + RETRY, 500, 128);
        let d = r.plugin.borrow().desired.clone().unwrap();
        assert_eq!((d.generation, d.rate), (2, 500));
        assert_eq!(d.interfaces, vec!["octeon0/0", "octeon1/0"]);
    }

    #[test]
    fn the_newest_generation_in_sight_is_passed() {
        let mut r = rig();
        let mut s = applied(41, 1, 2);
        s.rejected_generation = 42;
        r.plugin.borrow_mut().status = Some(s);
        r.side.tick(r.t0, 1000, 128);
        assert_eq!(r.plugin.borrow().desired.as_ref().unwrap().generation, 43);
    }

    #[test]
    fn health_says_what_is_wrong() {
        let mut r = rig();
        r.plugin.borrow_mut().claim_error = Some("not a tmpfs".into());
        r.side.tick(r.t0, 1000, 128);
        assert_eq!(r.side.health().coverage, Coverage::Unavailable);
        assert!(r.side.health().why.contains("not a tmpfs"));
        assert!(r.plugin.borrow().desired.is_none());
        // Claimed a second later; the plugin has not applied it yet.
        r.plugin.borrow_mut().claim_error = None;
        r.side.tick(r.t0 + RETRY, 1000, 128);
        assert_eq!(r.side.health().coverage, Coverage::Unavailable, "no status");
        r.plugin.borrow_mut().status = Some(applied(0, 1, 2));
        r.side.tick(r.t0 + RETRY + crate::worker::TICK, 1000, 128);
        assert_eq!(r.side.health().coverage, Coverage::Degraded);
        assert!(r.side.health().why.contains("desired generation 1"));
        // Applied, but losing samples.
        r.plugin.borrow_mut().status = Some(applied(1, 1, 2));
        r.plugin.borrow_mut().corrupt = 2;
        r.side
            .tick(r.t0 + RETRY + 2 * crate::worker::TICK, 1000, 128);
        assert_eq!(r.side.health().coverage, Coverage::Degraded);
        assert!(r.side.health().why.contains("2 samples lost"));
        r.side.end_window();
        r.side
            .tick(r.t0 + RETRY + 3 * crate::worker::TICK, 1000, 128);
        assert!(r.side.health().coverage.is_healthy());
    }

    /// Samples that cannot be read are lost to the collectors: a process
    /// whose mappings cannot be read leaves every one unmapped, and the
    /// sampler is not healthy for it.
    #[test]
    fn samples_that_cannot_be_read_degrade_the_sampler() {
        let mut r = rig();
        r.plugin.borrow_mut().mappers.clear();
        r.side.tick(r.t0, 1000, 128);
        r.plugin.borrow_mut().status = Some(applied(1, 1, 2));
        r.plugin.borrow_mut().queued = vec![sample(1, 1), sample(1, 2)];
        let t = r.side.tick(r.t0 + crate::worker::TICK, 1000, 128);
        assert_eq!(t.unmapped, 2);
        assert_eq!(r.side.health().coverage, Coverage::Degraded);
        assert!(r.side.health().why.contains("2 samples could not be read"));
        r.side.end_window();
        r.side.tick(r.t0 + 2 * crate::worker::TICK, 1000, 128);
        assert!(r.side.health().coverage.is_healthy(), "none in this window");
    }

    #[test]
    fn a_generation_with_none_after_it_is_reported_not_wrapped() {
        let mut r = rig();
        r.plugin.borrow_mut().status = Some(applied(u64::MAX, 1, 2));
        r.side.tick(r.t0, 1000, 128);
        assert!(r.plugin.borrow().desired.is_none());
        assert_eq!(r.side.health().coverage, Coverage::Unavailable);
        assert!(
            r.side.health().why.contains("none can follow it"),
            "{}",
            r.side.health().why
        );
    }

    #[test]
    fn a_write_that_fails_is_reported_and_retried() {
        let mut r = rig();
        r.plugin.borrow_mut().write_error = Some("ENOSPC".into());
        r.side.tick(r.t0, 1000, 128);
        assert_eq!(r.side.health().coverage, Coverage::Unavailable);
        assert!(r.side.health().why.contains("ENOSPC"));
        r.side.tick(r.t0 + crate::worker::TICK, 1000, 128);
        r.plugin.borrow_mut().write_error = None;
        r.side.tick(r.t0 + RETRY, 1000, 128);
        assert_eq!(r.plugin.borrow().desired.as_ref().unwrap().generation, 1);
    }

    #[test]
    fn stopping_removes_what_was_written_and_only_that() {
        let mut r = rig();
        r.plugin.borrow_mut().claim_error = Some("held".into());
        r.side.tick(r.t0, 1000, 128);
        r.side.stop().unwrap();
        assert!(!r.plugin.borrow().removed, "never claimed: not ours");
        r.plugin.borrow_mut().claim_error = None;
        r.side.tick(r.t0 + RETRY, 1000, 128);
        r.side.stop().unwrap();
        assert!(r.plugin.borrow().removed);
        assert!(r.plugin.borrow().desired.is_none());
    }
}
