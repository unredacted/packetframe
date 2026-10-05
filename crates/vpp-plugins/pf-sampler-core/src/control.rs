//! What the plugin should be doing, from `desired.conf` and VPP's
//! interfaces: the configuration the workers sample with, the interfaces
//! the sampling feature is enabled on, and the status it reports.
//!
//! - **Validity is separate from resolution.** An invalid `desired.conf` is
//!   reported and the last valid one stays in force; a valid one naming
//!   interfaces VPP does not have yet is applied, and each name is resolved
//!   again on every reconcile (PacketFrame creates interfaces after VPP
//!   starts, and may recreate them).
//! - **VPP's own feature state is the truth.** A deleted interface loses
//!   its features inside VPP; a reconcile asks VPP whether sampling is
//!   enabled on each resolved interface and re-enables it where VPP
//!   cleared it, so a delete-and-recreate under the same index and name is
//!   not missed, and an enable is never applied twice.
//! - **The applied generation is what the workers were given**, published
//!   under VPP's barrier: every worker uses it from its next frame, so a
//!   worker that has seen no frame since is idle, not behind.

use packetframe_sampler_shm::desired::{Desired, Error as DesiredError};
use packetframe_sampler_shm::status::{reason, Interface, State, Status};
use packetframe_sampler_shm::Classes;

use crate::pools::PoolIndexes;

/// A `sw_if_index` sampled under no pool index.
pub const NOT_SAMPLED: u8 = u8::MAX;

/// What every worker samples with.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkerConfig {
    pub generation: u64,
    /// 1-in-N; 0 selects nothing.
    pub rate: u32,
    pub header_bytes: u32,
    /// Pool index by `sw_if_index`; [`NOT_SAMPLED`] where nothing is
    /// sampled, and beyond the end.
    pub pools: Vec<u8>,
}

impl WorkerConfig {
    pub fn pool_of(&self, sw_if_index: u32) -> u8 {
        self.pools
            .get(sw_if_index as usize)
            .copied()
            .unwrap_or(NOT_SAMPLED)
    }
}

/// VPP, as the controller needs it. Called on VPP's main thread.
pub trait Vpp {
    /// The `sw_if_index` of the interface named exactly `name`.
    fn resolve(&mut self, name: &str) -> Option<u32>;
    /// Whether the sampling feature is enabled on `sw_if_index` now.
    fn sampling_enabled(&mut self, sw_if_index: u32) -> bool;
    /// Under VPP's barrier: give the workers `cfg`, enable sampling on each
    /// of `enable` where it is not enabled, and disable it on each of
    /// `disable` where it is.
    fn apply(&mut self, cfg: &WorkerConfig, enable: &[u32], disable: &[u32]);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// Not looked at yet.
    Unchecked,
    Missing,
    Present,
}

pub struct Controller {
    header_capacity: usize,
    implemented: Classes,
    source: Source,
    /// The last valid configuration.
    valid: Option<Desired>,
    /// The current file, when it is invalid: its stated generation (0 if
    /// none could be read) and why.
    rejection: Option<(u64, DesiredError)>,
    pools: PoolIndexes,
    interfaces: Vec<Interface>,
    /// Interfaces sampling was last enabled on, and the configuration the
    /// workers were last given.
    enabled: Vec<u32>,
    worker: WorkerConfig,
    changed_ns: u64,
    changed: bool,
}

impl Controller {
    /// For a plugin whose epoch holds `header_capacity` bytes per sample
    /// and which samples the `implemented` classes.
    pub fn new(header_capacity: usize, implemented: Classes) -> Self {
        Self {
            header_capacity,
            implemented,
            source: Source::Unchecked,
            valid: None,
            rejection: None,
            pools: PoolIndexes::new(),
            interfaces: Vec::new(),
            enabled: Vec::new(),
            worker: WorkerConfig::default(),
            changed_ns: 0,
            changed: true,
        }
    }

    fn touch(&mut self, now_ns: u64) {
        self.changed_ns = now_ns;
        self.changed = true;
    }

    /// `desired.conf` as just read, `None` when there is none. Removing the
    /// file stops sampling; an invalid file leaves the last valid one in
    /// force.
    pub fn desired(&mut self, text: Option<&str>, now_ns: u64) {
        let Some(text) = text else {
            if self.source != Source::Missing || self.valid.is_some() || self.rejection.is_some() {
                self.source = Source::Missing;
                self.valid = None;
                self.rejection = None;
                self.touch(now_ns);
            }
            return;
        };
        let was = self.source;
        self.source = Source::Present;
        let parsed = Desired::parse(text).and_then(|d| {
            d.check_supported(self.header_capacity, self.implemented)
                .map(|()| d)
        });
        match parsed {
            Ok(d) => {
                if self.valid.as_ref() != Some(&d)
                    || self.rejection.is_some()
                    || was != Source::Present
                {
                    self.valid = Some(d);
                    self.rejection = None;
                    self.touch(now_ns);
                }
            }
            Err(e) => {
                let r = (stated_generation(text).unwrap_or(0), e);
                if self.rejection.as_ref() != Some(&r) || was != Source::Present {
                    self.rejection = Some(r);
                    self.touch(now_ns);
                }
            }
        }
    }

    /// Resolves every configured interface and brings VPP in line: the
    /// workers' configuration, and sampling enabled on exactly the resolved
    /// interfaces. Calls [`Vpp::apply`] only when something differs.
    pub fn reconcile(&mut self, vpp: &mut impl Vpp, now_ns: u64) {
        let names: Vec<String> = self
            .valid
            .as_ref()
            .map(|d| d.interfaces.clone())
            .unwrap_or_default();
        let pool_indexes = self.pools.assign(&names);
        let interfaces: Vec<Interface> = names
            .into_iter()
            .zip(pool_indexes)
            .map(|(name, pool_index)| {
                let sw_if_index = vpp.resolve(&name);
                let unresolved_since_ns = match sw_if_index {
                    Some(_) => 0,
                    None => self
                        .interfaces
                        .iter()
                        .find(|i| i.name == name && i.sw_if_index.is_none())
                        .map_or(now_ns, |i| i.unresolved_since_ns),
                };
                Interface {
                    name,
                    sw_if_index,
                    pool_index,
                    unresolved_since_ns,
                }
            })
            .collect();

        let mut want: Vec<u32> = interfaces.iter().filter_map(|i| i.sw_if_index).collect();
        want.sort_unstable();
        want.dedup();
        let mut pools = vec![NOT_SAMPLED; want.last().map_or(0, |&m| m as usize + 1)];
        for i in &interfaces {
            if let Some(sw) = i.sw_if_index {
                pools[sw as usize] = i.pool_index;
            }
        }
        let worker = match &self.valid {
            Some(d) => WorkerConfig {
                generation: d.generation,
                rate: d.rate,
                header_bytes: d.header_bytes,
                pools,
            },
            None => WorkerConfig::default(),
        };
        let disable: Vec<u32> = self
            .enabled
            .iter()
            .copied()
            .filter(|i| want.binary_search(i).is_err())
            .collect();
        let cleared = want.iter().any(|&i| !vpp.sampling_enabled(i));
        if worker != self.worker || want != self.enabled || !disable.is_empty() || cleared {
            vpp.apply(&worker, &want, &disable);
            if worker.generation != self.worker.generation
                || worker.rate != self.worker.rate
                || worker.header_bytes != self.worker.header_bytes
            {
                self.touch(now_ns);
            }
            self.worker = worker;
            self.enabled = want;
        }
        if interfaces != self.interfaces {
            self.interfaces = interfaces;
            self.touch(now_ns);
        }
    }

    pub fn status(&self) -> Status {
        let (state, why) = match (self.source, &self.valid) {
            (Source::Unchecked, _) => (State::Initializing, reason::NONE),
            (_, Some(d)) if !d.interfaces.is_empty() => (State::Enabled, reason::NONE),
            (_, Some(_)) => (State::Disabled, reason::NO_INTERFACES),
            (Source::Missing, None) => (State::Disabled, reason::NO_CONFIG),
            (Source::Present, None) => (State::Disabled, reason::NO_VALID_CONFIG),
        };
        let (rejected_generation, rejected_reason, rejected_line) = match &self.rejection {
            Some((g, e)) => (*g, e.kind.code(), e.line),
            None => (0, 0, 0),
        };
        Status {
            state,
            reason: why,
            applied_generation: self.worker.generation,
            rejected_generation,
            rejected_reason,
            rejected_line,
            rate: self.worker.rate,
            header_bytes: self.worker.header_bytes,
            classes: self.valid.as_ref().map_or(0, |d| d.classes),
            changed_ns: self.changed_ns,
            interfaces: self.interfaces.clone(),
        }
    }

    /// Whether the status changed since the last call.
    pub fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    pub fn worker(&self) -> &WorkerConfig {
        &self.worker
    }

    /// Why the current file was refused, if it was.
    pub fn rejection(&self) -> Option<&DesiredError> {
        self.rejection.as_ref().map(|(_, e)| e)
    }
}

/// The generation a file states, read leniently so a refused file's
/// generation can still be reported.
fn stated_generation(text: &str) -> Option<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix("generation "))
        .and_then(|g| g.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_sampler_shm::desired::ErrorKind;
    use packetframe_sampler_shm::Class;
    use std::collections::{BTreeSet, HashMap};

    #[derive(Default)]
    struct FakeVpp {
        names: HashMap<String, u32>,
        enabled: BTreeSet<u32>,
        applied: Vec<(WorkerConfig, Vec<u32>, Vec<u32>)>,
    }

    impl Vpp for FakeVpp {
        fn resolve(&mut self, name: &str) -> Option<u32> {
            self.names.get(name).copied()
        }
        fn sampling_enabled(&mut self, i: u32) -> bool {
            self.enabled.contains(&i)
        }
        fn apply(&mut self, cfg: &WorkerConfig, enable: &[u32], disable: &[u32]) {
            for i in disable {
                self.enabled.remove(i);
            }
            self.enabled.extend(enable);
            self.applied
                .push((cfg.clone(), enable.to_vec(), disable.to_vec()));
        }
    }

    impl FakeVpp {
        /// An interface deleted inside VPP: gone, and its features with it.
        fn delete(&mut self, name: &str) {
            if let Some(i) = self.names.remove(name) {
                self.enabled.remove(&i);
            }
        }
    }

    fn desired(generation: u64, ifaces: &[&str]) -> String {
        Desired {
            generation,
            rate: 100,
            header_bytes: 128,
            classes: Class::Ingress.bit(),
            interfaces: ifaces.iter().map(|s| s.to_string()).collect(),
        }
        .render()
    }

    fn ctl() -> Controller {
        Controller::new(256, Class::Ingress.bit())
    }

    #[test]
    fn states_follow_the_file() {
        let mut c = ctl();
        let mut v = FakeVpp::default();
        assert_eq!(c.status().state, State::Initializing);
        c.desired(None, 1);
        c.reconcile(&mut v, 1);
        assert_eq!(
            (c.status().state, c.status().reason),
            (State::Disabled, reason::NO_CONFIG)
        );
        assert!(v.applied.is_empty(), "nothing to change");

        c.desired(Some("garbage"), 2);
        assert_eq!(
            (c.status().state, c.status().reason),
            (State::Disabled, reason::NO_VALID_CONFIG)
        );
        assert_eq!(c.status().rejected_reason, ErrorKind::Missing.code());

        c.desired(Some(&desired(5, &[])), 3);
        assert_eq!(
            (c.status().state, c.status().reason),
            (State::Disabled, reason::NO_INTERFACES)
        );
        c.desired(Some(&desired(6, &["pg0"])), 4);
        assert_eq!(c.status().state, State::Enabled);
    }

    #[test]
    fn interfaces_are_resolved_when_they_appear_and_followed_when_recreated() {
        let mut c = ctl();
        let mut v = FakeVpp::default();
        v.names.insert("a".into(), 3);
        c.desired(Some(&desired(1, &["a", "b"])), 10);
        c.reconcile(&mut v, 10);
        let s = c.status();
        assert_eq!(s.applied_generation, 1);
        assert_eq!(s.interfaces[0].sw_if_index, Some(3));
        assert_eq!(
            (
                s.interfaces[1].sw_if_index,
                s.interfaces[1].unresolved_since_ns
            ),
            (None, 10)
        );
        assert_eq!(v.enabled, BTreeSet::from([3]));
        assert_eq!(c.worker().pool_of(3), 0);
        assert_eq!(c.worker().pool_of(5), NOT_SAMPLED);

        c.reconcile(&mut v, 11);
        assert_eq!(v.applied.len(), 1, "no change, no barrier");
        assert_eq!(
            c.status().interfaces[1].unresolved_since_ns,
            10,
            "since is kept"
        );

        v.names.insert("b".into(), 5);
        c.reconcile(&mut v, 12);
        assert_eq!(v.enabled, BTreeSet::from([3, 5]));
        assert_eq!(c.worker().pool_of(5), 1);

        // a recreated elsewhere: off the old index, on the new.
        v.delete("a");
        v.names.insert("a".into(), 7);
        c.reconcile(&mut v, 13);
        assert_eq!(v.enabled, BTreeSet::from([5, 7]));
        assert_eq!(v.applied.last().unwrap().2, [3]);
        assert_eq!(c.worker().pool_of(7), 0, "same pool index after the move");

        // b recreated under the same index: VPP dropped the feature, the
        // reconcile puts it back.
        v.delete("b");
        v.names.insert("b".into(), 5);
        c.reconcile(&mut v, 14);
        assert!(v.enabled.contains(&5));
        assert_eq!(v.applied.len(), 4);
    }

    #[test]
    fn an_invalid_file_keeps_the_last_valid_one() {
        let mut c = ctl();
        let mut v = FakeVpp::default();
        v.names.insert("pg0".into(), 1);
        c.desired(Some(&desired(4, &["pg0"])), 1);
        c.reconcile(&mut v, 1);
        let bad = desired(5, &["pg0"]).replace("rate 100", "rate 101");
        c.desired(Some(&bad), 2);
        c.reconcile(&mut v, 2);
        let s = c.status();
        assert_eq!(s.state, State::Enabled);
        assert_eq!((s.applied_generation, s.rejected_generation), (4, 5));
        assert_eq!(s.rejected_reason, ErrorKind::Checksum.code());
        assert_eq!(v.applied.len(), 1, "workers untouched");

        // Valid, but beyond what this plugin's epoch holds: unsupported.
        let big = Desired {
            header_bytes: 512,
            ..Desired::parse(&desired(6, &["pg0"])).unwrap()
        }
        .render();
        c.desired(Some(&big), 3);
        assert_eq!(c.status().rejected_reason, ErrorKind::Unsupported.code());
        assert_eq!(c.status().applied_generation, 4);

        c.desired(Some(&desired(7, &["pg0"])), 4);
        c.reconcile(&mut v, 4);
        assert_eq!(
            (c.status().applied_generation, c.status().rejected_reason),
            (7, 0)
        );
    }

    #[test]
    fn removing_the_file_stops_sampling_everywhere() {
        let mut c = ctl();
        let mut v = FakeVpp::default();
        v.names.insert("pg0".into(), 1);
        v.names.insert("pg1".into(), 2);
        c.desired(Some(&desired(1, &["pg0", "pg1"])), 1);
        c.reconcile(&mut v, 1);
        c.desired(None, 2);
        c.reconcile(&mut v, 2);
        assert!(v.enabled.is_empty());
        assert_eq!(v.applied.last().unwrap().0, WorkerConfig::default());
        assert_eq!(c.status().reason, reason::NO_CONFIG);
    }

    #[test]
    fn status_changes_are_reported_once() {
        let mut c = ctl();
        let mut v = FakeVpp::default();
        assert!(c.take_changed(), "initial status");
        c.desired(Some(&desired(1, &["x"])), 1);
        c.reconcile(&mut v, 1);
        assert!(c.take_changed());
        c.desired(Some(&desired(1, &["x"])), 2);
        c.reconcile(&mut v, 2);
        assert!(!c.take_changed(), "same file, same resolution");
    }
}
