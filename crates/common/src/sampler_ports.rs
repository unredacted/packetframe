//! Which kernel port each VPP interface stands for, per VPP process: what
//! flow export needs to read a sample from VPP's sampler plugin.
//!
//! A VPP sample names its interface by `sw_if_index`, and an index means
//! something only to the process that assigned it; a restarted VPP can
//! hand the same index to another port. vpp-offload publishes a snapshot
//! for each process once its ports are attached and withdraws it when the
//! process is gone, and flow export reads a sample only through the
//! snapshot of the process that wrote it. The sampler's epoch file is
//! mapped by exactly one VPP for its life, so `/proc/<pid>/maps` ties an
//! epoch to its process.

use std::sync::{Arc, RwLock};

/// One VPP process. The start time (clock ticks after boot, field 22 of
/// `/proc/<pid>/stat`) and the boot rule out a recycled pid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VppInstance {
    pub pid: i32,
    pub start_ticks: u64,
    pub boot_id: Option<String>,
}

/// A member port as VPP and the kernel each know it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampledPort {
    /// The kernel port (`port` in the config).
    pub port: String,
    /// Its kernel ifindex, the identity flow export reports; `None` when
    /// it could not be read.
    pub ifindex: Option<u32>,
    /// VPP's name for its interface, which `desired.conf` lists.
    pub vpp_name: String,
    pub sw_if_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VppPortsSnapshot {
    pub instance: VppInstance,
    pub ports: Vec<SampledPort>,
}

/// The current snapshot, `None` while no VPP has its ports attached.
#[derive(Debug, Default)]
pub struct VppSamplerPorts {
    current: RwLock<Option<Arc<VppPortsSnapshot>>>,
}

impl VppSamplerPorts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn publish(&self, snapshot: VppPortsSnapshot) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = Some(Arc::new(snapshot));
    }

    /// The process is gone: its indices mean nothing any more.
    pub fn withdraw(&self) {
        *self.current.write().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn current(&self) -> Option<Arc<VppPortsSnapshot>> {
        self.current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_lasts_until_its_process_is_withdrawn() {
        let h = VppSamplerPorts::new();
        assert!(h.current().is_none());
        let s = VppPortsSnapshot {
            instance: VppInstance {
                pid: 10,
                start_ticks: 20,
                boot_id: Some("b".into()),
            },
            ports: vec![SampledPort {
                port: "eth0".into(),
                ifindex: Some(2),
                vpp_name: "octeon0/0".into(),
                sw_if_index: 1,
            }],
        };
        h.publish(s.clone());
        assert_eq!(*h.current().unwrap(), s);
        h.withdraw();
        assert!(h.current().is_none());
    }
}
