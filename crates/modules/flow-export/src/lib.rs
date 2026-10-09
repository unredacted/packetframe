//! flow-export: sampled packets from PacketFrame's forwarding paths to flow
//! collectors, as sFlow v5.
//!
//! The samplers live where the packets are: fast-path's XDP and tc
//! programs select packets (`bpf/src/sample.rs` there) and hand them over
//! through per-CPU perf rings. This module turns them into datagrams for
//! every configured collector, counts each port's pool from the kernel's
//! own packet counter, and judges per port whether the samples still
//! represent its traffic ([`coverage`]).
//!
//! VPP's sampler plugin does the same for the ports vpp-offload steers
//! into VPP ([`vpp`]): this module owns its `desired.conf`, and reads its
//! rings and per-interface counts through `packetframe_sampler_shm`.
//!
//! Telemetry never affects forwarding: a failure to start degrades this
//! module and leaves the rest running (the loader's policy), and every
//! failure after that is a status row, not an error the dataplane sees.

pub mod cfg;
pub mod collector;
pub mod coverage;
pub mod feasibility;
pub mod flows;
pub mod ipfix_out;
pub mod pool;
pub mod report;
pub mod sflow_out;
#[cfg(target_os = "linux")]
pub(crate) mod tc_links;
pub mod vpp;
pub mod worker;

#[cfg(target_os = "linux")]
mod kernel;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod vpp_live;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use packetframe_common::fib::asn::AsnTable;
use packetframe_common::fib::SharedPrefixes;
use packetframe_common::flow_coverage::FlowCoverage;
use packetframe_common::sampler_ports::VppSamplerPorts;

use packetframe_common::module::{
    Attachment, HealthCtx, HealthReport, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
    ModuleError, ModuleResult,
};

use crate::cfg::FlowExportConfig;

pub const MODULE_NAME: &str = "flow-export";

/// The worker thread's name, as `placement::CONTROL_PLANE_THREADS` lists
/// it.
pub const THREAD_NAME: &str = "pf-flow-export";

/// The kernel sampler's ELF (`bpf/`, `kernel_sample`), embedded at build
/// time; empty when the BPF toolchain was not available (macOS dev
/// loops), and then `kernel-sample` refuses to attach. Copy through
/// [`aligned_kernel_sample_copy`] before loading.
pub const KERNEL_SAMPLE_BPF: &[u8] = include_bytes!(env!("KERNEL_SAMPLE_BPF_OBJ"));

pub const KERNEL_SAMPLE_BPF_AVAILABLE: bool = !KERNEL_SAMPLE_BPF.is_empty();

/// A heap copy aligned for the ELF reader (`include_bytes!` is not).
pub fn aligned_kernel_sample_copy() -> Vec<u8> {
    KERNEL_SAMPLE_BPF.to_vec()
}

/// Every interface fast-path may redirect to, so every output ifindex a
/// sample can carry: `(name, ifindex)`.
#[cfg(target_os = "linux")]
pub use packetframe_fast_path::enumerate_redirect_targets as redirect_targets;

/// VPP's sampler directory, where vpp-offload prepares it
/// (`packetframe_sampler_shm::fs::DEFAULT_DIR`).
pub const VPP_SAMPLER_DIR: &str = "/run/packetframe/vpp/sampler";

#[derive(Default)]
pub struct FlowExportModule {
    cfg: Option<FlowExportConfig>,
    bpffs_root: PathBuf,
    state_dir: PathBuf,
    /// vpp-offload's ports and its sampler directory, when it is
    /// configured.
    vpp: Option<(Arc<VppSamplerPorts>, PathBuf)>,
    coverage: Arc<FlowCoverage>,
    asn: Option<Arc<AsnTable>>,
    local_default: Option<Arc<SharedPrefixes>>,
    #[cfg(target_os = "linux")]
    running: Option<linux::Running>,
}

/// What the module is handed from outside its section, for its worker.
#[cfg(target_os = "linux")]
pub(crate) struct Handles {
    pub vpp: Option<(Arc<VppSamplerPorts>, PathBuf)>,
    pub coverage: Arc<FlowCoverage>,
    pub asn: Option<Arc<AsnTable>>,
}

impl FlowExportModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sample VPP's ports too: vpp-offload's per-process port snapshots,
    /// and the directory it prepares for the sampler plugin. The loader
    /// is the only place that sees both modules.
    pub fn set_vpp(&mut self, ports: Arc<VppSamplerPorts>, dir: PathBuf) {
        self.vpp = Some((ports, dir));
    }

    /// Fill flow records' AS fields from the origins fast-path's
    /// programmer publishes. The loader builds the table when fast-path
    /// has a route source.
    pub fn set_asn_table(&mut self, table: Arc<AsnTable>) {
        self.asn = Some(table);
    }

    /// fast-path's allowlist, as the loader keeps it current: the local
    /// prefixes of the privacy profiles when the section names none.
    /// Taken at attach and at each reconfigure, which runs after
    /// fast-path's: a reload fast-path refused leaves it as it was.
    pub fn set_local_default(&mut self, prefixes: Arc<SharedPrefixes>) {
        self.local_default = Some(prefixes);
    }

    fn with_local_default(&self, mut c: FlowExportConfig) -> FlowExportConfig {
        c.local_default = self
            .local_default
            .as_ref()
            .map(|h| h.get())
            .unwrap_or_default();
        c
    }

    /// What this module vouches for, per port and path and per collector,
    /// for a consumer that acts on telemetry: fresh while the worker
    /// runs, nothing once it stops.
    pub fn coverage(&self) -> Arc<FlowCoverage> {
        self.coverage.clone()
    }
}

impl Module for FlowExportModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn hook_spec(&self) -> Vec<HookUse> {
        Vec::new()
    }

    fn load(&mut self, cfg: &ModuleConfig<'_>, ctx: &LoaderCtx<'_>) -> ModuleResult<()> {
        let c = FlowExportConfig::from_directives(&cfg.section.directives)
            .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        self.cfg = Some(c);
        self.bpffs_root = ctx.bpffs_root.to_owned();
        self.state_dir = ctx.state_dir.to_owned();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn attach(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
        let c = self
            .cfg
            .clone()
            .map(|c| self.with_local_default(c))
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "attach before load"))?;
        let running = linux::Running::start(
            c,
            &self.bpffs_root,
            &self.state_dir,
            Handles {
                vpp: self.vpp.clone(),
                coverage: self.coverage.clone(),
                asn: self.asn.clone(),
            },
        )
        .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        self.running = Some(running);
        // Nothing of fast-path's registry is ours: the programs are its.
        Ok(Vec::new())
    }

    #[cfg(not(target_os = "linux"))]
    fn attach(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    fn reconfigure(&mut self, cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
        let new = FlowExportConfig::from_directives(&cfg.section.directives)
            .map(|c| self.with_local_default(c))
            .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        if let Some(old) = &self.cfg {
            old.restart_only_delta(&new)
                .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        }
        // Applied by the worker and kept only once it says so: on a failure
        // nothing changed, and the loader reports the reload as failed.
        #[cfg(target_os = "linux")]
        if let Some(r) = &self.running {
            r.shared
                .request_reload(new.clone(), worker::RELOAD_WAIT)
                .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        }
        self.cfg = Some(new);
        Ok(())
    }

    fn detach(&mut self) -> ModuleResult<()> {
        #[cfg(target_os = "linux")]
        if let Some(r) = self.running.take() {
            r.stop().map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        }
        Ok(())
    }

    /// Sampling stops with the daemon, which is its only reader; the
    /// programs stay attached and forwarding.
    fn exit_preserving(&mut self) {
        if let Err(e) = self.detach() {
            tracing::warn!(error = %e, "flow-export: stopping the sampler at exit failed");
        }
    }

    fn sample_metrics(&self, out: &mut MetricsWriter<'_>) -> ModuleResult<()> {
        #[cfg(target_os = "linux")]
        if let Some(r) = &self.running {
            let age = r.shared.heartbeat_age(std::time::Instant::now());
            let up = report::worker_up(age, r.shared.panicked().as_deref());
            report::metrics(&r.shared.snapshot(), out.out, up);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = out;
        Ok(())
    }

    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<HealthReport> {
        #[cfg(target_os = "linux")]
        if let Some(r) = &self.running {
            let now = std::time::Instant::now();
            return Ok(report::health(
                &r.shared.snapshot(),
                r.shared.heartbeat_age(now),
                r.shared.panicked().as_deref(),
            ));
        }
        Ok(HealthReport::healthy())
    }
}

/// Stop the samplers with no module running, as `detach --all` and the
/// loader's release after a failed start do: fast-path's through its
/// pinned configuration map (rate 0), if its maps are pinned at all; the
/// kernel sampler by removing the filters `state_dir` records; and VPP's
/// by removing `desired.conf` from `vpp_dir`, if that is a directory the
/// plugin could use.
#[cfg(target_os = "linux")]
pub fn release_sampler(
    bpffs_root: &Path,
    state_dir: &Path,
    vpp_dir: Option<&Path>,
) -> Result<(), String> {
    linux::release_sampler(bpffs_root, state_dir, vpp_dir)
}

#[cfg(not(target_os = "linux"))]
pub fn release_sampler(
    _bpffs_root: &Path,
    _state_dir: &Path,
    _vpp_dir: Option<&Path>,
) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Placed with the control plane: listed under the name the kernel
    /// keeps (`comm` is 15 bytes).
    #[test]
    fn the_worker_thread_is_placed_with_the_control_plane() {
        assert!(THREAD_NAME.len() <= 15);
        assert!(packetframe_common::placement::CONTROL_PLANE_THREADS.contains(&THREAD_NAME));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_vpp_sampler_directory_is_the_plugins_default() {
        assert_eq!(VPP_SAMPLER_DIR, packetframe_sampler_shm::fs::DEFAULT_DIR);
    }
}
