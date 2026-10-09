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
pub mod pool;
pub mod report;
pub mod sflow_out;
pub mod vpp;
pub mod worker;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod vpp_live;

use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    #[cfg(target_os = "linux")]
    running: Option<linux::Running>,
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
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "attach before load"))?;
        let running = linux::Running::start(
            c,
            &self.bpffs_root,
            &self.state_dir,
            self.vpp.clone(),
            self.coverage.clone(),
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
/// pinned configuration map (rate 0), if its maps are pinned at all, and
/// VPP's by removing `desired.conf` from `vpp_dir`, if that is a
/// directory the plugin could use.
#[cfg(target_os = "linux")]
pub fn release_sampler(bpffs_root: &Path, vpp_dir: Option<&Path>) -> Result<(), String> {
    linux::release_sampler(bpffs_root, vpp_dir)
}

#[cfg(not(target_os = "linux"))]
pub fn release_sampler(_bpffs_root: &Path, _vpp_dir: Option<&Path>) -> Result<(), String> {
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
