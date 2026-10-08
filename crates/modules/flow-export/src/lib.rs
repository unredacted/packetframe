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
//! Telemetry never affects forwarding: a failure to start degrades this
//! module and leaves the rest running (the loader's policy), and every
//! failure after that is a status row, not an error the dataplane sees.

pub mod cfg;
pub mod collector;
pub mod coverage;
pub mod pool;
pub mod report;
pub mod sflow_out;
pub mod worker;

#[cfg(target_os = "linux")]
mod linux;

use std::path::{Path, PathBuf};

use packetframe_common::module::{
    Attachment, HealthCtx, HealthReport, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
    ModuleError, ModuleResult,
};

use crate::cfg::FlowExportConfig;

pub const MODULE_NAME: &str = "flow-export";

/// The worker thread's name, as `placement::CONTROL_PLANE_THREADS` lists
/// it.
pub const THREAD_NAME: &str = "pf-flow-export";

#[derive(Default)]
pub struct FlowExportModule {
    cfg: Option<FlowExportConfig>,
    bpffs_root: PathBuf,
    state_dir: PathBuf,
    #[cfg(target_os = "linux")]
    running: Option<linux::Running>,
}

impl FlowExportModule {
    pub fn new() -> Self {
        Self::default()
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
        let running = linux::Running::start(c, &self.bpffs_root, &self.state_dir)
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
            report::metrics(&r.shared.snapshot(), out.out);
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
            ));
        }
        Ok(HealthReport::healthy())
    }
}

/// Stop fast-path's sampler through its pinned configuration map (rate
/// 0), if fast-path's maps are pinned at all: what `detach --all` and the
/// loader's release after a failed start run, with no module running.
#[cfg(target_os = "linux")]
pub fn release_sampler(bpffs_root: &Path) -> Result<(), String> {
    linux::release_sampler(bpffs_root)
}

#[cfg(not(target_os = "linux"))]
pub fn release_sampler(_bpffs_root: &Path) -> Result<(), String> {
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
}
