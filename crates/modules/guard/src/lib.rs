//! PacketFrame guard module: a tc-**egress** frame policer.
//!
//! Polices locally-originated L2 frames the platform's firmware emits
//! uncontrollably (UniFi udapi-server ARP/NS storms, lldpd, the HA
//! standby's MAC leaking onto IX VLANs). Fixed frame classes, each
//! per-interface and monitor-or-enforce:
//!
//! 1. ARP requests + ICMPv6 Neighbor Solicitations — per-target-IP
//!    GCRA rate limit (legitimate kernel resolution passes; same-
//!    target storms clamp).
//! 2. LLDP (ethertype 0x88cc) — drop.
//! 3. Foreign source MAC (anything but the interface's own) — drop.
//! 4. Catch-all broadcast/multicast — coarse per-interface rate limit.
//!
//! tc egress is the only eBPF hook that observes this traffic class:
//! it is kernel egress (including AF_PACKET injections like arping's),
//! invisible to XDP (ingress-only), NIC ntuple/MCAM (RX-only), and the
//! vpp-offload dataplane (which never carries kernel-originated
//! frames). That remains true at every stage of the vpp-offload
//! roadmap, so this module is permanent architecture, not a stopgap.
//!
//! **Slice status:** config model, state-file, and pin-path layers are
//! in place; the BPF datapath and the Linux attach/detach lifecycle
//! land in the next slice, and the CLI does not construct this module
//! until the slice after that.

pub mod cfg;
pub mod pin;
pub mod tc_links;

use std::path::PathBuf;

use packetframe_common::module::{
    HealthCtx, HealthReport, HookType, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
    ModuleError, ModuleResult,
};

use crate::cfg::GuardConfig;

pub const MODULE_NAME: &str = "guard";

/// SPEC §3.2 hook priority. Guard is a policer, not a forwarder; it
/// sits outside the 1000–1999 forwarding range. Recorded, not yet
/// consulted (single-module-per-hook dispatch).
pub const GUARD_PRIORITY: u16 = 100;

#[derive(Default)]
pub struct GuardModule {
    /// Parsed section, set by `load`.
    config: Option<GuardConfig>,
    /// Captured at `load` (`attach` receives no ctx).
    bpffs_root: Option<PathBuf>,
    state_dir: Option<PathBuf>,
}

impl GuardModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Module for GuardModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn hook_spec(&self) -> Vec<HookUse> {
        vec![HookUse {
            hook: HookType::TcEgress,
            priority: GUARD_PRIORITY,
        }]
    }

    fn load(&mut self, cfg: &ModuleConfig<'_>, ctx: &LoaderCtx<'_>) -> ModuleResult<()> {
        let parsed = GuardConfig::from_directives(&cfg.section.directives)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("module guard: {e}")))?;
        self.config = Some(parsed);
        self.bpffs_root = Some(ctx.bpffs_root.to_path_buf());
        self.state_dir = Some(ctx.state_dir.to_path_buf());
        Ok(())
    }

    fn attach(
        &mut self,
        _cfg: &ModuleConfig<'_>,
    ) -> ModuleResult<Vec<packetframe_common::module::Attachment>> {
        // Next slice: per-interface clsact + netlink cls_bpf egress
        // attach, GUARD_CFG population, guard-tc-links.json persistence,
        // pinning. Returns no `Attachment`s even then (the shared
        // attachments.json registry is single-module; guard's teardown
        // truth is its own state file, the vpp-offload precedent).
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    fn reconfigure(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    fn detach(&mut self) -> ModuleResult<()> {
        // Nothing can be attached while `attach` is unimplemented;
        // no-op is the honest answer for this slice.
        Ok(())
    }

    fn sample_metrics(&self, _out: &mut MetricsWriter<'_>) -> ModuleResult<()> {
        Ok(())
    }

    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<HealthReport> {
        Ok(HealthReport::healthy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::config::Config;

    /// `load` accepts a valid section and refuses an invalid one with
    /// the module name in the message — the same verdict the config
    /// validator gives, per the "one verdict at the earliest point"
    /// rule.
    #[test]
    fn load_parses_and_refuses() {
        let good = Config::parse("module guard\n  interface br0\n  lldp br0 drop\n").unwrap();
        let bad = Config::parse("module guard\n  lldp br0 drop\n").unwrap();
        let global = packetframe_common::config::GlobalConfig::default();
        let ctx = LoaderCtx {
            bpffs_root: std::path::Path::new("/sys/fs/bpf/packetframe"),
            state_dir: std::path::Path::new("/var/lib/packetframe/state"),
        };

        let mut m = GuardModule::new();
        m.load(
            &ModuleConfig {
                section: &good.modules[0],
                global: &global,
            },
            &ctx,
        )
        .expect("valid section loads");
        assert!(m.config.is_some());

        let mut m = GuardModule::new();
        let e = m
            .load(
                &ModuleConfig {
                    section: &bad.modules[0],
                    global: &global,
                },
                &ctx,
            )
            .expect_err("orphan rule refused");
        assert!(format!("{e}").contains("no `interface` line"), "{e}");
    }
}
