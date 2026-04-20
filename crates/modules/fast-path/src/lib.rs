//! PacketFrame fast-path module.
//!
//! v0.0.1 ships a stub that implements [`Module`] with
//! [`ModuleError::NotImplemented`] returns on every lifecycle method. This
//! exercises the crate graph and feature flag wiring so v0.1 can land the
//! real BPF program, aya loader glue, VLAN choreography, and metrics without
//! shape churn. See SPEC.md §4 for the full module contract and the v0.1
//! forward view in the approved plan.

use packetframe_common::module::{
    Attachment, HealthCtx, HookType, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
    ModuleError, ModuleResult,
};

pub const MODULE_NAME: &str = "fast-path";

/// Priority the fast-path module claims in the 1000-1999 forwarding range
/// per SPEC.md §3.2. Not consulted in v0.0.1 (single-module MVP, see §3.4).
pub const FAST_PATH_PRIORITY: u16 = 1000;

#[derive(Default)]
pub struct FastPathModule {
    // Populated in v0.1 when `load` starts placing BPF objects and
    // attachments in here.
}

impl FastPathModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Module for FastPathModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn hook_spec(&self) -> Vec<HookUse> {
        vec![HookUse {
            hook: HookType::NativeXdp,
            priority: FAST_PATH_PRIORITY,
        }]
    }

    fn load(&mut self, _cfg: &ModuleConfig<'_>, _ctx: &LoaderCtx<'_>) -> ModuleResult<()> {
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    fn attach(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    fn reconfigure(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    fn detach(&mut self) -> ModuleResult<()> {
        Ok(())
    }

    fn sample_metrics(&self, _out: &mut MetricsWriter<'_>) -> ModuleResult<()> {
        Ok(())
    }

    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_name_matches_spec() {
        let m = FastPathModule::new();
        assert_eq!(m.name(), "fast-path");
    }

    #[test]
    fn module_claims_native_xdp_hook() {
        let m = FastPathModule::new();
        let hooks = m.hook_spec();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0].hook, HookType::NativeXdp);
        assert_eq!(hooks[0].priority, FAST_PATH_PRIORITY);
    }

    #[test]
    fn lifecycle_methods_are_not_implemented_stubs() {
        let mut m = FastPathModule::new();
        // detach/sample_metrics/health_check must succeed even on a
        // not-loaded module — they're called during teardown paths.
        assert!(m.detach().is_ok());
        let mut buf = String::new();
        let mut w = MetricsWriter::new(&mut buf, "fast-path");
        assert!(m.sample_metrics(&mut w).is_ok());
        assert!(m.health_check(&HealthCtx::new()).is_ok());
    }
}
