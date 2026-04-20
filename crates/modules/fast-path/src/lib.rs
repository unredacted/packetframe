//! PacketFrame fast-path module.
//!
//! v0.0.1 shipped a stub. This crate now embeds the BPF ELF produced by
//! `bpf/` via [`build.rs`](../build.rs) and `include_bytes!` (SPEC.md §3.6).
//! The userspace [`Module`] lifecycle (load/attach/detach via aya) lands in
//! PR #4 — this PR just adds the BPF program itself and the maps/counter
//! type definitions needed to test it.
//!
//! When the BPF toolchain (nightly + `bpf-linker` + `bpfel-unknown-none`)
//! is unavailable at build time (e.g. macOS dev laptops per the PR #3
//! plan), the build falls back to an empty ELF and
//! [`FAST_PATH_BPF_AVAILABLE`] is `false`; `cfg(packetframe_bpf_built)`
//! is unset so tests that need the real object can be `#[cfg_attr]`-ignored.

use packetframe_common::module::{
    Attachment, HealthCtx, HookType, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
    ModuleError, ModuleResult,
};

/// The compiled fast-path BPF ELF, staged by `build.rs` and embedded at
/// crate-compile time. Empty (zero bytes) when the BPF toolchain isn't
/// available — see [`FAST_PATH_BPF_AVAILABLE`].
pub const FAST_PATH_BPF: &[u8] = include_bytes!(env!("FAST_PATH_BPF_OBJ"));

/// `true` when `build.rs` produced a real BPF ELF; `false` when the build
/// fell back to an empty stub (CI-only BPF builds per the PR #3 plan).
/// Const-evaluable so tests can early-return or be `cfg`-gated on it.
pub const FAST_PATH_BPF_AVAILABLE: bool = !FAST_PATH_BPF.is_empty();

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

    #[test]
    fn bpf_elf_embedded_when_built() {
        // When the toolchain is available (CI), expect a non-empty ELF
        // starting with the 4-byte ELF magic. When not (local dev on
        // macOS without rustup), expect the empty stub.
        if FAST_PATH_BPF_AVAILABLE {
            assert!(FAST_PATH_BPF.len() >= 4, "BPF object suspiciously small");
            assert_eq!(
                &FAST_PATH_BPF[..4],
                &[0x7f, b'E', b'L', b'F'],
                "BPF object does not start with ELF magic"
            );
        } else {
            assert!(FAST_PATH_BPF.is_empty());
        }
    }
}
