//! PacketFrame fast-path module.
//!
//! Embeds the BPF ELF produced by `bpf/` via [`build.rs`](../build.rs)
//! (SPEC.md §3.6) and exposes it as a [`Module`] whose lifecycle methods
//! drive aya's loader: `load` opens the ELF and populates the cfg /
//! allowlist maps, `attach` XDP-attaches to every configured interface
//! with the trial-attach fallback behavior from SPEC.md §2.3, `detach`
//! tears everything down. The real logic lives in [`linux_impl`] and
//! is cfg-gated to `target_os = "linux"` so macOS dev loops still
//! compile — non-Linux builds return [`ModuleError::NotImplemented`]
//! from every lifecycle method.

use packetframe_common::module::{
    Attachment, HealthCtx, HookType, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
    ModuleError, ModuleResult,
};

pub mod metrics;
pub mod pin;
pub mod registry;

#[cfg(target_os = "linux")]
pub mod linux_impl;

#[cfg(target_os = "linux")]
pub use linux_impl::{stats_from_pin, trial_attach_native, TrialResult};

pub const MODULE_NAME: &str = "fast-path";

/// Priority the fast-path module claims in the 1000-1999 forwarding range
/// per SPEC.md §3.2. Not consulted in v0.0.1 (single-module MVP, see §3.4).
pub const FAST_PATH_PRIORITY: u16 = 1000;

/// The compiled fast-path BPF ELF, staged by `build.rs` and embedded at
/// crate-compile time. Empty (zero bytes) when the BPF toolchain isn't
/// available — see [`FAST_PATH_BPF_AVAILABLE`].
///
/// Note: `include_bytes!` returns a 1-byte-aligned slice. Passing it
/// directly to `aya::Ebpf::load` fails with "Invalid ELF header size
/// or alignment" because the `object` crate's ELF parser does
/// unaligned u32/u64 reads into the header. Callers must copy to an
/// aligned buffer — use [`FastPathModule::new`] + `Module::load`,
/// which handles this internally, or call [`aligned_bpf_copy`] to
/// get a heap-allocated 16-byte-aligned `Vec<u8>` suitable for
/// `aya::Ebpf::load`.
pub const FAST_PATH_BPF: &[u8] = include_bytes!(env!("FAST_PATH_BPF_OBJ"));

/// Allocate an aligned `Vec<u8>` containing a copy of [`FAST_PATH_BPF`].
/// The system allocator aligns to at least 16 bytes on 64-bit
/// platforms, which is enough for the `object` crate to parse the
/// ELF header without trapping on misaligned access.
pub fn aligned_bpf_copy() -> Vec<u8> {
    FAST_PATH_BPF.to_vec()
}

/// `true` when `build.rs` produced a real BPF ELF; `false` when the build
/// fell back to an empty stub (CI-only BPF builds per the PR #3 plan).
/// Const-evaluable so tests can early-return or be `cfg`-gated on it.
pub const FAST_PATH_BPF_AVAILABLE: bool = !FAST_PATH_BPF.is_empty();

/// Fast-path module handle. `Default` and `new` produce an unloaded
/// instance; call [`Module::load`] to bring it online.
#[derive(Default)]
pub struct FastPathModule {
    #[cfg(target_os = "linux")]
    state: Option<linux_impl::ActiveState>,
}

impl FastPathModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of the current attach set for status reporting.
    /// Non-Linux always returns an empty list (no attach occurred).
    #[cfg(target_os = "linux")]
    pub fn links(&self) -> Vec<(String, u32, packetframe_common::config::AttachMode)> {
        self.state
            .as_ref()
            .map(linux_impl::snapshot_links)
            .unwrap_or_default()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn links(&self) -> Vec<(String, u32, packetframe_common::config::AttachMode)> {
        Vec::new()
    }

    /// Per-CPU-aggregated stats snapshot, indexed by `StatIdx`
    /// discriminants (SPEC.md §4.6). Returns all-zeros when unloaded
    /// or on non-Linux.
    #[cfg(target_os = "linux")]
    pub fn stats(&self) -> ModuleResult<Vec<u64>> {
        match &self.state {
            Some(s) => linux_impl::snapshot_stats(s),
            None => Ok(vec![0u64; 19]),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn stats(&self) -> ModuleResult<Vec<u64>> {
        Ok(vec![0u64; 19])
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

    #[cfg(target_os = "linux")]
    fn load(&mut self, cfg: &ModuleConfig<'_>, ctx: &LoaderCtx<'_>) -> ModuleResult<()> {
        self.state = Some(linux_impl::load(cfg, ctx)?);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn load(&mut self, _cfg: &ModuleConfig<'_>, _ctx: &LoaderCtx<'_>) -> ModuleResult<()> {
        Err(ModuleError::other(
            MODULE_NAME,
            "fast-path loader is Linux-only; this build was cross-compiled for a non-Linux target",
        ))
    }

    #[cfg(target_os = "linux")]
    fn attach(&mut self, cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "attach called before load"))?;
        linux_impl::attach(state, cfg)
    }

    #[cfg(not(target_os = "linux"))]
    fn attach(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    fn reconfigure(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
        // SPEC.md §4.5 calls for delta-only reconfigure. Full
        // implementation (stale-entry purge, LPM delta vs. current)
        // lands in PR #6 with the SIGHUP reconcile flow.
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    #[cfg(target_os = "linux")]
    fn detach(&mut self) -> ModuleResult<()> {
        if let Some(mut state) = self.state.take() {
            linux_impl::detach(&mut state)?;
            // Dropping `state` drops the `Ebpf`, which unloads the
            // program and maps. PR #6 adds pin cleanup when pinning
            // exists.
            drop(state);
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn detach(&mut self) -> ModuleResult<()> {
        // Nothing to tear down; no-op is the honest answer on a stub.
        Ok(())
    }

    fn sample_metrics(&self, _out: &mut MetricsWriter<'_>) -> ModuleResult<()> {
        // Prometheus textfile emission lands in PR #6. No-op here.
        Ok(())
    }

    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<()> {
        // Circuit breaker evaluation lands in PR #6. No-op here.
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
    fn lifecycle_stubs_safe_to_call() {
        let mut m = FastPathModule::new();
        // detach on an unloaded module must succeed — teardown paths
        // call it unconditionally.
        assert!(m.detach().is_ok());
        let mut buf = String::new();
        let mut w = MetricsWriter::new(&mut buf, "fast-path");
        assert!(m.sample_metrics(&mut w).is_ok());
        assert!(m.health_check(&HealthCtx::new()).is_ok());
    }

    #[test]
    fn bpf_elf_embedded_when_built() {
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
