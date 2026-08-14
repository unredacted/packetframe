//! PacketFrame fast-path module.
//!
//! Embeds the BPF ELF produced by `bpf/` via [`build.rs`](../build.rs)
//! (SPEC.md §3.6) and exposes it as a [`Module`] whose lifecycle methods
//! drive aya's loader: `load` opens the ELF and populates the cfg /
//! allowlist maps, `attach` XDP-attaches to every configured interface
//! with the trial-attach fallback behavior from SPEC.md §2.3, `detach`
//! tears everything down. The real logic lives in [`linux_impl`] and
//! is cfg-gated to `target_os = "linux"` so macOS dev loops still
//! compile, non-Linux builds return [`ModuleError::NotImplemented`]
//! from every lifecycle method.

use packetframe_common::module::{
    Attachment, HealthCtx, HealthReport, HookType, HookUse, LoaderCtx, MetricsWriter, Module,
    ModuleConfig, ModuleError, ModuleResult,
};

pub mod breaker;
pub mod fib;
pub mod metrics;
pub mod pin;
pub mod registry;
pub mod softnet;
pub mod tc_links;

#[cfg(target_os = "linux")]
pub mod linux_impl;

#[cfg(target_os = "linux")]
pub mod reconcile;

#[cfg(target_os = "linux")]
pub use linux_impl::{
    fib_status_from_pin, stats_from_pin, tail_call_chain_from_pin, tc_attach_iface,
    tc_detach_from_state_dir, trial_attach_native, FibStatusSnapshot, TrialResult,
};

pub const MODULE_NAME: &str = "fast-path";

/// Priority the fast-path module claims in the 1000-1999 forwarding range
/// per SPEC.md §3.2. Not consulted in v0.0.1 (single-module MVP, see §3.4).
pub const FAST_PATH_PRIORITY: u16 = 1000;

/// The compiled fast-path BPF ELF, staged by `build.rs` and embedded at
/// crate-compile time. Empty (zero bytes) when the BPF toolchain isn't
/// available, see [`FAST_PATH_BPF_AVAILABLE`].
///
/// Note: `include_bytes!` returns a 1-byte-aligned slice. Passing it
/// directly to `aya::Ebpf::load` fails with "Invalid ELF header size
/// or alignment" because the `object` crate's ELF parser does
/// unaligned u32/u64 reads into the header. Callers must copy to an
/// aligned buffer, use [`FastPathModule::new`] + `Module::load`,
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
/// fell back to an empty stub (build.rs uses a stub when bpf-linker / the
/// nightly toolchain isn't available, so macOS dev loops still compile).
/// Const-evaluable so tests can early-return or be `cfg`-gated on it.
pub const FAST_PATH_BPF_AVAILABLE: bool = !FAST_PATH_BPF.is_empty();

/// Fast-path module handle. `Default` and `new` produce an unloaded
/// instance; call [`Module::load`] to bring it online.
#[derive(Default)]
pub struct FastPathModule {
    #[cfg(target_os = "linux")]
    state: Option<linux_impl::ActiveState>,
    /// A second forwarding tier's sink, if one is configured.
    ///
    /// Set before `attach` and consumed there: the programmer can only
    /// accept a sink before it starts, because one registered later would
    /// have missed every route resolved in the meantime.
    #[cfg(target_os = "linux")]
    route_sink: Option<std::sync::Arc<dyn packetframe_common::fib::ResolvedRouteSink>>,
    #[cfg(target_os = "linux")]
    completeness: Option<std::sync::Arc<packetframe_common::fib::TableCompleteness>>,
    #[cfg(target_os = "linux")]
    feed_session: Option<std::sync::Arc<packetframe_common::fib::FeedSession>>,
}

impl FastPathModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Announce the resolved FIB to a second tier.
    ///
    /// Must be called before [`Module::attach`]; after that the
    /// programmer is running and cannot take one. The loader is the only
    /// caller, because it is the only place that knows both tiers exist.
    #[cfg(target_os = "linux")]
    pub fn set_route_sink(
        &mut self,
        sink: std::sync::Arc<dyn packetframe_common::fib::ResolvedRouteSink>,
    ) {
        self.route_sink = Some(sink);
    }

    /// Publish how complete the route mirror is, for a second tier to
    /// consult before it diverts traffic.
    ///
    /// Same constraint and same reason as [`Self::set_route_sink`]: the
    /// loader is the only caller, and it must land before
    /// [`Module::attach`] spawns the integrity checker.
    #[cfg(target_os = "linux")]
    pub fn set_completeness(
        &mut self,
        handle: std::sync::Arc<packetframe_common::fib::TableCompleteness>,
    ) {
        self.completeness = Some(handle);
    }

    /// Report the route feed's session liveness through `handle`, for
    /// the second tier's release gating. Same constraint and caller as
    /// [`Self::set_completeness`].
    #[cfg(target_os = "linux")]
    pub fn set_feed_session(
        &mut self,
        handle: std::sync::Arc<packetframe_common::fib::FeedSession>,
    ) {
        self.feed_session = Some(handle);
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
            // Sized from COUNTER_NAMES like every other stats surface;
            // a hardcoded length here previously drifted (32 < 38).
            None => Ok(vec![0u64; metrics::COUNTER_COUNT]),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn stats(&self) -> ModuleResult<Vec<u64>> {
        Ok(vec![0u64; metrics::COUNTER_COUNT])
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
        linux_impl::attach(
            state,
            cfg,
            self.route_sink.clone(),
            self.completeness.clone(),
            self.feed_session.clone(),
        )
    }

    #[cfg(not(target_os = "linux"))]
    fn attach(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    #[cfg(target_os = "linux")]
    fn reconfigure(&mut self, cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "reconfigure called before load"))?;
        reconcile::reconcile(state, cfg)
    }

    #[cfg(not(target_os = "linux"))]
    fn reconfigure(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
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
        // Module-side hook is a no-op; the cli's MetricsExporter
        // (`crates/cli/src/metrics.rs`) reads STATS + the FIB
        // snapshot from pinned maps directly on its 15 s cadence.
        Ok(())
    }

    /// Subsystem health for the custom-FIB control plane.
    ///
    /// One row so far: the integrity check's verdict, which was
    /// computed every 300 s and discarded — `packetframe status` had
    /// nothing to say about whether the mirror matches bird, and the
    /// second tier's steering gate acts on exactly that comparison.
    /// BmpStation and NeighborResolver freshness are the obvious next
    /// rows; neither publishes anything readable yet, and a row that
    /// reported "fine" from an unread source would be worse than none.
    ///
    /// The row is absent only when nothing is checking (kernel-fib
    /// mode, or a control plane with no route source). Whenever a
    /// checker exists the row appears, including before its first
    /// check completes — the whole point being that silence must not
    /// be readable as agreement.
    #[cfg(target_os = "linux")]
    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<HealthReport> {
        let subsystems: Vec<_> = self
            .state
            .as_ref()
            .and_then(linux_impl::integrity_posture)
            .map(|p| p.subsystem_health())
            .into_iter()
            .collect();
        // `worse_of` rather than a hand-rolled escalation: a module that
        // reports Healthy over a Degraded subsystem disagrees with its
        // own report, which is the defect vpp-offload's `nominal()`
        // documents at length.
        let overall = subsystems.iter().fold(
            packetframe_common::module::HealthState::Healthy,
            |acc, s| acc.worse_of(s.state),
        );
        Ok(HealthReport {
            overall,
            subsystems,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<HealthReport> {
        // Nothing runs here to report on: the control plane is
        // Linux-only, so there is no check whose silence could mislead.
        Ok(HealthReport::healthy())
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
        // detach on an unloaded module must succeed, teardown paths
        // call it unconditionally.
        assert!(m.detach().is_ok());
        let mut buf = String::new();
        let mut w = MetricsWriter::new(&mut buf, "fast-path");
        assert!(m.sample_metrics(&mut w).is_ok());
        assert!(m.health_check(&HealthCtx::new()).is_ok());
    }

    /// With nothing loaded there is no control plane, so there is no
    /// integrity row — and its absence is deliberate rather than the
    /// old unconditional `healthy()`. Whenever a checker DOES exist the
    /// row is present even before its first comparison; that
    /// distinction is covered in `fib::integrity_status`.
    #[test]
    fn unloaded_module_reports_no_integrity_row() {
        let m = FastPathModule::new();
        let r = m.health_check(&HealthCtx::new()).unwrap();
        assert!(r.subsystems.is_empty());
        assert_eq!(
            r.overall,
            packetframe_common::module::HealthState::Healthy,
            "nothing is running, so nothing is impaired"
        );
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
