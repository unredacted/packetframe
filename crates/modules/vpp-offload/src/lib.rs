//! vpp-offload: the VPP-on-VF forwarding vector (phase 4).
//!
//! PacketFrame's first non-eBPF module — `hook_spec()` is empty. The
//! module is an **orchestrator**: it owns SR-IOV VF + vfio + hugepage
//! resources, renders VPP's startup.conf, supervises the VPP child
//! process, mirrors the RouteController's full table into VPP over
//! the binary API, and owns the MCAM steering rules that bifurcate
//! allowlisted traffic onto the VF. Zero dataplane code lives here;
//! VPP is the upstream program.
//!
//! Slice 1 (this crate's initial form) ships the scaffold: config
//! handling, feasibility probes, and the startup.conf renderer with
//! its route-count-driven memory arithmetic. `attach` is
//! NotImplemented until slice 2 (resource lifecycle).
//!
//! Design record: `.claude/plans/` phase-4 plan v5 (frozen after four
//! review rounds). Key invariants enforced from day one:
//! - membership (VF on every possible egress port) is all-or-nothing;
//!   steering is the per-port canary lever (`Config::validate_vpp_offload`);
//! - the steered-prefix set inherits the fast-path allowlist, which
//!   must mean pure stateless L3 transit;
//! - the eBPF fast-path on the PFs is the permanent failover tier.

pub mod resources;
pub mod startup_conf;

#[cfg(target_os = "linux")]
mod probe_linux;

use packetframe_common::config::ModuleDirective;
use packetframe_common::module::{
    Attachment, HealthCtx, HealthReport, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
    ModuleError, ModuleResult,
};
use packetframe_common::probe::Capability;

pub const MODULE_NAME: &str = "vpp-offload";

/// Parsed view of the module's section, extracted once at load.
#[derive(Debug, Clone, Default)]
pub struct VppOffloadConfig {
    /// (iface, cores, steer) in config order.
    pub ports: Vec<(String, u16, bool)>,
    pub vpp_binary: Option<String>,
    pub expected_routes: u64,
    pub hugepages: Option<u32>,
}

/// Default sizing input when `expected-routes` is absent.
///
/// Measured 2026-08-02 on the reference fleet: ~1.30M nexthops across
/// v4+v6 (see `docs/runbooks/vpp-offload-spike.md` §0). The DFZ grows
/// roughly 100k routes/yr, so this is about three years of headroom.
/// The previous 1_400_000 sat barely above the live table — under a
/// year — which is not a useful default for a value that sizes VPP's
/// main heap at startup.
pub const DEFAULT_EXPECTED_ROUTES: u64 = 1_600_000;

impl VppOffloadConfig {
    pub fn from_directives(directives: &[ModuleDirective]) -> Self {
        let mut out = Self {
            expected_routes: DEFAULT_EXPECTED_ROUTES,
            ..Self::default()
        };
        for d in directives {
            match d {
                ModuleDirective::VppPort {
                    iface,
                    cores,
                    steer,
                    ..
                } => out.ports.push((iface.clone(), *cores, *steer)),
                ModuleDirective::VppBinary(p) => out.vpp_binary = Some(p.clone()),
                ModuleDirective::ExpectedRoutes(n) => out.expected_routes = *n,
                ModuleDirective::VppHugepages(n) => out.hugepages = Some(*n),
                _ => {}
            }
        }
        out
    }
}

pub struct VppOffloadModule {
    cfg: VppOffloadConfig,
}

impl VppOffloadModule {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            cfg: VppOffloadConfig::default(),
        }
    }
}

impl Module for VppOffloadModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    /// No BPF hooks: the first exercise of the multi-vector Module
    /// contract. The loader must treat an empty hook set as valid.
    fn hook_spec(&self) -> Vec<HookUse> {
        Vec::new()
    }

    fn load(&mut self, cfg: &ModuleConfig<'_>, _ctx: &LoaderCtx<'_>) -> ModuleResult<()> {
        self.cfg = VppOffloadConfig::from_directives(&cfg.section.directives);
        if self.cfg.ports.is_empty() {
            return Err(ModuleError::other(
                MODULE_NAME,
                "module vpp-offload declares no `port` lines; nothing to orchestrate",
            ));
        }
        // Cross-section membership/steering/custom-fib validation runs
        // at the Config level (`Config::validate_vpp_offload`) where
        // the fast-path section is visible; by load time it has passed.
        // Here: validate the sizing arithmetic so a too-small
        // `hugepages` is a clean startup error, not a VPP init abort.
        let sizing = startup_conf::derive_sizing(self.cfg.expected_routes)
            .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        if let Some(pages) = self.cfg.hugepages {
            startup_conf::check_hugepage_budget(&sizing, pages, default_hugepage_bytes())
                .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        }
        Ok(())
    }

    fn attach(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
        // Slice 2: hugepages → VF → vfio → startup.conf → spawn/adopt
        // → resync-verify → steer.
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    fn reconfigure(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    fn detach(&mut self) -> ModuleResult<()> {
        // Nothing attached in slice 1; detach of nothing succeeds so
        // `packetframe detach --all` stays idempotent.
        Ok(())
    }

    fn sample_metrics(&self, _out: &mut MetricsWriter<'_>) -> ModuleResult<()> {
        Ok(())
    }

    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<HealthReport> {
        Ok(HealthReport::healthy())
    }
}

/// Feasibility probes for `packetframe feasibility`, mirroring how the
/// fast-path's per-interface probes graft into the report. All
/// non-required: feasibility output informs, attach enforces.
pub fn run_feasibility_probes(ports: &[String], vpp_binary: Option<&str>) -> Vec<Capability> {
    #[cfg(target_os = "linux")]
    {
        probe_linux::run(ports, vpp_binary)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ports, vpp_binary);
        Vec::new()
    }
}

/// Default hugepage size in bytes, from /proc/meminfo `Hugepagesize`.
/// Non-Linux and read failures return 0, which the budget check treats
/// as "unknown — skip the byte-accurate comparison" (feasibility will
/// flag the platform anyway).
pub fn default_hugepage_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        probe_linux::default_hugepage_bytes()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}
