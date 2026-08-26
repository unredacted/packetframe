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
//! Operations: `docs/runbooks/guard.md` (monitor→enforce ladder,
//! counter attribution, triage, recovery).

pub mod cfg;
pub mod metrics;
pub mod pin;
pub mod probe_linux;
pub mod tc_links;

#[cfg(target_os = "linux")]
mod linux_impl;
#[cfg(target_os = "linux")]
pub use linux_impl::{detach_from_state_dir, stats_from_pin, tc_attach_egress};

pub use probe_linux::run_feasibility_probes;

use packetframe_common::module::{
    Attachment, HealthCtx, HealthReport, HookType, HookUse, LoaderCtx, MetricsWriter, Module,
    ModuleConfig, ModuleError, ModuleResult,
};

use crate::cfg::GuardConfig;

pub const MODULE_NAME: &str = "guard";

/// SPEC §3.2 hook priority. Guard is a policer, not a forwarder; it
/// sits outside the 1000–1999 forwarding range. Recorded, not yet
/// consulted (single-module-per-hook dispatch).
pub const GUARD_PRIORITY: u16 = 100;

/// The compiled guard BPF ELF, staged by `build.rs` and embedded at
/// crate-compile time. Empty (zero bytes) when the BPF toolchain isn't
/// available — see [`GUARD_BPF_AVAILABLE`] and fast-path's twin for
/// the alignment note (`include_bytes!` is 1-byte aligned; copy via
/// [`aligned_bpf_copy`] before `aya::Ebpf::load`).
pub const GUARD_BPF: &[u8] = include_bytes!(env!("GUARD_BPF_OBJ"));

/// Heap copy aligned enough (≥16 bytes from the system allocator) for
/// the `object` crate's ELF header reads.
pub fn aligned_bpf_copy() -> Vec<u8> {
    GUARD_BPF.to_vec()
}

/// `true` when `build.rs` produced a real BPF ELF; `false` when it
/// fell back to the empty stub (macOS dev loops). Load refuses on the
/// stub; tests early-return on it.
pub const GUARD_BPF_AVAILABLE: bool = !GUARD_BPF.is_empty();

/// Guard module handle. `Default`/`new` produce an unloaded instance;
/// call [`Module::load`] to bring it online.
#[derive(Default)]
pub struct GuardModule {
    #[cfg(target_os = "linux")]
    state: Option<linux_impl::ActiveState>,
    /// Non-Linux keeps just the parsed config so the load-time
    /// validation surface behaves identically on dev laptops.
    #[cfg(not(target_os = "linux"))]
    config: Option<GuardConfig>,
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

    #[cfg(target_os = "linux")]
    fn load(&mut self, cfg: &ModuleConfig<'_>, ctx: &LoaderCtx<'_>) -> ModuleResult<()> {
        // Parse first: config refusals must not depend on BPF/pin
        // state, so every caller gets the same verdict at the earliest
        // point.
        let parsed = GuardConfig::from_directives(&cfg.section.directives)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("module guard: {e}")))?;
        let state = linux_impl::load(parsed, ctx.bpffs_root, ctx.state_dir)?;
        self.state = Some(state);
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn load(&mut self, cfg: &ModuleConfig<'_>, _ctx: &LoaderCtx<'_>) -> ModuleResult<()> {
        let parsed = GuardConfig::from_directives(&cfg.section.directives)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("module guard: {e}")))?;
        self.config = Some(parsed);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn attach(&mut self, cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
        let state = self
            .state
            .as_mut()
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "attach before load"))?;
        linux_impl::attach(state, cfg.global.attach_settle_time)?;
        // No `Attachment`s by design: the shared attachments.json
        // registry is single-module (last writer wins), so guard's
        // teardown truth is guard-tc-links.json + its pins — the
        // vpp-offload precedent.
        Ok(Vec::new())
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
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "reconfigure before load"))?;
        let parsed = GuardConfig::from_directives(&cfg.section.directives)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("module guard: {e}")))?;
        linux_impl::reconfigure(state, parsed)
    }

    #[cfg(not(target_os = "linux"))]
    fn reconfigure(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    #[cfg(target_os = "linux")]
    fn detach(&mut self) -> ModuleResult<()> {
        if let Some(state) = self.state.as_mut() {
            linux_impl::detach(state)?;
        }
        self.state = None;
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn detach(&mut self) -> ModuleResult<()> {
        // Nothing can be attached on a stub platform; no-op is the
        // honest answer.
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn sample_metrics(&self, out: &mut MetricsWriter<'_>) -> ModuleResult<()> {
        match self.state.as_ref() {
            // Unloaded: emit nothing rather than zeroed counters that
            // read as healthy-idle (the vpp-offload rule).
            None => Ok(()),
            Some(state) => linux_impl::sample_metrics(state, out.out),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn sample_metrics(&self, _out: &mut MetricsWriter<'_>) -> ModuleResult<()> {
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<HealthReport> {
        Ok(match self.state.as_ref() {
            None => HealthReport::healthy(),
            Some(state) => linux_impl::health(state),
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<HealthReport> {
        // A stub platform has nothing attached; silence would be
        // misleading only if something could be running here, and
        // nothing can.
        Ok(HealthReport::healthy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::config::Config;

    /// A leftover `guard-tc-links.json` is prior state: attach saves
    /// records BEFORE pinning, so a crash in that window leaves live
    /// filters whose only teardown metadata is that file — a fresh
    /// attach would overwrite it and orphan them (review finding,
    /// PR #205). The refusal runs before any privileged BPF work, so
    /// this test needs a real ELF but no capabilities.
    #[cfg(target_os = "linux")]
    #[test]
    fn load_refuses_leftover_tc_link_records() {
        if !crate::GUARD_BPF_AVAILABLE {
            eprintln!("BPF stub in effect (no rustup); skipping leftover-state test.");
            return;
        }
        let dir = std::env::temp_dir().join(format!("pf-guard-leftover-{}", std::process::id()));
        let state_dir = dir.join("state");
        let bpffs_root = dir.join("bpffs");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::create_dir_all(&bpffs_root).unwrap();
        crate::tc_links::save(
            &state_dir,
            &crate::tc_links::TcLinksFile {
                links: vec![crate::tc_links::TcLinkRecord {
                    iface: "br3998".into(),
                    ifindex: 42,
                    priority: 49152,
                    handle: 1,
                }],
            },
        )
        .unwrap();

        let good = Config::parse("module guard\n  interface br0\n  lldp br0 drop\n").unwrap();
        let global = packetframe_common::config::GlobalConfig::default();
        let ctx = LoaderCtx {
            bpffs_root: &bpffs_root,
            state_dir: &state_dir,
        };
        let mut m = GuardModule::new();
        let e = m
            .load(
                &ModuleConfig {
                    section: &good.modules[0],
                    global: &global,
                },
                &ctx,
            )
            .expect_err("leftover records refused");
        assert!(format!("{e}").contains("detach --all"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A config the validator refuses is refused by `load` with the
    /// same verdict — before any BPF or pin state is consulted, so
    /// this holds unprivileged on every platform.
    #[test]
    fn load_refuses_invalid_section_first() {
        let bad = Config::parse("module guard\n  lldp br0 drop\n").unwrap();
        let global = packetframe_common::config::GlobalConfig::default();
        let ctx = LoaderCtx {
            bpffs_root: std::path::Path::new("/sys/fs/bpf/packetframe"),
            state_dir: std::path::Path::new("/var/lib/packetframe/state"),
        };
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

    /// On stub platforms the happy path parses and stores the config
    /// (the Linux happy path needs CAP_BPF and is covered by the
    /// ignored integration tests).
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn load_parses_on_stub_platforms() {
        let good = Config::parse("module guard\n  interface br0\n  lldp br0 drop\n").unwrap();
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
    }
}
