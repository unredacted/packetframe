//! PacketFrame neigh-snoop module: a passive ARP/ND neighbour snooper
//! for IX-facing bridges.
//!
//! On an exchange fabric every participant floods ARP requests and
//! IPv6 neighbour solicitations to every member port, and each carries
//! the sender's `(ip, mac)`. Linux discards them unless they ask about
//! one of its own addresses. When a router cannot send broadcast ARP
//! or multicast NS itself (a switch ACL drops them, deliberately), the
//! kernel can only reach a peer whose MAC it already holds — after a
//! reboot that means hours. This module:
//!
//! 1. listens, receive-only, on configured bridges (promiscuous
//!    AF_PACKET socket with a classic-BPF filter; **never transmits**);
//! 2. learns `(ip, mac)` pairs from third-party ARP requests/replies and
//!    ICMPv6 NS/NA inside configured prefixes, refusing its own
//!    addresses and MACs and a deny list;
//! 3. installs missing or failed kernel neighbour entries as
//!    `NUD_STALE` (a STALE entry with a valid MAC forwards immediately
//!    and is confirmed by a *unicast* probe the ACL permits), rate
//!    limited, never overriding a MAC the kernel has confirmed;
//! 4. persists the table per bridge and re-seeds the kernel on start
//!    and whenever the bridge — tracked **by name**, because the
//!    platform daemon recreates it — comes back up;
//! 5. tells fast-path's neighbour resolver, via `ix-mode`, to stop
//!    issuing its own broadcast probes for nexthops via those bridges;
//! 6. optionally reconciles FRR's runtime next-hop prefix-lists (the
//!    dynamic half of the IX next-hop gate) through `vtysh`, and
//!    measures how many route-server prefixes remain demoted.
//!
//! Userspace only: no BPF program, no pins, nothing for `packetframe
//! detach` to tear down. Learned STALE entries and the JSON cache are
//! deliberately left in place.
//!
//! Operations: `docs/runbooks/neigh-snoop.md`.

pub mod bpf_filter;
pub mod cfg;
pub mod frame;
pub mod health;
pub mod metrics;
pub mod persist;
pub mod probe_linux;
pub mod snapshot;
pub mod table;

pub use probe_linux::run_feasibility_probes;

use std::path::PathBuf;

use packetframe_common::module::{
    Attachment, HealthCtx, HealthReport, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
    ModuleError, ModuleResult,
};

use crate::cfg::SnoopConfig;

pub const MODULE_NAME: &str = "neigh-snoop";

/// What `load` establishes: the parsed section and a persist directory
/// proven writable. The engine (Linux) is started by `attach`.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub config: SnoopConfig,
    pub persist_dir: PathBuf,
}

/// Module handle. `Default`/`new` produce an unloaded instance; call
/// [`Module::load`] to bring it online.
#[derive(Default)]
pub struct NeighSnoopModule {
    loaded: Option<Loaded>,
}

impl NeighSnoopModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// The parsed configuration, once loaded.
    pub fn loaded(&self) -> Option<&Loaded> {
        self.loaded.as_ref()
    }
}

fn parse(cfg: &ModuleConfig<'_>) -> ModuleResult<SnoopConfig> {
    SnoopConfig::from_directives(&cfg.section.directives)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("module neigh-snoop: {e}")))
}

impl Module for NeighSnoopModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    /// No BPF hook: the module is a userspace listener. Nothing in the
    /// loader dispatches on this yet; an empty list is the honest
    /// answer.
    fn hook_spec(&self) -> Vec<HookUse> {
        Vec::new()
    }

    fn load(&mut self, cfg: &ModuleConfig<'_>, ctx: &LoaderCtx<'_>) -> ModuleResult<()> {
        // Parse first: config refusals must not depend on filesystem
        // state, so every caller gets the same verdict at the earliest
        // point.
        let config = parse(cfg)?;
        let persist_dir = config.resolve_persist_dir(ctx.state_dir);
        // Refuse an unwritable persist directory now rather than at the
        // first debounced save minutes after attach.
        persist::ensure_dir_writable(&persist_dir).map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("module neigh-snoop: persist-dir is not writable: {e}"),
            )
        })?;
        tracing::info!(
            bridges = config.bridges.len(),
            persist_dir = %persist_dir.display(),
            "neigh-snoop configuration loaded"
        );
        self.loaded = Some(Loaded {
            config,
            persist_dir,
        });
        Ok(())
    }

    fn attach(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
        self.loaded
            .as_ref()
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "attach before load"))?;
        // The engine (capture sockets, netlink, runtime) lands in a
        // later slice; until then the module loads and validates but
        // cannot run. Returning NotImplemented keeps it unreachable
        // from a production config while the grammar is reviewable.
        Err(ModuleError::not_implemented(MODULE_NAME))
    }

    fn reconfigure(&mut self, cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
        let loaded = self
            .loaded
            .as_mut()
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "reconfigure before load"))?;
        let new = parse(cfg)?;
        loaded
            .config
            .restart_only_delta(&new)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("module neigh-snoop: {e}")))?;
        loaded.config = new;
        Ok(())
    }

    fn detach(&mut self) -> ModuleResult<()> {
        // Nothing attached in this slice. Once the engine exists, detach
        // stops it and deliberately leaves the kernel's STALE entries
        // and the JSON cache in place.
        self.loaded = None;
        Ok(())
    }

    fn sample_metrics(&self, _out: &mut MetricsWriter<'_>) -> ModuleResult<()> {
        // Unattached: emit nothing rather than zeroed counters that read
        // as healthy-idle (the guard/vpp-offload rule).
        Ok(())
    }

    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<HealthReport> {
        Ok(HealthReport::healthy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::config::{Config, GlobalConfig};
    use std::path::Path;

    fn scratch(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("pf-neigh-snoop-lib-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn load_with(body: &str, state_dir: &Path) -> Result<NeighSnoopModule, ModuleError> {
        let c = Config::parse(&format!("module neigh-snoop\n{body}")).unwrap();
        let global = GlobalConfig::default();
        let ctx = LoaderCtx {
            bpffs_root: Path::new("/sys/fs/bpf/packetframe"),
            state_dir,
        };
        let mut m = NeighSnoopModule::new();
        m.load(
            &ModuleConfig {
                section: &c.modules[0],
                global: &global,
            },
            &ctx,
        )?;
        Ok(m)
    }

    /// A config the validator refuses is refused by `load` with the
    /// same verdict — before any filesystem state is consulted.
    #[test]
    fn load_refuses_invalid_section_first() {
        let e = load_with(
            "  prefix br0 192.0.2.0/24\n",
            Path::new("/nonexistent/state"),
        )
        .err()
        .expect("orphan prefix refused");
        assert!(e.to_string().contains("no `bridge` line"), "{e}");
    }

    #[test]
    fn load_creates_default_persist_dir_under_state_dir() {
        let state = scratch("default-dir");
        let m = load_with("  bridge br0\n  prefix br0 192.0.2.0/24\n", &state).unwrap();
        let l = m.loaded().unwrap();
        assert_eq!(l.persist_dir, state.join("neigh-cache"));
        assert!(l.persist_dir.is_dir());
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn load_refuses_unwritable_persist_dir() {
        let state = scratch("unwritable");
        let file = state.join("a-file");
        std::fs::write(&file, b"x").unwrap();
        let body = format!(
            "  bridge br0\n  prefix br0 192.0.2.0/24\n  persist-dir {}\n",
            file.display()
        );
        let e = load_with(&body, &state).err().expect("file as dir refused");
        assert!(e.to_string().contains("persist-dir is not writable"), "{e}");
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn attach_is_not_implemented_yet_and_reconfigure_refuses_restart_only() {
        let state = scratch("attach");
        let mut m = load_with("  bridge br0\n  prefix br0 192.0.2.0/24\n", &state).unwrap();
        let global = GlobalConfig::default();
        let c =
            Config::parse("module neigh-snoop\n  bridge br0\n  prefix br0 192.0.2.0/24\n").unwrap();
        let mc = ModuleConfig {
            section: &c.modules[0],
            global: &global,
        };
        assert!(matches!(
            m.attach(&mc),
            Err(ModuleError::NotImplemented { .. })
        ));
        let c2 =
            Config::parse("module neigh-snoop\n  bridge br1\n  prefix br1 192.0.2.0/24\n").unwrap();
        let e = m
            .reconfigure(&ModuleConfig {
                section: &c2.modules[0],
                global: &global,
            })
            .expect_err("bridge set is restart-only");
        assert!(e.to_string().contains("restart-only"), "{e}");
        // A hot change is accepted and stored.
        let c3 = Config::parse(
            "module neigh-snoop\n  bridge br0\n  prefix br0 192.0.2.0/24\n  table-max 64\n",
        )
        .unwrap();
        m.reconfigure(&ModuleConfig {
            section: &c3.modules[0],
            global: &global,
        })
        .unwrap();
        assert_eq!(m.loaded().unwrap().config.hot.table_max, 64);
        let _ = std::fs::remove_dir_all(&state);
    }
}
