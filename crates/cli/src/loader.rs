//! CLI glue that drives the fast-path module lifecycle.
//!
//! - `run`: parse config, probe capabilities, load + attach fast-path,
//!   persist the pin registry, block on SIGTERM/SIGINT (SPEC.md §7.3).
//! - `detach`: read the pin registry and report what's recorded.
//!   Actual in-kernel detach without an active loader requires pinning,
//!   which lands with PR #6 — this subcommand graduates then.
//! - `status`: read the pin registry and (when a loader is running with
//!   a pinned stats map) the counter values. v0.1 reports the registry
//!   alone.

use std::path::{Path, PathBuf};

use packetframe_common::{config::Config, probe::run_probes};

#[cfg(all(target_os = "linux", feature = "fast-path"))]
use packetframe_common::module::{LoaderCtx, Module, ModuleConfig};

#[cfg(all(target_os = "linux", feature = "fast-path"))]
use packetframe_fast_path::{
    registry::{save, RegistryFile},
    FastPathModule,
};

#[cfg(feature = "fast-path")]
use packetframe_fast_path::registry::HookTypeRecord;

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// Config parse / interface-missing / capability fail — exit 1.
    #[error("{0}")]
    Startup(String),
    /// Post-attach errors or unexpected runtime failures — exit 2.
    /// Only constructed on Linux (the non-Linux path returns Startup
    /// immediately), so non-Linux builds flag this as dead code.
    #[cfg_attr(not(all(target_os = "linux", feature = "fast-path")), allow(dead_code))]
    #[error("{0}")]
    Runtime(String),
}

pub fn run(config_path: &Path) -> Result<(), RunError> {
    let config = Config::from_file(config_path)
        .map_err(|e| RunError::Startup(format!("config parse: {e}")))?;
    config
        .validate_interfaces()
        .map_err(|e| RunError::Startup(e.to_string()))?;

    // Feasibility gate: refuse to attach if any required capability is
    // missing. The per-interface trial-attach probe (§2.3) runs here
    // too — if a specific iface can't receive an XDP program at all,
    // the user finds out before we try to actually attach.
    let attach_ifaces = crate::feasibility::attach_ifaces_from_config(&config);
    let report = run_probes(&config.global.bpffs_root);
    let iface_report = trial_attach_probes(&attach_ifaces);
    if !report.passed {
        let fails: Vec<&str> = report
            .capabilities
            .iter()
            .filter(|c| c.required && c.status != packetframe_common::probe::CapabilityStatus::Pass)
            .map(|c| c.name.as_str())
            .collect();
        return Err(RunError::Startup(format!(
            "required kernel capabilities missing: {}",
            fails.join(", ")
        )));
    }
    for (iface, verdict) in &iface_report {
        tracing::info!(iface, %verdict, "per-interface trial attach");
    }

    // Dispatch to platform-specific runner. On non-Linux we'd have
    // already failed the capability probe above, so this is
    // belt-and-suspenders.
    #[cfg(all(target_os = "linux", feature = "fast-path"))]
    return run_linux(config, config_path);

    #[cfg(not(all(target_os = "linux", feature = "fast-path")))]
    {
        let _ = config_path;
        Err(RunError::Startup(
            "fast-path module is Linux-only; this build cannot run the data plane".into(),
        ))
    }
}

#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn run_linux(config: Config, config_path: &Path) -> Result<(), RunError> {
    use packetframe_common::module::ModuleError;

    let mut modules: Vec<(String, Box<dyn Module>)> = Vec::new();
    for section in &config.modules {
        match section.name.as_str() {
            "fast-path" => modules.push((
                section.name.clone(),
                Box::new(FastPathModule::new()) as Box<dyn Module>,
            )),
            other => {
                return Err(RunError::Startup(format!(
                    "unknown module `{other}` in {}",
                    config_path.display()
                )));
            }
        }
    }

    let ctx = LoaderCtx {
        bpffs_root: &config.global.bpffs_root,
        state_dir: &config.global.state_dir,
    };

    for (name, module) in &mut modules {
        let section = config
            .modules
            .iter()
            .find(|m| &m.name == name)
            .expect("module name resolves");
        let mcfg = ModuleConfig::new(section, &config.global);
        module
            .load(&mcfg, &ctx)
            .map_err(|e: ModuleError| RunError::Startup(e.to_string()))?;
        let attachments = module
            .attach(&mcfg)
            .map_err(|e: ModuleError| RunError::Runtime(e.to_string()))?;

        // Persist the pin registry so `packetframe detach` has
        // something to look at post-exit. Pinning itself is PR #6.
        let file = RegistryFile {
            module: module.name().to_string(),
            attachments: attachments.into_iter().map(Into::into).collect(),
        };
        save(&config.global.state_dir, &file)
            .map_err(|e| RunError::Runtime(format!("pin registry save: {e}")))?;

        tracing::info!(module = %name, attachments = file.attachments.len(), "module attached");
    }

    tracing::info!(
        "fast-path running — SIGTERM/SIGINT to exit; detach on exit pending pin support (PR #6)"
    );

    wait_for_termination().map_err(RunError::Runtime)?;

    // SPEC.md §7.3 / §8.5: SIGTERM/SIGINT must exit *without* detaching.
    // In v0.1 there's no bpffs pinning yet, so dropping the `Ebpf`
    // inside `modules` necessarily tears down the attach (the
    // kernel-side `bpf_link` closes when its FD does). PR #6 will
    // make this a true no-op-on-exit by pinning programs + maps
    // before the drop. For now we deliberately *do not* call
    // `Module::detach` here; the drop path is the same end state,
    // and leaving it implicit keeps the exit intent aligned with
    // what pinning will later honor.
    tracing::info!("termination signal received; exiting (no explicit detach, per §8.5)");
    drop(modules);
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn wait_for_termination() -> Result<(), String> {
    use signal_hook::{
        consts::{SIGHUP, SIGINT, SIGTERM},
        iterator::Signals,
    };

    let mut signals =
        Signals::new([SIGTERM, SIGINT, SIGHUP]).map_err(|e| format!("signal registration: {e}"))?;

    for sig in signals.forever() {
        match sig {
            SIGHUP => {
                // SPEC.md §8.4 / §4.5: delta-only reconcile lives in PR #6.
                tracing::warn!("SIGHUP received; reconfigure flow not implemented in this release");
            }
            SIGTERM | SIGINT => {
                // SPEC.md §7.3 / §8.5: exit without detach. Pin-based
                // program persistence requires PR #6; until then, exit
                // *does* implicitly detach.
                tracing::info!(signal = sig, "termination requested");
                return Ok(());
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn detach(config: Option<&Path>, all: bool) -> Result<(), String> {
    let state_dir = match config {
        Some(p) => {
            Config::from_file(p)
                .map_err(|e| format!("config parse: {e}"))?
                .global
                .state_dir
        }
        None => PathBuf::from(packetframe_common::config::DEFAULT_STATE_DIR),
    };

    if all {
        tracing::warn!(
            "`--all` requires bpffs pin sweep (PR #6); for now, honoring the pin registry only"
        );
    }

    #[cfg(feature = "fast-path")]
    {
        use packetframe_fast_path::registry::load as registry_load;
        match registry_load(&state_dir) {
            Ok(Some(file)) => {
                tracing::info!(
                    module = %file.module,
                    count = file.attachments.len(),
                    "pin registry found"
                );
                for a in &file.attachments {
                    tracing::info!(
                        iface = %a.iface,
                        hook = ?a.hook,
                        prog_id = a.prog_id,
                        "registered attachment"
                    );
                }
                tracing::warn!(
                    "in-kernel detach without an active loader requires bpffs pinning (SPEC.md §8.5 + pinning support in PR #6); removing registry file only"
                );
                packetframe_fast_path::registry::remove(&state_dir)
                    .map_err(|e| format!("registry remove: {e}"))?;
            }
            Ok(None) => {
                tracing::info!("no pin registry found — nothing to detach");
            }
            Err(e) => return Err(format!("registry read: {e}")),
        }
    }

    Ok(())
}

pub fn status(config_path: &Path) -> Result<(), String> {
    let config = Config::from_file(config_path).map_err(|e| format!("config parse: {e}"))?;

    #[cfg(feature = "fast-path")]
    {
        use packetframe_fast_path::registry::load as registry_load;
        match registry_load(&config.global.state_dir) {
            Ok(Some(file)) => {
                println!("module: {}", file.module);
                println!("attachments ({}):", file.attachments.len());
                for a in &file.attachments {
                    let hook_name = match a.hook {
                        HookTypeRecord::NativeXdp => "xdp-native",
                        HookTypeRecord::GenericXdp => "xdp-generic",
                        HookTypeRecord::TcIngress => "tc-ingress",
                        HookTypeRecord::TcEgress => "tc-egress",
                    };
                    println!(
                        "  {} [{}] prog_id={} pinned={}",
                        a.iface,
                        hook_name,
                        a.prog_id,
                        a.pinned_path.display()
                    );
                }
            }
            Ok(None) => {
                println!("no pin registry at {}", config.global.state_dir.display());
            }
            Err(e) => return Err(format!("registry read: {e}")),
        }
    }

    eprintln!("note: live counter readback requires bpffs-pinned stats (PR #6)");
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn trial_attach_probes(ifaces: &[String]) -> Vec<(String, String)> {
    use packetframe_fast_path::{trial_attach_native, TrialResult};
    ifaces
        .iter()
        .map(|iface| {
            let r = trial_attach_native(iface);
            let verdict = match r {
                TrialResult::NativeOk => "native OK".to_string(),
                TrialResult::GenericOnly { .. } => "native failed, generic OK".to_string(),
                TrialResult::Neither {
                    native_error,
                    generic_error,
                } => {
                    format!("native+generic both failed: {native_error}; {generic_error}")
                }
                TrialResult::NoSuchInterface(e) => format!("no such interface: {e}"),
                TrialResult::LoadFailed(e) => format!("load failed: {e}"),
                TrialResult::NoBpfBinary => "no BPF ELF embedded".to_string(),
            };
            (iface.clone(), verdict)
        })
        .collect()
}

#[cfg(not(all(target_os = "linux", feature = "fast-path")))]
fn trial_attach_probes(_ifaces: &[String]) -> Vec<(String, String)> {
    Vec::new()
}
