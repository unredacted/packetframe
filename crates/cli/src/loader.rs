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

    // Fail fast if metrics-textfile can't be written — the exporter
    // would retry silently every 15s otherwise.
    if let Some(path) = &config.global.metrics_textfile {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        if !parent.exists() {
            return Err(RunError::Startup(format!(
                "metrics-textfile parent dir {} does not exist",
                parent.display()
            )));
        }
    }

    // Refuse startup if a circuit-breaker trip flag from a prior
    // invocation is still present. The flag is sticky across kernel
    // reboots — SPEC §8.3 — and must be cleared by an operator.
    #[cfg(feature = "fast-path")]
    {
        let flag_path = packetframe_fast_path::breaker::trip_flag_path(&config.global.state_dir);
        if flag_path.exists() {
            return Err(RunError::Startup(format!(
                "circuit-breaker trip flag present at {}; \
                 investigate and `rm` it before restarting (SPEC §8.3 sticky detach)",
                flag_path.display()
            )));
        }
    }

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

    // Start the metrics exporter once STATS is pinned (which happens
    // in the attach loop above).
    let metrics_exporter = config.global.metrics_textfile.as_ref().map(|path| {
        crate::metrics::MetricsExporter::start(path.clone(), config.global.bpffs_root.clone())
    });

    // Start circuit-breaker sampler(s) for each module that declared
    // one. v0.1 has one module so this is at most one thread.
    let mut breaker_samplers: Vec<crate::breaker::BreakerSampler> = Vec::new();
    for section in &config.modules {
        if let Some(spec) = extract_breaker_spec(section) {
            breaker_samplers.push(crate::breaker::BreakerSampler::start(
                spec,
                config.global.bpffs_root.clone(),
                config.global.state_dir.clone(),
            ));
        }
    }

    tracing::info!("fast-path running — SIGHUP to reconfigure, SIGTERM/SIGINT to exit (§8.5)");

    let termination = drive_signal_loop(config_path, &mut modules).map_err(RunError::Runtime)?;

    // Stop the exporter + breaker sampler(s) first so their final
    // writes complete before we touch module state.
    if let Some(m) = metrics_exporter {
        m.shutdown();
    }
    for sampler in breaker_samplers {
        sampler.shutdown();
    }

    match termination {
        Termination::ExitPreserveAttach => {
            // SPEC.md §7.3 / §8.5: SIGTERM/SIGINT exit *without*
            // detaching. Dropping `modules` closes our userspace FDs;
            // the bpffs pins hold the kernel references, so the XDP
            // attachment survives.
            tracing::info!("termination signal received; exiting (pins hold the attach per §8.5)");
            drop(modules);
        }
        Termination::BreakerTrip => {
            // Breaker fired (SIGUSR1). Tear down pins so the kernel
            // detaches; the sticky trip flag is already on disk so
            // subsequent `run` invocations refuse to re-attach.
            tracing::error!("circuit breaker tripped — detaching every module");
            for (name, module) in modules.iter_mut() {
                if let Err(e) = module.detach() {
                    tracing::error!(module = %name, error = %e, "detach failed");
                }
            }
            drop(modules);
        }
    }
    Ok(())
}

/// Look through a module section's directives and return its
/// `CircuitBreakerSpec`, if present. Multiple directives of the same
/// kind aren't rejected by the parser — take the last one if so.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn extract_breaker_spec(
    section: &packetframe_common::config::ModuleSection,
) -> Option<packetframe_common::config::CircuitBreakerSpec> {
    section.directives.iter().rev().find_map(|d| match d {
        packetframe_common::config::ModuleDirective::CircuitBreaker(s) => Some(*s),
        _ => None,
    })
}

#[cfg(all(target_os = "linux", feature = "fast-path"))]
enum Termination {
    /// SIGTERM/SIGINT: exit, leave pins in place.
    ExitPreserveAttach,
    /// SIGUSR1 from the breaker: detach, then exit.
    BreakerTrip,
}

/// Drive the signal loop. Returns the termination reason the caller
/// uses to decide whether to detach or preserve pins on exit.
///
/// - SIGHUP → re-parse config + reconfigure each loaded module.
/// - SIGTERM/SIGINT → `Termination::ExitPreserveAttach` (keep pins).
/// - SIGUSR1 → `Termination::BreakerTrip` (breaker fired; caller
///   detaches). SIGUSR1 is raised by the breaker sampler thread on
///   trip.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn drive_signal_loop(
    config_path: &Path,
    modules: &mut [(String, Box<dyn packetframe_common::module::Module>)],
) -> Result<Termination, String> {
    use signal_hook::{
        consts::{SIGHUP, SIGINT, SIGTERM, SIGUSR1},
        iterator::Signals,
    };

    let mut signals = Signals::new([SIGTERM, SIGINT, SIGHUP, SIGUSR1])
        .map_err(|e| format!("signal registration: {e}"))?;

    for sig in signals.forever() {
        match sig {
            SIGHUP => reconfigure_from_signal(config_path, modules),
            SIGTERM | SIGINT => {
                tracing::info!(signal = sig, "termination requested");
                return Ok(Termination::ExitPreserveAttach);
            }
            SIGUSR1 => {
                tracing::warn!("SIGUSR1 received — breaker-triggered shutdown");
                return Ok(Termination::BreakerTrip);
            }
            _ => {}
        }
    }
    Ok(Termination::ExitPreserveAttach)
}

/// SIGHUP handler. Re-parses the config from `config_path` and calls
/// `Module::reconfigure` on each loaded module. Parse failures and
/// per-module reconfigure errors are logged and swallowed — a bad
/// SIGHUP never kills the running data plane.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn reconfigure_from_signal(
    config_path: &Path,
    modules: &mut [(String, Box<dyn packetframe_common::module::Module>)],
) {
    use packetframe_common::module::ModuleConfig;

    tracing::info!(config = %config_path.display(), "SIGHUP received; reconfiguring");

    let new_config = match Config::from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "SIGHUP config parse failed; keeping current config");
            return;
        }
    };

    for (name, module) in modules.iter_mut() {
        let section = match new_config.modules.iter().find(|m| &m.name == name) {
            Some(s) => s,
            None => {
                tracing::warn!(
                    module = %name,
                    "module removed from config; reconfigure skipped (attach-set changes require restart)"
                );
                continue;
            }
        };
        let mcfg = ModuleConfig::new(section, &new_config.global);
        if let Err(e) = module.reconfigure(&mcfg) {
            tracing::warn!(module = %name, error = %e, "reconfigure failed");
        }
    }
}

/// Look for a live `packetframe run` daemon via `/proc`. Returns the
/// pid of the first match, None if none found. Only our own process
/// name is matched (not arbitrary substrings), so a text editor
/// holding a `packetframe.conf` file doesn't false-positive.
#[cfg(target_os = "linux")]
fn daemon_pid() -> Option<u32> {
    let self_pid = std::process::id();
    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let pid: u32 = match name.to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        if pid == self_pid {
            continue;
        }
        let comm_path = format!("/proc/{pid}/comm");
        let comm = match std::fs::read_to_string(&comm_path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if comm.trim() == "packetframe" {
            // Confirm it's actually the `run` subcommand, not e.g.
            // `packetframe detach` from another shell.
            let cmdline_path = format!("/proc/{pid}/cmdline");
            if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
                if cmdline.split('\0').any(|a| a == "run") {
                    return Some(pid);
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn daemon_pid() -> Option<u32> {
    None
}

pub fn detach(config: Option<&Path>, all: bool) -> Result<(), String> {
    // Refuse to detach while a `packetframe run` daemon is live. The
    // daemon holds PinnedLink FDs in-process; unlinking the bpffs pin
    // paths alone doesn't drop the kernel-side bpf_link refcount, so
    // the XDP program stays attached even after `detach` claims
    // success. The operator needs to SIGTERM/kill the daemon first.
    // Confirmed outage-adjacent on the reference EFG 2026-04-21 — the
    // detach ran, reported clean, but `ip link show` still had
    // `xdpgeneric` attached.
    if let Some(pid) = daemon_pid() {
        return Err(format!(
            "a `packetframe run` daemon is still running (pid {pid}); \
             stop it first (e.g. `kill {pid}`) before detaching. \
             Detach unlinks bpffs pins, but the kernel-side bpf_link \
             holds refs through the daemon's open FDs — both have to \
             be released for the iface to actually detach."
        ));
    }

    let (bpffs_root, state_dir, settle_time) = match config {
        Some(p) => {
            let c = Config::from_file(p).map_err(|e| format!("config parse: {e}"))?;
            (
                c.global.bpffs_root,
                c.global.state_dir,
                c.global.attach_settle_time,
            )
        }
        None => (
            PathBuf::from(packetframe_common::config::DEFAULT_BPFFS_ROOT),
            PathBuf::from(packetframe_common::config::DEFAULT_STATE_DIR),
            packetframe_common::config::DEFAULT_ATTACH_SETTLE_TIME,
        ),
    };

    // v0.1 has one module (fast-path), so `--all` and the default case
    // behave identically — both tear down every pin under the module's
    // pin root. `--all` becomes meaningful once a second module ships.
    let _ = all;

    #[cfg(feature = "fast-path")]
    {
        use packetframe_fast_path::registry::load as registry_load;
        match registry_load(&state_dir) {
            Ok(Some(file)) => {
                tracing::info!(
                    module = %file.module,
                    count = file.attachments.len(),
                    "pin registry found; tearing down"
                );
                for a in &file.attachments {
                    tracing::info!(
                        iface = %a.iface,
                        hook = ?a.hook,
                        prog_id = a.prog_id,
                        "registered attachment"
                    );
                }
            }
            Ok(None) => {
                tracing::info!("no pin registry found — sweeping bpffs pin root anyway");
            }
            Err(e) => return Err(format!("registry read: {e}")),
        }

        // Unlink every pin under `<bpffs-root>/fast-path/`. Removing
        // link pins triggers the kernel-side XDP detach (§8.5). Pace
        // by `attach_settle_time` so bridge-member detaches don't
        // pile up inside one STP reconvergence window — that's the
        // post-rc5 fix for the EFG kernel-panic-on-detach observed
        // during Phase 4 cutover testing. Map + program pins are
        // housekeeping with no kernel-link side effects, no pacing.
        packetframe_fast_path::pin::remove_all_paced(&bpffs_root, settle_time)
            .map_err(|e| format!("remove pins under {}: {e}", bpffs_root.display()))?;
        tracing::info!(
            pin_root = %packetframe_fast_path::pin::module_root(&bpffs_root).display(),
            settle_secs = settle_time.as_secs_f64(),
            "pins removed; kernel detached"
        );

        packetframe_fast_path::registry::remove(&state_dir)
            .map_err(|e| format!("registry remove: {e}"))?;
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

        // Live counter readback from the pinned STATS map. Works
        // whether or not the loader is running — the pin survives
        // process exit (§8.5).
        #[cfg(target_os = "linux")]
        print_stats(&config.global.bpffs_root);
    }

    Ok(())
}

#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn print_stats(bpffs_root: &Path) {
    // §4.6 counter names, indexed by `StatIdx` discriminants. Order
    // matches `crates/modules/fast-path/bpf/src/maps.rs::StatIdx`.
    // Append-only — adding new entries at the end is fine; renumbering
    // breaks dashboards. Indices 0-19 are the kernel-fib counter set;
    // 20-31 were appended in the Option F custom-FIB rollout (§4.11).
    const NAMES: [&str; 33] = [
        "rx_total",
        "matched_v4",
        "matched_v6",
        "matched_src_only",
        "matched_dst_only",
        "matched_both",
        "fwd_ok",
        "fwd_dry_run",
        "pass_fragment",
        "pass_low_ttl",
        "pass_no_neigh",
        "pass_not_ip",
        "pass_frag_needed",
        "drop_unreachable",
        "err_parse",
        "err_fib_other",
        "err_vlan",
        "pass_not_in_devmap",
        "pass_complex_header",
        "err_head_shift",
        // --- Custom FIB (Option F, Phase 1) ---
        "custom_fib_hit",
        "custom_fib_miss",
        "custom_fib_no_neigh",
        "compare_agree",
        "compare_disagree",
        "ecmp_hash_v4",
        "ecmp_hash_v6",
        "ecmp_dead_leg_fallback",
        "route_source_resync",
        "neigh_cache_miss",
        "nexthop_seq_retry",
        "bmp_peer_down",
        "bogon_dropped",
    ];

    print_fib_status(bpffs_root);

    match packetframe_fast_path::stats_from_pin(bpffs_root) {
        Ok(values) => {
            println!();
            println!("counters (from {}):", bpffs_root.display());
            let name_w = NAMES.iter().map(|n| n.len()).max().unwrap_or(20);
            for (name, value) in NAMES.iter().zip(values.iter()) {
                println!("  {name:<name_w$}  {value}");
            }
        }
        Err(e) => {
            eprintln!("note: STATS pin unavailable ({e}); loader may not be attached");
        }
    }
}

/// Print the Option F custom-FIB status — map occupancies, nexthop
/// state distribution, default hash mode. Best-effort: prints
/// whatever readable slice of the FIB pins returns. Runs regardless
/// of forwarding-mode so operators can verify pins exist and the
/// programmer has populated them (or hasn't, in kernel-fib mode).
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn print_fib_status(bpffs_root: &Path) {
    let snap = packetframe_fast_path::fib_status_from_pin(bpffs_root);
    println!();
    println!("custom-FIB status (from {}):", bpffs_root.display());
    match snap.forwarding_mode {
        Some(mode) => println!("  forwarding-mode:            {mode}"),
        None => println!("  forwarding-mode:            <CFG pin not readable>"),
    }
    if let Some(h) = snap.default_hash_mode {
        println!("  default-hash-mode:          {h}-tuple");
    }
    if snap.nh_max_entries > 0 {
        let used = snap.nh_resolved + snap.nh_failed + snap.nh_stale;
        let pct = 100.0 * used as f64 / snap.nh_max_entries as f64;
        println!("  nexthops (resolved):        {}", snap.nh_resolved);
        println!("  nexthops (failed):          {}", snap.nh_failed);
        println!("  nexthops (stale):           {}", snap.nh_stale);
        println!(
            "  nexthops (total used / max): {} / {} ({pct:.2}%)",
            used, snap.nh_max_entries
        );
    } else {
        println!("  nexthops pin:               unavailable");
    }
    if snap.ecmp_max_entries > 0 {
        println!(
            "  ecmp groups (active / max): {} / {}",
            snap.ecmp_active, snap.ecmp_max_entries
        );
    } else {
        println!("  ecmp groups pin:            unavailable");
    }
    println!(
        "  FIB_V4 / FIB_V6 occupancy:  not shown (LpmTrie walk is O(N); \
         infer from custom_fib_hit / custom_fib_miss counters below)"
    );
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
