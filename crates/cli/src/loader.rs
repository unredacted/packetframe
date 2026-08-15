//! CLI glue that drives the fast-path module lifecycle.
//!
//! - `run`: parse config, probe capabilities, load + attach fast-path,
//!   persist the pin registry, block on SIGTERM/SIGINT (SPEC.md §7.3).
//! - `detach`: read the pin registry and report what's recorded.
//!   Actual in-kernel detach without an active loader requires pinning,
//!   which lands with PR #6, this subcommand graduates then.
//! - `status`: read the pin registry and (when a loader is running with
//!   a pinned stats map) the counter values. v0.1 reports the registry
//!   alone.

use std::path::{Path, PathBuf};

use crate::scrub::scrub_for_terminal;
#[cfg(all(target_os = "linux", feature = "fast-path"))]
use std::time::{Duration, Instant};

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
    /// Config parse / interface-missing / capability fail, exit 1.
    #[error("{0}")]
    Startup(String),
    /// Post-attach errors or unexpected runtime failures, exit 2.
    /// Only constructed on Linux (the non-Linux path returns Startup
    /// immediately), so non-Linux builds flag this as dead code.
    #[cfg_attr(not(all(target_os = "linux", feature = "fast-path")), allow(dead_code))]
    #[error("{0}")]
    Runtime(String),
}

/// Errors from `packetframe reconfigure`. Kept separate from
/// [`RunError`] because the CLI maps each variant to a different exit
/// code + log message, distinguishing "no daemon" from "daemon
/// rejected the new config" matters for operator scripts. Most
/// variants are Linux-only since the underlying signal/PID-file flow
/// is Linux-only; the macOS dev build gates them behind a generic
/// stub.
#[derive(Debug, thiserror::Error)]
pub enum ReconfigureError {
    /// Config / pidfile / proc IO error, exit 2 (runtime).
    #[error("{0}")]
    Io(String),
    /// PID file absent or stale, exit 1 (startup-style).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    #[error("{0}")]
    DaemonNotRunning(String),
    /// SIGHUP delivered, daemon ack'd, but the ack reported a parse
    /// error or per-module reconcile failure. Exit 2 (runtime).
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    #[error("{0}")]
    DaemonRejected(String),
    /// SIGHUP delivered but no ack within 5s. Daemon may be wedged.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    #[error("daemon did not acknowledge reconfigure within 5s")]
    Timeout,
}

/// Sub-path under `state-dir` for the PID file. Written by the
/// running `run` loop after attach succeeds; removed on clean exit.
/// systemd's `PIDFile=` directive references the same path so the
/// supervisor has a clean handle (also enables `Type=forking` later
/// without protocol changes).
#[cfg(all(target_os = "linux", feature = "fast-path"))]
const PIDFILE_NAME: &str = "packetframe.pid";

/// Sidecar holding the running daemon's `(pid, start_ticks, boot_id)`.
///
/// Separate from the pid file rather than folded into it: that file's
/// format is load-bearing for CLIs we do not ship with, and older ones
/// parse it whole. A reader that does not know about this file falls
/// back to what it always did.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
const IDENTITY_NAME: &str = "packetframe.identity";

/// Sub-path under `state-dir` for the reconfigure ack marker. The
/// daemon writes one line `OK <unix_ns>` after a successful SIGHUP
/// reconcile or `ERR <unix_ns> <message>` on parse / per-module
/// failure. The `packetframe reconfigure` CLI polls this file for
/// up to 5s after sending SIGHUP and exits accordingly.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
const RECONFIGURE_MARKER_NAME: &str = "last-reconfigure.timestamp";

/// Polling cadence + timeout for the CLI side of the reconfigure
/// handshake. 5s is plenty: the SIGHUP handler is synchronous and
/// finishes in ~tens of ms (mostly LPM-trie diffs).
#[cfg(target_os = "linux")]
const RECONFIGURE_POLL_INTERVAL_MS: u64 = 100;
#[cfg(target_os = "linux")]
const RECONFIGURE_TIMEOUT_MS: u64 = 5_000;

pub fn run(config_path: &Path) -> Result<(), RunError> {
    let config = Config::from_file(config_path)
        .map_err(|e| RunError::Startup(format!("config parse: {e}")))?;

    // First thing after the parse, so the level the operator asked for
    // covers the whole of startup — the feasibility gate, the attach,
    // and the route-source bring-up are where the debug lines that are
    // worth turning on actually live. A parse failure above keeps the
    // startup default, which is how its own error message got printed.
    crate::logging::apply_config_level(config.global.log_level);

    config
        .validate_interfaces()
        .map_err(|e| RunError::Startup(e.to_string()))?;
    config
        .validate_vpp_offload()
        .map_err(|e| RunError::Startup(e.to_string()))?;

    // Fail fast if metrics-textfile can't be written, the exporter
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
    // reboots, SPEC §8.3, and must be cleared by an operator.
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
    // too, if a specific iface can't receive an XDP program at all,
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

/// Whether a route feed is needed, and whether the config can support one.
///
/// Pure, so the two refusals are testable off a router — `run_linux`
/// itself needs a live bpffs and real interfaces.
///
/// `Ok(true)` = build the feed and hand it to both tiers. `Ok(false)` =
/// no vpp-offload section, nothing to wire. `Err` = a config that would
/// bring VPP up against a table nobody is filling.
#[cfg(all(target_os = "linux", feature = "fast-path", feature = "vpp-offload"))]
fn feed_wiring(names: &[&str]) -> Result<bool, String> {
    let vpp = names.iter().position(|n| *n == "vpp-offload");
    let fp = names.iter().position(|n| *n == "fast-path");
    match (vpp, fp) {
        (None, _) => Ok(false),
        (Some(_), None) => Err(
            "module vpp-offload needs a `module fast-path` section: its FIB comes from the \
             fast-path route controller, and without one VPP would come up with an empty table"
                .into(),
        ),
        // Attach order is config order, and vpp-offload's first resync
        // reads whatever the feed holds at that instant. Refused rather
        // than reordered: an operator who wrote it this way should learn
        // it from the error, not from a VPP that came up short.
        (Some(v), Some(f)) if f > v => Err(
            "module fast-path must be declared before module vpp-offload: modules attach in \
             config order, and vpp-offload's first FIB resync reads what the fast-path route \
             controller has already resolved"
                .into(),
        ),
        (Some(_), Some(_)) => Ok(true),
    }
}

#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn run_linux(config: Config, config_path: &Path) -> Result<(), RunError> {
    // The route feed, built before either module so both can be handed
    // the SAME one.
    //
    // Two objects here would be two mirrors, and the vpp-offload engine
    // would resync from a table nothing was writing to — which converges
    // cleanly, verifies cleanly, and forwards nothing.
    //
    // Order is enforced rather than assumed. vpp-offload's first resync
    // reads whatever the feed holds at that instant, so the fast-path
    // programmer has to be running first. Config order is attach order,
    // so a config listing them the other way round is refused with the
    // reason rather than quietly reordered.
    //
    // What this does NOT guarantee, and cannot: that the table is
    // *complete* when vpp-offload attaches. bird's initial dump takes
    // time, so the first convergence may cover a fraction of it and the
    // rest arrives as deltas.
    //
    // Slice 5 has landed, so `bring_up` no longer refuses `steer on` —
    // and the guards that replaced it do NOT close this. Steering is
    // reachable only from `Ready`, i.e. after a verified resync, and
    // `blocks_first_steer` withholds it while anything is unresolvable;
    // but verification samples what the LEDGER holds, so a table that is
    // merely incomplete verifies clean. A config that steers on the
    // first attach can therefore divert traffic into a partial FIB.
    //
    // The mitigation is procedural, not enforced here: the rollout's
    // staging state is every port `steer off` until the table has
    // converged, then one port at a time. That is what the runbook's
    // canary ladder is for. Closing it in code needs a completeness
    // signal the module does not have — bird's own route count, which
    // the fast-path integrity checker already fetches for a different
    // purpose.
    #[cfg(feature = "vpp-offload")]
    let feed = {
        let names: Vec<&str> = config.modules.iter().map(|m| m.name.as_str()).collect();
        match feed_wiring(&names).map_err(RunError::Startup)? {
            true => Some(std::sync::Arc::new(
                packetframe_vpp_offload::feed::RouteFeed::new(),
            )),
            false => None,
        }
    };

    // One allowlist object, not a copy per consumer. The SIGHUP path
    // republishes into it from the SAME derivation the startup path
    // uses, which is what makes "vpp-offload steers exactly what
    // fast-path allows" survive a reconfigure — see `SharedAllowlist`.
    #[cfg(feature = "vpp-offload")]
    let allowlist = std::sync::Arc::new(packetframe_vpp_offload::SharedAllowlist::new(
        crate::feasibility::allowlist_from_config(&config),
    ));

    // How complete the route mirror is, published by the fast-path's
    // integrity checker and read by vpp-offload before it diverts
    // traffic. One object, both tiers, same wiring as the feed and the
    // allowlist — and only built when BOTH modules are present, because
    // an unpublished handle is what `require-table-complete on` refuses
    // at attach rather than silently treating as permission.
    #[cfg(feature = "vpp-offload")]
    let completeness = feed
        .as_ref()
        .map(|_| std::sync::Arc::new(packetframe_common::fib::TableCompleteness::new()));

    // Whether the feed's BGP/BMP session is up right now, written by
    // the session owner inside the fast-path controller and read by
    // vpp-offload's deferred-reconciliation gate. Same wiring rule as
    // completeness: one object, both tiers, built only when both exist.
    #[cfg(feature = "vpp-offload")]
    let feed_session = feed
        .as_ref()
        .map(|_| std::sync::Arc::new(packetframe_common::fib::FeedSession::new()));

    let mut modules: Vec<(String, Box<dyn Module>)> = Vec::new();
    for section in &config.modules {
        match section.name.as_str() {
            "fast-path" => {
                #[allow(unused_mut)]
                let mut m = FastPathModule::new();
                #[cfg(feature = "vpp-offload")]
                if let Some(f) = &feed {
                    m.set_route_sink(f.clone());
                }
                #[cfg(feature = "vpp-offload")]
                if let Some(c) = &completeness {
                    m.set_completeness(c.clone());
                }
                #[cfg(feature = "vpp-offload")]
                if let Some(h) = &feed_session {
                    m.set_feed_session(h.clone());
                }
                modules.push((section.name.clone(), Box::new(m) as Box<dyn Module>));
            }
            #[cfg(feature = "vpp-offload")]
            "vpp-offload" => {
                let mut m = packetframe_vpp_offload::VppOffloadModule::new();
                // `feed` is `Some` whenever a vpp-offload section exists —
                // the match above returns before here otherwise.
                m.set_route_source(Box::new(
                    feed.clone().expect("a vpp-offload section implies a feed"),
                ));
                // Steering diverts the fast-path allowlist, so it comes
                // from that section. The loader is the only place that
                // sees both.
                m.set_allowlist(allowlist.clone());
                // The `local-route` ↔ `local-prefix` join — the kernel
                // device each mirrored neighbour set comes from. Only
                // the loader sees both sections; the module refuses to
                // attach if config promises local routes it was never
                // handed.
                match crate::feasibility::vpp_local_routes_from_config(&config) {
                    Ok(lr) => m.set_local_routes(lr),
                    Err(e) => return Err(RunError::Startup(e)),
                }
                if let Some(c) = &completeness {
                    m.set_completeness(c.clone());
                }
                if let Some(h) = &feed_session {
                    m.set_feed_session(h.clone());
                }
                modules.push((section.name.clone(), Box::new(m) as Box<dyn Module>));
            }
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

    // Index of the last module whose `attach` succeeded, so a failure
    // partway through a multi-module config can unwind.
    //
    // Without this, module N's attach failure exits startup with
    // modules 0..N still attached — and because bpffs pins deliberately
    // survive the process (§8.5), the data plane keeps forwarding with
    // no daemon while the next start refuses the orphaned pins. That is
    // exactly the crash-loop-with-frozen-FIB failure that hit
    // production twice on 2026-07-31/08-01, arriving through a
    // different door. Multi-module configs became reachable with the
    // vpp-offload module, so the unwind is no longer hypothetical.
    let mut attached: Vec<usize> = Vec::new();
    macro_rules! unwind_attached {
        ($modules:expr, $attached:expr, $failed:expr) => {
            for idx in $attached.iter().rev() {
                let (n, m): &mut (String, Box<dyn Module>) = &mut $modules[*idx];
                match m.detach() {
                    Ok(()) => tracing::warn!(
                        module = %n,
                        failed_module = %$failed,
                        "rolled back attach after a later module failed"
                    ),
                    Err(e) => tracing::error!(
                        module = %n,
                        error = %e,
                        "ROLLBACK FAILED: this module is still attached with no daemon; \
                         run `packetframe detach --all` before starting again"
                    ),
                }
            }
        };
    }

    for i in 0..modules.len() {
        let name = modules[i].0.clone();
        let section = config
            .modules
            .iter()
            .find(|m| m.name == name)
            .expect("module name resolves");
        let mcfg = ModuleConfig::new(section, &config.global);
        let module = &mut modules[i].1;
        if let Err(e) = module.load(&mcfg, &ctx) {
            unwind_attached!(modules, attached, name);
            return Err(RunError::Startup(e.to_string()));
        }
        let attachments = match module.attach(&mcfg) {
            Ok(a) => {
                attached.push(i);
                a
            }
            Err(e) => {
                unwind_attached!(modules, attached, name);
                return Err(RunError::Runtime(e.to_string()));
            }
        };
        let module = &mut modules[i].1;

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
    // Shared with the exporter so the modules' gauges reach the same
    // textfile as the BPF counters, without a second writer. Created even
    // when no textfile is configured, because the health poll publishes
    // into it unconditionally and a slot nobody reads costs one
    // allocation.
    let module_gauges: crate::metrics::ModuleGauges = Default::default();
    let metrics_exporter = config.global.metrics_textfile.as_ref().map(|path| {
        crate::metrics::MetricsExporter::start(
            path.clone(),
            config.global.bpffs_root.clone(),
            module_gauges.clone(),
        )
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

    // Write the PID file now, after attach has fully succeeded and
    // the breaker sampler is up. Doing it any earlier would expose
    // operators (and systemd's PIDFile=) to a half-attached daemon.
    // Clean-exit paths below remove it; an uncontrolled crash leaves
    // it stale, which `packetframe reconfigure` detects via the
    // /proc/<pid>/comm cross-check.
    let pid_file_path = config.global.state_dir.join(PIDFILE_NAME);
    if let Err(e) = write_pid_file(&pid_file_path) {
        tracing::warn!(
            path = %pid_file_path.display(),
            error = %e,
            "could not write PID file; `packetframe reconfigure` and `systemctl reload` will not work"
        );
    }

    // AFTER the pid file, and that order is load-bearing: a reader
    // accepts the sidecar only if it is at least as new as the pid
    // record. A rollback to a pre-sidecar daemon rewrites only the pid
    // file and cannot know to remove this one, so without the ordering
    // its stale identity would be matched to the new daemon by pid and
    // then reject it as reused (review finding).
    let identity_path = config.global.state_dir.join(IDENTITY_NAME);
    match crate::daemon_presence::DaemonIdentity::current()
        .and_then(|id| write_state_record(&identity_path, &id.encode()))
    {
        Ok(()) => {}
        // Non-fatal, but the OLD sidecar must not survive. A restart
        // handed its predecessor's pid — routine after a crash — leaves
        // a record that `read_identity` accepts by pid and whose ticks
        // then reject the live process, so `reconfigure` and current
        // health stay unavailable for that daemon's whole lifetime. The
        // comment here used to claim a failed write "falls back
        // safely"; it did not (review finding).
        Err(e) => {
            tracing::warn!(
                path = %identity_path.display(),
                error = %e,
                "could not record process identity; removing any stale one so readers fall \
                 back rather than compare against a predecessor"
            );
            if let Err(e) = remove_state_record(&identity_path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::error!(
                        path = %identity_path.display(),
                        error = %e,
                        "could not remove the stale identity either; `packetframe \
                         reconfigure` and current health will be unavailable for this \
                         daemon — remove the file by hand"
                    );
                }
            }
        }
    }
    tracing::info!("fast-path running, SIGHUP to reconfigure, SIGTERM/SIGINT to exit (§8.5)");

    let termination = drive_signal_loop(
        config_path,
        &config.global.state_dir,
        &mut modules,
        &module_gauges,
        #[cfg(feature = "vpp-offload")]
        &allowlist,
    )
    .map_err(RunError::Runtime)?;

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
            tracing::error!("circuit breaker tripped, detaching every module");
            for (name, module) in modules.iter_mut() {
                if let Err(e) = module.detach() {
                    tracing::error!(module = %name, error = %e, "detach failed");
                }
            }
            drop(modules);
        }
    }
    // The health snapshot describes a *daemon*, and this one is
    // leaving. Unlike the pins — which deliberately outlive the process
    // (§8.5) — a report kept past its writer is only misleading:
    // `packetframe status` would render the last `Healthy` from a
    // process that no longer exists. Removed here on the clean paths;
    // for a crash, `status` falls back to the recorded pid, which is the
    // check that cannot be forgotten.
    crate::health::remove(&config.global.state_dir);

    // Best-effort PID file cleanup. Non-fatal, the file is harmless
    // if left behind (PID will be unrecognized on re-validate).
    // Through the walked descriptor, like every other touch of the
    // state dir by this root process — `remove_file` follows
    // intermediate symlinks (review finding on the failed-write
    // cleanup; same rule here).
    if let Err(e) = remove_state_record(&identity_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(path = %identity_path.display(), error = %e, "could not remove identity file");
        }
    }
    if let Err(e) = remove_state_record(&pid_file_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(
                path = %pid_file_path.display(),
                error = %e,
                "could not remove PID file on exit"
            );
        }
    }
    Ok(())
}

// `create_excl_no_follow` — the pathname O_NOFOLLOW|O_EXCL primitive
// from the May 2026 audit — is gone. Every privileged write, rename,
// and unlink in a configured directory now goes through
// `walk_dir_no_follow` + the `openat`/`renameat`/`unlinkat` helpers
// below, because O_NOFOLLOW on the final component never guarded the
// intermediate ones (review finding, P1).

/// Open an ABSOLUTE directory path one component at a time, each step
/// `openat(O_DIRECTORY | O_NOFOLLOW)` relative to the descriptor of the
/// previous one, creating missing components (0755) on the way.
///
/// Why a walk and not one `open`: `O_NOFOLLOW` guards only the FINAL
/// component. The state-dir writes and the umask chmod used to resolve
/// the whole path at once, so a symlink at an intermediate component —
/// `/tmp/plant/state` with `plant` attacker-controlled — carried this
/// root process wherever the attacker pointed, and the descriptor
/// "verified" at the end belonged to a directory of their choosing
/// (review finding, P1; the reader was already refusing such paths via
/// canonicalize-equality, and the privileged writer must be at least as
/// suspicious as the reader). Every component is opened without
/// following; a symlink ANYWHERE fails with `ELOOP` and the write is
/// refused.
///
/// `..` is refused outright — a state dir has no business being
/// specified through parent traversal, and accepting it would make the
/// walk's guarantees path-dependent.
#[cfg(target_os = "linux")]
pub(crate) fn create_and_open_dir_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    walk_dir_no_follow(path, true)
}

/// The non-creating walk, for operations that have no business making
/// directories — removal in particular: if the walk cannot reach the
/// directory, there is nothing there this process is entitled to touch.
#[cfg(target_os = "linux")]
pub(crate) fn open_dir_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    walk_dir_no_follow(path, false)
}

#[cfg(target_os = "linux")]
fn walk_dir_no_follow(path: &Path, create: bool) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("state paths must be absolute: {}", path.display()),
        ));
    }
    let mut dir = std::fs::File::open("/")?;
    for comp in path.components() {
        let name = match comp {
            std::path::Component::RootDir | std::path::Component::CurDir => continue,
            std::path::Component::Normal(n) => n,
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("refusing path component {other:?} in {}", path.display()),
                ))
            }
        };
        let c = std::ffi::CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in path component")
        })?;
        let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_RDONLY | libc::O_CLOEXEC;
        let mut fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
        if create
            && fd < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
        {
            // Create it and re-open. A concurrent creator making this
            // mkdirat lose with EEXIST is fine — the reopen decides.
            unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o755) };
            fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags) };
        }
        if fd < 0 {
            let e = std::io::Error::last_os_error();
            return Err(std::io::Error::new(
                e.kind(),
                format!(
                    "open component {name:?} of {}: {e} (a symlink here is refused)",
                    path.display()
                ),
            ));
        }
        dir = unsafe { std::fs::File::from_raw_fd(fd) };
    }
    Ok(dir)
}

/// `O_CREAT|O_EXCL|O_NOFOLLOW` a file RELATIVE to an already-walked
/// directory descriptor, mode 0600 — the dirfd twin of
/// `create_excl_no_follow`, for writers that must not re-resolve the
/// directory path between verifying it and using it.
#[cfg(target_os = "linux")]
fn openat_excl_no_follow(dir: &std::fs::File, name: &str) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name"))?;
    let flags = libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_WRONLY | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Same shape but with one stale-`.tmp` retry, dirfd-relative
/// throughout. The retry runs only when the create returns
/// `AlreadyExists` and the existing entry is a regular file (a leftover
/// from a crashed run), checked with `fstatat(AT_SYMLINK_NOFOLLOW)` so
/// an attacker's symlink is not misclassified as a file. A second
/// `EEXIST` is a real race between competing writers and errors out.
#[cfg(target_os = "linux")]
pub(crate) fn openat_excl_with_retry(
    dir: &std::fs::File,
    name: &str,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::AsRawFd;
    match openat_excl_no_follow(dir, name) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let c = std::ffi::CString::new(name).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name")
            })?;
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::fstatat(
                    dir.as_raw_fd(),
                    c.as_ptr(),
                    &mut st,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if st.st_mode & libc::S_IFMT != libc::S_IFREG {
                return Err(e);
            }
            if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            openat_excl_no_follow(dir, name)
        }
        Err(e) => Err(e),
    }
}

/// Remove a state record through the same component-wise no-follow
/// walk the writers use — never by resolving the pathname whole.
///
/// `std::fs::remove_file` does not follow a symlink at the FINAL
/// component, but it follows every intermediate one, so the identity
/// cleanup on a failed write could be pointed at another instance's
/// state directory and have this root daemon delete THAT instance's
/// sidecar — disabling its identity-based status and reconfigure
/// (review finding, P1; the writes had just been converted to
/// descriptor-relative operations while this cleanup stayed
/// pathname-based). If the walk cannot reach the directory, nothing is
/// removed: a path this process refuses to write through is a path it
/// must refuse to delete through.
#[cfg(target_os = "linux")]
pub(crate) fn remove_state_record(path: &Path) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
    let dir = open_dir_no_follow(parent)?;
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name"))?;
    if unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// `renameat` within one already-walked directory descriptor.
#[cfg(target_os = "linux")]
pub(crate) fn renameat_within(dir: &std::fs::File, from: &str, to: &str) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let (f, t) = (std::ffi::CString::new(from), std::ffi::CString::new(to));
    let (f, t) = (
        f.map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in name"))?,
        t.map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in name"))?,
    );
    if unsafe { libc::renameat(dir.as_raw_fd(), f.as_ptr(), dir.as_raw_fd(), t.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Atomically write the current PID to `path`. Uses write-then-rename
/// so a half-written file is never observed; the temp file is opened
/// with `O_NOFOLLOW | O_EXCL | O_CREAT | 0600` so a pre-existing
/// symlink at `<path>.tmp` cannot redirect the write.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
/// Write a state-dir record without following a symlink.
///
/// O_EXCL|O_NOFOLLOW into a temp name, then rename. `std::fs::write`
/// would follow: `state-dir` can be a pre-existing directory an
/// unprivileged user can write, so a `packetframe.identity` symlink
/// planted before startup would have this root daemon truncate whatever
/// it pointed at (review finding, P1). The pid file has always been
/// written this way; the identity sidecar was not, until it was routed
/// through here.
fn write_state_record(path: &Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
    // EVERYTHING below happens relative to this one descriptor,
    // obtained by a component-wise no-follow walk: the directory that
    // was verified is the directory that is chmodded, written into,
    // and renamed within. Resolving the path again for any of those
    // steps would reintroduce the symlink redirections this exists to
    // refuse (review findings, two rounds of them: first the final
    // component, then the intermediate ones).
    let dir = create_and_open_dir_no_follow(parent)?;
    // The reader trusts records only in a directory nobody else can
    // write (`dir_is_authentic`): a writable directory lets `rename`
    // relocate root-owned records whole, so per-file ownership proves
    // nothing there. `create_dir_all` inherits the umask, and a 002
    // umask would create a group-writable dir whose every record then
    // reads as untrusted — `reconfigure` refused for the daemon's whole
    // lifetime. Clear exactly the group/world-write bits and leave the
    // rest alone (an operator's deliberate 0700 stays 0700). Best
    // effort: if it fails, the reader refuses, which is the safe side.
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = dir.metadata() {
            let mode = meta.permissions().mode();
            if meta.is_dir() && mode & 0o022 != 0 {
                let _ = dir.set_permissions(std::fs::Permissions::from_mode(mode & !0o022));
            }
        }
    }
    let tmp = format!("{name}.tmp");
    {
        let mut f = openat_excl_with_retry(&dir, &tmp)?;
        writeln!(f, "{body}")?;
        f.sync_all()?;
    }
    renameat_within(&dir, &tmp, name)
}

/// A BARE PID, exactly as before. The identity lives in a sidecar
/// instead, because this file has readers we do not ship with: a CLI
/// from the previous bundle parses the whole trimmed file as one
/// integer, so widening the format broke `reconfigure` for anyone
/// rolling back or running mixed versions.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn write_pid_file(path: &Path) -> std::io::Result<()> {
    write_state_record(path, &std::process::id().to_string())
}

/// Look through a module section's directives and return its
/// `CircuitBreakerSpec`, if present. Multiple directives of the same
/// kind aren't rejected by the parser, take the last one if so.
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

/// How often the loop samples `health_check` and `sample_metrics`.
///
/// Deliberately shorter than the exporter's 15 s write interval. The
/// exporter appends whatever fragment it finds, and the two run on
/// independent phases — at equal cadences a fragment could be a whole
/// write period old, so the file would routinely pair fresh BPF counters
/// with module gauges from the previous cycle. At 5 s the pairing is off
/// by at most a third of a write.
///
/// It is also the health snapshot's cadence, which sets how stale
/// `packetframe status` can be while the daemon is healthy.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
const MODULE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// How long the loop sleeps between checks for a pending signal.
///
/// The cost of not blocking on the signal fd: one wakeup per interval,
/// each a non-blocking drain plus two `Instant` comparisons. The same
/// 250 ms the metrics exporter already uses for its shutdown check, and
/// it bounds SIGTERM latency the same way.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
const SIGNAL_POLL: Duration = Duration::from_millis(250);

/// Drive the daemon's main loop: signals, plus the module health and
/// metrics cadence. Returns the termination reason the caller uses to
/// decide whether to detach or preserve pins on exit.
///
/// - SIGHUP → re-parse config + reconfigure each loaded module.
/// - SIGTERM/SIGINT → `Termination::ExitPreserveAttach` (keep pins).
/// - SIGUSR1 → `Termination::BreakerTrip` (breaker fired; caller
///   detaches). SIGUSR1 is raised by the breaker sampler thread on
///   trip.
/// - every [`MODULE_POLL_INTERVAL`] → sample the modules.
///
/// **This loop is where the module polling has to live**, and that is
/// what turned a blocking `signals.forever()` into a poll. `health_check`
/// and `sample_metrics` need the modules, the modules are owned here
/// alongside the `&mut` uses (reconfigure, detach), and sharing them with
/// the exporter thread would mean an `Arc<Mutex<_>>` that serialises a
/// metrics read against a reconfigure. Polling here keeps single
/// ownership and keeps the textfile single-writer; the cost is one
/// wakeup per [`SIGNAL_POLL`].
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn drive_signal_loop(
    config_path: &Path,
    state_dir: &Path,
    modules: &mut [(String, Box<dyn packetframe_common::module::Module>)],
    module_gauges: &crate::metrics::ModuleGauges,
    #[cfg(feature = "vpp-offload")] allowlist: &packetframe_vpp_offload::SharedAllowlist,
) -> Result<Termination, String> {
    use signal_hook::{
        consts::{SIGHUP, SIGINT, SIGTERM, SIGUSR1},
        iterator::Signals,
    };

    let mut signals = Signals::new([SIGTERM, SIGINT, SIGHUP, SIGUSR1])
        .map_err(|e| format!("signal registration: {e}"))?;

    // Sample once immediately. Waiting a full interval would leave
    // `packetframe status` reporting "no snapshot" for the first 5 s of
    // every daemon's life — which is exactly when an operator who just
    // started it is looking.
    let mut next_poll = Instant::now();

    loop {
        for sig in signals.pending() {
            match sig {
                SIGHUP => {
                    let published = reconfigure_from_signal(
                        config_path,
                        state_dir,
                        modules,
                        module_gauges,
                        #[cfg(feature = "vpp-offload")]
                        allowlist,
                    );
                    // Only when it actually published: a rejected
                    // reload refreshed nothing, and skipping the next
                    // poll on its behalf ages the health file.
                    if published == Published::Yes {
                        next_poll = Instant::now() + MODULE_POLL_INTERVAL;
                    }
                }
                SIGTERM | SIGINT => {
                    tracing::info!(signal = sig, "termination requested");
                    return Ok(Termination::ExitPreserveAttach);
                }
                SIGUSR1 => {
                    tracing::warn!("SIGUSR1 received, breaker-triggered shutdown");
                    return Ok(Termination::BreakerTrip);
                }
                _ => {}
            }
        }

        let now = Instant::now();
        if now >= next_poll {
            crate::health::poll(state_dir, modules, module_gauges);
            next_poll = now + MODULE_POLL_INTERVAL;
        }

        std::thread::sleep(SIGNAL_POLL);
    }
}

/// SIGHUP handler. Re-parses the config from `config_path` and calls
/// `Module::reconfigure` on each loaded module. Parse failures and
/// per-module reconfigure errors are logged and swallowed, a bad
/// SIGHUP never kills the running data plane. Writes an ack marker
/// to `state_dir/last-reconfigure.timestamp` for the
/// `packetframe reconfigure` CLI to poll.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn reconfigure_from_signal(
    config_path: &Path,
    state_dir: &Path,
    modules: &mut [(String, Box<dyn packetframe_common::module::Module>)],
    module_gauges: &std::sync::Mutex<String>,
    #[cfg(feature = "vpp-offload")] allowlist: &packetframe_vpp_offload::SharedAllowlist,
) -> Published {
    use packetframe_common::module::ModuleConfig;

    tracing::info!(config = %config_path.display(), "SIGHUP received; reconfiguring");

    let marker_path = state_dir.join(RECONFIGURE_MARKER_NAME);

    let new_config = match Config::from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "SIGHUP config parse failed; keeping current config");
            write_reconfigure_marker(&marker_path, &format!("ERR parse: {e}"));
            return Published::No;
        }
    };

    // The membership invariant, on THIS path as well as at startup.
    //
    // `run` validates before attaching, and that used to be the only
    // check — which left the guard enforced on the path nobody uses to
    // turn steering on, and absent from the one the rollout actually
    // follows. The canary ladder is `steer off` everywhere, then flip
    // one port and SIGHUP. Without this, that flip diverts traffic while
    // other egress ports have no `port` line, and every destination
    // whose best path leaves through one of them is blackholed: exactly
    // the failure the rule was written for, reached through the
    // documented procedure.
    //
    // A refusal here changes nothing. The daemon keeps running the
    // configuration it already had, and the operator gets the reason
    // from `packetframe reconfigure` — which is the right outcome for a
    // config that would have diverted traffic into a hole.
    if let Err(e) = new_config.validate_vpp_offload() {
        tracing::error!(error = %e, "SIGHUP config is unsafe to apply; keeping current config");
        write_reconfigure_marker(&marker_path, &format!("ERR validate: {e}"));
        return Published::No;
    }

    // After the two refusals above and before the module loop: a
    // rejected reload changes nothing, including this, and a module
    // reconcile that is about to run at debug should say so under the
    // level the operator just asked for. Hot-reloading the level is the
    // point — raising to debug to watch a canary steer, or a route
    // mirror converge, must not cost a restart of the data plane.
    crate::logging::apply_config_level(new_config.global.log_level);

    // Before the module loop, and for the WHOLE config rather than per
    // module. vpp-offload's steering target is derived from fast-path's
    // `allow-prefix` lines, which its own `ModuleConfig` does not
    // contain — so without this its `reconfigure` would re-derive the
    // steering plan from the allowlist as it was at startup, find it
    // unchanged, and report OK for a SIGHUP that changed nothing.
    #[cfg(feature = "vpp-offload")]
    allowlist.publish(crate::feasibility::allowlist_from_config(&new_config));

    let mut failures: Vec<String> = Vec::new();
    for (name, module) in modules.iter_mut() {
        let section = match new_config.modules.iter().find(|m| &m.name == name) {
            Some(s) => s,
            None => {
                tracing::warn!(
                    module = %name,
                    "module removed from config; reconfigure skipped (attach-set changes require restart)"
                );
                failures.push(format!("{name}: removed from config (restart required)"));
                continue;
            }
        };
        let mcfg = ModuleConfig::new(section, &new_config.global);
        if let Err(e) = module.reconfigure(&mcfg) {
            tracing::warn!(module = %name, error = %e, "reconfigure failed");
            failures.push(format!("{name}: {e}"));
        }
    }

    // Refresh the health file BEFORE the marker, because the marker is
    // what `packetframe reconfigure` is waiting on — so by the time it
    // returns, `packetframe status` already reflects what just changed.
    //
    // Without this the two surfaces disagreed for up to
    // MODULE_POLL_INTERVAL: on the shadow (2026-08-11) a reconfigure
    // returned OK and logged `steering UP`, `ethtool` showed the rules
    // in the NIC, and `status` still read `steer off (staging state)`
    // from a five-second-old snapshot. An operator stepping a canary
    // ladder reads `status` immediately after `reconfigure`; a rollout
    // script does it faster than a human can.
    //
    // Same shape as the service's publish-before-answer rule, one layer
    // up: publish the observation, then answer the caller.
    crate::health::poll(state_dir, modules, module_gauges);

    if failures.is_empty() {
        write_reconfigure_marker(&marker_path, "OK");
    } else {
        write_reconfigure_marker(
            &marker_path,
            &format!("ERR module: {}", failures.join("; ")),
        );
    }
    Published::Yes
}

/// Whether a reconfigure attempt refreshed the health file.
///
/// A rejected reload returns before publishing anything, so the caller
/// must NOT postpone its own poll on the strength of it — doing that
/// let a bad config arriving just before a scheduled poll age health by
/// nearly two intervals, and a config that kept failing suppress
/// polling for as long as it kept failing (review finding).
#[cfg(target_os = "linux")]
#[derive(PartialEq, Eq)]
enum Published {
    Yes,
    No,
}

/// Append a timestamp + status line to the reconfigure marker file.
/// Non-fatal on I/O error, the SIGHUP handler still completed its
/// real work; the marker is just a hint to the CLI ack-poller.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn write_reconfigure_marker(path: &Path, status: &str) {
    use std::io::Write;
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let body = format!("{} {}\n", crate::scrub::scrub_control_chars(status), now_ns);
    // Same dirfd discipline as `write_state_record`: this runs as root
    // in the daemon's SIGHUP handler, and a marker path resolved whole
    // would follow an intermediate symlink to wherever it points.
    let r = (|| -> std::io::Result<()> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
        let dir = create_and_open_dir_no_follow(parent)?;
        let tmp = format!("{name}.tmp");
        {
            let mut f = openat_excl_with_retry(&dir, &tmp)?;
            f.write_all(body.as_bytes())?;
            f.sync_all()?;
        }
        renameat_within(&dir, &tmp, name)
    })();
    if let Err(e) = r {
        tracing::warn!(error = %e, "could not write reconfigure marker");
    }
}

/// CLI entry for `packetframe reconfigure <config>`. Reads the
/// daemon's PID file from the configured `state-dir`, validates the
/// running process, sends SIGHUP, and polls the ack-marker for up to
/// 5s. See [`ReconfigureError`] for the failure axes.
#[cfg(target_os = "linux")]
pub fn reconfigure(config_path: &Path) -> Result<(), ReconfigureError> {
    let config = Config::from_file(config_path)
        .map_err(|e| ReconfigureError::Io(format!("config parse: {e}")))?;
    let state_dir = &config.global.state_dir;
    let pid_path = state_dir.join(PIDFILE_NAME);
    let marker_path = state_dir.join(RECONFIGURE_MARKER_NAME);

    // /proc/<pid>/exe cross-check defends against a stale PID file
    // pointing at a recycled PID. We previously consulted
    // /proc/<pid>/comm, but `comm` is user-settable via
    // `prctl(PR_SET_NAME)`, any local user could rename a process
    // to "packetframe" and be the target of the SIGHUP a root
    // reconfigure issues. The kernel publishes /proc/<pid>/exe as a
    // symlink to the process's executable inode and that link is not
    // user-writable; readlink-comparing it against our own
    // current_exe is a real identity check rather than a name match.
    // See the May 2026 audit Slice 4 finding.
    // The pid to signal comes FROM the check, not from a second read
    // of the same file. Reading twice let a concurrent restart swap the
    // record in between, so the check could validate the replacement
    // while the signal went to the pid the first read captured — a
    // recycled process, as root (review finding).
    let pid = match crate::daemon_presence::presence_of(
        &pid_path,
        &state_dir.join(IDENTITY_NAME),
        |p| is_daemon_process(p as libc::pid_t),
        scan_for_running_daemon,
    ) {
        crate::daemon_presence::DaemonPresence::Running { pid } => pid as libc::pid_t,
        crate::daemon_presence::DaemonPresence::Gone { why } => {
            return Err(ReconfigureError::DaemonNotRunning(format!(
                "no daemon to reconfigure: {why} (stale pidfile at {}?)",
                pid_path.display()
            )));
        }
        // A pid we cannot identify is one we must not signal. The old
        // check reported this as "not a packetframe process", which was
        // also how it read a LIVE daemon whenever this CLI ran from a
        // different path than it — so the canary lever failed during
        // exactly the upgrade it was meant to drive.
        crate::daemon_presence::DaemonPresence::Unknown { why } => {
            return Err(ReconfigureError::DaemonNotRunning(format!(
                "cannot confirm the daemon named by {} ({why}); refusing to signal it",
                pid_path.display()
            )));
        }
    };

    // Snapshot the marker mtime (or NotFound) before signaling so we
    // can detect "changed since SIGHUP."
    let pre_mtime = marker_mtime(&marker_path);

    // SIGHUP. The daemon's signal loop picks it up synchronously and
    // either reconciles or logs+writes ERR.
    let rc = unsafe { libc::kill(pid, libc::SIGHUP) };
    if rc != 0 {
        return Err(ReconfigureError::Io(format!(
            "kill -HUP {pid}: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Poll for up to 5s.
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_millis(RECONFIGURE_TIMEOUT_MS);
    let interval = std::time::Duration::from_millis(RECONFIGURE_POLL_INTERVAL_MS);
    loop {
        let now_mtime = marker_mtime(&marker_path);
        if now_mtime != pre_mtime && now_mtime.is_some() {
            // The daemon ack'd. Read the body to distinguish OK from
            // a parse-error or per-module reconcile failure.
            return match std::fs::read_to_string(&marker_path) {
                Ok(body) => parse_reconfigure_marker(&body),
                Err(e) => Err(ReconfigureError::Io(format!(
                    "read marker {}: {e}",
                    marker_path.display()
                ))),
            };
        }
        if start.elapsed() >= timeout {
            return Err(ReconfigureError::Timeout);
        }
        std::thread::sleep(interval);
    }
}

/// Non-Linux stub. The daemon can't actually run on non-Linux hosts
/// (XDP is Linux-only), so reconfigure has nothing to talk to.
#[cfg(not(target_os = "linux"))]
pub fn reconfigure(_config_path: &Path) -> Result<(), ReconfigureError> {
    Err(ReconfigureError::Io(
        "reconfigure is Linux-only, the daemon cannot run on this host".into(),
    ))
}

/// Whether `pid`'s executable could be a packetframe daemon — this
/// build's binary, or another copy of it deployed elsewhere.
///
/// Path equality alone answers "is it MY binary", which is exactly the
/// question that made every check in this module wrong during an
/// upgrade. A daemon from the previous bundle lives at a different
/// path, so an exe-path scan cannot see it, and a scan that cannot see
/// it must not be read as proving it absent.
///
/// So the basename counts too, and ONLY for finding. A false positive
/// here refuses a `detach` and names the pid, which an operator can
/// look at and resolve; a false negative unlinks pins under a live
/// daemon, which is the 2026-04-21 outage. Those are not symmetric.
///
/// This deliberately widens what the May 2026 audit narrowed, and not
/// as far back. That finding was about `comm`, settable to anything by
/// any local process via `prctl` with no file involved. Matching
/// `/proc/<pid>/exe`'s basename requires actually controlling a binary
/// named `packetframe`, exec'ing it, and carrying `run` in argv — and
/// the worst it buys is a refusal that says which pid to look at.
#[cfg(target_os = "linux")]
fn proc_exe_looks_like_a_daemon(pid: libc::pid_t) -> bool {
    if proc_exe_matches_current(pid) {
        return true;
    }
    let Ok(target) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    let Ok(current) = std::env::current_exe() else {
        return false;
    };
    // The kernel appends ` (deleted)` once the inode is unlinked, which
    // is the state an upgraded-in-place daemon is in.
    let target = target.to_string_lossy();
    let target = target.strip_suffix(" (deleted)").unwrap_or(&target);
    // Equal names, or a versioned sibling: `packetframe-v2` alongside
    // `packetframe-v1` is a real packaging shape, and the identity path
    // says elsewhere that a renamed binary is legitimate — so a scan
    // that demanded exact equality contradicted it, and missed the
    // daemon it exists to find (review finding).
    //
    // The residual limit, stated rather than papered over: a daemon
    // deployed under a name sharing no prefix with ours is NOT found
    // here. Nothing short of trusting argv could find it, and argv is
    // what the May 2026 audit rejected — any local process could then
    // block `detach` at will. The pid record is what covers that case;
    // this scan is the backstop for when there is none.
    match (Path::new(target).file_name(), current.as_path().file_name()) {
        (Some(a), Some(b)) => {
            let (a, b) = (a.to_string_lossy(), b.to_string_lossy());
            a == b || (a.starts_with("packetframe") && b.starts_with("packetframe"))
        }
        _ => false,
    }
}

/// Whether `pid` is a packetframe DAEMON: our binary (or another copy
/// of it), running the `run` subcommand.
///
/// One predicate, because the scan and the record path must ask the
/// same question. They did not: the scan filtered argv for `run`, while
/// the legacy record path took a bare executable match — so a stale
/// pid-only file whose pid had been reused by a long `packetframe
/// probe` from another bundle read as `Running`, and `reconfigure`
/// SIGHUPed the probe (review finding).
///
/// Reading argv is sound only after the executable check: a spoofed
/// `run` on its own proves nothing, which is why `comm` was rejected
/// for this to begin with.
#[cfg(target_os = "linux")]
fn is_daemon_process(pid: libc::pid_t) -> bool {
    daemon_process_verdict(pid) == Some(true)
}

/// The same question, keeping "could not tell" apart from "no".
///
/// `None` means a read failed for a reason other than the process
/// having exited: the answer is unavailable, not negative. The scan
/// needs that distinction because its negative is what licenses a
/// destructive `detach`; `is_daemon_process` does not, because there
/// an unavailable answer already falls through to `Unknown`.
#[cfg(target_os = "linux")]
fn daemon_process_verdict(pid: libc::pid_t) -> Option<bool> {
    // Not knowing our OWN path makes every comparison below vacuous, so
    // it is unavailability rather than a mismatch — for every pid at
    // once, which is why the scan cannot conclude anything at all.
    std::env::current_exe().ok()?;
    if !proc_exe_looks_like_a_daemon(pid) {
        // Distinguish "the exe link says it is something else" from
        // "the exe link could not be read at all". A process that has
        // exited takes its whole `/proc` entry with it and is a plain
        // no; anything else (EACCES on a hardened kernel, EPERM under
        // a non-root caller) is unreadable.
        return match std::fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(_) => Some(false),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
            Err(_) => None,
        };
    }
    // BYTES: `read_to_string` rejects the whole cmdline if any argument
    // is not UTF-8, and a `--config` path may legally contain arbitrary
    // bytes.
    // The SUBCOMMAND SLOT, not anywhere in argv. `any` matched a probe
    // run as `packetframe probe --iface run ...` on an interface named
    // `run` — which then reads as a daemon, takes SIGHUP from
    // `reconfigure`, and blocks `detach` (review finding). `struct Cli`
    // carries nothing but the subcommand, so clap accepts no global
    // options before it and argv[1] is where `run` must be.
    match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(cmdline) => Some(cmdline.split(|b| *b == 0).nth(1) == Some(b"run".as_slice())),
        // Gone between the two reads: not a daemon, and not a mystery.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(false),
        // It runs our binary and its argv cannot be read. The only
        // question left is the only one unanswerable, so this is not a
        // process the scan may report as harmless.
        Err(_) => None,
    }
}

/// Search the process table for a running daemon.
///
/// This was `daemon_pid`, and its answer was read as "no daemon is
/// running" whenever it came back empty — which is false for any daemon
/// started from a different path, i.e. during every upgrade, and is how
/// `detach` walked past its own guard. Its positive is still sound and
/// still useful: a process running this binary IS a daemon worth
/// refusing to detach under, even when no pid file names it (a failed
/// record write leaves exactly that).
///
/// So it reports THREE answers rather than an `Option`. `NoneFound`
/// still is not proof of absence — a differently named daemon is
/// invisible to `proc_exe_looks_like_a_daemon` — but it does assert
/// that the table was walked and every process in it examined, which
/// is the part `Option::None` was silently standing in for.
///
/// `/proc/<pid>/exe` rather than `comm`, which is user-settable via
/// `prctl` — the May 2026 audit Slice 4 finding.
#[cfg(target_os = "linux")]
fn scan_for_running_daemon() -> crate::daemon_presence::Scan {
    use crate::daemon_presence::Scan;
    let self_pid = std::process::id();
    let dir = match std::fs::read_dir("/proc") {
        Ok(dir) => dir,
        Err(e) => return Scan::Inconclusive(format!("/proc could not be listed: {e}")),
    };
    // Counted, never skipped. Each is a process the scan cannot vouch
    // for, and this scan's NEGATIVE is what licenses `detach` to unlink
    // pins — so an unexaminable process has to reach the caller rather
    // than quietly leave the total looking complete.
    let mut unexamined = 0usize;
    for entry in dir {
        let Ok(entry) = entry else {
            unexamined += 1;
            continue;
        };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == self_pid {
            continue;
        }
        match daemon_process_verdict(pid as libc::pid_t) {
            Some(true) => return Scan::Found(pid as i32),
            Some(false) => {}
            None => unexamined += 1,
        }
    }
    if unexamined > 0 {
        return Scan::Inconclusive(format!(
            "{unexamined} process(es) in /proc could not be examined"
        ));
    }
    Scan::NoneFound
}

/// Read /proc/<pid>/exe as a symlink and compare against the
/// canonicalized path of the currently running `packetframe`
/// executable. The kernel sets /proc/<pid>/exe to point at the
/// process's executable inode; the link is not writable from
/// userspace, which makes this a real identity check (unlike
/// /proc/<pid>/comm which any local user can spoof via
/// `prctl(PR_SET_NAME)`).
///
/// Handles the `(deleted)` suffix the kernel appends when the
/// executable file has been unlinked after the process started
/// (rolling upgrade), we accept the match if the prefix agrees.
///
/// Returns false on any I/O error or mismatch, the caller treats
/// that as "PID is not our process."
#[cfg(target_os = "linux")]
fn proc_exe_matches_current(pid: libc::pid_t) -> bool {
    let Ok(target) = std::fs::read_link(format!("/proc/{pid}/exe")) else {
        return false;
    };
    let Ok(current) = std::env::current_exe() else {
        return false;
    };
    let current = current.canonicalize().unwrap_or(current);
    // Strip a trailing ` (deleted)` from the target, the kernel
    // appends that when the inode has been unlinked since exec, e.g.
    // during a `cargo install --force` upgrade.
    let target_str = target.to_string_lossy();
    let target_clean = target_str.strip_suffix(" (deleted)").unwrap_or(&target_str);
    Path::new(target_clean) == current.as_path()
}

/// Modified time of the marker file, in (secs, nanos). `None` if the
/// file doesn't exist, used to detect "freshly written since
/// SIGHUP." Any non-NotFound error is treated as "no observation,"
/// which causes the poller to keep waiting until timeout.
#[cfg(target_os = "linux")]
fn marker_mtime(path: &Path) -> Option<(i64, u32)> {
    let meta = std::fs::metadata(path).ok()?;
    let m = meta.modified().ok()?;
    let dur = m.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some((dur.as_secs() as i64, dur.subsec_nanos()))
}

/// Parse the marker body, `OK <ns>` or `ERR <category>: <message>`.
#[cfg(target_os = "linux")]
fn parse_reconfigure_marker(body: &str) -> Result<(), ReconfigureError> {
    let trimmed = body.trim();
    if let Some(rest) = trimmed.strip_prefix("OK ") {
        // Rest is just the timestamp; we don't use it.
        let _ = rest;
        Ok(())
    } else if let Some(rest) = trimmed.strip_prefix("ERR ") {
        // Drop the trailing nanosecond stamp the writer appends. Without
        // this every rejection an operator reads ends in a 19-digit
        // number glued to the last word of the sentence, which reads as
        // part of the diagnostic — observed on the first real reconfigure
        // refusal. Only stripped when the tail actually is a number, so a
        // truncated or hand-edited marker still shows what it holds.
        let message = match rest.rsplit_once(' ') {
            Some((head, tail)) if !head.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => {
                head
            }
            _ => rest,
        };
        Err(ReconfigureError::DaemonRejected(message.to_string()))
    } else {
        // Marker exists but doesn't match the expected format.
        Err(ReconfigureError::Io(format!(
            "unexpected marker content: {trimmed}"
        )))
    }
}

pub fn detach(config: Option<&Path>, all: bool) -> Result<(), String> {
    // Refuse to detach while a `packetframe run` daemon is live. The
    // daemon holds PinnedLink FDs in-process; unlinking the bpffs pin
    // paths alone doesn't drop the kernel-side bpf_link refcount, so
    // the XDP program stays attached even after `detach` claims
    // success. The operator needs to SIGTERM/kill the daemon first.
    // Confirmed outage-adjacent on the reference EFG 2026-04-21, the
    // detach ran, reported clean, but `ip link show` still had
    // `xdpgeneric` attached.
    // `config_has_vpp` decides whether a SCOPED detach may touch VPP.
    //
    // `--all` means "tear down modules beyond those in the supplied config",
    // so `detach --config fast-path-only.conf` must leave the VPP dataplane
    // alone — the first version of this teardown ran unconditionally and
    // would have terminated a VPP the operator never asked about, purely
    // because it shares the state dir.
    let (bpffs_root, state_dir, settle_time, config_has_vpp) = match config {
        Some(p) => {
            let c = Config::from_file(p).map_err(|e| format!("config parse: {e}"))?;
            let has_vpp = c.modules.iter().any(|m| m.name == "vpp-offload");
            (
                c.global.bpffs_root,
                c.global.state_dir,
                c.global.attach_settle_time,
                has_vpp,
            )
        }
        // No config at all: nothing scopes the request, so only `--all`
        // authorises reaching past fast-path.
        None => (
            PathBuf::from(packetframe_common::config::DEFAULT_BPFFS_ROOT),
            PathBuf::from(packetframe_common::config::DEFAULT_STATE_DIR),
            packetframe_common::config::DEFAULT_ATTACH_SETTLE_TIME,
            false,
        ),
    };

    // Positive evidence of ABSENCE, not merely failure to find a
    // match. `daemon_pid()` answered by scanning /proc for a process
    // running this CLI's own executable path, so a detach run from a
    // freshly deployed bundle — the shape every upgrade has — found
    // nothing and proceeded straight past this guard, under a live
    // daemon. That is the outage this refusal exists to prevent, and
    // it was reachable exactly when someone was upgrading.
    #[cfg(target_os = "linux")]
    let presence = crate::daemon_presence::presence_of(
        &state_dir.join(PIDFILE_NAME),
        &state_dir.join(IDENTITY_NAME),
        |p| is_daemon_process(p as libc::pid_t),
        scan_for_running_daemon,
    );
    #[cfg(not(target_os = "linux"))]
    let presence = crate::daemon_presence::DaemonPresence::Gone {
        why: "no /proc on this platform; nothing could be attached".into(),
    };
    match presence {
        crate::daemon_presence::DaemonPresence::Gone { .. } => {}
        crate::daemon_presence::DaemonPresence::Running { pid } => {
            return Err(format!(
                "a `packetframe run` daemon is still running (pid {pid}); \
                 stop it first (e.g. `kill {pid}`) before detaching. \
                 Detach unlinks bpffs pins, but the kernel-side bpf_link \
                 holds refs through the daemon's open FDs, both have to \
                 be released for the iface to actually detach."
            ));
        }
        crate::daemon_presence::DaemonPresence::Unknown { why } => {
            return Err(format!(
                "cannot confirm no `packetframe run` daemon is running ({why}); refusing to \
                 detach. Unlinking pins under a live daemon leaves the program attached \
                 through its open FDs while reporting success. Stop the daemon, or remove \
                 a stale pid file if you have established there is none."
            ));
        }
    }

    // `--all` used to be a no-op with a comment saying it would "become
    // meaningful once a second module ships". A second module has now
    // shipped, and the comment outlived its truth: every message this
    // codebase prints about held VFs — from the module, from `bring_up`'s
    // rollback, from the supervision service's timeout and panic paths —
    // tells the operator to run `packetframe detach --all`, and that command
    // touched nothing but fast-path pins. The recovery path advertised
    // everywhere did not exist.
    //
    // Every module is attempted and the failures are aggregated, rather than
    // the first `?` ending the run. These teardowns are independent, and this
    // command IS the recovery path: a corrupt fast-path registry must not be
    // the reason a supervised VPP keeps holding its VF and hugepages.
    // `mut` is unused in the build with neither module feature enabled —
    // nothing can push. Not a CI configuration (clippy runs
    // `--all-features`), but a warning is a warning.
    #[cfg_attr(
        not(any(feature = "fast-path", feature = "vpp-offload")),
        allow(unused_mut)
    )]
    let mut errors: Vec<String> = Vec::new();

    #[cfg(feature = "fast-path")]
    if let Err(e) = detach_fast_path(&bpffs_root, &state_dir, settle_time) {
        errors.push(e);
    }

    #[cfg(feature = "vpp-offload")]
    if all || config_has_vpp {
        if let Err(e) = detach_vpp_offload(&state_dir) {
            errors.push(e);
        }
    } else {
        tracing::info!(
            "vpp-offload state left alone: this detach is scoped to the supplied config; \
             use `--all` to tear down modules it does not declare"
        );
    }
    #[cfg(not(feature = "vpp-offload"))]
    let _ = (all, config_has_vpp);

    if !errors.is_empty() {
        return Err(errors.join("; AND "));
    }
    Ok(())
}

/// The fast-path half of `detach`, unchanged except for being callable.
///
/// Split out so its `?`s abort only its own teardown: as one inline block its
/// first error returned from `detach` entirely, which meant an unrelated
/// module's failure could strand VPP's VFs.
#[cfg(feature = "fast-path")]
fn detach_fast_path(
    bpffs_root: &Path,
    state_dir: &Path,
    settle_time: std::time::Duration,
) -> Result<(), String> {
    {
        use packetframe_fast_path::registry::load as registry_load;
        match registry_load(state_dir) {
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
                tracing::info!("no pin registry found, sweeping bpffs pin root anyway");
            }
            Err(e) => return Err(format!("registry read: {e}")),
        }

        // Unlink every pin under `<bpffs-root>/fast-path/`. Removing
        // link pins triggers the kernel-side XDP detach (§8.5). Pace
        // by `attach_settle_time` so bridge-member detaches don't
        // pile up inside one STP reconvergence window, that's the
        // post-rc5 fix for the EFG kernel-panic-on-detach observed
        // during Phase 4 cutover testing. Map + program pins are
        // housekeeping with no kernel-link side effects, no pacing.
        packetframe_fast_path::pin::remove_all_paced(bpffs_root, settle_time)
            .map_err(|e| format!("remove pins under {}: {e}", bpffs_root.display()))?;
        tracing::info!(
            pin_root = %packetframe_fast_path::pin::module_root(bpffs_root).display(),
            settle_secs = settle_time.as_secs_f64(),
            "pins removed; kernel detached"
        );

        // tc-datapath filters (Phase T) have qdisc lifetime rather
        // than bpffs pins; tear them down from their own persistence
        // record. No-op when tc-links.json doesn't exist.
        #[cfg(target_os = "linux")]
        {
            let n = packetframe_fast_path::tc_detach_from_state_dir(state_dir)
                .map_err(|e| format!("tc filter teardown: {e}"))?;
            if n > 0 {
                tracing::info!(count = n, "tc filters detached");
            }
        }

        packetframe_fast_path::registry::remove(state_dir)
            .map_err(|e| format!("registry remove: {e}"))?;
    }

    Ok(())
}

/// Release what vpp-offload's state file records: the supervised VPP, its
/// VFs and vfio bindings, and the hugepage reservation.
///
/// This is the standalone recovery path, and it has to exist separately from
/// `Module::detach` because the two run at different times. `Module::detach`
/// needs a live daemon holding the supervision handle; but the daemon's
/// ordinary SIGTERM exit deliberately PRESERVES VPP for adoption (SPEC.md
/// §8.5), and `packetframe detach` refuses to run while a daemon is alive.
/// So by the time an operator can invoke this, the in-memory handle is gone
/// and the state file is the only record of what is held.
///
/// **Ordering is the same discipline the module's teardown uses, for the same
/// reason.** VPP is killed first and resources are released only if it is
/// confirmed gone: unbinding a VF or handing back hugepages while a process
/// can still DMA through them is memory corruption, whereas leaking a VF is a
/// line in `packetframe status` and a reboot's worth of inconvenience.
/// **Steering comes down first**, before the kill, or traffic is left pointed
/// at a VF nothing services.
#[cfg(feature = "vpp-offload")]
fn detach_vpp_offload(state_dir: &Path) -> Result<(), String> {
    use packetframe_vpp_offload::acquire::{release, SysPaths};
    use packetframe_vpp_offload::ntuple::NtupleSteering;
    use packetframe_vpp_offload::process::{terminate_or_leak, Disposition, VppProcess};
    use packetframe_vpp_offload::resources::{
        flatten_steer_rules, group_steer_rules, ResourceState,
    };
    use packetframe_vpp_offload::runtime::{Steering as _, TERM_GRACE};
    use packetframe_vpp_offload::steer::RuleSet;

    let Some(state) = ResourceState::load(state_dir).map_err(|e| format!("vpp state: {e}"))? else {
        return Ok(()); // nothing was ever acquired
    };

    // Recorded MCAM rules mean traffic is DIVERTED to a VF this function is
    // about to unbind, so they come down FIRST.
    //
    // The module's teardown ordering is unsteer → abort → kill → release, and
    // the first step is not decoration: releasing a VF that MCAM still points
    // at leaves steered traffic arriving at a function nothing services — a
    // blackhole, which is the failure the whole `Disposition::MustLeak`
    // discipline exists to avoid, reached from the other direction.
    //
    // This used to be a REFUSAL, guarding a state that could not yet occur:
    // nothing wrote `steer_rules`, so it was always empty. It is live now,
    // and a refusal would be the wrong answer — `packetframe detach --all` is
    // the remedy every error in this subsystem points an operator at, and
    // refusing it whenever a steered VPP had been running would strand the
    // box with no way forward. It can do the removal, so it does.
    //
    // Through `NtupleSteering` rather than a delete loop here, so this shares
    // the module's removal routine — including the half that matters, that a
    // rule the NIC will not delete stays on the record. A second
    // implementation of "take steering down" is exactly the asymmetry that
    // produced the release-a-steered-VF bug twice already.
    if !state.steer_rules.is_empty() {
        let recorded = flatten_steer_rules(&state.steer_rules);
        // The acquired ports are handed over even though there is no
        // target to steer, because removal needs them: `remove_all`
        // reads each location back and deletes only what steers into the
        // VF this module owns, and with no port list it cannot tell — it
        // would fall back to deleting by location, which is how a
        // teardown removes somebody else's classifier rule and breaks
        // its traffic. They go in as MEMBERS, not as a steering target:
        // this path installs nothing, and the record is the only thing
        // that says what to remove.
        //
        // VF 0 for the same reason `bring_up` uses it: `acquire` creates
        // exactly one per PF and reads it back through `virtfn0`.
        let members: Vec<(String, u32)> = state
            .ports
            .iter()
            .map(|p| (p.iface.clone(), 0u32))
            .collect();
        let mut steering = NtupleSteering::new(members, Vec::new(), RuleSet::default());
        steering.adopt_installed(recorded);
        if let Err(e) = steering.unsteer() {
            // Write back what is STILL in the NIC before refusing. The rules
            // that came out must not be retried by the operator's next
            // attempt, and the ones that did not have to stay findable —
            // this file is the only record of them.
            let mut state = state;
            state.steer_rules = group_steer_rules(&steering.installed());
            let _ = state.save(state_dir);
            return Err(format!(
                "vpp-offload: {e}. The VF(s) were NOT unbound, because MCAM is still \
                 diverting traffic to them — unbinding now would blackhole it. The state \
                 file records exactly which rules remain; remove them by hand \
                 (`ethtool -N <iface> delete <loc>`) and re-run."
            ));
        }
        tracing::info!("vpp-offload: MCAM steering rules removed");
    }

    // Kill the recorded VPP first, if it is still the process we recorded.
    //
    // The identity must be COMPLETE — pid, start_ticks AND boot_id — before
    // either action is safe, and that is the whole of this block's caution.
    // `VppProcess::adopt` returns `Ok(None)` for two very different reasons:
    // the process is genuinely gone, or the identity could not be verified
    // and it refused to guess. Reading the second as the first is what makes
    // it dangerous — this code passed `boot_id: None` straight through and
    // then treated the refusal as "gone", releasing the VF under a VPP that
    // may well have still been running. `process.rs` has a test named
    // `adoption_without_a_recorded_boot_id_is_refused` whose doc says exactly
    // that a boot-id-less record "cannot establish identity at all, and must
    // be refused rather than trusted".
    //
    // With a complete identity, `Ok(None)` really does mean gone: the pid is
    // dead, or its start time or boot id no longer match, and in every one of
    // those cases the process we recorded does not exist.
    if let Some(pid) = state.vpp_pid {
        let (Some(ticks), Some(boot)) = (state.vpp_start_ticks, state.vpp_boot_id.clone()) else {
            let missing = match (state.vpp_start_ticks, &state.vpp_boot_id) {
                (None, None) => "start-time cookie and boot id",
                (None, Some(_)) => "start-time cookie",
                _ => "boot id",
            };
            return Err(format!(
                "vpp-offload: the state file records pid {pid} with no {missing}, so that \
                 process can neither be identified nor ruled out. It must not be signalled \
                 (that risks SIGKILLing an unrelated process as root) and its VF and \
                 hugepages must not be released (that risks unbinding under a live VPP). \
                 Confirm by hand that no VPP is running, then remove the state file."
            ));
        };
        match VppProcess::adopt(pid, ticks, Some(&boot)) {
            Ok(Some(mut p)) => {
                tracing::info!(pid, "vpp-offload: terminating the recorded VPP");
                if terminate_or_leak(&mut p, TERM_GRACE) == Disposition::MustLeak {
                    // Refuse to release. The process survived SIGKILL — most
                    // likely parked in an uninterruptible VFIO/DMA call — and
                    // the state file stays intact so a later attempt can
                    // finish the job.
                    return Err(format!(
                        "vpp-offload: VPP (pid {pid}) survived SIGKILL, so its VF and \
                         hugepages were deliberately NOT released — releasing them under a \
                         process that can still DMA through them is worse than leaking \
                         them. The state file still records everything; retry once \
                         `ps {pid}` is empty."
                    ));
                }
            }
            // Verified against a complete identity, so this is genuinely gone.
            Ok(None) => tracing::info!(
                pid,
                "vpp-offload: the recorded VPP is gone; releasing its resources"
            ),
            Err(e) => {
                return Err(format!(
                    "vpp-offload: could not establish whether the recorded VPP (pid {pid}) \
                     is still running ({e}); refusing to release its VF and hugepages while \
                     that is unknown"
                ))
            }
        }
    }

    // Point release at the pool the state file RECORDS, not the pool that
    // happens to be the default now.
    //
    // `release` deliberately refuses a pool mismatch — freeing the wrong
    // pool while leaking the real reservation is worse than failing — so
    // using the current default meant that if the kernel's default page size
    // changed between attach and detach (a reboot between the fleet's 512 MiB
    // and 2 MiB defaults does it), release would free the VFs, refuse the
    // pool, keep the reservation in state, and then recompute the same wrong
    // default on every retry. The advertised recovery command could never
    // restore that pool. A recorded `0` means attach owned no reservation, so
    // there is nothing to match and the current default is fine.
    let pool_bytes = if state.hugepage_pool_bytes != 0 {
        state.hugepage_pool_bytes
    } else {
        packetframe_vpp_offload::default_hugepage_bytes()
    };
    let paths = SysPaths::live(state_dir, pool_bytes);
    release(&paths, state).map_err(|e| format!("vpp-offload: {e}"))?;
    tracing::info!("vpp-offload: VFs rebound and hugepages restored");
    Ok(())
}

pub fn status(config_path: &Path) -> Result<(), String> {
    let config = Config::from_file(config_path).map_err(|e| format!("config parse: {e}"))?;

    #[cfg(feature = "fast-path")]
    {
        use packetframe_fast_path::registry::load as registry_load;
        match registry_load(&config.global.state_dir) {
            Ok(Some(file)) => {
                println!("module: {}", scrub_for_terminal(&file.module));
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

        // v0.2.5+ tail-call chain summary. Confirms MUTATION_PROGS[0]
        // is populated with the `finalize` program FD; if empty,
        // fast_path's tail_call hits ErrTailCall and traffic falls
        // through to kernel slow-path. Operators see this immediately
        // in the status output rather than chasing it via err counter.
        #[cfg(target_os = "linux")]
        print_tail_call_chain(&config.global.bpffs_root);

        // Live counter readback from the pinned STATS map. Works
        // whether or not the loader is running, the pin survives
        // process exit (§8.5).
        #[cfg(target_os = "linux")]
        print_stats(&config.global.bpffs_root);

        print_module_health(&config.global.state_dir);
    }

    Ok(())
}

/// Whether the snapshot's own publisher is the process running now.
///
/// `false` when the snapshot recorded no identity: that is "cannot
/// confirm", and for a report that will be read as current it is the
/// same class of claim this module exists to stop making.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn snapshot_matches_live(snapshot: &crate::health::Snapshot) -> bool {
    let (Some(ticks), Some(boot)) = (snapshot.start_ticks, snapshot.boot_id.as_deref()) else {
        return false;
    };
    // ALIVE first. An unreaped exit keeps its start ticks, so matching
    // them proves the publisher is the process that once held that pid
    // — not that it can still publish. The zombie rule lives in
    // `presence_of`, and the snapshot fallback added later did not go
    // through it, so a crashed daemon whose pid record had also become
    // unreadable read as "confirmed current" (review finding).
    //
    // Checked HERE rather than at that call site, so the next caller
    // inherits it instead of having to remember.
    match crate::daemon_presence::proc_state(snapshot.pid) {
        Ok(state) if crate::daemon_presence::state_is_alive(state) => {}
        _ => return false,
    }
    matches!(
        (
            crate::daemon_presence::start_ticks(snapshot.pid),
            crate::daemon_presence::boot_id()
        ),
        (Ok(t), Ok(b)) if t == ticks && b == boot
    )
}

/// No `/proc` to compare against, so the publisher cannot be matched —
/// which reads as "cannot confirm", the same as an unidentified
/// snapshot on Linux.
#[cfg(all(not(target_os = "linux"), feature = "fast-path"))]
fn snapshot_matches_live(_snapshot: &crate::health::Snapshot) -> bool {
    false
}

/// Render the daemon's last published module health.
///
/// Everything else `status` prints is read from the kernel or from a pin
/// and is therefore *current by construction*. This is not: it is a file
/// a daemon wrote, and the daemon may be gone. So the liveness question
/// is answered first and separately — from the recorded pid, the same
/// cross-check `reconfigure` uses — and the age second. A report is only
/// presented as current when the process that wrote it still exists.
#[cfg(feature = "fast-path")]
fn print_module_health(state_dir: &Path) {
    use packetframe_common::module::HealthState;

    let snapshot = match crate::health::load(state_dir) {
        Ok(Some(s)) => s,
        Ok(None) => {
            println!();
            println!(
                "module health: no snapshot at {} — no daemon has published one (module \
                 health needs a running `packetframe run`; the counters above do not)",
                crate::health::Snapshot::path_in(state_dir).display()
            );
            return;
        }
        Err(e) => {
            // Scrubbed too: this carries a serde parse error, which can
            // quote bytes from the snapshot file. Ours to write, but a
            // corrupt or hand-edited one is exactly when this branch runs.
            eprintln!(
                "note: module health unavailable ({})",
                scrub_for_terminal(&e)
            );
            return;
        }
    };

    println!();
    // Liveness BEFORE the contents. An operator who reads "Healthy" and
    // only then learns the daemon is dead has already drawn the
    // conclusion, and it was the wrong one.
    #[cfg(target_os = "linux")]
    let presence = crate::daemon_presence::presence_of(
        &state_dir.join(PIDFILE_NAME),
        &state_dir.join(IDENTITY_NAME),
        |p| is_daemon_process(p as libc::pid_t),
        scan_for_running_daemon,
    );
    // No /proc to cross-check against, so liveness is unknown rather
    // than assumed either way.
    #[cfg(not(target_os = "linux"))]
    let presence = crate::daemon_presence::DaemonPresence::Unknown {
        why: "no /proc on this platform".into(),
    };

    let age = match crate::health::age_seconds(&snapshot) {
        Some(a) => format!("{a}s old"),
        // The clock moved backwards since the write; saying so beats
        // printing a flattering number derived from it.
        None => "written in the future (clock skew)".to_string(),
    };

    match &presence {
        // Running AND the same process that wrote this. A crash whose
        // replacement records its own pid before publishing health
        // leaves the old report on disk under a new pid file: validating
        // the file alone presented history as current, and labelled it
        // with the replacement's pid (review finding).
        crate::daemon_presence::DaemonPresence::Running { pid }
            if *pid == snapshot.pid && snapshot_matches_live(&snapshot) =>
        {
            println!("module health (pid {pid}, {age}):")
        }
        // A LIVE daemon whose snapshot predates identity recording —
        // an older build, still publishing. Its report is almost
        // certainly current, and calling it history was this PR's own
        // motivating bug in a new shape: a new CLI declaring a running
        // old daemon dead (review finding). Cannot confirm is the
        // honest answer, and the one that does not mislead in either
        // direction.
        crate::daemon_presence::DaemonPresence::Running { pid }
            if *pid == snapshot.pid
                && (snapshot.start_ticks.is_none() || snapshot.boot_id.is_none()) =>
        {
            println!(
                "module health (pid {pid}, {age}) — CANNOT CONFIRM this is the report of \
                 the daemon running now: it recorded no identity, which an older build \
                 does not. Restarting on this build makes it checkable."
            )
        }
        // Same pid is not the same process. A replacement handed the
        // pid its predecessor had — routine across a reboot — made the
        // pre-crash report read as live until the replacement published
        // its own (review finding). The identity settles it, and where
        // the snapshot predates identity recording it says so rather
        // than guessing either way.
        crate::daemon_presence::DaemonPresence::Running { pid } => println!(
            "module health: STALE — this report was written by pid {}, and the daemon \
             running now is pid {pid} (a different process, by its recorded identity). \
             The report below is history, {age}.",
            snapshot.pid
        ),
        // The record could not answer — or answered WRONG — but the
        // SNAPSHOT can: it carries the publisher's own identity, and a
        // match against the live process proves that exact process is
        // running. This override reaches `Gone` as well as `Unknown`,
        // and has to: a daemon whose non-fatal record writes BOTH
        // failed, running under a name the scan's prefix check does not
        // admit, resolves to `Gone` — and printing STALE over its
        // freshly published report is this PR's motivating bug again,
        // surviving in the one arm the override skipped (review
        // finding; the first version guarded only `Unknown`). Saying
        // "gone" over a live daemon is what happened on the shadow,
        // 2026-08-12.
        //
        // Safe for `status` precisely because status ACTS on nothing:
        // matching identity is the strongest evidence there is, and it
        // is only being used to label a report. `detach` and
        // `reconfigure` do not read snapshots and keep their verdicts.
        // Two arms rather than one, because the operator guidance
        // differs and a single message would promise `detach` behaviour
        // one of the two paths does not deliver (the #157 class):
        // `detach` refuses on `Unknown` but proceeds on `Gone` — the
        // documented residual — so the `Gone` text must warn, not
        // reassure.
        crate::daemon_presence::DaemonPresence::Gone { .. } if snapshot_matches_live(&snapshot) => {
            println!(
                "module health (pid {}, {age}) — confirmed by the report's own recorded \
                 identity. WARNING: every record-based check reads this daemon as absent \
                 (no pid file, no identity sidecar, and the process-table scan cannot see \
                 it), so `packetframe detach` would proceed under it. Stop the daemon \
                 before detaching.",
                snapshot.pid
            )
        }
        crate::daemon_presence::DaemonPresence::Unknown { .. }
            if snapshot_matches_live(&snapshot) =>
        {
            println!(
                "module health (pid {}, {age}) — confirmed by the report's own recorded \
                 identity; the pid record is missing or stale, which `packetframe detach` \
                 will refuse on until it is resolved.",
                snapshot.pid
            )
        }
        crate::daemon_presence::DaemonPresence::Gone { why } => println!(
            "module health: STALE — the daemon that wrote this (pid {}) is gone ({why}). The \
             report below is history, {age}; the dataplane may still be forwarding via its \
             pins (§8.5).",
            snapshot.pid
        ),
        crate::daemon_presence::DaemonPresence::Unknown { why } => println!(
            "module health (pid {}, {age}) — CANNOT CONFIRM the daemon is still running \
             ({why}). Read the report as possibly historical until it can be checked.",
            snapshot.pid
        ),
    }

    for m in &snapshot.modules {
        match (&m.report, &m.error) {
            // A check that could not run is not a verdict about the
            // module, and must not be rendered as one.
            (_, Some(e)) => println!(
                "  {}: health check FAILED — {}",
                scrub_for_terminal(&m.module),
                scrub_for_terminal(e)
            ),
            (Some(r), None) => {
                println!(
                    "  {}: {}",
                    scrub_for_terminal(&m.module),
                    health_word(r.overall)
                );
                for sub in &r.subsystems {
                    let age = match sub.last_success_age_seconds {
                        Some(a) => format!(" (last ok {a}s ago)"),
                        None => String::new(),
                    };
                    let msg = sub
                        .message
                        .as_deref()
                        .map(scrub_for_terminal)
                        .unwrap_or_default();
                    let sep = if msg.is_empty() { "" } else { " — " };
                    println!(
                        "    {:<14} {}{sep}{msg}{age}",
                        scrub_for_terminal(&sub.name),
                        health_word(sub.state)
                    );
                }
            }
            // Neither a report nor a reason. Unreachable from
            // `health::poll`, which always sets exactly one, so it means
            // the file was written by something else or hand-edited.
            (None, None) => println!(
                "  {}: no report and no error recorded (malformed snapshot)",
                scrub_for_terminal(&m.module)
            ),
        }
    }

    fn health_word(s: HealthState) -> &'static str {
        match s {
            HealthState::Healthy => "healthy",
            HealthState::Degraded => "DEGRADED",
            HealthState::Unhealthy => "UNHEALTHY",
        }
    }
}

#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn print_tail_call_chain(bpffs_root: &Path) {
    use packetframe_fast_path::tail_call_chain_from_pin;
    println!();
    println!("tail-call chain (from {}):", bpffs_root.display());
    match tail_call_chain_from_pin(bpffs_root) {
        Ok(true) => println!(
            "  MUTATION_PROGS[0]: populated (finalize), \
             confirm prog_id via `bpftool prog show name finalize`"
        ),
        Ok(false) => println!(
            "  MUTATION_PROGS[0]: <EMPTY>, fast_path's tail_call will fail; traffic \
             falls to kernel slow-path. Restart packetframe to repopulate."
        ),
        Err(e) => eprintln!("  MUTATION_PROGS pin unavailable ({e}); loader may not be attached"),
    }
}

#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn print_stats(bpffs_root: &Path) {
    // §4.6 counter names, indexed by `StatIdx` discriminants. The
    // authoritative userspace mirror is
    // `packetframe_fast_path::metrics::COUNTER_NAMES`; this used to be
    // a third hand-copied list and drifted (see the comment there).
    let names = &packetframe_fast_path::metrics::COUNTER_NAMES;

    print_fib_status(bpffs_root);

    match packetframe_fast_path::stats_from_pin(bpffs_root) {
        Ok(values) => {
            println!();
            println!("counters (from {}):", bpffs_root.display());
            let name_w = names.iter().map(|n| n.len()).max().unwrap_or(20);
            for (name, value) in names.iter().zip(values.iter()) {
                println!("  {name:<name_w$}  {value}");
            }
        }
        Err(e) => {
            eprintln!("note: STATS pin unavailable ({e}); loader may not be attached");
        }
    }
}

/// Print the Option F custom-FIB status, map occupancies, nexthop
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

#[cfg(all(test, feature = "vpp-offload"))]
mod vpp_detach_tests {
    use super::*;

    /// No vpp-offload section means no feed and no opinion about ordering.
    ///
    /// These three are gated exactly like `feed_wiring` itself. It is
    /// pure, but its only non-test caller is `run_linux`, so ungating it
    /// would make it dead code on a macOS build under `-D warnings`. They
    /// run in CI's Linux test job.
    #[cfg(all(target_os = "linux", feature = "vpp-offload"))]
    #[test]
    fn without_vpp_offload_there_is_nothing_to_wire() {
        assert_eq!(feed_wiring(&["fast-path"]), Ok(false));
        assert_eq!(feed_wiring(&[]), Ok(false));
    }

    /// vpp-offload alone is refused: there is no route controller to
    /// resolve a FIB, so VPP would come up against an empty table — which
    /// converges, verifies, and forwards nothing.
    #[cfg(all(target_os = "linux", feature = "vpp-offload"))]
    #[test]
    fn vpp_offload_without_fast_path_is_refused() {
        let e = feed_wiring(&["vpp-offload"]).expect_err("must refuse");
        assert!(e.contains("needs a `module fast-path` section"), "{e}");
    }

    /// Declared the wrong way round is refused rather than reordered.
    ///
    /// Modules attach in config order, and vpp-offload's first resync
    /// reads whatever the feed holds at that instant. Silently reordering
    /// would work, and would also mean the file no longer describes what
    /// the daemon did.
    #[cfg(all(target_os = "linux", feature = "vpp-offload"))]
    #[test]
    fn vpp_offload_before_fast_path_is_refused() {
        let e = feed_wiring(&["vpp-offload", "fast-path"]).expect_err("must refuse");
        assert!(e.contains("must be declared before"), "{e}");
        // The right order is accepted, so the test above is about order
        // and not about the pair being rejected outright.
        assert_eq!(feed_wiring(&["fast-path", "vpp-offload"]), Ok(true));
    }

    /// State records are never written through a symlink.
    ///
    /// `state-dir` can be a pre-existing directory an unprivileged user
    /// writes to, so a record name planted as a symlink before startup
    /// would have this root daemon truncate whatever it points at. The
    /// pid file was always written no-follow; the identity sidecar was
    /// added with `std::fs::write`, which follows (review finding, P1).
    /// Both go through one writer now, so the next record cannot get it
    /// wrong by being written somewhere else.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_planted_symlink_does_not_capture_a_state_record() {
        let dir = std::env::temp_dir().join(format!("pf-symlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, "do not truncate me").unwrap();

        // The attacker's plant, at the name the daemon will write.
        let planted = dir.join("packetframe.identity");
        std::os::unix::fs::symlink(&victim, &planted).unwrap();

        // Writing succeeds — the rename replaces the symlink itself —
        // and the victim is untouched.
        write_state_record(&planted, "1 2 boot").expect("write");
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "do not truncate me",
            "the symlink target must not be written through"
        );
        assert!(
            std::fs::read_to_string(&planted)
                .unwrap()
                .starts_with("1 2 boot"),
            "and the record lands at the real path"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `detach` refuses when it cannot prove no daemon is running.
    ///
    /// The policy lives in `daemon_presence::decide` and is tested
    /// there; this asserts the WIRING, which is the half that was
    /// wrong. `detach` consulted a /proc scan for a process running its
    /// own executable path, so a detach launched from a freshly
    /// deployed bundle — every upgrade — matched nothing and walked
    /// straight past the guard while the daemon was live. Unlinking
    /// pins under it leaves the program attached through its open FDs
    /// and reports success, which is the 2026-04-21 outage.
    ///
    /// Uses a legacy record naming THIS process: a live pid whose
    /// identity cannot be established. The only safe reading is "cannot
    /// tell", and the only safe action is to stop.
    ///
    /// The record is made world-writable on purpose, so the assertion
    /// holds whether or not the suite runs as root — and so it covers
    /// the second half of the rule as well: a record anyone could have
    /// written confirms nothing about a LIVE pid, whatever the
    /// executable says, because otherwise a planted pid file picks the
    /// process root signals (review finding). The authentic legacy
    /// record, which this test cannot create without being root, is
    /// covered in `daemon_presence`'s policy table.
    #[cfg(target_os = "linux")]
    #[test]
    fn detach_refuses_a_daemon_it_cannot_rule_out() {
        use crate::daemon_presence::{presence_of, DaemonPresence};
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("pf-detach-unknown-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A legacy record — pid only — naming a process that really is
        // running. This is what an older daemon leaves behind.
        let pidfile = dir.join(PIDFILE_NAME);
        std::fs::write(&pidfile, format!("{}\n", std::process::id())).unwrap();
        std::fs::set_permissions(&pidfile, std::fs::Permissions::from_mode(0o666)).unwrap();

        // A scan that ran and found nothing, so what is under test is
        // what the RECORD alone establishes — with the exe check
        // failing, as it does whenever the CLI runs from a different
        // path than the daemon, and then passing.
        for exe in [false, true] {
            let p = presence_of(
                &pidfile,
                &dir.join(IDENTITY_NAME),
                |_| exe,
                || crate::daemon_presence::Scan::NoneFound,
            );
            assert!(
                matches!(p, DaemonPresence::Unknown { .. }),
                "exe_matches={exe}: a live pid with no verifiable identity must be Unknown, \
                 not Gone — Gone is what let detach proceed: {p:?}"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A recorded pid with no start-time cookie must not be signalled, and
    /// its resources must not be released either.
    ///
    /// The pair `(pid, start_ticks)` is what makes a process identity
    /// verifiable across PID reuse; without the cookie we can neither
    /// confirm the recorded VPP is still running nor rule it out. Signalling
    /// would risk SIGKILLing a stranger as root; releasing would risk
    /// unbinding a VF under a live VPP. So it refuses and says what to do —
    /// and it refuses BEFORE touching sysfs, which is what makes this
    /// testable off a router.
    #[test]
    fn a_pid_without_a_start_cookie_is_refused() {
        use packetframe_vpp_offload::resources::ResourceState;

        let dir = std::env::temp_dir().join(format!("pf-detach-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = ResourceState::empty();
        state.vpp_pid = Some(4242);
        state.vpp_start_ticks = None; // the cookie is missing
        state.save(&dir).unwrap();

        let e = detach_vpp_offload(&dir).expect_err("must refuse");
        assert!(e.contains("4242"), "{e}");
        assert!(
            e.contains("must not be signalled"),
            "the reason must be stated: {e}"
        );
        // The record survives, so a later attempt can still act on it.
        assert!(ResourceState::load(&dir).unwrap().is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// No state file means nothing was ever acquired: a clean no-op, so
    /// `detach --all` stays idempotent for operators who run it habitually.
    /// A record with a start-time cookie but NO boot id must be refused too.
    ///
    /// `VppProcess::adopt` returns `Ok(None)` here because it cannot verify
    /// the identity, not because the process is gone — `start_ticks` counts
    /// from boot while the state file under /var/lib survives a reboot, so
    /// without the boot id an unrelated process can satisfy a (pid, ticks)
    /// check. Treating that refusal as "gone" released the VF under a VPP
    /// that may still have been running.
    #[test]
    fn a_pid_without_a_boot_id_is_refused() {
        use packetframe_vpp_offload::resources::ResourceState;

        let dir = std::env::temp_dir().join(format!("pf-detach-boot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = ResourceState::empty();
        state.vpp_pid = Some(4242);
        state.vpp_start_ticks = Some(99_999);
        state.vpp_boot_id = None; // the third leg is missing
        state.save(&dir).unwrap();

        let e = detach_vpp_offload(&dir).expect_err("must refuse");
        assert!(e.contains("boot id"), "the missing leg must be named: {e}");
        assert!(
            e.contains("must not be signalled"),
            "and the reason stated: {e}"
        );
        assert!(
            ResourceState::load(&dir).unwrap().is_some(),
            "the record must survive so a later attempt can act on it"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Steering that cannot be removed blocks the teardown, and the
    /// record keeps naming exactly what is left.
    ///
    /// Releasing a VF that MCAM still points at blackholes the traffic it
    /// diverts, so the removal comes first and a refused removal stops the
    /// release. What changed when `steer_rules` acquired a writer is the
    /// *shape* of the guard: this path used to refuse unconditionally,
    /// which was correct while the field was always empty and became wrong
    /// the moment it was not — `detach --all` is the remedy every error in
    /// this subsystem points at, and one that refuses whenever a steered
    /// VPP had been running would strand the box.
    ///
    /// On this host no ethtool call can succeed, so what is exercised is
    /// the refusal path. The assertion is on the RECORD rather than on the
    /// message, because that is the invariant: rules that would not come
    /// out must stay findable, or nothing can ever remove them.
    #[test]
    fn steering_that_will_not_come_down_blocks_the_teardown() {
        use packetframe_vpp_offload::resources::{flatten_steer_rules, ResourceState};

        let dir = std::env::temp_dir().join(format!("pf-detach-steer-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut state = ResourceState::empty();
        state.steer_rules = vec![("eth5".to_string(), vec![0, 1])];
        state.save(&dir).unwrap();

        let e = detach_vpp_offload(&dir).expect_err("must refuse while rules remain");
        assert!(e.contains("eth5"), "the steered port must be named: {e}");
        assert!(e.contains("blackhole"), "and the consequence stated: {e}");
        assert!(
            e.contains("ethtool -N"),
            "and the manual escape hatch, since nothing else can clear them: {e}"
        );

        let after = ResourceState::load(&dir)
            .unwrap()
            .expect("the record must survive");
        assert_eq!(
            flatten_steer_rules(&after.steer_rules),
            vec![("eth5".to_string(), 0), ("eth5".to_string(), 1)],
            "every rule still in the NIC must still be on the record"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn no_state_file_is_a_clean_no_op() {
        let dir = std::env::temp_dir().join(format!("pf-detach-none-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(detach_vpp_offload(&dir).is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The terminal scrub. Host-runnable on purpose: this is the rule that
/// existed on one path to an operator's TTY and not on the other, which
/// is exactly the shape that gets missed.
#[cfg(all(test, feature = "fast-path"))]
mod terminal_scrub_tests {
    use super::*;

    /// An ANSI escape in module-supplied text must not reach the
    /// terminal. `scrub_control_chars` has said so since the May 2026
    /// audit; the health surface is a second path to the same TTY and
    /// was not using it.
    #[test]
    fn an_escape_sequence_cannot_reach_the_terminal() {
        let hostile = "ntuple insert failed: \x1b[2J\x1b[1;1Hgotcha";
        let clean = scrub_for_terminal(hostile);
        assert!(!clean.contains('\x1b'), "{clean:?}");
        assert!(
            clean.contains("gotcha") && clean.contains("ntuple insert failed"),
            "the actual message must survive, or the scrub costs the operator the diagnosis: \
             {clean:?}"
        );
    }

    /// A newline must not survive either — on a terminal it FORGES A ROW.
    ///
    /// This is what makes the display scrub stricter than the marker
    /// scrub rather than the same function reused: the marker file keeps
    /// newlines because lines are its record separator. Here a subsystem
    /// message ending in a fake health line would print a module verdict
    /// no module reported, and the strings carry VPP/ethtool text from
    /// outside this process.
    #[test]
    fn a_newline_cannot_forge_a_health_row() {
        let forged = "cannot reach VPP\n  vpp-offload: healthy";
        let clean = scrub_for_terminal(forged);
        assert!(!clean.contains('\n'), "{clean:?}");
        assert_eq!(clean, "cannot reach VPP   vpp-offload: healthy");
    }

    /// And the marker path keeps its newlines, so this did not quietly
    /// change the file format underneath `packetframe reconfigure`.
    #[test]
    fn the_marker_scrub_still_keeps_its_record_separator() {
        assert_eq!(crate::scrub::scrub_control_chars("a\nb\tc"), "a\nb\tc");
        assert_eq!(crate::scrub::scrub_control_chars("a\x1bb"), "a?b");
    }
}
