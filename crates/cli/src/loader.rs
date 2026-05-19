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
    config
        .validate_interfaces()
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

    tracing::info!("fast-path running, SIGHUP to reconfigure, SIGTERM/SIGINT to exit (§8.5)");

    let termination = drive_signal_loop(config_path, &config.global.state_dir, &mut modules)
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
    // Best-effort PID file cleanup. Non-fatal, the file is harmless
    // if left behind (PID will be unrecognized on re-validate).
    if let Err(e) = std::fs::remove_file(&pid_file_path) {
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

/// Open `path` for writing with `O_NOFOLLOW | O_EXCL | O_CREAT | 0600`
/// the symlink-safe atomic-write primitive both pidfile / marker
/// writes (here) and the metrics-textfile writer ([`crate::metrics`])
/// use for their `.tmp` staging files.
///
/// `O_NOFOLLOW` makes the open fail (`ELOOP`) when `path` is a
/// symlink, so an attacker who can pre-create `<...>.tmp` as a
/// symlink pointing at e.g. `/etc/passwd` cannot redirect the
/// privileged daemon's write target. `O_EXCL` makes the open fail
/// (`EEXIST`) when the path already exists, so a stale `.tmp`
/// leftover from a crashed run is also surfaced rather than silently
/// truncated and overwritten, callers handle that one-shot with
/// `unlink-and-retry`.
///
/// The May 2026 audit Slice 4 finding flagged the previous use of
/// `File::create` (which both follows symlinks and `O_TRUNC`s) on
/// these temp paths as a privileged-write redirection primitive any
/// time the parent directory is writable to a non-root user.
#[cfg(target_os = "linux")]
pub(crate) fn create_excl_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
}

/// Same shape but with one stale-`.tmp` retry. The retry runs only
/// when `create_excl_no_follow` returns `AlreadyExists` and the
/// existing path is a regular file (a leftover from a crashed run);
/// a `.tmp` that's a symlink hits `ELOOP` on the retried open and
/// the function gives up. A second `EEXIST` is treated as a real
/// race between competing writers and errors out.
#[cfg(target_os = "linux")]
fn create_excl_no_follow_with_retry(path: &Path) -> std::io::Result<std::fs::File> {
    match create_excl_no_follow(path) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // unlink-and-retry, but only if the leftover is a plain
            // file. symlink_metadata avoids following the symlink so
            // we don't misclassify an attacker's symlink as a file.
            let meta = std::fs::symlink_metadata(path)?;
            if !meta.file_type().is_file() {
                return Err(e);
            }
            std::fs::remove_file(path)?;
            create_excl_no_follow(path)
        }
        Err(e) => Err(e),
    }
}

/// Atomically write the current PID to `path`. Uses write-then-rename
/// so a half-written file is never observed; the temp file is opened
/// with `O_NOFOLLOW | O_EXCL | O_CREAT | 0600` so a pre-existing
/// symlink at `<path>.tmp` cannot redirect the write.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn write_pid_file(path: &Path) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let tmp = path.with_extension("pid.tmp");
    {
        let mut f = create_excl_no_follow_with_retry(&tmp)?;
        writeln!(f, "{}", std::process::id())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
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
    state_dir: &Path,
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
            SIGHUP => reconfigure_from_signal(config_path, state_dir, modules),
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
    Ok(Termination::ExitPreserveAttach)
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
) {
    use packetframe_common::module::ModuleConfig;

    tracing::info!(config = %config_path.display(), "SIGHUP received; reconfiguring");

    let marker_path = state_dir.join(RECONFIGURE_MARKER_NAME);

    let new_config = match Config::from_file(config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "SIGHUP config parse failed; keeping current config");
            write_reconfigure_marker(&marker_path, &format!("ERR parse: {e}"));
            return;
        }
    };

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

    if failures.is_empty() {
        write_reconfigure_marker(&marker_path, "OK");
    } else {
        write_reconfigure_marker(
            &marker_path,
            &format!("ERR module: {}", failures.join("; ")),
        );
    }
}

/// Scrub ASCII control bytes (< 0x20) other than tab/newline from a
/// string that's about to be written to the reconfigure marker file
/// (and from there read back by `packetframe reconfigure` and
/// echoed via `tracing::error!` to an operator's terminal). The
/// failure-side `status` ultimately includes per-module error
/// messages that can carry parser bytes from external sources
/// (config text, BGP/BMP error text propagated up); a stray ANSI
/// escape sequence in the marker would corrupt the operator's TTY
/// when they run `packetframe reconfigure`. Audit Slice 5 hardening.
#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn scrub_control_chars(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c == '\t' || c == '\n' || !c.is_control() {
                c
            } else {
                '?'
            }
        })
        .collect()
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
    if let Err(e) = std::fs::create_dir_all(parent) {
        tracing::warn!(error = %e, "could not create reconfigure marker dir");
        return;
    }
    let tmp = path.with_extension("timestamp.tmp");
    let body = format!("{} {}\n", scrub_control_chars(status), now_ns);
    let r = (|| -> std::io::Result<()> {
        let mut f = create_excl_no_follow_with_retry(&tmp)?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
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

    let pid = read_pid_file(&pid_path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ReconfigureError::DaemonNotRunning(format!(
            "PID file not found at {}, daemon doesn't appear to be running",
            pid_path.display()
        )),
        _ => ReconfigureError::Io(format!("read PID file {}: {e}", pid_path.display())),
    })?;

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
    if !proc_exe_matches_current(pid) {
        return Err(ReconfigureError::DaemonNotRunning(format!(
            "PID {pid} from {} is not a packetframe process (stale pidfile?)",
            pid_path.display()
        )));
    }

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

#[cfg(target_os = "linux")]
fn read_pid_file(path: &Path) -> std::io::Result<libc::pid_t> {
    let s = std::fs::read_to_string(path)?;
    s.trim().parse::<libc::pid_t>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("PID parse `{}`: {e}", s.trim()),
        )
    })
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
        Err(ReconfigureError::DaemonRejected(rest.to_string()))
    } else {
        // Marker exists but doesn't match the expected format.
        Err(ReconfigureError::Io(format!(
            "unexpected marker content: {trimmed}"
        )))
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
        // /proc/<pid>/exe is the kernel-managed identity check (the
        // May 2026 audit Slice 4 finding). The `comm` field used to
        // gate this is user-settable via prctl(PR_SET_NAME), so a
        // local user could rename their own process to "packetframe"
        // and block the operator's `packetframe detach`. The exe
        // symlink resolves to the inode the kernel actually exec'd,
        // and is not user-writable.
        if !proc_exe_matches_current(pid as libc::pid_t) {
            continue;
        }
        // Confirm it's actually the `run` subcommand, not e.g.
        // `packetframe detach` from another shell. argv IS still
        // user-settable, but the exe match above pins identity; a
        // spoofed argv "run" entry only sources a self-match against
        // the very same binary.
        let cmdline_path = format!("/proc/{pid}/cmdline");
        if let Ok(cmdline) = std::fs::read_to_string(&cmdline_path) {
            if cmdline.split('\0').any(|a| a == "run") {
                return Some(pid);
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
    // Confirmed outage-adjacent on the reference EFG 2026-04-21, the
    // detach ran, reported clean, but `ip link show` still had
    // `xdpgeneric` attached.
    if let Some(pid) = daemon_pid() {
        return Err(format!(
            "a `packetframe run` daemon is still running (pid {pid}); \
             stop it first (e.g. `kill {pid}`) before detaching. \
             Detach unlinks bpffs pins, but the kernel-side bpf_link \
             holds refs through the daemon's open FDs, both have to \
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
    // behave identically, both tear down every pin under the module's
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
    }

    Ok(())
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
    // §4.6 counter names, indexed by `StatIdx` discriminants. Order
    // matches `crates/modules/fast-path/bpf/src/maps.rs::StatIdx`.
    // Append-only, adding new entries at the end is fine; renumbering
    // breaks dashboards. Indices 0-19 are the kernel-fib counter set;
    // 20-31 were appended in the Option F custom-FIB rollout (§4.11).
    const NAMES: [&str; 37] = [
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
        // --- v0.2.4: mss-clamp ---
        "mss_clamp_applied",
        "mss_clamp_skipped",
        // --- v0.2.5: two-stage datapath ---
        "err_tail_call",
        "err_mutation_ctx",
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
