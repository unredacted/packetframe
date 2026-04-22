//! `packetframe` — PacketFrame CLI.
//!
//! See SPEC.md §7.4 for the subcommand surface. PR #4 wires `run` to
//! load + attach the fast-path module via aya, persists the pin
//! registry, and blocks on SIGTERM/SIGINT for graceful exit. `detach`
//! and `status` read the pin registry and the live stats map
//! respectively. The `reconfigure` flow (SIGHUP → delta-only reconcile)
//! lands with PR #6.

#[cfg(all(target_os = "linux", feature = "fast-path"))]
mod breaker;
mod feasibility;
mod loader;
#[cfg(all(target_os = "linux", feature = "fast-path"))]
mod metrics;
#[cfg(feature = "probe")]
mod probe;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use packetframe_common::config::Config;
use tracing_subscriber::EnvFilter;

/// Exit codes per SPEC.md §7.3.
pub(crate) const EXIT_OK: u8 = 0;
pub(crate) const EXIT_STARTUP_ERROR: u8 = 1;
pub(crate) const EXIT_RUNTIME_ERROR: u8 = 2;

#[derive(Parser)]
#[command(
    name = "packetframe",
    version,
    about = "Modular eBPF data plane (see SPEC.md for the full spec).",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Probe the host kernel for PacketFrame's capability requirements (SPEC.md §2.1).
    Feasibility {
        /// Optional config path. When supplied, `bpffs-root` from config is
        /// probed instead of the default, and configured interfaces are
        /// checked against /sys/class/net. Also enables the per-interface
        /// XDP trial-attach probe (SPEC.md §2.3) for every `attach`ed iface.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Emit a human-readable table instead of JSON.
        #[arg(long)]
        human: bool,
    },

    /// Run PacketFrame in the foreground: load + attach + block on signal.
    Run {
        #[arg(long)]
        config: PathBuf,
    },

    /// Detach attached programs by removing every pin under the
    /// module's bpffs pin root. Removing a link pin triggers the
    /// kernel-side XDP detach (SPEC.md §8.5); removing map + program
    /// pins is housekeeping.
    Detach {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Tear down every PacketFrame pin across every module, not
        /// just the one in the supplied config. v0.1 has one module
        /// so this is equivalent to the default.
        #[arg(long)]
        all: bool,
    },

    /// Show attach state and live counter values.
    Status {
        #[arg(long)]
        config: PathBuf,
    },

    /// Re-read config and reconcile. Stubbed until PR #6.
    Reconfigure {
        #[arg(long)]
        config: PathBuf,
    },

    /// Direct BPF map ops for debugging. Lands in PR #6 alongside
    /// reconfigure (both need live map handles from the running loader).
    Map {
        module: String,
        map: String,
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },

    /// Attach a diagnostic XDP program, dump the first 16 bytes of a
    /// sample of incoming packets, detach. Built to answer "what does
    /// this driver hand to XDP?" — see SPEC.md §11.1(c) for the
    /// rvu-nicpf native-delivery investigation that motivated it.
    #[cfg(feature = "probe")]
    Probe {
        /// Interface to probe.
        #[arg(long)]
        iface: String,
        /// How long to sample. Accepts `30s`, `1m`, `500ms`, or a
        /// bare number of seconds. Default 10s keeps the tool quick
        /// to run while typically capturing a representative sample
        /// on live traffic.
        #[arg(long, default_value = "10s", value_parser = parse_duration)]
        duration: Duration,
        /// Attach mode. `auto` = native, fall back to generic;
        /// `native` = driver XDP; `generic` = SKB XDP. Comparing
        /// `native` vs `generic` output on the same iface is the
        /// standard way to confirm a driver-specific non-conformance.
        #[arg(long, default_value = "auto", value_parser = parse_mode)]
        mode: packetframe_probe::AttachMode,
        /// Byte offset at which the BPF program samples each packet's
        /// head. Default `0` (start of `xdp->data`). Non-zero values
        /// are for diagnosing drivers that point `xdp->data` into
        /// headroom instead of at the packet — e.g. `--offset 128`
        /// on rvu-nicpf pre-Linux-v6.8 to see the real Ethernet
        /// header. Capped at 512.
        #[arg(long, default_value_t = 0)]
        offset: u16,
    },
}

#[cfg(feature = "probe")]
fn parse_duration(s: &str) -> Result<Duration, String> {
    // Unit suffixes: `ms`, `s`, `m` — parsed in longest-match order so
    // `ms` wins over `s`. Bare integers are treated as seconds, which
    // matches the feel of most "how long" CLI flags.
    if let Some(num) = s.strip_suffix("ms") {
        num.parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|e| format!("bad millisecond count in `{s}`: {e}"))
    } else if let Some(num) = s.strip_suffix('s') {
        num.parse::<u64>()
            .map(Duration::from_secs)
            .map_err(|e| format!("bad second count in `{s}`: {e}"))
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<u64>()
            .map(|m| Duration::from_secs(m * 60))
            .map_err(|e| format!("bad minute count in `{s}`: {e}"))
    } else {
        s.parse::<u64>().map(Duration::from_secs).map_err(|e| {
            format!("expected `<n>s`, `<n>ms`, `<n>m`, or a bare second count; got `{s}`: {e}")
        })
    }
}

#[cfg(feature = "probe")]
fn parse_mode(s: &str) -> Result<packetframe_probe::AttachMode, String> {
    match s {
        "auto" => Ok(packetframe_probe::AttachMode::Auto),
        "native" => Ok(packetframe_probe::AttachMode::Native),
        "generic" => Ok(packetframe_probe::AttachMode::Generic),
        other => Err(format!(
            "expected one of `auto`, `native`, `generic`; got `{other}`"
        )),
    }
}

fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Feasibility { config, human } => run_feasibility(config, human),
        Command::Run { config } => match loader::run(&config) {
            Ok(()) => ExitCode::from(EXIT_OK),
            Err(loader::RunError::Startup(msg)) => {
                tracing::error!(error = %msg, "startup failed");
                ExitCode::from(EXIT_STARTUP_ERROR)
            }
            Err(loader::RunError::Runtime(msg)) => {
                tracing::error!(error = %msg, "runtime error");
                ExitCode::from(EXIT_RUNTIME_ERROR)
            }
        },
        Command::Detach { config, all } => match loader::detach(config.as_deref(), all) {
            Ok(()) => ExitCode::from(EXIT_OK),
            Err(e) => {
                tracing::error!(error = %e);
                ExitCode::from(EXIT_RUNTIME_ERROR)
            }
        },
        Command::Status { config } => match loader::status(&config) {
            Ok(()) => ExitCode::from(EXIT_OK),
            Err(e) => {
                tracing::error!(error = %e);
                ExitCode::from(EXIT_RUNTIME_ERROR)
            }
        },
        Command::Reconfigure { .. } => not_implemented("reconfigure"),
        Command::Map { .. } => not_implemented("map"),
        #[cfg(feature = "probe")]
        Command::Probe {
            iface,
            duration,
            mode,
            offset,
        } => probe::run(iface, mode, duration, offset),
    }
}

fn run_feasibility(config: Option<PathBuf>, human: bool) -> ExitCode {
    let (bpffs_root, attach_ifaces) = match &config {
        Some(path) => match Config::from_file(path) {
            Ok(c) => {
                if let Err(e) = c.validate_interfaces() {
                    eprintln!("config interface check failed: {e}");
                    return ExitCode::from(EXIT_STARTUP_ERROR);
                }
                let ifaces = feasibility::attach_ifaces_from_config(&c);
                (c.global.bpffs_root, ifaces)
            }
            Err(e) => {
                eprintln!("config parse error: {e}");
                return ExitCode::from(EXIT_STARTUP_ERROR);
            }
        },
        None => (
            std::path::PathBuf::from(packetframe_common::config::DEFAULT_BPFFS_ROOT),
            Vec::new(),
        ),
    };

    let report = feasibility::probe_and_render(&bpffs_root, &attach_ifaces, human);
    if let Some(json) = report.json_output {
        println!("{json}");
    }
    if report.passed {
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_STARTUP_ERROR)
    }
}

fn not_implemented(name: &str) -> ExitCode {
    tracing::warn!(
        subcommand = name,
        "not implemented in this release — tracked in the v0.1 plan"
    );
    ExitCode::from(EXIT_RUNTIME_ERROR)
}
