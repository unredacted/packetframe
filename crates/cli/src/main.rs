//! `packetframe` — PacketFrame CLI.
//!
//! See SPEC.md §7.4 for the subcommand surface. PR #4 wires `run` to
//! load + attach the fast-path module via aya, persists the pin
//! registry, and blocks on SIGTERM/SIGINT for graceful exit. `detach`
//! and `status` read the pin registry and the live stats map
//! respectively. The `reconfigure` flow (SIGHUP → delta-only reconcile)
//! lands with PR #6.

mod feasibility;
mod loader;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use packetframe_common::config::Config;
use tracing_subscriber::EnvFilter;

/// Exit codes per SPEC.md §7.3.
const EXIT_OK: u8 = 0;
const EXIT_STARTUP_ERROR: u8 = 1;
const EXIT_RUNTIME_ERROR: u8 = 2;

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
