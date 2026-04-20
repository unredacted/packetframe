//! `packetframe` — PacketFrame CLI.
//!
//! See SPEC.md §7.4 for the subcommand surface. v0.0.1 implements
//! `feasibility` fully and provides stubs for `run`, `detach`, `status`,
//! `reconfigure`, and `map` that parse their args and exit 2.

mod feasibility;

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
        /// checked against /sys/class/net.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Emit a human-readable table instead of JSON.
        #[arg(long)]
        human: bool,
    },

    /// Run PacketFrame in the foreground (stub in v0.0.1 — module loading not implemented).
    Run {
        #[arg(long)]
        config: PathBuf,
    },

    /// Detach attached programs. Not implemented in v0.0.1.
    Detach {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Tear down every PacketFrame pin, regardless of config.
        #[arg(long)]
        all: bool,
    },

    /// Show attach state and counters. Not implemented in v0.0.1.
    Status {
        #[arg(long)]
        config: PathBuf,
    },

    /// Re-read config and reconcile. Not implemented in v0.0.1.
    Reconfigure {
        #[arg(long)]
        config: PathBuf,
    },

    /// Direct BPF map ops for debugging. Not implemented in v0.0.1.
    Map {
        /// Module name, e.g. `fast-path`.
        module: String,
        /// Map name, e.g. `allow_v4`.
        map: String,
        /// Tool-specific arguments.
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,
    },
}

fn main() -> ExitCode {
    // Logs to stderr per SPEC.md §3.7. Default level is info; overridable
    // via RUST_LOG. Once we honor `log-level` from config in v0.1, this
    // reinitializes with the configured level after parse.
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
        Command::Run { config } => run_stub(config),
        Command::Detach { .. } => not_implemented("detach"),
        Command::Status { .. } => not_implemented("status"),
        Command::Reconfigure { .. } => not_implemented("reconfigure"),
        Command::Map { .. } => not_implemented("map"),
    }
}

fn run_feasibility(config: Option<PathBuf>, human: bool) -> ExitCode {
    let bpffs_root = match &config {
        Some(path) => match Config::from_file(path) {
            Ok(c) => {
                if let Err(e) = c.validate_interfaces() {
                    eprintln!("config interface check failed: {e}");
                    return ExitCode::from(EXIT_STARTUP_ERROR);
                }
                c.global.bpffs_root
            }
            Err(e) => {
                eprintln!("config parse error: {e}");
                return ExitCode::from(EXIT_STARTUP_ERROR);
            }
        },
        None => std::path::PathBuf::from(packetframe_common::config::DEFAULT_BPFFS_ROOT),
    };

    let report = feasibility::probe_and_render(&bpffs_root, human);
    // Stream the report to stdout — `human` formatter already wrote to
    // stdout in its branch; JSON branch returns a String we print here.
    if let Some(json) = report.json_output {
        println!("{json}");
    }
    if report.passed {
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_STARTUP_ERROR)
    }
}

fn run_stub(config: PathBuf) -> ExitCode {
    match Config::from_file(&config) {
        Ok(c) => {
            if let Err(e) = c.validate_interfaces() {
                tracing::error!(error = %e, "config interface check failed");
                return ExitCode::from(EXIT_STARTUP_ERROR);
            }
            tracing::info!(
                path = %config.display(),
                modules = c.modules.len(),
                "config parsed successfully"
            );
            let bpffs_root = c.global.bpffs_root.clone();
            let report = feasibility::probe_and_render(&bpffs_root, false);
            if let Some(json) = report.json_output {
                println!("{json}");
            }
            if !report.passed {
                tracing::error!(
                    "one or more required kernel capabilities are missing — see feasibility report above"
                );
                return ExitCode::from(EXIT_STARTUP_ERROR);
            }
            tracing::warn!(
                "module loading not implemented in v0.0.1 (see SPEC.md §4 and the v0.1 forward view in plans/i-m-handing-you-a-stateless-simon.md)"
            );
            ExitCode::from(EXIT_RUNTIME_ERROR)
        }
        Err(e) => {
            tracing::error!(error = %e, path = %config.display(), "config parse error");
            ExitCode::from(EXIT_STARTUP_ERROR)
        }
    }
}

fn not_implemented(name: &str) -> ExitCode {
    tracing::warn!(
        subcommand = name,
        "not implemented in v0.0.1 — tracked in the v0.1 forward view"
    );
    ExitCode::from(EXIT_RUNTIME_ERROR)
}
