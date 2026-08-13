//! Feasibility subcommand glue: run SPEC.md §2.1 probes and render the
//! report either as JSON (default) or as a human table. A per-interface
//! XDP trial-attach probe (§2.3) runs for each `attach`ed iface in the
//! config; it graduates the per-iface attach feasibility from Deferred
//! to a real pass/fail check.

use crate::scrub::scrub_for_terminal;
use std::path::Path;

use packetframe_common::{
    config::{Config, ModuleDirective},
    fib::IpPrefix,
    probe::{run_iface_probes, run_probes, Capability, CapabilityStatus, FeasibilityReport},
};

pub struct Rendered {
    pub passed: bool,
    pub json_output: Option<String>,
}

pub fn attach_ifaces_from_config(config: &Config) -> Vec<String> {
    let mut ifaces = Vec::new();
    for m in &config.modules {
        for d in &m.directives {
            if let ModuleDirective::Attach { iface, .. } = d {
                if !ifaces.contains(iface) {
                    ifaces.push(iface.clone());
                }
            }
        }
    }
    ifaces
}

/// Interfaces named by `port` lines in a `vpp-offload` section, if
/// any. Empty when the module isn't configured — the vpp probes then
/// stay out of the report entirely.
pub fn vpp_ports_from_config(config: &Config) -> Vec<String> {
    let mut ports = Vec::new();
    for m in &config.modules {
        if m.name != "vpp-offload" {
            continue;
        }
        for d in &m.directives {
            if let ModuleDirective::VppPort { iface, .. } = d {
                if !ports.contains(iface) {
                    ports.push(iface.clone());
                }
            }
        }
    }
    ports
}

/// Total VPP workers the config asks for — the sum of every `port`
/// line's `cores`. The IRQ-affinity probe needs it to derive the same
/// core map attach would, so the probe and the attach refusal cannot
/// disagree about which CPUs are at stake.
pub fn vpp_workers_from_config(config: &Config) -> u32 {
    let mut workers = 0u32;
    for m in &config.modules {
        if m.name != "vpp-offload" {
            continue;
        }
        for d in &m.directives {
            if let ModuleDirective::VppPort { cores, .. } = d {
                workers += u32::from(*cores);
            }
        }
    }
    workers
}

/// The fast-path allowlist, as the steering probe needs it.
///
/// It comes from the **fast-path** section, not vpp-offload's: steered
/// prefixes inherit the allowlist rather than declaring their own, which
/// is what makes "the offload carries a slice of the same traffic"
/// true by construction instead of by two lists agreeing.
pub fn allowlist_from_config(config: &Config) -> Vec<IpPrefix> {
    let mut out = Vec::new();
    for m in &config.modules {
        if m.name != "fast-path" {
            continue;
        }
        for d in &m.directives {
            match d {
                ModuleDirective::AllowPrefix4(p) => out.push(IpPrefix::V4 {
                    addr: p.addr.octets(),
                    prefix_len: p.prefix_len,
                }),
                ModuleDirective::AllowPrefix6(p) => out.push(IpPrefix::V6 {
                    addr: p.addr.octets(),
                    prefix_len: p.prefix_len,
                }),
                _ => {}
            }
        }
    }
    out
}

/// The `vpp-binary` override from a `vpp-offload` section, if set, so
/// feasibility probes the executable the module will actually run.
pub fn vpp_binary_from_config(config: &Config) -> Option<String> {
    config
        .modules
        .iter()
        .filter(|m| m.name == "vpp-offload")
        .flat_map(|m| &m.directives)
        .find_map(|d| match d {
            ModuleDirective::VppBinary(p) => Some(p.clone()),
            _ => None,
        })
}

pub fn probe_and_render(
    bpffs_root: &Path,
    attach_ifaces: &[String],
    vpp_ports: &[String],
    vpp_workers: u32,
    vpp_binary: Option<&str>,
    allowlist: &[IpPrefix],
    human: bool,
) -> Rendered {
    let mut report = run_probes(bpffs_root);

    // Graduate §2.3 per-interface trial-attach probe from Deferred
    // remove the placeholder entry and replace with real per-iface
    // verdicts.
    report
        .capabilities
        .retain(|c| c.name != "xdp.per_interface_attach_probe");
    for cap in trial_attach_caps(attach_ifaces) {
        report.capabilities.push(cap);
    }
    // Per-iface performance probes (GRO state, RPS masks). All
    // informational; they exist so a CPU-limited generic-XDP box
    // surfaces its highest-leverage host tuning knobs in the same
    // report operators already collect.
    for cap in run_iface_probes(attach_ifaces) {
        report.capabilities.push(cap);
    }
    // vpp-offload probes (phase 4): only when the config declares the
    // module. Non-required like the perf probes — feasibility informs,
    // the module's attach enforces.
    #[cfg(feature = "vpp-offload")]
    if !vpp_ports.is_empty() {
        for cap in packetframe_vpp_offload::run_feasibility_probes(
            vpp_ports,
            vpp_workers,
            vpp_binary,
            allowlist,
        ) {
            report.capabilities.push(cap);
        }
    }
    #[cfg(not(feature = "vpp-offload"))]
    let _ = (vpp_ports, vpp_workers, vpp_binary, allowlist);
    // `passed` needs recomputing after the iface probes; the trial
    // attach caps are non-required (a native-XDP failure shouldn't
    // abort startup), but we preserve the existing `passed` logic.
    let passed = report
        .capabilities
        .iter()
        .filter(|c| c.required)
        .all(|c| c.status == CapabilityStatus::Pass);
    let report = FeasibilityReport {
        version: report.version,
        passed,
        capabilities: report.capabilities,
    };

    if human {
        print_human(&report);
        Rendered {
            passed: report.passed,
            json_output: None,
        }
    } else {
        let json =
            serde_json::to_string_pretty(&report).expect("FeasibilityReport is serializable");
        Rendered {
            passed: report.passed,
            json_output: Some(json),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "fast-path"))]
fn trial_attach_caps(ifaces: &[String]) -> Vec<Capability> {
    use packetframe_common::probe::Capability;
    use packetframe_fast_path::{trial_attach_native, TrialResult};

    if ifaces.is_empty() {
        return vec![Capability {
            name: "xdp.per_interface_attach_probe".into(),
            status: CapabilityStatus::Deferred,
            detail: "no interfaces configured to probe (supply `--config`)".into(),
            required: false,
        }];
    }

    ifaces
        .iter()
        .map(|iface| {
            let name = format!("xdp.attach.{iface}");
            match trial_attach_native(iface) {
                TrialResult::NativeOk => Capability {
                    name,
                    status: CapabilityStatus::Pass,
                    detail: "native XDP attach succeeded".into(),
                    required: false,
                },
                TrialResult::GenericOnly { native_error } => Capability {
                    name,
                    status: CapabilityStatus::Pass,
                    detail: format!("generic XDP OK; native unsupported ({native_error})"),
                    required: false,
                },
                TrialResult::Neither {
                    native_error,
                    generic_error,
                } => Capability {
                    name,
                    status: CapabilityStatus::Fail,
                    detail: format!(
                        "native failed ({native_error}); generic failed ({generic_error})"
                    ),
                    required: false,
                },
                TrialResult::NoSuchInterface(e) => Capability {
                    name,
                    status: CapabilityStatus::Fail,
                    detail: e,
                    required: false,
                },
                TrialResult::LoadFailed(e) => Capability {
                    name,
                    status: CapabilityStatus::Unknown,
                    detail: format!("BPF load failed: {e}"),
                    required: false,
                },
                TrialResult::NoBpfBinary => Capability {
                    name,
                    status: CapabilityStatus::Unknown,
                    detail: "no BPF ELF embedded in this binary".into(),
                    required: false,
                },
            }
        })
        .collect()
}

#[cfg(not(all(target_os = "linux", feature = "fast-path")))]
fn trial_attach_caps(_ifaces: &[String]) -> Vec<Capability> {
    vec![Capability {
        name: "xdp.per_interface_attach_probe".into(),
        status: CapabilityStatus::Unknown,
        detail: "fast-path feature not built into this binary".into(),
        required: false,
    }]
}

fn print_human(report: &FeasibilityReport) {
    println!("PacketFrame feasibility report (v{})", report.version);
    println!();

    let name_w = report
        .capabilities
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(30)
        .max(30);

    println!(
        "{:<8} {:<4} {:<name_w$} DETAIL",
        "STATUS", "REQ", "CAPABILITY"
    );
    println!(
        "{:<8} {:<4} {:<name_w$} {dash}",
        "-".repeat(6),
        "---",
        "-".repeat(name_w),
        dash = "-".repeat(6),
    );

    for cap in &report.capabilities {
        print_row(cap, name_w);
    }

    println!();
    if report.passed {
        println!("Result: PASS, all required capabilities present.");
    } else {
        let failing: Vec<&Capability> = report
            .capabilities
            .iter()
            .filter(|c| c.required && c.status != CapabilityStatus::Pass)
            .collect();
        println!(
            "Result: FAIL, {} required capabilit{} missing or unknown:",
            failing.len(),
            if failing.len() == 1 { "y" } else { "ies" },
        );
        for f in failing {
            println!(
                "  - {} ({})",
                scrub_for_terminal(&f.name),
                scrub_for_terminal(&f.detail)
            );
        }
    }
}

/// Both `name` and `detail` are scrubbed, and `detail` is the reason.
///
/// A capability's detail is assembled from whatever the probe found:
/// `strerror` text from an ioctl, a VPP version string, a path out of
/// the config, an ethtool refusal. `vpp.steering.budget` alone now
/// carries the raw `io::Error` from `ETHTOOL_GRXCLSRLALL`. None of that
/// originated here, and this prints straight to a TTY.
fn print_row(cap: &Capability, name_w: usize) {
    let status = match cap.status {
        CapabilityStatus::Pass => "PASS",
        CapabilityStatus::Fail => "FAIL",
        CapabilityStatus::Unknown => "UNKN",
        CapabilityStatus::Deferred => "DEFER",
    };
    let req = if cap.required { "yes" } else { "no" };
    println!(
        "{:<8} {:<4} {:<name_w$} {}",
        status,
        req,
        scrub_for_terminal(&cap.name),
        scrub_for_terminal(&cap.detail)
    );
}
