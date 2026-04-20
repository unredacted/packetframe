//! Feasibility subcommand glue: run SPEC.md §2.1 probes and render the
//! report either as JSON (default) or as a human table. PR #4 adds the
//! per-interface XDP trial-attach probe (§2.3) for each `attach`ed iface
//! in the config — graduates from Deferred to a real check.

use std::path::Path;

use packetframe_common::{
    config::{Config, ModuleDirective},
    probe::{run_probes, Capability, CapabilityStatus, FeasibilityReport},
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

pub fn probe_and_render(bpffs_root: &Path, attach_ifaces: &[String], human: bool) -> Rendered {
    let mut report = run_probes(bpffs_root);

    // Graduate §2.3 per-interface trial-attach probe from Deferred —
    // remove the placeholder entry and replace with real per-iface
    // verdicts.
    report
        .capabilities
        .retain(|c| c.name != "xdp.per_interface_attach_probe");
    for cap in trial_attach_caps(attach_ifaces) {
        report.capabilities.push(cap);
    }
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
        println!("Result: PASS — all required capabilities present.");
    } else {
        let failing: Vec<&Capability> = report
            .capabilities
            .iter()
            .filter(|c| c.required && c.status != CapabilityStatus::Pass)
            .collect();
        println!(
            "Result: FAIL — {} required capabilit{} missing or unknown:",
            failing.len(),
            if failing.len() == 1 { "y" } else { "ies" },
        );
        for f in failing {
            println!("  - {} ({})", f.name, f.detail);
        }
    }
}

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
        status, req, cap.name, cap.detail
    );
}
