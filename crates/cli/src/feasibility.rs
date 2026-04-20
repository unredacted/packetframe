//! Feasibility subcommand glue: run SPEC.md §2.1 probes and render the
//! report either as JSON (default, machine-consumable) or as a human table.

use std::path::Path;

use packetframe_common::probe::{run_probes, Capability, CapabilityStatus, FeasibilityReport};

pub struct Rendered {
    pub passed: bool,
    /// Populated only in JSON mode. The human mode prints directly to stdout
    /// as it formats, since the table includes ANSI-free alignment that would
    /// otherwise require building a single large string anyway.
    pub json_output: Option<String>,
}

pub fn probe_and_render(bpffs_root: &Path, human: bool) -> Rendered {
    let report = run_probes(bpffs_root);
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
