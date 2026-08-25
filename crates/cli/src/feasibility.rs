//! Feasibility subcommand glue: run SPEC.md §2.1 probes and render the
//! report either as JSON (default) or as a human table. A per-interface
//! XDP trial-attach probe (§2.3) runs for each `attach`ed iface in the
//! config; it graduates the per-iface attach feasibility from Deferred
//! to a real pass/fail check.

use crate::scrub::scrub_for_terminal;
use std::path::Path;

use packetframe_common::{
    config::{Config, ModuleDirective, VppSteerDirection},
    fib::IpPrefix,
    probe::{run_iface_probes, run_probes, Capability, CapabilityStatus, FeasibilityReport},
};

pub struct Rendered {
    pub passed: bool,
    /// Every core requirement passed and only vpp-graft capabilities
    /// block — the "core capabilities PASS; vpp-offload attach
    /// BLOCKED" case, which gets its own exit code so automation
    /// gating fast-path work can tell it from a core failure (review
    /// finding on #200).
    pub vpp_blocked_only: bool,
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

/// The ports configured `steer on` — the set whose NICs the budget
/// probe queries, mirroring attach's `ifaces_to_query` so the two
/// cannot disagree (a down idle member must not fail the probe for a
/// config attach accepts).
pub fn vpp_steer_ports_from_config(config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    for m in &config.modules {
        if m.name != "vpp-offload" {
            continue;
        }
        for d in &m.directives {
            if let ModuleDirective::VppPort {
                iface, steer: true, ..
            } = d
            {
                if !out.contains(iface) {
                    out.push(iface.clone());
                }
            }
        }
    }
    out
}

/// The DISTINCT effective steer directions of the steering ports —
/// each port's `direction` tail falling back to the global, exactly as
/// the module derives its per-port plans, so the budget probe runs the
/// same arithmetic attach enforces. Falls back to the global default
/// when nothing steers yet (the staging state), so the probe still
/// reports what the first canary step would install.
pub fn vpp_steer_directions_from_config(config: &Config) -> Vec<VppSteerDirection> {
    let mut global = VppSteerDirection::default();
    let mut ports: Vec<(bool, Option<VppSteerDirection>)> = Vec::new();
    for m in &config.modules {
        if m.name != "vpp-offload" {
            continue;
        }
        for d in &m.directives {
            match d {
                ModuleDirective::VppSteerDirection(dir) => global = *dir,
                ModuleDirective::VppPort {
                    steer, direction, ..
                } => ports.push((*steer, *direction)),
                _ => {}
            }
        }
    }
    let mut out: Vec<VppSteerDirection> = Vec::new();
    for (steer, dir) in &ports {
        if !steer {
            continue;
        }
        let d = dir.unwrap_or(global);
        if !out.contains(&d) {
            out.push(d);
        }
    }
    if out.is_empty() {
        out.push(global);
    }
    out
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

/// The `steer-exempt` entries, so the budget probe counts the same
/// arithmetic attach enforces: diversions + built-ins + exemptions.
/// A probe that omitted them would pass a config attach refuses,
/// two slots short.
pub fn vpp_steer_exempts_from_config(
    config: &Config,
) -> Vec<packetframe_common::config::Ipv4Prefix> {
    config
        .modules
        .iter()
        .filter(|m| m.name == "vpp-offload")
        .flat_map(|m| &m.directives)
        .filter_map(|d| match d {
            ModuleDirective::VppSteerExempt(p) => Some(*p),
            _ => None,
        })
        .collect()
}

/// The `local-route` lines joined with the fast-path `local-prefix`
/// that covers each one — the join only the loader can perform, since
/// `Module` methods see one section. The covering prefix's `via` is the
/// kernel bridge device whose neighbours mirror onto the subif; the
/// longest cover wins, matching every other most-specific rule in the
/// config. `validate_vpp_offload` guarantees a cover exists, so the
/// error arm is a programming-order guard (extractor called on an
/// unvalidated config), not an operator surface.
///
/// Gated like [`crate::loader`]'s `feed_wiring` — its only caller is
/// the Linux module-wiring path, and a laxer gate reads as dead code on
/// every other build.
#[cfg(all(target_os = "linux", feature = "fast-path", feature = "vpp-offload"))]
pub fn vpp_local_routes_from_config(
    config: &Config,
) -> Result<Vec<packetframe_vpp_offload::LocalRoute>, String> {
    let covers: Vec<(&packetframe_common::config::Ipv4Prefix, &String)> = config
        .modules
        .iter()
        .filter(|m| m.name == "fast-path")
        .flat_map(|m| &m.directives)
        .filter_map(|d| match d {
            ModuleDirective::LocalPrefix { cidr, iface, .. } => Some((cidr, iface)),
            _ => None,
        })
        .collect();
    let mut out = Vec::new();
    for d in config
        .modules
        .iter()
        .filter(|m| m.name == "vpp-offload")
        .flat_map(|m| &m.directives)
    {
        if let ModuleDirective::VppLocalRoute {
            prefix,
            iface,
            vlan,
            ..
        } = d
        {
            let kernel_dev = covers
                .iter()
                .filter(|(c, _)| c.contains_prefix(prefix))
                .max_by_key(|(c, _)| c.prefix_len)
                .map(|(_, i)| (*i).clone())
                .ok_or_else(|| {
                    format!(
                        "local-route {}/{} matches no fast-path local-prefix — \
                         validate_vpp_offload should have refused this config",
                        prefix.addr, prefix.prefix_len
                    )
                })?;
            out.push(packetframe_vpp_offload::LocalRoute {
                prefix: *prefix,
                port: iface.clone(),
                vlan: *vlan,
                kernel_dev,
            });
        }
    }
    Ok(out)
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

/// The configured `loopback-address`, if any — `bring_up` refuses one
/// the kernel currently holds, so the `vpp.loopback` probe mirrors
/// that refusal (review finding on #200).
pub fn vpp_loopback_from_config(config: &Config) -> Option<std::net::Ipv4Addr> {
    config
        .modules
        .iter()
        .flat_map(|m| &m.directives)
        .find_map(|d| match d {
            ModuleDirective::VppLoopbackAddress(p) => Some(p.addr),
            _ => None,
        })
}

/// The vpp-offload facts the probes need, grouped so the parameter
/// list stops growing by one per directive (clippy agrees at eight).
pub struct VppProbeInputs<'a> {
    pub ports: &'a [String],
    pub steer_ports: &'a [String],
    pub workers: u32,
    pub binary: Option<&'a str>,
    pub loopback: Option<std::net::Ipv4Addr>,
    pub steer_directions: &'a [VppSteerDirection],
    pub steer_exempts: &'a [packetframe_common::config::Ipv4Prefix],
}

pub fn probe_and_render(
    bpffs_root: &Path,
    attach_ifaces: &[String],
    vpp: &VppProbeInputs<'_>,
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
    // module. They carry their own `required` flags — the module marks
    // a verdict required exactly when its attach refuses the same
    // condition — and their names are remembered so the summary can
    // say "vpp-offload attach BLOCKED" instead of a bare FAIL (or,
    // worse, the bare PASS an operator on edge1-mci1-net read over a
    // failing `vpp.irq-affinity` line on 2026-08-21).
    #[cfg(feature = "vpp-offload")]
    let vpp_cap_names: Vec<String> = {
        let mut names = Vec::new();
        if !vpp.ports.is_empty() {
            for cap in packetframe_vpp_offload::run_feasibility_probes(
                vpp.ports,
                vpp.steer_ports,
                vpp.workers,
                vpp.binary,
                vpp.loopback,
                allowlist,
                vpp.steer_directions,
                vpp.steer_exempts,
            ) {
                names.push(cap.name.clone());
                report.capabilities.push(cap);
            }
        }
        names
    };
    #[cfg(not(feature = "vpp-offload"))]
    let vpp_cap_names: Vec<String> = {
        let _ = (vpp, allowlist);
        Vec::new()
    };
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
    let (core_blockers, vpp_blockers) = partition_blockers(&report, &vpp_cap_names);
    let vpp_blocked_only = core_blockers.is_empty() && !vpp_blockers.is_empty();

    if human {
        print_human(&report, &vpp_cap_names);
        Rendered {
            passed: report.passed,
            vpp_blocked_only,
            json_output: None,
        }
    } else {
        // The JSON carries what the human summary partitions on —
        // without it a machine consumer is left with exactly the
        // name-prefix guess `summary_lines` disavows (review finding
        // on #200).
        #[derive(serde::Serialize)]
        struct JsonReport<'a> {
            #[serde(flatten)]
            report: &'a FeasibilityReport,
            /// Required vpp-graft capabilities whose verdict is not
            /// Pass; empty when nothing blocks the module's attach.
            vpp_attach_blockers: Vec<&'a str>,
        }
        let json = serde_json::to_string_pretty(&JsonReport {
            report: &report,
            vpp_attach_blockers: vpp_blockers.iter().map(|c| c.name.as_str()).collect(),
        })
        .expect("FeasibilityReport is serializable");
        Rendered {
            passed: report.passed,
            vpp_blocked_only,
            json_output: Some(json),
        }
    }
}

/// Required-and-not-Pass capabilities, split into (core, vpp) by
/// membership in the vpp graft.
fn partition_blockers<'a>(
    report: &'a FeasibilityReport,
    vpp_cap_names: &[String],
) -> (Vec<&'a Capability>, Vec<&'a Capability>) {
    let (vpp, core): (Vec<&Capability>, Vec<&Capability>) = report
        .capabilities
        .iter()
        .filter(|c| c.required && c.status != CapabilityStatus::Pass)
        .partition(|c| vpp_cap_names.contains(&c.name));
    (core, vpp)
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

fn print_human(report: &FeasibilityReport, vpp_cap_names: &[String]) {
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
    for line in summary_lines(report, vpp_cap_names) {
        println!("{line}");
    }
}

/// The verdict under the table, and why it is not just `report.passed`
/// prose: the vpp-offload capabilities are `required` only because the
/// loaded config declares that module, and a box that is ready for
/// fast-path but would refuse the vpp-offload attach must say exactly
/// that. The previous summary said "PASS, all required capabilities
/// present." over a failing (then-advisory) `vpp.irq-affinity` on
/// edge1-mci1-net (2026-08-21), and the operator met the refusal at
/// attach instead of before the window.
///
/// `vpp_cap_names` is the set of capability names grafted from
/// vpp-offload's probes — membership, not a name-prefix guess, decides
/// which failures read as "attach BLOCKED".
fn summary_lines(report: &FeasibilityReport, vpp_cap_names: &[String]) -> Vec<String> {
    let (core, vpp_blockers) = partition_blockers(report, vpp_cap_names);
    if core.is_empty() && vpp_blockers.is_empty() {
        return vec!["Result: PASS, all required capabilities present.".into()];
    }
    let item = |c: &Capability| {
        format!(
            "  - {} ({})",
            scrub_for_terminal(&c.name),
            scrub_for_terminal(&c.detail)
        )
    };
    let mut lines = Vec::new();
    if core.is_empty() {
        // "core capabilities PASS", not "PASS for fast-path": a
        // non-required fast-path row (an xdp.attach trial) can FAIL in
        // the table above, and the summary must not assert a readiness
        // it did not check (review finding on #200).
        lines.push(format!(
            "Result: core capabilities PASS; vpp-offload attach BLOCKED by {} check{}:",
            vpp_blockers.len(),
            if vpp_blockers.len() == 1 { "" } else { "s" },
        ));
        lines.extend(vpp_blockers.iter().map(|c| item(c)));
    } else {
        lines.push(format!(
            "Result: FAIL, {} required capabilit{} missing or unknown:",
            core.len(),
            if core.len() == 1 { "y" } else { "ies" },
        ));
        lines.extend(core.iter().map(|c| item(c)));
        if !vpp_blockers.is_empty() {
            lines.push(format!(
                "vpp-offload attach is also BLOCKED by {} check{}:",
                vpp_blockers.len(),
                if vpp_blockers.len() == 1 { "" } else { "s" },
            ));
            lines.extend(vpp_blockers.iter().map(|c| item(c)));
        }
    }
    lines
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

/// Deliberately outside any `cfg(target_os)` gate: the vpp probes'
/// own tests only run on Linux (#45), but the summary's promise — no
/// PASS over a failing attach gate — is pure over `Capability` and
/// must hold on every host CI job.
#[cfg(test)]
mod summary_tests {
    use super::*;

    // A struct literal, not a match over CapabilityStatus: this helper
    // must keep compiling when the enum grows a variant on another
    // branch (review finding on #200/#201 — the two PRs merged cleanly
    // and the exhaustive match here broke main).
    fn cap(name: &str, status: CapabilityStatus, required: bool) -> Capability {
        Capability {
            name: name.into(),
            status,
            detail: "probe detail".into(),
            required,
        }
    }

    #[test]
    fn all_required_passing_is_still_a_plain_pass() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Pass, true),
            cap("vpp.irq-affinity", CapabilityStatus::Pass, true),
        ]);
        let lines = summary_lines(&report, &["vpp.irq-affinity".to_string()]);
        assert_eq!(
            lines,
            vec!["Result: PASS, all required capabilities present.".to_string()]
        );
    }

    /// The edge1-mci1-net case (2026-08-21): every core capability
    /// passes, a required vpp gate fails. The summary must not contain
    /// the sentence an operator reads as "the box is ready".
    #[test]
    fn a_failing_attach_gate_is_never_summarized_as_a_bare_pass() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Pass, true),
            cap("vpp.irq-affinity", CapabilityStatus::Fail, true),
        ]);
        let lines = summary_lines(&report, &["vpp.irq-affinity".to_string()]);
        assert_eq!(
            lines[0],
            "Result: core capabilities PASS; vpp-offload attach BLOCKED by 1 check:"
        );
        assert!(
            lines.iter().any(|l| l.contains("vpp.irq-affinity")),
            "the blocking check is named: {lines:?}"
        );
        assert!(
            !lines
                .iter()
                .any(|l| l.contains("all required capabilities present")),
            "{lines:?}"
        );
    }

    /// A required vpp verdict that came back Unknown blocks too — the
    /// same rule the core report applies ("we can't promise the
    /// runtime will find what it needs"), and on the gates it is
    /// literal: `bring_up` propagates the same read failure as a
    /// refusal.
    #[test]
    fn a_required_unknown_gate_also_blocks() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Pass, true),
            cap("vpp.iommu", CapabilityStatus::Unknown, true),
        ]);
        let lines = summary_lines(&report, &["vpp.iommu".to_string()]);
        assert!(lines[0].contains("BLOCKED by 1 check"), "{lines:?}");
    }

    /// An advisory vpp verdict (a staging steering-budget line) stays
    /// advisory: attach installs nothing, so the summary stays PASS.
    #[test]
    fn an_advisory_vpp_failure_does_not_block() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Pass, true),
            cap("vpp.steering.budget", CapabilityStatus::Fail, false),
        ]);
        let lines = summary_lines(&report, &["vpp.steering.budget".to_string()]);
        assert_eq!(
            lines,
            vec!["Result: PASS, all required capabilities present.".to_string()]
        );
    }

    /// A core capability failure keeps the FAIL wording — and when a
    /// vpp gate fails alongside it, both are reported, neither hidden
    /// behind the other.
    #[test]
    fn core_failures_keep_fail_wording_and_vpp_blockers_are_still_named() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Fail, true),
            cap("vpp.binary", CapabilityStatus::Fail, true),
        ]);
        let lines = summary_lines(&report, &["vpp.binary".to_string()]);
        assert_eq!(
            lines[0],
            "Result: FAIL, 1 required capability missing or unknown:"
        );
        assert!(lines.iter().any(|l| l.contains("bpf.core")), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|l| l.contains("vpp-offload attach is also BLOCKED by 1 check:")),
            "{lines:?}"
        );
        assert!(lines.iter().any(|l| l.contains("vpp.binary")), "{lines:?}");

        // Core-only failure: no vpp sentence at all.
        let core_only = FeasibilityReport::new(vec![cap("bpf.core", CapabilityStatus::Fail, true)]);
        let lines = summary_lines(&core_only, &[]);
        assert!(
            !lines.iter().any(|l| l.contains("vpp-offload")),
            "{lines:?}"
        );
    }
}
