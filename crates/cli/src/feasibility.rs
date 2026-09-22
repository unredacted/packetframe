//! Feasibility subcommand glue: run SPEC.md §2.1 probes and render the
//! report either as JSON (default) or as a human table. A per-interface
//! XDP trial-attach probe (§2.3) runs for each `attach`ed iface in the
//! config; it graduates the per-iface attach feasibility from Deferred
//! to a real pass/fail check.

use crate::scrub::scrub_for_terminal;
use std::path::PathBuf;

use packetframe_common::{
    config::{Config, ModuleDirective, VppSteerDirection},
    fib::IpPrefix,
    probe::{
        run_iface_probes, run_probes, sysctl_hugepages, Capability, CapabilityStatus,
        FeasibilityReport,
    },
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

/// The neigh-snoop inputs `probe_and_render` needs: the configured
/// bridges and the resolved persist directory. `bridges` is empty when
/// the module isn't configured, and the probes then stay out of the
/// report entirely.
#[derive(Debug, Default, Clone)]
pub struct NeighSnoopProbeInputs {
    pub bridges: Vec<String>,
    pub persist_dir: std::path::PathBuf,
    /// `frr-gate` `(v4 list, v6 list)` when configured.
    pub gate_lists: Option<(String, String)>,
}

pub fn neigh_snoop_probe_inputs_from_config(config: &Config) -> NeighSnoopProbeInputs {
    let mut out = NeighSnoopProbeInputs {
        bridges: Vec::new(),
        persist_dir: config
            .global
            .state_dir
            .join(packetframe_common::config::NEIGH_SNOOP_PERSIST_SUBDIR),
        gate_lists: None,
    };
    for m in &config.modules {
        if m.name != "neigh-snoop" {
            continue;
        }
        for d in &m.directives {
            match d {
                ModuleDirective::SnoopBridge { iface, .. } if !out.bridges.contains(iface) => {
                    out.bridges.push(iface.clone());
                }
                ModuleDirective::SnoopPersistDir { path, .. } => out.persist_dir = path.clone(),
                ModuleDirective::SnoopFrrGate {
                    v4_list, v6_list, ..
                } => out.gate_lists = Some((v4_list.clone(), v6_list.clone())),
                _ => {}
            }
        }
    }
    out
}

/// Bridges a `neigh-snoop` section flags `ix-mode`, for fast-path's
/// resolver. Empty when none are. Consumed by the Linux run path only,
/// hence unused on the stub platforms.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn neigh_snoop_ix_ifaces_from_config(config: &Config) -> Vec<String> {
    let mut out = Vec::new();
    for m in &config.modules {
        if m.name != "neigh-snoop" {
            continue;
        }
        for d in &m.directives {
            if let ModuleDirective::SnoopBridge {
                iface,
                ix_mode: true,
                ..
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

/// Interfaces named by `interface` lines in a `guard` section, if
/// any. Empty when the module isn't configured — the guard probes
/// then stay out of the report entirely.
pub fn guard_ifaces_from_config(config: &Config) -> Vec<String> {
    let mut ifaces = Vec::new();
    for m in &config.modules {
        if m.name != "guard" {
            continue;
        }
        for d in &m.directives {
            if let ModuleDirective::GuardInterface { iface, .. } = d {
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
///
/// **Last one wins**, here and in [`vpp_loopback_from_config`], because
/// last-wins is what `VppOffloadConfig::from_directives` hands attach —
/// it overwrites the field as it iterates, and parsing permits repeated
/// scalar directives. A first-wins `find_map` probed a different value
/// than the one attach acts on whenever a directive was repeated
/// (review finding on #200, against the loopback twin of this).
pub fn vpp_binary_from_config(config: &Config) -> Option<String> {
    config
        .modules
        .iter()
        .filter(|m| m.name == "vpp-offload")
        .flat_map(|m| &m.directives)
        .filter_map(|d| match d {
            ModuleDirective::VppBinary(p) => Some(p.clone()),
            _ => None,
        })
        .next_back()
}

/// The configured `loopback-address`, if any — `bring_up` refuses one
/// the kernel currently holds, so the `vpp.loopback` probe mirrors
/// that refusal (review finding on #200). Last-wins and scoped to
/// `vpp-offload` sections, exactly as `from_directives` resolves it;
/// see [`vpp_binary_from_config`].
pub fn vpp_loopback_from_config(config: &Config) -> Option<std::net::Ipv4Addr> {
    config
        .modules
        .iter()
        .filter(|m| m.name == "vpp-offload")
        .flat_map(|m| &m.directives)
        .filter_map(|d| match d {
            ModuleDirective::VppLoopbackAddress(p) => Some(p.addr),
            _ => None,
        })
        .next_back()
}

/// The vpp-offload facts the probes need, grouped so the parameter
/// list stops growing by one per directive (clippy agrees at eight).
#[derive(Debug, Default, Clone)]
pub struct VppProbeInputs {
    pub ports: Vec<String>,
    pub steer_ports: Vec<String>,
    pub workers: u32,
    pub binary: Option<String>,
    pub loopback: Option<std::net::Ipv4Addr>,
    pub steer_directions: Vec<VppSteerDirection>,
    pub steer_exempts: Vec<packetframe_common::config::Ipv4Prefix>,
}

/// Everything `probe_and_render` needs from the config, in one named
/// place. This was a 12-element tuple built in `main`, destructured
/// positionally: four of the fields are `Vec<String>` and two more are
/// prefix vectors, so swapping a pair compiled cleanly and silently
/// probed the wrong thing. Field names make that swap a type error or
/// an obvious misread.
pub struct FeasibilityInputs {
    pub bpffs_root: PathBuf,
    pub attach_ifaces: Vec<String>,
    pub allowlist: Vec<IpPrefix>,
    pub guard_ifaces: Vec<String>,
    pub vpp: VppProbeInputs,
    pub snoop: NeighSnoopProbeInputs,
}

impl Default for FeasibilityInputs {
    /// The no-`--config` pass: the default bpffs root, and no module
    /// configured, so every module's probes stay out of the report.
    /// `bpffs_root` is why this is hand-written — an empty `PathBuf`
    /// would probe the wrong mount.
    fn default() -> Self {
        Self {
            bpffs_root: PathBuf::from(packetframe_common::config::DEFAULT_BPFFS_ROOT),
            attach_ifaces: Vec::new(),
            allowlist: Vec::new(),
            guard_ifaces: Vec::new(),
            vpp: VppProbeInputs::default(),
            snoop: NeighSnoopProbeInputs::default(),
        }
    }
}

impl FeasibilityInputs {
    /// Collect the per-module extractors against one parsed config.
    /// Callers validate the config first; this only reads it.
    pub fn from_config(config: &Config) -> Self {
        Self {
            bpffs_root: config.global.bpffs_root.clone(),
            attach_ifaces: attach_ifaces_from_config(config),
            allowlist: allowlist_from_config(config),
            guard_ifaces: guard_ifaces_from_config(config),
            vpp: VppProbeInputs {
                ports: vpp_ports_from_config(config),
                steer_ports: vpp_steer_ports_from_config(config),
                workers: vpp_workers_from_config(config),
                binary: vpp_binary_from_config(config),
                loopback: vpp_loopback_from_config(config),
                steer_directions: vpp_steer_directions_from_config(config),
                steer_exempts: vpp_steer_exempts_from_config(config),
            },
            snoop: neigh_snoop_probe_inputs_from_config(config),
        }
    }
}

pub fn probe_and_render(inputs: &FeasibilityInputs, human: bool) -> Rendered {
    let FeasibilityInputs {
        bpffs_root,
        attach_ifaces,
        allowlist,
        guard_ifaces,
        vpp,
        snoop,
    } = inputs;
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
    // Read before the graft consumes `vpp`: the boot-sysctl promotion
    // below needs it whether or not this binary carries the module.
    let vpp_configured = !vpp.ports.is_empty();
    #[cfg(feature = "vpp-offload")]
    let vpp_cap_names: Vec<String> = {
        let mut names = Vec::new();
        if !vpp.ports.is_empty() {
            for cap in packetframe_vpp_offload::run_feasibility_probes(
                &vpp.ports,
                &vpp.steer_ports,
                vpp.workers,
                vpp.binary.as_deref(),
                vpp.loopback,
                allowlist,
                &vpp.steer_directions,
                &vpp.steer_exempts,
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
    // guard probes: only when the config declares the module. All
    // non-required (feasibility informs, the module's attach enforces).
    #[cfg(feature = "guard")]
    if !guard_ifaces.is_empty() {
        for cap in packetframe_guard::run_feasibility_probes(guard_ifaces) {
            report.capabilities.push(cap);
        }
    }
    #[cfg(not(feature = "guard"))]
    let _ = guard_ifaces;
    // neigh-snoop probes: only when the config declares the module.
    // All non-required; an absent bridge is a warning because the
    // module waits for it by name.
    #[cfg(feature = "neigh-snoop")]
    if !snoop.bridges.is_empty() {
        for cap in packetframe_neigh_snoop::run_feasibility_probes(
            &snoop.bridges,
            &snoop.persist_dir,
            snoop
                .gate_lists
                .as_ref()
                .map(|(a, b)| (a.as_str(), b.as_str())),
        ) {
            report.capabilities.push(cap);
        }
    }
    #[cfg(not(feature = "neigh-snoop"))]
    let _ = snoop;
    // The boot-sysctl audit is advisory in the general set — a large
    // `vm.nr_hugepages` is the operator's business on a box that runs
    // no VPP. On a box whose config declares `module vpp-offload` it
    // stops being advisory: installing VPP is what plants the
    // assignment, the damage lands at the NEXT BOOT rather than at
    // attach, and a report that says PASS over it is how a 64 GB router
    // got a 512 GiB hugepage request and never came back (2026-08-21).
    //
    // Promotion is deliberately not the same as joining the vpp graft:
    // this is a reboot hazard, not an attach blocker, and it is
    // partitioned separately below so the verdict says which one it is.
    if vpp_configured {
        if let Some(cap) = report
            .capabilities
            .iter_mut()
            .find(|c| c.name == sysctl_hugepages::PROBE_NAME)
        {
            cap.required = true;
        }
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
    let Blockers {
        core: core_blockers,
        vpp: vpp_blockers,
        boot: boot_blockers,
    } = partition_blockers(&report, &vpp_cap_names);
    // A boot hazard blocks the rollout without blocking the attach, so
    // it shares the module-blocked exit rather than the core-failure
    // one: "this box is not ready" without claiming fast-path is broken.
    let vpp_blocked_only =
        core_blockers.is_empty() && !(vpp_blockers.is_empty() && boot_blockers.is_empty());

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
            /// Boot-persistence hazards whose verdict is not Pass.
            ///
            /// Reported **regardless of `required`**, so this doubles as
            /// a standalone pre-reboot gate on a box that has no
            /// `vpp-offload` block yet — which is exactly the state a
            /// router is in between installing VPP and configuring the
            /// module, and exactly when the hazard is planted.
            boot_sysctl_blockers: Vec<&'a str>,
        }
        let json = serde_json::to_string_pretty(&JsonReport {
            report: &report,
            vpp_attach_blockers: vpp_blockers.iter().map(|c| c.name.as_str()).collect(),
            boot_sysctl_blockers: boot_blockers.iter().map(|c| c.name.as_str()).collect(),
        })
        .expect("FeasibilityReport is serializable");
        Rendered {
            passed: report.passed,
            vpp_blocked_only,
            json_output: Some(json),
        }
    }
}

/// Not-Pass capabilities, split by what they actually block.
struct Blockers<'a> {
    /// Required core capabilities: fast-path itself is not ready.
    core: Vec<&'a Capability>,
    /// Required vpp-graft capabilities: the module's attach is refused.
    vpp: Vec<&'a Capability>,
    /// Boot-persistence hazards: attach is fine, the next REBOOT is not.
    boot: Vec<&'a Capability>,
}

/// Split the not-Pass capabilities into what each one blocks.
///
/// Three buckets rather than two because "attach will be refused" and
/// "the next boot will not come back" are different verdicts with
/// different remedies, and filing one under the other is how an
/// operator reads past it. The boot bucket ignores `required` on
/// purpose: the hazard is planted by installing VPP, which happens
/// before there is a `vpp-offload` block to promote the check, so this
/// has to answer on a box where the capability is still advisory.
fn partition_blockers<'a>(report: &'a FeasibilityReport, vpp_cap_names: &[String]) -> Blockers<'a> {
    let is_boot_hazard =
        |c: &Capability| c.name == packetframe_common::probe::sysctl_hugepages::PROBE_NAME;
    let boot: Vec<&Capability> = report
        .capabilities
        .iter()
        .filter(|c| is_boot_hazard(c) && c.status != CapabilityStatus::Pass)
        .collect();
    let (vpp, core): (Vec<&Capability>, Vec<&Capability>) = report
        .capabilities
        .iter()
        .filter(|c| c.required && c.status != CapabilityStatus::Pass && !is_boot_hazard(c))
        .partition(|c| vpp_cap_names.contains(&c.name));
    Blockers { core, vpp, boot }
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
    let Blockers {
        core,
        vpp: vpp_blockers,
        boot: boot_blockers,
    } = partition_blockers(report, vpp_cap_names);
    let item = |c: &Capability| {
        format!(
            "  - {} ({})",
            scrub_for_terminal(&c.name),
            scrub_for_terminal(&c.detail)
        )
    };
    // The boot hazard gets its own sentence wherever it appears. It
    // does not block the attach, so folding it into the attach verdict
    // would be wrong in both directions: it would overstate the attach
    // problem and understate a fault whose blast radius is the whole
    // box on next boot.
    let boot_lines = |lines: &mut Vec<String>| {
        if !boot_blockers.is_empty() {
            lines.push(format!(
                "REBOOT HAZARD: {} boot-persistent sysctl check{} not passing. \
                 The attach is unaffected; the next boot may be:",
                boot_blockers.len(),
                if boot_blockers.len() == 1 {
                    " is"
                } else {
                    "s are"
                },
            ));
            lines.extend(boot_blockers.iter().map(|c| item(c)));
        }
    };
    if core.is_empty() && vpp_blockers.is_empty() {
        if boot_blockers.is_empty() {
            return vec!["Result: PASS, all required capabilities present.".into()];
        }
        // A PROMOTED boot hazard makes `report.passed` false and the
        // exit code 3, so the headline must not also say every required
        // capability passed. One invocation printing "PASS" beside
        // `"passed": false` is a contradiction a parser resolves
        // arbitrarily and a tired operator resolves optimistically.
        //
        // The attach verdict stays separate either way: this blocks the
        // rollout, not the attach, and saying so is the whole reason
        // the hazard has its own bucket.
        let n = boot_blockers.len();
        let mut lines = vec![if boot_blockers.iter().any(|c| c.required) {
            format!(
                "Result: ROLLOUT BLOCKED by {n} boot-persistence check{}; \
                 the attach itself is unaffected:",
                if n == 1 { "" } else { "s" },
            )
        } else {
            format!(
                "Result: required capabilities PASS, but {n} boot-persistence check{} \
                 not passing; the attach itself is unaffected:",
                if n == 1 { " is" } else { "s are" },
            )
        }];
        lines.extend(boot_blockers.iter().map(|c| item(c)));
        return lines;
    }
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
    boot_lines(&mut lines);
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
        CapabilityStatus::Warn => "WARN",
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

    /// The scalar extractors resolve repeated directives exactly as
    /// `VppOffloadConfig::from_directives` does (last wins) — asserted
    /// against `from_directives` itself, so the two cannot drift
    /// silently. A first-wins `find_map` here probed the first
    /// `loopback-address` while attach refused (or accepted) the last
    /// (review finding on #200).
    #[cfg(feature = "vpp-offload")]
    #[test]
    fn scalar_extractors_pick_the_directive_attach_acts_on() {
        use packetframe_common::config::{GlobalConfig, Ipv4Prefix, ModuleSection};

        let lo = |a: u8| Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, a),
            prefix_len: 32,
        };
        let directives = vec![
            ModuleDirective::VppBinary("/opt/vpp-first".into()),
            ModuleDirective::VppLoopbackAddress(lo(1)),
            ModuleDirective::VppBinary("/opt/vpp-last".into()),
            ModuleDirective::VppLoopbackAddress(lo(2)),
        ];
        let config = Config {
            global: GlobalConfig::default(),
            modules: vec![ModuleSection {
                name: "vpp-offload".into(),
                directives: directives.clone(),
            }],
        };
        let runtime = packetframe_vpp_offload::VppOffloadConfig::from_directives(&directives);
        assert_eq!(vpp_binary_from_config(&config), runtime.vpp_binary);
        assert_eq!(
            vpp_loopback_from_config(&config),
            runtime.loopback_address.map(|p| p.addr)
        );
        assert_eq!(
            vpp_binary_from_config(&config).as_deref(),
            Some("/opt/vpp-last")
        );
    }

    /// A config whose same-typed fields all hold different values, so
    /// a cross-wired assignment in `from_config` cannot pass by
    /// coincidence. Four `Vec<String>` fields and two prefix vectors
    /// is exactly the shape that made the old positional tuple
    /// dangerous: a swap there compiled and probed the wrong thing.
    const CROSS_WIRING_CONFIG: &str = "\
global
  bpffs-root /sys/fs/bpf/pf-test
  state-dir /var/lib/pf-test
module fast-path
  attach fp0 native
  attach fp1 native
  allow-prefix 198.51.100.0/24
  allow-prefix6 2001:db8:1::/48
module guard
  interface gd0
module vpp-offload
  port vp0 cores 2 steer on
  port vp1 cores 2 steer off
  vpp-binary /opt/vpp-test
  loopback-address 203.0.113.9/32
  steer-direction dst
  steer-exempt 192.0.2.0/24
module neigh-snoop
  bridge ns0
  persist-dir /var/lib/pf-test/snoop
  frr-gate v4 pf-v4 v6 pf-v6
";

    /// Every field of `FeasibilityInputs` carries what its own
    /// extractor returns. Asserted against the extractors rather than
    /// against literals so this cannot drift when a directive's
    /// resolution rules change — the only thing pinned here is the
    /// wiring.
    #[test]
    fn from_config_wires_each_field_to_its_own_extractor() {
        let config = Config::parse(CROSS_WIRING_CONFIG).expect("parse");
        let inputs = FeasibilityInputs::from_config(&config);

        assert_eq!(inputs.bpffs_root, config.global.bpffs_root);
        assert_eq!(inputs.attach_ifaces, attach_ifaces_from_config(&config));
        assert_eq!(inputs.allowlist, allowlist_from_config(&config));
        assert_eq!(inputs.guard_ifaces, guard_ifaces_from_config(&config));
        assert_eq!(inputs.vpp.ports, vpp_ports_from_config(&config));
        assert_eq!(inputs.vpp.steer_ports, vpp_steer_ports_from_config(&config));
        assert_eq!(inputs.vpp.workers, vpp_workers_from_config(&config));
        assert_eq!(inputs.vpp.binary, vpp_binary_from_config(&config));
        assert_eq!(inputs.vpp.loopback, vpp_loopback_from_config(&config));
        assert_eq!(
            inputs.vpp.steer_directions,
            vpp_steer_directions_from_config(&config)
        );
        assert_eq!(
            inputs.vpp.steer_exempts,
            vpp_steer_exempts_from_config(&config)
        );
        let snoop = neigh_snoop_probe_inputs_from_config(&config);
        assert_eq!(inputs.snoop.bridges, snoop.bridges);
        assert_eq!(inputs.snoop.persist_dir, snoop.persist_dir);
        assert_eq!(inputs.snoop.gate_lists, snoop.gate_lists);
    }

    /// The assertions above only discriminate a swap if the fields
    /// they compare actually differ. Guard that premise: if a future
    /// edit makes two of these identical, the wiring test silently
    /// stops testing anything and this one says so.
    #[test]
    fn cross_wiring_config_gives_every_same_typed_field_a_distinct_value() {
        let config = Config::parse(CROSS_WIRING_CONFIG).expect("parse");
        let inputs = FeasibilityInputs::from_config(&config);

        let string_vecs = [
            ("attach_ifaces", &inputs.attach_ifaces),
            ("guard_ifaces", &inputs.guard_ifaces),
            ("vpp.ports", &inputs.vpp.ports),
            ("vpp.steer_ports", &inputs.vpp.steer_ports),
            ("snoop.bridges", &inputs.snoop.bridges),
        ];
        for (i, (na, a)) in string_vecs.iter().enumerate() {
            assert!(!a.is_empty(), "{na} is empty, so it discriminates nothing");
            for (nb, b) in &string_vecs[i + 1..] {
                assert_ne!(a, b, "{na} and {nb} are indistinguishable");
            }
        }
        assert!(!inputs.allowlist.is_empty());
        assert!(!inputs.vpp.steer_exempts.is_empty());
    }

    /// The `None` arm: no config means the default bpffs root — not
    /// an empty path — and no module configured, so every module's
    /// probes stay out of the report.
    #[test]
    fn default_inputs_probe_the_default_bpffs_root_and_no_module() {
        let inputs = FeasibilityInputs::default();
        assert_eq!(
            inputs.bpffs_root,
            PathBuf::from(packetframe_common::config::DEFAULT_BPFFS_ROOT)
        );
        assert!(inputs.attach_ifaces.is_empty());
        assert!(inputs.allowlist.is_empty());
        assert!(inputs.guard_ifaces.is_empty());
        assert!(inputs.vpp.ports.is_empty());
        assert!(inputs.vpp.steer_ports.is_empty());
        assert_eq!(inputs.vpp.workers, 0);
        assert!(inputs.vpp.binary.is_none());
        assert!(inputs.vpp.loopback.is_none());
        assert!(inputs.vpp.steer_directions.is_empty());
        assert!(inputs.vpp.steer_exempts.is_empty());
        assert!(inputs.snoop.bridges.is_empty());
        assert!(inputs.snoop.gate_lists.is_none());
    }

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

    /// A boot hazard is reported even when it is still advisory, and
    /// never as an attach blocker.
    ///
    /// This is the state a router is in between installing VPP and
    /// adding the `vpp-offload` block — exactly when the hazard is
    /// planted, and exactly when the capability is not yet `required`.
    /// A gate that only answered for a configured box would have
    /// nothing to say at the reboot that matters.
    #[test]
    fn an_advisory_boot_hazard_is_still_reported_and_is_not_an_attach_blocker() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Pass, true),
            cap(sysctl_hugepages::PROBE_NAME, CapabilityStatus::Fail, false),
        ]);
        let blockers = partition_blockers(&report, &[]);
        assert!(
            blockers.core.is_empty(),
            "a boot hazard is not a core fault"
        );
        assert!(
            blockers.vpp.is_empty(),
            "a boot hazard is not an attach blocker"
        );
        assert_eq!(blockers.boot.len(), 1);

        let lines = summary_lines(&report, &[]);
        assert!(
            !lines.iter().any(|l| l.contains("BLOCKED")),
            "advisory, and no attach blocker: nothing here is blocked: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains(sysctl_hugepages::PROBE_NAME)),
            "the hazard must still be named: {lines:?}"
        );
    }

    /// Promoted to `required`, it still does not become an attach
    /// blocker — and it still does not make the run a core FAIL, which
    /// would claim fast-path itself is not ready.
    #[test]
    fn a_promoted_boot_hazard_stays_in_its_own_bucket() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Pass, true),
            cap("vpp.iommu", CapabilityStatus::Pass, true),
            cap(sysctl_hugepages::PROBE_NAME, CapabilityStatus::Fail, true),
        ]);
        let blockers = partition_blockers(&report, &["vpp.iommu".to_string()]);
        assert!(blockers.core.is_empty());
        assert!(blockers.vpp.is_empty());
        assert_eq!(blockers.boot.len(), 1);
    }

    /// ...and the summary must not then claim every required capability
    /// passed. Promotion makes `report.passed` false and the exit code
    /// 3; a headline of "PASS" beside that is a contradiction one
    /// invocation should never emit (review finding on #225 — the
    /// bucket test above passed while the prose said the opposite).
    #[test]
    fn a_promoted_boot_hazard_is_never_summarized_as_a_pass() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Pass, true),
            cap(sysctl_hugepages::PROBE_NAME, CapabilityStatus::Fail, true),
        ]);
        assert!(!report.passed, "promotion must fail the report");

        let lines = summary_lines(&report, &[]);
        assert!(
            !lines.iter().any(|l| l.contains("PASS, all required")),
            "the report is not passing; the summary must not say it is: {lines:?}"
        );
        assert!(
            lines[0].starts_with("Result: ROLLOUT BLOCKED by 1 boot-persistence check;"),
            "{lines:?}"
        );
        assert!(
            lines[0].contains("the attach itself is unaffected"),
            "the attach verdict stays separate: {lines:?}"
        );
    }

    /// The advisory case still says the required capabilities passed —
    /// because they did, and `report.passed` is true — but does not
    /// leave it at that.
    #[test]
    fn an_advisory_boot_hazard_qualifies_the_pass_rather_than_blocking() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Pass, true),
            cap(sysctl_hugepages::PROBE_NAME, CapabilityStatus::Fail, false),
        ]);
        assert!(
            report.passed,
            "an advisory failure does not fail the report"
        );

        let lines = summary_lines(&report, &[]);
        assert!(
            lines[0].starts_with("Result: required capabilities PASS, but 1 boot-persistence"),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.contains(sysctl_hugepages::PROBE_NAME)),
            "the hazard is still named: {lines:?}"
        );
    }

    /// A boot hazard alongside a real attach blocker: both are stated,
    /// in their own words.
    #[test]
    fn a_boot_hazard_and_an_attach_blocker_are_reported_separately() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Pass, true),
            cap("vpp.irq-affinity", CapabilityStatus::Fail, true),
            cap(sysctl_hugepages::PROBE_NAME, CapabilityStatus::Fail, true),
        ]);
        let lines = summary_lines(&report, &["vpp.irq-affinity".to_string()]);
        assert_eq!(
            lines[0],
            "Result: core capabilities PASS; vpp-offload attach BLOCKED by 1 check:"
        );
        assert!(
            lines.iter().any(|l| l.contains("vpp.irq-affinity")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.starts_with("REBOOT HAZARD:")),
            "{lines:?}"
        );
    }

    /// A passing boot check says nothing at all.
    #[test]
    fn a_passing_boot_check_adds_no_line() {
        let report = FeasibilityReport::new(vec![
            cap("bpf.core", CapabilityStatus::Pass, true),
            cap(sysctl_hugepages::PROBE_NAME, CapabilityStatus::Pass, true),
        ]);
        assert!(partition_blockers(&report, &[]).boot.is_empty());
        assert_eq!(
            summary_lines(&report, &[]),
            vec!["Result: PASS, all required capabilities present.".to_string()]
        );
    }
}
