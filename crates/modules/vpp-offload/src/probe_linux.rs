//! Linux feasibility probes for the vpp-offload module (plan v5).
//!
//! Everything here mirrors the fast-path probe philosophy: read-only,
//! and each verdict names its fix inline. Probes cover the layers
//! proven live on the reference EFG (2026-08-01): active IOMMU, SR-IOV
//! capacity, VFIO device nodes, hugepage pools, and the VPP binary.
//!
//! Severity mirrors attach. These probes run only when the loaded
//! config declares the module, and each one probes a condition
//! `bring_up`/`acquire` refuses or cannot survive — so they are
//! `required`, and a FAIL is an attach refusal the operator has not
//! hit yet. They were advisory once, and an operator on edge1-mci1-net
//! (2026-08-21) read the summary's "PASS" over a failing
//! `vpp.irq-affinity` line and met the refusal at attach instead. The
//! one exception is per-verdict: steering-budget verdicts gate only
//! when a port is configured `steer on`, because attach queries and
//! plans nothing otherwise (`ifaces_to_query`).

use std::fs;
use std::path::Path;

use packetframe_common::probe::Capability;

use crate::nic::PortNic;

// One argument per attach-gated directive; the CLI groups them in
// `VppProbeInputs`, the module boundary keeps plain args.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    ports: &[String],
    steer_ports: &[String],
    workers: u32,
    vpp_binary: Option<&str>,
    loopback: Option<std::net::Ipv4Addr>,
    allowlist: &[packetframe_common::fib::IpPrefix],
    directions: &[packetframe_common::config::VppSteerDirection],
    steer_exempts: &[packetframe_common::config::Ipv4Prefix],
    steer_capacity: Option<u16>,
    section: &[packetframe_common::config::ModuleDirective],
) -> Vec<Capability> {
    let mut caps = Vec::with_capacity(6 + 2 * ports.len());
    // The NIC first: on any other one, every verdict below describes
    // hardware this module would refuse anyway. Read once, so the driver
    // lines and the steering-budget decision below cannot disagree.
    let nics: Vec<(&String, std::io::Result<PortNic>)> = ports
        .iter()
        .map(|p| (p, crate::nic::port_nic_in(Path::new("/sys/class/net"), p)))
        .collect();
    for (iface, read) in &nics {
        caps.push(probe_driver(iface, read));
    }
    caps.push(probe_iommu());
    caps.push(probe_vfio());
    caps.push(probe_hugepages());
    caps.push(probe_irq_affinity(ports, workers));
    if let Some(addr) = loopback {
        caps.push(probe_loopback(addr));
    }
    // Read from the section as attach reads it, like the v6 steering
    // plan below.
    if let Some(addr) = crate::VppOffloadConfig::from_directives(section).loopback_address6 {
        caps.push(probe_loopback6(addr));
    }
    // Probe the binary the module will ACTUALLY exec. Probing the
    // defaults while the config names another path would report a pass
    // for an executable we never run (or a failure for one that
    // exists) — a capability line describing a different program than
    // the module uses is worse than no line.
    caps.push(probe_vpp_binary(vpp_binary));
    for iface in ports {
        caps.push(probe_sriov(iface));
    }
    // The v6 half of each port's plan, from the section exactly as attach
    // derives it — `VppOffloadConfig::v6_steering`, `vlans all` VIDs held
    // to the kernel bridge included.
    let v6cfg = crate::VppOffloadConfig::from_directives(section);
    let v6_for = |port: &str| v6cfg.v6_steering(port, &crate::topology::kernel_tagged_vlans);
    // The plan is the supported NIC's rule table. Asked of another
    // driver, the same ioctl and devlink reads answer about a table this
    // module would never program, so the line would be a verdict on the
    // wrong hardware. The driver lines above already block the summary.
    let foreign: Vec<&str> = nics
        .iter()
        .filter(|(_, read)| !matches!(read, Ok(PortNic::Supported)))
        .map(|(p, _)| p.as_str())
        .collect();
    caps.push(if foreign.is_empty() {
        probe_steering_budget_v6(
            ports,
            steer_ports,
            allowlist,
            directions,
            steer_exempts,
            steer_capacity,
            &crate::topology::kernel_receive_macs,
            &v6_for,
        )
    } else {
        Capability::unknown(
            "vpp.steering.budget",
            format!(
                "not planned: {foreign:?} are not on `{}`, the only NIC whose rule table \
                 steering programs (see their `driver` lines)",
                crate::nic::SUPPORTED_PF_DRIVER
            ),
            false,
        )
    });
    caps
}

/// One member port's NIC, as attach's gate judges it
/// ([`crate::nic::check_ports_in`]): the same read, the same reasons.
/// Required on every arm, since attach refuses whatever is not a PASS.
fn probe_driver(iface: &str, read: &std::io::Result<PortNic>) -> Capability {
    let name = format!("vpp.{iface}.driver");
    match (read, crate::nic::unsupported_reason(iface, read)) {
        (_, None) => Capability::pass(
            &name,
            format!(
                "`{}` (Marvell OCTEON), the NIC this module drives",
                crate::nic::SUPPORTED_PF_DRIVER
            ),
            true,
        ),
        (Err(_), Some(why)) => Capability::unknown(
            &name,
            format!("{why} — attach refuses a port it cannot identify"),
            true,
        ),
        (Ok(nic), Some(why)) => {
            // Only another driver is a hardware answer; a driverless
            // netdev is a `port` line naming the wrong device.
            let elsewhere = if matches!(nic, PortNic::Other(_)) {
                ". The eBPF fast-path runs on this NIC without the vpp-offload section"
            } else {
                ""
            };
            Capability::fail(
                &name,
                format!(
                    "{why} — attach will refuse; {}{elsewhere}",
                    crate::nic::SUPPORTED_NIC
                ),
                true,
            )
        }
    }
}

/// Do any NIC queue IRQs currently fire on the cores VPP would burn?
///
/// The probe that was missing before the first primary attach
/// (2026-08-13): feasibility passed, and then six poll-mode workers
/// landed on CPUs carrying production rx-queue IRQs — the exact overlap
/// this reads off `/proc/irq` in seconds. Attach enforces the same
/// check (`cores::nic_irq_conflicts`); this surfaces it before a
/// maintenance window instead of during one.
fn probe_irq_affinity(ports: &[String], workers: u32) -> Capability {
    use std::path::Path;
    let name = "vpp.irq-affinity";
    // Required on every arm: `bring_up` runs this same derivation and
    // check behind `?`, so an Unknown here (the derive failing) is the
    // same refusal a conflict is.
    let map = match crate::cores::derive_from_sysfs(Path::new(crate::cores::SYSFS_CPU), workers) {
        Ok(m) => m,
        Err(e) => return Capability::unknown(name, format!("derive core map: {e}"), true),
    };
    let mut vpp_cores = vec![map.main];
    vpp_cores.extend(&map.workers);
    match crate::cores::nic_irq_conflicts(
        Path::new("/sys/class/net"),
        Path::new("/proc/irq"),
        ports,
        &vpp_cores,
    ) {
        Ok(c) if c.is_empty() => Capability::pass(
            name,
            format!(
                "no NIC queue IRQ fires on the derived VPP cores (main {}, workers {:?})",
                map.main, map.workers
            ),
            true,
        ),
        Ok(c) => {
            let sample: Vec<String> = c
                .iter()
                .take(8)
                .map(|x| format!("{} irq {} -> cpu {:?}", x.iface, x.irq, x.cpus))
                .collect();
            // Attach re-pins these itself now, so failing feasibility
            // over them would block a rollout over something attach
            // usually corrects. But "usually" is all a read-only probe
            // can say: a kernel-managed IRQ accepts or rejects the mask
            // only when written, and whether delivery then moves is
            // only known by reading it back — which attach does, and
            // refuses on. So a fixable conflict is a non-required WARN,
            // never a PASS: the probe does not promise what attach will
            // find (review finding, PR #238). No CPU to move them to is
            // knowable here, and still fails, required.
            let safe = match crate::cores::read_cpu_topology(Path::new(crate::cores::SYSFS_CPU)) {
                Ok((online, isolated)) => {
                    crate::cores::irq_safe_cpus(&online, &isolated, &vpp_cores)
                }
                Err(e) => {
                    return Capability::unknown(name, format!("read CPU topology: {e}"), true)
                }
            };
            if safe.is_empty() {
                return Capability::fail(
                    name,
                    format!(
                        "{} NIC queue IRQ(s) fire on the derived VPP cores (main {}, workers \
                         {:?}): {}{} — and no CPU is left outside VPP's cores and the \
                         isolated set to move them to, so attach will refuse. Reduce the \
                         `cores` totals or free an isolated CPU",
                        c.len(),
                        map.main,
                        map.workers,
                        sample.join(", "),
                        if c.len() > 8 { ", ..." } else { "" },
                    ),
                    true,
                );
            }
            Capability::warn(
                name,
                format!(
                    "{} NIC queue IRQ(s) currently fire on the derived VPP cores (main {}, \
                     workers {:?}): {}{} — attach will re-pin them onto CPUs in {} before \
                     starting VPP, and refuses if the kernel does not then move delivery \
                     (a kernel-managed IRQ ignores the mask). That cannot be known without \
                     writing the mask, which this probe never does",
                    c.len(),
                    map.main,
                    map.workers,
                    sample.join(", "),
                    if c.len() > 8 { ", ..." } else { "" },
                    crate::cores::format_cpu_list(&safe),
                ),
                false,
            )
        }
        Err(e) => Capability::unknown(name, e, true),
    }
}

/// Can the configured allowlist actually be steered?
///
/// Two answers an operator wants before the canary and not during it.
/// **Does it fit MCAM** — the rules are two per v4 prefix and the table
/// is shared with UniFi's own, so an allowlist that overruns the budget
/// cannot be steered at all (partially steering it would split the
/// allowlist across both forwarding tiers, which is a policy nobody
/// chose, so it is refused whole). And **how much of it is v6**, which
/// cannot be steered BY PREFIX on this NIC at any size: an `ip6` rule
/// naming an address is rejected by the AF, so a v6-heavy allowlist
/// means the offload covers far less traffic than the config reads like
/// it does. (`v6-divert` diverts v6 by frame instead, per port; its
/// rules are planned here too — see [`probe_steering_budget_v6`].)
///
/// Read-only, like every probe here: it computes the plan the module
/// would install, and installs nothing. Required exactly when a port
/// is configured `steer on` — those verdicts are attach refusals
/// (`bring_up` runs the same steerable check and plan behind `?`);
/// with every port `steer off`, attach queries and plans nothing
/// (`ifaces_to_query`), so a staging verdict advises the future canary
/// lever and must not block a feasibility attach would accept.
///
/// **The budget comes from the NIC.** This used to plan against
/// `McamBudget::default()` and report whether the arithmetic held — a
/// constant checked against itself, which passed while every insert the
/// module would issue was rejected, because the constant named a slot
/// 1008 past the end of the table. A probe whose answer cannot disagree
/// with the code it is probing is not a probe.
#[cfg(test)]
fn probe_steering_budget(
    member_ports: &[String],
    steer_ports: &[String],
    allowlist: &[packetframe_common::fib::IpPrefix],
    directions: &[packetframe_common::config::VppSteerDirection],
    steer_exempts: &[packetframe_common::config::Ipv4Prefix],
    steer_capacity: Option<u16>,
    receive_macs: &dyn Fn(&str) -> Vec<[u8; 6]>,
) -> Capability {
    probe_steering_budget_v6(
        member_ports,
        steer_ports,
        allowlist,
        directions,
        steer_exempts,
        steer_capacity,
        receive_macs,
        &|_: &str| Ok(crate::steer::V6Steering::default()),
    )
}

/// [`probe_steering_budget`] with each port's `v6-divert` half
/// (`v6_for`), planned as attach plans it: a port with v6 to divert has
/// something to steer whatever the allowlist holds, and its v6 rules
/// count against the same slots. Planned with the largest v6 set among
/// the candidate ports, the same conservative stand-in the receive-MAC
/// set already is.
#[allow(clippy::too_many_arguments)]
fn probe_steering_budget_v6(
    member_ports: &[String],
    steer_ports: &[String],
    allowlist: &[packetframe_common::fib::IpPrefix],
    directions: &[packetframe_common::config::VppSteerDirection],
    steer_exempts: &[packetframe_common::config::Ipv4Prefix],
    steer_capacity: Option<u16>,
    receive_macs: &dyn Fn(&str) -> Vec<[u8; 6]>,
    v6_for: &dyn Fn(&str) -> Result<crate::steer::V6Steering, String>,
) -> Capability {
    use crate::steer::McamBudget;

    // Tables as attach will find them once `steer-capacity` has been
    // applied: a resizable, empty table is planned at the requested
    // size. Nothing is written — the probe runs against a live box.
    let predicted = std::cell::Cell::new(false);
    let read = |iface: &str| {
        crate::capacity::predicted_table(&crate::capacity::Live, iface, steer_capacity).map(
            |(t, p)| {
                predicted.set(predicted.get() | p);
                t
            },
        )
    };

    let name = "vpp.steering.budget";
    // Whether this probe's verdicts gate attach: `bring_up` refuses an
    // unsteerable or over-budget plan only when something steers.
    let gating = !steer_ports.is_empty();
    // The ALLOWLIST question first, because it needs no NIC — the same
    // ordering `bring_up` documents and for the same reason: an
    // operator who wrote `steer on` against a v6-only allowlist must
    // read about their allowlist, not about whatever the ioctl said.
    let steerable = crate::steer::steerable_count(allowlist);
    // `v6-divert` is the other thing a port can steer, and it too needs
    // no NIC to settle — only the kernel bridge, for a `vlans all` trunk.
    let candidates: &[String] = if gating { steer_ports } else { member_ports };
    let mut v6_of: Vec<(&str, crate::steer::V6Steering)> = Vec::new();
    let mut v6_ports: Vec<&str> = Vec::new();
    for port in candidates {
        match v6_for(port) {
            Ok(s) => {
                if !s.vlans.is_empty() {
                    v6_ports.push(port.as_str());
                }
                v6_of.push((port.as_str(), s));
            }
            Err(e) => return Capability::fail(name, e, gating),
        }
    }
    let v6_for_port = |port: &str| {
        v6_of
            .iter()
            .find(|(p, _)| *p == port)
            .map(|(_, s)| s.clone())
            .unwrap_or_default()
    };
    // Attach refuses a `steer on` port with nothing to divert, per port;
    // staging advises only when no candidate could divert anything.
    let idle: Vec<&str> = candidates
        .iter()
        .map(String::as_str)
        .filter(|p| !v6_ports.contains(p))
        .collect();
    let refuses = if gating {
        !idle.is_empty()
    } else {
        v6_ports.is_empty()
    };
    if steerable == 0 && refuses {
        let also = if v6_ports.is_empty() {
            String::new()
        } else {
            format!("; {v6_ports:?} divert IPv6 (`v6-divert`) but {idle:?} would steer nothing")
        };
        return Capability::fail(
            name,
            if allowlist.is_empty() {
                format!(
                    "the fast-path allowlist is empty, so there is nothing to steer. Steered \
                     prefixes are inherited from fast-path's `allow-prefix`/`allow-prefix6`; \
                     without any, the offload would forward nothing while reporting \
                     healthy{also}"
                )
            } else {
                format!(
                    "none of the allowlist can be steered: all {} prefix(es) are IPv6, and \
                     `ip6` ntuple cannot match a v6 address on this NIC's AF (gate 0b round \
                     4). The offload would forward nothing while reporting healthy{also}",
                    allowlist.len()
                )
            },
            gating,
        );
    }

    // Which NICs to ask, and how strictly.
    //
    // Ports that STEER get exactly attach's treatment: the same set
    // `ifaces_to_query` uses, read through the same strict
    // `for_ifaces`, so an unreadable steering port fails here for the
    // reason it will fail there. Leniency on that path would let
    // feasibility PASS a configuration attach refuses (review finding
    // on this PR) — the probe may be softer than attach about ports
    // attach has nothing to say about, and never about the ones it
    // does.
    if !steer_ports.is_empty() {
        let budget = match McamBudget::for_ifaces_with(steer_ports.iter().map(String::as_str), read)
        {
            Ok(b) => b,
            Err(e) => {
                return Capability::fail(
                    name,
                    format!(
                        "{e} — this port is configured `steer on`, so attach will refuse the \
                         same way; check `ip -br link`, an administratively DOWN port answers \
                         like this"
                    ),
                    true,
                )
            }
        };
        // The receive MACs attach will scope each port's diversions to,
        // and its refusal when a port's cannot be read. Each port is
        // planned with ITS OWN MACs and v6 VLANs, as `plan_targets` plans
        // it: the largest MAC set of one port times the most VLANs of
        // another is a rule set no real port needs, and failing on it
        // refused configs attach accepts (review finding).
        let mut ports: Vec<PortPlanInputs> = Vec::new();
        for port in steer_ports {
            let macs = receive_macs(port);
            if macs.is_empty() {
                return Capability::fail(
                    name,
                    format!(
                        "cannot read the MAC(s) frames to this router arrive with on {port}; \
                         attach refuses to steer it, since rules without them would divert \
                         frames the kernel is only bridging"
                    ),
                    true,
                );
            }
            ports.push((port.as_str(), macs, v6_for_port(port)));
        }
        return plan_and_report(
            name,
            budget,
            steer_ports.iter().map(String::as_str).collect(),
            Vec::new(),
            false,
            requested_note(predicted.get(), steer_capacity),
            allowlist,
            directions,
            steer_exempts,
            &ports,
        );
    }

    // STAGING: every port is `steer off`, which is the state
    // feasibility is usually run in and the state the first canary
    // step starts from. The candidates are the members — any of them
    // could be the port the operator turns on — and here the read IS
    // lenient: an administratively DOWN idle member (the reference
    // primary's uncabled eth5) must not hide the arithmetic for the
    // ports that answered, because attach is not querying it either.
    //
    // What must NOT happen is the empty-candidate fallback: with no
    // NIC read at all, `McamBudget::for_ifaces` yields its synthetic
    // 16-slot table, and reporting PASS on that constant let a canary
    // NIC with occupied slots pass here and fail at the lever (review
    // finding). No reading, no verdict.
    let mut budget: Option<McamBudget> = None;
    let mut consulted: Vec<&str> = Vec::new();
    let mut skipped: Vec<String> = Vec::new();
    for iface in member_ports {
        match read(iface) {
            Ok(table) => {
                let next = McamBudget::from_table(&table);
                budget = Some(match budget {
                    None => next,
                    // The intersection, as `for_ifaces` takes it: one
                    // plan installs at the same locations on every
                    // steering port, so a slot free on one and taken
                    // on another is not a slot.
                    Some(prev) => McamBudget {
                        free: prev
                            .free
                            .into_iter()
                            .filter(|loc| next.free.contains(loc))
                            .collect(),
                    },
                });
                consulted.push(iface.as_str());
            }
            Err(e) => skipped.push(format!("{iface} ({e})")),
        }
    }
    let Some(budget) = budget else {
        return Capability::unknown(
            name,
            if skipped.is_empty() {
                "no candidate port to query, so the MCAM budget is unknown rather than proven"
                    .to_string()
            } else {
                format!(
                    "no candidate port could be read ({}), so the MCAM budget is unknown \
                     rather than proven; check `ip -br link` — a port that is \
                     administratively DOWN answers this way",
                    skipped.join(", ")
                )
            },
            false,
        );
    };
    // Any consulted member could be the one turned on: plan each with its
    // own receive MACs and v6 VLANs, and report the worst real port.
    let ports: Vec<PortPlanInputs> = consulted
        .iter()
        .map(|p| (*p, receive_macs(p), v6_for_port(p)))
        .collect();
    plan_and_report(
        name,
        budget,
        consulted,
        skipped,
        true,
        requested_note(predicted.get(), steer_capacity),
        allowlist,
        directions,
        steer_exempts,
        &ports,
    )
}

/// One port's planning inputs: its name, receive MACs and v6 half.
type PortPlanInputs<'a> = (&'a str, Vec<[u8; 6]>, crate::steer::V6Steering);

/// Said whenever the budget above rests on a size `steer-capacity` has
/// yet to obtain, because the shared pool can give fewer at attach.
fn requested_note(predicted: bool, steer_capacity: Option<u16>) -> String {
    match (predicted, steer_capacity) {
        (true, Some(n)) => format!(
            "; planned at steer-capacity {n}, which attach requests from the driver — the \
             shared classifier pool can give fewer, and attach plans against what it gives"
        ),
        _ => String::new(),
    }
}

/// Plan every configured direction against `budget` and render the
/// verdict. Split out so the strict (steering-port) and lenient
/// (staging-member) paths above cannot drift in their arithmetic —
/// only in which NICs they are willing to proceed without.
#[allow(clippy::too_many_arguments)]
fn plan_and_report(
    name: &'static str,
    budget: crate::steer::McamBudget,
    consulted: Vec<&str>,
    skipped: Vec<String>,
    staging: bool,
    requested: String,
    allowlist: &[packetframe_common::fib::IpPrefix],
    directions: &[packetframe_common::config::VppSteerDirection],
    steer_exempts: &[packetframe_common::config::Ipv4Prefix],
    ports: &[PortPlanInputs],
) -> Capability {
    use crate::steer::{RuleAction, RuleSet};

    let free = budget.free.len();
    // On the strict path a plan `bring_up` refuses (over budget) is an
    // attach refusal, so the verdict is required; staging plans advise
    // the first canary step, which attach does not take.
    let required = !staging;

    // No directions handed in = plan the global default, exactly as
    // the CLI extractor falls back when nothing steers yet. Without
    // this an empty slice would skip planning entirely and misreport
    // every allowlist as empty — caught by this probe's own test the
    // day the parameter became a list.
    let default_dir = [packetframe_common::config::VppSteerDirection::default()];
    let directions = if directions.is_empty() {
        &default_dir[..]
    } else {
        directions
    };
    // One plan per distinct effective direction — the SAME derivation
    // attach and reconfigure perform, so this probe cannot pass a
    // config they refuse. Divert and Keep counted from the rules' own
    // actions: the old `rules / 2` was right only for `both` with no
    // exemptions, since rule counts include the Keep rules and src/dst
    // plans carry one divert per prefix.
    //
    // Per PORT as well: each is planned with its own receive MACs and v6
    // VLANs, as attach plans it, and the largest real plan is reported.
    // No ports (only the tests' synthetic empty call) plans once with
    // no port facts.
    let no_port = [("", Vec::new(), crate::steer::V6Steering::default())];
    let ports = if ports.is_empty() {
        &no_port[..]
    } else {
        ports
    };
    let mut details = Vec::with_capacity(directions.len());
    let mut skipped_v6 = 0u32;
    for direction in directions {
        let mut worst: Option<(&str, RuleSet, &crate::steer::V6Steering)> = None;
        for (port, macs, v6) in ports {
            match RuleSet::plan_with_v6(
                allowlist,
                steer_exempts,
                budget.clone(),
                *direction,
                macs,
                v6,
            ) {
                Ok(set) => {
                    if worst
                        .as_ref()
                        .is_none_or(|(_, w, _)| set.rules.len() > w.rules.len())
                    {
                        worst = Some((port, set, v6));
                    }
                }
                Err(e) if port.is_empty() => return Capability::fail(name, e, required),
                Err(e) => return Capability::fail(name, format!("port {port}: {e}"), required),
            }
        }
        let (port, set, v6) = worst.expect("at least one port planned");
        skipped_v6 = set.skipped_v6;
        let diverts = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Divert)
            .count();
        let v6_rules = set.rules.iter().filter(|r| r.is_v6()).count();
        details.push(format!(
            "direction {direction}: {} rule(s) ({diverts} divert + {} keep{}){}",
            set.rules.len(),
            set.rules.len() - diverts,
            if v6_rules > 0 {
                format!(
                    "; {v6_rules} of them IPv6 diversion on {}",
                    crate::steer::V6Steering::describe_vlans(&v6.vlans)
                )
            } else {
                String::new()
            },
            if ports.len() > 1 {
                format!(" on {port}, the largest")
            } else {
                String::new()
            },
        ));
    }
    let detail = format!(
        "{}; {} free slot(s) across {} {}{}{}{}",
        details.join("; "),
        free,
        if staging {
            "candidate member port(s) (staging: no port steers yet)"
        } else {
            "steering port(s)"
        },
        consulted.join(", "),
        if skipped.is_empty() {
            String::new()
        } else {
            format!("; NOT consulted: {}", skipped.join(", "))
        },
        if skipped_v6 > 0 {
            format!(
                "; {skipped_v6} IPv6 prefix(es) NOT steerable on this NIC and left on the \
                 kernel path"
            )
        } else {
            String::new()
        },
        requested,
    );
    Capability::pass(name, detail, required)
}

/// An SMMU registered in /sys/class/iommu is the difference between
/// real IOMMU-isolated VFIO and no-iommu mode; the module refuses the
/// latter in `bring_up`'s pure phase — via the same
/// [`crate::bringup::iommu_active`] read this uses, so probe and
/// refusal cannot drift (review finding on #200: the inline copies
/// disagreed on an unreadable dirent). Path-injected so the non-PASS
/// arms are testable against a fixture sysfs.
fn probe_iommu() -> Capability {
    probe_iommu_at(Path::new("/sys/class/iommu"))
}

fn probe_iommu_at(dir: &Path) -> Capability {
    match crate::bringup::iommu_active(dir) {
        Ok(Some(name)) => Capability::pass(
            "vpp.iommu",
            format!("active: {}", name.to_string_lossy()),
            true,
        ),
        Ok(None) => Capability::fail(
            "vpp.iommu",
            "/sys/class/iommu is empty: SMMU compiled in but not active \
             (check firmware/boot config); VFIO would run no-iommu, which \
             the module refuses",
            true,
        ),
        Err(e) => Capability::unknown("vpp.iommu", format!("read {}: {e}", dir.display()), true),
    }
}

/// `bring_up` refuses a `loopback-address` the kernel currently holds
/// (the ARP responder war measured on the primary 2026-08-14). Mirrors
/// that refusal exactly — same collision check, same `getifaddrs`
/// read, same degrade-open on an empty list — so the summary cannot
/// say PASS over the one attach refusal that reads live kernel state
/// (review finding on #200).
fn probe_loopback(addr: std::net::Ipv4Addr) -> Capability {
    let name = "vpp.loopback";
    match crate::bringup::loopback_collision(addr, &crate::bringup::kernel_v4_addrs()) {
        Some(err) => Capability::fail(name, err, true),
        None => Capability::pass(
            name,
            format!("loopback-address {addr} is not a live kernel address"),
            true,
        ),
    }
}

/// `bring_up` refuses a `loopback-address6` the kernel holds on any
/// interface. The same check over the same `getifaddrs` read, so the
/// summary cannot say PASS over that refusal — the rule `probe_loopback`
/// follows for the v4 address.
fn probe_loopback6(addr: std::net::Ipv6Addr) -> Capability {
    let name = "vpp.loopback6";
    match crate::bringup::loopback6_collision(addr, &crate::bringup::kernel_v6_ifaddrs()) {
        Some(err) => Capability::fail(name, err, true),
        None => Capability::pass(
            name,
            format!("loopback-address6 {addr} is not a live kernel address"),
            true,
        ),
    }
}

fn probe_vfio() -> Capability {
    let dev = Path::new("/dev/vfio/vfio").exists();
    let drv = Path::new("/sys/bus/pci/drivers/vfio-pci").exists();
    match (dev, drv) {
        (true, true) => Capability::pass("vpp.vfio", "container node + vfio-pci driver", true),
        (false, _) => Capability::fail(
            "vpp.vfio",
            "/dev/vfio/vfio missing: CONFIG_VFIO not built in or module not loaded",
            true,
        ),
        (_, false) => Capability::fail(
            "vpp.vfio",
            "vfio-pci driver not registered (CONFIG_VFIO_PCI)",
            true,
        ),
    }
}

/// The two hugepage facts attach consumes — not just "pools exist"
/// (review finding on #200): `bring_up` refuses a zero default page
/// size, and acquire reserves from exactly the default-size pool
/// (`SysPaths::live` builds `hugepages-<default-kB>` from it), so an
/// unrelated pool cannot satisfy attach and must not pass here.
fn probe_hugepages() -> Capability {
    let name = "vpp.hugepages";
    let default_bytes = default_hugepage_bytes();
    if default_bytes == 0 {
        return Capability::fail(
            name,
            "no parseable `Hugepagesize` in /proc/meminfo (CONFIG_HUGETLBFS?) — attach \
             will refuse; VPP cannot be sized without it",
            true,
        );
    }
    let pools = match fs::read_dir("/sys/kernel/mm/hugepages") {
        Ok(entries) => entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        Err(e) => {
            return Capability::unknown(name, format!("read /sys/kernel/mm/hugepages: {e}"), true)
        }
    };
    let want = format!("hugepages-{}kB", default_bytes >> 10);
    if !pools.iter().any(|p| p == &want) {
        return Capability::fail(
            name,
            format!(
                "default-size pool {want} missing (found: {}) — acquire reserves from \
                 exactly that pool, so attach will fail",
                if pools.is_empty() {
                    "none".to_string()
                } else {
                    pools.join(", ")
                }
            ),
            true,
        );
    }
    Capability::pass(
        name,
        format!(
            "pools: {} (default {} MiB; attach reserves from {want})",
            pools.join(", "),
            default_bytes >> 20
        ),
        true,
    )
}

/// Mirrors `bring_up`'s binary gate exactly: the same single default
/// path (`DEFAULT_VPP_BINARY`), the same `is_file()` + `access(X_OK)`
/// checks. This used to accept either of two candidates on a bare
/// `exists()`, so a directory, a chmod-x file, or a box with only the
/// legacy `/usr/sbin/vpp` passed a required capability attach refuses
/// (review finding on #200).
fn probe_vpp_binary(override_path: Option<&str>) -> Capability {
    let name = "vpp.binary";
    let (path, note) = match override_path {
        Some(p) => (Path::new(p).to_path_buf(), " (from `vpp-binary`)"),
        None => (
            Path::new(crate::bringup::DEFAULT_VPP_BINARY).to_path_buf(),
            " (default path)",
        ),
    };
    // A failed check as non-root is a uid artifact, not a box fact:
    // attach runs as root, whose X_OK any x bit satisfies, and a
    // root-only parent directory hides the file from is_file()
    // entirely. Advisory Unknown, so the invoker's uid cannot flip the
    // BLOCKED verdict (review finding on #200).
    let non_root_unknown = |reason: String| -> Option<Capability> {
        // SAFETY: geteuid has no failure modes or preconditions.
        (unsafe { libc::geteuid() } != 0).then(|| {
            Capability::unknown(
                name,
                format!("cannot verify {} as non-root ({reason}); re-run feasibility as root — attach runs as root", path.display()),
                false,
            )
        })
    };
    if !path.is_file() {
        if let Some(cap) = non_root_unknown("not visible or not a file".to_string()) {
            return cap;
        }
        let hint = if override_path.is_some() {
            "configured via `vpp-binary`"
        } else {
            "install the pinned VPP package (see vpp-offload runbook), or set `vpp-binary`"
        };
        return Capability::fail(
            name,
            format!(
                "{} does not exist — attach will refuse; {hint}",
                path.display()
            ),
            true,
        );
    }
    if let Err(e) = crate::bringup::check_executable(&path) {
        if let Some(cap) = non_root_unknown(format!("access(X_OK): {e}")) {
            return cap;
        }
        return Capability::fail(
            name,
            format!(
                "{} is not executable ({e}) — attach will refuse; `chmod +x` it, or move \
                 it off a `noexec` mount (`/tmp` is one on UniFi OS)",
                path.display()
            ),
            true,
        );
    }
    Capability::pass(name, format!("{}{note}", path.display()), true)
}

fn probe_sriov(iface: &str) -> Capability {
    probe_sriov_at(Path::new("/sys/class/net"), iface)
}

/// Capacity AND current allocation, because attach needs both: the
/// numvfs write fails with `sriov_totalvfs` at 0, and `ensure_vf_in`
/// refuses `sriov_numvfs >= 2` by name — it manages exactly one VF per
/// port and cannot tell which of several is ours. Checking only the
/// hardware maximum passed a port some other setup had already put two
/// VFs on (review finding on #200). Path-injected so the refusal arm
/// is testable against a fixture sysfs.
fn probe_sriov_at(sysfs_net: &Path, iface: &str) -> Capability {
    let name = format!("vpp.{iface}.sriov");
    let dev = sysfs_net.join(iface).join("device");
    let total_path = dev.join("sriov_totalvfs");
    let total = match fs::read_to_string(&total_path) {
        Ok(raw) => match raw.trim().parse::<u32>() {
            Ok(0) => return Capability::fail(&name, "sriov_totalvfs is 0: no VFs available", true),
            Ok(n) => n,
            Err(_) => {
                return Capability::unknown(
                    &name,
                    format!("unparseable {}: {raw:?}", total_path.display()),
                    true,
                )
            }
        },
        Err(e) => {
            return Capability::unknown(&name, format!("{}: {e}", total_path.display()), true)
        }
    };
    let numvfs_path = dev.join("sriov_numvfs");
    // Unparseable reads as 0 here because that is exactly what
    // `ensure_vf_in` does with it (`parse().unwrap_or(0)`).
    let current = match fs::read_to_string(&numvfs_path) {
        Ok(raw) => raw.trim().parse::<u32>().unwrap_or(0),
        Err(e) => {
            return Capability::unknown(
                &name,
                format!(
                    "{}: {e} — attach reads this file before creating a VF",
                    numvfs_path.display()
                ),
                true,
            )
        }
    };
    if current >= 2 {
        return Capability::fail(
            &name,
            format!(
                "sriov_numvfs={current} — attach will refuse; vpp-offload manages exactly \
                 one VF per port and cannot tell which of {current} is ours, clear them \
                 first (`echo 0 > {}`)",
                numvfs_path.display()
            ),
            true,
        );
    }
    Capability::pass(
        &name,
        format!("{total} VFs available, {current} currently allocated"),
        true,
    )
}

pub(crate) fn default_hugepage_bytes() -> u64 {
    let Ok(meminfo) = fs::read_to_string("/proc/meminfo") else {
        return 0;
    };
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("Hugepagesize:") {
            let kb: u64 = rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

#[cfg(test)]
mod steering_probe_tests {
    use super::*;

    /// One receive MAC per port, as a plain L3 port has.
    fn one_mac(_port: &str) -> Vec<[u8; 6]> {
        vec![[0x02, 0, 0, 0, 0, 1]]
    }
    use packetframe_common::fib::IpPrefix;
    use packetframe_common::probe::CapabilityStatus;

    fn v4(a: u8, len: u8) -> IpPrefix {
        IpPrefix::V4 {
            addr: [10, a, 0, 0],
            prefix_len: len,
        }
    }

    /// Nothing to steer is a FAIL however it arose.
    ///
    /// Two ways to get there and they read very differently to an
    /// operator, so both are named — but neither may pass. A port that
    /// steers nothing diverts no traffic while every other line in the
    /// report, and the module's own health, says the offload is fine.
    /// The empty case is the one that slipped through: it is also what
    /// `validate_vpp_offload` permits, since nothing requires fast-path
    /// to declare an allowlist when a port asks to steer.
    #[test]
    fn an_allowlist_that_steers_nothing_never_passes() {
        // The allowlist verdict needs no NIC and is reached before any
        // ioctl, so these run on a host with no rvu hardware.
        let empty = probe_steering_budget(&[], &[], &[], Default::default(), &[], None, &one_mac);
        assert_eq!(empty.status, CapabilityStatus::Fail, "{empty:?}");
        assert!(
            empty.detail.contains("allowlist is empty"),
            "names which of the two ways it got here: {}",
            empty.detail
        );
        assert!(
            !empty.required,
            "no port steers, so attach installs nothing and this must stay advisory"
        );

        // The same nothing-to-steer verdict with a port `steer on` is
        // `bring_up`'s refusal, so it gates the summary.
        let gated = probe_steering_budget(
            &["eth4".to_string()],
            &["eth4".to_string()],
            &[],
            Default::default(),
            &[],
            None,
            &one_mac,
        );
        assert_eq!(gated.status, CapabilityStatus::Fail, "{gated:?}");
        assert!(
            gated.required,
            "attach refuses `steer on` over nothing steerable: {gated:?}"
        );

        let v6_only = probe_steering_budget(
            &[],
            &[],
            &[IpPrefix::V6 {
                addr: [0x26, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                prefix_len: 32,
            }],
            Default::default(),
            &[],
            None,
            &one_mac,
        );
        assert_eq!(v6_only.status, CapabilityStatus::Fail, "{v6_only:?}");
        assert!(
            v6_only.detail.contains("IPv6"),
            "and names the other: {}",
            v6_only.detail
        );
    }

    /// A budget nobody read is UNKNOWN, never a pass — and an
    /// unreadable port the config STEERS is a failure, because attach
    /// refuses it.
    ///
    /// Both halves shipped wrong once. The staging state (every port
    /// `steer off`, which is where feasibility is actually run) asked
    /// no NIC, so `McamBudget::for_ifaces` handed back its synthetic
    /// 16-slot table and the probe passed on a constant — a canary NIC
    /// with occupied slots passed here and failed at the lever. Then
    /// the leniency that fixed the down-idle-member case was applied
    /// to steering ports too, where attach's `for_ifaces` returns on
    /// the first error, so feasibility could PASS a config attach
    /// refuses. Both are review findings on PR #191.
    ///
    /// `wedge_table` is what makes this testable: under `cfg(test)`
    /// the in-memory NIC accepts every interface name, so a bogus name
    /// proves nothing — the earlier version of this test asserted
    /// Unknown against a fake that answered happily, and CI caught it.
    #[test]
    fn what_the_budget_probe_may_claim_about_nics_it_could_not_read() {
        use crate::ntuple::sys;
        let steerable = [v4(0, 24)];
        let dirs: &[packetframe_common::config::VppSteerDirection] = Default::default();

        // 1. No candidate anywhere: nothing was measured, so nothing
        //    is claimed.
        sys::reset();
        let none = probe_steering_budget(&[], &[], &steerable, dirs, &[], None, &one_mac);
        assert_eq!(none.status, CapabilityStatus::Unknown, "{none:?}");
        assert!(
            !none.detail.contains("free slot(s) across"),
            "must not report arithmetic it never measured: {}",
            none.detail
        );

        // 2. Staging, and every member refuses its table: still
        //    Unknown, and it names them.
        sys::reset();
        sys::wedge_table(&["eth4", "eth5"]);
        let all_dark = probe_steering_budget(
            &["eth4".to_string(), "eth5".to_string()],
            &[],
            &steerable,
            dirs,
            &[],
            None,
            &one_mac,
        );
        assert_eq!(all_dark.status, CapabilityStatus::Unknown, "{all_dark:?}");
        assert!(all_dark.detail.contains("eth4"), "{}", all_dark.detail);

        // 3. Staging with ONE dark idle member: the readable port's
        //    arithmetic still lands — this is the down-eth5 case the
        //    leniency exists for — and the skipped port is named
        //    rather than silently dropped.
        sys::reset();
        sys::wedge_table(&["eth5"]);
        let partial = probe_steering_budget(
            &["eth4".to_string(), "eth5".to_string()],
            &[],
            &steerable,
            dirs,
            &[],
            None,
            &one_mac,
        );
        assert_eq!(partial.status, CapabilityStatus::Pass, "{partial:?}");
        assert!(
            partial.detail.contains("NOT consulted") && partial.detail.contains("eth5"),
            "the port that did not answer must be named: {}",
            partial.detail
        );

        // 4. The same dark port, but the config STEERS it: attach
        //    would refuse, so this must not pass.
        sys::reset();
        sys::wedge_table(&["eth5"]);
        let steered_dark = probe_steering_budget(
            &["eth4".to_string(), "eth5".to_string()],
            &["eth4".to_string(), "eth5".to_string()],
            &steerable,
            dirs,
            &[],
            None,
            &one_mac,
        );
        assert_eq!(
            steered_dark.status,
            CapabilityStatus::Fail,
            "an unreadable STEERING port must fail, as attach will: {steered_dark:?}"
        );
        assert!(
            steered_dark.detail.contains("attach will refuse"),
            "and say why: {}",
            steered_dark.detail
        );

        // Severity follows the same line leniency does: the staging
        // verdicts above advise (attach installs nothing), the steering
        // verdict is attach's own refusal.
        assert!(!none.required, "{none:?}");
        assert!(!all_dark.required, "{all_dark:?}");
        assert!(!partial.required, "{partial:?}");
        assert!(steered_dark.required, "{steered_dark:?}");

        // 5. Steering and readable: a PASS on this path is still a
        //    required capability — the same plan failing tomorrow is a
        //    refusal, and REQ=yes is what tells the operator that.
        sys::reset();
        let steered_ok = probe_steering_budget(
            &["eth4".to_string()],
            &["eth4".to_string()],
            &steerable,
            dirs,
            &[],
            None,
            &one_mac,
        );
        assert_eq!(steered_ok.status, CapabilityStatus::Pass, "{steered_ok:?}");
        assert!(steered_ok.required, "{steered_ok:?}");

        // 6. Readable, but its receive MACs are not: attach refuses to
        //    steer a port it cannot scope, so this must fail too.
        sys::reset();
        let unscoped = probe_steering_budget(
            &["eth4".to_string()],
            &["eth4".to_string()],
            &steerable,
            dirs,
            &[],
            None,
            &|_: &str| Vec::new(),
        );
        assert_eq!(unscoped.status, CapabilityStatus::Fail, "{unscoped:?}");
        assert!(
            unscoped.detail.contains("only bridging"),
            "{}",
            unscoped.detail
        );
        assert!(unscoped.required, "{unscoped:?}");
    }

    /// The v6 half is planned as attach plans it: a `v6-divert` port
    /// steers with no v4 to divert, a port beside it without the tail
    /// fails as attach refuses it, and the v6 rules count against the
    /// same slots — so a table that fits v4 alone can still fail here.
    #[test]
    fn the_budget_probe_plans_the_v6_half() {
        use crate::ntuple::sys;
        use crate::steer::V6Steering;
        let dirs: &[packetframe_common::config::VppSteerDirection] = Default::default();
        let v6_on_eth4 = |p: &str| -> Result<V6Steering, String> {
            Ok(if p == "eth4" {
                V6Steering {
                    vlans: vec![Some(100), Some(200)],
                    keeps: vec![],
                }
            } else {
                V6Steering::default()
            })
        };
        let eth4 = ["eth4".to_string()];
        let both = ["eth4".to_string(), "eth5".to_string()];

        // No v4 at all, v6 on the steering port: a pass naming the v6.
        sys::reset();
        let ok =
            probe_steering_budget_v6(&eth4, &eth4, &[], dirs, &[], None, &one_mac, &v6_on_eth4);
        assert_eq!(ok.status, CapabilityStatus::Pass, "{ok:?}");
        assert!(
            ok.detail.contains("IPv6 diversion on vlan 100,200"),
            "{}",
            ok.detail
        );

        // A second steering port with nothing to divert: attach refuses.
        sys::reset();
        let idle =
            probe_steering_budget_v6(&both, &both, &[], dirs, &[], None, &one_mac, &v6_on_eth4);
        assert_eq!(idle.status, CapabilityStatus::Fail, "{idle:?}");
        assert!(idle.required && idle.detail.contains("eth5"), "{idle:?}");

        // v4 fits a 4-slot table alone (1 divert + 2 keeps); with v6
        // (2 diversions + 4 built-in keeps) it does not.
        sys::reset();
        sys::set_table_size(4);
        let v4 = [v4(0, 24)];
        let src = [packetframe_common::config::VppSteerDirection::Src];
        let alone = probe_steering_budget(&eth4, &eth4, &v4, &src, &[], None, &one_mac);
        assert_eq!(alone.status, CapabilityStatus::Pass, "{alone:?}");
        let with_v6 =
            probe_steering_budget_v6(&eth4, &eth4, &v4, &src, &[], None, &one_mac, &v6_on_eth4);
        assert_eq!(with_v6.status, CapabilityStatus::Fail, "{with_v6:?}");
        assert!(
            with_v6.detail.contains("IPv6 diversion(s)"),
            "{}",
            with_v6.detail
        );

        // A trunk whose bridge VLANs cannot be read: attach refuses, and
        // so does this.
        sys::reset();
        let dark =
            probe_steering_budget_v6(&eth4, &eth4, &v4, dirs, &[], None, &one_mac, &|_: &str| {
                Err("bridge VLANs unreadable".to_string())
            });
        assert_eq!(dark.status, CapabilityStatus::Fail, "{dark:?}");
        assert!(dark.required, "{dark:?}");
    }

    /// Each port is planned with its OWN receive MACs and v6 VLANs. One
    /// port with two MACs and no v6 beside another with one MAC and two
    /// v6 VLANs needs at most 11 slots (the second port: 1 + 2 v4, 2 × 2
    /// [TCP, UDP] + 4 v6); crossing the first's MACs with the second's
    /// VLANs would ask for 16, a rule set no real port needs, and fail an
    /// 11-slot table attach accepts.
    #[test]
    fn the_budget_probe_plans_each_ports_own_macs_and_vlans() {
        use crate::ntuple::sys;
        use crate::steer::V6Steering;
        let macs = |p: &str| -> Vec<[u8; 6]> {
            if p == "eth4" {
                vec![[0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2]]
            } else {
                vec![[0x02, 0, 0, 0, 0, 3]]
            }
        };
        let v6 = |p: &str| -> Result<V6Steering, String> {
            Ok(if p == "eth5" {
                V6Steering {
                    vlans: vec![Some(100), Some(200)],
                    keeps: vec![],
                }
            } else {
                V6Steering::default()
            })
        };
        let both = ["eth4".to_string(), "eth5".to_string()];
        let src = [packetframe_common::config::VppSteerDirection::Src];
        let allow = [v4(0, 24)];
        for (steering, what) in [(&both[..], "steering"), (&[][..], "staging")] {
            sys::reset();
            sys::set_table_size(11);
            let cap =
                probe_steering_budget_v6(&both, steering, &allow, &src, &[], None, &macs, &v6);
            assert_eq!(cap.status, CapabilityStatus::Pass, "{what}: {cap:?}");
            assert!(
                cap.detail.contains("11 rule(s)") && cap.detail.contains("on eth5, the largest"),
                "{what}: the worst REAL port is reported: {}",
                cap.detail
            );
            // One slot fewer and the worst real port no longer fits.
            sys::reset();
            sys::set_table_size(10);
            let short =
                probe_steering_budget_v6(&both, steering, &allow, &src, &[], None, &macs, &v6);
            assert_eq!(short.status, CapabilityStatus::Fail, "{what}: {short:?}");
            assert!(
                short.detail.contains("port eth5"),
                "{what}: {}",
                short.detail
            );
        }
    }

    /// The SR-IOV probe answers the question attach asks, not just the
    /// hardware's: `ensure_vf_in` refuses `sriov_numvfs >= 2` because
    /// it cannot tell which VF is ours, so a port with capacity but a
    /// foreign allocation must fail here too (review finding on #200 —
    /// checking only `sriov_totalvfs` passed it).
    #[test]
    fn a_port_with_foreign_vfs_fails_as_attach_refuses_it() {
        let base = std::env::temp_dir().join(format!("pf-probe-sriov-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dev = base.join("eth4").join("device");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("sriov_totalvfs"), "8\n").unwrap();

        std::fs::write(dev.join("sriov_numvfs"), "2\n").unwrap();
        let foreign = probe_sriov_at(&base, "eth4");
        assert_eq!(foreign.status, CapabilityStatus::Fail, "{foreign:?}");
        assert!(
            foreign.detail.contains("attach will refuse"),
            "{}",
            foreign.detail
        );
        assert!(foreign.required, "{foreign:?}");

        // 1 is the adoption path (`ensure_vf_in` takes it over), 0 is
        // fresh acquisition; both are states attach accepts.
        for ok in ["1", "0"] {
            std::fs::write(dev.join("sriov_numvfs"), ok).unwrap();
            let cap = probe_sriov_at(&base, "eth4");
            assert_eq!(cap.status, CapabilityStatus::Pass, "numvfs={ok}: {cap:?}");
        }

        std::fs::write(dev.join("sriov_totalvfs"), "0\n").unwrap();
        let none = probe_sriov_at(&base, "eth4");
        assert_eq!(none.status, CapabilityStatus::Fail, "{none:?}");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// The driver line passes only the supported NIC, fails another
    /// driver or a driverless netdev, and is Unknown — still required —
    /// when sysfs cannot say, each with the reason attach would give.
    #[test]
    fn the_driver_line_judges_each_port_as_attach_does() {
        let ok = probe_driver("eth4", &Ok(PortNic::Supported));
        assert_eq!(ok.status, CapabilityStatus::Pass, "{ok:?}");
        assert_eq!(ok.name, "vpp.eth4.driver");

        let other = probe_driver("eth4", &Ok(PortNic::Other("mlx5_core".into())));
        assert_eq!(other.status, CapabilityStatus::Fail, "{other:?}");
        assert!(other.detail.contains("driven by `mlx5_core`"), "{other:?}");
        assert!(other.detail.contains("attach will refuse"), "{other:?}");
        assert!(
            other.detail.contains(crate::nic::SUPPORTED_NIC),
            "{other:?}"
        );
        assert!(
            other.detail.contains("fast-path runs on this NIC"),
            "{other:?}"
        );

        // A bridge is the wrong device, not the wrong hardware: no advice
        // to run fast-path on it.
        let none = probe_driver("br0", &Ok(PortNic::NoDriver));
        assert_eq!(none.status, CapabilityStatus::Fail, "{none:?}");
        assert!(none.detail.contains("physical port"), "{none:?}");
        assert!(!none.detail.contains("fast-path runs"), "{none:?}");

        let unread = probe_driver(
            "eth4",
            &Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
        );
        assert_eq!(unread.status, CapabilityStatus::Unknown, "{unread:?}");
        assert!(unread.required, "attach refuses this too: {unread:?}");
    }

    /// On a port off the supported NIC the steering plan is not drawn:
    /// its rule table is not one this module programs, so the budget
    /// line says why it is absent instead of judging that table. The
    /// port cannot exist, so this holds on any host.
    #[test]
    fn no_budget_is_planned_against_a_foreign_nic() {
        let ports = vec!["pf-no-such-nic".to_string()];
        let caps = run(&ports, &ports, 1, None, None, &[], &[], &[], None, &[]);
        let driver = caps
            .iter()
            .find(|c| c.name == "vpp.pf-no-such-nic.driver")
            .expect("every member port gets a driver line");
        assert!(driver.required, "{driver:?}");
        let budget = caps
            .iter()
            .find(|c| c.name == "vpp.steering.budget")
            .expect("the budget line is replaced, not dropped");
        assert_eq!(budget.status, CapabilityStatus::Unknown, "{budget:?}");
        assert!(budget.detail.contains("not planned"), "{budget:?}");
        assert!(
            !budget.required,
            "the driver line gates, not this: {budget:?}"
        );
    }

    /// The `loopback-address6` probe FAILS on an address the host holds
    /// — `::1` is on every host's `lo` — exactly where `bring_up`
    /// refuses, and passes on one nothing holds.
    #[test]
    fn a_kernel_held_loopback6_fails_the_probe() {
        let held = probe_loopback6(std::net::Ipv6Addr::LOCALHOST);
        assert_eq!(held.status, CapabilityStatus::Fail, "{held:?}");
        assert!(held.detail.contains("kernel already holds"), "{held:?}");
        let free = probe_loopback6("2001:db8::ffff".parse().unwrap());
        assert_eq!(free.status, CapabilityStatus::Pass, "{free:?}");
    }

    /// Every hardware probe is `required` whatever it found.
    ///
    /// Each one probes a condition attach refuses (`bring_up`'s named
    /// checks) or cannot survive (acquire's vfio bind, VF creation).
    /// They were advisory once, and on edge1-mci1-net (2026-08-21) an
    /// operator read the summary's "PASS" over a failing
    /// `vpp.irq-affinity` line and met the refusal at attach — so the
    /// invariant is asserted on the flag alone, independent of what
    /// this host's sysfs happens to answer.
    #[test]
    fn every_hardware_verdict_is_required_whatever_it_found() {
        for cap in [
            probe_iommu(),
            probe_vfio(),
            probe_hugepages(),
            // A path that exists and is executable on any test host:
            // the binary probe's one deliberate exception is a FAILING
            // check under a non-root uid (a uid artifact, not a box
            // fact), so the invariant is asserted on a passing path.
            probe_vpp_binary(Some("/bin/sh")),
            probe_sriov("eth-nonexistent"),
            probe_driver(
                "eth-nonexistent",
                &crate::nic::port_nic_in(Path::new("/sys/class/net"), "eth-nonexistent"),
            ),
            probe_irq_affinity(&[], 1),
            probe_loopback6(std::net::Ipv6Addr::LOCALHOST),
            probe_loopback6("2001:db8::ffff".parse().unwrap()),
        ] {
            assert!(
                cap.required,
                "{} must gate the feasibility summary; attach refuses or dies on what it \
                 probes ({:?}: {})",
                cap.name, cap.status, cap.detail
            );
        }
    }
}
