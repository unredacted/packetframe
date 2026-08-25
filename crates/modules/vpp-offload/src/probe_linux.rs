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
) -> Vec<Capability> {
    let mut caps = Vec::with_capacity(6 + ports.len());
    caps.push(probe_iommu());
    caps.push(probe_vfio());
    caps.push(probe_hugepages());
    caps.push(probe_irq_affinity(ports, workers));
    if let Some(addr) = loopback {
        caps.push(probe_loopback(addr));
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
    caps.push(probe_steering_budget(
        ports,
        steer_ports,
        allowlist,
        directions,
        steer_exempts,
    ));
    caps
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
            Capability::fail(
                name,
                format!(
                    "{} NIC queue IRQ(s) fire on the derived VPP cores (main {}, workers \
                     {:?}): {}{} — attach will refuse; move them first: `echo <cpu-list \
                     outside the VPP cores> > /proc/irq/<N>/smp_affinity_list`",
                    c.len(),
                    map.main,
                    map.workers,
                    sample.join(", "),
                    if c.len() > 8 { ", ..." } else { "" },
                ),
                true,
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
/// cannot be steered on this NIC at any size: `ip6` ntuple is rejected
/// by the AF, so a v6-heavy allowlist means the offload covers far less
/// traffic than the config reads like it does.
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
fn probe_steering_budget(
    member_ports: &[String],
    steer_ports: &[String],
    allowlist: &[packetframe_common::fib::IpPrefix],
    directions: &[packetframe_common::config::VppSteerDirection],
    steer_exempts: &[packetframe_common::config::Ipv4Prefix],
) -> Capability {
    use crate::steer::McamBudget;

    let name = "vpp.steering.budget";
    // Whether this probe's verdicts gate attach: `bring_up` refuses an
    // unsteerable or over-budget plan only when something steers.
    let gating = !steer_ports.is_empty();
    // The ALLOWLIST question first, because it needs no NIC — the same
    // ordering `bring_up` documents and for the same reason: an
    // operator who wrote `steer on` against a v6-only allowlist must
    // read about their allowlist, not about whatever the ioctl said.
    let steerable = crate::steer::steerable_count(allowlist);
    if steerable == 0 {
        return Capability::fail(
            name,
            if allowlist.is_empty() {
                "the fast-path allowlist is empty, so there is nothing to steer. Steered \
                 prefixes are inherited from fast-path's `allow-prefix`/`allow-prefix6`; \
                 without any, the offload would forward nothing while reporting healthy"
                    .to_string()
            } else {
                format!(
                    "none of the allowlist can be steered: all {} prefix(es) are IPv6, and \
                     `ip6` ntuple is rejected by this NIC's AF (gate 0b round 4). The \
                     offload would forward nothing while reporting healthy",
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
        let budget = match McamBudget::for_ifaces(steer_ports.iter().map(String::as_str)) {
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
        return plan_and_report(
            name,
            budget,
            steer_ports.iter().map(String::as_str).collect(),
            Vec::new(),
            false,
            allowlist,
            directions,
            steer_exempts,
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
        match crate::ntuple::rule_table(iface) {
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
    plan_and_report(
        name,
        budget,
        consulted,
        skipped,
        true,
        allowlist,
        directions,
        steer_exempts,
    )
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
    allowlist: &[packetframe_common::fib::IpPrefix],
    directions: &[packetframe_common::config::VppSteerDirection],
    steer_exempts: &[packetframe_common::config::Ipv4Prefix],
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
    let mut details = Vec::with_capacity(directions.len());
    let mut skipped_v6 = 0u32;
    for direction in directions {
        match RuleSet::plan(allowlist, steer_exempts, budget.clone(), *direction) {
            Ok(set) => {
                skipped_v6 = set.skipped_v6;
                let diverts = set
                    .rules
                    .iter()
                    .filter(|r| r.action == RuleAction::Divert)
                    .count();
                details.push(format!(
                    "direction {direction}: {} rule(s) ({diverts} divert + {} keep)",
                    set.rules.len(),
                    set.rules.len() - diverts,
                ));
            }
            Err(e) => return Capability::fail(name, e, required),
        }
    }
    let detail = format!(
        "{}; {} free slot(s) across {} {}{}{}",
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
        }
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
        let empty = probe_steering_budget(&[], &[], &[], Default::default(), &[]);
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
        let none = probe_steering_budget(&[], &[], &steerable, dirs, &[]);
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
        );
        assert_eq!(steered_ok.status, CapabilityStatus::Pass, "{steered_ok:?}");
        assert!(steered_ok.required, "{steered_ok:?}");
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
            probe_irq_affinity(&[], 1),
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
