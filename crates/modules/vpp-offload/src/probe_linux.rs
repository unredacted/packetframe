//! Linux feasibility probes for the vpp-offload module (plan v5).
//!
//! Everything here mirrors the fast-path probe philosophy: read-only,
//! non-required (feasibility informs, attach enforces), and each
//! verdict names its fix inline. Probes cover the layers proven live
//! on the reference EFG (2026-08-01): active IOMMU, SR-IOV capacity,
//! VFIO device nodes, hugepage pools, and the VPP binary.

use std::fs;
use std::path::Path;

use packetframe_common::probe::Capability;

pub(crate) fn run(
    ports: &[String],
    workers: u32,
    vpp_binary: Option<&str>,
    allowlist: &[packetframe_common::fib::IpPrefix],
) -> Vec<Capability> {
    let mut caps = Vec::with_capacity(5 + ports.len());
    caps.push(probe_iommu());
    caps.push(probe_vfio());
    caps.push(probe_hugepages());
    caps.push(probe_irq_affinity(ports, workers));
    // Probe the binary the module will ACTUALLY exec. Probing the
    // defaults while the config names another path would report a pass
    // for an executable we never run (or a failure for one that
    // exists) — a capability line describing a different program than
    // the module uses is worse than no line.
    caps.push(probe_vpp_binary(vpp_binary));
    for iface in ports {
        caps.push(probe_sriov(iface));
    }
    caps.push(probe_steering_budget(ports, allowlist));
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
    let map = match crate::cores::derive_from_sysfs(Path::new(crate::cores::SYSFS_CPU), workers) {
        Ok(m) => m,
        Err(e) => return Capability::unknown(name, format!("derive core map: {e}"), false),
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
            false,
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
                false,
            )
        }
        Err(e) => Capability::unknown(name, e, false),
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
/// Read-only and non-required, like every probe here: it computes the
/// plan the module would install, and installs nothing.
///
/// **The budget comes from the NIC.** This used to plan against
/// `McamBudget::default()` and report whether the arithmetic held — a
/// constant checked against itself, which passed while every insert the
/// module would issue was rejected, because the constant named a slot
/// 1008 past the end of the table. A probe whose answer cannot disagree
/// with the code it is probing is not a probe.
fn probe_steering_budget(
    ports: &[String],
    allowlist: &[packetframe_common::fib::IpPrefix],
) -> Capability {
    use crate::steer::{McamBudget, RuleSet};

    let budget = match McamBudget::for_ifaces(ports.iter().map(String::as_str)) {
        Ok(b) => b,
        Err(e) => return Capability::fail("vpp.steering.budget", e, false),
    };
    let free = budget.free.len();
    match RuleSet::plan(allowlist, budget) {
        // Nothing to steer is a FAIL however it arose. The two ways there
        // read very differently to an operator, so they are named
        // separately — but neither may pass: a port that steers nothing
        // diverts no traffic while every other line in this report, and
        // the module's own health, says the offload is fine.
        Ok(set) if set.rules.is_empty() => Capability::fail(
            "vpp.steering.budget",
            if set.skipped_v6 > 0 {
                format!(
                    "none of the allowlist can be steered: all {} prefix(es) are IPv6, and \
                     `ip6` ntuple is rejected by this NIC's AF (gate 0b round 4). The offload \
                     would forward nothing while reporting healthy",
                    set.skipped_v6
                )
            } else {
                "the fast-path allowlist is empty, so there is nothing to steer. Steered \
                 prefixes are inherited from fast-path's `allow-prefix`/`allow-prefix6`; \
                 without any, the offload would forward nothing while reporting healthy"
                    .to_string()
            },
            false,
        ),
        Ok(set) => {
            let detail = format!(
                "{} rule(s) for {} steerable prefix(es); the NIC reports {} free slot(s){}",
                set.rules.len(),
                set.rules.len() / 2,
                free,
                if set.skipped_v6 > 0 {
                    format!(
                        "; {} IPv6 prefix(es) NOT steerable on this NIC and left on the \
                         kernel path",
                        set.skipped_v6
                    )
                } else {
                    String::new()
                }
            );
            Capability::pass("vpp.steering.budget", detail, false)
        }
        Err(e) => Capability::fail("vpp.steering.budget", e, false),
    }
}

/// An SMMU registered in /sys/class/iommu is the difference between
/// real IOMMU-isolated VFIO and no-iommu mode; the module refuses the
/// latter at attach.
fn probe_iommu() -> Capability {
    match fs::read_dir("/sys/class/iommu") {
        Ok(mut entries) => {
            if let Some(Ok(e)) = entries.next() {
                Capability::pass(
                    "vpp.iommu",
                    format!("active: {}", e.file_name().to_string_lossy()),
                    false,
                )
            } else {
                Capability::fail(
                    "vpp.iommu",
                    "/sys/class/iommu is empty: SMMU compiled in but not active \
                     (check firmware/boot config); VFIO would run no-iommu, which \
                     the module refuses",
                    false,
                )
            }
        }
        Err(e) => Capability::unknown("vpp.iommu", format!("read /sys/class/iommu: {e}"), false),
    }
}

fn probe_vfio() -> Capability {
    let dev = Path::new("/dev/vfio/vfio").exists();
    let drv = Path::new("/sys/bus/pci/drivers/vfio-pci").exists();
    match (dev, drv) {
        (true, true) => Capability::pass("vpp.vfio", "container node + vfio-pci driver", false),
        (false, _) => Capability::fail(
            "vpp.vfio",
            "/dev/vfio/vfio missing: CONFIG_VFIO not built in or module not loaded",
            false,
        ),
        (_, false) => Capability::fail(
            "vpp.vfio",
            "vfio-pci driver not registered (CONFIG_VFIO_PCI)",
            false,
        ),
    }
}

/// Report which hugepage pools exist and the default page size. The
/// module reserves at attach; the probe just proves pools exist and
/// captures the default size the sizing math will use.
fn probe_hugepages() -> Capability {
    let pools = match fs::read_dir("/sys/kernel/mm/hugepages") {
        Ok(entries) => entries
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>(),
        Err(e) => {
            return Capability::unknown(
                "vpp.hugepages",
                format!("read /sys/kernel/mm/hugepages: {e}"),
                false,
            )
        }
    };
    if pools.is_empty() {
        return Capability::fail(
            "vpp.hugepages",
            "no hugepage pools (CONFIG_HUGETLBFS?)",
            false,
        );
    }
    let default_mb = default_hugepage_bytes() >> 20;
    Capability::pass(
        "vpp.hugepages",
        format!("pools: {} (default {default_mb} MiB)", pools.join(", ")),
        false,
    )
}

fn probe_vpp_binary(override_path: Option<&str>) -> Capability {
    let candidates = match override_path {
        Some(p) => vec![p.to_string()],
        None => vec!["/usr/bin/vpp".to_string(), "/usr/sbin/vpp".to_string()],
    };
    for c in &candidates {
        if Path::new(c).exists() {
            let note = if override_path.is_some() {
                " (from `vpp-binary`)"
            } else {
                " (default path)"
            };
            return Capability::pass("vpp.binary", format!("{c}{note}"), false);
        }
    }
    let hint = if override_path.is_some() {
        "configured via `vpp-binary`"
    } else {
        "install the pinned VPP package (see vpp-offload runbook), or set `vpp-binary`"
    };
    Capability::fail(
        "vpp.binary",
        format!("not found at {} — {hint}", candidates.join(" or ")),
        false,
    )
}

fn probe_sriov(iface: &str) -> Capability {
    let name = format!("vpp.{iface}.sriov");
    let path = format!("/sys/class/net/{iface}/device/sriov_totalvfs");
    match fs::read_to_string(&path) {
        Ok(raw) => match raw.trim().parse::<u32>() {
            Ok(0) => Capability::fail(&name, "sriov_totalvfs is 0: no VFs available", false),
            Ok(n) => Capability::pass(&name, format!("{n} VFs available"), false),
            Err(_) => Capability::unknown(&name, format!("unparseable {path}: {raw:?}"), false),
        },
        Err(e) => Capability::unknown(&name, format!("{path}: {e}"), false),
    }
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
        // No ports: `for_ifaces` asks no NIC and yields the fallback
        // budget, so these stay tests of the ALLOWLIST logic — which is
        // what they were always about — on a host that has no rvu NIC.
        let empty = probe_steering_budget(&[], &[]);
        assert_eq!(empty.status, CapabilityStatus::Fail, "{empty:?}");
        assert!(
            empty.detail.contains("allowlist is empty"),
            "names which of the two ways it got here: {}",
            empty.detail
        );

        let v6_only = probe_steering_budget(
            &[],
            &[IpPrefix::V6 {
                addr: [0x26, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                prefix_len: 32,
            }],
        );
        assert_eq!(v6_only.status, CapabilityStatus::Fail, "{v6_only:?}");
        assert!(
            v6_only.detail.contains("IPv6"),
            "and names the other: {}",
            v6_only.detail
        );

        // A steerable prefix passes, so the failures above are about
        // having nothing to steer rather than the probe always failing.
        let ok = probe_steering_budget(&[], &[v4(0, 24)]);
        assert_eq!(ok.status, CapabilityStatus::Pass, "{ok:?}");
    }
}
