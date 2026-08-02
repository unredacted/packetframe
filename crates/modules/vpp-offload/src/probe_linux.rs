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

pub(crate) fn run(ports: &[String], vpp_binary: Option<&str>) -> Vec<Capability> {
    let mut caps = Vec::with_capacity(4 + ports.len());
    caps.push(probe_iommu());
    caps.push(probe_vfio());
    caps.push(probe_hugepages());
    // Probe the binary the module will ACTUALLY exec. Probing the
    // defaults while the config names another path would report a pass
    // for an executable we never run (or a failure for one that
    // exists) — a capability line describing a different program than
    // the module uses is worse than no line.
    caps.push(probe_vpp_binary(vpp_binary));
    for iface in ports {
        caps.push(probe_sriov(iface));
    }
    caps
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
