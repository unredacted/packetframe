//! The one NIC this module drives, and the gate that refuses the rest.
//!
//! vpp-offload is built for the Marvell OCTEON's RVU network functions,
//! whose PF driver is [`SUPPORTED_PF_DRIVER`], and everything below the
//! binary API assumes it:
//!
//! - steering is ethtool ntuple with this driver's semantics: a PF→VF
//!   `ring_cookie`, a small rule table that `steer-capacity` resizes
//!   through this driver's devlink parameter, and no IPv6 address match,
//!   which is why IPv6 is diverted by frame ([`crate::ntuple`],
//!   [`crate::steer`], [`crate::capacity`]);
//! - VPP drives the VF with its native `octeon` device driver
//!   ([`crate::attach::OCTEON_DRIVER`]), with DPDK disabled
//!   ([`crate::startup_conf`]);
//! - a VF leaving vfio is handed back to
//!   [`crate::acquire::KERNEL_VF_DRIVER`].
//!
//! On another NIC none of that fails at a clean point. SR-IOV, vfio and
//! the ntuple ioctls are generic, so attach would create a VF and bind it
//! to vfio before VPP's `octeon` driver refused the device, and releasing
//! it would name a VF driver that NIC does not have. So
//! [`check_ports_in`] refuses before attach touches any NIC, and the
//! `vpp.<port>.driver` feasibility probe reports the same verdict from
//! the same read ([`port_nic_in`], [`unsupported_reason`]).

use std::io;
use std::path::Path;

/// The PF driver this module supports, as sysfs spells it: the leaf of
/// `/sys/class/net/<port>/device/driver` on the reference EFG.
/// fast-path's `RVU_NICPF_DRIVERS` records why `ethtool -i` spells it
/// with a hyphen.
pub const SUPPORTED_PF_DRIVER: &str = "rvu_nicpf";

/// What the operator is told a refused port is missing. Shared by the
/// attach refusal and the probe so the two describe the same support.
pub const SUPPORTED_NIC: &str = "vpp-offload supports only Marvell OCTEON NICs (PF driver \
     `rvu_nicpf`)";

/// What sits behind one member port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortNic {
    /// A device bound to [`SUPPORTED_PF_DRIVER`].
    Supported,
    /// A device bound to another driver, by name.
    Other(String),
    /// No device, or nothing bound to it: a bridge, VLAN or veth, or a
    /// NIC whose driver is not loaded.
    NoDriver,
}

/// Read what `port` is from `<sysfs_net>/<port>/device/driver`.
///
/// `Err` when sysfs cannot say, and that includes a port that does not
/// exist. Callers refuse on it: a driver that could not be read is not
/// evidence of the supported one.
pub fn port_nic_in(sysfs_net: &Path, port: &str) -> io::Result<PortNic> {
    let dir = sysfs_net.join(port);
    // Not followed: `/sys/class/net/<port>` is itself a symlink, and
    // only its presence is in question here.
    std::fs::symlink_metadata(&dir)?;
    let target = match std::fs::read_link(dir.join("device").join("driver")) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(PortNic::NoDriver),
        Err(e) => return Err(e),
    };
    let name = target.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("driver link points at {}", target.display()),
        )
    })?;
    Ok(if name == SUPPORTED_PF_DRIVER {
        PortNic::Supported
    } else {
        PortNic::Other(name.to_string_lossy().into_owned())
    })
}

/// Why `port` cannot be a member, or `None` when it can.
pub fn unsupported_reason(port: &str, read: &io::Result<PortNic>) -> Option<String> {
    match read {
        Ok(PortNic::Supported) => None,
        Ok(PortNic::Other(driver)) => Some(format!("{port} is driven by `{driver}`")),
        Ok(PortNic::NoDriver) => Some(format!(
            "{port} has no device driver behind it (a bridge, VLAN or veth, where the \
             `port` must name the physical port instead, or a NIC whose driver is not loaded)"
        )),
        Err(e) => Some(format!("{port}: its driver could not be read ({e})")),
    }
}

/// Attach's gate: every member port on [`SUPPORTED_PF_DRIVER`], or one
/// refusal naming each port that is not.
pub fn check_ports_in(sysfs_net: &Path, ports: &[&str]) -> Result<(), String> {
    let problems: Vec<String> = ports
        .iter()
        .filter_map(|port| unsupported_reason(port, &port_nic_in(sysfs_net, port)))
        .collect();
    if problems.is_empty() {
        return Ok(());
    }
    Err(format!(
        "{}. {SUPPORTED_NIC}: its steering, its VF handling and the VPP device driver it \
         attaches are all specific to that NIC, so attach refuses before touching any port. \
         The eBPF fast-path runs on this hardware without the `module vpp-offload` section \
         (docs/runbooks/vpp-offload.md, \"Supported hardware\")",
        problems.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    /// A `/sys/class/net` with one port per shape the gate must tell
    /// apart. Driver links are relative and dangling, as read_link only
    /// reads them.
    fn fixture(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("pf-nic-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        for (port, driver) in [("eth0", Some("rvu_nicpf")), ("eth1", Some("ixgbe"))] {
            let dev = base.join(port).join("device");
            std::fs::create_dir_all(&dev).unwrap();
            if let Some(d) = driver {
                symlink(format!("../../../bus/pci/drivers/{d}"), dev.join("driver")).unwrap();
            }
        }
        // A NIC with its driver unloaded keeps its device, loses the link.
        std::fs::create_dir_all(base.join("eth2").join("device")).unwrap();
        // A bridge has no device at all.
        std::fs::create_dir_all(base.join("br0")).unwrap();
        base
    }

    #[test]
    fn each_port_shape_reads_as_what_it_is() {
        let base = fixture("read");
        assert_eq!(port_nic_in(&base, "eth0").unwrap(), PortNic::Supported);
        assert_eq!(
            port_nic_in(&base, "eth1").unwrap(),
            PortNic::Other("ixgbe".into())
        );
        assert_eq!(port_nic_in(&base, "eth2").unwrap(), PortNic::NoDriver);
        assert_eq!(port_nic_in(&base, "br0").unwrap(), PortNic::NoDriver);
        // A port that does not exist is unreadable, not "no driver": the
        // gate must not describe a typo as a bridge.
        assert!(port_nic_in(&base, "eth9").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_supported_nic_passes_the_gate() {
        let base = fixture("pass");
        check_ports_in(&base, &["eth0"]).expect("rvu_nicpf is the supported driver");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// One refusal names every port that fails, each with its own reason,
    /// and says what is supported and what still runs — so an operator on
    /// other hardware reads the answer once rather than one port per
    /// attempt.
    #[test]
    fn the_refusal_names_every_failing_port_and_the_way_out() {
        let base = fixture("refuse");
        let e = check_ports_in(&base, &["eth0", "eth1", "eth2", "br0", "eth9"])
            .expect_err("a mixed member set must refuse");
        assert!(e.contains("eth1 is driven by `ixgbe`"), "{e}");
        assert!(e.contains("eth2 has no device driver"), "{e}");
        assert!(e.contains("br0 has no device driver"), "{e}");
        assert!(e.contains("eth9: its driver could not be read"), "{e}");
        assert!(
            !e.contains("eth0"),
            "the supported port is not a problem: {e}"
        );
        assert!(e.contains(SUPPORTED_NIC), "{e}");
        assert!(e.contains("fast-path runs on this hardware"), "{e}");
        let _ = std::fs::remove_dir_all(&base);
    }
}
