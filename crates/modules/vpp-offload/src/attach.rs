//! Device attach over the binary API — the `AttachDevices` action.
//!
//! After the v7 driver pivot, device identity does not live in
//! startup.conf: the native octeon driver is attached at runtime, so
//! bringing a VF into VPP is API traffic. The sequence is the one
//! proven on the shadow (runbook §3, round 3), expressed as three
//! messages instead of three `vppctl` invocations:
//!
//! ```text
//! dev_attach          pci/0002:07:00.1 driver octeon   → dev_index
//! dev_create_port_if  dev_index, port 0, num_rx_queues → sw_if_index
//! sw_interface_set_flags sw_if_index up
//! ```
//!
//! **Why this runs before the resync, not after.** A FIB path is
//! encoded with an `sw_if_index`, and those indices do not exist until
//! `dev_create_port_if` returns them. Installing routes first would
//! either defer every one of them or — worse, if anything defaulted —
//! point them at index 0, which is `local0`: a route that looks
//! installed and silently drops. The supervisor orders
//! `AttachDevices` ahead of `StartResync` for exactly this reason.

use crate::vpp_api::generated::{
    DevAttach, DevAttachReply, DevCreatePortIf, DevCreatePortIfReply, SwInterfaceSetFlags,
    SwInterfaceSetFlagsReply,
};
use crate::vpp_api::{Transport, TransportError};

/// The driver name the native octeon path registers under.
///
/// Not `dev_octeon`, not a `net_*` PMD string — those are DPDK
/// spellings and this is not the DPDK path. Established by measurement
/// on the shadow: the driver ships as `vpp_drivers/octeon_driver.so`
/// and registers as `octeon`.
pub const OCTEON_DRIVER: &str = "octeon";

/// `IF_STATUS_API_FLAG_ADMIN_UP` from interface_types.api.
const ADMIN_UP: u32 = 1;

/// What to attach: one member port's VF.
#[derive(Debug, Clone)]
pub struct PortAttach {
    /// Kernel-side name of the PF this VF belongs to (`eth3`), used as
    /// the key the nexthop mapping resolves against.
    pub port: String,
    /// VF PCI address, e.g. `0002:07:00.1`.
    pub pci_addr: String,
    /// Port number within the device. 0 on this NIC.
    pub port_id: u16,
    /// Receive queues, from the operator's `cores` promise.
    pub num_rx_queues: u16,
}

/// A port VPP has accepted, with the index FIB paths must reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedPort {
    pub port: String,
    pub dev_index: u32,
    pub sw_if_index: u32,
}

#[derive(Debug)]
pub enum AttachError {
    Transport(TransportError),
    /// VPP refused a step. `error_string` is VPP's own text, which is
    /// far more useful than the retval alone (it names the driver or
    /// device that failed).
    Refused {
        step: &'static str,
        port: String,
        retval: i32,
        detail: String,
    },
    /// VPP returned success and an index of 0 for an interface.
    ///
    /// Treated as a hard failure rather than accepted: `sw_if_index` 0
    /// is `local0`, VPP's own drop interface. A FIB path pointing there
    /// forwards nothing while looking perfectly healthy, which is the
    /// single worst outcome this module can produce.
    LocalZero {
        port: String,
    },
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachError::Transport(e) => write!(f, "{e}"),
            AttachError::Refused {
                step,
                port,
                retval,
                detail,
            } => {
                write!(f, "{step} for {port} failed (retval {retval})")?;
                if !detail.is_empty() {
                    write!(f, ": {detail}")?;
                }
                Ok(())
            }
            AttachError::LocalZero { port } => write!(
                f,
                "VPP returned sw_if_index 0 (local0) for {port}; refusing to build FIB paths \
                 that would silently drop"
            ),
        }
    }
}

impl std::error::Error for AttachError {}

impl From<TransportError> for AttachError {
    fn from(e: TransportError) -> Self {
        AttachError::Transport(e)
    }
}

/// Attach every port and bring it admin-up.
///
/// Sequential rather than pipelined, deliberately: each step consumes
/// the index the previous one returned, and there are a handful of
/// ports rather than a million routes — the latency this would save is
/// irrelevant next to being able to name exactly which port failed.
///
/// Stops at the first failure. Ports already attached are returned in
/// the error-free prefix only on success; on failure the caller tears
/// the process down anyway (the supervisor routes an attach failure
/// through `fail()`), so partial cleanup here would duplicate work
/// that `Kill` does more reliably.
pub fn attach_ports(
    t: &mut Transport,
    ports: &[PortAttach],
) -> Result<Vec<AttachedPort>, AttachError> {
    let mut out = Vec::with_capacity(ports.len());
    for p in ports {
        let dev_index = attach_device(t, p)?;
        let sw_if_index = create_port_if(t, p, dev_index)?;
        set_admin_up(t, p, sw_if_index)?;
        out.push(AttachedPort {
            port: p.port.clone(),
            dev_index,
            sw_if_index,
        });
    }
    Ok(out)
}

fn attach_device(t: &mut Transport, p: &PortAttach) -> Result<u32, AttachError> {
    // VPP's device id is scheme-qualified: `pci/<addr>`, not the bare
    // address.
    let reply = t.request::<DevAttach, DevAttachReply>(DevAttach {
        context: 0,
        device_id: format!("pci/{}", p.pci_addr),
        driver_name: OCTEON_DRIVER.to_string(),
        flags: 0,
        args: String::new(),
    })?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "dev_attach",
            port: p.port.clone(),
            retval: reply.retval,
            detail: reply.error_string,
        });
    }
    Ok(reply.dev_index)
}

fn create_port_if(t: &mut Transport, p: &PortAttach, dev_index: u32) -> Result<u32, AttachError> {
    let reply = t.request::<DevCreatePortIf, DevCreatePortIfReply>(DevCreatePortIf {
        context: 0,
        dev_index,
        // Empty asks VPP to name it, which yields the `octeonN/P` form
        // the runbook and every operator command already use. Choosing
        // our own name would make `show interface` output diverge from
        // the documentation for no gain.
        intf_name: String::new(),
        num_rx_queues: p.num_rx_queues,
        num_tx_queues: p.num_rx_queues,
        // 0 = driver default. The gate-0b bring-up used defaults, and
        // queue sizing is a tuning question to open only once we are
        // packet-rate-bound with numbers to justify a change.
        rx_queue_size: 0,
        tx_queue_size: 0,
        port_id: p.port_id,
        flags: 0,
        args: String::new(),
    })?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "dev_create_port_if",
            port: p.port.clone(),
            retval: reply.retval,
            detail: reply.error_string,
        });
    }
    if reply.sw_if_index == 0 {
        return Err(AttachError::LocalZero {
            port: p.port.clone(),
        });
    }
    Ok(reply.sw_if_index)
}

fn set_admin_up(t: &mut Transport, p: &PortAttach, sw_if_index: u32) -> Result<(), AttachError> {
    let reply =
        t.request::<SwInterfaceSetFlags, SwInterfaceSetFlagsReply>(SwInterfaceSetFlags {
            context: 0,
            sw_if_index,
            flags: ADMIN_UP,
        })?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "sw_interface_set_flags",
            port: p.port.clone(),
            retval: reply.retval,
            detail: String::new(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_scheme_qualified() {
        // `dev_attach` takes `pci/<addr>`; the bare address is rejected
        // by VPP's device-id parser.
        let p = PortAttach {
            port: "eth3".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
        };
        assert_eq!(format!("pci/{}", p.pci_addr), "pci/0002:07:00.1");
    }

    #[test]
    fn the_driver_name_is_the_native_one() {
        // Guards against reintroducing a DPDK spelling: `net_cn9k`,
        // `net_octeontx2` and `dev_octeon` are all wrong here, and two
        // of them cost a bring-up round to establish.
        assert_eq!(OCTEON_DRIVER, "octeon");
    }

    #[test]
    fn local_zero_error_explains_the_danger() {
        let e = AttachError::LocalZero {
            port: "eth3".into(),
        };
        let msg = e.to_string();
        assert!(msg.contains("local0"), "{msg}");
        assert!(msg.contains("silently drop"), "{msg}");
    }
}
