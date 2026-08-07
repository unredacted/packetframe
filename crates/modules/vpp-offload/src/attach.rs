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

use packetframe_common::config::Ipv4Prefix;

use crate::vpp_api::generated::{
    Address, AddressUnion, CreateLoopback, CreateLoopbackReply, DevAttach, DevAttachReply,
    DevCreatePortIf, DevCreatePortIfReply, Prefix, SwInterfaceAddDelAddress,
    SwInterfaceAddDelAddressReply, SwInterfaceDetails, SwInterfaceDump, SwInterfaceSetFlags,
    SwInterfaceSetFlagsReply, SwInterfaceSetMacAddress, SwInterfaceSetMacAddressReply,
    SwInterfaceSetUnnumbered, SwInterfaceSetUnnumberedReply, ADDRESS_IP4,
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
pub const IF_STATUS_ADMIN_UP: u32 = 1;
/// `IF_STATUS_API_FLAG_LINK_UP` — carrier, not configuration.
pub const IF_STATUS_LINK_UP: u32 = 2;

/// Whether the VPP on the other end of the socket is one we just
/// started or one that was already running.
///
/// Explicit rather than inferred from `known` being empty, because the
/// two genuinely differ: a fresh VPP has no interfaces, so attaching is
/// always right; an adopted one may already have them, so attaching
/// without knowing the index is a duplicate waiting to happen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachMode {
    /// We spawned this process; it has no interfaces yet.
    Fresh,
    /// This process outlived us and may already own its interfaces.
    Adopted,
}

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
    /// The **PF's** MAC, read from `/sys/class/net/<port>/address`.
    ///
    /// The VF's own MAC is not usable: MCAM redirects frames addressed
    /// to the PF, so the interface must answer to that address or punt
    /// every one of them.
    pub pf_mac: [u8; 6],
}

/// A port VPP has accepted, with the index FIB paths must reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedPort {
    pub port: String,
    /// `Some` when we attached the device this pass; `None` when the
    /// interface was reused from a previous one (the dump does not
    /// report a device index, and nothing downstream needs it).
    pub dev_index: Option<u32>,
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
    /// The state file records an index VPP no longer has.
    ///
    /// Refused rather than silently re-attached: we cannot tell from
    /// here whether a live FIB still references the old index, and
    /// creating a second interface would leave routes pointing at
    /// something nothing services. A clean restart is the safe answer.
    /// The MAC we set is not the MAC VPP reports.
    ///
    /// Its own variant because the consequence is specific and silent:
    /// steered frames are addressed to the PF, so an interface holding
    /// any other MAC punts every one of them at `ethernet-input` while
    /// the FIB stays perfectly correct and health stays green.
    MacMismatch {
        port: String,
        asked: [u8; 6],
        got: [u8; 6],
    },
    StaleIndex {
        port: String,
        sw_if_index: u32,
    },
    /// We adopted a live VPP but have no recorded index for this port.
    ///
    /// Reachable without any schema mishap: process identity is
    /// persisted at spawn and the interface index only after attach, so
    /// a crash between those writes leaves a valid adoptable process
    /// and no index. Attaching would duplicate an interface the running
    /// VPP may already have, and the dump cannot disambiguate ports, so
    /// a clean restart is the only safe answer.
    UnknownIndexOnAdopt {
        port: String,
    },
}

impl std::fmt::Display for AttachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MacMismatch { port, asked, got } => write!(
                f,
                "{port}: asked VPP for MAC {} but it reports {}; steered frames are \
                 addressed to the PF, so this interface would punt every one of them at \
                 ethernet-input while the FIB and every health check stayed green",
                hex_mac(asked),
                hex_mac(got)
            ),
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
            AttachError::StaleIndex { port, sw_if_index } => write!(
                f,
                "state file records sw_if_index {sw_if_index} for {port} but VPP no longer has \
                 it; refusing to attach a duplicate while a live FIB may still reference the old \
                 index"
            ),
            AttachError::UnknownIndexOnAdopt { port } => write!(
                f,
                "adopted a running VPP but no sw_if_index is recorded for {port}; refusing to \
                 attach a possibly-duplicate interface — restart cleanly instead"
            ),
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

/// Attach every port and bring it admin-up — **idempotently**.
///
/// Sequential rather than pipelined, deliberately: each step consumes
/// the index the previous one returned, and there are a handful of
/// ports rather than a million routes — the latency this would save is
/// irrelevant next to being able to name exactly which port failed.
///
/// **A port VPP already has is reused, not re-attached.** The
/// supervisor emits `AttachDevices` on the adopted path too, where the
/// device and its interface already exist and the live FIB is already
/// pointing at their indices. Blindly re-issuing `dev_attach` there
/// would either be refused — and this module treats a refusal as fatal,
/// so it would cycle a healthy, possibly *steered* VPP, creating
/// exactly the outage adoption exists to avoid — or create a duplicate
/// interface whose index nothing in the FIB references. So the first
/// thing we do is ask VPP what it already has.
///
/// Stops at the first genuine failure. On failure the caller tears the
/// process down anyway (the supervisor routes it through `fail()`), so
/// partial cleanup here would duplicate what `Kill` does more reliably.
/// `known` maps a port name to the `sw_if_index` a previous attach
/// recorded — empty on a fresh attach, populated from the state file on
/// the adopted path. It is the identity source **because the interface
/// dump cannot be one**: the dump exposes `octeonN/P` and no PCI
/// address, so on a box with several member ports `octeon0/0` and
/// `octeon1/0` are indistinguishable by port id alone. Guessing there
/// would map a port to the wrong VF, which is worse than not adopting.
///
/// `mode` says whether the process on the other end of this socket was
/// adopted or freshly spawned, and it is **not** derivable from `known`
/// being empty. There is a real window in which we adopted a live VPP
/// and yet have no recorded index: the state file records process
/// identity at spawn and the interface index only after attach, so a
/// crash between those two writes — after `dev_create_port_if` already
/// succeeded — leaves exactly that combination. Blind-attaching there is
/// the duplicate-interface case this function exists to avoid, so
/// [`AttachMode::Adopted`] with a missing index refuses instead.
pub fn attach_ports(
    t: &mut Transport,
    ports: &[PortAttach],
    known: &[(String, u32)],
    mode: AttachMode,
    loop_idx: u32,
) -> Result<Vec<AttachedPort>, AttachError> {
    // One dump for the whole pass: it both confirms recorded indices
    // still exist and is the only way to see link state.
    let existing = interfaces(t)?;
    let mut out = Vec::with_capacity(ports.len());
    for p in ports {
        let recorded = known
            .iter()
            .find(|(name, _)| *name == p.port)
            .map(|(_, idx)| *idx);

        if recorded.is_none() && mode == AttachMode::Adopted {
            // We are talking to a VPP that was already running, and we
            // do not know what index it gave this port. It may already
            // have the interface; attaching would duplicate it, and
            // guessing from the dump is ruled out above. Refuse and let
            // the supervisor restart cleanly instead.
            return Err(AttachError::UnknownIndexOnAdopt {
                port: p.port.clone(),
            });
        }

        if let Some(idx) = recorded {
            if existing.iter().any(|i| i.sw_if_index == idx) {
                // Reuse. `dev_index` is not recoverable from the dump,
                // and nothing downstream needs it — FIB paths and link
                // checks both key on `sw_if_index` — so it stays `None`
                // rather than being invented.
                //
                // Admin-up is still asserted: controller deploys and
                // udapi provisioning can flap interface state under us,
                // and this is the reconcile point.
                set_admin_up(t, p, idx)?;
                // Re-asserted on the reuse path too, for the same
                // reason admin-up is: a controller deploy or a udapi
                // provisioning cycle can reset interface state under a
                // running VPP, and this is the reconcile point. A MAC
                // that silently reverted would punt every steered frame
                // while every counter stayed healthy.
                set_mac(t, p, idx, p.pf_mac)?;
                set_unnumbered(t, p, idx, loop_idx)?;
                out.push(AttachedPort {
                    port: p.port.clone(),
                    dev_index: None,
                    sw_if_index: idx,
                });
                continue;
            }
            // Recorded but gone. What that means depends entirely on
            // which VPP we are talking to.
            //
            // Adopted: refuse. A running VPP's FIB may still reference
            // the old index, and attaching a second interface would
            // leave two, with routes pointing at the one we are not
            // managing.
            //
            // Fresh: the index is stale by construction. We spawned this
            // process; it has no FIB and no interfaces, so nothing can
            // reference the recorded index and re-attaching is the only
            // correct move. Refusing here stranded the module on the
            // shadow (2026-08-07) after VPP was killed while packetframe
            // was not running — nothing had observed the exit, so
            // `on_process_gone` never cleared the record, and every
            // restart spawned a VPP it then refused to attach to. It
            // could not self-heal; only killing VPP again *with the
            // daemon watching* recovered it.
            if mode == AttachMode::Adopted {
                return Err(AttachError::StaleIndex {
                    port: p.port.clone(),
                    sw_if_index: idx,
                });
            }
            tracing::warn!(
                port = %p.port,
                stale_sw_if_index = idx,
                "state file records an interface this freshly spawned VPP does not have; \
                 discarding the record and attaching — a new process has no FIB that could \
                 reference it"
            );
        }

        let dev_index = attach_device(t, p)?;
        let sw_if_index = create_port_if(t, p, dev_index)?;
        set_admin_up(t, p, sw_if_index)?;
        // Order matters and is not arbitrary: MAC before unnumbered,
        // both before the port is announced as attached. A port handed
        // to the sink before it can forward is a port the FIB will
        // resolve routes onto while every packet dies at
        // `ip4-not-enabled`.
        set_mac(t, p, sw_if_index, p.pf_mac)?;
        set_unnumbered(t, p, sw_if_index, loop_idx)?;
        out.push(AttachedPort {
            port: p.port.clone(),
            dev_index: Some(dev_index),
            sw_if_index,
        });
    }
    Ok(out)
}

/// Every interface VPP currently has.
///
/// Returns [`TransportError`] rather than [`AttachError`] because a
/// dump has no attach-specific failure modes — and because
/// [`crate::verify`] needs it too, for link state.
pub fn interfaces(t: &mut Transport) -> Result<Vec<Interface>, TransportError> {
    let details: Vec<SwInterfaceDetails> = t.dump(SwInterfaceDump {
        context: 0,
        // ~0 = all interfaces; an empty name filter must be paired with
        // `name_filter_valid = false` or VPP matches nothing.
        sw_if_index: u32::MAX,
        name_filter_valid: false,
        name_filter: String::new(),
    })?;
    Ok(details
        .into_iter()
        .map(|d| Interface {
            sw_if_index: d.sw_if_index,
            name: d.interface_name,
            flags: d.flags,
            l2_address: d.l2_address,
        })
        .collect())
}

/// One interface as VPP reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub sw_if_index: u32,
    pub name: String,
    pub flags: u32,
    /// What VPP believes this interface's MAC is. The only way to check
    /// that `sw_interface_set_mac_address` did anything.
    pub l2_address: [u8; 6],
}

impl Interface {
    pub fn admin_up(&self) -> bool {
        self.flags & IF_STATUS_ADMIN_UP != 0
    }

    /// Whether the interface has carrier.
    ///
    /// Distinct from [`Self::admin_up`] and that distinction is the
    /// whole point: an admin-up interface with no link keeps every FIB
    /// path pointing at a valid index while forwarding nothing.
    pub fn link_up(&self) -> bool {
        self.flags & IF_STATUS_LINK_UP != 0
    }
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

/// A config prefix as VPP's wire `Prefix`.
fn prefix_of(p: Ipv4Prefix) -> Prefix {
    let mut u = [0u8; 16];
    u[..4].copy_from_slice(&p.addr.octets());
    Prefix {
        address: Address {
            af: ADDRESS_IP4,
            un: AddressUnion(u),
        },
        len: p.prefix_len,
    }
}

/// `58:d6:1f:4f:cd:56`, for error messages an operator compares against
/// `ip link` output.
fn hex_mac(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Give the interface the PF's MAC, then read the dump back and check.
///
/// Steered frames arrive addressed to the **PF**, because that is what
/// MCAM redirects; the VF carries its own MAC, so without this every one
/// of them is punted `ethernet-input: l3 mac mismatch`. Traced on
/// hardware 2026-08-07 — 100 frames in, 100 punted, FIB correct
/// throughout.
///
/// It is also what makes VPP *source* MAC-PF on transmit, which the
/// design requires: the frame then leaves the same LMAC the kernel uses,
/// so the upstream switch never sees the address move ports.
///
/// The readback is not ceremony. `sw_interface_set_mac_address` can
/// return 0 and leave the interface unchanged on a driver that does not
/// implement it, and the failure mode is invisible — every packet
/// punted, every counter healthy. `sw_interface_dump` reports
/// `l2_address`, so the check costs one dump we already know how to do.
fn set_mac(
    t: &mut Transport,
    p: &PortAttach,
    sw_if_index: u32,
    mac: [u8; 6],
) -> Result<(), AttachError> {
    let reply = t.request::<SwInterfaceSetMacAddress, SwInterfaceSetMacAddressReply>(
        SwInterfaceSetMacAddress {
            context: 0,
            sw_if_index,
            mac_address: mac,
        },
    )?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "sw_interface_set_mac_address",
            port: p.port.clone(),
            retval: reply.retval,
            detail: format!("mac {}", hex_mac(&mac)),
        });
    }
    let got = interfaces(t)?
        .into_iter()
        .find(|i| i.sw_if_index == sw_if_index)
        .map(|i| i.l2_address)
        .ok_or_else(|| AttachError::StaleIndex {
            port: p.port.clone(),
            sw_if_index,
        })?;
    if got != mac {
        return Err(AttachError::MacMismatch {
            port: p.port.clone(),
            asked: mac,
            got,
        });
    }
    Ok(())
}

/// The loopback a surviving VPP already has, if any.
///
/// Adoption must discover VPP's state, not recreate it — the same rule
/// that governs port interfaces, learned again the hard way. Creating a
/// second loopback and assigning it an address the first one already
/// holds fails with `VNET_API_ERROR_ADDRESS_IN_USE`, which is what a
/// daemon restart over a live VPP did on the shadow (2026-08-07) the
/// first time that path ran.
///
/// Matched by name because VPP names loopbacks `loop0`, `loop1`, … and
/// nothing else talks to this VPP: the module spawns it on a private
/// socket under its own runtime directory. That is the whole assumption,
/// and it is worth stating rather than leaving implicit — a loopback
/// created by anything else would be adopted as ours.
pub fn find_loopback(t: &mut Transport) -> Result<Option<u32>, TransportError> {
    let mut found: Vec<u32> = interfaces(t)?
        .into_iter()
        .filter(|i| i.name.starts_with("loop"))
        .map(|i| i.sw_if_index)
        .collect();
    // Lowest index: the first one created, which is ours if a previous
    // run left more than one behind.
    found.sort_unstable();
    Ok(found.first().copied())
}

/// `VNET_API_ERROR_DUPLICATE_IF_ADDRESS` from vnet/error.h (stable/2506).
///
/// VPP's error string says "already present on another interface" and the
/// string is wrong: `ip4_add_del_interface_address_internal` returns this
/// for an exact-prefix re-add on the **same** interface. The
/// cross-interface conflict is `-105 ADDRESS_IN_USE` — which is what the
/// shadow produced when a second loopback was given the first one's
/// address, and that observation is what disambiguates the two. Checked
/// against the source rather than recalled, because "re-adding an address
/// is idempotent" was the recalled version and it is false.
pub const VNET_API_ERROR_DUPLICATE_IF_ADDRESS: i32 = -127;

/// Reconcile an adopted loopback: re-assert its address and admin-up.
///
/// Discovery alone is not adoption. [`find_loopback`] matches by name,
/// and a name proves nothing about the two properties `create_loopback`
/// establishes after creating: the address members borrow, and admin-up.
/// A daemon crash between `create_loopback`'s create and its address-add
/// leaves exactly that — a named, addressless loopback — and adopting it
/// blind puts every member behind `ip4-not-enabled` with the FIB verified
/// green. The member reuse path re-asserts admin-up, MAC and unnumbered
/// for the same reason; this is the loopback's version of that reconcile
/// point.
///
/// The address re-assert cannot be a plain "must return 0": VPP answers
/// an exact re-add on the same interface with
/// [`VNET_API_ERROR_DUPLICATE_IF_ADDRESS`], which here means *the address
/// is already exactly where we want it* — the common case on every
/// healthy adoption. Anything else, including `-105 ADDRESS_IN_USE`
/// (something *else* holds the address), stays fatal.
pub fn adopt_loopback(
    t: &mut Transport,
    loop_idx: u32,
    addr: Ipv4Prefix,
) -> Result<(), AttachError> {
    let reply = t.request::<SwInterfaceAddDelAddress, SwInterfaceAddDelAddressReply>(
        SwInterfaceAddDelAddress {
            context: 0,
            sw_if_index: loop_idx,
            is_add: true,
            del_all: false,
            prefix: prefix_of(addr),
        },
    )?;
    if reply.retval != 0 && reply.retval != VNET_API_ERROR_DUPLICATE_IF_ADDRESS {
        return Err(AttachError::Refused {
            step: "sw_interface_add_del_address (adopt)",
            port: "loop0".into(),
            retval: reply.retval,
            detail: format!("{}/{}", addr.addr, addr.prefix_len),
        });
    }

    let reply =
        t.request::<SwInterfaceSetFlags, SwInterfaceSetFlagsReply>(SwInterfaceSetFlags {
            context: 0,
            sw_if_index: loop_idx,
            flags: IF_STATUS_ADMIN_UP,
        })?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "sw_interface_set_flags(loop0, adopt)",
            port: "loop0".into(),
            retval: reply.retval,
            detail: String::new(),
        });
    }
    Ok(())
}

/// Create the loopback that member ports borrow an address from.
///
/// One per VPP, holding the router address. Returns its `sw_if_index`
/// so teardown can delete it and so members can be unnumbered to it.
pub fn create_loopback(t: &mut Transport, addr: Ipv4Prefix) -> Result<u32, AttachError> {
    let reply = t.request::<CreateLoopback, CreateLoopbackReply>(CreateLoopback {
        context: 0,
        // Zero asks VPP to pick one. A loopback never puts a frame on a
        // wire, so its address is not load-bearing the way a member
        // port's is.
        mac_address: [0; 6],
    })?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "create_loopback",
            port: "loop0".into(),
            retval: reply.retval,
            detail: String::new(),
        });
    }
    let loop_idx = reply.sw_if_index;

    let reply = t.request::<SwInterfaceAddDelAddress, SwInterfaceAddDelAddressReply>(
        SwInterfaceAddDelAddress {
            context: 0,
            sw_if_index: loop_idx,
            is_add: true,
            del_all: false,
            prefix: prefix_of(addr),
        },
    )?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "sw_interface_add_del_address",
            port: "loop0".into(),
            retval: reply.retval,
            detail: format!("{}/{}", addr.addr, addr.prefix_len),
        });
    }

    let reply =
        t.request::<SwInterfaceSetFlags, SwInterfaceSetFlagsReply>(SwInterfaceSetFlags {
            context: 0,
            sw_if_index: loop_idx,
            flags: IF_STATUS_ADMIN_UP,
        })?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "sw_interface_set_flags(loop0)",
            port: "loop0".into(),
            retval: reply.retval,
            detail: String::new(),
        });
    }
    Ok(loop_idx)
}

/// Enable IPv4 on a member by borrowing the loopback's address.
///
/// Admin-up is not enough: an interface with no IPv4 drops every packet
/// at `ip4-not-enabled`, *after* a correct FIB lookup would have
/// succeeded. Observed on hardware with 1,053,960 routes installed and
/// verified, forwarding zero.
///
/// Unnumbered rather than a per-port address because VPP rejects
/// overlapping subnets across interfaces, and because one router address
/// is what should source ICMP — PMTUD's frag-needed has to come from an
/// address the sender can route back to.
///
/// **Not readback-verified**, unlike the MAC: `sw_interface_dump` does
/// not report IP-enabled state, and no dump in the whitelist does. This
/// rests on the API's acknowledgement, which is weaker, and the
/// difference is deliberate rather than overlooked.
fn set_unnumbered(
    t: &mut Transport,
    p: &PortAttach,
    sw_if_index: u32,
    loop_idx: u32,
) -> Result<(), AttachError> {
    let reply = t.request::<SwInterfaceSetUnnumbered, SwInterfaceSetUnnumberedReply>(
        SwInterfaceSetUnnumbered {
            context: 0,
            sw_if_index: loop_idx,
            unnumbered_sw_if_index: sw_if_index,
            is_add: true,
        },
    )?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "sw_interface_set_unnumbered",
            port: p.port.clone(),
            retval: reply.retval,
            detail: String::new(),
        });
    }
    Ok(())
}

fn set_admin_up(t: &mut Transport, p: &PortAttach, sw_if_index: u32) -> Result<(), AttachError> {
    let reply =
        t.request::<SwInterfaceSetFlags, SwInterfaceSetFlagsReply>(SwInterfaceSetFlags {
            context: 0,
            sw_if_index,
            flags: IF_STATUS_ADMIN_UP,
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
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
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
