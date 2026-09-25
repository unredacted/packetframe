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
//! Which worker polls each rx queue is decided by the ORDER of the
//! creates, not by any call here: the octeon driver runs on VPP's
//! `vnet_dev` framework, which assigns rx queues round-robin across
//! workers as ports are created and never registers them with the
//! generic rx-placement machinery — so `sw_interface_set_rx_placement`
//! answers "unknown queue" for every octeon port (measured on the rig,
//! 2026-09-24; `vnet_dev_port_if_create` in VPP v26.06). The caller
//! orders ports so that round-robin lands where the operator sized; see
//! [`crate::cores::creation_order`].
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
    Address, AddressUnion, BridgeDomainAddDelV2, BridgeDomainAddDelV2Reply, CreateLoopback,
    CreateLoopbackInstance, CreateLoopbackInstanceReply, CreateLoopbackReply, CreateVlanSubif,
    CreateVlanSubifReply, DevAttach, DevAttachReply, DevCreatePortIf, DevCreatePortIfReply,
    L2InterfaceVlanTagRewrite, L2InterfaceVlanTagRewriteReply, L2fibAddDel, L2fibAddDelReply,
    Prefix, SwInterfaceAddDelAddress, SwInterfaceAddDelAddressReply, SwInterfaceAddDelMacAddress,
    SwInterfaceAddDelMacAddressReply, SwInterfaceDetails, SwInterfaceDump, SwInterfaceSetFlags,
    SwInterfaceSetFlagsReply, SwInterfaceSetL2Bridge, SwInterfaceSetL2BridgeReply,
    SwInterfaceSetMacAddress, SwInterfaceSetMacAddressReply, SwInterfaceSetMtu,
    SwInterfaceSetMtuReply, SwInterfaceSetPromisc, SwInterfaceSetPromiscReply,
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
    /// Receive queues, from the operator's `cores` promise — at least
    /// one, since a `cores 0` port still has a queue (polled by the
    /// shared worker).
    pub num_rx_queues: u16,
    /// The member's PRIMARY MAC — always the PF's own address, from
    /// `/sys/class/net/<port>/address`.
    ///
    /// The VF's factory MAC is not usable (MCAM redirects frames as
    /// the wire carries them), and the bridge's MAC is not usable
    /// *here*: on this NIC the primary is programmed into the VF's
    /// hardware filter, so a bridge MAC in this field captures
    /// delivery of every gateway-addressed frame even with steering
    /// off — w22, 2026-08-14. Acceptance of other addresses belongs in
    /// [`Self::accept_macs`].
    pub pf_mac: [u8; 6],
    /// Additional MACs this interface must **accept** frames for,
    /// added as VPP secondary addresses.
    ///
    /// A bridge-member port's real audience addresses the *bridge's*
    /// MAC (it is what ARP hands out), and a secondary entry is an
    /// acceptance-list entry at `ethernet-input` — the node that
    /// punted w21's 7.17M classified frames — rather than a hardware
    /// filter. Empty for plain L3 ports and for a bridge that took its
    /// MAC from this port.
    pub accept_macs: Vec<[u8; 6]>,
    /// 802.1Q tags steered ingress arrives with on this port, from the
    /// operator's `vlans` declaration. One exact-match dot1q subif is
    /// created per id at attach; a tagged frame with no subif never
    /// reaches ip4-input — it is punted at ethernet-input regardless
    /// of MAC or promisc. Measured on the primary (w20, 2026-08-14):
    /// the first steer of a trunk port punted 8.7M frames in two
    /// minutes with every gauge green. Empty for untagged ports.
    pub vlans: Vec<u16>,
    /// The kernel port's MTU, to set as the VF's L3 MTU. VPP applies a
    /// parent's L3 MTU to its subifs too (`vnet_sw_interface_get_mtu`
    /// reads the sup interface) and falls back to 9000 when none was
    /// set — so without this, a jumbo frame arriving on a trunk left a
    /// 1500-byte transit port oversized instead of drawing the ICMP
    /// frag-needed PMTUD depends on. `None` leaves VPP's default.
    pub mtu: Option<u32>,
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
    /// `(vlan id, sw_if_index)` for every dot1q subinterface this
    /// port carries, created or adopted — in `vlans` declaration
    /// order. These are what `local-route` attached routes and the
    /// bridge neighbour mirror reference: a FIB path on the PARENT
    /// index would transmit untagged and die on the trunk.
    pub subifs: Vec<(u16, u32)>,
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
                set_mtu(t, p, idx)?;
                // Re-asserted on the reuse path too, for the same
                // reason admin-up is: a controller deploy or a udapi
                // provisioning cycle can reset interface state under a
                // running VPP, and this is the reconcile point. A MAC
                // that silently reverted would punt every steered frame
                // while every counter stayed healthy.
                set_mac(t, p, idx, p.pf_mac)?;
                set_accept_macs(t, p, idx, true)?;
                set_promisc_on(t, p, idx)?;
                set_unnumbered(t, p, idx, loop_idx)?;
                let subifs = ensure_vlan_subifs(t, p, idx, loop_idx, &existing)?;
                out.push(AttachedPort {
                    port: p.port.clone(),
                    dev_index: None,
                    sw_if_index: idx,
                    subifs,
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
        set_mtu(t, p, sw_if_index)?;
        // Order matters and is not arbitrary: MAC before unnumbered,
        // both before the port is announced as attached. A port handed
        // to the sink before it can forward is a port the FIB will
        // resolve routes onto while every packet dies at
        // `ip4-not-enabled`.
        set_mac(t, p, sw_if_index, p.pf_mac)?;
        set_accept_macs(t, p, sw_if_index, false)?;
        set_promisc_on(t, p, sw_if_index)?;
        set_unnumbered(t, p, sw_if_index, loop_idx)?;
        // A freshly created parent cannot have subifs, so the dump
        // taken before this pass is still the right reuse authority:
        // it can only say "not found", and every vid gets created.
        let subifs = ensure_vlan_subifs(t, p, sw_if_index, loop_idx, &existing)?;
        out.push(AttachedPort {
            port: p.port.clone(),
            dev_index: Some(dev_index),
            sw_if_index,
            subifs,
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

/// Reconcile an adopted loopback: re-assert admin-up, and admin-up
/// ONLY.
///
/// The address is deliberately **not** re-asserted, and the history is
/// the argument. The first version trusted the name alone; the second
/// re-asserted the address, accepting `-127 DUPLICATE_IF_ADDRESS` as
/// "already exactly where we want it" (correct per stable/2506 source
/// for a plain same-interface re-add). Hardware then refuted the model
/// (shadow, 2026-08-08): with member ports **unnumbered to the
/// loopback**, VPP's cross-interface conflict scan sees the borrowed
/// address as held by another interface and answers `-105
/// ADDRESS_IN_USE` — on every healthy adoption of this design's own
/// steady state. `-105` is also the genuine-conflict signal, so on this
/// topology the re-assert carries zero distinguishing information, and
/// whitelisting it would bless real conflicts. The failure it caused
/// was not hypothetical: the refusal drove teardown, killed the adopted
/// VPP, and the fresh respawn re-steered into a 6-second-old partial
/// table for 27 s of measured blackhole.
///
/// What this deliberately leaves open: a daemon crash between
/// `create_loopback`'s create and its address-add leaves a named,
/// addressless loopback that adoption will trust. That window is two
/// adjacent API round trips on a unix socket, no whitelisted message
/// can dump addresses to check (`sw_interface_dump` reports MACs, not
/// prefixes), and the cure measured worse than the disease. Closing it
/// properly means adding `ip_address_dump` to the API whitelist and
/// doing a true readback — tracked as future hardening, not faked with
/// a probe whose answer cannot be interpreted.
pub fn adopt_loopback(t: &mut Transport, loop_idx: u32) -> Result<(), AttachError> {
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

/// Add every [`PortAttach::accept_macs`] entry as a VPP secondary MAC.
///
/// This is the acceptance half of the dmac story, and it is separate
/// from [`set_mac`] on purpose. `sw_interface_set_mac_address` moves
/// the interface's identity — and on this NIC that identity is a
/// hardware filter, so pointing it at the bridge's address made the VF
/// receive gateway traffic the MCAM had never steered (w22,
/// 2026-08-14: ~300 kpps with the lever off). A secondary address adds
/// an entry to the acceptance list `ethernet-input` consults, which is
/// exactly the check that punted w21's classified frames, and adds
/// nothing to what the NIC delivers.
///
/// **Not idempotent, whatever the API reads like.** Re-adding an address
/// the interface already holds is refused with retval -9 on this
/// platform (lab rig, 2026-09-23): the first real restart over a
/// steered VPP re-added the bridge MAC the previous daemon had added,
/// the attach failed, and the supervisor tore down the VPP it had just
/// adopted. So on the reuse path (`reasserting`) that refusal, -9 and
/// only -9, is logged and tolerated: the recorded index is only persisted after a complete
/// attach, so the previous daemon added it, and -9 is VPP's catch-all
/// for a device-class failure, so it cannot distinguish "already held"
/// from "lost and not re-addable" — the same zero-information problem
/// `adopt_loopback`'s address re-assert had. The add is still ATTEMPTED
/// there, so a secondary a provisioning cycle really removed comes
/// back. On a fresh interface a refusal stays fatal: nothing can
/// already hold it.
///
/// **Unverified by readback**, unlike the primary: no whitelisted dump
/// reports an interface's secondary addresses. If the octeon driver
/// turns out to program secondaries into hardware after all, the
/// symptom is w22's — traffic arriving unsteered — and the rung-0
/// leak check in the runbook is what catches it.
/// What VPP answered for a re-added secondary on the rig (2026-09-23):
/// `VNET_API_ERROR_UNIMPLEMENTED`, its catch-all for a device-class
/// failure. The ONLY refusal tolerated on the reuse path — any other
/// code is not the observed duplicate, and stays fatal (review finding).
const DUPLICATE_SECONDARY_RETVAL: i32 = -9;

fn set_accept_macs(
    t: &mut Transport,
    p: &PortAttach,
    sw_if_index: u32,
    reasserting: bool,
) -> Result<(), AttachError> {
    for mac in &p.accept_macs {
        let reply = t.request::<SwInterfaceAddDelMacAddress, SwInterfaceAddDelMacAddressReply>(
            SwInterfaceAddDelMacAddress {
                context: 0,
                sw_if_index,
                addr: *mac,
                is_add: 1,
            },
        )?;
        if reply.retval == DUPLICATE_SECONDARY_RETVAL && reasserting {
            tracing::info!(
                port = %p.port,
                secondary_mac = %hex_mac(mac),
                retval = reply.retval,
                "VPP refused re-adding a secondary MAC on a reused interface — expected on a \
                 takeover, where the previous daemon already added it; if steered frames to \
                 this address start punting, `packetframe detach --all` and re-attach"
            );
            continue;
        }
        if reply.retval != 0 {
            return Err(AttachError::Refused {
                step: "sw_interface_add_del_mac_address",
                port: p.port.clone(),
                retval: reply.retval,
                detail: hex_mac(mac),
            });
        }
        tracing::info!(
            port = %p.port,
            secondary_mac = %hex_mac(mac),
            "secondary MAC accepted — frames addressed to the bridge now classify instead \
             of punting, without moving what the NIC delivers"
        );
    }
    Ok(())
}

/// Create (or re-adopt) one exact-match dot1q subif per declared vlan.
///
/// Why this exists: MCAM steering diverts frames as the wire carries
/// them, and on a trunk port that is 802.1Q-tagged. A tagged frame
/// with no matching subinterface never reaches `ip4-input` — VPP
/// punts it at `ethernet-input` before any MAC, promisc or FIB logic
/// runs. w20 on the primary (2026-08-14) measured the consequence:
/// the first steer of eth4 delivered 8.7M frames in two minutes and
/// every one was punted, with zero `ip4`, zero tx, and every health
/// surface green.
///
/// Each subif gets the same treatment as its parent — admin-up and
/// unnumbered to the loopback — so classified frames route with the
/// same adjacencies. MAC and promisc are the parent's; a subif has
/// neither of its own.
///
/// Reuse: on an adopted VPP the subifs already exist, and creating a
/// duplicate vid is a refusal. VPP names them `<parent>.<vid>`, so the
/// pre-pass dump identifies them by name; found ones are re-asserted
/// (up + unnumbered — the reconcile point, same as the parent's), and
/// only missing ones are created.
fn ensure_vlan_subifs(
    t: &mut Transport,
    p: &PortAttach,
    parent_idx: u32,
    loop_idx: u32,
    existing: &[Interface],
) -> Result<Vec<(u16, u32)>, AttachError> {
    if p.vlans.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::with_capacity(p.vlans.len());
    let parent_name = existing
        .iter()
        .find(|i| i.sw_if_index == parent_idx)
        .map(|i| i.name.clone());
    for &vid in &p.vlans {
        let reused = parent_name.as_deref().and_then(|parent| {
            let want = format!("{parent}.{vid}");
            existing
                .iter()
                .find(|i| i.name == want)
                .map(|i| i.sw_if_index)
        });
        let sub_idx = match reused {
            Some(idx) => idx,
            None => {
                let reply =
                    t.request::<CreateVlanSubif, CreateVlanSubifReply>(CreateVlanSubif {
                        context: 0,
                        sw_if_index: parent_idx,
                        vlan_id: u32::from(vid),
                    })?;
                if reply.retval != 0 {
                    return Err(AttachError::Refused {
                        step: "create_vlan_subif",
                        port: p.port.clone(),
                        retval: reply.retval,
                        detail: format!("vlan {vid}"),
                    });
                }
                if reply.sw_if_index == 0 {
                    return Err(AttachError::LocalZero {
                        port: format!("{}.{vid}", p.port),
                    });
                }
                reply.sw_if_index
            }
        };
        set_admin_up(t, p, sub_idx)?;
        set_unnumbered(t, p, sub_idx, loop_idx)?;
        tracing::info!(
            port = %p.port,
            vlan = vid,
            sw_if_index = sub_idx,
            reused = reused.is_some(),
            "dot1q subif ready — tagged steered ingress classifies to ip4 instead of punting"
        );
        out.push((vid, sub_idx));
    }
    Ok(out)
}

/// Give an attached port subifs for `vids`, while VPP runs — how a
/// `vlans all` trunk follows a VLAN added on the switch without a
/// restart. Same routine attach uses, over a fresh interface dump, so a
/// subif that already exists (a previous pass, an adopted VPP) is reused
/// and re-asserted rather than duplicated.
pub fn add_vlan_subifs(
    t: &mut Transport,
    p: &PortAttach,
    parent_idx: u32,
    loop_idx: u32,
    vids: &[u16],
) -> Result<Vec<(u16, u32)>, AttachError> {
    let existing = interfaces(t)?;
    let scoped = PortAttach {
        vlans: vids.to_vec(),
        ..p.clone()
    };
    ensure_vlan_subifs(t, &scoped, parent_idx, loop_idx, &existing)
}

/// One bridged VLAN's VPP side: a bridge domain, its BVI, and the trunk
/// subifs that carry the VLAN.
///
/// **Why a BVI.** VPP transmits from an interface's own MAC, and a
/// member VF's MAC must stay the port's own — making it the kernel
/// bridge's captured all gateway traffic into VPP (w22, a hardware RX
/// filter on this NIC). So a subif routing directly sends from the
/// PORT's MAC, while the kernel sends the same VLAN from the BRIDGE's —
/// the MAC an IX registers, and an IX drops (SIX) or shuts the port
/// (KCIX) on a foreign one. A BVI is a loopback, software-only, so it
/// can carry the bridge's MAC without filtering anything: VPP routes
/// onto the BVI, the frame leaves with the bridge MAC through the
/// bridge domain, and the member subif pushes the tag back on.
///
/// Member subifs join with split-horizon group 1, so VPP never forwards
/// between trunks — the kernel bridge does all real bridging — and pop
/// their tag on ingress (push on egress). Learning is off: placement
/// programs static L2FIB entries from the kernel's FDB, and an unknown
/// destination floods to every member, as the kernel bridge would.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeSpec {
    pub vid: u16,
    /// The kernel bridge-VLAN L3 device's MAC — what the kernel sends
    /// this VLAN from.
    pub mac: [u8; 6],
    pub mtu: Option<u32>,
    /// `(port, subif sw_if_index)` for each member carrying the VLAN.
    pub members: Vec<(String, u32)>,
}

/// VPP's "bridge domain already exists" — a surviving VPP's, re-asserted.
const BD_ALREADY_EXISTS: i32 = -119;
/// VPP's "bridge domain already has a BVI" — ours, from a previous run.
const BD_ALREADY_HAS_BVI: i32 = -152;
/// `L2_VTR_POP_1`: pop one tag on ingress, push it back on egress.
const L2_VTR_POP_1: u32 = 3;
/// `L2_API_PORT_TYPE_NORMAL` / `_BVI`.
const L2_PORT_NORMAL: u32 = 0;
const L2_PORT_BVI: u32 = 1;
/// The split-horizon group every trunk member shares: no forwarding
/// between them inside VPP.
const TRUNK_SHG: u8 = 1;

/// Create (or reuse) `spec`'s bridge domain, BVI and member wiring, and
/// return the BVI's index. Idempotent: a surviving VPP's domain, BVI
/// (found by its deterministic name, `loop<vid>`) and memberships are
/// re-asserted rather than duplicated.
pub fn ensure_bridge_domain(
    t: &mut Transport,
    spec: &BridgeSpec,
    loop_idx: u32,
) -> Result<u32, AttachError> {
    let label = format!("bridge vlan {}", spec.vid);
    let refused = |step: &'static str, retval: i32, detail: String| AttachError::Refused {
        step,
        port: label.clone(),
        retval,
        detail,
    };
    let bd_id = u32::from(spec.vid);
    let reply =
        t.request::<BridgeDomainAddDelV2, BridgeDomainAddDelV2Reply>(BridgeDomainAddDelV2 {
            context: 0,
            bd_id,
            flood: true,
            uu_flood: true,
            forward: true,
            learn: false,
            arp_term: false,
            arp_ufwd: false,
            mac_age: 0,
            bd_tag: String::new(),
            is_add: true,
        })?;
    if reply.retval != 0 && reply.retval != BD_ALREADY_EXISTS {
        return Err(refused(
            "bridge_domain_add_del_v2",
            reply.retval,
            String::new(),
        ));
    }

    let name = format!("loop{}", spec.vid);
    let existing = interfaces(t)?;
    let bvi = match existing.iter().find(|i| i.name == name) {
        Some(i) => i.sw_if_index,
        None => {
            let reply = t.request::<CreateLoopbackInstance, CreateLoopbackInstanceReply>(
                CreateLoopbackInstance {
                    context: 0,
                    mac_address: spec.mac,
                    is_specified: true,
                    user_instance: u32::from(spec.vid),
                },
            )?;
            if reply.retval != 0 || reply.sw_if_index == 0 {
                return Err(refused(
                    "create_loopback_instance",
                    reply.retval,
                    format!("{name} for the BVI"),
                ));
            }
            reply.sw_if_index
        }
    };
    let up = t.request::<SwInterfaceSetFlags, SwInterfaceSetFlagsReply>(SwInterfaceSetFlags {
        context: 0,
        sw_if_index: bvi,
        flags: IF_STATUS_ADMIN_UP,
    })?;
    if up.retval != 0 {
        return Err(refused("sw_interface_set_flags", up.retval, name.clone()));
    }
    let un = t.request::<SwInterfaceSetUnnumbered, SwInterfaceSetUnnumberedReply>(
        SwInterfaceSetUnnumbered {
            context: 0,
            sw_if_index: loop_idx,
            unnumbered_sw_if_index: bvi,
            is_add: true,
        },
    )?;
    if un.retval != 0 {
        return Err(refused(
            "sw_interface_set_unnumbered",
            un.retval,
            name.clone(),
        ));
    }
    if let Some(mtu) = spec.mtu {
        let r = t.request::<SwInterfaceSetMtu, SwInterfaceSetMtuReply>(SwInterfaceSetMtu {
            context: 0,
            sw_if_index: bvi,
            mtu: [mtu, 0, 0, 0],
        })?;
        if r.retval != 0 {
            return Err(refused(
                "sw_interface_set_mtu",
                r.retval,
                format!("{name} mtu {mtu}"),
            ));
        }
    }
    let join = |t: &mut Transport, sw: u32, port_type: u32, shg: u8| {
        t.request::<SwInterfaceSetL2Bridge, SwInterfaceSetL2BridgeReply>(SwInterfaceSetL2Bridge {
            context: 0,
            rx_sw_if_index: sw,
            bd_id,
            port_type,
            shg,
            enable: true,
        })
    };
    let r = join(t, bvi, L2_PORT_BVI, 0)?;
    if r.retval != 0 && r.retval != BD_ALREADY_HAS_BVI {
        return Err(refused(
            "sw_interface_set_l2_bridge",
            r.retval,
            format!("{name} as BVI"),
        ));
    }
    for (port, subif) in &spec.members {
        let r = join(t, *subif, L2_PORT_NORMAL, TRUNK_SHG)?;
        if r.retval != 0 {
            return Err(refused(
                "sw_interface_set_l2_bridge",
                r.retval,
                format!("{port}.{} into the bridge domain", spec.vid),
            ));
        }
        let r = t.request::<L2InterfaceVlanTagRewrite, L2InterfaceVlanTagRewriteReply>(
            L2InterfaceVlanTagRewrite {
                context: 0,
                sw_if_index: *subif,
                vtr_op: L2_VTR_POP_1,
                push_dot1q: 0,
                tag1: 0,
                tag2: 0,
            },
        )?;
        if r.retval != 0 {
            return Err(refused(
                "l2_interface_vlan_tag_rewrite",
                r.retval,
                format!("{port}.{} pop 1", spec.vid),
            ));
        }
    }
    tracing::info!(
        vlan = spec.vid,
        bvi = %name,
        mac = %hex_mac(&spec.mac),
        members = ?spec.members.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        "bridged VLAN routes through its BVI — frames leave from the kernel bridge's MAC"
    );
    Ok(bvi)
}

/// Point `mac` at `subif` in bridge domain `vid` (static), or remove the
/// entry so the MAC floods to every member again.
pub fn l2fib_set(
    t: &mut Transport,
    vid: u16,
    mac: [u8; 6],
    subif: u32,
    is_add: bool,
) -> Result<(), AttachError> {
    let r = t.request::<L2fibAddDel, L2fibAddDelReply>(L2fibAddDel {
        context: 0,
        mac,
        bd_id: u32::from(vid),
        sw_if_index: subif,
        is_add,
        static_mac: true,
        filter_mac: false,
        bvi_mac: false,
    })?;
    // Deleting an entry that is not there is the postcondition already.
    if r.retval != 0 && is_add {
        return Err(AttachError::Refused {
            step: "l2fib_add_del",
            port: format!("bridge vlan {vid}"),
            retval: r.retval,
            detail: hex_mac(&mac),
        });
    }
    Ok(())
}

/// Promiscuous mode on the member VF — a shared-LMAC VOTE, not a local
/// flag, and the fix for the primary bridge-blackout (2026-08-14).
///
/// On this hardware the rvu AF keeps per-function rx-mode state and
/// re-evaluates the channel's default MCAM entries — the AF-installed
/// promisc + multicast catch-alls that forward to the KERNEL PF — on
/// every rx-mode event from ANY function sharing the LMAC. VPP's octeon
/// driver asserts promisc=off at port start (its default), which
/// disabled those entries channel-wide: the bridge-member PF went deaf
/// to every frame not addressed to its exact unicast MAC, service
/// delivery died below the kernel (rx_drops flat — frames never reached
/// the PF), and the kernel's own IFF_PROMISC flag stayed set the whole
/// time, so nothing host-side looked wrong. Measured directly: NPC MCAM
/// entries 2004/2005 on channel 0x800 flipped enabled yes->no at VPP
/// interface-up; an rx-mode kick from the kernel side re-enabled them,
/// and the next AF re-evaluation (bridge mcast churn arrives every few
/// seconds) disabled them again — a war, not a fix.
///
/// Setting the VPP port promiscuous flips the VF's STORED vote, so
/// every future re-evaluation — whoever triggers it — lands on
/// enabled. The entries forward to the PF, not to us, so this does not
/// divert bridge traffic into VPP; it stops VPP's default from
/// un-forwarding it. Asserted on both the fresh and reuse paths for
/// the same reason the MAC is: this is the reconcile point.
fn set_promisc_on(t: &mut Transport, p: &PortAttach, sw_if_index: u32) -> Result<(), AttachError> {
    let reply =
        t.request::<SwInterfaceSetPromisc, SwInterfaceSetPromiscReply>(SwInterfaceSetPromisc {
            context: 0,
            sw_if_index,
            promisc_on: true,
        })?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "sw_interface_set_promisc",
            port: p.port.clone(),
            retval: reply.retval,
            detail: String::new(),
        });
    }
    Ok(())
}

/// Mirror the kernel port's MTU onto the VF as its L3 MTU. The
/// per-protocol slots stay 0 so IP4/IP6/MPLS inherit it. Idempotent —
/// VPP compares before changing — so it is re-asserted on reuse like the
/// MAC and admin state.
fn set_mtu(t: &mut Transport, p: &PortAttach, sw_if_index: u32) -> Result<(), AttachError> {
    let Some(mtu) = p.mtu else {
        return Ok(());
    };
    let reply = t.request::<SwInterfaceSetMtu, SwInterfaceSetMtuReply>(SwInterfaceSetMtu {
        context: 0,
        sw_if_index,
        mtu: [mtu, 0, 0, 0],
    })?;
    if reply.retval != 0 {
        return Err(AttachError::Refused {
            step: "sw_interface_set_mtu",
            port: p.port.clone(),
            retval: reply.retval,
            detail: format!("mtu {mtu}"),
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
            accept_macs: vec![],
            mtu: None,
            vlans: vec![],
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
