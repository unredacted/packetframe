//! The IPv6 hand-back path: how router-owned IPv6 that a `v6-divert`
//! rule delivered to VPP gets back to the kernel.
//!
//! ## Why it exists
//!
//! A `v6-divert` rule matches by frame — TCP or UDP over IPv6 addressed
//! to one of the router's receive MACs ([`crate::steer`]) — because the
//! NIC cannot read a v6 address. On a transit or IX port the router's OWN
//! IPv6 arrives on that same MAC as the traffic it forwards: replies to
//! its DNS queries, its SSH, Tailscale, the vendor's cloud session. Ports
//! cannot separate them (a src-port-443 keep would keep every web reply
//! to every customer), so they are diverted too, and VPP — which runs
//! without linux-cp and has no path into the kernel — would drop them.
//!
//! So PacketFrame builds one:
//!
//! - a veth pair, [`KERNEL_IF`] on the kernel's side and [`VPP_HOST_IF`]
//!   opened by VPP as an af_packet host interface (af_packet rather than
//!   tap, which needs vhost-net);
//! - a /128 in VPP's IPv6 table for every GLOBAL address the host holds,
//!   whose path leaves by VPP's end of the veth toward the kernel's
//!   link-local, resolved by a static neighbour — VPP never solicits;
//! - an nftables table ([`NFT_TABLE`]) on the kernel side that admits
//!   only established and related traffic arriving on the veth, because
//!   that traffic bypasses the vendor's WAN_LOCAL rules, which key on the
//!   physical WAN ports.
//!
//! The next hop is the EUI-64 link-local of the kernel veth's MAC
//! ([`eui64_link_local`]) — what the kernel's default `addr_gen_mode`
//! gives the interface, and PF-internal: it never comes from the route
//! feed, and only the static neighbour's MAC decides where a packet goes.
//! The kernel accepts the frame by MAC and delivers it by destination
//! address, which is one of its own.
//!
//! ## Order, and what may wait on what
//!
//! The /128s are installed before any v6 diversion rule is: the steering
//! holds its IPv6 half until [`Handback::ready`] says the path is whole
//! ([`crate::ntuple::NtupleSteering`]'s v6 gate), and IPv4 steering never
//! waits on it. The /128s are PF-owned topology, installed straight onto
//! the transport like `local-route`'s attached routes — never through the
//! route ledger — and the hand-back interface is kept out of the engine's
//! port index, which is what keeps adoption's readback from mistaking
//! them for mirror routes (`looks_self_installed` admits only paths on
//! owned ports) and so from the diff, verify and the drift tripwire.
//!
//! ## Hop limit
//!
//! VPP decrements the hop limit of what it hands back. Anything
//! router-owned that arrives at hop limit 1 would reach the kernel at 0
//! and be dropped: eBGP to a directly connected peer is exactly that,
//! which is why BGP is a built-in keep and never enters VPP
//! ([`crate::steer::BUILTIN_KEEPS6`]). Single-hop BFD would need a keep
//! too; nothing else router-owned is known to arrive that way.
//!
//! ## Lifetime
//!
//! Built on the first steering target that diverts IPv6 under `v6 on`,
//! kept until teardown — the module's stop, or `packetframe detach
//! --all` ([`teardown_host`]) — and left in place by a `--keep-vpp`
//! restart, whose next daemon re-verifies every part of it rather than
//! trusting it. The VPP half dies with a VPP process; the next one gets
//! a new one.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use packetframe_common::fib::IpPrefix;

use crate::vpp_api::generated::{
    AfPacketCreateV3, AfPacketCreateV3Reply, AfPacketDelete, AfPacketDeleteReply, AfPacketDetails,
    AfPacketDump, CliInband, CliInbandReply, IpNeighbor, IpNeighborAddDel, IpNeighborAddDelReply,
    IpNeighborDetails, IpNeighborDump, IpRoute, IpRouteAddDel, IpRouteAddDelReply, IpRouteDetails,
    IpRouteDump, IpTable, SwInterfaceSetFlags, SwInterfaceSetFlagsReply, SwInterfaceSetMtu,
    SwInterfaceSetMtuReply, ADDRESS_IP6, AF_PACKET_API_FLAG_QDISC_BYPASS,
    AF_PACKET_API_MODE_ETHERNET,
};
use crate::vpp_api::{Transport, TransportError};

/// The kernel's end of the veth pair.
pub const KERNEL_IF: &str = "pfpunt0";
/// VPP's end: the host interface its af_packet socket opens. VPP names
/// the resulting interface `host-pfpunt0-vpp`.
pub const VPP_HOST_IF: &str = "pfpunt0-vpp";
/// The nftables table the guard lives in (family `inet`), so teardown is
/// one delete.
pub const NFT_TABLE: &str = "packetframe_handback";

/// How often a built path is re-checked end to end: the veth still up,
/// the guard table still loaded, VPP's interface still up. A kernel read,
/// one `nft` spawn and two API calls — cheap, but not per tick.
pub const CHECK_EVERY: Duration = Duration::from_secs(30);
/// How long a failed build or sync waits before it is tried again, so a
/// permanently refusing kernel or VPP costs one attempt per interval
/// rather than one per tick.
pub const RETRY_EVERY: Duration = Duration::from_secs(10);

/// How a kernel-side failure's reason begins.
const KERNEL_SIDE: &str = "kernel side: ";

/// `RT_SCOPE_UNIVERSE`: a global address. Link-local is `RT_SCOPE_LINK`,
/// `::1` `RT_SCOPE_HOST`.
pub const RT_SCOPE_UNIVERSE: u8 = 0;
/// `IFA_F_DADFAILED`: duplicate address detection failed, so the kernel
/// will never use the address.
pub const IFA_F_DADFAILED: u32 = 0x08;

/// One IPv6 address the kernel holds, as an RTM_NEWADDR describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostAddr {
    pub ifindex: u32,
    pub addr: Ipv6Addr,
    /// `ifa_scope`.
    pub scope: u8,
    /// `IFA_FLAGS` (or the header's 8-bit flags where it is absent).
    pub flags: u32,
}

/// The addresses VPP must hand back to the kernel: every global-scope
/// IPv6 address the host holds, on any interface but the hand-back veth
/// itself (`exclude`).
///
/// Everything global, deliberately, rather than a guess at which
/// interfaces face transit: a transit /127, an IX address, the customer
/// gateway, a Tailscale /128 — any of them can be the destination of a
/// reply arriving on a diverted port, and a missing one is a session the
/// router loses. Link-local is out (VPP routes no link-local, and a
/// packet for the router's link-local is never forwarded to it), and so
/// is an address whose DAD failed (the kernel will never answer for it).
/// A tentative address is IN: DAD finishes in about a second, and the
/// route being there early costs nothing.
pub fn router_owned(addrs: &[HostAddr], exclude: &[u32]) -> BTreeSet<Ipv6Addr> {
    addrs
        .iter()
        .filter(|a| a.scope == RT_SCOPE_UNIVERSE)
        .filter(|a| !exclude.contains(&a.ifindex))
        .filter(|a| a.flags & IFA_F_DADFAILED == 0)
        // Scope is the kernel's own answer; these guard against a
        // mislabelled one reaching VPP as a /128 it must never hold.
        .filter(|a| {
            let s = a.addr.segments()[0];
            s & 0xffc0 != 0xfe80
                && !a.addr.is_multicast()
                && !a.addr.is_loopback()
                && !a.addr.is_unspecified()
        })
        .map(|a| a.addr)
        .collect()
}

/// The EUI-64 link-local for `mac` (RFC 4291 §2.5.1, the universal/local
/// bit inverted): the next hop VPP's /128s name.
pub fn eui64_link_local(mac: [u8; 6]) -> Ipv6Addr {
    Ipv6Addr::from([
        0xfe,
        0x80,
        0,
        0,
        0,
        0,
        0,
        0,
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ])
}

/// The guard, as one `nft -f` transaction.
///
/// Declare-then-delete-then-define makes it idempotent and atomic: a
/// re-apply (adoption, a check that found it altered) replaces the table
/// in one transaction, with no instant where the veth is unguarded.
/// `iifname` rather than `iif`, so a veth recreated with a new ifindex is
/// still matched without reloading the table.
///
/// - input: established/related arriving on the veth is accepted —
///   replies to what the router itself opened, and the ICMPv6 errors
///   about them (PMTUD included); everything else arriving there is
///   dropped. That traffic bypasses the vendor's WAN_LOCAL rules (they
///   key on the physical WAN ports), so without this a new inbound
///   connection to the router over IPv6 through VPP would be accepted
///   with no firewall at all. Services that need new inbound
///   connections are `steer-keep6`'d and never enter VPP.
/// - forward: nothing arriving on the veth is forwarded. VPP sends the
///   veth only the router's own /128s, so a packet that would be
///   forwarded is one for an address the router has just dropped, and
///   forwarding it would bypass every forward-path rule too.
pub fn nft_ruleset() -> String {
    format!(
        "table inet {NFT_TABLE}\n\
         delete table inet {NFT_TABLE}\n\
         table inet {NFT_TABLE} {{\n\
         \tchain input {{\n\
         \t\ttype filter hook input priority filter; policy accept;\n\
         \t\tiifname \"{KERNEL_IF}\" ct state established,related accept\n\
         \t\tiifname \"{KERNEL_IF}\" drop\n\
         \t}}\n\
         \tchain forward {{\n\
         \t\ttype filter hook forward priority filter; policy accept;\n\
         \t\tiifname \"{KERNEL_IF}\" drop\n\
         \t}}\n\
         }}\n"
    )
}

/// Whether `nft list table` output is the guard [`nft_ruleset`] loads —
/// both chains, the accept and both drops, on the veth.
pub fn guard_matches(listing: &str) -> bool {
    let on_veth = format!("iifname \"{KERNEL_IF}\"");
    listing.contains("chain input")
        && listing.contains("chain forward")
        && listing.contains("established,related accept")
        && listing.matches(&on_veth).count() >= 3
}

/// `tx packets` for `name` from VPP's `show interface <name>` text.
///
/// VPP prints only non-zero counters, so an interface listed with no
/// `tx packets` row has sent nothing: `Some(0)`. `None` when the text does
/// not list the interface at all — no answer, rather than a zero.
pub fn parse_tx_packets(text: &str, name: &str) -> Option<u64> {
    if !text
        .lines()
        .any(|l| l.split_whitespace().next() == Some(name))
    {
        return None;
    }
    for line in text.lines() {
        if let Some(i) = line.find("tx packets") {
            return line[i + "tx packets".len()..].trim().parse().ok();
        }
    }
    Some(0)
}

/// Whether any plan in a steering target diverts IPv6 — the hand-back
/// path's want.
pub fn plans_divert_v6(targets: &[(String, u32, crate::steer::RuleSet)]) -> bool {
    targets.iter().any(|(_, _, plan)| {
        plan.rules.iter().any(|r| {
            r.action == crate::steer::RuleAction::Divert
                && matches!(r.shape, crate::steer::RuleMatch::V6Frame { .. })
        })
    })
}

/// What the kernel half reports once it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    pub kernel_ifindex: u32,
    pub kernel_mac: [u8; 6],
    pub vpp_ifindex: u32,
    pub vpp_mac: [u8; 6],
    /// Both ends' MTU: the largest member port's, so a router-owned
    /// packet any port accepted fits the hand-back too.
    pub mtu: u32,
}

/// One periodic look at the kernel half.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostCheck {
    /// Both veth ends present, with the ifindexes they were built with,
    /// and up.
    pub veth: bool,
    /// The guard table is loaded and is the one [`nft_ruleset`] loads.
    pub guard: bool,
}

/// The kernel half: veth, sysctls, guard, and the host's addresses.
/// [`KernelHostSide`] on Linux; tests supply their own.
pub trait HostSide {
    /// Create — or adopt, when it already exists as built — the veth
    /// pair, set its sysctls and MTU, bring both ends up and (re)load the
    /// guard. Idempotent.
    fn ensure(&mut self) -> Result<HostFacts, String>;
    /// Whether what [`Self::ensure`] built is still there, as built.
    fn check(&mut self, facts: &HostFacts) -> HostCheck;
    /// The router-owned addresses ([`router_owned`]) if they may have
    /// changed since the last call — `Some` on the first call, after any
    /// RTM_NEWADDR/RTM_DELADDR, and on a periodic resync; `None` when
    /// nothing has been heard.
    fn owned_addrs(&mut self, facts: &HostFacts) -> Result<Option<BTreeSet<Ipv6Addr>>, String>;
    /// Remove the guard table and the veth pair. Absent is success.
    fn teardown(&mut self) -> Result<(), String>;
}

/// A refusal or transport failure from VPP while building or syncing the
/// VPP half.
#[derive(Debug)]
pub enum HandbackError {
    Transport(TransportError),
    Refused {
        step: &'static str,
        retval: i32,
        detail: String,
    },
}

impl From<TransportError> for HandbackError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

impl std::fmt::Display for HandbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "VPP API: {e}"),
            Self::Refused {
                step,
                retval,
                detail,
            } => write!(f, "VPP refused {step} (retval {retval}){detail}"),
        }
    }
}

fn refused(step: &'static str, retval: i32, detail: impl Into<String>) -> HandbackError {
    let detail = detail.into();
    HandbackError::Refused {
        step,
        retval,
        detail: if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        },
    }
}

/// VPP's end, as last established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VppHalf {
    pub sw_if_index: u32,
    /// `(kernel ifindex, vpp ifindex)` of the veth this interface's
    /// socket was opened on. A veth rebuilt under it has new ones, and
    /// the old socket is bound to an interface that no longer exists.
    pub bound_to: (u32, u32),
    /// The kernel veth's link-local, which the static neighbour resolves.
    pub next_hop: Ipv6Addr,
    /// The /128s VPP has ACKNOWLEDGED holding through this interface.
    pub routes: BTreeSet<Ipv6Addr>,
}

/// Find the host interface a surviving VPP already has, or create it;
/// assert its MTU, admin state, ip6 and RA suppression; make sure the
/// static neighbour is there; and read back which /128s it holds.
///
/// Adoption is by host interface NAME: creating a second af_packet socket
/// on the same veth would leave two VPP interfaces on one wire. Every
/// setting is re-asserted rather than trusted — each is idempotent in VPP
/// — and the neighbour is added only when the dump does not show it,
/// exactly as the mirror's neighbours are: a re-add replaces the entry
/// and walks every route through it.
pub fn ensure_vpp(t: &mut Transport, facts: &HostFacts) -> Result<VppHalf, HandbackError> {
    let existing: Vec<AfPacketDetails> = t.dump(AfPacketDump { context: 0 })?;
    let adopted = existing
        .iter()
        .find(|d| d.host_if_name == VPP_HOST_IF)
        .map(|d| d.sw_if_index);
    let sw_if_index = match adopted {
        Some(idx) => {
            tracing::info!(
                sw_if_index = idx,
                host_if = VPP_HOST_IF,
                "reusing the hand-back host interface this VPP already has"
            );
            idx
        }
        None => create_host_if(t, facts)?,
    };
    let reply: SwInterfaceSetMtuReply = t.request(SwInterfaceSetMtu {
        context: 0,
        sw_if_index,
        mtu: [facts.mtu, 0, 0, 0],
    })?;
    if reply.retval != 0 {
        return Err(refused(
            "sw_interface_set_mtu",
            reply.retval,
            format!("hand-back interface, mtu {}", facts.mtu),
        ));
    }
    let reply: SwInterfaceSetFlagsReply = t.request(SwInterfaceSetFlags {
        context: 0,
        sw_if_index,
        flags: crate::attach::IF_STATUS_ADMIN_UP,
    })?;
    if reply.retval != 0 {
        return Err(refused(
            "sw_interface_set_flags",
            reply.retval,
            "hand-back interface",
        ));
    }
    crate::attach::enable_ip6(t, "hand-back interface", sw_if_index).map_err(|e| match e {
        crate::attach::AttachError::Transport(t) => HandbackError::Transport(t),
        other => refused("ip6 enable", -1, other.to_string()),
    })?;

    let next_hop = eui64_link_local(facts.kernel_mac);
    let neighbours: Vec<IpNeighborDetails> = t.dump(IpNeighborDump {
        context: 0,
        sw_if_index,
        af: ADDRESS_IP6,
    })?;
    let present = neighbours.iter().any(|d| {
        d.neighbor.sw_if_index == sw_if_index
            && crate::fib_sync::from_address(&d.neighbor.ip_address) == Some(IpAddr::V6(next_hop))
            && d.neighbor.mac_address == facts.kernel_mac
            && d.neighbor.flags == crate::engine::IP_NEIGHBOR_STATIC
    });
    if !present {
        let reply: IpNeighborAddDelReply = t.request(IpNeighborAddDel {
            context: 0,
            is_add: true,
            neighbor: IpNeighbor {
                sw_if_index,
                flags: crate::engine::IP_NEIGHBOR_STATIC,
                mac_address: facts.kernel_mac,
                ip_address: crate::fib_sync::to_address(IpAddr::V6(next_hop)),
            },
        })?;
        if reply.retval != 0 {
            return Err(refused(
                "ip_neighbor_add_del",
                reply.retval,
                format!("static neighbour {next_hop} on the hand-back interface"),
            ));
        }
    }
    // A just-created interface has no routes through it; only an adopted
    // one is worth a table read.
    let routes = if adopted.is_some() {
        routes_via(t, sw_if_index)?
    } else {
        BTreeSet::new()
    };
    Ok(VppHalf {
        sw_if_index,
        bound_to: (facts.kernel_ifindex, facts.vpp_ifindex),
        next_hop,
        routes,
    })
}

/// Open VPP's end on [`VPP_HOST_IF`], wearing the veth end's own MAC.
///
/// Frame sizes and block counts are left zero, which VPP reads as its
/// defaults — what `create host-interface` does. QDISC_BYPASS as the CLI
/// defaults; no checksum/GSO offload, because what VPP sends here was
/// forwarded off the wire with its checksums already valid, and nothing
/// needs segmenting.
fn create_host_if(t: &mut Transport, facts: &HostFacts) -> Result<u32, HandbackError> {
    let reply: AfPacketCreateV3Reply = t.request(AfPacketCreateV3 {
        context: 0,
        mode: AF_PACKET_API_MODE_ETHERNET,
        hw_addr: facts.vpp_mac,
        use_random_hw_addr: false,
        host_if_name: VPP_HOST_IF.into(),
        rx_frame_size: 0,
        tx_frame_size: 0,
        rx_frames_per_block: 0,
        tx_frames_per_block: 0,
        flags: AF_PACKET_API_FLAG_QDISC_BYPASS,
        num_rx_queues: 1,
        num_tx_queues: 1,
    })?;
    if reply.retval != 0 {
        return Err(refused(
            "af_packet_create_v3",
            reply.retval,
            format!("host interface {VPP_HOST_IF}"),
        ));
    }
    tracing::info!(
        sw_if_index = reply.sw_if_index,
        host_if = VPP_HOST_IF,
        "created the IPv6 hand-back host interface in VPP"
    );
    Ok(reply.sw_if_index)
}

/// The /128s VPP's IPv6 table routes through `sw_if_index`.
fn routes_via(t: &mut Transport, sw_if_index: u32) -> Result<BTreeSet<Ipv6Addr>, TransportError> {
    let details: Vec<IpRouteDetails> = t.dump(IpRouteDump {
        context: 0,
        table: IpTable {
            table_id: 0,
            is_ip6: true,
            name: String::new(),
        },
    })?;
    Ok(details
        .into_iter()
        .filter(|d| d.route.paths.iter().any(|p| p.sw_if_index == sw_if_index))
        .filter_map(|d| match crate::fib_sync::from_prefix(&d.route.prefix) {
            Some(IpPrefix::V6 {
                addr,
                prefix_len: 128,
            }) => Some(Ipv6Addr::from(addr)),
            _ => None,
        })
        .collect())
}

fn route_op(
    t: &mut Transport,
    half: &VppHalf,
    addr: Ipv6Addr,
    is_add: bool,
) -> Result<(), HandbackError> {
    let reply: IpRouteAddDelReply = t.request(IpRouteAddDel {
        context: 0,
        is_add,
        is_multipath: false,
        route: IpRoute {
            table_id: 0,
            stats_index: 0,
            prefix: crate::fib_sync::to_prefix(IpPrefix::V6 {
                addr: addr.octets(),
                prefix_len: 128,
            }),
            n_paths: 1,
            paths: vec![crate::fib_sync::wire_path(
                IpAddr::V6(half.next_hop),
                half.sw_if_index,
            )],
        },
    })?;
    if reply.retval != 0 {
        return Err(refused(
            "ip_route_add_del",
            reply.retval,
            format!(
                "{} hand-back route {addr}/128",
                if is_add { "adding" } else { "removing" }
            ),
        ));
    }
    Ok(())
}

/// Make VPP's /128s through the hand-back interface exactly `desired`:
/// withdrawals first (an address the host dropped), then additions.
/// Recorded per acknowledgement, so a failure part-way leaves `routes`
/// saying what VPP holds.
pub fn sync_routes(
    t: &mut Transport,
    half: &mut VppHalf,
    desired: &BTreeSet<Ipv6Addr>,
) -> Result<(), HandbackError> {
    let stale: Vec<Ipv6Addr> = half.routes.difference(desired).copied().collect();
    for addr in stale {
        route_op(t, half, addr, false)?;
        half.routes.remove(&addr);
        tracing::info!(%addr, "hand-back route withdrawn: the host no longer holds this address");
    }
    let missing: Vec<Ipv6Addr> = desired.difference(&half.routes).copied().collect();
    for addr in missing {
        route_op(t, half, addr, true)?;
        half.routes.insert(addr);
        tracing::info!(%addr, "hand-back route installed: VPP hands this address to the kernel");
    }
    Ok(())
}

/// Take VPP's end down: its routes, its neighbour, the host interface.
pub fn remove_vpp(t: &mut Transport, half: &mut VppHalf) -> Result<(), HandbackError> {
    sync_routes(t, half, &BTreeSet::new())?;
    let reply: AfPacketDeleteReply = t.request(AfPacketDelete {
        context: 0,
        host_if_name: VPP_HOST_IF.into(),
    })?;
    if reply.retval != 0 {
        return Err(refused(
            "af_packet_delete",
            reply.retval,
            format!("host interface {VPP_HOST_IF}"),
        ));
    }
    // The static neighbour went with its interface.
    Ok(())
}

/// VPP's view of its end: `(name, admin and link up, tx packets)`.
fn vpp_side_state(
    t: &mut Transport,
    sw_if_index: u32,
) -> Result<Option<(String, bool, Option<u64>)>, TransportError> {
    let Some(i) = crate::attach::interfaces(t)?
        .into_iter()
        .find(|i| i.sw_if_index == sw_if_index)
    else {
        return Ok(None);
    };
    let reply: CliInbandReply = t.request(CliInband {
        context: 0,
        cmd: format!("show interface {}", i.name),
    })?;
    let tx = if reply.retval == 0 {
        parse_tx_packets(&reply.reply, &i.name)
    } else {
        None
    };
    Ok(Some((i.name.clone(), i.admin_up() && i.link_up(), tx)))
}

/// The hand-back path as status reports it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HandbackStatus {
    /// The steering target diverts IPv6, so the path is needed.
    pub wanted: bool,
    /// Complete and in sync: the v6 half of steering may be installed.
    pub ready: bool,
    /// The veth pair exists as built and is up.
    pub veth: bool,
    /// The guard table is loaded.
    pub guard: bool,
    /// VPP's interface name, when VPP has one.
    pub vpp_if: Option<String>,
    /// VPP's interface is admin- and link-up.
    pub vpp_up: bool,
    /// /128s VPP has acknowledged.
    pub routes: usize,
    /// Router-owned addresses the host last reported, when read.
    pub owned: Option<usize>,
    /// Packets VPP has sent the kernel over it, when sampled.
    pub tx_packets: Option<u64>,
    /// Why the last attempt failed, until one succeeds.
    pub error: Option<String>,
}

/// The whole path, owned by the engine (which owns the transport the VPP
/// half is programmed over).
pub struct Handback {
    host: Box<dyn HostSide>,
    wanted: bool,
    facts: Option<HostFacts>,
    check: HostCheck,
    vpp: Option<VppHalf>,
    /// VPP's routes are in doubt: a transport failure mid-sync may have
    /// applied an op whose acknowledgement never came. Re-read before the
    /// next sync.
    routes_in_doubt: bool,
    vpp_name: Option<String>,
    vpp_up: bool,
    tx_packets: Option<u64>,
    desired: Option<BTreeSet<Ipv6Addr>>,
    error: Option<String>,
    retry_at: Option<Instant>,
    checked_at: Option<Instant>,
}

impl Handback {
    pub fn new(host: Box<dyn HostSide>) -> Self {
        Self {
            host,
            wanted: false,
            facts: None,
            check: HostCheck::default(),
            vpp: None,
            routes_in_doubt: false,
            vpp_name: None,
            vpp_up: false,
            tx_packets: None,
            desired: None,
            error: None,
            retry_at: None,
            checked_at: None,
        }
    }

    /// Whether the steering target diverts IPv6. Only a want builds the
    /// path; losing it does not tear the path down (the module's stop
    /// does), so a reconfigure that drops and re-adds `v6-divert` does not
    /// churn a veth.
    pub fn set_wanted(&mut self, wanted: bool) {
        if wanted != self.wanted {
            // A new want is attempted now, not after a retry interval a
            // previous, unwanted attempt left behind.
            self.retry_at = None;
        }
        self.wanted = wanted;
    }

    pub fn wanted(&self) -> bool {
        self.wanted
    }

    /// Complete, and holding a /128 for every address the host last
    /// reported: the only state in which the v6 half of steering may be
    /// installed.
    pub fn ready(&self) -> bool {
        self.wanted
            && self.facts.is_some()
            && self.check.veth
            && self.check.guard
            && self.vpp_up
            && !self.routes_in_doubt
            && match (&self.vpp, &self.desired) {
                (Some(v), Some(d)) => v.routes == *d,
                _ => false,
            }
    }

    pub fn status(&self) -> HandbackStatus {
        HandbackStatus {
            wanted: self.wanted,
            ready: self.ready(),
            veth: self.facts.is_some() && self.check.veth,
            guard: self.facts.is_some() && self.check.guard,
            vpp_if: self.vpp.as_ref().and(self.vpp_name.clone()),
            vpp_up: self.vpp.is_some() && self.vpp_up,
            routes: self.vpp.as_ref().map_or(0, |v| v.routes.len()),
            owned: self.desired.as_ref().map(BTreeSet::len),
            tx_packets: self.tx_packets,
            error: self.error.clone(),
        }
    }

    /// Whether anything was ever built — status reports a path that is
    /// built but no longer wanted, too.
    pub fn built(&self) -> bool {
        self.facts.is_some() || self.vpp.is_some()
    }

    /// The VPP process is gone, and its half with it.
    pub fn vpp_gone(&mut self) {
        self.vpp = None;
        self.vpp_name = None;
        self.vpp_up = false;
        self.tx_packets = None;
        self.routes_in_doubt = false;
    }

    /// Read VPP's interface state into the status fields. `false` when
    /// VPP no longer lists the interface or it is not up.
    fn observe_vpp_side(
        &mut self,
        t: &mut Transport,
        sw_if_index: u32,
    ) -> Result<bool, TransportError> {
        match vpp_side_state(t, sw_if_index)? {
            Some((name, up, tx)) => {
                self.vpp_name = Some(name);
                self.vpp_up = up;
                self.tx_packets = tx;
                Ok(up)
            }
            None => {
                self.vpp_name = None;
                self.vpp_up = false;
                Ok(false)
            }
        }
    }

    fn fail(&mut self, now: Instant, why: String) {
        if self.error.as_deref() != Some(why.as_str()) {
            tracing::warn!(
                error = %why,
                "IPv6 hand-back path not ready; no v6 diversion is installed until it is \
                 (IPv4 steering is unaffected)"
            );
        }
        self.error = Some(why);
        self.retry_at = Some(now + RETRY_EVERY);
    }

    /// One servicing pass: build what is missing, re-check what is built
    /// on [`CHECK_EVERY`], and — with `sync` — bring VPP's /128s to the
    /// host's addresses.
    ///
    /// `t` is `None` while VPP's API is not connected; the kernel half is
    /// still built. `sync` is false at device attach: an adopted VPP's
    /// FIB must reach the preserved ledger's fingerprint check unchanged
    /// ([`crate::ledger_record`]), so the /128s move on the next tick —
    /// the host's addresses are still read, so a surviving path that
    /// already holds all of them is ready from the attach.
    ///
    /// `Err` only for a transport failure — the caller drops the socket,
    /// as for every other one. A refusal from VPP or the kernel is
    /// recorded, paced by [`RETRY_EVERY`], and leaves the path not ready.
    pub fn service(
        &mut self,
        mut t: Option<&mut Transport>,
        now: Instant,
        sync: bool,
    ) -> Result<(), TransportError> {
        if !self.wanted && !self.built() {
            return Ok(());
        }
        if self.retry_at.is_some_and(|at| now < at) {
            return Ok(());
        }
        let check_due = self
            .checked_at
            .is_none_or(|c| now.saturating_duration_since(c) >= CHECK_EVERY);
        if check_due {
            if let Some(facts) = self.facts.clone() {
                self.checked_at = Some(now);
                self.check = self.host.check(&facts);
                if !(self.check.veth && self.check.guard) {
                    tracing::warn!(
                        veth = self.check.veth,
                        guard = self.check.guard,
                        "the IPv6 hand-back path's kernel side changed under it; rebuilding"
                    );
                    self.facts = None;
                }
            }
            let sw_if_index = self.vpp.as_ref().map(|v| v.sw_if_index);
            if let (Some(t), Some(sw_if_index)) = (t.as_deref_mut(), sw_if_index) {
                if !self.observe_vpp_side(t, sw_if_index)? {
                    tracing::warn!(
                        sw_if_index,
                        "the hand-back interface is gone from VPP or not up; re-asserting it"
                    );
                    // Re-asserted by the ensure below, which is idempotent
                    // (adopt by name, admin up); a link that stays down —
                    // the veth end down — keeps the path not ready.
                    self.vpp = None;
                }
            }
        }
        if self.facts.is_none() {
            match self.host.ensure() {
                Ok(f) => {
                    self.check = HostCheck {
                        veth: true,
                        guard: true,
                    };
                    self.checked_at = Some(now);
                    self.facts = Some(f);
                    // A kernel-side failure is over the moment the kernel
                    // side builds, VPP or no VPP to finish the pass.
                    if self
                        .error
                        .as_deref()
                        .is_some_and(|e| e.starts_with(KERNEL_SIDE))
                    {
                        self.error = None;
                    }
                }
                Err(e) => {
                    self.fail(now, format!("{KERNEL_SIDE}{e}"));
                    return Ok(());
                }
            }
        }
        let facts = self.facts.clone().expect("built just above");
        let Some(t) = t else {
            return Ok(());
        };
        // A veth rebuilt under a live VPP: its socket is bound to the old
        // interface, so the VPP half is recreated, not adopted.
        if let Some(mut v) = self
            .vpp
            .take_if(|v| v.bound_to != (facts.kernel_ifindex, facts.vpp_ifindex))
        {
            tracing::warn!("the hand-back veth was rebuilt; recreating VPP's end on it");
            if let Err(e) = remove_vpp(t, &mut v) {
                match e {
                    HandbackError::Transport(e) => return Err(e),
                    other => {
                        self.vpp = Some(v);
                        self.fail(now, other.to_string());
                        return Ok(());
                    }
                }
            }
        }
        if self.vpp.is_none() {
            match ensure_vpp(t, &facts) {
                Ok(v) => {
                    let sw_if_index = v.sw_if_index;
                    self.vpp = Some(v);
                    self.routes_in_doubt = false;
                    // Up as VPP reports it, not as just asked: the link
                    // follows the veth end's carrier.
                    self.observe_vpp_side(t, sw_if_index)?;
                }
                Err(HandbackError::Transport(e)) => return Err(e),
                Err(other) => {
                    self.fail(now, other.to_string());
                    return Ok(());
                }
            }
        }
        // Read even without `sync`: it touches only the kernel, and knowing
        // the host's addresses is what lets an adopted path that already
        // holds every /128 read as ready at attach, before anything moves.
        match self.host.owned_addrs(&facts) {
            Ok(Some(set)) => self.desired = Some(set),
            Ok(None) => {}
            Err(e) => {
                self.fail(now, format!("reading the router's IPv6 addresses: {e}"));
                return Ok(());
            }
        }
        if !sync {
            return Ok(());
        }
        let v = self.vpp.as_mut().expect("ensured just above");
        if self.routes_in_doubt {
            v.routes = routes_via(t, v.sw_if_index)?;
            self.routes_in_doubt = false;
        }
        if let Some(desired) = &self.desired {
            if v.routes != *desired {
                match sync_routes(t, v, desired) {
                    Ok(()) => {}
                    Err(HandbackError::Transport(e)) => {
                        self.routes_in_doubt = true;
                        return Err(e);
                    }
                    Err(other) => {
                        self.fail(now, other.to_string());
                        return Ok(());
                    }
                }
            }
        }
        if self.error.take().is_some() {
            tracing::info!("IPv6 hand-back path recovered");
        }
        self.retry_at = None;
        Ok(())
    }

    /// Tear the path down: VPP's half when there is a VPP to ask, then the
    /// kernel's — whether or not this process built it, since a crashed
    /// predecessor's veth is PacketFrame's to remove too.
    pub fn teardown(&mut self, t: Option<&mut Transport>) -> Result<(), String> {
        let mut errors = Vec::new();
        if let (Some(t), Some(mut v)) = (t, self.vpp.take()) {
            if let Err(e) = remove_vpp(t, &mut v) {
                errors.push(format!("VPP side: {e}"));
            }
        }
        self.vpp_gone();
        if let Err(e) = self.host.teardown() {
            errors.push(format!("kernel side: {e}"));
        }
        self.facts = None;
        self.desired = None;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

/// Remove the kernel half by name — `packetframe detach --all`, which has
/// no engine and no record of it. Absent is success.
pub fn teardown_host() -> Result<(), String> {
    KernelHostSide::new(0).teardown()
}

#[cfg(target_os = "linux")]
pub use kernel::KernelHostSide;

#[cfg(target_os = "linux")]
mod kernel {
    //! The real kernel half: rtnetlink on a blocking socket (this crate
    //! has no async runtime), sysctls through procfs, and `nft -f -`.

    use std::collections::BTreeSet;
    use std::io::Write as _;
    use std::net::{IpAddr, Ipv6Addr};
    use std::time::{Duration, Instant};

    use netlink_packet_core::{
        NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL,
        NLM_F_REQUEST,
    };
    use netlink_packet_route::address::{AddressAttribute, AddressMessage};
    use netlink_packet_route::link::{
        InfoData, InfoKind, InfoVeth, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
    };
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    use super::{
        guard_matches, nft_ruleset, router_owned, HostAddr, HostCheck, HostFacts, HostSide,
        KERNEL_IF, NFT_TABLE, VPP_HOST_IF,
    };

    /// `RTMGRP_IPV6_IFADDR`: the multicast group RTM_NEWADDR/RTM_DELADDR
    /// for IPv6 arrive on.
    const RTMGRP_IPV6_IFADDR: u32 = 0x100;
    /// A full address re-read even with no event heard, in case one was
    /// lost somewhere an ENOBUFS did not report.
    const RESYNC_EVERY: Duration = Duration::from_secs(300);

    pub struct KernelHostSide {
        mtu: u32,
        watch: Option<Socket>,
        dumped_at: Option<Instant>,
    }

    impl KernelHostSide {
        /// `mtu`: both veth ends' MTU (the largest member port's).
        pub fn new(mtu: u32) -> Self {
            Self {
                mtu,
                watch: None,
                dumped_at: None,
            }
        }
    }

    #[derive(Debug, Clone)]
    struct Link {
        index: u32,
        name: String,
        veth: bool,
        peer: Option<u32>,
        mac: Option<[u8; 6]>,
        mtu: Option<u32>,
        up: bool,
    }

    /// One request, answered by an ack or a dump.
    fn rtnl(msg: RouteNetlinkMessage, flags: u16) -> Result<Vec<RouteNetlinkMessage>, String> {
        let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
        // On the supervision loop: a receive must never block unbounded.
        crate::fdb::bound_recv(&socket)?;
        socket
            .bind_auto()
            .map_err(|e| format!("netlink bind: {e}"))?;
        socket
            .connect(&SocketAddr::new(0, 0))
            .map_err(|e| format!("netlink connect: {e}"))?;
        let mut nl = NetlinkMessage::from(msg);
        nl.header.flags = flags;
        nl.header.sequence_number = 1;
        nl.finalize();
        let mut buf = vec![0u8; nl.header.length as usize];
        nl.serialize(&mut buf);
        socket
            .send(&buf, 0)
            .map_err(|e| format!("netlink send: {e}"))?;
        let mut out = Vec::new();
        let mut recv = vec![0u8; 64 * 1024];
        loop {
            let n = socket
                .recv(&mut &mut recv[..], 0)
                .map_err(|e| format!("netlink recv: {e}"))?;
            let mut offset = 0usize;
            while offset < n {
                let pkt = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv[offset..n])
                    .map_err(|e| format!("netlink parse: {e}"))?;
                let len = pkt.header.length as usize;
                if len == 0 {
                    return Ok(out);
                }
                match pkt.payload {
                    NetlinkPayload::Done(_) => return Ok(out),
                    // An ACK: `code` None. A NACK carries the errno.
                    NetlinkPayload::Error(e) if e.code.is_none() => return Ok(out),
                    NetlinkPayload::Error(e) => return Err(e.to_io().to_string()),
                    NetlinkPayload::InnerMessage(m) => out.push(m),
                    _ => {}
                }
                offset += len;
            }
        }
    }

    fn dump_links() -> Result<Vec<Link>, String> {
        let msgs = rtnl(
            RouteNetlinkMessage::GetLink(LinkMessage::default()),
            NLM_F_REQUEST | NLM_F_DUMP,
        )?;
        Ok(msgs
            .into_iter()
            .filter_map(|m| match m {
                RouteNetlinkMessage::NewLink(l) => Some(link_of(&l)),
                _ => None,
            })
            .collect())
    }

    fn link_of(l: &LinkMessage) -> Link {
        let mut out = Link {
            index: l.header.index,
            name: String::new(),
            veth: false,
            peer: None,
            mac: None,
            mtu: None,
            up: l.header.flags.contains(LinkFlags::Up),
        };
        for a in &l.attributes {
            match a {
                LinkAttribute::IfName(n) => out.name = n.clone(),
                LinkAttribute::Link(p) => out.peer = Some(*p),
                LinkAttribute::Mtu(m) => out.mtu = Some(*m),
                LinkAttribute::Address(b) if b.len() == 6 => {
                    let mut m = [0u8; 6];
                    m.copy_from_slice(b);
                    out.mac = Some(m);
                }
                LinkAttribute::LinkInfo(infos) => {
                    out.veth |= infos
                        .iter()
                        .any(|i| matches!(i, LinkInfo::Kind(InfoKind::Veth)));
                }
                _ => {}
            }
        }
        out
    }

    fn create_veth(mtu: u32) -> Result<(), String> {
        let mut peer = LinkMessage::default();
        peer.attributes
            .push(LinkAttribute::IfName(VPP_HOST_IF.to_string()));
        peer.attributes.push(LinkAttribute::Mtu(mtu));
        let mut msg = LinkMessage::default();
        msg.attributes
            .push(LinkAttribute::IfName(KERNEL_IF.to_string()));
        msg.attributes.push(LinkAttribute::Mtu(mtu));
        msg.attributes.push(LinkAttribute::LinkInfo(vec![
            LinkInfo::Kind(InfoKind::Veth),
            LinkInfo::Data(InfoData::Veth(InfoVeth::Peer(peer))),
        ]));
        rtnl(
            RouteNetlinkMessage::NewLink(msg),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        )
        .map(|_| ())
        .map_err(|e| format!("creating veth {KERNEL_IF}/{VPP_HOST_IF}: {e}"))
    }

    fn set_link(index: u32, name: &str, mtu: Option<u32>, up: bool) -> Result<(), String> {
        let mut msg = LinkMessage::default();
        msg.header.index = index;
        if up {
            msg.header.flags = LinkFlags::Up;
            msg.header.change_mask = LinkFlags::Up;
        }
        if let Some(mtu) = mtu {
            msg.attributes.push(LinkAttribute::Mtu(mtu));
        }
        rtnl(RouteNetlinkMessage::SetLink(msg), NLM_F_REQUEST | NLM_F_ACK)
            .map(|_| ())
            .map_err(|e| format!("configuring {name}: {e}"))
    }

    fn del_link(index: u32) -> Result<(), String> {
        let mut msg = LinkMessage::default();
        msg.header.index = index;
        rtnl(RouteNetlinkMessage::DelLink(msg), NLM_F_REQUEST | NLM_F_ACK)
            .map(|_| ())
            .map_err(|e| format!("deleting {KERNEL_IF}: {e}"))
    }

    fn sysctl(iface: &str, key: &str, value: &str) -> Result<(), String> {
        let path = format!("/proc/sys/net/ipv6/conf/{iface}/{key}");
        std::fs::write(&path, value).map_err(|e| format!("writing {path}: {e}"))
    }

    /// `nft` from the places distributions install it: a daemon's PATH
    /// may not carry `/usr/sbin`.
    fn nft_binary() -> &'static str {
        ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap_or("nft")
    }

    fn nft(args: &[&str], stdin: Option<&str>) -> Result<String, String> {
        let mut cmd = std::process::Command::new(nft_binary());
        cmd.args(args)
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("running {}: {e}", nft_binary()))?;
        if let Some(text) = stdin {
            let mut pipe = child.stdin.take().expect("piped above");
            pipe.write_all(text.as_bytes())
                .map_err(|e| format!("writing the ruleset to nft: {e}"))?;
        }
        let out = child
            .wait_with_output()
            .map_err(|e| format!("waiting for nft: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "nft {} exited {}: {}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn guard_listing() -> Option<String> {
        nft(&["list", "table", "inet", NFT_TABLE], None).ok()
    }

    /// Ours: a veth named [`KERNEL_IF`] whose peer is [`VPP_HOST_IF`].
    fn find_pair(links: &[Link]) -> Result<Option<(Link, Link)>, String> {
        let k = links.iter().find(|l| l.name == KERNEL_IF);
        let v = links.iter().find(|l| l.name == VPP_HOST_IF);
        match (k, v) {
            (None, None) => Ok(None),
            (Some(k), Some(v)) if k.veth && v.veth && k.peer == Some(v.index) => {
                Ok(Some((k.clone(), v.clone())))
            }
            (k, v) => Err(format!(
                "{} exists but is not PacketFrame's hand-back veth pair ({KERNEL_IF} ↔ \
                 {VPP_HOST_IF}); nothing was changed. Remove or rename it — `ip -d link show \
                 {}` shows what it is",
                k.or(v).map_or("an interface", |l| l.name.as_str()),
                k.or(v).map_or(KERNEL_IF, |l| l.name.as_str())
            )),
        }
    }

    fn dump_v6_addrs() -> Result<Vec<HostAddr>, String> {
        let mut req = AddressMessage::default();
        req.header.family = AddressFamily::Inet6;
        let msgs = rtnl(
            RouteNetlinkMessage::GetAddress(req),
            NLM_F_REQUEST | NLM_F_DUMP,
        )?;
        Ok(msgs
            .into_iter()
            .filter_map(|m| match m {
                RouteNetlinkMessage::NewAddress(a) if a.header.family == AddressFamily::Inet6 => {
                    host_addr(&a)
                }
                _ => None,
            })
            .collect())
    }

    fn host_addr(a: &AddressMessage) -> Option<HostAddr> {
        let mut local = None;
        let mut address = None;
        let mut flags = u32::from(a.header.flags.bits());
        for attr in &a.attributes {
            match attr {
                AddressAttribute::Local(IpAddr::V6(ip)) => local = Some(*ip),
                AddressAttribute::Address(IpAddr::V6(ip)) => address = Some(*ip),
                AddressAttribute::Flags(f) => flags = f.bits(),
                _ => {}
            }
        }
        // IFA_LOCAL wins where present: on a point-to-point address
        // IFA_ADDRESS is the peer's.
        let addr: Ipv6Addr = local.or(address)?;
        Some(HostAddr {
            ifindex: a.header.index,
            addr,
            scope: u8::from(a.header.scope),
            flags,
        })
    }

    /// Open the watch: a non-blocking socket on the IPv6 address group.
    fn open_watch() -> Result<Socket, String> {
        let mut s = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
        s.bind(&SocketAddr::new(0, RTMGRP_IPV6_IFADDR))
            .map_err(|e| format!("netlink bind to the IPv6 address group: {e}"))?;
        s.set_non_blocking(true)
            .map_err(|e| format!("netlink non-blocking: {e}"))?;
        Ok(s)
    }

    /// Drain the watch. `Ok(true)` when anything arrived — its content
    /// does not matter, the caller re-reads the whole (small) table — or
    /// when the kernel reported an overrun (ENOBUFS), which means events
    /// were lost.
    fn drain_watch(s: &Socket) -> Result<bool, String> {
        let mut heard = false;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match s.recv(&mut &mut buf[..], libc::MSG_DONTWAIT) {
                Ok(0) => return Ok(heard),
                Ok(_) => heard = true,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(heard),
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => heard = true,
                Err(e) => return Err(format!("address watch: {e}")),
            }
        }
    }

    impl HostSide for KernelHostSide {
        fn ensure(&mut self) -> Result<HostFacts, String> {
            let links = dump_links()?;
            let mtu = self.mtu.max(1280);
            if find_pair(&links)?.is_none() {
                create_veth(mtu)?;
                tracing::info!(
                    kernel = KERNEL_IF,
                    vpp = VPP_HOST_IF,
                    mtu,
                    "created the IPv6 hand-back veth pair"
                );
            }
            let links = dump_links()?;
            let (k, v) = find_pair(&links)?
                .ok_or_else(|| format!("{KERNEL_IF} is missing right after creating it"))?;
            // Before the link comes up, so the kernel side never
            // autoconfigures a global address, solicits a router or takes
            // one from an RA: its only address is the link-local VPP's
            // neighbour names. VPP's end carries no IPv6 in the kernel at
            // all — the kernel must not speak on the wire VPP reads.
            for (key, value) in [
                ("disable_ipv6", "0"),
                ("accept_ra", "0"),
                ("autoconf", "0"),
                ("router_solicitations", "0"),
            ] {
                sysctl(KERNEL_IF, key, value)?;
            }
            sysctl(VPP_HOST_IF, "disable_ipv6", "1")?;
            for l in [&k, &v] {
                let mtu_change = (l.mtu != Some(mtu)).then_some(mtu);
                if mtu_change.is_some() || !l.up {
                    set_link(l.index, &l.name, mtu_change, true)?;
                }
            }
            // The guard is (re)loaded on every ensure: one atomic
            // transaction, so re-applying it never leaves a gap.
            nft(&["-f", "-"], Some(&nft_ruleset()))
                .map_err(|e| format!("loading the hand-back guard: {e}"))?;
            Ok(HostFacts {
                kernel_ifindex: k.index,
                kernel_mac: k
                    .mac
                    .ok_or_else(|| format!("{KERNEL_IF} reports no MAC address"))?,
                vpp_ifindex: v.index,
                vpp_mac: v
                    .mac
                    .ok_or_else(|| format!("{VPP_HOST_IF} reports no MAC address"))?,
                mtu,
            })
        }

        fn check(&mut self, facts: &HostFacts) -> HostCheck {
            let veth = match dump_links().map(|l| find_pair(&l)) {
                Ok(Ok(Some((k, v)))) => {
                    k.index == facts.kernel_ifindex && v.index == facts.vpp_ifindex && k.up && v.up
                }
                _ => false,
            };
            let guard = guard_listing().is_some_and(|l| guard_matches(&l));
            HostCheck { veth, guard }
        }

        fn owned_addrs(&mut self, facts: &HostFacts) -> Result<Option<BTreeSet<Ipv6Addr>>, String> {
            // The watch opens BEFORE the dump it triggers, so an address
            // added between the two is heard rather than lost.
            let mut due = false;
            if self.watch.is_none() {
                self.watch = Some(open_watch()?);
                due = true;
            }
            match drain_watch(self.watch.as_ref().expect("opened above")) {
                Ok(heard) => due |= heard,
                Err(e) => {
                    // Reopened, with a full read, on the next call.
                    self.watch = None;
                    return Err(e);
                }
            }
            due |= self.dumped_at.is_none_or(|t| t.elapsed() >= RESYNC_EVERY);
            if !due {
                return Ok(None);
            }
            let addrs = dump_v6_addrs()?;
            self.dumped_at = Some(Instant::now());
            Ok(Some(router_owned(
                &addrs,
                &[facts.kernel_ifindex, facts.vpp_ifindex],
            )))
        }

        fn teardown(&mut self) -> Result<(), String> {
            let mut errors = Vec::new();
            if guard_listing().is_some() {
                if let Err(e) = nft(&["delete", "table", "inet", NFT_TABLE], None) {
                    errors.push(e);
                }
            }
            match dump_links().and_then(|l| find_pair(&l)) {
                // Deleting one end deletes both.
                Ok(Some((k, _))) => {
                    if let Err(e) = del_link(k.index) {
                        errors.push(e);
                    }
                }
                Ok(None) => {}
                Err(e) => errors.push(e),
            }
            self.watch = None;
            self.dumped_at = None;
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }
}

/// The non-Linux stand-in: there is no veth, rtnetlink or nftables to
/// build the path from, so every build refuses — which keeps the v6 half
/// of steering withheld, the safe direction — and teardown has nothing
/// to remove.
#[cfg(not(target_os = "linux"))]
pub struct KernelHostSide;

#[cfg(not(target_os = "linux"))]
impl KernelHostSide {
    pub fn new(_mtu: u32) -> Self {
        Self
    }
}

#[cfg(not(target_os = "linux"))]
impl HostSide for KernelHostSide {
    fn ensure(&mut self) -> Result<HostFacts, String> {
        Err("the IPv6 hand-back path needs Linux (veth, rtnetlink, nftables)".into())
    }
    fn check(&mut self, _facts: &HostFacts) -> HostCheck {
        HostCheck::default()
    }
    fn owned_addrs(&mut self, _facts: &HostFacts) -> Result<Option<BTreeSet<Ipv6Addr>>, String> {
        Err("the IPv6 hand-back path needs Linux".into())
    }
    fn teardown(&mut self) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn a(ifindex: u32, addr: &str, scope: u8, flags: u32) -> HostAddr {
        HostAddr {
            ifindex,
            addr: addr.parse().unwrap(),
            scope,
            flags,
        }
    }

    /// Every global address on every interface but the veth — transit,
    /// IX, customer gateway, a tunnel /128, ULA — and nothing else:
    /// link-local by scope and by prefix, host scope, a failed DAD, and
    /// whatever sits on the hand-back veth itself.
    #[test]
    fn router_owned_is_every_global_address_off_the_veth() {
        const TENTATIVE: u32 = 0x40;
        let addrs = [
            a(2, "2001:db8:0:1::1", RT_SCOPE_UNIVERSE, 0),
            a(3, "2001:db8:ffff::0", RT_SCOPE_UNIVERSE, 0),
            a(4, "2001:db8:100::1", RT_SCOPE_UNIVERSE, TENTATIVE),
            a(5, "2001:db8:5::7", RT_SCOPE_UNIVERSE, 0),
            a(6, "fd00:db8::1", RT_SCOPE_UNIVERSE, 0),
            a(2, "fe80::1", 253, 0),
            // A link-local mislabelled universe still never reaches VPP.
            a(2, "fe80::2", RT_SCOPE_UNIVERSE, 0),
            a(1, "::1", 254, 0),
            a(2, "2001:db8:dead::1", RT_SCOPE_UNIVERSE, IFA_F_DADFAILED),
            a(9, "2001:db8:9::1", RT_SCOPE_UNIVERSE, 0),
            // The same address on two interfaces is one route.
            a(3, "2001:db8:0:1::1", RT_SCOPE_UNIVERSE, 0),
        ];
        let got = router_owned(&addrs, &[9, 10]);
        let want: BTreeSet<Ipv6Addr> = [
            "2001:db8:0:1::1",
            "2001:db8:ffff::0",
            "2001:db8:100::1",
            "2001:db8:5::7",
            "fd00:db8::1",
        ]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn the_next_hop_is_the_eui64_link_local() {
        assert_eq!(
            eui64_link_local([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            "fe80::ff:fe00:1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            eui64_link_local([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]),
            "fe80::aa:bbff:fecc:ddee".parse::<Ipv6Addr>().unwrap()
        );
    }

    /// One atomic, idempotent transaction: the table is declared, deleted
    /// and redefined, so a re-apply replaces it with no unguarded instant.
    /// Established/related accepted on the veth, everything else on it
    /// dropped at input, and nothing from it forwarded.
    #[test]
    fn the_guard_admits_only_established_and_forwards_nothing() {
        let r = nft_ruleset();
        let lines: Vec<&str> = r.lines().map(str::trim).collect();
        assert_eq!(lines[0], "table inet packetframe_handback");
        assert_eq!(lines[1], "delete table inet packetframe_handback");
        assert_eq!(lines[2], "table inet packetframe_handback {");
        let input = r.find("chain input").unwrap();
        let forward = r.find("chain forward").unwrap();
        let (input_body, forward_body) = (&r[input..forward], &r[forward..]);
        let accept = input_body
            .find("iifname \"pfpunt0\" ct state established,related accept")
            .unwrap();
        let drop = input_body.find("iifname \"pfpunt0\" drop").unwrap();
        assert!(accept < drop, "the accept must precede the drop");
        assert!(input_body.contains("hook input"));
        assert!(forward_body.contains("hook forward"));
        assert!(forward_body.contains("iifname \"pfpunt0\" drop"));
        assert!(!forward_body.contains("established"));
        // What `nft list table` prints of it reads back as the guard.
        let listing = "table inet packetframe_handback {\n\tchain input {\n\t\ttype filter hook \
                       input priority filter; policy accept;\n\t\tiifname \"pfpunt0\" ct state \
                       established,related accept\n\t\tiifname \"pfpunt0\" drop\n\t}\n\n\tchain \
                       forward {\n\t\ttype filter hook forward priority filter; policy \
                       accept;\n\t\tiifname \"pfpunt0\" drop\n\t}\n}\n";
        assert!(guard_matches(listing));
        assert!(!guard_matches(
            "table inet packetframe_handback {\n\tchain input {\n\t}\n}\n"
        ));
    }

    /// VPP's `show interface` layout: counters beside the name row and
    /// under it, zero counters omitted.
    #[test]
    fn tx_packets_parse_from_show_interface() {
        let text = "              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     \
                    Counter          Count     \n\
                    host-pfpunt0-vpp                  4      up          9000/0/0/0     rx \
                    packets                     3\n\
                    \x20                                                                   rx \
                    bytes                     258\n\
                    \x20                                                                   tx \
                    packets                    17\n\
                    \x20                                                                   tx \
                    bytes                    1478\n";
        assert_eq!(parse_tx_packets(text, "host-pfpunt0-vpp"), Some(17));
        let idle = "              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     \
                    Counter          Count     \n\
                    host-pfpunt0-vpp                  4      up          9000/0/0/0\n";
        assert_eq!(parse_tx_packets(idle, "host-pfpunt0-vpp"), Some(0));
        assert_eq!(
            parse_tx_packets("unknown interface", "host-pfpunt0-vpp"),
            None
        );
    }

    /// A kernel half that answers from shared state, so a test can move
    /// the host's addresses and break the veth between passes.
    #[derive(Clone, Default)]
    struct FakeHost(Arc<Mutex<FakeHostState>>);

    #[derive(Default)]
    struct FakeHostState {
        refuse: Option<String>,
        ensures: usize,
        veth_ok: bool,
        addrs: Option<BTreeSet<Ipv6Addr>>,
        torn_down: bool,
    }

    impl HostSide for FakeHost {
        fn ensure(&mut self) -> Result<HostFacts, String> {
            let mut s = self.0.lock().unwrap();
            s.ensures += 1;
            if let Some(e) = &s.refuse {
                return Err(e.clone());
            }
            s.veth_ok = true;
            Ok(HostFacts {
                kernel_ifindex: 90,
                kernel_mac: [0x02, 0, 0, 0, 0, 0x90],
                vpp_ifindex: 91,
                vpp_mac: [0x02, 0, 0, 0, 0, 0x91],
                mtu: 1500,
            })
        }
        fn check(&mut self, _facts: &HostFacts) -> HostCheck {
            let s = self.0.lock().unwrap();
            HostCheck {
                veth: s.veth_ok,
                guard: true,
            }
        }
        fn owned_addrs(
            &mut self,
            _facts: &HostFacts,
        ) -> Result<Option<BTreeSet<Ipv6Addr>>, String> {
            Ok(self.0.lock().unwrap().addrs.take())
        }
        fn teardown(&mut self) -> Result<(), String> {
            self.0.lock().unwrap().torn_down = true;
            Ok(())
        }
    }

    /// Nothing is built until the steering target diverts IPv6; a want
    /// builds the kernel half even with no VPP to talk to, and the path is
    /// not ready without VPP's half.
    #[test]
    fn only_a_want_builds_and_the_kernel_half_alone_is_not_ready() {
        let host = FakeHost::default();
        let mut hb = Handback::new(Box::new(host.clone()));
        let now = Instant::now();
        hb.service(None, now, true).unwrap();
        assert_eq!(host.0.lock().unwrap().ensures, 0, "no want, no veth");
        assert!(!hb.ready());

        hb.set_wanted(true);
        hb.service(None, now, true).unwrap();
        assert_eq!(host.0.lock().unwrap().ensures, 1);
        let st = hb.status();
        assert!(
            st.wanted && st.veth && st.guard && !st.vpp_up && !st.ready,
            "{st:?}"
        );
        assert!(hb.built());
    }

    /// A refused build is retried on RETRY_EVERY, not every tick, and its
    /// reason is on the status until an attempt succeeds.
    #[test]
    fn a_refused_build_is_paced_and_reported() {
        let host = FakeHost::default();
        host.0.lock().unwrap().refuse = Some("nft: not found".into());
        let mut hb = Handback::new(Box::new(host.clone()));
        hb.set_wanted(true);
        let t0 = Instant::now();
        hb.service(None, t0, true).unwrap();
        hb.service(None, t0 + Duration::from_secs(1), true).unwrap();
        assert_eq!(host.0.lock().unwrap().ensures, 1, "paced");
        assert!(hb.status().error.unwrap().contains("nft: not found"));

        host.0.lock().unwrap().refuse = None;
        hb.service(None, t0 + RETRY_EVERY, true).unwrap();
        assert_eq!(host.0.lock().unwrap().ensures, 2);
        assert!(hb.status().error.is_none());
    }

    /// A veth that went away is noticed on the next check and rebuilt.
    #[test]
    fn a_broken_veth_is_rebuilt_on_the_next_check() {
        let host = FakeHost::default();
        let mut hb = Handback::new(Box::new(host.clone()));
        hb.set_wanted(true);
        let t0 = Instant::now();
        hb.service(None, t0, true).unwrap();
        host.0.lock().unwrap().veth_ok = false;
        hb.service(None, t0 + Duration::from_secs(1), true).unwrap();
        assert_eq!(host.0.lock().unwrap().ensures, 1, "not due yet");
        hb.service(None, t0 + CHECK_EVERY, true).unwrap();
        assert_eq!(host.0.lock().unwrap().ensures, 2, "rebuilt");
        assert!(hb.status().veth);
    }

    /// Teardown removes the kernel half whether or not this process
    /// built it.
    #[test]
    fn teardown_reaches_the_kernel_half_unconditionally() {
        let host = FakeHost::default();
        let mut hb = Handback::new(Box::new(host.clone()));
        hb.teardown(None).unwrap();
        assert!(host.0.lock().unwrap().torn_down);
    }

    #[test]
    fn a_target_wants_the_path_only_when_it_diverts_v6() {
        use crate::steer::{McamBudget, RuleSet, V6Steering};
        use packetframe_common::config::VppSteerDirection;
        let v4 = [IpPrefix::V4 {
            addr: [192, 0, 2, 0],
            prefix_len: 24,
        }];
        let mac = [0x02, 0, 0, 0, 0, 1];
        let v4_only = RuleSet::plan(
            &v4,
            &[],
            McamBudget::default(),
            VppSteerDirection::Src,
            &[mac],
        )
        .unwrap();
        let with_v6 = RuleSet::plan_with_v6(
            &v4,
            &[],
            McamBudget::default(),
            VppSteerDirection::Src,
            &[mac],
            &V6Steering {
                vlans: vec![Some(100)],
                keeps: vec![],
            },
        )
        .unwrap();
        assert!(!plans_divert_v6(&[("eth4".into(), 0, v4_only.clone())]));
        assert!(plans_divert_v6(&[
            ("eth4".into(), 0, v4_only),
            ("eth5".into(), 0, with_v6)
        ]));
        assert!(!plans_divert_v6(&[]));
    }
}
