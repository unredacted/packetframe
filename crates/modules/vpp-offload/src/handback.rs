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
//! - a guard IN VPP ([`render_guard`]): a stateless ACL bound as the
//!   hand-back interface's output ACL, admitting only traffic to the
//!   router's own addresses that is a reply — TCP with ACK or RST set, UDP
//!   from a DNS or NTP server to the kernel's ephemeral ports — because
//!   what arrives on the veth
//!   bypasses the vendor's WAN_LOCAL rules (they key on the physical WAN
//!   ports), and the vendor controller rewrites the kernel's netfilter on
//!   every config apply, so no kernel rule would stay put. It needs VPP's
//!   acl_plugin, which the handshake requires by name like af_packet's.
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
    AclAddReplace, AclAddReplaceReply, AclDel, AclDelReply, AclDetails, AclDump,
    AclInterfaceListDetails, AclInterfaceListDump, AclInterfaceSetAclList,
    AclInterfaceSetAclListReply, AclRule, AfPacketCreateV3, AfPacketCreateV3Reply, AfPacketDelete,
    AfPacketDeleteReply, AfPacketDetails, AfPacketDump, CliInband, CliInbandReply, IpNeighbor,
    IpNeighborAddDel, IpNeighborAddDelReply, IpNeighborDetails, IpNeighborDump, IpRoute,
    IpRouteAddDel, IpRouteAddDelReply, IpRouteDetails, IpRouteDump, IpRouteLookup,
    IpRouteLookupReply, IpTable, SwInterfaceSetFlags, SwInterfaceSetFlagsReply, SwInterfaceSetMtu,
    SwInterfaceSetMtuReply, ACL_ACTION_API_DENY, ACL_ACTION_API_PERMIT, ADDRESS_IP6,
    AF_PACKET_API_FLAG_QDISC_BYPASS, AF_PACKET_API_MODE_ETHERNET, IP_API_PROTO_TCP,
    IP_API_PROTO_UDP,
};
use crate::vpp_api::{Transport, TransportError};

/// The kernel's end of the veth pair.
pub const KERNEL_IF: &str = "pfpunt0";
/// VPP's end: the host interface its af_packet socket opens. VPP names
/// the resulting interface `host-pfpunt0-vpp`.
pub const VPP_HOST_IF: &str = "pfpunt0-vpp";
/// How often a built path is re-checked end to end: the veth still up,
/// VPP's interface, /128s, neighbour and guard ACL still exactly there,
/// and the kernel's ephemeral port range re-read. A kernel read and a
/// handful of API calls — cheap, but not per tick.
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

/// The tag the guard ACL carries — how adoption finds it in a surviving
/// VPP, and how a second copy is recognised as ours to remove.
pub const ACL_TAG: &str = "packetframe-handback";

/// TCP flag bits, as the ACL's `tcp_flags_mask`/`tcp_flags_value` read them.
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_ACK: u8 = 0x10;

/// The ports a guard rule's destination may use: the kernel's ephemeral
/// range, `(first, last)`.
pub type PortRange = (u16, u16);

/// `/proc/sys/net/ipv4/ip_local_port_range` → `(first, last)`, validated:
/// two ports, `1 <= first <= last`. The file is IPv4's by name and the
/// kernel's ephemeral range for IPv6 sockets too.
pub fn parse_port_range(text: &str) -> Result<PortRange, String> {
    let mut it = text.split_whitespace().map(str::parse::<u16>);
    match (it.next(), it.next(), it.next()) {
        (Some(Ok(first)), Some(Ok(last)), None) if first >= 1 && first <= last => Ok((first, last)),
        _ => Err(format!(
            "ip_local_port_range reads {:?}, not two ports `first last` with 1 <= first <= last",
            text.trim()
        )),
    }
}

fn any_v6() -> crate::vpp_api::generated::Prefix {
    crate::fib_sync::to_prefix(IpPrefix::V6 {
        addr: [0; 16],
        prefix_len: 0,
    })
}

/// The UDP source ports whose replies the guard hands back — and only to
/// a destination port inside the kernel's ephemeral range: the classic
/// stateless reply rule, `permit udp any eq domain any gt 1023`. Each is a
/// service the router is a CLIENT of, whose answers can arrive on a
/// diverted port:
///
/// - 53, DNS: answers to the router's own resolver's upstream queries
///   (the built-in DNS keep covers queries TO the router, not these);
/// - 123, NTP: answers to the router's time sync.
///
/// Deliberately a short constant, not a knob: every other UDP datagram
/// handed back would reach a kernel socket past the vendor's WAN_LOCAL
/// rules, and a listener inside the ephemeral range (an overlay VPN's
/// port) must not become reachable from the internet through it. What
/// stays open is a datagram SPOOFING source port 53 or 123 aimed at such a
/// listener — the residual cost of a stateless rule.
pub const UDP_REPLY_SOURCE_PORTS: [u16; 2] = [53, 123];

fn guard_rule(
    is_permit: u8,
    dst: Option<Ipv6Addr>,
    proto: u8,
    (sports, dports): (PortRange, PortRange),
    tcp_flags: (u8, u8),
) -> AclRule {
    AclRule {
        is_permit,
        src_prefix: any_v6(),
        dst_prefix: dst.map_or_else(any_v6, |a| {
            crate::fib_sync::to_prefix(IpPrefix::V6 {
                addr: a.octets(),
                prefix_len: 128,
            })
        }),
        proto,
        srcport_or_icmptype_first: sports.0,
        srcport_or_icmptype_last: sports.1,
        dstport_or_icmpcode_first: dports.0,
        dstport_or_icmpcode_last: dports.1,
        tcp_flags_mask: tcp_flags.0,
        tcp_flags_value: tcp_flags.1,
    }
}

/// The guard: the stateless ACL VPP applies to everything it sends the
/// kernel through the hand-back interface (its OUTPUT ACL). In VPP rather
/// than the kernel because PacketFrame owns VPP, while the vendor
/// controller flushes and rewrites the kernel's netfilter on every config
/// apply — no kernel rule would stay put.
///
/// Per router-owned address `A` (the same set the /128s route; nothing is
/// handed back for any other destination, defence in depth against a
/// stray packet Linux would forward — it has no per-interface IPv6
/// forwarding switch):
///
/// 1. TCP to `A` with ACK set — the classic stateless `established` test
///    (the `established` keyword of Cisco and Juniper ACLs): every segment
///    of a connection the router opened, its SYN+ACK included.
/// 2. TCP to `A` with RST set — the other half of that same test.
/// 3. UDP to `A` FROM one of [`UDP_REPLY_SOURCE_PORTS`] (DNS, NTP) TO a
///    port in the kernel's ephemeral range ([`parse_port_range`]) — one
///    rule per source port: replies to the router's own client queries.
///
/// then deny everything. So a pure SYN — every NEW inbound TCP connection
/// to the router over diverted IPv6 — is refused, and so are NULL,
/// FIN-only and Xmas-style probes, and every other UDP datagram. A service
/// that must accept new sessions is `steer-keep6`'d and never enters VPP;
/// so must an overlay or VPN that relies on direct inbound UDP over IPv6
/// through a diverted port, or it falls back (to relays, or IPv4).
pub fn render_guard(addrs: &BTreeSet<Ipv6Addr>, ports: PortRange) -> Vec<AclRule> {
    let all = (0, u16::MAX);
    let mut rules = Vec::with_capacity(addrs.len() * (2 + UDP_REPLY_SOURCE_PORTS.len()) + 1);
    for a in addrs {
        rules.push(guard_rule(
            ACL_ACTION_API_PERMIT,
            Some(*a),
            IP_API_PROTO_TCP,
            (all, all),
            (TCP_FLAG_ACK, TCP_FLAG_ACK),
        ));
        rules.push(guard_rule(
            ACL_ACTION_API_PERMIT,
            Some(*a),
            IP_API_PROTO_TCP,
            (all, all),
            (TCP_FLAG_RST, TCP_FLAG_RST),
        ));
        for sport in UDP_REPLY_SOURCE_PORTS {
            rules.push(guard_rule(
                ACL_ACTION_API_PERMIT,
                Some(*a),
                IP_API_PROTO_UDP,
                ((sport, sport), ports),
                (0, 0),
            ));
        }
    }
    // VPP's ACLs end in an implicit deny; stated, so the readback shows
    // the whole policy and a rule appended after it would be visible drift.
    rules.push(guard_rule(ACL_ACTION_API_DENY, None, 0, (all, all), (0, 0)));
    rules
}

/// Our tagged ACLs in VPP, `(index, rules)`.
fn our_acls(t: &mut Transport) -> Result<Vec<(u32, Vec<AclRule>)>, TransportError> {
    let details: Vec<AclDetails> = t.dump(AclDump {
        context: 0,
        acl_index: u32::MAX,
    })?;
    Ok(details
        .into_iter()
        .filter(|d| d.tag == ACL_TAG)
        .map(|d| (d.acl_index, d.r))
        .collect())
}

/// What is bound to `sw_if_index`: `(n_input, acls)`, `None` for nothing.
fn bound_acls(
    t: &mut Transport,
    sw_if_index: u32,
) -> Result<Option<(u8, Vec<u32>)>, TransportError> {
    let details: Vec<AclInterfaceListDetails> = t.dump(AclInterfaceListDump {
        context: 0,
        sw_if_index,
    })?;
    Ok(details
        .into_iter()
        .find(|d| d.sw_if_index == sw_if_index && d.count > 0)
        .map(|d| (d.n_input, d.acls)))
}

fn bind_output(t: &mut Transport, sw_if_index: u32, acls: Vec<u32>) -> Result<(), HandbackError> {
    let reply: AclInterfaceSetAclListReply = t.request(AclInterfaceSetAclList {
        context: 0,
        sw_if_index,
        count: acls.len() as u8,
        n_input: 0,
        acls,
    })?;
    if reply.retval != 0 {
        return Err(refused(
            "acl_interface_set_acl_list",
            reply.retval,
            "the guard as the hand-back interface's output ACL",
        ));
    }
    Ok(())
}

/// Whether the guard is in VPP EXACTLY as intended for `addrs` and
/// `ports`: our ACL holding precisely the rendered rules in order, and it
/// alone bound to the hand-back interface as its output ACL. Any drift —
/// a rule missing, reordered or widened, the ACL unbound or joined by
/// another — is `false`.
pub fn guard_in_place(
    t: &mut Transport,
    half: &VppHalf,
    addrs: &BTreeSet<Ipv6Addr>,
    ports: PortRange,
) -> Result<bool, TransportError> {
    let Some(idx) = half.acl else {
        return Ok(false);
    };
    let want = render_guard(addrs, ports);
    let ours = our_acls(t)?;
    if ours.iter().find(|(i, _)| *i == idx).map(|(_, r)| r) != Some(&want) {
        return Ok(false);
    }
    Ok(bound_acls(t, half.sw_if_index)? == Some((0, vec![idx])))
}

/// Build or repair the guard: reuse our ACL (the one this process knows,
/// else the one a surviving VPP holds under [`ACL_TAG`]), replace its
/// rules in place when they are not exactly the intended ones, bind it
/// alone as the hand-back interface's output ACL, and remove any other
/// copy. Idempotent: a guard in place is only read.
pub fn ensure_guard(
    t: &mut Transport,
    half: &mut VppHalf,
    addrs: &BTreeSet<Ipv6Addr>,
    ports: PortRange,
) -> Result<(), HandbackError> {
    let want = render_guard(addrs, ports);
    let ours = our_acls(t)?;
    let known = half
        .acl
        .filter(|i| ours.iter().any(|(j, _)| j == i))
        .or_else(|| ours.first().map(|(i, _)| *i));
    let current = known.and_then(|i| ours.iter().find(|(j, _)| *j == i).map(|(_, r)| r));
    let idx = if current == Some(&want) {
        known.expect("current implies known")
    } else {
        let reply: AclAddReplaceReply = t.request(AclAddReplace {
            context: 0,
            // ~0 creates; an index replaces that ACL's rules in place, so
            // the binding never points at a missing ACL.
            acl_index: known.unwrap_or(u32::MAX),
            tag: ACL_TAG.into(),
            count: want.len() as u32,
            r: want,
        })?;
        if reply.retval != 0 {
            return Err(refused(
                "acl_add_replace",
                reply.retval,
                "the hand-back guard ACL",
            ));
        }
        reply.acl_index
    };
    half.acl = Some(idx);
    if bound_acls(t, half.sw_if_index)? != Some((0, vec![idx])) {
        bind_output(t, half.sw_if_index, vec![idx])?;
    }
    for (other, _) in ours.iter().filter(|(i, _)| *i != idx) {
        let reply: AclDelReply = t.request(AclDel {
            context: 0,
            acl_index: *other,
        })?;
        if reply.retval != 0 {
            return Err(refused(
                "acl_del",
                reply.retval,
                format!("a second hand-back guard ACL, index {other}"),
            ));
        }
    }
    half.guard_for = Some((addrs.clone(), ports));
    Ok(())
}

/// Unbind and delete the guard. Absent is success.
fn remove_guard(t: &mut Transport, half: &mut VppHalf) -> Result<(), HandbackError> {
    if bound_acls(t, half.sw_if_index)?.is_some() {
        bind_output(t, half.sw_if_index, Vec::new())?;
    }
    for (idx, _) in our_acls(t)? {
        let reply: AclDelReply = t.request(AclDel {
            context: 0,
            acl_index: idx,
        })?;
        if reply.retval != 0 {
            return Err(refused(
                "acl_del",
                reply.retval,
                format!("the hand-back guard ACL, index {idx}"),
            ));
        }
    }
    half.acl = None;
    half.guard_for = None;
    Ok(())
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

/// The kernel half: veth, sysctls, the host's addresses and its ephemeral
/// port range.
/// [`KernelHostSide`] on Linux; tests supply their own.
pub trait HostSide {
    /// Create — or adopt, when it already exists as built — the veth
    /// pair, set its sysctls and MTU and bring both ends up. Idempotent.
    fn ensure(&mut self) -> Result<HostFacts, String>;
    /// Whether the veth is still exactly as [`Self::ensure`] built it
    /// ([`veth_as_built`]): ifindexes, MACs, MTU, both ends up.
    fn check(&mut self, facts: &HostFacts) -> bool;
    /// The kernel's ephemeral port range ([`parse_port_range`]), which the
    /// guard admits UDP replies to.
    fn ephemeral_ports(&mut self) -> Result<PortRange, String>;
    /// The router-owned addresses ([`router_owned`]) if they may have
    /// changed since the last call — `Some` on the first call, after any
    /// RTM_NEWADDR/RTM_DELADDR, and on a periodic resync; `None` when
    /// nothing has been heard. A failed read says whether a change was
    /// PENDING ([`AddrReadError::pending`]), and a pending change stays
    /// pending — re-read on every call — until a read succeeds.
    fn owned_addrs(
        &mut self,
        facts: &HostFacts,
    ) -> Result<Option<BTreeSet<Ipv6Addr>>, AddrReadError>;
    /// Remove the veth pair. Absent is success.
    fn teardown(&mut self) -> Result<(), String>;
}

/// One veth end as the kernel reports it now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkState {
    pub index: u32,
    pub mac: Option<[u8; 6]>,
    pub mtu: Option<u32>,
    pub up: bool,
}

/// Whether the veth, as the kernel reports it now, is still the one
/// `facts` describes: both ends with the ifindexes, MACs and MTU they were
/// built with, and up. A MAC or MTU changed by hand is as much a changed
/// path as a missing end: the neighbour VPP resolves through, or the MTU a
/// router-owned packet must fit, no longer holds.
pub fn veth_as_built(kernel: &LinkState, vpp: &LinkState, facts: &HostFacts) -> bool {
    kernel.up
        && vpp.up
        && (kernel.index, vpp.index) == (facts.kernel_ifindex, facts.vpp_ifindex)
        && (kernel.mac, vpp.mac) == (Some(facts.kernel_mac), Some(facts.vpp_mac))
        && (kernel.mtu, vpp.mtu) == (Some(facts.mtu), Some(facts.mtu))
}

/// A failed read of the host's addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrReadError {
    /// An address event had arrived (or the watch overran or broke, so
    /// events may have been lost) and the read that would have followed
    /// it failed: the host's address set is UNKNOWN, and a /128 may be
    /// missing for an address the router now answers on. `false` for a
    /// failed periodic re-read with nothing heard since the last good
    /// one, which leaves that set standing.
    pub pending: bool,
    pub why: String,
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
    /// The veth this half was built or adopted for. Other ifindexes mean
    /// the veth was rebuilt under it and the socket is bound to one that no
    /// longer exists (recreate); another MAC or MTU on the same veth means
    /// the neighbour, next hop or MTU is stale (re-ensure). Either way the
    /// path is not ready until it matches again ([`Handback::ready`]).
    pub bound_to: HostFacts,
    /// The kernel veth's link-local, which the static neighbour resolves.
    pub next_hop: Ipv6Addr,
    /// The kernel veth's MAC: the static neighbour's link-layer address.
    pub next_hop_mac: [u8; 6],
    /// The guard ACL's index, once this process has made or found it.
    pub acl: Option<u32>,
    /// The `(addresses, port range)` the guard was last programmed or
    /// verified for; `None` when it must be (re)checked or repaired.
    pub guard_for: Option<(BTreeSet<Ipv6Addr>, PortRange)>,
    /// The /128s VPP has ACKNOWLEDGED holding through this interface —
    /// an acknowledgement cache, re-read against VPP on every check
    /// ([`revalidate`]), since another client or an operator can remove
    /// or replace one behind it.
    pub routes: BTreeSet<Ipv6Addr>,
    /// /128s a surviving VPP routes through this interface in a shape this
    /// module never installs (more than one path, another next hop): not
    /// acknowledged, so the sync replaces the ones the host still holds and
    /// withdraws the rest.
    pub malformed: BTreeSet<Ipv6Addr>,
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
    let mut adopted = existing
        .iter()
        .find(|d| d.host_if_name == VPP_HOST_IF)
        .map(|d| d.sw_if_index);
    // A host interface of that NAME may be bound to a veth that no longer
    // exists: `pfpunt0` deleted and recreated while VPP survived (a
    // `--keep-vpp` restart across it, an operator's `ip link del`). Its
    // socket then reads a dead ifindex forever, and adopting it would
    // re-adopt a down interface on every check. Two tells, either enough:
    // it does not wear the current veth end's MAC (we create it wearing
    // that MAC, and a recreated veth gets a new one), or its link is down
    // while that end is up (ensure brought it up just before this).
    if let Some(idx) = adopted {
        let bound = crate::attach::interfaces(t)?
            .into_iter()
            .find(|i| i.sw_if_index == idx)
            .is_some_and(|i| i.l2_address == facts.vpp_mac && i.link_up());
        if !bound {
            tracing::warn!(
                sw_if_index = idx,
                host_if = VPP_HOST_IF,
                "VPP's hand-back host interface is bound to a veth that is gone (wrong MAC or \
                 no link); deleting and recreating it"
            );
            delete_host_if(t)?;
            adopted = None;
        }
    }
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
    ensure_neighbour(t, sw_if_index, next_hop, facts.kernel_mac)?;
    // A just-created interface has no routes through it; only an adopted
    // one is worth a table read.
    let (routes, malformed) = if adopted.is_some() {
        routes_via(t, sw_if_index, next_hop)?
    } else {
        Default::default()
    };
    Ok(VppHalf {
        sw_if_index,
        bound_to: facts.clone(),
        malformed,
        next_hop,
        next_hop_mac: facts.kernel_mac,
        acl: None,
        guard_for: None,
        routes,
    })
}

/// Make sure VPP holds the static neighbour the /128s resolve through,
/// adding it only when the dump does not show it exactly — a re-add
/// replaces the entry and walks every route through it. `true` when it
/// had to be added.
fn ensure_neighbour(
    t: &mut Transport,
    sw_if_index: u32,
    next_hop: Ipv6Addr,
    mac: [u8; 6],
) -> Result<bool, HandbackError> {
    let neighbours: Vec<IpNeighborDetails> = t.dump(IpNeighborDump {
        context: 0,
        sw_if_index,
        af: ADDRESS_IP6,
    })?;
    let present = neighbours.iter().any(|d| {
        d.neighbor.sw_if_index == sw_if_index
            && crate::fib_sync::from_address(&d.neighbor.ip_address) == Some(IpAddr::V6(next_hop))
            && d.neighbor.mac_address == mac
            && d.neighbor.flags == crate::engine::IP_NEIGHBOR_STATIC
    });
    if present {
        return Ok(false);
    }
    let reply: IpNeighborAddDelReply = t.request(IpNeighborAddDel {
        context: 0,
        is_add: true,
        neighbor: IpNeighbor {
            sw_if_index,
            flags: crate::engine::IP_NEIGHBOR_STATIC,
            mac_address: mac,
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
    Ok(true)
}

/// Read back what readiness rests on, cheaply: an exact lookup per /128
/// the cache says VPP holds (a handful, not a table dump), and the
/// interface's neighbour dump. A /128 that is gone, or no longer points
/// at the hand-back interface and next hop, leaves the cache — so the
/// path reads not ready until the next sync puts it back. A missing or
/// altered neighbour is re-added on the spot. Returns the /128s dropped.
pub fn revalidate(t: &mut Transport, half: &mut VppHalf) -> Result<usize, HandbackError> {
    let mut lost = 0usize;
    for addr in half.routes.clone() {
        let reply: IpRouteLookupReply = t.request(IpRouteLookup {
            context: 0,
            table_id: 0,
            exact: 1,
            prefix: crate::fib_sync::to_prefix(IpPrefix::V6 {
                addr: addr.octets(),
                prefix_len: 128,
            }),
        })?;
        let ours = reply.retval == 0
            && !reply.route.paths.is_empty()
            && reply.route.paths.iter().all(|p| {
                p.sw_if_index == half.sw_if_index && p.nh.address.0 == half.next_hop.octets()
            });
        if !ours {
            tracing::warn!(
                %addr,
                "a hand-back /128 is gone from VPP or no longer points at the hand-back \
                 interface; re-installing it"
            );
            half.routes.remove(&addr);
            lost += 1;
        }
    }
    if ensure_neighbour(t, half.sw_if_index, half.next_hop, half.next_hop_mac)? {
        tracing::warn!(
            next_hop = %half.next_hop,
            "the hand-back static neighbour was missing or altered in VPP; re-added"
        );
    }
    Ok(lost)
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

/// The /128s VPP's IPv6 table routes through `sw_if_index`, split into
/// `(ours, malformed)`: ours has exactly the shape [`route_op`] installs —
/// one path, NORMAL, via `sw_if_index` to `next_hop` — and anything else
/// touching the interface (a second path, another next hop) is malformed,
/// never counted as acknowledged.
fn routes_via(
    t: &mut Transport,
    sw_if_index: u32,
    next_hop: Ipv6Addr,
) -> Result<(BTreeSet<Ipv6Addr>, BTreeSet<Ipv6Addr>), TransportError> {
    let details: Vec<IpRouteDetails> = t.dump(IpRouteDump {
        context: 0,
        table: IpTable {
            table_id: 0,
            is_ip6: true,
            name: String::new(),
        },
    })?;
    let want = crate::fib_sync::wire_path(IpAddr::V6(next_hop), sw_if_index);
    let mut ours = BTreeSet::new();
    let mut malformed = BTreeSet::new();
    for d in details {
        if !d.route.paths.iter().any(|p| p.sw_if_index == sw_if_index) {
            continue;
        }
        let Some(IpPrefix::V6 {
            addr,
            prefix_len: 128,
        }) = crate::fib_sync::from_prefix(&d.route.prefix)
        else {
            continue;
        };
        let exact = matches!(d.route.paths.as_slice(), [p] if p.sw_if_index == want.sw_if_index
            && p.r#type == want.r#type
            && p.proto == want.proto
            && p.nh.address == want.nh.address);
        if exact {
            ours.insert(Ipv6Addr::from(addr));
        } else {
            malformed.insert(Ipv6Addr::from(addr));
        }
    }
    Ok((ours, malformed))
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
    // A malformed route for an address the host no longer holds goes; one
    // it still holds is replaced by the add below (`is_multipath` false
    // replaces every path).
    let strays: Vec<Ipv6Addr> = half.malformed.difference(desired).copied().collect();
    for addr in strays {
        route_op(t, half, addr, false)?;
        half.malformed.remove(&addr);
        tracing::info!(%addr, "a malformed hand-back route was withdrawn");
    }
    let stale: Vec<Ipv6Addr> = half.routes.difference(desired).copied().collect();
    for addr in stale {
        route_op(t, half, addr, false)?;
        half.routes.remove(&addr);
        tracing::info!(%addr, "hand-back route withdrawn: the host no longer holds this address");
    }
    let missing: Vec<Ipv6Addr> = desired.difference(&half.routes).copied().collect();
    for addr in missing {
        route_op(t, half, addr, true)?;
        half.malformed.remove(&addr);
        half.routes.insert(addr);
        tracing::info!(%addr, "hand-back route installed: VPP hands this address to the kernel");
    }
    Ok(())
}

/// Take VPP's end down: its routes, its neighbour, the host interface.
pub fn remove_vpp(t: &mut Transport, half: &mut VppHalf) -> Result<(), HandbackError> {
    // Routes first, so nothing is handed back while the guard comes off.
    sync_routes(t, half, &BTreeSet::new())?;
    remove_guard(t, half)?;
    // The static neighbour goes with its interface.
    delete_host_if(t)
}

fn delete_host_if(t: &mut Transport) -> Result<(), HandbackError> {
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
    /// The guard ACL is in VPP exactly as intended and bound.
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
    veth_ok: bool,
    /// The kernel's ephemeral port range, as last read. A failed re-read
    /// keeps it: the range changes by hand, rarely, and a guard that
    /// flapped on every unreadable procfs read would churn the v6 rules.
    ports: Option<PortRange>,
    vpp: Option<VppHalf>,
    /// VPP's routes are in doubt: a transport failure mid-sync may have
    /// applied an op whose acknowledgement never came. Re-read before the
    /// next sync.
    routes_in_doubt: bool,
    vpp_name: Option<String>,
    vpp_up: bool,
    tx_packets: Option<u64>,
    desired: Option<BTreeSet<Ipv6Addr>>,
    /// An address change is pending and its read failed: `desired` may be
    /// missing an address the router now answers on. See
    /// [`AddrReadError::pending`] and [`Self::ready`].
    addrs_unknown: bool,
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
            veth_ok: false,
            ports: None,
            vpp: None,
            routes_in_doubt: false,
            vpp_name: None,
            vpp_up: false,
            tx_packets: None,
            desired: None,
            addrs_unknown: false,
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
    ///
    /// Not ready while an address change is pending and could not be read
    /// (`addrs_unknown`): a new address may be one the router already
    /// answers on with no /128 behind it, and its traffic would die in
    /// VPP. A failed PERIODIC re-read, with nothing heard since the last
    /// good one, leaves the last good set standing instead — the watch
    /// would have heard a change, and closing the gate on a flaky read
    /// would churn every v6 rule for nothing.
    pub fn ready(&self) -> bool {
        self.wanted
            && self.facts.is_some()
            && self.veth_ok
            && self.guard_ok()
            && self.vpp_up
            && !self.routes_in_doubt
            && !self.addrs_unknown
            && match (&self.vpp, &self.desired, &self.facts) {
                // Built for THIS veth — a half left from a veth since rebuilt,
                // or whose MAC or MTU moved, is not ready even when a refused
                // cleanup kept it around to retry — and holding exactly the
                // host's addresses, nothing malformed beside them.
                (Some(v), Some(d), Some(f)) => {
                    v.bound_to == *f && v.routes == *d && v.malformed.is_empty()
                }
                _ => false,
            }
    }

    /// The guard ACL was last programmed or verified for exactly the
    /// current addresses and port range.
    fn guard_ok(&self) -> bool {
        match (&self.vpp, &self.desired, self.ports) {
            (Some(v), Some(d), Some(p)) => v.guard_for.as_ref() == Some(&(d.clone(), p)),
            _ => false,
        }
    }

    pub fn status(&self) -> HandbackStatus {
        HandbackStatus {
            wanted: self.wanted,
            ready: self.ready(),
            veth: self.facts.is_some() && self.veth_ok,
            guard: self.guard_ok(),
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
                self.veth_ok = self.host.check(&facts);
                if !self.veth_ok {
                    tracing::warn!("the IPv6 hand-back veth changed under the path; rebuilding it");
                    self.facts = None;
                }
                // Re-read on the check's cadence; a failure keeps the last
                // good range (see `ports`), and with none yet the read is
                // retried below before anything is built on it.
                match self.host.ephemeral_ports() {
                    Ok(p) => self.ports = Some(p),
                    Err(e) => tracing::warn!(
                        error = %e,
                        "could not re-read the kernel's ephemeral port range; the guard keeps \
                         the last one"
                    ),
                }
            }
            let sw_if_index = self.vpp.as_ref().map(|v| v.sw_if_index);
            if let (Some(t), Some(sw_if_index)) = (t.as_deref_mut(), sw_if_index) {
                if !self.observe_vpp_side(t, sw_if_index)? {
                    tracing::warn!(
                        sw_if_index,
                        "the hand-back interface is gone from VPP or not up; re-asserting it"
                    );
                    // Re-asserted by the ensure below: adopted by name when
                    // it is still bound to the veth, recreated when not; a
                    // link that stays down keeps the path not ready.
                    self.vpp = None;
                } else if !self.routes_in_doubt {
                    // The /128s and the neighbour, read back. What is gone
                    // leaves the cache, so the path reads not ready — the
                    // v6 gate closed — until the sync below re-installs it,
                    // in this same pass on a tick; a sync VPP refuses keeps
                    // it closed.
                    let v = self.vpp.as_mut().expect("checked just above");
                    match revalidate(t, v) {
                        Ok(_) => {}
                        Err(HandbackError::Transport(e)) => return Err(e),
                        Err(other) => {
                            self.vpp = None;
                            self.fail(now, other.to_string());
                            return Ok(());
                        }
                    }
                    // And the guard, compared structurally: any drift
                    // forgets that it was verified, which closes the gate
                    // until the repair below.
                    if let (Some(d), Some(p)) = (&self.desired, self.ports) {
                        if !guard_in_place(t, v, d, p)? {
                            tracing::warn!(
                                "the hand-back guard ACL drifted in VPP (a rule changed, or \
                                 it is no longer bound); repairing it"
                            );
                            v.guard_for = None;
                        }
                    }
                }
            }
        }
        if self.facts.is_none() {
            match self.host.ensure() {
                Ok(f) => {
                    self.veth_ok = true;
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
        // The same veth with another MAC or MTU: the neighbour, next hop or
        // MTU VPP holds is stale, and the idempotent ensure below puts each
        // right (a VPP end no longer wearing its veth's MAC is recreated by
        // its stale check; routes via the old next hop read as malformed
        // and are replaced).
        if self.vpp.as_ref().is_some_and(|v| {
            v.bound_to != facts
                && (v.bound_to.kernel_ifindex, v.bound_to.vpp_ifindex)
                    == (facts.kernel_ifindex, facts.vpp_ifindex)
        }) {
            tracing::warn!("the hand-back veth's MAC or MTU changed; re-asserting VPP's end");
            self.vpp = None;
        }
        // A veth rebuilt under a live VPP: its socket is bound to the old
        // interface, so the VPP half is recreated, not adopted. A refused
        // cleanup keeps the old half to retry, and `ready` stays false
        // while its `bound_to` names the old veth.
        if let Some(mut v) = self.vpp.take_if(|v| {
            (v.bound_to.kernel_ifindex, v.bound_to.vpp_ifindex)
                != (facts.kernel_ifindex, facts.vpp_ifindex)
        }) {
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
            Ok(Some(set)) => {
                self.desired = Some(set);
                self.addrs_unknown = false;
            }
            Ok(None) => {}
            Err(e) => {
                self.addrs_unknown |= e.pending;
                self.fail(
                    now,
                    format!(
                        "reading the router's IPv6 addresses{}: {}",
                        if e.pending {
                            " after a change (the v6 half is held back until it is read)"
                        } else {
                            " (periodic re-read; the last good set stands)"
                        },
                        e.why
                    ),
                );
                return Ok(());
            }
        }
        if self.ports.is_none() {
            match self.host.ephemeral_ports() {
                Ok(p) => self.ports = Some(p),
                Err(e) => {
                    self.fail(
                        now,
                        format!("reading the kernel's ephemeral port range: {e}"),
                    );
                    return Ok(());
                }
            }
        }
        // The guard, before any /128 moves — and even without `sync`: it is
        // ACL state, not FIB, so an adoption's fingerprint check is not
        // disturbed, and an intact guard is only read. Rendered from the
        // host's addresses, which the /128s are then brought to: a new
        // address is admitted before its route exists, a removed one is
        // refused before its route goes.
        if let (Some(d), Some(p), Some(v)) = (&self.desired, self.ports, self.vpp.as_mut()) {
            if v.guard_for.as_ref() != Some(&(d.clone(), p)) {
                match ensure_guard(t, v, d, p) {
                    Ok(()) => {}
                    Err(HandbackError::Transport(e)) => return Err(e),
                    Err(other) => {
                        self.fail(now, other.to_string());
                        return Ok(());
                    }
                }
            }
        }
        if !sync {
            return Ok(());
        }
        let v = self.vpp.as_mut().expect("ensured just above");
        if self.routes_in_doubt {
            (v.routes, v.malformed) = routes_via(t, v.sw_if_index, v.next_hop)?;
            self.routes_in_doubt = false;
        }
        if let Some(desired) = &self.desired {
            if v.routes != *desired || !v.malformed.is_empty() {
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
    //! has no async runtime), and sysctls and the ephemeral port range
    //! through procfs.

    use std::collections::BTreeSet;
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
        parse_port_range, router_owned, veth_as_built, AddrReadError, HostAddr, HostFacts,
        HostSide, LinkState, PortRange, KERNEL_IF, VPP_HOST_IF,
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
        /// A change was heard (or events may have been lost) and no read
        /// has succeeded since. See [`super::AddrReadError::pending`].
        pending: bool,
    }

    impl KernelHostSide {
        /// `mtu`: both veth ends' MTU (the largest member port's).
        pub fn new(mtu: u32) -> Self {
            Self {
                mtu,
                watch: None,
                dumped_at: None,
                pending: false,
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

        fn check(&mut self, facts: &HostFacts) -> bool {
            let state = |l: &Link| LinkState {
                index: l.index,
                mac: l.mac,
                mtu: l.mtu,
                up: l.up,
            };
            match dump_links().map(|l| find_pair(&l)) {
                Ok(Ok(Some((k, v)))) => veth_as_built(&state(&k), &state(&v), facts),
                _ => false,
            }
        }

        fn ephemeral_ports(&mut self) -> Result<PortRange, String> {
            let path = "/proc/sys/net/ipv4/ip_local_port_range";
            let text = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
            parse_port_range(&text)
        }

        fn owned_addrs(
            &mut self,
            facts: &HostFacts,
        ) -> Result<Option<BTreeSet<Ipv6Addr>>, AddrReadError> {
            // A watch that is not open (first call, or broken below) may
            // have missed events: the read it forces is pending, not
            // periodic. It opens BEFORE the dump it triggers, so an
            // address added between the two is heard rather than lost.
            if self.watch.is_none() {
                self.pending = true;
                match open_watch() {
                    Ok(s) => self.watch = Some(s),
                    Err(why) => return Err(AddrReadError { pending: true, why }),
                }
            }
            match drain_watch(self.watch.as_ref().expect("opened above")) {
                Ok(heard) => self.pending |= heard,
                Err(why) => {
                    // Reopened, with a full read, on the next call.
                    self.watch = None;
                    self.pending = true;
                    return Err(AddrReadError { pending: true, why });
                }
            }
            let periodic = self.dumped_at.is_none_or(|t| t.elapsed() >= RESYNC_EVERY);
            if !self.pending && !periodic {
                return Ok(None);
            }
            // `pending` survives a failure, so the next call reads again
            // even with nothing new heard.
            let addrs = dump_v6_addrs().map_err(|why| AddrReadError {
                pending: self.pending,
                why,
            })?;
            self.pending = false;
            self.dumped_at = Some(Instant::now());
            Ok(Some(router_owned(
                &addrs,
                &[facts.kernel_ifindex, facts.vpp_ifindex],
            )))
        }

        fn teardown(&mut self) -> Result<(), String> {
            let mut errors = Vec::new();
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
            self.pending = false;
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }
}

/// The non-Linux stand-in: there is no veth, rtnetlink or procfs to
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
        Err("the IPv6 hand-back path needs Linux (veth, rtnetlink, procfs)".into())
    }
    fn check(&mut self, _facts: &HostFacts) -> bool {
        false
    }
    fn ephemeral_ports(&mut self) -> Result<PortRange, String> {
        Err("the IPv6 hand-back path needs Linux".into())
    }
    fn owned_addrs(
        &mut self,
        _facts: &HostFacts,
    ) -> Result<Option<BTreeSet<Ipv6Addr>>, AddrReadError> {
        Err(AddrReadError {
            pending: true,
            why: "the IPv6 hand-back path needs Linux".into(),
        })
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

    /// The kernel's ephemeral range, validated at the boundary: two ports,
    /// tab- or space-separated, `1 <= first <= last`; anything else refused
    /// with the text it read.
    #[test]
    fn the_ephemeral_range_parses_and_refuses_nonsense() {
        assert_eq!(parse_port_range("32768\t60999\n"), Ok((32768, 60999)));
        assert_eq!(parse_port_range("1024 1024"), Ok((1024, 1024)));
        for bad in [
            "",
            "32768",
            "60999 32768",
            "0 100",
            "32768 70000",
            "a b",
            "1 2 3",
        ] {
            let e = parse_port_range(bad).expect_err(bad);
            assert!(e.contains("ip_local_port_range"), "{e}");
        }
    }

    /// Per address: TCP with ACK set, TCP with RST set — the classic
    /// stateless `established` test — and, per reply source port (DNS 53,
    /// NTP 123), UDP from that port to the ephemeral range; one explicit
    /// deny at the end. Every rule is scoped to the address as a /128, from
    /// any source. So a pure SYN (no ACK, no RST), a NULL or FIN-only probe,
    /// UDP to a service port, and UDP from anything but 53/123 into the
    /// ephemeral range (an overlay VPN's inbound datagram) all fall to the
    /// deny.
    #[test]
    fn the_guard_renders_the_established_policy_per_address() {
        let a: Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:7::7".parse().unwrap();
        let rules = render_guard(&[a, b].into_iter().collect(), (32768, 60999));
        let per = 2 + UDP_REPLY_SOURCE_PORTS.len();
        assert_eq!(UDP_REPLY_SOURCE_PORTS, [53, 123]);
        assert_eq!(rules.len(), 2 * per + 1);
        let dst = |r: &AclRule| crate::fib_sync::from_prefix(&r.dst_prefix).unwrap();
        let host = |x: Ipv6Addr| IpPrefix::V6 {
            addr: x.octets(),
            prefix_len: 128,
        };
        let any = Some(IpPrefix::V6 {
            addr: [0; 16],
            prefix_len: 0,
        });
        // BTreeSet order: 2001:db8:7::7 first.
        for (chunk, addr) in rules.chunks(per).zip([b, a]) {
            assert!(chunk.iter().all(|r| r.is_permit == ACL_ACTION_API_PERMIT
                && dst(r) == host(addr)
                && crate::fib_sync::from_prefix(&r.src_prefix) == any));
            for (r, flag) in chunk[..2].iter().zip([TCP_FLAG_ACK, TCP_FLAG_RST]) {
                assert_eq!(
                    (
                        r.proto,
                        r.tcp_flags_mask,
                        r.tcp_flags_value,
                        (r.srcport_or_icmptype_first, r.srcport_or_icmptype_last),
                        (r.dstport_or_icmpcode_first, r.dstport_or_icmpcode_last)
                    ),
                    (IP_API_PROTO_TCP, flag, flag, (0, u16::MAX), (0, u16::MAX))
                );
            }
            for (r, sport) in chunk[2..].iter().zip(UDP_REPLY_SOURCE_PORTS) {
                assert_eq!(
                    (
                        r.proto,
                        (r.srcport_or_icmptype_first, r.srcport_or_icmptype_last),
                        (r.dstport_or_icmpcode_first, r.dstport_or_icmpcode_last),
                        r.tcp_flags_mask
                    ),
                    (IP_API_PROTO_UDP, (sport, sport), (32768, 60999), 0),
                    "UDP only FROM {sport}, only INTO the ephemeral range"
                );
            }
        }
        let last = rules.last().unwrap();
        assert_eq!((last.is_permit, last.proto), (ACL_ACTION_API_DENY, 0));
        assert_eq!(crate::fib_sync::from_prefix(&last.dst_prefix), any);
        // No address yet: the deny alone.
        assert_eq!(render_guard(&BTreeSet::new(), (32768, 60999)).len(), 1);
    }

    /// The veth check covers everything the path rests on: ifindexes, both
    /// MACs, the MTU, both ends up. A change to any one is not the veth
    /// that was built.
    #[test]
    fn the_veth_check_covers_macs_and_mtu() {
        let facts = HostFacts {
            kernel_ifindex: 90,
            kernel_mac: [0x02, 0, 0, 0, 0, 0x90],
            vpp_ifindex: 91,
            vpp_mac: [0x02, 0, 0, 0, 0, 0x91],
            mtu: 9000,
        };
        let k = LinkState {
            index: 90,
            mac: Some(facts.kernel_mac),
            mtu: Some(9000),
            up: true,
        };
        let v = LinkState {
            index: 91,
            mac: Some(facts.vpp_mac),
            mtu: Some(9000),
            up: true,
        };
        assert!(veth_as_built(&k, &v, &facts));
        type Change = fn(&mut LinkState, &mut LinkState);
        let changes: [(&str, Change); 6] = [
            ("kernel MTU", |k, _| k.mtu = Some(1500)),
            ("VPP-end MTU", |_, v| v.mtu = Some(1500)),
            ("kernel MAC", |k, _| k.mac = Some([0x02, 0, 0, 0, 0, 0xee])),
            ("VPP-end MAC", |_, v| v.mac = Some([0x02, 0, 0, 0, 0, 0xee])),
            ("ifindex", |k, _| k.index = 92),
            ("down", |_, v| v.up = false),
        ];
        for (what, change) in changes {
            let (mut k2, mut v2) = (k, v);
            change(&mut k2, &mut v2);
            assert!(!veth_as_built(&k2, &v2, &facts), "{what}");
        }
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
        fn check(&mut self, _facts: &HostFacts) -> bool {
            self.0.lock().unwrap().veth_ok
        }
        fn ephemeral_ports(&mut self) -> Result<PortRange, String> {
            Ok((32768, 60999))
        }
        fn owned_addrs(
            &mut self,
            _facts: &HostFacts,
        ) -> Result<Option<BTreeSet<Ipv6Addr>>, AddrReadError> {
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
            st.wanted && st.veth && !st.guard && !st.vpp_up && !st.ready,
            "{st:?}"
        );
        assert!(hb.built());
    }

    /// A refused build is retried on RETRY_EVERY, not every tick, and its
    /// reason is on the status until an attempt succeeds.
    #[test]
    fn a_refused_build_is_paced_and_reported() {
        let host = FakeHost::default();
        host.0.lock().unwrap().refuse = Some("netlink: operation not permitted".into());
        let mut hb = Handback::new(Box::new(host.clone()));
        hb.set_wanted(true);
        let t0 = Instant::now();
        hb.service(None, t0, true).unwrap();
        hb.service(None, t0 + Duration::from_secs(1), true).unwrap();
        assert_eq!(host.0.lock().unwrap().ensures, 1, "paced");
        assert!(hb
            .status()
            .error
            .unwrap()
            .contains("netlink: operation not permitted"));

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
