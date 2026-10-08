//! MCAM steering: the ntuple rules that divert allowlisted traffic to
//! VPP's VF, and the canary lever the rollout turns.
//!
//! ## What is being asked of the NIC
//!
//! One rule per (allowlisted prefix × direction). A packet whose source
//! *or* destination falls in the allowlist is redirected to the VF VPP
//! owns; everything else stays on the kernel path with the eBPF
//! fast-path in front of it. That asymmetry is the whole design: the
//! offload takes a slice of traffic and the fallback tier keeps the
//! rest, so a VPP that dies costs only the steered slice.
//!
//! ## The two details that are not guessable
//!
//! **`ring_cookie` is `(vf + 1) << 32`.** `ethtool`'s own `vf N`
//! keyword mis-encodes this on the rvu driver — gate 0a established the
//! raw form works and the keyword does not, by inserting both and
//! reading back what the NIC actually stored. Nothing about the uapi
//! documents it.
//!
//! **`loc` must be an allocated slot, and there are sixteen.** The
//! driver rejects an out-of-range location rather than assigning one, so
//! this module tracks the locations it owns and hands back exactly
//! those. The size comes from the NIC via `ETHTOOL_GRXCLSRLALL` — see
//! [`McamBudget::for_ifaces`] — because this file previously asserted it
//! instead, from `npc/mcam_info`'s "2048 entries, 1689 available". Those
//! figures are real and describe the NPC block across all six PFs; they
//! have never governed an ethtool `loc`, which on this hardware runs
//! `0..=15` per port. At two rules per prefix that is a ceiling of
//! **eight steerable IPv4 prefixes per port**, which is tight at
//! allowlist scale and is the opposite of what this paragraph used to
//! say.
//!
//! ## IPv6: by frame, never by address
//!
//! Gate 0b round 4: every `ip6`/`tcp6`/`udp6` rule naming an ADDRESS is
//! rejected by the AF (error 710, `NPC_FLOW_NOT_SUPPORTED`) while the v4
//! control inserts cleanly — the vendor NPC profile extracts no v6 L3
//! address fields. So a v6 prefix in the allowlist is skipped here
//! rather than attempted, exactly as before.
//!
//! What the profile DOES extract was probed on 2026-09-26 against the
//! production kernel: the ethertype, the destination MAC, the outer VLAN
//! id and TCP/UDP ports (an `ip6 l4proto` rule inserts but matches every
//! v6 frame — see [`BUILTIN_KEEPS6`]). That is enough for one
//! policy that needs no address: **IPv6 by frame** — a TCP or UDP frame
//! over IPv6 addressed to one of the router's receive MACs, on a VLAN
//! the operator named (`port … v6-divert <vid>,…`), is traffic sent
//! through (or to) the router, and is diverted to the VF
//! ([`RuleMatch::V6Frame`]). On a customer VLAN that is outbound traffic;
//! on a transit or IX port it is inbound. Everything else — ICMPv6 above
//! all, so neighbour discovery in both directions and echo — matches no
//! diversion and stays with the kernel. What the ROUTER terminates over
//! TCP/UDP arrives on that same MAC. The services that must never enter
//! VPP are carved back out by higher-priority kernel-delivery rules keyed
//! on L4 ports alone ([`RuleMatch::V6L4`]): DNS, BGP, and whatever the
//! operator adds with `steer-keep6`. The rest of the router's own traffic
//! (the replies to sessions it opened) cannot be told apart by port, so
//! it is diverted and VPP hands it back to the kernel over the hand-back
//! path ([`crate::handback`]).
//!
//! The allowlist does not scope a v6 diversion — the NIC cannot read the
//! source address that would. Every TCP/UDP frame to the router on a listed
//! VLAN goes to VPP, whatever its source; which VLANs to list is the
//! operator's call, and the runbook says what it implies.
//!
//! Because the diversion is by frame, any v6 destination can reach VPP
//! once one exists, so the route-drift tripwire ([`crate::drift`]) scans
//! the kernel's IPv6 routes too while any port carries `v6-divert`. It
//! can only report: there is no v6 address rule to exempt with. The
//! keeps are what protect the control plane.
//!
//! ## What is here, and what is not
//!
//! This is the **policy** half only: which rules should exist, in which
//! slots, and what is refused. It touches no NIC, which is the point —
//! every mistake that silently misroutes traffic (a direction missed, a
//! family attempted that cannot work, a budget overrun leaving a port
//! half-steered) is decided here and tested without hardware.
//!
//! The ioctl half is [`crate::ntuple`], which installs what this plans
//! and reads every rule back with `ETHTOOL_GRXCLSRULE` before believing
//! it — `ethtool_rx_flow_spec` is not in `libc`, so its layout is
//! hand-written, and a field in the wrong place produces rules that
//! install cleanly and match the wrong traffic.

use std::net::Ipv4Addr;

use packetframe_common::config::VppSteerDirection;
use packetframe_common::fib::IpPrefix;

/// One steering rule, before it becomes bytes.
///
/// Persisted inside [`RuleSet`] (in
/// [`crate::resources::ResourceState::steer_plans`]), and the on-disk
/// form is deliberately not this struct's shape — see [`RuleSet`]'s
/// serde note for why v4 rules keep the pre-v6 record verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SteerRule {
    /// What the NIC compares.
    pub shape: RuleMatch,
    /// MCAM slot. Assigned by [`RuleSet::plan`], not by the driver.
    pub location: u32,
    /// Where a match goes: into VPP, or back to the kernel.
    pub action: RuleAction,
}

/// The match a rule asks the NIC for. One variant per `flow_type` shape
/// [`crate::ntuple`] encodes — every one of them inserted on the
/// production kernel before it was written here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleMatch {
    /// An IPv4 prefix on one side of the packet (`IP_USER_FLOW`).
    V4 {
        prefix: Ipv4Addr,
        prefix_len: u8,
        /// Which side of the packet this rule matches.
        side: Side,
        /// The destination MAC a `Divert` rule also requires: one the
        /// router's L3 devices answer to on this port
        /// ([`crate::topology::receive_macs`]). Without it a bridge
        /// member diverts frames the kernel is only bridging between two
        /// hosts, which VPP's split-horizon group then drops. `None` on
        /// `Keep` rules — delivering to the kernel is right for bridged
        /// frames too — and on plans read from a state file written
        /// before the field.
        dmac: Option<[u8; 6]>,
    },
    /// IPv6 by frame: destination MAC `dmac` (a receive MAC —
    /// required, for the same bridging reason as the v4 `dmac`), the
    /// outer VLAN id under mask 0x0FFF (PCP and DEI ignored), and the L4
    /// protocol. `vlan: None` is the untagged form, which carries no VLAN
    /// term at all: the NIC has no untagged-only match, so config
    /// validation admits it only on a port that declares no VLANs.
    ///
    /// `l4: Some(p)` is what the planner emits — `TCP_V6_FLOW` /
    /// `UDP_V6_FLOW` with no port, one rule per protocol — so ICMPv6
    /// never matches and neighbour discovery stays with the kernel (see
    /// [`BUILTIN_KEEPS6`] for why no keep can do that instead).
    /// `l4: None` is the whole-ethertype `ETHER_FLOW` rule the first
    /// IPv6-diversion build planned, which also took the NA replies to the
    /// kernel's own neighbour solicitations. It is never planned; it stays
    /// so a state file naming one still describes what is in the MCAM.
    V6Frame {
        dmac: [u8; 6],
        vlan: Option<u16>,
        l4: Option<L4Proto>,
    },
    /// An IPv6 L4 match with no address and no MAC — the v6 keeps. Port
    /// wide on purpose: a kernel-delivery rule that matches more than it
    /// needs to sends traffic where unmatched traffic goes anyway.
    V6L4(L4Match),
}

impl RuleMatch {
    /// Whether every frame `other` matches, this matches too — so a rule
    /// of this shape already takes all of `other`'s traffic wherever it
    /// sends it ([`adds_diversion`]).
    ///
    /// Conservative: only what can be shown is. A v4 prefix covers a
    /// longer one inside it on the same side, and a `dmac` term covers
    /// only the same MAC (no term covers any); a v6 frame match needs the
    /// same receive MAC, and covers a tagged one only from the untagged
    /// form (which carries no VLAN term) and an L4 one only from the
    /// whole-ethertype form. A v6 keep covers only itself. Different
    /// kinds never cover each other.
    pub fn covers(&self, other: &RuleMatch) -> bool {
        match (self, other) {
            (
                RuleMatch::V4 {
                    prefix: wide,
                    prefix_len: wide_len,
                    side: wide_side,
                    dmac: wide_dmac,
                },
                RuleMatch::V4 {
                    prefix: narrow,
                    prefix_len: narrow_len,
                    side: narrow_side,
                    dmac: narrow_dmac,
                },
            ) => {
                let mask = |len: u8| match len.min(32) {
                    0 => 0,
                    l => u32::MAX << (32 - u32::from(l)),
                };
                wide_side == narrow_side
                    && wide_len <= narrow_len
                    && u32::from(*wide) & mask(*wide_len) == u32::from(*narrow) & mask(*wide_len)
                    && (wide_dmac.is_none() || wide_dmac == narrow_dmac)
            }
            (
                RuleMatch::V6Frame {
                    dmac: wide_dmac,
                    vlan: wide_vlan,
                    l4: wide_l4,
                },
                RuleMatch::V6Frame {
                    dmac: narrow_dmac,
                    vlan: narrow_vlan,
                    l4: narrow_l4,
                },
            ) => {
                wide_dmac == narrow_dmac
                    && (wide_vlan.is_none() || wide_vlan == narrow_vlan)
                    && (wide_l4.is_none() || wide_l4 == narrow_l4)
            }
            (RuleMatch::V6L4(wide), RuleMatch::V6L4(narrow)) => wide == narrow,
            _ => false,
        }
    }
}

/// The L4 half of a v6 keep.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum L4Match {
    /// `ip6 l4proto N` (`IPV6_USER_FLOW`). NEVER planned: this NIC's
    /// driver accepts the rule but ignores the next-header value, so it
    /// matches every IPv6 frame (see [`BUILTIN_KEEPS6`]). The variant
    /// stays so the encoder, the readback and state files written by the
    /// build that planned one can still describe and remove it.
    Proto(u8),
    /// `tcp6`/`udp6` `src-port`/`dst-port N` (`TCP_V6_FLOW`/`UDP_V6_FLOW`).
    Port {
        proto: L4Proto,
        side: Side,
        port: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum L4Proto {
    Tcp,
    Udp,
}

impl std::fmt::Display for L4Match {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            L4Match::Proto(58) => write!(f, "ICMPv6"),
            L4Match::Proto(n) => write!(f, "IPv6 protocol {n}"),
            L4Match::Port { proto, side, port } => {
                let p = match proto {
                    L4Proto::Tcp => "TCP",
                    L4Proto::Udp => "UDP",
                };
                match side {
                    Side::Dst => write!(f, "{p} {port}"),
                    Side::Src => write!(f, "{p} src-port {port}"),
                }
            }
        }
    }
}

impl SteerRule {
    /// An IPv4 prefix rule — the pre-v6 shape, spelt as it always was.
    pub fn v4(
        prefix: Ipv4Addr,
        prefix_len: u8,
        side: Side,
        location: u32,
        action: RuleAction,
        dmac: Option<[u8; 6]>,
    ) -> Self {
        Self {
            shape: RuleMatch::V4 {
                prefix,
                prefix_len,
                side,
                dmac,
            },
            location,
            action,
        }
    }

    /// The destination MAC this rule is scoped to, whatever its shape.
    pub fn dmac(&self) -> Option<[u8; 6]> {
        match self.shape {
            RuleMatch::V4 { dmac, .. } => dmac,
            RuleMatch::V6Frame { dmac, .. } => Some(dmac),
            RuleMatch::V6L4(_) => None,
        }
    }

    /// Whether this is one of the IPv6 shapes.
    pub fn is_v6(&self) -> bool {
        !matches!(self.shape, RuleMatch::V4 { .. })
    }

    /// A v4 rule's side. Tests only — they assert on v4 plans, and a v6
    /// rule reaching one is itself the failure.
    #[cfg(test)]
    pub(crate) fn side(&self) -> Side {
        match self.shape {
            RuleMatch::V4 { side, .. } => side,
            other => panic!("not a v4 rule: {other:?}"),
        }
    }

    /// A v4 rule's prefix. Tests only, as [`Self::side`].
    #[cfg(test)]
    pub(crate) fn prefix(&self) -> (Ipv4Addr, u8) {
        match self.shape {
            RuleMatch::V4 {
                prefix, prefix_len, ..
            } => (prefix, prefix_len),
            other => panic!("not a v4 rule: {other:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Side {
    Src,
    Dst,
}

/// What a matching packet's fate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RuleAction {
    /// Redirect to VPP's VF — the steering rules proper.
    Divert,
    /// Deliver to the kernel (PF queue 0) — the exemptions, installed
    /// at HIGHER MCAM priority than any `Divert` rule so
    /// locally-terminating traffic never enters a dataplane that
    /// cannot deliver it.
    ///
    /// Why these exist, measured (w23, 2026-08-14): with `src`
    /// steering live, 110,917 packets in five minutes — the box's own
    /// service-monitoring replies, unicast DHCP renewals to the
    /// gateway, service-net→router management — matched the src rules
    /// and died at VPP's `null-node`, and 3,200 multicast frames
    /// (IGMP among them) were RPF-dropped instead of reaching the
    /// kernel bridge. The kernel is the only correct owner of that
    /// traffic; a `Keep` rule is how it stays there.
    ///
    /// `ring_cookie` 0 = the PF. HOW the PF receives it is
    /// [`crate::ntuple::KeepForm`]: spread over its queues by RSS on the
    /// default context, or — where the driver declines that — onto PF
    /// queue 0 (`otx2_add_flow_msg`: `NIX_RX_ACTIONOP_UCAST`). One queue
    /// was once an accepted cost, on the theory that this was
    /// control-plane volume; exemptions grew into NAT return paths, LAN
    /// subnets and IX LANs, and on 2026-10-07 queue 0's one CPU ran a
    /// production gateway's exempt traffic into the ground
    /// ([`crate::kernel_path`] has the incident).
    Keep,
}

/// The v6 keeps every port that diverts IPv6 carries regardless of
/// config, at higher priority than the diversion: DNS (TCP and UDP 53,
/// the router's resolver) and BGP (TCP 179, both port fields).
///
/// BGP both ways because the router is either end of a session: dst 179
/// is a peer's session to the router's listener, src 179 the replies on a
/// session the router opened. And a keep rather than the hand-back,
/// because eBGP to a directly connected peer is sent at hop limit 1 (or
/// 255 under GTSM, which the receiver requires arrive as 255): VPP
/// forwarding it to the kernel over [`crate::handback`] decrements the hop
/// limit, and the kernel then drops every segment of the session. BGP
/// must never enter VPP at all.
///
/// There is deliberately NO ICMPv6 keep, and none may ever be planned.
/// This NIC's key-extraction profile carries no IPv6 L3 fields, and the
/// driver accepts an `ip6 l4proto N` rule while ignoring the next-header
/// value: on hardware (2026-09-27), a drop-all-v6 divert beside an
/// `l4proto 58` keep let TCP through, so the "ICMPv6" keep matched every
/// v6 frame and would have disabled the diversion entirely. The readback
/// cannot catch it — the driver echoes the spec back. TCP/UDP PORT keeps
/// were proven port-specific the same day (a `tcp6 dst-port 80` keep left
/// TCP 443 blocked; `dst-port 443` let it through), so they stay.
///
/// What an ICMPv6 keep was for is done by the diversion's own shape
/// instead: it matches TCP and UDP only ([`V6_DIVERT_PROTOS`]), so no
/// ICMPv6 frame reaches the VF. That matters beyond the customers'
/// probes of their gateway: the NA a customer sends back to the KERNEL'S
/// neighbour solicitation is unicast to the router's MAC too, and a
/// diversion that took it would starve the kernel's neighbour table on
/// that VLAN — and with it every inbound v6 packet the kernel forwards
/// to those customers.
///
/// Matched on L4 alone, so they also keep DNS and BGP to EXTERNAL
/// destinations on the eBPF tier. That is intended: correct, and a small
/// slice. Anything else that opens a NEW session to the router on a
/// diverted VLAN or port (NTP 123, unicast DHCPv6 547, SSH …) is the
/// operator's `steer-keep6`: without it the packet reaches VPP, whose
/// hand-back guard admits toward the kernel only replies — TCP with ACK or
/// RST set, UDP from a DNS or NTP server ([`crate::handback`]) — the
/// w23 lesson in IPv6 form, refused on purpose rather than lost.
pub const BUILTIN_KEEPS6: [L4Match; 4] = [
    L4Match::Port {
        proto: L4Proto::Tcp,
        side: Side::Dst,
        port: 53,
    },
    L4Match::Port {
        proto: L4Proto::Udp,
        side: Side::Dst,
        port: 53,
    },
    L4Match::Port {
        proto: L4Proto::Tcp,
        side: Side::Dst,
        port: BGP_PORT,
    },
    L4Match::Port {
        proto: L4Proto::Tcp,
        side: Side::Src,
        port: BGP_PORT,
    },
];

/// BGP's TCP port, kept in both directions ([`BUILTIN_KEEPS6`]).
pub const BGP_PORT: u16 = 179;

/// How [`BUILTIN_KEEPS6`] reads in a refusal or a log line.
pub const BUILTIN_KEEPS6_DESCRIBED: &str = "TCP 53, UDP 53, TCP 179 dst, TCP 179 src";

/// The L4 protocols a v6 diversion takes, one rule each per
/// (VLAN × receive MAC). `tcp6`/`udp6` with no port: the otx2 driver
/// puts the parsed-L4-type term (`NPC_IPPROTO_TCP`/`_UDP`) on every rule
/// of those flow types, port or not — unlike `ip6 l4proto`, whose value
/// it drops. Everything else — ICMPv6, and any other next header —
/// stays on the kernel path. Proven with real frames (rig, 2026-09-27):
/// a port-less `tcp6 dst-mac <router>` drop blocked TCP while echo, DNS
/// and the kernel's own neighbour resolution (a deleted entry back to
/// REACHABLE) all passed; the `udp6` twin blocked DNS and left TCP and
/// echo alone.
pub const V6_DIVERT_PROTOS: [L4Proto; 2] = [L4Proto::Tcp, L4Proto::Udp];

/// The IPv6 half of one port's steering, from config.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct V6Steering {
    /// VLANs whose IPv6 is diverted (`port … v6-divert`):
    /// `Some(vid)` a tag match, `None` the untagged form. Empty = this
    /// port diverts no IPv6 and plans no v6 keeps either.
    pub vlans: Vec<Option<u16>>,
    /// `steer-keep6` matches, beside [`BUILTIN_KEEPS6`].
    pub keeps: Vec<L4Match>,
}

impl V6Steering {
    /// "vlan 100,200" / "untagged" — the phrase status and refusals use.
    pub fn describe_vlans(vlans: &[Option<u16>]) -> String {
        let tagged: Vec<String> = vlans.iter().flatten().map(u16::to_string).collect();
        let untagged = vlans.iter().any(Option::is_none);
        match (tagged.is_empty(), untagged) {
            (true, true) => "untagged".into(),
            (false, false) => format!("vlan {}", tagged.join(",")),
            (false, true) => format!("vlan {} + untagged", tagged.join(",")),
            (true, false) => "no VLAN".into(),
        }
    }
}

/// Exemptions every steered port carries regardless of config: IPv4
/// broadcast and multicast. Both are subnet-operational traffic the
/// kernel must see (DHCP DISCOVER answers, IGMP membership for the
/// bridge's snooping) and neither can ever be forwarded by VPP's
/// unicast FIB. Router-address exemptions are the operator's
/// (`steer-exempt`) because only the operator knows which addresses
/// terminate locally.
pub const BUILTIN_EXEMPTS: [(Ipv4Addr, u8); 2] = [
    (Ipv4Addr::new(255, 255, 255, 255), 32),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
];

/// What steering *should* look like for a port, derived from the
/// allowlist.
///
/// Separated from the ioctl so the policy — which prefixes, which
/// directions, how many slots, what gets skipped — is decided and
/// tested without a NIC. Every mistake that silently misroutes traffic
/// lives in here rather than in the syscall.
/// Serializable because the plan has to outlive the process that
/// installed it. A `Keep` rule carries `ring_cookie` 0, so nothing in
/// the cookie distinguishes it from a stranger's kernel-delivery rule —
/// the only thing that can is the spec it was installed under, compared
/// field by field. A teardown running in a *different* process (the
/// CLI's `detach --all`) has no such spec in memory, so it must read it
/// off the state file; see [`crate::resources::ResourceState::steer_plans`].
///
/// ## The on-disk form, and why it is split by family
///
/// Serialized through [`RuleSetRecord`], which keeps every v4 rule in
/// `rules` as EXACTLY the record the pre-v6 build wrote (flat `prefix`,
/// `prefix_len`, `side`, `location`, `action`, `dmac`) and puts the v6
/// shapes in a separate `rules_v6` list that is omitted when empty.
/// Both directions of a binary swap then read the file:
///
/// - **Upgrade** (this build adopting an older file): `rules` parses as
///   it always did and `rules_v6` defaults to empty. No version bump, so
///   no forced `detach --all` — a bump would make every steered box's
///   state file unadoptable on the restart that ships this, for a change
///   no v4 rule's meaning depends on.
/// - **Downgrade** (an older build reading a file this one wrote): the
///   older build ignores the unknown `rules_v6` and reads the v4 rules.
///   The v6 LOCATIONS are still in the ledger, so its teardown removes
///   the v6 diversions by their ring cookie; the v6 keeps (cookie 0, no
///   plan it can match) are disowned and left in the MCAM — delivering
///   to the kernel, where unmatched traffic goes anyway, but occupying
///   slots. The runbook's rollback drops `v6-divert` before a
///   downgrade for that reason. A single tagged list would instead make
///   the older build refuse the whole file, and with it both adoption
///   and `detach --all`, leaving the v6 diversions in the NIC with no
///   binary able to remove them.
///
/// Round-tripping yields every v4 rule, then every v6 rule, each in
/// original order — the order [`Self::plan`] produces, so a planned set
/// survives the file unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(from = "RuleSetRecord", into = "RuleSetRecord")]
pub struct RuleSet {
    pub rules: Vec<SteerRule>,
    /// v6 prefixes skipped because the NIC cannot match them. Reported
    /// rather than dropped: an operator whose allowlist is mostly v6
    /// should see that address-scoped steering covers none of it (a
    /// `v6-divert` diversion is by frame, not by allowlisted prefix).
    pub skipped_v6: u32,
}

/// [`RuleSet`] as the state file holds it. See the note there.
#[derive(serde::Serialize, serde::Deserialize)]
struct RuleSetRecord {
    rules: Vec<V4RuleRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    rules_v6: Vec<V6RuleRecord>,
    skipped_v6: u32,
}

/// The pre-v6 `SteerRule`, field for field.
#[derive(serde::Serialize, serde::Deserialize)]
struct V4RuleRecord {
    prefix: Ipv4Addr,
    prefix_len: u8,
    side: Side,
    location: u32,
    action: RuleAction,
    #[serde(default)]
    dmac: Option<[u8; 6]>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct V6RuleRecord {
    location: u32,
    action: RuleAction,
    shape: V6ShapeRecord,
}

#[derive(serde::Serialize, serde::Deserialize)]
enum V6ShapeRecord {
    Frame {
        dmac: [u8; 6],
        vlan: Option<u16>,
        /// Absent in a record of the whole-ethertype rule, which is
        /// exactly what `None` describes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        l4: Option<L4Proto>,
    },
    L4(L4Match),
}

impl From<RuleSetRecord> for RuleSet {
    fn from(r: RuleSetRecord) -> Self {
        let v4 = r
            .rules
            .into_iter()
            .map(|v| SteerRule::v4(v.prefix, v.prefix_len, v.side, v.location, v.action, v.dmac));
        let v6 = r.rules_v6.into_iter().map(|v| SteerRule {
            shape: match v.shape {
                V6ShapeRecord::Frame { dmac, vlan, l4 } => RuleMatch::V6Frame { dmac, vlan, l4 },
                V6ShapeRecord::L4(m) => RuleMatch::V6L4(m),
            },
            location: v.location,
            action: v.action,
        });
        RuleSet {
            rules: v4.chain(v6).collect(),
            skipped_v6: r.skipped_v6,
        }
    }
}

impl From<RuleSet> for RuleSetRecord {
    fn from(set: RuleSet) -> Self {
        let mut rules = Vec::new();
        let mut rules_v6 = Vec::new();
        for r in set.rules {
            match r.shape {
                RuleMatch::V4 {
                    prefix,
                    prefix_len,
                    side,
                    dmac,
                } => rules.push(V4RuleRecord {
                    prefix,
                    prefix_len,
                    side,
                    location: r.location,
                    action: r.action,
                    dmac,
                }),
                RuleMatch::V6Frame { dmac, vlan, l4 } => rules_v6.push(V6RuleRecord {
                    location: r.location,
                    action: r.action,
                    shape: V6ShapeRecord::Frame { dmac, vlan, l4 },
                }),
                RuleMatch::V6L4(m) => rules_v6.push(V6RuleRecord {
                    location: r.location,
                    action: r.action,
                    shape: V6ShapeRecord::L4(m),
                }),
            }
        }
        RuleSetRecord {
            rules,
            rules_v6,
            skipped_v6: set.skipped_v6,
        }
    }
}

/// Which MCAM slots a port may use, in the order they should be taken.
///
/// A budget rather than a constant because the NIC's table is shared —
/// UniFi's own rules live in it too — and overrunning it fails the
/// insert of whichever rule happens to be last, leaving a *partially*
/// steered port: some allowlisted traffic diverted to VPP, the rest on
/// the kernel path. That is not a degraded version of steering, it is a
/// different forwarding policy than either tier was configured for.
///
/// **A list of locations rather than a base and a count**, because the
/// previous shape could not express the two things that actually govern
/// it: which slots exist, and which are already taken. It carried
/// `base: 1024, count: 512`, reasoned from `npc/mcam_info` reporting
/// 2048 entries with 1689 available — figures that describe the NPC
/// block across all six PFs and have never governed an ethtool `loc`.
/// The real per-port space on this NIC is **0..=15**, so the first rule
/// the module ever tried to install was 1008 slots past the end and the
/// driver rejected it with `EINVAL`. See [`McamBudget::from_table`],
/// which asks the NIC instead of asserting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McamBudget {
    /// Locations this module may use, most-preferred first.
    pub free: Vec<u32>,
}

impl McamBudget {
    /// Take the free locations, highest first.
    ///
    /// Highest-first preserves the intent behind the old `base: 1024` —
    /// keep clear of whatever the vendor installs, without enumerating
    /// it, since the UniFi controller rewrites classifier state on every
    /// push. That reasoning was sound; only its arithmetic was wrong.
    /// Occupied slots are excluded outright rather than merely avoided,
    /// so a vendor rule appearing between `feasibility` and a steer
    /// costs a refusal instead of an overwrite.
    pub fn from_table(table: &crate::ntuple::RuleTable) -> Self {
        let free = (0..table.size)
            .rev()
            .filter(|loc| !table.occupied.contains(loc))
            .collect();
        Self { free }
    }

    /// The slots usable across *every* port that will steer.
    ///
    /// The intersection, not the first port's answer. One plan is
    /// installed on all of them at the same locations, so a slot free on
    /// eth4 and taken on eth5 is not a slot — and finding that out at
    /// insert time would leave a partially steered port, which is the
    /// one outcome [`RuleSet::plan`] exists to prevent.
    pub fn for_ifaces<'a>(ifaces: impl IntoIterator<Item = &'a str>) -> Result<Self, String> {
        Self::for_ifaces_with(ifaces, crate::ntuple::rule_table)
    }

    /// [`Self::for_ifaces`] over tables from `read` — the feasibility
    /// probe's seam, which plans against the table `steer-capacity`
    /// will ask for without writing anything.
    pub fn for_ifaces_with<'a>(
        ifaces: impl IntoIterator<Item = &'a str>,
        read: impl Fn(&str) -> Result<crate::ntuple::RuleTable, String>,
    ) -> Result<Self, String> {
        let mut budget: Option<Self> = None;
        for iface in ifaces {
            let next = Self::from_table(&read(iface)?);
            budget = Some(match budget {
                None => next,
                Some(prev) => Self {
                    free: prev
                        .free
                        .into_iter()
                        .filter(|loc| next.free.contains(loc))
                        .collect(),
                },
            });
        }
        // No steering ports means no NIC was asked and none will be
        // written; the caller is building a plan it will not install.
        Ok(budget.unwrap_or_default())
    }
}

impl Default for McamBudget {
    fn default() -> Self {
        // The measured size of an empty table on this NIC, used only
        // where there is no interface to ask — tests, and the non-Linux
        // stub. Every production path goes through `from_table`.
        Self {
            free: (0..crate::ntuple::FALLBACK_TABLE_SIZE).rev().collect(),
        }
    }
}

/// The sides a configured [`VppSteerDirection`] matches.
///
/// `both` is right for pure-transit deployments where VPP can forward
/// either direction of a flow. `src` is the service-edge staging
/// shape: outbound (src in the service prefix) rides VPP full-table
/// best path while inbound stays on the eBPF tier. `dst` steers
/// inbound, which is loadable only with `local-route` coverage of
/// steerable local prefixes — VPP must be able to DELIVER what a dst
/// rule diverts, and config validation refuses otherwise. Split-tier
/// flow halves are safe under the stateless-transit invariant
/// steering already requires.
pub fn sides_for(direction: VppSteerDirection) -> &'static [Side] {
    match direction {
        VppSteerDirection::Src => &[Side::Src],
        VppSteerDirection::Dst => &[Side::Dst],
        VppSteerDirection::Both => &[Side::Src, Side::Dst],
    }
}

/// How many prefixes in `allowlist` this NIC could steer at all.
///
/// v4 only: an address-bearing `ip6` rule is rejected by this NIC's AF, so a v6 prefix
/// consumes no slot and cannot be diverted. (A `v6-divert` diversion is
/// by frame, not by prefix, and is counted per port, not here.)
///
/// A named function because two callers need the answer and one of them
/// needs it *before* touching a NIC: whether there is anything to steer
/// is a property of the config, and settling it first is what keeps an
/// unsteerable allowlist from being reported as an ioctl failure.
pub fn steerable_count(allowlist: &[IpPrefix]) -> usize {
    allowlist
        .iter()
        .filter(|p| matches!(p, IpPrefix::V4 { .. }))
        .count()
}

impl RuleSet {
    /// Decide the rules for one port: one per v4 prefix per configured
    /// side (see [`sides_for`] for what each direction means and when
    /// it is right).
    ///
    /// Fails rather than truncates when the budget cannot hold them all:
    /// a partially steered port forwards some allowlisted traffic
    /// through VPP and the rest through the kernel, which is a policy
    /// nobody chose.
    /// `dmacs`: the port's receive MACs. Each divert rule is planned once
    /// per MAC (`None` when the slice is empty, which only planning
    /// without a port — a probe estimate, a test — does).
    pub fn plan(
        allowlist: &[IpPrefix],
        exempts: &[packetframe_common::config::Ipv4Prefix],
        budget: McamBudget,
        direction: VppSteerDirection,
        dmacs: &[[u8; 6]],
    ) -> Result<Self, String> {
        Self::plan_with_v6(
            allowlist,
            exempts,
            budget,
            direction,
            dmacs,
            &V6Steering::default(),
        )
    }

    /// [`Self::plan`], plus the port's IPv6 diversion and its
    /// keeps.
    ///
    /// The v6 diversions are one rule per (VLAN × receive MAC); the keeps
    /// are [`BUILTIN_KEEPS6`] plus `v6.keeps`, deduplicated, and exist
    /// only when some v6 diversion does — each family's exemptions guard
    /// that family's diversion and nothing else. A port with no v4 to
    /// steer can still divert v6, and the other way round.
    ///
    /// The whole port is refused, both families, when the total does not
    /// fit: the refusal is about a port half-steered, and a port whose v4
    /// landed while its v6 did not is exactly that.
    pub fn plan_with_v6(
        allowlist: &[IpPrefix],
        exempts: &[packetframe_common::config::Ipv4Prefix],
        budget: McamBudget,
        direction: VppSteerDirection,
        dmacs: &[[u8; 6]],
        v6: &V6Steering,
    ) -> Result<Self, String> {
        let dmac_slots: Vec<Option<[u8; 6]>> = if dmacs.is_empty() {
            vec![None]
        } else {
            dmacs.iter().copied().map(Some).collect()
        };
        let sides = sides_for(direction);
        // Partition first, then check capacity, then build. The order is
        // what makes the refusal's numbers true: counting as we go can
        // only ever report how far we got, which is the budget size — the
        // one number the operator already knows.
        let steerable: Vec<(Ipv4Addr, u8)> = allowlist
            .iter()
            .filter_map(|p| match p {
                IpPrefix::V4 { addr, prefix_len } => Some((Ipv4Addr::from(*addr), *prefix_len)),
                IpPrefix::V6 { .. } => None,
            })
            .collect();
        let skipped_v6 = (allowlist.len() - steerable.len()) as u32;
        // Nothing to divert means nothing to exempt FROM — an all-v6
        // allowlist plans no v4 rules at all rather than exemptions that
        // guard against a diversion that cannot happen. Per family: v4
        // keeps guard v4 diversions, v6 keeps guard v6 ones.
        let keeps: Vec<(Ipv4Addr, u8)> = if steerable.is_empty() {
            Vec::new()
        } else {
            BUILTIN_EXEMPTS
                .iter()
                .copied()
                .chain(exempts.iter().map(|p| (p.addr, p.prefix_len)))
                .collect()
        };
        // A v6 diversion without a MAC scope would take frames the kernel
        // is only bridging, and there is no v6 address match to fall back
        // on. Planning without a port (`dmacs` empty) can estimate v4
        // only; production planning always has the port's MACs.
        if !v6.vlans.is_empty() && dmacs.is_empty() {
            return Err(
                "an IPv6 diversion needs the port's receive MAC(s), and none were \
                 given; without that scope it would divert frames the kernel is only \
                 bridging"
                    .into(),
            );
        }
        // Two rules per (VLAN × MAC), TCP and UDP: the protocol term is
        // what keeps ICMPv6 — neighbour discovery above all — off the VF.
        let v6_diverts: Vec<(Option<u16>, [u8; 6], L4Proto)> = v6
            .vlans
            .iter()
            .flat_map(|vlan| {
                dmacs
                    .iter()
                    .flat_map(move |mac| V6_DIVERT_PROTOS.iter().map(move |p| (*vlan, *mac, *p)))
            })
            .collect();
        let mut keeps6: Vec<L4Match> = Vec::new();
        if !v6_diverts.is_empty() {
            for k in BUILTIN_KEEPS6.iter().chain(&v6.keeps) {
                if !keeps6.contains(k) {
                    keeps6.push(*k);
                }
            }
        }
        let operator_keeps6 = keeps6.len().saturating_sub(BUILTIN_KEEPS6.len());

        let diverts = steerable.len() * sides.len() * dmac_slots.len();
        let needed = diverts + keeps.len() + v6_diverts.len() + keeps6.len();

        if needed > budget.free.len() {
            let mut parts = Vec::new();
            if !steerable.is_empty() {
                parts.push(format!(
                    "{} steerable prefix(es) × {} direction(s), `steer-direction {direction}`, \
                     × {} receive MAC(s), plus {} kernel exemption(s): 2 built-in [broadcast, \
                     multicast] + {} `steer-exempt`",
                    steerable.len(),
                    sides.len(),
                    dmac_slots.len(),
                    keeps.len(),
                    exempts.len(),
                ));
            }
            if !v6_diverts.is_empty() {
                parts.push(format!(
                    "{} IPv6 diversion(s) ({} × {} receive MAC(s) × [TCP, UDP]), plus {} \
                     IPv6 keep(s): {} built-in [{BUILTIN_KEEPS6_DESCRIBED}] + {operator_keeps6} \
                     `steer-keep6`",
                    v6_diverts.len(),
                    V6Steering::describe_vlans(&v6.vlans),
                    dmacs.len(),
                    keeps6.len(),
                    BUILTIN_KEEPS6.len(),
                ));
            }
            return Err(format!(
                "steering needs {needed} MCAM rule(s) ({}) but only {} slot(s) are free on \
                 this NIC; steering part of the allowlist would split it across both \
                 forwarding tiers, so none is installed. `steer-capacity` raises the \
                 per-port table from its default of 16",
                parts.join("; "),
                budget.free.len()
            ));
        }

        // Slot assignment carries the PRIORITY, so it is not free-form:
        // lower loc = lower MCAM entry index = matched first (v5.15
        // otx2_flows.c keeps flow_ent[] ascending and indexes it by
        // location). Divert rules take the budget's front (highest
        // locs, clear of vendor rules, as ever); Keep rules take the
        // BACK — the lowest free locs — so every exemption outranks
        // every diversion by construction, v6 keeps over the v6
        // diversion included. A `free` list sorted highest-first makes
        // front ≥ back unconditionally, and `needed` fitting the budget
        // keeps the two ends from meeting.
        //
        // Emitted v4 first, then v6 — the order a round trip through the
        // state file preserves (see the serde note on this type).
        let mut rules = Vec::with_capacity(needed);
        let mut front = 0usize;
        let mut back = 0usize;
        let mut take_front = || {
            let loc = budget.free[front];
            front += 1;
            loc
        };
        let mut v4_diverts = Vec::with_capacity(diverts);
        for (addr, prefix_len) in steerable {
            for side in sides.iter().copied() {
                for dmac in &dmac_slots {
                    v4_diverts.push(SteerRule::v4(
                        addr,
                        prefix_len,
                        side,
                        take_front(),
                        RuleAction::Divert,
                        *dmac,
                    ));
                }
            }
        }
        let v6_divert_rules: Vec<SteerRule> = v6_diverts
            .into_iter()
            .map(|(vlan, dmac, l4)| SteerRule {
                shape: RuleMatch::V6Frame {
                    dmac,
                    vlan,
                    l4: Some(l4),
                },
                location: take_front(),
                action: RuleAction::Divert,
            })
            .collect();
        let mut take_back = || {
            let loc = budget.free[budget.free.len() - 1 - back];
            back += 1;
            loc
        };
        rules.extend(v4_diverts);
        for (addr, prefix_len) in keeps {
            rules.push(SteerRule::v4(
                addr,
                prefix_len,
                Side::Dst,
                take_back(),
                RuleAction::Keep,
                None,
            ));
        }
        rules.extend(v6_divert_rules);
        for k in keeps6 {
            rules.push(SteerRule {
                shape: RuleMatch::V6L4(k),
                location: take_back(),
                action: RuleAction::Keep,
            });
        }
        Ok(RuleSet { rules, skipped_v6 })
    }

    /// The VLANs this set diverts IPv6 on, in plan order and
    /// once each — what the status row names.
    pub fn v6_divert_vlans(&self) -> Vec<Option<u16>> {
        let mut out = Vec::new();
        for r in &self.rules {
            if let (RuleMatch::V6Frame { vlan, .. }, RuleAction::Divert) = (r.shape, r.action) {
                if !out.contains(&vlan) {
                    out.push(vlan);
                }
            }
        }
        out
    }

    /// The slots this set occupies, for the state file — teardown must
    /// remove exactly what was installed and nothing else.
    pub fn locations(&self) -> Vec<u32> {
        self.rules.iter().map(|r| r.location).collect()
    }
}

/// Whether reconciling a port set from `installed` to `target` diverts
/// traffic onto VPP that `installed` does not: a `Divert` match on a port
/// that no installed `Divert` on that port covers ([`RuleMatch::covers`])
/// — a new port, a new or wider prefix, a new direction, a new receive
/// MAC, a new `v6-divert` frame.
///
/// Every one of those is new traffic routed by VPP's whole FIB: a
/// diversion selects flows by source or by frame, and VPP then looks up
/// each one's destination, so a newly diverted flow meets every route VPP
/// lacks however small the allowlist change that diverted it.
///
/// So is a `Keep` REMOVED or narrowed on a port that goes on diverting —
/// one no target `Keep` there covers: keeps sit at higher MCAM priority
/// and take their matches back to the kernel, so dropping a
/// `steer-exempt` or a `steer-keep6` from a steered port puts that
/// traffic onto VPP as surely as a new diversion would (review finding,
/// PR #333). On a port the target no longer diverts at all, its keeps go
/// with its diversions, which is a removal.
///
/// What does NOT add is removal (a port, prefix or direction dropped), a
/// diversion narrowed inside an installed one, a `Keep` added or widened
/// (that takes traffic back to the kernel), and a rule moved to another
/// slot or another VF index — slots are the planner's, and the VF is VPP
/// either way.
pub fn adds_diversion(
    target: &[(String, u32, RuleSet)],
    installed: &[(String, u32, RuleSet)],
) -> bool {
    let rules_on = |plans: &[(String, u32, RuleSet)], port: &str, action: RuleAction| {
        plans
            .iter()
            .filter(|(p, _, _)| p == port)
            .flat_map(|(_, _, set)| set.rules.iter())
            .filter(|r| r.action == action)
            .map(|r| r.shape)
            .collect::<Vec<RuleMatch>>()
    };
    // By COVERAGE, not equal shapes: a /16 replacing an installed /8 it
    // sits inside diverts nothing the /8 did not, and judged as new it was
    // held — leaving the broader /8 diverting, indefinitely under a
    // mismatch (review finding, PR #333). One rule must cover another
    // whole; a match covered only by several together counts as new.
    let new_divert = target.iter().any(|(port, _, _)| {
        let have = rules_on(installed, port, RuleAction::Divert);
        rules_on(target, port, RuleAction::Divert)
            .iter()
            .any(|shape| !have.iter().any(|h| h.covers(shape)))
    });
    let lost_keep = installed.iter().any(|(port, _, _)| {
        let still_diverting = !rules_on(target, port, RuleAction::Divert).is_empty();
        let keeps = rules_on(target, port, RuleAction::Keep);
        still_diverting
            && rules_on(installed, port, RuleAction::Keep)
                .iter()
                .any(|shape| !keeps.iter().any(|k| k.covers(shape)))
    });
    new_divert || lost_keep
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpPrefix {
        IpPrefix::V4 {
            addr: [a, b, c, d],
            prefix_len: len,
        }
    }

    /// What a reconcile adds, as the first-steer hold judges it: a port,
    /// a prefix or a direction diverted that was not — never a removal, an
    /// exemption added, or the same rules on other slots.
    #[test]
    fn only_new_diversions_count_as_added() {
        let mac = [0x02, 0, 0, 0, 0, 1];
        let plan = |allow: &[IpPrefix], exempt: &[packetframe_common::config::Ipv4Prefix], dir| {
            RuleSet::plan(allow, exempt, McamBudget::default(), dir, &[mac]).expect("fits")
        };
        let a = v4(192, 0, 2, 0, 24);
        let b = v4(198, 51, 100, 0, 24);
        let src = VppSteerDirection::Src;
        let one = |port: &str, set: RuleSet| vec![(port.to_string(), 0u32, set)];
        let installed = one("eth4", plan(&[a], &[], src));

        assert!(!adds_diversion(&installed, &installed), "unchanged");
        assert!(!adds_diversion(&[], &[]), "nothing at all");
        // A second port: the canary ladder's next rung.
        let mut two = installed.clone();
        two.push(("eth5".into(), 0, plan(&[a], &[], src)));
        assert!(adds_diversion(&two, &installed));
        // A prefix, and a direction, on the port already steered.
        assert!(adds_diversion(
            &one("eth4", plan(&[a, b], &[], src)),
            &installed
        ));
        assert!(adds_diversion(
            &one("eth4", plan(&[a], &[], VppSteerDirection::Both)),
            &installed
        ));
        // Removals and exemptions take traffic OFF VPP.
        assert!(!adds_diversion(
            &one("eth4", plan(&[], &[], src)),
            &installed
        ));
        assert!(!adds_diversion(&installed, &two), "a port dropped");
        let exempt = [packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(192, 0, 2, 1),
            prefix_len: 32,
        }];
        let exempted = one("eth4", plan(&[a], &exempt, src));
        assert!(!adds_diversion(&exempted, &installed));
        // ...and dropping that exemption from a port still diverting puts
        // its traffic back onto VPP: an addition. Dropping the port with
        // it is a removal.
        assert!(
            adds_diversion(&installed, &exempted),
            "an exemption removed"
        );
        assert!(!adds_diversion(&[], &exempted), "the whole port removed");
        // The same diversion on another slot is not a new one.
        let mut moved = installed.clone();
        for r in &mut moved[0].2.rules {
            r.location += 100;
        }
        assert!(!adds_diversion(&moved, &installed));
    }

    /// Additions by COVERAGE, not equal shapes (review finding, PR #333):
    /// a diversion narrowed inside an installed one adds nothing and a
    /// broadened one does; a keep narrowed gives traffic back to VPP and
    /// a broadened one does not.
    #[test]
    fn coverage_decides_what_a_reconcile_adds() {
        let mac = [0x02, 0, 0, 0, 0, 1];
        let src = VppSteerDirection::Src;
        let plan = |allow: &[IpPrefix], exempt: &[packetframe_common::config::Ipv4Prefix]| {
            vec![(
                "eth4".to_string(),
                0u32,
                RuleSet::plan(allow, exempt, McamBudget::default(), src, &[mac]).expect("fits"),
            )]
        };
        let wide = plan(&[v4(198, 51, 100, 0, 24)], &[]);
        let narrow = plan(&[v4(198, 51, 100, 0, 25)], &[]);
        assert!(!adds_diversion(&narrow, &wide), "a diversion narrowed");
        assert!(adds_diversion(&wide, &narrow), "a diversion broadened");
        let beside = plan(&[v4(198, 51, 100, 128, 25)], &[]);
        assert!(adds_diversion(&beside, &narrow), "a disjoint one");

        let exempt = |a: u8, len: u8| packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(198, 51, 100, a),
            prefix_len: len,
        };
        let keep_wide = plan(&[v4(198, 51, 100, 0, 24)], &[exempt(0, 28)]);
        let keep_narrow = plan(&[v4(198, 51, 100, 0, 24)], &[exempt(1, 32)]);
        assert!(
            adds_diversion(&keep_narrow, &keep_wide),
            "a keep narrowed hands the rest of its traffic to VPP"
        );
        assert!(
            !adds_diversion(&keep_wide, &keep_narrow),
            "a keep broadened takes traffic off VPP"
        );

        // A plan recorded before diversions carried a receive MAC covers
        // the same diversion with one; not the other way round.
        let mut unscoped = wide.clone();
        for r in &mut unscoped[0].2.rules {
            if let RuleMatch::V4 { dmac, .. } = &mut r.shape {
                *dmac = None;
            }
        }
        assert!(!adds_diversion(&wide, &unscoped));
        assert!(adds_diversion(&unscoped, &wide));
    }

    /// The containment rule itself, both ways, for every shape.
    #[test]
    fn a_match_covers_only_what_it_provably_contains() {
        let v4m = |a: [u8; 4], len: u8, side: Side, dmac: Option<[u8; 6]>| RuleMatch::V4 {
            prefix: Ipv4Addr::from(a),
            prefix_len: len,
            side,
            dmac,
        };
        let m = Some([0x02, 0, 0, 0, 0, 1]);
        let wide = v4m([198, 51, 100, 0], 24, Side::Src, m);
        let narrow = v4m([198, 51, 100, 64], 26, Side::Src, m);
        assert!(wide.covers(&narrow) && wide.covers(&wide));
        assert!(!narrow.covers(&wide));
        assert!(
            !wide.covers(&v4m([198, 51, 100, 64], 26, Side::Dst, m)),
            "side"
        );
        assert!(
            !wide.covers(&v4m([192, 0, 2, 0], 26, Side::Src, m)),
            "elsewhere"
        );
        assert!(
            !wide.covers(&v4m([198, 51, 100, 64], 26, Side::Src, None)),
            "dmac"
        );
        assert!(
            v4m([0, 0, 0, 0], 0, Side::Src, None).covers(&narrow),
            "default"
        );

        let frame = |vlan: Option<u16>, l4: Option<L4Proto>| RuleMatch::V6Frame {
            dmac: [0x02, 0, 0, 0, 0, 1],
            vlan,
            l4,
        };
        assert!(frame(None, None).covers(&frame(Some(100), Some(L4Proto::Tcp))));
        assert!(frame(Some(100), None).covers(&frame(Some(100), Some(L4Proto::Udp))));
        assert!(!frame(Some(100), None).covers(&frame(Some(200), None)));
        assert!(!frame(Some(100), Some(L4Proto::Tcp)).covers(&frame(Some(100), None)));
        assert!(!frame(None, None).covers(&RuleMatch::V6Frame {
            dmac: [0x02, 0, 0, 0, 0, 2],
            vlan: None,
            l4: None,
        }));

        let keep = |port: u16| {
            RuleMatch::V6L4(L4Match::Port {
                proto: L4Proto::Tcp,
                side: Side::Dst,
                port,
            })
        };
        assert!(keep(179).covers(&keep(179)) && !keep(179).covers(&keep(22)));
        assert!(!frame(None, None).covers(&keep(179)), "kinds never cover");
        assert!(!wide.covers(&frame(None, None)));
    }

    /// Both directions, in slot order, with v6 counted rather than
    /// silently dropped.
    /// Each divert rule is planned once per receive MAC, each copy
    /// scoped to its MAC; exemptions are planned once and unscoped, since
    /// delivering to the kernel is right for bridged frames too. The
    /// extra copies count against the budget.
    #[test]
    fn divert_rules_are_scoped_to_each_receive_mac() {
        let (m1, m2) = ([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2]);
        let allow = vec![v4(192, 0, 2, 0, 24)];
        let exempt = [packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(192, 0, 2, 1),
            prefix_len: 32,
        }];
        let set = RuleSet::plan(
            &allow,
            &exempt,
            McamBudget::default(),
            VppSteerDirection::Both,
            &[m1, m2],
        )
        .expect("fits");
        let diverts: Vec<&SteerRule> = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Divert)
            .collect();
        assert_eq!(diverts.len(), 4, "2 sides x 2 MACs");
        for side in [Side::Src, Side::Dst] {
            let mut macs: Vec<[u8; 6]> = diverts
                .iter()
                .filter(|r| r.side() == side)
                .filter_map(|r| r.dmac())
                .collect();
            macs.sort_unstable();
            assert_eq!(macs, vec![m1, m2], "{side:?}");
        }
        assert!(set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Keep)
            .all(|r| r.dmac().is_none()));
        let mut locs = set.locations();
        locs.sort_unstable();
        locs.dedup();
        assert_eq!(locs.len(), set.rules.len(), "every copy has its own slot");

        // 5 free slots: 2 sides x 2 MACs + 3 exemptions = 7 does not fit.
        let tight = McamBudget {
            free: (0..5).rev().collect(),
        };
        let e = RuleSet::plan(&allow, &exempt, tight, VppSteerDirection::Both, &[m1, m2])
            .expect_err("the copies count");
        assert!(e.contains("2 receive MAC(s)"), "{e}");
    }

    #[test]
    fn a_plan_covers_both_directions_and_reports_skipped_v6() {
        let allow = vec![
            v4(192, 0, 2, 0, 24),
            IpPrefix::V6 {
                addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                prefix_len: 48,
            },
            v4(198, 51, 100, 0, 24),
        ];
        let set = RuleSet::plan(
            &allow,
            &[],
            McamBudget::default(),
            VppSteerDirection::Both,
            &[],
        )
        .expect("fits");

        assert_eq!(set.skipped_v6, 1, "the v6 prefix is reported, not hidden");
        assert_eq!(
            set.rules.len(),
            6,
            "two v4 prefixes x both directions, plus the two built-in exemptions"
        );
        assert_eq!(
            set.rules.iter().filter(|r| r.side() == Side::Src).count(),
            2,
            "one source rule per v4 prefix"
        );
        let diverts: Vec<u32> = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Divert)
            .map(|r| r.location)
            .collect();
        let keeps: Vec<u32> = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Keep)
            .map(|r| r.location)
            .collect();
        assert_eq!(
            diverts,
            vec![15, 14, 13, 12],
            "diversions take the highest free slots, clear of vendor rules, as ever"
        );
        assert_eq!(
            keeps,
            vec![0, 1],
            "exemptions take the LOWEST free slots — lower loc is higher MCAM priority, so \
             every exemption outranks every diversion"
        );
    }

    /// The two invariants the exemptions exist for: they outrank every
    /// diversion (lower slot = higher priority on this NIC), and the
    /// operator's `steer-exempt` entries ride alongside the built-ins.
    #[test]
    fn exemptions_outrank_diversions_and_include_the_operators() {
        use packetframe_common::config::Ipv4Prefix;
        let allow = vec![v4(192, 0, 2, 0, 24)];
        let exempts = vec![Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(192, 0, 2, 1),
            prefix_len: 32,
        }];
        let set = RuleSet::plan(
            &allow,
            &exempts,
            McamBudget::default(),
            VppSteerDirection::Src,
            &[],
        )
        .expect("fits");
        let max_keep = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Keep)
            .map(|r| r.location)
            .max()
            .expect("keeps exist");
        let min_divert = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Divert)
            .map(|r| r.location)
            .min()
            .expect("diverts exist");
        assert!(
            max_keep < min_divert,
            "every exemption must outrank every diversion: keep max {max_keep} vs divert \
             min {min_divert}"
        );
        // Built-ins + the operator's router address, all Keep, all Dst.
        let keep_prefixes: Vec<(std::net::Ipv4Addr, u8)> = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Keep)
            .map(|r| {
                assert_eq!(r.side(), Side::Dst, "an exemption matches destinations");
                r.prefix()
            })
            .collect();
        assert!(keep_prefixes.contains(&(std::net::Ipv4Addr::new(255, 255, 255, 255), 32)));
        assert!(keep_prefixes.contains(&(std::net::Ipv4Addr::new(224, 0, 0, 0), 4)));
        assert!(
            keep_prefixes.contains(&(std::net::Ipv4Addr::new(192, 0, 2, 1), 32)),
            "the operator's gateway exemption is the one that rescues DHCP renews and \
             monitoring replies (w23: 110,917 blackholed in five minutes without it)"
        );
    }

    /// An allowlist that does not fit installs NOTHING, and says how
    /// many rules it actually needed.
    ///
    /// The failure mode the refusal prevents is worse than no steering: a
    /// partially steered port forwards some allowlisted traffic through
    /// VPP and the rest through the kernel, a policy neither tier was
    /// configured for and which no counter names.
    ///
    /// The *number* is asserted because it is the number an operator
    /// sizes the budget from. Counting rules as they are built can only
    /// report how far the loop got — which is the budget size, the one
    /// figure they already have — so this asserts the true requirement
    /// and, explicitly, that the old understated figure is gone.
    #[test]
    fn an_allowlist_that_exceeds_the_budget_is_refused_whole() {
        let allow: Vec<IpPrefix> = (0..4).map(|i| v4(10, i, 0, 0, 16)).collect();
        let budget = McamBudget {
            free: (0..5).rev().collect(),
        };
        let e = RuleSet::plan(&allow, &[], budget, VppSteerDirection::Both, &[])
            .expect_err("must refuse");

        assert!(
            e.contains("needs 10 MCAM rule(s)"),
            "must name the TRUE requirement — diversions AND exemptions: {e}"
        );
        assert!(
            e.contains("2 built-in"),
            "the built-in exemptions are part of the arithmetic the operator sizes from: {e}"
        );
        assert!(
            e.contains("none is installed"),
            "the message must say the port is left unsteered: {e}"
        );

        // Enough slots and the same allowlist fits, so the refusal is
        // about the budget and not about the allowlist's shape.
        let ok = RuleSet::plan(
            &allow,
            &[],
            McamBudget {
                free: (0..10).rev().collect(),
            },
            VppSteerDirection::Both,
            &[],
        )
        .expect("fits exactly");
        assert_eq!(ok.rules.len(), 10);
    }

    /// The refusal counts STEERABLE prefixes, not every line in the
    /// allowlist.
    ///
    /// A v6 prefix consumes no slot, so including it in the count would
    /// overstate the shortfall and send an operator looking for a budget
    /// increase they do not need — the inverse of the understatement
    /// above, and equally a number they would act on.
    #[test]
    fn the_refusal_does_not_count_prefixes_that_consume_no_slots() {
        let allow = vec![
            v4(10, 0, 0, 0, 16),
            v4(10, 1, 0, 0, 16),
            IpPrefix::V6 {
                addr: [0x26, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                prefix_len: 32,
            },
        ];
        let e = RuleSet::plan(
            &allow,
            &[],
            McamBudget {
                free: (0..3).rev().collect(),
            },
            VppSteerDirection::Both,
            &[],
        )
        .expect_err("must refuse");
        assert!(
            e.contains("needs 6 MCAM rule(s)") && e.contains("2 steerable prefix(es)"),
            "the v6 prefix is not steerable and must not inflate either number: {e}"
        );
    }

    /// `steer-direction src` builds exactly one rule per prefix, all
    /// Src-side, at half the budget cost of `both` — the service-edge
    /// shape, where inbound stays on the eBPF tier because VPP has no
    /// path to the bridge-attached hosts it terminates on.
    #[test]
    fn src_only_builds_one_rule_per_prefix() {
        let allow = vec![v4(10, 0, 0, 0, 16), v4(10, 1, 0, 0, 16)];
        let set = RuleSet::plan(
            &allow,
            &[],
            McamBudget::default(),
            VppSteerDirection::Src,
            &[],
        )
        .expect("fits");
        assert_eq!(
            set.rules.len(),
            4,
            "2 src diverts + 2 built-in keeps: {:?}",
            set.rules
        );
        assert!(
            set.rules
                .iter()
                .filter(|r| r.action == RuleAction::Divert)
                .all(|r| r.side() == Side::Src),
            "src-only must never DIVERT on a Dst match: {:?}",
            set.rules
        );

        let dst = RuleSet::plan(
            &allow,
            &[],
            McamBudget::default(),
            VppSteerDirection::Dst,
            &[],
        )
        .expect("fits");
        assert!(
            dst.rules
                .iter()
                .filter(|r| r.action == RuleAction::Divert)
                .all(|r| r.side() == Side::Dst),
            "{:?}",
            dst.rules
        );

        // Half the divert rules means more prefixes fit: a budget that
        // refuses 2 prefixes under `both` takes them under `src`.
        let tight = McamBudget {
            free: (0..4).rev().collect(),
        };
        RuleSet::plan(&allow, &[], tight.clone(), VppSteerDirection::Both, &[])
            .expect_err("four diverts + two keeps cannot fit four slots");
        let fits =
            RuleSet::plan(&allow, &[], tight, VppSteerDirection::Src, &[]).expect("fits src-only");
        assert_eq!(fits.rules.len(), 4);
    }

    /// The refusal names the configured direction, so an operator
    /// reading it knows which multiplier produced the number.
    #[test]
    fn the_refusal_names_the_direction() {
        let allow = vec![v4(10, 0, 0, 0, 16), v4(10, 1, 0, 0, 16)];
        let e = RuleSet::plan(
            &allow,
            &[],
            McamBudget { free: vec![15] },
            VppSteerDirection::Src,
            &[],
        )
        .expect_err("must refuse");
        assert!(
            e.contains("1 direction(s)") && e.contains("steer-direction src"),
            "{e}"
        );
    }

    const M1: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const M2: [u8; 6] = [0x02, 0, 0, 0, 0, 2];

    fn ntp() -> L4Match {
        L4Match::Port {
            proto: L4Proto::Udp,
            side: Side::Dst,
            port: 123,
        }
    }

    fn v6_on(vlans: &[u16], keeps: &[L4Match]) -> V6Steering {
        V6Steering {
            vlans: vlans.iter().copied().map(Some).collect(),
            keeps: keeps.to_vec(),
        }
    }

    /// No planned IPv6 rule can match ICMPv6. No keep is a protocol match
    /// — this NIC's driver ignores the next-header value of an `ip6
    /// l4proto` rule, so one would match every v6 frame, sit above the
    /// diversion and switch it off without the readback noticing
    /// (hardware, 2026-09-27) — and every diversion names TCP or UDP, so
    /// the NA a customer returns to the kernel's neighbour solicitation
    /// stays on the kernel path.
    #[test]
    fn no_planned_v6_rule_can_match_icmpv6() {
        assert!(BUILTIN_KEEPS6
            .iter()
            .all(|k| matches!(k, L4Match::Port { .. })));
        let set = RuleSet::plan_with_v6(
            &[],
            &[],
            McamBudget {
                free: (0..64).rev().collect(),
            },
            VppSteerDirection::Both,
            &[M1],
            &v6_on(&[100], &[]),
        )
        .expect("fits");
        assert!(set
            .rules
            .iter()
            .all(|r| !matches!(r.shape, RuleMatch::V6L4(L4Match::Proto(_)))));
        let diverts: Vec<Option<L4Proto>> = set
            .rules
            .iter()
            .filter_map(|r| match r.shape {
                RuleMatch::V6Frame { l4, .. } => Some(l4),
                _ => None,
            })
            .collect();
        assert_eq!(diverts, vec![Some(L4Proto::Tcp), Some(L4Proto::Udp)]);
    }

    /// Every port that diverts IPv6 keeps BGP on the kernel in both port
    /// fields, whatever the operator wrote: eBGP to a directly connected
    /// peer arrives at hop limit 1, and the hop VPP's hand-back costs would
    /// drop every segment. Both sit below every diversion, like any keep.
    #[test]
    fn bgp_is_kept_both_ways_on_every_v6_diverting_port() {
        let set = RuleSet::plan_with_v6(
            &[],
            &[],
            McamBudget::default(),
            VppSteerDirection::Src,
            &[M1],
            &v6_on(&[100], &[]),
        )
        .expect("fits");
        let bgp = |side| L4Match::Port {
            proto: L4Proto::Tcp,
            side,
            port: BGP_PORT,
        };
        let min_divert = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Divert)
            .map(|r| r.location)
            .min()
            .unwrap();
        for side in [Side::Dst, Side::Src] {
            let keep = set
                .rules
                .iter()
                .find(|r| r.shape == RuleMatch::V6L4(bgp(side)))
                .unwrap_or_else(|| panic!("no BGP {side:?} keep: {:?}", set.rules));
            assert_eq!(keep.action, RuleAction::Keep);
            assert!(
                keep.location < min_divert,
                "{side:?} outranks the diversion"
            );
        }
        assert_eq!(
            BUILTIN_KEEPS6.len(),
            BUILTIN_KEEPS6_DESCRIBED.split(", ").count(),
            "the refusal names every built-in"
        );
    }

    /// The v6 diversion is two rules per (VLAN × receive MAC), TCP and
    /// UDP, each scoped to both; the v6 keeps are the built-ins plus the
    /// operator's; and EVERY keep — v4 and v6 — sits below every
    /// diversion, so DNS to the router is delivered to the kernel before
    /// the v6 diversion can see it.
    #[test]
    fn v6_keeps_outrank_every_diversion_on_the_port() {
        let set = RuleSet::plan_with_v6(
            &[v4(192, 0, 2, 0, 24)],
            &[],
            McamBudget {
                free: (0..32).rev().collect(),
            },
            VppSteerDirection::Src,
            &[M1, M2],
            &v6_on(&[100, 200], &[ntp()]),
        )
        .expect("fits: 2 + 2 v4, 8 + 5 v6");
        let frames: Vec<(Option<u16>, [u8; 6], Option<L4Proto>)> = set
            .rules
            .iter()
            .filter_map(|r| match (r.shape, r.action) {
                (RuleMatch::V6Frame { dmac, vlan, l4 }, RuleAction::Divert) => {
                    Some((vlan, dmac, l4))
                }
                _ => None,
            })
            .collect();
        let (t, u) = (Some(L4Proto::Tcp), Some(L4Proto::Udp));
        assert_eq!(
            frames,
            vec![
                (Some(100), M1, t),
                (Some(100), M1, u),
                (Some(100), M2, t),
                (Some(100), M2, u),
                (Some(200), M1, t),
                (Some(200), M1, u),
                (Some(200), M2, t),
                (Some(200), M2, u),
            ]
        );
        let keeps6: Vec<L4Match> = set
            .rules
            .iter()
            .filter_map(|r| match (r.shape, r.action) {
                (RuleMatch::V6L4(m), RuleAction::Keep) => Some(m),
                _ => None,
            })
            .collect();
        let mut want = BUILTIN_KEEPS6.to_vec();
        want.push(ntp());
        assert_eq!(keeps6, want);
        assert!(
            set.rules
                .iter()
                .all(|r| !matches!(r.shape, RuleMatch::V6Frame { .. })
                    || r.action == RuleAction::Divert),
            "a frame match is only ever a diversion"
        );

        let max_keep = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Keep)
            .map(|r| r.location)
            .max()
            .unwrap();
        let min_divert = set
            .rules
            .iter()
            .filter(|r| r.action == RuleAction::Divert)
            .map(|r| r.location)
            .min()
            .unwrap();
        assert!(
            max_keep < min_divert,
            "keep max {max_keep} vs divert min {min_divert}"
        );
        let mut locs = set.locations();
        locs.sort_unstable();
        locs.dedup();
        assert_eq!(locs.len(), set.rules.len(), "every rule has its own slot");
        assert_eq!(set.rules.len(), 2 + 2 + 8 + 5);
        assert_eq!(set.v6_divert_vlans(), vec![Some(100), Some(200)]);
        // v4 first, then v6 — the order the state file round trip keeps.
        let first_v6 = set.rules.iter().position(|r| r.is_v6()).unwrap();
        assert!(set.rules[first_v6..].iter().all(|r| r.is_v6()));
    }

    /// The refusal's arithmetic includes the v6 rules, term by term, so
    /// the operator can see which multiplier produced the number.
    #[test]
    fn the_refusal_counts_the_v6_rules() {
        let e = RuleSet::plan_with_v6(
            &[v4(192, 0, 2, 0, 24)],
            &[],
            McamBudget {
                free: (0..15).rev().collect(),
            },
            VppSteerDirection::Src,
            &[M1, M2],
            &v6_on(&[100, 200], &[]),
        )
        .expect_err("2 + 2 + 8 + 4 = 16 cannot fit 15");
        assert!(e.contains("needs 16 MCAM rule(s)"), "{e}");
        assert!(
            e.contains("8 IPv6 diversion(s) (vlan 100,200 × 2 receive MAC(s) × [TCP, UDP])"),
            "{e}"
        );
        assert!(
            e.contains("4 IPv6 keep(s): 4 built-in [TCP 53, UDP 53, TCP 179 dst, TCP 179 src]"),
            "{e}"
        );
        assert!(e.contains("0 `steer-keep6`"), "{e}");
        assert!(e.contains("none is installed"), "{e}");

        // v6 alone: the v4 clause is absent rather than a row of zeros.
        let e = RuleSet::plan_with_v6(
            &[],
            &[],
            McamBudget {
                free: (0..6).rev().collect(),
            },
            VppSteerDirection::Src,
            &[M1],
            &v6_on(&[100], &[ntp()]),
        )
        .expect_err("2 + 5 cannot fit 6");
        assert!(e.contains("needs 7 MCAM rule(s)"), "{e}");
        assert!(e.contains("1 `steer-keep6`"), "{e}");
        assert!(!e.contains("steerable prefix"), "{e}");
    }

    /// Each family's keeps guard that family's diversion and nothing
    /// else: a port diverting only v6 plans no v4 exemptions, a port
    /// diverting only v4 plans no v6 keeps — however many `steer-keep6`
    /// lines exist — and a built-in the operator restated costs no second
    /// slot.
    #[test]
    fn each_familys_keeps_exist_only_with_its_diversion() {
        let v6_only = RuleSet::plan_with_v6(
            &[IpPrefix::V6 {
                addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                prefix_len: 48,
            }],
            &[],
            McamBudget::default(),
            VppSteerDirection::Both,
            &[M1],
            &v6_on(
                &[100],
                &[L4Match::Port {
                    proto: L4Proto::Tcp,
                    side: Side::Dst,
                    port: 53,
                }],
            ),
        )
        .expect("fits");
        assert!(
            v6_only.rules.iter().all(SteerRule::is_v6),
            "{:?}",
            v6_only.rules
        );
        assert_eq!(
            v6_only.rules.len(),
            2 + 4,
            "the restated TCP 53 is not a 5th keep"
        );
        assert_eq!(
            v6_only.skipped_v6, 1,
            "the v6 PREFIX is still not address-steerable"
        );

        let v4_only = RuleSet::plan_with_v6(
            &[v4(192, 0, 2, 0, 24)],
            &[],
            McamBudget::default(),
            VppSteerDirection::Src,
            &[M1],
            &V6Steering {
                vlans: Vec::new(),
                keeps: vec![ntp()],
            },
        )
        .expect("fits");
        assert!(
            !v4_only.rules.iter().any(SteerRule::is_v6),
            "{:?}",
            v4_only.rules
        );
    }

    /// A v6 diversion with no MAC to scope it to is refused: there is no
    /// v6 address match to narrow it instead, so it would take bridged
    /// frames.
    #[test]
    fn a_v6_diversion_without_receive_macs_is_refused() {
        let e = RuleSet::plan_with_v6(
            &[v4(192, 0, 2, 0, 24)],
            &[],
            McamBudget::default(),
            VppSteerDirection::Src,
            &[],
            &v6_on(&[100], &[]),
        )
        .expect_err("must refuse");
        assert!(e.contains("receive MAC"), "{e}");
    }

    /// A planned set survives the state file's JSON unchanged — v4 rules
    /// in the pre-v6 record, v6 in `rules_v6` — which is what lets a
    /// teardown in another process match its v6 keeps.
    #[test]
    fn a_planned_set_round_trips_through_json() {
        let set = RuleSet::plan_with_v6(
            &[v4(192, 0, 2, 0, 24)],
            &[],
            McamBudget::default(),
            VppSteerDirection::Both,
            &[M1],
            &V6Steering {
                vlans: vec![None],
                keeps: vec![ntp()],
            },
        )
        .expect("fits");
        let json = serde_json::to_value(&set).unwrap();
        assert_eq!(json["rules"].as_array().unwrap().len(), 2 + 2);
        assert_eq!(json["rules_v6"].as_array().unwrap().len(), 2 + 5);
        let back: RuleSet = serde_json::from_value(json).unwrap();
        assert_eq!(back, set);
        // A record of the whole-ethertype diversion — written by the build
        // before diversions named a protocol — reads back as exactly that.
        let old: RuleSet = serde_json::from_value(serde_json::json!({
            "rules": [],
            "rules_v6": [{
                "location": 9,
                "action": "Divert",
                "shape": {"Frame": {"dmac": M1, "vlan": 100}},
            }],
            "skipped_v6": 0,
        }))
        .unwrap();
        assert_eq!(
            old.rules[0].shape,
            RuleMatch::V6Frame {
                dmac: M1,
                vlan: Some(100),
                l4: None
            }
        );
        // A v4-only set writes no `rules_v6` at all: byte-identical to
        // what the previous build wrote.
        let v4 = RuleSet::plan(
            &[v4(192, 0, 2, 0, 24)],
            &[],
            McamBudget::default(),
            VppSteerDirection::Both,
            &[M1],
        )
        .unwrap();
        assert!(serde_json::to_value(&v4).unwrap().get("rules_v6").is_none());
    }

    /// An allowlist with no v4 in it produces no rules and says why.
    #[test]
    fn a_v6_only_allowlist_produces_nothing_to_steer() {
        let allow = vec![IpPrefix::V6 {
            addr: [0x26, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 32,
        }];
        let set = RuleSet::plan(
            &allow,
            &[],
            McamBudget::default(),
            VppSteerDirection::Both,
            &[],
        )
        .expect("no rules is not an error");
        assert!(
            set.rules.is_empty(),
            "nothing to divert means nothing to exempt from — no keeps either: {:?}",
            set.rules
        );
        assert_eq!(
            set.skipped_v6, 1,
            "the operator has to be able to see that steering covers none of their allowlist"
        );
    }
}
