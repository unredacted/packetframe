//! The exemption tripwire: kernel paths VPP cannot take, unexempted.
//!
//! VPP owns member VFs and the dot1q subinterfaces on them, and
//! nothing else. Any destination the kernel forwards through some
//! OTHER device — an IPSec VTI, WireGuard, a GRE tunnel — has no path
//! in VPP: the mirror route resolves to no member and never installs,
//! so a steered packet for it dies at VPP's default route instead of
//! falling back to the kernel that would have delivered it.
//!
//! The eBPF tier PASSes those flows to the kernel, which is why they
//! work unsteered; steering removes that safety net, and VPP cannot
//! do IPSec, so the kernel path is their permanent, correct home. One
//! `steer-exempt` per such destination keeps them there.
//!
//! Found the hard way on the reference primary (w26, 2026-08-16):
//! inter-site IPSec carried a remote /24 plus seven host routes INSIDE
//! the local service /24, and every steered window for three weeks had
//! been silently one-way-blackholing them — invisible to every
//! watchdog, visible only as a steady rate on a drop counter nobody
//! had decomposed.
//!
//! ## Why a tripwire and not automatic exemption
//!
//! Deriving MCAM rules from kernel state would change forwarding
//! without an operator asking, and could exhaust a 16-slot budget
//! silently. The route sets that produce this are also frequently
//! dynamic — bird announces a new remote host route and the hole
//! re-opens — which is exactly the argument for CONTINUOUS detection
//! rather than a one-time audit. So this names what is uncovered and
//! degrades health; installing the rule stays the operator's decision.
//!
//! ## IPv6
//!
//! A v6 diversion ([`crate::steer::RuleMatch::V6Frame`]) matches by
//! FRAME — TCP or UDP over IPv6 to a router receive MAC on a listed VLAN
//! — never by address, so once one exists ANY v6 destination can reach
//! VPP, and a kernel-only v6 route VPP lacks (an overlay's ULA via its
//! tunnel device, a static route out an interface VPP does not own) is
//! silently black-holed there. So the scan walks the kernel's IPv6 routes
//! too, but only while that can happen: VPP carries the family AND some
//! port line carries `v6-divert` ([`DriftScope::scans_v6`]). Same
//! judgement ([`reach_clears`]), with four differences, each forced by
//! the v6 steering shape ([`uncovered_paths_v6`]):
//!
//! - nothing exempts. There is no v6 address rule to install (the NIC
//!   cannot match one), so `steer-exempt` does not apply and the remedy
//!   is the feed, a `steer-keep6`, or dropping `v6-divert`. A finding
//!   the operator has examined and decided to live with can instead be
//!   ACCEPTED (`drift-accept6`, [`DriftAccepts6`]): still listed, counted
//!   on its own gauge, degrading nothing — an acknowledgement, not a
//!   remedy, so there is no v4 form;
//! - a kernel route whose owned-device hops are link-local is judged by
//!   what VPP HOLDS, not by its hops: zebra installs the `fe80::` hop
//!   while the feed also carries a global one VPP installs through, and
//!   VPP refuses only routes whose every feed next hop is link-local
//!   (the engine's `link_local_refused`). Only prefixes VPP holds no
//!   route for are reported, as one summary line ([`V6Scan::settle`]);
//! - a bridge is v6 reach by `local-route6`, not `local-route`. Each
//!   delivers its own family's subnet ([`crate::LocalRoutePrefix`]), so a
//!   bridge with only a v4 `local-route` gets no v6 route from VPP, and
//!   one with a `local-route6` does ([`VppReach::local_devices_v6`]);
//! - link-local and multicast destinations, and the router's own
//!   addresses, are not paths at all.

use packetframe_common::config::{Ipv4Prefix, Ipv6Prefix};

/// A route destination either family's scan can name: what sorting and
/// the operator-facing line need, and nothing else.
pub trait RoutePrefix: Copy + Eq + std::fmt::Debug {
    /// Whether this family has a `steer-exempt` to offer as a remedy.
    const EXEMPTABLE: bool;
    /// `(length, address)`: least specific first, then by address.
    fn sort_key(&self) -> (u8, u128);
    /// `addr/len`, as `ip route` prints it.
    fn cidr(&self) -> String;
}

impl RoutePrefix for Ipv4Prefix {
    const EXEMPTABLE: bool = true;
    fn sort_key(&self) -> (u8, u128) {
        (self.prefix_len, u128::from(u32::from(self.addr)))
    }
    fn cidr(&self) -> String {
        format!("{}/{}", self.addr, self.prefix_len)
    }
}

impl RoutePrefix for Ipv6Prefix {
    // The NIC cannot match a v6 address, so no v6 exemption exists.
    const EXEMPTABLE: bool = false;
    fn sort_key(&self) -> (u8, u128) {
        (self.prefix_len, u128::from(self.addr))
    }
    fn cidr(&self) -> String {
        format!("{}/{}", self.addr, self.prefix_len)
    }
}

/// One kernel route, reduced to what the comparison needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRoute<P = Ipv4Prefix> {
    /// Destination prefix. A default route is `0.0.0.0/0` (`::/0`).
    pub prefix: P,
    /// Output device name(s). More than one for a multipath route —
    /// ECMP encodes its nexthops in `RTA_MULTIPATH` rather than
    /// `RTA_OIF`, and a route read as having no device at all would
    /// be skipped silently (review finding). Empty means the kernel
    /// named no interface, which this check has nothing to say about.
    pub oifs: Vec<String>,
    /// Routing table id, for the operator-facing message: "table 100"
    /// is how they will find it again.
    pub table: u32,
    /// Whether the kernel would DROP this itself (blackhole,
    /// unreachable, prohibit). VPP dropping the same packet is
    /// equivalent behaviour, so these are not findings.
    pub drops: bool,
    /// The kernel DELIVERS this itself rather than forwarding over a
    /// path — `RTN_LOCAL` (its own addresses), `RTN_BROADCAST` (the
    /// segment's directed broadcast, `.255` on a service bridge) and
    /// `RTN_ANYCAST`. The `oif` names the interface that owns the
    /// address or segment, which is not an egress VPP could take, so
    /// device reachability says nothing about these and must not be
    /// consulted — the local class this scan exists to cover was
    /// being skipped precisely because those addresses sit on member
    /// ports and bridges, and directed broadcast was being skipped
    /// the same way one round later (both review findings). VPP has
    /// no local delivery and cannot reproduce a broadcast, so
    /// steered traffic to any of them dies unless exempted.
    pub kernel_delivers: bool,
    /// Per entry of `oifs`: whether that hop forwards via a GATEWAY
    /// (`RTA_GATEWAY`, or `RTA_VIA` for a cross-family next hop) rather
    /// than onto a connected segment. The distinction decides
    /// bridge-VLAN coverage: VPP reaches a gateway on a bridge VLAN by
    /// per-neighbour placement, but has no route at all for the
    /// connected subnet itself unless a `local-route` delivers it — so
    /// a connected hop out a bridged device stays a finding. Per hop,
    /// not per route: an ECMP route mixing a connected bridge hop with
    /// a gatewayed one elsewhere must not lend the bridge hop the other
    /// hop's gateway (review finding).
    pub gatewayed: Vec<bool>,
    /// Per entry of `oifs`: whether that hop's gateway is IPv6
    /// link-local (`fe80::/10`). Such a hop cannot clear the route by its
    /// device: VPP never installs through one (the feed does not carry
    /// the interface that scopes it), so whether VPP has the prefix is a
    /// question for VPP's table, not the kernel's ([`uncovered_paths_v6`]).
    /// Always false on an IPv4 route, whose gateways cannot be.
    pub link_local: Vec<bool>,
    /// The route names a NEXTHOP OBJECT (`ip route ... nhid N`,
    /// `RTA_NH_ID`) instead of carrying its devices inline. Those
    /// routes are opaque here: the vendored netlink crate does not
    /// parse the attribute, and resolving it means a second
    /// `RTM_GETNEXTHOP` dump this module does not have. Left as a
    /// device-less route it would be SKIPPED — a tunnel-backed nhid
    /// route blackholing under a clean scan (review finding) — so it
    /// is counted and reported as a gap in the scan's own coverage
    /// rather than silently dropped or guessed at.
    pub via_nexthop_object: bool,
    /// The route carries a LIGHTWEIGHT ENCAPSULATION action —
    /// `ip route ... encap mpls|seg6|ip|xfrm ... dev eth3` — named
    /// here by its kernel type for the operator-facing message.
    ///
    /// This one is nastier than a tunnel device, because the `oif` is
    /// an ORDINARY device: a member port, usually. Read for
    /// reachability alone the route looks perfectly coverable, so the
    /// scan would call it clean while the mirror — which encodes
    /// prefix, nexthop and interface, and has nowhere to put a label
    /// stack or a segment list — forwarded the packet bare out the
    /// same port. Bare is not a slower path, it is a different
    /// destination (review finding). The encapsulation is a property
    /// of the PATH, so a multipath hop carrying one counts too.
    pub encap: Option<String>,
}

/// What VPP can actually egress, from config: member ports and the
/// kernel bridge devices `local-route` and `local-route6` deliver into.
#[derive(Debug, Clone, Default)]
pub struct VppReach {
    /// `port` lines — VPP owns a VF on each.
    pub members: Vec<String>,
    /// Bridge devices named (indirectly) by `local-route`: VPP
    /// delivers those prefixes on a subif, so a kernel route out the
    /// bridge is covered.
    pub local_devices: Vec<String>,
    /// The same for `local-route6`: the bridges VPP delivers a v6
    /// subnet into. IPv6 reach only ([`Self::for_v6`]); the v4 scan never
    /// reads it.
    pub local_devices_v6: Vec<String>,
    /// VLAN and bridge devices VPP reaches through a member's subif
    /// ([`crate::topology::reachable_devices`]): an IX LAN bridge, say,
    /// whose next hops VPP places per neighbour. A route VIA A GATEWAY
    /// out one is a path VPP can take; the device's connected subnet is
    /// not, unless it is also a `local_devices` entry.
    pub bridged_devices: Vec<String>,
}

impl VppReach {
    fn covers_device(&self, dev: &str, gatewayed: bool) -> bool {
        self.members.iter().any(|m| m == dev)
            || self.local_devices.iter().any(|d| d == dev)
            || (gatewayed && self.bridged_devices.iter().any(|d| d == dev))
    }

    /// The reach IPv6 has: the same members and bridged devices, with the
    /// `local-route6` bridges in place of the `local-route` ones. Each
    /// names its own family's prefix, so VPP delivers a `local-route`
    /// bridge's v4 subnet and no v6 one — counting it as v6 reach would
    /// clear exactly the connected v6 subnet VPP has no route for — and a
    /// `local-route6` bridge's v6 subnet, which is covered on the same
    /// per-device terms a `local-route` bridge is for v4. Idempotent: the
    /// dump and [`classify_v6`] each apply it.
    fn for_v6(&self) -> Self {
        Self {
            local_devices: self.local_devices_v6.clone(),
            ..self.clone()
        }
    }
}

/// The scope a scan judges under — everything a reconfigure can change
/// about it, travelling together because freezing any one of them at
/// attach re-opens the hole (the recurring review finding this type's
/// fields each cost once).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriftScope {
    /// The current `steer-exempt` set.
    pub exempts: Vec<Ipv4Prefix>,
    /// [`divertible_scope`]'s answer.
    pub dst_only: Option<Vec<packetframe_common::fib::IpPrefix>>,
    /// Whether the IPv6 half runs: VPP carries IPv6 AND some port line
    /// carries `v6-divert`.
    ///
    /// From CONFIG, not the `steer` lever, for the reason the v4 scan is
    /// installed before any port steers: the hole opens the instant the
    /// lever moves, and the operator wants it named before then. A
    /// `v6-divert` on a `steer off` port is the staged form of exactly
    /// that; dropping `v6-divert` is what switches the half off.
    pub scans_v6: bool,
}

impl DriftScope {
    /// The ONE derivation of a scope from config, run at attach and on
    /// every accepted reconfigure.
    pub fn from_config(
        cfg: &crate::VppOffloadConfig,
        allowlist: &[packetframe_common::fib::IpPrefix],
    ) -> Self {
        Self {
            exempts: cfg.steer_exempts.clone(),
            dst_only: divertible_scope(&cfg.ports, cfg.steer_direction, allowlist),
            scans_v6: cfg.v6 && !cfg.v6_divert.is_empty(),
        }
    }
}

/// Which destinations steering can actually divert into VPP.
///
/// `Any` — some port matches on SOURCE, so a steered host's packet
/// reaches VPP whatever it is addressed to, and every kernel path is
/// at risk. `OnlyDst(prefixes)` — every steering port matches on
/// destination, so only packets addressed inside the allowlist are
/// diverted at all, and demanding an MCAM slot for a path no packet
/// can reach would spend a scarce resource on nothing (review
/// finding).
#[derive(Debug, Clone)]
pub enum Divertible<'a> {
    Any,
    OnlyDst(&'a [packetframe_common::fib::IpPrefix]),
}

impl Scope<'_> {
    /// Is every DIVERTIBLE packet for this route already exempted?
    ///
    /// Under `Any`, that is every address in the route, so the
    /// exemption must contain the whole prefix. Under `OnlyDst` only
    /// the route's intersection with the allowlist can be diverted at
    /// all — an allowlisted `/32` inside a tunnel-backed `/24` puts
    /// exactly one host at risk — so a `/32` exemption covering that
    /// host covers the risk, and demanding one for the whole `/24`
    /// would send the operator to install a broader rule than the
    /// hazard warrants (review finding).
    ///
    /// Cover is tested against single exemptions, never their union: a
    /// pair of `/25`s covering a `/24` between them still reports. That
    /// under-approximates coverage, which over-reports, which is the
    /// direction this scan is allowed to be wrong in.
    fn covers(&self, route: &Ipv4Prefix) -> bool {
        let covered = |p: &Ipv4Prefix| self.exempts.iter().any(|e| e.contains_prefix(p));
        match &self.divertible {
            Divertible::Any => covered(route),
            Divertible::OnlyDst(allow) => allow
                .iter()
                .filter_map(|a| {
                    let packetframe_common::fib::IpPrefix::V4 { addr, prefix_len } = a else {
                        return None;
                    };
                    let a = Ipv4Prefix {
                        addr: std::net::Ipv4Addr::from(*addr),
                        prefix_len: *prefix_len,
                    };
                    // Two CIDRs that overlap are nested, so the
                    // intersection is whichever is more specific.
                    if a.contains_prefix(route) {
                        Some(*route)
                    } else if route.contains_prefix(&a) {
                        Some(a)
                    } else {
                        None
                    }
                })
                .all(|intersection| covered(&intersection)),
        }
    }
}

impl Divertible<'_> {
    /// Can a packet for `prefix` be diverted into VPP at all?
    ///
    /// OVERLAP, not containment: a dst rule for one address inside a
    /// route's prefix is enough to send traffic for that route into
    /// VPP, so the route is at risk even though the allowlist does
    /// not cover all of it.
    fn reaches(&self, prefix: &Ipv4Prefix) -> bool {
        match self {
            Self::Any => true,
            Self::OnlyDst(allow) => allow.iter().any(|a| {
                let packetframe_common::fib::IpPrefix::V4 { addr, prefix_len } = a else {
                    return false;
                };
                let a = Ipv4Prefix {
                    addr: std::net::Ipv4Addr::from(*addr),
                    prefix_len: *prefix_len,
                };
                a.contains_prefix(prefix) || prefix.contains_prefix(&a)
            }),
        }
    }
}

/// Derive the diversion scope from config — the ONE place it is
/// computed, called at attach and again on every accepted
/// reconfigure.
///
/// A function rather than a value each caller builds, because the
/// inputs are hot: the allowlist and both direction knobs are rebuilt
/// on reconfigure, and a scope captured at attach goes stale the
/// moment either changes — a dst-only deployment that adds an
/// allow-prefix, or flips a port to `src`, starts diverting traffic
/// the frozen scope tells the scan to ignore (review finding, and the
/// same freeze the exemption set had one field over).
///
/// `None` = every destination is at risk: some port matches on
/// source, or nothing steers yet, or the config declares no ports.
/// The conservative answer is the default in all three.
pub fn divertible_scope(
    ports: &[crate::PortLine],
    global: packetframe_common::config::VppSteerDirection,
    allowlist: &[packetframe_common::fib::IpPrefix],
) -> Option<Vec<packetframe_common::fib::IpPrefix>> {
    use packetframe_common::config::VppSteerDirection;
    if ports.is_empty() {
        return None;
    }
    ports
        .iter()
        .all(|(_, _, _, _, dir)| dir.unwrap_or(global) == VppSteerDirection::Dst)
        .then(|| allowlist.to_vec())
}

/// Everything the comparison judges against, bundled so the parameter
/// list stops growing by one per question asked.
pub struct Scope<'a> {
    pub reach: &'a VppReach,
    pub exempts: &'a [Ipv4Prefix],
    pub divertible: Divertible<'a>,
    /// Tables some policy rule can select. `None` = the rule set could
    /// not be read, so nothing is filtered.
    ///
    /// This models table SELECTION only, never the finer predicates —
    /// fwmark, iif, from/to — deliberately. "A table no rule names
    /// cannot be consulted by any packet" is unconditionally true, so
    /// filtering on it cannot hide a real path; evaluating the rest
    /// would mean reimplementing the kernel's rule walk, where a
    /// permissive mistake re-opens exactly the hole this scan closes.
    /// Over-reporting is the safe direction, and this takes only the
    /// share of it that is provably noise (an unreferenced VRF or
    /// auxiliary table — review finding).
    pub selected_tables: Option<&'a [u32]>,
}

/// A kernel path VPP cannot take that nothing exempts — or, for
/// [`Uncovered::Opaque`] and [`Uncovered::LinkLocal`], a count of routes
/// summarised on one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Uncovered<P = Ipv4Prefix> {
    Path {
        prefix: P,
        oif: String,
        table: u32,
        /// Kernel-owned delivery (an address or a broadcast) rather
        /// than a forwarding path — the message says so, because the
        /// remedy reads differently.
        kernel_delivers: bool,
        /// The lightweight-encapsulation type this path applies, when
        /// it applies one. Present means the finding is about what
        /// the kernel puts ON the packet, not where it sends it, so
        /// the message must not read "via a device VPP does not own"
        /// — VPP very likely owns it, which is the trap.
        encap: Option<String>,
    },
    /// Routes using nexthop objects, whose devices this scan cannot
    /// see. Reported so the operator knows the coverage is partial
    /// rather than believing a quiet scan means a clean box.
    Opaque(usize),
    /// IPv6 only: kernel routes whose owned-device hops are link-local,
    /// for prefixes VPP holds no route for ([`V6Scan::settle`]). One line
    /// for all of them, like
    /// [`Self::Opaque`] and for the same reason — a box whose BGP
    /// sessions run over link-local can hold a great many, and a finding
    /// per route would bury every other line. `examples` names the first
    /// few, `prefix via dev (table n)`, so there is something to look up.
    LinkLocal {
        routes: usize,
        examples: Vec<String>,
    },
}

impl<P> Uncovered<P> {
    /// How many kernel routes this finding stands for — one, except
    /// for the summaries, which stand for as many as they counted.
    pub fn routes(&self) -> usize {
        match self {
            Self::Path { .. } => 1,
            Self::Opaque(n) => *n,
            Self::LinkLocal { routes, .. } => *routes,
        }
    }

    /// The table this finding sits in, for tests and log context.
    /// `None` for the summaries, which name no single route.
    pub fn table(&self) -> Option<u32> {
        match self {
            Self::Path { table, .. } => Some(*table),
            Self::Opaque(_) | Self::LinkLocal { .. } => None,
        }
    }
}

impl<P: RoutePrefix> std::fmt::Display for Uncovered<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Encapsulation first: it is true of a path whatever the
            // route type, and its remedy is the one an operator would
            // never reach from a reachability message.
            Self::Path {
                prefix,
                oif,
                table,
                encap: Some(kind),
                ..
            } => write!(
                f,
                "{} via {oif} (table {table}) applies {kind} encapsulation — VPP's mirror \
                 carries no encap action, so steered packets would leave {oif} bare",
                prefix.cidr()
            ),
            Self::Path {
                prefix,
                oif,
                table,
                kernel_delivers: true,
                ..
            } => write!(
                f,
                "{} is delivered by the kernel on {oif} (table {table}) — an address or \
                 broadcast VPP cannot reproduce",
                prefix.cidr()
            ),
            Self::Path {
                prefix,
                oif,
                table,
                kernel_delivers: false,
                ..
            } => write!(f, "{} via {oif} (table {table})", prefix.cidr()),
            Self::Opaque(n) => write!(
                f,
                "{n} route(s) use nexthop objects (`ip route ... nhid`) whose devices this \
                 scan cannot read, so it cannot tell whether VPP can take them — inspect \
                 with `ip nexthop show` and {}",
                // IPv6 has no exemption to add; the row names its remedies.
                if P::EXEMPTABLE {
                    "exempt any that leave via a tunnel"
                } else {
                    "treat any that leave via a tunnel as a finding"
                }
            ),
            Self::LinkLocal { routes, examples } => write!(
                f,
                "{routes} route(s) leave the kernel only through link-local next hops and \
                 VPP holds no route for the prefix ({}{}) — the feed gave VPP only link-local \
                 next hops, which it refuses (their interface is not carried), or never \
                 carried the prefix at all",
                examples.join(", "),
                if *routes > examples.len() {
                    ", …"
                } else {
                    ""
                }
            ),
        }
    }
}

/// The pure half: which kernel routes would blackhole under steering.
///
/// A route is a finding iff steering can divert traffic for it, the
/// kernel does not drop it itself, VPP has no way to deliver it, and
/// no `steer-exempt` covers its prefix.
///
/// "No way to deliver it" is two different questions:
///
/// - a FORWARDED route is unreachable when none of its nexthop
///   devices is a member port or a `local-route` bridge. Multipath
///   counts as reachable if ANY path is, because VPP installs the
///   paths it can resolve and forwards over those;
/// - a LOCAL route is an address the kernel terminates. VPP has no
///   local delivery at all, so device reachability is irrelevant and
///   asking it is the bug this arm exists to fix — the w23 blackhole
///   was traffic to a gateway address sitting on a bridge that this
///   scan would otherwise have called covered.
///
/// Coverage is by prefix containment, and an exempt must contain the
/// route — not merely overlap it. A `/32` exemption does not cover the
/// `/24` around it, and reporting the `/24` as handled because one
/// host inside it is exempted would be the silent-hole shape all over
/// again.
pub fn uncovered_paths(routes: &[KernelRoute], scope: &Scope<'_>) -> Vec<Uncovered> {
    let reach = scope.reach;
    let mut out = Vec::new();
    // Routes whose devices this scan cannot see at all. Counted
    // across the whole dump and reported once, because the answer is
    // "this scan does not cover N of your routes", not N separate
    // hazards — and flooding a finding per route would make an
    // nhid-using box's tripwire unreadable, which is how an alarm
    // stops being read.
    let mut opaque = 0usize;
    for r in routes {
        if !scope.divertible.reaches(&r.prefix) {
            continue;
        }
        // A table no policy rule names is inert for every packet.
        // BEFORE the opaque branch below, not after: an nhid route
        // parked in an unreferenced VRF is no more reachable than a
        // readable one, and counting it would send the operator to
        // inspect nexthops for traffic that cannot exist (review
        // finding — this filter, bypassed by a branch added two
        // rounds after it).
        if scope.selected_tables.is_some_and(|t| !t.contains(&r.table)) {
            continue;
        }
        // Drops, device-less routes and paths VPP can take: the one
        // judgement the dump also makes, so the two cannot drift.
        if r.cleared_by(reach) {
            continue;
        }
        if r.via_nexthop_object && r.oifs.is_empty() {
            if !scope.covers(&r.prefix) {
                opaque += 1;
            }
            continue;
        }
        let Some(oif) = r.oifs.first() else { continue };
        // Built-in exemptions cover these on every steered port.
        if crate::steer::BUILTIN_EXEMPTS.iter().any(|(addr, len)| {
            Ipv4Prefix {
                addr: *addr,
                prefix_len: *len,
            }
            .contains_prefix(&r.prefix)
        }) {
            continue;
        }
        if scope.covers(&r.prefix) {
            continue;
        }
        out.push(Uncovered::Path {
            prefix: r.prefix,
            oif: oif.clone(),
            table: r.table,
            kernel_delivers: r.kernel_delivers,
            encap: r.encap.clone(),
        });
    }
    sort_paths(&mut out);
    if opaque > 0 {
        out.push(Uncovered::Opaque(opaque));
    }
    out
}

/// Path findings in a stable order, duplicates dropped. Only paths are
/// in the list at this point; the summaries are appended after.
fn sort_paths<P: RoutePrefix>(out: &mut Vec<Uncovered<P>>) {
    out.sort_by_key(|u| match u {
        Uncovered::Path { prefix, .. } => prefix.sort_key(),
        Uncovered::Opaque(_) | Uncovered::LinkLocal { .. } => (u8::MAX, u128::MAX),
    });
    out.dedup();
}

/// How many example routes a [`Uncovered::LinkLocal`] summary names.
const LINK_LOCAL_EXAMPLES: usize = 3;

/// [`uncovered_paths`] for the kernel's IPv6 routes, while some port
/// diverts IPv6 ([`DriftScope::scans_v6`]).
///
/// The same judgement — [`reach_clears`], so the two families cannot
/// disagree about what VPP can take — with no [`Scope`], because both of
/// its halves are v4 shapes: a v6 diversion matches by frame, so every
/// destination is divertible, and no v6 exemption exists to cover one.
/// Tables are filtered by the v6 policy rules (`ip -6 rule`), which are
/// their own set.
///
/// Skipped, because they are not paths a diverted packet takes:
///
/// - **link-local destinations** (`fe80::/10`). A router never forwards
///   them (RFC 4291 §2.5.6); the per-interface `fe80::/64` routes say
///   which link an address is on, not where to send transit.
/// - **multicast destinations** (`ff00::/8`). A multicast packet travels
///   in a `33:33:…` frame, and every diversion names a router UNICAST
///   receive MAC, so none can match it.
/// - **the router's own addresses** (`RTN_LOCAL`, and `RTN_ANYCAST` — the
///   subnet-router anycast; v6 has no broadcast). Where the v4 scan
///   reports these on `local-route` bridges, remedy `steer-exempt`, v6
///   has no address rule to offer: what reaches the router over a
///   diverted VLAN stays on the kernel by PORT (the built-in DNS keeps,
///   `steer-keep6`), a match this scan cannot relate to a route. A
///   finding with no remedy it can name is one operators learn to
///   ignore; router-bound v6 is a local-delivery question, answered
///   where diverted traffic to the router is handed back, not a kernel
///   path VPP lacks.
///
/// Judged against VPP, not the kernel: a route VPP could take but for
/// its kernel next hops being link-local ([`LinkLocalRoute`]). Those hops
/// say nothing about VPP's copy. Under FRR, an eBGP peer that sends both
/// a global and a link-local next hop gets its KERNEL route installed via
/// the `fe80::` hop, while the feed carries the global one too and the
/// engine installs the prefix in VPP through that alone — it refuses only
/// a route whose EVERY feed next hop is link-local (`link_local_refused`).
/// So such a route is a finding only when VPP holds no route for the
/// prefix ([`V6Scan::settle`]): refused as link-local-only, or never in
/// the feed at all (an RA-learned default, say). Diverted traffic for
/// that prefix takes whatever less specific route VPP holds, or dies at
/// its default, which is the black hole this scan exists for; judging
/// by the kernel's hops alone would instead report nearly every v6 route
/// of a link-local BGP mesh, permanently. What remains is summarised
/// ([`Uncovered::LinkLocal`]): counted per route (the gauge), one line
/// (the health surface). A link-local hop out a device VPP does not own
/// is an ordinary path finding instead: the device is the problem there.
///
/// `vpp_holds` answers "does VPP hold a route for exactly this prefix" —
/// [`crate::engine::ConvergenceEngine::holds_v6`] in production.
pub fn uncovered_paths_v6(
    routes: &[KernelRoute<Ipv6Prefix>],
    reach: &VppReach,
    selected_tables: Option<&[u32]>,
    vpp_holds: impl Fn(&Ipv6Prefix) -> bool,
) -> Vec<Uncovered<Ipv6Prefix>> {
    classify_v6(routes, Vec::new(), reach, selected_tables).settle(vpp_holds)
}

/// A kernel v6 route VPP could take but for its link-local next hops —
/// a finding only if VPP holds no route for the prefix. Kept this small
/// because a link-local BGP mesh makes nearly every v6 route one of
/// these, and the dump builds them instead of a full [`KernelRoute`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLocalRoute {
    pub prefix: Ipv6Prefix,
    pub table: u32,
    /// The first owned device a link-local hop leaves by, for the example
    /// line — shared per device.
    pub oif: std::sync::Arc<str>,
    /// The first hop out a device VPP does not own, when the route mixes
    /// one in (an ECMP group of a link-local member hop and a tunnel hop).
    /// If VPP lacks the prefix, THAT hop is the finding and names the
    /// device — the link-local summary would name the wrong interface.
    pub unowned: Option<std::sync::Arc<str>>,
}

/// Where a link-local candidate's hops point, by position: the first
/// link-local hop on an owned device, and the first hop out a device VPP
/// does not own, if any. Every other hop of a candidate is one of these
/// two kinds — a covered global hop would have cleared it.
fn candidate_hops<'a>(
    hops: impl Iterator<Item = Hop<'a>>,
    reach: &VppReach,
) -> (usize, Option<usize>) {
    let mut link_local = 0;
    let mut unowned = None;
    let mut seen_link_local = false;
    for (i, h) in hops.enumerate() {
        let owned = reach.covers_device(h.dev, h.gatewayed);
        if owned && h.link_local && !seen_link_local {
            link_local = i;
            seen_link_local = true;
        } else if !owned && unowned.is_none() {
            unowned = Some(i);
        }
    }
    (link_local, unowned)
}

/// The v6 half of one scan, before it is settled against VPP's table.
///
/// Split because the two halves live on different threads: the scan
/// cannot read the engine (it runs beside the supervision loop, never on
/// it), so it hands the loop the link-local candidates and the loop
/// settles them against the ledger when the result lands.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct V6Scan {
    /// Path findings that stand whatever VPP holds. Sorted.
    pub findings: Vec<Uncovered<Ipv6Prefix>>,
    /// The nexthop-object routes, by prefix — summarised on one line when
    /// settled ([`Uncovered::Opaque`]), but kept per route until then so a
    /// `drift-accept6` can match each ([`Self::settle_accepting`]).
    pub opaque: Vec<Ipv6Prefix>,
    /// Link-local candidates, sorted by prefix then table.
    pub link_local: Vec<LinkLocalRoute>,
}

/// One v6 scan settled against VPP's table and the `drift-accept6` set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettledV6 {
    /// What no accept covers — the findings that degrade health.
    pub findings: Vec<Uncovered<Ipv6Prefix>>,
    /// What some accept covers, in the same shape: paths, then the
    /// summaries, each summary counting only its accepted routes.
    pub accepted: Vec<Uncovered<Ipv6Prefix>>,
    /// Accepts that cover no finding at all, accepted or not, in config
    /// order: the finding they were written for is gone.
    pub unmatched: Vec<Ipv6Prefix>,
}

impl V6Scan {
    /// The findings, plus the link-local candidates whose prefix VPP does
    /// not hold, summarised.
    ///
    /// Settled when the scan lands, not on every status poll: the
    /// candidates can number in the hundreds of thousands, and a verdict
    /// up to one scan interval behind VPP's table is the cadence the
    /// whole tripwire already runs at. So in the first scan after an
    /// attach, before the table has loaded, VPP holds nothing and they
    /// are reported — truly, at that moment — until the next scan.
    ///
    /// A lacking candidate that mixes in a hop out an unowned device is an
    /// ordinary path finding naming that device, not part of the summary:
    /// VPP has no route, and the reason worth naming is the tunnel (review
    /// finding). A HELD one is covered whatever its other hops are — VPP
    /// forwards over the paths it resolved, the any-path rule the v4 scan
    /// applies to ECMP.
    pub fn settle(&self, vpp_holds: impl Fn(&Ipv6Prefix) -> bool) -> Vec<Uncovered<Ipv6Prefix>> {
        self.settle_accepting(vpp_holds, &[]).findings
    }

    /// [`Self::settle`], with every finding a `drift-accept6` covers set
    /// apart ([`SettledV6`]).
    ///
    /// Matched per ROUTE prefix, whatever the category — a path, a
    /// nexthop-object route, a link-local candidate VPP lacks — and before
    /// the summaries are built, so one accepted route never takes the rest
    /// of its summary with it. An accept covers a finding whose prefix it
    /// equals or contains; a finding LESS specific than the accept (a
    /// default route via a tunnel, under an accept for one overlay /48)
    /// is not covered, since most of what it carries is not what the
    /// operator accepted.
    pub fn settle_accepting(
        &self,
        vpp_holds: impl Fn(&Ipv6Prefix) -> bool,
        accepts: &[Ipv6Prefix],
    ) -> SettledV6 {
        // Every accept covering the prefix is marked, not just the first:
        // a nested pair both match, and neither is reported as stale.
        let mut matched = vec![false; accepts.len()];
        let mut accepted = |p: &Ipv6Prefix| {
            let mut any = false;
            for (i, a) in accepts.iter().enumerate() {
                if a.contains_prefix(p) {
                    matched[i] = true;
                    any = true;
                }
            }
            any
        };
        let (mut open, mut taken) = (V6Findings::default(), V6Findings::default());
        for f in &self.findings {
            let Uncovered::Path { prefix, .. } = f else {
                continue;
            };
            let side = if accepted(prefix) {
                &mut taken
            } else {
                &mut open
            };
            side.paths.push(f.clone());
        }
        for p in &self.opaque {
            let side = if accepted(p) { &mut taken } else { &mut open };
            side.opaque += 1;
        }
        for r in self.link_local.iter().filter(|r| !vpp_holds(&r.prefix)) {
            let side = if accepted(&r.prefix) {
                &mut taken
            } else {
                &mut open
            };
            // An unowned hop makes it a path naming that device
            // ([`Self::settle`]).
            match &r.unowned {
                Some(dev) => side.paths.push(Uncovered::Path {
                    prefix: r.prefix,
                    oif: dev.to_string(),
                    table: r.table,
                    kernel_delivers: false,
                    encap: None,
                }),
                None => side.lacking.push(r),
            }
        }
        SettledV6 {
            findings: open.into_lines(),
            accepted: taken.into_lines(),
            unmatched: accepts
                .iter()
                .zip(matched)
                .filter(|(_, m)| !m)
                .map(|(a, _)| *a)
                .collect(),
        }
    }
}

/// One side of a settled v6 scan, before it is put in reporting order.
#[derive(Default)]
struct V6Findings<'a> {
    paths: Vec<Uncovered<Ipv6Prefix>>,
    opaque: usize,
    lacking: Vec<&'a LinkLocalRoute>,
}

impl V6Findings<'_> {
    /// Paths first, sorted, as everywhere else; the summaries follow.
    /// Sorted here rather than trusted from the scan because the lacking
    /// candidates with an unowned hop were appended as paths.
    fn into_lines(self) -> Vec<Uncovered<Ipv6Prefix>> {
        let mut out = self.paths;
        sort_paths(&mut out);
        if self.opaque > 0 {
            out.push(Uncovered::Opaque(self.opaque));
        }
        if !self.lacking.is_empty() {
            out.push(Uncovered::LinkLocal {
                routes: self.lacking.len(),
                examples: self
                    .lacking
                    .iter()
                    .take(LINK_LOCAL_EXAMPLES)
                    .map(|r| format!("{} via {} (table {})", r.prefix.cidr(), r.oif, r.table))
                    .collect(),
            });
        }
        out
    }
}

/// Whether a route is a link-local candidate: not cleared, and some hop
/// VPP would take were its gateway not link-local — the refusal, not the
/// device, is what may leave VPP without a path. Not for an
/// encapsulating route (the action is its finding) nor kernel delivery.
/// One predicate for the dump and [`classify_v6`], so they cannot drift.
fn link_local_candidate<'a, I: Iterator<Item = Hop<'a>>>(
    kind: RouteKind,
    hops: impl Fn() -> I,
    reach: &VppReach,
) -> bool {
    // The hop test first: it is false for every IPv4 route, and the dump
    // runs this over the whole v4 table.
    !kind.encapsulated
        && !kind.kernel_delivers
        && hops().any(|h| h.link_local && reach.covers_device(h.dev, h.gatewayed))
        && !reach_clears(kind, hops(), reach)
}

/// The unsettled half of [`uncovered_paths_v6`]: `routes` as the dump
/// builds them, plus the link-local candidates it built compactly.
fn classify_v6(
    routes: &[KernelRoute<Ipv6Prefix>],
    candidates: Vec<LinkLocalRoute>,
    reach: &VppReach,
    selected_tables: Option<&[u32]>,
) -> V6Scan {
    let reach = reach.for_v6();
    let link_local_dst = Ipv6Prefix {
        addr: std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        prefix_len: 10,
    };
    let multicast_dst = Ipv6Prefix {
        addr: std::net::Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
        prefix_len: 8,
    };
    // Destinations that are no path, and tables no rule selects — before
    // every branch below, as in the v4 scan: inert is inert, whatever
    // else the route is.
    let skipped = |prefix: &Ipv6Prefix, table: u32| {
        link_local_dst.contains_prefix(prefix)
            || multicast_dst.contains_prefix(prefix)
            || selected_tables.is_some_and(|t| !t.contains(&table))
    };
    let mut out = Vec::new();
    let mut opaque = Vec::new();
    let mut link_local: Vec<LinkLocalRoute> = candidates
        .into_iter()
        .filter(|c| !skipped(&c.prefix, c.table))
        .collect();
    for r in routes {
        if r.kernel_delivers || skipped(&r.prefix, r.table) || r.cleared_by(&reach) {
            continue;
        }
        if r.via_nexthop_object && r.oifs.is_empty() {
            opaque.push(r.prefix);
            continue;
        }
        let Some(oif) = r.oifs.first() else { continue };
        if link_local_candidate(r.kind(), || r.hops(), &reach) {
            let (ll, unowned) = candidate_hops(r.hops(), &reach);
            link_local.push(LinkLocalRoute {
                prefix: r.prefix,
                table: r.table,
                oif: r.oifs[ll].as_str().into(),
                unowned: unowned.map(|i| r.oifs[i].as_str().into()),
            });
            continue;
        }
        out.push(Uncovered::Path {
            prefix: r.prefix,
            oif: oif.clone(),
            table: r.table,
            kernel_delivers: false,
            encap: r.encap.clone(),
        });
    }
    sort_paths(&mut out);
    link_local.sort_by_key(|a| (a.prefix.sort_key(), a.table));
    V6Scan {
        findings: out,
        opaque,
        link_local,
    }
}

/// What a route IS, apart from where it goes: the facts
/// [`reach_clears`] reads alongside its hops.
#[derive(Debug, Clone, Copy)]
struct RouteKind {
    drops: bool,
    kernel_delivers: bool,
    via_nexthop_object: bool,
    encapsulated: bool,
}

/// Whether a route is a finding under NO exemption set, diversion
/// scope or table filter — decided from the route itself and VPP's
/// reach alone.
///
/// Every condition here is one [`uncovered_paths`] skips a route for
/// regardless of scope, and nothing else is: the kernel drops it; it
/// names no device and no nexthop object hides one; or VPP can take
/// it. Each route's verdict is independent of every other's, so
/// discarding a cleared route cannot change the findings. That is what
/// lets [`dump_routes`] drop the bulk of a full table before building
/// it: BGP routes via a gateway on a member port are cleared here by
/// their DEVICE, never their protocol — the same protocol carries the
/// w26 remote /24 over an IPSec tunnel, which is a finding.
///
/// `hops` in route order. Shared by both families: an IPv6 route
/// differs only in its hops' link-local flags and in the reach it is
/// judged against ([`VppReach::for_v6`]).
fn reach_clears<'a>(
    kind: RouteKind,
    hops: impl Iterator<Item = Hop<'a>>,
    reach: &VppReach,
) -> bool {
    if kind.drops {
        return true;
    }
    let mut hops = hops.peekable();
    let Some(&Hop { dev: oif, .. }) = hops.peek() else {
        // Nothing to judge — unless a nexthop object hides the devices,
        // which is a coverage gap `uncovered_paths` counts.
        return !kind.via_nexthop_object;
    };
    // A lightweight-encap path is unreproducible REGARDLESS of which
    // device it leaves by, so both reachability arms below are skipped
    // for it — they would clear the route on the strength of an `oif`
    // that is not the problem.
    if kind.encapsulated {
        return false;
    }
    if kind.kernel_delivers {
        // Only the segments whose hosts steering diverts. A transit
        // port's own address is reachable from a steered host only by a
        // route that would itself be a finding, and reporting every
        // address on the box would demand more exemptions than the
        // 16-slot budget holds — an alarm with no available remedy is
        // one operators learn to ignore. Documented in the runbook,
        // with the null-drop gauge as the backstop for the rest.
        return !reach.local_devices.iter().any(|d| d == oif);
    }
    // A link-local hop is no path: VPP refuses the route through it.
    hops.any(|h| !h.link_local && reach.covers_device(h.dev, h.gatewayed))
}

/// One next hop as [`reach_clears`] reads it.
#[derive(Debug, Clone, Copy)]
struct Hop<'a> {
    dev: &'a str,
    /// Via a gateway rather than onto a connected segment.
    gatewayed: bool,
    /// That gateway is IPv6 link-local.
    link_local: bool,
}

impl<P> KernelRoute<P> {
    /// The route's hops, flags aligned by position.
    fn hops(&self) -> impl Iterator<Item = Hop<'_>> {
        self.oifs.iter().enumerate().map(|(i, d)| Hop {
            dev: d.as_str(),
            gatewayed: self.gatewayed.get(i).copied().unwrap_or(false),
            link_local: self.link_local.get(i).copied().unwrap_or(false),
        })
    }

    fn kind(&self) -> RouteKind {
        RouteKind {
            drops: self.drops,
            kernel_delivers: self.kernel_delivers,
            via_nexthop_object: self.via_nexthop_object,
            encapsulated: self.encap.is_some(),
        }
    }

    /// [`reach_clears`] for a route already built.
    fn cleared_by(&self, reach: &VppReach) -> bool {
        reach_clears(self.kind(), self.hops(), reach)
    }
}

/// What one scan concluded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DriftFindings {
    /// One line per finding, for the health surface.
    pub lines: Vec<String>,
    /// How many ROUTES those lines represent. Not `lines.len()`: the
    /// nexthop-object summary is one line for `n` routes, and a gauge
    /// derived from the line count published `1` however much of the
    /// table the scan could not see — undercounting exactly the blind
    /// portion it exists to report (review finding).
    pub routes: usize,
    /// The IPv6 half. Its own verdict, including its own read failure: a
    /// v6 dump that fails must not discard a v4 verdict that succeeded,
    /// nor be papered over by it.
    pub v6: V6Drift,
}

/// What the IPv6 half of one scan concluded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum V6Drift {
    /// Not scanned: VPP carries no IPv6, or no port diverts it, so no v6
    /// destination can reach VPP and there is nothing to judge.
    #[default]
    Inactive,
    /// Scanned, not yet settled against VPP's table — the loop does that
    /// ([`V6DriftState::absorb`]).
    Scanned(V6Scan),
    /// The kernel would not answer the v6 dump.
    Unreadable(String),
}

/// The IPv6 tripwire as the runtime retains it between scans and status
/// renders it.
///
/// Kept by the same rules as the v4 fields beside it: findings survive a
/// failed read (an unreadable kernel is not evidence the routes went
/// away) but the failure is carried with them, and the count is published
/// only from a read that worked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct V6DriftState {
    /// The last scan ran the v6 half. False = no row, no gauge: with no
    /// port diverting v6 there is no v6 verdict to give, clean or not.
    pub active: bool,
    /// Findings from the last v6 read that worked.
    pub lines: Vec<String>,
    /// How many routes `lines` stand for — the v6 gauge.
    pub routes: usize,
    /// Findings from the same read that a `drift-accept6` covers: listed
    /// and counted apart, degrading nothing ([`V6Scan::settle_accepting`]).
    pub accepted: Vec<String>,
    /// How many routes `accepted` stands for — the accepted gauge.
    pub accepted_routes: usize,
    /// `drift-accept6` prefixes that matched no finding in that read,
    /// `addr/len`. Reported so an accept does not outlive its reason
    /// unseen; they degrade nothing.
    pub unmatched_accepts: Vec<String>,
    /// Why the latest v6 read failed, if it did.
    pub unreadable: Option<String>,
}

impl V6DriftState {
    /// Take one scan's v6 verdict, settling its link-local candidates
    /// against `vpp_holds` and setting apart what `accepts` covers
    /// ([`V6Scan::settle_accepting`]). Returns the unaccepted findings when
    /// they are non-empty and changed, for the caller's warning — an
    /// accepted one is a decision already made, not news.
    ///
    /// The accepts are the set in force NOW, not when the scan started:
    /// they change what is reported, never what is scanned, so a reload
    /// that edits them is honoured by the next scan to land.
    pub fn absorb(
        &mut self,
        v6: V6Drift,
        vpp_holds: impl Fn(&Ipv6Prefix) -> bool,
        accepts: &[Ipv6Prefix],
    ) -> Option<&[String]> {
        match v6 {
            V6Drift::Inactive => {
                *self = Self::default();
                None
            }
            V6Drift::Scanned(scan) => {
                let settled = scan.settle_accepting(vpp_holds, accepts);
                let lines: Vec<String> =
                    settled.findings.iter().map(Uncovered::to_string).collect();
                let changed = !lines.is_empty() && lines != self.lines;
                *self = Self {
                    active: true,
                    lines,
                    routes: settled.findings.iter().map(Uncovered::routes).sum(),
                    accepted: settled.accepted.iter().map(accepted_line).collect(),
                    accepted_routes: settled.accepted.iter().map(Uncovered::routes).sum(),
                    unmatched_accepts: settled.unmatched.iter().map(RoutePrefix::cidr).collect(),
                    unreadable: None,
                };
                changed.then_some(self.lines.as_slice())
            }
            V6Drift::Unreadable(why) => {
                self.active = true;
                self.unreadable = Some(why);
                None
            }
        }
    }

    /// The whole scan failed before the v6 half could run. An active half
    /// is blind with it; an inactive one had nothing to read.
    pub fn scan_failed(&mut self, why: &str) {
        if self.active {
            self.unreadable = Some(why.to_string());
        }
    }

    /// A new scope was committed: the findings described the old one.
    /// The read failure stays, as the v4 one does — whether the kernel
    /// answers has nothing to do with which config is judged.
    ///
    /// Unless the new scope switches the half OFF: then there is nothing
    /// left to be blind about, and the whole state goes. Keeping `active`
    /// until the scanner next answered `Inactive` let a v4 dump failing in
    /// between be recorded as a v6 failure ([`Self::scan_failed`]), and
    /// under a persistently failing v4 dump `exempt-drift-v6` would claim
    /// a disabled scan was unreadable indefinitely (review finding).
    pub fn scope_committed(&mut self, scans_v6: bool) {
        if scans_v6 {
            self.lines.clear();
            self.routes = 0;
            self.accepted.clear();
            self.accepted_routes = 0;
            self.unmatched_accepts.clear();
        } else {
            *self = Self::default();
        }
    }

    /// Nothing for health to object to: inactive, or active with a clean
    /// read. Accepted findings and unmatched accepts do not count — they
    /// are notes on a Healthy row, not degradation.
    pub fn quiet(&self) -> bool {
        !self.active || (self.lines.is_empty() && self.unreadable.is_none())
    }
}

/// An accepted finding as the row lists it. A path reads as it would
/// unaccepted; a summary drops the diagnosis, which the operator read
/// before accepting, and keeps the count and examples.
fn accepted_line(u: &Uncovered<Ipv6Prefix>) -> String {
    match u {
        Uncovered::Path { .. } => u.to_string(),
        Uncovered::Opaque(n) => format!("{n} route(s) via nexthop objects"),
        Uncovered::LinkLocal { routes, examples } => format!(
            "{routes} route(s) via link-local next hops only ({}{})",
            examples.join(", "),
            if *routes > examples.len() {
                ", …"
            } else {
                ""
            }
        ),
    }
}

/// The `drift-accept6` set, shared between the module, which replaces it
/// on every accepted reconfigure, and the supervision loop, which reads it
/// each time a scan lands ([`V6DriftState::absorb`]).
///
/// A handle, not a [`DriftScope`] field. The scope is committed only once
/// the NIC holds rules matching it — while steered, a reload that moves no
/// lever leaves it pending until the next steer — because the exemptions
/// it carries describe NIC state. An accept describes none: it changes
/// what the tripwire reports and nothing else, so holding it back for a
/// steer would keep the row red over a decision the operator has already
/// made and reloaded. Same shape as [`crate::SharedAllowlist`].
#[derive(Debug, Default)]
pub struct DriftAccepts6(std::sync::RwLock<Vec<Ipv6Prefix>>);

impl DriftAccepts6 {
    pub fn new(accepts: Vec<Ipv6Prefix>) -> Self {
        Self(std::sync::RwLock::new(accepts))
    }

    /// Replace the whole set. The module is the only writer.
    pub fn publish(&self, accepts: Vec<Ipv6Prefix>) {
        *self.0.write().expect("drift-accept6 lock") = accepts;
    }

    pub fn get(&self) -> Vec<Ipv6Prefix> {
        self.0.read().expect("drift-accept6 lock").clone()
    }
}

/// Why a scan produced no verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanError {
    /// The kernel would not answer. The caller keeps its previous
    /// verdict and publishes the failure.
    Unreadable(String),
    /// A link changed state while the scan was reading, named here. Never
    /// published: the scanner waits for links to settle and scans again
    /// ([`Pacing`]).
    Interrupted(String),
}

impl From<String> for ScanError {
    fn from(why: String) -> Self {
        Self::Unreadable(why)
    }
}

/// The scan seam the runtime holds, mirroring [`crate::runtime::RxModeKick`]:
/// a trait so tests record calls and non-Linux builds never pretend.
pub trait DriftWatch {
    /// The scan's findings, empty when the exemptions hold. With
    /// `interruptible`, a link changing state mid-scan abandons it
    /// ([`ScanError::Interrupted`]); without, the scan reads to the end.
    fn uncovered(&mut self, interruptible: bool) -> Result<DriftFindings, ScanError>;

    /// Adopt a reloaded scope. Called from the same place the steering
    /// target is retargeted, so the scan judges the config the operator
    /// just applied rather than the one at attach.
    fn set_scope(&mut self, scope: DriftScope);

    /// The latest link up/down transition since the last call, named for
    /// the log. `None` when there was none, or when this watch cannot see
    /// links. Each change is reported once.
    fn link_changed(&mut self) -> Option<String> {
        None
    }
}

/// One finished pass: the scope generation it judged under, its verdict,
/// and how long it took.
#[derive(Debug)]
pub struct ScanReport {
    pub generation: u64,
    pub result: Result<DriftFindings, String>,
    /// Wall time of the pass: what it held the kernel's routing lock for,
    /// at most, one dump chunk at a time.
    pub took: std::time::Duration,
}

/// When the scanner runs.
///
/// Every dump chunk is served under `rtnl_mutex` (5.15), the lock every
/// route and link change needs too. A full-table scan is thousands of
/// chunks, and the worst time to take them is right after a link changes
/// state: the kernel flushes the routes through it, the routing daemon
/// withdraws and reinstalls its sessions' routes, all under the same lock.
/// A v6 dump fares worst — each chunk that finds the tree changed re-walks
/// it from the root, under the table lock with bottom halves off. On
/// 2026-10-07 a platform daemon toggling IX bridges flushed ~225k routes
/// and the box stalled ~40 s. So a pass that falls due within `settle` of
/// a link change waits, and a pass a change catches mid-read is abandoned.
///
/// Bounded by `max_defer`: a link that never stops flapping must not blind
/// the tripwire. A pass that has waited that long runs to the end, changes
/// or not.
#[derive(Debug, Clone, Copy)]
pub struct Pacing {
    /// Between the end of one pass and the start of the next.
    pub every: std::time::Duration,
    /// How long links must have been quiet before a pass starts.
    pub settle: std::time::Duration,
    /// The longest a due pass waits for links to settle, counted from when
    /// it fell due.
    pub max_defer: std::time::Duration,
}

impl Pacing {
    /// When a pass due since `due` may start, given the last link change:
    /// `None` = now. Capped at `due + max_defer`.
    fn hold_until(
        &self,
        now: std::time::Instant,
        due: std::time::Instant,
        last_change: Option<std::time::Instant>,
    ) -> Option<std::time::Instant> {
        let cap = due + self.max_defer;
        let settled = last_change? + self.settle;
        (now < settled && now < cap).then(|| settled.min(cap))
    }

    /// Whether a pass starting at `now` may be abandoned for a link change.
    /// Not once it has waited out `max_defer`, or a flapping link would
    /// abandon every attempt.
    fn interruptible(&self, now: std::time::Instant, due: std::time::Instant) -> bool {
        now < due + self.max_defer
    }
}

/// What woke the scan thread from a rest.
enum Woke {
    Stop,
    Scope,
    Slept,
}

/// Rest up to `slice`, waking early for a teardown and, when `scope_wakes`,
/// for a scope handover.
fn rest(
    inbox: &(std::sync::Mutex<ScannerInbox>, std::sync::Condvar),
    slice: std::time::Duration,
    scope_wakes: bool,
) -> Woke {
    let woke = |i: &ScannerInbox| {
        if i.stop {
            Some(Woke::Stop)
        } else if scope_wakes && i.pending.is_some() {
            Some(Woke::Scope)
        } else {
            None
        }
    };
    let guard = inbox.0.lock().expect("drift inbox lock");
    if let Some(w) = woke(&guard) {
        return w;
    }
    let (guard, _) = inbox
        .1
        .wait_timeout(guard, slice)
        .expect("drift inbox wait");
    woke(&guard).unwrap_or(Woke::Slept)
}

/// How often the scan thread looks up from a rest: the stop latency, and
/// how stale a link change's timestamp can be.
const REST_SLICE: std::time::Duration = std::time::Duration::from_millis(200);

#[derive(Default)]
struct ScannerInbox {
    /// A scope waiting to be adopted. Only the newest matters — an
    /// older pending scope is superseded, not queued.
    pending: Option<DriftScope>,
    /// Which scope the pending (or last adopted) one IS. Lives HERE,
    /// under the same lock as `pending`, because the two must move
    /// together: an atomic bumped outside the lock let the worker
    /// adopt nothing, read the incremented counter, and stamp a scan
    /// of the OLD exemptions as belonging to the NEW scope — the
    /// stale-result check would then accept it as current and publish
    /// a clean verdict over a path the new config had just stopped
    /// exempting (review finding). One lock, one truth.
    generation: u64,
    stop: bool,
}

/// The scan, running on its OWN thread.
///
/// A full `RTM_GETROUTE` dump on the reference primary walks ~1.05M
/// prefixes — parsed one message at a time — and the
/// supervision loop it used to run on is the same thread that answers
/// liveness pings, wedge detection, stop requests and steering
/// changes. A dump that outran the 3 s steering budget would time out
/// an operator's `steer off`: the rollback lever, blocked by a
/// monitoring scan (review finding). Monitoring must never be able to
/// delay the thing it monitors.
///
/// So the scan lives here: one thread, its own cadence, publishing
/// COMPLETED results into a slot the loop reads without blocking.
///
/// ## Every result is stamped with the scope it judged
///
/// Moving the scan off-thread created two ways to publish an answer
/// about the wrong configuration, and both hide a blackhole (review
/// findings on the async version):
///
/// - a scan already IN FLIGHT when the loop commits a new scope
///   finishes and publishes a verdict about the OLD exemptions;
/// - the worker then sleeps out its interval before adopting the new
///   one, so up to a minute passes with nothing re-examined.
///
/// The generation counter answers both. The loop bumps it when it
/// hands over a scope; the worker stamps each result with the
/// generation it actually scanned under; the loop discards any result
/// whose stamp is stale. And a handover WAKES the worker, so the
/// re-scan starts immediately rather than at the end of a sleep.
/// Until a result for the current generation arrives, the tripwire
/// reports that it has not scanned this configuration yet — never a
/// clean zero it has not earned.
///
/// ## Paced around link churn
///
/// See [`Pacing`]. A pass held for links to settle adopts no scope until
/// it runs, so a reconfigure landing meanwhile reads as "not scanned yet"
/// for the current generation, which it is.
pub struct DriftScanner {
    latest: std::sync::Arc<std::sync::Mutex<Option<ScanReport>>>,
    inbox: std::sync::Arc<(std::sync::Mutex<ScannerInbox>, std::sync::Condvar)>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl DriftScanner {
    /// Start scanning, beginning immediately unless a link has just
    /// changed state.
    pub fn spawn(watch: Box<dyn DriftWatch + Send>, pacing: Pacing) -> Self {
        let latest: std::sync::Arc<std::sync::Mutex<Option<ScanReport>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let inbox = std::sync::Arc::new((
            std::sync::Mutex::new(ScannerInbox::default()),
            std::sync::Condvar::new(),
        ));
        let (l, ib) = (latest.clone(), inbox.clone());
        let handle = std::thread::Builder::new()
            .name("pf-drift-scan".into())
            .spawn(move || scan_loop(watch, pacing, &l, &ib))
            .ok();
        Self {
            latest,
            inbox,
            handle,
        }
    }

    /// The newest COMPLETED result, if one has arrived since the last
    /// look. `None` means nothing new — the caller keeps what it had.
    ///
    /// Carries the generation it was scanned under so the caller can
    /// tell a verdict about the current configuration from one about
    /// a superseded scope.
    pub fn take_result(&self) -> Option<ScanReport> {
        self.latest.lock().expect("drift result lock").take()
    }

    /// The scope generation currently in force.
    pub fn generation(&self) -> u64 {
        self.inbox.0.lock().expect("drift inbox lock").generation
    }

    /// Hand the scanner a scope to adopt, and wake it to re-scan now.
    pub fn set_scope(&self, scope: DriftScope) {
        let mut inbox = self.inbox.0.lock().expect("drift inbox lock");
        // Both under the lock the worker adopts and stamps under, so
        // there is no window where the counter has moved and the
        // scope has not.
        inbox.generation += 1;
        inbox.pending = Some(scope);
        self.inbox.1.notify_all();
    }
}

/// The scan thread: hold while links settle, scan, publish, rest.
fn scan_loop(
    mut watch: Box<dyn DriftWatch + Send>,
    pacing: Pacing,
    latest: &std::sync::Mutex<Option<ScanReport>>,
    inbox: &(std::sync::Mutex<ScannerInbox>, std::sync::Condvar),
) {
    use std::time::Instant;
    // When the next pass fell due. Kept across abandoned attempts, so
    // `max_defer` bounds the whole delay rather than each attempt.
    let mut due = Instant::now();
    // The latest link change, and when it was seen. Polled on every rest
    // slice, so it is timed within a slice of when it happened.
    let mut last_change: Option<(Instant, String)> = None;
    loop {
        let mut held = false;
        loop {
            if let Some(what) = watch.link_changed() {
                if held {
                    tracing::debug!(link = %what, "links still changing; drift scan held");
                }
                last_change = Some((Instant::now(), what));
            }
            let now = Instant::now();
            let Some(until) = pacing.hold_until(now, due, last_change.as_ref().map(|c| c.0)) else {
                break;
            };
            if !held {
                held = true;
                if let Some((_, what)) = &last_change {
                    tracing::info!(
                        link = %what,
                        settle_s = pacing.settle.as_secs(),
                        "a link changed state; holding the drift scan until links settle"
                    );
                }
            }
            if let Woke::Stop = rest(inbox, REST_SLICE.min(until - now), false) {
                return;
            }
        }
        // Adopt and stamp under ONE lock hold, so `scanned_under` names
        // exactly the scope the watcher is about to scan with.
        let scanned_under = {
            let mut inbox = inbox.0.lock().expect("drift inbox lock");
            if inbox.stop {
                return;
            }
            if let Some(scope) = inbox.pending.take() {
                watch.set_scope(scope);
            }
            inbox.generation
        };
        let started = Instant::now();
        let interruptible = pacing.interruptible(started, due);
        if held && !interruptible {
            tracing::info!(
                waited_s = started.duration_since(due).as_secs(),
                "links have not settled; running the drift scan anyway"
            );
        }
        let outcome = watch.uncovered(interruptible);
        let took = started.elapsed();
        let result = match outcome {
            Ok(found) => Ok(found),
            Err(ScanError::Unreadable(why)) => Err(why),
            Err(ScanError::Interrupted(what)) => {
                tracing::info!(
                    link = %what,
                    after_ms = took.as_millis() as u64,
                    "a link changed state mid-scan; abandoned the drift scan until links settle"
                );
                last_change = Some((Instant::now(), what));
                continue;
            }
        };
        tracing::debug!(
            took_ms = took.as_millis() as u64,
            ok = result.is_ok(),
            "drift scan finished"
        );
        *latest.lock().expect("drift result lock") = Some(ScanReport {
            generation: scanned_under,
            result,
            took,
        });

        // Wake early for a new scope or a teardown; otherwise rest out the
        // interval in slices so a stop is not waiting on a full one.
        let rested = Instant::now();
        loop {
            if let Some(what) = watch.link_changed() {
                tracing::debug!(link = %what, "a link changed state between drift scans");
                last_change = Some((Instant::now(), what));
            }
            let Some(left) = pacing.every.checked_sub(rested.elapsed()) else {
                break;
            };
            match rest(inbox, REST_SLICE.min(left), true) {
                Woke::Stop => return,
                Woke::Scope => break,
                Woke::Slept => {}
            }
        }
        due = Instant::now();
    }
}

/// How long teardown waits for the scan thread before abandoning it.
///
/// A sleeping worker is woken by the stop notify and exits in
/// microseconds, which is the overwhelmingly common case; this only
/// has to be long enough to cover that wake.
const TEARDOWN_GRACE: std::time::Duration = std::time::Duration::from_millis(50);

impl Drop for DriftScanner {
    /// Ask the scan to stop, wait briefly, and ABANDON it if a dump is
    /// in flight.
    ///
    /// This runs on the supervision thread as it unwinds, AFTER the
    /// real teardown has killed VPP, released the VF and published its
    /// result — and `SupervisionService::stop()` gives that thread 900
    /// ms to finish before it tells the operator the teardown is
    /// incomplete and resources may still be held. A netlink dump has
    /// no cancellation and takes seconds on a DFZ table, so joining it
    /// unconditionally made a completed teardown report itself as an
    /// unfinished one, over a monitoring scan holding nothing (review
    /// finding).
    ///
    /// Abandoning is safe here in a way it would not be for the
    /// resource owners: this thread holds a read-only netlink socket,
    /// its watcher, and `Arc` clones of a result slot nobody reads any
    /// more. It owns no VPP process, no VF, no hugepage reservation —
    /// nothing whose lifetime a detach must account for — and the stop
    /// flag is already set, so it exits the moment its dump returns.
    /// (The previous comment here defended the join by calling the
    /// open socket a reason to wait; that conflated a thread holding a
    /// file descriptor with a thread holding the resources teardown
    /// exists to release.) A bounded receive keeps "the moment its
    /// dump returns" finite even if the kernel goes quiet.
    fn drop(&mut self) {
        {
            let mut inbox = self.inbox.0.lock().expect("drift inbox lock");
            inbox.stop = true;
            self.inbox.1.notify_all();
        }
        let Some(h) = self.handle.take() else { return };
        let deadline = std::time::Instant::now() + TEARDOWN_GRACE;
        while !h.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        if h.is_finished() {
            let _ = h.join();
            return;
        }
        // Dropping the handle detaches the thread.
        tracing::debug!(
            "drift scan still in flight at teardown; detaching it rather than delaying detach"
        );
    }
}

/// The production scan: dump the IPv4 routes the reach does not clear
/// from every table a policy rule selects ([`dump_routes`]), compare —
/// and, while some port diverts IPv6, the same for IPv6
/// ([`dump_routes_v6`]).
#[cfg(target_os = "linux")]
pub struct KernelDriftWatch {
    /// `bridged_devices` is recomputed on every scan
    /// ([`Self::refresh_bridged`]); the rest is config.
    pub reach: VppReach,
    /// Each member's declared (or attach-time) tagged VLANs.
    pub port_vlans: Vec<(String, Vec<u16>)>,
    /// `vlans all` members, whose tagged VLANs follow the kernel bridge.
    pub trunk_ports: Vec<String>,
    /// The CURRENT scope, refreshed on every accepted reconfigure. A
    /// watcher frozen at attach would call a newly-unexempted path
    /// covered (the blackhole this exists to catch) and, worse, keep
    /// reporting a path the operator had just exempted BECAUSE the
    /// health message told them to (review finding) — and the same goes
    /// for a `v6-divert` added or dropped under a running daemon.
    pub scope: DriftScope,
    /// Link up/down transitions, for [`Pacing`]. `None` when the watch
    /// could not be opened: scans then run on the clock alone, as they did
    /// before pacing existed.
    pub links: Option<KernelLinkWatch>,
}

#[cfg(target_os = "linux")]
impl KernelDriftWatch {
    /// The VLAN and bridge devices VPP reaches now: each member's
    /// declared VLANs, every VLAN it sends untagged (reached through the
    /// VF), and — on a `vlans all` trunk — every VLAN the kernel bridge
    /// has it carry. Frozen at attach, a VLAN a trunk gained later would
    /// stay a finding until restart, degrading health and asking for
    /// exemptions nothing needs (review finding). An unreadable table
    /// keeps the last answer.
    fn refresh_bridged(&mut self) {
        let live = crate::fdb::dump_port_vlans().map(|e| {
            crate::topology::PortVlans::from_entries(
                e.into_iter().map(|v| (v.port, v.vid, v.untagged)),
            )
        });
        let port_vlans: Vec<(String, Vec<u16>)> = self
            .port_vlans
            .iter()
            .map(|(port, declared)| {
                let mut v = declared.clone();
                if let Ok(pv) = &live {
                    v.extend(pv.untagged(port));
                    if self.trunk_ports.contains(port) {
                        v.extend(pv.tagged(port));
                    }
                }
                (port.clone(), v)
            })
            .collect();
        match crate::topology::kernel_links() {
            Ok(links) => {
                self.reach.bridged_devices = crate::topology::reachable_devices(
                    &links,
                    &crate::topology::all_netdevs(),
                    &port_vlans,
                )
            }
            Err(e) => tracing::debug!(error = %e, "VLAN table unreadable; keeping the last reach"),
        }
    }
}

#[cfg(target_os = "linux")]
impl DriftWatch for KernelDriftWatch {
    fn uncovered(&mut self, interruptible: bool) -> Result<DriftFindings, ScanError> {
        let started = std::time::Instant::now();
        // Refreshed BEFORE the dump, which discards against this reach:
        // a stale one would drop a route via a bridge VPP no longer
        // reaches as if it were still a path VPP can take.
        self.refresh_bridged();
        // The rules first: they say which tables to dump. A rule dump
        // that fails filters nothing rather than failing the scan — the
        // routes are the finding, the rules only narrow them, and losing
        // the narrowing costs noise where losing the scan costs the
        // blackhole.
        let tables =
            dump_rule_tables(netlink_packet_route::AddressFamily::Inet).unwrap_or_else(|e| {
                tracing::debug!(error = %e, "policy-rule dump failed; dumping every table");
                None
            });
        let links = &mut self.links;
        let mut interrupt = || match links {
            Some(l) if interruptible => l.changed(),
            _ => None,
        };
        let v4 = dump_routes(&self.reach, tables.as_deref(), &mut interrupt)?;
        let v4_ms = started.elapsed().as_millis() as u64;
        let divertible = match &self.scope.dst_only {
            Some(allow) => Divertible::OnlyDst(allow),
            None => Divertible::Any,
        };
        let scope = Scope {
            reach: &self.reach,
            exempts: &self.scope.exempts,
            divertible,
            // Already applied by the dump; kept so the comparison stands
            // on its own whatever produced the routes.
            selected_tables: tables.as_deref(),
        };
        let found = uncovered_paths(&v4.routes, &scope);
        // After the v4 half, which keeps its verdict whatever the v6 dump
        // does: each family's read failure is its own. A link change is
        // not a read failure — it abandons the whole scan.
        let v6_started = std::time::Instant::now();
        let (v6, v6_read) = if self.scope.scans_v6 {
            match scan_v6(&self.reach, &mut interrupt) {
                Ok((scan, read)) => (V6Drift::Scanned(scan), Some(read)),
                Err(ScanError::Unreadable(e)) => (V6Drift::Unreadable(e), None),
                Err(interrupted) => return Err(interrupted),
            }
        } else {
            (V6Drift::Inactive, None)
        };
        // What the scan cost the kernel, beside the gauge the runtime
        // publishes: whether the dump was filtered, and what each family
        // read and took.
        tracing::debug!(
            v4_tables = ?tables,
            v4_routes_read = v4.read,
            v4_routes_kept = v4.routes.len(),
            v4_ms,
            v6_routes_read = ?v6_read,
            v6_ms = v6_started.elapsed().as_millis() as u64,
            "drift scan read the kernel's routes"
        );
        Ok(DriftFindings {
            routes: found.iter().map(Uncovered::routes).sum(),
            lines: found.iter().map(Uncovered::to_string).collect(),
            v6,
        })
    }

    fn link_changed(&mut self) -> Option<String> {
        self.links.as_mut()?.changed()
    }

    fn set_scope(&mut self, scope: DriftScope) {
        self.scope = scope;
    }
}

/// The IPv6 half: the v6 routes the v6 reach does not clear, from the
/// tables the v6 policy rules select. Same failure rules as the v4 half —
/// an unreadable rule set filters nothing, an unreadable route dump is
/// the half's `Err`. Unsettled: the loop settles the link-local
/// candidates against VPP's table ([`V6Scan::settle`]). Also returns how
/// many routes the dump read.
#[cfg(target_os = "linux")]
fn scan_v6(
    reach: &VppReach,
    interrupt: &mut dyn FnMut() -> Option<String>,
) -> Result<(V6Scan, usize), ScanError> {
    let tables = dump_rule_tables(netlink_packet_route::AddressFamily::Inet6).unwrap_or_else(|e| {
        tracing::debug!(error = %e, "IPv6 policy-rule dump failed; dumping every table");
        None
    });
    let dump = dump_routes_v6(reach, tables.as_deref(), interrupt)?;
    Ok((
        classify_v6(&dump.routes, dump.link_local, reach, tables.as_deref()),
        dump.read,
    ))
}

/// One family's route dump: what [`dump_family`] kept, and how many
/// routes it read to get there.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct RouteDump<P> {
    /// The routes [`reach_clears`] does not clear, less the link-local
    /// candidates.
    pub routes: Vec<KernelRoute<P>>,
    /// IPv6 only: the link-local candidates, compact ([`LinkLocalRoute`]).
    pub link_local: Vec<LinkLocalRoute>,
    /// Route messages read off the socket, kept or not: the dump's cost.
    pub read: usize,
}

/// One blocking strict-check RTM_GETROUTE dump per table in `tables` —
/// every table when `None` — returning only the routes [`reach_clears`]
/// does not clear under `reach`. `interrupt` is polled after every read;
/// `Some` abandons the dump ([`ScanError::Interrupted`]).
///
/// Hand-rolled on `netlink-sys` for the same reason [`crate::fdb`] is:
/// this crate runs a supervision loop, not an async runtime, and one
/// dump per minute does not earn one.
///
/// **Which routes the verdict can depend on.** Routes via a device VPP
/// does not take (a tunnel, an unreached bridge, a bridged segment's
/// connected subnet), the kernel's own addresses on `local-route`
/// bridges, encapsulating and nexthop-object routes, and (IPv6) routes
/// out owned devices via link-local next hops — in a table some policy
/// rule selects ([`Scope::selected_tables`]). Nothing else can be a
/// finding.
///
/// **What the kernel filters.** The table, nothing finer. `tables` is
/// the rule set's selection ([`dump_rule_tables`]), so a table no rule
/// names — an unreferenced VRF, a daemon's staging copy — is never
/// serialised at all, and the comparison skips the same tables, so the
/// findings cannot change. A strict request also stops the kernel
/// interleaving nexthop exceptions (cached PMTU and redirect entries,
/// `RTM_F_CLONED`), which a legacy dump returns as /32 and /128 routes:
/// copies of paths already judged, except where they are wrong — an
/// exception on the tunnel leg of an ECMP route VPP takes read as a
/// finding, and one under a link-local v6 route as a prefix VPP lacks.
///
/// **What it cannot filter.** The bulk: on a full-table router the main
/// table holds ~1.06M routes, nearly all BGP-installed via a gateway on
/// a member port or bridged VLAN, and the main table is always selected.
/// A strict dump narrows by table, route type, protocol and device, each
/// as "only this one", never "all but", and none removes that bulk
/// without hiding something above: a type filter keeps every unicast
/// route; a protocol filter would hide BGP routes via an IPSec tunnel,
/// the w26 finding; and dumping only the devices VPP does not take would
/// hide encapsulation out a member port, connected subnets on bridged
/// VLANs, nexthop-object routes and the v6 link-local candidates. Each
/// filtered dump also walks the whole table in one lock hold when it
/// matches little, so several of them would trade many short holds of
/// the routing lock for a few long ones. The bulk is read and judged
/// before a `KernelRoute` is built, so it costs parsing, not a
/// million-entry allocation.
///
/// The LOCAL table is always selected (rule 0). Its entries are the
/// router's own addresses, and steered traffic to those dies in VPP
/// exactly like tunnel-bound traffic does — that is the w23 blackhole
/// (110,917 packets in five minutes) which `steer-exempt` was
/// introduced to fix. A check that only looked at forwarding would
/// have missed the first instance of the very class it exists for.
#[cfg(target_os = "linux")]
pub fn dump_routes(
    reach: &VppReach,
    tables: Option<&[u32]>,
    interrupt: &mut dyn FnMut() -> Option<String>,
) -> Result<RouteDump<Ipv4Prefix>, ScanError> {
    use netlink_packet_route::route::RouteAddress;
    // No IPv4 gateway is link-local, so no candidate is ever built here.
    let (routes, _, read) = dump_family(
        netlink_packet_route::AddressFamily::Inet,
        reach,
        tables,
        interrupt,
        |dst, prefix_len| Ipv4Prefix {
            // No RTA_DST = the default route.
            addr: match dst {
                Some(RouteAddress::Inet(a)) => *a,
                _ => std::net::Ipv4Addr::UNSPECIFIED,
            },
            prefix_len,
        },
    )?;
    Ok(RouteDump {
        routes,
        link_local: Vec::new(),
        read,
    })
}

/// [`dump_routes`] for IPv6, against the v6 reach ([`VppReach::for_v6`])
/// so the discard agrees with [`classify_v6`]. The member-gatewayed bulk
/// is discarded as for v4; the link-local candidates come back compact
/// ([`LinkLocalRoute`]), because under a link-local BGP mesh that is
/// nearly the whole v6 table, and building a full route for each only
/// for most to settle as held would be the million-entry allocation the
/// v4 dump was changed to avoid.
#[cfg(target_os = "linux")]
pub fn dump_routes_v6(
    reach: &VppReach,
    tables: Option<&[u32]>,
    interrupt: &mut dyn FnMut() -> Option<String>,
) -> Result<RouteDump<Ipv6Prefix>, ScanError> {
    use netlink_packet_route::route::RouteAddress;
    let (routes, candidates, read) = dump_family(
        netlink_packet_route::AddressFamily::Inet6,
        &reach.for_v6(),
        tables,
        interrupt,
        |dst, prefix_len| Ipv6Prefix {
            addr: match dst {
                Some(RouteAddress::Inet6(a)) => *a,
                _ => std::net::Ipv6Addr::UNSPECIFIED,
            },
            prefix_len,
        },
    )?;
    let link_local = candidates
        .into_iter()
        .map(|(prefix, table, oif, unowned)| LinkLocalRoute {
            prefix,
            table,
            oif,
            unowned,
        })
        .collect();
    Ok(RouteDump {
        routes,
        link_local,
        read,
    })
}

/// Link-local candidates as [`dump_family`] builds them:
/// `(prefix, table, link-local device, unowned device)` — see
/// [`LinkLocalRoute`].
#[cfg(target_os = "linux")]
type Candidates<P> = Vec<(P, u32, std::sync::Arc<str>, Option<std::sync::Arc<str>>)>;

/// What [`dump_family`] returns: the routes kept, the link-local
/// candidates, and how many route messages it read.
#[cfg(target_os = "linux")]
type FamilyDump<P> = (Vec<KernelRoute<P>>, Candidates<P>, usize);

/// The dump both families share; `prefix` builds the destination from
/// `RTA_DST` (absent for a default route) and the header's length.
/// Returns the routes [`reach_clears`] does not clear, less the
/// link-local candidates ([`link_local_candidate`]), which come back
/// separately and compact, and how many route messages it read.
#[cfg(target_os = "linux")]
fn dump_family<P>(
    family: netlink_packet_route::AddressFamily,
    reach: &VppReach,
    tables: Option<&[u32]>,
    interrupt: &mut dyn FnMut() -> Option<String>,
    prefix: impl Fn(Option<&netlink_packet_route::route::RouteAddress>, u8) -> P,
) -> Result<FamilyDump<P>, ScanError> {
    use netlink_packet_core::{
        NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST,
    };
    use netlink_packet_route::route::{
        RouteAddress, RouteAttribute, RouteLwEnCapType, RouteMessage, RouteType,
    };
    use netlink_packet_route::RouteNetlinkMessage;
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    /// Whether a gateway attribute names an IPv6 link-local address —
    /// the next hop VPP refuses. `RTA_VIA` (a cross-family next hop) and
    /// every IPv4 gateway are not.
    fn link_local_gateway(a: &RouteAttribute) -> bool {
        matches!(
            a,
            RouteAttribute::Gateway(RouteAddress::Inet6(g))
                if g.segments()[0] & 0xffc0 == 0xfe80
        )
    }

    /// The kernel's name for a lightweight-encap action, for the
    /// operator's message. `None` is the overwhelming majority and is
    /// not an encapsulation — the kernel emits `RTA_ENCAP_TYPE` on
    /// plain routes too.
    fn encap_name(t: RouteLwEnCapType) -> Option<String> {
        Some(match t {
            RouteLwEnCapType::None => return None,
            RouteLwEnCapType::Mpls => "MPLS".to_string(),
            RouteLwEnCapType::Ip => "IP-in-IP".to_string(),
            RouteLwEnCapType::Ila => "ILA".to_string(),
            RouteLwEnCapType::Ip6 => "IPv6 tunnel".to_string(),
            RouteLwEnCapType::Seg6 => "SRv6".to_string(),
            RouteLwEnCapType::Seg6Local => "SRv6-local".to_string(),
            RouteLwEnCapType::Bpf => "BPF".to_string(),
            RouteLwEnCapType::Rpl => "RPL".to_string(),
            RouteLwEnCapType::Ioam6 => "IOAM6".to_string(),
            RouteLwEnCapType::Xfrm => "XFRM".to_string(),
            // The enum is `#[non_exhaustive]` and the kernel adds
            // types; an unrecognised one is still an encap action
            // and must still be reported, by number.
            other => format!("encap type {}", u16::from(other)),
        })
    }

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
    // A receive that can block forever is a scan thread that never
    // settles — and teardown abandons an in-flight scan rather than
    // waiting on it, so "forever" would mean a thread and its socket
    // held for the daemon's life.
    crate::fdb::bound_recv(&socket)?;
    // Strict: the kernel honours the table in the request, and refuses
    // a request it cannot honour rather than quietly dumping everything
    // — the same pattern as neigh-snoop's coverage dump. The request
    // carries no protocol, type or device: strict check reads each as a
    // filter (rtnetlink's builder presets `protocol = Static`, which
    // neigh-snoop has to clear; `RouteMessage::default()` sets none).
    socket
        .set_netlink_get_strict_chk(true)
        .map_err(|e| format!("NETLINK_GET_STRICT_CHK: {e}"))?;
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;

    // Interface names are resolved once per dump rather than per
    // route: a full table can carry thousands of entries out of a
    // handful of devices.
    // Shared, so a link-local candidate carries its device for a refcount.
    let mut names: std::collections::HashMap<u32, std::sync::Arc<str>> =
        std::collections::HashMap::new();
    let mut out = Vec::new();
    let mut candidates: Candidates<P> = Vec::new();
    let mut read = 0usize;
    let mut recv_buf = vec![0u8; 64 * 1024];
    // `None` = one request for every table.
    let requests: Vec<Option<u32>> = match tables {
        Some(t) => t.iter().copied().map(Some).collect(),
        None => vec![None],
    };
    for (seq, wanted) in (1u32..).zip(requests) {
        let mut route = RouteMessage::default();
        route.header.address_family = family;
        // RTA_TABLE, not the header's u8: policy tables live above 255.
        if let Some(t) = wanted {
            route.attributes.push(RouteAttribute::Table(t));
        }
        let mut msg = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(route));
        msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
        msg.header.sequence_number = seq;
        msg.finalize();
        let mut send_buf = vec![0u8; msg.header.length as usize];
        msg.serialize(&mut send_buf);
        socket
            .send(&send_buf, 0)
            .map_err(|e| format!("netlink send: {e}"))?;
        'dump: loop {
            let n = socket
                .recv(&mut &mut recv_buf[..], 0)
                .map_err(|e| format!("netlink recv: {e}"))?;
            // Between chunks, where abandoning costs nothing: the kernel
            // serves the next chunk only when asked, and closing the socket
            // frees the dump.
            if let Some(what) = interrupt() {
                return Err(ScanError::Interrupted(what));
            }
            let mut offset = 0usize;
            while offset < n {
                let pkt = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[offset..n])
                    .map_err(|e| format!("netlink parse: {e}"))?;
                let len = pkt.header.length as usize;
                if len == 0 {
                    break;
                }
                // The kernel sets NLM_F_DUMP_INTR when the table changed
                // under the dump, which makes the result a mix of two
                // states rather than a snapshot. On a box with a live BGP
                // feed that is not rare, and a partial list fails the
                // dangerous way: a missing route reads as "no such path"
                // and a missing rule narrows the filter onto an active
                // table. Refuse it; the caller keeps its previous verdict
                // and the next scan is a minute away (review finding).
                if pkt.header.flags & NLM_F_DUMP_INTR != 0 {
                    return Err(ScanError::Unreadable(
                        "the kernel interrupted the dump (NLM_F_DUMP_INTR): the \
                         table changed underneath it, so this result is not a \
                         snapshot"
                            .into(),
                    ));
                }
                match pkt.payload {
                    // A dump reports its own failure HERE, as a negative errno
                    // in the DONE message, not as NLMSG_ERROR — a strict
                    // request the kernel refuses ends this way, and reading it
                    // as a clean end would publish an empty table as a clean
                    // scan.
                    NetlinkPayload::Done(d) if d.code == 0 => break 'dump,
                    // A table a rule names but no route has created: nothing
                    // in it to find. Every box has one — `lookup default`.
                    NetlinkPayload::Done(d) if wanted.is_some() && d.code == -libc::ENOENT => {
                        break 'dump
                    }
                    NetlinkPayload::Done(d) => {
                        return Err(ScanError::Unreadable(format!(
                            "route dump{}: {}",
                            wanted.map_or(String::new(), |t| format!(" of table {t}")),
                            std::io::Error::from_raw_os_error(-d.code)
                        )))
                    }
                    NetlinkPayload::Error(e) => {
                        return Err(ScanError::Unreadable(format!("netlink error: {e}")))
                    }
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(m)) => {
                        read += 1;
                        let mut dst: Option<&RouteAddress> = None;
                        let mut oifs: Vec<u32> = Vec::new();
                        // Multipath hops, each with its own gateway flags;
                        // single-path `oifs` take the top-level ones.
                        let mut hop_oifs: Vec<(u32, bool, bool)> = Vec::new();
                        let mut nexthop_object = false;
                        let mut gatewayed = false;
                        let mut link_local = false;
                        let mut encap: Option<String> = None;
                        let mut table = u32::from(m.header.table);
                        for attr in &m.attributes {
                            match attr {
                                RouteAttribute::Destination(a) => dst = Some(a),
                                RouteAttribute::Oif(i) => oifs.push(*i),
                                RouteAttribute::Gateway(_) | RouteAttribute::Via(_) => {
                                    gatewayed = true;
                                    link_local = link_local_gateway(attr);
                                }
                                // `RTA_ENCAP_TYPE`: the route hands the
                                // packet to a lightweight tunnel before it
                                // leaves. See `KernelRoute::encap` for why
                                // the ordinary `oif` makes this the
                                // quietest failure in the dump.
                                RouteAttribute::EncapType(t) => {
                                    encap = encap.take().or_else(|| encap_name(*t))
                                }
                                // ECMP puts its nexthops HERE and leaves
                                // RTA_OIF unset, so a route read only for
                                // RTA_OIF looks device-less and gets
                                // skipped — an all-tunnel ECMP route would
                                // blackhole under a clean health surface
                                // (review finding).
                                RouteAttribute::MultiPath(hops) => {
                                    hop_oifs.extend(hops.iter().map(|h| {
                                        let gw = h.attributes.iter().any(|a| {
                                            matches!(
                                                a,
                                                RouteAttribute::Gateway(_) | RouteAttribute::Via(_)
                                            )
                                        });
                                        let ll = h.attributes.iter().any(link_local_gateway);
                                        (h.interface_index, gw, ll)
                                    }));
                                    // Encapsulation is per PATH, and ECMP
                                    // puts each path's attributes here. A
                                    // route with one plain path and one
                                    // encapped path is reported: VPP would
                                    // install both and hash traffic into
                                    // the one it cannot reproduce.
                                    encap = encap.take().or_else(|| {
                                        hops.iter().flat_map(|h| h.attributes.iter()).find_map(
                                            |a| match a {
                                                RouteAttribute::EncapType(t) => encap_name(*t),
                                                _ => None,
                                            },
                                        )
                                    });
                                }
                                // RTA_TABLE carries ids past the u8 header
                                // field — policy tables live up there.
                                RouteAttribute::Table(t) => table = *t,
                                // RTA_NH_ID: a route carrying it names its
                                // devices in a nexthop object, nowhere this
                                // scan can read. See
                                // [`KernelRoute::via_nexthop_object`].
                                RouteAttribute::NhId(_) => nexthop_object = true,
                                _ => {}
                            }
                        }
                        let hops: Vec<(u32, bool, bool)> = oifs
                            .into_iter()
                            .map(|i| (i, gatewayed, link_local))
                            .chain(hop_oifs)
                            .collect();
                        let kind = RouteKind {
                            drops: matches!(
                                m.header.kind,
                                RouteType::BlackHole | RouteType::Unreachable | RouteType::Prohibit
                            ),
                            kernel_delivers: matches!(
                                m.header.kind,
                                RouteType::Local | RouteType::Broadcast | RouteType::Anycast
                            ),
                            via_nexthop_object: nexthop_object,
                            encapsulated: encap.is_some(),
                        };
                        for &(i, _, _) in &hops {
                            names
                                .entry(i)
                                .or_insert_with(|| crate::fdb::ifname(i).into());
                        }
                        let name = |i: u32| &*names[&i];
                        let judged = || {
                            hops.iter().map(|&(i, gatewayed, link_local)| Hop {
                                dev: name(i),
                                gatewayed,
                                link_local,
                            })
                        };
                        // Judged here, before anything is allocated for it:
                        // on a full-table box nearly every route is cleared,
                        // and under a link-local mesh nearly every v6 one is
                        // a candidate.
                        if link_local_candidate(kind, judged, reach) {
                            let (ll, unowned) = candidate_hops(judged(), reach);
                            let dev = |at: usize| names[&hops[at].0].clone();
                            candidates.push((
                                prefix(dst, m.header.destination_prefix_length),
                                table,
                                dev(ll),
                                unowned.map(dev),
                            ));
                        } else if !reach_clears(kind, judged(), reach) {
                            out.push(KernelRoute {
                                prefix: prefix(dst, m.header.destination_prefix_length),
                                oifs: hops.iter().map(|&(i, _, _)| name(i).to_string()).collect(),
                                table,
                                drops: kind.drops,
                                kernel_delivers: kind.kernel_delivers,
                                via_nexthop_object: nexthop_object,
                                gatewayed: hops.iter().map(|&(_, gw, _)| gw).collect(),
                                link_local: hops.iter().map(|&(_, _, ll)| ll).collect(),
                                encap,
                            });
                        }
                    }
                    _ => {}
                }
                offset += len;
            }
        }
    }
    Ok((out, candidates, read))
}

/// The table ids some policy rule can select, or `None` when they
/// cannot be enumerated safely and NOTHING may be filtered.
///
/// One `RTM_GETRULE` dump. See [`Scope::selected_tables`] for what
/// this models and, more importantly, what it deliberately does not.
///
/// `None` has two producers, and both are the safe direction:
///
/// - **an l3mdev rule** (`from all lookup [l3mdev-table]`), which
///   carries table id 0 and resolves to a VRF's table at forwarding
///   time. Its tables are not in the rule set at all, so filtering by
///   what IS there would drop every VRF route — and a tunnel route in
///   an active VRF would go unreported while steered traffic
///   blackholed (review finding). Mapping l3mdev to its VRF tables
///   means enumerating VRF devices and their table ids; until that
///   exists, a host with one gets no filtering, which is exactly the
///   behaviour before the filter was added.
/// - **an empty result.** Filtering by an empty set would skip every
///   route and report a permanently clean scan, which is the failure
///   this whole module exists to prevent.
///
/// Per `family`: `ip rule` and `ip -6 rule` are separate rule sets, and
/// a v6 route is selected only by a v6 rule.
#[cfg(target_os = "linux")]
pub fn dump_rule_tables(
    family: netlink_packet_route::AddressFamily,
) -> Result<Option<Vec<u32>>, String> {
    use netlink_packet_core::{
        NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST,
    };
    use netlink_packet_route::rule::{RuleAttribute, RuleMessage};
    use netlink_packet_route::RouteNetlinkMessage;
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
    crate::fdb::bound_recv(&socket)?;
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;

    let mut rule = RuleMessage::default();
    rule.header.family = family;
    let mut msg = NetlinkMessage::from(RouteNetlinkMessage::GetRule(rule));
    msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.header.sequence_number = 1;
    msg.finalize();
    let mut send_buf = vec![0u8; msg.header.length as usize];
    msg.serialize(&mut send_buf);
    socket
        .send(&send_buf, 0)
        .map_err(|e| format!("netlink send: {e}"))?;

    let mut out: Vec<u32> = Vec::new();
    let mut recv_buf = vec![0u8; 64 * 1024];
    'dump: loop {
        let n = socket
            .recv(&mut &mut recv_buf[..], 0)
            .map_err(|e| format!("netlink recv: {e}"))?;
        let mut offset = 0usize;
        while offset < n {
            let pkt = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[offset..n])
                .map_err(|e| format!("netlink parse: {e}"))?;
            let len = pkt.header.length as usize;
            if len == 0 {
                break;
            }
            // The kernel sets NLM_F_DUMP_INTR when the table changed
            // under the dump, which makes the result a mix of two
            // states rather than a snapshot. On a box with a live BGP
            // feed that is not rare, and a partial list fails the
            // dangerous way: a missing route reads as "no such path"
            // and a missing rule narrows the filter onto an active
            // table. Refuse it; the caller keeps its previous verdict
            // and the next scan is a minute away (review finding).
            if pkt.header.flags & NLM_F_DUMP_INTR != 0 {
                return Err("the kernel interrupted the dump (NLM_F_DUMP_INTR): the \
                            table changed underneath it, so this result is not a \
                            snapshot"
                    .into());
            }
            match pkt.payload {
                NetlinkPayload::Done(_) => break 'dump,
                NetlinkPayload::Error(e) => return Err(format!("netlink error: {e}")),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRule(m)) => {
                    // FRA_TABLE carries ids past the u8 header field,
                    // exactly as RTA_TABLE does for routes.
                    let mut table = u32::from(m.header.table);
                    for attr in &m.attributes {
                        match attr {
                            RuleAttribute::Table(t) => table = *t,
                            // The VRF case: this rule names no table
                            // of its own and picks one per packet, so
                            // the enumeration cannot be complete.
                            RuleAttribute::L3MDev(true) => return Ok(None),
                            _ => {}
                        }
                    }
                    if table != 0 && !out.contains(&table) {
                        out.push(table);
                    }
                }
                _ => {}
            }
            offset += len;
        }
    }
    // Empty means "no rule named a table", which cannot be used to
    // filter — see this function's doc.
    Ok((!out.is_empty()).then_some(out))
}

/// The link state [`KernelLinkWatch`] compares: administratively up,
/// operationally up, carrier. A change in any of them moves routes; the
/// rest of `ifi_flags` (promiscuity, allmulti) does not, and toggles under
/// a running daemon — neigh-snoop's promisc, the rx-mode kick, a tcpdump.
#[cfg(target_os = "linux")]
fn link_state(flags: netlink_packet_route::link::LinkFlags) -> u32 {
    use netlink_packet_route::link::LinkFlags;
    (flags & (LinkFlags::Up | LinkFlags::Running | LinkFlags::LowerUp)).bits()
}

/// A link state as the log names it.
#[cfg(target_os = "linux")]
fn describe_link_state(state: u32) -> &'static str {
    let up = state & libc::IFF_UP as u32 != 0;
    let running = state & libc::IFF_RUNNING as u32 != 0;
    let carrier = state & libc::IFF_LOWER_UP as u32 != 0;
    match (up, carrier, running) {
        (false, _, _) => "down",
        (true, false, _) => "up without carrier",
        (true, true, false) => "up, not running",
        (true, true, true) => "up",
    }
}

/// Link up/down transitions, read from `RTNLGRP_LINK` without blocking,
/// for [`Pacing`].
///
/// Seeded with one link dump at open, so the first event a device sends
/// is compared against its real state rather than read as news. A device
/// that appears is a change only if it appears up, and one that vanishes
/// only if it was up: an unconfigured interface coming and going moves no
/// routes.
#[cfg(target_os = "linux")]
pub struct KernelLinkWatch {
    socket: netlink_sys::Socket,
    state: std::collections::HashMap<u32, u32>,
    buf: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl KernelLinkWatch {
    pub fn open() -> Result<Self, String> {
        use netlink_sys::{protocols::NETLINK_ROUTE, Socket};
        let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
        socket
            .bind_auto()
            .map_err(|e| format!("netlink bind: {e}"))?;
        // Subscribed before the seed dump, so a change between the two is
        // queued rather than lost; replayed against the seed, it counts
        // only if it differs.
        socket
            .add_membership(libc::RTNLGRP_LINK)
            .map_err(|e| format!("RTNLGRP_LINK: {e}"))?;
        socket
            .set_non_blocking(true)
            .map_err(|e| format!("netlink non-blocking: {e}"))?;
        Ok(Self {
            socket,
            state: dump_link_states()?,
            buf: vec![0u8; 64 * 1024],
        })
    }

    /// The latest transition queued since the last call, `"<dev> <state>"`,
    /// or `None`. Drains the socket.
    pub fn changed(&mut self) -> Option<String> {
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
        use netlink_packet_route::link::{LinkAttribute, LinkMessage};
        use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};

        let name = |m: &LinkMessage| {
            m.attributes
                .iter()
                .find_map(|a| match a {
                    LinkAttribute::IfName(n) => Some(n.clone()),
                    _ => None,
                })
                .unwrap_or_else(|| crate::fdb::ifname(m.header.index))
        };
        let mut latest = None;
        loop {
            let n = match self.socket.recv(&mut &mut self.buf[..], 0) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                // The queue overflowed: more link events than it holds
                // since the last look, which is churn whatever they said.
                // The lost ones leave `state` stale, so it is re-read; an
                // event queued before the re-read and replayed after it can
                // only over-report.
                Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                    latest = Some("link notifications overflowed".to_string());
                    match dump_link_states() {
                        Ok(state) => self.state = state,
                        Err(e) => tracing::debug!(error = %e, "link state re-read failed"),
                    }
                    continue;
                }
                // Not churn, and nothing to hold a scan for. A socket that
                // keeps failing leaves scans on the clock alone.
                Err(e) => {
                    tracing::debug!(error = %e, "link watch unreadable");
                    break;
                }
            };
            let mut offset = 0usize;
            while offset < n {
                let Ok(pkt) =
                    NetlinkMessage::<RouteNetlinkMessage>::deserialize(&self.buf[offset..n])
                else {
                    break;
                };
                let len = pkt.header.length as usize;
                if len == 0 {
                    break;
                }
                offset += len;
                // AF_BRIDGE messages describe bridge PORTS (STP state, a
                // port leaving its bridge); the device's own message is
                // AF_UNSPEC.
                let (m, gone) = match pkt.payload {
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m)) => (m, false),
                    NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelLink(m)) => (m, true),
                    _ => continue,
                };
                if m.header.interface_family != AddressFamily::Unspec {
                    continue;
                }
                let index = m.header.index;
                let now = if gone { 0 } else { link_state(m.header.flags) };
                let was = if gone {
                    self.state.remove(&index)
                } else {
                    self.state.insert(index, now)
                }
                .unwrap_or(0);
                if was != now {
                    latest = Some(if gone {
                        format!("{} removed", name(&m))
                    } else {
                        format!("{} {}", name(&m), describe_link_state(now))
                    });
                }
            }
        }
        latest
    }
}

/// Every link's [`link_state`], by ifindex: one RTM_GETLINK dump.
#[cfg(target_os = "linux")]
fn dump_link_states() -> Result<std::collections::HashMap<u32, u32>, String> {
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
    use netlink_packet_route::link::LinkMessage;
    use netlink_packet_route::RouteNetlinkMessage;
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
    crate::fdb::bound_recv(&socket)?;
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;
    let mut msg = NetlinkMessage::from(RouteNetlinkMessage::GetLink(LinkMessage::default()));
    msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.header.sequence_number = 1;
    msg.finalize();
    let mut send_buf = vec![0u8; msg.header.length as usize];
    msg.serialize(&mut send_buf);
    socket
        .send(&send_buf, 0)
        .map_err(|e| format!("netlink send: {e}"))?;

    let mut out = std::collections::HashMap::new();
    let mut recv_buf = vec![0u8; 64 * 1024];
    'dump: loop {
        let n = socket
            .recv(&mut &mut recv_buf[..], 0)
            .map_err(|e| format!("netlink recv: {e}"))?;
        let mut offset = 0usize;
        while offset < n {
            let pkt = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[offset..n])
                .map_err(|e| format!("netlink parse: {e}"))?;
            let len = pkt.header.length as usize;
            if len == 0 {
                break;
            }
            match pkt.payload {
                NetlinkPayload::Done(d) if d.code == 0 => break 'dump,
                NetlinkPayload::Done(d) => {
                    return Err(format!(
                        "link dump: {}",
                        std::io::Error::from_raw_os_error(-d.code)
                    ))
                }
                NetlinkPayload::Error(e) => return Err(format!("netlink error: {e}")),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m)) => {
                    out.insert(m.header.index, link_state(m.header.flags));
                }
                _ => {}
            }
            offset += len;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn p(a: u8, b: u8, c: u8, d: u8, len: u8) -> Ipv4Prefix {
        Ipv4Prefix {
            addr: Ipv4Addr::new(a, b, c, d),
            prefix_len: len,
        }
    }

    fn route(prefix: Ipv4Prefix, oif: &str) -> KernelRoute {
        KernelRoute {
            prefix,
            oifs: vec![oif.to_string()],
            table: 100,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: false,
            gatewayed: vec![false],
            link_local: Vec::new(),
            encap: None,
        }
    }

    /// [`Pacing`] in milliseconds: interval, settle, max deferral.
    fn pacing(every: u64, settle: u64, max_defer: u64) -> Pacing {
        let ms = std::time::Duration::from_millis;
        Pacing {
            every: ms(every),
            settle: ms(settle),
            max_defer: ms(max_defer),
        }
    }

    fn reach() -> VppReach {
        VppReach {
            members: vec!["eth3".into(), "eth4".into()],
            local_devices: vec!["br1337".into()],
            local_devices_v6: vec!["br100".into()],
            bridged_devices: vec!["br3998".into()],
        }
    }

    fn find(routes: &[KernelRoute], exempts: &[Ipv4Prefix]) -> Vec<Uncovered> {
        uncovered_paths(
            routes,
            &Scope {
                reach: &reach(),
                exempts,
                divertible: Divertible::Any,
                selected_tables: None,
            },
        )
    }

    /// The dump discards what `reach_clears` clears before building it
    /// (`dump_routes`), and that must never change a finding. A full
    /// table's bulk — gatewayed routes via member ports, however many —
    /// is dropped, and every scope finds the same things in what is left
    /// as in the whole table. Nothing is filtered by protocol: the w26
    /// remote /24, BGP-announced over an IPSec tunnel, looks exactly like
    /// the bulk except for its device, and it survives.
    #[test]
    fn filtering_cleared_routes_at_the_dump_never_changes_the_findings() {
        use packetframe_common::fib::IpPrefix;
        let gatewayed = |mut r: KernelRoute| {
            r.gatewayed = vec![true; r.oifs.len()];
            r
        };
        let in_table = |mut r: KernelRoute, table: u32| {
            r.table = table;
            r
        };
        // The bulk: BGP routes via a gateway on a member port, one ECMP
        // pair across both members every hundredth route.
        const BULK: u32 = 20_000;
        let mut table: Vec<KernelRoute> = (0..BULK)
            .map(|n| {
                let prefix = Ipv4Prefix {
                    addr: Ipv4Addr::from(u32::from(Ipv4Addr::new(198, 18, 0, 0)) + n),
                    prefix_len: 32,
                };
                let mut r = route(prefix, if n % 2 == 0 { "eth3" } else { "eth4" });
                if n % 100 == 0 {
                    r.oifs.push("eth3".into());
                }
                in_table(gatewayed(r), 254)
            })
            .collect();
        let bulk_len = table.len();

        // What the verdict can depend on, plus cleared look-alikes.
        let mut local_on_service_bridge = route(p(192, 0, 2, 1, 32), "br1337");
        local_on_service_bridge.kernel_delivers = true;
        local_on_service_bridge.table = 255;
        let mut local_on_member = route(p(203, 0, 113, 1, 32), "eth3");
        local_on_member.kernel_delivers = true;
        local_on_member.table = 255;
        let mut mpls_out_a_member = gatewayed(route(p(203, 0, 113, 0, 25), "eth3"));
        mpls_out_a_member.encap = Some("MPLS".into());
        let mut opaque_nhid = route(p(203, 0, 113, 128, 26), "eth3");
        opaque_nhid.oifs.clear();
        opaque_nhid.gatewayed.clear();
        opaque_nhid.via_nexthop_object = true;
        let mut inline_nhid = gatewayed(route(p(203, 0, 113, 192, 26), "eth4"));
        inline_nhid.via_nexthop_object = true;
        let mut blackhole = route(p(198, 51, 100, 0, 28), "vti64");
        blackhole.drops = true;
        let mut deviceless = route(p(198, 51, 100, 16, 28), "vti64");
        deviceless.oifs.clear();
        let mut ecmp_member_and_tunnel = gatewayed(route(p(198, 51, 100, 32, 28), "eth3"));
        ecmp_member_and_tunnel.oifs.push("vti64".into());
        ecmp_member_and_tunnel.gatewayed.push(true);
        let mut ecmp_bridge_and_tunnel = route(p(198, 51, 100, 48, 28), "br3998");
        ecmp_bridge_and_tunnel.oifs.push("vti64".into());
        ecmp_bridge_and_tunnel.gatewayed = vec![false, true];
        table.extend([
            in_table(gatewayed(route(p(198, 51, 100, 128, 25), "vti64")), 254),
            in_table(gatewayed(route(p(198, 51, 100, 64, 27), "br4040")), 254),
            in_table(gatewayed(route(p(198, 51, 100, 96, 27), "br3998")), 254),
            in_table(route(p(192, 0, 2, 0, 24), "br3998"), 254),
            in_table(route(p(198, 51, 100, 0, 24), "vti64"), 100),
            local_on_service_bridge,
            local_on_member,
            mpls_out_a_member,
            opaque_nhid,
            inline_nhid,
            blackhole,
            deviceless,
            ecmp_member_and_tunnel,
            ecmp_bridge_and_tunnel,
        ]);

        let reach = reach();
        let kept: Vec<KernelRoute> = table
            .iter()
            .filter(|r| !r.cleared_by(&reach))
            .cloned()
            .collect();
        let kept_prefixes: Vec<String> = kept
            .iter()
            .map(|r| format!("{}/{}", r.prefix.addr, r.prefix.prefix_len))
            .collect();
        assert_eq!(
            kept_prefixes,
            [
                "198.51.100.128/25", // BGP via the tunnel: w26
                "198.51.100.64/27",  // via a bridge no member carries
                "192.0.2.0/24",      // a bridged segment's connected subnet
                "198.51.100.0/24",   // tunnel route in a policy table
                "192.0.2.1/32",      // kernel address on a local-route bridge
                "203.0.113.0/25",    // encapsulated out a member
                "203.0.113.128/26",  // devices hidden in a nexthop object
                "198.51.100.48/28",  // ECMP whose only bridge hop is connected
            ],
            "every member-gatewayed route cleared, nothing the verdict reads"
        );
        assert!(bulk_len >= BULK as usize && kept.len() < 10);

        let allow = [
            IpPrefix::V4 {
                addr: [198, 51, 100, 0],
                prefix_len: 25,
            },
            IpPrefix::V4 {
                addr: [203, 0, 113, 128],
                prefix_len: 25,
            },
        ];
        let tables = [254u32, 255];
        let exempts = [p(198, 51, 100, 128, 25), p(192, 0, 2, 1, 32)];
        let scopes = [
            (Divertible::Any, None, &[][..]),
            (Divertible::Any, Some(&tables[..]), &exempts[..]),
            (Divertible::OnlyDst(&allow), None, &[][..]),
            (Divertible::OnlyDst(&allow), Some(&tables[..]), &exempts[..]),
        ];
        for (divertible, selected_tables, exempts) in scopes {
            let scope = Scope {
                reach: &reach,
                exempts,
                divertible: divertible.clone(),
                selected_tables,
            };
            let whole = uncovered_paths(&table, &scope);
            assert!(!whole.is_empty(), "every scope here has findings");
            assert_eq!(
                uncovered_paths(&kept, &scope),
                whole,
                "{divertible:?} tables {selected_tables:?} exempts {exempts:?}"
            );
        }
    }

    /// The gateway flag is per hop. An ECMP route whose bridge hop is
    /// connected and whose gatewayed hop leaves by a tunnel has no path
    /// VPP can take, and must not borrow the tunnel hop's gateway to
    /// clear the bridge hop (review finding).
    #[test]
    fn a_bridge_hop_is_covered_only_by_its_own_gateway() {
        let mut mixed = route(p(198, 51, 100, 0, 24), "br3998");
        mixed.oifs.push("vti64".into());
        mixed.gatewayed = vec![false, true];
        assert_eq!(find(&[mixed.clone()], &[]).len(), 1, "connected bridge hop");

        mixed.gatewayed = vec![true, false];
        assert!(find(&[mixed], &[]).is_empty(), "gatewayed bridge hop");
    }

    /// The w26 shape: tunnel-bound routes are findings, and only the
    /// ones no exemption covers.
    #[test]
    fn tunnel_paths_are_findings_until_an_exemption_covers_them() {
        let routes = vec![
            route(p(198, 51, 100, 128, 25), "vti64"), // remote site: finding
            route(p(198, 51, 100, 2, 32), "vti64"),   // host inside the local /25
            route(p(0, 0, 0, 0, 0), "eth3"),          // default via a member: fine
            route(p(198, 51, 100, 0, 25), "br1337"),  // local delivery: fine
            route(p(10, 0, 0, 0, 8), "eth4"),         // member: fine
            {
                // Via an IX peer on a bridge VLAN a member carries:
                // placed per neighbour, so fine.
                let mut r = route(p(198, 51, 100, 0, 24), "br3998");
                r.gatewayed = vec![true];
                r
            },
            // The same bridge's CONNECTED subnet: VPP has no route for it
            // without a local-route, so it is a finding.
            route(p(192, 0, 2, 0, 24), "br3998"),
            route(p(203, 0, 113, 0, 24), "br4040"), // a bridge no member carries: finding
        ];
        let found = find(&routes, &[]);
        assert_eq!(found.len(), 4, "{found:?}");
        assert!(found.iter().any(|u| u.to_string().contains("via br4040")));
        assert!(found.iter().any(|u| u.to_string().contains("192.0.2.0/24")));
        assert!(!found
            .iter()
            .any(|u| u.to_string().contains("198.51.100.0/24")));
        let found: Vec<_> = found
            .into_iter()
            .filter(|u| !u.to_string().contains("br4040") && !u.to_string().contains("br3998"))
            .collect();
        assert!(found.iter().all(|u| u.to_string().contains("via vti64")));

        let exempts = [
            p(198, 51, 100, 128, 25),
            p(198, 51, 100, 2, 32),
            p(203, 0, 113, 0, 24),
            p(192, 0, 2, 0, 24),
        ];
        assert!(find(&routes, &exempts).is_empty());
    }

    /// Containment, not overlap: a /32 exemption inside a /25 route
    /// does NOT cover the /25.
    #[test]
    fn an_exemption_must_contain_the_route_not_merely_overlap_it() {
        let routes = vec![route(p(203, 0, 113, 0, 25), "vti64")];
        assert_eq!(
            find(&routes, &[p(203, 0, 113, 5, 32)]).len(),
            1,
            "a /32 inside the route must not silence the /25"
        );
        assert!(find(&routes, &[p(203, 0, 113, 0, 24)]).is_empty());
    }

    /// Routes the kernel drops itself are not findings: VPP dropping
    /// the same packet is the same outcome, one hop earlier.
    #[test]
    fn routes_the_kernel_itself_drops_are_not_findings() {
        let mut blackhole = route(p(198, 18, 0, 0, 15), "vti64");
        blackhole.drops = true;
        let mut no_oif = route(p(203, 0, 113, 0, 24), "vti64");
        no_oif.oifs.clear();
        assert!(find(&[blackhole, no_oif], &[]).is_empty());
    }

    /// Broadcast and multicast are exempted on every steered port
    /// without a directive.
    #[test]
    fn the_built_in_exemptions_count_as_cover() {
        let routes = vec![
            route(p(224, 0, 0, 0, 4), "vti64"),
            route(p(255, 255, 255, 255, 32), "vti64"),
        ];
        assert!(find(&routes, &[]).is_empty());
    }

    /// A LOCAL route is an address the kernel terminates, so device
    /// reachability says nothing about it — VPP has no local delivery
    /// at any interface. Skipping these because their oif is a member
    /// or bridge is exactly how the w23 class (110,917 packets to a
    /// gateway address in five minutes) would go unreported by a scan
    /// whose docs claimed to cover it (review finding).
    #[test]
    fn a_local_address_on_a_service_bridge_is_a_finding_despite_the_device() {
        let mut gw = route(p(192, 0, 2, 1, 32), "br1337");
        gw.kernel_delivers = true;
        gw.table = 255;
        let found = find(&[gw.clone()], &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(matches!(
            found[0],
            Uncovered::Path {
                kernel_delivers: true,
                ..
            }
        ));
        assert!(
            found[0]
                .to_string()
                .contains("delivered by the kernel on br1337"),
            "the message must read as termination, not a path: {}",
            found[0]
        );
        // And the exemption an operator would add silences it.
        assert!(find(&[gw], &[p(192, 0, 2, 1, 32)]).is_empty());
    }

    /// A service bridge's directed broadcast (`.255`) is
    /// `RTN_BROADCAST` with the bridge as its oif — kernel-owned
    /// delivery VPP cannot reproduce, not a forwarding path — so the
    /// device check must not wave it through just because the bridge
    /// is a local device (review finding, one round after the same
    /// thing was fixed for `RTN_LOCAL`).
    #[test]
    fn a_service_bridges_directed_broadcast_is_kernel_delivery_too() {
        let mut bcast = route(p(192, 0, 2, 255, 32), "br1337");
        bcast.kernel_delivers = true;
        bcast.table = 255;
        let found = find(std::slice::from_ref(&bcast), &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(
            found[0].to_string().contains("delivered by the kernel"),
            "{}",
            found[0]
        );
        assert!(find(&[bcast], &[p(192, 0, 2, 255, 32)]).is_empty());
    }

    /// Local addresses NOT on a steered segment are deliberately out
    /// of scope: the 16-slot budget cannot hold an exemption for every
    /// address on the box, and an alarm with no available remedy is
    /// one operators learn to ignore. Documented, with the null-drop
    /// gauge as the backstop.
    #[test]
    fn local_addresses_off_the_steered_segments_are_out_of_scope() {
        let mut transit = route(p(198, 51, 100, 51, 32), "eth3");
        transit.kernel_delivers = true;
        let mut loopback = route(p(127, 0, 0, 1, 32), "lo");
        loopback.kernel_delivers = true;
        assert!(find(&[transit, loopback], &[]).is_empty());
    }

    /// ECMP encodes nexthops in RTA_MULTIPATH, leaving RTA_OIF unset.
    /// A route read only for RTA_OIF looks device-less and is skipped
    /// — so an all-tunnel ECMP route would blackhole under a clean
    /// health surface (review finding). Any reachable path makes the
    /// route deliverable, because VPP installs the paths it can
    /// resolve and forwards over those.
    #[test]
    fn a_multipath_route_is_judged_by_all_its_nexthops() {
        let all_tunnel = KernelRoute {
            prefix: p(198, 51, 100, 0, 24),
            oifs: vec!["vti64".into(), "wg0".into()],
            table: 254,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: false,
            gatewayed: vec![false, false],
            link_local: Vec::new(),
            encap: None,
        };
        assert_eq!(find(&[all_tunnel], &[]).len(), 1);

        let mixed = KernelRoute {
            prefix: p(198, 51, 100, 0, 24),
            oifs: vec!["vti64".into(), "eth3".into()],
            table: 254,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: false,
            gatewayed: vec![false, false],
            link_local: Vec::new(),
            encap: None,
        };
        assert!(
            find(&[mixed], &[]).is_empty(),
            "one resolvable path is enough for VPP to forward the prefix"
        );
    }

    /// A lightweight-encap route (`ip route ... encap mpls 100 dev
    /// eth3`) leaves by an ORDINARY device — a member port, here — so
    /// every reachability test in this scan passes it, and the mirror,
    /// which has nowhere to put a label stack, would forward the
    /// packet bare out the same port (review finding). The device is
    /// not the hazard; the action is.
    #[test]
    fn an_encapsulating_route_is_a_finding_even_out_a_member_port() {
        let mut mpls = route(p(203, 0, 113, 0, 24), "eth3");
        mpls.encap = Some("MPLS".into());
        let found = find(std::slice::from_ref(&mpls), &[]);
        assert_eq!(
            found.len(),
            1,
            "a member-port oif must not clear an encap action: {found:?}"
        );
        let msg = found[0].to_string();
        assert!(
            msg.contains("MPLS") && msg.contains("bare"),
            "the message must name the action, not the reachability: {msg}"
        );
        // And an exemption still silences it — exempted traffic never
        // reaches VPP, so there is nothing to misforward.
        assert!(find(&[mpls], &[p(203, 0, 113, 0, 24)]).is_empty());
    }

    /// Encapsulation is a property of a PATH, so an ECMP route with
    /// one plain member path and one encapped path is still a finding:
    /// VPP installs both and hashes traffic into the one it cannot
    /// reproduce. The any-path-reachable rule must not clear it.
    #[test]
    fn one_encapped_path_in_an_ecmp_group_is_enough() {
        let mixed = KernelRoute {
            prefix: p(203, 0, 113, 0, 24),
            oifs: vec!["eth3".into(), "eth4".into()],
            table: 254,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: false,
            gatewayed: vec![false, false],
            link_local: Vec::new(),
            encap: Some("SRv6".into()),
        };
        assert_eq!(find(&[mixed], &[]).len(), 1);
    }

    /// Under dst-only steering the NIC diverts only packets addressed
    /// inside the allowlist, so a path outside it can never enter VPP
    /// and must not cost an exemption slot (review finding). Any src
    /// rule anywhere restores the everything-is-at-risk scope.
    #[test]
    fn dst_only_steering_scopes_the_scan_to_divertible_destinations() {
        use packetframe_common::fib::IpPrefix;
        let allow = [IpPrefix::V4 {
            addr: [192, 0, 2, 0],
            prefix_len: 24,
        }];
        let routes = vec![
            route(p(192, 0, 2, 2, 32), "vti64"),    // inside the allowlist
            route(p(198, 51, 100, 0, 24), "vti64"), // outside it
        ];
        let scoped = uncovered_paths(
            &routes,
            &Scope {
                reach: &reach(),
                exempts: &[],
                divertible: Divertible::OnlyDst(&allow),
                selected_tables: None,
            },
        );
        assert_eq!(scoped.len(), 1, "{scoped:?}");
        assert!(scoped[0].to_string().contains("192.0.2.2/32"), "{scoped:?}");

        // A src rule anywhere means any destination can be diverted.
        assert_eq!(find(&routes, &[]).len(), 2);
    }

    /// A table no policy rule names cannot be consulted by any
    /// packet, so a tunnel route parked in an unreferenced VRF must
    /// not cost an exemption slot (review finding). Only SELECTION is
    /// modelled — fwmark/iif/from are not, because over-reporting is
    /// the safe direction and a permissive mistake in a rule walk
    /// re-opens the hole this scan closes.
    #[test]
    fn routes_in_tables_no_rule_selects_are_not_findings() {
        let mut in_use = route(p(203, 0, 113, 0, 24), "vti64");
        in_use.table = 100;
        let mut orphan = route(p(198, 51, 100, 0, 24), "vti64");
        orphan.table = 4242;
        let routes = [in_use, orphan];
        let selected = [100u32, 254, 255];
        let found = uncovered_paths(
            &routes,
            &Scope {
                reach: &reach(),
                exempts: &[],
                divertible: Divertible::Any,
                selected_tables: Some(&selected),
            },
        );
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].table(), Some(100));
        // Unknown rule set filters nothing: losing the narrowing
        // costs noise, losing the scan costs the blackhole. This is
        // the arm an l3mdev (VRF) rule takes — its tables resolve per
        // packet and are absent from the rule set, so filtering by
        // what IS there would drop every VRF route and report clean
        // while steered traffic blackholed (review finding). Same arm
        // for a failed dump, and for an empty enumeration, which
        // would otherwise skip every route on the box.
        assert_eq!(find(&routes, &[]).len(), 2);
        let empty_selection: [u32; 0] = [];
        let blind = uncovered_paths(
            &routes,
            &Scope {
                reach: &reach(),
                exempts: &[],
                divertible: Divertible::Any,
                selected_tables: Some(&empty_selection),
            },
        );
        assert!(
            blind.is_empty(),
            "an empty selection filters everything — which is why the dump returns None \
             for it rather than an empty Vec: {blind:?}"
        );
    }

    /// The scope derivation is shared by attach and reconfigure, so a
    /// hot allowlist or direction edit cannot leave the scan judging
    /// the config from attach time (review finding).
    #[test]
    fn the_diversion_scope_follows_config_not_attach_time() {
        use packetframe_common::config::VppSteerDirection as D;
        use packetframe_common::fib::IpPrefix;
        let allow = [IpPrefix::V4 {
            addr: [192, 0, 2, 0],
            prefix_len: 24,
        }];
        let port = |steer: bool, dir: Option<D>| ("eth4".to_string(), 1u16, steer, Vec::new(), dir);

        // Every port dst → scoped to the allowlist.
        let scoped = divertible_scope(&[port(true, Some(D::Dst))], D::Both, &allow);
        assert_eq!(scoped.as_deref(), Some(&allow[..]));

        // One src port anywhere → everything is at risk.
        assert!(
            divertible_scope(
                &[port(true, Some(D::Dst)), port(false, Some(D::Src))],
                D::Dst,
                &allow
            )
            .is_none(),
            "a src port makes any destination divertible"
        );
        // The global default applies to ports that declare nothing.
        assert!(divertible_scope(&[port(true, None)], D::Both, &allow).is_none());
        assert_eq!(
            divertible_scope(&[port(true, None)], D::Dst, &allow).as_deref(),
            Some(&allow[..])
        );
        // No ports at all: conservative.
        assert!(divertible_scope(&[], D::Dst, &allow).is_none());
    }

    /// Under dst-only steering only the route's INTERSECTION with the
    /// allowlist can be diverted, so an exemption covering that
    /// intersection covers the whole hazard — demanding one for the
    /// entire route would send the operator to install a broader rule
    /// than the risk warrants (review finding).
    #[test]
    fn dst_only_coverage_is_judged_on_the_divertible_intersection() {
        use packetframe_common::fib::IpPrefix;
        // One host of a tunnel-backed /24 is allowlisted, so only that
        // host can be diverted at all.
        let allow = [IpPrefix::V4 {
            addr: [203, 0, 113, 7],
            prefix_len: 32,
        }];
        let routes = [route(p(203, 0, 113, 0, 24), "vti64")];
        let scoped = |exempts: &[Ipv4Prefix]| {
            uncovered_paths(
                &routes,
                &Scope {
                    reach: &reach(),
                    exempts,
                    divertible: Divertible::OnlyDst(&allow),
                    selected_tables: None,
                },
            )
        };
        assert_eq!(scoped(&[]).len(), 1, "uncovered: the /32 can be diverted");
        assert!(
            scoped(&[p(203, 0, 113, 7, 32)]).is_empty(),
            "exempting the one divertible host covers the whole hazard"
        );

        // Under src steering the same /32 exemption is NOT enough:
        // every address in the /24 can be diverted there.
        let any = uncovered_paths(
            &routes,
            &Scope {
                reach: &reach(),
                exempts: &[p(203, 0, 113, 7, 32)],
                divertible: Divertible::Any,
                selected_tables: None,
            },
        );
        assert_eq!(any.len(), 1, "{any:?}");
    }

    /// A route using a nexthop object names its devices nowhere this
    /// scan can read. Left as a device-less route it would be SKIPPED
    /// — a tunnel-backed nhid route blackholing under a clean scan
    /// (review finding) — so the scan reports its own blind spot
    /// instead, once, rather than flooding a finding per route or
    /// guessing at reachability.
    #[test]
    fn routes_via_nexthop_objects_are_reported_as_a_coverage_gap() {
        let opaque = KernelRoute {
            prefix: p(198, 51, 100, 0, 24),
            oifs: Vec::new(),
            table: 254,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: true,
            gatewayed: Vec::new(),
            link_local: Vec::new(),
            encap: None,
        };
        let found = find(&[opaque.clone(), opaque.clone()], &[]);
        assert_eq!(found.len(), 1, "one summary, not one per route: {found:?}");
        assert_eq!(found[0], Uncovered::Opaque(2));
        assert_eq!(
            found[0].routes(),
            2,
            "one LINE, but it stands for two routes — the gauge counts routes"
        );
        let line = found[0].to_string();
        assert!(line.contains("nhid"), "{line}");
        assert!(line.contains("ip nexthop show"), "names the tool: {line}");

        // An exemption covering it makes it a non-issue, exactly as
        // for a route whose device we CAN see.
        assert!(find(std::slice::from_ref(&opaque), &[p(198, 51, 100, 0, 24)]).is_empty());

        // And a table no rule selects silences it for the same reason
        // it silences a readable route: no packet can use it, so
        // nobody should be sent to inspect nexthops for it (review
        // finding — this branch bypassed the filter).
        let mut parked = opaque;
        parked.table = 4242;
        let selected = [254u32, 255];
        let scoped = uncovered_paths(
            &[parked],
            &Scope {
                reach: &reach(),
                exempts: &[],
                divertible: Divertible::Any,
                selected_tables: Some(&selected),
            },
        );
        assert!(scoped.is_empty(), "{scoped:?}");
    }

    /// The scanner's scope hand-off is atomic: a result is stamped
    /// with the scope it actually scanned under, never one that
    /// arrived mid-pass.
    ///
    /// A bare counter bumped outside the inbox lock let the worker
    /// adopt nothing, read the incremented value, and stamp a scan of
    /// the OLD exemptions as the NEW scope's — which the loop would
    /// then accept as current (review finding). This drives the seam
    /// directly rather than racing threads, which is the part that
    /// can actually be asserted.
    #[test]
    fn a_result_is_stamped_with_the_scope_it_scanned_under() {
        use std::sync::{Arc, Mutex};

        /// Records the scope in force at each `uncovered()` call.
        struct Recorder {
            seen: Arc<Mutex<Vec<usize>>>,
            exempts: usize,
        }
        impl DriftWatch for Recorder {
            fn uncovered(&mut self, _: bool) -> Result<DriftFindings, ScanError> {
                self.seen.lock().unwrap().push(self.exempts);
                Ok(DriftFindings::default())
            }
            fn set_scope(&mut self, scope: DriftScope) {
                self.exempts = scope.exempts.len();
            }
        }

        let seen = Arc::new(Mutex::new(Vec::new()));
        let scanner = DriftScanner::spawn(
            Box::new(Recorder {
                seen: seen.clone(),
                exempts: 0,
            }),
            pacing(50, 0, 0),
        );
        // Generation starts at zero and only a hand-off moves it.
        assert_eq!(scanner.generation(), 0);
        scanner.set_scope(DriftScope {
            exempts: vec![p(10, 0, 0, 0, 8)],
            ..DriftScope::default()
        });
        assert_eq!(scanner.generation(), 1, "the hand-off bumps it");

        // Whatever the worker publishes, its stamp is a generation
        // that existed, and the newest one is eventually reported.
        let mut stamped_current = false;
        for _ in 0..200 {
            if let Some(ScanReport {
                generation: gen, ..
            }) = scanner.take_result()
            {
                assert!(gen <= scanner.generation(), "no stamp from the future");
                if gen == 1 {
                    stamped_current = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(
            stamped_current,
            "a scan under the new scope must be published"
        );
        assert!(
            seen.lock().unwrap().contains(&1),
            "and it must have scanned with the new exemptions"
        );
    }

    /// Teardown does not wait out a scan in flight.
    ///
    /// This drop runs on the supervision thread after the real
    /// teardown is done, and `SupervisionService::stop()` gives that
    /// thread 900 ms before it tells the operator resources may still
    /// be held. A full route dump takes seconds, so joining it made a
    /// finished teardown report itself unfinished (review finding).
    #[test]
    fn teardown_abandons_a_scan_in_flight_instead_of_waiting_for_it() {
        use std::sync::{Arc, Condvar, Mutex};

        /// Blocks inside `uncovered()` the way a real dump does, and
        /// says when it has entered.
        struct Blocking {
            entered: Arc<(Mutex<bool>, Condvar)>,
        }
        impl DriftWatch for Blocking {
            fn uncovered(&mut self, _: bool) -> Result<DriftFindings, ScanError> {
                {
                    let mut in_dump = self.entered.0.lock().unwrap();
                    *in_dump = true;
                    self.entered.1.notify_all();
                }
                std::thread::sleep(std::time::Duration::from_millis(1500));
                Ok(DriftFindings::default())
            }
            fn set_scope(&mut self, _scope: DriftScope) {}
        }

        let entered = Arc::new((Mutex::new(false), Condvar::new()));
        let scanner = DriftScanner::spawn(
            Box::new(Blocking {
                entered: entered.clone(),
            }),
            pacing(60_000, 0, 0),
        );
        // Only meaningful once the worker is actually inside the dump.
        let mut in_dump = entered.0.lock().unwrap();
        while !*in_dump {
            let (g, timed_out) = entered
                .1
                .wait_timeout(in_dump, std::time::Duration::from_secs(5))
                .unwrap();
            in_dump = g;
            assert!(!timed_out.timed_out(), "the scan never started");
        }
        drop(in_dump);

        let started = std::time::Instant::now();
        drop(scanner);
        let waited = started.elapsed();
        assert!(
            waited < std::time::Duration::from_millis(500),
            "teardown waited {waited:?} on a monitoring scan; the detach budget is 900 ms for \
             the whole supervision thread"
        );
    }

    /// The hold rule itself: a pass due within `settle` of a link change
    /// waits for it, never past `max_defer` from when it fell due, and is
    /// interruptible only until then.
    #[test]
    fn a_due_scan_waits_out_link_churn_but_never_past_max_defer() {
        use std::time::{Duration, Instant};
        let pace = pacing(60_000, 60_000, 300_000);
        let s = Duration::from_secs;
        let due = Instant::now();

        assert_eq!(pace.hold_until(due, due, None), None, "quiet links: now");
        assert_eq!(
            pace.hold_until(due + s(5), due, Some(due)),
            Some(due + s(60)),
            "a change 5 s ago holds until 60 s after it"
        );
        assert_eq!(
            pace.hold_until(due + s(61), due, Some(due)),
            None,
            "settled: now"
        );
        assert_eq!(
            pace.hold_until(due + s(280), due, Some(due + s(270))),
            Some(due + s(300)),
            "a hold never reaches past due + max_defer"
        );
        assert_eq!(
            pace.hold_until(due + s(300), due, Some(due + s(299))),
            None,
            "and at max_defer the pass runs, changes or not"
        );

        assert!(pace.interruptible(due + s(299), due));
        assert!(
            !pace.interruptible(due + s(300), due),
            "a pass that waited out max_defer reads to the end"
        );
    }

    /// Link changes as a test scripts them, beside the scans it saw.
    struct Churn {
        /// What `link_changed` returns, call by call; `None` once empty,
        /// or forever `Some` when `endless`.
        changes: Vec<&'static str>,
        endless: bool,
        /// The `interruptible` of each scan, in order.
        scans: std::sync::Arc<std::sync::Mutex<Vec<bool>>>,
        /// How many interruptible scans to abandon before one completes.
        abandon: usize,
    }
    impl DriftWatch for Churn {
        fn uncovered(&mut self, interruptible: bool) -> Result<DriftFindings, ScanError> {
            let mut scans = self.scans.lock().unwrap();
            scans.push(interruptible);
            if interruptible && self.abandon > 0 {
                self.abandon -= 1;
                return Err(ScanError::Interrupted("eth9 down".into()));
            }
            Ok(DriftFindings {
                lines: vec![format!("scan {}", scans.len())],
                ..DriftFindings::default()
            })
        }
        fn set_scope(&mut self, _scope: DriftScope) {}
        fn link_changed(&mut self) -> Option<String> {
            if self.endless {
                return Some("eth9 flapping".into());
            }
            (!self.changes.is_empty()).then(|| self.changes.remove(0).to_string())
        }
    }

    /// Wait for the scanner's next report.
    fn next_report(scanner: &DriftScanner, within: std::time::Duration) -> ScanReport {
        let deadline = std::time::Instant::now() + within;
        loop {
            if let Some(r) = scanner.take_result() {
                return r;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no report within {within:?}"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// A link that has just changed holds the first pass for `settle`
    /// instead of scanning into the churn it starts.
    #[test]
    fn a_link_change_holds_the_scan_until_links_settle() {
        let scans = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let started = std::time::Instant::now();
        let scanner = DriftScanner::spawn(
            Box::new(Churn {
                changes: vec!["br1 down"],
                endless: false,
                scans: scans.clone(),
                abandon: 0,
            }),
            pacing(60_000, 300, 60_000),
        );
        let report = next_report(&scanner, std::time::Duration::from_secs(5));
        // The change is seen after `started`, so the hold ends at least
        // `settle` after it.
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_millis(300),
            "scanned {waited:?} after a link change; it should have waited out the 300 ms settle"
        );
        assert_eq!(report.result.unwrap().lines, vec!["scan 1".to_string()]);
        assert_eq!(*scans.lock().unwrap(), vec![true]);
    }

    /// A pass a link change catches mid-read publishes nothing — not a
    /// clean verdict, not a failure — and runs again once links settle.
    #[test]
    fn a_link_change_mid_scan_abandons_it_unpublished_and_it_reruns_after_settle() {
        let scans = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let started = std::time::Instant::now();
        let scanner = DriftScanner::spawn(
            Box::new(Churn {
                changes: Vec::new(),
                endless: false,
                scans: scans.clone(),
                abandon: 1,
            }),
            pacing(60_000, 300, 60_000),
        );
        let report = next_report(&scanner, std::time::Duration::from_secs(5));
        assert_eq!(
            report.result.unwrap().lines,
            vec!["scan 2".to_string()],
            "the first report is the rerun's; the abandoned pass published nothing"
        );
        assert!(
            started.elapsed() >= std::time::Duration::from_millis(300),
            "the rerun waited out the settle after the change that abandoned the first"
        );
        assert_eq!(*scans.lock().unwrap(), vec![true, true]);
    }

    /// Links that never settle cannot blind the tripwire: at `max_defer`
    /// the pass runs and is not abandoned, though changes keep coming.
    #[test]
    fn links_that_never_settle_hold_the_scan_no_longer_than_max_defer() {
        let scans = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let started = std::time::Instant::now();
        let scanner = DriftScanner::spawn(
            Box::new(Churn {
                changes: Vec::new(),
                endless: true,
                scans: scans.clone(),
                abandon: usize::MAX,
            }),
            pacing(60_000, 60_000, 300),
        );
        let report = next_report(&scanner, std::time::Duration::from_secs(5));
        let waited = started.elapsed();
        assert!(
            waited >= std::time::Duration::from_millis(300),
            "ran after {waited:?}, before max_defer"
        );
        assert!(report.result.is_ok(), "the forced pass completes");
        assert_eq!(
            *scans.lock().unwrap(),
            vec![false],
            "one pass, run uninterruptible, never abandoned"
        );
    }

    /// The report carries the pass's wall time, for the gauge.
    #[test]
    fn a_report_carries_how_long_the_scan_took() {
        struct Slow;
        impl DriftWatch for Slow {
            fn uncovered(&mut self, _: bool) -> Result<DriftFindings, ScanError> {
                std::thread::sleep(std::time::Duration::from_millis(60));
                Err(ScanError::Unreadable("netlink recv: EIO".into()))
            }
            fn set_scope(&mut self, _scope: DriftScope) {}
        }
        let scanner = DriftScanner::spawn(Box::new(Slow), pacing(60_000, 0, 0));
        let report = next_report(&scanner, std::time::Duration::from_secs(5));
        assert!(
            report.took >= std::time::Duration::from_millis(60),
            "a failed pass is timed too: {:?}",
            report.took
        );
        assert_eq!(report.result, Err("netlink recv: EIO".to_string()));
    }

    /// The operator-facing line names the three things needed to act:
    /// what, out of where, and which table to look in.
    #[test]
    fn a_finding_names_prefix_device_and_table() {
        let found = find(&[route(p(203, 0, 113, 0, 24), "vti64")], &[]);
        let line = found[0].to_string();
        assert!(line.contains("203.0.113.0/24"), "{line}");
        assert!(line.contains("vti64"), "{line}");
        assert!(line.contains("table 100"), "{line}");
    }

    // ---- IPv6 -----------------------------------------------------------

    fn p6(addr: &str, len: u8) -> Ipv6Prefix {
        Ipv6Prefix {
            addr: addr.parse().expect("test address"),
            prefix_len: len,
        }
    }

    /// A connected (gateway-less) v6 route in the main table.
    fn route6(prefix: Ipv6Prefix, oif: &str) -> KernelRoute<Ipv6Prefix> {
        KernelRoute {
            prefix,
            oifs: vec![oif.to_string()],
            table: 254,
            drops: false,
            kernel_delivers: false,
            via_nexthop_object: false,
            gatewayed: vec![false],
            link_local: vec![false],
            encap: None,
        }
    }

    /// The same route via a gateway on every hop — link-local or global.
    fn via(mut r: KernelRoute<Ipv6Prefix>, link_local: bool) -> KernelRoute<Ipv6Prefix> {
        r.gatewayed = vec![true; r.oifs.len()];
        r.link_local = vec![link_local; r.oifs.len()];
        r
    }

    /// Against a VPP that holds nothing — every link-local candidate is
    /// then lacking, so the non-link-local tests see exactly the paths.
    fn find6(routes: &[KernelRoute<Ipv6Prefix>]) -> Vec<Uncovered<Ipv6Prefix>> {
        uncovered_paths_v6(routes, &reach(), None, |_| false)
    }

    fn lines6(found: &[Uncovered<Ipv6Prefix>]) -> Vec<String> {
        found.iter().map(Uncovered::to_string).collect()
    }

    /// The v6 comparison is the v4 one: a route whose only path leaves
    /// by a device VPP does not own is a finding (an overlay's ULA via
    /// its tunnel, a static route out an unowned interface), and one VPP
    /// can take — via a member, via a gateway on a bridge VLAN a member
    /// carries, or connected on a member — is not. A bridge's CONNECTED
    /// v6 subnet is a finding for the v4 reason: VPP places next hops
    /// there per neighbour but has no route for the subnet itself.
    #[test]
    fn v6_paths_vpp_cannot_take_are_findings_and_its_own_are_not() {
        let routes = [
            via(route6(p6("2001:db8:100::", 48), "tun0"), false), // overlay: finding
            via(route6(p6("2001:db8:200::", 48), "eth3"), false), // member: fine
            via(route6(p6("::", 0), "eth4"), false),              // default via member
            via(route6(p6("2001:db8:300::", 48), "br3998"), false), // IX peer: fine
            route6(p6("2001:db8:400::", 64), "br3998"),           // connected: finding
            route6(p6("2001:db8:500::", 64), "eth3"),             // connected on member
        ];
        assert_eq!(
            lines6(&find6(&routes)),
            [
                "2001:db8:100::/48 via tun0 (table 254)",
                "2001:db8:400::/64 via br3998 (table 254)",
            ]
        );
    }

    /// `local-route` delivers an IPv4 subnet, so the bridge it names is v4
    /// reach only. The same connected shape that is covered for v4 is a
    /// v6 finding: VPP has no v6 route onto that bridge at all.
    #[test]
    fn a_local_route_bridge_is_no_v6_reach() {
        assert!(find(&[route(p(192, 0, 2, 0, 24), "br1337")], &[]).is_empty());
        let found = find6(&[route6(p6("2001:db8:1::", 64), "br1337")]);
        assert_eq!(lines6(&found), ["2001:db8:1::/64 via br1337 (table 254)"]);
    }

    /// `local-route6` installs an attached v6 route on the bridge's
    /// BVI/subif/VF, so VPP delivers into that subnet: the kernel's
    /// connected route for it is covered, where without the line it is
    /// the permanent false finding this reach exists to prevent. The
    /// bridge is v6 reach on the terms a `local-route` bridge is v4
    /// reach — by device — and v4 reach not at all.
    #[test]
    fn a_local_route6_bridge_is_v6_reach_and_only_v6() {
        let connected = route6(p6("2001:db8:0:100::", 64), "br100");
        assert!(find6(std::slice::from_ref(&connected)).is_empty());

        // The same route with no `local-route6` naming the bridge.
        let without = VppReach {
            local_devices_v6: Vec::new(),
            ..reach()
        };
        let found = uncovered_paths_v6(&[connected], &without, None, |_| false);
        assert_eq!(
            lines6(&found),
            ["2001:db8:0:100::/64 via br100 (table 254)"]
        );

        // A route on that bridge outside the declared prefix is judged as
        // the v4 half judges one outside a `local-route` prefix on its
        // bridge: by the device, which VPP reaches. The v4 twin pins the
        // parity.
        assert!(find6(&[route6(p6("2001:db8:0:200::", 64), "br100")]).is_empty());
        assert!(find(&[route(p(198, 51, 100, 0, 24), "br1337")], &[]).is_empty());

        // v4 never reads the v6 set: a v4 connected route out a bridge only
        // `local-route6` names is a finding, as before.
        let found = find(&[route(p(203, 0, 113, 0, 24), "br100")], &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].to_string(), "203.0.113.0/24 via br100 (table 100)");

        // Applied twice (the dump, then `classify_v6`), still the v6 set.
        let twice = reach().for_v6().for_v6();
        assert_eq!(twice.local_devices, ["br100"]);
    }

    /// A kernel route with only link-local hops on owned devices, for a
    /// prefix VPP holds no route for (refused as link-local-only, or
    /// never in the feed), is a finding. Reported as ONE summary line
    /// counting every such route — a link-local BGP mesh can produce a
    /// great many — naming the first few. A route with ANY global next
    /// hop on an owned device is covered by its device. A link-local hop
    /// out a device VPP does not own is an ordinary path finding, because
    /// the device is the problem there — whatever VPP holds.
    #[test]
    fn link_local_next_hops_for_prefixes_vpp_lacks_are_one_summary() {
        let mut ecmp_one_global = via(route6(p6("2001:db8:20::", 48), "eth3"), true);
        ecmp_one_global.oifs.push("eth4".into());
        ecmp_one_global.gatewayed.push(true);
        ecmp_one_global.link_local.push(false);
        let routes = [
            via(route6(p6("::", 0), "eth3"), true), // RA-style default
            via(route6(p6("2001:db8:10::", 48), "br3998"), true), // IX peer over fe80
            ecmp_one_global,
            via(route6(p6("2001:db8:30::", 48), "wg0"), true), // unowned device
        ];
        let found = find6(&routes);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].to_string(), "2001:db8:30::/48 via wg0 (table 254)");
        assert_eq!(
            found[1],
            Uncovered::LinkLocal {
                routes: 2,
                examples: vec![
                    "::/0 via eth3 (table 254)".into(),
                    "2001:db8:10::/48 via br3998 (table 254)".into(),
                ],
            }
        );
        assert_eq!(found[1].routes(), 2, "the gauge counts routes, not lines");
        assert!(found[1].to_string().contains("link-local"), "{}", found[1]);

        // Past the example limit the line says there are more, and the
        // count stays exact.
        let many: Vec<_> = (0..5u16)
            .map(|i| via(route6(p6(&format!("2001:db8:{i:x}::"), 48), "eth3"), true))
            .collect();
        let found = find6(&many);
        let Uncovered::LinkLocal { routes, examples } = &found[0] else {
            panic!("{found:?}");
        };
        assert_eq!((*routes, examples.len()), (5, LINK_LOCAL_EXAMPLES));
        assert!(found[0].to_string().contains(", …)"), "{}", found[0]);
    }

    /// The FRR shape: an eBGP peer sends a global AND a link-local next
    /// hop, zebra installs the KERNEL route via the `fe80::` one, and the
    /// engine installs the prefix in VPP through the global one. The
    /// kernel's hops say "link-local only", VPP holds the prefix, so it is
    /// covered and must NOT be reported — flagging it would hold
    /// `exempt-drift-v6` Degraded forever over routes VPP forwards fine.
    /// Only the prefixes VPP genuinely lacks are counted.
    #[test]
    fn a_link_local_kernel_hop_is_covered_when_vpp_holds_the_prefix() {
        let held = p6("2001:db8:10::", 48); // installed via the global
        let refused = p6("2001:db8:11::", 48); // every feed next hop link-local
        let absent = p6("::", 0); // RA-learned default, never in the feed
        let routes = [
            via(route6(held, "br3998"), true),
            via(route6(refused, "eth3"), true),
            via(route6(absent, "eth3"), true),
        ];
        let vpp_holds = |p: &Ipv6Prefix| *p == held;
        let found = uncovered_paths_v6(&routes, &reach(), None, vpp_holds);
        assert_eq!(
            found,
            [Uncovered::LinkLocal {
                routes: 2,
                examples: vec![
                    "::/0 via eth3 (table 254)".into(),
                    "2001:db8:11::/48 via eth3 (table 254)".into(),
                ],
            }],
            "the held prefix is covered; the refused and the absent ones are not"
        );

        // VPP holding all of them: nothing to say.
        assert!(uncovered_paths_v6(&routes, &reach(), None, |_| true).is_empty());

        // Holding the prefix does NOT cover a path finding: a link-local
        // hop out a device VPP does not own is about the device.
        let unowned = [via(route6(held, "wg0"), true)];
        assert_eq!(
            lines6(&uncovered_paths_v6(&unowned, &reach(), None, vpp_holds)),
            ["2001:db8:10::/48 via wg0 (table 254)"]
        );
    }

    /// Not paths a diverted packet takes, so never findings, whatever
    /// device they name: link-local destinations (a router never
    /// forwards them), multicast destinations (a `33:33` frame no
    /// diversion's unicast MAC matches), and the router's own addresses
    /// — local and anycast — which have no address-level v6 remedy for
    /// this scan to name (the keeps are by port). The v4 scan reports
    /// the same local address on a `local-route` bridge, because
    /// `steer-exempt` IS its remedy.
    #[test]
    fn link_local_multicast_and_router_addresses_are_not_v6_paths() {
        let mut local = route6(p6("2001:db8:1::1", 128), "br1337");
        local.kernel_delivers = true;
        local.table = 255;
        let mut anycast = route6(p6("2001:db8:1::", 128), "br1337");
        anycast.kernel_delivers = true;
        anycast.table = 255;
        let mut multicast = route6(p6("ff00::", 8), "wg0");
        multicast.table = 255;
        let routes = [
            route6(p6("fe80::", 64), "wg0"),
            route6(p6("fe80::", 64), "br1337"),
            multicast,
            local,
            anycast,
        ];
        assert!(find6(&routes).is_empty(), "{:?}", find6(&routes));

        // The v4 twin of `local` IS a finding: an exemption can cover it.
        let mut local4 = route(p(192, 0, 2, 1, 32), "br1337");
        local4.kernel_delivers = true;
        assert_eq!(find(&[local4], &[]).len(), 1);
    }

    /// What the v4 scan drops for everyone, the v6 one drops too: routes
    /// the kernel itself drops, tables no v6 rule selects — and the
    /// nexthop-object coverage gap is reported rather than skipped. The
    /// opaque line offers no exemption: IPv6 has none.
    #[test]
    fn v6_drops_unselected_tables_and_nexthop_objects_follow_the_v4_rules() {
        let mut blackhole = route6(p6("2001:db8:dead::", 48), "tun0");
        blackhole.drops = true;
        let mut parked = via(route6(p6("2001:db8:52::", 48), "tun0"), false);
        parked.table = 4242;
        let mut in_use = via(route6(p6("2001:db8:53::", 48), "tun0"), false);
        in_use.table = 52;
        let mut opaque = route6(p6("2001:db8:60::", 48), "eth3");
        opaque.oifs.clear();
        opaque.gatewayed.clear();
        opaque.link_local.clear();
        opaque.via_nexthop_object = true;
        let routes = [blackhole, parked, in_use, opaque];

        let selected = [52u32, 254, 255];
        let found = uncovered_paths_v6(&routes, &reach(), Some(&selected), |_| false);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].table(), Some(52));
        assert_eq!(found[1], Uncovered::Opaque(1));
        let line = found[1].to_string();
        assert!(!line.contains("exempt"), "no v6 exemption exists: {line}");
        // An unreadable rule set filters nothing.
        assert_eq!(find6(&routes).len(), 3);
    }

    /// The v6 dump discards what `reach_clears` clears against the v6
    /// reach and builds link-local candidates compactly instead of as
    /// routes, and neither may change a v6 finding — the same invariant
    /// the v4 dump rests on, over the v6 shapes: a member-gatewayed bulk,
    /// a link-local bulk (the FRR mesh), a local-route bridge that is not
    /// v6 reach, a local-route6 bridge that is, and the router's own
    /// addresses. Checked against a VPP
    /// that holds the link-local bulk but not the default.
    #[test]
    fn splitting_v6_routes_at_the_dump_never_changes_the_findings() {
        let mut table: Vec<KernelRoute<Ipv6Prefix>> = (0..2_000u16)
            .map(|n| {
                let dev = if n % 2 == 0 { "eth3" } else { "eth4" };
                // Half gatewayed globally, half via fe80:: (the FRR mesh).
                via(route6(p6(&format!("2001:db8:{n:x}::"), 48), dev), n % 4 < 2)
            })
            .collect();
        let mut local = route6(p6("2001:db8:ffff::1", 128), "br1337");
        local.kernel_delivers = true;
        let mut ll_parked = via(route6(p6("2001:db8:fff2::", 48), "eth3"), true);
        ll_parked.table = 4242;
        // ECMP: a link-local member hop beside a tunnel hop.
        let mut mixed = via(route6(p6("2001:db8:fff3::", 48), "eth3"), true);
        mixed.oifs.push("tun0".into());
        mixed.gatewayed.push(true);
        mixed.link_local.push(false);
        table.extend([
            via(route6(p6("::", 0), "eth3"), true),
            via(route6(p6("2001:db8:fff0::", 48), "tun0"), false),
            route6(p6("2001:db8:fff1::", 64), "br1337"),
            route6(p6("2001:db8:fff4::", 64), "br100"),
            route6(p6("fe80::", 64), "tun0"),
            ll_parked,
            mixed,
            local,
        ]);
        let v6_reach = reach().for_v6();
        let is_candidate =
            |r: &KernelRoute<Ipv6Prefix>| link_local_candidate(r.kind(), || r.hops(), &v6_reach);
        let kept: Vec<_> = table
            .iter()
            .filter(|r| !is_candidate(r) && !r.cleared_by(&v6_reach))
            .cloned()
            .collect();
        let candidates: Vec<LinkLocalRoute> = table
            .iter()
            .filter(|r| is_candidate(r))
            .map(|r| {
                let (ll, unowned) = candidate_hops(r.hops(), &v6_reach);
                LinkLocalRoute {
                    prefix: r.prefix,
                    table: r.table,
                    oif: r.oifs[ll].as_str().into(),
                    unowned: unowned.map(|i| r.oifs[i].as_str().into()),
                }
            })
            .collect();
        assert!(kept.len() < 10, "the bulk is discarded: {}", kept.len());
        assert_eq!(
            candidates.len(),
            1_000 + 3,
            "the mesh, the default, the parked one, the mixed one"
        );

        let selected = [254u32, 255];
        // VPP holds the mesh (installed via the feed's global next hops)
        // and lacks the default, the parked prefix and the mixed one.
        let lacking = [
            p6("::", 0),
            p6("2001:db8:fff2::", 48),
            p6("2001:db8:fff3::", 48),
        ];
        let holds = |p: &Ipv6Prefix| !lacking.contains(p);
        for tables in [None, Some(&selected[..])] {
            let whole = uncovered_paths_v6(&table, &reach(), tables, holds);
            let split = classify_v6(&kept, candidates.clone(), &reach(), tables).settle(holds);
            assert_eq!(split, whole, "tables {tables:?}");
            // Paths: tun0, br1337's connected subnet, and the mixed route
            // by its tunnel hop. Summary: the default VPP lacks, plus the
            // parked one only when no table filter applies.
            let paths: Vec<String> = whole
                .iter()
                .filter(|u| matches!(u, Uncovered::Path { .. }))
                .map(Uncovered::to_string)
                .collect();
            assert_eq!(
                paths,
                [
                    "2001:db8:fff0::/48 via tun0 (table 254)",
                    "2001:db8:fff3::/48 via tun0 (table 254)",
                    "2001:db8:fff1::/64 via br1337 (table 254)",
                ]
            );
            let Some(Uncovered::LinkLocal { routes, .. }) = whole.last() else {
                panic!("{whole:?}");
            };
            assert_eq!(*routes, if tables.is_some() { 1 } else { 2 }, "{whole:?}");
        }
    }

    /// The v6 half runs only while VPP carries IPv6 AND some port line
    /// carries `v6-divert` — from config, so a `steer off` port with
    /// `v6-divert` (the staged form) already turns it on, as the v4
    /// scan runs before any lever moves.
    #[test]
    fn the_v6_half_runs_only_with_v6_on_and_a_diverting_port() {
        use packetframe_common::config::VppV6Divert;
        let cfg = |v6: bool, divert: bool, steer: bool| crate::VppOffloadConfig {
            v6,
            ports: vec![("eth4".into(), 1, steer, vec![100], None)],
            v6_divert: if divert {
                vec![("eth4".into(), VppV6Divert::Vlans(vec![100]))]
            } else {
                Vec::new()
            },
            ..crate::VppOffloadConfig::default()
        };
        let scans = |c: &crate::VppOffloadConfig| DriftScope::from_config(c, &[]).scans_v6;
        assert!(!scans(&cfg(false, false, true)), "v6 off, nothing diverted");
        assert!(!scans(&cfg(true, false, true)), "v6 on, no port diverts it");
        assert!(
            !scans(&cfg(false, true, true)),
            "no v6 table in VPP (validation refuses this; the scope must not rely on it)"
        );
        assert!(scans(&cfg(true, true, true)));
        assert!(scans(&cfg(true, true, false)), "staged behind `steer off`");
    }

    /// The retained v6 state follows the v4 rules: an inactive half says
    /// nothing, a failed read keeps the last findings but is carried with
    /// them, a whole-scan failure blinds an active half only, and a scope
    /// change clears findings but not the read failure.
    #[test]
    fn the_v6_state_is_omitted_when_inactive_or_unreadable_never_zeroed() {
        let mut s = V6DriftState::default();
        assert!(s.quiet() && !s.active);
        s.scan_failed("netlink recv: EIO");
        assert_eq!(
            s,
            V6DriftState::default(),
            "an inactive half had nothing to read"
        );

        let tun = route6(p6("2001:db8:100::", 48), "tun0");
        let held = p6("2001:db8:10::", 48);
        let scan = classify_v6(
            &[tun, via(route6(held, "eth3"), true)],
            Vec::new(),
            &reach(),
            None,
        );
        let found = vec!["2001:db8:100::/48 via tun0 (table 254)".to_string()];
        let holds = |p: &Ipv6Prefix| *p == held;
        assert_eq!(
            s.absorb(V6Drift::Scanned(scan.clone()), holds, &[]),
            Some(found.as_slice()),
            "new findings are handed back for the warning — settled, so the \
             held link-local prefix is not among them"
        );
        assert_eq!(s.routes, 1);
        assert_eq!(
            s.absorb(V6Drift::Scanned(scan.clone()), holds, &[]),
            None,
            "unchanged findings are not warned twice"
        );
        assert!(!s.quiet());
        // The same scan settled against a VPP that lost the prefix.
        s.absorb(V6Drift::Scanned(scan), |_| false, &[]);
        assert_eq!(s.routes, 2, "{:?}", s.lines);
        s.absorb(
            V6Drift::Scanned(classify_v6(
                &[route6(p6("2001:db8:100::", 48), "tun0")],
                Vec::new(),
                &reach(),
                None,
            )),
            holds,
            &[],
        );

        s.absorb(V6Drift::Unreadable("netlink recv: EIO".into()), holds, &[]);
        assert_eq!(s.lines, found, "retained across the failed read");
        assert_eq!(s.unreadable.as_deref(), Some("netlink recv: EIO"));

        s.scope_committed(true);
        assert!(s.lines.is_empty() && s.routes == 0);
        assert!(
            s.unreadable.is_some(),
            "the read failure is not the scope's"
        );

        s.absorb(V6Drift::Scanned(V6Scan::default()), holds, &[]);
        assert!(s.active && s.quiet() && s.unreadable.is_none());
        s.scan_failed("netlink socket: permission denied");
        assert!(!s.quiet(), "an active half is blind with the whole scan");

        s.absorb(V6Drift::Inactive, holds, &[]);
        assert_eq!(s, V6DriftState::default(), "no port diverts v6 any more");
    }

    /// A reload that drops the last `v6-divert` switches the v6 half off
    /// the moment its scope commits — not when the scanner next answers
    /// `Inactive`. A v4 dump failing in between must not be recorded as a
    /// v6 failure, or `exempt-drift-v6` claims a disabled scan is
    /// unreadable, for as long as the v4 dump keeps failing (review
    /// finding).
    #[test]
    fn committing_a_scope_without_v6_resets_the_half() {
        let mut s = V6DriftState::default();
        s.absorb(
            V6Drift::Scanned(classify_v6(
                &[route6(p6("2001:db8:100::", 48), "tun0")],
                Vec::new(),
                &reach(),
                None,
            )),
            |_| false,
            &[],
        );
        assert!(s.active && !s.quiet());

        s.scope_committed(false);
        assert_eq!(s, V6DriftState::default());
        s.scan_failed("netlink recv: EIO");
        assert!(
            s.quiet() && s.unreadable.is_none(),
            "a disabled half cannot be blind: {s:?}"
        );
    }

    /// An ECMP route mixing a link-local hop on a member with a hop out an
    /// unowned device: if VPP lacks the prefix, the finding is the tunnel
    /// hop, named — not a link-local summary naming the member (review
    /// finding). If VPP holds the prefix it is covered, the any-path rule
    /// the v4 scan applies to ECMP.
    #[test]
    fn a_mixed_ecmp_route_vpp_lacks_names_its_unowned_hop() {
        let mut mixed = via(route6(p6("2001:db8:40::", 48), "eth3"), true);
        mixed.oifs.push("wg0".into());
        mixed.gatewayed.push(true);
        mixed.link_local.push(false);
        let pure = via(route6(p6("2001:db8:41::", 48), "eth4"), true);
        let routes = [mixed.clone(), pure];

        let found = uncovered_paths_v6(&routes, &reach(), None, |_| false);
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].to_string(), "2001:db8:40::/48 via wg0 (table 254)");
        assert_eq!(
            found[1],
            Uncovered::LinkLocal {
                routes: 1,
                examples: vec!["2001:db8:41::/48 via eth4 (table 254)".into()],
            },
            "only the pure link-local route is summarised"
        );

        let held = p6("2001:db8:40::", 48);
        let found = uncovered_paths_v6(&[mixed.clone()], &reach(), None, |p| *p == held);
        assert!(found.is_empty(), "held = covered: {found:?}");

        // The unowned hop first in route order: same verdict, and the
        // summary's example names the owned link-local hop's device.
        let mut flipped = via(route6(p6("2001:db8:42::", 48), "wg0"), false);
        flipped.oifs.push("eth3".into());
        flipped.gatewayed.push(true);
        flipped.link_local.push(true);
        let found = uncovered_paths_v6(&[flipped], &reach(), None, |_| false);
        assert_eq!(lines6(&found), ["2001:db8:42::/48 via wg0 (table 254)"]);
    }

    // ---- drift-accept6 ---------------------------------------------------

    /// An accept covers a finding whose prefix it equals or contains, and
    /// nothing less specific: a default route via a tunnel is NOT covered
    /// by an accept for one overlay /48 inside it.
    #[test]
    fn an_accept_covers_equal_and_narrower_v6_findings_only() {
        let routes = [
            via(route6(p6("::", 0), "tun0"), false),
            via(route6(p6("2001:db8:100::", 48), "tun0"), false),
            via(route6(p6("2001:db8:100:5::", 64), "tun0"), false),
            via(route6(p6("2001:db8:200::", 48), "tun0"), false),
        ];
        let scan = classify_v6(&routes, Vec::new(), &reach(), None);
        let settled = scan.settle_accepting(|_| false, &[p6("2001:db8:100::", 48)]);
        assert_eq!(
            lines6(&settled.findings),
            [
                "::/0 via tun0 (table 254)",
                "2001:db8:200::/48 via tun0 (table 254)",
            ]
        );
        assert_eq!(
            lines6(&settled.accepted),
            [
                "2001:db8:100::/48 via tun0 (table 254)",
                "2001:db8:100:5::/64 via tun0 (table 254)",
            ]
        );
        assert!(settled.unmatched.is_empty());
        // No accepts: `settle` exactly.
        assert_eq!(
            scan.settle_accepting(|_| false, &[]).findings,
            scan.settle(|_| false)
        );
    }

    /// Every v6 category is matched per ROUTE prefix before its summary
    /// is built: a path, a nexthop-object route, a link-local candidate
    /// VPP lacks, and one that mixes in an unowned hop. Each summary on
    /// either side counts only its own routes, and a candidate VPP holds
    /// is no finding on either side — so an accept covering only that is
    /// unmatched.
    #[test]
    fn every_v6_finding_category_is_accepted_per_route() {
        let nhid = |prefix: Ipv6Prefix| {
            let mut r = route6(prefix, "eth3");
            r.oifs.clear();
            r.gatewayed.clear();
            r.link_local.clear();
            r.via_nexthop_object = true;
            r
        };
        let mut mixed = via(route6(p6("2001:db8:a4::", 48), "eth3"), true);
        mixed.oifs.push("wg0".into());
        mixed.gatewayed.push(true);
        mixed.link_local.push(false);
        let held = p6("2001:db8:c0::", 48);
        let routes = [
            via(route6(p6("2001:db8:a0::", 48), "tun0"), false),
            via(route6(p6("2001:db8:b0::", 48), "tun0"), false),
            nhid(p6("2001:db8:a1::", 48)),
            nhid(p6("2001:db8:b1::", 48)),
            nhid(p6("2001:db8:b2::", 48)),
            via(route6(p6("2001:db8:a2::", 48), "eth3"), true),
            via(route6(p6("2001:db8:b3::", 48), "br3998"), true),
            via(route6(p6("2001:db8:b4::", 48), "eth4"), true),
            mixed,
            via(route6(held, "eth3"), true),
        ];
        let scan = classify_v6(&routes, Vec::new(), &reach(), None);
        let accepts = [
            p6("2001:db8:a0::", 44), // a0..af: one of each category
            held,                    // held by VPP: no finding to match
        ];
        let settled = scan.settle_accepting(|p| *p == held, &accepts);

        assert_eq!(
            settled.findings,
            [
                Uncovered::Path {
                    prefix: p6("2001:db8:b0::", 48),
                    oif: "tun0".into(),
                    table: 254,
                    kernel_delivers: false,
                    encap: None,
                },
                Uncovered::Opaque(2),
                Uncovered::LinkLocal {
                    routes: 2,
                    examples: vec![
                        "2001:db8:b3::/48 via br3998 (table 254)".into(),
                        "2001:db8:b4::/48 via eth4 (table 254)".into(),
                    ],
                },
            ]
        );
        assert_eq!(
            settled.accepted,
            [
                Uncovered::Path {
                    prefix: p6("2001:db8:a0::", 48),
                    oif: "tun0".into(),
                    table: 254,
                    kernel_delivers: false,
                    encap: None,
                },
                Uncovered::Path {
                    prefix: p6("2001:db8:a4::", 48),
                    oif: "wg0".into(),
                    table: 254,
                    kernel_delivers: false,
                    encap: None,
                },
                Uncovered::Opaque(1),
                Uncovered::LinkLocal {
                    routes: 1,
                    examples: vec!["2001:db8:a2::/48 via eth3 (table 254)".into()],
                },
            ]
        );
        let count = |u: &[Uncovered<Ipv6Prefix>]| u.iter().map(Uncovered::routes).sum::<usize>();
        assert_eq!((count(&settled.findings), count(&settled.accepted)), (5, 4));
        assert_eq!(settled.unmatched, [held]);
    }

    /// An accept that covers no finding at all — accepted or not — is
    /// reported, in config order; a nested pair that both cover one
    /// finding are both matched.
    #[test]
    fn an_accept_that_matches_nothing_is_reported() {
        let scan = classify_v6(
            &[via(route6(p6("2001:db8:100::", 48), "tun0"), false)],
            Vec::new(),
            &reach(),
            None,
        );
        let accepts = [
            p6("2001:db8:900::", 48),
            p6("2001:db8::", 32),
            p6("2001:db8:100::", 48),
            p6("2001:db8:901::", 48),
        ];
        let settled = scan.settle_accepting(|_| false, &accepts);
        assert!(settled.findings.is_empty());
        assert_eq!(settled.accepted.len(), 1);
        assert_eq!(
            settled.unmatched,
            [p6("2001:db8:900::", 48), p6("2001:db8:901::", 48)]
        );
        // Nothing found at all: every accept is unmatched.
        let clean = V6Scan::default().settle_accepting(|_| false, &accepts);
        assert_eq!(clean.unmatched, accepts);
    }

    /// The retained state splits the count: `routes` (the degrading gauge)
    /// holds only the unaccepted findings, `accepted_routes` the rest; an
    /// accepted finding is listed, is never handed back for the warning,
    /// and leaves the half quiet when it is all there is.
    #[test]
    fn absorbed_v6_findings_split_into_open_and_accepted() {
        let scan = classify_v6(
            &[
                via(route6(p6("2001:db8:100::", 48), "tun0"), false),
                via(route6(p6("2001:db8:200::", 48), "tun0"), false),
                via(route6(p6("2001:db8:300::", 48), "eth3"), true),
            ],
            Vec::new(),
            &reach(),
            None,
        );
        let mut s = V6DriftState::default();
        let accepts = [p6("2001:db8:100::", 48), p6("2001:db8:900::", 48)];
        let warned = s
            .absorb(V6Drift::Scanned(scan.clone()), |_| false, &accepts)
            .map(<[String]>::to_vec)
            .expect("unaccepted findings are news");
        assert_eq!(warned.len(), 2, "{warned:?}");
        assert_eq!(warned[0], "2001:db8:200::/48 via tun0 (table 254)");
        assert!(
            warned[1].contains("2001:db8:300::/48 via eth3"),
            "{warned:?}"
        );
        assert_eq!((s.routes, s.accepted_routes), (2, 1));
        assert_eq!(s.accepted, ["2001:db8:100::/48 via tun0 (table 254)"]);
        assert_eq!(s.unmatched_accepts, ["2001:db8:900::/48"]);
        assert!(!s.quiet());

        // Everything accepted: quiet, nothing to warn about, still listed.
        let all = [p6("2001:db8::", 32)];
        assert_eq!(
            s.absorb(V6Drift::Scanned(scan.clone()), |_| false, &all),
            None
        );
        assert!(s.quiet() && s.active);
        assert_eq!((s.routes, s.accepted_routes), (0, 3));
        assert_eq!(
            s.accepted,
            [
                "2001:db8:100::/48 via tun0 (table 254)",
                "2001:db8:200::/48 via tun0 (table 254)",
                "1 route(s) via link-local next hops only (2001:db8:300::/48 via eth3 (table 254))",
            ]
        );
        assert!(s.unmatched_accepts.is_empty());

        // A failed read keeps them; a new scope drops them with the findings.
        s.absorb(
            V6Drift::Unreadable("netlink recv: EIO".into()),
            |_| false,
            &all,
        );
        assert_eq!(s.accepted_routes, 3, "retained across the failed read");
        s.scope_committed(true);
        assert!(s.accepted.is_empty() && s.accepted_routes == 0 && s.unmatched_accepts.is_empty());
    }

    /// Hot reload: the accepts are read when a scan LANDS, from the handle
    /// the module publishes into, so the next scan after a reload is
    /// classified under the new set — in both directions.
    #[test]
    fn a_reloaded_accept_set_reclassifies_the_next_scan() {
        let scan = classify_v6(
            &[via(route6(p6("2001:db8:100::", 48), "tun0"), false)],
            Vec::new(),
            &reach(),
            None,
        );
        let handle = std::sync::Arc::new(DriftAccepts6::default());
        let mut s = V6DriftState::default();
        s.absorb(V6Drift::Scanned(scan.clone()), |_| false, &handle.get());
        assert_eq!((s.routes, s.accepted_routes), (1, 0));

        handle.publish(vec![p6("2001:db8:100::", 48)]);
        s.absorb(V6Drift::Scanned(scan.clone()), |_| false, &handle.get());
        assert_eq!((s.routes, s.accepted_routes), (0, 1));
        assert!(s.quiet());

        handle.publish(Vec::new());
        assert_eq!(
            s.absorb(V6Drift::Scanned(scan), |_| false, &handle.get()),
            Some(["2001:db8:100::/48 via tun0 (table 254)".to_string()].as_slice()),
            "an accept taken away degrades again — and warns, as news"
        );
        assert_eq!((s.routes, s.accepted_routes), (1, 0));
    }
}
