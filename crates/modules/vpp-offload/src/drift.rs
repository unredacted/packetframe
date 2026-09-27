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
//! port line carries `v6-outbound` ([`DriftScope::scans_v6`]). Same
//! judgement ([`reach_clears`]), with four differences, each forced by
//! the v6 steering shape ([`uncovered_paths_v6`]):
//!
//! - nothing exempts. There is no v6 address rule to install (the NIC
//!   cannot match one), so `steer-exempt` does not apply and the remedy
//!   is the feed, a `steer-keep6`, or dropping `v6-outbound`;
//! - a link-local next hop is not a path. VPP refuses a route whose every
//!   next hop is link-local by design (the engine's
//!   `link_local_refused`), so such a route is a black-hole risk and is
//!   REPORTED, as one summary line, rather than cleared by its device;
//! - `local-route` bridges are not reach. `local-route` is IPv4
//!   ([`crate::LocalRoute::prefix`]), so VPP delivers no v6 subnet there;
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
    /// link-local (`fe80::/10`). VPP installs no route through one — the
    /// feed does not carry the interface that scopes it — so such a hop
    /// is no path whatever its device (see [`uncovered_paths_v6`]).
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
/// kernel bridge devices `local-route` delivers into.
#[derive(Debug, Clone, Default)]
pub struct VppReach {
    /// `port` lines — VPP owns a VF on each.
    pub members: Vec<String>,
    /// Bridge devices named (indirectly) by `local-route`: VPP
    /// delivers those prefixes on a subif, so a kernel route out the
    /// bridge is covered.
    pub local_devices: Vec<String>,
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

    /// The reach IPv6 has: the same devices minus the `local-route`
    /// bridges. A `local-route` names an IPv4 prefix, so VPP delivers
    /// that bridge's v4 subnet and no v6 one — counting the bridge as v6
    /// reach would clear exactly the connected v6 subnet VPP has no
    /// route for.
    fn for_v6(&self) -> Self {
        Self {
            local_devices: Vec::new(),
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
    /// carries `v6-outbound`.
    ///
    /// From CONFIG, not the `steer` lever, for the reason the v4 scan is
    /// installed before any port steers: the hole opens the instant the
    /// lever moves, and the operator wants it named before then. A
    /// `v6-outbound` on a `steer off` port is the staged form of exactly
    /// that; dropping `v6-outbound` is what switches the half off.
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
            scans_v6: cfg.v6 && !cfg.v6_outbound.is_empty(),
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
    /// IPv6 only: routes VPP could take but for their link-local next
    /// hops, which it refuses. One line for all of them, like
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
                "{routes} route(s) leave only through link-local next hops ({}{}), and VPP \
                 installs no route whose every next hop is link-local — the feed does not \
                 carry the interface that scopes one — so VPP holds no path of its own for \
                 them",
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
/// Reported that the v4 scan never sees: a route VPP could take but for
/// its link-local next hops ([`Uncovered::LinkLocal`]). The engine
/// refuses those by design (`link_local_refused`), so VPP has no route
/// of its own for the prefix, and diverted traffic for it takes whatever
/// less specific route VPP holds — or dies at VPP's default. That is the
/// black hole this scan exists for, so it is summarised rather than
/// hidden: counted per route (the gauge), one line (the health surface).
/// A link-local hop out a device VPP does not own is an ordinary path
/// finding instead: the device is the problem there, and the message
/// should say so.
pub fn uncovered_paths_v6(
    routes: &[KernelRoute<Ipv6Prefix>],
    reach: &VppReach,
    selected_tables: Option<&[u32]>,
) -> Vec<Uncovered<Ipv6Prefix>> {
    let reach = reach.for_v6();
    let link_local_dst = Ipv6Prefix {
        addr: std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        prefix_len: 10,
    };
    let multicast_dst = Ipv6Prefix {
        addr: std::net::Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0),
        prefix_len: 8,
    };
    let mut out = Vec::new();
    let mut opaque = 0usize;
    let mut link_local: Vec<&KernelRoute<Ipv6Prefix>> = Vec::new();
    for r in routes {
        if link_local_dst.contains_prefix(&r.prefix)
            || multicast_dst.contains_prefix(&r.prefix)
            || r.kernel_delivers
        {
            continue;
        }
        // Before the opaque and link-local branches, as in the v4 scan:
        // a route in a table no rule selects is inert, whatever it is.
        if selected_tables.is_some_and(|t| !t.contains(&r.table)) {
            continue;
        }
        if r.cleared_by(&reach) {
            continue;
        }
        if r.via_nexthop_object && r.oifs.is_empty() {
            opaque += 1;
            continue;
        }
        let Some(oif) = r.oifs.first() else { continue };
        // A hop VPP would take were its gateway not link-local: the
        // refusal, not the device, is what leaves VPP without a path.
        // Not for an encapsulating route, whose finding is the action.
        if r.encap.is_none()
            && r.hops()
                .any(|h| h.link_local && reach.covers_device(h.dev, h.gatewayed))
        {
            link_local.push(r);
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
    if opaque > 0 {
        out.push(Uncovered::Opaque(opaque));
    }
    if !link_local.is_empty() {
        link_local.sort_by_key(|r| (r.prefix.sort_key(), r.table));
        out.push(Uncovered::LinkLocal {
            routes: link_local.len(),
            examples: link_local
                .iter()
                .take(LINK_LOCAL_EXAMPLES)
                .map(|r| {
                    format!(
                        "{} via {} (table {})",
                        r.prefix.cidr(),
                        r.oifs.first().map(String::as_str).unwrap_or_default(),
                        r.table
                    )
                })
                .collect(),
        });
    }
    out
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

    /// [`reach_clears`] for a route already built.
    fn cleared_by(&self, reach: &VppReach) -> bool {
        reach_clears(
            RouteKind {
                drops: self.drops,
                kernel_delivers: self.kernel_delivers,
                via_nexthop_object: self.via_nexthop_object,
                encapsulated: self.encap.is_some(),
            },
            self.hops(),
            reach,
        )
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
    /// Scanned: `lines` and `routes` as [`DriftFindings`]' v4 pair.
    Scanned { lines: Vec<String>, routes: usize },
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
    /// Why the latest v6 read failed, if it did.
    pub unreadable: Option<String>,
}

impl V6DriftState {
    /// Take one scan's v6 verdict. Returns the findings when they are
    /// non-empty and changed, for the caller's warning.
    pub fn absorb(&mut self, v6: V6Drift) -> Option<&[String]> {
        match v6 {
            V6Drift::Inactive => {
                *self = Self::default();
                None
            }
            V6Drift::Scanned { lines, routes } => {
                let changed = !lines.is_empty() && lines != self.lines;
                *self = Self {
                    active: true,
                    lines,
                    routes,
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
    pub fn clear_findings(&mut self) {
        self.lines.clear();
        self.routes = 0;
    }

    /// Nothing for health to say: inactive, or active with a clean read.
    pub fn quiet(&self) -> bool {
        !self.active || (self.lines.is_empty() && self.unreadable.is_none())
    }
}

/// The scan seam the runtime holds, mirroring [`crate::runtime::RxModeKick`]:
/// a trait so tests record calls and non-Linux builds never pretend.
pub trait DriftWatch {
    /// The scan's findings, empty when the exemptions hold. `Err` =
    /// the kernel would not answer; the caller keeps its previous
    /// verdict.
    fn uncovered(&mut self) -> Result<DriftFindings, String>;

    /// Adopt a reloaded scope. Called from the same place the steering
    /// target is retargeted, so the scan judges the config the operator
    /// just applied rather than the one at attach.
    fn set_scope(&mut self, scope: DriftScope);
}

/// A completed pass and the scope generation it judged under.
type StampedResult = (u64, Result<DriftFindings, String>);

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
pub struct DriftScanner {
    latest: std::sync::Arc<std::sync::Mutex<Option<StampedResult>>>,
    inbox: std::sync::Arc<(std::sync::Mutex<ScannerInbox>, std::sync::Condvar)>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl DriftScanner {
    /// Start scanning every `every`, beginning immediately.
    pub fn spawn(mut watch: Box<dyn DriftWatch + Send>, every: std::time::Duration) -> Self {
        let latest: std::sync::Arc<std::sync::Mutex<Option<StampedResult>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let inbox = std::sync::Arc::new((
            std::sync::Mutex::new(ScannerInbox::default()),
            std::sync::Condvar::new(),
        ));
        let (l, ib) = (latest.clone(), inbox.clone());
        let handle = std::thread::Builder::new()
            .name("pf-drift-scan".into())
            .spawn(move || loop {
                // Adopt and stamp under ONE lock hold, so
                // `scanned_under` names exactly the scope the watcher
                // is about to scan with.
                let scanned_under = {
                    let mut inbox = ib.0.lock().expect("drift inbox lock");
                    if inbox.stop {
                        return;
                    }
                    if let Some(scope) = inbox.pending.take() {
                        watch.set_scope(scope);
                    }
                    inbox.generation
                };
                let result = watch.uncovered();
                *l.lock().expect("drift result lock") = Some((scanned_under, result));

                let mut inbox = ib.0.lock().expect("drift inbox lock");
                let mut waited = std::time::Duration::ZERO;
                // Wake early for a new scope or a teardown; otherwise
                // sleep out the interval in slices so a stop is not
                // waiting on a full one.
                while !inbox.stop && inbox.pending.is_none() && waited < every {
                    let slice = std::time::Duration::from_millis(200);
                    let (guard, _) = ib.1.wait_timeout(inbox, slice).expect("drift inbox wait");
                    inbox = guard;
                    waited += slice;
                }
                if inbox.stop {
                    return;
                }
            })
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
    /// Returns the generation it was scanned under so the caller can
    /// tell a verdict about the current configuration from one about
    /// a superseded scope.
    pub fn take_result(&self) -> Option<StampedResult> {
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

/// The production scan: dump the IPv4 routes of every table the reach
/// does not clear ([`dump_routes`]), compare — and, while some port
/// diverts IPv6, the same for IPv6 ([`dump_routes_v6`]).
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
    /// for a `v6-outbound` added or dropped under a running daemon.
    pub scope: DriftScope,
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
    fn uncovered(&mut self) -> Result<DriftFindings, String> {
        // Refreshed BEFORE the dump, which discards against this reach:
        // a stale one would drop a route via a bridge VPP no longer
        // reaches as if it were still a path VPP can take.
        self.refresh_bridged();
        let routes = dump_routes(&self.reach)?;
        // A rule dump that fails filters nothing rather than failing
        // the scan: the routes are the finding, the rules only narrow
        // them, and losing the narrowing costs noise where losing the
        // scan costs the blackhole.
        let tables =
            dump_rule_tables(netlink_packet_route::AddressFamily::Inet).unwrap_or_else(|e| {
                tracing::debug!(error = %e, "policy-rule dump failed; not filtering by table");
                None
            });
        let divertible = match &self.scope.dst_only {
            Some(allow) => Divertible::OnlyDst(allow),
            None => Divertible::Any,
        };
        let scope = Scope {
            reach: &self.reach,
            exempts: &self.scope.exempts,
            divertible,
            selected_tables: tables.as_deref(),
        };
        let found = uncovered_paths(&routes, &scope);
        // After the v4 half, which keeps its verdict whatever the v6 dump
        // does: each family's read failure is its own.
        let v6 = if self.scope.scans_v6 {
            match self.scan_v6() {
                Ok(found) => V6Drift::Scanned {
                    routes: found.iter().map(Uncovered::routes).sum(),
                    lines: found.iter().map(Uncovered::to_string).collect(),
                },
                Err(e) => V6Drift::Unreadable(e),
            }
        } else {
            V6Drift::Inactive
        };
        Ok(DriftFindings {
            routes: found.iter().map(Uncovered::routes).sum(),
            lines: found.iter().map(Uncovered::to_string).collect(),
            v6,
        })
    }

    fn set_scope(&mut self, scope: DriftScope) {
        self.scope = scope;
    }
}

#[cfg(target_os = "linux")]
impl KernelDriftWatch {
    /// The IPv6 half: the v6 routes the v6 reach does not clear, judged
    /// under the v6 policy rules. Same failure rules as the v4 half — an
    /// unreadable rule set filters nothing, an unreadable route dump is
    /// the half's `Err`.
    fn scan_v6(&self) -> Result<Vec<Uncovered<Ipv6Prefix>>, String> {
        let routes = dump_routes_v6(&self.reach)?;
        let tables =
            dump_rule_tables(netlink_packet_route::AddressFamily::Inet6).unwrap_or_else(|e| {
                tracing::debug!(error = %e, "IPv6 policy-rule dump failed; not filtering by table");
                None
            });
        Ok(uncovered_paths_v6(&routes, &self.reach, tables.as_deref()))
    }
}

/// One blocking RTM_GETROUTE dump across every table, returning only
/// the routes [`reach_clears`] does not clear under `reach`.
///
/// Hand-rolled on `netlink-sys` for the same reason [`crate::fdb`] is:
/// this crate runs a supervision loop, not an async runtime, and one
/// dump per minute does not earn one.
///
/// **Why the dump returns so little.** On a full-table router the main
/// table holds ~1.06M routes, nearly all BGP-installed via a gateway on
/// a member port — paths VPP takes, which can never be findings. They
/// are still read off the socket and parsed, but judged before a
/// `KernelRoute` is built, so the scan no longer allocates a
/// million-entry list (a String per hop, a Vec regrown to the table's
/// size) only to discard it a moment later. What comes back is what the
/// verdict can depend on: routes via a device VPP does not take (a
/// tunnel, an unreached bridge, a bridged segment's connected subnet),
/// the kernel's own addresses on `local-route` bridges, and
/// encapsulating and nexthop-object routes.
///
/// **Why the kernel does not filter it instead.** A strict-check dump
/// honours a table, a route type, a protocol and a device — each as
/// "only this one", never "all but". None of them removes the bulk
/// without hiding something the verdict needs: the main table is always
/// selected; a type filter keeps every unicast route; a protocol filter
/// would hide BGP routes via an IPSec tunnel, the w26 finding; and a
/// device filter over the non-member devices would hide encapsulation
/// out a member port, nexthop-object routes and the kernel's own
/// addresses on `local-route` bridges.
///
/// The LOCAL table is included deliberately. Its entries are the
/// router's own addresses, and steered traffic to those dies in VPP
/// exactly like tunnel-bound traffic does — that is the w23 blackhole
/// (110,917 packets in five minutes) which `steer-exempt` was
/// introduced to fix. A check that only looked at forwarding would
/// have missed the first instance of the very class it exists for.
#[cfg(target_os = "linux")]
pub fn dump_routes(reach: &VppReach) -> Result<Vec<KernelRoute>, String> {
    use netlink_packet_route::route::RouteAddress;
    dump_family(
        netlink_packet_route::AddressFamily::Inet,
        reach,
        |dst, prefix_len| Ipv4Prefix {
            // No RTA_DST = the default route.
            addr: match dst {
                Some(RouteAddress::Inet(a)) => *a,
                _ => std::net::Ipv4Addr::UNSPECIFIED,
            },
            prefix_len,
        },
    )
}

/// [`dump_routes`] for IPv6, against the v6 reach ([`VppReach::for_v6`])
/// so the discard agrees with [`uncovered_paths_v6`]. The v6 table is
/// the smaller one (a quarter of the v4 DFZ), and the same discard keeps
/// its member-gatewayed bulk from being built at all.
#[cfg(target_os = "linux")]
pub fn dump_routes_v6(reach: &VppReach) -> Result<Vec<KernelRoute<Ipv6Prefix>>, String> {
    use netlink_packet_route::route::RouteAddress;
    dump_family(
        netlink_packet_route::AddressFamily::Inet6,
        &reach.for_v6(),
        |dst, prefix_len| Ipv6Prefix {
            addr: match dst {
                Some(RouteAddress::Inet6(a)) => *a,
                _ => std::net::Ipv6Addr::UNSPECIFIED,
            },
            prefix_len,
        },
    )
}

/// The dump both families share; `prefix` builds the destination from
/// `RTA_DST` (absent for a default route) and the header's length.
#[cfg(target_os = "linux")]
fn dump_family<P>(
    family: netlink_packet_route::AddressFamily,
    reach: &VppReach,
    prefix: impl Fn(Option<&netlink_packet_route::route::RouteAddress>, u8) -> P,
) -> Result<Vec<KernelRoute<P>>, String> {
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
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;

    let mut route = RouteMessage::default();
    route.header.address_family = family;
    let mut msg = NetlinkMessage::from(RouteNetlinkMessage::GetRoute(route));
    msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.header.sequence_number = 1;
    msg.finalize();
    let mut send_buf = vec![0u8; msg.header.length as usize];
    msg.serialize(&mut send_buf);
    socket
        .send(&send_buf, 0)
        .map_err(|e| format!("netlink send: {e}"))?;

    // Interface names are resolved once per dump rather than per
    // route: a full table can carry thousands of entries out of a
    // handful of devices.
    let mut names: std::collections::HashMap<u32, String> = std::collections::HashMap::new();
    let mut out = Vec::new();
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
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(m)) => {
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
                                    hops.iter().flat_map(|h| h.attributes.iter()).find_map(|a| {
                                        match a {
                                            RouteAttribute::EncapType(t) => encap_name(*t),
                                            _ => None,
                                        }
                                    })
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
                        names.entry(i).or_insert_with(|| crate::fdb::ifname(i));
                    }
                    let name = |i: u32| names[&i].as_str();
                    let judged = hops.iter().map(|&(i, gatewayed, link_local)| Hop {
                        dev: name(i),
                        gatewayed,
                        link_local,
                    });
                    // Judged here, before anything is allocated for it:
                    // on a full-table box nearly every route is cleared.
                    if !reach_clears(kind, judged, reach) {
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
    Ok(out)
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

    fn reach() -> VppReach {
        VppReach {
            members: vec!["eth3".into(), "eth4".into()],
            local_devices: vec!["br1337".into()],
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
            fn uncovered(&mut self) -> Result<DriftFindings, String> {
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
            std::time::Duration::from_millis(50),
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
            if let Some((gen, _)) = scanner.take_result() {
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
            fn uncovered(&mut self) -> Result<DriftFindings, String> {
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
            std::time::Duration::from_secs(60),
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

    fn find6(routes: &[KernelRoute<Ipv6Prefix>]) -> Vec<Uncovered<Ipv6Prefix>> {
        uncovered_paths_v6(routes, &reach(), None)
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

    /// A route VPP could take but for its link-local next hops is a
    /// finding: the engine refuses it (`link_local_refused`), so VPP has
    /// no route of its own for the prefix. Reported as ONE summary line
    /// counting every such route — a link-local BGP mesh can produce a
    /// great many — naming the first few. A route with ANY global next
    /// hop on an owned device is covered: VPP installs through that one.
    /// A link-local hop out a device VPP does not own is an ordinary path
    /// finding, because the device is the problem there.
    #[test]
    fn link_local_next_hops_are_reported_in_one_summary() {
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
        let found = uncovered_paths_v6(&routes, &reach(), Some(&selected));
        assert_eq!(found.len(), 2, "{found:?}");
        assert_eq!(found[0].table(), Some(52));
        assert_eq!(found[1], Uncovered::Opaque(1));
        let line = found[1].to_string();
        assert!(!line.contains("exempt"), "no v6 exemption exists: {line}");
        // An unreadable rule set filters nothing.
        assert_eq!(find6(&routes).len(), 3);
    }

    /// The v6 dump discards what `reach_clears` clears against the v6
    /// reach before building a route, and that must never change a v6
    /// finding — the same invariant the v4 dump rests on, over the v6
    /// shapes: a member-gatewayed bulk, link-local next hops, a local-route
    /// bridge that is not v6 reach, and the router's own addresses.
    #[test]
    fn filtering_cleared_v6_routes_at_the_dump_never_changes_the_findings() {
        let mut table: Vec<KernelRoute<Ipv6Prefix>> = (0..2_000u16)
            .map(|n| {
                let dev = if n % 2 == 0 { "eth3" } else { "eth4" };
                via(route6(p6(&format!("2001:db8:{n:x}::"), 48), dev), false)
            })
            .collect();
        let mut local = route6(p6("2001:db8:ffff::1", 128), "br1337");
        local.kernel_delivers = true;
        table.extend([
            via(route6(p6("::", 0), "eth3"), true),
            via(route6(p6("2001:db8:fff0::", 48), "tun0"), false),
            route6(p6("2001:db8:fff1::", 64), "br1337"),
            route6(p6("fe80::", 64), "tun0"),
            local,
        ]);
        let v6_reach = reach().for_v6();
        let kept: Vec<_> = table
            .iter()
            .filter(|r| !r.cleared_by(&v6_reach))
            .cloned()
            .collect();
        assert!(kept.len() < 10, "the bulk is discarded: {}", kept.len());
        let whole = find6(&table);
        assert_eq!(whole.len(), 3, "{whole:?}");
        assert_eq!(find6(&kept), whole);
    }

    /// The v6 half runs only while VPP carries IPv6 AND some port line
    /// carries `v6-outbound` — from config, so a `steer off` port with
    /// `v6-outbound` (the staged form) already turns it on, as the v4
    /// scan runs before any lever moves.
    #[test]
    fn the_v6_half_runs_only_with_v6_on_and_a_diverting_port() {
        use packetframe_common::config::VppV6Outbound;
        let cfg = |v6: bool, divert: bool, steer: bool| crate::VppOffloadConfig {
            v6,
            ports: vec![("eth4".into(), 1, steer, vec![100], None)],
            v6_outbound: if divert {
                vec![("eth4".into(), VppV6Outbound::Vlans(vec![100]))]
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

        let found = vec!["2001:db8:100::/48 via tun0 (table 254)".to_string()];
        assert_eq!(
            s.absorb(V6Drift::Scanned {
                lines: found.clone(),
                routes: 1
            }),
            Some(found.as_slice()),
            "new findings are handed back for the warning"
        );
        assert_eq!(
            s.absorb(V6Drift::Scanned {
                lines: found.clone(),
                routes: 1
            }),
            None,
            "unchanged findings are not warned twice"
        );
        assert!(!s.quiet());

        s.absorb(V6Drift::Unreadable("netlink recv: EIO".into()));
        assert_eq!(s.lines, found, "retained across the failed read");
        assert_eq!(s.unreadable.as_deref(), Some("netlink recv: EIO"));

        s.clear_findings();
        assert!(s.lines.is_empty() && s.routes == 0);
        assert!(
            s.unreadable.is_some(),
            "the read failure is not the scope's"
        );

        s.absorb(V6Drift::Scanned {
            lines: Vec::new(),
            routes: 0,
        });
        assert!(s.active && s.quiet() && s.unreadable.is_none());
        s.scan_failed("netlink socket: permission denied");
        assert!(!s.quiet(), "an active half is blind with the whole scan");

        s.absorb(V6Drift::Inactive);
        assert_eq!(s, V6DriftState::default(), "no port diverts v6 any more");
    }
}
