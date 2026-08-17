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

use packetframe_common::config::Ipv4Prefix;

/// One kernel route, reduced to what the comparison needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRoute {
    /// Destination prefix. A default route is `0.0.0.0/0`.
    pub prefix: Ipv4Prefix,
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
    /// `RTN_LOCAL`: an address the kernel TERMINATES rather than a
    /// path it forwards over. Its `oif` names the interface that owns
    /// the address, which is not an egress VPP could take — so device
    /// reachability says nothing about it and must not be consulted
    /// (review finding: the local class this scan exists to cover was
    /// being skipped precisely because those addresses sit on member
    /// ports and bridges).
    pub local: bool,
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
}

impl VppReach {
    fn covers_device(&self, dev: &str) -> bool {
        self.members.iter().any(|m| m == dev) || self.local_devices.iter().any(|d| d == dev)
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

/// A kernel path VPP cannot take that nothing exempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uncovered {
    pub prefix: Ipv4Prefix,
    pub oif: String,
    pub table: u32,
    /// A terminated address rather than a forwarding path — the
    /// message says so, because the remedy reads differently.
    pub local: bool,
}

impl std::fmt::Display for Uncovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.local {
            write!(
                f,
                "{}/{} terminates on {} (table {}, the router's own address)",
                self.prefix.addr, self.prefix.prefix_len, self.oif, self.table
            )
        } else {
            write!(
                f,
                "{}/{} via {} (table {})",
                self.prefix.addr, self.prefix.prefix_len, self.oif, self.table
            )
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
    for r in routes {
        if r.drops || !scope.divertible.reaches(&r.prefix) {
            continue;
        }
        // A table no policy rule names is inert for every packet.
        if scope.selected_tables.is_some_and(|t| !t.contains(&r.table)) {
            continue;
        }
        let Some(oif) = r.oifs.first() else { continue };
        if r.local {
            // Only the segments whose hosts steering diverts. A
            // transit port's own address is reachable from a steered
            // host only by a route that would itself be a finding,
            // and reporting every address on the box would demand
            // more exemptions than the 16-slot budget holds — an
            // alarm with no available remedy is one operators learn
            // to ignore. Documented in the runbook, with the
            // null-drop gauge as the backstop for the rest.
            if !reach.local_devices.iter().any(|d| d == oif) {
                continue;
            }
        } else if r.oifs.iter().any(|d| reach.covers_device(d)) {
            continue;
        }
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
        if scope.exempts.iter().any(|e| e.contains_prefix(&r.prefix)) {
            continue;
        }
        out.push(Uncovered {
            prefix: r.prefix,
            oif: oif.clone(),
            table: r.table,
            local: r.local,
        });
    }
    out.sort_by_key(|u| (u.prefix.prefix_len, u32::from(u.prefix.addr)));
    out.dedup();
    out
}

/// The scan seam the runtime holds, mirroring [`crate::fdb::FdbWatch`]:
/// a trait so tests record calls and non-Linux builds never pretend.
pub trait DriftWatch {
    /// One line per uncovered kernel path, empty when the exemptions
    /// hold. `Err` = the kernel would not answer; the caller keeps its
    /// previous verdict.
    fn uncovered(&mut self) -> Result<Vec<String>, String>;

    /// Adopt a reloaded exemption set AND diversion scope. Called
    /// from the same place the steering target is retargeted, so the
    /// scan judges the config the operator just applied rather than
    /// the one at attach. Both travel together because both come from
    /// the same reconfigure and freezing either one re-opens the hole.
    fn set_scope(
        &mut self,
        exempts: Vec<Ipv4Prefix>,
        dst_only: Option<Vec<packetframe_common::fib::IpPrefix>>,
    );
}

/// The production scan: dump every IPv4 route in every table, compare.
#[cfg(target_os = "linux")]
pub struct KernelDriftWatch {
    pub reach: VppReach,
    /// The CURRENT exemptions. `steer-exempt` is hot-reloadable, so
    /// this is refreshed on every accepted reconfigure — a watcher
    /// frozen at attach would call a newly-unexempted path covered
    /// (the blackhole this exists to catch) and, worse, keep
    /// reporting a path the operator had just exempted BECAUSE the
    /// health message told them to (review finding).
    pub exempts: Vec<Ipv4Prefix>,
    /// Whether steering can divert anything, or only allowlisted
    /// destinations. Config-derived and restart-only, like the port
    /// directions it comes from.
    pub dst_only: Option<Vec<packetframe_common::fib::IpPrefix>>,
}

#[cfg(target_os = "linux")]
impl DriftWatch for KernelDriftWatch {
    fn uncovered(&mut self) -> Result<Vec<String>, String> {
        let routes = dump_routes()?;
        // A rule dump that fails filters nothing rather than failing
        // the scan: the routes are the finding, the rules only narrow
        // them, and losing the narrowing costs noise where losing the
        // scan costs the blackhole.
        let tables = dump_rule_tables().unwrap_or_else(|e| {
            tracing::debug!(error = %e, "policy-rule dump failed; not filtering by table");
            None
        });
        let divertible = match &self.dst_only {
            Some(allow) => Divertible::OnlyDst(allow),
            None => Divertible::Any,
        };
        let scope = Scope {
            reach: &self.reach,
            exempts: &self.exempts,
            divertible,
            selected_tables: tables.as_deref(),
        };
        Ok(uncovered_paths(&routes, &scope)
            .into_iter()
            .map(|u| u.to_string())
            .collect())
    }

    fn set_scope(
        &mut self,
        exempts: Vec<Ipv4Prefix>,
        dst_only: Option<Vec<packetframe_common::fib::IpPrefix>>,
    ) {
        self.exempts = exempts;
        self.dst_only = dst_only;
    }
}

/// One blocking RTM_GETROUTE dump across every table.
///
/// Hand-rolled on `netlink-sys` for the same reason [`crate::fdb`] is:
/// this crate runs a supervision loop, not an async runtime, and one
/// dump per minute does not earn one.
///
/// The LOCAL table is included deliberately. Its entries are the
/// router's own addresses, and steered traffic to those dies in VPP
/// exactly like tunnel-bound traffic does — that is the w23 blackhole
/// (110,917 packets in five minutes) which `steer-exempt` was
/// introduced to fix. A check that only looked at forwarding would
/// have missed the first instance of the very class it exists for.
#[cfg(target_os = "linux")]
pub fn dump_routes() -> Result<Vec<KernelRoute>, String> {
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
    use netlink_packet_route::route::{RouteAddress, RouteAttribute, RouteMessage, RouteType};
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;

    let mut route = RouteMessage::default();
    route.header.address_family = AddressFamily::Inet;
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
            match pkt.payload {
                NetlinkPayload::Done(_) => break 'dump,
                NetlinkPayload::Error(e) => return Err(format!("netlink error: {e}")),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(m)) => {
                    let mut dst: Option<std::net::Ipv4Addr> = None;
                    let mut oifs: Vec<u32> = Vec::new();
                    let mut table = u32::from(m.header.table);
                    for attr in &m.attributes {
                        match attr {
                            RouteAttribute::Destination(RouteAddress::Inet(a)) => dst = Some(*a),
                            RouteAttribute::Oif(i) => oifs.push(*i),
                            // ECMP puts its nexthops HERE and leaves
                            // RTA_OIF unset, so a route read only for
                            // RTA_OIF looks device-less and gets
                            // skipped — an all-tunnel ECMP route would
                            // blackhole under a clean health surface
                            // (review finding).
                            RouteAttribute::MultiPath(hops) => {
                                oifs.extend(hops.iter().map(|h| h.interface_index))
                            }
                            // RTA_TABLE carries ids past the u8 header
                            // field — policy tables live up there.
                            RouteAttribute::Table(t) => table = *t,
                            _ => {}
                        }
                    }
                    out.push(KernelRoute {
                        prefix: Ipv4Prefix {
                            // No RTA_DST = the default route.
                            addr: dst.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
                            prefix_len: m.header.destination_prefix_length,
                        },
                        oifs: oifs
                            .into_iter()
                            .map(|i| {
                                names
                                    .entry(i)
                                    .or_insert_with(|| crate::fdb::ifname(i))
                                    .clone()
                            })
                            .collect(),
                        table,
                        drops: matches!(
                            m.header.kind,
                            RouteType::BlackHole | RouteType::Unreachable | RouteType::Prohibit
                        ),
                        local: m.header.kind == RouteType::Local,
                    });
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
#[cfg(target_os = "linux")]
pub fn dump_rule_tables() -> Result<Option<Vec<u32>>, String> {
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
    use netlink_packet_route::rule::{RuleAttribute, RuleMessage};
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;

    let mut rule = RuleMessage::default();
    rule.header.family = AddressFamily::Inet;
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
            local: false,
        }
    }

    fn reach() -> VppReach {
        VppReach {
            members: vec!["eth3".into(), "eth4".into()],
            local_devices: vec!["br1337".into()],
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

    /// The w26 shape: tunnel-bound routes are findings, and only the
    /// ones no exemption covers.
    #[test]
    fn tunnel_paths_are_findings_until_an_exemption_covers_them() {
        let routes = vec![
            route(p(23, 191, 201, 0, 24), "vti64"), // remote site: finding
            route(p(23, 191, 200, 2, 32), "vti64"), // host inside the local /24
            route(p(0, 0, 0, 0, 0), "eth3"),        // default via a member: fine
            route(p(23, 191, 200, 0, 24), "br1337"), // local delivery: fine
            route(p(10, 0, 0, 0, 8), "eth4"),       // member: fine
        ];
        let found = find(&routes, &[]);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().all(|u| u.oif == "vti64"));

        let exempts = [p(23, 191, 201, 0, 24), p(23, 191, 200, 2, 32)];
        assert!(find(&routes, &exempts).is_empty());
    }

    /// Containment, not overlap: a /32 exemption inside a /24 route
    /// does NOT cover the /24.
    #[test]
    fn an_exemption_must_contain_the_route_not_merely_overlap_it() {
        let routes = vec![route(p(23, 191, 201, 0, 24), "vti64")];
        assert_eq!(
            find(&routes, &[p(23, 191, 201, 5, 32)]).len(),
            1,
            "a /32 inside the route must not silence the /24"
        );
        assert!(find(&routes, &[p(23, 191, 0, 0, 16)]).is_empty());
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
        let mut gw = route(p(23, 191, 200, 1, 32), "br1337");
        gw.local = true;
        gw.table = 255;
        let found = find(&[gw.clone()], &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].local);
        assert!(
            found[0].to_string().contains("terminates on br1337"),
            "the message must read as termination, not a path: {}",
            found[0]
        );
        // And the exemption an operator would add silences it.
        assert!(find(&[gw], &[p(23, 191, 200, 1, 32)]).is_empty());
    }

    /// Local addresses NOT on a steered segment are deliberately out
    /// of scope: the 16-slot budget cannot hold an exemption for every
    /// address on the box, and an alarm with no available remedy is
    /// one operators learn to ignore. Documented, with the null-drop
    /// gauge as the backstop.
    #[test]
    fn local_addresses_off_the_steered_segments_are_out_of_scope() {
        let mut transit = route(p(194, 110, 60, 51, 32), "eth3");
        transit.local = true;
        let mut loopback = route(p(127, 0, 0, 1, 32), "lo");
        loopback.local = true;
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
            local: false,
        };
        assert_eq!(find(&[all_tunnel], &[]).len(), 1);

        let mixed = KernelRoute {
            prefix: p(198, 51, 100, 0, 24),
            oifs: vec!["vti64".into(), "eth3".into()],
            table: 254,
            drops: false,
            local: false,
        };
        assert!(
            find(&[mixed], &[]).is_empty(),
            "one resolvable path is enough for VPP to forward the prefix"
        );
    }

    /// Under dst-only steering the NIC diverts only packets addressed
    /// inside the allowlist, so a path outside it can never enter VPP
    /// and must not cost an exemption slot (review finding). Any src
    /// rule anywhere restores the everything-is-at-risk scope.
    #[test]
    fn dst_only_steering_scopes_the_scan_to_divertible_destinations() {
        use packetframe_common::fib::IpPrefix;
        let allow = [IpPrefix::V4 {
            addr: [23, 191, 200, 0],
            prefix_len: 24,
        }];
        let routes = vec![
            route(p(23, 191, 200, 2, 32), "vti64"), // inside the allowlist
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
        assert_eq!(scoped[0].prefix.addr, Ipv4Addr::new(23, 191, 200, 2));

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
        let mut in_use = route(p(23, 191, 201, 0, 24), "vti64");
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
        assert_eq!(found[0].table, 100);
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
            addr: [23, 191, 200, 0],
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

    /// The operator-facing line names the three things needed to act:
    /// what, out of where, and which table to look in.
    #[test]
    fn a_finding_names_prefix_device_and_table() {
        let found = find(&[route(p(23, 191, 201, 0, 24), "vti64")], &[]);
        let line = found[0].to_string();
        assert!(line.contains("23.191.201.0/24"), "{line}");
        assert!(line.contains("vti64"), "{line}");
        assert!(line.contains("table 100"), "{line}");
    }
}
