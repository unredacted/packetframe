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
    /// Output device name, or `None` for routes with no oif (which
    /// this check ignores — nothing to compare against).
    pub oif: Option<String>,
    /// Routing table id, for the operator-facing message: "table 100"
    /// is how they will find it again.
    pub table: u32,
    /// Whether the kernel would DROP this itself (blackhole,
    /// unreachable, prohibit). VPP dropping the same packet is
    /// equivalent behaviour, so these are not findings.
    pub drops: bool,
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

/// A kernel path VPP cannot take that nothing exempts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uncovered {
    pub prefix: Ipv4Prefix,
    pub oif: String,
    pub table: u32,
}

impl std::fmt::Display for Uncovered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} via {} (table {})",
            self.prefix.addr, self.prefix.prefix_len, self.oif, self.table
        )
    }
}

/// The pure half: which kernel routes would blackhole under steering.
///
/// A route is a finding iff it egresses a device VPP cannot use, the
/// kernel does not drop it itself, and no `steer-exempt` covers its
/// prefix. Deliberately NOT filtered by the allowlist: with source
/// steering, which packets get diverted is decided by where they came
/// FROM, so any destination a steered host can reach is at risk.
///
/// Coverage is by prefix containment, and an exempt must contain the
/// route — not merely overlap it. A `/32` exemption does not cover the
/// `/24` around it, and reporting the `/24` as handled because one
/// host inside it is exempted would be the silent-hole shape all over
/// again.
pub fn uncovered_paths(
    routes: &[KernelRoute],
    reach: &VppReach,
    exempts: &[Ipv4Prefix],
) -> Vec<Uncovered> {
    let mut out = Vec::new();
    for r in routes {
        if r.drops {
            continue;
        }
        let Some(oif) = &r.oif else { continue };
        if reach.covers_device(oif) {
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
        if exempts.iter().any(|e| e.contains_prefix(&r.prefix)) {
            continue;
        }
        out.push(Uncovered {
            prefix: r.prefix,
            oif: oif.clone(),
            table: r.table,
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
}

/// The production scan: dump every IPv4 route in every table, compare.
#[cfg(target_os = "linux")]
pub struct KernelDriftWatch {
    pub reach: VppReach,
    pub exempts: Vec<Ipv4Prefix>,
}

#[cfg(target_os = "linux")]
impl DriftWatch for KernelDriftWatch {
    fn uncovered(&mut self) -> Result<Vec<String>, String> {
        let routes = dump_routes()?;
        Ok(uncovered_paths(&routes, &self.reach, &self.exempts)
            .into_iter()
            .map(|u| u.to_string())
            .collect())
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
                    let mut oif: Option<u32> = None;
                    let mut table = u32::from(m.header.table);
                    for attr in &m.attributes {
                        match attr {
                            RouteAttribute::Destination(RouteAddress::Inet(a)) => dst = Some(*a),
                            RouteAttribute::Oif(i) => oif = Some(*i),
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
                        oif: oif.map(|i| {
                            names
                                .entry(i)
                                .or_insert_with(|| crate::fdb::ifname(i))
                                .clone()
                        }),
                        table,
                        drops: matches!(
                            m.header.kind,
                            RouteType::BlackHole | RouteType::Unreachable | RouteType::Prohibit
                        ),
                    });
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
            oif: Some(oif.to_string()),
            table: 100,
            drops: false,
        }
    }

    fn reach() -> VppReach {
        VppReach {
            members: vec!["eth3".into(), "eth4".into()],
            local_devices: vec!["br1337".into()],
        }
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
        let found = uncovered_paths(&routes, &reach(), &[]);
        assert_eq!(found.len(), 2, "{found:?}");
        assert!(found.iter().any(|u| u.oif == "vti64"));

        // Exempting both silences it.
        let exempts = [p(23, 191, 201, 0, 24), p(23, 191, 200, 2, 32)];
        assert!(uncovered_paths(&routes, &reach(), &exempts).is_empty());
    }

    /// Containment, not overlap: a /32 exemption inside a /24 route
    /// does NOT cover the /24. Reporting it as handled because one
    /// host is exempted is the silent-hole shape this exists to end.
    #[test]
    fn an_exemption_must_contain_the_route_not_merely_overlap_it() {
        let routes = vec![route(p(23, 191, 201, 0, 24), "vti64")];
        let too_narrow = [p(23, 191, 201, 5, 32)];
        assert_eq!(
            uncovered_paths(&routes, &reach(), &too_narrow).len(),
            1,
            "a /32 inside the route must not silence the /24"
        );
        // The other direction is genuine cover.
        let wide = [p(23, 191, 0, 0, 16)];
        assert!(uncovered_paths(&routes, &reach(), &wide).is_empty());
    }

    /// Routes the kernel drops itself are not findings: VPP dropping
    /// the same packet is the same outcome, one hop earlier. The
    /// reference primary's bird carries a service host as
    /// `unreachable`, and flagging it would be permanent noise.
    #[test]
    fn routes_the_kernel_itself_drops_are_not_findings() {
        let mut blackhole = route(p(198, 18, 0, 0, 15), "vti64");
        blackhole.drops = true;
        let mut no_oif = route(p(203, 0, 113, 0, 24), "vti64");
        no_oif.oif = None;
        let found = uncovered_paths(&[blackhole, no_oif], &reach(), &[]);
        assert!(found.is_empty(), "{found:?}");
    }

    /// Broadcast and multicast are exempted on every steered port
    /// without a directive, so the scan must not demand config for
    /// what is already handled.
    #[test]
    fn the_built_in_exemptions_count_as_cover() {
        let routes = vec![
            route(p(224, 0, 0, 0, 4), "vti64"),
            route(p(255, 255, 255, 255, 32), "vti64"),
        ];
        assert!(uncovered_paths(&routes, &reach(), &[]).is_empty());
    }

    /// The operator-facing line names the three things needed to act:
    /// what, out of where, and which table to look in.
    #[test]
    fn a_finding_names_prefix_device_and_table() {
        let mut r = route(p(23, 191, 201, 0, 24), "vti64");
        r.table = 100;
        let found = uncovered_paths(&[r], &reach(), &[]);
        let line = found[0].to_string();
        assert!(line.contains("23.191.201.0/24"), "{line}");
        assert!(line.contains("vti64"), "{line}");
        assert!(line.contains("table 100"), "{line}");
    }
}
