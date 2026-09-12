//! Kernel-route next-hop coverage for a bridge, and participant
//! coverage over the learned table.
//!
//! FRR installs routes with kernel **nexthop objects**: the route
//! message carries `RTA_NH_ID` and no gateway. A route dump alone
//! therefore reads zero next-hops (`ip route` shows `via` only because
//! it resolves the id for display). So every sample does two dumps:
//! `RTM_GETNEXTHOP` (small: one object per distinct next-hop, groups
//! expanded recursively, gateway-less connected objects skipped) and a
//! strict-check `RTA_OIF`-filtered route dump per family, joined
//! through the id map with the classic gateway attributes kept for the
//! non-object case.
//!
//! The nexthop message type has no decoder in the netlink crates we
//! use and libc exports none of its constants, so that dump is
//! hand-rolled on a raw `netlink_sys` socket; the byte parser is
//! portable and tested here.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::snapshot::Ratio;
use crate::table::{KernelMirror, LearnedTable};

// linux/nexthop.h
pub const RTM_NEWNEXTHOP: u16 = 104;
pub const RTM_GETNEXTHOP: u16 = 106;
const NHA_ID: u16 = 1;
const NHA_GROUP: u16 = 2;
const NHA_BLACKHOLE: u16 = 4;
const NHA_OIF: u16 = 5;
const NHA_GATEWAY: u16 = 6;
/// `struct nhmsg`: family, scope, protocol, reserved, flags(u32).
pub const NHMSG_LEN: usize = 8;
const NLA_HDR: usize = 4;
const NLA_TYPE_MASK: u16 = 0x3fff;
/// Groups nesting deeper than this are a cycle or nonsense.
const MAX_GROUP_DEPTH: usize = 8;

/// One kernel nexthop object.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NexthopObj {
    pub id: u32,
    pub gateway: Option<IpAddr>,
    pub oif: Option<u32>,
    /// Member ids when this is a group.
    pub group: Vec<u32>,
    pub blackhole: bool,
}

/// Parse the payload of one `RTM_NEWNEXTHOP` (everything after the
/// 16-byte `nlmsghdr`).
pub fn parse_nexthop_payload(payload: &[u8]) -> Option<NexthopObj> {
    if payload.len() < NHMSG_LEN {
        return None;
    }
    let family = payload[0];
    let mut obj = NexthopObj::default();
    let mut off = NHMSG_LEN;
    let mut saw_id = false;
    while off + NLA_HDR <= payload.len() {
        let nla_len = u16::from_ne_bytes([payload[off], payload[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([payload[off + 2], payload[off + 3]]) & NLA_TYPE_MASK;
        if nla_len < NLA_HDR || off + nla_len > payload.len() {
            return None;
        }
        let data = &payload[off + NLA_HDR..off + nla_len];
        match nla_type {
            NHA_ID if data.len() == 4 => {
                obj.id = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                saw_id = true;
            }
            NHA_GROUP => {
                // struct nexthop_grp { id: u32, weight: u8, resvd1: u8, resvd2: u16 }
                for chunk in data.chunks_exact(8) {
                    obj.group
                        .push(u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
                }
            }
            NHA_BLACKHOLE => obj.blackhole = true,
            NHA_OIF if data.len() == 4 => {
                obj.oif = Some(u32::from_ne_bytes([data[0], data[1], data[2], data[3]]));
            }
            NHA_GATEWAY => {
                obj.gateway = match (family, data.len()) {
                    (_, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                        data[0], data[1], data[2], data[3],
                    ))),
                    (_, 16) => {
                        let mut b = [0u8; 16];
                        b.copy_from_slice(data);
                        Some(IpAddr::V6(Ipv6Addr::from(b)))
                    }
                    _ => None,
                };
            }
            _ => {}
        }
        off += (nla_len + 3) & !3;
    }
    saw_id.then_some(obj)
}

/// Collect the gateways behind nexthop object `id` that egress `oif`,
/// expanding groups recursively with a depth guard. Gateway-less
/// objects (connected routes) contribute nothing.
pub fn expand_nexthop(
    map: &HashMap<u32, NexthopObj>,
    id: u32,
    oif: u32,
    out: &mut HashSet<IpAddr>,
    depth: usize,
) -> bool {
    if depth > MAX_GROUP_DEPTH {
        return false;
    }
    let Some(obj) = map.get(&id) else {
        return false;
    };
    if !obj.group.is_empty() {
        let mut all = true;
        for m in &obj.group {
            all &= expand_nexthop(map, *m, oif, out, depth + 1);
        }
        return all;
    }
    if obj.oif == Some(oif) {
        if let Some(gw) = obj.gateway {
            out.insert(gw);
        }
    }
    true
}

/// What one coverage sample found for a bridge.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoverageSample {
    pub nexthops: HashSet<IpAddr>,
    pub nexthop_objects: u64,
    pub routes_seen: u64,
    /// Routes whose `RTA_NH_ID` was missing from the object dump (a
    /// race between the two dumps); never counted as resolved.
    pub unknown_ids: u64,
    pub dump_ms: u64,
}

/// Join a next-hop set with the mirror: `(ratio, unresolved sample)`.
pub fn join_coverage(
    nexthops: &HashSet<IpAddr>,
    ifindex: u32,
    mirror: &KernelMirror,
    sample_max: usize,
) -> (Ratio, Vec<IpAddr>) {
    let mut resolved = 0u64;
    let mut unresolved = Vec::new();
    for nh in nexthops {
        if mirror.get(ifindex, nh).is_some_and(|e| e.resolves()) {
            resolved += 1;
        } else if unresolved.len() < sample_max {
            unresolved.push(*nh);
        }
    }
    unresolved.sort();
    (
        Ratio {
            resolved,
            total: nexthops.len() as u64,
        },
        unresolved,
    )
}

/// Fraction of learned addresses whose kernel entry resolves.
pub fn participant_coverage(table: &LearnedTable, ifindex: u32, mirror: &KernelMirror) -> Ratio {
    let mut resolved = 0u64;
    for (ip, _) in table.iter() {
        if mirror.get(ifindex, ip).is_some_and(|e| e.resolves()) {
            resolved += 1;
        }
    }
    Ratio {
        resolved,
        total: table.len() as u64,
    }
}

#[cfg(target_os = "linux")]
pub use linux::{dump_nexthops_blocking, sample};

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::time::Instant;

    use futures::TryStreamExt;
    use netlink_packet_route::route::{
        RouteAddress, RouteAttribute, RouteHeader, RouteProtocol, RouteVia,
    };
    use netlink_packet_route::AddressFamily;
    use rtnetlink::{Handle, RouteMessageBuilder};

    // linux/netlink.h
    const NLMSG_HDR: usize = 16;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const NLM_F_REQUEST: u16 = 0x01;
    const NLM_F_DUMP: u16 = 0x300;

    /// One blocking `RTM_GETNEXTHOP` dump: `id → object`. The table is
    /// one object per distinct next-hop, so no filter is needed.
    pub fn dump_nexthops_blocking() -> Result<HashMap<u32, NexthopObj>, String> {
        use rtnetlink::sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

        let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
        socket
            .bind_auto()
            .map_err(|e| format!("netlink bind: {e}"))?;
        socket
            .connect(&SocketAddr::new(0, 0))
            .map_err(|e| format!("netlink connect: {e}"))?;
        // A bounded receive so a wedged dump cannot hang the sampler.
        let tv = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        // SAFETY: `tv` is a timeval of exactly the passed length.
        let rc = unsafe {
            libc::setsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&socket),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                std::ptr::addr_of!(tv).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(format!("SO_RCVTIMEO: {}", std::io::Error::last_os_error()));
        }

        // nlmsghdr + nhmsg, all zero but the header fields.
        let mut req = vec![0u8; NLMSG_HDR + NHMSG_LEN];
        req[0..4].copy_from_slice(&((NLMSG_HDR + NHMSG_LEN) as u32).to_ne_bytes());
        req[4..6].copy_from_slice(&RTM_GETNEXTHOP.to_ne_bytes());
        req[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req[8..12].copy_from_slice(&1u32.to_ne_bytes());
        // nh_family = AF_UNSPEC (0): both families.
        socket
            .send(&req, 0)
            .map_err(|e| format!("netlink send: {e}"))?;

        let mut out = HashMap::new();
        let mut buf = vec![0u8; 64 * 1024];
        'dump: loop {
            let n = socket
                .recv(&mut &mut buf[..], 0)
                .map_err(|e| format!("netlink recv: {e}"))?;
            let mut off = 0usize;
            while off + NLMSG_HDR <= n {
                let len = u32::from_ne_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
                    as usize;
                let kind = u16::from_ne_bytes([buf[off + 4], buf[off + 5]]);
                if len < NLMSG_HDR || off + len > n {
                    return Err("netlink: malformed message length".into());
                }
                let payload = &buf[off + NLMSG_HDR..off + len];
                match kind {
                    NLMSG_DONE => break 'dump,
                    NLMSG_ERROR => {
                        let errno = payload
                            .get(0..4)
                            .map(|b| i32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
                            .unwrap_or(0);
                        if errno != 0 {
                            return Err(format!(
                                "RTM_GETNEXTHOP: {}",
                                std::io::Error::from_raw_os_error(-errno)
                            ));
                        }
                        break 'dump;
                    }
                    RTM_NEWNEXTHOP => {
                        if let Some(obj) = parse_nexthop_payload(payload) {
                            out.insert(obj.id, obj);
                        }
                    }
                    _ => {}
                }
                off += (len + 3) & !3;
            }
        }
        Ok(out)
    }

    fn push_gateway(out: &mut HashSet<IpAddr>, attr: &RouteAttribute) {
        match attr {
            RouteAttribute::Gateway(RouteAddress::Inet(a)) => {
                out.insert(IpAddr::V4(*a));
            }
            RouteAttribute::Gateway(RouteAddress::Inet6(a)) => {
                out.insert(IpAddr::V6(*a));
            }
            RouteAttribute::Via(RouteVia::Inet(a)) => {
                out.insert(IpAddr::V4(*a));
            }
            RouteAttribute::Via(RouteVia::Inet6(a)) => {
                out.insert(IpAddr::V6(*a));
            }
            _ => {}
        }
    }

    async fn dump_routes(
        strict: &Handle,
        ifindex: u32,
        v6: bool,
        objects: &HashMap<u32, NexthopObj>,
        sample: &mut CoverageSample,
    ) -> Result<(), String> {
        let mut builder = RouteMessageBuilder::<IpAddr>::new()
            .output_interface(ifindex)
            .table_id(u32::from(RouteHeader::RT_TABLE_MAIN));
        {
            let header = &mut builder.get_mut().header;
            header.address_family = if v6 {
                AddressFamily::Inet6
            } else {
                AddressFamily::Inet
            };
            // The builder presets `protocol = Static`; under strict check
            // that is a filter and the dump would return only static
            // routes. Unspec means "any".
            header.protocol = RouteProtocol::Unspec;
        }
        let msg = builder.build();
        let mut routes = strict.route().get(msg).execute();
        while let Some(route) = routes
            .try_next()
            .await
            .map_err(|e| format!("route dump: {e}"))?
        {
            sample.routes_seen += 1;
            for attr in &route.attributes {
                match attr {
                    RouteAttribute::NhId(id) => {
                        if !expand_nexthop(objects, *id, ifindex, &mut sample.nexthops, 0) {
                            sample.unknown_ids += 1;
                        }
                    }
                    RouteAttribute::MultiPath(hops) => {
                        for h in hops {
                            if h.interface_index == ifindex {
                                for a in &h.attributes {
                                    push_gateway(&mut sample.nexthops, a);
                                }
                            }
                        }
                    }
                    other => push_gateway(&mut sample.nexthops, other),
                }
            }
        }
        Ok(())
    }

    /// One full sample for a bridge: nexthop objects, then both
    /// families' filtered route dumps.
    pub async fn sample(strict: &Handle, ifindex: u32) -> Result<CoverageSample, String> {
        let started = Instant::now();
        let objects = tokio::task::spawn_blocking(dump_nexthops_blocking)
            .await
            .map_err(|e| format!("nexthop dump task: {e}"))??;
        let mut sample = CoverageSample {
            nexthop_objects: objects.len() as u64,
            ..Default::default()
        };
        dump_routes(strict, ifindex, false, &objects, &mut sample).await?;
        dump_routes(strict, ifindex, true, &objects, &mut sample).await?;
        sample.dump_ms = started.elapsed().as_millis() as u64;
        Ok(sample)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Source;
    use crate::table::{MirrorEntry, NudState};
    use std::time::{Instant, SystemTime};

    fn nla(t: u16, data: &[u8]) -> Vec<u8> {
        let len = (NLA_HDR + data.len()) as u16;
        let mut v = Vec::new();
        v.extend_from_slice(&len.to_ne_bytes());
        v.extend_from_slice(&t.to_ne_bytes());
        v.extend_from_slice(data);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    fn nhmsg(family: u8, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![family, 0, 0, 0, 0, 0, 0, 0];
        for a in attrs {
            v.extend_from_slice(a);
        }
        v
    }

    fn grp(members: &[u32]) -> Vec<u8> {
        let mut d = Vec::new();
        for m in members {
            d.extend_from_slice(&m.to_ne_bytes());
            d.extend_from_slice(&[1, 0, 0, 0]);
        }
        nla(NHA_GROUP, &d)
    }

    #[test]
    fn parses_single_gateway_objects_both_families() {
        let v4 = nhmsg(
            2,
            &[
                nla(NHA_ID, &10u32.to_ne_bytes()),
                nla(NHA_OIF, &7u32.to_ne_bytes()),
                nla(NHA_GATEWAY, &[192, 0, 2, 10]),
            ],
        );
        let o = parse_nexthop_payload(&v4).unwrap();
        assert_eq!(o.id, 10);
        assert_eq!(o.oif, Some(7));
        assert_eq!(o.gateway, Some("192.0.2.10".parse().unwrap()));
        assert!(o.group.is_empty());

        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let v6 = nhmsg(
            10,
            &[
                nla(NHA_ID, &11u32.to_ne_bytes()),
                nla(NHA_OIF, &7u32.to_ne_bytes()),
                nla(NHA_GATEWAY, &ll.octets()),
            ],
        );
        let o = parse_nexthop_payload(&v6).unwrap();
        assert_eq!(o.gateway, Some(IpAddr::V6(ll)));
    }

    #[test]
    fn gateway_less_connected_object_contributes_nothing() {
        let dev_only = nhmsg(
            2,
            &[
                nla(NHA_ID, &12u32.to_ne_bytes()),
                nla(NHA_OIF, &7u32.to_ne_bytes()),
            ],
        );
        let o = parse_nexthop_payload(&dev_only).unwrap();
        assert_eq!(o.gateway, None);
        let mut map = HashMap::new();
        map.insert(12, o);
        let mut out = HashSet::new();
        assert!(expand_nexthop(&map, 12, 7, &mut out, 0));
        assert!(out.is_empty());
    }

    #[test]
    fn groups_expand_recursively_with_cycle_guard() {
        let mut map = HashMap::new();
        for (id, last) in [(10u32, 10u8), (11, 11)] {
            map.insert(
                id,
                NexthopObj {
                    id,
                    gateway: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))),
                    oif: Some(7),
                    group: vec![],
                    blackhole: false,
                },
            );
        }
        // An object on another interface must not leak in.
        map.insert(
            13,
            NexthopObj {
                id: 13,
                gateway: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
                oif: Some(8),
                ..Default::default()
            },
        );
        let group = parse_nexthop_payload(&nhmsg(
            0,
            &[nla(NHA_ID, &20u32.to_ne_bytes()), grp(&[10, 11, 13])],
        ))
        .unwrap();
        assert_eq!(group.group, vec![10, 11, 13]);
        map.insert(20, group);
        map.insert(
            21,
            NexthopObj {
                id: 21,
                group: vec![20],
                ..Default::default()
            },
        );
        let mut out = HashSet::new();
        assert!(expand_nexthop(&map, 21, 7, &mut out, 0));
        assert_eq!(out.len(), 2);
        assert!(out.contains(&"192.0.2.10".parse().unwrap()));
        assert!(!out.contains(&"198.51.100.1".parse().unwrap()));

        // Self-referencing group terminates and reports incompleteness.
        map.insert(
            30,
            NexthopObj {
                id: 30,
                group: vec![30],
                ..Default::default()
            },
        );
        let mut out = HashSet::new();
        assert!(!expand_nexthop(&map, 30, 7, &mut out, 0));
        // Unknown id is incomplete too.
        assert!(!expand_nexthop(&map, 99, 7, &mut out, 0));
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        assert!(parse_nexthop_payload(&[0u8; 4]).is_none());
        // No NHA_ID at all.
        assert!(parse_nexthop_payload(&nhmsg(2, &[nla(NHA_OIF, &7u32.to_ne_bytes())])).is_none());
        // Attribute claiming to run past the end.
        let mut bad = nhmsg(2, &[nla(NHA_ID, &1u32.to_ne_bytes())]);
        bad.extend_from_slice(&[40u8, 0, 6, 0, 1, 2]);
        assert!(parse_nexthop_payload(&bad).is_none());
    }

    #[test]
    fn join_and_participant_coverage() {
        let mut mirror = KernelMirror::default();
        let a: IpAddr = "192.0.2.10".parse().unwrap();
        let b: IpAddr = "192.0.2.11".parse().unwrap();
        let c: IpAddr = "192.0.2.12".parse().unwrap();
        mirror.upsert(
            7,
            a,
            MirrorEntry {
                state: NudState::Stale,
                mac: Some([2, 0, 0, 0, 0, 1]),
            },
        );
        mirror.upsert(
            7,
            b,
            MirrorEntry {
                state: NudState::Failed,
                mac: None,
            },
        );
        let nexthops: HashSet<IpAddr> = [a, b, c].into_iter().collect();
        let (ratio, unresolved) = join_coverage(&nexthops, 7, &mirror, 10);
        assert_eq!(
            ratio,
            Ratio {
                resolved: 1,
                total: 3
            }
        );
        assert_eq!(unresolved, vec![b, c]);
        // Sample cap.
        let (_, capped) = join_coverage(&nexthops, 7, &mirror, 1);
        assert_eq!(capped.len(), 1);

        let mut table = LearnedTable::new(16);
        let now = SystemTime::now();
        let mono = Instant::now();
        table.observe(a, [2, 0, 0, 0, 0, 1], Source::ArpRequest, now, mono);
        table.observe(b, [2, 0, 0, 0, 0, 2], Source::ArpRequest, now, mono);
        assert_eq!(
            participant_coverage(&table, 7, &mirror),
            Ratio {
                resolved: 1,
                total: 2
            }
        );
    }
}
