//! Route-server coverage: how many of a route server's received
//! prefixes are still demoted by the next-hop gate, measured from
//! `show bgp <afi> unicast neighbors <rs> received-routes json` —
//! available for every received path, installed or not, because the
//! IX sessions run `soft-reconfiguration inbound`. This answers the
//! route-server question while every unresolved path is still safely
//! below transit: the exact unresolved next-hops and the prefix count
//! behind them.
//!
//! The JSON parser is lenient on purpose (FRR's field set varies across
//! releases): it looks for the `receivedRoutes` object and, per prefix,
//! a `nextHop` string or the first `nexthops[].ip`. The parser is
//! portable; the dump runs through the gate's `Vtysh` runner.

use std::collections::HashSet;
use std::net::IpAddr;

use serde_json::Value;

use crate::cfg::BridgeCfg;
use crate::snapshot::Ratio;
use crate::table::KernelMirror;

/// The parsed dump: `(prefix, next-hop)` for every received route with
/// a parsable next-hop, plus how many entries had none. The latter is
/// kept so `received_prefixes` stays the true count and a silently
/// understated coverage figure is impossible.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceivedRoutes {
    pub routes: Vec<(String, IpAddr)>,
    pub unparsed: u64,
}

pub fn parse_received_routes(json: &str) -> Result<ReceivedRoutes, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("received-routes json: {e}"))?;
    let routes = v
        .get("receivedRoutes")
        .or_else(|| v.get("advertisedRoutes"))
        .and_then(Value::as_object)
        .ok_or_else(|| "received-routes json: no `receivedRoutes` object".to_string())?;
    let mut out = ReceivedRoutes {
        routes: Vec::with_capacity(routes.len()),
        unparsed: 0,
    };
    for (prefix, entry) in routes {
        let nh = entry
            .get("nextHop")
            .and_then(Value::as_str)
            .or_else(|| {
                entry
                    .get("nexthops")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(|n| n.get("ip"))
                    .and_then(Value::as_str)
            })
            .and_then(|s| s.parse::<IpAddr>().ok());
        match nh {
            Some(nh) => out.routes.push((prefix.clone(), nh)),
            None => out.unparsed += 1,
        }
    }
    Ok(out)
}

/// The vtysh command for one route server's received routes.
pub fn received_routes_command(rs: IpAddr) -> String {
    let afi = if rs.is_ipv4() { "ipv4" } else { "ipv6" };
    format!("show bgp {afi} unicast neighbors {rs} received-routes json")
}

/// The join: which received prefixes the gate currently demotes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RsJoin {
    pub received_prefixes: u64,
    pub nexthops: Ratio,
    pub unresolved_nexthops: Vec<IpAddr>,
    /// Prefixes whose next-hop is neither a bilateral peer nor resolved.
    pub demoted_prefixes: u64,
}

/// A next-hop is "preferred" by the gate when it is a bilateral peer
/// (the static list) or resolves in the kernel (the runtime list).
pub fn join(
    routes: &[(String, IpAddr)],
    bridge: &BridgeCfg,
    ifindex: u32,
    mirror: &KernelMirror,
    sample_max: usize,
) -> RsJoin {
    let bilateral: HashSet<IpAddr> = bridge
        .peers
        .iter()
        .filter(|p| !p.route_server)
        .flat_map(|p| p.addrs.iter().copied())
        .collect();
    let mut nexthops: HashSet<IpAddr> = HashSet::new();
    let mut demoted = 0u64;
    for (_, nh) in routes {
        nexthops.insert(*nh);
        let ok = bilateral.contains(nh) || mirror.get(ifindex, nh).is_some_and(|e| e.resolves());
        if !ok {
            demoted += 1;
        }
    }
    let mut unresolved: Vec<IpAddr> = nexthops
        .iter()
        .filter(|nh| {
            !bilateral.contains(nh) && !mirror.get(ifindex, nh).is_some_and(|e| e.resolves())
        })
        .copied()
        .collect();
    unresolved.sort();
    let resolved = nexthops.len() as u64 - unresolved.len() as u64;
    unresolved.truncate(sample_max);
    RsJoin {
        received_prefixes: routes.len() as u64,
        nexthops: Ratio {
            resolved,
            total: nexthops.len() as u64,
        },
        unresolved_nexthops: unresolved,
        demoted_prefixes: demoted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cfg::PeerCfg;
    use crate::table::{MirrorEntry, NudState};

    const SAMPLE: &str = r#"{
      "bgpTableVersion": 7, "bgpLocalRouterId": "192.0.2.1",
      "receivedRoutes": {
        "203.0.113.0/24": {"addrPrefix":"203.0.113.0","prefixLen":24,"network":"203.0.113.0/24","nextHop":"192.0.2.10","path":"64496"},
        "203.0.113.128/25": {"network":"203.0.113.128/25","nexthops":[{"ip":"192.0.2.11","afi":"ipv4"}]},
        "198.51.100.0/24": {"network":"198.51.100.0/24","nextHop":"192.0.2.12"},
        "192.0.2.128/25": {"network":"192.0.2.128/25","nextHop":"192.0.2.10"},
        "broken": {"network":"x"}
      },
      "totalPrefixCounter": 5
    }"#;

    #[test]
    fn parses_both_nexthop_shapes_and_counts_broken_entries() {
        let parsed = parse_received_routes(SAMPLE).unwrap();
        assert_eq!(parsed.unparsed, 1);
        let mut r = parsed.routes;
        r.sort();
        assert_eq!(r.len(), 4);
        assert!(r.contains(&("203.0.113.0/24".into(), "192.0.2.10".parse().unwrap())));
        assert!(r.contains(&("203.0.113.128/25".into(), "192.0.2.11".parse().unwrap())));
        assert!(parse_received_routes("{}").is_err());
        assert!(parse_received_routes("not json").is_err());
        assert_eq!(
            received_routes_command("192.0.2.2".parse().unwrap()),
            "show bgp ipv4 unicast neighbors 192.0.2.2 received-routes json"
        );
        assert_eq!(
            received_routes_command("2001:db8::2".parse().unwrap()),
            "show bgp ipv6 unicast neighbors 2001:db8::2 received-routes json"
        );
    }

    #[test]
    fn join_counts_demoted_prefixes_not_nexthops() {
        let routes = parse_received_routes(SAMPLE).unwrap().routes;
        let bridge = BridgeCfg {
            name: "br0".into(),
            ix_mode: true,
            prefixes: vec!["192.0.2.0/24".parse().unwrap()],
            peers: vec![
                PeerCfg {
                    addrs: vec!["192.0.2.11".parse().unwrap()],
                    route_server: false,
                },
                PeerCfg {
                    addrs: vec!["192.0.2.2".parse().unwrap()],
                    route_server: true,
                },
            ],
        };
        let mut mirror = KernelMirror::default();
        mirror.upsert(
            7,
            "192.0.2.10".parse().unwrap(),
            MirrorEntry {
                state: NudState::Stale,
                mac: Some([2, 0, 0, 0, 0, 1]),
            },
        );
        // .10 resolves (two prefixes), .11 is bilateral (one), .12 is
        // neither (one prefix demoted).
        let j = join(&routes, &bridge, 7, &mirror, 10);
        assert_eq!(j.received_prefixes, 4);
        assert_eq!(
            j.nexthops,
            Ratio {
                resolved: 2,
                total: 3
            }
        );
        assert_eq!(
            j.unresolved_nexthops,
            vec!["192.0.2.12".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(j.demoted_prefixes, 1);
    }
}
