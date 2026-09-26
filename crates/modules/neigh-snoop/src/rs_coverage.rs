//! Route-server coverage: how many of a route server's received
//! prefixes are still demoted by the next-hop gate, measured from
//! `show bgp <afi> unicast neighbors <rs> received-routes json` —
//! available for every received path, installed or not, because the
//! IX sessions run `soft-reconfiguration inbound`. This answers the
//! route-server question while every unresolved path is still safely
//! below transit: the exact unresolved next-hops and the prefix count
//! behind them.
//!
//! **The next-hop key depends on the family.** FRR renders each
//! received path with `route_vty_out_tmp`, which writes `nextHop` for
//! an IPv4 next-hop and `nextHopGlobal` for an IPv6 one (10.0 through
//! master), and no link-local at all. The first parser knew only
//! `nextHop`, so every IPv6 route read as "without a parsable
//! next-hop" and the v6 half of the check was blind. The richer
//! `nexthops[]` array of other renderings is still accepted.
//!
//! **The global next-hop is the one checked.** It is the address the
//! route server passes through unchanged from the announcing
//! participant, the one the gate's prefix-lists hold (link-locals are
//! never listed), and the one `set ipv6 next-hop prefer-global`
//! installs. A link-local on a route-server path, when there is one, is
//! normally the route server's own and says nothing about the
//! participant.
//!
//! Lenient about the field set (it varies across releases), not about
//! types, and only the fields read are deserialised: a route-server
//! dump is 70k–150k entries of about ten fields each, and a generic
//! JSON tree builds every one of them. The parser is portable; the
//! dump runs through the gate's `Vtysh` runner.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use serde::Deserialize;

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

/// Unknown fields are skipped without being built, which is where the
/// memory goes in a generic tree.
#[derive(Deserialize)]
struct Dump {
    #[serde(rename = "receivedRoutes")]
    received: Option<HashMap<String, Entry>>,
    #[serde(rename = "advertisedRoutes")]
    advertised: Option<HashMap<String, Entry>>,
    /// FRR's answer when it has no table to show (no such neighbour,
    /// soft-reconfiguration off).
    warning: Option<String>,
}

#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "nextHopGlobal")]
    next_hop_global: Option<String>,
    #[serde(rename = "nextHop")]
    next_hop: Option<String>,
    #[serde(default)]
    nexthops: Vec<Nexthop>,
}

#[derive(Deserialize)]
struct Nexthop {
    ip: Option<String>,
}

impl Entry {
    /// `nextHopGlobal`, else `nextHop`, else the first `nexthops[]`
    /// address that is not link-local.
    fn nexthop(&self) -> Option<IpAddr> {
        let parse = |s: &String| s.parse::<IpAddr>().ok();
        self.next_hop_global
            .as_ref()
            .and_then(parse)
            .or_else(|| self.next_hop.as_ref().and_then(parse))
            .or_else(|| {
                self.nexthops
                    .iter()
                    .filter_map(|n| n.ip.as_ref().and_then(parse))
                    .find(|ip| !matches!(ip, IpAddr::V6(v) if v.is_unicast_link_local()))
            })
    }
}

/// Parse one dump. The object is located first: FRR 10's vtysh output
/// is per daemon (zebra's `%` line and a `BGP:` header ahead of bgpd's
/// answer — the shape that silenced the gate once, see
/// `frr_gate::parse_prefix_list`), and a line in front of the object
/// must read as the data it precedes, never as a failed dump.
pub fn parse_received_routes(out: &str) -> Result<ReceivedRoutes, String> {
    let mut starts = json_starts(out);
    let first = starts.next().ok_or_else(|| {
        format!(
            "received-routes json: no JSON object in the reply: {:?}",
            first_line(out)
        )
    })?;
    let dump = match dump_at(out, first) {
        Ok(d) => d,
        // FRR 10 prints the braces around a table before it knows there
        // is none, so "soft reconfiguration not enabled" and "no such
        // address family" arrive as `{` / `{"warning":…}` / `}`. The
        // inner object is the message worth reporting.
        Err(e) => match starts.next().and_then(|s| dump_at(out, s).ok()) {
            Some(d) if d.warning.is_some() => d,
            _ => return Err(format!("received-routes json: {e}")),
        },
    };
    let routes = match (dump.received, dump.advertised) {
        (Some(r), _) | (None, Some(r)) => r,
        (None, None) => {
            return Err(match dump.warning {
                Some(w) => format!("received-routes json: FRR says: {w}"),
                None => "received-routes json: no `receivedRoutes` object".to_string(),
            })
        }
    };
    let mut parsed = ReceivedRoutes {
        routes: Vec::with_capacity(routes.len()),
        unparsed: 0,
    };
    for (prefix, entry) in routes {
        match entry.nexthop() {
            Some(nh) => parsed.routes.push((prefix, nh)),
            None => parsed.unparsed += 1,
        }
    }
    Ok(parsed)
}

/// Byte offsets of the lines that open a JSON object.
fn json_starts(out: &str) -> impl Iterator<Item = usize> + '_ {
    out.split_inclusive('\n')
        .scan(0usize, |off, line| {
            let at = *off;
            *off += line.len();
            Some((at, line))
        })
        .filter_map(|(at, line)| {
            let body = line.trim_start();
            body.starts_with('{')
                .then_some(at + line.len() - body.len())
        })
}

/// The first JSON value at `start`; whatever follows it is ignored.
fn dump_at(out: &str, start: usize) -> Result<Dump, serde_json::Error> {
    Dump::deserialize(&mut serde_json::Deserializer::from_str(&out[start..]))
}

/// The first non-blank line, bounded, for an error message.
fn first_line(out: &str) -> &str {
    let l = out
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    match l.char_indices().nth(120) {
        Some((i, _)) => &l[..i],
        None => l,
    }
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

    /// `show bgp ipv6 unicast neighbors <rs> received-routes json` as
    /// FRR 10 writes it: the header fields and `{`/`}` printed by hand
    /// around one `vty_json_no_pretty` object, `nextHopGlobal` per
    /// path, no link-local.
    const V6_FRR10: &str = "{\n\"bgpTableVersion\":0,\"bgpLocalRouterId\":\"192.0.2.1\",\
\"defaultLocPrf\":100,\"localAS\":64496,\"receivedRoutes\": {\
\"2001:db8:100::/48\":{\"addrPrefix\":\"2001:db8:100::\",\"prefixLen\":48,\
\"network\":\"2001:db8:100::/48\",\"nextHopGlobal\":\"2001:db8:16::10\",\"weight\":0,\
\"path\":\"64497\",\"origin\":\"IGP\",\"valid\":true,\"best\":true},\
\"2001:db8:ffff:ffff:ffff:ffff::/96\":{\"addrPrefix\":\"2001:db8:ffff:ffff:ffff:ffff::\",\
\"prefixLen\":96,\"network\":\"2001:db8:ffff:ffff:ffff:ffff::/96\",\
\"nextHopGlobal\":\"2001:db8:16:ffff:ffff:ffff:ffff:ffff\",\"metric\":0,\"weight\":0,\
\"path\":\"64498 64499 64500\",\"origin\":\"incomplete\",\"valid\":true,\"best\":true}},\
\"totalPrefixCounter\":2,\"filteredPrefixCounter\":0}\n";

    #[test]
    fn parses_frr10_ipv6_next_hop_global() {
        let mut r = parse_received_routes(V6_FRR10).unwrap();
        assert_eq!(
            r.unparsed, 0,
            "the production failure: every v6 route unparsed"
        );
        r.routes.sort();
        assert_eq!(
            r.routes,
            vec![
                (
                    "2001:db8:100::/48".to_string(),
                    "2001:db8:16::10".parse().unwrap()
                ),
                (
                    "2001:db8:ffff:ffff:ffff:ffff::/96".to_string(),
                    "2001:db8:16:ffff:ffff:ffff:ffff:ffff".parse().unwrap()
                ),
            ]
        );
    }

    #[test]
    fn nexthops_array_checks_the_global_never_the_link_local() {
        let json = r#"{"receivedRoutes":{
          "2001:db8:1::/48":{"nexthops":[
            {"ip":"fe80::2:ff:fe00:1","afi":"ipv6","scope":"link-local"},
            {"ip":"2001:db8:16::11","afi":"ipv6","scope":"global"}]},
          "2001:db8:2::/48":{"nexthops":[
            {"ip":"2001:db8:16::12","afi":"ipv6","scope":"global"},
            {"ip":"fe80::2:ff:fe00:2","afi":"ipv6","scope":"link-local"}]},
          "2001:db8:3::/48":{"nexthops":[
            {"ip":"fe80::2:ff:fe00:3","afi":"ipv6","scope":"link-local"}]}
        }}"#;
        let mut r = parse_received_routes(json).unwrap();
        r.routes.sort();
        assert_eq!(
            r.routes,
            vec![
                (
                    "2001:db8:1::/48".to_string(),
                    "2001:db8:16::11".parse().unwrap()
                ),
                (
                    "2001:db8:2::/48".to_string(),
                    "2001:db8:16::12".parse().unwrap()
                ),
            ]
        );
        assert_eq!(r.unparsed, 1, "a link-local alone is no participant");
    }

    #[test]
    fn ipv4_prefix_with_ipv6_next_hop() {
        // RFC 8950: FRR writes `nextHopGlobal` for a v4 prefix too.
        let r = parse_received_routes(
            r#"{"receivedRoutes":{"203.0.113.0/24":{"nextHopGlobal":"2001:db8:16::13"}}}"#,
        )
        .unwrap();
        assert_eq!(
            r.routes,
            vec![(
                "203.0.113.0/24".to_string(),
                "2001:db8:16::13".parse().unwrap()
            )]
        );
    }

    #[test]
    fn multi_daemon_preamble_and_pretty_printing_are_data() {
        // Daemon lines ahead of the object, the object pretty-printed
        // across lines, a trailing line after it.
        let out = "% Can't find specified prefix-list\nBGP:\n{\n  \"receivedRoutes\": {\n    \
                   \"2001:db8:100::/48\": {\n      \"nextHopGlobal\": \"2001:db8:16::10\"\n    },\n    \
                   \"203.0.113.0\\/24\": {\n      \"nextHop\": \"192.0.2.10\"\n    }\n  }\n}\n\
                   % trailing notice\n";
        let mut r = parse_received_routes(out).unwrap();
        r.routes.sort();
        assert_eq!(r.unparsed, 0);
        assert_eq!(
            r.routes,
            vec![
                (
                    "2001:db8:100::/48".to_string(),
                    "2001:db8:16::10".parse().unwrap()
                ),
                ("203.0.113.0/24".to_string(), "192.0.2.10".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn failures_are_errors_not_empty_tables() {
        let e = parse_received_routes("% No such neighbor or address family\n").unwrap_err();
        assert!(e.contains("No such neighbor"), "{e}");
        let e = parse_received_routes(r#"{"warning":"Inbound soft reconfiguration not enabled"}"#)
            .unwrap_err();
        assert!(e.contains("soft reconfiguration"), "{e}");
        // FRR 10's wrapped form of the same warning.
        let e = parse_received_routes(
            "{\n{\"warning\":\"Inbound soft reconfiguration not enabled\"}\n}\n",
        )
        .unwrap_err();
        assert!(e.contains("FRR says: Inbound soft reconfiguration"), "{e}");
        assert!(parse_received_routes("").is_err());
        assert!(parse_received_routes("{\"receivedRoutes\": {").is_err());
        // A type FRR never writes fails the dump rather than hiding.
        assert!(parse_received_routes(r#"{"receivedRoutes":{"x":{"nextHop":7}}}"#).is_err());
        // An empty table is a real, empty answer.
        let r = parse_received_routes(r#"{"receivedRoutes":{}}"#).unwrap();
        assert_eq!(r, ReceivedRoutes::default());
    }

    #[test]
    fn join_resolves_ipv6_next_hops_against_the_mirror() {
        let routes = parse_received_routes(V6_FRR10).unwrap().routes;
        let bridge = BridgeCfg {
            name: "br0".into(),
            ix_mode: true,
            prefixes: vec!["2001:db8:16::/48".parse().unwrap()],
            peers: vec![PeerCfg {
                addrs: vec!["2001:db8:16::2".parse().unwrap()],
                route_server: true,
            }],
        };
        let mut mirror = KernelMirror::default();
        mirror.upsert(
            7,
            "2001:db8:16::10".parse().unwrap(),
            MirrorEntry {
                state: NudState::Reachable,
                mac: Some([2, 0, 0, 0, 0, 2]),
            },
        );
        let j = join(&routes, &bridge, 7, &mirror, 10);
        assert_eq!(j.received_prefixes, 2);
        assert_eq!(j.demoted_prefixes, 1);
        assert_eq!(
            j.unresolved_nexthops,
            vec!["2001:db8:16:ffff:ffff:ffff:ffff:ffff"
                .parse::<IpAddr>()
                .unwrap()]
        );
    }
}
