//! Reading FRR as a completeness authority (`integrity-authority frr`).
//!
//! The parsing is pure and lives outside the platform gate so its tests
//! run on every host; only the `vtysh` invocation is Linux-only. Same
//! split as `probe::sysctl_hugepages`, for the same reason.
//!
//! ## Why this is more than a prefix count
//!
//! bird's authority is count-only: `show route count` reports bird's
//! whole table, and a mirror short of it is still loading. FRR's
//! equivalent count cannot carry the same weight, because on an
//! FRR-fed box **both sides fill together** — FRR receives from
//! upstream while packetframe receives from FRR, so a count taken
//! mid-convergence agrees with a mirror that is equally incomplete.
//! The gate would read converged the whole way up.
//!
//! So the authority also requires **End-of-RIB from every declared
//! upstream, for the current session**. Measured on the reference lab
//! gateway (FRR 10.1.2, 2026-09-22): two seconds after `clear bgp` the
//! peer read `Established` with `endOfRibRecv=false`. Session state
//! alone would have called that table complete.
//!
//! ## Two field choices that are not the obvious ones
//!
//! **`ribCount` is not the prefix count.** It is the number of nodes in
//! FRR's BGP table trie, internal nodes included. Observed on the lab
//! gateway: three prefixes, `ribCount=5` (3 leaves + 2 internal). A
//! radix trie over N leaves holds close to N−1 internal nodes, so at
//! DFZ scale this reads roughly 2x the real table and the mirror would
//! look permanently ~50% short — a gate that never releases, which is
//! indistinguishable from a table that never loads. Use
//! `show bgp <afi> unicast statistics json` → `totalPrefixes`.
//!
//! **`pfxSnt` is not it either**, for the opposite reason: it counts
//! what FRR has sent US, so it tracks the mirror during the initial
//! dump and agrees at every point. That is the vacuous-gate failure
//! the readiness requirement exists to prevent, and reading it as the
//! authority would reintroduce it through the count instead.

// The pure half is compiled everywhere so its unit tests run on a
// macOS dev host; its only production caller is the Linux collector.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use packetframe_common::config::AuthorityFamily;

/// The default `vtysh` location on the reference fleet.
pub const DEFAULT_VTYSH_PATH: &str = "/usr/bin/vtysh";

/// What one upstream session looks like right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamState {
    /// The peer as configured, for messages.
    pub peer: String,
    /// `bgpState == "Established"`.
    pub established: bool,
    /// Families whose End-of-RIB has NOT arrived for this session.
    /// Empty means every declared family is loaded.
    pub missing_eor: Vec<AuthorityFamily>,
    /// When the current session established, as FRR reports it. `None`
    /// when the peer has never come up.
    ///
    /// This is the session generation marker: an epoch that has moved
    /// since a reading was taken means that reading describes a session
    /// which no longer exists. It also doubles as a config-change
    /// detector on UniFi, where any FRR config change restarts zebra
    /// and bgpd and therefore re-establishes every peer.
    pub established_epoch: Option<u64>,
}

impl UpstreamState {
    /// Whether this upstream has finished loading every declared
    /// family for its current session.
    ///
    /// **Deliberately does not consider `established_epoch`, and the
    /// caller must.** This answers "is the table loaded"; the epoch
    /// answers "which session loaded it", and that is a comparison
    /// against a previous reading, which a method on one reading cannot
    /// make. But an epoch that is `None` is not merely uncomparable — it
    /// means nothing here can be tied to a session at all, so readiness
    /// without one is a completeness decision with no session identity
    /// behind it (review finding, PR #229). `classify_eligibility`
    /// treats that as `Unknown` rather than letting it pass; see the
    /// `a_ready_upstream_with_no_epoch_is_unknown` test.
    pub fn ready(&self) -> bool {
        self.established && self.missing_eor.is_empty()
    }

    /// Operator-facing reason it is not ready, or `None` when it is.
    pub fn why_not_ready(&self) -> Option<String> {
        if !self.established {
            return Some(format!("upstream {} is not Established", self.peer));
        }
        if self.missing_eor.is_empty() {
            return None;
        }
        let fams: Vec<&str> = self.missing_eor.iter().map(|f| f.afi()).collect();
        Some(format!(
            "upstream {} is Established but has not sent End-of-RIB for {} on this \
             session — its table is still filling, so a count taken now describes a \
             partial RIB",
            self.peer,
            fams.join(", ")
        ))
    }
}

/// `show bgp <afi> unicast statistics json` → the family's prefix count.
///
/// The document is keyed by the family and holds one entry per VRF
/// instance; we take the default VRF, which is the one the sessions
/// live in. An absent family is an error rather than a zero: a family
/// the operator declared and FRR does not report is a configuration
/// mismatch, and reading it as "no prefixes" would let the comparison
/// pass against an equally empty mirror.
pub fn parse_total_prefixes(json: &str, family: AuthorityFamily) -> Result<u64, String> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| format!("statistics for {} is not JSON: {e}", family.afi()))?;
    let arr = v
        .get(family.json_key())
        .and_then(|f| f.as_array())
        .ok_or_else(|| {
            format!(
                "statistics has no `{}` array — is that family configured on this FRR?",
                family.json_key()
            )
        })?;
    // `instance` names the VRF. Prefer the default explicitly rather
    // than taking [0]: a box with VRFs would otherwise have the
    // authority silently counting whichever one FRR listed first.
    let entry = arr
        .iter()
        .find(|e| {
            e.get("instance")
                .and_then(|i| i.as_str())
                .is_some_and(|i| i == "VRF default")
        })
        .ok_or_else(|| {
            format!(
                "statistics for {} has no `VRF default` instance",
                family.afi()
            )
        })?;
    entry
        .get("totalPrefixes")
        .and_then(|p| p.as_u64())
        .ok_or_else(|| {
            format!(
                "statistics for {} has no numeric `totalPrefixes`",
                family.afi()
            )
        })
}

/// `show bgp neighbor <peer> json` → that peer's readiness.
///
/// Reads `gracefulRestartInfo.<family>.endOfRibStatus.endOfRibRecv`,
/// which is the field observed to clear on a session reset (lab
/// gateway, 2026-09-22) — FRR publishes a second copy at
/// `gracefulRestartInfo.endOfRibRecv.<family>`, but only the one used
/// here has been watched through a flap.
///
/// A missing EoR field reads as NOT received. That is the safe
/// direction and it is also correct for a session that has never
/// carried the family.
pub fn parse_upstream_state(
    json: &str,
    peer: &str,
    families: &[AuthorityFamily],
) -> Result<UpstreamState, String> {
    let v: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| format!("neighbor {peer} output is not JSON: {e}"))?;
    let n = v
        .get(peer)
        .ok_or_else(|| format!("neighbor {peer} is not in FRR's output — is it configured?"))?;
    let established = n
        .get("bgpState")
        .and_then(|s| s.as_str())
        .is_some_and(|s| s == "Established");
    let gr = n.get("gracefulRestartInfo");
    let missing_eor = families
        .iter()
        .copied()
        .filter(|f| {
            let got = gr
                .and_then(|g| g.get(f.json_key()))
                .and_then(|a| a.get("endOfRibStatus"))
                .and_then(|s| s.get("endOfRibRecv"))
                .and_then(|b| b.as_bool())
                .unwrap_or(false);
            !got
        })
        .collect();
    Ok(UpstreamState {
        peer: peer.to_string(),
        established,
        missing_eor,
        established_epoch: None,
    })
}

/// `show bgp ipv4 unicast summary json` → a peer's establishment epoch.
///
/// Absent for a peer that has never come up, which is why the caller
/// treats `None` as "no current session" rather than as an error.
pub fn parse_established_epoch(summary_json: &str, peer: &str) -> Option<u64> {
    let v: serde_json::Value = serde_json::from_str(summary_json).ok()?;
    v.get("peers")?
        .get(peer)?
        .get("peerUptimeEstablishedEpoch")?
        .as_u64()
}

/// Whether the session feeding packetframe carries the whole table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportPolicy {
    /// Nothing narrows what packetframe receives.
    Unfiltered,
    /// Something does. The count comparison cannot see this — at a 1%
    /// drift tolerance a filter removing 5,000 prefixes from a million
    /// still reads `Converged` — so it has to be refused on the
    /// configuration rather than inferred from the numbers.
    Filtered { why: String },
}

/// Read the PF peer's outbound policy out of `show running-config`.
///
/// **A blacklist of the directives known to narrow a table, and its
/// doc used to claim the opposite.** The first version said it was a
/// whitelist — "anything this does not recognise as harmless counts as
/// filtering" — which is the stronger design and is not what the code
/// did or does. It matches six keywords and calls everything else
/// unfiltered. The claim is withdrawn rather than the code inverted,
/// because a genuine whitelist has to enumerate FRR's whole per-neighbor
/// grammar, and every directive missing from it refuses a valid config;
/// guessing at that list is exactly what [D2b] existed to stop. Widening
/// it is a measurement task, not an edit.
///
/// What the blacklist DOES cover is stated so an operator can reason
/// about the gap: `route-map`, `prefix-list`, `filter-list`,
/// `distribute-list`, `unsuppress-map` and `maximum-prefix`, in either
/// direction, on the peer **or on a peer-group it belongs to**.
///
/// Peer-group inheritance is not an extra: FRR keys an inherited policy
/// by the GROUP name, and the peer's own line reads `neighbor <peer>
/// peer-group <G>`, which matches nothing in the list. Without
/// resolving it, the single most ordinary way to attach a route-map to
/// a session was invisible and this returned `Unfiltered` over a
/// narrowed feed — the one failure mode the counts cannot catch
/// afterwards (review finding, PR #229).
///
/// `next-hop-self` is the one known-harmless per-peer AF directive on
/// this path — it rewrites an attribute, it does not remove prefixes.
///
/// [D2b]: the discovery gate in the VPP readiness plan
pub fn parse_export_policy(running_config: &str, peer: &str) -> ExportPolicy {
    const NARROWING: [&str; 6] = [
        "route-map",
        "prefix-list",
        "filter-list",
        "distribute-list",
        "unsuppress-map",
        "maximum-prefix",
    ];
    // The peer's own name, plus every peer-group it is a member of.
    // Resolved first, in its own pass, because a `peer-group` line can
    // appear after the group's policy in the rendered config and a
    // single pass would miss it.
    let mut names = vec![peer.to_string()];
    let member_of = format!("neighbor {peer} peer-group ");
    for raw in running_config.lines() {
        if let Some(group) = raw.trim().strip_prefix(&member_of) {
            let group = group.trim();
            if !group.is_empty() && !names.iter().any(|n| n == group) {
                names.push(group.to_string());
            }
        }
    }

    for name in &names {
        let needle = format!("neighbor {name} ");
        for raw in running_config.lines() {
            let line = raw.trim();
            let Some(tail) = line.strip_prefix(&needle) else {
                continue;
            };
            // Direction matters only for reporting: an INBOUND filter on
            // this peer is equally disqualifying, because the peer is a
            // consumer and an inbound filter there means the operator is
            // running a shape this authority was not designed for.
            for kw in NARROWING {
                if tail.starts_with(kw) {
                    let via = if name == peer {
                        String::new()
                    } else {
                        format!(" (inherited by {peer} from peer-group {name})")
                    };
                    return ExportPolicy::Filtered {
                        why: format!(
                            "`neighbor {name} {tail}` narrows what this peer receives{via}"
                        ),
                    };
                }
            }
        }
    }
    ExportPolicy::Unfiltered
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured verbatim from the reference lab gateway, FRR 10.1.2,
    /// 2026-09-22. Three prefixes announced by one upstream.
    const STATISTICS_V4: &str = r#"{
      "ipv4Unicast":[
        {
          "instance":"VRF default",
          "totalAdvertisements":3,
          "totalPrefixes":3,
          "averagePrefixLength":24.0,
          "unaggregateablePrefixes":3
        }
      ]
    }"#;

    /// The same box's `show bgp neighbor`, trimmed to the fields read
    /// here — including BOTH places FRR publishes End-of-RIB, so a
    /// change that started reading the other one is visible.
    const NEIGHBOR_READY: &str = r#"{
      "192.168.10.1":{
        "bgpState":"Established",
        "gracefulRestartInfo":{
          "endOfRibSend":{"ipv4Unicast":true},
          "endOfRibRecv":{"ipv4Unicast":true},
          "ipv4Unicast":{
            "endOfRibStatus":{
              "endOfRibSend":true,
              "endOfRibSentAfterUpdate":true,
              "endOfRibRecv":true
            }
          }
        },
        "addressFamilyInfo":{"ipv4Unicast":{"acceptedPrefixCounter":3}}
      }
    }"#;

    /// The state observed two seconds after `clear bgp`: up, and still
    /// filling. This is the case the whole readiness requirement
    /// exists for.
    const NEIGHBOR_ESTABLISHED_NO_EOR: &str = r#"{
      "192.168.10.1":{
        "bgpState":"Established",
        "gracefulRestartInfo":{
          "ipv4Unicast":{"endOfRibStatus":{"endOfRibRecv":false}}
        }
      }
    }"#;

    const SUMMARY: &str = r#"{
      "routerId":"10.255.0.1",
      "as":65000,
      "ribCount":5,
      "peers":{
        "192.168.10.1":{
          "state":"Established",
          "pfxRcd":3,
          "peerUptimeEstablishedEpoch":1790045332
        },
        "10.255.0.2":{"state":"Active","pfxRcd":0}
      }
    }"#;

    #[test]
    fn total_prefixes_is_the_real_count() {
        assert_eq!(
            parse_total_prefixes(STATISTICS_V4, AuthorityFamily::V4),
            Ok(3)
        );
    }

    /// The trap this module exists to avoid. `ribCount` counts trie
    /// nodes: the same three prefixes report 5. Nothing here may ever
    /// read it, and the fixture carries it so a future edit that starts
    /// doing so fails against a known-wrong number rather than against
    /// a plausible one.
    #[test]
    fn rib_count_is_not_the_prefix_count() {
        let v: serde_json::Value = serde_json::from_str(SUMMARY).unwrap();
        assert_eq!(v["ribCount"].as_u64(), Some(5));
        assert_eq!(
            parse_total_prefixes(STATISTICS_V4, AuthorityFamily::V4),
            Ok(3),
            "three prefixes; ribCount says 5 because a trie over 3 leaves has 2 \
             internal nodes, and at DFZ scale that is ~2x the table"
        );
    }

    /// A declared family FRR does not report is an error, not a zero —
    /// a zero would compare equal to an equally empty mirror and read
    /// as converged.
    #[test]
    fn a_missing_family_is_an_error_not_zero() {
        let e = parse_total_prefixes(STATISTICS_V4, AuthorityFamily::V6).unwrap_err();
        assert!(e.contains("ipv6Unicast"), "{e}");
    }

    #[test]
    fn a_vrf_other_than_default_is_not_counted() {
        let other = r#"{"ipv4Unicast":[{"instance":"VRF red","totalPrefixes":9}]}"#;
        assert!(parse_total_prefixes(other, AuthorityFamily::V4).is_err());
    }

    #[test]
    fn a_loaded_upstream_is_ready() {
        let s = parse_upstream_state(NEIGHBOR_READY, "192.168.10.1", &[AuthorityFamily::V4])
            .expect("parses");
        assert!(s.ready());
        assert_eq!(s.why_not_ready(), None);
    }

    /// Established is NOT ready. Observed on hardware at +2s after a
    /// `clear bgp`, and it is the entire reason this authority is more
    /// than a count.
    #[test]
    fn established_without_end_of_rib_is_not_ready() {
        let s = parse_upstream_state(
            NEIGHBOR_ESTABLISHED_NO_EOR,
            "192.168.10.1",
            &[AuthorityFamily::V4],
        )
        .expect("parses");
        assert!(s.established, "the session really is up");
        assert!(!s.ready(), "but its table is still filling");
        let why = s.why_not_ready().expect("a reason");
        assert!(why.contains("End-of-RIB"), "{why}");
    }

    /// A family with no EoR field at all reads as not-received.
    #[test]
    fn an_absent_eor_field_is_not_received() {
        let s = parse_upstream_state(
            NEIGHBOR_READY,
            "192.168.10.1",
            &[AuthorityFamily::V4, AuthorityFamily::V6],
        )
        .expect("parses");
        assert_eq!(s.missing_eor, vec![AuthorityFamily::V6]);
        assert!(!s.ready());
    }

    #[test]
    fn an_unconfigured_peer_is_an_error() {
        let e = parse_upstream_state(NEIGHBOR_READY, "203.0.113.9", &[AuthorityFamily::V4])
            .unwrap_err();
        assert!(e.contains("not in FRR's output"), "{e}");
    }

    #[test]
    fn the_epoch_is_the_session_generation() {
        assert_eq!(
            parse_established_epoch(SUMMARY, "192.168.10.1"),
            Some(1790045332)
        );
        assert_eq!(
            parse_established_epoch(SUMMARY, "10.255.0.2"),
            None,
            "a peer that has never come up has no epoch"
        );
    }

    /// The shape the lab gateway runs: next-hop-self only.
    #[test]
    fn next_hop_self_alone_is_unfiltered() {
        let cfg = "\
router bgp 65000
 neighbor 10.255.0.2 remote-as 65000
 address-family ipv4 unicast
  neighbor 10.255.0.2 next-hop-self force
 exit-address-family
";
        assert_eq!(
            parse_export_policy(cfg, "10.255.0.2"),
            ExportPolicy::Unfiltered
        );
    }

    /// The case counts cannot see: a filter narrowing the table by less
    /// than the drift tolerance still reads `Converged`, so it has to
    /// be caught here or not at all.
    #[test]
    fn a_route_map_is_filtering() {
        let cfg = "\
router bgp 65000
 address-family ipv4 unicast
  neighbor 10.255.0.2 route-map TRIM out
 exit-address-family
";
        match parse_export_policy(cfg, "10.255.0.2") {
            ExportPolicy::Filtered { why } => assert!(why.contains("route-map"), "{why}"),
            other => panic!("expected Filtered, got {other:?}"),
        }
    }

    #[test]
    fn a_prefix_list_is_filtering() {
        let cfg = "  neighbor 10.255.0.2 prefix-list ONLY-SOME out\n";
        assert!(matches!(
            parse_export_policy(cfg, "10.255.0.2"),
            ExportPolicy::Filtered { .. }
        ));
    }

    /// Another peer's filter says nothing about ours.
    #[test]
    fn a_filter_on_a_different_peer_is_ignored() {
        let cfg = "  neighbor 192.168.10.1 route-map UPSTREAM in\n";
        assert_eq!(
            parse_export_policy(cfg, "10.255.0.2"),
            ExportPolicy::Unfiltered
        );
    }

    /// A route-map the peer inherits from a peer-group is found.
    ///
    /// The single most ordinary way to attach outbound policy in FRR,
    /// and the first version missed all of it: the policy line is keyed
    /// by the GROUP name, and the peer's own line says `peer-group <G>`,
    /// which matches none of the narrowing keywords. So the check
    /// returned `Unfiltered` over a narrowed feed — and a filter below
    /// the drift tolerance is precisely what the counts can never catch
    /// afterwards.
    #[test]
    fn a_peer_group_route_map_is_found() {
        let cfg = "\
router bgp 65000
 neighbor TRANSIT peer-group
 neighbor TRANSIT remote-as 65001
 neighbor 10.255.0.2 peer-group TRANSIT
 neighbor 10.255.0.2 port 1179
 address-family ipv4 unicast
  neighbor TRANSIT route-map ONLY-CUSTOMERS out
 exit-address-family
";
        let ExportPolicy::Filtered { why } = parse_export_policy(cfg, "10.255.0.2") else {
            panic!("an inherited route-map must disqualify");
        };
        assert!(why.contains("ONLY-CUSTOMERS"), "{why}");
        assert!(
            why.contains("inherited") && why.contains("TRANSIT"),
            "and say where it came from, or an operator greps the peer's own lines and \
             finds nothing: {why}"
        );
    }

    /// Order-independent: FRR renders the group's policy inside an
    /// `address-family` block, which comes AFTER the `peer-group`
    /// membership line — but a config written the other way round must
    /// resolve identically, so membership is collected in its own pass.
    #[test]
    fn peer_group_membership_is_resolved_before_the_scan() {
        let cfg = "\
 neighbor TRANSIT route-map OUT out
 neighbor 10.255.0.2 peer-group TRANSIT
";
        assert!(matches!(
            parse_export_policy(cfg, "10.255.0.2"),
            ExportPolicy::Filtered { .. }
        ));
    }

    /// Membership alone is not a filter. A peer-group with no narrowing
    /// policy is the ordinary way to share timers and remote-as, and
    /// refusing it would make the authority unusable on most real
    /// configs.
    #[test]
    fn a_plain_peer_group_is_not_a_filter() {
        let cfg = "\
 neighbor TRANSIT peer-group
 neighbor TRANSIT remote-as 65001
 neighbor TRANSIT timers 3 9
 neighbor 10.255.0.2 peer-group TRANSIT
 neighbor 10.255.0.2 next-hop-self
";
        assert_eq!(
            parse_export_policy(cfg, "10.255.0.2"),
            ExportPolicy::Unfiltered
        );
    }

    /// Another peer's group must not be attributed to ours.
    #[test]
    fn a_group_this_peer_is_not_in_is_ignored() {
        let cfg = "\
 neighbor CUSTOMERS route-map NARROW out
 neighbor 192.0.2.7 peer-group CUSTOMERS
 neighbor 10.255.0.2 remote-as 65000
";
        assert_eq!(
            parse_export_policy(cfg, "10.255.0.2"),
            ExportPolicy::Unfiltered
        );
    }
}
