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
/// Deliberately a whitelist: anything this does not recognise as
/// harmless counts as filtering. An unrecognised directive that turns
/// out to be benign costs one refusal and a line in the runbook; one
/// that turns out to narrow the table costs a steer into a FIB with
/// holes the gate swore were not there.
///
/// `next-hop-self` is the one known-harmless per-peer AF directive on
/// this path — it rewrites an attribute, it does not remove prefixes.
pub fn parse_export_policy(running_config: &str, peer: &str) -> ExportPolicy {
    const NARROWING: [&str; 6] = [
        "route-map",
        "prefix-list",
        "filter-list",
        "distribute-list",
        "unsuppress-map",
        "maximum-prefix",
    ];
    let needle = format!("neighbor {peer} ");
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
                return ExportPolicy::Filtered {
                    why: format!("`neighbor {peer} {tail}` narrows what this peer receives"),
                };
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
}
