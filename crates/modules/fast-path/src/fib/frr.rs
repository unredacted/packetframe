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

/// Read the PF peer's outbound policy out of `show running-config`, for
/// the families being attested.
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
/// about the gap: `route-map`, `prefix-list`, `filter-list` and
/// `distribute-list` applied **outbound** (an `in` policy filters what
/// packetframe sends FRR, not what FRR exports), plus `unsuppress-map`
/// and `maximum-prefix-out`, on the peer **or on a peer-group it
/// belongs to**. Plain `maximum-prefix` caps what the peer may send us
/// and is not covered.
///
/// **An outbound route-map is read, not refused on sight.** The first
/// launch on an FRR 10 production router disqualified a mirror whose
/// outbound maps drop nothing: an empty `permit 10` for v4, and for v6 a
/// `match` + `set ipv6 next-hop` entry ahead of an empty `permit 20`.
/// Whether a map passes every route is [`route_map_narrows`]'s call, and
/// every shape it does not recognise still narrows.
///
/// **Only the attested families count.** A line inside `address-family
/// ipv6 unicast` shapes the v6 table and nothing else; refusing a v4-only
/// attestation over it refuses on a table nobody compared (and a v6 feed
/// the declaration does not cover is already revoked by
/// [`mirror_family_mismatch`]). Lines outside any address-family block
/// apply to every family, and so does a block this cannot place as v4 or
/// v6 — the conservative reading.
///
/// Peer-group inheritance is not an extra: FRR keys an inherited policy
/// by the GROUP name, and the peer's own line reads `neighbor <peer>
/// peer-group <G>`, which matches nothing in the list. Without
/// resolving it, the single most ordinary way to attach a route-map to
/// a session was invisible and this returned `Unfiltered` over a
/// narrowed feed — the one failure mode the counts cannot catch
/// afterwards (review finding, PR #229). Membership is read wherever it
/// appears; the group's policy lines are scoped per family exactly like
/// the peer's own.
///
/// `next-hop-self` is the one known-harmless per-peer AF directive on
/// this path — it rewrites an attribute, it does not remove prefixes.
///
/// [D2b]: the discovery gate in the VPP readiness plan
pub fn parse_export_policy(
    running_config: &str,
    peer: &str,
    families: &[AuthorityFamily],
) -> ExportPolicy {
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
    // Its own pass for the same reason: FRR renders the route-maps after
    // the `router bgp` block that references them.
    let maps = parse_route_maps(running_config);
    let needles: Vec<(String, &String)> = names
        .iter()
        .map(|name| (format!("neighbor {name} "), name))
        .collect();

    let mut scope = AfScope::All;
    for raw in running_config.lines() {
        let line = raw.trim();
        // A column-0 line (`exit`, `router bgp …`, `route-map …`, `!`)
        // closes any address-family block that was open.
        if !raw.starts_with(char::is_whitespace) {
            scope = AfScope::All;
        }
        if let Some(af) = line.strip_prefix("address-family ") {
            scope = AfScope::of(af);
            continue;
        }
        if line == "exit-address-family" {
            scope = AfScope::All;
            continue;
        }
        if !scope.covers_any(families) {
            continue;
        }
        for (needle, name) in &needles {
            let Some(tail) = line.strip_prefix(needle.as_str()) else {
                continue;
            };
            let Some(detail) = narrows_export(tail, &maps) else {
                continue;
            };
            let within = match &scope {
                AfScope::All => String::new(),
                AfScope::Only { label, .. } => format!(" in `address-family {label}`"),
            };
            let via = if name.as_str() == peer {
                String::new()
            } else {
                format!(" (inherited by {peer} from peer-group {name})")
            };
            return ExportPolicy::Filtered {
                why: format!(
                    "`neighbor {name} {tail}`{within} narrows what this peer receives{via}{detail}"
                ),
            };
        }
    }
    ExportPolicy::Unfiltered
}

/// The families a `neighbor …` line applies to, from the address-family
/// block it sits in.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AfScope {
    /// Outside any address-family block, or inside one that is neither
    /// `ipv4 …` nor `ipv6 …`: every family, which is the safe reading.
    All,
    /// Inside `address-family <label>`, which shapes `family` only.
    Only {
        family: AuthorityFamily,
        label: String,
    },
}

impl AfScope {
    /// From the words after `address-family`. Every `ipv4` SAFI maps to
    /// v4 rather than only `unicast`: a policy on `ipv4 labeled-unicast`
    /// counted against a v4 attestation errs toward refusing.
    fn of(af: &str) -> Self {
        let label = af.split_whitespace().collect::<Vec<_>>().join(" ");
        let family = match label.split(' ').next() {
            Some("ipv4") => AuthorityFamily::V4,
            Some("ipv6") => AuthorityFamily::V6,
            _ => return AfScope::All,
        };
        AfScope::Only { family, label }
    }

    fn covers_any(&self, families: &[AuthorityFamily]) -> bool {
        match self {
            AfScope::All => true,
            AfScope::Only { family, .. } => families.contains(family),
        }
    }
}

/// Whether one `neighbor <x> …` tail narrows what FRR SENDS that peer.
/// `Some(detail)` when it does; the detail is appended to the operator
/// message and is empty when the line alone says everything.
///
/// **Outbound only.** An inbound filter on the packetframe peer governs
/// what packetframe advertises to FRR, which is nothing — it cannot
/// change the table packetframe receives, so it is no evidence against
/// the mirror. The first version disqualified inbound filters too, on
/// the theory that any policy there was an unsupported shape; the
/// primary's first `frr` attach (2026-09-24) showed the opposite: a
/// `route-map PACKETFRAME-IN in` hardening the session (accept nothing
/// from packetframe) is the sensible production shape, and the rule
/// DISQUALIFIED a converged mirror over it — while its own message
/// claimed the line narrowed "what this peer receives", which an `in`
/// filter never does.
///
/// Direction is the LAST word of a `route-map`/`prefix-list`/
/// `filter-list`/`distribute-list` line; anything other than a literal
/// `in` counts as narrowing, so an unrecognised form errs toward
/// refusing. An outbound `route-map <NAME> out` is the one line whose
/// verdict depends on something else in the config — the map itself —
/// and only that exact three-word form is looked up. `unsuppress-map`
/// and `maximum-prefix-out` only ever shape the outbound table. Plain
/// `maximum-prefix` limits what the peer sends US, so it is inbound and
/// ignored.
fn narrows_export(tail: &str, maps: &HashMap<String, RouteMap>) -> Option<String> {
    let words: Vec<&str> = tail.split_whitespace().collect();
    match words.first().copied()? {
        "route-map" => match words[..] {
            [.., "in"] => None,
            [_, name, "out"] => route_map_narrows(maps, name).map(|why| format!(": {why}")),
            _ => Some(String::new()),
        },
        "prefix-list" | "filter-list" | "distribute-list" => {
            (words.last() != Some(&"in")).then(String::new)
        }
        "unsuppress-map" | "maximum-prefix-out" => Some(String::new()),
        _ => None,
    }
}

/// One `route-map <NAME> permit|deny <SEQ>` entry and its clauses, as
/// `show running-config` renders them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteMapEntry {
    permit: bool,
    seq: u32,
    /// Each indented line under the header, trimmed.
    clauses: Vec<String>,
}

/// Every entry of one route-map, or the header that could not be read.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct RouteMap {
    entries: Vec<RouteMapEntry>,
    /// A `route-map <NAME> …` header this does not understand. The map
    /// is then of unknown shape and narrows.
    unparsed: Option<String>,
}

/// Collect every route-map in `show running-config`, keyed by name.
///
/// A header is a line whose first word is `route-map` — no other line
/// FRR renders starts with it (a neighbor's reads `neighbor …`,
/// redistribution's `redistribute …`). Its clauses are the indented
/// lines that follow, up to the next column-0 line (`exit` in FRR 10,
/// `!` in older renderings).
fn parse_route_maps(running_config: &str) -> HashMap<String, RouteMap> {
    let mut maps: HashMap<String, RouteMap> = HashMap::new();
    // The map and entry index clauses are currently being added to.
    let mut open: Option<(String, usize)> = None;
    for raw in running_config.lines() {
        let line = raw.trim();
        let indented = raw.starts_with(char::is_whitespace);
        if indented && !line.is_empty() && line != "exit" && line != "!" {
            if let Some((name, idx)) = &open {
                if let Some(e) = maps.get_mut(name).and_then(|m| m.entries.get_mut(*idx)) {
                    e.clauses.push(line.to_string());
                }
                continue;
            }
        }
        open = None;
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.first() != Some(&"route-map") {
            continue;
        }
        let Some(name) = words.get(1) else {
            continue;
        };
        let map = maps.entry(name.to_string()).or_default();
        let entry = match words[..] {
            [_, _, action @ ("permit" | "deny"), seq] => {
                seq.parse::<u32>().ok().map(|seq| RouteMapEntry {
                    permit: action == "permit",
                    seq,
                    clauses: Vec::new(),
                })
            }
            _ => None,
        };
        match entry {
            Some(e) => {
                map.entries.push(e);
                open = Some((name.to_string(), map.entries.len() - 1));
            }
            None => {
                map.unparsed.get_or_insert_with(|| line.to_string());
            }
        }
    }
    maps
}

/// Why applying route-map `name` outbound can drop a route, or `None`
/// when it passes every route.
///
/// It passes every route when some entry is `permit` with no `match`,
/// and every entry before it is a `permit` too. A `permit` entry with
/// matches never drops: a route it matches is permitted (its `set`
/// clauses rewrite attributes, which is not narrowing), and a route it
/// does not match falls through to the next entry — so walking in
/// sequence order, the first unconditional permit is reached by every
/// route that nothing before it permitted.
///
/// Everything else narrows, and deliberately includes shapes that might
/// not: a `deny` anywhere before that entry; no unconditional permit at
/// all (a route no entry matches meets FRR's implicit deny); a clause
/// other than `match`/`set`/`description` in the entries walked
/// (`call`, `on-match`, `continue` can each carry a route to an entry
/// this walk never inspected); an unreadable header; and a name with no
/// map, which FRR applies as deny-all.
fn route_map_narrows(maps: &HashMap<String, RouteMap>, name: &str) -> Option<String> {
    let Some(map) = maps.get(name) else {
        return Some(format!(
            "route-map {name} is not defined, and FRR applies a missing route-map as deny-all"
        ));
    };
    if let Some(header) = &map.unparsed {
        return Some(format!(
            "route-map {name} has an entry this check cannot read (`{header}`)"
        ));
    }
    let mut entries: Vec<&RouteMapEntry> = map.entries.iter().collect();
    entries.sort_by_key(|e| e.seq);
    for e in entries {
        let action = if e.permit { "permit" } else { "deny" };
        let mut conditional = false;
        for clause in &e.clauses {
            match clause.split_whitespace().next() {
                Some("set") | Some("description") => {}
                Some("match") => conditional = true,
                _ => {
                    return Some(format!(
                        "route-map {name} entry `{action} {}` has `{clause}`, which this check \
                         does not follow",
                        e.seq
                    ))
                }
            }
        }
        if !e.permit {
            return Some(format!(
                "route-map {name} entry `deny {}` comes before any permit that matches \
                 everything",
                e.seq
            ));
        }
        if !conditional {
            return None;
        }
    }
    Some(format!(
        "route-map {name} has no permit entry without a `match`, so a route no entry \
         matches is denied"
    ))
}

// ---------------------------------------------------------------------
// What a tick concludes. Pure, so it is tested on a dev host rather than
// only in the qemu job — and because the *precedence* between these
// outcomes is the whole safety argument, which is not a thing to leave
// to an integration test that needs a NIC and a live FRR.
// ---------------------------------------------------------------------

use std::collections::HashMap;
use std::net::IpAddr;

use packetframe_common::fib::{AuthorityObservation, CompletenessReport, Revocation};

/// What one tick established about eligibility, before the counts are
/// considered.
///
/// Three outcomes rather than a `Result`, because "could not read" and
/// "read, and it is disqualified" must not collapse: the first retains
/// whatever standing eligibility there is, the second withdraws it. A
/// `Result<bool, _>` would have said the same thing and invited every
/// caller to `unwrap_or(false)` its way into treating a timeout as a
/// disqualification — which is the *safe* direction for steering and the
/// wrong one for an operator, who would be sent to check a BGP config
/// that is fine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Eligibility {
    /// Every declared upstream is loaded for its current session, the
    /// session generation is unchanged, and nothing narrows our feed.
    Ok,
    /// Positive evidence of disqualification.
    Revoked(Revocation),
    /// Could not be established. Says nothing either way.
    Unknown(String),
}

/// How far forward `peerUptimeEstablishedEpoch` must move before it
/// means a different session.
///
/// The field is not a stored timestamp. FRR derives it from two clocks
/// that tick at different points within each second, so ONE session
/// reads one lower when the read lands in a narrow window at the top of
/// a second. Measured on the lab gateway (FRR 10.1.2, 2026-09-22), one
/// idle session over six checker ticks:
///
/// | read at (s past the minute) | epoch |
/// |---|---|
/// | 12.68 | 1790066204 |
/// | 12.99 | 1790066203 |
/// | 13.31 | 1790066204 |
/// | 13.63 | 1790066204 |
/// | 13.94 | 1790066203 |
/// | 14.26 | 1790066204 |
///
/// The checker's period is its interval plus the check's own duration,
/// so every tick lands ~0.3 s later than the last and sweeps the whole
/// second — while twenty back-to-back manual reads all missed the
/// window. Exact comparison revoked the mirror on four of those six
/// ticks: near-permanent ineligibility on a perfectly stable box, which
/// on the primary would have refused essentially every steer.
///
/// Five seconds absorbs that and a small clock slew. What a tolerance
/// costs is a session that lived for less than it before being
/// replaced — every sustained session, and every replacement caused by
/// a bgpd restart (a UniFi upload), moves the epoch by the old session's
/// whole lifetime, which is minutes at least.
pub const EPOCH_TOLERANCE_SECS: u64 = 5;

/// Is `now` the epoch of a DIFFERENT session from `prev`?
///
/// Only a forward move beyond the tolerance. A replacement session is
/// established after the one it replaces, so its epoch is later by at
/// least the old session's lifetime; a BACKWARD move is never a new
/// session — it is the derivation's jitter, or the wall clock stepping
/// back, and treating it as a flap is how an idle box revoked itself.
pub fn is_new_session(prev: u64, now: u64) -> bool {
    now > prev.saturating_add(EPOCH_TOLERANCE_SECS)
}

/// Decide eligibility from one tick's readings.
///
/// `seen_epochs` is read AND updated here, because the session-
/// generation check is a comparison against the last successful reading
/// and the two must not drift apart.
///
/// Precedence, and each step of it is load-bearing:
///
/// 1. **A narrowed export policy disqualifies outright**, whatever the
///    upstreams say. It is the condition the counts are completely blind
///    to — at a 1% tolerance a filter dropping 5,000 of a million reads
///    `Converged` — so it can only ever be refused on the configuration.
///    An export policy that could not be READ is a different matter: it
///    is recorded and the upstreams are still evaluated, because a
///    concrete not-ready upstream in the same tick outranks it.
/// 2. **An upstream that answered and is not ready disqualifies**, and
///    returns immediately: no later upstream can make this one ready.
/// 3. **A session that re-established since the last reading
///    disqualifies**, even when it is ready NOW. The permission standing
///    at that moment was earned by a session that no longer exists, and
///    on this platform a session flap is what an FRR configuration
///    upload looks like — so the export policy read alongside the old
///    reading may not be the current one. Revocation is sticky, so the
///    cost is one tick.
/// 4. **A ready upstream with no session epoch is `Unknown`.** Not
///    `Revoked` — nothing disqualifying was observed, something simply
///    could not be read — but not `Ok` either, because readiness with
///    no session identity behind it is the decision the epoch exists to
///    prevent.
/// 5. **A read that failed is `Unknown`, and only if nothing above
///    fired.** Positive evidence outranks a partial read: one upstream
///    timing out must not hide another one answering "not Established".
pub fn classify_eligibility(
    export: Result<ExportPolicy, String>,
    upstreams: &[(IpAddr, Result<UpstreamState, String>)],
    seen_epochs: &mut HashMap<IpAddr, u64>,
) -> Eligibility {
    // The export read is CLASSIFIED first and ACTED ON last, and those
    // are different things. A filtered export is positive evidence and
    // outranks everything; a read that failed is not, and returning
    // early on it threw away a concrete "this upstream is down" that the
    // same tick had already established — publishing `Unreadable`, which
    // retains a permitting report for its full 900 s, over a table the
    // tick had just proved incomplete (review finding, PR #232). The
    // documented precedence says positive evidence outranks a partial
    // read; this is that rule applied to the export read too.
    let mut unknown: Option<String> = None;
    match export {
        Ok(ExportPolicy::Filtered { why }) => {
            return Eligibility::Revoked(Revocation::UnsupportedExport(why))
        }
        Ok(ExportPolicy::Unfiltered) => {}
        Err(e) => unknown = Some(e),
    }

    let mut moved: Option<String> = None;
    for (peer, result) in upstreams {
        let state = match result {
            Ok(s) => s,
            Err(e) => {
                unknown.get_or_insert(e.clone());
                continue;
            }
        };
        if let Some(why) = state.why_not_ready() {
            return Eligibility::Revoked(Revocation::UpstreamNotReady(why));
        }
        // Ready — but is it the same session the standing permission was
        // earned under? Recorded even when it is the first sighting, so
        // the NEXT tick has something to compare against.
        //
        // No epoch means that question CANNOT be asked. `ready()`
        // answers "the table is loaded" from the neighbor document
        // alone, and without an epoch there is nothing tying that answer
        // to a session — a future FRR that renames the field, or a
        // summary whose schema drifts, would hand back a completeness
        // decision with no session identity behind it, which is exactly
        // what the epoch was introduced to prevent. `Unknown` rather
        // than `Revoked`: we failed to read something, we did not
        // observe a disqualifying fact (review finding, PR #229).
        let Some(epoch) = state.established_epoch else {
            unknown.get_or_insert(format!(
                "upstream {peer} reports Established with End-of-RIB, but FRR gave no \
                 `peerUptimeEstablishedEpoch` for it — without a session generation \
                 there is nothing to tie that readiness to the current session, so it \
                 cannot be acted on"
            ));
            continue;
        };
        if let Some(prev) = seen_epochs.insert(*peer, epoch) {
            if is_new_session(prev, epoch) && moved.is_none() {
                moved = Some(format!(
                    "upstream {peer} re-established since the last check (epoch \
                     {prev} → {epoch}); on this platform an FRR configuration \
                     upload restarts bgpd and flaps every session, so the previous \
                     reading described a session that no longer exists — and the \
                     export policy it was taken under may not be the current one"
                ));
            }
        }
    }

    if let Some(why) = moved {
        return Eligibility::Revoked(Revocation::UpstreamNotReady(why));
    }
    match unknown {
        Some(e) => Eligibility::Unknown(e),
        None => Eligibility::Ok,
    }
}

/// One upstream read twice in a check: right after the counts, and
/// again after the running-config.
#[derive(Debug, Clone)]
pub struct UpstreamBracket {
    pub peer: IpAddr,
    /// The reading that describes the upstream when the counts were
    /// taken.
    pub before: Result<UpstreamState, String>,
    /// The reading after the check's slowest read, which is what the
    /// published observation has to still be true at.
    pub after: Result<UpstreamState, String>,
}

/// [`classify_eligibility`] over a check that read every upstream on
/// BOTH sides of the running-config.
///
/// One reading cannot be placed well. Taken before the running-config,
/// an upstream that flaps during that read (the slowest one on a loaded
/// box) goes unseen and the check publishes clean on the dead session's
/// state (review finding, PR #268). Taken after it, End-of-RIB arriving
/// during the read pairs a mid-fill count with readiness that came
/// later — the vacuous gate. So both, and the check has to hold at each
/// end:
///
/// - **Not ready in either reading is readiness loss.** Before: the
///   counts were taken of a table still filling, whatever it says now.
///   After: it is not ready now. Either is positive evidence, so it
///   outranks a failed read of the other side.
/// - **An epoch that moved between the two is readiness loss**, for the
///   reason [`is_new_session`] exists: the counts describe a session
///   that is gone. It is caught here even on the first sighting, when
///   the previous-check comparison inside `classify_eligibility` has
///   nothing to compare against.
/// - **Anything unreadable on either side is `Unknown`**, including a
///   `before` reading that is ready but carries no epoch — with no
///   session identity at count time there is nothing to show the
///   session held.
///
/// Classification then runs on the `after` readings, so the
/// previous-check epochs are updated from the latest sample.
pub fn classify_bracketed(
    export: Result<ExportPolicy, String>,
    brackets: &[UpstreamBracket],
    seen_epochs: &mut HashMap<IpAddr, u64>,
) -> Eligibility {
    let mut moved: Option<String> = None;
    let merged: Vec<(IpAddr, Result<UpstreamState, String>)> = brackets
        .iter()
        .map(|b| {
            let peer = b.peer;
            let state = match (&b.before, &b.after) {
                (Ok(before), _) if !before.ready() => Ok(before.clone()),
                (_, Ok(after)) if !after.ready() => Ok(after.clone()),
                (Ok(before), Ok(after)) => {
                    match (before.established_epoch, after.established_epoch) {
                        (Some(e0), Some(e1)) => {
                            if is_new_session(e0, e1) && moved.is_none() {
                                moved = Some(format!(
                                "upstream {peer} re-established during the check (epoch {e0} → \
                                 {e1}), so the counts it took describe a session that no \
                                 longer exists"
                            ));
                            }
                            Ok(after.clone())
                        }
                        (None, _) => Err(format!(
                            "upstream {peer} gave no `peerUptimeEstablishedEpoch` when the counts \
                         were taken, so nothing shows its session held through the check"
                        )),
                        // `classify_eligibility` reports the missing epoch.
                        (Some(_), None) => Ok(after.clone()),
                    }
                }
                (Err(e), _) | (_, Err(e)) => Err(e.clone()),
            };
            (peer, state)
        })
        .collect();
    match (classify_eligibility(export, &merged, seen_epochs), moved) {
        (revoked @ Eligibility::Revoked(_), _) => revoked,
        (_, Some(why)) => Eligibility::Revoked(Revocation::UpstreamNotReady(why)),
        (other, None) => other,
    }
}

/// Does the feed deliver a family no declared upstream carries?
///
/// The two halves of the comparison must count the same thing. The
/// authority side sums only the declared families; the mirror side is
/// the whole mirror, because that is what a steer would divert traffic
/// into. When the feed carries a family nobody declared, those two are
/// measuring different sets — and the arithmetic reads the mirror as
/// LARGER than the authority, which `assess` classifies as
/// `AuthorityMismatch`: "that is not the authority feeding this mirror".
/// It is, and the message would send an operator to check which FRR
/// `vtysh` is talking to when the answer is one missing word in their
/// own config.
///
/// **Route-source routes only.** The first version took its evidence
/// from `mirror_counts()`, which includes the synthetic `local-prefix`
/// /32s and /128s the neighbour resolver injects under `local_arp` —
/// resident for the daemon's life, belonging to no session. One
/// `local-prefix6` on a v4-only box then read as "the feed carries v6",
/// and this check revoked, stickily, a perfectly valid deployment: the
/// refuse-forever failure the whole family redesign existed to remove,
/// reintroduced by the check meant to guard it (review finding, PR
/// #234). The caller passes `FibProgrammerHandle::session_families`.
///
/// Reported as a revocation rather than left to the counts, for the
/// reason every other conjunct here exists: it is a fact about the
/// deployment that the numbers can only misdescribe. Narrowing the
/// mirror side to the declared families instead would be worse — it
/// would attest a table whose other half nobody compared, which is
/// exactly what declaring too few families is supposed to prevent.
pub fn mirror_family_mismatch(
    session_v4: bool,
    session_v6: bool,
    declared: &[AuthorityFamily],
) -> Option<Revocation> {
    for (present, family) in [
        (session_v4, AuthorityFamily::V4),
        (session_v6, AuthorityFamily::V6),
    ] {
        if present && !declared.contains(&family) {
            return Some(Revocation::UnsupportedExport(format!(
                "the route feed is delivering {} routes, but no declared upstream carries \
                 {} — the comparison would count the authority's declared families against \
                 the whole mirror, which reads as a mismatch rather than the missing \
                 declaration it is. Add `families` covering {} to the upstream that carries \
                 it (restart-only)",
                family.afi(),
                family.afi(),
                family.afi()
            )));
        }
    }
    None
}

/// The single observation a tick publishes to the steering gate.
///
/// Three inputs, one answer, and the combination rules are why this is
/// not written inline at the call site:
///
/// - A disqualification publishes regardless of the counts. It is a fact
///   about the deployment, and the counts cannot argue with it.
/// - `Clean` needs eligibility AND both fresh counts. A tick that read
///   eligibility fine and lost a count has established nothing new.
/// - Everything else is `Unreadable`, which is not neutral — it retains
///   the previous report under the age policy and retains any standing
///   revocation. That is the whole reason it is a distinct outcome and
///   not "publish nothing".
pub fn observation(
    eligibility: &Eligibility,
    authority: Option<usize>,
    mirror: Option<usize>,
    at: std::time::Instant,
) -> AuthorityObservation {
    match (eligibility, authority, mirror) {
        (Eligibility::Revoked(r), _, _) => AuthorityObservation::Disqualified(r.clone()),
        (Eligibility::Ok, Some(auth), Some(pf)) => {
            AuthorityObservation::Clean(CompletenessReport {
                authority_routes: auth as u64,
                mirror_routes: pf as u64,
                at,
            })
        }
        _ => AuthorityObservation::Unreadable,
    }
}

/// The first retry after an `Unreadable` check, and the base its
/// backoff doubles from. The same ten seconds as the interval floor
/// (`FRR_INTERVAL_SECS`), and for the same reason: below it a slow
/// check simply runs back to back.
pub const UNREADABLE_RETRY_FLOOR: std::time::Duration = std::time::Duration::from_secs(10);

/// How long the checker sleeps before its next check, given how many
/// checks in a row have come back `Unreadable`.
///
/// A readable check — `Clean` or `Disqualified` — is followed by the
/// full interval. An unreadable one is retried sooner, because it
/// established nothing and the retained report is what a steering gate
/// is left holding: vpp-offload's fresh-convergence hold releases only
/// on a CURRENT converged report, so on a loaded full-table box every
/// timed-out sample used to cost a whole interval of delayed verify
/// after the table was already complete.
///
/// **Doubling, capped at the interval**, rather than a fixed short
/// retry. Most unreadable checks are a daemon too busy to answer in the
/// subprocess budget, and killing a timed-out `vtysh` does not withdraw
/// the command it already wrote — that is queued on the daemon's socket
/// and runs when the daemon's event loop reaches it (how a vty session
/// reads its input; not measured here) — so an aggressive retry stacks a
/// second table walk behind the first. The rest are persistent — output
/// this parser does not accept, a ready upstream with no epoch — and a
/// fixed retry would run the whole check every ten seconds for as long
/// as they last. The backoff reaches the interval within a few attempts
/// either way.
///
/// Nothing about what an unreadable check MEANS changes: it retains the
/// previous report under the age policy and any standing revocation.
/// This only decides when the next chance to renew it comes.
pub fn next_check_delay(
    interval: std::time::Duration,
    consecutive_unreadable: u32,
) -> std::time::Duration {
    let Some(doublings) = consecutive_unreadable.checked_sub(1) else {
        return interval;
    };
    let factor = 1u32.checked_shl(doublings).unwrap_or(u32::MAX);
    UNREADABLE_RETRY_FLOOR.saturating_mul(factor).min(interval)
}

/// Split `vtysh`'s concatenated output into its first two JSON
/// documents.
///
/// `vtysh -c A -c B` writes both answers to one stream with nothing
/// between them. Two commands in one invocation is what lets a caller
/// sample a session's state and the epoch that qualifies it from ONE
/// view of FRR — read from two processes, a flap can land between them
/// and produce a reading that is self-consistently wrong.
///
/// String-aware, because a route-map name, a peer description or an
/// interface name can contain a brace and a naive depth count would cut
/// in the wrong place.
pub fn split_two_json(out: &str) -> Option<(&str, &str)> {
    let bytes = out.as_bytes();
    let start = out.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for i in start..bytes.len() {
        let c = bytes[i];
        if in_string {
            match c {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&out[start..=i], &out[i + 1..]));
                }
            }
            _ => {}
        }
    }
    None
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
      "routerId":"192.0.2.201",
      "as":65000,
      "ribCount":5,
      "peers":{
        "192.168.10.1":{
          "state":"Established",
          "pfxRcd":3,
          "peerUptimeEstablishedEpoch":1790045332
        },
        "192.0.2.202":{"state":"Active","pfxRcd":0}
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
            parse_established_epoch(SUMMARY, "192.0.2.202"),
            None,
            "a peer that has never come up has no epoch"
        );
    }

    /// The shape the lab gateway runs: next-hop-self only.
    #[test]
    fn next_hop_self_alone_is_unfiltered() {
        let cfg = "\
router bgp 65000
 neighbor 192.0.2.202 remote-as 65000
 address-family ipv4 unicast
  neighbor 192.0.2.202 next-hop-self force
 exit-address-family
";
        assert_eq!(
            parse_export_policy(cfg, "192.0.2.202", DUAL),
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
  neighbor 192.0.2.202 route-map TRIM out
 exit-address-family
";
        match parse_export_policy(cfg, "192.0.2.202", DUAL) {
            ExportPolicy::Filtered { why } => assert!(why.contains("route-map"), "{why}"),
            other => panic!("expected Filtered, got {other:?}"),
        }
    }

    #[test]
    fn a_prefix_list_is_filtering() {
        let cfg = "  neighbor 192.0.2.202 prefix-list ONLY-SOME out\n";
        assert!(matches!(
            parse_export_policy(cfg, "192.0.2.202", DUAL),
            ExportPolicy::Filtered { .. }
        ));
    }

    /// The primary's shape (2026-09-24): an inbound route-map hardening
    /// the packetframe session. It governs what packetframe advertises
    /// to FRR — nothing — so it must not disqualify the mirror.
    #[test]
    fn an_inbound_filter_on_the_peer_is_not_export_policy() {
        let cfg = "\
router bgp 65000
 neighbor 192.0.2.202 remote-as 65000
 address-family ipv4 unicast
  neighbor 192.0.2.202 route-map PACKETFRAME-IN in
  neighbor 192.0.2.202 prefix-list NOTHING in
  neighbor 192.0.2.202 maximum-prefix 10
 exit-address-family
";
        assert_eq!(
            parse_export_policy(cfg, "192.0.2.202", DUAL),
            ExportPolicy::Unfiltered
        );
    }

    /// Outbound still disqualifies, beside an inbound one, and via a
    /// peer-group; so do the outbound-only knobs.
    #[test]
    fn outbound_policy_still_disqualifies_beside_an_inbound_one() {
        let cfg = "\
  neighbor 192.0.2.202 route-map PACKETFRAME-IN in
  neighbor 192.0.2.202 route-map TRIM out
";
        let ExportPolicy::Filtered { why } = parse_export_policy(cfg, "192.0.2.202", DUAL) else {
            panic!("an outbound route-map must disqualify");
        };
        assert!(why.contains("TRIM out"), "names the outbound line: {why}");

        for tail in [
            "maximum-prefix-out 100",
            "unsuppress-map SOME",
            "distribute-list 10 out",
            "filter-list AS out",
        ] {
            let cfg = format!("  neighbor 192.0.2.202 {tail}\n");
            assert!(
                matches!(
                    parse_export_policy(&cfg, "192.0.2.202", DUAL),
                    ExportPolicy::Filtered { .. }
                ),
                "{tail}"
            );
        }

        let cfg = "\
 neighbor PF route-map PF-IN in
 neighbor 192.0.2.202 peer-group PF
";
        assert_eq!(
            parse_export_policy(cfg, "192.0.2.202", DUAL),
            ExportPolicy::Unfiltered,
            "an inherited inbound filter is no more export policy than the peer's own"
        );
    }

    /// Another peer's filter says nothing about ours.
    #[test]
    fn a_filter_on_a_different_peer_is_ignored() {
        let cfg = "  neighbor 192.168.10.1 route-map UPSTREAM in\n";
        assert_eq!(
            parse_export_policy(cfg, "192.0.2.202", DUAL),
            ExportPolicy::Unfiltered
        );
    }

    const V4: &[AuthorityFamily] = &[AuthorityFamily::V4];
    const V6: &[AuthorityFamily] = &[AuthorityFamily::V6];
    const DUAL: &[AuthorityFamily] = &[AuthorityFamily::V4, AuthorityFamily::V6];

    fn filtered_why(cfg: &str, families: &[AuthorityFamily]) -> String {
        match parse_export_policy(cfg, "192.0.2.202", families) {
            ExportPolicy::Filtered { why } => why,
            ExportPolicy::Unfiltered => panic!("expected Filtered for {families:?}"),
        }
    }

    /// The shape of the FRR 10 production router whose first launch
    /// disqualified the mirror: an inbound deny-all, and outbound maps
    /// that rewrite attributes and drop nothing. Sanitized, structure
    /// verbatim.
    const PASS_ALL_OUT: &str = "\
router bgp 64500
 neighbor 192.0.2.202 remote-as 64500
 !
 address-family ipv4 unicast
  neighbor 192.0.2.202 activate
  neighbor 192.0.2.202 send-community all
  neighbor 192.0.2.202 route-map PF-IN in
  neighbor 192.0.2.202 route-map PF-OUT-V4 out
 exit-address-family
 !
 address-family ipv6 unicast
  neighbor 192.0.2.202 activate
  neighbor 192.0.2.202 route-map PF-IN in
  neighbor 192.0.2.202 route-map PF-OUT-V6 out
 exit-address-family
exit
!
bgp as-path access-list LOCAL-ORIGIN seq 5 permit ^$
!
route-map PF-IN deny 10
exit
!
route-map PF-OUT-V4 permit 10
exit
!
route-map PF-OUT-V6 permit 10
 match as-path LOCAL-ORIGIN
 set ipv6 next-hop global 2001:db8::2
exit
!
route-map PF-OUT-V6 permit 20
exit
";

    #[test]
    fn a_pass_all_outbound_route_map_is_unfiltered() {
        for families in [V4, V6, DUAL] {
            assert_eq!(
                parse_export_policy(PASS_ALL_OUT, "192.0.2.202", families),
                ExportPolicy::Unfiltered,
                "{families:?}"
            );
        }
    }

    /// A `deny` walked before the first unconditional permit drops the
    /// routes it matches; the message names the entry.
    #[test]
    fn a_deny_before_the_unconditional_permit_is_filtering() {
        let cfg = "\
router bgp 64500
 address-family ipv4 unicast
  neighbor 192.0.2.202 route-map TRIM out
 exit-address-family
exit
route-map TRIM deny 10
 match ip address prefix-list SOME
exit
route-map TRIM permit 20
exit
";
        let why = filtered_why(cfg, V4);
        assert!(why.contains("route-map TRIM out"), "names the line: {why}");
        assert!(why.contains("`deny 10`"), "and the entry: {why}");
        assert!(why.contains("address-family ipv4 unicast"), "{why}");
    }

    /// Sequence order, not rendering order, decides which entry is
    /// walked first.
    #[test]
    fn entries_are_walked_in_sequence_order() {
        let cfg = "\
 neighbor 192.0.2.202 route-map TRIM out
route-map TRIM permit 20
exit
route-map TRIM deny 10
exit
";
        assert!(filtered_why(cfg, V4).contains("`deny 10`"));
    }

    /// Every entry conditional: a route none of them matches meets
    /// FRR's implicit deny.
    #[test]
    fn a_map_with_only_conditional_permits_is_filtering() {
        let cfg = "\
 neighbor 192.0.2.202 route-map ONLY-LOCAL out
route-map ONLY-LOCAL permit 10
 match as-path LOCAL-ORIGIN
 set local-preference 200
exit
";
        let why = filtered_why(cfg, V4);
        assert!(why.contains("no permit entry without a `match`"), "{why}");
    }

    /// FRR applies a referenced-but-missing map as deny-all.
    #[test]
    fn an_undefined_route_map_is_filtering() {
        let cfg = "\
 address-family ipv4 unicast
  neighbor 192.0.2.202 route-map NOWHERE out
 exit-address-family
";
        let why = filtered_why(cfg, V4);
        assert!(why.contains("NOWHERE is not defined"), "{why}");
    }

    /// Clauses that move a route to an entry the walk never inspected,
    /// and headers that cannot be read, are of unknown shape and narrow.
    #[test]
    fn unknown_route_map_shapes_are_filtering() {
        for clause in ["call OTHER", "on-match goto 30", "continue 30"] {
            let cfg = format!(
                " neighbor 192.0.2.202 route-map M out\nroute-map M permit 10\n {clause}\nexit\n"
            );
            let why = filtered_why(&cfg, V4);
            assert!(why.contains(clause), "{clause}: {why}");
        }
        let cfg = " neighbor 192.0.2.202 route-map M out\nroute-map M permit\nexit\n";
        assert!(filtered_why(cfg, V4).contains("cannot read"));
    }

    /// `set` alone never narrows, before or on the unconditional permit.
    #[test]
    fn set_clauses_do_not_narrow() {
        let cfg = "\
 neighbor 192.0.2.202 route-map REWRITE out
route-map REWRITE permit 10
 description tag everything
 set community 64500:1 additive
 set as-path prepend 64500
exit
";
        assert_eq!(
            parse_export_policy(cfg, "192.0.2.202", V4),
            ExportPolicy::Unfiltered
        );
    }

    /// A filter in the v6 block says nothing about the v4 table, and the
    /// reverse; a v4-only attestation must not refuse over it.
    #[test]
    fn only_the_attested_families_count() {
        let cfg = "\
router bgp 64500
 address-family ipv4 unicast
  neighbor 192.0.2.202 route-map PF-OUT-V4 out
 exit-address-family
 address-family ipv6 unicast
  neighbor 192.0.2.202 route-map TRIM6 out
  neighbor 192.0.2.202 prefix-list SOME6 out
 exit-address-family
exit
route-map PF-OUT-V4 permit 10
exit
route-map TRIM6 deny 10
exit
";
        assert_eq!(
            parse_export_policy(cfg, "192.0.2.202", V4),
            ExportPolicy::Unfiltered
        );
        let why = filtered_why(cfg, V6);
        assert!(why.contains("TRIM6"), "{why}");
        assert!(why.contains("address-family ipv6 unicast"), "{why}");
        assert!(filtered_why(cfg, DUAL).contains("TRIM6"));

        let v4_only = cfg.replace(
            "route-map PF-OUT-V4 permit 10",
            "route-map PF-OUT-V4 deny 10",
        );
        let v4_only = v4_only.replace("TRIM6 out", "PF-OUT-V4 in");
        let v4_only = v4_only.replace("prefix-list SOME6 out", "activate");
        assert!(filtered_why(&v4_only, V4).contains("PF-OUT-V4"));
        assert_eq!(
            parse_export_policy(&v4_only, "192.0.2.202", V6),
            ExportPolicy::Unfiltered
        );
    }

    /// Outside any address-family block — including after one closes —
    /// a line applies to every family.
    #[test]
    fn a_line_outside_any_address_family_applies_to_every_family() {
        let cfg = "\
router bgp 64500
 address-family ipv6 unicast
  neighbor 192.0.2.202 activate
 exit-address-family
 neighbor 192.0.2.202 prefix-list ONLY-SOME out
exit
";
        for families in [V4, V6] {
            let why = filtered_why(cfg, families);
            assert!(!why.contains("address-family"), "{why}");
        }
    }

    /// A block this cannot place as v4 or v6 counts against every family.
    #[test]
    fn an_unrecognised_address_family_counts_against_every_family() {
        let cfg = "\
 address-family l2vpn evpn
  neighbor 192.0.2.202 route-map NOWHERE out
 exit-address-family
";
        assert!(matches!(
            parse_export_policy(cfg, "192.0.2.202", V4),
            ExportPolicy::Filtered { .. }
        ));
    }

    /// Inheritance is resolved per family too: the group's v6 policy is
    /// found for a v6 attestation and ignored for a v4 one.
    #[test]
    fn peer_group_inheritance_is_per_family() {
        let cfg = "\
router bgp 64500
 neighbor PF peer-group
 neighbor PF remote-as 64500
 neighbor 192.0.2.202 peer-group PF
 address-family ipv4 unicast
  neighbor PF route-map PASS out
 exit-address-family
 address-family ipv6 unicast
  neighbor PF route-map TRIM6 out
 exit-address-family
exit
route-map PASS permit 10
exit
route-map TRIM6 permit 10
 match ipv6 address prefix-list SOME6
exit
";
        assert_eq!(
            parse_export_policy(cfg, "192.0.2.202", V4),
            ExportPolicy::Unfiltered
        );
        let why = filtered_why(cfg, V6);
        assert!(
            why.contains("inherited") && why.contains("peer-group PF"),
            "{why}"
        );
        assert!(why.contains("TRIM6"), "{why}");
    }

    /// The other outbound directives are not looked into and still
    /// narrow in the attested family.
    #[test]
    fn a_prefix_list_out_in_the_attested_family_is_filtering() {
        let cfg = "\
 address-family ipv4 unicast
  neighbor 192.0.2.202 prefix-list ONLY-SOME out
 exit-address-family
";
        let why = filtered_why(cfg, V4);
        assert!(why.contains("prefix-list ONLY-SOME out"), "{why}");
    }

    /// The precedence between "disqualified", "could not read" and
    /// "fine" — the whole safety argument of this authority.
    mod eligibility {
        use super::super::*;
        use std::collections::HashMap;
        use std::net::{IpAddr, Ipv4Addr};

        fn peer(last: u8) -> IpAddr {
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
        }

        fn ready(p: IpAddr, epoch: Option<u64>) -> (IpAddr, Result<UpstreamState, String>) {
            (
                p,
                Ok(UpstreamState {
                    peer: p.to_string(),
                    established: true,
                    missing_eor: Vec::new(),
                    established_epoch: epoch,
                }),
            )
        }

        fn down(p: IpAddr) -> (IpAddr, Result<UpstreamState, String>) {
            (
                p,
                Ok(UpstreamState {
                    peer: p.to_string(),
                    established: false,
                    missing_eor: Vec::new(),
                    established_epoch: None,
                }),
            )
        }

        fn filling(p: IpAddr) -> (IpAddr, Result<UpstreamState, String>) {
            (
                p,
                Ok(UpstreamState {
                    peer: p.to_string(),
                    established: true,
                    missing_eor: vec![AuthorityFamily::V4],
                    established_epoch: Some(1000),
                }),
            )
        }

        fn unreadable(p: IpAddr) -> (IpAddr, Result<UpstreamState, String>) {
            (p, Err("vtysh timed out after 10s".into()))
        }

        #[test]
        fn everything_ready_and_unfiltered_is_eligible() {
            let mut seen = HashMap::new();
            let e = classify_eligibility(
                Ok(ExportPolicy::Unfiltered),
                &[ready(peer(1), Some(1000)), ready(peer(2), Some(1001))],
                &mut seen,
            );
            assert_eq!(e, Eligibility::Ok);
            assert_eq!(seen.len(), 2, "and the epochs are banked for next tick");
        }

        /// An Established peer that has not sent End-of-RIB is the case
        /// this authority exists for: measured on the lab gateway two
        /// seconds after `clear bgp`, and session state alone would have
        /// called that table complete.
        #[test]
        fn established_without_end_of_rib_is_revoked() {
            let mut seen = HashMap::new();
            let Eligibility::Revoked(Revocation::UpstreamNotReady(why)) =
                classify_eligibility(Ok(ExportPolicy::Unfiltered), &[filling(peer(1))], &mut seen)
            else {
                panic!("a filling upstream must revoke");
            };
            assert!(why.contains("End-of-RIB"), "{why}");
        }

        #[test]
        fn a_down_upstream_is_revoked() {
            let mut seen = HashMap::new();
            assert!(matches!(
                classify_eligibility(Ok(ExportPolicy::Unfiltered), &[down(peer(1))], &mut seen),
                Eligibility::Revoked(Revocation::UpstreamNotReady(_))
            ));
        }

        /// Export policy outranks everything, because it is the one
        /// condition the counts cannot see at all.
        #[test]
        fn a_narrowed_export_revokes_even_with_every_upstream_ready() {
            let mut seen = HashMap::new();
            let e = classify_eligibility(
                Ok(ExportPolicy::Filtered {
                    why: "neighbor 198.51.100.2 route-map OUT out".into(),
                }),
                &[ready(peer(1), Some(1000))],
                &mut seen,
            );
            assert!(matches!(
                e,
                Eligibility::Revoked(Revocation::UnsupportedExport(_))
            ));
            assert!(
                seen.is_empty(),
                "and it short-circuits — no point reading sessions for a feed that is \
                 filtered whatever they say"
            );
        }

        /// **Positive evidence outranks a partial read.** One upstream
        /// timing out must not hide another one answering "not
        /// Established": the safe outcome and the honest one are the
        /// same here, and collapsing them would make a disqualification
        /// depend on which peer the loop reached first.
        #[test]
        fn a_disqualification_beats_an_unreadable_peer_in_either_order() {
            for order in [
                vec![unreadable(peer(1)), down(peer(2))],
                vec![down(peer(2)), unreadable(peer(1))],
            ] {
                let mut seen = HashMap::new();
                assert!(
                    matches!(
                        classify_eligibility(Ok(ExportPolicy::Unfiltered), &order, &mut seen),
                        Eligibility::Revoked(_)
                    ),
                    "order must not decide this"
                );
            }
        }

        /// An unreadable export policy must not bury a concrete
        /// upstream disqualification found in the same tick.
        ///
        /// The first version returned `Unknown` the moment `show
        /// running-config` failed, discarding a "this peer is down" the
        /// tick had already established. `Unreadable` then retains a
        /// PERMITTING report for its full 900 s over a table the tick
        /// had just proved incomplete — the documented precedence
        /// (positive evidence outranks a partial read) applied
        /// everywhere except here (review finding, PR #232).
        #[test]
        fn an_unreadable_export_does_not_hide_a_down_upstream() {
            let mut seen = HashMap::new();
            let e = classify_eligibility(
                Err("vtysh timed out after 10s".into()),
                &[down(peer(1))],
                &mut seen,
            );
            assert!(
                matches!(e, Eligibility::Revoked(Revocation::UpstreamNotReady(_))),
                "the disqualification is a fact; the failed read is not: {e:?}"
            );
        }

        /// But a filtered export still outranks everything, since it is
        /// positive evidence too and the one the counts cannot see.
        #[test]
        fn a_filtered_export_outranks_a_down_upstream() {
            let mut seen = HashMap::new();
            let e = classify_eligibility(
                Ok(ExportPolicy::Filtered {
                    why: "neighbor 198.51.100.2 route-map OUT out".into(),
                }),
                &[down(peer(1))],
                &mut seen,
            );
            assert!(matches!(
                e,
                Eligibility::Revoked(Revocation::UnsupportedExport(_))
            ));
        }

        /// A read that failed and nothing else is `Unknown`, which is
        /// NOT a disqualification: it retains whatever eligibility
        /// stands rather than withdrawing one on no evidence.
        #[test]
        fn an_unreadable_peer_alone_is_unknown() {
            let mut seen = HashMap::new();
            let e = classify_eligibility(
                Ok(ExportPolicy::Unfiltered),
                &[ready(peer(1), Some(1000)), unreadable(peer(2))],
                &mut seen,
            );
            let Eligibility::Unknown(why) = e else {
                panic!("expected Unknown, got {e:?}");
            };
            assert!(why.contains("timed out"), "{why}");
        }

        /// So is an unreadable running-config — and it short-circuits,
        /// because an export policy we could not read is not one we can
        /// call unfiltered.
        #[test]
        fn an_unreadable_export_policy_is_unknown() {
            let mut seen = HashMap::new();
            assert!(matches!(
                classify_eligibility(
                    Err("vtysh exited 1".into()),
                    &[ready(peer(1), Some(1000))],
                    &mut seen
                ),
                Eligibility::Unknown(_)
            ));
        }

        /// Readiness with no session epoch cannot be acted on.
        ///
        /// `ready()` answers "the table is loaded" from the neighbor
        /// document alone. The epoch is what ties that answer to a
        /// session, and without one there is nothing to compare against
        /// next tick and nothing to prove the End-of-RIB belongs to the
        /// session running now — a completeness decision with no session
        /// identity behind it, which is the thing the epoch was
        /// introduced to prevent.
        ///
        /// `Unknown`, not `Revoked`: a field we could not read is not a
        /// disqualifying fact, and reporting it as one would send an
        /// operator to inspect a BGP config that is fine.
        #[test]
        fn a_ready_upstream_with_no_epoch_is_unknown() {
            let mut seen = HashMap::new();
            let e = classify_eligibility(
                Ok(ExportPolicy::Unfiltered),
                &[ready(peer(1), None)],
                &mut seen,
            );
            let Eligibility::Unknown(why) = e else {
                panic!("expected Unknown, got {e:?}");
            };
            assert!(why.contains("peerUptimeEstablishedEpoch"), "{why}");
            assert!(
                seen.is_empty(),
                "and nothing is banked, or the next tick would compare against a \
                 generation this one never established"
            );
        }

        /// One upstream missing its epoch does not mask another
        /// upstream's positive disqualification.
        #[test]
        fn a_disqualification_still_beats_a_missing_epoch() {
            let mut seen = HashMap::new();
            assert!(matches!(
                classify_eligibility(
                    Ok(ExportPolicy::Unfiltered),
                    &[ready(peer(1), None), down(peer(2))],
                    &mut seen
                ),
                Eligibility::Revoked(_)
            ));
        }

        /// A session that re-established since the last reading revokes
        /// **even though it is ready now**.
        ///
        /// The permission standing at that moment was earned by a
        /// session that no longer exists, and on UniFi a session flap is
        /// what an FRR configuration upload looks like — so the export
        /// policy read alongside the old reading may not be the current
        /// one. Revocation is sticky, so this costs exactly one tick.
        #[test]
        fn a_re_established_session_revokes_for_one_tick() {
            let mut seen = HashMap::new();
            assert_eq!(
                classify_eligibility(
                    Ok(ExportPolicy::Unfiltered),
                    &[ready(peer(1), Some(1000))],
                    &mut seen
                ),
                Eligibility::Ok
            );

            let Eligibility::Revoked(Revocation::UpstreamNotReady(why)) = classify_eligibility(
                Ok(ExportPolicy::Unfiltered),
                &[ready(peer(1), Some(2000))],
                &mut seen,
            ) else {
                panic!("a moved epoch must revoke");
            };
            assert!(why.contains("1000 → 2000"), "{why}");

            // And the new epoch is banked, so the very next tick is
            // clean again — one tick of caution, not a latch.
            assert_eq!(
                classify_eligibility(
                    Ok(ExportPolicy::Unfiltered),
                    &[ready(peer(1), Some(2000))],
                    &mut seen
                ),
                Eligibility::Ok
            );
        }

        /// The lab rig's exact readings: one idle session, two ticks,
        /// the epoch one second LOWER on the second. Exact comparison
        /// revoked the mirror for it (2026-09-22).
        #[test]
        fn epoch_jitter_on_an_idle_session_is_not_a_re_establishment() {
            let mut seen = HashMap::new();
            for epoch in [1_790_066_204, 1_790_066_203, 1_790_066_204, 1_790_066_203] {
                assert_eq!(
                    classify_eligibility(
                        Ok(ExportPolicy::Unfiltered),
                        &[ready(peer(1), Some(epoch))],
                        &mut seen
                    ),
                    Eligibility::Ok,
                    "a reading alternating by a second is one session, not a flap per tick"
                );
            }
        }

        /// Backward is never a new session, however far — it is the
        /// wall clock stepping back, not a session established earlier
        /// than the one it replaced.
        #[test]
        fn a_backward_epoch_move_is_never_a_new_session() {
            assert!(!is_new_session(1_000_000, 999_000));
            assert!(!is_new_session(1_000_000, 999_999));
        }

        /// The tolerance boundary, both sides.
        #[test]
        fn only_a_forward_move_beyond_the_tolerance_is_a_new_session() {
            let t = EPOCH_TOLERANCE_SECS;
            assert!(!is_new_session(1_000, 1_000));
            assert!(!is_new_session(1_000, 1_000 + t));
            assert!(is_new_session(1_000, 1_000 + t + 1));
            // What a real flap looks like on the rig: `clear bgp` moved
            // it by ~4 hours of session lifetime.
            assert!(is_new_session(1_790_052_235, 1_790_066_204));
        }

        /// The FIRST sighting of a peer is not a move.
        #[test]
        fn a_first_sighting_is_not_a_re_establishment() {
            let mut seen = HashMap::new();
            assert_eq!(
                classify_eligibility(
                    Ok(ExportPolicy::Unfiltered),
                    &[ready(peer(1), Some(7))],
                    &mut seen
                ),
                Eligibility::Ok,
                "a fresh daemon has nothing to compare against and must not refuse for it"
            );
        }
    }

    /// What a tick publishes, from the three things it knows.
    mod observations {
        use super::super::*;
        use packetframe_common::fib::AuthorityObservation;
        use std::time::Instant;

        fn revoked() -> Eligibility {
            Eligibility::Revoked(Revocation::UpstreamNotReady(
                "upstream 192.0.2.1 down".into(),
            ))
        }

        #[test]
        fn a_disqualification_publishes_whatever_the_counts_say() {
            for counts in [(Some(10), Some(10)), (None, None), (Some(10), None)] {
                assert!(
                    matches!(
                        observation(&revoked(), counts.0, counts.1, Instant::now()),
                        AuthorityObservation::Disqualified(_)
                    ),
                    "the counts cannot argue with a fact about the deployment"
                );
            }
        }

        #[test]
        fn clean_needs_eligibility_and_both_counts() {
            let at = Instant::now();
            assert!(matches!(
                observation(&Eligibility::Ok, Some(100), Some(99), at),
                AuthorityObservation::Clean(_)
            ));
            for counts in [(None, Some(99)), (Some(100), None), (None, None)] {
                assert_eq!(
                    observation(&Eligibility::Ok, counts.0, counts.1, at),
                    AuthorityObservation::Unreadable,
                    "a tick that lost a count has established nothing new"
                );
            }
        }

        /// `Unknown` never publishes a report, however good the counts
        /// look. Eligibility we could not establish is not eligibility.
        #[test]
        fn unknown_eligibility_never_produces_a_report() {
            assert_eq!(
                observation(
                    &Eligibility::Unknown("vtysh timed out".into()),
                    Some(1_000_000),
                    Some(1_000_000),
                    Instant::now()
                ),
                AuthorityObservation::Unreadable
            );
        }
    }

    /// Splitting the two-command `vtysh` response.
    mod splitting {
        use super::super::*;

        #[test]
        fn it_cuts_between_two_documents() {
            let (a, b) = split_two_json(r#"{"x":1}{"y":2}"#).expect("two documents");
            assert_eq!(a, r#"{"x":1}"#);
            assert_eq!(b.trim(), r#"{"y":2}"#);
        }

        #[test]
        fn whitespace_and_a_leading_banner_do_not_break_it() {
            let (a, b) = split_two_json("\n{\n  \"x\": 1\n}\n\n{\"y\":2}\n").expect("two");
            assert!(a.contains("\"x\""));
            assert_eq!(b.trim(), r#"{"y":2}"#);
        }

        /// The reason this is not a depth counter: FRR emits peer
        /// descriptions, route-map names and interface names verbatim,
        /// and a brace inside one would cut the first document short —
        /// handing the parser a truncated body and the caller a
        /// "not JSON" error on output that was fine.
        #[test]
        fn a_brace_inside_a_string_is_not_a_delimiter() {
            let (a, b) = split_two_json(r#"{"desc":"peer {A}","n":{"k":1}}{"y":2}"#).expect("two");
            assert_eq!(a, r#"{"desc":"peer {A}","n":{"k":1}}"#);
            assert_eq!(b, r#"{"y":2}"#);
        }

        #[test]
        fn an_escaped_quote_does_not_end_the_string() {
            let (a, _) = split_two_json(r#"{"desc":"a \" {b}"}{"y":2}"#).expect("two");
            assert_eq!(a, r#"{"desc":"a \" {b}"}"#);
        }

        #[test]
        fn one_document_or_none_is_no_split() {
            assert!(split_two_json(r#"{"only":1}"#).expect("cuts").1.is_empty());
            assert!(split_two_json("not json at all").is_none());
            assert!(
                split_two_json(r#"{"unterminated": "#).is_none(),
                "a truncated document must not be reported as a clean cut"
            );
        }
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
 neighbor 192.0.2.202 peer-group TRANSIT
 neighbor 192.0.2.202 port 1179
 address-family ipv4 unicast
  neighbor TRANSIT route-map ONLY-CUSTOMERS out
 exit-address-family
";
        let ExportPolicy::Filtered { why } = parse_export_policy(cfg, "192.0.2.202", DUAL) else {
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
 neighbor 192.0.2.202 peer-group TRANSIT
";
        assert!(matches!(
            parse_export_policy(cfg, "192.0.2.202", DUAL),
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
 neighbor 192.0.2.202 peer-group TRANSIT
 neighbor 192.0.2.202 next-hop-self
";
        assert_eq!(
            parse_export_policy(cfg, "192.0.2.202", DUAL),
            ExportPolicy::Unfiltered
        );
    }

    /// Another peer's group must not be attributed to ours.
    #[test]
    fn a_group_this_peer_is_not_in_is_ignored() {
        let cfg = "\
 neighbor CUSTOMERS route-map NARROW out
 neighbor 192.0.2.7 peer-group CUSTOMERS
 neighbor 192.0.2.202 remote-as 65000
";
        assert_eq!(
            parse_export_policy(cfg, "192.0.2.202", DUAL),
            ExportPolicy::Unfiltered
        );
    }

    /// A mirror family nobody declared is named, not left to look like
    /// an authority mismatch.
    ///
    /// Observed reasoning from the rig (2026-09-22): the authority side
    /// sums only the declared families while the mirror side is the
    /// whole mirror. Declare `families v4` on a box whose feed also
    /// carries v6 and the mirror reads LARGER than the authority, which
    /// `assess` calls `AuthorityMismatch` — "that is not the authority
    /// feeding this mirror". It is; the answer is one missing word in
    /// the operator's own config, and the mismatch message sends them to
    /// check which FRR vtysh is talking to instead.
    mod mirror_families {
        use super::super::*;

        #[test]
        fn an_undeclared_family_in_the_feed_revokes_and_says_which() {
            let r = mirror_family_mismatch(true, true, &[AuthorityFamily::V4])
                .expect("v6 in the feed with only v4 declared");
            let why = r.describe();
            assert!(why.contains("delivering ipv6 routes"), "{why}");
            assert!(why.contains("`families`"), "name the remedy: {why}");
            assert!(why.contains("restart-only"), "and that it needs one: {why}");
        }

        /// Symmetric — a v4-only feed under a v6-only declaration is the
        /// same mistake in the other direction.
        #[test]
        fn it_works_in_both_directions() {
            assert!(mirror_family_mismatch(true, false, &[AuthorityFamily::V6]).is_some());
            assert!(mirror_family_mismatch(false, true, &[AuthorityFamily::V4]).is_some());
        }

        /// An ABSENT family is not a mismatch. A dual-stack box whose v6
        /// half has not loaded yet must not be disqualified for it —
        /// that is the ordinary startup shape, and readiness already
        /// covers a feed that never arrives.
        #[test]
        fn a_family_the_feed_is_not_delivering_is_not_a_mismatch() {
            assert!(mirror_family_mismatch(true, false, &[AuthorityFamily::V4]).is_none());
            assert!(mirror_family_mismatch(false, false, &[AuthorityFamily::V4]).is_none());
        }

        #[test]
        fn declaring_what_the_feed_delivers_is_clean() {
            assert!(mirror_family_mismatch(
                true,
                true,
                &[AuthorityFamily::V4, AuthorityFamily::V6]
            )
            .is_none());
        }
    }

    mod check_pacing {
        use super::*;
        use std::time::Duration;

        const INTERVAL: Duration = Duration::from_secs(300);

        /// A readable check — clean or disqualified — keeps the full
        /// interval. The flap cost the runbook states (one to two
        /// intervals) is a property of that, and pacing does not touch
        /// it.
        #[test]
        fn a_readable_check_waits_the_full_interval() {
            assert_eq!(next_check_delay(INTERVAL, 0), INTERVAL);
        }

        /// The first unreadable check retries at the floor and each
        /// further one doubles, so a persistent failure reaches the
        /// interval within a few attempts instead of running the whole
        /// check every ten seconds for as long as it lasts.
        #[test]
        fn unreadable_checks_back_off_from_the_floor_to_the_interval() {
            let got: Vec<u64> = (1..=7)
                .map(|n| next_check_delay(INTERVAL, n).as_secs())
                .collect();
            assert_eq!(got, vec![10, 20, 40, 80, 160, 300, 300]);
        }

        /// The production shape: a short interval caps the backoff at
        /// itself, so a retry is never LATER than the interval would
        /// have been.
        #[test]
        fn the_backoff_never_exceeds_the_interval() {
            let short = Duration::from_secs(30);
            for n in 0..=64 {
                assert!(next_check_delay(short, n) <= short, "streak {n}");
            }
            assert_eq!(next_check_delay(short, 1), UNREADABLE_RETRY_FLOOR);
            assert_eq!(next_check_delay(short, 2), Duration::from_secs(20));
            assert_eq!(next_check_delay(short, 3), short);
        }

        /// A streak long enough to overflow the doubling saturates
        /// rather than wrapping back to a short delay.
        #[test]
        fn a_long_streak_saturates_at_the_interval() {
            assert_eq!(next_check_delay(INTERVAL, 33), INTERVAL);
            assert_eq!(next_check_delay(INTERVAL, u32::MAX), INTERVAL);
        }
    }

    mod bracketed {
        use super::*;

        const PEER: &str = "192.0.2.1";
        const EPOCH: u64 = 1_790_000_000;

        fn state(established: bool, eor: bool, epoch: Option<u64>) -> UpstreamState {
            UpstreamState {
                peer: PEER.to_string(),
                established,
                missing_eor: if eor {
                    vec![]
                } else {
                    vec![AuthorityFamily::V4]
                },
                established_epoch: epoch,
            }
        }

        fn ready(epoch: u64) -> Result<UpstreamState, String> {
            Ok(state(true, true, Some(epoch)))
        }

        fn classify(
            before: Result<UpstreamState, String>,
            after: Result<UpstreamState, String>,
        ) -> Eligibility {
            classify_bracketed(
                Ok(ExportPolicy::Unfiltered),
                &[UpstreamBracket {
                    peer: PEER.parse().expect("ip"),
                    before,
                    after,
                }],
                &mut HashMap::new(),
            )
        }

        fn not_ready(e: &Eligibility) -> bool {
            matches!(e, Eligibility::Revoked(Revocation::UpstreamNotReady(_)))
        }

        /// The session held and was loaded at both ends: clean. Epoch
        /// jitter within the tolerance is the same session.
        #[test]
        fn a_steady_ready_session_is_ok() {
            assert_eq!(classify(ready(EPOCH), ready(EPOCH)), Eligibility::Ok);
            assert_eq!(classify(ready(EPOCH), ready(EPOCH - 1)), Eligibility::Ok);
        }

        /// The review finding: a flap during the running-config read.
        /// On the FIRST check there is no previous epoch to compare
        /// against, so only the two readings of this check can catch it.
        #[test]
        fn an_epoch_that_moves_during_the_check_revokes() {
            let e = classify(ready(EPOCH), ready(EPOCH + 600));
            assert!(not_ready(&e), "{e:?}");
        }

        /// End-of-RIB arriving during the check: the counts were taken
        /// of a table still filling, and the later reading must not
        /// launder them into a clean check.
        #[test]
        fn not_ready_when_the_counts_were_taken_revokes() {
            let e = classify(Ok(state(true, false, Some(EPOCH))), ready(EPOCH));
            assert!(not_ready(&e), "{e:?}");
        }

        #[test]
        fn not_ready_afterwards_revokes_even_past_a_failed_first_read() {
            let e = classify(Err("timed out".into()), Ok(state(false, false, None)));
            assert!(not_ready(&e), "{e:?}");
        }

        /// A failed read on either side of a ready reading establishes
        /// nothing — `Unknown`, which retains, never `Ok`.
        #[test]
        fn a_failed_read_on_either_side_is_unknown() {
            let e = classify(Err("timed out".into()), ready(EPOCH));
            assert!(matches!(e, Eligibility::Unknown(_)), "{e:?}");
            let e = classify(ready(EPOCH), Err("timed out".into()));
            assert!(matches!(e, Eligibility::Unknown(_)), "{e:?}");
        }

        /// No epoch at count time: nothing shows the session held.
        #[test]
        fn no_epoch_when_the_counts_were_taken_is_unknown() {
            let e = classify(Ok(state(true, true, None)), ready(EPOCH));
            assert!(matches!(e, Eligibility::Unknown(_)), "{e:?}");
        }

        /// A within-check flap is positive evidence and outranks a
        /// failed running-config read.
        #[test]
        fn a_within_check_flap_outranks_a_failed_export_read() {
            let e = classify_bracketed(
                Err("vtysh running-config: timed out".into()),
                &[UpstreamBracket {
                    peer: PEER.parse().expect("ip"),
                    before: ready(EPOCH),
                    after: ready(EPOCH + 600),
                }],
                &mut HashMap::new(),
            );
            assert!(not_ready(&e), "{e:?}");
        }

        /// The previous-check comparison still runs, on the latest
        /// reading, and records it for the next check.
        #[test]
        fn the_latest_reading_updates_the_seen_epochs() {
            let peer: IpAddr = PEER.parse().expect("ip");
            let mut seen = HashMap::new();
            let b = |e0, e1| UpstreamBracket {
                peer,
                before: ready(e0),
                after: ready(e1),
            };
            let ok =
                classify_bracketed(Ok(ExportPolicy::Unfiltered), &[b(EPOCH, EPOCH)], &mut seen);
            assert_eq!(ok, Eligibility::Ok);
            assert_eq!(seen.get(&peer), Some(&EPOCH));
            // A flap BETWEEN checks: both readings of this one agree, the
            // previous check's does not.
            let e = classify_bracketed(
                Ok(ExportPolicy::Unfiltered),
                &[b(EPOCH + 600, EPOCH + 600)],
                &mut seen,
            );
            assert!(not_ready(&e), "{e:?}");
        }
    }
}
