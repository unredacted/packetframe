//! Readback verification — the `StartVerify` action.
//!
//! Health is not "the process answers". A VPP that is up, pingable and
//! holding an empty or half-installed FIB will accept steered traffic
//! and drop it, so steering is gated on this passing (rule 1). The
//! mechanism is defined here, ahead of the incident that would
//! otherwise define it.
//!
//! **Prefixes are re-sampled on every pass.** A fixed probe set is
//! worse than useless: once those few routes install, it passes forever
//! while the rest of the table rots. The caller varies `seed` per
//! verify, so each pass looks at different routes and repeated passes
//! cover the table stochastically.
//!
//! **What this checks, precisely.** For each sampled prefix the ledger
//! believes is installed, VPP must return a route with at least one
//! path, and every path must egress an interface we actually own. That
//! last clause is the valuable one: `sw_if_index` 0 is `local0`, VPP's
//! drop interface, so a path pointing there is a route that looks
//! installed and forwards nothing — the exact silent blackhole the
//! deferred-index logic in the drainer exists to prevent, checked here
//! from the other side.
//!
//! **What it does NOT check**, so nobody reads more into a pass than
//! it earns:
//!
//! - *Per-path nexthop correctness.* Confirming VPP's paths match
//!   bird's intent would mean holding the expected nexthop set for
//!   ~1.05M prefixes, which is the memory the ledger deliberately does
//!   not spend. Path bytes are covered instead by the golden vectors
//!   (encoding) and the drainer's per-route acknowledgement (delivery).
//! - *Total route count.* The plan pairs sampling with VPP's own
//!   `show ip fib summary`, which needs `cli_inband` — a message from
//!   `vlib.api.json`, not among the vendored files. Until that is
//!   vendored, a uniform shortfall is caught only stochastically by
//!   sampling. Recorded as owed rather than quietly dropped.

use packetframe_common::fib::IpPrefix;

use crate::fib_sync::{to_prefix, PortIndex};
use crate::sink::RouteLedger;
use crate::vpp_api::generated::{IpRouteLookup, IpRouteLookupReply};
use crate::vpp_api::{Transport, TransportError};

/// How many prefixes a verify pass probes.
///
/// A round trip each, so this is a latency cost paid inside the
/// recovery budget — 64 keeps a pass well under a second while giving
/// a wide-enough net that a systemic miss is very unlikely to hide. It
/// is a sample, not a proof, and the module docs say so.
pub const DEFAULT_SAMPLE: usize = 64;

/// Why a sampled prefix failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mismatch {
    /// VPP has no route for a prefix the ledger says is installed.
    Absent { prefix: IpPrefix, retval: i32 },
    /// The route exists but carries no paths.
    NoPaths { prefix: IpPrefix },
    /// A path egresses an interface we do not own — `local0` (index 0)
    /// or something attached behind our back.
    ForeignPath { prefix: IpPrefix, sw_if_index: u32 },
}

/// An interface that cannot forward, whatever the FIB says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadInterface {
    pub sw_if_index: u32,
    pub name: String,
    pub admin_up: bool,
    pub link_up: bool,
}

/// Result of one verify pass.
#[derive(Debug, Clone, Default)]
pub struct VerifyOutcome {
    pub sampled: usize,
    pub mismatches: Vec<Mismatch>,
    /// Routes the mapping could not resolve to a VPP-owned device.
    /// Steady state on the reference fleet is exactly 0, which is what
    /// makes it a usable gate rather than noise.
    pub unresolvable: u64,
    /// Routes held back by capacity. Degraded but *known*, and
    /// deliberately NOT a verify failure: withholding is the designed
    /// response to a table that outgrew its heap, and failing verify
    /// on it would convert a graceful degradation into a restart loop.
    /// Reported so it can alarm separately.
    pub withheld: u64,
    /// Owned interfaces that are not both admin-up and link-up.
    pub dead_interfaces: Vec<DeadInterface>,
}

impl VerifyOutcome {
    /// Whether the FIB itself agrees with the ledger: at least one
    /// route was actually probed, nothing sampled disagreed, and the
    /// nexthop-device mapping has no holes. This — and only this — is
    /// the restart-worthy question: a wrong FIB is rebuilt by a fresh
    /// resync, so teardown is a remedy.
    ///
    /// **`sampled == 0` fails.** An earlier version treated it as a
    /// vacuous pass, and a test asserted that as intended — which was
    /// wrong in the case that matters: a resync completing against an
    /// unexpectedly empty mirror would verify clean, and the supervisor
    /// would (re-)steer traffic into a VPP with an empty FIB. That is
    /// the blackhole rule 1 exists to prevent, arrived at through the
    /// gate meant to prevent it. A box with genuinely no routes should
    /// not be steered either, so failing is right in both readings.
    ///
    /// `unresolvable > 0` fails because it means the nexthop-device
    /// mapping is wrong — a misconfiguration, not a capacity condition
    /// — and steering traffic into a FIB with known holes is how a
    /// deploy becomes an outage.
    ///
    /// `dead_interfaces` is deliberately NOT here. A member with no
    /// link makes the dataplane unfit to take traffic — [`Self::passed`]
    /// still fails on it, and steering still refuses — but the FIB is
    /// not wrong and a restart cannot plug in a cable. Routing it
    /// through the restart-worthy verdict turned three uncabled shadow
    /// ports into an infinite kill-respawn loop (repro 2026-08-13,
    /// after the first primary attach hid the same shape behind IRQ
    /// starvation): every cycle rebuilt a flawless FIB, re-observed the
    /// same dark ports, and died for it.
    pub fn fib_correct(&self) -> bool {
        self.sampled > 0 && self.mismatches.is_empty() && self.unresolvable == 0
    }

    /// Pass criteria for *steering*: the FIB is correct AND every owned
    /// interface can forward. The two halves fail differently — see
    /// [`Self::fib_correct`] — and `Verdict::event` is where the
    /// difference becomes a supervisor decision.
    pub fn passed(&self) -> bool {
        self.fib_correct() && self.dead_interfaces.is_empty()
    }

    /// One-line operator summary. Separates the two degraded counts,
    /// because "mapping is misconfigured" and "table outgrew the box"
    /// are different pages at 03:00 — and a third label for dark
    /// members, because "the FIB is wrong" and "a cable is out" are
    /// too: the first is restart-worthy, the second reads FAIL only if
    /// you want an operator to bounce a healthy dataplane.
    pub fn summary(&self) -> String {
        let mut s = format!(
            "verify {}: {}/{} probes matched, unresolvable={}, withheld={}",
            if self.passed() {
                "PASS"
            } else if self.fib_correct() {
                "FIB OK, MEMBER(S) DARK — steering refused, no restart"
            } else {
                "FAIL"
            },
            self.sampled.saturating_sub(self.mismatches.len()),
            self.sampled,
            self.unresolvable,
            self.withheld
        );
        if self.sampled == 0 {
            s.push_str(" (no installed routes to verify)");
        }
        for d in &self.dead_interfaces {
            s.push_str(&format!(
                ", {} (idx {}) admin_up={} link_up={}",
                d.name, d.sw_if_index, d.admin_up, d.link_up
            ));
        }
        s
    }
}

/// Every owned interface that cannot forward right now, from a fresh
/// `sw_interface_dump`.
///
/// Shared between the verify pass and the steer gate — the second
/// caller is the fix for the dark-member restart loop (shadow repro,
/// 2026-08-13): verify routes dark members through the no-restart
/// verdict, so the moment-of-steer check has to be its own, *fresh*
/// read. Checking a recorded outcome instead would refuse a steer on a
/// cable that was plugged back in an hour ago, or permit one on a
/// cable pulled after the last verify.
pub(crate) fn dead_interface_scan(
    t: &mut Transport,
    owned: &std::collections::HashSet<u32>,
) -> Result<Vec<DeadInterface>, TransportError> {
    let mut dead = Vec::new();
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for iface in crate::attach::interfaces(t)? {
        if !owned.contains(&iface.sw_if_index) {
            continue;
        }
        seen.insert(iface.sw_if_index);
        let (admin_up, link_up) = (iface.admin_up(), iface.link_up());
        if !admin_up || !link_up {
            dead.push(DeadInterface {
                sw_if_index: iface.sw_if_index,
                name: iface.name,
                admin_up,
                link_up,
            });
        }
    }
    // An owned index that is ABSENT from the dump is not healthy by
    // omission. Only iterating what the dump returned meant a port that
    // disappeared after attach was invisible: if the random sample
    // happened not to select a route through it, every probe matched and
    // verification passed on a port that could not forward. Report each
    // missing index as its own failure — nothing about it is up.
    for idx in owned.iter().copied() {
        if !seen.contains(&idx) {
            dead.push(DeadInterface {
                sw_if_index: idx,
                name: format!("<absent from VPP, idx {idx}>"),
                admin_up: false,
                link_up: false,
            });
        }
    }
    // Deterministic order so a failing scan reads the same twice.
    dead.sort_by_key(|d| d.sw_if_index);
    Ok(dead)
}

/// Deterministic sampler.
///
/// Seeded rather than drawing from the OS so a failing verify can be
/// replayed exactly — a probe set you cannot reproduce is a bug report
/// nobody can act on. The caller supplies a fresh seed per pass, which
/// is what makes the sampling vary.
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Pick up to `n` distinct prefixes from `all`.
///
/// Partial Fisher-Yates over indices: distinct by construction, and
/// O(n) rather than O(len), which matters when `all` is the whole
/// installed table and `n` is 64.
pub fn sample(all: &[IpPrefix], n: usize, seed: u64) -> Vec<IpPrefix> {
    if all.is_empty() {
        return Vec::new();
    }
    let take = n.min(all.len());
    // Seed 0 is a fixed point for xorshift — it would return the same
    // index forever and silently collapse the sample to one prefix.
    let mut state = if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    };
    let mut idx: Vec<usize> = (0..all.len()).collect();
    for i in 0..take {
        let j = i + (xorshift(&mut state) as usize) % (idx.len() - i);
        idx.swap(i, j);
    }
    idx[..take].iter().map(|&i| all[i]).collect()
}

/// Probe a random sample of installed prefixes against VPP's FIB.
///
/// Errors only on transport failure; a route that disagrees is a
/// [`Mismatch`] in the outcome, not an error, because the caller needs
/// the whole picture to decide whether to steer rather than the first
/// disagreement.
pub fn verify(
    t: &mut Transport,
    ledger: &RouteLedger,
    ports: &PortIndex,
    sample_size: usize,
    seed: u64,
) -> Result<VerifyOutcome, TransportError> {
    let counts = ledger.counts();
    let installed = ledger.verifiable_prefixes();
    let probes = sample(&installed, sample_size, seed);
    let owned = ports.indices();

    let mut out = VerifyOutcome {
        sampled: probes.len(),
        unresolvable: counts.unresolvable,
        withheld: counts.withheld,
        ..Default::default()
    };

    // Link state, before the probes. A VF that is admin-up with no
    // carrier keeps every route on a valid, owned `sw_if_index`, so the
    // per-route checks below cannot see it at all — every probe passes
    // and we steer into an interface that forwards nothing. The runbook
    // treats link-up as the bring-up pass for exactly this reason;
    // `set_admin_up` only ever asserted the administrative flag.
    out.dead_interfaces = dead_interface_scan(t, &owned)?;

    for prefix in probes {
        let reply = t.request::<IpRouteLookup, IpRouteLookupReply>(IpRouteLookup {
            context: 0,
            table_id: 0,
            // Exact-match: a covering less-specific route would
            // otherwise answer for a prefix that is actually missing,
            // which is precisely the hole we are looking for.
            exact: 1,
            prefix: to_prefix(prefix),
        })?;
        if reply.retval != 0 {
            out.mismatches.push(Mismatch::Absent {
                prefix,
                retval: reply.retval,
            });
            continue;
        }
        if reply.route.paths.is_empty() {
            out.mismatches.push(Mismatch::NoPaths { prefix });
            continue;
        }
        for path in &reply.route.paths {
            if !owned.contains(&path.sw_if_index) {
                out.mismatches.push(Mismatch::ForeignPath {
                    prefix,
                    sw_if_index: path.sw_if_index,
                });
                break;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8) -> IpPrefix {
        IpPrefix::V4 {
            addr: [10, a, b, 0],
            prefix_len: 24,
        }
    }

    fn table(n: usize) -> Vec<IpPrefix> {
        (0..n)
            .map(|i| v4((i / 256) as u8, (i % 256) as u8))
            .collect()
    }

    #[test]
    fn sampling_returns_distinct_prefixes() {
        let all = table(500);
        let got = sample(&all, 64, 12345);
        assert_eq!(got.len(), 64);
        let uniq: std::collections::HashSet<_> = got.iter().collect();
        assert_eq!(uniq.len(), 64, "a probe set with duplicates wastes probes");
    }

    /// The whole point of seeding: consecutive passes must look at
    /// different routes, or a fixed probe set passes forever while the
    /// rest of the table rots.
    #[test]
    fn different_seeds_sample_differently() {
        let all = table(500);
        let a = sample(&all, 64, 1);
        let b = sample(&all, 64, 2);
        assert_ne!(a, b, "re-sampling must actually re-sample");
    }

    /// ...but a given seed must replay exactly, so a failing verify can
    /// be reproduced.
    #[test]
    fn the_same_seed_replays_exactly() {
        let all = table(500);
        assert_eq!(sample(&all, 32, 99), sample(&all, 32, 99));
    }

    /// Seed 0 is a xorshift fixed point. Unguarded it would return one
    /// index forever, collapsing a 64-probe verify to a single route
    /// while still reporting 64 samples.
    #[test]
    fn seed_zero_does_not_collapse_the_sample() {
        let all = table(500);
        let got = sample(&all, 64, 0);
        let uniq: std::collections::HashSet<_> = got.iter().collect();
        assert_eq!(uniq.len(), 64);
    }

    #[test]
    fn sampling_a_short_table_takes_everything_once() {
        let all = table(10);
        let got = sample(&all, 64, 7);
        assert_eq!(got.len(), 10);
        let uniq: std::collections::HashSet<_> = got.iter().collect();
        assert_eq!(uniq.len(), 10);
    }

    #[test]
    fn an_empty_table_samples_nothing() {
        assert!(sample(&[], 64, 1).is_empty());
    }

    #[test]
    fn unresolvable_fails_the_pass_but_withheld_does_not() {
        let mut o = VerifyOutcome {
            sampled: 64,
            withheld: 5_000,
            ..Default::default()
        };
        assert!(
            o.passed(),
            "withholding is the designed response to a full table, not a fault"
        );
        o.unresolvable = 1;
        assert!(!o.passed(), "a mapping hole must block steering");
    }

    #[test]
    fn a_mismatch_fails_the_pass() {
        let o = VerifyOutcome {
            sampled: 64,
            mismatches: vec![Mismatch::NoPaths { prefix: v4(0, 1) }],
            ..Default::default()
        };
        assert!(!o.passed());
        assert!(o.summary().contains("FAIL"), "{}", o.summary());
        assert!(o.summary().contains("63/64"), "{}", o.summary());
    }

    #[test]
    fn the_summary_separates_the_two_degraded_counts() {
        let o = VerifyOutcome {
            sampled: 10,
            unresolvable: 3,
            withheld: 7,
            ..Default::default()
        };
        let s = o.summary();
        assert!(s.contains("unresolvable=3"), "{s}");
        assert!(s.contains("withheld=7"), "{s}");
    }
}
