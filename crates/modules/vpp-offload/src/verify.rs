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
//! - *Per-path nexthop correctness*, on an ordinary pass. The ledger now
//!   records the path set each route was acknowledged through (interned,
//!   4 bytes a route), but an ordinary pass verifies a table this process
//!   installed and acknowledged itself, so path bytes stay covered by the
//!   golden vectors (encoding) and the drainer's per-route acknowledgement
//!   (delivery). [`verify_paths`] adds the comparison for the one table
//!   this process did NOT install: a ledger seeded from the previous
//!   process's preserved record, where the paths are the claim under
//!   test.
//! - *Total route count*, on an ordinary pass. The plan pairs sampling
//!   with VPP's own `show ip fib summary`; `cli_inband` is vendored now,
//!   and the preserved-ledger adoption compares those per-length counts
//!   against the ones the previous process recorded before it trusts the
//!   record at all (`crate::ledger_record::FibFingerprint`). An ordinary
//!   pass still catches a uniform shortfall only stochastically.

use packetframe_common::fib::IpPrefix;

use crate::fib_sync::{to_prefix, FamilyPolicy, PortIndex};
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

/// The least share of the IPv4 table installed NOW, in percent, that a
/// verify must have been taken against to vouch for it at a first steer
/// ([`covers`]).
///
/// A verify probes [`DEFAULT_SAMPLE`] routes drawn from what was
/// installed when it ran. Routes installed afterwards were never
/// candidates, and on the path that matters they did not even arrive
/// the same way: the 2026-10-07 restart verified an adopted VPP on ONE
/// probe against a one-route table, then the full-table reload reached
/// VPP as steady-state deltas, and a lever moved nine minutes later was
/// admitted on that verdict with VPP holding ~60% of the table. 90%
/// bounds how much of the table being steered can postdate its verdict
/// to a tenth.
///
/// Why not tighter: ordinary churn has to fit inside it, or every lever
/// move costs a re-verify. Net growth of a full table is ~10% a YEAR,
/// and day-to-day churn moves the count by a fraction of a percent, so a
/// verdict taken at convergence still covers the table at any lever
/// move a canary ladder makes. Why it cannot loop: the remedy is the
/// re-run ([`ReverifySchedule`]), which takes the verdict against the
/// table as it is, back at 100%; it is outgrown again only after the
/// table grows by another ~11%. Shrinkage is not judged — what is
/// installed now is mostly what the sample was drawn from — and that
/// is also the limit of a count: a table that turned over at constant
/// size reads as covered.
pub const VERIFY_COVERS_PERCENT: u64 = 90;

/// Whether a verify of `sampled` probes against a `table`-route table
/// vouches for the `installed` routes there are now — THE coverage rule,
/// the one the first-steer gate, the re-run and the `fib-synced` row all
/// ask, so none of them can answer it differently.
///
/// Two halves:
/// - **The probes**: the standard sample, or the whole table when the
///   table was smaller than that. A pass of fewer probes than its own
///   table allowed did not look at what it claims to have looked at.
/// - **The table**: at least [`VERIFY_COVERS_PERCENT`] of `installed`.
///
/// On a full-table box the first half cannot be met by a short pass and
/// the second cannot be met by a small table, so a one-probe verdict
/// vouches only for a box with about one route.
pub fn covers(sampled: usize, table: u64, installed: u64) -> bool {
    let probed = sampled as u64 >= table.min(DEFAULT_SAMPLE as u64);
    let large_enough = table.saturating_mul(100) >= installed.saturating_mul(VERIFY_COVERS_PERCENT);
    probed && large_enough
}

/// What clears a mismatch a verify found. One wording for every surface
/// that names it — the steer refusal, the `fib-synced` row and the
/// re-run's log line.
///
/// A restart that keeps VPP does, because the stopping daemon will not
/// preserve a route ledger a verify has disproved (`Runtime::preserve`):
/// the next start has no record to trust, reads VPP's FIB, and its resync
/// diff corrects what VPP holds against the mirror before it verifies.
/// Preserved, the ledger would be seeded instead, VPP's per-length counts
/// would match it, and the diff would skip exactly the prefixes VPP has
/// wrong. Replacing VPP clears it as well, at the cost of a cold attach.
///
/// The want does not survive for a port that was never steered: an
/// unsteered adoption starts with none, so its lever has to move again.
pub const MISMATCH_REMEDY: &str = "restart the daemon (`systemctl restart packetframe`, or the \
     `detach --keep-vpp` sequence): the stop will not preserve a route ledger a verify has \
     disproved, so the next start reads VPP's FIB and its resync corrects what VPP holds. A port \
     that was never steered needs its lever moved again afterwards. Replacing VPP also clears \
     it: stop the daemon, run `packetframe detach --all`, start it";

/// Why the last verify does not vouch for the IPv4 table installed now,
/// as a first steer needs it to — [`unvouched`] decides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unvouched {
    /// No verify has completed against this VPP.
    NoVerdict,
    /// The last verify found VPP disagreeing with the ledger. Not
    /// outgrown by waiting, and never re-run away: a new sample can miss
    /// the prefix this one caught. [`MISMATCH_REMEDY`] clears it.
    ///
    /// Not a transient of churn. Verify runs only when nothing is in
    /// flight — at the end of a convergence, which drains nothing while
    /// verifying, or as a re-run on a tick whose drain went idle — and
    /// the drain and the probes share one thread, so no update can land
    /// between a probe's sample and VPP's answer. A mismatch is VPP's
    /// FIB, not the moment.
    Mismatch,
    /// The last verify was taken against a table [`covers`] says is too
    /// small for the one installed now.
    Outgrown {
        sampled: usize,
        table: u64,
        installed: u64,
    },
}

impl std::fmt::Display for Unvouched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unvouched::NoVerdict => write!(f, "no verify has completed against this VPP"),
            Unvouched::Mismatch => write!(
                f,
                "the last verify found VPP disagreeing with the route ledger, which waiting \
                 and re-verifying do not clear — {MISMATCH_REMEDY}"
            ),
            Unvouched::Outgrown {
                sampled,
                table,
                installed,
            } => write!(
                f,
                "the last verify ran on {sampled} probe(s) against {table} routes and {installed} \
                 are installed now, so it vouches for less than {VERIFY_COVERS_PERCENT}% of the \
                 table being steered"
            ),
        }
    }
}

/// What the last verify leaves unvouched for a first steer into the
/// `installed` IPv4 routes there are now, or `None` when it vouches for
/// them.
///
/// Deliberately NOT a pass/fail test. A verdict that failed only on
/// conditions the live table can be seen to outgrow — unresolvable
/// routes, an unexempted kernel-delivered prefix, a dark member — is
/// judged on those conditions as they stand NOW, by the gates that read
/// them live (`SinkCounts::blocks_first_steer`, the steer's fresh link
/// scan); re-reading them off a recording would hold a steer for a
/// reason that has since cleared. What a recording CAN say, and nothing
/// live can, is what the probes saw and how much of the table they were
/// drawn from: a mismatch, and coverage.
pub fn unvouched(verdict: Option<&VerifyOutcome>, installed: u64) -> Option<Unvouched> {
    match verdict {
        None => Some(Unvouched::NoVerdict),
        Some(v) if v.restart_worthy() => Some(Unvouched::Mismatch),
        Some(v) if !v.covers(installed) => Some(Unvouched::Outgrown {
            sampled: v.sampled,
            table: v.table,
            installed,
        }),
        Some(_) => None,
    }
}

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
    /// VPP holds the route through different paths than the ledger
    /// records. Only a path-checking pass ([`verify_paths`]) reports it,
    /// and only for a prefix whose paths the ledger knows.
    WrongPaths {
        prefix: IpPrefix,
        expected: Vec<crate::sink::PathKey>,
        got: Vec<crate::sink::PathKey>,
    },
}

/// An interface that cannot forward, whatever the FIB says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeadInterface {
    pub sw_if_index: u32,
    pub name: String,
    pub admin_up: bool,
    pub link_up: bool,
    /// Whether any installed route can actually egress here — the FIB
    /// holds at least one static neighbour on this interface (counting
    /// unacked ones, conservatively). This is what separates "a
    /// blackhole is one steer away" from "a port is dark and nothing
    /// routes through it": a dark port mostly CANNOT carry routes,
    /// because the BGP session that would produce them died with the
    /// link — the primary's uncabled eth5 is the motivating case. Only
    /// `in_use` dark members block steering; idle ones degrade the
    /// report and nothing else.
    pub in_use: bool,
}

/// Result of one verify pass.
///
/// **Every top-level field is IPv4's** — the family steering diverts,
/// and so the one whose table decides whether it may (the same split as
/// [`crate::sink::SinkCounts`]). IPv6, when VPP carries it, is probed
/// with its own sample and reported in [`Self::v6`], where nothing it
/// finds can fail the pass: at rung 0 no v6 is steered, and a v6
/// disagreement tearing down a VPP that forwards steered v4 would make
/// `v6 on` a way to take v4 off it.
#[derive(Debug, Clone, Default)]
pub struct VerifyOutcome {
    pub sampled: usize,
    /// How many IPv4 routes the ledger held installed when the probes
    /// were drawn — the population the sample speaks for, and the only
    /// one. A route installed after the pass was never a candidate, so
    /// a verdict vouches for the table it was taken against and not for
    /// whatever has arrived since; [`Self::covers`] is where that is
    /// judged against the table installed now.
    pub table: u64,
    pub mismatches: Vec<Mismatch>,
    /// Routes the mapping could not resolve to a VPP-owned device.
    /// Steady state on the reference fleet is exactly 0, which is what
    /// makes it a usable gate rather than noise.
    pub unresolvable: u64,
    /// Up to a handful of those routes by name, each with its next hops
    /// and why they do not reach VPP, then "+K more" — filled by the
    /// engine ([`crate::engine::ConvergenceEngine::unresolvable_named`]),
    /// which alone holds the mapping. Empty when `unresolvable` is 0.
    pub unresolvable_named: Vec<String>,
    /// Routes held back by capacity. Degraded but *known*, and
    /// deliberately NOT a verify failure: withholding is the designed
    /// response to a table that outgrew its heap, and failing verify
    /// on it would convert a graceful degradation into a restart loop.
    /// Reported so it can alarm separately.
    pub withheld: u64,
    /// The router's own connected subnets, left out of VPP, that no
    /// `steer-exempt` covers — filled by the engine, which alone knows
    /// them. Fails the pass like `unresolvable`: steered traffic for one
    /// has no route in VPP.
    pub unexempted_local: u64,
    /// Owned interfaces that are not both admin-up and link-up.
    pub dead_interfaces: Vec<DeadInterface>,
    /// IPv6's half of the pass, when VPP carries the family (`v6 on`);
    /// `None` under `V4Only`.
    pub v6: Option<FamilyVerify>,
}

/// One family's probes and degraded counts, for a family that does not
/// gate steering (see [`VerifyOutcome`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FamilyVerify {
    /// Probes sent: a sample of its own, the same size as IPv4's, so a
    /// ~250k-route family is not left to the few probes its share of a
    /// mixed pool would draw.
    pub sampled: usize,
    /// See [`VerifyOutcome::table`]; this family's.
    pub table: u64,
    pub mismatches: Vec<Mismatch>,
    pub unresolvable: u64,
    /// See [`VerifyOutcome::unresolvable_named`].
    pub unresolvable_named: Vec<String>,
    pub withheld: u64,
}

impl FamilyVerify {
    /// Whether every probe agreed and nothing is missing.
    pub fn clean(&self) -> bool {
        self.mismatches.is_empty() && self.unresolvable == 0 && self.withheld == 0
    }
}

impl VerifyOutcome {
    /// Whether the FIB itself agrees with the ledger: at least one
    /// route was actually probed, nothing sampled disagreed, and the
    /// nexthop-device mapping has no holes. This is the *fit to take
    /// traffic* question, NOT the restart-worthy one — those were the
    /// same predicate until 2026-08-13, when the primary's w7 window
    /// showed the difference the hard way. Only `mismatches` is
    /// restart-worthy (a fresh resync rebuilds a wrong FIB); the other
    /// two failure modes here are conditions a teardown cannot change,
    /// and `Verdict::event` routes them to a hold instead.
    ///
    /// **`sampled == 0` fails.** An earlier version treated it as a
    /// vacuous pass, and a test asserted that as intended — which was
    /// wrong in the case that matters: a resync completing against an
    /// unexpectedly empty mirror would verify clean, and the supervisor
    /// would (re-)steer traffic into a VPP with an empty FIB. That is
    /// the blackhole rule 1 exists to prevent, arrived at through the
    /// gate meant to prevent it. A box with genuinely no routes should
    /// not be steered either, so failing is right in both readings —
    /// but failing here means "refuse steering", never "tear down": an
    /// empty sample is what a fresh attach looks like before bird has
    /// dumped, and tearing down for it produced seven kill-respawn
    /// cycles in 31 s on the primary (w7, 2026-08-13).
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
        self.sampled > 0
            && self.mismatches.is_empty()
            && self.unresolvable == 0
            && self.unexempted_local == 0
    }

    /// Whether a teardown is the remedy — **the** restart-worthy
    /// predicate, and the only one.
    ///
    /// A mismatch means VPP answered a probe and disagreed with the
    /// ledger, and a fresh resync rebuilds a wrong FIB. Every other way
    /// of failing [`Self::fib_correct`] is a condition a restart cannot
    /// change, and each has produced a kill-respawn loop by being
    /// treated as one — see [`crate::engine::Verdict::event`], which
    /// lists the three and what they cost.
    ///
    /// Lives here rather than inline at its callers because it has two:
    /// the supervisor event and the health surface. They disagreed —
    /// `Verdict::event` honoured the distinction and routed an
    /// incomplete verify to a hold, while
    /// [`crate::status::FibSync::from_outcome`] folded every non-pass
    /// into one `Failed` and paged on it. So a box whose verify ran
    /// before the feed landed reported UNHEALTHY with a summary that
    /// said, in the same line, "no restart".
    pub fn restart_worthy(&self) -> bool {
        !self.mismatches.is_empty()
    }

    /// Whether this verdict vouches for the `installed` IPv4 routes there
    /// are now — [`covers`], over this pass's own sample and table.
    pub fn covers(&self, installed: u64) -> bool {
        covers(self.sampled, self.table, installed)
    }

    /// Whether ANY probe, of any family, disagreed with the ledger.
    ///
    /// The test a preserved-ledger seed is judged by, which is wider than
    /// [`Self::restart_worthy`] on purpose: an IPv6 disagreement cannot
    /// tear down a VPP forwarding steered v4, but it does disprove the
    /// record it was checked against — and a seed kept with wrong v6
    /// paths would have its resync skip exactly the routes it has wrong.
    pub fn any_mismatch(&self) -> bool {
        !self.mismatches.is_empty() || self.v6.as_ref().is_some_and(|v| !v.mismatches.is_empty())
    }

    /// Pass criteria for *steering*: the FIB is correct AND every dark
    /// member is idle — no installed route can egress an interface
    /// that cannot forward. The halves fail differently — see
    /// [`Self::fib_correct`] and [`DeadInterface::in_use`] — and
    /// `Verdict::event` is where the difference becomes a supervisor
    /// decision.
    pub fn passed(&self) -> bool {
        self.fib_correct() && !self.dead_interfaces.iter().any(|d| d.in_use)
    }

    /// Whether this verdict failed ONLY for reasons the live table can
    /// be seen to outgrow: unresolvable routes, kernel-delivered prefixes
    /// without a `steer-exempt`, or nothing installed to probe — and
    /// nothing that says VPP is wrong (a mismatch) or that a cable is out
    /// (an in-use dark member), which a clean table does not clear.
    ///
    /// The verdict the re-run exists for ([`ReverifySchedule`]).
    /// Verification is a convergence-time gate, so a verify that found
    /// one unresolvable route stood as the last word — `fib-synced`
    /// Degraded — long after the route had resolved or been withdrawn,
    /// with nothing that would ever look again short of a restart.
    pub fn awaits_clean_table(&self) -> bool {
        !self.passed()
            && self.mismatches.is_empty()
            && !self.dead_interfaces.iter().any(|d| d.in_use)
            && (self.unresolvable > 0 || self.unexempted_local > 0 || self.sampled == 0)
    }

    /// One-line operator summary. Separates the two degraded counts,
    /// because "mapping is misconfigured" and "table outgrew the box"
    /// are different pages at 03:00 — and distinct labels for dark
    /// members and for a not-yet-deliverable table, because "the FIB
    /// is wrong" and "a cable is out" and "bird has not dumped yet"
    /// are three different situations: only the first is
    /// restart-worthy, and labelling the others FAIL invites an
    /// operator to bounce a dataplane a bounce cannot fix (the
    /// supervisor made exactly that mistake until 2026-08-13 — see
    /// `Verdict::event`).
    pub fn summary(&self) -> String {
        let mut s = format!(
            "verify {}: {}/{} probes matched against {} routes, unresolvable={}{}, withheld={}",
            if self.passed() {
                "PASS"
            } else if self.fib_correct() {
                "FIB OK, IN-USE MEMBER(S) DARK — steering refused, no restart"
            } else if !self.mismatches.is_empty() {
                "FAIL"
            } else {
                "INCOMPLETE — steering refused, no restart"
            },
            self.sampled.saturating_sub(self.mismatches.len()),
            self.sampled,
            self.table,
            self.unresolvable,
            named_in_parens(&self.unresolvable_named),
            self.withheld
        );
        if self.unexempted_local > 0 {
            s.push_str(&format!(
                ", {} kernel-delivered prefix(es) without a steer-exempt",
                self.unexempted_local
            ));
        }
        if self.sampled == 0 {
            s.push_str(" (no installed routes to verify)");
        }
        if let Some(v6) = &self.v6 {
            s.push_str(&format!(
                "; IPv6 (loaded, not steered — cannot fail the pass): {}/{} probes matched \
                 against {} routes, unresolvable={}{}, withheld={}",
                v6.sampled.saturating_sub(v6.mismatches.len()),
                v6.sampled,
                v6.table,
                v6.unresolvable,
                named_in_parens(&v6.unresolvable_named),
                v6.withheld
            ));
        }
        for d in &self.dead_interfaces {
            s.push_str(&format!(
                ", {} (idx {}) admin_up={} link_up={}{}",
                d.name,
                d.sw_if_index,
                d.admin_up,
                d.link_up,
                if d.in_use {
                    " CARRIES ROUTES"
                } else {
                    " (idle: no routes egress here; not blocking)"
                }
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
    active_egress: &std::collections::HashSet<u32>,
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
                in_use: active_egress.contains(&iface.sw_if_index),
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
                in_use: active_egress.contains(&idx),
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
    active_egress: &std::collections::HashSet<u32>,
    sample_size: usize,
    seed: u64,
) -> Result<VerifyOutcome, TransportError> {
    verify_paths(
        t,
        ledger,
        ports,
        active_egress,
        sample_size,
        seed,
        false,
        FamilyPolicy::V4Only,
    )
}

/// [`verify`], optionally also comparing each probed route's paths with
/// the set the ledger records for it.
///
/// `check_paths` is for a ledger this process did not build — one seeded
/// from the previous process's preserved record. There the record's
/// claim is exactly "VPP holds these routes through these paths", so a
/// probe that finds the prefix present on an owned interface but through
/// different paths has disproved it, and that is a [`Mismatch`]. A prefix
/// whose paths the ledger does not know is checked as an ordinary probe.
///
/// Under [`FamilyPolicy::Both`] IPv6 gets a sample of its own, drawn from
/// a seed derived from `seed` so the pass stays replayable, and its
/// findings go to [`VerifyOutcome::v6`].
#[allow(clippy::too_many_arguments)]
pub fn verify_paths(
    t: &mut Transport,
    ledger: &RouteLedger,
    ports: &PortIndex,
    active_egress: &std::collections::HashSet<u32>,
    sample_size: usize,
    seed: u64,
    check_paths: bool,
    families: FamilyPolicy,
) -> Result<VerifyOutcome, TransportError> {
    let counts = ledger.counts();
    let (v4_pool, v6_pool): (Vec<IpPrefix>, Vec<IpPrefix>) = ledger
        .verifiable_prefixes()
        .into_iter()
        .partition(|p| matches!(p, IpPrefix::V4 { .. }));
    let mut probes = sample(&v4_pool, sample_size, seed);
    let v4_probes = probes.len();
    let owned = ports.indices();

    let mut out = VerifyOutcome {
        sampled: v4_probes,
        // The pool itself, which is `counts.installed`: both are the
        // ledger's IPv4 routes in `Installed`, so the coverage check
        // compares like with like.
        table: v4_pool.len() as u64,
        unresolvable: counts.unresolvable,
        withheld: counts.withheld,
        ..Default::default()
    };
    if families.carries_v6() {
        let v6c = ledger.v6_counts();
        // A different seed, so the two samples are not the same index
        // walk over two pools; still a pure function of `seed`.
        let v6_probes = sample(&v6_pool, sample_size, seed.rotate_left(32) ^ 0x6666);
        out.v6 = Some(FamilyVerify {
            sampled: v6_probes.len(),
            table: v6_pool.len() as u64,
            unresolvable: v6c.unresolvable,
            withheld: v6c.withheld,
            ..Default::default()
        });
        probes.extend(v6_probes);
    }
    let mut v6_mismatches = Vec::new();

    // Link state, before the probes. A VF that is admin-up with no
    // carrier keeps every route on a valid, owned `sw_if_index`, so the
    // per-route checks below cannot see it at all — every probe passes
    // and we steer into an interface that forwards nothing. The runbook
    // treats link-up as the bring-up pass for exactly this reason;
    // `set_admin_up` only ever asserted the administrative flag.
    out.dead_interfaces = dead_interface_scan(t, &owned, active_egress)?;

    for prefix in probes {
        // Each family's disagreements land in its own list: `out.mismatches`
        // is IPv4's and gates steering, IPv6's does not (see the type docs).
        let found = if matches!(prefix, IpPrefix::V6 { .. }) {
            &mut v6_mismatches
        } else {
            &mut out.mismatches
        };
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
            found.push(Mismatch::Absent {
                prefix,
                retval: reply.retval,
            });
            continue;
        }
        if reply.route.paths.is_empty() {
            found.push(Mismatch::NoPaths { prefix });
            continue;
        }
        let foreign = reply
            .route
            .paths
            .iter()
            .find(|p| !owned.contains(&p.sw_if_index));
        if let Some(path) = foreign {
            found.push(Mismatch::ForeignPath {
                prefix,
                sw_if_index: path.sw_if_index,
            });
            continue;
        }
        if !check_paths {
            continue;
        }
        let Some(expected) = ledger
            .installed_via(prefix)
            .and_then(|id| ledger.paths_of(id))
        else {
            continue;
        };
        let got = crate::fib_sync::path_set_of(&reply.route.paths);
        if got != expected {
            found.push(Mismatch::WrongPaths {
                prefix,
                expected: expected.to_vec(),
                got,
            });
        }
    }
    if let Some(v6) = out.v6.as_mut() {
        v6.mismatches = v6_mismatches;
    }
    Ok(out)
}

/// `" (a; b; +K more)"` for named unresolvable routes, nothing for none.
fn named_in_parens(names: &[String]) -> String {
    if names.is_empty() {
        String::new()
    } else {
        format!(" ({})", names.join("; "))
    }
}

/// How long the table must stay clean before a stale verdict is re-run
/// ([`ReverifySchedule`]). Long enough that a route flapping between
/// unresolvable and resolved does not buy a verify per flap; short
/// against how long an operator watches a Degraded row.
pub const REVERIFY_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(10);

/// The least time between two re-runs of an INCOMPLETE verdict
/// ([`Stale::Incomplete`]). A verify probes VPP with [`DEFAULT_SAMPLE`]
/// requests on the supervision loop; this keeps a table that keeps
/// getting dirty and clean again from turning a convergence-time gate
/// into a heartbeat.
///
/// An outgrown verdict ([`Stale::Outgrown`]) does not wait it out. It
/// cannot recur without the table growing by another ~11% past the
/// verdict the re-run takes, so it needs no rate limit to stay off the
/// heartbeat — and a first steer is waiting on it: a re-run taken during
/// a lull part-way through a reload left the steer held for most of this
/// interval after VPP had caught up (review finding, PR #333).
pub const REVERIFY_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(300);

/// Why a standing verdict is due a re-run ([`ReverifySchedule`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stale {
    /// It failed only on what the table can outgrow
    /// ([`VerifyOutcome::awaits_clean_table`]).
    Incomplete,
    /// It no longer covers the table ([`VerifyOutcome::covers`]), and
    /// found no mismatch. Wins over `Incomplete` when both hold: it is the
    /// one a held first steer waits on.
    Outgrown,
}

/// When a verdict known to be stale is re-run, once the table it is stale
/// against is clean and VPP has caught up with the route mirror.
///
/// Verification stays a convergence-time gate — `status::FibSync` gives
/// the reasons a periodic verify is a design change — and this does not
/// make it a heartbeat. It re-runs only a verdict the live counts can
/// show is stale, in one of two ways:
///
/// - it failed only because the table was not yet clean
///   ([`VerifyOutcome::awaits_clean_table`]): the table held
///   unresolvable routes, kernel-delivered prefixes without an
///   exemption, or nothing at all, and now holds none of those;
/// - the table has outgrown it ([`VerifyOutcome::covers`]): it was
///   taken against too small a share of what is installed now to vouch
///   for it, which is what a first steer needs from it — unless it found
///   a MISMATCH, which no new sample may overwrite
///   ([`Unvouched::Mismatch`]).
///
/// One re-run per clearing, debounced by [`REVERIFY_DEBOUNCE`] and at
/// most once per [`REVERIFY_MIN_INTERVAL`]. A re-run verdict covers the
/// table it ran against in full, so the second trigger cannot fire again
/// until the table grows by another ~11% (see [`VERIFY_COVERS_PERCENT`]).
///
/// **It refreshes the verdict and decides nothing.** No supervisor event
/// comes of it, and a first attach still never steers on its own. A
/// steer the operator already asked for, held because the verdict did
/// not cover the table (`Runtime`'s first-steer hold), is admitted by
/// the ordinary steer retry once the refreshed verdict does — the retry
/// re-reads the verdict, the re-run only replaces it.
///
/// Pure bookkeeping over the caller's clock, so the policy is testable
/// without a VPP; the runtime owns the conditions and the verify.
#[derive(Debug, Default)]
pub struct ReverifySchedule {
    /// Since when the stale verdict and the clean table have held
    /// together, uninterrupted.
    clean_since: Option<std::time::Instant>,
    /// When the last re-run was granted.
    last_run: Option<std::time::Instant>,
}

impl ReverifySchedule {
    /// Whether to re-run verify now. `stale` is why the standing verdict
    /// is due one, if it is; `clean` is the caller's reading that the live
    /// table no longer holds what failed it and the moment is quiet enough
    /// to probe. Both triggers wait out [`REVERIFY_DEBOUNCE`]; only
    /// [`Stale::Incomplete`] waits out [`REVERIFY_MIN_INTERVAL`]. A `true`
    /// is spent: the caller runs verify, and the schedule starts over.
    pub fn poll(&mut self, now: std::time::Instant, stale: Option<Stale>, clean: bool) -> bool {
        let Some(stale) = stale.filter(|_| clean) else {
            self.clean_since = None;
            return false;
        };
        let since = *self.clean_since.get_or_insert(now);
        if now.duration_since(since) < REVERIFY_DEBOUNCE {
            return false;
        }
        if stale == Stale::Incomplete
            && self
                .last_run
                .is_some_and(|t| now.duration_since(t) < REVERIFY_MIN_INTERVAL)
        {
            return false;
        }
        self.last_run = Some(now);
        self.clean_since = None;
        true
    }
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
    /// The verdict a re-run exists for: failed only on unresolvable
    /// routes, unexempted kernel-delivered prefixes or an empty sample.
    /// Never one that says VPP is wrong, or that a member carrying routes
    /// is dark — a clean table does not clear either.
    #[test]
    fn only_a_verdict_the_table_can_outgrow_awaits_a_clean_table() {
        let base = VerifyOutcome {
            sampled: 64,
            ..Default::default()
        };
        assert!(!base.awaits_clean_table(), "a pass awaits nothing");
        for o in [
            VerifyOutcome {
                unresolvable: 1,
                ..base.clone()
            },
            VerifyOutcome {
                unexempted_local: 2,
                ..base.clone()
            },
            VerifyOutcome {
                sampled: 0,
                ..base.clone()
            },
        ] {
            assert!(o.awaits_clean_table(), "{}", o.summary());
        }
        let wrong = VerifyOutcome {
            unresolvable: 1,
            mismatches: vec![Mismatch::NoPaths { prefix: v4(0, 0) }],
            ..base.clone()
        };
        assert!(!wrong.awaits_clean_table(), "a mismatch is not outgrown");
        let dark = VerifyOutcome {
            unresolvable: 1,
            dead_interfaces: vec![DeadInterface {
                name: "eth5".into(),
                sw_if_index: 3,
                admin_up: true,
                link_up: false,
                in_use: true,
            }],
            ..base.clone()
        };
        assert!(!dark.awaits_clean_table(), "nor is a cable");
    }

    /// The 2026-10-07 verdict, and what it may vouch for: one probe
    /// against a one-route table vouches for a one-route table and for
    /// nothing a reload grows it into — at 60% loaded or at 100%.
    #[test]
    fn a_one_probe_verdict_vouches_for_nothing_a_reload_grows() {
        let incident = VerifyOutcome {
            sampled: 1,
            table: 1,
            ..Default::default()
        };
        assert!(incident.passed(), "{}", incident.summary());
        assert!(incident.covers(1), "it does vouch for the table it saw");
        for installed in [2, 666_382, 1_095_605] {
            assert!(
                !incident.covers(installed),
                "one probe of one route cannot vouch for {installed}"
            );
            assert_eq!(
                unvouched(Some(&incident), installed),
                Some(Unvouched::Outgrown {
                    sampled: 1,
                    table: 1,
                    installed
                })
            );
        }
        // The text an operator reads names both numbers.
        let why = unvouched(Some(&incident), 666_382).unwrap().to_string();
        assert!(why.contains("1 probe(s) against 1 routes"), "{why}");
        assert!(why.contains("666382 are installed now"), "{why}");
        assert!(
            incident
                .summary()
                .contains("1/1 probes matched against 1 routes"),
            "{}",
            incident.summary()
        );
    }

    /// The probe half: a pass that drew fewer probes than its own table
    /// allowed does not vouch for that table, however large; one that
    /// drew the whole of a table smaller than the standard sample does.
    #[test]
    fn coverage_needs_the_standard_sample_or_the_whole_table() {
        assert!(!covers(1, 1_000_000, 1_000_000));
        assert!(!covers(DEFAULT_SAMPLE - 1, 1_000_000, 1_000_000));
        assert!(covers(DEFAULT_SAMPLE, 1_000_000, 1_000_000));
        assert!(covers(10, 10, 10), "exhaustive over a small table");
        assert!(!covers(9, 10, 10));
    }

    /// The table half, at the threshold: ordinary growth since the verdict
    /// stays covered, growth past ~11% does not, and shrinkage is never
    /// judged.
    #[test]
    fn coverage_tolerates_churn_and_refuses_a_table_that_outgrew_it() {
        let verified = 1_000_000;
        // A year of DFZ growth is ~10%; a few percent is any lever move.
        assert!(covers(DEFAULT_SAMPLE, verified, 1_030_000));
        assert!(covers(DEFAULT_SAMPLE, verified, 1_111_111));
        assert!(!covers(DEFAULT_SAMPLE, verified, 1_111_112));
        assert!(!covers(DEFAULT_SAMPLE, verified, 2_000_000));
        assert!(covers(DEFAULT_SAMPLE, verified, 500_000), "shrink");
        assert!(covers(DEFAULT_SAMPLE, verified, 0));
    }

    /// What a recording may and may not decide. A mismatch is the probes'
    /// own finding and stands until a restart; a verdict that failed only
    /// on conditions the live table outgrows (unresolvable routes here)
    /// is NOT unvouched — those are judged live — provided it covers the
    /// table; and no verdict at all vouches for nothing.
    #[test]
    fn only_coverage_and_mismatches_are_read_off_the_recording() {
        assert_eq!(unvouched(None, 5), Some(Unvouched::NoVerdict));
        let wrong = VerifyOutcome {
            sampled: 64,
            table: 1_000,
            mismatches: vec![Mismatch::NoPaths { prefix: v4(0, 0) }],
            ..Default::default()
        };
        assert_eq!(unvouched(Some(&wrong), 1_000), Some(Unvouched::Mismatch));
        let holed = VerifyOutcome {
            sampled: 64,
            table: 1_000,
            unresolvable: 3,
            ..Default::default()
        };
        assert!(!holed.passed());
        assert_eq!(unvouched(Some(&holed), 1_000), None);
        assert!(matches!(
            unvouched(Some(&holed), 2_000),
            Some(Unvouched::Outgrown { .. })
        ));
    }

    /// One re-run per clearing: only once the table has stayed clean for
    /// the debounce, never twice inside the minimum interval, and the
    /// debounce starts over whenever the table gets dirty again.
    #[test]
    fn a_re_run_fires_once_when_the_table_clears_and_is_rate_limited() {
        let t0 = std::time::Instant::now();
        let at = |s: u64| t0 + std::time::Duration::from_secs(s);
        let mut r = ReverifySchedule::default();
        let stale = Some(Stale::Incomplete);
        // A stale verdict over a dirty table: nothing.
        assert!(!r.poll(at(0), stale, false));
        // Clean from t=1: not before the debounce has run.
        assert!(!r.poll(at(1), stale, true));
        assert!(!r.poll(at(5), stale, true));
        // Dirty again at t=8 resets it.
        assert!(!r.poll(at(8), stale, false));
        assert!(!r.poll(at(9), stale, true));
        assert!(!r.poll(at(18), stale, true));
        assert!(r.poll(at(19), stale, true), "clean for the debounce: fire");
        // Spent: a verdict that is still stale (the re-run did not clear
        // it) waits out the interval, however clean the table reads.
        assert!(!r.poll(at(30), stale, true));
        assert!(!r.poll(at(19 + 299), stale, true));
        assert!(r.poll(at(19 + 300), stale, true), "the interval has run");
        // A verdict that is no longer stale asks for nothing.
        assert!(!r.poll(at(10_000), None, true));
        assert!(!r.poll(at(10_100), None, true));
    }

    /// An outgrown verdict waits out the debounce and not the minimum
    /// interval: a re-run a moment ago (taken in a lull part-way through
    /// a reload) does not hold a steer for five minutes once the table
    /// has outgrown THAT verdict and VPP has caught up.
    #[test]
    fn an_outgrown_verdict_is_not_rate_limited_by_an_earlier_re_run() {
        let t0 = std::time::Instant::now();
        let at = |s: u64| t0 + std::time::Duration::from_secs(s);
        let mut r = ReverifySchedule::default();
        assert!(!r.poll(at(0), Some(Stale::Outgrown), true));
        assert!(r.poll(at(10), Some(Stale::Outgrown), true), "debounced");
        // Twenty seconds later the table has outgrown the new verdict too.
        assert!(!r.poll(at(30), Some(Stale::Outgrown), true));
        assert!(
            r.poll(at(40), Some(Stale::Outgrown), true),
            "the debounce again, and no five-minute wait"
        );
        // An incomplete one still waits the interval out.
        assert!(!r.poll(at(41), Some(Stale::Incomplete), true));
        assert!(!r.poll(at(60), Some(Stale::Incomplete), true));
    }
}
