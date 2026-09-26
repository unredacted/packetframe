//! The FRR completeness authority: the loop that asks, and what it
//! concludes.
//!
//! The grammar it speaks — which JSON field carries a per-AF prefix
//! count, what End-of-RIB looks like for the CURRENT session, which
//! `neighbor` directives narrow a table — lives in [`crate::fib::frr`],
//! outside the platform gate, with fixtures taken off the reference lab
//! gateway. This module is the part that runs `vtysh`, so it is
//! Linux-only for the same reason [`crate::fib::integrity`] is.
//!
//! ## What it guarantees, and what it does not
//!
//! **Count agreement within tolerance, for a table relationship that has
//! been independently validated, as sampled evidence with a defined
//! freshness bound.** Not "the tables are identical", and not a standing
//! fact.
//!
//! It is deliberately stronger than the `birdc` authority, which is
//! count-only. The extra conjuncts are not decoration:
//!
//! - **Upstream readiness.** Before an upstream has finished loading,
//!   FRR's table and our mirror fill *together*, so the counts agree the
//!   whole way up and the comparison is vacuous. Measured on the lab
//!   gateway (FRR 10.1.2, 2026-09-22): two seconds after `clear bgp` the
//!   peer read `Established` with `endOfRibRecv=false`. Session state
//!   alone would have called that table complete.
//! - **Export policy.** A filter on the session feeding us cannot be
//!   seen in the numbers at all: at `STEER_MAX_DRIFT` of 1%, something
//!   removing 5,000 prefixes from a million still reads `Converged`, and
//!   a larger deficit is indistinguishable from an unfinished dump. So
//!   it is refused on the *configuration*, and count drift is never
//!   labelled as proven export mismatch.
//!
//! Both of those disqualify rather than fail: see
//! [`packetframe_common::fib::Revocation`] for why that distinction has
//! to exist and why it is sticky.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use packetframe_common::config::{AuthorityFamily, AuthorityUpstream};
use packetframe_common::fib::{AuthorityObservation, TableCompleteness};
use packetframe_common::frr::{RealVtysh, Vtysh};

use crate::fib::frr::{
    classify_bracketed, mirror_family_mismatch, next_check_delay, observation,
    parse_established_epoch, parse_export_policy, parse_total_prefixes, parse_upstream_state,
    split_two_json, Eligibility, ExportPolicy, UpstreamBracket, UpstreamState,
};
use crate::fib::integrity::{Comparison, Drift, SharedSnapshot, DEFAULT_DRIFT_WARN_FRACTION};
use crate::fib::programmer::FibProgrammerHandle;

/// Subprocess budget for one `vtysh` call.
///
/// A ceiling that catches a genuine hang, not a latency target — but
/// sized for a LOADED full-table box, which the 10 s it used to share
/// with `BIRDC_TIMEOUT` was not. On a production router refilling a
/// ~1.3M-route table at 30–60% softirq, both `show bgp ipv4 unicast
/// statistics` and `show running-config` timed out at 10 s on check
/// after check for several minutes, though the running-config returns
/// well inside a second on an idle box. The load is what changed, not
/// the commands: every read waits its turn on the daemon's main event
/// loop behind the UPDATE processing (bgpd) or route installs (zebra)
/// of the refill, and the statistics read then walks the whole table on
/// top of that. None of the cheaper counters measures the same thing —
/// `ribCount` and `pfxSnt` are ruled out in [`crate::fib::frr`]'s module
/// docs, and summing per-peer `pfxRcd` counts a prefix once per upstream
/// that sends it. `birdc`'s premise — bird answers synchronously against
/// the live RIB — does not carry over.
///
/// A short budget is worse than useless here: a killed `vtysh` loses the
/// answer without withdrawing the work (see
/// [`crate::fib::frr::next_check_delay`]), so the daemon pays for the
/// walk and the checker gets nothing for it.
///
/// Why not longer: a check is four phases in sequence — the counts, the
/// upstreams, the running-config, the upstreams again — each of which is
/// one call or several concurrent ones, so 30 s per call is 120 s per
/// check, inside [`CHECK_BUDGET`].
pub const VTYSH_TIMEOUT: Duration = Duration::from_secs(30);

/// Wall-clock budget for all of one check's `vtysh` reads together.
///
/// `FRR_INTERVAL_SECS`'s ceiling is derived from "one failed check must
/// not age the retained report out": with a full interval after every
/// attempt, the second attempt after a report lands at
/// `2 × interval + 2 × check time`, which must stay under
/// `STEER_MAX_REPORT_AGE`. At the 300 s ceiling that leaves 150 s per
/// check, and a per-call timeout alone cannot promise it — the first
/// revision of this change read upstreams one after another, so the
/// check grew by 30 s per declared upstream and eight of them broke the
/// arithmetic (review finding, PR #268). The upstream reads are
/// concurrent now, and this deadline makes the bound hold for any
/// config the parser accepts rather than for the configs somebody
/// counted. A read the deadline cuts off is a failed read: an
/// observation failure like any timeout.
///
/// The rest of a check — the mirror counts and the snapshot write — is
/// in-process and not charged here.
pub const CHECK_BUDGET: Duration =
    Duration::from_secs(packetframe_common::fib::STEER_MAX_REPORT_AGE.as_secs() / 6);

#[derive(Debug, Clone)]
pub struct FrrAuthorityConfig {
    pub interval: Duration,
    /// `None` ⇒ the shared client's default, itself overridable by
    /// `PACKETFRAME_VTYSH` (which is how the netns tests get a fake in
    /// front of it).
    pub vtysh_path: Option<PathBuf>,
    /// Upstreams whose End-of-RIB must have arrived for their current
    /// session, each with the families ITS session carries. Declared by
    /// the operator, never inferred — see
    /// [`AuthorityUpstream`] for why there is no default and why the
    /// families are per-upstream rather than global.
    pub upstreams: Vec<AuthorityUpstream>,
    /// The FRR neighbour that IS packetframe — the session being
    /// attested, and the one whose export policy must not narrow the
    /// table.
    ///
    /// Taken from `route-source bgp`'s listen address rather than
    /// configured again here. One fewer thing for an operator to get
    /// wrong, and it cannot drift from the session that actually feeds
    /// the mirror.
    pub pf_peer: IpAddr,
    pub drift_warn_fraction: f64,
}

impl FrrAuthorityConfig {
    pub fn new(
        interval: Duration,
        vtysh_path: Option<PathBuf>,
        upstreams: Vec<AuthorityUpstream>,
        pf_peer: IpAddr,
    ) -> Self {
        Self {
            interval,
            vtysh_path,
            upstreams,
            pf_peer,
            drift_warn_fraction: DEFAULT_DRIFT_WARN_FRACTION,
        }
    }

    /// The families the COMPARISON counts: the union of what the
    /// upstreams carry.
    ///
    /// Derived rather than declared, because the mirror holds exactly
    /// what the upstreams deliver — a separate global list would be a
    /// second place to state the same fact, and the two would disagree
    /// the first time an upstream was added.
    ///
    /// Order is v4 then v6 so the summed count and the log line are
    /// stable across config edits.
    pub fn counted_families(&self) -> Vec<AuthorityFamily> {
        [AuthorityFamily::V4, AuthorityFamily::V6]
            .into_iter()
            .filter(|f| self.upstreams.iter().any(|u| u.families.contains(f)))
            .collect()
    }
}

pub struct FrrAuthorityChecker {
    config: FrrAuthorityConfig,
    vtysh: Arc<dyn Vtysh>,
    snapshot: SharedSnapshot,
    prog: FibProgrammerHandle,
    completeness: Option<Arc<TableCompleteness>>,
    shutdown: CancellationToken,
    /// Each upstream's establishment epoch as of the last time it was
    /// read successfully.
    ///
    /// The session-generation marker. A reading taken before a peer
    /// bounced describes a session that no longer exists, so an epoch
    /// that has MOVED revokes — even when the peer is Established with
    /// End-of-RIB already in, because the permission standing at that
    /// moment was earned by the old session. Revocation is sticky, so
    /// the cost is exactly one tick: the next clean, agreeing
    /// observation restores it.
    ///
    /// It doubles as a config-change detector on UniFi, where any FRR
    /// configuration upload restarts zebra and bgpd and therefore
    /// re-establishes every session — which is the one event that can
    /// introduce an export filter under a running daemon.
    seen_epochs: HashMap<IpAddr, u64>,
    /// The revocation reason currently announced in the log, so the
    /// transitions are logged and the steady state is not.
    ///
    /// A disqualification is an operator-visible state change and until
    /// now it reached `packetframe status` and nothing else — which is
    /// fine on a rig somebody is watching and useless on the primary at
    /// 03:00, where the journal is the record. Logging it every tick
    /// instead would be 288 identical warnings a day, which is the same
    /// as not logging it.
    announced_revocation: Option<String>,
    /// [`CHECK_BUDGET`], as a field so a test can shrink it.
    check_budget: Duration,
    /// When the running check's reads must be done by. Set at the start
    /// of each check; every `vtysh` call goes through [`Self::ask`].
    deadline: tokio::time::Instant,
}

impl FrrAuthorityChecker {
    pub fn new(
        config: FrrAuthorityConfig,
        snapshot: SharedSnapshot,
        prog: FibProgrammerHandle,
        shutdown: CancellationToken,
    ) -> Self {
        let vtysh: Arc<dyn Vtysh> = match &config.vtysh_path {
            Some(p) => Arc::new(RealVtysh::at(p.clone(), VTYSH_TIMEOUT)),
            None => Arc::new(RealVtysh::from_env(VTYSH_TIMEOUT)),
        };
        Self::with_vtysh(config, vtysh, snapshot, prog, shutdown)
    }

    /// Injectable `vtysh`, for the tests that drive whole ticks.
    pub fn with_vtysh(
        config: FrrAuthorityConfig,
        vtysh: Arc<dyn Vtysh>,
        snapshot: SharedSnapshot,
        prog: FibProgrammerHandle,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            config,
            vtysh,
            snapshot,
            prog,
            completeness: None,
            shutdown,
            seen_epochs: HashMap::new(),
            announced_revocation: None,
            check_budget: CHECK_BUDGET,
            deadline: tokio::time::Instant::now(),
        }
    }

    /// Publish each observation to the second forwarding tier as well.
    /// Set by the loader, which is the only place that sees both
    /// modules.
    pub fn with_completeness(mut self, handle: Arc<TableCompleteness>) -> Self {
        self.completeness = Some(handle);
        self
    }

    pub async fn run(mut self) {
        info!(
            interval_secs = self.config.interval.as_secs(),
            upstreams = ?self.config.upstreams,
            families = ?self.config.counted_families(),
            pf_peer = %self.config.pf_peer,
            "FrrAuthorityChecker started"
        );
        let shutdown = self.shutdown.clone();
        let mut unreadable_streak = 0u32;
        loop {
            let delay = next_check_delay(self.config.interval, unreadable_streak);
            if unreadable_streak > 0 {
                debug!(
                    streak = unreadable_streak,
                    retry_in_secs = delay.as_secs(),
                    "FRR authority: check unreadable, retrying before the interval"
                );
            }
            tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("FrrAuthorityChecker shutdown");
                    return;
                }
                _ = tokio::time::sleep(delay) => {}
            }
            // The check races shutdown too. With a 30 s subprocess
            // budget a check can outlast the controller's drain window
            // by a wide margin, and dropping it here is clean: every
            // `vtysh` is `kill_on_drop`, nothing is published until the
            // reads are done, and after shutdown nothing reads what was.
            let readable = tokio::select! {
                _ = shutdown.cancelled() => {
                    info!("FrrAuthorityChecker shutdown");
                    return;
                }
                readable = self.run_check() => readable,
            };
            unreadable_streak = if readable {
                0
            } else {
                unreadable_streak.saturating_add(1)
            };
        }
    }

    /// One check. Returns whether it was READABLE — `Clean` or
    /// `Disqualified` — which is all the loop needs to pace the next one
    /// ([`next_check_delay`]).
    async fn run_check(&mut self) -> bool {
        self.deadline = tokio::time::Instant::now() + self.check_budget;
        // THE PAIR, CONCURRENTLY, for the same reason the birdc checker
        // does it: the gap between the two numbers is the report's error
        // bar, and whatever the mirror does while the other number is
        // being fetched shows up as drift that never existed. Every
        // per-family `vtysh` call and the mirror read overlap on this
        // task.
        let (authority, mirror) = tokio::join!(self.authority_count(), self.prog.mirror_counts());
        // ONE `Instant`, stamped the moment the pair completes — the
        // comparison, `last_run` and the published report all carry it,
        // and `IntegrityPosture` tells a current comparison from a
        // retained one by comparing them for equality.
        let at = Instant::now();

        // Eligibility is NOT part of the comparison, so it is read
        // outside the pair — same placement as the birdc checker's peer
        // count, and for the same reason: a subprocess call that neither
        // number depends on must not sit between them.
        let mut eligibility = self.eligibility().await;
        // The mirror's own composition is evidence too, and it needs no
        // subprocess — so it is checked here rather than inside
        // `eligibility`, which is the vtysh half. It outranks
        // `Unknown` for the usual reason (a fact beats a failed read)
        // and defers to an existing `Revoked`, because the first reason
        // found is as true as the second and churning the message
        // between ticks helps nobody.
        //
        // ROUTE-SOURCE families, not `mirror`: the mirror carries the
        // resolver's synthetic `local-prefix` routes too, and one /128
        // would read as a v6 feed on a v4-only box. A failed query is
        // simply no evidence — it cannot produce a revocation.
        if let Ok((v4, v6)) = self.prog.session_families().await {
            if let Some(r) = mirror_family_mismatch(v4, v6, &self.config.counted_families()) {
                if !matches!(eligibility, Eligibility::Revoked(_)) {
                    eligibility = Eligibility::Revoked(r);
                }
            }
        }

        let fresh_authority = authority.as_ref().ok().copied();
        let fresh_mirror = mirror.as_ref().ok().map(|(v4, v6)| v4 + v6);

        // Exactly one observation per tick, and the precedence is the
        // point of the ordering.
        //
        // A disqualification is POSITIVE evidence and outranks a partial
        // read: if one upstream could not be read and another answered
        // "not Established", the second is a fact and must withdraw
        // permission. A count that could not be sampled, by contrast,
        // can never produce `Clean` — so a tick that read eligibility
        // fine and lost the counts is `Unreadable`, which retains the
        // previous report under the age policy and retains any standing
        // revocation. Neither of those is the same as renewing.
        let obs = observation(&eligibility, fresh_authority, fresh_mirror, at);
        let readable = !matches!(obs, AuthorityObservation::Unreadable);
        if let Some(handle) = self.completeness.as_ref() {
            handle.record(obs);
        }

        let mut snap = self.snapshot.write().await;
        snap.last_run = Some(at);
        snap.last_error = None;
        snap.authority = Some("FRR");
        // The disqualification, on the snapshot as its own fact.
        //
        // It is NOT an error — nothing failed to be read, and the remedy
        // is in the operator's BGP configuration. Without it a tick
        // whose counts agreed recorded a clean comparison and no error,
        // so `fib-integrity` reported a converged authority while
        // `TableCompleteness` held `Ineligible` and the second tier
        // refused every steer, with the concrete reason nowhere on the
        // box (review finding, PR #232).
        //
        // **The STANDING revocation, not this tick's observation**, and
        // that is the whole reason the handle is consulted rather than
        // `eligibility` read directly. Revocation is sticky: a tick that
        // could not read `vtysh` publishes `Unreadable`, which leaves it
        // in force. Reporting this tick instead would drop the
        // DISQUALIFIED clause the moment vtysh failed — while steering
        // stayed refused — and the row would go back to advertising the
        // rollout, which is the contradiction fixed one commit ago
        // arriving through a second door.
        //
        // With no handle there is no second tier and so no standing
        // state to consult; this tick's own observation is then the only
        // thing there is to report, and nothing is enforcing stickiness
        // for it to contradict.
        snap.revoked = match self.completeness.as_ref() {
            Some(handle) => match handle.latest_verdict().1 {
                packetframe_common::fib::Completeness::Ineligible(r) => Some(r),
                _ => None,
            },
            // A failed read changes nothing — the rule
            // `TableCompleteness::record(Unreadable)` applies, stated
            // for the one path that has no handle to apply it. Mapping
            // `Unknown` to `None` here logged a false "eligible again"
            // on every unreadable tick and a fresh DISQUALIFIED warning
            // on the next readable one (review finding, PR #234).
            None => match &eligibility {
                Eligibility::Revoked(r) => Some(r.clone()),
                Eligibility::Ok => None,
                Eligibility::Unknown(_) => snap.revoked.clone(),
            },
        };
        // Transitions only. Entering a revocation, or the reason
        // changing under it, is what an operator needs in the journal;
        // the steady state is what `packetframe status` is for.
        let now_reason = snap.revoked.as_ref().map(|r| r.describe().to_string());
        match (&now_reason, &self.announced_revocation) {
            (Some(now), prev) if prev.as_deref() != Some(now.as_str()) => {
                // SUBJUNCTIVE, for the reason the status row is: this
                // checker cannot see whether anything consults it. With
                // no vpp-offload there is no gate at all, and with
                // `require-table-complete off` the runtime deliberately
                // discards this one — so "steering refused" would send
                // an operator hunting a refusal that never happened
                // (review finding, PR #234).
                warn!(
                    reason = %now,
                    "completeness authority: mirror DISQUALIFIED — a steering gate that \
                     consults this authority would refuse until a check comes back clean AND \
                     the counts agree"
                );
                self.announced_revocation = Some(now.clone());
            }
            (None, Some(prev)) => {
                info!(
                    cleared = %prev,
                    "completeness authority: mirror eligible again"
                );
                self.announced_revocation = None;
            }
            _ => {}
        }
        if let Err(e) = &authority {
            snap.last_error = Some(e.clone());
            warn!(error = %e, "FRR authority: prefix count failed");
        }
        if let Err(e) = &mirror {
            snap.last_error = Some(format!("programmer mirror_counts: {e}"));
            warn!(error = %e, "FRR authority: mirror_counts failed");
        }
        if let Eligibility::Unknown(why) = &eligibility {
            if snap.last_error.is_none() {
                snap.last_error = Some(why.clone());
            }
            warn!(reason = %why, "FRR authority: eligibility could not be established");
        }

        // The comparison is recorded whenever BOTH counts came from THIS
        // run — eligibility does not suppress it. The snapshot is what
        // an operator reads, and hiding the numbers behind a
        // disqualification would leave them watching a mirror fill with
        // nothing to watch it by. Eligibility gates the second tier's
        // PERMISSION, below; it does not gate reporting.
        if let (Some(auth), Some(pf)) = (fresh_authority, fresh_mirror) {
            let drift = (auth != 0).then(|| {
                let fraction = (auth as f64 - pf as f64).abs() / auth as f64;
                Drift {
                    fraction,
                    threshold: self.config.drift_warn_fraction,
                    above: fraction >= self.config.drift_warn_fraction,
                }
            });
            match drift {
                Some(d) if d.above => warn!(
                    authority_prefixes = auth,
                    packetframe_prefixes = pf,
                    drift_fraction = d.fraction,
                    "integrity drift above threshold"
                ),
                Some(d) => debug!(
                    authority_prefixes = auth,
                    packetframe_prefixes = pf,
                    drift_fraction = d.fraction,
                    "integrity check OK"
                ),
                None => warn!(
                    authority_prefixes = auth,
                    packetframe_prefixes = pf,
                    "FRR authority reports no prefixes in the declared families"
                ),
            }
            snap.last_comparison = Some(Comparison {
                at,
                authority_prefixes: auth,
                packetframe_prefixes: pf,
                drift,
            });
        }
        readable
    }
    /// Sum the declared families' prefix counts.
    ///
    /// One `vtysh` per family, run concurrently. Batching them into a
    /// single invocation would give one consistent view of FRR, which is
    /// the better property — but the answers come back as concatenated
    /// JSON documents, and splitting that stream is a parsing contract
    /// nothing on the box has been measured against. Concurrent calls
    /// narrow the window without inventing one.
    ///
    /// Concurrency does not double bgpd's work — each family's table is
    /// walked once per check, and bgpd runs vty commands one at a time
    /// on its main thread whichever order they arrive in — but it does
    /// mean one call's [`VTYSH_TIMEOUT`] can include the other family's
    /// walk. Checks never overlap each other: the loop awaits one before
    /// it sleeps toward the next.
    ///
    /// A family that cannot be read fails the WHOLE count. Summing the
    /// families that answered would report a smaller authority than
    /// exists, which is drift pointing the wrong way — it reads as the
    /// mirror being too big, which `assess` classifies as
    /// `AuthorityMismatch`: "that is not the authority feeding this
    /// mirror", a conclusion a missing subprocess has not earned.
    async fn authority_count(&self) -> Result<usize, String> {
        let families = self.config.counted_families();
        let counts =
            futures::future::join_all(families.iter().map(|f| self.family_count(*f))).await;
        let mut total = 0usize;
        for c in counts {
            total += c?;
        }
        Ok(total)
    }

    async fn family_count(&self, family: AuthorityFamily) -> Result<usize, String> {
        let out = self
            .ask(&[format!("show bgp {} unicast statistics json", family.afi())])
            .await
            .map_err(|e| format!("vtysh statistics {}: {e}", family.afi()))?;
        Ok(parse_total_prefixes(&out, family)? as usize)
    }

    /// Every `vtysh` call, bounded by the check's [`CHECK_BUDGET`] on top
    /// of the per-call [`VTYSH_TIMEOUT`]. Dropping the call at the
    /// deadline kills the child (`kill_on_drop`), exactly as a per-call
    /// timeout does.
    async fn ask(&self, commands: &[String]) -> Result<String, String> {
        tokio::time::timeout_at(self.deadline, self.vtysh.run(commands))
            .await
            .map_err(|_| {
                format!(
                    "check budget of {:?} spent before vtysh answered",
                    self.check_budget
                )
            })?
    }

    /// Read everything eligibility depends on, then judge it.
    ///
    /// The judging is [`classify_bracketed`], deliberately: the
    /// precedence between "disqualified", "could not read" and "fine" is
    /// the safety argument of this whole authority, and it belongs
    /// somewhere its tests do not need a NIC, a live FRR and a qemu job.
    /// This half is the subprocess calls and nothing else.
    ///
    /// **Upstreams, running-config, upstreams again.** The first reading
    /// follows the counts directly, because End-of-RIB has a timing
    /// relationship to them; the second follows the running-config — the
    /// slowest read on a loaded box — so a flap during it cannot slip
    /// under a clean observation (review finding, PR #268).
    /// [`classify_bracketed`] says why one reading on either side is not
    /// enough.
    async fn eligibility(&mut self) -> Eligibility {
        let before = self.upstreams().await;
        let export = self.export_policy().await;
        let after = self.upstreams().await;
        let brackets: Vec<UpstreamBracket> = self
            .config
            .upstreams
            .iter()
            .zip(before.into_iter().zip(after))
            .map(|(u, (before, after))| UpstreamBracket {
                peer: u.addr,
                before,
                after,
            })
            .collect();
        classify_bracketed(export, &brackets, &mut self.seen_epochs)
    }

    /// Every declared upstream, one `vtysh` each, concurrently, in
    /// config order.
    ///
    /// Concurrent so the phase costs one wait on bgpd rather than one per
    /// upstream (see [`CHECK_BUDGET`]). One invocation each rather than
    /// all of them batched into one, so an upstream whose read fails
    /// fails alone and cannot erase another's positive evidence.
    async fn upstreams(&self) -> Vec<Result<UpstreamState, String>> {
        futures::future::join_all(self.config.upstreams.iter().map(|u| self.upstream(u))).await
    }

    /// One upstream's readiness and session generation.
    ///
    /// Two commands in ONE `vtysh` invocation, so the state and the
    /// epoch describe the same instant — the epoch is what says whether
    /// the state can be trusted, and reading them from two processes
    /// would let a flap land between them and produce a reading that is
    /// self-consistently wrong. The outputs are split on the boundary
    /// between the two JSON documents.
    async fn upstream(&self, up: &AuthorityUpstream) -> Result<UpstreamState, String> {
        let peer = up.addr;
        // The summary is asked under a family THIS session carries. The
        // epoch it reports is a session property rather than a per-AF
        // one, but a family the peer does not carry has no row to read
        // it from — which is how a v6-only upstream lost its epoch when
        // the afi was picked from a global list.
        let afi = up
            .families
            .first()
            .copied()
            .unwrap_or(AuthorityFamily::V4)
            .afi();
        let out = self
            .ask(&[
                format!("show bgp neighbor {peer} json"),
                format!("show bgp {afi} unicast summary json"),
            ])
            .await
            .map_err(|e| format!("vtysh neighbor {peer}: {e}"))?;
        let (neighbor, summary) = split_two_json(&out)
            .ok_or_else(|| format!("vtysh returned no second document for neighbor {peer}"))?;

        let mut state = parse_upstream_state(neighbor, &peer.to_string(), &up.families)?;
        state.established_epoch = parse_established_epoch(summary, &peer.to_string());
        Ok(state)
    }

    async fn export_policy(&self) -> Result<ExportPolicy, String> {
        let out = self
            .ask(&["show running-config".to_string()])
            .await
            .map_err(|e| format!("vtysh running-config: {e}"))?;
        Ok(parse_export_policy(
            &out,
            &self.config.pf_peer.to_string(),
            &self.config.counted_families(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::fib::integrity::shared_snapshot;
    use crate::fib::programmer::recording_handle;

    /// A `vtysh` that answers one tick "the upstream is down" and every
    /// tick after with a failure — the drill-2 shape from the rig: a
    /// revocation, then a tick where nothing can be read.
    struct DownThenGone {
        gone: AtomicBool,
    }

    impl Vtysh for DownThenGone {
        fn run<'a>(
            &'a self,
            commands: &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
            Box::pin(async move {
                if self.gone.load(Ordering::SeqCst) {
                    return Err("spawn /usr/bin/vtysh: No such file or directory".into());
                }
                let first = commands.first().map(String::as_str).unwrap_or("");
                Ok(if first.starts_with("show bgp neighbor") {
                    // neighbor document, then the summary document, as one
                    // invocation's concatenated output.
                    r#"{"192.0.2.1":{"bgpState":"Active"}}{"peers":{}}"#.to_string()
                } else if first == "show running-config" {
                    String::new()
                } else {
                    r#"{"ipv4Unicast":[{"totalPrefixes":10}]}"#.to_string()
                })
            })
        }
    }

    fn config() -> FrrAuthorityConfig {
        FrrAuthorityConfig::new(
            Duration::from_secs(300),
            None,
            vec![AuthorityUpstream {
                addr: "192.0.2.1".parse().expect("ip"),
                families: vec![AuthorityFamily::V4],
            }],
            "198.51.100.2".parse().expect("ip"),
        )
    }

    /// An unreadable tick must not announce a recovery that did not
    /// happen — on the path with NO completeness handle, which is the
    /// one that has no `TableCompleteness` to apply stickiness for it.
    ///
    /// Before the fix, `Unknown` mapped `snap.revoked` to `None`, so the
    /// tick after a revocation logged "mirror eligible again" merely
    /// because `vtysh` could not be run, and the next readable tick
    /// logged a fresh DISQUALIFIED warning for the same condition
    /// (review finding, PR #234). Asserted on the snapshot and the
    /// announcement state together, because those are what `status`
    /// and the journal are built from.
    #[tokio::test]
    async fn an_unreadable_tick_keeps_the_revocation_without_a_handle() {
        let (prog, _log) = recording_handle();
        let vtysh = Arc::new(DownThenGone {
            gone: AtomicBool::new(false),
        });
        let snapshot = shared_snapshot();
        let mut checker = FrrAuthorityChecker::with_vtysh(
            config(),
            vtysh.clone(),
            snapshot.clone(),
            prog,
            CancellationToken::new(),
        );
        assert!(
            checker.completeness.is_none(),
            "the fixture must be the no-handle path, or this proves nothing about it"
        );

        checker.run_check().await;
        let first = snapshot.read().await.revoked.clone();
        assert!(
            matches!(
                first,
                Some(packetframe_common::fib::Revocation::UpstreamNotReady(_))
            ),
            "tick 1 revokes on the down upstream: {first:?}"
        );
        let announced = checker.announced_revocation.clone();
        assert!(announced.is_some(), "and announces it once");

        vtysh.gone.store(true, Ordering::SeqCst);
        checker.run_check().await;
        assert_eq!(
            snapshot.read().await.revoked,
            first,
            "a tick that could read nothing must not lift the revocation"
        );
        assert_eq!(
            checker.announced_revocation, announced,
            "nor announce a recovery — the journal would say 'eligible again' while \
             nothing had changed"
        );
        assert!(
            snapshot.read().await.last_error.is_some(),
            "the failed read is still reported, as an error rather than a verdict"
        );
    }

    /// The error [`RealVtysh`] returns when its budget runs out, so the
    /// fakes below fail the way production does.
    fn timed_out() -> String {
        format!("vtysh timed out after {VTYSH_TIMEOUT:?}")
    }

    /// A `vtysh` whose upstream is ready and whose reads can each be
    /// made to time out, recording the first command of every call so
    /// the order of the reads is observable.
    #[derive(Default)]
    struct Scripted {
        upstream_down: AtomicBool,
        stats_time_out: AtomicBool,
        config_times_out: AtomicBool,
        flap_during_config: AtomicBool,
        neighbor_hangs: AtomicBool,
        epoch_offset: std::sync::atomic::AtomicU64,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl Vtysh for Scripted {
        fn run<'a>(
            &'a self,
            commands: &'a [String],
        ) -> Pin<Box<dyn Future<Output = Result<String, String>> + Send + 'a>> {
            Box::pin(async move {
                let first = commands.first().cloned().unwrap_or_default();
                self.calls.lock().expect("calls").push(first.clone());
                if first.starts_with("show bgp neighbor") {
                    if self.neighbor_hangs.load(Ordering::SeqCst) {
                        return std::future::pending().await;
                    }
                    let state = if self.upstream_down.load(Ordering::SeqCst) {
                        "Active"
                    } else {
                        "Established"
                    };
                    let epoch = 1_790_000_000 + self.epoch_offset.load(Ordering::SeqCst);
                    return Ok(format!(
                        r#"{{"192.0.2.1":{{"bgpState":"{state}","gracefulRestartInfo":{{"ipv4Unicast":{{"endOfRibStatus":{{"endOfRibRecv":true}}}}}}}}}}{{"peers":{{"192.0.2.1":{{"peerUptimeEstablishedEpoch":{epoch}}}}}}}"#
                    ));
                }
                if first == "show running-config" {
                    if self.flap_during_config.load(Ordering::SeqCst) {
                        // The session is replaced while the slow read is
                        // in flight; the new one is already loaded by
                        // the time anything looks again.
                        self.epoch_offset.fetch_add(600, Ordering::SeqCst);
                    }
                    if self.config_times_out.load(Ordering::SeqCst) {
                        return Err(timed_out());
                    }
                    return Ok(String::new());
                }
                if self.stats_time_out.load(Ordering::SeqCst) {
                    return Err(timed_out());
                }
                Ok(
                    r#"{"ipv4Unicast":[{"instance":"VRF default","totalPrefixes":10}]}"#
                        .to_string(),
                )
            })
        }
    }

    fn checker_with_handle(
        vtysh: Arc<Scripted>,
    ) -> (FrrAuthorityChecker, Arc<TableCompleteness>, SharedSnapshot) {
        let (prog, _log) = recording_handle();
        let snapshot = shared_snapshot();
        let handle = Arc::new(TableCompleteness::new());
        let checker = FrrAuthorityChecker::with_vtysh(
            config(),
            vtysh,
            snapshot.clone(),
            prog,
            CancellationToken::new(),
        )
        .with_completeness(handle.clone());
        (checker, handle, snapshot)
    }

    /// A timed-out count is an observation failure: the previous report
    /// stands exactly as it was — same sample, same `at` — nothing is
    /// revoked, and the loop is told to retry early. The longer budget
    /// and the retry change WHEN a sample can land, never what a failed
    /// one means.
    #[tokio::test]
    async fn a_timed_out_count_retains_the_report_and_revokes_nothing() {
        let vtysh = Arc::new(Scripted::default());
        let (mut checker, handle, snapshot) = checker_with_handle(vtysh.clone());

        assert!(checker.run_check().await, "a fully read check is readable");
        let (before, verdict) = handle.latest_verdict();
        assert!(before.is_some(), "the clean check published a report");
        assert!(
            !matches!(
                verdict,
                packetframe_common::fib::Completeness::Ineligible(_)
            ),
            "nothing disqualifying was observed: {verdict:?}"
        );

        vtysh.stats_time_out.store(true, Ordering::SeqCst);
        assert!(
            !checker.run_check().await,
            "a check whose count timed out is unreadable, so the loop retries early"
        );
        let (after, verdict) = handle.latest_verdict();
        assert_eq!(after, before, "the previous report is retained untouched");
        assert!(
            !matches!(
                verdict,
                packetframe_common::fib::Completeness::Ineligible(_)
            ),
            "a timeout is not evidence, so it cannot revoke: {verdict:?}"
        );
        let snap = snapshot.read().await;
        assert!(
            snap.last_error
                .as_deref()
                .is_some_and(|e| e.contains("timed out")),
            "the timeout is reported as an error: {:?}",
            snap.last_error
        );
        assert!(snap.revoked.is_none(), "and not as a disqualification");
    }

    /// The running-config read timing out is the same observation
    /// failure, and it keeps a STANDING revocation in force: stickiness
    /// clears only on a fully successful check, and a check that could
    /// not read the export policy is not one — even when the upstream
    /// that caused the revocation has recovered and the counts read
    /// fine.
    #[tokio::test]
    async fn a_timed_out_running_config_keeps_a_standing_revocation() {
        let vtysh = Arc::new(Scripted::default());
        vtysh.upstream_down.store(true, Ordering::SeqCst);
        let (mut checker, handle, _snapshot) = checker_with_handle(vtysh.clone());

        assert!(
            checker.run_check().await,
            "a disqualification is readable — it is positive evidence, paced at the interval"
        );
        let revoked = |h: &TableCompleteness| {
            matches!(
                h.latest_verdict().1,
                packetframe_common::fib::Completeness::Ineligible(
                    packetframe_common::fib::Revocation::UpstreamNotReady(_)
                )
            )
        };
        assert!(revoked(&handle), "the down upstream revokes");

        vtysh.upstream_down.store(false, Ordering::SeqCst);
        vtysh.config_times_out.store(true, Ordering::SeqCst);
        assert!(
            !checker.run_check().await,
            "counts and upstream fine, running-config timed out: unreadable"
        );
        assert!(
            revoked(&handle),
            "an unreadable check must not lift a standing revocation"
        );
    }

    /// Upstream readiness is read on both sides of the running-config:
    /// directly after the counts, and again after the slow read.
    #[tokio::test]
    async fn upstream_readiness_brackets_the_running_config() {
        let vtysh = Arc::new(Scripted::default());
        let (mut checker, _handle, _snapshot) = checker_with_handle(vtysh.clone());
        checker.run_check().await;

        let calls = vtysh.calls.lock().expect("calls").clone();
        let first = |prefix: &str| {
            calls
                .iter()
                .position(|c| c.starts_with(prefix))
                .unwrap_or_else(|| panic!("no `{prefix}` call in {calls:?}"))
        };
        let last = |prefix: &str| {
            calls
                .iter()
                .rposition(|c| c.starts_with(prefix))
                .unwrap_or_else(|| panic!("no `{prefix}` call in {calls:?}"))
        };
        assert!(first("show bgp ipv4 unicast statistics") < first("show bgp neighbor"));
        assert!(
            first("show bgp neighbor") < first("show running-config"),
            "readiness must not wait behind the running-config: {calls:?}"
        );
        assert!(
            last("show running-config") < last("show bgp neighbor"),
            "and must be read again after it: {calls:?}"
        );
    }

    fn not_ready(h: &TableCompleteness) -> bool {
        matches!(
            h.latest_verdict().1,
            packetframe_common::fib::Completeness::Ineligible(
                packetframe_common::fib::Revocation::UpstreamNotReady(_)
            )
        )
    }

    /// Review finding (PR #268): an upstream replaced while the slow
    /// running-config read is in flight must revoke, not publish clean
    /// on the dead session's state. The FIRST check, so no previous
    /// epoch exists and only the two readings of this check can see it.
    #[tokio::test]
    async fn a_flap_during_the_running_config_revokes() {
        let vtysh = Arc::new(Scripted::default());
        vtysh.flap_during_config.store(true, Ordering::SeqCst);
        let (mut checker, handle, _snapshot) = checker_with_handle(vtysh.clone());

        assert!(checker.run_check().await, "a revocation is readable");
        assert!(not_ready(&handle), "{:?}", handle.latest_verdict());
        assert!(
            handle.latest_verdict().0.is_none(),
            "and nothing clean was published from the check"
        );
    }

    /// The same session at both ends of the check stays clean.
    #[tokio::test]
    async fn an_unchanged_session_across_both_readings_is_clean() {
        let vtysh = Arc::new(Scripted::default());
        let (mut checker, handle, _snapshot) = checker_with_handle(vtysh.clone());

        assert!(checker.run_check().await);
        let (report, verdict) = handle.latest_verdict();
        assert!(report.is_some(), "a clean check publishes its report");
        assert!(
            !matches!(
                verdict,
                packetframe_common::fib::Completeness::Ineligible(_)
            ),
            "{verdict:?}"
        );
    }

    /// The whole check is bounded, however many upstreams there are and
    /// however slowly each answers — the guarantee `FRR_INTERVAL_SECS`
    /// is derived from (review finding, PR #268). Eight upstreams whose
    /// reads never return: the check ends at the budget, unreadable,
    /// with the budget named as the reason.
    #[tokio::test]
    async fn the_check_is_bounded_whatever_the_upstream_count() {
        let vtysh = Arc::new(Scripted::default());
        vtysh.neighbor_hangs.store(true, Ordering::SeqCst);
        let mut cfg = config();
        cfg.upstreams = (1..=8)
            .map(|i| AuthorityUpstream {
                addr: format!("192.0.2.{i}").parse().expect("ip"),
                families: vec![AuthorityFamily::V4],
            })
            .collect();
        let (prog, _log) = recording_handle();
        let snapshot = shared_snapshot();
        let mut checker = FrrAuthorityChecker::with_vtysh(
            cfg,
            vtysh,
            snapshot.clone(),
            prog,
            CancellationToken::new(),
        );
        checker.check_budget = Duration::from_millis(200);

        let started = Instant::now();
        assert!(!checker.run_check().await, "a check cut off is unreadable");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
        let err = snapshot.read().await.last_error.clone();
        assert!(
            err.as_deref().is_some_and(|e| e.contains("check budget")),
            "{err:?}"
        );
    }

    /// The arithmetic the budget exists for, pinned against the
    /// constants it is derived from: four phases of one per-call timeout
    /// fit the budget, and two checks at the interval ceiling still land
    /// before the report-age limit.
    #[test]
    fn the_check_budget_fits_the_report_age_arithmetic() {
        let max_interval =
            Duration::from_secs(*packetframe_common::config::FRR_INTERVAL_SECS.end());
        assert!(4 * VTYSH_TIMEOUT <= CHECK_BUDGET);
        assert!(
            2 * max_interval + 2 * CHECK_BUDGET <= packetframe_common::fib::STEER_MAX_REPORT_AGE
        );
    }
}
