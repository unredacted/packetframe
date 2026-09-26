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
    classify_eligibility, mirror_family_mismatch, next_check_delay, observation,
    parse_established_epoch, parse_export_policy, parse_total_prefixes, parse_upstream_state,
    split_two_json, Eligibility, ExportPolicy, UpstreamState,
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
/// Why not longer: `FRR_INTERVAL_SECS`'s ceiling assumes a check fits in
/// half of a 300 s interval, and a check is the counts, then one call
/// per upstream, then the running-config — sequentially. At 30 s, one
/// upstream's check is at most 90 s and two upstreams' 120 s.
pub const VTYSH_TIMEOUT: Duration = Duration::from_secs(30);

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
            .vtysh
            .run(&[format!("show bgp {} unicast statistics json", family.afi())])
            .await
            .map_err(|e| format!("vtysh statistics {}: {e}", family.afi()))?;
        Ok(parse_total_prefixes(&out, family)? as usize)
    }

    /// Read everything eligibility depends on, then judge it.
    ///
    /// The judging is [`classify_eligibility`], deliberately: the
    /// precedence between "disqualified", "could not read" and "fine" is
    /// the safety argument of this whole authority, and it belongs
    /// somewhere its tests do not need a NIC, a live FRR and a qemu job.
    /// This half is the subprocess calls and nothing else.
    ///
    /// **Upstreams first, running-config last.** The End-of-RIB read is
    /// the one with a timing relationship to the counts just taken: EoR
    /// landing between a mid-fill count that agrees with an equally
    /// partial mirror and the read that sees it would pair the two into
    /// a clean check, so the gap between them should be as short as the
    /// reads allow. The running-config is the slowest read on a loaded
    /// box, has no such relationship, and used to sit in that gap — which
    /// a longer [`VTYSH_TIMEOUT`] would have widened threefold.
    /// [`classify_eligibility`] does not care which answer came first.
    async fn eligibility(&mut self) -> Eligibility {
        let mut upstreams = Vec::with_capacity(self.config.upstreams.len());
        for u in self.config.upstreams.clone() {
            let state = self.upstream(&u).await;
            upstreams.push((u.addr, state));
        }
        let export = self.export_policy().await;
        classify_eligibility(export, &upstreams, &mut self.seen_epochs)
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
            .vtysh
            .run(&[
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
            .vtysh
            .run(&["show running-config".to_string()])
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
                    let state = if self.upstream_down.load(Ordering::SeqCst) {
                        "Active"
                    } else {
                        "Established"
                    };
                    return Ok(format!(
                        r#"{{"192.0.2.1":{{"bgpState":"{state}","gracefulRestartInfo":{{"ipv4Unicast":{{"endOfRibStatus":{{"endOfRibRecv":true}}}}}}}}}}{{"peers":{{"192.0.2.1":{{"peerUptimeEstablishedEpoch":1790000000}}}}}}"#
                    ));
                }
                if first == "show running-config" {
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

    /// The End-of-RIB read follows the counts directly; the slow
    /// running-config read goes last instead of sitting between them.
    #[tokio::test]
    async fn upstream_readiness_is_read_before_the_running_config() {
        let vtysh = Arc::new(Scripted::default());
        let (mut checker, _handle, _snapshot) = checker_with_handle(vtysh.clone());
        checker.run_check().await;

        let calls = vtysh.calls.lock().expect("calls").clone();
        let at = |prefix: &str| {
            calls
                .iter()
                .position(|c| c.starts_with(prefix))
                .unwrap_or_else(|| panic!("no `{prefix}` call in {calls:?}"))
        };
        assert!(at("show bgp ipv4 unicast statistics") < at("show bgp neighbor"));
        assert!(
            at("show bgp neighbor") < at("show running-config"),
            "readiness must not wait behind the running-config: {calls:?}"
        );
    }
}
