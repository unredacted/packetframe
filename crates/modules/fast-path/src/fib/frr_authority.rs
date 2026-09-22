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
use packetframe_common::fib::TableCompleteness;
use packetframe_common::frr::{RealVtysh, Vtysh};

use crate::fib::frr::{
    classify_eligibility, mirror_family_mismatch, observation, parse_established_epoch,
    parse_export_policy, parse_total_prefixes, parse_upstream_state, split_two_json, Eligibility,
    ExportPolicy, UpstreamState,
};
use crate::fib::integrity::{Comparison, Drift, SharedSnapshot, DEFAULT_DRIFT_WARN_FRACTION};
use crate::fib::programmer::FibProgrammerHandle;

/// Subprocess budget for one `vtysh` call.
///
/// Matches `BIRDC_TIMEOUT` and for the same reason: it is a ceiling that
/// catches a genuine hang, not a latency target. `show running-config`
/// is the slowest of the four and returns well inside a second on the
/// reference fleet.
pub const VTYSH_TIMEOUT: Duration = Duration::from_secs(10);

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
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("FrrAuthorityChecker shutdown");
                    return;
                }
                _ = tokio::time::sleep(self.config.interval) => {
                    self.run_check().await;
                }
            }
        }
    }

    async fn run_check(&mut self) {
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
        if let Some((v4, v6)) = mirror.as_ref().ok().copied() {
            if let Some(r) = mirror_family_mismatch(v4, v6, &self.config.counted_families()) {
                if !matches!(eligibility, Eligibility::Revoked(_)) {
                    eligibility = Eligibility::Revoked(r);
                }
            }
        }

        let fresh_authority = authority.as_ref().ok().copied();
        let fresh_mirror = mirror.as_ref().ok().map(|(v4, v6)| v4 + v6);

        let mut snap = self.snapshot.write().await;
        snap.last_run = Some(at);
        snap.last_error = None;
        snap.authority = Some("FRR");
        // The disqualification, on the snapshot as its own fact.
        //
        // It is NOT an error — nothing failed to be read, and the remedy
        // is in the operator's BGP configuration. But without it a tick
        // whose counts agreed recorded a clean comparison and no error,
        // so `fib-integrity` reported a converged authority while
        // `TableCompleteness` held `Ineligible` and the second tier
        // refused every steer, with the concrete reason nowhere on the
        // box (review finding, PR #232). Cleared on every run that is
        // not revoked, so it always describes THIS tick.
        snap.revoked = match &eligibility {
            Eligibility::Revoked(r) => Some(r.clone()),
            Eligibility::Ok | Eligibility::Unknown(_) => None,
        };
        // Transitions only. Entering a revocation, or the reason
        // changing under it, is what an operator needs in the journal;
        // the steady state is what `packetframe status` is for.
        let now_reason = snap.revoked.as_ref().map(|r| r.describe().to_string());
        match (&now_reason, &self.announced_revocation) {
            (Some(now), prev) if prev.as_deref() != Some(now.as_str()) => {
                warn!(
                    reason = %now,
                    "completeness authority: mirror DISQUALIFIED — steering refused until a \
                     check comes back clean AND the counts agree"
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

        let Some(handle) = self.completeness.as_ref() else {
            return;
        };
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
        handle.record(observation(&eligibility, fresh_authority, fresh_mirror, at));
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
    async fn eligibility(&mut self) -> Eligibility {
        let export = self.export_policy().await;
        let mut upstreams = Vec::with_capacity(self.config.upstreams.len());
        for u in self.config.upstreams.clone() {
            let state = self.upstream(&u).await;
            upstreams.push((u.addr, state));
        }
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
        Ok(parse_export_policy(&out, &self.config.pf_peer.to_string()))
    }
}
