//! Health, status and metrics: what an operator sees.
//!
//! The one principle everything here follows: **overall health tracks
//! whether packets are being forwarded correctly, not whether the
//! offload is working.** The eBPF fast-path on the PFs is a permanent
//! failover tier, not a bootstrap crutch — so a dead, unsteered VPP is a
//! degradation (the box forwards, just slower), while a *steered* VPP
//! that cannot forward is the worst state in the system. Reporting a
//! crash-looping-but-unsteered VPP as `Unhealthy` would page someone at
//! 03:00 for a box that is serving traffic correctly, and that is how
//! alerts get muted.
//!
//! The same principle will set the ceiling on the metrics path when it
//! lands: a stats segment we cannot read must degrade *metrics*, never
//! forwarding, which means it needs a subsystem of its own rather than a
//! contribution to any dataplane one. See the note at the bottom on why
//! it is not here yet.
//!
//! ## Nothing here derives an observation from an intention
//!
//! Slices 3 and 4 spent ~31 review findings on one defect shape: state
//! recorded when an effect was *requested* rather than *observed*. A
//! health surface is the most tempting place in the module to repeat it,
//! because every input is a `bool` and a plausible-looking one is always
//! within reach. Two structural defences:
//!
//! - [`StatusSnapshot`] has **no `Default`**. A defaulted health
//!   snapshot reads as healthy, so a field added later would silently
//!   report "fine" at every call site that had not been updated. Adding
//!   a field must break the build instead.
//! - The four fields most likely to be filled from intent — lifecycle
//!   state, steering, undead, failure count — are not parameters of
//!   [`StatusSnapshot::observe`]. They are read out of the
//!   [`Supervisor`], which is the only thing that knows them.
//!
//! What is *not* here: stats-segment gauges. The plan assigns VPP's
//! statseg to metrics-only, but reading it needs a shared-memory parser
//! that does not exist yet. A placeholder field reporting "unavailable"
//! forever would be a shim for a hypothetical state, so the segment is
//! simply absent until something can read it.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use packetframe_common::module::{HealthReport, HealthState, SubsystemHealth};

use crate::liveness::WedgeDetector;
use crate::sink::{PendingMap, SinkCounts};
use crate::supervisor::{State, Supervisor};
use crate::verify::VerifyOutcome;

/// Stable subsystem names. Append-safe, rename-unsafe: operator
/// dashboards and `packetframe status` key on these strings, exactly as
/// the `stats` counter indices are append-only once shipped.
pub const SUBSYS_PROCESS: &str = "vpp-process";
pub const SUBSYS_API: &str = "api-ping";
pub const SUBSYS_FIB: &str = "fib-synced";
pub const SUBSYS_STEERING: &str = "steering";
pub const SUBSYS_PORTS: &str = "ports";
/// Reported only when a persist failed; see
/// [`StatusSnapshot::store_error`].
pub const SUBSYS_STATE_FILE: &str = "state-file";
/// Subsystem name for the cross-tier route feed.
pub const SUBSYS_ROUTE_FEED: &str = "route-feed";

/// Liveness of the binary API, as observed from ping/pong timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiHealth {
    /// No supervised process, so there is nothing to ping. Distinct from
    /// silence: an absent process is the `vpp-process` subsystem's story
    /// to tell, and duplicating it as an API fault would double-report
    /// one failure.
    NoProcess,
    /// A process exists but the API has not answered yet. Bounded by
    /// `API_STARTUP_BUDGET`, not by the ping budget — VPP takes real
    /// time to open its socket, and counting that as silence would
    /// declare a wedge before it could possibly reply.
    Starting,
    /// Answering. `silent_for` is the age of the last pong, which is a
    /// genuine freshness signal even while healthy.
    Answering { silent_for: Duration },
    /// Silent past its budget. Carries the budget that was in force,
    /// because which one applies (steady-state 1.5 s vs resync 10 s) is
    /// the single most confusing thing about this detector in a log.
    Silent {
        silent_for: Duration,
        budget: Duration,
    },
}

impl ApiHealth {
    /// Derive from the detector the driver holds. `det` is `None`
    /// exactly when the API has not answered since this process
    /// started — the detector is created on `ApiUp`, not on spawn.
    pub fn observe(
        state: State,
        det: Option<&WedgeDetector>,
        now: Instant,
        budget: Duration,
    ) -> Self {
        if !state.has_process() {
            return Self::NoProcess;
        }
        match det {
            None => Self::Starting,
            Some(d) => {
                let silent_for = d.silent_for(now);
                if d.is_wedged(now, budget) {
                    Self::Silent { silent_for, budget }
                } else {
                    Self::Answering { silent_for }
                }
            }
        }
    }

    fn state(self) -> HealthState {
        match self {
            // Not this subsystem's failure to report.
            Self::NoProcess => HealthState::Healthy,
            Self::Starting => HealthState::Degraded,
            Self::Answering { .. } => HealthState::Healthy,
            Self::Silent { .. } => HealthState::Unhealthy,
        }
    }

    fn message(self) -> Option<String> {
        match self {
            Self::NoProcess => Some("no process to ping".into()),
            Self::Starting => Some("waiting for the API to open".into()),
            Self::Answering { .. } => None,
            Self::Silent { silent_for, budget } => Some(format!(
                "silent {:.1}s, past the {:.1}s budget — wedged",
                silent_for.as_secs_f64(),
                budget.as_secs_f64()
            )),
        }
    }

    /// Age of the last successful round trip, where that notion applies.
    fn last_success_age(self) -> Option<u64> {
        match self {
            Self::Answering { silent_for } | Self::Silent { silent_for, .. } => {
                Some(silent_for.as_secs())
            }
            Self::NoProcess | Self::Starting => None,
        }
    }
}

/// Whether VPP's FIB is known to mirror the route source.
///
/// "Known" is load-bearing. This reports the last **completed readback
/// verification**, never the fact that a resync finished — a drained
/// pending map means we sent everything, which is exactly the kind of
/// requested-not-observed claim that has bitten this module repeatedly.
///
/// **Verification is a convergence-time gate, not a heartbeat**, and the
/// `age` here is how an operator sees that. It runs on first attach and
/// after every resync, and then not again: a periodic verify would have
/// to sample the ledger and probe VPP while deltas are in flight, and a
/// withdrawal landing between sample and probe reads as a mismatch —
/// which is why `drain_batch` is excluded during `Verifying` in the
/// first place. Steady-state divergence is meant to surface as drain
/// errors and a rising outstanding count instead.
///
/// The consequence is real and worth knowing before reading a
/// dashboard: on a long-lived steered daemon this can legitimately say
/// `last ok 18966s ago` (measured, 2026-08-06), and nothing would notice
/// VPP's FIB drifting for a reason other than our own deltas. Making it
/// a heartbeat is a design change, not a tweak — it needs an answer for
/// the in-flight-delta race first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FibSync {
    /// No verify has completed for the current process.
    NeverVerified,
    Verified {
        /// How long ago the passing verify finished.
        age: Duration,
        sampled: usize,
    },
    Failed {
        age: Duration,
        summary: String,
    },
}

impl FibSync {
    /// Build from a verify pass and how long ago it completed.
    /// [`VerifyOutcome::passed`] decides pass/fail — this must not
    /// re-derive the criteria, or the gate that governs steering and the
    /// gate that reports health could disagree.
    pub fn from_outcome(outcome: &VerifyOutcome, age: Duration) -> Self {
        if outcome.passed() {
            Self::Verified {
                age,
                sampled: outcome.sampled,
            }
        } else {
            Self::Failed {
                age,
                summary: outcome.summary(),
            }
        }
    }

    fn verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    fn last_success_age(&self) -> Option<u64> {
        match self {
            Self::Verified { age, .. } => Some(age.as_secs()),
            // A failed verify is not a success, and reporting its age
            // here would read as freshness on a dashboard.
            Self::NeverVerified | Self::Failed { .. } => None,
        }
    }
}

/// One member port's forwarding fitness inside VPP, from the same
/// `sw_interface_dump` the verify pass reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortLink {
    pub port: String,
    pub sw_if_index: u32,
    pub admin_up: bool,
    pub link_up: bool,
}

impl PortLink {
    fn forwards(&self) -> bool {
        self.admin_up && self.link_up
    }
}

/// Everything the health and metrics surfaces report on, observed once
/// so both agree. **Deliberately not `Default`** — see the module docs.
#[derive(Debug, Clone)]
pub struct StatusSnapshot {
    pub state: State,
    pub steered: bool,
    /// Steering is *meant* to be up but is not. Distinguishes a failed
    /// or lost steer from the deliberate all-members-steer-off staging
    /// state, which is the designed rollback landing zone rather than a
    /// fault.
    pub steer_intended: bool,
    /// The config asks at least one port to steer.
    ///
    /// Separate from `steer_intended`, which is the supervisor's belief
    /// about whether traffic is or should be diverted *right now*. The
    /// machine never steers a first attach on its own — when traffic
    /// moves is an operator decision, paced by hand up the canary ladder
    /// — so a port configured `steer on` that has never steered sits in
    /// the designed staging state. Without this the surface reported the
    /// identical line for that and for `steer off`, and an operator who
    /// had just written `steer on` could not tell the config had been
    /// read at all.
    pub steer_configured: bool,
    /// Rules the ledger names that the NIC no longer holds. See
    /// [`crate::runtime::RuntimeStatus::steer_missing`].
    pub steer_missing: usize,
    /// Rules still steering a port the config leaves unsteered. See
    /// [`crate::runtime::SteeringAudit::stray`]. Its own count because
    /// it points the other way: `steer_missing` says install, this says
    /// remove.
    pub steer_stray: usize,
    /// Why the last steering audit could not read the NIC, if so. See
    /// [`crate::runtime::RuntimeStatus::steer_audit_error`].
    pub steer_audit_unreadable: Option<String>,
    pub undead: bool,
    pub failures: u32,
    pub counts: SinkCounts,
    /// Ops the sink still owes VPP. Bounded by table size, so a large
    /// value during convergence is normal and a large value at rest is
    /// not.
    pub pending_ops: u64,
    /// Ops parked because the table is at its high-water mark.
    pub parked_ops: u64,
    pub api: ApiHealth,
    pub fib: FibSync,
    /// `Some((have, want))` while an adopted resync waits for the route
    /// source to finish loading. See `Runtime`'s deferral: the adopted
    /// FIB is deliberately left forwarding, so this reads as Degraded
    /// with the reason, never as steered-but-broken.
    pub resync_deferred: Option<(u64, u64)>,
    /// See [`crate::runtime::RuntimeStatus::authority`].
    pub authority: crate::runtime::AuthorityPosture,
    pub ports: Vec<PortLink>,
    /// The runtime could not persist something it observed.
    ///
    /// Part of the **snapshot**, not something a caller layers on top of
    /// the report afterwards. It was that at first, in the supervision
    /// service — and the consequence was precise: `report()` was patched
    /// to `Degraded` while [`render_metrics`] rendered its health gauge
    /// from the unpatched snapshot, so `packetframe_vpp_health` went on
    /// reporting `healthy` during exactly the persistence failure the
    /// patch existed to surface. Two surfaces, one condition, one place
    /// to encode it.
    pub store_error: Option<String>,
    /// Why the last drain failed, or `None` if the last one succeeded.
    ///
    /// Its own field rather than folded into `api_error`, because the
    /// two fail differently and only one of them is silent. An API error
    /// already shows up as a ping failure and eventually a wedge; a drain
    /// failure in steady state is deliberately *not* escalated — the
    /// batch is retried — so without this the module would degrade with
    /// nothing saying why.
    pub drain_error: Option<String>,
    /// Changes the route source is holding that the engine has not
    /// pulled. Separate from `pending_ops`: a backlog here means the
    /// engine is not draining, a backlog there means VPP is not
    /// accepting.
    pub source_backlog: u64,
}

/// The steering audit, as the health surface consumes it.
///
/// One parameter rather than three, because two of them are `usize`
/// that point OPPOSITE ways — install versus remove — and adjacent
/// positional counts of the same type are a transposition nothing would
/// catch.
#[derive(Debug, Default, Clone)]
pub struct SteerAudit {
    pub missing: usize,
    pub stray: usize,
    pub unreadable: Option<String>,
}

impl StatusSnapshot {
    /// Observe live state.
    ///
    /// Lifecycle state, steering, undead and the failure count come from
    /// `sup` rather than from parameters, so a caller cannot pass what it
    /// *believes* about them.
    pub fn observe(
        sup: &Supervisor,
        counts: SinkCounts,
        pending: &PendingMap,
        api: ApiHealth,
        fib: FibSync,
        ports: Vec<PortLink>,
        steer_configured: bool,
    ) -> Self {
        Self::observe_parts(
            sup,
            counts,
            pending.len() as u64,
            pending.withheld_len() as u64,
            api,
            fib,
            None,
            // No deferral in this shorthand, so the posture is unread;
            // Absent is the honest default rather than a claim.
            crate::runtime::AuthorityPosture::Absent,
            ports,
            None,
            None,
            0,
            steer_configured,
            // The shorthand has no NIC audit behind it; claiming zero
            // drift would be a claim. Zero here means "not observed",
            // and every caller of this form is a path with no steering
            // ledger to audit against.
            SteerAudit::default(),
        )
    }

    /// Same observation, from already-extracted pending counts — for
    /// the supervision service, which reads them out of the runtime's
    /// [`crate::runtime::RuntimeStatus`] rather than holding the
    /// `PendingMap` itself. Every supervisor-derived field still comes
    /// from `sup`, never from a caller's belief.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_parts(
        sup: &Supervisor,
        counts: SinkCounts,
        pending_ops: u64,
        parked_ops: u64,
        api: ApiHealth,
        fib: FibSync,
        resync_deferred: Option<(u64, u64)>,
        authority: crate::runtime::AuthorityPosture,
        ports: Vec<PortLink>,
        store_error: Option<String>,
        drain_error: Option<String>,
        source_backlog: u64,
        steer_configured: bool,
        audit: SteerAudit,
    ) -> Self {
        Self {
            state: sup.state(),
            steered: sup.is_steered(),
            steer_intended: sup.steer_intended(),
            steer_configured,
            steer_missing: audit.missing,
            steer_stray: audit.stray,
            steer_audit_unreadable: audit.unreadable,
            undead: sup.is_undead(),
            failures: sup.failures(),
            counts,
            pending_ops,
            parked_ops,
            api,
            fib,
            resync_deferred,
            authority,
            ports,
            store_error,
            drain_error,
            source_backlog,
        }
    }

    /// Ports that cannot forward.
    fn dead_ports(&self) -> Vec<&PortLink> {
        self.ports.iter().filter(|p| !p.forwards()).collect()
    }

    /// Whether traffic is diverted into a VPP that cannot forward it
    /// correctly. The worst condition the module can be in, and the
    /// reason `overall` is not simply the max of the subsystems.
    ///
    /// Every arm is a live blackhole: no process behind the MCAM rules,
    /// a wedged one, a FIB never verified or known wrong, or a port
    /// whose link is down under paths that resolve through it.
    fn steered_but_broken(&self) -> bool {
        // A deferred adopted resync is steered with `fib` unverified BY
        // THIS DAEMON — deliberately: the table it forwards with was
        // verified by the previous daemon, and preserving it untouched is
        // the protection. Counting that as "steered but broken" would
        // report the safeguard as the module's worst fault for as long
        // as bird takes to reload.
        let fib_unverified = !self.fib.verified() && self.resync_deferred.is_none();
        self.steered
            && (!self.state.has_process()
                || matches!(self.api, ApiHealth::Silent { .. })
                || fib_unverified
                || !self.dead_ports().is_empty())
    }

    /// Structured report for `packetframe status`, circuit breakers and
    /// the Prometheus surface.
    pub fn report(&self) -> HealthReport {
        let mut subsystems = vec![
            self.process_health(),
            self.api_health(),
            self.fib_health(),
            self.steering_health(),
            self.ports_health(),
        ];
        // Only present when the runtime actually failed to persist
        // something, so the subsystem list does not carry a permanent
        // "state-file: fine" row nobody reads.
        // Same shape and the same reason as the state-file row below:
        // present only when it actually failed, so there is no permanent
        // "route-feed: fine" line for an operator to learn to ignore.
        if let Some(e) = &self.drain_error {
            subsystems.push(SubsystemHealth {
                name: SUBSYS_ROUTE_FEED.into(),
                state: HealthState::Degraded,
                message: Some(format!(
                    "could not apply route updates to VPP ({e}); {} change(s) waiting at the \
                     source and {} queued for VPP. Retried every tick — the offload is forwarding \
                     a table that is behind bird, not a wrong one.",
                    self.source_backlog, self.pending_ops
                )),
                last_success_age_seconds: None,
            });
        }
        if let Some(e) = &self.store_error {
            subsystems.push(SubsystemHealth {
                name: SUBSYS_STATE_FILE.into(),
                state: HealthState::Degraded,
                message: Some(format!(
                    "could not persist observed state ({e}); a daemon restart will refuse \
                     adoption and cycle VPP instead"
                )),
                last_success_age_seconds: None,
            });
        }
        HealthReport {
            overall: self.overall(),
            subsystems,
        }
    }

    /// Overall state.
    ///
    /// **Not** the max of the subsystems, deliberately. A dead VPP is an
    /// `Unhealthy` *process* and simultaneously a correctly-forwarding
    /// *box*, because the eBPF tier has the traffic — so the maximum
    /// would report an outage that is not happening, on the module whose
    /// entire design premise is that its failure is survivable. What
    /// escalates to `Unhealthy` is either traffic diverted into
    /// something that cannot forward it, or a state that blocks recovery.
    fn overall(&self) -> HealthState {
        // Undead first: a process that survived SIGKILL may still be
        // DMAing through a VF we cannot release and blocks any restart.
        // Nothing recovers on its own from here.
        if self.undead {
            return HealthState::Unhealthy;
        }
        if self.steered_but_broken() {
            return HealthState::Unhealthy;
        }
        // Everything else is Degraded unless it is *positively* nominal.
        if self.nominal() {
            HealthState::Healthy
        } else {
            HealthState::Degraded
        }
    }

    /// The narrow set of conditions under which this module is doing its
    /// job. Stated as a whitelist on purpose.
    ///
    /// The first cut of `overall` enumerated the ways things go wrong and
    /// fell through to `Healthy`, which meant every condition nobody had
    /// thought of read as fine. Concretely: a first start sitting in
    /// `Starting`, `Syncing` or `Verifying` has a live process, no
    /// failures, an empty port list and clean route counts — so it
    /// reported `Healthy` while the API was still opening and the FIB had
    /// never been verified, and it *disagreed with its own subsystems*,
    /// which were reporting `Degraded` for exactly those reasons.
    ///
    /// Inverting it makes the default safe: a lifecycle state, port
    /// condition or ledger state that nothing here anticipates lands in
    /// `Degraded`, which is an honest "this module is impaired" rather
    /// than a false all-clear. Same discipline as [`StatusSnapshot`]
    /// having no `Default`.
    ///
    /// Note `Ready` counts as arrived: it is the deliberate
    /// all-members-verified-nothing-steered staging state, which is a
    /// designed resting place rather than an impairment. Every state
    /// short of it — including the whole of a first convergence — is a
    /// module that is not yet forwarding anything, and says so.
    fn nominal(&self) -> bool {
        // Arrived: verified and either steered or deliberately staged.
        matches!(self.state, State::Ready | State::Steered)
            && self.fib.verified()
            && matches!(self.api, ApiHealth::Answering { .. })
            && self.failures == 0
            // A complete table. Withheld and unresolvable are real
            // degradation even when everything else is clean.
            && !self.counts.degraded()
            // Membership is all-or-nothing, so "no ports" is not a
            // vacuous pass — it means nothing was ever attached.
            && !self.ports.is_empty()
            && self.dead_ports().is_empty()
            // Steering wanted but absent: a broken rollout, not staging.
            && (self.steered || !self.steer_intended)
            // Convergence is fine and the interfaces work, but the next
            // daemon restart will refuse adoption and cycle a VPP that
            // was forwarding. Nominal has to mean "and it will survive a
            // restart", or the whitelist quietly stops covering the one
            // failure whose consequence is deferred.
            && self.store_error.is_none()
            // A drain that is failing means VPP's FIB is drifting away
            // from bird's with every update it misses. Nothing restarts
            // over it by design, which is exactly why it must not read as
            // nominal.
            && self.drain_error.is_none()
    }

    fn process_health(&self) -> SubsystemHealth {
        let (state, message) = if self.undead {
            (
                HealthState::Unhealthy,
                Some(
                    "survived SIGKILL — VFs and hugepages cannot be released, restart blocked"
                        .into(),
                ),
            )
        } else {
            match self.state {
                State::Stopped => (HealthState::Degraded, Some("stopped".into())),
                State::Backoff => (
                    HealthState::Degraded,
                    Some(format!("restarting after {} failure(s)", self.failures)),
                ),
                State::Starting => (HealthState::Degraded, Some("starting".into())),
                s => {
                    let msg = (self.failures > 0).then(|| {
                        format!("running; {} failure(s) since last healthy", self.failures)
                    });
                    // A running process with a clean history is the only
                    // healthy case; everything else says why.
                    let st = if self.failures > 0 {
                        HealthState::Degraded
                    } else {
                        HealthState::Healthy
                    };
                    let _ = s;
                    (st, msg)
                }
            }
        };
        SubsystemHealth {
            name: SUBSYS_PROCESS.into(),
            state,
            message,
            // "Last successful operation" has no meaning for a process
            // that is either running or not; inventing one would put a
            // number on a dashboard that nothing can act on.
            last_success_age_seconds: None,
        }
    }

    fn api_health(&self) -> SubsystemHealth {
        SubsystemHealth {
            name: SUBSYS_API.into(),
            state: self.api.state(),
            message: self.api.message(),
            last_success_age_seconds: self.api.last_success_age(),
        }
    }

    fn fib_health(&self) -> SubsystemHealth {
        let (state, message) = match &self.fib {
            // Checked before the steered arm below, deliberately: a
            // deferred adopted resync IS steered — the whole point of the
            // deferral is leaving a forwarding VPP alone — and the
            // steered arm's "traffic steered into an unverified FIB"
            // would report the designed protection as the worst fault
            // the module has. The FIB in question was verified by the
            // previous daemon and is being deliberately preserved; what
            // the operator needs is the reason convergence has not
            // started, not an alarm that invites them to restart it.
            FibSync::NeverVerified if self.resync_deferred.is_some() => {
                let (have, want) = self.resync_deferred.expect("checked above");
                // Two phases, two messages: below the floor the source
                // is plainly still loading; at or above it the gate is
                // waiting for the growth to stop, because a loading
                // feed passes through every count on its way to full
                // and only quiescence says "done".
                use crate::runtime::AuthorityPosture;
                // ORDER MATTERS, and every arm names its posture. The
                // veto arm goes FIRST because it is the one case where
                // the floor is irrelevant — the authority blocks release
                // at any table size — and when it sat after the
                // unconditional below-floor arm, a vetoing box below the
                // floor was told it had "no authority" and should enable
                // `require-table-complete`, which was already enabled and
                // was the thing blocking it (review finding).
                let msg = if self.authority == AuthorityPosture::Vetoing {
                    // Persistent by construction: `Vetoing` is only
                    // `AuthorityMismatch`, the one verdict waiting cannot
                    // fix.
                    format!(
                        "resync deferred: the route source holds {have} routes (release \
                         floor {want}) and the floor is not what is holding this — the \
                         completeness authority reports a route count that cannot describe \
                         this mirror (far fewer than it holds, or none at all), so it is \
                         not the authority feeding it, and that vetoes release at any \
                         table size, so waiting for the source to go quiet will not clear \
                         it — quiescence is never what releases a veto. CONFIRM BEFORE \
                         ACTING: the checker reads bird and the mirror a few subprocess \
                         calls apart, so one report can catch a bulk withdrawal mid-flight \
                         and show a mismatch the next check does not. If the next check \
                         (within 300 s) still reports one, it is real. Then: check which \
                         bird `birdc` is talking to on THIS box; where the routes \
                         legitimately come from elsewhere, `require-table-complete off` is \
                         the right answer — but it is read at bring-up, so it needs a \
                         daemon RESTART, and a reload will not do it (from here a reload \
                         is refused outright). The adopted FIB keeps forwarding untouched \
                         meanwhile, and every steering change is refused while this holds"
                    )
                } else if self.authority == AuthorityPosture::AwaitingAuthority {
                    // Blocked, but self-clearing: no report yet, one that
                    // aged out, or a mirror still short. Deliberately
                    // does NOT tell the operator to go looking — the next
                    // check releases it, and sending someone after a
                    // startup transient is how a healthy box gets
                    // "fixed" into a broken one.
                    format!(
                        "resync deferred: the completeness authority has not attested yet \
                         — no report has arrived, the last one aged out, the mirror is \
                         still short of it, or the mirror has grown past the count the \
                         last sample took (the checker measures both every 300 s, and a \
                         loading DFZ moves further than that in between) — so release is \
                         blocked for now. It releases itself once a sample agrees; the \
                         source holds {have} routes against a floor of {want}. If the \
                         authority really is behind rather than merely unasked, the next \
                         sample says so and this line changes to name it. Nothing is \
                         dropping: the adopted FIB keeps forwarding untouched"
                    )
                } else if have < want && self.authority == AuthorityPosture::Attesting {
                    format!(
                        "resync deferred: the route source holds {have} routes, below the \
                         release floor of {want}; the adopted FIB keeps forwarding \
                         untouched. The completeness authority can release this once its \
                         report agrees with the mirror — expected within one integrity \
                         interval (300 s). If it persists well beyond that, check the \
                         integrity checker and bird rather than the sizing"
                    )
                } else if have < want && self.authority == AuthorityPosture::DemotedByFlap {
                    format!(
                        "resync deferred: the route source holds {have} routes, below the \
                         release floor of {want}; the adopted FIB keeps forwarding \
                         untouched. The feed session reconnected under this deferral, so \
                         the authority's report can no longer attest that the mirror is \
                         THIS session's — a count can match while a reannouncement is \
                         still mid-flight. Attestation returns when the source reports \
                         its initiation-complete GC, which needs 5 s without updates: on \
                         a continuously active DFZ feed that gap may never arrive, and \
                         this deferral can hold indefinitely BY DESIGN. Nothing is \
                         dropping — VPP forwards the FIB it was adopted with. To resolve \
                         it, let the feed idle briefly, or restart the daemon once the \
                         table is loaded so the adoption starts unsteered"
                    )
                } else if have < want {
                    // Reachable only with NO authority now: every other
                    // posture is claimed by an arm above, which is what
                    // makes this text's "with no authority" accurate
                    // rather than an assumption.
                    format!(
                        "resync deferred: the route source holds {have} routes, below the \
                         release floor of {want}; the adopted FIB keeps forwarding \
                         untouched. If the source is still loading this clears itself — \
                         but if {have} IS the whole table, the gate will never release: \
                         with no authority it refuses to guess completeness below the \
                         floor, by design. Size `expected-routes` within 16x of the real \
                         table, or give this box a bird and enable \
                         `require-table-complete`"
                    )
                } else {
                    format!(
                        "resync deferred: the route source holds {have} routes (release \
                         floor {want} met); the diff runs once the source is live and has \
                         gone quiet, and the adopted FIB keeps forwarding untouched until \
                         then"
                    )
                };
                (HealthState::Degraded, Some(msg))
            }
            FibSync::NeverVerified if self.steered => (
                HealthState::Unhealthy,
                Some("traffic steered into an unverified FIB".into()),
            ),
            FibSync::NeverVerified => (HealthState::Degraded, Some("not yet verified".into())),
            FibSync::Failed { summary, .. } => (HealthState::Unhealthy, Some(summary.clone())),
            FibSync::Verified { sampled, .. } => {
                let c = self.counts;
                if c.degraded() {
                    // Both counts, always, and named: "table outgrew the
                    // box" and "nexthop mapping is wrong" are different
                    // pages, and collapsing them hides whichever is
                    // rarer.
                    (
                        HealthState::Degraded,
                        Some(format!(
                            "verified on {sampled} probes; {} withheld (at capacity), \
                             {} unresolvable (mapping)",
                            c.withheld, c.unresolvable
                        )),
                    )
                } else {
                    // "verified AT" rather than "verified", because
                    // nothing re-runs verification in steady state and
                    // this line is read hours later. See `FibSync`.
                    (
                        HealthState::Healthy,
                        Some(format!(
                            "{} routes installed; last verified on {sampled} probes",
                            c.installed
                        )),
                    )
                }
            }
        };
        SubsystemHealth {
            name: SUBSYS_FIB.into(),
            state,
            message,
            last_success_age_seconds: self.fib.last_success_age(),
        }
    }

    fn steering_health(&self) -> SubsystemHealth {
        // Checked before the steered arm: "steered" is a fact about
        // what we asked for, and this is a fact about what the NIC
        // actually holds. A provisioning push can strip rules with
        // nothing else noticing — measured on the shadow 2026-08-11,
        // still missing two minutes later with `steering healthy` —
        // and the answer an operator needs is not "steered" but "part
        // of it is gone, and here is the one command that fixes it".
        //
        // DEGRADED, not Unhealthy: the stripped traffic falls back to
        // the eBPF tier, which is where it belongs. Nothing is
        // dropping; the offload is smaller than it claims.
        //
        // A NIC that will not answer is not healthy either, and the two
        // facts are INDEPENDENT: `Runtime::status` retains the last count
        // when a readback fails, so a nonzero count and an unreadable
        // audit can both hold. Ordering them could not fix that —
        // whichever arm ran first hid the other, and the first version
        // published the retained count as though it were current while
        // further drift had become invisible (review finding). So one
        // arm, and the message carries whichever facts are true.
        //
        // Three facts now, composed rather than matched. The third
        // points the OTHER way: rules still steering a port the config
        // asks to leave unsteered. It is named first when present,
        // because that is the rollback lever failing — an operator
        // pulling traffic OFF a port is the one case where "steering
        // healthy" is the most expensive possible answer (review
        // finding).
        //
        // The remedy depends on the lifecycle state, and saying so is
        // the point. `packetframe reconfigure` reconciles steering only
        // from a state that accepts steering changes; during an adopted
        // resync it is refused. That is not a corner — a held deferral
        // is the state this audit was written for, and on a box with no
        // completeness authority it can hold indefinitely, so the line
        // shipped promising a command that answers "not converged" in
        // exactly the case it appears most (measured on the shadow,
        // 2026-08-11). The repair does arrive on its own: the verify
        // that ends the resync re-emits the steer, and `steer` is a
        // reconcile.
        // Four answers, because there are four situations and giving
        // the wrong one sends an operator somewhere useless.
        // No shared cleanup string: the two arms below differ in
        // whether the daemon is still running, and that is exactly what
        // decides which command works. `loader::detach` refuses outright
        // while a `packetframe run` pid exists — the daemon holds the
        // bpf_link FDs — so telling a live module to run it is a second
        // refusal (review finding). Factoring these together was a DRY
        // move that erased the distinguishing fact.
        let remedy = if self.state.accepts_steering_changes() {
            // NAMES the repair; does not promise it will succeed. The
            // state gate this arm reads is not the only one — the steer
            // path refuses again if the table is not complete enough to
            // steer into — and predicting a command's outcome by
            // re-deriving its preconditions here is a copy that drifts.
            // It found a new precondition on each of four review rounds.
            // What is always true, and all an operator needs: this is
            // the command, and it reports its own reason when it
            // refuses (review finding).
            "`packetframe reconfigure` re-applies steering, and reports its own reason if \
             it refuses — a table too incomplete to steer into is the usual one"
                .to_string()
        } else if matches!(self.state, State::Stopped) {
            // Nothing is running and nothing is trying to. Reachable and
            // nasty: `StopRequested` assigns `Stopped` before knowing
            // whether `Unsteer` succeeded, a refused removal keeps the
            // rules in the ledger, and the final status is published
            // either way — so this is precisely the snapshot reporting
            // rules that still divert traffic into a VF whose VPP has
            // just been killed (review finding).
            "supervision has stopped, so nothing will reconcile this on its own: with the \
             daemon exited, `packetframe detach --all` retries the teardown, and `ethtool \
             -N <iface> delete <loc>` removes a rule by hand"
                .to_string()
        } else if !self.steer_configured {
            // A convergence CAN clear these now, and for a while none
            // could. `VerifyPassed` re-steers while `steered ||
            // steer_wanted`, and a refused `unsteer` deliberately keeps
            // `steered` true — so a `steer off` whose removal the NIC
            // declined re-emitted `Action::Steer` on every convergence.
            // `steer` used to refuse an empty target outright, before
            // reaching its stale-rule removal, because `Ok` had no way
            // to say "nothing is steered" and would have become
            // `Event::Steered`. The refusal repeated forever while the
            // rules kept diverting. `SteerOutcome::NothingToSteer` is
            // the vocabulary that was missing.
            //
            // CAN, not will, and the qualifier is the same one the arm
            // below carries: only `VerifyPassed` emits the steer that
            // carries the reconcile. `VerifyIncomplete` parks in `Ready`
            // with no action at all, so a convergence that ends with
            // routes withheld or unresolvable leaves these exactly where
            // they are — and the promise this line made in its first
            // draft was the very thing #157 was written to stop it
            // doing (review finding). The state is not stuck: `Ready`
            // takes the `reconfigure` arm above, and with no port asking
            // to steer that reconcile removes rather than reinstalls.
            //
            // The manual removals stay named anyway. This arm is also
            // reached from `Backoff`, where the next convergence is
            // however long the exponential schedule says, and a stray
            // rule is diverting traffic into a VF whose VPP is not
            // running — that is not something to wait out.
            //
            // Deliberately NOT claiming the steer retry here, though it
            // does cover part of this. From `Ready` with a want still
            // recorded — a death while those rules were installed
            // re-arms one — `Event::SteerUnblocked` reconciles to the
            // empty target within `STEER_RETRY_EVERY` and
            // `NothingToSteer` retires the want. But with no want there
            // is nothing for it to act on, and this line cannot see
            // which case it is in: `steer_intended` is on the snapshot,
            // yet inferring "and therefore the module will fix it" from
            // it is precisely the re-derivation that has made this arm
            // wrong four times. Understating costs an operator one
            // unnecessary `reconfigure`; overstating costs them the
            // rules.
            "no port is configured to steer, so a convergence that verifies without \
             withheld or unresolvable routes reconciles the NIC to an empty target and \
             removes these. One that ends incomplete parks in the staging state and \
             emits no steer at all, so nothing reconciles and this line outlives the \
             convergence — `packetframe reconfigure` is then the retry, and with no port \
             asking to steer it removes the rules rather than reinstalling any. Do not \
             wait for either if VPP is not forwarding: `ethtool -N <iface> delete <loc>` \
             removes a rule now, and `packetframe detach --all` retries the whole \
             teardown once this daemon has exited"
                .to_string()
        } else {
            // A convergence is in flight or is coming (`Backoff` has no
            // resync running yet, which is why this does not say "this
            // resync"), and the target it will reconcile to is non-empty,
            // so its stale-rule removal covers whatever is left over.
            //
            // This arm ends by saying `reconfigure` will NOT help, which
            // is the opposite of what it shipped saying. Every state that
            // reaches it — `Starting`, `Syncing`, `Verifying`,
            // `AdoptedResyncing`, `Backoff` — fails
            // `accepts_steering_changes()`, since the two that pass it
            // took the first arm. So the promise that reconfigure "asks
            // immediately" was wrong on every line it ever printed, not
            // in a corner: measured on the shadow 2026-08-12, where an
            // adopted resync deferred for 23 hours printed it and the
            // reconfigure it named answered "not converged" and changed
            // nothing. The comment at the top of this selection had
            // already written down the rule; the last sentence of this
            // arm broke it, and no test compared the two.
            "a convergence re-applies steering only if it verifies clean — one that ends \
             with routes withheld or unresolvable parks in the staging state and emits no \
             steer at all, and a steer that IS emitted can still be refused by the \
             completeness gate. Both settle in the staging state with the want \
             remembered, and from there the module re-attempts the steer by itself once \
             both gates permit. Until it converges there is nothing to ask: `packetframe \
             reconfigure` answers \"not converged\" from here and changes no steering"
                .to_string()
        };
        // Stray rules do NOT share that remedy, and sharing it was a
        // P1. The two complaints differ in what waiting costs: a
        // MISSING rule means its prefix is on the eBPF tier, which
        // forwards, so waiting out a convergence is free. A STRAY rule
        // is diverting traffic INTO VPP — and `fail()` unsteers before
        // it kills, precisely because "until the MCAM rules are gone,
        // every steered packet is going to a VF nothing is servicing".
        // When that unsteer is refused the rules stay and VPP dies
        // anyway, so in `Backoff` the affected prefixes are being
        // dropped while this line says to wait for a convergence that
        // exponential backoff can push out indefinitely.
        //
        // So it names the removal that works from anywhere, always,
        // and never defers to a convergence.
        let mut clauses: Vec<String> = Vec::new();
        if self.steer_stray > 0 {
            // "Still occupied", not "still ours". Where the outgoing
            // target is known the audit proves ownership field by
            // field; after a restart that dropped the port there is
            // nothing to check against, and claiming the traffic is
            // ours would be the ownership guess this audit keeps
            // getting wrong. `ethtool -n` settles it either way.
            clauses.push(format!(
                "{} location(s) the ledger names are still occupied by rules this config \
                 does not ask for — a port it leaves unsteered, or prefixes dropped from \
                 the allowlist — so traffic may still be diverted into VPP that should \
                 not be. The rules outlived the request to remove them. `packetframe \
                 reconfigure` removes exactly the locations the ledger names, so nothing \
                 has to be identified by eye — but it deletes BY LOCATION, so it can no \
                 more prove they still hold OUR rules than this audit can. Do not wait \
                 for a convergence: while VPP is not forwarding, that traffic is going to \
                 a VF nothing is servicing. Where reconfigure will not run, remove by \
                 hand (`ethtool -n <iface>`, then `ethtool -N <iface> delete <loc>`); the \
                 current allowlist is not the test, since the commonest stray is a prefix \
                 just removed from it. The runbook has the field table",
                self.steer_stray
            ));
        }
        if self.steer_missing > 0 {
            clauses.push(format!(
                "{} steering rule(s) this target asks for are missing from the NIC, no \
                 longer match what was asked for, or were never installed — that traffic \
                 is on the eBPF tier. Something changed them out of band (a UniFi \
                 provisioning push does this), or the allowlist grew while the inherited \
                 rules stayed as they were; {remedy}",
                self.steer_missing
            ));
        }
        if let Some(why) = &self.steer_audit_unreadable {
            let unverifiable = format!(
                "the NIC would not answer a rule readback ({why}), so rules may be \
                 removed or altered without this being visible; `ethtool -n <iface>` is \
                 the ground truth until it clears"
            );
            clauses.push(if clauses.is_empty() {
                format!("cannot verify steering: {unverifiable}")
            } else {
                // The counts above are real but STALE, and saying so is
                // the whole point — an operator reading a count as
                // current will fix that many rules and stop looking.
                format!(
                    "and the count(s) above are the last answer the NIC gave, not current \
                     ones: {unverifiable}"
                )
            });
        }
        let message = (!clauses.is_empty()).then(|| clauses.join(". "));
        if let Some(message) = message {
            return SubsystemHealth {
                name: SUBSYS_STEERING.into(),
                state: HealthState::Degraded,
                message: Some(message),
                last_success_age_seconds: None,
            };
        }
        let (state, message) = match (self.steered, self.steer_intended) {
            (true, _) => (HealthState::Healthy, None),
            // Intended but absent: a failed steer, or steering torn down
            // by trouble and not yet restored.
            //
            // The self-repair is named only from `Ready`, which is where
            // it is actually armed: a refused steer settles there and
            // the module re-attempts it (`Event::SteerUnblocked`).
            // Everywhere else the repair is the convergence, on its own
            // schedule — and predicting a paced retry that is not
            // running is exactly how the lines in this file have gone
            // wrong before.
            (false, true) => (
                HealthState::Degraded,
                Some(if matches!(self.state, State::Ready) {
                    format!(
                        "steering intended but not in place — traffic is on the eBPF tier. \
                         The module re-attempts it on its own, at most every {}s, once \
                         nothing is refusing it; `packetframe reconfigure` asks immediately \
                         and reports the reason if it is refused again",
                        crate::driver::STEER_RETRY_EVERY.as_secs()
                    )
                } else {
                    "steering intended but not in place — traffic is on the eBPF tier".to_string()
                }),
            ),
            // The deliberate staging state: all members up, FIB synced
            // and verified, nothing diverted. Every canary's waypoint
            // and every rollback's landing zone, so it is not a fault.
            //
            // Split by what the CONFIG says, because the two ways to be
            // here read very differently to whoever is holding the
            // rollout. Both are Healthy — waiting for a lever is not a
            // fault — but "I asked for this" and "the machine is waiting
            // for me" must not print the same line.
            (false, false) if self.steer_configured => (
                HealthState::Healthy,
                // The continuations are load-bearing: without the
                // trailing `\` the source indentation is part of the
                // string, and this arm shipped two twenty-space runs in
                // an operator's line for exactly that reason. It went
                // unnoticed because the guard test rendered only the
                // arms an already-steering port reaches; it covers
                // these now.
                Some(
                    "configured `steer on`, awaiting an operator lever move; traffic is on \
                     the eBPF tier. A first attach never steers by itself — set the port \
                     `steer off`, `packetframe reconfigure`, then back to `steer on` and \
                     reconfigure again (canary ladder, docs/runbooks/vpp-offload.md)"
                        .into(),
                ),
            ),
            (false, false) => (
                HealthState::Healthy,
                Some("steer off (staging state); traffic is on the eBPF tier".into()),
            ),
        };
        SubsystemHealth {
            name: SUBSYS_STEERING.into(),
            state,
            message,
            last_success_age_seconds: None,
        }
    }

    fn ports_health(&self) -> SubsystemHealth {
        let dead = self.dead_ports();
        let (state, message) = if self.ports.is_empty() {
            (HealthState::Degraded, Some("no ports attached".into()))
        } else if dead.is_empty() {
            (
                HealthState::Healthy,
                Some(format!("{} member port(s) up", self.ports.len())),
            )
        } else {
            // Membership is all-or-nothing: a down member port means
            // every prefix whose best path egresses it is a blackhole
            // once anything is steered, which is why this is Unhealthy
            // while steered and Degraded otherwise.
            let names = dead
                .iter()
                .map(|p| format!("{} (admin_up={} link_up={})", p.port, p.admin_up, p.link_up))
                .collect::<Vec<_>>()
                .join(", ");
            let st = if self.steered {
                HealthState::Unhealthy
            } else {
                HealthState::Degraded
            };
            (st, Some(format!("down: {names}")))
        };
        SubsystemHealth {
            name: SUBSYS_PORTS.into(),
            state,
            message,
            last_success_age_seconds: None,
        }
    }
}

/// Stable metric label for a lifecycle state. One-hot rendering needs
/// the full set, so this is exhaustive by construction rather than a
/// `Debug` string that would silently rename a series on a refactor.
const STATE_LABELS: [(State, &str); 8] = [
    (State::Stopped, "stopped"),
    (State::Backoff, "backoff"),
    (State::Starting, "starting"),
    (State::Syncing, "syncing"),
    (State::Verifying, "verifying"),
    (State::Ready, "ready"),
    (State::Steered, "steered"),
    (State::AdoptedResyncing, "adopted_resyncing"),
];

const HEALTH_LABELS: [(HealthState, &str); 3] = [
    (HealthState::Healthy, "healthy"),
    (HealthState::Degraded, "degraded"),
    (HealthState::Unhealthy, "unhealthy"),
];

fn gauge(out: &mut String, name: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
}

/// Escape a dynamic Prometheus label value (text exposition format:
/// backslash, double quote, newline).
///
/// Needed because interface names reach the label set from config, and
/// `validate_iface_name` mirrors the kernel's `dev_valid_name()` — it
/// rejects `/`, `\`, NUL and whitespace but permits `"`. A port named
/// `eth"0` therefore parses, and would emit `port="eth"0"`.
///
/// The blast radius is what makes this worth handling rather than
/// asserting away: a single malformed line makes the textfile collector
/// reject the **whole file**, so one odd interface name would take out
/// every metric on the host, fast-path's included. Escaping at the point
/// of emission is also the right layer — the renderer owes valid
/// exposition for whatever name it is handed, whatever the source.
fn label(value: &str) -> String {
    if !value.contains(['\\', '"', '\n']) {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 8);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Render `packetframe_vpp_*` gauges for the Prometheus textfile
/// collector.
///
/// Gauges throughout: every value here is a current level, not an
/// accumulation. `failures` is a *consecutive* count that resets on a
/// healthy start, so exporting it as a counter would make `rate()`
/// nonsense.
///
/// Enums render one-hot (`{state="ready"} 1`) following the established
/// `packetframe_fib_forwarding_mode` pattern: a numeric encoding cannot
/// be aggregated or alerted on without a lookup table living in the
/// alert rule.
pub fn render_metrics(snap: &StatusSnapshot, module: &str) -> String {
    let mut out = String::with_capacity(2048);

    gauge(
        &mut out,
        "packetframe_vpp_state",
        "1 for the current supervision state, 0 otherwise",
    );
    for (st, label) in STATE_LABELS {
        let _ = writeln!(
            out,
            "packetframe_vpp_state{{module=\"{module}\",state=\"{label}\"}} {}",
            u8::from(snap.state == st)
        );
    }

    let overall = snap.report().overall;
    gauge(
        &mut out,
        "packetframe_vpp_health",
        "1 for the current overall health state, 0 otherwise",
    );
    for (hs, label) in HEALTH_LABELS {
        let _ = writeln!(
            out,
            "packetframe_vpp_health{{module=\"{module}\",state=\"{label}\"}} {}",
            u8::from(overall == hs)
        );
    }

    gauge(
        &mut out,
        "packetframe_vpp_steered",
        "1 when MCAM rules are diverting traffic to VPP",
    );
    let _ = writeln!(
        out,
        "packetframe_vpp_steered{{module=\"{module}\"}} {}",
        u8::from(snap.steered)
    );

    gauge(
        &mut out,
        "packetframe_vpp_steer_intended",
        "1 when steering is meant to be up, whether or not it is",
    );
    let _ = writeln!(
        out,
        "packetframe_vpp_steer_intended{{module=\"{module}\"}} {}",
        u8::from(snap.steer_intended)
    );

    gauge(
        &mut out,
        "packetframe_vpp_undead",
        "1 when a terminated VPP survived SIGKILL and blocks restart",
    );
    let _ = writeln!(
        out,
        "packetframe_vpp_undead{{module=\"{module}\"}} {}",
        u8::from(snap.undead)
    );

    gauge(
        &mut out,
        "packetframe_vpp_consecutive_failures",
        "supervision failures since the last verified-healthy state",
    );
    let _ = writeln!(
        out,
        "packetframe_vpp_consecutive_failures{{module=\"{module}\"}} {}",
        snap.failures
    );

    gauge(
        &mut out,
        "packetframe_vpp_routes",
        "route-ledger entries per state",
    );
    let c = snap.counts;
    for (label, value) in [
        ("installed", c.installed),
        ("installing", c.installing),
        ("withheld", c.withheld),
        ("unresolvable", c.unresolvable),
    ] {
        let _ = writeln!(
            out,
            "packetframe_vpp_routes{{module=\"{module}\",state=\"{label}\"}} {value}"
        );
    }

    gauge(
        &mut out,
        "packetframe_vpp_pending_ops",
        "route ops the sink still owes VPP",
    );
    let _ = writeln!(
        out,
        "packetframe_vpp_pending_ops{{module=\"{module}\"}} {}",
        snap.pending_ops
    );

    gauge(
        &mut out,
        "packetframe_vpp_source_backlog",
        "route and neighbour changes the feed holds that the engine has not pulled",
    );
    let _ = writeln!(
        out,
        "packetframe_vpp_source_backlog{{module=\"{module}\"}} {}",
        snap.source_backlog
    );

    gauge(
        &mut out,
        "packetframe_vpp_drain_failing",
        "1 when the last attempt to push route updates to VPP failed",
    );
    let _ = writeln!(
        out,
        "packetframe_vpp_drain_failing{{module=\"{module}\"}} {}",
        u8::from(snap.drain_error.is_some())
    );

    gauge(
        &mut out,
        "packetframe_vpp_parked_ops",
        "route ops parked at the capacity high-water mark",
    );
    let _ = writeln!(
        out,
        "packetframe_vpp_parked_ops{{module=\"{module}\"}} {}",
        snap.parked_ops
    );

    // Only emitted when the API has actually answered at least once.
    // Emitting 0 for "never answered" would be indistinguishable from a
    // perfectly fresh pong, which is the opposite of the truth.
    if let Some(age) = snap.api.last_success_age() {
        gauge(
            &mut out,
            "packetframe_vpp_api_silent_seconds",
            "seconds since the binary API last answered",
        );
        let _ = writeln!(
            out,
            "packetframe_vpp_api_silent_seconds{{module=\"{module}\"}} {age}"
        );
    }

    gauge(
        &mut out,
        "packetframe_vpp_fib_verified",
        "1 when the last readback verification passed",
    );
    let _ = writeln!(
        out,
        "packetframe_vpp_fib_verified{{module=\"{module}\"}} {}",
        u8::from(snap.fib.verified())
    );

    // Same reasoning as the API age: absent rather than zero when no
    // verify has passed.
    if let Some(age) = snap.fib.last_success_age() {
        gauge(
            &mut out,
            "packetframe_vpp_fib_verify_age_seconds",
            "seconds since the last passing readback verification",
        );
        let _ = writeln!(
            out,
            "packetframe_vpp_fib_verify_age_seconds{{module=\"{module}\"}} {age}"
        );
    }

    if !snap.ports.is_empty() {
        gauge(
            &mut out,
            "packetframe_vpp_port_up",
            "1 when a member port is both admin-up and link-up inside VPP",
        );
        for p in &snap.ports {
            let _ = writeln!(
                out,
                "packetframe_vpp_port_up{{module=\"{module}\",port=\"{}\",sw_if_index=\"{}\"}} {}",
                label(&p.port),
                p.sw_if_index,
                u8::from(p.forwards())
            );
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::Event;
    use packetframe_common::fib::IpPrefix;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::sink::{Capacity, NexthopMap, RouteLedger};

    fn ledger_with(installed: u64, withheld: u64, unresolvable: u64) -> RouteLedger {
        let mut map = NexthopMap::new(vec!["eth4".into()]);
        let good = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let bad = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        map.set_device(good, "eth4");
        map.set_device(bad, "eth0"); // excluded

        let mut led = RouteLedger::new(Capacity::new(installed));
        let mut n = 0u32;
        let mut next = || {
            n += 1;
            IpPrefix::V4 {
                addr: [10, (n >> 8) as u8, (n & 0xff) as u8, 0],
                prefix_len: 24,
            }
        };
        for _ in 0..installed {
            let p = next();
            led.classify_upsert(p, &[good], &map);
            led.commit_installed(p);
        }
        for _ in 0..withheld {
            let p = next();
            led.classify_upsert(p, &[good], &map);
        }
        for _ in 0..unresolvable {
            let p = next();
            led.classify_upsert(p, &[bad], &map);
        }
        led
    }

    fn ports_up() -> Vec<PortLink> {
        vec![PortLink {
            port: "eth4".into(),
            sw_if_index: 3,
            admin_up: true,
            link_up: true,
        }]
    }

    fn port_down() -> Vec<PortLink> {
        vec![PortLink {
            port: "eth4".into(),
            sw_if_index: 3,
            admin_up: true,
            link_up: false,
        }]
    }

    fn verified(secs: u64) -> FibSync {
        FibSync::Verified {
            age: Duration::from_secs(secs),
            sampled: 64,
        }
    }

    /// A supervisor driven to steered-and-healthy through real events,
    /// rather than a hand-built struct — the states have invariants and
    /// constructing them by hand would test a shape the machine cannot
    /// actually reach.
    fn steered_supervisor() -> Supervisor {
        let mut sup = Supervisor::new();
        sup.on(Event::StartRequested);
        sup.on(Event::Spawned);
        sup.on(Event::ApiUp);
        sup.on(Event::SyncComplete);
        sup.on(Event::VerifyPassed);
        sup.on(Event::Steered);
        assert!(sup.is_steered());
        sup
    }

    fn ready_supervisor() -> Supervisor {
        let mut sup = Supervisor::new();
        sup.on(Event::StartRequested);
        sup.on(Event::Spawned);
        sup.on(Event::ApiUp);
        sup.on(Event::SyncComplete);
        sup.on(Event::VerifyPassed);
        assert_eq!(sup.state(), State::Ready);
        sup
    }

    /// Every `(steered, steer_intended)` a snapshot can carry.
    ///
    /// The steering health match has four arms and a `steered` snapshot
    /// reaches exactly one of them, so a matrix built from
    /// `steered_supervisor()` alone renders a quarter of the lines it
    /// looks like it renders — which is how a twenty-space run shipped
    /// in the awaiting-a-lever line under two class guards.
    fn steering_postures() -> [(bool, bool); 4] {
        [(true, true), (false, true), (false, false), (true, false)]
    }

    fn snap_of(
        sup: &Supervisor,
        led: &RouteLedger,
        api: ApiHealth,
        fib: FibSync,
        ports: Vec<PortLink>,
    ) -> StatusSnapshot {
        StatusSnapshot::observe(
            sup,
            led.counts(),
            &PendingMap::new(),
            api,
            fib,
            ports,
            false,
        )
    }

    /// Rules missing from the NIC degrade steering, even while steered.
    ///
    /// The arm is checked BEFORE `steered`, because "steered" says what
    /// we asked for and this says what the NIC actually holds. On the
    /// shadow (2026-08-11) a rule deleted out of band left `steering
    /// healthy` for two minutes with three of four rules installed; an
    /// operator reading that line had no way to know.
    ///
    /// Degraded rather than Unhealthy on purpose: the stripped traffic
    /// falls back to the eBPF tier, so nothing is dropping — the offload
    /// is just smaller than it claims.
    /// A NIC that will not answer is not a healthy NIC.
    ///
    /// The audit keeps its previous count when a readback fails, which
    /// is right — an unreadable NIC is not a wrong one. But publishing
    /// only that count meant a persistently unreadable NIC kept
    /// reporting the last clean answer forever, so steering read
    /// Healthy while drift had become undetectable (review finding).
    /// "Cannot check" and "checked, fine" must not print the same line.
    #[test]
    fn an_unreadable_steering_audit_is_not_healthy() {
        let led = ledger_with(10, 0, 0);
        let mut snap = snap_of(
            &steered_supervisor(),
            &led,
            ApiHealth::Answering {
                silent_for: Duration::from_millis(200),
            },
            verified(3),
            ports_up(),
        );
        // Zero missing — the last audit that SUCCEEDED found nothing.
        snap.steer_missing = 0;
        snap.steer_audit_unreadable = Some("EIO: readback failed".into());

        let rep = snap.report();
        let steering = rep
            .subsystems
            .iter()
            .find(|s| s.name == SUBSYS_STEERING)
            .expect("steering row");
        assert_eq!(
            steering.state,
            HealthState::Degraded,
            "an audit that could not read the NIC must not present the previous \
             clean count as current: {steering:?}"
        );
        let msg = steering.message.as_deref().unwrap_or_default();
        assert!(
            msg.contains("cannot verify") && msg.contains("EIO"),
            "the line must say it could not check, and why: {msg}"
        );
    }

    /// The remedy the drift line names must be one the module accepts.
    ///
    /// Measured on the shadow 2026-08-11: an out-of-band `ethtool -N
    /// eth1 delete 12` was detected in under 20 s and reported
    /// `steering DEGRADED ... packetframe reconfigure reconciles either
    /// way`. Running that command answered *"vpp-offload is
    /// AdoptedResyncing, not converged — steering changes apply only
    /// from Ready or Steered"*. The line pointed an operator at a wall,
    /// in the very state the audit exists to report: an adopted
    /// deferral, which on a box with no completeness authority holds
    /// indefinitely.
    ///
    /// Asserted as an INVARIANT over every state rather than for the one
    /// that bit us. The message and `apply_steering`'s gate now read the
    /// same predicate, and this is what keeps them from drifting apart
    /// again.
    #[test]
    fn the_drift_remedy_matches_the_gate_that_governs_it() {
        let states = [
            State::Stopped,
            State::Backoff,
            State::Starting,
            State::Syncing,
            State::Verifying,
            State::Ready,
            State::Steered,
            State::AdoptedResyncing,
        ];
        // Tripwire: a new variant makes this match non-exhaustive, so it
        // cannot be added without deciding what its drift line should
        // tell an operator to do.
        for s in states {
            match s {
                State::Stopped
                | State::Backoff
                | State::Starting
                | State::Syncing
                | State::Verifying
                | State::Ready
                | State::Steered
                | State::AdoptedResyncing => {}
            }
        }

        for state in states {
            for steer_configured in [true, false] {
                let led = ledger_with(10, 0, 0);
                let mut snap = snap_of(
                    &steered_supervisor(),
                    &led,
                    ApiHealth::Answering {
                        silent_for: Duration::from_millis(200),
                    },
                    verified(3),
                    ports_up(),
                );
                snap.state = state;
                snap.steer_configured = steer_configured;
                // MISSING only. Stray carries its own remedy now — a
                // stray rule can be dropping traffic, so it never defers
                // to a convergence — and mixing the two here would let
                // either string satisfy the assertions below.
                snap.steer_missing = 1;
                snap.steer_stray = 0;

                let rep = snap.report();
                let steering = rep
                    .subsystems
                    .iter()
                    .find(|s| s.name == SUBSYS_STEERING)
                    .expect("steering row");
                let msg = steering.message.as_deref().unwrap_or_default();

                // Exactly one of the four may appear. Asserting the
                // other three ABSENT is what makes this a
                // classification rather than four independent
                // contains() that could all drift true.
                let expected = if state.accepts_steering_changes() {
                    "`packetframe reconfigure` re-applies steering"
                } else if matches!(state, State::Stopped) {
                    "supervision has stopped"
                } else if !steer_configured {
                    "no port is configured to steer"
                } else {
                    "only if it verifies clean"
                };
                for marker in [
                    "`packetframe reconfigure` re-applies steering",
                    "supervision has stopped",
                    "no port is configured to steer",
                    "only if it verifies clean",
                ] {
                    assert_eq!(
                        msg.contains(marker),
                        marker == expected,
                        "state {state:?}, steer_configured={steer_configured}: the line \
                         must offer exactly the remedy this situation admits. \
                         `reconfigure` is refused outside Ready/Steered; a stopped \
                         daemon reconciles nothing; and with no port configured to \
                         steer, the convergence reconciles to an empty target, which \
                         is a different promise from the one the general arm makes: \
                         {msg}"
                    );
                }
                // This arm names a convergence, but it is reached from
                // `Backoff` too — where the next one is however long
                // the exponential schedule says, and VPP is not
                // forwarding meanwhile. So it must ALSO name a removal
                // that works right now, and must not point at `detach`
                // without saying that a live daemon refuses it.
                if expected == "no port is configured to steer" {
                    assert!(
                        msg.contains("ethtool -N") && msg.contains("once this daemon has exited"),
                        "state {state:?}: waiting out a convergence is not always an \
                         option here, and `loader::detach` is refused while this \
                         daemon holds the bpf_link FDs: {msg}"
                    );
                }
            }
        }
    }

    /// Every backticked command in a health message is well-formed.
    ///
    /// Twice in one PR a scripted edit shipped a broken operator
    /// command — first a literal with thirty spaces in it, then
    /// `` `ethtool -n reconfigure` `` where `` `packetframe
    /// reconfigure` `` was meant — and both times every assertion
    /// passed, because they all match short fragments and none spans
    /// the damage. Matching fragments cannot show a command is intact.
    ///
    /// So: collect every backticked span these messages render and
    /// require it to be one this module means to print. A new one has
    /// to be added here deliberately, which is the point.
    #[test]
    fn every_backticked_command_is_one_we_meant_to_print() {
        const ALLOWED: &[&str] = &[
            "packetframe reconfigure",
            "packetframe detach --all",
            "ethtool -n <iface>",
            "ethtool -N <iface> delete <loc>",
            "steer",
            "require-table-complete off",
            // Config directives rather than commands, but they go
            // through the same check for the same reason: an operator
            // types what the line prints, and a mangled one sends them
            // to edit something that does not exist. Rendered by the
            // awaiting-a-lever arm, which nothing exercised until the
            // matrix covered the unsteered postures.
            "steer on",
            "steer off",
        ];
        let mut seen: Vec<String> = Vec::new();
        for state in [
            State::Stopped,
            State::Backoff,
            State::Starting,
            State::Syncing,
            State::Verifying,
            State::Ready,
            State::Steered,
            State::AdoptedResyncing,
        ] {
            for steer_configured in [true, false] {
                // Both sides of the steering match, not just the arms an
                // already-steering port reaches. A `steered` snapshot
                // returns None from three of the four, so the matrix was
                // silently rendering one of them — and the awaiting-a-
                // lever line sat mangled underneath.
                for steering in steering_postures() {
                    for (missing, stray, unreadable) in [
                        (1usize, 0usize, None),
                        (0, 1, None),
                        (1, 1, Some("EIO: readback failed".to_string())),
                        (0, 0, Some("EIO: readback failed".to_string())),
                        (0, 0, None),
                    ] {
                        let led = ledger_with(10, 0, 0);
                        let mut snap = snap_of(
                            &steered_supervisor(),
                            &led,
                            ApiHealth::Answering {
                                silent_for: Duration::from_millis(200),
                            },
                            verified(3),
                            ports_up(),
                        );
                        snap.state = state;
                        snap.steer_configured = steer_configured;
                        (snap.steered, snap.steer_intended) = steering;
                        snap.steer_missing = missing;
                        snap.steer_stray = stray;
                        snap.steer_audit_unreadable = unreadable.clone();

                        for sub in snap.report().subsystems {
                            let Some(msg) = sub.message else { continue };
                            let mut rest = msg.as_str();
                            while let Some(open) = rest.find('`') {
                                rest = &rest[open + 1..];
                                let Some(close) = rest.find('`') else { break };
                                let span = &rest[..close];
                                rest = &rest[close + 1..];
                                if !seen.iter().any(|s| s == span) {
                                    seen.push(span.to_string());
                                }
                                assert!(
                                    ALLOWED.contains(&span),
                                    "{} in {state:?} prints `{span}`, which is not a \
                                     command this module means to emit. Either it is \
                                     mangled — the way `ethtool -n reconfigure` was — or \
                                     it is new and belongs in ALLOWED. Full line: {msg}",
                                    sub.name
                                );
                            }
                        }
                    }
                }
            }
        }
        assert!(
            seen.len() >= 4,
            "the matrix must actually render commands, or this proves nothing: {seen:?}"
        );
    }

    /// A remedy may not present `packetframe reconfigure` as something
    /// to run NOW from a state that refuses it.
    ///
    /// The rule, not the case. #157 split the remedy four ways for
    /// exactly this reason and wrote the rule into the comment above
    /// the selection — and the convergence arm's last sentence then
    /// broke it, saying reconfigure "asks immediately rather than
    /// waiting" from the only states that reach that arm, all of which
    /// fail `accepts_steering_changes()`. It printed on the shadow for
    /// 23 hours under an adopted resync, and the reconfigure it named
    /// answered "not converged" (2026-08-12, hardware). No test
    /// compared the message against the gate the module actually
    /// applies, so this one does: the assertion is derived from
    /// `accepts_steering_changes()` rather than from a list of states I
    /// thought of, and it fails if a future arm regresses the same way.
    #[test]
    fn no_remedy_offers_reconfigure_where_the_module_refuses_it() {
        for state in [
            State::Stopped,
            State::Backoff,
            State::Starting,
            State::Syncing,
            State::Verifying,
            State::Ready,
            State::Steered,
            State::AdoptedResyncing,
        ] {
            if state.accepts_steering_changes() {
                continue;
            }
            for steer_configured in [true, false] {
                for steering in steering_postures() {
                    for (missing, stray) in [(1usize, 0usize), (0, 1), (1, 1)] {
                        let led = ledger_with(10, 0, 0);
                        let mut snap = snap_of(
                            &steered_supervisor(),
                            &led,
                            ApiHealth::Answering {
                                silent_for: Duration::from_millis(200),
                            },
                            verified(3),
                            ports_up(),
                        );
                        snap.state = state;
                        snap.steer_configured = steer_configured;
                        (snap.steered, snap.steer_intended) = steering;
                        snap.steer_missing = missing;
                        snap.steer_stray = stray;

                        for sub in snap.report().subsystems {
                            let Some(msg) = sub.message else { continue };
                            // The exact phrasing that was wrong, plus the
                            // generic form of the same promise. A remedy
                            // may still NAME reconfigure — the stray arm
                            // does, hedged with "where reconfigure will
                            // not run" — but it may not say it works now.
                            for banned in [
                                "asks immediately",
                                "re-applies steering, and reports its own reason",
                            ] {
                                assert!(
                                    !msg.contains(banned),
                                    "{} in {state:?} (steer_configured={steer_configured}, \
                                     missing={missing}, stray={stray}) offers reconfigure \
                                     as an immediate remedy, but \
                                     accepts_steering_changes() is false there, so the \
                                     module answers \"not converged\" and changes nothing. \
                                     Full line: {msg}",
                                    sub.name
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// No health message contains a run of whitespace.
    ///
    /// Cheap guard for a class rather than an instance: `dfdc9b8`
    /// shipped a remedy bound as `let x = "... \` + continuation`,
    /// which rustfmt joined onto one line while KEEPING the source
    /// indentation inside the literal — so the operator's line read
    /// "rather than" followed by thirty spaces. Every assertion in
    /// these tests matches a short fragment, and no fragment spanned
    /// the gap, so all of them passed over it.
    #[test]
    fn no_health_message_carries_mangled_whitespace() {
        for state in [
            State::Backoff,
            State::Ready,
            State::Steered,
            State::AdoptedResyncing,
        ] {
            // Both values of `steer_configured` and every steering
            // posture, because the arms a steered snapshot never reaches
            // are exactly where the second instance of this defect was
            // sitting — the awaiting-a-lever line, unrendered by this
            // guard and by the backtick one.
            for steer_configured in [true, false] {
                for steering in steering_postures() {
                    for (missing, stray, unreadable) in [
                        (1usize, 0usize, None),
                        (0, 1, None),
                        (1, 1, Some("EIO: readback failed".to_string())),
                        (0, 0, Some("EIO: readback failed".to_string())),
                        (0, 0, None),
                    ] {
                        let led = ledger_with(10, 0, 0);
                        let mut snap = snap_of(
                            &steered_supervisor(),
                            &led,
                            ApiHealth::Answering {
                                silent_for: Duration::from_millis(200),
                            },
                            verified(3),
                            ports_up(),
                        );
                        snap.state = state;
                        snap.steer_configured = steer_configured;
                        (snap.steered, snap.steer_intended) = steering;
                        snap.steer_missing = missing;
                        snap.steer_stray = stray;
                        snap.steer_audit_unreadable = unreadable.clone();

                        for sub in snap.report().subsystems {
                            let Some(msg) = sub.message else { continue };
                            assert!(
                                !msg.contains("   "),
                                "{} in {state:?} renders a whitespace run — a line an \
                                 operator reads at 3am, mangled by a source-formatting \
                                 artefact: {msg:?}",
                                sub.name
                            );
                        }
                    }
                }
            }
        }
    }

    /// A stray rule never gets told to wait, in any state.
    ///
    /// The two complaints differ in what waiting costs. A MISSING rule
    /// means its prefix is on the eBPF tier, which forwards — waiting
    /// out a convergence is free. A STRAY rule is diverting traffic
    /// INTO VPP, and `Supervisor::fail` unsteers before it kills for
    /// exactly that reason: "until the MCAM rules are gone, every
    /// steered packet is going to a VF nothing is servicing". A refused
    /// unsteer leaves them installed and VPP dies anyway, so in
    /// `Backoff` those prefixes are being dropped — while the shared
    /// remedy told the operator to wait for a convergence that
    /// exponential backoff can postpone indefinitely (review finding,
    /// P1).
    #[test]
    fn a_stray_rule_is_never_told_to_wait() {
        for state in [
            State::Stopped,
            State::Backoff,
            State::Starting,
            State::Syncing,
            State::Verifying,
            State::Ready,
            State::Steered,
            State::AdoptedResyncing,
        ] {
            for steer_configured in [true, false] {
                let led = ledger_with(10, 0, 0);
                let mut snap = snap_of(
                    &steered_supervisor(),
                    &led,
                    ApiHealth::Answering {
                        silent_for: Duration::from_millis(200),
                    },
                    verified(3),
                    ports_up(),
                );
                snap.state = state;
                snap.steer_configured = steer_configured;
                snap.steer_stray = 1;
                snap.steer_missing = 0;

                let rep = snap.report();
                let steering = rep
                    .subsystems
                    .iter()
                    .find(|s| s.name == SUBSYS_STEERING)
                    .expect("steering row");
                let msg = steering.message.as_deref().unwrap_or_default();
                assert!(
                    msg.contains("ethtool -N <iface> delete <loc>"),
                    "state {state:?}: the hand removal must still be named — it is the \
                     fallback wherever `reconfigure` cannot run: {msg}"
                );
                assert!(
                    !msg.contains("only if it verifies clean"),
                    "state {state:?}: and must never defer to a convergence — with a \
                     refused unsteer the rules outlive the process, so waiting means \
                     dropping that prefix, not merely losing the offload: {msg}"
                );
                assert!(
                    msg.contains("removes exactly the locations the ledger names")
                        && msg.contains("current allowlist is not the test"),
                    "state {state:?}: lead with the repair that needs no identification, \
                     and warn about the trap in the one that does — a rule for a prefix \
                     just removed from the allowlist cannot match the current config, \
                     which is exactly the stray an allowlist shrink produces: {msg}"
                );
            }
        }
    }

    /// Rules still steering a port the config turned OFF degrade it.
    ///
    /// The opposite complaint to drift, and the one an operator is
    /// least able to afford being wrong about: it means the rollback
    /// lever did not take. Named first in the message for that reason,
    /// and counted separately because a single number would have to
    /// pick one story — install or remove — and this one says remove.
    #[test]
    fn rules_left_on_a_port_the_config_unsteered_degrade_it() {
        let led = ledger_with(10, 0, 0);
        let mut snap = snap_of(
            &steered_supervisor(),
            &led,
            ApiHealth::Answering {
                silent_for: Duration::from_millis(200),
            },
            verified(3),
            ports_up(),
        );
        snap.steer_missing = 0;
        snap.steer_stray = 2;

        let rep = snap.report();
        let steering = rep
            .subsystems
            .iter()
            .find(|s| s.name == SUBSYS_STEERING)
            .expect("steering row");
        assert_eq!(
            steering.state,
            HealthState::Degraded,
            "a port the config leaves unsteered that is still steering is not \
             healthy, whatever the drift count says: {steering:?}"
        );
        let msg = steering.message.as_deref().unwrap_or_default();
        assert!(
            msg.contains('2') && msg.contains("may still be diverted"),
            "and the line must say which way the problem points — these rules \
             need REMOVING, not reinstalling: {msg}"
        );
        assert!(
            !msg.contains("are still diverting"),
            "without claiming ownership it cannot always prove: after a restart \
             that dropped the port there is nothing left to check the readback \
             against, and `ethtool -n` is what settles it: {msg}"
        );
    }

    /// A RETAINED drift count must say it can no longer be checked.
    ///
    /// The two facts are independent — `Runtime::status` keeps the last
    /// count when a readback fails — so this combination is reachable and
    /// was the one the previous fix left behind: proven drift returned
    /// first and the unreadable audit went unmentioned, so an operator
    /// read "1 rule missing, reconfigure fixes it", fixed one rule, and
    /// had no way to know the audit had stopped being able to find the
    /// rest. Ordering cannot fix it; whichever arm runs first hides the
    /// other (review finding).
    #[test]
    fn a_retained_drift_count_says_it_is_no_longer_current() {
        let led = ledger_with(10, 0, 0);
        let mut snap = snap_of(
            &steered_supervisor(),
            &led,
            ApiHealth::Answering {
                silent_for: Duration::from_millis(200),
            },
            verified(3),
            ports_up(),
        );
        // Drift was proven by an earlier audit; the NIC has since stopped
        // answering, so the count stands but nothing can add to it.
        snap.steer_missing = 1;
        snap.steer_audit_unreadable = Some("EIO: readback failed".into());

        let rep = snap.report();
        let steering = rep
            .subsystems
            .iter()
            .find(|s| s.name == SUBSYS_STEERING)
            .expect("steering row");
        assert_eq!(steering.state, HealthState::Degraded);
        let msg = steering.message.as_deref().unwrap_or_default();
        assert!(
            msg.contains('1') && msg.contains("eBPF tier"),
            "the proven drift must still be reported: {msg}"
        );
        assert!(
            msg.contains("EIO") && msg.contains("not current ones"),
            "and so must the fact that the count is stale and further drift is \
             invisible — reporting only the count sends an operator to fix that \
             many rules and stop looking: {msg}"
        );
    }

    #[test]
    fn steering_rules_missing_from_the_nic_degrade_it() {
        let led = ledger_with(10, 0, 0);
        let mut snap = snap_of(
            &steered_supervisor(),
            &led,
            ApiHealth::Answering {
                silent_for: Duration::from_millis(200),
            },
            verified(3),
            ports_up(),
        );
        // Baseline: a NIC that agrees is healthy.
        let base = snap.report();
        let steering = base
            .subsystems
            .iter()
            .find(|s| s.name == SUBSYS_STEERING)
            .expect("steering row");
        assert_eq!(steering.state, HealthState::Healthy, "{steering:?}");

        snap.steer_missing = 1;
        let rep = snap.report();
        let steering = rep
            .subsystems
            .iter()
            .find(|s| s.name == SUBSYS_STEERING)
            .expect("steering row");
        assert_eq!(
            steering.state,
            HealthState::Degraded,
            "a NIC missing a rule the ledger names must not read healthy"
        );
        let msg = steering.message.as_deref().unwrap_or_default();
        assert!(
            msg.contains("reconfigure"),
            "the line has to name the one command that fixes it: {msg}"
        );
    }

    #[test]
    fn steered_and_clean_is_healthy() {
        let led = ledger_with(10, 0, 0);
        let s = snap_of(
            &steered_supervisor(),
            &led,
            ApiHealth::Answering {
                silent_for: Duration::from_millis(200),
            },
            verified(3),
            ports_up(),
        );
        let r = s.report();
        assert_eq!(r.overall, HealthState::Healthy);
        assert!(r.subsystems.iter().all(|x| x.state == HealthState::Healthy));
    }

    /// The module's whole premise: the eBPF fast-path is a permanent
    /// failover tier, so a dead-and-unsteered VPP means the box is
    /// forwarding correctly. Reporting that as Unhealthy would page for
    /// a healthy router — which is how alerts get muted.
    #[test]
    fn a_crash_looping_but_unsteered_vpp_is_degraded_not_unhealthy() {
        let mut sup = Supervisor::new();
        sup.on(Event::StartRequested);
        sup.on(Event::Spawned);
        sup.on(Event::ProcessExited { status: Some(139) });
        assert!(!sup.is_steered());

        let led = ledger_with(0, 0, 0);
        let s = snap_of(
            &sup,
            &led,
            ApiHealth::NoProcess,
            FibSync::NeverVerified,
            ports_up(),
        );
        assert_eq!(s.report().overall, HealthState::Degraded);
        // ...and the process subsystem still says plainly what is wrong,
        // so the degradation is not silent.
        let proc = s
            .report()
            .subsystems
            .into_iter()
            .find(|x| x.name == SUBSYS_PROCESS)
            .unwrap();
        assert_ne!(proc.state, HealthState::Healthy);
    }

    /// The inverse, and the worst state in the system: MCAM is diverting
    /// traffic to a process that is gone.
    #[test]
    fn steered_with_a_dead_process_is_unhealthy() {
        let mut s = snap_of(
            &steered_supervisor(),
            &ledger_with(10, 0, 0),
            ApiHealth::NoProcess,
            verified(1),
            ports_up(),
        );
        // Force the pairing the supervisor tears down within 50 ms, but
        // which is exactly what must page while it exists.
        s.state = State::Stopped;
        assert!(s.steered);
        assert_eq!(s.report().overall, HealthState::Unhealthy);
    }

    #[test]
    fn steered_into_a_wedged_api_is_unhealthy() {
        let s = snap_of(
            &steered_supervisor(),
            &ledger_with(10, 0, 0),
            ApiHealth::Silent {
                silent_for: Duration::from_secs(3),
                budget: Duration::from_millis(1500),
            },
            verified(1),
            ports_up(),
        );
        assert_eq!(s.report().overall, HealthState::Unhealthy);
    }

    /// Rule 1, expressed as health: never steer into an unverified FIB.
    #[test]
    fn steered_without_a_passing_verify_is_unhealthy() {
        for fib in [
            FibSync::NeverVerified,
            FibSync::Failed {
                age: Duration::from_secs(1),
                summary: "verify FAIL: 60/64 probes matched".into(),
            },
        ] {
            let s = snap_of(
                &steered_supervisor(),
                &ledger_with(10, 0, 0),
                ApiHealth::Answering {
                    silent_for: Duration::ZERO,
                },
                fib.clone(),
                ports_up(),
            );
            assert_eq!(
                s.report().overall,
                HealthState::Unhealthy,
                "steered with {fib:?} must page"
            );
        }
    }

    /// An incomplete-but-mostly-right table must NOT read as an outage:
    /// unsteering a mostly-correct VPP is worse than the holes, so this
    /// has to stay Degraded or the circuit breaker would do exactly the
    /// wrong thing.
    #[test]
    fn steered_with_an_incomplete_table_is_degraded_not_unhealthy() {
        let led = ledger_with(10, 3, 2);
        assert!(led.counts().degraded());
        let s = snap_of(
            &steered_supervisor(),
            &led,
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(2),
            ports_up(),
        );
        assert_eq!(s.report().overall, HealthState::Degraded);
    }

    /// The two degraded counts page differently, so both must appear by
    /// name — collapsing them into one "incomplete" number hides
    /// whichever is rarer.
    #[test]
    fn withheld_and_unresolvable_are_reported_separately() {
        let led = ledger_with(10, 3, 2);
        let s = snap_of(
            &steered_supervisor(),
            &led,
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(2),
            ports_up(),
        );
        let fib = s
            .report()
            .subsystems
            .into_iter()
            .find(|x| x.name == SUBSYS_FIB)
            .unwrap();
        let msg = fib.message.unwrap();
        assert!(msg.contains("3 withheld"), "{msg}");
        assert!(msg.contains("2 unresolvable"), "{msg}");
    }

    /// All members up, FIB verified, nothing diverted. The plan calls
    /// this every canary's waypoint and every rollback's landing zone —
    /// it is the designed safe state, so it must not read as a fault or
    /// operators learn to ignore the signal during every rollout.
    #[test]
    fn the_staging_state_is_healthy() {
        let sup = ready_supervisor();
        assert!(!sup.is_steered());
        assert!(!sup.steer_intended());
        let s = snap_of(
            &sup,
            &ledger_with(10, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(1),
            ports_up(),
        );
        assert_eq!(s.report().overall, HealthState::Healthy);
    }

    /// But steering that was *supposed* to be up and is not is a real
    /// degradation — otherwise a failed steer looks identical to the
    /// deliberate staging state and a rollout could silently do nothing.
    ///
    /// Both routes to that state are checked: a steer that failed on
    /// first attach, and steering lost to a restart and not restored.
    #[test]
    fn a_failed_steer_is_distinguishable_from_deliberate_steer_off() {
        // First attach: the operator asked, the MCAM insert failed.
        let mut first = ready_supervisor();
        first.on(Event::SteerFailed {
            rules_remain: false,
        });
        assert!(!first.is_steered());
        assert!(
            first.steer_intended(),
            "a failed first-attach steer must record the want, or it is \
             indistinguishable from `steer off` and never retried"
        );

        // Restart path: was steered, crashed, came back, re-steer failed.
        let mut sup = steered_supervisor();
        sup.on(Event::ProcessExited { status: None });
        sup.on(Event::BackoffElapsed);
        sup.on(Event::ApiUp);
        sup.on(Event::SyncComplete);
        sup.on(Event::VerifyPassed);
        sup.on(Event::Unsteered); // rules torn down on the way through
        sup.on(Event::SteerFailed {
            rules_remain: false,
        });
        assert!(!sup.is_steered());
        assert!(sup.steer_intended());

        let s = snap_of(
            &sup,
            &ledger_with(10, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(1),
            ports_up(),
        );
        assert_eq!(s.report().overall, HealthState::Degraded);
        let steer = s
            .report()
            .subsystems
            .into_iter()
            .find(|x| x.name == SUBSYS_STEERING)
            .unwrap();
        assert_eq!(steer.state, HealthState::Degraded);
    }

    /// The intended-but-absent line names the module's own retry only
    /// where that retry is armed.
    ///
    /// From `Ready` a refused steer is re-attempted on the driver's
    /// interval, so telling the operator to run `reconfigure` is telling
    /// them to do by hand what is already happening. From anywhere else
    /// nothing is armed and the repair rides the next convergence —
    /// promising a paced retry there would be the same overclaim this
    /// file has now made four times.
    #[test]
    fn the_retry_is_named_only_where_it_is_armed() {
        let mut sup = ready_supervisor();
        sup.on(Event::SteerFailed {
            rules_remain: false,
        });
        assert!(sup.steer_retry_pending());

        let line = |state: State| {
            let mut snap = snap_of(
                &sup,
                &ledger_with(10, 0, 0),
                ApiHealth::Answering {
                    silent_for: Duration::ZERO,
                },
                verified(1),
                ports_up(),
            );
            snap.state = state;
            snap.report()
                .subsystems
                .into_iter()
                .find(|x| x.name == SUBSYS_STEERING)
                .and_then(|x| x.message)
                .unwrap_or_default()
        };

        let ready = line(State::Ready);
        assert!(
            ready.contains("re-attempts it on its own"),
            "from Ready the module is already retrying, and the line must say so: {ready}"
        );
        assert!(
            ready.contains(&format!("{}s", crate::driver::STEER_RETRY_EVERY.as_secs())),
            "and name the interval from the constant that governs it: {ready}"
        );
        for state in [State::Backoff, State::Syncing, State::AdoptedResyncing] {
            let msg = line(state);
            assert!(
                msg.contains("intended but not in place"),
                "{state:?}: still the same complaint: {msg}"
            );
            assert!(
                !msg.contains("re-attempts it on its own"),
                "{state:?}: nothing is armed here — the repair is the convergence: {msg}"
            );
        }
    }

    /// The two ways to be unsteered must not print the same line.
    ///
    /// Both are Healthy — a first attach never steers by itself, so
    /// `steer on` waiting for a lever is the designed staging state, not
    /// a fault. But an operator who has just written `steer on` and
    /// restarted needs to see that the config was read. Reporting
    /// `steer off (staging state)` at them says the opposite, and this
    /// bit us directly on the shadow: the first steer needed a lever
    /// round-trip that nothing in the output suggested.
    ///
    /// Asserts the DISTINCTION rather than either message's wording — a
    /// test pinning one string passes just as well when both arms print
    /// it.
    #[test]
    fn configured_steer_on_reads_differently_from_steer_off() {
        let led = ledger_with(10, 0, 0);
        let sup = ready_supervisor();
        assert!(!sup.is_steered() && !sup.steer_intended());

        let msg = |configured: bool| {
            StatusSnapshot::observe(
                &sup,
                led.counts(),
                &PendingMap::new(),
                ApiHealth::Answering {
                    silent_for: Duration::ZERO,
                },
                verified(1),
                ports_up(),
                configured,
            )
            .report()
            .subsystems
            .into_iter()
            .find(|x| x.name == SUBSYS_STEERING)
            .map(|x| (x.state, x.message.unwrap_or_default()))
            .unwrap()
        };

        let (off_state, off_msg) = msg(false);
        let (on_state, on_msg) = msg(true);

        assert_eq!(off_state, HealthState::Healthy, "steer off is not a fault");
        assert_eq!(
            on_state,
            HealthState::Healthy,
            "and neither is waiting for the lever"
        );
        assert_ne!(
            off_msg, on_msg,
            "a config asking to steer must not report as one that is not"
        );
        assert!(
            on_msg.contains("lever"),
            "the waiting case must say what unblocks it: {on_msg}"
        );
    }

    /// Undead outranks everything: the VF cannot be released and no
    /// restart can proceed, so nothing recovers without an operator.
    #[test]
    fn undead_is_unhealthy_even_unsteered() {
        let mut sup = Supervisor::new();
        sup.on(Event::StartRequested);
        sup.on(Event::Spawned);
        sup.on(Event::ApiUp);
        sup.on(Event::TerminationFailed);
        assert!(sup.is_undead());
        assert!(!sup.is_steered());

        let s = snap_of(
            &sup,
            &ledger_with(0, 0, 0),
            ApiHealth::NoProcess,
            FibSync::NeverVerified,
            ports_up(),
        );
        assert_eq!(s.report().overall, HealthState::Unhealthy);
    }

    /// A down member port blackholes every prefix whose best path
    /// egresses it — but only once traffic is steered. Membership is
    /// all-or-nothing, so this is the difference between an outage and a
    /// staging problem.
    #[test]
    fn a_down_member_port_escalates_only_when_steered() {
        let steered = snap_of(
            &steered_supervisor(),
            &ledger_with(10, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(1),
            port_down(),
        );
        assert_eq!(steered.report().overall, HealthState::Unhealthy);

        let staged = snap_of(
            &ready_supervisor(),
            &ledger_with(10, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(1),
            port_down(),
        );
        assert_eq!(staged.report().overall, HealthState::Degraded);
    }

    /// `FibSync` must not re-derive the pass criteria — if it did, the
    /// gate governing steering and the gate reporting health could
    /// disagree, and `sampled == 0` is exactly where they would.
    #[test]
    fn fib_sync_defers_to_the_verify_outcome() {
        let empty = VerifyOutcome::default();
        assert!(!empty.passed(), "sampled == 0 must fail");
        assert!(matches!(
            FibSync::from_outcome(&empty, Duration::ZERO),
            FibSync::Failed { .. }
        ));

        let good = VerifyOutcome {
            sampled: 64,
            ..Default::default()
        };
        assert!(good.passed());
        assert!(matches!(
            FibSync::from_outcome(&good, Duration::ZERO),
            FibSync::Verified { sampled: 64, .. }
        ));
    }

    /// A vetoed deferral must not be described as waiting for quiet.
    ///
    /// Measured, not hypothesised: on the shadow (2026-08-12) a box
    /// whose local bird held 13 routes against a 1.3M-route mirror sat
    /// deferred for 23 hours printing "the diff runs once the source is
    /// live and has gone quiet". The source going quiet could never
    /// have released it — `authority_current` was returning false, which
    /// vetoes the release outright — and no surface said so, because
    /// `AuthorityPosture` had no variant for a veto and the snapshot
    /// therefore read `Attesting`.
    ///
    /// The assertion is on the DIFFERENCE the operator acts on: the
    /// vetoed message must not send them to watch quiescence, and must
    /// name the authority as the blocker.
    #[test]
    fn a_vetoed_deferral_does_not_blame_quiescence() {
        use crate::runtime::AuthorityPosture;
        let led = ledger_with(10, 0, 0);
        let deferred = |authority| {
            let mut snap = snap_of(
                &steered_supervisor(),
                &led,
                ApiHealth::Answering {
                    silent_for: Duration::from_millis(200),
                },
                FibSync::NeverVerified,
                ports_up(),
            );
            // Floor MET — so the only thing that can be holding this is
            // quiescence or the authority.
            snap.resync_deferred = Some((1_303_920, 156_734));
            snap.authority = authority;
            snap.report()
                .subsystems
                .into_iter()
                .find(|s| s.name == SUBSYS_FIB)
                .and_then(|s| s.message)
                .expect("a deferral always explains itself")
        };

        let vetoed = deferred(AuthorityPosture::Vetoing);
        assert!(
            !vetoed.contains("gone quiet"),
            "a vetoed deferral must not point at quiescence, which cannot release it: \
             {vetoed}"
        );
        assert!(
            vetoed.contains("completeness authority") && vetoed.contains("vetoes"),
            "and it must name the authority as the blocker: {vetoed}"
        );
        assert!(
            vetoed.contains("quiescence is never what releases a veto"),
            "and say plainly that waiting for quiet is not the remedy: {vetoed}"
        );
        // But one sample is not proof of permanence: the checker reads
        // bird and the mirror a few subprocess calls apart, so a bulk
        // withdrawal caught mid-flight can produce a mismatch the next
        // check does not reproduce. The line may say "stop waiting for
        // quiet"; it may not say "go restart a daemon" on that evidence
        // alone (review finding).
        assert!(
            vetoed.contains("CONFIRM BEFORE ACTING"),
            "a single sample must not send an operator to restart anything: {vetoed}"
        );
        // The opt-out it recommends is read at bring-up, and
        // `reconfigure` never installs or removes the completeness
        // handle — so recommending it without saying RESTART sends an
        // operator to edit a file and reload into no change at all,
        // from a state where the reload is refused anyway (review
        // finding).
        assert!(
            vetoed.contains("RESTART"),
            "recommending `require-table-complete off` without saying it needs a restart \
             is a remedy that silently does nothing: {vetoed}"
        );

        // The permitting posture keeps the quiescence wording, so this
        // test cannot pass by making every deferral message identical.
        let attesting = deferred(AuthorityPosture::Attesting);
        assert!(
            attesting.contains("gone quiet"),
            "a non-vetoed deferral above the floor IS waiting for quiet: {attesting}"
        );

        // A blocked-but-self-clearing authority must NOT inherit the
        // veto's "waiting will not clear it" — that fires at every
        // startup before the first integrity check lands (review
        // finding).
        let awaiting = deferred(AuthorityPosture::AwaitingAuthority);
        assert!(
            !awaiting.contains("Waiting will not clear it"),
            "an authority that has merely not reported yet clears itself: {awaiting}"
        );
        assert!(
            awaiting.contains("releases itself"),
            "and the line must say so, or an operator goes looking for a fault that is a \
             startup transient: {awaiting}"
        );
    }

    /// A vetoing authority below the release floor must not be told it
    /// has no authority.
    ///
    /// The below-floor arm was unconditional, so it consumed the
    /// snapshot before the veto arm could be reached: a box that HAD
    /// `require-table-complete` enabled and was being vetoed by it read
    /// "with no authority ... give this box a bird and enable
    /// `require-table-complete`" (review finding). Both halves of that
    /// advice were already true and neither was the problem.
    #[test]
    fn a_vetoed_deferral_below_the_floor_is_not_an_absent_authority() {
        use crate::runtime::AuthorityPosture;
        let led = ledger_with(10, 0, 0);
        let mut snap = snap_of(
            &steered_supervisor(),
            &led,
            ApiHealth::Answering {
                silent_for: Duration::from_millis(200),
            },
            FibSync::NeverVerified,
            ports_up(),
        );
        // BELOW the floor and vetoing — the ordering trap.
        snap.resync_deferred = Some((40_000, 156_734));
        snap.authority = AuthorityPosture::Vetoing;
        let msg = snap
            .report()
            .subsystems
            .into_iter()
            .find(|s| s.name == SUBSYS_FIB)
            .and_then(|s| s.message)
            .expect("a deferral always explains itself");

        assert!(
            !msg.contains("with no authority"),
            "the authority is configured and is the thing blocking release: {msg}"
        );
        assert!(
            !msg.contains("give this box a bird and enable"),
            "and telling the operator to enable what is already enabled sends them \
             nowhere: {msg}"
        );
        assert!(
            msg.contains("not the authority feeding it"),
            "it must name the real blocker instead: {msg}"
        );
    }

    #[test]
    fn api_health_distinguishes_absent_from_silent() {
        let now = Instant::now();
        assert_eq!(
            ApiHealth::observe(State::Stopped, None, now, Duration::from_secs(1)),
            ApiHealth::NoProcess
        );
        // A process exists but has never answered: not a wedge.
        assert_eq!(
            ApiHealth::observe(State::Starting, None, now, Duration::from_secs(1)),
            ApiHealth::Starting
        );

        let det = WedgeDetector::started(now);
        assert!(matches!(
            ApiHealth::observe(State::Steered, Some(&det), now, Duration::from_secs(1)),
            ApiHealth::Answering { .. }
        ));
        assert!(matches!(
            ApiHealth::observe(
                State::Steered,
                Some(&det),
                now + Duration::from_secs(5),
                Duration::from_secs(1)
            ),
            ApiHealth::Silent { .. }
        ));
    }

    /// The freshness gauges must be absent rather than zero when there
    /// is no success to age: a `0` is indistinguishable from a pong that
    /// just landed, which inverts the meaning on every dashboard.
    #[test]
    fn freshness_gauges_are_absent_rather_than_zero_when_never_successful() {
        let s = snap_of(
            &Supervisor::new(),
            &ledger_with(0, 0, 0),
            ApiHealth::NoProcess,
            FibSync::NeverVerified,
            Vec::new(),
        );
        let m = render_metrics(&s, "vpp-offload");
        assert!(!m.contains("packetframe_vpp_api_silent_seconds"), "{m}");
        assert!(!m.contains("packetframe_vpp_fib_verify_age_seconds"), "{m}");
        // The boolean is still emitted — "not verified" is a fact worth
        // scraping.
        assert!(m.contains("packetframe_vpp_fib_verified{module=\"vpp-offload\"} 0"));
    }

    #[test]
    fn every_state_renders_exactly_one_hot() {
        // Guards the pairing between STATE_LABELS and State: a state
        // added without a label would silently render all-zero, which
        // reads as "no data" rather than "new state".
        for (st, label) in STATE_LABELS {
            let mut s = snap_of(
                &Supervisor::new(),
                &ledger_with(0, 0, 0),
                ApiHealth::NoProcess,
                FibSync::NeverVerified,
                ports_up(),
            );
            s.state = st;
            let m = render_metrics(&s, "vpp-offload");
            let ones = m
                .lines()
                .filter(|l| l.starts_with("packetframe_vpp_state{") && l.ends_with(" 1"))
                .count();
            assert_eq!(ones, 1, "state {label} must be exactly one-hot:\n{m}");
            assert!(m.contains(&format!("state=\"{label}\"}} 1")), "{m}");
        }
    }

    /// A drain that keeps failing degrades health, names itself, and
    /// says so on both surfaces.
    ///
    /// The policy is that a steady-state drain failure is retried rather
    /// than escalated — nothing restarts, nothing unsteers. That is the
    /// right call for a VPP carrying traffic, and it is exactly why this
    /// has to be loud: the only thing distinguishing "retrying, will be
    /// fine" from "VPP's FIB has been drifting from bird's for an hour"
    /// is that somebody is told.
    #[test]
    fn a_failing_drain_degrades_and_is_named_on_both_surfaces() {
        let clean = snap_of(
            &steered_supervisor(),
            &ledger_with(10, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(1),
            ports_up(),
        );
        assert_eq!(
            clean.report().overall,
            HealthState::Healthy,
            "the control must be healthy or this proves nothing"
        );

        let mut degraded = clean.clone();
        degraded.drain_error = Some("socket closed".into());
        degraded.source_backlog = 12;
        degraded.pending_ops = 34;

        assert_eq!(degraded.report().overall, HealthState::Degraded);
        assert!(
            !degraded.nominal(),
            "a drifting FIB must not read as nominal just because nothing restarted"
        );

        // Named, with both backlogs, because they point at different
        // faults and the operator needs to know which one is stuck.
        let sub = degraded
            .report()
            .subsystems
            .into_iter()
            .find(|s| s.name == SUBSYS_ROUTE_FEED)
            .expect("the route feed must appear as its own subsystem");
        assert_eq!(sub.state, HealthState::Degraded);
        let msg = sub.message.unwrap_or_default();
        assert!(msg.contains("socket closed"), "{msg}");
        assert!(msg.contains("12"), "the source backlog is named: {msg}");
        assert!(msg.contains("34"), "the queued count is named: {msg}");

        // And Prometheus agrees. This is the pairing that `store_error`
        // got wrong once: the report said Degraded while the gauge, built
        // from a different input, went on saying healthy.
        let m = render_metrics(&degraded, "vpp-offload");
        assert!(
            m.contains("packetframe_vpp_health{module=\"vpp-offload\",state=\"degraded\"} 1"),
            "the gauge disagrees with the report: {m}"
        );
        assert!(
            m.contains("packetframe_vpp_drain_failing{module=\"vpp-offload\"} 1"),
            "{m}"
        );
        assert!(
            m.contains("packetframe_vpp_source_backlog{module=\"vpp-offload\"} 12"),
            "{m}"
        );

        // A recovered drain stops degrading — the clearing observation,
        // without which a fault that healed reports forever.
        let mut recovered = degraded.clone();
        recovered.drain_error = None;
        assert_eq!(recovered.report().overall, HealthState::Healthy);
        assert!(!render_metrics(&recovered, "vpp-offload")
            .contains("packetframe_vpp_drain_failing{module=\"vpp-offload\"} 1"));
    }

    #[test]
    fn health_renders_exactly_one_hot_and_agrees_with_the_report() {
        let s = snap_of(
            &steered_supervisor(),
            &ledger_with(10, 3, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(1),
            ports_up(),
        );
        let m = render_metrics(&s, "vpp-offload");
        let ones = m
            .lines()
            .filter(|l| l.starts_with("packetframe_vpp_health{") && l.ends_with(" 1"))
            .count();
        assert_eq!(ones, 1, "{m}");
        // The gauge and the structured report must never disagree.
        assert_eq!(s.report().overall, HealthState::Degraded);
        assert!(m.contains("packetframe_vpp_health{module=\"vpp-offload\",state=\"degraded\"} 1"));
    }

    /// The agreement above must hold for **every** condition, including
    /// the ones added last. A store failure used to be layered onto the
    /// report by the supervision service *after* the snapshot, so
    /// `health_check` said Degraded while `packetframe_vpp_health` — which
    /// renders from `report()` on the unmodified snapshot — went on saying
    /// healthy, during exactly the failure the layering existed to
    /// surface. Asserted here rather than at the service, because this is
    /// where the two surfaces have to come from one input.
    #[test]
    fn a_store_failure_degrades_the_report_and_the_gauge_together() {
        let clean = snap_of(
            &steered_supervisor(),
            &ledger_with(10, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(1),
            ports_up(),
        );
        assert_eq!(
            clean.report().overall,
            HealthState::Healthy,
            "the control must be healthy or this proves nothing"
        );

        let mut degraded = clean.clone();
        degraded.store_error = Some("state dir is read-only".into());
        assert_eq!(degraded.report().overall, HealthState::Degraded);
        let m = render_metrics(&degraded, "vpp-offload");
        assert!(
            m.contains("packetframe_vpp_health{module=\"vpp-offload\",state=\"degraded\"} 1"),
            "the gauge disagrees with the report: {m}"
        );
        assert!(
            m.contains("packetframe_vpp_health{module=\"vpp-offload\",state=\"healthy\"} 0"),
            "{m}"
        );
        // And it is NAMED, with the consequence spelled out — the
        // degradation is invisible until a restart, so the message has to
        // say what that restart will do.
        let sub = degraded
            .report()
            .subsystems
            .into_iter()
            .find(|s| s.name == SUBSYS_STATE_FILE)
            .expect("the state-file subsystem must be present");
        let msg = sub.message.unwrap_or_default();
        assert!(msg.contains("read-only"), "{msg}");
        assert!(msg.contains("refuse adoption"), "{msg}");

        // No row at all when nothing failed, rather than a permanent
        // "state-file: fine" nobody reads.
        assert!(
            !clean
                .report()
                .subsystems
                .iter()
                .any(|s| s.name == SUBSYS_STATE_FILE),
            "a healthy snapshot grew a state-file row"
        );
    }

    #[test]
    fn every_metric_carries_help_and_type() {
        let s = snap_of(
            &steered_supervisor(),
            &ledger_with(10, 1, 1),
            ApiHealth::Answering {
                silent_for: Duration::from_secs(1),
            },
            verified(5),
            ports_up(),
        );
        let m = render_metrics(&s, "vpp-offload");
        let mut declared = std::collections::BTreeSet::new();
        for line in m.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                declared.insert(rest.split_whitespace().next().unwrap().to_string());
            }
        }
        assert!(!declared.is_empty());
        for line in m.lines() {
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let name = line
                .split(['{', ' '])
                .next()
                .expect("sample line has a name");
            assert!(
                declared.contains(name),
                "sample {name} has no # TYPE header:\n{m}"
            );
            // Prometheus rejects a gauge whose sample has no value.
            assert!(
                line.split_whitespace().count() >= 2,
                "sample line missing a value: {line}"
            );
        }
    }

    /// A first convergence is not healthy. Every state short of `Ready`
    /// means this module is not forwarding anything yet — and reporting
    /// otherwise made `overall` contradict its own subsystems, which were
    /// already saying "API still opening" and "never verified".
    #[test]
    fn a_first_convergence_is_degraded_at_every_step() {
        let mut sup = Supervisor::new();
        sup.on(Event::StartRequested);
        sup.on(Event::Spawned);

        // Starting: process alive, API not yet open, nothing verified.
        let starting = snap_of(
            &sup,
            &ledger_with(0, 0, 0),
            ApiHealth::Starting,
            FibSync::NeverVerified,
            ports_up(),
        );
        assert_eq!(starting.report().overall, HealthState::Degraded);

        // Syncing: API up, resync in flight.
        sup.on(Event::ApiUp);
        assert_eq!(sup.state(), State::Syncing);
        let syncing = snap_of(
            &sup,
            &ledger_with(5, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            FibSync::NeverVerified,
            ports_up(),
        );
        assert_eq!(syncing.report().overall, HealthState::Degraded);

        // Verifying: drained, verification in flight.
        sup.on(Event::SyncComplete);
        assert_eq!(sup.state(), State::Verifying);
        let verifying = snap_of(
            &sup,
            &ledger_with(10, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            FibSync::NeverVerified,
            ports_up(),
        );
        assert_eq!(verifying.report().overall, HealthState::Degraded);

        // Only a verified Ready is healthy.
        sup.on(Event::VerifyPassed);
        let ready = snap_of(
            &sup,
            &ledger_with(10, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(0),
            ports_up(),
        );
        assert_eq!(ready.report().overall, HealthState::Healthy);
    }

    /// `overall` must never be a cheerier verdict than its own
    /// subsystems. A whitelist makes that structural; the enumerate-the-
    /// failures version violated it during every first convergence.
    #[test]
    fn overall_is_never_better_than_its_worst_subsystem() {
        let rank = |h: HealthState| match h {
            HealthState::Healthy => 0,
            HealthState::Degraded => 1,
            HealthState::Unhealthy => 2,
        };
        // Sweep the lifecycle against both port conditions and a
        // never-verified FIB, which is the shape that regressed.
        for state in STATE_LABELS.map(|(s, _)| s) {
            for ports in [ports_up(), port_down(), Vec::new()] {
                for fib in [FibSync::NeverVerified, verified(1)] {
                    for api in [
                        ApiHealth::NoProcess,
                        ApiHealth::Starting,
                        ApiHealth::Answering {
                            silent_for: Duration::ZERO,
                        },
                    ] {
                        let mut s = snap_of(
                            &Supervisor::new(),
                            &ledger_with(4, 0, 0),
                            api,
                            fib.clone(),
                            ports.clone(),
                        );
                        s.state = state;
                        let r = s.report();
                        let worst = r.subsystems.iter().map(|x| rank(x.state)).max().unwrap();
                        assert!(
                            rank(r.overall) >= worst,
                            "overall {:?} is cheerier than the worst subsystem in \
                             state={state:?} fib={fib:?} api={api:?}:\n{:#?}",
                            r.overall,
                            r.subsystems
                        );
                    }
                }
            }
        }
    }

    /// A port name can reach the label set with a `"` in it:
    /// `validate_iface_name` mirrors the kernel's `dev_valid_name()`,
    /// which rejects `/`, `\`, NUL and whitespace but not quotes. One
    /// malformed line makes the textfile collector reject the entire
    /// file, so this would take out every metric on the host.
    #[test]
    fn dynamic_label_values_are_escaped() {
        assert_eq!(label("eth4"), "eth4");
        assert_eq!(label("eth\"0"), "eth\\\"0");
        assert_eq!(label("a\\b"), "a\\\\b");

        let mut s = snap_of(
            &steered_supervisor(),
            &ledger_with(10, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(1),
            vec![PortLink {
                port: "eth\"0".into(),
                sw_if_index: 3,
                admin_up: true,
                link_up: true,
            }],
        );
        let m = render_metrics(&s, "vpp-offload");
        assert!(m.contains(r#"port="eth\"0""#), "{m}");
        // Every label set must still be balanced: an unescaped quote
        // closes the value early and leaves a stray `"` before the `}`.
        for line in m.lines().filter(|l| !l.starts_with('#')) {
            let unescaped = line
                .char_indices()
                .filter(|(i, c)| *c == '"' && (*i == 0 || line.as_bytes()[i - 1] != b'\\'))
                .count();
            assert_eq!(unescaped % 2, 0, "unbalanced quotes in: {line}");
        }
        s.ports.clear();
        assert!(!render_metrics(&s, "vpp-offload").contains("packetframe_vpp_port_up"));
    }

    #[test]
    fn port_gauges_label_every_member() {
        let mut s = snap_of(
            &steered_supervisor(),
            &ledger_with(10, 0, 0),
            ApiHealth::Answering {
                silent_for: Duration::ZERO,
            },
            verified(1),
            ports_up(),
        );
        s.ports.push(PortLink {
            port: "eth5".into(),
            sw_if_index: 4,
            admin_up: true,
            link_up: false,
        });
        let m = render_metrics(&s, "vpp-offload");
        assert!(m.contains("port=\"eth4\",sw_if_index=\"3\"} 1"), "{m}");
        assert!(m.contains("port=\"eth5\",sw_if_index=\"4\"} 0"), "{m}");
    }
}
