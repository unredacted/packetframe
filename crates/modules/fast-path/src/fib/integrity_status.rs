//! What the integrity check *says*, and how an operator reads it.
//!
//! The comparison itself lives in [`crate::fib::integrity`], which is
//! Linux-only because it shells out to `birdc`. Everything here is the
//! result and its rendering: plain data, no syscalls, **deliberately not
//! behind the platform gate** so it compiles and its tests run on the
//! macOS dev loop rather than only inside the qemu job. The same reason
//! `crates/cli/src/health.rs` is portable — a `#[cfg(target_os =
//! "linux")]` test is invisible to every host gate.
//!
//! ## Why this module exists at all
//!
//! The checker published an [`IntegritySnapshot`] every 300 s and
//! nothing read it: `RouteController::integrity_snapshot()` had no
//! caller anywhere in the tree. A successful comparison logs at
//! **debug**, and only above-threshold drift logs at warn — so at the
//! default `log-level info` a healthy check printed *nothing*, and the
//! only way to see the verdict was to raise the log level (which costs a
//! restart: the filter is built from `RUST_LOG` at process start) and
//! grep for `integrity check OK`.
//!
//! That mattered beyond tidiness. vpp-offload's steering gate and its
//! adopted-resync release both act on this comparison — a box whose
//! authority disagrees refuses to steer and defers indefinitely — so the
//! operator's pre-flight check for a rollout was log archaeology.
//!
//! ## Silence is not agreement
//!
//! The one rule this file follows, and the defect the vpp-offload
//! runbook had to work around: **"no check has completed yet" and "a
//! check completed and they agree" must not render identically.** They
//! lead somewhere completely different — one is a startup transient that
//! clears itself within an interval, the other is positive evidence a
//! rollout can proceed on — and an absent line was equally consistent
//! with the checker never having run, `birdc` failing every time, or the
//! log having rotated.
//!
//! Same care as [`crate::fib::integrity`]'s own rule about what it
//! republishes to the second tier: a partial run publishes nothing
//! rather than a mixed report. [`IntegrityPosture`] extends that rule to
//! the reader — a comparison is either from the most recent run or is
//! labelled as history, never presented as current because it happens to
//! be the newest thing in the struct.

use std::time::{Duration, Instant};

use packetframe_common::module::{HealthState, SubsystemHealth};

/// Stable subsystem name. Append-safe, rename-unsafe: `packetframe
/// status` and operator dashboards key on this string, exactly as the
/// `stats` counter indices are append-only once shipped.
pub const SUBSYS_FIB_INTEGRITY: &str = "fib-integrity";

/// Default interval between integrity checks. Slow enough to be
/// cheap, fast enough that a drift window of "up to 5 minutes"
/// is acceptable.
///
/// Lives here rather than next to the checker so the health surface can
/// name the wait without a second copy of the number.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(300);

/// How far the mirror is from the authority, and whether that cleared
/// the configured warn threshold.
///
/// One struct rather than a bare fraction plus a threshold the reader
/// re-applies: `above` is recorded by the same branch that decides
/// whether to emit the warn log, so the log and the health line cannot
/// disagree about the verdict. Same discipline as vpp-offload's
/// `FibSync::from_outcome` deferring to `VerifyOutcome::passed`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Drift {
    /// `|bird - mirror| / bird`, as a fraction.
    pub fraction: f64,
    /// The threshold in force for the run that produced `fraction`.
    pub threshold: f64,
    pub above: bool,
}

/// One completed comparison: **both counts from the same run**.
///
/// The counts are not stored separately on the snapshot any more, and
/// that is the point. They used to be, and they were sticky — a failed
/// `birdc` or a failed `mirror_counts` left the previous run's number in
/// place — so a drift fraction could be computed from one fresh number
/// and one five minutes old. That is tolerable for a log line nobody
/// gates on and wrong for a surface an operator reads before a rollout.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Comparison {
    /// When the run that produced it recorded its result. Shared with
    /// [`IntegritySnapshot::last_run`] for that same run, which is what
    /// lets a reader tell a current comparison from a retained one.
    pub at: Instant,
    pub bird_routes: usize,
    pub packetframe_routes: usize,
    /// `None` when bird reported zero routes, where a fraction of the
    /// authority's count is undefined. Not "no drift" — see
    /// [`IntegrityPosture::subsystem_health`], which reports a zero
    /// authority as its own condition.
    pub drift: Option<Drift>,
}

/// Snapshot of the most recent integrity-check result.
///
/// Two readers, asking different questions. The BmpStalled gate wants
/// `bird_established_peers` — "does bird still think there are peers to
/// hear from?" — before it calls a quiet feed a stall. The health
/// surface wants the comparison, via [`IntegrityPosture`]. Neither
/// reads a field the other writes, which is why the counts live inside
/// [`Comparison`] rather than loose alongside the peer count.
#[derive(Debug, Clone, Default)]
pub struct IntegritySnapshot {
    /// The most recent run, whether or not it produced a comparison.
    pub last_run: Option<Instant>,
    /// The most recent run that did. Retained across a failed run, so it
    /// can be older than `last_run`.
    pub last_comparison: Option<Comparison>,
    pub bird_established_peers: Option<usize>,
    /// Why the most recent run could not complete. Cleared at the start
    /// of every run, so it always describes `last_run` and never an
    /// older one.
    pub last_error: Option<String>,
}

/// A comparison as the health surface reads it: aged, and knowing
/// whether it came from the most recent run.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// When the comparison was recorded, and when it was read. Both,
    /// rather than a precomputed age, because [`Self::gate_verdict`]
    /// needs to hand the real decision function the same two instants
    /// it would get in production. `age` is derived from them so the
    /// two cannot disagree.
    pub at: Instant,
    pub observed_at: Instant,
    pub bird_routes: usize,
    pub packetframe_routes: usize,
    pub drift: Option<Drift>,
    /// This comparison is the most recent run's own result, rather than
    /// one retained across a run that failed. A retained sample is
    /// history and must be labelled as such.
    pub current: bool,
}

impl Sample {
    pub fn age(&self) -> Duration {
        self.observed_at.saturating_duration_since(self.at)
    }

    /// The comparison as the second tier's steering gate receives it.
    ///
    /// Field-for-field what [`crate::fib::integrity::IntegrityChecker`]
    /// publishes to `TableCompleteness` in the same breath that it
    /// records the comparison — same counts, same `at`. Reconstructed
    /// rather than read back off the handle because the handle is
    /// `None` in every single-module deployment, and this row has to
    /// work there too.
    fn report(&self) -> packetframe_common::fib::CompletenessReport {
        packetframe_common::fib::CompletenessReport {
            authority_routes: self.bird_routes as u64,
            mirror_routes: self.packetframe_routes as u64,
            at: self.at,
        }
    }

    /// What a steering gate would decide from this comparison —
    /// obtained by **calling the decision function**, not by
    /// reimplementing its rules.
    ///
    /// This surface exists to predict the gate, so any rule restated
    /// here is a rule that can drift out from under it. It already did,
    /// twice, and both were caught in review rather than by a test:
    /// staleness was not considered at all, and the drift comparison
    /// used the checker's configurable **warn** threshold with a `>=`
    /// where the gate uses its own fixed `STEER_MAX_DRIFT` with a `<=`.
    /// The boundary was the visible symptom; the real defect was that
    /// two different thresholds were being passed off as one, so any
    /// operator who tuned `drift-warn-fraction` away from the default
    /// got a row that advertised a rollout across a whole range the
    /// gate refuses.
    pub fn gate_verdict(&self) -> packetframe_common::fib::Completeness {
        packetframe_common::fib::assess(
            Some(self.report()),
            self.observed_at,
            packetframe_common::fib::STEER_MAX_DRIFT,
            packetframe_common::fib::STEER_MAX_REPORT_AGE,
        )
    }
}

/// The integrity check's standing, as `packetframe status` reports it.
///
/// Three arms because there are three genuinely different answers, and
/// the first two must never print the same line.
#[derive(Debug, Clone, PartialEq)]
pub enum IntegrityPosture {
    /// The checker is running and no check has finished yet. **Not
    /// agreement** — nothing has compared bird against the mirror.
    AwaitingFirstCheck,
    /// At least one check has run. Composed rather than matched: a run
    /// can produce a comparison, an error, or both (the route counts
    /// succeed while `birdc show protocols` fails), and each fact is
    /// reported on its own.
    Checked {
        /// Age of the most recent run.
        run_age: Duration,
        /// The most recent completed comparison, if any has ever
        /// completed.
        sample: Option<Sample>,
        /// Why the most recent run could not complete.
        error: Option<String>,
    },
    /// The snapshot was being written at the instant status sampled it.
    ///
    /// The write happens once per interval and holds the lock for a
    /// handful of field assignments, so this is vanishingly rare — but a
    /// contended lock is a condition that *can* occur, and the two
    /// alternatives were both worse: a blocking read panics if this is
    /// ever called from an async context, and rendering it as
    /// [`Self::AwaitingFirstCheck`] would be the exact silence-as-a-state
    /// confusion this file exists to prevent.
    Unread,
}

impl IntegrityPosture {
    /// Read a snapshot. `now` is a parameter so the ages are testable.
    pub fn observe(snap: &IntegritySnapshot, now: Instant) -> Self {
        let Some(last_run) = snap.last_run else {
            // `last_run` is stamped by every run before anything else it
            // records, so its absence is the one unambiguous "nothing has
            // happened yet".
            return Self::AwaitingFirstCheck;
        };
        Self::Checked {
            run_age: now.saturating_duration_since(last_run),
            sample: snap.last_comparison.map(|c| Sample {
                at: c.at,
                observed_at: now,
                bird_routes: c.bird_routes,
                packetframe_routes: c.packetframe_routes,
                drift: c.drift,
                // Instant equality, not an age comparison: the checker
                // stamps one `Instant` per run and writes it to both
                // fields, so this is exact rather than a tolerance.
                current: c.at == last_run,
            }),
            error: snap.last_error.clone(),
        }
    }

    /// The row `packetframe status` prints.
    pub fn subsystem_health(&self) -> SubsystemHealth {
        let (state, message) = match self {
            Self::AwaitingFirstCheck => (
                // Healthy: forwarding does not depend on this. The
                // checker is a diagnostic safety net, and a box that has
                // simply not reached its first interval is not impaired.
                // The message carries the whole content of this state.
                HealthState::Healthy,
                format!(
                    "no comparison has completed yet — the first lands one interval ({}s by \
                     default) after the control plane starts. This is NOT agreement: nothing \
                     has yet compared bird's RIB against the mirror, and a second-tier \
                     steering gate that consults it holds until something does",
                    DEFAULT_INTERVAL.as_secs()
                ),
            ),
            Self::Unread => (
                HealthState::Degraded,
                "the integrity snapshot was being written at the moment this was sampled, so \
                 the last comparison could not be read. Self-clearing: the next health poll \
                 (5 s) carries it. Nothing about the comparison itself is implied either way"
                    .to_string(),
            ),
            Self::Checked {
                run_age,
                sample,
                error,
            } => Self::checked_health(*run_age, sample.as_ref(), error.as_deref()),
        };
        SubsystemHealth {
            name: SUBSYS_FIB_INTEGRITY.into(),
            state,
            message: Some(message),
            last_success_age_seconds: self.last_success_age(),
        }
    }

    /// Age of the last **completed comparison**, which is the only thing
    /// here that is a success. A run that could not compare is not one,
    /// and reporting its age would read as freshness on a dashboard.
    fn last_success_age(&self) -> Option<u64> {
        match self {
            Self::Checked { sample, .. } => sample.map(|s| s.age().as_secs()),
            Self::AwaitingFirstCheck | Self::Unread => None,
        }
    }

    /// The composed form: the verdict, then whatever the most recent run
    /// could not do. Clauses rather than a match over combinations —
    /// vpp-offload's `steering_health` arrived at the same shape after a
    /// review finding that ordering arms hid whichever fact came second.
    fn checked_health(
        run_age: Duration,
        sample: Option<&Sample>,
        error: Option<&str>,
    ) -> (HealthState, String) {
        let mut state = HealthState::Healthy;
        let mut clauses: Vec<String> = Vec::new();

        match sample {
            Some(s) => {
                let (verdict_state, verdict) = Self::verdict(s);
                state = state.worse_of(verdict_state);
                clauses.push(verdict);
            }
            None => {
                // A run finished and produced nothing to compare. With an
                // error alongside it this is the ordinary "birdc is
                // unreachable" case; the clause below says what that
                // costs rather than restating the error.
                state = state.worse_of(HealthState::Degraded);
                clauses.push(format!(
                    "no comparison has ever completed ({:.0}s since the last attempt), so \
                     there is no verdict to read — this is NOT agreement",
                    run_age.as_secs_f64()
                ));
            }
        }

        if let Some(e) = error {
            state = state.worse_of(HealthState::Degraded);
            // Whether the numbers above survive this is the whole
            // question, and the answer is not the same in the two cases:
            // a run that failed outright left the previous comparison
            // standing as history, while a run that compared fine and
            // then failed on `birdc show protocols` leaves the comparison
            // current. Presenting a retained sample as though the check
            // had just confirmed it is the failure this surface exists to
            // avoid.
            clauses.push(match sample {
                Some(s) if s.current => format!(
                    "the same run reported an error: {e} — the comparison above is from this \
                     run and stands"
                ),
                Some(_) => format!(
                    "the most recent check ({:.0}s ago) could not complete: {e} — so the \
                     comparison above is HISTORY, not the current state, and it ages until a \
                     check succeeds. Forwarding is unaffected; what is degraded is the \
                     ability to attest completeness at all, which a second-tier steering gate \
                     will refuse on",
                    run_age.as_secs_f64()
                ),
                None => format!(
                    "the most recent check ({:.0}s ago) could not complete: {e}. Forwarding is \
                     unaffected; what is degraded is the ability to attest completeness at \
                     all, which a second-tier steering gate will refuse on",
                    run_age.as_secs_f64()
                ),
            });
        } else if sample.is_none() {
            // Unreachable from the checker, which records an error on
            // every path that produces no comparison. Stated rather than
            // asserted: a surface that panics is worse than one that says
            // it does not understand what it read.
            clauses.push(
                "the run recorded neither a comparison nor a reason, which the checker has no \
                 path to produce — read this as a malformed snapshot rather than as a verdict"
                    .to_string(),
            );
        }

        (state, clauses.join(". "))
    }

    /// The comparison itself, without regard to what else the run did.
    ///
    /// **Two facts, from two authorities, and neither speaks for the
    /// other.** They were one fact once, and that was the bug:
    ///
    /// - The **drift-catch diagnostic** is fast-path's own alarm,
    ///   measured against the `drift-warn-fraction` the run applied.
    ///   Configurable, and nothing outside this module acts on it.
    /// - The **rollout verdict** is what a second tier's steering gate
    ///   will decide, and it is obtained by calling
    ///   [`Sample::gate_verdict`] rather than by restating its rules.
    ///
    /// Conflating them let the row print "the positive evidence a
    /// rollout needs" from a threshold the gate does not use — exactly
    /// at the boundary where the two comparisons differ (`>=` here,
    /// `<=` there), and across the entire range between them for any
    /// operator who had tuned the warn fraction (review finding).
    fn verdict(s: &Sample) -> (HealthState, String) {
        let mut state = HealthState::Healthy;
        let counts = format!(
            "bird {} routes, mirror {}",
            s.bird_routes, s.packetframe_routes
        );

        let diagnostic = match s.drift {
            Some(d) => {
                if d.above {
                    state = state.worse_of(HealthState::Degraded);
                }
                format!(
                    "drift {:.3}%, {} the {:.3}% warn threshold",
                    d.fraction * 100.0,
                    if d.above { "at or above" } else { "within" },
                    d.threshold * 100.0
                )
            }
            // Not "no drift". A zero authority cannot attest anything,
            // and it is a real and documented state — a box running a
            // bird that carries none of the table the mirror is fed.
            None => "no drift fraction is defined: bird reports NO routes in \
                     master4/master6, and a fraction of zero says nothing"
                .to_string(),
        };

        let gate = s.gate_verdict();
        let rollout = if gate.permits_steering() {
            // No `describe()` here: on the converged path it only
            // restates the drift already printed. Refusals keep it
            // verbatim, where it carries the reason and the remedy.
            "A steering gate reads this same comparison and would permit a steer — this is the \
             positive evidence a rollout needs, and the counts behind it are bird's master4 plus \
             master6 against the mirror's v4+v6"
                .to_string()
        } else {
            state = state.worse_of(HealthState::Degraded);
            // `describe()` is the refusal an operator would see from the
            // steer itself, verbatim — including the staleness case,
            // which `assess` checks before it will look at drift at all.
            format!(
                "A steering gate reads this same comparison and REFUSES: {}",
                gate.describe()
            )
        };

        (state, format!("{counts} — {diagnostic}. {rollout}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    fn drift(fraction: f64, threshold: f64) -> Option<Drift> {
        Some(Drift {
            fraction,
            threshold,
            above: fraction >= threshold,
        })
    }

    /// A snapshot as the checker leaves it after one clean run: the same
    /// `Instant` in `last_run` and in the comparison.
    fn clean_run(at: Instant, bird: usize, mirror: usize, d: Option<Drift>) -> IntegritySnapshot {
        IntegritySnapshot {
            last_run: Some(at),
            last_comparison: Some(Comparison {
                at,
                bird_routes: bird,
                packetframe_routes: mirror,
                drift: d,
            }),
            bird_established_peers: Some(2),
            last_error: None,
        }
    }

    #[test]
    fn no_check_yet_is_its_own_state() {
        let p = IntegrityPosture::observe(&IntegritySnapshot::default(), t0());
        assert_eq!(p, IntegrityPosture::AwaitingFirstCheck);
        let h = p.subsystem_health();
        assert_eq!(h.name, SUBSYS_FIB_INTEGRITY);
        // No comparison has happened, so there is no success to age.
        assert_eq!(h.last_success_age_seconds, None);
    }

    /// The defect the vpp-offload runbook worked around: an operator
    /// could not tell "nothing has checked" from "checked and they
    /// agree". Both are Healthy; they must not read the same.
    #[test]
    fn no_check_yet_does_not_render_like_agreement() {
        let waiting =
            IntegrityPosture::observe(&IntegritySnapshot::default(), t0()).subsystem_health();
        let at = t0();
        let agreeing = IntegrityPosture::observe(
            &clean_run(at, 1_272_306, 1_272_281, drift(0.0000196, 0.01)),
            at + Duration::from_secs(30),
        )
        .subsystem_health();

        assert_eq!(waiting.state, HealthState::Healthy);
        assert_eq!(agreeing.state, HealthState::Healthy);
        assert_ne!(waiting.message, agreeing.message);

        let waiting_msg = waiting.message.unwrap();
        assert!(waiting_msg.contains("NOT agreement"), "{waiting_msg}");
        assert!(waiting_msg.contains("300s"), "{waiting_msg}");
        // The freshness field is the other half of the distinction.
        assert_eq!(waiting.last_success_age_seconds, None);
        assert_eq!(agreeing.last_success_age_seconds, Some(30));

        let agreeing_msg = agreeing.message.unwrap();
        assert!(agreeing_msg.contains("bird 1272306 routes, mirror 1272281"));
        assert!(agreeing_msg.contains("within the 1.000% warn threshold"));
    }

    #[test]
    fn drift_above_threshold_degrades_and_names_both_numbers() {
        let at = t0();
        let h = IntegrityPosture::observe(
            &clean_run(at, 1_272_306, 1_100_000, drift(0.1354, 0.01)),
            at + Duration::from_secs(12),
        )
        .subsystem_health();
        assert_eq!(h.state, HealthState::Degraded);
        let m = h.message.unwrap();
        assert!(m.contains("drift 13.540%"), "{m}");
        assert!(m.contains("1.000% warn threshold"), "{m}");
        // Still a completed comparison, so it still has an age.
        assert_eq!(h.last_success_age_seconds, Some(12));
    }

    /// Drift exactly ON the threshold. The checker's warn fires at
    /// `>=` while the gate converges at `<=`, so this is the one drift
    /// where the diagnostic and the rollout verdict legitimately
    /// disagree — the row must report both rather than let the warn
    /// speak for the gate. Reported Degraded either way, but the text
    /// must not claim a refusal that will not happen.
    #[test]
    fn drift_exactly_on_the_threshold_does_not_claim_a_refusal() {
        use packetframe_common::fib::STEER_MAX_DRIFT;
        let at = t0();
        // bird=1000, mirror=990 → drift exactly 0.01.
        let snap = clean_run(at, 1000, 990, drift(STEER_MAX_DRIFT, STEER_MAX_DRIFT));
        let s = match IntegrityPosture::observe(&snap, at) {
            IntegrityPosture::Checked { sample, .. } => sample.expect("a comparison"),
            other => panic!("expected Checked, got {other:?}"),
        };
        // The gate permits at the boundary; the warn fires at it.
        assert!(s.gate_verdict().permits_steering());
        assert!(s.drift.unwrap().above);

        let m = IntegrityPosture::observe(&snap, at)
            .subsystem_health()
            .message
            .unwrap();
        assert!(m.contains("at or above the 1.000% warn threshold"), "{m}");
        assert!(
            m.contains("would permit a steer"),
            "claimed a refusal the gate will not make: {m}"
        );
        assert!(!m.contains("REFUSES"), "{m}");
    }

    /// A tuned `drift-warn-fraction` is the range version of the same
    /// defect, and the reason aligning the two comparison operators
    /// would not have been enough: at a 5% warn threshold, a 3% drift
    /// is "within" fast-path's alarm while the gate — which uses its
    /// own fixed `STEER_MAX_DRIFT` — refuses outright.
    #[test]
    fn a_tuned_warn_threshold_does_not_speak_for_the_gate() {
        let at = t0();
        let snap = clean_run(at, 1_000_000, 970_000, drift(0.03, 0.05));
        let h = IntegrityPosture::observe(&snap, at).subsystem_health();
        let m = h.message.clone().unwrap();
        assert!(m.contains("within the 5.000% warn threshold"), "{m}");
        assert!(m.contains("REFUSES"), "{m}");
        assert_eq!(
            h.state,
            HealthState::Degraded,
            "the gate refuses, so the row cannot be healthy: {m}"
        );
    }

    /// The threshold travels with the comparison, so a non-default
    /// `drift_warn_fraction` is reported as the one actually applied
    /// rather than a constant re-read at render time.
    #[test]
    fn threshold_reported_is_the_one_the_run_applied() {
        let at = t0();
        let h = IntegrityPosture::observe(&clean_run(at, 1000, 995, drift(0.005, 0.05)), at)
            .subsystem_health();
        assert_eq!(h.state, HealthState::Healthy);
        assert!(h
            .message
            .unwrap()
            .contains("within the 5.000% warn threshold"));
    }

    /// The runbook's measured case: bird up, carrying 13 routes against
    /// a 1.3M mirror. Here the degenerate end of it — a bird with none.
    #[test]
    fn zero_authority_is_not_zero_drift() {
        let at = t0();
        let h =
            IntegrityPosture::observe(&clean_run(at, 0, 1_300_000, None), at).subsystem_health();
        assert_eq!(h.state, HealthState::Degraded);
        let m = h.message.unwrap();
        assert!(m.contains("NO routes in master4/master6"), "{m}");
        assert!(
            !m.contains("drift 0"),
            "a zero authority must not read as agreement: {m}"
        );
    }

    /// A comparison that has aged out is not evidence, however well the
    /// two counts agreed when it was taken. Without this the row printed
    /// "the positive evidence a rollout needs" indefinitely after the
    /// checker task stopped, because nothing recorded an error and no
    /// age fed the verdict.
    #[test]
    fn stale_sample_does_not_read_as_agreement() {
        let at = t0();
        let snap = clean_run(at, 1_272_306, 1_272_281, drift(0.0000196, 0.01));
        let stale = IntegrityPosture::observe(
            &snap,
            at + packetframe_common::fib::STEER_MAX_REPORT_AGE + Duration::from_secs(1),
        )
        .subsystem_health();
        assert_eq!(stale.state, HealthState::Degraded);
        let m = stale.message.unwrap();
        assert!(m.contains("REFUSES"), "{m}");
        // Verbatim from `Completeness::describe()`, so the row prints
        // the refusal the steer itself would print.
        assert!(m.contains("too old to act on"), "{m}");
        // Still a real completed comparison, so its age is still
        // reported — that number is the whole diagnosis here.
        assert_eq!(
            stale.last_success_age_seconds,
            Some(packetframe_common::fib::STEER_MAX_REPORT_AGE.as_secs() + 1)
        );
    }

    /// The row and the gate must flip at the same instant. They read the
    /// same comparison — the checker publishes it to both — so a status
    /// surface that says "proceed" while `assess` says `Stale` is worse
    /// than no surface at all. Pinned to the consumer's own constant, so
    /// changing one side without the other fails here.
    #[test]
    fn freshness_window_matches_the_steering_gate() {
        use packetframe_common::fib::{
            assess, Completeness, CompletenessReport, STEER_MAX_DRIFT, STEER_MAX_REPORT_AGE,
        };
        let at = t0();
        // Drift far below either threshold, so age is the only variable.
        let snap = clean_run(at, 1_000_000, 1_000_000, drift(0.0, 0.01));
        let report = CompletenessReport {
            authority_routes: 1_000_000,
            mirror_routes: 1_000_000,
            at,
        };
        for offset in [
            Duration::from_secs(0),
            STEER_MAX_REPORT_AGE - Duration::from_secs(1),
            STEER_MAX_REPORT_AGE,
            STEER_MAX_REPORT_AGE + Duration::from_secs(1),
            STEER_MAX_REPORT_AGE * 3,
        ] {
            let now = at + offset;
            let row_says_go = IntegrityPosture::observe(&snap, now)
                .subsystem_health()
                .state
                == HealthState::Healthy;
            let gate_says_go = matches!(
                assess(Some(report), now, STEER_MAX_DRIFT, STEER_MAX_REPORT_AGE),
                Completeness::Converged { .. }
            );
            assert_eq!(
                row_says_go, gate_says_go,
                "row and gate disagree at age {offset:?}: status healthy={row_says_go}, \
                 gate converged={gate_says_go}"
            );
        }
    }

    #[test]
    fn failed_check_with_no_history_says_there_is_no_verdict() {
        let at = t0();
        let snap = IntegritySnapshot {
            last_run: Some(at),
            last_comparison: None,
            bird_established_peers: None,
            last_error: Some("birdc show route count: spawn /usr/sbin/birdc: No such file".into()),
        };
        let h = IntegrityPosture::observe(&snap, at + Duration::from_secs(4)).subsystem_health();
        assert_eq!(h.state, HealthState::Degraded);
        assert_eq!(h.last_success_age_seconds, None);
        let m = h.message.unwrap();
        assert!(m.contains("no comparison has ever completed"), "{m}");
        assert!(m.contains("No such file"), "{m}");
    }

    /// A retained comparison must be labelled history. Presenting it as
    /// current is how an operator approves a rollout on a five-minute-old
    /// number from a checker that has since gone dark.
    #[test]
    fn retained_comparison_across_a_failed_run_is_labelled_history() {
        let compared_at = t0();
        let snap = IntegritySnapshot {
            last_run: Some(compared_at + Duration::from_secs(300)),
            last_comparison: Some(Comparison {
                at: compared_at,
                bird_routes: 1_272_306,
                packetframe_routes: 1_272_281,
                drift: drift(0.0000196, 0.01),
            }),
            bird_established_peers: Some(2),
            last_error: Some("programmer mirror_counts: channel closed".into()),
        };
        let p = IntegrityPosture::observe(&snap, compared_at + Duration::from_secs(305));
        match &p {
            IntegrityPosture::Checked { sample, .. } => {
                assert!(!sample.expect("a retained comparison").current)
            }
            other => panic!("expected Checked, got {other:?}"),
        }
        let h = p.subsystem_health();
        assert_eq!(h.state, HealthState::Degraded);
        // The age is the comparison's own, not the failed run's.
        assert_eq!(h.last_success_age_seconds, Some(305));
        let m = h.message.unwrap();
        assert!(m.contains("HISTORY"), "{m}");
        assert!(m.contains("channel closed"), "{m}");
    }

    /// The partial case: both route counts succeeded and `birdc show
    /// protocols` did not. The comparison is current and says so, and the
    /// error is still reported.
    #[test]
    fn error_alongside_a_current_comparison_keeps_the_comparison() {
        let at = t0();
        let mut snap = clean_run(at, 1000, 1000, drift(0.0, 0.01));
        snap.bird_established_peers = None;
        snap.last_error = Some("birdc show protocols: exit 1".into());
        let p = IntegrityPosture::observe(&snap, at + Duration::from_secs(2));
        match &p {
            IntegrityPosture::Checked { sample, .. } => {
                assert!(sample.expect("a comparison").current)
            }
            other => panic!("expected Checked, got {other:?}"),
        }
        let h = p.subsystem_health();
        // An error is an error, even beside a good comparison.
        assert_eq!(h.state, HealthState::Degraded);
        let m = h.message.unwrap();
        assert!(m.contains("is from this run and stands"), "{m}");
        assert!(!m.contains("HISTORY"), "{m}");
        assert!(m.contains("exit 1"), "{m}");
    }

    #[test]
    fn unread_snapshot_is_not_reported_as_never_checked() {
        let h = IntegrityPosture::Unread.subsystem_health();
        assert_eq!(h.state, HealthState::Degraded);
        assert_eq!(h.last_success_age_seconds, None);
        let m = h.message.unwrap();
        assert!(m.contains("Self-clearing"), "{m}");
        assert_ne!(
            Some(m),
            IntegrityPosture::AwaitingFirstCheck
                .subsystem_health()
                .message
        );
    }

    /// Every arm renders a message. A row with a state and no text is
    /// the silence this module was written to remove.
    #[test]
    fn every_posture_says_something() {
        let at = t0();
        for p in [
            IntegrityPosture::AwaitingFirstCheck,
            IntegrityPosture::Unread,
            IntegrityPosture::observe(&clean_run(at, 10, 10, drift(0.0, 0.01)), at),
            IntegrityPosture::observe(
                &IntegritySnapshot {
                    last_run: Some(at),
                    ..Default::default()
                },
                at,
            ),
        ] {
            let h = p.subsystem_health();
            let m = h.message.unwrap_or_default();
            assert!(!m.trim().is_empty(), "empty message for {p:?}");
            // Continuation lines in the source must not leak runs of
            // indentation into an operator's terminal — the same defect
            // vpp-offload's status arms shipped once.
            assert!(!m.contains("   "), "indentation leaked into {p:?}: {m}");
        }
    }
}
