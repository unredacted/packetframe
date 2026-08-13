//! Turns the supervisor's [`Action`] list into real effects.
//!
//! The supervisor decides *what* must happen and in *what order*; this
//! carries it out and reports back what actually happened. Keeping the
//! two apart is what lets the decisions be tested without a process and
//! the execution be tested without a decision.
//!
//! **This module is where the ordering rules stop being advisory.** The
//! supervisor returns a `Vec<Action>` whose order encodes an outage —
//! "unsteer then kill" and "kill then unsteer" differ by however long
//! MCAM keeps pointing traffic at a dead VF. An interpreter that
//! reordered, skipped, or continued blindly past a failure would
//! silently undo every guarantee upstream of it, and nothing in the
//! supervisor's own tests could notice.
//!
//! So the effects are a trait, and the rules below are tested against a
//! recording fake rather than trusted to review:
//!
//! 1. Actions run in the order given, with none skipped.
//! 2. `ReleaseResources` is withheld unless teardown actually
//!    succeeded — see [`Outcome::resources_leaked`].
//! 3. Every action that can fail produces either a follow-up event the
//!    supervisor understands, or a recorded failure. Silence is never
//!    an outcome.

use std::time::Duration;

use crate::process::Disposition;
use crate::runtime::SteerOutcome;
use crate::supervisor::{Action, Event};

/// Everything the executor does to the world outside itself.
///
/// A trait so the ordering and failure-handling rules can be tested
/// against a recorder. `Steer`/`Unsteer` are real
/// ([`crate::ntuple::NtupleSteering`]) and must **fail loudly** rather
/// than returning `Ok(())` on any doubt — a no-op steer that reports
/// success lets the supervisor believe traffic is diverted when nothing
/// is, and a no-op unsteer releases a VF that MCAM is still pointing
/// traffic at.
pub trait Effects {
    fn spawn(&mut self) -> Result<(), String>;

    /// Remove MCAM steering rules. First in any teardown.
    fn unsteer(&mut self) -> Result<(), String>;

    /// Reconcile MCAM steering rules to the current target. `Ok` says
    /// which side of the tier boundary that left the traffic on — see
    /// [`SteerOutcome`].
    fn steer(&mut self) -> Result<SteerOutcome, String>;

    /// Re-install steering for the intact adoptee, bypassing the
    /// completeness gate — see [`Action::RestoreSteer`] for why the
    /// gate inverts on this one path.
    fn restore_steer(&mut self) -> Result<SteerOutcome, String>;

    /// Whether the steering ledger currently names any rule in the NIC.
    ///
    /// Read after a failed [`Self::steer`] so the supervisor is *told*
    /// whether traffic is still diverted rather than assuming. A steer
    /// that fails may leave the NIC empty or holding rules that would
    /// not delete, and the two demand opposite handling — see
    /// [`Event::SteerFailed`].
    fn steering_in_place(&self) -> bool;

    /// Stop the process. Returns whether its resources may be released
    /// — see [`Disposition`].
    fn kill(&mut self) -> Disposition;

    fn attach_devices(&mut self) -> Result<(), String>;

    /// Begin (not complete) a FIB resync. The drain proceeds across
    /// ticks so the API ping and pidfd stay serviced; `SyncComplete`
    /// comes from the loop, not from here.
    fn start_resync(&mut self) -> Result<(), String>;

    fn start_verify(&mut self) -> Result<(), String>;

    /// Stop an in-flight resync/verify. Confirmation arrives later as
    /// `Event::ConvergenceStopped`, so this cannot fail meaningfully.
    fn abort_convergence(&mut self);

    fn arm_backoff(&mut self, delay: Duration);

    /// Release VF/hugepage resources. Only ever called when teardown
    /// succeeded; see rule 2.
    fn release_resources(&mut self) -> Result<(), String>;
}

/// What executing a batch of actions produced.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Events to feed back into the supervisor, in order.
    pub events: Vec<Event>,
    /// Actions that failed, with the reason, for status and logs.
    pub failures: Vec<(Action, String)>,
    /// Resources were NOT released because teardown did not fully
    /// succeed.
    ///
    /// The alternative to leaking is unbinding a VF or handing back
    /// hugepages while a process may still be DMAing into them, or
    /// while MCAM is still steering traffic at that VF. Both are memory
    /// corruption or a hard blackhole; a leaked VF is a line in
    /// `packetframe status` and a reboot's worth of inconvenience.
    pub resources_leaked: bool,
}

impl Outcome {
    pub fn ok(&self) -> bool {
        self.failures.is_empty() && !self.resources_leaked
    }
}

/// Execute `actions` in order, in full.
///
/// Failures are recorded and execution continues, with one exception
/// that is the whole point of rule 2: a failed `Unsteer`, or a `Kill`
/// that reports [`Disposition::MustLeak`], suppresses any later
/// `ReleaseResources`.
///
/// Why continue at all after a failure? Because the remaining actions
/// are usually the ones that contain the damage. If `Unsteer` fails,
/// abandoning the batch leaves a wedged VPP running *and* traffic
/// pointed at it; carrying on at least stops the process. What must not
/// happen is handing the resources back, and that is what gets
/// suppressed.
pub fn execute(actions: &[Action], fx: &mut dyn Effects) -> Outcome {
    let mut out = Outcome::default();
    // Set by anything that makes releasing resources unsafe.
    let mut teardown_clean = true;

    for action in actions {
        match action {
            Action::Unsteer => out.events.push(match fx.unsteer() {
                // Acknowledged, so the supervisor may believe steering
                // is down. Reporting this rather than letting `fail()`
                // assume it is what stops a later teardown from
                // releasing a VF that MCAM is still pointing at.
                Ok(()) => {
                    tracing::info!("steering DOWN: traffic returned to the eBPF fast-path tier");
                    Event::Unsteered
                }
                Err(e) => {
                    // Traffic is still being diverted to a dataplane we
                    // are about to stop supervising. Loud, and it
                    // forfeits the right to release the VF.
                    tracing::error!(
                        error = %e,
                        "steering could NOT be removed; traffic is still diverted into a VPP \
                         that is being stopped, and the VF will be withheld"
                    );
                    out.failures.push((*action, e));
                    teardown_clean = false;
                    Event::UnsteerFailed
                }
            }),
            Action::Kill => {
                if fx.kill() == Disposition::MustLeak {
                    out.failures.push((
                        *action,
                        "process survived termination; resources must not be released".into(),
                    ));
                    teardown_clean = false;
                    // Not just a leaked VF: the restart must not spawn a
                    // second VPP while this one can still own the API
                    // socket and DMA through the VF.
                    out.events.push(Event::TerminationFailed);
                }
            }
            Action::Spawn => out.events.push(match fx.spawn() {
                Ok(()) => Event::Spawned,
                Err(e) => {
                    out.failures.push((*action, e));
                    // No process exists, so no pidfd will ever report
                    // an exit — the retry has to be driven from here.
                    Event::SpawnFailed
                }
            }),
            Action::AttachDevices => {
                if let Err(e) = fx.attach_devices() {
                    out.failures.push((*action, e));
                    out.events.push(Event::ConvergenceFailed);
                }
            }
            Action::StartResync => {
                if let Err(e) = fx.start_resync() {
                    out.failures.push((*action, e));
                    out.events.push(Event::ConvergenceFailed);
                }
            }
            Action::StartVerify => {
                if let Err(e) = fx.start_verify() {
                    out.failures.push((*action, e));
                    out.events.push(Event::ConvergenceFailed);
                }
            }
            Action::RestoreSteer => out.events.push(match fx.restore_steer() {
                Ok(SteerOutcome::Steered) => {
                    tracing::info!(
                        "steering RESTORED: the adopted VPP's intact FIB takes the traffic \
                         back while the fallback is not ready"
                    );
                    Event::Steered
                }
                // The config stopped asking for this port between the
                // adoption and the revocation. Nothing to restore, and
                // the reconcile has cleared the adoptee's inherited
                // rules — which is the outcome, not a failure to
                // produce the other one.
                Ok(SteerOutcome::NothingToSteer) => {
                    tracing::info!(
                        "steering DOWN: no port is configured to steer, so the restore \
                         removed the adopted rules instead of re-installing them"
                    );
                    Event::NothingToSteer
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        rules_remain = fx.steering_in_place(),
                        "restore-steer failed; traffic stays on the eBPF tier"
                    );
                    out.failures.push((*action, e));
                    Event::SteerFailed {
                        rules_remain: fx.steering_in_place(),
                    }
                }
            }),
            Action::Steer => out.events.push(match fx.steer() {
                Ok(SteerOutcome::Steered) => {
                    // The one action that moves customer traffic between
                    // forwarding tiers. It had no log line at all until
                    // a shadow run came up steered with nothing in the
                    // log to say when, or by which path — the state
                    // field was the only record, and an incident
                    // reconstruction needs a timestamp.
                    tracing::info!(
                        "steering UP: allowlisted traffic is now diverted to VPP (the eBPF \
                         tier remains the failover)"
                    );
                    Event::Steered
                }
                // A reconcile whose target asks for nothing. It is a
                // SUCCESS and it moves traffic the other way, so it
                // gets the acknowledgement that says so rather than
                // `Event::Steered` — which would report an offload
                // carrying traffic it had just stopped carrying — or an
                // error, which is what left a refused `steer off`
                // retrying a no-op while its rules kept diverting.
                Ok(SteerOutcome::NothingToSteer) => {
                    tracing::info!(
                        "steering DOWN: no port is configured to steer, so the reconcile \
                         removed what was left and installed nothing; traffic is on the \
                         eBPF fast-path tier"
                    );
                    Event::NothingToSteer
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        rules_remain = fx.steering_in_place(),
                        "steer failed; traffic stays on the eBPF tier"
                    );
                    out.failures.push((*action, e));
                    // Verified but not steered as asked: reported, not
                    // papered over, and NOT a process restart — the
                    // dataplane is fine.
                    //
                    // `rules_remain` is read from the ledger AFTER the
                    // failure, because only the ledger knows whether the
                    // rollback emptied the NIC or left rules it could
                    // not delete. See `Event::SteerFailed`.
                    Event::SteerFailed {
                        rules_remain: fx.steering_in_place(),
                    }
                }
            }),
            Action::AbortConvergence => fx.abort_convergence(),
            Action::ArmBackoff(d) => fx.arm_backoff(*d),
            Action::ReleaseResources => {
                if !teardown_clean {
                    out.resources_leaked = true;
                    continue;
                }
                if let Err(e) = fx.release_resources() {
                    out.failures.push((*action, e));
                }
            }
        }
    }
    // Every failure goes to the JOURNAL, not only to the status
    // snapshot. `last_failures` carries these on `packetframe status`,
    // but a snapshot dies with the daemon — the first primary attach
    // (2026-08-13) restart-looped through eight teardowns whose reasons
    // existed only in status rows nobody captured, and the post-mortem
    // had to be reconstructed from the VPP side of the conversation.
    // The journal is the record that survives.
    for (action, why) in &out.failures {
        tracing::warn!(action = ?action, error = %why, "supervised action failed");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records calls in order and fails whichever ones it is told to.
    #[derive(Default)]
    struct Recorder {
        calls: Vec<&'static str>,
        fail_unsteer: bool,
        fail_steer: bool,
        fail_spawn: bool,
        fail_attach: bool,
        fail_resync: bool,
        fail_verify: bool,
        fail_release: bool,
        kill_disposition: Option<Disposition>,
        /// What the steering ledger reports after a failed steer.
        rules_remain: bool,
        /// The target asks for no port, so a reconcile installs nothing
        /// and removes whatever is left. Separate from `fail_steer`
        /// because it is a SUCCESS that moves traffic the other way.
        empty_target: bool,
    }

    impl Recorder {
        fn steer_result(&self) -> Result<SteerOutcome, String> {
            if self.fail_steer {
                return Err("no free MCAM loc".into());
            }
            Ok(if self.empty_target {
                SteerOutcome::NothingToSteer
            } else {
                SteerOutcome::Steered
            })
        }
    }

    impl Effects for Recorder {
        /// Whatever the test says the ledger holds after a steer.
        fn steering_in_place(&self) -> bool {
            self.rules_remain
        }
        fn spawn(&mut self) -> Result<(), String> {
            self.calls.push("spawn");
            err_if(self.fail_spawn, "no such binary")
        }
        fn unsteer(&mut self) -> Result<(), String> {
            self.calls.push("unsteer");
            err_if(self.fail_unsteer, "ioctl refused")
        }
        fn steer(&mut self) -> Result<SteerOutcome, String> {
            self.calls.push("steer");
            self.steer_result()
        }
        fn restore_steer(&mut self) -> Result<SteerOutcome, String> {
            self.calls.push("steer");
            self.steer_result()
        }
        fn kill(&mut self) -> Disposition {
            self.calls.push("kill");
            self.kill_disposition.unwrap_or(Disposition::SafeToRelease)
        }
        fn attach_devices(&mut self) -> Result<(), String> {
            self.calls.push("attach");
            err_if(self.fail_attach, "dev_attach refused")
        }
        fn start_resync(&mut self) -> Result<(), String> {
            self.calls.push("resync");
            err_if(self.fail_resync, "socket closed")
        }
        fn start_verify(&mut self) -> Result<(), String> {
            self.calls.push("verify");
            err_if(self.fail_verify, "socket closed")
        }
        fn abort_convergence(&mut self) {
            self.calls.push("abort");
        }
        fn arm_backoff(&mut self, _d: Duration) {
            self.calls.push("backoff");
        }
        fn release_resources(&mut self) -> Result<(), String> {
            self.calls.push("release");
            err_if(self.fail_release, "numvfs write failed")
        }
    }

    fn err_if(cond: bool, msg: &str) -> Result<(), String> {
        if cond {
            Err(msg.to_string())
        } else {
            Ok(())
        }
    }

    // ---- Invariant 1: order is preserved, nothing is skipped ----

    /// The teardown order IS the ≤50 ms number. Reordering these two is
    /// not a style question; it is how long MCAM keeps pointing traffic
    /// at a VF nothing is servicing.
    #[test]
    fn teardown_unsteers_before_it_kills() {
        let mut r = Recorder::default();
        let out = execute(
            &[
                Action::Unsteer,
                Action::Kill,
                Action::ArmBackoff(Duration::from_millis(250)),
            ],
            &mut r,
        );
        assert_eq!(r.calls, vec!["unsteer", "kill", "backoff"]);
        assert!(out.ok());
    }

    /// Devices before routes: a FIB path references an `sw_if_index`
    /// that does not exist until the device is attached.
    #[test]
    fn convergence_attaches_before_it_resyncs() {
        let mut r = Recorder::default();
        execute(&[Action::AttachDevices, Action::StartResync], &mut r);
        assert_eq!(r.calls, vec!["attach", "resync"]);
    }

    #[test]
    fn every_action_is_executed_exactly_once() {
        let mut r = Recorder::default();
        execute(
            &[
                Action::Unsteer,
                Action::AbortConvergence,
                Action::Kill,
                Action::ArmBackoff(Duration::from_secs(1)),
            ],
            &mut r,
        );
        assert_eq!(r.calls, vec!["unsteer", "abort", "kill", "backoff"]);
    }

    // ---- Invariant 2: resources are never released under a live
    // process or live steering ----

    /// The invariant this module exists to hold. A process that
    /// survived SIGKILL may still be DMAing into the buffers we are
    /// about to hand back to the kernel.
    #[test]
    fn a_process_that_survives_kill_blocks_resource_release() {
        let mut r = Recorder {
            kill_disposition: Some(Disposition::MustLeak),
            ..Default::default()
        };
        let out = execute(&[Action::Kill, Action::ReleaseResources], &mut r);

        assert_eq!(r.calls, vec!["kill"], "release must not be attempted");
        assert!(out.resources_leaked);
        assert!(!out.ok());
    }

    /// Same invariant from the other direction: if steering is still up,
    /// the VF is still receiving diverted traffic, so it is not ours to
    /// give back.
    #[test]
    fn a_failed_unsteer_blocks_resource_release() {
        let mut r = Recorder {
            fail_unsteer: true,
            ..Default::default()
        };
        let out = execute(
            &[Action::Unsteer, Action::Kill, Action::ReleaseResources],
            &mut r,
        );

        assert_eq!(
            r.calls,
            vec!["unsteer", "kill"],
            "the kill still happens — abandoning the batch would leave a \
             wedged VPP running AND traffic pointed at it"
        );
        assert!(out.resources_leaked);
        assert!(out.failures.iter().any(|(a, _)| *a == Action::Unsteer));
    }

    /// A clean teardown does release.
    #[test]
    fn a_clean_teardown_releases_resources() {
        let mut r = Recorder::default();
        let out = execute(
            &[Action::Unsteer, Action::Kill, Action::ReleaseResources],
            &mut r,
        );
        assert_eq!(r.calls, vec!["unsteer", "kill", "release"]);
        assert!(!out.resources_leaked);
        assert!(out.ok());
    }

    /// A release that fails on its own is a failure but not a leak: we
    /// had the right to release, the write just did not land.
    #[test]
    fn a_failed_release_is_reported_without_claiming_a_leak() {
        let mut r = Recorder {
            fail_release: true,
            ..Default::default()
        };
        let out = execute(&[Action::Kill, Action::ReleaseResources], &mut r);
        assert!(!out.resources_leaked);
        assert!(out
            .failures
            .iter()
            .any(|(a, _)| *a == Action::ReleaseResources));
    }

    // ---- Invariant 3: no action fails silently ----

    #[test]
    fn a_failed_spawn_reports_an_event_the_supervisor_understands() {
        let mut r = Recorder {
            fail_spawn: true,
            ..Default::default()
        };
        let out = execute(&[Action::Spawn], &mut r);
        assert_eq!(out.events, vec![Event::SpawnFailed]);
        assert!(out.failures.iter().any(|(a, _)| *a == Action::Spawn));
    }

    #[test]
    fn a_successful_spawn_reports_spawned() {
        let mut r = Recorder::default();
        let out = execute(&[Action::Spawn], &mut r);
        assert_eq!(out.events, vec![Event::Spawned]);
        assert!(out.ok());
    }

    /// Steering that could not be installed must say so, not report
    /// success — the supervisor gates `Steered` on this acknowledgement
    /// precisely so a failed MCAM install cannot look like a steered
    /// dataplane.
    #[test]
    fn a_failed_steer_reports_steer_failed_not_steered() {
        let mut r = Recorder {
            fail_steer: true,
            ..Default::default()
        };
        let out = execute(&[Action::Steer], &mut r);
        assert_eq!(
            out.events,
            vec![Event::SteerFailed {
                rules_remain: false
            }]
        );
        assert!(!out.events.contains(&Event::Steered));
    }

    #[test]
    fn a_successful_steer_reports_steered() {
        let mut r = Recorder::default();
        let out = execute(&[Action::Steer], &mut r);
        assert_eq!(out.events, vec![Event::Steered]);
    }

    /// A reconcile against a target that asks for nothing is a success
    /// that moves traffic the OTHER way, and the acknowledgement has to
    /// say which way.
    ///
    /// `Event::Steered` here would report an offload carrying traffic
    /// the reconcile had just stopped carrying — and would set
    /// `steered`, withholding the VF for rules that are no longer
    /// there. The seam is the only place the distinction can be made:
    /// by the time the supervisor sees an event, the outcome is a word.
    #[test]
    fn a_reconcile_to_an_empty_target_reports_nothing_to_steer() {
        for action in [Action::Steer, Action::RestoreSteer] {
            let mut r = Recorder {
                empty_target: true,
                ..Default::default()
            };
            let out = execute(&[action], &mut r);
            assert_eq!(out.events, vec![Event::NothingToSteer], "{action:?}");
            assert!(
                !out.events.contains(&Event::Steered),
                "{action:?}: nothing was steered"
            );
            assert!(
                out.ok(),
                "{action:?}: a reconcile that succeeded is not a failure"
            );
        }
    }

    /// A deterministic pipeline failure must not be left for the phase
    /// timeout to notice two minutes later.
    #[test]
    fn a_failed_attach_reports_convergence_failed_immediately() {
        let mut r = Recorder {
            fail_attach: true,
            ..Default::default()
        };
        let out = execute(&[Action::AttachDevices, Action::StartResync], &mut r);
        assert!(out.events.contains(&Event::ConvergenceFailed));
        // The batch still completes; the supervisor decides what the
        // events mean, not this loop.
        assert_eq!(r.calls, vec!["attach", "resync"]);
    }

    #[test]
    fn a_failed_resync_reports_convergence_failed() {
        let mut r = Recorder {
            fail_resync: true,
            ..Default::default()
        };
        let out = execute(&[Action::StartResync], &mut r);
        assert_eq!(out.events, vec![Event::ConvergenceFailed]);
    }

    #[test]
    fn a_failed_verify_start_reports_convergence_failed() {
        let mut r = Recorder {
            fail_verify: true,
            ..Default::default()
        };
        let out = execute(&[Action::StartVerify], &mut r);
        assert_eq!(out.events, vec![Event::ConvergenceFailed]);
    }

    /// Actions with nothing to report stay silent, so the supervisor is
    /// not fed events that did not happen.
    #[test]
    fn actions_with_no_outcome_emit_no_events() {
        let mut r = Recorder::default();
        let out = execute(
            &[
                Action::AbortConvergence,
                Action::ArmBackoff(Duration::from_secs(1)),
                Action::AttachDevices,
                Action::StartResync,
                Action::StartVerify,
                Action::Kill,
            ],
            &mut r,
        );
        assert!(out.events.is_empty(), "{:?}", out.events);
        assert!(out.ok());
    }

    #[test]
    fn an_empty_batch_does_nothing() {
        let mut r = Recorder::default();
        let out = execute(&[], &mut r);
        assert!(r.calls.is_empty());
        assert_eq!(out, Outcome::default());
    }

    // ---- The two halves composed ----
    //
    // Each half is tested in isolation above and in supervisor.rs. What
    // neither can catch alone is a mistake in the seam: an event the
    // executor produces that the supervisor mishandles, or a batch whose
    // follow-up events drive the wrong next batch. These drive both
    // together, feeding executor output back in as supervisor input.

    use crate::supervisor::{State, Supervisor};

    /// Apply one event, execute what it asks for, and feed the resulting
    /// events back until the system settles.
    fn step(sup: &mut Supervisor, r: &mut Recorder, event: Event) {
        let mut pending = vec![event];
        // Bounded: a seam that will not settle is itself the bug, and an
        // unbounded loop would hang the suite instead of reporting it.
        for _ in 0..16 {
            if pending.is_empty() {
                return;
            }
            let mut next = Vec::new();
            for e in pending.drain(..) {
                let actions = sup.on(e);
                next.extend(execute(&actions, r).events);
            }
            pending = next;
        }
        panic!("the supervisor/executor seam did not settle");
    }

    fn bring_up_steered(sup: &mut Supervisor, r: &mut Recorder) {
        step(sup, r, Event::StartRequested);
        step(sup, r, Event::ApiUp);
        step(sup, r, Event::SyncComplete);
        step(sup, r, Event::VerifyPassed);
        // First attach does not steer itself — that is the operator's
        // canary lever. Do it explicitly.
        step(sup, r, Event::Steered);
        assert_eq!(sup.state(), State::Steered);
        assert!(sup.is_steered());
    }

    #[test]
    fn a_crash_while_steered_unsteers_first_then_restarts() {
        let mut sup = Supervisor::new();
        let mut r = Recorder::default();
        bring_up_steered(&mut sup, &mut r);
        r.calls.clear();

        step(&mut sup, &mut r, Event::ProcessExited { status: None });

        assert_eq!(
            r.calls.first(),
            Some(&"unsteer"),
            "steering must come down before anything else: {:?}",
            r.calls
        );
        assert!(r.calls.contains(&"kill"));
        assert!(r.calls.contains(&"backoff"));
        assert!(!sup.is_steered());
        assert_eq!(sup.state(), State::Backoff);
        // Crucially: no resource release on a crash we intend to recover
        // from.
        assert!(!r.calls.contains(&"release"), "{:?}", r.calls);
    }

    /// The full recovery, end to end: crash while steered → restart →
    /// resync → verify → steering restored, and in that order.
    #[test]
    fn recovery_restores_steering_only_after_a_verified_resync() {
        let mut sup = Supervisor::new();
        let mut r = Recorder::default();
        bring_up_steered(&mut sup, &mut r);

        step(&mut sup, &mut r, Event::ProcessExited { status: None });
        r.calls.clear();

        step(&mut sup, &mut r, Event::BackoffElapsed);
        step(&mut sup, &mut r, Event::ApiUp);
        step(&mut sup, &mut r, Event::SyncComplete);
        step(&mut sup, &mut r, Event::VerifyPassed);

        // The order of the recovery is the invariant: attach, then
        // routes, then verify, and only then traffic.
        let pos = |name: &str| r.calls.iter().position(|c| *c == name);
        let (attach, resync, verify, steer) = (
            pos("attach").expect("attached"),
            pos("resync").expect("resynced"),
            pos("verify").expect("verified"),
            pos("steer").expect("steered"),
        );
        assert!(attach < resync, "devices before routes: {:?}", r.calls);
        assert!(resync < verify, "routes before verification: {:?}", r.calls);
        assert!(
            verify < steer,
            "traffic must not be diverted before the FIB is verified: {:?}",
            r.calls
        );
        assert_eq!(sup.state(), State::Steered);
        assert!(sup.is_steered());
    }

    /// Adoption composed: a surviving steered VPP is resynced and
    /// verified with traffic still flowing, and `unsteer` is never
    /// called.
    #[test]
    fn adoption_never_unsteers_a_forwarding_dataplane() {
        let mut sup = Supervisor::new();
        let mut r = Recorder::default();

        step(&mut sup, &mut r, Event::Adopted { steered: true });
        step(&mut sup, &mut r, Event::SyncComplete);
        step(&mut sup, &mut r, Event::VerifyPassed);

        assert!(
            !r.calls.contains(&"unsteer"),
            "tearing steering down to rebuild it is the outage adoption avoids: {:?}",
            r.calls
        );
        assert!(!r.calls.contains(&"spawn"), "{:?}", r.calls);
        assert_eq!(sup.state(), State::Steered);
    }

    /// A failed steer during recovery must leave the system verified but
    /// NOT steered, and must not restart the process — the dataplane is
    /// healthy, so cycling it would trade an idle forwarder for an
    /// outage.
    #[test]
    fn a_failed_steer_during_recovery_does_not_cycle_the_process() {
        let mut sup = Supervisor::new();
        let mut r = Recorder::default();
        bring_up_steered(&mut sup, &mut r);
        step(&mut sup, &mut r, Event::ProcessExited { status: None });
        step(&mut sup, &mut r, Event::BackoffElapsed);
        step(&mut sup, &mut r, Event::ApiUp);
        step(&mut sup, &mut r, Event::SyncComplete);

        r.fail_steer = true;
        r.calls.clear();
        step(&mut sup, &mut r, Event::VerifyPassed);

        assert!(
            r.calls.contains(&"steer"),
            "it was attempted: {:?}",
            r.calls
        );
        assert_eq!(sup.state(), State::Ready, "verified but not steered");
        assert!(!sup.is_steered());
        assert!(
            !r.calls.contains(&"kill"),
            "a healthy dataplane must not be cycled for a steering failure: {:?}",
            r.calls
        );
    }

    /// A spawn that fails must land in backoff and retry, not stall —
    /// this is the seam that made `SpawnFailed` necessary.
    #[test]
    fn a_failed_spawn_reaches_backoff_through_the_seam() {
        let mut sup = Supervisor::new();
        let mut r = Recorder {
            fail_spawn: true,
            ..Default::default()
        };

        step(&mut sup, &mut r, Event::StartRequested);
        assert_eq!(sup.state(), State::Backoff, "{:?}", r.calls);
        assert!(r.calls.contains(&"backoff"));
        assert!(sup.may_restart());

        // And the retry actually runs.
        r.fail_spawn = false;
        r.calls.clear();
        step(&mut sup, &mut r, Event::BackoffElapsed);
        assert_eq!(r.calls, vec!["spawn"]);
        assert_eq!(sup.state(), State::Starting);
    }

    /// A deterministic attach failure reaches backoff immediately rather
    /// than waiting out the convergence budget.
    #[test]
    fn a_failed_attach_reaches_backoff_without_waiting_for_the_timeout() {
        let mut sup = Supervisor::new();
        let mut r = Recorder {
            fail_attach: true,
            ..Default::default()
        };

        step(&mut sup, &mut r, Event::StartRequested);
        step(&mut sup, &mut r, Event::ApiUp);

        assert_eq!(sup.state(), State::Backoff, "{:?}", r.calls);
        assert!(
            r.calls.contains(&"abort"),
            "the half-started convergence must be told to stop: {:?}",
            r.calls
        );
        assert!(
            !sup.may_restart(),
            "and the restart waits for it to confirm"
        );
        step(&mut sup, &mut r, Event::ConvergenceStopped);
        assert!(sup.may_restart());
    }

    /// The cross-batch hole. A failed `Unsteer` used to be forgotten
    /// when `execute` returned, *and* the supervisor cleared `steered`
    /// optimistically — so a later `StopRequested` emitted no `Unsteer`
    /// at all and its fresh, clean batch released a VF that MCAM was
    /// still pointing traffic at.
    #[test]
    fn a_failed_unsteer_still_withholds_the_vf_in_a_later_batch() {
        let mut sup = Supervisor::new();
        let mut r = Recorder {
            fail_unsteer: true,
            ..Default::default()
        };
        bring_up_steered(&mut sup, &mut r);

        // Crash while steered. The unsteer fails.
        step(&mut sup, &mut r, Event::ProcessExited { status: None });
        assert!(
            sup.is_steered(),
            "a failed unsteer must NOT be recorded as unsteered"
        );

        // Now a clean stop, in a brand-new batch.
        r.calls.clear();
        let actions = sup.on(Event::StopRequested);
        assert!(
            actions.contains(&Action::Unsteer),
            "the retry must be attempted because we still believe we steer: {actions:?}"
        );
        let out = execute(&actions, &mut r);
        assert!(
            !r.calls.contains(&"release"),
            "the VF is still receiving diverted traffic: {:?}",
            r.calls
        );
        assert!(out.resources_leaked);
    }

    /// The same path when the unsteer eventually succeeds: the VF is
    /// then genuinely ours to release.
    #[test]
    fn an_unsteer_that_succeeds_on_retry_permits_release() {
        let mut sup = Supervisor::new();
        let mut r = Recorder {
            fail_unsteer: true,
            ..Default::default()
        };
        bring_up_steered(&mut sup, &mut r);
        step(&mut sup, &mut r, Event::ProcessExited { status: None });
        assert!(sup.is_steered());

        r.fail_unsteer = false;
        r.calls.clear();
        let actions = sup.on(Event::StopRequested);
        let out = execute(&actions, &mut r);
        assert_eq!(r.calls, vec!["unsteer", "kill", "release"]);
        assert!(out.ok());
        // Feeding the ack back settles the belief.
        for e in out.events {
            sup.on(e);
        }
        assert!(!sup.is_steered());
    }

    /// A process that survived termination must not be joined by a
    /// second one. `ArmBackoff` alone would let `BackoffElapsed` spawn
    /// another VPP onto the same API socket and VF.
    #[test]
    fn a_process_that_survives_kill_blocks_the_restart() {
        let mut sup = Supervisor::new();
        let mut r = Recorder {
            kill_disposition: Some(Disposition::MustLeak),
            ..Default::default()
        };
        step(&mut sup, &mut r, Event::StartRequested);
        step(&mut sup, &mut r, Event::Wedged);

        assert_eq!(sup.state(), State::Backoff);
        assert!(sup.is_undead(), "the old process may still be alive");
        assert!(
            !sup.may_restart(),
            "a second VPP on the same VF is worse than staying down"
        );

        // The pidfd eventually reports the exit; only then may we retry.
        sup.on(Event::ProcessExited { status: None });
        assert!(!sup.is_undead());
        assert!(sup.may_restart());
        r.calls.clear();
        r.kill_disposition = None;
        step(&mut sup, &mut r, Event::BackoffElapsed);
        assert_eq!(r.calls, vec!["spawn"]);
    }

    /// A clean stop releases resources; a stop whose teardown fails does
    /// not. This is the invariant-2 path through the seam.
    #[test]
    fn a_clean_stop_releases_but_a_failed_teardown_leaks() {
        let mut sup = Supervisor::new();
        let mut r = Recorder::default();
        bring_up_steered(&mut sup, &mut r);
        r.calls.clear();

        let actions = sup.on(Event::StopRequested);
        let out = execute(&actions, &mut r);
        assert_eq!(r.calls, vec!["unsteer", "kill", "release"]);
        assert!(out.ok());
        assert_eq!(sup.state(), State::Stopped);

        // Same stop, but the process will not die.
        let mut sup = Supervisor::new();
        let mut r = Recorder::default();
        bring_up_steered(&mut sup, &mut r);
        r.calls.clear();
        r.kill_disposition = Some(Disposition::MustLeak);

        let actions = sup.on(Event::StopRequested);
        let out = execute(&actions, &mut r);
        assert!(!r.calls.contains(&"release"), "{:?}", r.calls);
        assert!(out.resources_leaked);
    }
}
