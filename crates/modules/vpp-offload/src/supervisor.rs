//! Supervision state machine for the VPP child.
//!
//! Pure logic: no processes, no sockets, no clock reads. Everything
//! arrives as an [`Event`] and leaves as an [`Action`], which is what
//! makes the ordering rules below testable at all — the failure modes
//! that matter (a crash while steered, an adoption of a healthy VPP, a
//! restart racing a resync) are exactly the ones that are miserable to
//! reproduce against a live process.
//!
//! Four ordering rules are encoded here, each from a specific way this
//! can go wrong:
//!
//! 1. **Steering is never enabled before a verified resync.** MCAM
//!    diverts by allowlist, not by what we managed to install, so
//!    steering into an unverified FIB blackholes whatever is missing —
//!    and the diverted packet cannot fall back to the eBPF tier
//!    because the hardware already took it.
//! 2. **On process death while steered, steering dies FIRST.** That is
//!    the ≤50 ms number: until the MCAM rules are gone, every steered
//!    packet is going to a VF nothing is servicing. Restart comes
//!    after.
//! 3. **Adoption does NOT unsteer.** A packetframe restart that finds
//!    a healthy VPP still forwarding must resync and verify *while
//!    traffic keeps flowing*; tearing steering down to rebuild it
//!    would create precisely the outage adoption exists to avoid.
//! 4. **No restart while a resync is in flight.** Backoff is measured
//!    against the recovery budget, so a crash loop cannot become a
//!    resync loop that never converges.

use std::time::Duration;

/// Ceiling on restart backoff.
///
/// Deliberately below the published 90 s recovery number: a backoff
/// longer than the recovery budget would mean the *waiting* dominates
/// the outage, and the operator-visible promise would be a function of
/// this constant rather than of how long a resync actually takes.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// First retry delay. Short because the common crash is a transient
/// one and the FIB is still warm in bird's mirror.
pub const BASE_BACKOFF: Duration = Duration::from_millis(250);

/// How long VPP may take to answer its binary API after spawn before
/// we give up on it.
///
/// Without this, `Starting` is a **trap with no exit**. A VPP that
/// lives but deadlocks before opening its API socket generates no
/// event at all: `ApiUp` never arrives, the pidfd stays quiet because
/// the process is alive, and the wedge detector cannot help because it
/// only starts once the API has answered at least once. Forwarding
/// would stay down until an operator noticed.
///
/// Generous, because startup genuinely takes time on this platform:
/// VPP allocates and faults in a multi-GB main heap on 512 MiB
/// hugepages, then probes and attaches the device. Being wrong in the
/// slow direction costs a longer first attach; being wrong in the fast
/// direction restart-loops a VPP that was about to come up.
pub const API_STARTUP_BUDGET: Duration = Duration::from_secs(60);

/// How long a resync + verify cycle may take before we treat it as
/// hung.
///
/// Same failure shape as [`API_STARTUP_BUDGET`]: a resync that never
/// finishes emits neither `SyncComplete` nor a failure, so `Syncing`
/// would also be a trap. Sized above the ≤60 s convergence budget the
/// full v4 table is measured against, with room for the verify pass —
/// exceeding it means something is wrong, not merely slow.
pub const CONVERGENCE_BUDGET: Duration = Duration::from_secs(120);

/// A group of states that share one deadline.
///
/// Exists so a multi-state phase is bounded as a whole rather than
/// per-state. Startup is one state today, but naming it keeps the
/// schedule from having to infer the grouping from a duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhaseKind {
    /// Spawned, waiting for the API to answer.
    Startup,
    /// Attach → resync → verify, budgeted as one cycle.
    Convergence,
}

/// Where the supervised VPP is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing running; not trying to.
    Stopped,
    /// Waiting out a backoff before the next start attempt.
    Backoff,
    /// Process exists, API not yet answering.
    Starting,
    /// API answering; devices attached; FIB resync in flight.
    Syncing,
    /// Resync drained; readback verification in flight.
    Verifying,
    /// Verified. Steering may be enabled — and only from here.
    Ready,
    /// Traffic is being diverted to VPP.
    Steered,
    /// Adopted a running VPP that is still steered. Resync and verify
    /// run WITHOUT tearing steering down (rule 3), so this is
    /// deliberately distinct from `Syncing`.
    AdoptedResyncing,
}

impl State {
    /// Whether a supervised process exists that could die or wedge.
    ///
    /// `Backoff` deliberately counts as NO process: the previous one
    /// is already dead and its failure already counted. Without this,
    /// a ping timeout landing just after an exit is handled would
    /// count a second failure and double the backoff for one crash.
    pub fn has_process(self) -> bool {
        !matches!(self, State::Stopped | State::Backoff)
    }
}
// NOTE: there is deliberately no `State::is_converging()`. Deriving
// "a resync is in flight" from the lifecycle state is what broke rule
// 4: `fail()` moves the state to `Backoff`, which is not a converging
// state, so the guard vanished exactly when VPP died mid-convergence.
// Ask `Supervisor::is_converging()`, which tracks the real thing.
// `State::is_steered()` is absent for the same reason.

/// Something that happened to the supervised process or its FIB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Operator or module asked for VPP to be running.
    StartRequested,
    /// A child was spawned successfully.
    Spawned,
    /// fork/exec failed — the binary is missing, not yet installed, or
    /// the mount is briefly unavailable. Distinct from
    /// `ProcessExited` because no process ever existed, so no pidfd
    /// will report anything and the retry has to be driven from here.
    SpawnFailed,
    /// A pre-existing VPP was adopted from the state file. `steered`
    /// records whether its MCAM rules are still in place, which
    /// decides whether we may keep traffic flowing through it.
    Adopted {
        steered: bool,
    },
    /// The binary API answered.
    ApiUp,
    /// The pending map drained to empty.
    SyncComplete,
    /// Readback verification finished.
    VerifyPassed,
    VerifyFailed,
    /// Verification found nothing *wrong*, but the FIB is **incomplete**:
    /// routes are withheld at the capacity high-water mark or
    /// unresolvable.
    ///
    /// A third outcome because collapsing it into either of the other two
    /// is wrong in a different way. As `VerifyFailed` it would cycle a
    /// perfectly healthy VPP and turn the designed response to a table
    /// that outgrew its heap into a restart loop. As `VerifyPassed` it
    /// re-steers traffic into a FIB known to be missing prefixes —
    /// `VerifyOutcome::passed()` deliberately ignores `withheld`, and
    /// `SinkCounts::blocks_first_steer()` was the intended gate but
    /// nothing consulted it, so a restart of a previously-steered VPP
    /// would divert traffic into the incomplete table and blackhole
    /// exactly the prefixes that did not fit.
    ///
    /// So: reach `Ready` without restarting, and do **not** steer. The
    /// want is preserved, so the next complete verify re-steers.
    VerifyIncomplete,
    /// A step in the attach → resync pipeline failed outright: the
    /// device would not attach, or the transport broke mid-drain.
    ///
    /// Distinct from `VerifyFailed`, which means "VPP is answering and
    /// its FIB is wrong". This means the pipeline itself did not run.
    /// Without it a deterministic attach failure would sit in `Syncing`
    /// until `CONVERGENCE_BUDGET` expired — two minutes of waiting for
    /// something already known to have failed.
    ConvergenceFailed,
    /// Steering rules installed.
    Steered,
    /// The process exited — from pidfd, not SIGCHLD, because adoption
    /// reparents the child and SIGCHLD would never arrive.
    ProcessExited {
        status: Option<i32>,
    },
    /// The API ping did not answer within its interval. The process is
    /// alive but not scheduling; treated as death because a wedged
    /// forwarder drops exactly as thoroughly as a dead one.
    Wedged,
    /// The current phase outran its budget — [`API_STARTUP_BUDGET`] in
    /// `Starting`, [`CONVERGENCE_BUDGET`] while converging.
    ///
    /// Exists because those phases are otherwise **exitless**: a VPP
    /// that is alive but not answering, or a resync that never
    /// finishes, produces no event whatsoever. The caller arms a
    /// deadline from [`Supervisor::phase_budget`] and sends this when
    /// it fires.
    PhaseTimedOut,
    /// Installing the MCAM rules failed. The dataplane is verified but
    /// traffic is not going where it was asked to go.
    ///
    /// `rules_remain` is **observed from the steering ledger**, not
    /// inferred: [`crate::ntuple::NtupleSteering::steer`] rolls back
    /// all-or-nothing, so a failure may leave the NIC empty (clean
    /// rollback) or holding rules the NIC refused to delete — and on a
    /// *reconcile* of an already-steering port the rollback removes the
    /// rules that were working a moment ago. Nothing in the lifecycle
    /// state distinguishes those, so the executor reads the ledger and
    /// says which.
    ///
    /// Guessing either way is wrong in a way that matters. Assuming
    /// rules remain reports a steered, healthy offload over an empty NIC
    /// — traffic is on the eBPF tier and every surface says otherwise.
    /// Assuming they are gone suppresses the `Unsteer` teardown owes and
    /// releases a VF that MCAM may still target.
    SteerFailed {
        rules_remain: bool,
    },
    /// MCAM rules are confirmed removed.
    ///
    /// Steering is only believed *down* on this acknowledgement, for
    /// the same reason it is only believed *up* on `Steered`: an
    /// optimistic clear meant a later teardown saw `steered == false`,
    /// emitted no `Unsteer`, and happily released a VF that MCAM was
    /// still pointing traffic at.
    Unsteered,
    /// Removing the MCAM rules failed. Traffic is still diverted to a
    /// dataplane we are trying to stop — `steered` stays true so every
    /// later teardown keeps trying and keeps withholding the VF.
    UnsteerFailed,
    /// The process survived termination (uninterruptible sleep, most
    /// likely on a VFIO or DMA call).
    ///
    /// Blocks the restart: spawning a second VPP while the first still
    /// owns the API socket and can DMA through the VF is worse than
    /// staying down. Cleared when the pidfd finally reports the exit.
    TerminationFailed,
    /// An aborted resync or verify has actually finished unwinding.
    ///
    /// The supervisor cannot observe this itself: the work runs in the
    /// caller's task, so only the caller knows when it has stopped
    /// touching the transport. Until it arrives,
    /// [`Supervisor::may_restart`] stays false so a restart cannot
    /// stack a second load onto one VPP.
    ConvergenceStopped,
    /// Backoff elapsed.
    BackoffElapsed,
    /// This attach inherited MCAM rules with no process behind them.
    ///
    /// Steering is NIC state, so a VPP that died steered leaves its
    /// rules diverting allowlisted traffic into a VF nothing is
    /// servicing — a blackhole that started when it died and that a
    /// fresh spawn does not end, since reaching `Ready` takes a full
    /// convergence and the machine never steers a first attach on its
    /// own.
    ///
    /// Reported rather than cleaned up by the caller so the ordinary
    /// teardown ordering handles it: `Unsteer` first, and if the NIC
    /// refuses, `steered` stays true and the VF stays withheld. The
    /// *want* is recorded too — steering was established and never
    /// deliberately stopped — so the replacement re-steers once it
    /// verifies, which is what closes the blackhole.
    InheritedSteering,
    /// The operator turned the canary lever ON: a `steer on` appeared,
    /// or the allowlist changed under a port that is already steering.
    ///
    /// Distinct from `VerifyPassed`'s automatic re-steer because the
    /// machine deliberately never steers a first attach on its own —
    /// that decision is the operator's, and this is how they make it
    /// without a restart. The caller must have called
    /// [`crate::runtime::Steering::retarget`] first; `Action::Steer`
    /// reconciles the NIC to whatever the target now is.
    SteerRequested,
    /// The operator turned the canary lever OFF — the rollback landing
    /// zone. Membership stays, the FIB stays synced, traffic goes back
    /// to the fallback tier.
    UnsteerRequested,
    /// Operator asked for a clean stop.
    StopRequested,
}

/// What the caller must do. Ordering within a single transition is
/// significant and given as a `Vec`, because "unsteer then restart"
/// and "restart then unsteer" differ by an outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Remove MCAM rules. First in any teardown.
    Unsteer,
    /// Kill the process if it is still alive.
    Kill,
    /// Spawn a new VPP.
    Spawn,
    /// Attach devices and create interfaces over the API.
    AttachDevices,
    /// Begin a full FIB resync against the authoritative mirror.
    StartResync,
    /// Begin readback verification.
    StartVerify,
    /// Install MCAM steering rules.
    Steer,
    /// Stop an in-flight resync/verify. Paired with
    /// `Event::ConvergenceStopped`, which reports when it has actually
    /// wound down — the restart waits for that, not for this.
    AbortConvergence,
    /// Arm the backoff timer.
    ArmBackoff(Duration),
    /// Release VF/hugepage resources; terminal.
    ReleaseResources,
}

/// Supervision state plus the backoff schedule.
#[derive(Debug, Clone)]
pub struct Supervisor {
    state: State,
    /// Consecutive failures since the last verified-healthy moment.
    failures: u32,
    /// Whether MCAM rules are diverting traffic RIGHT NOW.
    ///
    /// A field rather than a property of [`State`], because the two are
    /// genuinely orthogonal and adoption proves it: an adopted VPP is
    /// steered while it is still syncing and verifying. Deriving this
    /// from the lifecycle state meant `AdoptedResyncing → Verifying`
    /// silently dropped it, so a verify failure — or a crash, wedge, or
    /// stop during that window — killed VPP *without* removing the
    /// steering rules first, leaving traffic diverted to a VF nothing
    /// was servicing. That is precisely the blackhole the ≤50 ms
    /// teardown rule exists to prevent.
    steered: bool,
    /// Whether steering is *wanted*, as distinct from in place.
    ///
    /// Set when steering has been established, when an adopted VPP came
    /// with rules already live, and when a steer attempt failed —
    /// remembered across a restart so `Ready` knows whether to re-steer
    /// automatically or wait for the operator's canary. Cleared only by
    /// a deliberate full stop.
    ///
    /// Named for the want rather than the past tense (it was
    /// `was_steered`) because the failed-attempt case makes the past
    /// tense wrong: a
    /// first attach whose MCAM insert failed never had steering up, yet
    /// steering is unambiguously wanted. A field whose name mis-describes
    /// its contents is how the next bug gets written.
    steer_wanted: bool,
    /// Whether a resync or verify task is still running.
    ///
    /// A field for the same reason `steered` is one: derived from the
    /// lifecycle state it was wrong in exactly the case that matters.
    /// `fail()` moves the state straight to `Backoff`, and `Backoff` is
    /// not a converging state — so `may_restart()` said yes while the
    /// resync task was still unwinding, and rule 4 ("no restart while a
    /// resync is in flight") failed precisely when VPP died *during*
    /// convergence, which is when it is most likely to.
    ///
    /// Only the caller knows when its task has truly stopped, so this
    /// is cleared by `Event::ConvergenceStopped`, not by a state change.
    converging: bool,
    /// A previous process survived termination and may still be alive.
    ///
    /// Blocks the restart. Spawning a second VPP while the first still
    /// owns the API socket and can DMA through the VF is worse than
    /// staying down — and `ArmBackoff` alone would have let
    /// `BackoffElapsed` do exactly that. Cleared only when the pidfd
    /// reports the exit.
    undead: bool,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            state: State::Stopped,
            failures: 0,
            steered: false,
            steer_wanted: false,
            converging: false,
            undead: false,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// Whether MCAM rules are currently diverting traffic to VPP.
    pub fn is_steered(&self) -> bool {
        self.steered
    }

    /// Whether steering is *wanted* — in place, or established once and
    /// not deliberately stopped, or attempted and failed.
    ///
    /// This is the predicate `VerifyPassed` uses to decide whether to
    /// re-steer, exposed so the health surface reports the same thing the
    /// machine acts on rather than a second guess at it.
    ///
    /// **Not** config intent: the machine deliberately never steers a
    /// first attach on its own (that is the operator's canary), so a
    /// `steer on` port that has never yet steered and never failed to
    /// reads as not-wanted here. The distinction is real — one is the
    /// designed staging state, the other is a rollout that broke.
    pub fn steer_intended(&self) -> bool {
        self.steered || self.steer_wanted
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Backoff for the current failure count: exponential, capped.
    ///
    /// No jitter, deliberately — there is exactly one supervised
    /// process per box and nothing to thunder against, and a
    /// deterministic schedule is one fewer variable when reading a
    /// crash loop out of logs.
    pub fn backoff(&self) -> Duration {
        if self.failures == 0 {
            return BASE_BACKOFF;
        }
        let shift = (self.failures - 1).min(16);
        BASE_BACKOFF
            .checked_mul(1u32 << shift)
            .unwrap_or(MAX_BACKOFF)
            .min(MAX_BACKOFF)
    }

    /// Apply an event, returning the ordered actions to perform.
    pub fn on(&mut self, event: Event) -> Vec<Action> {
        use Event::*;
        use State::*;

        match (self.state, event) {
            // --- starting up ---
            (Stopped, StartRequested) => {
                self.state = Starting;
                vec![Action::Spawn]
            }
            (Backoff, BackoffElapsed) => {
                self.state = Starting;
                vec![Action::Spawn]
            }
            (Starting, Spawned) => vec![],
            // fork/exec itself failed — no process exists, so no pidfd
            // will ever report an exit. Without an explicit event the
            // supervisor would sit in `Starting` forever: `Starting`
            // ignores both StartRequested and BackoffElapsed, so the
            // retry policy it has would never run.
            (Starting, SpawnFailed) => self.fail(),
            // VPP is alive but never answered. Without this the state
            // is exitless — see API_STARTUP_BUDGET.
            (Starting, PhaseTimedOut) => self.fail(),
            (Starting, ApiUp) => {
                self.state = Syncing;
                self.converging = true;
                // Devices first: the FIB paths we are about to install
                // reference interface indices that do not exist until
                // the device is attached and its port interface
                // created.
                vec![Action::AttachDevices, Action::StartResync]
            }

            // --- adoption (rule 3) ---
            (Stopped | Backoff | Starting, Adopted { steered }) => {
                self.steered = steered;
                self.steer_wanted = steered;
                self.converging = true;
                // An adopted VPP is presumed good until proven stale:
                // mark dirty, resync, verify — but do NOT unsteer a
                // correctly-forwarding dataplane to do it.
                self.state = if steered { AdoptedResyncing } else { Syncing };
                vec![Action::AttachDevices, Action::StartResync]
            }

            // --- converging ---
            (Syncing | AdoptedResyncing, SyncComplete) => {
                self.state = Verifying;
                vec![Action::StartVerify]
            }
            // A resync or verify that never finishes is the same trap
            // as a VPP that never answers.
            (Syncing | AdoptedResyncing | Verifying, PhaseTimedOut) => self.fail(),
            // The pipeline broke rather than merely being slow.
            //
            // `converging` is deliberately NOT cleared here, unlike on
            // `VerifyFailed`. A failed verify has *finished* — the task
            // reported its own result, so nothing is in flight. A failed
            // pipeline step says nothing about the other steps: an
            // attach failure still leaves the resync that was started
            // after it running against the transport. So `fail()` emits
            // `AbortConvergence` and the restart waits for the caller's
            // `ConvergenceStopped`, which is the only thing that knows.
            (Syncing | AdoptedResyncing | Verifying, ConvergenceFailed) => self.fail(),
            (Verifying, VerifyPassed) => {
                self.failures = 0;
                self.converging = false;
                // Steer if traffic was flowing before the disruption —
                // or is still flowing, in the adopted case. A first
                // attach waits for the operator's explicit canary;
                // that is the whole point of `steer on|off` being per
                // port.
                //
                // Steer is emitted even when we believe we are already
                // steered. On this platform that is not redundant: the
                // UniFi controller wipes custom classifier state on
                // provisioning and deploys, so rules we installed
                // before a restart may simply be gone. Re-asserting
                // them is the reconcile step, and it is cheap.
                //
                // The state does NOT become `Steered` here. Installing
                // MCAM rules can fail, and claiming success before the
                // action has run would report a steered dataplane whose
                // rules were never installed — failures cleared, no
                // retry, traffic quietly still on the fallback tier.
                // `Event::Steered` is the acknowledgement, exactly as
                // on the first-attach path.
                self.state = Ready;
                if self.steer_intended() {
                    vec![Action::Steer]
                } else {
                    vec![]
                }
            }
            // Correct as far as it goes, but incomplete: settle into the
            // safe staging state rather than diverting traffic into a FIB
            // with known holes. Not a failure — restarting would trade a
            // partially-working forwarder for an outage and would loop,
            // because the next resync withholds the same routes.
            (Verifying | AdoptedResyncing, VerifyIncomplete) => {
                self.converging = false;
                self.failures = 0;
                self.state = Ready;
                vec![]
            }
            (Verifying, VerifyFailed) => {
                // A FIB we cannot verify is not one to divert traffic
                // into. Treat as a failure and cycle, rather than
                // steering optimistically.
                self.converging = false;
                self.fail()
            }
            (Ready, Event::Steered) => {
                self.state = State::Steered;
                self.steered = true;
                self.steer_wanted = true;
                vec![]
            }

            // Rules without a process. Believed steered on the strength
            // of the record, because that is the only evidence there is
            // — and believing it is what makes the teardown emit
            // `Unsteer` and withhold the VF if the removal is refused.
            //
            // Only from `Stopped`: this is an attach-time fact, injected
            // before the first `StartRequested`. Anywhere else it would
            // be describing a process that exists.
            (Stopped, InheritedSteering) => {
                self.steered = true;
                self.steer_wanted = true;
                vec![Action::Unsteer]
            }

            // --- the canary lever, turned without a restart ---
            //
            // Legal only from the two converged states. Everywhere else
            // there is either no verified FIB to divert traffic into or
            // a teardown in progress, and both make an operator's steer
            // request something to decline rather than to queue: a
            // request that survives a crash and fires against the
            // replacement is not what was asked for.
            //
            // From `Ready` this is the first steer. From `Steered` it is
            // a reconcile — the target changed underneath live rules —
            // and the state deliberately does not move, because traffic
            // never stopped being diverted.
            (Ready | State::Steered, SteerRequested) => {
                self.steer_wanted = true;
                vec![Action::Steer]
            }
            // Believed down only on `Unsteered`, exactly as everywhere
            // else. The state returns to `Ready` because that is what
            // membership-without-steering is — the designed staging
            // state — but `steered` is left for the acknowledgement, so
            // a refused removal keeps the VF withheld.
            (Ready | State::Steered, UnsteerRequested) => {
                self.steer_wanted = false;
                self.state = Ready;
                if self.steered {
                    vec![Action::Unsteer]
                } else {
                    vec![]
                }
            }

            // --- death and wedging ---
            (s, ProcessExited { .. }) if s.has_process() => {
                // Proof it is gone, whatever we believed before.
                self.undead = false;
                if self.steered {
                    self.steer_wanted = true;
                }
                self.fail()
            }
            // A wedge says the process is NOT scheduling; it says
            // nothing about whether it is alive, so `undead` is left
            // alone here.
            (s, Wedged) if s.has_process() => {
                if self.steered {
                    self.steer_wanted = true;
                }
                self.fail()
            }
            // A late exit for a process we had already given up on. Not
            // a new failure — but it IS the proof the restart has been
            // waiting for.
            (s, ProcessExited { .. }) if !s.has_process() => {
                self.undead = false;
                vec![]
            }

            // Steering could not be installed. We stay verified but
            // UNSTEERED — the safe staging state, and one an operator
            // can see. Deliberately not a `fail()`: the dataplane is
            // fine, so killing and restarting VPP would trade a
            // working-but-idle forwarder for an outage. `steered` is
            // left untouched, because on the adopted path the previous
            // rules may still be live and claiming otherwise would
            // suppress the Unsteer we owe on teardown.
            //
            // But the *want* is recorded. On a first attach nothing else
            // records it — the machine never steers a first attach on
            // its own — so without this line a failed rollout is
            // indistinguishable from a deliberate `steer off`: no retry
            // on the next `VerifyPassed`, and every health surface reads
            // it as the designed staging state. Same defect shape as the
            // rest of this file: an attempt that failed left no trace.
            //
            // Reachable from `State::Steered` too, since a reconfigure
            // re-steers a live port — and that is the case where leaving
            // `steered` alone was actively wrong: the rollback empties
            // the NIC, so the machine would sit in `Steered`, report the
            // steering subsystem Healthy with no message, and publish
            // `packetframe_vpp_state{state="steered"}` while every
            // steered packet was in fact on the eBPF tier. `state`
            // returns to `Ready` because that is where "verified, not
            // diverting what we asked" belongs.
            (Ready | State::Steered, SteerFailed { rules_remain }) => {
                self.steer_wanted = true;
                self.steered = rules_remain;
                self.state = Ready;
                vec![]
            }

            // --- steering acknowledgements ---
            (_, Unsteered) => {
                self.steered = false;
                vec![]
            }
            // Traffic is still diverted. `steered` stays true so the
            // next teardown tries again and keeps withholding the VF.
            (_, UnsteerFailed) => vec![],

            // --- convergence bookkeeping ---
            (_, ConvergenceStopped) => {
                self.converging = false;
                vec![]
            }
            (_, TerminationFailed) => {
                self.undead = true;
                vec![]
            }

            // --- clean stop ---
            (_, StopRequested) => {
                let mut actions = Vec::new();
                // Same rule as `fail()`: believed down only on the ack.
                if self.steered {
                    actions.push(Action::Unsteer);
                }
                if self.converging {
                    actions.push(Action::AbortConvergence);
                }
                actions.push(Action::Kill);
                actions.push(Action::ReleaseResources);
                self.state = Stopped;
                self.steer_wanted = false;
                self.failures = 0;
                actions
            }

            // Anything else is a no-op: events can race (a ping
            // timeout arriving just after an exit), and treating a
            // stale event as a state change is how a supervisor
            // restarts something it already restarted.
            _ => vec![],
        }
    }

    /// Common teardown for death, wedging, and failed verification.
    ///
    /// Steering comes down FIRST (rule 2) — until it does, every
    /// steered packet is going to a VF nothing is servicing.
    fn fail(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        // Unsteer FIRST and unconditionally on the current fact, not on
        // the lifecycle state: until the MCAM rules are gone, every
        // steered packet is going to a VF nothing is servicing.
        //
        // `steered` is NOT cleared here. Clearing it optimistically
        // meant a failed unsteer still recorded "not steered", so a
        // later teardown emitted no Unsteer at all and released a VF
        // that MCAM was still pointing traffic at. `Event::Unsteered`
        // is the acknowledgement, symmetric with `Steered`.
        if self.steered {
            actions.push(Action::Unsteer);
        }
        // Tell the caller to wind down any resync/verify still running.
        // `converging` stays true until it confirms with
        // `ConvergenceStopped`, which is what holds the restart back —
        // this action only asks.
        if self.converging {
            actions.push(Action::AbortConvergence);
        }
        actions.push(Action::Kill);
        self.failures = self.failures.saturating_add(1);
        let delay = self.backoff();
        self.state = State::Backoff;
        actions.push(Action::ArmBackoff(delay));
        actions
    }

    /// Whether a resync or verify is still running.
    pub fn is_converging(&self) -> bool {
        self.converging
    }

    /// How long the current phase may take before the caller should
    /// send `Event::PhaseTimedOut`. `None` = no deadline applies.
    ///
    /// The caller arms this rather than the supervisor, which owns no
    /// clock — but the *budget* belongs here, next to the states it
    /// bounds.
    pub fn phase_budget(&self) -> Option<Duration> {
        self.phase().map(|(_, budget)| budget)
    }

    /// The current phase and its budget, or `None` when no deadline
    /// applies.
    ///
    /// The **kind** matters as much as the duration. `CONVERGENCE_BUDGET`
    /// is documented as covering a resync *plus* verify, but `Syncing`,
    /// `AdoptedResyncing` and `Verifying` are three distinct states —
    /// so re-arming a fresh budget on each transition would hand out
    /// 120 s for the resync and another 120 s for the verify, twice the
    /// number the constant claims to be. States that share a kind share
    /// one deadline, and only a change of kind restarts the clock.
    ///
    /// Which states share a deadline is supervisor knowledge, so it
    /// lives here rather than in [`crate::schedule::Schedule`], which
    /// only does the arithmetic.
    pub fn phase(&self) -> Option<(PhaseKind, Duration)> {
        match self.state {
            State::Starting => Some((PhaseKind::Startup, API_STARTUP_BUDGET)),
            State::Syncing | State::AdoptedResyncing | State::Verifying => {
                Some((PhaseKind::Convergence, CONVERGENCE_BUDGET))
            }
            _ => None,
        }
    }

    /// Whether a restart may be started right now (rule 4).
    ///
    /// Gated on the `converging` FIELD, not on the lifecycle state.
    /// `fail()` sets the state to `Backoff`, which is not a converging
    /// state, so a state-derived check returned true while the resync
    /// task was still unwinding — the guard evaporated exactly when VPP
    /// died mid-convergence. The caller checks this before acting on
    /// `BackoffElapsed`; starting another attempt would stack two loads
    /// onto one VPP.
    pub fn may_restart(&self) -> bool {
        !self.converging && !self.undead
    }

    /// Whether a process we tried to kill may still be alive.
    pub fn is_undead(&self) -> bool {
        self.undead
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running_and_steered() -> Supervisor {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::Spawned);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        s.on(Event::VerifyPassed);
        s.on(Event::Steered);
        assert_eq!(s.state(), State::Steered);
        s
    }

    #[test]
    fn first_attach_does_not_steer_itself() {
        // Steering is the operator's canary lever; a fresh attach
        // reaching Ready must WAIT rather than divert traffic on its
        // own initiative.
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        let actions = s.on(Event::VerifyPassed);
        assert_eq!(s.state(), State::Ready);
        assert!(
            !actions.contains(&Action::Steer),
            "a first attach must not steer without being asked"
        );
    }

    #[test]
    fn devices_are_attached_before_the_resync() {
        // FIB paths reference interface indices that do not exist
        // until the device is attached — installing first would defer
        // every route.
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        let actions = s.on(Event::ApiUp);
        assert_eq!(
            actions,
            vec![Action::AttachDevices, Action::StartResync],
            "device attach must precede the resync"
        );
    }

    #[test]
    fn steering_is_never_reached_without_a_passing_verify() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        assert_eq!(s.state(), State::Verifying);
        // A Steered event arriving out of order must not promote us.
        s.on(Event::Steered);
        assert_eq!(s.state(), State::Verifying, "verify gates steering");
    }

    #[test]
    fn a_crash_while_steered_unsteers_before_anything_else() {
        // The 50 ms number: until MCAM is torn down, steered packets
        // go to a VF nothing services.
        let mut s = running_and_steered();
        let actions = s.on(Event::ProcessExited { status: Some(139) });
        assert_eq!(actions[0], Action::Unsteer, "unsteer must come first");
        assert!(actions.contains(&Action::Kill));
        assert!(matches!(actions.last(), Some(Action::ArmBackoff(_))));
        assert_eq!(s.state(), State::Backoff);
    }

    #[test]
    fn a_wedge_is_treated_exactly_like_a_death() {
        // A process that is alive but not scheduling drops just as
        // thoroughly as one that exited.
        let mut s = running_and_steered();
        let actions = s.on(Event::Wedged);
        assert_eq!(actions[0], Action::Unsteer);
        assert!(actions.contains(&Action::Kill));
    }

    #[test]
    fn adoption_of_a_steered_vpp_does_not_unsteer_it() {
        // Rule 3, and the reason AdoptedResyncing exists as its own
        // state: tearing steering down to rebuild it would create the
        // outage adoption exists to avoid.
        let mut s = Supervisor::new();
        let actions = s.on(Event::Adopted { steered: true });
        assert_eq!(s.state(), State::AdoptedResyncing);
        assert!(
            !actions.contains(&Action::Unsteer),
            "a correctly-forwarding VPP must keep forwarding"
        );
        assert!(s.is_steered());
        assert_eq!(actions, vec![Action::AttachDevices, Action::StartResync]);
    }

    /// The window the `steered` field exists to protect. An adopted
    /// VPP is steered while it syncs AND while it verifies; if
    /// steered-ness is derived from the lifecycle state, the
    /// `AdoptedResyncing → Verifying` step silently drops it and every
    /// teardown from there kills VPP with traffic still pointed at it.
    #[test]
    fn a_steered_adoptee_that_fails_verification_is_unsteered_first() {
        let mut s = Supervisor::new();
        s.on(Event::Adopted { steered: true });
        s.on(Event::SyncComplete);
        assert_eq!(s.state(), State::Verifying);
        assert!(s.is_steered(), "still forwarding while we verify");

        let actions = s.on(Event::VerifyFailed);
        assert_eq!(
            actions.first(),
            Some(&Action::Unsteer),
            "steering must come down BEFORE the kill: {actions:?}"
        );
        assert!(actions.contains(&Action::Kill));
        // Still believed steered until the removal is acknowledged —
        // clearing it optimistically is what let a later teardown skip
        // the Unsteer and release a VF MCAM still pointed at.
        assert!(s.is_steered(), "not down until confirmed down");
        s.on(Event::Unsteered);
        assert!(!s.is_steered());
    }

    /// Same window, reached by the other three exits.
    #[test]
    fn every_teardown_during_adopted_verification_unsteers_first() {
        for event in [
            Event::VerifyFailed,
            Event::ProcessExited { status: None },
            Event::Wedged,
            Event::StopRequested,
        ] {
            let mut s = Supervisor::new();
            s.on(Event::Adopted { steered: true });
            s.on(Event::SyncComplete);
            let actions = s.on(event.clone());
            assert_eq!(
                actions.first(),
                Some(&Action::Unsteer),
                "{event:?} tore down without unsteering: {actions:?}"
            );
            // Believed steered until acknowledged; the acknowledgement
            // is what clears it.
            assert!(s.is_steered(), "{event:?} cleared it optimistically");
            s.on(Event::Unsteered);
            assert!(!s.is_steered(), "{event:?} left us believing we steer");
        }
    }

    /// A spawn that never produced a process still has to retry. There
    /// is no pidfd to report an exit, and `Starting` ignores both
    /// StartRequested and BackoffElapsed, so without this the
    /// supervisor sits in `Starting` forever with its retry policy
    /// intact and unreachable.
    #[test]
    fn a_failed_spawn_backs_off_and_retries() {
        let mut s = Supervisor::new();
        assert_eq!(s.on(Event::StartRequested), vec![Action::Spawn]);
        assert_eq!(s.state(), State::Starting);

        let actions = s.on(Event::SpawnFailed);
        assert_eq!(s.state(), State::Backoff);
        assert!(
            actions.iter().any(|a| matches!(a, Action::ArmBackoff(_))),
            "a failed spawn must arm the retry: {actions:?}"
        );
        assert_eq!(s.failures(), 1);
        assert!(s.may_restart());

        // And the retry actually fires.
        assert_eq!(s.on(Event::BackoffElapsed), vec![Action::Spawn]);
        assert_eq!(s.state(), State::Starting);
    }

    /// Repeated spawn failures escalate rather than hammering.
    #[test]
    fn repeated_spawn_failures_escalate_the_backoff() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        let mut last = Duration::ZERO;
        for _ in 0..5 {
            s.on(Event::SpawnFailed);
            let d = s.backoff();
            assert!(d >= last, "backoff went backwards: {d:?} after {last:?}");
            last = d;
            s.on(Event::BackoffElapsed);
        }
        assert!(last <= MAX_BACKOFF);
    }

    /// A spawn failure while nothing was ever steered must not invent
    /// an Unsteer for rules that do not exist.
    #[test]
    fn an_unsteered_failure_does_not_emit_unsteer() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        let actions = s.on(Event::SpawnFailed);
        assert!(!actions.contains(&Action::Unsteer), "{actions:?}");
    }

    #[test]
    fn adoption_resyncs_and_verifies_then_keeps_steering() {
        let mut s = Supervisor::new();
        s.on(Event::Adopted { steered: true });
        s.on(Event::SyncComplete);
        assert_eq!(s.state(), State::Verifying);
        let actions = s.on(Event::VerifyPassed);
        assert!(
            actions.contains(&Action::Steer),
            "re-assert rules after adoption so ours own them"
        );
        // Pending, not done: the rules are not confirmed installed
        // until the action reports back.
        assert_eq!(s.state(), State::Ready);
        s.on(Event::Steered);
        assert_eq!(s.state(), State::Steered);
        assert!(s.is_steered());
    }

    /// `Starting` used to be a trap with no exit: a VPP that lives but
    /// never opens its API emits nothing at all — no `ApiUp`, no pidfd
    /// exit (it is alive), and no wedge event (the detector only starts
    /// after the first answer). Forwarding stayed down until a human
    /// noticed.
    #[test]
    fn a_vpp_that_never_answers_its_api_is_not_waited_on_forever() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        assert_eq!(s.state(), State::Starting);
        assert_eq!(
            s.phase_budget(),
            Some(API_STARTUP_BUDGET),
            "the caller needs a deadline to arm"
        );

        let actions = s.on(Event::PhaseTimedOut);
        assert_eq!(s.state(), State::Backoff);
        assert!(actions.contains(&Action::Kill));
        assert!(actions.iter().any(|a| matches!(a, Action::ArmBackoff(_))));
        assert!(s.may_restart(), "nothing was converging");
        assert_eq!(s.on(Event::BackoffElapsed), vec![Action::Spawn]);
    }

    /// Same trap, one phase later: a resync that never finishes.
    #[test]
    fn a_hung_resync_times_out_instead_of_hanging_forever() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ApiUp);
        assert_eq!(s.state(), State::Syncing);
        assert_eq!(s.phase_budget(), Some(CONVERGENCE_BUDGET));

        let actions = s.on(Event::PhaseTimedOut);
        assert_eq!(s.state(), State::Backoff);
        assert!(
            actions.contains(&Action::AbortConvergence),
            "the hung task must be told to stop: {actions:?}"
        );
    }

    /// Rule 4 through the path that actually breaks it. `fail()` sets
    /// the state to `Backoff`, which is not a converging *state* — so a
    /// state-derived `may_restart()` said yes while the resync task was
    /// still unwinding, and the guard evaporated exactly when VPP died
    /// mid-convergence.
    #[test]
    fn a_death_during_convergence_blocks_restart_until_the_task_stops() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ApiUp);
        assert!(s.is_converging());

        let actions = s.on(Event::ProcessExited { status: None });
        assert_eq!(s.state(), State::Backoff);
        assert!(
            actions.contains(&Action::AbortConvergence),
            "must ask the resync to wind down: {actions:?}"
        );
        assert!(
            !s.may_restart(),
            "a restart here would stack two loads onto one VPP"
        );

        // The action only ASKS. Only the caller knows when its task has
        // actually stopped touching the transport.
        s.on(Event::ConvergenceStopped);
        assert!(s.may_restart());
    }

    /// A steer that fails must not be reported as success. The
    /// first-attach path always waited for an acknowledgement; the
    /// automatic-restore path assumed it.
    #[test]
    fn a_failed_steer_leaves_us_verified_but_unsteered() {
        let mut s = running_and_steered();
        s.on(Event::ProcessExited { status: None });
        s.on(Event::BackoffElapsed);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        let actions = s.on(Event::VerifyPassed);
        assert!(actions.contains(&Action::Steer));
        assert_eq!(s.state(), State::Ready);

        // Rules could not be installed.
        assert_eq!(s.on(Event::SteerFailed { rules_remain: true }), vec![]);
        assert_eq!(
            s.state(),
            State::Ready,
            "verified but not steered — the safe staging state"
        );
        // And it must NOT be reported as a running steered dataplane.
        assert_ne!(s.state(), State::Steered);
    }

    /// A steer that fails on a **first** attach must record that
    /// steering is wanted.
    ///
    /// Nothing else records it on this path — the machine deliberately
    /// never steers a first attach on its own — so without it a broken
    /// rollout is byte-for-byte identical to a deliberate `steer off`:
    /// never retried on the next convergence cycle, and reported by
    /// health as the designed staging state. Same shape as the other
    /// bugs in this file: an attempt that failed left no trace.
    #[test]
    fn a_failed_first_attach_steer_is_remembered_and_retried() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::Spawned);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        assert!(
            !s.on(Event::VerifyPassed).contains(&Action::Steer),
            "a first attach is the operator's canary, not ours"
        );
        assert!(!s.steer_intended(), "nothing has asked for steering yet");

        // The operator's canary fires and the MCAM insert fails.
        s.on(Event::SteerFailed {
            rules_remain: false,
        });
        assert!(!s.is_steered());
        assert!(
            s.steer_intended(),
            "the want must survive the failure, or it is indistinguishable \
             from `steer off`"
        );

        // The next convergence cycle retries it rather than silently
        // leaving traffic on the fallback tier forever.
        s.on(Event::ProcessExited { status: None });
        s.on(Event::BackoffElapsed);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        assert!(
            s.on(Event::VerifyPassed).contains(&Action::Steer),
            "a remembered want must drive a retry"
        );
    }

    /// The inverse, so the fix above cannot quietly turn every staged
    /// box into a steering one: a port that was never asked to steer
    /// stays unsteered across restarts.
    #[test]
    fn a_never_steered_dataplane_is_never_auto_steered() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::Spawned);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        s.on(Event::VerifyPassed);
        s.on(Event::ProcessExited { status: None });
        s.on(Event::BackoffElapsed);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        assert!(!s.on(Event::VerifyPassed).contains(&Action::Steer));
        assert!(!s.steer_intended());
    }

    /// An incomplete FIB settles into the staging state: no restart, no
    /// steer.
    ///
    /// Both collapses are wrong. As a failure it would cycle a healthy
    /// VPP and loop, because the next resync withholds the same routes.
    /// As a pass it would re-steer a previously-steered deployment into a
    /// FIB missing exactly the prefixes that did not fit — and
    /// `VerifyOutcome::passed()` ignores `withheld` by design, so nothing
    /// downstream would have caught it.
    #[test]
    fn an_incomplete_verify_reaches_ready_without_steering() {
        let mut s = running_and_steered();
        s.on(Event::ProcessExited { status: None });
        // The executor's acknowledgement that the MCAM rules are gone —
        // steering is only believed down on this, never optimistically.
        s.on(Event::Unsteered);
        s.on(Event::BackoffElapsed);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        assert_eq!(s.state(), State::Verifying);

        let actions = s.on(Event::VerifyIncomplete);
        assert_eq!(s.state(), State::Ready, "verified, just not complete");
        assert!(
            !actions.contains(&Action::Steer),
            "must not divert traffic into a FIB with known holes"
        );
        assert!(!s.is_steered());
        assert_eq!(s.failures(), 0, "not a failure — nothing to back off from");
        assert!(
            s.steer_intended(),
            "the want survives, so a later complete verify re-steers"
        );

        // And that is exactly what happens once the table fits again.
        s.on(Event::ProcessExited { status: None });
        s.on(Event::Unsteered);
        s.on(Event::BackoffElapsed);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        assert!(s.on(Event::VerifyPassed).contains(&Action::Steer));
    }

    /// Adoption takes the same path: an adopted VPP whose table is
    /// incomplete must not have its steering re-asserted on that basis.
    #[test]
    fn an_incomplete_adopted_verify_also_declines_to_steer() {
        let mut s = Supervisor::new();
        s.on(Event::Adopted { steered: true });
        s.on(Event::SyncComplete);
        let actions = s.on(Event::VerifyIncomplete);
        assert!(!actions.contains(&Action::Steer));
        assert_eq!(s.state(), State::Ready);
    }

    #[test]
    fn adoption_of_an_unsteered_vpp_waits_for_the_canary() {
        let mut s = Supervisor::new();
        s.on(Event::Adopted { steered: false });
        assert_eq!(s.state(), State::Syncing);
        s.on(Event::SyncComplete);
        let actions = s.on(Event::VerifyPassed);
        assert_eq!(s.state(), State::Ready);
        assert!(!actions.contains(&Action::Steer));
    }

    #[test]
    fn a_restart_re_steers_only_if_traffic_was_flowing_before() {
        let mut s = running_and_steered();
        s.on(Event::ProcessExited { status: None });
        s.on(Event::BackoffElapsed);
        assert_eq!(s.state(), State::Starting);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        let actions = s.on(Event::VerifyPassed);
        assert!(
            actions.contains(&Action::Steer),
            "traffic was flowing before the crash, so restore it"
        );
        assert_eq!(s.state(), State::Ready, "awaiting the steer ack");
        s.on(Event::Steered);
        assert_eq!(s.state(), State::Steered);
    }

    #[test]
    fn no_restart_while_a_resync_is_in_flight() {
        // Rule 4: a crash loop must not become a resync loop.
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ApiUp);
        assert_eq!(s.state(), State::Syncing);
        assert!(!s.may_restart(), "a draining resync blocks a restart");
        s.on(Event::SyncComplete);
        assert!(!s.may_restart(), "so does an in-flight verify");
        s.on(Event::VerifyPassed);
        assert!(s.may_restart());
    }

    #[test]
    fn a_failed_verify_cycles_rather_than_steering_optimistically() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        let actions = s.on(Event::VerifyFailed);
        assert_eq!(s.state(), State::Backoff);
        assert!(actions.contains(&Action::Kill));
        assert_eq!(s.failures(), 1);
    }

    #[test]
    fn backoff_grows_then_caps_below_the_recovery_budget() {
        let mut s = Supervisor::new();
        assert_eq!(s.backoff(), BASE_BACKOFF);
        let mut seen = Vec::new();
        for _ in 0..12 {
            s.on(Event::StartRequested);
            s.on(Event::ProcessExited { status: None });
            seen.push(s.backoff());
            s.on(Event::BackoffElapsed);
        }
        assert!(
            seen.windows(2).all(|w| w[1] >= w[0]),
            "backoff must be monotonic: {seen:?}"
        );
        assert_eq!(*seen.last().unwrap(), MAX_BACKOFF);
        assert!(
            MAX_BACKOFF < Duration::from_secs(90),
            "a backoff above the recovery budget would make the published \
             number a function of this constant rather than of resync time"
        );
    }

    #[test]
    fn a_healthy_verify_clears_the_failure_count() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ProcessExited { status: None });
        s.on(Event::ProcessExited { status: None });
        assert!(s.failures() >= 1);
        s.on(Event::BackoffElapsed);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        s.on(Event::VerifyPassed);
        assert_eq!(s.failures(), 0, "a healthy cycle resets the schedule");
        assert_eq!(s.backoff(), BASE_BACKOFF);
    }

    #[test]
    fn a_stale_event_is_a_no_op_not_a_second_restart() {
        // A ping timeout can land just after an exit was handled.
        // Acting on both would restart something already restarting.
        let mut s = running_and_steered();
        s.on(Event::ProcessExited { status: None });
        let failures = s.failures();
        let actions = s.on(Event::Wedged);
        assert!(actions.is_empty(), "the second event must do nothing");
        assert_eq!(s.failures(), failures, "and must not count twice");
    }

    #[test]
    fn stop_unsteers_then_kills_then_releases() {
        let mut s = running_and_steered();
        let actions = s.on(Event::StopRequested);
        assert_eq!(
            actions,
            vec![Action::Unsteer, Action::Kill, Action::ReleaseResources],
            "teardown order is steering, process, resources"
        );
        assert_eq!(s.state(), State::Stopped);
    }

    #[test]
    fn stopping_an_unsteered_supervisor_skips_the_unsteer() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        let actions = s.on(Event::StopRequested);
        assert!(!actions.contains(&Action::Unsteer));
        assert_eq!(actions, vec![Action::Kill, Action::ReleaseResources]);
    }

    #[test]
    fn events_while_stopped_do_nothing() {
        let mut s = Supervisor::new();
        assert!(s.on(Event::ProcessExited { status: None }).is_empty());
        assert!(s.on(Event::Wedged).is_empty());
        assert_eq!(s.state(), State::Stopped);
        assert_eq!(s.failures(), 0);
    }

    /// Turning the canary lever on from the staging state.
    ///
    /// The whole point of `reconfigure`: the rollout's first steer, and
    /// every step after it, must not cost a VPP restart — that is ~40 s
    /// of resync with the offload down, per step.
    fn ready_unsteered() -> Supervisor {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::Spawned);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        s.on(Event::VerifyPassed);
        assert_eq!(s.state(), State::Ready);
        assert!(!s.is_steered());
        s
    }

    #[test]
    fn an_operator_can_steer_a_ready_vpp_without_a_restart() {
        let mut s = ready_unsteered();
        assert_eq!(s.on(Event::SteerRequested), vec![Action::Steer]);
        // The state does NOT move on the request. `Steered` is the
        // acknowledgement, exactly as on the automatic path: claiming it
        // here would report a steered dataplane whose MCAM inserts had
        // not yet been attempted.
        assert_eq!(s.state(), State::Ready);
        assert!(!s.is_steered());

        s.on(Event::Steered);
        assert_eq!(s.state(), State::Steered);
        assert!(s.is_steered());
    }

    /// A refused canary step leaves the *want* recorded, so the next
    /// verify retries it — the same rule the automatic path follows.
    #[test]
    fn a_refused_operator_steer_is_not_mistaken_for_steer_off() {
        let mut s = ready_unsteered();
        s.on(Event::SteerRequested);
        s.on(Event::SteerFailed {
            rules_remain: false,
        });
        assert!(!s.is_steered(), "nothing was diverted");
        assert!(
            s.steer_intended(),
            "a rollout that broke must be distinguishable from the designed staging state"
        );
    }

    /// Turning it off is the rollback landing zone: membership stays,
    /// the FIB stays synced, traffic returns to the fallback tier.
    #[test]
    fn unsteering_on_request_returns_to_the_staging_state() {
        let mut s = running_and_steered();
        assert_eq!(s.on(Event::UnsteerRequested), vec![Action::Unsteer]);
        assert_eq!(s.state(), State::Ready);
        assert!(
            s.is_steered(),
            "still believed steered until the removal is acknowledged — releasing a VF on \
             an optimistic clear is the failure this rule exists for"
        );

        s.on(Event::Unsteered);
        assert!(!s.is_steered());
        assert!(
            !s.steer_intended(),
            "a deliberate `steer off` must not be re-steered by the next verify"
        );
    }

    /// A removal the NIC refused keeps the VF withheld.
    #[test]
    fn a_refused_operator_unsteer_keeps_the_vf_withheld() {
        let mut s = running_and_steered();
        s.on(Event::UnsteerRequested);
        s.on(Event::UnsteerFailed);
        assert!(s.is_steered(), "traffic is still diverted");
        assert!(
            s.on(Event::StopRequested).contains(&Action::Unsteer),
            "every later teardown must keep trying, and keep withholding the VF"
        );
    }

    /// Rules inherited from a dead VPP are taken down first, and
    /// withhold the VF if they will not come down.
    ///
    /// MCAM outlives the process. Without this the record's rules were
    /// adopted into the ledger and then ignored: the supervisor believed
    /// nothing was diverted, so teardown emitted no `Unsteer` and
    /// released the VF while the NIC was still steering into it.
    #[test]
    fn inherited_steering_is_taken_down_before_anything_else() {
        let mut s = Supervisor::new();
        assert_eq!(s.on(Event::InheritedSteering), vec![Action::Unsteer]);
        assert!(
            s.is_steered(),
            "the record is the only evidence there is, and believing it is what makes \
             the teardown emit Unsteer"
        );

        // Removal refused: the VF must stay withheld, on this and every
        // later teardown.
        s.on(Event::UnsteerFailed);
        assert!(s.is_steered());
        assert!(s.on(Event::StopRequested).contains(&Action::Unsteer));
    }

    /// Inheriting steering also inherits the *want*, so the replacement
    /// re-steers once it verifies.
    ///
    /// Steering was established and never deliberately stopped — and
    /// until the replacement steers, those prefixes are diverted into a
    /// VF with nothing behind them. Waiting for an operator would leave
    /// the blackhole open across a restart nobody watched.
    #[test]
    fn a_replacement_re_steers_what_the_dead_vpp_was_steering() {
        let mut s = Supervisor::new();
        s.on(Event::InheritedSteering);
        s.on(Event::Unsteered);
        assert!(!s.is_steered(), "the stale rules are gone");
        assert!(s.steer_intended(), "but the want survives them");

        s.on(Event::StartRequested);
        s.on(Event::Spawned);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        assert!(
            s.on(Event::VerifyPassed).contains(&Action::Steer),
            "a verified replacement must restore the offload without being asked"
        );
    }

    /// Steering requests are refused outside the converged states rather
    /// than queued.
    ///
    /// A request that survives a crash and fires against the replacement
    /// is not what the operator asked for — and it is unnecessary: the
    /// replacement re-steers on its own if steering was wanted.
    #[test]
    fn a_steer_request_while_converging_does_nothing() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::Spawned);
        s.on(Event::ApiUp);
        assert_eq!(s.state(), State::Syncing);

        assert!(s.on(Event::SteerRequested).is_empty());
        assert_eq!(s.state(), State::Syncing);
        assert!(
            !s.steer_intended(),
            "a refused request must leave no want behind, or the next VerifyPassed acts on it"
        );
    }

    /// A failed reconcile of a LIVE steered port must not leave the
    /// machine claiming it is steering.
    ///
    /// `steer` rolls back all-or-nothing, and on a reconcile that
    /// rollback removes the rules that were working a moment ago — so a
    /// clean rollback empties the NIC. With `SteerFailed` falling through
    /// to the catch-all from `State::Steered`, the machine stayed
    /// `Steered` with `steered == true`: `steering_health()` reports
    /// Healthy with no message and the state gauge publishes
    /// `state="steered"`, while every steered packet is in fact on the
    /// eBPF tier.
    ///
    /// So the observed ledger decides, and the assertion is on
    /// `is_steered()` rather than on the state name — that is the field
    /// health and teardown both read.
    #[test]
    fn a_failed_reconcile_of_a_live_port_stops_claiming_to_steer() {
        let mut s = running_and_steered();
        s.on(Event::SteerRequested);
        s.on(Event::SteerFailed {
            rules_remain: false,
        });

        assert!(
            !s.is_steered(),
            "the rollback emptied the NIC, so nothing is diverted and nothing may say it is"
        );
        assert_eq!(s.state(), State::Ready, "verified, but not diverting");
        assert!(
            s.steer_intended(),
            "the want survives, so the next verify restores the offload"
        );
        assert!(
            !s.on(Event::StopRequested).contains(&Action::Unsteer),
            "and no Unsteer is owed for rules that are confirmed gone"
        );
    }

    /// The same failure with rules left behind keeps the VF withheld.
    ///
    /// The other polarity, and the reason this is observed rather than
    /// assumed: a rollback that could not delete leaves rules diverting
    /// traffic, so `steered` must stay true or `ReleaseResources` unbinds
    /// a VF that MCAM still targets.
    #[test]
    fn a_failed_reconcile_that_left_rules_keeps_the_vf_withheld() {
        let mut s = running_and_steered();
        s.on(Event::SteerRequested);
        s.on(Event::SteerFailed { rules_remain: true });

        assert!(s.is_steered(), "rules are still in the NIC");
        assert!(
            s.on(Event::StopRequested).contains(&Action::Unsteer),
            "so every teardown must try again and keep withholding the VF"
        );
    }
}
