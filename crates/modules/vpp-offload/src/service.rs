//! The supervision service: the loop, on its own thread, with a stop
//! switch and a status window.
//!
//! `Module::attach()` cannot run the tick loop inline — `attach` must
//! return while supervision continues for the life of the attachment —
//! so this owns the thread. Everything inside is machinery that already
//! exists ([`Driver`], [`Runtime`]); the service adds exactly three
//! things: the real clock, the stop protocol, and a continuously
//! published [`HealthReport`] + metrics snapshot for
//! `health_check`/`sample_metrics` to read without touching the loop.
//!
//! ## Construction happens ON the loop thread
//!
//! [`Runtime`] is deliberately `!Send` (its two trait views share an
//! `Rc<RefCell>` core), so the service takes a **factory** and calls it
//! from inside the spawned thread. That is not a workaround; it is the
//! ownership story stated in types: the loop thread is the only thing
//! that may ever drive the runtime, and handing a built one across
//! threads would be the lie the `Rc` exists to prevent.
//!
//! ## The stop protocol
//!
//! `stop()` flips the flag; the loop then injects `StopRequested` —
//! which the supervisor turns into the full teardown ordering
//! (unsteer-if-steered → abort convergence → kill → release) — and
//! keeps ticking until the machine settles in `Stopped` or the bounded
//! patience runs out (an undead VPP can legitimately refuse to die,
//! and a detach that hangs forever on it would be worse than one that
//! reports it). The final status is published either way, so the
//! caller can see exactly what the shutdown left behind.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use packetframe_common::module::HealthReport;

use crate::driver::Driver;
use crate::runtime::Runtime;
use crate::status::{FibSync, StatusSnapshot};
use crate::supervisor::{Event, State};

/// Ceiling on any single sleep, so the stop flag is honoured promptly
/// even when the schedule would otherwise permit a long doze. This is
/// a bounded sleep, not a busy loop: at worst ~20 wakeups/second while
/// completely idle, each a flag check and nothing more.
const STOP_POLL_CAP: Duration = Duration::from_millis(50);

/// How long `stop()` waits for the teardown to settle before giving up
/// on the loop. Covers the kill path's worst honest case (SIGTERM
/// grace + bounded SIGKILL wait) with margin; past it, either the
/// machine is `Stopped` or something (an undead VPP) is refusing, and
/// the final published status says which.
const STOP_PATIENCE: Duration = Duration::from_secs(10);

/// Marker prefixed to any error meaning **a VPP may still be running and
/// holding its VF and hugepages**.
///
/// Exists so a caller can distinguish "attach failed and left nothing
/// behind" from "attach failed and may have left a live VPP holding a VF".
/// The two demand opposite handling: the first should roll back, the second
/// must NOT, because releasing a VF under a process that can still DMA
/// through it is worse than leaking it.
///
/// Two producers, and it started with only one. The pre-publish panic path
/// sets it here. But a **factory** must set it too, on any error it returns
/// after it has adopted or spawned a VPP — an adoption that fails partway
/// (an unreadable boot id, a pidfd that will not open) leaves the recorded
/// process running exactly as a panic does, and forwarding that as an
/// ordinary error let the caller roll back and unbind the VF underneath it.
/// [`may_hold_resources`] is the check; use it rather than re-spelling the
/// prefix.
pub const MAY_HOLD_RESOURCES: &str = "RESOURCES MAY BE HELD";

/// Whether an error from [`SupervisionService::start`] means resources may
/// still be held.
///
/// A function rather than leaving callers to `starts_with` by hand: the one
/// caller that must branch on this is deciding whether to unbind a VF, and
/// a check spelled slightly differently at a second call site fails open
/// into memory corruption.
pub fn may_hold_resources(e: &str) -> bool {
    e.starts_with(MAY_HOLD_RESOURCES)
}

/// Cap on distinct reasons retained for one unhealthy episode.
///
/// Enough for a cause plus a few symptoms, small enough that a backoff loop
/// cannot grow a `Vec` that is cloned into every published snapshot.
const MAX_EPISODE_REASONS: usize = 8;

/// How long `stop()` waits for the loop before returning with an
/// unfinished teardown on the record.
///
/// Sized to the `Module::detach` contract (under 1 s, SPEC.md §3.2) with
/// room for the poll granularity, NOT to the loop's internal teardown
/// budget. The distinction is the point: the loop may legitimately need
/// `STOP_PATIENCE` to outlast an undead VPP, and the caller must not be
/// blocked for it. What the caller gets instead is a snapshot that says
/// the teardown is unfinished.
///
/// **The contract this is sized against is not met on hardware, and this
/// constant is not what misses it.** `detach --all` measured **2.814 s**
/// on the shadow (2026-08-11, ONE VF, live VPP holding 1.05M routes):
/// pins came out in 1 ms, then ~2.80 s went on terminating VPP and
/// rebinding the VF and restoring hugepages — work that happens after
/// `stop()` has already returned within this budget. So `stop()` keeps
/// its 900 ms promise while the operator-visible command takes about
/// three times the published figure. Raising this would not help; the
/// cost is in VPP's exit and the resource release, and the honest
/// number is recorded in the runbook's measured table rather than
/// papered over here.
const DETACH_BUDGET: Duration = Duration::from_millis(900);

/// How long [`SupervisionService::apply_steering`] waits for the loop to
/// pick up a steering change and report what happened.
///
/// The alternative — post and return `Ok` — is what makes this worth a
/// wait at all. `packetframe reconfigure` writes an OK/ERR marker the
/// operator reads, and this is the canary lever: "the rollout step
/// succeeded" and "the rollout step was queued" must not look the same.
/// A refused MCAM insert has to come back as a failure at the moment
/// the operator is watching for one.
///
/// Sized against **one tick**, not against the poll cadence. The request
/// is picked up before the next tick, so the wait is however long the
/// tick already in progress takes — and in `Ready`/`Steered`, the only
/// states a steering change is accepted from, that is a liveness ping
/// (1.5 s budget while steered) plus a delta drain. Two seconds would
/// therefore time out on an ordinary busy tick and report a failure over
/// a change that was about to happen.
///
/// Bounded above by the CLI's own 5 s ack timeout
/// (`RECONFIGURE_TIMEOUT_MS`), which covers every module's reconfigure,
/// so this cannot simply be made generous. 3 s leaves room for
/// fast-path's reconcile alongside it. A timeout is not a lost change
/// either way: the wait withdraws the request if the loop has not taken
/// it, and says plainly which of the two happened.
const STEERING_BUDGET: Duration = Duration::from_secs(3);

/// Poll granularity while waiting for the loop to answer.
const STEERING_POLL: Duration = Duration::from_millis(5);

/// A steering change on its way from `Module::reconfigure` to the loop.
///
/// Carries the whole target rather than a delta. The loop applies it
/// with [`crate::runtime::Runtime::retarget`] and one supervisor event,
/// and `Action::Steer` reconciles the NIC — so there is exactly one
/// routine that decides which rules exist, and a reconfigure cannot
/// grow a second, subtly different one.
#[derive(Debug, Clone)]
pub struct SteeringRequest {
    /// Matched against the answer so a caller cannot collect the result
    /// of somebody else's request — or of its own previous one.
    seq: u64,
    /// `(PF iface, VF index)` for every port now configured `steer on`.
    pub ports: Vec<(String, u32)>,
    pub plan: crate::steer::RuleSet,
    /// Whether traffic should be diverted once the target is in place.
    /// False is the rollback landing zone, not an error.
    pub want_steer: bool,
    /// Whether the `steer` flag itself moved in this reconfigure.
    ///
    /// The difference between "the operator just turned the lever" and
    /// "the config still says `steer on`, and this port was deliberately
    /// left unsteered". Without it, a SIGHUP for an unrelated reason —
    /// an added `allow-prefix`, a changed global — would divert traffic
    /// on every `steer on` port that had not yet been steered, because
    /// the flag is *present*. The machine never steers a first attach on
    /// its own precisely because that decision is the operator's, and a
    /// side effect of editing something else is not that decision.
    ///
    /// A port that is already steering is reconciled either way: its
    /// traffic is diverted now, so the rules must match the new
    /// allowlist whether or not the lever moved.
    pub lever_moved: bool,
}

/// Builds the loop's non-`Send` pieces on the loop thread, and returns
/// the events to inject before the first tick.
///
/// `Err` is an **attach failure** — a dead API socket, a version-skewed
/// VPP, a refused adoption — surfaced synchronously by
/// [`SupervisionService::start`] rather than becoming a dead thread the
/// first health check discovers.
pub type LoopFactory = Box<dyn FnOnce() -> Result<(Driver, Runtime, Vec<Event>), String> + Send>;

/// What the loop publishes after every pass.
#[derive(Debug, Clone)]
pub struct Published {
    pub report: HealthReport,
    /// Rendered `packetframe_vpp_*` gauges, ready for the textfile
    /// exporter.
    pub metrics: String,
    /// The supervision state at publish time, for `packetframe status`.
    pub state: State,
    /// The engine's last API error, verbatim. Carried so a CRC
    /// mismatch reads as "our definitions say X, this VPP says Y"
    /// instead of a generic startup failure.
    pub api_error: Option<String>,
    /// Set when the loop ended itself: the reason supervision is over
    /// and will not resume (today: a permanently incompatible API).
    pub terminal: Option<String>,
    /// Failures collected while executing the stop transition —
    /// including a refused resource release, which produces NO event
    /// (the supervisor is already `Stopped`) and would otherwise
    /// vanish with the discarded Tick, leaving detach reporting a
    /// clean stop over still-held VFs.
    pub teardown_failures: Vec<String>,
    /// The teardown declined to release resources (unsteer failed or
    /// the process survived); they are deliberately still held.
    pub resources_leaked: bool,
    /// Why the last failure happened — a missing VPP binary, a refused
    /// device attach, a broken resync, a refused steer. The supervisor
    /// only counts these ("restarting after N failures"); the actionable
    /// reason lives here and nowhere else.
    ///
    /// **Retained until recovery**, not just for the tick that produced
    /// it. Failures are followed by backoff ticks with empty outcomes, so
    /// republishing each tick verbatim cleared this within ~50 ms while
    /// the service stayed in the same failed state for seconds — an
    /// operator polling status would essentially always miss it. Cleared
    /// when the supervisor's consecutive-failure count returns to zero,
    /// which it does only on a verified-healthy cycle.
    ///
    /// Covers failures from injected events too (a `VerifyPassed` whose
    /// `Steer` was refused, a `VerifyFailed` whose teardown failed);
    /// those run synchronously inside the injection and can never appear
    /// in an ordinary tick's outcome.
    pub last_failures: Vec<String>,
    /// The runtime could not persist something it observed. Not fatal
    /// to convergence by design — but it means the next daemon restart
    /// will refuse adoption, so it degrades health rather than passing
    /// silently.
    pub store_error: Option<String>,
}

/// Shared between the loop and the module.
struct Shared {
    stop: AtomicBool,
    latest: Mutex<Option<Published>>,
    /// A steering change waiting to be applied. At most one: a second
    /// request supersedes the first, which is right — both describe the
    /// complete target, and the newer one is the config that is now on
    /// disk. The superseded caller learns it was superseded rather than
    /// waiting out its budget for an answer that will never come.
    steering_request: Mutex<Option<SteeringRequest>>,
    /// What the loop made of request `seq`.
    steering_result: Mutex<Option<(u64, Result<(), String>)>>,
    /// Hands out request sequence numbers.
    steering_seq: AtomicU64,
}

/// The one place a shutdown that did not complete is turned into a snapshot.
///
/// Three callers now — the detach-budget timeout, a panicked loop, and a
/// background teardown that panics after `stop()` has already returned — and
/// they had started to diverge at two. All three need the same three things:
/// the reason on `teardown_failures`, `resources_leaked` set because nothing
/// confirmed a release, and the health snapshot corrected.
///
/// The correction matters as much as the reason. The rest of the snapshot
/// comes from the last ORDINARY publish, which may well say `Ready`/Healthy —
/// true when it was published, not true now — so returning it unchanged
/// advertised a healthy dataplane alongside "teardown unfinished, resources
/// may be held", in one object. Metrics are CLEARED rather than adjusted:
/// they were rendered from a snapshot that no longer describes anything, and
/// rewriting gauge lines by string surgery would be a second, divergent
/// renderer. No data beats stale data that reads as healthy.
///
/// A free function because `PendingTeardown` needs it too and does not own a
/// `SupervisionService`; making it a method is what made the pending path
/// grow its own, absent, version of this correction.
fn incomplete_teardown(last: Option<Published>, why: String) -> Published {
    // `status()` is `Some` for any started service — `start` blocks on
    // the first publish — so the fallback is unreachable in practice
    // and is written as a real snapshot rather than a `?` that would
    // silently discard the reason.
    let mut last = last.unwrap_or_else(|| Published {
        report: HealthReport::healthy(),
        metrics: String::new(),
        state: State::Stopped,
        api_error: None,
        terminal: None,
        teardown_failures: Vec::new(),
        resources_leaked: false,
        last_failures: Vec::new(),
        store_error: None,
    });
    last.report.overall = packetframe_common::module::HealthState::Unhealthy;
    last.report
        .subsystems
        .push(packetframe_common::module::SubsystemHealth {
            name: "supervision".into(),
            state: packetframe_common::module::HealthState::Unhealthy,
            message: Some(why.clone()),
            last_success_age_seconds: None,
        });
    last.teardown_failures.push(why);
    last.resources_leaked = true;
    last.metrics.clear();
    // `state` is deliberately LEFT as the last observed one, and this
    // note exists because leaving it unremarked is what made the
    // metrics case a review finding.
    //
    // It cannot be corrected truthfully: the machine may be anywhere,
    // `Stopped` would claim a completed teardown that did not happen,
    // and there is no `Unknown` variant to reach for. So it stays a
    // factual record of the last publish — with `report.overall` now
    // `Unhealthy` and a named subsystem saying why, which is what a
    // reader consults. If a consumer is ever added that keys on `state`
    // rather than on the report, this is the line it will need.
    last
}

/// A teardown that outlived the detach budget, and the way to watch it.
///
/// `stop()` returns one of these instead of simply dropping the thread
/// handle. It has to: the timeout message tells the operator to check
/// `packetframe status`, and without this the background thread became the
/// only owner of the shared status window — so its eventual final publish,
/// including whether `ReleaseResources` finally succeeded or exactly which
/// VF refused to unbind, went somewhere nobody could read and was destroyed
/// when the thread exited. A promise of information with no channel behind
/// it is the defect this file has produced repeatedly; this one promised it
/// to an operator rather than to a caller.
pub struct PendingTeardown {
    shared: Arc<Shared>,
    thread: JoinHandle<()>,
}

impl PendingTeardown {
    /// The most recent snapshot the loop published, including the final one
    /// once it settles. Poll while [`Self::is_finished`] is false.
    pub fn status(&self) -> Option<Published> {
        self.shared.latest.lock().expect("status lock").clone()
    }

    /// Whether the loop has stopped running. **Not** the same as "the
    /// result is trustworthy": a thread that panicked is also finished, and
    /// published nothing after it. [`Self::settle`] is the authoritative
    /// end.
    pub fn is_finished(&self) -> bool {
        self.thread.is_finished()
    }

    /// Join the background teardown and return its FINAL snapshot.
    ///
    /// The panic case is why this exists. `is_finished()` goes true for a
    /// panicked thread just as it does for a clean one, and a panicked
    /// thread publishes nothing further — so a caller polling `status()`
    /// would take the last ordinary snapshot as the promised final result,
    /// which is the same "a panic reads as a clean stop" defect `stop()`
    /// already fixes on its own path. Same reason, same report: this routes
    /// through the one `incomplete_teardown`.
    ///
    /// Blocks until the loop exits. It is already bounded by
    /// `STOP_PATIENCE` on its own side, so this cannot wait indefinitely on
    /// anything the loop can control.
    pub fn settle(self) -> Published {
        // Read AFTER the join, not before. The loop is still running when
        // `settle` is called in the case that matters — that is the whole
        // point of the handle — and it publishes its real final status
        // during the join: whether the release finally succeeded, which VF
        // refused to unbind. A pre-join read returned the timeout snapshot
        // instead and threw that away, which is the same "promise the final
        // word, deliver a stale one" defect this handle was added to fix.
        let joined = self.thread.join();
        let last = self.shared.latest.lock().expect("status lock").clone();
        match joined {
            Ok(()) => last.unwrap_or_else(|| {
                incomplete_teardown(
                    None,
                    "the supervision loop finished without publishing a final status".into(),
                )
            }),
            Err(_) => incomplete_teardown(
                last,
                "the background teardown PANICKED after detach returned; VPP may still be \
                 running and holding its VF and hugepages — check `ip link show`, the state \
                 file and the log, and run `packetframe detach --all` before re-attaching"
                    .to_string(),
            ),
        }
    }
}

/// What `stop()` observed.
///
/// A struct rather than an enum because most callers only want
/// `published`; `pending` is `Some` exactly when the loop was still working
/// when the detach budget expired, and making it a field is what turns
/// dropping it into a deliberate act rather than an accident.
pub struct StopReport {
    /// What to report now.
    pub published: Option<Published>,
    /// `Some` when the teardown is still running in the background.
    pub pending: Option<PendingTeardown>,
}

/// Handle to a running supervision loop.
pub struct SupervisionService {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl SupervisionService {
    /// Spawn the loop. `factory` runs on the new thread and builds the
    /// non-`Send` pieces there; `initial` is injected before the first
    /// tick (a `StartRequested`, or `Adopted { steered }` when the
    /// attach wiring adopted a process — in which case it MUST also
    /// have called `Runtime::adopt_process` inside the factory).
    ///
    /// `module` labels the published metrics.
    /// Blocks until the loop has published its first snapshot, so a
    /// successful return GUARANTEES `status()` is `Some` — and a
    /// factory that dies (bad socket, failed adoption) surfaces here,
    /// synchronously, as the attach failure it is, rather than as a
    /// mysteriously dead thread discovered on the first health check.
    pub fn start(module: &'static str, factory: LoopFactory) -> Result<Self, String> {
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            latest: Mutex::new(None),
            steering_request: Mutex::new(None),
            steering_result: Mutex::new(None),
            steering_seq: AtomicU64::new(0),
        });
        let looped = Arc::clone(&shared);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
        let thread = std::thread::Builder::new()
            .name("vpp-supervision".into())
            .spawn(move || run_loop(module, factory, &looped, ready_tx))
            .map_err(|e| format!("spawning the supervision thread: {e}"))?;
        // Three outcomes, all reported synchronously as the attach
        // failures they are: the factory returned an error (a dead API
        // socket, a version-skewed VPP), the factory panicked (dropped
        // sender → RecvError), or it succeeded and published.
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                shared,
                thread: Some(thread),
            }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                // A panic BEFORE the first publish, which is the twin of
                // the post-publish one `stop()` handles — and it was left
                // uncovered when that one was fixed.
                //
                // There is nothing to tear down from here and no snapshot
                // to correct: the thread unwound, and unwinding dropped
                // `Runtime`, which drops the VPP process handle WITHOUT
                // terminating the process. So if the factory had already
                // adopted (or the initial injection had already spawned) a
                // VPP, it is still running, still holding its VF and
                // hugepages, and nothing left in this address space can
                // reach it. The only remedy is telling the operator, in
                // words that say what to do.
                //
                // `MAY_HOLD_RESOURCES` is a marker the caller can
                // match on: `bring_up`'s rollback must NOT release VFs and
                // hugepages after this, because releasing them under a live
                // VPP is the DMA hazard the whole `MustLeak` path exists to
                // avoid.
                Err(format!(
                    "{MAY_HOLD_RESOURCES}: the supervision loop panicked before \
                     publishing its first status (see the log). If it had already adopted \
                     or started VPP, that process is STILL RUNNING and still holds its VF \
                     and hugepages — nothing here can reach it any more. Run `packetframe \
                     detach --all` and check `ip link show` and the state file before \
                     re-attaching."
                ))
            }
        }
    }

    /// The most recent snapshot, if the loop has completed a pass.
    pub fn status(&self) -> Option<Published> {
        self.shared.latest.lock().expect("status lock").clone()
    }

    /// Request shutdown and wait for the loop to finish its teardown.
    ///
    /// Consumes the handle: there is nothing meaningful to do with a
    /// service after stopping it except read the final status, which
    /// is returned.
    pub fn stop(mut self) -> StopReport {
        self.shared.stop.store(true, Ordering::SeqCst);
        let Some(t) = self.thread.take() else {
            return StopReport {
                published: self.status(),
                pending: None,
            };
        };
        // Bounded and interruptible, NOT `join()`, and bounded by the
        // CONTRACT rather than by this module's convenience.
        //
        // An unconditional join cannot observe any deadline until the tick
        // in progress returns — and a tick can legitimately sit in a
        // synchronous API call for a full `SYNC_PING_BUDGET` (10 s
        // unsteered), with verification issuing several in a row. So the
        // honest worst case was ~20 s with no ceiling.
        //
        // The first fix bounded it at `STOP_PATIENCE` (10 s), which was
        // still wrong for a reason worth naming: `Module::detach` is
        // documented to complete in under a second, and 10 s is an order of
        // magnitude past it. Choosing the loop's internal budget as the
        // caller's bound was picking whichever of two contradicting
        // documents suited the code.
        //
        // Waiting for the whole teardown inside a second is genuinely
        // impossible here — the kill path alone budgets 500 ms of SIGTERM
        // grace plus a bounded SIGKILL wait, and VFIO/DMA can defeat
        // SIGKILL entirely. But *returning* inside a second is not: the
        // loop keeps its own `STOP_PATIENCE` and finishes the teardown in
        // the background, and the state file is what lets a later
        // `detach --all` complete anything left. So this waits only for the
        // fast path — the overwhelmingly common case, where nothing is
        // wedged and the loop settles in milliseconds — and past that
        // reports an unfinished teardown rather than blocking the loader.
        let deadline = Instant::now() + DETACH_BUDGET;
        while !t.is_finished() && Instant::now() < deadline {
            std::thread::sleep(STOP_POLL_CAP);
        }
        if !t.is_finished() {
            // Deliberately NOT joined. The thread is left to finish its own
            // teardown under `STOP_PATIENCE`, but the caller is told,
            // because a detach that reports success over a teardown still
            // in flight is exactly the lie `teardown_failures` exists to
            // prevent.
            //
            let corrected = incomplete_teardown(
                self.status(),
                format!(
                    "the supervision loop was still working after {} ms and was not waited on \
                 further; VPP and its resources may still be held — it continues tearing \
                 down in the background, but check `packetframe status` and the state file \
                 before re-attaching",
                    DETACH_BUDGET.as_millis()
                ),
            );
            // Written INTO the shared window, not just returned. The
            // correction existed only in the returned value, so a caller
            // polling `PendingTeardown::status()` — which is what the
            // message tells the operator to do — kept reading the stale
            // `Ready`/Healthy snapshot for the rest of `STOP_PATIENCE`. One
            // window, one truth.
            *self.shared.latest.lock().expect("status lock") = Some(corrected.clone());
            // The thread keeps its own `Arc<Shared>`, so handing the caller
            // one keeps the eventual final publish reachable.
            return StopReport {
                published: Some(corrected),
                pending: Some(PendingTeardown {
                    shared: Arc::clone(&self.shared),
                    thread: t,
                }),
            };
        }
        // A panic is NOT a clean stop, and discarding the join error made
        // it look like one. `is_finished()` is true for a panicked thread,
        // so this path was reached with the last snapshot possibly saying
        // `Ready`/Healthy — while the stop transition never ran at all.
        // Dropping `Runtime` drops the process handle; it does not
        // terminate VPP. So the process and its VF can still be live while
        // `stop()` reports success.
        //
        // The panic payload itself is not propagated as a second panic
        // here: the thread already printed it, and the caller needs a
        // status, not an unwind.
        let published = match t.join() {
            Ok(()) => self.status(),
            Err(_) => Some(incomplete_teardown(
                self.status(),
                "the supervision loop PANICKED; the stop transition never ran, so VPP may \
                 still be running and holding its VF and hugepages — check `ip link show`, \
                 the state file and the log, and run `packetframe detach --all` before \
                 re-attaching"
                    .to_string(),
            )),
        };
        // Settled — the loop is gone, so there is nothing left to watch.
        StopReport {
            published,
            pending: None,
        }
    }

    /// Hand the loop a new steering target and wait for its verdict.
    ///
    /// Synchronous on purpose — see [`STEERING_BUDGET`]. Returns `Err`
    /// when the loop refused the change (not converged, the FIB is
    /// incomplete, an MCAM insert failed), when a newer request
    /// superseded this one, or when the loop did not answer in time. In
    /// every one of those cases the operator's rollout step did NOT
    /// happen, which is what they need to know.
    pub fn apply_steering(
        &self,
        ports: Vec<(String, u32)>,
        plan: crate::steer::RuleSet,
        want_steer: bool,
        lever_moved: bool,
    ) -> Result<(), String> {
        // Sequence first, so the request that lands in the slot is
        // always the one whose number we then wait for.
        let seq = self.shared.steering_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let displaced = self
            .shared
            .steering_request
            .lock()
            .expect("steering lock")
            .replace(SteeringRequest {
                seq,
                ports,
                plan,
                want_steer,
                lever_moved,
            });
        // A request still sitting in the slot never ran, and now never
        // will — the slot holds one, and this call just took it. Answer
        // it here or its caller waits out the whole budget for a verdict
        // nobody will ever publish.
        //
        // Answered at the displacement rather than inferred by the
        // waiter, which is what the first version did: it peeked at the
        // slot and treated a higher sequence as proof of being
        // superseded. That is wrong in the case that matters — the loop
        // may have taken request A and be applying it right now, so a
        // newly-arrived B makes A's waiter report "replaced before it
        // was applied" about a change that DID happen. State recorded
        // from a request rather than from an observation, in the
        // machinery built to avoid exactly that.
        //
        // Unreachable from the loader today (SIGHUP handling is serial,
        // and each `reconfigure` blocks for its answer), so this is
        // about the seam being honest rather than about a live race.
        if let Some(older) = displaced {
            *self.shared.steering_result.lock().expect("steering lock") = Some((
                older.seq,
                Err(
                    "a newer configuration change replaced this one before the supervision \
                     loop saw it; re-run `packetframe reconfigure` to see where the newer \
                     one landed"
                        .into(),
                ),
            ));
        }

        let deadline = Instant::now() + STEERING_BUDGET;
        loop {
            if let Some((answered, outcome)) = self
                .shared
                .steering_result
                .lock()
                .expect("steering lock")
                .clone()
            {
                if answered == seq {
                    return outcome;
                }
            }
            if Instant::now() >= deadline {
                // WITHDRAW it, if the loop has not taken it yet.
                //
                // Leaving it in the slot is how "the change was NOT
                // applied" becomes a lie: the loop takes whatever is
                // there on its next free iteration, so a rollback
                // reported as failed would quietly take effect afterwards
                // — and publish its verdict where this caller is no
                // longer listening. An operator who has just been told
                // their `steer off` failed will do something else about
                // it; the change must not also happen.
                let withdrawn = {
                    let mut slot = self.shared.steering_request.lock().expect("steering lock");
                    let ours = slot.as_ref().is_some_and(|r| r.seq == seq);
                    if ours {
                        *slot = None;
                    }
                    ours
                };
                if !withdrawn {
                    // The loop has it, so it is genuinely in flight and
                    // cannot be recalled. One last look for the verdict —
                    // it may have landed between the poll and now, and
                    // reporting a timeout over a published answer would
                    // be the same lie in the other direction.
                    if let Some((answered, outcome)) = self
                        .shared
                        .steering_result
                        .lock()
                        .expect("steering lock")
                        .clone()
                    {
                        if answered == seq {
                            return outcome;
                        }
                    }
                    return Err(format!(
                        "the supervision loop took the steering change but had not finished it \
                         within {STEERING_BUDGET:?}, so it MAY still take effect. \
                         `packetframe status` reports what the module is doing; re-run once it \
                         settles."
                    ));
                }
                return Err(format!(
                    "the supervision loop did not pick up the steering change within \
                     {STEERING_BUDGET:?} — it is busy or wedged. The change was withdrawn and \
                     NOT applied; `packetframe status` reports what the module is doing."
                ));
            }
            std::thread::sleep(STEERING_POLL);
        }
    }

    /// Whether the loop thread is still running. `false` after `stop`,
    /// and — importantly — after a panic: a dead loop means nothing is
    /// supervising VPP, which the caller must surface rather than keep
    /// reporting the last published (now frozen) status as current.
    pub fn is_alive(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }
}

impl Drop for SupervisionService {
    /// **Deliberately does not tear anything down.**
    ///
    /// The loader's SIGTERM/SIGINT path is `drop(modules)`, and it means
    /// that literally: SPEC.md §7.3/§8.5 exit *without* detaching, so the
    /// dataplane survives a daemon restart. For the eBPF modules that works
    /// because bpffs pins hold the kernel references. For this one it works
    /// because VPP is a separate process that a later daemon adopts —
    /// which is drill (d) in the plan: restart packetframe with VPP alive,
    /// adopt, dirty-resync, WITHOUT unsteering, zero loss.
    ///
    /// This used to set the stop flag, which raced that: if the supervision
    /// thread got scheduled before the process exited it would unsteer and
    /// kill the very VPP the loader was preserving, and if it did not the
    /// attachment survived. Same signal, two different outcomes, decided by
    /// the scheduler — and the losing case is a blackhole plus a full
    /// reconvergence on the next start.
    ///
    /// So teardown has exactly one entrance: [`SupervisionService::stop`],
    /// which `Module::detach` calls. A drop that still holds the thread
    /// handle is by definition NOT that path, and is either a preserving
    /// exit (the thread dies with the process — correct) or a caller that
    /// dropped without detaching, which leaks one thread and is logged
    /// rather than silently converted into a teardown.
    fn drop(&mut self) {
        if self.thread.is_some() {
            tracing::info!(
                "vpp-offload supervision dropped without stop(); VPP is left running and \
                 adoptable (§8.5 preserve-on-exit). `packetframe detach` is what tears it down."
            );
        }
    }
}

/// One action failure per line, `Action: reason`, for the published
/// diagnostics. Shared so an ordinary tick, an injected event and the
/// teardown all render identically.
/// Drop a verify verdict that no longer describes a live process, keeping
/// the REASON if it was a failure.
///
/// A free function with exactly two callers — the main loop and the final
/// publish after teardown — because that is the shape the alternative kept
/// getting wrong. The rule first lived inline in the loop, which meant the
/// stopped snapshot published after `StopRequested` killed the process still
/// carried the passing verdict: `packetframe_vpp_fib_verified 1` for a VPP
/// that had just been killed. Teardown is a second exit path, and a rule
/// written at one exit is not a rule.
///
/// The verdict's lifetime is the process's, in BOTH polarities. A passing
/// one kept past the process claims a verified FIB that no longer exists; a
/// failing one kept past it survived into the *replacement* and described a
/// process it had never seen. What keeps the second case from losing
/// information is that the summary moves to `last_failures`, the field that
/// exists to retain reasons across ticks — the FIB subsystem reports on the
/// current instance, "why are we in backoff" does not.
///
/// Not keyed on any state name: `Starting` never fires (a lost process lands
/// in `Backoff`), and the false→true edge of a replacement cannot be
/// sampled at all, since `BackoffElapsed` enters `Starting` and a failed
/// spawn returns to `Backoff` inside one tick. `has_process()` is stable for
/// as long as it matters.
fn expire_verdict(
    driver: &Driver,
    last_verify: &mut Option<crate::verify::VerifyOutcome>,
    last_verify_at: &mut Option<Instant>,
    last_failures: &mut Vec<String>,
) {
    if driver.state().has_process() {
        return;
    }
    if let Some(v) = last_verify.take() {
        if !v.passed() {
            // Through `remember_failures` like every other writer. This
            // one used to append directly while the tick paths assigned,
            // so whether the verify reason survived depended on ordering.
            remember_failures(last_failures, vec![format!("Verify: {}", v.summary())]);
        }
    }
    *last_verify_at = None;
}

/// Add reasons for the CURRENT unhealthy episode, keeping the earliest as
/// well as the latest.
///
/// One operation, because there were three writers with two different
/// semantics: `expire_verdict` appended a failed verify's summary while the
/// tick paths assigned, so whether the root cause survived depended on
/// which happened last. A failed verify followed by a failed respawn would
/// report only "cannot spawn" — losing the reason the restart was happening
/// at all.
///
/// Accumulating rather than replacing is the right default here because an
/// episode has a cause and a symptom and an operator needs both, but it is
/// bounded: `MAX_EPISODE_REASONS` distinct entries, deduplicated, because a
/// long backoff loop would otherwise append the same spawn failure forever
/// into a `Vec` published on every tick. The episode ends — and the list is
/// cleared — when health returns to `Healthy`.
fn remember_failures(into: &mut Vec<String>, new: Vec<String>) {
    for reason in new {
        if into.len() >= MAX_EPISODE_REASONS {
            return;
        }
        if !into.contains(&reason) {
            into.push(reason);
        }
    }
}

fn fmt_failures(outcome: &crate::executor::Outcome) -> Vec<String> {
    outcome
        .failures
        .iter()
        .map(|(action, why)| format!("{action:?}: {why}"))
        .collect()
}

/// Apply one steering change, from inside the loop.
///
/// Split out so the two halves of a steering change — the target and
/// the reconcile — happen in one place and in one order. The target is
/// recorded first, unconditionally, because `Action::Steer` reconciles
/// against whatever the target is: swapping it after the event would
/// install the OLD rules and leave the new ones for whenever the next
/// verify happened to fire.
fn apply_steering(
    driver: &mut Driver,
    runtime: &Runtime,
    fx: &mut dyn crate::executor::Effects,
    req: &SteeringRequest,
) -> Result<(), String> {
    let state = driver.state();
    if !matches!(state, State::Ready | State::Steered) {
        // Deliberately refused rather than queued. A steer request that
        // outlives a crash and fires against the replacement is not what
        // the operator asked for, and the replacement re-steers on its
        // own if steering was wanted. The new config is on disk either
        // way, so the next attach picks it up.
        return Err(format!(
            "vpp-offload is {state:?}, not converged — steering changes apply only from \
             Ready or Steered. The new configuration is on disk and takes effect at the \
             next successful convergence"
        ));
    }
    runtime.retarget(req.ports.clone(), req.plan.clone());

    let steered = driver.supervisor().is_steered();
    let event = if req.want_steer {
        // The config says steer, but that is not the same as the
        // operator asking for it NOW.
        //
        // A `steer on` port that has never steered is in the designed
        // staging state: the machine never steers a first attach on its
        // own, because when traffic moves is the operator's decision and
        // the canary ladder is paced by hand. So a SIGHUP that did not
        // move the lever — an added `allow-prefix`, a changed global —
        // updates the target and stops there. Diverting traffic as a side
        // effect of editing something else is precisely the decision this
        // module is not allowed to make.
        if !steered && !req.lever_moved {
            return Ok(());
        }
        // The same gate the automatic path uses, and applied on the same
        // terms: **first steer only**. An operator turning the lever on
        // an unsteered port is no more entitled to divert traffic into a
        // FIB with known holes than a `VerifyPassed` is, and this is the
        // likelier door — the canary ladder's shape is "steer once the
        // table has converged", which is exactly when someone is
        // impatient.
        //
        // A port that is ALREADY steered is deliberately not gated.
        // `blocks_first_steer` counts `installing`, which is nonzero
        // whenever routes are in flight — routine under a live BGP feed
        // — so gating the reconcile would make `packetframe reconfigure`
        // fail at random. And the failure would be the wrong way round:
        // refusing leaves the PREVIOUS rules installed, so a prefix the
        // operator just removed from the allowlist keeps being diverted.
        if !steered {
            let counts = runtime.status().counts;
            if counts.blocks_first_steer() {
                return Err(format!(
                    "refusing the first steer: the FIB is incomplete ({} unresolvable, {} \
                     withheld, {} still installing). Diverting traffic into it would \
                     blackhole exactly the prefixes that are missing. `packetframe status` \
                     reports all three; they must be zero",
                    counts.unresolvable, counts.withheld, counts.installing
                ));
            }
        }
        Event::SteerRequested
    } else {
        Event::UnsteerRequested
    };

    let tick = driver.inject(Instant::now(), event, fx);
    // The actions ran synchronously inside `inject`, and their failures
    // exist only in this Tick — the same reason the main loop keeps its
    // injected outcomes. Here they are also the operator's answer.
    let failures = fmt_failures(&tick.outcome);
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn run_loop(
    module: &'static str,
    factory: LoopFactory,
    shared: &Shared,
    ready: std::sync::mpsc::Sender<Result<(), String>>,
) {
    let (mut driver, runtime, initial) = match factory() {
        Ok(parts) => parts,
        Err(e) => {
            // Nothing was built, so there is nothing to publish or tear
            // down; `start()` turns this into its return value.
            let _ = ready.send(Err(e));
            return;
        }
    };
    let (mut obs, mut fx) = runtime.views();
    let mut terminal: Option<String> = None;
    let mut teardown_failures: Vec<String> = Vec::new();
    let mut resources_leaked = false;
    // The most recent nonempty failure set, retained across the empty
    // backoff ticks that follow it. See the publish site for why.
    let mut last_failures: Vec<String> = Vec::new();
    // The last COMPLETED verify verdict and when it completed.
    //
    // Held here rather than read from the engine at publish time,
    // because the engine's copy is per-process state and the verdict's
    // own teardown destroys it: `VerifyFailed` injects `Kill`, `kill`
    // calls `process_gone`, and `on_process_gone` sets
    // `last_verify = None`. The publish that followed therefore paired a
    // fresh timestamp with no outcome and reported `NeverVerified` —
    // hiding a concrete failure summary behind "not yet verified",
    // which is the same disappearance an earlier round fixed for the
    // timestamp alone, arriving through the engine's state reset instead.
    //
    // `VerifyOutcome` deliberately carries no clock, hence the pair.
    let mut last_verify: Option<crate::verify::VerifyOutcome> = None;
    let mut last_verify_at: Option<Instant> = None;

    // The initial injection is a real attach step, and its failures are
    // no less actionable than an ordinary tick's — a `StartRequested`
    // whose `Spawn` fails, or an `Adopted` whose `AttachDevices` is
    // refused, has its only detailed reason in this Tick. Discarding it
    // published a first snapshot with an empty `last_failures`, and if
    // the failure left an undead process blocking retries, no later tick
    // could ever reconstruct the reason.
    for e in initial {
        let now = Instant::now();
        let injected = driver.inject(now, e, &mut fx);
        remember_failures(&mut last_failures, fmt_failures(&injected.outcome));
    }

    // Returns the overall health it published, which is what decides
    // whether a retained failure reason may finally be dropped.
    let publish = |driver: &Driver,
                   runtime: &Runtime,
                   last_verify: &Option<crate::verify::VerifyOutcome>,
                   last_verify_at: &Option<Instant>,
                   terminal: &Option<String>,
                   teardown_failures: &[String],
                   resources_leaked: bool,
                   last_failures: &[String]|
     -> packetframe_common::module::HealthState {
        let now = Instant::now();
        let rs = runtime.status();
        let fib = match (last_verify, last_verify_at) {
            (Some(outcome), Some(at)) => FibSync::from_outcome(outcome, now - *at),
            _ => FibSync::NeverVerified,
        };
        // The store failure goes INTO the snapshot, not onto the report
        // afterwards. A store failure is a real degradation — convergence
        // continues correctly, but the next daemon restart will refuse
        // adoption because the index it needs was never persisted — and
        // patching `report()` here left `render_metrics` rendering
        // `packetframe_vpp_health` from the unpatched snapshot. The health
        // check said Degraded and Prometheus said Healthy, about the same
        // instant, during exactly the failure the patch existed to
        // surface. One condition, one place: `StatusSnapshot`.
        let snap = StatusSnapshot::observe_parts(
            driver.supervisor(),
            rs.counts,
            rs.pending_ops,
            rs.parked_ops,
            driver.api_health(now),
            fib,
            rs.resync_deferred,
            rs.authority,
            rs.port_links,
            rs.store_error.clone(),
            rs.drain_error.clone(),
            rs.source_backlog,
            rs.steer_configured_ports > 0,
        );
        let report = snap.report();
        let overall = report.overall;
        let published = Published {
            report,
            metrics: crate::status::render_metrics(&snap, module),
            state: driver.state(),
            api_error: rs.api_error,
            terminal: terminal.clone(),
            teardown_failures: teardown_failures.to_vec(),
            resources_leaked,
            last_failures: last_failures.to_vec(),
            store_error: rs.store_error,
        };
        *shared.latest.lock().expect("status lock") = Some(published);
        overall
    };

    // First snapshot before the first tick; the handshake below is
    // what makes `start()`'s "status() is Some on return" guarantee
    // actually true rather than a race the test suite happens to win.
    publish(
        &driver,
        &runtime,
        &last_verify,
        &last_verify_at,
        &None,
        &[],
        false,
        &last_failures,
    );
    let _ = ready.send(Ok(()));

    while !shared.stop.load(Ordering::SeqCst) {
        // Steering changes first, before the tick. They are the
        // operator's, they are synchronous on the far side, and a tick
        // can take a while — a resync batch, a verify sample — so
        // applying them after would spend the caller's budget waiting
        // for work that has nothing to do with the request.
        let request = shared
            .steering_request
            .lock()
            .expect("steering lock")
            .take();
        if let Some(req) = request {
            let outcome = apply_steering(&mut driver, &runtime, &mut fx, &req);
            if let Err(e) = &outcome {
                // Also onto the health surface. `apply_steering` answers
                // the caller, but `packetframe reconfigure` is not the
                // only way this is read: a refused canary step has to be
                // visible in `packetframe status` afterwards, the same
                // as a refused automatic steer.
                remember_failures(&mut last_failures, vec![format!("Reconfigure: {e}")]);
            }
            // The engine's socket deadline keys on whether packets are
            // on VPP, and that may have just changed. Synced here rather
            // than left to the post-tick call for the same reason
            // `adopt_process` takes `steered` as a parameter: the work
            // in between runs under the wrong budget otherwise.
            runtime.set_steered(driver.supervisor().is_steered());
            // PUBLISHED BEFORE THE CALLER IS ANSWERED, so `packetframe
            // reconfigure` returning OK means `packetframe status`
            // already shows the new state.
            //
            // Answering first left the window holding the PREVIOUS
            // state until the tick below republished it, so an operator
            // — or a rollout script — reading status immediately after
            // a lever flip could see the state it just changed away
            // from, and a canary ladder that checks its own step is
            // exactly the caller that does this. A real race, not a
            // theoretical one: two tests asserted the synchronous
            // contract and won it almost always, until CI lost the
            // toss. One extra publish per `reconfigure` costs nothing;
            // this runs once per operator action, not once per tick.
            publish(
                &driver,
                &runtime,
                &last_verify,
                &last_verify_at,
                &terminal,
                &[],
                false,
                &last_failures,
            );
            *shared.steering_result.lock().expect("steering lock") = Some((req.seq, outcome));
        }

        let now = Instant::now();
        let tick = driver.tick(now, &mut obs, &mut fx);
        let mut failures: Vec<String> = fmt_failures(&tick.outcome);
        for e in runtime.take_pending() {
            // Every COMPLETED verify gets the timestamp, not only a
            // pass. Stamping only `VerifyPassed` converted a first
            // failed verify into `NeverVerified` — hiding a concrete
            // failure summary behind "not yet verified" — and gave a
            // later failure the stale timestamp of the last pass.
            if matches!(
                e,
                Event::VerifyPassed | Event::VerifyFailed | Event::VerifyIncomplete
            ) {
                // BEFORE the injection, because the injection may destroy
                // it: `VerifyFailed`'s teardown runs `Kill` →
                // `process_gone` → `on_process_gone`, which clears the
                // engine's `last_verify`. Reading it afterwards yields
                // `None` and reports `NeverVerified` over a verify that
                // definitely completed and definitely failed.
                last_verify = runtime.status().last_verify;
                last_verify_at = Some(Instant::now());
            }
            // The injected event's actions run synchronously HERE, and
            // its failures exist only in this Tick. Discarding it lost a
            // whole class of diagnostic: `VerifyPassed` triggers `Steer`,
            // so a refused steer — the canary failing — never appeared
            // anywhere, and `VerifyFailed`'s teardown failures went the
            // same way. Neither can ever show up in the ordinary tick's
            // outcome, because neither is produced by one.
            let injected = driver.inject(Instant::now(), e, &mut fx);
            failures.extend(fmt_failures(&injected.outcome));
        }
        runtime.set_steered(driver.supervisor().is_steered());
        // Retained BEFORE the terminal check below, which `break`s.
        //
        // With the assignment after it, a tick whose failures coincided
        // with detecting a permanently-incompatible API had those failures
        // discarded — on the one path where supervision ends for good and
        // the final snapshot is all an operator has. `terminal` carries
        // the API error itself, but not the refused attach or steer beside
        // it.
        //
        // Found by re-reading rather than by review, and deliberately NOT
        // accompanied by a test: the window is a single tick's
        // coincidence, and every test I could construct for it reached the
        // assertion without ever setting `terminal`, which is coverage
        // theatre. The ordering is defensive and free; the honest note is
        // that it is unproven.
        // The supervisor counts failures; only the outcome carries WHY —
        // and the reason has to OUTLIVE the tick that produced it.
        //
        // A failing tick is followed immediately by backoff ticks whose
        // outcomes are empty, and republishing those verbatim overwrote
        // `last_failures` with nothing within one 50 ms poll while the
        // service sat in the same failed retry state for seconds. An
        // operator running `packetframe status` would essentially always
        // land in the empty window and see a bare failure count.
        //
        // So it is sticky, and the release condition is an *observation*
        // of recovery: the reason is dropped only once the published
        // health returns to `Healthy`. A newer failure supersedes an
        // older one.
        //
        // The obvious release condition — the supervisor's own
        // consecutive-failure count reaching zero — is WRONG, and
        // instructively so. A refused `Steer` deliberately does not count
        // as a supervisor failure (a failed canary must not cycle a VPP
        // that is forwarding fine), so `failures()` is already zero at
        // the moment the steer is refused, and keying on it wiped the
        // reason on the very next tick. `Healthy` is the condition that
        // actually covers every way this module can be unwell, because it
        // is the same whitelist `nominal()` applies.
        remember_failures(&mut last_failures, failures);

        // One call, one rule. See `expire_verdict`.
        expire_verdict(
            &driver,
            &mut last_verify,
            &mut last_verify_at,
            &mut last_failures,
        );

        // The check `api_incompatible` exists FOR, in the loop it was
        // built for. A CRC mismatch or handshake refusal fails
        // identically on every attempt: without this, the loop polls
        // out the 60 s startup budget, kills a VPP that answered its
        // socket perfectly well, restarts it, and repeats forever —
        // while the version skew that explains everything sits
        // unread in the engine. Terminal means terminal: tear down and
        // end supervision with the reason on the record.
        if runtime.api_incompatible() {
            terminal = Some(format!(
                "VPP's API is permanently incompatible: {}",
                runtime
                    .status()
                    .api_error
                    .as_deref()
                    .unwrap_or("(no detail recorded)")
            ));
            break;
        }
        // The stop flag is rechecked HERE, not only at the top of the loop.
        //
        // `stop()` can set it — and write its corrected, unhealthy snapshot
        // into the shared window — while this iteration is blocked inside a
        // tick. Publishing an ordinary snapshot afterwards overwrote that
        // correction with one carrying no timeout failure and
        // `resources_leaked = false`, so a caller polling
        // `PendingTeardown::status()` lost the warning again until teardown
        // finished. The teardown below publishes the real final word; this
        // iteration has nothing left to say.
        if shared.stop.load(Ordering::SeqCst) {
            break;
        }
        let overall = publish(
            &driver,
            &runtime,
            &last_verify,
            &last_verify_at,
            &terminal,
            &[],
            false,
            &last_failures,
        );
        if overall == packetframe_common::module::HealthState::Healthy {
            last_failures.clear();
        }

        match tick.sleep {
            Some(d) if d.is_zero() => {} // more work queued; go again
            Some(d) => std::thread::sleep(d.min(STOP_POLL_CAP)),
            // "Block on the fds" — this loop has no reactor, so the
            // bounded poll interval stands in for one. The cost is one
            // flag-check wakeup per interval while fully idle.
            None => std::thread::sleep(STOP_POLL_CAP),
        }
    }

    // Orderly teardown: hand the machine the stop, then keep working until
    // the resources are actually released or the bounded patience expires.
    //
    // Outcomes are ACCUMULATED here, not dropped. The stop transition's
    // `ReleaseResources` can fail after the supervisor is already
    // `Stopped`, so no event will ever carry that failure — the
    // discarded Tick was the only witness, and discarding it made
    // `stop()` return a clean-looking snapshot over still-held VFs.
    // A free function rather than a closure: the retry below has to read
    // and reset `resources_leaked`, which a closure capturing it mutably
    // would forbid.
    fn absorb(outcome: crate::executor::Outcome, failures: &mut Vec<String>, leaked: &mut bool) {
        failures.extend(fmt_failures(&outcome));
        *leaked |= outcome.resources_leaked;
    }
    let deadline = Instant::now() + STOP_PATIENCE;
    absorb(
        driver
            .inject(Instant::now(), Event::StopRequested, &mut fx)
            .outcome,
        &mut teardown_failures,
        &mut resources_leaked,
    );
    // The loop waits on the ONE condition that waiting can resolve: an
    // undead process.
    //
    // Two bugs met here. `(_, StopRequested)` assigns `Stopped`
    // unconditionally — before knowing whether `Unsteer` succeeded or
    // `Kill` reported `MustLeak` — so the old `while state != Stopped`
    // condition was false on its first evaluation and the whole patience
    // window was dead code: a VPP that exits a moment after SIGKILL, whose
    // VF could then have been released well inside the budget, produced an
    // immediate leaked-resources snapshot instead.
    //
    // But the fix must not be "retry while anything is still held". On a
    // structural refusal — `SteeringUnavailable` declining to unsteer, a VF
    // that will not unbind — nothing changes by waiting, and looping to the
    // deadline would add ten seconds to every such detach. `undead` is
    // different in kind: it means SIGKILL could not bite (VFIO/DMA), and
    // the pidfd will report the exit whenever it comes. Ticking is what
    // observes it.
    //
    // Retrying is possible because `StopRequested` is NOT a no-op on an
    // already-`Stopped` machine (the comment here used to claim it was):
    // it matches any state and re-emits Unsteer/Kill/ReleaseResources
    // against a world that has since changed.
    let was_undead = driver.supervisor().is_undead();
    while driver.supervisor().is_undead() && Instant::now() < deadline {
        let now = Instant::now();
        let tick = driver.tick(now, &mut obs, &mut fx);
        absorb(
            tick.outcome.clone(),
            &mut teardown_failures,
            &mut resources_leaked,
        );
        for e in runtime.take_pending() {
            absorb(
                driver.inject(Instant::now(), e, &mut fx).outcome,
                &mut teardown_failures,
                &mut resources_leaked,
            );
        }
        match tick.sleep {
            Some(d) if d.is_zero() => {}
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    if was_undead && !driver.supervisor().is_undead() {
        // The process that survived SIGKILL has since exited, so its VF and
        // hugepages are releasable now. Clear the verdict from the attempt
        // that could not proceed before re-running the teardown, or the
        // stale `true` would outlive the condition that produced it.
        resources_leaked = false;
        teardown_failures
            .push("the process survived SIGKILL and then exited; teardown re-run".into());
        absorb(
            driver
                .inject(Instant::now(), Event::StopRequested, &mut fx)
                .outcome,
            &mut teardown_failures,
            &mut resources_leaked,
        );
    }
    // The teardown just killed the process, so the verdict it produced no
    // longer describes anything. Same rule, same function — this is the
    // second exit path the inline version missed.
    expire_verdict(
        &driver,
        &mut last_verify,
        &mut last_verify_at,
        &mut last_failures,
    );

    // The final word: whatever the teardown left behind — an undead VPP
    // that refused to die, a release that failed after `Stopped`, the
    // incompatibility that ended supervision — is on the record.
    publish(
        &driver,
        &runtime,
        &last_verify,
        &last_verify_at,
        &terminal,
        &teardown_failures,
        resources_leaked,
        &last_failures,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A factory that FAILS is an attach failure carrying its own
    /// reason — this is the path a version-skewed VPP takes, since the
    /// attach wiring verifies the API before it commits to adopting.
    #[test]
    fn a_factory_error_fails_start_with_its_own_reason() {
        let result = SupervisionService::start(
            "vpp-offload",
            Box::new(|| Err("API mismatch for `ip_route_add_del`".into())),
        );
        let err = result.err().expect("start must fail");
        assert!(err.contains("API mismatch"), "{err}");
    }

    /// A factory error carrying the marker survives to the caller, so a
    /// rollback can be suppressed.
    ///
    /// The pre-publish panic is not the only way a failed attach can leave a
    /// live VPP: a factory that adopted a recorded process and THEN failed —
    /// an unreadable boot id, a pidfd that will not open — leaves it running
    /// just the same. `start` forwards factory errors verbatim, so the
    /// marker has to survive that forwarding for the distinction to reach
    /// the caller who decides whether to unbind a VF.
    #[test]
    fn a_marked_factory_error_reaches_the_caller_intact() {
        let err = SupervisionService::start(
            "vpp-offload",
            Box::new(|| {
                Err(format!(
                    "{MAY_HOLD_RESOURCES}: adopted pid 4242, then failed"
                ))
            }),
        )
        .err()
        .expect("start must fail");
        assert!(
            may_hold_resources(&err),
            "the caller cannot tell this from a clean failure and will roll back: {err}"
        );
        assert!(err.contains("adopted pid 4242"), "{err}");
    }

    /// An ordinary factory error must NOT be marked, or every failed attach
    /// would leak its VF rather than rolling back.
    #[test]
    fn an_ordinary_factory_error_is_not_marked() {
        let err = SupervisionService::start(
            "vpp-offload",
            Box::new(|| Err("API mismatch for `ip_route_add_del`".into())),
        )
        .err()
        .expect("start must fail");
        assert!(!may_hold_resources(&err), "{err}");
    }

    /// A pre-publish panic must SAY that resources may be held.
    ///
    /// The twin of the post-publish panic path, and it was left uncovered
    /// when that one was fixed. Nothing here can tear down: the thread
    /// unwound, and unwinding dropped `Runtime`, which drops the VPP
    /// process handle without terminating the process. So the only remedy
    /// is an error an operator can act on — and a marker `bring_up` can
    /// match on, because its rollback must NOT release a VF that a live VPP
    /// may still be DMAing through.
    #[test]
    fn a_pre_publish_panic_says_resources_may_be_held() {
        let err = SupervisionService::start(
            "vpp-offload",
            Box::new(|| panic!("initial injection panicked on purpose")),
        )
        .err()
        .expect("start must fail");
        assert!(
            err.starts_with(MAY_HOLD_RESOURCES),
            "the caller cannot distinguish this from a clean failure: {err}"
        );
        assert!(err.contains("STILL RUNNING"), "{err}");
        assert!(
            err.contains("detach --all"),
            "the remedy must be named: {err}"
        );
    }

    /// A factory that PANICS must not leave a dead thread behind a
    /// health check that would go on reading frozen status as current.
    #[test]
    fn a_panicking_factory_fails_start_synchronously() {
        let result = SupervisionService::start(
            "vpp-offload",
            Box::new(|| panic!("factory failed on purpose")),
        );
        let err = result
            .err()
            .expect("start must fail, not hand back a dead loop");
        assert!(err.contains("panicked"), "{err}");
    }
}
