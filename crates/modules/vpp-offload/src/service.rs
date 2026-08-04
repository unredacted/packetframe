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

use std::sync::atomic::{AtomicBool, Ordering};
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

/// How long `stop()` waits for the loop before returning with an
/// unfinished teardown on the record.
///
/// Sized to the `Module::detach` contract (under 1 s, SPEC.md §3.2) with
/// room for the poll granularity, NOT to the loop's internal teardown
/// budget. The distinction is the point: the loop may legitimately need
/// `STOP_PATIENCE` to outlast an undead VPP, and the caller must not be
/// blocked for it. What the caller gets instead is a snapshot that says
/// the teardown is unfinished.
const DETACH_BUDGET: Duration = Duration::from_millis(900);

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
                Err(
                    "the supervision loop died before publishing its first status — the \
                     factory panicked (see the log)"
                        .into(),
                )
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
    pub fn stop(mut self) -> Option<Published> {
        self.shared.stop.store(true, Ordering::SeqCst);
        let Some(t) = self.thread.take() else {
            return self.status();
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
            // `status()` is `Some` for any started service —
            // `SupervisionService::start` blocks on the first publish — so
            // the fallback below is unreachable in practice and is written
            // as a real snapshot rather than a `?` that would silently
            // discard the timeout.
            let mut last = self.status().unwrap_or_else(|| Published {
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
            last.teardown_failures.push(format!(
                "the supervision loop was still working after {} ms and was not waited on \
                 further; VPP and its resources may still be held — it continues tearing \
                 down in the background, but check `packetframe status` and the state file \
                 before re-attaching",
                DETACH_BUDGET.as_millis()
            ));
            last.resources_leaked = true;
            // The rest of the snapshot is from the last ORDINARY publish,
            // which may well say `Ready`/Healthy — it was true when the
            // loop published it and is not true now. Returning it unchanged
            // advertised healthy-and-ready alongside "teardown unfinished,
            // resources may be held", in one object.
            last.report.overall = packetframe_common::module::HealthState::Unhealthy;
            last.report
                .subsystems
                .push(packetframe_common::module::SubsystemHealth {
                    name: "supervision".into(),
                    state: packetframe_common::module::HealthState::Unhealthy,
                    message: Some(
                        "shutdown did not complete within the detach budget; the loop is \
                         still running"
                            .into(),
                    ),
                    last_success_age_seconds: None,
                });
            // Metrics are emptied rather than adjusted. They were rendered
            // from a snapshot that no longer describes anything, and
            // rewriting individual gauge lines by string surgery would be a
            // second, divergent renderer. No data beats stale data that
            // reads as healthy.
            last.metrics.clear();
            return Some(last);
        }
        // A panicked loop already published nothing further; the join
        // error carries no more than the panic message the thread
        // printed, so it is not propagated as a second panic here.
        let _ = t.join();
        self.status()
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
    fn drop(&mut self) {
        // A dropped-without-stop service still signals the loop; the
        // thread is detached rather than joined, because blocking an
        // arbitrary drop site for the teardown's duration is worse
        // than letting shutdown proceed in the background. `stop()` is
        // the orderly path and the module's detach uses it.
        self.shared.stop.store(true, Ordering::SeqCst);
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
            let summary = format!("Verify: {}", v.summary());
            if !last_failures.contains(&summary) {
                last_failures.push(summary);
            }
        }
    }
    *last_verify_at = None;
}

fn fmt_failures(outcome: &crate::executor::Outcome) -> Vec<String> {
    outcome
        .failures
        .iter()
        .map(|(action, why)| format!("{action:?}: {why}"))
        .collect()
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
        let f = fmt_failures(&injected.outcome);
        if !f.is_empty() {
            last_failures = f;
        }
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
            rs.port_links,
            rs.store_error.clone(),
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
        if !failures.is_empty() {
            last_failures = failures;
        }

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
