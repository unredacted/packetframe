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
        if let Some(t) = self.thread.take() {
            // A panicked loop already published nothing further; the
            // join error carries no more than the panic message the
            // thread printed, so it is not propagated as a second
            // panic here.
            let _ = t.join();
        }
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
    // When the last passing verify was observed, for the freshness the
    // health surface reports. Tracked here because `VerifyOutcome`
    // deliberately carries no clock.
    let mut last_verify_at: Option<Instant> = None;

    for e in initial {
        let now = Instant::now();
        let _ = driver.inject(now, e, &mut fx);
    }

    let publish = |driver: &Driver,
                   runtime: &Runtime,
                   last_verify_at: &Option<Instant>,
                   terminal: &Option<String>,
                   teardown_failures: &[String],
                   resources_leaked: bool| {
        let now = Instant::now();
        let rs = runtime.status();
        let fib = match (&rs.last_verify, last_verify_at) {
            (Some(outcome), Some(at)) => FibSync::from_outcome(outcome, now - *at),
            _ => FibSync::NeverVerified,
        };
        let snap = StatusSnapshot::observe_parts(
            driver.supervisor(),
            rs.counts,
            rs.pending_ops,
            rs.parked_ops,
            driver.api_health(now),
            fib,
            rs.port_links,
        );
        let published = Published {
            report: snap.report(),
            metrics: crate::status::render_metrics(&snap, module),
            state: driver.state(),
            api_error: rs.api_error,
            terminal: terminal.clone(),
            teardown_failures: teardown_failures.to_vec(),
            resources_leaked,
        };
        *shared.latest.lock().expect("status lock") = Some(published);
    };

    // First snapshot before the first tick; the handshake below is
    // what makes `start()`'s "status() is Some on return" guarantee
    // actually true rather than a race the test suite happens to win.
    publish(&driver, &runtime, &last_verify_at, &None, &[], false);
    let _ = ready.send(Ok(()));

    while !shared.stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        let tick = driver.tick(now, &mut obs, &mut fx);
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
                last_verify_at = Some(Instant::now());
            }
            let _ = driver.inject(Instant::now(), e, &mut fx);
        }
        runtime.set_steered(driver.supervisor().is_steered());

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
        publish(&driver, &runtime, &last_verify_at, &terminal, &[], false);

        match tick.sleep {
            Some(d) if d.is_zero() => {} // more work queued; go again
            Some(d) => std::thread::sleep(d.min(STOP_POLL_CAP)),
            // "Block on the fds" — this loop has no reactor, so the
            // bounded poll interval stands in for one. The cost is one
            // flag-check wakeup per interval while fully idle.
            None => std::thread::sleep(STOP_POLL_CAP),
        }
    }

    // Orderly teardown: hand the machine the stop and tick it until it
    // settles or the bounded patience expires. `StopRequested` on an
    // already-Stopped machine is a no-op, so the redundant case is
    // harmless.
    //
    // Outcomes are ACCUMULATED here, not dropped. The stop transition's
    // `ReleaseResources` can fail after the supervisor is already
    // `Stopped`, so no event will ever carry that failure — the
    // discarded Tick was the only witness, and discarding it made
    // `stop()` return a clean-looking snapshot over still-held VFs.
    let mut absorb = |outcome: crate::executor::Outcome| {
        for (action, why) in outcome.failures {
            teardown_failures.push(format!("{action:?}: {why}"));
        }
        resources_leaked |= outcome.resources_leaked;
    };
    let deadline = Instant::now() + STOP_PATIENCE;
    absorb(
        driver
            .inject(Instant::now(), Event::StopRequested, &mut fx)
            .outcome,
    );
    while driver.state() != State::Stopped && Instant::now() < deadline {
        let now = Instant::now();
        let tick = driver.tick(now, &mut obs, &mut fx);
        absorb(tick.outcome.clone());
        for e in runtime.take_pending() {
            absorb(driver.inject(Instant::now(), e, &mut fx).outcome);
        }
        match tick.sleep {
            Some(d) if d.is_zero() => {}
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    // The final word: whatever the teardown left behind — an undead VPP
    // that refused to die, a release that failed after `Stopped`, the
    // incompatibility that ended supervision — is on the record.
    publish(
        &driver,
        &runtime,
        &last_verify_at,
        &terminal,
        &teardown_failures,
        resources_leaked,
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
