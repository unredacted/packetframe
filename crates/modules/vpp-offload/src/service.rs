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

/// What the loop publishes after every pass.
#[derive(Debug, Clone)]
pub struct Published {
    pub report: HealthReport,
    /// Rendered `packetframe_vpp_*` gauges, ready for the textfile
    /// exporter.
    pub metrics: String,
    /// The supervision state at publish time, for `packetframe status`.
    pub state: State,
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
    pub fn start(
        module: &'static str,
        factory: Box<dyn FnOnce() -> (Driver, Runtime, Vec<Event>) + Send>,
    ) -> Result<Self, String> {
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            latest: Mutex::new(None),
        });
        let looped = Arc::clone(&shared);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("vpp-supervision".into())
            .spawn(move || run_loop(module, factory, &looped, ready_tx))
            .map_err(|e| format!("spawning the supervision thread: {e}"))?;
        // A dropped sender (the factory panicked before the first
        // publish) turns this into RecvError — the failure is reaped
        // and reported here instead of leaking a dead thread.
        if ready_rx.recv().is_err() {
            let _ = thread.join();
            return Err(
                "the supervision loop died before publishing its first status — the \
                 factory failed (see the panic in the log)"
                    .into(),
            );
        }
        Ok(Self {
            shared,
            thread: Some(thread),
        })
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
    factory: Box<dyn FnOnce() -> (Driver, Runtime, Vec<Event>) + Send>,
    shared: &Shared,
    ready: std::sync::mpsc::Sender<()>,
) {
    let (mut driver, runtime, initial) = factory();
    let (mut obs, mut fx) = runtime.views();
    // When the last passing verify was observed, for the freshness the
    // health surface reports. Tracked here because `VerifyOutcome`
    // deliberately carries no clock.
    let mut last_verify_at: Option<Instant> = None;

    for e in initial {
        let now = Instant::now();
        let _ = driver.inject(now, e, &mut fx);
    }

    let publish = |driver: &Driver, runtime: &Runtime, last_verify_at: &Option<Instant>| {
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
        };
        *shared.latest.lock().expect("status lock") = Some(published);
    };

    // First snapshot before the first tick; the handshake below is
    // what makes `start()`'s "status() is Some on return" guarantee
    // actually true rather than a race the test suite happens to win.
    publish(&driver, &runtime, &last_verify_at);
    let _ = ready.send(());

    while !shared.stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        let tick = driver.tick(now, &mut obs, &mut fx);
        for e in runtime.take_pending() {
            if matches!(e, Event::VerifyPassed) {
                last_verify_at = Some(Instant::now());
            }
            let _ = driver.inject(Instant::now(), e, &mut fx);
        }
        runtime.set_steered(driver.supervisor().is_steered());
        publish(&driver, &runtime, &last_verify_at);

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
    let deadline = Instant::now() + STOP_PATIENCE;
    let _ = driver.inject(Instant::now(), Event::StopRequested, &mut fx);
    while driver.state() != State::Stopped && Instant::now() < deadline {
        let now = Instant::now();
        let tick = driver.tick(now, &mut obs, &mut fx);
        for e in runtime.take_pending() {
            let _ = driver.inject(Instant::now(), e, &mut fx);
        }
        match tick.sleep {
            Some(d) if d.is_zero() => {}
            _ => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    // The final word: whatever the teardown left behind — including an
    // undead VPP that refused to die — is on the record for the caller.
    publish(&driver, &runtime, &last_verify_at);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A factory that dies is an ATTACH failure, reported synchronously
    /// from `start()` — not a mysteriously dead thread discovered later
    /// by a health check reading frozen status.
    #[test]
    fn a_failed_factory_fails_start_synchronously() {
        let result = SupervisionService::start(
            "vpp-offload",
            Box::new(|| panic!("factory failed on purpose")),
        );
        let err = result
            .err()
            .expect("start must fail, not hand back a dead loop");
        assert!(err.contains("died before publishing"), "{err}");
    }
}
