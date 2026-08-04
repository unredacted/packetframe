//! The runtime: [`Observe`] and [`Effects`] implemented by delegation
//! to the real machinery — [`VppProcess`] for the process,
//! [`ConvergenceEngine`] for everything reachable over the API socket,
//! and a [`Steering`] seam for the MCAM rules that land in slice 5.
//!
//! This is the last layer of pure wiring before `Module::attach()`. It
//! deliberately contains **no policy**: every decision lives in the
//! supervisor, every deadline in the schedule, and this module's only
//! job is to make requests happen and report what was observed. The one
//! rule inherited from the driver applies with full force here —
//! *nothing is recorded as done because it was requested* — and each
//! method below says which side of that line it sits on.
//!
//! ## One machine, two traits, and why there is a `RefCell`
//!
//! [`Driver::tick`](crate::driver::Driver::tick) takes `Observe` and
//! `Effects` as two separate `&mut` receivers, which is right for tests
//! and right conceptually. But in the real system both traits terminate
//! in the same state — the engine owns the socket that `ping` (observe)
//! and `start_resync` (effect) both use — so one struct cannot be handed
//! out as two exclusive borrows. [`Runtime::views`] therefore yields two
//! lightweight views over a shared `RefCell` core. That is sound because
//! the driver's call pattern is strictly sequential: no `Observe` call
//! is made while an `Effects` call is in progress or vice versa, so a
//! borrow never overlaps. A re-entrant borrow panic here would mean the
//! driver broke that contract, and a loud panic is the correct report.
//!
//! ## What is deliberately NOT here
//!
//! - **Resource acquisition** (hugepages → VF → vfio → startup.conf).
//!   That is `attach()`-time setup with its own ordering and rollback,
//!   already implemented in [`crate::resources`]; the wiring PR owns it.
//! - **State-file I/O.** The runtime reports identity changes through
//!   [`IdentityStore`] at the moment they are observed, but what a
//!   record means on disk belongs to the owner of the
//!   [`ResourceState`](crate::resources::ResourceState) — the same
//!   attach wiring. A [`NullStore`] exists for tests only.
//! - **MCAM steering.** [`Steering`] is a seam; the ETHTOOL
//!   implementation is slice 5. The placeholder here refuses in both
//!   directions — see [`SteeringUnavailable`] for why refusing to
//!   *unsteer* is the load-bearing half.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use crate::driver::Observe;
use crate::engine::{ConvergenceEngine, RouteSource};
use crate::executor::Effects;
use crate::process::{terminate_or_leak, Disposition, VppProcess};
use crate::supervisor::Event;

/// How long a SIGTERM gets before escalation, on top of the bounded
/// SIGKILL wait inside [`VppProcess::terminate`].
///
/// SIGTERM here is a courtesy, not a correctness need: by the time
/// `Kill` is issued steering is already down (rule 2), and VPP holds no
/// durable state — its FIB is reconstructed from the mirror on every
/// start. So the grace is sized against the `Module::detach` contract
/// (< 1 s, SPEC.md §3.2), which this kill path sits inside: 500 ms of
/// courtesy keeps the cooperative case within the contract. The
/// uninterruptible-sleep case (VFIO/DMA, SIGKILL cannot bite) exceeds
/// any budget by nature; `terminate` bounds that wait at 2 s and
/// reports `MustLeak` rather than hanging, which is the documented
/// best-effort relaxation from slice 2 — detach fails loudly instead of
/// blocking forever on a process the kernel will not release.
pub const TERM_GRACE: Duration = Duration::from_millis(500);

/// The `(pid, start_ticks, boot_id)` triple that makes a recorded
/// process identity safe to act on across restarts and PID reuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: i32,
    pub start_ticks: u64,
    pub boot_id: Option<String>,
}

/// Where observed identity changes are recorded.
///
/// A trait rather than direct file I/O because the runtime does not own
/// the state file — the attach wiring does, along with the hugepage and
/// VF records that live in the same [`crate::resources::ResourceState`].
/// The contract is *observed, then recorded*: these are called at the
/// moment the fact becomes true, never in anticipation of it.
pub trait IdentityStore {
    /// The supervised process changed: `Some` after a successful spawn,
    /// `None` once it is confirmed gone.
    fn process_changed(&mut self, identity: Option<ProcessIdentity>) -> Result<(), String>;

    /// VPP acknowledged these interfaces (`(port, sw_if_index)`).
    /// Persisting them is what lets the next daemon adopt instead of
    /// blind-attaching.
    fn interfaces_attached(&mut self, indices: &[(String, u32)]) -> Result<(), String>;
}

/// Hands back the VF/vfio/hugepage resources attach acquired.
///
/// Separate from [`IdentityStore`] because the two are called by
/// different actors at different moments — the store on every observed
/// identity change, this exactly once, from the executor's
/// `ReleaseResources`, and only when teardown reported clean. It is a
/// constructor argument rather than an optional setter for the reason
/// this phase keeps relearning: an omitted-by-default seam is one nobody
/// notices is unwired, and the symptom here would be a `detach` that
/// reports success over still-held VFs.
///
/// The implementation ([`crate::acquire::ResourceOwner`]) shares one
/// [`crate::resources::ResourceState`] with the identity store, so that
/// a `process_changed` arriving after the release cannot re-create a
/// state file describing resources that are gone.
pub trait ResourceRelease {
    /// `Ok` means everything the state recorded is confirmed released
    /// and the state file is gone. `Err` means some of it is still held,
    /// and the message names what.
    fn release(&mut self) -> Result<(), String>;
}

/// Store that records nothing. Tests only — a production runtime with a
/// null store produces orphans no future daemon can adopt.
#[derive(Debug, Default)]
pub struct NullStore;

impl IdentityStore for NullStore {
    fn process_changed(&mut self, _: Option<ProcessIdentity>) -> Result<(), String> {
        Ok(())
    }
    fn interfaces_attached(&mut self, _: &[(String, u32)]) -> Result<(), String> {
        Ok(())
    }
}

/// Releases nothing, and says so. Tests only, and it must keep
/// **refusing**: `Ok` from a release the supervisor believes is real
/// would clear `resources_leaked` and let `detach` report freed VFs that
/// are still bound to vfio.
#[derive(Debug, Default)]
pub struct NoResources;

impl ResourceRelease for NoResources {
    fn release(&mut self) -> Result<(), String> {
        Err("this runtime holds no resources to release".into())
    }
}

/// The MCAM steering seam. Real implementation lands in slice 5
/// (ETHTOOL_SRXCLSRLINS, ring_cookie `(vf+1)<<32`, loc budgeting).
pub trait Steering {
    /// Install the rules. `Ok` means they are confirmed in the NIC.
    fn steer(&mut self) -> Result<(), String>;
    /// Remove the rules. `Ok` means they are confirmed gone — and only
    /// then, because the supervisor releases VFs on the strength of it.
    fn unsteer(&mut self) -> Result<(), String>;
}

/// The placeholder until slice 5: refuses both directions.
///
/// `steer` refusing is obvious. `unsteer` refusing is the half that
/// matters: `Ok` from unsteer becomes `Event::Unsteered`, which clears
/// `steered` and unblocks `ReleaseResources` — so a placeholder that
/// faked success would let the supervisor release a VF that MCAM rules
/// from a previous run might still be pointing traffic at. Refusing
/// keeps `steered` true and the VF withheld, which is the designed
/// behaviour for "rules exist that we cannot manage". A config with
/// every port `steer off` never reaches either path.
#[derive(Debug, Default)]
pub struct SteeringUnavailable;

impl Steering for SteeringUnavailable {
    fn steer(&mut self) -> Result<(), String> {
        Err("MCAM steering is not implemented until slice 5; port stays unsteered".into())
    }
    fn unsteer(&mut self) -> Result<(), String> {
        Err("MCAM steering is not implemented until slice 5; cannot confirm rules removed".into())
    }
}

/// Everything both trait views share.
struct Core {
    engine: ConvergenceEngine,
    /// `None` when nothing is supervised: before the first spawn, after
    /// a confirmed exit, or after a clean kill. Kept across `MustLeak`,
    /// because the pidfd is the only way the late exit will ever be
    /// observed.
    process: Option<VppProcess>,
    source: Box<dyn RouteSource>,
    steering: Box<dyn Steering>,
    store: Box<dyn IdentityStore>,
    resources: Box<dyn ResourceRelease>,
    vpp_binary: PathBuf,
    startup_conf: PathBuf,
    /// Whether this convergence adopts interfaces VPP already has.
    /// Set by the attach wiring alongside the injected `Adopted` event;
    /// reset to `Fresh` once the process it described is gone.
    attach_mode: crate::attach::AttachMode,
    /// Events produced by completed work, waiting for the loop to
    /// inject them. The verify verdict travels this way: `start_verify`
    /// is an effect, its outcome is an observation of what VPP
    /// answered, and the loop feeds it back through
    /// [`Driver::inject`](crate::driver::Driver::inject) — the same
    /// path every driver test uses.
    pending: Vec<Event>,
    /// The last identity-store failure on a path that could not refuse
    /// (an observed exit is a fact whether or not it can be recorded).
    /// Surfaced for status; never blocks the loop.
    last_store_error: Option<String>,
}

/// Owner handle. Create once, then [`Runtime::views`] per tick.
pub struct Runtime {
    core: Rc<RefCell<Core>>,
}

/// The `Observe` half. See the module docs for why this is a view.
pub struct ObserveView {
    core: Rc<RefCell<Core>>,
}

/// The `Effects` half.
pub struct EffectsView {
    core: Rc<RefCell<Core>>,
}

impl Runtime {
    pub fn new(
        engine: ConvergenceEngine,
        source: Box<dyn RouteSource>,
        steering: Box<dyn Steering>,
        store: Box<dyn IdentityStore>,
        resources: Box<dyn ResourceRelease>,
        vpp_binary: impl Into<PathBuf>,
        startup_conf: impl Into<PathBuf>,
    ) -> Self {
        Self {
            core: Rc::new(RefCell::new(Core {
                engine,
                process: None,
                source,
                steering,
                store,
                resources,
                vpp_binary: vpp_binary.into(),
                startup_conf: startup_conf.into(),
                attach_mode: crate::attach::AttachMode::Fresh,
                pending: Vec::new(),
                last_store_error: None,
            })),
        }
    }

    /// Hand over an adopted process, with the steering fact attached.
    ///
    /// The caller injects `Event::Adopted { steered }` itself — adoption
    /// is an external fact, not something the runtime infers — and MUST
    /// call this first, passing the same `steered`. This records the
    /// handle, switches the next attach to `Adopted` so recorded
    /// interface indices are reused rather than duplicated, and applies
    /// the steering fact to the engine's socket deadline **atomically
    /// with the handover**.
    ///
    /// The last part is why `steered` is a parameter here instead of the
    /// loop's post-tick `set_steered` sync: `Driver::inject(Adopted)`
    /// synchronously runs `AttachDevices` and `StartResync` before any
    /// post-tick call can happen, and an adopted VPP is the one case
    /// still carrying live traffic while it converges. With the engine
    /// still thinking `steered == false`, those requests would run under
    /// the relaxed 10 s resync budget — a stall the published ≤ 2 s
    /// wedge bound is supposed to catch while packets are on VPP.
    pub fn adopt_process(&self, p: VppProcess, steered: bool) {
        let mut c = self.core.borrow_mut();
        c.process = Some(p);
        c.attach_mode = crate::attach::AttachMode::Adopted;
        c.engine.set_steered(steered);
    }

    /// The two trait views the driver's tick takes.
    pub fn views(&self) -> (ObserveView, EffectsView) {
        (
            ObserveView {
                core: Rc::clone(&self.core),
            },
            EffectsView {
                core: Rc::clone(&self.core),
            },
        )
    }

    /// Drain events produced by completed work (verify verdicts), for
    /// the loop to feed through `Driver::inject`.
    pub fn take_pending(&self) -> Vec<Event> {
        std::mem::take(&mut self.core.borrow_mut().pending)
    }

    /// Keep the engine's socket deadline keyed to the budget in force.
    /// Called by the loop after every tick with
    /// `driver.supervisor().is_steered()`.
    pub fn set_steered(&self, steered: bool) {
        self.core.borrow_mut().engine.set_steered(steered);
    }

    /// Whether the API handshake failed in a way retrying cannot fix
    /// (CRC mismatch, unknown message, refusal). The loop uses this to
    /// stop burning the startup budget on a VPP that can never answer.
    pub fn api_incompatible(&self) -> bool {
        self.core.borrow().engine.api_incompatible()
    }

    /// Status inputs, observed: last verify, counts, port links, the
    /// last API error, and any store failure from a path that could not
    /// refuse.
    pub fn status(&self) -> RuntimeStatus {
        let c = self.core.borrow();
        RuntimeStatus {
            counts: c.engine.counts(),
            pending_ops: c.engine.pending().len() as u64,
            parked_ops: c.engine.pending().withheld_len() as u64,
            last_verify: c.engine.last_verify().cloned(),
            port_links: c.engine.port_links(),
            api_error: c.engine.last_api_error().map(str::to_string),
            store_error: c.last_store_error.clone(),
        }
    }
}

/// One coherent snapshot of the runtime's observable state, for the
/// health surface. Everything in it came from an observation.
#[derive(Debug, Clone)]
pub struct RuntimeStatus {
    pub counts: crate::sink::SinkCounts,
    pub pending_ops: u64,
    pub parked_ops: u64,
    pub last_verify: Option<crate::verify::VerifyOutcome>,
    pub port_links: Vec<crate::status::PortLink>,
    pub api_error: Option<String>,
    pub store_error: Option<String>,
}

impl Core {
    /// A freshly spawned child whose identity cannot be made durable —
    /// the store refused it, or its boot_id could not be read — must
    /// not survive unrecorded, and must not be *forgotten* either.
    ///
    /// Termination is attempted; the disposition decides everything.
    /// `SafeToRelease`: the child is gone and the spawn simply failed.
    /// `MustLeak`: the child survived SIGKILL (VFIO/DMA), and the first
    /// version of this path dropped the handle anyway — discarding the
    /// one observer (the pidfd) that will ever report the late exit,
    /// and leaving `SpawnFailed`'s retry free to start a second VPP
    /// over a VF the survivor may still be DMAing through. The handle
    /// is retained, so `spawn` refuses while it exists.
    ///
    /// Deliberately, **no `TerminationFailed` is queued here.** The
    /// `SpawnFailed` this returns drives the supervisor's `fail()`,
    /// whose `Kill` action re-runs termination against the retained
    /// handle — and the *executor* emits `TerminationFailed` if that
    /// kill still reports `MustLeak`. Queuing one here as well was a
    /// second clock for one deadline, and a stale one: if the child
    /// died between the two kills, the second returned `SafeToRelease`
    /// and dropped the handle, and the queued event then set `undead`
    /// with no pidfd left alive to ever clear it — permanently
    /// suppressing restarts. Letting the kill path be the sole emitter
    /// means the event exists exactly when the survivor does.
    fn abandon_spawn(&mut self, mut p: VppProcess, why: String) -> String {
        let pid = p.pid();
        match terminate_or_leak(&mut p, TERM_GRACE) {
            Disposition::SafeToRelease => {
                format!("spawned pid {pid} but {why}; the child was terminated")
            }
            Disposition::MustLeak => {
                self.process = Some(p);
                format!(
                    "spawned pid {pid} but {why}; the child SURVIVED termination — \
                     handle retained, the follow-up kill will report it"
                )
            }
        }
    }

    /// The process is confirmed gone: invalidate everything learned
    /// from it. Indices are per-instance, the ledger describes a FIB
    /// that no longer exists, and the socket belongs to the dead
    /// process. The next spawn starts from nothing — including
    /// `AttachMode::Fresh`, because the recorded indices died with the
    /// instance (the engine clears its own copy for the same reason).
    fn process_gone(&mut self) {
        self.process = None;
        self.attach_mode = crate::attach::AttachMode::Fresh;
        self.engine.on_process_gone();
        // The exit is a fact whether or not it can be recorded; surface
        // the failure, do not block on it.
        let r = self.store.process_changed(None);
        let _ = self.note_persist(r);
    }

    /// The single place a persist outcome is recorded — and the only
    /// place it is cleared.
    ///
    /// Clearing on success matters because the degradation is otherwise
    /// permanent: `last_store_error` was set on every failure and never
    /// reset, so one transient failure (a briefly read-only state dir, a
    /// full filesystem) kept the module out of `nominal()` for the life of
    /// the service even after the record became durable again.
    ///
    /// And a single successful write really does restore the whole
    /// record: [`crate::acquire::FileStore`] saves the entire
    /// `ResourceState` on every observation rather than a delta, so any
    /// write that lands makes the file current — hugepages, VFs,
    /// interface indices and process identity together. That is what
    /// makes "adoption is safe again" a fact rather than a hope.
    /// Returns the outcome so callers that must ACT on a failure — spawn's
    /// persist-or-kill — can still branch on it without bypassing the
    /// recorder. The first version returned `()`, which is precisely why
    /// `spawn` kept its own direct `store.process_changed` call and a
    /// successful spawn-persist never cleared an earlier failure: the
    /// helper's own doc claimed to be the single recorder while one writer
    /// in the same file went around it.
    fn note_persist(&mut self, r: Result<(), String>) -> Result<(), String> {
        match &r {
            Ok(()) => self.last_store_error = None,
            Err(e) => self.last_store_error = Some(e.clone()),
        }
        r
    }
}

impl Observe for ObserveView {
    fn poll_exit(&mut self) -> Option<Option<i32>> {
        let mut c = self.core.borrow_mut();
        let p = c.process.as_mut()?;
        match p.poll_exit(Duration::ZERO) {
            Ok(Some(status)) => {
                // Observed dead: report it exactly once, and clean up
                // now — the handle has nothing more to say.
                c.process_gone();
                Some(status)
            }
            Ok(None) => None,
            // A pidfd read error is indistinguishable from "cannot
            // observe" — report nothing rather than invent an exit.
            // The wedge detector covers a process that is silently
            // broken.
            Err(_) => None,
        }
    }

    fn api_ready(&mut self) -> bool {
        self.core.borrow_mut().engine.api_ready()
    }

    fn ping(&mut self) -> Result<(), String> {
        self.core
            .borrow_mut()
            .engine
            .ping()
            .map_err(|e| e.to_string())
    }

    fn drain_batch(&mut self) -> Result<bool, String> {
        self.core
            .borrow_mut()
            .engine
            .drain_batch()
            .map(|(done, _stats)| done)
            .map_err(|e| e.to_string())
    }
}

impl Effects for EffectsView {
    fn spawn(&mut self) -> Result<(), String> {
        let mut c = self.core.borrow_mut();
        if c.process.is_some() {
            // Two processes cannot share the VF and the API socket. If
            // the supervisor asks for a spawn while a handle exists,
            // something upstream is wrong — refuse rather than orphan
            // the first.
            return Err("refusing to spawn: a supervised process already exists".into());
        }
        let (binary, conf) = (c.vpp_binary.clone(), c.startup_conf.clone());
        let p = VppProcess::spawn(&binary, &conf).map_err(|e| format!("spawning VPP: {e}"))?;

        // The boot_id is not optional in spirit: `VppProcess::adopt`
        // refuses an identity without one (a `(pid, ticks)` pair is
        // forgeable across a reboot), so recording `None` here would
        // manufacture a live VPP no future daemon can ever adopt — an
        // orphan holding the VF. An unreadable boot_id therefore gets
        // the same treatment as a store failure: the child does not
        // survive unrecorded.
        let boot_id = match crate::process::boot_id() {
            Ok(b) => b,
            Err(e) => {
                return Err(c.abandon_spawn(
                    p,
                    format!("its boot_id could not be read ({e}), making it unadoptable"),
                ))
            }
        };
        let identity = ProcessIdentity {
            pid: p.pid(),
            start_ticks: p.start_ticks(),
            boot_id: Some(boot_id),
        };
        // Through `note_persist`, not around it: a spawn that persists
        // successfully must also CLEAR any earlier failure, since the save
        // is whole-record. Persist-or-kill still applies — a VPP whose
        // identity is not on disk cannot be adopted after a daemon restart.
        let recorded = c.store.process_changed(Some(identity));
        if let Err(e) = c.note_persist(recorded) {
            return Err(c.abandon_spawn(p, format!("could not record it: {e}")));
        }
        c.process = Some(p);
        Ok(())
    }

    fn unsteer(&mut self) -> Result<(), String> {
        self.core.borrow_mut().steering.unsteer()
    }

    fn steer(&mut self) -> Result<(), String> {
        self.core.borrow_mut().steering.steer()
    }

    fn kill(&mut self) -> Disposition {
        let mut c = self.core.borrow_mut();
        let Some(p) = c.process.as_mut() else {
            // Nothing supervised: nothing holds the resources.
            return Disposition::SafeToRelease;
        };
        match terminate_or_leak(p, TERM_GRACE) {
            Disposition::SafeToRelease => {
                c.process_gone();
                Disposition::SafeToRelease
            }
            Disposition::MustLeak => {
                // The process survived SIGKILL — most likely parked in
                // an uninterruptible VFIO/DMA call. Keep the handle:
                // the pidfd is the only observer that will ever report
                // the late exit, and dropping it would leave the
                // supervisor's `undead` flag with no way to clear.
                // Identity stays recorded for the same reason.
                Disposition::MustLeak
            }
        }
    }

    fn attach_devices(&mut self) -> Result<(), String> {
        let mut c = self.core.borrow_mut();
        let mode = c.attach_mode;
        c.engine.attach_devices(mode).map_err(|e| e.to_string())?;
        let indices = c.engine.attached_indices();
        // Unlike spawn, do not tear anything down: the interfaces exist
        // and work. The cost of a lost record is one refused adoption
        // after a daemon restart (UnknownIndexOnAdopt → clean restart),
        // which is the designed safe fallback. Surfaced, not fatal — and
        // a success here CLEARS an earlier failure, since the save is
        // whole-record (see `note_persist`).
        let r = c.store.interfaces_attached(&indices);
        let _ = c.note_persist(r);
        Ok(())
    }

    fn start_resync(&mut self) -> Result<(), String> {
        let mut c = self.core.borrow_mut();
        // Split borrow: the engine walks the source while both live in
        // the same core.
        let Core { engine, source, .. } = &mut *c;
        let _plan = engine.begin_resync(source.as_ref());
        // Neighbours between attach and the first drain, and fatal on
        // refusal: a route through an unprogrammed adjacency installs
        // cleanly, verifies cleanly, and drops every packet.
        engine
            .program_neighbours(source.as_ref())
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    fn start_verify(&mut self) -> Result<(), String> {
        let mut c = self.core.borrow_mut();
        match c.engine.run_verify() {
            Ok(verdict) => {
                // The verdict is an observation of what VPP answered.
                // It reaches the supervisor through the loop's inject,
                // not from inside this Effects call — the same seam
                // every driver test drives.
                let event = verdict.event();
                c.pending.push(event);
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    fn abort_convergence(&mut self) {
        let mut c = self.core.borrow_mut();
        c.engine.abort_convergence();
        // The abort is complete as soon as the engine forgets its
        // phase — nothing here runs on another thread — so the
        // supervisor's `converging` flag can be cleared immediately.
        // Without this the flag never clears (nothing else emits the
        // event) and `may_restart` stays false forever.
        c.pending.push(Event::ConvergenceStopped);
    }

    fn arm_backoff(&mut self, _delay: Duration) {
        // The Driver arms its own Schedule from the same action (see
        // Driver::apply); this hook exists for callers without one.
        // Doing it twice would be two clocks for one deadline.
    }

    fn release_resources(&mut self) -> Result<(), String> {
        // The state file and the sysfs paths belong to the attach
        // wiring, so this delegates rather than reaching for them; see
        // [`ResourceRelease`]. The executor only ever calls this after
        // teardown reported clean, so a live VPP cannot be DMAing into
        // what it releases.
        self.core.borrow_mut().resources.release()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fib_sync::FamilyPolicy;
    use packetframe_common::fib::IpPrefix;
    use std::net::IpAddr;
    // Only the Linux-gated process tests need these.
    #[cfg(target_os = "linux")]
    use std::sync::{Arc, Mutex};

    struct EmptySource;
    impl RouteSource for EmptySource {
        fn for_each_route(&self, _: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, _: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {}
    }

    fn engine() -> ConvergenceEngine {
        ConvergenceEngine::new(
            "/nonexistent/api.sock",
            Vec::new(),
            vec!["eth4".into()],
            1_000,
            FamilyPolicy::V4Only,
        )
    }

    fn runtime() -> Runtime {
        Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(SteeringUnavailable),
            Box::new(NullStore),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        )
    }

    /// The placeholder must refuse BOTH directions. `unsteer` faking
    /// success would emit `Unsteered`, clear `steered`, and unblock the
    /// release of a VF that rules from a previous run might still be
    /// pointing traffic at.
    #[test]
    fn steering_placeholder_refuses_both_directions() {
        let rt = runtime();
        let (_, mut fx) = rt.views();
        assert!(fx.steer().is_err());
        assert!(
            fx.unsteer().is_err(),
            "a faked Unsteered releases a VF that MCAM may still target"
        );
    }

    /// A verify verdict travels through `take_pending` to be injected —
    /// never applied from inside the Effects call. And a transport
    /// failure produces no verdict at all: "could not ask" is not an
    /// answer about the FIB.
    #[test]
    fn verify_failure_produces_no_pending_verdict() {
        let rt = runtime();
        let (_, mut fx) = rt.views();
        assert!(
            fx.start_verify().is_err(),
            "no transport → the effect fails"
        );
        assert!(
            rt.take_pending().is_empty(),
            "a failed verify must not leave a verdict to inject"
        );
    }

    /// `abort_convergence` must deliver `ConvergenceStopped`, because
    /// nothing else ever will: the engine's abort is synchronous, and a
    /// supervisor whose `converging` flag never clears can never
    /// restart.
    #[test]
    fn abort_delivers_convergence_stopped() {
        let rt = runtime();
        let (_, mut fx) = rt.views();
        fx.abort_convergence();
        assert_eq!(rt.take_pending(), vec![Event::ConvergenceStopped]);
        assert!(rt.take_pending().is_empty(), "delivered exactly once");
    }

    /// With nothing supervised, `kill` reports the resources safe —
    /// there is no process to be holding them.
    #[test]
    fn kill_with_no_process_is_safe_to_release() {
        let rt = runtime();
        let (_, mut fx) = rt.views();
        assert_eq!(fx.kill(), Disposition::SafeToRelease);
    }

    /// `release_resources` refuses rather than no-ops: reporting
    /// resources freed that the (unbuilt) attach wiring still holds is
    /// the requested-vs-observed bug in its purest form.
    #[test]
    fn release_refuses_until_the_owner_exists() {
        let rt = runtime();
        let (_, mut fx) = rt.views();
        assert!(fx.release_resources().is_err());
    }

    /// Observe calls with no process/transport report absence rather
    /// than failing or inventing.
    #[test]
    fn observations_with_nothing_to_observe_report_nothing() {
        let rt = runtime();
        let (mut obs, _) = rt.views();
        assert_eq!(obs.poll_exit(), None);
        assert!(!obs.api_ready(), "nothing is listening");
        assert!(obs.ping().is_err());
        assert!(obs.drain_batch().is_err());
    }

    /// A store that fails at spawn time must kill the child. A VPP
    /// whose identity is not on disk cannot be adopted after a daemon
    /// restart — it survives as an orphan holding the VF.
    #[cfg(target_os = "linux")]
    #[test]
    fn spawn_kills_the_child_if_identity_cannot_be_recorded() {
        struct FailingStore;
        impl IdentityStore for FailingStore {
            fn process_changed(&mut self, id: Option<ProcessIdentity>) -> Result<(), String> {
                if id.is_some() {
                    Err("disk full".into())
                } else {
                    Ok(())
                }
            }
            fn interfaces_attached(&mut self, _: &[(String, u32)]) -> Result<(), String> {
                Ok(())
            }
        }
        let rt = Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(SteeringUnavailable),
            Box::new(FailingStore),
            Box::new(NoResources),
            // Any spawnable binary will do; it is killed immediately.
            "/bin/sleep",
            "/dev/null",
        );
        let (mut obs, mut fx) = rt.views();
        let err = fx.spawn().expect_err("persist-or-kill");
        assert!(err.contains("could not record"), "{err}");
        // The handle must NOT be retained: the spawn failed as far as
        // the supervisor is concerned, and a kept process would leak.
        assert_eq!(obs.poll_exit(), None, "no supervised process remains");
    }

    /// Identity recorded on spawn, cleared on observed exit — each at
    /// the moment it became true.
    #[cfg(target_os = "linux")]
    #[test]
    fn identity_is_recorded_on_spawn_and_cleared_on_exit() {
        #[derive(Default)]
        struct Recording(Arc<Mutex<Vec<Option<i32>>>>);
        impl IdentityStore for Recording {
            fn process_changed(&mut self, id: Option<ProcessIdentity>) -> Result<(), String> {
                self.0.lock().unwrap().push(id.map(|i| i.pid));
                Ok(())
            }
            fn interfaces_attached(&mut self, _: &[(String, u32)]) -> Result<(), String> {
                Ok(())
            }
        }
        let log = Arc::new(Mutex::new(Vec::new()));
        let rt = Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(SteeringUnavailable),
            Box::new(Recording(Arc::clone(&log))),
            Box::new(NoResources),
            // `VppProcess::spawn(binary, conf)` execs `binary -c conf`;
            // /bin/true exits immediately regardless of arguments,
            // which is exactly what this test wants.
            "/bin/true",
            "/dev/null",
        );
        let (mut obs, mut fx) = rt.views();
        fx.spawn().expect("spawn /bin/true");
        {
            let l = log.lock().unwrap();
            assert_eq!(l.len(), 1);
            assert!(l[0].is_some(), "identity recorded with a real pid");
        }
        // The child exits at once; the pidfd reports it, and the exit
        // clears the record.
        let mut exited = None;
        for _ in 0..100 {
            if let Some(status) = obs.poll_exit() {
                exited = Some(status);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(exited.is_some(), "the exit must be observed via the pidfd");
        assert_eq!(
            log.lock().unwrap().last().unwrap(),
            &None,
            "identity cleared once the exit was observed"
        );
        // And only once.
        assert_eq!(obs.poll_exit(), None);
    }
}
