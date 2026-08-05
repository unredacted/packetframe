//! The runtime: [`Observe`] and [`Effects`] implemented by delegation
//! to the real machinery — [`VppProcess`] for the process,
//! [`ConvergenceEngine`] for everything reachable over the API socket,
//! and a [`Steering`] seam over the MCAM rules ([`crate::ntuple`]).
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
//!   implementation is [`crate::ntuple`]. [`SteeringUnavailable`] stands
//!   in where no port steers, and refuses in both directions — see it
//!   for why refusing to *unsteer* is the load-bearing half.

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

/// How many live route changes one tick pulls from the source.
///
/// Bounded for the same reason `drain_batch` is: this runs on the
/// supervision thread, and an unbounded pull during a peering flap would
/// hold the tick for as long as the flap lasted, sending no ping and
/// noticing no exit. Whatever is left stays in the source's map — which
/// collapses per prefix, so waiting costs staleness, never depth.
const DELTA_BATCH: usize = 4096;

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

    /// The MCAM rules believed installed right now, as `(iface, loc)`.
    ///
    /// Written after every steer and unsteer, in both polarities.
    /// MCAM rules outlive the process that installed them — they are
    /// NIC state, not process state — so this file is the only thing
    /// that can tell the next daemon they exist.
    ///
    /// Without it a restart with a steered VPP alive was doubly unsafe.
    /// `bring_up` derives `Adopted { steered }` from the recorded rules,
    /// so an empty record meant the supervisor believed nothing was
    /// diverted: teardown emitted no `Unsteer` and released the VF with
    /// MCAM still pointing traffic into it. And
    /// [`Steering::unsteer`] removes what its own ledger names, so a
    /// fresh ledger would have answered `Ok` — reporting rules removed
    /// that were still in the NIC.
    fn steering_changed(&mut self, rules: &[(String, u32)]) -> Result<(), String>;
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
    fn steering_changed(&mut self, _: &[(String, u32)]) -> Result<(), String> {
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

/// The MCAM steering seam ([`crate::ntuple::NtupleSteering`] is the
/// real one: ETHTOOL_SRXCLSRLINS, ring_cookie `(vf+1)<<32`, loc
/// budgeting).
///
/// [`Self::steer`] is a **reconcile**, not an append: it makes the NIC
/// match the current target, whatever was there before. That is what
/// the supervisor already assumes when it re-emits `Action::Steer` for
/// a VPP it believes is steered (the UniFi controller wipes classifier
/// state on provisioning, so rules may simply be gone), and it is what
/// lets [`Self::retarget`] change the target under a live port without
/// a second code path.
pub trait Steering {
    /// Install the rules. `Ok` means they are confirmed in the NIC.
    fn steer(&mut self) -> Result<(), String>;
    /// Remove the rules. `Ok` means they are confirmed gone — and only
    /// then, because the supervisor releases VFs on the strength of it.
    fn unsteer(&mut self) -> Result<(), String>;
    /// `(iface, loc)` for every rule believed to be in the NIC right
    /// now, including any that a removal could not clear.
    ///
    /// Read after **every** steer and unsteer, successful or not, and
    /// persisted — see [`IdentityStore::steering_changed`]. A rule that
    /// would not come out is still diverting traffic, so the failure
    /// path is the one that most needs this recorded.
    fn installed(&self) -> Vec<(String, u32)>;
    /// Change what steering *should* be, without touching the NIC.
    ///
    /// Deliberately infallible and side-effect-free: it records intent,
    /// and the next `steer`/`unsteer` is what makes the hardware agree.
    /// Splitting it that way keeps one routine — `steer` — responsible
    /// for every rule that ever reaches the NIC, so a reconfigure cannot
    /// grow its own, subtly different, installation path.
    fn retarget(&mut self, ports: Vec<(String, u32)>, plan: crate::steer::RuleSet);
}

/// A steering seam that refuses both directions.
///
/// Used where no port asks to steer, and by tests. `steer` refusing is
/// obvious. `unsteer` refusing is the half that matters: `Ok` from
/// unsteer becomes `Event::Unsteered`, which clears `steered` and
/// unblocks `ReleaseResources` — so a stand-in that faked success would
/// let the supervisor release a VF that MCAM rules from a previous run
/// might still be pointing traffic at. Refusing keeps `steered` true
/// and the VF withheld, which is the designed behaviour for "rules
/// exist that we cannot manage". A config with every port `steer off`
/// never reaches either path.
#[derive(Debug, Default)]
pub struct SteeringUnavailable;

impl Steering for SteeringUnavailable {
    fn steer(&mut self) -> Result<(), String> {
        Err("MCAM steering is unavailable in this runtime; port stays unsteered".into())
    }
    fn unsteer(&mut self) -> Result<(), String> {
        Err("MCAM steering is unavailable in this runtime; cannot confirm rules removed".into())
    }
    fn installed(&self) -> Vec<(String, u32)> {
        Vec::new()
    }
    fn retarget(&mut self, _ports: Vec<(String, u32)>, _plan: crate::steer::RuleSet) {}
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
    /// The completeness gate: may traffic be diverted into the mirror
    /// yet?
    ///
    /// `None` when `require-table-complete off` — the deployment has no
    /// authority to compare against (the shadow has no bird of its own)
    /// and the operator owns the judgement instead.
    completeness: Option<std::sync::Arc<packetframe_common::fib::TableCompleteness>>,
    /// Why the last drain failed, or `None` if the last one succeeded.
    ///
    /// Recorded here rather than left to the caller because the caller
    /// deliberately throws it away: outside a resync a failed batch is
    /// retried, not escalated, so the driver's steady-state arm has no
    /// event to carry a reason on. Without this the module would degrade
    /// silently — the one shape this phase keeps producing — and the
    /// operator would see a stalled `pending_ops` with nothing saying
    /// why.
    last_drain_error: Option<String>,
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
                completeness: None,
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
                last_drain_error: None,
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

    /// Require the route mirror to be confirmed converged before any
    /// steer installs rules.
    ///
    /// Set by the attach wiring when `require-table-complete on` (the
    /// default). Left unset, [`Effects::steer`] does not consult
    /// completeness at all — which is the honest shape for a deployment
    /// with no authority to compare against, and is a config decision
    /// rather than an inference.
    pub fn require_table_complete(
        &self,
        handle: std::sync::Arc<packetframe_common::fib::TableCompleteness>,
    ) {
        self.core.borrow_mut().completeness = Some(handle);
    }

    /// Point steering at a new set of ports and rules.
    ///
    /// Records intent only — see [`Steering::retarget`]. The caller must
    /// follow it with the supervisor event that reconciles the NIC, and
    /// the supervision loop is the only caller precisely so that the two
    /// cannot be separated.
    pub fn retarget(&self, ports: Vec<(String, u32)>, plan: crate::steer::RuleSet) {
        self.core.borrow_mut().steering.retarget(ports, plan);
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
            drain_error: c.last_drain_error.clone(),
            source_backlog: c.source.backlog(),
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
    /// Why the last drain failed. See `Core::last_drain_error`.
    pub drain_error: Option<String>,
    /// Changes the source is holding that the engine has not pulled yet.
    ///
    /// Distinct from `pending_ops`, which is what the engine has pulled
    /// and not yet sent. Both can be non-zero at once and they fail
    /// differently: a backlog here means the engine is not draining, a
    /// backlog there means VPP is not accepting.
    pub source_backlog: u64,
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

    /// Write the steering ledger through, after any change to it.
    ///
    /// Called on **both** outcomes of steer and unsteer, which is the
    /// whole point. The failure paths are the ones that matter: a
    /// rollback that could not clear a rule, or an unsteer the NIC
    /// refused, leaves rules diverting traffic — and those are exactly
    /// the rules a later `detach --all` has to be able to find.
    /// Recording only successes would persist an empty list at the
    /// moment the record most needs to be non-empty.
    ///
    /// The result goes through [`Self::note_persist`], so a failure
    /// degrades health rather than failing the steer: the rules are in
    /// the NIC either way, and reporting the steer as failed would make
    /// the supervisor believe traffic is not diverted when it is.
    fn record_steering(&mut self) {
        let rules = self.steering.installed();
        let r = self.store.steering_changed(&rules);
        let _ = self.note_persist(r);
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
        let mut c = self.core.borrow_mut();
        // Live changes are pulled in FIRST, so a route learned while VPP
        // was already converged goes out in this same batch rather than
        // waiting for a resync that may never come. The engine's pending
        // map is the single queue either way, so `done` below already
        // accounts for whatever was just added.
        let Core {
            engine,
            source,
            last_drain_error,
            ..
        } = &mut *c;
        // `?`-equivalent: a failed neighbour programming must not be
        // followed by a route drain that installs paths through the
        // adjacency that just failed to land.
        let r = match engine.apply_changes(source.as_ref(), DELTA_BATCH) {
            Err(e) => Err(e.to_string()),
            Ok(_) => engine
                .drain_batch()
                .map(|(done, _stats)| done)
                .map_err(|e| e.to_string()),
        };
        // Set on failure and cleared on success, in one place, for the
        // same reason `note_persist` is: a field that only ever gets set
        // reports a fault that recovered as though it were still
        // happening.
        *last_drain_error = r.as_ref().err().cloned();
        r
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
        let mut c = self.core.borrow_mut();
        let outcome = c.steering.unsteer();
        c.record_steering();
        outcome
    }

    fn steer(&mut self) -> Result<(), String> {
        let mut c = self.core.borrow_mut();
        // The completeness gate, HERE rather than at either caller.
        //
        // Two paths reach a steer: the operator's `reconfigure`, and the
        // supervisor's automatic re-steer once a replacement verifies.
        // The second is the one that would have been missed — the
        // fast-path's mirror rebuilds from bird after a daemon restart,
        // so a VPP that comes back up while the dump is still arriving
        // re-steers into a table missing most of its prefixes. Gating
        // the operator path alone would leave exactly that door open, so
        // the check sits at the single point both go through.
        //
        // Refusing is cheap and self-correcting: it becomes
        // `SteerFailed`, which leaves `steer_wanted` set, so the next
        // verify retries — and by then the dump has usually finished. No
        // rules are installed, so `rules_remain` is unaffected.
        if let Some(handle) = &c.completeness {
            let verdict = handle.verdict();
            if !verdict.permits_steering() {
                return Err(format!(
                    "refusing to steer: {}. Traffic would be diverted into a table that \
                     cannot forward it, and a steered miss is dropped rather than falling \
                     back to the kernel path. This retries on its own once the mirror \
                     converges; `require-table-complete off` opts out where there is no \
                     bird to compare against",
                    verdict.describe()
                ));
            }
        }
        let outcome = c.steering.steer();
        c.record_steering();
        outcome
    }

    fn steering_in_place(&self) -> bool {
        !self.core.borrow().steering.installed().is_empty()
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
        // BEFORE the diff, because the diff is what consumes it: the
        // ledger's contents are where withdrawals come from, and on an
        // adoption it is empty while the surviving VPP's FIB is not.
        // A no-op unless the ledger is empty, so a fresh spawn pays one
        // round trip and adopts nothing.
        let adopted = engine.adopt_vpp_fib().map_err(|e| e.to_string())?;
        if adopted > 0 {
            tracing::info!(
                routes = adopted,
                "adopted VPP's existing FIB; the resync diff can now withdraw what the \
                 route source no longer advertises"
            );
        }
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

    /// Steering that reports a ledger and can be made to fail, so the
    /// persistence wiring can be observed on both polarities.
    #[derive(Default)]
    struct LedgerSteering {
        rules: Vec<(String, u32)>,
        /// What the next call leaves behind, and whether it succeeds.
        next: Option<(Vec<(String, u32)>, bool)>,
    }

    impl Steering for LedgerSteering {
        fn steer(&mut self) -> Result<(), String> {
            let (rules, ok) = self.next.take().unwrap_or_default();
            self.rules = rules;
            if ok {
                Ok(())
            } else {
                Err("MCAM refused".into())
            }
        }
        fn unsteer(&mut self) -> Result<(), String> {
            let (rules, ok) = self.next.take().unwrap_or_default();
            self.rules = rules;
            if ok {
                Ok(())
            } else {
                Err("a rule would not come out".into())
            }
        }
        fn installed(&self) -> Vec<(String, u32)> {
            self.rules.clone()
        }
        fn retarget(&mut self, _: Vec<(String, u32)>, _: crate::steer::RuleSet) {}
    }

    /// Every ledger the store was handed, in order.
    type LedgerLog = std::rc::Rc<std::cell::RefCell<Vec<Vec<(String, u32)>>>>;

    /// Records every steering ledger it is handed.
    #[derive(Default)]
    struct RecordingStore(LedgerLog);

    impl IdentityStore for RecordingStore {
        fn process_changed(&mut self, _: Option<ProcessIdentity>) -> Result<(), String> {
            Ok(())
        }
        fn interfaces_attached(&mut self, _: &[(String, u32)]) -> Result<(), String> {
            Ok(())
        }
        fn steering_changed(&mut self, rules: &[(String, u32)]) -> Result<(), String> {
            self.0.borrow_mut().push(rules.to_vec());
            Ok(())
        }
    }

    /// Every steer and unsteer writes the ledger through — **including
    /// the ones that fail**.
    ///
    /// The failure polarity is the whole reason this is asserted. A
    /// rollback that could not clear a rule, or an unsteer the NIC
    /// refused, leaves rules diverting traffic; recording only successes
    /// would persist an empty list at exactly the moment the record has
    /// to be non-empty, and `detach --all` would have nothing to find.
    #[test]
    fn every_steering_change_is_persisted_including_the_failures() {
        let seen: LedgerLog = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        // A steer that lands two rules, then an unsteer that gets one
        // out and leaves the other stuck.
        let steering = LedgerSteering {
            next: Some((vec![("eth4".into(), 1024), ("eth4".into(), 1025)], true)),
            ..Default::default()
        };

        let rt = Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(steering),
            Box::new(RecordingStore(std::rc::Rc::clone(&seen))),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        let (_, mut fx) = rt.views();
        fx.steer().expect("installs");

        rt.core.borrow_mut().steering = Box::new(LedgerSteering {
            rules: vec![("eth4".into(), 1024), ("eth4".into(), 1025)],
            next: Some((vec![("eth4".into(), 1025)], false)),
        });
        fx.unsteer().expect_err("one rule would not come out");

        let seen = seen.borrow();
        assert_eq!(seen.len(), 2, "both changes reached the store");
        assert_eq!(
            seen[0],
            vec![("eth4".to_string(), 1024), ("eth4".to_string(), 1025)],
            "the successful steer recorded what it installed"
        );
        assert_eq!(
            seen[1],
            vec![("eth4".to_string(), 1025)],
            "the FAILED unsteer recorded the rule still in the NIC — a record of nothing \
             here is a VF released under live steering"
        );
    }

    /// A store that cannot record the ledger degrades health; it does
    /// not fail the steer.
    ///
    /// The rules are in the NIC either way. Reporting the steer as
    /// failed would tell the supervisor traffic is not diverted while it
    /// is, which is the more dangerous of the two wrong answers.
    #[test]
    fn an_unrecordable_steering_ledger_degrades_rather_than_failing() {
        struct Refusing;
        impl IdentityStore for Refusing {
            fn process_changed(&mut self, _: Option<ProcessIdentity>) -> Result<(), String> {
                Ok(())
            }
            fn interfaces_attached(&mut self, _: &[(String, u32)]) -> Result<(), String> {
                Ok(())
            }
            fn steering_changed(&mut self, _: &[(String, u32)]) -> Result<(), String> {
                Err("state dir is read-only".into())
            }
        }

        let steering = LedgerSteering {
            next: Some((vec![("eth4".into(), 1024)], true)),
            ..Default::default()
        };
        let rt = Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(steering),
            Box::new(Refusing),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        let (_, mut fx) = rt.views();
        fx.steer()
            .expect("the steer itself succeeded and must say so");
        assert!(
            rt.status().store_error.is_some(),
            "but the operator has to learn the record is stale — the next start cannot adopt"
        );
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

    /// `release_resources` refuses rather than no-ops: reporting resources
    /// freed that something else still holds is the requested-vs-observed
    /// bug in its purest form.
    ///
    /// This runtime is built with [`NoResources`], so the refusal comes from
    /// the seam having nothing to release — not from the attach wiring being
    /// absent, which it no longer is. (The earlier wording said "unbuilt".
    /// A comment whose truth expires is how `detach --all` came to promise a
    /// recovery path it did not have.)
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
            fn steering_changed(&mut self, _: &[(String, u32)]) -> Result<(), String> {
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
            fn steering_changed(&mut self, _: &[(String, u32)]) -> Result<(), String> {
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

    /// A steer into a mirror that is still loading is refused.
    ///
    /// The gate sits in `steer()` rather than at either caller, and this
    /// is why: the operator's `reconfigure` is the obvious path, but the
    /// supervisor also re-steers automatically once a replacement
    /// verifies — and after a daemon restart the fast-path's mirror is
    /// rebuilding from bird, so that automatic path can divert traffic
    /// into a table missing most of its prefixes. One check, both paths.
    #[test]
    fn a_steer_into_a_loading_mirror_is_refused() {
        use packetframe_common::fib::{CompletenessReport, TableCompleteness};

        let steering = LedgerSteering {
            next: Some((vec![("eth4".into(), 1024)], true)),
            ..Default::default()
        };
        let rt = Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(steering),
            Box::new(NullStore),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        let handle = std::sync::Arc::new(TableCompleteness::new());
        rt.require_table_complete(handle.clone());

        let (_, mut fx) = rt.views();
        // Nothing published yet: unknown is not permission.
        let e = fx.steer().expect_err("must refuse without a verdict");
        assert!(e.contains("refusing to steer"), "{e}");
        assert!(
            e.contains("require-table-complete off"),
            "the message must name the way out, or an operator with no bird is stuck: {e}"
        );

        // Still loading.
        handle.publish(CompletenessReport {
            authority_routes: 1_000_000,
            mirror_routes: 300_000,
            at: std::time::Instant::now(),
        });
        let e = fx.steer().expect_err("must refuse a partial mirror");
        assert!(e.contains("300000") && e.contains("1000000"), "{e}");

        // And NOTHING was installed on either refusal — the refusal is
        // before the NIC, so a later retry starts clean.
        assert!(
            rt.core.borrow().steering.installed().is_empty(),
            "a refused steer must not have touched the NIC"
        );

        // Converged: the same call now goes through.
        handle.publish(CompletenessReport {
            authority_routes: 1_000_000,
            mirror_routes: 999_000,
            at: std::time::Instant::now(),
        });
        fx.steer().expect("a converged mirror permits steering");
        assert_eq!(rt.core.borrow().steering.installed().len(), 1);
    }

    /// Without the handle the gate does not exist at all.
    ///
    /// `require-table-complete off` is a deployment with no authority to
    /// compare against — the shadow has no bird of its own. That is a
    /// config decision, not an inference: `bring_up` refuses `on` with
    /// nothing publishing, so this state is only ever reached
    /// deliberately.
    #[test]
    fn an_unset_gate_does_not_block_steering() {
        let steering = LedgerSteering {
            next: Some((vec![("eth4".into(), 1024)], true)),
            ..Default::default()
        };
        let rt = Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(steering),
            Box::new(NullStore),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        let (_, mut fx) = rt.views();
        fx.steer().expect("no gate configured, no gate applied");
    }
}
