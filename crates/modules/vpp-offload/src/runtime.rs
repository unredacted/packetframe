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

/// What one pass of the steering audit established.
///
/// Two facts rather than one, because they are independent: a pass can
/// prove drift AND fail to read some of what it was asked about.
/// Returning only the first published a partial answer as a complete
/// one — the caller cleared its "cannot verify" state on any `Ok` — so
/// health reported the confirmed count as current while more drift
/// could have been sitting behind an unreadable location (review
/// finding, the third instance of this shape in this audit).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SteeringAudit {
    /// Rules the current target needs in the NIC that are not there.
    pub missing: Vec<(String, u32)>,
    /// Rules the ledger still names on a port the current target does
    /// **not** steer, confirmed still occupying their slot.
    ///
    /// The opposite complaint to `missing`, and the more urgent one: an
    /// operator asked for a port to stop diverting and it has not. The
    /// two are separate counts because they point opposite ways — one
    /// says install, the other says remove — and a single number would
    /// have to pick one story to tell.
    pub stray: Vec<(String, u32)>,
    /// Why the pass was incomplete, if it was. The locations behind it
    /// were neither confirmed present nor confirmed missing, so
    /// `missing` is a floor rather than a count.
    pub unreadable: Option<String>,
}

impl SteeringAudit {
    /// Everything the target asks for is present and correct, and the
    /// whole of it was read.
    pub fn clean() -> Self {
        Self::default()
    }
}

/// Which side of the tier boundary a successful reconcile left the
/// traffic on.
///
/// Two answers rather than a bare `Ok(())`, because a reconcile against
/// an EMPTY target succeeds by removing everything, and "it worked" is
/// the same word for both outcomes while the consequences are
/// opposites. The executor turns this into the supervisor's
/// acknowledgement, and the supervisor releases VFs and paints health
/// on that acknowledgement — so collapsing the two reported an offload
/// carrying traffic it had just stopped carrying.
///
/// The alternative — `Err` for the empty target, which is what shipped
/// — is what wedged the rollback: a `steer off` whose `unsteer` the NIC
/// refused leaves rules installed and `steered` true, every later
/// convergence re-emits `Action::Steer`, and a `steer` that refuses
/// before reaching its stale-rule removal can never clear them. The
/// module retried a no-op error forever while the rules kept diverting
/// traffic the operator had asked it to stop diverting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SteerOutcome {
    /// Rules are confirmed in the NIC; allowlisted traffic is diverted.
    Steered,
    /// The target asks for no port, and the NIC now holds nothing —
    /// including anything a previous target left behind. Traffic is on
    /// the eBPF tier, and nothing is wanted.
    NothingToSteer,
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
    /// Reconcile the NIC to the current target. `Ok` means the NIC now
    /// holds exactly what the target asks for — which, for a target
    /// that asks for nothing, means it holds nothing.
    fn steer(&mut self) -> Result<SteerOutcome, String>;
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
    /// Rules the NIC should be holding for the current target and is
    /// not — both directions: ones the ledger names that are gone or
    /// altered, and ones the target asks for that were never installed
    /// (a restart after the allowlist grew inherits only the old set).
    ///
    /// DETECTION ONLY — it must not repair, and it must not touch the
    /// ledger. A rule can leave the NIC without us: a UniFi
    /// provisioning push, a firmware event, an operator with `ethtool
    /// -N`. Nothing re-emits `Action::Steer` in steady state (only
    /// `VerifyPassed` does, and verify does not recur), so the offload
    /// goes silently partial with health green — measured on the shadow
    /// 2026-08-11, still missing two minutes later with no log line.
    ///
    /// Kept observational on purpose. The traffic is not lost — it falls
    /// back to the eBPF tier, which is where it belongs — so the cost of
    /// a wrong answer here is a misleading health line, not a forwarding
    /// decision. Repair stays the operator's `packetframe reconfigure`,
    /// which reinstalls what is missing because `steer` is a reconcile.
    ///
    /// `Err` means the pass established **nothing** — no count to adopt,
    /// so the caller keeps its previous one. A pass that established
    /// something while failing to read the rest is `Ok` with
    /// [`SteeringAudit::unreadable`] set.
    fn missing_from_nic(&self) -> Result<SteeringAudit, String>;

    fn installed(&self) -> Vec<(String, u32)>;
    /// Change what steering *should* be, without touching the NIC.
    ///
    /// Deliberately infallible and side-effect-free: it records intent,
    /// and the next `steer`/`unsteer` is what makes the hardware agree.
    /// Splitting it that way keeps one routine — `steer` — responsible
    /// for every rule that ever reaches the NIC, so a reconfigure cannot
    /// grow its own, subtly different, installation path.
    fn retarget(&mut self, ports: Vec<(String, u32)>, plan: crate::steer::RuleSet);
    /// How many ports the CONFIG asks to steer, whether or not any rule
    /// is installed.
    ///
    /// Distinct from everything else here, which reports what the NIC
    /// holds. The supervisor deliberately never steers a first attach on
    /// its own — `steer on` in the file is the designed staging state
    /// until an operator moves the lever — so without this the health
    /// surface cannot tell "configured off" from "configured on and
    /// waiting", and reports the identical line for both. An operator
    /// who wrote `steer on`, restarted, and read `steer off (staging
    /// state)` has no way to know the config was seen.
    fn configured_ports(&self) -> usize;
}

/// A steering seam that refuses both directions. **Tests only.**
///
/// `bring_up` constructs a [`crate::ntuple::NtupleSteering`]
/// unconditionally — a config with every port `steer off` gets one with
/// an empty port list, not this — so nothing in production reaches it.
/// It is kept because it encodes the rule every stand-in must follow,
/// and a test double that got this wrong would prove the opposite of
/// what it claims: `steer` refusing is obvious, but `unsteer` refusing
/// is the half that matters. `Ok` from unsteer becomes
/// `Event::Unsteered`, which clears `steered` and unblocks
/// `ReleaseResources` — so faking success releases a VF that MCAM rules
/// from a previous run might still be pointing traffic at. Refusing
/// keeps `steered` true and the VF withheld, which is the designed
/// behaviour for "rules exist that we cannot manage".
#[derive(Debug, Default)]
pub struct SteeringUnavailable;

impl Steering for SteeringUnavailable {
    fn configured_ports(&self) -> usize {
        0
    }

    fn steer(&mut self) -> Result<SteerOutcome, String> {
        Err("MCAM steering is unavailable in this runtime; port stays unsteered".into())
    }
    fn unsteer(&mut self) -> Result<(), String> {
        Err("MCAM steering is unavailable in this runtime; cannot confirm rules removed".into())
    }
    fn missing_from_nic(&self) -> Result<SteeringAudit, String> {
        Ok(SteeringAudit::clean())
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
    /// The feed session-liveness handle: whether the BGP/BMP session
    /// that fills the mirror is up RIGHT NOW, written by the session
    /// owner in the fast-path controller. `None` when the wiring has no
    /// second tier or a harness never set one; the small-table release
    /// is then simply off.
    feed_session: Option<std::sync::Arc<packetframe_common::fib::FeedSession>>,
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
    /// `Some` while an adopted reconciliation is deferred, holding the
    /// release gate's state. Set by `start_resync` on every adoption
    /// that has anything to protect; cleared by `drain_batch` when the
    /// gate opens and the work actually begins. While set, the adopted
    /// VPP is left exactly as found — routes intact, and on the steered
    /// stage even its FIB unread — because a diff against a loading
    /// source is ~all withdrawals (drill (d), 2026-08-07), and the dump
    /// itself freezes VPP's workers (drill (d10), 2026-08-09). See
    /// [`DeferredResync`] for the two stages.
    deferred_resync: Option<DeferredResync>,
    /// When the NIC was last audited against the steering ledger, and
    /// how many rules it was missing. See [`STEER_AUDIT_EVERY`].
    last_steer_audit: Option<std::time::Instant>,
    steer_missing: usize,
    /// Rules still steering a port the config asks to leave unsteered,
    /// as of the last audit. Its own count because it points the other
    /// way: `steer_missing` says install, this says remove.
    steer_stray: usize,
    /// Why the last audit could not read the NIC, if it could not.
    ///
    /// Kept apart from `steer_missing` because they answer different
    /// questions: that one is "how many are gone", this one is "the
    /// answer is not known". Collapsing them let a NIC that stopped
    /// answering keep publishing the last clean count, so steering read
    /// Healthy while drift had become undetectable (review finding).
    steer_audit_error: Option<String>,
}

/// The loaded-and-quiet release gate, shared by both deferral stages.
/// See [`ADOPTED_SOURCE_FLOOR_DIVISOR`] for why the floor and the
/// quiescence are BOTH load-bearing.
#[derive(Debug, Clone, Copy)]
struct SourceGate {
    /// Minimum source size before quiescence even counts.
    floor: u64,
    /// The source's change counter at the previous check, for the
    /// activity rate. The COUNTER, not the table size: net size hides
    /// balanced churn and reads a shrinking source as quiet.
    last_seq: u64,
    /// The session pulse counter at the previous check. Tracked
    /// SEPARATELY from `last_seq` so the activity rate is the MAX of
    /// the two deltas, never their sum: a changed route bumps both
    /// counters (the tee mutates the mirror AND its element pulses),
    /// and summing recorded two units per route — steady churn at
    /// half the quiet threshold read as at-threshold and held the
    /// gate forever (review finding). Max counts a changed element
    /// once, and still catches what each counter alone misses:
    /// reannouncements pulse without mutating, local-state churn
    /// mutates without pulsing.
    last_pulses: u64,
    /// When the counters were observed. `None` until the first check —
    /// a rate needs two observations.
    last_check: Option<std::time::Instant>,
    /// Since when the source has stayed below the quiet rate, or `None`
    /// while it is loading. Release requires this to have lasted
    /// [`SOURCE_QUIET_FOR`].
    quiet_since: Option<std::time::Instant>,
    /// Since when the RATE alone has been quiet, floor ignored. The
    /// pre-dump stage's alternate releases need quiet that the floor
    /// cannot veto — they exist precisely for tables the floor is
    /// wrong about.
    rate_quiet_since: Option<std::time::Instant>,
}

/// One tick's reading of the source, taken by the caller and handed to
/// [`SourceGate::observe`] whole — the gate consumes a consistent
/// snapshot, and the observe signature stays within reason.
#[derive(Debug, Clone, Copy)]
struct SourceSample {
    have: u64,
    seq: u64,
    pulses: u64,
    live: bool,
}

/// What one gate observation saw. `released` is the coupled
/// floor-plus-quiescence verdict both stages share; the other fields
/// serve the pre-dump stage's alternate releases, which must work
/// exactly where the floor does not.
#[derive(Debug, Clone, Copy)]
struct GateView {
    released: bool,
    /// How long the rate alone has been quiet, floor ignored.
    rate_quiet_for: Option<Duration>,
}

impl SourceGate {
    fn new(floor: u64, seq_baseline: u64) -> Self {
        Self {
            floor,
            last_seq: seq_baseline,
            last_pulses: 0,
            last_check: None,
            quiet_since: None,
            rate_quiet_since: None,
        }
    }

    /// One paced observation; `true` once loaded-and-quiet has held for
    /// [`SOURCE_QUIET_FOR`]. Both gates, in order: below the floor
    /// nothing else matters, and above it only quiet SUSTAINED FOR A
    /// DURATION counts — a loading feed passes through the floor by
    /// construction (the floor-only version withdrew half a live table,
    /// 2026-08-08), and "quiet" is a rate over elapsed time, never a
    /// per-call delta: the production loop caps its sleeps at 50 ms, so
    /// a per-call threshold shrinks with cadence until a full-speed
    /// reload classifies as quiet.
    /// `live` conditions BOTH quiet trackers: quiet accumulated while
    /// the feed was down is not evidence of anything — a dead session
    /// is perfectly quiet — and without the reset, the first OPEN or
    /// BMP frame after an outage would release instantly on stale
    /// quiet, before the fresh session had streamed a single route
    /// (review finding). Rebaselining continuously while down also
    /// covers the up-transition: the clock starts from the moment
    /// liveness returns.
    /// Forget every piece of quiet evidence and restart the rate
    /// baseline at `seq_now`. Called when a validation OUTSIDE the
    /// gate rejects what the gate released — the post-dump churn
    /// check — because reinserting an unchanged gate let the very
    /// next tick average the rejected burst below the rate, keep the
    /// pre-dump `quiet_since`, and re-release immediately: the
    /// rejection undone one tick later (review finding). After this,
    /// the source must establish a fresh sustained quiet interval.
    fn rebaseline(&mut self, seq_now: u64, pulses_now: u64) {
        self.last_seq = seq_now;
        self.last_pulses = pulses_now;
        self.last_check = None;
        self.quiet_since = None;
        self.rate_quiet_since = None;
    }

    /// `quiet_rate` is supplied per observation, not stored, because
    /// the honest basis DIFFERS by stage and time: the diff stage
    /// scales it to the dumped table it protects, while the pre-dump
    /// stage must scale it to the mirror AS OBSERVED — a
    /// capacity-scaled rate let a 16M sizing call a steady 10k/s
    /// reload quiet and release mid-load at the floor (review
    /// finding). A rate frozen at construction cannot track a mirror
    /// that is still growing.
    fn observe(
        &mut self,
        now: std::time::Instant,
        sample: SourceSample,
        quiet_rate: u64,
        quiet_for: Duration,
    ) -> GateView {
        let SourceSample {
            have,
            seq,
            pulses,
            live,
        } = sample;
        let activity_per_sec = match self.last_check {
            // A rate needs two observations; the first check only
            // baselines, and reports as loading — which a source
            // this young almost certainly is.
            None => u64::MAX,
            Some(prev) => {
                let ms = now.duration_since(prev).as_millis().max(1) as u64;
                let mirror_delta = seq.saturating_sub(self.last_seq);
                let pulse_delta = pulses.saturating_sub(self.last_pulses);
                // ROUNDED UP, so activity can never divide away. Ticks
                // are not pinned to one second, and truncating integer
                // division turned one pulse over two seconds into a
                // rate of ZERO — which the unattested posture, whose
                // quiet_rate IS zero to demand literal silence, then
                // accepted as quiet and let the five-second clock run
                // through actual stream activity (review finding).
                // Overstating by at most 1/s is free against every
                // mirror-scaled rate and is the safe direction anyway.
                mirror_delta
                    .max(pulse_delta)
                    .saturating_mul(1_000)
                    .div_ceil(ms)
            }
        };
        let rate_quiet = live && activity_per_sec <= quiet_rate;
        if !rate_quiet {
            self.rate_quiet_since = None;
        } else if self.rate_quiet_since.is_none() {
            self.rate_quiet_since = Some(now);
        }
        let still_loading = have < self.floor || !rate_quiet;
        if still_loading {
            self.quiet_since = None;
        } else if self.quiet_since.is_none() {
            self.quiet_since = Some(now);
        }
        let released = self
            .quiet_since
            .is_some_and(|since| now.duration_since(since) >= quiet_for);
        self.last_seq = seq;
        self.last_pulses = pulses;
        self.last_check = Some(now);
        GateView {
            released,
            rate_quiet_for: self.rate_quiet_since.map(|s| now.duration_since(s)),
        }
    }
}

/// Which direction the deferral last asked the supervisor to move
/// steering. See `DeferredResync::AwaitingFallback::last_request`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SteerRequest {
    Settle,
    Revoke,
}

/// What a deferred adopted reconciliation is waiting for.
#[derive(Debug, Clone, Copy)]
enum DeferredResync {
    /// A STEERED adoption: even the FIB DUMP is deferred. VPP processes
    /// `ip_route_dump` with every worker parked in barrier sync — the
    /// message is not mp-safe (`ip_api.c` marks `ip_route_add_del`
    /// thread-safe but not the dump), so at the reference table the
    /// dump is ~5.4 s of the NIC dropping frames no VPP counter sees
    /// (drill (d10), shadow 2026-08-09; invariant across six prior runs
    /// because every one of them ran this dump at attach). It may only
    /// run against a VPP carrying no traffic. Once the source is loaded
    /// and quiet — which means the eBPF tier is equally loaded, both
    /// consuming the same mirror commits — the runtime asks the
    /// supervisor to unsteer ([`Event::FallbackSettled`]) and dumps
    /// only after the NIC ledger confirms the rules are gone.
    /// `steer_wanted` survives the unsteer, so `VerifyPassed` re-steers
    /// on the existing verified path.
    AwaitingFallback {
        gate: SourceGate,
        /// The last steering request and when it was made, so a
        /// refused or unacknowledged transition is re-asked every
        /// [`UNSTEER_REQUEST_EVERY`] instead of on each 50 ms tick.
        /// The KIND is part of the record because opposite transitions
        /// must not share a throttle: a revocation arriving just after
        /// an acknowledged unsteer is the safety path, and waiting out
        /// the unsteer's pace window left traffic on a collapsing
        /// fallback for up to five seconds (review finding).
        last_request: Option<(SteerRequest, std::time::Instant)>,
        /// True from the moment this deferral's unsteer is observed
        /// complete until the gate re-releases: the revocation path
        /// keeps re-asking on THIS flag, never on the ledger being
        /// empty — a partial restore leaves rules in the ledger, and
        /// gating on emptiness is what wedged half the allowlist on
        /// the condemned fallback with no retry (review finding).
        restoring: bool,
        /// The feed session's epoch count at the FIRST live
        /// observation of this deferral — `None` until the session has
        /// been seen up. A later epoch advance means the session went
        /// down and up again underneath us: the world may have been
        /// reloaded, a cached authority report cannot attest that
        /// routes belong to the current stream (review finding), and
        /// the deferral adopts the full unattested posture until it
        /// releases. Baselined at first-up rather than at creation
        /// because the deferral is normally created BEFORE the feed
        /// connects — counting the initial raise as a flap demoted
        /// every ordinary release (caught by the completeness test
        /// before it shipped).
        epoch: Option<u64>,
        /// True while this deferral's attestation is demoted by a
        /// session flap it has observed.
        ///
        /// The demotion has to be revocable or it is a wedge, not a
        /// safeguard. What a flap invalidates is the AUTHORITY'S WORD,
        /// because a report from before the reconnect cannot attest
        /// that routes belong to the current stream — and the integrity
        /// checker publishes a new one every few minutes, which can.
        /// Latching `flapped` forever meant a single ordinary session
        /// bounce (bird restart, hold-timer expiry) permanently
        /// disabled the completeness door: a below-floor authoritative
        /// deployment could then never release at all, and an
        /// above-floor churning one fell to the zero-rate posture it
        /// never satisfies (review finding). So the demotion lasts
        /// exactly until a report timestamped after this moment
        /// arrives, at which point the epoch re-baselines and the
        /// attested path returns. A report that is merely NEWER is
        /// enough: its own drift check is what judges whether the
        /// current stream has actually converged.
        demoted: bool,
    },
    /// An UNSTEERED adoption whose dump has already run — harmlessly,
    /// because with no rules installed nothing is on VPP for the
    /// barrier to stall. The DIFF is deferred until the source is
    /// loaded and quiet, exactly the original gate: a diff against a
    /// loading source is ~all withdrawals.
    AwaitingDiff { adopted: u64, gate: SourceGate },
}

impl DeferredResync {
    fn floor(&self) -> u64 {
        match self {
            DeferredResync::AwaitingFallback { gate, .. } => gate.floor,
            DeferredResync::AwaitingDiff { gate, .. } => gate.floor,
        }
    }
}

/// Floor for the pre-dump stage, as a fraction of the ledger's route
/// capacity. Before the dump the adopted table's size is unknowable —
/// reading it is exactly what is being deferred — so the floor that
/// keeps a dead or trickling source from triggering an unsteer needs
/// another basis, and capacity is the one available: it derives from
/// the operator's `expected-routes`, so it scales with the deployment
/// instead of encoding this fleet's table.
///
/// Capacity is an UPPER sizing bound, so this floor doubles as a
/// CONTRACT: with `require-table-complete off` there is no authority
/// to say a small table is complete, and the release gate refuses to
/// guess — a deployment whose real table sits below `capacity / 16`
/// defers its adopted reconciliation indefinitely, visibly, with the
/// remedy in the health text (size `expected-routes` within 16x of
/// the real table, or add bird and enable the authority). A
/// session-backed small-table heuristic existed briefly and was
/// removed deliberately: ten of PR #151's twenty review rounds were
/// spent on its corner cases, every one serving a configuration the
/// fleet does not run, and its liveness settling wedged the FLEET
/// path within hours of merging (#152). Supported configurations
/// release in seconds through the floor or the authority; everything
/// else is refused by arithmetic rather than guarded by heuristics.
pub const FALLBACK_FLOOR_DIVISOR: u64 = 16;

/// How often a refused or unacknowledged unsteer is re-requested while
/// the pre-dump stage waits. Paced because the gate re-checks every
/// driver tick: asking on each one would emit an action per 50 ms at a
/// NIC that just refused the last one.
const UNSTEER_REQUEST_EVERY: Duration = Duration::from_secs(5);

/// The adopted diff runs only when the source holds at least
/// `adopted / ADOPTED_SOURCE_FLOOR_DIVISOR` routes **and** has been
/// quiet for [`SOURCE_QUIET_TICKS`] checks. Both conditions, because
/// each covers the other's blind spot:
///
/// - **Quiescence alone** releases against a DEAD feed — a source that
///   never loaded anything is perfectly quiet, and the diff would
///   withdraw the entire adopted table, which is the original disaster.
///   The floor holds that case deferred forever, health degraded:
///   stale-but-verified forwarding plus an alarm beats withdrawing a
///   live table.
/// - **The floor alone** releases MID-LOAD, because a loading feed
///   passes through every fraction on its way to full — by
///   construction, not by bad luck. The first version used only the
///   floor and hardware billed it precisely (shadow, 2026-08-08): the
///   diff ran at have=527,557 of an eventual 1.05M, withdrew the
///   not-yet-reloaded half from the live steered VPP, and the drill
///   flow measured 12.75 s of blackhole. A count threshold cannot
///   distinguish "loading, at 60%" from "loaded, shrunk to 60%"; only
///   the growth rate can.
pub const ADOPTED_SOURCE_FLOOR_DIVISOR: u64 = 2;

/// The activity rate an UNATTESTED release tolerates: ZERO. Any
/// allowance re-opens the same hole at a slower speed — the
/// mirror-scaled rate admitted a 200/s reconnect trickle, and the
/// 64/s noise floor that replaced it admitted a 64/s one, which can
/// run indefinitely while its sub-5s frame cadence also holds off
/// InitiationComplete and the GC forever (review findings, in that
/// order). Without an authority there is no way to distinguish slow
/// churn from a throttled reload, so the gate does not try: an
/// unattested release requires the stream and the mirror to be
/// LITERALLY still for the whole window. Real feeds have such
/// windows between churn bursts; a feed busy enough not to simply
/// keeps the deferral — visible, remedied, and correct. Attested
/// releases keep the mirror-scaled rate: their authority carries
/// completion truth and vetoes partial tables on current-mirror
/// drift regardless of quiet.
pub const UNATTESTED_QUIET_RATE_PER_SEC: u64 = 0;

/// The quiet a release must show when NO completeness authority is
/// configured. Five seconds, deliberately equal to both listeners'
/// INIT_COMPLETE_QUIESCENCE: that is each protocol's own definition of
/// "the initial dump is complete", and a release that has no authority
/// to attest completion must not claim it on LESS evidence than the
/// protocol itself requires — two seconds of stall mid-dump released a
/// partial mirror whose only sin was pausing (review finding). With an
/// authority present the shorter window stands, because the authority
/// carries the completion truth and its current-mirror drift vetoes a
/// partial table regardless of quiet.
pub const UNATTESTED_QUIET_FOR: Duration = Duration::from_secs(5);

/// How long the source must stay below the quiet RATE before it counts
/// as loaded. A duration, never a number of checks: the production loop
/// caps its sleeps at 50 ms for stop-responsiveness, so check cadence is
/// an implementation detail that varies by two orders of magnitude
/// between the service loop and the tests — a per-check threshold
/// shrinks per-call growth with cadence until a full-speed reload
/// classifies as quiet (review finding; at 50 ms checks an 18k routes/s
/// reload adds ~900 per check). This costs every populated adoption
/// ~2 s of deliberate patience. The residual risk is a feed that stalls
/// mid-load for the whole window; the feed is one hop away on this
/// fleet, making a 2 s silent stall the rare case, and its cost is
/// bounded by the same deltas that finish the load.
pub const SOURCE_QUIET_FOR: Duration = Duration::from_secs(2);

/// Activity rate (mutations per second) below which the source is
/// "quiet": 1/1024th of the adopted table per second, floored at 64/s
/// so tiny fixtures release promptly. Measured on the CHANGE COUNTER,
/// not on table growth — balanced churn and active shrink are zero
/// growth and are anything but quiet (review finding). Steady-state
/// BGP churn on the reference fleet is tens of mutations per second; a
/// reload is ~18k/s — orders of magnitude on either side, so the exact
/// divisor is not delicate.
fn source_quiet_rate_per_sec(adopted: u64) -> u64 {
    (adopted / 1024).max(64)
}

/// The authority's CURRENT word, or `None` when no authority is
/// configured: the cached verdict must still permit steering AND the
/// report must still describe the mirror as it is now (its authority
/// count against `mirror_now`, under the same drift bound the verdict
/// itself enforces). One function because it has two callers — the
/// release computation and the post-dump revalidation — and the review
/// caught them drifting apart twice: first the /2 bound diverging from
/// the policy, then the veto trusting the cached verdict while only
/// the `complete` release recomputed (a stale Converged carried a
/// since-shrunken mirror through the floor path for the length of the
/// dump).
fn authority_current(
    completeness: &Option<std::sync::Arc<packetframe_common::fib::TableCompleteness>>,
    mirror_now: u64,
) -> Option<bool> {
    completeness.as_ref().map(|h| {
        h.verdict().permits_steering()
            && h.latest().is_some_and(|r| {
                let now_r = packetframe_common::fib::CompletenessReport {
                    mirror_routes: mirror_now,
                    ..r
                };
                now_r
                    .drift()
                    .is_some_and(|d| d <= packetframe_common::fib::STEER_MAX_DRIFT)
            })
    })
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
                feed_session: None,
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
                deferred_resync: None,
                last_steer_audit: None,
                steer_missing: 0,
                steer_stray: 0,
                steer_audit_error: None,
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

    /// Attach the feed session-liveness handle. The small-table
    /// release consults it, because no mirror-side count can
    /// distinguish a loaded small table from the husk a dead session
    /// leaves behind.
    pub fn feed_session(&self, handle: std::sync::Arc<packetframe_common::fib::FeedSession>) {
        self.core.borrow_mut().feed_session = Some(handle);
    }

    /// Point steering at a new set of ports and rules.
    ///
    /// Records intent only — see [`Steering::retarget`]. The caller must
    /// follow it with the supervisor event that reconciles the NIC, and
    /// the supervision loop is the only caller precisely so that the two
    /// cannot be separated.
    pub fn retarget(&self, ports: Vec<(String, u32)>, plan: crate::steer::RuleSet) {
        self.core.borrow_mut().retarget(ports, plan);
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
        // Ask the NIC whether it still holds what the ledger claims,
        // at most once per STEER_AUDIT_EVERY. Rate-limited on the REAL
        // clock rather than the driven one: this is a hardware poll,
        // not a supervision deadline, and pacing it off a clock a test
        // can fast-forward would turn every driven tick into an ioctl.
        //
        // Detection only. Nothing here re-asserts, and the ledger is
        // never touched — a wrong answer costs a health line, not a
        // forwarding decision. Repair is the operator's `reconfigure`.
        {
            let mut c = self.core.borrow_mut();
            let now = std::time::Instant::now();
            // An EMPTY ledger claims nothing, so nothing can be
            // missing from it. Clearing here rather than skipping is
            // the fix for the obvious version of this: guarding the
            // whole audit on a non-empty ledger meant an unsteer after
            // a drift reading froze `steer_missing` at its last value
            // and blocked every future audit, so status reported
            // missing rules forever on a port that was deliberately
            // off (review finding).
            if c.steering.installed().is_empty() {
                c.steer_missing = 0;
                c.steer_stray = 0;
                c.steer_audit_error = None;
                c.last_steer_audit = None;
            }
            let due = c
                .last_steer_audit
                .is_none_or(|t| now.duration_since(t) >= STEER_AUDIT_EVERY);
            if due && !c.steering.installed().is_empty() {
                c.last_steer_audit = Some(now);
                match c.steering.missing_from_nic() {
                    Ok(audit) => {
                        if !audit.missing.is_empty() && c.steer_missing != audit.missing.len() {
                            tracing::warn!(
                                missing = ?audit.missing,
                                "steering rules this target needs are not in the NIC; \
                                 traffic for them is on the eBPF tier. `packetframe \
                                 reconfigure` reinstalls them"
                            );
                        }
                        c.steer_missing = audit.missing.len();
                        if !audit.stray.is_empty() && c.steer_stray != audit.stray.len() {
                            tracing::warn!(
                                stray = ?audit.stray,
                                "rules are still steering a port this config asks to leave \
                                 unsteered; `packetframe reconfigure` removes them"
                            );
                        }
                        c.steer_stray = audit.stray.len();
                        // Taken from the audit rather than cleared: a
                        // pass that proved drift AND could not read the
                        // rest is an incomplete answer, and clearing
                        // here published it as a complete one (review
                        // finding). `None` is the only thing that says
                        // the whole target was checked.
                        if let Some(why) = &audit.unreadable {
                            tracing::warn!(
                                error = %why,
                                confirmed = audit.missing.len(),
                                "steering audit was incomplete; the count is a floor"
                            );
                        }
                        c.steer_audit_error = audit.unreadable;
                    }
                    // A NIC we cannot read is not a NIC we can call
                    // wrong — the last count stands. But it is not a
                    // NIC we can call RIGHT either, and publishing the
                    // stale count alone let a persistently unreadable
                    // NIC keep reporting the last clean answer forever
                    // (review finding). Record the failure so health
                    // can say the answer is unknown.
                    Err(e) => {
                        tracing::warn!(error = %e, "steering audit could not read the NIC");
                        c.steer_audit_error = Some(e);
                    }
                }
            }
        }
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
            steer_configured_ports: c.steering.configured_ports(),
            resync_deferred: c
                .deferred_resync
                .map(|d| (c.source.route_count(), d.floor())),
            steer_missing: c.steer_missing,
            steer_stray: c.steer_stray,
            steer_audit_error: c.steer_audit_error.clone(),
            authority: if c.completeness.is_none() {
                AuthorityPosture::Absent
            } else if matches!(
                &c.deferred_resync,
                Some(DeferredResync::AwaitingFallback { demoted: true, .. })
            ) {
                AuthorityPosture::DemotedByFlap
            } else {
                AuthorityPosture::Attesting
            },
        }
    }
}

/// How often to ask the NIC whether it still holds the rules the ledger
/// names.
///
/// Two ioctls per steered interface per interval, so 30 s is free even
/// on a fully steered box. Sized against how long a silently-partial
/// offload should be allowed to go unnoticed rather than against any
/// hardware limit — on the shadow it went two minutes and would have
/// gone indefinitely.
const STEER_AUDIT_EVERY: Duration = Duration::from_secs(30);

/// What the completeness authority can currently say, for the health
/// text.
///
/// Three states rather than a bool plus a second bool, because the
/// interesting case is neither "configured" nor "absent": an authority
/// that exists but whose word this deferral may not use. Reported as
/// one field so the two cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityPosture {
    /// No `require-table-complete` handle; the proxies stand alone.
    Absent,
    /// Configured and usable.
    Attesting,
    /// Configured, but this deferral saw the feed flap and has not yet
    /// seen the current epoch reconciled, so the authority's word
    /// cannot be trusted to describe the current stream.
    DemotedByFlap,
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
    /// How many ports the config asks to steer. See
    /// [`Steering::configured_ports`].
    pub steer_configured_ports: usize,
    /// Changes the source is holding that the engine has not pulled yet.
    ///
    /// Distinct from `pending_ops`, which is what the engine has pulled
    /// and not yet sent. Both can be non-zero at once and they fail
    /// differently: a backlog here means the engine is not draining, a
    /// backlog there means VPP is not accepting.
    pub source_backlog: u64,
    /// `Some((have, want))` while an adopted resync is deferred for a
    /// still-loading route source. See `Core::deferred_resync`.
    pub resync_deferred: Option<(u64, u64)>,
    /// What the authority can say right now — the deferral health text
    /// depends on it: an attested deployment's below-floor wait
    /// resolves through the authority and telling it to "add bird"
    /// recommends the thing it already has, while a demoted one is
    /// waiting on something else entirely.
    pub authority: AuthorityPosture,
    /// How many rules the ledger names that the NIC no longer holds, as
    /// of the last audit. See [`STEER_AUDIT_EVERY`].
    pub steer_missing: usize,
    /// Rules still steering a port the config leaves unsteered. See
    /// [`SteeringAudit::stray`].
    pub steer_stray: usize,
    /// Why the last steering audit could not read the NIC, if so.
    pub steer_audit_error: Option<String>,
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
        // The ledger just moved, so the cached audit describes a NIC
        // that no longer exists. Invalidate rather than wait out the
        // interval: a successful re-steer would otherwise keep
        // reporting the drift it just repaired for up to
        // STEER_AUDIT_EVERY, which is exactly the window an operator
        // stepping a canary ladder is watching (review finding).
        self.last_steer_audit = None;
        let rules = self.steering.installed();
        let r = self.store.steering_changed(&rules);
        let _ = self.note_persist(r);
    }

    /// Point steering at a new target, and invalidate the cached audit.
    ///
    /// The audit answers "does the NIC hold what THIS target asks for",
    /// so it is a function of two things — the ledger and the target —
    /// and both have to invalidate it. Only the ledger did, and the
    /// target can move on its own: `retarget` runs before the
    /// reconciling steer, which can refuse at the completeness gate and
    /// return without ever reaching `record_steering`. The answer to
    /// the OLD question then stood for up to STEER_AUDIT_EVERY, and
    /// `reconfigure` republishes status the moment it returns — so an
    /// operator who had just been told the steer was refused could read
    /// `steering healthy` in the same breath (review finding).
    fn retarget(&mut self, ports: Vec<(String, u32)>, plan: crate::steer::RuleSet) {
        self.steering.retarget(ports, plan);
        self.last_steer_audit = None;
    }

    /// Whether a steer against the current target would divert traffic
    /// at all, as opposed to only removing rules.
    ///
    /// The discriminator both gates hang off, named once because both
    /// have to make the same exception and one of them is easy to
    /// forget. A target with no port installs nothing — it is a
    /// reconcile to empty, the shape `steer off` takes — so there is no
    /// traffic for either gate to protect, and refusing it blocks the
    /// one steer whose job is to take traffic OFF VPP.
    fn steer_diverts_traffic(&self) -> bool {
        self.steering.configured_ports() > 0
    }

    /// The completeness verdict a steer would be judged against, or
    /// `None` when nothing would judge it: no authority configured, or
    /// a target that diverts no traffic.
    ///
    /// One accessor because it has two readers that must not disagree:
    /// [`Effects::steer`], which refuses on it, and
    /// [`Observe::steer_permitted`], which decides whether re-attempting
    /// a refused steer is worth anything. A retry keyed to a different
    /// question than the refusal is either a loop that never stops
    /// asking or one that never asks again. The polarity is
    /// [`packetframe_common::fib::Completeness::permits_steering`]'s, on
    /// the type, so only the verdict travels.
    fn steer_verdict(&self) -> Option<packetframe_common::fib::Completeness> {
        self.completeness
            .as_ref()
            .filter(|_| self.steer_diverts_traffic())
            .map(|h| h.verdict())
    }

    /// Whether the source has handed over everything it holds.
    ///
    /// Not a gate the steer path applies — it is the thing neither gate
    /// can see. `Drain::Idle` is the ENGINE's pending map going empty,
    /// which is weaker than it looks: `drain_batch` pulls at most
    /// `DELTA_BATCH` and sends at most `DRAIN_BATCH`, and the two are
    /// the same number, so one tick can pull 4096, send all 4096, and
    /// report idle with the feed still holding the rest of a burst. A
    /// reload is hundreds of thousands.
    ///
    /// The ledger has not classified those changes, so nothing is
    /// `installing`; completeness compares bird against the MIRROR,
    /// which the tee already updated, so a burst of route UPDATES keeps
    /// the count identical and the verdict converged. Everything reads
    /// healthy while VPP is tens of thousands of changes behind, and
    /// steering there blackholes every prefix in the gap —
    /// `RouteSource::backlog`'s own doc calls it "an unexplained gap
    /// between what bird advertises and what VPP holds" (review
    /// finding, PR #160).
    ///
    /// **This is only a complete proof while an undelivered batch goes
    /// BACK to the source.** The backlog can only report work the source
    /// still holds, so anything that takes a batch out of the feed and
    /// then drops it is invisible here — and to the ledger, and to
    /// completeness. `Engine::apply_changes` did exactly that until
    /// #161: `drain_changes` is destructive, and a failed
    /// `send_neighbour` returned before the loop that queues the batch's
    /// routes, so those deltas existed nowhere and no count moved. The
    /// requeue is what makes this predicate cover them. Anything added
    /// later that drains the source and can fail must hand the batch
    /// back for the same reason, or this silently stops covering it.
    ///
    /// Carries the empty-target exception like the other two, and the
    /// history is the argument for keeping it that way: this predicate
    /// was added AFTER the exception was pushed down into each gate, on
    /// the reasoning that a later one could otherwise land on the wrong
    /// side of a shared early return. It did exactly that on the first
    /// attempt — a backlog held back a reconcile that only removes.
    fn source_current(&self) -> bool {
        !self.steer_diverts_traffic() || self.source.backlog() == 0
    }

    /// Whether the FIB itself is fit to take traffic.
    ///
    /// The second gate, and the one that is easy to forget: `steer` does
    /// not apply it — `apply_steering` and `Verdict::may_steer` do — so
    /// a retry that consulted completeness alone would walk straight
    /// past `VerifyIncomplete`. That arm reaches `Ready` with the want
    /// intact and emits no steer precisely because routes are withheld
    /// or unresolvable; re-attempting there would divert traffic into
    /// the FIB with known holes that the arm exists to protect.
    ///
    /// Carries the empty-target exception itself, next to the gate it
    /// exempts, exactly as `steer_verdict` does — rather than both
    /// sharing an early return in the caller, where a third gate added
    /// later can quietly land on the wrong side of it.
    ///
    /// Applied UNCONDITIONALLY otherwise, unlike `apply_steering`, which exempts
    /// an already-steering port. That exemption exists because
    /// `blocks_first_steer` counts `installing`, nonzero whenever routes
    /// are in flight and so routine under a live feed that gating an
    /// operator's reconcile on it would fail at random. The retry does
    /// not need it: it runs only on a tick whose drain reported
    /// `Drain::Idle`, which is that exemption's whole subject matter
    /// already excluded.
    ///
    /// An earlier version exempted a non-empty NIC ledger on the same
    /// reasoning, and that was wrong in a case the ledger cannot
    /// distinguish: a FIRST steer whose rollback could not delete leaves
    /// debris, so "some rules are installed" stops meaning "this port
    /// was steering happily". If the table then developed holes, the
    /// retry would install the REST of the allowlist into it and widen
    /// the blackhole the debris had started (review finding, PR #160).
    /// Nothing is lost by dropping it: a partly-installed target over a
    /// whole FIB still repairs, because that FIB does not block.
    fn fib_fit_to_steer(&self) -> bool {
        !self.steer_diverts_traffic() || !self.engine.counts().blocks_first_steer()
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

    fn steer_permitted(&mut self) -> bool {
        let c = self.core.borrow();
        // Both gates, through the same accessors the steer path and the
        // verify verdict use. Neither is re-derived here — including
        // their shared exception for a target that diverts nothing,
        // which each accessor carries itself: the retry is what drives
        // a `steer off`'s reconcile-to-empty from `Ready`, and asking a
        // stricter question here than the one `steer` answers is how a
        // retry ends up either refusing forever or asking forever.
        c.source_current()
            && c.steer_verdict().is_none_or(|v| v.permits_steering())
            && c.fib_fit_to_steer()
    }

    fn drain_batch(&mut self, now: std::time::Instant) -> Result<crate::driver::Drain, String> {
        let mut c = self.core.borrow_mut();
        // A deferred adopted resync is re-checked here, on the driver's
        // paced cadence, because this is the only Observe call that runs
        // every tick of a resync state. While the source is below the
        // floor NOTHING touches the engine — no deltas either, since the
        // coming diff reads the full mirror and covers them, and
        // applying a partial feed's withdrawals early is the exact
        // hazard being deferred.
        if let Some(d) = c.deferred_resync {
            let have = c.source.route_count();
            // Two counters, tracked separately: the gate takes the MAX
            // of their deltas, never the sum — a changed route bumps
            // both (its element pulses AND the tee mutates the mirror),
            // and summing double-counted steady churn until half the
            // quiet threshold read as at-threshold (review finding).
            // Max still catches what each alone misses: reannouncement
            // dumps pulse without mutating, local-state churn mutates
            // without pulsing.
            let seq = c.source.change_seq();
            let pulses = c.feed_session.as_ref().map_or(0, |f| f.pulse_count());
            match d {
                DeferredResync::AwaitingFallback {
                    mut gate,
                    mut last_request,
                    mut restoring,
                    mut epoch,
                    mut demoted,
                } => {
                    // ONE observation for both — see `FeedLiveness`. Read
                    // separately, `live` could come from after a raise
                    // and the epoch from before its increment, and the
                    // next tick's higher epoch reads as a flap on what
                    // was an ordinary first raise (review finding).
                    let liveness = c.feed_session.as_ref().map(|f| f.liveness());
                    let live = liveness.is_some_and(|l| l.up);
                    // Rate scaled to the mirror as observed — never
                    // to capacity, which is a ceiling, not a table.
                    // The floor door's quiet requirement depends on
                    // whether anyone can attest completion: with no
                    // authority, quiet must at least match the
                    // protocol's own initiation-complete standard —
                    // see UNATTESTED_QUIET_FOR.
                    // The attested fast path holds only while the
                    // session has NOT flapped under this deferral: a
                    // reconnect reopens the stream epoch, and a cached
                    // report cannot attest that routes belong to the
                    // current one — so a flapped deferral takes the
                    // full unattested posture UNTIL A REPORT NEWER THAN
                    // THE GC HAS RUN (see `demoted`; latching it
                    // forever turned an ordinary session bounce into a
                    // deferral that could never release). The fleet's
                    // steady 40 s release never flaps and never pays
                    // this at all.
                    let current_epoch = liveness.map(|l| l.epoch);
                    if live && epoch.is_none() {
                        epoch = current_epoch;
                    }
                    if matches!((epoch, current_epoch), (Some(e), Some(c_)) if c_ != e) {
                        demoted = true;
                    }
                    // Only the GC lifts it. A completeness report
                    // published after the flap is NOT evidence the
                    // mirror is this session's: the checker compares
                    // counts, and a reannouncement still carrying the
                    // previous session's unseen routes keeps the count
                    // aligned — so a positive post-flap report can sit
                    // over a half-current mirror, and if the
                    // reannouncement trickles below the attested quiet
                    // rate the gate would release and diff against it
                    // (review finding, refuting the timestamp test that
                    // stood here). `InitiationComplete`'s GC is the one
                    // event that destroys prior-session state, and
                    // `reconciled` is stamped for the epoch it ran in.
                    if demoted && liveness.is_some_and(|l| l.reconciled) {
                        epoch = current_epoch;
                        demoted = false;
                    }
                    // Consequence, accepted deliberately: on a feed
                    // whose churn never yields the initiation-complete
                    // silence, a flap mid-deferral holds the deferral in
                    // the unattested posture indefinitely. That is the
                    // safe direction and a visible one — VPP keeps
                    // forwarding the FIB it was adopted with, health
                    // reports the deferral — and it is the same bargain
                    // FALLBACK_FLOOR_DIVISOR already makes: refuse
                    // visibly rather than release on evidence that does
                    // not mean what it appears to.
                    let flapped = demoted;
                    let attested = c.completeness.is_some() && !flapped;
                    let view = gate.observe(
                        now,
                        SourceSample {
                            have,
                            seq,
                            pulses,
                            live,
                        },
                        if attested {
                            source_quiet_rate_per_sec(have)
                        } else {
                            UNATTESTED_QUIET_RATE_PER_SEC
                        },
                        if attested {
                            SOURCE_QUIET_FOR
                        } else {
                            UNATTESTED_QUIET_FOR
                        },
                    );
                    let want = gate.floor;
                    // Three ways the fallback proves itself ready,
                    // because the floor alone cannot: capacity is an
                    // upper sizing bound, so a real table below
                    // capacity/16 would defer forever on it (review
                    // finding).
                    //  - the coupled floor+quiescence release, for
                    //    tables within 16x of their sizing (the fleet);
                    //  - the completeness authority, where a bird
                    //    exists — the exact signal, and the same one
                    //    `Effects::steer` gates on.
                    // TWO releases, deliberately not three: a
                    // below-floor table with no authority defers
                    // forever, visibly, because nothing honest can say
                    // it is complete — see FALLBACK_FLOOR_DIVISOR for
                    // the contract and for what happened to the
                    // heuristic that used to guess.
                    // The authority's CURRENT word gates every path:
                    // the cached verdict alone let a stale Converged
                    // carry a since-shrunken mirror through the floor
                    // release for the length of the dump (review
                    // finding). `authority_current` recomputes the
                    // report against the mirror as it is now; None
                    // means no authority is configured and the proxies
                    // stand on their own.
                    let authority = authority_current(&c.completeness, have);
                    let veto = authority == Some(false);
                    // `!flapped` here too: a positive authority word is
                    // epoch-blind — the report may predate the
                    // reconnect entirely, and stale prior-session
                    // routes keep its counts aligned (review finding:
                    // round twelve demoted only the floor door). A
                    // NEGATIVE word still vetoes regardless of epoch;
                    // caution does not expire.
                    let complete = live
                        && !flapped
                        && view.rate_quiet_for.is_some_and(|q| q >= SOURCE_QUIET_FOR)
                        && authority == Some(true);
                    let released = !veto && ((view.released && live) || complete);
                    let unsteered = c.steering.installed().is_empty();
                    if !released {
                        // Revocation AFTER the unsteer was acknowledged
                        // — the feed dropped in the window before the
                        // dump. The adopted FIB is still whole (nothing
                        // has touched it), so ask for the traffic back
                        // rather than leaving it idle over a fallback
                        // that may be losing routes (review finding).
                        // Paced like the unsteer request; a refused
                        // steer is re-asked the same way.
                        // `restoring` LATCHES on the first observation
                        // of this deferral's unsteer having landed, and
                        // the re-ask keys on the latch, never on the
                        // ledger being empty: a PARTIAL restore leaves
                        // rules in the ledger, and gating on emptiness
                        // wedged half the allowlist on the condemned
                        // fallback with no retry (review finding).
                        // RestoreSteer is a reconcile, so re-asking
                        // over an already-complete set is an idempotent
                        // re-assert.
                        if unsteered || restoring {
                            restoring = true;
                            // Same-kind pacing only: the first
                            // revocation after an acknowledged unsteer
                            // goes out immediately.
                            let ask = last_request.is_none_or(|(kind, t)| {
                                kind != SteerRequest::Revoke
                                    || now.duration_since(t) >= UNSTEER_REQUEST_EVERY
                            });
                            if ask {
                                c.pending.push(Event::FallbackRevoked);
                                last_request = Some((SteerRequest::Revoke, now));
                            }
                        }
                        c.deferred_resync = Some(DeferredResync::AwaitingFallback {
                            gate,
                            last_request,
                            restoring,
                            epoch,
                            demoted,
                        });
                        return Ok(crate::driver::Drain::AwaitingSource { have, want });
                    }
                    if !unsteered {
                        // A re-release after a revocation cycle starts
                        // the settle/unsteer sequence over.
                        restoring = false;
                        // The fallback can carry the traffic now; ask the
                        // supervisor to take it off VPP. Through the
                        // machine, never `steering.unsteer()` from here:
                        // the ledger persist and the `steered` fact live
                        // with the executor, and a second unsteer path is
                        // two owners for one NIC.
                        let ask = last_request.is_none_or(|(kind, t)| {
                            kind != SteerRequest::Settle
                                || now.duration_since(t) >= UNSTEER_REQUEST_EVERY
                        });
                        if ask {
                            c.pending.push(Event::FallbackSettled);
                            last_request = Some((SteerRequest::Settle, now));
                        }
                        c.deferred_resync = Some(DeferredResync::AwaitingFallback {
                            gate,
                            last_request,
                            restoring,
                            epoch,
                            demoted,
                        });
                        return Ok(crate::driver::Drain::AwaitingSource { have, want });
                    }
                    // Unsteered and quiet: the dump is free — nothing is
                    // on VPP for the barrier to stall.
                    {
                        let Core {
                            engine,
                            source,
                            feed_session,
                            completeness,
                            ..
                        } = &mut *c;
                        let adopted = engine.adopt_vpp_fib().map_err(|e| e.to_string())?;
                        // Revalidate on the FAR side of the dump: it
                        // blocks this thread for seconds, and the world
                        // it re-checks is the MIRROR, not just the
                        // transport — a live BGP soft reload withdraws
                        // and reannounces with the session up and a
                        // cached verdict still permitting, and a diff
                        // snapshotted in that trough queues withdrawals
                        // that destroy the intact FIB just read (review
                        // finding, twice: liveness alone was the first
                        // version's check). Three current facts must
                        // hold:
                        //  - the session is still up;
                        //  - the mirror moved during the dump at no
                        //    more than the gate's own quiet rate — any
                        //    faster and the quiet that released us is
                        //    retroactively false;
                        //  - a configured authority's report, recomputed
                        //    against the mirror AS IT IS NOW, still
                        //    permits.
                        // The deferral is KEPT on refusal: the ledger
                        // holds the dumped FIB (the dump no-ops on a
                        // populated ledger), the revocation path
                        // re-steers, and a later release diffs against
                        // a recovered source.
                        // One observation for liveness and epoch, as at
                        // the deferral site above.
                        let liveness_now = feed_session.as_ref().map(|f| f.liveness());
                        let live_now = liveness_now.is_some_and(|l| l.up);
                        let have_now = source.route_count();
                        let seq_now = source.change_seq();
                        let pulses_now = feed_session.as_ref().map_or(0, |f| f.pulse_count());
                        // An ABSOLUTE budget for the whole dump, never
                        // a dump-wide average: dividing by the dump's
                        // duration let a withdrawal burst early in a
                        // slow dump dilute into "settled" across the
                        // idle seconds that followed (review finding —
                        // twice: the first fix was claimed and never
                        // landed, caught by the reviewer reading the
                        // actual expression). The entire dump may see
                        // at most what a legitimately quiet source
                        // produces in one SOURCE_QUIET_FOR window,
                        // scaled by the mirror being protected.
                        // The same authority split as the release that
                        // authorized this dump: an unattested budget of
                        // zero, because a reconnect trickle running
                        // through the dump window is a reload the gate
                        // just promised was not happening — accepting
                        // ~2k elements of it here undid the zero-rate
                        // release one step later (review finding).
                        let flapped_now = matches!(
                            (epoch, liveness_now.map(|l| l.epoch)),
                            (Some(e), Some(c_)) if c_ != e
                        );
                        let churn_budget = if completeness.is_some() && !flapped_now {
                            source_quiet_rate_per_sec(have) * SOURCE_QUIET_FOR.as_secs()
                        } else {
                            UNATTESTED_QUIET_RATE_PER_SEC * UNATTESTED_QUIET_FOR.as_secs()
                        };
                        // Max, not sum, for the same double-count
                        // reason as the gate's rate.
                        let dump_churn = seq_now
                            .saturating_sub(seq)
                            .max(pulses_now.saturating_sub(pulses));
                        // Both bounds, because each covers the other's
                        // small end: the absolute budget is 128
                        // mutations at the 64/s floor, which is noise
                        // for a 1M mirror and a 99% wipe for a
                        // 100-route one (review finding). Half is the
                        // same fraction the diff-stage floor has always
                        // used for "the source still knows the table".
                        let mirror_settled =
                            have_now >= (have / 2).max(1) && dump_churn <= churn_budget;
                        let authority_agrees =
                            authority_current(completeness, have_now) != Some(false);
                        if !live_now || !mirror_settled || !authority_agrees {
                            tracing::warn!(
                                adopted,
                                live = live_now,
                                dump_churn,
                                churn_budget,
                                have_now,
                                "the feed changed while VPP's FIB was being dumped; holding \
                                 the diff — the adopted routes stay in the ledger and the \
                                 reconciliation resumes when the source is ready again"
                            );
                            gate.rebaseline(seq_now, pulses_now);
                            c.deferred_resync = Some(DeferredResync::AwaitingFallback {
                                gate,
                                last_request,
                                restoring: true,
                                epoch,
                                demoted,
                            });
                            return Ok(crate::driver::Drain::AwaitingSource { have, want });
                        }
                        tracing::info!(
                            have,
                            adopted,
                            "route source loaded and quiet and VPP unsteered; dumped its \
                             FIB against no traffic and running the adopted resync diff"
                        );
                        let _plan = engine.begin_resync(source.as_ref());
                        engine
                            .program_neighbours(source.as_ref())
                            .map(|_| ())
                            .map_err(|e| e.to_string())?;
                    }
                    c.deferred_resync = None;
                }
                DeferredResync::AwaitingDiff { adopted, mut gate } => {
                    // The diff stage has no session requirement (its
                    // floor is measured against the DUMPED table, and
                    // nothing at this stage is steered), so quiet needs
                    // no liveness conditioning: pass live.
                    let released = gate
                        .observe(
                            now,
                            SourceSample {
                                have,
                                seq,
                                pulses,
                                live: true,
                            },
                            source_quiet_rate_per_sec(adopted),
                            SOURCE_QUIET_FOR,
                        )
                        .released;
                    if !released {
                        let want = gate.floor;
                        c.deferred_resync = Some(DeferredResync::AwaitingDiff { adopted, gate });
                        return Ok(crate::driver::Drain::AwaitingSource { have, want });
                    }
                    tracing::info!(
                        have,
                        adopted,
                        "route source loaded and quiet; running the adopted resync diff"
                    );
                    {
                        let Core { engine, source, .. } = &mut *c;
                        let _plan = engine.begin_resync(source.as_ref());
                        engine
                            .program_neighbours(source.as_ref())
                            .map(|_| ())
                            .map_err(|e| e.to_string())?;
                    }
                    c.deferred_resync = None;
                }
            }
        }
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
                .map(|(done, _stats)| {
                    if done {
                        crate::driver::Drain::Idle
                    } else {
                        crate::driver::Drain::More
                    }
                })
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

    fn restore_steer(&mut self) -> Result<SteerOutcome, String> {
        // NO completeness gate, deliberately — the one divergence from
        // `steer`, and the whole reason this method exists. The gate
        // protects traffic from a VPP synced off an incomplete MIRROR;
        // the adoptee's FIB was never built from the mirror, and a
        // verdict condemning the mirror is precisely when traffic
        // belongs back on the intact adoptee rather than on the
        // fallback the verdict condemned (review finding: the gate
        // blocked the restoration exactly when its verdict caused the
        // revocation). Reachable only through Action::RestoreSteer,
        // which only (AdoptedResyncing, FallbackRevoked) emits.
        let mut c = self.core.borrow_mut();
        let outcome = c.steering.steer();
        c.record_steering();
        outcome
    }

    fn steer(&mut self) -> Result<SteerOutcome, String> {
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
        // `SteerFailed`, which leaves `steer_wanted` set, and the driver
        // re-attempts the steer once this verdict permits one — see
        // `Event::SteerUnblocked`. No rules are installed, so
        // `rules_remain` is unaffected.
        //
        // Not applied to an EMPTY target, and that exception is the
        // whole of the gate's own logic turned round: it exists to stop
        // traffic being diverted into a table that cannot forward it,
        // and a reconcile against a target with no port diverts
        // nothing — it only removes. Gating it refuses the one steer
        // whose entire job is to take traffic OFF VPP, and does so
        // precisely when the mirror is unhealthy, which is when the
        // operator is most likely to be rolling back. The exception
        // lives in `steer_verdict` so the retry's own gate cannot
        // forget it.
        if let Some(verdict) = c.steer_verdict() {
            if !verdict.permits_steering() {
                return Err(format!(
                    "refusing to steer: {}. Traffic would be diverted into a table that \
                     cannot forward it, and a steered miss is dropped rather than falling \
                     back to the kernel path. The want is remembered and re-attempted on \
                     its own, at most every {}s, once the verdict permits — \
                     `packetframe reconfigure` asks immediately rather than waiting. \
                     `require-table-complete off` opts out where there is no bird to \
                     compare against",
                    verdict.describe(),
                    crate::driver::STEER_RETRY_EVERY.as_secs()
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
        // A steered start is necessarily a steered ADOPTION: rules
        // reach the NIC only after a verify, which no fresh spawn has
        // had, and inherited orphan rules are torn down before
        // `StartRequested` is ever injected. It is also the one case
        // where `adopt_vpp_fib` must NOT run yet: the dump parks every
        // VPP worker in barrier sync (see
        // `DeferredResync::AwaitingFallback`), and this VPP is the one
        // carrying the traffic. Defer everything — the dump included —
        // until the fallback tier can take over. The NIC ledger is the
        // discriminator, not the supervisor's belief, because rules in
        // the NIC are what puts packets on VPP.
        if !c.steering.installed().is_empty() {
            let capacity = c.engine.route_capacity();
            let floor = (capacity / FALLBACK_FLOOR_DIVISOR).max(1);
            let seq =
                c.source.change_seq() + c.feed_session.as_ref().map_or(0, |f| f.pulse_count());
            tracing::info!(
                floor,
                "adopted VPP is steered, so reading its FIB waits: the dump freezes \
                 every worker for seconds (ip_route_dump holds VPP's barrier). Once the \
                 route source is loaded and quiet the eBPF tier takes the traffic, the \
                 dump runs against an idle VPP, and steering returns after the verified \
                 resync"
            );
            c.deferred_resync = Some(DeferredResync::AwaitingFallback {
                gate: SourceGate::new(floor, seq),
                last_request: None,
                restoring: false,
                epoch: None,
                demoted: false,
            });
            return Ok(());
        }
        // Unsteered: nothing is on VPP, so the dump's worker stall
        // costs no packets. Split borrow: the engine walks the source
        // while both live in the same core.
        let deferral = {
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
            // The diff is only meaningful against a source that has
            // finished loading, and a daemon restart is exactly when it
            // has not: the feed reconnects at startup and takes tens of
            // seconds to reload. Diffing an adopted ledger against that
            // window queues ~everything as a withdrawal (drill (d),
            // 2026-08-07). EVERY adoption of a POPULATED FIB defers,
            // even one whose source already looks complete — a count
            // cannot say "complete", only the floor-plus-quiescence gate
            // in `drain_batch` can, and an above-floor count at this
            // instant is exactly what a half-finished reload looks like
            // (2026-08-08).
            //
            // `adopted == 0` — a fresh spawn, or a survivor with an
            // empty FIB — starts immediately instead: there is no
            // withdrawal universe to protect, the resync is pure
            // installs that safely trickle in as the feed loads, and a
            // floor of zero would otherwise turn the gate into a bare
            // quiescence wait — deferring an EMPTY dataplane behind a
            // loading feed, the one situation where converging as fast
            // as routes arrive is strictly better (review finding on
            // this PR).
            if adopted == 0 {
                let _plan = engine.begin_resync(source.as_ref());
                // Neighbours between attach and the first drain, and
                // fatal on refusal: a route through an unprogrammed
                // adjacency installs cleanly, verifies cleanly, and
                // drops every packet.
                engine
                    .program_neighbours(source.as_ref())
                    .map(|_| ())
                    .map_err(|e| e.to_string())?;
                None
            } else {
                let have = source.route_count();
                let seq = source.change_seq();
                tracing::info!(
                    have,
                    adopted,
                    "adopted resync deferred until the route source is loaded and quiet; \
                     the adopted FIB keeps forwarding untouched meanwhile"
                );
                Some(DeferredResync::AwaitingDiff {
                    adopted,
                    // Clamped to 1: integer division floors adopted=1
                    // to zero, and a floor of zero lets a DEAD source
                    // (have=0) pass the gate, go quiet, and withdraw
                    // the sole live route — the exact case the floor
                    // exists for (review finding). A populated
                    // adoption's floor is never satisfied by nothing.
                    gate: SourceGate::new((adopted / ADOPTED_SOURCE_FLOOR_DIVISOR).max(1), seq),
                })
            }
        };
        c.deferred_resync = deferral;
        Ok(())
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

    /// Activity cannot divide away, however slowly the tick ran.
    ///
    /// The unattested posture sets `quiet_rate` to ZERO precisely to
    /// demand literal silence, so a rate that truncates to zero is not
    /// a rounding detail — it is the difference between "the stream
    /// stopped" and "the stream is running and we divided it away".
    /// Ticks are not pinned to one second, so the interval is the
    /// attacker here, not the volume.
    #[test]
    fn one_pulse_over_a_slow_tick_is_not_silence() {
        let sample = |pulses| SourceSample {
            have: 1_000,
            seq: 0,
            pulses,
            live: true,
        };
        let mut gate = SourceGate::new(0, 0);
        let t0 = std::time::Instant::now();
        // First observation only baselines.
        gate.observe(t0, sample(0), 0, UNATTESTED_QUIET_FOR);

        // One pulse two seconds later: 1 * 1000 / 2000 truncates to 0,
        // and 0 <= 0 read as quiet.
        let v = gate.observe(
            t0 + Duration::from_secs(2),
            sample(1),
            0,
            UNATTESTED_QUIET_FOR,
        );
        assert!(
            v.rate_quiet_for.is_none(),
            "a pulse is activity at any tick spacing; the zero-rate \
             posture must see it"
        );

        // And genuine silence across the same slow tick still reads
        // quiet — the fix must not make the gate unsatisfiable.
        let v = gate.observe(
            t0 + Duration::from_secs(4),
            sample(1),
            0,
            UNATTESTED_QUIET_FOR,
        );
        assert!(
            v.rate_quiet_for.is_some(),
            "no new pulses is silence, whatever the interval"
        );
    }

    struct EmptySource;
    impl RouteSource for EmptySource {
        fn for_each_route(&self, _: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, _: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {}
        fn route_count(&self) -> u64 {
            0
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }

    fn engine() -> ConvergenceEngine {
        ConvergenceEngine::new(
            "/nonexistent/api.sock",
            Vec::new(),
            vec!["eth4".into()],
            1_000,
            FamilyPolicy::V4Only,
            packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
                prefix_len: 32,
            },
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
        /// Ports the config asks to steer. Its own field rather than
        /// derived from `rules`, because the whole point of
        /// `configured_ports` is being answerable when nothing is
        /// installed.
        configured: usize,
    }

    impl Steering for LedgerSteering {
        fn missing_from_nic(&self) -> Result<SteeringAudit, String> {
            Ok(SteeringAudit::clean())
        }
        fn configured_ports(&self) -> usize {
            self.configured
        }

        fn steer(&mut self) -> Result<SteerOutcome, String> {
            let (rules, ok) = self.next.take().unwrap_or_default();
            self.rules = rules;
            if ok {
                Ok(SteerOutcome::Steered)
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
            configured: 1,
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

    /// An INCOMPLETE audit reaches status as both of its facts.
    ///
    /// The audit can prove drift and still fail to read the rest, and
    /// the caller used to treat any `Ok` as a complete pass: it cleared
    /// `steer_audit_error` and published the confirmed count as current,
    /// so health said "1 rule missing" while more could have been
    /// sitting behind the unreadable location and nothing said so
    /// (review finding). The count is a floor whenever the pass was
    /// partial, and the two travel together for that reason.
    #[test]
    fn an_incomplete_audit_publishes_its_count_and_its_gap() {
        struct PartialAudit;
        impl Steering for PartialAudit {
            fn missing_from_nic(&self) -> Result<SteeringAudit, String> {
                Ok(SteeringAudit {
                    missing: vec![("eth4".into(), 1024)],
                    unreadable: Some("loc 1025 on eth4: EIO".into()),
                    ..SteeringAudit::clean()
                })
            }
            fn configured_ports(&self) -> usize {
                1
            }
            fn steer(&mut self) -> Result<SteerOutcome, String> {
                Ok(SteerOutcome::Steered)
            }
            fn unsteer(&mut self) -> Result<(), String> {
                Ok(())
            }
            // Non-empty: the caller skips the audit on an empty ledger.
            fn installed(&self) -> Vec<(String, u32)> {
                vec![("eth4".into(), 1024), ("eth4".into(), 1025)]
            }
            fn retarget(&mut self, _: Vec<(String, u32)>, _: crate::steer::RuleSet) {}
        }

        let rt = Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(PartialAudit),
            Box::new(NullStore),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        let st = rt.status();
        assert_eq!(
            st.steer_missing, 1,
            "the drift the pass DID prove must be published"
        );
        assert_eq!(
            st.steer_audit_error.as_deref(),
            Some("loc 1025 on eth4: EIO"),
            "and so must the fact that the pass was incomplete — without it the \
             floor is published as a current count and further drift is invisible"
        );
    }

    /// Retargeting invalidates the cached audit, like a ledger change.
    ///
    /// The audit answers "does the NIC hold what THIS target asks for",
    /// so both inputs must invalidate it — and only the ledger did.
    /// `retarget` runs before the reconciling steer, which can refuse at
    /// the completeness gate and return without reaching
    /// `record_steering`, so the answer to the old question stood for up
    /// to STEER_AUDIT_EVERY while `reconfigure` republished status
    /// immediately (review finding).
    ///
    /// The rate limiter is the discriminator: a second `status()` must
    /// NOT re-audit, and the one after the retarget must.
    #[test]
    fn retargeting_invalidates_the_cached_audit() {
        /// Clean on the first pass, drifting on every one after — so a
        /// re-audit is visible in the published count.
        struct DriftsAfterFirstPass(std::cell::Cell<usize>);
        impl Steering for DriftsAfterFirstPass {
            fn missing_from_nic(&self) -> Result<SteeringAudit, String> {
                let n = self.0.get();
                self.0.set(n + 1);
                Ok(if n == 0 {
                    SteeringAudit::clean()
                } else {
                    SteeringAudit {
                        missing: vec![("eth4".into(), 1024)],
                        ..SteeringAudit::clean()
                    }
                })
            }
            fn configured_ports(&self) -> usize {
                1
            }
            fn steer(&mut self) -> Result<SteerOutcome, String> {
                Ok(SteerOutcome::Steered)
            }
            fn unsteer(&mut self) -> Result<(), String> {
                Ok(())
            }
            // Non-empty: the caller skips the audit on an empty ledger.
            fn installed(&self) -> Vec<(String, u32)> {
                vec![("eth4".into(), 1024)]
            }
            fn retarget(&mut self, _: Vec<(String, u32)>, _: crate::steer::RuleSet) {}
        }

        let rt = Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(DriftsAfterFirstPass(std::cell::Cell::new(0))),
            Box::new(NullStore),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        assert_eq!(rt.status().steer_missing, 0, "the first pass reads clean");
        assert_eq!(
            rt.status().steer_missing,
            0,
            "and the second is served from the cache — without this the test \
             would pass whether or not retarget invalidates anything"
        );

        rt.retarget(vec![("eth4".into(), 0)], crate::steer::RuleSet::default());
        assert_eq!(
            rt.status().steer_missing,
            1,
            "a new target must be asked about, not answered from the old \
             question's cache"
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
        assert!(obs.drain_batch(std::time::Instant::now()).is_err());
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
            // The gate applies to a target that ASKS for a port —
            // that is the traffic it protects. A double that installs a
            // rule while reporting nothing configured would exercise
            // the empty-target bypass instead, and pass for the wrong
            // reason.
            configured: 1,
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

    /// The gate does not block a reconcile that diverts nothing.
    ///
    /// It exists to keep traffic out of a table that cannot forward it.
    /// A target with no port installs nothing and only removes, so
    /// gating it refuses the one steer whose job is to take traffic OFF
    /// VPP — and refuses it precisely when the mirror is unhealthy,
    /// which is when an operator is most likely to be rolling back. The
    /// rollback would then be unable to complete for the same reason it
    /// was started.
    #[test]
    fn the_completeness_gate_does_not_block_an_empty_target() {
        use packetframe_common::fib::{CompletenessReport, TableCompleteness};

        let steering = LedgerSteering {
            // Reconciled to nothing, successfully: no port configured.
            next: Some((Vec::new(), true)),
            configured: 0,
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
        // The most condemning verdict there is.
        handle.publish(CompletenessReport {
            authority_routes: 1_000_000,
            mirror_routes: 1,
            at: std::time::Instant::now(),
        });

        let (_, mut fx) = rt.views();
        fx.steer()
            .expect("a reconcile that installs nothing has no traffic to protect");

        // And the RETRY's gate must make the same exception, or it
        // becomes the thing that holds a `steer off` unfinished: it is
        // what drives this reconcile from `Ready` without waiting for a
        // convergence, and a condemning verdict is exactly the weather
        // a rollback happens in.
        let (mut obs, _) = rt.views();
        assert!(
            obs.steer_permitted(),
            "the retry asked a stricter question than the steer it drives"
        );
    }

    /// A source still holding changes disqualifies the moment, however
    /// clean everything else looks.
    ///
    /// The engine's pending map going empty is not the same statement:
    /// `drain_batch` pulls at most `DELTA_BATCH` and sends at most
    /// `DRAIN_BATCH`, and they are the same number, so one tick can pull
    /// 4096, send all 4096, and report `Drain::Idle` with the feed still
    /// holding the rest of a reload. Neither gate sees it — the ledger
    /// has not classified those changes, and completeness compares bird
    /// against the mirror the tee already updated, so a burst of route
    /// UPDATES keeps the count identical and the verdict converged.
    /// Everything reads healthy while VPP is tens of thousands of
    /// changes behind (review finding, PR #160).
    #[test]
    fn a_source_backlog_defers_the_retry() {
        struct Backlogged(std::cell::Cell<u64>);
        impl RouteSource for Backlogged {
            fn for_each_route(&self, _: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
            fn for_each_neighbour(&self, _: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {}
            fn route_count(&self) -> u64 {
                0
            }
            fn change_seq(&self) -> u64 {
                0
            }
            fn backlog(&self) -> u64 {
                self.0.get()
            }
        }

        // Everything else is as permissive as it gets: no completeness
        // handle, an empty ledger, a target that asks for a port.
        let rt = Runtime::new(
            engine(),
            Box::new(Backlogged(std::cell::Cell::new(4_096))),
            Box::new(LedgerSteering {
                configured: 1,
                ..Default::default()
            }),
            Box::new(NullStore),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        {
            let (mut obs, _) = rt.views();
            assert!(
                !obs.steer_permitted(),
                "changes the engine has not pulled are invisible to both gates, and \
                 steering over them blackholes every prefix in the backlog"
            );
        }
        // Drained: the same moment is fine.
        rt.core.borrow_mut().source = Box::new(Backlogged(std::cell::Cell::new(0)));
        {
            let (mut obs, _) = rt.views();
            assert!(obs.steer_permitted());
        }

        // ...but a backlog must NOT hold back a reconcile to an empty
        // target, for the same reason neither gate does: that steer only
        // removes rules, and changes still queued for a table it is
        // taking traffic OFF are no argument for leaving it steered.
        // This predicate was added after the exception was pushed down
        // into each gate, and got this wrong on the first attempt.
        rt.core.borrow_mut().source = Box::new(Backlogged(std::cell::Cell::new(4_096)));
        rt.core.borrow_mut().steering = Box::new(LedgerSteering {
            configured: 0,
            ..Default::default()
        });
        let (mut obs, _) = rt.views();
        assert!(
            obs.steer_permitted(),
            "a backlog is a reason not to divert traffic INTO VPP, not a reason to \
             leave a rollback unfinished"
        );
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
            // The gate applies to a target that ASKS for a port —
            // that is the traffic it protects. A double that installs a
            // rule while reporting nothing configured would exercise
            // the empty-target bypass instead, and pass for the wrong
            // reason.
            configured: 1,
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
