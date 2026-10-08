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

use packetframe_common::events::{self as event_log, kind as event_kind};

use crate::driver::Observe;
use crate::engine::{ConvergenceEngine, EngineError, RouteSource};
use crate::executor::{Effects, StepError};
use crate::kernel_path::KernelWatch;
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
    ///
    /// `plans` is what those locations were installed to HOLD, and it
    /// travels with them because a location alone cannot be taken back
    /// out: see
    /// [`crate::resources::ResourceState::steer_plans`]. The two are one
    /// argument list rather than two calls so the file can never record
    /// rules without the plan that removes them.
    fn steering_changed(
        &mut self,
        rules: &[(String, u32)],
        plans: &[(String, u32, crate::steer::RuleSet)],
    ) -> Result<(), String>;

    /// A preserving stop's route ledger, to be left for the next daemon
    /// ([`crate::ledger_record`]), tied to the process this store records.
    ///
    /// The store supplies the identity because it is the one that knows
    /// which process it recorded — the ledger describes THAT VPP or
    /// nothing. The default refuses, which is the safe answer for any
    /// store that cannot make the binding durable: no record means the
    /// next adoption reads VPP's FIB, as every adoption did before.
    fn preserve_ledger(&mut self, _body: crate::ledger_record::LedgerBody) -> Result<(), String> {
        Err("this identity store cannot preserve a route ledger".into())
    }
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
    fn steering_changed(
        &mut self,
        _: &[(String, u32)],
        _: &[(String, u32, crate::steer::RuleSet)],
    ) -> Result<(), String> {
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

/// Re-asserts a member port's KERNEL PF rx-mode after the VPP side of
/// a device attach settles.
///
/// Why this exists (w8, primary, 2026-08-13): bringing the member VF up
/// disables the AF's channel-default MCAM entries for the whole shared
/// LMAC (observed as entries 2004/2005 flipping `enabled: no`), which
/// leaves the kernel PF deaf BELOW the kernel — `rx_drops` frozen,
/// `IFF_PROMISC` still set, every host surface green — and on a
/// bridge-member port (the primary's eth4/switch0) that is a full
/// bridge blackout. The VF-side promisc vote (#178) provably does NOT
/// re-enable them: w8 ran a single stable VPP — no respawns, zero
/// `VerifyFailed`, `sw_interface_set_promisc` acknowledged — and the
/// port froze within a second of device attach anyway. Only a PF-side
/// rx-mode event makes the AF re-install its defaults, proven
/// five-for-five by the w6 kick cycles (~1 s recovery each). The
/// re-breaks that made the kick look non-viable in w6 were the verify
/// kill-respawn loop #180 removed: each new VPP's port start
/// re-disabled the entries within its backoff interval.
///
/// A trait rather than a direct ioctl so the service tests can record
/// calls and non-Linux builds never pretend.
pub trait RxModeKick {
    /// Force the kernel netdev named `port` to resend its rx-mode to
    /// the AF. Any rx-mode event does it; the Linux implementation
    /// toggles `IFF_ALLMULTI`.
    fn kick(&mut self, port: &str) -> Result<(), String>;
}

/// No kick installed: tests and harnesses. Deliberately SILENT — the
/// real implementation logs each kick, so a production attach log
/// without the kick lines means the wiring did not install
/// [`AllmultiKick`], visibly, rather than a stub logging success it
/// never performed.
#[derive(Debug, Default)]
pub struct NoKick;
impl RxModeKick for NoKick {
    fn kick(&mut self, _port: &str) -> Result<(), String> {
        Ok(())
    }
}

/// The real kick: `IFF_ALLMULTI` on, then back to the flags that were
/// read, via `SIOCSIFFLAGS` on the kernel netdev. Two rx-mode events,
/// each forcing the PF driver to resend `NIX_RX_MODE` to the AF; the
/// entries end enabled and the port's flags end where they started.
/// Same ioctl shape and musl/glibc cast note as
/// `ntuple::sys::ethtool_raw`.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct AllmultiKick;

#[cfg(target_os = "linux")]
impl RxModeKick for AllmultiKick {
    fn kick(&mut self, port: &str) -> Result<(), String> {
        fn flags_ioctl(port: &str, set_to: Option<libc::c_short>) -> Result<libc::c_short, String> {
            let name = port.as_bytes();
            let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
            if name.len() >= ifr.ifr_name.len() {
                return Err(format!("interface name `{port}` exceeds IFNAMSIZ"));
            }
            for (dst, src) in ifr.ifr_name.iter_mut().zip(name) {
                *dst = *src as libc::c_char;
            }
            let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
            if sock < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let (cmd, verb) = match set_to {
                Some(f) => {
                    ifr.ifr_ifru.ifru_flags = f;
                    (libc::SIOCSIFFLAGS, "SIOCSIFFLAGS")
                }
                None => (libc::SIOCGIFFLAGS, "SIOCGIFFLAGS"),
            };
            // `ioctl`'s request argument is `c_ulong` on glibc and
            // `c_int` on musl; without the cast one published target
            // does not compile, with it the other needs the allow.
            #[allow(clippy::unnecessary_cast)]
            let rc = unsafe { libc::ioctl(sock, cmd as _, &mut ifr) };
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(sock) };
            if rc != 0 {
                return Err(format!("{verb} on {port}: {err}"));
            }
            Ok(unsafe { ifr.ifr_ifru.ifru_flags })
        }

        let original = flags_ioctl(port, None)?;
        let allmulti = libc::IFF_ALLMULTI as libc::c_short;
        flags_ioctl(port, Some(original | allmulti))?;
        // Restore EXACTLY what was read — an operator running with
        // allmulti deliberately on must get it back.
        flags_ioctl(port, Some(original))?;
        tracing::info!(
            port,
            "kernel rx-mode re-asserted (allmulti toggle): the AF re-installs its \
             channel-default MCAM entries for this LMAC"
        );
        Ok(())
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
    /// `(iface, form)` for every keep rule the pass found present: the
    /// form the NIC actually holds it in, read back, as opposed to the
    /// form a steer meant to install ([`Steering::keep_forms`]). A
    /// queue-0 keep on a port whose driver takes RSS is one an older
    /// daemon installed and no steer has rewritten yet.
    pub keeps_observed: Vec<(String, crate::ntuple::KeepForm)>,
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
    /// Every port with keep rules in the ledger, with the form this
    /// process installed them in — RSS, or the queue-0 fallback where
    /// the driver declined RSS — or `None` where they were inherited and
    /// not yet re-installed. What decides the queue-0 IRQ placement
    /// ([`crate::kernel_path`]).
    ///
    /// A default returning nothing because only a seam that installs
    /// keeps has anything to say, and every test double here installs
    /// none. A real seam that forgot it would cost the IRQ placement
    /// and the status line, not a rule left in the NIC — unlike
    /// [`Self::installed_plan`], which is why that one has no default.
    fn keep_forms(&self) -> Vec<crate::ntuple::KeepPort> {
        Vec::new()
    }
    /// `(iface, VF, plan)` the ledger above was last successfully
    /// installed under — empty where nothing has been.
    ///
    /// Persisted next to the ledger on every change, for the half of
    /// removal that locations cannot express: a `Keep` rule's
    /// `ring_cookie` is 0, so only its spec distinguishes it from a
    /// stranger's kernel-delivery rule, and a teardown in another
    /// process has no spec unless this one wrote it down.
    ///
    /// Not a trait default. An implementor that quietly returned
    /// nothing here would leak exemptions exactly as the missing field
    /// did, and silently — the failure this module has already paid for
    /// once with `adopt_installed` shipping with no caller (#127).
    fn installed_plan(&self) -> Vec<(String, u32, crate::steer::RuleSet)>;
    /// `(iface, VF, plan)` the next [`Self::steer`] would install — the
    /// target as it stands, after anything held back from it (the IPv6
    /// half while the hand-back path is not ready). Read against
    /// [`Self::installed_plan`] to tell a reconcile that diverts MORE
    /// traffic onto VPP from one that diverts the same or less
    /// ([`crate::steer::adds_diversion`]), which is what decides whether
    /// the first-steer hold applies to it.
    ///
    /// Not a trait default, for the same reason as `installed_plan`: an
    /// implementor answering "nothing" would make every reconcile look
    /// like a pure removal, and a later canary port would be diverted
    /// into a VPP still loading the table.
    fn target_plan(&self) -> Vec<(String, u32, crate::steer::RuleSet)>;
    /// Change what steering *should* be, without touching the NIC.
    ///
    /// Deliberately infallible and side-effect-free: it records intent,
    /// and the next `steer`/`unsteer` is what makes the hardware agree.
    /// Splitting it that way keeps one routine — `steer` — responsible
    /// for every rule that ever reaches the NIC, so a reconfigure cannot
    /// grow its own, subtly different, installation path.
    fn retarget(&mut self, targets: Vec<(String, u32, crate::steer::RuleSet)>);
    /// Whether the IPv6 half of the target may be installed: the IPv6
    /// hand-back path is whole ([`crate::handback`]), so router-owned
    /// traffic a v6 diversion takes has a way back to the kernel.
    ///
    /// Intent only, like [`Self::retarget`]: the next `steer` is what
    /// makes the NIC agree. A default no-op because only a seam that
    /// plans IPv6 has anything to withhold — every test double here plans
    /// none — and [`crate::ntuple::NtupleSteering`], which does, starts
    /// withheld, so a forgotten call fails closed: v6 is held back,
    /// never diverted without a way home.
    fn set_v6_ready(&mut self, _ready: bool) {}
    /// Take out, now, any IPv6 rule the NIC holds while the v6 half is held
    /// back — rules inherited from a previous process that was steering v6
    /// when this one's hand-back path is not ready — leaving every IPv4
    /// rule exactly where it is. Returns how many came out.
    ///
    /// Without it such rules outlive the gate: the target already withholds
    /// v6, so no gate TRANSITION fires, and they keep diverting the router's
    /// own IPv6 into a VPP that cannot hand it back until the adoption's
    /// resync and verify end in a steer. A default no-op for seams that
    /// plan no IPv6, like [`Self::set_v6_ready`].
    fn drop_held_v6(&mut self) -> Result<usize, String> {
        Ok(0)
    }
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

    /// Nothing, and truthfully so: this seam refuses every `steer`, so
    /// no plan of its ever reached a NIC.
    fn installed_plan(&self) -> Vec<(String, u32, crate::steer::RuleSet)> {
        Vec::new()
    }
    fn target_plan(&self) -> Vec<(String, u32, crate::steer::RuleSet)> {
        Vec::new()
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
    fn retarget(&mut self, _targets: Vec<(String, u32, crate::steer::RuleSet)>) {}
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
    /// `Some` while a FRESH resync is holding `SyncComplete` back until
    /// the completeness authority says the source has converged. Armed
    /// by `start_resync`'s fresh arm when an authority is configured;
    /// cleared by `drain_batch` on release. See [`FreshHold`].
    fresh_hold: Option<FreshHold>,
    /// The kernel rx-mode kick, run per member port after every device
    /// attach. [`NoKick`] until the attach wiring installs
    /// [`AllmultiKick`] on Linux. See [`RxModeKick`] for the incident.
    rx_kick: Box<dyn RxModeKick>,
    /// The kernel path exempt traffic takes: queue-0 IRQ placement and
    /// the receive counters ([`crate::kernel_path`]).
    /// [`crate::kernel_path::NoKernelPath`] until the attach wiring
    /// installs the live one on Linux.
    kernel_path: Box<dyn crate::kernel_path::KernelPath>,
    /// What the kernel path has been observed doing, per steered port.
    kernel_watch: KernelWatch,
    /// When the NIC was last audited against the steering ledger, and
    /// how many rules it was missing. See [`STEER_AUDIT_EVERY`].
    last_steer_audit: Option<std::time::Instant>,
    /// When the null-drop counter was last sampled over `cli_inband`.
    /// Same real-clock pacing argument as `last_steer_audit`: a
    /// metrics poll, not a supervision deadline.
    last_null_sample: Option<std::time::Instant>,
    /// When bridge-neighbour placement was last refreshed from the FDB
    /// ([`ConvergenceEngine::refresh_placement`]). Real clock, paced by
    /// [`PLACEMENT_EVERY`]: a kernel read, not a supervision deadline.
    last_placement: Option<std::time::Instant>,
    /// The exemption tripwire: kernel paths VPP cannot take that no
    /// `steer-exempt` covers. Installed on Linux whenever steering is
    /// configured at all — the hole it finds opens the moment a port
    /// steers, and an operator wants it named BEFORE that.
    /// The scan runs on its own thread — see [`crate::drift::DriftScanner`]
    /// for why a full route dump must never sit on this loop.
    drift_scanner: Option<crate::drift::DriftScanner>,
    /// Last completed scan's findings, kept across a failed scan (an
    /// unreadable kernel is not evidence the routes went away).
    drift_uncovered: Vec<String>,
    /// How many ROUTES those findings stand for. Tracked beside the
    /// lines because the nexthop-object summary is one line for many
    /// routes, and the gauge must count routes.
    drift_routes: usize,
    /// The scope generation the retained findings were scanned under,
    /// and whether that is still the current one. A million-route
    /// dump takes seconds, so "attached but not yet scanned" is a
    /// real window an operator can steer inside — and an empty
    /// finding list there is not a clean verdict, it is no verdict
    /// (review finding).
    drift_result_gen: Option<u64>,
    /// A scanner exists and has not yet reported on the CURRENT
    /// scope. False when no scanner is installed — nothing to wait
    /// for — and false once a current-generation verdict lands.
    drift_pending: bool,
    /// A drift scope the config asked for that the NIC has not taken
    /// yet.
    ///
    /// Staged rather than applied, because the scan judges what the
    /// NIC is BELIEVED TO HOLD and a reconfigure's rules do not reach
    /// it until a steer succeeds. Committing at request time hid a
    /// path whose exemption had been refused; committing only on the
    /// synchronous success then missed the OTHER door — a first steer
    /// deferred by the FIB gate is retried automatically by the
    /// driver, installs the new rules with nobody replaying the
    /// request, and would have left the watcher on the old exemptions
    /// (both review findings). It is committed at the places every
    /// steering action goes through, whichever path asked for it.
    pending_drift_scope: Option<crate::drift::DriftScope>,
    /// The IPv6 half of the tripwire, retained by the same rules as the
    /// v4 fields above — see [`crate::drift::V6DriftState`].
    drift_v6: crate::drift::V6DriftState,
    /// The `drift-accept6` set, read each time a v6 verdict lands. The
    /// module's handle, so a reload reaches it without this loop — see
    /// [`crate::drift::DriftAccepts6`] for why it is not in the scope.
    drift_accepts6: std::sync::Arc<crate::drift::DriftAccepts6>,
    /// Set when a steering change failed PARTWAY and left rules on
    /// the NIC, so neither the old exemption set nor the new one
    /// describes what is installed.
    ///
    /// `NtupleSteering::steer` rolls back a partial install, and a
    /// rollback that itself fails deliberately keeps those rules in
    /// the ledger — they are still diverting traffic. The scope gate
    /// is `is_ok()`, so the watcher stayed on the old exemptions
    /// while a surviving divert rule blackholed a prefix the
    /// reconfigure had just unexempted (review finding). There is no
    /// correct set to adopt in that state, so the scan says it does
    /// not know rather than answering from either one.
    drift_scope_stale: Option<String>,
    /// Why the last scan could not read the kernel, if it could not.
    ///
    /// Its own field for the same reason `steer_audit_error` is: a
    /// check that cannot run must not be indistinguishable from one
    /// that ran and found nothing. Without it a permanently broken
    /// netlink read published an empty finding list, no health row and
    /// a zero gauge — the newest safety check presenting as clean
    /// while blind, which is the shape it exists to catch (review
    /// finding). Same rule as the null-drop gauge's absent-not-zero.
    drift_unreadable: Option<String>,
    /// How long the latest finished drift scan took, in ms — whatever its
    /// verdict and whichever scope it judged: the kernel paid for it
    /// either way. `None` until one finishes.
    drift_scan_ms: Option<u64>,
    steer_missing: usize,
    /// Rules still steering a port the config asks to leave unsteered,
    /// as of the last audit. Its own count because it points the other
    /// way: `steer_missing` says install, this says remove.
    steer_stray: usize,
    /// The `at` of the FIRST sample in the current unbroken run of
    /// readings that blamed the AUTHORITY, or `None` when the last
    /// reading did not.
    ///
    /// The runtime's only piece of history about the authority, and it
    /// exists because one sample cannot establish the thing the health
    /// line escalates on. `CompletenessReport` carries two counts taken
    /// a moment apart, and a bulk withdrawal landing in that moment
    /// reads as "the authority is measuring a different table" — which
    /// sends an operator to restart a daemon. A fault that is real is
    /// still there when the next report measures both counts again; one
    /// made by the clock is not. See [`track_authority_fault`].
    ///
    /// Updated on the tick path (`drain_batch`), next to the
    /// `authority_current` call whose answer it qualifies, because that
    /// is the only place that runs every tick of a deferral. `status()`
    /// reads it and does not advance it — a health surface that is
    /// polled irregularly, or never, must not be what decides whether a
    /// fault has persisted.
    authority_fault_since: Option<std::time::Instant>,
    /// Why the last audit could not read the NIC, if it could not.
    ///
    /// Kept apart from `steer_missing` because they answer different
    /// questions: that one is "how many are gone", this one is "the
    /// answer is not known". Collapsing them let a NIC that stopped
    /// answering keep publishing the last clean count, so steering read
    /// Healthy while drift had become undetectable (review finding).
    steer_audit_error: Option<String>,
    /// The previous process's preserved route ledger, handed over by the
    /// attach wiring with every identity check already passed, and not
    /// yet checked against VPP. `start_resync` consumes it — seeding the
    /// engine's ledger, or discarding it with the reason — before
    /// anything reads or changes VPP's FIB. Kept across a resync start
    /// that lost the API, so the resumed step decides it instead.
    preserved: Option<crate::ledger_record::LedgerRecord>,
    /// The seed the engine's ledger holds from a preserved record, while
    /// that seed is still unverified by this process. Set by
    /// `start_resync`; cleared by the verify that judges it (either way),
    /// by the pre-diff re-check disproving it, and by the process going
    /// away. While set, verify compares paths too, and a disagreement is
    /// [`Event::PreservedLedgerRejected`] rather than a teardown.
    seeded: Option<Seed>,
    /// How long the last `drain_batch` took on the real clock. See
    /// [`Observe::last_drain_took`].
    last_drain_took: Duration,
    /// How long the slowest adopted FIB dump took, on the real clock — the
    /// observed half of the convergence budget
    /// ([`crate::supervisor::convergence_budget`]). Survives the process:
    /// it describes this host and this table, not one VPP.
    last_dump_took: Option<Duration>,
    /// The IPv6 hand-back path's readiness as last handed to the steering
    /// ([`Steering::set_v6_ready`]) — the gate on the v6 half of steering.
    /// A change is what re-steers ([`Core::service_handback`]).
    v6_gate: bool,
    /// When a verdict the table has outgrown is re-run
    /// ([`crate::verify::ReverifySchedule`], [`Observe::poll_reverify`]).
    reverify: crate::verify::ReverifySchedule,
    /// A re-run verdict the loop has not picked up yet
    /// ([`Runtime::take_refreshed_verify`]). Handed over rather than read
    /// off the engine because the loop stamps its own clock on every
    /// completed verdict, and a verdict it never hears about would be
    /// reported with the previous one's age.
    refreshed_verify: Option<crate::verify::VerifyOutcome>,
    /// The named unresolvable routes as last written to the event log
    /// ([`UnresolvableLog`]).
    unresolvable_log: UnresolvableLog,
}

/// How often, at most, a changed set of named unresolvable routes is
/// written to the event log ([`UnresolvableLog`]).
pub const UNRESOLVABLE_LOG_EVERY: Duration = Duration::from_secs(60);

/// When the named unresolvable routes go to the event log: once per
/// change of the set, never per tick, and at most once per
/// [`UNRESOLVABLE_LOG_EVERY`] — a route flapping between unresolvable
/// and resolved must not own the log. A change inside the window is not
/// lost: it is what the next write says, once the window has passed.
/// The status rows carry the live list regardless.
#[derive(Debug, Default)]
pub struct UnresolvableLog {
    written: (Vec<String>, Vec<String>),
    at: Option<std::time::Instant>,
}

impl UnresolvableLog {
    /// Whether `(v4, v6)` should be written now. A `true` records it as
    /// written.
    pub fn due(&mut self, now: std::time::Instant, v4: &[String], v6: &[String]) -> bool {
        if self.written.0 == v4 && self.written.1 == v6 {
            return false;
        }
        if self
            .at
            .is_some_and(|t| now.duration_since(t) < UNRESOLVABLE_LOG_EVERY)
        {
            return false;
        }
        self.written = (v4.to_vec(), v6.to_vec());
        self.at = Some(now);
        true
    }
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

/// Armed by a FRESH `start_resync` when a completeness authority is
/// configured (`require-table-complete on`). While armed, an idle
/// drain during the resync reports [`crate::driver::Drain::AwaitingSource`]
/// instead of `Idle`, so `SyncComplete` cannot fire — and the single
/// verify runs over the full table rather than over whatever had
/// trickled in when the pending map first went momentarily empty.
///
/// Why this exists: on a fresh attach the feed connects AFTER the
/// module (bird dials the passive listener), so the first idle drain
/// lands ~1 s after spawn with the mirror holding only the local seeds
/// the tee excludes. Verify then sampled nothing, and the old verdict
/// mapping tore VPP down for it — seven kill-respawn cycles in 31 s on
/// the primary (w7, 2026-08-13), the first BEFORE bird's session had
/// even opened, each respawn re-running the octeon driver's port start
/// against the shared LMAC and blacking out the switch0 bridge. The
/// adopted paths already defer behind [`SourceGate`]s for exactly this
/// reason; this is the fresh path's equivalent, minus the floor
/// machinery an empty dataplane does not need — installs keep
/// trickling in while the hold is armed, so convergence overlaps the
/// dump instead of following it.
///
/// Release needs the authority's CURRENT word (`authority_current`,
/// the same helper the adopted release consults) AND a drained source
/// backlog — the mirror-vs-bird comparison cannot see updates the feed
/// still holds (`Core::behind`'s doc describes that gap). With no
/// authority configured there is nothing honest to wait for, the hold
/// is never armed, and `Verdict::event`'s `VerifyIncomplete` arm is
/// the backstop.
struct FreshHold {
    /// One log line per hold, not one per tick.
    announced: bool,
}

/// The loaded-and-quiet release of a STEERED adopted stage, with the feed
/// session's epoch bookkeeping that goes with it. Shared by the pre-dump
/// stage and the preserved-ledger diff, because both hold a diff back
/// from a VPP that is carrying traffic, and a release that is good enough
/// for one is exactly as good for the other. See `Core::read_fallback`.
#[derive(Debug, Clone, Copy)]
struct FeedGate {
    gate: SourceGate,
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
}

impl FeedGate {
    fn new(floor: u64, seq_baseline: u64) -> Self {
        Self {
            gate: SourceGate::new(floor, seq_baseline),
            epoch: None,
            demoted: false,
        }
    }
}

/// A ledger seeded from a preserved record, and what it was checked
/// against when it was seeded.
#[derive(Debug, Clone)]
struct Seed {
    /// How many routes it seeded.
    routes: u64,
    /// VPP's per-length route counts as they stood when the seed was
    /// accepted — equal to the preserving stop's. Kept because the diff
    /// can wait minutes for the source after that check, and a route
    /// another client adds or removes in that window is one the seed
    /// knows nothing about: never withdrawn by the diff, and never
    /// sampled by verify, which probes only ledger entries (review
    /// finding). So the counts are read again immediately before the
    /// deferred diff is released — see `Core::seed_still_holds`.
    fingerprint: crate::ledger_record::FibFingerprint,
}

/// Why VPP's current route counts (`now`, `None` if unreadable) do not
/// vouch for a ledger checked against `expected`, or `None` if they do.
/// One wording for the check at seeding and the re-check before the diff.
fn fingerprint_refusal(
    now: Option<&crate::ledger_record::FibFingerprint>,
    expected: &crate::ledger_record::FibFingerprint,
) -> Option<String> {
    match now {
        None => Some(
            "VPP's `show ip fib summary` could not be read, so whether anything changed its \
             FIB cannot be established"
                .to_string(),
        ),
        Some(now) if now != expected => {
            let recorded = &expected.counts;
            let first = now
                .counts
                .iter()
                .chain(recorded.iter())
                .find(|c| !recorded.contains(c) || !now.counts.contains(c))
                .map(|(t, l, n)| format!("{t} /{l} = {n}"))
                .unwrap_or_default();
            Some(format!(
                "VPP's route counts no longer match the preserved ledger's (first difference: \
                 {first}) — something added or removed routes"
            ))
        }
        Some(_) => None,
    }
}

/// What one paced look at the fallback tier found. See
/// `Core::read_fallback`.
#[derive(Debug, Clone, Copy)]
struct FallbackReading {
    /// Loaded, quiet and not vetoed: an adopted diff may run.
    released: bool,
    /// The feed session is up right now.
    live: bool,
    /// The completeness authority's current word is NO.
    veto: bool,
}

/// What a deferred adopted reconciliation is waiting for.
// The shared prefix IS the meaning — every variant is a wait — and the
// names are what the logs, health text and review history call them.
#[allow(clippy::enum_variant_names)]
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
    ///
    /// This is now the FALLBACK path of a steered adoption: one whose
    /// previous process left a preserved ledger that checks out never
    /// gets here (`AwaitingSeededDiff`). And a dump happens at most once
    /// per deferral: once it completes, the ledger holds VPP's FIB and a
    /// release the feed spoiled is retried as a diff against it, with no
    /// second read and no unsteer owed (see `spoiled`).
    AwaitingFallback {
        feed: FeedGate,
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
        /// Dumps this deferral has taken that the feed then spoiled —
        /// changed faster than the gate's quiet allowed while VPP's FIB
        /// was being read. The exponent of the quiet the next release
        /// needs (see `spoiled_backoff`): the quiet that released the
        /// spoiled attempt was, in hindsight, a lull.
        ///
        /// Structurally small. A completed dump stays in the ledger —
        /// nothing changes VPP's FIB while the diff waits (no deltas are
        /// applied during a deferral, and a restore touches only MCAM) —
        /// so the retry diffs against the FIB already read rather than
        /// reading it again, and a dump that is never re-taken cannot be
        /// spoiled twice.
        spoiled: u32,
        /// The source's size when this deferral last judged the fallback
        /// ready and asked for the unsteer. A live feed that then loses
        /// half of it is not a busy fallback but a collapsing one, and
        /// the revocation below puts traffic back on the intact adopted
        /// FIB for it.
        settled_have: Option<u64>,
    },
    /// An UNSTEERED adoption whose dump has already run — harmlessly,
    /// because with no rules installed nothing is on VPP for the
    /// barrier to stall. The DIFF is deferred until the source is
    /// loaded and quiet, exactly the original gate: a diff against a
    /// loading source is ~all withdrawals.
    AwaitingDiff { adopted: u64, gate: SourceGate },
    /// A STEERED adoption whose ledger was seeded from the previous
    /// process's preserved record ([`crate::ledger_record`]): VPP's FIB
    /// is known without reading it, so neither the dump nor the unsteer
    /// that existed for the dump is owed, and traffic stays on VPP
    /// throughout (rule 3, with nothing left to refine it). Only the DIFF
    /// waits — behind the pre-dump stage's own release, because it lands
    /// on a VPP carrying traffic exactly as that stage's would, and a
    /// diff against a loading source is ~all withdrawals (drill (d)). The
    /// floor is half the seeded table rather than a capacity fraction:
    /// here the adopted size IS known.
    AwaitingSeededDiff { feed: FeedGate },
}

impl DeferredResync {
    fn floor(&self) -> u64 {
        match self {
            DeferredResync::AwaitingFallback { feed, .. } => feed.gate.floor,
            DeferredResync::AwaitingDiff { gate, .. } => gate.floor,
            DeferredResync::AwaitingSeededDiff { feed } => feed.gate.floor,
        }
    }

    /// The feed gate a steered stage releases on, for the status surface's
    /// authority posture — the stages that consult the authority.
    fn feed(&self) -> Option<&FeedGate> {
        match self {
            DeferredResync::AwaitingFallback { feed, .. }
            | DeferredResync::AwaitingSeededDiff { feed } => Some(feed),
            DeferredResync::AwaitingDiff { .. } => None,
        }
    }
}

/// Ceiling on the quiet a release needs after spoiled dumps. See
/// `spoiled_backoff`.
const SPOILED_QUIET_MAX: Duration = Duration::from_secs(30);

/// The quiet a release needs after `spoiled` dumps the feed spoiled:
/// doubled per spoil, capped at [`SPOILED_QUIET_MAX`]. A dump spoiled by
/// churn means the quiet that released it was a lull between bursts, and
/// releasing on the same evidence again invites the same diff snapshot in
/// the next trough.
fn spoiled_backoff(base: Duration, spoiled: u32) -> Duration {
    base.saturating_mul(1u32 << spoiled.min(4))
        .min(SPOILED_QUIET_MAX.max(base))
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

/// The most route work still owed to VPP — changes the source holds plus
/// ops the engine has pulled and not sent — that still counts as VPP
/// having caught up with a `mirror`-route mirror ([`Core::behind`]): what
/// a QUIET source produces in one second ([`source_quiet_rate_per_sec`]),
/// 64 on a small table and ~1,300 on a full one.
///
/// Not zero, because zero is not a state a live feed is in at an
/// arbitrary instant. The loop drains the source once per tick and a
/// lever move lands between ticks, behind whatever churn queued since the
/// last drain; on a full-table feed a strict zero would refuse most lever
/// moves for a steer the next tick admits, and starve the verify re-run,
/// whose quiet moment must hold unbroken for its debounce. What it must
/// still refuse is a feed that is LOADING, and that is the line
/// `source_quiet_rate_per_sec` already draws: steady churn is tens of
/// changes a second, a reload arrives at ~18k a second and sits deep in
/// the source while VPP installs it — hundreds of thousands deep, for ten
/// minutes, on 2026-10-07.
///
/// A count of route WORK, not of a time: it says nothing about how fast
/// VPP will absorb it, only that what is owed is churn-sized rather than
/// table-sized. That is all it can say about a reload's TAIL, too: the
/// last few hundred changes of a reload pass under it as they would under
/// a quiet source, so a steer can land with that many prefixes still to
/// reach VPP. They follow a less specific VPP route until the next drain
/// or two takes them — the exposure a steered box has to any burst of
/// churn, which is a moment of staleness rather than a table missing.
///
/// Route work only. Neighbour work has no allowance (`Core::behind`).
fn caught_up_allowance(mirror: u64) -> u64 {
    source_quiet_rate_per_sec(mirror)
}

/// How far VPP is behind the route mirror, when further than a first
/// steer allows ([`Core::behind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Behind {
    /// ROUTE changes the route source holds that the engine has not
    /// pulled.
    pub backlog: u64,
    /// Neighbour changes it holds — any one is too many
    /// ([`RouteSource::neighbour_backlog`]).
    pub neighbours: u64,
    /// Ops the engine has pulled and not yet sent.
    pub pending: u64,
    /// The most of `backlog` and `pending` together that counts as
    /// caught up ([`caught_up_allowance`]).
    pub allowance: u64,
    /// The last attempt to apply route updates to VPP failed, so how far
    /// behind it is cannot be told from the counts: a batch handed back
    /// to the source is in the backlog, one lost in the engine is not.
    pub failing: bool,
}

/// Why a first steer must wait ([`Core::steer_hold`]): VPP has not caught
/// up with the route mirror, the last verify does not vouch for the table
/// being steered, or both. Each half names its own facts, so one wording
/// serves the refusal and both status rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteerHold {
    pub behind: Option<Behind>,
    pub unvouched: Option<crate::verify::Unvouched>,
}

impl SteerHold {
    /// Whether this hold clears with time, so a remembered want steers on
    /// its own: VPP catches up, and an outgrown verdict is re-run. A
    /// mismatch does not — it is never re-run, and the restart that clears
    /// it starts a never-steered port with no want (`MISMATCH_REMEDY`) —
    /// and neither does a missing verdict, which waiting cannot produce.
    /// What every surface promising "on its own" asks first.
    pub fn clears_itself(&self) -> bool {
        !matches!(
            self.unvouched,
            Some(crate::verify::Unvouched::Mismatch | crate::verify::Unvouched::NoVerdict)
        )
    }
}

impl std::fmt::Display for SteerHold {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut parts = Vec::new();
        if let Some(b) = &self.behind {
            parts.push(if b.failing {
                format!(
                    "the last attempt to apply route updates to VPP failed, so VPP is behind \
                     the route mirror by an amount the counts cannot show ({} change(s) still \
                     at the route source, {} queued for VPP)",
                    b.backlog + b.neighbours,
                    b.pending
                )
            } else {
                let neighbours = if b.neighbours > 0 {
                    format!(
                        " and {} neighbour change(s), where caught up is none: one moves \
                         every route through that next hop",
                        b.neighbours
                    )
                } else {
                    String::new()
                };
                format!(
                    "VPP has not caught up with the route mirror: {} change(s) still at the \
                     route source and {} queued for VPP, where caught up is at most {}{}",
                    b.backlog, b.pending, b.allowance, neighbours
                )
            });
        }
        if let Some(u) = &self.unvouched {
            parts.push(match u {
                crate::verify::Unvouched::Outgrown { .. } => format!(
                    "{u}; verify re-runs on its own {}s after VPP has caught up and the table \
                     is clean",
                    crate::verify::REVERIFY_DEBOUNCE.as_secs()
                ),
                _ => u.to_string(),
            });
        }
        write!(f, "{}", parts.join("; and "))
    }
}

/// Whether an UNSTEERED adoption's resync diff may run against the mirror
/// now, because the fast-path seeded it from its route ledger, rather
/// than after the route source's replay has gone quiet.
///
/// **What the quiet protects, and against what.** The diff withdraws
/// from VPP every route the mirror lacks, so it is only as good as the
/// mirror is complete; "a diff against a loading source is ~all
/// withdrawals" (drill (d)). Quiet is how the gate tells a loaded mirror
/// from a loading one when nothing else can, and since #153 it counts
/// every element the route source streams, changed or not, because a
/// reconnect's reannouncement leaves the mirror's own counter still: a
/// mirror quiet by mutations could be mid-reload. That protection is
/// untouched here for every mirror that was NOT seeded — a cold start
/// fills from empty, and nothing but the stream going quiet says it has
/// finished.
///
/// **Why a seeded mirror does not owe it — every one of these, together:**
/// - `mirror_seeded`: the mirror holds the previous process's whole
///   table from before the route source connected. It is not a table
///   filling from empty, so the withdrawal universe the gate guards is
///   not at stake: the diff withdraws only what VPP holds and the
///   previous process's mirror had already let go of.
/// - the feed session is up, in its FIRST epoch
///   ([`FIRST_FEED_EPOCH`]): the route source is streaming to this
///   process now, and has not dropped and reconnected since it began.
/// - the completeness authority's CURRENT word is yes
///   ([`authority_current`]: its last report permits steering, and its
///   count is within `STEER_MAX_DRIFT` of the mirror as it is now). The
///   fast-path authorities never attest a seed before the route source's
///   first route, so a yes in the first epoch was measured while THIS
///   stream was live; and a source that dropped part of the table while
///   this process was down shows as drift, refusing the door until the
///   replay's GC removes it. With no authority configured there is
///   nothing to vouch for the seed, and the door stays shut: the quiet
///   gate alone decides.
/// - and the ordinary floor, for completeness' sake.
///
/// **Why the first epoch only.** That first-route block is the one thing
/// that ties an authority report to a stream, and it applies once: to
/// the first session after the seed. After a reconnect the cached report
/// may predate the new stream, and a report taken since is the evidence
/// the steered gate already refuses after a flap (see `read_fallback`):
/// counts compared over a mirror whose previous-session routes are being
/// re-announced stay aligned whether or not the new stream has caught
/// up. There, only the GC restores trust — and the first GC also ends
/// the seed. So a reconnect shuts this door for good, and the replay has
/// to go quiet like any other (review finding, PR #324).
///
/// **What it costs.** Routes the source changed while the daemon was
/// down reach VPP when the replay re-advertises them, as ordinary
/// deltas, and routes it withdrew leave VPP when the route source's GC
/// withdraws them from the mirror — exactly as on the eBPF tier, which
/// forwards on the same seed. VPP carries no traffic at this stage
/// either way; what the door changes is that verify, and with it the
/// first steer, need not wait out the replay.
fn seeded_mirror_releases_diff(
    liveness: Option<packetframe_common::fib::FeedLiveness>,
    authority: Option<bool>,
    have: u64,
    floor: u64,
) -> bool {
    liveness.is_some_and(|l| l.mirror_seeded && l.up && l.epoch == FIRST_FEED_EPOCH)
        && authority == Some(true)
        && have >= floor
}

/// The feed session's epoch after its first down-to-up transition in this
/// process ([`packetframe_common::fib::FeedSession::set_up`]). A seed is
/// handed over before any route source can connect, so this is the first
/// session after the seed.
const FIRST_FEED_EPOCH: u64 = 1;

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
        // One read for both halves — the verdict and the report it came
        // from have to describe the SAME sample, or a publish landing
        // between two separate reads recomputes one report's drift
        // against another report's verdict.
        let (report, verdict) = h.latest_verdict();
        verdict.permits_steering()
            && report.is_some_and(|r| {
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

/// What the authority means **for the deferral that is actually
/// running** — a pure function so the rule can be stated and tested
/// rather than assembled inline in a struct literal.
///
/// Deferral-scoped, exactly like `DemotedByFlap`, and that is the whole
/// point. The question is not "what does the authority say" but "what
/// does THIS deferral's release path do with what it says", and the stages
/// differ: the steered ones (`AwaitingFallback`, `AwaitingSeededDiff`)
/// consult `authority_current` and a `false` there vetoes release
/// outright, while `AwaitingDiff` releases
/// on floor-and-quiet alone and never asks. Reporting a veto on the
/// diff stage would tell an operator that waiting cannot clear a
/// deferral that waiting clears perfectly well — the first version of
/// this did exactly that (review finding), which is the same defect
/// class as the message it was written to fix.
fn authority_posture(
    configured: bool,
    demoted: bool,
    gate_consults_authority: bool,
    current: Option<bool>,
    verdict: Option<packetframe_common::fib::Completeness>,
    fault_confirmed: bool,
) -> AuthorityPosture {
    // `authority_is_at_fault` rather than a match on the variant: the
    // zero-route case arrives as `Unknown` (assess returns it before the
    // mismatch branch) and is just as permanent, so the classification
    // has to live next to the variants and their reason strings rather
    // than being re-derived here (review finding).
    //
    // `fault_confirmed` is the second half of the same question, and it
    // is about the DATA rather than the verdict: one sample saying the
    // authority is wrong is a claim two counts taken a moment apart can
    // manufacture on their own (see [`authority_fault_confirmed`]). A
    // fault seen once is reported as `AwaitingAuthority` — blocked, and
    // clearing on its own if the next check disagrees — and becomes a
    // veto when a second, distinct sample says the same thing.
    let vetoing = gate_consults_authority
        && current == Some(false)
        && fault_confirmed
        && verdict.as_ref().is_some_and(|v| v.authority_is_at_fault());
    if !configured {
        AuthorityPosture::Absent
    } else if vetoing {
        // BEFORE the demotion, deliberately. `drain_batch` applies the
        // veto regardless of epoch — "a NEGATIVE word still vetoes
        // regardless of epoch; caution does not expire" — so when a
        // flap and a mismatch coincide, clearing the flap only reveals
        // the veto. Reporting the demotion there sends an operator to
        // idle the feed for a deferral that the feed cannot release
        // (review finding). The mismatch is the blocker that has to be
        // fixed either way; once it is, a surviving demotion reports
        // itself on the next snapshot.
        //
        // An UNCONFIRMED fault falls through to the demotion below, and
        // that ordering is right rather than merely tolerable: the flap
        // is an observed fact and the fault is not established yet, so
        // for that one interval the demotion is the true story. If the
        // next sample confirms the fault, it takes precedence here.
        AuthorityPosture::Vetoing
    } else if demoted {
        AuthorityPosture::DemotedByFlap
    } else if !gate_consults_authority || current != Some(false) {
        AuthorityPosture::Attesting
    } else {
        // Blocked, but by a verdict the next check can clear: no report
        // yet, one that aged out, a mirror still short of the authority,
        // or a fault only one sample has claimed. Only a CONFIRMED
        // `AuthorityMismatch` — a mirror holding substantially MORE than
        // the authority claims, twice — is not a loading state, and that
        // is `vetoing` above.
        AuthorityPosture::AwaitingAuthority
    }
}

/// One reading of the authority: the verdict on the sample **as it was
/// taken**, and **which sample it was read from**.
///
/// The identity matters as much as the verdict. The supervision loop
/// ticks every ~50 ms against a checker that publishes every ~300 s, so
/// the same sample is read some six thousand times, and "seen twice" has
/// to mean two different reports rather than two reads of one.
///
/// The verdict here briefly substituted the LIVE mirror count first, to
/// match what [`authority_current`] does before deciding the veto. That
/// was an over-correction, and the two review findings that produced
/// and then removed it are worth keeping together, because they look
/// contradictory and are not.
///
/// The first was right that the reason and the decision were reading
/// different mirrors. The wrong conclusion I drew was that the
/// classification should therefore substitute too — because a live
/// mirror measured against a STALE authority count manufactures an
/// `AuthorityMismatch` out of ordinary loading: a sample of 1.0M/1.0M
/// at T, a mirror at 1.3M by T+200s, and the substitution calls that
/// "the authority is measuring a different table" when the next 300 s
/// check simply re-measures both and agrees (review finding).
///
/// So the fault question — *is the authority itself wrong* — is asked
/// of the sample rather than of a live count measured against a stale
/// one. A mismatch that is real survives into the next sample and is
/// classified again; one created by the clock does not. What the
/// substituted view legitimately shows is that release is blocked RIGHT
/// NOW, and that belongs in the blocked-but-clearing message, which
/// names it.
///
/// **A sample is not an instant, and one sample is not proof.**
/// `IntegrityChecker::run_check` now takes its two counts concurrently,
/// so the gap between them is the difference between two concurrent
/// completions rather than a whole `birdc` invocation — but it is still
/// a gap, and under a bulk withdrawal or a reload a narrow one can
/// still read bird low and the mirror high, producing an
/// `AuthorityMismatch` the next check does not reproduce (review
/// finding). So the escalation to `Vetoing` is not decided by this
/// verdict alone: it needs the same fault in two DISTINCT samples, which
/// [`authority_fault_confirmed`] answers from the run tracked on the
/// tick path.
///
/// Both halves come out of ONE lock acquisition — see
/// `TableCompleteness::latest_verdict` for why a verdict read separately
/// from the report it describes can pair the two across a publish.
#[derive(Debug, Clone, PartialEq)]
struct AuthorityReading {
    /// `CompletenessReport::at` — the sample's identity. `None` only
    /// before the first report has ever been published, where the
    /// verdict is `Unknown` and nothing is at fault.
    at: Option<std::time::Instant>,
    verdict: packetframe_common::fib::Completeness,
}

fn authority_reading(
    completeness: &Option<std::sync::Arc<packetframe_common::fib::TableCompleteness>>,
) -> Option<AuthorityReading> {
    completeness.as_ref().map(|h| {
        let (report, verdict) = h.latest_verdict();
        AuthorityReading {
            at: report.map(|r| r.at),
            verdict,
        }
    })
}

/// Fold one reading into the run of consecutive at-fault samples,
/// returning the `at` of the FIRST sample in it.
///
/// The whole persistence rule is these few lines, and it is deliberately
/// interval-independent: nothing here knows the checker's 300 s cadence,
/// so changing it (or running a test at millisecond speed) does not
/// change what escalates. Keeping the FIRST sample's identity rather
/// than the latest is what makes the comparison in
/// [`authority_fault_confirmed`] mean "a second distinct sample agreed".
///
/// Any verdict that is not the authority's fault ends the run —
/// including `Stale` and every self-clearing unknown. That is the point:
/// a mismatch, a clean check, then another mismatch is two transients,
/// and only an unbroken run is evidence of something that will not
/// clear itself.
fn track_authority_fault(
    run_since: Option<std::time::Instant>,
    reading: Option<&AuthorityReading>,
) -> Option<std::time::Instant> {
    match reading {
        Some(r) if r.verdict.authority_is_at_fault() => run_since.or(r.at),
        _ => None,
    }
}

/// Whether the authority's fault has now been seen in TWO DISTINCT
/// samples: this reading is at fault, and the run it belongs to started
/// at a different sample.
///
/// Note what this does NOT require: a fixed number of ticks, a minimum
/// elapsed time, or the checker's cadence. Two reports is the property
/// that matters, because the transient this exists to filter — the two
/// counts of ONE report taken a moment apart — cannot survive being
/// measured again.
fn authority_fault_confirmed(
    run_since: Option<std::time::Instant>,
    reading: Option<&AuthorityReading>,
) -> bool {
    reading.is_some_and(|r| {
        r.verdict.authority_is_at_fault()
            && matches!((run_since, r.at), (Some(first), Some(at)) if first != at)
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
                fresh_hold: None,
                rx_kick: Box::new(NoKick),
                kernel_path: Box::new(crate::kernel_path::NoKernelPath),
                kernel_watch: KernelWatch::default(),
                last_steer_audit: None,
                last_null_sample: None,
                last_placement: None,
                drift_scanner: None,
                drift_uncovered: Vec::new(),
                drift_routes: 0,
                drift_result_gen: None,
                drift_pending: false,
                drift_unreadable: None,
                drift_scan_ms: None,
                drift_scope_stale: None,
                pending_drift_scope: None,
                drift_v6: crate::drift::V6DriftState::default(),
                drift_accepts6: std::sync::Arc::default(),
                steer_missing: 0,
                steer_stray: 0,
                steer_audit_error: None,
                authority_fault_since: None,
                preserved: None,
                seeded: None,
                last_drain_took: Duration::ZERO,
                last_dump_took: None,
                v6_gate: false,
                reverify: crate::verify::ReverifySchedule::default(),
                refreshed_verify: None,
                unresolvable_log: UnresolvableLog::default(),
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

    /// Hand over the previous process's preserved route ledger, which the
    /// attach wiring has already tied to the adopted process
    /// ([`crate::ledger_record::LedgerRecord::check_adoptee`]). Must
    /// precede the `Adopted` injection: `start_resync`, which that runs
    /// synchronously, is where it is judged against VPP and seeded.
    pub fn seed_ledger(&self, record: crate::ledger_record::LedgerRecord) {
        self.core.borrow_mut().preserved = Some(record);
    }

    /// Leave the route ledger for the next daemon: the preserving half of
    /// a `--keep-vpp` restart ([`crate::ledger_record`]). Called by the
    /// supervision loop on a preserving exit, after its last tick, and
    /// never on a teardown.
    ///
    /// Refused — returning why, and leaving no record, so the next
    /// adoption takes the dump path — unless the ledger is exactly what
    /// VPP holds and this process has verified it, or is the previous
    /// process's seed not yet touched:
    ///  - converged (`Ready`/`Steered`): every entry acknowledged by this
    ///    VPP, verify passed or held it incomplete;
    ///  - a preserved-ledger adoption still waiting on the source: the
    ///    seed, which the previous process verified, and which nothing
    ///    has changed since (the diff has not run).
    ///
    /// Anything else — a dump-path adoption mid-deferral, a convergence
    /// in flight, a request whose acknowledgement never came — is not a
    /// FIB this process can vouch for. So is one whose summary cannot be
    /// read: the record's "nothing changed since" check needs it.
    pub fn preserve(&self, state: crate::supervisor::State) -> Result<u64, String> {
        use crate::supervisor::State;
        let mut c = self.core.borrow_mut();
        let converged = matches!(state, State::Ready | State::Steered);
        let untouched_seed = c.seeded.is_some() && c.deferred_resync.is_some();
        if !(converged || untouched_seed) {
            return Err(format!(
                "the supervisor is {state:?}, so the ledger is not a verified picture of VPP's FIB"
            ));
        }
        // Converged is not vouched for: a verify re-run that found VPP
        // disagreeing leaves the module in `Ready`/`Steered` with a ledger
        // that verify just disproved. Preserved, it would be seeded at the
        // next start, VPP's per-length counts would still match it, the
        // diff would skip exactly the prefixes VPP has wrong, and a fresh
        // sample could miss them — clearing the first-steer hold with
        // nothing rebuilt (review finding, PR #333). Refused, the next
        // start reads VPP's FIB, and the resync corrects what it holds.
        if c.engine
            .last_verify()
            .is_some_and(crate::verify::VerifyOutcome::restart_worthy)
        {
            return Err(
                "the last verify found VPP disagreeing with the route ledger, so the ledger is \
                 disproved: the next start reads VPP's FIB instead, and its resync corrects \
                 what VPP holds"
                    .into(),
            );
        }
        let Core { engine, store, .. } = &mut *c;
        let interfaces = engine.attached_indices();
        if interfaces.is_empty() {
            return Err("no interfaces are attached".into());
        }
        let (path_sets, entries) = engine.preservable_ledger()?;
        // A transport the last tick dropped is reconnected rather than
        // read as "no summary": one handshake is cheap next to a restart
        // that has to read the whole FIB instead.
        if !engine.api_ready() {
            return Err("VPP's binary API is not answering".into());
        }
        let fingerprint = engine
            .fib_fingerprint()
            .map_err(|e| format!("reading VPP's FIB summary: {e}"))?
            .ok_or("VPP's FIB summary could not be read")?;
        let n = entries.len() as u64;
        store.preserve_ledger(crate::ledger_record::LedgerBody {
            fingerprint,
            interfaces,
            path_sets,
            entries,
        })?;
        Ok(n)
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

    /// Install the kernel rx-mode kick. The attach wiring installs the
    /// ioctl-backed [`AllmultiKick`] on Linux; everything else keeps
    /// [`NoKick`]. See [`RxModeKick`] for why this exists.
    /// Attach the `drift-accept6` handle the module publishes reloads
    /// into. Without one the set is empty: every v6 finding degrades.
    pub fn drift_accepts6(&self, handle: std::sync::Arc<crate::drift::DriftAccepts6>) {
        self.core.borrow_mut().drift_accepts6 = handle;
    }

    /// Install the exemption tripwire. Same wiring rule as the others.
    pub fn drift_watch(&self, w: Box<dyn crate::drift::DriftWatch + Send>) {
        self.core.borrow_mut().drift_scanner = Some(crate::drift::DriftScanner::spawn(
            w,
            crate::drift::Pacing {
                every: DRIFT_SCAN_EVERY,
                settle: DRIFT_SETTLE,
                max_defer: DRIFT_MAX_DEFER,
            },
        ));
    }

    /// Declare that the NIC holds rules INHERITED from a previous
    /// process, so the tripwire is judging a config it cannot assume
    /// matches them.
    ///
    /// The watcher is built from the config on disk, and a restart
    /// that adopts a live VPP re-adopts whatever rules the last
    /// process installed — which the operator may have edited the
    /// config away from in between. An exemption added while the
    /// daemon was down would then suppress a path the inherited
    /// divert rule still sends into VPP (review finding). The first
    /// successful steer reconciles the NIC to the current target and
    /// clears this.
    pub fn note_inherited_steering(&self) {
        self.core.borrow_mut().drift_scope_stale = Some(
            "steering rules were inherited from a previous process and have not been \
             reconciled with the running config yet"
                .into(),
        );
    }

    pub fn rx_mode_kick(&self, k: Box<dyn RxModeKick>) {
        self.core.borrow_mut().rx_kick = k;
    }

    /// Install the kernel-path seam: queue-0 IRQ placement while a
    /// port's keeps pin to queue 0, and the counters status reports.
    /// The attach wiring installs [`crate::kernel_path::LiveKernelPath`];
    /// everything else keeps [`crate::kernel_path::NoKernelPath`].
    pub fn kernel_path(&self, k: Box<dyn crate::kernel_path::KernelPath>) {
        self.core.borrow_mut().kernel_path = k;
    }

    /// Point steering at a new set of ports and rules.
    ///
    /// Records intent only — see [`Steering::retarget`]. The caller must
    /// follow it with the supervisor event that reconciles the NIC, and
    /// the supervision loop is the only caller precisely so that the two
    /// cannot be separated.
    pub fn retarget(&self, targets: Vec<(String, u32, crate::steer::RuleSet)>) {
        self.core.borrow_mut().retarget(targets);
    }

    /// Hand the engine the reloaded `steer-exempt` set — see
    /// [`ConvergenceEngine::unexempted_local`](crate::engine::ConvergenceEngine::unexempted_local).
    pub fn set_steer_exempts(&self, exempts: Vec<packetframe_common::config::Ipv4Prefix>) {
        self.core.borrow_mut().engine.set_steer_exempts(exempts);
    }

    /// The IPv4 unresolvable routes by name, for the refusal that names
    /// them ([`crate::engine::ConvergenceEngine::unresolvable_named`]).
    pub fn unresolvable_named(&self) -> Vec<String> {
        self.core.borrow().engine.unresolvable_named(false)
    }

    /// The kernel-delivered prefixes no `steer-exempt` covers, for the
    /// refusal that names them.
    pub fn unexempted_local(&self) -> Vec<String> {
        self.core
            .borrow()
            .engine
            .unexempted_local()
            .iter()
            .filter_map(|p| match p {
                packetframe_common::fib::IpPrefix::V4 { addr, prefix_len } => {
                    Some(format!("{}/{prefix_len}", std::net::Ipv4Addr::from(*addr)))
                }
                packetframe_common::fib::IpPrefix::V6 { .. } => None,
            })
            .collect()
    }

    /// Hand the exemption tripwire a reloaded exemption set.
    /// Whether the NIC holds any steering rule right now.
    ///
    /// Read by the reconfigure path to decide whether a request that
    /// installs nothing may still commit its drift scope: with no
    /// rules installed there are no old exemptions to describe, so the
    /// staged config IS what a scan should judge.
    pub fn steering_rules_installed(&self) -> bool {
        !self.core.borrow().steering.installed().is_empty()
    }

    /// Adopt the staged scope now — for the path where the request
    /// performs no steering action at all.
    pub fn commit_drift_scope(&self) {
        self.core.borrow_mut().commit_drift_scope();
    }

    pub fn stage_drift_scope(&self, scope: crate::drift::DriftScope) {
        self.core.borrow_mut().stage_drift_scope(scope);
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

    /// A verdict re-run since the last call ([`Observe::poll_reverify`]),
    /// for the loop to record as the latest completed verify. Never an
    /// event: a re-run refreshes what `fib-synced` reports and decides
    /// nothing ([`crate::verify::ReverifySchedule`]).
    pub fn take_refreshed_verify(&self) -> Option<crate::verify::VerifyOutcome> {
        self.core.borrow_mut().refreshed_verify.take()
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
                c.kernel_watch.clear();
            }
            let due = c
                .last_steer_audit
                .is_none_or(|t| now.duration_since(t) >= STEER_AUDIT_EVERY);
            if due && !c.steering.installed().is_empty() {
                c.last_steer_audit = Some(now);
                match c.steering.missing_from_nic() {
                    Ok(audit) => {
                        if !audit.missing.is_empty() && c.steer_missing != audit.missing.len() {
                            // NAMES NO REMEDY. The audit runs in every
                            // state, and the remedy depends on the state:
                            // `reconfigure` reconciles steering only from
                            // `Ready`/`Steered`, so this line promised it
                            // during adopted resyncs and backoffs, where
                            // it answers "not converged" and changes
                            // nothing (observed on the shadow,
                            // 2026-08-12). `steering_health` already
                            // selects the right remedy from the state and
                            // is tested to; a second copy here is a copy
                            // that cannot see what it needs and drifts
                            // from the one that can.
                            tracing::warn!(
                                missing = ?audit.missing,
                                "steering rules this target needs are not in the NIC; \
                                 traffic for them is on the eBPF tier. `packetframe \
                                 status` names the remedy for the current state"
                            );
                        }
                        c.steer_missing = audit.missing.len();
                        if !audit.stray.is_empty() && c.steer_stray != audit.stray.len() {
                            // Same reason as the missing arm above, and
                            // the stray remedy is the one that must not
                            // be waited on — the health line says so,
                            // with the by-hand `ethtool` removal for
                            // where reconfigure will not run.
                            tracing::warn!(
                                stray = ?audit.stray,
                                "rules are still steering a port this config asks to leave \
                                 unsteered; `packetframe status` names the remedy for the \
                                 current state"
                            );
                        }
                        c.steer_stray = audit.stray.len();
                        c.kernel_watch.keeps_observed = audit.keeps_observed;
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
            // The kernel path every port with rules in the ledger hands
            // its exempt traffic to: queue-0 and total receive, and the
            // PF's drops, every `kernel_path::SAMPLE_EVERY` on the real
            // clock — a host read, like the audit above, not a
            // supervision deadline.
            let mut ports: Vec<String> =
                c.steering.installed().into_iter().map(|(i, _)| i).collect();
            ports.sort();
            ports.dedup();
            if !ports.is_empty() {
                let keeps = c.steering.keep_forms();
                let core = &mut *c;
                core.kernel_watch
                    .tick(now, &ports, core.kernel_path.as_mut(), &keeps);
            }
        }
        {
            let mut c = self.core.borrow_mut();
            let now = std::time::Instant::now();
            let due = c
                .last_null_sample
                .is_none_or(|t| now.duration_since(t) >= ERROR_COUNTERS_EVERY);
            if due && c.engine.is_connected() {
                c.last_null_sample = Some(now);
                c.engine.sample_error_counters();
            }
            // A COMPLETED result, if the scanner finished a pass
            // since the last look. Never a scan performed here: this
            // is the thread that answers pings, stops and steering
            // requests, and a 1.05M-prefix dump on it would delay all
            // three (review finding).
            // A COMPLETED result, and only one scanned under the
            // CURRENT scope: a pass already in flight when a
            // reconfigure landed is answering about the exemptions
            // that were in force when it started, and publishing that
            // as the new config's verdict is how a newly blackholed
            // path would read as covered (review finding).
            let report = c.drift_scanner.as_ref().and_then(|s| {
                let current = s.generation();
                s.take_result().map(|r| (r, current))
            });
            if let Some((r, _)) = &report {
                c.drift_scan_ms = Some(r.took.as_millis() as u64);
            }
            let fresh = report.and_then(|(r, current)| {
                if r.generation == current {
                    return Some(r.result);
                }
                tracing::debug!(
                    scanned_under = r.generation,
                    current,
                    "discarding a drift result about a superseded scope"
                );
                None
            });
            // Whether a verdict about the CURRENT config exists at
            // all. Until one does — the first pass after attach, or
            // after a scope change — the tripwire has nothing to say
            // and must not say `0`.
            if let Some(s) = c.drift_scanner.as_ref() {
                let current = s.generation();
                if fresh.is_some() {
                    c.drift_result_gen = Some(current);
                }
                // PENDING, not "unscanned": a deployment with no
                // tripwire installed at all (non-Linux, or a config
                // the loader gave no watcher) is not waiting for
                // anything, and degrading it would report a missing
                // feature as a broken one.
                c.drift_pending = c.drift_result_gen != Some(current);
            }
            if let Some(result) = fresh {
                match result {
                    Ok(found) => {
                        if !found.lines.is_empty() && c.drift_uncovered != found.lines {
                            tracing::warn!(
                                paths = ?found,
                                "kernel path(s) VPP cannot take are not covered by any \
                                 `steer-exempt`; steered traffic for them dies at VPP's \
                                 default route instead of falling back to the kernel. Add \
                                 a steer-exempt for each, or stop steering the port"
                            );
                        }
                        c.drift_routes = found.routes;
                        c.drift_uncovered = found.lines;
                        c.drift_unreadable = None;
                        // Settled HERE, against the ledger: the scan
                        // thread cannot read the engine, and whether VPP
                        // holds a prefix is the engine's to say.
                        let core = &mut *c;
                        let engine = &core.engine;
                        let accepts = core.drift_accepts6.get();
                        if let Some(lines) =
                            core.drift_v6
                                .absorb(found.v6, |p| engine.holds_v6(p), &accepts)
                        {
                            tracing::warn!(
                                paths = ?lines,
                                "IPv6 kernel path(s) VPP cannot take while a port diverts \
                                 IPv6; diverted traffic for them dies in VPP instead of \
                                 reaching the kernel path. No IPv6 exemption exists: fix the \
                                 feed if VPP should carry the route, or keep the traffic \
                                 with `steer-keep6`, or stop diverting the port, or accept \
                                 the risk with `drift-accept6`"
                            );
                        }
                    }
                    // The previous findings stand — an unreadable
                    // kernel is not evidence the routes went away —
                    // but the failure is published, so a scan that
                    // never succeeds cannot pass for a quiet one.
                    // Both families: the v6 half never ran.
                    Err(e) => {
                        tracing::debug!(error = %e, "route-drift scan failed");
                        c.drift_v6.scan_failed(&e);
                        c.drift_unreadable = Some(e);
                    }
                }
            }
        }
        let c = self.core.borrow();
        // ONE reading, used for both the verdict and the question of
        // whether it has been seen before: asking twice could pair a
        // verdict from one sample with the identity of the next.
        let reading = authority_reading(&c.completeness);
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
            steer_hold: c.steer_hold(),
            steer_configured_ports: c.steering.configured_ports(),
            steer_v6_divert: v6_divert_summary(&c.steering.installed_plan()),
            steer_v6_only: {
                let plan = c.steering.installed_plan();
                !v6_divert_summary(&plan).is_empty() && !installs_v4_diversion(&plan)
            },
            handback: c.engine.handback_status(),
            icmp6_source: c.engine.icmp6_source(),
            resync_deferred: c
                .deferred_resync
                .map(|d| (c.source.route_count(), d.floor())),
            // `want` is the authority's own count so the status row can
            // say how far along the dump is; 0 until its first report,
            // which the row words for separately.
            fresh_hold: c.fresh_hold.as_ref().map(|_| {
                (
                    c.source.route_count(),
                    c.completeness
                        .as_ref()
                        .and_then(|h| h.latest_verdict().0)
                        .map_or(0, |r| r.authority_routes),
                )
            }),
            steer_missing: c.steer_missing,
            steer_stray: c.steer_stray,
            steer_audit_error: c.steer_audit_error.clone(),
            shadowed_routes: c.engine.shadowed_routes(),
            kernel_delivered_routes: c.engine.kernel_delivered_routes(),
            unresolvable_named: c.engine.unresolvable_named(false),
            unresolvable_named_v6: if c.engine.counts().v6.is_some() {
                c.engine.unresolvable_named(true)
            } else {
                Vec::new()
            },
            null_drops: c.engine.null_drops(),
            neighbour_counters: c.engine.neighbour_counters(),
            kernel_path: c
                .kernel_watch
                .report(&c.steering.keep_forms(), &c.kernel_path.queue0_irqs()),
            neighbours_unplaced: c
                .engine
                .unplaced_neighbours()
                .into_iter()
                .map(|(nh, dev, port)| match port {
                    None => format!("{nh} on {dev}"),
                    Some(p) => format!("{nh} on {dev} (behind {p}, which has no subif for it)"),
                })
                .collect(),
            neighbour_moves: c.engine.placement_moves(),
            neighbours_flooded: c.engine.flooding_neighbours() as u64,
            fdb_unreadable: c.engine.fdb_unreadable(),
            drift_uncovered: c.drift_uncovered.clone(),
            drift_routes: c.drift_routes,
            drift_pending: c.drift_pending,
            drift_unreadable: c.drift_unreadable.clone(),
            drift_scan_ms: c.drift_scan_ms,
            drift_scope_stale: c.drift_scope_stale.clone(),
            drift_v6: c.drift_v6.clone(),
            preserved_fib: c.seeded.is_some(),
            authority: authority_posture(
                c.completeness.is_some(),
                c.deferred_resync
                    .as_ref()
                    .and_then(DeferredResync::feed)
                    .is_some_and(|f| f.demoted),
                // The steered stages consult the authority; the diff stage
                // does not.
                c.deferred_resync
                    .as_ref()
                    .and_then(DeferredResync::feed)
                    .is_some(),
                // The SAME recompute the release path applies, not a
                // re-derivation of it: the health line and the gate must
                // not be able to disagree about whether the authority is
                // currently permitting.
                authority_current(&c.completeness, c.source.route_count()),
                reading.as_ref().map(|r| r.verdict.clone()),
                // Read, never advanced, from the run the tick path
                // keeps. A fault this reading has already contributed to
                // that run confirms itself only if the run started at a
                // DIFFERENT sample.
                authority_fault_confirmed(c.authority_fault_since, reading.as_ref()),
            ),
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

/// How often to take one error-counter read (null-drop, glean and
/// ARP-reply gauges).
///
/// Each tick is ONE `cli_inband` round trip on the API socket, which
/// shares VPP's main thread with the route batches, alternating between
/// `show errors` and `show ip neighbor-stats`
/// ([`crate::engine::ConvergenceEngine::sample_error_counters`]). So a
/// tick never blocks this thread longer than the single null-drop read
/// did, and at 30 s each read keeps the 60 s cadence the null-drop
/// gauge always had — invisible next to the liveness ping while still
/// giving Prometheus a usable rate.
const ERROR_COUNTERS_EVERY: Duration = Duration::from_secs(30);

/// How often the bridge-FDB tripwire scans for hosts behind a port
/// other than their `local-route` declaration. One netlink dump; a
/// moved host is a provisioning-scale event, so a minute of latency
/// on the tripwire costs nothing.
/// How often bridge-neighbour placement is checked against the FDB. Cheap
/// on this thread — the kernel topology serves a snapshot its own thread
/// keeps fresh (`topology::FDB_REFRESH`) — so the move-detection window
/// is the two intervals together, a few seconds.
const PLACEMENT_EVERY: Duration = Duration::from_secs(2);

/// How often to check the kernel's routes against the exemptions.
///
/// One route dump per minute. The sets this watches are edited by
/// routing daemons, not by hand — the reference primary's tunnel host
/// routes come from bird — so the interesting change arrives without
/// anyone touching packetframe, which is the whole argument for
/// scanning on a clock rather than at config load.
const DRIFT_SCAN_EVERY: Duration = Duration::from_secs(60);

/// How long links must have been quiet before a drift scan starts — see
/// [`crate::drift::Pacing`]. A judgement, not a measurement: one scan
/// interval, and longer than the ~40 s the 2026-10-07 bridge toggle held
/// the box. Routes a daemon reinstalls once sessions come back up can
/// still be churning after it; the scan abandons itself only for a link
/// change, so it can read through that.
const DRIFT_SETTLE: Duration = Duration::from_secs(60);

/// The longest a due drift scan waits for links to settle before it runs
/// regardless: under a link that never stops flapping the tripwire still
/// looks every five minutes rather than never.
const DRIFT_MAX_DEFER: Duration = Duration::from_secs(300);

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
    /// Configured, usable, and currently permitting.
    Attesting,
    /// Configured, but this deferral saw the feed flap and has not yet
    /// seen the current epoch reconciled, so the authority's word
    /// cannot be trusted to describe the current stream.
    DemotedByFlap,
    /// Configured, usable, currently saying NO — **and the running
    /// deferral is one that asks.** Its report does not describe the
    /// mirror as it is now, so `authority_current` vetoes release
    /// regardless of floor, liveness or quiescence.
    ///
    /// Added because the posture could not express it, and that gap had
    /// a measured cost. On the shadow (2026-08-12) a box whose local
    /// bird holds 13 routes against a 1.3M-route mirror sat deferred
    /// for 23 hours reading `Attesting`, while the health line told the
    /// operator to wait for the source to go quiet — the one thing that
    /// could never release it. A veto does not clear on its own: it
    /// clears when the authority's report agrees with the mirror, or
    /// not at all.
    ///
    /// Scoped to the deferral by `authority_posture`, because only the
    /// steered stages consult the authority; the diff stage
    /// releases on floor-and-quiet and a disagreeing authority there is
    /// not blocking anything.
    ///
    /// And scoped to the PERSISTENT verdict, `AuthorityMismatch`.
    /// `assess()` already draws that line — "short of the authority is a
    /// mirror still loading — wait; larger than the authority cannot be
    /// a loading state at all" — and the first version of this variant
    /// flattened all four non-permitting verdicts into it, so a box
    /// whose first integrity check had simply not run yet was told that
    /// waiting would not help. That fires at every startup on a box
    /// with an authority (review finding).
    ///
    /// And scoped to a fault seen in TWO DISTINCT SAMPLES. The verdict
    /// alone cannot carry that: a report's two counts are taken a moment
    /// apart, so a bulk withdrawal in that moment manufactures one
    /// `AuthorityMismatch` out of a healthy pair. A first such sample
    /// reports `AwaitingAuthority` — release is blocked either way — and
    /// this variant is reached when the next report says the same thing.
    /// See [`authority_fault_confirmed`].
    Vetoing,
    /// Configured, currently not permitting, for a reason that clears
    /// itself: no report yet (`Unknown`), one that aged out (`Stale`),
    /// a mirror still short of the authority (`Incomplete`), or a
    /// mismatch that only ONE sample has reported and no second has
    /// confirmed. The integrity checker publishes a fresh report every
    /// interval and the deferral releases on its own.
    ///
    /// Distinct from `Vetoing` because the operator action differs
    /// completely — wait, versus go and find out which bird `birdc` is
    /// talking to — and distinct from `Attesting` because release IS
    /// currently blocked, which a line saying "attesting" would deny.
    AwaitingAuthority,
}

/// `"<port> vlan <ids>"` for every port whose plan diverts
/// IPv6, in plan order — the phrase the steering row prints.
pub fn v6_divert_summary(plans: &[(String, u32, crate::steer::RuleSet)]) -> Vec<String> {
    plans
        .iter()
        .filter_map(|(iface, _, plan)| {
            let vlans = plan.v6_divert_vlans();
            (!vlans.is_empty()).then(|| {
                format!(
                    "{iface} {}",
                    crate::steer::V6Steering::describe_vlans(&vlans)
                )
            })
        })
        .collect()
}

/// Whether any installed plan diverts IPv4 — the other half of what the
/// steering row claims, read from the same installed rules.
pub fn installs_v4_diversion(plans: &[(String, u32, crate::steer::RuleSet)]) -> bool {
    plans.iter().any(|(_, _, plan)| {
        plan.rules.iter().any(|r| {
            r.action == crate::steer::RuleAction::Divert
                && matches!(r.shape, crate::steer::RuleMatch::V4 { .. })
        })
    })
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
    /// Where the INSTALLED steering diverts IPv6, one
    /// `"<port> vlan <ids>"` / `"<port> untagged"` per port — read from
    /// [`Steering::installed_plan`], so it names what reached the NIC,
    /// not what the config wants. Empty when no v6 is diverted.
    pub steer_v6_divert: Vec<String>,
    /// The installed plan diverts IPv6 and no IPv4 at all (a v6-only
    /// allowlist beside `v6-divert`), so the steering row must not
    /// claim allowlisted IPv4 is diverted. See [`installs_v4_diversion`].
    pub steer_v6_only: bool,
    /// The IPv6 hand-back path, while it is wanted or built
    /// ([`crate::handback`]).
    pub handback: Option<crate::handback::HandbackStatus>,
    /// The global address VPP sources ICMPv6 errors from, as read back
    /// on its loopback ([`ConvergenceEngine::icmp6_source`]). `None`
    /// while `steer_v6_divert` is non-empty means diverted IPv6 gets no
    /// Time Exceeded or Packet Too Big from VPP at all.
    pub icmp6_source: Option<std::net::Ipv6Addr>,
    /// Changes the source is holding that the engine has not pulled yet.
    ///
    /// Distinct from `pending_ops`, which is what the engine has pulled
    /// and not yet sent. Both can be non-zero at once and they fail
    /// differently: a backlog here means the engine is not draining, a
    /// backlog there means VPP is not accepting.
    pub source_backlog: u64,
    /// Why a first steer would be held right now — the same
    /// [`Core::steer_hold`] the steer and its retry refuse on, so the
    /// status rows say what a held steer waits for without re-deriving
    /// it. `None` for a target that diverts nothing.
    pub steer_hold: Option<SteerHold>,
    /// `Some((have, want))` while an adopted resync is deferred for a
    /// still-loading route source. See `Core::deferred_resync`.
    pub resync_deferred: Option<(u64, u64)>,
    /// `Some((have, want))` while a fresh convergence holds verify for
    /// the completeness authority. See [`FreshHold`] and the status
    /// row's doc in `status.rs`.
    pub fresh_hold: Option<(u64, u64)>,
    /// What the authority can say right now — the deferral health text
    /// depends on it: an attested deployment's below-floor wait
    /// resolves through the authority and telling it to "add bird"
    /// recommends the thing it already has, while a demoted one is
    /// waiting on something else entirely.
    pub authority: AuthorityPosture,
    /// The FIB being converged is the previous process's, adopted from
    /// its preserved route ledger and not yet verified by this one. See
    /// `Core::seeded` and `StatusSnapshot::preserved_fib`.
    pub preserved_fib: bool,
    /// How many rules the ledger names that the NIC no longer holds, as
    /// of the last audit. See [`STEER_AUDIT_EVERY`].
    pub steer_missing: usize,
    /// Rules still steering a port the config leaves unsteered. See
    /// [`SteeringAudit::stray`].
    pub steer_stray: usize,
    /// Why the last steering audit could not read the NIC, if so.
    pub steer_audit_error: Option<String>,
    /// Mirror prefixes a `local-route` is currently suppressing. See
    /// [`crate::engine::ConvergenceEngine::shadowed_routes`].
    pub shadowed_routes: u64,
    /// [`crate::engine::ConvergenceEngine::kernel_delivered_routes`].
    pub kernel_delivered_routes: u64,
    /// [`crate::engine::ConvergenceEngine::unresolvable_named`], IPv4.
    pub unresolvable_named: Vec<String>,
    /// The same for IPv6; empty under `v6 off`.
    pub unresolvable_named_v6: Vec<String>,
    /// Cumulative null-node drops as last sampled, absent until read.
    pub null_drops: Option<u64>,
    /// VPP's glean and ARP-reply transmit counters as last sampled,
    /// absent until read. See [`crate::engine::NeighbourCounters`].
    pub neighbour_counters: Option<crate::engine::NeighbourCounters>,
    /// The kernel path each port with rules in the ledger hands its
    /// exempt traffic to: keep form, queue-0 IRQ placement, counters.
    /// See [`crate::kernel_path`].
    pub kernel_path: Vec<crate::kernel_path::PortReport>,
    /// Bridge neighbours the FDB has never placed behind a member port,
    /// `"<nexthop> on <device>"` each: their routes are unresolvable.
    pub neighbours_unplaced: Vec<String>,
    /// Neighbours moved behind another bridge port since start.
    pub neighbour_moves: u64,
    /// Bridged neighbours flooding for want of an FDB placement.
    pub neighbours_flooded: u64,
    /// Why the bridge FDB cannot be read, if it cannot: placements hold at
    /// the last good read, and a move made meanwhile goes unfollowed.
    pub fdb_unreadable: Option<String>,
    /// Kernel paths VPP cannot take that no `steer-exempt` covers.
    pub drift_uncovered: Vec<String>,
    /// How many routes those findings stand for — the gauge's value.
    pub drift_routes: usize,
    /// A scan is outstanding for the CURRENT configuration — the
    /// tripwire has no verdict yet, which is not the same as a clean
    /// one. False when no tripwire is installed.
    pub drift_pending: bool,
    /// Why the last drift scan could not read the kernel, if so.
    pub drift_unreadable: Option<String>,
    /// How long the latest finished drift scan took, ms; `None` until one
    /// finishes.
    pub drift_scan_ms: Option<u64>,
    /// Why the scan cannot say which exemptions the NIC holds, if so.
    pub drift_scope_stale: Option<String>,
    /// The IPv6 half of the tripwire.
    pub drift_v6: crate::drift::V6DriftState,
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
        // Both described the dead instance's FIB.
        self.seeded = None;
        self.preserved = None;
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
        let plans = self.steering.installed_plan();
        let r = self.store.steering_changed(&rules, &plans);
        let _ = self.note_persist(r);
        self.place_queue0_irqs();
    }

    /// Bring the queue-0 IRQ placements in line with the keeps the
    /// ledger now holds ([`crate::kernel_path`]): placed for every port
    /// whose keeps this process installed in the queue-0 form, left
    /// alone for ports whose keeps it has not re-installed (inherited —
    /// their form is unknown until the next steer), restored for every
    /// other. Here, on every steer and unsteer, because those are the
    /// only moments the answer changes — and the unsteer of a teardown
    /// is what takes a placement back off.
    fn place_queue0_irqs(&mut self) {
        let ports = self.steering.keep_forms();
        let want: Vec<String> = ports
            .iter()
            .filter(|p| {
                p.verdict
                    .as_ref()
                    .is_some_and(|v| v.form == crate::ntuple::KeepForm::Queue0)
            })
            .map(|p| p.iface.clone())
            .collect();
        let hold: Vec<String> = ports
            .iter()
            .filter(|p| p.verdict.is_none())
            .map(|p| p.iface.clone())
            .collect();
        self.kernel_path.reconcile_queue0(&want, &hold);
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
    fn retarget(&mut self, targets: Vec<(String, u32, crate::steer::RuleSet)>) {
        // The hand-back path is wanted exactly while the target diverts
        // IPv6; a new want is built by the steer this retarget precedes.
        self.engine
            .set_handback_wanted(crate::handback::plans_divert_v6(&targets));
        self.steering.retarget(targets);
        self.last_steer_audit = None;
    }

    /// Service the IPv6 hand-back path and hand its readiness to the
    /// steering as the gate on the v6 half.
    ///
    /// With `resteer`, a gate that CHANGED under installed rules asks the
    /// supervisor for a reconcile (`SteerRequested`, which from `Steered`
    /// re-steers without moving the state): ready, the v6 half goes in;
    /// broken, it comes out and IPv4 stays. Only where rules are in the
    /// NIC and the target diverts v6 — never a first steer, which stays
    /// the operator's, and a v6-only port waiting on the path is retried
    /// by the refused steer's own paced retry. The steer path passes
    /// `false`: the steer it precedes already reads the new gate.
    fn service_handback(&mut self, sync: bool, resteer: bool) -> Result<(), EngineError> {
        let served = self.engine.service_handback(sync);
        self.apply_v6_gate(resteer);
        served
    }

    /// Hand the path's readiness to the steering; see
    /// [`Self::service_handback`] for `resteer`.
    fn apply_v6_gate(&mut self, resteer: bool) {
        let ready = self.engine.handback_ready();
        // Held back: whatever v6 rule the NIC still holds comes out now,
        // whether or not this is a transition — inherited rules meet a gate
        // that STARTS closed, and nothing else would reach them before the
        // adoption's steer. IPv4 is untouched.
        if !ready {
            match self.steering.drop_held_v6() {
                Ok(0) => {}
                Ok(n) => {
                    tracing::warn!(
                        rules = n,
                        "IPv6 steering rules were in the NIC while the hand-back path is not \
                         ready; removed them (IPv4 steering untouched)"
                    );
                    self.record_steering();
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "IPv6 steering rules are in the NIC while the hand-back path is not \
                         ready, and could not all be removed"
                    );
                    self.record_steering();
                }
            }
        }
        if ready != self.v6_gate {
            self.v6_gate = ready;
            self.steering.set_v6_ready(ready);
            tracing::info!(
                ready,
                "IPv6 hand-back path {}; the IPv6 half of steering is {}",
                if ready { "ready" } else { "not ready" },
                if ready { "permitted" } else { "held back" }
            );
            let ev = if ready {
                event_log::Event::info(crate::MODULE_NAME, event_kind::HANDBACK_READY)
                    .detail("IPv6 hand-back path ready; the IPv6 half of steering is permitted")
            } else {
                event_log::Event::warn(crate::MODULE_NAME, event_kind::HANDBACK_HELD_BACK)
                    .detail("IPv6 hand-back path not ready; the IPv6 half of steering is held back")
            };
            ev.emit();
            if resteer
                && self.engine.steered()
                && self.engine.handback_wanted()
                && !self.steering.installed().is_empty()
            {
                self.pending.push(Event::SteerRequested);
            }
        }
    }

    /// Bring the hand-back path up to date and set the v6 gate from it,
    /// immediately before a steer — the chokepoint every steer passes, so
    /// no v6 diversion is ever installed ahead of the /128s that hand the
    /// router's own traffic back. A failure here never stops the steer:
    /// IPv4 does not wait on the path, the gate stays as it was, and a
    /// lost socket surfaces on the next drain.
    fn gate_v6_for_steer(&mut self) {
        if let Err(e) = self.service_handback(true, false) {
            tracing::warn!(
                error = %e,
                "the IPv6 hand-back path could not be serviced before the steer"
            );
        }
    }

    /// Hand the exemption tripwire the reloaded `steer-exempt` set.
    ///
    /// Called from the same place as `retarget` and for the same
    /// reason the audit is invalidated there: the scan's verdict was
    /// computed against the OLD config the moment this one is
    /// accepted. Also clears the scan clock, so the next status poll
    /// re-reads rather than serving a verdict about a config that no
    /// longer exists — the operator who just added the exemption the
    /// health line asked for should not have to wait out a minute of
    /// it still complaining.
    fn stage_drift_scope(&mut self, scope: crate::drift::DriftScope) {
        if self.drift_scanner.is_some() {
            self.pending_drift_scope = Some(scope);
        }
    }

    /// A steering change failed. If it left rules installed while a
    /// new scope was waiting, the NIC now holds some of one config
    /// and some of another and the scan must say so — see
    /// [`Self::drift_scope_stale`].
    fn note_partial_steer(&mut self) {
        if self.pending_drift_scope.is_some() && !self.steering.installed().is_empty() {
            self.drift_scope_stale = Some(
                "a steering change failed partway and left rules installed, so the \
                 exemptions the NIC holds are neither the old set nor the new one"
                    .into(),
            );
        }
    }

    /// Adopt the staged scope, if any — called where a steering action
    /// has just succeeded, so the watcher only ever describes rules
    /// the NIC took.
    fn commit_drift_scope(&mut self) {
        // A successful steering action means the NIC now holds what
        // the current target asks for — including, on the adoption
        // path, rules that were INHERITED and have just been
        // reconciled. That settles the staleness whether or not a
        // scope was staged: startup adoption stages none, so gating
        // this on `pending` left every adopted restart permanently
        // Degraded with the gauge absent until an unrelated
        // reconfigure happened along (review finding).
        self.drift_scope_stale = None;
        let Some(scope) = self.pending_drift_scope.take() else {
            return;
        };
        if let Some(s) = self.drift_scanner.as_ref() {
            let scans_v6 = scope.scans_v6;
            s.set_scope(scope);
            // The findings described the OLD config, so they go —
            // the scanner republishes against the new one on its next
            // pass. The READ failure does not go with them: whether
            // the kernel answers has nothing to do with which config
            // we are judging. (A v6 half the new scope switches off goes
            // entirely — see `V6DriftState::scope_committed`.)
            self.drift_uncovered.clear();
            self.drift_routes = 0;
            self.drift_v6.scope_committed(scans_v6);
        }
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

    /// How far VPP is behind the route mirror, or `None` when it has
    /// caught up: the route work still owed to it — changes the source
    /// holds plus ops the engine has pulled and not sent — is within
    /// [`caught_up_allowance`], and the last attempt to apply updates
    /// landed.
    ///
    /// The thing neither table gate can see. `Drain::Idle` is the
    /// ENGINE's pending map going empty, which is weaker than it looks:
    /// `drain_batch` pulls at most `DELTA_BATCH` and sends at most
    /// `DRAIN_BATCH`, and the two are the same number, so one tick can
    /// pull 4096, send all 4096, and report idle with the feed still
    /// holding the rest of a burst. A reload is hundreds of thousands.
    /// The ledger has not classified those changes, so nothing is
    /// `installing`; completeness compares the authority against the
    /// MIRROR, which the tee already updated, so it reads converged.
    /// Everything reads healthy while VPP is hundreds of thousands of
    /// changes behind, and steering there blackholes every prefix in the
    /// gap — `RouteSource::backlog`'s own doc calls it "an unexplained
    /// gap between what bird advertises and what VPP holds" (review
    /// finding, PR #160). Only the retry asked this until 2026-10-07,
    /// when a lever move was admitted with VPP ~430k IPv4 routes behind a
    /// mirror the authority had already attested.
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
    /// Shared by the first-steer hold ([`Self::steer_hold`]) and the
    /// verify re-run's quiet moment (`Observe::poll_reverify`), so "VPP
    /// has caught up" means one thing on both.
    ///
    /// The allowance is for ROUTE work only. A neighbour change still at
    /// the source must be zero: it moves the adjacency of every route
    /// through that next hop, and verify cannot see a stale adjacency —
    /// it checks a probed route has paths on owned interfaces, not where
    /// they lead (review finding, PR #333).
    fn behind(&self) -> Option<Behind> {
        let neighbours = self.source.neighbour_backlog();
        let backlog = self.source.backlog().saturating_sub(neighbours);
        let pending = self.engine.pending().len() as u64;
        let allowance = caught_up_allowance(self.source.route_count());
        let failing = self.last_drain_error.is_some();
        (failing || neighbours > 0 || backlog.saturating_add(pending) > allowance).then_some(
            Behind {
                backlog,
                neighbours,
                pending,
                allowance,
                failing,
            },
        )
    }

    /// Why a first steer must wait right now, or `None` when nothing here
    /// holds it.
    ///
    /// THE first-steer hold, one accessor for its three readers:
    /// [`Effects::steer`], which refuses on it; [`Observe::steer_permitted`],
    /// which decides whether re-attempting a refused steer is worth
    /// anything; and the status rows, which say what a held steer is
    /// waiting for (`RuntimeStatus::steer_hold`). A retry keyed to a
    /// different question than the refusal either never stops asking or
    /// never asks again, and a status row that re-derived it would be the
    /// "classification re-derived by the surface that reports it" defect.
    ///
    /// It completes a chain the other gates start. Completeness says the
    /// mirror holds what the authority holds; [`Self::behind`] says VPP
    /// holds what the mirror holds; and [`crate::verify::unvouched`] says
    /// a verify has looked at a fair sample of what VPP holds — the
    /// standard probe count, drawn from a table not materially smaller
    /// than the one being steered. On 2026-10-07 the first link held and
    /// the other two did not: a verify of ONE probe against a one-route
    /// table vouched for a lever move made over ~666k installed routes,
    /// with ~430k more still on their way.
    ///
    /// It judges a steer that would put NEW traffic onto VPP
    /// ([`Self::expands_diversion`]): the first steer, and equally a
    /// reconcile that adds a port, a prefix or a direction to ports
    /// already steered — the canary ladder's second rung during a reload
    /// diverts into the same behind-and-unverified VPP the first rung
    /// would have. A reconcile that diverts the same or less is not
    /// judged, because refusing it would leave the previous rules
    /// installed — including ones the operator just asked to remove.
    ///
    /// Carries the empty-target exception itself, next to the gate it
    /// exempts, as `steer_verdict` and `fib_fit_to_steer` do: a target
    /// with no port only removes rules, and a `steer off` must never wait
    /// on VPP or on a verify.
    fn steer_hold(&self) -> Option<SteerHold> {
        if !self.steer_diverts_traffic() || !self.expands_diversion() {
            return None;
        }
        let behind = self.behind();
        let unvouched =
            crate::verify::unvouched(self.engine.last_verify(), self.engine.counts().installed);
        (behind.is_some() || unvouched.is_some()).then_some(SteerHold { behind, unvouched })
    }

    /// Whether steering the current target would divert traffic onto VPP
    /// that the rules installed now do not.
    ///
    /// With nothing installed every diversion is new: the first steer.
    /// With rules installed it is [`crate::steer::adds_diversion`] over
    /// the target and the plan the rules were installed under — the NIC
    /// ledger, not the supervisor's `steered`, which reaches this core only
    /// as a copy synced after each pass. Rules in the NIC with NO recorded
    /// plan (a state file from before plans were kept, or a first steer
    /// whose rollback could not delete) cannot be compared, so they are
    /// read as adding: holding is the direction that cannot divert traffic
    /// into a VPP that is behind.
    fn expands_diversion(&self) -> bool {
        if self.steering.installed().is_empty() {
            return true;
        }
        let installed = self.steering.installed_plan();
        installed.is_empty()
            || crate::steer::adds_diversion(&self.steering.target_plan(), &installed)
    }

    /// Write the named unresolvable routes to the event log when the set
    /// has changed ([`UnresolvableLog`]), and to the journal alongside.
    fn log_unresolvable(&mut self, now: std::time::Instant) {
        let v4 = self.engine.unresolvable_named(false);
        let v6 = if self.engine.counts().v6.is_some() {
            self.engine.unresolvable_named(true)
        } else {
            Vec::new()
        };
        if !self.unresolvable_log.due(now, &v4, &v6) {
            return;
        }
        if v4.is_empty() && v6.is_empty() {
            tracing::info!("no route is unresolvable any more");
            event_log::Event::info(crate::MODULE_NAME, event_kind::UNRESOLVABLE_ROUTES)
                .detail("none")
                .emit();
            return;
        }
        tracing::warn!(
            ipv4 = ?v4,
            ipv6 = ?v6,
            "unresolvable routes: VPP holds no path for these, so they are missing from its FIB"
        );
        event_log::Event::warn(crate::MODULE_NAME, event_kind::UNRESOLVABLE_ROUTES)
            .field("ipv4", v4.join("; "))
            .field("ipv6", v6.join("; "))
            .emit();
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

    /// One paced look at whether the fallback tier is loaded and quiet
    /// enough for a STEERED adopted stage to proceed — the release the
    /// pre-dump stage and the preserved-ledger diff share. `spoiled`
    /// stretches the quiet it needs (see `spoiled_backoff`).
    ///
    /// Three ways the fallback proves itself ready, because the floor
    /// alone cannot: capacity is an upper sizing bound, so a real table
    /// below capacity/16 would defer forever on it (review finding).
    ///  - the coupled floor+quiescence release, for tables within 16x of
    ///    their sizing (the fleet);
    ///  - the completeness authority, where a bird exists — the exact
    ///    signal, and the same one `Effects::steer` gates on.
    ///
    /// TWO releases, deliberately not three: a below-floor table with no
    /// authority defers forever, visibly, because nothing honest can say
    /// it is complete — see FALLBACK_FLOOR_DIVISOR for the contract and
    /// for what happened to the heuristic that used to guess.
    fn read_fallback(
        &mut self,
        now: std::time::Instant,
        feed: &mut FeedGate,
        have: u64,
        seq: u64,
        pulses: u64,
        spoiled: u32,
    ) -> FallbackReading {
        // ONE observation for both — see `FeedLiveness`. Read
        // separately, `live` could come from after a raise and the epoch
        // from before its increment, and the next tick's higher epoch
        // reads as a flap on what was an ordinary first raise (review
        // finding).
        let liveness = self.feed_session.as_ref().map(|f| f.liveness());
        let live = liveness.is_some_and(|l| l.up);
        // Rate scaled to the mirror as observed — never to capacity,
        // which is a ceiling, not a table. The floor door's quiet
        // requirement depends on whether anyone can attest completion:
        // with no authority, quiet must at least match the protocol's own
        // initiation-complete standard — see UNATTESTED_QUIET_FOR.
        // The attested fast path holds only while the session has NOT
        // flapped under this deferral: a reconnect reopens the stream
        // epoch, and a cached report cannot attest that routes belong to
        // the current one — so a flapped deferral takes the full
        // unattested posture UNTIL A REPORT NEWER THAN THE GC HAS RUN
        // (see `demoted`; latching it forever turned an ordinary session
        // bounce into a deferral that could never release). The fleet's
        // steady 40 s release never flaps and never pays this at all.
        let current_epoch = liveness.map(|l| l.epoch);
        if live && feed.epoch.is_none() {
            feed.epoch = current_epoch;
        }
        if matches!((feed.epoch, current_epoch), (Some(e), Some(c_)) if c_ != e) {
            feed.demoted = true;
        }
        // Only the GC lifts it. A completeness report published after the
        // flap is NOT evidence the mirror is this session's: the checker
        // compares counts, and a reannouncement still carrying the
        // previous session's unseen routes keeps the count aligned — so a
        // positive post-flap report can sit over a half-current mirror,
        // and if the reannouncement trickles below the attested quiet
        // rate the gate would release and diff against it (review
        // finding, refuting the timestamp test that stood here).
        // `InitiationComplete`'s GC is the one event that destroys
        // prior-session state, and `reconciled` is stamped for the epoch
        // it ran in.
        if feed.demoted && liveness.is_some_and(|l| l.reconciled) {
            feed.epoch = current_epoch;
            feed.demoted = false;
        }
        // Consequence, accepted deliberately: on a feed whose churn never
        // yields the initiation-complete silence, a flap mid-deferral
        // holds the deferral in the unattested posture indefinitely. That
        // is the safe direction and a visible one — VPP keeps forwarding
        // the FIB it was adopted with, health reports the deferral — and
        // it is the same bargain FALLBACK_FLOOR_DIVISOR already makes:
        // refuse visibly rather than release on evidence that does not
        // mean what it appears to.
        let flapped = feed.demoted;
        let attested = self.completeness.is_some() && !flapped;
        let view = feed.gate.observe(
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
            spoiled_backoff(
                if attested {
                    SOURCE_QUIET_FOR
                } else {
                    UNATTESTED_QUIET_FOR
                },
                spoiled,
            ),
        );
        // The authority's CURRENT word gates every path: the cached
        // verdict alone let a stale Converged carry a since-shrunken
        // mirror through the floor release for the length of the dump
        // (review finding). `authority_current` recomputes the report
        // against the mirror as it is now; None means no authority is
        // configured and the proxies stand on their own.
        let authority = authority_current(&self.completeness, have);
        let veto = authority == Some(false);
        // The authority's word is acted on here; whether it has said the
        // same thing TWICE is recorded here for the same reason — this is
        // the only path that runs every tick of the deferral, and the
        // health surface that reports the escalation cannot be the thing
        // that decides it (`status()` may never be called).
        //
        // Nothing about the release changes: a veto is a veto on the
        // first sample, because refusing to steer on a doubtful reading
        // is the safe direction. What two samples buy is the right to
        // tell an operator the authority itself is broken.
        //
        // A releasing tick clears the run on its way out: it releases
        // with `authority != Some(false)`, meaning the verdict permits or
        // there is no authority, and neither is at fault — so a deferral
        // does not hand a half-run to the next one. Nothing depends on
        // that being airtight; a leftover start only ever costs one
        // interval of earliness on a fault that is being reported again
        // anyway.
        let reading = authority_reading(&self.completeness);
        self.authority_fault_since =
            track_authority_fault(self.authority_fault_since, reading.as_ref());
        // `!flapped` here too: a positive authority word is epoch-blind —
        // the report may predate the reconnect entirely, and stale
        // prior-session routes keep its counts aligned (review finding:
        // round twelve demoted only the floor door). A NEGATIVE word
        // still vetoes regardless of epoch; caution does not expire.
        let complete = live
            && !flapped
            && view
                .rate_quiet_for
                .is_some_and(|q| q >= spoiled_backoff(SOURCE_QUIET_FOR, spoiled))
            && authority == Some(true);
        FallbackReading {
            released: !veto && ((view.released && live) || complete),
            live,
            veto,
        }
    }

    /// Check the preserved ledger against VPP and seed the engine from it,
    /// or discard it with the reason. Consumed either way — unless the
    /// check itself lost the API, in which case it is kept for the
    /// resumed step to decide.
    ///
    /// The check is VPP's own per-length route counts against the ones
    /// the preserving stop read ([`crate::ledger_record::FibFingerprint`]):
    /// anything that added or removed a route since shows up as a count.
    /// A summary that cannot be read is "cannot establish" and discards
    /// the ledger, never "matches".
    fn try_seed(&mut self) -> Result<(), StepError> {
        let Some(rec) = self.preserved.take() else {
            return Ok(());
        };
        let fingerprint = match self.engine.fib_fingerprint() {
            Ok(fp) => fp,
            Err(e) => {
                self.preserved = Some(rec);
                return Err(step_error(&mut self.engine, e));
            }
        };
        if let Some(why) = fingerprint_refusal(fingerprint.as_ref(), &rec.body.fingerprint) {
            tracing::warn!(
                reason = %why,
                "preserved route ledger not used; this adoption reads VPP's FIB instead \
                 (the dump path: unsteer when the fallback is ready, dump, diff, verify)"
            );
            ledger_rejected("fingerprint", &why);
            return Ok(());
        }
        match self.engine.seed_ledger(&rec.body) {
            Ok(n) => {
                self.seeded = Some(Seed {
                    routes: n,
                    fingerprint: rec.body.fingerprint,
                });
                tracing::info!(
                    routes = n,
                    "adopted VPP's FIB from the preserved route ledger — no dump. VPP's route \
                     counts match the stop that wrote it; the diff pushes only what changed, \
                     and verify probes VPP against the ledger, paths included, before it \
                     counts as verified"
                );
                adoption_path("preserved-ledger", n);
            }
            Err(why) => {
                tracing::warn!(
                    reason = %why,
                    "preserved route ledger not used; this adoption reads VPP's FIB instead"
                );
                ledger_rejected("seed", &why);
            }
        }
        Ok(())
    }

    /// Re-read VPP's route counts immediately before a seeded diff is
    /// released, and discard the seed if they moved since it was
    /// accepted (see [`Seed::fingerprint`]). `Ok(true)`: the seed still
    /// stands (or there is none). `Ok(false)`: it was discarded, with the
    /// reason logged, and the engine's ledger is empty for the dump that
    /// must follow. `Err`: the read lost the API, and the seed is kept for
    /// the retried release to judge.
    ///
    /// Cost, since on the steered path it runs with traffic on VPP: one
    /// `cli_inband` (`show ip fib summary`, per family carried). That is a
    /// non-mp-safe message, so VPP takes its worker barrier for it. For
    /// IPv4 it is a per-prefix-length hash count, not a table walk: the
    /// same class of pause as the null-drop sampler's `show errors`, which
    /// already runs every minute while steered, and nothing like the
    /// dump's seconds. **IPv6's is a walk** (`v6 on` only): VPP 26.06's
    /// `ip6_fib_table_show` counts by iterating the table's whole
    /// non-forwarding hash under that barrier — a counting loop over
    /// ~250k entries, no per-route formatting or messaging, so orders of
    /// magnitude below the dump but not free. Unmeasured; rung 0 of the
    /// v6 runbook measures it.
    fn seed_still_holds(&mut self) -> Result<bool, StepError> {
        let Some(expected) = self.seeded.as_ref().map(|s| s.fingerprint.clone()) else {
            return Ok(true);
        };
        let now = self
            .engine
            .fib_fingerprint()
            .map_err(|e| step_error(&mut self.engine, e))?;
        let Some(why) = fingerprint_refusal(now.as_ref(), &expected) else {
            return Ok(true);
        };
        tracing::warn!(
            reason = %why,
            "the preserved ledger no longer describes VPP after the wait for the route source; \
             discarding the seed — this adoption reads VPP's FIB instead (the dump path: \
             unsteer, dump, diff, verify)"
        );
        ledger_rejected("fingerprint-moved", &why);
        self.seeded = None;
        self.engine.discard_ledger();
        Ok(false)
    }
}

/// Which of the three ways an adoption took over VPP's FIB — the
/// preserved ledger (no dump), a read of VPP's FIB (the dump path), or
/// none at all (an empty VPP: fresh installs) — for the event log.
fn adoption_path(path: &'static str, routes: u64) {
    event_log::Event::info(crate::MODULE_NAME, event_kind::ADOPTION_PATH)
        .field("path", path)
        .field("routes", routes)
        .emit();
}

/// The preserved ledger was not used (or was disproved); `stage` says
/// which check refused it. The dump path follows.
fn ledger_rejected(stage: &'static str, why: &dyn std::fmt::Display) {
    event_log::Event::warn(crate::MODULE_NAME, event_kind::PRESERVED_LEDGER_REJECTED)
        .field("stage", stage)
        .field("reason", why.to_string())
        .detail("the preserved route ledger was not used; this adoption reads VPP's FIB instead")
        .emit();
}

/// An engine failure, classified for the supervision loop: the binary
/// API lost, or VPP answering and refusing. See [`StepError`].
///
/// The transport is dropped whenever the answer is "API lost", even
/// where the engine path that failed did not drop it itself — several
/// return a transport error without doing so (`install_attached_routes`'
/// requests among them). That was harmless while such a failure always
/// ended in a teardown that took the socket with the process. A step is
/// now RESUMED on the same process, so a socket that may still owe a
/// late reply must never be the one the resume reuses: that reply would
/// be read as the answer to a different request.
fn step_error(engine: &mut ConvergenceEngine, e: EngineError) -> StepError {
    if e.api_lost() {
        engine.disconnect();
        StepError::ApiLost(e.to_string())
    } else {
        StepError::Failed(e.to_string())
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

    fn api_wait(&self) -> Duration {
        self.core.borrow().engine.api_wait()
    }

    fn api_answers(&self) -> u64 {
        self.core.borrow().engine.api_answers()
    }

    fn api_error(&self) -> Option<String> {
        self.core
            .borrow()
            .engine
            .last_api_error()
            .map(str::to_string)
    }

    fn steer_permitted(&mut self) -> bool {
        let c = self.core.borrow();
        // Every gate, through the same accessors the steer path and the
        // verify verdict use. None is re-derived here — including their
        // shared exception for a target that diverts nothing, which each
        // accessor carries itself: the retry is what drives a `steer
        // off`'s reconcile-to-empty from `Ready`, and asking a stricter
        // question here than the one `steer` answers is how a retry ends
        // up either refusing forever or asking forever.
        c.steer_hold().is_none()
            && c.steer_verdict().is_none_or(|v| v.permits_steering())
            && c.fib_fit_to_steer()
    }

    fn fib_empty(&mut self) -> bool {
        self.core.borrow().engine.counts().installed == 0
    }

    fn drain_batch(&mut self, now: std::time::Instant) -> Result<crate::driver::Drain, StepError> {
        // Timed on the real clock for the driver's deadline arithmetic —
        // see `Observe::last_drain_took`. Around the WHOLE call, because
        // the call that blocks longest (an adopted dump) is inside it.
        let started = std::time::Instant::now();
        let r = self.drain_once(now);
        let mut c = self.core.borrow_mut();
        c.last_drain_took = started.elapsed();
        c.log_unresolvable(now);
        r
    }

    fn poll_reverify(&mut self, now: std::time::Instant) {
        let mut c = self.core.borrow_mut();
        let counts = c.engine.counts();
        // Stale two ways (`verify::ReverifySchedule`): failed only on
        // what the table can outgrow, or taken against too little of the
        // table to vouch for it now — the coverage rule the first-steer
        // hold applies, through the same predicate.
        //
        // Never a MISMATCH, however much the table has grown. The probes
        // found VPP disagreeing with the ledger, and a re-run draws a new
        // sample that can simply miss the prefix it disagreed on — a pass
        // that would release a held first steer with nothing rebuilt
        // (review finding, PR #333). Nothing samples its way out of a
        // mismatch; a FIB rebuild does (`verify::Unvouched::Mismatch`).
        let (incomplete, outgrown) = c.engine.last_verify().map_or((false, None), |v| {
            (
                v.awaits_clean_table(),
                (!v.restart_worthy() && !v.covers(counts.installed)).then_some(v.table),
            )
        });
        let stale = if outgrown.is_some() {
            Some(crate::verify::Stale::Outgrown)
        } else {
            incomplete.then_some(crate::verify::Stale::Incomplete)
        };
        // Clean: nothing the verdict failed on is left, and nothing about
        // the moment would make a probe race the table — the same
        // conditions the convergence verify runs under. Nothing in
        // flight, VPP caught up with the mirror (`Core::behind`, which
        // also needs the last drain to have landed), no deferral or hold
        // between the mirror and VPP, and no seed still waiting for its
        // own judgement.
        //
        // Caught up, not "nothing at the source". This runs only on a
        // tick whose drain proved the engine idle, so nothing is on the
        // wire, and nothing reaches VPP between a probe's sample and its
        // answer: the drain and the probes share this thread. A few
        // changes queued at the source since that drain race nothing —
        // and requiring none starved the debounce on a full-table feed,
        // whose churn leaves a handful queued on most ticks, so the one
        // verdict the first steer now waits on would never be refreshed.
        let clean = counts.unresolvable == 0
            && counts.unexempted_local == 0
            && counts.installing == 0
            && counts.installed > 0
            && c.behind().is_none()
            && c.deferred_resync.is_none()
            && c.fresh_hold.is_none()
            && c.seeded.is_none();
        if !c.reverify.poll(now, stale, clean) {
            return;
        }
        let cause = match outgrown {
            Some(table) => format!(
                "the table had outgrown the last verdict ({table} routes when it ran, {} now)",
                counts.installed
            ),
            None => "the table was clean again".to_string(),
        };
        match c.engine.refresh_verify() {
            Ok(outcome) => {
                let summary = outcome.summary();
                let kind = if outcome.passed() {
                    tracing::info!(outcome = %summary, cause = %cause, "verify re-run: passed");
                    event_log::Event::info(crate::MODULE_NAME, event_kind::VERIFY_PASSED)
                } else if outcome.restart_worthy() {
                    tracing::warn!(
                        outcome = %summary,
                        cause = %cause,
                        remedy = crate::verify::MISMATCH_REMEDY,
                        "verify re-run found FIB mismatches; a re-run tears nothing down, so \
                         VPP stays up and steering already in place is unchanged, but no steer \
                         that diverts more is admitted on this verdict, and it is not re-run"
                    );
                    event_log::Event::warn(crate::MODULE_NAME, event_kind::VERIFY_FAILED).detail(
                        "re-run; nothing is torn down by a re-run, and a first steer is held",
                    )
                } else {
                    tracing::info!(outcome = %summary, cause = %cause, "verify re-run: still incomplete");
                    event_log::Event::info(crate::MODULE_NAME, event_kind::VERIFY_INCOMPLETE)
                };
                kind.field("outcome", summary.to_string())
                    .field("rerun", true)
                    .field("cause", cause)
                    .emit();
                c.refreshed_verify = Some(outcome);
            }
            // The API is the loop's business: a lost socket is reconnected
            // by the next tick's `api_ready`, exactly as after a failed
            // steady-state drain. The verdict stands as it was.
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "verify re-run could not reach VPP; the previous verdict stands"
                );
                // A pass that lost the socket dropped it. Reconnect now, as
                // the driver would after a failed drain: left for the next
                // tick, the pings in between would fail on a socket that is
                // gone and count toward a wedge VPP is not in.
                if e.api_lost() {
                    let _ = c.engine.api_ready();
                }
            }
        }
    }

    fn last_drain_took(&self) -> Duration {
        self.core.borrow().last_drain_took
    }

    fn convergence_budget(&mut self) -> Duration {
        let c = self.core.borrow();
        // The table a convergence here has to move: the larger of what the
        // source holds and what the ledger believes VPP holds (before the
        // mirror has loaded, the second is the honest size of an adopted
        // FIB).
        let routes = c
            .source
            .route_count()
            // Every family VPP holds: a v6 table moves through the same
            // drains and counts against the same budget.
            .max(c.engine.counts().installed_all())
            .max(c.seeded.as_ref().map_or(0, |s| s.routes));
        crate::supervisor::convergence_budget(routes, c.last_dump_took)
    }
}

impl ObserveView {
    fn drain_once(&mut self, now: std::time::Instant) -> Result<crate::driver::Drain, StepError> {
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
                    mut feed,
                    mut last_request,
                    mut restoring,
                    spoiled,
                    mut settled_have,
                } => {
                    let r = c.read_fallback(now, &mut feed, have, seq, pulses, spoiled);
                    let want = feed.gate.floor;
                    let unsteered = c.steering.installed().is_empty();
                    if !r.released {
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
                        //
                        // Only for a fallback that is UNFIT — the feed
                        // down, the authority saying no, or the mirror
                        // under the floor or collapsed to under half of
                        // what it held at the unsteer. A fallback that
                        // is merely BUSY (live, loaded, churning faster
                        // than the quiet allows) is the better tier to
                        // be on: it tracks the mirror live, while the
                        // adopted FIB is frozen at adoption — no deltas
                        // reach VPP during a deferral. Restoring on
                        // churn, as this did, flapped steering on every
                        // burst, and after a churn-spoiled dump put
                        // traffic back on a FIB going staler by the
                        // minute (2026-09-26).
                        let unfit = !r.live
                            || r.veto
                            || have < want
                            || settled_have.is_some_and(|h| have < (h / 2).max(1));
                        if (unsteered || restoring) && unfit {
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
                            feed,
                            last_request,
                            restoring,
                            spoiled,
                            settled_have,
                        });
                        return Ok(crate::driver::Drain::AwaitingSource { have, want });
                    }
                    if !c.engine.ledger_is_empty() {
                        // An earlier release already read VPP's FIB and
                        // the feed spoiled the diff it was for. That
                        // read is still exact — nothing changes VPP's
                        // FIB while a deferral holds — so the retry
                        // diffs against it rather than dumping again,
                        // and runs whether or not traffic went back on
                        // VPP meanwhile: the unsteer exists for the
                        // dump's barrier, and there is no dump.
                        let routes = c.engine.counts().installed;
                        let Core { engine, source, .. } = &mut *c;
                        let plan = engine.begin_resync(source.as_ref());
                        tracing::info!(
                            have,
                            adopted = routes,
                            steered = !unsteered,
                            upserts = plan.upserts,
                            out_of_family = plan.out_of_family,
                            withdrawals = plan.withdrawals,
                            "route source loaded and quiet again; running the adopted resync \
                             diff against the FIB an earlier dump already read — no second \
                             dump (nothing has changed VPP's FIB since) and no unsteer (that \
                             was only ever for the dump)"
                        );
                        engine
                            .program_neighbours(source.as_ref())
                            .map(|_| ())
                            .map_err(|e| step_error(engine, e))?;
                        c.deferred_resync = None;
                    } else if !unsteered {
                        // A re-release after a revocation cycle starts
                        // the settle/unsteer sequence over.
                        restoring = false;
                        settled_have = Some(have);
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
                            feed,
                            last_request,
                            restoring,
                            spoiled,
                            settled_have,
                        });
                        return Ok(crate::driver::Drain::AwaitingSource { have, want });
                    } else {
                        // Unsteered and quiet: the dump is free — nothing
                        // is on VPP for the barrier to stall.
                        let Core {
                            engine,
                            source,
                            feed_session,
                            completeness,
                            last_dump_took,
                            ..
                        } = &mut *c;
                        let started = std::time::Instant::now();
                        let adopted = engine.adopt_vpp_fib().map_err(|e| step_error(engine, e))?;
                        let took = started.elapsed();
                        *last_dump_took = Some(last_dump_took.map_or(took, |t| t.max(took)));
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
                        // The deferral is KEPT on refusal, and so is the
                        // dump: the ledger holds the FIB just read, the
                        // next release diffs against it without reading
                        // it again (see the arm above), and the
                        // revocation path re-steers only if the fallback
                        // turns unfit meanwhile.
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
                            (feed.epoch, liveness_now.map(|l| l.epoch)),
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
                            let spoiled = spoiled.saturating_add(1);
                            tracing::warn!(
                                adopted,
                                live = live_now,
                                dump_churn,
                                churn_budget,
                                have_now,
                                dump_secs = took.as_secs_f64(),
                                spoiled,
                                next_quiet_secs =
                                    spoiled_backoff(SOURCE_QUIET_FOR, spoiled).as_secs(),
                                "the feed changed while VPP's FIB was being dumped; the dump \
                                 is KEPT (nothing changes VPP's FIB while the diff waits), and \
                                 the diff runs against it once the source has been quiet for \
                                 longer — no second dump, and no teardown: a busy feed is not \
                                 a broken VPP"
                            );
                            feed.gate.rebaseline(seq_now, pulses_now);
                            c.deferred_resync = Some(DeferredResync::AwaitingFallback {
                                feed,
                                last_request,
                                restoring: true,
                                spoiled,
                                settled_have,
                            });
                            return Ok(crate::driver::Drain::AwaitingSource { have, want });
                        }
                        let plan = engine.begin_resync(source.as_ref());
                        tracing::info!(
                            have,
                            adopted,
                            dump_secs = took.as_secs_f64(),
                            upserts = plan.upserts,
                            out_of_family = plan.out_of_family,
                            withdrawals = plan.withdrawals,
                            "route source loaded and quiet and VPP unsteered; dumped its FIB \
                             against no traffic and running the adopted resync diff"
                        );
                        engine
                            .program_neighbours(source.as_ref())
                            .map(|_| ())
                            .map_err(|e| step_error(engine, e))?;
                        c.deferred_resync = None;
                    }
                }
                DeferredResync::AwaitingSeededDiff { mut feed } => {
                    let r = c.read_fallback(now, &mut feed, have, seq, pulses, 0);
                    let want = feed.gate.floor;
                    if !r.released {
                        c.deferred_resync = Some(DeferredResync::AwaitingSeededDiff { feed });
                        return Ok(crate::driver::Drain::AwaitingSource { have, want });
                    }
                    // The seed was checked against VPP before the wait;
                    // the wait may have been minutes. Checked again now,
                    // and a seed that no longer holds takes the dump path
                    // from here — through the pre-dump stage, handed THIS
                    // gate so the release already earned carries over and
                    // the next tick asks for the unsteer at once. Traffic
                    // is not steered into a FIB the seed misdescribes for
                    // any longer than that request takes.
                    if !c.seed_still_holds()? {
                        c.deferred_resync = Some(DeferredResync::AwaitingFallback {
                            feed,
                            last_request: None,
                            restoring: false,
                            spoiled: 0,
                            settled_have: None,
                        });
                        return Ok(crate::driver::Drain::AwaitingSource { have, want });
                    }
                    let Core { engine, source, .. } = &mut *c;
                    let plan = engine.begin_resync(source.as_ref());
                    tracing::info!(
                        have,
                        unchanged = plan.unchanged,
                        upserts = plan.upserts,
                        out_of_family = plan.out_of_family,
                        withdrawals = plan.withdrawals,
                        "route source loaded and quiet; diffing it against the preserved \
                         ledger while VPP keeps forwarding — no dump and no unsteer, and \
                         only the differences go to VPP"
                    );
                    engine
                        .program_neighbours(source.as_ref())
                        .map(|_| ())
                        .map_err(|e| step_error(engine, e))?;
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
                    // The second door, for a mirror the fast-path seeded
                    // from its route ledger: see
                    // `seeded_mirror_releases_diff` for when the replay's
                    // quiet is not owed. Observed every tick above all the
                    // same, so the rate baseline stays current if this
                    // door never opens.
                    let seeded_release = !released
                        && seeded_mirror_releases_diff(
                            c.feed_session.as_ref().map(|f| f.liveness()),
                            authority_current(&c.completeness, have),
                            have,
                            gate.floor,
                        );
                    if !released && !seeded_release {
                        let want = gate.floor;
                        c.deferred_resync = Some(DeferredResync::AwaitingDiff { adopted, gate });
                        return Ok(crate::driver::Drain::AwaitingSource { have, want });
                    }
                    if seeded_release {
                        tracing::info!(
                            have,
                            adopted,
                            "the route mirror was seeded from the fast-path route ledger, the \
                             route source is streaming and the completeness authority agrees \
                             with it: running the adopted resync diff now rather than after the \
                             replay goes quiet (VPP carries no traffic; the replay's changes \
                             follow as ordinary updates)"
                        );
                    }
                    // The unsteered seeded adoption re-checks too (see the
                    // steered arm). Nothing is on VPP here, so the dump
                    // the discarded seed owes runs at once, and the diff
                    // then waits behind a gate sized to what it read.
                    if c.seeded.is_some() && !c.seed_still_holds()? {
                        let Core {
                            engine,
                            last_dump_took,
                            ..
                        } = &mut *c;
                        let started = std::time::Instant::now();
                        let adopted = engine.adopt_vpp_fib().map_err(|e| step_error(engine, e))?;
                        let took = started.elapsed();
                        *last_dump_took = Some(last_dump_took.map_or(took, |t| t.max(took)));
                        if adopted > 0 {
                            let gate = SourceGate::new(
                                (adopted / ADOPTED_SOURCE_FLOOR_DIVISOR).max(1),
                                seq,
                            );
                            let want = gate.floor;
                            c.deferred_resync =
                                Some(DeferredResync::AwaitingDiff { adopted, gate });
                            return Ok(crate::driver::Drain::AwaitingSource { have, want });
                        }
                        // An empty FIB has no withdrawal universe to
                        // protect: diff now, as a fresh resync would.
                    }
                    {
                        let Core { engine, source, .. } = &mut *c;
                        let plan = engine.begin_resync(source.as_ref());
                        tracing::info!(
                            have,
                            adopted,
                            unchanged = plan.unchanged,
                            upserts = plan.upserts,
                            out_of_family = plan.out_of_family,
                            withdrawals = plan.withdrawals,
                            "route source loaded and quiet; running the adopted resync diff"
                        );
                        engine
                            .program_neighbours(source.as_ref())
                            .map(|_| ())
                            .map_err(|e| step_error(engine, e))?;
                    }
                    c.deferred_resync = None;
                }
            }
        }
        // The IPv6 hand-back path, every tick with a live API: the kernel's
        // address watch is drained here, so a new or removed router
        // address reaches VPP's /128s within a tick. Only a lost socket
        // fails the drain — a path that is not ready is held on its own
        // status and gates only the v6 half of steering.
        if let Err(e) = c.service_handback(true, true) {
            c.last_drain_error = Some(e.to_string());
            return Err(step_error(&mut c.engine, e));
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
            completeness,
            fresh_hold,
            last_placement,
            ..
        } = &mut *c;
        // Follow bridge neighbours spanning tree moved, before this
        // batch: a move re-queues the neighbour's routes into the source,
        // and they go out in the same drain as everything else.
        let placement_due = last_placement.is_none_or(|t| t.elapsed() >= PLACEMENT_EVERY);
        if placement_due {
            *last_placement = Some(std::time::Instant::now());
            if let Err(e) = engine.refresh_placement(source.as_ref()) {
                *last_drain_error = Some(e.to_string());
                return Err(step_error(engine, e));
            }
        }
        // `?`-equivalent: a failed neighbour programming must not be
        // followed by a route drain that installs paths through the
        // adjacency that just failed to land.
        let r = match engine.apply_changes(source.as_ref(), DELTA_BATCH) {
            Err(e) => Err(e),
            Ok(_) => engine.drain_batch().map(|(done, _stats)| {
                if done {
                    crate::driver::Drain::Idle
                } else {
                    crate::driver::Drain::More
                }
            }),
        };
        // Every re-queued route of a moved neighbour has gone out once the
        // drain is idle with nothing left in the source: only now does
        // the old adjacency stop carrying traffic, so only now is it
        // removed.
        let r = match r {
            Ok(crate::driver::Drain::Idle) if source.backlog() == 0 => {
                engine.settle_moves().map(|()| crate::driver::Drain::Idle)
            }
            other => other,
        };
        // Set on failure and cleared on success, in one place, for the
        // same reason `note_persist` is: a field that only ever gets set
        // reports a fault that recovered as though it were still
        // happening.
        *last_drain_error = r.as_ref().err().map(|e| e.to_string());
        // The fresh-resync hold: an idle pending map during a fresh
        // resync is NOT completion while the authority still says the
        // source is short — it is what "bird has not dumped yet" looks
        // like from in here, and letting it become `SyncComplete` runs
        // verify against a table that is not there (see [`FreshHold`]).
        // `AwaitingSource` extends the phase deadline, exactly as the
        // adopted deferrals do, so a multi-minute dump cannot time the
        // convergence out either. Backlog must be drained too: the
        // authority compares bird against the MIRROR, which the tee has
        // already updated, so an idle map plus a converged word can
        // still hide a burst the feed holds (`Core::behind`'s gap).
        let mut release_hold = false;
        if let (Ok(crate::driver::Drain::Idle), Some(hold)) = (&r, fresh_hold.as_mut()) {
            let have = source.route_count();
            let released =
                authority_current(completeness, have) == Some(true) && source.backlog() == 0;
            if !released {
                if !hold.announced {
                    hold.announced = true;
                    tracing::info!(
                        have,
                        "fresh resync is idle but the route source has not converged; \
                         holding verify while installs continue"
                    );
                }
                let want = completeness
                    .as_ref()
                    .and_then(|h| h.latest_verdict().0)
                    .map_or(0, |rep| rep.authority_routes);
                return Ok(crate::driver::Drain::AwaitingSource { have, want });
            }
            tracing::info!(
                have,
                "route source converged and drained; fresh resync complete — verifying \
                 the full table"
            );
            release_hold = true;
        }
        if release_hold {
            *fresh_hold = None;
        }
        r.map_err(|e| step_error(engine, e))
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
        // A confirmed removal is the config taking effect too: nothing
        // is diverted, so the scan turns predictive, and it should
        // predict from the config the operator just applied.
        if outcome.is_ok() {
            c.commit_drift_scope();
        }
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
        c.gate_v6_for_steer();
        let outcome = c.steering.steer();
        c.record_steering();
        // One of the places every steer passes through — the
        // operator's reconfigure and the driver's automatic retry
        // alike — so the staged scope lands whichever asked, and
        // never when the NIC refused.
        if outcome.is_ok() {
            c.commit_drift_scope();
        } else {
            c.note_partial_steer();
        }
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
        // The first-steer hold, same chokepoint: VPP has caught up with
        // the mirror the completeness gate just judged, and a verify has
        // looked at a fair sample of the table being steered. HERE rather
        // than beside the FIB gate in `apply_steering`, because three
        // paths make a first steer and only the lever goes through there
        // — the retry and a convergence's `VerifyPassed` re-steer of a
        // want come straight to this effect.
        //
        // Any steer that diverts MORE, not only the first: the accessor
        // asks `expands_diversion`, so a reconcile adding a canary port
        // to ports already steered is held as the first port was, while
        // one that diverts the same or less goes through whatever the
        // backlog — refusing it would leave the previous rules installed.
        // The refusal is before the NIC, so the ports already steered
        // keep exactly the rules they have.
        //
        // A refusal is `SteerFailed` with the want kept, and the retry
        // re-attempts once `steer_permitted` — the same accessor — says
        // the hold has cleared; an outgrown verdict is refreshed by the
        // verify re-run first. The empty-target exception is inside the
        // accessor.
        if let Some(hold) = c.steer_hold() {
            let kept = if c.steering.installed().is_empty() {
                ""
            } else {
                " Nothing was changed: the rules already installed stay as they are, \
                 including any this change would remove — a change that only removes \
                 rules is never held, so apply a removal on its own if it cannot wait."
            };
            let then = if hold.clears_itself() {
                format!(
                    "The want is remembered and re-attempted on its own, at most every {}s, \
                     once nothing holds it — `packetframe status` says what it waits for, and \
                     `packetframe reconfigure` asks immediately",
                    crate::driver::STEER_RETRY_EVERY.as_secs()
                )
            } else {
                "Waiting does not clear this, so the remembered want will not steer by itself"
                    .to_string()
            };
            return Err(format!(
                "refusing to steer: {hold}. A steered packet whose prefix VPP does not \
                 hold yet, or holds through a FIB no verify has sampled, is dropped or \
                 follows a less specific route inside VPP rather than falling back to the \
                 kernel path.{kept} {then}"
            ));
        }
        // The link gate, same chokepoint, same shape, FRESH read. The
        // verify verdict deliberately routes dark members through
        // `VerifyIncomplete` (a restart cannot plug in a cable — shadow
        // repro 2026-08-13), which means nothing upstream of this point
        // has refused them; a steer is the moment traffic would start
        // dying on the dark port, so the check runs here, against what
        // the interfaces report NOW rather than what the last verify
        // recorded. Recovery is free: a refusal is `SteerFailed`, the
        // want stays set, and the retry that runs after the cable comes
        // back passes this gate. Same empty-target exception as the
        // completeness gate, for the same reason: a reconcile that only
        // removes rules diverts nothing.
        //
        // "Cannot read link state" refuses too. Steering is the one
        // operation where "probably fine" and "verified fine" differ by
        // a blackhole, and the transport being unable to answer an
        // interfaces dump is not a state to divert traffic into.
        if c.steer_diverts_traffic() {
            match c.engine.dead_members() {
                Ok(dead) => {
                    // Only dark members that CARRY ROUTES block: a
                    // steered packet can only die on an egress some
                    // route names, and a dark port mostly has none —
                    // its BGP session died with the link. An idle dark
                    // port (the primary's uncabled eth5) degrades the
                    // report and holds nothing hostage.
                    let blocking: Vec<&crate::verify::DeadInterface> =
                        dead.iter().filter(|d| d.in_use).collect();
                    if !blocking.is_empty() {
                        let names: Vec<String> = blocking
                            .iter()
                            .map(|d| {
                                format!(
                                    "{} (admin_up={} link_up={})",
                                    d.name, d.admin_up, d.link_up
                                )
                            })
                            .collect();
                        let idle = dead.len() - blocking.len();
                        return Err(format!(
                            "refusing to steer: {} member interface(s) carry routes but \
                             cannot forward: {}. A steered packet whose best path exits \
                             a dark port is dropped, not failed over. Restore link/admin \
                             on the port(s); the steer retries on its own at most every \
                             {}s, or `packetframe reconfigure` asks immediately{}",
                            names.len(),
                            names.join(", "),
                            crate::driver::STEER_RETRY_EVERY.as_secs(),
                            if idle > 0 {
                                format!(
                                    " ({idle} further dark member(s) carry no routes \
                                     and do not block)"
                                )
                            } else {
                                String::new()
                            }
                        ));
                    }
                }
                Err(e) => {
                    return Err(format!(
                        "refusing to steer: member link state could not be read from VPP \
                         ({e}); cannot confirm every egress can forward, and a steered \
                         miss is dropped rather than falling back"
                    ));
                }
            }
        }
        c.gate_v6_for_steer();
        let outcome = c.steering.steer();
        c.record_steering();
        // One of the places every steer passes through — the
        // operator's reconfigure and the driver's automatic retry
        // alike — so the staged scope lands whichever asked, and
        // never when the NIC refused.
        if outcome.is_ok() {
            c.commit_drift_scope();
        } else {
            c.note_partial_steer();
        }
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

    fn attach_devices(&mut self) -> Result<(), StepError> {
        let mut c = self.core.borrow_mut();
        let mode = c.attach_mode;
        if let Err(e) = c.engine.attach_devices(mode) {
            return Err(step_error(&mut c.engine, e));
        }
        // The attach built or adopted the hand-back path; an adopted one
        // that already holds every /128 is ready now, so the steering's
        // audit judges inherited v6 rules against a target that includes
        // them. No re-steer from here: nothing reconciles mid-attach.
        c.apply_v6_gate(false);
        let indices = c.engine.attached_indices();
        // Unlike spawn, do not tear anything down: the interfaces exist
        // and work. The cost of a lost record is one refused adoption
        // after a daemon restart (UnknownIndexOnAdopt → clean restart),
        // which is the designed safe fallback. Surfaced, not fatal — and
        // a success here CLEARS an earlier failure, since the save is
        // whole-record (see `note_persist`).
        let r = c.store.interfaces_attached(&indices);
        let _ = c.note_persist(r);
        // The kernel PF's half of the attach: the VF that just came up
        // disabled the AF's channel-default MCAM entries for the whole
        // LMAC, and only a PF-side rx-mode event re-enables them — the
        // VPP-side promisc vote provably does not (w8, 2026-08-13; see
        // [`RxModeKick`]). Per member port, after EVERY device attach,
        // so a supervisor respawn re-asserts it on the same path that
        // re-created the condition. Failure is surfaced, not fatal: a
        // teardown cannot fix a host-side ioctl, and escalating it is
        // the #180 defect with a new face — but it IS a possible bridge
        // blackout, so the warning names the by-hand remedy.
        for (port, _) in &indices {
            if let Err(e) = c.rx_kick.kick(port) {
                tracing::warn!(
                    port = %port,
                    error = %e,
                    "kernel rx-mode kick failed; the AF's channel-default MCAM entries \
                     for this LMAC may be disabled and the kernel PF deaf below the \
                     kernel (bridge members go dark). By hand: `ip link set <port> \
                     allmulti on` then `allmulti off`"
                );
            }
        }
        Ok(())
    }

    fn start_resync(&mut self) -> Result<(), StepError> {
        let mut c = self.core.borrow_mut();
        // Any hold from an earlier attempt is that attempt's state.
        // The fresh arm below re-arms it when it applies.
        c.fresh_hold = None;
        // The preserved ledger, if the attach wiring handed one over:
        // judged against VPP and seeded, or discarded, BEFORE anything
        // below reads VPP's FIB. It only ever describes the adopted
        // process — the wiring hands it over with the adoption, and the
        // process going away drops it (`process_gone`) — so a fresh VPP
        // never sees one.
        c.try_seed()?;
        // A seeded ledger IS VPP's FIB, as far as this convergence is
        // concerned until verify says otherwise: no dump is owed, so a
        // steered adoption owes no unsteer either. Only the diff waits —
        // behind the steered release when traffic is on VPP, behind the
        // ordinary diff gate when it is not. Checked before the steered
        // arm below, which would otherwise schedule exactly the dump the
        // seed replaces.
        if let Some(seeded) = c.seeded.as_ref().map(|s| s.routes) {
            let floor = (seeded / ADOPTED_SOURCE_FLOOR_DIVISOR).max(1);
            let seq = c.source.change_seq();
            let steered = !c.steering.installed().is_empty();
            tracing::info!(
                routes = seeded,
                floor,
                steered,
                "adopted resync deferred until the route source is loaded and quiet; the \
                 preserved FIB keeps forwarding untouched meanwhile{}",
                if steered {
                    ", and steering stays up throughout"
                } else {
                    ""
                }
            );
            c.deferred_resync = Some(if steered {
                DeferredResync::AwaitingSeededDiff {
                    feed: FeedGate::new(floor, seq),
                }
            } else {
                DeferredResync::AwaitingDiff {
                    adopted: seeded,
                    gate: SourceGate::new(floor, seq),
                }
            });
            return Ok(());
        }
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
            event_log::Event::info(crate::MODULE_NAME, event_kind::ADOPTION_PATH)
                .field("path", "readback-deferred")
                .field("steered", true)
                .detail(
                    "adopted a steered VPP; its FIB is read once the route source is loaded \
                     and the eBPF tier has taken the traffic back",
                )
                .emit();
            c.deferred_resync = Some(DeferredResync::AwaitingFallback {
                feed: FeedGate::new(floor, seq),
                last_request: None,
                restoring: false,
                spoiled: 0,
                settled_have: None,
            });
            return Ok(());
        }
        // Unsteered: nothing is on VPP, so the dump's worker stall
        // costs no packets. Split borrow: the engine walks the source
        // while both live in the same core.
        let deferral = {
            let Core {
                engine,
                source,
                last_dump_took,
                ..
            } = &mut *c;
            // BEFORE the diff, because the diff is what consumes it: the
            // ledger's contents are where withdrawals come from, and on an
            // adoption it is empty while the surviving VPP's FIB is not.
            // A no-op unless the ledger is empty, so a fresh spawn pays one
            // round trip and adopts nothing.
            let started = std::time::Instant::now();
            let adopted = engine.adopt_vpp_fib().map_err(|e| step_error(engine, e))?;
            if adopted > 0 {
                let took = started.elapsed();
                *last_dump_took = Some(last_dump_took.map_or(took, |t| t.max(took)));
            }
            if adopted > 0 {
                tracing::info!(
                    routes = adopted,
                    "adopted VPP's existing FIB; the resync diff can now withdraw what the \
                     route source no longer advertises"
                );
                adoption_path("readback", adopted);
            } else {
                adoption_path("fresh", 0);
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
                    .map_err(|e| step_error(engine, e))?;
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
        // The fresh arm (deferral: none) trickle-converges by design,
        // but its VERIFY must wait for the loaded table where anyone
        // can attest one. See [`FreshHold`] for the incident this
        // encodes.
        let fresh = deferral.is_none();
        c.deferred_resync = deferral;
        if fresh && c.completeness.is_some() {
            tracing::info!(
                "fresh resync under a completeness authority: routes install as the \
                 source loads, and verify waits until the authority confirms the \
                 table is complete (require-table-complete)"
            );
            c.fresh_hold = Some(FreshHold { announced: false });
        }
        Ok(())
    }

    fn start_verify(&mut self) -> Result<(), StepError> {
        let mut c = self.core.borrow_mut();
        // A seeded ledger is verified with its PATHS compared too: the
        // preserved record's claim is "VPP holds these routes through
        // these paths", and this process never saw VPP acknowledge any
        // of them.
        let seeded = c.seeded.is_some();
        match c.engine.run_verify_paths(seeded) {
            Ok(mut verdict) => {
                // A failed delivery attempt narrows the verdict, because
                // the ledger's counts cannot describe one. `apply_changes`
                // hands an unapplied delta batch back to the source, so
                // its routes are neither installed nor installing nor
                // withheld nor unresolvable — they are simply not here,
                // and `blocks_first_steer` reads a table with a hole in it
                // as complete. Steering into that diverts traffic into a
                // FIB that is behind bird by however much the failed batch
                // held.
                //
                // Wider than strictly needed — a transport failure mid-
                // drain also sets this, and that batch is safe in the
                // pending map — and deliberately so: every cause is "the
                // last attempt to push route intent into VPP did not
                // land", and the conservative direction for a FIRST steer
                // is to wait one tick for the retry. It clears on the
                // next clean drain.
                if let Some(why) = &c.last_drain_error {
                    if verdict.may_steer {
                        tracing::warn!(
                            error = %why,
                            "verify passed but the last route-update attempt did not; \
                             withholding the first steer until one lands"
                        );
                    }
                    verdict.may_steer = false;
                }
                // The seed is judged by this verdict, whichever way it
                // goes. A disagreement disproves the RECORD rather than
                // VPP, so it is not the restart-worthy `VerifyFailed`:
                // the seeded ledger is discarded here — the dump that
                // follows needs an empty ledger to read into — and the
                // supervisor unsteers and restarts the resync on the
                // dump path (`Event::PreservedLedgerRejected`).
                if seeded {
                    c.seeded = None;
                    // Any family: a v6 disagreement cannot fail the pass,
                    // but it disproves the record all the same
                    // (`VerifyOutcome::any_mismatch`).
                    if verdict.outcome.any_mismatch() {
                        ledger_rejected("verify", &verdict.outcome.summary());
                        tracing::warn!(
                            outcome = %verdict.outcome.summary(),
                            first = ?verdict.outcome.mismatches.first().or_else(|| {
                                verdict.outcome.v6.as_ref().and_then(|v| v.mismatches.first())
                            }),
                            "VPP disagrees with the preserved route ledger; discarding it — \
                             steering comes off, and the resync starts over from a read of \
                             VPP's FIB (the dump path). No teardown: it is the record that is \
                             wrong, not necessarily VPP"
                        );
                        c.engine.discard_ledger();
                        c.deferred_resync = None;
                        c.pending.push(Event::PreservedLedgerRejected);
                        return Ok(());
                    }
                }
                // The verdict is an observation of what VPP answered.
                // It reaches the supervisor through the loop's inject,
                // not from inside this Effects call — the same seam
                // every driver test drives.
                let event = verdict.event();
                // Logged HERE, with the outcome's own words: the w7
                // window (2026-08-13) produced seven teardowns whose
                // only trace was the supervisor WARN naming the event
                // — sampled/mismatches/unresolvable were invisible
                // even with the unit log captured, and the loop was
                // misread for a hardware fault because of it.
                let summary = verdict.outcome.summary();
                let recorded = match event {
                    Event::VerifyFailed => {
                        tracing::warn!(
                            outcome = %summary,
                            "verify found FIB mismatches; teardown and a fresh resync follow"
                        );
                        event_log::Event::warn(crate::MODULE_NAME, event_kind::VERIFY_FAILED)
                            .detail("FIB mismatches; teardown and a fresh resync follow")
                    }
                    Event::VerifyIncomplete => {
                        tracing::info!(
                            outcome = %summary,
                            "verify incomplete; steering stays refused and VPP stays up"
                        );
                        event_log::Event::info(crate::MODULE_NAME, event_kind::VERIFY_INCOMPLETE)
                            .detail("steering stays refused and VPP stays up")
                    }
                    _ => {
                        tracing::info!(outcome = %summary, "verify passed");
                        event_log::Event::info(crate::MODULE_NAME, event_kind::VERIFY_PASSED)
                    }
                };
                recorded
                    .field("outcome", summary.to_string())
                    .field("seeded", seeded)
                    .field("may_steer", verdict.may_steer)
                    .emit();
                c.pending.push(event);
                Ok(())
            }
            Err(e) => Err(step_error(&mut c.engine, e)),
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
        let mut c = self.core.borrow_mut();
        // The IPv6 hand-back path's kernel half first — its VPP half died
        // with the process — while the state file still exists, so a
        // leftover is never the only trace of this module. Reported, never
        // fatal: the VFs are the resources whose release must not be
        // blocked, and `packetframe detach --all` removes the veth and the
        // guard by name, with or without a state file.
        if let Err(e) = c.engine.teardown_handback() {
            tracing::warn!(
                error = %e,
                "could not remove the IPv6 hand-back path; `packetframe detach --all` \
                 removes it"
            );
        }
        c.resources.release()
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

    /// The seeded-mirror door needs every leg, and each one alone is
    /// refused: a seed with no stream, a stream with no seed, a seed the
    /// authority does not vouch for (or no authority at all), a seed
    /// below the floor.
    #[test]
    fn the_seeded_mirror_door_needs_seed_stream_and_authority() {
        use packetframe_common::fib::FeedLiveness;
        let live = |up, mirror_seeded| {
            Some(FeedLiveness {
                up,
                epoch: 1,
                reconciled: false,
                mirror_seeded,
            })
        };
        assert!(seeded_mirror_releases_diff(
            live(true, true),
            Some(true),
            100,
            50
        ));
        let reconnected = Some(FeedLiveness {
            up: true,
            epoch: 2,
            reconciled: false,
            mirror_seeded: true,
        });
        for (liveness, authority, have, why) in [
            (
                reconnected,
                Some(true),
                100,
                "a reconnect: the yes may predate this stream",
            ),
            (
                live(true, false),
                Some(true),
                100,
                "no seed: the quiet gate decides",
            ),
            (
                live(false, true),
                Some(true),
                100,
                "the route source is not streaming",
            ),
            (
                live(true, true),
                Some(false),
                100,
                "the authority does not agree",
            ),
            (
                live(true, true),
                None,
                100,
                "no authority to vouch for the seed",
            ),
            (live(true, true), Some(true), 49, "below the floor"),
            (None, Some(true), 100, "no feed session handle at all"),
        ] {
            assert!(
                !seeded_mirror_releases_diff(liveness, authority, have, 50),
                "{why}"
            );
        }
    }

    /// The named unresolvable routes reach the event log once per change,
    /// never per tick, and no more than once a minute; a change inside the
    /// window is written when it has passed, and the set emptying is
    /// written too.
    #[test]
    fn the_named_unresolvable_routes_are_logged_once_per_change_and_paced() {
        let t0 = std::time::Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let a = vec!["198.51.100.0/24 via 192.0.2.9 (no neighbour)".to_string()];
        let b = vec!["203.0.113.0/24 via 192.0.2.9 (no neighbour)".to_string()];
        let mut log = UnresolvableLog::default();
        assert!(
            !log.due(at(0), &[], &[]),
            "nothing, and nothing written yet"
        );
        assert!(log.due(at(1), &a, &[]), "a new set");
        assert!(!log.due(at(2), &a, &[]), "unchanged: not per tick");
        assert!(!log.due(at(30), &b, &[]), "changed, inside the window");
        assert!(log.due(at(61), &b, &[]), "written once the window passed");
        assert!(!log.due(at(200), &b, &[]));
        assert!(log.due(at(300), &[], &[]), "emptying is a change");
        assert!(!log.due(at(400), &[], &[]));
        assert!(log.due(at(500), &[], &a), "v6 counts as the set too");
    }

    /// A veto is only a veto where the gate actually asks.
    ///
    /// `AwaitingFallback` consults `authority_current` and a `false`
    /// there blocks release outright. `AwaitingDiff` releases on
    /// floor-and-quiet and never asks — so a disagreeing authority
    /// during the diff stage blocks nothing, and reporting `Vetoing`
    /// there tells an operator that waiting cannot clear a deferral
    /// that waiting clears perfectly well (review finding). The first
    /// version of this posture keyed on the authority alone and did
    /// exactly that, which is the same defect class it was written to
    /// fix, one stage over.
    #[test]
    fn a_veto_is_scoped_to_the_gate_that_consults_the_authority() {
        use packetframe_common::fib::Completeness;
        let mismatch = Some(Completeness::AuthorityMismatch {
            authority: 13,
            mirror: 1_303_920,
        });
        // Every call here passes a CONFIRMED fault (the trailing
        // `true`), so what is under test is the scoping rule alone —
        // `one_mismatching_sample_is_not_yet_a_veto` covers the other
        // axis.
        // Absent beats everything: no handle, nothing to say.
        for consults in [true, false] {
            assert_eq!(
                authority_posture(false, false, consults, None, None, true),
                AuthorityPosture::Absent
            );
        }
        // A flap demotes — but NOT over a persistent mismatch. The veto
        // survives the demotion clearing (`drain_batch` applies it
        // regardless of epoch), so reporting the flap there would send
        // an operator to idle the feed for something the feed cannot
        // release (review finding).
        assert_eq!(
            authority_posture(true, true, true, Some(false), mismatch.clone(), true),
            AuthorityPosture::Vetoing,
            "a mismatch outranks a flap: letting the feed settle only reveals the veto"
        );
        assert_eq!(
            authority_posture(
                true,
                true,
                true,
                Some(false),
                Some(packetframe_common::fib::Completeness::Unknown {
                    why: "no check has run yet"
                }),
                true
            ),
            AuthorityPosture::DemotedByFlap,
            "but with a self-clearing verdict the flap IS the story worth telling"
        );
        // THE RULE: same disagreeing authority, opposite verdicts,
        // decided only by whether this deferral's gate consults it.
        assert_eq!(
            authority_posture(true, false, true, Some(false), mismatch.clone(), true),
            AuthorityPosture::Vetoing,
            "AwaitingFallback consults the authority, so a false there IS the blocker"
        );
        assert_eq!(
            authority_posture(true, false, false, Some(false), mismatch.clone(), true),
            AuthorityPosture::Attesting,
            "AwaitingDiff never asks, so a disagreeing authority is not blocking it and \
             must not be reported as if it were"
        );
        // A permitting or unknown authority is never a veto.
        for current in [Some(true), None] {
            assert_eq!(
                authority_posture(true, false, true, current, mismatch.clone(), true),
                AuthorityPosture::Attesting
            );
        }
    }

    /// A mirror that has moved since the last sample is not a faulty
    /// authority.
    ///
    /// **This test asserted the opposite one round earlier, and that
    /// assertion was wrong.** It was written for a real finding — the
    /// reason and the gate were reading different mirrors — but the
    /// conclusion it encoded, that the classification should therefore
    /// substitute the live count too, manufactures a permanent-sounding
    /// verdict out of ordinary loading: the checker samples every 300 s,
    /// a DFZ mirror grows past 1% drift in far less, and comparing that
    /// live mirror against the stale authority number reads as "not the
    /// authority feeding this mirror" when the next sample re-measures
    /// both and agrees (review finding).
    ///
    /// The fault question is asked of the sample, where both numbers
    /// describe one moment. A genuine mismatch survives into the next
    /// sample and is classified then, within one interval; one created
    /// by the clock does not. The gate still blocks meanwhile — that is
    /// `authority_current`'s job and is unchanged — and the
    /// blocked-but-clearing message is what says so.
    #[test]
    fn a_mirror_that_outgrew_its_sample_is_not_a_faulty_authority() {
        use packetframe_common::fib::{Completeness, CompletenessReport, TableCompleteness};
        let handle = std::sync::Arc::new(TableCompleteness::new());
        handle.publish(CompletenessReport {
            authority_routes: 1_000_000,
            mirror_routes: 1_000_000,
            at: std::time::Instant::now(),
        });
        let completeness = Some(handle);

        // The sample itself: both counts describing one moment,
        // converged.
        assert!(matches!(
            authority_reading(&completeness).map(|r| r.verdict),
            Some(Completeness::Converged { .. })
        ));

        // The source has grown since. The gate DOES block on the live
        // count — unchanged, and correct.
        assert_eq!(authority_current(&completeness, 1_400_000), Some(false));

        // But the authority is not what is wrong: nothing has asked it
        // since, and the next check will. So the operator is told this
        // clears itself, not to go restarting daemons.
        assert_eq!(
            authority_posture(
                true,
                false,
                true,
                Some(false),
                authority_reading(&completeness).map(|r| r.verdict),
                // Nothing to confirm: the sample is not at fault at all,
                // so no run of at-fault readings exists to be in.
                false
            ),
            AuthorityPosture::AwaitingAuthority,
            "a stale authority count against a grown mirror is the clock, not a fault"
        );

        // And when the mismatch is real — both counts describing one
        // sample — it is a fault, which is the shadow's actual case.
        // Confirmation (the trailing `true`) is the separate axis pinned
        // by `one_mismatching_sample_is_not_yet_a_veto`; what this
        // asserts is that the CLASSIFICATION still reaches the veto once
        // a second sample agrees, where the grown-mirror case above
        // never does however many times it is sampled.
        let real = std::sync::Arc::new(TableCompleteness::new());
        real.publish(CompletenessReport {
            authority_routes: 13,
            mirror_routes: 1_303_920,
            at: std::time::Instant::now(),
        });
        let real = Some(real);
        assert_eq!(
            authority_posture(
                true,
                false,
                true,
                Some(false),
                authority_reading(&real).map(|r| r.verdict),
                true
            ),
            AuthorityPosture::Vetoing,
            "13 routes against 1.3M is the authority being wrong, not a mirror loading"
        );
    }

    /// One mismatching sample is not a veto; two consecutive ones are.
    ///
    /// A `CompletenessReport` is two counts, and they are not taken at
    /// the same instant — concurrently since this change, but still not
    /// simultaneously. A bulk withdrawal or a reload landing in that gap
    /// reads bird low and the mirror high, which `assess` classifies as
    /// `AuthorityMismatch`: the authority measuring a different table.
    /// That verdict sends an operator to restart a daemon, and the next
    /// check does not reproduce it.
    ///
    /// PR #166 answered this in prose — the veto text gated its
    /// disruptive half behind "CONFIRM BEFORE ACTING" and pointed at the
    /// next check. This asserts the property instead, and it is the
    /// stronger claim: the escalation is not reachable from one sample
    /// at all, so the wording no longer has to ask the operator to do
    /// the checking.
    ///
    /// Interval-independent by construction — samples are told apart by
    /// `CompletenessReport::at`, not by elapsed time or tick count — so
    /// this test runs at memory speed over a rule that ships at 300 s.
    #[test]
    fn one_mismatching_sample_is_not_yet_a_veto() {
        use packetframe_common::fib::{CompletenessReport, TableCompleteness};
        let handle = std::sync::Arc::new(TableCompleteness::new());
        let completeness = Some(std::sync::Arc::clone(&handle));
        let t0 = std::time::Instant::now();
        let mismatch = |at| CompletenessReport {
            authority_routes: 13,
            mirror_routes: 1_303_920,
            at,
        };
        // The posture as the deferral would report it, given the run
        // state the tick path is holding.
        let posture = |run| {
            let reading = authority_reading(&completeness);
            authority_posture(
                true,
                false,
                true,
                Some(false),
                reading.as_ref().map(|r| r.verdict.clone()),
                authority_fault_confirmed(run, reading.as_ref()),
            )
        };

        // FIRST at-fault sample. Release is blocked either way — that is
        // `authority_current`'s job and is untouched — but the operator
        // is told this can clear itself, because it can.
        handle.publish(mismatch(t0));
        // `None` is what a fresh `Core` holds: no run in progress.
        let mut run = track_authority_fault(None, authority_reading(&completeness).as_ref());
        assert_eq!(
            run,
            Some(t0),
            "the run starts at the sample that first blamed the authority"
        );
        assert_eq!(
            posture(run),
            AuthorityPosture::AwaitingAuthority,
            "one sample can be two counts taken across a withdrawal; it is not proof the \
             authority is wrong"
        );

        // The supervision loop ticks every ~50 ms against a checker that
        // publishes every ~300 s, so this same sample is read thousands
        // of times. Re-reading one report is not a second opinion.
        for _ in 0..5 {
            run = track_authority_fault(run, authority_reading(&completeness).as_ref());
            assert_eq!(run, Some(t0));
            assert_eq!(
                posture(run),
                AuthorityPosture::AwaitingAuthority,
                "a sample seen twice is one sample"
            );
        }

        // THE SECOND SAMPLE reproduces it. A transient cannot: the next
        // report measures both counts again.
        handle.publish(mismatch(t0 + Duration::from_secs(300)));
        run = track_authority_fault(run, authority_reading(&completeness).as_ref());
        assert_eq!(
            run,
            Some(t0),
            "the run keeps the FIRST sample's identity — that is what makes the second one \
             distinguishable from it"
        );
        assert_eq!(
            posture(run),
            AuthorityPosture::Vetoing,
            "two distinct samples agreeing is the authority being wrong, and now it may be \
             said without hedging"
        );

        // And a good check in between resets it: a mismatch, agreement,
        // a mismatch is two transients, not one persistent fault. The
        // escalation needs an UNBROKEN run.
        handle.publish(CompletenessReport {
            authority_routes: 1_303_920,
            mirror_routes: 1_303_920,
            at: t0 + Duration::from_secs(600),
        });
        run = track_authority_fault(run, authority_reading(&completeness).as_ref());
        assert_eq!(
            run, None,
            "a verdict that does not blame the authority ends the run"
        );
        handle.publish(mismatch(t0 + Duration::from_secs(900)));
        run = track_authority_fault(run, authority_reading(&completeness).as_ref());
        assert_eq!(
            posture(run),
            AuthorityPosture::AwaitingAuthority,
            "the run restarted, so this is a first sample again"
        );
    }

    /// The same rule, through the surfaces that actually carry it: the
    /// tick path records the run, `status()` reads it.
    ///
    /// `one_mismatching_sample_is_not_yet_a_veto` pins the rule; this
    /// pins the WIRING, and the wiring is where this could quietly do
    /// nothing. `RuntimeStatus` is built from a `&Core` that cannot
    /// mutate, so the run has to be advanced somewhere else — and if
    /// that update were dropped, or the field were never written, every
    /// pure-function test above would still pass while the escalation
    /// became unreachable. Two published samples, one `drain_batch` per
    /// sample, and the posture read from `status()` each time.
    #[test]
    fn the_tick_path_is_what_turns_a_repeated_mismatch_into_a_veto() {
        use packetframe_common::fib::{CompletenessReport, TableCompleteness};

        // Steered at adoption: that is what defers into
        // `AwaitingFallback`, the one stage that consults the authority.
        let steering = LedgerSteering {
            rules: vec![("eth4".into(), 1024)],
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
        rt.require_table_complete(std::sync::Arc::clone(&handle));
        let t0 = std::time::Instant::now();
        let mismatch = |at| CompletenessReport {
            authority_routes: 13,
            mirror_routes: 1_303_920,
            at,
        };

        let (_, mut fx) = rt.views();
        fx.start_resync().expect("a steered adoption defers");
        assert!(
            matches!(
                rt.core.borrow().deferred_resync,
                Some(DeferredResync::AwaitingFallback { .. })
            ),
            "the deferral this posture is scoped to"
        );

        let (mut obs, _) = rt.views();
        handle.publish(mismatch(t0));
        obs.drain_batch(t0).expect("a vetoed deferral just waits");
        assert_eq!(
            rt.status().authority,
            AuthorityPosture::AwaitingAuthority,
            "the first sample blocks release, but must not be reported as a fault an \
             operator should act on"
        );

        // A second tick over the SAME report is not a second opinion,
        // and this is the case the run state exists for: the loop ticks
        // ~6000 times per published report.
        obs.drain_batch(t0 + Duration::from_millis(50))
            .expect("still waiting");
        assert_eq!(rt.status().authority, AuthorityPosture::AwaitingAuthority);

        // The next check reproduces it.
        handle.publish(mismatch(t0 + Duration::from_secs(300)));
        obs.drain_batch(t0 + Duration::from_secs(300))
            .expect("still waiting, and now for a reason worth naming");
        assert_eq!(
            rt.status().authority,
            AuthorityPosture::Vetoing,
            "two distinct samples reached the health surface through the tick path"
        );
    }

    /// Only `AuthorityMismatch` is a veto; the rest clear themselves.
    ///
    /// `authority_current` returns false for EVERY non-permitting
    /// verdict, so keying the veto on it alone told a box whose first
    /// integrity check simply had not run yet that waiting would not
    /// help — at every startup with an authority configured (review
    /// finding). `assess()` already draws the line this test pins:
    /// short of the authority is a mirror still loading; larger than
    /// the authority cannot be a loading state at all.
    #[test]
    fn only_a_mismatched_authority_is_a_veto() {
        use packetframe_common::fib::Completeness;
        let self_clearing = [
            Completeness::Unknown {
                why: "no check has run yet",
            },
            Completeness::Stale {
                age: Duration::from_secs(9_999),
            },
            Completeness::Incomplete {
                drift: 0.5,
                authority: 1_000_000,
                mirror: 500_000,
            },
        ];
        // An authority answering ZERO is not a transient unknown. It
        // arrives as `Unknown` because `assess` returns that before the
        // mismatch branch, and it is exactly as permanent as a
        // mismatch — the fully-empty form of the shadow incident
        // (review finding).
        assert_eq!(
            authority_posture(
                true,
                false,
                true,
                Some(false),
                Some(packetframe_common::fib::Completeness::Unknown {
                    why: packetframe_common::fib::ZERO_ROUTE_AUTHORITY
                }),
                true
            ),
            AuthorityPosture::Vetoing,
            "a bird with no routes at all cannot be waited out any more than a mismatched \
             one can"
        );
        for verdict in self_clearing {
            assert_eq!(
                authority_posture(true, false, true, Some(false), Some(verdict.clone()), true),
                AuthorityPosture::AwaitingAuthority,
                "{verdict:?} is a report that has not arrived, aged out, or describes a \
                 mirror still loading — the next check can clear all three, so this must \
                 not be reported as a veto"
            );
        }
        assert_eq!(
            authority_posture(
                true,
                false,
                true,
                Some(false),
                Some(Completeness::AuthorityMismatch {
                    authority: 13,
                    mirror: 1_303_920,
                }),
                true
            ),
            AuthorityPosture::Vetoing,
            "a mirror holding far more than the authority claims is not a loading state \
             and no check will clear it"
        );
    }

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
        fn requeue(&self, _: crate::engine::SourceChanges) {
            unreachable!("this source hands nothing over, so nothing can come back")
        }
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
        /// The plan the ledger was installed under. Reported alongside
        /// it so the persistence wiring can be observed carrying BOTH —
        /// a record holding locations without their spec is a teardown
        /// that cannot remove the exemptions.
        plan: Vec<(String, u32, crate::steer::RuleSet)>,
        /// What the next steer would install, for the first-steer hold's
        /// "does this reconcile divert more" question.
        target: Vec<(String, u32, crate::steer::RuleSet)>,
    }

    impl Steering for LedgerSteering {
        fn missing_from_nic(&self) -> Result<SteeringAudit, String> {
            Ok(SteeringAudit::clean())
        }
        fn installed_plan(&self) -> Vec<(String, u32, crate::steer::RuleSet)> {
            self.plan.clone()
        }
        fn target_plan(&self) -> Vec<(String, u32, crate::steer::RuleSet)> {
            self.target.clone()
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
        fn retarget(&mut self, _: Vec<(String, u32, crate::steer::RuleSet)>) {}
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
        fn steering_changed(
            &mut self,
            rules: &[(String, u32)],
            _: &[(String, u32, crate::steer::RuleSet)],
        ) -> Result<(), String> {
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
            plan: Vec::new(),
            target: Vec::new(),
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

    /// The ledger and the plan reach the store in the SAME call.
    ///
    /// Two separate writes would be two chances to record one without
    /// the other, and the half-record is not benign: locations with no
    /// plan is precisely the state in which `packetframe detach --all`
    /// removes the diversions, silently disowns every cookie-zero
    /// exemption, and reports success. The store's argument list is
    /// where that is made impossible, so this asserts on the pairing
    /// rather than on either field.
    #[test]
    fn the_installed_plan_is_persisted_alongside_the_ledger() {
        type PlanLog = std::rc::Rc<
            std::cell::RefCell<
                Vec<(
                    Vec<(String, u32)>,
                    Vec<(String, u32, crate::steer::RuleSet)>,
                )>,
            >,
        >;
        struct PairStore(PlanLog);
        impl IdentityStore for PairStore {
            fn process_changed(&mut self, _: Option<ProcessIdentity>) -> Result<(), String> {
                Ok(())
            }
            fn interfaces_attached(&mut self, _: &[(String, u32)]) -> Result<(), String> {
                Ok(())
            }
            fn steering_changed(
                &mut self,
                rules: &[(String, u32)],
                plans: &[(String, u32, crate::steer::RuleSet)],
            ) -> Result<(), String> {
                self.0.borrow_mut().push((rules.to_vec(), plans.to_vec()));
                Ok(())
            }
        }

        let exemption = crate::steer::RuleSet {
            rules: vec![crate::steer::SteerRule::v4(
                std::net::Ipv4Addr::new(198, 51, 100, 0),
                24,
                crate::steer::Side::Dst,
                1024,
                crate::steer::RuleAction::Keep,
                None,
            )],
            skipped_v6: 0,
        };

        let seen: PlanLog = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let steering = LedgerSteering {
            next: Some((vec![("eth4".into(), 1024)], true)),
            plan: vec![("eth4".into(), 0, exemption.clone())],
            ..Default::default()
        };
        let rt = Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(steering),
            Box::new(PairStore(std::rc::Rc::clone(&seen))),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        let (_, mut fx) = rt.views();
        fx.steer().expect("installs");

        let seen = seen.borrow();
        assert_eq!(seen.len(), 1, "one write, carrying both");
        let (rules, plans) = &seen[0];
        assert_eq!(rules, &vec![("eth4".to_string(), 1024)]);
        assert_eq!(
            plans,
            &vec![("eth4".to_string(), 0, exemption)],
            "the spec the location was installed under, not just the location"
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
            fn steering_changed(
                &mut self,
                _: &[(String, u32)],
                _: &[(String, u32, crate::steer::RuleSet)],
            ) -> Result<(), String> {
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
            fn installed_plan(&self) -> Vec<(String, u32, crate::steer::RuleSet)> {
                Vec::new()
            }
            fn target_plan(&self) -> Vec<(String, u32, crate::steer::RuleSet)> {
                Vec::new()
            }
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
            fn retarget(&mut self, _: Vec<(String, u32, crate::steer::RuleSet)>) {}
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
            fn installed_plan(&self) -> Vec<(String, u32, crate::steer::RuleSet)> {
                Vec::new()
            }
            fn target_plan(&self) -> Vec<(String, u32, crate::steer::RuleSet)> {
                Vec::new()
            }
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
            fn retarget(&mut self, _: Vec<(String, u32, crate::steer::RuleSet)>) {}
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

        rt.retarget(vec![("eth4".into(), 0, crate::steer::RuleSet::default())]);
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

    /// Every queue-0 reconcile the runtime asked for, `(want, hold)`.
    type Queue0Log = std::rc::Rc<std::cell::RefCell<Vec<(Vec<String>, Vec<String>)>>>;

    #[derive(Clone, Default)]
    struct RecordingKernelPath(Queue0Log);

    impl crate::kernel_path::KernelPath for RecordingKernelPath {
        fn reconcile_queue0(&mut self, want: &[String], hold: &[String]) {
            self.0.borrow_mut().push((want.to_vec(), hold.to_vec()));
        }
        fn queue0_irqs(&self) -> Vec<(String, crate::kernel_path::Queue0Irq)> {
            Vec::new()
        }
        fn queue0_delivery(&self, _: &str) -> Option<String> {
            None
        }
        fn counters(&mut self, _: &str) -> Result<crate::kernel_path::QueueCounters, String> {
            Err("no counters in this fixture".into())
        }
    }

    /// The queue-0 IRQ follows the keeps, through the real steering and
    /// the fake NIC: placed for the port whose driver refused RSS and
    /// for no other, reported on the status surface with the form each
    /// port's keeps were installed in AND read back in, and given back by
    /// the unsteer of a teardown.
    #[test]
    fn the_queue0_irq_is_placed_only_while_a_ports_keeps_pin_queue0() {
        crate::ntuple::sys::reset();
        crate::ntuple::sys::refuse_rss("eth4");
        let plan = crate::steer::RuleSet::plan(
            &[packetframe_common::fib::IpPrefix::V4 {
                addr: [198, 51, 100, 0],
                prefix_len: 24,
            }],
            &[],
            crate::steer::McamBudget::default(),
            packetframe_common::config::VppSteerDirection::Both,
            &[],
        )
        .expect("fits");
        let ports = ["eth4", "eth5"];
        let steering = crate::ntuple::NtupleSteering::new(
            ports.iter().map(|p| (p.to_string(), 0)).collect(),
            ports
                .iter()
                .map(|p| (p.to_string(), 0, plan.clone()))
                .collect(),
        );
        let log = Queue0Log::default();
        let rt = Runtime::new(
            engine(),
            Box::new(EmptySource),
            Box::new(steering),
            Box::new(NullStore),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        rt.kernel_path(Box::new(RecordingKernelPath(std::rc::Rc::clone(&log))));
        let (_, mut fx) = rt.views();
        fx.restore_steer().expect("installs");
        assert_eq!(
            log.borrow().last(),
            Some(&(vec!["eth4".to_string()], Vec::new())),
            "eth4's keeps fell back to queue 0; eth5's spread over RSS and need nothing"
        );

        let reports = rt.status().kernel_path;
        let report = |i: &str| reports.iter().find(|r| r.iface == i).expect("reported");
        assert_eq!(
            report("eth4").verdict.as_ref().map(|v| v.form),
            Some(crate::ntuple::KeepForm::Queue0)
        );
        assert!(report("eth4").observed_queue0 > 0 && report("eth4").observed_rss == 0);
        assert_eq!(
            report("eth5").verdict.as_ref().map(|v| v.form),
            Some(crate::ntuple::KeepForm::Rss)
        );
        assert!(report("eth5").observed_rss > 0 && report("eth5").observed_queue0 == 0);
        assert!(
            report("eth4").unreadable.is_some(),
            "a counter read that failed is said, never shown as zero"
        );

        fx.unsteer().expect("removes");
        assert_eq!(
            log.borrow().last(),
            Some(&(Vec::new(), Vec::new())),
            "no keep left, so every placement is given back"
        );
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
            fn steering_changed(
                &mut self,
                _: &[(String, u32)],
                _: &[(String, u32, crate::steer::RuleSet)],
            ) -> Result<(), String> {
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
            fn steering_changed(
                &mut self,
                _: &[(String, u32)],
                _: &[(String, u32, crate::steer::RuleSet)],
            ) -> Result<(), String> {
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
        // This test exercises the COMPLETENESS gate; give the link gate
        // a clean answer, and the first-steer hold a verify over the
        // (empty) table, so the refusals below are the verdict's.
        rt.core.borrow_mut().engine.test_dead_members = Some(Vec::new());
        rt.core.borrow_mut().engine.verified_for_test();

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
            // Never drained here, so nothing can be handed back.
            // `unreachable!` rather than a no-op: #161 removed this
            // method's default body precisely because a `requeue` that
            // silently does not deliver is the delta-loss bug again,
            // and if this test ever grows a drain the failure must be
            // loud rather than quiet.
            fn requeue(&self, _: crate::engine::SourceChanges) {
                unreachable!("this source hands nothing over, so nothing can be requeued");
            }
        }

        // Everything else is as permissive as it gets: no completeness
        // handle, a one-route table with nothing in flight, a target that
        // asks for a port. One route rather than none, because an empty
        // table is itself a refusal now — this test is about the backlog.
        let mut eng = engine();
        {
            let mut map = crate::sink::NexthopMap::new(vec!["eth4".into()]);
            let nh = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
            map.set_device(nh, "eth4");
            let p = IpPrefix::V4 {
                addr: [203, 0, 113, 0],
                prefix_len: 24,
            };
            eng.ledger_mut().classify_upsert(p, &[nh], &map);
            eng.ledger_mut().commit_installed(p);
        }
        // And verified, so the first-steer hold's verdict half is clear
        // and only its caught-up half is under test.
        eng.verified_for_test();
        let rt = Runtime::new(
            eng,
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
        // And so is churn: what a quiet source queues between two drains
        // is not VPP behind the mirror. `caught_up_allowance` is 64 at
        // this size; one past it is a backlog again.
        for (backlog, permitted) in [(caught_up_allowance(0), true), (65, false)] {
            rt.core.borrow_mut().source = Box::new(Backlogged(std::cell::Cell::new(backlog)));
            let (mut obs, _) = rt.views();
            assert_eq!(obs.steer_permitted(), permitted, "backlog {backlog}");
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
        // Completeness gate under test; link gate answered clean, and the
        // first-steer hold given the verify it needs.
        rt.core.borrow_mut().engine.test_dead_members = Some(Vec::new());
        rt.core.borrow_mut().engine.verified_for_test();
        let (_, mut fx) = rt.views();
        fx.steer().expect("no gate configured, no gate applied");
    }

    /// The link gate: a dark member refuses a diverting steer, an
    /// unreadable link state refuses too, and an empty target is
    /// exempt — its only job is removal.
    ///
    /// This is the second half of the dark-member fix (shadow repro
    /// 2026-08-13): the verify verdict deliberately stops restarting
    /// over dark members, so the steer gate is where traffic is
    /// actually protected from them — with a FRESH read, which is what
    /// lets the existing retry loop recover on its own once the cable
    /// comes back.
    #[test]
    fn a_dark_member_refuses_a_diverting_steer_and_an_empty_target_is_exempt() {
        let steering = LedgerSteering {
            next: Some((vec![("eth4".into(), 1024)], true)),
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

        // The link gate is under test: the first-steer hold, which runs
        // before it, gets the verify it needs.
        rt.core.borrow_mut().engine.verified_for_test();

        // Unreadable link state (no transport, no test override):
        // refusal, because "probably fine" and "verified fine" differ
        // by a blackhole here.
        {
            let (_, mut fx) = rt.views();
            let e = fx.steer().expect_err("unknown link state must refuse");
            assert!(e.contains("link state could not be read"), "{e}");
        }

        // An IN-USE dark member: refusal that names the port and the
        // way back.
        rt.core.borrow_mut().engine.test_dead_members = Some(vec![crate::verify::DeadInterface {
            in_use: true,
            sw_if_index: 2,
            name: "octeon0/0".into(),
            admin_up: true,
            link_up: false,
        }]);
        {
            let (_, mut fx) = rt.views();
            let e = fx.steer().expect_err("a dark member must refuse");
            assert!(e.contains("octeon0/0"), "the port must be named: {e}");
            assert!(
                e.contains("link_up=false"),
                "and its state, so the operator fixes the right thing: {e}"
            );
            assert!(
                rt.core.borrow().steering.installed().is_empty(),
                "a refused steer must not have touched the NIC"
            );
        }

        // Link restored: the same call now goes through — the recovery
        // path the retry loop drives after a cable comes back.
        rt.core.borrow_mut().engine.test_dead_members = Some(Vec::new());
        {
            let (_, mut fx) = rt.views();
            fx.steer().expect("clean links steer");
            assert_eq!(rt.core.borrow().steering.installed().len(), 1);
        }
    }

    /// An IDLE dark member — no installed route can egress it — must
    /// not block a steer: holding five live ports hostage to one
    /// uncabled one is the refusal this refinement removes (the
    /// primary's eth5 is the motivating case). The dark port is still
    /// reported — verify's summary and the ports row carry it — it
    /// just decides nothing.
    #[test]
    fn an_idle_dark_member_does_not_block_a_steer() {
        let steering = LedgerSteering {
            next: Some((vec![("eth4".into(), 1024)], true)),
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
        rt.core.borrow_mut().engine.test_dead_members = Some(vec![crate::verify::DeadInterface {
            in_use: false,
            sw_if_index: 5,
            name: "octeon5/0".into(),
            admin_up: true,
            link_up: false,
        }]);
        rt.core.borrow_mut().engine.verified_for_test();
        let (_, mut fx) = rt.views();
        fx.steer()
            .expect("an idle dark member must not hold the offload hostage");
        assert_eq!(rt.core.borrow().steering.installed().len(), 1);
    }

    /// The empty-target exemption for the link gate specifically: a
    /// reconcile that only removes rules must proceed with members
    /// dark — it is the rollback direction, and refusing it would trap
    /// traffic ON the dark dataplane.
    #[test]
    fn an_empty_target_unsteers_despite_dark_members() {
        let steering = LedgerSteering {
            // Empty target: nothing to install, removal only.
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
        // Members dark AND unreadable-by-default would both refuse a
        // diverting steer; neither may block the removal direction.
        rt.core.borrow_mut().engine.test_dead_members = Some(vec![crate::verify::DeadInterface {
            in_use: true,
            sw_if_index: 2,
            name: "octeon0/0".into(),
            admin_up: true,
            link_up: false,
        }]);
        let (_, mut fx) = rt.views();
        fx.steer()
            .expect("an empty target diverts nothing and must not be link-gated");
    }

    /// Route churn at the source is tolerated, neighbour work is not: one
    /// queued neighbour change — a next hop's MAC moved — holds a first
    /// steer that a handful of queued route changes does not, and the
    /// refusal says why (review finding, PR #333).
    #[test]
    fn a_queued_neighbour_change_holds_a_first_steer_that_route_churn_does_not() {
        struct Queued {
            routes: u64,
            neighbours: u64,
        }
        impl RouteSource for Queued {
            fn for_each_route(&self, _: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
            fn for_each_neighbour(&self, _: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {}
            fn route_count(&self) -> u64 {
                1_000_000
            }
            fn change_seq(&self) -> u64 {
                0
            }
            fn backlog(&self) -> u64 {
                self.routes + self.neighbours
            }
            fn neighbour_backlog(&self) -> u64 {
                self.neighbours
            }
            fn requeue(&self, _: crate::engine::SourceChanges) {
                unreachable!("this source hands nothing over, so nothing can be requeued");
            }
        }
        let mut eng = engine();
        {
            let mut map = crate::sink::NexthopMap::new(vec!["eth4".into()]);
            let nh = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
            map.set_device(nh, "eth4");
            let p = IpPrefix::V4 {
                addr: [203, 0, 113, 0],
                prefix_len: 24,
            };
            eng.ledger_mut().classify_upsert(p, &[nh], &map);
            eng.ledger_mut().commit_installed(p);
        }
        eng.verified_for_test();
        let rt = Runtime::new(
            eng,
            Box::new(Queued {
                routes: 5,
                neighbours: 0,
            }),
            Box::new(LedgerSteering {
                next: Some((vec![("eth4".into(), 1024)], true)),
                configured: 1,
                ..Default::default()
            }),
            Box::new(NullStore),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        rt.core.borrow_mut().engine.test_dead_members = Some(Vec::new());
        {
            let (mut obs, _) = rt.views();
            assert!(obs.steer_permitted(), "five route changes are churn");
        }
        rt.core.borrow_mut().source = Box::new(Queued {
            routes: 0,
            neighbours: 1,
        });
        let (mut obs, mut fx) = rt.views();
        assert!(!obs.steer_permitted(), "one neighbour change is not");
        let e = fx.steer().expect_err("a neighbour change is queued");
        assert!(
            e.contains("and 1 neighbour change(s), where caught up is none"),
            "{e}"
        );
        assert!(rt.core.borrow().steering.installed().is_empty());
    }

    /// The first-steer hold at the chokepoint: a FIRST diverting steer is
    /// refused while VPP is behind the mirror or no verify vouches for the
    /// table, and the refusal names both; a reconcile of ports already
    /// steered is refused only when it diverts MORE (a port added), and
    /// then touches nothing installed; and a target that diverts nothing
    /// — `steer off`'s reconcile — is held by neither the steer nor the
    /// retry that drives it.
    #[test]
    fn the_first_steer_hold_refuses_a_steer_that_diverts_more_and_never_a_removal() {
        struct Behind;
        impl RouteSource for Behind {
            fn for_each_route(&self, _: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
            fn for_each_neighbour(&self, _: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {}
            fn route_count(&self) -> u64 {
                1_000_000
            }
            fn change_seq(&self) -> u64 {
                0
            }
            // A reload's worth, far past what a million-route mirror
            // allows as churn.
            fn backlog(&self) -> u64 {
                430_000
            }
            fn requeue(&self, _: crate::engine::SourceChanges) {
                unreachable!("this source hands nothing over, so nothing can be requeued");
            }
        }
        let rt = Runtime::new(
            engine(),
            Box::new(Behind),
            Box::new(LedgerSteering {
                next: Some((vec![("eth4".into(), 1024)], true)),
                configured: 1,
                ..Default::default()
            }),
            Box::new(NullStore),
            Box::new(NoResources),
            "/usr/bin/vpp",
            "/tmp/startup.conf",
        );
        // Every other gate clear: links clean, no completeness handle.
        rt.core.borrow_mut().engine.test_dead_members = Some(Vec::new());
        {
            let (_, mut fx) = rt.views();
            let e = fx.steer().expect_err("behind and unverified");
            assert!(e.contains("refusing to steer"), "{e}");
            assert!(
                e.contains("VPP has not caught up with the route mirror: 430000 change(s)"),
                "{e}"
            );
            assert!(e.contains("no verify has completed"), "{e}");
            assert!(rt.core.borrow().steering.installed().is_empty());
            let (mut obs, _) = rt.views();
            assert!(!obs.steer_permitted(), "the retry asks the same question");
        }
        assert_eq!(
            rt.status().steer_hold,
            rt.core.borrow().steer_hold(),
            "and status carries the gate's own answer"
        );

        // Already steered on eth4, plan recorded. A reconcile that
        // diverts no more — the same target — is refused by nothing here.
        let plan = |allow: &[IpPrefix]| {
            crate::steer::RuleSet::plan(
                allow,
                &[],
                crate::steer::McamBudget::default(),
                packetframe_common::config::VppSteerDirection::Src,
                &[[0x02, 0, 0, 0, 0, 1]],
            )
            .expect("fits")
        };
        let a = IpPrefix::V4 {
            addr: [192, 0, 2, 0],
            prefix_len: 24,
        };
        let eth4 = vec![("eth4".to_string(), 0u32, plan(&[a]))];
        let installed = vec![("eth4".to_string(), 1024u32)];
        rt.core.borrow_mut().steering = Box::new(LedgerSteering {
            rules: installed.clone(),
            next: Some((installed.clone(), true)),
            configured: 1,
            plan: eth4.clone(),
            target: eth4.clone(),
        });
        {
            let (_, mut fx) = rt.views();
            fx.steer()
                .expect("a reconcile that diverts no more is not held");
        }

        // The next canary rung: eth5 added to the target. Refused before
        // the NIC, eth4's rules exactly as they were, and the refusal
        // says so.
        let mut eth4_and_eth5 = eth4.clone();
        eth4_and_eth5.push(("eth5".to_string(), 0, plan(&[a])));
        rt.core.borrow_mut().steering = Box::new(LedgerSteering {
            rules: installed.clone(),
            next: Some((
                vec![("eth4".to_string(), 1024), ("eth5".to_string(), 1024)],
                true,
            )),
            configured: 2,
            plan: eth4.clone(),
            target: eth4_and_eth5,
        });
        {
            let (_, mut fx) = rt.views();
            let e = fx.steer().expect_err("a port added while VPP is behind");
            assert!(
                e.contains("VPP has not caught up") && e.contains("Nothing was changed"),
                "{e}"
            );
            assert_eq!(rt.core.borrow().steering.installed(), installed);
            assert_eq!(rt.core.borrow().steering.installed_plan(), eth4);
            let (mut obs, _) = rt.views();
            assert!(!obs.steer_permitted(), "nor does the retry add it");
        }

        // A removal, from an unsteered port: never held.
        rt.core.borrow_mut().steering = Box::new(LedgerSteering {
            next: Some((Vec::new(), true)),
            configured: 0,
            ..Default::default()
        });
        assert!(rt.status().steer_hold.is_none());
        let (mut obs, mut fx) = rt.views();
        assert!(
            obs.steer_permitted(),
            "a backlog is no reason to leave a rollback unfinished"
        );
        fx.steer().expect("an empty target diverts nothing");
    }
}
