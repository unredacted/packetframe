//! vpp-offload: the VPP-on-VF forwarding vector (phase 4).
//!
//! PacketFrame's first non-eBPF module — `hook_spec()` is empty. The
//! module is an **orchestrator**: it owns SR-IOV VF + vfio + hugepage
//! resources, renders VPP's startup.conf, supervises the VPP child
//! process, mirrors the RouteController's full table into VPP over
//! the binary API, and owns the MCAM steering rules that bifurcate
//! allowlisted traffic onto the VF. Zero dataplane code lives here;
//! VPP is the upstream program.
//!
//! Built so far: slice 1 (config handling, feasibility probes, the
//! startup.conf renderer and its route-count-driven memory arithmetic),
//! slice 2 (VF/vfio/hugepage lifecycle, state file, pidfd adopt,
//! teardown ordering), slice 3 ([`vpp_api`] — generated wire structs,
//! socket transport, CRC-checked handshake) and slice 4:
//! [`sink`] (pending map, nexthop mapping, three-valued route ledger),
//! [`supervisor`] + [`process`] + [`liveness`] + [`schedule`] +
//! [`executor`] + [`driver`] (the supervision loop), [`attach`] and
//! [`verify`] (device bring-up and readback), [`status`]
//! (health/metrics), [`engine`] (transport, ledger, diffing resync,
//! static neighbours), [`runtime`] + [`service`] (the loop, on a
//! thread, with a published status window), and [`bringup`] — the
//! composition [`Module::attach`] performs.
//!
//! ## What "built" does and does not mean here
//!
//! [`Module::attach`] runs, end to end, against a fixture sysfs and a
//! fake VPP on a real socket (`tests/vpp_bringup.rs`). What has **never**
//! run is any of it against a real VPP process on real hardware: spawn,
//! the octeon device attach, a full-table convergence through this path,
//! and every one of the three published failover numbers. The
//! convergence budget was measured separately (gate 0b, 40.32 s of 60 s)
//! by a bench driving the same engine, not by this module.
//!
//! **Stats-segment gauges** are deliberately absent rather than stubbed:
//! they need a shared-memory parser that does not exist, and a field
//! reporting "unavailable" forever would be a shim for a hypothetical
//! state.
//!
//! MCAM steering is real ([`steer`] plans, [`ntuple`] installs and reads
//! back), and [`Module::reconfigure`] turns it on and off under a
//! running VPP — that is the canary lever, and making it cost a restart
//! would put ~40 s of resync between an operator and every rollout step,
//! including the rollback.
//!
//! Design record: `.claude/plans/` phase-4 plan v7. Key invariants
//! enforced from day one:
//! - membership (VF on every possible egress port) is all-or-nothing;
//!   steering is the per-port canary lever (`Config::validate_vpp_offload`);
//! - the steered-prefix set inherits the fast-path allowlist, which
//!   must mean pure stateless L3 transit;
//! - the eBPF fast-path on the PFs is the permanent failover tier.

pub mod acquire;
pub mod attach;
pub mod bringup;
pub mod cores;
pub mod driver;
pub mod engine;
pub mod executor;
pub mod feed;
pub mod fib_sync;
pub mod liveness;
pub mod ntuple;
pub mod process;
pub mod resources;
pub mod runtime;
pub mod schedule;
pub mod service;
pub mod sink;
pub mod startup_conf;
pub mod status;
pub mod steer;
pub mod supervisor;
pub mod verify;
pub mod vpp_api;

#[cfg(target_os = "linux")]
mod probe_linux;

use packetframe_common::config::ModuleDirective;
use packetframe_common::module::{
    Attachment, HealthCtx, HealthReport, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
    ModuleError, ModuleResult,
};
use packetframe_common::probe::Capability;

pub const MODULE_NAME: &str = "vpp-offload";

/// Parsed view of the module's section, extracted once at load.
#[derive(Debug, Clone, Default)]
pub struct VppOffloadConfig {
    /// (iface, cores, steer) in config order.
    pub ports: Vec<(String, u16, bool)>,
    pub vpp_binary: Option<String>,
    pub expected_routes: u64,
    pub hugepages: Option<u32>,
    /// Whether a first steer waits for the route mirror to be confirmed
    /// converged against bird. See
    /// [`packetframe_common::fib::TableCompleteness`].
    pub require_table_complete: bool,
    /// The address VPP's loopback holds; every member port is
    /// unnumbered to it.
    ///
    /// `None` is a config error whenever there are ports, refused at
    /// load — see [`packetframe_common::config::Config::validate_vpp_offload`].
    /// Attaching without it produces a VPP that passes every health
    /// check and forwards nothing, which is the failure this whole
    /// module is built to make impossible.
    pub loopback_address: Option<packetframe_common::config::Ipv4Prefix>,
}

/// Default sizing input when `expected-routes` is absent.
///
/// Measured 2026-08-02 on the reference fleet: ~1.30M nexthops across
/// v4+v6 (see `docs/runbooks/vpp-offload-spike.md` §0). The DFZ grows
/// roughly 100k routes/yr, so this is about three years of headroom.
/// The previous 1_400_000 sat barely above the live table — under a
/// year — which is not a useful default for a value that sizes VPP's
/// main heap at startup.
pub const DEFAULT_EXPECTED_ROUTES: u64 = 1_600_000;

impl VppOffloadConfig {
    pub fn from_directives(directives: &[ModuleDirective]) -> Self {
        let mut out = Self {
            expected_routes: DEFAULT_EXPECTED_ROUTES,
            // Safe by default: absent config must not mean "divert
            // traffic into whatever the mirror happens to hold".
            require_table_complete: true,
            ..Self::default()
        };
        for d in directives {
            match d {
                ModuleDirective::VppPort {
                    iface,
                    cores,
                    steer,
                    ..
                } => out.ports.push((iface.clone(), *cores, *steer)),
                ModuleDirective::VppBinary(p) => out.vpp_binary = Some(p.clone()),
                ModuleDirective::ExpectedRoutes(n) => out.expected_routes = *n,
                ModuleDirective::VppHugepages(n) => out.hugepages = Some(*n),
                ModuleDirective::VppRequireTableComplete(v) => out.require_table_complete = *v,
                ModuleDirective::VppLoopbackAddress(p) => out.loopback_address = Some(*p),
                _ => {}
            }
        }
        out
    }

    /// What in `new` cannot be applied without a restart.
    ///
    /// `Ok(())` means the only differences are ones `reconfigure` can
    /// act on: the per-port `steer` flag and `require-table-complete`,
    /// neither of which VPP knows about. Everything else is fixed at
    /// VPP's start or at VF acquisition, so the honest answer is to
    /// refuse and say so — the alternative is a daemon whose running
    /// configuration silently differs from the file an operator just
    /// edited, which is how the wrong thing gets debugged for an hour.
    ///
    /// A pure function over two configs so the rule is testable without
    /// a VPP, a NIC, or an attachment.
    pub fn restart_only_delta(&self, new: &Self) -> Result<(), String> {
        // Ports are compared as (iface, cores) IN ORDER. Order matters
        // as much as membership: it decides which VF is created on which
        // PF, and `acquire` refuses to adopt across a change to either.
        let old_ports: Vec<(&str, u16)> = self
            .ports
            .iter()
            .map(|(i, c, _)| (i.as_str(), *c))
            .collect();
        let new_ports: Vec<(&str, u16)> =
            new.ports.iter().map(|(i, c, _)| (i.as_str(), *c)).collect();
        if old_ports != new_ports {
            return Err(format!(
                "the `port` lines changed ({old_ports:?} → {new_ports:?}); VF and worker \
                 topology is fixed when VPP starts, so this needs a restart \
                 (`packetframe detach --all`, then start). Only `steer on|off` can change \
                 under a running VPP"
            ));
        }
        if self.expected_routes != new.expected_routes {
            return Err(format!(
                "`expected-routes` changed ({} → {}); it sizes VPP's main heap and stats \
                 segment, both fixed at start. Applying the new ceiling to a VPP running on \
                 the old segments is what aborts it mid-resync — restart to apply",
                self.expected_routes, new.expected_routes
            ));
        }
        if self.hugepages != new.hugepages {
            return Err(format!(
                "`hugepages` changed ({:?} → {:?}); the reservation is made at attach and \
                 VPP maps it at start — restart to apply",
                self.hugepages, new.hugepages
            ));
        }
        if self.loopback_address != new.loopback_address {
            return Err(format!(
                "`loopback-address` changed ({:?} → {:?}); the loopback is created and the \
                 member ports unnumbered to it at attach, and VPP's adjacencies are built \
                 from it — restart to apply",
                self.loopback_address, new.loopback_address
            ));
        }
        if self.vpp_binary != new.vpp_binary {
            return Err(format!(
                "`vpp-binary` changed ({:?} → {:?}); the running VPP is the one that was \
                 spawned — restart to apply",
                self.vpp_binary, new.vpp_binary
            ));
        }
        Ok(())
    }

    /// Total VPP worker threads the config promises, across all ports.
    ///
    /// VPP's thread count is global, not per-interface, and its counter
    /// vectors replicate per thread — so this, not any single port's
    /// `cores`, is what sizes the stats segment
    /// (`startup_conf::derive_sizing`).
    pub fn total_workers(&self) -> u32 {
        self.ports
            .iter()
            .map(|(_, cores, _)| u32::from(*cores))
            .sum()
    }
}

/// The fast-path allowlist, as a live handle rather than a copy.
///
/// A handle because a copy is wrong at exactly one moment, and it is the
/// moment that matters. `attach` reads the allowlist once at startup;
/// `reconfigure` runs on SIGHUP, when the operator has *just changed
/// it*. But the allowlist lives in the fast-path section, and
/// `Module::reconfigure` is handed only its own module's `ModuleConfig`
/// — so a module holding a `Vec` would compare the new steering target
/// against a snapshot of the old allowlist, find no change, and silently
/// do nothing. The one thing SIGHUP exists to do.
///
/// So the loader owns one of these, publishes into it from a single
/// derivation, and hands the same object to the module. There is nothing
/// to keep in sync because there is only one copy.
#[derive(Debug, Default)]
pub struct SharedAllowlist(std::sync::RwLock<Vec<packetframe_common::fib::IpPrefix>>);

impl SharedAllowlist {
    pub fn new(prefixes: Vec<packetframe_common::fib::IpPrefix>) -> Self {
        Self(std::sync::RwLock::new(prefixes))
    }

    /// Replace the whole list. The loader is the only writer.
    pub fn publish(&self, prefixes: Vec<packetframe_common::fib::IpPrefix>) {
        *self.0.write().expect("allowlist lock") = prefixes;
    }

    pub fn get(&self) -> Vec<packetframe_common::fib::IpPrefix> {
        self.0.read().expect("allowlist lock").clone()
    }
}

/// Which interfaces `attach` should ask for their ntuple table.
///
/// Every steering port — unless the allowlist holds nothing this NIC can
/// steer, in which case: none.
///
/// The exception is the whole point. `bring_up` refuses an unsteerable
/// allowlist on the config alone, deliberately *before* any ioctl, so an
/// operator who wrote `steer on` against a v6-only allowlist reads about
/// their allowlist. Querying every steering port here regardless moved
/// the NIC read one layer out and back in front of that refusal, so on
/// an administratively-down port the answer became `EOPNOTSUPP` — a true
/// statement about the wrong problem. Found in review on #132; the
/// ordering `bring_up`'s own comment promises is only real if this
/// function honours it.
///
/// A named function, so the rule is testable without a NIC.
fn ifaces_to_query<'a>(
    cfg: &'a VppOffloadConfig,
    allowlist: &[packetframe_common::fib::IpPrefix],
) -> Vec<&'a str> {
    if steer::steerable_count(allowlist) == 0 {
        return Vec::new();
    }
    cfg.ports
        .iter()
        .filter(|(_, _, steer)| *steer)
        .map(|(iface, _, _)| iface.as_str())
        .collect()
}

/// What steering should look like for a config + allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteeringTarget {
    /// `(PF iface, VF index)` for every port configured `steer on`.
    pub ports: Vec<(String, u32)>,
    /// The rules those ports should hold. Empty when nothing steers.
    pub plan: steer::RuleSet,
    /// Whether traffic should be diverted once the target is in place.
    pub want_steer: bool,
}

/// Derive the steering target.
///
/// A free function so the one rule that is easy to get backwards is
/// testable without an attachment, a VPP or a NIC: **the plan is built
/// only when something is going to be installed.**
///
/// `RuleSet::plan` refuses an allowlist that overruns the MCAM budget,
/// which is right on the way in and wrong on the way out.
/// [`crate::runtime::Steering::unsteer`] removes what the ledger names
/// and never reads the plan, so validating it unconditionally lets an
/// over-budget allowlist block `steer off` — the one reconfigure an
/// operator must always be able to make, since it is how traffic comes
/// off a misbehaving VPP. An allowlist growing past the budget is a
/// plausible way to arrive at wanting exactly that.
fn steering_target(
    cfg: &VppOffloadConfig,
    allowlist: &[packetframe_common::fib::IpPrefix],
) -> Result<SteeringTarget, String> {
    // VF 0 because `acquire` creates exactly one per PF.
    let ports: Vec<(String, u32)> = cfg
        .ports
        .iter()
        .filter(|(_, _, steer)| *steer)
        .map(|(iface, _, _)| (iface.clone(), 0u32))
        .collect();
    let want_steer = !ports.is_empty();
    if !want_steer {
        // Nothing to install and nothing that reads a plan. An empty
        // target is also the truthful one: no port steers.
        return Ok(SteeringTarget {
            ports,
            plan: steer::RuleSet::default(),
            want_steer: false,
        });
    }
    let budget = steer::McamBudget::for_ifaces(ports.iter().map(|(iface, _)| iface.as_str()))?;
    let plan = steer::RuleSet::plan(allowlist, budget)?;
    // `steer on` with nothing steerable is refused for the same reason
    // `bring_up` refuses it: steering would divert nothing while every
    // surface reported it on.
    if plan.rules.is_empty() {
        return Err(format!(
            "port(s) are configured `steer on`, but the allowlist produces no steerable \
             rules ({} IPv6 prefix(es) skipped — `ip6` ntuple is rejected by this NIC). \
             Steering would divert nothing while reporting Healthy",
            plan.skipped_v6
        ));
    }
    Ok(SteeringTarget {
        ports,
        plan,
        want_steer: true,
    })
}

pub struct VppOffloadModule {
    cfg: VppOffloadConfig,
    /// From [`LoaderCtx`] at load; `attach` has no ctx of its own.
    state_dir: std::path::PathBuf,
    /// Where routes and neighbours come from. Set before `attach` by
    /// whoever owns the RouteController; see [`Self::set_route_source`].
    source: Option<Box<dyn engine::RouteSource + Send + Sync>>,
    /// Prefixes steering diverts, inherited from fast-path's allowlist.
    /// Empty until the loader sets it; see [`Self::set_allowlist`].
    allowlist: std::sync::Arc<SharedAllowlist>,
    /// Where the route mirror says how complete it is. `None` until the
    /// loader wires it, which it does only when a route authority
    /// exists; see [`Self::set_completeness`].
    completeness: Option<std::sync::Arc<packetframe_common::fib::TableCompleteness>>,
    /// `Some` once supervision is running.
    attached: Option<bringup::Attached>,
    /// A teardown still running in the background after `detach` returned.
    ///
    /// `stop()` bounds its wait at the `Module::detach` budget and hands
    /// back a handle when the loop has not settled; keeping it is what lets
    /// `health_check` report the eventual result — released, or still held
    /// and why — instead of the message pointing at a status nobody can
    /// reach.
    teardown_pending: Option<service::PendingTeardown>,
    /// VPP's cores and the pre-restriction masks, held across a pending
    /// teardown so `reconcile_pending_teardown` can restore the daemon's
    /// affinity once a late teardown settles clean.
    ///
    /// Without this, a `stop()` that overran the detach budget dropped
    /// `attached` — and with it the `CoreMap`/`AffinitySnapshot` — so a
    /// teardown that finished successfully afterwards left the daemon
    /// confined to a subset of its cores until restart, even though VPP
    /// was gone (review finding).
    deferred_core_release: Option<(cores::CoreMap, cores::AffinitySnapshot)>,
    /// Set when a `detach` could not confirm the teardown.
    ///
    /// Outlives the attachment on purpose. `detach` takes `attached` before
    /// it can discover a failure — the service is consumed by `stop()` — so
    /// without this a second `detach` found `None` and returned `Ok`,
    /// reporting a clean detach over VFs and hugepages that were still
    /// held. `packetframe detach --all` retries, so that is the likely
    /// path, not a hypothetical one.
    teardown_failure: Option<String>,
}

impl VppOffloadModule {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            allowlist: std::sync::Arc::new(SharedAllowlist::default()),
            completeness: None,
            cfg: VppOffloadConfig::default(),
            state_dir: std::path::PathBuf::new(),
            source: None,
            attached: None,
            teardown_pending: None,
            deferred_core_release: None,
            teardown_failure: None,
        }
    }

    /// Hand the module its route source.
    ///
    /// Required before [`Module::attach`], which refuses without one.
    /// That refusal is the point: the source is the fast-path
    /// RouteController's mirror, and a VPP brought up without it would
    /// pass every check this module makes — process alive, API
    /// answering, devices attached, zero routes installed, verify
    /// trivially passing on an empty sample — and then blackhole every
    /// steered packet. An empty FIB is indistinguishable from a healthy
    /// one to everything except the traffic.
    ///
    /// Separate from `load` because the wiring across to the fast-path
    /// crate is its own change (it touches the live control plane); this
    /// is the seam it plugs into.
    pub fn set_route_source(&mut self, source: Box<dyn engine::RouteSource + Send + Sync>) {
        self.source = Some(source);
    }

    /// The prefixes steering diverts, inherited from fast-path.
    ///
    /// A setter rather than config, because the allowlist belongs to the
    /// fast-path section: steered prefixes inherit it rather than
    /// declaring their own, which is what makes "both tiers carry the
    /// same traffic" true by construction instead of by two lists
    /// agreeing. The loader is the only caller — it is the only place
    /// that sees both sections.
    ///
    /// Takes the shared handle, not a snapshot: see [`SharedAllowlist`]
    /// for why a snapshot is wrong on exactly the SIGHUP path.
    pub fn set_allowlist(&mut self, allowlist: std::sync::Arc<SharedAllowlist>) {
        self.allowlist = allowlist;
    }

    /// Hand the module the route mirror's completeness handle.
    ///
    /// The loader sets this when the fast-path has a route authority to
    /// compare against; without it, `require-table-complete on` refuses
    /// at attach rather than refusing every steer forever. Same wiring
    /// as the route feed and the allowlist — the loader is the only
    /// place that sees both modules.
    pub fn set_completeness(
        &mut self,
        handle: std::sync::Arc<packetframe_common::fib::TableCompleteness>,
    ) {
        self.completeness = Some(handle);
    }

    /// Settle a finished background teardown and replace the provisional
    /// verdict with what actually happened.
    ///
    /// `stop()` bounds its wait at the detach budget, so a teardown delayed
    /// by an in-flight API call gets recorded as a failure while it is still
    /// in progress. That verdict is provisional by construction: the loop
    /// runs on under `STOP_PATIENCE` and usually finishes. Without this,
    /// the provisional failure was permanent — `health_check` reported
    /// Unhealthy and every `detach` retried into an error, over resources
    /// that had in fact been released.
    ///
    /// Only consumes the handle once the thread has finished, so a teardown
    /// still in flight keeps being reported as in flight rather than being
    /// waited on inside a health check.
    fn reconcile_pending_teardown(&mut self) {
        let Some(pending) = &self.teardown_pending else {
            return;
        };
        if !pending.is_finished() {
            return;
        }
        let final_status = self
            .teardown_pending
            .take()
            .expect("checked just above")
            .settle();
        // `None` clears the provisional failure: it finished cleanly after
        // all, and the failure was about the budget rather than the outcome.
        self.teardown_failure = settled_verdict(&final_status);
        // A late teardown that settled clean means VPP is finally gone —
        // so the cores held across the budget overrun go back now, with
        // the operator's saved masks. A late teardown that settled dirty
        // keeps them: resources may still be held on those cores.
        if let Some((cm, snap)) = self.deferred_core_release.take() {
            if self.teardown_failure.is_none() {
                if let Err(e) = cores::release_daemon_to(&cm, &snap) {
                    tracing::warn!(error = %e, "could not return VPP's cores to the daemon");
                }
            } else {
                // Dirty settle: hold the cores AND keep the pair, so a
                // later reconcile that flips to clean can still restore.
                self.deferred_core_release = Some((cm, snap));
            }
        }
    }

    /// Record a teardown that could not be confirmed, and build the error
    /// for it. One place, so the recording cannot be forgotten at one of
    /// `detach`'s two failure exits.
    fn remember_teardown_failure(&mut self, why: String) -> ModuleError {
        self.teardown_failure = Some(why.clone());
        ModuleError::other(MODULE_NAME, why)
    }

    /// The last published supervision snapshot, if the loop has run.
    pub fn published(&self) -> Option<service::Published> {
        self.attached.as_ref().and_then(|a| a.service.status())
    }
}

/// What a FINISHED teardown actually amounted to: `Some(reason)` if
/// something is still held, `None` if everything was released.
///
/// Pure, because the alternative is untestable. The verdict recorded when
/// `stop()` times out is provisional — the loop keeps working under its own
/// patience — and getting the reconciliation wrong in the clearing direction
/// reports a leak that does not exist, while getting it wrong the other way
/// reports a clean detach over held VFs. Both need to be checkable without
/// standing up a supervision thread that misses its budget.
fn settled_verdict(final_status: &service::Published) -> Option<String> {
    if !final_status.resources_leaked && final_status.teardown_failures.is_empty() {
        return None;
    }
    Some(format!(
        "teardown finished but did not complete{}{}",
        if final_status.resources_leaked {
            "; VF/hugepage resources are still held"
        } else {
            ""
        },
        if final_status.teardown_failures.is_empty() {
            String::new()
        } else {
            format!(": {}", final_status.teardown_failures.join("; "))
        }
    ))
}

/// Turn a published snapshot into the module's health report.
///
/// Pure, so the reporting rules are testable without a supervision
/// thread — and so the several failure kinds `Published` carries cannot
/// be dropped on the way out, which is exactly what happened to two of
/// them at the publish boundary one layer down.
fn report_from(published: Option<&service::Published>, alive: bool) -> HealthReport {
    use packetframe_common::module::{HealthState, SubsystemHealth};

    let Some(p) = published else {
        // Attached but nothing published yet cannot happen —
        // `SupervisionService::start` blocks on the first publish — so
        // this is the unattached case: loaded, orchestrating nothing.
        return HealthReport::healthy();
    };
    let mut report = p.report.clone();
    fn degrade_to(report: &mut HealthReport, state: HealthState) {
        report.overall = report.overall.worse_of(state);
    }

    // A dead loop thread means nothing is supervising VPP. The last
    // published report is frozen at whatever it said, so reporting it
    // as-is would show a healthy dataplane nobody is watching.
    if !alive {
        degrade_to(&mut report, HealthState::Unhealthy);
        report.subsystems.push(SubsystemHealth {
            name: "supervision".into(),
            state: HealthState::Unhealthy,
            message: Some(
                "the supervision loop is not running; VPP is unmonitored and will not be \
                 restarted or unsteered — `packetframe detach` then re-attach"
                    .into(),
            ),
            last_success_age_seconds: None,
        });
    }
    // Supervision ended itself: an API this VPP can never speak. Not a
    // transient failure and not retried, so it must not read as one.
    if let Some(why) = &p.terminal {
        degrade_to(&mut report, HealthState::Unhealthy);
        report.subsystems.push(SubsystemHealth {
            name: "supervision".into(),
            state: HealthState::Unhealthy,
            message: Some(format!("supervision ended and will not resume: {why}")),
            last_success_age_seconds: None,
        });
    }
    // Held resources after a teardown. Deliberate — releasing a VF a
    // live process may still DMA into is worse — but it needs an
    // operator, because nothing else will ever free them.
    if p.resources_leaked {
        degrade_to(&mut report, HealthState::Unhealthy);
        report.subsystems.push(SubsystemHealth {
            name: "resources".into(),
            state: HealthState::Unhealthy,
            message: Some(format!(
                "VF/hugepage resources are still held after teardown{}",
                if p.teardown_failures.is_empty() {
                    String::new()
                } else {
                    format!(": {}", p.teardown_failures.join("; "))
                }
            )),
            last_success_age_seconds: None,
        });
    }
    // The reason behind a retry loop. The supervisor counts failures;
    // only this says what they were.
    if !p.last_failures.is_empty() {
        degrade_to(&mut report, HealthState::Degraded);
        report.subsystems.push(SubsystemHealth {
            name: "last-tick".into(),
            state: HealthState::Degraded,
            message: Some(p.last_failures.join("; ")),
            last_success_age_seconds: None,
        });
    }
    report
}

impl Module for VppOffloadModule {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    /// No BPF hooks: the first exercise of the multi-vector Module
    /// contract. The loader must treat an empty hook set as valid.
    fn hook_spec(&self) -> Vec<HookUse> {
        Vec::new()
    }

    fn load(&mut self, cfg: &ModuleConfig<'_>, ctx: &LoaderCtx<'_>) -> ModuleResult<()> {
        self.cfg = VppOffloadConfig::from_directives(&cfg.section.directives);
        // `attach` gets no ctx of its own, and the state file is the
        // whole basis of adoption and of `detach --all` — so capture the
        // directory here rather than assuming a default location.
        self.state_dir = ctx.state_dir.to_path_buf();
        if self.cfg.ports.is_empty() {
            return Err(ModuleError::other(
                MODULE_NAME,
                "module vpp-offload declares no `port` lines; nothing to orchestrate",
            ));
        }
        // Cross-section membership/steering/custom-fib validation runs
        // at the Config level (`Config::validate_vpp_offload`) where
        // the fast-path section is visible; by load time it has passed.
        // Here: validate the sizing arithmetic so a too-small
        // `hugepages` is a clean startup error, not a VPP init abort.
        let sizing =
            startup_conf::derive_sizing(self.cfg.expected_routes, self.cfg.total_workers())
                .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        if let Some(pages) = self.cfg.hugepages {
            startup_conf::check_hugepage_budget(&sizing, pages, default_hugepage_bytes())
                .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        }
        Ok(())
    }

    /// hugepages → VF → vfio → startup.conf → adopt-or-arm → supervise.
    ///
    /// Returns **no [`Attachment`]s**: the module owns no BPF programs
    /// or links, which is what `hook_spec() == []` already declares. Its
    /// attachment is a supervised process and a set of held host
    /// resources, both tracked in the state file rather than in the
    /// loader's registry.
    ///
    /// Blocks only until the supervision loop publishes its first
    /// snapshot — long enough for a dead API socket or a version-skewed
    /// VPP to surface here as the attach failure it is, and no longer.
    /// Convergence (up to the ≤60 s budget) continues on the loop
    /// thread; `health_check` reports where it got to.
    fn attach(&mut self, _cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
        if self.attached.is_some() {
            return Err(ModuleError::other(
                MODULE_NAME,
                "vpp-offload is already attached; detach first",
            ));
        }
        // A previous teardown must be RESOLVED before another attach.
        //
        // `detach` takes `attached` before it can discover a failure, so
        // `attached.is_none()` is not evidence that nothing is going on: the
        // background loop may still be killing VPP and releasing the VF, or a
        // recorded failure may mean resources are still held. Attaching over
        // either starts a new supervisor against hardware the old teardown is
        // concurrently releasing — two supervisors, one VF — and even after a
        // clean background finish the stale handle would make `health_check`
        // report the old teardown instead of the new attachment.
        self.reconcile_pending_teardown();
        if self.teardown_pending.is_some() {
            return Err(ModuleError::other(
                MODULE_NAME,
                "a previous teardown is still running in the background (it kills VPP and                  releases its VF); attaching now would race it. Wait for it to settle —                  `health_check` reports when it has — and retry.",
            ));
        }
        if let Some(why) = &self.teardown_failure {
            return Err(ModuleError::other(
                MODULE_NAME,
                format!(
                    "a previous teardown did not complete, so its resources may still be                      held: {why}. Resolve that first (`packetframe detach --all` once VPP                      is confirmed gone); attaching over it would put a second supervisor on                      the same VF."
                ),
            ));
        }
        let source = self.source.take().ok_or_else(|| {
            ModuleError::other(
                MODULE_NAME,
                "no route source is wired to vpp-offload; refusing to attach — VPP would come \
                 up with an empty FIB, pass every health check, and blackhole every steered \
                 packet (see `set_route_source`)",
            )
        })?;
        // `load` supplies the state directory, and the state file is the
        // whole basis of adoption and of `detach --all`. Without it,
        // `AttachPaths::live` would build a RELATIVE state path — a
        // record written into whatever the daemon's cwd happens to be,
        // which the next start would not find and no detach could act on.
        // Reachable only by attaching an unloaded module, which is a
        // programming error, so it says so.
        if self.state_dir.as_os_str().is_empty() {
            return Err(ModuleError::other(
                MODULE_NAME,
                "attach() called before load(): no state directory, so nothing acquired could \
                 be recorded or later released",
            ));
        }
        let paths = bringup::AttachPaths::live(&self.state_dir, default_hugepage_bytes());
        // The NIC is asked here rather than inside `bring_up`, which
        // keeps its pure phase pure: planning slots is arithmetic, and
        // which slots exist is an environment read like every other one
        // this function performs before delegating.
        let allowlist = self.allowlist.get();
        let budget = match steer::McamBudget::for_ifaces(ifaces_to_query(&self.cfg, &allowlist)) {
            Ok(b) => b,
            Err(e) => return Err(ModuleError::other(MODULE_NAME, e)),
        };
        let attached = match bringup::bring_up(
            &self.cfg,
            &paths,
            source,
            &allowlist,
            self.completeness.clone(),
            &budget,
        ) {
            Ok(a) => a,
            Err(e) => return Err(ModuleError::other(MODULE_NAME, e)),
        };
        // The derived worker placement, logged because it is an operator
        // input: on the reference NIC every CPU carries an rx-queue IRQ
        // 1:1, so nothing this module can do keeps a poll-mode worker off
        // one — moving the PF IRQs is manual, and this names the set to
        // move them off. See [`cores`].
        tracing::info!(
            main_core = attached.cores.main,
            workers = ?attached.cores.workers,
            acquired = ?attached.acquired,
            adopted_process = attached.adopted_process,
            "vpp-offload attached; move PF IRQ affinity off the worker cores"
        );
        self.attached = Some(attached);
        Ok(Vec::new())
    }

    /// Allowlist and `steer on|off` deltas become MCAM deltas.
    ///
    /// This is the canary lever. The rollout turns it port by port, and
    /// its rollback turns it back — so it must not cost a VPP restart:
    /// that would be ~40 s of resync with the offload down, per step,
    /// including the step whose whole purpose is to get traffic OFF a
    /// misbehaving VPP quickly.
    ///
    /// Everything else in the section is restart-only, and refused with
    /// the reason rather than silently ignored. `port` and `cores` are
    /// VF and thread topology that VPP fixes at start (and `acquire`
    /// refuses to adopt across); `expected-routes` sizes the main heap
    /// and the stats segment, which VPP also fixes at start — applying a
    /// raised ceiling to a VPP running on the old segments is the
    /// mid-resync OOM abort gate 0b found; `vpp-binary` and `hugepages`
    /// likewise only mean anything at spawn.
    fn reconfigure(&mut self, cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
        let new = VppOffloadConfig::from_directives(&cfg.section.directives);
        if let Err(why) = self.cfg.restart_only_delta(&new) {
            return Err(ModuleError::other(MODULE_NAME, why));
        }

        // Nothing to steer into. Not an error: a config with every port
        // `steer off` and no attachment is a legitimate state, and so is
        // a SIGHUP arriving between `load` and `attach`.
        let Some(attached) = &self.attached else {
            self.cfg = new;
            return Ok(());
        };

        let target = steering_target(&new, &self.allowlist.get())
            .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        // Did the operator actually turn the lever, or does the config
        // merely still say `steer on`?
        //
        // The two must not look the same. A `steer on` port that has
        // never steered is in the designed staging state, and a SIGHUP
        // for an unrelated reason — an added `allow-prefix`, a changed
        // global — must not divert its traffic as a side effect. Only the
        // flag moving is the operator asking.
        //
        // Positional comparison is sound because `restart_only_delta`
        // has already established the port list is identical, in order.
        let lever_moved = self
            .cfg
            .ports
            .iter()
            .map(|(_, _, steer)| *steer)
            .ne(new.ports.iter().map(|(_, _, steer)| *steer));
        attached
            .service
            .apply_steering(target.ports, target.plan, target.want_steer, lever_moved)
            .map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        // Recorded only after the change landed. A `cfg` updated ahead of
        // the apply would make the NEXT reconfigure diff against a target
        // that was never installed, so a failed canary step would look
        // like a no-op change and never be retried.
        self.cfg = new;
        Ok(())
    }

    fn detach(&mut self) -> ModuleResult<()> {
        // Reconcile a background teardown before answering. The failure
        // recorded when `stop()` timed out is PROVISIONAL: the loop kept
        // working under its own patience and may have released everything
        // after `detach` returned. Reporting the provisional failure forever
        // — which is what happens without this — makes an
        // otherwise-successful teardown permanently Unhealthy and every
        // retry an error, purely because an in-flight API call pushed it
        // past the 900 ms budget.
        self.reconcile_pending_teardown();
        // A teardown that really did fail keeps failing. The service is
        // consumed by `stop()`, so there is nothing left to retry — but
        // answering `Ok` because `attached` is now `None` would report a
        // clean detach over resources that are still held, on exactly the
        // retry an operator is most likely to run.
        if let Some(why) = &self.teardown_failure {
            return Err(ModuleError::other(MODULE_NAME, why.clone()));
        }
        // Detach of nothing succeeds, so `packetframe detach --all`
        // stays idempotent.
        let Some(attached) = self.attached.take() else {
            return Ok(());
        };
        // Captured before `stop()` consumes the service, because the
        // affinity restore needs them on every exit — including the one
        // where `stop()` overruns and `attached` is gone by the time the
        // teardown settles.
        let core_release = (attached.cores.clone(), attached.affinity.clone());
        // `stop` drives the supervisor's full teardown ordering —
        // unsteer if steered, abort convergence, kill, release — and
        // waits out its bounded patience. The final snapshot is the only
        // record of what that left behind.
        let report = attached.service.stop();
        // A teardown still running past the detach budget is kept, not
        // dropped: `stop()`'s message sends the operator to `packetframe
        // status`, and this is what makes that reachable — `health_check`
        // below reports through it until the loop settles.
        if report.pending.is_some() {
            // Hand the cores to reconciliation, which runs when the loop
            // finally settles: releasing now would return them while VPP
            // may still be alive on them.
            self.deferred_core_release = Some(core_release.clone());
        }
        self.teardown_pending = report.pending;
        let Some(p) = report.published else {
            return Err(self.remember_teardown_failure(
                "the supervision loop published no final status; whether VPP stopped and \
                 whether its VFs were released are both unknown — check `ip link show` and \
                 the state file before re-attaching"
                    .to_string(),
            ));
        };
        if p.resources_leaked || !p.teardown_failures.is_empty() {
            // Loud, and NOT converted into a clean detach. The resources
            // are deliberately still held (releasing a VF a live process
            // may still DMA into is worse), but only an operator can
            // finish this.
            return Err(self.remember_teardown_failure(format!(
                "teardown did not complete{}{}",
                if p.resources_leaked {
                    "; VF/hugepage resources are still held"
                } else {
                    ""
                },
                if p.teardown_failures.is_empty() {
                    String::new()
                } else {
                    format!(": {}", p.teardown_failures.join("; "))
                }
            )));
        }
        // The teardown completed synchronously and released everything:
        // no VPP is left to protect, so the daemon gets its cores back
        // with the operator's pre-restriction masks. This path did not
        // stash into `deferred_core_release` (pending was None), so there
        // is nothing there to double-release.
        let (cm, snap) = &core_release;
        if let Err(e) = cores::release_daemon_to(cm, snap) {
            tracing::warn!(error = %e, "could not return VPP's cores to the daemon");
        }
        Ok(())
    }

    fn sample_metrics(&self, out: &mut MetricsWriter<'_>) -> ModuleResult<()> {
        // Only what the loop actually published. An unattached module
        // emits nothing rather than zeroed gauges — a zero series is
        // indistinguishable from a healthy idle one, and would keep
        // reporting after a detach.
        if let Some(p) = self.published() {
            out.out.push_str(&p.metrics);
        }
        Ok(())
    }

    fn health_check(&self, _ctx: &HealthCtx) -> ModuleResult<HealthReport> {
        // A teardown still in flight outranks a recorded failure: it is
        // the more current fact, and it may yet resolve to success.
        if let Some(pending) = &self.teardown_pending {
            use packetframe_common::module::{HealthState, SubsystemHealth};
            let settled = pending.is_finished();
            // `&self` cannot consume the handle, so this reports what the
            // loop has published so far. A finished teardown that released
            // everything is reconciled — and the provisional failure
            // cleared — on the next `detach`; see
            // `reconcile_pending_teardown`.
            let detail = pending
                .status()
                .map(|p| {
                    if p.resources_leaked || !p.teardown_failures.is_empty() {
                        format!("resources still held: {}", p.teardown_failures.join("; "))
                    } else {
                        "everything was released".into()
                    }
                })
                .unwrap_or_else(|| "no snapshot published".into());
            return Ok(HealthReport {
                overall: HealthState::Unhealthy,
                subsystems: vec![SubsystemHealth {
                    name: "resources".into(),
                    state: HealthState::Unhealthy,
                    message: Some(if settled {
                        format!("teardown finished after detach returned; {detail}")
                    } else {
                        format!("teardown still running after detach returned; {detail}")
                    }),
                    last_success_age_seconds: None,
                }],
            });
        }
        // An unconfirmed teardown outranks everything else. The module is
        // no longer attached, so there is no snapshot left to report, and
        // `report_from(None, _)` answers "loaded, orchestrating nothing" —
        // which over still-held VFs is the same lie the `detach` retry used
        // to tell.
        if let Some(why) = &self.teardown_failure {
            use packetframe_common::module::{HealthState, SubsystemHealth};
            return Ok(HealthReport {
                overall: HealthState::Unhealthy,
                subsystems: vec![SubsystemHealth {
                    name: "resources".into(),
                    state: HealthState::Unhealthy,
                    message: Some(why.clone()),
                    last_success_age_seconds: None,
                }],
            });
        }
        let alive = self.attached.as_ref().is_some_and(|a| a.service.is_alive());
        Ok(report_from(self.published().as_ref(), alive))
    }
}

/// Feasibility probes for `packetframe feasibility`, mirroring how the
/// fast-path's per-interface probes graft into the report. All
/// non-required: feasibility output informs, attach enforces.
pub fn run_feasibility_probes(
    ports: &[String],
    vpp_binary: Option<&str>,
    allowlist: &[packetframe_common::fib::IpPrefix],
) -> Vec<Capability> {
    #[cfg(target_os = "linux")]
    {
        probe_linux::run(ports, vpp_binary, allowlist)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (ports, vpp_binary, allowlist);
        Vec::new()
    }
}

/// Default hugepage size in bytes, from /proc/meminfo `Hugepagesize`.
/// Non-Linux and read failures return 0, which the budget check treats
/// as "unknown — skip the byte-accurate comparison" (feasibility will
/// flag the platform anyway).
pub fn default_hugepage_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        probe_linux::default_hugepage_bytes()
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::module::{HealthState, SubsystemHealth};
    use supervisor::State;

    struct NoRoutes;
    impl engine::RouteSource for NoRoutes {
        fn for_each_route(
            &self,
            _: &mut dyn FnMut(packetframe_common::fib::IpPrefix, &[std::net::IpAddr]),
        ) {
        }
        fn for_each_neighbour(&self, _: &mut dyn FnMut(std::net::IpAddr, &str, [u8; 6])) {}
        fn route_count(&self) -> u64 {
            0
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }

    /// A published snapshot the loop would produce in the designed
    /// resting state: verified, nothing steered, nothing wrong.
    fn healthy_published() -> service::Published {
        service::Published {
            report: HealthReport::healthy(),
            metrics: String::new(),
            state: State::Ready,
            api_error: None,
            terminal: None,
            teardown_failures: Vec::new(),
            resources_leaked: false,
            last_failures: Vec::new(),
            store_error: None,
        }
    }

    /// `attach` asks no NIC when the allowlist has nothing steerable.
    ///
    /// The ordering is the assertion. `bring_up` refuses an unsteerable
    /// allowlist on the config alone, deliberately ahead of any ioctl, so
    /// that an operator who wrote `steer on` against a v6-only allowlist
    /// reads about their allowlist rather than about `EOPNOTSUPP` from a
    /// port that happens to be down. Querying unconditionally here put
    /// the NIC read back in front of that refusal — found in review, and
    /// invisible to every other test because both paths still refuse.
    #[test]
    fn nothing_steerable_means_no_nic_is_asked() {
        let cfg = VppOffloadConfig {
            ports: vec![("eth4".into(), 1, true), ("eth5".into(), 1, false)],
            ..VppOffloadConfig::default()
        };
        let v6_only = [packetframe_common::fib::IpPrefix::V6 {
            addr: [0x26, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 32,
        }];
        assert!(
            ifaces_to_query(&cfg, &v6_only).is_empty(),
            "a v6-only allowlist is a config error; asking a NIC first answers the wrong question"
        );
        assert!(
            ifaces_to_query(&cfg, &[]).is_empty(),
            "and so is an empty one"
        );

        // With something steerable, only the steering ports are asked —
        // `steer off` is the staging state and installs nothing, so its
        // table is not a constraint on the plan.
        let v4 = [packetframe_common::fib::IpPrefix::V4 {
            addr: [10, 88, 1, 0],
            prefix_len: 24,
        }];
        assert_eq!(ifaces_to_query(&cfg, &v4), vec!["eth4"]);
    }

    /// An unattached module orchestrates nothing, and says so honestly
    /// rather than inventing a fault.
    #[test]
    fn nothing_attached_reports_healthy() {
        assert_eq!(report_from(None, false).overall, HealthState::Healthy);
    }

    /// A dead loop thread is the worst thing this surface can report:
    /// the last published snapshot is frozen, so it may well say
    /// "Healthy, steered, verified" — about a VPP that will never be
    /// restarted, never unsteered, and never observed again.
    #[test]
    fn a_dead_supervision_thread_is_unhealthy_and_named() {
        let p = healthy_published();
        let r = report_from(Some(&p), false);
        assert_eq!(r.overall, HealthState::Unhealthy, "{r:?}");
        let s = r
            .subsystems
            .iter()
            .find(|s| s.name == "supervision")
            .expect("the dead loop must be named");
        assert_eq!(s.state, HealthState::Unhealthy);
        assert!(
            s.message
                .as_deref()
                .unwrap_or_default()
                .contains("unmonitored"),
            "{s:?}"
        );
    }

    /// A terminal reason means supervision ENDED. Reporting it as an
    /// ordinary degradation would read as "retrying", which is exactly
    /// what it is not.
    #[test]
    fn a_terminal_reason_is_unhealthy_and_says_it_will_not_resume() {
        let mut p = healthy_published();
        p.terminal = Some("VPP's API is permanently incompatible: CRC mismatch".into());
        let r = report_from(Some(&p), true);
        assert_eq!(r.overall, HealthState::Unhealthy);
        assert!(
            r.subsystems.iter().any(|s| s
                .message
                .as_deref()
                .unwrap_or_default()
                .contains("will not resume")),
            "{r:?}"
        );
    }

    /// Leaked resources need an operator: nothing else will ever free
    /// them, and the state file is the only record that they exist.
    #[test]
    fn leaked_resources_are_unhealthy_and_carry_the_teardown_detail() {
        let mut p = healthy_published();
        p.resources_leaked = true;
        p.teardown_failures = vec!["Unsteer: MCAM rules could not be removed".into()];
        let r = report_from(Some(&p), true);
        assert_eq!(r.overall, HealthState::Unhealthy);
        let s = r
            .subsystems
            .iter()
            .find(|s| s.name == "resources")
            .expect("held resources must be named");
        assert!(
            s.message
                .as_deref()
                .unwrap_or_default()
                .contains("MCAM rules"),
            "the teardown reason must survive: {s:?}"
        );
    }

    /// The supervisor counts failures; only `last_failures` says what
    /// they were. Dropping it leaves an operator watching a retry loop
    /// with no way to learn why.
    #[test]
    fn tick_failures_degrade_and_are_reported_verbatim() {
        let mut p = healthy_published();
        p.last_failures = vec!["Start: no such file or directory".into()];
        let r = report_from(Some(&p), true);
        assert_eq!(r.overall, HealthState::Degraded);
        assert!(
            r.subsystems.iter().any(|s| s.name == "last-tick"
                && s.message.as_deref() == Some("Start: no such file or directory")),
            "{r:?}"
        );
    }

    /// An unresolved teardown must block another attach.
    ///
    /// `detach` takes `attached` before it can discover a failure, so
    /// `attached.is_none()` is not evidence that nothing is happening. A
    /// caller that rewires the route source and retries `attach` would start a
    /// second supervisor against a VF the previous teardown may still be
    /// releasing.
    #[test]
    fn a_failed_teardown_blocks_a_reattach() {
        use packetframe_common::config::{GlobalConfig, ModuleSection};
        use packetframe_common::module::{Module as _, ModuleConfig};

        let mut m = VppOffloadModule::new();
        m.state_dir = std::path::PathBuf::from("/tmp/pf-reattach-guard");
        m.set_route_source(Box::new(NoRoutes));
        let _ = m.remember_teardown_failure(
            "teardown did not complete; VF/hugepage resources are still held".to_string(),
        );

        let section = ModuleSection {
            name: "vpp-offload".into(),
            directives: Vec::new(),
        };
        let global = GlobalConfig::default();
        let e = m
            .attach(&ModuleConfig::new(&section, &global))
            .expect_err("must refuse while the teardown is unresolved");
        let msg = e.to_string();
        assert!(msg.contains("did not complete"), "{msg}");
        assert!(
            msg.contains("second supervisor"),
            "the consequence must be stated: {msg}"
        );
    }

    /// A teardown that finished cleanly clears the provisional failure.
    ///
    /// `stop()` records a failure when it times out, but that verdict is
    /// about the BUDGET, not the outcome: the loop keeps working under its
    /// own patience and usually finishes. Without reconciliation the
    /// provisional failure was permanent — health Unhealthy forever and
    /// every retry an error — over resources that had in fact been released.
    #[test]
    fn a_clean_finish_clears_the_provisional_failure() {
        let clean = healthy_published();
        assert!(
            settled_verdict(&clean).is_none(),
            "a teardown that released everything must not stay reported as failed"
        );
    }

    /// And a teardown that finished BADLY must be reported, with the detail.
    /// Clearing on any finish would report a clean detach over held VFs,
    /// which is the opposite and worse mistake.
    #[test]
    fn a_dirty_finish_is_reported_with_its_detail() {
        let mut leaked = healthy_published();
        leaked.resources_leaked = true;
        leaked.teardown_failures = vec!["Unsteer: rules could not be removed".into()];
        let why = settled_verdict(&leaked).expect("must be reported");
        assert!(why.contains("still held"), "{why}");
        assert!(why.contains("Unsteer"), "the detail must survive: {why}");

        // Failures without the leak flag still count: the teardown said
        // something went wrong.
        let mut failed = healthy_published();
        failed.teardown_failures = vec!["Kill: process did not exit".into()];
        assert!(settled_verdict(&failed).is_some());
    }

    /// A `detach` that could not confirm the teardown must keep saying so.
    ///
    /// `detach` takes `attached` before it can discover a failure — the
    /// service is consumed by `stop()` — so the second call found `None`
    /// and answered `Ok`, reporting a clean detach over VFs and hugepages
    /// that were still held. `packetframe detach --all` retries, which
    /// makes that the likely path rather than a hypothetical one.
    ///
    /// Driven through the recorder rather than a real teardown: reaching a
    /// failed `stop()` needs a supervision thread, and what is under test
    /// is that the record OUTLIVES the attachment.
    #[test]
    fn an_unconfirmed_teardown_keeps_failing_and_stays_unhealthy() {
        use packetframe_common::config::{GlobalConfig, ModuleSection};
        use packetframe_common::module::{Module as _, ModuleConfig};

        let mut m = VppOffloadModule::new();
        let e = m.remember_teardown_failure(
            "teardown did not complete; VF/hugepage resources are still held".to_string(),
        );
        assert!(e.to_string().contains("still held"));

        // The retry must NOT read as a clean detach just because there is
        // no attachment left.
        let again = m
            .detach()
            .expect_err("a retry after an unconfirmed teardown must not report success");
        assert!(again.to_string().contains("still held"), "{again}");

        // And health must not read as "loaded, orchestrating nothing".
        let r = m.health_check(&HealthCtx::new()).unwrap();
        assert_eq!(r.overall, HealthState::Unhealthy, "{r:?}");
        assert!(
            r.subsystems.iter().any(|s| s.name == "resources"
                && s.message
                    .as_deref()
                    .is_some_and(|x| x.contains("still held"))),
            "{:?}",
            r.subsystems
        );

        // Re-attaching must not paper over it either: the route-source
        // refusal comes first, but the record is still there afterwards.
        let section = ModuleSection {
            name: "vpp-offload".into(),
            directives: Vec::new(),
        };
        let global = GlobalConfig::default();
        let _ = m.attach(&ModuleConfig::new(&section, &global));
        assert!(m.teardown_failure.is_some(), "the record was lost");
    }

    /// The invariant, asserted as an invariant: whatever this function
    /// adds, the result may never be cheerier than the worst thing in
    /// it. A `match` that escalated only from `Healthy` — the shape this
    /// replaced — would silently downgrade an Unhealthy report to
    /// Degraded when a tick failure arrived after a leak.
    #[test]
    fn the_overall_state_is_never_cheerier_than_its_worst_finding() {
        let mut p = healthy_published();
        p.report.overall = HealthState::Unhealthy;
        p.report.subsystems.push(SubsystemHealth {
            name: "vpp-process".into(),
            state: HealthState::Unhealthy,
            message: None,
            last_success_age_seconds: None,
        });
        // A merely-Degraded finding arrives on top of an Unhealthy
        // report.
        p.last_failures = vec!["Resync: socket closed".into()];
        let r = report_from(Some(&p), true);
        assert_eq!(r.overall, HealthState::Unhealthy, "{r:?}");

        for worst in [HealthState::Degraded, HealthState::Unhealthy] {
            let mut p = healthy_published();
            p.report.subsystems.push(SubsystemHealth {
                name: "x".into(),
                state: worst,
                message: None,
                last_success_age_seconds: None,
            });
            p.report.overall = worst;
            let r = report_from(Some(&p), true);
            assert_eq!(r.overall, worst, "a clean pass must not improve {worst:?}");
        }
    }

    /// `worse_of` is the ordering the report relies on; check it directly
    /// rather than only through its callers.
    #[test]
    fn severity_escalates_in_one_direction_only() {
        use HealthState::*;
        for (a, b, want) in [
            (Healthy, Degraded, Degraded),
            (Degraded, Healthy, Degraded),
            (Degraded, Unhealthy, Unhealthy),
            (Unhealthy, Degraded, Unhealthy),
            (Unhealthy, Healthy, Unhealthy),
            (Healthy, Healthy, Healthy),
        ] {
            assert_eq!(a.worse_of(b), want, "{a:?}.worse_of({b:?})");
        }
    }

    fn cfg(ports: &[(&str, u16, bool)], routes: u64) -> VppOffloadConfig {
        VppOffloadConfig {
            ports: ports
                .iter()
                .map(|(i, c, s)| (i.to_string(), *c, *s))
                .collect(),
            vpp_binary: None,
            expected_routes: routes,
            hugepages: None,
            require_table_complete: true,
            loopback_address: Some(packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
                prefix_len: 32,
            }),
        }
    }

    /// The `steer` flag is the ONLY thing a SIGHUP may change.
    ///
    /// It has to be: it is the canary lever, and the rollout turns it
    /// port by port. Making it restart-only would cost ~40 s of resync
    /// with the offload down per rollout step — including the rollback
    /// step, whose whole purpose is to get traffic off a misbehaving VPP
    /// quickly.
    #[test]
    fn flipping_the_canary_lever_is_not_a_restart() {
        let before = cfg(&[("eth4", 1, false), ("eth5", 1, false)], 1_600_000);
        let after = cfg(&[("eth4", 1, false), ("eth5", 1, true)], 1_600_000);
        before
            .restart_only_delta(&after)
            .expect("steer on|off must be applicable under a running VPP");
    }

    /// Everything VPP fixes at start is refused, and says which knob and
    /// what to do.
    ///
    /// Silently ignoring any of these is the failure mode that matters:
    /// the daemon's running configuration would differ from the file the
    /// operator just edited, with nothing anywhere saying so.
    #[test]
    fn everything_fixed_at_start_is_refused_by_name() {
        let base = cfg(&[("eth4", 1, false)], 1_600_000);

        for (new, needle) in [
            (
                cfg(&[("eth4", 1, false), ("eth5", 1, false)], 1_600_000),
                "`port` lines changed",
            ),
            (
                cfg(&[("eth4", 2, false)], 1_600_000),
                "`port` lines changed",
            ),
            (
                cfg(&[("eth4", 1, false)], 2_000_000),
                "`expected-routes` changed",
            ),
        ] {
            let e = base.restart_only_delta(&new).expect_err("must refuse");
            assert!(e.contains(needle), "{e}");
            assert!(
                e.contains("restart"),
                "the operator needs to be told what to DO about it: {e}"
            );
        }

        let mut pages = base.clone();
        pages.hugepages = Some(12);
        assert!(base
            .restart_only_delta(&pages)
            .expect_err("hugepages")
            .contains("`hugepages` changed"));

        let mut binary = base.clone();
        binary.vpp_binary = Some("/opt/vpp/bin/vpp".into());
        assert!(base
            .restart_only_delta(&binary)
            .expect_err("vpp-binary")
            .contains("`vpp-binary` changed"));
    }

    /// A reordered port list is a change, not a permutation.
    ///
    /// Order decides which VF is created on which PF, and `acquire`
    /// refuses to adopt across it — so accepting it here would produce a
    /// reconfigure that reports OK and a next start that refuses.
    #[test]
    fn reordering_the_ports_is_a_restart() {
        let before = cfg(&[("eth4", 1, false), ("eth5", 1, false)], 1_600_000);
        let after = cfg(&[("eth5", 1, false), ("eth4", 1, false)], 1_600_000);
        assert!(before.restart_only_delta(&after).is_err());
    }

    /// The shared allowlist is a window, not a copy.
    ///
    /// The defect it exists to prevent: `reconfigure` is handed only its
    /// own module's section, so a module holding a `Vec` would compare
    /// the new steering target against the allowlist as it was at
    /// startup, find no change, and report OK for the one thing SIGHUP
    /// was raised to do.
    #[test]
    fn a_republished_allowlist_is_visible_through_the_handle() {
        use packetframe_common::fib::IpPrefix;
        let v4 = |a: u8| IpPrefix::V4 {
            addr: [10, a, 0, 0],
            prefix_len: 16,
        };
        let shared = std::sync::Arc::new(SharedAllowlist::new(vec![v4(0)]));

        let mut m = VppOffloadModule::new();
        m.set_allowlist(shared.clone());
        assert_eq!(m.allowlist.get(), vec![v4(0)]);

        // What the loader does on SIGHUP, from the whole new config.
        shared.publish(vec![v4(0), v4(1)]);
        assert_eq!(
            m.allowlist.get(),
            vec![v4(0), v4(1)],
            "the module must see the republished list without being handed anything"
        );
    }

    /// An over-budget allowlist must never block `steer off`.
    ///
    /// `RuleSet::plan` refuses an allowlist bigger than the MCAM budget,
    /// which is correct when rules are about to be installed. Validating
    /// it on the way OUT blocks the one reconfigure an operator must
    /// always be able to make — turning traffic off a misbehaving VPP —
    /// and `unsteer` never reads the plan anyway. An allowlist growing
    /// past the budget is a plausible route to wanting exactly that
    /// rollback.
    #[test]
    fn an_over_budget_allowlist_does_not_block_the_rollback() {
        use packetframe_common::fib::IpPrefix;
        // The default budget is 512 slots at two rules per prefix, so
        // 300 v4 prefixes cannot fit.
        let allow: Vec<IpPrefix> = (0..300u32)
            .map(|i| IpPrefix::V4 {
                addr: [10, (i >> 8) as u8, (i & 0xff) as u8, 0],
                prefix_len: 24,
            })
            .collect();

        // Steering ON is refused, and names the true requirement.
        let on = cfg(&[("eth4", 1, true)], 1_600_000);
        let e = steering_target(&on, &allow).expect_err("cannot fit");
        assert!(e.contains("600 MCAM rule(s)"), "{e}");

        // Steering OFF succeeds with the same allowlist. This is the
        // assertion that matters: the rollback path must not consult a
        // budget it does not spend.
        let off = cfg(&[("eth4", 1, false)], 1_600_000);
        let t = steering_target(&off, &allow).expect("rollback must be possible");
        assert!(t.ports.is_empty() && !t.want_steer);
        assert!(
            t.plan.rules.is_empty(),
            "and it carries an empty target, which is what no port steering means"
        );
    }

    /// A `steer on` port with a v6-only allowlist is refused, not
    /// silently accepted as steering nothing.
    #[test]
    fn steer_on_with_nothing_steerable_is_refused() {
        use packetframe_common::fib::IpPrefix;
        let allow = vec![IpPrefix::V6 {
            addr: [0x26, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 32,
        }];
        let on = cfg(&[("eth4", 1, true)], 1_600_000);
        let e = steering_target(&on, &allow).expect_err("must refuse");
        assert!(e.contains("no steerable rules"), "{e}");
        assert!(
            e.contains("reporting Healthy"),
            "the consequence has to be stated: {e}"
        );
    }
}
