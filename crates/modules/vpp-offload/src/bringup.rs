//! `Module::attach()`, as a function of its inputs.
//!
//! Every layer below this exists and is tested; this is where they are
//! composed into one sequence. It is a free function taking its host
//! paths rather than a method reaching for `/sys` and `/run`, so the
//! whole thing — the refusals, the ordering, the rollback — runs against
//! a tempdir on a dev laptop. [`crate::VppOffloadModule::attach`] calls
//! it with the live paths and keeps the returned handle.
//!
//! ## The sequence, and what each step protects
//!
//! ```text
//! derive sizing + core map     pure; no mutation yet, so a bad config
//!                              costs nothing
//! acquire hugepages → VF → vfio   rollback-safe, state file per step
//! render + write startup.conf  the last thing before a process could exist
//! adopt (only if the record names a live VPP)
//! start the supervision loop   which does the spawning, if any
//! ```
//!
//! **Nothing here spawns VPP.** The supervisor owns that: `attach`
//! injects `StartRequested` and the loop's `Start` action spawns,
//! records the identity, and arms backoff on failure. Spawning here
//! instead would duplicate that path — and duplicate it in the one
//! direction that matters, since a spawn this function performed and
//! then failed to hand over would be a VPP nothing supervises, holding a
//! VF nothing can release.
//!
//! Adoption is the exception, because it is an *observation* rather than
//! an action: whether a VPP from a previous daemon is still alive is a
//! fact about the box, and the supervisor cannot discover it. So this
//! establishes it and injects `Adopted { steered }`, which is
//! deliberately distinct from `StartRequested` — an adopted VPP may be
//! carrying live traffic, and rule 3 says resync and verify must NOT
//! tear its steering down first.

use std::path::{Path, PathBuf};

use crate::acquire::{self, Acquired, ResourceOwner, SharedOwner, SysPaths};
use crate::attach::PortAttach;
use crate::cores;
use crate::driver::Driver;
use crate::engine::{ConvergenceEngine, RouteSource};
use crate::fib_sync::FamilyPolicy;
use crate::process::VppProcess;
use crate::resources::ResourceState;
use crate::runtime::{Runtime, SteeringUnavailable};
use crate::service::{LoopFactory, SupervisionService};
use crate::startup_conf;
use crate::supervisor::Event;
use crate::{VppOffloadConfig, MODULE_NAME};

/// Where VPP's binary API socket lives.
///
/// Under packetframe's own runtime dir, not `/run/vpp`, so a
/// distro-packaged `vpp.service` (which UniFi's install leaves masked but
/// present) cannot collide with the instance this module supervises.
pub const API_SOCKET: &str = "/run/packetframe/vpp/api.sock";

/// The rendered startup.conf. Regenerated on every attach — it is
/// derived entirely from config, and VPP reads it once at start.
pub const STARTUP_CONF: &str = "/run/packetframe/vpp/startup.conf";

/// The default VPP binary, overridable with `vpp-binary` in config.
pub const DEFAULT_VPP_BINARY: &str = "/usr/bin/vpp";

/// Host paths the sequence touches, all injectable.
#[derive(Debug, Clone)]
pub struct AttachPaths {
    pub sys: SysPaths,
    /// `/sys/devices/system/cpu`, for the worker placement.
    pub sysfs_cpu: PathBuf,
    pub api_socket: PathBuf,
    pub startup_conf: PathBuf,
}

impl AttachPaths {
    pub fn live(state_dir: impl Into<PathBuf>, hugepage_bytes: u64) -> Self {
        Self {
            sys: SysPaths::live(state_dir, hugepage_bytes),
            sysfs_cpu: PathBuf::from(cores::SYSFS_CPU),
            api_socket: PathBuf::from(API_SOCKET),
            startup_conf: PathBuf::from(STARTUP_CONF),
        }
    }
}

/// What a successful bring-up produced, for the module to hold.
pub struct Attached {
    pub service: SupervisionService,
    /// The core map that was rendered, so the operator can move PF IRQs
    /// off it — on the reference NIC every CPU carries an rx-queue IRQ,
    /// so this is not optional work. Logged at attach for that reason.
    pub cores: cores::CoreMap,
    /// How the resources were obtained, and whether a running VPP was
    /// adopted. `packetframe status` reads differently for an adopted
    /// dataplane: it may already be forwarding.
    pub acquired: Acquired,
    pub adopted_process: bool,
}

/// Acquire, render, adopt-or-arm, and start supervising.
///
/// On any failure after acquisition, everything acquired is released
/// before returning — a failed attach must leave the box as it found it,
/// or say precisely what it could not hand back.
pub fn bring_up(
    cfg: &VppOffloadConfig,
    paths: &AttachPaths,
    source: Box<dyn RouteSource + Send + Sync>,
) -> Result<Attached, String> {
    // --- Everything pure first. A config that cannot work must cost no
    // sysfs writes; the alternative is a rollback path exercised by
    // ordinary operator typos.
    //
    // Zero ports is refused rather than treated as a no-op attach.
    // `Module::load` already rejects it, but this is reachable directly,
    // and the result would be a supervised VPP with no interfaces: every
    // route unresolvable, every verify sampling an empty pool, and
    // membership — which is all-or-nothing across the forwarding domain —
    // vacuously satisfied.
    if cfg.ports.is_empty() {
        return Err("no `port` lines; there is no forwarding domain to bring up".into());
    }
    let workers = cfg.total_workers();
    let sizing = startup_conf::derive_sizing(cfg.expected_routes, workers)?;
    let core_map = cores::derive_from_sysfs(&paths.sysfs_cpu, workers)?;

    let hugepage_bytes = paths.sys.hugepage_bytes;
    if hugepage_bytes == 0 {
        return Err(
            "the default hugepage size could not be read from /proc/meminfo; VPP cannot be \
             sized without it (run `packetframe feasibility` for the platform state)"
                .into(),
        );
    }
    let pages = match cfg.hugepages {
        Some(p) => {
            // Also checked at load; re-checked here because `bring_up`
            // is reachable without it and the failure it prevents is a
            // cryptic VPP init abort.
            startup_conf::check_hugepage_budget(&sizing, p, hugepage_bytes)?;
            p
        }
        None => u32::try_from(sizing.total_bytes.div_ceil(hugepage_bytes)).map_err(|_| {
            format!(
                "derived hugepage count for {} routes does not fit in u32; \
                                  lower `expected-routes`",
                cfg.expected_routes
            )
        })?,
    };

    let vpp_binary = PathBuf::from(
        cfg.vpp_binary
            .clone()
            .unwrap_or_else(|| DEFAULT_VPP_BINARY.to_string()),
    );
    // Checked before acquiring rather than discovered by the loop's
    // first `Start`. A missing binary is a permanent condition, and the
    // supervisor's answer to a failed spawn is backoff-and-retry — so
    // without this, a typo'd `vpp-binary` becomes an attach that
    // "succeeds", holds VFs and hugepages, and retries forever.
    if !vpp_binary.is_file() {
        return Err(format!(
            "VPP binary {} does not exist; set `vpp-binary <path>` or install the pinned \
             VPP package",
            vpp_binary.display()
        ));
    }

    // --- The first mutation.
    let ports: Vec<(String, u16)> = cfg
        .ports
        .iter()
        .map(|(iface, cores, _)| (iface.clone(), *cores))
        .collect();
    let (state, acquired) = acquire::acquire(&paths.sys, &ports, pages, cfg.expected_routes)?;

    // From here, every failure releases. `?` would return holding VFs
    // and a hugepage reservation that only the state file knows about —
    // recoverable by `detach --all`, but an attach that leaves the box
    // changed after reporting failure is how leaks become normal.
    match finish(
        paths,
        source,
        &sizing,
        &core_map,
        state.clone(),
        acquired,
        &vpp_binary,
    ) {
        Ok(attached) => Ok(attached),
        // A supervision panic is the one failure that must NOT roll back.
        //
        // NOT covered by a test, and the reason is structural: the window
        // only opens once a process exists, i.e. after an adoption or a
        // successful spawn. On the fresh path the spawn is the first thing
        // that can fail, so nothing walks the route source inside `start`
        // and the panic cannot be provoked; adoption needs a live VPP. It
        // belongs with the failover drills. The guard is one comparison and
        // its absence risks memory corruption, so it ships unproven rather
        // than not at all.
        //
        // Everything else here failed before any process could exist, so
        // releasing is right. But a panic inside `SupervisionService::start`
        // may have unwound with a VPP already adopted or spawned — the
        // handle is dropped by the unwind without terminating the process —
        // and releasing then unbinds a VF that a live VPP can still DMA
        // through. That is the hazard `Disposition::MustLeak` exists to
        // avoid, arriving by a different route. A leaked VF is a line in
        // `packetframe status`; memory corruption is not.
        Err(e) if crate::service::may_hold_resources(&e) => Err(format!(
            "{e} The acquired VF(s) and hugepage reservation were deliberately NOT released \
             for that reason; the state file still records them, so `packetframe detach \
             --all` can release them once VPP is confirmed gone."
        )),
        Err(e) => Err(match acquire::release(&paths.sys, state) {
            Ok(()) => format!("{e}; everything acquired was released"),
            Err(re) => format!(
                "{e}; AND the rollback did not complete: {re} — run `packetframe detach --all`"
            ),
        }),
    }
}

/// The part that runs with resources held, split out so `bring_up` has
/// exactly one rollback site.
#[allow(clippy::too_many_arguments)]
fn finish(
    paths: &AttachPaths,
    source: Box<dyn RouteSource + Send + Sync>,
    sizing: &startup_conf::Sizing,
    core_map: &cores::CoreMap,
    state: ResourceState,
    acquired: Acquired,
    vpp_binary: &Path,
) -> Result<Attached, String> {
    // --- startup.conf. Written before any process could read it, and
    // rewritten on every attach: it is a pure function of config, and
    // VPP consults it once at start.
    let api_socket = paths
        .api_socket
        .to_str()
        .ok_or_else(|| format!("API socket path {:?} is not UTF-8", paths.api_socket))?;
    let conf = startup_conf::render(
        sizing,
        &core_map.workers,
        core_map.main,
        api_socket,
        paths.sys.hugepage_bytes,
    );
    for dir in [paths.startup_conf.parent(), paths.api_socket.parent()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    }
    std::fs::write(&paths.startup_conf, &conf)
        .map_err(|e| format!("write {}: {e}", paths.startup_conf.display()))?;

    // --- The attach step's inputs, from what acquisition recorded. The
    // VF PCI addresses are the state file's, not re-derived: the record
    // is what release will act on, so attaching a device the record does
    // not name would be a VF nothing can hand back.
    let port_attach: Vec<PortAttach> = state
        .ports
        .iter()
        .map(|p| PortAttach {
            port: p.iface.clone(),
            pci_addr: p.vf_pci.clone(),
            port_id: 0,
            num_rx_queues: p.cores,
        })
        .collect();
    // Every member port, whether or not it steers: a steered packet's
    // best path may egress any of them, so the nexthop mapping must
    // resolve all of them (plan v5, membership vs steering).
    let members: Vec<String> = state.ports.iter().map(|p| p.iface.clone()).collect();
    let recorded: Vec<(String, u32)> = state
        .ports
        .iter()
        .filter_map(|p| p.sw_if_index.map(|i| (p.iface.clone(), i)))
        .collect();

    // --- Adoption is an observation: is the VPP the record names still
    // alive? `adopt` verifies (pid, start_ticks, boot_id) and declines
    // on any mismatch, so a recycled PID cannot be adopted — and a
    // decline simply means we start one instead.
    let prior = match (state.vpp_pid, state.vpp_start_ticks) {
        (Some(pid), Some(ticks)) => Some((pid, ticks, state.vpp_boot_id.clone())),
        _ => None,
    };
    let adopted: Option<VppProcess> = match prior {
        // A FAILED adoption is marked, because failing is not the same as
        // finding nothing: `adopt` declines cleanly (`Ok(None)`) when the
        // recorded process is gone, so an `Err` here means it is probably
        // still there and we could not take it over — an unreadable boot
        // id, a pidfd that would not open. Rolling back then unbinds the VF
        // underneath a VPP that is still running and still able to DMA
        // through it.
        Some((pid, ticks, boot)) => {
            VppProcess::adopt(pid, ticks, boot.as_deref()).map_err(|e| {
                format!(
                    "{}: could not adopt the recorded VPP (pid {pid}): {e}. That process is \
                     probably still running and still holds its VF and hugepages.",
                    crate::service::MAY_HOLD_RESOURCES
                )
            })?
        }
        None => None,
    };
    // Whether that VPP is diverting traffic right now. From the recorded
    // steering rules, because that is the only durable evidence — and
    // getting it wrong in the `false` direction would run the resync on
    // the relaxed 10 s socket budget while packets are on VPP, defeating
    // the published ≤2 s wedge bound.
    let steered = !state.steer_rules.is_empty();
    let adopted_process = adopted.is_some();

    let capacity = startup_conf::route_capacity(sizing);
    let api_socket_path = paths.api_socket.clone();
    let startup_conf_path = paths.startup_conf.clone();
    let vpp_binary = vpp_binary.to_path_buf();
    let sys = paths.sys.clone();

    // The factory runs on the loop thread because `Runtime` is `!Send`
    // (see `service`), which is also why the resource owner is built in
    // here rather than passed in: it shares one record between the
    // identity store and the release seam through an `Rc`.
    let factory: LoopFactory = Box::new(move || {
        let engine = ConvergenceEngine::new(
            api_socket_path,
            port_attach,
            members,
            capacity,
            FamilyPolicy::V4Only,
        )
        .with_recorded_indices(recorded);
        let owner = SharedOwner::new(ResourceOwner::new(state, sys));
        let runtime = Runtime::new(
            engine,
            source,
            Box::new(SteeringUnavailable),
            Box::new(owner.clone()),
            Box::new(owner),
            vpp_binary,
            startup_conf_path,
        );
        let initial = match adopted {
            Some(p) => {
                // Order matters and is contractual: `adopt_process`
                // first, with the same `steered`, so the engine's socket
                // deadline is already the steered one when `inject`
                // synchronously runs AttachDevices and StartResync.
                runtime.adopt_process(p, steered);
                vec![Event::Adopted { steered }]
            }
            None => vec![Event::StartRequested],
        };
        Ok((Driver::new(), runtime, initial))
    });

    // `start` MUST be the last fallible step, and nothing may be added
    // after it that can fail.
    //
    // `bring_up` releases everything on any `Err` from here. Once `start`
    // has succeeded a supervision loop is running against these VFs and
    // hugepages, and a later failure would hand them back underneath it —
    // unbinding a VF while VPP may be DMAing through it. The ordering is
    // the only thing preventing that, so it is stated rather than left to
    // be noticed.
    let service = SupervisionService::start(MODULE_NAME, factory).map_err(|e| {
        // Once a process was adopted, the factory owns its handle — and a
        // failure inside `start` drops that handle without terminating the
        // process. So every error from here is resource-bearing when we
        // adopted, not just the panic that already marks itself.
        if adopted_process && !crate::service::may_hold_resources(&e) {
            format!(
                "{}: {e} (the adopted VPP is still running and still holds its VF)",
                crate::service::MAY_HOLD_RESOURCES
            )
        } else {
            e
        }
    })?;
    Ok(Attached {
        service,
        cores: core_map.clone(),
        acquired,
        adopted_process,
    })
}
