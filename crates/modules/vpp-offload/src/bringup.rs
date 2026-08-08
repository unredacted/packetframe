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
use std::sync::Arc;

use crate::acquire::{self, Acquired, ResourceOwner, SharedOwner, SysPaths};
use crate::attach::PortAttach;
use crate::cores;
use crate::driver::Driver;
use crate::engine::{ConvergenceEngine, RouteSource};
use crate::fib_sync::FamilyPolicy;
use crate::ntuple::NtupleSteering;
use crate::process::VppProcess;
use crate::resources::ResourceState;
use crate::runtime::Runtime;
use crate::service::{LoopFactory, SupervisionService};
use crate::startup_conf;
use crate::steer::{McamBudget, RuleSet};
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

/// The PF's MAC, from `/sys/class/net/<iface>/address`.
///
/// Read here rather than asked of VPP, because VPP cannot know it: the
/// interface it owns is the **VF**, which has its own address. MCAM
/// redirects frames addressed to the PF, so the PF's MAC is what the VPP
/// interface must answer to — and what it must source on tx, so the
/// frame leaves the same LMAC and the upstream switch sees no move.
fn pf_mac(sysfs_net: &Path, iface: &str) -> Result<[u8; 6], String> {
    let path = sysfs_net.join(iface).join("address");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 6 {
        return Err(format!(
            "{} holds {:?}, which is not a MAC address",
            path.display(),
            text.trim()
        ));
    }
    let mut out = [0u8; 6];
    for (slot, byte) in out.iter_mut().zip(&parts) {
        *slot = u8::from_str_radix(byte, 16)
            .map_err(|_| format!("{}: {byte:?} is not a hex octet", path.display()))?;
    }
    Ok(out)
}

/// Which completeness handle the runtime should actually gate on.
///
/// A named function rather than an inline `if` because the bug it fixes
/// was an inline nothing: the directive was parsed, refused against, and
/// never consulted where it decided anything. One place, one rule,
/// testable without a NIC.
fn completeness_gate(
    cfg: &VppOffloadConfig,
    handle: Option<Arc<packetframe_common::fib::TableCompleteness>>,
) -> Option<Arc<packetframe_common::fib::TableCompleteness>> {
    if cfg.require_table_complete {
        handle
    } else {
        None
    }
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
    allowlist: &[packetframe_common::fib::IpPrefix],
    completeness: Option<Arc<packetframe_common::fib::TableCompleteness>>,
    budget: &McamBudget,
) -> Result<Attached, String> {
    // `require-table-complete on` with nothing publishing completeness
    // is refused at attach rather than discovered at the first canary
    // step. The gate would never pass — every steer would be declined
    // with "no check has run yet" — and the operator would be debugging
    // a rollout that cannot proceed instead of reading this once.
    if cfg.require_table_complete && completeness.is_none() {
        return Err(
            "`require-table-complete on` (the default), but nothing is publishing route \
             completeness — the fast-path integrity checker needs `birdc` and a bird to \
             ask. Steering would be refused forever. Either give this box a bird, or set \
             `require-table-complete off` and own the judgement yourself (see the canary \
             ladder in docs/runbooks/vpp-offload.md)"
                .into(),
        );
    }
    // `off` means off.
    //
    // The loader builds a completeness handle whenever both modules are
    // configured and hands it over unconditionally — it has no view of
    // this directive. So dropping it HERE is the only thing that makes
    // `require-table-complete off` mean anything. Without this the
    // directive was read, validated against above, and then ignored: the
    // gate ran on every deployment, including the ones that set it off
    // precisely because they have no authority worth comparing to.
    let completeness = completeness_gate(cfg, completeness);

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
    // Steering is real now, so `steer on` is planned rather than
    // refused — but the plan is built HERE, in the pure phase, because
    // an allowlist that cannot be steered is a config error and must
    // cost nothing to discover. `RuleSet::plan` refuses an allowlist
    // that overruns the MCAM budget rather than truncating it: a
    // partially steered port divides traffic between the two forwarding
    // tiers along a line nobody chose.
    //
    // Built only when something steers, for the same reason
    // `steering_target` does it that way: `plan` refuses an allowlist
    // that overruns the budget, and the budget is now the NIC's real 16
    // slots rather than an imagined 512. Planning unconditionally would
    // make an allowlist of more than eight v4 prefixes refuse to *attach*
    // — on a config whose ports are all `steer off`, where no rule would
    // ever be installed and the refusal decides nothing.
    let wants_steer = cfg.ports.iter().any(|(_, _, steer)| *steer);
    let steer_plan = if wants_steer {
        // An allowlist with nothing steerable in it is a config error,
        // and settling that needs no NIC — so it is settled BEFORE the
        // table query. Otherwise the operator's answer is whatever the
        // ioctl said (on a down port, `EOPNOTSUPP`), which names the
        // wrong problem entirely.
        let steerable = crate::steer::steerable_count(allowlist);
        if steerable == 0 {
            return Err(format!(
                "port(s) are configured `steer on`, but the allowlist produces no steerable \
                 rules ({} IPv6 prefix(es) skipped — `ip6` ntuple is rejected by this NIC). \
                 Steering would divert nothing while reporting Healthy; set the ports \
                 `steer off` or give fast-path a v4 `allow-prefix`",
                allowlist.len() - steerable
            ));
        }
        RuleSet::plan(allowlist, budget.clone())?
    } else {
        RuleSet::default()
    };

    // Only the ports the operator asked to steer. `steer off` is the
    // designed staging state and the rollback landing zone, so a port
    // left off must get no rules at all — not rules that happen to be
    // unused. VF 0 because `acquire` creates exactly one per PF and
    // reads it back through `virtfn0`.
    let steer_ports: Vec<(String, u32)> = cfg
        .ports
        .iter()
        .filter(|(_, _, steer)| *steer)
        .map(|(iface, _, _)| (iface.clone(), 0u32))
        .collect();
    let steering = NtupleSteering::new(steer_ports, steer_plan);

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
    // Existing is not enough: `is_file()` says nothing about the execute
    // bit or the mount it sits on. A `chmod -x` binary, or one dropped
    // somewhere mounted `noexec` (which is how UniFi OS mounts `/tmp` —
    // the obvious place to park a hand-built VPP), fails at execve with
    // EACCES. That would be discovered by the loop's first `Start`, i.e.
    // one step too late: it is permanent, the supervisor answers a failed
    // spawn with backoff-and-retry, and so attach would report success
    // and hold the VFs and hugepages forever — the exact outcome the
    // existence check above exists to prevent, arriving one stat later.
    if let Err(e) = check_executable(&vpp_binary) {
        return Err(format!(
            "VPP binary {} is not executable ({e}); `chmod +x` it, or move it off a \
             `noexec` mount (`/tmp` is one on UniFi OS)",
            vpp_binary.display()
        ));
    }

    // --- The first mutation.
    let ports: Vec<(String, u16)> = cfg
        .ports
        .iter()
        .map(|(iface, cores, _)| (iface.clone(), *cores))
        .collect();
    // Mandatory, and checked in the pure phase so a config that cannot
    // forward costs no VF and no hugepage reservation.
    // `Config::validate_vpp_offload` refuses it at load; this is the
    // guard for callers that reach `bring_up` directly.
    let Some(loopback) = cfg.loopback_address else {
        return Err(
            "no `loopback-address`; member ports are unnumbered to a loopback and forward \
             nothing without one — while reporting healthy, because the FIB stays correct \
             and every packet dies at `ip4-not-enabled`"
                .into(),
        );
    };

    // The daemon vacates VPP's cores here — after the LAST pure check,
    // so a refused config costs no affinity change, and before anything
    // whose failure the rollback below undoes. The harm this prevents
    // arrives through the scheduler, not the API: a resync's mirror
    // walk landing on the worker's core preempts the poll loop, the
    // 1024-descriptor rx ring overflows in ~2 s, and the drops happen
    // at the NIC where no VPP counter sees them — a constant ~5.4 s of
    // loss at every adopted release until this call existed (shadow,
    // 2026-08-08). Warn-and-continue on partial failure: a cgroup that
    // refuses the mask degrades protection, and failing the attach over
    // it would brick deployments that share cores gracefully today.
    // The cores to vacate: the map just derived, PLUS any placement a
    // previous attach recorded.
    //
    // The union rather than either alone, because which one is right
    // depends on something not yet known here — whether `finish` below
    // will adopt a surviving VPP or spawn a fresh one. VPP fixes thread
    // placement at start, so an adopted VPP is on the RECORDED cores
    // while a fresh one will be on the DERIVED cores, and the two differ
    // exactly when the online CPU set changed in between (a core
    // offlined for thermal reasons, or administratively). Vacating both
    // sets is correct under either outcome and costs the daemon nothing
    // when they agree, which is every ordinary restart (review finding).
    let derived_cores: Vec<u16> = std::iter::once(core_map.main)
        .chain(core_map.workers.iter().copied())
        .collect();
    let mut vacate = derived_cores.clone();
    if let Ok(Some(prior)) = ResourceState::load(&paths.sys.state_dir) {
        for cpu in prior.vpp_cores {
            if !vacate.contains(&cpu) {
                tracing::info!(
                    cpu,
                    "a previous attach placed a VPP thread here; vacating it too in case \
                     this attach adopts that VPP rather than spawning a new one"
                );
                vacate.push(cpu);
            }
        }
    }
    vacate.sort_unstable();
    match cores::restrict_daemon_from(&vacate) {
        // `0` is NOT success: no mask changed, so the daemon is still
        // free to run on VPP's cores. Logging it as a restriction would
        // be the claim-because-requested shape this module exists to
        // avoid — say plainly that it did not happen.
        Ok(0) => tracing::warn!(
            vacated = ?vacate,
            "no daemon thread accepted an affinity change; the daemon can still be \
             scheduled onto VPP's cores and resync bursts may preempt the worker"
        ),
        Ok(threads) => tracing::info!(
            threads,
            vacated = ?vacate,
            "daemon threads restricted away from VPP's cores"
        ),
        Err(e) => tracing::warn!(
            error = %e,
            "could not restrict the daemon off VPP's cores; expect loss during \
             resync bursts if they share a core with a worker"
        ),
    }

    // The affinity restriction is deliberately NOT undone on this or
    // any other failure path: see `cores::restrict_daemon_from` — a CPU
    // mask is per-process state and every one of these paths ends the
    // daemon, so there is nothing to hand it back to.
    let (state, acquired) = acquire::acquire(
        &paths.sys,
        &ports,
        pages,
        cfg.expected_routes,
        &derived_cores,
    )?;

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
        steering,
        completeness,
        loopback,
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

/// Can this process actually `execve` `path`?
///
/// `access(2)` rather than the mode bits, because the mode bits are only
/// half the question: the kernel's `do_faccessat` checks `path_noexec()`
/// for `X_OK` on a regular file, so this is the one call that answers for
/// the permission *and* the mount. Real-uid semantics (`access`, not
/// `faccessat(AT_EACCESS)`) — packetframe is not setuid, so the two
/// coincide, and it keeps libc out of its AT_EACCESS emulation paths.
fn check_executable(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::ffi::OsStrExt as _;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `c` is NUL-terminated and outlives the call, which does not
    // retain it.
    if unsafe { libc::access(c.as_ptr(), libc::X_OK) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
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
    steering: NtupleSteering,
    completeness: Option<Arc<packetframe_common::fib::TableCompleteness>>,
    loopback: packetframe_common::config::Ipv4Prefix,
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
        .map(|p| {
            Ok(PortAttach {
                port: p.iface.clone(),
                pci_addr: p.vf_pci.clone(),
                port_id: 0,
                num_rx_queues: p.cores,
                pf_mac: pf_mac(&paths.sys.sysfs_net, &p.iface)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
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
    // The recorded identity must be COMPLETE before adoption is attempted,
    // and an incomplete one with a pid is a refusal, not a "no process".
    //
    // This is the same defect the standalone detach had, in the startup path,
    // and it is worse here. `VppProcess::adopt` returns `Ok(None)` when it
    // cannot verify an identity — not when the process is confirmed gone — so
    // passing `boot_id: None` through and reading the refusal as "nothing
    // running" made `finish` emit `StartRequested`: a SECOND VPP on the same
    // VF and the same API socket, with the recorded pid overwritten and the
    // original orphaned holding the hardware.
    //
    // (I fixed this in the CLI and did not check this path, having audited
    // the CLI against the module's rules and not the module against itself.)
    let prior = match (state.vpp_pid, state.vpp_start_ticks, &state.vpp_boot_id) {
        (Some(pid), Some(ticks), Some(boot)) => Some((pid, ticks, boot.clone())),
        // Nothing was running when the record was last written.
        (None, _, _) => None,
        // A pid with an incomplete cookie: it can be neither identified nor
        // ruled out, so it must not be adopted, and a fresh spawn on the same
        // VF is exactly what must not happen.
        (Some(pid), ticks, boot) => {
            let missing = match (ticks, boot) {
                (None, None) => "start-time cookie and boot id",
                (None, Some(_)) => "start-time cookie",
                _ => "boot id",
            };
            return Err(format!(
                "{}: the state file records VPP pid {pid} with no {missing}, so it can \
                 neither be adopted nor ruled out. Starting a fresh VPP would put a second \
                 process on the same VF and API socket and orphan the first, so this \
                 refuses. Confirm by hand whether that process is running: if it is, \
                 `packetframe detach --all` after stopping it; if not, remove the state \
                 file.",
                crate::service::MAY_HOLD_RESOURCES
            ));
        }
    };
    let adopted: Option<VppProcess> = match prior {
        // A FAILED adoption is marked, because failing is not the same as
        // finding nothing: `adopt` declines cleanly (`Ok(None)`) when the
        // recorded process is gone, so an `Err` here means it is probably
        // still there and we could not take it over — an unreadable boot
        // id, a pidfd that would not open. Rolling back then unbinds the VF
        // underneath a VPP that is still running and still able to DMA
        // through it.
        Some((pid, ticks, boot)) => VppProcess::adopt(pid, ticks, Some(&boot)).map_err(|e| {
            format!(
                "{}: could not adopt the recorded VPP (pid {pid}): {e}. That process is \
                     probably still running and still holds its VF and hugepages.",
                crate::service::MAY_HOLD_RESOURCES
            )
        })?,
        None => None,
    };
    // Whether that VPP is diverting traffic right now. From the recorded
    // steering rules, because that is the only durable evidence — and
    // getting it wrong in the `false` direction would run the resync on
    // the relaxed 10 s socket budget while packets are on VPP, defeating
    // the published ≤2 s wedge bound.
    let steered = !state.steer_rules.is_empty();
    // The CONFIG's answer, captured before `steering` moves into the
    // runtime. Inherited rules say what the NIC holds; only this says
    // what the operator asked for.
    let config_wants_steer = {
        use crate::runtime::Steering as _;
        steering.configured_ports() > 0
    };
    let adopted_process = adopted.is_some();

    // Take ownership of the rules the record names, so `unsteer` can
    // remove them.
    //
    // `steered` above is derived from the same field, and the two must
    // not diverge: believing traffic is diverted while holding no way to
    // undivert it is worse than either mistake alone — every teardown
    // would emit an `Unsteer` that found an empty ledger, answered `Ok`,
    // and released the VF with the rules still in the NIC.
    //
    // Rules recorded for an interface that is no longer a member port
    // are adopted TOO, deliberately. They are in the NIC either way, and
    // this object is the only thing that will ever remove them; dropping
    // them here because the config changed is how a `steer on` port
    // removed from the config keeps diverting traffic forever.
    let mut steering = steering;
    steering.adopt_installed(crate::resources::flatten_steer_rules(&state.steer_rules));

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
            loopback,
        )
        .with_recorded_indices(recorded);
        // Counted before the record moves into the owner: the log line
        // below needs it, and reaching for it afterwards is what the
        // borrow checker just refused.
        let inherited_rule_count: usize =
            state.steer_rules.iter().map(|(_, locs)| locs.len()).sum();
        let owner = SharedOwner::new(ResourceOwner::new(state, sys));
        let runtime = Runtime::new(
            engine,
            source,
            Box::new(steering),
            Box::new(owner.clone()),
            Box::new(owner),
            vpp_binary,
            startup_conf_path,
        );
        if let Some(handle) = completeness {
            runtime.require_table_complete(handle);
        }
        let initial = match adopted {
            Some(p) => {
                // The API handshake MUST happen before the adoption is
                // injected, and this is the only place it can.
                //
                // `Event::Adopted` runs `AttachDevices` and `StartResync`
                // synchronously. Against an engine whose transport has never
                // connected, both return `NotConnected` → `ConvergenceFailed`
                // → `fail()` → **Kill** — so the adopted VPP, the one thing
                // preserve-on-restart exists to keep, was killed and replaced
                // by a full restart and reconvergence. That is drill (d)
                // inverted, and every adoption test in `vpp_service.rs` does
                // this handshake in its factory with a comment saying the
                // attach wiring does the same. The comment was aspirational.
                {
                    use crate::driver::Observe as _;
                    let (mut obs, _) = runtime.views();
                    if !obs.api_ready() {
                        // Do NOT kill it and do NOT release anything. VPP is
                        // running and may be forwarding steered traffic; the
                        // one thing we now know is that we cannot talk to it.
                        // Deciding to restart it is the supervisor's job on
                        // evidence, and we have none beyond a refused
                        // handshake — so this reports and leaves the box
                        // alone. `MAY_HOLD_RESOURCES` suppresses the caller's
                        // rollback, because the VF is still under a live
                        // process.
                        let detail = runtime
                            .status()
                            .api_error
                            .unwrap_or_else(|| "(no detail recorded)".into());
                        let permanent = if runtime.api_incompatible() {
                            " This is a permanent incompatibility (CRC/version skew); \
                             retrying cannot fix it."
                        } else {
                            ""
                        };
                        return Err(format!(
                            "{}: adopted VPP (pid {}) does not answer its binary API: \
                             {detail}.{permanent} It is still running and still holds its \
                             VF and hugepages — nothing was killed or released. Investigate, \
                             or `packetframe detach --all` to clear it and start fresh.",
                            crate::service::MAY_HOLD_RESOURCES,
                            p.pid()
                        ));
                    }
                }
                // Order matters and is contractual: `adopt_process`
                // first, with the same `steered`, so the engine's socket
                // deadline is already the steered one when `inject`
                // synchronously runs AttachDevices and StartResync.
                runtime.adopt_process(p, steered);
                vec![Event::Adopted { steered }]
            }
            // Nothing to hand over: VPP does not exist yet, so there is no
            // API to handshake with. The loop's `Start` spawns it and the
            // driver polls `api_ready` while `Starting`.
            //
            // But the RULES may still be there. MCAM outlives the
            // process, so a VPP that died steered leaves its rules
            // diverting allowlisted traffic into a VF with nothing
            // behind it — blackholing since the moment it died. Telling
            // the supervisor makes its own teardown ordering handle it:
            // `Unsteer` first, and if the NIC refuses, `steered` stays
            // true and the VF stays withheld. Doing the removal here
            // instead would be a second, unsupervised path to the same
            // effect, whose failures nothing would ever retry.
            None if steered => {
                // Visible, because everything that follows from it is
                // consequential and none of it is obvious: this process
                // will unsteer rules it did not install, spawn a new
                // VPP, and — if the config still asks for steering —
                // steer again once the resync verifies. Observed on the
                // shadow 2026-08-07 happening in complete silence.
                tracing::warn!(
                    rules = inherited_rule_count,
                    still_configured = config_wants_steer,
                    "MCAM rules from a previous run are still installed and the process that \
                     owned them is gone; removing them now, and restoring steering after this \
                     VPP's table verifies ONLY if the config still asks for it"
                );
                vec![
                    Event::InheritedSteering {
                        // The config's answer, not the NIC's. A
                        // deployment sitting at `steer off` must come
                        // back at `steer off`, however its last run
                        // ended.
                        still_configured: config_wants_steer,
                    },
                    Event::StartRequested,
                ]
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

/// `require-table-complete off` must actually turn the gate off.
///
/// The loader hands over a completeness handle whenever both modules are
/// configured — it has no view of this directive — so the module is the
/// only thing that can honour it. Before this, the directive was parsed,
/// refused against when no publisher existed, and then ignored: the gate
/// ran on every deployment, including the ones that set it off precisely
/// because their `birdc` answers for the wrong bird. Found on the shadow,
/// where `off` was set and the steer was refused anyway.
#[cfg(test)]
mod completeness_gate_tests {
    use super::*;

    fn cfg(require: bool) -> VppOffloadConfig {
        VppOffloadConfig {
            ports: vec![("eth1".into(), 1, false)],
            vpp_binary: None,
            expected_routes: 1_600_000,
            hugepages: None,
            require_table_complete: require,
            loopback_address: Some(packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
                prefix_len: 32,
            }),
        }
    }

    #[test]
    fn off_drops_the_handle_and_on_keeps_it() {
        let handle = Arc::new(packetframe_common::fib::TableCompleteness::new());

        assert!(
            completeness_gate(&cfg(false), Some(handle.clone())).is_none(),
            "`off` must drop the handle, or the directive decides nothing"
        );
        assert!(
            completeness_gate(&cfg(true), Some(handle)).is_some(),
            "`on` must keep it"
        );
        // And nothing invents a gate that was never handed over.
        assert!(completeness_gate(&cfg(true), None).is_none());
    }
}
