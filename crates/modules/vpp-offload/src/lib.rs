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
pub mod capacity;
pub mod cores;
pub mod drift;
pub mod driver;
pub mod engine;
pub mod executor;
pub mod fdb;
pub mod feed;
pub mod fib_sync;
pub mod handback;
pub mod ledger_record;
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
pub mod topology;
pub mod verify;
pub mod vpp_api;

#[cfg(target_os = "linux")]
mod probe_linux;

use packetframe_common::config::{ModuleDirective, VppSteerDirection};
use packetframe_common::module::{
    Attachment, HealthCtx, HealthReport, HookUse, LoaderCtx, MetricsWriter, Module, ModuleConfig,
    ModuleError, ModuleResult,
};
use packetframe_common::probe::Capability;

pub const MODULE_NAME: &str = "vpp-offload";

/// Parsed view of the module's section, extracted once at load.
#[derive(Debug, Clone, Default)]
pub struct VppOffloadConfig {
    /// One entry per `port` line, in config order. The direction is
    /// the per-port override; `None` defers to the global
    /// `steer_direction`. Hot like the steer flag — rules reconcile on
    /// reconfigure.
    pub ports: Vec<PortLine>,
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
    /// `loopback-address6`: the global IPv6 address the same loopback
    /// holds as a /128 under `v6 on` — the source of every ICMPv6 error
    /// VPP originates, through the owned interfaces' unnumbered borrow
    /// ([`attach::ensure_loopback_address6`] has the VPP evidence).
    /// `None` leaves VPP with no global v6 source, so those errors are
    /// dropped inside VPP. Restart-only, like `loopback_address`.
    pub loopback_address6: Option<std::net::Ipv6Addr>,
    /// Destinations that stay on the kernel path while steering is on
    /// (`steer-exempt`, repeatable) — installed as higher-priority
    /// MCAM rules toward the PF. Broadcast and multicast are built in;
    /// these are the operator's additions, the router's own service
    /// addresses above all. Hot-reloadable like the allowlist: the
    /// plan is rebuilt on every reconfigure.
    pub steer_exempts: Vec<packetframe_common::config::Ipv4Prefix>,
    /// Which packet side the MCAM rules match. Hot-reloadable: the
    /// steering target is rebuilt from config on every reconfigure and
    /// `steer` is a reconcile, so a change installs/removes exactly
    /// the delta — including the rollback direction.
    pub steer_direction: packetframe_common::config::VppSteerDirection,
    /// `(prefix, port, vlan)` per `local-route` line, in config order —
    /// the section's own view, used for the restart-only comparison.
    /// The loader-resolved form (with the kernel bridge device joined
    /// in from fast-path's `local-prefix`) is [`LocalRoute`], installed
    /// via [`VppOffloadModule::set_local_routes`]. Restart-only: the
    /// attached route and the subif it lands on are attach-time work.
    pub local_routes: Vec<(packetframe_common::config::Ipv4Prefix, String, u16)>,
    /// `(prefix, port, vlan)` per `local-route6` line, in config order —
    /// `local_routes`' IPv6 twin, resolved into the same [`LocalRoute`]
    /// list. Restart-only for the same reasons.
    pub local_routes6: Vec<(packetframe_common::config::Ipv6Prefix, String, u16)>,
    /// `steer-capacity`: the ntuple table size to ask each steerable
    /// member port for at attach. `None` leaves the driver's default
    /// alone. Restart-only — the driver refuses to resize a table
    /// holding rules, so it is attach-time work (see [`capacity`]).
    pub steer_capacity: Option<u16>,
    /// Ports declared `vlans all`: their subinterfaces follow the tagged
    /// VLANs the kernel bridge carries on them — read at attach, then
    /// kept in step while VPP runs, so a VLAN added on the switch needs
    /// no restart. Their `vlans` entry in [`Self::ports`] stays empty;
    /// bring-up fills the attach-time set from the kernel.
    pub trunk_ports: Vec<String>,
    /// `(port, v6-divert)` for every port line carrying the tail, in
    /// config order. Hot, like `direction`: it selects among subifs VPP
    /// already has (`vlans` is restart-only and validation holds every
    /// VID to it; a `vlans all` trunk is checked against the kernel
    /// bridge when planned), so a change is an MCAM delta and nothing
    /// else — `steer` reconciles it like an allowlist edit.
    pub v6_divert: Vec<(String, packetframe_common::config::VppV6Divert)>,
    /// `steer-keep6` lines, in config order. Hot, like `steer-exempt`.
    pub steer_keeps6: Vec<packetframe_common::config::VppSteerKeep6>,
    /// `drift-accept6` lines, in config order: `exempt-drift-v6` findings
    /// the operator has accepted ([`drift::DriftAccepts6`]). Hot, and
    /// applied without the supervision loop — it changes what the
    /// tripwire reports, never what the NIC holds, so it does not wait on
    /// a steer the way the drift scope does.
    pub drift_accepts6: Vec<packetframe_common::config::Ipv6Prefix>,
    /// `v6 on`: VPP carries IPv6 routes and neighbours
    /// ([`fib_sync::FamilyPolicy::Both`]). Default off. Restart-only —
    /// it sizes the segments VPP fixes at start, and decides what the
    /// adopted FIB holds. It steers nothing.
    pub v6: bool,
}

/// One `local-route` or `local-route6`, resolved for the engine: the
/// config triple plus the kernel device whose neighbours mirror onto the
/// subif.
///
/// `kernel_dev` is not in the module's own section — it is the `via`
/// of the fast-path `local-prefix` (`local-prefix6` for a v6 route)
/// covering `prefix` (validation guarantees exactly that cover exists).
/// The loader performs the join because `Module` methods only see their
/// own section; same reason the allowlist is a handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRoute {
    pub prefix: LocalRoutePrefix,
    pub port: String,
    pub vlan: u16,
    pub kernel_dev: String,
}

/// A local route's prefix, as declared. One list carries both families
/// because everything done with one — where the attached route lands,
/// what it shadows, that it stays out of the ledger — is the same for
/// both; only the path's next-hop protocol differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalRoutePrefix {
    V4(packetframe_common::config::Ipv4Prefix),
    V6(packetframe_common::config::Ipv6Prefix),
}

impl LocalRoutePrefix {
    /// The prefix VPP is given: the network, host bits cleared
    /// (declarations need not be aligned).
    pub fn network(&self) -> packetframe_common::fib::IpPrefix {
        match self {
            Self::V4(p) => packetframe_common::fib::IpPrefix::V4 {
                addr: p.network().octets(),
                prefix_len: p.prefix_len,
            },
            Self::V6(p) => packetframe_common::fib::IpPrefix::V6 {
                addr: p.network().octets(),
                prefix_len: p.prefix_len,
            },
        }
    }

    /// Whether `p` lies wholly inside this prefix. Never across families.
    pub fn covers(&self, p: &packetframe_common::fib::IpPrefix) -> bool {
        use packetframe_common::fib::IpPrefix;
        match (self, p) {
            (Self::V4(lr), IpPrefix::V4 { addr, prefix_len }) => {
                lr.prefix_len <= *prefix_len && lr.contains_addr(std::net::Ipv4Addr::from(*addr))
            }
            (Self::V6(lr), IpPrefix::V6 { addr, prefix_len }) => {
                lr.prefix_len <= *prefix_len && lr.contains_addr(std::net::Ipv6Addr::from(*addr))
            }
            _ => false,
        }
    }

    pub fn is_v6(&self) -> bool {
        matches!(self, Self::V6(_))
    }
}

impl std::fmt::Display for LocalRoutePrefix {
    /// As declared, host bits included — what the operator wrote.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V4(p) => write!(f, "{}/{}", p.addr, p.prefix_len),
            Self::V6(p) => write!(f, "{}/{}", p.addr, p.prefix_len),
        }
    }
}

/// One parsed `port` line: `(iface, cores, steer, vlans, direction)`.
pub type PortLine = (String, u16, bool, Vec<u16>, Option<VppSteerDirection>);

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
                    vlans,
                    vlans_all,
                    direction,
                    v6_divert,
                    ..
                } => {
                    out.ports
                        .push((iface.clone(), *cores, *steer, vlans.clone(), *direction));
                    if *vlans_all {
                        out.trunk_ports.push(iface.clone());
                    }
                    if let Some(v6) = v6_divert {
                        out.v6_divert.push((iface.clone(), v6.clone()));
                    }
                }
                ModuleDirective::VppSteerKeep6(k) => out.steer_keeps6.push(*k),
                ModuleDirective::VppDriftAccept6 { prefix, .. } => out.drift_accepts6.push(*prefix),
                ModuleDirective::VppBinary(p) => out.vpp_binary = Some(p.clone()),
                ModuleDirective::ExpectedRoutes(n) => out.expected_routes = *n,
                ModuleDirective::VppHugepages(n) => out.hugepages = Some(*n),
                ModuleDirective::VppSteerCapacity(n) => out.steer_capacity = Some(*n),
                ModuleDirective::VppRequireTableComplete(v) => out.require_table_complete = *v,
                ModuleDirective::VppV6(v) => out.v6 = *v,
                ModuleDirective::VppLoopbackAddress(p) => out.loopback_address = Some(*p),
                ModuleDirective::VppLoopbackAddress6(a) => out.loopback_address6 = Some(*a),
                ModuleDirective::VppSteerExempt(p) => out.steer_exempts.push(*p),
                ModuleDirective::VppSteerDirection(d) => out.steer_direction = *d,
                ModuleDirective::VppLocalRoute {
                    prefix,
                    iface,
                    vlan,
                    ..
                } => out.local_routes.push((*prefix, iface.clone(), *vlan)),
                ModuleDirective::VppLocalRoute6 {
                    prefix,
                    iface,
                    vlan,
                    ..
                } => out.local_routes6.push((*prefix, iface.clone(), *vlan)),
                _ => {}
            }
        }
        out
    }

    /// What in `new` cannot be applied without a restart.
    ///
    /// `Ok(())` means the only difference is the per-port `steer` flag —
    /// the canary lever, and the only thing a reload may change under a
    /// running VPP. Everything else is fixed at VPP's start, at VF
    /// acquisition, or (for `require-table-complete`) when the runtime is
    /// built, so the honest answer is to refuse and say so — the
    /// alternative is a daemon whose running configuration silently
    /// differs from the file an operator just edited, which is how the
    /// wrong thing gets debugged for an hour.
    ///
    /// **`require-table-complete` is refused here rather than wired into
    /// `reconfigure`, and that is a decision, not an omission.** It used
    /// to be permitted and then ignored: the handle is installed or
    /// withheld once, by the attach wiring
    /// (`Runtime::require_table_complete`), and `reconfigure` never
    /// touched it — so a toggled value was stored in `cfg`, reported OK,
    /// and changed nothing until the next start. Three things decided
    /// refusal over wiring:
    ///
    /// - **Where the toggle is recommended, a reload is already refused.**
    ///   The `AuthorityMismatch` remedy is read from a deferred adopted
    ///   resync, whose state is `AdoptedResyncing` or `Syncing`;
    ///   `apply_steering` admits changes only from `Ready`/`Steered`. So
    ///   wiring the toggle through the steering request would deliver it
    ///   everywhere EXCEPT the state it exists for. Delivering it there
    ///   means a second in-loop request path with its own admission rule,
    ///   past `State::accepts_steering_changes` — new machinery in the
    ///   module's most safety-critical seam, to reach a case a restart
    ///   already reaches.
    /// - **This check runs first**, before the attachment is consulted, so
    ///   the operator gets a message about the directive they edited in
    ///   EVERY state — including the deferred one, which today answers a
    ///   `require-table-complete` edit with a refusal about steering and a
    ///   promise ("takes effect at the next successful convergence") that
    ///   is not true of this directive.
    /// - **The silent window included the arming direction.** From
    ///   `Ready`/`Steered` the reload was accepted, so an operator turning
    ///   the gate ON was told the safety gate was armed while the runtime
    ///   held no handle at all. That is worse than the remedy needing a
    ///   restart, and refusing fixes both directions at once.
    ///
    /// A pure function over two configs so the rule is testable without
    /// a VPP, a NIC, or an attachment.
    pub fn restart_only_delta(&self, new: &Self) -> Result<(), String> {
        // Ports are compared as (iface, cores) IN ORDER. Order matters
        // as much as membership: it decides which VF is created on which
        // PF, and `acquire` refuses to adopt across a change to either.
        // `vlans` is in the restart-only set with iface and cores: the
        // dot1q subifs are created at attach, and a reload that claimed
        // to add one would leave steered tagged ingress punting at
        // ethernet-input (the w20 blackhole) while reporting OK.
        let old_ports: Vec<(&str, u16, &[u16])> = self
            .ports
            .iter()
            .map(|(i, c, _, v, _)| (i.as_str(), *c, v.as_slice()))
            .collect();
        let new_ports: Vec<(&str, u16, &[u16])> = new
            .ports
            .iter()
            .map(|(i, c, _, v, _)| (i.as_str(), *c, v.as_slice()))
            .collect();
        if old_ports != new_ports {
            return Err(format!(
                "the `port` lines changed ({old_ports:?} → {new_ports:?}); VF, worker and \
                 subinterface topology is fixed when VPP starts, so this needs a restart \
                 (`packetframe detach --all`, then start). Only `steer on|off` can change \
                 under a running VPP"
            ));
        }
        if self.v6 != new.v6 {
            let onoff = |v: bool| if v { "on" } else { "off" };
            return Err(format!(
                "`v6` changed ({} → {}); it sizes VPP's main heap and stats segment for the \
                 IPv6 table, both fixed at start, and decides which families the FIB holds \
                 and which interfaces carry ip6 — restart to apply",
                onoff(self.v6),
                onoff(new.v6)
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
        if self.trunk_ports != new.trunk_ports {
            return Err(format!(
                "which ports are `vlans all` changed ({:?} → {:?}); a trunk port's \
                 subinterfaces are created from the kernel at attach and followed from \
                 there — restart to apply",
                self.trunk_ports, new.trunk_ports
            ));
        }
        if self.steer_capacity != new.steer_capacity {
            return Err(format!(
                "`steer-capacity` changed ({:?} → {:?}); the driver resizes a port's rule \
                 table only while it holds no rules, so it is applied at attach — restart \
                 to apply",
                self.steer_capacity, new.steer_capacity
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
        if self.loopback_address6 != new.loopback_address6 {
            return Err(format!(
                "`loopback-address6` changed ({:?} → {:?}); the /128 is added to the \
                 loopback and read back at attach, and nothing re-programs it while VPP runs \
                 — restart to apply",
                self.loopback_address6, new.loopback_address6
            ));
        }
        if self.vpp_binary != new.vpp_binary {
            return Err(format!(
                "`vpp-binary` changed ({:?} → {:?}); the running VPP is the one that was \
                 spawned — restart to apply",
                self.vpp_binary, new.vpp_binary
            ));
        }
        if self.local_routes != new.local_routes {
            return Err(format!(
                "the `local-route` lines changed ({:?} → {:?}); the attached route, its \
                 subif, and the neighbour-mirror wiring are installed at attach — restart \
                 to apply",
                self.local_routes, new.local_routes
            ));
        }
        if self.local_routes6 != new.local_routes6 {
            return Err(format!(
                "the `local-route6` lines changed ({:?} → {:?}); the attached route and the \
                 interface it lands on are installed at attach — restart to apply",
                self.local_routes6, new.local_routes6
            ));
        }
        // Restart-only for a different reason than everything above:
        // VPP has never heard of this directive. What is fixed is the
        // WIRING — the attach sequence installs or withholds the
        // completeness handle once, and the first-steer gate and the
        // adopted resync's release both read whatever it decided. See
        // this function's doc comment for why the reload refuses it
        // rather than applying it.
        if self.require_table_complete != new.require_table_complete {
            let onoff = |v: bool| if v { "on" } else { "off" };
            return Err(format!(
                "`require-table-complete` changed ({} → {}); the completeness handle is \
                 installed or withheld once, when the runtime is built, and both gates that \
                 read it — the first-steer refusal and the adopted resync's release — were \
                 decided from it at that moment. Restart to apply. Refused rather than \
                 accepted-and-ignored on purpose: `packetframe status` and the \
                 AuthorityMismatch text recommend toggling this directive, and a reload that \
                 answered OK while the running daemon kept the old gate is a remedy that gets \
                 tried, believed, and debugged for an hour. Turning it ON is worse — that \
                 reports a safety gate as armed when no handle was ever installed",
                onoff(self.require_table_complete),
                onoff(new.require_table_complete)
            ));
        }
        Ok(())
    }

    /// What a running VPP cannot take a change to, recorded at attach
    /// ([`resources::ResourceState::restart_only`]) and compared on
    /// adoption — the restart counterpart of [`Self::restart_only_delta`],
    /// which guards the reload.
    ///
    /// The fields are that function's, less two: `expected-routes` has
    /// its own adoption check, and `require-table-complete` is runtime
    /// wiring a new daemon builds afresh. Steering levers and directions
    /// are left out because adoption does apply them.
    pub fn restart_only(&self) -> resources::RestartOnly {
        let ports: Vec<(&str, u16, &[u16])> = self
            .ports
            .iter()
            .map(|(i, c, _, v, _)| (i.as_str(), *c, v.as_slice()))
            .collect();
        [
            ("port", format!("{ports:?}")),
            ("hugepages", format!("{:?}", self.hugepages)),
            ("steer-capacity", format!("{:?}", self.steer_capacity)),
            ("loopback-address", format!("{:?}", self.loopback_address)),
            ("vpp-binary", format!("{:?}", self.vpp_binary)),
            ("local-route", format!("{:?}", self.local_routes)),
            // `vlans all`: which ports follow the kernel bridge's VLANs
            // is wiring the adopted engine is built with, and a port
            // leaving trunk mode would keep the subifs it gained.
            ("vlans-all", format!("{:?}", self.trunk_ports)),
        ]
        .into_iter()
        // `v6`, recorded only when ON: its heap and stats segment are
        // fixed at start, and a VPP adopted across a flip would hold the
        // wrong families (v6 routes nothing withdraws, or a v6 table its
        // segments were not sized for). Absent when off, so every record
        // written before this directive existed — all `v6 off` by
        // construction — still matches a `v6 off` config and adopts.
        .chain(self.v6.then(|| ("v6", "on".to_string())))
        // `local-route6`, recorded only when present, for the same
        // reason: every record written before the directive existed has
        // none, and must still adopt. Recorded at all because nothing
        // else removes an attached route — it is outside the ledger —
        // so a line dropped across a `--keep-vpp` restart must refuse
        // adoption and restart VPP rather than leave the route behind.
        .chain(
            (!self.local_routes6.is_empty())
                .then(|| ("local-route6", format!("{:?}", self.local_routes6))),
        )
        // `loopback-address6`, recorded only when set, for the same
        // reason: every record written before it existed matches a config
        // without it. Recorded at all so a change is refused here, naming
        // the field, before anything is adopted: past this point the
        // loopback readback would find the OLD /128 and refuse the attach
        // over a foreign address — the right verdict, reached after the
        // VPP was already taken over, with a message about the loopback
        // rather than about the edit.
        .chain(
            self.loopback_address6
                .map(|a| ("loopback-address6", a.to_string())),
        )
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    /// Which families VPP carries.
    pub fn families(&self) -> fib_sync::FamilyPolicy {
        if self.v6 {
            fib_sync::FamilyPolicy::Both
        } else {
            fib_sync::FamilyPolicy::V4Only
        }
    }

    /// Total VPP worker threads the config promises, across all ports:
    /// every port's `cores`, plus the ONE worker all `cores 0` ports
    /// share when any exist
    /// ([`packetframe_common::config::vpp_worker_count`]).
    ///
    /// VPP's thread count is global, not per-interface, and its counter
    /// vectors replicate per thread — so this, not any single port's
    /// `cores`, is what sizes the stats segment
    /// (`startup_conf::derive_sizing`), `corelist-workers`, and the
    /// placement plan's worker indices ([`cores::rx_placement_plan`]).
    pub fn total_workers(&self) -> u32 {
        packetframe_common::config::vpp_worker_count(
            self.ports.iter().map(|(_, cores, _, _, _)| *cores),
        )
    }

    /// Whether `iface` carries a `v6-divert` tail — i.e. would plan v6
    /// rules the moment it steers, whatever the allowlist holds.
    pub fn diverts_v6(&self, iface: &str) -> bool {
        self.v6_divert.iter().any(|(i, _)| i == iface)
    }

    /// The `steer-keep6` lines as the matches the planner takes, `both`
    /// expanded into its two rules.
    pub fn keeps6(&self) -> Vec<steer::L4Match> {
        use packetframe_common::config::{VppL4Proto, VppSteerDirection};
        let mut out = Vec::new();
        for k in &self.steer_keeps6 {
            let proto = match k.proto {
                VppL4Proto::Tcp => steer::L4Proto::Tcp,
                VppL4Proto::Udp => steer::L4Proto::Udp,
            };
            let sides: &[steer::Side] = match k.side {
                VppSteerDirection::Dst => &[steer::Side::Dst],
                VppSteerDirection::Src => &[steer::Side::Src],
                VppSteerDirection::Both => &[steer::Side::Dst, steer::Side::Src],
            };
            for side in sides {
                out.push(steer::L4Match::Port {
                    proto,
                    side: *side,
                    port: k.port,
                });
            }
        }
        out
    }

    /// The v6 half of `iface`'s plan: its `v6-divert` VLANs and the
    /// section's keeps. Empty when the port diverts no v6.
    ///
    /// A `vlans all` trunk's VIDs are held to the VLANs the kernel
    /// bridge carries TAGGED on it (`tagged_vlans`), because that is the
    /// set VPP's subinterfaces follow: a VID outside it has no subif, and
    /// every frame diverted on it would be punted at ethernet-input (the
    /// w20 blackhole). An explicit `vlans` list was already held to the
    /// same rule by config validation. Unreadable bridge VLANs refuse the
    /// plan rather than guess.
    pub(crate) fn v6_steering(
        &self,
        iface: &str,
        tagged_vlans: &dyn Fn(&str) -> Result<Vec<u16>, String>,
    ) -> Result<steer::V6Steering, String> {
        use packetframe_common::config::VppV6Divert;
        let Some((_, v6)) = self.v6_divert.iter().find(|(i, _)| i == iface) else {
            return Ok(steer::V6Steering::default());
        };
        let vlans = match v6 {
            VppV6Divert::Untagged => vec![None],
            VppV6Divert::Vlans(vids) => {
                if self.trunk_ports.iter().any(|t| t == iface) {
                    let carried = tagged_vlans(iface).map_err(|e| {
                        format!(
                            "`port {iface}` diverts IPv6 on `vlans all` VLANs, and whether \
                             the kernel bridge carries them could not be read ({e}); a VID it \
                             does not carry has no VPP subinterface and every frame diverted \
                             on it would be dropped, so nothing is planned"
                        )
                    })?;
                    if let Some(missing) = vids.iter().find(|v| !carried.contains(v)) {
                        return Err(format!(
                            "`port {iface}` diverts IPv6 on vlan {missing} (`v6-divert`), \
                             but the kernel bridge does not carry it tagged on {iface} \
                             (carries {carried:?}), so VPP has no subinterface for it and \
                             every diverted frame would be punted and dropped. Drop it from \
                             `v6-divert`, or add the VLAN to the bridge port first"
                        ));
                    }
                }
                vids.iter().copied().map(Some).collect()
            }
        };
        Ok(steer::V6Steering {
            vlans,
            keeps: self.keeps6(),
        })
    }
}

/// What a refused reload must ALSO say: what it left behind.
///
/// The refusal named only the restart-only directive, and the rest of the
/// edit vanished in silence. The case that matters: one SIGHUP that
/// changes `require-table-complete` **and** rolls a port back to
/// `steer off` returns an error about a completeness gate,
/// `apply_steering` never runs, and the `steer off` whose whole purpose
/// is to get traffic off a misbehaving VPP quickly did nothing and said
/// nothing (review finding, PR #170).
///
/// Not new to `require-table-complete`: every restart-only field has
/// always refused this way, which is why this hangs off the refusal
/// rather than off one directive.
///
/// **Two things this must not claim, both of which the first version
/// claimed** (review findings on the fix, same class as the defect):
///
/// - **That the reload was atomic.** It was not. A SIGHUP is atomic
///   within this module and nowhere else: `reconfigure_from_signal`
///   publishes the shared allowlist and runs fast-path's `reconcile`
///   BEFORE vpp-offload is asked anything — modules reconfigure in config
///   order and `fast-path` is *required* to be declared first. Saying
///   "nothing else was applied" sends an operator to look for a whole
///   rollback that did not happen, when what they have is a split
///   configuration. Making the SIGHUP atomic across modules needs a
///   reload-validation hook on the `Module` trait and a loader change;
///   filed, not widened into this.
/// - **Where traffic currently is.** Neither direction of the flag can be
///   read off this snapshot. `reconfigure` deliberately leaves `self.cfg`
///   unmoved when a steer apply fails — so the config can say `off` while
///   the supervisor holds the want and installs the rules the moment its
///   gate clears — and equally it can say `on` over a steer that was
///   refused and never landed. `packetframe status` reads the NIC and the
///   supervisor; this function reads two config structs, and must say
///   only what they can support: which lever the operator moved, and that
///   it was not applied.
///
/// Two more, from the round after — the same class again, which is why
/// the rule below is stated as a rule rather than as three more patches:
///
/// - **That fast-path's half LANDED.** Ordering proves it was attempted
///   first, not that it succeeded: the loader records a module failure
///   and carries on to the next module, and `reconcile` is not
///   transactional, so a failure there can be partial. The result is
///   reported next to this one in the same `packetframe reconfigure`
///   output, which is where the operator should be sent.
/// - **That the allowlist changed AT ALL.** The module holds a live
///   [`SharedAllowlist`] handle and keeps no previous snapshot, so it
///   cannot diff one — which is exactly why the split-tier warning is
///   phrased as a conditional. A reload that touched only a restart-only
///   directive left fast-path reconciling an unchanged allowlist and
///   introduced no split, and telling that operator to expect the tiers
///   to disagree sends them hunting a divergence that is not there.
/// - **That a clean re-send applies immediately.** It is still subject to
///   `State::accepts_steering_changes`: `service::apply_steering` refuses
///   from anything but `Ready`/`Steered`, and that set excludes the
///   deferred adopted resync where this directive's own remedy is read.
///   Promising an immediate rollback there sends an operator into the
///   same failed emergency rollback twice — and contradicts the finding
///   this whole PR is built on.
///
/// **The rule, since patching one claim kept producing the next:** this
/// function sees two config structs. It may say what the operator asked
/// for and that this module did not apply it. Every other question —
/// what the NIC holds, what the eBPF tier holds, whether a retry will be
/// admitted — belongs to a surface that can observe the answer, and this
/// text's job is to name that surface, not to predict it.
///
/// The lever sentence appears only when a lever actually moved: a warning
/// about a rollback nobody asked for is noise on every ordinary
/// restart-only refusal. Matched by INTERFACE rather than by position,
/// because the port list is one of the things that may have just been
/// refused — so a positional comparison could read a reordered or resized
/// list as a lever move.
fn reload_collateral(old: &VppOffloadConfig, new: &VppOffloadConfig) -> String {
    let mut out = String::from(
        ". This module applied NOTHING from this reload. The SIGHUP is not atomic across \
         modules, though: the loader publishes the shared allowlist and runs fast-path's \
         reconcile BEFORE vpp-offload is asked anything. So IF this reload also edited \
         `allow-prefix`, that edit was already ATTEMPTED against the eBPF tier — whether \
         it landed is fast-path's own result, reported beside this one in the same \
         `packetframe reconfigure` output, and its reconcile is not transactional so a \
         failure there can be partial. This module holds a live allowlist handle with no \
         previous snapshot, so it cannot tell you whether that is what happened; where it \
         is, expect the two tiers to disagree until this is resolved",
    );
    // Direction is named because a skipped rollback is the urgent one —
    // but as a statement about the REQUEST, never about where traffic
    // ended up, which this snapshot cannot see.
    let mut rolled_back: Vec<&str> = Vec::new();
    let mut turned_on: Vec<&str> = Vec::new();
    for (iface, _, was, _, _) in &old.ports {
        let Some((_, _, now, _, _)) = new.ports.iter().find(|(i, _, _, _, _)| i == iface) else {
            continue;
        };
        match (was, now) {
            (true, false) => rolled_back.push(iface.as_str()),
            (false, true) => turned_on.push(iface.as_str()),
            _ => {}
        }
    }
    if !rolled_back.is_empty() {
        out.push_str(&format!(
            ". IN PARTICULAR {rolled_back:?} asked for `steer on → off` and it was NOT \
             applied — a rollback that did not happen. This reload changed nothing in the \
             NIC; what it actually holds is `packetframe status`'s answer, not this \
             message's to guess — the supervisor moves steering on its own cadence too. Re-send the `steer` change in an edit \
             that does not also touch a restart-only directive: that part needs no restart, \
             but it is still subject to the steering admission gate — it applies from \
             `Ready`/`Steered` and is REFUSED from a resync or backoff state, which \
             includes the deferred adopted resync that `require-table-complete`'s own \
             remedy is read in. `packetframe status` names the remedy for the state the \
             module is actually in"
        ));
    }
    if !turned_on.is_empty() {
        out.push_str(&format!(
            ". {turned_on:?} asked for `steer off → on` and it was NOT applied either, so \
             that canary step did not happen — which is not the same as nothing being \
             steered there: a want recorded by an earlier refused steer survives in the \
             supervisor and installs on its own once its gate clears. `packetframe status` \
             is the surface that knows"
        ));
    }
    out
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
///
/// The module does remember the [`SteeringInputs`] its last request
/// carried, and that is not a copy of this: it is what the loop holds, and
/// a reload compares a plan freshly derived from this handle against it.
/// The allowlist itself is still never snapshotted.
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
///
/// "Can steer" is per port now: a `v6-divert` port plans v6 rules
/// whatever the allowlist holds, so it is asked even when no v4 prefix
/// is steerable — and a port with neither is still not.
fn ifaces_to_query<'a>(
    cfg: &'a VppOffloadConfig,
    allowlist: &[packetframe_common::fib::IpPrefix],
) -> Vec<&'a str> {
    let v4 = steer::steerable_count(allowlist) > 0;
    cfg.ports
        .iter()
        .filter(|(iface, _, steer, _, _)| *steer && (v4 || cfg.diverts_v6(iface)))
        .map(|(iface, _, _, _, _)| iface.as_str())
        .collect()
}

/// What steering should look like for a config + allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteeringTarget {
    /// `(PF iface, VF index, rules)` for every port configured
    /// `steer on`. Per-port rule sets because direction is per-port —
    /// the bidirectional service edge steers `src` on the trunk and
    /// `dst` on the transits, and each side's rules differ. Ports
    /// sharing a direction share one planned set (same slot numbers on
    /// every NIC; slots are per-interface, so that costs nothing).
    pub targets: Vec<(String, u32, steer::RuleSet)>,
    /// Whether traffic should be diverted once the target is in place.
    pub want_steer: bool,
}

/// Everything one steering request hands the supervision loop, as the
/// loop holds it after applying one: the target it reconciles the NIC to,
/// the drift watcher's scope (whose exemptions the first-steer gate judges
/// too), and whether anything is to be steered.
///
/// Compared, never diffed: a reload whose freshly planned inputs equal the
/// ones the loop holds may skip the round trip — see
/// [`service::ResendVerdict`] for when that is safe. Planned from the LIVE
/// allowlist every time, so this is not the stale snapshot
/// [`SharedAllowlist`] exists to prevent: an `allow-prefix` edit changes
/// the plan and the plan goes to the loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SteeringInputs {
    pub targets: Vec<(String, u32, steer::RuleSet)>,
    pub scope: drift::DriftScope,
    pub want_steer: bool,
}

/// Ask every port that can steer for `steer-capacity` rule entries.
///
/// Advisory by construction: a port left short is logged, never fatal.
/// The budget read that follows plans against the table the NIC really
/// holds, so a shortfall surfaces where it matters — as the existing
/// over-budget refusal when a plan does not fit, naming the free slots
/// — and a config that fits the default table attaches exactly as it
/// did before this directive existed. `cores 0` ports are skipped:
/// config refuses `steer on` for them, so no rule ever lands there.
///
/// `steer on` ports are served first. The pool is shared and a short
/// allocation is an ordinary driver outcome, so whatever is left should
/// go to the ports whose plan attach is about to check, not to a staging
/// port that happens to come earlier in the file.
///
/// Returns `(port, original size)` for every table that moved, for
/// [`release_steer_capacity`] should attach then refuse.
fn apply_steer_capacity(
    cfg: &VppOffloadConfig,
    ctl: &dyn capacity::CapacityControl,
) -> Vec<(String, u32)> {
    let Some(want) = cfg.steer_capacity else {
        return Vec::new();
    };
    let mut order: Vec<&PortLine> = cfg.ports.iter().filter(|p| p.1 > 0).collect();
    order.sort_by_key(|p| !p.2); // stable: `steer on` first, config order within each
    let mut moved = Vec::new();
    for (iface, _, _, _, _) in order {
        let outcome = capacity::ensure(ctl, iface, want);
        let line = outcome.describe(iface, want);
        if outcome.met() {
            tracing::info!(port = %iface, "steer-capacity: {line}");
        } else {
            tracing::warn!(port = %iface, "steer-capacity: {line}");
        }
        if let Some(from) = outcome.changed_from() {
            moved.push((iface.clone(), from));
        }
    }
    moved
}

/// Return every table [`apply_steer_capacity`] moved to its original
/// size, after an attach that refused. Best effort: a port that will not
/// go back is logged and the reboot that resets the driver is the
/// backstop.
fn release_steer_capacity(moved: &[(String, u32)], ctl: &dyn capacity::CapacityControl) {
    for (iface, from) in moved {
        match capacity::release(ctl, iface, *from) {
            Ok(()) => tracing::info!(
                port = %iface,
                "steer-capacity: attach refused; ntuple table returned to {from}"
            ),
            Err(e) => tracing::warn!(
                port = %iface,
                "steer-capacity: attach refused and the table was not returned to {from}: {e}"
            ),
        }
    }
}

/// How planning reads a port's rule table: with this module's own
/// recorded rules counted as free ([`ntuple::rule_table_reclaiming`]).
///
/// The ledger comes from the state file, which every steer persists, so
/// the attach of an adopting restart and a reload of a running module
/// read the same record. An unreadable or absent file reclaims nothing
/// — planning then sees the raw table, as it always did, which can only
/// refuse, never overwrite.
fn planning_table(
    state_dir: &std::path::Path,
) -> impl Fn(&str) -> Result<ntuple::RuleTable, String> {
    let ledger = resources::ResourceState::load(state_dir).ok().flatten();
    move |iface: &str| {
        let Some(st) = &ledger else {
            return ntuple::rule_table(iface);
        };
        let recorded: Vec<u32> = st
            .steer_rules
            .iter()
            .filter(|(i, _)| i == iface)
            .flat_map(|(_, locs)| locs.iter().copied())
            .collect();
        let plan = st.steer_plans.iter().find(|(i, _, _)| i == iface);
        // VF 0: `acquire` creates exactly one per PF.
        let vf = plan.map_or(0, |(_, vf, _)| *vf);
        ntuple::rule_table_reclaiming(iface, vf, &recorded, plan.map(|(_, _, p)| p))
    }
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
/// `(PF iface, VF index, rules)` for every `steer on` port: one plan per
/// distinct (effective direction, receive MACs), all drawn from the shared
/// free-slot intersection so a location number names the same slot on
/// every steering port. Locations are per-interface, so ports of
/// different plans reusing the same numbers do not collide — and each
/// port's budget requirement is its OWN plan's size, not the union's.
///
/// The one derivation attach and reconfigure share: if they disagreed
/// about what fits, a config that attached could refuse its first reload.
///
/// A steering port whose receive MACs cannot be read is refused: rules
/// without them would divert frames the kernel is only bridging.
///
/// The port's `v6-divert` joins the plan key: two ports share a plan
/// only when their v6 diversion is the same too. `tagged_vlans` answers
/// which VLANs a `vlans all` trunk's kernel bridge carries tagged — see
/// [`VppOffloadConfig::v6_steering`].
pub(crate) fn plan_targets(
    cfg: &VppOffloadConfig,
    allowlist: &[packetframe_common::fib::IpPrefix],
    budget: &steer::McamBudget,
    receive_macs: &dyn Fn(&str) -> Vec<[u8; 6]>,
    tagged_vlans: &dyn Fn(&str) -> Result<Vec<u16>, String>,
) -> Result<Vec<(String, u32, steer::RuleSet)>, String> {
    type PlanKey = (VppSteerDirection, Vec<[u8; 6]>, steer::V6Steering);
    let mut plans: Vec<(PlanKey, steer::RuleSet)> = Vec::new();
    let mut targets = Vec::new();
    for (iface, _, steer_on, _, dir) in &cfg.ports {
        if !steer_on {
            continue;
        }
        let macs = receive_macs(iface);
        if macs.is_empty() {
            return Err(format!(
                "cannot read the MAC(s) frames to this router arrive with on {iface}; \
                 steering it without them would divert frames the kernel is only bridging \
                 between hosts, and VPP would drop them"
            ));
        }
        let v6 = cfg.v6_steering(iface, tagged_vlans)?;
        let key: PlanKey = (dir.unwrap_or(cfg.steer_direction), macs, v6);
        if !plans.iter().any(|(k, _)| *k == key) {
            let plan = steer::RuleSet::plan_with_v6(
                allowlist,
                &cfg.steer_exempts,
                budget.clone(),
                key.0,
                &key.1,
                &key.2,
            )
            .map_err(|e| format!("port {iface}: {e}"))?;
            plans.push((key.clone(), plan));
        }
        let plan = plans
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, p)| p.clone())
            .expect("planned above");
        // VF 0 because `acquire` creates exactly one per PF.
        targets.push((iface.clone(), 0u32, plan));
    }
    Ok(targets)
}

fn steering_target(
    cfg: &VppOffloadConfig,
    allowlist: &[packetframe_common::fib::IpPrefix],
    table: impl Fn(&str) -> Result<ntuple::RuleTable, String>,
    receive_macs: &dyn Fn(&str) -> Vec<[u8; 6]>,
    tagged_vlans: &dyn Fn(&str) -> Result<Vec<u16>, String>,
) -> Result<SteeringTarget, String> {
    // VF 0 because `acquire` creates exactly one per PF.
    let ports: Vec<(String, u32, VppSteerDirection)> = cfg
        .ports
        .iter()
        .filter(|(_, _, steer, _, _)| *steer)
        .map(|(iface, _, _, _, dir)| (iface.clone(), 0u32, dir.unwrap_or(cfg.steer_direction)))
        .collect();
    if ports.is_empty() {
        // Nothing to install and nothing that reads a plan. An empty
        // target is also the truthful one: no port steers.
        return Ok(SteeringTarget {
            targets: Vec::new(),
            want_steer: false,
        });
    }
    let budget = steer::McamBudget::for_ifaces_with(
        ports.iter().map(|(iface, _, _)| iface.as_str()),
        table,
    )?;
    let targets = plan_targets(cfg, allowlist, &budget, receive_macs, tagged_vlans)?;
    // `steer on` with nothing steerable is refused for the same reason
    // `bring_up` refuses it: steering would divert nothing while every
    // surface reported it on. Per PORT, now that plans differ by more
    // than the shared allowlist: a `v6-divert` port has rules with no
    // v4 to steer, and a port beside it without the tail has none —
    // which `steer` would refuse for the whole target anyway, so it is
    // refused here, naming the port, before anything reaches the loop.
    let empty: Vec<&str> = targets
        .iter()
        .filter(|(_, _, p)| p.rules.is_empty())
        .map(|(i, _, _)| i.as_str())
        .collect();
    if !empty.is_empty() {
        let skipped = targets.first().map_or(0, |(_, _, p)| p.skipped_v6);
        return Err(format!(
            "port(s) {empty:?} are configured `steer on`, but the allowlist produces no \
             steerable rules for them ({skipped} IPv6 prefix(es) skipped — `ip6` ntuple \
             cannot match a v6 address on this NIC) and they have no `v6-divert`. \
             Steering would divert nothing while reporting Healthy"
        ));
    }
    Ok(SteeringTarget {
        targets,
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
    /// The feed's session-liveness handle, when the loader wired one;
    /// see [`Self::set_feed_session`].
    feed_session: Option<std::sync::Arc<packetframe_common::fib::FeedSession>>,
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
    /// Set when a `detach` could not confirm the teardown.
    ///
    /// Outlives the attachment on purpose. `detach` takes `attached` before
    /// it can discover a failure — the service is consumed by `stop()` — so
    /// without this a second `detach` found `None` and returned `Ok`,
    /// reporting a clean detach over VFs and hugepages that were still
    /// held. `packetframe detach --all` retries, so that is the likely
    /// path, not a hypothetical one.
    teardown_failure: Option<String>,
    /// Loader-resolved `local-route` set (config triple + kernel bridge
    /// device). See [`Self::set_local_routes`].
    local_routes: Vec<LocalRoute>,
    /// How `reconfigure` plans its steering target: [`live_reload_plan`]
    /// everywhere but the reload tests, whose host has neither the NIC's
    /// rule tables nor the kernel's receive MACs to read.
    plan_reload: ReloadPlanner,
}

/// Plans a reload's steering target from the new config, the live
/// allowlist and the state directory.
type ReloadPlanner = fn(
    &VppOffloadConfig,
    &[packetframe_common::fib::IpPrefix],
    &std::path::Path,
) -> Result<SteeringTarget, String>;

/// The reload's plan, drawn from the NIC and the kernel as they are now.
fn live_reload_plan(
    cfg: &VppOffloadConfig,
    allowlist: &[packetframe_common::fib::IpPrefix],
    state_dir: &std::path::Path,
) -> Result<SteeringTarget, String> {
    steering_target(
        cfg,
        allowlist,
        planning_table(state_dir),
        &topology::kernel_receive_macs,
        &topology::kernel_tagged_vlans,
    )
}

impl VppOffloadModule {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            allowlist: std::sync::Arc::new(SharedAllowlist::default()),
            completeness: None,
            feed_session: None,
            cfg: VppOffloadConfig::default(),
            state_dir: std::path::PathBuf::new(),
            source: None,
            attached: None,
            teardown_pending: None,
            teardown_failure: None,
            local_routes: Vec::new(),
            plan_reload: live_reload_plan,
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

    /// Hand the module its resolved `local-route` and `local-route6` set.
    ///
    /// A setter for the same reason the allowlist is one: the kernel
    /// bridge device each prefix's neighbours mirror from is the `via`
    /// of the fast-path `local-prefix` covering it, and only the loader
    /// sees both sections. A plain Vec rather than a shared handle
    /// because `local-route` is restart-only — there is no SIGHUP path
    /// that could make a snapshot stale.
    pub fn set_local_routes(&mut self, routes: Vec<LocalRoute>) {
        self.local_routes = routes;
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

    /// Hand the module the feed's session-liveness handle.
    ///
    /// Read by the deferred adopted reconciliation: a small table's
    /// release needs to know the session that fed the mirror is still
    /// up, because no mirror-side count can distinguish a loaded small
    /// table from the husk a dead session leaves behind (review
    /// finding). Absent, the small-table release is simply off — the
    /// capacity floor and the completeness authority still release.
    pub fn set_feed_session(
        &mut self,
        handle: std::sync::Arc<packetframe_common::fib::FeedSession>,
    ) {
        self.feed_session = Some(handle);
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
        let sizing = startup_conf::derive_sizing(
            self.cfg.expected_routes,
            self.cfg.total_workers(),
            self.cfg.v6,
        )
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
                "a previous teardown is still running in the background (it kills VPP and \
                 releases its VF); attaching now would race it. Wait for it to settle — \
                 `health_check` reports when it has — and retry.",
            ));
        }
        if let Some(why) = &self.teardown_failure {
            return Err(ModuleError::other(
                MODULE_NAME,
                format!(
                    "a previous teardown did not complete, so its resources may still be \
                     held: {why}. Resolve that first (`packetframe detach --all` once VPP \
                     is confirmed gone); attaching over it would put a second supervisor on \
                     the same VF."
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
        // The loader resolves `local-route` against fast-path's
        // `local-prefix` and hands the result to `set_local_routes`.
        // A section carrying lines the module was never handed means
        // that wiring is missing — refused loudly here rather than
        // attaching a VPP that silently skips the delivery this config
        // exists to provide (the published-is-not-read class).
        let declared = self.cfg.local_routes.len() + self.cfg.local_routes6.len();
        if declared != self.local_routes.len() {
            return Err(ModuleError::other(
                MODULE_NAME,
                format!(
                    "config declares {declared} local-route line(s) but the loader resolved {} — \
                     set_local_routes was not wired; refusing to attach without the local \
                     delivery the config promises",
                    self.local_routes.len()
                ),
            ));
        }
        // Size the rule tables BEFORE the budget is read, so the plan is
        // drawn from the table the NIC actually holds afterwards — and
        // hand the entries back if attach then refuses, since the shared
        // pool would otherwise stay drained until reboot.
        let resized = apply_steer_capacity(&self.cfg, &capacity::Live);
        let brought_up = steer::McamBudget::for_ifaces_with(
            ifaces_to_query(&self.cfg, &allowlist),
            planning_table(&self.state_dir),
        )
        .and_then(|budget| {
            bringup::bring_up(
                &self.cfg,
                &paths,
                source,
                &allowlist,
                self.completeness.clone(),
                self.feed_session.clone(),
                &budget,
                &self.local_routes,
            )
        });
        let attached = match brought_up {
            Ok(a) => a,
            Err(e) => {
                release_steer_capacity(&resized, &capacity::Live);
                return Err(ModuleError::other(MODULE_NAME, e));
            }
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
        // Here and not inside `bring_up`: from this point the attach
        // cannot fail, so the placement never outlives a module that
        // degraded (`bringup::place_control_plane`).
        if let Some(cp) = &attached.control_plane {
            bringup::place_control_plane(cp);
        }
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
    /// likewise only mean anything at spawn. `require-table-complete` is
    /// restart-only too, though nothing about VPP makes it so: the
    /// completeness handle is installed once by the attach wiring and
    /// this method never touches it, so the refusal is the only thing
    /// keeping the running gate and the file on disk from disagreeing.
    /// See [`VppOffloadConfig::restart_only_delta`] for why refusing beat
    /// wiring it up.
    ///
    /// A reload that changes no steering input is applied unchanged,
    /// without a round trip to the supervision loop, in every state —
    /// unless re-sending it is the operator's lever there (a steering
    /// repair, an immediate retry, a removal); see the comment at the skip.
    fn reconfigure(&mut self, cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
        let new = VppOffloadConfig::from_directives(&cfg.section.directives);
        if let Err(why) = self.cfg.restart_only_delta(&new) {
            return Err(ModuleError::other(
                MODULE_NAME,
                format!("{why}{}", reload_collateral(&self.cfg, &new)),
            ));
        }

        // Nothing to steer into. Not an error: a config with every port
        // `steer off` and no attachment is a legitimate state, and so is
        // a SIGHUP arriving between `load` and `attach`.
        let Some(attached) = &mut self.attached else {
            self.cfg = new;
            return Ok(());
        };
        // Before anything below can return: `drift-accept6` is hot on its
        // own terms. It changes only what the tripwire reports, so it
        // neither waits for the loop nor for the steering outcome — a
        // first steer refused by the completeness gate, say, must not
        // leave an accepted finding degrading health. The loop reads it
        // when the next scan lands ([`drift::DriftAccepts6`]).
        attached.drift_accepts6.publish(new.drift_accepts6.clone());

        let allowlist = self.allowlist.get();
        let target = (self.plan_reload)(&new, &allowlist, &self.state_dir)
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
            .map(|(_, _, steer, _, _)| *steer)
            .ne(new.ports.iter().map(|(_, _, steer, _, _)| *steer));
        let planned = SteeringInputs {
            targets: target.targets,
            // The SAME derivation attach uses, run against the config
            // just accepted — exemptions, allowlist, directions and
            // `v6-divert` are all hot, so a scope captured at attach
            // goes stale the moment any of them moves.
            scope: drift::DriftScope::from_config(&new, &allowlist),
            want_steer: target.want_steer,
        };
        // Nothing for the loop to do? Then do not ask it.
        //
        // Every reload used to go through the loop, including one that
        // edited only fast-path's section — and a loop mid-convergence
        // can spend longer than the steering budget on one tick, so a
        // fast-path `dry-run` flip failed here with "did not pick up the
        // steering change" about a change nobody made (hardware, during a
        // fresh 1.09M-route convergence). And a loop that DID answer
        // refused it: the same flip during a keep-VPP restart came back
        // "vpp-offload is AdoptedResyncing, not converged" and was logged
        // `reconfigure_failed` for a module whose configuration had not
        // changed (hardware). Now a reload skips the round trip when all
        // of these hold:
        //
        // - the lever did not move — implied by equal targets, stated so
        //   the canary rule does not rest on an inference;
        // - the planned inputs equal what the loop holds, which this
        //   module knows only after an attach or an `Ok`
        //   (`held_steering` is cleared on every failure). The plan is
        //   every hot input this method applies through the loop — the
        //   `steer` flags, directions, exemptions, keeps, `v6-divert`, and
        //   fast-path's allowlist read live — so an `allow-prefix` edit
        //   fails this test and a `dry-run` flip passes it. The one other
        //   hot directive, `drift-accept6`, was published above;
        // - an identical request would not ACT: nothing is steered or
        //   wanted, or the state would refuse it untouched — in every
        //   convergence state, degraded or not. What still goes to the
        //   loop is the plain `reconfigure` the runbook uses as a lever —
        //   the steering repair from `Steered`, "ask now" for a remembered
        //   want from `Ready`, and the rollback's retry for a removal —
        //   which is the only place a re-send does something. See
        //   `service::ResendVerdict`.
        //
        // "The state would refuse it" is only as fresh as the loop's last
        // snapshot, and a pass in flight may already have reached `Ready`
        // with a want, where this reload is the immediate retry. So from
        // a snapshot a pass may be moving past, the reload still answers
        // `Ok` but also posts the identical request without waiting for
        // it: if the retry is due it happens now, and if the loop is
        // still converging its refusal goes unread.
        //
        // The drift scope is safe too: nothing is staged, and nothing
        // needs to be, because what would have been staged is what the
        // watcher already has or is waiting to commit — and a nudge
        // stages the very scope the loop holds.
        if !lever_moved && attached.held_steering.as_ref() == Some(&planned) {
            let advice = attached.service.resend_advice(planned.want_steer);
            if advice != service::ResendAdvice::Send {
                if advice == service::ResendAdvice::SkipAndNudge {
                    attached.service.nudge_steering(
                        planned.targets.clone(),
                        planned.scope.clone(),
                        planned.want_steer,
                    );
                }
                tracing::info!(
                    nudged = advice == service::ResendAdvice::SkipAndNudge,
                    "vpp-offload: reload changes none of this module's steering inputs; \
                     applied unchanged without waiting on the supervision loop"
                );
                self.cfg = new;
                return Ok(());
            }
        }
        let outcome = attached.service.apply_steering(
            planned.targets.clone(),
            planned.scope.clone(),
            planned.want_steer,
            lever_moved,
        );
        // Known only on success. A refusal after `retarget` leaves the
        // loop holding the NEW target, one before it the old, and a
        // timeout either — so remembering the old inputs could skip a
        // reload that reverts to them while the loop holds something else.
        attached.held_steering = outcome.is_ok().then_some(planned);
        outcome.map_err(|e| ModuleError::other(MODULE_NAME, e))?;
        // Recorded only after the change landed. A `cfg` updated ahead of
        // the apply would make the NEXT reconfigure diff against a target
        // that was never installed, so a failed canary step would look
        // like a no-op change and never be retried.
        self.cfg = new;
        Ok(())
    }

    /// The daemon is exiting without detaching: hand VPP to the next start
    /// with its route ledger, and stop supervising — the process is going
    /// away, so there is nothing left to supervise from.
    fn exit_preserving(&mut self) {
        if let Some(attached) = self.attached.take() {
            attached.service.shutdown_preserving();
        }
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
        // `stop` drives the supervisor's full teardown ordering —
        // unsteer if steered, abort convergence, kill, release — and
        // waits out its bounded patience. The final snapshot is the only
        // record of what that left behind.
        let report = attached.service.stop();
        // A teardown still running past the detach budget is kept, not
        // dropped: `stop()`'s message sends the operator to `packetframe
        // status`, and this is what makes that reachable — `health_check`
        // below reports through it until the loop settles.
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
        // The daemon's affinity restriction is deliberately not undone:
        // a CPU mask is per-process state and every caller of this
        // method exits the process (see `cores::restrict_daemon_from`).
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
/// fast-path's per-interface probes graft into the report. Severity
/// mirrors attach: the caller runs these only when the config declares
/// this module, and every verdict on a condition attach refuses is
/// `required` — steering verdicts gate only when a port is configured
/// `steer on`, since attach installs nothing otherwise. See
/// `probe_linux`'s module doc for the incident that ended the
/// all-advisory rule.
// One argument per attach-gated directive; the CLI groups them in
// `VppProbeInputs`, the module boundary keeps plain args.
#[allow(clippy::too_many_arguments)]
pub fn run_feasibility_probes(
    ports: &[String],
    steer_ports: &[String],
    workers: u32,
    vpp_binary: Option<&str>,
    loopback: Option<std::net::Ipv4Addr>,
    allowlist: &[packetframe_common::fib::IpPrefix],
    directions: &[packetframe_common::config::VppSteerDirection],
    steer_exempts: &[packetframe_common::config::Ipv4Prefix],
    steer_capacity: Option<u16>,
    section: &[packetframe_common::config::ModuleDirective],
) -> Vec<Capability> {
    #[cfg(target_os = "linux")]
    {
        probe_linux::run(
            ports,
            steer_ports,
            workers,
            vpp_binary,
            loopback,
            allowlist,
            directions,
            steer_exempts,
            steer_capacity,
            section,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            ports,
            steer_ports,
            workers,
            vpp_binary,
            loopback,
            allowlist,
            directions,
            steer_exempts,
            steer_capacity,
            section,
        );
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

    /// One receive MAC per port, distinct per port, as a plain L3 box has.
    fn test_macs(port: &str) -> Vec<[u8; 6]> {
        let n = port.bytes().last().unwrap_or(0);
        vec![[0x02, 0, 0, 0, 0, n]]
    }

    /// A kernel bridge carrying no tagged VLAN anywhere — what every
    /// fixture without a `vlans all` v6 trunk needs, since only that
    /// asks.
    fn no_vlans(_: &str) -> Result<Vec<u16>, String> {
        Ok(Vec::new())
    }

    /// Every divert rule is scoped to the port's receive MAC, so two
    /// ports with different MACs get plans of their own — over the same
    /// slots, since locations are per-interface — and a port whose MAC
    /// cannot be read is refused rather than steered unscoped (it would
    /// divert frames the kernel is only bridging).
    #[test]
    fn divert_rules_carry_each_ports_receive_mac() {
        use packetframe_common::fib::IpPrefix;
        let allow = vec![IpPrefix::V4 {
            addr: [192, 0, 2, 0],
            prefix_len: 24,
        }];
        let on = cfg(&[("eth2", 1, true), ("eth3", 1, true)], 1_600_000);
        let t = steering_target(
            &on,
            &allow,
            |_: &str| {
                Ok(ntuple::RuleTable {
                    size: 16,
                    occupied: Vec::new(),
                })
            },
            &test_macs,
            &no_vlans,
        )
        .expect("fits");
        for (iface, _, plan) in &t.targets {
            let want = test_macs(iface)[0];
            assert!(
                plan.rules
                    .iter()
                    .filter(|r| r.action == steer::RuleAction::Divert)
                    .all(|r| r.dmac() == Some(want)),
                "{iface}: {plan:?}"
            );
        }
        assert_eq!(t.targets[0].2.locations(), t.targets[1].2.locations());

        let e = steering_target(
            &on,
            &allow,
            |_: &str| {
                Ok(ntuple::RuleTable {
                    size: 16,
                    occupied: Vec::new(),
                })
            },
            &|_: &str| Vec::new(),
            &no_vlans,
        )
        .expect_err("must refuse");
        assert!(e.contains("only bridging"), "{e}");
    }
    use packetframe_common::module::{HealthState, SubsystemHealth};
    use supervisor::State;

    struct NoRoutes;
    impl engine::RouteSource for NoRoutes {
        fn requeue(&self, _: engine::SourceChanges) {
            unreachable!("this source hands nothing over, so nothing can come back")
        }
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
            resend: service::ResendVerdict::observe(State::Ready, false),
        }
    }

    /// Records which ports `apply_steer_capacity` asked about, and what
    /// each one was set to.
    struct AskedPorts(
        std::cell::RefCell<Vec<String>>,
        std::cell::RefCell<std::collections::BTreeMap<String, u32>>,
    );

    impl AskedPorts {
        fn new() -> Self {
            Self(Default::default(), Default::default())
        }
        fn size(&self, iface: &str) -> u32 {
            *self.1.borrow().get(iface).unwrap_or(&16)
        }
    }

    impl capacity::CapacityControl for AskedPorts {
        fn table(&self, iface: &str) -> Result<ntuple::RuleTable, String> {
            let mut asked = self.0.borrow_mut();
            if asked.last().map(String::as_str) != Some(iface) {
                asked.push(iface.to_string());
            }
            Ok(ntuple::RuleTable {
                size: self.size(iface),
                occupied: Vec::new(),
            })
        }
        fn adjustable(&self, iface: &str) -> Result<u16, String> {
            Ok(self.size(iface) as u16)
        }
        fn set(&self, iface: &str, n: u16) -> Result<(), String> {
            self.1.borrow_mut().insert(iface.to_string(), u32::from(n));
            Ok(())
        }
    }

    #[test]
    fn steer_capacity_asks_only_ports_that_can_steer() {
        // `cores 0` members are egress-only — config refuses `steer on`
        // for them — so resizing their tables would spend shared pool
        // entries on rules that can never exist.
        let mut cfg = with_cores(&[1, 0, 1]);
        let ctl = AskedPorts::new();
        assert!(apply_steer_capacity(&cfg, &ctl).is_empty());
        assert!(ctl.0.borrow().is_empty(), "no directive, no NIC reads");

        cfg.steer_capacity = Some(64);
        let moved = apply_steer_capacity(&cfg, &ctl);
        assert_eq!(
            *ctl.0.borrow(),
            vec!["eth0".to_string(), "eth2".to_string()]
        );
        assert_eq!(moved, vec![("eth0".into(), 16), ("eth2".into(), 16)]);

        // A refused attach hands both back.
        release_steer_capacity(&moved, &ctl);
        assert_eq!((ctl.size("eth0"), ctl.size("eth2")), (16, 16));
    }

    #[test]
    fn steer_capacity_serves_steering_ports_before_staging_ones() {
        // A short pool must not go to a `steer off` port just because it
        // comes first in the file.
        let mut cfg = with_cores(&[1, 1, 1]);
        cfg.ports[2].2 = true;
        cfg.steer_capacity = Some(64);
        let ctl = AskedPorts::new();
        apply_steer_capacity(&cfg, &ctl);
        assert_eq!(
            *ctl.0.borrow(),
            vec!["eth2".to_string(), "eth0".to_string(), "eth1".to_string()]
        );
    }

    fn with_cores(cores: &[u16]) -> VppOffloadConfig {
        VppOffloadConfig {
            ports: cores
                .iter()
                .enumerate()
                .map(|(i, c)| (format!("eth{i}"), *c, false, vec![], None))
                .collect(),
            ..VppOffloadConfig::default()
        }
    }

    /// Without `cores 0` ports the total is the plain sum; with any,
    /// ONE shared worker is added however many there are.
    #[test]
    fn total_workers_adds_one_shared_worker_for_cores_zero_ports() {
        assert_eq!(with_cores(&[1, 1, 1]).total_workers(), 3);
        assert_eq!(with_cores(&[2, 1]).total_workers(), 3);
        assert_eq!(with_cores(&[1, 0]).total_workers(), 2);
        assert_eq!(with_cores(&[1, 0, 0, 0, 0]).total_workers(), 2);
        assert_eq!(with_cores(&[0, 0]).total_workers(), 1);
        assert_eq!(with_cores(&[2, 0, 1, 0]).total_workers(), 4);
    }

    /// The rendered startup.conf for a mixed config names exactly the
    /// workers the placement plan uses: the dedicated ones plus one
    /// shared, and the sizing agrees (`render` asserts it).
    #[test]
    fn startup_conf_for_a_mixed_config_renders_the_shared_worker() {
        let cfg = with_cores(&[1, 0, 0, 2, 0]);
        let workers = cfg.total_workers();
        assert_eq!(workers, 4);
        let online: Vec<u16> = (0..12).collect();
        let map = cores::derive_core_map(&online, &[], workers).unwrap();
        assert_eq!(map.workers, vec![8, 9, 10, 11]);
        let sizing = startup_conf::derive_sizing(DEFAULT_EXPECTED_ROUTES, workers, false).unwrap();
        let conf = startup_conf::render(&sizing, &map.workers, map.main, "/run/pf/api.sock", 0);
        assert!(conf.contains("main-core 7\n"), "{conf}");
        assert!(conf.contains("corelist-workers 8,9,10,11\n"), "{conf}");
        // And every worker the conf starts is one the plan places a
        // queue on — the shared one last.
        let ports: Vec<(&str, u16)> = cfg
            .ports
            .iter()
            .map(|(i, c, ..)| (i.as_str(), *c))
            .collect();
        let max_worker = cores::rx_placement_plan(&ports)
            .into_iter()
            .flat_map(|(_, q)| q)
            .map(|q| q.worker_id)
            .max()
            .unwrap();
        assert_eq!(max_worker, workers - 1);
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
            ports: vec![
                ("eth4".into(), 1, true, vec![], None),
                ("eth5".into(), 1, false, vec![], None),
            ],
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
            addr: [198, 51, 100, 0],
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
                .map(|(i, c, s)| (i.to_string(), *c, *s, vec![], None))
                .collect(),
            vpp_binary: None,
            expected_routes: routes,
            hugepages: None,
            require_table_complete: true,
            steer_exempts: vec![],
            local_routes: vec![],
            local_routes6: vec![],
            steer_capacity: None,
            trunk_ports: vec![],
            v6_divert: vec![],
            steer_keeps6: vec![],
            drift_accepts6: vec![],
            v6: false,
            steer_direction: Default::default(),
            loopback_address6: None,
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

    /// Toggling `require-table-complete` is refused, in both directions.
    ///
    /// The third acceptable outcome — accepted-and-ignored — is the one
    /// that shipped: the directive was permitted through this function
    /// and then never applied, because the completeness handle is
    /// installed once by the attach wiring and `reconfigure` never
    /// touches it. So an operator following the `AuthorityMismatch`
    /// remedy edited the file, reloaded, was told OK, and ran on the old
    /// gate. Either it takes effect or it is refused; "OK" over no
    /// change is the one answer that is not allowed.
    ///
    /// Both directions, deliberately. `on → off` is the documented
    /// remedy and the obvious case; `off → on` is the dangerous one,
    /// because a success there reports a safety gate as armed when the
    /// runtime holds no handle at all.
    #[test]
    fn toggling_require_table_complete_is_a_restart() {
        let on = cfg(&[("eth4", 1, false)], 1_600_000);
        let mut off = on.clone();
        off.require_table_complete = false;

        for (before, after, from, to) in [(&on, &off, "on", "off"), (&off, &on, "off", "on")] {
            let e = before
                .restart_only_delta(after)
                .expect_err("a toggled `require-table-complete` must never be accepted silently");
            assert!(
                e.contains("`require-table-complete` changed"),
                "the operator has to be told WHICH knob: {e}"
            );
            assert!(
                e.contains(&format!("({from} → {to})")),
                "and in the direction they edited it: {e}"
            );
            assert!(
                e.contains("Restart to apply"),
                "and what to DO about it, since the reload will not: {e}"
            );
        }

        // The positive control: same value, no refusal. Without this the
        // test above passes just as well against a function that refuses
        // every reload.
        on.restart_only_delta(&on.clone())
            .expect("an unchanged directive is not a change");
    }

    /// And the refusal is reachable through the RELOAD, not just through
    /// the pure function.
    ///
    /// `restart_only_delta` is called first in `reconfigure`, before the
    /// attachment is consulted — which is what makes the message right
    /// in every state, including the deferred adopted resync where the
    /// remedy is read and where `apply_steering` would otherwise answer
    /// with a refusal about steering and a promise ("takes effect at the
    /// next successful convergence") that is false of this directive.
    /// Asserted end-to-end because that ordering is the whole reason
    /// refusing was chosen over wiring it up.
    #[test]
    fn a_reload_that_toggles_the_directive_is_refused_not_ignored() {
        use packetframe_common::config::{GlobalConfig, ModuleDirective, ModuleSection};
        use packetframe_common::module::{Module as _, ModuleConfig};

        let section_with = |require: bool| ModuleSection {
            name: "vpp-offload".into(),
            directives: vec![
                ModuleDirective::VppPort {
                    iface: "eth4".into(),
                    cores: 1,
                    steer: false,
                    vlans: vec![],
                    vlans_all: false,
                    direction: None,
                    v6_divert: None,
                    line: 1,
                },
                ModuleDirective::VppRequireTableComplete(require),
            ],
        };
        let global = GlobalConfig::default();
        let loaded = section_with(true);
        let ctx = LoaderCtx {
            bpffs_root: std::path::Path::new("/sys/fs/bpf"),
            state_dir: std::path::Path::new("/tmp/pf-require-table-complete"),
        };

        let mut m = VppOffloadModule::new();
        m.load(&ModuleConfig::new(&loaded, &global), &ctx)
            .expect("a single-port section loads");

        // Unchanged reloads through the same path, so the refusal below
        // cannot be an artefact of reconfiguring an unattached module.
        m.reconfigure(&ModuleConfig::new(&loaded, &global))
            .expect("an unchanged section reloads");

        let toggled = section_with(false);
        let e = m
            .reconfigure(&ModuleConfig::new(&toggled, &global))
            .expect_err("the reload must refuse a toggled `require-table-complete`");
        let msg = e.to_string();
        assert!(msg.contains("`require-table-complete` changed"), "{msg}");
        assert!(msg.contains("Restart to apply"), "{msg}");

        // And the refusal did not half-apply: `cfg` still holds what the
        // running daemon was built from, so a later status or a second
        // reload describes the gate that is actually installed.
        assert!(
            m.cfg.require_table_complete,
            "a refused reload must not record the value it refused"
        );
    }

    /// One `dst` port plus whatever else a test adds. `dst` so the
    /// watcher's scope IS the allowlist, which makes an `allow-prefix`
    /// edit a steering change.
    fn section_steering(
        steer: bool,
        extra: Vec<packetframe_common::config::ModuleDirective>,
    ) -> packetframe_common::config::ModuleSection {
        let mut directives = vec![packetframe_common::config::ModuleDirective::VppPort {
            iface: "eth4".into(),
            cores: 1,
            steer,
            vlans: vec![],
            vlans_all: false,
            direction: Some(VppSteerDirection::Dst),
            v6_divert: None,
            line: 1,
        }];
        directives.extend(extra);
        packetframe_common::config::ModuleSection {
            name: "vpp-offload".into(),
            directives,
        }
    }

    /// The port `steer off`: planning reads nothing and plans nothing.
    fn resend_section(
        extra: Vec<packetframe_common::config::ModuleDirective>,
    ) -> packetframe_common::config::ModuleSection {
        section_steering(false, extra)
    }

    /// The port `steer on`, as on a box whose adopted VPP is carrying
    /// traffic.
    fn steered_section(
        extra: Vec<packetframe_common::config::ModuleDirective>,
    ) -> packetframe_common::config::ModuleSection {
        section_steering(true, extra)
    }

    fn doc_prefix(fourth: u8) -> packetframe_common::fib::IpPrefix {
        packetframe_common::fib::IpPrefix::V4 {
            addr: [192, 0, 2, fourth],
            prefix_len: 32,
        }
    }

    fn doc_exempt() -> packetframe_common::config::ModuleDirective {
        packetframe_common::config::ModuleDirective::VppSteerExempt(
            packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(198, 51, 100, 0),
                prefix_len: 24,
            },
        )
    }

    /// The reload's plan against an empty 16-slot table and fixed receive
    /// MACs: `steering_target` itself, minus the NIC and the kernel.
    fn table_free_plan(
        cfg: &VppOffloadConfig,
        allowlist: &[packetframe_common::fib::IpPrefix],
        _: &std::path::Path,
    ) -> Result<SteeringTarget, String> {
        steering_target(
            cfg,
            allowlist,
            |_: &str| {
                Ok(ntuple::RuleTable {
                    size: 16,
                    occupied: Vec::new(),
                })
            },
            &test_macs,
            &no_vlans,
        )
    }

    /// A snapshot from `state`, with the want as given — the verdict
    /// observed from the same two predicates the loop publishes it from.
    fn published_in(state: State, steer_intended: bool) -> service::Published {
        service::Published {
            state,
            resend: service::ResendVerdict::observe(state, steer_intended),
            ..healthy_published()
        }
    }

    /// Loaded and attached as `attach` would leave it — `held_steering`
    /// as `bring_up` records it, planned the way a reload plans — behind
    /// `service`.
    fn attached_behind(
        section: &packetframe_common::config::ModuleSection,
        service: service::SupervisionService,
    ) -> VppOffloadModule {
        let global = packetframe_common::config::GlobalConfig::default();
        let ctx = LoaderCtx {
            bpffs_root: std::path::Path::new("/sys/fs/bpf"),
            state_dir: std::path::Path::new("/tmp/pf-resend-skip"),
        };
        let mut m = VppOffloadModule::new();
        m.plan_reload = table_free_plan;
        m.set_allowlist(std::sync::Arc::new(SharedAllowlist::new(vec![doc_prefix(
            1,
        )])));
        m.load(&ModuleConfig::new(section, &global), &ctx)
            .expect("the section loads");
        let allowlist = m.allowlist.get();
        let target = (m.plan_reload)(&m.cfg, &allowlist, &m.state_dir).expect("plans");
        let held = SteeringInputs {
            targets: target.targets,
            scope: drift::DriftScope::from_config(&m.cfg, &allowlist),
            want_steer: target.want_steer,
        };
        m.attached = Some(bringup::Attached {
            service,
            cores: cores::CoreMap {
                main: 0,
                workers: Vec::new(),
            },
            acquired: acquire::Acquired::Fresh,
            adopted_process: false,
            held_steering: Some(held),
            control_plane: None,
            drift_accepts6: std::sync::Arc::new(drift::DriftAccepts6::new(
                m.cfg.drift_accepts6.clone(),
            )),
        });
        m
    }

    /// Behind a loop that never picks up a steering request: the tick
    /// mid-convergence, held forever.
    fn behind_a_wedged_loop(
        section: &packetframe_common::config::ModuleSection,
        published: service::Published,
    ) -> VppOffloadModule {
        attached_behind(
            section,
            service::SupervisionService::wedged_for_test(published),
        )
    }

    /// Behind a loop that answers at once, with `apply_steering`'s own
    /// admission verdict for the snapshot's state.
    fn behind_an_answering_loop(
        section: &packetframe_common::config::ModuleSection,
        published: service::Published,
    ) -> VppOffloadModule {
        attached_behind(
            section,
            service::SupervisionService::answering_for_test(published),
        )
    }

    fn requests(m: &VppOffloadModule) -> u64 {
        m.attached
            .as_ref()
            .expect("attached")
            .service
            .requests_for_test()
    }

    fn reload(
        m: &mut VppOffloadModule,
        section: &packetframe_common::config::ModuleSection,
    ) -> ModuleResult<()> {
        let global = packetframe_common::config::GlobalConfig::default();
        m.reconfigure(&ModuleConfig::new(section, &global))
    }

    /// The loader's SIGTERM path reaches the service's preserving
    /// shutdown through `Module::exit_preserving`: supervision ends —
    /// the process is going away — without the detach teardown, and the
    /// module no longer claims an attachment it has handed on.
    #[test]
    fn exit_preserving_ends_supervision_without_a_teardown() {
        let section = resend_section(vec![]);
        let mut m = behind_a_wedged_loop(&section, healthy_published());
        let started = std::time::Instant::now();
        m.exit_preserving();
        assert!(m.attached.is_none(), "the attachment is handed on");
        assert!(m.teardown_failure.is_none() && m.teardown_pending.is_none());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "the stand-in loop honours the preserve request promptly: {:?}",
            started.elapsed()
        );
    }

    /// The first hardware failure: a reload that edited only fast-path's
    /// section, while the loop was mid-convergence, failed on a steering
    /// change nobody made. With the inputs unchanged and nothing for the
    /// loop to re-apply, the loop is not asked.
    #[test]
    fn an_unchanged_reload_does_not_wait_for_a_busy_loop() {
        let section = resend_section(vec![]);
        let mut m = behind_a_wedged_loop(&section, published_in(State::Syncing, false));
        let started = std::time::Instant::now();
        reload(&mut m, &section).expect("nothing changed, so nothing can be refused");
        assert!(
            started.elapsed() < service::STEERING_BUDGET / 2,
            "answered in {:?} — that is the loop's budget, so it was asked",
            started.elapsed()
        );
        assert_eq!(requests(&m), 0, "the loop was not asked");
        m.detach().expect("the stand-in loop stops");
    }

    /// The second hardware failure, and every state like it: a keep-VPP
    /// restart adopted a steered VPP, so the want is recorded, and a
    /// reload that flipped only fast-path's `dry-run` came back
    /// "vpp-offload is AdoptedResyncing, not converged" — `reconfigure_failed`
    /// for a module whose configuration had not changed.
    ///
    /// Behind a loop that WOULD answer, with its own refusal: a reload
    /// that reached it fails here with that message rather than passing
    /// on a timing. Every state that refuses a steer, with and without a
    /// want — the adopted resync, a fresh convergence, the verify, and the
    /// degraded ones with no process — plus the two that admit one with
    /// nothing steered or wanted.
    #[test]
    fn an_unchanged_reload_is_applied_in_every_state_without_asking_the_loop() {
        let section = steered_section(vec![]);
        let every_state = [
            State::Stopped,
            State::Backoff,
            State::Starting,
            State::Syncing,
            State::Verifying,
            State::Ready,
            State::Steered,
            State::AdoptedResyncing,
        ];
        for state in every_state {
            for intended in [false, true] {
                if intended && state.accepts_steering_changes() {
                    // The operator's lever: see the Steered test below.
                    continue;
                }
                let mut m = behind_an_answering_loop(&section, published_in(state, intended));
                reload(&mut m, &section).unwrap_or_else(|e| {
                    panic!("{state:?} intended={intended}: nothing changed, yet: {e}")
                });
                assert_eq!(
                    requests(&m),
                    0,
                    "{state:?} intended={intended}: asked the loop"
                );
                assert!(
                    m.attached
                        .as_ref()
                        .expect("attached")
                        .held_steering
                        .is_some(),
                    "{state:?}: an unchanged reload keeps what the loop is known to hold"
                );
                m.detach().expect("the stand-in loop stops");
            }
        }
    }

    /// Behind a stand-in loop whose snapshot says `published.state` while
    /// it is really in `actually`, with a pass in flight or not — plus the
    /// record of every request it takes, as `(want_steer, admitted)`.
    fn behind_a_loop_really_in(
        section: &packetframe_common::config::ModuleSection,
        published: service::Published,
        mid_pass: bool,
        actually: State,
    ) -> (VppOffloadModule, service::TakenLog) {
        let (svc, taken) =
            service::SupervisionService::stub_for_test(published, mid_pass, Some(actually));
        (attached_behind(section, svc), taken)
    }

    /// Wait for the stand-in loop to have taken `n` requests.
    fn taken_after(taken: &std::sync::Mutex<Vec<(bool, bool)>>, n: usize) -> Vec<(bool, bool)> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let seen = taken.lock().unwrap().clone();
            if seen.len() >= n || std::time::Instant::now() >= deadline {
                return seen;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// (a) The review finding: the snapshot says `AdoptedResyncing`, but a
    /// pass in flight has already reached `Ready` with the want recorded —
    /// where this unchanged reload is the operator's immediate retry. The
    /// reload answers `Ok` without waiting, and the loop receives exactly
    /// one nudge, which it ADMITS: the steer attempt happens now rather
    /// than at the next retry interval.
    #[test]
    fn a_stale_snapshot_answers_ok_and_nudges_the_retry_that_is_due() {
        let section = steered_section(vec![]);
        let (mut m, taken) = behind_a_loop_really_in(
            &section,
            published_in(State::AdoptedResyncing, true),
            true,
            State::Ready,
        );
        let started = std::time::Instant::now();
        reload(&mut m, &section).expect("nothing changed, so nothing can fail");
        assert!(
            started.elapsed() < service::STEERING_BUDGET / 2,
            "the reload does not wait on the nudge: {:?}",
            started.elapsed()
        );
        assert_eq!(
            taken_after(&taken, 1),
            [(true, true)],
            "one nudge, admitted by the loop that is really in Ready"
        );
        assert_eq!(requests(&m), 1, "exactly one nudge");
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(taken.lock().unwrap().len(), 1, "and nothing after it");
        m.detach().expect("the stand-in loop stops");
    }

    /// (b) The same stale snapshot over a loop that IS still resyncing:
    /// the nudge is refused, nobody reads the refusal, and the reload —
    /// and the next one — are still `Ok`, with the loop's target still
    /// known, since a nudge re-sends exactly what it holds.
    #[test]
    fn a_nudge_into_a_genuine_resync_is_refused_harmlessly() {
        let section = steered_section(vec![]);
        let (mut m, taken) = behind_a_loop_really_in(
            &section,
            published_in(State::AdoptedResyncing, true),
            true,
            State::AdoptedResyncing,
        );
        reload(&mut m, &section).expect("the refused nudge is not the reload's answer");
        assert_eq!(taken_after(&taken, 1), [(true, false)], "refused, unread");
        assert!(
            m.attached
                .as_ref()
                .expect("attached")
                .held_steering
                .is_some(),
            "a nudge re-sends what the loop holds, so the target stays known"
        );
        reload(&mut m, &section).expect("and again");
        assert_eq!(taken_after(&taken, 2), [(true, false), (true, false)]);
        m.detach().expect("the stand-in loop stops");
    }

    /// (c) From a SETTLED snapshot the refusal it predicts is current — a
    /// request placed now is taken before the next tick against exactly
    /// that state — so there is nothing to nudge.
    #[test]
    fn a_settled_non_converged_snapshot_sends_no_nudge() {
        let section = steered_section(vec![]);
        for state in [
            State::AdoptedResyncing,
            State::Syncing,
            State::Verifying,
            State::Backoff,
        ] {
            let (mut m, taken) =
                behind_a_loop_really_in(&section, published_in(state, true), false, state);
            reload(&mut m, &section).expect("nothing changed");
            std::thread::sleep(std::time::Duration::from_millis(50));
            assert_eq!(requests(&m), 0, "{state:?}: no nudge");
            assert!(taken.lock().unwrap().is_empty(), "{state:?}");
            m.detach().expect("the stand-in loop stops");
        }
    }

    /// An `allow-prefix` edit IS a change to this module — the plan is
    /// drawn from fast-path's allowlist — so during an adopted resync it is
    /// still refused, in the loop's own words, and the reload after it
    /// (still carrying the unapplied prefix) is refused too.
    #[test]
    fn an_allowlist_edit_during_an_adopted_resync_is_still_refused() {
        let section = steered_section(vec![]);
        let mut m = behind_an_answering_loop(&section, published_in(State::AdoptedResyncing, true));
        m.allowlist.publish(vec![doc_prefix(1), doc_prefix(2)]);
        let e = reload(&mut m, &section).expect_err("the plan moved");
        let e = e.to_string();
        assert!(
            e.contains("vpp-offload is AdoptedResyncing, not converged")
                && e.contains("takes effect at the next successful convergence"),
            "the existing refusal: {e}"
        );
        assert_eq!(requests(&m), 1);
        assert!(
            m.attached
                .as_ref()
                .expect("attached")
                .held_steering
                .is_none(),
            "a failed request leaves the loop's target unknown"
        );

        let e = reload(&mut m, &section).expect_err("the prefix is still unapplied");
        assert!(e.to_string().contains("not converged"), "{e}");
        assert_eq!(requests(&m), 2);
        m.detach().expect("the stand-in loop stops");
    }

    /// A real hot change from `Steered` still goes to the loop and lands:
    /// the loop's answer is `Ok`, and what it now holds — the new
    /// exemption in the scope — is what the next reload compares against.
    #[test]
    fn a_hot_change_in_steered_still_applies() {
        let section = steered_section(vec![]);
        let changed = steered_section(vec![doc_exempt()]);
        let mut m = behind_an_answering_loop(&section, published_in(State::Steered, true));
        reload(&mut m, &changed).expect("Steered admits a steering change");
        assert_eq!(requests(&m), 1, "a change goes to the loop");
        let held = m
            .attached
            .as_ref()
            .expect("attached")
            .held_steering
            .clone()
            .expect("an Ok is remembered");
        assert_eq!(held.scope.exempts.len(), 1, "{held:?}");
        assert_eq!(m.cfg.steer_exempts.len(), 1);

        // And the plain `reconfigure` after it is the runbook's steering
        // repair — a reconcile that re-installs what a provisioning push
        // deleted — so from `Steered` it still reaches the loop.
        reload(&mut m, &changed).expect("the repair reconciles");
        assert_eq!(requests(&m), 2, "the repair lever reaches the loop");
        m.detach().expect("the stand-in loop stops");
    }

    /// Any real steering change still goes to the loop, with the same
    /// timeout and withdrawal as before — and a failure forgets what the
    /// loop holds, so re-sending the same config is not mistaken for a
    /// no-op. That re-send is how an operator retries.
    #[test]
    fn a_changed_reload_still_needs_the_loop_and_a_failure_is_not_remembered() {
        let section = resend_section(vec![]);
        let changed = resend_section(vec![doc_exempt()]);
        let mut m = behind_a_wedged_loop(&section, healthy_published());
        let e = reload(&mut m, &changed).expect_err("a new `steer-exempt` must reach the loop");
        assert!(e.to_string().contains("did not pick up"), "{e}");
        assert!(
            m.attached
                .as_ref()
                .expect("attached")
                .held_steering
                .is_none(),
            "a failed request leaves the loop's target unknown"
        );
        let e = reload(&mut m, &changed).expect_err("the retry must reach the loop too");
        assert!(e.to_string().contains("did not pick up"), "{e}");
        m.detach().expect("the stand-in loop stops");
    }

    /// The allowlist lives in fast-path's section, and the plan is drawn
    /// from the live handle — so an `allow-prefix` edit with this module's
    /// own section untouched is still a steering change, which is the
    /// whole reason `SharedAllowlist` is a handle.
    #[test]
    fn an_allowlist_edit_alone_still_needs_the_loop() {
        let section = resend_section(vec![]);
        let mut m = behind_a_wedged_loop(&section, healthy_published());
        m.allowlist.publish(vec![doc_prefix(1), doc_prefix(2)]);
        let e = reload(&mut m, &section).expect_err("the watcher's scope moved");
        assert!(e.to_string().contains("did not pick up"), "{e}");
        m.detach().expect("the stand-in loop stops");
    }

    /// `drift-accept6` is hot WITHOUT the loop: it is no steering input,
    /// so a reload that edits only it is answered at once — even behind a
    /// loop that would never pick up a request — and lands in the handle
    /// the loop reads each scan, in both directions.
    #[test]
    fn a_drift_accept6_edit_reaches_the_loop_handle_without_asking_the_loop() {
        let accept = packetframe_common::config::Ipv6Prefix {
            addr: "2001:db8:100::".parse().unwrap(),
            prefix_len: 48,
        };
        let section = resend_section(vec![]);
        let accepting = resend_section(vec![
            packetframe_common::config::ModuleDirective::VppDriftAccept6 {
                prefix: accept,
                line: 2,
            },
        ]);
        let mut m = behind_a_wedged_loop(&section, healthy_published());
        let handle = m
            .attached
            .as_ref()
            .expect("attached")
            .drift_accepts6
            .clone();
        assert!(handle.get().is_empty());

        let started = std::time::Instant::now();
        reload(&mut m, &accepting).expect("an accept is not a steering change");
        assert!(
            started.elapsed() < service::STEERING_BUDGET / 2,
            "answered in {:?} — that is the loop's budget, so it was asked",
            started.elapsed()
        );
        assert_eq!(handle.get(), [accept]);
        assert_eq!(m.cfg.drift_accepts6, [accept]);

        reload(&mut m, &section).expect("and taking it away is not either");
        assert!(handle.get().is_empty());
        m.detach().expect("the stand-in loop stops");
    }

    /// Unchanged inputs are not enough. Here the config asks for nothing
    /// steered while the loop still has something steered or wanted — a
    /// refused removal, say — and re-sending is the rollback's retry, so
    /// it must reach the loop: from `Ready`, and from a converging state,
    /// which admits a removal precisely so a deferral cannot strand
    /// traffic on VPP.
    #[test]
    fn an_unchanged_reload_still_reaches_the_loop_when_a_resend_would_act() {
        let section = resend_section(vec![]);
        let mut m = behind_a_wedged_loop(&section, published_in(State::Ready, true));
        let e = reload(&mut m, &section).expect_err("the removal must be re-asked");
        assert!(e.to_string().contains("did not pick up"), "{e}");
        m.detach().expect("the stand-in loop stops");

        let mut m = behind_an_answering_loop(&section, published_in(State::AdoptedResyncing, true));
        reload(&mut m, &section).expect("a converging state admits a removal");
        assert_eq!(requests(&m), 1, "the rollback's retry reached the loop");
        m.detach().expect("the stand-in loop stops");
    }

    /// A refused reload says what ELSE it did not apply.
    ///
    /// The trap the refusal used to leave open: one SIGHUP that changes
    /// `require-table-complete` and rolls a port back to `steer off`
    /// returns an error about a completeness gate. `apply_steering` never
    /// runs, so the MCAM rules keep diverting what they diverted before —
    /// an emergency rollback that did nothing, reported as a refusal
    /// about something else entirely (review finding, PR #170).
    ///
    /// Not specific to this directive: every restart-only field has
    /// always refused the whole reload, which is why the sentence hangs
    /// off the refusal rather than off one knob.
    #[test]
    fn a_refused_reload_names_the_rollback_it_skipped() {
        let steered = cfg(&[("eth4", 1, true), ("eth5", 1, true)], 1_600_000);
        // The dangerous edit: gate toggled AND one port rolled back.
        let mut both = steered.clone();
        both.require_table_complete = false;
        both.ports[0].2 = false;

        let e = steered.restart_only_delta(&both).expect_err("refused");
        let full = format!("{e}{}", reload_collateral(&steered, &both));
        assert!(
            full.contains("asked for `steer on → off` and it was NOT applied")
                && full.contains("a rollback that did not happen"),
            "a skipped rollback must be named, not left to be inferred from a message \
             about a completeness gate: {full}"
        );
        assert!(
            full.contains("eth4") && !full.contains("eth5"),
            "and named precisely — eth5 did not move: {full}"
        );
        assert!(
            full.contains("needs no restart"),
            "and the way out must not read as another restart: {full}"
        );

        // THE RULE, asserted as a rule: this function sees two config
        // structs. Every claim it made about a state it cannot observe
        // became a review finding, in four separate rounds — so what the
        // test pins is the ABSENCE of each, not just the presence of the
        // replacement text.
        //
        // (1) The reload was not atomic across modules...
        assert!(
            full.contains("not atomic"),
            "fast-path's half of the same edit went first; claiming a whole rollback sends \
             the operator looking for something that did not happen: {full}"
        );
        assert!(
            !full.contains("Nothing else in this reload was applied"),
            "round 1's false claim: {full}"
        );
        // ...but ordering proves fast-path was ATTEMPTED first, not that
        // it succeeded: the loader records a module failure and carries
        // on, and `reconcile` is not transactional.
        assert!(
            full.contains("ATTEMPTED") && !full.contains("ALREADY taken effect"),
            "round 3's false claim — the eBPF tier's state is fast-path's result to \
             report, not ours to assert: {full}"
        );
        // ...and it is a CONDITIONAL, because the module holds a live
        // allowlist handle with no previous snapshot: it cannot know
        // whether `allow-prefix` changed at all. A reload touching only a
        // restart-only directive introduced no split, and sending that
        // operator to hunt a divergence is the same over-claim once more.
        assert!(
            full.contains("IF this reload also edited `allow-prefix`")
                && full.contains("cannot tell you whether that is what happened"),
            "round 5's false claim: the split-tier warning must be conditional and say why \
             it cannot be more than that: {full}"
        );
        // (2) Where traffic is. `self.cfg` is deliberately left unmoved
        // when a steer apply fails, and the supervisor keeps the want and
        // installs on its own once its gate clears — so neither direction
        // of the flag testifies about the NIC.
        assert!(
            !full.contains("still on VPP") && !full.contains("nothing was diverted"),
            "round 2's false claims, in opposite directions: {full}"
        );
        // (3) Whether the clean retry will even be admitted. It is gated
        // by `State::accepts_steering_changes`, and the excluded set
        // includes the deferred adopted resync this directive's remedy is
        // read in — so promising an immediate rollback there walks the
        // operator into the same failed rollback twice.
        assert!(
            !full.contains("applies immediately"),
            "round 4's false claim: the retry is still subject to the admission gate: \
             {full}"
        );
        assert!(
            full.contains("REFUSED from a resync or backoff state"),
            "and the gate must be named, since the state the remedy is read in is inside \
             it: {full}"
        );
        // Every one of those defers to a surface that CAN observe the
        // answer. Naming it is this text's job; predicting it is not.
        assert!(
            full.contains("packetframe status") && full.contains("packetframe reconfigure"),
            "the message must name the surfaces that know what it does not: {full}"
        );

        // The unconditional half covers the allowlist, which this module
        // cannot diff — it holds a live handle, so there is no previous
        // list to compare against.
        assert!(
            full.contains("allow-prefix"),
            "an allowlist edit in the same file is named too: {full}"
        );

        // And no crying wolf: a restart-only refusal with no lever
        // movement must not claim a rollback was skipped. Otherwise the
        // sentence appears on every `expected-routes` edit and stops
        // being read.
        let mut sizing = steered.clone();
        sizing.expected_routes = 2_000_000;
        let quiet = reload_collateral(&steered, &sizing);
        assert!(
            !quiet.contains("steer on → off"),
            "no lever moved, so nothing was rolled back: {quiet}"
        );
        assert!(
            quiet.contains("allow-prefix"),
            "but the general statement still holds: {quiet}"
        );

        // A port added or removed by the same edit must not read as a
        // lever move. Matching by position rather than by interface is
        // how a reordered list manufactures one.
        let reordered = cfg(&[("eth5", 1, true), ("eth4", 1, true)], 1_600_000);
        let swapped = reload_collateral(&steered, &reordered);
        assert!(
            !swapped.contains("steer on"),
            "reordering moved no lever: {swapped}"
        );
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

        // The driver refuses to resize a table holding rules, so a
        // reload that claimed to apply this would be reporting a size
        // the NIC never took.
        let mut capacity = base.clone();
        capacity.steer_capacity = Some(64);
        let e = base
            .restart_only_delta(&capacity)
            .expect_err("steer-capacity");
        assert!(
            e.contains("`steer-capacity` changed") && e.contains("restart"),
            "{e}"
        );

        let mut binary = base.clone();
        binary.vpp_binary = Some("/opt/vpp/bin/vpp".into());
        assert!(base
            .restart_only_delta(&binary)
            .expect_err("vpp-binary")
            .contains("`vpp-binary` changed"));

        // local-route: the attached route and its subif are installed
        // at attach, so an edited line must refuse the reload — a
        // reconfigure that reported OK while VPP kept delivering the
        // old footprint would be the silent-divergence shape above.
        let mut lr = base.clone();
        lr.local_routes.push((
            packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(192, 0, 2, 0),
                prefix_len: 24,
            },
            "eth4".into(),
            1337,
        ));
        let e = base.restart_only_delta(&lr).expect_err("local-route");
        assert!(e.contains("`local-route` lines changed"), "{e}");
        assert!(e.contains("restart"), "{e}");
    }

    /// Every field `restart_only` records moves the record, and the
    /// hot-reloadable levers do not. Kept beside the reload test above
    /// because the two lists must not drift apart: a restart-only field
    /// missing here is one `detach --keep-vpp` adopts as if applied.
    #[test]
    fn the_adoption_record_tracks_the_restart_only_fields() {
        let base = cfg(&[("eth4", 1, false)], 1_600_000);
        let record = base.restart_only();
        let mut changes: Vec<VppOffloadConfig> = Vec::new();
        let mut c = base.clone();
        c.ports[0].3 = vec![1337];
        changes.push(c);
        let mut c = base.clone();
        c.ports[0].1 = 2;
        changes.push(c);
        let mut c = base.clone();
        c.hugepages = Some(12);
        changes.push(c);
        let mut c = base.clone();
        c.steer_capacity = Some(64);
        changes.push(c);
        let mut c = base.clone();
        c.loopback_address = Some(packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(192, 0, 2, 254),
            prefix_len: 32,
        });
        changes.push(c);
        let mut c = base.clone();
        c.vpp_binary = Some("/opt/vpp/bin/vpp".into());
        changes.push(c);
        let mut c = base.clone();
        c.local_routes.push((
            packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(192, 0, 2, 0),
                prefix_len: 24,
            },
            "eth4".into(),
            1337,
        ));
        changes.push(c);
        let mut c = base.clone();
        c.trunk_ports = vec!["eth4".into()];
        changes.push(c);
        let mut c = base.clone();
        c.v6 = true;
        changes.push(c);
        let mut c = base.clone();
        c.local_routes6.push((doc_v6_64(), "eth4".into(), 1337));
        changes.push(c);
        let mut c = base.clone();
        c.loopback_address6 = Some("2001:db8::1".parse().unwrap());
        changes.push(c);
        for c in &changes {
            assert!(
                base.restart_only_delta(c).is_err(),
                "not restart-only: {c:?}"
            );
            assert_ne!(c.restart_only(), record, "not recorded: {c:?}");
        }

        let mut lever = base.clone();
        lever.ports[0].2 = true;
        lever.steer_direction = packetframe_common::config::VppSteerDirection::Both;
        assert_eq!(lever.restart_only(), record);
    }

    /// `v6` is restart-only in both directions and on both doors — the
    /// reload refuses it by name, and the adoption record carries it —
    /// while `v6 off` records exactly what a build that predates the
    /// directive recorded, so an upgrade still adopts.
    #[test]
    fn v6_is_restart_only_and_off_records_nothing_new() {
        let off = cfg(&[("eth4", 1, false)], 1_600_000);
        let mut on = off.clone();
        on.v6 = true;
        for (a, b) in [(&off, &on), (&on, &off)] {
            let e = a.restart_only_delta(b).expect_err("a v6 flip must refuse");
            assert!(e.contains("`v6` changed") && e.contains("restart"), "{e}");
        }
        assert!(!off.restart_only().contains_key("v6"));
        assert_eq!(on.restart_only().get("v6").map(String::as_str), Some("on"));
        assert_eq!(off.families(), fib_sync::FamilyPolicy::V4Only);
        assert_eq!(on.families(), fib_sync::FamilyPolicy::Both);

        let parsed = VppOffloadConfig::from_directives(&[ModuleDirective::VppV6(true)]);
        assert!(parsed.v6);
        assert!(!VppOffloadConfig::from_directives(&[]).v6, "default off");
    }

    fn doc_v6_64() -> packetframe_common::config::Ipv6Prefix {
        packetframe_common::config::Ipv6Prefix {
            addr: "2001:db8:1::".parse().unwrap(),
            prefix_len: 64,
        }
    }

    /// `local-route6` is restart-only on both doors — nothing but a VPP
    /// restart removes an attached route, since it is outside the ledger
    /// — and a config without it records exactly what a build that
    /// predates the directive recorded, so an upgrade still adopts.
    #[test]
    fn local_route6_is_restart_only_and_absent_records_nothing_new() {
        let without = cfg(&[("eth4", 1, false)], 1_600_000);
        let mut with = without.clone();
        with.local_routes6.push((doc_v6_64(), "eth4".into(), 1337));
        for (a, b) in [(&without, &with), (&with, &without)] {
            let e = a
                .restart_only_delta(b)
                .expect_err("a local-route6 edit must refuse the reload");
            assert!(
                e.contains("`local-route6` lines changed") && e.contains("restart"),
                "{e}"
            );
        }
        assert!(!without.restart_only().contains_key("local-route6"));
        assert!(with.restart_only().contains_key("local-route6"));

        let parsed = VppOffloadConfig::from_directives(&[ModuleDirective::VppLocalRoute6 {
            prefix: doc_v6_64(),
            iface: "eth4".into(),
            vlan: 1337,
            line: 1,
        }]);
        assert_eq!(
            parsed.local_routes6,
            vec![(doc_v6_64(), "eth4".to_string(), 1337)]
        );
        assert!(
            parsed.local_routes.is_empty(),
            "never mixed into the v4 list"
        );
    }

    /// The resolved prefix: what VPP is given is the network, what an
    /// operator reads is what they wrote, and coverage never crosses a
    /// family — a v6 local route shadows nothing v4 and vice versa.
    #[test]
    fn local_route_prefix_normalizes_and_covers_within_its_family() {
        use packetframe_common::fib::IpPrefix;
        let v6 = LocalRoutePrefix::V6(packetframe_common::config::Ipv6Prefix {
            addr: "2001:db8:1::5".parse().unwrap(),
            prefix_len: 64,
        });
        assert_eq!(v6.to_string(), "2001:db8:1::5/64");
        let mut net = [0u8; 16];
        net[..6].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 1]);
        assert_eq!(
            v6.network(),
            IpPrefix::V6 {
                addr: net,
                prefix_len: 64
            }
        );
        let mut host = net;
        host[15] = 7;
        assert!(v6.covers(&IpPrefix::V6 {
            addr: host,
            prefix_len: 128
        }));
        assert!(v6.covers(&IpPrefix::V6 {
            addr: net,
            prefix_len: 64
        }));
        assert!(!v6.covers(&IpPrefix::V6 {
            addr: net,
            prefix_len: 48
        }));
        let mut other = net;
        other[7] = 1; // 2001:db8:1:1::/64
        assert!(!v6.covers(&IpPrefix::V6 {
            addr: other,
            prefix_len: 64
        }));

        let v4 = LocalRoutePrefix::V4(packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(192, 0, 2, 9),
            prefix_len: 24,
        });
        assert_eq!(v4.to_string(), "192.0.2.9/24");
        assert_eq!(
            v4.network(),
            IpPrefix::V4 {
                addr: [192, 0, 2, 0],
                prefix_len: 24
            }
        );
        // Bytes that would match if families were confused.
        assert!(!v4.covers(&IpPrefix::V6 {
            addr: [192, 0, 2, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 128
        }));
        assert!(!v6.covers(&IpPrefix::V4 {
            addr: [0x20, 0x01, 0x0d, 0xb8],
            prefix_len: 32
        }));
    }

    /// `loopback-address6` on both doors: the reload refuses any change
    /// to it by name (set, cleared, moved), and the adoption record
    /// carries it only when set — so a record written before the
    /// directive existed still adopts under a config without it.
    #[test]
    fn loopback_address6_is_restart_only_and_unset_records_nothing_new() {
        let mut unset = cfg(&[("eth4", 1, false)], 1_600_000);
        unset.v6 = true;
        let a: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let mut set_a = unset.clone();
        set_a.loopback_address6 = Some(a);
        let mut set_b = unset.clone();
        set_b.loopback_address6 = Some(b);
        for (from, to) in [(&unset, &set_a), (&set_a, &unset), (&set_a, &set_b)] {
            let e = from
                .restart_only_delta(to)
                .expect_err("a loopback-address6 change must refuse");
            assert!(
                e.contains("`loopback-address6` changed") && e.contains("restart"),
                "{e}"
            );
        }
        assert!(set_a.restart_only_delta(&set_a.clone()).is_ok());
        assert!(!unset.restart_only().contains_key("loopback-address6"));
        assert_eq!(
            set_a
                .restart_only()
                .get("loopback-address6")
                .map(String::as_str),
            Some("2001:db8::1")
        );
        let parsed = VppOffloadConfig::from_directives(&[ModuleDirective::VppLoopbackAddress6(a)]);
        assert_eq!(parsed.loopback_address6, Some(a));
        assert_eq!(
            VppOffloadConfig::from_directives(&[]).loopback_address6,
            None
        );
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

    /// Subifs are created at attach; a reload that claimed to add a
    /// vlan would report OK while steered tagged ingress kept punting
    /// at ethernet-input — the w20 blackhole with a green reconfigure
    /// on top.
    #[test]
    fn changing_a_ports_vlans_is_a_restart() {
        let mut before = cfg(&[("eth4", 1, false)], 1_600_000);
        before.ports[0].3 = vec![88, 1337];
        let mut after = before.clone();
        after.ports[0].3 = vec![1337];
        let e = before.restart_only_delta(&after).expect_err("must refuse");
        assert!(e.contains("subinterface"), "{e}");
        // Same list, only the lever moved: not a restart.
        let mut steered = before.clone();
        steered.ports[0].2 = true;
        assert!(before.restart_only_delta(&steered).is_ok());
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
        let e = steering_target(&on, &allow, ntuple::rule_table, &test_macs, &no_vlans)
            .expect_err("cannot fit");
        // 600 diversions plus the two built-in kernel exemptions.
        assert!(e.contains("602 MCAM rule(s)"), "{e}");

        // Steering OFF succeeds with the same allowlist. This is the
        // assertion that matters: the rollback path must not consult a
        // budget it does not spend.
        let off = cfg(&[("eth4", 1, false)], 1_600_000);
        let t = steering_target(&off, &allow, ntuple::rule_table, &test_macs, &no_vlans)
            .expect("rollback must be possible");
        assert!(t.targets.is_empty() && !t.want_steer);
    }

    /// A `steer on` port with a v6-only allowlist is refused, not
    /// A reload that steers a second port while the first one's rules
    /// fill most of the table: the launch sequence's second `steer on`.
    ///
    /// Every steering port's table is intersected, so the steered
    /// port's own 13 rules left 3 free slots of 16 and the reload
    /// refused (the Codex finding on #249, reload flavour). Reading the
    /// tables through the state file's ledger counts those rules as
    /// ours, and the steered port's plan comes back unchanged.
    #[test]
    fn a_reload_steering_a_second_port_reuses_the_first_ports_slots() {
        use crate::runtime::Steering as _;
        ntuple::sys::reset();
        let allow = vec![
            packetframe_common::fib::IpPrefix::V4 {
                addr: [198, 51, 100, 0],
                prefix_len: 24,
            },
            packetframe_common::fib::IpPrefix::V4 {
                addr: [203, 0, 113, 0],
                prefix_len: 24,
            },
        ];
        let mut first = cfg(&[("eth4", 1, true), ("eth3", 1, false)], 1_600_000);
        first.steer_exempts = (1..=7u8)
            .map(|h| packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(198, 51, 100, h),
                prefix_len: 32,
            })
            .collect();
        let t1 = steering_target(&first, &allow, ntuple::rule_table, &test_macs, &no_vlans)
            .expect("fits");
        assert_eq!(t1.targets[0].2.rules.len(), 13);
        let mut steering = ntuple::NtupleSteering::new(
            vec![("eth4".into(), 0), ("eth3".into(), 0)],
            t1.targets.clone(),
        );
        steering.steer().expect("eth4 steers");

        // What every steer persists: the ledger and the plan it holds.
        let dir = std::env::temp_dir().join(format!("pf-reclaim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut st = resources::ResourceState::empty();
        st.steer_rules = resources::group_steer_rules(&steering.installed());
        st.steer_plans = t1.targets.clone();
        st.save(&dir).unwrap();

        let mut second = first.clone();
        second.ports[1].2 = true;
        steering_target(&second, &allow, ntuple::rule_table, &test_macs, &no_vlans)
            .expect_err("the raw tables leave 3 free slots");
        let t2 = steering_target(&second, &allow, planning_table(&dir), &test_macs, &no_vlans)
            .expect("eth4's own slots count as free");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            t2.targets[0], t1.targets[0],
            "eth4's plan is the one already installed: nothing moves"
        );
        assert_eq!(t2.targets[1].0, "eth3");
    }

    /// The bidirectional service edge: per-port `direction` yields
    /// per-port plans — src diverts on the trunk, dst diverts on the
    /// transit — with the built-in Keep exemptions on both, drawn from
    /// one shared free-slot intersection.
    #[test]
    fn per_port_direction_yields_per_port_plans() {
        use crate::steer::{RuleAction, Side};
        let mut on = cfg(&[("eth3", 1, true), ("eth4", 1, true)], 1_600_000);
        on.ports[0].4 = Some(packetframe_common::config::VppSteerDirection::Dst);
        on.ports[1].4 = Some(packetframe_common::config::VppSteerDirection::Src);
        let allow = vec![packetframe_common::fib::IpPrefix::V4 {
            addr: [192, 0, 2, 0],
            prefix_len: 24,
        }];
        let t = steering_target(&on, &allow, ntuple::rule_table, &test_macs, &no_vlans)
            .expect("both plans fit");
        assert!(t.want_steer);
        assert_eq!(t.targets.len(), 2);
        let plan_of = |iface: &str| {
            &t.targets
                .iter()
                .find(|(i, _, _)| i == iface)
                .expect("port present")
                .2
        };
        let (eth3, eth4) = (plan_of("eth3"), plan_of("eth4"));
        let diverts = |p: &steer::RuleSet| {
            p.rules
                .iter()
                .filter(|r| r.action == RuleAction::Divert)
                .copied()
                .collect::<Vec<_>>()
        };
        let d3 = diverts(eth3);
        let d4 = diverts(eth4);
        assert_eq!(d3.len(), 1, "dst = one divert per prefix: {d3:?}");
        assert_eq!(d4.len(), 1, "src = one divert per prefix: {d4:?}");
        assert!(d3.iter().all(|r| r.side() == Side::Dst), "{d3:?}");
        assert!(d4.iter().all(|r| r.side() == Side::Src), "{d4:?}");
        for (name, plan) in [("eth3", eth3), ("eth4", eth4)] {
            assert_eq!(
                plan.rules
                    .iter()
                    .filter(|r| r.action == RuleAction::Keep)
                    .count(),
                2,
                "{name} must carry the built-in broadcast+multicast keeps"
            );
        }
    }

    /// silently accepted as steering nothing.
    #[test]
    fn steer_on_with_nothing_steerable_is_refused() {
        use packetframe_common::fib::IpPrefix;
        let allow = vec![IpPrefix::V6 {
            addr: [0x26, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 32,
        }];
        let on = cfg(&[("eth4", 1, true)], 1_600_000);
        let e = steering_target(&on, &allow, ntuple::rule_table, &test_macs, &no_vlans)
            .expect_err("must refuse");
        assert!(e.contains("no steerable rules"), "{e}");
        assert!(
            e.contains("reporting Healthy"),
            "the consequence has to be stated: {e}"
        );
    }

    fn v6_cfg() -> VppOffloadConfig {
        use packetframe_common::config::{VppL4Proto, VppSteerKeep6, VppV6Divert};
        let mut c = cfg(&[("eth3", 1, true), ("eth4", 1, true)], 1_600_000);
        c.ports[0].3 = vec![100];
        c.trunk_ports = vec!["eth4".into()];
        c.v6_divert = vec![
            ("eth3".into(), VppV6Divert::Vlans(vec![100])),
            ("eth4".into(), VppV6Divert::Vlans(vec![200])),
        ];
        c.steer_keeps6 = vec![VppSteerKeep6 {
            proto: VppL4Proto::Tcp,
            port: 179,
            side: VppSteerDirection::Both,
        }];
        c
    }

    fn doc4() -> Vec<packetframe_common::fib::IpPrefix> {
        vec![packetframe_common::fib::IpPrefix::V4 {
            addr: [192, 0, 2, 0],
            prefix_len: 24,
        }]
    }

    /// Each `v6-divert` port gets its own VLANs in its own plan, scoped
    /// to its own MAC, with the section's keeps (`both` expanded into two
    /// rules) — and a `vlans all` trunk's VID is held to what the kernel
    /// bridge carries tagged, since that is the set VPP's subifs follow.
    #[test]
    fn v6_divert_plans_per_port_and_holds_trunk_vids_to_the_bridge() {
        use crate::steer::{L4Match, RuleMatch};
        sys_reset();
        let c = v6_cfg();
        let carries_200 = |p: &str| -> Result<Vec<u16>, String> {
            Ok(if p == "eth4" { vec![200] } else { vec![] })
        };
        let t = steering_target(&c, &doc4(), ntuple::rule_table, &test_macs, &carries_200)
            .expect("fits");
        for (iface, vid) in [("eth3", 100), ("eth4", 200)] {
            let plan = &t.targets.iter().find(|(i, _, _)| i == iface).unwrap().2;
            assert_eq!(plan.v6_divert_vlans(), vec![Some(vid)], "{iface}");
            for proto in crate::steer::V6_DIVERT_PROTOS {
                let frames: Vec<[u8; 6]> = plan
                    .rules
                    .iter()
                    .filter_map(|r| match r.shape {
                        RuleMatch::V6Frame { dmac, l4, .. } if l4 == Some(proto) => Some(dmac),
                        _ => None,
                    })
                    .collect();
                assert_eq!(
                    frames,
                    test_macs(iface),
                    "{iface}: {proto:?} scoped to its own MAC"
                );
            }
            let bgp = plan
                .rules
                .iter()
                .filter(|r| matches!(r.shape, RuleMatch::V6L4(L4Match::Port { port: 179, .. })))
                .count();
            assert_eq!(bgp, 2, "{iface}: `both` is dst + src");
        }

        let e = steering_target(&c, &doc4(), ntuple::rule_table, &test_macs, &no_vlans)
            .expect_err("the trunk no longer carries 200");
        assert!(
            e.contains("vlan 200") && e.contains("does not carry"),
            "{e}"
        );
        let e = steering_target(&c, &doc4(), ntuple::rule_table, &test_macs, &|_: &str| {
            Err("netlink said no".to_string())
        })
        .expect_err("unreadable is not permission");
        assert!(e.contains("netlink said no"), "{e}");
    }

    /// With nothing v4 to steer, a `v6-divert` port still has rules and
    /// is still asked for its table; a `steer on` port beside it with no
    /// v6 has none, and is refused by name. `steer off` plans nothing
    /// whatever its tail says — the rollback lever stays one token.
    #[test]
    fn v6_divert_steers_without_v4_and_steer_off_stays_inert() {
        sys_reset();
        let v6_only_allow = vec![packetframe_common::fib::IpPrefix::V6 {
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 48,
        }];
        let mut c = v6_cfg();
        c.trunk_ports.clear();
        c.ports[1].3 = vec![200];
        assert_eq!(ifaces_to_query(&c, &v6_only_allow), vec!["eth3", "eth4"]);
        let t = steering_target(
            &c,
            &v6_only_allow,
            ntuple::rule_table,
            &test_macs,
            &no_vlans,
        )
        .expect("both ports divert v6");
        assert!(t
            .targets
            .iter()
            .all(|(_, _, p)| p.rules.iter().all(|r| r.is_v6())));

        c.v6_divert.retain(|(i, _)| i == "eth3");
        assert_eq!(ifaces_to_query(&c, &v6_only_allow), vec!["eth3"]);
        let e = steering_target(
            &c,
            &v6_only_allow,
            ntuple::rule_table,
            &test_macs,
            &no_vlans,
        )
        .expect_err("eth4 would steer nothing");
        assert!(e.contains("\"eth4\"") && !e.contains("\"eth3\""), "{e}");

        c.ports[1].2 = false; // eth4 `steer off`
        c.ports[0].2 = false; // and eth3, v6-divert and all
        let t = steering_target(
            &c,
            &v6_only_allow,
            ntuple::rule_table,
            &test_macs,
            &no_vlans,
        )
        .expect("nothing steers");
        assert!(t.targets.is_empty() && !t.want_steer);
    }

    /// `v6-divert` and `steer-keep6` are steering inputs, applied by the
    /// reconcile like `direction` and `steer-exempt` — not restart-only.
    #[test]
    fn v6_steering_changes_are_not_a_restart() {
        let before = cfg(&[("eth3", 1, true)], 1_600_000);
        let after = v6_cfg();
        let mut after_one = cfg(&[("eth3", 1, true)], 1_600_000);
        after_one.v6_divert = after.v6_divert[..1].to_vec();
        after_one.steer_keeps6 = after.steer_keeps6.clone();
        before
            .restart_only_delta(&after_one)
            .expect("an MCAM delta, nothing VPP fixed at start");
        after_one
            .restart_only_delta(&before)
            .expect("and the rollback direction too");
    }

    fn sys_reset() {
        ntuple::sys::reset();
    }
}
