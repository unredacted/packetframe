//! RouteController, owns the tokio runtime, spawns the
//! NeighborResolver and FibProgrammer tasks, and exposes a clean
//! `start()` / `shutdown()` lifecycle that mirrors the
//! `BreakerSampler` and `MetricsExporter` pattern in
//! `crates/cli/src/loader.rs:172-194`.
//!
//! **Phase 2 scope.** Starts the netlink resolver + the programmer
//! (neigh-side). The RouteSource (BMP station) and its integration
//! into this controller land in Phase 3, the tokio runtime shape
//! here accommodates that expansion without rework: spawning a
//! third long-lived task is an additive change.
//!
//! Runtime choice: the controller owns its own dedicated multi-thread
//! tokio runtime with 2 worker threads. The main binary's signal loop
//! is sync (signal-hook blocking iterator, pre-existing), so we can't
//! share a runtime without rearchitecting that. Two workers is enough
//! for the resolver's netlink reader + the programmer's event loop,
//! with headroom for Phase 3's BMP task.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::fib::integrity::{
    shared_snapshot, IntegrityChecker, IntegrityConfig, IntegrityPosture, SharedSnapshot,
};
use crate::fib::netlink_neigh::{
    FallbackDefaultSpec, LocalPrefixSpec, NeighborResolveHandle, NetlinkNeighborResolver,
};
use crate::fib::programmer::{FibProgrammer, FibProgrammerHandle, ProgrammerError};
use crate::fib::route_source_bgp::{BgpListener, BgpListenerConfig};
use crate::fib::route_source_bmp::BmpStation;
use packetframe_common::config::IntegrityAuthoritySpec;

/// Forwarding-feed source. The controller spawns at most one route
/// source: operators pick `bmp` or `bgp` via `route-source ...`.
/// `Bgp` is the recommended choice today because bird lacks RFC 9069
/// Loc-RIB BMP, see `route_source_bgp.rs` module docs.
///
/// The `peer_acl` / `expected_peer_ip` fields carry the
/// authorization opt-in declared in the operator config. The config
/// parser already enforces "loopback default-allow, non-loopback
/// requires opt-in"; the controller passes the parsed ACL into the
/// listener so the runtime `accept()` filter can reject sources
/// outside the declared CIDRs before any BMP/BGP framing starts.
#[derive(Debug, Clone)]
pub enum RouteSourceConfig {
    Bmp {
        listen: SocketAddr,
        /// When true, the BmpStation rejects any RouteMonitoring
        /// frame whose peer_type is not `LocalRib` (RFC 9069 peer
        /// type 3). Required for safe forwarding use against
        /// emitters that send pre/post-policy streams.
        require_loc_rib: bool,
        /// CIDR ACL applied to the source IP of every accepted TCP
        /// connection. Empty means "loopback-only" (the config
        /// parser only permits empty when the listen address is
        /// itself loopback).
        peer_acl: Vec<ipnet::IpNet>,
    },
    Bgp {
        listen: SocketAddr,
        local_as: u32,
        peer_as: u32,
        router_id: Ipv4Addr,
        /// CIDR ACL, same semantics as the BMP variant.
        peer_acl: Vec<ipnet::IpNet>,
        /// Optional pin on the peer's source IP. When set, an
        /// accepted connection whose source IP differs is closed
        /// before the BGP OPEN exchange.
        expected_peer_ip: Option<IpAddr>,
        /// Install a `local <listen>/32 dev lo` kernel route (AnyIP)
        /// before binding, remove it on shutdown. See the `anyip`
        /// module docs for the FRR pairing this exists for.
        anyip: bool,
    },
}

/// Grace period for tasks to drain after `cancel()` fires. Netlink
/// reader and programmer should both unwind well within this.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// v0.2.2: starting backoff between route-source listener restart
/// attempts. Doubles up to [`LISTENER_BACKOFF_MAX`] then plateaus.
const LISTENER_BACKOFF_INITIAL: Duration = Duration::from_secs(1);

/// v0.2.2: ceiling on the listener restart backoff. After a transient
/// bind failure (TIME_WAIT, port held by orphan, etc.), we want to
/// retry promptly. After a sustained failure (real port conflict), we
/// don't want to spam the kernel, 60 s is operator-readable in the
/// log without being too loud.
const LISTENER_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Cadence of the AnyIP reconcile task. The per-retry ensure in the
/// listener loop only runs when `BgpListener::run` *exits*, and a
/// flushed route doesn't make a bound listener exit — the socket
/// stays bound, SYNs silently stop being delivered locally, and the
/// session dies on hold-timer with nothing to restart the loop
/// (review finding, PR #196). A periodic replace is the signal-free
/// fix: one netlink round-trip every 30 s, idempotent, and the feed
/// heals within one FRR connect-retry of the route coming back.
const ANYIP_RECONCILE_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("tokio runtime build failed: {0}")]
    Runtime(#[from] std::io::Error),
    #[error("programmer setup failed: {0}")]
    Programmer(#[from] ProgrammerError),
    #[error("anyip listen-address setup failed: {0}")]
    Anyip(#[from] crate::fib::anyip::AnyipError),
}

pub struct RouteController {
    /// `Option` so we can take it out and drop it deliberately in
    /// `shutdown()`. `Runtime::drop` on a running runtime panics if
    /// we're inside one of its own tasks, so we explicitly
    /// `shutdown_timeout` rather than rely on Drop.
    runtime: Option<Runtime>,
    shutdown_token: CancellationToken,
    tasks: Vec<JoinHandle<()>>,

    neigh_handle: NeighborResolveHandle,
    prog_handle: FibProgrammerHandle,
    /// Shared snapshot from the integrity checker. `None` when the
    /// checker isn't enabled (no route source → no bird to ask, or
    /// `integrity-authority none` → nothing local to ask).
    integrity: Option<SharedSnapshot>,
    /// The operator declared `integrity-authority none`: there is a
    /// route source but no local authority for the mirror, so no
    /// comparison runs. Distinct from `integrity: None` with no route
    /// source, because the health surface says something different —
    /// "not attested by choice" versus "nothing to attest".
    authority_declared_none: bool,
    /// `Some` when this controller installed an AnyIP local route for
    /// the BGP listener; removed during `shutdown()` so the route's
    /// lifetime never exceeds the daemon's.
    anyip_addr: Option<Ipv4Addr>,
}

/// The external route feed and the authority the integrity checker
/// validates the resulting mirror against. One struct because they are
/// two halves of one decision — where the routes come from, and what
/// counts as the truth to check them against — and pairing them keeps
/// `start()` under the argument-count lint (which only the cross-clippy
/// job sees, since this file is `cfg(target_os = "linux")`).
pub struct RouteFeed {
    /// `Some(...)` when `route-source bmp|bgp ...` was configured;
    /// `None` runs without a live feed (test harnesses).
    pub source: Option<RouteSourceConfig>,
    /// Which authority the integrity checker cross-checks against. See
    /// [`IntegrityAuthoritySpec`]; absent in config ⇒ `Birdc` default,
    /// resolved by the caller.
    pub integrity_authority: IntegrityAuthoritySpec,
}

/// The handles a second forwarding tier registers before attach — how
/// complete the mirror is, and whether the feed's transport session is
/// up. One struct because they are created together (the loader),
/// stored together (both modules), and consumed together (here).
#[derive(Default)]
pub struct SecondTierSignals {
    pub completeness: Option<std::sync::Arc<packetframe_common::fib::TableCompleteness>>,
    pub feed_session: Option<std::sync::Arc<packetframe_common::fib::FeedSession>>,
}

impl RouteController {
    /// Build and start the controller. `bpffs_root` is the same
    /// `global.bpffs_root` path the loader pins maps under; the
    /// programmer opens each map from its corresponding pin.
    ///
    /// `route_source` is `Some(...)` when the operator configured
    /// `route-source bmp ...` or `route-source bgp ...`; the
    /// controller then spawns the matching listener as a third task
    /// alongside the resolver + programmer. `None` runs without a
    /// live route source, useful for test harnesses that drive the
    /// programmer directly via its `FibProgrammerHandle`.
    pub fn start(
        bpffs_root: &Path,
        feed: RouteFeed,
        local_prefixes: Vec<LocalPrefixSpec>,
        fallback_default: Option<FallbackDefaultSpec>,
        fdb_pin_chains: std::collections::HashMap<u32, (u32, u16)>,
        route_sink: Option<std::sync::Arc<dyn packetframe_common::fib::ResolvedRouteSink>>,
        signals: SecondTierSignals,
    ) -> Result<Self, ControllerError> {
        let RouteFeed {
            source: route_source,
            integrity_authority,
        } = feed;
        let SecondTierSignals {
            completeness,
            feed_session,
        } = signals;
        // Dedicated runtime. `worker_threads(2)` keeps task count to
        // what Phase 3 actually needs; the resolver, programmer, and
        // BMP station are all I/O-bound so CPU is never the limit.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("packetframe-fib")
            .build()
            .map_err(ControllerError::Runtime)?;

        let shutdown_token = CancellationToken::new();
        let nexthops = FibProgrammer::open_nexthops(bpffs_root)?;
        let fib_v4 = FibProgrammer::open_fib_v4(bpffs_root)?;
        let fib_v6 = FibProgrammer::open_fib_v6(bpffs_root)?;
        let ecmp_groups = FibProgrammer::open_ecmp_groups(bpffs_root)?;
        let cache_cfg = FibProgrammer::open_fib_cache_cfg(bpffs_root)?;

        let (resolver, events_rx, neigh_handle) =
            NetlinkNeighborResolver::new(shutdown_token.clone());
        // Phase 3.9 fix: pass the resolve handle through so
        // FibProgrammer::register() can kick proactive resolution on
        // every newly-allocated nexthop. Pre-fix this was wired but
        // never called, leaving nexthops dependent on multicast events
        // that don't fire for stable REACHABLE kernel entries.
        let (mut programmer, prog_handle) = FibProgrammer::new_with_resolver(
            nexthops,
            fib_v4,
            fib_v6,
            ecmp_groups,
            Some(cache_cfg),
            events_rx,
            shutdown_token.clone(),
            Some(neigh_handle.clone()),
        );
        // Registered before the programmer is spawned, which is the only
        // window `set_route_sink` accepts: a sink attached afterwards
        // would have missed every route resolved in the meantime, and a
        // second tier silently short those prefixes is the shape of bug
        // that reports healthy and black-holes.
        if let Some(sink) = route_sink {
            programmer.set_route_sink(sink);
            info!("second-tier route sink registered with the FibProgrammer");
        }

        // v0.2.1: enable the connected fast-path when the operator
        // declared at least one `local-prefix`. The resolver gets the
        // FibProgrammer handle so it can synthesize per-/32
        // RouteEvent::Add events directly (sibling to the BgpListener
        // / BmpStation paths), reusing the existing nexthop-resolution
        // pipeline. Empty list → no-op.
        let resolver = if local_prefixes.is_empty() {
            resolver
        } else {
            resolver.with_local_prefixes(local_prefixes, prog_handle.clone())
        };
        // v0.2.1 issue #31: optional synthetic 0.0.0.0/0. Unused unless
        // the operator declared `fallback-default`.
        let resolver = match fallback_default {
            Some(spec) => resolver.with_fallback_default(spec, prog_handle.clone()),
            None => resolver,
        };
        // v0.2.9: FDB-pinned direct-to-port egress. Empty map = no-op.
        let resolver = if fdb_pin_chains.is_empty() {
            resolver
        } else {
            resolver.with_fdb_pin(fdb_pin_chains, prog_handle.clone())
        };

        let resolver_task = runtime.spawn(async move {
            if let Err(e) = resolver.run().await {
                // Non-fatal: the controller stays up and the programmer
                // keeps draining commands. Operators notice via the
                // Phase 3.5 health report / metrics.
                warn!(error = %e, "NeighborResolver task exited with error");
            }
        });
        let programmer_task = runtime.spawn(async move { programmer.run().await });

        let mut tasks = vec![resolver_task, programmer_task];

        // Spawn the configured route-source feed (BMP or BGP). The
        // integrity checker spawns alongside any feed because both
        // depend on a live bird to cross-check against.
        let mut integrity: Option<SharedSnapshot> = None;
        let mut anyip_installed: Option<Ipv4Addr> = None;
        match route_source {
            Some(RouteSourceConfig::Bmp {
                listen,
                require_loc_rib,
                peer_acl,
            }) => {
                let snapshot = shared_snapshot();
                // Spawn the checker only when a LOCAL authority is named.
                // `integrity-authority none` still allocates the snapshot
                // (the BMP stall gate reads it) but runs no comparison:
                // there is no local RIB that is this mirror's authority,
                // so a birdc comparison would be against the wrong
                // reference — the 6.8-million-percent "drift" the shadow
                // reported for months.
                if let IntegrityAuthoritySpec::Birdc { path } = &integrity_authority {
                    let mut icfg = IntegrityConfig::default();
                    if let Some(p) = path {
                        icfg.birdc_path = p.clone();
                    }
                    let mut checker = IntegrityChecker::new(
                        icfg,
                        snapshot.clone(),
                        prog_handle.clone(),
                        shutdown_token.clone(),
                    );
                    // The second tier's steering gate reads what this
                    // publishes; see `TableCompleteness`.
                    if let Some(h) = completeness.clone() {
                        checker = checker.with_completeness(h);
                    }
                    tasks.push(runtime.spawn(async move { checker.run().await }));
                }

                // v0.2.2: spawn under a retry-with-backoff loop. Pre-fix,
                // a `bind` failure (TIME_WAIT after a quick restart) would
                // exit `run()` with `Err(...)`, the JoinHandle would
                // swallow it, and packetframe would silently keep running
                // with a dead BMP feed. Now we restart on Err, capped at
                // LISTENER_BACKOFF_MAX between attempts. Clean shutdown
                // (Ok(())) returns immediately; the cancel token check in
                // the sleep arm exits promptly on operator shutdown.
                let prog = prog_handle.clone();
                let shut = shutdown_token.clone();
                let stall = snapshot.clone();
                let peer_acl_for_spawn = peer_acl.clone();
                tasks.push(runtime.spawn(async move {
                    let mut backoff = LISTENER_BACKOFF_INITIAL;
                    loop {
                        let mut station = BmpStation::new(listen, prog.clone(), shut.clone())
                            .with_feed_session(feed_session.clone())
                            .with_stall_gate(stall.clone())
                            .with_peer_acl(peer_acl_for_spawn.clone());
                        if require_loc_rib {
                            station = station.with_require_loc_rib();
                        }
                        match station.run().await {
                            Ok(()) => return,
                            Err(e) => {
                                error!(
                                    error = %e,
                                    backoff_secs = backoff.as_secs(),
                                    "BmpStation task exited with error; restarting"
                                );
                            }
                        }
                        tokio::select! {
                            _ = shut.cancelled() => return,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(LISTENER_BACKOFF_MAX);
                    }
                }));

                integrity = Some(snapshot);

                let loopback_only = listen.ip().is_loopback() && peer_acl.is_empty();
                info!(
                    bmp_addr = %listen,
                    require_loc_rib,
                    peer_acl_entries = peer_acl.len(),
                    auth_posture = if loopback_only { "loopback-only" } else { "allow-remote (no TCP-MD5)" },
                    "RouteController started: NetlinkNeighborResolver + FibProgrammer + BmpStation + IntegrityChecker"
                );
            }
            Some(RouteSourceConfig::Bgp {
                listen,
                local_as,
                peer_as,
                router_id,
                peer_acl,
                expected_peer_ip,
                anyip,
            }) => {
                let snapshot = shared_snapshot();
                // Spawn the checker only when a LOCAL authority is named.
                // `integrity-authority none` still allocates the snapshot
                // (the BMP stall gate reads it) but runs no comparison:
                // there is no local RIB that is this mirror's authority,
                // so a birdc comparison would be against the wrong
                // reference — the 6.8-million-percent "drift" the shadow
                // reported for months.
                if let IntegrityAuthoritySpec::Birdc { path } = &integrity_authority {
                    let mut icfg = IntegrityConfig::default();
                    if let Some(p) = path {
                        icfg.birdc_path = p.clone();
                    }
                    let mut checker = IntegrityChecker::new(
                        icfg,
                        snapshot.clone(),
                        prog_handle.clone(),
                        shutdown_token.clone(),
                    );
                    // The second tier's steering gate reads what this
                    // publishes; see `TableCompleteness`.
                    if let Some(h) = completeness.clone() {
                        checker = checker.with_completeness(h);
                    }
                    tasks.push(runtime.spawn(async move { checker.run().await }));
                }

                // `anyip`: claim the phantom listen address before the
                // first bind so a fresh start binds on attempt one
                // instead of eating a backoff cycle. The ownership
                // check inside `ensure_local_route` is the hard gate:
                // an interface-owned address is an operator error the
                // paired FRR would reject too, so attach fails loudly
                // here rather than converging into a feed that can
                // never establish (same shape as vpp-offload's
                // refusal of a live loopback IP, #188).
                let anyip_addr: Option<Ipv4Addr> = if anyip {
                    let IpAddr::V4(a) = listen.ip() else {
                        // Config parse rejects `anyip` on non-v4
                        // listens; reaching here means the parser and
                        // this code disagree, which is a bug, not an
                        // operator error.
                        unreachable!("config parser permits anyip on IPv4 listens only");
                    };
                    runtime.block_on(crate::fib::anyip::ensure_local_route(a))?;
                    Some(a)
                } else {
                    None
                };
                anyip_installed = anyip_addr;

                // v0.2.2: same retry-with-backoff pattern as BmpStation
                // above. See that comment for rationale.
                let mut cfg = BgpListenerConfig::new(listen, local_as, peer_as, router_id);
                cfg.session = feed_session.clone();
                cfg.peer_acl = peer_acl;
                cfg.expected_peer_ip = expected_peer_ip;
                // Capture the auth-posture fields before the spawn
                // moves `cfg` into the retry loop's coroutine, the
                // post-spawn `info!` reads them and can't share with
                // the move.
                let peer_acl_entries = cfg.peer_acl.len();
                let peer_ip_log = cfg.expected_peer_ip;
                let loopback_only =
                    listen.ip().is_loopback() && peer_acl_entries == 0 && peer_ip_log.is_none();
                let prog = prog_handle.clone();
                let shut = shutdown_token.clone();
                let stall = snapshot.clone();
                tasks.push(runtime.spawn(async move {
                    let mut backoff = LISTENER_BACKOFF_INITIAL;
                    loop {
                        // Self-heal the AnyIP route on every listener
                        // (re)start: a route flushed at runtime comes
                        // back on the next retry instead of wedging
                        // the feed until a daemon restart. Warn-only:
                        // the bind below is the authoritative failure
                        // signal and drives the same backoff.
                        if let Some(a) = anyip_addr {
                            if let Err(e) = crate::fib::anyip::ensure_local_route(a).await {
                                warn!(error = %e, addr = %a, "anyip: re-ensure failed");
                            }
                        }
                        let listener = BgpListener::new(cfg.clone(), prog.clone(), shut.clone())
                            .with_stall_gate(stall.clone());
                        // (The flushed-while-BOUND case is covered by
                        // the reconcile task spawned below, not this
                        // loop — a bound listener gives no exit signal
                        // when the route disappears.)
                        match listener.run().await {
                            Ok(()) => return,
                            Err(e) => {
                                error!(
                                    error = %e,
                                    backoff_secs = backoff.as_secs(),
                                    "BgpListener task exited with error; restarting"
                                );
                            }
                        }
                        tokio::select! {
                            _ = shut.cancelled() => return,
                            _ = tokio::time::sleep(backoff) => {}
                        }
                        backoff = (backoff * 2).min(LISTENER_BACKOFF_MAX);
                    }
                }));

                // AnyIP reconcile: heal the route while the listener
                // is bound and healthy, which the retry loop above
                // structurally cannot (see ANYIP_RECONCILE_INTERVAL).
                // First tick fires immediately and is a no-op replace.
                if let Some(a) = anyip_addr {
                    let shut = shutdown_token.clone();
                    tasks.push(runtime.spawn(async move {
                        let mut tick = tokio::time::interval(ANYIP_RECONCILE_INTERVAL);
                        loop {
                            tokio::select! {
                                _ = shut.cancelled() => return,
                                _ = tick.tick() => {
                                    if let Err(e) = crate::fib::anyip::ensure_local_route(a).await {
                                        warn!(error = %e, addr = %a, "anyip: reconcile failed");
                                    }
                                }
                            }
                        }
                    }));
                }
                integrity = Some(snapshot);

                info!(
                    bgp_addr = %listen,
                    local_as,
                    peer_as,
                    peer_acl_entries,
                    peer_ip = ?peer_ip_log,
                    auth_posture = if loopback_only { "loopback-only" } else { "allow-remote (no TCP-MD5)" },
                    "RouteController started: NetlinkNeighborResolver + FibProgrammer + BgpListener + IntegrityChecker"
                );
            }
            None => {
                // No external feed means no session that could be down:
                // the mirror's content — local-prefix and neighbour
                // state — IS this deployment's whole world, and it is
                // resident the moment the resolver runs. Raised once
                // and never lowered, deliberately: leaving the handle
                // at its default "down" made every release clause
                // unsatisfiable after a daemon restart, parking a
                // steered adoption forever (review finding).
                if let Some(h) = &feed_session {
                    h.set_up(true);
                    // ...and reconciled by definition: with no external
                    // feed there is no prior session whose routes could
                    // linger, so there is no GC to wait for. Without
                    // this the gate would treat a feedless deployment
                    // as permanently un-attestable.
                    h.mark_reconciled();
                }
                info!(
                    "RouteController started: NetlinkNeighborResolver + FibProgrammer \
                     (no route source, `route-source` not configured)"
                );
            }
        }

        Ok(Self {
            runtime: Some(runtime),
            shutdown_token,
            tasks,
            neigh_handle,
            prog_handle,
            integrity,
            authority_declared_none: matches!(
                integrity_authority,
                packetframe_common::config::IntegrityAuthoritySpec::None
            ),
            anyip_addr: anyip_installed,
        })
    }

    /// The last integrity check, for the module's health surface.
    ///
    /// `None` when no checker is running — no route source is
    /// configured, so there is no bird to cross-check against and no
    /// verdict to report. That is the one case the health surface
    /// prints no row for; every other case has something to say,
    /// including "nothing has compared yet".
    ///
    /// Replaces an `integrity_snapshot()` getter that had no caller
    /// anywhere in the tree: the checker compared bird against the
    /// mirror every 300 s and threw the result away, leaving a debug
    /// log as the only way to see it.
    ///
    /// `try_read` rather than a blocking one. This is called from the
    /// daemon's sync signal loop today, where blocking would be safe,
    /// but `Module::health_check` is a public surface and a blocking
    /// tokio read panics inside an async context. The writer holds this
    /// lock for a handful of field assignments once per interval, so
    /// losing the race is vanishingly rare and says so when it happens
    /// rather than being mistaken for "no check yet".
    pub fn integrity_posture(&self) -> Option<IntegrityPosture> {
        // `integrity-authority none`: a route source exists but no local
        // authority attests it, so there is a checker-shaped hole to
        // explain rather than a comparison to read. Reported as its own
        // posture — informational, not an alarm — because silence here
        // would read as "checker crashed", and a birdc comparison would
        // be against the wrong RIB.
        if self.authority_declared_none {
            return Some(IntegrityPosture::NoAuthority);
        }
        let snapshot = self.integrity.as_ref()?;
        Some(match snapshot.try_read() {
            Ok(snap) => IntegrityPosture::observe(&snap, Instant::now()),
            Err(_) => IntegrityPosture::Unread,
        })
    }

    /// Cooperative shutdown. Signals the cancellation token, awaits
    /// each task up to [`SHUTDOWN_TIMEOUT`], then tears down the
    /// runtime. Drops any tasks that blow past the timeout, they'd
    /// leak otherwise when the runtime finalizes.
    pub fn shutdown(mut self) {
        self.shutdown_token.cancel();
        if let Some(runtime) = self.runtime.take() {
            let anyip_addr = self.anyip_addr.take();
            runtime.block_on(async {
                for task in self.tasks.drain(..) {
                    match tokio::time::timeout(SHUTDOWN_TIMEOUT, task).await {
                        Ok(Ok(())) => {}
                        Ok(Err(join_err)) => {
                            warn!(error = %join_err, "controller task panicked during shutdown");
                        }
                        Err(_) => {
                            warn!(
                                "controller task did not drain within {} s; forcing drop",
                                SHUTDOWN_TIMEOUT.as_secs()
                            );
                        }
                    }
                }
                // After the listener has drained: remove the AnyIP
                // route this controller installed. Best-effort — an
                // already-absent route is success — so shutdown never
                // wedges on kernel state someone else cleaned up.
                if let Some(a) = anyip_addr {
                    if let Err(e) = crate::fib::anyip::remove_local_route(a).await {
                        warn!(error = %e, addr = %a, "anyip: route removal failed during shutdown");
                    }
                }
            });
            runtime.shutdown_timeout(Duration::from_secs(2));
        }
        info!("RouteController shut down");
    }

    /// Handle for proactive neighbor resolution. Clone freely; each
    /// clone posts to the same underlying queue.
    pub fn neighbor_handle(&self) -> NeighborResolveHandle {
        self.neigh_handle.clone()
    }

    /// Handle for nexthop registration + future route commands. Clone
    /// freely.
    pub fn programmer_handle(&self) -> FibProgrammerHandle {
        self.prog_handle.clone()
    }
}

/// The §8.5 preserve-attach exit (SIGTERM/SIGINT) drops modules
/// without calling `detach`, so [`RouteController::shutdown`] never
/// runs on the *normal* stop path — and the AnyIP route survived
/// every ordinary `systemctl stop` (review finding, PR #196). The
/// pins are meant to outlive the process; the AnyIP route is not: it
/// serves only this daemon's listener, a dead listener answers
/// nothing on the phantom address anyway, and the next start with
/// `anyip` re-installs it before the first bind. So Drop removes it.
///
/// Ordering matters: the runtime is torn down FIRST so the reconcile
/// task cannot re-install the route between our removal and process
/// exit; the removal then runs on a throwaway current-thread runtime.
/// After an explicit `shutdown()` both fields are already `None` and
/// this is a no-op. Drop runs on the daemon's signal-loop thread,
/// never inside a tokio context, so `shutdown_timeout`/`block_on`
/// here cannot panic on nested-runtime rules.
impl Drop for RouteController {
    fn drop(&mut self) {
        let Some(runtime) = self.runtime.take() else {
            return; // explicit shutdown() already ran
        };
        self.shutdown_token.cancel();
        runtime.shutdown_timeout(Duration::from_secs(2));
        if let Some(addr) = self.anyip_addr.take() {
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => {
                    if let Err(e) = rt.block_on(crate::fib::anyip::remove_local_route(addr)) {
                        warn!(error = %e, %addr, "anyip: route removal failed during drop");
                    }
                }
                Err(e) => {
                    warn!(error = %e, %addr, "anyip: no runtime for route removal during drop");
                }
            }
        }
    }
}
