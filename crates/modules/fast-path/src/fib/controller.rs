//! RouteController — owns the tokio runtime, spawns the
//! NeighborResolver and FibProgrammer tasks, and exposes a clean
//! `start()` / `shutdown()` lifecycle that mirrors the
//! `BreakerSampler` and `MetricsExporter` pattern in
//! `crates/cli/src/loader.rs:172-194`.
//!
//! **Phase 2 scope.** Starts the netlink resolver + the programmer
//! (neigh-side). The RouteSource (BMP station) and its integration
//! into this controller land in Phase 3 — the tokio runtime shape
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

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::fib::integrity::{shared_snapshot, IntegrityChecker, IntegrityConfig, SharedSnapshot};
use crate::fib::netlink_neigh::{NeighborResolveHandle, NetlinkNeighborResolver};
use crate::fib::programmer::{FibProgrammer, FibProgrammerHandle, ProgrammerError};
use crate::fib::route_source_bgp::{BgpListener, BgpListenerConfig};
use crate::fib::route_source_bmp::BmpStation;

/// Forwarding-feed source. The controller spawns at most one route
/// source: operators pick `bmp` or `bgp` via `route-source ...`.
/// `Bgp` is the recommended choice today because bird lacks RFC 9069
/// Loc-RIB BMP — see `route_source_bgp.rs` module docs.
#[derive(Debug, Clone)]
pub enum RouteSourceConfig {
    Bmp {
        listen: SocketAddr,
        /// When true, the BmpStation rejects any RouteMonitoring
        /// frame whose peer_type is not `LocalRib` (RFC 9069 peer
        /// type 3). Required for safe forwarding use against
        /// emitters that send pre/post-policy streams.
        require_loc_rib: bool,
    },
    Bgp {
        listen: SocketAddr,
        local_as: u32,
        peer_as: u32,
        router_id: Ipv4Addr,
    },
}

/// Grace period for tasks to drain after `cancel()` fires. Netlink
/// reader and programmer should both unwind well within this.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("tokio runtime build failed: {0}")]
    Runtime(#[from] std::io::Error),
    #[error("programmer setup failed: {0}")]
    Programmer(#[from] ProgrammerError),
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
    /// checker isn't enabled (no BMP configured → no bird to ask).
    integrity: Option<SharedSnapshot>,
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
    /// live route source — useful for test harnesses that drive the
    /// programmer directly via its `FibProgrammerHandle`.
    pub fn start(
        bpffs_root: &Path,
        route_source: Option<RouteSourceConfig>,
    ) -> Result<Self, ControllerError> {
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

        let (resolver, events_rx, neigh_handle) =
            NetlinkNeighborResolver::new(shutdown_token.clone());
        let (programmer, prog_handle) = FibProgrammer::new(
            nexthops,
            fib_v4,
            fib_v6,
            ecmp_groups,
            events_rx,
            shutdown_token.clone(),
        );

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
        match route_source {
            Some(RouteSourceConfig::Bmp {
                listen,
                require_loc_rib,
            }) => {
                let snapshot = shared_snapshot();
                let checker = IntegrityChecker::new(
                    IntegrityConfig::default(),
                    snapshot.clone(),
                    prog_handle.clone(),
                    shutdown_token.clone(),
                );
                tasks.push(runtime.spawn(async move { checker.run().await }));

                let mut station =
                    BmpStation::new(listen, prog_handle.clone(), shutdown_token.clone())
                        .with_stall_gate(snapshot.clone());
                if require_loc_rib {
                    station = station.with_require_loc_rib();
                }
                tasks.push(runtime.spawn(async move {
                    if let Err(e) = station.run().await {
                        warn!(error = %e, "BmpStation task exited with error");
                    }
                }));
                integrity = Some(snapshot);

                info!(
                    bmp_addr = %listen,
                    require_loc_rib,
                    "RouteController started: NetlinkNeighborResolver + FibProgrammer + BmpStation + IntegrityChecker"
                );
            }
            Some(RouteSourceConfig::Bgp {
                listen,
                local_as,
                peer_as,
                router_id,
            }) => {
                let snapshot = shared_snapshot();
                let checker = IntegrityChecker::new(
                    IntegrityConfig::default(),
                    snapshot.clone(),
                    prog_handle.clone(),
                    shutdown_token.clone(),
                );
                tasks.push(runtime.spawn(async move { checker.run().await }));

                let cfg = BgpListenerConfig::new(listen, local_as, peer_as, router_id);
                let listener = BgpListener::new(cfg, prog_handle.clone(), shutdown_token.clone())
                    .with_stall_gate(snapshot.clone());
                tasks.push(runtime.spawn(async move {
                    if let Err(e) = listener.run().await {
                        warn!(error = %e, "BgpListener task exited with error");
                    }
                }));
                integrity = Some(snapshot);

                info!(
                    bgp_addr = %listen,
                    local_as,
                    peer_as,
                    "RouteController started: NetlinkNeighborResolver + FibProgrammer + BgpListener + IntegrityChecker"
                );
            }
            None => {
                info!(
                    "RouteController started: NetlinkNeighborResolver + FibProgrammer \
                     (no route source — `route-source` not configured)"
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
        })
    }

    /// Shared snapshot from the integrity checker. `None` when BMP
    /// isn't configured. Callers read the snapshot to diagnose drift
    /// or to gate a BmpStalled alert on "bird still thinks there are
    /// peers to hear from."
    pub fn integrity_snapshot(&self) -> Option<SharedSnapshot> {
        self.integrity.clone()
    }

    /// Cooperative shutdown. Signals the cancellation token, awaits
    /// each task up to [`SHUTDOWN_TIMEOUT`], then tears down the
    /// runtime. Drops any tasks that blow past the timeout — they'd
    /// leak otherwise when the runtime finalizes.
    pub fn shutdown(mut self) {
        self.shutdown_token.cancel();
        if let Some(runtime) = self.runtime.take() {
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
