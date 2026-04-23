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

use std::path::Path;
use std::time::Duration;

use tokio::runtime::Runtime;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::fib::netlink_neigh::{NeighborResolveHandle, NetlinkNeighborResolver};
use crate::fib::programmer::{FibProgrammer, FibProgrammerHandle, ProgrammerError};

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
}

impl RouteController {
    /// Build and start the controller. `bpffs_root` is the same
    /// `global.bpffs_root` path the loader pins maps under; the
    /// programmer opens `NEXTHOPS` from
    /// `<bpffs_root>/fast-path/maps/NEXTHOPS`.
    pub fn start(bpffs_root: &Path) -> Result<Self, ControllerError> {
        // Dedicated runtime. `worker_threads(2)` keeps task count to
        // what Phase 2 + 3 actually need; larger worker counts buy
        // nothing because the resolver + programmer aren't CPU-bound.
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("packetframe-fib")
            .build()
            .map_err(ControllerError::Runtime)?;

        let shutdown_token = CancellationToken::new();
        let nexthops = FibProgrammer::open_nexthops(bpffs_root)?;

        let (resolver, events_rx, neigh_handle) =
            NetlinkNeighborResolver::new(shutdown_token.clone());
        let (programmer, prog_handle) =
            FibProgrammer::new(nexthops, events_rx, shutdown_token.clone());

        let resolver_task = runtime.spawn(async move {
            if let Err(e) = resolver.run().await {
                // Non-fatal: the controller stays up and the programmer
                // keeps draining commands. Operators notice via the
                // Phase 3.5 health report / metrics.
                warn!(error = %e, "NeighborResolver task exited with error");
            }
        });
        let programmer_task = runtime.spawn(async move { programmer.run().await });

        info!(
            "RouteController started: NetlinkNeighborResolver + FibProgrammer spawned \
             on dedicated 2-thread tokio runtime"
        );

        Ok(Self {
            runtime: Some(runtime),
            shutdown_token,
            tasks: vec![resolver_task, programmer_task],
            neigh_handle,
            prog_handle,
        })
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
