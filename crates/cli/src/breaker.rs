//! Circuit-breaker sampler thread (SPEC.md §4.9, §8.3).
//!
//! Spawned when the module's config carries a `circuit-breaker`
//! directive. On each tick of the configured window, reads the
//! pinned STATS map and feeds the delta to
//! [`packetframe_fast_path::breaker::CircuitBreaker`]. When the
//! breaker trips:
//!
//! 1. Writes a sticky flag to `<state-dir>/breaker-tripped-<module>.flag`.
//! 2. Raises SIGUSR1 so the main loop tears down and exits cleanly.
//!
//! The sticky flag survives restart; the main loop refuses attach at
//! startup if the flag is present, matching SPEC §8.3's "sticky
//! detach" requirement.

#![cfg(all(target_os = "linux", feature = "fast-path"))]

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use packetframe_common::config::CircuitBreakerSpec;
use packetframe_fast_path::breaker::{CircuitBreaker, Decision};

/// Shutdown-check granularity — how often the sampler wakes between
/// window ticks to check for shutdown.
const POLL: Duration = Duration::from_millis(250);

pub struct BreakerSampler {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl BreakerSampler {
    pub fn start(spec: CircuitBreakerSpec, bpffs_root: PathBuf, state_dir: PathBuf) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name("pf-breaker".into())
            .spawn(move || sampler_loop(spec, bpffs_root, state_dir, shutdown_clone))
            .expect("spawn breaker sampler thread");
        tracing::info!(
            drop_ratio = spec.drop_ratio,
            window_secs = spec.window.as_secs(),
            threshold = spec.threshold,
            "circuit-breaker sampler started"
        );
        Self {
            shutdown,
            handle: Some(handle),
        }
    }

    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn sampler_loop(
    spec: CircuitBreakerSpec,
    bpffs_root: PathBuf,
    state_dir: PathBuf,
    shutdown: Arc<AtomicBool>,
) {
    let mut breaker = CircuitBreaker::new(spec);

    loop {
        // Wait `window` with periodic shutdown checks.
        let deadline = Instant::now() + spec.window;
        while Instant::now() < deadline {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(POLL);
        }
        if shutdown.load(Ordering::Relaxed) {
            return;
        }

        let stats = match packetframe_fast_path::stats_from_pin(&bpffs_root) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "breaker: STATS read failed; skipping tick");
                continue;
            }
        };

        match breaker.sample(&stats) {
            Decision::NoData => {}
            Decision::Ok { ratio } => {
                tracing::debug!(ratio, "breaker tick: healthy");
            }
            Decision::Bad { ratio, streak } => {
                tracing::warn!(
                    ratio,
                    streak,
                    threshold = spec.threshold,
                    "breaker tick: over threshold"
                );
            }
            Decision::Trip {
                ratio,
                window_drops,
                window_matched,
            } => {
                tracing::error!(
                    ratio,
                    window_drops,
                    window_matched,
                    drop_ratio = spec.drop_ratio,
                    "CIRCUIT BREAKER TRIPPED"
                );
                if let Err(e) = packetframe_fast_path::breaker::write_trip_flag(
                    &state_dir,
                    ratio,
                    window_drops,
                    window_matched,
                    &spec,
                ) {
                    tracing::error!(error = %e, "breaker: writing trip flag failed");
                }
                raise_sigusr1();
                return;
            }
        }
    }
}

/// Raise SIGUSR1 on the current process so the main signal loop
/// notices and initiates a detach-and-exit.
fn raise_sigusr1() {
    // SAFETY: getpid + kill are both thread-safe and take no refs.
    let pid = unsafe { libc::getpid() };
    unsafe {
        libc::kill(pid, libc::SIGUSR1);
    }
}
