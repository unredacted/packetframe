//! 15-second-cadence Prometheus textfile exporter (SPEC.md §7.3).
//!
//! Spawned by `packetframe run` when the config sets `metrics-textfile`.
//! Reads the pinned STATS map and writes a Prometheus textfile
//! atomically (write-then-rename), the convention Prometheus's
//! textfile collector expects. On shutdown, performs one final write
//! so the last-sampled values aren't lost between ticks.

#![cfg(all(target_os = "linux", feature = "fast-path"))]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(15);
/// Shutdown-check granularity so SIGTERM doesn't wait up to INTERVAL
/// for the exporter to wake.
const POLL: Duration = Duration::from_millis(250);

pub struct MetricsExporter {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MetricsExporter {
    pub fn start(textfile_path: PathBuf, bpffs_root: PathBuf) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name("pf-metrics".into())
            .spawn(move || exporter_loop(textfile_path, bpffs_root, shutdown_clone))
            .expect("spawn metrics thread");
        tracing::info!("metrics exporter started; 15s cadence");
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

fn exporter_loop(textfile_path: PathBuf, bpffs_root: PathBuf, shutdown: Arc<AtomicBool>) {
    let start = Instant::now();
    let mut next_write = Instant::now();

    loop {
        let now = Instant::now();
        if now >= next_write {
            let uptime = start.elapsed().as_secs();
            if let Err(e) = write_once(&textfile_path, &bpffs_root, uptime) {
                tracing::warn!(error = %e, "metrics write failed; will retry at next tick");
            }
            next_write = now + INTERVAL;
        }

        if shutdown.load(Ordering::Relaxed) {
            // One final write so external collectors see the last
            // state before this process exits.
            let uptime = start.elapsed().as_secs();
            let _ = write_once(&textfile_path, &bpffs_root, uptime);
            return;
        }

        std::thread::sleep(POLL);
    }
}

fn write_once(textfile_path: &Path, bpffs_root: &Path, uptime_seconds: u64) -> Result<(), String> {
    let stats = packetframe_fast_path::stats_from_pin(bpffs_root)
        .map_err(|e| format!("read STATS pin: {e}"))?;
    let mut body = packetframe_fast_path::metrics::render_textfile(&stats, uptime_seconds);
    // Custom-FIB occupancy gauges (Option F, Phase 3.8). Best-effort:
    // `fib_status_from_pin` returns a default snapshot when the pins
    // aren't readable (e.g., kernel-fib mode), and the renderer
    // handles that by emitting zeros + a `mode=\"kernel-fib\"` one-hot.
    let fib = packetframe_fast_path::fib_status_from_pin(bpffs_root);
    body.push_str(&packetframe_fast_path::metrics::render_fib_gauges(&fib));
    atomic_write(textfile_path, body.as_bytes())
        .map_err(|e| format!("atomic write {}: {e}", textfile_path.display()))?;
    Ok(())
}

/// Write-then-rename. The rename is atomic on POSIX when source and
/// dest are on the same filesystem — node_exporter's textfile
/// collector relies on this to never read a half-written file.
fn atomic_write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    // Use the same filename with `.tmp` appended so we stay on the
    // same filesystem as the target (`with_extension("tmp")` would
    // drop the `.prom` and prevent a second writer from
    // distinguishing ours).
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("packetframe.prom"),
    ));
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
