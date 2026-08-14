//! 15-second-cadence Prometheus textfile exporter (SPEC.md §7.3).
//!
//! Spawned by `packetframe run` when the config sets `metrics-textfile`.
//! Reads the pinned STATS map and writes a Prometheus textfile
//! atomically (write-then-rename), the convention Prometheus's
//! textfile collector expects. On shutdown, performs one final write
//! so the last-sampled values aren't lost between ticks.

#![cfg(all(target_os = "linux", feature = "fast-path"))]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const INTERVAL: Duration = Duration::from_secs(15);
/// Shutdown-check granularity so SIGTERM doesn't wait up to INTERVAL
/// for the exporter to wake.
const POLL: Duration = Duration::from_millis(250);

/// Where the loader leaves the modules' rendered gauges for the
/// exporter to include.
///
/// A slot rather than a second writer, because the textfile has exactly
/// one writer and that is what makes its atomic rename mean anything.
/// `Module::sample_metrics` needs `&dyn Module`, and the modules live in
/// `run_linux`'s vector alongside the `&mut` uses (reconfigure, detach)
/// — so the loader samples on its own cadence and publishes the text
/// here, and the exporter appends whatever it finds.
///
/// Consequence, deliberate: the fragment can be up to one loader poll
/// interval stale relative to the BPF counters in the same file. That is
/// the price of not sharing the modules across threads, and it is why
/// the poll interval is shorter than the write interval rather than
/// equal to it — equal cadences with independent phase would have made
/// the staleness a whole write period.
pub type ModuleGauges = Arc<Mutex<String>>;

pub struct MetricsExporter {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl MetricsExporter {
    pub fn start(textfile_path: PathBuf, bpffs_root: PathBuf, modules: ModuleGauges) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let handle = std::thread::Builder::new()
            .name("pf-metrics".into())
            .spawn(move || exporter_loop(textfile_path, bpffs_root, modules, shutdown_clone))
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

fn exporter_loop(
    textfile_path: PathBuf,
    bpffs_root: PathBuf,
    modules: ModuleGauges,
    shutdown: Arc<AtomicBool>,
) {
    let start = Instant::now();
    let mut next_write = Instant::now();

    loop {
        let now = Instant::now();
        if now >= next_write {
            let uptime = start.elapsed().as_secs();
            if let Err(e) = write_once(&textfile_path, &bpffs_root, &modules, uptime) {
                tracing::warn!(error = %e, "metrics write failed; will retry at next tick");
            }
            next_write = now + INTERVAL;
        }

        if shutdown.load(Ordering::Relaxed) {
            // One final write so external collectors see the last
            // state before this process exits.
            let uptime = start.elapsed().as_secs();
            let _ = write_once(&textfile_path, &bpffs_root, &modules, uptime);
            return;
        }

        std::thread::sleep(POLL);
    }
}

fn write_once(
    textfile_path: &Path,
    bpffs_root: &Path,
    modules: &ModuleGauges,
    uptime_seconds: u64,
) -> Result<(), String> {
    let stats = packetframe_fast_path::stats_from_pin(bpffs_root)
        .map_err(|e| format!("read STATS pin: {e}"))?;
    let mut body = packetframe_fast_path::metrics::render_textfile(&stats, uptime_seconds);
    // Custom-FIB occupancy gauges (Option F, Phase 3.8). Best-effort:
    // `fib_status_from_pin` returns a default snapshot when the pins
    // aren't readable (e.g., kernel-fib mode), and the renderer
    // handles that by emitting zeros + a `mode=\"kernel-fib\"` one-hot.
    let fib = packetframe_fast_path::fib_status_from_pin(bpffs_root);
    body.push_str(&packetframe_fast_path::metrics::render_fib_gauges(&fib));
    // Host softirq pressure. `time_squeeze` is the one early signal
    // for the silent generic-XDP TX drop mechanism (2026-08-13,
    // w12–w19), which no packetframe counter, qdisc stat, or tcpdump
    // can see. Best-effort: a read/parse failure loses this block for
    // one tick, never the file.
    match packetframe_fast_path::softnet::from_proc() {
        Ok(t) => body.push_str(&packetframe_fast_path::metrics::render_softnet(&t)),
        Err(e) => tracing::debug!(error = %e, "softnet_stat unavailable this tick"),
    }
    // Whatever the loader last sampled from the modules. Appended rather
    // than merged: each module namespaces its own gauges
    // (`packetframe_vpp_*`), so there is nothing to reconcile — and a
    // renderer here would be a second place that decides what a module's
    // metrics look like.
    //
    // An empty fragment is the honest output before the loader's first
    // poll, and after a module whose `sample_metrics` is a no-op.
    match modules.lock() {
        Ok(fragment) => body.push_str(&fragment),
        // A poisoned lock means the loader panicked while holding it.
        // The BPF gauges are still true and still worth writing; losing
        // the module fragment is the smaller loss, and the panic itself
        // is already on its way to the log.
        Err(e) => tracing::warn!(error = %e, "module gauges unavailable this tick"),
    }
    crate::atomic::write(textfile_path, body.as_bytes())
        .map_err(|e| format!("atomic write {}: {e}", textfile_path.display()))?;
    Ok(())
}
