//! Periodic integrity check (Option F, Phase 3.8).
//!
//! Runs every ~5 minutes (configurable), shells out to `birdc`, and
//! compares bird's authoritative RIB against packetframe's FIB
//! mirror. Flags drift above a threshold and caches the set of BGP
//! peers in `Established` state so the BMP stall detector can gate
//! its alert on "bird says there are peers to hear from."
//!
//! Scope: diagnostic safety net. Not on the feed path — if this
//! crashes or `birdc` is uninstallable, forwarding is unaffected;
//! only the integrity alert goes dark. The 5-minute cadence is
//! deliberately slow because this is a drift-catch job, not a
//! liveness probe.
//!
//! Parsing bird's text output is inherently brittle; version drift
//! can break the parser. Treating that as "integrity check stops
//! working" is fine — forwarding keeps going, the operator gets a
//! warning log, and we update the parser. The plan explicitly
//! accepts this fragility as the price of having the check at all.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::programmer::FibProgrammerHandle;

/// Default interval between integrity checks. Slow enough to be
/// cheap, fast enough that a drift window of "up to 5 minutes"
/// is acceptable.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(300);

/// Drift threshold above which the checker warns (as a fraction:
/// `0.01` = 1%). BGP convergence can transiently drift by several
/// percent so a modest threshold keeps the warning signal-to-noise
/// reasonable.
pub const DEFAULT_DRIFT_WARN_FRACTION: f64 = 0.01;

/// Default `birdc` binary path. Most distros ship it at this
/// location; override via config when bird lives elsewhere.
pub const DEFAULT_BIRDC_PATH: &str = "/usr/sbin/birdc";

/// Subprocess time budget per `birdc` call. Bird handles text
/// output synchronously against the live RIB; a full `show route
/// count` on a 1M-route table returns in <1 s on our hardware.
/// 10 s is a comfortable ceiling that catches genuine hangs.
pub const BIRDC_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct IntegrityConfig {
    pub interval: Duration,
    pub birdc_path: PathBuf,
    pub drift_warn_fraction: f64,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_INTERVAL,
            birdc_path: PathBuf::from(DEFAULT_BIRDC_PATH),
            drift_warn_fraction: DEFAULT_DRIFT_WARN_FRACTION,
        }
    }
}

/// Snapshot of the most recent integrity-check result. Readers —
/// specifically the BmpStalled gate — consult this to decide whether
/// a stall warrants an alert.
#[derive(Debug, Clone, Default)]
pub struct IntegritySnapshot {
    pub last_run: Option<Instant>,
    pub bird_route_count: Option<usize>,
    pub packetframe_route_count: Option<usize>,
    pub bird_established_peers: Option<usize>,
    pub drift_fraction: Option<f64>,
    pub last_error: Option<String>,
}

pub type SharedSnapshot = Arc<RwLock<IntegritySnapshot>>;

pub fn shared_snapshot() -> SharedSnapshot {
    Arc::new(RwLock::new(IntegritySnapshot::default()))
}

pub struct IntegrityChecker {
    config: IntegrityConfig,
    snapshot: SharedSnapshot,
    prog: FibProgrammerHandle,
    shutdown: CancellationToken,
}

impl IntegrityChecker {
    pub fn new(
        config: IntegrityConfig,
        snapshot: SharedSnapshot,
        prog: FibProgrammerHandle,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            config,
            snapshot,
            prog,
            shutdown,
        }
    }

    /// Main loop. Sleeps `config.interval`, runs one check, repeats.
    /// Each tick is independent — a failure writes `last_error` into
    /// the snapshot and continues.
    pub async fn run(self) {
        info!(
            interval_secs = self.config.interval.as_secs(),
            birdc = %self.config.birdc_path.display(),
            "IntegrityChecker started"
        );
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("IntegrityChecker shutdown");
                    return;
                }
                _ = tokio::time::sleep(self.config.interval) => {
                    self.run_check().await;
                }
            }
        }
    }

    async fn run_check(&self) {
        let bird_route = run_birdc_count(&self.config.birdc_path).await;
        let bird_peers = run_birdc_protocols(&self.config.birdc_path).await;
        let pf_route = self.prog.mirror_counts().await;

        let mut snap = self.snapshot.write().await;
        snap.last_run = Some(Instant::now());
        snap.last_error = None;

        match bird_route {
            Ok(n) => snap.bird_route_count = Some(n),
            Err(e) => {
                snap.last_error = Some(format!("birdc show route count: {e}"));
                warn!(error = %e, "integrity check: birdc route count failed");
            }
        }
        match bird_peers {
            Ok(n) => snap.bird_established_peers = Some(n),
            Err(e) => {
                // Non-fatal for the route-count side, but the stall
                // gate relies on this so surface it.
                let msg = format!("birdc show protocols: {e}");
                if snap.last_error.is_none() {
                    snap.last_error = Some(msg.clone());
                }
                warn!(error = %e, "integrity check: birdc protocols failed");
            }
        }
        match pf_route {
            Ok((v4, v6)) => snap.packetframe_route_count = Some(v4 + v6),
            Err(e) => {
                snap.last_error = Some(format!("programmer mirror_counts: {e}"));
                warn!(error = %e, "integrity check: mirror_counts failed");
            }
        }

        if let (Some(bird), Some(pf)) = (snap.bird_route_count, snap.packetframe_route_count) {
            if bird == 0 {
                snap.drift_fraction = None;
            } else {
                let frac = (bird as f64 - pf as f64).abs() / bird as f64;
                snap.drift_fraction = Some(frac);
                if frac >= self.config.drift_warn_fraction {
                    warn!(
                        bird_routes = bird,
                        packetframe_routes = pf,
                        drift_fraction = frac,
                        "integrity drift above threshold"
                    );
                } else {
                    debug!(
                        bird_routes = bird,
                        packetframe_routes = pf,
                        drift_fraction = frac,
                        "integrity check OK"
                    );
                }
            }
        }
    }
}

/// Parse `birdc show route count` output. Bird emits a line of the
/// form `1048587 of 1048587 routes for 1048573 networks in table
/// master4` per table; we sum the first number across tables.
pub fn parse_route_count(output: &str) -> Result<usize, String> {
    let mut total: Option<usize> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        // Matches `N of N routes for M networks in table X` — take
        // the first integer.
        if let Some(first_space) = trimmed.find(' ') {
            let first_tok = &trimmed[..first_space];
            if trimmed.contains("routes") {
                if let Ok(n) = first_tok.parse::<usize>() {
                    total = Some(total.unwrap_or(0) + n);
                }
            }
        }
    }
    total.ok_or_else(|| "no `N routes` line in birdc output".to_string())
}

/// Parse `birdc show protocols` output for Established BGP peer
/// count. Bird's table has a trailing "Info" column; BGP sessions
/// in Established state have the literal word "Established" there.
pub fn parse_established_peers(output: &str) -> Result<usize, String> {
    let mut count = 0;
    let mut saw_any_line = false;
    for line in output.lines() {
        if line.starts_with("BIRD") || line.starts_with("Access") || line.trim().is_empty() {
            continue;
        }
        saw_any_line = true;
        // Column-position-agnostic: any line containing the literal
        // " Established" (with leading space to avoid matching a
        // substring of e.g. "NotEstablished" if a future bird version
        // ever emits that).
        if line.contains(" Established") || line.ends_with("Established") {
            count += 1;
        }
    }
    if !saw_any_line {
        return Err("no protocol lines in birdc output".to_string());
    }
    Ok(count)
}

async fn run_birdc_count(birdc: &std::path::Path) -> Result<usize, String> {
    let output = run_birdc(birdc, &["show", "route", "count"]).await?;
    parse_route_count(&output)
}

async fn run_birdc_protocols(birdc: &std::path::Path) -> Result<usize, String> {
    let output = run_birdc(birdc, &["show", "protocols"]).await?;
    parse_established_peers(&output)
}

async fn run_birdc(birdc: &std::path::Path, args: &[&str]) -> Result<String, String> {
    let birdc = birdc.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    // Stringify the args before the blocking task takes ownership; we
    // still want to name them in the timeout-error message.
    let args_display = format!("{args:?}");
    let join = tokio::task::spawn_blocking(move || {
        Command::new(&birdc)
            .args(&args)
            .output()
            .map_err(|e| format!("spawn {}: {e}", birdc.display()))
    });
    let result = tokio::time::timeout(BIRDC_TIMEOUT, join)
        .await
        .map_err(|_| format!("birdc {args_display} exceeded {BIRDC_TIMEOUT:?}"))?
        .map_err(|e| format!("birdc task join: {e}"))??;
    if !result.status.success() {
        return Err(format!(
            "birdc exit {}: stderr={}",
            result.status,
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_route_count_single_table() {
        let out = "BIRD 2.17.2 ready.\n\
                   1048587 of 1048587 routes for 1048573 networks in table master4\n";
        assert_eq!(parse_route_count(out).unwrap(), 1_048_587);
    }

    #[test]
    fn parse_route_count_multi_table_sums() {
        let out = "BIRD 2.17.2 ready.\n\
                   1048587 of 1048587 routes for 1048573 networks in table master4\n\
                   233456 of 233456 routes for 233456 networks in table master6\n";
        assert_eq!(parse_route_count(out).unwrap(), 1_048_587 + 233_456);
    }

    #[test]
    fn parse_route_count_missing_errors() {
        let out = "BIRD 2.17.2 ready.\n";
        assert!(parse_route_count(out).is_err());
    }

    #[test]
    fn parse_established_peers_counts_lines() {
        let out = "BIRD 2.17.2 ready.\n\
                   Access restricted\n\
                   Name       Proto      Table      State  Since         Info\n\
                   device1    Device     ---        up     2026-04-23    \n\
                   kernel1    Kernel     master4    up     2026-04-23    \n\
                   pv_as12345 BGP        ---        up     2026-04-23    Established\n\
                   pv_as67890 BGP        ---        start  2026-04-23    Idle\n\
                   pv_as99999 BGP        ---        up     2026-04-23    Established\n\
                   bmp1       BMP        ---        up     2026-04-23    \n";
        assert_eq!(parse_established_peers(out).unwrap(), 2);
    }

    #[test]
    fn parse_established_peers_empty_errors() {
        let out = "BIRD 2.17.2 ready.\n\n";
        assert!(parse_established_peers(out).is_err());
    }

    #[test]
    fn default_config_is_five_minutes() {
        let c = IntegrityConfig::default();
        assert_eq!(c.interval.as_secs(), 300);
        assert_eq!(c.drift_warn_fraction, 0.01);
    }
}
