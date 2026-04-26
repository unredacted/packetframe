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

/// Parse `birdc show route count` output and return the selected-route
/// total across the BGP RIB tables (`master4` + `master6`). Bird emits
/// one `N of M routes for K networks in table <name>` line per table,
/// followed by a `Total: ...` summary across ALL tables in
/// multi-table outputs. The `Total:` line includes RPKI tables (and
/// any other custom tables operators have configured), which is NOT
/// what we want — packetframe's mirror only ever holds master4/master6
/// content.
///
/// **v0.2.2 fix.** The rc5 fix preferred the `Total:` line over per-
/// table sums to avoid double-counting when bird emitted both. But
/// on operators with RPKI enabled (including the reference EFG via
/// pathvector's `rtr-server` directive), the Total includes the
/// RPKI tables — observed `bird_routes = 2,120,822` (sum of master4
/// 1.04M, master6 0.24M, rpki4 0.66M, rpki6 0.19M) where the operator
/// expected 1.27M (master4 plus master6). The drift warning fired
/// every 5 minutes for a non-existent drift.
///
/// Now we explicitly filter for `in table master4` / `in table master6`
/// per-table lines and sum those, ignoring `Total:` and any other
/// table names. Single-table outputs (just `master4`) still work — we
/// pick up that one line.
///
/// **rc5 fix retained**: pre-rc5 we summed every line containing
/// `routes`, including transient lines that produced >2× counts. The
/// `in table master[46]` filter is strict enough that this can't
/// recur.
pub fn parse_route_count(output: &str) -> Result<usize, String> {
    let mut sum: Option<usize> = None;

    for line in output.lines() {
        let trimmed = line.trim();
        // Strict filter: only sum lines for the BGP RIB tables we
        // actually mirror. Skip RPKI tables, kernel-export tables,
        // and the `Total:` aggregate (which includes them all).
        if !(trimmed.contains("in table master4") || trimmed.contains("in table master6")) {
            continue;
        }
        if let Some(first) = trimmed.split_whitespace().next() {
            if let Ok(n) = first.parse::<usize>() {
                sum = Some(sum.unwrap_or(0) + n);
            }
        }
    }

    sum.ok_or_else(|| {
        "no `... in table master4` / `... in table master6` line in birdc output".to_string()
    })
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
    fn parse_route_count_multi_table_no_total_line_sums_per_table() {
        // Older bird builds (or single-table outputs) don't emit a
        // Total line. Fall back to summing per-table firsts.
        let out = "BIRD 2.17.2 ready.\n\
                   1048587 of 1048587 routes for 1048573 networks in table master4\n\
                   233456 of 233456 routes for 233456 networks in table master6\n";
        assert_eq!(parse_route_count(out).unwrap(), 1_048_587 + 233_456);
    }

    #[test]
    fn parse_route_count_ignores_total_line() {
        // v0.2.2: even when `Total:` is present, we sum master4 +
        // master6 ourselves. This protects against the RPKI-table
        // case where Total includes tables we don't mirror.
        let out = "BIRD 2.17.2 ready.\n\
                   1037000 of 1500467 routes for 1037000 networks in table master4\n\
                   235306 of 457217 routes for 235306 networks in table master6\n\
                   Total: 1272306 of 1957684 routes for 1272306 networks in 2 tables\n";
        assert_eq!(parse_route_count(out).unwrap(), 1_037_000 + 235_306);
    }

    #[test]
    fn parse_route_count_excludes_rpki_tables() {
        // v0.2.2 fix: operators with `rtr-server` enabled get rpki4 /
        // rpki6 tables in `show route count`. Pre-fix we picked the
        // Total: line which summed all 4 tables, producing a count
        // ~70% above reality and triggering false integrity-drift
        // warnings every 5 minutes. Post-fix we strictly count only
        // `in table master4` + `in table master6`.
        let out = "BIRD 2.17.2 ready.\n\
                   1038232 of 1038232 routes for 1038230 networks in table master4\n\
                   235677 of 235677 routes for 235677 networks in table master6\n\
                   657970 of 657970 routes for 657970 networks in table rpki4\n\
                   188943 of 188943 routes for 188943 networks in table rpki6\n\
                   Total: 2120822 of 2120822 routes for 2120820 networks in 4 tables\n";
        // Should be master4 + master6 only, NOT the 2.12M Total.
        assert_eq!(parse_route_count(out).unwrap(), 1_038_232 + 235_677);
    }

    #[test]
    fn parse_route_count_ignores_kernel_protocol_tables() {
        // Bird operators sometimes have additional tables for
        // kernel-import / static / per-protocol shadow RIBs. Confirm
        // we don't accidentally count those either.
        let out = "BIRD 2.17.2 ready.\n\
                   1000 of 1000 routes for 1000 networks in table master4\n\
                   500  of  500 routes for  500 networks in table kernel_in\n\
                   200  of  200 routes for  200 networks in table master6\n";
        assert_eq!(parse_route_count(out).unwrap(), 1_000 + 200);
    }

    #[test]
    fn parse_route_count_missing_errors() {
        let out = "BIRD 2.17.2 ready.\n";
        let err = parse_route_count(out).unwrap_err();
        assert!(err.contains("master4"));
    }

    #[test]
    fn parse_route_count_only_master4() {
        // Single-table case (operator only runs IPv4 BGP).
        let out = "BIRD 2.17.2 ready.\n\
                   42 of 100 routes for 42 networks in table master4\n";
        assert_eq!(parse_route_count(out).unwrap(), 42);
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
