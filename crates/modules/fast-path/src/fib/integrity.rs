//! Periodic integrity check (Option F, Phase 3.8).
//!
//! Runs every ~5 minutes (configurable), shells out to `birdc`, and
//! compares bird's authoritative RIB against packetframe's FIB
//! mirror. Flags drift above a threshold and caches the set of BGP
//! peers in `Established` state so the BMP stall detector can gate
//! its alert on "bird says there are peers to hear from."
//!
//! Scope: diagnostic safety net. Not on the feed path, if this
//! crashes or `birdc` is uninstallable, forwarding is unaffected;
//! only the integrity alert goes dark. The 5-minute cadence is
//! deliberately slow because this is a drift-catch job, not a
//! liveness probe.
//!
//! Parsing bird's text output is inherently brittle; version drift
//! can break the parser. Treating that as "integrity check stops
//! working" is fine, forwarding keeps going, the operator gets a
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

/// The result types and their rendering live in a platform-independent
/// module so `packetframe status`'s view of this check is testable off
/// Linux; re-exported here because this is where callers expect them.
pub use crate::fib::integrity_status::{
    Comparison, Drift, IntegrityPosture, IntegritySnapshot, DEFAULT_INTERVAL, SUBSYS_FIB_INTEGRITY,
};

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

pub type SharedSnapshot = Arc<RwLock<IntegritySnapshot>>;

pub fn shared_snapshot() -> SharedSnapshot {
    Arc::new(RwLock::new(IntegritySnapshot::default()))
}

pub struct IntegrityChecker {
    config: IntegrityConfig,
    snapshot: SharedSnapshot,
    prog: FibProgrammerHandle,
    shutdown: CancellationToken,
    /// Where the same comparison is republished for the **second
    /// forwarding tier** to read before it diverts traffic.
    ///
    /// Same numbers, different consumer and a different question. This
    /// checker asks "should an operator look at this?" on a 5-minute
    /// drift-catch cadence; vpp-offload asks "may I steer packets into
    /// this mirror yet?", where the case that matters is bird's initial
    /// dump still arriving. Publishing rather than having vpp-offload
    /// run its own `birdc` keeps one process shelling out to bird and
    /// one place parsing its output.
    ///
    /// `None` when nothing is consuming it, which is every
    /// single-module deployment.
    completeness: Option<Arc<packetframe_common::fib::TableCompleteness>>,
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
            completeness: None,
        }
    }

    /// Publish each comparison to the second forwarding tier as well.
    ///
    /// Set by the loader, which is the only place that sees both
    /// modules — the same wiring the route feed and the allowlist use.
    pub fn with_completeness(
        mut self,
        handle: Arc<packetframe_common::fib::TableCompleteness>,
    ) -> Self {
        self.completeness = Some(handle);
        self
    }

    /// Main loop. Sleeps `config.interval`, runs one check, repeats.
    /// Each tick is independent, a failure writes `last_error` into
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

        // Captured from THIS run's results, before anything is folded
        // into the snapshot.
        //
        // Nothing derived from a mix of runs ever reaches the snapshot:
        // a failed `birdc` or a failed `mirror_counts` used to leave the
        // previous run's number in a sticky per-count field, so a drift
        // fraction could be computed from one fresh number and one five
        // minutes old. That was tolerable while the only reader was a
        // log line; it is not, now that `packetframe status` prints the
        // verdict and a rollout is gated on it. A partial run records
        // its error and leaves the previous COMPARISON standing whole,
        // aged, and labelled as history.
        let fresh_bird = bird_route.as_ref().ok().copied();
        let fresh_mirror = pf_route.as_ref().ok().map(|(v4, v6)| v4 + v6);

        // One `Instant` for the whole run, written to `last_run` and to
        // the comparison alike. That equality is load-bearing:
        // `IntegrityPosture` tells a current comparison from a retained
        // one by comparing the two, so two separate `now()` calls would
        // make every comparison read as history.
        let at = Instant::now();
        let mut snap = self.snapshot.write().await;
        snap.last_run = Some(at);
        snap.last_error = None;

        if let Err(e) = &bird_route {
            snap.last_error = Some(format!("birdc show route count: {e}"));
            warn!(error = %e, "integrity check: birdc route count failed");
        }
        match bird_peers {
            Ok(n) => snap.bird_established_peers = Some(n),
            Err(e) => {
                // Non-fatal for the route-count side, but the stall
                // gate relies on this so surface it.
                if snap.last_error.is_none() {
                    snap.last_error = Some(format!("birdc show protocols: {e}"));
                }
                warn!(error = %e, "integrity check: birdc protocols failed");
            }
        }
        if let Err(e) = &pf_route {
            snap.last_error = Some(format!("programmer mirror_counts: {e}"));
            warn!(error = %e, "integrity check: mirror_counts failed");
        }

        // Recorded, and republished to the steering gate, only when BOTH
        // counts came from THIS run.
        //
        // A partial run publishes nothing rather than a mixed report:
        // the reader treats an absent report as "refuse to steer", which
        // is the safe reading, while a fabricated one would be acted on.
        // Leaving the previous report in place is correct — it ages out
        // on its own, and its own timestamp says how far behind it is.
        if let (Some(bird), Some(pf)) = (fresh_bird, fresh_mirror) {
            // `above` is decided here, in the same place that decides
            // whether to warn, and carried on the comparison. The health
            // surface reports that verdict rather than re-applying the
            // threshold, so the log and `packetframe status` cannot
            // disagree about whether a box has drifted.
            let drift = (bird != 0).then(|| {
                let fraction = (bird as f64 - pf as f64).abs() / bird as f64;
                Drift {
                    fraction,
                    threshold: self.config.drift_warn_fraction,
                    above: fraction >= self.config.drift_warn_fraction,
                }
            });
            match drift {
                Some(d) if d.above => warn!(
                    bird_routes = bird,
                    packetframe_routes = pf,
                    drift_fraction = d.fraction,
                    "integrity drift above threshold"
                ),
                Some(d) => debug!(
                    bird_routes = bird,
                    packetframe_routes = pf,
                    drift_fraction = d.fraction,
                    "integrity check OK"
                ),
                // A zero authority used to record `drift_fraction =
                // None` and log nothing at all — the quietest possible
                // treatment of a bird that cannot attest anything. It is
                // the degenerate end of the case the vpp-offload runbook
                // measured (a box whose own bird carried 13 routes
                // against a 1.3M mirror), so it warns like drift does.
                None => warn!(
                    bird_routes = bird,
                    packetframe_routes = pf,
                    "integrity check: bird reports no routes in master4/master6"
                ),
            }
            snap.last_comparison = Some(Comparison {
                at,
                bird_routes: bird,
                packetframe_routes: pf,
                drift,
            });
            if let Some(handle) = self.completeness.as_ref() {
                handle.publish(packetframe_common::fib::CompletenessReport {
                    authority_routes: bird as u64,
                    mirror_routes: pf as u64,
                    at,
                });
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
/// what we want, packetframe's mirror only ever holds master4/master6
/// content.
///
/// **v0.2.2 fix.** The rc5 fix preferred the `Total:` line over per-
/// table sums to avoid double-counting when bird emitted both. But
/// on operators with RPKI enabled (including the reference EFG via
/// pathvector's `rtr-server` directive), the Total includes the
/// RPKI tables, observed `bird_routes = 2,120,822` (sum of master4
/// 1.04M, master6 0.24M, rpki4 0.66M, rpki6 0.19M) where the operator
/// expected 1.27M (master4 plus master6). The drift warning fired
/// every 5 minutes for a non-existent drift.
///
/// Now we explicitly filter for `in table master4` / `in table master6`
/// per-table lines and sum those, ignoring `Total:` and any other
/// table names. Single-table outputs (just `master4`) still work, we
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

/// Cap on bytes read from birdc's stdout and stderr. The May 2026
/// audit Slice 4 finding: `Command::output()` reads stdout into
/// memory uncapped, so a misbehaving or compromised `birdc` could
/// emit gigabytes inside the 10s timeout and consume daemon memory.
/// 1 MiB is two orders of magnitude above legitimate output (`birdc
/// show route count` is ~100 bytes; `birdc show protocols` on a
/// 2K-peer router is single-digit KB).
const BIRDC_OUTPUT_CAP: usize = 1024 * 1024;

async fn run_birdc(birdc: &std::path::Path, args: &[&str]) -> Result<String, String> {
    let birdc = birdc.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let args_display = format!("{args:?}");
    let join = tokio::task::spawn_blocking(move || -> Result<BirdcOutput, String> {
        // `Read` is in scope inside `read_capped` via its `R: Read`
        // bound, no need to pull it in here.
        use std::process::Stdio;
        let mut child = Command::new(&birdc)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("spawn {}: {e}", birdc.display()))?;
        // SAFETY: `stdout`/`stderr` are Some because we configured
        // both as `Stdio::piped()` above. Unwrap-on-piped is the
        // standard pattern; the `.take()` removes them from the
        // child so `wait()` doesn't block on us.
        let mut stdout = child.stdout.take().expect("piped stdout");
        let mut stderr = child.stderr.take().expect("piped stderr");
        let mut stdout_buf = Vec::with_capacity(4096);
        let mut stderr_buf = Vec::with_capacity(1024);
        let stdout_truncated = read_capped(&mut stdout, &mut stdout_buf, BIRDC_OUTPUT_CAP)
            .map_err(|e| format!("read birdc stdout: {e}"))?;
        let _ = read_capped(&mut stderr, &mut stderr_buf, BIRDC_OUTPUT_CAP);
        let status = child.wait().map_err(|e| format!("birdc wait: {e}"))?;
        Ok(BirdcOutput {
            status,
            stdout: stdout_buf,
            stderr: stderr_buf,
            stdout_truncated,
        })
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
    if result.stdout_truncated {
        return Err(format!(
            "birdc {args_display} stdout exceeded {BIRDC_OUTPUT_CAP} bytes, refusing to parse a runaway response"
        ));
    }
    Ok(String::from_utf8_lossy(&result.stdout).into_owned())
}

/// Spawn result for [`run_birdc`]. Carries the captured streams plus
/// a flag signalling whether stdout hit the size cap.
struct BirdcOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
}

/// Read from `r` into `buf` up to `cap` bytes. Returns true when the
/// reader had more data than the cap (the caller surfaces this as a
/// hard error rather than parsing a runaway stream).
fn read_capped<R: std::io::Read>(
    r: &mut R,
    buf: &mut Vec<u8>,
    cap: usize,
) -> std::io::Result<bool> {
    let mut chunk = [0u8; 4096];
    loop {
        let n = match r.read(&mut chunk) {
            Ok(0) => return Ok(false),
            Ok(n) => n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let allowed = cap.saturating_sub(buf.len());
        if n > allowed {
            buf.extend_from_slice(&chunk[..allowed]);
            // Drain the rest of the reader so the child's write end
            // doesn't block on a full pipe buffer once we return.
            let mut sink = [0u8; 4096];
            while r.read(&mut sink).unwrap_or(0) > 0 {}
            return Ok(true);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
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
