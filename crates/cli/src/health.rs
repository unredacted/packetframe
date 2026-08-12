//! The module health snapshot, published to disk so `packetframe
//! status` can read it.
//!
//! ## Why a file
//!
//! `Module::health_check` is an in-process call on a live module, and
//! the modules live inside `packetframe run`'s own `Vec<Box<dyn
//! Module>>`. `packetframe status` is a *different process*, and it
//! deliberately works with no daemon running at all — it reads the pin
//! registry and the pinned maps, because the dataplane survives a daemon
//! exit (SPEC.md §8.5). There is no way for it to call into the daemon.
//!
//! So the daemon publishes, on a cadence, and `status` reads. Same shape
//! as the reconfigure ack marker, and the same write-then-rename, for
//! the same reason: a reader must never see a half-written file.
//!
//! ## Why the snapshot carries a pid
//!
//! A file outlives the process that wrote it. Age alone cannot tell a
//! snapshot from a *stale* snapshot — the wall clock can jump, and "30
//! seconds old" means something completely different for a running
//! daemon than for one that died 30 seconds in. The pid is the
//! liveness question answered directly: if that process is gone, this
//! file describes a daemon that no longer exists, and `status` must say
//! so rather than presenting `Healthy` from history.
//!
//! Both are recorded. The pid answers "is this live", the timestamp
//! answers "how far behind is it", and neither substitutes for the
//! other.

#![cfg(feature = "fast-path")]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use packetframe_common::module::{HealthCtx, HealthReport, MetricsWriter, Module};
use serde::{Deserialize, Serialize};

/// Sub-path under `state-dir`.
pub const HEALTH_FILE_NAME: &str = "module-health.json";

/// One module's last health check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleEntry {
    pub module: String,
    /// `None` when the check itself failed — which is not the same as
    /// an unhealthy report and must not be rendered as one.
    pub report: Option<HealthReport>,
    /// Why the check could not be performed.
    pub error: Option<String>,
}

/// What the daemon publishes each cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// The publishing daemon's pid. See the module docs: this is the
    /// liveness question, not a diagnostic.
    pub pid: i32,
    /// The publisher's start time in clock ticks, and the boot id it
    /// counts from.
    ///
    /// The pid alone cannot say the report is current. A crash whose
    /// replacement is handed the SAME pid — routine after a reboot,
    /// possible any time — made the pre-crash report read as live until
    /// the replacement published its own (review finding). `None` for a
    /// snapshot written before this was recorded, which reads as
    /// "cannot confirm" rather than as either answer.
    #[serde(default)]
    pub start_ticks: Option<u64>,
    #[serde(default)]
    pub boot_id: Option<String>,
    /// Unix seconds at write time, for the age.
    pub written_at: u64,
    pub modules: Vec<ModuleEntry>,
}

impl Snapshot {
    pub fn path_in(state_dir: &Path) -> PathBuf {
        state_dir.join(HEALTH_FILE_NAME)
    }
}

/// Ask every module how it is and what it wants published.
///
/// The call site that was missing: nothing in the CLI invoked
/// `Module::health_check` or `Module::sample_metrics` for **any** module,
/// so everything they produced — vpp-offload's `HealthReport` and its
/// `packetframe_vpp_*` gauges, fast-path's subsystem health — was
/// unreachable.
///
/// Deliberately portable rather than living in the Linux-only loop that
/// calls it. Nothing here touches Linux, and a `#[cfg(target_os =
/// "linux")]` test is invisible to every host gate — it compiles under a
/// per-target clippy and only ever *runs* in CI, which is how a
/// signature change here would first be discovered by a red pipeline.
///
/// Nothing in it can fail the daemon: a module that cannot answer is
/// recorded as unable to answer, and a snapshot that cannot be written is
/// logged and dropped. A health surface that could take the dataplane
/// down would be worse than one that goes quiet.
// Only the Linux daemon loop calls this, so a non-Linux build has no
// production caller — the tests below are the only ones. Same treatment
// as `RunError::Runtime` in `loader.rs`: cfg the lint, not the code, so
// the macOS dev loop keeps compiling AND keeps running the tests. The
// alternative (gating the whole module to Linux) would make these tests
// invisible to every host gate, which is the trap this project has hit
// twice.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn poll(state_dir: &Path, modules: &[(String, Box<dyn Module>)], gauges: &Mutex<String>) {
    let ctx = HealthCtx::new();
    let mut entries = Vec::with_capacity(modules.len());
    let mut rendered = String::new();

    for (name, module) in modules {
        entries.push(match module.health_check(&ctx) {
            Ok(report) => ModuleEntry {
                module: name.clone(),
                report: Some(report),
                error: None,
            },
            // A check that could not run is NOT an unhealthy module. The
            // two are different facts that lead somewhere different —
            // "the dataplane is unwell" versus "we do not know" — and
            // collapsing them pages on the wrong thing.
            Err(e) => ModuleEntry {
                module: name.clone(),
                report: None,
                error: Some(e.to_string()),
            },
        });

        // Rendered into a per-module buffer and appended only on success.
        // The textfile is parsed as a whole, so half a line from a module
        // that failed partway through writing would take out every other
        // module's gauges and the BPF counters in the same file.
        let mut buf = String::new();
        match module.sample_metrics(&mut MetricsWriter::new(&mut buf, name)) {
            Ok(()) => rendered.push_str(&buf),
            Err(e) => tracing::warn!(module = %name, error = %e, "sample_metrics failed"),
        }
    }

    match gauges.lock() {
        Ok(mut slot) => *slot = rendered,
        Err(e) => tracing::warn!(error = %e, "module gauge slot is poisoned"),
    }
    if let Err(e) = publish(state_dir, entries) {
        tracing::warn!(error = %e, "could not publish the module health snapshot");
    }
}

/// Write the snapshot, atomically.
///
/// Failures are the caller's to log and swallow: a health surface that
/// could take the daemon down would be worse than one that goes quiet.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn publish(state_dir: &Path, modules: Vec<ModuleEntry>) -> Result<(), String> {
    let snapshot = Snapshot {
        pid: std::process::id() as i32,
        start_ticks: crate::daemon_presence::self_start_ticks(),
        boot_id: crate::daemon_presence::self_boot_id(),
        written_at: unix_now(),
        modules,
    };
    let body = serde_json::to_vec_pretty(&snapshot).map_err(|e| format!("serialise: {e}"))?;
    std::fs::create_dir_all(state_dir).map_err(|e| format!("create state dir: {e}"))?;
    crate::atomic::write(&Snapshot::path_in(state_dir), &body)
        .map_err(|e| format!("write {}: {e}", Snapshot::path_in(state_dir).display()))
}

/// Remove it. Called on a clean exit, so `status` does not present a
/// departed daemon's last report as the current one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn remove(state_dir: &Path) {
    let path = Snapshot::path_in(state_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "could not remove health snapshot")
        }
    }
}

/// Read it back. `Ok(None)` means no daemon has ever published one.
pub fn load(state_dir: &Path) -> Result<Option<Snapshot>, String> {
    let path = Snapshot::path_in(state_dir);
    let body = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("read {}: {e}", path.display())),
    };
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| format!("parse {}: {e}", path.display()))
}

/// How old the snapshot is, in seconds, or `None` if the clock has moved
/// backwards since it was written.
///
/// `None` rather than a saturating `0`: a negative age means the clock
/// jumped, and reporting "0 seconds old" would present the most
/// suspicious snapshot as the freshest possible one.
pub fn age_seconds(snapshot: &Snapshot) -> Option<u64> {
    unix_now().checked_sub(snapshot.written_at)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::module::{HealthState, SubsystemHealth};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pf-health-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A published report survives the round trip with its structure
    /// intact.
    ///
    /// The subsystem list is what an operator reads to tell "the offload
    /// is staged" from "the offload is broken", so a snapshot that kept
    /// only `overall` would be a summary of the one thing they cannot
    /// act on.
    #[test]
    fn a_report_round_trips_with_its_subsystems() {
        let dir = tmpdir("roundtrip");
        publish(
            &dir,
            vec![ModuleEntry {
                module: "vpp-offload".into(),
                report: Some(HealthReport {
                    overall: HealthState::Degraded,
                    subsystems: vec![SubsystemHealth {
                        name: "steering".into(),
                        state: HealthState::Degraded,
                        message: Some("steer off (staging state)".into()),
                        last_success_age_seconds: Some(4),
                    }],
                }),
                error: None,
            }],
        )
        .unwrap();

        let got = load(&dir).unwrap().expect("published");
        assert_eq!(got.pid, std::process::id() as i32);
        assert_eq!(got.modules.len(), 1);
        let m = &got.modules[0];
        assert_eq!(m.module, "vpp-offload");
        let r = m.report.as_ref().expect("a report");
        assert_eq!(r.overall, HealthState::Degraded);
        assert_eq!(r.subsystems.len(), 1);
        assert_eq!(r.subsystems[0].name, "steering");
        assert_eq!(
            r.subsystems[0].message.as_deref(),
            Some("steer off (staging state)")
        );
        assert_eq!(r.subsystems[0].last_success_age_seconds, Some(4));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A failed check is recorded as a failed check, not as an unhealthy
    /// module.
    ///
    /// The two are different facts and lead somewhere different: one
    /// says the dataplane is unwell, the other says we do not know. A
    /// snapshot that collapsed them would page on the wrong thing.
    #[test]
    fn a_failed_check_is_not_an_unhealthy_report() {
        let dir = tmpdir("failed");
        publish(
            &dir,
            vec![ModuleEntry {
                module: "vpp-offload".into(),
                report: None,
                error: Some("module `vpp-offload`: supervision loop is gone".into()),
            }],
        )
        .unwrap();

        let got = load(&dir).unwrap().expect("published");
        assert!(got.modules[0].report.is_none());
        assert!(got.modules[0]
            .error
            .as_deref()
            .is_some_and(|e| e.contains("supervision loop is gone")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Nothing published reads as nothing published, not as an error.
    #[test]
    fn a_missing_snapshot_is_not_a_failure() {
        let dir = tmpdir("missing");
        assert!(load(&dir).unwrap().is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A clock that moved backwards yields no age rather than a
    /// flattering one.
    ///
    /// Saturating to `0` would present the most suspicious snapshot —
    /// one apparently written in the future — as the freshest possible,
    /// which is the direction that hides a problem.
    #[test]
    fn a_snapshot_from_the_future_reports_no_age() {
        let s = Snapshot {
            pid: 1,
            start_ticks: None,
            boot_id: None,
            written_at: unix_now() + 3600,
            modules: Vec::new(),
        };
        assert!(age_seconds(&s).is_none());
    }

    use packetframe_common::module::{
        Attachment, HookUse, LoaderCtx, ModuleConfig, ModuleError, ModuleResult,
    };

    /// A module that reports whatever the test tells it to.
    struct Fake {
        name: &'static str,
        health: Option<HealthReport>,
        gauges: Option<&'static str>,
    }

    impl Module for Fake {
        fn name(&self) -> &'static str {
            self.name
        }
        fn hook_spec(&self) -> Vec<HookUse> {
            Vec::new()
        }
        fn load(&mut self, _: &ModuleConfig<'_>, _: &LoaderCtx<'_>) -> ModuleResult<()> {
            Ok(())
        }
        fn attach(&mut self, _: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
            Ok(Vec::new())
        }
        fn reconfigure(&mut self, _: &ModuleConfig<'_>) -> ModuleResult<()> {
            Ok(())
        }
        fn detach(&mut self) -> ModuleResult<()> {
            Ok(())
        }
        fn sample_metrics(&self, out: &mut MetricsWriter<'_>) -> ModuleResult<()> {
            // Writes FIRST, then fails, which is the case that matters:
            // the partial output must be discarded rather than appended.
            out.out.push_str("packetframe_partial_line_no_newl");
            match self.gauges {
                Some(text) => {
                    out.out.clear();
                    out.out.push_str(text);
                    Ok(())
                }
                None => Err(ModuleError::other(self.name, "cannot sample")),
            }
        }
        fn health_check(&self, _: &HealthCtx) -> ModuleResult<HealthReport> {
            match &self.health {
                Some(r) => Ok(r.clone()),
                None => Err(ModuleError::other(self.name, "supervision loop is gone")),
            }
        }
    }

    /// The poll reaches BOTH destinations an operator reads.
    ///
    /// Before it, nothing in the CLI called `health_check` or
    /// `sample_metrics` for any module, so everything they produced was
    /// unreachable. Asserting only that the call happened would pass with
    /// the results dropped at either boundary — the shape this project
    /// keeps producing — so this checks the gauge slot and the snapshot.
    #[test]
    fn the_poll_reaches_both_the_gauge_slot_and_the_snapshot() {
        let dir = tmpdir("both");
        let modules: Vec<(String, Box<dyn Module>)> = vec![(
            "vpp-offload".into(),
            Box::new(Fake {
                name: "vpp-offload",
                health: Some(HealthReport {
                    overall: HealthState::Degraded,
                    subsystems: vec![SubsystemHealth {
                        name: "steering".into(),
                        state: HealthState::Healthy,
                        message: Some("steer off (staging state)".into()),
                        last_success_age_seconds: None,
                    }],
                }),
                gauges: Some("packetframe_vpp_health 1\n"),
            }),
        )];
        let slot = Mutex::new(String::new());

        poll(&dir, &modules, &slot);

        assert_eq!(
            slot.lock().unwrap().as_str(),
            "packetframe_vpp_health 1\n",
            "the module's gauges must reach the slot the exporter appends"
        );
        let snap = load(&dir).unwrap().expect("published");
        let r = snap.modules[0].report.as_ref().expect("a report");
        assert_eq!(r.overall, HealthState::Degraded);
        assert_eq!(r.subsystems[0].name, "steering");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One module's failure must not cost another module its gauges.
    ///
    /// The textfile is parsed as a whole, so a partial line from a module
    /// that failed partway through writing would take out every other
    /// module's gauges AND the BPF counters in the same file. Each module
    /// renders into its own buffer; only a successful one is appended.
    #[test]
    fn a_failing_module_does_not_corrupt_the_others_gauges() {
        let dir = tmpdir("partial");
        let modules: Vec<(String, Box<dyn Module>)> = vec![
            (
                "broken".into(),
                Box::new(Fake {
                    name: "broken",
                    health: None,
                    gauges: None,
                }),
            ),
            (
                "fast-path".into(),
                Box::new(Fake {
                    name: "fast-path",
                    health: Some(HealthReport::healthy()),
                    gauges: Some("packetframe_fp_ok 1\n"),
                }),
            ),
        ];
        let slot = Mutex::new(String::new());

        poll(&dir, &modules, &slot);

        assert_eq!(
            slot.lock().unwrap().as_str(),
            "packetframe_fp_ok 1\n",
            "the healthy module's gauges survive, and the broken module's partial line is \
             nowhere in the output"
        );

        let snap = load(&dir).unwrap().expect("published");
        let broken = snap
            .modules
            .iter()
            .find(|m| m.module == "broken")
            .expect("recorded");
        assert!(broken.report.is_none(), "no verdict was obtained");
        assert!(broken
            .error
            .as_deref()
            .is_some_and(|e| e.contains("supervision loop is gone")));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A poll replaces the previous fragment rather than appending to it.
    ///
    /// Appending would grow the textfile without bound and publish every
    /// gauge many times over, which Prometheus reads as a duplicate-metric
    /// error for the whole file.
    #[test]
    fn a_second_poll_replaces_the_first_fragment() {
        let dir = tmpdir("replace");
        let modules: Vec<(String, Box<dyn Module>)> = vec![(
            "fast-path".into(),
            Box::new(Fake {
                name: "fast-path",
                health: Some(HealthReport::healthy()),
                gauges: Some("packetframe_fp_ok 1\n"),
            }),
        )];
        let slot = Mutex::new(String::new());

        poll(&dir, &modules, &slot);
        poll(&dir, &modules, &slot);

        assert_eq!(
            slot.lock().unwrap().as_str(),
            "packetframe_fp_ok 1\n",
            "one copy, however many polls have run"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
