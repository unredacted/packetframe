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

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use packetframe_common::module::{
    HealthCtx, HealthReport, HealthState, MetricsWriter, Module, SubsystemHealth, RESTART_SEQUENCE,
};
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
    /// The event-log writer's counters and last error, so `status` can
    /// say when the log is not being written. `None` when it is off, or
    /// from a daemon that predates it.
    #[serde(default)]
    pub event_log: Option<packetframe_common::events::Status>,
}

impl Snapshot {
    pub fn path_in(state_dir: &Path) -> PathBuf {
        state_dir.join(HEALTH_FILE_NAME)
    }
}

/// A module the config declares that did not come up at startup, and
/// why.
///
/// Only modules whose startup failure DEGRADES the daemon rather than
/// aborting it ever land here — see `DEGRADE_ON_START_FAILURE` in the
/// loader. The daemon keeps running without them, so the one thing that
/// must not happen is for them to vanish from every surface an operator
/// reads: no health row, no reconfigure line, only a journal entry from
/// boot that nobody is watching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotAttached {
    pub module: String,
    pub reason: String,
    /// The module's gauges for this state, rendered once by the loader.
    /// Carried because the module itself is gone from the running set,
    /// so nothing else would emit them — and a missing series is not an
    /// alert, a zeroed healthy one is.
    pub metrics: String,
}

/// The health row for a module that did not come up.
///
/// **Degraded, not Unhealthy**, and the choice is not a softening. The
/// modules that degrade this way are second tiers: the eBPF fast-path
/// is forwarding on its own, which is the designed fallback, and
/// vpp-offload's own health doctrine already reports "dead and
/// unsteered" as Degraded for exactly that reason — paging as the
/// worst state in the system for a router that is forwarding correctly
/// is how alerts get muted. Degraded is still not-healthy, so the
/// sustained-not-healthy page fires; it just fires as what it is.
pub fn not_attached_entry(n: &NotAttached) -> ModuleEntry {
    ModuleEntry {
        module: n.module.clone(),
        report: Some(HealthReport {
            overall: HealthState::Degraded,
            subsystems: vec![SubsystemHealth {
                name: "startup".into(),
                state: HealthState::Degraded,
                message: Some(format!(
                    "did not come up at startup: {}. The eBPF fast-path is forwarding on its \
                     own and nothing is offloaded to this module. Fix the cause, then \
                     `{RESTART_SEQUENCE}` — a reload cannot start a module that failed to \
                     attach, and a bare restart leaves pins the next start refuses",
                    n.reason
                )),
                last_success_age_seconds: None,
            }],
        }),
        error: None,
    }
}

/// What `packetframe reconfigure` reports for a module that did not
/// come up.
///
/// Without it, the reload's "is every configured module running?" check
/// saw a section with no module and called it "added to config (restart
/// required)" — true in its remedy and false in its cause, on every
/// SIGHUP for as long as the daemon ran. The operator would go looking
/// for a config edit they never made.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn not_attached_reconfigure_line(n: &NotAttached) -> String {
    format!(
        "{}: not running — it failed to come up at startup ({}); fix the cause, then \
         `{RESTART_SEQUENCE}`",
        n.module, n.reason
    )
}

/// What `packetframe reconfigure` reports when the section of a module
/// that did not come up is REMOVED from the config.
///
/// Not OK: the daemon still carries it as configured-but-failed, and
/// keeps reporting it Degraded, until a restart re-reads the module set
/// — the same restart-only rule a running module's removal gets.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn not_attached_removed_line(n: &NotAttached) -> String {
    format!(
        "{}: removed from config, but it failed at startup and is still reported until \
         the daemon restarts (`{RESTART_SEQUENCE}`)",
        n.module
    )
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
pub fn poll(
    state_dir: &Path,
    modules: &[(String, Box<dyn Module>)],
    not_attached: &[NotAttached],
    gauges: &Mutex<String>,
) {
    let ctx = HealthCtx::new();
    let mut entries = Vec::with_capacity(modules.len() + not_attached.len());
    let mut rendered = String::new();

    // First, so `packetframe status` leads with the module that is
    // missing rather than burying it under the ones that are fine.
    entries.extend(not_attached.iter().map(not_attached_entry));
    for n in not_attached {
        rendered.push_str(&n.metrics);
    }

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
    // Running modules only: one that never came up is recorded once, as
    // `module_start_failed`, and its row here never changes.
    record_transitions(
        &mut TRANSITIONS.lock().unwrap_or_else(|e| e.into_inner()),
        entries
            .iter()
            .filter(|e| !not_attached.iter().any(|n| n.module == e.module)),
    );
    if let Err(e) = publish(state_dir, entries) {
        tracing::warn!(error = %e, "could not publish the module health snapshot");
    }
}

/// The daemon's health-transition tracker. One per process, like the
/// poll loop that feeds it.
static TRANSITIONS: Mutex<Transitions> = Mutex::new(Transitions::new());

/// How many consecutive polls a new state must hold before it is
/// recorded. Two polls is ten seconds: a state that flickers for one
/// poll is the journal's business, and without this a subsystem that
/// flaps would fill the event log with pairs.
const TRANSITION_CONFIRM_POLLS: u8 = 2;

/// Each module's overall health as last recorded in the event log.
#[derive(Debug, Default)]
pub struct Transitions {
    modules: BTreeMap<String, Tracked>,
}

#[derive(Debug, Default)]
struct Tracked {
    /// `None` until the first state is established.
    recorded: Option<&'static str>,
    /// A different state seen on the most recent polls, and how many.
    candidate: Option<(&'static str, u8)>,
}

/// A confirmed change, for the event log.
#[derive(Debug, PartialEq, Eq)]
pub struct Transition {
    /// `None` for the first state recorded for this module.
    pub from: Option<&'static str>,
    pub to: &'static str,
}

impl Transitions {
    pub const fn new() -> Self {
        Self {
            modules: BTreeMap::new(),
        }
    }

    /// Feed one poll's observation. A module whose first observation is
    /// healthy is simply established — "came up healthy" is what
    /// `module_attached` already said.
    pub fn observe(&mut self, module: &str, state: &'static str) -> Option<Transition> {
        let t = self.modules.entry(module.to_string()).or_default();
        if t.recorded == Some(state) || (t.recorded.is_none() && state == HEALTHY) {
            t.recorded = Some(state);
            t.candidate = None;
            return None;
        }
        let seen = match t.candidate {
            Some((s, n)) if s == state => n.saturating_add(1),
            _ => 1,
        };
        if seen < TRANSITION_CONFIRM_POLLS {
            t.candidate = Some((state, seen));
            return None;
        }
        let from = t.recorded.replace(state);
        t.candidate = None;
        Some(Transition { from, to: state })
    }
}

const HEALTHY: &str = "healthy";

/// The label a health entry is tracked under. A check that could not
/// run is its own state, not an unhealthy report (see [`ModuleEntry`]).
fn state_label(e: &ModuleEntry) -> &'static str {
    match e.report.as_ref().map(|r| r.overall) {
        Some(HealthState::Healthy) => HEALTHY,
        Some(HealthState::Degraded) => "degraded",
        Some(HealthState::Unhealthy) => "unhealthy",
        None => "unknown",
    }
}

/// Why a module is not healthy, in one line: its failing subsystems and
/// their messages, or the reason the check could not run.
fn state_detail(e: &ModuleEntry) -> Option<String> {
    if let Some(err) = &e.error {
        return Some(format!("health check could not run: {err}"));
    }
    let parts: Vec<String> = e
        .report
        .as_ref()?
        .subsystems
        .iter()
        .filter(|s| s.state != HealthState::Healthy)
        .map(|s| match &s.message {
            Some(m) => format!("{}: {m}", s.name),
            None => s.name.clone(),
        })
        .collect();
    (!parts.is_empty()).then(|| parts.join("; "))
}

fn record_transitions<'a>(t: &mut Transitions, entries: impl Iterator<Item = &'a ModuleEntry>) {
    use packetframe_common::events::{kind, Event, Level};
    for e in entries {
        let to = state_label(e);
        let Some(tr) = t.observe(&e.module, to) else {
            continue;
        };
        let level = match to {
            HEALTHY => Level::Info,
            "unhealthy" => Level::Error,
            _ => Level::Warn,
        };
        let mut ev = Event::new(level, &e.module, kind::MODULE_HEALTH)
            .field("from", tr.from.unwrap_or("none"))
            .field("to", to);
        if let Some(d) = state_detail(e) {
            ev = ev.detail(d);
        }
        ev.emit();
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
        event_log: packetframe_common::events::status(),
    };
    let body = serde_json::to_vec_pretty(&snapshot).map_err(|e| format!("serialise: {e}"))?;
    // No `create_dir_all` first: on Linux `atomic::write` makes a missing
    // `state-dir` itself, through the no-follow walk it writes through,
    // and never writable by group or others. The pathname create in
    // front of it followed a symlink anywhere in the path, creating
    // directories wherever it pointed, and left their modes to the
    // umask.
    crate::atomic::write(&Snapshot::path_in(state_dir), &body)
        .map_err(|e| format!("write {}: {e}", Snapshot::path_in(state_dir).display()))
}

/// Remove it. Called on a clean exit, so `status` does not present a
/// departed daemon's last report as the current one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn remove(state_dir: &Path) {
    let path = Snapshot::path_in(state_dir);
    // Through the walked directory descriptor on Linux — a pathname
    // `remove_file` follows intermediate symlinks, and this runs as
    // root (review finding on the identity cleanup; same rule for
    // every removal in a configured directory).
    #[cfg(target_os = "linux")]
    let removed = crate::loader::remove_state_record(&path);
    #[cfg(not(target_os = "linux"))]
    let removed = std::fs::remove_file(&path);
    match removed {
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

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pf-health-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
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
            event_log: None,
        };
        assert!(age_seconds(&s).is_none());
    }

    #[test]
    fn a_health_change_is_recorded_once_it_holds_for_two_polls() {
        let mut t = Transitions::new();
        // Came up healthy: established, not an event.
        assert_eq!(t.observe("vpp-offload", "healthy"), None);
        // One poll of degraded is a flicker.
        assert_eq!(t.observe("vpp-offload", "degraded"), None);
        assert_eq!(t.observe("vpp-offload", "healthy"), None);
        // Two in a row is a transition, recorded once.
        assert_eq!(t.observe("vpp-offload", "degraded"), None);
        assert_eq!(
            t.observe("vpp-offload", "degraded"),
            Some(Transition {
                from: Some("healthy"),
                to: "degraded"
            })
        );
        assert_eq!(t.observe("vpp-offload", "degraded"), None);
        // A candidate that changes restarts the count.
        assert_eq!(t.observe("vpp-offload", "unhealthy"), None);
        assert_eq!(t.observe("vpp-offload", "healthy"), None);
        assert_eq!(
            t.observe("vpp-offload", "healthy"),
            Some(Transition {
                from: Some("degraded"),
                to: "healthy"
            })
        );
        // Modules are tracked independently; a first state that is not
        // healthy is recorded from `none`.
        assert_eq!(t.observe("fast-path", "unknown"), None);
        assert_eq!(
            t.observe("fast-path", "unknown"),
            Some(Transition {
                from: None,
                to: "unknown"
            })
        );
    }

    #[test]
    fn transition_detail_names_the_failing_subsystems() {
        let e = ModuleEntry {
            module: "fast-path".into(),
            report: Some(HealthReport {
                overall: HealthState::Degraded,
                subsystems: vec![
                    SubsystemHealth {
                        name: "fib-programmer".into(),
                        state: HealthState::Healthy,
                        message: None,
                        last_success_age_seconds: None,
                    },
                    SubsystemHealth {
                        name: "bgp-listener".into(),
                        state: HealthState::Degraded,
                        message: Some("session down".into()),
                        last_success_age_seconds: None,
                    },
                ],
            }),
            error: None,
        };
        assert_eq!(state_label(&e), "degraded");
        assert_eq!(
            state_detail(&e).as_deref(),
            Some("bgp-listener: session down")
        );
        let failed = ModuleEntry {
            module: "guard".into(),
            report: None,
            error: Some("map read failed".into()),
        };
        assert_eq!(state_label(&failed), "unknown");
        assert!(state_detail(&failed).unwrap().contains("map read failed"));
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

        poll(&dir, &modules, &[], &slot);

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

    /// A module that did not come up still has a row — first, Degraded,
    /// and saying what is forwarding instead.
    ///
    /// The daemon keeps running without it (the loader's degrade path),
    /// so this row is the only place an operator reading `status` learns
    /// it is missing. Asserted on the published snapshot, which is what
    /// `packetframe status` renders, rather than on the entry builder.
    #[test]
    fn a_module_that_did_not_come_up_is_reported_not_omitted() {
        let dir = tmpdir("not-attached");
        let modules: Vec<(String, Box<dyn Module>)> = vec![(
            "fast-path".into(),
            Box::new(Fake {
                name: "fast-path",
                health: Some(HealthReport::healthy()),
                gauges: Some(""),
            }),
        )];
        let missing = NotAttached {
            module: "vpp-offload".into(),
            reason: "1 NIC queue IRQ(s) currently fire on the cores derived for VPP".into(),
            metrics: "vpp_gauge{module=\"vpp-offload\"} 1\n".into(),
        };
        let slot = Mutex::new(String::new());

        poll(&dir, &modules, std::slice::from_ref(&missing), &slot);

        let snap = load(&dir).unwrap().expect("published");
        assert_eq!(snap.modules.len(), 2, "both modules appear");
        let row = &snap.modules[0];
        assert_eq!(row.module, "vpp-offload", "the missing one leads");
        let r = row.report.as_ref().expect("a report, not a check error");
        assert_eq!(
            r.overall,
            HealthState::Degraded,
            "the fast-path is forwarding — Degraded, not the worst state in the system"
        );
        let msg = r.subsystems[0].message.as_deref().expect("a message");
        assert!(
            msg.contains("NIC queue IRQ"),
            "the reason is carried: {msg}"
        );
        assert!(
            msg.contains("fast-path is forwarding"),
            "and what still works: {msg}"
        );
        assert!(
            msg.contains(RESTART_SEQUENCE),
            "and the remedy, as the full sequence: {msg}"
        );
        assert_eq!(snap.modules[1].module, "fast-path");
        assert!(
            slot.lock()
                .unwrap()
                .contains("vpp_gauge{module=\"vpp-offload\"} 1"),
            "its gauges are published although the module is not in the running set"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The reload line names the real cause, not "added to config".
    #[test]
    fn reconfigure_reports_the_startup_failure_not_a_config_edit() {
        let n = NotAttached {
            module: "vpp-offload".into(),
            reason: "vpp binary not found".into(),
            metrics: String::new(),
        };
        let line = not_attached_reconfigure_line(&n);
        assert!(line.starts_with("vpp-offload: not running"), "{line}");
        assert!(line.contains("vpp binary not found"), "{line}");
        assert!(!line.contains("added to config"), "{line}");
        assert!(line.contains(RESTART_SEQUENCE), "{line}");

        let removed = not_attached_removed_line(&n);
        assert!(
            removed.starts_with("vpp-offload: removed from config"),
            "{removed}"
        );
        assert!(removed.contains(RESTART_SEQUENCE), "{removed}");
    }

    /// The remedy is never a bare restart: SIGTERM preserves the pins
    /// and the next start refuses them.
    #[test]
    fn the_remedy_detaches_between_stop_and_start() {
        let stop = RESTART_SEQUENCE.find("stop").unwrap();
        let detach = RESTART_SEQUENCE.find("detach --all").unwrap();
        let start = RESTART_SEQUENCE.find("start packetframe").unwrap();
        assert!(stop < detach && detach < start, "{RESTART_SEQUENCE}");
        assert!(!RESTART_SEQUENCE.contains("restart"), "{RESTART_SEQUENCE}");
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

        poll(&dir, &modules, &[], &slot);

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

        poll(&dir, &modules, &[], &slot);
        poll(&dir, &modules, &[], &slot);

        assert_eq!(
            slot.lock().unwrap().as_str(),
            "packetframe_fp_ok 1\n",
            "one copy, however many polls have run"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A symlink at the temp name fails the publish, and nothing is
    /// written through it or renamed into place. (`atomic::write` already
    /// refused this before the `create_dir_all` in front of it went; this
    /// pins it for the snapshot.)
    #[cfg(target_os = "linux")]
    #[test]
    fn publish_refuses_a_symlink_at_the_temp_name() {
        let dir = tmpdir("tmp-link");
        let victim = dir.join("victim");
        std::fs::write(&victim, "do not truncate me").unwrap();
        let tmp = dir.join(format!("{HEALTH_FILE_NAME}.tmp"));
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        assert!(
            publish(&dir, Vec::new()).is_err(),
            "published through the link"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "do not truncate me"
        );
        assert!(
            std::fs::symlink_metadata(Snapshot::path_in(&dir)).is_err(),
            "something was renamed into place"
        );

        std::fs::remove_file(&tmp).unwrap();
        publish(&dir, Vec::new()).unwrap();
        assert!(load(&dir).unwrap().is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A symlink at any component of `state-dir` fails the publish
    /// before anything is made where it points. The `create_dir_all` in
    /// front of `atomic::write` followed it and created the missing
    /// directories in the link's target; only the write was refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn publish_creates_nothing_through_a_symlink_in_the_state_dir_path() {
        let base = tmpdir("dir-link");
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        for state_dir in [link.join("state"), link.join("a").join("b"), link.clone()] {
            let Err(err) = publish(&state_dir, Vec::new()) else {
                panic!("published through the link at {}", state_dir.display());
            };
            assert!(
                err.contains("a symlink here is refused"),
                "{}: {err}",
                state_dir.display()
            );
        }
        assert_eq!(
            std::fs::read_dir(&real).unwrap().count(),
            0,
            "something was made or written through the link"
        );
        std::fs::remove_dir_all(&base).unwrap();
    }
}
