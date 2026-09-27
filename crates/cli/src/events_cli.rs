//! `packetframe events`, and the CLI's wiring of the persistent event
//! log ([`packetframe_common::events`]).
//!
//! Portable on purpose: the log is plain files, so reading it — on the
//! router, or a copy pulled off one onto a laptop with `--file` — needs
//! nothing Linux-specific, and the tests run on every host gate.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, SystemTime};

use packetframe_common::config::{Config, GlobalConfig};
use packetframe_common::events::{self, parse_rfc3339, Record};
use serde_json::Value;

use crate::scrub::scrub_for_terminal;
use crate::{DEFAULT_CONFIG_PATH, EXIT_OK, EXIT_RUNTIME_ERROR, EXIT_STARTUP_ERROR};

/// Install the process's event log from the config, unless it is off.
/// Once per process; the daemon and `detach` are the callers.
pub fn install_from(global: &GlobalConfig) {
    if let Some(path) = global.event_log_path() {
        events::install(path, global.event_log_max);
    }
}

/// `event-log` and `event-log-max` are restart-only: the writer owns an
/// open file. Say so on a reload that changes them, rather than leave
/// the operator believing the new path is being written.
#[cfg_attr(not(all(target_os = "linux", feature = "fast-path")), allow(dead_code))]
pub fn warn_if_event_log_changed(global: &GlobalConfig) {
    let running = events::installed().map(|l| (l.path().to_path_buf(), l.max_bytes()));
    let configured = global.event_log_path().map(|p| (p, global.event_log_max));
    if running != configured {
        tracing::warn!(
            running = ?running,
            configured = ?configured,
            "event-log / event-log-max changed; the event log keeps its current file and \
             bound until the daemon restarts"
        );
    }
}

#[derive(clap::Args)]
pub struct EventsArgs {
    /// Path to the config file, for `event-log` / `state-dir`. Defaults
    /// to `/etc/packetframe/packetframe.conf`; with no file there, the
    /// built-in default location is read.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Read this log file (and its rotated `.1`) instead of the
    /// configured one — e.g. a copy pulled off a router.
    #[arg(long, conflicts_with = "config")]
    file: Option<PathBuf>,
    /// Only events at or after this point: a duration back from now
    /// (`90s`, `30m`, `12h`, `2d`, `1w`) or a timestamp (RFC 3339, e.g.
    /// `2026-09-27T06:00:00Z`, or a bare `2026-09-27`, midnight UTC).
    #[arg(long, value_parser = parse_since)]
    since: Option<SystemTime>,
    /// Only events from this module (`daemon`, `vpp-offload`,
    /// `fast-path`, `event-log`, …).
    #[arg(long)]
    module: Option<String>,
    /// One JSON object per line, as stored, instead of the table.
    #[arg(long)]
    json: bool,
}

fn parse_since(s: &str) -> Result<SystemTime, String> {
    parse_since_at(s, SystemTime::now())
}

/// `parse_since` against a fixed "now", for the tests.
fn parse_since_at(s: &str, now: SystemTime) -> Result<SystemTime, String> {
    if let Some(t) = parse_rfc3339(s) {
        return Ok(t);
    }
    let neither =
        || format!("`{s}` is neither a duration (`30m`, `12h`, `2d`, …) nor an RFC 3339 timestamp");
    let unit = s.chars().last().ok_or_else(neither)?;
    let per = match unit {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86_400,
        'w' => 7 * 86_400,
        _ => return Err(neither()),
    };
    let digits = &s[..s.len() - 1];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(neither());
    }
    let n: u64 = digits
        .parse()
        .map_err(|_| format!("`{s}` is too far back"))?;
    let back = n
        .checked_mul(per)
        .map(Duration::from_secs)
        .ok_or_else(|| format!("`{s}` is too far back"))?;
    Ok(now.checked_sub(back).unwrap_or(SystemTime::UNIX_EPOCH))
}

/// Which records a query keeps. A record whose own timestamp does not
/// parse is kept unless a `--since` asks a question it cannot answer.
fn keep(r: &Record, since: Option<SystemTime>, module: Option<&str>) -> bool {
    if module.is_some_and(|m| m != r.module) {
        return false;
    }
    match since {
        None => true,
        Some(t) => parse_rfc3339(&r.ts).is_some_and(|ts| ts >= t),
    }
}

/// One record as a terminal line: time, level, module, event, the
/// detail sentence, then the remaining fields in brackets.
fn render(r: &Record) -> String {
    let mut out = format!(
        "{}  {:<5}  {:<12}  {}",
        r.ts,
        r.level.as_str().to_uppercase(),
        r.module,
        r.event
    );
    if let Some(d) = r.fields.get("detail").and_then(Value::as_str) {
        out.push_str(" — ");
        out.push_str(d);
    }
    let rest: Vec<String> = r
        .fields
        .iter()
        .filter(|(k, _)| k.as_str() != "detail")
        .map(|(k, v)| match v {
            Value::String(s) if !s.is_empty() && !s.contains(char::is_whitespace) => {
                format!("{k}={s}")
            }
            other => format!("{k}={other}"),
        })
        .collect();
    if !rest.is_empty() {
        out.push_str("  [");
        out.push_str(&rest.join(" "));
        out.push(']');
    }
    // Every byte here came from a file; see `scrub`.
    scrub_for_terminal(&out)
}

/// Where the log is, from `--file` or the config. `Err` carries the exit
/// code to use.
fn resolve_path(args: &EventsArgs) -> Result<PathBuf, (u8, String)> {
    if let Some(f) = &args.file {
        return Ok(f.clone());
    }
    let global = match &args.config {
        Some(p) => {
            Config::from_file(p)
                .map_err(|e| (EXIT_STARTUP_ERROR, format!("config parse: {e}")))?
                .global
        }
        None => {
            let default = PathBuf::from(DEFAULT_CONFIG_PATH);
            if default.exists() {
                Config::from_file(&default)
                    .map_err(|e| (EXIT_STARTUP_ERROR, format!("config parse: {e}")))?
                    .global
            } else {
                GlobalConfig::default()
            }
        }
    };
    global.event_log_path().ok_or_else(|| {
        (
            EXIT_STARTUP_ERROR,
            "the event log is off in this config (`event-log off`)".to_string(),
        )
    })
}

/// Stream the matching records to `out` as they are read — memory stays
/// at one record however large the files are. Returns `(shown, skipped)`.
fn print_matching(
    path: &Path,
    args: &EventsArgs,
    out: &mut impl Write,
) -> std::io::Result<(usize, usize)> {
    let mut shown = 0usize;
    let mut write_err = None;
    let skipped = events::read_each(path, |r| {
        if write_err.is_some() || !keep(&r, args.since, args.module.as_deref()) {
            return;
        }
        shown += 1;
        let line = if args.json {
            serde_json::to_string(&r).unwrap_or_default()
        } else {
            render(&r)
        };
        if let Err(e) = writeln!(out, "{line}") {
            write_err = Some(e);
        }
    })?;
    match write_err {
        Some(e) => Err(e),
        None => Ok((shown, skipped)),
    }
}

/// The event-log section of `packetframe status`.
///
/// `running` is the daemon writer's status from its health snapshot:
/// when there is one, it names the file actually being written, and the
/// section describes THAT file — `event-log` is restart-only, so after
/// an edit and a reload the config names a file nobody is writing yet.
/// The configured target is then shown separately, as what the next
/// restart will use.
pub fn status_lines(
    configured: Option<(PathBuf, u64)>,
    running: Option<&events::Status>,
    size: impl Fn(&Path) -> Option<u64>,
) -> Vec<String> {
    let describe = |path: &Path, max: u64| {
        let rotated = events::rotated_path(path);
        format!(
            "event log: {} ({} of {} per file{}); `packetframe events` reads it",
            path.display(),
            size(path).map_or_else(|| "not yet written".to_string(), human_bytes),
            human_bytes(max),
            if size(&rotated).is_some() {
                ", plus the rotated .1"
            } else {
                ""
            }
        )
    };
    let Some(st) = running else {
        return vec![match &configured {
            Some((path, max)) => describe(path, *max),
            None => "event log: off (`event-log off`)".to_string(),
        }];
    };
    let mut lines = vec![
        describe(&st.path, st.max_bytes),
        format!(
            "  daemon writer: {} written, {} dropped (queue full), {} lost (write failed)",
            st.written, st.dropped, st.lost
        ),
    ];
    if configured.as_ref() != Some(&(st.path.clone(), st.max_bytes)) {
        lines.push(format!(
            "  after restart: {} (the config changed; event-log is restart-only, and \
             `packetframe events` reads the configured file — `--file {}` reads this one)",
            match &configured {
                Some((p, m)) => format!("{} at {} per file", p.display(), human_bytes(*m)),
                None => "off".to_string(),
            },
            st.path.display()
        ));
    }
    if let Some(e) = &st.last_error {
        lines.push(format!(
            "  WARNING: the daemon cannot write the event log: {}",
            scrub_for_terminal(e)
        ));
    }
    lines
}

fn human_bytes(n: u64) -> String {
    const K: u64 = 1024;
    if n >= K * K {
        format!("{:.1} MiB", n as f64 / (K * K) as f64)
    } else if n >= K {
        format!("{:.1} KiB", n as f64 / K as f64)
    } else {
        format!("{n} B")
    }
}

pub fn run(args: EventsArgs) -> ExitCode {
    let path = match resolve_path(&args) {
        Ok(p) => p,
        Err((code, msg)) => {
            eprintln!("{}", scrub_for_terminal(&msg));
            return ExitCode::from(code);
        }
    };
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    let (shown, skipped) = match print_matching(&path, &args, &mut out) {
        Ok(r) => r,
        Err(e) => {
            let _ = out.flush();
            eprintln!(
                "could not read {}: {}",
                path.display(),
                scrub_for_terminal(&e.to_string())
            );
            return ExitCode::from(EXIT_RUNTIME_ERROR);
        }
    };
    let _ = out.flush();
    if skipped > 0 {
        eprintln!(
            "note: {skipped} line(s) in {} did not parse and were skipped",
            path.display()
        );
    }
    if shown == 0 && !args.json {
        eprintln!(
            "no events{} in {} (and its rotated .1)",
            if args.since.is_some() || args.module.is_some() {
                " match"
            } else {
                ""
            },
            path.display()
        );
    }
    ExitCode::from(EXIT_OK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::events::{kind, Event, Level};

    fn rec(ts: &str, module: &str, event: &'static str) -> Record {
        let mut r = Event::info(module, event).into_record();
        r.ts = ts.to_string();
        r
    }

    #[test]
    fn since_takes_durations_and_timestamps() {
        let now = parse_rfc3339("2026-09-27T12:00:00Z").unwrap();
        let at = |s| parse_since_at(s, now).unwrap();
        assert_eq!(at("90s"), now - Duration::from_secs(90));
        assert_eq!(at("30m"), now - Duration::from_secs(1800));
        assert_eq!(at("12h"), parse_rfc3339("2026-09-27T00:00:00Z").unwrap());
        assert_eq!(at("2d"), parse_rfc3339("2026-09-25T12:00:00Z").unwrap());
        assert_eq!(at("1w"), parse_rfc3339("2026-09-20T12:00:00Z").unwrap());
        assert_eq!(
            at("2026-09-27T06:00:00Z"),
            parse_rfc3339("2026-09-27T06:00:00Z").unwrap()
        );
        assert_eq!(
            at("2026-09-26"),
            parse_rfc3339("2026-09-26T00:00:00Z").unwrap()
        );
        for bad in ["", "m", "12", "1y", "-5m", "soon", "99999999999999999999w"] {
            assert!(parse_since_at(bad, now).is_err(), "{bad}");
        }
    }

    #[test]
    fn filters_by_time_and_module() {
        let records = [
            rec("2026-09-27T01:00:00.000Z", "daemon", kind::PROCESS_START),
            rec("2026-09-27T03:00:00.000Z", "vpp-offload", kind::STEERING_UP),
            rec(
                "2026-09-27T05:00:00.000Z",
                "vpp-offload",
                kind::STEERING_DOWN,
            ),
            rec("not a time", "vpp-offload", kind::VERIFY_PASSED),
        ];
        let since = parse_rfc3339("2026-09-27T03:00:00Z");
        let pick = |since, module| {
            records
                .iter()
                .filter(|r| keep(r, since, module))
                .map(|r| r.event.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(pick(None, None).len(), 4);
        // `since` is inclusive, and cannot vouch for an unparseable time.
        assert_eq!(pick(since, None), [kind::STEERING_UP, kind::STEERING_DOWN]);
        assert_eq!(
            pick(None, Some("vpp-offload")),
            [kind::STEERING_UP, kind::STEERING_DOWN, kind::VERIFY_PASSED]
        );
        assert_eq!(pick(since, Some("daemon")), Vec::<&str>::new());
        // Exact module match, not a prefix.
        assert!(pick(None, Some("vpp")).is_empty());
    }

    #[test]
    fn renders_one_scrubbed_line_with_detail_then_fields() {
        let mut r = Event::new(Level::Warn, "vpp-offload", kind::STEER_FAILED)
            .detail("steer failed\n  vpp-offload  steering_up — forged")
            .field("rules_remain", false)
            .field("reason", "ntuple insert refused")
            .field("port", "eth0")
            .into_record();
        r.ts = "2026-09-27T12:00:00.000Z".into();
        let line = render(&r);
        assert!(
            !line.contains('\n'),
            "a detail must not forge a row: {line}"
        );
        assert!(
            line.starts_with(
                "2026-09-27T12:00:00.000Z  WARN   vpp-offload   steer_failed — steer failed"
            ),
            "{line}"
        );
        assert!(
            line.ends_with("[port=eth0 reason=\"ntuple insert refused\" rules_remain=false]"),
            "{line}"
        );
    }

    #[test]
    fn a_bare_record_renders_without_empty_brackets() {
        let r = rec(
            "2026-09-27T12:00:00.000Z",
            "fast-path",
            kind::RECONFIGURE_APPLIED,
        );
        assert_eq!(
            render(&r),
            "2026-09-27T12:00:00.000Z  INFO   fast-path     reconfigure_applied"
        );
    }

    fn args(since: Option<SystemTime>, module: Option<&str>, json: bool) -> EventsArgs {
        EventsArgs {
            config: None,
            file: None,
            since,
            module: module.map(str::to_string),
            json,
        }
    }

    #[test]
    fn prints_matching_records_as_it_streams() {
        let dir = std::env::temp_dir().join(format!("pf-events-cli-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("events.log");
        let line = |r: Record| format!("{}\n", serde_json::to_string(&r).unwrap());
        std::fs::write(
            events::rotated_path(&path),
            line(rec(
                "2026-09-27T01:00:00.000Z",
                "daemon",
                kind::PROCESS_START,
            )),
        )
        .unwrap();
        std::fs::write(
            &path,
            format!(
                "{}not json\n{}",
                line(rec(
                    "2026-09-27T03:00:00.000Z",
                    "vpp-offload",
                    kind::STEERING_UP
                )),
                line(rec(
                    "2026-09-27T05:00:00.000Z",
                    "daemon",
                    kind::PROCESS_STOP
                )),
            ),
        )
        .unwrap();

        let mut out = Vec::new();
        let (shown, skipped) = print_matching(&path, &args(None, None, false), &mut out).unwrap();
        assert_eq!((shown, skipped), (3, 1));
        let text = String::from_utf8(out).unwrap();
        let events: Vec<&str> = text
            .lines()
            .map(|l| l.split_whitespace().nth(3).unwrap())
            .collect();
        assert_eq!(
            events,
            [kind::PROCESS_START, kind::STEERING_UP, kind::PROCESS_STOP],
            "rotated generation first"
        );

        let mut out = Vec::new();
        let since = parse_rfc3339("2026-09-27T02:00:00Z");
        let (shown, _) =
            print_matching(&path, &args(since, Some("daemon"), true), &mut out).unwrap();
        assert_eq!(shown, 1);
        let back: Record = serde_json::from_slice(out.trim_ascii_end()).unwrap();
        assert_eq!(back.event, kind::PROCESS_STOP);
    }

    fn writer(path: &str, max: u64) -> events::Status {
        events::Status {
            path: PathBuf::from(path),
            max_bytes: max,
            written: 7,
            dropped: 0,
            lost: 0,
            last_error: None,
        }
    }

    #[test]
    fn status_describes_the_running_writer_not_an_edited_config() {
        let running = writer("/var/lib/packetframe/state/events.log", 10 << 20);
        let size = |_: &Path| Some(2048);
        // Unchanged config: the running file, no restart note.
        let same = status_lines(
            Some((running.path.clone(), running.max_bytes)),
            Some(&running),
            size,
        );
        assert!(
            same[0].contains("/var/lib/packetframe/state/events.log"),
            "{same:?}"
        );
        assert!(
            !same.iter().any(|l| l.contains("after restart")),
            "{same:?}"
        );

        // Edited and reloaded: the section still names the file being
        // written, and the edit shows as what a restart will do.
        let edited = status_lines(
            Some((PathBuf::from("/persist/pf/events.log"), 1 << 20)),
            Some(&running),
            size,
        );
        assert!(
            edited[0].starts_with(
                "event log: /var/lib/packetframe/state/events.log (2.0 KiB of 10.0 MiB"
            ),
            "{edited:?}"
        );
        let after = edited.iter().find(|l| l.contains("after restart")).unwrap();
        assert!(
            after.contains("/persist/pf/events.log at 1.0 MiB"),
            "{after}"
        );

        let off = status_lines(None, Some(&running), size);
        assert!(
            off.iter().any(|l| l.contains("after restart: off")),
            "{off:?}"
        );

        // No daemon snapshot: the config is all there is.
        let idle = status_lines(
            Some((PathBuf::from("/persist/pf/events.log"), 1 << 20)),
            None,
            |_| None,
        );
        assert_eq!(
            idle,
            ["event log: /persist/pf/events.log (not yet written of 1.0 MiB per file); `packetframe events` reads it"]
        );
        assert_eq!(
            status_lines(None, None, size),
            ["event log: off (`event-log off`)"]
        );

        let failing = events::Status {
            last_error: Some("No space left on device\x1b[2J".into()),
            ..running
        };
        let lines = status_lines(None, Some(&failing), size);
        let warn = lines.iter().find(|l| l.contains("WARNING")).unwrap();
        assert!(
            warn.contains("No space left") && !warn.contains('\x1b'),
            "{warn}"
        );
    }

    #[test]
    fn install_is_skipped_when_off() {
        let g = GlobalConfig {
            event_log: packetframe_common::config::EventLogTarget::Off,
            ..Default::default()
        };
        // Off: nothing to install and nothing to fail. (Installing for
        // real would claim the process-wide log for the whole test run.)
        assert_eq!(g.event_log_path(), None);
        install_from(&g);
    }
}
