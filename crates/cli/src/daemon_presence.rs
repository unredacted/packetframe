//! Is the daemon that wrote the state still running?
//!
//! Three callers ask this — `status` to say whether its report is
//! current, `reconfigure` before signalling a pid, and `detach` before
//! unlinking pins the daemon holds FDs for — and they had one answer
//! between them: does some process run *my exact executable path*.
//!
//! That is an identity test being used as a liveness test, and the two
//! diverge in exactly the window an upgrade creates. Deploy a new
//! bundle, run any of the three from it while the old daemon is still
//! up, and the paths differ:
//!
//! - `status` printed `STALE — the daemon is gone` over a daemon that
//!   was demonstrably alive (observed on the shadow, 2026-08-12);
//! - `reconfigure` refused with "not a packetframe process (stale
//!   pidfile?)", which is the canary lever failing mid-rollout;
//! - `detach` found no daemon and **proceeded**, which is the one that
//!   costs an outage. Its own comment records the precedent: the detach
//!   ran, reported clean, and `ip link show` still had `xdpgeneric`
//!   attached, because the daemon holds the `bpf_link` FDs.
//!
//! It was also wrong in the other direction. The comparison is on the
//! path *string*, with a trailing ` (deleted)` stripped, so a daemon
//! whose binary had been replaced under it read as "the same binary as
//! me" while running entirely different code.
//!
//! So this answers three-valued, and the callers apply their own safe
//! default — which is the point, because theirs are opposite. `status`
//! may say "cannot tell" and be useful. `detach` must have positive
//! evidence of ABSENCE before it touches anything.
//!
//! Identity is the pair the rest of this codebase already uses for
//! adoption: `(pid, start_ticks)` against a `boot_id`, because a bare
//! pid is reusable and `start_ticks` counts from boot. The daemon
//! records its own at startup, in the root-owned state dir, so no
//! user-settable name is trusted anywhere — the reason the exe check
//! existed in the first place (`comm` is settable via `prctl`).

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
use std::path::Path;

/// What can be established about the daemon named by the pid file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonPresence {
    /// A live process, confirmed to be the one that wrote the record.
    Running { pid: i32 },
    /// Positively established absent: no record, no such process, or a
    /// pid whose identity no longer matches what was recorded — which
    /// means it was reused and our daemon is gone.
    Gone { why: String },
    /// Neither could be shown. **Not** a synonym for absent: a caller
    /// that would act destructively must treat this as present.
    Unknown { why: String },
}

/// The identity a daemon records for itself, and that a later CLI
/// checks against.
///
/// Written as one line so the file stays `cat`-able and a legacy
/// single-pid file still parses — an older daemon's record yields
/// `None` here rather than a parse error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonIdentity {
    pub pid: i32,
    pub start_ticks: u64,
    pub boot_id: String,
}

impl DaemonIdentity {
    /// This process's own identity, for the daemon to record.
    #[cfg(target_os = "linux")]
    pub fn current() -> std::io::Result<Self> {
        let pid = std::process::id() as i32;
        Ok(Self {
            pid,
            start_ticks: start_ticks(pid)?,
            boot_id: boot_id()?,
        })
    }

    /// One line: `<pid> <start_ticks> <boot_id>`.
    pub fn encode(&self) -> String {
        format!("{} {} {}", self.pid, self.start_ticks, self.boot_id)
    }

    /// Parse a record. `Ok(None)` for a legacy file holding only a pid,
    /// which is a different thing from a malformed one.
    pub fn decode(s: &str) -> std::io::Result<(i32, Option<Self>)> {
        let mut parts = s.split_whitespace();
        let pid: i32 = parts
            .next()
            .ok_or_else(|| bad_data("empty pid file"))?
            .parse()
            .map_err(|e| bad_data(&format!("pid parse: {e}")))?;
        let (Some(ticks), Some(boot)) = (parts.next(), parts.next()) else {
            return Ok((pid, None));
        };
        let start_ticks = ticks
            .parse()
            .map_err(|e| bad_data(&format!("start_ticks parse: {e}")))?;
        Ok((
            pid,
            Some(Self {
                pid,
                start_ticks,
                boot_id: boot.to_string(),
            }),
        ))
    }
}

fn bad_data(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

/// Field 22 of `/proc/<pid>/stat`, the process start time in clock
/// ticks since boot.
///
/// Parsed from the LAST `)` rather than by splitting from the start:
/// field 2 is `comm` in parentheses and may itself contain spaces and
/// brackets, which is the classic way this parse goes wrong.
#[cfg(target_os = "linux")]
pub fn start_ticks(pid: i32) -> std::io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let tail = stat
        .rfind(')')
        .map(|i| &stat[i + 1..])
        .ok_or_else(|| bad_data("no comm terminator in /proc/<pid>/stat"))?;
    // After `)` the fields are state (3) onward, so start_ticks (22) is
    // the 20th token here.
    tail.split_whitespace()
        .nth(19)
        .ok_or_else(|| bad_data("short /proc/<pid>/stat"))?
        .parse()
        .map_err(|e| bad_data(&format!("start_ticks parse: {e}")))
}

#[cfg(target_os = "linux")]
pub fn boot_id() -> std::io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_string())
}

/// What the reader could observe, so the policy below can be decided
/// without touching a filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// No pid file. Nothing was ever recorded, or a clean exit removed it.
    Absent,
    /// Present but unreadable or malformed.
    Unreadable(String),
    /// A pid, and an identity if the daemon that wrote it recorded one.
    Found(i32, Option<DaemonIdentity>),
}

/// THE POLICY, as a pure function.
///
/// Deliberately separate from the `/proc` reads: this is a safety
/// guard, `detach` acts destructively on its answer, and a table that
/// can only be exercised on Linux would be unverified on every host a
/// change is written on.
///
/// `live_identity` is `None` when the process exists but its identity
/// could not be read — which is an answer of "cannot tell", never of
/// "absent".
pub fn decide(
    record: Record,
    proc_alive: bool,
    live_identity: Option<(u64, String)>,
    exe_matches: bool,
    scanned: Option<i32>,
) -> DaemonPresence {
    let (pid, recorded) = match record {
        // No record is NOT evidence of no daemon. The file is written
        // after every module attaches — deliberately, so systemd's
        // `PIDFile=` never points at a half-attached daemon — and a
        // failed write is non-fatal, so a live daemon can legitimately
        // have none. `scanned` is the independent check: it can FIND a
        // daemon (a process running this binary), and its silence
        // proves nothing, which is the polarity the deleted /proc scan
        // had backwards (review finding).
        Record::Absent => {
            return match scanned {
                Some(pid) => DaemonPresence::Unknown {
                    why: format!(
                        "no pid file, but pid {pid} is running this binary — it may be a \
                         daemon that could not write its record"
                    ),
                },
                None => DaemonPresence::Gone {
                    why: "no pid file, and no process is running this binary".into(),
                },
            }
        }
        Record::Unreadable(why) => return DaemonPresence::Unknown { why },
        Record::Found(pid, id) => (pid, id),
    };
    if !proc_alive {
        return DaemonPresence::Gone {
            why: format!("pid {pid} is not running"),
        };
    }
    let Some(recorded) = recorded else {
        // Legacy record. The exe match still CONFIRMS — a process
        // running this very binary, at the pid a root-owned file names,
        // is ours. Its FAILURE proves nothing, and reading that as
        // absence is the whole defect.
        return if exe_matches {
            DaemonPresence::Running { pid }
        } else {
            DaemonPresence::Unknown {
                why: format!(
                    "pid {pid} is running but the record predates identity tracking, and this \
                     command is a different binary than that process — restart the daemon on \
                     this build to make it checkable"
                ),
            }
        };
    };
    let Some((ticks, boot)) = live_identity else {
        return DaemonPresence::Unknown {
            why: format!("pid {pid} is running but its identity could not be read"),
        };
    };
    if ticks == recorded.start_ticks && boot == recorded.boot_id {
        DaemonPresence::Running { pid }
    } else {
        // Alive, but not the process that wrote the record: the pid was
        // reused. The one case where a live pid still proves absence.
        DaemonPresence::Gone {
            why: format!(
                "pid {pid} is running but was reused; the daemon that wrote the record is gone"
            ),
        }
    }
}

/// Establish presence from the record at `pid_path`. Thin I/O over
/// [`decide`], which holds the policy.
#[cfg(target_os = "linux")]
pub fn presence_of(
    pid_path: &Path,
    exe_matches: impl Fn(i32) -> bool,
    scan: impl Fn() -> Option<i32>,
) -> DaemonPresence {
    let record = match std::fs::read_to_string(pid_path) {
        Ok(s) => match DaemonIdentity::decode(&s) {
            Ok((pid, id)) => Record::Found(pid, id),
            Err(e) => Record::Unreadable(format!("unreadable {}: {e}", pid_path.display())),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Record::Absent,
        Err(e) => Record::Unreadable(format!("cannot read {}: {e}", pid_path.display())),
    };
    let pid = match &record {
        Record::Found(pid, _) => *pid,
        // Only the no-record path consults the scan, and only to find.
        _ => return decide(record, false, None, false, scan()),
    };
    let alive = Path::new(&format!("/proc/{pid}")).exists();
    let live_identity = match (start_ticks(pid), boot_id()) {
        (Ok(t), Ok(b)) => Some((t, b)),
        _ => None,
    };
    decide(record, alive, live_identity, exe_matches(pid), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only `Gone` may license a destructive act. `Unknown` must not —
    /// that is the whole polarity question `detach` turns on.
    fn is_gone(p: &DaemonPresence) -> bool {
        matches!(p, DaemonPresence::Gone { .. })
    }

    fn id(pid: i32, ticks: u64) -> DaemonIdentity {
        DaemonIdentity {
            pid,
            start_ticks: ticks,
            boot_id: "boot-a".into(),
        }
    }

    /// The policy table, on every host.
    ///
    /// `detach` acts destructively on this answer and its half of the
    /// original defect could never be observed without unlinking pins
    /// under a live daemon — so it is pinned here rather than left
    /// inferred. The rule that matters: only `Gone` may license a
    /// destructive act, and it requires positive evidence.
    #[test]
    fn absence_is_never_concluded_from_a_failed_identity_check() {
        // The upgrade window, and the whole bug: a live daemon, a
        // legacy record, and a CLI at a different path. Was `Gone`.
        let unknown = decide(Record::Found(42, None), true, None, false, None);
        assert!(
            matches!(unknown, DaemonPresence::Unknown { .. }),
            "a live pid we cannot identify is not absence: {unknown:?}"
        );
        assert!(
            !is_gone(&unknown),
            "so nothing destructive may proceed on it"
        );

        // Same record, same binary: the exe match still confirms.
        assert_eq!(
            decide(Record::Found(42, None), true, None, true, None),
            DaemonPresence::Running { pid: 42 }
        );

        // Identity recorded and matching: Running whatever the exe says.
        // This is the upgrade window working — a different CLI binary
        // reads its own daemon correctly.
        assert_eq!(
            decide(
                Record::Found(42, Some(id(42, 900))),
                true,
                Some((900, "boot-a".into())),
                false,
                None,
            ),
            DaemonPresence::Running { pid: 42 }
        );

        // Identity mismatch: the pid was reused, so our daemon IS gone.
        // The only case where a live pid proves absence.
        let reused = decide(
            Record::Found(42, Some(id(42, 900))),
            true,
            Some((901, "boot-a".into())),
            true,
            None,
        );
        assert!(is_gone(&reused), "{reused:?}");

        // Same pid and ticks across a reboot is a real collision, and
        // the boot id is what separates them.
        let rebooted = decide(
            Record::Found(42, Some(id(42, 900))),
            true,
            Some((900, "boot-b".into())),
            true,
            None,
        );
        assert!(is_gone(&rebooted), "{rebooted:?}");

        // Identity recorded but unreadable now: cannot tell.
        assert!(!is_gone(&decide(
            Record::Found(42, Some(id(42, 900))),
            true,
            None,
            true,
            None
        )));

        // No process: absent, regardless of what was recorded.
        assert!(is_gone(&decide(
            Record::Found(42, Some(id(42, 900))),
            false,
            None,
            true,
            None
        )));
        assert!(is_gone(&decide(Record::Absent, false, None, false, None)));

        // No record, but a process IS running this binary: the daemon
        // may simply have failed to write one — the file is written
        // after attach and a failed write is non-fatal. Must not read
        // as absence (review finding, P1).
        let orphan = decide(Record::Absent, false, None, false, Some(77));
        assert!(
            matches!(orphan, DaemonPresence::Unknown { .. }),
            "a running copy of this binary with no record is not absence: {orphan:?}"
        );

        // Unreadable record: cannot tell. A corrupt file is exactly
        // when the destructive path must not fire.
        assert!(!is_gone(&decide(
            Record::Unreadable("torn".into()),
            false,
            None,
            false,
            None
        )));
    }

    /// A legacy record parses as "pid, no identity" rather than as an
    /// error — an older daemon's file must stay readable.
    #[test]
    fn a_legacy_record_is_not_a_parse_failure() {
        let (pid, id) = DaemonIdentity::decode("12345\n").expect("legacy parses");
        assert_eq!(pid, 12345);
        assert!(id.is_none());

        let (pid, id) = DaemonIdentity::decode("12345 998877 abc-def").expect("full parses");
        assert_eq!(pid, 12345);
        let id = id.expect("identity");
        assert_eq!(id.start_ticks, 998877);
        assert_eq!(id.boot_id, "abc-def");
    }

    /// Field 22 is read past a `comm` that would break a naive split:
    /// it is parenthesised and may contain spaces and brackets.
    #[test]
    fn start_ticks_is_anchored_on_the_last_bracket() {
        // After the last `)` the first token is field 3 (state), so
        // field 22 is the 20th here: state plus 18 fillers, then it.
        let stat = "4242 (evil ) proc 1 2) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 \
                    987654 23 24";
        let tail = stat.rfind(')').map(|i| &stat[i + 1..]).expect("terminator");
        let field22: u64 = tail
            .split_whitespace()
            .nth(19)
            .expect("field")
            .parse()
            .expect("number");
        assert_eq!(field22, 987654, "the last `)` is the only safe anchor");
    }

    /// And the real reader agrees with that arithmetic on this process.
    #[cfg(target_os = "linux")]
    #[test]
    fn start_ticks_reads_this_process() {
        assert!(start_ticks(std::process::id() as i32).expect("own start_ticks") > 0);
    }
}
