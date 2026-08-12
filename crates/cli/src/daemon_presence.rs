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

/// Whether the process is alive in the sense that matters here: it can
/// still hold FDs, answer a signal, and publish health.
///
/// Directory existence is not that. A daemon that has exited but has
/// not been reaped keeps `/proc/<pid>` and its original start ticks, so
/// it read as `Running` — `status` presented its final snapshot as
/// current, `reconfigure` waited out its timeout for an acknowledgement
/// that could never come, and `detach` refused for as long as the
/// zombie persisted, even though its FDs are already closed and the
/// links released (review finding).
///
/// The state is the first token after the comm field, which is why the
/// last `)` is the anchor here too.
#[cfg(target_os = "linux")]
pub fn proc_state(pid: i32) -> std::io::Result<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rfind(')')
        .and_then(|i| stat[i + 1..].split_whitespace().next())
        .and_then(|s| s.chars().next())
        .ok_or_else(|| bad_data("no state field in /proc/<pid>/stat"))
}

/// `Z` (zombie) and `X` (dead) are exits that have not been reaped.
pub fn state_is_alive(state: char) -> bool {
    !matches!(state, 'Z' | 'X' | 'x')
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
    scan: impl FnOnce() -> Option<i32>,
) -> DaemonPresence {
    // ANY route to `Gone` has to survive the scan, not just the
    // missing-record one. A replacement daemon attaches BEFORE it
    // rewrites the record, and its write is non-fatal — so a stale
    // record naming a dead or recycled pid is exactly the shape a live
    // replacement leaves, and returning `Gone` there let `detach`
    // unlink pins under it. The first fix covered the case that was
    // named; this covers the rule (review finding, P1).
    let verdict = decide_from_record(record, proc_alive, live_identity, exe_matches);
    // The scan is a CLOSURE, and it is run here rather than passed in
    // as a value. As a value the caller had to remember to supply it on
    // every path, and did not: `presence_of` hard-coded `None` for
    // every `Record::Found`, so the rule this function had just been
    // restructured to enforce never reached the case it was written
    // for. The policy was right and the wiring silently was not, which
    // the table test could not see because it called this directly
    // (review finding). Now there is no `None` to hard-code, and it is
    // only invoked where it can change the answer.
    let scanned = match &verdict {
        DaemonPresence::Gone { .. } => scan(),
        _ => None,
    };
    match (&verdict, scanned) {
        (DaemonPresence::Gone { why }, Some(found)) => DaemonPresence::Unknown {
            why: format!(
                "{why}, but pid {found} is running this binary — it may be a daemon whose \
                 record is stale or was never written"
            ),
        },
        _ => verdict,
    }
}

/// What the record alone establishes, before the scan gets a say.
fn decide_from_record(
    record: Record,
    proc_alive: bool,
    live_identity: Option<(u64, String)>,
    exe_matches: bool,
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
            return DaemonPresence::Gone {
                why: "no pid file".into(),
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

/// This process's own start ticks, or `None` where they cannot be read.
///
/// `Option` rather than a fallible read the caller must handle: a
/// snapshot that cannot record its identity is still worth publishing,
/// and the reader treats the absence as "cannot confirm".
pub fn self_start_ticks() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        start_ticks(std::process::id() as i32).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// This boot's id, or `None` where it cannot be read.
pub fn self_boot_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        boot_id().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
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
        _ => return decide(record, false, None, false, scan),
    };
    // Not directory existence: a zombie keeps its entry and its start
    // ticks, and is not a daemon anything can talk to.
    let alive = match proc_state(pid) {
        Ok(state) => state_is_alive(state),
        // No entry at all is the ordinary dead case. Any other read
        // error leaves `alive` true, so the identity check below
        // decides rather than this line guessing.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => Path::new(&format!("/proc/{pid}")).exists(),
    };
    let live_identity = match (start_ticks(pid), boot_id()) {
        (Ok(t), Ok(b)) => Some((t, b)),
        _ => None,
    };
    decide(record, alive, live_identity, exe_matches(pid), scan)
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
        let unknown = decide(Record::Found(42, None), true, None, false, || None);
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
            decide(Record::Found(42, None), true, None, true, || None),
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
                || None,
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
            || None,
        );
        assert!(is_gone(&reused), "{reused:?}");

        // Same pid and ticks across a reboot is a real collision, and
        // the boot id is what separates them.
        let rebooted = decide(
            Record::Found(42, Some(id(42, 900))),
            true,
            Some((900, "boot-b".into())),
            true,
            || None,
        );
        assert!(is_gone(&rebooted), "{rebooted:?}");

        // Identity recorded but unreadable now: cannot tell.
        assert!(!is_gone(&decide(
            Record::Found(42, Some(id(42, 900))),
            true,
            None,
            true,
            || None
        )));

        // No process: absent, regardless of what was recorded.
        assert!(is_gone(&decide(
            Record::Found(42, Some(id(42, 900))),
            false,
            None,
            true,
            || None
        )));
        assert!(is_gone(&decide(Record::Absent, false, None, false, || {
            None
        })));

        // EVERY route to Gone must survive the scan, not just the
        // missing-record one — a replacement attaches before it
        // rewrites the record, and its write is non-fatal, so each of
        // these is a shape a live daemon leaves behind. The first fix
        // covered only the case that had been named (review finding).
        for (label, record, alive, live) in [
            ("no record", Record::Absent, false, None),
            (
                "recorded pid dead",
                Record::Found(42, Some(id(42, 900))),
                false,
                None,
            ),
            (
                "recorded pid reused",
                Record::Found(42, Some(id(42, 900))),
                true,
                Some((901, "boot-a".to_string())),
            ),
        ] {
            let alone = decide(record.clone(), alive, live.clone(), false, || None);
            assert!(is_gone(&alone), "{label}: the record alone says gone");
            let with_scan = decide(record, alive, live, false, || Some(77));
            assert!(
                matches!(with_scan, DaemonPresence::Unknown { .. }),
                "{label}: but a process running this binary makes it unprovable: \
                 {with_scan:?}"
            );
        }

        // Unreadable record: cannot tell. A corrupt file is exactly
        // when the destructive path must not fire.
        assert!(!is_gone(&decide(
            Record::Unreadable("torn".into()),
            false,
            None,
            false,
            || None
        )));
    }

    /// The WIRING, not the policy: `presence_of` must hand the scan to
    /// every path, including a record that names a dead pid.
    ///
    /// The policy test above passes `decide` its arguments directly, so
    /// it could not see that `presence_of` hard-coded `None` for every
    /// `Record::Found` — the rule was enforced in the function and
    /// never delivered to the case it was written for, which is a live
    /// replacement whose predecessor's record is still on disk (review
    /// finding). Testing a policy in isolation says nothing about
    /// whether anything asks it the right question.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_scan_reaches_the_stale_record_path() {
        let dir = std::env::temp_dir().join(format!("pf-wiring-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let path = dir.join("packetframe.pid");
        // A record naming a pid that cannot exist: dead, so the record
        // alone says Gone.
        std::fs::write(&path, "2147483646 1 boot-a").expect("write");

        assert!(
            is_gone(&presence_of(&path, |_| false, || None)),
            "with nothing running, a dead record is absence"
        );
        let with_daemon = presence_of(&path, |_| false, || Some(77));
        assert!(
            matches!(with_daemon, DaemonPresence::Unknown { .. }),
            "but a live daemon the scan can see must reach this path too — this is \
             where `detach` would otherwise unlink pins beneath it: {with_daemon:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A zombie is not a daemon.
    #[test]
    fn unreaped_exits_are_not_alive() {
        for dead in ['Z', 'X', 'x'] {
            assert!(!state_is_alive(dead), "state {dead} has already exited");
        }
        for live in ['R', 'S', 'D', 'T', 't', 'I'] {
            assert!(state_is_alive(live), "state {live} is a process to respect");
        }
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
