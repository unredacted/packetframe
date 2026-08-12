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
        let parts: Vec<&str> = s.split_whitespace().collect();
        let pid = |raw: &str| -> std::io::Result<i32> {
            raw.parse()
                .map_err(|e| bad_data(&format!("pid parse: {e}")))
        };
        match parts.as_slice() {
            [] => Err(bad_data("empty record")),
            // EXACTLY one field is the legacy shape. A partially
            // written identity — pid and ticks, no boot id, which a
            // truncated write produces — used to land here too, and the
            // legacy path then accepted a reused pid on an exe match
            // alone: `reconfigure` would signal it and `status` would
            // present the old report as current (review finding).
            [one] => Ok((pid(one)?, None)),
            [p, ticks, boot] => {
                let p = pid(p)?;
                Ok((
                    p,
                    Some(Self {
                        pid: p,
                        start_ticks: ticks
                            .parse()
                            .map_err(|e| bad_data(&format!("start_ticks parse: {e}")))?,
                        boot_id: boot.to_string(),
                    }),
                ))
            }
            // Anything else is a record this build does not understand:
            // report it rather than guessing which half to trust.
            other => Err(bad_data(&format!(
                "expected 1 or 3 fields, found {}",
                other.len()
            ))),
        }
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
    /// A pid from a record whose provenance is whoever could write the
    /// state directory: the file is not root-owned, or the directory
    /// itself is writable by others — in which case even a root-owned
    /// file proves nothing, because `rename` moves files between
    /// directories without touching their contents or ownership.
    ///
    /// Kept apart from `Found` rather than folded into it: an
    /// unauthenticated record may still show that a pid is DEAD — that
    /// is a fact about `/proc`, not about the file — and `detach` after
    /// a crash depends on it. What it may not do is confirm a LIVE pid,
    /// which is what let a planted record aim root's SIGHUP (review
    /// finding).
    Unauthenticated(i32),
    /// Two authenticated records that disagree: a valid pid file names
    /// one pid, and the sidecar names a DIFFERENT pid that could not be
    /// ruled out as a live process — shown live, or unanswerable.
    ///
    /// Nothing in the data says which record is stale. A restart whose
    /// pid-file rewrite failed (it is non-fatal) leaves the OLD pid
    /// file beside the NEW daemon's sidecar — so discarding the
    /// sidecar for disagreeing with the pid file turned "old pid dead"
    /// plus a name-limited scan into `Gone`, and `detach` unlinked
    /// pins beneath the live replacement (review finding, P1). A
    /// disagreement between two authenticated records with a live
    /// daemon in one of them can never resolve to absence.
    ConflictingRecords { recorded: i32, sidecar: i32 },
}

/// What a search of the process table established.
///
/// Three-valued for the same reason [`DaemonPresence`] is: a search
/// that could not run and a search that ran and found nothing are
/// different facts, and collapsing them into one `None` made the
/// second the default reading of the first (review finding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scan {
    /// A process running a packetframe daemon, at this pid.
    Found(i32),
    /// The table was walked end to end, every process in it was
    /// examined, and none was a daemon.
    ///
    /// The strongest negative available, and still not a proof of
    /// absence: a daemon deployed under a name sharing no prefix with
    /// ours is invisible here by construction — see
    /// `proc_exe_looks_like_a_daemon`'s residual limit. The pid record
    /// is what covers that case, and this variant is only ever
    /// consulted when there is no record to consult.
    NoneFound,
    /// The table could not be walked, or a process in it could not be
    /// examined. Evidence in neither direction.
    Inconclusive(String),
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
    scan: impl FnOnce() -> Scan,
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
    let DaemonPresence::Gone { why } = verdict else {
        return verdict;
    };
    match scan() {
        Scan::Found(found) => DaemonPresence::Unknown {
            why: format!(
                "{why}, but pid {found} is running this binary — it may be a daemon whose \
                 record is stale or was never written"
            ),
        },
        // "Survives the scan" has to mean the scan RAN. It returned a
        // bare `Option`, so a `/proc` that could not be read — or a
        // process in it that could not be examined — was indistinguishable
        // from a table with no daemon in it, and licensed `detach`. That
        // is the same "cannot establish X, therefore not X" this whole
        // module exists to undo, reproduced inside its own fix (review
        // finding, P1). It matters most for `Record::Absent`, where the
        // scan is the ONLY evidence there is.
        Scan::Inconclusive(reason) => DaemonPresence::Unknown {
            why: format!("{why}, and the process table could not be searched for one ({reason})"),
        },
        Scan::NoneFound => DaemonPresence::Gone { why },
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
        // have none. Reaching here means the sidecar did not cover it
        // either (`presence_of` reads that first), so the scan is the
        // only evidence in play — and `decide` demotes this to
        // `Unknown` unless the scan actually completed. A scan that
        // could not look is not a scan that looked and saw nothing,
        // which is the polarity the deleted /proc scan had backwards
        // and that its replacement re-introduced one level down
        // (review findings).
        //
        // THE RESIDUAL, stated because it is a deliberate trade and not
        // an oversight: a completed scan is still name-limited, so a
        // daemon that wrote NEITHER file and runs under a binary name
        // sharing no prefix with ours reads as absent. Refusing on
        // every recordless `Absent` instead would disable `detach`
        // after every clean stop — the daemon removes both files on the
        // way out, and `detach` is the advertised recovery path — which
        // trades a narrow hole for a certain one. Closing it properly
        // needs evidence that does not go through pids at all: whether
        // any process holds the pinned links. See the runbook.
        Record::Absent => {
            return DaemonPresence::Gone {
                why: "no pid file".into(),
            }
        }
        Record::Unreadable(why) => return DaemonPresence::Unknown { why },
        // A record anyone could have written names a pid; it does not
        // vouch for it. Liveness still applies below — a dead pid is
        // dead whoever claimed it, and `detach` after a crash needs
        // that — but a LIVE one cannot be confirmed from here, which is
        // what let a planted record pick the process root SIGHUPs
        // (review finding).
        Record::Unauthenticated(pid) if proc_alive => {
            return DaemonPresence::Unknown {
                why: format!(
                    "pid {pid} is running, but the record naming it cannot be trusted — the \
                     file is not root-owned, or the state directory is writable by others, \
                     and anything with write access could have put the record there (or \
                     moved it there whole), so it cannot be acted on"
                ),
            }
        }
        Record::Unauthenticated(pid) => (pid, None),
        // A live daemon exists whichever record is stale, so no
        // verdict below — least of all `Gone` — may be reached from
        // the pid file alone. Signalling needs certainty about WHICH
        // process, and two disagreeing authenticated records are the
        // definition of not having it.
        Record::ConflictingRecords { recorded, sidecar } => {
            return DaemonPresence::Unknown {
                why: format!(
                    "two authenticated records disagree: the pid file names {recorded} but \
                     the identity sidecar names {sidecar}, which could not be ruled out as \
                     a live daemon — likely a failed pid-file rewrite during a restart. \
                     Restart the daemon to re-record both, or remove the stale pid file"
                ),
            }
        }
        Record::Found(pid, id) => (pid, id),
    };
    if !proc_alive {
        return DaemonPresence::Gone {
            why: format!("pid {pid} is not running"),
        };
    }
    let Some(recorded) = recorded else {
        // Legacy record: a root-owned file names a pid and nothing
        // else. THE RULE, now applied here too: only a matching
        // identity confirms a live pid, and weaker evidence never
        // upgrades a verdict.
        //
        // This arm used to confirm on the executable match, arguing
        // that our binary at a root-recorded pid is ours. But the exe
        // predicate deliberately accepts versioned siblings across
        // bundles — right for FINDING a daemon, not for identifying
        // one — so a legacy record surviving a crash, its pid reused
        // by a `packetframe* run` from another bundle and another
        // state directory, read as `Running` and took root's SIGHUP
        // (review finding; the identity-mismatch arm fell to the same
        // reasoning one round earlier).
        //
        // The cost lands once, on the first upgrade from a pre-sidecar
        // build: `reconfigure` refuses and `status` cannot confirm
        // until the daemon restarts on a build that records identity.
        // `status` usually recovers sooner than that — the health
        // snapshot carries the publisher's own identity, which is the
        // matching-identity evidence this record lacks.
        let what = if exe_matches {
            "a packetframe daemon is running at that pid, but a pid alone cannot show it \
             is the one that wrote the record"
        } else {
            "this command is a different binary than that process"
        };
        return DaemonPresence::Unknown {
            why: format!(
                "pid {pid} is running but the record predates identity tracking — {what}; \
                 restart the daemon on this build to make it checkable"
            ),
        };
    };
    let Some((ticks, boot)) = live_identity else {
        return DaemonPresence::Unknown {
            why: format!("pid {pid} is running but its identity could not be read"),
        };
    };
    // A record that does NOT describe the live process settles nothing:
    // two situations produce it and the data cannot separate them. The
    // pid was reused after our daemon died, or the record is stale — a
    // rollback to a build that does not maintain the sidecar rewrites
    // only the pid file and cannot know to remove it, and after a
    // reboot the pids can coincide.
    //
    // Concluding `Gone` there was the fail-open half: it licenses
    // `detach` while a rolled-back daemon is live. `Unknown` is the
    // whole answer — the mismatch says which daemon this is NOT, and
    // nothing says which one it is.
    //
    // It briefly fell back to the executable match and returned
    // `Running`. That rehabilitated a record the identity had just
    // CONTRADICTED, on weaker evidence than the contradiction: a
    // `packetframe run` from another bundle and another state directory
    // satisfies the exe check, so a reused pid made `reconfigure`
    // SIGHUP an unrelated production daemon into a config reload while
    // the intended one timed out (review finding). Reachable because
    // that predicate now accepts versioned siblings, which is exactly
    // right for FINDING a daemon and not enough for identifying one.
    //
    // The rollback case it was meant to serve — an old build rewriting
    // the pid file under a sidecar it cannot know to remove — needs the
    // pids to coincide across a reboot before it lands here at all, and
    // its cost is a refusal that names the pid. Signalling a stranger
    // is not.
    //
    // An earlier attempt dated the two files by mtime, which a
    // coarse-resolution filesystem defeats and which forced an ordering
    // on the writer. Removed: cleverness standing in for the
    // observation that a mismatched record is simply not evidence.
    if ticks == recorded.start_ticks && boot == recorded.boot_id {
        // Identity matched, and the record was shown to be root-owned
        // before it was read — see `record_is_authentic`, which is what
        // stops an unprivileged writer naming a victim pid here.
        //
        // Deliberately NOT also requiring an executable match. The
        // ownership check already closes that attack — an unprivileged
        // user cannot create a root-owned file — and demanding the exe
        // as well would refuse a daemon deployed under a different
        // binary NAME for no gain against an attacker who cannot get
        // past the file check anyway.
        //
        // That claim about renamed binaries was inconsistent with the
        // scan, which required an exactly equal filename and so missed
        // the daemon it exists to find (review finding). The scan now
        // accepts a versioned sibling; a name sharing no prefix is
        // found by this record and by nothing else, which is why the
        // record path may not add an executable requirement on top.
        DaemonPresence::Running { pid }
    } else {
        // `exe_matches` deliberately does not appear here. It changes
        // this from "some process holds that pid" to "some packetframe
        // daemon holds that pid", which is worth SAYING — an operator
        // triaging the refusal wants to know — and is not identity.
        let what = if exe_matches {
            "is running a packetframe daemon, but not the one the record describes"
        } else {
            "does not match the recorded identity and is not a packetframe daemon"
        };
        DaemonPresence::Unknown {
            why: format!(
                "pid {pid} {what} — the pid was reused, or the record is stale. Check what \
                 pid {pid} is before acting on it; restarting the daemon re-records the \
                 identity"
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

/// Whether a recorded identity describes a process that is alive right
/// now. THREE answers, because the callers act on the negative:
/// `Some(true)` — alive, non-zombie, ticks and boot id match;
/// `Some(false)` — positively shown absent, exited, or a different
/// process (the pid was reused); `None` — could not be established.
///
/// This is the arbiter between two authenticated records that disagree
/// — `/proc` is the only party with an opinion about which still
/// describes something — and the first version was a bool, collapsing
/// "could not read its state" into "not live". A transient `/proc`
/// read failure then discarded the live replacement's sidecar as
/// stale, and the dead pid in the old record resolved to `Gone`
/// (review finding: the same cannot-tell-vs-no collapse as `Scan` and
/// `Sidecar`, in the third structure this module grew).
#[cfg(target_os = "linux")]
fn identity_liveness(id: &DaemonIdentity) -> Option<bool> {
    let state = match proc_state(id.pid) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    if !state_is_alive(state) {
        return Some(false);
    }
    let ticks = match start_ticks(id.pid) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    if ticks != id.start_ticks {
        return Some(false);
    }
    match boot_id() {
        Ok(b) if b == id.boot_id => Some(true),
        // A different boot id means every recorded tick count is from a
        // previous boot: the recorded process is positively gone.
        Ok(_) => Some(false),
        Err(_) => None,
    }
}

/// Read a state file and say whether it was root-owned, through ONE
/// descriptor.
///
/// Provenance rather than a bare read because the two files are trusted
/// differently and both are trusted for something: the sidecar only if
/// authentic, the pid file's pid for liveness either way. Returning the
/// bit alongside the bytes is what stops a caller reading the file and
/// then forgetting to ask.
///
/// Root-owned, a regular file, and not group- or world-writable. An
/// attacker with directory write can still unlink either file; anything
/// they create in its place is theirs and fails this.
#[cfg(target_os = "linux")]
fn read_with_provenance(path: &Path) -> std::io::Result<(String, bool)> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = f.metadata()?;
    let root_owned = meta.is_file() && meta.uid() == 0 && meta.mode() & 0o022 == 0;
    let mut raw = String::new();
    f.read_to_string(&mut raw)?;
    Ok((raw, root_owned))
}

/// Whether the state DIRECTORY can vouch for what it contains: the
/// directory itself root-owned, a real directory, not group- or
/// world-writable — and NOT MOVABLE, which is a property of its
/// ancestors, not of it.
///
/// Per-file ownership is not enough, and the gap is `rename`: moving a
/// file needs write on the two directories and nothing from the file,
/// so an unprivileged user with write on two state dirs could relocate
/// a root-owned pid file and sidecar — never creating or modifying a
/// root-owned byte — and have root's `reconfigure` for one instance
/// SIGHUP the other (review finding). A directory the attacker can
/// write is a directory whose contents they choose, whoever owns the
/// files; so in such a directory, no record confirms a live pid.
///
/// And checking the directory alone is not enough either, for the same
/// operation one level up: under a writable parent, two whole
/// root-owned state directories can have their NAMES exchanged without
/// a byte of either being modified, so the configured path leads to the
/// other instance's records and every per-file and per-directory check
/// passes (review finding — the first replay fix, replayed against
/// itself). So the ancestors are checked too, every one to the root:
/// each must be root-owned and either not writable by others or
/// sticky — in a sticky directory (`/tmp`) only the owner of an entry
/// may rename it, and the entry in question is root-owned.
///
/// Symlinks are refused ANYWHERE in the path, not just at the final
/// component: a symlinked ancestor is repointable by whoever can write
/// its containing directory, which is the swap again without a rename
/// of the target. `canonicalize` resolves every link, so equality with
/// the configured path proves there were none. The cost, documented in
/// the runbook: a state dir configured through a symlinked path (e.g.
/// `/var/run` on systems where it links to `/run`) must be configured
/// by its real path.
///
/// Judged on descriptors and canonical paths; errors return `false` —
/// unauthenticated, never trusted.
#[cfg(target_os = "linux")]
fn dir_is_authentic(dir: &Path) -> bool {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // No symlinks anywhere in the path.
    match std::fs::canonicalize(dir) {
        Ok(canon) if canon == dir => {}
        _ => return false,
    }
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
    else {
        return false;
    };
    let Ok(meta) = f.metadata() else {
        return false;
    };
    if !(meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0) {
        return false;
    }
    // The chain: nobody below root may be able to rename this
    // directory or any ancestor of it. The path is symlink-free (just
    // proven), so plain metadata on each ancestor examines the
    // directory it names.
    for ancestor in dir.ancestors().skip(1) {
        let Ok(meta) = std::fs::metadata(ancestor) else {
            return false;
        };
        let mode = meta.mode();
        let unmovable_children = mode & 0o022 == 0 || mode & 0o1000 != 0;
        if !(meta.is_dir() && meta.uid() == 0 && unmovable_children) {
            return false;
        }
    }
    true
}

/// What the sidecar yields when it must stand as the record of last
/// resort — when the pid file is missing or unusable.
///
/// Three-valued, because "no sidecar" and "a sidecar that cannot
/// vouch" license opposite things: a missing file falls through to the
/// scan and may end in `Gone`, while a present-but-unreadable one is
/// exactly a live daemon's record mid-trouble and must stay `Unknown`.
/// The first version collapsed both into `None`, so a transient read
/// failure on the sidecar of a daemon whose pid write had also failed
/// read as `Absent`, survived a name-limited scan, and licensed
/// `detach` (review finding, P1 — the same collapse the `Scan` enum
/// had just been introduced to fix, one file over).
#[cfg(target_os = "linux")]
enum Sidecar {
    /// No file at all.
    Missing,
    /// Authentic, whole, and carrying a full identity.
    Identity(DaemonIdentity),
    /// Present, but it cannot vouch: unreadable, malformed, not
    /// root-owned, identity-less, or sitting in a directory anyone can
    /// rewrite.
    Unusable(String),
}

#[cfg(target_os = "linux")]
fn sidecar_record(path: &Path, dir_authentic: bool) -> Sidecar {
    match read_with_provenance(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Sidecar::Missing,
        Err(e) => Sidecar::Unusable(format!("cannot read {}: {e}", path.display())),
        Ok((raw, root_owned)) => {
            if !dir_authentic {
                return Sidecar::Unusable(format!(
                    "{} sits in a state directory that is not root-owned and unwritable by \
                     others, so its contents could have been placed there by anyone",
                    path.display()
                ));
            }
            if !root_owned {
                return Sidecar::Unusable(format!("{} is not root-owned", path.display()));
            }
            match DaemonIdentity::decode(&raw) {
                Ok((_, Some(id))) => Sidecar::Identity(id),
                // The daemon never writes a pid-only sidecar; whatever
                // produced this, it identifies nothing.
                Ok((pid, None)) => Sidecar::Unusable(format!(
                    "{} holds only a pid ({pid}), not an identity",
                    path.display()
                )),
                Err(e) => Sidecar::Unusable(format!("malformed {}: {e}", path.display())),
            }
        }
    }
}

/// Establish presence from the record at `pid_path`. Thin I/O over
/// [`decide`], which holds the policy.
#[cfg(target_os = "linux")]
pub fn presence_of(
    pid_path: &Path,
    identity_path: &Path,
    exe_matches: impl Fn(i32) -> bool,
    scan: impl Fn() -> Scan,
) -> DaemonPresence {
    // The directory gate applies to BOTH files: file ownership cannot
    // say which directory a record was written FOR, and `rename` moves
    // root-owned files between attacker-writable directories without
    // touching a byte of them (review finding — the replay).
    let dir_ok = pid_path.parent().is_some_and(dir_is_authentic);
    // The sidecar consulted whenever the pid file cannot answer alone —
    // missing, unreadable, or undecodable. It carries its own pid, it
    // is authenticated, and it identifies the daemon WITHOUT reference
    // to what its binary is called, which is the case the name-limited
    // `/proc` scan cannot see (review finding). The identity it names
    // still has to match the live process in `decide`, so a stale one
    // ends in `Unknown`, not a confirmation.
    let fall_back_to_sidecar = |on_no_sidecar: Record| match sidecar_record(identity_path, dir_ok) {
        Sidecar::Identity(id) => Record::Found(id.pid, Some(id)),
        Sidecar::Missing => on_no_sidecar,
        // A sidecar that exists but cannot vouch is not a missing one:
        // it is what a live daemon's record looks like mid-trouble, and
        // reading it as absence licensed `detach` (review finding, P1).
        Sidecar::Unusable(why) => Record::Unreadable(why),
    };
    let record = match read_with_provenance(pid_path) {
        Ok((s, root_owned)) => match DaemonIdentity::decode(&s) {
            // The pid file yields a PID AND NOTHING ELSE. It is not
            // authenticated, so an identity read from it would let an
            // attacker with directory write plant a combined record and
            // pick the pid root signals — which is what happened when
            // an inline identity was preferred here (review finding).
            // It also stays a bare pid on the write side, because CLIs
            // from other bundles parse it whole.
            Ok((pid, _unauthenticated)) if root_owned && dir_ok => {
                match sidecar_record(identity_path, dir_ok) {
                    Sidecar::Identity(id) if id.pid == pid => Record::Found(pid, Some(id)),
                    // A sidecar naming a DIFFERENT pid used to be
                    // discarded as a previous daemon's leftover. It is
                    // just as much the shape a restart leaves when its
                    // pid-file rewrite fails: NEW sidecar, OLD pid
                    // file — and discarding the newer record let "old
                    // pid dead" resolve to `Gone` under the live
                    // replacement (review finding, P1). Which record
                    // is stale is decided by /proc, the only party
                    // with an opinion — and ONLY a positive answer
                    // discards: `Some(false)` means shown dead,
                    // exited, or a different process. `None` means the
                    // question went unanswered, and an unanswered
                    // question keeps the conflict, because "could not
                    // read its state" is not "not live" (review
                    // finding: the arbiter itself had the module's
                    // recurring collapse).
                    Sidecar::Identity(id) if identity_liveness(&id) != Some(false) => {
                        Record::ConflictingRecords {
                            recorded: pid,
                            sidecar: id.pid,
                        }
                    }
                    // The sidecar names something positively gone, so
                    // IT is the stale one; the pid file stands alone,
                    // as an identity-less record.
                    Sidecar::Identity(_) => Record::Found(pid, None),
                    _ => Record::Found(pid, None),
                }
            }
            Ok((pid, _)) => Record::Unauthenticated(pid),
            // A pid file that exists but does not parse says nothing —
            // but the sidecar might: a torn pid write next to a whole,
            // authentic identity is still an identifiable daemon, and
            // refusing `reconfigure` for its whole lifetime over the
            // torn file helped no one (review finding).
            Err(e) => fall_back_to_sidecar(Record::Unreadable(format!(
                "unreadable {}: {e}",
                pid_path.display()
            ))),
        },
        // NO pid file, which is not the same as no daemon: the write is
        // non-fatal and happens after attach, and the daemon carries on
        // to write its sidecar. So the sidecar is the record here.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => fall_back_to_sidecar(Record::Absent),
        Err(e) => fall_back_to_sidecar(Record::Unreadable(format!(
            "cannot read {}: {e}",
            pid_path.display()
        ))),
    };
    let pid = match &record {
        Record::Found(pid, _) | Record::Unauthenticated(pid) => *pid,
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
        let unknown = decide(Record::Found(42, None), true, None, false, || {
            Scan::NoneFound
        });
        assert!(
            matches!(unknown, DaemonPresence::Unknown { .. }),
            "a live pid we cannot identify is not absence: {unknown:?}"
        );
        assert!(
            !is_gone(&unknown),
            "so nothing destructive may proceed on it"
        );

        // Same record, exe match passing: STILL Unknown. The predicate
        // accepts versioned siblings across bundles — right for finding
        // a daemon, not for identifying one — so a legacy record whose
        // pid was reused by a `packetframe* run` from another bundle
        // read as Running and took root's SIGHUP (review finding).
        // Only a matching identity confirms; this record cannot carry
        // one, so a live pid under it is never better than Unknown.
        let legacy_exe = decide(Record::Found(42, None), true, None, true, || {
            Scan::NoneFound
        });
        assert!(
            matches!(legacy_exe, DaemonPresence::Unknown { .. }),
            "an exe match must not upgrade an identity-less record to signal-capable: \
             {legacy_exe:?}"
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
                || Scan::NoneFound,
            ),
            DaemonPresence::Running { pid: 42 }
        );

        // A record that does not describe the live process is NOT
        // absence. Two situations produce it — the pid was reused, or
        // the record is stale after a rollback to a build that does not
        // maintain it — and nothing in the data separates them, so
        // concluding `Gone` licensed `detach` while a rolled-back
        // daemon was live (review finding).
        for live in [(901, "boot-a"), (900, "boot-b")] {
            let mismatch = |exe| {
                decide(
                    Record::Found(42, Some(id(42, 900))),
                    true,
                    Some((live.0, live.1.to_string())),
                    exe,
                    || Scan::NoneFound,
                )
            };
            assert!(
                !is_gone(&mismatch(false)) && !is_gone(&mismatch(true)),
                "a mismatched record never proves absence, whatever the executable says"
            );
            // Nor is it confirmation. The executable check finds *a*
            // daemon, which is not *the* daemon, and reading it as one
            // aimed `reconfigure`'s SIGHUP at an unrelated instance
            // (review finding).
            assert!(matches!(mismatch(true), DaemonPresence::Unknown { .. }));
            assert!(matches!(mismatch(false), DaemonPresence::Unknown { .. }));
        }

        // Identity recorded but unreadable now: cannot tell.
        assert!(!is_gone(&decide(
            Record::Found(42, Some(id(42, 900))),
            true,
            None,
            true,
            || Scan::NoneFound
        )));

        // No process: absent, regardless of what was recorded.
        assert!(is_gone(&decide(
            Record::Found(42, Some(id(42, 900))),
            false,
            None,
            true,
            || Scan::NoneFound
        )));
        assert!(is_gone(&decide(Record::Absent, false, None, false, || {
            Scan::NoneFound
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
        ] {
            let alone = decide(record.clone(), alive, live.clone(), false, || {
                Scan::NoneFound
            });
            assert!(is_gone(&alone), "{label}: the record alone says gone");
            let with_scan = decide(record.clone(), alive, live.clone(), false, || {
                Scan::Found(77)
            });
            assert!(
                matches!(with_scan, DaemonPresence::Unknown { .. }),
                "{label}: but a process running this binary makes it unprovable: \
                 {with_scan:?}"
            );
            // And a scan that could not LOOK is not a scan that looked
            // and saw nothing. `Option` conflated the two, so an
            // unreadable `/proc` — or one process in it that could not
            // be examined — read as positive absence and licensed
            // `detach` (review finding). This is the same defect the
            // whole module exists to undo, one level inside its own
            // fix, which is why the assertion is here rather than in a
            // test of its own.
            let blind = decide(record, alive, live, false, || {
                Scan::Inconclusive("proc unreadable".into())
            });
            assert!(
                matches!(blind, DaemonPresence::Unknown { .. }),
                "{label}: a scan that could not run cannot confirm absence: {blind:?}"
            );
        }

        // Unreadable record: cannot tell. A corrupt file is exactly
        // when the destructive path must not fire.
        assert!(!is_gone(&decide(
            Record::Unreadable("torn".into()),
            false,
            None,
            false,
            || Scan::NoneFound
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
        // Bare pid in the pid file, identity in the sidecar — the
        // shapes the daemon actually writes.
        std::fs::write(&path, "2147483646\n").expect("write");
        let ident = dir.join("packetframe.identity");
        std::fs::write(&ident, "2147483646 1 boot-a").expect("write");

        assert!(
            is_gone(&presence_of(&path, &ident, |_| false, || Scan::NoneFound)),
            "with nothing running, a dead record is absence"
        );
        let with_daemon = presence_of(&path, &ident, |_| false, || Scan::Found(77));
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

    /// An identity record only counts if root wrote it, and only the
    /// SIDECAR can carry one.
    ///
    /// The identity path returns `Running` without consulting the
    /// executable — that is what survives an upgrade — so the record
    /// decides which pid `reconfigure` signals as root. Three ways that
    /// was reachable by an unprivileged writer, each found after the
    /// last was fixed: no ownership check at all; a check on the
    /// pathname rather than the file that was read; and a combined
    /// record planted in the unauthenticated pid file, which bypassed
    /// the check entirely.
    #[cfg(target_os = "linux")]
    #[test]
    fn only_a_root_owned_sidecar_can_name_our_daemon() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("pf-authentic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let ident = dir.join("packetframe.identity");
        let pidfile = dir.join("packetframe.pid");

        // A sidecar this test wrote — so not root-owned unless the
        // suite runs as root, in which case the mode disqualifies it.
        let real = DaemonIdentity::current().expect("own identity");
        std::fs::write(&ident, real.encode()).expect("write");
        std::fs::set_permissions(&ident, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        assert!(
            matches!(sidecar_record(&ident, true), Sidecar::Unusable(_)),
            "a record any user can write must not decide which pid is our daemon"
        );

        // The combined record in the PID FILE must supply nothing, even
        // though `decode` understands the shape.
        std::fs::write(&pidfile, real.encode()).expect("write");
        let _ = std::fs::remove_file(&ident);
        let planted = presence_of(&pidfile, &ident, |_| false, || Scan::NoneFound);
        assert!(
            !matches!(planted, DaemonPresence::Running { .. }),
            "an identity in the unauthenticated pid file is not an identity: {planted:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record anyone could have written names a pid; it vouches for
    /// nothing.
    ///
    /// With directory write and no sidecar to authenticate, an
    /// unprivileged user could plant a pid file naming any
    /// `packetframe* run` process — one from another bundle, with its
    /// own state directory — and the identity-less path read the
    /// widened executable match as proof it was ours. A root
    /// `reconfigure` then SIGHUPs a stranger into a config reload
    /// (review finding).
    ///
    /// Liveness is the exception, and deliberately so: a dead pid is
    /// dead whoever named it. That keeps `detach` working after a crash
    /// on a state dir the daemon no longer owns.
    #[test]
    fn an_unauthenticated_record_cannot_confirm_a_live_pid() {
        for exe in [true, false] {
            let live = decide(Record::Unauthenticated(42), true, None, exe, || {
                Scan::NoneFound
            });
            assert!(
                matches!(live, DaemonPresence::Unknown { .. }),
                "exe_matches={exe}: a planted record must not be able to name the process \
                 root acts on: {live:?}"
            );
            let dead = decide(Record::Unauthenticated(42), false, None, exe, || {
                Scan::NoneFound
            });
            assert!(
                is_gone(&dead),
                "exe_matches={exe}: but a dead pid is dead whoever named it, or `detach` \
                 stops working after a crash: {dead:?}"
            );
        }
    }

    /// A daemon whose pid-file write failed is found by its sidecar.
    ///
    /// The write is non-fatal and the daemon carries on to record its
    /// identity, so this is the ordinary shape of "no pid file, live
    /// daemon" — and the `/proc` scan that used to be the only
    /// backstop for it is name-limited by construction, so a daemon
    /// deployed under an unrelated binary name was invisible and
    /// `detach` unlinked pins beneath it (review finding). The sidecar
    /// identifies it without reference to what it is called.
    ///
    /// Root-only, because the point is a root-owned record and this
    /// cannot forge one. It runs in the qemu CI job, which is root.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_daemon_whose_pid_write_failed_is_found_by_its_sidecar() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pf-sidecar-only-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        // The reader trusts nothing in a directory others can write, so
        // pin the mode rather than inherit the umask.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let pidfile = dir.join("packetframe.pid");
        let ident = dir.join("packetframe.identity");
        // No pid file at all — only the identity, naming this process.
        let real = DaemonIdentity::current().expect("own identity");
        std::fs::write(&ident, real.encode()).expect("write");
        std::fs::set_permissions(&ident, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let p = presence_of(&pidfile, &ident, |_| false, || Scan::NoneFound);
        assert!(
            matches!(p, DaemonPresence::Running { .. }),
            "the sidecar names a live process and is root-owned; nothing about the \
             executable's NAME may be needed to find it: {p:?}"
        );

        // And a TORN PID FILE beside that sidecar is the same daemon:
        // the pid file exists but does not parse, and refusing
        // `reconfigure` for the daemon's whole lifetime over the torn
        // file helps no one when the sidecar identifies it (review
        // finding).
        std::fs::write(&pidfile, "12a4!\n").expect("write");
        std::fs::set_permissions(&pidfile, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let p = presence_of(&pidfile, &ident, |_| false, || Scan::NoneFound);
        assert!(
            matches!(p, DaemonPresence::Running { .. }),
            "a torn pid file next to a whole, authentic sidecar is still an identifiable \
             daemon: {p:?}"
        );

        // A VALID stale pid file — naming a dead pid — beside that live
        // sidecar is the restart-with-failed-rewrite shape, and it used
        // to discard the sidecar for disagreeing with the pid file:
        // "old pid dead" plus a name-limited scan became `Gone`, and
        // `detach` unlinked pins beneath the live replacement (review
        // finding, P1). Two authenticated records that disagree, with a
        // live daemon in one, resolve to nothing.
        std::fs::write(&pidfile, "2147483646\n").expect("write");
        std::fs::set_permissions(&pidfile, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let p = presence_of(&pidfile, &ident, |_| false, || Scan::NoneFound);
        assert!(
            matches!(p, DaemonPresence::Unknown { .. }),
            "a stale-but-valid pid file must not override a live sidecar into Gone: {p:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two authenticated records that disagree resolve to nothing —
    /// never to absence, never to a signal-capable confirmation.
    #[test]
    fn conflicting_records_never_resolve_either_way() {
        for alive in [false, true] {
            for exe in [false, true] {
                let p = decide(
                    Record::ConflictingRecords {
                        recorded: 42,
                        sidecar: 43,
                    },
                    alive,
                    None,
                    exe,
                    || Scan::NoneFound,
                );
                assert!(
                    matches!(p, DaemonPresence::Unknown { .. }),
                    "alive={alive} exe={exe}: a record conflict with a live daemon in it \
                     must stay Unknown: {p:?}"
                );
            }
        }
    }

    /// A sidecar that exists but cannot vouch is not a missing one.
    ///
    /// With no pid file, the sidecar is the record of last resort, and
    /// the first version collapsed "present but unreadable or
    /// malformed" into "no sidecar" — `Record::Absent` — so a daemon
    /// whose pid write failed and whose sidecar hit transient trouble
    /// read as absent, survived a completed name-limited scan, and
    /// licensed `detach` (review finding, P1). Malformed lands the same
    /// whether or not the suite runs as root: as root the file is
    /// authentic and fails decode; as non-root it fails provenance.
    /// Either way it must surface as `Unknown`, never `Gone`.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unusable_sidecar_is_not_a_missing_one() {
        let dir = std::env::temp_dir().join(format!("pf-sidecar-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        let pidfile = dir.join("packetframe.pid");
        let ident = dir.join("packetframe.identity");
        std::fs::write(&ident, "not an identity at all\n").expect("write");

        let p = presence_of(&pidfile, &ident, |_| false, || Scan::NoneFound);
        assert!(
            matches!(p, DaemonPresence::Unknown { .. }),
            "a present-but-unusable sidecar, as the record of last resort, is `cannot \
             tell` — reading it as absence is what licenses detach under a live daemon: \
             {p:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A writable state directory vouches for nothing inside it.
    ///
    /// Per-file root ownership cannot say which directory a record was
    /// written FOR: `rename` moves a root-owned file between
    /// attacker-writable directories without reading or modifying it,
    /// so records replayed whole from another instance's state dir
    /// would pass every per-file check and aim root's SIGHUP at that
    /// other instance (review finding). The directory gate makes the
    /// replay unexpressible — a directory the attacker can write into
    /// is a directory whose records confirm nothing.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_writable_state_directory_vouches_for_nothing() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("pf-replay-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch");
        // Records that would be fully authentic in a root-owned dir:
        // this process's real identity, its real pid.
        let real = DaemonIdentity::current().expect("own identity");
        let pidfile = dir.join("packetframe.pid");
        let ident = dir.join("packetframe.identity");
        std::fs::write(&pidfile, format!("{}\n", real.pid)).expect("write");
        std::fs::write(&ident, real.encode()).expect("write");
        if unsafe { libc::geteuid() } == 0 {
            std::fs::set_permissions(&pidfile, std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
            std::fs::set_permissions(&ident, std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
        }
        // The directory itself is world-writable — the replay surface.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).expect("chmod");

        let p = presence_of(&pidfile, &ident, |_| true, || Scan::NoneFound);
        assert!(
            matches!(p, DaemonPresence::Unknown { .. }),
            "records in a directory others can write may have been renamed in whole from \
             another instance's state dir; they must not become signal-capable: {p:?}"
        );

        // And the swap one level up: a state dir that is ITSELF
        // impeccable — root-owned, 0755, authentic records — sitting
        // under a writable parent can be renamed away whole and another
        // instance's swapped into its name, so the ancestor chain is
        // part of what authenticates it (review finding).
        let sub = dir.join("state");
        std::fs::create_dir_all(&sub).expect("scratch");
        let sub_pid = sub.join("packetframe.pid");
        let sub_ident = sub.join("packetframe.identity");
        std::fs::write(&sub_pid, format!("{}\n", real.pid)).expect("write");
        std::fs::write(&sub_ident, real.encode()).expect("write");
        if unsafe { libc::geteuid() } == 0 {
            std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).expect("chmod");
            std::fs::set_permissions(&sub_pid, std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
            std::fs::set_permissions(&sub_ident, std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
        }
        let p = presence_of(&sub_pid, &sub_ident, |_| true, || Scan::NoneFound);
        assert!(
            matches!(p, DaemonPresence::Unknown { .. }),
            "a movable state dir is not bound to its configured path, however authentic \
             its contents: {p:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A contradicted record settles nothing in EITHER direction.
    ///
    /// Not `Gone`: a rollback to a build without the sidecar rewrites
    /// only the pid file and cannot know to remove
    /// `packetframe.identity`, so after a reboot the pids can coincide
    /// and the stale record rejects a live daemon — concluding absence
    /// there licenses `detach` to unlink pins beneath it. (The first
    /// attempt dated the files by mtime, which a coarse filesystem
    /// defeats.)
    ///
    /// And not `Running` on an executable match either, which is what
    /// it briefly did: a `packetframe run` from another bundle and
    /// another state directory passes that check, so a reused pid put
    /// `reconfigure`'s SIGHUP into an unrelated daemon (review
    /// finding). The identity said this is not the recorded process;
    /// a weaker check does not get to overrule it.
    #[test]
    fn a_contradicted_record_identifies_nothing_in_either_direction() {
        let stale = |exe| {
            decide(
                Record::Found(42, Some(id(42, 900))),
                true,
                Some((7777, "boot-after-reboot".to_string())),
                exe,
                || Scan::NoneFound,
            )
        };
        for exe in [true, false] {
            assert!(
                matches!(stale(exe), DaemonPresence::Unknown { .. }),
                "exe_matches={exe}: a mismatched identity is unknown, never absent and \
                 never confirmed: {:?}",
                stale(exe)
            );
        }
        // The distinction still reaches the operator, because it is
        // what they triage with — it just does not license an action.
        let DaemonPresence::Unknown { why } = stale(true) else {
            unreachable!()
        };
        assert!(
            why.contains("packetframe daemon"),
            "the refusal has to say a daemon holds that pid: {why}"
        );
    }

    /// A partial identity is not a legacy record.
    ///
    /// Both arrive as "a pid and no usable identity", and treating them
    /// alike put a truncated write on the legacy path, where an exe
    /// match alone accepts a reused pid (review finding).
    #[test]
    fn a_half_written_identity_is_refused_not_downgraded() {
        for partial in ["12345 998877", "12345 998877 boot extra", "12345 x y"] {
            assert!(
                DaemonIdentity::decode(partial).is_err(),
                "`{partial}` is not a record this build understands, and guessing which \
                 half to trust is how a reused pid gets accepted"
            );
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
