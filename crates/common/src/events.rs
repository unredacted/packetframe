//! The persistent event log: the daemon's operationally significant
//! transitions, one JSON object per line, in a small bounded file of its
//! own.
//!
//! ## Why a file of our own
//!
//! Everything else PacketFrame says goes to stdout and from there to the
//! journal. On the reference platform the journal is capped for the whole
//! box and another daemon fills it, so it holds a couple of hours; the
//! history of what the data plane *did* overnight — steering up and down,
//! verify results, restarts and the adoption path each one took,
//! reconfigure outcomes, health transitions — is gone by morning. Neither
//! the cap nor the other daemon can be changed durably (the vendor
//! rewrites both), so this is a log the journal's neighbours cannot
//! evict.
//!
//! ## What belongs here
//!
//! **Transitions and outcomes only**: a few events an hour in steady
//! state. Never per-packet, per-route, or periodic stats lines — the
//! journal keeps those, and a log that records them stops being one an
//! operator can read in the morning. The stable event kinds are in
//! [`kind`]; the runbook lists them with their fields.
//!
//! ## Cost and failure
//!
//! [`Event::emit`] is a `try_send` into a bounded channel: it never
//! blocks and never fails the caller. A full queue drops the event and
//! counts it, and the writer records the count ([`kind::EVENTS_DROPPED`])
//! ahead of the next event it handles. Writing happens on one thread, one
//! `write(2)` per event, no fsync per event (flash wear); the file is
//! synced once on a clean [`shutdown`]. A write that fails — disk full,
//! permissions, a symlink where the file should be — costs one warning in
//! the journal and a line in `packetframe status`; the writer backs off
//! and tries again, and says when it recovered and how many events the
//! outage cost ([`kind::EVENT_LOG_RECOVERED`]). Nothing here can block or
//! fail the data plane or a module.
//!
//! ## Bounded
//!
//! When the next line would take the file past its bound it is renamed to
//! `<path>.1` (replacing the previous one) and a fresh file is started,
//! so the log never holds more than twice the bound on disk.

use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// File name under `state-dir` when `event-log` is not configured.
pub const DEFAULT_FILE_NAME: &str = "events.log";
/// `event-log-max` default: per file, so up to twice this on disk.
pub const DEFAULT_MAX_BYTES: u64 = 10 * 1024 * 1024;
/// Floor for `event-log-max`. Below it rotation would churn through the
/// one kept file fast enough to defeat the point of keeping history.
pub const MIN_MAX_BYTES: u64 = 64 * 1024;
/// Ceiling for `event-log-max`. The log is a morning's reading, not an
/// archive, and `packetframe events` reads both files into memory.
pub const MAX_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Events queued between emitters and the writer. Steady state is a few
/// an hour; a burst is a restart or a teardown, tens of events. A queue
/// this deep only fills when the writer is stuck in a `write(2)`.
const CHANNEL_CAPACITY: usize = 1024;
/// How long the writer leaves a failing file alone before trying it
/// again. Events arriving in between are counted as lost without a
/// syscall.
const RETRY_EVERY: Duration = Duration::from_secs(30);
/// Longest string a field keeps. A message quoting a whole error chain is
/// still useful at this length; a line per event stays small.
const FIELD_MAX_CHARS: usize = 1024;
/// How long [`EventLog::flush`] and [`EventLog::shutdown`] wait for the
/// writer. Bounded because shutdown must not hang on a wedged disk.
const FLUSH_BUDGET: Duration = Duration::from_secs(2);

/// The `module` the event log's own records carry.
pub const SELF_MODULE: &str = "event-log";
/// The `module` for process-level events the loader emits.
pub const DAEMON_MODULE: &str = "daemon";

/// Stable, machine-readable event kinds. Append-only in spirit: a
/// renamed kind breaks whatever an operator greps for. Documented with
/// their fields in `docs/runbooks/event-log.md`.
pub mod kind {
    // --- process (module `daemon`) ---
    pub const PROCESS_START: &str = "process_start";
    pub const PROCESS_STOP: &str = "process_stop";
    pub const MODULE_ATTACHED: &str = "module_attached";
    pub const MODULE_START_FAILED: &str = "module_start_failed";
    pub const CIRCUIT_BREAKER_TRIPPED: &str = "circuit_breaker_tripped";
    pub const RECONFIGURE_REFUSED: &str = "reconfigure_refused";
    pub const RECONFIGURE_APPLIED: &str = "reconfigure_applied";
    pub const RECONFIGURE_FAILED: &str = "reconfigure_failed";
    pub const MODULE_HEALTH: &str = "module_health";
    pub const DETACH: &str = "detach";

    // --- vpp-offload ---
    pub const STEERING_UP: &str = "steering_up";
    pub const STEERING_DOWN: &str = "steering_down";
    pub const STEERING_RESTORED: &str = "steering_restored";
    pub const STEER_FAILED: &str = "steer_failed";
    pub const UNSTEER_FAILED: &str = "unsteer_failed";
    pub const VERIFY_PASSED: &str = "verify_passed";
    pub const VERIFY_FAILED: &str = "verify_failed";
    pub const VERIFY_INCOMPLETE: &str = "verify_incomplete";
    pub const ADOPTION_PATH: &str = "adoption_path";
    pub const PRESERVED_LEDGER_REJECTED: &str = "preserved_ledger_rejected";
    pub const LEDGER_PRESERVED: &str = "ledger_preserved";
    pub const VPP_TEARDOWN: &str = "vpp_teardown";
    pub const HANDBACK_READY: &str = "handback_ready";
    pub const HANDBACK_HELD_BACK: &str = "handback_held_back";

    // --- the event log itself (module `event-log`) ---
    pub const EVENTS_DROPPED: &str = "events_dropped";
    pub const EVENT_LOG_RECOVERED: &str = "event_log_recovered";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// One line of the log, as written and as read back.
///
/// The fixed keys come first in every line; the event's own fields follow
/// in key order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// RFC 3339, UTC, millisecond precision.
    pub ts: String,
    /// The module the event is ABOUT — a reconfigure outcome the loader
    /// records for vpp-offload carries `vpp-offload` — so filtering by
    /// module finds it. [`DAEMON_MODULE`] for process-level events.
    pub module: String,
    pub event: String,
    pub level: Level,
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

/// The keys a field may not take: flattening would emit them twice.
const RESERVED: [&str; 4] = ["ts", "module", "event", "level"];

/// An event under construction. Nothing is recorded until [`Event::emit`].
///
/// The timestamp is taken here, at the transition, not when the writer
/// gets to it.
#[derive(Debug, Clone)]
#[must_use = "an event is recorded only by .emit()"]
pub struct Event {
    at: SystemTime,
    module: String,
    kind: &'static str,
    level: Level,
    fields: Map<String, Value>,
}

impl Event {
    pub fn new(level: Level, module: &str, kind: &'static str) -> Self {
        Self {
            at: SystemTime::now(),
            module: module.to_string(),
            kind,
            level,
            fields: Map::new(),
        }
    }

    pub fn info(module: &str, kind: &'static str) -> Self {
        Self::new(Level::Info, module, kind)
    }

    pub fn warn(module: &str, kind: &'static str) -> Self {
        Self::new(Level::Warn, module, kind)
    }

    pub fn error(module: &str, kind: &'static str) -> Self {
        Self::new(Level::Error, module, kind)
    }

    /// The human sentence, the field `packetframe events` leads with.
    pub fn detail(self, text: impl AsRef<str>) -> Self {
        self.field("detail", text.as_ref())
    }

    /// A structured field. Strings are capped at a length that keeps one
    /// event one short line; a reserved key is ignored rather than
    /// allowed to corrupt the record.
    pub fn field(mut self, key: &'static str, value: impl Into<Value>) -> Self {
        if RESERVED.contains(&key) {
            debug_assert!(false, "event field `{key}` collides with a fixed key");
            return self;
        }
        let value = match value.into() {
            Value::String(s) => Value::String(truncate(s)),
            v => v,
        };
        self.fields.insert(key.to_string(), value);
        self
    }

    /// The event's kind, one of [`kind`].
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    /// Record it in the process's event log, if one is installed. Never
    /// blocks; see the module docs.
    pub fn emit(self) {
        if let Some(log) = GLOBAL.get() {
            log.emit(self);
        }
    }

    pub fn into_record(self) -> Record {
        Record {
            ts: format_rfc3339(self.at),
            module: self.module,
            event: self.kind.to_string(),
            level: self.level,
            fields: self.fields,
        }
    }
}

fn truncate(s: String) -> String {
    if s.chars().count() <= FIELD_MAX_CHARS {
        return s;
    }
    let mut t: String = s.chars().take(FIELD_MAX_CHARS).collect();
    t.push('…');
    t
}

/// What the writer has done so far, for `packetframe status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub path: PathBuf,
    pub max_bytes: u64,
    /// Events written to the file.
    pub written: u64,
    /// Events dropped because the queue was full.
    pub dropped: u64,
    /// Events the writer could not write (the file was failing).
    pub lost: u64,
    /// Why the file is failing; `None` while writes succeed.
    pub last_error: Option<String>,
}

struct Shared {
    path: PathBuf,
    max_bytes: u64,
    written: AtomicU64,
    dropped: AtomicU64,
    lost: AtomicU64,
    last_error: Mutex<Option<String>>,
}

enum Msg {
    Event(Box<Event>),
    Flush(SyncSender<()>),
    Shutdown(SyncSender<()>),
}

/// The writer's parameters. Only the path and bound are an operator's;
/// the rest exist so tests can run the real writer without waiting.
struct Options {
    path: PathBuf,
    max_bytes: u64,
    capacity: usize,
    retry_every: Duration,
}

impl Options {
    fn new(path: PathBuf, max_bytes: u64) -> Self {
        Self {
            path,
            max_bytes,
            capacity: CHANNEL_CAPACITY,
            retry_every: RETRY_EVERY,
        }
    }
}

/// A running event log: the queue and its writer thread.
pub struct EventLog {
    tx: SyncSender<Msg>,
    shared: Arc<Shared>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl EventLog {
    /// Start a writer appending to `path`, rotating at `max_bytes`.
    ///
    /// Never fails: a file that cannot be opened is the first write
    /// failure, reported the way every later one is.
    pub fn start(path: PathBuf, max_bytes: u64) -> Self {
        Self::start_with(Options::new(path, max_bytes))
    }

    fn start_with(opts: Options) -> Self {
        let retry_every = opts.retry_every;
        let (log, rx) = Self::unstarted(opts);
        log.spawn_writer(rx, retry_every);
        log
    }

    /// The queue without its writer, so a test can fill it
    /// deterministically before anything drains it.
    fn unstarted(opts: Options) -> (Self, Receiver<Msg>) {
        let (tx, rx) = mpsc::sync_channel(opts.capacity);
        let shared = Arc::new(Shared {
            path: opts.path,
            max_bytes: opts.max_bytes,
            written: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            last_error: Mutex::new(None),
        });
        (
            Self {
                tx,
                shared,
                writer: Mutex::new(None),
            },
            rx,
        )
    }

    fn spawn_writer(&self, rx: Receiver<Msg>, retry_every: Duration) {
        let shared = self.shared.clone();
        let spawned = std::thread::Builder::new()
            .name("pf-event-log".into())
            .spawn(move || Writer::new(shared, retry_every).run(rx));
        match spawned {
            Ok(h) => *lock(&self.writer) = Some(h),
            // No writer means the queue fills and every event is counted
            // as dropped — degraded, and visible in status, which is the
            // contract for every other failure here too.
            Err(e) => {
                tracing::warn!(error = %e, "could not start the event-log writer; events will not be recorded");
                *lock(&self.shared.last_error) = Some(format!("writer thread: {e}"));
            }
        }
    }

    /// Queue `event`. Never blocks: a full queue drops it and counts it.
    pub fn emit(&self, event: Event) {
        match self.tx.try_send(Msg::Event(Box::new(event))) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
            }
            // The writer is gone: after `shutdown`, or it never started.
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Wait (bounded) until everything queued before this call has been
    /// handed to the file. `false` if the writer did not answer in time.
    pub fn flush(&self) -> bool {
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        self.send_control(Msg::Flush(ack_tx), ack_rx)
    }

    /// Write out what is queued, fsync once, and stop the writer. Bounded
    /// like [`Self::flush`]; after it, [`Self::emit`] is a no-op.
    pub fn shutdown(&self) {
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        if self.send_control(Msg::Shutdown(ack_tx), ack_rx) {
            if let Some(h) = lock(&self.writer).take() {
                let _ = h.join();
            }
        }
        // Otherwise the writer is wedged in a write; it is left to the
        // process exit rather than waited on.
    }

    fn send_control(&self, mut msg: Msg, ack: Receiver<()>) -> bool {
        let deadline = Instant::now() + FLUSH_BUDGET;
        loop {
            match self.tx.try_send(msg) {
                Ok(()) => break,
                Err(TrySendError::Full(m)) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    msg = m;
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
        let left = deadline.saturating_duration_since(Instant::now());
        match ack.recv_timeout(left) {
            Ok(()) => true,
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => false,
        }
    }

    pub fn status(&self) -> Status {
        Status {
            path: self.shared.path.clone(),
            max_bytes: self.shared.max_bytes,
            written: self.shared.written.load(Ordering::Relaxed),
            dropped: self.shared.dropped.load(Ordering::Relaxed),
            lost: self.shared.lost.load(Ordering::Relaxed),
            last_error: lock(&self.shared.last_error).clone(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.shared.path
    }

    pub fn max_bytes(&self) -> u64 {
        self.shared.max_bytes
    }
}

/// Poisoning means a panic elsewhere while holding a bookkeeping lock;
/// the data is still usable, and losing the event log over it would be
/// the wrong trade.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// The writer thread's state.
struct Writer {
    shared: Arc<Shared>,
    sink: FileSink,
    /// The value of `shared.dropped` already recorded in the file.
    reported_dropped: u64,
    /// Inside a failure streak: the warning has been said, and the
    /// recovery record is owed.
    failing: bool,
    /// Events lost in the current streak.
    streak_lost: u64,
}

impl Writer {
    fn new(shared: Arc<Shared>, retry_every: Duration) -> Self {
        let sink = FileSink::new(shared.path.clone(), shared.max_bytes, retry_every);
        Self {
            shared,
            sink,
            reported_dropped: 0,
            failing: false,
            streak_lost: 0,
        }
    }

    fn run(mut self, rx: Receiver<Msg>) {
        while let Ok(msg) = rx.recv() {
            match msg {
                Msg::Event(ev) => self.handle(*ev),
                Msg::Flush(ack) => {
                    let _ = ack.try_send(());
                }
                Msg::Shutdown(ack) => {
                    self.handle_dropped();
                    self.sink.sync();
                    let _ = ack.try_send(());
                    return;
                }
            }
        }
        // Every sender dropped without a shutdown: the process is going
        // away. Sync what was written, best-effort.
        self.sink.sync();
    }

    fn handle(&mut self, ev: Event) {
        if self.failing && !self.try_recover() {
            self.count_lost();
            return;
        }
        self.handle_dropped();
        self.write(ev);
    }

    /// Record queue overflow, once per batch of drops, ahead of the next
    /// event that makes it through.
    fn handle_dropped(&mut self) {
        let dropped = self.shared.dropped.load(Ordering::Relaxed);
        if dropped > self.reported_dropped {
            let n = dropped - self.reported_dropped;
            let rec = Event::warn(SELF_MODULE, kind::EVENTS_DROPPED)
                .field("count", n)
                .detail("the event queue was full; this many events were not recorded");
            if self.write(rec) {
                self.reported_dropped = dropped;
            }
        }
    }

    /// Attempt the recovery record. `true` once the file takes writes
    /// again.
    fn try_recover(&mut self) -> bool {
        let error = lock(&self.shared.last_error).clone();
        let mut rec = Event::info(SELF_MODULE, kind::EVENT_LOG_RECOVERED)
            .field("lost", self.streak_lost)
            .detail("the event log is writable again; `lost` events were not recorded");
        if let Some(e) = error {
            rec = rec.field("error", e);
        }
        match self.sink.write_line(&line_for(rec)) {
            SinkResult::Written => {
                self.shared.written.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    path = %self.shared.path.display(),
                    lost = self.streak_lost,
                    "event log writable again"
                );
                *lock(&self.shared.last_error) = None;
                self.failing = false;
                self.streak_lost = 0;
                true
            }
            SinkResult::Failed(e) => {
                *lock(&self.shared.last_error) = Some(e.to_string());
                false
            }
            SinkResult::Skipped => false,
        }
    }

    fn write(&mut self, ev: Event) -> bool {
        match self.sink.write_line(&line_for(ev)) {
            SinkResult::Written => {
                self.shared.written.fetch_add(1, Ordering::Relaxed);
                true
            }
            SinkResult::Failed(e) => {
                if !self.failing {
                    // The one warning per streak. The journal still has
                    // the event itself; what it needs is that this file
                    // does not.
                    tracing::warn!(
                        path = %self.shared.path.display(),
                        error = %e,
                        "event log write failed; events are not recorded to it until it recovers \
                         (the journal still carries them, and `packetframe status` shows the error)"
                    );
                    self.failing = true;
                }
                *lock(&self.shared.last_error) = Some(e.to_string());
                self.count_lost();
                false
            }
            SinkResult::Skipped => {
                self.count_lost();
                false
            }
        }
    }

    fn count_lost(&mut self) {
        self.streak_lost += 1;
        self.shared.lost.fetch_add(1, Ordering::Relaxed);
    }
}

fn line_for(ev: Event) -> Vec<u8> {
    // A `Record` of strings, numbers and a JSON map cannot fail to
    // serialise; an empty line is the harmless answer if it ever did.
    let mut line = serde_json::to_vec(&ev.into_record()).unwrap_or_default();
    line.push(b'\n');
    line
}

enum SinkResult {
    Written,
    Failed(std::io::Error),
    /// Inside the backoff after a failure; nothing was attempted.
    Skipped,
}

/// The file end: open-on-demand, rotate at the bound, back off on error.
struct FileSink {
    path: PathBuf,
    max_bytes: u64,
    retry_every: Duration,
    open: Option<OpenFile>,
    size: u64,
    retry_at: Option<Instant>,
}

struct OpenFile {
    file: File,
    /// The walked parent directory, for the rotation's `renameat`.
    #[cfg(target_os = "linux")]
    dir: File,
}

impl FileSink {
    fn new(path: PathBuf, max_bytes: u64, retry_every: Duration) -> Self {
        Self {
            path,
            max_bytes,
            retry_every,
            open: None,
            size: 0,
            retry_at: None,
        }
    }

    fn write_line(&mut self, line: &[u8]) -> SinkResult {
        if self.open.is_none() && self.retry_at.is_some_and(|t| Instant::now() < t) {
            return SinkResult::Skipped;
        }
        match self.try_write(line) {
            Ok(()) => {
                self.retry_at = None;
                SinkResult::Written
            }
            Err(e) => {
                self.open = None;
                self.retry_at = Some(Instant::now() + self.retry_every);
                SinkResult::Failed(e)
            }
        }
    }

    fn try_write(&mut self, line: &[u8]) -> std::io::Result<()> {
        if self.open.is_none() {
            self.reopen()?;
        }
        if self.size > 0 && self.size + line.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        let f = self.open.as_mut().expect("opened above");
        // One write(2) for the whole line: an O_APPEND write of a small
        // buffer lands contiguously, so a concurrent writer (a `detach`
        // run while nothing else is) cannot interleave inside a line.
        f.file.write_all(line)?;
        self.size += line.len() as u64;
        Ok(())
    }

    fn reopen(&mut self) -> std::io::Result<()> {
        let open = open_append(&self.path)?;
        self.size = open.file.metadata()?.len();
        self.open = Some(open);
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        let open = self.open.take().expect("rotate needs an open file");
        rename_to_rotated(&open, &self.path)?;
        drop(open);
        self.reopen()
    }

    fn sync(&mut self) {
        if let Some(o) = &self.open {
            let _ = o.file.sync_all();
        }
    }
}

/// `<path>.1`: the one rotated file kept.
pub fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".1");
    path.with_file_name(name)
}

fn file_name(path: &Path) -> std::io::Result<&str> {
    path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))
}

/// Open for append without following a symlink anywhere in the path —
/// the daemon is root and `state-dir` may be writable by others (the
/// discipline of [`crate::statefile`]). The directory is created if
/// missing, as the state records' writers do.
#[cfg(target_os = "linux")]
fn open_append(path: &Path) -> std::io::Result<OpenFile> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = file_name(path)?;
    let dir = crate::statefile::create_and_open_dir_no_follow(parent)?;
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name"))?;
    let flags =
        libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::openat(dir.as_raw_fd(), c.as_ptr(), flags, 0o640 as libc::c_uint) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nothing
    // else.
    let file = unsafe { File::from_raw_fd(fd) };
    Ok(OpenFile { file, dir })
}

#[cfg(target_os = "linux")]
fn rename_to_rotated(open: &OpenFile, path: &Path) -> std::io::Result<()> {
    let name = file_name(path)?;
    crate::statefile::renameat_within(&open.dir, name, &format!("{name}.1"))
}

/// The portable fallback, for the macOS dev loop and its tests. No
/// daemon runs here, so the no-follow walk has nothing to protect.
#[cfg(not(target_os = "linux"))]
fn open_append(path: &Path) -> std::io::Result<OpenFile> {
    let _ = file_name(path)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;
    Ok(OpenFile { file })
}

#[cfg(not(target_os = "linux"))]
fn rename_to_rotated(_open: &OpenFile, path: &Path) -> std::io::Result<()> {
    std::fs::rename(path, rotated_path(path))
}

// --- the process's log ---

static GLOBAL: OnceLock<EventLog> = OnceLock::new();

/// Install the process's event log. Once per process; `false` (and the
/// argument dropped) if one is already installed.
pub fn install(path: PathBuf, max_bytes: u64) -> bool {
    let mut installed = false;
    GLOBAL.get_or_init(|| {
        installed = true;
        EventLog::start(path, max_bytes)
    });
    installed
}

/// The installed log, if any.
pub fn installed() -> Option<&'static EventLog> {
    GLOBAL.get()
}

/// The installed log's status, if any.
pub fn status() -> Option<Status> {
    GLOBAL.get().map(EventLog::status)
}

/// Flush, fsync, and stop the installed log's writer. Bounded; a no-op
/// when none is installed.
pub fn shutdown() {
    if let Some(log) = GLOBAL.get() {
        log.shutdown();
    }
}

// --- reading ---

/// Every parseable record in the log, oldest first: the rotated file,
/// then the current one. The second value counts lines that did not
/// parse (a line torn by a crash mid-write, or a file that is not an
/// event log). A missing file is empty, not an error.
pub fn read(path: &Path) -> std::io::Result<(Vec<Record>, usize)> {
    let mut records = Vec::new();
    let mut skipped = 0;
    for p in [rotated_path(path), path.to_path_buf()] {
        let Some(body) = read_file(&p)? else {
            continue;
        };
        for line in body.split(|b| *b == b'\n') {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            match serde_json::from_slice::<Record>(line) {
                Ok(r) => records.push(r),
                Err(_) => skipped += 1,
            }
        }
    }
    Ok((records, skipped))
}

#[cfg(target_os = "linux")]
fn read_file(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    crate::statefile::read_no_follow(path)
}

#[cfg(not(target_os = "linux"))]
fn read_file(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

// --- RFC 3339 ---

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`. A time before the epoch (a clock that has
/// not been set) prints as the epoch rather than panicking.
pub fn format_rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs() as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, day) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// Parse an RFC 3339 timestamp (`Z` or a `±HH:MM` offset, optional
/// fraction, `T` or a space between date and time) or a bare
/// `YYYY-MM-DD` (midnight UTC). `None` for anything else, or a time
/// before the epoch.
pub fn parse_rfc3339(s: &str) -> Option<SystemTime> {
    let s = s.trim();
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = s.get(from..from + len)?;
        if !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, mo, d) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let days = days_from_civil(y, mo as u32, d as u32);
    let (mut secs, mut nanos) = (days * 86_400, 0u32);
    if b.len() > 10 {
        if !(b[10] == b'T' || b[10] == b't' || b[10] == b' ') || b.len() < 19 {
            return None;
        }
        if b[13] != b':' || b[16] != b':' {
            return None;
        }
        let (h, mi, se) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
        if h > 23 || mi > 59 || se > 60 {
            return None;
        }
        secs += h * 3600 + mi * 60 + se;
        let mut i = 19;
        if b.get(i) == Some(&b'.') {
            let start = i + 1;
            i = start;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            if i == start {
                return None;
            }
            let frac = &s[start..i.min(start + 9)];
            nanos = frac.parse::<u32>().ok()? * 10u32.pow(9 - frac.len() as u32);
        }
        match b.get(i) {
            Some(b'Z' | b'z') if i + 1 == b.len() => {}
            Some(sign @ (b'+' | b'-')) if i + 6 == b.len() && b[i + 3] == b':' => {
                let (oh, om) = (num(i + 1, 2)?, num(i + 4, 2)?);
                if oh > 23 || om > 59 {
                    return None;
                }
                let off = oh * 3600 + om * 60;
                // A local time at +HH:MM is that much AHEAD of UTC.
                secs += if *sign == b'+' { -off } else { off };
            }
            _ => return None,
        }
    }
    if secs < 0 {
        return None;
    }
    Some(UNIX_EPOCH + Duration::new(secs as u64, nanos))
}

/// Days since the epoch to a proleptic Gregorian date (Hinnant's
/// `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// The inverse (Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(m);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pf-events-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn opts(path: PathBuf, max_bytes: u64) -> Options {
        Options {
            path,
            max_bytes,
            capacity: 64,
            retry_every: Duration::from_millis(0),
        }
    }

    fn lines(path: &Path) -> Vec<Record> {
        read(path).unwrap().0
    }

    #[test]
    fn record_serialises_fixed_keys_first_then_fields() {
        let ev = Event::warn("vpp-offload", kind::STEERING_DOWN)
            .detail("traffic returned to the eBPF tier")
            .field("ports", 4u64)
            .field("cause", "teardown");
        let at = ev.at;
        let json = String::from_utf8(line_for(ev)).unwrap();
        assert!(
            json.ends_with('\n') && json.matches('\n').count() == 1,
            "{json}"
        );
        let prefix = format!(
            "{{\"ts\":\"{}\",\"module\":\"vpp-offload\",\"event\":\"steering_down\",\"level\":\"warn\",",
            format_rfc3339(at)
        );
        assert!(json.starts_with(&prefix), "{json}");
        let back: Record = serde_json::from_str(json.trim_end()).unwrap();
        assert_eq!(back.fields["ports"], 4);
        assert_eq!(back.fields["cause"], "teardown");
        assert_eq!(back.fields["detail"], "traffic returned to the eBPF tier");
        assert_eq!(back.level, Level::Warn);
    }

    #[test]
    fn long_strings_are_capped_and_newlines_stay_escaped() {
        let ev = Event::info("daemon", kind::RECONFIGURE_FAILED).detail("x\n".repeat(4000));
        let json = String::from_utf8(line_for(ev)).unwrap();
        assert_eq!(json.matches('\n').count(), 1, "one event is one line");
        let back: Record = serde_json::from_str(json.trim_end()).unwrap();
        let detail = back.fields["detail"].as_str().unwrap();
        assert_eq!(detail.chars().count(), FIELD_MAX_CHARS + 1);
        assert!(detail.ends_with('…'));
    }

    #[test]
    fn rfc3339_round_trips_and_knows_its_calendar() {
        assert_eq!(format_rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        // 2024 is a leap year: Feb 29 exists, and the day after is Mar 1.
        let leap = parse_rfc3339("2024-02-29T23:59:59.250Z").unwrap();
        assert_eq!(format_rfc3339(leap), "2024-02-29T23:59:59.250Z");
        assert_eq!(
            format_rfc3339(leap + Duration::from_secs(1)),
            "2024-03-01T00:00:00.250Z"
        );
        for s in [
            "2000-01-01T00:00:00.000Z",
            "2026-09-27T12:34:56.789Z",
            "2100-12-31T23:59:59.999Z",
        ] {
            assert_eq!(format_rfc3339(parse_rfc3339(s).unwrap()), s);
        }
        // Offsets, spaces, bare dates, no fraction.
        assert_eq!(
            parse_rfc3339("2026-09-27T14:34:56+02:00"),
            parse_rfc3339("2026-09-27T12:34:56Z")
        );
        assert_eq!(
            parse_rfc3339("2026-09-27 07:04:56-05:30"),
            parse_rfc3339("2026-09-27T12:34:56Z")
        );
        assert_eq!(
            parse_rfc3339("2026-09-27"),
            parse_rfc3339("2026-09-27T00:00:00Z")
        );
        for bad in [
            "",
            "yesterday",
            "2026-13-01",
            "2026-09-27T25:00:00Z",
            "2026-09-27T12:34:56",
            "2026-09-27T12:34:56.Z",
            "1969-12-31T23:59:59Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }

    #[test]
    fn events_reach_the_file_in_order() {
        let dir = tmpdir("order");
        let path = dir.join("events.log");
        let log = EventLog::start_with(opts(path.clone(), DEFAULT_MAX_BYTES));
        for i in 0..10u64 {
            log.emit(Event::info("daemon", kind::MODULE_ATTACHED).field("i", i));
        }
        assert!(log.flush());
        let got = lines(&path);
        assert_eq!(got.len(), 10);
        for (i, r) in got.iter().enumerate() {
            assert_eq!(r.fields["i"], i as u64);
        }
        assert_eq!(log.status().written, 10);
        log.shutdown();
        // After shutdown, emit is a harmless no-op.
        log.emit(Event::info("daemon", kind::PROCESS_STOP));
        assert_eq!(lines(&path).len(), 10);
    }

    #[test]
    fn rotation_keeps_both_files_under_the_bound() {
        let dir = tmpdir("rotate");
        let path = dir.join("events.log");
        let max = 2048;
        // Deep enough that the burst below is never dropped.
        let log = EventLog::start_with(Options {
            capacity: 1024,
            ..opts(path.clone(), max)
        });
        let n = 200u64;
        for i in 0..n {
            log.emit(
                Event::info("vpp-offload", kind::VERIFY_PASSED)
                    .field("i", i)
                    .detail("sampled routes agree with the route source"),
            );
        }
        assert!(log.flush());
        let cur = std::fs::metadata(&path).unwrap().len();
        let old = std::fs::metadata(rotated_path(&path)).unwrap().len();
        assert!(cur <= max, "current {cur} > {max}");
        assert!(old <= max, "rotated {old} > {max}");
        assert!(old > max / 2, "rotated file was cut short: {old}");
        // Only one rotated copy is kept, and what survives is the NEWEST
        // events, contiguous and in order.
        assert!(!dir.join("events.log.2").exists());
        let got = lines(&path);
        assert!(!got.is_empty() && got.len() < n as usize);
        let last = got.last().unwrap().fields["i"].as_u64().unwrap();
        assert_eq!(last, n - 1);
        for w in got.windows(2) {
            assert_eq!(
                w[0].fields["i"].as_u64().unwrap() + 1,
                w[1].fields["i"].as_u64().unwrap()
            );
        }
        assert_eq!(log.status().written, n);
        log.shutdown();
    }

    #[test]
    fn rotation_resumes_from_an_existing_file_size() {
        let dir = tmpdir("resume");
        let path = dir.join("events.log");
        std::fs::write(&path, vec![b'x'; 1000]).unwrap();
        let log = EventLog::start_with(opts(path.clone(), 1024));
        log.emit(Event::info("daemon", kind::PROCESS_START).detail("a line that does not fit"));
        assert!(log.flush());
        // The pre-existing 1000 bytes were counted: this line would have
        // crossed the bound, so the old contents rotated out first.
        assert_eq!(std::fs::metadata(rotated_path(&path)).unwrap().len(), 1000);
        assert_eq!(lines(&path).len(), 1);
        log.shutdown();
    }

    /// A path that cannot be opened — its parent is a regular file —
    /// must cost nothing but the bookkeeping: emit returns immediately,
    /// nothing panics, and the status says why.
    #[test]
    fn write_failure_is_isolated_and_reported() {
        let dir = tmpdir("fail");
        let blocker = dir.join("not-a-dir");
        std::fs::write(&blocker, b"").unwrap();
        let path = blocker.join("events.log");
        let log = EventLog::start_with(opts(path.clone(), DEFAULT_MAX_BYTES));
        let started = Instant::now();
        for _ in 0..50 {
            log.emit(Event::info("daemon", kind::MODULE_ATTACHED));
        }
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "emit must never wait on the file"
        );
        assert!(log.flush());
        let st = log.status();
        assert_eq!(st.written, 0);
        assert_eq!(st.lost, 50);
        assert!(st.last_error.is_some(), "{st:?}");
        log.shutdown();
    }

    #[test]
    fn a_recovered_file_says_what_the_outage_cost() {
        let dir = tmpdir("recover");
        let blocker = dir.join("sub");
        std::fs::write(&blocker, b"").unwrap();
        let path = blocker.join("events.log");
        let log = EventLog::start_with(opts(path.clone(), DEFAULT_MAX_BYTES));
        for _ in 0..3 {
            log.emit(Event::info("daemon", kind::MODULE_ATTACHED));
        }
        assert!(log.flush());
        assert_eq!(log.status().lost, 3);

        // The cause goes away.
        std::fs::remove_file(&blocker).unwrap();
        std::fs::create_dir_all(&blocker).unwrap();
        log.emit(Event::info("daemon", kind::PROCESS_STOP));
        assert!(log.flush());

        let got = lines(&path);
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0].event, kind::EVENT_LOG_RECOVERED);
        assert_eq!(got[0].fields["lost"], 3);
        assert_eq!(got[1].event, kind::PROCESS_STOP);
        let st = log.status();
        assert_eq!(st.last_error, None);
        assert_eq!(st.written, 2);
        log.shutdown();
    }

    /// ENOSPC, the failure the appliance actually has.
    #[cfg(target_os = "linux")]
    #[test]
    fn disk_full_does_not_block_or_panic() {
        let log = EventLog::start_with(opts(PathBuf::from("/dev/full"), DEFAULT_MAX_BYTES));
        for _ in 0..5 {
            log.emit(Event::info("daemon", kind::MODULE_ATTACHED));
        }
        assert!(log.flush());
        let st = log.status();
        assert_eq!(st.written, 0);
        assert_eq!(st.lost, 5);
        assert!(st.last_error.is_some());
        log.shutdown();
    }

    #[test]
    fn overflow_drops_counts_and_records_the_count() {
        let dir = tmpdir("overflow");
        let path = dir.join("events.log");
        let o = opts(path.clone(), DEFAULT_MAX_BYTES);
        let (cap, retry) = (o.capacity, o.retry_every);
        // No writer yet: the queue fills and nothing drains it.
        let (log, rx) = EventLog::unstarted(o);
        let started = Instant::now();
        for i in 0..(cap + 5) {
            log.emit(Event::info("daemon", kind::MODULE_HEALTH).field("i", i as u64));
        }
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "a full queue must not block"
        );
        assert_eq!(log.status().dropped, 5);

        log.spawn_writer(rx, retry);
        // Drain the full queue before emitting again, or this event is
        // itself a drop.
        assert!(log.flush());
        log.emit(Event::info("daemon", kind::PROCESS_STOP));
        assert!(log.flush());
        let got = lines(&path);
        // The drop count, recorded ahead of the next event the writer
        // handles, then every event that made it into the queue.
        assert_eq!(got.len(), cap + 2, "{}", got.len());
        assert_eq!(got[0].event, kind::EVENTS_DROPPED);
        assert_eq!(got[0].module, SELF_MODULE);
        assert_eq!(got[0].fields["count"], 5);
        assert_eq!(got[1].fields["i"], 0);
        assert_eq!(got[cap + 1].event, kind::PROCESS_STOP);
        // Recorded once, not again with every later event.
        log.emit(Event::info("daemon", kind::PROCESS_START));
        assert!(log.flush());
        assert_eq!(lines(&path).len(), cap + 3);
        log.shutdown();
    }

    #[test]
    fn read_merges_rotated_then_current_and_skips_torn_lines() {
        let dir = tmpdir("read");
        let path = dir.join("events.log");
        let a = String::from_utf8(line_for(Event::info("daemon", kind::PROCESS_START))).unwrap();
        let b = String::from_utf8(line_for(Event::info("daemon", kind::PROCESS_STOP))).unwrap();
        std::fs::write(rotated_path(&path), &a).unwrap();
        std::fs::write(&path, format!("{b}{{\"ts\":\"torn\n\n")).unwrap();
        let (got, skipped) = read(&path).unwrap();
        assert_eq!(skipped, 1);
        assert_eq!(
            got.iter().map(|r| r.event.as_str()).collect::<Vec<_>>(),
            [kind::PROCESS_START, kind::PROCESS_STOP]
        );
        // Neither file existing is an empty log.
        assert_eq!(read(&dir.join("nothing")).unwrap().0.len(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_symlink_at_the_log_path_is_refused_not_followed() {
        let dir = tmpdir("symlink");
        let target = dir.join("victim");
        std::fs::write(&target, b"precious\n").unwrap();
        let path = dir.join("events.log");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let log = EventLog::start_with(opts(path, DEFAULT_MAX_BYTES));
        log.emit(Event::info("daemon", kind::PROCESS_START));
        assert!(log.flush());
        assert_eq!(std::fs::read(&target).unwrap(), b"precious\n");
        assert!(log.status().last_error.is_some());
        log.shutdown();
    }
}
