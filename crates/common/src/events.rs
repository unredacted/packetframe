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
//! so the log never holds more than twice the bound on disk. Whenever the
//! writer opens the file — at start, after a rotation, on recovery — a
//! generation already over the bound (left by a larger `event-log-max`)
//! is trimmed to its newest whole lines within it, and a line torn by a
//! failed write is truncated away, so the next record starts on a line
//! of its own.

use std::fs::File;
use std::io::{BufRead, BufReader, Seek as _, SeekFrom, Write as _};
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
/// Floor on the failing writer's wake-up, so a zero retry interval (the
/// tests') cannot spin.
const MIN_RETRY_POLL: Duration = Duration::from_millis(10);
/// Longest line the reader will buffer. Records are far smaller (every
/// string field is capped); a longer line is not one of ours, and is
/// skipped without being held in memory.
const READ_LINE_MAX: usize = 64 * 1024;
/// How many times the reader re-opens the pair of files when a rotation
/// lands between its two opens.
const READ_OPEN_ATTEMPTS: usize = 5;
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
    /// The set of named unresolvable routes changed (rate-limited at the
    /// source); `detail` "none" once it empties.
    pub const UNRESOLVABLE_ROUTES: &str = "unresolvable_routes";
    /// A port's driver declined an RSS-action keep rule, so its keeps
    /// deliver to PF queue 0 (`port`, `detail` the driver's answer). Once
    /// per port per process.
    pub const KEEP_QUEUE0_FALLBACK: &str = "keep_queue0_fallback";
    /// A steered port's kernel path started or stopped dropping frames
    /// (`port`, `drops_per_second`, `queue0_share`, `dropping`).
    /// Rate-limited at the source.
    pub const KERNEL_PATH_DROPPING: &str = "kernel_path_dropping";

    // --- fast-path ---
    /// `wan-egress` put back policy rules that had disappeared from the
    /// kernel under an unchanged config. Rate-limited at the source.
    pub const WAN_EGRESS_REPAIRED: &str = "wan_egress_repaired";
    /// A clean stop preserved (or failed to preserve) the route mirror
    /// as the fast-path route ledger.
    pub const ROUTE_LEDGER_PRESERVED: &str = "route_ledger_preserved";
    /// A start seeded the route mirror from the route ledger.
    pub const ROUTE_LEDGER_SEEDED: &str = "route_ledger_seeded";
    /// A start found no usable route ledger; `reason` says why
    /// (`missing` included), and the mirror loads cold.
    pub const ROUTE_LEDGER_REFUSED: &str = "route_ledger_refused";
    /// The route source's first completed initial dump after a seed
    /// garbage-collected what it did not re-advertise.
    pub const ROUTE_LEDGER_RECONCILED: &str = "route_ledger_reconciled";

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
        loop {
            // While failing, wake on the retry schedule even with nothing
            // to write: recovery is probed when the backoff says, not
            // when the next event happens to arrive — which in steady
            // state can be hours, all of it reported as failing.
            let msg = if self.failing {
                match rx.recv_timeout(self.sink.retry_every.max(MIN_RETRY_POLL)) {
                    Ok(m) => m,
                    Err(RecvTimeoutError::Timeout) => {
                        if self.try_recover() {
                            self.handle_dropped();
                        }
                        continue;
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            } else {
                match rx.recv() {
                    Ok(m) => m,
                    Err(_) => break,
                }
            };
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
    /// The parent directory, for the rotation's rename.
    dir: LogDir,
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
        // A write that fails part-way leaves a fragment; the reopen that
        // follows truncates it (`repair_tail`).
        f.file.write_all(line)?;
        self.size += line.len() as u64;
        Ok(())
    }

    /// Open the current file for append, first bringing both
    /// generations within the bound and the current file's end to a
    /// line boundary.
    fn reopen(&mut self) -> std::io::Result<()> {
        let name = file_name(&self.path)?;
        let dir = LogDir::open(parent_of(&self.path), true)?;
        trim_to_newest(&dir, &rotated_name(name), self.max_bytes)?;
        trim_to_newest(&dir, name, self.max_bytes)?;
        let file = dir.open_append(name)?;
        let len = file.metadata()?.len();
        self.size = repair_tail(&file, len)?;
        self.open = Some(OpenFile { file, dir });
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        let open = self.open.take().expect("rotate needs an open file");
        let name = file_name(&self.path)?;
        open.dir.rename(name, &rotated_name(name))?;
        drop(open);
        self.reopen()
    }

    fn sync(&mut self) {
        if let Some(o) = &self.open {
            let _ = o.file.sync_all();
        }
    }
}

/// Rewrite `name` to its newest whole lines within `max` bytes, if it is
/// larger — what a generation written under a larger `event-log-max`
/// needs, or it would sit over the new bound until it rotated out.
/// The newest lines are kept because they are the ones an operator reads
/// the log for; the older ones were already past the bound's promise.
/// Streamed through a temp file and renamed over the original, so memory
/// stays bounded and a crash mid-trim leaves the old file intact.
fn trim_to_newest(dir: &LogDir, name: &str, max: u64) -> std::io::Result<()> {
    let Some(mut f) = dir.open_read(name)? else {
        return Ok(());
    };
    let size = f.metadata()?.len();
    if size <= max {
        return Ok(());
    }
    // From one byte before the cut, discarding through the first
    // newline: a line that starts exactly at the cut is kept, a line
    // the cut splits is dropped whole.
    f.seek(SeekFrom::Start(size - max - 1))?;
    let mut r = BufReader::new(f);
    skip_through_newline(&mut r)?;
    let tmp = format!("{name}.tmp");
    {
        let mut out = dir.create_tmp(&tmp)?;
        std::io::copy(&mut r, &mut out)?;
        out.sync_all()?;
    }
    dir.rename(&tmp, name)
}

/// Consume up to and including the next `\n` (or to EOF).
fn skip_through_newline(r: &mut impl BufRead) -> std::io::Result<()> {
    loop {
        let (used, found) = {
            let buf = r.fill_buf()?;
            if buf.is_empty() {
                return Ok(());
            }
            match buf.iter().position(|b| *b == b'\n') {
                Some(i) => (i + 1, true),
                None => (buf.len(), false),
            }
        };
        r.consume(used);
        if found {
            return Ok(());
        }
    }
}

/// If the file does not end in `\n`, truncate it back to the last one
/// (or to empty) and return the new length.
///
/// A write that fails part-way — ENOSPC mid-line — leaves a fragment,
/// and appending the next record to it would weld the two into one line
/// that parses as neither. Truncating rather than writing a newline
/// after it keeps the file all whole records: the fragment was an event
/// already counted as lost.
fn repair_tail(file: &File, len: u64) -> std::io::Result<u64> {
    const CHUNK: u64 = 4096;
    let mut end = len;
    let mut buf = vec![0u8; CHUNK as usize];
    while end > 0 {
        let start = end.saturating_sub(CHUNK);
        let chunk = &mut buf[..(end - start) as usize];
        read_exact_at(file, chunk, start)?;
        if end == len && chunk.last() == Some(&b'\n') {
            return Ok(len);
        }
        if let Some(i) = chunk.iter().rposition(|b| *b == b'\n') {
            let keep = start + i as u64 + 1;
            file.set_len(keep)?;
            return Ok(keep);
        }
        end = start;
    }
    if len > 0 {
        file.set_len(0)?;
    }
    Ok(0)
}

#[cfg(unix)]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::read_exact_at(file, buf, offset)
}

#[cfg(not(unix))]
fn read_exact_at(file: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
    use std::io::Read as _;
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(buf)
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

fn rotated_name(name: &str) -> String {
    format!("{name}.1")
}

fn file_name(path: &Path) -> std::io::Result<&str> {
    path.file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))
}

fn parent_of(path: &Path) -> &Path {
    path.parent().unwrap_or_else(|| Path::new("/"))
}

/// The log's directory, and every file operation the log does in it.
///
/// On Linux, a descriptor from [`crate::statefile::open_dir_trusted_links`],
/// with every open relative to it and `O_NOFOLLOW` on the final
/// component: the daemon is root and `state-dir` may be writable by
/// others, so a symlink in the path is refused unless only root could
/// have made it (an appliance's persistent-storage link), and a symlink
/// at the file itself — or at `.1` / `.tmp` — is never followed.
/// Elsewhere (the macOS dev loop, where no daemon runs) plain paths.
struct LogDir {
    #[cfg(target_os = "linux")]
    fd: File,
    #[cfg(not(target_os = "linux"))]
    path: PathBuf,
}

#[cfg(target_os = "linux")]
impl LogDir {
    fn open(path: &Path, create: bool) -> std::io::Result<Self> {
        let fd = crate::statefile::open_dir_trusted_links(path, create, "event-log")?;
        Ok(Self { fd })
    }

    fn openat(&self, name: &str, flags: libc::c_int) -> std::io::Result<File> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let c = std::ffi::CString::new(name).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in file name")
        })?;
        let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe {
            libc::openat(
                self.fd.as_raw_fd(),
                c.as_ptr(),
                flags,
                0o640 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by openat and is owned by
        // nothing else.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Read-write so [`repair_tail`] can read the end it truncates.
    fn open_append(&self, name: &str) -> std::io::Result<File> {
        self.openat(name, libc::O_RDWR | libc::O_APPEND | libc::O_CREAT)
    }

    fn open_read(&self, name: &str) -> std::io::Result<Option<File>> {
        match self.openat(name, libc::O_RDONLY) {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn create_tmp(&self, name: &str) -> std::io::Result<File> {
        crate::statefile::openat_excl_with_retry(&self.fd, name)
    }

    fn rename(&self, from: &str, to: &str) -> std::io::Result<()> {
        crate::statefile::renameat_within(&self.fd, from, to)
    }
}

#[cfg(not(target_os = "linux"))]
impl LogDir {
    fn open(path: &Path, create: bool) -> std::io::Result<Self> {
        if create {
            std::fs::create_dir_all(path)?;
        } else if !path.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no such directory",
            ));
        }
        Ok(Self {
            path: path.to_path_buf(),
        })
    }

    fn open_append(&self, name: &str) -> std::io::Result<File> {
        std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(self.path.join(name))
    }

    fn open_read(&self, name: &str) -> std::io::Result<Option<File>> {
        match File::open(self.path.join(name)) {
            Ok(f) => Ok(Some(f)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn create_tmp(&self, name: &str) -> std::io::Result<File> {
        let p = self.path.join(name);
        let _ = std::fs::remove_file(&p);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(p)
    }

    fn rename(&self, from: &str, to: &str) -> std::io::Result<()> {
        std::fs::rename(self.path.join(from), self.path.join(to))
    }
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

/// Stream every parseable record in the log to `on`, oldest first: the
/// rotated file, then the current one. Returns how many lines did not
/// parse (a line torn by a crash, one longer than any record, or a file
/// that is not an event log). A missing file is empty, not an error.
///
/// Memory is bounded by one line whatever the files' sizes: nothing is
/// collected, so a caller that prints as it goes holds one record.
///
/// The two generations are opened before either is read, and the pair
/// is accepted only if the rotated file is still the one opened after
/// the current one is — otherwise a rotation landed between the opens,
/// the pair would skip a whole generation (old `.1` plus a fresh current,
/// missing the file that became `.1`), and the opens are retried. A
/// rotation after that is harmless: the open descriptors keep reading
/// the files they named.
pub fn read_each(path: &Path, on: impl FnMut(Record)) -> std::io::Result<usize> {
    read_each_with(path, &mut || {}, on)
}

/// [`read_each`], with a hook between opening the rotated file and the
/// current one — where a rotation is a race — so the test can put one
/// there.
fn read_each_with(
    path: &Path,
    between_opens: &mut dyn FnMut(),
    mut on: impl FnMut(Record),
) -> std::io::Result<usize> {
    let mut skipped = 0;
    for file in open_generations(path, between_opens)?.into_iter().flatten() {
        for_each_line(BufReader::new(file), |line| match line {
            Some(l) if l.iter().all(u8::is_ascii_whitespace) => {}
            Some(l) => match serde_json::from_slice::<Record>(l) {
                Ok(r) => on(r),
                Err(_) => skipped += 1,
            },
            None => skipped += 1,
        })?;
    }
    Ok(skipped)
}

/// `[rotated, current]`, opened as a consistent pair; see [`read_each`].
fn open_generations(
    path: &Path,
    between_opens: &mut dyn FnMut(),
) -> std::io::Result<[Option<File>; 2]> {
    let name = file_name(path)?;
    let rotated = rotated_name(name);
    for _ in 0..READ_OPEN_ATTEMPTS {
        let dir = match LogDir::open(parent_of(path), false) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok([None, None]),
            Err(e) => return Err(e),
        };
        let old = dir.open_read(&rotated)?;
        between_opens();
        let current = dir.open_read(name)?;
        let again = dir.open_read(&rotated)?;
        if identity(old.as_ref())? == identity(again.as_ref())? {
            return Ok([old, current]);
        }
    }
    Err(std::io::Error::other(
        "the event log kept rotating while it was being opened; try again",
    ))
}

/// What names a file across renames: device and inode.
#[cfg(unix)]
fn identity(f: Option<&File>) -> std::io::Result<Option<(u64, u64)>> {
    use std::os::unix::fs::MetadataExt;
    f.map(|f| f.metadata().map(|m| (m.dev(), m.ino())))
        .transpose()
}

#[cfg(not(unix))]
fn identity(f: Option<&File>) -> std::io::Result<Option<(u64, u64)>> {
    Ok(f.map(|_| (0, 0)))
}

/// Call `on` once per line, without the newline: `Some(line)`, or `None`
/// for a line longer than [`READ_LINE_MAX`], which is skipped without
/// being buffered. A final line without a newline is still a line.
fn for_each_line(mut r: impl BufRead, mut on: impl FnMut(Option<&[u8]>)) -> std::io::Result<()> {
    let mut line = Vec::new();
    let mut overlong = false;
    loop {
        let (used, ended) = {
            let buf = r.fill_buf()?;
            if buf.is_empty() {
                if overlong {
                    on(None);
                } else if !line.is_empty() {
                    on(Some(&line));
                }
                return Ok(());
            }
            let (part, used, ended) = match buf.iter().position(|b| *b == b'\n') {
                Some(i) => (&buf[..i], i + 1, true),
                None => (buf, buf.len(), false),
            };
            if !overlong {
                if line.len() + part.len() > READ_LINE_MAX {
                    overlong = true;
                    line.clear();
                } else {
                    line.extend_from_slice(part);
                }
            }
            (used, ended)
        };
        r.consume(used);
        if ended {
            if overlong {
                on(None);
            } else {
                on(Some(&line));
            }
            line.clear();
            overlong = false;
        }
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
    if !(1..=12).contains(&mo) || d < 1 || d > days_in_month(y, mo as u32) {
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

/// Feb 29 exists only in leap years, and the 31st only in the long
/// months: a date that is not in the calendar is refused, not rolled over
/// into the next month.
fn days_in_month(y: i64, m: u32) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
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

    fn read_all(path: &Path) -> (Vec<Record>, usize) {
        let mut v = Vec::new();
        let skipped = read_each(path, |r| v.push(r)).unwrap();
        (v, skipped)
    }

    fn lines(path: &Path) -> Vec<Record> {
        read_all(path).0
    }

    fn line(ev: Event) -> String {
        String::from_utf8(line_for(ev)).unwrap()
    }

    /// Poll `cond` for up to two seconds.
    fn eventually(mut cond: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        cond()
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
        // Leap years by the Gregorian rule.
        assert!(parse_rfc3339("2000-02-29").is_some());
        assert!(parse_rfc3339("2024-02-29").is_some());
        for bad in [
            "2026-02-29",
            "1900-02-29",
            "2100-02-29",
            "2026-02-31",
            "2026-04-31",
            "2026-06-31",
            "2026-09-31",
            "2026-11-31",
            "2026-01-00",
            "2026-01-32",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
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
        // Ten whole 100-byte lines: a tail without a newline would be
        // truncated as a torn write before the size is taken.
        std::fs::write(&path, format!("{}\n", "x".repeat(99)).repeat(10)).unwrap();
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
        let (got, skipped) = read_all(&path);
        assert_eq!(skipped, 1);
        assert_eq!(
            got.iter().map(|r| r.event.as_str()).collect::<Vec<_>>(),
            [kind::PROCESS_START, kind::PROCESS_STOP]
        );
        // Neither file existing is an empty log, and so is a missing
        // directory.
        assert_eq!(read_all(&dir.join("nothing")).0.len(), 0);
        assert_eq!(read_all(&dir.join("no-dir").join("events.log")).0.len(), 0);
    }

    /// A rotation between the two opens would pair the OLD `.1` with a
    /// fresh current file and skip the generation that became `.1`. The
    /// hook rotates exactly there, once; the reader must notice and
    /// re-open.
    #[test]
    fn a_rotation_between_the_opens_is_retried_not_skipped() {
        let dir = tmpdir("read-race");
        let path = dir.join("events.log");
        let a = line(Event::info("daemon", kind::PROCESS_START).field("gen", "a"));
        let b = line(Event::info("daemon", kind::PROCESS_START).field("gen", "b"));
        let c = line(Event::info("daemon", kind::PROCESS_START).field("gen", "c"));
        std::fs::write(rotated_path(&path), &a).unwrap();
        std::fs::write(&path, &b).unwrap();
        let mut rotated = false;
        let mut got = Vec::new();
        let skipped = read_each_with(
            &path,
            &mut || {
                if !rotated {
                    rotated = true;
                    std::fs::rename(&path, rotated_path(&path)).unwrap();
                    std::fs::write(&path, &c).unwrap();
                }
            },
            |r| got.push(r.fields["gen"].as_str().unwrap().to_string()),
        )
        .unwrap();
        assert!(rotated);
        assert_eq!(skipped, 0);
        // `a` rotated out for real; `b` must not be skipped.
        assert_eq!(got, ["b", "c"]);
    }

    /// Streaming: records arrive oldest first, one at a time, and a line
    /// longer than any record is skipped and counted, not buffered.
    #[test]
    fn reading_streams_and_skips_overlong_lines() {
        let dir = tmpdir("read-stream");
        let path = dir.join("events.log");
        let first = line(Event::info("daemon", kind::PROCESS_START));
        let last = line(Event::info("daemon", kind::PROCESS_STOP));
        let huge = "x".repeat(READ_LINE_MAX + 10);
        std::fs::write(&path, format!("{first}{huge}\n{last}")).unwrap();
        let mut seen = Vec::new();
        let skipped = read_each(&path, |r| seen.push(r.event)).unwrap();
        assert_eq!(skipped, 1);
        assert_eq!(seen, [kind::PROCESS_START, kind::PROCESS_STOP]);
        // The line splitter itself: a final line without a newline counts,
        // and an overlong one at EOF is reported as skipped.
        let mut out = Vec::new();
        for_each_line(&b"a\n\nbb"[..], |l| out.push(l.map(<[u8]>::to_vec))).unwrap();
        assert_eq!(
            out,
            [Some(b"a".to_vec()), Some(vec![]), Some(b"bb".to_vec())]
        );
        let tail = vec![b'y'; READ_LINE_MAX + 1];
        let mut out = Vec::new();
        for_each_line(&tail[..], |l| out.push(l.is_none())).unwrap();
        assert_eq!(out, [true]);
    }

    /// A write that failed part-way left a fragment with no newline. The
    /// next record must start on its own line, not be welded to it.
    #[test]
    fn a_torn_tail_is_truncated_before_the_next_record() {
        let dir = tmpdir("torn");
        let path = dir.join("events.log");
        let whole = line(Event::info("daemon", kind::PROCESS_START));
        std::fs::write(&path, format!("{whole}{{\"ts\":\"2026-09-27T0")).unwrap();
        let log = EventLog::start_with(opts(path.clone(), DEFAULT_MAX_BYTES));
        log.emit(Event::info("daemon", kind::PROCESS_STOP));
        assert!(log.flush());
        let (got, skipped) = read_all(&path);
        assert_eq!(skipped, 0, "the fragment must be gone, not welded");
        assert_eq!(
            got.iter().map(|r| r.event.as_str()).collect::<Vec<_>>(),
            [kind::PROCESS_START, kind::PROCESS_STOP]
        );
        log.shutdown();

        // A file that is ALL fragment is emptied.
        let path2 = dir.join("only-fragment.log");
        std::fs::write(&path2, "{\"ts\":").unwrap();
        let log = EventLog::start_with(opts(path2.clone(), DEFAULT_MAX_BYTES));
        log.emit(Event::info("daemon", kind::PROCESS_STOP));
        assert!(log.flush());
        assert_eq!(read_all(&path2), (lines(&path2), 0));
        assert_eq!(lines(&path2).len(), 1);
        log.shutdown();
    }

    /// Generations left over-size by a larger `event-log-max` are trimmed
    /// to their newest whole lines on open, not carried for months.
    #[test]
    fn oversized_generations_are_trimmed_to_their_newest_lines() {
        let dir = tmpdir("trim");
        let path = dir.join("events.log");
        let max = 2048u64;
        let body = |gen: &str| {
            (0..100u64)
                .map(|i| {
                    line(
                        Event::info("daemon", kind::MODULE_HEALTH)
                            .field("gen", gen)
                            .field("i", i),
                    )
                })
                .collect::<String>()
        };
        std::fs::write(rotated_path(&path), body("old")).unwrap();
        std::fs::write(&path, body("cur")).unwrap();
        assert!(std::fs::metadata(&path).unwrap().len() > 4 * max);

        let log = EventLog::start_with(opts(path.clone(), max));
        log.emit(Event::info("daemon", kind::PROCESS_START));
        assert!(log.flush());
        log.shutdown();
        for p in [path.clone(), rotated_path(&path)] {
            let len = std::fs::metadata(&p).unwrap().len();
            assert!(len <= max, "{} is {len} > {max}", p.display());
        }
        let (got, skipped) = read_all(&path);
        assert_eq!(skipped, 0, "trimming keeps whole lines only");
        // The newest line of the old current file survived the trim.
        assert!(got
            .iter()
            .any(|r| r.fields.get("gen") == Some(&"cur".into()) && r.fields["i"] == 99));
        assert!(!got.iter().any(|r| r.fields.get("i") == Some(&0.into())));
        assert_eq!(got.last().unwrap().event, kind::PROCESS_START);
        assert!(!dir.join("events.log.tmp").exists());
    }

    /// With nothing to write, a failing writer still probes on its
    /// retry schedule and records its recovery.
    #[test]
    fn recovery_is_probed_on_schedule_without_new_events() {
        let dir = tmpdir("timed-recover");
        let blocker = dir.join("sub");
        std::fs::write(&blocker, b"").unwrap();
        let path = blocker.join("events.log");
        let log = EventLog::start_with(opts(path.clone(), DEFAULT_MAX_BYTES));
        log.emit(Event::info("daemon", kind::MODULE_ATTACHED));
        assert!(log.flush());
        assert!(log.status().last_error.is_some());

        std::fs::remove_file(&blocker).unwrap();
        std::fs::create_dir_all(&blocker).unwrap();
        // No emit: only the timer can notice.
        assert!(
            eventually(|| log.status().last_error.is_none()),
            "{:?}",
            log.status()
        );
        let got = lines(&path);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].event, kind::EVENT_LOG_RECOVERED);
        assert_eq!(got[0].fields["lost"], 1);
        log.shutdown();
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

    /// `dir/persist -> dir/real`, in a directory group and others cannot
    /// write: the shape of an appliance's persistent-storage link.
    #[cfg(target_os = "linux")]
    fn persist_link(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tmpdir(tag);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let real = dir.join("real");
        std::fs::create_dir(&real).unwrap();
        let persist = dir.join("persist");
        std::os::unix::fs::symlink(&real, &persist).unwrap();
        (dir, real, persist)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_log_under_a_trusted_symlinked_directory_writes_rotates_and_reads() {
        let (_dir, real, persist) = persist_link("trusted-link");
        let path = persist.join("packetframe/events.log");
        let max = 2048;
        let log = EventLog::start_with(Options {
            capacity: 1024,
            ..opts(path.clone(), max)
        });
        let n = 100u64;
        for i in 0..n {
            log.emit(
                Event::info("vpp-offload", kind::VERIFY_PASSED)
                    .field("i", i)
                    .detail("sampled routes agree with the route source"),
            );
        }
        assert!(log.flush());
        assert_eq!(log.status().last_error, None);
        assert_eq!(log.status().written, n);
        let written = real.join("packetframe/events.log");
        assert!(written.is_file(), "the file is in the link's target");
        assert!(rotated_path(&written).is_file(), "and so is `.1`");
        // The reader follows the same link and sees the newest events.
        let got = lines(&path);
        assert_eq!(got.last().unwrap().fields["i"].as_u64(), Some(n - 1));
        log.shutdown();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_symlink_at_the_file_is_refused_inside_a_followed_directory() {
        for leaf in ["events.log", "events.log.1"] {
            let (_dir, real, persist) = persist_link(&format!("leaf-{leaf}"));
            let victim = real.join("victim");
            std::fs::write(&victim, b"precious\n").unwrap();
            std::os::unix::fs::symlink(&victim, real.join(leaf)).unwrap();
            let log = EventLog::start_with(opts(persist.join("events.log"), DEFAULT_MAX_BYTES));
            log.emit(Event::info("daemon", kind::PROCESS_START));
            assert!(log.flush());
            assert_eq!(std::fs::read(&victim).unwrap(), b"precious\n", "{leaf}");
            assert!(log.status().last_error.is_some(), "{leaf}");
            log.shutdown();
        }
    }
}
