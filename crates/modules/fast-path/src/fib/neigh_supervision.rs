//! The neighbour resolver's supervision, resync and health: the pure
//! half.
//!
//! The resolver itself ([`crate::fib::netlink_neigh`]) is Linux-only,
//! because it talks netlink. Everything here is the decisions it makes
//! and the status it publishes — plain data, no syscalls, **deliberately
//! not behind the platform gate** so the tests run on the macOS dev loop
//! rather than only inside the qemu job, the same reason
//! [`crate::fib::integrity_status`] is ungated.
//!
//! ## Why this exists (2026-10-07)
//!
//! A configuration apply on a production gateway admin-bounced a member
//! port and an IX bridge to flush the kernel's routes, and the kernel
//! flushed every neighbour on those links with them. The resolver's
//! multicast socket overflowed (tens of thousands of drops), and the
//! loop then waited forever on a netlink reply the kernel had dropped
//! on that same full socket: its route lookups, neighbour writes and
//! read-backs all went over the multicast connection with no timeout.
//! Nothing restarted it and nothing reported it. The kernel had the
//! nexthops REACHABLE, the FIB had 2 of 475 resolved, XDP forwarded
//! nothing, every packet took the kernel path — and the fast-path
//! module read healthy for over 13 minutes, until a daemon restart.
//!
//! Four things answer it, and this file holds the parts of each that
//! can be decided without a socket:
//!
//! - **Requests are bounded** ([`REQUEST_TIMEOUT`], [`DUMP_TIMEOUT`]) and
//!   go over a socket of their own, so a lost reply costs one probe.
//! - **An overrun is a resync** ([`ResyncSchedule`], [`reconcile_neighbours`],
//!   [`reconcile_links`]): lost notifications are recovered by re-reading
//!   the kernel and announcing what changed, not ignored.
//! - **A stuck loop is restarted** ([`StallWatch`], [`RestartBackoff`]).
//! - **None of it is silent** ([`ResolverStatus::subsystem_health`]): the
//!   `neigh-resolver` row reads Unhealthy while the loop makes no progress
//!   and Degraded for a while after any restart, with the reason.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use packetframe_common::module::{HealthState, SubsystemHealth};

use crate::fib::route_ledger::human_secs;

/// Stable subsystem name. Append-safe, rename-unsafe: `packetframe
/// status` and operator dashboards key on it.
pub const SUBSYS_NEIGH_RESOLVER: &str = "neigh-resolver";

/// Bound on one netlink request: a route lookup, a neighbour write's
/// ACK, a single-entry neighbour or link read.
///
/// The kernel answers these inside the `sendmsg` that carries them, so
/// the reply is normally queued in microseconds. What can delay one is
/// `rtnl_lock`: a neighbour write takes it on the kernels this runs on,
/// and the platform's own configuration applies have held it for tens of
/// seconds (a route flush by link toggle; ~40 s was measured on
/// 2026-10-07). A request that waits on the lock is not lost, though —
/// and while it waits, nothing else the loop does needs it to finish.
/// So the bound is not "how long could the kernel take" but "how long
/// may one nexthop's probe hold the loop": 5 s, past which the probe is
/// abandoned and the nexthop is left for the programmer's next re-probe.
/// A reply the kernel *dropped* (the 2026-10-07 shape) costs the same
/// 5 s, once, instead of the resolver.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on one netlink dump: the links, the neighbour table, the
/// bridge FDB. These are a few thousand entries at most, read in
/// milliseconds; the link dump is the one that runs under `rtnl_lock`.
/// Twice [`REQUEST_TIMEOUT`] because a dump is several replies, and it
/// is still well inside [`STALL_AFTER`], which must stay above the
/// longest wait the loop can make.
pub const DUMP_TIMEOUT: Duration = Duration::from_secs(10);

/// No progress for this long, outside a wait on the FibProgrammer, and
/// the resolver's loop is stuck: the supervisor restarts it.
///
/// Every wait the loop can make is now bounded — a request by
/// [`REQUEST_TIMEOUT`], a dump by [`DUMP_TIMEOUT`] — and an idle loop
/// still makes progress every second from its housekeeping tick. So
/// 30 s, three times the longest bounded wait, is only reached by
/// something unbounded, which is what the 2026-10-07 hang was. Waits on
/// the programmer do not count (see [`StallWatch`]).
pub const STALL_AFTER: Duration = Duration::from_secs(30);

/// How often the supervisor looks at the loop's progress.
pub const STALL_CHECK_EVERY: Duration = Duration::from_secs(1);

/// First restart delay, doubled per consecutive restart up to
/// [`RESTART_BACKOFF_MAX`]. The first is short: a stall has already
/// cost [`STALL_AFTER`] of fast-path forwarding.
pub const RESTART_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
pub const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// An incarnation that lived this long resets the backoff: its exit is
/// a new failure, not the next step of a loop.
pub const RESTART_BACKOFF_RESET_AFTER: Duration = Duration::from_secs(300);

/// How long the `neigh-resolver` row stays Degraded after a restart. The
/// restart healed the symptom, not the cause, and an operator reading
/// `status` some minutes later should still see that it happened and
/// why. The `neigh_resolver_restarted` event keeps the record.
pub const RESTART_REPORTED_FOR: Duration = Duration::from_secs(600);

/// After the first overrun of a burst, how long to wait before dumping.
/// Overruns come in bursts — the flush that overflowed the socket is
/// usually still running — and one resync after it is worth more than
/// one per overrun. This is not about draining the overflowed socket:
/// the resync never reads it again (it dumps on a fresh subscription;
/// see `NetlinkNeighborResolver::resync_now`).
pub const RESYNC_SETTLE: Duration = Duration::from_secs(1);

/// Floor between two resyncs, so a socket that keeps overflowing costs a
/// dump every 5 s rather than a dump per overrun.
pub const RESYNC_MIN_SPACING: Duration = Duration::from_secs(5);

/// Retry delay for a resync that failed (a dump that timed out, or no
/// request socket to dump with).
pub const RESYNC_RETRY: Duration = Duration::from_secs(5);

/// The supervisor's timing. Production uses [`Default`]; the tests
/// shorten it so a stall does not take 30 s to observe.
#[derive(Debug, Clone, Copy)]
pub struct SupervisionTiming {
    pub stall_after: Duration,
    pub check_every: Duration,
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    pub backoff_reset_after: Duration,
}

impl Default for SupervisionTiming {
    fn default() -> Self {
        Self {
            stall_after: STALL_AFTER,
            check_every: STALL_CHECK_EVERY,
            backoff_initial: RESTART_BACKOFF_INITIAL,
            backoff_max: RESTART_BACKOFF_MAX,
            backoff_reset_after: RESTART_BACKOFF_RESET_AFTER,
        }
    }
}

// --- Supervision decisions ---------------------------------------------

/// Decides when the loop is stuck, from the progress it reports.
///
/// Counts only silence the supervisor itself watched. The supervisor
/// shares a runtime with the loop, and a runtime starved for a while
/// (the kernel holding `rtnl_lock` under a blocked `sendmsg`) wakes both
/// at once with a large gap behind them; reading that gap as the loop's
/// silence would restart a loop that was never stuck — the lesson of
/// vpp-offload's #322. Each check therefore adds at most two check
/// intervals, however late it ran.
///
/// Time the loop spends waiting on the FibProgrammer (its event channel
/// full, or a route command not yet answered) is not silence either. A
/// full-table load can legitimately keep the programmer from draining
/// for long stretches, and a new resolver would wait on the same
/// programmer: a restart cannot change the condition, so it must not be
/// the remedy. The health row reports that wait on its own.
#[derive(Debug, Clone)]
pub struct StallWatch {
    stall_after: Duration,
    max_step: Duration,
    seen: Option<u64>,
    last_check: Option<Instant>,
    silent: Duration,
}

impl StallWatch {
    pub fn new(timing: &SupervisionTiming) -> Self {
        Self {
            stall_after: timing.stall_after,
            max_step: timing.check_every.saturating_mul(2),
            seen: None,
            last_check: None,
            silent: Duration::ZERO,
        }
    }

    /// One check. `progress` is the loop's monotonic progress count;
    /// `waiting_on_programmer` whether it is inside a programmer wait
    /// right now. Returns the silence counted so far once it reaches the
    /// stall threshold.
    pub fn observe(
        &mut self,
        now: Instant,
        progress: u64,
        waiting_on_programmer: bool,
    ) -> Option<Duration> {
        let step = self
            .last_check
            .map(|t| now.saturating_duration_since(t).min(self.max_step))
            .unwrap_or(Duration::ZERO);
        self.last_check = Some(now);
        if self.seen != Some(progress) {
            self.seen = Some(progress);
            self.silent = Duration::ZERO;
            return None;
        }
        if waiting_on_programmer {
            return None;
        }
        self.silent += step;
        (self.silent >= self.stall_after).then_some(self.silent)
    }
}

/// Restart delays: doubling from the initial delay to the cap, reset by
/// an incarnation that ran long enough to count as healthy.
#[derive(Debug, Clone)]
pub struct RestartBackoff {
    initial: Duration,
    max: Duration,
    reset_after: Duration,
    next: Duration,
}

impl RestartBackoff {
    pub fn new(timing: &SupervisionTiming) -> Self {
        Self {
            initial: timing.backoff_initial,
            max: timing.backoff_max,
            reset_after: timing.backoff_reset_after,
            next: timing.backoff_initial,
        }
    }

    /// The delay before the next incarnation, given how long the one
    /// that just ended ran.
    pub fn delay_after(&mut self, ran_for: Duration) -> Duration {
        if ran_for >= self.reset_after {
            self.next = self.initial;
        }
        let d = self.next;
        self.next = self.next.saturating_mul(2).min(self.max);
        d
    }
}

/// When the next resync runs. Coalesces a burst of overruns into one
/// resync after [`RESYNC_SETTLE`], keeps resyncs [`RESYNC_MIN_SPACING`]
/// apart, and retries a failed one after [`RESYNC_RETRY`].
#[derive(Debug, Clone, Default)]
pub struct ResyncSchedule {
    due: Option<Instant>,
    last_start: Option<Instant>,
}

impl ResyncSchedule {
    /// An overrun was read: notifications were lost. Schedules a resync
    /// unless one is already due, which this one joins.
    pub fn on_overrun(&mut self, now: Instant) {
        if self.due.is_some() {
            return;
        }
        let mut at = now + RESYNC_SETTLE;
        if let Some(last) = self.last_start {
            at = at.max(last + RESYNC_MIN_SPACING);
        }
        self.due = Some(at);
    }

    /// The resync now owed, if any.
    pub fn due(&self) -> Option<Instant> {
        self.due
    }

    /// A resync starts: it answers every overrun read so far. One read
    /// after it starts schedules the next.
    pub fn start(&mut self, now: Instant) {
        self.due = None;
        self.last_start = Some(now);
    }

    /// The resync could not complete; it is owed again.
    pub fn failed(&mut self, now: Instant) {
        self.due = Some(now + RESYNC_RETRY);
    }
}

// --- Reconciling a dump against the resolver's view --------------------

/// The resolver's view of the kernel's neighbour table, as it has
/// announced it: `ip → (ifindex, mac)`.
pub type NeighView = HashMap<IpAddr, (u32, [u8; 6])>;

/// What a dump says changed relative to the view.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct NeighDelta {
    /// Usable entries that are new, or moved device, or changed MAC.
    pub learned: Vec<(IpAddr, u32, [u8; 6])>,
    /// `(address, device)` pairs the view holds that the dump no longer
    /// lists as usable: the address missing altogether, or listed only on
    /// other devices (a move, which also appears in `learned`).
    pub lost: Vec<(IpAddr, u32)>,
}

/// Compare a neighbour dump (every usable entry, in dump order) with the
/// view. The view is keyed by address while the kernel keys `(device,
/// address)`, so an address the dump holds on several devices keeps the
/// one the view already has, if the dump still has it there; otherwise
/// the last one in dump order wins, which is what a fresh seed does, and
/// the device the view had is reported lost. Output is sorted by address
/// so the announcements are deterministic.
pub fn reconcile_neighbours(view: &NeighView, dump: &[(IpAddr, u32, [u8; 6])]) -> NeighDelta {
    let mut by_ip: HashMap<IpAddr, Vec<(u32, [u8; 6])>> = HashMap::new();
    for &(ip, ifindex, mac) in dump {
        by_ip.entry(ip).or_default().push((ifindex, mac));
    }
    let mut delta = NeighDelta::default();
    for (ip, entries) in &by_ip {
        let last = *entries.last().expect("grouped from at least one entry");
        let chosen = match view.get(ip) {
            Some(&(cached_if, cached_mac)) => {
                match entries.iter().rev().find(|(i, _)| *i == cached_if) {
                    Some(&(_, mac)) if mac == cached_mac => continue,
                    Some(&e) => e,
                    None => {
                        // A move: the address is listed, but not on the
                        // device the view holds it on. That entry is
                        // missing like any other, and is lost on its own —
                        // as its RTM_DELNEIGH would have, withdrawing what
                        // was announced for it there — besides the new
                        // device being learned.
                        delta.lost.push((*ip, cached_if));
                        last
                    }
                }
            }
            None => last,
        };
        delta.learned.push((*ip, chosen.0, chosen.1));
    }
    for (ip, &(ifindex, _)) in view {
        if !by_ip.contains_key(ip) {
            delta.lost.push((*ip, ifindex));
        }
    }
    delta.learned.sort_by_key(|e| e.0);
    delta.lost.sort_by_key(|e| e.0);
    delta
}

/// One link as a dump or an `RTM_NEWLINK` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkObs {
    pub ifindex: u32,
    pub name: Option<String>,
    pub mac: Option<[u8; 6]>,
}

/// What a link dump says changed relative to the resolver's link caches.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LinkDelta {
    /// Links that are new, renamed, or carry a new MAC: each is applied
    /// as its `RTM_NEWLINK` would have been.
    pub changed: Vec<LinkObs>,
    /// Links the caches know and the dump does not: each is applied as
    /// its `RTM_DELLINK` would have been. Apply these first, so a name
    /// that moved to a recreated link is re-pointed, not dropped.
    pub gone: Vec<u32>,
}

/// Compare a link dump with the resolver's two link caches (`ifindex →
/// MAC` and `name → ifindex`). A link with no MAC or no name in the dump
/// is not a change in that field, matching the `RTM_NEWLINK` handler,
/// which only ever adds what a message carries.
pub fn reconcile_links(
    macs: &HashMap<u32, [u8; 6]>,
    names: &HashMap<String, u32>,
    dump: &[LinkObs],
) -> LinkDelta {
    let name_of: HashMap<u32, &str> = names.iter().map(|(n, &i)| (i, n.as_str())).collect();
    let known: HashSet<u32> = names
        .values()
        .copied()
        .chain(macs.keys().copied())
        .collect();
    let present: HashSet<u32> = dump.iter().map(|l| l.ifindex).collect();
    let mut delta = LinkDelta::default();
    for l in dump {
        let new = !known.contains(&l.ifindex);
        let renamed = l
            .name
            .as_deref()
            .is_some_and(|n| name_of.get(&l.ifindex).copied() != Some(n));
        let re_mac = l.mac.is_some_and(|m| macs.get(&l.ifindex) != Some(&m));
        if new || renamed || re_mac {
            delta.changed.push(l.clone());
        }
    }
    delta.gone = known.difference(&present).copied().collect();
    delta.gone.sort_unstable();
    delta.changed.sort_by_key(|l| l.ifindex);
    delta
}

// --- Rate-limited logging ------------------------------------------------

/// At most one log line per window, carrying how many it swallowed.
#[derive(Debug, Default)]
pub struct LogLimiter {
    last: Option<Instant>,
    suppressed: u64,
}

impl LogLimiter {
    pub const WINDOW: Duration = Duration::from_secs(60);

    /// `Some(suppressed since the last line)` when this occurrence should
    /// be logged; `None` when it is counted instead.
    pub fn admit(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            Some(t) if now.saturating_duration_since(t) < Self::WINDOW => {
                self.suppressed += 1;
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
        }
    }
}

// --- Status ---------------------------------------------------------------

/// Why an incarnation of the loop ended without being asked to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitCause {
    /// It returned an error (the multicast stream closed, a socket could
    /// not be opened).
    Failed(String),
    /// It made no progress for this long outside a programmer wait, and
    /// the supervisor dropped it.
    Stalled { silent: Duration },
    /// It returned without an error and without a shutdown. Nothing does
    /// that today; it is a restart rather than an end so that nothing
    /// can.
    Returned,
}

impl ExitCause {
    /// The event-log `cause` field.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Failed(_) => "failed",
            Self::Stalled { .. } => "stalled",
            Self::Returned => "returned",
        }
    }
}

impl std::fmt::Display for ExitCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(e) => write!(f, "exited with an error: {e}"),
            Self::Stalled { silent } => write!(
                f,
                "made no progress for {} (stuck; dropped by the supervisor)",
                human_secs(silent.as_secs())
            ),
            Self::Returned => f.write_str("returned without being asked to stop"),
        }
    }
}

/// Where the supervisor is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// An incarnation is subscribing and reading the kernel's tables.
    Starting,
    /// An incarnation is in its event loop.
    Running,
    /// No incarnation runs: the last one ended, the next starts at `until`.
    Restarting { until: Instant },
    /// Shut down.
    Stopped,
}

/// The last restart, kept for the health row and the metrics.
#[derive(Debug, Clone)]
pub struct RestartRecord {
    pub at: Instant,
    pub cause: ExitCause,
    /// How long the incarnation that ended had run.
    pub ran_for: Duration,
}

/// Why a resync is owed — carried with it, so the row names the cause
/// of *this* debt rather than the last overrun ever seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwedResync {
    pub since: Instant,
    pub cause: OwedCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwedCause {
    /// The multicast socket overflowed: notifications were lost.
    Overrun,
    /// A read of the kernel's tables failed, or could not confirm that
    /// entries missing from a dump are really gone.
    ReadIncomplete,
}

/// Lifetime counters, across incarnations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolverCounters {
    /// Overruns read on the multicast socket: notifications the kernel
    /// dropped because the socket's receive buffer was full.
    pub overruns: u64,
    /// Resyncs completed (the kernel's tables re-read and reconciled).
    pub resyncs: u64,
    pub resync_failures: u64,
    /// Netlink requests or dumps abandoned at their bound.
    pub request_timeouts: u64,
    /// Proactive probes not issued because the request socket of a
    /// timed-out request had not closed yet.
    pub probes_skipped: u64,
    pub restarts: u64,
}

/// Everything the resolver publishes about itself. One struct, read as
/// one snapshot, so the health row and the metrics cannot be derived
/// from different moments.
#[derive(Debug, Clone)]
pub struct ResolverStatus {
    /// The supervisor's stall threshold, so the health row judges
    /// silence against the same number.
    pub stall_after: Duration,
    pub phase: Phase,
    /// 1 for the first incarnation, +1 per restart.
    pub incarnation: u64,
    /// Monotonic progress count: bumped each time the loop completes a
    /// unit of work (an event, a request, a dump, a tick).
    pub progress: u64,
    pub last_progress: Instant,
    /// Set while the loop waits on the FibProgrammer.
    pub programmer_wait_since: Option<Instant>,
    pub last_restart: Option<RestartRecord>,
    /// A resync is owed: what first made it owed, and when. Cleared only
    /// by a completed read of the kernel.
    pub resync_owed: Option<OwedResync>,
    pub last_resync: Option<Instant>,
    pub last_resync_error: Option<String>,
    /// A request timed out on the request socket and the socket's task
    /// has not exited yet; no new socket is opened until it does.
    pub request_socket_stuck_since: Option<Instant>,
    pub counters: ResolverCounters,
}

impl ResolverStatus {
    pub fn new(now: Instant, stall_after: Duration) -> Self {
        Self {
            stall_after,
            phase: Phase::Starting,
            incarnation: 0,
            progress: 0,
            last_progress: now,
            programmer_wait_since: None,
            last_restart: None,
            resync_owed: None,
            last_resync: None,
            last_resync_error: None,
            request_socket_stuck_since: None,
            counters: ResolverCounters::default(),
        }
    }

    /// Wall-clock time since the loop last made progress, while an
    /// incarnation is meant to be making it. `None` when none is (between
    /// incarnations, or stopped) and while it waits on the programmer,
    /// which [`Self::subsystem_health`] reports separately.
    ///
    /// Deliberately not the supervisor's counted silence
    /// ([`StallWatch`]): that answers "is a restart the remedy", which
    /// excuses a starved runtime. This answers "is neighbour resolution
    /// happening right now", which a starved runtime is not doing either.
    pub fn silent_for(&self, now: Instant) -> Option<Duration> {
        if !matches!(self.phase, Phase::Starting | Phase::Running) {
            return None;
        }
        if self.programmer_wait_since.is_some() {
            return None;
        }
        Some(now.saturating_duration_since(self.last_progress))
    }

    /// The `neigh-resolver` row. Healthy only when every condition below
    /// is absent — a whitelist, so a state nobody anticipated reads
    /// Degraded rather than fine.
    pub fn subsystem_health(&self, now: Instant) -> SubsystemHealth {
        let mut problems: Vec<(HealthState, String)> = Vec::new();
        let ago = |t: Instant| human_secs(now.saturating_duration_since(t).as_secs());
        match &self.phase {
            Phase::Running => {}
            Phase::Starting => problems.push((
                HealthState::Degraded,
                "starting: subscribing and reading the kernel's links and neighbours".into(),
            )),
            Phase::Restarting { until } => {
                let cause = self
                    .last_restart
                    .as_ref()
                    .map_or_else(|| "ended".to_string(), |r| r.cause.to_string());
                problems.push((
                    HealthState::Unhealthy,
                    format!(
                        "NOT RUNNING: the resolver {cause}; restart #{} in {} — until then no \
                         nexthop is resolved or re-resolved and their traffic takes the kernel \
                         path",
                        self.counters.restarts,
                        human_secs(until.saturating_duration_since(now).as_secs())
                    ),
                ));
            }
            Phase::Stopped => problems.push((HealthState::Degraded, "stopped".into())),
        }
        if let Some(silent) = self.silent_for(now) {
            if silent >= self.stall_after {
                problems.push((
                    HealthState::Unhealthy,
                    format!(
                        "no progress for {} — neighbour events and resolve requests are not \
                         being served, so nexthops cannot resolve; the supervisor restarts a \
                         loop stuck for {}",
                        human_secs(silent.as_secs()),
                        human_secs(self.stall_after.as_secs())
                    ),
                ));
            }
        }
        if let Some(since) = self.programmer_wait_since {
            if now.saturating_duration_since(since) >= self.stall_after {
                problems.push((
                    HealthState::Degraded,
                    format!(
                        "waiting {} for the FibProgrammer to accept its events — neighbour \
                         changes are queued behind it; this is the programmer's backlog, and \
                         restarting the resolver cannot clear it",
                        ago(since)
                    ),
                ));
            }
        }
        if let Some(r) = &self.last_restart {
            if now.saturating_duration_since(r.at) < RESTART_REPORTED_FOR
                && !matches!(self.phase, Phase::Restarting { .. })
            {
                problems.push((
                    HealthState::Degraded,
                    format!(
                        "restarted {} ago (restart #{}): the previous loop {} after running {}",
                        ago(r.at),
                        self.counters.restarts,
                        r.cause,
                        human_secs(r.ran_for.as_secs())
                    ),
                ));
            }
        }
        if let Some(owed) = self.resync_owed {
            let lost = match owed.cause {
                OwedCause::Overrun => format!(
                    "neighbour/link notifications were lost {} ago (socket overrun)",
                    ago(owed.since)
                ),
                OwedCause::ReadIncomplete => format!(
                    "a read of the kernel's links and neighbours did not complete {} ago",
                    ago(owed.since)
                ),
            };
            let state = match &self.last_resync_error {
                Some(e) => format!("the resync failed ({e}) and is retried"),
                None => "a resync is pending".into(),
            };
            problems.push((
                HealthState::Degraded,
                format!(
                    "{lost}; {state} — until it completes, a neighbour that changed meanwhile \
                     is unknown here"
                ),
            ));
        }
        // A retired socket normally exits at once (its task is idle in a
        // read); one still there after a request's bound is blocked in
        // the kernel.
        if let Some(since) = self
            .request_socket_stuck_since
            .filter(|&t| now.saturating_duration_since(t) >= REQUEST_TIMEOUT)
        {
            problems.push((
                HealthState::Degraded,
                format!(
                    "the request socket was retired {} ago and the kernel still holds it \
                     (typically `rtnl_lock`); proactive probes are skipped until it lets go",
                    ago(since)
                ),
            ));
        }

        let c = &self.counters;
        let last_resync = self
            .last_resync
            .map(|t| format!(", last {} ago", ago(t)))
            .unwrap_or_default();
        let counters = format!(
            "overruns {} (resyncs {}{last_resync}, failed {}), request timeouts {}, probes \
             skipped {}, restarts {}",
            c.overruns,
            c.resyncs,
            c.resync_failures,
            c.request_timeouts,
            c.probes_skipped,
            c.restarts
        );
        let state = problems
            .iter()
            .fold(HealthState::Healthy, |acc, (s, _)| acc.worse_of(*s));
        let message = if problems.is_empty() {
            format!(
                "running (incarnation {}); last progress {} ago; {counters}",
                self.incarnation,
                ago(self.last_progress)
            )
        } else {
            let mut m: Vec<String> = problems.into_iter().map(|(_, m)| m).collect();
            m.push(counters);
            m.join("; ")
        };
        SubsystemHealth {
            name: SUBSYS_NEIGH_RESOLVER.to_string(),
            state,
            message: Some(message),
            last_success_age_seconds: Some(
                now.saturating_duration_since(self.last_progress).as_secs(),
            ),
        }
    }

    /// Textfile counters and gauges.
    pub fn render_metrics(&self, now: Instant, out: &mut String) {
        let c = &self.counters;
        let counters: [(&str, &str, u64); 6] = [
            (
                "packetframe_fib_neigh_resolver_overruns_total",
                "Overruns on the neighbour resolver's multicast socket (notifications the \
                 kernel dropped)",
                c.overruns,
            ),
            (
                "packetframe_fib_neigh_resolver_resyncs_total",
                "Resyncs of the kernel's links and neighbours the resolver completed",
                c.resyncs,
            ),
            (
                "packetframe_fib_neigh_resolver_resync_failures_total",
                "Resyncs that could not complete and were retried",
                c.resync_failures,
            ),
            (
                "packetframe_fib_neigh_resolver_request_timeouts_total",
                "Netlink requests and dumps the resolver abandoned at their bound",
                c.request_timeouts,
            ),
            (
                "packetframe_fib_neigh_resolver_probes_skipped_total",
                "Proactive probes skipped while a timed-out request socket closed",
                c.probes_skipped,
            ),
            (
                "packetframe_fib_neigh_resolver_restarts_total",
                "Times the supervisor restarted the neighbour resolver",
                c.restarts,
            ),
        ];
        for (name, help, value) in counters {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name}{{module=\"fast-path\"}} {value}");
        }
        let _ = writeln!(
            out,
            "# HELP packetframe_fib_neigh_resolver_running 1 while a resolver loop runs (0 \
             between a failure and its restart)"
        );
        let _ = writeln!(out, "# TYPE packetframe_fib_neigh_resolver_running gauge");
        let _ = writeln!(
            out,
            "packetframe_fib_neigh_resolver_running{{module=\"fast-path\"}} {}",
            u8::from(matches!(self.phase, Phase::Starting | Phase::Running))
        );
        let _ = writeln!(
            out,
            "# HELP packetframe_fib_neigh_resolver_progress_age_seconds Seconds since the \
             resolver's loop last made progress (an idle loop still ticks every second)"
        );
        let _ = writeln!(
            out,
            "# TYPE packetframe_fib_neigh_resolver_progress_age_seconds gauge"
        );
        let _ = writeln!(
            out,
            "packetframe_fib_neigh_resolver_progress_age_seconds{{module=\"fast-path\"}} {}",
            now.saturating_duration_since(self.last_progress).as_secs()
        );
        // Beside the progress age because a long wait on the programmer
        // also stops progress, and is not the resolver's fault: an alert
        // on the age alone cannot tell the two apart, as the row does.
        let _ = writeln!(
            out,
            "# HELP packetframe_fib_neigh_resolver_programmer_wait_seconds Seconds the resolver \
             has been waiting for the FibProgrammer to accept its events (0: not waiting)"
        );
        let _ = writeln!(
            out,
            "# TYPE packetframe_fib_neigh_resolver_programmer_wait_seconds gauge"
        );
        let _ = writeln!(
            out,
            "packetframe_fib_neigh_resolver_programmer_wait_seconds{{module=\"fast-path\"}} {}",
            self.programmer_wait_since
                .map_or(0, |t| now.saturating_duration_since(t).as_secs())
        );
    }
}

/// The resolver's status, shared between the loop that writes it, the
/// supervisor that writes the restarts, and the health and metrics
/// surfaces that read it.
#[derive(Debug, Clone)]
pub struct SharedResolverStatus(Arc<Mutex<ResolverStatus>>);

impl SharedResolverStatus {
    pub fn new(stall_after: Duration) -> Self {
        Self(Arc::new(Mutex::new(ResolverStatus::new(
            Instant::now(),
            stall_after,
        ))))
    }

    /// A copy, for one health or metrics read.
    pub fn snapshot(&self) -> ResolverStatus {
        self.lock().clone()
    }

    /// Mutate under the lock. Poisoning is recovered rather than
    /// propagated: the status is a report, and a panic elsewhere must not
    /// take the health surface down with it.
    pub fn update<R>(&self, f: impl FnOnce(&mut ResolverStatus) -> R) -> R {
        f(&mut self.lock())
    }

    /// The loop completed a unit of work.
    pub fn beat(&self) {
        self.update(|s| {
            s.progress = s.progress.wrapping_add(1);
            s.last_progress = Instant::now();
        });
    }

    /// `(progress, waiting on the programmer)`, for the supervisor.
    pub fn progress(&self) -> (u64, bool) {
        self.update(|s| (s.progress, s.programmer_wait_since.is_some()))
    }

    /// Mark a wait on the FibProgrammer, cleared (and counted as
    /// progress) when the guard drops — including when the loop is
    /// dropped mid-wait.
    pub fn programmer_wait(&self) -> ProgrammerWait {
        self.update(|s| {
            s.programmer_wait_since.get_or_insert_with(Instant::now);
        });
        ProgrammerWait(self.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ResolverStatus> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// See [`SharedResolverStatus::programmer_wait`].
#[must_use = "the wait ends when this guard drops"]
pub struct ProgrammerWait(SharedResolverStatus);

impl Drop for ProgrammerWait {
    fn drop(&mut self) {
        self.0.update(|s| {
            s.programmer_wait_since = None;
            s.progress = s.progress.wrapping_add(1);
            s.last_progress = Instant::now();
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    /// A map in key order, for comparing two views.
    fn sorted<K: Ord + Clone, V: Clone>(m: &HashMap<K, V>) -> BTreeMap<K, V> {
        m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    const M1: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const M2: [u8; 6] = [0x02, 0, 0, 0, 0, 2];

    fn timing() -> SupervisionTiming {
        SupervisionTiming::default()
    }

    // --- reconcile_neighbours ------------------------------------------

    #[test]
    fn reconcile_announces_new_changed_and_lost_and_nothing_else() {
        let mut view = NeighView::new();
        view.insert(ip(1), (10, M1)); // unchanged
        view.insert(ip(2), (10, M1)); // MAC changes
        view.insert(ip(3), (10, M1)); // gone from the kernel
        let dump = vec![
            (ip(1), 10, M1),
            (ip(2), 10, M2),
            (ip(4), 11, M2), // new
        ];
        let d = reconcile_neighbours(&view, &dump);
        assert_eq!(d.learned, vec![(ip(2), 10, M2), (ip(4), 11, M2)]);
        assert_eq!(d.lost, vec![(ip(3), 10)]);
    }

    /// The kernel keys `(device, address)`, the view keys address. An
    /// address present on two devices must not flap the nexthop to the
    /// other device on every resync: the device the view holds wins
    /// while the kernel still has it there.
    #[test]
    fn reconcile_keeps_the_viewed_device_when_the_kernel_still_has_it() {
        let mut view = NeighView::new();
        view.insert(ip(1), (10, M1));
        let dump = vec![(ip(1), 10, M1), (ip(1), 20, M2)];
        assert_eq!(reconcile_neighbours(&view, &dump), NeighDelta::default());

        // Off the viewed device but still on another: a move. The device
        // that remains is learned, and the viewed one is lost in its own
        // right — whatever was announced for the address there (a
        // local-prefix host route on that interface) must be withdrawn,
        // as that device's RTM_DELNEIGH would have done.
        let dump = vec![(ip(1), 20, M2)];
        let d = reconcile_neighbours(&view, &dump);
        assert_eq!(d.learned, vec![(ip(1), 20, M2)]);
        assert_eq!(d.lost, vec![(ip(1), 10)]);
    }

    #[test]
    fn reconcile_against_an_empty_view_learns_everything_last_wins() {
        let dump = vec![(ip(1), 10, M1), (ip(1), 20, M2), (ip(2), 10, M1)];
        let d = reconcile_neighbours(&NeighView::new(), &dump);
        assert_eq!(d.learned, vec![(ip(1), 20, M2), (ip(2), 10, M1)]);
        assert!(d.lost.is_empty());
    }

    /// The invariant, not a case list: applying the delta to the view
    /// yields exactly the view a fresh seed from the same dump would hold
    /// (modulo the device preference), and a second reconcile against the
    /// result is empty.
    #[test]
    fn applying_the_delta_converges_and_a_second_reconcile_is_empty() {
        let mut view = NeighView::new();
        for i in 0..20u8 {
            view.insert(ip(i), (u32::from(i % 3), [0x02, 0, 0, 0, i, 1]));
        }
        let dump: Vec<_> = (10..30u8)
            .map(|i| (ip(i), u32::from(i % 4), [0x02, 0, 0, 0, i, (i % 2) + 1]))
            .collect();
        let d = reconcile_neighbours(&view, &dump);
        for (ip, _) in &d.lost {
            view.remove(ip);
        }
        for &(ip, i, m) in &d.learned {
            view.insert(ip, (i, m));
        }
        let fresh: NeighView = dump.iter().map(|&(a, i, m)| (a, (i, m))).collect();
        assert_eq!(sorted(&view), sorted(&fresh));
        assert_eq!(reconcile_neighbours(&view, &dump), NeighDelta::default());
    }

    // --- reconcile_links -----------------------------------------------

    fn link(ifindex: u32, name: &str, mac: Option<[u8; 6]>) -> LinkObs {
        LinkObs {
            ifindex,
            name: Some(name.into()),
            mac,
        }
    }

    #[test]
    fn link_reconcile_finds_new_renamed_remac_and_gone() {
        let macs: HashMap<u32, [u8; 6]> = [(1, M1), (2, M1), (3, M1)].into();
        let names: HashMap<String, u32> = [
            ("a".to_string(), 1),
            ("b".to_string(), 2),
            ("c".to_string(), 3),
            ("lo".to_string(), 9),
        ]
        .into();
        let dump = vec![
            link(1, "a", Some(M1)),  // unchanged
            link(2, "b", Some(M2)),  // MAC changed
            link(3, "c2", Some(M1)), // renamed
            link(9, "lo", None),     // no MAC: not a change
            link(7, "d", Some(M2)),  // new
        ];
        let d = reconcile_links(&macs, &names, &dump);
        let changed: Vec<u32> = d.changed.iter().map(|l| l.ifindex).collect();
        assert_eq!(changed, vec![2, 3, 7]);
        assert!(d.gone.is_empty());

        let d = reconcile_links(&macs, &names, &dump[..2]);
        assert_eq!(d.gone, vec![3, 9], "known links absent from the dump");
    }

    /// The platform recreates bridges under the same name with a new
    /// ifindex. The old ifindex is gone and the name lands on the new
    /// one; applied gone-first, the name ends up re-pointed.
    #[test]
    fn a_recreated_link_is_gone_plus_new() {
        let macs: HashMap<u32, [u8; 6]> = [(5, M1)].into();
        let names: HashMap<String, u32> = [("br0".to_string(), 5)].into();
        let d = reconcile_links(&macs, &names, &[link(6, "br0", Some(M1))]);
        assert_eq!(d.gone, vec![5]);
        assert_eq!(d.changed, vec![link(6, "br0", Some(M1))]);
    }

    // --- StallWatch -----------------------------------------------------

    #[test]
    fn progress_resets_the_watch() {
        let t = timing();
        let mut w = StallWatch::new(&t);
        let t0 = Instant::now();
        for s in 0..100u64 {
            let now = t0 + Duration::from_secs(s);
            assert_eq!(w.observe(now, s, false), None, "progress at every check");
        }
    }

    #[test]
    fn silence_past_the_threshold_is_a_stall() {
        let t = timing();
        let mut w = StallWatch::new(&t);
        let t0 = Instant::now();
        let mut verdict = None;
        for s in 0..=40u64 {
            verdict = w.observe(t0 + Duration::from_secs(s), 7, false);
            if verdict.is_some() {
                assert_eq!(s, STALL_AFTER.as_secs(), "fires at the threshold");
                break;
            }
        }
        assert_eq!(verdict, Some(STALL_AFTER));
    }

    /// The 2026-10-07 shape is a loop silent outside the programmer. The
    /// programmer's own backlog is not: a restart could not change it.
    #[test]
    fn a_programmer_wait_is_never_a_stall() {
        let t = timing();
        let mut w = StallWatch::new(&t);
        let t0 = Instant::now();
        for s in 0..600u64 {
            assert_eq!(w.observe(t0 + Duration::from_secs(s), 3, true), None);
        }
        // And the wait does not bank silence for afterwards: counting
        // starts when the wait ends (here without progress), one check
        // interval at a time.
        let after = t0 + Duration::from_secs(600);
        let n = STALL_AFTER.as_secs();
        for s in 0..n - 1 {
            assert_eq!(
                w.observe(after + Duration::from_secs(s), 3, false),
                None,
                "s={s}"
            );
        }
        assert_eq!(
            w.observe(after + Duration::from_secs(n - 1), 3, false),
            Some(STALL_AFTER)
        );
    }

    /// A supervisor check that runs late (the runtime was starved, both
    /// it and the loop were off-CPU) counts at most two intervals, so one
    /// long gap is never a stall by itself (vpp-offload #322).
    #[test]
    fn a_late_check_counts_at_most_two_intervals() {
        let t = timing();
        let mut w = StallWatch::new(&t);
        let t0 = Instant::now();
        assert_eq!(w.observe(t0, 1, false), None);
        // A 120 s gap with no progress: one check, capped at 2 s.
        assert_eq!(w.observe(t0 + Duration::from_secs(120), 1, false), None);
        // Still needs the rest of the threshold watched check by check.
        let mut fired_at = None;
        for s in 1..=40u64 {
            if w.observe(t0 + Duration::from_secs(120 + s), 1, false)
                .is_some()
            {
                fired_at = Some(s);
                break;
            }
        }
        assert_eq!(fired_at, Some(STALL_AFTER.as_secs() - 2));
    }

    // --- RestartBackoff -------------------------------------------------

    #[test]
    fn backoff_doubles_caps_and_resets_after_a_long_run() {
        let t = timing();
        let mut b = RestartBackoff::new(&t);
        let short = Duration::from_secs(1);
        let delays: Vec<u64> = (0..9).map(|_| b.delay_after(short).as_secs()).collect();
        assert_eq!(delays, vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
        assert_eq!(b.delay_after(RESTART_BACKOFF_RESET_AFTER).as_secs(), 1);
        assert_eq!(b.delay_after(short).as_secs(), 2);
    }

    // --- ResyncSchedule -------------------------------------------------

    #[test]
    fn a_burst_of_overruns_is_one_resync_after_the_settle() {
        let mut s = ResyncSchedule::default();
        let t0 = Instant::now();
        s.on_overrun(t0);
        for ms in 1..900u64 {
            s.on_overrun(t0 + Duration::from_millis(ms));
        }
        assert_eq!(s.due(), Some(t0 + RESYNC_SETTLE));
    }

    #[test]
    fn resyncs_keep_their_spacing_and_a_failure_is_retried() {
        let mut s = ResyncSchedule::default();
        let t0 = Instant::now();
        s.on_overrun(t0);
        let start = t0 + RESYNC_SETTLE;
        s.start(start);
        assert_eq!(s.due(), None, "the started resync answers what came before");
        // An overrun read right after: spaced from the last start.
        s.on_overrun(start + Duration::from_millis(10));
        assert_eq!(s.due(), Some(start + RESYNC_MIN_SPACING));
        s.start(start + RESYNC_MIN_SPACING);
        let failed_at = start + RESYNC_MIN_SPACING + Duration::from_millis(5);
        s.failed(failed_at);
        assert_eq!(s.due(), Some(failed_at + RESYNC_RETRY));
    }

    // --- LogLimiter -----------------------------------------------------

    #[test]
    fn log_limiter_admits_one_per_window_and_counts_the_rest() {
        let mut l = LogLimiter::default();
        let t0 = Instant::now();
        assert_eq!(l.admit(t0), Some(0));
        for s in 1..10 {
            assert_eq!(l.admit(t0 + Duration::from_secs(s)), None);
        }
        assert_eq!(l.admit(t0 + LogLimiter::WINDOW), Some(9));
    }

    // --- Health ---------------------------------------------------------

    fn running(now: Instant) -> ResolverStatus {
        let mut s = ResolverStatus::new(now, STALL_AFTER);
        s.phase = Phase::Running;
        s.incarnation = 1;
        s
    }

    #[test]
    fn a_running_loop_with_recent_progress_is_healthy() {
        let now = Instant::now();
        let s = running(now);
        let h = s.subsystem_health(now + Duration::from_secs(9));
        assert_eq!(h.state, HealthState::Healthy, "{:?}", h.message);
        assert_eq!(h.name, SUBSYS_NEIGH_RESOLVER);
        assert_eq!(h.last_success_age_seconds, Some(9));
    }

    /// The incident's reading: a loop that stopped making progress must
    /// never render as healthy, whatever else is true.
    #[test]
    fn a_loop_with_no_progress_is_unhealthy_and_says_for_how_long() {
        let now = Instant::now();
        let s = running(now);
        let later = now + Duration::from_secs(13 * 60);
        let h = s.subsystem_health(later);
        assert_eq!(h.state, HealthState::Unhealthy);
        let m = h.message.unwrap();
        assert!(m.contains("no progress for 13m"), "{m}");
    }

    #[test]
    fn a_long_programmer_wait_is_degraded_not_a_stall() {
        let now = Instant::now();
        let mut s = running(now);
        s.programmer_wait_since = Some(now);
        let h = s.subsystem_health(now + Duration::from_secs(120));
        assert_eq!(h.state, HealthState::Degraded);
        let m = h.message.unwrap();
        assert!(m.contains("FibProgrammer"), "{m}");
        assert!(!m.contains("no progress"), "{m}");
    }

    #[test]
    fn a_restart_reads_degraded_with_its_cause_for_a_while() {
        let now = Instant::now();
        let mut s = running(now);
        s.incarnation = 2;
        s.counters.restarts = 1;
        s.last_restart = Some(RestartRecord {
            at: now,
            cause: ExitCause::Stalled {
                silent: Duration::from_secs(31),
            },
            ran_for: Duration::from_secs(3600),
        });
        let h = s.subsystem_health(now + Duration::from_secs(5));
        assert_eq!(h.state, HealthState::Degraded);
        let m = h.message.unwrap();
        assert!(m.contains("restart #1"), "{m}");
        assert!(m.contains("made no progress for 31s"), "{m}");

        let mut s2 = s.clone();
        s2.last_progress = now + RESTART_REPORTED_FOR;
        let h = s2.subsystem_health(now + RESTART_REPORTED_FOR + Duration::from_secs(1));
        assert_eq!(h.state, HealthState::Healthy, "the window ends");
    }

    #[test]
    fn between_incarnations_is_unhealthy_with_the_error() {
        let now = Instant::now();
        let mut s = running(now);
        s.counters.restarts = 3;
        s.last_restart = Some(RestartRecord {
            at: now,
            cause: ExitCause::Failed("netlink multicast stream closed".into()),
            ran_for: Duration::from_secs(1),
        });
        s.phase = Phase::Restarting {
            until: now + Duration::from_secs(4),
        };
        let h = s.subsystem_health(now);
        assert_eq!(h.state, HealthState::Unhealthy);
        let m = h.message.unwrap();
        assert!(m.contains("NOT RUNNING"), "{m}");
        assert!(m.contains("netlink multicast stream closed"), "{m}");
        assert!(m.contains("restart #3 in 4s"), "{m}");
    }

    #[test]
    fn an_owed_resync_is_degraded_and_names_the_overrun() {
        let now = Instant::now();
        let mut s = running(now);
        s.resync_owed = Some(OwedResync {
            since: now,
            cause: OwedCause::Overrun,
        });
        s.counters.overruns = 4;
        let h = s.subsystem_health(now + Duration::from_secs(2));
        assert_eq!(h.state, HealthState::Degraded);
        let m = h.message.unwrap();
        assert!(m.contains("socket overrun"), "{m}");
        assert!(m.contains("resync is pending"), "{m}");
        assert!(m.contains("overruns 4"), "{m}");

        s.resync_owed = None;
        s.counters.resyncs = 1;
        let h = s.subsystem_health(now + Duration::from_secs(3));
        assert_eq!(
            h.state,
            HealthState::Healthy,
            "a resynced overrun is history, still in the counters: {:?}",
            h.message
        );
        assert!(h.message.unwrap().contains("overruns 4 (resyncs 1"));
    }

    /// A debt names its own cause. An overrun answered days ago must not
    /// be what the row blames for a read that fails today, and a restart
    /// line must not claim a re-read that did not complete.
    #[test]
    fn an_owed_read_names_the_failed_read_not_an_old_overrun() {
        let now = Instant::now();
        let mut s = running(now);
        s.counters.overruns = 1;
        s.counters.resyncs = 1;
        s.last_resync = Some(now);
        let later = now + Duration::from_secs(3 * 86_400);
        s.last_progress = later;
        s.counters.restarts = 1;
        s.last_restart = Some(RestartRecord {
            at: later,
            cause: ExitCause::Failed("netlink multicast stream closed".into()),
            ran_for: Duration::from_secs(60),
        });
        s.resync_owed = Some(OwedResync {
            since: later,
            cause: OwedCause::ReadIncomplete,
        });
        s.last_resync_error = Some("neighbour dump timed out after 10 s".into());
        let m = s
            .subsystem_health(later + Duration::from_secs(1))
            .message
            .unwrap();
        assert!(!m.contains("socket overrun"), "{m}");
        assert!(m.contains("did not complete 1s ago"), "{m}");
        assert!(m.contains("neighbour dump timed out"), "{m}");
        assert!(!m.contains("re-read the kernel"), "{m}");
    }

    /// Whitelist: of every phase, only `Running` can be healthy.
    #[test]
    fn only_running_can_be_healthy() {
        let now = Instant::now();
        for phase in [
            Phase::Starting,
            Phase::Stopped,
            Phase::Restarting {
                until: now + Duration::from_secs(1),
            },
        ] {
            let mut s = running(now);
            s.phase = phase.clone();
            assert_ne!(
                s.subsystem_health(now).state,
                HealthState::Healthy,
                "{phase:?}"
            );
        }
    }

    #[test]
    fn metrics_carry_every_counter_and_the_running_gauge() {
        let now = Instant::now();
        let mut s = running(now);
        s.counters = ResolverCounters {
            overruns: 1,
            resyncs: 2,
            resync_failures: 3,
            request_timeouts: 4,
            probes_skipped: 5,
            restarts: 6,
        };
        let mut out = String::new();
        s.render_metrics(now + Duration::from_secs(7), &mut out);
        for line in [
            "packetframe_fib_neigh_resolver_overruns_total{module=\"fast-path\"} 1",
            "packetframe_fib_neigh_resolver_resyncs_total{module=\"fast-path\"} 2",
            "packetframe_fib_neigh_resolver_resync_failures_total{module=\"fast-path\"} 3",
            "packetframe_fib_neigh_resolver_request_timeouts_total{module=\"fast-path\"} 4",
            "packetframe_fib_neigh_resolver_probes_skipped_total{module=\"fast-path\"} 5",
            "packetframe_fib_neigh_resolver_restarts_total{module=\"fast-path\"} 6",
            "packetframe_fib_neigh_resolver_running{module=\"fast-path\"} 1",
            "packetframe_fib_neigh_resolver_progress_age_seconds{module=\"fast-path\"} 7",
            "packetframe_fib_neigh_resolver_programmer_wait_seconds{module=\"fast-path\"} 0",
        ] {
            assert!(out.lines().any(|l| l == line), "missing {line}:\n{out}");
        }

        s.programmer_wait_since = Some(now + Duration::from_secs(2));
        let mut out = String::new();
        s.render_metrics(now + Duration::from_secs(7), &mut out);
        assert!(
            out.lines().any(|l| {
                l
                == "packetframe_fib_neigh_resolver_programmer_wait_seconds{module=\"fast-path\"} 5"
            }),
            "{out}"
        );
    }

    #[test]
    fn the_programmer_wait_guard_clears_and_counts_as_progress_when_dropped() {
        let shared = SharedResolverStatus::new(STALL_AFTER);
        let before = shared.progress().0;
        let guard = shared.programmer_wait();
        assert_eq!(shared.progress(), (before, true));
        drop(guard);
        assert_eq!(shared.progress(), (before + 1, false));
    }
}
