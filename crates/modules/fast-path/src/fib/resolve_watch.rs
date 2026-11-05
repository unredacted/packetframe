//! Why a next hop was slow to resolve, kept in the persistent event log.
//!
//! After the 2026-11-05 reboot of the reference gateway, the transit next
//! hop carrying ~486k routes stayed unresolved for minutes. The programmer
//! had asked the kernel to resolve it as the route ledger seed registered
//! it, and kept re-probing it on its backoff. But what each request did,
//! what the kernel answered and whether the egress link was up were only
//! in the journal (at debug, or rate-limited), and the RAM journal had
//! rotated by morning. Whether restoring saved neighbour MACs at a start
//! would be safe turns on that answer: a next hop that was not answering
//! ARP would have been restored as resolved, and VPP steered into it.
//!
//! So each next hop's unresolved stretch is watched, from its
//! registration or its loss to the next `Learned`. That stretch is an
//! [`Episode`]. Two events report it:
//!
//! - `nexthop_resolve_slow` (warn): it has been unresolved for
//!   [`SLOW_AFTER`].
//! - `nexthop_resolved_late` (info): a next hop that had the first event
//!   resolved.
//!
//! Each carries:
//! - what the programmer asked ([`Episode`]);
//! - what the resolver did with those requests ([`ProbeTally`], through the
//!   shared [`ProbeLog`]);
//! - what the kernel reported (`NUD_FAILED`, deletions, the last
//!   read-back);
//! - the egress link's state and its carrier changes since the first probe
//!   ([`LinkNow`]).
//!
//! Its `reading` ([`Reading`]) names the likeliest cause.
//!
//! **Bounded.** At most [`SLOW_EVENTS_PER_WINDOW`] slow events per
//! [`SLOW_EVENT_WINDOW`], taken from the next hops carrying the most
//! routes first. Each is followed by at most one resolved event. A next
//! hop that never resolves is reported once. Nothing here is per route or
//! periodic.
//!
//! Pure apart from the sysfs read in [`read_link`], so the tests run on
//! the macOS dev loop.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use packetframe_common::events::{kind, Event};

/// How long a next hop may stay unresolved before it is reported. A live
/// neighbour answers the first solicitation within a second. Thirty
/// seconds also covers the kernel's own retries (three solicitations a
/// second apart) and the first several re-probes.
pub const SLOW_AFTER: Duration = Duration::from_secs(30);
/// Slow events per [`SLOW_EVENT_WINDOW`]. A start with every transit and a
/// few large IX peers late fits; a fabric of small dead peers does not
/// fill the log.
pub const SLOW_EVENTS_PER_WINDOW: u32 = 16;
pub const SLOW_EVENT_WINDOW: Duration = Duration::from_secs(3600);
/// Next hops the resolver keeps a tally for. Only unresolved ones have
/// one, and the programmer takes each when it resolves or goes, so this
/// is a backstop against a leak, not a working limit.
const TALLY_CAP: usize = 16_384;

/// What started an episode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cause {
    /// Registered while the route ledger seed was going in: a next hop
    /// the last stop saved.
    Seed,
    /// Registered by a live route, or by an address that stopped being
    /// the router's own.
    New,
    /// It was resolved, and the kernel reported it failed or gone.
    Lost,
}

impl Cause {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::New => "new",
            Self::Lost => "lost",
        }
    }
}

/// The programmer's account of one unresolved stretch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Episode {
    pub since: Instant,
    pub cause: Cause,
    /// Resolve requests the programmer queued: the kick at registration
    /// and each re-probe.
    pub asked: u32,
    /// Requests the resolver's queue was too full to take.
    pub queue_full: u32,
    /// `NUD_FAILED` reports: a solicitation the kernel gave up on.
    pub kernel_failed: u32,
    /// Deletions the kernel reported.
    pub kernel_gone: u32,
    /// Whether `nexthop_resolve_slow` was emitted for it.
    pub reported: bool,
}

impl Episode {
    pub fn new(since: Instant, cause: Cause) -> Self {
        Self {
            since,
            cause,
            asked: 0,
            queue_full: 0,
            kernel_failed: 0,
            kernel_gone: 0,
            reported: false,
        }
    }

    /// A request the programmer tried to queue: `enqueued` false when the
    /// resolver's queue refused it.
    pub fn requested(&mut self, enqueued: bool) {
        if enqueued {
            self.asked = self.asked.saturating_add(1);
        } else {
            self.queue_full = self.queue_full.saturating_add(1);
        }
    }

    /// Unresolved for `after` ([`SLOW_AFTER`] in production) and not yet
    /// reported.
    pub fn is_slow(&self, now: Instant, after: Duration) -> bool {
        !self.reported && self.waited(now) >= after
    }

    pub fn waited(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.since)
    }
}

/// What the resolver did with one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// `RTM_NEWNEIGH NTF_USE` accepted: the kernel is soliciting.
    Kicked,
    /// The egress is an `ix-mode` interface: deliberately not solicited.
    Suppressed,
    /// No request socket (one stuck on `rtnl_lock` was retired): not
    /// asked.
    Skipped,
    /// The route lookup or the kick hit its timeout.
    TimedOut,
    /// The kernel's route lookup found no unicast egress.
    NoRoute,
    /// The kernel refused the kick.
    Failed,
}

/// The resolver's account of the requests it served for one unresolved
/// next hop.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProbeTally {
    /// When it served the first.
    pub first_served: Option<Instant>,
    pub kicked: u32,
    pub suppressed: u32,
    pub skipped: u32,
    pub timed_out: u32,
    pub no_route: u32,
    pub failed: u32,
    /// The egress device the kernel's route lookup last named.
    pub dev: Option<String>,
    /// That device's carrier-change count when it was first named.
    pub carrier_changes_at_first: Option<u64>,
    /// What the last read-back after a kick found: a NUD state name,
    /// `no entry`, `unsupported`, `timed out` or `error`.
    pub kernel: Option<&'static str>,
}

impl ProbeTally {
    pub fn served(&self) -> u32 {
        self.kicked
            .saturating_add(self.suppressed)
            .saturating_add(self.skipped)
            .saturating_add(self.timed_out)
            .saturating_add(self.no_route)
            .saturating_add(self.failed)
    }
}

/// The resolver's tallies, shared with the programmer through the
/// resolve handle. The resolver writes; the programmer reads a tally when
/// it reports, and takes it when the episode ends.
#[derive(Debug, Clone, Default)]
pub struct ProbeLog {
    inner: Arc<Mutex<HashMap<IpAddr, ProbeTally>>>,
}

impl ProbeLog {
    fn lock(&self) -> MutexGuard<'_, HashMap<IpAddr, ProbeTally>> {
        // A panic while holding it left a tally half-counted at worst.
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The resolver served a request for `ip` at `now` and this is what
    /// it did.
    pub fn record(&self, ip: IpAddr, probe: Probe, now: Instant) {
        let mut map = self.lock();
        if map.len() >= TALLY_CAP && !map.contains_key(&ip) {
            return;
        }
        let t = map.entry(ip).or_default();
        t.first_served.get_or_insert(now);
        let n = match probe {
            Probe::Kicked => &mut t.kicked,
            Probe::Suppressed => &mut t.suppressed,
            Probe::Skipped => &mut t.skipped,
            Probe::TimedOut => &mut t.timed_out,
            Probe::NoRoute => &mut t.no_route,
            Probe::Failed => &mut t.failed,
        };
        *n = n.saturating_add(1);
    }

    /// The route lookup for `ip` named `dev`. The carrier-change count is
    /// kept from the first time each device is named, so a later report
    /// can say whether the link bounced meanwhile.
    pub fn egress(&self, ip: IpAddr, dev: &str, carrier_changes: Option<u64>) {
        let mut map = self.lock();
        let Some(t) = map.get_mut(&ip) else {
            return;
        };
        if t.dev.as_deref() != Some(dev) {
            t.dev = Some(dev.to_string());
            t.carrier_changes_at_first = carrier_changes;
        }
    }

    /// What the read-back after a kick found.
    pub fn kernel_answer(&self, ip: IpAddr, answer: &'static str) {
        if let Some(t) = self.lock().get_mut(&ip) {
            t.kernel = Some(answer);
        }
    }

    pub fn get(&self, ip: &IpAddr) -> Option<ProbeTally> {
        self.lock().get(ip).cloned()
    }

    /// End `ip`'s tally: it resolved, or it is no longer a next hop.
    pub fn take(&self, ip: &IpAddr) -> Option<ProbeTally> {
        self.lock().remove(ip)
    }

    /// Drop the tallies of next hops `keep` rejects: requests the
    /// resolver served after the programmer had already let the next hop
    /// go.
    pub fn retain(&self, mut keep: impl FnMut(&IpAddr) -> bool) {
        self.lock().retain(|ip, _| keep(ip));
    }

    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }
}

/// An egress link as sysfs shows it now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinkNow {
    /// `operstate`: `up`, `down`, `lowerlayerdown`, `dormant`, `unknown`…
    pub operstate: Option<String>,
    /// `carrier_changes`: the kernel's count of carrier transitions.
    pub carrier_changes: Option<u64>,
}

impl LinkNow {
    /// A state that says the link cannot carry a solicitation. `unknown`
    /// is not one: drivers that do not report operstate show it on a
    /// working link.
    fn down(&self) -> Option<&str> {
        match self.operstate.as_deref() {
            Some(s @ ("down" | "lowerlayerdown" | "notpresent" | "dormant" | "testing")) => Some(s),
            _ => None,
        }
    }
}

const SYS_CLASS_NET: &str = "/sys/class/net";

/// `dev`'s state from `/sys/class/net`.
pub fn read_link(dev: &str) -> LinkNow {
    read_link_at(Path::new(SYS_CLASS_NET), dev)
}

/// `dev`'s carrier-change count, the one value the resolver keeps.
pub fn carrier_changes(dev: &str) -> Option<u64> {
    read_link_at(Path::new(SYS_CLASS_NET), dev).carrier_changes
}

/// [`read_link`] under `root`. A name the kernel would not give a device
/// (empty, `.`, `..`, or with a `/`) reads as nothing known.
pub fn read_link_at(root: &Path, dev: &str) -> LinkNow {
    if dev.is_empty() || dev == "." || dev == ".." || dev.contains('/') {
        return LinkNow::default();
    }
    let dir = root.join(dev);
    let read = |name: &str| {
        std::fs::read_to_string(dir.join(name))
            .ok()
            .map(|s| s.trim().to_string())
    };
    LinkNow {
        operstate: read("operstate").filter(|s| !s.is_empty()),
        carrier_changes: read("carrier_changes").and_then(|s| s.parse().ok()),
    }
}

/// The name of the device with `ifindex` now, or `ifindex <n>` when no
/// device has it (or the lookup failed): an event names the device
/// either way.
#[cfg(unix)]
pub fn ifname(ifindex: u32) -> String {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: a buffer of IF_NAMESIZE, which the call NUL-terminates.
    let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr()) };
    if p.is_null() {
        return format!("ifindex {ifindex}");
    }
    // SAFETY: NUL-terminated by the call above, within `buf`.
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    name.to_string_lossy().into_owned()
}

/// The likeliest reason a next hop is, or was, slow, judged from the
/// first cause that explains the rest. Its code is the event's `reading`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// Every request found the resolver's queue full.
    QueueFull,
    /// The resolver served no request for it: still starting, or behind.
    NotServed,
    /// The egress link is not up.
    LinkDown(String),
    /// The egress link changed carrier meanwhile.
    LinkFlapped(u64),
    /// Every request was skipped for want of a request socket.
    ProbesSkipped,
    /// Every request timed out.
    ProbesTimedOut,
    /// The kernel had no route to it.
    NoRoute,
    /// The egress is `ix-mode`: not solicited, left to the snooper.
    IxMode,
    /// The kernel solicited it and gave up this many times.
    Unanswered(u32),
    /// The kernel was asked to solicit it and reported nothing back.
    Pending,
    /// Every request to the kernel was refused.
    RequestsFailed,
}

impl Reading {
    pub fn code(&self) -> &'static str {
        match self {
            Self::QueueFull => "queue-full",
            Self::NotServed => "not-served",
            Self::LinkDown(_) => "link-down",
            Self::LinkFlapped(_) => "link-flapped",
            Self::ProbesSkipped => "probes-skipped",
            Self::ProbesTimedOut => "probes-timed-out",
            Self::NoRoute => "no-route",
            Self::IxMode => "ix-mode",
            Self::Unanswered(_) => "unanswered",
            Self::Pending => "pending",
            Self::RequestsFailed => "requests-failed",
        }
    }

    pub fn sentence(&self, dev: &str) -> String {
        match self {
            Self::QueueFull => "every request found the resolver's queue full".into(),
            Self::NotServed => {
                "the resolver served none of its requests (still starting, or behind)".into()
            }
            Self::LinkDown(state) => format!("its egress {dev} is {state}"),
            Self::LinkFlapped(n) => format!("its egress {dev} changed carrier {n} times meanwhile"),
            Self::ProbesSkipped => {
                "every probe was skipped: no request socket (one was stuck on rtnl_lock)".into()
            }
            Self::ProbesTimedOut => {
                "every probe timed out (rtnl_lock held, or the replies dropped)".into()
            }
            Self::NoRoute => "the kernel had no route to it".into(),
            Self::IxMode => {
                format!("its egress {dev} is ix-mode: not solicited, the snooper seeds it")
            }
            Self::Unanswered(n) => {
                format!("the kernel solicited it on {dev} and got no answer ({n} NUD_FAILED)")
            }
            Self::Pending => {
                format!("the kernel was asked to solicit it on {dev} and reported nothing back")
            }
            Self::RequestsFailed => "the kernel refused every request to solicit it".into(),
        }
    }
}

/// Everything known about one slow next hop at one moment.
#[derive(Debug, Clone)]
pub struct Report<'a> {
    pub nexthop: IpAddr,
    /// Routes through it (its refcount) now.
    pub routes: u32,
    pub episode: &'a Episode,
    pub tally: Option<&'a ProbeTally>,
    /// The tally's egress as sysfs shows it now; `None` when the route
    /// lookup never named one.
    pub link: Option<&'a LinkNow>,
    pub now: Instant,
}

impl Report<'_> {
    fn dev(&self) -> &str {
        self.tally.and_then(|t| t.dev.as_deref()).unwrap_or("none")
    }

    /// Carrier transitions on the egress since it was first named.
    fn carrier_delta(&self) -> Option<u64> {
        let first = self.tally?.carrier_changes_at_first?;
        let now = self.link?.carrier_changes?;
        Some(now.saturating_sub(first))
    }

    pub fn reading(&self) -> Reading {
        let e = self.episode;
        let t = self.tally.cloned().unwrap_or_default();
        if t.served() == 0 {
            if e.asked == 0 && e.queue_full > 0 {
                return Reading::QueueFull;
            }
            return Reading::NotServed;
        }
        if let Some(state) = self.link.and_then(LinkNow::down) {
            return Reading::LinkDown(state.to_string());
        }
        if let Some(n) = self.carrier_delta().filter(|n| *n > 0) {
            return Reading::LinkFlapped(n);
        }
        if t.kicked > 0 {
            return if e.kernel_failed > 0 {
                Reading::Unanswered(e.kernel_failed)
            } else {
                Reading::Pending
            };
        }
        if t.suppressed > 0 {
            return Reading::IxMode;
        }
        if t.no_route > 0 {
            return Reading::NoRoute;
        }
        if t.skipped > 0 && t.skipped >= t.timed_out {
            return Reading::ProbesSkipped;
        }
        if t.timed_out > 0 {
            return Reading::ProbesTimedOut;
        }
        Reading::RequestsFailed
    }

    /// The fields both events carry.
    fn fields(&self, ev: Event, reading: &Reading) -> Event {
        let e = self.episode;
        let t = self.tally.cloned().unwrap_or_default();
        let mut ev = ev
            .field("nexthop", self.nexthop.to_string())
            .field("routes", self.routes)
            .field("cause", e.cause.as_str())
            .field("waited_secs", e.waited(self.now).as_secs())
            .field("reading", reading.code())
            .field("asked", e.asked)
            .field("queue_full", e.queue_full)
            .field("served", t.served())
            .field("kicked", t.kicked)
            .field("suppressed", t.suppressed)
            .field("skipped", t.skipped)
            .field("timed_out", t.timed_out)
            .field("no_route", t.no_route)
            .field("probe_failed", t.failed)
            .field("kernel_failed", e.kernel_failed)
            .field("kernel_gone", e.kernel_gone)
            .field("kernel", t.kernel.unwrap_or("not read"))
            .field("dev", self.dev())
            .field(
                "link",
                self.link
                    .and_then(|l| l.operstate.clone())
                    .unwrap_or_else(|| "unknown".into()),
            );
        if let Some(first) = t.first_served {
            ev = ev.field(
                "first_served_secs",
                first.saturating_duration_since(e.since).as_secs(),
            );
        }
        if let Some(n) = self.carrier_delta() {
            ev = ev.field("carrier_changes", n);
        }
        ev
    }

    /// `nexthop_resolve_slow`. `slow_now` is how many next hops are past
    /// [`SLOW_AFTER`] at this moment, this one included.
    pub fn slow_event(&self, module: &str, slow_now: usize) -> Event {
        let reading = self.reading();
        let detail = format!(
            "next hop {} ({} routes) unresolved for {} s: {}",
            self.nexthop,
            self.routes,
            self.episode.waited(self.now).as_secs(),
            reading.sentence(self.dev()),
        );
        self.fields(Event::warn(module, kind::NEXTHOP_RESOLVE_SLOW), &reading)
            .field("slow_nexthops", slow_now as u64)
            .detail(detail)
    }

    /// `nexthop_resolved_late`, on `resolved_dev`.
    pub fn resolved_event(&self, module: &str, resolved_dev: &str) -> Event {
        let reading = self.reading();
        let detail = format!(
            "next hop {} ({} routes) resolved on {} after {} s; while slow, {}",
            self.nexthop,
            self.routes,
            resolved_dev,
            self.episode.waited(self.now).as_secs(),
            reading.sentence(self.dev()),
        );
        self.fields(Event::info(module, kind::NEXTHOP_RESOLVED_LATE), &reading)
            .field("resolved_dev", resolved_dev)
            .detail(detail)
    }
}

/// [`SLOW_EVENTS_PER_WINDOW`] per [`SLOW_EVENT_WINDOW`], the window
/// starting at the first event after the last one closed.
#[derive(Debug, Default)]
pub struct Budget {
    window_start: Option<Instant>,
    used: u32,
}

impl Budget {
    /// Whether an event may be emitted now; counts it if so.
    pub fn admit(&mut self, now: Instant) -> bool {
        if !self.available(now) {
            return false;
        }
        match self.window_start {
            Some(t) if now.saturating_duration_since(t) < SLOW_EVENT_WINDOW => self.used += 1,
            _ => {
                self.window_start = Some(now);
                self.used = 1;
            }
        }
        true
    }

    /// Whether [`Self::admit`] would say yes, without counting.
    pub fn available(&self, now: Instant) -> bool {
        match self.window_start {
            Some(t) if now.saturating_duration_since(t) < SLOW_EVENT_WINDOW => {
                self.used < SLOW_EVENTS_PER_WINDOW
            }
            _ => true,
        }
    }
}

/// Which of the slow next hops to report now, most routes first:
/// `candidates` are `(next hop, routes)` past [`SLOW_AFTER`] and not yet
/// reported. Ties go to the lower address, so the order is stable.
pub fn by_routes(mut candidates: Vec<(IpAddr, u32)>) -> Vec<(IpAddr, u32)> {
    candidates.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    candidates
}

/// The resolver's name for a `NeighbourState`, as `ip neigh` prints it,
/// lowercased. Taken as the `u16` the kernel sends.
pub fn nud_name(state: u16) -> &'static str {
    match state {
        0x00 => "none",
        0x01 => "incomplete",
        0x02 => "reachable",
        0x04 => "stale",
        0x08 => "delay",
        0x10 => "probe",
        0x20 => "failed",
        0x40 => "noarp",
        0x80 => "permanent",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const MODULE: &str = "fast-path";

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(194, 110, 60, last))
    }

    fn record(ev: Event) -> serde_json::Map<String, serde_json::Value> {
        ev.into_record().fields
    }

    #[test]
    fn an_episode_is_slow_once_after_the_threshold_and_not_again() {
        let t0 = Instant::now();
        let mut e = Episode::new(t0, Cause::Seed);
        assert!(!e.is_slow(t0 + SLOW_AFTER - Duration::from_millis(1), SLOW_AFTER));
        assert!(e.is_slow(t0 + SLOW_AFTER, SLOW_AFTER));
        e.reported = true;
        assert!(!e.is_slow(t0 + SLOW_AFTER * 10, SLOW_AFTER));

        e.requested(true);
        e.requested(false);
        e.requested(true);
        assert_eq!((e.asked, e.queue_full), (2, 1));
    }

    #[test]
    fn the_probe_log_tallies_what_the_resolver_did_and_where() {
        let log = ProbeLog::default();
        let t0 = Instant::now();
        let nh = ip(50);

        // Facts about a next hop the resolver has not served are dropped.
        log.egress(nh, "eth3", Some(4));
        log.kernel_answer(nh, "incomplete");
        assert!(log.is_empty());

        log.record(nh, Probe::Skipped, t0);
        log.record(nh, Probe::Kicked, t0 + Duration::from_secs(5));
        log.egress(nh, "eth3", Some(4));
        log.record(nh, Probe::Kicked, t0 + Duration::from_secs(7));
        // Named again with a later count: the first one stays.
        log.egress(nh, "eth3", Some(9));
        log.kernel_answer(nh, "incomplete");

        let t = log.get(&nh).expect("a tally");
        assert_eq!(t.first_served, Some(t0));
        assert_eq!((t.kicked, t.skipped, t.served()), (2, 1, 3));
        assert_eq!(t.dev.as_deref(), Some("eth3"));
        assert_eq!(t.carrier_changes_at_first, Some(4));
        assert_eq!(t.kernel, Some("incomplete"));

        // A different egress starts its own carrier count.
        log.egress(nh, "eth4", Some(1));
        let t = log.get(&nh).unwrap();
        assert_eq!(
            (t.dev.as_deref(), t.carrier_changes_at_first),
            (Some("eth4"), Some(1))
        );

        log.record(ip(51), Probe::NoRoute, t0);
        log.retain(|a| *a == nh);
        assert_eq!(log.len(), 1);
        assert!(log.take(&nh).is_some());
        assert!(log.take(&nh).is_none());
    }

    #[test]
    fn the_link_is_read_from_sysfs_and_a_bad_name_reads_nothing() {
        let root = std::env::temp_dir().join(format!(
            "pf-resolve-watch-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let dev = root.join("eth3");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("operstate"), "up\n").unwrap();
        std::fs::write(dev.join("carrier_changes"), "6\n").unwrap();

        let l = read_link_at(&root, "eth3");
        assert_eq!(l.operstate.as_deref(), Some("up"));
        assert_eq!(l.carrier_changes, Some(6));
        assert_eq!(l.down(), None);

        assert_eq!(read_link_at(&root, "eth9"), LinkNow::default());
        for bad in ["", ".", "..", "../eth3", "eth3/.."] {
            assert_eq!(read_link_at(&root, bad), LinkNow::default(), "{bad}");
        }

        std::fs::write(dev.join("operstate"), "lowerlayerdown\n").unwrap();
        assert_eq!(read_link_at(&root, "eth3").down(), Some("lowerlayerdown"));
        std::fs::write(dev.join("operstate"), "unknown\n").unwrap();
        assert_eq!(read_link_at(&root, "eth3").down(), None);

        std::fs::remove_dir_all(&root).unwrap();
    }

    fn tally(f: impl FnOnce(&mut ProbeTally)) -> ProbeTally {
        let mut t = ProbeTally {
            first_served: Some(Instant::now()),
            dev: Some("eth3".into()),
            carrier_changes_at_first: Some(4),
            ..ProbeTally::default()
        };
        f(&mut t);
        t
    }

    fn reading(e: &Episode, t: Option<&ProbeTally>, link: Option<&LinkNow>) -> Reading {
        Report {
            nexthop: ip(50),
            routes: 1,
            episode: e,
            tally: t,
            link,
            now: Instant::now(),
        }
        .reading()
    }

    #[test]
    fn the_reading_names_the_first_cause_that_explains_the_rest() {
        let t0 = Instant::now();
        let mut e = Episode::new(t0, Cause::Seed);
        let up = LinkNow {
            operstate: Some("up".into()),
            carrier_changes: Some(4),
        };

        // Never reached the resolver.
        e.queue_full = 3;
        assert_eq!(reading(&e, None, None), Reading::QueueFull);
        e.asked = 1;
        assert_eq!(reading(&e, None, None), Reading::NotServed);

        // The link explains everything after it.
        let kicked = tally(|t| t.kicked = 4);
        e.kernel_failed = 4;
        let down = LinkNow {
            operstate: Some("down".into()),
            carrier_changes: Some(5),
        };
        assert_eq!(
            reading(&e, Some(&kicked), Some(&down)),
            Reading::LinkDown("down".into())
        );
        let bounced = LinkNow {
            operstate: Some("up".into()),
            carrier_changes: Some(6),
        };
        assert_eq!(
            reading(&e, Some(&kicked), Some(&bounced)),
            Reading::LinkFlapped(2)
        );

        // Solicited on a steady link: answered or not.
        assert_eq!(
            reading(&e, Some(&kicked), Some(&up)),
            Reading::Unanswered(4)
        );
        e.kernel_failed = 0;
        assert_eq!(reading(&e, Some(&kicked), Some(&up)), Reading::Pending);

        // Never solicited.
        let ix = tally(|t| t.suppressed = 2);
        assert_eq!(reading(&e, Some(&ix), Some(&up)), Reading::IxMode);
        let unroutable = tally(|t| t.no_route = 2);
        assert_eq!(reading(&e, Some(&unroutable), None), Reading::NoRoute);
        let skipped = tally(|t| {
            t.skipped = 3;
            t.timed_out = 1;
        });
        assert_eq!(reading(&e, Some(&skipped), None), Reading::ProbesSkipped);
        let timed_out = tally(|t| {
            t.skipped = 1;
            t.timed_out = 3;
        });
        assert_eq!(reading(&e, Some(&timed_out), None), Reading::ProbesTimedOut);
        let refused = tally(|t| t.failed = 2);
        assert_eq!(reading(&e, Some(&refused), None), Reading::RequestsFailed);
    }

    #[test]
    fn the_slow_event_carries_what_was_asked_done_and_answered() {
        let t0 = Instant::now();
        let mut e = Episode::new(t0, Cause::Seed);
        e.asked = 7;
        e.kernel_failed = 5;
        let t = ProbeTally {
            first_served: Some(t0 + Duration::from_secs(12)),
            kicked: 6,
            skipped: 1,
            dev: Some("eth3".into()),
            carrier_changes_at_first: Some(4),
            kernel: Some("incomplete"),
            ..ProbeTally::default()
        };
        let link = LinkNow {
            operstate: Some("up".into()),
            carrier_changes: Some(4),
        };
        let r = Report {
            nexthop: ip(50),
            routes: 486_318,
            episode: &e,
            tally: Some(&t),
            link: Some(&link),
            now: t0 + Duration::from_secs(31),
        };
        let ev = r.slow_event(MODULE, 3);
        assert_eq!(ev.kind(), kind::NEXTHOP_RESOLVE_SLOW);
        let rec = ev.into_record();
        assert_eq!(rec.level, packetframe_common::events::Level::Warn);
        let f = rec.fields;
        for (k, v) in [
            ("nexthop", serde_json::json!("194.110.60.50")),
            ("routes", serde_json::json!(486_318)),
            ("cause", serde_json::json!("seed")),
            ("waited_secs", serde_json::json!(31)),
            ("reading", serde_json::json!("unanswered")),
            ("asked", serde_json::json!(7)),
            ("queue_full", serde_json::json!(0)),
            ("served", serde_json::json!(7)),
            ("kicked", serde_json::json!(6)),
            ("skipped", serde_json::json!(1)),
            ("kernel_failed", serde_json::json!(5)),
            ("kernel", serde_json::json!("incomplete")),
            ("dev", serde_json::json!("eth3")),
            ("link", serde_json::json!("up")),
            ("first_served_secs", serde_json::json!(12)),
            ("carrier_changes", serde_json::json!(0)),
            ("slow_nexthops", serde_json::json!(3)),
        ] {
            assert_eq!(f.get(k), Some(&v), "{k}");
        }
        let detail = f["detail"].as_str().unwrap();
        assert!(detail.contains("194.110.60.50 (486318 routes) unresolved for 31 s"));
        assert!(detail.contains("got no answer (5 NUD_FAILED)"), "{detail}");
    }

    #[test]
    fn a_next_hop_the_resolver_never_served_says_so_and_names_no_device() {
        let t0 = Instant::now();
        let mut e = Episode::new(t0, Cause::Lost);
        e.asked = 2;
        let r = Report {
            nexthop: ip(50),
            routes: 10,
            episode: &e,
            tally: None,
            link: None,
            now: t0 + Duration::from_secs(40),
        };
        let f = record(r.slow_event(MODULE, 1));
        assert_eq!(f["reading"], "not-served");
        assert_eq!(f["cause"], "lost");
        assert_eq!(f["served"], 0);
        assert_eq!(f["dev"], "none");
        assert_eq!(f["link"], "unknown");
        assert_eq!(f["kernel"], "not read");
        assert!(!f.contains_key("first_served_secs"));
        assert!(!f.contains_key("carrier_changes"));
    }

    #[test]
    fn the_resolved_event_says_where_and_after_how_long() {
        let t0 = Instant::now();
        let mut e = Episode::new(t0, Cause::Seed);
        e.reported = true;
        e.kernel_failed = 40;
        let t = tally(|t| t.kicked = 42);
        let link = LinkNow {
            operstate: Some("up".into()),
            carrier_changes: Some(4),
        };
        let r = Report {
            nexthop: ip(50),
            routes: 486_318,
            episode: &e,
            tally: Some(&t),
            link: Some(&link),
            now: t0 + Duration::from_secs(301),
        };
        let ev = r.resolved_event(MODULE, "eth3");
        assert_eq!(ev.kind(), kind::NEXTHOP_RESOLVED_LATE);
        let rec = ev.into_record();
        assert_eq!(rec.level, packetframe_common::events::Level::Info);
        assert_eq!(rec.fields["resolved_dev"], "eth3");
        assert_eq!(rec.fields["waited_secs"], 301);
        assert_eq!(rec.fields["reading"], "unanswered");
        assert!(!rec.fields.contains_key("slow_nexthops"));
        let detail = rec.fields["detail"].as_str().unwrap();
        assert!(
            detail
                .starts_with("next hop 194.110.60.50 (486318 routes) resolved on eth3 after 301 s"),
            "{detail}"
        );
    }

    #[test]
    fn the_budget_admits_a_window_s_worth_then_waits_for_the_next() {
        let t0 = Instant::now();
        let mut b = Budget::default();
        for i in 0..SLOW_EVENTS_PER_WINDOW {
            assert!(b.admit(t0 + Duration::from_secs(u64::from(i))), "{i}");
        }
        let late = t0 + SLOW_EVENT_WINDOW - Duration::from_secs(1);
        assert!(!b.available(late));
        assert!(!b.admit(late));
        assert!(b.admit(t0 + SLOW_EVENT_WINDOW));
        assert_eq!(b.used, 1);
    }

    #[test]
    fn the_next_hops_with_the_most_routes_are_reported_first() {
        let order = by_routes(vec![
            (ip(9), 12),
            (ip(50), 486_318),
            (ip(1), 12),
            (ip(7), 900),
        ]);
        assert_eq!(
            order,
            vec![(ip(50), 486_318), (ip(7), 900), (ip(1), 12), (ip(9), 12)]
        );
    }

    #[test]
    fn a_device_is_named_and_a_missing_one_by_its_index() {
        assert_eq!(ifname(0), "ifindex 0");
        // The loopback is index 1 on Linux and macOS alike.
        assert!(ifname(1).starts_with("lo"), "{}", ifname(1));
    }

    #[test]
    fn nud_states_read_as_ip_neigh_names_them() {
        assert_eq!(nud_name(0x01), "incomplete");
        assert_eq!(nud_name(0x20), "failed");
        assert_eq!(nud_name(0x00), "none");
        assert_eq!(nud_name(0x200), "other");
    }
}
