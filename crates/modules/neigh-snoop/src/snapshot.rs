//! The engine's published view, read by metrics and health. Portable
//! so both renderers are tested on macOS against synthetic snapshots.
//! Every counter is a closed-label array indexed by an enum defined
//! here or in `frame`/`table`; metrics iterate the arrays, so a
//! counter added to an enum renders without touching the renderer.

use std::net::IpAddr;

use crate::frame::{Reject, Source};
use crate::table::{FilterReject, SkipReason};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LinkState {
    /// No device of that name exists (yet). Normal during a provision.
    #[default]
    Absent,
    Down,
    Up,
}

impl LinkState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Down => "down",
            Self::Up => "up",
        }
    }
}

/// `resolved / total`; `fraction` is `None` when nothing is measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ratio {
    pub resolved: u64,
    pub total: u64,
}

impl Ratio {
    pub fn fraction(&self) -> Option<f64> {
        (self.total > 0).then(|| self.resolved as f64 / self.total as f64)
    }
}

/// One kernel-route next-hop coverage sample for a bridge.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Coverage {
    pub nexthops: Ratio,
    /// Up to a few dozen unresolved next-hops, for the health message.
    pub unresolved_sample: Vec<IpAddr>,
    pub nexthop_objects: u64,
    pub routes_seen: u64,
    pub dump_ms: u64,
    pub age_secs: u64,
}

/// Route coverage has three honest states; collapsing "not yet" and
/// "cannot" into one would let a broken dump read as a fresh start.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CoverageState {
    #[default]
    Pending,
    Unavailable(String),
    Measured(Coverage),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearnOutcome {
    New,
    Refreshed,
    MacChanged,
    Evicted,
    /// Installed for another address of a declared peer because a MAC
    /// was learned for one of its addresses (one MAC per member port).
    Derived,
}

impl LearnOutcome {
    pub const COUNT: usize = 5;
    pub const LABELS: [&'static str; Self::COUNT] =
        ["new", "refreshed", "mac_changed", "evicted", "derived"];
    pub fn index(self) -> usize {
        match self {
            Self::New => 0,
            Self::Refreshed => 1,
            Self::MacChanged => 2,
            Self::Evicted => 3,
            Self::Derived => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Sent to the kernel (diagnostic; the real number is `Confirmed`).
    Requested,
    /// The RTM_NEWNEIGH echo arrived with our MAC and STALE.
    Confirmed,
    /// No echo within the confirmation window.
    Unconfirmed,
    /// Netlink returned an error.
    Failed,
    /// The echo carried a different MAC: the kernel learned something
    /// else between our request and its answer.
    Overridden,
    Skipped(SkipReason),
}

impl InstallOutcome {
    pub const COUNT: usize = 5 + SkipReason::COUNT;
    pub const LABELS: [&'static str; Self::COUNT] = [
        "requested",
        "confirmed",
        "unconfirmed",
        "failed",
        "overridden",
        "skipped_same_mac",
        "skipped_permanent",
        "skipped_noarp",
        "skipped_unknown_state",
        "skipped_holddown",
        "mac_conflict",
    ];
    pub fn index(self) -> usize {
        match self {
            Self::Requested => 0,
            Self::Confirmed => 1,
            Self::Unconfirmed => 2,
            Self::Failed => 3,
            Self::Overridden => 4,
            Self::Skipped(s) => 5 + s.index(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedOutcome {
    Requested,
    Confirmed,
    /// No RTM_NEWNEIGH echo inside the confirmation window.
    Unconfirmed,
    /// The netlink write itself was refused.
    Failed,
    /// Dropped at load for exceeding `seed-max-age`.
    Expired,
    /// Persisted entries the file held but which did not parse.
    BadEntry,
}

impl SeedOutcome {
    pub const COUNT: usize = 6;
    pub const LABELS: [&'static str; Self::COUNT] = [
        "requested",
        "confirmed",
        "unconfirmed",
        "failed",
        "expired",
        "bad_entry",
    ];
    pub fn index(self) -> usize {
        match self {
            Self::Requested => 0,
            Self::Confirmed => 1,
            Self::Unconfirmed => 2,
            Self::Failed => 3,
            Self::Expired => 4,
            Self::BadEntry => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistOutcome {
    Written,
    Failed,
}

impl PersistOutcome {
    pub const COUNT: usize = 2;
    pub const LABELS: [&'static str; Self::COUNT] = ["written", "failed"];
    pub fn index(self) -> usize {
        match self {
            Self::Written => 0,
            Self::Failed => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkEvent {
    Up,
    Down,
    /// Same name, new ifindex: the device was destroyed and recreated.
    Recreated,
}

impl LinkEvent {
    pub const COUNT: usize = 3;
    pub const LABELS: [&'static str; Self::COUNT] = ["up", "down", "recreated"];
    pub fn index(self) -> usize {
        match self {
            Self::Up => 0,
            Self::Down => 1,
            Self::Recreated => 2,
        }
    }
}

/// Per-bridge counters. Arrays are indexed by the enums' `index()`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Counters {
    pub frames: [u64; Source::COUNT],
    pub learn: [u64; LearnOutcome::COUNT],
    pub filter_rejects: [u64; FilterReject::COUNT],
    pub parse_rejects: [u64; Reject::COUNT],
    pub installs: [u64; InstallOutcome::COUNT],
    pub seeds: [u64; SeedOutcome::COUNT],
    pub persist: [u64; PersistOutcome::COUNT],
    pub link_events: [u64; LinkEvent::COUNT],
    pub socket_errors: u64,
    /// Frames the kernel marked outgoing that still reached us (the
    /// filter should make this zero; non-zero means the filter is not
    /// attached).
    pub frames_outgoing_dropped: u64,
    /// Frames dropped because the engine's inbound channel was full.
    pub frames_backpressure_dropped: u64,
}

impl Counters {
    pub fn frame(&mut self, s: Source) {
        self.frames[s.index()] += 1;
    }
    pub fn learn(&mut self, o: LearnOutcome) {
        self.learn[o.index()] += 1;
    }
    pub fn filter_reject(&mut self, r: FilterReject) {
        self.filter_rejects[r.index()] += 1;
    }
    pub fn parse_reject(&mut self, r: &Reject) {
        self.parse_rejects[r.index()] += 1;
    }
    pub fn install(&mut self, o: InstallOutcome) {
        self.installs[o.index()] += 1;
    }
    pub fn seed(&mut self, o: SeedOutcome) {
        self.seeds[o.index()] += 1;
    }
    pub fn persist(&mut self, o: PersistOutcome) {
        self.persist[o.index()] += 1;
    }
    pub fn link_event(&mut self, e: LinkEvent) {
        self.link_events[e.index()] += 1;
    }
}

/// One bridge's state as of the snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IfaceSnapshot {
    pub name: String,
    pub ifindex: Option<u32>,
    pub link: LinkState,
    /// The kernel echoed `IFF_PROMISC` for the device after our
    /// membership request.
    pub promisc_confirmed: bool,
    pub socket_error: Option<String>,
    /// Seconds since the last learnable frame, or since the link came
    /// up if none has arrived yet. `None` while the link is not up.
    pub silent_secs: Option<u64>,
    pub table_entries: u64,
    pub install_backlog: u64,
    pub peers_total: u64,
    pub never_heard: Vec<IpAddr>,
    pub route_coverage: CoverageState,
    /// Learned-table entries whose kernel entry resolves.
    pub participant_coverage: Ratio,
    pub counters: Counters,
}

/// One reconcile tick's verdict for the FRR next-hop gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    /// Lists already matched; nothing written.
    Noop,
    /// Commands applied and the readback matched.
    Changed,
    /// The lists had been emptied by an FRR reload and were refilled.
    ReloadRefill,
    /// vtysh failed, the lists were absent, or the readback mismatched.
    Failed,
}

impl GateOutcome {
    pub const COUNT: usize = 4;
    pub const LABELS: [&'static str; Self::COUNT] = ["noop", "changed", "reload_refill", "failed"];
    pub fn index(self) -> usize {
        match self {
            Self::Noop => 0,
            Self::Changed => 1,
            Self::ReloadRefill => 2,
            Self::Failed => 3,
        }
    }
}

/// The gate reconciler's last published state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GateSnapshot {
    pub lists_present: bool,
    pub permitted_v4: u64,
    pub permitted_v6: u64,
    pub pending_removals: u64,
    pub last_change_age_secs: Option<u64>,
    pub vtysh_ms: u64,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    pub outcomes: [u64; GateOutcome::COUNT],
    pub age_secs: u64,
}

/// One route server's received-routes coverage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsCoverageSnapshot {
    pub rs: IpAddr,
    pub bridge: String,
    pub received_prefixes: u64,
    pub nexthops: Ratio,
    pub unresolved_nexthops: Vec<IpAddr>,
    /// Prefixes whose next-hop is neither a bilateral peer nor
    /// resolved: the real cost of passive learning, in prefixes.
    pub demoted_prefixes: u64,
    pub dump_ms: u64,
    pub age_secs: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub bridges: Vec<IfaceSnapshot>,
    /// `Some` only when `frr-gate` is configured.
    pub gate: Option<GateSnapshot>,
    /// One per `route-server` peer, sorted by address.
    pub rs: Vec<RsCoverageSnapshot>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_distinct_and_indices_dense() {
        fn check(labels: &[&str]) {
            let mut l = labels.to_vec();
            l.sort_unstable();
            l.dedup();
            assert_eq!(l.len(), labels.len(), "{labels:?}");
        }
        check(&LearnOutcome::LABELS);
        check(&InstallOutcome::LABELS);
        check(&SeedOutcome::LABELS);
        check(&PersistOutcome::LABELS);
        check(&LinkEvent::LABELS);
        check(&GateOutcome::LABELS);
        for (i, s) in [
            SkipReason::SameMac,
            SkipReason::Permanent,
            SkipReason::Noarp,
            SkipReason::UnknownState,
            SkipReason::Holddown,
            SkipReason::MacConflict,
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(InstallOutcome::Skipped(s).index(), 5 + i);
        }
        assert_eq!(
            InstallOutcome::LABELS[InstallOutcome::Skipped(SkipReason::MacConflict).index()],
            "mac_conflict"
        );
    }

    #[test]
    fn ratio_fraction() {
        assert_eq!(Ratio::default().fraction(), None);
        assert_eq!(
            Ratio {
                resolved: 1,
                total: 4
            }
            .fraction(),
            Some(0.25)
        );
    }
}
