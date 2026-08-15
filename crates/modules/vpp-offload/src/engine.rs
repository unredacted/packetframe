//! The convergence engine: everything that talks to VPP's binary API on
//! the supervisor's behalf.
//!
//! [`crate::supervisor`] decides *what* should happen and
//! [`crate::driver`] decides *when*; this is the half that actually
//! does it. It owns the transport, the route ledger, the pending map and
//! the port-index mapping, and exposes the operations the supervision
//! loop's `Effects`/`Observe` seams are defined in terms of: connect,
//! ping, attach devices, resync, verify.
//!
//! Split out from the process and resource lifecycle deliberately.
//! Everything here is reachable over a unix socket, which means all of
//! it is testable on host CI against a fake VPP speaking the real wire
//! format — and the pieces that are *not* (fork/exec, pidfd, sysfs VF
//! writes) are Linux-only and untestable on a dev laptop. Keeping the
//! two apart is what lets the interesting logic be tested at all.
//!
//! ## The resync is a diff, not a replay
//!
//! `begin_resync` walks the route source and also computes
//! **withdrawals**: prefixes the ledger holds that the source no longer
//! advertises. An add-only resync is the failure the plan calls out by
//! name — a route withdrawn while VPP (or packetframe) was down stays in
//! VPP's FIB, forwarding to a nexthop nobody advertises, and readback
//! verification cannot catch it because verification samples what the
//! ledger claims and the ledger claims that route is fine.
//!
//! ## Nothing is claimed before VPP acknowledges it
//!
//! The engine never marks a route installed, an interface attached, or a
//! FIB verified on its own authority; every one of those comes back from
//! the transport. That is not a style preference — it is the single
//! defect shape that produced most of this phase's review findings, and
//! the ledger's four-valued state exists precisely so the
//! not-yet-acknowledged case has somewhere honest to live.

use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;

use packetframe_common::fib::IpPrefix;

use crate::attach::{attach_ports, AttachError, AttachMode, AttachedPort, PortAttach};
use crate::fib_sync::{from_prefix, to_address};
use crate::fib_sync::{DrainStats, Drainer, FamilyPolicy, PortIndex, ResolvedPath, DEFAULT_WINDOW};
use crate::sink::{Capacity, NexthopMap, PendingMap, RouteLedger, SinkCounts};
use crate::status::PortLink;
use crate::verify::{verify, VerifyOutcome, DEFAULT_SAMPLE};
use crate::vpp_api::generated::{
    FibPath, IpNeighbor, IpNeighborAddDel, IpNeighborAddDelReply, IpNeighborDetails,
    IpNeighborDump, IpRoute, IpRouteAddDel, IpRouteAddDelReply, IpRouteDetails, IpRouteDump,
    IpTable, ADDRESS_IP4, ADDRESS_IP6, FIB_API_PATH_FLAG_NONE, FIB_API_PATH_NH_PROTO_IP4,
    FIB_API_PATH_TYPE_NORMAL,
};
use crate::vpp_api::{Transport, TransportError};

/// `IP_API_NEIGHBOR_FLAG_STATIC` from ip_neighbor.api.
///
/// Static because VPP cannot refresh a neighbour on this platform: MCAM
/// rules match IP fields, so an ARP or ND frame can never be steered to
/// it. An ageing dynamic entry would silently become an unresolved
/// adjacency and blackhole every route through that nexthop.
pub const IP_NEIGHBOR_STATIC: u8 = 1;

/// How long to wait for the handshake on a connect attempt.
///
/// Short on purpose: `api_ready` is polled from the supervision loop and
/// a long blocking connect would stall the tick that also services the
/// pidfd and the wedge ping. A timeout here just means the next tick
/// tries again; the *overall* patience for a slow start is
/// `API_STARTUP_BUDGET`, which is the loop's business, not this call's.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);

/// Socket timeout for requests after the handshake: **exactly the
/// liveness budget in force**.
///
/// `Transport::connect` installs its timeout with `set_read_timeout`, so
/// it governs every subsequent reply, not just the handshake. Two wrong
/// answers were tried before this one and both are instructive:
///
/// - Reusing the short handshake value (500 ms) made the transport error
///   during a full-table load, when VPP legitimately takes seconds to
///   answer because it services the API on the same main thread that is
///   executing our route batch. That silently defeats
///   `SYNC_PING_BUDGET`, whose entire purpose is letting a resync be slow
///   without being declared dead.
/// - Using the *largest* budget globally (12 s) fixed that and broke the
///   other end: `Driver` calls `ping()` synchronously, so a wedged API
///   parks the whole loop inside one socket read. The loop cannot
///   evaluate the detector or emit `Wedged` while blocked, so the
///   published **blackhole-wedge ≤ 2 s** number became ~12 s. The
///   reasoning that led there — "the socket is only a backstop, the
///   detector owns wedge decisions" — is wrong, because the detector
///   only gets to decide if the loop regains control.
///
/// So the socket enforces the same deadline the detector would, with no
/// margin: a reply that takes longer than the budget *is* a wedge by the
/// detector's own definition, and erroring at precisely that point is the
/// only value that contradicts neither side.
fn op_timeout(steered: bool, converging: bool) -> Duration {
    crate::liveness::budget_for(steered, converging)
}

/// Route ops handed to VPP per drain call.
///
/// Bounds one tick's work, not the resync: the loop calls back
/// immediately while there is more pending. Sized well above the
/// pipeline window so a drain amortises its syscalls, and well below the
/// full table so a tick cannot monopolise the loop and starve the ping.
pub const DRAIN_BATCH: usize = 4_096;

/// Where routes and nexthop devices come from.
///
/// A trait because the real source is the fast-path crate's
/// RouteController mirror, and reaching across to it is a separate
/// concern from getting the FIB into VPP — one that touches the live
/// forwarding path's control plane and deserves its own review.
///
/// Both methods are visitors rather than `Vec` returns. At 1.05M routes
/// a materialised `Vec<(IpPrefix, Vec<IpAddr>)>` is on the order of a
/// hundred MB of transient allocation and a million small `Vec`s, paid
/// on every resync — inside the ≤60 s convergence budget this engine
/// exists to meet.
pub trait RouteSource {
    /// Visit every route in the authoritative mirror, best-path
    /// nexthops included. Multipath routes present all their nexthops.
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr]));

    /// Visit each resolved neighbour: nexthop address, egress device, and
    /// **link-layer address**.
    ///
    /// The MAC is not optional here. VPP is started without `linux-cp`
    /// (it cannot pair kernel-owned PFs), so it begins with an empty
    /// neighbour table, and MCAM rules match IP fields so an ARP frame
    /// can never be steered into it — VPP physically cannot learn a
    /// neighbour. Every adjacency has to be programmed statically from
    /// this snapshot.
    ///
    /// Getting this wrong is a silent blackhole of the worst kind: route
    /// installs are acknowledged, readback verification passes (it checks
    /// a path exists on an interface we own, not that the adjacency
    /// resolves), and traffic is dropped on the floor by an incomplete
    /// adjacency. Nothing in the module would report a fault.
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6]));

    /// Changes since the last call, bounded by `max` routes.
    ///
    /// The default is "none", which is correct for a static snapshot: a
    /// fixture mirror does not change under the engine, and every
    /// in-tree implementation but the live feed is one of those. A source
    /// that *does* change must override this, or its updates reach the
    /// engine only at the next full resync.
    ///
    /// Both kinds come back from one call because they must be applied
    /// together and in order — see [`SourceChanges`].
    fn drain_changes(&self, _max: usize) -> SourceChanges {
        SourceChanges::default()
    }

    /// Take back the part of a [`Self::drain_changes`] batch that could
    /// not be applied, so it is retried intact.
    ///
    /// Handed **everything still owed**, routes included — that is the
    /// whole point. `drain_changes` is destructive on the live feed, so
    /// a batch whose neighbours failed partway used to lose its route
    /// half outright: out of the source's queue, never into the engine's,
    /// and nothing retried it. VPP then forwarded a stale FIB — a
    /// withdrawn prefix still forwarded, a changed nexthop still on the
    /// old adjacency — with `installed`/`installing`/`withheld`/
    /// `unresolvable` all unaffected, and readback verification blind to
    /// it, since verify samples prefixes the LEDGER believes installed
    /// and the ledger never learned these existed.
    ///
    /// Implementations must treat this as **fill-if-absent**. An entry
    /// already queued for the same prefix or nexthop was written after
    /// this batch was drained, so it is the newer intent and has to win;
    /// re-inserting the batch's older value would resurrect a state the
    /// source has already replaced.
    ///
    /// **No default body**, and not because a no-op would be wrong for
    /// the static sources — they hand nothing over, so this is never
    /// called with work to lose. It is the delegating wrapper:
    /// `route_count` had a default, the production loader's
    /// `Arc<RouteFeed>` inherited it while forwarding every other
    /// method, and a `requeue` that silently does not delegate is
    /// exactly the bug above, back again.
    fn requeue(&self, changes: SourceChanges);

    /// How many changes are queued but not yet handed over.
    ///
    /// Reported so a source that is filling faster than the engine drains
    /// is visible as its own fault, rather than as an unexplained gap
    /// between what bird advertises and what VPP holds. Default `0` for
    /// the static sources, which never queue anything.
    fn backlog(&self) -> u64 {
        0
    }

    /// How many routes the source currently holds.
    ///
    /// Exists for one consumer: the adopted-resync deferral. A resync is
    /// a diff whose withdrawals are "everything the ledger holds that the
    /// source does not" — which is only meaningful when the source is
    /// COMPLETE. A daemon restart is precisely when it is not: the BGP
    /// feed reconnects at startup and takes tens of seconds to reload,
    /// and an adopted ledger diffed against that window queues mass
    /// withdrawals against a live, possibly steered VPP. Observed on the
    /// shadow (drill (d), 2026-08-07): ~1M withdrawals began draining a
    /// verified forwarding table, convergence failed, and the teardown
    /// killed the adopted VPP that preserve-on-restart exists to keep.
    ///
    /// Deliberately **no default body**, and it used to have one (a
    /// full-table walk "fine for fixtures"): a defaulted method lets a
    /// delegating wrapper silently not-delegate, and that is not a
    /// hypothetical — the production loader's `Arc<RouteFeed>` wrapper
    /// forwarded every explicit method and inherited the default for
    /// this one, so the gate that polls it every ~50 ms was walking a
    /// 1.05M-entry mirror instead of reading a length (review finding).
    /// The compiler now makes every implementor answer; a fixture's
    /// answer is one line.
    fn route_count(&self) -> u64;

    /// Mutations ever applied to this source — a monotonic activity
    /// counter, NOT the table size. The adopted-resync gate's
    /// quiescence signal: net size hides balanced churn and reads a
    /// shrinking source as quiet, and both of those mid-reload would
    /// release a diff against an incomplete mirror (review finding). A
    /// static fixture may return any constant (including its length);
    /// what matters is that it changes exactly when the source does.
    /// No default body, same reason as `route_count`: a defaulted
    /// method lets a delegating wrapper silently not-delegate.
    fn change_seq(&self) -> u64;
}

/// One route change: the prefix, and its new nexthop set — or `None`
/// if it was withdrawn.
pub type RouteChange = (IpPrefix, Option<Vec<IpAddr>>);

/// One neighbour change: the nexthop, and its (egress device, MAC) —
/// or `None` if it is no longer resolved.
pub type NeighbourChange = (IpAddr, Option<(String, [u8; 6])>);

/// What changed at the source since it was last asked.
///
/// One struct rather than two calls so a tick cannot take the routes and
/// leave the neighbours behind. The order they are applied in is not
/// cosmetic: a route whose nexthop the engine's map has never seen is
/// classified **unresolvable**, so neighbours must land first or a
/// genuinely new nexthop black-holes its own routes until the next full
/// resync.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SourceChanges {
    /// Prefix → new nexthop set, or `None` for withdrawn.
    pub routes: Vec<RouteChange>,
    /// Nexthop → (egress device, MAC), or `None` for lost.
    pub neighbours: Vec<NeighbourChange>,
}

impl SourceChanges {
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.neighbours.is_empty()
    }

    pub fn len(&self) -> usize {
        self.routes.len() + self.neighbours.len()
    }
}

/// What a full-table resync queued.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResyncPlan {
    pub upserts: u64,
    /// Prefixes the ledger holds that the source no longer advertises.
    /// Non-zero after any outage during which routes were withdrawn.
    pub withdrawals: u64,
    /// Mirror prefixes suppressed by a `local-route` this walk. Logged
    /// so an operator reading the resync line can see the shadowing
    /// working (the reference primary expects exactly its poisoned
    /// host route here).
    pub shadowed: u64,
}

/// What a verify pass concluded, and whether traffic may be diverted
/// into the result.
///
/// Two fields because they answer different questions and collapsing
/// them is a bug in either direction. `VerifyOutcome::passed()`
/// deliberately ignores `withheld` — withholding is the designed
/// response to a table that outgrew its heap, and failing verification
/// on it would turn graceful degradation into a restart loop. But a FIB
/// missing prefixes is still not one to divert traffic into.
///
/// `#[must_use]` because ignoring `may_steer` is exactly the mistake:
/// `SinkCounts::blocks_first_steer()` existed as the intended gate and
/// nothing consulted it, so a restart of a previously-steered VPP would
/// have re-steered into an incomplete table.
#[must_use]
#[derive(Debug, Clone)]
pub struct Verdict {
    pub outcome: VerifyOutcome,
    /// False when the ledger holds routes it could not install, or when
    /// route intent is outstanding somewhere the ledger cannot see it —
    /// the runtime narrows it for the second case, which the counts
    /// cannot express (a delta batch handed back to the source after a
    /// failed neighbour send is not `installing`, not `withheld` and not
    /// `unresolvable`; it is simply not there yet).
    pub may_steer: bool,
}

impl Verdict {
    /// The supervisor event this verdict implies. Keeps the mapping in
    /// one place so a caller cannot pick `VerifyPassed` for an
    /// incomplete table.
    ///
    /// `VerifyFailed` — the restart-worthy verdict — fires only on
    /// **mismatches**: VPP answered a probe and disagreed with the
    /// ledger. That is the one condition a teardown remedies, because
    /// a fresh resync rebuilds a wrong FIB. Everything else that fails
    /// [`VerifyOutcome::fib_correct`] is a condition a restart cannot
    /// change, and each has produced a kill-respawn loop by riding
    /// this verdict:
    ///
    /// - `sampled == 0` — the source has not delivered the table yet.
    ///   On a fresh attach the feed connects AFTER the module (bird
    ///   dials the passive listener), so the first verify can run with
    ///   the sink legitimately empty. The primary's w7 window
    ///   (2026-08-13) took SEVEN teardowns in 31 s through this arm —
    ///   the first before bird's session had even opened — and every
    ///   respawn re-ran the octeon driver's port start against the
    ///   shared LMAC, blacking out the switch0 bridge below the
    ///   kernel. A restart cannot make bird dump faster. (The
    ///   fresh-resync hold in `runtime.rs` keeps verify from running
    ///   this early at all when a completeness authority is
    ///   configured; this arm is the backstop for deployments
    ///   without one.)
    /// - `unresolvable > 0` — the nexthop-device mapping has holes: a
    ///   nexthop egresses a port VPP does not own, or a neighbour has
    ///   not resolved yet. A restart cannot make eth3 a member. The
    ///   single-member bisection configs are the standing case: the
    ///   full table's nexthops egress non-member ports, permanently.
    /// - Dark member interfaces that CARRY ROUTES — a restart cannot
    ///   plug in a cable. Three uncabled shadow ports turned exactly
    ///   this into an infinite kill-respawn loop over a flawless FIB
    ///   (repro 2026-08-13).
    ///
    /// All of those ride `VerifyIncomplete`: reach `Ready`, keep the
    /// want, do NOT steer. Steering stays refused by the LIVE gates —
    /// `steer_permitted` re-reads the authority verdict, the source
    /// backlog and `blocks_first_steer` on every retry, none of which
    /// consult this verdict's snapshot — so recovery is the retry loop
    /// noticing conditions changed, not a verdict going stale in
    /// either direction.
    ///
    /// A dark member that is IDLE — no installed route can egress it,
    /// which is the normal state of a dark port, since the BGP session
    /// that would produce its routes died with the link — blocks
    /// nothing: it shows in the summary and the ports row, and the
    /// verdict is whatever the rest of the outcome earns. Refusing to
    /// steer five live ports over one uncabled one would hold the
    /// whole offload hostage to a port that poses no risk (the
    /// primary's eth5 is the motivating case).
    pub fn event(&self) -> crate::supervisor::Event {
        let blocking_dark = self.outcome.dead_interfaces.iter().any(|d| d.in_use);
        if !self.outcome.mismatches.is_empty() {
            crate::supervisor::Event::VerifyFailed
        } else if self.outcome.fib_correct() && self.may_steer && !blocking_dark {
            crate::supervisor::Event::VerifyPassed
        } else {
            crate::supervisor::Event::VerifyIncomplete
        }
    }
}

/// Which convergence step is in flight, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Resync,
    Verify,
}

#[derive(Debug)]
pub enum EngineError {
    /// No transport. Either the API has not answered yet or the previous
    /// connection broke; the loop's job, not an operation's, to decide
    /// what that means.
    NotConnected,
    Transport(TransportError),
    Attach(AttachError),
    /// VPP refused a static neighbour. Fatal to convergence rather than
    /// skippable: every route through that nexthop would install cleanly
    /// and then drop traffic on an unresolved adjacency.
    NeighbourRefused {
        nexthop: IpAddr,
        retval: i32,
    },
    /// A `local-route` attached route could not be installed. Fatal to
    /// the attach rather than skippable: this prefix's delivery is the
    /// declared reason the config steers at all, and dst steering may
    /// be counting on it.
    AttachedRouteFailed {
        prefix: String,
        detail: String,
    },
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConnected => write!(f, "binary API is not connected"),
            Self::Transport(e) => write!(f, "{e}"),
            Self::Attach(e) => write!(f, "{e}"),
            Self::NeighbourRefused { nexthop, retval } => write!(
                f,
                "VPP refused the static neighbour for {nexthop} (retval {retval}); \
                 every route through it would blackhole"
            ),
            Self::AttachedRouteFailed { prefix, detail } => write!(
                f,
                "the attached route for local-route {prefix} could not be installed \
                 ({detail}); steered traffic to it would die at null-node"
            ),
        }
    }
}

impl From<TransportError> for EngineError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e)
    }
}

impl From<AttachError> for EngineError {
    fn from(e: AttachError) -> Self {
        Self::Attach(e)
    }
}

/// Owns the API-side half of the supervised dataplane.
pub struct ConvergenceEngine {
    api_socket: std::path::PathBuf,
    transport: Option<Transport>,

    ports: Vec<PortAttach>,
    /// Locally terminated prefixes VPP delivers itself: an attached
    /// route onto the named port's dot1q subif, kernel neighbours on
    /// the backing bridge mirrored as static neighbours, and the BGP
    /// mirror's view INSIDE each prefix shadowed (skipped at resync
    /// and in deltas). Restart-only config, resolved by the loader
    /// against fast-path's `local-prefix` for the kernel device.
    local_routes: Vec<crate::LocalRoute>,
    /// Mirror prefixes currently suppressed by a `local-route` — kept
    /// as a set so health can report a count that means "routes the
    /// mirror carries that VPP deliberately does not", not a
    /// monotonically growing skip tally. Entries leave when the mirror
    /// withdraws them. Survives reconnects: it describes the mirror,
    /// not the process.
    shadowed: HashSet<IpPrefix>,
    /// The address the loopback holds; every member is unnumbered to it.
    loopback: packetframe_common::config::Ipv4Prefix,
    /// The loopback's index once created. `None` until the first attach
    /// pass — and reset with the transport, because an index from a VPP
    /// that has since died names nothing.
    loop_index: Option<u32>,
    /// `(port, sw_if_index)` recorded from a previous run, for adoption.
    recorded_indices: Vec<(String, u32)>,
    attached: Vec<AttachedPort>,
    port_index: PortIndex,

    pending: PendingMap,
    ledger: RouteLedger,
    nexthops: NexthopMap,
    /// Static neighbours VPP has ACKNOWLEDGED holding, keyed by
    /// `(sw_if_index, nexthop)` with the MAC as the value.
    ///
    /// The single ledger both neighbour-programming paths consult
    /// before sending, because a re-add of an identical static
    /// neighbour is not a no-op: VPP replaces the entry and walks every
    /// dependent FIB entry — ~1M routes hang off ONE adjacency on this
    /// topology — null-noding traffic through it for the duration.
    /// #146 taught `program_neighbours` to skip via a dump and the
    /// 5.5 s blackhole did not move, because `apply_changes` is a
    /// second path to the same message: the deltas accumulated during
    /// the resync deferral re-added the very neighbour the resync walk
    /// had just left untouched. Two paths, one ledger, one skip.
    ///
    /// Written only on VPP's acknowledgement (in `send_neighbour`) or
    /// from VPP's own dump (in `program_neighbours`); cleared with the
    /// process, because it describes a table that died with it.
    neighbours_installed: std::collections::HashMap<(u32, IpAddr), [u8; 6]>,
    /// Neighbours whose last message reached the socket but whose reply
    /// never came back, so `neighbours_installed` cannot be trusted for
    /// them until VPP is asked again.
    ///
    /// A transport error after the write is genuinely ambiguous — VPP may
    /// have applied the change — and the ledger records only
    /// acknowledgements, so both directions are left describing the wrong
    /// table. They fail in opposite ways and the second is the dangerous
    /// one:
    ///
    /// - An unacknowledged **add** VPP did apply gets sent again on the
    ///   retry, and re-adding an existing static neighbour walks every
    ///   dependent FIB entry: ~1M routes hang off one adjacency here, for
    ///   a measured 5.51 s blackhole (shadow, 2026-08-08).
    /// - An unacknowledged **remove** VPP did apply leaves the ledger
    ///   claiming an adjacency VPP no longer has, and the delta path's
    ///   skip then absorbs the next add of that exact MAC — silently,
    ///   permanently, with every route through it black-holed. Strictly
    ///   worse than a redundant walk.
    ///
    /// Both are settled by asking VPP, so these keys are reconciled
    /// against a fresh `ip_neighbor_dump` before either send path
    /// consults the ledger again. Keyed, not a flag, so the dump corrects
    /// exactly what is in doubt — a wholesale rebuild would drop what the
    /// v4-only dump cannot see.
    neighbours_unacked: std::collections::HashSet<(u32, IpAddr)>,
    drainer: Drainer,

    /// Whether MCAM rules are diverting traffic right now.
    ///
    /// Not the engine's to decide — the supervisor owns it — but the
    /// engine needs it because the socket timeout must track the liveness
    /// budget in force, and `budget_for` keys on steered.
    steered: bool,

    phase: Option<Phase>,
    last_verify: Option<VerifyOutcome>,
    /// Unit-test seam for [`Self::dead_members`]: the real scan needs a
    /// live transport, which in-crate unit tests of the steer gate do
    /// not have (the fake VPP lives in the integration-test crate).
    /// `None` — the only production value — means "run the real scan".
    #[cfg(test)]
    pub(crate) test_dead_members: Option<Vec<crate::verify::DeadInterface>>,
    /// The last handshake failure, and whether it can ever succeed.
    ///
    /// `api_ready` returns a bool, which collapses "VPP has not opened
    /// its socket yet" together with "this VPP speaks a different API
    /// than the one we generated against". The second is permanent: the
    /// supervisor would wait out `API_STARTUP_BUDGET` and restart-loop
    /// forever without anything reporting the version skew that makes
    /// every attempt fail. CRC mismatch is meant to be a loud refusal by
    /// construction; a silent retry loop is the opposite.
    last_api_error: Option<String>,
    api_incompatible: bool,

    /// Advanced once per verify so each pass samples a different set.
    ///
    /// Counter-derived rather than drawn from the OS, for the reason
    /// [`crate::verify::sample`] takes a seed at all: a failing verify
    /// has to be replayable, and a probe set nobody can reproduce is a
    /// bug report nobody can act on. Varying per pass is what matters —
    /// fixed probes pass forever once installed.
    verify_seed: u64,
}

impl ConvergenceEngine {
    pub fn new(
        api_socket: impl Into<std::path::PathBuf>,
        ports: Vec<PortAttach>,
        members: Vec<String>,
        high_water_routes: u64,
        families: FamilyPolicy,
        loopback: packetframe_common::config::Ipv4Prefix,
    ) -> Self {
        Self {
            api_socket: api_socket.into(),
            transport: None,
            ports,
            local_routes: Vec::new(),
            shadowed: HashSet::new(),
            loopback,
            loop_index: None,
            recorded_indices: Vec::new(),
            attached: Vec::new(),
            port_index: PortIndex::default(),
            pending: PendingMap::new(),
            ledger: RouteLedger::new(Capacity::new(high_water_routes)),
            nexthops: NexthopMap::new(members),
            neighbours_installed: std::collections::HashMap::new(),
            neighbours_unacked: std::collections::HashSet::new(),
            drainer: Drainer::new(DEFAULT_WINDOW).with_families(families),
            steered: false,
            last_api_error: None,
            api_incompatible: false,
            phase: None,
            last_verify: None,
            #[cfg(test)]
            test_dead_members: None,
            verify_seed: 0,
        }
    }

    /// Seed the port→index map from the state file so an adopted VPP's
    /// existing interfaces are reused rather than duplicated.
    pub fn with_recorded_indices(mut self, known: Vec<(String, u32)>) -> Self {
        self.recorded_indices = known;
        self
    }

    /// Declare the locally terminated prefixes this engine delivers.
    ///
    /// This is the ONLY caller of [`NexthopMap::add_vlan`], and the
    /// preconditions the old NOTE here demanded now hold by
    /// construction: `create_vlan_subif` is whitelisted, attach creates
    /// the subifs from the same config that names them here, and
    /// `attach_devices` records the indices VPP assigns into
    /// [`PortIndex`] under `(port, Some(vid))` — so a `Subif` target
    /// resolves instead of deferring its routes forever. Registered at
    /// construction because the VLAN policy is static config;
    /// `forget_devices` deliberately keeps it.
    pub fn with_local_routes(mut self, routes: Vec<crate::LocalRoute>) -> Self {
        for lr in &routes {
            self.nexthops
                .add_vlan(lr.kernel_dev.clone(), lr.port.clone(), lr.vlan);
        }
        self.local_routes = routes;
        self
    }

    /// Whether the mirror's view of `p` is suppressed by a local-route.
    ///
    /// The kernel tier delivers to bridge hosts BEFORE its FIB lookup,
    /// so a mirrored route inside a locally delivered prefix describes
    /// what bird would do, not what the box does — the reference
    /// primary carries a service host route as `unreachable` in bird,
    /// which the kernel path never consults and VPP would faithfully
    /// blackhole with. Local delivery comes from the attached route +
    /// neighbour mirror instead.
    fn shadows(&self, p: &IpPrefix) -> bool {
        let IpPrefix::V4 { addr, prefix_len } = p else {
            return false;
        };
        self.local_routes.iter().any(|lr| {
            lr.prefix.prefix_len <= *prefix_len
                && lr.prefix.contains_addr(std::net::Ipv4Addr::from(*addr))
        })
    }

    /// How many mirror prefixes a `local-route` is currently shadowing.
    pub fn shadowed_routes(&self) -> u64 {
        self.shadowed.len() as u64
    }

    pub fn counts(&self) -> SinkCounts {
        self.ledger.counts()
    }

    pub fn pending(&self) -> &PendingMap {
        &self.pending
    }

    pub fn phase(&self) -> Option<Phase> {
        self.phase
    }

    pub fn last_verify(&self) -> Option<&VerifyOutcome> {
        self.last_verify.as_ref()
    }

    pub fn is_connected(&self) -> bool {
        self.transport.is_some()
    }

    /// Interface state for the health surface.
    ///
    /// Flags come from the most recent **observation**, which is the
    /// verify pass's interface dump — `VerifyOutcome::dead_interfaces`
    /// names every owned interface that is not both admin- and link-up,
    /// including ones absent from VPP entirely.
    ///
    /// An earlier version hard-coded both flags true and rationalised it
    /// as "the attach-time observation". It was not one: `attach_ports`
    /// asserts the admin flag but never checks carrier, so link state was
    /// pure fabrication — and it persisted, so a port that verify had
    /// just found dead still reported as forwarding. That is exactly the
    /// defect this module's docs claim to defend against, in the health
    /// surface, written by the same hand that wrote the claim.
    ///
    /// Before the first verify there is genuinely no link observation.
    /// Reporting up there cannot cause a false all-clear, because
    /// `status::StatusSnapshot::nominal` requires a *passing verify*
    /// independently — so the window is bounded by something that does
    /// not trust this value.
    ///
    /// `in_use` is deliberately NOT the verify-time
    /// [`crate::verify::DeadInterface::in_use`]: verify does not re-run
    /// in steady state, so that copy ages exactly like the link flags —
    /// but in the dangerous direction. Routes shifting ONTO a dark
    /// member after the last verify are what turn "idle, carries
    /// nothing" into a blackhole, and the neighbour ledger here is the
    /// engine's own current bookkeeping (the same `active_egress_indices`
    /// read that feeds the steer gate), so the health surface reads it
    /// live rather than as a recording.
    pub fn port_links(&self) -> Vec<PortLink> {
        let dead = self
            .last_verify
            .as_ref()
            .map(|v| v.dead_interfaces.as_slice())
            .unwrap_or_default();
        let active = self.active_egress_indices();
        self.attached
            .iter()
            .map(|p| {
                let in_use = active.contains(&p.sw_if_index);
                match dead.iter().find(|d| d.sw_if_index == p.sw_if_index) {
                    Some(d) => PortLink {
                        port: p.port.clone(),
                        sw_if_index: p.sw_if_index,
                        admin_up: d.admin_up,
                        link_up: d.link_up,
                        in_use,
                    },
                    None => PortLink {
                        port: p.port.clone(),
                        sw_if_index: p.sw_if_index,
                        admin_up: true,
                        link_up: true,
                        in_use,
                    },
                }
            })
            .collect()
    }

    /// Tell the engine whether traffic is currently steered.
    ///
    /// Only affects the socket timeout, which must match the liveness
    /// budget in force — a steered dataplane gets the short budget even
    /// mid-resync, because an adopted resync forwards the whole time and
    /// a 10 s blind window on live traffic is not affordable.
    pub fn set_steered(&mut self, steered: bool) {
        self.steered = steered;
        // Re-arm immediately: the state can change between operations,
        // and a stale timeout is the bug this whole mechanism exists to
        // avoid.
        self.arm_timeout();
    }

    /// Re-arm the socket deadline from the budget currently in force.
    ///
    /// Called before every request rather than once at connect: two
    /// `setsockopt` calls per operation (not per route) is nothing, and
    /// it makes drift structurally impossible.
    fn arm_timeout(&mut self) {
        let d = op_timeout(self.steered, self.phase.is_some());
        if let Some(t) = self.transport.as_mut() {
            // A socket that will not take a timeout is not one to keep.
            if t.set_timeout(d).is_err() {
                self.transport = None;
            }
        }
    }

    /// Attempt to connect, reporting whether the API is answering.
    ///
    /// A failure is not an error: VPP takes real time to open its socket
    /// while it faults in a multi-GB heap on 512 MiB hugepages. The
    /// startup deadline decides when that has gone on too long.
    pub fn api_ready(&mut self) -> bool {
        if self.transport.is_some() {
            return true;
        }
        match Transport::connect(&self.api_socket, HANDSHAKE_TIMEOUT) {
            Ok(mut t) => {
                // Re-arm off the handshake value. It is deliberately short
                // so a failed connect costs the loop one tick, but
                // `connect` installs it as the socket's persistent
                // read/write timeout — leaving it in force would make
                // every drain reply time out at 500 ms during a
                // full-table load and defeat SYNC_PING_BUDGET.
                if t.set_timeout(op_timeout(self.steered, self.phase.is_some()))
                    .is_err()
                {
                    return false;
                }
                self.transport = Some(t);
                self.last_api_error = None;
                self.api_incompatible = false;
                true
            }
            Err(e) => {
                // A version-skew or refusal will fail identically every
                // time; a missing socket will not. Recording which is
                // which is what lets the supervisor stop retrying and the
                // status surface name the actual fault.
                self.api_incompatible = matches!(
                    e,
                    TransportError::CrcMismatch { .. }
                        | TransportError::MessageUnknown(_)
                        | TransportError::HandshakeRefused(_)
                );
                self.last_api_error = Some(e.to_string());
                false
            }
        }
    }

    /// The last handshake failure, if the API is not up.
    pub fn last_api_error(&self) -> Option<&str> {
        self.last_api_error.as_deref()
    }

    /// Whether the failure is permanent — this VPP cannot ever speak to
    /// us. Retrying wastes the startup budget and restarting produces the
    /// same VPP; the fault has to reach an operator instead.
    pub fn api_incompatible(&self) -> bool {
        self.api_incompatible
    }

    /// Drop the connection. Called when a round trip fails, so the next
    /// `api_ready` reconnects rather than reusing a socket whose framing
    /// may be desynchronised — a half-read reply would corrupt every
    /// subsequent context match.
    pub fn disconnect(&mut self) {
        self.transport = None;
    }

    fn transport(&mut self) -> Result<&mut Transport, EngineError> {
        self.transport.as_mut().ok_or(EngineError::NotConnected)
    }

    /// One liveness round trip.
    pub fn ping(&mut self) -> Result<(), EngineError> {
        self.arm_timeout();
        let t = self.transport()?;
        match t.ping() {
            Ok(_) => Ok(()),
            Err(e) => {
                // A failed ping means this socket is no longer usable.
                self.disconnect();
                Err(EngineError::Transport(e))
            }
        }
    }

    /// Attach the member ports' devices and record the indices FIB paths
    /// must reference.
    ///
    /// Runs before any route is installed. The indices do not exist
    /// until VPP assigns them, so a resync that ran first would defer
    /// every single route — which the drainer handles correctly but
    /// which would burn a whole convergence cycle doing nothing.
    pub fn attach_devices(&mut self, mode: AttachMode) -> Result<(), EngineError> {
        self.arm_timeout();
        let ports = std::mem::take(&mut self.ports);
        let known = std::mem::take(&mut self.recorded_indices);
        let t = match self.transport.as_mut() {
            Some(t) => t,
            None => {
                self.ports = ports;
                self.recorded_indices = known;
                return Err(EngineError::NotConnected);
            }
        };
        // The loopback comes first and exists once per VPP: members are
        // unnumbered to it, so there is nothing to borrow an address
        // from until it does. Re-created after a restart because the
        // index died with the process.
        let loop_index = match self.loop_index {
            Some(idx) => Ok(idx),
            // Adopt before creating. A surviving VPP already has the
            // loopback and its address; creating a second one and
            // assigning the same address fails ADDRESS_IN_USE, and the
            // attach step never completes.
            //
            // Adoption re-asserts admin-up and trusts the address. The
            // address CANNOT be probed: re-adding it answers -105
            // through the members' unnumbered borrow on every healthy
            // adoption (hardware, 2026-08-08), and no whitelisted
            // message dumps addresses. See `adopt_loopback` for the
            // full argument and the accepted crash window.
            None => match crate::attach::find_loopback(t) {
                Ok(Some(idx)) => {
                    tracing::info!(
                        sw_if_index = idx,
                        "reusing the loopback this VPP already has rather than creating another"
                    );
                    crate::attach::adopt_loopback(t, idx).map(|()| idx)
                }
                Ok(None) => crate::attach::create_loopback(t, self.loopback),
                Err(e) => Err(e.into()),
            },
        };
        let result = match loop_index {
            Ok(idx) => {
                self.loop_index = Some(idx);
                attach_ports(t, &ports, &known, mode, idx)
            }
            Err(e) => Err(e),
        };
        self.ports = ports;
        self.recorded_indices = known;
        let attached = match result {
            Ok(a) => a,
            Err(e) => {
                // A transport failure may have left an unread or partial
                // reply on the stream, so the socket has to go — reusing
                // it would match a later reply against the wrong context.
                // Ping, drain and verify all do this; attach must not be
                // the one path that leaves a poisoned socket looking
                // healthy to `api_ready`.
                //
                // A plain refusal (`Refused`, `LocalZero`, `StaleIndex`,
                // `UnknownIndexOnAdopt`) is VPP answering us correctly, so
                // the connection stays.
                if matches!(e, AttachError::Transport(_)) {
                    self.disconnect();
                }
                return Err(e.into());
            }
        };

        // Only now, with VPP's own indices in hand.
        for p in &attached {
            self.port_index.insert(p.port.clone(), None, p.sw_if_index);
            for &(vid, idx) in &p.subifs {
                self.port_index.insert(p.port.clone(), Some(vid), idx);
            }
        }
        self.attached = attached;
        self.install_attached_routes()
    }

    /// Install one attached route per `local-route`, straight onto the
    /// subif — deliberately OUTSIDE the pending/ledger path.
    ///
    /// These are module-owned topology, not mirror state: the resync
    /// diff withdraws whatever the ledger holds that the source no
    /// longer advertises, and an attached route is never advertised by
    /// the source, so entering the ledger would get it withdrawn on
    /// the very next resync. Not entering it is also what exempts it
    /// from adoption's shape test (a nexthop-less route never looks
    /// self-installed) — a restart over a live VPP re-sends it, and
    /// VPP treats the identical add as an update.
    ///
    /// The nexthop-less NORMAL path on the subif is VPP's attached
    /// route: dst inside the prefix resolves via the interface, with
    /// per-host adjacencies coming from the mirrored static
    /// neighbours (VPP never ARPs; a never-seen host drops here where
    /// the kernel would ARP-queue — documented, service hosts are
    /// static).
    fn install_attached_routes(&mut self) -> Result<(), EngineError> {
        if self.local_routes.is_empty() {
            return Ok(());
        }
        let t = self.transport.as_mut().ok_or(EngineError::NotConnected)?;
        for lr in &self.local_routes {
            let target = crate::sink::NexthopTarget::Subif {
                port: lr.port.clone(),
                vlan: lr.vlan,
            };
            let Some(sw_if_index) = self.port_index.get(&target) else {
                // Config guarantees the port declares this vlan, and
                // attach just created every declared subif — a miss
                // here is an ordering bug, not an operator error, and
                // installing onto index 0 would route the prefix to
                // local0.
                return Err(EngineError::AttachedRouteFailed {
                    prefix: format!("{}/{}", lr.prefix.addr, lr.prefix.prefix_len),
                    detail: format!("no subif index for {}.{}", lr.port, lr.vlan),
                });
            };
            let prefix = IpPrefix::V4 {
                addr: lr.prefix.network().octets(),
                prefix_len: lr.prefix.prefix_len,
            };
            let mut path = FibPath {
                sw_if_index,
                table_id: 0,
                rpf_id: 0,
                weight: 1,
                preference: 0,
                r#type: FIB_API_PATH_TYPE_NORMAL,
                flags: FIB_API_PATH_FLAG_NONE,
                proto: FIB_API_PATH_NH_PROTO_IP4,
                nh: Default::default(),
                n_labels: 0,
                label_stack: Default::default(),
            };
            // Zero nexthop = attached: resolve via the interface.
            path.nh = Default::default();
            let reply: IpRouteAddDelReply = t.request(IpRouteAddDel {
                context: 0,
                is_add: true,
                is_multipath: false,
                route: IpRoute {
                    table_id: 0,
                    stats_index: 0,
                    prefix: crate::fib_sync::to_prefix(prefix),
                    n_paths: 1,
                    paths: vec![path],
                },
            })?;
            if reply.retval != 0 {
                return Err(EngineError::AttachedRouteFailed {
                    prefix: format!("{}/{}", lr.prefix.addr, lr.prefix.prefix_len),
                    detail: format!("retval {}", reply.retval),
                });
            }
            tracing::info!(
                prefix = %format!("{}/{}", lr.prefix.addr, lr.prefix.prefix_len),
                port = %lr.port,
                vlan = lr.vlan,
                sw_if_index,
                "attached route installed — VPP delivers this prefix itself"
            );
        }
        Ok(())
    }

    /// Every attached port's `(name, sw_if_index)`, for persisting to
    /// the state file so the next run can adopt rather than re-attach.
    pub fn attached_indices(&self) -> Vec<(String, u32)> {
        self.attached
            .iter()
            .map(|p| (p.port.clone(), p.sw_if_index))
            .collect()
    }

    /// Program the static neighbours the resolved routes will depend on.
    ///
    /// Runs after `attach_devices` (the adjacency needs the interface
    /// index) and **before** any route drains: a route installed against
    /// an unresolved adjacency is acknowledged by VPP and then drops
    /// every packet, and neither the ledger nor readback verification can
    /// see it.
    ///
    /// Neighbours whose device is not VPP-owned are skipped rather than
    /// refused — the same policy the nexthop mapping applies to routes,
    /// and for the same reason: a management or tunnel neighbour is not
    /// an error, it is simply not ours.
    ///
    /// Returns how many were programmed. Sized by the neighbour table
    /// (~129 nexthops on the reference fleet), not the route table, so
    /// this is not a batched pipeline like the drainer.
    pub fn program_neighbours(&mut self, src: &dyn RouteSource) -> Result<u64, EngineError> {
        self.arm_timeout();
        if self.transport.is_none() {
            return Err(EngineError::NotConnected);
        }

        // What VPP already holds — so nothing it has is re-added.
        //
        // Re-adding an existing static neighbour is NOT a no-op: VPP
        // replaces the entry (the dump's own `age` field resets), and
        // the replacement walks every dependent FIB entry. On this
        // topology ~1M routes resolve through ONE adjacency, and while
        // that walk runs, traffic through it goes to null-node.
        // Measured on the shadow (2026-08-08): a 5.51 s blackhole at
        // the moment of an otherwise perfect adoption, 21,055
        // `null-node blackholed` across the three drill-(d) runs that
        // re-added blind. Discover, don't recreate — the same rule as
        // ports and the loopback, one object further down.
        //
        // Skipped only on an EXACT match (interface, MAC, and the
        // static flag): an entry with a stale MAC must be replaced —
        // that walk is the price of correctness — and a dynamic entry
        // must be replaced with a static one, because VPP can never
        // refresh it here (MCAM cannot steer ARP).
        let existing = self.dump_static_neighbours()?;
        // Seed the acknowledged ledger from VPP's own answer, so the
        // DELTA path's skip covers adopted entries too — not only ones
        // this process sent.
        for &(idx, ip, mac) in &existing {
            self.neighbours_installed.insert((idx, ip), mac);
        }
        // Insert-only above, so a key VPP no longer holds keeps its stale
        // entry — harmless for the general case (the walk below re-sends
        // anything whose MAC differs) but not for one left in doubt,
        // where a stale "installed" is what makes the skip permanent.
        // Those are corrected against the same dump.
        self.settle_unacked(&existing);

        // Collect first: the visitor borrows `src` while the sends need
        // `&mut self`.
        let mut wanted: Vec<(IpAddr, u32, [u8; 6])> = Vec::new();
        {
            let nexthops = &self.nexthops;
            let ports = &self.port_index;
            src.for_each_neighbour(&mut |ip, _dev, mac| {
                if let Some(target) = nexthops.resolve(&ip) {
                    if let Some(idx) = ports.get(&target) {
                        wanted.push((ip, idx, mac));
                    }
                }
            });
        }

        let mut programmed = 0u64;
        let mut kept = 0u64;
        for (ip, sw_if_index, mac_address) in wanted {
            if existing.contains(&(sw_if_index, ip, mac_address)) {
                kept += 1;
                continue;
            }
            self.send_neighbour(ip, sw_if_index, mac_address, true)?;
            programmed += 1;
        }
        if kept > 0 {
            tracing::info!(
                kept,
                programmed,
                "neighbours VPP already holds correct were left untouched; re-adding one \
                 walks every dependent route"
            );
        }
        Ok(programmed)
    }

    /// Every static neighbour VPP currently holds, as
    /// `(sw_if_index, address, MAC)`.
    ///
    /// One dump, two consumers — the resync walk's skip and
    /// [`Self::reconcile_unacked_neighbours`] — because a second
    /// hand-written copy of the flag filter is how the two would come to
    /// disagree about what "an entry we would have created" means.
    ///
    /// Asked **once per family the policy carries**, from the same
    /// `dump_families` the FIB readback uses. A v4-only dump answers "not
    /// present" for every v6 neighbour, and both consumers read absence as
    /// permission to send: the resync walk re-adds a v6 adjacency VPP
    /// already holds, and `settle_unacked` drops a v6 claim it cannot
    /// verify — each paying the dependent-FIB walk this ledger exists to
    /// avoid (review finding). Under `V4Only` this is exactly the single
    /// dump it was before.
    fn dump_static_neighbours(&mut self) -> Result<HashSet<(u32, IpAddr, [u8; 6])>, EngineError> {
        let mut out = HashSet::new();
        for &is_ip6 in self.drainer.families().dump_families() {
            let af = if is_ip6 { ADDRESS_IP6 } else { ADDRESS_IP4 };
            let t = self.transport.as_mut().ok_or(EngineError::NotConnected)?;
            let details: Vec<IpNeighborDetails> = match t.dump(IpNeighborDump {
                context: 0,
                sw_if_index: u32::MAX,
                af,
            }) {
                Ok(d) => d,
                Err(e) => {
                    self.disconnect();
                    return Err(EngineError::Transport(e));
                }
            };
            for d in details {
                // EXACT flags, not a bit test: `send_neighbour` programs
                // precisely IP_NEIGHBOR_STATIC, so an entry carrying any
                // extra flag (STATIC|NO_FIB_ENTRY, say) is not the entry
                // we would create, and skipping it would silently
                // preserve the difference forever (review finding).
                if d.neighbor.flags != IP_NEIGHBOR_STATIC {
                    continue;
                }
                if let Some(ip) = crate::fib_sync::from_address(&d.neighbor.ip_address) {
                    out.insert((d.neighbor.sw_if_index, ip, d.neighbor.mac_address));
                }
            }
        }
        Ok(out)
    }

    /// Ask VPP what became of the neighbours whose replies never arrived,
    /// and make the ledger say that.
    ///
    /// Called before either send path consults `neighbours_installed`, so
    /// the skip decides against what VPP holds rather than against what we
    /// last managed to hear. See [`Self::neighbours_unacked`] for why both
    /// directions need it and why the remove case is the dangerous one.
    ///
    /// A no-op with nothing in doubt, which is every ordinary tick — the
    /// dump only happens after a transport error mid-neighbour.
    fn reconcile_unacked_neighbours(&mut self) -> Result<(), EngineError> {
        if self.neighbours_unacked.is_empty() {
            return Ok(());
        }
        let existing = self.dump_static_neighbours()?;
        self.settle_unacked(&existing);
        Ok(())
    }

    /// Apply a dump's answer to the in-doubt keys, then consider them
    /// settled. Split from the dump so the resync walk, which has already
    /// paid for one, does not issue a second.
    fn settle_unacked(&mut self, existing: &HashSet<(u32, IpAddr, [u8; 6])>) {
        if self.neighbours_unacked.is_empty() {
            return;
        }
        for (idx, ip) in std::mem::take(&mut self.neighbours_unacked) {
            match existing
                .iter()
                .find(|(i, a, _)| *i == idx && *a == ip)
                .map(|(_, _, mac)| *mac)
            {
                // VPP has it: record the MAC it actually holds, which is
                // what stops the retry re-adding it and walking ~1M
                // dependent routes. Not necessarily the MAC we sent —
                // if the add never landed, this is the older entry, and
                // recording it truthfully is what makes the delta path
                // re-send.
                Some(mac) => {
                    self.neighbours_installed.insert((idx, ip), mac);
                }
                // VPP does not: drop the claim. An unacknowledged remove
                // that did land would otherwise leave the ledger
                // asserting an adjacency that is gone, and the skip would
                // swallow every later add of that MAC.
                None => {
                    self.neighbours_installed.remove(&(idx, ip));
                }
            }
        }
    }

    /// One `ip_neighbor_add_del`, the single place this message is built.
    ///
    /// Extracted because there are now two callers — the resync walk and
    /// the steady-state delta path — and a second hand-written copy of
    /// this is how the tiers end up disagreeing about a flag. The static
    /// bit especially: VPP must never age these out and never ARP to
    /// refresh them, because it cannot receive the reply.
    fn send_neighbour(
        &mut self,
        ip: IpAddr,
        sw_if_index: u32,
        mac_address: [u8; 6],
        is_add: bool,
    ) -> Result<(), EngineError> {
        let t = self.transport.as_mut().ok_or(EngineError::NotConnected)?;
        let reply = match t.request::<IpNeighborAddDel, IpNeighborAddDelReply>(IpNeighborAddDel {
            context: 0,
            is_add,
            neighbor: IpNeighbor {
                sw_if_index,
                flags: IP_NEIGHBOR_STATIC,
                mac_address,
                ip_address: to_address(ip),
            },
        }) {
            Ok(r) => r,
            Err(e) => {
                // The message was written; the answer never came. VPP may
                // have applied it, so the ledger is not entitled to an
                // opinion about this neighbour until VPP is asked again.
                // See `neighbours_unacked` — both directions fail here,
                // and silently.
                self.neighbours_unacked.insert((sw_if_index, ip));
                self.disconnect();
                return Err(EngineError::Transport(e));
            }
        };
        if reply.retval != 0 {
            // A removal VPP does not recognise is not a fault: the
            // adjacency we wanted gone is gone. An *add* it refuses is,
            // because every route through that nexthop would install
            // cleanly and then blackhole.
            if !is_add {
                self.neighbours_installed.remove(&(sw_if_index, ip));
                return Ok(());
            }
            return Err(EngineError::NeighbourRefused {
                nexthop: ip,
                retval: reply.retval,
            });
        }
        // Recorded on the acknowledgement, in the one function both
        // callers share — the ledger the skip consults must have a
        // single writer, or the two paths drift apart again.
        if is_add {
            self.neighbours_installed
                .insert((sw_if_index, ip), mac_address);
        } else {
            self.neighbours_installed.remove(&(sw_if_index, ip));
        }
        Ok(())
    }

    /// Seed the ledger from VPP's own FIB, so an adoption can compute
    /// withdrawals.
    ///
    /// Only acts when the ledger is **empty**, which is the condition
    /// rather than an adoption flag: an empty ledger means this process
    /// has no record of what VPP holds, whether because it just adopted
    /// a survivor or because it is starting fresh. A freshly spawned VPP
    /// answers with its own infrastructure routes and none of them pass
    /// the filter below, so the fresh case seeds nothing and costs one
    /// round trip.
    ///
    /// ## What it deliberately does NOT adopt, and why that matters
    ///
    /// VPP's FIB is not only ours. A fresh instance already holds drop
    /// routes, connected routes for interface subnets, and local `/32`s
    /// for interface addresses — all created by VPP itself. Seeding
    /// those would hand them to the resync diff, which withdraws
    /// everything the route source does not advertise, and the next
    /// convergence would delete the infrastructure VPP needs to resolve
    /// any adjacency at all.
    ///
    /// So a dumped route is adopted only if it looks like something this
    /// module installed: at least one path that is
    /// `FIB_API_PATH_TYPE_NORMAL`, egresses an interface **we** own, and
    /// carries a **non-zero nexthop address**. That last clause is what
    /// excludes connected routes, which are attached and therefore have
    /// no nexthop; type excludes local and drop. Anything else is left
    /// alone — an unadopted route is one we will not withdraw, which is
    /// the safe direction.
    pub fn adopt_vpp_fib(&mut self) -> Result<u64, EngineError> {
        if !self.ledger.known_prefixes().is_empty() {
            return Ok(0);
        }
        self.arm_timeout();
        if self.transport.is_none() {
            return Err(EngineError::NotConnected);
        }

        let mut adopted = 0u64;
        for &is_ip6 in self.drainer.families().dump_families() {
            let t = self.transport.as_mut().expect("checked just above");
            let details: Vec<IpRouteDetails> = match t.dump(IpRouteDump {
                context: 0,
                table: IpTable {
                    table_id: 0,
                    is_ip6,
                    name: String::new(),
                },
            }) {
                Ok(d) => d,
                Err(e) => {
                    self.disconnect();
                    return Err(EngineError::Transport(e));
                }
            };
            for d in details {
                let Some(prefix) = from_prefix(&d.route.prefix) else {
                    continue;
                };
                if !self.drainer.families().carries(prefix) {
                    continue;
                }
                if !self.looks_self_installed(&d.route) {
                    continue;
                }
                self.ledger.adopt_installed(prefix);
                adopted += 1;
            }
        }
        Ok(adopted)
    }

    /// Whether a route read back from VPP is one this module installed.
    /// See [`Self::adopt_vpp_fib`] for why the answer must be
    /// conservative.
    ///
    /// The adj-fib exclusion is the hard-won clause. VPP auto-creates a
    /// host route for every neighbour — `169.254.254.2/32` via the
    /// member port here — and it wears our exact signature: NORMAL
    /// path, owned interface, non-zero nexthop. Adopting it hands it to
    /// the diff, the route source never advertises it, and every
    /// adoption withdrew the neighbour's own host route: cover churn on
    /// the adjacency every route in the table resolves through, a
    /// dependent walk over ~1M entries, and a constant ~5.5 s blackhole
    /// that survived BOTH neighbour-send fixes because nothing here
    /// sent a neighbour message at all — the withdrawal recreated the
    /// entry from the route side (neighbour age reset at the release
    /// instant with both senders provably silent, shadow 2026-08-08).
    /// The tell is exact: a host route whose prefix IS its own nexthop,
    /// which this module never installs — our prefixes are the DFZ and
    /// our nexthops are the interconnect.
    fn looks_self_installed(&self, route: &IpRoute) -> bool {
        route.paths.iter().any(|p| {
            p.r#type == FIB_API_PATH_TYPE_NORMAL
                && self.port_index.owns(p.sw_if_index)
                && p.nh.address.0.iter().any(|b| *b != 0)
                && !is_neighbour_adj_fib(route, &p.nh.address.0)
        })
    }

    /// Queue a full-table resync as a **diff** against the route source.
    ///
    /// ## Adoption withdrawals: closed by the FIB readback
    ///
    /// The diff derives deletions from `ledger.known_prefixes()`, and on
    /// **adoption** the ledger starts empty while VPP's FIB does not — so
    /// a prefix withdrawn while packetframe was down used to stay
    /// installed in the surviving VPP, where a stale more-specific keeps
    /// overriding the live table, invisible to verification because it
    /// samples only what the ledger knows.
    ///
    /// [`Self::adopt_vpp_fib`] now seeds the ledger from `ip_route_dump`
    /// before this runs, so the diff below sees what VPP actually holds
    /// and withdraws accordingly. Callers must invoke it first;
    /// `Runtime::start_resync` does. Persisting the installed prefix set
    /// to the state file was the alternative and is not one: that is
    /// 1.05M prefixes rewritten continuously.
    ///
    /// Refreshes the nexthop→device mapping first: a route's
    /// resolvability depends on it, and resolving against a stale map
    /// would classify routes unresolvable for a neighbour that has since
    /// been learned.
    /// Pull live changes from the source into the pending map.
    ///
    /// Returns how many were taken. This only *queues* — sending is
    /// `drain_batch`'s job, exactly as it is for a resync, so there is one
    /// path to VPP rather than a steady-state one and a convergence one
    /// that can disagree.
    ///
    /// **Neighbours before routes**, and the order is load-bearing: a
    /// route whose nexthop the map has never seen is classified
    /// unresolvable, so a new nexthop arriving in the same batch as the
    /// routes that use it would black-hole them for a full resync cycle
    /// if applied the other way round.
    ///
    /// A neighbour that fails hands the **whole remainder** back to the
    /// source — the neighbour that failed, the ones not tried, and every
    /// route in the batch — and only then returns the error.
    /// `drain_changes` is destructive, so returning early with the route
    /// loop unreached dropped that batch's deltas: out of the feed's
    /// pending map, never into ours, retried by nothing. An already-
    /// steered VPP went on forwarding a withdrawn prefix and resolving a
    /// changed nexthop to its old adjacency, with every count clean and
    /// verify unable to see it (verify samples what the ledger believes
    /// installed, and the ledger never learned these existed).
    ///
    /// Handing the routes BACK rather than queueing them here is what
    /// keeps the ordering intact. Queued now, they would install through
    /// an adjacency VPP has just refused — #115's worst finding arriving
    /// through the delta door, which is the trap the note in
    /// [`Self::apply_neighbour`] describes.
    pub fn apply_changes(&mut self, src: &dyn RouteSource, max: usize) -> Result<u64, EngineError> {
        // Before the drain, so a failure here costs nothing: nothing has
        // been taken from the source yet. The skip below consults
        // `neighbours_installed`, and after a transport error mid-neighbour
        // that ledger describes a table VPP may not have — so VPP is asked
        // first. Ordinary ticks have nothing in doubt and this is free.
        if self.transport.is_some() {
            self.reconcile_unacked_neighbours()?;
        }
        let mut changes = src.drain_changes(max);
        if changes.is_empty() {
            return Ok(0);
        }
        let n = changes.len() as u64;
        // Popped from the back, which reorders nothing that has an order:
        // the feed holds neighbour deltas in a `HashMap`, so the batch
        // arrives in an arbitrary order already, and each entry names a
        // distinct nexthop. What matters is that whatever has not been
        // applied is still in the vec when a failure hands it back.
        while let Some((nh, state)) = changes.neighbours.pop() {
            if let Err(e) = self.apply_neighbour(nh, state.clone()) {
                changes.neighbours.push((nh, state));
                src.requeue(changes);
                return Err(e);
            }
        }
        for (prefix, nhs) in changes.routes {
            // Shadowed by a local-route: the mirror's view inside a
            // locally delivered prefix never reaches the pending map,
            // on the delta path exactly as at resync. The set tracks
            // presence so health can count what is being suppressed.
            if self.shadows(&prefix) {
                match nhs {
                    Some(_) => self.shadowed.insert(prefix),
                    None => self.shadowed.remove(&prefix),
                };
                continue;
            }
            match nhs {
                Some(v) => self.pending.upsert(prefix, v),
                None => self.pending.withdraw(prefix),
            }
        }
        Ok(n)
    }

    /// Apply one neighbour delta: program the adjacency in VPP, then
    /// record the mapping that makes routes through it resolvable.
    fn apply_neighbour(
        &mut self,
        nh: IpAddr,
        state: Option<(String, [u8; 6])>,
    ) -> Result<(), EngineError> {
        match state {
            Some((dev, mac)) => {
                // Resolved through the device the delta names, WITHOUT
                // recording it yet — the send comes first and the mapping
                // second.
                //
                // `set_device` alone makes `resolve` return `Some`, so
                // routes through this nexthop classify as resolvable and
                // install — while VPP, which runs without linux-cp and
                // can never ARP for the adjacency, has nothing to send
                // them to. Verification would not catch it either: it
                // checks a route exists on an interface we own,
                // deliberately not that its adjacency resolves. That is
                // #115's worst finding exactly, arriving through the
                // delta door instead of the resync one.
                //
                // Recording it before the send left that door open even
                // when the send FAILED: the mapping survived the error,
                // so the next drain resolved every pending route through
                // an adjacency VPP had refused and installed them clean.
                if let Some(idx) = self
                    .nexthops
                    .target_for_device(&dev)
                    .and_then(|t| self.port_index.get(&t))
                {
                    // Identical to what VPP acknowledged: nothing to
                    // send. The delta path re-learning a neighbour at
                    // daemon start is routine — the resolver re-reads
                    // the kernel table — and re-adding it walks every
                    // dependent route (the second door of the 5.5 s
                    // adoption blackhole; the first was
                    // `program_neighbours`).
                    if self.neighbours_installed.get(&(idx, nh)) != Some(&mac) {
                        self.send_neighbour(nh, idx, mac, true)?;
                    }
                }
                // Recorded even for a device VPP does not own, where the
                // send above never happened: `resolve` answers `None` for
                // an excluded device either way, so the entry cannot make
                // such a route installable, and leaving it out would make
                // a later loss for the same nexthop look like a mapping
                // that was never learned.
                self.nexthops.set_device(nh, dev);
                Ok(())
            }
            // Forgotten rather than left at its last known device —
            // see `NexthopMap::forget_device`. The routes through it
            // become unresolvable, which is the honest answer and the
            // one health reports.
            //
            // The adjacency is withdrawn from VPP first, while the
            // mapping that names its interface is still there to
            // withdraw it *with*.
            None => {
                if let Some(idx) = self
                    .nexthops
                    .resolve(&nh)
                    .and_then(|t| self.port_index.get(&t))
                {
                    self.send_neighbour(nh, idx, [0; 6], false)?;
                }
                self.nexthops.forget_device(&nh);
                Ok(())
            }
        }
    }

    pub fn begin_resync(&mut self, src: &dyn RouteSource) -> ResyncPlan {
        self.phase = Some(Phase::Resync);

        // Rebuild, not merge. An insert-only refresh leaves a nexthop the
        // source has stopped reporting mapped to its last known device,
        // so a route still naming it resolves as reachable through a
        // stale interface rather than being classified unresolvable —
        // traffic aimed at a neighbour that is gone, invisible to
        // readback verification because verification checks that the
        // route exists on an interface we own, not that its nexthop is
        // the one we meant.
        //
        // The source is authoritative, so an empty snapshot means every
        // route is unresolvable. That is loud by construction — verify
        // fails on `unresolvable > 0` and first-attach steering is
        // blocked — which is the right direction to fail if the
        // neighbour source is broken. Silently keeping stale mappings
        // would forward into the hole instead.
        self.nexthops.forget_devices();
        src.for_each_neighbour(&mut |nh, dev, _mac| self.nexthops.set_device(nh, dev));

        let mut plan = ResyncPlan::default();
        // The source's prefix set, so withdrawals are everything the
        // ledger holds that is not in it. ~50 MB transient at full
        // table, which is the unavoidable cost of a correct diff — the
        // alternative is an add-only resync that black-holes withdrawn
        // routes.
        let mut seen: HashSet<IpPrefix> = HashSet::with_capacity(1 << 20);
        // Rebuilt from this walk, so a prefix the mirror dropped while
        // we were not looking leaves the count too.
        self.shadowed.clear();
        src.for_each_route(&mut |prefix, nexthops| {
            if self.shadows(&prefix) {
                // Deliberately NOT in `seen`: if the ledger holds a
                // stale install of a shadowed prefix (a pre-local-route
                // run, or adoption), the withdrawal loop below is what
                // cleans it out of VPP.
                self.shadowed.insert(prefix);
                plan.shadowed += 1;
                return;
            }
            self.pending.upsert(prefix, nexthops.to_vec());
            seen.insert(prefix);
            plan.upserts += 1;
        });

        let known: HashSet<IpPrefix> = self.ledger.known_prefixes().into_iter().collect();
        for prefix in &known {
            if !seen.contains(prefix) {
                self.pending.withdraw(*prefix);
                plan.withdrawals += 1;
            }
        }

        // Drop leftovers from an aborted resync. Those prefixes live only
        // in the pending map — never classified, so the ledger cannot see
        // them and the withdrawal loop above cannot reach them. Without
        // this, a prefix the source dropped between an aborted resync and
        // this one keeps its stale upsert and gets installed later,
        // against a snapshot that no longer advertises it.
        //
        // Dropped rather than withdrawn: the ledger never knew them, so
        // VPP never received them, and a withdrawal for a route that was
        // never installed is a wasted round trip inside the convergence
        // budget.
        self.pending
            .retain(|p| seen.contains(p) || known.contains(p));

        // Anything parked at the high-water mark gets another chance:
        // withdrawals in this same plan may have freed the headroom.
        self.pending.release_withheld();
        if plan.shadowed > 0 {
            // The operator-visible proof the shadowing is doing its
            // job — the reference primary expects exactly its poisoned
            // host route here, and a jump in this number is a mirror
            // change worth reading about in `packetframe status`.
            tracing::info!(
                shadowed = plan.shadowed,
                "local-route shadowing suppressed mirror routes this resync"
            );
        }
        plan
    }

    /// Push one bounded batch. `Ok(true)` = nothing left pending.
    pub fn drain_batch(&mut self) -> Result<(bool, DrainStats), EngineError> {
        self.arm_timeout();
        // Resolve through the current map. Captured by reference so the
        // drainer sees the same mapping the ledger was classified
        // against.
        let nexthops = &self.nexthops;
        let resolve = move |addrs: &[IpAddr]| -> Vec<ResolvedPath> {
            addrs
                .iter()
                .filter_map(|nh| {
                    nexthops.resolve(nh).map(|target| ResolvedPath {
                        nexthop: *nh,
                        target,
                    })
                })
                .collect()
        };

        let t = self.transport.as_mut().ok_or(EngineError::NotConnected)?;
        match self.drainer.drain(
            &mut self.pending,
            &mut self.ledger,
            &resolve,
            &self.port_index,
            t,
            DRAIN_BATCH,
        ) {
            Ok(stats) => Ok((self.pending.is_empty(), stats)),
            Err((_, e)) => {
                // The drainer has already requeued everything it did not
                // get an acknowledgement for; the socket is what is
                // broken.
                self.disconnect();
                Err(EngineError::Transport(e))
            }
        }
    }

    /// Readback verification against a fresh random sample.
    pub fn run_verify(&mut self) -> Result<Verdict, EngineError> {
        // Transport first. Setting the phase before this check leaves it
        // stuck on `Verify` when the early return fires, and a phase
        // that never clears is a convergence the loop believes is still
        // running — so `may_restart` stays false and the supervisor can
        // never recover. Own test caught it; keep the order.
        if self.transport.is_none() {
            return Err(EngineError::NotConnected);
        }
        self.phase = Some(Phase::Verify);
        self.arm_timeout();
        self.verify_seed = next_seed(self.verify_seed);
        let seed = self.verify_seed;

        let active = self.active_egress_indices();
        let t = self.transport.as_mut().expect("checked just above");
        match verify(
            t,
            &self.ledger,
            &self.port_index,
            &active,
            DEFAULT_SAMPLE,
            seed,
        ) {
            Ok(outcome) => {
                self.last_verify = Some(outcome.clone());
                self.phase = None;
                // The gate the ledger has always been able to answer and
                // nothing asked.
                let may_steer = !self.ledger.counts().blocks_first_steer();
                Ok(Verdict { outcome, may_steer })
            }
            Err(e) => {
                self.disconnect();
                // Deliberately does NOT record a `last_verify`: a
                // transport failure is not a verdict on the FIB, and
                // storing it as a failed verify would report "FIB is
                // wrong" for what is actually "we could not ask".
                self.phase = None;
                Err(EngineError::Transport(e))
            }
        }
    }

    /// Every owned member interface that cannot forward right now,
    /// from a fresh `sw_interface_dump`. The steer gate's read — see
    /// [`crate::verify::dead_interface_scan`] for why it must be fresh
    /// rather than the last verify's recorded outcome.
    pub fn dead_members(&mut self) -> Result<Vec<crate::verify::DeadInterface>, EngineError> {
        #[cfg(test)]
        if let Some(dead) = &self.test_dead_members {
            return Ok(dead.clone());
        }
        let active = self.active_egress_indices();
        let Some(t) = self.transport.as_mut() else {
            return Err(EngineError::NotConnected);
        };
        crate::verify::dead_interface_scan(t, &self.port_index.indices(), &active)
            .map_err(EngineError::Transport)
    }

    /// Interfaces at least one static neighbour lives on — the set of
    /// egresses the FIB can actually choose, since every route the sink
    /// installs resolves through a neighbour it installed. Unacked
    /// neighbours count too: "VPP might hold an adjacency here" is
    /// enough to treat the interface as in use, in the direction that
    /// over-blocks rather than under-blocks a steer.
    fn active_egress_indices(&self) -> std::collections::HashSet<u32> {
        self.neighbours_installed
            .keys()
            .map(|(idx, _)| *idx)
            .chain(self.neighbours_unacked.iter().map(|(idx, _)| *idx))
            .collect()
    }

    /// Abandon whatever convergence step is in flight.
    ///
    /// Only clears the engine's own view. The pending map is left
    /// exactly as it is — those routes are still owed, and dropping them
    /// would make an aborted resync silently lose work that no later
    /// event would restore.
    pub fn abort_convergence(&mut self) {
        self.phase = None;
    }

    /// Forget everything learned from a VPP that is gone.
    ///
    /// Called when the process dies, and load-bearing for correctness on
    /// restart: interface indices are per-VPP-instance, so reusing them
    /// against a fresh process would install every route onto whatever
    /// interface happened to land on that index. The ledger is cleared
    /// for the same reason — a new VPP's FIB is empty, and claiming
    /// otherwise would let readback verification sample routes that were
    /// never installed and, worse, let `blocks_first_steer` read as
    /// clean.
    pub fn on_process_gone(&mut self) {
        self.disconnect();
        self.attached.clear();
        self.port_index = PortIndex::default();
        // The state file's recorded indices belong to the dead instance
        // too. Keeping them meant the replacement process was handed
        // indices its interface dump cannot contain, so `attach_ports`
        // answered `StaleIndex` — correctly, it cannot tell whether a
        // live FIB still references them — and every recovery after an
        // adopted-process failure was driven straight back into teardown.
        self.recorded_indices.clear();
        // Same reasoning, one interface further: the loopback belonged
        // to the dead process. Keeping its index would have the next
        // attach unnumber every member to an interface that no longer
        // exists — which VPP would refuse, or worse accept.
        self.loop_index = None;
        // The neighbour ledger describes the dead instance's table.
        self.neighbours_installed.clear();
        // And so does the doubt about it: whatever the dead VPP did or did
        // not apply is moot, and carrying the keys over would make the
        // replacement's first delta pay for a dump that can only confirm
        // an empty table.
        self.neighbours_unacked.clear();
        self.pending = PendingMap::new();
        self.ledger = RouteLedger::new(self.ledger_capacity());
        self.phase = None;
        self.last_verify = None;
    }

    fn ledger_capacity(&self) -> Capacity {
        // Capacity is a policy, not observed state, so it survives the
        // process it was applied to.
        self.ledger.capacity()
    }

    /// The route capacity in force — the high-water policy derived from
    /// the operator's `expected-routes`. The pre-dump deferral floor is
    /// computed from this, because at that point the adopted table's
    /// size is unknowable: reading it is exactly the thing being
    /// deferred.
    pub fn route_capacity(&self) -> u64 {
        self.ledger.capacity().high_water()
    }
}

/// splitmix64. Deterministic successor so verify samples differ per pass
/// while staying replayable from the recorded seed.
/// The adj-fib signature: a HOST route whose prefix is its own nexthop.
///
/// `nh` is the path's 16-byte wire address (v4 in the first four bytes,
/// zero-padded — the same layout `Prefix.address.un` uses), so equality
/// over the whole union plus the host length is the exact test. See
/// [`ConvergenceEngine::looks_self_installed`] for why this exists.
fn is_neighbour_adj_fib(route: &IpRoute, nh: &[u8; 16]) -> bool {
    let host = match route.prefix.address.af {
        crate::vpp_api::generated::ADDRESS_IP4 => route.prefix.len == 32,
        _ => route.prefix.len == 128,
    };
    host && route.prefix.address.un.0 == *nh
}

fn next_seed(prev: u64) -> u64 {
    let mut z = prev.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpPrefix {
        IpPrefix::V4 {
            addr: [a, b, c, d],
            prefix_len: len,
        }
    }

    fn nh(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, d))
    }

    /// A mirror we can mutate between resyncs, which is the whole point
    /// of testing the diff.
    struct Mirror {
        routes: Vec<(IpPrefix, Vec<IpAddr>)>,
        devices: Vec<(IpAddr, String)>,
    }

    impl RouteSource for Mirror {
        fn requeue(&self, _: SourceChanges) {
            unreachable!("this source hands nothing over, so nothing can come back")
        }
        fn route_count(&self) -> u64 {
            let mut n = 0u64;
            self.for_each_route(&mut |_, _| n += 1);
            n
        }
        fn change_seq(&self) -> u64 {
            self.route_count()
        }

        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            for (p, nhs) in &self.routes {
                visit(*p, nhs);
            }
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            for (a, d) in &self.devices {
                visit(*a, d, [0x02, 0, 0, 0, 0, 1]);
            }
        }
    }

    fn engine() -> ConvergenceEngine {
        ConvergenceEngine::new(
            "/nonexistent/api.sock",
            vec![PortAttach {
                port: "eth4".into(),
                pci_addr: "0002:07:00.1".into(),
                port_id: 0,
                num_rx_queues: 1,
                pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                accept_macs: vec![],
                vlans: vec![],
            }],
            vec!["eth4".into()],
            1_000_000,
            FamilyPolicy::V4Only,
            packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
                prefix_len: 32,
            },
        )
    }

    fn mirror(n: u8) -> Mirror {
        Mirror {
            routes: (0..n).map(|i| (v4(10, i, 0, 0, 16), vec![nh(1)])).collect(),
            devices: vec![(nh(1), "eth4".into())],
        }
    }

    #[test]
    fn a_resync_queues_every_route_from_the_source() {
        let mut e = engine();
        let plan = e.begin_resync(&mirror(5));
        assert_eq!(plan.upserts, 5);
        assert_eq!(plan.withdrawals, 0);
        assert_eq!(e.pending().len(), 5);
        assert_eq!(e.phase(), Some(Phase::Resync));
    }

    /// The failure the plan names: an add-only resync leaves a withdrawn
    /// route installed, forwarding to a nexthop nobody advertises — and
    /// readback verification cannot see it, because verification samples
    /// what the ledger claims and the ledger claims it is fine.
    #[test]
    fn a_resync_withdraws_what_the_source_dropped() {
        let mut e = engine();
        // Pretend a previous run installed five routes.
        let m = mirror(5);
        e.begin_resync(&m);
        for (p, nhs) in &m.routes {
            e.ledger.classify_upsert(*p, nhs, &e.nexthops.clone());
            e.ledger.commit_installed(*p);
        }
        assert_eq!(e.counts().installed, 5);

        // Two prefixes go away while we were not looking.
        let mut shrunk = mirror(5);
        shrunk.routes.truncate(3);
        let plan = e.begin_resync(&shrunk);
        assert_eq!(plan.upserts, 3);
        assert_eq!(
            plan.withdrawals, 2,
            "the two dropped prefixes must be queued for withdrawal"
        );
    }

    #[test]
    fn a_resync_refreshes_the_nexthop_map_before_resolving() {
        let mut e = engine();
        // Nothing known yet, so this nexthop is unresolvable.
        assert!(e.nexthops.resolve(&nh(7)).is_none());
        let m = Mirror {
            routes: vec![(v4(10, 0, 0, 0, 8), vec![nh(7)])],
            devices: vec![(nh(7), "eth4".into())],
        };
        e.begin_resync(&m);
        assert!(
            e.nexthops.resolve(&nh(7)).is_some(),
            "the neighbour learned since last time must be usable now, or \
             the route is misclassified unresolvable"
        );
    }

    /// Interface indices are per-VPP-instance. Reusing them against a
    /// fresh process would install every route onto whatever interface
    /// happened to take that index.
    #[test]
    fn a_dead_process_invalidates_everything_learned_from_it() {
        let mut e = engine();
        e.port_index.insert("eth4", None, 3);
        e.attached.push(AttachedPort {
            port: "eth4".into(),
            dev_index: Some(0),
            sw_if_index: 3,
            subifs: vec![],
        });
        let m = mirror(4);
        e.begin_resync(&m);
        for (p, nhs) in &m.routes {
            e.ledger.classify_upsert(*p, nhs, &e.nexthops.clone());
            e.ledger.commit_installed(*p);
        }
        e.last_verify = Some(VerifyOutcome {
            sampled: 64,
            ..Default::default()
        });
        assert!(e.counts().installed > 0);

        e.on_process_gone();

        assert_eq!(e.counts(), SinkCounts::default(), "ledger must be empty");
        assert!(e.port_links().is_empty(), "indices are per-instance");
        assert!(e.pending().is_empty());
        assert!(e.last_verify().is_none(), "a dead VPP has no verdict");
        assert_eq!(e.phase(), None);
        assert!(!e.is_connected());
        // And the empty ledger must not read as a clean table: nothing
        // is installed, so nothing is verified, so steering stays
        // blocked until a fresh resync says otherwise.
        assert!(!e.counts().blocks_first_steer());
        assert!(e.last_verify().is_none());
    }

    /// Capacity is policy, not observed state, so it has to survive the
    /// process it was applied to — otherwise a restart would rebuild the
    /// ledger with an unbounded high-water mark and install past the
    /// heap.
    #[test]
    fn capacity_policy_survives_a_restart() {
        let mut e = ConvergenceEngine::new(
            "/nonexistent/api.sock",
            Vec::new(),
            vec!["eth4".into()],
            2,
            FamilyPolicy::V4Only,
            packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
                prefix_len: 32,
            },
        );
        e.nexthops.set_device(nh(1), "eth4");
        for i in 0..4u8 {
            let p = v4(10, i, 0, 0, 16);
            e.ledger.classify_upsert(p, &[nh(1)], &e.nexthops.clone());
            e.ledger.commit_installed(p);
        }
        assert_eq!(e.counts().installed, 2);
        assert_eq!(e.counts().withheld, 2);

        e.on_process_gone();
        for i in 0..4u8 {
            let p = v4(10, i, 0, 0, 16);
            e.ledger.classify_upsert(p, &[nh(1)], &e.nexthops.clone());
            e.ledger.commit_installed(p);
        }
        assert_eq!(
            e.counts().installed,
            2,
            "the high-water mark must still bind after a restart"
        );
    }

    /// `on_process_gone` clears the last verify verdict, and it must —
    /// the verdict describes a FIB that died with the instance.
    ///
    /// Pinned because the supervision loop depends on it in the awkward
    /// direction: `VerifyFailed`'s own teardown kills the process, so the
    /// engine erases the verdict as a side effect of acting on it. The
    /// loop therefore keeps its own copy, captured before the injection
    /// (see `service::run_loop`), and without that a completed, failed
    /// verification was reported as "never verified" — a concrete failure
    /// summary replaced by something indistinguishable from a VPP still
    /// converging. If this clearing is ever removed, the retention in the
    /// loop becomes redundant rather than load-bearing; this test is where
    /// that shows up.
    #[test]
    fn a_dead_process_takes_its_verify_verdict_with_it() {
        let mut e = ConvergenceEngine::new(
            "/nonexistent/api.sock",
            Vec::new(),
            vec!["eth4".into()],
            1_000,
            FamilyPolicy::V4Only,
            packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
                prefix_len: 32,
            },
        );
        e.last_verify = Some(crate::verify::VerifyOutcome {
            sampled: 4,
            mismatches: vec![],
            unresolvable: 0,
            withheld: 0,
            dead_interfaces: vec![],
        });
        assert!(e.last_verify().is_some());
        e.on_process_gone();
        assert!(
            e.last_verify().is_none(),
            "the verdict outlived the instance it describes"
        );
    }

    /// Every operation must refuse rather than pretend when there is no
    /// socket. An engine that silently no-ops would report a converged
    /// FIB it never sent.
    #[test]
    fn nothing_succeeds_without_a_transport() {
        let mut e = engine();
        assert!(!e.is_connected());
        assert!(matches!(e.ping(), Err(EngineError::NotConnected)));
        assert!(matches!(e.drain_batch(), Err(EngineError::NotConnected)));
        assert!(matches!(e.run_verify(), Err(EngineError::NotConnected)));
        assert!(matches!(
            e.attach_devices(AttachMode::Fresh),
            Err(EngineError::NotConnected)
        ));
        // A refused attach must not have consumed the port list — the
        // next attempt needs it.
        assert!(matches!(
            e.attach_devices(AttachMode::Fresh),
            Err(EngineError::NotConnected)
        ));
    }

    /// A transport failure during verify is not a verdict on the FIB.
    /// Recording it as a failed verify would report "the FIB is wrong"
    /// for what is actually "we could not ask", and that difference
    /// decides whether the supervisor cycles a healthy VPP.
    #[test]
    fn a_transport_failure_is_not_a_verify_verdict() {
        let mut e = engine();
        assert!(e.run_verify().is_err());
        assert!(e.last_verify().is_none());
        assert_eq!(e.phase(), None, "the phase must not stay stuck");
    }

    #[test]
    fn verify_seeds_differ_per_pass_but_are_reproducible() {
        let a = next_seed(0);
        let b = next_seed(a);
        assert_ne!(a, b);
        assert_ne!(a, 0);
        // Deterministic: the same predecessor always gives the same
        // successor, which is what makes a failing pass replayable.
        assert_eq!(next_seed(0), a);
    }

    /// A nexthop the source stops reporting must become unresolvable, not
    /// keep its last known device. Otherwise a route naming a vanished
    /// neighbour resolves as reachable through a stale interface, and
    /// readback verification cannot see it — verification checks the
    /// route exists on an interface we own, deliberately not that its
    /// nexthop is the one we meant.
    #[test]
    fn a_nexthop_the_source_dropped_becomes_unresolvable() {
        let mut e = engine();
        let p = v4(10, 0, 0, 0, 8);

        let with_nh = Mirror {
            routes: vec![(p, vec![nh(1)])],
            devices: vec![(nh(1), "eth4".into())],
        };
        e.begin_resync(&with_nh);
        assert!(e.nexthops.resolve(&nh(1)).is_some());

        // The neighbour goes away; the route still names it.
        let without_nh = Mirror {
            routes: vec![(p, vec![nh(1)])],
            devices: Vec::new(),
        };
        e.begin_resync(&without_nh);
        assert!(
            e.nexthops.resolve(&nh(1)).is_none(),
            "a dropped nexthop must not keep its stale device"
        );
        // And classification now says so, rather than pointing a path at
        // an interface the neighbour no longer lives on.
        let st = e
            .ledger
            .classify_resolved(p, e.nexthops.resolve_all(&[nh(1)]).len());
        assert_eq!(
            st,
            crate::sink::RouteState::NotInstalled(crate::sink::NotInstalled::Unresolvable)
        );
    }

    /// The state file's indices belong to the instance that is gone.
    /// Keeping them handed the replacement process indices its dump
    /// cannot contain, so attach answered `StaleIndex` and every recovery
    /// after an adopted-process failure went straight back to teardown.
    #[test]
    fn a_dead_process_invalidates_the_recorded_indices_too() {
        let mut e = engine().with_recorded_indices(vec![("eth4".into(), 9)]);
        assert!(!e.recorded_indices.is_empty());
        e.on_process_gone();
        assert!(
            e.recorded_indices.is_empty(),
            "recorded indices belong to the dead instance"
        );
    }

    /// The socket deadline must equal the budget in force — not the
    /// largest one.
    ///
    /// Too short and the transport errors during a legitimate full-table
    /// load, defeating SYNC_PING_BUDGET. Too long and `Driver`'s
    /// synchronous `ping()` parks the whole loop inside one socket read,
    /// so the detector never gets to emit `Wedged` and the published
    /// blackhole-wedge <= 2 s number becomes whatever the timeout is.
    /// Both were shipped, in that order.
    #[test]
    fn the_socket_deadline_tracks_the_budget_in_force() {
        for steered in [false, true] {
            for converging in [false, true] {
                assert_eq!(
                    op_timeout(steered, converging),
                    crate::liveness::budget_for(steered, converging),
                    "steered={steered} converging={converging}"
                );
            }
        }
        // The worst case must still leave the published wedge bound
        // intact: a blocked ping returns within the budget, so detection
        // is budget + interval exactly as `worst_case_detection` says.
        let steady = op_timeout(true, false);
        assert!(
            crate::liveness::worst_case_detection(steady) <= Duration::from_secs(2),
            "a blocked ping must not push detection past the published 2s"
        );
        // A resync that is not forwarding may take much longer.
        assert!(op_timeout(false, true) > steady);
    }

    /// The deadline follows the state rather than being fixed at connect,
    /// because the state changes between operations.
    #[test]
    fn arming_follows_steered_and_converging() {
        let mut e = engine();
        assert_eq!(
            op_timeout(e.steered, e.phase.is_some()),
            crate::liveness::PING_BUDGET
        );
        e.begin_resync(&mirror(1));
        assert_eq!(
            op_timeout(e.steered, e.phase.is_some()),
            crate::liveness::SYNC_PING_BUDGET,
            "an unsteered resync gets the long budget"
        );
        e.set_steered(true);
        assert_eq!(
            op_timeout(e.steered, e.phase.is_some()),
            crate::liveness::PING_BUDGET,
            "a steered resync forwards the whole time and cannot afford it"
        );
    }

    /// Link state must come from an observation. An earlier version
    /// hard-coded both flags true, so a port verify had just found dead
    /// still reported as forwarding.
    #[test]
    fn port_links_report_what_verify_observed() {
        let mut e = engine();
        e.attached.push(AttachedPort {
            port: "eth4".into(),
            dev_index: Some(0),
            sw_if_index: 3,
            subifs: vec![],
        });
        // No verify yet: nothing contradicts, so it reads up — bounded by
        // `nominal()` independently requiring a passing verify.
        assert!(e.port_links()[0].link_up);

        e.last_verify = Some(VerifyOutcome {
            sampled: 64,
            dead_interfaces: vec![crate::verify::DeadInterface {
                in_use: true,
                sw_if_index: 3,
                name: "octeon0/0".into(),
                admin_up: true,
                link_up: false,
            }],
            ..Default::default()
        });
        let links = e.port_links();
        assert_eq!(links.len(), 1);
        assert!(links[0].admin_up);
        assert!(
            !links[0].link_up,
            "a port verify found dead must not report as forwarding"
        );
        // `in_use` is the CURRENT neighbour ledger, not the verify-time
        // recording — the dead entry above claims in_use and must not be
        // believed while no neighbour lives on the port. Verify never
        // re-runs in steady state, so a recording would miss routes
        // shifting onto a dark member afterwards.
        assert!(
            !links[0].in_use,
            "no neighbour lives on idx 3, so nothing can egress there now"
        );
        e.neighbours_installed
            .insert((3, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))), [0; 6]);
        assert!(
            e.port_links()[0].in_use,
            "a neighbour on the port means installed routes can egress it"
        );
    }

    /// A withheld route must not re-steer traffic into the FIB.
    ///
    /// `VerifyOutcome::passed()` deliberately ignores `withheld` — failing
    /// on it would turn the designed response to a table that outgrew its
    /// heap into a restart loop — so the gate has to live somewhere else.
    /// It lived in `blocks_first_steer()`, which nothing consulted, so a
    /// restart of a previously-steered VPP would have diverted traffic
    /// into a FIB missing exactly the prefixes that did not fit.
    #[test]
    fn an_incomplete_table_verifies_without_permitting_a_steer() {
        use crate::supervisor::Event;

        let clean = Verdict {
            outcome: VerifyOutcome {
                sampled: 64,
                ..Default::default()
            },
            may_steer: true,
        };
        assert_eq!(clean.event(), Event::VerifyPassed);

        // Incomplete: correct as far as it goes, so NOT a failure — but
        // not steerable either.
        let incomplete = Verdict {
            outcome: VerifyOutcome {
                sampled: 64,
                withheld: 12,
                ..Default::default()
            },
            may_steer: false,
        };
        assert!(
            incomplete.outcome.passed(),
            "withheld must not fail verification, or a full table \
             restart-loops"
        );
        assert_eq!(
            incomplete.event(),
            Event::VerifyIncomplete,
            "and must not re-steer either"
        );

        // A genuinely wrong FIB still fails, regardless of steerability
        // — and "wrong" means MISMATCHES: VPP answered a probe and
        // disagreed. That is the only condition a teardown repairs.
        let wrong = Verdict {
            outcome: VerifyOutcome {
                sampled: 64,
                mismatches: vec![crate::verify::Mismatch::NoPaths {
                    prefix: IpPrefix::V4 {
                        addr: [192, 0, 2, 0],
                        prefix_len: 24,
                    },
                }],
                ..Default::default()
            },
            may_steer: true,
        };
        assert!(!wrong.outcome.passed());
        assert_eq!(wrong.event(), Event::VerifyFailed);
    }

    /// A table the source has not delivered yet is not a wrong FIB,
    /// and neither is a nexthop-device mapping with holes. Both fail
    /// `fib_correct` — steering must refuse them — but neither is
    /// restart-worthy: a teardown cannot make bird dump faster, and it
    /// cannot make a non-member port a member.
    ///
    /// The primary's w7 window (2026-08-13) is the repro for the first
    /// arm: verify ran ~1 s after spawn, before bird's session opened,
    /// sampled nothing, and `sampled == 0` rode the restart-worthy
    /// verdict — seven kill-respawn cycles in 31 s, each one re-running
    /// the octeon driver's port start against the shared LMAC and
    /// blacking out the switch0 bridge. The eth4-only bisection config
    /// is the repro for the second: the full table's nexthops egress
    /// eth2/eth3, which are not members, so `unresolvable` is
    /// structurally nonzero and the old mapping could never converge.
    #[test]
    fn an_undelivered_or_unmappable_table_holds_rather_than_restarts() {
        use crate::supervisor::Event;

        let empty = Verdict {
            outcome: VerifyOutcome::default(),
            may_steer: false,
        };
        assert!(!empty.outcome.fib_correct(), "empty is still not correct");
        assert_eq!(
            empty.event(),
            Event::VerifyIncomplete,
            "an empty sample must hold, not tear down"
        );

        let holes = Verdict {
            outcome: VerifyOutcome {
                sampled: 64,
                unresolvable: 3,
                ..Default::default()
            },
            may_steer: false,
        };
        assert!(!holes.outcome.fib_correct(), "holes still refuse steering");
        assert_eq!(
            holes.event(),
            Event::VerifyIncomplete,
            "unresolvable routes must hold, not tear down"
        );
    }

    /// A dark member interface is not a wrong FIB, and must not reach
    /// the restart-worthy verdict — a restart cannot plug in a cable.
    /// Three uncabled shadow ports turned exactly this mapping into an
    /// infinite kill-respawn loop over a flawless FIB (repro
    /// 2026-08-13). It rides the `VerifyIncomplete` arm instead: reach
    /// `Ready`, keep the want, do not steer — the steer path re-checks
    /// link state fresh at steer time.
    #[test]
    fn a_dark_member_is_incomplete_not_failed() {
        use crate::supervisor::Event;
        use crate::verify::DeadInterface;

        let dark = Verdict {
            outcome: VerifyOutcome {
                sampled: 64,
                dead_interfaces: vec![DeadInterface {
                    sw_if_index: 2,
                    name: "octeon0/0".into(),
                    admin_up: true,
                    link_up: false,
                    in_use: true,
                }],
                ..Default::default()
            },
            may_steer: true,
        };
        assert!(dark.outcome.fib_correct(), "the FIB itself is flawless");
        assert!(
            !dark.outcome.passed(),
            "but an in-use dark member must still block a steering pass"
        );
        assert_eq!(
            dark.event(),
            Event::VerifyIncomplete,
            "in-use dark members must not restart-loop a healthy VPP"
        );

        // An IDLE dark member — no route can egress it — blocks
        // nothing: the whole offload must not be held hostage to an
        // uncabled port with no routes (the primary's eth5).
        let idle_dark = Verdict {
            outcome: VerifyOutcome {
                sampled: 64,
                dead_interfaces: vec![DeadInterface {
                    sw_if_index: 5,
                    name: "octeon5/0".into(),
                    admin_up: true,
                    link_up: false,
                    in_use: false,
                }],
                ..Default::default()
            },
            may_steer: true,
        };
        assert!(
            idle_dark.outcome.passed(),
            "{}",
            idle_dark.outcome.summary()
        );
        assert_eq!(
            idle_dark.event(),
            Event::VerifyPassed,
            "an idle dark member must not block the offload"
        );
        assert!(
            idle_dark.outcome.summary().contains("idle"),
            "but it must still be visible: {}",
            idle_dark.outcome.summary()
        );

        // Both at once: a wrong FIB wins — teardown IS the remedy for
        // that half, whatever the cabling looks like. "Wrong" means a
        // probe mismatch; an empty sample alongside a dark member is
        // two hold conditions, not a failure (the old `sampled: 0`
        // fixture here asserted the exact mapping that kill-looped the
        // primary's w7 window, 2026-08-13).
        let dark_and_wrong = Verdict {
            outcome: VerifyOutcome {
                sampled: 64,
                mismatches: vec![crate::verify::Mismatch::NoPaths {
                    prefix: IpPrefix::V4 {
                        addr: [192, 0, 2, 0],
                        prefix_len: 24,
                    },
                }],
                dead_interfaces: vec![DeadInterface {
                    sw_if_index: 2,
                    name: "octeon0/0".into(),
                    admin_up: true,
                    link_up: false,
                    in_use: true,
                }],
                ..Default::default()
            },
            may_steer: false,
        };
        assert_eq!(dark_and_wrong.event(), Event::VerifyFailed);
    }

    /// Leftovers from an aborted resync live only in the pending map —
    /// never classified, so the ledger cannot see them and the withdrawal
    /// loop cannot reach them. A prefix the source drops in between would
    /// otherwise keep its stale upsert and install later.
    #[test]
    fn an_aborted_resyncs_leftovers_do_not_survive_the_next_one() {
        let mut e = engine();
        e.begin_resync(&mirror(5));
        assert_eq!(e.pending().len(), 5);
        // Aborted before anything was classified.
        e.abort_convergence();
        assert_eq!(e.counts(), SinkCounts::default(), "nothing classified");

        // The source drops two prefixes while we were not draining.
        let mut shrunk = mirror(5);
        shrunk.routes.truncate(3);
        e.begin_resync(&shrunk);
        assert_eq!(
            e.pending().len(),
            3,
            "the two dropped prefixes must not still be queued for install"
        );
    }

    /// A permanent handshake failure must be distinguishable from a slow
    /// start, or the supervisor waits out the startup budget and
    /// restart-loops forever without anything naming the version skew.
    #[test]
    fn a_permanent_handshake_failure_is_named_as_such() {
        let mut e = engine();
        // Nothing listening: transient, and retrying is right.
        assert!(!e.api_ready());
        assert!(e.last_api_error().is_some(), "the reason must be recorded");
        assert!(
            !e.api_incompatible(),
            "a missing socket is not a version skew"
        );
    }

    #[test]
    fn aborting_convergence_keeps_the_work_owed() {
        let mut e = engine();
        e.begin_resync(&mirror(6));
        assert_eq!(e.pending().len(), 6);
        e.abort_convergence();
        assert_eq!(e.phase(), None);
        assert_eq!(
            e.pending().len(),
            6,
            "aborting must not drop routes that are still owed"
        );
    }
}
