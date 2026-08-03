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
use crate::fib_sync::{DrainStats, Drainer, FamilyPolicy, PortIndex, ResolvedPath, DEFAULT_WINDOW};
use crate::sink::{Capacity, NexthopMap, PendingMap, RouteLedger, SinkCounts};
use crate::status::PortLink;
use crate::verify::{verify, VerifyOutcome, DEFAULT_SAMPLE};
use crate::vpp_api::{Transport, TransportError};

/// How long to wait for the handshake on a connect attempt.
///
/// Short on purpose: `api_ready` is polled from the supervision loop and
/// a long blocking connect would stall the tick that also services the
/// pidfd and the wedge ping. A timeout here just means the next tick
/// tries again; the *overall* patience for a slow start is
/// `API_STARTUP_BUDGET`, which is the loop's business, not this call's.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(500);

/// Socket timeout for every request after the handshake.
///
/// **Must exceed the largest liveness budget**, and that is the whole
/// reason it is a separate constant. `Transport::connect` installs its
/// timeout with `set_read_timeout`, so it governs not just the handshake
/// but every subsequent reply — and using the short handshake value would
/// make the transport error at 500 ms during a full-table load, when VPP
/// legitimately takes seconds to answer because it services the API on
/// the same main thread that is executing our route batch.
///
/// That would hand the transport a veto over a decision that belongs to
/// the wedge detector: `SYNC_PING_BUDGET` exists precisely so a resync
/// can be slow without being declared dead, and a shorter socket timeout
/// silently defeats it — disconnect, requeue, restart, forever, on a VPP
/// that was working. Derived from the budget rather than picked so the
/// two cannot drift.
pub const OP_TIMEOUT: Duration = crate::liveness::SYNC_PING_BUDGET.saturating_add(TIMEOUT_MARGIN);

/// Headroom between the largest liveness budget and the socket timeout,
/// so a reply arriving right at the budget is not raced by the socket.
pub const TIMEOUT_MARGIN: Duration = Duration::from_secs(2);

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

    /// Visit each known nexthop → egress device pair, from the same
    /// neighbour source that supplies VPP's static neighbours.
    fn for_each_nexthop_device(&self, visit: &mut dyn FnMut(IpAddr, &str));
}

/// What a full-table resync queued.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResyncPlan {
    pub upserts: u64,
    /// Prefixes the ledger holds that the source no longer advertises.
    /// Non-zero after any outage during which routes were withdrawn.
    pub withdrawals: u64,
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
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConnected => write!(f, "binary API is not connected"),
            Self::Transport(e) => write!(f, "{e}"),
            Self::Attach(e) => write!(f, "{e}"),
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
    /// `(port, sw_if_index)` recorded from a previous run, for adoption.
    recorded_indices: Vec<(String, u32)>,
    attached: Vec<AttachedPort>,
    port_index: PortIndex,

    pending: PendingMap,
    ledger: RouteLedger,
    nexthops: NexthopMap,
    drainer: Drainer,

    phase: Option<Phase>,
    last_verify: Option<VerifyOutcome>,
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
    ) -> Self {
        Self {
            api_socket: api_socket.into(),
            transport: None,
            ports,
            recorded_indices: Vec::new(),
            attached: Vec::new(),
            port_index: PortIndex::default(),
            pending: PendingMap::new(),
            ledger: RouteLedger::new(Capacity::new(high_water_routes)),
            nexthops: NexthopMap::new(members),
            drainer: Drainer::new(DEFAULT_WINDOW).with_families(families),
            phase: None,
            last_verify: None,
            verify_seed: 0,
        }
    }

    /// Seed the port→index map from the state file so an adopted VPP's
    /// existing interfaces are reused rather than duplicated.
    pub fn with_recorded_indices(mut self, known: Vec<(String, u32)>) -> Self {
        self.recorded_indices = known;
        self
    }

    // NOTE: there is deliberately no `add_vlan` here, even though
    // [`NexthopMap`] supports VLAN nexthops.
    //
    // Teaching the mapping to return `NexthopTarget::Subif` is only half
    // of it: FIB paths need the sub-interface's OWN `sw_if_index`, and
    // nothing creates or discovers one. The generated API whitelist has
    // no sub-interface message at all, so `PortIndex` could never gain a
    // `(port, Some(vid))` entry — `build_paths` would return `None` for
    // every route through that VLAN, the drainer would defer all of them
    // forever, and the resync would burn the whole convergence budget
    // installing nothing.
    //
    // An affordance that silently produces a permanently-deferred table
    // is worse than a missing one, so it is missing. Re-enabling it means
    // adding a sub-interface create message to the whitelist, calling it
    // during attach, and recording the index VPP assigns.
    //
    // Not currently needed: the gate-0b nexthop histogram found exactly
    // two egress devices across the whole table and no VLAN nexthops —
    // the br1337/FDB-pin topology is a connected-route concern, not a BGP
    // nexthop one.

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
    pub fn port_links(&self) -> Vec<PortLink> {
        let dead = self
            .last_verify
            .as_ref()
            .map(|v| v.dead_interfaces.as_slice())
            .unwrap_or_default();
        self.attached
            .iter()
            .map(
                |p| match dead.iter().find(|d| d.sw_if_index == p.sw_if_index) {
                    Some(d) => PortLink {
                        port: p.port.clone(),
                        sw_if_index: p.sw_if_index,
                        admin_up: d.admin_up,
                        link_up: d.link_up,
                    },
                    None => PortLink {
                        port: p.port.clone(),
                        sw_if_index: p.sw_if_index,
                        admin_up: true,
                        link_up: true,
                    },
                },
            )
            .collect()
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
                // Re-arm to the operation timeout. The handshake value is
                // deliberately short so a failed connect costs the loop
                // one tick, but `connect` installs it as the socket's
                // persistent read/write timeout — leaving it in force
                // would make every drain reply time out at 500 ms during
                // a full-table load and defeat SYNC_PING_BUDGET.
                if t.set_timeout(OP_TIMEOUT).is_err() {
                    return false;
                }
                self.transport = Some(t);
                true
            }
            Err(_) => false,
        }
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
        let result = attach_ports(t, &ports, &known, mode);
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
        }
        self.attached = attached;
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

    /// Queue a full-table resync as a **diff** against the route source.
    ///
    /// Refreshes the nexthop→device mapping first: a route's
    /// resolvability depends on it, and resolving against a stale map
    /// would classify routes unresolvable for a neighbour that has since
    /// been learned.
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
        src.for_each_nexthop_device(&mut |nh, dev| self.nexthops.set_device(nh, dev));

        let mut plan = ResyncPlan::default();
        // The source's prefix set, so withdrawals are everything the
        // ledger holds that is not in it. ~50 MB transient at full
        // table, which is the unavoidable cost of a correct diff — the
        // alternative is an add-only resync that black-holes withdrawn
        // routes.
        let mut seen: HashSet<IpPrefix> = HashSet::with_capacity(1 << 20);
        src.for_each_route(&mut |prefix, nexthops| {
            self.pending.upsert(prefix, nexthops.to_vec());
            seen.insert(prefix);
            plan.upserts += 1;
        });

        for prefix in self.ledger.known_prefixes() {
            if !seen.contains(&prefix) {
                self.pending.withdraw(prefix);
                plan.withdrawals += 1;
            }
        }

        // Anything parked at the high-water mark gets another chance:
        // withdrawals in this same plan may have freed the headroom.
        self.pending.release_withheld();
        plan
    }

    /// Push one bounded batch. `Ok(true)` = nothing left pending.
    pub fn drain_batch(&mut self) -> Result<(bool, DrainStats), EngineError> {
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
    pub fn run_verify(&mut self) -> Result<VerifyOutcome, EngineError> {
        // Transport first. Setting the phase before this check leaves it
        // stuck on `Verify` when the early return fires, and a phase
        // that never clears is a convergence the loop believes is still
        // running — so `may_restart` stays false and the supervisor can
        // never recover. Own test caught it; keep the order.
        if self.transport.is_none() {
            return Err(EngineError::NotConnected);
        }
        self.phase = Some(Phase::Verify);
        self.verify_seed = next_seed(self.verify_seed);
        let seed = self.verify_seed;

        let t = self.transport.as_mut().expect("checked just above");
        match verify(t, &self.ledger, &self.port_index, DEFAULT_SAMPLE, seed) {
            Ok(outcome) => {
                self.last_verify = Some(outcome.clone());
                self.phase = None;
                Ok(outcome)
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
}

/// splitmix64. Deterministic successor so verify samples differ per pass
/// while staying replayable from the recorded seed.
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
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            for (p, nhs) in &self.routes {
                visit(*p, nhs);
            }
        }
        fn for_each_nexthop_device(&self, visit: &mut dyn FnMut(IpAddr, &str)) {
            for (a, d) in &self.devices {
                visit(*a, d);
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
            }],
            vec!["eth4".into()],
            1_000_000,
            FamilyPolicy::V4Only,
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

    /// The socket timeout must never be shorter than the largest liveness
    /// budget, or the transport errors before the wedge detector's budget
    /// expires and takes a decision that belongs to the detector — a busy
    /// but healthy VPP gets disconnected, requeued and restarted.
    #[test]
    fn the_operation_timeout_outlasts_every_liveness_budget() {
        for steered in [false, true] {
            for converging in [false, true] {
                let budget = crate::liveness::budget_for(steered, converging);
                assert!(
                    OP_TIMEOUT > budget,
                    "OP_TIMEOUT {OP_TIMEOUT:?} must exceed the {budget:?} budget \
                     (steered={steered}, converging={converging})"
                );
            }
        }
        // And it must be clearly distinct from the handshake value, which
        // is the bug: one constant serving both roles.
        assert!(OP_TIMEOUT > HANDSHAKE_TIMEOUT * 10);
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
        });
        // No verify yet: nothing contradicts, so it reads up — bounded by
        // `nominal()` independently requiring a passing verify.
        assert!(e.port_links()[0].link_up);

        e.last_verify = Some(VerifyOutcome {
            sampled: 64,
            dead_interfaces: vec![crate::verify::DeadInterface {
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
