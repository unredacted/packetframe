//! Custom-FIB trait shapes shared across userspace modules (Option F).
//!
//! Phase 1 defines only the trait surfaces so Phase 2-3 can land
//! concrete implementations (BMP station, netlink neighbor listener,
//! FibProgrammer) without churning the shape. No impls here, the
//! fast-path module owns its own concrete impls under
//! `crates/modules/fast-path/src/fib/`.

use std::net::IpAddr;

// --- RouteSource ------------------------------------------------------

/// A stream of BGP route events. Concrete impls include the BMP
/// station (bird 2.17 Loc-RIB RFC 9069) and, potentially, file / MRT
/// replay for testing and offline validation.
///
/// `run` is blocking in the sync sense or a long-lived async task;
/// concrete impls decide. It must consume `shutdown` cooperatively
/// and drain pending events before returning.
pub trait RouteSource: Send {
    /// Run the source. Emits `RouteEvent`s via the provided sink
    /// until `shutdown` signals quit. Returns on error or clean
    /// shutdown.
    ///
    /// Phase 1 sink / shutdown types are intentionally unspecified
    /// at the trait level, Phase 3 lands a concrete channel pair
    /// under `crates/modules/fast-path/src/fib/` along with the
    /// BMP station impl.
    fn run(&mut self) -> Result<(), RouteSourceError>;
}

/// Events emitted by a [`RouteSource`]. Consumed by the
/// `FibProgrammer` to maintain the BPF maps.
#[derive(Debug, Clone)]
pub enum RouteEvent {
    /// A peer came up. Used by the programmer to track per-peer
    /// route sets; on `PeerDown` the programmer withdraws everything
    /// tagged with this `peer_id`.
    PeerUp {
        peer_id: PeerId,
        peer_ip: IpAddr,
        peer_asn: u32,
    },
    /// A peer went down; the programmer removes all routes tagged
    /// with this `peer_id`.
    PeerDown { peer_id: PeerId },
    /// Route announcement.
    ///
    /// `path_id` is `Some(_)` only when RFC 7911 ADD-PATH has been
    /// negotiated on the source session; `None` otherwise. Sources that
    /// never negotiate ADD-PATH always emit `None`. The FibProgrammer
    /// keys its per-advertisement state by `(peer_id, path_id)` so that
    /// multiple paths per prefix can coexist and be aggregated into an
    /// ECMP group.
    ///
    /// `local_pref` carries the BGP LOCAL_PREF attribute when the source
    /// is a BGP-like protocol; `None` for non-BGP sources (netlink,
    /// connected-fast-path seeding) and for BGP UPDATEs that omit the
    /// attribute. The FibProgrammer filters the per-prefix NH union to
    /// the maximum local-pref tier across the prefix's advertisements,
    /// so operator-encoded preferences (e.g., IX peers at LP 150 vs
    /// transit at LP 100) survive ADD-PATH aggregation: ECMP forms
    /// within a tier, not across tiers. Missing local_pref is treated
    /// as RFC 4271's default of 100.
    Add {
        peer_id: PeerId,
        prefix: IpPrefix,
        nexthops: Vec<IpAddr>,
        path_id: Option<u32>,
        local_pref: Option<u32>,
    },
    /// Route withdrawal. `path_id` matches the `Add` it pairs with;
    /// see [`RouteEvent::Add`] for semantics. `local_pref` is not part
    /// of the withdrawal key because the FibProgrammer looks up the
    /// advertisement by `(peer_id, path_id)` and removes it regardless
    /// of its stored LP.
    Del {
        peer_id: PeerId,
        prefix: IpPrefix,
        path_id: Option<u32>,
    },
    /// The RouteSource finished its initial RIB dump (all known
    /// peers have quiesced). The programmer uses this to garbage-
    /// collect entries left over from a prior session.
    InitiationComplete,
    /// The RouteSource reconnected after a disconnect. Programmer
    /// should stale-and-reconcile: mark all entries "not-yet-seen",
    /// clear the mark as `Add` events arrive, and GC anything still
    /// marked at the next `InitiationComplete`.
    Resync,
}

/// Opaque peer identifier assigned by the RouteSource. For BMP this
/// derives from the per-peer header's `peer_address + peer_distinguisher`;
/// for the iBGP source, a hash of `(listen_addr, peer_asn)`. The
/// FibProgrammer treats it as a transparent handle, scoped per-source
/// so that a `PeerDown` from one feed never tears down routes another
/// feed installed.
///
/// **`local_arp(ifindex)`** (v0.2.1) carves out a deterministic
/// sub-range for the v0.2.1 connected fast-path feature
/// ([`crate::config::ModuleDirective::LocalPrefix`]): the high bit of
/// the 64-bit space is set, the next 31 bits are zeroed, and the low
/// 32 bits hold the kernel ifindex. RouteSource-derived hashes
/// effectively never produce values with both halves of this layout
/// (the high bit set + 31 zero bits + a small u32-shaped low half),
/// so collision with a hash-allocated PeerId is mathematically
/// negligible. `is_local_arp` recovers the per-iface scope so the
/// programmer can withdraw a single iface's worth of /32s on
/// `RTM_DELLINK`.
/// `Ord` / `PartialOrd` are derived (lexicographic on the wrapped
/// `u64`) so `PeerId` can key a `BTreeMap` / `BTreeSet`. The
/// FibProgrammer uses `BTreeMap<(PeerId, Option<u32>), _>` for its
/// per-advertisement state so iteration order is stable across
/// process runs without an explicit sort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerId(pub u64);

impl PeerId {
    /// High-bit marker that distinguishes [`PeerId::local_arp`] values
    /// from RouteSource-derived hashes. See the type-level docs.
    const LOCAL_ARP_MARKER: u64 = 1u64 << 63;

    /// Synthesize a per-iface PeerId for the v0.2.1 connected
    /// fast-path source. `ifindex` is the kernel ifindex; PeerDown
    /// for this PeerId withdraws every /32 the resolver registered
    /// behind that iface.
    pub fn local_arp(ifindex: u32) -> Self {
        Self(Self::LOCAL_ARP_MARKER | (ifindex as u64))
    }

    /// `Some(ifindex)` when this PeerId came from
    /// [`Self::local_arp`]; `None` otherwise.
    pub fn as_local_arp_ifindex(self) -> Option<u32> {
        if self.0 & Self::LOCAL_ARP_MARKER != 0 {
            Some((self.0 & 0xFFFF_FFFF) as u32)
        } else {
            None
        }
    }
}

// --- Table completeness ----------------------------------------------

/// Drift at or below which the mirror counts as converged, for the
/// purpose of **letting traffic be steered into it**.
///
/// A separate constant from the integrity checker's own warn threshold
/// even though both start at 1%, because they answer different
/// questions and will drift apart the moment either is tuned. The
/// checker asks "should an operator look at this?"; this asks "may we
/// divert packets into it?".
///
/// What it is actually separating is **"bird's initial dump is still
/// arriving"** — where the mirror holds a fraction of the table — from
/// an ordinary converged state with BGP churn on top. That is a gap of
/// tens of percent, so a modest threshold does the job while tolerating
/// the churn a tighter one would trip over. A gate that refuses during
/// normal operation is a gate operators turn off.
///
/// The residual is deliberate and bounded: both tiers mirror the same
/// table, so a prefix missing here is missing from the eBPF tier too.
/// Steering makes it worse rather than new — an unsteered miss falls to
/// the kernel path, a steered one is dropped by VPP — which is why the
/// gate exists at all, and why it is sized to catch the large case.
pub const STEER_MAX_DRIFT: f64 = 0.01;

/// How old a completeness report may be and still be acted on.
///
/// The publisher's cadence is ~5 minutes, so this tolerates two missed
/// runs rather than blocking a rollout step on one slow `birdc`. It is
/// generous because of what the report says: "the table had converged".
/// A table does not un-converge while nobody is looking — and the case
/// that would matter, a daemon restart mid-dump, cannot produce a stale
/// report at all, since the handle lives in memory and a fresh process
/// starts with none.
pub const STEER_MAX_REPORT_AGE: std::time::Duration = std::time::Duration::from_secs(900);

/// One comparison of the mirror against its authority.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CompletenessReport {
    /// What the authority (bird) says it has.
    pub authority_routes: u64,
    /// What our mirror holds.
    pub mirror_routes: u64,
    /// When the comparison was made.
    pub at: std::time::Instant,
}

impl CompletenessReport {
    /// How far the mirror is from the authority, as a fraction of the
    /// authority's count. `None` when the authority reports zero, which
    /// is not a 100%-complete mirror — it is no basis for a judgement.
    pub fn drift(&self) -> Option<f64> {
        if self.authority_routes == 0 {
            return None;
        }
        let a = self.authority_routes as f64;
        Some((a - self.mirror_routes as f64).abs() / a)
    }
}

/// The verdict a steering decision acts on.
#[derive(Debug, Clone, PartialEq)]
pub enum Completeness {
    /// Safe to divert traffic into.
    Converged { drift: f64 },
    /// The mirror is measurably short of the authority.
    Incomplete {
        drift: f64,
        authority: u64,
        mirror: u64,
    },
    /// The mirror holds substantially MORE than the authority claims.
    ///
    /// Not a loading state, and not a drift figure worth printing — it
    /// means the thing being asked is not the thing feeding us. Seen on
    /// first contact: the box had a local `birdc` answering for its own
    /// near-empty bird while the table arrived from a different router,
    /// and the "% short" arithmetic reported 6852510%. Steering is still
    /// refused — an authority we cannot trust is no basis for diverting
    /// traffic — but the reason has to say which problem it is.
    AuthorityMismatch { authority: u64, mirror: u64 },
    /// There is a report, but it is too old to act on.
    Stale { age: std::time::Duration },
    /// No report at all, or none that supports a judgement.
    Unknown { why: &'static str },
}

impl Completeness {
    /// Whether traffic may be steered on the strength of this.
    ///
    /// Only `Converged` says yes. `Unknown` deliberately does **not** —
    /// "I could not establish this" is not the same as "there is no
    /// constraint", and reading it as permission is the exact shape that
    /// has produced the worst bugs in this subsystem. Deployments with
    /// no authority to compare against say so in config rather than
    /// arriving here.
    pub fn permits_steering(&self) -> bool {
        matches!(self, Completeness::Converged { .. })
    }

    /// Operator-facing reason, for the refusal message.
    pub fn describe(&self) -> String {
        match self {
            Completeness::Converged { drift } => {
                format!("converged ({:.3}% drift)", drift * 100.0)
            }
            Completeness::Incomplete {
                drift,
                authority,
                mirror,
            } => format!(
                "the route mirror holds {mirror} of the authority's {authority} routes \
                 ({:.2}% short) — it is probably still loading",
                drift * 100.0
            ),
            Completeness::AuthorityMismatch { authority, mirror } => format!(
                "the route mirror holds {mirror} routes but the authority reports only \
                 {authority} — that is not the authority feeding this mirror. Check which \
                 bird `birdc` is talking to; on a box whose routes come from elsewhere, \
                 `require-table-complete off` is the right answer"
            ),
            Completeness::Stale { age } => format!(
                "the last completeness check was {}s ago, too old to act on",
                age.as_secs()
            ),
            Completeness::Unknown { why } => format!("completeness is unknown: {why}"),
        }
    }
}

/// Turn a report into a verdict. Pure, so the rule is testable without
/// a bird, a VPP or a NIC.
pub fn assess(
    report: Option<CompletenessReport>,
    now: std::time::Instant,
    max_drift: f64,
    max_age: std::time::Duration,
) -> Completeness {
    let Some(r) = report else {
        return Completeness::Unknown {
            why: "no check has run yet",
        };
    };
    // Age first. A report whose drift looks fine but which predates
    // anything we care about is not evidence, and reporting its drift
    // would invite acting on it.
    let age = now.saturating_duration_since(r.at);
    if age > max_age {
        return Completeness::Stale { age };
    }
    let Some(drift) = r.drift() else {
        return Completeness::Unknown {
            why: "the authority reports zero routes",
        };
    };
    if drift <= max_drift {
        return Completeness::Converged { drift };
    }
    // Which side is short decides which problem this is, and they lead
    // somewhere different. Short of the authority is a mirror still
    // loading — wait. Larger than the authority cannot be a loading
    // state at all; it means the authority is not the one feeding this
    // mirror, and no amount of waiting fixes it.
    if r.mirror_routes > r.authority_routes {
        return Completeness::AuthorityMismatch {
            authority: r.authority_routes,
            mirror: r.mirror_routes,
        };
    }
    Completeness::Incomplete {
        drift,
        authority: r.authority_routes,
        mirror: r.mirror_routes,
    }
}

/// Where the route mirror publishes how complete it is, for the second
/// forwarding tier to read before diverting traffic.
///
/// A shared handle rather than a copy, and a `std` lock rather than
/// tokio's, because the two ends live in different worlds: the publisher
/// is the fast-path's async integrity checker, the reader is
/// vpp-offload's synchronous supervision loop. Neither should have to
/// adopt the other's runtime to answer one question.
///
/// The loader owns it and hands the same object to both, exactly as it
/// does for the route feed and the allowlist.
#[derive(Debug, Default)]
pub struct TableCompleteness(std::sync::RwLock<Option<CompletenessReport>>);

impl TableCompleteness {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a comparison. The integrity checker is the only writer.
    pub fn publish(&self, report: CompletenessReport) {
        *self.0.write().expect("completeness lock") = Some(report);
    }

    pub fn latest(&self) -> Option<CompletenessReport> {
        *self.0.read().expect("completeness lock")
    }

    /// The verdict now, under the steering policy.
    pub fn verdict(&self) -> Completeness {
        assess(
            self.latest(),
            std::time::Instant::now(),
            STEER_MAX_DRIFT,
            STEER_MAX_REPORT_AGE,
        )
    }
}

/// Whether the route feed's transport session is up right now —
/// written by whichever session owner feeds the mirror (the BGP
/// listener or the BMP station), read by consumers that must
/// distinguish "the source finished loading" from "the source is gone
/// and left its last answer standing".
///
/// Out-of-band of the route-event stream on purpose: the BGP listener
/// deliberately does NOT wipe the mirror on session loss — stale
/// forwarding while bird restarts beats an empty table — so session
/// lifecycle cannot be inferred downstream from route events, and a
/// count of mirror routes says nothing about liveness (review
/// finding: neighbour-synthesized local routes alone can number in
/// the hundreds, so no husk-size bound works either).
#[derive(Debug, Default)]
pub struct FeedSession {
    up: std::sync::atomic::AtomicBool,
    /// Stream activity the mirror cannot see: a reconnect's dump
    /// REANNOUNCES mostly-unchanged routes, which take the
    /// programmer's no-change early return and never reach the mirror
    /// — so a mutation counter reads quiet while the dump is actively
    /// streaming (review finding). The session owner bumps this on
    /// every UPDATE / RouteMonitoring frame, and the release gate
    /// folds it into its activity rate: quiet means the STREAM went
    /// quiet, not merely that nothing changed.
    pulses: std::sync::atomic::AtomicU64,
}

impl FeedSession {
    pub fn new() -> Self {
        Self::default()
    }

    /// The session owner's report. `true` only while a session is
    /// actually established — for BGP, after the OPEN exchange; set
    /// back to `false` the moment the connection handler returns,
    /// including on hold-timer expiry, which is what bounds how long
    /// a hung session can keep this stale.
    pub fn set_up(&self, up: bool) {
        self.up.store(up, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_up(&self) -> bool {
        self.up.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// One unit of stream activity, whether or not it changed anything.
    /// See the field doc for why the mirror's own counter is not
    /// enough. The UNIT is one route element, not one frame — the gate
    /// compares this against route-scaled quiet rates, and a frame can
    /// fan out to thousands of elements, so frame-counting let a
    /// batched million-route dump read as quiet (review finding). Use
    /// [`Self::pulse_n`] with the element count wherever it is known.
    pub fn pulse(&self) {
        self.pulse_n(1);
    }

    /// `n` route elements of stream activity in one frame.
    pub fn pulse_n(&self, n: u64) {
        self.pulses
            .fetch_add(n, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn pulse_count(&self) -> u64 {
        self.pulses.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[cfg(test)]
mod peer_id_tests {
    use super::*;

    #[test]
    fn local_arp_round_trips_ifindex() {
        for ifindex in [1u32, 33, 1234, u32::MAX] {
            let pid = PeerId::local_arp(ifindex);
            assert_eq!(pid.as_local_arp_ifindex(), Some(ifindex));
        }
    }

    #[test]
    fn non_local_arp_peer_id_is_not_misidentified() {
        // A small / hash-shaped value (high bit clear) must NOT
        // present as local-arp.
        assert_eq!(PeerId(0xdead_beef).as_local_arp_ifindex(), None);
        assert_eq!(PeerId(0).as_local_arp_ifindex(), None);
    }

    #[test]
    fn distinct_ifindexes_yield_distinct_peer_ids() {
        let a = PeerId::local_arp(1);
        let b = PeerId::local_arp(2);
        assert_ne!(a, b);
    }
}

/// Either v4 or v6 prefix with length. The address octets are
/// stored in network order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpPrefix {
    V4 { addr: [u8; 4], prefix_len: u8 },
    V6 { addr: [u8; 16], prefix_len: u8 },
}

/// Errors a `RouteSource` can surface. `recoverable` signals whether
/// the caller should reconnect / re-run or treat the source as gone.
#[derive(Debug)]
pub struct RouteSourceError {
    pub recoverable: bool,
    pub cause: String,
}

impl RouteSourceError {
    pub fn recoverable(cause: impl Into<String>) -> Self {
        Self {
            recoverable: true,
            cause: cause.into(),
        }
    }
    pub fn fatal(cause: impl Into<String>) -> Self {
        Self {
            recoverable: false,
            cause: cause.into(),
        }
    }
}

impl std::fmt::Display for RouteSourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            self.cause,
            if self.recoverable {
                "recoverable"
            } else {
                "fatal"
            }
        )
    }
}

impl std::error::Error for RouteSourceError {}

// --- NeighborResolver -------------------------------------------------

/// Kernel neighbor cache subscription. Subscribes to netlink
/// RTM_NEWNEIGH / RTM_DELNEIGH / RTM_NEWLINK / RTM_DELLINK multicast
/// and emits [`NeighEvent`]s. Proactive resolution is initiated via
/// [`request_resolve`](Self::request_resolve).
pub trait NeighborResolver: Send {
    /// Run the resolver. Blocks (or runs as a long-lived async task)
    /// until shutdown.
    fn run(&mut self) -> Result<(), NeighError>;

    /// Request proactive resolution of `nh`. The resolver issues an
    /// `RTM_NEWNEIGH` with `NUD_NONE` so the kernel initiates
    /// ARP/ND. Returns immediately; resolution completes
    /// asynchronously and a `NeighEvent::Learned` is emitted.
    fn request_resolve(&self, nh: IpAddr);
}

/// Events emitted by a [`NeighborResolver`]. Consumed by the
/// FibProgrammer to update `NEXTHOPS[idx]` via the seqlock.
#[derive(Debug, Clone)]
pub enum NeighEvent {
    /// A neighbor resolved successfully. Programmer writes
    /// `{mac, ifindex, src_mac}` into the corresponding `NexthopEntry`.
    /// `src_mac` is the MAC of the egress interface (i.e., the MAC
    /// the XDP program writes as the Ethernet source address on
    /// redirected frames). Added in Phase 3.6; pre-3.6 the programmer
    /// wrote `0x00…00` here, which works on most switches but breaks
    /// policy tools that inspect src_mac. `[0; 6]` is still a valid
    /// value when the resolver couldn't look up the egress MAC, the
    /// programmer writes whatever's provided.
    Learned {
        ip: IpAddr,
        mac: [u8; 6],
        ifindex: u32,
        src_mac: [u8; 6],
    },
    /// Resolution failed after retries. Programmer marks the
    /// nexthop `Failed`; XDP packets for routes pointing at this
    /// NH return `NoNeigh` to the kernel.
    Failed { ip: IpAddr, reason: String },
    /// The kernel removed the neighbor (link down, RTM_DELNEIGH).
    /// Programmer marks `Incomplete` and queues a fresh resolve.
    Gone { ip: IpAddr },
}

// --- ResolvedRouteSink ------------------------------------------------

/// A second consumer of the FIB, fed with what the programmer
/// **resolved** rather than with what a peer advertised.
///
/// This exists so `vpp-offload` can mirror the forwarding table without
/// re-deriving it. The obvious alternative — tee [`RouteEvent`]s where
/// they enter the controller — looks cheaper and is a trap: a
/// `RouteEvent::Add` carries one *advertisement* (`peer_id`, `path_id`,
/// `local_pref`), and turning a prefix's advertisements into the nexthop
/// set that actually forwards is the programmer's local-pref tiering and
/// ADD-PATH aggregation. A second consumer of the raw events would have
/// to reimplement that, which is two copies of the rule that decides
/// where packets go — and the failure mode is the two tiers forwarding
/// differently, discovered during a failover.
///
/// So the notification sites are the programmer's mirror commits, and
/// what crosses this trait is the resolved best-path union. The
/// consequence is deliberate and worth stating: the second tier inherits
/// the first tier's resolution, **including its refusals**. A prefix the
/// programmer declined on capacity is not announced here either. The two
/// tiers agreeing is worth more than the second one being independently
/// complete, because it means a failover cannot change forwarding.
///
/// ## Why nothing here can fail
///
/// No `Result`, no `async`, `&self`. The fallback tier must never be
/// stalled by a sick consumer — that is the standing requirement for the
/// eBPF path, which carries production traffic whenever the offload is
/// down. A signature that cannot report failure cannot tempt a caller
/// into waiting for one, so an implementation must absorb its own
/// backpressure (a prefix-keyed map with last-write-wins collapses churn
/// and is bounded by table size, not event rate) and must not block:
/// anything held across these calls is held against the programmer's
/// task, which is the fallback tier's control plane.
pub trait ResolvedRouteSink: Send + Sync {
    /// `prefix` now forwards over `nexthops` — the resolved, sorted,
    /// deduplicated best-path union, exactly what the data plane reads.
    /// Replaces any previous set for this prefix.
    fn route_resolved(&self, prefix: IpPrefix, nexthops: &[IpAddr]);

    /// `prefix` no longer forwards and must be withdrawn downstream.
    ///
    /// Distinct from `route_resolved(prefix, &[])`, which would read as
    /// "still present, currently unresolvable" — a state that black-holes
    /// rather than falls back, so conflating them would leave a withdrawn
    /// route installed in the second tier.
    fn route_withdrawn(&self, prefix: IpPrefix);

    /// `nh` resolved to `mac` out of `ifindex`.
    ///
    /// Forwarded because a consumer running VPP has no way to learn it:
    /// VPP runs without `linux-cp` and MCAM rules match IP fields, so an
    /// ARP frame can never reach it. Every adjacency it has must be
    /// programmed from what the kernel already resolved here.
    fn neighbour_resolved(&self, nh: IpAddr, mac: [u8; 6], ifindex: u32);

    /// `nh` is no longer resolved — the kernel dropped it, or resolution
    /// failed after retries.
    ///
    /// Both cases collapse into one call on purpose: the consumer's
    /// question is only "may I still forward through this adjacency",
    /// and the answer is no either way. Why it failed is the fast-path
    /// tier's diagnostic, and it already reports it.
    fn neighbour_lost(&self, nh: IpAddr);
}

/// Errors a NeighborResolver can surface.
#[derive(Debug)]
pub struct NeighError {
    pub cause: String,
}

impl NeighError {
    pub fn new(cause: impl Into<String>) -> Self {
        Self {
            cause: cause.into(),
        }
    }
}

impl std::fmt::Display for NeighError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.cause)
    }
}

impl std::error::Error for NeighError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_prefix_variants_are_distinct() {
        let v4 = IpPrefix::V4 {
            addr: [10, 0, 0, 0],
            prefix_len: 8,
        };
        let v6 = IpPrefix::V6 {
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 32,
        };
        assert_ne!(v4, v6);
    }

    #[test]
    fn peer_id_is_copy_eq_hash() {
        let a = PeerId(0xdead_beef);
        let b = a;
        assert_eq!(a, b);
        let mut s = std::collections::HashSet::new();
        s.insert(a);
        assert!(s.contains(&b));
    }

    #[test]
    fn route_source_error_variants() {
        let r = RouteSourceError::recoverable("peer reset");
        assert!(r.recoverable);
        assert!(format!("{r}").contains("recoverable"));
        let f = RouteSourceError::fatal("listener bind");
        assert!(!f.recoverable);
        assert!(format!("{f}").contains("fatal"));
    }

    mod completeness {
        use super::super::*;
        use std::time::{Duration, Instant};

        fn report(authority: u64, mirror: u64, age: Duration) -> CompletenessReport {
            CompletenessReport {
                authority_routes: authority,
                mirror_routes: mirror,
                at: Instant::now() - age,
            }
        }

        fn verdict(r: Option<CompletenessReport>) -> Completeness {
            assess(r, Instant::now(), STEER_MAX_DRIFT, STEER_MAX_REPORT_AGE)
        }

        /// The case the gate exists for: bird's initial dump is still
        /// arriving, so the mirror holds a fraction of the table.
        /// Steering into it blackholes everything not yet loaded, and —
        /// unlike an unsteered miss, which falls to the kernel path —
        /// a steered one is dropped.
        #[test]
        fn a_mirror_still_loading_does_not_permit_steering() {
            let v = verdict(Some(report(1_053_360, 400_000, Duration::ZERO)));
            assert!(!v.permits_steering());
            assert!(matches!(v, Completeness::Incomplete { .. }), "{v:?}");
            let msg = v.describe();
            assert!(
                msg.contains("1053360") && msg.contains("400000"),
                "the operator needs both numbers to judge it: {msg}"
            );
        }

        /// Ordinary churn must not refuse a rollout step. A gate that
        /// fires during normal operation is a gate operators disable.
        #[test]
        fn ordinary_churn_still_permits_steering() {
            // 0.5% short — well inside the noise BGP produces.
            let v = verdict(Some(report(1_000_000, 995_000, Duration::ZERO)));
            assert!(v.permits_steering(), "{v:?}");
        }

        /// No report is NOT permission.
        ///
        /// "I could not establish this" read as "there is no
        /// constraint" is the shape that has produced the worst bugs in
        /// this subsystem. A deployment with no authority to compare
        /// against says so in config rather than arriving here.
        #[test]
        fn an_absent_report_is_not_permission() {
            let v = verdict(None);
            assert!(!v.permits_steering());
            assert!(matches!(v, Completeness::Unknown { .. }), "{v:?}");
        }

        /// An authority reporting zero routes is not a complete mirror.
        ///
        /// The arithmetic would divide by zero; the honest reading is
        /// that bird has nothing to compare against, which is no basis
        /// for diverting traffic.
        #[test]
        fn a_zero_route_authority_is_unknown_not_converged() {
            let v = verdict(Some(report(0, 0, Duration::ZERO)));
            assert!(!v.permits_steering(), "{v:?}");
            assert!(matches!(v, Completeness::Unknown { .. }), "{v:?}");
        }

        /// Age is judged BEFORE drift.
        ///
        /// A report that looks converged but predates anything we care
        /// about is not evidence, and reporting its drift would invite
        /// acting on it.
        #[test]
        fn a_stale_report_is_refused_even_when_it_looks_converged() {
            let old = report(
                1_000_000,
                1_000_000,
                STEER_MAX_REPORT_AGE + Duration::from_secs(1),
            );
            let v = verdict(Some(old));
            assert!(!v.permits_steering());
            assert!(matches!(v, Completeness::Stale { .. }), "{v:?}");
        }

        /// The handle is a window, not a copy: a publish is visible to
        /// the reader without anything being handed over.
        #[test]
        fn a_published_report_is_visible_through_the_handle() {
            let h = TableCompleteness::new();
            assert!(
                !h.verdict().permits_steering(),
                "empty handle permits nothing"
            );

            h.publish(report(1_000_000, 999_000, Duration::ZERO));
            assert!(h.verdict().permits_steering());

            // And a later, worse report replaces it rather than being
            // merged with the good one.
            h.publish(report(1_000_000, 100_000, Duration::ZERO));
            assert!(
                !h.verdict().permits_steering(),
                "the newest report is the verdict"
            );
        }

        /// A mirror LARGER than the authority is not a loading state.
        ///
        /// This is what the shadow produced on first contact: a local
        /// `birdc` answering for a near-empty bird while the table
        /// arrived from a different router. The old arithmetic called it
        /// "6852510% short — probably still loading", which is the exact
        /// opposite of what was wrong and sends an operator to wait for
        /// something that will never happen.
        #[test]
        fn a_mirror_larger_than_the_authority_names_the_right_problem() {
            let v = verdict(Some(report(19, 1_301_996, Duration::ZERO)));
            assert!(!v.permits_steering());
            assert!(matches!(v, Completeness::AuthorityMismatch { .. }), "{v:?}");
            let msg = v.describe();
            assert!(
                msg.contains("not the authority feeding this mirror"),
                "the operator must be told it is the wrong authority, not a slow one: {msg}"
            );
            assert!(
                !msg.contains("short") && !msg.contains("loading"),
                "and must NOT be told to wait: {msg}"
            );
        }

        /// A mirror trivially ahead of the authority is still converged.
        ///
        /// Routes arrive between the two counts, so the mirror leading by
        /// a hair is ordinary churn. Only a gap past the drift threshold
        /// means the authority is wrong.
        #[test]
        fn a_mirror_a_hair_ahead_is_still_converged() {
            let v = verdict(Some(report(1_000_000, 1_000_500, Duration::ZERO)));
            assert!(v.permits_steering(), "{v:?}");
        }
    }
}
