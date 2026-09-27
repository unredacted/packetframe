//! VppSink route-state core: the pieces that decide *what* should be in
//! VPP's FIB, independent of *how* it gets there.
//!
//! Deliberately wire-format-free — no binary-API types appear here. The
//! transport lands in slice 3 and is blocked on the gate-0b version pin
//! (generated structs must come from the VPP that will actually run);
//! this module is the half that pin does not gate, so it is built and
//! tested on host CI ahead of it.
//!
//! Two decisions from the plan drive the whole design:
//!
//! **Not a delta FIFO.** Under a peering flap a FIFO overflows, and the
//! overflow response — full resync — races the very churn that caused
//! it, so it never converges. Instead a **prefix-keyed pending map with
//! last-write-wins**: repeated churn on one prefix collapses to a single
//! entry, so the backlog is bounded by *table size*, not by event rate.
//! "Resync in progress + live deltas arriving" stops being a special
//! case, because events simply update the same map the drainer walks.
//!
//! **Route state is three-valued**, not installed/absent: a route can be
//! `Installed`, `Withheld` (deliberately, above the capacity high-water
//! mark), or `Unresolvable` (its nexthop device maps to nothing VPP
//! owns). The two degraded counts page differently — `Unresolvable` is a
//! misconfigured mapping, `Withheld` is the table outgrowing the box —
//! and conflating them would hide whichever is rarer. Both, however,
//! mean the FIB is incomplete, so both block *first-attach* steering:
//! MCAM diverts by allowlist, not by what the ledger managed to install,
//! and a diverted packet can no longer fall back to the eBPF tier.
//!
//! **Nothing is recorded as installed until VPP says so.** A fourth,
//! transient `Installing` state covers the window between handing an op
//! to the transport and hearing back. It holds a capacity slot — so one
//! drained batch cannot oversubscribe the table — but is excluded from
//! readback verification, and a rejection unwinds it to whatever is
//! genuinely still in VPP.

use std::collections::BTreeMap;
use std::net::IpAddr;

use packetframe_common::fib::IpPrefix;

/// Ordered, round-trippable form of [`IpPrefix`].
///
/// `IpPrefix` derives `Hash`/`Eq` but not `Ord`, and the pending map
/// wants a `BTreeMap` for the same reason the FibProgrammer's
/// per-advertisement state does: stable iteration order across process
/// runs, so a drained batch is reproducible and tests don't depend on
/// hash seed. Keyed on `(family, addr, len)`; v4 addresses occupy the
/// low 4 bytes with the rest zeroed, so v4 and v6 never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrefixKey {
    family: u8,
    addr: [u8; 16],
    len: u8,
}

impl From<IpPrefix> for PrefixKey {
    fn from(p: IpPrefix) -> Self {
        match p {
            IpPrefix::V4 { addr, prefix_len } => {
                let mut wide = [0u8; 16];
                wide[..4].copy_from_slice(&addr);
                Self {
                    family: 4,
                    addr: wide,
                    len: prefix_len,
                }
            }
            IpPrefix::V6 { addr, prefix_len } => Self {
                family: 6,
                addr,
                len: prefix_len,
            },
        }
    }
}

impl From<PrefixKey> for IpPrefix {
    fn from(k: PrefixKey) -> Self {
        if k.family == 4 {
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&k.addr[..4]);
            IpPrefix::V4 {
                addr,
                prefix_len: k.len,
            }
        } else {
            IpPrefix::V6 {
                addr: k.addr,
                prefix_len: k.len,
            }
        }
    }
}

/// What the sink still owes VPP for one prefix. Last-write-wins: a
/// `Withdraw` landing on a pending `Upsert` replaces it outright rather
/// than queueing behind it, which is what makes churn collapse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingOp {
    /// Install or replace. Carries the full nexthop set — multipath from
    /// day one (`RouteEvent` is already `Vec<IpAddr>`), because
    /// retrofitting multi-path encoding after the fact is the expensive
    /// path even on a box that currently runs zero ECMP groups.
    Upsert { nexthops: Vec<IpAddr> },
    /// Withdraw. Always honored regardless of capacity — a withdrawal
    /// frees table space, so refusing one under pressure would be
    /// exactly backwards, and a withdrawn route left installed
    /// black-holes.
    Withdraw,
}

/// Why a route is not in VPP's FIB. Kept separate from "installed" so
/// health can distinguish a mapping bug from a capacity ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotInstalled {
    /// Above the capacity high-water mark. Retried when headroom
    /// returns; excluded from resync retry until then, so a full table
    /// doesn't spin the drainer against a wall.
    Withheld,
    /// No nexthop resolved to a VPP-owned interface. Not retried on
    /// capacity changes — nothing about headroom fixes a mapping.
    Unresolvable,
}

/// Route state. See the module docs for the three terminal values;
/// `Installing` is the transient added so the ledger never claims a
/// route is in VPP before the transport says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteState {
    /// VPP has acknowledged this route.
    Installed,
    /// Handed to the transport, not yet acknowledged. Holds a capacity
    /// slot (so a batch in flight cannot oversubscribe the table) but is
    /// **not** eligible for readback verification.
    ///
    /// `replacing` records whether a previous version of this route is
    /// still live in VPP, which is what a failed install has to fall
    /// back to: a rejected *replacement* leaves the old route
    /// forwarding, while a rejected *first* install leaves nothing.
    Installing {
        replacing: bool,
    },
    NotInstalled(NotInstalled),
}

/// Per-state totals, exported as `packetframe_vpp_*` gauges and folded
/// into the readback-verify pass criteria.
///
/// Maintained incrementally by [`RouteLedger`] rather than recomputed:
/// a full-table load runs ~1.3M classifications, so an O(n) recount per
/// route would be quadratic — on the order of 10^12 state visits before
/// steering could be enabled.
///
/// **The top-level counts are IPv4's**, and every gate and gauge that
/// reads them — the first-steer refusal, verify's pass criteria, the
/// empty-table alarms, `packetframe_vpp_routes` — means IPv4 by them.
/// That is not an accident of history: steering diverts IPv4 and nothing
/// else, so what decides whether traffic may be diverted is whether the
/// v4 table is whole. A v6 route withheld or unresolvable says nothing
/// about a steered v4 packet, and letting it block a v4 steer would make
/// `v6 on` — rung 0, which steers no v6 at all — a way to take v4 off
/// VPP. IPv6 is counted beside it in [`Self::v6`], reported on its own
/// rows and gauges, and gates only what diverts v6 (nothing, yet).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SinkCounts {
    pub installed: u64,
    pub installing: u64,
    pub withheld: u64,
    pub unresolvable: u64,
    /// The router's own connected subnets, left out of VPP, that no
    /// `steer-exempt` covers. Never tallied by the ledger — those routes
    /// never enter it — the engine fills it in
    /// ([`crate::engine::ConvergenceEngine::unexempted_local`]).
    pub unexempted_local: u64,
    /// IPv6's counts, when VPP carries the family (`v6 on`); `None`
    /// under [`crate::fib_sync::FamilyPolicy::V4Only`], which is how
    /// every surface tells "v6 is not loaded" from "v6 is loaded and
    /// empty". The ledger does not know the policy, so it reports `None`
    /// and the engine fills this in
    /// ([`crate::engine::ConvergenceEngine::counts`]).
    pub v6: Option<FamilyCounts>,
}

/// One address family's route-ledger totals. See [`SinkCounts`].
///
/// The first four are the ledger's. The rest are conditions only a
/// NON-GATING family has — IPv6 under `v6 on`, which every surface
/// reports and nothing lets block, stall or tear down IPv4 — so the
/// ledger leaves them zero and the engine fills them in
/// ([`crate::engine::ConvergenceEngine::counts`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FamilyCounts {
    pub installed: u64,
    pub installing: u64,
    pub withheld: u64,
    pub unresolvable: u64,
    /// Ops VPP refused (a non-zero `ip_route_add_del` retval), parked out
    /// of the active queue ([`PendingMap::reject`]) rather than retried
    /// on every drain — a retry loop that kept the drain from ever going
    /// idle would hold IPv4's convergence hostage.
    pub rejected: u64,
    /// Routes left out of VPP because every next hop is link-local, whose
    /// interface scope the route feed does not carry
    /// ([`crate::engine::ConvergenceEngine`]'s link-local refusal).
    pub link_local_refused: u64,
    /// Probes of this family the last verify found VPP disagreeing on —
    /// retained here because the family cannot fail the pass, so
    /// nothing else would keep it.
    pub verify_mismatches: u64,
    /// Member interfaces that cannot forward and that this family's
    /// adjacencies use. Reported here and nowhere that gates: IPv4's link
    /// gate counts only interfaces IPv4 routes use.
    pub dark_egress: u64,
}

impl FamilyCounts {
    /// Whether this family's table is incomplete or disagrees with VPP —
    /// the per-family twin of [`SinkCounts::degraded`], wider because a
    /// non-gating family has more ways to be impaired without blocking
    /// anything.
    pub fn degraded(&self) -> bool {
        self.unresolvable > 0
            || self.withheld > 0
            || self.rejected > 0
            || self.link_local_refused > 0
            || self.verify_mismatches > 0
            || self.dark_egress > 0
    }
}

impl SinkCounts {
    /// Whether first-attach steering must be blocked.
    ///
    /// **Any** route we know about but have not installed blocks it.
    /// MCAM steering inherits the fast-path *allowlist*, not this
    /// ledger's installed subset — so a steered packet whose route is
    /// missing from VPP's FIB is dropped or follows a less-specific
    /// covering route, and it can no longer fall back to the eBPF tier
    /// because the hardware already diverted it. That is true whether
    /// the route is missing because its nexthop device is unmapped
    /// (`unresolvable`) or because the table outgrew its heap
    /// (`withheld`); an earlier revision treated withheld as merely
    /// alarming, which would have blackholed exactly the prefixes that
    /// did not fit.
    ///
    /// `installing` counts too: a table still in flight is an
    /// incomplete table. In the normal pipeline (resync → verify →
    /// steer) it has drained to zero by the time steering is
    /// considered.
    ///
    /// And an EMPTY table: diverting traffic into a FIB with no routes
    /// drops every packet of it, while the eBPF tier would have passed
    /// the same traffic to the kernel. Verify already refused one
    /// (`sampled == 0`), but the lever and the retry read these counts,
    /// not a verdict — so without this a retry could steer straight back
    /// into the table whose emptiness just took steering down (see
    /// [`crate::supervisor::Event::TableEmptied`]).
    ///
    /// And a kernel-delivered connected subnet with no `steer-exempt`
    /// (`unexempted_local`): absent from VPP by design, so a steered
    /// packet for it would follow a less-specific route out of the box.
    ///
    /// This deliberately governs only **first-attach**. Once traffic is
    /// steered, a single later withheld route must not tear steering
    /// down — unsteering a mostly-correct VPP is worse than the gap. An
    /// empty one is not mostly-correct, and has its own event.
    pub fn blocks_first_steer(&self) -> bool {
        self.unresolvable > 0
            || self.withheld > 0
            || self.unexempted_local > 0
            || self.installing > 0
            || self.installed == 0
    }

    /// Health signal. Coincides with [`Self::blocks_first_steer`] on the
    /// terminal states by design — both mean "the FIB is incomplete" —
    /// but the two are reported separately because they answer different
    /// questions, and because `withheld` and `unresolvable` page
    /// differently: table-outgrew-the-box versus misconfigured mapping.
    pub fn degraded(&self) -> bool {
        self.unresolvable > 0 || self.withheld > 0
    }

    /// Routes VPP holds in every family it carries: the size of the table
    /// a convergence moves, for budgets — never a gate (see the type docs).
    pub fn installed_all(&self) -> u64 {
        self.installed + self.v6.map_or(0, |v| v.installed)
    }
}

/// Capacity policy. The high-water mark is derived from the **measured**
/// VPP heap gauge, never from the configured `expected-routes` — that
/// number is a sizing input, and reusing it as a runtime ceiling would
/// be the same static guess wearing a second hat. Above the mark the
/// sink withholds rather than installing, so DFZ growth (~100k
/// routes/yr) degrades to "table-incomplete + alarming" instead of a
/// heap-exhaustion crash loop.
///
/// **One pool per address family.** VPP's segments are sized additively
/// — the v4 table from `expected-routes`, the v6 table from its own
/// budget on top (`startup_conf::derive_sizing`) — and the ledger
/// enforces the same split: a v6 route can only ever take a v6 slot. A
/// shared pool would let the ~250k-route v6 table, loaded first by
/// nothing more than key order, withhold v4 routes that steered traffic
/// depends on, which is the one degradation `v6 on` must never cause.
/// Under `V4Only` the v6 pool is never touched.
#[derive(Debug, Clone, Copy)]
pub struct Capacity {
    high_water_routes: u64,
    high_water_v6: u64,
}

impl Capacity {
    /// The same mark for each family's own pool. For callers that size
    /// one family (every `V4Only` path) or do not care how the split
    /// falls (fixtures); bring-up states both with [`Self::per_family`].
    pub fn new(high_water_routes: u64) -> Self {
        Self::per_family(high_water_routes, high_water_routes)
    }

    /// Separate marks for the v4 and v6 pools.
    pub fn per_family(v4: u64, v6: u64) -> Self {
        Self {
            high_water_routes: v4,
            high_water_v6: v6,
        }
    }

    /// The IPv4 high-water route count this policy enforces. Exposed for
    /// the pre-dump deferral floor, which needs a table-scale number at a
    /// moment when the adopted table itself cannot yet be read — and
    /// which is compared against the v4-sized `expected-routes` contract,
    /// so it stays v4's.
    pub fn high_water(&self) -> u64 {
        self.high_water_routes
    }

    /// The IPv6 pool's mark.
    pub fn high_water_v6(&self) -> u64 {
        self.high_water_v6
    }

    fn has_headroom(&self, v6: bool, occupied: u64) -> bool {
        occupied
            < if v6 {
                self.high_water_v6
            } else {
                self.high_water_routes
            }
    }
}

/// Where a nexthop's egress device lands in VPP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NexthopTarget {
    /// A member port's VF — the ordinary case.
    Vf { port: String },
    /// A VLAN nexthop → VPP sub-interface on the member VF: fixed by the
    /// device for [`DevKind::PortVlan`], chosen per neighbour from the
    /// bridge FDB for [`DevKind::BridgeVlan`] (see [`crate::topology`]).
    Subif { port: String, vlan: u16 },
    /// A bridged VLAN's BVI ([`crate::attach::BridgeSpec`]): routes and
    /// neighbours land on it whichever trunk the neighbour is behind, and
    /// frames leave from the kernel bridge's MAC. Placement decides the
    /// L2FIB entry, not the target.
    Bvi { vlan: u16 },
}

use crate::topology::DevKind;

/// Kernel-device → VPP-interface policy. Devices that are neither a
/// member port nor reachable through one (management, tunnels, a bridge
/// of unknown shape) are **explicitly excluded** rather than guessed at,
/// and every route resolving only through them counts as `Unresolvable`.
#[derive(Debug, Clone, Default)]
pub struct NexthopMap {
    /// Nexthop address → egress device, learned from the NeighborResolver.
    device_of: BTreeMap<IpAddr, String>,
    /// Member ports (the `port` config lines).
    members: Vec<String>,
    /// Each member's declared `vlans`: the only subifs attach creates, so
    /// the only VLAN targets that can resolve.
    port_vlans: BTreeMap<String, Vec<u16>>,
    /// VLANs each member sends UNTAGGED (its bridge PVID, typically 1):
    /// a neighbour placed behind the port on one of these is reached
    /// through the port's own VF, since a tagged subif would put a tag
    /// on a frame the wire expects bare.
    port_untagged: BTreeMap<String, Vec<u16>>,
    /// Bridged VLANs that have a BVI. A tagged bridged VLAN resolves ONLY
    /// through one: the per-port subif path would send from the port's
    /// own MAC, which an IX drops or answers by shutting the port.
    /// BVI'd VLAN → the bridge whose BVI it is.
    bvis: BTreeMap<u16, String>,
    /// Devices classified by [`crate::topology::classify`]. `Some(None)`
    /// is a shape VPP cannot reach through; a device with no entry at all
    /// is treated as [`DevKind::Plain`], which is what every device was
    /// before placement existed.
    kinds: BTreeMap<String, Option<DevKind>>,
    /// `BridgeVlan` neighbour → the member port its MAC was last learned
    /// behind, and on which bridge and VLAN. Kept across an FDB entry
    /// ageing out or a spanning-tree flush — the last known port beats
    /// no port, and the host's own traffic re-teaches the bridge within a
    /// moment — and replaced only by a fresh sighting elsewhere. Scoped
    /// to the bridge and VLAN it was seen on: a nexthop that reappears on
    /// a different one has no last known port there.
    placed: BTreeMap<IpAddr, Placement>,
}

/// Where a bridge neighbour was last seen: `port`, in `bridge`'s FDB for
/// `vid`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    pub bridge: String,
    pub vid: u16,
    pub port: String,
}

impl NexthopMap {
    pub fn new(members: Vec<String>) -> Self {
        Self {
            members,
            ..Default::default()
        }
    }

    /// Declare which VLAN subifs each member carries (its `vlans`).
    pub fn with_port_vlans(mut self, vlans: impl IntoIterator<Item = (String, Vec<u16>)>) -> Self {
        self.port_vlans = vlans.into_iter().collect();
        self
    }

    /// Add subifs a `vlans all` trunk gained while running.
    pub fn add_port_vlans(&mut self, port: &str, vlans: &[u16]) {
        let have = self.port_vlans.entry(port.to_string()).or_default();
        for v in vlans {
            if !have.contains(v) {
                have.push(*v);
            }
        }
    }

    /// Record that bridged VLAN `vid` has a BVI.
    /// Record that `vid` on `bridge` has a BVI. Only devices on that
    /// bridge resolve to it: a second VLAN-aware bridge reusing the vid
    /// is a different L2 domain, and resolving it to this BVI would
    /// flood its traffic into the first (review finding).
    pub fn set_bvi(&mut self, vid: u16, bridge: &str) {
        self.bvis.insert(vid, bridge.to_string());
    }

    /// The bridge `vid`'s BVI belongs to, if it has one.
    pub fn bvi_bridge(&self, vid: u16) -> Option<&str> {
        self.bvis.get(&vid).map(String::as_str)
    }

    /// Forget every BVI — they died with the VPP process.
    pub fn forget_bvis(&mut self) {
        self.bvis.clear();
    }

    /// Replace the VLANs `port` sends untagged, from the kernel bridge.
    pub fn set_port_untagged(&mut self, port: &str, vlans: Vec<u16>) {
        self.port_untagged.insert(port.to_string(), vlans);
    }

    /// The VLANs the kernel bridge sends out of `port` untagged.
    pub fn untagged_of(&self, port: &str) -> Vec<u16> {
        self.port_untagged.get(port).cloned().unwrap_or_default()
    }

    /// Whether the kernel bridge sends `vid` out of `port` untagged —
    /// reached through the VF itself, with no subif.
    pub fn is_untagged(&self, port: &str, vid: u16) -> bool {
        self.port_untagged
            .get(port)
            .is_some_and(|v| v.contains(&vid))
    }

    /// Record what a device is. See [`Self::kinds`].
    pub fn set_kind(&mut self, dev: impl Into<String>, kind: Option<DevKind>) {
        self.kinds.insert(dev.into(), kind);
    }

    /// Whether `dev` has been classified.
    pub fn classified(&self, dev: &str) -> bool {
        self.kinds.contains_key(dev)
    }

    /// Forget every classification, so the next sighting re-reads the
    /// kernel: UniFi provisioning can recreate interfaces, and a resync
    /// is where the engine starts from what is true now.
    pub fn forget_kinds(&mut self) {
        self.kinds.clear();
    }

    /// Record which device a nexthop address egresses through. Fed by
    /// the NeighborResolver, the same source that supplies VPP's static
    /// neighbors.
    pub fn set_device(&mut self, nexthop: IpAddr, dev: impl Into<String>) {
        self.device_of.insert(nexthop, dev.into());
    }

    /// Record where a `BridgeVlan` neighbour was seen.
    pub fn place(&mut self, nexthop: IpAddr, placement: Placement) {
        self.placed.insert(nexthop, placement);
    }

    /// The port a neighbour was last seen behind on `bridge`/`vid` — the
    /// scope check that keeps a nexthop moved to another bridge from
    /// inheriting its old trunk.
    pub fn placement_on(&self, nexthop: &IpAddr, bridge: &str, vid: u16) -> Option<&str> {
        self.placed
            .get(nexthop)
            .filter(|p| p.bridge == bridge && p.vid == vid)
            .map(|p| p.port.as_str())
    }

    /// The port a neighbour is placed behind on its CURRENT device's
    /// bridge and VLAN, if any.
    pub fn placement(&self, nexthop: &IpAddr) -> Option<&str> {
        let (bridge, vid) = self.bridge_vlan(nexthop)?;
        self.placement_on(nexthop, bridge, vid)
    }

    /// `(bridge, vid)` when `nexthop`'s device is a [`DevKind::BridgeVlan`].
    pub fn bridge_vlan(&self, nexthop: &IpAddr) -> Option<(&str, u16)> {
        match self.kind_of(self.device_of.get(nexthop)?)? {
            DevKind::BridgeVlan { bridge, vid } => Some((bridge.as_str(), *vid)),
            _ => None,
        }
    }

    /// Every known nexthop on a `BridgeVlan` device, with that device.
    pub fn bridge_nexthops(&self) -> Vec<(IpAddr, String)> {
        self.device_of
            .iter()
            .filter(|(nh, _)| self.bridge_vlan(nh).is_some())
            .map(|(nh, dev)| (*nh, dev.clone()))
            .collect()
    }

    /// Forget every learned nexthop→device pair, keeping the members and
    /// VLAN policy.
    ///
    /// Called before repopulating from an authoritative snapshot. Without
    /// it the map is insert-only, so a nexthop the source has stopped
    /// reporting keeps its last known device forever — and a route still
    /// naming that nexthop resolves as *reachable* through a stale
    /// interface instead of being classified unresolvable. Traffic then
    /// keeps pointing at a neighbour that is gone, and readback
    /// verification cannot catch it: verification checks that a route
    /// exists on an interface we own, deliberately not that its nexthop
    /// is still the one we intended.
    ///
    /// Placements survive: they describe where a MAC was last seen, not
    /// whether the source still reports the neighbour, and a resync that
    /// re-learns it re-reads the FDB anyway.
    pub fn forget_devices(&mut self) {
        self.device_of.clear();
    }

    /// Forget one nexthop's device, for a live loss between resyncs.
    ///
    /// The incremental half of [`Self::forget_devices`], and it exists
    /// for exactly the failure that one describes: without it the delta
    /// path is insert-only, so a nexthop the source reports as lost keeps
    /// its last known device until the next full resync, and routes
    /// naming it resolve as reachable through a stale interface rather
    /// than being classified unresolvable. A lost neighbour's placement
    /// goes with it.
    pub fn forget_device(&mut self, nexthop: &IpAddr) {
        self.device_of.remove(nexthop);
        self.placed.remove(nexthop);
    }

    /// Resolve one nexthop, or `None` if its device is excluded or, for
    /// a bridge neighbour, not yet placed behind a member.
    pub fn resolve(&self, nexthop: &IpAddr) -> Option<NexthopTarget> {
        let dev = self.device_of.get(nexthop)?;
        self.target(dev, self.placement(nexthop))
    }

    /// The same mapping policy for a device and candidate placement this
    /// map has not been told about yet.
    ///
    /// Exists so the delta path can ask "where would this nexthop land?"
    /// before committing the nexthop→device pair. Programming the
    /// adjacency has to happen first, and recording the mapping in order
    /// to look the interface up would make every route through the
    /// nexthop installable before VPP had acknowledged anything.
    pub fn target(&self, dev: &str, placed: Option<&str>) -> Option<NexthopTarget> {
        let subif = |port: &str, vlan: u16| {
            (self.is_member(port) && self.port_vlans.get(port).is_some_and(|v| v.contains(&vlan)))
                .then(|| NexthopTarget::Subif {
                    port: port.to_string(),
                    vlan,
                })
        };
        match self.kind_of(dev)? {
            DevKind::Plain => self.is_member(dev).then(|| NexthopTarget::Vf {
                port: dev.to_string(),
            }),
            // A VLAN whose port was never made a member, or never given
            // that vid, is still excluded: the subif has nothing to sit on.
            DevKind::PortVlan { port, vid } => subif(port, *vid),
            // A bridged VLAN with a BVI resolves to it regardless of
            // placement; a neighbour placed on the port's UNTAGGED VLAN
            // goes through the VF. A tagged bridged VLAN with no BVI does
            // not resolve at all — deliberately never to a subif, which
            // would send from the port's MAC instead of the bridge's.
            DevKind::BridgeVlan { bridge, vid } => {
                if self.bvis.get(vid) == Some(bridge) {
                    return Some(NexthopTarget::Bvi { vlan: *vid });
                }
                let port = placed?;
                let bare = self
                    .port_untagged
                    .get(port)
                    .is_some_and(|v| v.contains(vid));
                (bare && self.is_member(port)).then(|| NexthopTarget::Vf {
                    port: port.to_string(),
                })
            }
        }
    }

    /// What `dev` is, treating an unclassified device as
    /// [`DevKind::Plain`]; `None` for a shape VPP cannot reach through.
    pub fn kind(&self, dev: &str) -> Option<&DevKind> {
        self.kind_of(dev)
    }

    fn kind_of(&self, dev: &str) -> Option<&DevKind> {
        const PLAIN: DevKind = DevKind::Plain;
        match self.kinds.get(dev) {
            Some(k) => k.as_ref(),
            None => Some(&PLAIN),
        }
    }

    fn is_member(&self, port: &str) -> bool {
        self.members.iter().any(|m| m == port)
    }

    /// Resolve a whole nexthop set. Returns only the resolvable targets;
    /// an empty result means the route is `Unresolvable`.
    ///
    /// Partial resolution is deliberately *not* a failure: on a
    /// multipath route whose paths exit a mix of member and excluded
    /// devices, installing the member-side paths forwards correctly and
    /// is strictly better than withholding the prefix entirely. The
    /// alternative — all-or-nothing — would black-hole a prefix that had
    /// a perfectly good path available.
    pub fn resolve_all(&self, nexthops: &[IpAddr]) -> Vec<NexthopTarget> {
        nexthops.iter().filter_map(|nh| self.resolve(nh)).collect()
    }
}

/// The pending map: what the sink still owes VPP.
///
/// Bounded by table size rather than event rate. Not a queue — a second
/// event for the same prefix overwrites the first.
#[derive(Debug, Default)]
pub struct PendingMap {
    ops: BTreeMap<PrefixKey, PendingOp>,
    /// Ops parked because the table is at its high-water mark.
    ///
    /// Held here rather than in `ops` for a specific reason: the caller
    /// drains until `ops` is empty, so leaving withheld work there
    /// would spin — every pass would re-classify routes that cannot
    /// possibly install yet. Held here rather than dropped for a
    /// stronger one: the ledger records only the prefix and its
    /// `Withheld` state, so the nexthops are the only copy of what the
    /// route should become. Discard them and "retried when headroom
    /// returns" is unimplementable — the route stays missing until an
    /// unrelated source event happens to touch the same prefix.
    withheld: BTreeMap<PrefixKey, PendingOp>,
    /// IPv6 ops VPP refused, parked out of `ops` ([`Self::reject`]).
    rejected: BTreeMap<PrefixKey, PendingOp>,
}

impl PendingMap {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn withheld_len(&self) -> usize {
        self.withheld.len()
    }

    /// Park an op that capacity refused. A newer intent for the same
    /// prefix in the active map always wins, so parking never
    /// resurrects stale state.
    pub fn withhold(&mut self, prefix: IpPrefix, op: PendingOp) {
        self.withheld.insert(prefix.into(), op);
    }

    /// Move every parked op back into the active map, for a caller
    /// that has observed headroom returning. Uses the same
    /// don't-clobber-newer-intent rule as [`Self::requeue`].
    ///
    /// Returns how many were released.
    pub fn release_withheld(&mut self) -> usize {
        let n = self.withheld.len();
        for (k, op) in std::mem::take(&mut self.withheld) {
            self.ops.entry(k).or_insert(op);
        }
        n
    }

    /// Release only one family's parked ops — `v6` or v4 — for a caller
    /// that has observed headroom return in THAT family's pool.
    ///
    /// The drainer releases after every drain that ends with headroom,
    /// and with one pool per family ([`Capacity`]) headroom is a
    /// per-family fact. Releasing everything on any headroom would spin
    /// whenever one family sits at its mark while the other does not:
    /// every drain re-classifying the full family's parked ops, only to
    /// park them again. A range split rather than a filter, so a family
    /// at its mark costs nothing per drain however much of it is parked
    /// ([`PrefixKey`] orders every v4 key before every v6 one).
    pub fn release_withheld_family(&mut self, v6: bool) -> usize {
        let first_v6 = PrefixKey {
            family: 6,
            addr: [0; 16],
            len: 0,
        };
        let v6_part = self.withheld.split_off(&first_v6);
        let released = if v6 {
            v6_part
        } else {
            std::mem::replace(&mut self.withheld, v6_part)
        };
        let n = released.len();
        for (k, op) in released {
            self.ops.entry(k).or_insert(op);
        }
        n
    }

    /// Record an install/replace. Overwrites any pending op for this
    /// prefix, including a pending withdrawal (the newer intent wins).
    pub fn upsert(&mut self, prefix: IpPrefix, nexthops: Vec<IpAddr>) {
        let k = PrefixKey::from(prefix);
        // A newer intent supersedes a refused one outright, and is the
        // retry: it goes back through the drain like any other op.
        self.rejected.remove(&k);
        self.ops.insert(k, PendingOp::Upsert { nexthops });
    }

    /// Record a withdrawal, overwriting any pending upsert.
    pub fn withdraw(&mut self, prefix: IpPrefix) {
        let k = PrefixKey::from(prefix);
        self.rejected.remove(&k);
        self.ops.insert(k, PendingOp::Withdraw);
    }

    /// Park an IPv6 op VPP refused, out of the active map.
    ///
    /// IPv4's refusals are requeued, so a transient cause resolves on the
    /// next drain — and a permanent one keeps the drain busy, which is
    /// right for the family steering depends on: its table is not
    /// complete, and "not idle" is how that holds a first steer back.
    /// IPv6 gates nothing, so the same requeue would make one refused v6
    /// route keep the drain from ever reporting idle, and with it hold
    /// back `SyncComplete`, verify and every IPv4 steer. Parked here it is
    /// counted ([`FamilyCounts::rejected`]) and retried when anything
    /// newer arrives for the prefix — a source update, or the next resync,
    /// which re-queues every route VPP is not recorded holding.
    pub fn reject(&mut self, prefix: IpPrefix, op: PendingOp) {
        self.rejected.insert(prefix.into(), op);
    }

    /// How many refused ops are parked.
    pub fn rejected_len(&self) -> usize {
        self.rejected.len()
    }

    /// Take up to `max` pending ops in key order, removing them from the
    /// map. The caller re-queues anything the transport rejects, so a
    /// failed batch is not lost.
    pub fn drain_batch(&mut self, max: usize) -> Vec<(IpPrefix, PendingOp)> {
        let keys: Vec<PrefixKey> = self.ops.keys().copied().take(max).collect();
        keys.into_iter()
            .map(|k| {
                let op = self.ops.remove(&k).expect("key came from this map");
                (k.into(), op)
            })
            .collect()
    }

    /// Drop every active op whose prefix fails `keep`.
    ///
    /// Used by the full-table resync to discard ops left over from an
    /// aborted one. Those prefixes live only here — they were never
    /// classified, so `RouteLedger::known_prefixes` cannot see them, and
    /// the resync's withdrawal loop walks the ledger. Without this, a
    /// prefix the source dropped between an aborted resync and the next
    /// one keeps its stale pending upsert and is installed later, even
    /// though the current snapshot does not advertise it.
    ///
    /// Only the active map: parked (withheld) ops keep their own
    /// lifecycle, and the resync releases them separately.
    pub fn retain(&mut self, keep: impl Fn(&IpPrefix) -> bool) {
        self.ops.retain(|k, _| keep(&IpPrefix::from(*k)));
        // Refused ops too: one for a prefix the source has since dropped
        // is owed nothing, and left parked would keep counting.
        self.rejected.retain(|k, _| keep(&IpPrefix::from(*k)));
    }

    /// Re-queue an op the transport could not apply — but only if the
    /// prefix has not been superseded in the meantime. A newer event
    /// that arrived while the batch was in flight is the current intent
    /// and must not be clobbered by the stale retry.
    pub fn requeue(&mut self, prefix: IpPrefix, op: PendingOp) {
        self.ops.entry(prefix.into()).or_insert(op);
    }

    /// Forget whatever is owed for `prefix`, active or parked.
    ///
    /// For the resync walk's skip of a route VPP is recorded holding
    /// exactly as the source describes it: an op left here from an
    /// aborted resync or an earlier delta is an OLDER intent than the
    /// walk just read, and draining it after the skip would install
    /// yesterday's nexthops over today's.
    pub fn discard(&mut self, prefix: IpPrefix) {
        let k = PrefixKey::from(prefix);
        self.ops.remove(&k);
        self.withheld.remove(&k);
        self.rejected.remove(&k);
    }
}

/// One FIB path as VPP holds it — every attribute of it that decides
/// forwarding, not just where it goes. What a route was installed
/// THROUGH, which is what a restart compares to decide whether re-sending
/// it would change anything, and what verify compares against a seeded
/// ledger.
///
/// Where-it-goes alone was the first version and it was not enough
/// (review finding): another client replacing a route with the same
/// nexthop and interface but a different weight, preference, type, flags
/// or label stack keeps every per-length count and every
/// `(nexthop, interface)` pair, so neither the fingerprint nor a
/// where-only verify would notice, and the resync would skip restoring
/// it. Built only by `fib_sync::path_key` from a wire path — the one
/// decoding the drainer, the resync and verify share — which also
/// normalizes the defaults VPP echoes differently from what was sent.
///
/// Deliberately NOT here: `table_id` (the lookup table of a recursive or
/// deag path), `rpf_id` (multicast), and the `via_label` / `obj_id` /
/// `classify_table_index` members of the nexthop union — none is
/// consulted for the NORMAL attached-nexthop paths this module installs,
/// and a path that became one of the kinds that does consult them has
/// changed `kind`, which is compared.
///
/// Interned with the rest of its set (see [`PathSets`]), so the wider key
/// costs per distinct path set, not per route: the ledger still holds a
/// 4-byte id a route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathKey {
    pub nexthop: IpAddr,
    pub sw_if_index: u32,
    /// Normalized: VPP installs a weight of 0 as 1.
    pub weight: u8,
    pub preference: u8,
    /// `FIB_API_PATH_TYPE_*`.
    pub kind: u32,
    /// `FIB_API_PATH_FLAG_*`.
    pub flags: u32,
    /// `FIB_API_PATH_NH_PROTO_*`.
    pub proto: u32,
    /// The MPLS label stack as `(label, ttl, exp, is_uniform)` — only the
    /// `n_labels` entries that exist, never the zero padding behind them.
    pub labels: Vec<(u32, u8, u8, u8)>,
}

/// An interned path set. See [`RouteLedger::intern_paths`].
pub type PathSetId = u32;

/// Sentinel for "the paths VPP holds for this prefix are not known" — a
/// prefix adopted from a FIB dump, or one whose live version predates
/// the tracking. Never skipped by a resync and never path-verified.
const UNKNOWN_PATHS: PathSetId = PathSetId::MAX;

/// Distinct path sets, interned.
///
/// A full table is ~1.1M prefixes over a few dozen nexthops, so storing
/// each route's paths inline would be a `Vec` per route — the memory the
/// ledger has always refused to spend (see `verify`'s module docs). Sets
/// are shared instead, and the ledger holds a 4-byte id per route.
///
/// Never shrinks within a process: a set some route stopped using stays
/// interned. The population is bounded by the distinct nexthop
/// combinations the feed has produced, and the whole table is rebuilt
/// with the ledger when the process it describes dies.
#[derive(Debug, Default)]
struct PathSets {
    sets: Vec<Box<[PathKey]>>,
    index: std::collections::HashMap<Box<[PathKey]>, PathSetId>,
}

impl PathSets {
    fn intern(&mut self, paths: &[PathKey]) -> PathSetId {
        if let Some(id) = self.index.get(paths) {
            return *id;
        }
        let id = self.sets.len() as PathSetId;
        // `UNKNOWN_PATHS` is the one id that must never be issued. Four
        // billion distinct nexthop combinations is not a table, it is a
        // bug upstream — and the safe answer to it is "unknown", which
        // costs a re-send, never a skip.
        if id == UNKNOWN_PATHS {
            return UNKNOWN_PATHS;
        }
        let boxed: Box<[PathKey]> = paths.into();
        self.sets.push(boxed.clone());
        self.index.insert(boxed, id);
        id
    }

    fn find(&self, paths: &[PathKey]) -> Option<PathSetId> {
        self.index.get(paths).copied()
    }

    fn get(&self, id: PathSetId) -> Option<&[PathKey]> {
        self.sets.get(id as usize).map(|b| &b[..])
    }
}

/// Put a path set in the one order every comparison uses. VPP keeps a
/// route's paths as a set, so two installs of the same paths in a
/// different order are the same route and must intern as one.
pub fn canonical_paths(mut paths: Vec<PathKey>) -> Vec<PathKey> {
    paths.sort_unstable();
    paths.dedup();
    paths
}

/// One ledger entry: the route's state and, while VPP holds a live
/// version of it, the paths that version was installed through.
#[derive(Debug, Clone, Copy)]
struct Slot {
    state: RouteState,
    /// [`UNKNOWN_PATHS`] unless VPP was OBSERVED to hold this prefix
    /// through a known path set — its acknowledgement of our own write,
    /// or the previous process's record of the same. Kept across an
    /// in-flight replacement (the old version is still what forwards)
    /// and cleared by anything that says nothing live remains.
    via: PathSetId,
}

/// Tracks per-prefix state and decides what each pending op becomes.
///
/// **Two-phase by construction.** [`Self::classify_upsert`] decides and
/// *reserves*, but only [`Self::commit_installed`] may record a route as
/// present in VPP. Nothing else is honest: `PendingMap` exists precisely
/// because the transport can reject an op, and a ledger that marked
/// routes installed at classification time would report a FIB it never
/// confirmed, feed unconfirmed prefixes to readback verification, and
/// hold capacity slots for routes VPP never accepted — so one
/// path-specific rejection loop could leave VPP nearly empty while
/// unrelated valid routes were withheld for lack of headroom.
///
/// Counters are maintained incrementally. Recomputing them per
/// classification made a full-table load quadratic.
#[derive(Debug)]
pub struct RouteLedger {
    state: BTreeMap<PrefixKey, Slot>,
    /// IPv4's totals (the top-level fields; `v6` stays `None` here).
    counts: SinkCounts,
    /// IPv6's, kept apart for the same reason [`SinkCounts`] reports them
    /// apart, and so each family's pool is judged against its own
    /// occupancy ([`Capacity`]).
    v6: FamilyCounts,
    capacity: Capacity,
    paths: PathSets,
    /// How many IPv4 prefixes are recorded holding each path set — so
    /// the IPv4 link gate can ask which next hops IPv4 routes actually
    /// use ([`Self::v4_nexthops`]) without walking a million routes.
    v4_via_refs: std::collections::HashMap<PathSetId, u64>,
}

impl RouteLedger {
    pub fn new(capacity: Capacity) -> Self {
        Self {
            state: BTreeMap::new(),
            counts: SinkCounts::default(),
            v6: FamilyCounts::default(),
            capacity,
            paths: PathSets::default(),
            v4_via_refs: std::collections::HashMap::new(),
        }
    }

    pub fn state_of(&self, prefix: IpPrefix) -> Option<RouteState> {
        self.state.get(&prefix.into()).map(|s| s.state)
    }

    /// Intern a canonical path set (see [`canonical_paths`]).
    pub fn intern_paths(&mut self, paths: &[PathKey]) -> PathSetId {
        self.paths.intern(paths)
    }

    /// The id of an already-interned path set, without interning it.
    pub fn find_paths(&self, paths: &[PathKey]) -> Option<PathSetId> {
        self.paths.find(paths)
    }

    /// The paths a set id stands for.
    pub fn paths_of(&self, id: PathSetId) -> Option<&[PathKey]> {
        self.paths.get(id)
    }

    /// The paths VPP is recorded holding for an INSTALLED prefix, if
    /// they are known. `None` for anything not `Installed`, and for an
    /// installed prefix whose paths were never observed (a dump
    /// adoption) — the caller must then assume nothing about them.
    pub fn installed_via(&self, prefix: IpPrefix) -> Option<PathSetId> {
        match self.state.get(&prefix.into()) {
            Some(Slot {
                state: RouteState::Installed,
                via,
            }) if *via != UNKNOWN_PATHS => Some(*via),
            _ => None,
        }
    }

    /// Every `Installed` prefix with the path set VPP is recorded
    /// holding it through (`None` = unknown), in key order.
    pub fn installed_entries(&self) -> impl Iterator<Item = (IpPrefix, Option<PathSetId>)> + '_ {
        self.state
            .iter()
            .filter(|(_, s)| s.state == RouteState::Installed)
            .map(|(k, s)| ((*k).into(), (s.via != UNKNOWN_PATHS).then_some(s.via)))
    }

    /// IPv4's totals, O(1) — see the type docs. `v6` is `None`: the
    /// ledger does not know whether the family is carried, so the engine
    /// fills it in from [`Self::v6_counts`].
    pub fn counts(&self) -> SinkCounts {
        self.counts
    }

    /// IPv6's totals, O(1).
    pub fn v6_counts(&self) -> FamilyCounts {
        self.v6
    }

    /// The capacity policy this ledger enforces.
    ///
    /// Exposed so a caller rebuilding the ledger — on restart, when the
    /// old VPP's FIB is gone and every recorded install is void — can
    /// carry the policy across. Capacity is derived from the measured
    /// heap gauge, not from the process that happened to be running, so
    /// losing it on restart would rebuild an unbounded ledger and
    /// install straight past the high-water mark.
    pub fn capacity(&self) -> Capacity {
        self.capacity
    }

    fn tally(
        counts: &mut SinkCounts,
        v6: &mut FamilyCounts,
        key: &PrefixKey,
        st: RouteState,
        add: bool,
    ) {
        let slot = match (key.family == 6, st) {
            (false, RouteState::Installed) => &mut counts.installed,
            (false, RouteState::Installing { .. }) => &mut counts.installing,
            (false, RouteState::NotInstalled(NotInstalled::Withheld)) => &mut counts.withheld,
            (false, RouteState::NotInstalled(NotInstalled::Unresolvable)) => {
                &mut counts.unresolvable
            }
            (true, RouteState::Installed) => &mut v6.installed,
            (true, RouteState::Installing { .. }) => &mut v6.installing,
            (true, RouteState::NotInstalled(NotInstalled::Withheld)) => &mut v6.withheld,
            (true, RouteState::NotInstalled(NotInstalled::Unresolvable)) => &mut v6.unresolvable,
        };
        // Only ever decrements a state just read out of the map, so it
        // cannot underflow; debug_assert makes a future refactor that
        // breaks that pairing fail loudly instead of wrapping.
        if add {
            *slot += 1;
        } else {
            debug_assert!(*slot > 0, "counter underflow for {st:?}");
            *slot -= 1;
        }
    }

    /// Set a state and decide the recorded paths: `via` when it names
    /// the paths VPP just acknowledged, the old version's paths when
    /// `keep_via` says that version is still what forwards, unknown
    /// otherwise.
    fn set_slot(&mut self, key: PrefixKey, st: RouteState, via: Option<PathSetId>, keep_via: bool) {
        let prior_via = self.state.get(&key).map_or(UNKNOWN_PATHS, |s| s.via);
        let via = match via {
            Some(v) => v,
            None if keep_via => prior_via,
            None => UNKNOWN_PATHS,
        };
        if let Some(old) = self.state.insert(key, Slot { state: st, via }) {
            Self::tally(&mut self.counts, &mut self.v6, &key, old.state, false);
            self.via_ref(&key, old.via, false);
        }
        Self::tally(&mut self.counts, &mut self.v6, &key, st, true);
        self.via_ref(&key, via, true);
    }

    fn set_state(&mut self, key: PrefixKey, st: RouteState) {
        // Only a state with a live version still in VPP may keep the
        // paths that version was installed through: a replacement in
        // flight, or a rejected one falling back to what forwards.
        let live = matches!(
            st,
            RouteState::Installed | RouteState::Installing { replacing: true }
        );
        self.set_slot(key, st, None, live);
    }

    fn clear_state(&mut self, key: PrefixKey) -> Option<RouteState> {
        let old = self.state.remove(&key)?;
        Self::tally(&mut self.counts, &mut self.v6, &key, old.state, false);
        self.via_ref(&key, old.via, false);
        Some(old.state)
    }

    /// Keep [`Self::v4_via_refs`] in step with one v4 slot's recorded
    /// paths. A known path set is recorded only while VPP holds a live
    /// version (see `set_state`), so counting known ids counts live routes.
    fn via_ref(&mut self, key: &PrefixKey, via: PathSetId, add: bool) {
        if key.family != 4 || via == UNKNOWN_PATHS {
            return;
        }
        if add {
            *self.v4_via_refs.entry(via).or_default() += 1;
        } else if let Some(n) = self.v4_via_refs.get_mut(&via) {
            *n -= 1;
            if *n == 0 {
                self.v4_via_refs.remove(&via);
            }
        }
    }

    /// Every next hop an IPv4 route is recorded installed through. Routes
    /// whose paths were never observed (a dump adoption not yet re-sent)
    /// contribute nothing; see the link gate for why that is safe.
    pub fn v4_nexthops(&self) -> std::collections::HashSet<IpAddr> {
        self.v4_via_refs
            .keys()
            .filter_map(|id| self.paths.get(*id))
            .flatten()
            .map(|p| p.nexthop)
            .collect()
    }

    /// Capacity slots in use in one family's pool: installed plus
    /// in-flight. Counting in-flight routes is what stops a single
    /// drained batch from oversubscribing the table before any of it is
    /// acknowledged.
    fn occupied(&self, v6: bool) -> u64 {
        if v6 {
            self.v6.installed + self.v6.installing
        } else {
            self.counts.installed + self.counts.installing
        }
    }

    /// Whether another route of the family (`v6`, or v4) would fit under
    /// that family's high-water mark. Drives the release of parked
    /// (withheld) ops, per family ([`PendingMap::release_withheld_family`]).
    pub fn has_headroom(&self, v6: bool) -> bool {
        self.capacity.has_headroom(v6, self.occupied(v6))
    }

    /// Decide the outcome of an upsert and reserve a slot for it.
    ///
    /// Resolution is checked *before* capacity: a route with no
    /// VPP-reachable nexthop is unresolvable whether or not there is
    /// headroom, and calling it `Withheld` would make it retry forever
    /// on every capacity change.
    ///
    /// A resolvable route lands in [`RouteState::Installing`]; the
    /// caller must follow the transport's answer with
    /// [`Self::commit_installed`] or [`Self::fail_install`].
    pub fn classify_upsert(
        &mut self,
        prefix: IpPrefix,
        nexthops: &[IpAddr],
        map: &NexthopMap,
    ) -> (RouteState, Vec<NexthopTarget>) {
        let targets = map.resolve_all(nexthops);
        let st = self.classify_resolved(prefix, targets.len());
        (st, targets)
    }

    /// Same decision, for a caller that has already resolved the
    /// nexthops.
    ///
    /// The drainer resolves once and needs the addresses alongside the
    /// targets to encode FIB paths; making it re-resolve through
    /// [`Self::classify_upsert`] would run the mapping policy twice per
    /// route — a million times over on a full-table load — and risk
    /// the two answers diverging if the map changed in between.
    pub fn classify_resolved(&mut self, prefix: IpPrefix, n_resolved: usize) -> RouteState {
        let key = PrefixKey::from(prefix);
        if n_resolved == 0 {
            let st = RouteState::NotInstalled(NotInstalled::Unresolvable);
            self.set_state(key, st);
            return st;
        }
        // A prefix that already holds a slot keeps it on replace — a
        // route update must not be withheld just because the table sits
        // at the mark, or steady-state churn would silently erode the
        // installed set.
        let prior = self.state.get(&key).map(|s| s.state);
        let st = match prior {
            Some(RouteState::Installed) | Some(RouteState::Installing { replacing: true }) => {
                RouteState::Installing { replacing: true }
            }
            Some(RouteState::Installing { replacing: false }) => {
                RouteState::Installing { replacing: false }
            }
            _ if self
                .capacity
                .has_headroom(key.family == 6, self.occupied(key.family == 6)) =>
            {
                RouteState::Installing { replacing: false }
            }
            _ => RouteState::NotInstalled(NotInstalled::Withheld),
        };
        self.set_state(key, st);
        st
    }

    /// VPP acknowledged the route.
    /// Record a prefix VPP is **observed** to already hold.
    ///
    /// For adoption, and only for adoption: the ledger starts empty
    /// while a surviving VPP's FIB does not, so without this the resync
    /// diff — which derives withdrawals from what the ledger knows —
    /// cannot see a prefix that was withdrawn while packetframe was
    /// down, and it stays installed where a stale more-specific keeps
    /// overriding the live table.
    ///
    /// `Installed` is honest here rather than optimistic: the caller
    /// read it out of VPP with `ip_route_dump`. That is a stronger
    /// observation than the one `commit_installed` acts on, which is an
    /// acknowledgement of our own write.
    ///
    /// Refuses to overwrite a prefix the ledger already tracks — a
    /// readback must not stomp an in-flight `Installing`, and a
    /// non-empty ledger means this is not an adoption.
    pub fn adopt_installed(&mut self, prefix: IpPrefix) {
        let key = PrefixKey::from(prefix);
        if self.state.contains_key(&key) {
            return;
        }
        // Paths unknown: the dump names the prefix, and what a later
        // resync may skip is decided only by paths this ledger OBSERVED.
        self.set_slot(key, RouteState::Installed, None, false);
    }

    /// Record a prefix the previous process's preserved ledger says VPP
    /// holds, through the paths it recorded.
    ///
    /// Adoption only, with the same refusal as [`Self::adopt_installed`].
    /// `Installed` here rests on that record rather than on a readback,
    /// which is why the caller verifies VPP against it — paths included —
    /// before the state counts as verified (see `runtime`'s
    /// preserved-ledger path).
    pub fn adopt_recorded(&mut self, prefix: IpPrefix, via: Option<PathSetId>) {
        let key = PrefixKey::from(prefix);
        if self.state.contains_key(&key) {
            return;
        }
        self.set_slot(key, RouteState::Installed, via, false);
    }

    pub fn commit_installed(&mut self, prefix: IpPrefix) {
        self.commit_installed_via(prefix, None);
    }

    /// VPP acknowledged the route, installed through `via` — the path set
    /// the acknowledged request carried. `None` records the paths as
    /// unknown, which only ever costs a later re-send.
    pub fn commit_installed_via(&mut self, prefix: IpPrefix, via: Option<PathSetId>) {
        let key = PrefixKey::from(prefix);
        if matches!(
            self.state.get(&key).map(|s| s.state),
            Some(RouteState::Installing { .. })
        ) {
            self.set_slot(key, RouteState::Installed, via, false);
        }
    }

    /// The transport rejected the route.
    ///
    /// A rejected **replacement** falls back to `Installed`: the prior
    /// version is still live in VPP, so claiming otherwise would drop a
    /// forwarding route out of the verify pool. A rejected **first**
    /// install is forgotten outright, releasing its slot so the headroom
    /// it reserved becomes available to routes that can use it. The
    /// retry intent lives in [`PendingMap`], not here.
    pub fn fail_install(&mut self, prefix: IpPrefix) {
        let key = PrefixKey::from(prefix);
        match self.state.get(&key).map(|s| s.state) {
            Some(RouteState::Installing { replacing: true }) => {
                self.set_state(key, RouteState::Installed)
            }
            Some(RouteState::Installing { replacing: false }) => {
                self.clear_state(key);
            }
            _ => {}
        }
    }

    /// Forget a prefix on withdrawal.
    pub fn forget(&mut self, prefix: IpPrefix) {
        self.clear_state(prefix.into());
    }

    /// Prefixes eligible for retry once headroom returns. Excludes
    /// `Unresolvable` — no amount of capacity fixes a mapping — so the
    /// retry set stays proportional to real headroom.
    pub fn withheld_prefixes(&self) -> Vec<IpPrefix> {
        self.state
            .iter()
            .filter(|(_, s)| s.state == RouteState::NotInstalled(NotInstalled::Withheld))
            .map(|(k, _)| (*k).into())
            .collect()
    }

    /// Whether the ledger holds an opinion about any prefix. O(1), where
    /// asking [`Self::known_prefixes`] would materialise the table.
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }

    /// Every prefix the ledger holds an opinion about, in any state.
    ///
    /// The full-table resync needs this to compute **withdrawals**. A
    /// prefix that left the route source while VPP was down, or while
    /// packetframe was, is still installed in VPP's FIB — an add-only
    /// resync would leave it forwarding to a nexthop the source no
    /// longer advertises, which is a black hole that readback
    /// verification cannot see (it samples what the ledger claims, and
    /// the ledger claims that route is fine).
    pub fn known_prefixes(&self) -> Vec<IpPrefix> {
        self.state.keys().map(|k| (*k).into()).collect()
    }

    /// Sampling pool for readback verification: only prefixes VPP has
    /// **confirmed**. Withheld and unresolvable prefixes would fail by
    /// design; in-flight ones would race the transport.
    pub fn verifiable_prefixes(&self) -> Vec<IpPrefix> {
        self.state
            .iter()
            .filter(|(_, s)| s.state == RouteState::Installed)
            .map(|(k, _)| (*k).into())
            .collect()
    }

    /// Recompute counts by scanning. Test-only cross-check against the
    /// incrementally maintained figures.
    #[cfg(test)]
    fn counts_by_scan(&self) -> (SinkCounts, FamilyCounts) {
        let mut c = SinkCounts::default();
        let mut v6 = FamilyCounts::default();
        for (k, s) in &self.state {
            Self::tally(&mut c, &mut v6, k, s.state, true);
        }
        (c, v6)
    }
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

    fn nh(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn member_map() -> NexthopMap {
        let mut m = NexthopMap::new(vec!["eth4".into(), "eth5".into()]);
        m.set_device(nh(192, 0, 2, 1), "eth4");
        m.set_device(nh(192, 0, 2, 2), "eth5");
        m.set_device(nh(192, 0, 2, 9), "eth0"); // excluded (mgmt)
        m
    }

    #[test]
    fn prefix_key_round_trips_both_families() {
        let p4 = v4(10, 0, 0, 0, 8);
        assert_eq!(IpPrefix::from(PrefixKey::from(p4)), p4);
        let p6 = IpPrefix::V6 {
            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            prefix_len: 48,
        };
        assert_eq!(IpPrefix::from(PrefixKey::from(p6)), p6);
    }

    #[test]
    fn v4_and_v6_keys_never_collide() {
        // A v6 prefix whose leading bytes match a v4 address must not
        // share a key with it.
        let p4 = v4(0x20, 0x01, 0x0d, 0xb8, 32);
        let mut wide = [0u8; 16];
        wide[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        let p6 = IpPrefix::V6 {
            addr: wide,
            prefix_len: 32,
        };
        assert_ne!(PrefixKey::from(p4), PrefixKey::from(p6));
    }

    #[test]
    fn churn_on_one_prefix_collapses_to_one_entry() {
        // The whole reason this is a map and not a FIFO: a flapping
        // prefix must not grow the backlog.
        let mut pm = PendingMap::new();
        for i in 0..1000u32 {
            pm.upsert(v4(10, 0, 0, 0, 8), vec![nh(192, 0, 2, (i % 2) as u8 + 1)]);
        }
        assert_eq!(pm.len(), 1);
    }

    #[test]
    fn withdraw_overwrites_pending_upsert_and_vice_versa() {
        let mut pm = PendingMap::new();
        let p = v4(10, 0, 0, 0, 8);
        pm.upsert(p, vec![nh(192, 0, 2, 1)]);
        pm.withdraw(p);
        assert_eq!(pm.drain_batch(10), vec![(p, PendingOp::Withdraw)]);

        pm.withdraw(p);
        pm.upsert(p, vec![nh(192, 0, 2, 1)]);
        assert_eq!(
            pm.drain_batch(10),
            vec![(
                p,
                PendingOp::Upsert {
                    nexthops: vec![nh(192, 0, 2, 1)]
                }
            )]
        );
    }

    #[test]
    fn drain_batch_is_bounded_and_removes_what_it_returns() {
        let mut pm = PendingMap::new();
        for i in 0..10u8 {
            pm.upsert(v4(10, i, 0, 0, 16), vec![nh(192, 0, 2, 1)]);
        }
        assert_eq!(pm.drain_batch(4).len(), 4);
        assert_eq!(pm.len(), 6);
        assert_eq!(pm.drain_batch(100).len(), 6);
        assert!(pm.is_empty());
    }

    #[test]
    fn requeue_does_not_clobber_a_newer_event() {
        // A batch fails in flight while a fresher event lands for the
        // same prefix. The retry must lose.
        let mut pm = PendingMap::new();
        let p = v4(10, 0, 0, 0, 8);
        pm.upsert(p, vec![nh(192, 0, 2, 1)]);
        let batch = pm.drain_batch(10);
        pm.withdraw(p); // newer intent arrives
        for (prefix, op) in batch {
            pm.requeue(prefix, op);
        }
        assert_eq!(pm.drain_batch(10), vec![(p, PendingOp::Withdraw)]);
    }

    #[test]
    fn nexthop_map_excludes_non_member_devices() {
        let m = member_map();
        assert_eq!(
            m.resolve(&nh(192, 0, 2, 1)),
            Some(NexthopTarget::Vf {
                port: "eth4".into()
            })
        );
        assert_eq!(m.resolve(&nh(192, 0, 2, 9)), None, "mgmt must be excluded");
        assert_eq!(m.resolve(&nh(198, 51, 100, 1)), None, "unknown nexthop");
    }

    #[test]
    fn vlan_nexthop_maps_to_subif_only_when_port_is_a_member() {
        let port_vlan = Some(DevKind::PortVlan {
            port: "eth4".into(),
            vid: 1337,
        });
        let mut m = member_map().with_port_vlans([("eth4".to_string(), vec![1337])]);
        m.set_kind("br1337", port_vlan.clone());
        m.set_device(nh(192, 0, 2, 20), "br1337");
        assert_eq!(
            m.resolve(&nh(192, 0, 2, 20)),
            Some(NexthopTarget::Subif {
                port: "eth4".into(),
                vlan: 1337
            })
        );

        // Same VLAN over a non-member port: the subif has nothing to sit
        // on, so it must be excluded rather than silently invented.
        let mut orphan = NexthopMap::new(vec!["eth5".into()])
            .with_port_vlans([("eth4".to_string(), vec![1337])]);
        orphan.set_kind("br1337", port_vlan.clone());
        orphan.set_device(nh(192, 0, 2, 20), "br1337");
        assert_eq!(orphan.resolve(&nh(192, 0, 2, 20)), None);

        // A member that does not carry the vid has no subif for it.
        let mut undeclared = member_map();
        undeclared.set_kind("br1337", port_vlan);
        undeclared.set_device(nh(192, 0, 2, 20), "br1337");
        assert_eq!(undeclared.resolve(&nh(192, 0, 2, 20)), None);
    }

    /// The trunk case: one bridge VLAN, neighbours behind either port.
    /// With a BVI every one of them resolves to it — placement only
    /// decides the L2FIB entry — and WITHOUT one a tagged bridged VLAN
    /// resolves to nothing at all, never to a port's subif: that path
    /// would send from the port's MAC, which an IX drops or answers by
    /// shutting the port.
    #[test]
    fn bridge_vlan_neighbours_resolve_through_the_bvi_only() {
        let bridge = Some(DevKind::BridgeVlan {
            bridge: "switch0".into(),
            vid: 3998,
        });
        let mut m = member_map().with_port_vlans([
            ("eth4".to_string(), vec![3998]),
            ("eth5".to_string(), vec![3998]),
        ]);
        m.set_kind("br3998", bridge);
        let (a, b, c) = (nh(192, 0, 2, 31), nh(192, 0, 2, 32), nh(192, 0, 2, 33));
        for n in [a, b, c] {
            m.set_device(n, "br3998");
        }
        let at = |port: &str| Placement {
            bridge: "switch0".into(),
            vid: 3998,
            port: port.into(),
        };
        m.place(a, at("eth4"));
        m.place(b, at("eth5"));
        // No BVI: nothing resolves, placed or not — the subifs exist and
        // are deliberately not used.
        for n in [a, b, c] {
            assert_eq!(m.resolve(&n), None, "{n}");
        }
        // A BVI on another bridge reusing the vid is a different L2
        // domain: nothing here resolves to it.
        m.set_bvi(3998, "switch1");
        for n in [a, b, c] {
            assert_eq!(m.resolve(&n), None, "{n}");
        }
        m.set_bvi(3998, "switch0");
        let bvi = Some(NexthopTarget::Bvi { vlan: 3998 });
        assert_eq!(m.resolve(&a), bvi);
        assert_eq!(m.resolve(&b), bvi);
        assert_eq!(m.resolve(&c), bvi, "unplaced still resolves: it floods");
        assert_eq!(m.bridge_nexthops().len(), 3);

        // A move changes the placement, not the target.
        m.place(a, at("eth5"));
        assert_eq!(m.placement(&a), Some("eth5"));
        assert_eq!(m.resolve(&a), bvi);

        // Reappearing on another bridge VLAN, the old trunk does not
        // follow it there.
        m.set_kind(
            "br3999",
            Some(DevKind::BridgeVlan {
                bridge: "switch0".into(),
                vid: 3999,
            }),
        );
        m.set_device(a, "br3999");
        assert_eq!(m.placement(&a), None);
        m.set_device(a, "br3998");

        // A lost neighbour loses its placement.
        m.forget_device(&a);
        assert_eq!(m.placement(&a), None);
    }

    /// A neighbour on the port's untagged VLAN (the PVID, br0 on a UniFi
    /// box) is reached through the VF itself — no subif, no tag.
    #[test]
    fn an_untagged_vlan_resolves_to_the_port_itself() {
        let mut m = member_map();
        m.set_kind(
            "br0",
            Some(DevKind::BridgeVlan {
                bridge: "switch0".into(),
                vid: 1,
            }),
        );
        m.set_port_untagged("eth4", vec![1]);
        let n = nh(192, 0, 2, 50);
        m.set_device(n, "br0");
        m.place(
            n,
            Placement {
                bridge: "switch0".into(),
                vid: 1,
                port: "eth4".into(),
            },
        );
        assert_eq!(
            m.resolve(&n),
            Some(NexthopTarget::Vf {
                port: "eth4".into()
            })
        );
        // Without the untagged fact it is a tagged bridged VLAN: only a
        // BVI reaches it, never the port's subif.
        m.set_port_untagged("eth4", vec![]);
        assert_eq!(m.resolve(&n), None);
        m.add_port_vlans("eth4", &[1]);
        assert_eq!(m.resolve(&n), None, "a subif alone is not enough");
        m.set_bvi(1, "switch0");
        assert_eq!(m.resolve(&n), Some(NexthopTarget::Bvi { vlan: 1 }));
    }

    #[test]
    fn an_unreachable_shape_is_excluded() {
        let mut m = member_map();
        m.set_kind("brwide", None);
        m.set_device(nh(192, 0, 2, 40), "brwide");
        assert_eq!(m.resolve(&nh(192, 0, 2, 40)), None);
    }

    #[test]
    fn multipath_keeps_resolvable_paths_and_drops_excluded_ones() {
        let m = member_map();
        let targets = m.resolve_all(&[nh(192, 0, 2, 1), nh(192, 0, 2, 9), nh(192, 0, 2, 2)]);
        assert_eq!(
            targets,
            vec![
                NexthopTarget::Vf {
                    port: "eth4".into()
                },
                NexthopTarget::Vf {
                    port: "eth5".into()
                }
            ],
            "a usable path must not be discarded because a sibling is excluded"
        );
    }

    #[test]
    fn route_with_no_reachable_nexthop_is_unresolvable_not_withheld() {
        let mut led = RouteLedger::new(Capacity::new(100));
        let (st, targets) =
            led.classify_upsert(v4(10, 0, 0, 0, 8), &[nh(192, 0, 2, 9)], &member_map());
        assert_eq!(st, RouteState::NotInstalled(NotInstalled::Unresolvable));
        assert!(targets.is_empty());
        assert_eq!(led.counts().unresolvable, 1);
        assert_eq!(led.counts().withheld, 0);
        // Not retried on headroom: unresolvable is a mapping problem.
        assert!(led.withheld_prefixes().is_empty());
    }

    /// classify + acknowledge, the ordinary success path.
    fn install(led: &mut RouteLedger, p: IpPrefix, nexthops: &[IpAddr], map: &NexthopMap) {
        led.classify_upsert(p, nexthops, map);
        led.commit_installed(p);
    }

    #[test]
    fn installs_are_withheld_above_the_high_water_mark() {
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(2));
        for i in 0..4u8 {
            install(&mut led, v4(10, i, 0, 0, 16), &[nh(192, 0, 2, 1)], &map);
        }
        let c = led.counts();
        assert_eq!(c.installed, 2);
        assert_eq!(c.withheld, 2);
        assert_eq!(led.withheld_prefixes().len(), 2);
    }

    #[test]
    fn in_flight_routes_hold_capacity_slots() {
        // A drained batch must not oversubscribe the table before any of
        // it is acknowledged: classification alone consumes headroom.
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(2));
        for i in 0..4u8 {
            led.classify_upsert(v4(10, i, 0, 0, 16), &[nh(192, 0, 2, 1)], &map);
        }
        let c = led.counts();
        assert_eq!(c.installing, 2, "only two slots exist");
        assert_eq!(c.installed, 0, "nothing acknowledged yet");
        assert_eq!(c.withheld, 2);
    }

    #[test]
    fn classification_alone_never_reports_installed() {
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(10));
        let p = v4(10, 0, 0, 0, 8);
        let (st, _) = led.classify_upsert(p, &[nh(192, 0, 2, 1)], &map);
        assert_eq!(st, RouteState::Installing { replacing: false });
        assert_eq!(led.counts().installed, 0);
        assert!(
            led.verifiable_prefixes().is_empty(),
            "in-flight routes must not be verified — that races the transport"
        );

        led.commit_installed(p);
        assert_eq!(led.state_of(p), Some(RouteState::Installed));
        assert_eq!(led.verifiable_prefixes(), vec![p]);
    }

    #[test]
    fn rejected_first_install_releases_its_slot() {
        // Otherwise a persistent path-specific failure would hold
        // capacity hostage and withhold unrelated valid routes.
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(1));
        let bad = v4(10, 0, 0, 0, 8);
        let good = v4(10, 1, 0, 0, 16);
        led.classify_upsert(bad, &[nh(192, 0, 2, 1)], &map);
        led.fail_install(bad);
        assert_eq!(led.state_of(bad), None);
        assert_eq!(led.counts(), SinkCounts::default());

        install(&mut led, good, &[nh(192, 0, 2, 1)], &map);
        assert_eq!(led.counts().installed, 1);
    }

    #[test]
    fn rejected_replacement_falls_back_to_the_live_route() {
        // VPP still holds the previous version, so dropping the prefix
        // would take a forwarding route out of the verify pool.
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(10));
        let p = v4(10, 0, 0, 0, 8);
        install(&mut led, p, &[nh(192, 0, 2, 1)], &map);

        let (st, _) = led.classify_upsert(p, &[nh(192, 0, 2, 2)], &map);
        assert_eq!(st, RouteState::Installing { replacing: true });
        led.fail_install(p);
        assert_eq!(led.state_of(p), Some(RouteState::Installed));
        assert_eq!(led.counts().installed, 1);
        assert_eq!(led.verifiable_prefixes(), vec![p]);
    }

    #[test]
    fn replacing_an_installed_route_at_the_mark_keeps_it_installed() {
        // Steady-state churn at capacity must not erode the installed
        // set — a route update is not a new allocation.
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(1));
        let p = v4(10, 0, 0, 0, 8);
        install(&mut led, p, &[nh(192, 0, 2, 1)], &map);
        install(&mut led, p, &[nh(192, 0, 2, 2)], &map);
        assert_eq!(led.state_of(p), Some(RouteState::Installed));
        assert_eq!(led.counts().installed, 1);
    }

    #[test]
    fn withdrawal_frees_headroom_for_a_withheld_route() {
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(1));
        let a = v4(10, 0, 0, 0, 8);
        let b = v4(10, 1, 0, 0, 16);
        install(&mut led, a, &[nh(192, 0, 2, 1)], &map);
        install(&mut led, b, &[nh(192, 0, 2, 1)], &map);
        assert_eq!(led.counts().withheld, 1);

        led.forget(a);
        install(&mut led, b, &[nh(192, 0, 2, 1)], &map);
        assert_eq!(led.counts().installed, 1);
        assert_eq!(led.counts().withheld, 0);
    }

    #[test]
    fn any_uninstalled_route_blocks_first_steer() {
        // Steering inherits the fast-path ALLOWLIST, not the installed
        // subset, so a steered packet whose route is missing from VPP is
        // dropped or takes a covering route — and cannot fall back to
        // the eBPF tier, because the hardware already diverted it. That
        // holds for withheld exactly as for unresolvable.
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(1));
        install(&mut led, v4(10, 0, 0, 0, 8), &[nh(192, 0, 2, 1)], &map);
        assert!(!led.counts().blocks_first_steer(), "complete table is fine");

        install(&mut led, v4(10, 1, 0, 0, 16), &[nh(192, 0, 2, 1)], &map);
        let c = led.counts();
        assert_eq!(c.withheld, 1);
        assert!(c.blocks_first_steer(), "withheld blackholes those prefixes");
        assert!(c.degraded());

        install(&mut led, v4(10, 2, 0, 0, 16), &[nh(192, 0, 2, 9)], &map);
        assert!(led.counts().blocks_first_steer());
    }

    /// An empty table blocks a first steer: every diverted packet would
    /// be dropped in VPP. And a table that has drained back to empty
    /// blocks again — the retry after `TableEmptied` reads this.
    #[test]
    fn an_empty_table_blocks_first_steer() {
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(10));
        assert!(led.counts().blocks_first_steer(), "nothing installed");

        let p = v4(10, 0, 0, 0, 8);
        install(&mut led, p, &[nh(192, 0, 2, 1)], &map);
        assert!(!led.counts().blocks_first_steer());

        led.forget(p);
        assert_eq!(led.counts().installed, 0);
        assert!(led.counts().blocks_first_steer(), "drained back to empty");
    }

    #[test]
    fn in_flight_table_blocks_first_steer() {
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(10));
        let p = v4(10, 0, 0, 0, 8);
        led.classify_upsert(p, &[nh(192, 0, 2, 1)], &map);
        assert!(
            led.counts().blocks_first_steer(),
            "a table still in flight is an incomplete table"
        );
        led.commit_installed(p);
        assert!(!led.counts().blocks_first_steer());
    }

    #[test]
    fn verify_pool_contains_only_confirmed_prefixes() {
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(2));
        let good = v4(10, 0, 0, 0, 8);
        install(&mut led, good, &[nh(192, 0, 2, 1)], &map);
        led.classify_upsert(v4(10, 3, 0, 0, 16), &[nh(192, 0, 2, 1)], &map); // in flight
        install(&mut led, v4(10, 1, 0, 0, 16), &[nh(192, 0, 2, 1)], &map); // withheld
        install(&mut led, v4(10, 2, 0, 0, 16), &[nh(192, 0, 2, 9)], &map); // unresolvable
        assert_eq!(led.verifiable_prefixes(), vec![good]);
    }

    #[test]
    fn counters_track_a_long_mixed_transition_sequence() {
        // The incremental counters replaced an O(n) rescan per
        // classification. This checks they stay identical to a full
        // scan across every transition the ledger supports — and the
        // 20k loop would crawl if the quadratic recount came back.
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(8_000));
        for i in 0..20_000u32 {
            let p = v4(10, (i >> 8) as u8, (i & 0xff) as u8, 0, 24);
            // Rotate through reachable, unreachable, commit, reject and
            // withdraw so no state is left untouched.
            match i % 5 {
                0 => install(&mut led, p, &[nh(192, 0, 2, 1)], &map),
                1 => install(&mut led, p, &[nh(192, 0, 2, 9)], &map),
                2 => {
                    led.classify_upsert(p, &[nh(192, 0, 2, 1)], &map);
                    led.fail_install(p);
                }
                3 => {
                    install(&mut led, p, &[nh(192, 0, 2, 1)], &map);
                    led.forget(p);
                }
                _ => {
                    led.classify_upsert(p, &[nh(192, 0, 2, 2)], &map);
                }
            }
        }
        assert_eq!(
            (led.counts(), led.v6_counts()),
            led.counts_by_scan(),
            "incremental counters drifted from the ledger contents"
        );
        let c = led.counts();
        assert_eq!(
            c.installed + c.installing + c.withheld + c.unresolvable,
            led.state.len() as u64
        );
    }

    fn pk(d: u8, idx: u32) -> PathKey {
        crate::fib_sync::installed_path_key(nh(192, 0, 2, d), idx)
    }

    /// The paths a route is recorded holding are VPP's acknowledgement,
    /// kept exactly as long as the version they describe is what VPP
    /// forwards — the property the resync skip and the preserved ledger
    /// both stand on.
    #[test]
    fn recorded_paths_follow_what_vpp_acknowledged_and_nothing_else() {
        let mut led = RouteLedger::new(Capacity::new(100));
        let p = v4(10, 0, 0, 0, 24);
        let a = led.intern_paths(&[pk(1, 3)]);
        let b = led.intern_paths(&[pk(2, 3)]);
        assert_eq!(led.intern_paths(&[pk(1, 3)]), a, "interned once");

        led.classify_resolved(p, 1);
        assert_eq!(
            led.installed_via(p),
            None,
            "nothing is recorded before the ack"
        );
        led.commit_installed_via(p, Some(a));
        assert_eq!(led.installed_via(p), Some(a));

        // A replacement in flight, then refused: the old version is still
        // what VPP forwards, so its paths come back with it.
        led.classify_resolved(p, 1);
        led.fail_install(p);
        assert_eq!(led.installed_via(p), Some(a));

        // Accepted: the new paths.
        led.classify_resolved(p, 1);
        led.commit_installed_via(p, Some(b));
        assert_eq!(led.installed_via(p), Some(b));

        // A hole — the derived withdrawal VPP acknowledged — holds nothing.
        led.classify_resolved(p, 0);
        assert_eq!(led.installed_via(p), None);
        // Re-installed without known paths: unknown, never the stale set.
        led.classify_resolved(p, 1);
        led.commit_installed(p);
        assert_eq!(led.installed_via(p), None);

        // A dump names prefixes, not paths; a preserved record names both.
        let dumped = v4(10, 0, 1, 0, 24);
        let kept = v4(10, 0, 2, 0, 24);
        led.adopt_installed(dumped);
        led.adopt_recorded(kept, Some(a));
        assert_eq!(led.installed_via(dumped), None);
        assert_eq!(led.installed_via(kept), Some(a));
        let entries: Vec<_> = led.installed_entries().collect();
        assert_eq!(entries, vec![(p, None), (dumped, None), (kept, Some(a))]);
        assert_eq!(led.paths_of(a), Some(&[pk(1, 3)][..]));
    }

    #[test]
    fn canonical_paths_ignore_order_and_repeats() {
        let x = pk(1, 3);
        let y = pk(2, 4);
        assert_eq!(
            canonical_paths(vec![y.clone(), x.clone(), y.clone()]),
            canonical_paths(vec![x, y])
        );
    }

    fn v6p(i: u8) -> IpPrefix {
        IpPrefix::V6 {
            addr: [0x20, 0x01, 0x0d, 0xb8, i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 32,
        }
    }

    /// Each family fills its own pool: a v6 table at its mark leaves every
    /// v4 slot free, and the v4 counts — the ones every steering gate
    /// reads — never see a v6 route.
    #[test]
    fn a_full_v6_pool_leaves_v4_its_own() {
        let mut led = RouteLedger::new(Capacity::per_family(2, 3));
        for i in 0..5 {
            led.classify_resolved(v6p(i), 1);
            led.commit_installed(v6p(i));
        }
        let v6 = led.v6_counts();
        assert_eq!((v6.installed, v6.withheld), (3, 2));
        assert_eq!(led.counts(), SinkCounts::default(), "v4 saw nothing");
        assert!(!led.has_headroom(true));
        assert!(led.has_headroom(false));
        for i in 0..3u8 {
            led.classify_resolved(v4(10, i, 0, 0, 24), 1);
            led.commit_installed(v4(10, i, 0, 0, 24));
        }
        let c = led.counts();
        assert_eq!((c.installed, c.withheld), (2, 1), "v4 stops at ITS mark");
        assert_eq!(led.v6_counts(), v6, "and v6 is untouched by it");
        assert_eq!((led.counts(), led.v6_counts()), led.counts_by_scan());
    }

    /// The v4 next-hop index the IPv4 link gate reads follows exactly the
    /// paths v4 routes are recorded holding — replaced, forgotten, and
    /// never a v6 route's.
    #[test]
    fn v4_nexthops_follow_the_recorded_v4_paths() {
        let mut led = RouteLedger::new(Capacity::new(100));
        let v6nh = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let a = led.intern_paths(&[pk(1, 3)]);
        let b = led.intern_paths(&[crate::fib_sync::installed_path_key(v6nh, 3)]);
        let p = v4(10, 0, 0, 0, 24);
        led.classify_resolved(p, 1);
        led.commit_installed_via(p, Some(a));
        led.classify_resolved(v6p(0), 1);
        led.commit_installed_via(v6p(0), Some(b));
        assert_eq!(led.v4_nexthops(), [nh(192, 0, 2, 1)].into_iter().collect());
        // Replaced through a v6 next hop (RFC 8950): the index moves.
        led.classify_resolved(p, 1);
        led.commit_installed_via(p, Some(b));
        assert_eq!(led.v4_nexthops(), [v6nh].into_iter().collect());
        led.forget(p);
        assert!(led.v4_nexthops().is_empty(), "the v6 route never counted");
        assert!(led.v4_via_refs.is_empty());
    }

    /// Only the family with headroom has its parked ops released.
    #[test]
    fn release_is_per_family() {
        let mut led = RouteLedger::new(Capacity::per_family(10, 1));
        led.classify_resolved(v6p(0), 1);
        led.commit_installed(v6p(0));
        let mut m = PendingMap::new();
        m.withhold(v6p(1), PendingOp::Withdraw);
        m.withhold(v4(10, 0, 0, 0, 24), PendingOp::Withdraw);
        assert!(led.has_headroom(false) && !led.has_headroom(true));
        assert_eq!(m.release_withheld_family(false), 1);
        assert_eq!(m.withheld_len(), 1, "the v6 op stays parked");
        assert_eq!(
            m.drain_batch(10),
            vec![(v4(10, 0, 0, 0, 24), PendingOp::Withdraw)]
        );
        assert_eq!(m.release_withheld_family(true), 1);
        assert_eq!(m.withheld_len(), 0);
        assert_eq!(m.drain_batch(10), vec![(v6p(1), PendingOp::Withdraw)]);
    }

    /// The resync skip must be able to drop an older owed op outright.
    #[test]
    fn discard_forgets_active_and_parked_ops() {
        let mut m = PendingMap::new();
        let p = v4(10, 0, 0, 0, 24);
        m.upsert(p, vec![nh(192, 0, 2, 1)]);
        m.withhold(p, PendingOp::Withdraw);
        m.discard(p);
        assert!(m.is_empty());
        assert_eq!(m.withheld_len(), 0);
    }
}
