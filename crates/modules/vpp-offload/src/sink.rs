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
//! and conflating them would hide whichever is rarer.

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

/// Three-valued route state. See the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteState {
    Installed,
    NotInstalled(NotInstalled),
}

/// Per-state totals, exported as `packetframe_vpp_*` gauges and folded
/// into the readback-verify pass criteria.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SinkCounts {
    pub installed: u64,
    pub withheld: u64,
    pub unresolvable: u64,
}

impl SinkCounts {
    /// `unresolvable > 0` is Degraded health and **blocks first-attach
    /// steering**: if we cannot install the table, we must not divert
    /// traffic into it. Withheld routes are a softer signal — the table
    /// is incomplete but what is installed is correct — so they alarm
    /// without blocking.
    pub fn blocks_first_steer(&self) -> bool {
        self.unresolvable > 0
    }

    pub fn degraded(&self) -> bool {
        self.unresolvable > 0 || self.withheld > 0
    }
}

/// Capacity policy. The high-water mark is derived from the **measured**
/// VPP heap gauge, never from the configured `expected-routes` — that
/// number is a sizing input, and reusing it as a runtime ceiling would
/// be the same static guess wearing a second hat. Above the mark the
/// sink withholds rather than installing, so DFZ growth (~100k
/// routes/yr) degrades to "table-incomplete + alarming" instead of a
/// heap-exhaustion crash loop.
#[derive(Debug, Clone, Copy)]
pub struct Capacity {
    high_water_routes: u64,
}

impl Capacity {
    pub fn new(high_water_routes: u64) -> Self {
        Self { high_water_routes }
    }

    fn has_headroom(&self, installed: u64) -> bool {
        installed < self.high_water_routes
    }
}

/// Where a nexthop's egress device lands in VPP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NexthopTarget {
    /// A member port's VF — the ordinary case.
    Vf { port: String },
    /// A VLAN nexthop (the br1337 / FDB-pin topology) → VPP sub-interface
    /// on the member VF.
    Subif { port: String, vlan: u16 },
}

/// Kernel-device → VPP-interface policy. Devices that are neither a
/// member port nor a known VLAN nexthop (management, tunnels) are
/// **explicitly excluded** rather than guessed at, and every route
/// resolving only through them counts as `Unresolvable`.
#[derive(Debug, Clone, Default)]
pub struct NexthopMap {
    /// Nexthop address → egress device, learned from the NeighborResolver.
    device_of: BTreeMap<IpAddr, String>,
    /// Member ports (the `port` config lines).
    members: Vec<String>,
    /// VLAN device name → (underlying member port, vid).
    vlans: BTreeMap<String, (String, u16)>,
}

impl NexthopMap {
    pub fn new(members: Vec<String>) -> Self {
        Self {
            members,
            ..Default::default()
        }
    }

    /// Register a VLAN device as a sub-interface of a member port.
    pub fn add_vlan(&mut self, dev: impl Into<String>, port: impl Into<String>, vid: u16) {
        self.vlans.insert(dev.into(), (port.into(), vid));
    }

    /// Record which device a nexthop address egresses through. Fed by
    /// the NeighborResolver, the same source that supplies VPP's static
    /// neighbors.
    pub fn set_device(&mut self, nexthop: IpAddr, dev: impl Into<String>) {
        self.device_of.insert(nexthop, dev.into());
    }

    /// Resolve one nexthop, or `None` if its device is excluded.
    pub fn resolve(&self, nexthop: &IpAddr) -> Option<NexthopTarget> {
        let dev = self.device_of.get(nexthop)?;
        if let Some((port, vlan)) = self.vlans.get(dev) {
            // A VLAN whose underlying port was never made a member is
            // still excluded: the subif has nothing to sit on.
            return self
                .members
                .iter()
                .any(|m| m == port)
                .then(|| NexthopTarget::Subif {
                    port: port.clone(),
                    vlan: *vlan,
                });
        }
        self.members
            .iter()
            .any(|m| m == dev)
            .then(|| NexthopTarget::Vf { port: dev.clone() })
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

    /// Record an install/replace. Overwrites any pending op for this
    /// prefix, including a pending withdrawal (the newer intent wins).
    pub fn upsert(&mut self, prefix: IpPrefix, nexthops: Vec<IpAddr>) {
        self.ops
            .insert(prefix.into(), PendingOp::Upsert { nexthops });
    }

    /// Record a withdrawal, overwriting any pending upsert.
    pub fn withdraw(&mut self, prefix: IpPrefix) {
        self.ops.insert(prefix.into(), PendingOp::Withdraw);
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

    /// Re-queue an op the transport could not apply — but only if the
    /// prefix has not been superseded in the meantime. A newer event
    /// that arrived while the batch was in flight is the current intent
    /// and must not be clobbered by the stale retry.
    pub fn requeue(&mut self, prefix: IpPrefix, op: PendingOp) {
        self.ops.entry(prefix.into()).or_insert(op);
    }
}

/// Tracks which prefixes are installed / withheld / unresolvable and
/// decides what each pending op should become.
#[derive(Debug)]
pub struct RouteLedger {
    state: BTreeMap<PrefixKey, RouteState>,
    capacity: Capacity,
}

impl RouteLedger {
    pub fn new(capacity: Capacity) -> Self {
        Self {
            state: BTreeMap::new(),
            capacity,
        }
    }

    pub fn state_of(&self, prefix: IpPrefix) -> Option<RouteState> {
        self.state.get(&prefix.into()).copied()
    }

    pub fn counts(&self) -> SinkCounts {
        let mut c = SinkCounts::default();
        for st in self.state.values() {
            match st {
                RouteState::Installed => c.installed += 1,
                RouteState::NotInstalled(NotInstalled::Withheld) => c.withheld += 1,
                RouteState::NotInstalled(NotInstalled::Unresolvable) => c.unresolvable += 1,
            }
        }
        c
    }

    fn installed_count(&self) -> u64 {
        self.state
            .values()
            .filter(|s| matches!(s, RouteState::Installed))
            .count() as u64
    }

    /// Decide the outcome of an upsert. Resolution is checked *before*
    /// capacity: a route with no VPP-reachable nexthop is unresolvable
    /// whether or not there is headroom, and calling it `Withheld` would
    /// make it retry forever on every capacity change.
    pub fn classify_upsert(
        &mut self,
        prefix: IpPrefix,
        nexthops: &[IpAddr],
        map: &NexthopMap,
    ) -> (RouteState, Vec<NexthopTarget>) {
        let targets = map.resolve_all(nexthops);
        let key = PrefixKey::from(prefix);
        if targets.is_empty() {
            let st = RouteState::NotInstalled(NotInstalled::Unresolvable);
            self.state.insert(key, st);
            return (st, targets);
        }
        // An already-installed prefix keeps its slot on replace — a
        // route update must not be withheld just because the table sits
        // at the mark, or steady-state churn would silently erode the
        // installed set.
        let already = matches!(self.state.get(&key), Some(RouteState::Installed));
        if already || self.capacity.has_headroom(self.installed_count()) {
            self.state.insert(key, RouteState::Installed);
            (RouteState::Installed, targets)
        } else {
            let st = RouteState::NotInstalled(NotInstalled::Withheld);
            self.state.insert(key, st);
            (st, targets)
        }
    }

    /// Forget a prefix on withdrawal.
    pub fn forget(&mut self, prefix: IpPrefix) {
        self.state.remove(&prefix.into());
    }

    /// Prefixes eligible for retry once headroom returns. Excludes
    /// `Unresolvable` — no amount of capacity fixes a mapping — so the
    /// retry set stays proportional to real headroom.
    pub fn withheld_prefixes(&self) -> Vec<IpPrefix> {
        self.state
            .iter()
            .filter(|(_, st)| **st == RouteState::NotInstalled(NotInstalled::Withheld))
            .map(|(k, _)| (*k).into())
            .collect()
    }

    /// Sampling pool for readback verification: only prefixes that
    /// *should* be in VPP's FIB. Verifying against withheld or
    /// unresolvable prefixes would fail by design.
    pub fn verifiable_prefixes(&self) -> Vec<IpPrefix> {
        self.state
            .iter()
            .filter(|(_, st)| **st == RouteState::Installed)
            .map(|(k, _)| (*k).into())
            .collect()
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
        let mut m = member_map();
        m.add_vlan("br1337", "eth4", 1337);
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
        let mut orphan = NexthopMap::new(vec!["eth5".into()]);
        orphan.add_vlan("br1337", "eth4", 1337);
        orphan.set_device(nh(192, 0, 2, 20), "br1337");
        assert_eq!(orphan.resolve(&nh(192, 0, 2, 20)), None);
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

    #[test]
    fn installs_are_withheld_above_the_high_water_mark() {
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(2));
        for i in 0..4u8 {
            led.classify_upsert(v4(10, i, 0, 0, 16), &[nh(192, 0, 2, 1)], &map);
        }
        let c = led.counts();
        assert_eq!(c.installed, 2);
        assert_eq!(c.withheld, 2);
        assert_eq!(led.withheld_prefixes().len(), 2);
    }

    #[test]
    fn replacing_an_installed_route_at_the_mark_keeps_it_installed() {
        // Steady-state churn at capacity must not erode the installed
        // set — a route update is not a new allocation.
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(1));
        let p = v4(10, 0, 0, 0, 8);
        led.classify_upsert(p, &[nh(192, 0, 2, 1)], &map);
        assert_eq!(led.state_of(p), Some(RouteState::Installed));
        led.classify_upsert(p, &[nh(192, 0, 2, 2)], &map);
        assert_eq!(led.state_of(p), Some(RouteState::Installed));
        assert_eq!(led.counts().installed, 1);
    }

    #[test]
    fn withdrawal_frees_headroom_for_a_withheld_route() {
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(1));
        let a = v4(10, 0, 0, 0, 8);
        let b = v4(10, 1, 0, 0, 16);
        led.classify_upsert(a, &[nh(192, 0, 2, 1)], &map);
        led.classify_upsert(b, &[nh(192, 0, 2, 1)], &map);
        assert_eq!(led.counts().withheld, 1);

        led.forget(a);
        led.classify_upsert(b, &[nh(192, 0, 2, 1)], &map);
        assert_eq!(led.counts().installed, 1);
        assert_eq!(led.counts().withheld, 0);
    }

    #[test]
    fn unresolvable_blocks_first_steer_but_withheld_only_alarms() {
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(1));
        led.classify_upsert(v4(10, 0, 0, 0, 8), &[nh(192, 0, 2, 1)], &map);
        led.classify_upsert(v4(10, 1, 0, 0, 16), &[nh(192, 0, 2, 1)], &map);
        let c = led.counts();
        assert!(!c.blocks_first_steer(), "withheld alone must not block");
        assert!(c.degraded(), "but it is still degraded");

        led.classify_upsert(v4(10, 2, 0, 0, 16), &[nh(192, 0, 2, 9)], &map);
        assert!(led.counts().blocks_first_steer());
    }

    #[test]
    fn verify_pool_contains_only_installed_prefixes() {
        let map = member_map();
        let mut led = RouteLedger::new(Capacity::new(1));
        let good = v4(10, 0, 0, 0, 8);
        led.classify_upsert(good, &[nh(192, 0, 2, 1)], &map);
        led.classify_upsert(v4(10, 1, 0, 0, 16), &[nh(192, 0, 2, 1)], &map); // withheld
        led.classify_upsert(v4(10, 2, 0, 0, 16), &[nh(192, 0, 2, 9)], &map); // unresolvable
        assert_eq!(led.verifiable_prefixes(), vec![good]);
    }
}
