//! The route feed: what the fast-path tier resolved, held for this one.
//!
//! One structure sits between the two tiers, written by the
//! FibProgrammer's tokio task through [`ResolvedRouteSink`] and read by
//! the supervision thread through [`crate::engine::RouteSource`]. It
//! answers both of the engine's questions from the same state:
//!
//! - **"What is the whole table?"** — a resync walk, on first attach and
//!   after every VPP restart.
//! - **"What changed since I last asked?"** — the steady-state delta,
//!   which before this had no entry point at all: the engine's pending
//!   map was written only by resync, so a route learned after convergence
//!   reached the eBPF tier and stopped there.
//!
//! ## Why deltas are a map and not a queue
//!
//! [`Inner::pending`] is keyed by prefix, so churn on one prefix collapses
//! to one entry and the structure is bounded by **table size, not event
//! rate**. A queue is the tempting shape and it fails exactly when it
//! matters: under a peering flap it grows without bound, and the usual
//! answer — drop the overflow and schedule a full resync — turns a flap
//! into a resync loop that never converges, while the tier that is
//! actually carrying traffic waits.
//!
//! `Option<SetId>` rather than two sets (changed + withdrawn), because
//! two sets can hold the same prefix and then the answer depends on which
//! one is read first. `None` is a withdrawal, and an insert overwrites,
//! so last-write-wins is the structure's behaviour rather than a rule
//! written next to it.
//!
//! ## Why nexthop sets are interned
//!
//! At the full table this holds ~1.05M prefixes. Storing a `Vec<IpAddr>`
//! per prefix is a million small heap allocations and ~100 MB; storing a
//! `u32` index into a table of distinct sets is ~40 MB and no per-route
//! allocation. The table is small because the number of distinct nexthop
//! sets is a property of the topology rather than of the table: the
//! 2026-08-02 histogram of the live table found **129 nexthops across two
//! egress devices** and zero ECMP groups.
//!
//! Nothing is ever evicted from it. Refcounting an intern table is a
//! bookkeeping problem with a silent failure mode (a set freed while a
//! prefix still names it), and the thing it would buy is bounded by that
//! same topology: each entry is a `Vec` of a handful of addresses, so even
//! a pathological ten thousand distinct sets is well under a megabyte.
//! [`RouteFeed::stats`] exports the count so growth is visible rather
//! than assumed.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;

use packetframe_common::fib::{IpPrefix, ResolvedRouteSink};

use crate::engine::{RouteSource, SourceChanges};
use crate::sink::PrefixKey;

/// Index into [`Inner::sets`].
type SetId = u32;

/// A neighbour change as the feed stores it, before device names are
/// resolved: the nexthop, and its (MAC, kernel ifindex) or `None`.
type RawNeighChange = (IpAddr, Option<([u8; 6], u32)>);

/// How many prefixes one lock acquisition copies out during a full-table
/// walk.
///
/// The walk cannot hold the lock throughout: the writer is the
/// FibProgrammer's task, i.e. the control plane of the tier carrying
/// production traffic, and a full-table copy takes long enough to be a
/// visible stall in BGP convergence. Chunking bounds what a writer can
/// ever wait for to one chunk's copy.
///
/// The cost of chunking is that the walk is not a coherent snapshot — a
/// prefix can change after its chunk was copied. That is already the
/// engine's normal condition (resync queues into the same prefix-keyed
/// pending map that live deltas write, so the newer intent wins), which
/// is what makes chunking free here rather than a correctness trade.
const WALK_CHUNK: usize = 8192;

/// Observable size of the feed, for health and metrics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FeedStats {
    pub routes: u64,
    /// Deltas the engine has not drained yet. Steady state is ~0; a
    /// sustained non-zero means the engine is not keeping up with the
    /// route source, which is a different fault from VPP being slow.
    pub pending: u64,
    pub neighbours: u64,
    /// Neighbour changes the engine has not drained yet.
    pub pending_neighbours: u64,
    /// Distinct nexthop sets interned. Expected to sit near the
    /// topology's shape (129 nexthops / 2 devices as measured); an
    /// order-of-magnitude departure means the assumption behind
    /// never-evicting has stopped holding.
    pub nexthop_sets: u64,
}

#[derive(Default)]
struct Inner {
    /// The authoritative mirror: every prefix the other tier resolved.
    routes: BTreeMap<PrefixKey, SetId>,
    /// Interned nexthop sets, indexed by [`SetId`]. Append-only.
    sets: Vec<Vec<IpAddr>>,
    /// Reverse index for interning. Keyed by the set itself, which is
    /// already sorted and deduplicated by the programmer — so equal sets
    /// are equal `Vec`s and no canonicalisation is needed here.
    set_ids: HashMap<Vec<IpAddr>, SetId>,
    /// Prefix → new state, or `None` for withdrawn. See the module docs.
    pending: BTreeMap<PrefixKey, Option<SetId>>,
    /// Nexthop → (MAC, kernel egress ifindex). Names are resolved on the
    /// read path, not here: `if_indextoname` is a socket-and-ioctl on
    /// glibc, and this runs on the other tier's task.
    neighbours: HashMap<IpAddr, ([u8; 6], u32)>,
    /// Neighbour → new state, or `None` for lost. Same shape and the same
    /// reason as `pending`.
    ///
    /// Carried as deltas rather than re-walked, because the alternative
    /// is a full neighbour refresh on every tick that has route changes —
    /// ~129 entries and an `if_indextoname` each, repeatedly, to discover
    /// that nothing moved. And it cannot simply be skipped: a route delta
    /// naming a nexthop the engine's map has never seen classifies
    /// **unresolvable**, so without this a genuinely new nexthop would
    /// black-hole its routes until the next full resync.
    neigh_pending: HashMap<IpAddr, Option<([u8; 6], u32)>>,
}

impl Inner {
    fn intern(&mut self, nexthops: &[IpAddr]) -> SetId {
        if let Some(id) = self.set_ids.get(nexthops) {
            return *id;
        }
        let id = self.sets.len() as SetId;
        self.sets.push(nexthops.to_vec());
        self.set_ids.insert(nexthops.to_vec(), id);
        id
    }
}

/// Shared between the two tiers. Cheap to clone the `Arc`; the lock is
/// held only for map operations and bounded copies.
#[derive(Default)]
pub struct RouteFeed {
    inner: Mutex<Inner>,
}

impl RouteFeed {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> FeedStats {
        let g = self.lock();
        FeedStats {
            routes: g.routes.len() as u64,
            pending: g.pending.len() as u64,
            neighbours: g.neighbours.len() as u64,
            pending_neighbours: g.neigh_pending.len() as u64,
            nexthop_sets: g.sets.len() as u64,
        }
    }

    /// `PoisonError` cannot mean what it usually means here.
    ///
    /// Every critical section is a map insert or a bounded copy, with no
    /// `?`, no user callback, and nothing that can panic while the lock is
    /// held — so a poisoned lock would mean a panic somewhere that cannot
    /// panic. Recovering the guard keeps a bug in this file from taking
    /// out the other tier's control plane, which is the one thing this
    /// seam must never do.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl ResolvedRouteSink for RouteFeed {
    fn route_resolved(&self, prefix: IpPrefix, nexthops: &[IpAddr]) {
        let mut g = self.lock();
        let id = g.intern(nexthops);
        let key = PrefixKey::from(prefix);
        g.routes.insert(key, id);
        g.pending.insert(key, Some(id));
    }

    fn route_withdrawn(&self, prefix: IpPrefix) {
        let mut g = self.lock();
        let key = PrefixKey::from(prefix);
        g.routes.remove(&key);
        // Queued even when the mirror held nothing. A withdrawal for a
        // prefix this feed never saw still has to reach the engine: the
        // engine's ledger is populated by resync as well as by these
        // deltas, so it can hold prefixes the mirror has already lost, and
        // swallowing the withdrawal here would leave one installed in VPP
        // with nothing left to withdraw it.
        g.pending.insert(key, None);
    }

    fn neighbour_resolved(&self, nh: IpAddr, mac: [u8; 6], ifindex: u32) {
        let mut g = self.lock();
        g.neighbours.insert(nh, (mac, ifindex));
        g.neigh_pending.insert(nh, Some((mac, ifindex)));
    }

    fn neighbour_lost(&self, nh: IpAddr) {
        let mut g = self.lock();
        g.neighbours.remove(&nh);
        // Queued even if the map held nothing, for the same reason a
        // withdrawal is: the engine's nexthop map is filled by resync too,
        // so it can know a mapping this feed has already dropped.
        g.neigh_pending.insert(nh, None);
    }
}

impl RouteSource for RouteFeed {
    fn drain_changes(&self, max: usize) -> SourceChanges {
        // Neighbours are taken whole rather than bounded: there are ~129
        // of them against ~1.05M routes, so a cap would add a resumption
        // path for a set that cannot produce a batch worth resuming.
        let (neigh_raw, routes) = {
            let mut g = self.lock();
            let neigh: Vec<RawNeighChange> = g.neigh_pending.drain().collect();
            let keys: Vec<PrefixKey> = g.pending.keys().take(max).copied().collect();
            let mut routes = Vec::with_capacity(keys.len());
            for k in keys {
                let Some(state) = g.pending.remove(&k) else {
                    continue;
                };
                let nhs = state.map(|id| g.sets[id as usize].clone());
                routes.push((IpPrefix::from(k), nhs));
            }
            (neigh, routes)
        };
        // Names resolved after the lock is dropped: `if_indextoname` is a
        // syscall, and the writer is the other tier's task.
        let neighbours = neigh_raw
            .into_iter()
            .map(|(ip, state)| {
                let resolved = state.and_then(|(mac, idx)| {
                    // A link that vanished between the notification and
                    // here reads as a loss, not as a name we invented.
                    if_indextoname(idx).map(|dev| (dev, mac))
                });
                (ip, resolved)
            })
            .collect();
        SourceChanges { routes, neighbours }
    }

    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        // Chunked so the writer never waits for more than `WALK_CHUNK`
        // copies. `after` is the resume cursor; a prefix inserted below it
        // mid-walk is missed by this pass and picked up as a pending
        // delta, which is the same path every other live change takes.
        let mut after: Option<PrefixKey> = None;
        loop {
            let chunk: Vec<(PrefixKey, Vec<IpAddr>)> = {
                let g = self.lock();
                let lower = match after {
                    Some(k) => std::ops::Bound::Excluded(k),
                    None => std::ops::Bound::Unbounded,
                };
                g.routes
                    .range((lower, std::ops::Bound::Unbounded))
                    .take(WALK_CHUNK)
                    .map(|(k, id)| (*k, g.sets[*id as usize].clone()))
                    .collect()
            };
            if chunk.is_empty() {
                return;
            }
            after = Some(chunk[chunk.len() - 1].0);
            for (k, nhs) in chunk {
                visit(k.into(), &nhs);
            }
        }
    }

    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        // Copied out first, then resolved: `if_indextoname` is a syscall,
        // and doing it under the lock would hold the other tier's task
        // behind one per neighbour for no reason.
        let snapshot: Vec<(IpAddr, [u8; 6], u32)> = {
            let g = self.lock();
            g.neighbours
                .iter()
                .map(|(ip, (mac, idx))| (*ip, *mac, *idx))
                .collect()
        };
        for (ip, mac, ifindex) in snapshot {
            // A vanished link is skipped rather than reported with a
            // placeholder name: the caller matches the device against the
            // configured ports, and an unresolvable name can only produce
            // a wrong match or a confusing one. The neighbour is unusable
            // either way, and its loss arrives as `neighbour_lost`.
            if let Some(dev) = if_indextoname(ifindex) {
                visit(ip, &dev, mac);
            }
        }
    }
}

/// So the loader can hand the *same* feed to both tiers.
///
/// The programmer needs an `Arc<dyn ResolvedRouteSink>` and the engine
/// needs a `Box<dyn RouteSource>`; without this the second one would have
/// to be a separate object, and two objects is two mirrors — the engine
/// would resync from a table nothing was writing to.
impl RouteSource for std::sync::Arc<RouteFeed> {
    fn drain_changes(&self, max: usize) -> SourceChanges {
        (**self).drain_changes(max)
    }
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        (**self).for_each_route(visit)
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        (**self).for_each_neighbour(visit)
    }
}

/// Kernel interface name for `ifindex`, or `None` if the link is gone.
fn if_indextoname(ifindex: u32) -> Option<String> {
    // IF_NAMESIZE, which `if_indextoname` requires the buffer to be.
    let mut buf = [0u8; 16];
    // SAFETY: `buf` is IF_NAMESIZE bytes as the call requires, and it
    // writes a NUL-terminated name or returns null.
    let rc = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
    if rc.is_null() {
        return None;
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).ok().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(a: u8, b: u8) -> IpPrefix {
        IpPrefix::V4 {
            addr: [a, b, 0, 0],
            prefix_len: 16,
        }
    }

    fn nh(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    /// Churn on one prefix collapses to one delta. This is the property
    /// that makes the feed bounded by table size instead of event rate,
    /// so it is asserted as a count rather than inferred from the shape.
    #[test]
    fn churn_on_one_prefix_collapses_to_one_delta() {
        let f = RouteFeed::new();
        for i in 0..100u8 {
            f.route_resolved(v4(192, 0), &[nh(i)]);
        }
        assert_eq!(f.stats().pending, 1, "100 updates, one pending delta");
        let drained = f.drain_changes(64).routes;
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0], (v4(192, 0), Some(vec![nh(99)])), "newest wins");
        assert_eq!(f.stats().pending, 0, "drain removes what it returned");
    }

    /// A withdrawal after an upsert replaces it, and vice versa — the
    /// direction that is easy to get backwards is the second one, where a
    /// stale withdrawal must not survive a fresh install.
    #[test]
    fn the_newest_intent_wins_in_both_directions() {
        let f = RouteFeed::new();

        f.route_resolved(v4(198, 18), &[nh(1)]);
        f.route_withdrawn(v4(198, 18));
        assert_eq!(
            f.drain_changes(64).routes,
            vec![(v4(198, 18), None)],
            "withdraw wins"
        );
        assert_eq!(f.stats().routes, 0, "and leaves the mirror");

        f.route_withdrawn(v4(198, 19));
        f.route_resolved(v4(198, 19), &[nh(2)]);
        assert_eq!(
            f.drain_changes(64).routes,
            vec![(v4(198, 19), Some(vec![nh(2)]))],
            "a fresh install must displace a queued withdrawal"
        );
        assert_eq!(f.stats().routes, 1);
    }

    /// A withdrawal for a prefix the feed never held is still queued.
    ///
    /// The engine's ledger is filled by resync as well as by deltas, so it
    /// can hold prefixes this mirror has already dropped. Swallowing the
    /// withdrawal as "nothing to do" would leave that one installed in
    /// VPP with nothing left to remove it.
    #[test]
    fn a_withdrawal_for_an_unknown_prefix_still_reaches_the_engine() {
        let f = RouteFeed::new();
        f.route_withdrawn(v4(203, 0));
        assert_eq!(f.drain_changes(64).routes, vec![(v4(203, 0), None)]);
    }

    /// `drain` is bounded and resumes in key order.
    #[test]
    fn drain_is_bounded_and_ordered() {
        let f = RouteFeed::new();
        for i in 0..10u8 {
            f.route_resolved(v4(10, i), &[nh(1)]);
        }
        let first = f.drain_changes(4).routes;
        assert_eq!(first.len(), 4);
        assert_eq!(first[0].0, v4(10, 0), "key order, lowest first");
        assert_eq!(f.stats().pending, 6, "the rest stay queued");
        assert_eq!(f.drain_changes(100).routes.len(), 6);
        assert!(f.drain_changes(100).routes.is_empty());
    }

    /// Equal nexthop sets share one intern entry; distinct ones do not.
    /// The count is the assertion because the memory argument for the
    /// whole design rests on it.
    #[test]
    fn equal_nexthop_sets_are_interned_once() {
        let f = RouteFeed::new();
        for i in 0..50u8 {
            f.route_resolved(v4(172, i), &[nh(1), nh(2)]);
        }
        assert_eq!(
            f.stats().nexthop_sets,
            1,
            "50 prefixes over the same pair of nexthops is one set"
        );
        f.route_resolved(v4(172, 200), &[nh(1)]);
        assert_eq!(f.stats().nexthop_sets, 2, "a different set is a new entry");
        // Order matters for identity, and that is correct rather than a
        // gap: the programmer hands over sorted, deduplicated unions, so
        // two orderings of the same addresses cannot both arrive.
        assert_eq!(f.stats().routes, 51);
    }

    /// The full-table walk visits every prefix exactly once, across more
    /// chunks than one.
    #[test]
    fn the_walk_covers_the_table_across_chunk_boundaries() {
        let f = RouteFeed::new();
        let total = WALK_CHUNK * 2 + 7;
        for i in 0..total {
            f.route_resolved(
                IpPrefix::V4 {
                    addr: (i as u32).to_be_bytes(),
                    prefix_len: 32,
                },
                &[nh(1)],
            );
        }
        let mut seen = std::collections::HashSet::new();
        let mut count = 0usize;
        f.for_each_route(&mut |p, nhs| {
            assert_eq!(nhs, [nh(1)]);
            assert!(seen.insert(p), "{p:?} visited twice");
            count += 1;
        });
        assert_eq!(count, total, "every prefix visited once");
    }

    /// The walk terminates on an empty table rather than spinning on the
    /// resume cursor.
    #[test]
    fn the_walk_terminates_on_an_empty_table() {
        let f = RouteFeed::new();
        let mut count = 0;
        f.for_each_route(&mut |_, _| count += 1);
        assert_eq!(count, 0);
    }

    /// Neighbour resolution and loss are reflected in what the walk
    /// reports. Loopback is used because it is the one ifindex a test can
    /// rely on existing.
    #[test]
    fn neighbours_appear_and_disappear() {
        let f = RouteFeed::new();
        let lo = some_real_ifindex();
        let mac = [2, 0, 0, 0, 0, 1];
        f.neighbour_resolved(nh(1), mac, lo);
        let mut seen = Vec::new();
        f.for_each_neighbour(&mut |ip, dev, m| seen.push((ip, dev.to_string(), m)));
        assert_eq!(seen.len(), 1, "the resolved neighbour is reported");
        assert_eq!(seen[0].0, nh(1));
        assert_eq!(seen[0].2, mac);
        assert!(!seen[0].1.is_empty(), "with a device name");

        f.neighbour_lost(nh(1));
        let mut after = 0;
        f.for_each_neighbour(&mut |_, _, _| after += 1);
        assert_eq!(after, 0);
    }

    /// A neighbour whose link is gone is skipped, not reported with a
    /// placeholder device.
    #[test]
    fn a_neighbour_on_a_vanished_link_is_skipped() {
        let f = RouteFeed::new();
        // No kernel assigns this ifindex; `if_indextoname` fails.
        f.neighbour_resolved(nh(1), [2, 0, 0, 0, 0, 1], u32::MAX);
        let mut seen = 0;
        f.for_each_neighbour(&mut |_, _, _| seen += 1);
        assert_eq!(seen, 0, "an unresolvable device name is not guessed at");
        assert_eq!(
            f.stats().neighbours,
            1,
            "but it stays recorded — the walk skipping it is not a delete"
        );
    }

    /// Any ifindex this host will resolve to a name.
    ///
    /// Found by scanning rather than by naming loopback: `lo` on Linux is
    /// `lo0` on macOS, and this file is not Linux-gated, so hard-coding
    /// either one makes the test pass on one dev box and fail on the
    /// other. Index 1 is loopback on both by convention, but scanning
    /// does not need the convention to hold.
    fn some_real_ifindex() -> u32 {
        (1..=16)
            .find(|i| if_indextoname(*i).is_some())
            .expect("a host with no interfaces at index 1..16")
    }
}
