//! Nexthops that are the router's own addresses.
//!
//! A routing daemon feeding the BGP listener sends what it originates —
//! `redistribute connected` and `static` above all — with its own session
//! address as NEXT_HOP (and `elem_to_route_event` falls back to the
//! listen address when bird sends none). The kernel never resolves a
//! neighbour for its own address, so such a nexthop stays `Incomplete`
//! for as long as a route uses it, and XDP PASSes its traffic to the
//! kernel (`fib_no_neigh`) — which is exactly right: the kernel delivers
//! those prefixes, or routes them on.
//!
//! What was wrong is the reporting. The programmer armed a re-probe for
//! every one of them and counted them in the once-a-minute "nexthops
//! awaiting resolution" line as pending and, after a minute, chronic: a
//! line that fired every minute forever on a healthy box and read as a
//! fault. Here they are classified `local` instead, kept out of the
//! re-probe schedule and its summary, and named once in the journal
//! when the set changes.
//!
//! **Reporting only.** Nothing written to the BPF maps changes: the slot
//! stays seeded `Incomplete`, the datapath still PASSes, and the map
//! layout and the stats counters are untouched (CLAUDE.md, append-only
//! counters). Ungated, like `integrity_status`, so the classification is
//! tested on a macOS dev loop; only the address read is Linux's.

use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;

/// The router's own addresses, and which registered nexthops are among
/// them.
#[derive(Debug, Default)]
pub struct LocalNexthops {
    /// Every address the kernel holds, as last read.
    addrs: HashSet<IpAddr>,
    /// Registered nexthops that are in `addrs`. Ordered, so the journal
    /// line names them the same way every time.
    local: BTreeSet<IpAddr>,
}

/// What a re-read of the router's addresses changed about the registered
/// nexthops ([`LocalNexthops::set_addrs`]).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LocalChange {
    /// Registered nexthops that are the router's own now and were not:
    /// their re-probe is owed nothing any more.
    pub became_local: Vec<IpAddr>,
    /// Registered nexthops that were the router's own and are not now
    /// (the address moved off the box): owed a resolve and a re-probe
    /// like any other nexthop.
    pub stopped_local: Vec<IpAddr>,
}

impl LocalChange {
    pub fn is_empty(&self) -> bool {
        self.became_local.is_empty() && self.stopped_local.is_empty()
    }

    /// What the programmer owes the slots this change moved, in order.
    ///
    /// A nexthop that became the router's own may be RESOLVED right now —
    /// an address takeover moves a neighbour's address onto the box — and
    /// its slot then still rewrites and redirects to the former neighbour.
    /// `local` promises the kernel path, so the slot and the cached live
    /// state go back to `Incomplete` (the datapath PASSes), and the second
    /// tier hears the neighbour is gone (review finding). The reverse is
    /// an ordinary unresolved nexthop: ask the resolver, arm the re-probe.
    pub fn actions(&self) -> Vec<SlotAction> {
        self.became_local
            .iter()
            .map(|ip| SlotAction::ForgetResolution(*ip))
            .chain(self.stopped_local.iter().map(|ip| SlotAction::Resolve(*ip)))
            .collect()
    }
}

/// One slot's due after a reclassification ([`LocalChange::actions`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotAction {
    /// Write the slot `Incomplete`, drop the cached live resolution and
    /// any re-probe, and tell the second tier the neighbour is lost.
    ForgetResolution(IpAddr),
    /// Hand the nexthop to the resolver and arm its re-probe.
    Resolve(IpAddr),
}

/// What to do with a neighbour event ([`LocalNexthops::neigh_event`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighVerdict {
    Apply,
    /// The nexthop is the router's own: whatever the kernel says about a
    /// neighbour at that address is stale or about another entry, and
    /// applying a `Learned` would put a redirect back into a slot the
    /// `local` classification reset to the kernel path.
    IgnoreLocal,
}

impl LocalNexthops {
    pub fn new(addrs: HashSet<IpAddr>) -> Self {
        Self {
            addrs,
            local: BTreeSet::new(),
        }
    }

    /// Record a newly registered nexthop. `true` when it is the router's
    /// own — the caller then neither asks the resolver about it nor arms
    /// a re-probe.
    pub fn register(&mut self, ip: IpAddr) -> bool {
        if self.addrs.contains(&ip) {
            self.local.insert(ip);
            true
        } else {
            false
        }
    }

    /// Forget a nexthop whose last route went.
    pub fn unregister(&mut self, ip: &IpAddr) {
        self.local.remove(ip);
    }

    pub fn is_local(&self, ip: &IpAddr) -> bool {
        self.local.contains(ip)
    }

    /// Whether a neighbour event for `ip` may touch its slot. A `Learned`
    /// already in flight when the address moved onto the box lands after
    /// the reset; it is dropped here for as long as the nexthop is local.
    pub fn neigh_event(&self, ip: &IpAddr) -> NeighVerdict {
        if self.is_local(ip) {
            NeighVerdict::IgnoreLocal
        } else {
            NeighVerdict::Apply
        }
    }

    /// The registered nexthops that are the router's own, in order.
    pub fn local(&self) -> impl Iterator<Item = &IpAddr> {
        self.local.iter()
    }

    pub fn len(&self) -> usize {
        self.local.len()
    }

    pub fn is_empty(&self) -> bool {
        self.local.is_empty()
    }

    /// Take a fresh read of the router's addresses and reclassify every
    /// registered nexthop against it. An address added to the box after
    /// its nexthop was registered moves it to `local`; one removed moves
    /// it back.
    pub fn set_addrs(
        &mut self,
        addrs: HashSet<IpAddr>,
        registered: impl IntoIterator<Item = IpAddr>,
    ) -> LocalChange {
        self.addrs = addrs;
        let mut change = LocalChange::default();
        let now: BTreeSet<IpAddr> = registered
            .into_iter()
            .filter(|ip| self.addrs.contains(ip))
            .collect();
        change.became_local = now.difference(&self.local).copied().collect();
        change.stopped_local = self.local.difference(&now).copied().collect();
        self.local = now;
        change
    }
}

/// `(pending, chronic)` for the "nexthops awaiting resolution" summary:
/// re-probes outstanding, and those past `chronic_after` attempts —
/// excluding the router's own addresses, which are not awaiting anything.
/// The programmer never arms a re-probe for one, so this exclusion is the
/// second line, for a nexthop that became local while armed.
pub fn awaiting_summary<'a>(
    attempts: impl IntoIterator<Item = (&'a IpAddr, u32)>,
    local: &LocalNexthops,
    chronic_after: u32,
) -> (usize, usize) {
    let mut pending = 0;
    let mut chronic = 0;
    for (ip, n) in attempts {
        if local.is_local(ip) {
            continue;
        }
        pending += 1;
        if n >= chronic_after {
            chronic += 1;
        }
    }
    (pending, chronic)
}

/// Every address the kernel holds, from `getifaddrs`, both families.
/// Empty on a failed read, which classifies nothing as local — the
/// pre-existing behaviour, noisy but never wrong about traffic.
#[cfg(target_os = "linux")]
pub fn kernel_local_addrs() -> HashSet<IpAddr> {
    kernel_addrs_by_iface()
        .into_iter()
        .map(|(_, addr)| addr)
        .collect()
}

/// Every address the kernel holds with the interface holding it, from
/// `getifaddrs`, both families. Empty on a failed read.
#[cfg(target_os = "linux")]
pub fn kernel_addrs_by_iface() -> Vec<(String, IpAddr)> {
    let mut out = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs allocates the list; freed below on every path
    // that saw a zero return.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return out;
    }
    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: walking the list getifaddrs returned, until null.
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: non-null; the family decides the layout read below.
            let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });
            let addr = if family == libc::AF_INET {
                // SAFETY: AF_INET guarantees sockaddr_in layout.
                let raw = unsafe {
                    (*(ifa.ifa_addr as *const libc::sockaddr_in))
                        .sin_addr
                        .s_addr
                };
                Some(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(raw))))
            } else if family == libc::AF_INET6 {
                // SAFETY: AF_INET6 guarantees sockaddr_in6 layout.
                let raw = unsafe {
                    (*(ifa.ifa_addr as *const libc::sockaddr_in6))
                        .sin6_addr
                        .s6_addr
                };
                Some(IpAddr::V6(std::net::Ipv6Addr::from(raw)))
            } else {
                None
            };
            if let Some(addr) = addr {
                // SAFETY: getifaddrs gives every entry a NUL-terminated name.
                let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                    .to_string_lossy()
                    .into_owned();
                out.push((name, addr));
            }
        }
        cur = ifa.ifa_next;
    }
    // SAFETY: the list came from a successful getifaddrs.
    unsafe { libc::freeifaddrs(ifap) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, d))
    }

    fn addrs(ds: &[u8]) -> HashSet<IpAddr> {
        ds.iter().map(|d| ip(*d)).collect()
    }

    /// The router's own address is `local` and kept out of the
    /// awaiting-resolution summary; a real neighbour that has not
    /// resolved is still pending, and still chronic after a minute.
    #[test]
    fn own_addresses_are_local_and_not_awaiting_resolution() {
        let mut l = LocalNexthops::new(addrs(&[1]));
        assert!(l.register(ip(1)), "the router's own address");
        assert!(!l.register(ip(7)), "a peer");
        assert!(l.is_local(&ip(1)) && !l.is_local(&ip(7)));
        assert_eq!(l.local().copied().collect::<Vec<_>>(), vec![ip(1)]);

        // Both armed (as a pre-fix programmer would have): only the peer
        // counts, and it is chronic past the threshold.
        let armed = [(ip(1), 9u32), (ip(7), 9u32)];
        let (pending, chronic) = awaiting_summary(armed.iter().map(|(i, n)| (i, *n)), &l, 6);
        assert_eq!((pending, chronic), (1, 1));

        // Only local nexthops outstanding: nothing awaits resolution, so
        // the per-minute line has nothing to say.
        let only_local = [(ip(1), 9u32)];
        assert_eq!(
            awaiting_summary(only_local.iter().map(|(i, n)| (i, *n)), &l, 6),
            (0, 0)
        );

        l.unregister(&ip(1));
        assert!(!l.is_local(&ip(1)) && l.is_empty());
    }

    /// An address added to the box after its nexthop registered makes the
    /// nexthop local; one removed hands it back to resolution.
    #[test]
    fn a_re_read_moves_nexthops_both_ways() {
        let mut l = LocalNexthops::new(addrs(&[1]));
        l.register(ip(1));
        l.register(ip(2));
        let change = l.set_addrs(addrs(&[2]), [ip(1), ip(2)]);
        assert_eq!(
            change,
            LocalChange {
                became_local: vec![ip(2)],
                stopped_local: vec![ip(1)],
            }
        );
        assert!(l.is_local(&ip(2)) && !l.is_local(&ip(1)));
        assert!(l.set_addrs(addrs(&[2]), [ip(1), ip(2)]).is_empty());
    }
    /// An address takeover: a RESOLVED nexthop's address moves onto the
    /// box. Its slot must go back to the kernel path, and a `Learned`
    /// still in flight for it must not put the redirect back. When the
    /// address leaves again it resolves like any other nexthop, and
    /// neighbour events apply once more.
    #[test]
    fn a_takeover_forgets_the_resolution_and_drops_stale_learned_events() {
        let mut l = LocalNexthops::new(addrs(&[1]));
        assert!(!l.register(ip(7)), "a peer, resolvable");
        assert_eq!(l.neigh_event(&ip(7)), NeighVerdict::Apply);

        // The peer's address is added to the router.
        let change = l.set_addrs(addrs(&[1, 7]), [ip(7)]);
        assert_eq!(change.actions(), vec![SlotAction::ForgetResolution(ip(7))]);
        assert_eq!(
            l.neigh_event(&ip(7)),
            NeighVerdict::IgnoreLocal,
            "the in-flight Learned must not re-resolve a local slot"
        );

        // And removed again: resolvable through the normal path.
        let change = l.set_addrs(addrs(&[1]), [ip(7)]);
        assert_eq!(change.actions(), vec![SlotAction::Resolve(ip(7))]);
        assert_eq!(l.neigh_event(&ip(7)), NeighVerdict::Apply);
    }
}
