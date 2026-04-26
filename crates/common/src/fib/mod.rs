//! Custom-FIB trait shapes shared across userspace modules (Option F).
//!
//! Phase 1 defines only the trait surfaces so Phase 2-3 can land
//! concrete implementations (BMP station, netlink neighbor listener,
//! FibProgrammer) without churning the shape. No impls here — the
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
    /// at the trait level — Phase 3 lands a concrete channel pair
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
    Add {
        peer_id: PeerId,
        prefix: IpPrefix,
        nexthops: Vec<IpAddr>,
    },
    /// Route withdrawal.
    Del { peer_id: PeerId, prefix: IpPrefix },
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    /// value when the resolver couldn't look up the egress MAC — the
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
}
