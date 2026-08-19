//! AnyIP phantom-listen support for `route-source bgp ... anyip`.
//!
//! Some routing daemons refuse to peer with any address their host
//! owns: FRR rejects `neighbor <addr>` for every interface-owned
//! address at config time ("Can not configure the local system as
//! neighbor"), and cannot complete a session over loopback either
//! (zebra treats 127/8 as martian, so peer NHT never resolves and
//! `bgp_nexthop_set` finds no owning interface). bird has neither
//! restriction, which is why the BgpListener's loopback default was
//! sufficient until an FRR deployment appeared.
//!
//! The escape hatch is the kernel's AnyIP mechanism: a route of type
//! `local` makes its destination bindable and locally deliverable
//! without assigning the address to any interface. From FRR's view
//! the phantom address is an ordinary connected neighbor; from the
//! kernel's view packets to it are local traffic; from every other
//! host's view it doesn't exist (the /32 lives only in this box's
//! `local` table).
//!
//! This module owns exactly that one route. The controller calls
//! [`ensure_local_route`] before the listener's first bind, before
//! each listener retry, and on a periodic reconcile tick — the last
//! because a *bound* listener emits no error when the route is
//! flushed (SYNs silently stop being delivered; review finding,
//! PR #196), so only time-based replacement can heal that case.
//! Replace semantics make every call idempotent. The controller
//! calls [`remove_local_route`] during explicit shutdown AND from
//! its `Drop` impl — the latter because the §8.5 preserve-attach
//! exit (the normal `systemctl stop`) drops the controller without
//! ever calling `shutdown()` — so the route's lifetime is a strict
//! subset of the daemon's on every exit path short of SIGKILL — no kernel
//! state survives that a restart doesn't recreate, which is the
//! property that lets the operator's config file remain the single
//! source of truth on fleets where hand-installed routes are
//! prohibited (they don't survive firmware upgrades).
//!
//! [`ensure_local_route`] refuses an address some interface already
//! owns, for the same reason the vpp-offload loader refuses a live
//! loopback IP (#188): an owned address means the operator pointed
//! `anyip` at a real interface address, and FRR would reject the
//! neighbor outright — better to fail attach loudly than converge
//! into a feed that can never establish. It likewise refuses a
//! same-destination local route installed by anything else: routes
//! we install wear [`ANYIP_ROUTE_PROTOCOL`] as an ownership tag, so
//! a crash-orphaned route from a previous daemon life is adopted
//! silently while a foreign owner's route is neither replaced at
//! startup nor deletable at shutdown (the kernel's protocol-scoped
//! delete cannot match it).

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};

use futures::TryStreamExt;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteProtocol, RouteScope, RouteType,
};
use rtnetlink::{Handle, RouteMessageBuilder};
use tracing::info;

/// The kernel's `local` routing table, where type-`local` routes
/// conventionally live (`ip route show table local`).
const LOCAL_TABLE: u32 = 255;

/// The route-protocol value that marks the AnyIP route as OURS.
///
/// This is the ownership tag that makes three behaviors possible at
/// once (review finding, PR #196):
/// - crash adoption: a route left behind by a SIGKILL'd daemon wears
///   the tag, so the next start adopts it silently instead of
///   refusing its own leftovers;
/// - contested refusal: a `local <addr>/32` installed by anything
///   else does NOT wear it, so [`ensure_local_route`] refuses rather
///   than silently replacing another owner's route;
/// - scoped delete: `RTM_DELROUTE` with a nonzero protocol only
///   matches routes carrying that protocol, so shutdown removal is
///   structurally unable to delete a route we don't own.
///
/// 199 is unassigned in iproute2's `rt_protos` (186 bgp, 187 isis,
/// 188 ospf, 189 rip, 192 eigrp are the neighbors); `ip route show
/// table local` renders it as `proto 199`.
const ANYIP_ROUTE_PROTOCOL: RouteProtocol = RouteProtocol::Other(199);

#[derive(Debug, thiserror::Error)]
pub enum AnyipError {
    #[error("netlink connection failed: {0}")]
    Connection(#[from] std::io::Error),
    #[error("netlink request failed: {0}")]
    Request(#[from] rtnetlink::Error),
    #[error(
        "anyip address {addr} is already owned by interface index {ifindex}; \
         a phantom listen address must not be assigned to any interface \
         (FRR refuses interface-owned addresses as neighbors — pick an \
         unassigned address, e.g. the unused host in the feed /30)"
    )]
    AddressOwned { addr: Ipv4Addr, ifindex: u32 },
    #[error("interface `lo` not found via RTM_GETLINK")]
    NoLoopbackIface,
    #[error(
        "a `local {addr}/32` route already exists with protocol {proto:?}, \
         installed by something other than packetframe; refusing to adopt \
         or replace it — the anyip address must be exclusively ours \
         (pick a different phantom address, or remove the foreign route's \
         owner first)"
    )]
    RouteContested {
        addr: Ipv4Addr,
        proto: RouteProtocol,
    },
}

/// Ensure `local <addr>/32 dev lo` exists in the `local` table.
///
/// Idempotent (`NLM_F_REPLACE`), so the controller can call it before
/// every listener (re)start: a route someone flushed at runtime is
/// healed on the next retry rather than requiring a daemon restart.
///
/// Fails with [`AnyipError::AddressOwned`] if any interface holds
/// `addr` — see the module docs for why that is a hard refusal.
pub async fn ensure_local_route(addr: Ipv4Addr) -> Result<(), AnyipError> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    if let Some(ifindex) = owning_ifindex(&handle, addr).await? {
        return Err(AnyipError::AddressOwned { addr, ifindex });
    }
    // A pre-existing local /32 for this address is adopted only when
    // it wears our protocol tag (a previous daemon life); any other
    // protocol means another owner got here first, and replacing
    // their route now means deleting it at our shutdown later.
    if let Some(proto) = existing_local_route_protocol(&handle, addr).await? {
        if proto != ANYIP_ROUTE_PROTOCOL {
            return Err(AnyipError::RouteContested { addr, proto });
        }
    }

    let lo = lo_ifindex(&handle).await?;
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(addr, 32)
        .output_interface(lo)
        .table_id(LOCAL_TABLE)
        .scope(RouteScope::Host)
        .kind(RouteType::Local)
        .protocol(ANYIP_ROUTE_PROTOCOL)
        .build();
    handle.route().add(route).replace().execute().await?;
    info!(%addr, "anyip: local /32 ensured on lo (kernel AnyIP)");
    Ok(())
}

/// Remove the route [`ensure_local_route`] installed. Best-effort by
/// contract: an already-absent route is success, not an error, so
/// shutdown never fails on a route someone else already cleaned up.
///
/// The delete carries [`ANYIP_ROUTE_PROTOCOL`]; the kernel only
/// matches routes with that protocol, so a same-destination route
/// owned by anything else is unreachable from here — it survives as
/// an ESRCH, which the tolerant arm below reports as success.
pub async fn remove_local_route(addr: Ipv4Addr) -> Result<(), AnyipError> {
    let (conn, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(conn);

    let lo = lo_ifindex(&handle).await?;
    let route = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(addr, 32)
        .output_interface(lo)
        .table_id(LOCAL_TABLE)
        .scope(RouteScope::Host)
        .kind(RouteType::Local)
        .protocol(ANYIP_ROUTE_PROTOCOL)
        .build();
    match handle.route().del(route).execute().await {
        Ok(()) => {
            info!(%addr, "anyip: local /32 removed");
            Ok(())
        }
        // ESRCH/ENOENT: the route is already gone. That is the state
        // we wanted; report success.
        Err(rtnetlink::Error::NetlinkError(e))
            if e.raw_code() == -libc::ESRCH || e.raw_code() == -libc::ENOENT =>
        {
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// The ifindex of whichever interface holds `addr`, if any. Both the
/// `Address` and `Local` attributes are checked: point-to-point
/// interfaces carry the local address in `Local` with the peer in
/// `Address`, and either shape means the address is owned.
async fn owning_ifindex(handle: &Handle, addr: Ipv4Addr) -> Result<Option<u32>, AnyipError> {
    let mut addrs = handle.address().get().execute();
    while let Some(msg) = addrs.try_next().await? {
        let owned = msg.attributes.iter().any(|attr| {
            matches!(
                attr,
                AddressAttribute::Address(IpAddr::V4(a)) | AddressAttribute::Local(IpAddr::V4(a))
                    if *a == addr
            )
        });
        if owned {
            return Ok(Some(msg.header.index));
        }
    }
    Ok(None)
}

/// The protocol of an existing `local <addr>/32` in the local table,
/// or `None` when no such route exists. This is the ownership probe:
/// the caller compares the result against [`ANYIP_ROUTE_PROTOCOL`].
async fn existing_local_route_protocol(
    handle: &Handle,
    addr: Ipv4Addr,
) -> Result<Option<RouteProtocol>, AnyipError> {
    let filter = RouteMessageBuilder::<Ipv4Addr>::new().build();
    let mut routes = handle.route().get(filter).execute();
    while let Some(msg) = routes.try_next().await? {
        if msg.header.kind != RouteType::Local
            || msg.header.destination_prefix_length != 32
            || u32::from(msg.header.table) != LOCAL_TABLE
        {
            continue;
        }
        let dst_matches = msg.attributes.iter().any(|attr| {
            matches!(
                attr,
                RouteAttribute::Destination(RouteAddress::Inet(a)) if *a == addr
            )
        });
        if dst_matches {
            return Ok(Some(msg.header.protocol));
        }
    }
    Ok(None)
}

async fn lo_ifindex(handle: &Handle) -> Result<u32, AnyipError> {
    let mut links = handle.link().get().match_name("lo".to_string()).execute();
    match links.try_next().await? {
        Some(link) => Ok(link.header.index),
        None => Err(AnyipError::NoLoopbackIface),
    }
}
