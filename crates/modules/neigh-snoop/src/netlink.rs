//! rtnetlink helpers for the engine: dumps of links, addresses and
//! neighbours; the STALE installer; message decoders shared by the
//! dump and multicast paths (so both agree on what a neighbour means);
//! and the strict-check connection the coverage dump needs.

#![cfg(target_os = "linux")]

use std::io;
use std::net::IpAddr;

use futures::channel::mpsc::UnboundedReceiver;
use futures::TryStreamExt;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_route::address::{AddressAttribute, AddressMessage};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use netlink_packet_route::neighbour::{
    NeighbourAddress, NeighbourAttribute, NeighbourMessage, NeighbourState,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use rtnetlink::proto::Connection;
use rtnetlink::sys::{AsyncSocket, SocketAddr, TokioSocket};
use rtnetlink::Handle;

use crate::table::{MirrorEntry, NudState};

/// What one RTM_NEWLINK tells us about a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInfo {
    pub ifindex: u32,
    pub name: Option<String>,
    pub mac: Option<[u8; 6]>,
    pub up: bool,
    pub promisc: bool,
}

pub fn link_info(msg: &LinkMessage) -> LinkInfo {
    let mut name = None;
    let mut mac = None;
    let mut promiscuity = 0u32;
    for attr in &msg.attributes {
        match attr {
            LinkAttribute::IfName(n) => name = Some(n.clone()),
            LinkAttribute::Address(bytes) if bytes.len() == 6 => {
                let mut m = [0u8; 6];
                m.copy_from_slice(bytes);
                mac = Some(m);
            }
            LinkAttribute::Promiscuity(n) => promiscuity = *n,
            _ => {}
        }
    }
    // `IFF_PROMISC` in the flags word reflects only the user-visible
    // flag (`ip link set promisc on`); promiscuity raised through a
    // socket membership is reported as the `IFLA_PROMISCUITY` refcount
    // (what `ip -d link` prints as `promiscuity N`). Either counts.
    LinkInfo {
        ifindex: msg.header.index,
        name,
        mac,
        up: msg.header.flags.contains(LinkFlags::Up),
        promisc: promiscuity > 0 || msg.header.flags.contains(LinkFlags::Promisc),
    }
}

/// `(ifindex, address)` from an RTM_NEWADDR / RTM_DELADDR. `Local`
/// wins over `Address` (for point-to-point the latter is the peer).
pub fn addr_of(msg: &AddressMessage) -> Option<(u32, IpAddr)> {
    let mut local = None;
    let mut addr = None;
    for a in &msg.attributes {
        match a {
            AddressAttribute::Local(ip) => local = Some(*ip),
            AddressAttribute::Address(ip) => addr = Some(*ip),
            _ => {}
        }
    }
    local.or(addr).map(|ip| (msg.header.index, ip))
}

/// `(ifindex, ip, mirror entry)` from a neighbour message, or `None`
/// for AF_BRIDGE FDB rows and non-IP destinations. Every NUD state is
/// kept — the install decision needs INCOMPLETE/FAILED/NONE as much as
/// the valid ones.
pub fn neigh_of(msg: &NeighbourMessage) -> Option<(u32, IpAddr, MirrorEntry)> {
    if msg.header.family == AddressFamily::Bridge {
        return None;
    }
    let mut ip = None;
    let mut mac = None;
    for attr in &msg.attributes {
        match attr {
            NeighbourAttribute::Destination(NeighbourAddress::Inet(v4)) => {
                ip = Some(IpAddr::V4(*v4))
            }
            NeighbourAttribute::Destination(NeighbourAddress::Inet6(v6)) => {
                ip = Some(IpAddr::V6(*v6))
            }
            NeighbourAttribute::LinkLayerAddress(bytes) if bytes.len() == 6 => {
                let mut m = [0u8; 6];
                m.copy_from_slice(bytes);
                mac = Some(m);
            }
            _ => {}
        }
    }
    let ip = ip?;
    let state = NudState::from_raw(u16::from(msg.header.state));
    Some((msg.header.ifindex, ip, MirrorEntry { state, mac }))
}

pub async fn dump_links(handle: &Handle) -> Result<Vec<LinkInfo>, String> {
    let mut out = Vec::new();
    let mut links = handle.link().get().execute();
    while let Some(msg) = links
        .try_next()
        .await
        .map_err(|e| format!("link dump: {e}"))?
    {
        out.push(link_info(&msg));
    }
    Ok(out)
}

pub async fn dump_addrs(handle: &Handle) -> Result<Vec<(u32, IpAddr)>, String> {
    let mut out = Vec::new();
    // No kernel-side filter: `set_link_index_filter` is ignored without
    // strict check, and the address table is small.
    let mut addrs = handle.address().get().execute();
    while let Some(msg) = addrs
        .try_next()
        .await
        .map_err(|e| format!("address dump: {e}"))?
    {
        if let Some(pair) = addr_of(&msg) {
            out.push(pair);
        }
    }
    Ok(out)
}

pub async fn dump_neighs(handle: &Handle) -> Result<Vec<(u32, IpAddr, MirrorEntry)>, String> {
    let mut out = Vec::new();
    let mut neighs = handle.neighbours().get().execute();
    while let Some(msg) = neighs
        .try_next()
        .await
        .map_err(|e| format!("neighbour dump: {e}"))?
    {
        if let Some(row) = neigh_of(&msg) {
            out.push(row);
        }
    }
    Ok(out)
}

/// `RTM_NEWNEIGH` with `NLM_F_CREATE | NLM_F_REPLACE`, `NUD_STALE`,
/// `NDA_DST` + `NDA_LLADDR`. rtnetlink's `add()` presets PERMANENT, so
/// `.state(Stale)` must follow it; PERMANENT is never written.
pub async fn install_stale(
    handle: &Handle,
    ifindex: u32,
    ip: IpAddr,
    mac: [u8; 6],
) -> Result<(), String> {
    handle
        .neighbours()
        .add(ifindex, ip)
        .link_layer_address(&mac)
        .state(NeighbourState::Stale)
        .replace()
        .execute()
        .await
        .map_err(|e| e.to_string())
}

pub type StrictConnection = Connection<RouteNetlinkMessage, TokioSocket>;
pub type Messages = UnboundedReceiver<(NetlinkMessage<RouteNetlinkMessage>, SocketAddr)>;

/// A unicast connection with `NETLINK_GET_STRICT_CHK` set, so the
/// kernel honours dump filters (`RTA_OIF`, table, protocol). Without
/// it a filtered route dump returns the whole table — on a full-table
/// router that is a million routes and tens of seconds per tick.
/// Shaped so fast-path's anyip reconcile can adopt it later.
pub fn new_strict_connection() -> io::Result<(StrictConnection, Handle, Messages)> {
    let (mut conn, handle, msgs) = rtnetlink::new_connection_with_socket::<TokioSocket>()?;
    conn.socket_mut()
        .socket_mut()
        .set_netlink_get_strict_chk(true)?;
    Ok((conn, handle, msgs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn neigh_of_keeps_every_state_and_skips_bridge_rows() {
        let mut m = NeighbourMessage::default();
        m.header.ifindex = 7;
        m.header.state = NeighbourState::Failed;
        m.attributes = vec![NeighbourAttribute::Destination(NeighbourAddress::Inet(
            Ipv4Addr::new(192, 0, 2, 1),
        ))];
        let (ifindex, ip, e) = neigh_of(&m).unwrap();
        assert_eq!(ifindex, 7);
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(e.state, NudState::Failed);
        assert_eq!(e.mac, None);

        m.header.state = NeighbourState::Stale;
        m.attributes
            .push(NeighbourAttribute::LinkLayerAddress(vec![2, 0, 0, 0, 0, 1]));
        let (_, _, e) = neigh_of(&m).unwrap();
        assert_eq!(e.state, NudState::Stale);
        assert_eq!(e.mac, Some([2, 0, 0, 0, 0, 1]));
        assert!(e.resolves());

        m.header.family = AddressFamily::Bridge;
        assert!(neigh_of(&m).is_none());
    }

    #[test]
    fn link_info_reads_name_mac_and_flags() {
        let mut m = LinkMessage::default();
        m.header.index = 9;
        m.header.flags = LinkFlags::Up | LinkFlags::Promisc;
        m.attributes = vec![
            LinkAttribute::IfName("br0".into()),
            LinkAttribute::Address(vec![2, 0, 0, 0, 0, 9]),
        ];
        let l = link_info(&m);
        assert_eq!(l.ifindex, 9);
        assert_eq!(l.name.as_deref(), Some("br0"));
        assert_eq!(l.mac, Some([2, 0, 0, 0, 0, 9]));
        assert!(l.up && l.promisc);
        // Socket-membership promiscuity: refcount attribute, no flag.
        m.header.flags = LinkFlags::Up;
        m.attributes.push(LinkAttribute::Promiscuity(1));
        assert!(link_info(&m).promisc);
        m.attributes.pop();
        assert!(!link_info(&m).promisc);
    }

    #[test]
    fn addr_of_prefers_local() {
        let mut m = AddressMessage::default();
        m.header.index = 3;
        m.attributes = vec![
            AddressAttribute::Address("192.0.2.2".parse().unwrap()),
            AddressAttribute::Local("192.0.2.1".parse().unwrap()),
        ];
        assert_eq!(addr_of(&m), Some((3, "192.0.2.1".parse().unwrap())));
    }
}
