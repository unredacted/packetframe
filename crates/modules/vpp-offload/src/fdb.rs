//! The kernel bridge FDB, read over AF_BRIDGE netlink.
//!
//! Which bridge port a MAC is learned on, per VLAN — the fact
//! [`crate::topology`] places bridge neighbours by (B3 v2). B3 v1 used
//! the same dump only to REPORT a host that had moved behind another
//! port than its `local-route` declared; placement now follows it.
//!
//! The dump is kernel-side and read-only: one RTM_GETNEIGH on a blocking
//! netlink socket, no tokio (this crate's control plane is the
//! supervision loop, not a runtime), bounded by a receive timeout. A
//! failed read costs a log line and keeps the previous snapshot; it must
//! never escalate into supervision.

/// One AF_BRIDGE FDB entry, reduced to what placement needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdbEntry {
    pub mac: [u8; 6],
    /// NDA_VLAN; `None` for VLAN-unaware entries.
    pub vlan: Option<u16>,
    /// The member port the kernel learned the MAC on.
    pub port: u32,
    /// NDA_MASTER — the bridge whose FDB this is. Entries without one
    /// are port-local ("self") records, not bridge paths.
    pub master: Option<u32>,
    /// NUD_PERMANENT: interface addresses and static plumbing, not
    /// learned hosts. A bridge holds its own MAC as permanent on a
    /// member; flagging those would page on every box ever built.
    pub permanent: bool,
}

/// `if_indextoname`, shared with [`crate::drift`]'s route dump — both
/// turn kernel ifindexes into the names an operator reads.
#[cfg(target_os = "linux")]
pub(crate) fn ifname(index: u32) -> String {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: `buf` is IF_NAMESIZE bytes as the contract requires.
    let ret = unsafe { libc::if_indextoname(index, buf.as_mut_ptr().cast()) };
    if ret.is_null() {
        return format!("ifindex {index}");
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

/// Bound how long ONE `recv` on a dump socket may block, shared with
/// [`crate::drift`]'s route dump.
///
/// Netlink has no cancellation, so an unbounded receive is a thread
/// that never settles: on the supervision loop that is a liveness
/// stall, and on the scan thread it is a teardown that can never
/// complete. The kernel produces dump batches promptly — 5 s is orders
/// of magnitude past any real one — so a timeout here means something
/// is wrong, and the caller's error path (scan unreadable, gauge
/// absent) already says so honestly. A monitoring read must never be
/// able to wedge anything, including itself (review finding).
#[cfg(target_os = "linux")]
pub(crate) fn bound_recv(socket: &netlink_sys::Socket) -> Result<(), String> {
    use std::os::fd::AsRawFd as _;
    let tv = libc::timeval {
        tv_sec: 5,
        tv_usec: 0,
    };
    // SAFETY: `socket` owns the fd for the call, and `tv` is a
    // `timeval` of exactly the length passed.
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(format!(
            "netlink SO_RCVTIMEO: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// One blocking AF_BRIDGE RTM_GETNEIGH dump.
///
/// Hand-rolled on `netlink-sys` rather than `rtnetlink` because this
/// crate has no async runtime to park a connection on, and one dump
/// per minute does not earn one. The message shapes are the same
/// crates fast-path's resolver decodes with.
#[cfg(target_os = "linux")]
pub fn dump_bridge_fdb() -> Result<Vec<FdbEntry>, String> {
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
    use netlink_packet_route::neighbour::{NeighbourAttribute, NeighbourMessage, NeighbourState};
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
    // This dump runs ON the supervision loop, so an unbounded receive
    // would stall liveness, wedge detection and `steer off` alike.
    bound_recv(&socket)?;
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;

    let mut neigh = NeighbourMessage::default();
    neigh.header.family = AddressFamily::Bridge;
    let mut msg = NetlinkMessage::from(RouteNetlinkMessage::GetNeighbour(neigh));
    msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.header.sequence_number = 1;
    msg.finalize();
    let mut send_buf = vec![0u8; msg.header.length as usize];
    msg.serialize(&mut send_buf);
    socket
        .send(&send_buf, 0)
        .map_err(|e| format!("netlink send: {e}"))?;

    let mut out = Vec::new();
    let mut recv_buf = vec![0u8; 64 * 1024];
    'dump: loop {
        let n = socket
            .recv(&mut &mut recv_buf[..], 0)
            .map_err(|e| format!("netlink recv: {e}"))?;
        let mut offset = 0usize;
        while offset < n {
            let pkt = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[offset..n])
                .map_err(|e| format!("netlink parse: {e}"))?;
            let len = pkt.header.length as usize;
            if len == 0 {
                break;
            }
            match pkt.payload {
                NetlinkPayload::Done(_) => break 'dump,
                NetlinkPayload::Error(e) => return Err(format!("netlink error: {e}")),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNeighbour(m)) => {
                    let mut mac = None;
                    let mut vlan = None;
                    let mut master = None;
                    for attr in &m.attributes {
                        match attr {
                            NeighbourAttribute::LinkLayerAddress(bytes) if bytes.len() == 6 => {
                                let mut m6 = [0u8; 6];
                                m6.copy_from_slice(bytes);
                                mac = Some(m6);
                            }
                            NeighbourAttribute::Vlan(v) => vlan = Some(*v),
                            NeighbourAttribute::Controller(idx) => master = Some(*idx),
                            _ => {}
                        }
                    }
                    if let Some(mac) = mac {
                        out.push(FdbEntry {
                            mac,
                            vlan,
                            port: m.header.ifindex,
                            master,
                            permanent: m.header.state == NeighbourState::Permanent,
                        });
                    }
                }
                _ => {}
            }
            offset += len;
        }
    }
    Ok(out)
}

/// One bridge port's VLAN membership, from an AF_BRIDGE RTM_GETLINK dump
/// with `RTEXT_FILTER_BRVLAN`: `(vid, egress untagged)` per VLAN — what
/// `bridge vlan show` prints.
/// One `IFLA_BRIDGE_VLAN_INFO` record, as far as membership needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanInfo {
    pub vid: u16,
    pub untagged: bool,
    pub range_begin: bool,
    pub range_end: bool,
}

/// `(vid, untagged)` for every VLAN the records name, expanding a
/// `RANGE_BEGIN`…`RANGE_END` pair into each vid between. The
/// `RTEXT_FILTER_BRVLAN` dump reports VLANs one per record today (ranges
/// are `RTEXT_FILTER_BRVLAN_COMPRESSED`'s), but a range read as two
/// VLANs would leave every VLAN inside it without a subif, punting its
/// steered frames — so it is expanded rather than assumed away. A range
/// takes its flags from its first record; one left open is dropped.
pub fn expand_vlan_ranges(infos: &[VlanInfo]) -> Vec<(u16, bool)> {
    let mut out = Vec::new();
    let mut begin: Option<VlanInfo> = None;
    for i in infos {
        match (begin, i.range_end) {
            (Some(b), true) => {
                out.extend((b.vid..=i.vid).map(|vid| (vid, b.untagged)));
                begin = None;
            }
            _ if i.range_begin => begin = Some(*i),
            _ => {
                begin = None;
                out.push((i.vid, i.untagged));
            }
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortVlanEntry {
    /// The enslaved port, by name.
    pub port: String,
    pub vid: u16,
    /// The bridge sends this VLAN out of the port without a tag (the
    /// PVID of an access or trunk port, typically VLAN 1).
    pub untagged: bool,
}

/// Every bridge port's VLANs. Blocking, bounded by [`bound_recv`], like
/// [`dump_bridge_fdb`]; callers run it off the supervision loop.
#[cfg(target_os = "linux")]
pub fn dump_port_vlans() -> Result<Vec<PortVlanEntry>, String> {
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
    use netlink_packet_route::link::{
        AfSpecBridge, BridgeVlanInfoFlags, LinkAttribute, LinkExtentMask, LinkMessage,
    };
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut socket = Socket::new(NETLINK_ROUTE).map_err(|e| format!("netlink socket: {e}"))?;
    bound_recv(&socket)?;
    socket
        .bind_auto()
        .map_err(|e| format!("netlink bind: {e}"))?;
    socket
        .connect(&SocketAddr::new(0, 0))
        .map_err(|e| format!("netlink connect: {e}"))?;

    let mut link = LinkMessage::default();
    link.header.interface_family = AddressFamily::Bridge;
    link.attributes
        .push(LinkAttribute::ExtMask(vec![LinkExtentMask::Brvlan]));
    let mut msg = NetlinkMessage::from(RouteNetlinkMessage::GetLink(link));
    msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.header.sequence_number = 1;
    msg.finalize();
    let mut send_buf = vec![0u8; msg.header.length as usize];
    msg.serialize(&mut send_buf);
    socket
        .send(&send_buf, 0)
        .map_err(|e| format!("netlink send: {e}"))?;

    let mut out = Vec::new();
    let mut recv_buf = vec![0u8; 64 * 1024];
    'dump: loop {
        let n = socket
            .recv(&mut &mut recv_buf[..], 0)
            .map_err(|e| format!("netlink recv: {e}"))?;
        let mut offset = 0usize;
        while offset < n {
            let pkt = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[offset..n])
                .map_err(|e| format!("netlink parse: {e}"))?;
            let len = pkt.header.length as usize;
            if len == 0 {
                break;
            }
            match pkt.payload {
                NetlinkPayload::Done(_) => break 'dump,
                NetlinkPayload::Error(e) => return Err(format!("netlink error: {e}")),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m)) => {
                    // Only enslaved ports: the bridge master reports its
                    // own "self" VLANs here too, which are not a port's.
                    let enslaved = m
                        .attributes
                        .iter()
                        .any(|a| matches!(a, LinkAttribute::Controller(_)));
                    if !enslaved {
                        offset += len;
                        continue;
                    }
                    let port = ifname(m.header.index);
                    let mut infos = Vec::new();
                    for a in &m.attributes {
                        if let LinkAttribute::AfSpecBridge(specs) = a {
                            for spec in specs {
                                if let AfSpecBridge::VlanInfo(v) = spec {
                                    infos.push(VlanInfo {
                                        vid: v.vid,
                                        untagged: v.flags.contains(BridgeVlanInfoFlags::Untagged),
                                        range_begin: v
                                            .flags
                                            .contains(BridgeVlanInfoFlags::RangeBegin),
                                        range_end: v.flags.contains(BridgeVlanInfoFlags::RangeEnd),
                                    });
                                }
                            }
                        }
                    }
                    out.extend(
                        expand_vlan_ranges(&infos)
                            .into_iter()
                            .map(|(vid, untagged)| PortVlanEntry {
                                port: port.clone(),
                                vid,
                                untagged,
                            }),
                    );
                }
                _ => {}
            }
            offset += len;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(vid: u16, untagged: bool, range_begin: bool, range_end: bool) -> VlanInfo {
        VlanInfo {
            vid,
            untagged,
            range_begin,
            range_end,
        }
    }

    /// `vid 2-5` arrives as a begin/end pair and means every vid between;
    /// singles pass through with their own flags (review finding).
    #[test]
    fn a_vlan_range_expands_to_every_vid() {
        let got = expand_vlan_ranges(&[
            info(1, true, false, false),
            info(2, false, true, false),
            info(5, false, false, true),
            info(88, false, false, false),
        ]);
        assert_eq!(
            got,
            vec![
                (1, true),
                (2, false),
                (3, false),
                (4, false),
                (5, false),
                (88, false)
            ]
        );
        // A range never closed names nothing it can vouch for.
        assert!(expand_vlan_ranges(&[info(2, false, true, false)]).is_empty());
    }
}
