//! Every bridge device's and bridge port's VLAN table, from one AF_BRIDGE
//! `RTM_GETLINK` dump with `RTEXT_FILTER_BRVLAN`: what `bridge vlan show`
//! prints. The rule the tables feed is
//! [`crate::topology::BridgeVlans`].

use std::collections::HashMap;
use std::io;

use crate::nl::bound_recv;
use crate::topology::VlanRecord;

/// Each device's VLAN records, by name: a bridge port's own table, and a
/// bridge's "self" table (the VLANs it passes up to its own stack).
/// A device reported more than once (a NIC whose driver answers the
/// bridge dump too, alongside its bridge) has its records merged. A
/// device with no VLANs is absent.
///
/// Blocking: each receive is bounded (`crate::nl::RECV_BOUND`). The
/// socket is in the calling thread's network namespace.
pub fn dump_vlan_records() -> io::Result<HashMap<String, Vec<VlanRecord>>> {
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
    use netlink_packet_route::link::{
        AfSpecBridge, BridgeVlanInfoFlags, LinkAttribute, LinkExtentMask, LinkMessage,
    };
    use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let mut socket = Socket::new(NETLINK_ROUTE)?;
    bound_recv(&socket)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

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
    socket.send(&send_buf, 0)?;

    let mut out: HashMap<String, Vec<VlanRecord>> = HashMap::new();
    let mut recv_buf = vec![0u8; 64 * 1024];
    'dump: loop {
        let n = socket.recv(&mut &mut recv_buf[..], 0)?;
        let mut offset = 0usize;
        while offset < n {
            let pkt = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&recv_buf[offset..n])
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("netlink parse: {e}"))
                })?;
            let len = pkt.header.length as usize;
            if len == 0 {
                break;
            }
            match pkt.payload {
                NetlinkPayload::Done(_) => break 'dump,
                NetlinkPayload::Error(e) => return Err(e.to_io()),
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewLink(m)) => {
                    let mut name = None;
                    let mut records = Vec::new();
                    for a in &m.attributes {
                        match a {
                            LinkAttribute::IfName(n) => name = Some(n.clone()),
                            LinkAttribute::AfSpecBridge(specs) => {
                                for spec in specs {
                                    if let AfSpecBridge::VlanInfo(v) = spec {
                                        records.push(VlanRecord {
                                            vid: v.vid,
                                            pvid: v.flags.contains(BridgeVlanInfoFlags::Pvid),
                                            untagged: v
                                                .flags
                                                .contains(BridgeVlanInfoFlags::Untagged),
                                            range_begin: v
                                                .flags
                                                .contains(BridgeVlanInfoFlags::RangeBegin),
                                            range_end: v
                                                .flags
                                                .contains(BridgeVlanInfoFlags::RangeEnd),
                                        });
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if let (Some(name), false) = (name, records.is_empty()) {
                        out.entry(name).or_default().extend(records);
                    }
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

    /// A dump needs no privilege, and a namespace with no bridge has no
    /// VLAN table to report.
    #[test]
    fn a_dump_reads_without_privilege() {
        let records = dump_vlan_records().unwrap();
        assert!(!records.contains_key("lo"));
    }
}
