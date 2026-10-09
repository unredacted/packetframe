//! What one clsact filter slot holds, read before a teardown deletes a
//! recorded cls_bpf filter from a device it can vouch for only by
//! ifindex.
//!
//! fast-path and guard find a recorded filter's device by its ifindex,
//! so a filter follows a renamed device. But an ifindex can be handed
//! on: `ip link add … index N`, or a device moved into the namespace,
//! which keeps its index when it is free. Under the recorded name the
//! name and the ifindex vouch for each other; under another name only
//! the program in the slot says whose filter it is.

use std::io;
use std::time::Duration;

/// The clsact hook a filter hangs off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClsactHook {
    Ingress,
    Egress,
}

/// How long one receive of the dump may block. A reply is microseconds;
/// netlink has no cancellation, so this bounds a kernel that sends none.
const RECV_BOUND: Duration = Duration::from_secs(5);

/// The name of the BPF program in the cls_bpf filter at
/// `(priority, handle)` in chain 0 of `ifindex`'s clsact `hook`, from one
/// `RTM_GETTFILTER` dump, as `tc filter show` reads it. `Ok(None)` when
/// no eBPF filter is there: no filter, another classifier, a classic-BPF
/// one, or no clsact qdisc (or device) at all.
pub fn bpf_program_at(
    ifindex: u32,
    hook: ClsactHook,
    priority: u16,
    handle: u32,
) -> io::Result<Option<String>> {
    Ok(slot(ifindex, hook, priority, handle)?.and_then(|s| s.name))
}

/// The id of the BPF program in that slot, `Ok(None)` as for
/// [`bpf_program_at`]. For a caller that holds the program: an id names
/// one loaded program, where a name is shared by every load of the ELF.
pub fn bpf_program_id_at(
    ifindex: u32,
    hook: ClsactHook,
    priority: u16,
    handle: u32,
) -> io::Result<Option<u32>> {
    Ok(slot(ifindex, hook, priority, handle)?.and_then(|s| s.id))
}

/// What the eBPF program in a slot reports of itself.
struct Slot {
    name: Option<String>,
    id: Option<u32>,
}

fn slot(ifindex: u32, hook: ClsactHook, priority: u16, handle: u32) -> io::Result<Option<Slot>> {
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
    use netlink_packet_route::tc::{TcAttribute, TcFilterBpfOption, TcHandle, TcMessage, TcOption};
    use netlink_packet_route::RouteNetlinkMessage;
    use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};

    let ifindex = i32::try_from(ifindex)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ifindex past i32"))?;
    let mut socket = Socket::new(NETLINK_ROUTE)?;
    bound_recv(&socket)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;

    let mut tc = TcMessage::default();
    tc.header.index = ifindex;
    tc.header.parent = TcHandle {
        major: u16::MAX,
        minor: match hook {
            ClsactHook::Ingress => TcHandle::MIN_INGRESS,
            ClsactHook::Egress => TcHandle::MIN_EGRESS,
        },
    };
    let mut msg = NetlinkMessage::from(RouteNetlinkMessage::GetTrafficFilter(tc));
    msg.header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    msg.header.sequence_number = 1;
    msg.finalize();
    let mut send_buf = vec![0u8; msg.header.length as usize];
    msg.serialize(&mut send_buf);
    socket.send(&send_buf, 0)?;

    let mut found = None;
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
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewTrafficFilter(m))
                    if (m.header.info >> 16) as u16 == priority
                        && u32::from(m.header.handle) == handle =>
                {
                    let mut chain = 0;
                    let mut name = None;
                    let mut id = None;
                    for attr in &m.attributes {
                        match attr {
                            TcAttribute::Chain(c) => chain = *c,
                            TcAttribute::Options(opts) => {
                                for opt in opts {
                                    match opt {
                                        TcOption::Bpf(TcFilterBpfOption::ProgName(n)) => {
                                            name = Some(n.clone());
                                        }
                                        TcOption::Bpf(TcFilterBpfOption::ProgId(i)) => {
                                            id = Some(*i);
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    if chain == 0 {
                        found = Some(Slot { name, id });
                    }
                }
                _ => {}
            }
            offset += len;
        }
    }
    Ok(found)
}

fn bound_recv(socket: &netlink_sys::Socket) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    // `as _`: `time_t`/`suseconds_t`, which libc deprecates by name on
    // musl; the inferred cast is the same conversion on every target.
    let tv = libc::timeval {
        tv_sec: RECV_BOUND.as_secs() as _,
        tv_usec: RECV_BOUND.subsec_micros() as _,
    };
    // SAFETY: `socket` owns the fd for the call, and `tv` is a `timeval`
    // of exactly the length passed.
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
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A dump needs no privilege. No clsact qdisc on `lo`, and no device
    /// at all for an ifindex nothing has: both an empty slot.
    #[test]
    fn an_empty_slot_reads_as_none() {
        let lo = std::ffi::CString::new("lo").unwrap();
        // SAFETY: a NUL-terminated name.
        let lo = unsafe { libc::if_nametoindex(lo.as_ptr()) };
        assert_ne!(lo, 0);
        for hook in [ClsactHook::Ingress, ClsactHook::Egress] {
            assert_eq!(bpf_program_at(lo, hook, 49152, 1).unwrap(), None);
            assert_eq!(bpf_program_id_at(lo, hook, 49152, 1).unwrap(), None);
        }
        assert_eq!(
            bpf_program_at(i32::MAX as u32, ClsactHook::Ingress, 49152, 1).unwrap(),
            None
        );
    }
}
