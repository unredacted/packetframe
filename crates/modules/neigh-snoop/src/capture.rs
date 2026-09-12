//! The receive-only capture socket, one per bridge.
//!
//! `AF_PACKET`/`SOCK_RAW`/`ETH_P_ALL`, non-blocking, with the classic
//! BPF program from [`crate::bpf_filter`] attached **before** the bind
//! so no unfiltered frame is ever queued to userspace, outgoing frames
//! ignored at the socket, and promiscuous mode requested through
//! `PACKET_ADD_MEMBERSHIP` so the kernel refcounts it and releases it
//! when the socket closes. Nothing is ever written to this socket.
//!
//! Why promiscuous and not allmulti: the bridge's own forwarding code
//! decides what reaches the bridge device's taps, and it consults
//! `IFF_PROMISC` — never `IFF_ALLMULTI`. Multicast reaches the host
//! only while no MLD querier exists on the segment; the day one
//! appears, neighbour solicitations for other participants stop
//! arriving under allmulti and IPv6 learning collapses silently. On a
//! single-member bridge behind a switch that only delivers our frames,
//! promiscuous mode admits nothing extra.

#![cfg(target_os = "linux")]

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::bpf_filter::{SockFilter, PROG};
use crate::engine::EngineMsg;

/// Largest frame we bother copying; ARP and ND fit in a fraction.
const RECV_BUF: usize = 2048;

fn last_err(what: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// Open, filter, bind and set promiscuous. Returns the owned fd;
/// closing it releases the promiscuity refcount.
pub fn open_capture(ifindex: u32) -> io::Result<OwnedFd> {
    let proto_be = (libc::ETH_P_ALL as u16).to_be();
    let raw = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            i32::from(proto_be),
        )
    };
    if raw < 0 {
        return Err(last_err("socket(AF_PACKET)"));
    }
    // SAFETY: the kernel returned a valid fd we now own.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // Filter first: between bind and attach an unfiltered frame could
    // otherwise land in the queue.
    const _: () = assert!(mem::size_of::<SockFilter>() == mem::size_of::<libc::sock_filter>());
    let prog = libc::sock_fprog {
        len: PROG.len() as u16,
        filter: PROG.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: `prog` points at a `'static` array of the declared length
    // and layout; the kernel copies it during the call.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            std::ptr::addr_of!(prog).cast(),
            mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(last_err("SO_ATTACH_FILTER"));
    }

    // Belt: the filter already drops outgoing frames; this stops the
    // kernel from even queueing them. Kernel ≥ 4.20; absent is fine.
    let one: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_IGNORE_OUTGOING,
            std::ptr::addr_of!(one).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENOPROTOOPT) {
            return Err(io::Error::new(
                e.kind(),
                format!("PACKET_IGNORE_OUTGOING: {e}"),
            ));
        }
        warn!("PACKET_IGNORE_OUTGOING unsupported on this kernel; relying on the BPF filter");
    }

    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = proto_be;
    sll.sll_ifindex = ifindex as i32;
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            std::ptr::addr_of!(sll).cast(),
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(last_err(&format!("bind(AF_PACKET, ifindex={ifindex})")));
    }

    let mreq = libc::packet_mreq {
        mr_ifindex: ifindex as libc::c_int,
        mr_type: libc::PACKET_MR_PROMISC as libc::c_ushort,
        mr_alen: 0,
        mr_address: [0u8; 8],
    };
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_ADD_MEMBERSHIP,
            std::ptr::addr_of!(mreq).cast(),
            mem::size_of::<libc::packet_mreq>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(last_err("PACKET_ADD_MEMBERSHIP(PROMISC)"));
    }
    Ok(fd)
}

/// One `recvfrom`, returning the frame length and the kernel's packet
/// type (`sll_pkttype`).
fn recv_one(fd: &OwnedFd, buf: &mut [u8]) -> io::Result<(usize, u8)> {
    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    let mut len = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    let n = unsafe {
        libc::recvfrom(
            fd.as_raw_fd(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            std::ptr::addr_of_mut!(sll).cast(),
            &mut len,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((n as usize, sll.sll_pkttype))
}

/// Pump frames from the socket into the engine until cancelled or
/// the socket errors. Uses `try_send`: the pump must never stall the
/// socket read; a full channel drops the frame and counts it.
pub async fn pump(
    fd: OwnedFd,
    bridge_idx: usize,
    ifindex: u32,
    tx: mpsc::Sender<EngineMsg>,
    dropped: Arc<AtomicU64>,
    cancel: CancellationToken,
) -> Result<(), String> {
    let afd =
        AsyncFd::with_interest(fd, Interest::READABLE).map_err(|e| format!("AsyncFd: {e}"))?;
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let mut guard = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            g = afd.readable() => g.map_err(|e| format!("readable: {e}"))?,
        };
        match guard.try_io(|inner| recv_one(inner.get_ref(), &mut buf)) {
            Ok(Ok((n, pkt_type))) => {
                let msg = EngineMsg::Frame {
                    bridge_idx,
                    ifindex,
                    pkt_type,
                    bytes: buf[..n].to_vec(),
                };
                if tx.try_send(msg).is_err() {
                    dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
            Ok(Err(e)) => {
                debug!(ifindex, error = %e, "capture recv failed");
                return Err(format!("recv: {e}"));
            }
            // Spurious readiness: the guard cleared it; loop.
            Err(_would_block) => {}
        }
    }
}
