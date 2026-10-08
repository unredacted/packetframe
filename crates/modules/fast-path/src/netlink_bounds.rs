//! Bounds on the netlink sockets the fast-path's own watchers and
//! reconcilers open (the redirect-target watcher, `wan-egress`, `anyip`):
//! how long an exchange may go unanswered, and how a multicast
//! subscription asks for a bigger receive buffer.

use std::io;
use std::os::fd::AsRawFd;
use std::time::Duration;

/// How long one short netlink exchange — a dump of a small table, or a
/// few writes and their ACKs — may go unanswered before it is abandoned.
///
/// Replies normally arrive in microseconds. A request that needs RTNL
/// queues behind whoever holds it, and a port bounce that flushes a full
/// routing table holds it for seconds while the softirq load of the same
/// event delays the reader, so the bound sits well above that. A reply
/// the kernel could not allocate (a write's ACK, or a dump's next chunk)
/// never arrives at all, and netlink-proto waits for it forever: without
/// a bound the task awaiting it hangs for good. Every caller opens a
/// fresh connection per exchange, so abandoning one replaces it.
pub(crate) const NETLINK_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Ask for `bytes` of receive buffer on a subscription's `socket` and
/// return what the kernel granted (it doubles the request to cover its
/// own bookkeeping). `SO_RCVBUFFORCE` needs CAP_NET_ADMIN, which the
/// daemon has; without it `SO_RCVBUF` is still worth asking, capped at
/// `net.core.rmem_max`. A bigger buffer makes an overrun rarer, never
/// impossible: the consumer must still recover from one.
pub(crate) fn raise_rcvbuf(socket: &rtnetlink::sys::Socket, bytes: usize) -> io::Result<usize> {
    let want = libc::c_int::try_from(bytes).unwrap_or(libc::c_int::MAX / 2);
    let set = |opt: libc::c_int| {
        // SAFETY: `want` is a c_int of exactly the passed length, and
        // `socket` owns the fd for the call.
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                opt,
                std::ptr::addr_of!(want).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };
    if set(libc::SO_RCVBUFFORCE).is_err() {
        set(libc::SO_RCVBUF)?;
    }
    socket.get_rx_buf_sz()
}
