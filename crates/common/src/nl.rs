//! What the blocking rtnetlink dumps in this crate share.

use std::io;
use std::time::Duration;

/// How long one receive of a dump may block. A reply is microseconds;
/// netlink has no cancellation, so this bounds a kernel that sends none.
pub(crate) const RECV_BOUND: Duration = Duration::from_secs(5);

/// Bound every receive on `socket` by [`RECV_BOUND`].
pub(crate) fn bound_recv(socket: &netlink_sys::Socket) -> io::Result<()> {
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
