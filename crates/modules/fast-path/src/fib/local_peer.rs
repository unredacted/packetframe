//! Which local accounts may feed the route mirror.
//!
//! A route-source listener on a loopback or AnyIP address is reachable
//! by every process on the router, and neither BGP nor BMP authenticates
//! the speaker here, so any local account that found the feed slot free
//! could program the forwarding mirror (Codex Security finding
//! `occ_d9beffd5`, 2026-11-18).
//!
//! The kernel knows who opened the other end of a local connection:
//! socket diagnostics (`NETLINK_SOCK_DIAG`, `inet_diag`) report every
//! TCP socket's owning uid and inode. At `accept()`, before a byte is
//! read, the listener finds the peer's socket by its address pair and
//! admits it only when that socket is still open and owned by root or
//! an allowed account. Nothing here is a packet filter, so it needs
//! neither nftables nor iptables' owner match, both absent from the
//! UniFi gateways' kernels; it needs `CONFIG_INET_DIAG` and
//! `CONFIG_INET_TCP_DIAG`, which they build in.
//!
//! Why each rule:
//!
//! - **Root always.** FRR's bgpd keeps root as its real uid and switches
//!   back to it to open its outbound sessions, so the socket bgpd
//!   connects to us from is owned by uid 0, not by `frr` (measured on
//!   the reference lab gateway, 2026-11-20). Root can rewrite the
//!   forwarding maps directly in any case.
//! - **A live inode.** On 5.15, `sock_i_uid()` reports root for a socket
//!   its owner has closed, so a process could write a whole feed, close,
//!   and pass as root. The kernel fills a diag record's uid before its
//!   inode, and a socket loses both in the one step that orphans it, so
//!   a uid read as root for that reason always comes with inode 0.
//! - **ESTABLISHED.** A peer that has half-closed has given the session
//!   up.
//! - **A dump, not an exact lookup.** `inet_diag`'s exact lookup with no
//!   interface misses a socket bound to a device, which FRR binds for
//!   interface and VRF peers.
//! - **No matching socket.** The peer is remote only if its address is
//!   not local to this host (the kernel's route lookup does not answer
//!   `RTN_LOCAL`). A local address with no socket behind it is a
//!   connection its owner reset, or closed long enough ago to be
//!   forgotten, and what it left in our receive queue is not a feed.
//!   Remote peers stay governed by `peer-from` and `peer-ip`.

use std::ffi::CString;
use std::fmt;
use std::io;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[cfg(target_os = "linux")]
use linux::{route_is_local, tcp_sockets};
#[cfg(not(target_os = "linux"))]
use stub::{route_is_local, tcp_sockets};

/// The routing daemons' accounts admitted, besides root, when no
/// `peer-user` names one: each that exists on this host.
pub const DEFAULT_ACCOUNTS: [&str; 2] = ["frr", "bird"];

/// The uids whose sockets may feed routes from this host. Always holds
/// root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPeers {
    uids: Vec<u32>,
}

/// Who an admitted connection came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Peer {
    /// Another host: no socket on this one, from an address that is
    /// not this host's.
    Remote,
    /// A socket on this host, owned by `uid`.
    Local { uid: u32 },
}

/// Why a connection was refused.
#[derive(Debug)]
pub enum Refusal {
    /// A live local socket owned by an account that may not feed routes.
    Account { uid: u32 },
    /// The local socket has been closed or half-closed by its owner.
    NotOpen { state: u8 },
    /// From an address of this host, with no socket left behind it.
    Vanished,
    /// The kernel could not be asked.
    Lookup(io::Error),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Account { uid } => write!(
                f,
                "the connecting socket is owned by uid {uid}, which may not feed routes \
                 (root, the peer-user account, or by default frr/bird)"
            ),
            Refusal::NotOpen { state } => write!(
                f,
                "the connecting socket was already closed by its owner (TCP state {state})"
            ),
            Refusal::Vanished => write!(
                f,
                "it came from an address of this host and no socket is left behind it"
            ),
            Refusal::Lookup(e) => write!(f, "socket ownership lookup failed: {e}"),
        }
    }
}

impl LocalPeers {
    /// Root alone.
    pub fn root_only() -> Self {
        Self { uids: vec![0] }
    }

    /// These peers and `uid`.
    pub fn and_uid(mut self, uid: u32) -> Self {
        self.uids.push(uid);
        self.uids.sort_unstable();
        self.uids.dedup();
        self
    }

    pub fn uids(&self) -> &[u32] {
        &self.uids
    }

    /// Root and the `peer-user` account (a name or a numeric uid), or,
    /// with none, root and each of [`DEFAULT_ACCOUNTS`] that exists
    /// here. A name is looked up now, so a `peer-user` this host has no
    /// account for fails the start rather than every connection.
    pub fn resolve(peer_user: Option<&str>) -> Result<Self, String> {
        match peer_user {
            Some(user) => {
                let uid = match user.parse::<u32>() {
                    Ok(uid) => uid,
                    Err(_) => uid_of(user)
                        .map_err(|e| format!("peer-user `{user}`: account lookup failed: {e}"))?
                        .ok_or_else(|| {
                            format!("peer-user `{user}`: no such account on this host")
                        })?,
                };
                Ok(Self::root_only().and_uid(uid))
            }
            None => {
                DEFAULT_ACCOUNTS
                    .iter()
                    .try_fold(Self::root_only(), |peers, name| {
                        match uid_of(name)
                            .map_err(|e| format!("account `{name}`: lookup failed: {e}"))?
                        {
                            Some(uid) => Ok(peers.and_uid(uid)),
                            None => Ok(peers),
                        }
                    })
            }
        }
    }

    /// Judge the connection accepted on `local` from `peer`.
    ///
    /// Blocking, but brief: two socket dumps and, for a peer with no
    /// socket here, one route lookup, each a local netlink round trip
    /// with a one-second ceiling.
    pub fn check(&self, local: SocketAddr, peer: SocketAddr) -> Result<Peer, Refusal> {
        let sockets = tcp_sockets().map_err(Refusal::Lookup)?;
        judge(&sockets, local, peer, &self.uids, || {
            is_local_address(peer.ip())
        })
    }
}

/// Ask the kernel each question [`LocalPeers::check`] will, once, so a
/// kernel without socket diagnostics fails the start, naming what it
/// lacks, rather than refusing every connection.
pub fn self_test() -> io::Result<()> {
    tcp_sockets().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "TCP socket diagnostics unavailable ({e}); the route-source listener needs \
                 CONFIG_INET_DIAG and CONFIG_INET_TCP_DIAG (modules inet_diag, tcp_diag)"
            ),
        )
    })?;
    if !route_is_local(IpAddr::V4(Ipv4Addr::LOCALHOST))? {
        return Err(io::Error::other(
            "the kernel's route lookup does not call 127.0.0.1 local",
        ));
    }
    Ok(())
}

/// One TCP socket as socket diagnostics report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpSocket {
    state: u8,
    src: SocketAddr,
    dst: SocketAddr,
    uid: u32,
    inode: u32,
}

/// `TCP_ESTABLISHED` in include/net/tcp_states.h.
const TCP_ESTABLISHED: u8 = 1;

/// The rules in the module docs, over a socket table already read.
fn judge(
    sockets: &[TcpSocket],
    local: SocketAddr,
    peer: SocketAddr,
    allowed: &[u32],
    peer_is_local: impl FnOnce() -> io::Result<bool>,
) -> Result<Peer, Refusal> {
    let (local, peer) = (canonical(local), canonical(peer));
    let mut found = None;
    // The peer's socket is the one sending from its address to ours.
    // There is one at most; were there more, every one must pass.
    for s in sockets.iter().filter(|s| s.src == peer && s.dst == local) {
        if s.inode == 0 || s.state != TCP_ESTABLISHED {
            return Err(Refusal::NotOpen { state: s.state });
        }
        if !allowed.contains(&s.uid) {
            return Err(Refusal::Account { uid: s.uid });
        }
        found = Some(s.uid);
    }
    if let Some(uid) = found {
        return Ok(Peer::Local { uid });
    }
    match peer_is_local() {
        Ok(false) => Ok(Peer::Remote),
        Ok(true) => Err(Refusal::Vanished),
        Err(e) => Err(Refusal::Lookup(e)),
    }
}

/// `addr` with an IPv4-mapped IPv6 address as the IPv4 address it maps,
/// and no scope: how the two ends of one connection compare when one
/// is an IPv6 socket.
fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// The uid of account `name`, if this host has one.
fn uid_of(name: &str) -> io::Result<Option<u32>> {
    let cname = CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    loop {
        // SAFETY: plain-old-data out-parameter, filled by getpwnam_r.
        let mut pwd: libc::passwd = unsafe { mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call: a NUL-terminated
        // name, `pwd`, and `buf` with its true length.
        let rc = unsafe {
            libc::getpwnam_r(
                cname.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        match rc {
            0 if result.is_null() => return Ok(None),
            0 => return Ok(Some(pwd.pw_uid)),
            libc::ERANGE if buf.len() < 1 << 20 => buf.resize(buf.len() * 2, 0),
            // getpwnam_r(3): ways some libcs say "not found".
            libc::ENOENT | libc::ESRCH => return Ok(None),
            e => return Err(io::Error::from_raw_os_error(e)),
        }
    }
}

/// Whether `ip` is an address of this host: loopback, or what the
/// kernel's route lookup calls local (interface addresses, AnyIP
/// `local` routes).
fn is_local_address(ip: IpAddr) -> io::Result<bool> {
    let ip = ip.to_canonical();
    if ip.is_loopback() {
        return Ok(true);
    }
    route_is_local(ip)
}

// --- netlink -----------------------------------------------------------

/// Socket diagnostics are Linux's: elsewhere every question fails with
/// `ENOSYS`, as the crate's other kernel interfaces do off Linux.
#[cfg(not(target_os = "linux"))]
mod stub {
    use super::TcpSocket;
    use std::io;
    use std::net::IpAddr;

    pub(super) fn tcp_sockets() -> io::Result<Vec<TcpSocket>> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }

    pub(super) fn route_is_local(_: IpAddr) -> io::Result<bool> {
        Err(io::Error::from_raw_os_error(libc::ENOSYS))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::TcpSocket;
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    /// `NETLINK_SOCK_DIAG` in include/uapi/linux/netlink.h.
    const NETLINK_SOCK_DIAG: libc::c_int = 4;
    /// include/uapi/linux/sock_diag.h.
    const SOCK_DIAG_BY_FAMILY: u16 = 20;
    /// include/uapi/linux/rtnetlink.h.
    const RTM_NEWROUTE: u16 = 24;
    const RTM_GETROUTE: u16 = 26;
    const RTA_DST: u16 = 1;
    const RTN_LOCAL: u8 = 2;
    const NLMSG_HDRLEN: usize = 16;
    /// `struct inet_diag_msg`: 4 bytes of family/state/timer/retrans, the
    /// 48-byte `inet_diag_sockid`, then expires, rqueue, wqueue, uid and
    /// inode, 4 bytes each.
    const INET_DIAG_MSG_LEN: usize = 72;
    /// Larger than any one read of a dump: the kernel sizes a dump's
    /// messages to at most 32 KiB.
    const RECV_BUF: usize = 64 * 1024;

    /// Every TCP socket in this network namespace, IPv4 and IPv6, in every
    /// state.
    pub(super) fn tcp_sockets() -> io::Result<Vec<TcpSocket>> {
        let nl = Netlink::open(NETLINK_SOCK_DIAG)?;
        let mut sockets = Vec::new();
        for (seq, family) in [(1, libc::AF_INET), (2, libc::AF_INET6)] {
            nl.send(&dump_request(seq, family as u8))?;
            for (kind, payload) in nl.replies(seq, true)? {
                if kind != SOCK_DIAG_BY_FAMILY {
                    continue;
                }
                sockets.push(parse_diag(&payload)?);
            }
        }
        Ok(sockets)
    }

    /// `SOCK_DIAG_BY_FAMILY` dump request: `inet_diag_req_v2` for TCP,
    /// every state, no socket filter.
    fn dump_request(seq: u32, family: u8) -> Vec<u8> {
        let mut m = header(
            SOCK_DIAG_BY_FAMILY,
            (libc::NLM_F_REQUEST | libc::NLM_F_DUMP) as u16,
            seq,
            56,
        );
        m.extend_from_slice(&[family, libc::IPPROTO_TCP as u8, 0, 0]);
        m.extend_from_slice(&u32::MAX.to_ne_bytes());
        m.extend_from_slice(&[0; 48]);
        m
    }

    fn parse_diag(p: &[u8]) -> io::Result<TcpSocket> {
        if p.len() < INET_DIAG_MSG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("short inet_diag_msg: {} bytes", p.len()),
            ));
        }
        let family = p[0] as libc::c_int;
        let ip = |b: &[u8]| -> io::Result<IpAddr> {
            match family {
                libc::AF_INET => Ok(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))),
                libc::AF_INET6 => {
                    let octets: [u8; 16] = b.try_into().expect("16-byte slice");
                    Ok(IpAddr::V6(Ipv6Addr::from(octets)).to_canonical())
                }
                other => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("inet_diag_msg of family {other}"),
                )),
            }
        };
        let word = |at: usize| u32::from_ne_bytes(p[at..at + 4].try_into().expect("4 bytes"));
        Ok(TcpSocket {
            state: p[1],
            src: SocketAddr::new(ip(&p[8..24])?, u16::from_be_bytes([p[4], p[5]])),
            dst: SocketAddr::new(ip(&p[24..40])?, u16::from_be_bytes([p[6], p[7]])),
            uid: word(64),
            inode: word(68),
        })
    }

    pub(super) fn route_is_local(ip: IpAddr) -> io::Result<bool> {
        let nl = Netlink::open(libc::NETLINK_ROUTE)?;
        nl.send(&route_request(1, ip))?;
        match nl.replies(1, false) {
            Ok(msgs) => match msgs.first() {
                // rtmsg: family, dst_len, src_len, tos, table, protocol,
                // scope, type.
                Some((RTM_NEWROUTE, p)) if p.len() >= 12 => Ok(p[7] == RTN_LOCAL),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "route lookup answered with no route",
                )),
            },
            // The local table is consulted first, so a lookup that fails
            // further on (an unreachable or prohibit route, none at all)
            // found no local route.
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENETUNREACH | libc::EHOSTUNREACH | libc::EACCES)
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// `RTM_GETROUTE` for `ip`, as `ip route get` sends it.
    fn route_request(seq: u32, ip: IpAddr) -> Vec<u8> {
        let (family, octets) = match ip {
            IpAddr::V4(v4) => (libc::AF_INET as u8, v4.octets().to_vec()),
            IpAddr::V6(v6) => (libc::AF_INET6 as u8, v6.octets().to_vec()),
        };
        // 8 or 20 bytes: already 4-aligned.
        let attr_len = 4 + octets.len();
        let mut m = header(RTM_GETROUTE, libc::NLM_F_REQUEST as u16, seq, 12 + attr_len);
        m.extend_from_slice(&[family, (octets.len() * 8) as u8, 0, 0, 0, 0, 0, 0]);
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(&(attr_len as u16).to_ne_bytes());
        m.extend_from_slice(&RTA_DST.to_ne_bytes());
        m.extend_from_slice(&octets);
        m
    }

    /// `nlmsghdr` for a message with `payload` bytes after it; the port id
    /// is left to the kernel.
    fn header(kind: u16, flags: u16, seq: u32, payload: usize) -> Vec<u8> {
        let mut m = Vec::with_capacity(NLMSG_HDRLEN + payload);
        m.extend_from_slice(&((NLMSG_HDRLEN + payload) as u32).to_ne_bytes());
        m.extend_from_slice(&kind.to_ne_bytes());
        m.extend_from_slice(&flags.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m
    }

    struct Netlink {
        fd: OwnedFd,
    }

    impl Netlink {
        fn open(protocol: libc::c_int) -> io::Result<Self> {
            // SAFETY: plain socket(2); the result is checked before use.
            let fd = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    protocol,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: a fresh descriptor this function alone owns.
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            // The accept path waits on this, so a kernel that never answers
            // costs a second, not the feed.
            let timeout = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            // SAFETY: a valid descriptor and a timeval of the size given.
            let rc = unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    (&timeout as *const libc::timeval).cast(),
                    mem::size_of::<libc::timeval>() as libc::socklen_t,
                )
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { fd })
        }

        fn send(&self, msg: &[u8]) -> io::Result<()> {
            // SAFETY: zeroed sockaddr_nl is the kernel's address (pid 0).
            let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
            kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            // SAFETY: `msg` and `kernel` are valid for the lengths given.
            let n = unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    msg.as_ptr().cast(),
                    msg.len(),
                    0,
                    (&kernel as *const libc::sockaddr_nl).cast(),
                    mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        /// The reply to request `seq`, as (type, payload) pairs: up to
        /// `NLMSG_DONE` for a dump, its one message otherwise. An
        /// `NLMSG_ERROR` carrying an errno is that error.
        fn replies(&self, seq: u32, dump: bool) -> io::Result<Vec<(u16, Vec<u8>)>> {
            let mut out = Vec::new();
            let mut buf = vec![0u8; RECV_BUF];
            loop {
                // SAFETY: `buf` is valid for its length.
                let n = unsafe {
                    libc::recv(
                        self.fd.as_raw_fd(),
                        buf.as_mut_ptr().cast(),
                        buf.len(),
                        libc::MSG_TRUNC,
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                let n = n as usize;
                if n > buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("netlink message of {n} bytes truncated"),
                    ));
                }
                let mut at = 0;
                while at + NLMSG_HDRLEN <= n {
                    let len = u32::from_ne_bytes(buf[at..at + 4].try_into().expect("4")) as usize;
                    let kind = u16::from_ne_bytes(buf[at + 4..at + 6].try_into().expect("2"));
                    let mseq = u32::from_ne_bytes(buf[at + 8..at + 12].try_into().expect("4"));
                    if len < NLMSG_HDRLEN || at + len > n {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "malformed netlink message",
                        ));
                    }
                    let payload = &buf[at + NLMSG_HDRLEN..at + len];
                    at += (len + 3) & !3;
                    if mseq != seq {
                        continue;
                    }
                    match kind as libc::c_int {
                        libc::NLMSG_ERROR | libc::NLMSG_DONE => {
                            let errno = payload
                                .get(..4)
                                .map_or(0, |b| i32::from_ne_bytes(b.try_into().expect("4")));
                            if errno < 0 {
                                return Err(io::Error::from_raw_os_error(-errno));
                            }
                            return Ok(out);
                        }
                        _ => {
                            out.push((kind, payload.to_vec()));
                            if !dump {
                                return Ok(out);
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRR: u32 = 124;
    const OTHER: u32 = 1000;

    fn sa(s: &str) -> SocketAddr {
        s.parse().expect("socket address")
    }

    fn live(src: &str, dst: &str, uid: u32) -> TcpSocket {
        TcpSocket {
            state: TCP_ESTABLISHED,
            src: sa(src),
            dst: sa(dst),
            uid,
            inode: 4242,
        }
    }

    fn never_asked() -> io::Result<bool> {
        panic!("a peer with a socket here needs no route lookup")
    }

    const LISTEN: &str = "127.0.0.1:1179";
    const PEER: &str = "127.0.0.1:40000";

    #[test]
    fn a_live_socket_of_an_allowed_account_is_local() {
        let table = [live(PEER, LISTEN, FRR)];
        let got = judge(&table, sa(LISTEN), sa(PEER), &[0, FRR], never_asked);
        assert_eq!(got.expect("admitted"), Peer::Local { uid: FRR });
    }

    /// bgpd's outbound socket is root's, so root is admitted with no
    /// account configured at all.
    #[test]
    fn root_is_admitted() {
        let table = [live(PEER, LISTEN, 0)];
        let got = judge(&table, sa(LISTEN), sa(PEER), &[0], never_asked);
        assert_eq!(got.expect("admitted"), Peer::Local { uid: 0 });
    }

    /// The finding: an unprivileged local process on a free feed slot.
    #[test]
    fn another_account_is_refused() {
        let table = [live(PEER, LISTEN, OTHER)];
        let got = judge(&table, sa(LISTEN), sa(PEER), &[0, FRR], never_asked);
        assert!(
            matches!(got, Err(Refusal::Account { uid: OTHER })),
            "{got:?}"
        );
    }

    /// Written and closed: 5.15 reports such a socket's uid as root, with
    /// inode 0. It must not pass as root.
    #[test]
    fn an_orphaned_socket_reading_as_root_is_refused() {
        let mut orphan = live(PEER, LISTEN, 0);
        orphan.inode = 0;
        orphan.state = 4; // FIN_WAIT1
        let got = judge(&[orphan], sa(LISTEN), sa(PEER), &[0], never_asked);
        assert!(matches!(got, Err(Refusal::NotOpen { state: 4 })), "{got:?}");

        // And inode 0 alone refuses, whatever state was read before it.
        orphan.state = TCP_ESTABLISHED;
        let got = judge(&[orphan], sa(LISTEN), sa(PEER), &[0], never_asked);
        assert!(matches!(got, Err(Refusal::NotOpen { .. })), "{got:?}");
    }

    #[test]
    fn a_half_closed_socket_is_refused() {
        let mut half = live(PEER, LISTEN, FRR);
        half.state = 5; // FIN_WAIT2
        let got = judge(&[half], sa(LISTEN), sa(PEER), &[0, FRR], never_asked);
        assert!(matches!(got, Err(Refusal::NotOpen { state: 5 })), "{got:?}");
    }

    /// Only the peer's own socket decides: ours (the reverse pair) and
    /// unrelated sockets of other accounts do not.
    #[test]
    fn only_the_peer_socket_is_judged() {
        let table = [
            live(LISTEN, PEER, OTHER),
            live("127.0.0.1:40001", LISTEN, OTHER),
            live(PEER, LISTEN, FRR),
        ];
        let got = judge(&table, sa(LISTEN), sa(PEER), &[0, FRR], never_asked);
        assert_eq!(got.expect("admitted"), Peer::Local { uid: FRR });
    }

    /// An IPv6 socket connecting to a v4-mapped address reaches an IPv4
    /// listener; the two ends still pair up.
    #[test]
    fn a_v4_mapped_peer_pairs_with_its_ipv4_view() {
        let table = [live(
            "[::ffff:127.0.0.1]:40000",
            "[::ffff:127.0.0.1]:1179",
            OTHER,
        )];
        let table: Vec<TcpSocket> = table
            .iter()
            .map(|s| TcpSocket {
                src: canonical(s.src),
                dst: canonical(s.dst),
                ..*s
            })
            .collect();
        let got = judge(&table, sa(LISTEN), sa(PEER), &[0], never_asked);
        assert!(
            matches!(got, Err(Refusal::Account { uid: OTHER })),
            "{got:?}"
        );
        let got = judge(
            &table,
            sa("[::ffff:127.0.0.1]:1179"),
            sa("[::ffff:127.0.0.1]:40000"),
            &[0],
            never_asked,
        );
        assert!(
            matches!(got, Err(Refusal::Account { uid: OTHER })),
            "{got:?}"
        );
    }

    #[test]
    fn no_socket_from_a_remote_address_is_remote() {
        let got = judge(
            &[],
            sa("192.0.2.1:1179"),
            sa("198.51.100.7:40000"),
            &[0],
            || Ok(false),
        );
        assert_eq!(got.expect("admitted"), Peer::Remote);
    }

    /// Reset or long closed while it waited to be accepted: its data must
    /// not be read as a feed.
    #[test]
    fn no_socket_from_a_local_address_is_refused() {
        let got = judge(
            &[],
            sa("192.0.2.1:1179"),
            sa("192.0.2.9:40000"),
            &[0],
            || Ok(true),
        );
        assert!(matches!(got, Err(Refusal::Vanished)), "{got:?}");
    }

    #[test]
    fn a_failed_route_lookup_refuses() {
        let got = judge(
            &[],
            sa("192.0.2.1:1179"),
            sa("198.51.100.7:40000"),
            &[0],
            || Err(io::Error::other("no netlink")),
        );
        assert!(matches!(got, Err(Refusal::Lookup(_))), "{got:?}");
    }

    #[test]
    fn peers_always_hold_root() {
        assert_eq!(LocalPeers::root_only().uids(), &[0]);
        assert_eq!(
            LocalPeers::root_only().and_uid(7).and_uid(0).uids(),
            &[0, 7]
        );
        assert_eq!(LocalPeers::resolve(Some("0")).expect("root").uids(), &[0]);
        assert_eq!(
            LocalPeers::resolve(Some("124")).expect("uid").uids(),
            &[0, 124]
        );
        assert!(LocalPeers::resolve(None)
            .expect("defaults")
            .uids()
            .contains(&0));
    }

    #[test]
    fn an_unknown_peer_user_fails_the_start() {
        let err = LocalPeers::resolve(Some("pf-no-such-account")).expect_err("unknown");
        assert!(err.contains("no such account"), "{err}");
    }

    // --- against this host's kernel -------------------------------------

    /// Unprivileged: socket diagnostics and route lookups need no
    /// capability.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_kernel_answers_the_self_test() {
        self_test().expect("inet_diag and route lookup");
    }

    /// This process's own loopback connection, judged through the real
    /// socket table: admitted when its uid is allowed, refused otherwise.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_real_loopback_connection_is_judged_by_its_owner() {
        let me = unsafe { libc::geteuid() };
        let lst = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let client =
            std::net::TcpStream::connect(lst.local_addr().expect("addr")).expect("connect");
        let (accepted, peer) = lst.accept().expect("accept");
        let local = accepted.local_addr().expect("local");

        let mine = LocalPeers::root_only().and_uid(me);
        assert_eq!(
            mine.check(local, peer).expect("own uid admitted"),
            Peer::Local { uid: me }
        );
        if me != 0 {
            let got = LocalPeers::root_only().check(local, peer);
            assert!(
                matches!(got, Err(Refusal::Account { uid }) if uid == me),
                "{got:?}"
            );
        }

        // Closed by its owner: refused even when the owner is allowed.
        drop(client);
        let got = mine.check(local, peer);
        assert!(
            matches!(got, Err(Refusal::NotOpen { .. })),
            "a closed peer socket must be refused: {got:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn this_hosts_addresses_are_local_and_documentation_ones_are_not() {
        assert!(is_local_address(IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("lookup"));
        assert!(route_is_local(IpAddr::V4(Ipv4Addr::LOCALHOST)).expect("lookup"));
        // RFC 5737: routed (or unreachable) here, never local.
        assert!(!route_is_local("198.51.100.7".parse().expect("ip")).expect("lookup"));
    }
}
