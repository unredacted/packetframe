//! A socket-owned nftables OUTPUT policy for local route-feed connections.
//! The kernel compares the originating socket's UID before TCP admission.
//! The netlink descriptor owns the table for the lifetime of the listener.
use rtnetlink::sys::{protocols::NETLINK_NETFILTER, Socket, SocketAddr as NetlinkAddr};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;

pub(crate) struct LocalFeedGuard {
    _owner: Socket,
}

// linux/netfilter/nf_tables.h and nfnetlink.h. Attribute numbers are
// scoped to the expression type. Numeric attributes use network order;
// register literals match the byte order in which each expression loads them.
const NESTED: u16 = 1 << 15;
const NFT: u16 = (libc::NFNL_SUBSYS_NFTABLES as u16) << 8;
const REQUEST: u16 = libc::NLM_F_REQUEST as u16;
const CREATE: u16 = REQUEST | libc::NLM_F_CREATE as u16 | libc::NLM_F_ACK as u16;
const REG: u32 = 1;
const NFT_MSG_NEWTABLE: u16 = NFT;
const NFT_MSG_NEWCHAIN: u16 = NFT + 3;
const NFT_MSG_NEWRULE: u16 = NFT + 6;
const NFT_TABLE_F_OWNER: u32 = 2;
const NFT_META_SKUID: u32 = 10;
const NFT_META_NFPROTO: u32 = 15;
const NFT_META_L4PROTO: u32 = 16;
const NETWORK_HEADER: u32 = 1;
const TRANSPORT_HEADER: u32 = 2;

fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
    let len = 4 + value.len();
    let mut bytes = Vec::with_capacity(len.next_multiple_of(4));
    bytes.extend_from_slice(&(len as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    bytes.resize(len.next_multiple_of(4), 0);
    bytes
}

fn number(kind: u16, value: u32) -> Vec<u8> {
    attr(kind, &value.to_be_bytes())
}

fn nested(kind: u16, fields: &[Vec<u8>]) -> Vec<u8> {
    attr(kind | NESTED, &fields.concat())
}

fn expression(name: &[u8], fields: &[Vec<u8>]) -> Vec<u8> {
    nested(1, &[attr(1, name), nested(2, fields)])
}

fn meta(key: u32) -> Vec<u8> {
    expression(b"meta\0", &[number(1, REG), number(2, key)])
}

fn payload(base: u32, offset: u32, length: u32) -> Vec<u8> {
    expression(
        b"payload\0",
        &[
            number(1, REG),
            number(2, base),
            number(3, offset),
            number(4, length),
        ],
    )
}

fn equals(value: &[u8]) -> Vec<u8> {
    expression(
        b"cmp\0",
        &[number(1, REG), number(2, 0), nested(3, &[attr(1, value)])],
    )
}

fn verdict(code: u32) -> Vec<u8> {
    expression(
        b"immediate\0",
        &[number(1, 0), nested(2, &[nested(2, &[number(1, code)])])],
    )
}

fn message(
    kind: u16,
    flags: u16,
    seq: u32,
    family: u8,
    resource: u16,
    attrs: &[Vec<u8>],
) -> Vec<u8> {
    let mut bytes = vec![0; 16];
    bytes.extend_from_slice(&[family, 0]);
    bytes.extend_from_slice(&resource.to_be_bytes());
    bytes.extend_from_slice(&attrs.concat());
    let length = bytes.len() as u32;
    bytes[..4].copy_from_slice(&length.to_ne_bytes());
    bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
    bytes[6..8].copy_from_slice(&flags.to_ne_bytes());
    bytes[8..12].copy_from_slice(&seq.to_ne_bytes());
    bytes
}

// Match an opening TCP SYN, including ECN and Fast Open. FINs and RSTs
// may outlive their socket file and must still reach an admitted connection.
fn opening_connection(addr: SocketAddr) -> Vec<Vec<u8>> {
    let mut rule = Vec::new();
    let ip = addr.ip().to_canonical();
    rule.extend([
        meta(NFT_META_NFPROTO),
        equals(&[if ip.is_ipv4() {
            libc::AF_INET as u8
        } else {
            libc::AF_INET6 as u8
        }]),
    ]);
    match ip {
        IpAddr::V4(ip) => rule.extend([payload(NETWORK_HEADER, 16, 4), equals(&ip.octets())]),
        IpAddr::V6(ip) => rule.extend([payload(NETWORK_HEADER, 24, 16), equals(&ip.octets())]),
    }
    rule.extend([
        meta(NFT_META_L4PROTO),
        equals(&[libc::IPPROTO_TCP as u8]),
        payload(TRANSPORT_HEADER, 2, 2),
        equals(&addr.port().to_be_bytes()),
        payload(TRANSPORT_HEADER, 13, 1),
    ]);
    rule.push(expression(
        b"bitwise\0",
        &[
            number(1, REG),
            number(2, REG),
            number(3, 1),
            nested(4, &[attr(1, &[0x12])]),
            nested(5, &[attr(1, &[0])]),
        ],
    ));
    rule.push(equals(&[0x02]));
    rule
}

impl LocalFeedGuard {
    /// Reserve the address, commit the policy, then allow TCP to listen.
    pub(crate) fn bind(
        addr: SocketAddr,
        uid: Option<u32>,
    ) -> io::Result<(tokio::net::TcpListener, Self)> {
        if addr.ip().to_canonical().is_unspecified() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "route-source requires a concrete listen address for its UID policy",
            ));
        }
        let socket = match addr {
            SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
            SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
        };
        if addr.ip().to_canonical().is_loopback() {
            socket.bind_device(Some(b"lo"))?;
        }
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        let guard = Self::install(socket.local_addr()?, uid)?;
        Ok((socket.listen(8)?, guard))
    }

    fn install(addr: SocketAddr, uid: Option<u32>) -> io::Result<Self> {
        if addr.ip().to_canonical().is_loopback() && uid.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "set peer-uid to the routing service's socket UID for local feeds",
            ));
        }
        if let Some(uid) = uid {
            // nft_meta maps an unmapped UID to the kernel overflow UID.
            let overflow_uid = std::fs::read_to_string("/proc/sys/kernel/overflowuid")?
                .trim()
                .parse::<u32>()
                .map_err(io::Error::other)?;
            if uid == overflow_uid || uid == u32::MAX {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "peer-uid must name a mapped, dedicated service account",
                ));
            }
        }
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        let owner = socket.bind_auto()?;
        socket.connect(&NetlinkAddr::new(0, 0))?;
        let timeout = libc::timeval {
            tv_sec: 3,
            tv_usec: 0,
        };
        // SAFETY: timeval is initialized and the descriptor is owned by socket.
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                size_of_val(&timeout) as _,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let table = format!("packetframe_feed_{}\0", owner.port_number());
        let table = table.as_bytes();
        let subsystem = libc::NFNL_SUBSYS_NFTABLES as u16;
        let mut batch = message(
            libc::NFNL_MSG_BATCH_BEGIN as _,
            REQUEST,
            1,
            0,
            subsystem,
            &[],
        );
        // NFT_TABLE_F_OWNER prevents another netlink client (including a
        // firewall reload) from modifying this table and removes it on close.
        batch.extend(message(
            NFT_MSG_NEWTABLE,
            CREATE | libc::NLM_F_EXCL as u16,
            2,
            libc::NFPROTO_INET as u8,
            0,
            &[attr(1, table), number(2, NFT_TABLE_F_OWNER)],
        ));
        // Filter after OUTPUT destination NAT, before local delivery.
        let chain = b"output\0";
        batch.extend(message(
            NFT_MSG_NEWCHAIN,
            CREATE,
            3,
            libc::NFPROTO_INET as u8,
            0,
            &[
                attr(1, table),
                attr(3, chain),
                attr(7, b"filter\0"),
                nested(
                    4,
                    &[
                        number(1, libc::NF_INET_LOCAL_OUT as u32),
                        number(2, i32::MAX as u32),
                    ],
                ),
                number(5, libc::NF_ACCEPT as u32),
            ],
        ));
        let mut seq = 4;
        let opening = opening_connection(addr);
        let mut append_rule = |exprs: Vec<Vec<u8>>| {
            batch.extend(message(
                NFT_MSG_NEWRULE,
                CREATE | libc::NLM_F_APPEND as u16,
                seq,
                libc::NFPROTO_INET as u8,
                0,
                &[attr(1, table), attr(2, chain), nested(4, &exprs)],
            ));
            seq += 1;
        };
        if let Some(uid) = uid {
            let mut allowed = opening.clone();
            allowed.extend([
                meta(NFT_META_SKUID),
                equals(&uid.to_ne_bytes()),
                verdict(libc::NF_ACCEPT as u32),
            ]);
            append_rule(allowed);
        }
        // Separate unconditional deny: skuid can be unavailable. A single
        // "skuid != uid" rule would fall through in that case.
        let mut denied = opening;
        denied.push(verdict(libc::NF_DROP as u32));
        append_rule(denied);
        batch.extend(message(
            libc::NFNL_MSG_BATCH_END as _,
            REQUEST,
            seq,
            0,
            subsystem,
            &[],
        ));
        socket.send(&batch, 0)?;
        let mut pending: std::collections::BTreeSet<_> = (2..seq).collect();
        while !pending.is_empty() {
            let (data, sender) = socket.recv_from_full()?;
            if sender.port_number() != 0 {
                continue;
            }
            let mut rest = data.as_slice();
            while rest.len() >= 20 {
                let len = u32::from_ne_bytes(rest[..4].try_into().unwrap()) as usize;
                if len < 20
                    || len.next_multiple_of(4) > rest.len()
                    || u16::from_ne_bytes(rest[4..6].try_into().unwrap())
                        != libc::NLMSG_ERROR as u16
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid nftables acknowledgement",
                    ));
                }
                let error = i32::from_ne_bytes(rest[16..20].try_into().unwrap());
                if error != 0 {
                    return Err(io::Error::from_raw_os_error(-error));
                }
                pending.remove(&u32::from_ne_bytes(rest[8..12].try_into().unwrap()));
                rest = &rest[len.next_multiple_of(4)..];
            }
            if !rest.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated nftables acknowledgement",
                ));
            }
        }
        Ok(Self { _owner: socket })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::time::Duration;

    // Invoked under two real service UIDs by the namespace test below.
    #[test]
    fn client_connect() {
        let Ok(addr) = std::env::var("PF_TEST_LOCAL_FEED_ADDR") else {
            return;
        };
        let addr = addr.parse().unwrap();
        let connected = TcpStream::connect_timeout(&addr, Duration::from_millis(350)).is_ok();
        assert_eq!(
            connected,
            std::env::var("PF_TEST_LOCAL_FEED_ALLOWED").unwrap() == "yes"
        );
    }

    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN and permission to change UID; reserves an ephemeral loopback port"]
    async fn only_the_service_uid_can_connect_and_reconnect() {
        for host in ["127.0.0.1", "::1", "::ffff:127.0.0.1"] {
            let addr = SocketAddr::new(host.parse().unwrap(), 0);
            let (listener, _guard) = LocalFeedGuard::bind(addr, Some(31001)).unwrap();
            let addr = listener.local_addr().unwrap();
            for (uid, allowed) in [(31002, false), (31001, true), (31002, false), (31001, true)] {
                let status = Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "fib::local_feed::tests::client_connect"])
                    .env("PF_TEST_LOCAL_FEED_ADDR", addr.to_string())
                    .env(
                        "PF_TEST_LOCAL_FEED_ALLOWED",
                        if allowed { "yes" } else { "no" },
                    )
                    .uid(uid)
                    .status()
                    .unwrap();
                assert!(status.success());
                if allowed {
                    drop(
                        tokio::time::timeout(Duration::from_secs(2), listener.accept())
                            .await
                            .unwrap()
                            .unwrap(),
                    );
                }
            }
        }
    }
}
