//! The shared fake VPP: a real unix socket speaking the real wire
//! format, built from the same generated types the client encodes with.
//!
//! Extracted from `vpp_engine.rs` so new integration tests do not grow a
//! divergent copy. `vpp_api_loopback.rs` and `vpp_attach_verify.rs` keep
//! their own **servers** deliberately — they script handshake failures,
//! CRC mismatches and device attach, and folding that into a fake built
//! to model success would complicate the shared one in service of tests
//! whose job is to break the protocol. What all three now share is
//! `wire.rs`: frame geometry, reply headers, context extraction.
//!
//! Reply headers come from `MESSAGE_META` because header geometry is
//! per-message; a hand-assumed prefix here would quietly match a
//! hand-assumed prefix in the client and prove nothing.
#![allow(dead_code)]

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use packetframe_common::fib::IpPrefix;
use std::net::{IpAddr, Ipv4Addr};

use packetframe_vpp_offload::vpp_api::codec::{
    peek_msg_id, Decode, Decoder, Encode, SOCKCLNT_CREATE_MSG_ID,
};
#[path = "wire.rs"]
mod wire;
use wire::{name_for, read_frame, reply_head, request_context, write_frame};

use packetframe_vpp_offload::vpp_api::generated::{
    Address, AddressUnion, ControlPingReply, DevAttachReply, DevCreatePortIfReply, FibPath,
    FibPathNh, IpNeighborAddDel, IpNeighborAddDelReply, IpRoute, IpRouteAddDel, IpRouteAddDelReply,
    IpRouteDetails, IpRouteLookupReply, MessageTableEntry, Prefix, SockclntCreateReply,
    SwInterfaceDetails, SwInterfaceSetFlagsReply, ADDRESS_IP4, FIB_API_PATH_NH_PROTO_IP4,
    FIB_API_PATH_TYPE_NORMAL, MESSAGE_META,
};

/// The index the fake's `dev_create_port_if` hands out. Routes must
/// install onto *this*, learned from VPP, never onto a guess.
pub const ASSIGNED_INDEX: u32 = 3;

/// Link-layer address the fake mirror hands out for its one neighbour.
pub const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

mod tempdir {
    use std::path::{Path, PathBuf};
    pub struct TempDir(PathBuf);
    impl TempDir {
        pub fn new(tag: &str) -> std::io::Result<Self> {
            let mut p = std::env::temp_dir();
            // Short by construction: a unix socket path is capped at
            // SUN_LEN (~104 bytes) and macOS $TMPDIR is already ~50 of
            // them, so a full nanosecond stamp overflows it and the
            // failure surfaces as an unrelated-looking bind error.
            p.push(format!(
                "pf-e{tag}-{}-{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
                    % 0x100_000
            ));
            std::fs::create_dir_all(&p)?;
            Ok(Self(p))
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// One route operation as the fake decoded it off the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireRoute {
    pub is_add: bool,
    /// First four address bytes + prefix length, enough to identify the
    /// v4 prefixes these tests use.
    pub addr: [u8; 4],
    pub len: u8,
    /// Interface indices the paths reference.
    pub path_indices: Vec<u32>,
}

#[derive(Debug, Clone)]
pub enum Event {
    Msg(String),
    Route(WireRoute),
    Neighbour {
        sw_if_index: u32,
        mac: [u8; 6],
        flags: u8,
    },
}

pub struct Fake {
    pub path: PathBuf,
    _dir: tempdir::TempDir,
    events: Receiver<Event>,
}

/// How the fake misbehaves.
#[derive(Clone, Copy, Default)]
pub struct Behaviour {
    /// Drop the connection after this many route ops.
    pub hangup_after: Option<usize>,
    /// Reject this many *deletes* with a non-zero retval before
    /// accepting them.
    pub reject_deletes: usize,
    /// Advertise garbage CRCs in the handshake's message table — the
    /// version-skew shape the transport must refuse loudly.
    pub garbage_crcs: bool,
    /// Stop answering `control_ping` after this many of them, WITHOUT
    /// closing the connection.
    ///
    /// Models a VPP whose main thread is busy: the client blocks in its
    /// synchronous socket read until the timeout in force. That is the
    /// shape that made `stop()` unbounded — a tick sitting inside an API
    /// call cannot observe the stop flag — and a hangup cannot model it,
    /// because a closed socket returns immediately.
    pub stall_pings_after: Option<usize>,
    /// Answer `ip_route_lookup` with a path on an interface the module
    /// does not own, so readback verification FAILS.
    ///
    /// The shape that matters: routes install cleanly, the drain
    /// completes, and only the verify catches that VPP's FIB is not what
    /// we asked for. It is also the only way to reach the supervisor's
    /// `VerifyFailed` teardown from a test, because the verdict arrives
    /// as an INJECTED event rather than from an ordinary tick.
    pub verify_mismatch: bool,
    /// Prefixes this VPP already holds when the client connects, as
    /// `(addr, len, sw_if_index, nexthop_is_set)`.
    ///
    /// Models a **surviving** VPP for the adoption path: its FIB is
    /// populated and the freshly started packetframe's ledger is not.
    /// `nexthop_is_set` false / an index we do not own reproduces VPP's
    /// own infrastructure routes, which the readback must leave alone —
    /// adopting those would hand them to the resync diff, and the next
    /// convergence would delete the connected and local routes VPP needs
    /// to resolve any adjacency at all.
    pub existing_routes: &'static [([u8; 4], u8, u32, bool)],
}

impl Fake {
    pub fn start(tag: &str) -> Self {
        Self::start_behaving(tag, Behaviour::default())
    }

    /// Drop the connection after `hangup_after` route ops — the
    /// mid-drain failure the unwind path exists for.
    ///
    /// **One-shot, deliberately.** The point of the test is that a fresh
    /// connection can finish the job, so a fake that hung up on every
    /// connection would make recovery untestable rather than testing it.
    pub fn start_with(tag: &str, hangup_after: usize) -> Self {
        Self::start_behaving(
            tag,
            Behaviour {
                hangup_after: Some(hangup_after),
                ..Default::default()
            },
        )
    }

    pub fn start_behaving(tag: &str, behaviour: Behaviour) -> Self {
        let dir = tempdir::TempDir::new(tag).unwrap();
        let path = dir.path().join("api.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx): (Sender<Event>, Receiver<Event>) = channel();

        thread::spawn(move || {
            let mut b = behaviour;
            // Accept repeatedly: a disconnect-and-reconnect is part of
            // what these tests exercise.
            while let Ok((mut sock, _)) = listener.accept() {
                serve(&mut sock, &tx, b);
                // One-shot hangup: the point of that test is that a fresh
                // connection can finish the job.
                b.hangup_after = None;
            }
        });

        Self {
            path,
            _dir: dir,
            events: rx,
        }
    }

    pub fn drain_events(&self) -> Vec<Event> {
        let mut v = Vec::new();
        while let Ok(e) = self.events.try_recv() {
            v.push(e);
        }
        v
    }
}

fn serve(sock: &mut UnixStream, tx: &Sender<Event>, mut behaviour: Behaviour) -> Option<()> {
    read_frame(sock)?;
    let mut reply = SockclntCreateReply {
        context: 1,
        response: 0,
        index: 7,
        count: MESSAGE_META.len() as u16,
        message_table: Vec::new(),
    };
    for (i, m) in MESSAGE_META.iter().enumerate() {
        let crc = if behaviour.garbage_crcs {
            "deadbeef".to_string()
        } else {
            m.crc.trim_start_matches("0x").to_string()
        };
        reply.message_table.push(MessageTableEntry {
            index: 100 + i as u16,
            name: format!("{}_{crc}", m.name),
        });
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(&SOCKCLNT_CREATE_MSG_ID.to_be_bytes());
    payload.extend_from_slice(&7u32.to_be_bytes());
    reply.encode(&mut payload);
    write_frame(sock, &payload);

    let mut routes_seen = 0usize;

    loop {
        let req = read_frame(sock)?;
        let id = peek_msg_id(&req).expect("msg id");
        let ctx = request_context(&req);
        let which = name_for(id);
        let _ = tx.send(Event::Msg(which.to_string()));

        let mut out;
        match which {
            "dev_attach" => {
                out = reply_head("dev_attach_reply");
                DevAttachReply {
                    context: ctx,
                    dev_index: 0,
                    retval: 0,
                    error_string: String::new(),
                }
                .encode(&mut out);
            }
            "dev_create_port_if" => {
                out = reply_head("dev_create_port_if_reply");
                DevCreatePortIfReply {
                    context: ctx,
                    sw_if_index: ASSIGNED_INDEX,
                    retval: 0,
                    error_string: String::new(),
                }
                .encode(&mut out);
            }
            "sw_interface_set_flags" => {
                out = reply_head("sw_interface_set_flags_reply");
                SwInterfaceSetFlagsReply {
                    context: ctx,
                    retval: 0,
                }
                .encode(&mut out);
            }
            "ip_route_add_del" => {
                // Decoded with the same generated impl the client
                // encodes with, so this asserts on the real wire.
                let mut d = Decoder::new(&req);
                let r = IpRouteAddDel::decode(&mut d).expect("decodes as a route op");
                let mut addr = [0u8; 4];
                addr.copy_from_slice(&r.route.prefix.address.un.0[..4]);
                let _ = tx.send(Event::Route(WireRoute {
                    is_add: r.is_add,
                    addr,
                    len: r.route.prefix.len,
                    path_indices: r.route.paths.iter().map(|p| p.sw_if_index).collect(),
                }));

                routes_seen += 1;
                if behaviour.hangup_after.is_some_and(|n| routes_seen > n) {
                    return None;
                }
                // Reject deletes for a while, so the retry path is
                // exercised against a per-route refusal rather than a
                // connection fault.
                let retval = if !r.is_add && behaviour.reject_deletes > 0 {
                    behaviour.reject_deletes -= 1;
                    -1
                } else {
                    0
                };
                out = reply_head("ip_route_add_del_reply");
                IpRouteAddDelReply {
                    context: ctx,
                    retval,
                    stats_index: 0,
                }
                .encode(&mut out);
            }
            "ip_neighbor_add_del" => {
                let mut d = Decoder::new(&req);
                let n = IpNeighborAddDel::decode(&mut d).expect("decodes as a neighbour op");
                let _ = tx.send(Event::Neighbour {
                    sw_if_index: n.neighbor.sw_if_index,
                    mac: n.neighbor.mac_address,
                    flags: n.neighbor.flags,
                });
                out = reply_head("ip_neighbor_add_del_reply");
                IpNeighborAddDelReply {
                    context: ctx,
                    retval: 0,
                    stats_index: 0,
                }
                .encode(&mut out);
            }
            "ip_route_lookup" => {
                out = reply_head("ip_route_lookup_reply");
                // A path on an index we never attached: present, ack'd,
                // and forwarding nowhere we control.
                let idx = if behaviour.verify_mismatch {
                    ASSIGNED_INDEX + 100
                } else {
                    ASSIGNED_INDEX
                };
                IpRouteLookupReply {
                    context: ctx,
                    retval: 0,
                    route: IpRoute {
                        table_id: 0,
                        stats_index: 0,
                        prefix: prefix_of(v4(10, 0)),
                        n_paths: 1,
                        paths: vec![path_on(idx)],
                    },
                }
                .encode(&mut out);
            }
            // DUMP: one details frame per interface, no terminator — the
            // trailing control_ping's reply ends the stream, as VPP does.
            "ip_route_dump" => {
                for &(addr, len, sw_if_index, has_nh) in behaviour.existing_routes {
                    let mut d = reply_head("ip_route_details");
                    IpRouteDetails {
                        context: ctx,
                        route: existing_route(addr, len, sw_if_index, has_nh),
                    }
                    .encode(&mut d);
                    write_frame(sock, &d);
                }
                continue;
            }
            "sw_interface_dump" => {
                let mut d = reply_head("sw_interface_details");
                details(ASSIGNED_INDEX, "octeon0/0", 3, ctx).encode(&mut d);
                write_frame(sock, &d);
                continue;
            }
            "control_ping" if behaviour.stall_pings_after == Some(0) => {
                // Silence, connection held open: the client blocks until
                // its read timeout.
                continue;
            }
            "control_ping" => {
                if let Some(n) = behaviour.stall_pings_after.as_mut() {
                    *n -= 1;
                }
                out = reply_head("control_ping_reply");
                ControlPingReply {
                    context: ctx,
                    retval: 0,
                    vpe_pid: 4242,
                }
                .encode(&mut out);
            }
            other => panic!("fake got unexpected message {other}"),
        }
        write_frame(sock, &out);
    }
}

/// One route as a surviving VPP would report it.
///
/// `has_nh` is the whole point: a real nexthop address plus a path type
/// of NORMAL on an interface we own is what our own drainer emits, and
/// is what the readback filter looks for. Leaving it zero produces the
/// shape of a connected route — attached, no nexthop — which must NOT be
/// adopted.
fn existing_route(addr: [u8; 4], len: u8, sw_if_index: u32, has_nh: bool) -> IpRoute {
    let mut un = [0u8; 16];
    un[..4].copy_from_slice(&addr);
    let mut nh_un = [0u8; 16];
    if has_nh {
        // 192.0.2.1, the same nexthop the tests' mirror advertises.
        nh_un[..4].copy_from_slice(&[192, 0, 2, 1]);
    }
    IpRoute {
        table_id: 0,
        stats_index: 0,
        prefix: Prefix {
            address: Address {
                af: ADDRESS_IP4,
                un: AddressUnion(un),
            },
            len,
        },
        n_paths: 1,
        paths: vec![FibPath {
            sw_if_index,
            table_id: 0,
            rpf_id: 0,
            weight: 1,
            preference: 0,
            r#type: FIB_API_PATH_TYPE_NORMAL,
            flags: 0,
            proto: FIB_API_PATH_NH_PROTO_IP4,
            nh: FibPathNh {
                address: AddressUnion(nh_un),
                via_label: 0,
                obj_id: 0,
                classify_table_index: 0,
            },
            n_labels: 0,
            label_stack: Default::default(),
        }],
    }
}

fn details(sw_if_index: u32, name: &str, flags: u32, context: u32) -> SwInterfaceDetails {
    SwInterfaceDetails {
        context,
        sw_if_index,
        sup_sw_if_index: sw_if_index,
        l2_address: [0u8; 6],
        flags,
        r#type: 0,
        link_duplex: 0,
        link_speed: 2_500_000,
        link_mtu: 9000,
        mtu: [9000, 0, 0, 0],
        sub_id: 0,
        sub_number_of_tags: 0,
        sub_outer_vlan_id: 0,
        sub_inner_vlan_id: 0,
        sub_if_flags: 0,
        vtr_op: 0,
        vtr_push_dot1q: 0,
        vtr_tag1: 0,
        vtr_tag2: 0,
        outer_tag: 0,
        b_dmac: [0u8; 6],
        b_smac: [0u8; 6],
        b_vlanid: 0,
        i_sid: 0,
        interface_name: name.to_string(),
        interface_dev_type: "octeon".into(),
        tag: String::new(),
    }
}

fn path_on(sw_if_index: u32) -> FibPath {
    FibPath {
        sw_if_index,
        table_id: 0,
        rpf_id: 0,
        weight: 1,
        preference: 0,
        r#type: 0,
        flags: 0,
        proto: 0,
        nh: Default::default(),
        n_labels: 0,
        label_stack: Default::default(),
    }
}

fn prefix_of(p: IpPrefix) -> packetframe_vpp_offload::vpp_api::generated::Prefix {
    packetframe_vpp_offload::fib_sync::to_prefix(p)
}

pub fn v4(a: u8, b: u8) -> IpPrefix {
    IpPrefix::V4 {
        addr: [10, a, b, 0],
        prefix_len: 24,
    }
}

pub fn nh() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
}
