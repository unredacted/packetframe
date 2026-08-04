//! The shared fake VPP: a real unix socket speaking the real wire
//! format, built from the same generated types the client encodes with.
//!
//! Extracted from `vpp_engine.rs` so new integration tests do not grow a
//! fourth divergent copy (loopback and attach_verify predate it and
//! still carry their own — migrating them is recorded follow-up work).
//! Reply headers come from `MESSAGE_META` because header geometry is
//! per-message; a hand-assumed prefix here would quietly match a
//! hand-assumed prefix in the client and prove nothing.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use packetframe_common::fib::IpPrefix;
use std::net::{IpAddr, Ipv4Addr};

use packetframe_vpp_offload::vpp_api::codec::{
    parse_frame_header, peek_msg_id, write_frame_header, Decode, Decoder, Encode, MSG_HEADER_LEN,
    SOCKCLNT_CREATE_MSG_ID,
};
use packetframe_vpp_offload::vpp_api::generated::{
    ControlPingReply, DevAttachReply, DevCreatePortIfReply, FibPath, IpNeighborAddDel,
    IpNeighborAddDelReply, IpRoute, IpRouteAddDel, IpRouteAddDelReply, IpRouteLookupReply,
    MessageTableEntry, SockclntCreateReply, SwInterfaceDetails, SwInterfaceSetFlagsReply,
    MESSAGE_META,
};

/// The index the fake's `dev_create_port_if` hands out. Routes must
/// install onto *this*, learned from VPP, never onto a guess.
pub const ASSIGNED_INDEX: u32 = 3;

/// Link-layer address the fake mirror hands out for its one neighbour.
pub const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

fn id_for(name: &str) -> u16 {
    100 + MESSAGE_META.iter().position(|m| m.name == name).unwrap() as u16
}

fn name_for(id: u16) -> &'static str {
    MESSAGE_META[(id - 100) as usize].name
}

fn reply_head(name: &str) -> Vec<u8> {
    let meta = MESSAGE_META
        .iter()
        .find(|m| m.name == name)
        .expect("known reply");
    let mut out = Vec::new();
    out.extend_from_slice(&id_for(name).to_be_bytes());
    if meta.client_index_prefix {
        out.extend_from_slice(&7u32.to_be_bytes());
    }
    out
}

fn read_frame(s: &mut UnixStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; MSG_HEADER_LEN];
    s.read_exact(&mut hdr).ok()?;
    let len = parse_frame_header(&hdr) as usize;
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).ok()?;
    Some(payload)
}

fn write_frame(s: &mut UnixStream, payload: &[u8]) {
    let mut framed = Vec::new();
    write_frame_header(&mut framed, payload.len());
    framed.extend_from_slice(payload);
    let _ = s.write_all(&framed);
    let _ = s.flush();
}

fn request_context(payload: &[u8]) -> u32 {
    u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]])
}

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
        reply.message_table.push(MessageTableEntry {
            index: 100 + i as u16,
            name: format!("{}_{}", m.name, m.crc.trim_start_matches("0x")),
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
                IpRouteLookupReply {
                    context: ctx,
                    retval: 0,
                    route: IpRoute {
                        table_id: 0,
                        stats_index: 0,
                        prefix: prefix_of(v4(10, 0)),
                        n_paths: 1,
                        paths: vec![path_on(ASSIGNED_INDEX)],
                    },
                }
                .encode(&mut out);
            }
            // DUMP: one details frame per interface, no terminator — the
            // trailing control_ping's reply ends the stream, as VPP does.
            "sw_interface_dump" => {
                let mut d = reply_head("sw_interface_details");
                details(ASSIGNED_INDEX, "octeon0/0", 3, ctx).encode(&mut d);
                write_frame(sock, &d);
                continue;
            }
            "control_ping" => {
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
