//! The convergence engine against a fake VPP on a real unix socket.
//!
//! The unit tests in `engine.rs` cover its bookkeeping; this covers the
//! thing that cannot be unit-tested — that attach, resync, drain and
//! verify **compose** over one live transport, in the right order, and
//! that what reaches the wire is what the ledger claims.
//!
//! Assertions are on decoded requests, not on byte offsets. The fake
//! decodes `ip_route_add_del` with the same generated `Decode` impl the
//! client encodes with, and builds reply headers from `MESSAGE_META`
//! rather than assuming `[id][context]` — header geometry is per-message
//! (`dev_create_port_if_reply` carries a `client_index`, its sibling
//! `dev_attach_reply` does not), and a hand-assumed prefix here would
//! quietly match a hand-assumed prefix in the client and prove nothing.
//!
//! What it deliberately does NOT model is forwarding. Whether VPP
//! actually moves packets is gate 0b's job on hardware, and nothing here
//! should be read as evidence about that.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

use packetframe_common::fib::IpPrefix;
use packetframe_vpp_offload::attach::{AttachMode, PortAttach};
use packetframe_vpp_offload::engine::{ConvergenceEngine, RouteSource};
use packetframe_vpp_offload::fib_sync::FamilyPolicy;
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
const ASSIGNED_INDEX: u32 = 3;

/// Link-layer address the fake mirror hands out for its one neighbour.
const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

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
struct WireRoute {
    is_add: bool,
    /// First four address bytes + prefix length, enough to identify the
    /// v4 prefixes these tests use.
    addr: [u8; 4],
    len: u8,
    /// Interface indices the paths reference.
    path_indices: Vec<u32>,
}

#[derive(Debug, Clone)]
enum Event {
    Msg(String),
    Route(WireRoute),
    Neighbour {
        sw_if_index: u32,
        mac: [u8; 6],
        flags: u8,
    },
}

struct Fake {
    path: PathBuf,
    _dir: tempdir::TempDir,
    events: Receiver<Event>,
}

/// How the fake misbehaves.
#[derive(Clone, Copy, Default)]
struct Behaviour {
    /// Drop the connection after this many route ops.
    hangup_after: Option<usize>,
    /// Reject this many *deletes* with a non-zero retval before
    /// accepting them.
    reject_deletes: usize,
}

impl Fake {
    fn start(tag: &str) -> Self {
        Self::start_behaving(tag, Behaviour::default())
    }

    /// Drop the connection after `hangup_after` route ops — the
    /// mid-drain failure the unwind path exists for.
    ///
    /// **One-shot, deliberately.** The point of the test is that a fresh
    /// connection can finish the job, so a fake that hung up on every
    /// connection would make recovery untestable rather than testing it.
    fn start_with(tag: &str, hangup_after: usize) -> Self {
        Self::start_behaving(
            tag,
            Behaviour {
                hangup_after: Some(hangup_after),
                ..Default::default()
            },
        )
    }

    fn start_behaving(tag: &str, behaviour: Behaviour) -> Self {
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

    fn drain_events(&self) -> Vec<Event> {
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

fn v4(a: u8, b: u8) -> IpPrefix {
    IpPrefix::V4 {
        addr: [10, a, b, 0],
        prefix_len: 24,
    }
}

fn nh() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
}

struct Mirror {
    routes: Vec<IpPrefix>,
}

impl RouteSource for Mirror {
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        for p in &self.routes {
            visit(*p, &[nh()]);
        }
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(nh(), "eth4", MAC);
    }
}

fn mirror(n: u8) -> Mirror {
    Mirror {
        routes: (0..n).map(|i| v4(0, i)).collect(),
    }
}

fn engine_for(fake: &Fake) -> ConvergenceEngine {
    ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
        }],
        vec!["eth4".into()],
        1_000_000,
        FamilyPolicy::V4Only,
    )
}

/// Drain until the pending map reports empty, with a bound so a
/// regression that never converges fails instead of hanging CI.
fn drain_to_empty(e: &mut ConvergenceEngine) -> usize {
    for pass in 1..=64 {
        let (done, _) = e.drain_batch().expect("drain succeeds against the fake");
        if done {
            return pass;
        }
    }
    panic!("resync did not converge in 64 drains");
}

/// The composition test: one transport, the whole pipeline, in order.
#[test]
fn the_convergence_pipeline_composes_over_one_transport() {
    let fake = Fake::start("pipeline");
    let mut e = engine_for(&fake);

    assert!(e.api_ready(), "the fake must answer the handshake");
    e.attach_devices(AttachMode::Fresh).expect("attach");
    assert_eq!(e.port_links().len(), 1);

    let m = mirror(10);
    let plan = e.begin_resync(&m);
    assert_eq!(plan.upserts, 10);
    drain_to_empty(&mut e);

    assert_eq!(e.counts().installed, 10, "every route acknowledged");
    assert_eq!(e.counts().installing, 0, "nothing left in flight");
    assert!(e.pending().is_empty());

    let outcome = e.run_verify().expect("verify");
    assert!(outcome.passed(), "{}", outcome.summary());

    // Ordering: devices attach before any route is installed. FIB paths
    // reference indices VPP has not assigned yet otherwise, and every
    // route would be deferred — correct, but a wasted cycle.
    let names: Vec<String> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Msg(n) => Some(n),
            _ => None,
        })
        .collect();
    let first_attach = names.iter().position(|n| n == "dev_attach").unwrap();
    let first_route = names.iter().position(|n| n == "ip_route_add_del").unwrap();
    assert!(
        first_attach < first_route,
        "devices must attach before routes: {names:?}"
    );
}

/// Every installed path must carry the index VPP assigned, not one the
/// module guessed. A path on the wrong index forwards nothing while
/// looking perfectly installed.
#[test]
fn routes_install_onto_the_index_vpp_assigned() {
    let fake = Fake::start("index");
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();
    e.begin_resync(&mirror(4));
    drain_to_empty(&mut e);

    let routes: Vec<WireRoute> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Route(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(routes.len(), 4);
    for r in &routes {
        assert!(r.is_add);
        assert_eq!(
            r.path_indices,
            vec![ASSIGNED_INDEX],
            "path must reference the index from dev_create_port_if_reply"
        );
    }
}

/// The diff, observed on the wire. A prefix the source dropped must
/// reach VPP as a delete — an add-only resync leaves it forwarding to a
/// nexthop nobody advertises, and readback verification cannot see it
/// because verification samples what the ledger claims.
#[test]
fn a_prefix_the_source_dropped_reaches_vpp_as_a_delete() {
    let fake = Fake::start("withdraw");
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();

    e.begin_resync(&mirror(5));
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 5);
    let _ = fake.drain_events();

    // Two prefixes disappear from the source.
    let shrunk = Mirror {
        routes: mirror(5).routes[..3].to_vec(),
    };
    let plan = e.begin_resync(&shrunk);
    assert_eq!(plan.withdrawals, 2);
    drain_to_empty(&mut e);

    let deletes: Vec<WireRoute> = fake
        .drain_events()
        .into_iter()
        .filter_map(|ev| match ev {
            Event::Route(r) if !r.is_add => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(deletes.len(), 2, "both dropped prefixes must be deleted");
    let mut got: Vec<(u8, u8, u8)> = deletes
        .iter()
        .map(|r| (r.addr[1], r.addr[2], r.len))
        .collect();
    got.sort_unstable();
    assert_eq!(
        got,
        vec![(0, 3, 24), (0, 4, 24)],
        "the two the source dropped, at their own prefix lengths"
    );

    // And the ledger must no longer claim them.
    assert_eq!(e.counts().installed, 3);
}

/// A connection that dies mid-drain must leave nothing claimed that VPP
/// did not acknowledge, put the unacknowledged work back, and drop the
/// socket so the next attempt reconnects rather than reusing a stream
/// whose framing may be desynchronised.
#[test]
fn a_hangup_mid_drain_requeues_and_disconnects() {
    let fake = Fake::start_with("hangup", 3);
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();
    e.begin_resync(&mirror(20));

    let err = loop {
        match e.drain_batch() {
            Ok((true, _)) => panic!("the fake hung up; this cannot converge"),
            Ok((false, _)) => continue,
            Err(err) => break err,
        }
    };
    let _ = err;

    assert!(
        !e.is_connected(),
        "a broken socket must be dropped, not reused"
    );
    let c = e.counts();
    assert_eq!(c.installing, 0, "nothing may be left claimed in flight");
    assert!(
        c.installed <= 3,
        "only acknowledged routes may count as installed, got {}",
        c.installed
    );
    assert!(
        !e.pending().is_empty(),
        "unacknowledged work must still be owed"
    );

    // A fresh connection can finish the job.
    assert!(e.api_ready(), "must be able to reconnect");
    e.attach_devices(AttachMode::Fresh).unwrap();
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 20);
    assert!(e.run_verify().unwrap().passed());
}

/// A mirror that still advertises the prefix but no longer resolves its
/// nexthop — the shape the rebuilt device map produces when a neighbour
/// disappears.
struct OrphanedMirror {
    routes: Vec<IpPrefix>,
}

impl RouteSource for OrphanedMirror {
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        for p in &self.routes {
            visit(*p, &[nh()]);
        }
    }
    /// No neighbours: the nexthop is gone.
    fn for_each_neighbour(&self, _visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {}
}

/// When an advertised prefix loses every VPP-reachable nexthop, the stale
/// route must leave VPP **and** the prefix must be recorded as
/// unresolvable.
///
/// Recording it before the delete was acknowledged meant a successful
/// delete hit `forget`, which erased the state — so `verify` saw
/// `unresolvable == 0`, never sampled the prefix, and the supervisor
/// could steer traffic into a table with a known hole.
#[test]
fn a_prefix_that_loses_its_nexthops_is_deleted_and_recorded_unresolvable() {
    let fake = Fake::start("orphan");
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();

    e.begin_resync(&mirror(3));
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 3);
    let _ = fake.drain_events();

    // Same prefixes, no reachable nexthop.
    e.begin_resync(&OrphanedMirror {
        routes: mirror(3).routes,
    });
    drain_to_empty(&mut e);

    // The stale routes actually left VPP.
    let deletes = fake
        .drain_events()
        .into_iter()
        .filter(|ev| matches!(ev, Event::Route(r) if !r.is_add))
        .count();
    assert_eq!(deletes, 3, "every stale route must be withdrawn");

    // And the hole is on the books.
    let c = e.counts();
    assert_eq!(c.installed, 0);
    assert_eq!(
        c.unresolvable, 3,
        "the prefixes are still advertised and still unreachable"
    );
    assert!(
        c.blocks_first_steer(),
        "a table with a known hole must not be steered into"
    );
    // Verification must agree, not report a clean table.
    let outcome = e.run_verify().unwrap();
    assert!(!outcome.passed(), "{}", outcome.summary());
    assert_eq!(outcome.unresolvable, 3);
}

/// A per-route refusal of that derived delete must be retried, not
/// swallowed.
///
/// Recording `Unresolvable` before the ack left the requeued upsert
/// seeing `was_installed == false`, so it stopped re-sending the delete
/// — a transient refusal became permanent with the stale route still
/// live in VPP and verification failing forever.
#[test]
fn a_refused_derived_delete_is_retried() {
    let fake = Fake::start_behaving(
        "orphan-reject",
        Behaviour {
            hangup_after: None,
            reject_deletes: 1,
        },
    );
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();

    e.begin_resync(&mirror(1));
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 1);
    let _ = fake.drain_events();

    // Nexthop vanishes. The first delete is refused.
    e.begin_resync(&OrphanedMirror {
        routes: mirror(1).routes,
    });
    let (done, stats) = e.drain_batch().unwrap();
    assert_eq!(stats.rejected, 1, "the fake refused the delete");
    assert!(!done, "a refused op stays owed");
    assert_eq!(
        e.counts().installed,
        1,
        "the route is still live in VPP, so the ledger must still say so \
         — otherwise nothing knows to retry the delete"
    );

    // The retry goes out and succeeds.
    drain_to_empty(&mut e);
    let deletes = fake
        .drain_events()
        .into_iter()
        .filter(|ev| matches!(ev, Event::Route(r) if !r.is_add))
        .count();
    assert_eq!(deletes, 2, "one refused delete, one successful retry");
    assert_eq!(e.counts().installed, 0);
    assert_eq!(e.counts().unresolvable, 1);
}

/// Static neighbours must be programmed, on the index VPP assigned, and
/// **before** the routes that depend on them.
///
/// VPP starts without `linux-cp` and MCAM rules match IP fields, so an
/// ARP frame can never be steered to it — VPP physically cannot learn a
/// neighbour. Skip this and route installs are still acknowledged and
/// readback verification still passes (it checks a path exists on an
/// interface we own, not that the adjacency resolves) while every packet
/// is dropped on an incomplete adjacency. Nothing else in the module
/// would report a fault, which is what makes it worth a wire test.
#[test]
fn static_neighbours_are_programmed_before_the_routes_that_need_them() {
    let fake = Fake::start("nbr");
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();

    let m = mirror(4);
    // The mapping has to exist before neighbours can be resolved to an
    // interface, which is what the resync's refresh does.
    e.begin_resync(&m);
    assert_eq!(e.program_neighbours(&m).unwrap(), 1);
    drain_to_empty(&mut e);

    let events = fake.drain_events();
    let neighbours: Vec<_> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Neighbour {
                sw_if_index,
                mac,
                flags,
            } => Some((*sw_if_index, *mac, *flags)),
            _ => None,
        })
        .collect();
    assert_eq!(neighbours.len(), 1, "the one reachable nexthop");
    assert_eq!(
        neighbours[0].0, ASSIGNED_INDEX,
        "the adjacency must sit on the index VPP assigned"
    );
    assert_eq!(neighbours[0].1, MAC, "the resolved link-layer address");
    assert_eq!(
        neighbours[0].2, 1,
        "STATIC: VPP cannot ARP to refresh it, so an ageing entry would \
         silently become an unresolved adjacency"
    );

    // Ordering, on the wire.
    let names: Vec<&str> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Msg(n) => Some(n.as_str()),
            _ => None,
        })
        .collect();
    let first_nbr = names.iter().position(|n| *n == "ip_neighbor_add_del");
    let first_route = names.iter().position(|n| *n == "ip_route_add_del");
    assert!(
        first_nbr.is_some() && first_nbr < first_route,
        "neighbours before routes: {names:?}"
    );
}

/// A neighbour whose device is not VPP-owned is skipped, not refused —
/// same policy the route mapping applies, for the same reason: a
/// management or tunnel neighbour is not an error, it is not ours.
#[test]
fn neighbours_on_foreign_devices_are_skipped() {
    struct MixedMirror;
    impl RouteSource for MixedMirror {
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            visit(v4(0, 0), &[nh()]);
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(nh(), "eth4", MAC);
            // Management: excluded by the nexthop mapping.
            visit(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
                "eth0",
                [0x02, 0, 0, 0, 0, 9],
            );
        }
    }

    let fake = Fake::start("fgn");
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();
    e.begin_resync(&MixedMirror);
    assert_eq!(
        e.program_neighbours(&MixedMirror).unwrap(),
        1,
        "only the member-port neighbour"
    );
}
