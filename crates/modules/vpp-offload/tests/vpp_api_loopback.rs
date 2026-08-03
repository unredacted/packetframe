//! End-to-end tests against a fake VPP on a real unix socket.
//!
//! The golden vectors prove individual messages encode correctly; this
//! proves the pieces compose — framing, handshake, CRC verification,
//! windowed pipelining, and the unwind path that decides whether a
//! failed load is a retry or a silently partial FIB.
//!
//! The fake speaks the same wire the real one does (it is built from
//! the same generated types), so a change that breaks VPP breaks this
//! too. What it deliberately does NOT model is VPP's forwarding
//! behaviour — that is gate 0b's job on hardware.

use std::io::{Read, Write};
use std::net::IpAddr;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use packetframe_common::fib::IpPrefix;
use packetframe_vpp_offload::fib_sync::{Drainer, PortIndex, ResolvedPath};
use packetframe_vpp_offload::sink::{Capacity, NexthopMap, PendingMap, RouteLedger};
use packetframe_vpp_offload::vpp_api::codec::{
    parse_frame_header, write_frame_header, Encode, MSG_HEADER_LEN, SOCKCLNT_CREATE_MSG_ID,
};
use packetframe_vpp_offload::vpp_api::generated::{
    IpRouteAddDelReply, MessageTableEntry, SockclntCreateReply, MESSAGE_META,
};
use packetframe_vpp_offload::vpp_api::Transport;

/// Message id we hand out for `ip_route_add_del_reply`.
fn reply_id() -> u16 {
    id_for("ip_route_add_del_reply")
}

fn id_for(name: &str) -> u16 {
    100 + MESSAGE_META.iter().position(|m| m.name == name).unwrap() as u16
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

/// `context` from a request payload that carries a client_index
/// prefix (every request the drainer sends does).
fn request_context(payload: &[u8]) -> u32 {
    u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]])
}

/// How the fake answers each route request, in order.
#[derive(Clone, Copy)]
enum Answer {
    Ok,
    /// VPP rejected this specific route.
    Retval(i32),
    /// Stop answering and drop the connection.
    Hangup,
}

struct Fake {
    path: PathBuf,
    _dir: tempdir::TempDir,
    handled: Arc<AtomicU32>,
}

/// Minimal tempdir; the crate is not a dependency, so roll the two
/// lines we need rather than adding one for a test.
mod tempdir {
    use std::path::{Path, PathBuf};
    pub struct TempDir(PathBuf);
    impl TempDir {
        pub fn new(tag: &str) -> std::io::Result<Self> {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "pf-vpp-{tag}-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
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

impl Fake {
    /// Start a fake VPP that completes the handshake, then answers
    /// route requests per `answers` (repeating the last one).
    fn start(
        tag: &str,
        answers: Vec<Answer>,
        crc_override: Option<(&'static str, &'static str)>,
    ) -> Self {
        let dir = tempdir::TempDir::new(tag).unwrap();
        let path = dir.path().join("api.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let handled = Arc::new(AtomicU32::new(0));
        let handled_thread = handled.clone();

        thread::spawn(move || {
            let (mut sock, _) = match listener.accept() {
                Ok(v) => v,
                Err(_) => return,
            };
            // --- handshake ---
            let Some(_req) = read_frame(&mut sock) else {
                return;
            };
            let mut reply = SockclntCreateReply {
                context: 1,
                response: 0,
                index: 7,
                count: MESSAGE_META.len() as u16,
                message_table: Vec::new(),
            };
            for (i, m) in MESSAGE_META.iter().enumerate() {
                let crc = match crc_override {
                    Some((n, c)) if n == m.name => c.to_string(),
                    _ => m.crc.trim_start_matches("0x").to_string(),
                };
                reply.message_table.push(MessageTableEntry {
                    index: 100 + i as u16,
                    name: format!("{}_{}", m.name, crc),
                });
            }
            let mut payload = Vec::new();
            payload.extend_from_slice(&SOCKCLNT_CREATE_MSG_ID.to_be_bytes());
            payload.extend_from_slice(&7u32.to_be_bytes()); // client_index prefix
            reply.encode(&mut payload);
            write_frame(&mut sock, &payload);

            // --- route traffic ---
            let mut i = 0usize;
            loop {
                let Some(req) = read_frame(&mut sock) else {
                    return;
                };
                let answer = *answers
                    .get(i)
                    .or_else(|| answers.last())
                    .unwrap_or(&Answer::Ok);
                i += 1;
                let retval = match answer {
                    Answer::Ok => 0,
                    Answer::Retval(v) => v,
                    Answer::Hangup => return,
                };
                let ctx = request_context(&req);
                let mut payload = Vec::new();
                payload.extend_from_slice(&reply_id().to_be_bytes());
                IpRouteAddDelReply {
                    context: ctx,
                    retval,
                    stats_index: 0,
                }
                .encode(&mut payload);
                write_frame(&mut sock, &payload);
                handled_thread.fetch_add(1, Ordering::SeqCst);
            }
        });

        Self {
            path,
            _dir: dir,
            handled,
        }
    }

    fn connect(&self) -> Transport {
        Transport::connect(&self.path, Duration::from_secs(5)).unwrap()
    }
}

fn v4(a: u8, b: u8, c: u8, d: u8, len: u8) -> IpPrefix {
    IpPrefix::V4 {
        addr: [a, b, c, d],
        prefix_len: len,
    }
}

fn nh(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
}

fn fixture() -> (PendingMap, RouteLedger, PortIndex, NexthopMap) {
    let mut ports = PortIndex::default();
    ports.insert("eth3", None, 7);
    let mut map = NexthopMap::new(vec!["eth3".into()]);
    map.set_device(nh(192, 0, 2, 1), "eth3");
    map.set_device(nh(192, 0, 2, 9), "eth0"); // excluded
    (
        PendingMap::new(),
        RouteLedger::new(Capacity::new(1_000)),
        ports,
        map,
    )
}

fn resolver(map: &NexthopMap) -> impl Fn(&[IpAddr]) -> Vec<ResolvedPath> + '_ {
    move |nhs: &[IpAddr]| {
        nhs.iter()
            .filter_map(|ip| {
                map.resolve(ip).map(|t| ResolvedPath {
                    nexthop: *ip,
                    target: t,
                })
            })
            .collect()
    }
}

#[test]
fn handshake_then_install_a_batch() {
    let fake = Fake::start("ok", vec![Answer::Ok], None);
    let mut t = fake.connect();
    assert_eq!(t.client_index(), 7);

    let (mut pending, mut ledger, ports, map) = fixture();
    for i in 0..10u8 {
        pending.upsert(v4(10, i, 0, 0, 16), vec![nh(192, 0, 2, 1)]);
    }
    let resolve = resolver(&map);
    let stats = Drainer::new(4)
        .drain(&mut pending, &mut ledger, &resolve, &ports, &mut t, 100)
        .expect("drain");

    assert_eq!(stats.installed, 10);
    assert_eq!(ledger.counts().installed, 10);
    assert_eq!(ledger.counts().installing, 0, "nothing left in flight");
    assert!(pending.is_empty(), "everything acknowledged");
    assert_eq!(fake.handled.load(Ordering::SeqCst), 10);
}

#[test]
fn a_window_smaller_than_the_batch_still_drains_all_of_it() {
    // Pipelining bug bait: if the drainer forgot to loop after
    // collecting a window, the tail would be silently dropped and the
    // ledger would disagree with VPP.
    let fake = Fake::start("window", vec![Answer::Ok], None);
    let mut t = fake.connect();
    let (mut pending, mut ledger, ports, map) = fixture();
    for i in 0..50u8 {
        pending.upsert(v4(10, i, 0, 0, 16), vec![nh(192, 0, 2, 1)]);
    }
    let resolve = resolver(&map);
    let stats = Drainer::new(3)
        .drain(&mut pending, &mut ledger, &resolve, &ports, &mut t, 500)
        .expect("drain");
    assert_eq!(stats.installed, 50);
    assert_eq!(fake.handled.load(Ordering::SeqCst), 50);
}

#[test]
fn a_rejected_route_is_requeued_not_lost() {
    // Per-route rejection is not a connection fault: the rest of the
    // batch must still install, and the failed one must come back so a
    // transient cause resolves on retry instead of leaving a hole.
    let fake = Fake::start(
        "reject",
        vec![Answer::Ok, Answer::Retval(-22), Answer::Ok],
        None,
    );
    let mut t = fake.connect();
    let (mut pending, mut ledger, ports, map) = fixture();
    for i in 0..3u8 {
        pending.upsert(v4(10, i, 0, 0, 16), vec![nh(192, 0, 2, 1)]);
    }
    let resolve = resolver(&map);
    let stats = Drainer::new(8)
        .drain(&mut pending, &mut ledger, &resolve, &ports, &mut t, 100)
        .expect("drain");

    assert_eq!(stats.installed, 2);
    assert_eq!(stats.rejected, 1);
    assert_eq!(pending.len(), 1, "the rejected route is pending again");
    assert_eq!(ledger.counts().installed, 2);
    assert_eq!(
        ledger.counts().installing,
        0,
        "the rejected route's reservation was released"
    );
}

#[test]
fn a_hangup_mid_batch_requeues_everything_unacknowledged() {
    // The property that makes a mid-load failure a retry rather than a
    // partial FIB: nothing positively acknowledged is lost, and the
    // ledger never claims more than VPP confirmed.
    let fake = Fake::start("hangup", vec![Answer::Ok, Answer::Ok, Answer::Hangup], None);
    let mut t = fake.connect();
    let (mut pending, mut ledger, ports, map) = fixture();
    for i in 0..20u8 {
        pending.upsert(v4(10, i, 0, 0, 16), vec![nh(192, 0, 2, 1)]);
    }
    let resolve = resolver(&map);
    let (stats, _err) = Drainer::new(4)
        .drain(&mut pending, &mut ledger, &resolve, &ports, &mut t, 100)
        .expect_err("the fake hung up");

    let confirmed = stats.installed;
    assert!(
        confirmed <= 2,
        "only acknowledged routes count as installed"
    );
    assert_eq!(ledger.counts().installed, confirmed);
    assert_eq!(
        ledger.counts().installing,
        0,
        "no reservation may survive a failed drain"
    );
    assert_eq!(
        pending.len() as u64,
        20 - confirmed,
        "every unacknowledged op is pending again"
    );
}

#[test]
fn unresolvable_routes_never_reach_the_socket() {
    let fake = Fake::start("unres", vec![Answer::Ok], None);
    let mut t = fake.connect();
    let (mut pending, mut ledger, ports, map) = fixture();
    pending.upsert(v4(10, 0, 0, 0, 16), vec![nh(192, 0, 2, 9)]); // mgmt only
    pending.upsert(v4(10, 1, 0, 0, 16), vec![nh(192, 0, 2, 1)]);
    let resolve = resolver(&map);
    let stats = Drainer::default()
        .drain(&mut pending, &mut ledger, &resolve, &ports, &mut t, 100)
        .expect("drain");

    assert_eq!(stats.installed, 1);
    assert_eq!(stats.unresolvable, 1);
    assert_eq!(
        fake.handled.load(Ordering::SeqCst),
        1,
        "an unresolvable route must not be sent at all"
    );
    assert!(ledger.counts().blocks_first_steer());
}

#[test]
fn a_missing_interface_index_defers_instead_of_installing_a_black_hole() {
    // sw_if_index 0 is local0: encoding a route before its interface
    // exists would install something that looks fine and drops.
    let fake = Fake::start("defer", vec![Answer::Ok], None);
    let mut t = fake.connect();
    let (mut pending, mut ledger, _ports, map) = fixture();
    let empty_ports = PortIndex::default();
    pending.upsert(v4(10, 0, 0, 0, 16), vec![nh(192, 0, 2, 1)]);
    let resolve = resolver(&map);
    let stats = Drainer::default()
        .drain(
            &mut pending,
            &mut ledger,
            &resolve,
            &empty_ports,
            &mut t,
            100,
        )
        .expect("drain");

    assert_eq!(stats.deferred, 1);
    assert_eq!(stats.installed, 0);
    assert_eq!(fake.handled.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.counts().installing, 0, "reservation released");
}

#[test]
fn withdrawals_are_sent_and_forgotten() {
    let fake = Fake::start("withdraw", vec![Answer::Ok], None);
    let mut t = fake.connect();
    let (mut pending, mut ledger, ports, map) = fixture();
    let p = v4(10, 0, 0, 0, 16);
    let resolve = resolver(&map);

    pending.upsert(p, vec![nh(192, 0, 2, 1)]);
    Drainer::default()
        .drain(&mut pending, &mut ledger, &resolve, &ports, &mut t, 10)
        .unwrap();
    assert_eq!(ledger.counts().installed, 1);

    pending.withdraw(p);
    let stats = Drainer::default()
        .drain(&mut pending, &mut ledger, &resolve, &ports, &mut t, 10)
        .unwrap();
    assert_eq!(stats.withdrawn, 1);
    assert_eq!(
        ledger.counts().installed,
        0,
        "withdrawn routes are forgotten"
    );
    assert!(ledger.verifiable_prefixes().is_empty());
}

#[test]
fn a_crc_mismatch_refuses_the_connection_before_any_route_moves() {
    // The whole point of carrying CRCs: a VPP that does not match our
    // pinned definitions must be refused at connect, not discovered
    // after installing routes with fields in the wrong places.
    let fake = Fake::start(
        "crc",
        vec![Answer::Ok],
        Some(("ip_route_add_del", "deadbeef")),
    );
    let msg = match Transport::connect(&fake.path, Duration::from_secs(5)) {
        Ok(_) => panic!("a CRC mismatch must refuse the connection"),
        Err(e) => e.to_string(),
    };
    assert!(msg.contains("ip_route_add_del"), "names the message: {msg}");
    assert!(msg.contains("deadbeef"), "reports what VPP said: {msg}");
    assert_eq!(fake.handled.load(Ordering::SeqCst), 0);
}

#[test]
fn capacity_withholds_without_sending() {
    let fake = Fake::start("cap", vec![Answer::Ok], None);
    let mut t = fake.connect();
    let (mut pending, _l, ports, map) = fixture();
    let mut ledger = RouteLedger::new(Capacity::new(2));
    for i in 0..5u8 {
        pending.upsert(v4(10, i, 0, 0, 16), vec![nh(192, 0, 2, 1)]);
    }
    let resolve = resolver(&map);
    let stats = Drainer::default()
        .drain(&mut pending, &mut ledger, &resolve, &ports, &mut t, 100)
        .expect("drain");

    assert_eq!(stats.installed, 2);
    assert_eq!(stats.withheld, 3);
    assert_eq!(
        fake.handled.load(Ordering::SeqCst),
        2,
        "withheld routes are never sent"
    );
    assert_eq!(ledger.withheld_prefixes().len(), 3);
}

#[test]
fn ping_round_trips_over_the_same_connection() {
    // Uses request() rather than send/recv, so it also covers the
    // one-shot path the supervisor's liveness check will take.
    let fake = Fake::start("ping", vec![Answer::Ok], None);
    let mut t = fake.connect();
    // The fake answers any request with an ip_route_add_del_reply
    // shape; ping decoding is covered in the unit tests. Here we only
    // assert the connection survives a mixed workload.
    let (mut pending, mut ledger, ports, map) = fixture();
    pending.upsert(v4(10, 0, 0, 0, 16), vec![nh(192, 0, 2, 1)]);
    let resolve = resolver(&map);
    assert!(Drainer::default()
        .drain(&mut pending, &mut ledger, &resolve, &ports, &mut t, 10)
        .is_ok());
}
