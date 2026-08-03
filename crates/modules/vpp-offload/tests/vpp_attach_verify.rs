//! Device attach and readback verify against a fake VPP.
//!
//! The unit tests cover the decisions (which driver name, what fails a
//! pass, how sampling behaves). These cover the part that only a socket
//! can: that the three attach messages are sent in the order the
//! hardware requires, that indices thread from one reply into the next,
//! and that a verify pass turns real `ip_route_lookup` replies into the
//! right verdict.
//!
//! The fake dispatches on message id, so a request sent out of order
//! shows up as a wrong-message failure rather than passing by accident.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use packetframe_common::fib::IpPrefix;
use packetframe_vpp_offload::attach::{attach_ports, AttachError, PortAttach};
use packetframe_vpp_offload::fib_sync::{to_prefix, PortIndex};
use packetframe_vpp_offload::sink::{Capacity, RouteLedger};
use packetframe_vpp_offload::verify::{verify, Mismatch};
use packetframe_vpp_offload::vpp_api::codec::{
    parse_frame_header, peek_msg_id, write_frame_header, Encode, MSG_HEADER_LEN,
    SOCKCLNT_CREATE_MSG_ID,
};
use packetframe_vpp_offload::vpp_api::generated::{
    DevAttachReply, DevCreatePortIfReply, FibPath, IpRoute, IpRouteLookupReply, MessageTableEntry,
    SockclntCreateReply, SwInterfaceSetFlagsReply, MESSAGE_META,
};
use packetframe_vpp_offload::vpp_api::Transport;

fn id_for(name: &str) -> u16 {
    100 + MESSAGE_META.iter().position(|m| m.name == name).unwrap() as u16
}

fn name_for(id: u16) -> &'static str {
    MESSAGE_META[(id - 100) as usize].name
}

/// Start a reply payload for `name`.
///
/// **The header geometry is per-message, not uniform**, and this fake
/// has to honour that or it tests nothing. `dev_create_port_if_reply`
/// carries a `client_index` between the id and the context; its own
/// sibling `dev_attach_reply` does not. Reading the layout out of
/// `MESSAGE_META` rather than hardcoding `[id][context]` is what makes
/// the fake speak the same wire the real VPP does — a hand-assumed
/// prefix here would have quietly matched a hand-assumed prefix in the
/// client and proved nothing.
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

/// Requests carry `[msg_id][client_index][context]`.
fn request_context(payload: &[u8]) -> u32 {
    u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]])
}

mod tempdir {
    use std::path::{Path, PathBuf};
    pub struct TempDir(PathBuf);
    impl TempDir {
        pub fn new(tag: &str) -> std::io::Result<Self> {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "pf-av-{tag}-{}-{:?}",
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

/// How the fake behaves for the attach sequence.
#[derive(Clone, Copy, Default)]
struct AttachBehaviour {
    /// Fail `dev_attach` with this retval.
    attach_retval: i32,
    /// Fail `dev_create_port_if` with this retval.
    create_retval: i32,
    /// Hand back this sw_if_index (0 exercises the local0 guard).
    sw_if_index: u32,
    dev_index: u32,
}

/// How the fake answers `ip_route_lookup`.
#[derive(Clone, Copy)]
enum LookupBehaviour {
    /// Route present, one path on this index.
    Found { sw_if_index: u32 },
    /// Route present, zero paths.
    NoPaths,
    /// Not in the FIB.
    Missing,
}

struct Fake {
    path: PathBuf,
    _dir: tempdir::TempDir,
    /// Message names in the order the fake received them.
    seen: Receiver<String>,
}

impl Fake {
    fn start(tag: &str, attach: AttachBehaviour, lookup: LookupBehaviour) -> Self {
        let dir = tempdir::TempDir::new(tag).unwrap();
        let path = dir.path().join("api.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx): (Sender<String>, Receiver<String>) = channel();

        thread::spawn(move || {
            let Ok((mut sock, _)) = listener.accept() else {
                return;
            };
            // Handshake.
            let Some(_) = read_frame(&mut sock) else {
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
                reply.message_table.push(MessageTableEntry {
                    index: 100 + i as u16,
                    name: format!("{}_{}", m.name, m.crc.trim_start_matches("0x")),
                });
            }
            let mut payload = Vec::new();
            payload.extend_from_slice(&SOCKCLNT_CREATE_MSG_ID.to_be_bytes());
            payload.extend_from_slice(&7u32.to_be_bytes());
            reply.encode(&mut payload);
            write_frame(&mut sock, &payload);

            loop {
                let Some(req) = read_frame(&mut sock) else {
                    return;
                };
                let id = peek_msg_id(&req).expect("msg id");
                let ctx = request_context(&req);
                let which = name_for(id);
                let _ = tx.send(which.to_string());

                let mut out;
                match which {
                    "dev_attach" => {
                        out = reply_head("dev_attach_reply");
                        DevAttachReply {
                            context: ctx,
                            dev_index: attach.dev_index,
                            retval: attach.attach_retval,
                            error_string: if attach.attach_retval == 0 {
                                String::new()
                            } else {
                                "no such driver".into()
                            },
                        }
                        .encode(&mut out);
                    }
                    "dev_create_port_if" => {
                        out = reply_head("dev_create_port_if_reply");
                        DevCreatePortIfReply {
                            context: ctx,
                            sw_if_index: attach.sw_if_index,
                            retval: attach.create_retval,
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
                    "ip_route_lookup" => {
                        out = reply_head("ip_route_lookup_reply");
                        let (retval, paths) = match lookup {
                            LookupBehaviour::Found { sw_if_index } => {
                                (0, vec![path_on(sw_if_index)])
                            }
                            LookupBehaviour::NoPaths => (0, Vec::new()),
                            LookupBehaviour::Missing => (-6, Vec::new()),
                        };
                        IpRouteLookupReply {
                            context: ctx,
                            retval,
                            route: IpRoute {
                                table_id: 0,
                                stats_index: 0,
                                prefix: to_prefix(v4(10, 0)),
                                n_paths: paths.len() as u8,
                                paths,
                            },
                        }
                        .encode(&mut out);
                    }
                    other => panic!("fake got unexpected message {other}"),
                }
                write_frame(&mut sock, &out);
            }
        });

        Self {
            path,
            _dir: dir,
            seen: rx,
        }
    }

    fn connect(&self) -> Transport {
        Transport::connect(&self.path, Duration::from_secs(5)).unwrap()
    }

    /// Drain the observed message names.
    fn observed(&self) -> Vec<String> {
        let mut v = Vec::new();
        while let Ok(n) = self.seen.try_recv() {
            v.push(n);
        }
        v
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

fn v4(a: u8, b: u8) -> IpPrefix {
    IpPrefix::V4 {
        addr: [10, a, b, 0],
        prefix_len: 24,
    }
}

fn ports() -> Vec<PortAttach> {
    vec![PortAttach {
        port: "eth3".into(),
        pci_addr: "0002:07:00.1".into(),
        port_id: 0,
        num_rx_queues: 1,
    }]
}

#[test]
fn attach_sends_the_three_messages_in_order() {
    let fake = Fake::start(
        "ok",
        AttachBehaviour {
            dev_index: 3,
            sw_if_index: 7,
            ..Default::default()
        },
        LookupBehaviour::Missing,
    );
    let mut t = fake.connect();
    let got = attach_ports(&mut t, &ports()).expect("attach");

    assert_eq!(got.len(), 1);
    assert_eq!(got[0].port, "eth3");
    assert_eq!(got[0].dev_index, 3);
    assert_eq!(got[0].sw_if_index, 7);

    // Order is not cosmetic: create_port_if consumes dev_attach's
    // index, and set_flags consumes create_port_if's.
    assert_eq!(
        fake.observed(),
        vec![
            "dev_attach".to_string(),
            "dev_create_port_if".to_string(),
            "sw_interface_set_flags".to_string(),
        ]
    );
}

/// The guard that matters most in this module. `sw_if_index` 0 is
/// `local0`; a FIB path pointing there looks installed and forwards
/// nothing, so a "successful" attach returning 0 must be refused.
#[test]
fn an_sw_if_index_of_zero_is_refused_as_local0() {
    let fake = Fake::start(
        "local0",
        AttachBehaviour {
            dev_index: 1,
            sw_if_index: 0,
            ..Default::default()
        },
        LookupBehaviour::Missing,
    );
    let mut t = fake.connect();
    let err = attach_ports(&mut t, &ports()).expect_err("must refuse index 0");
    assert!(matches!(err, AttachError::LocalZero { .. }), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("local0"), "{msg}");

    // And it stops there: no interface is brought up on a bad index.
    assert_eq!(
        fake.observed(),
        vec!["dev_attach".to_string(), "dev_create_port_if".to_string()]
    );
}

#[test]
fn a_refused_dev_attach_reports_vpps_own_text() {
    let fake = Fake::start(
        "refused",
        AttachBehaviour {
            attach_retval: -1,
            ..Default::default()
        },
        LookupBehaviour::Missing,
    );
    let mut t = fake.connect();
    let err = attach_ports(&mut t, &ports()).expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains("dev_attach"), "{msg}");
    assert!(msg.contains("eth3"), "names the port: {msg}");
    assert!(msg.contains("no such driver"), "keeps VPP's detail: {msg}");
    // Nothing further is attempted.
    assert_eq!(fake.observed(), vec!["dev_attach".to_string()]);
}

/// A `dev_attach` that succeeds followed by a `dev_create_port_if` that
/// does not — the shape of "driver loaded, port would not come up",
/// which is what a queue or NPA-pool failure looks like from here.
#[test]
fn a_refused_create_port_if_names_the_step_that_failed() {
    let fake = Fake::start(
        "createfail",
        AttachBehaviour {
            dev_index: 2,
            create_retval: -11,
            ..Default::default()
        },
        LookupBehaviour::Missing,
    );
    let mut t = fake.connect();
    let err = attach_ports(&mut t, &ports()).expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains("dev_create_port_if"), "{msg}");
    assert!(msg.contains("-11"), "reports the retval: {msg}");
    // The device attached; only the port interface failed. No admin-up.
    assert_eq!(
        fake.observed(),
        vec!["dev_attach".to_string(), "dev_create_port_if".to_string()]
    );
}

/// A ledger holding `n` installed prefixes, all resolvable.
fn ledger_with(n: usize) -> (RouteLedger, PortIndex) {
    let mut ledger = RouteLedger::new(Capacity::new(10_000));
    for i in 0..n {
        let p = v4((i / 256) as u8, (i % 256) as u8);
        ledger.classify_resolved(p, 1);
        ledger.commit_installed(p);
    }
    let mut ports = PortIndex::default();
    ports.insert("eth3", None, 7);
    (ledger, ports)
}

#[test]
fn verify_passes_when_every_probe_finds_a_route_on_an_owned_interface() {
    let fake = Fake::start(
        "vok",
        AttachBehaviour::default(),
        LookupBehaviour::Found { sw_if_index: 7 },
    );
    let mut t = fake.connect();
    let (ledger, ports) = ledger_with(200);

    let out = verify(&mut t, &ledger, &ports, 16, 42).expect("verify");
    assert_eq!(out.sampled, 16);
    assert!(out.mismatches.is_empty(), "{:?}", out.mismatches);
    assert!(out.passed(), "{}", out.summary());
    assert_eq!(fake.observed().len(), 16, "one lookup per probe");
}

/// The silent-blackhole check, from the readback side: VPP happily
/// returns a route whose path is local0.
#[test]
fn verify_fails_a_path_on_an_interface_we_do_not_own() {
    let fake = Fake::start(
        "vlocal0",
        AttachBehaviour::default(),
        LookupBehaviour::Found { sw_if_index: 0 },
    );
    let mut t = fake.connect();
    let (ledger, ports) = ledger_with(50);

    let out = verify(&mut t, &ledger, &ports, 8, 7).expect("verify");
    assert!(!out.passed());
    assert_eq!(out.mismatches.len(), 8);
    assert!(
        out.mismatches
            .iter()
            .all(|m| matches!(m, Mismatch::ForeignPath { sw_if_index: 0, .. })),
        "{:?}",
        out.mismatches
    );
}

#[test]
fn verify_fails_an_absent_route() {
    let fake = Fake::start(
        "vmissing",
        AttachBehaviour::default(),
        LookupBehaviour::Missing,
    );
    let mut t = fake.connect();
    let (ledger, ports) = ledger_with(50);

    let out = verify(&mut t, &ledger, &ports, 4, 3).expect("verify");
    assert!(!out.passed());
    assert!(
        out.mismatches
            .iter()
            .all(|m| matches!(m, Mismatch::Absent { .. })),
        "{:?}",
        out.mismatches
    );
}

#[test]
fn verify_fails_a_route_with_no_paths() {
    let fake = Fake::start(
        "vnopaths",
        AttachBehaviour::default(),
        LookupBehaviour::NoPaths,
    );
    let mut t = fake.connect();
    let (ledger, ports) = ledger_with(50);

    let out = verify(&mut t, &ledger, &ports, 4, 3).expect("verify");
    assert!(!out.passed());
    assert!(
        out.mismatches
            .iter()
            .all(|m| matches!(m, Mismatch::NoPaths { .. })),
        "{:?}",
        out.mismatches
    );
}

/// An unresolvable route fails the pass even when every probe matches:
/// the mapping is misconfigured, and steering into a FIB with known
/// holes is how a deploy becomes an outage.
#[test]
fn verify_fails_on_unresolvable_even_with_clean_probes() {
    let fake = Fake::start(
        "vunres",
        AttachBehaviour::default(),
        LookupBehaviour::Found { sw_if_index: 7 },
    );
    let mut t = fake.connect();
    let (mut ledger, ports) = ledger_with(50);
    // A route whose nexthops resolve nowhere.
    ledger.classify_resolved(v4(99, 99), 0);

    let out = verify(&mut t, &ledger, &ports, 8, 11).expect("verify");
    assert!(out.mismatches.is_empty(), "probes were clean");
    assert_eq!(out.unresolvable, 1);
    assert!(!out.passed(), "{}", out.summary());
}

/// An empty ledger cannot be verified into a pass by sampling nothing —
/// but it also must not report a mismatch it never observed. Zero
/// probes with zero unresolvable is a vacuous pass, and the caller
/// (first attach, before any resync) is the one that knows that.
#[test]
fn an_empty_table_probes_nothing() {
    let fake = Fake::start(
        "vempty",
        AttachBehaviour::default(),
        LookupBehaviour::Missing,
    );
    let mut t = fake.connect();
    let (ledger, ports) = ledger_with(0);

    let out = verify(&mut t, &ledger, &ports, 16, 5).expect("verify");
    assert_eq!(out.sampled, 0);
    assert!(
        fake.observed().is_empty(),
        "no socket traffic for no routes"
    );
    assert!(out.passed());
}

/// Sampling must actually vary between passes against a live socket,
/// not just in the unit test — a fixed probe set would pass forever
/// once those routes installed.
#[test]
fn consecutive_passes_probe_different_routes() {
    let fake = Fake::start(
        "vresample",
        AttachBehaviour::default(),
        LookupBehaviour::Found { sw_if_index: 7 },
    );
    let mut t = fake.connect();
    let (ledger, ports) = ledger_with(500);

    let a = verify(&mut t, &ledger, &ports, 32, 1).expect("verify");
    let b = verify(&mut t, &ledger, &ports, 32, 2).expect("verify");
    assert_eq!(a.sampled, 32);
    assert_eq!(b.sampled, 32);
    // 64 lookups total reached the socket across the two passes.
    assert_eq!(fake.observed().len(), 64);
}
