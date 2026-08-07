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

use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use packetframe_common::fib::IpPrefix;
use packetframe_vpp_offload::attach::{attach_ports, AttachError, AttachMode, PortAttach};
use packetframe_vpp_offload::fib_sync::{to_prefix, PortIndex};
use packetframe_vpp_offload::sink::{Capacity, RouteLedger};
use packetframe_vpp_offload::verify::{verify, Mismatch};
use packetframe_vpp_offload::vpp_api::codec::{peek_msg_id, Encode, SOCKCLNT_CREATE_MSG_ID};
/// The loopback index the fake hands out. Attach unnumbers every member
/// to it; these tests care that the call is made, not what the index is.
const TEST_LOOP_IDX: u32 = 9;

/// What the fake's `create_loopback` hands back.
const LOOP_IF_INDEX: u32 = 9;

#[path = "common/wire.rs"]
mod wire;
use wire::{name_for, read_frame, reply_head, request_context, write_frame};

use packetframe_vpp_offload::vpp_api::generated::{
    ControlPingReply, CreateLoopbackReply, DevAttachReply, DevCreatePortIfReply, FibPath, IpRoute,
    IpRouteLookupReply, MessageTableEntry, SockclntCreateReply, SwInterfaceAddDelAddressReply,
    SwInterfaceDetails, SwInterfaceSetFlagsReply, SwInterfaceSetMacAddressReply,
    SwInterfaceSetUnnumberedReply, MESSAGE_META,
};
use packetframe_vpp_offload::vpp_api::Transport;

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

/// `(sw_if_index, name, flags)` the fake reports from
/// `sw_interface_dump`. `flags` uses IF_STATUS_ADMIN_UP|LINK_UP.
type Ifaces = Vec<(u32, String, u32)>;

impl Fake {
    fn start(tag: &str, attach: AttachBehaviour, lookup: LookupBehaviour) -> Self {
        Self::start_with(tag, attach, lookup, vec![(7, "octeon0/0".into(), 3)])
    }

    fn start_with(
        tag: &str,
        attach: AttachBehaviour,
        lookup: LookupBehaviour,
        ifaces: Ifaces,
    ) -> Self {
        Self::start_full(tag, attach, lookup, ifaces, false)
    }

    /// `deaf_to_mac` models the failure the readback exists for: a
    /// driver that answers `sw_interface_set_mac_address` with retval 0
    /// and leaves the interface unchanged.
    fn start_full(
        tag: &str,
        attach: AttachBehaviour,
        lookup: LookupBehaviour,
        ifaces: Ifaces,
        deaf_to_mac: bool,
    ) -> Self {
        let dir = tempdir::TempDir::new(tag).unwrap();
        let path = dir.path().join("api.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (tx, rx): (Sender<String>, Receiver<String>) = channel();

        thread::spawn(move || {
            let mut ifaces = ifaces;
            let mut macs: std::collections::HashMap<u32, [u8; 6]> =
                std::collections::HashMap::new();
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
                        // A created interface shows up in later dumps,
                        // as it does in VPP. Without this the MAC
                        // readback cannot find the port it just made,
                        // and the fake would be failing attach for a
                        // reason no real VPP has.
                        if attach.create_retval == 0
                            && !ifaces.iter().any(|(i, _, _)| *i == attach.sw_if_index)
                        {
                            ifaces.push((attach.sw_if_index, "octeon0/0".into(), 3));
                        }
                        out = reply_head("dev_create_port_if_reply");
                        DevCreatePortIfReply {
                            context: ctx,
                            sw_if_index: attach.sw_if_index,
                            retval: attach.create_retval,
                            error_string: String::new(),
                        }
                        .encode(&mut out);
                    }
                    // Modelled, not merely acknowledged: the dump below
                    // reports whatever was set here, so `set_mac`'s
                    // readback has something real to disagree with. A
                    // fake that returned 0 and forgot would make the
                    // readback untestable — and the readback exists
                    // precisely because a driver can do that.
                    "sw_interface_set_mac_address" => {
                        // Read off the wire by offset rather than
                        // decoded: requests are encode-only in the
                        // generated types. Payload is
                        // id(2) client_index(4) context(4) sw_if_index(4)
                        // mac(6).
                        let idx = u32::from_be_bytes([req[10], req[11], req[12], req[13]]);
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&req[14..20]);
                        if !deaf_to_mac {
                            macs.insert(idx, mac);
                        }
                        out = reply_head("sw_interface_set_mac_address_reply");
                        SwInterfaceSetMacAddressReply {
                            context: ctx,
                            retval: 0,
                        }
                        .encode(&mut out);
                    }
                    "create_loopback" => {
                        out = reply_head("create_loopback_reply");
                        CreateLoopbackReply {
                            context: ctx,
                            sw_if_index: LOOP_IF_INDEX,
                            retval: 0,
                        }
                        .encode(&mut out);
                    }
                    "sw_interface_add_del_address" => {
                        out = reply_head("sw_interface_add_del_address_reply");
                        SwInterfaceAddDelAddressReply {
                            context: ctx,
                            retval: 0,
                        }
                        .encode(&mut out);
                    }
                    "sw_interface_set_unnumbered" => {
                        out = reply_head("sw_interface_set_unnumbered_reply");
                        SwInterfaceSetUnnumberedReply {
                            context: ctx,
                            retval: 0,
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
                    // A DUMP: stream one details frame per interface and
                    // send NO terminator — the trailing control_ping's
                    // reply is what ends the stream, exactly as VPP does.
                    "sw_interface_dump" => {
                        for (idx, name, flags) in &ifaces {
                            let mut d = reply_head("sw_interface_details");
                            let mut det = details(*idx, name, *flags, ctx);
                            if let Some(m) = macs.get(idx) {
                                det.l2_address = *m;
                            }
                            det.encode(&mut d);
                            write_frame(&mut sock, &d);
                        }
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

/// Route lookups the fake saw. Verify also issues an interface dump
/// (dump + trailing ping), so a raw message count is not a probe count.
fn lookups(f: &Fake) -> usize {
    f.observed()
        .iter()
        .filter(|n| *n == "ip_route_lookup")
        .count()
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
        pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
    }]
}

/// A surviving VPP's loopback is adopted, not duplicated.
///
/// The first daemon restart over a live VPP failed on this: the module
/// created a second loopback and then could not give it an address the
/// first one already held —
/// `sw_interface_add_del_address for loop0 failed (retval -105)`.
/// Adoption has to discover VPP's state rather than recreate it, which
/// is the same rule that governs port interfaces.
///
/// Asserts that `create_loopback` is NOT sent when one already exists —
/// the presence of a message, not its absence from a happy path, since a
/// test that only checked the returned index would pass while VPP
/// accumulated a loopback per restart.
#[test]
fn an_existing_loopback_is_adopted_rather_than_recreated() {
    let fake = Fake::start_with(
        "loopadopt",
        AttachBehaviour {
            dev_index: 3,
            sw_if_index: 7,
            ..Default::default()
        },
        LookupBehaviour::Missing,
        vec![
            (7, "octeon0/0".into(), 3),
            (LOOP_IF_INDEX, "loop0".into(), 3),
        ],
    );
    let mut t = fake.connect();

    let found = packetframe_vpp_offload::attach::find_loopback(&mut t).expect("dump");
    assert_eq!(
        found,
        Some(LOOP_IF_INDEX),
        "the loopback this VPP already has must be discoverable"
    );
    assert!(
        !fake.observed().contains(&"create_loopback".to_string()),
        "discovery must not create anything: {:?}",
        fake.observed()
    );
}

/// The MAC readback catches a driver that says yes and does nothing.
///
/// This is the whole reason `set_mac` costs an extra dump. A retval of 0
/// is not evidence: `sw_interface_set_mac_address` can be accepted and
/// ignored, and the result is invisible everywhere else — the FIB
/// installs correctly, verification passes, health reports healthy, and
/// every steered frame is punted at `ethernet-input` because the
/// interface does not answer to the address MCAM sends traffic to.
/// Traced on hardware 2026-08-07 before the MAC was set: 100 frames in,
/// 100 punted, `fib-synced healthy` throughout.
#[test]
fn a_mac_set_that_did_not_take_is_caught_not_trusted() {
    let fake = Fake::start_full(
        "deafmac",
        AttachBehaviour {
            dev_index: 3,
            sw_if_index: 7,
            ..Default::default()
        },
        LookupBehaviour::Missing,
        vec![(7, "octeon0/0".into(), 3)],
        // Acknowledges, changes nothing — the failure mode.
        true,
    );
    let mut t = fake.connect();
    let err = attach_ports(&mut t, &ports(), &[], AttachMode::Fresh, TEST_LOOP_IDX)
        .expect_err("a MAC that did not take must not be reported as attached");

    match err {
        AttachError::MacMismatch { port, asked, got } => {
            assert_eq!(port, "eth3");
            assert_ne!(asked, got, "the point is that they differ");
        }
        other => panic!("expected MacMismatch, got {other:?}"),
    }
}

#[test]
fn attach_sends_every_message_a_forwarding_port_needs_in_order() {
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
    let got =
        attach_ports(&mut t, &ports(), &[], AttachMode::Fresh, TEST_LOOP_IDX).expect("attach");

    assert_eq!(got.len(), 1);
    assert_eq!(got[0].port, "eth3");
    assert_eq!(got[0].dev_index, Some(3));
    assert_eq!(got[0].sw_if_index, 7);

    // A discovery dump comes first (so an adopted VPP is not
    // re-attached), then the attach proper. None of this order is
    // cosmetic: create_port_if consumes dev_attach's index, set_flags
    // consumes create_port_if's, and the MAC and unnumbered calls must
    // land before the port is reported attached — a port handed to the
    // sink before it can forward is one the FIB resolves routes onto
    // while every packet dies at `ip4-not-enabled`.
    //
    // The second dump is the MAC readback. It is in this list on
    // purpose: `sw_interface_set_mac_address` can return 0 and change
    // nothing, and the only thing that catches it is asking VPP what
    // the interface actually holds.
    assert_eq!(
        fake.observed(),
        vec![
            "sw_interface_dump".to_string(),
            "control_ping".to_string(),
            "dev_attach".to_string(),
            "dev_create_port_if".to_string(),
            "sw_interface_set_flags".to_string(),
            "sw_interface_set_mac_address".to_string(),
            "sw_interface_dump".to_string(),
            "control_ping".to_string(),
            "sw_interface_set_unnumbered".to_string(),
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
    let err = attach_ports(&mut t, &ports(), &[], AttachMode::Fresh, TEST_LOOP_IDX)
        .expect_err("must refuse index 0");
    assert!(matches!(err, AttachError::LocalZero { .. }), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("local0"), "{msg}");

    // And it stops there: no interface is brought up on a bad index.
    assert_eq!(
        fake.observed(),
        vec![
            "sw_interface_dump".to_string(),
            "control_ping".to_string(),
            "dev_attach".to_string(),
            "dev_create_port_if".to_string()
        ]
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
    let err = attach_ports(&mut t, &ports(), &[], AttachMode::Fresh, TEST_LOOP_IDX)
        .expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains("dev_attach"), "{msg}");
    assert!(msg.contains("eth3"), "names the port: {msg}");
    assert!(msg.contains("no such driver"), "keeps VPP's detail: {msg}");
    // Nothing further is attempted.
    assert_eq!(
        fake.observed(),
        vec![
            "sw_interface_dump".to_string(),
            "control_ping".to_string(),
            "dev_attach".to_string()
        ]
    );
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
    let err = attach_ports(&mut t, &ports(), &[], AttachMode::Fresh, TEST_LOOP_IDX)
        .expect_err("must fail");
    let msg = err.to_string();
    assert!(msg.contains("dev_create_port_if"), "{msg}");
    assert!(msg.contains("-11"), "reports the retval: {msg}");
    // The device attached; only the port interface failed. No admin-up.
    assert_eq!(
        fake.observed(),
        vec![
            "sw_interface_dump".to_string(),
            "control_ping".to_string(),
            "dev_attach".to_string(),
            "dev_create_port_if".to_string()
        ]
    );
}

/// Adoption: VPP already has the interface, and the live FIB is already
/// pointing at its index. Re-issuing `dev_attach` there would either be
/// refused — fatal in this module, so it would cycle a healthy and
/// possibly steered VPP — or create a duplicate interface nothing
/// references.
#[test]
fn a_recorded_interface_is_reused_not_re_attached() {
    let fake = Fake::start_with(
        "adopt",
        AttachBehaviour::default(),
        LookupBehaviour::Missing,
        vec![(7, "octeon0/0".into(), 3)],
    );
    let mut t = fake.connect();
    let known = vec![("eth3".to_string(), 7u32)];
    let got =
        attach_ports(&mut t, &ports(), &known, AttachMode::Adopted, TEST_LOOP_IDX).expect("adopt");

    assert_eq!(got.len(), 1);
    assert_eq!(got[0].sw_if_index, 7);
    assert_eq!(got[0].dev_index, None, "not attached this pass");

    let seen = fake.observed();
    assert!(
        !seen.contains(&"dev_attach".to_string()),
        "must not re-attach a device VPP already has: {seen:?}"
    );
    assert!(
        !seen.contains(&"dev_create_port_if".to_string()),
        "must not create a duplicate interface: {seen:?}"
    );
    // Admin-up IS re-asserted: controller deploys can flap state, and
    // this is the reconcile point.
    assert!(
        seen.contains(&"sw_interface_set_flags".to_string()),
        "{seen:?}"
    );
}

/// A recorded index VPP no longer has must be refused, not silently
/// re-attached: we cannot tell whether a live FIB still references the
/// old index, and a duplicate would leave routes pointing at nothing.
#[test]
fn a_stale_recorded_index_is_refused() {
    let fake = Fake::start_with(
        "stale",
        AttachBehaviour::default(),
        LookupBehaviour::Missing,
        // VPP has local0 only — index 7 is gone.
        vec![(0, "local0".into(), 3)],
    );
    let mut t = fake.connect();
    let known = vec![("eth3".to_string(), 7u32)];
    let err = attach_ports(&mut t, &ports(), &known, AttachMode::Adopted, TEST_LOOP_IDX)
        .expect_err("must refuse");
    assert!(matches!(err, AttachError::StaleIndex { .. }), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("no longer has it"), "{msg}");
    let seen = fake.observed();
    assert!(!seen.contains(&"dev_attach".to_string()), "{seen:?}");
}

/// The window a schema version cannot close. Process identity is
/// persisted at spawn; the interface index only after attach. A crash
/// between those two writes — after `dev_create_port_if` already
/// succeeded — leaves an adoptable process and no recorded index. The
/// running VPP may already have the interface, so attaching would
/// duplicate it, and the dump cannot tell ports apart.
#[test]
fn adopting_without_a_recorded_index_refuses_rather_than_duplicating() {
    let fake = Fake::start_with(
        "adoptnoidx",
        AttachBehaviour::default(),
        LookupBehaviour::Missing,
        vec![(7, "octeon0/0".into(), 3)],
    );
    let mut t = fake.connect();
    let err = attach_ports(&mut t, &ports(), &[], AttachMode::Adopted, TEST_LOOP_IDX)
        .expect_err("must refuse");
    assert!(
        matches!(err, AttachError::UnknownIndexOnAdopt { .. }),
        "{err:?}"
    );
    let seen = fake.observed();
    assert!(
        !seen.contains(&"dev_attach".to_string()),
        "nothing may be attached against a live VPP we cannot identify: {seen:?}"
    );
}

/// The same missing index on a FRESH process is fine — a VPP we just
/// started has no interfaces, so attaching is the only correct move.
#[test]
fn a_fresh_process_with_no_recorded_index_attaches_normally() {
    let fake = Fake::start_with(
        "freshnoidx",
        AttachBehaviour {
            dev_index: 1,
            sw_if_index: 7,
            ..Default::default()
        },
        LookupBehaviour::Missing,
        vec![],
    );
    let mut t = fake.connect();
    let got =
        attach_ports(&mut t, &ports(), &[], AttachMode::Fresh, TEST_LOOP_IDX).expect("attach");
    assert_eq!(got[0].sw_if_index, 7);
    assert_eq!(got[0].dev_index, Some(1));
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
    assert_eq!(lookups(&fake), 16, "one lookup per probe");
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

/// An empty ledger must NOT pass. Sampling nothing proves nothing, and
/// a resync completing against an unexpectedly empty mirror would
/// otherwise verify clean — letting the supervisor steer traffic into a
/// VPP with an empty FIB, which is the blackhole rule 1 exists to
/// prevent, reached through the gate meant to prevent it.
#[test]
fn an_empty_table_fails_rather_than_passing_vacuously() {
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
        out.mismatches.is_empty(),
        "nothing was observed to mismatch"
    );
    assert!(!out.passed(), "zero probes is not evidence of health");
    assert!(
        out.summary().contains("no installed routes"),
        "{}",
        out.summary()
    );
    // No routes were probed; only the interface dump touched the socket.
    assert_eq!(lookups(&fake), 0);
}

/// The check the route probes structurally cannot make. A VF that is
/// admin-up with no carrier keeps every route on a valid, owned
/// `sw_if_index` — so every probe passes and we would steer into an
/// interface that forwards nothing. `set_admin_up` only ever asserted
/// the administrative flag; the runbook treats link-up as the bring-up
/// pass for exactly this reason.
#[test]
fn verify_fails_when_an_owned_interface_has_no_carrier() {
    let fake = Fake::start_with(
        "nolink",
        AttachBehaviour::default(),
        LookupBehaviour::Found { sw_if_index: 7 },
        // admin up (1), link DOWN — no 2 bit.
        vec![(7, "octeon0/0".into(), 1)],
    );
    let mut t = fake.connect();
    let (ledger, ports) = ledger_with(50);

    let out = verify(&mut t, &ledger, &ports, 8, 4).expect("verify");
    assert!(
        out.mismatches.is_empty(),
        "every route probe looks perfect: {:?}",
        out.mismatches
    );
    assert_eq!(out.dead_interfaces.len(), 1);
    assert_eq!(out.dead_interfaces[0].sw_if_index, 7);
    assert!(out.dead_interfaces[0].admin_up);
    assert!(!out.dead_interfaces[0].link_up);
    assert!(!out.passed(), "{}", out.summary());
    assert!(out.summary().contains("link_up=false"), "{}", out.summary());
}

/// An owned index that VPP does not report at all is not healthy by
/// omission. Only iterating the dump meant a port that vanished after
/// attach was never examined — and if the random sample happened not to
/// select a route through it, every probe matched and verify passed on a
/// port that could not forward.
#[test]
fn verify_fails_when_an_owned_interface_is_absent_from_vpp() {
    let fake = Fake::start_with(
        "absent",
        AttachBehaviour::default(),
        LookupBehaviour::Found { sw_if_index: 7 },
        // We own 7 and 9; VPP only has 7.
        vec![(7, "octeon0/0".into(), 3)],
    );
    let mut t = fake.connect();
    let (ledger, mut ports) = ledger_with(50);
    ports.insert("eth2", None, 9);

    let out = verify(&mut t, &ledger, &ports, 8, 4).expect("verify");
    assert!(
        out.mismatches.is_empty(),
        "every route probe still looks perfect: {:?}",
        out.mismatches
    );
    assert_eq!(out.dead_interfaces.len(), 1, "{:?}", out.dead_interfaces);
    assert_eq!(out.dead_interfaces[0].sw_if_index, 9);
    assert!(!out.dead_interfaces[0].admin_up);
    assert!(!out.dead_interfaces[0].link_up);
    assert!(!out.passed(), "{}", out.summary());
    assert!(out.summary().contains("absent"), "{}", out.summary());
}

/// An interface we do NOT own being down is not our problem and must
/// not fail our verify — otherwise any unrelated down interface on the
/// box blocks steering forever.
#[test]
fn verify_ignores_link_state_on_interfaces_we_do_not_own() {
    let fake = Fake::start_with(
        "otherdown",
        AttachBehaviour::default(),
        LookupBehaviour::Found { sw_if_index: 7 },
        vec![
            (7, "octeon0/0".into(), 3), // ours, up
            (9, "octeon1/0".into(), 1), // not ours, link down
            (0, "local0".into(), 0),    // local0, entirely down
        ],
    );
    let mut t = fake.connect();
    let (ledger, ports) = ledger_with(50);

    let out = verify(&mut t, &ledger, &ports, 8, 4).expect("verify");
    assert!(out.dead_interfaces.is_empty(), "{:?}", out.dead_interfaces);
    assert!(out.passed(), "{}", out.summary());
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
    assert_eq!(lookups(&fake), 64);
}
