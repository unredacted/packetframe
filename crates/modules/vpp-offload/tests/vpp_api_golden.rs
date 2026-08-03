//! Golden wire vectors for the generated binary-API types.
//!
//! The generator is machine-checked against the `.api.json` shapes,
//! but nothing in that loop proves the *encoding* is right — a
//! consistently wrong endianness or a silently dropped field would
//! round-trip through our own encoder and decoder perfectly happily.
//! These vectors are byte-counted by hand from the message
//! definitions, so they fail if the generator's rules drift even when
//! generated code and generated tests would still agree with each
//! other.
//!
//! Byte budgets are asserted explicitly: VPP's structs are packed and
//! unpadded, so a length change IS a wire break, and catching it here
//! beats catching it as a FIB that installs garbage.

use packetframe_vpp_offload::vpp_api::codec::{
    parse_frame_header, peek_reply_header, write_frame_header, write_request_header, Decode,
    Decoder, Encode, MSG_HEADER_LEN, SOCKCLNT_CREATE_MSG_ID,
};
use packetframe_vpp_offload::vpp_api::generated::*;

/// address = af(u8) + union(16) = 17 bytes.
const ADDRESS_LEN: usize = 17;
/// prefix = address(17) + len(u8) = 18.
const PREFIX_LEN: usize = 18;
/// fib_path_nh = union(16) + via_label(4) + obj_id(4) + classify(4) = 28.
const FIB_PATH_NH_LEN: usize = 28;
/// fib_mpls_label = is_uniform(1) + label(4) + ttl(1) + exp(1) = 7.
const FIB_MPLS_LABEL_LEN: usize = 7;
/// fib_path = sw_if_index(4) + table_id(4) + rpf_id(4) + weight(1)
///          + preference(1) + type(4) + flags(4) + proto(4)
///          + nh(28) + n_labels(1) + label_stack(16*7=112) = 167.
const FIB_PATH_LEN: usize = 167;

fn v4_address(o: [u8; 4]) -> Address {
    let mut un = [0u8; 16];
    un[..4].copy_from_slice(&o);
    Address {
        af: ADDRESS_IP4,
        un: AddressUnion(un),
    }
}

#[test]
fn address_is_seventeen_bytes_af_then_union() {
    let mut buf = Vec::new();
    v4_address([10, 0, 0, 1]).encode(&mut buf);
    assert_eq!(buf.len(), ADDRESS_LEN);
    assert_eq!(buf[0], ADDRESS_IP4, "family byte leads");
    assert_eq!(&buf[1..5], &[10, 0, 0, 1], "v4 octets at the union head");
    assert!(
        buf[5..].iter().all(|&b| b == 0),
        "the v6 tail of the union must be zero-filled, not omitted"
    );
}

#[test]
fn prefix_appends_length_after_the_address() {
    let mut buf = Vec::new();
    Prefix {
        address: v4_address([192, 0, 2, 0]),
        len: 24,
    }
    .encode(&mut buf);
    assert_eq!(buf.len(), PREFIX_LEN);
    assert_eq!(buf[PREFIX_LEN - 1], 24);
}

#[test]
fn fib_path_matches_its_hand_counted_length() {
    let mut buf = Vec::new();
    FibPath::default().encode(&mut buf);
    assert_eq!(
        buf.len(),
        FIB_PATH_LEN,
        "fib_path is the widest type on this wire; a length drift here \
         silently corrupts every route we install"
    );
}

#[test]
fn fib_path_scalars_are_big_endian_at_known_offsets() {
    let mut p = FibPath {
        sw_if_index: 0x0102_0304,
        table_id: 0x0506_0708,
        weight: 0x11,
        preference: 0x22,
        ..Default::default()
    };
    p.nh.via_label = 0x090a_0b0c;
    let mut buf = Vec::new();
    p.encode(&mut buf);
    assert_eq!(&buf[0..4], &[0x01, 0x02, 0x03, 0x04], "sw_if_index BE");
    assert_eq!(&buf[4..8], &[0x05, 0x06, 0x07, 0x08], "table_id BE");
    assert_eq!(buf[12], 0x11, "weight after the three u32s");
    assert_eq!(buf[13], 0x22, "preference");
    // nh starts after sw_if_index..proto = 4+4+4+1+1+4+4+4 = 26.
    assert_eq!(&buf[26..42], &[0u8; 16], "nh union head");
    assert_eq!(&buf[42..46], &[0x09, 0x0a, 0x0b, 0x0c], "nh.via_label BE");
}

#[test]
fn fib_path_nh_is_twenty_eight_bytes() {
    let mut buf = Vec::new();
    FibPathNh::default().encode(&mut buf);
    assert_eq!(
        buf.len(),
        FIB_PATH_NH_LEN,
        "the nexthop union carries a full 16-byte address regardless of family"
    );
}

#[test]
fn fib_mpls_label_and_stack_are_fixed_width() {
    let mut buf = Vec::new();
    FibMplsLabel::default().encode(&mut buf);
    assert_eq!(buf.len(), FIB_MPLS_LABEL_LEN);
    // The stack is a FIXED 16 entries regardless of n_labels — VPP
    // sends all of it. Encoding only n_labels entries would shorten
    // every message by up to 112 bytes and desynchronise the stream.
    let mut buf = Vec::new();
    FibPath {
        n_labels: 0,
        ..Default::default()
    }
    .encode(&mut buf);
    assert_eq!(buf.len(), FIB_PATH_LEN);
}

#[test]
fn ip_route_roundtrips_with_two_paths() {
    let route = IpRoute {
        table_id: 0,
        stats_index: 0,
        prefix: Prefix {
            address: v4_address([198, 51, 100, 0]),
            len: 24,
        },
        n_paths: 2,
        paths: vec![
            FibPath {
                sw_if_index: 7,
                weight: 1,
                ..Default::default()
            },
            FibPath {
                sw_if_index: 9,
                weight: 1,
                ..Default::default()
            },
        ],
    };
    let mut buf = Vec::new();
    route.encode(&mut buf);
    // table_id(4) + stats_index(4) + prefix(18) + n_paths(1) + 2 paths.
    assert_eq!(buf.len(), 4 + 4 + PREFIX_LEN + 1 + 2 * FIB_PATH_LEN);

    let mut d = Decoder::new(&buf);
    let back = IpRoute::decode(&mut d).unwrap();
    assert_eq!(back, route, "multipath route must survive a round trip");
    assert_eq!(d.remaining(), 0, "decoder must consume exactly the message");
}

#[test]
fn ip_route_add_del_omits_transport_owned_fields() {
    // _vl_msg_id and client_index are stamped by the transport, so the
    // generated body must NOT re-encode them — otherwise every request
    // carries them twice and VPP reads garbage.
    let msg = IpRouteAddDel {
        context: 0,
        is_add: true,
        is_multipath: false,
        route: IpRoute {
            n_paths: 0,
            paths: vec![],
            ..Default::default()
        },
    };
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    // context(4) + is_add(1) + is_multipath(1) + route(4+4+18+1).
    assert_eq!(buf.len(), 4 + 1 + 1 + 4 + 4 + PREFIX_LEN + 1);
    assert_eq!(buf[4], 1, "is_add encodes as a single byte");
    assert_eq!(buf[5], 0, "is_multipath");
}

#[test]
fn variable_length_array_encodes_from_vec_len_not_count_field() {
    // A route whose n_paths disagrees with paths.len() must still emit
    // the vec it actually holds — the encoder writes what is there, so
    // a stale count cannot produce a short read on VPP's side.
    let route = IpRoute {
        n_paths: 7, // lie
        paths: vec![FibPath::default()],
        ..Default::default()
    };
    let mut buf = Vec::new();
    route.encode(&mut buf);
    assert_eq!(buf.len(), 4 + 4 + PREFIX_LEN + 1 + FIB_PATH_LEN);
}

#[test]
fn dev_attach_strings_are_fixed_and_variable_as_declared() {
    let msg = DevAttach {
        context: 0,
        device_id: "pci/0002:07:00.1".into(),
        driver_name: "octeon".into(),
        flags: 0,
        args: String::new(),
    };
    let mut buf = Vec::new();
    msg.encode(&mut buf);
    // context(4) + device_id[48] + driver_name[16] + flags(4)
    //   + args(u32 len prefix + 0 bytes).
    assert_eq!(buf.len(), 4 + 48 + 16 + 4 + 4);
    assert_eq!(&buf[4..20], b"pci/0002:07:00.1");
    assert!(
        buf[20..52].iter().all(|&b| b == 0),
        "fixed strings NUL-pad to their declared width"
    );
    assert_eq!(&buf[52..58], b"octeon");
    assert_eq!(&buf[buf.len() - 4..], &[0, 0, 0, 0], "empty args length");
}

#[test]
fn dev_attach_reply_decodes_error_string() {
    // msg_id(2) + context(4) + dev_index(4) + retval(4) + len(4) + text
    let mut payload = Vec::new();
    payload.extend_from_slice(&7u16.to_be_bytes());
    payload.extend_from_slice(&0xabcdu32.to_be_bytes());
    payload.extend_from_slice(&3u32.to_be_bytes());
    payload.extend_from_slice(&(-22i32).to_be_bytes());
    payload.extend_from_slice(&5u32.to_be_bytes());
    payload.extend_from_slice(b"oh no");

    let (id, ctx) = peek_reply_header(&payload).unwrap();
    assert_eq!((id, ctx), (7, 0xabcd));

    let mut d = Decoder::new(&payload);
    let r = DevAttachReply::decode(&mut d).unwrap();
    assert_eq!(r.context, 0xabcd);
    assert_eq!(r.dev_index, 3);
    assert_eq!(r.retval, -22);
    assert_eq!(r.error_string, "oh no");
}

#[test]
fn sockclnt_create_reply_parses_the_message_table() {
    // The handshake's whole point: name -> id mapping arrives here.
    let mut payload = Vec::new();
    payload.extend_from_slice(&SOCKCLNT_CREATE_MSG_ID.to_be_bytes());
    payload.extend_from_slice(&11u32.to_be_bytes()); // client_index
    payload.extend_from_slice(&1u32.to_be_bytes()); // context
    payload.extend_from_slice(&0i32.to_be_bytes()); // response
    payload.extend_from_slice(&11u32.to_be_bytes()); // index
    payload.extend_from_slice(&2u16.to_be_bytes()); // count
    for (idx, name) in [
        (100u16, "ip_route_add_del_b8ecfe0d"),
        (101, "control_ping_51077d14"),
    ] {
        payload.extend_from_slice(&idx.to_be_bytes());
        let mut fixed = [0u8; 64];
        fixed[..name.len()].copy_from_slice(name.as_bytes());
        payload.extend_from_slice(&fixed);
    }

    let mut d = Decoder::new(&payload);
    let reply = SockclntCreateReply::decode(&mut d).unwrap();
    assert_eq!(reply.response, 0);
    assert_eq!(reply.count, 2);
    assert_eq!(reply.message_table.len(), 2);
    assert_eq!(reply.message_table[0].index, 100);
    assert_eq!(reply.message_table[0].name, "ip_route_add_del_b8ecfe0d");
    assert_eq!(reply.message_table[1].index, 101);
    assert_eq!(d.remaining(), 0);
}

#[test]
fn framing_and_request_header_compose() {
    let msg = ControlPing { context: 42 };
    let mut payload = Vec::new();
    write_request_header(&mut payload, 77, 5, 42);
    msg.encode(&mut payload);

    let mut frame = Vec::new();
    write_frame_header(&mut frame, payload.len());
    frame.extend_from_slice(&payload);

    let hdr: [u8; MSG_HEADER_LEN] = frame[..MSG_HEADER_LEN].try_into().unwrap();
    assert_eq!(parse_frame_header(&hdr) as usize, payload.len());
    assert_eq!(
        &frame[MSG_HEADER_LEN..MSG_HEADER_LEN + 2],
        &77u16.to_be_bytes()
    );
}

#[test]
fn every_whitelisted_message_has_a_crc() {
    // The message table is keyed by name_crc; an empty CRC means the
    // generator failed to read one and version-mismatch detection
    // would silently degrade to name-only matching.
    assert!(!MESSAGE_CRCS.is_empty());
    for (name, crc) in MESSAGE_CRCS {
        assert!(
            crc.starts_with("0x") && crc.len() > 2,
            "message {name} has no usable CRC: {crc:?}"
        );
    }
}
