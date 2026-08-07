//! Frame and header geometry for every fake VPP in this test suite.
//!
//! Three fakes exist and they are **not** duplicates of each other:
//! `fake_vpp.rs` models a working VPP for the engine and runtime tests,
//! `vpp_api_loopback.rs` scripts handshake and CRC-mismatch failures,
//! and `vpp_attach_verify.rs` drives device attach and readback. Their
//! *servers* differ on purpose — pushing failure injection into a fake
//! built to model success would make the shared one harder to reason
//! about in service of tests whose whole job is to break the protocol.
//!
//! What they had no business each owning is this: how a frame is read,
//! how one is written, where the context lives, and how a reply header
//! is laid out. Three copies of the wire format is three places for it
//! to drift, in a suite whose entire purpose is catching wire-format
//! mistakes — and the header geometry comes from `MESSAGE_META` rather
//! than being hardcoded precisely so it cannot be got wrong once, let
//! alone three times.
//!
//! Included by `#[path]` into several test binaries, each of which uses
//! a different subset — a loopback test that never builds a reply header
//! still needs the frame reader.
#![allow(dead_code)]

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;

use packetframe_vpp_offload::vpp_api::codec::{
    parse_frame_header, write_frame_header, MSG_HEADER_LEN,
};
use packetframe_vpp_offload::vpp_api::generated::MESSAGE_META;

/// The client index every fake hands out at handshake.
pub const CLIENT_INDEX: u32 = 7;

/// Message ids are assigned from 100 upward, in `MESSAGE_META` order —
/// the same mapping every fake's handshake advertises.
pub fn id_for(name: &str) -> u16 {
    100 + MESSAGE_META.iter().position(|m| m.name == name).unwrap() as u16
}

pub fn name_for(id: u16) -> &'static str {
    MESSAGE_META[(id - 100) as usize].name
}

/// A reply's leading bytes: id, then the client index **only for the
/// messages whose meta says so**.
///
/// Driven off `MESSAGE_META.client_index_prefix` rather than hardcoded
/// as `[id][context]`, because that prefix is exactly the field a
/// hand-written header gets wrong — and a fake with the wrong geometry
/// validates a client with the same wrong geometry, which is worse than
/// no test at all.
pub fn reply_head(name: &str) -> Vec<u8> {
    let meta = MESSAGE_META
        .iter()
        .find(|m| m.name == name)
        .expect("known reply");
    let mut out = Vec::new();
    out.extend_from_slice(&id_for(name).to_be_bytes());
    if meta.client_index_prefix {
        out.extend_from_slice(&CLIENT_INDEX.to_be_bytes());
    }
    out
}

pub fn read_frame(s: &mut UnixStream) -> Option<Vec<u8>> {
    let mut hdr = [0u8; MSG_HEADER_LEN];
    s.read_exact(&mut hdr).ok()?;
    let len = parse_frame_header(&hdr) as usize;
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).ok()?;
    Some(payload)
}

pub fn write_frame(s: &mut UnixStream, payload: &[u8]) {
    let mut framed = Vec::new();
    write_frame_header(&mut framed, payload.len());
    framed.extend_from_slice(payload);
    let _ = s.write_all(&framed);
    let _ = s.flush();
}

/// The request's context, which every reply must echo back.
pub fn request_context(payload: &[u8]) -> u32 {
    u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]])
}
