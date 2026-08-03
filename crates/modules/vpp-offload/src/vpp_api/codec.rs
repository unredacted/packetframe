//! Wire codec for VPP's binary API over the unix socket.
//!
//! Hand-written and small on purpose: the generated code in
//! [`super::generated`] handles the message *shapes*, this handles the
//! *framing*, which no `.api.json` describes.
//!
//! **Everything on this wire is big-endian**, including the framing
//! header — VPP's socket transport uses network byte order throughout,
//! which is easy to get wrong because the messages themselves are
//! packed C structs that look host-endian at a glance.
//!
//! Frame layout, per message (matching govpp's `socketclient`, which
//! is the reference implementation of this transport):
//!
//! ```text
//! 16-byte header:  [0..8]  reserved/zero (msgbuf bookkeeping)
//!                  [8..12] u32 BE: payload length
//!                  [12..16] reserved/zero
//! payload:         u16 BE message id
//!                  u32 BE client index   (requests only)
//!                  u32 BE context
//!                  ...message fields...
//! ```
//!
//! **There is no uniform header.** An earlier revision of this file
//! assumed requests are `[id][client_index][context]` and replies are
//! `[id][context]`. The vendored schemas say otherwise, and all three
//! shapes are in our whitelist:
//!
//! | message | prefix |
//! |---|---|
//! | `sockclnt_create` (a REQUEST) | `[id][context]` — no client_index |
//! | `ip_route_add_del`, `dev_attach` | `[id][client_index][context]` |
//! | `ip_route_add_del_reply` | `[id][context]` |
//! | `sockclnt_create_reply`, `dev_create_port_if_reply` | `[id][client_index][context]` |
//! | `control_ping_reply` | `[id][context][retval][client_index]` |
//!
//! So the geometry is per message and comes from the schema: the
//! generator emits [`Message::CONTEXT_OFFSET`] and
//! [`Message::CLIENT_INDEX_PREFIX`], and [`MESSAGE_META`] carries the
//! same for runtime lookup by message id. Guessing here misparses a
//! context (replies routed to the wrong waiter) or shifts a request
//! body (VPP reading `is_add` out of a client index).

/// Bytes of framing that precede every message payload.
pub const MSG_HEADER_LEN: usize = 16;

/// Offset of the payload-length field within the framing header.
const LEN_OFFSET: usize = 8;

/// Message ID of `sockclnt_create`, the bootstrap chicken-and-egg:
/// the message table that maps names to IDs arrives IN the reply to
/// this message, so this one ID must be known a priori. VPP has kept
/// it stable at 15 across every release we support, and govpp
/// hardcodes the same value. Verified against the handshake on the
/// shadow before relying on it.
pub const SOCKCLNT_CREATE_MSG_ID: u16 = 15;

/// A malformed or truncated message. Deliberately not an
/// `io::Error`: this is a *protocol* fault — the peer sent something
/// the pinned API definitions cannot explain — and it must never be
/// retried as if it were a transient socket condition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Ran out of bytes mid-message.
    Truncated { need: usize, have: usize },
    /// A length prefix exceeded what the frame can contain.
    BadLength { field: &'static str, len: usize },
    /// A string field held bytes that are not valid UTF-8.
    BadUtf8,
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated message: need {need} bytes, have {have}")
            }
            Self::BadLength { field, len } => {
                write!(f, "implausible length {len} for field `{field}`")
            }
            Self::BadUtf8 => write!(f, "non-UTF-8 string field"),
        }
    }
}

impl std::error::Error for WireError {}

/// Something that can be written to the wire.
pub trait Encode {
    fn encode(&self, buf: &mut Vec<u8>);
}

/// Something that can be read from the wire.
pub trait Decode: Sized {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, WireError>;
}

/// Schema-derived facts about one API message.
///
/// Generated, never hand-written: every field here is read out of the
/// pinned `.api.json`, so a pin bump that moves `context` moves this
/// with it instead of silently breaking correlation.
pub trait Message: Encode {
    /// Wire name, as it appears in the handshake's message table
    /// (which is keyed `name_crc`).
    const NAME: &'static str;
    /// CRC of the message definition. A mismatch against the table
    /// means our types describe a different VPP than the one we are
    /// talking to.
    const CRC: &'static str;
    /// Byte offset of `context` in the full wire payload.
    const CONTEXT_OFFSET: usize;
    /// Whether a `client_index` sits between the id and `context`, and
    /// so must be stamped by the transport.
    const CLIENT_INDEX_PREFIX: bool;
    /// Set the correlation context. Owned by the transport: a caller
    /// choosing its own would break reply matching.
    fn set_context(&mut self, context: u32);
}

/// Runtime form of [`Message`], for looking geometry up by message id
/// once the handshake table is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageMeta {
    pub name: &'static str,
    pub crc: &'static str,
    pub context_offset: usize,
    pub client_index_prefix: bool,
}

/// Cursor over one message payload.
///
/// Every read is bounds-checked and returns [`WireError`] rather than
/// panicking: this parses bytes from another process, and a panic in
/// the sink would take the supervisor down with it.
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        if self.remaining() < n {
            return Err(WireError::Truncated {
                need: n,
                have: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn bytes<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn i8(&mut self) -> Result<i8, WireError> {
        Ok(self.take(1)?[0] as i8)
    }

    pub fn bool(&mut self) -> Result<bool, WireError> {
        Ok(self.u8()? != 0)
    }

    pub fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_be_bytes(self.bytes::<2>()?))
    }

    pub fn i16(&mut self) -> Result<i16, WireError> {
        Ok(i16::from_be_bytes(self.bytes::<2>()?))
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_be_bytes(self.bytes::<4>()?))
    }

    pub fn i32(&mut self) -> Result<i32, WireError> {
        Ok(i32::from_be_bytes(self.bytes::<4>()?))
    }

    pub fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_be_bytes(self.bytes::<8>()?))
    }

    pub fn i64(&mut self) -> Result<i64, WireError> {
        Ok(i64::from_be_bytes(self.bytes::<8>()?))
    }

    pub fn f64(&mut self) -> Result<f64, WireError> {
        Ok(f64::from_be_bytes(self.bytes::<8>()?))
    }

    /// Fixed-width string field: `n` bytes, NUL-padded.
    pub fn string_fixed(&mut self, n: usize) -> Result<String, WireError> {
        let s = self.take(n)?;
        let end = s.iter().position(|&b| b == 0).unwrap_or(n);
        std::str::from_utf8(&s[..end])
            .map(|s| s.to_string())
            .map_err(|_| WireError::BadUtf8)
    }

    /// Variable-width string field: u32 length prefix, no NUL.
    ///
    /// The length is checked against what actually remains before
    /// allocating — a corrupt prefix must not turn into a 4 GiB
    /// reservation.
    pub fn string_var(&mut self) -> Result<String, WireError> {
        let n = self.u32()? as usize;
        if n > self.remaining() {
            return Err(WireError::BadLength {
                field: "string",
                len: n,
            });
        }
        let s = self.take(n)?;
        std::str::from_utf8(s)
            .map(|s| s.to_string())
            .map_err(|_| WireError::BadUtf8)
    }
}

/// Write the 16-byte framing header for a payload of `payload_len`.
pub fn write_frame_header(buf: &mut Vec<u8>, payload_len: usize) {
    let start = buf.len();
    buf.extend_from_slice(&[0u8; MSG_HEADER_LEN]);
    buf[start + LEN_OFFSET..start + LEN_OFFSET + 4]
        .copy_from_slice(&(payload_len as u32).to_be_bytes());
}

/// Read the payload length out of a framing header.
pub fn parse_frame_header(hdr: &[u8; MSG_HEADER_LEN]) -> u32 {
    u32::from_be_bytes([
        hdr[LEN_OFFSET],
        hdr[LEN_OFFSET + 1],
        hdr[LEN_OFFSET + 2],
        hdr[LEN_OFFSET + 3],
    ])
}

/// Write the bytes that precede a message's own encoded body: the id,
/// and a `client_index` only when this message's schema has one there.
///
/// The body itself starts at `context`, which the generated `encode`
/// writes — so `context` appears exactly once. Stamping it here too
/// (as an earlier revision did) shifted every subsequent field by four
/// bytes: for `ip_route_add_del`, VPP would read the duplicated
/// context's high bytes as `is_add`/`is_multipath` and apply the wrong
/// FIB operation.
pub fn write_msg_prefix<M: Message>(buf: &mut Vec<u8>, msg_id: u16, client_index: u32) {
    buf.extend_from_slice(&msg_id.to_be_bytes());
    if M::CLIENT_INDEX_PREFIX {
        buf.extend_from_slice(&client_index.to_be_bytes());
    }
}

/// Encode a complete request: prefix, then the body with `context`
/// stamped by the transport rather than the caller.
pub fn encode_request<M: Message>(
    buf: &mut Vec<u8>,
    msg: &mut M,
    msg_id: u16,
    client_index: u32,
    context: u32,
) {
    msg.set_context(context);
    write_msg_prefix::<M>(buf, msg_id, client_index);
    msg.encode(buf);
}

/// Message id of a payload. Always the first two bytes, for every
/// message shape.
pub fn peek_msg_id(payload: &[u8]) -> Result<u16, WireError> {
    if payload.len() < 2 {
        return Err(WireError::Truncated {
            need: 2,
            have: payload.len(),
        });
    }
    Ok(u16::from_be_bytes([payload[0], payload[1]]))
}

/// Correlation context at a schema-derived offset.
///
/// `context_offset` must come from the message's own metadata — see
/// the table in this module's docs. Reading byte 2 unconditionally
/// returns a client index for `sockclnt_create_reply` and
/// `dev_create_port_if_reply`, so those replies would never match the
/// request that is waiting for them.
pub fn peek_context(payload: &[u8], context_offset: usize) -> Result<u32, WireError> {
    let end = context_offset + 4;
    if payload.len() < end {
        return Err(WireError::Truncated {
            need: end,
            have: payload.len(),
        });
    }
    Ok(u32::from_be_bytes([
        payload[context_offset],
        payload[context_offset + 1],
        payload[context_offset + 2],
        payload[context_offset + 3],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_header_roundtrips_big_endian() {
        let mut buf = Vec::new();
        write_frame_header(&mut buf, 0x0102_0304);
        assert_eq!(buf.len(), MSG_HEADER_LEN);
        // Length must land at [8..12] in network order — a
        // little-endian slip here yields a plausible-looking but
        // wildly wrong frame length.
        assert_eq!(&buf[8..12], &[0x01, 0x02, 0x03, 0x04]);
        let hdr: [u8; MSG_HEADER_LEN] = buf.try_into().unwrap();
        assert_eq!(parse_frame_header(&hdr), 0x0102_0304);
    }

    #[test]
    fn msg_id_is_always_the_first_two_bytes() {
        let payload = [0x02, 0x03, 0xde, 0xad, 0xbe, 0xef, 0xff, 0xff];
        assert_eq!(peek_msg_id(&payload).unwrap(), 0x0203);
        assert!(matches!(
            peek_msg_id(&[0]),
            Err(WireError::Truncated { need: 2, have: 1 })
        ));
    }

    #[test]
    fn context_is_read_at_the_offset_it_is_given() {
        // Same bytes, two shapes: offset 2 for a plain reply, offset 6
        // when a client_index precedes context.
        let payload = [0x02, 0x03, 0xde, 0xad, 0xbe, 0xef, 0x11, 0x22, 0x33, 0x44];
        assert_eq!(peek_context(&payload, 2).unwrap(), 0xdead_beef);
        assert_eq!(peek_context(&payload, 6).unwrap(), 0x1122_3344);
    }

    #[test]
    fn context_peek_rejects_a_runt() {
        assert!(matches!(
            peek_context(&[0, 1, 2], 2),
            Err(WireError::Truncated { need: 6, have: 3 })
        ));
    }

    #[test]
    fn decoder_is_bounds_checked_not_panicking() {
        let mut d = Decoder::new(&[0x00, 0x01]);
        assert_eq!(d.u16().unwrap(), 1);
        assert!(matches!(
            d.u32(),
            Err(WireError::Truncated { need: 4, have: 0 })
        ));
    }

    #[test]
    fn fixed_string_stops_at_nul() {
        let mut d = Decoder::new(b"vpp\0\0\0\0\0");
        assert_eq!(d.string_fixed(8).unwrap(), "vpp");
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn var_string_rejects_an_implausible_length() {
        // Length prefix claims 4 GiB with 2 bytes present. Must be a
        // clean error, not an allocation attempt.
        let mut d = Decoder::new(&[0xff, 0xff, 0xff, 0xff, 0x41, 0x42]);
        assert!(matches!(d.string_var(), Err(WireError::BadLength { .. })));
    }

    #[test]
    fn var_string_reads_exactly_its_prefix() {
        let mut d = Decoder::new(&[0, 0, 0, 3, b'a', b'b', b'c', b'z']);
        assert_eq!(d.string_var().unwrap(), "abc");
        assert_eq!(d.remaining(), 1);
    }

    /// Two stand-ins for the two prefix shapes; the real impls are
    /// generated, but the codec must be testable without them.
    struct WithCi(u32);
    struct WithoutCi(u32);

    impl Encode for WithCi {
        fn encode(&self, buf: &mut Vec<u8>) {
            buf.extend_from_slice(&self.0.to_be_bytes());
        }
    }
    impl Message for WithCi {
        const NAME: &'static str = "with_ci";
        const CRC: &'static str = "0x0";
        const CONTEXT_OFFSET: usize = 6;
        const CLIENT_INDEX_PREFIX: bool = true;
        fn set_context(&mut self, context: u32) {
            self.0 = context;
        }
    }
    impl Encode for WithoutCi {
        fn encode(&self, buf: &mut Vec<u8>) {
            buf.extend_from_slice(&self.0.to_be_bytes());
        }
    }
    impl Message for WithoutCi {
        const NAME: &'static str = "without_ci";
        const CRC: &'static str = "0x0";
        const CONTEXT_OFFSET: usize = 2;
        const CLIENT_INDEX_PREFIX: bool = false;
        fn set_context(&mut self, context: u32) {
            self.0 = context;
        }
    }

    #[test]
    fn prefix_includes_client_index_only_when_the_schema_does() {
        let mut a = WithCi(0);
        let mut buf = Vec::new();
        encode_request(&mut buf, &mut a, 0x1234, 0xaabb_ccdd, 7);
        // id + client_index + context(=body), written once each.
        assert_eq!(buf, vec![0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 7]);

        let mut b = WithoutCi(0);
        let mut buf = Vec::new();
        encode_request(&mut buf, &mut b, 0x1234, 0xaabb_ccdd, 7);
        assert_eq!(buf, vec![0x12, 0x34, 0, 0, 0, 7]);
    }

    #[test]
    fn context_lands_where_the_metadata_says_it_will() {
        // The invariant that ties encoding to correlation: whatever we
        // write, peek_context at the message's own offset finds it.
        for (ci, off) in [(true, 6usize), (false, 2usize)] {
            let mut buf = Vec::new();
            if ci {
                let mut m = WithCi(0);
                encode_request(&mut buf, &mut m, 9, 0xffff_ffff, 0x5555_5555);
            } else {
                let mut m = WithoutCi(0);
                encode_request(&mut buf, &mut m, 9, 0xffff_ffff, 0x5555_5555);
            }
            assert_eq!(peek_context(&buf, off).unwrap(), 0x5555_5555);
        }
    }
}
