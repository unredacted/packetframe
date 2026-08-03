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
//! The reply header is shorter than the request header: replies carry
//! `[u16 msg_id][u32 context]` with no client_index. That asymmetry is
//! in the `.api.json` field lists themselves, so the generated
//! encode/decode already reflects it — this module only needs to know
//! it when stamping request headers.

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

/// Stamp a request's `_vl_msg_id`, `client_index` and `context` ahead
/// of the generated body.
///
/// Kept here rather than in generated code because these three fields
/// are transport state, not message content: the caller does not own
/// them, and letting a caller set them would make context-matching
/// (which pairs replies to requests) silently unreliable.
pub fn write_request_header(buf: &mut Vec<u8>, msg_id: u16, client_index: u32, context: u32) {
    buf.extend_from_slice(&msg_id.to_be_bytes());
    buf.extend_from_slice(&client_index.to_be_bytes());
    buf.extend_from_slice(&context.to_be_bytes());
}

/// `(msg_id, context)` from a reply payload, without consuming it.
///
/// Replies carry no `client_index`, so context sits at byte 2 — one of
/// the easiest things to get wrong when reading VPP's structs, and the
/// reason this is a named function rather than an inline slice.
pub fn peek_reply_header(payload: &[u8]) -> Result<(u16, u32), WireError> {
    if payload.len() < 6 {
        return Err(WireError::Truncated {
            need: 6,
            have: payload.len(),
        });
    }
    let msg_id = u16::from_be_bytes([payload[0], payload[1]]);
    let context = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
    Ok((msg_id, context))
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
    fn reply_header_reads_context_without_client_index() {
        // msg_id=0x0203, context=0xdeadbeef, then body.
        let payload = [0x02, 0x03, 0xde, 0xad, 0xbe, 0xef, 0xff, 0xff];
        assert_eq!(peek_reply_header(&payload).unwrap(), (0x0203, 0xdead_beef));
    }

    #[test]
    fn reply_header_rejects_a_runt() {
        assert!(matches!(
            peek_reply_header(&[0, 1, 2]),
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

    #[test]
    fn request_header_is_id_client_context_in_order() {
        let mut buf = Vec::new();
        write_request_header(&mut buf, 0x1234, 0xaabb_ccdd, 0x0000_0007);
        assert_eq!(
            buf,
            vec![0x12, 0x34, 0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x07]
        );
    }
}
