//! Socket transport for VPP's binary API.
//!
//! Blocking `UnixStream`, deliberately. The sink's concurrency lives
//! above this layer (a prefix-keyed pending map drained in batches),
//! so an async runtime here would buy nothing but a dependency and a
//! second scheduler inside a process whose whole job is to be boring
//! while forwarding happens elsewhere.
//!
//! The connection is **stateful and version-bound**: after
//! [`Transport::connect`] the handshake yields a name→id table, every
//! subsequent send resolves its id through that table, and a CRC
//! mismatch on any message we speak is a connect-time refusal rather
//! than a decode surprise a million routes later.
//!
//! What this module does NOT do: batching, retry, or resync policy.
//! Those belong to the sink, which owns the notion of what *should* be
//! installed. Keeping them out means a transport error is always
//! "this connection is unusable", never "this route was rejected".

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use super::codec::{
    encode_request, parse_frame_header, peek_context, peek_msg_id, write_frame_header, Decode,
    Decoder, Message, MSG_HEADER_LEN, SOCKCLNT_CREATE_MSG_ID,
};
use super::generated::{
    ControlPing, ControlPingReply, SockclntCreate, SockclntCreateReply, MESSAGE_META,
};

/// Largest payload we will accept from VPP before declaring the
/// stream unusable.
///
/// A corrupt or desynchronised length prefix must not become a
/// multi-gigabyte allocation in the process that supervises the
/// dataplane. The real ceiling is the full-table dump reply, which is
/// well under a megabyte per message; 16 MiB is generous by three
/// orders of magnitude and still bounded.
const MAX_PAYLOAD: u32 = 16 * 1024 * 1024;

/// Client name registered with VPP. Shows up in `show api clients`,
/// so make it obvious who is holding the connection at 3am.
const CLIENT_NAME: &str = "packetframe-vpp-offload";

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connecting to {path}: {source}")]
    Connect {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("socket I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("wire format: {0}")]
    Wire(#[from] super::codec::WireError),

    /// VPP refused the handshake outright.
    #[error("sockclnt_create refused: response {0}")]
    HandshakeRefused(i32),

    /// The pinned API definitions describe a different VPP than the
    /// one on the other end of this socket. Refusing here is the
    /// entire point of carrying CRCs: the alternative is encoding a
    /// route with fields in the wrong places and watching traffic take
    /// a path nobody chose.
    #[error(
        "API mismatch for `{name}`: our definitions say {ours}, this VPP says {theirs}. \
         The running binary disagrees with the vendored API definitions \
         (crates/modules/vpp-offload/vpp-api/SOURCE.json names the VPP release they came from)."
    )]
    CrcMismatch {
        name: &'static str,
        ours: &'static str,
        theirs: String,
    },

    /// A message we must speak is absent from VPP's table — typically
    /// a plugin that did not load (e.g. no `dev_*` without the device
    /// framework).
    #[error("this VPP does not implement `{0}` — is the plugin loaded?")]
    MessageUnknown(&'static str),

    /// A reply arrived whose id is not in the table. Distinct from a
    /// CRC mismatch: the stream is intact, we simply cannot interpret
    /// this message, which usually means an async event we did not
    /// subscribe to.
    #[error("reply with unknown message id {0}")]
    UnknownReplyId(u16),

    #[error("payload of {0} bytes exceeds the {MAX_PAYLOAD}-byte ceiling")]
    PayloadTooLarge(u32),

    /// Read a reply whose context does not match the request in
    /// flight. With one request outstanding at a time this means the
    /// stream has desynchronised, which is not recoverable in place.
    #[error("expected context {expected}, got {got} — stream desynchronised")]
    ContextMismatch { expected: u32, got: u32 },
}

/// A connected, handshaken VPP API client.
pub struct Transport {
    sock: UnixStream,
    client_index: u32,
    /// Wire name → message id, from the handshake.
    ids: HashMap<String, u16>,
    /// Message id → byte offset of `context`, for correlating replies
    /// before their type is known. Built from [`MESSAGE_META`], because
    /// the offset is per message and not a constant.
    context_offsets: HashMap<u16, usize>,
    /// Monotonic request context. Wraps, which is fine: correlation
    /// only needs uniqueness among requests in flight, and we keep one.
    next_context: u32,
    /// Scratch buffers, reused so a full-table load does not allocate
    /// per route.
    tx: Vec<u8>,
    rx: Vec<u8>,
}

impl Transport {
    /// Connect and complete the handshake.
    ///
    /// On return the connection is proven usable: VPP accepted us, and
    /// every message in our whitelist exists on the other side with a
    /// matching CRC.
    pub fn connect(path: impl AsRef<Path>, timeout: Duration) -> Result<Self, TransportError> {
        let path = path.as_ref();
        let sock = UnixStream::connect(path).map_err(|source| TransportError::Connect {
            path: path.display().to_string(),
            source,
        })?;
        // Timeouts on both directions: a wedged VPP must surface as an
        // error the supervisor can act on, not a thread parked forever
        // holding the sink's only connection.
        sock.set_read_timeout(Some(timeout))?;
        sock.set_write_timeout(Some(timeout))?;

        let mut t = Self {
            sock,
            client_index: 0,
            ids: HashMap::new(),
            context_offsets: HashMap::new(),
            next_context: 1,
            tx: Vec::with_capacity(4096),
            rx: Vec::with_capacity(4096),
        };
        t.handshake()?;
        Ok(t)
    }

    /// `sockclnt_create` and the table it returns.
    ///
    /// The bootstrap chicken-and-egg: this one message's id cannot be
    /// looked up, because the lookup table arrives in its reply. See
    /// [`SOCKCLNT_CREATE_MSG_ID`].
    fn handshake(&mut self) -> Result<(), TransportError> {
        let mut req = SockclntCreate {
            context: 0,
            name: CLIENT_NAME.to_string(),
        };
        let context = self.take_context();
        self.tx.clear();
        encode_request(
            &mut self.tx,
            &mut req,
            SOCKCLNT_CREATE_MSG_ID,
            /* client_index */ 0,
            context,
        );
        self.write_frame()?;

        let payload = self.read_frame()?;
        let mut d = Decoder::new(&payload);
        let reply = SockclntCreateReply::decode(&mut d)?;
        if reply.response != 0 {
            return Err(TransportError::HandshakeRefused(reply.response));
        }
        self.client_index = reply.index;

        for entry in &reply.message_table {
            // Entries are `name_crc`; split on the LAST underscore
            // because message names contain plenty of their own
            // (`ip_route_add_del_b8ecfe0d`). The CRC half is checked
            // in verify_against, which reads the same table.
            if let Some((name, _crc)) = entry.name.rsplit_once('_') {
                self.ids.insert(name.to_string(), entry.index);
            }
        }
        self.verify_against(&reply)?;

        // Now that ids are known, index the per-message context offsets.
        for meta in MESSAGE_META {
            if let Some(&id) = self.ids.get(meta.name) {
                self.context_offsets.insert(id, meta.context_offset);
            }
        }
        Ok(())
    }

    /// Every message we speak must exist with our CRC.
    ///
    /// Checked eagerly at connect rather than lazily at first use: a
    /// version skew discovered halfway through installing a million
    /// routes is a half-populated FIB, while one discovered here is a
    /// clean failure the supervisor can report and back off from.
    fn verify_against(&self, reply: &SockclntCreateReply) -> Result<(), TransportError> {
        let mut theirs: HashMap<&str, &str> = HashMap::new();
        for entry in &reply.message_table {
            if let Some((name, crc)) = entry.name.rsplit_once('_') {
                theirs.insert(name, crc);
            }
        }
        for meta in MESSAGE_META {
            let Some(their_crc) = theirs.get(meta.name) else {
                return Err(TransportError::MessageUnknown(meta.name));
            };
            // Ours is `0xdeadbeef`; theirs is the bare hex suffix.
            let ours = meta.crc.trim_start_matches("0x");
            if !their_crc.eq_ignore_ascii_case(ours) {
                return Err(TransportError::CrcMismatch {
                    name: meta.name,
                    ours: meta.crc,
                    theirs: (*their_crc).to_string(),
                });
            }
        }
        Ok(())
    }

    fn take_context(&mut self) -> u32 {
        let c = self.next_context;
        self.next_context = self.next_context.wrapping_add(1).max(1);
        c
    }

    /// Message id for a name, or a typed error naming what is missing.
    fn id_of<M: Message>(&self) -> Result<u16, TransportError> {
        self.ids
            .get(M::NAME)
            .copied()
            .ok_or(TransportError::MessageUnknown(M::NAME))
    }

    /// Send a request WITHOUT waiting for its reply; returns the
    /// context to match it by.
    ///
    /// This is what makes a full-table load feasible. Strict
    /// request/reply costs a round trip per route — at ~1.05M routes
    /// and even 30 µs each that is half a minute of pure latency,
    /// against a 60 s convergence budget that also has to cover VPP
    /// actually installing them. Pipelining a window of requests and
    /// collecting the replies afterwards spends that latency once per
    /// window instead of once per route.
    ///
    /// The caller is responsible for eventually reading exactly one
    /// reply per send: VPP answers every request, so an unread reply
    /// desynchronises the next read.
    pub fn send<Req: Message>(&mut self, mut req: Req) -> Result<u32, TransportError> {
        let id = self.id_of::<Req>()?;
        let context = self.take_context();
        self.tx.clear();
        encode_request(&mut self.tx, &mut req, id, self.client_index, context);
        self.write_frame()?;
        Ok(context)
    }

    /// Read one reply, returning its context alongside the decoded
    /// message.
    ///
    /// The context is returned rather than checked because a
    /// pipelining caller has several outstanding and must decide which
    /// one this answers.
    pub fn recv<Rep: Message + Decode>(&mut self) -> Result<(u32, Rep), TransportError> {
        let payload = self.read_frame()?;
        let msg_id = peek_msg_id(&payload)?;
        let offset = *self
            .context_offsets
            .get(&msg_id)
            .ok_or(TransportError::UnknownReplyId(msg_id))?;
        let context = peek_context(&payload, offset)?;
        let mut d = Decoder::new(&payload);
        Ok((context, Rep::decode(&mut d)?))
    }

    /// Send a request and read its reply, matched by context.
    ///
    /// For one-shot operations (attach, ping, a spot verify). Bulk
    /// paths should use [`Self::send`] + [`Self::recv`].
    pub fn request<Req, Rep>(&mut self, req: Req) -> Result<Rep, TransportError>
    where
        Req: Message,
        Rep: Message + Decode,
    {
        let context = self.send(req)?;
        let (got, reply) = self.recv::<Rep>()?;
        if got != context {
            return Err(TransportError::ContextMismatch {
                expected: context,
                got,
            });
        }
        Ok(reply)
    }

    /// Liveness probe. The plan's wedge detector: a VPP that answers
    /// this is scheduling its main loop, which a process-alive check
    /// (pidfd) cannot tell you.
    pub fn ping(&mut self) -> Result<u32, TransportError> {
        let reply: ControlPingReply = self.request(ControlPing { context: 0 })?;
        Ok(reply.vpe_pid)
    }

    /// Run a DUMP request and collect every streamed item.
    ///
    /// VPP dumps have **no end-of-stream marker**. The idiom every
    /// client uses is to trail the dump with a `control_ping`: replies
    /// come back in order, so the ping's reply arriving means the dump
    /// finished. That is why this cannot be expressed as
    /// [`Self::request`] — one request, N replies, and the terminator is
    /// a different message type.
    ///
    /// A message that is neither an item nor the terminator is a
    /// desynchronised stream, not something to skip: silently ignoring
    /// it would leave the next caller reading someone else's reply.
    pub fn dump<Req, Item>(&mut self, req: Req) -> Result<Vec<Item>, TransportError>
    where
        Req: Message,
        Item: Message + Decode,
    {
        let item_id = self.id_of::<Item>()?;
        let end_id = self.id_of::<ControlPingReply>()?;
        self.send(req)?;
        self.send(ControlPing { context: 0 })?;

        let mut out = Vec::new();
        loop {
            let payload = self.read_frame()?;
            let id = peek_msg_id(&payload)?;
            if id == end_id {
                return Ok(out);
            }
            if id != item_id {
                return Err(TransportError::UnknownReplyId(id));
            }
            let mut d = Decoder::new(&payload);
            out.push(Item::decode(&mut d)?);
        }
    }

    pub fn client_index(&self) -> u32 {
        self.client_index
    }

    /// Re-arm the socket's read/write timeouts after the handshake.
    ///
    /// [`Self::connect`]'s `timeout` governs the handshake *and*, because
    /// it is installed with `set_read_timeout`, every request that
    /// follows. Those two want very different values: a connect attempt
    /// should fail fast so the supervision loop stays responsive, while a
    /// request issued during a full-table load legitimately waits far
    /// longer — VPP answers the binary API on its main thread, the same
    /// thread executing the route batch.
    ///
    /// Leaving one short value in force means the transport errors before
    /// the wedge detector's budget expires, which hands the transport a
    /// veto over a decision that belongs to the detector: a busy but
    /// healthy VPP would be disconnected, requeued and eventually
    /// restarted. The socket timeout is a backstop against parking
    /// forever, not a liveness policy.
    pub fn set_timeout(&mut self, timeout: Duration) -> Result<(), TransportError> {
        self.sock.set_read_timeout(Some(timeout))?;
        self.sock.set_write_timeout(Some(timeout))?;
        Ok(())
    }

    /// Message id table, for callers that need to recognise async
    /// events. Read-only by design; nothing outside may mutate it.
    pub fn message_id(&self, name: &str) -> Option<u16> {
        self.ids.get(name).copied()
    }

    fn write_frame(&mut self) -> Result<(), TransportError> {
        let mut framed = Vec::with_capacity(MSG_HEADER_LEN + self.tx.len());
        write_frame_header(&mut framed, self.tx.len());
        framed.extend_from_slice(&self.tx);
        self.sock.write_all(&framed)?;
        self.sock.flush()?;
        Ok(())
    }

    /// Read exactly one framed message.
    ///
    /// `read_exact` rather than a single `read`: a unix stream may
    /// deliver a frame across several reads, and treating a short read
    /// as a complete message is how a parser silently desynchronises.
    fn read_frame(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut hdr = [0u8; MSG_HEADER_LEN];
        self.sock.read_exact(&mut hdr).map_err(|e| {
            // A closed socket mid-frame is VPP exiting, which the
            // supervisor treats differently from a protocol fault.
            if e.kind() == ErrorKind::UnexpectedEof {
                std::io::Error::new(ErrorKind::ConnectionAborted, "VPP closed the API socket")
            } else {
                e
            }
        })?;
        let len = parse_frame_header(&hdr);

        if len > MAX_PAYLOAD {
            return Err(TransportError::PayloadTooLarge(len));
        }
        self.rx.clear();
        self.rx.resize(len as usize, 0);
        self.sock.read_exact(&mut self.rx)?;
        Ok(std::mem::take(&mut self.rx))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vpp_api::codec::Encode;
    use crate::vpp_api::generated::MessageTableEntry;

    /// Build a `sockclnt_create_reply` payload whose table is
    /// name-and-CRC exactly as VPP composes it.
    fn table_reply(entries: &[(&str, &str, u16)], response: i32) -> Vec<u8> {
        let mut reply = SockclntCreateReply {
            context: 1,
            response,
            index: 42,
            count: entries.len() as u16,
            message_table: Vec::new(),
        };
        for (name, crc, idx) in entries {
            reply.message_table.push(MessageTableEntry {
                index: *idx,
                name: format!("{name}_{crc}"),
            });
        }
        let mut payload = Vec::new();
        // sockclnt_create_reply carries a client_index prefix.
        payload.extend_from_slice(&SOCKCLNT_CREATE_MSG_ID.to_be_bytes());
        payload.extend_from_slice(&42u32.to_be_bytes());
        reply.encode(&mut payload);
        payload
    }

    fn all_ours(mangle: Option<(&str, &str)>) -> Vec<(String, String, u16)> {
        MESSAGE_META
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let crc = match mangle {
                    Some((n, c)) if n == m.name => c.to_string(),
                    _ => m.crc.trim_start_matches("0x").to_string(),
                };
                (m.name.to_string(), crc, 100 + i as u16)
            })
            .collect()
    }

    fn verify(entries: &[(String, String, u16)], response: i32) -> Result<(), TransportError> {
        let owned: Vec<(&str, &str, u16)> = entries
            .iter()
            .map(|(n, c, i)| (n.as_str(), c.as_str(), *i))
            .collect();
        let payload = table_reply(&owned, response);
        let mut d = Decoder::new(&payload);
        let reply = SockclntCreateReply::decode(&mut d).unwrap();
        if reply.response != 0 {
            return Err(TransportError::HandshakeRefused(reply.response));
        }
        // Construct a bare Transport just to exercise verification;
        // connect() is covered by the integration test that needs a
        // real socket.
        let t = Transport {
            sock: UnixStream::pair().unwrap().0,
            client_index: 0,
            ids: HashMap::new(),
            context_offsets: HashMap::new(),
            next_context: 1,
            tx: Vec::new(),
            rx: Vec::new(),
        };
        t.verify_against(&reply)
    }

    #[test]
    fn a_matching_table_verifies() {
        assert!(verify(&all_ours(None), 0).is_ok());
    }

    #[test]
    fn a_crc_mismatch_is_refused_by_name() {
        let entries = all_ours(Some(("ip_route_add_del", "deadbeef")));
        match verify(&entries, 0) {
            Err(TransportError::CrcMismatch { name, theirs, .. }) => {
                assert_eq!(name, "ip_route_add_del");
                assert_eq!(theirs, "deadbeef");
            }
            other => panic!("expected a CRC mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_message_names_itself() {
        let mut entries = all_ours(None);
        entries.retain(|(n, _, _)| n != "dev_attach");
        match verify(&entries, 0) {
            Err(TransportError::MessageUnknown(name)) => assert_eq!(name, "dev_attach"),
            other => panic!("expected MessageUnknown, got {other:?}"),
        }
    }

    #[test]
    fn a_refused_handshake_surfaces_its_response_code() {
        match verify(&all_ours(None), -1) {
            Err(TransportError::HandshakeRefused(-1)) => {}
            other => panic!("expected HandshakeRefused, got {other:?}"),
        }
    }

    #[test]
    fn crc_comparison_ignores_case_and_the_0x_prefix() {
        // VPP's table gives a bare lowercase suffix; ours are `0x`-
        // prefixed. A naive string compare would reject every message
        // on a perfectly good connection.
        let entries: Vec<(String, String, u16)> = MESSAGE_META
            .iter()
            .enumerate()
            .map(|(i, m)| {
                (
                    m.name.to_string(),
                    m.crc.trim_start_matches("0x").to_uppercase(),
                    100 + i as u16,
                )
            })
            .collect();
        assert!(verify(&entries, 0).is_ok());
    }

    #[test]
    fn table_names_split_on_the_last_underscore() {
        // `ip_route_add_del_b8ecfe0d` must yield the full message name,
        // not `ip`. Splitting on the first underscore would leave every
        // multi-word message unresolvable.
        let (name, crc) = "ip_route_add_del_b8ecfe0d".rsplit_once('_').unwrap();
        assert_eq!(name, "ip_route_add_del");
        assert_eq!(crc, "b8ecfe0d");
    }
}
