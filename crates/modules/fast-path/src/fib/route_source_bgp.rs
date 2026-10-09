//! BGP route source, receives bird's selected best paths over an
//! iBGP session and translates UPDATEs into [`RouteEvent`]s for the
//! FibProgrammer.
//!
//! **Why BGP and not BMP for the forwarding feed.** Bird's BMP
//! implementation (as of bird master, April 2026) does not implement
//! RFC 9069 Loc-RIB, only `monitoring rib in pre_policy` /
//! `post_policy`, which deliver per-peer Adj-RIB-In streams. For a
//! prefix announced by N peers, that's N RouteMonitoring frames with
//! N different nexthops, leaving the FibProgrammer to either
//! re-implement bird's best-path selection (drift risk forever) or
//! pick wrong. iBGP, by contrast, has bird's `protocol bgp` export
//! filter run after best-path selection. Without ADD-PATH the export
//! emits exactly one UPDATE per prefix with the path bird picked;
//! with ADD-PATH negotiated, the export emits one UPDATE per path
//! bird kept (typically equal-cost multipath), each tagged with a
//! distinct `path_id` per RFC 7911 §3, and the FibProgrammer
//! aggregates them into an ECMP group on the prefix. See
//! `docs/runbooks/packetframe-fib.md` "Phase 4 bird config" for the
//! `protocol bgp packetframe { ... }` snippet and the
//! "Multi-NH ECMP from BGP" section for the ADD-PATH enablement
//! steps.
//!
//! **Direction.** This is a *passive* BGP speaker: packetframe
//! listens, bird connects out (configurable via bird's
//! `neighbor 127.0.0.1 port <port> as <asn>`). Same direction as the
//! BMP station so both feeds work the same operationally.
//!
//! **Capabilities advertised in OPEN.**
//! - Multi-Protocol Extensions (RFC 4760) for IPv4 unicast and
//!   IPv6 unicast, without this bird only sends v4 routes over
//!   the session.
//! - Four-octet ASN (RFC 6793), required for any modern AS
//!   numbering when the local AS is greater than 65535.
//! - ADD-PATH (RFC 7911) with Receive direction (Send/Receive
//!   value 1) for both IPv4 unicast and IPv6 unicast. Peer-side
//!   capability negotiation is decoded by
//!   [`walk_open_capabilities`]; mutual negotiation flips the
//!   per-message `add_path` flag in [`parse_bgp_message`] for the
//!   session. ADD-PATH is treated all-or-nothing across the two
//!   AFIs because `bgpkit_parser::parse_bgp_message` takes one
//!   per-message `add_path: bool` rather than a per-AFI flag; an
//!   asymmetric advertisement falls back to non-ADD-PATH decoding
//!   for both AFIs.
//! - Route Refresh is **not** advertised. We never originate routes,
//!   so bird has nothing to ask us to refresh.
//!
//! **Hold time.** Proposed at [`DEFAULT_HOLD_TIME`] (90 s); the
//! effective hold is `min(ours, peer's)` after the OPEN exchange.
//! KEEPALIVEs are sent at `effective_hold / 3` by a task of their own
//! ([`keepalive_writer`]), and our hold timer runs in the reader
//! ([`reader_task`]), so neither direction's liveness waits on route
//! processing.
//!
//! **What we never send.** No UPDATE, no NOTIFICATION (we close on
//! protocol error rather than send a structured NOTIFICATION, bird
//! reconnects either way), no ROUTE-REFRESH (we don't advertise the
//! capability).
//!
//! **Disconnect handling.** Mirrors `BmpStation`: TCP close → emit
//! [`RouteEvent::Resync`] → re-listen → on reconnect, bird's full
//! RIB streams in and the InitiationComplete quiescence timer fires.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bgpkit_parser::models::{Asn, AsnLength, BgpMessage, ElemType, NetworkPrefix};
use bgpkit_parser::parser::bgp::messages::parse_bgp_message;
use bgpkit_parser::Elementor;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use packetframe_common::fib::{IpPrefix, PeerId, RouteEvent, RouteSourceError};

use crate::fib::programmer::FibProgrammerHandle;
use crate::fib::route_source_bmp::SharedIntegritySnapshot;

// --- Wire constants ---------------------------------------------------------

/// BGP message marker, 16 bytes of 0xFF per RFC 4271 §4.1.
const BGP_MARKER: [u8; 16] = [0xFF; 16];

/// Minimum BGP message length (header only, KEEPALIVE).
const BGP_HEADER_LEN: usize = 19;

/// Cap on a single BGP message size. RFC 8654 extends OPEN/KEEPALIVE
/// to 4096 max and UPDATE/NOTIFICATION to 65535. Use the larger
/// envelope for the framing buffer.
const MAX_BGP_MSG_SIZE: usize = 65535;

/// BGP message-type bytes (RFC 4271 §4.1). Kept as named constants
/// for readability at call sites and self-documentation of the
/// protocol; UPDATE / NOTIFICATION are recognized via bgpkit-parser's
/// typed enum, so the constants don't appear directly in code.
const MSG_TYPE_OPEN: u8 = 1;
#[allow(dead_code)]
const MSG_TYPE_UPDATE: u8 = 2;
#[allow(dead_code)]
const MSG_TYPE_NOTIFICATION: u8 = 3;
const MSG_TYPE_KEEPALIVE: u8 = 4;
const MSG_TYPE_ROUTE_REFRESH: u8 = 5;

/// AS_TRANS placeholder (RFC 6793 §4.2.4): the 2-byte "My AS" field
/// in OPEN holds 23456 when the real ASN is > 65535. The peer reads
/// the actual 4-byte ASN out of the four-octet-ASN capability.
const AS_TRANS: u16 = 23456;

/// Default proposed hold time. Negotiated down to peer's value if
/// peer proposes lower. RFC 4271 recommends ≥ 3 seconds; 90 is the
/// Cisco/Juniper convention and matches bird's default.
pub const DEFAULT_HOLD_TIME: u16 = 90;

/// BMP/BGP idiom: the InitiationComplete quiescence timer fires
/// once after [`INIT_COMPLETE_QUIESCENCE`] of no UPDATE traffic
/// post the first UPDATE, signaling "initial RIB dump done."
const INIT_COMPLETE_QUIESCENCE: Duration = Duration::from_secs(5);

/// Bounded reader→main channel capacity (frames).
const FRAME_CHANNEL_CAPACITY: usize = 256;

/// Cap on time spent waiting for the peer's OPEN after we send
/// ours. RFC 4271's 120s ConnectRetry default applies to the
/// *active* connector waiting for TCP to come up, we're the
/// passive side with TCP already established, where real peers
/// send OPEN within milliseconds. 10s is comfortable headroom that
/// still bounds the slowloris primitive a misconfigured (or
/// hostile) peer can leverage against the single-connection accept
/// loop (audit Slice 2).
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on iterations through one UPDATE's per-prefix elems. A
/// single attacker-controlled UPDATE can encode tens of thousands
/// of NLRI entries that bgpkit-parser's `Elementor` fans out into
/// `BgpElem`s, each of which `apply_route_event().await`s, a
/// control-plane amplification primitive flagged by the audit
/// (Slice 2). 8192 leaves comfortable headroom above any
/// realistic bird best-path stream (a full v4 table is ~960K
/// prefixes spread across many UPDATEs) while putting an explicit
/// ceiling on per-message work.
const MAX_ELEMS_PER_UPDATE: usize = 8192;

// --- BgpListener ------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BgpListenerConfig {
    pub listen_addr: SocketAddr,
    pub local_as: u32,
    pub peer_as: u32,
    pub router_id: Ipv4Addr,
    pub hold_time: u16,
    /// CIDR ACL applied at `accept()`. Empty means "loopback only"
    /// the config parser only permits empty when `listen_addr` is
    /// loopback. When non-empty, every accepted source IP must fall
    /// within at least one entry or the connection is dropped before
    /// the BGP OPEN exchange.
    pub peer_acl: Vec<ipnet::IpNet>,
    /// Optional pin on the peer's source IP. When `Some(_)`, an
    /// accepted connection whose source IP differs is closed
    /// immediately. The pre-existing `peer_as` cross-check inside
    /// `handle_connection` then closes any session whose OPEN ASN
    /// disagrees with the configured value. Together these two
    /// checks are the only identity binding available in the
    /// absence of TCP-MD5 / TCP-AO.
    pub expected_peer_ip: Option<IpAddr>,
    /// Session-liveness handle, reported to the second tier. See
    /// [`packetframe_common::fib::FeedSession`] for why this travels
    /// out-of-band of the route events.
    pub session: Option<std::sync::Arc<packetframe_common::fib::FeedSession>>,
}

impl BgpListenerConfig {
    pub fn new(listen_addr: SocketAddr, local_as: u32, peer_as: u32, router_id: Ipv4Addr) -> Self {
        Self {
            listen_addr,
            local_as,
            peer_as,
            router_id,
            hold_time: DEFAULT_HOLD_TIME,
            peer_acl: Vec::new(),
            expected_peer_ip: None,
            session: None,
        }
    }
}

/// Whether `addr` is permitted by the listener's `peer_acl`. An empty
/// ACL means "loopback only", the config parser already enforces
/// that empty + non-loopback listen is rejected, so an empty ACL
/// implies the listener bound to loopback and only loopback sources
/// can reach `accept()` in the first place. We still defensively
/// double-check `is_loopback()` here so a misconstructed in-process
/// config can't slip past.
fn source_ip_permitted(addr: IpAddr, peer_acl: &[ipnet::IpNet]) -> bool {
    if peer_acl.is_empty() {
        addr.is_loopback()
    } else {
        peer_acl.iter().any(|net| net.contains(&addr))
    }
}

pub struct BgpListener {
    cfg: BgpListenerConfig,
    prog_handle: FibProgrammerHandle,
    shutdown: CancellationToken,
    /// Unix seconds of the last UPDATE accepted; 0 = none since process
    /// start. Written and, today, read by nothing: unlike `BmpStation`,
    /// this listener spawns no stall monitor (see `stall_gate`).
    last_update_unix: Arc<AtomicI64>,
    /// The integrity snapshot the controller hands every route source
    /// for a stall monitor. Stored, not yet consulted. `BmpStation`'s
    /// `stall_monitor` is not a fit as it stands: it only logs, and it
    /// gates on `authority_established_peers`, which only the bird
    /// authority fills, so on an FRR-fed box it would stay silent. A
    /// programmer wedged behind an established session is therefore
    /// reported by nothing on this path yet.
    stall_gate: Option<SharedIntegritySnapshot>,
    /// Empty outside tests; see [`ReadHold`].
    read_hold: ReadHold,
}

impl BgpListener {
    pub fn new(
        cfg: BgpListenerConfig,
        prog_handle: FibProgrammerHandle,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            cfg,
            prog_handle,
            shutdown,
            last_update_unix: Arc::new(AtomicI64::new(0)),
            stall_gate: None,
            read_hold: ReadHold::default(),
        }
    }

    /// Same builder as `BmpStation::with_stall_gate`, but nothing here
    /// reads the snapshot yet: see the `stall_gate` field.
    pub fn with_stall_gate(mut self, snapshot: SharedIntegritySnapshot) -> Self {
        self.stall_gate = Some(snapshot);
        self
    }

    /// Accept loop. One bird connection at a time; on disconnect emit
    /// `Resync` and re-accept.
    pub async fn run(self) -> Result<(), RouteSourceError> {
        let listener = bind_with_reuseaddr(self.cfg.listen_addr)
            .map_err(|e| RouteSourceError::fatal(format!("bind {}: {e}", self.cfg.listen_addr)))?;
        let loopback_only = self.cfg.listen_addr.ip().is_loopback()
            && self.cfg.peer_acl.is_empty()
            && self.cfg.expected_peer_ip.is_none();
        info!(
            addr = %self.cfg.listen_addr,
            local_as = self.cfg.local_as,
            peer_as = self.cfg.peer_as,
            peer_acl_entries = self.cfg.peer_acl.len(),
            peer_ip_pin = ?self.cfg.expected_peer_ip,
            auth_posture = if loopback_only { "loopback-only" } else { "allow-remote (no TCP-MD5)" },
            "BGP listener started"
        );

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("BgpListener shutdown requested");
                    return Ok(());
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            // Source-IP gating runs before any byte is
                            // read: an unauthorized peer must not reach
                            // BGP framing because that's the surface the
                            // audit (May 2026) flagged as the
                            // arbitrary-route-injection primitive.
                            if !source_ip_permitted(addr.ip(), &self.cfg.peer_acl) {
                                warn!(
                                    %addr,
                                    peer_acl_entries = self.cfg.peer_acl.len(),
                                    "BGP accept rejected: source IP outside peer-from ACL"
                                );
                                drop(stream);
                                continue;
                            }
                            if let Some(expected) = self.cfg.expected_peer_ip {
                                if addr.ip() != expected {
                                    warn!(
                                        %addr,
                                        %expected,
                                        "BGP accept rejected: source IP does not match peer-ip pin"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            }
                            info!(%addr, "BGP client connected");
                            if let Err(e) = self.handle_connection(stream).await {
                                warn!(error = %e, "BGP connection handler exited with error");
                            } else {
                                info!("BGP client disconnected cleanly");
                            }
                            // However the session ended — clean close,
                            // NOTIFICATION, hold-timer expiry — it is
                            // down now, and the hold timer above is what
                            // bounds how long a hung session could have
                            // kept the flag stale.
                            if let Some(sess) = &self.cfg.session {
                                sess.set_up(false);
                            }
                            if let Err(e) = self
                                .prog_handle
                                .apply_route_event(RouteEvent::Resync)
                                .await
                            {
                                warn!(error = %e, "Resync dispatch failed");
                            }
                        }
                        Err(e) => warn!(error = %e, "TCP accept failed"),
                    }
                }
            }
        }
    }

    /// Handshake + drain one BGP session.
    async fn handle_connection(&self, mut stream: TcpStream) -> Result<(), RouteSourceError> {
        // Step 1: send our OPEN.
        let open = encode_open(self.cfg.local_as, self.cfg.hold_time, self.cfg.router_id);
        stream
            .write_all(&open)
            .await
            .map_err(|e| RouteSourceError::recoverable(format!("send OPEN: {e}")))?;
        debug!("sent OPEN");

        // Step 2: read peer's OPEN within OPEN_TIMEOUT and validate.
        // OPEN itself is always decoded with add_path=false; capability
        // 69 negotiation completes only after OPEN parsing succeeds.
        let peer_open = tokio::time::timeout(OPEN_TIMEOUT, read_one_message(&mut stream, false))
            .await
            .map_err(|_| RouteSourceError::recoverable("peer OPEN timeout".to_string()))?
            .map_err(|e| RouteSourceError::recoverable(format!("read peer OPEN: {e}")))?;
        let (effective_hold, peer_asn_observed, add_path_in_effect) = match peer_open {
            BgpMessage::Open(o) => {
                if o.version != 4 {
                    return Err(RouteSourceError::recoverable(format!(
                        "peer BGP version {}; expected 4",
                        o.version
                    )));
                }
                let peer_asn_2byte = asn_to_u32(o.asn);
                let negotiated = walk_open_capabilities(&o.opt_params);
                // RFC 6793: when the peer supports 4-octet ASNs, the
                // 2-byte field carries AS_TRANS (23456) and the real
                // ASN comes via capability 65. Resolve the effective
                // ASN by preferring the capability when present, then
                // cross-check against the operator-configured
                // `peer_as`. Pre-audit this was a soft warning; the
                // audit (May 2026) flagged it as the second leg of
                // the "anyone-can-speak-iBGP" Critical finding, so
                // it's now a session-fatal close.
                let effective_peer_asn = negotiated.four_octet_asn.unwrap_or(peer_asn_2byte);
                if effective_peer_asn != self.cfg.peer_as {
                    return Err(RouteSourceError::recoverable(format!(
                        "peer ASN mismatch in OPEN: observed {effective_peer_asn} (2-byte field {peer_asn_2byte}, 4-octet cap {:?}), expected {}, closing session",
                        negotiated.four_octet_asn, self.cfg.peer_as
                    )));
                }
                let effective_hold = self.cfg.hold_time.min(o.hold_time).max(3);
                let add_path_in_effect = negotiated.add_path_in_effect();
                info!(
                    peer_asn = effective_peer_asn,
                    peer_router_id = %o.bgp_identifier,
                    effective_hold,
                    add_path_in_effect,
                    add_path_v4 = negotiated.add_path_v4_recv,
                    add_path_v6 = negotiated.add_path_v6_recv,
                    "received peer OPEN"
                );
                (effective_hold, effective_peer_asn, add_path_in_effect)
            }
            other => {
                return Err(RouteSourceError::recoverable(format!(
                    "expected OPEN, got {:?}",
                    other.msg_type()
                )));
            }
        };

        // Step 3: send KEEPALIVE to confirm OPEN.
        stream
            .write_all(&encode_keepalive())
            .await
            .map_err(|e| RouteSourceError::recoverable(format!("send KEEPALIVE: {e}")))?;

        // Step 4: established. The connection splits three ways: the
        // reader frames messages and runs the hold timer, the writer
        // sends the periodic KEEPALIVEs, and this loop applies what the
        // reader framed, in order. Both liveness duties used to live in
        // this loop's `select!`, where they waited out every
        // `process_msg` await, so a full-table load behind a slow
        // programmer went quiet toward the peer for its whole hold time
        // and the peer tore the session down (2026-08-19, 2026-10-07),
        // costing a full re-dump each time.
        let (read_half, write_half) = stream.into_split();
        let (frame_tx, mut frame_rx) = mpsc::channel::<Frame>(FRAME_CHANNEL_CAPACITY);
        let hold = Duration::from_secs(effective_hold as u64);
        let mut reader = SessionTask(tokio::spawn(reader_task(
            read_half,
            frame_tx,
            add_path_in_effect,
            hold,
            self.read_hold.clone(),
        )));
        let mut writer = SessionTask(tokio::spawn(keepalive_writer(
            write_half,
            Duration::from_secs(effective_hold.max(3) as u64 / 3),
        )));

        // Deliberately NOT live yet: OPEN proves the SESSION, not the
        // table. A session that establishes and then delays its first
        // UPDATE would read as live-and-quiet, and two seconds of
        // pre-stream quiet releases the second tier's gate onto a
        // mirror holding only local routes (review finding). Liveness
        // raises on the FIRST UPDATE of the session — the stream has
        // started, which is all "live" must attest. It must NOT wait
        // for post-stream silence: a live DFZ feed never pauses five
        // seconds (measured on the shadow, 2026-08-09 — 91 minutes of
        // session, zero InitiationComplete firings, the reconciliation
        // wedged behind a silence that cannot come). Whether the load
        // has FINISHED is the release gate's question, and its
        // mirror-scaled rate answers it: an initial load runs orders
        // of magnitude above the quiet rate, so live-but-loading can
        // never release early.
        let mut init_complete_fired = false;
        let mut updates_seen = 0usize;

        // Synthetic peer_id for an iBGP session: bird is the singular
        // peer here, so PeerId is constant. We hash (peer_ip, peer_asn)
        // for stability across reconnects.
        let peer_id = synthetic_peer_id(self.cfg.listen_addr, peer_asn_observed);

        // Every return below drops `reader` and `writer`, which aborts
        // them: see `SessionTask`.
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    return Ok(());
                }
                frame = frame_rx.recv() => {
                    match frame {
                        Some(Frame::Message(m)) => {
                            self.process_msg(m, peer_id, peer_asn_observed, &mut updates_seen).await?;
                        }
                        Some(Frame::Quiet) => {
                            // InitiationComplete heuristic. The reader sends
                            // Quiet only once it has gone
                            // INIT_COMPLETE_QUIESCENCE without reading an
                            // UPDATE and has just found the socket empty, and
                            // Quiet travels behind every UPDATE it read: so
                            // here the peer has been quiet that long by the
                            // socket's own account, and everything it sent
                            // before has been applied. See `reader_task` for
                            // why only the reader can judge that.
                            if !init_complete_fired {
                                if let Err(e) = self
                                    .prog_handle
                                    .apply_route_event(RouteEvent::InitiationComplete)
                                    .await
                                {
                                    warn!(error = %e, "InitiationComplete dispatch failed");
                                } else {
                                    info!(
                                        updates_seen,
                                        quiescence_secs = INIT_COMPLETE_QUIESCENCE.as_secs(),
                                        "InitiationComplete fired"
                                    );
                                    init_complete_fired = true;
                                    // The GC this event triggers removed
                                    // every unseen prior-session route,
                                    // so the mirror is now this epoch's
                                    // and nothing of the one before it.
                                    // The second tier's gate treats this
                                    // — and nothing else — as grounds to
                                    // trust an authority report again
                                    // after a session flap.
                                    //
                                    // Safe HERE, unlike the BMP station:
                                    // the reader sends Quiet only after
                                    // an UPDATE, and Quiet follows it
                                    // through the channel, so
                                    // `process_msg` has already accepted
                                    // that UPDATE and raised on the
                                    // session's first, and the epoch is
                                    // open. Marking before a raise stamps
                                    // the epoch that is ending and
                                    // `set_up` clears it a moment later
                                    // (review finding, on the BMP path).
                                    // Do not move this above the raise.
                                    if let Some(sess) = &self.cfg.session {
                                        sess.mark_reconciled();
                                    }
                                }
                            }
                        }
                        None => {
                            // Reader exited (EOF, read error, or hold
                            // timer expiry), surface the result.
                            return match (&mut reader.0).await {
                                Ok(Ok(())) => {
                                    debug!(updates_seen, "BGP stream done");
                                    Ok(())
                                }
                                Ok(Err(e)) => Err(e),
                                Err(e) => Err(RouteSourceError::recoverable(format!(
                                    "reader task join: {e}"
                                ))),
                            };
                        }
                    }
                }
                ended = &mut writer.0 => {
                    // The writer returns only when a KEEPALIVE could not
                    // be written: the peer's hold timer is now running
                    // down with nothing to reset it, so end the session
                    // here rather than wait for the peer to.
                    return Err(ended.unwrap_or_else(|e| {
                        RouteSourceError::recoverable(format!("keepalive writer join: {e}"))
                    }));
                }
            }
        }
    }

    /// `Err` is session-fatal: the caller must tear the connection
    /// down. It was `()` until a review pass caught the oversized-
    /// UPDATE arm logging "closing session" while only returning from
    /// this helper — the connection lived on, quiesced, fired
    /// InitiationComplete, and marked a feed LIVE whose last UPDATE
    /// had been thrown away whole.
    async fn process_msg(
        &self,
        msg: BgpMessage,
        peer_id: PeerId,
        peer_asn: u32,
        updates_seen: &mut usize,
    ) -> Result<(), RouteSourceError> {
        match msg {
            BgpMessage::Open(_) => {
                // Spurious post-handshake OPEN, bird shouldn't do
                // this. Log + ignore.
                warn!("unexpected OPEN after handshake");
            }
            BgpMessage::KeepAlive => {
                // The reader re-armed the hold timer when it read this;
                // no further work.
            }
            BgpMessage::Notification(n) => {
                // Session-fatal for real, not just in the log line: a
                // NOTIFICATION ends the session per RFC 4271, and while
                // bird usually closes the TCP right after (the reader
                // would see EOF), waiting on the peer's close leaves a
                // window where the connection quiesces, settles, and
                // reports a feed live that its peer has already
                // renounced.
                return Err(RouteSourceError::recoverable(format!(
                    "received NOTIFICATION ({:?}); closing session",
                    n.error
                )));
            }
            BgpMessage::Update(update) => {
                // Pretend the peer-IP for Elementor is the listen
                // address (bird-side IP isn't carried in BGP UPDATE
                // we know it from the connection, but Elementor
                // doesn't need an accurate value, just something
                // stable for elem.peer_ip). For peer_asn we pass
                // bird's observed ASN.
                let peer_ip_for_elems = self.cfg.listen_addr.ip();
                let peer_asn_for_elems = Asn::from(peer_asn);
                let elems = Elementor::bgp_update_to_elems(
                    update,
                    0.0,
                    &peer_ip_for_elems,
                    &peer_asn_for_elems,
                );
                let fallback_nh = self.cfg.listen_addr.ip();
                if elems.len() > MAX_ELEMS_PER_UPDATE {
                    // Session-fatal: leaving an UPDATE half-applied
                    // would put the FIB in a torn state across
                    // peer_id's mirror, and we don't want the next
                    // attacker-shaped UPDATE to just keep adding to
                    // the per-message budget. Close, emit Resync,
                    // let the peer reconnect.
                    return Err(RouteSourceError::recoverable(format!(
                        "BGP UPDATE fanned out to {} elems (cap {}); closing session — a \
                         skipped UPDATE must not leave a session that later settles and \
                         reports a feed live with that UPDATE's prefixes missing",
                        elems.len(),
                        MAX_ELEMS_PER_UPDATE
                    )));
                }
                // ACCEPTED — and not one line earlier. Everything below
                // records this UPDATE as stream evidence, and the cap
                // above closes the session, so recording it first meant
                // publishing a feed EPOCH for an UPDATE that never
                // applied. A runtime sampling that transient raise
                // during an adopted deferral baselines on it, the next
                // healthy connection reads as a flap, and the
                // attestation is gone for good (review finding; the
                // BMP path had the same ordering).
                *updates_seen += 1;
                self.last_update_unix.store(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64,
                    Ordering::Relaxed,
                );
                if *updates_seen == 1 {
                    // The stream has started; see the handshake note
                    // for why this — and not post-stream silence — is
                    // where the session becomes live.
                    //
                    // DELIBERATELY UNLIKE `BmpStation`, which withholds
                    // this raise while a previous stream's routes may
                    // still sit in the mirror (`stale_state_possible`)
                    // and waits for InitiationComplete's GC. The
                    // asymmetry is the point, not an oversight: that
                    // wait is five seconds of UPDATE silence, and a
                    // live DFZ feed does not go quiet for five seconds
                    // — measured on the shadow 2026-08-09, 91 minutes
                    // of session and zero InitiationComplete firings.
                    // Porting the guard here would re-create #152 on
                    // the one path the fleet actually runs, trading a
                    // narrow staleness window for a reconciliation that
                    // never happens at all.
                    //
                    // What covers the window instead: a reconnect's
                    // stale credit only reaches the floor door if the
                    // stream ALSO stalls immediately (a streaming dump
                    // runs orders of magnitude above the quiet rate),
                    // and on any deployment with a completeness
                    // authority the drift a stale mirror shows against
                    // bird's current count vetoes the release outright.
                    // The residual is an unattested deployment whose
                    // feed reconnects and then stops mid-dump; it is
                    // named here rather than closed, because closing it
                    // the obvious way is worse.
                    if let Some(sess) = &self.cfg.session {
                        sess.set_up(true);
                    }
                }
                if let Some(sess) = &self.cfg.session {
                    // Stream activity in ROUTE-ELEMENT units, changed
                    // or not: a reconnect reannounces an unchanged
                    // table, the mirror never moves, and the gate
                    // compares activity against route-scaled quiet
                    // rates — counting frames instead of the elements
                    // they fan out to let a batched million-route dump
                    // read as quiet (review finding). Floored at one
                    // unit so an empty UPDATE (End-of-RIB shape) still
                    // counts as stream evidence — one unit against
                    // route-scaled rates is noise.
                    sess.pulse_n((elems.len() as u64).max(1));
                }
                for elem in elems {
                    let event = match elem_to_route_event(&elem, peer_id, fallback_nh) {
                        Some(e) => e,
                        None => continue,
                    };
                    if let Err(e) = self.prog_handle.apply_route_event(event).await {
                        warn!(error = %e, "route event dispatch failed");
                    }
                }
            }
        }
        Ok(())
    }
}

// --- Session tasks ----------------------------------------------------------

/// A task that lives exactly as long as one session: dropping it aborts
/// it, so every way out of `handle_connection` (a returned error,
/// shutdown, the caller dropping the future) ends it. A writer that
/// outlived its session would hold the dead connection open and keep
/// its KEEPALIVEs going across the reconnect; a reader would hold the
/// read half until the peer closed its end.
struct SessionTask<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for SessionTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sends the periodic KEEPALIVEs (RFC 4271 §4.4) every `period`,
/// owning the write half. It shares no await with route processing,
/// which is the point: the peer's hold timer is fed by these alone, so
/// how long we take to apply its UPDATEs must not decide when they go
/// out. The OPEN-confirming KEEPALIVE is not this task's: it went out
/// before the split, so it still precedes every periodic one.
///
/// Returns only when a write fails, with the error that ends the
/// session. `handle_connection` aborts it when the session ends any
/// other way.
async fn keepalive_writer<W>(mut stream: W, period: Duration) -> RouteSourceError
where
    W: AsyncWriteExt + Unpin + Send,
{
    let keepalive = encode_keepalive();
    let mut tick = tokio::time::interval(period);
    // `Delay`, not the default `Burst`: a writer descheduled across
    // several periods would fire the missed ticks back to back, and
    // RFC 4271 §4.4 forbids KEEPALIVEs more often than one per second,
    // which a 3 s hold's period is exactly. `Skip` keeps the original
    // grid, so the tick after a late one can land under a period later.
    // `Delay` restarts the period from the late send.
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick.tick().await; // skip immediate fire
    loop {
        tick.tick().await;
        if let Err(e) = stream.write_all(&keepalive).await {
            return RouteSourceError::recoverable(format!("send periodic KEEPALIVE: {e}"));
        }
    }
}

/// What the reader hands the main loop, in the order it happened.
enum Frame {
    Message(BgpMessage),
    /// No UPDATE read for [`INIT_COMPLETE_QUIESCENCE`], judged on an
    /// empty socket; see `reader_task`. Behind every UPDATE read before
    /// it, so the main loop applies InitiationComplete only after them.
    Quiet,
}

/// Test seam: holds the reader between handing a message over and
/// starting its next read, the way a reader the scheduler has not run
/// yet sits. Empty outside tests, where `wait` returns at once.
#[derive(Clone, Default)]
struct ReadHold {
    #[cfg(test)]
    open: Option<tokio::sync::watch::Receiver<bool>>,
}

impl ReadHold {
    async fn wait(&mut self) {
        #[cfg(test)]
        if let Some(open) = self.open.as_mut() {
            let _ = open.wait_for(|open| *open).await;
        }
    }
}

/// Drains the TCP stream, parses BGP messages, and forwards them to
/// the main `select!` loop via a bounded channel, and runs the
/// session's hold timer and its quiescence judgement. Same
/// cancel-safety pattern as `BmpStation::reader_task`.
///
/// `add_path` carries the result of OPEN-time RFC 7911 capability
/// negotiation (computed by [`walk_open_capabilities`]). It controls
/// the per-message NLRI decode in [`read_one_message`]: when true,
/// every prefix in MP_REACH / MP_UNREACH / legacy NLRI is prefixed
/// by a 4-byte path_id.
async fn reader_task<R>(
    mut stream: R,
    tx: mpsc::Sender<Frame>,
    add_path: bool,
    hold: Duration,
    mut read_hold: ReadHold,
) -> Result<(), RouteSourceError>
where
    R: AsyncReadExt + Unpin + Send,
{
    let mut messages_parsed = 0usize;
    // When the session goes quiet if no UPDATE comes first: set by each
    // UPDATE read, cleared once Quiet is sent.
    let mut quiet_at: Option<tokio::time::Instant> = None;
    loop {
        read_hold.wait().await;
        // THE HOLD TIMER (RFC 4271 §6.5) is this timeout, armed afresh
        // for every message, and it runs only while we wait on the
        // socket. That is the one interval that says anything about the
        // peer.
        //
        // The other place this task waits is `tx.send` below, when the
        // main loop is behind and the channel is full. That is
        // backpressure, not silence: the peer's messages are queued in
        // our receive buffer, and TCP flow control holds the rest in its
        // send buffer. A last-receipt timestamp checked from anywhere
        // else would count those seconds against the peer and expire a
        // healthy session exactly when ingest is slowest, a full-table
        // load behind a slow programmer. A read that starts after the
        // stall finds the queued messages at once instead, and
        // `timeout` polls the read before it checks its deadline, so a
        // reader that was starved of CPU past the deadline still takes
        // the bytes that arrived rather than expiring over them.
        //
        // A dead peer is still caught. We stop reading only while the
        // channel is full, and resume as soon as the main loop takes
        // one frame, so a peer that died while we were behind expires
        // `hold` after we catch up with what it sent before dying. A
        // main loop that never takes another frame (a wedged
        // programmer) keeps the session up: that is our fault, not the
        // peer's, and this timer is not the place to report it.
        let read = tokio::time::timeout(hold, read_one_message(&mut stream, add_path));
        tokio::pin!(read);
        let read = loop {
            // QUIESCENCE (InitiationComplete, which GCs whatever the
            // session has not re-sent) is judged here too, and only
            // here: no UPDATE read for INIT_COMPLETE_QUIESCENCE, AND the
            // socket found empty. Only this task can see the second
            // half. Anywhere else, UPDATEs still unread in our receive
            // buffer are invisible: counting what was read against what
            // was applied, and timing from when it was read, declared
            // quiet whenever the main loop caught up with a reader the
            // scheduler had not yet run to read the rest, and after a
            // stall longer than the window the stamps it compared were
            // old, so the GC ran mid-reload (review finding).
            //
            // `biased` polls the read first, so Quiet goes out only on
            // a poll where the read found nothing, and an overdue
            // deadline after a stall loses to whatever the stall left
            // in the buffer. A budget-starved poll cannot pass for an
            // empty socket: the sleep is budgeted too and stays pending
            // with it. KEEPALIVEs do not restart the window; if they
            // did, a hold time under 15 s (a KEEPALIVE more often than
            // every 5 s) would keep it shut for good. Quiet queues
            // behind every UPDATE handed over, so it reaches the main
            // loop only after they are applied.
            let quiet = async move {
                match quiet_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                biased;
                read = &mut read => break read,
                () = quiet => {
                    quiet_at = None;
                    if tx.send(Frame::Quiet).await.is_err() {
                        debug!(messages_parsed, "frame receiver closed; reader exiting");
                        return Ok(());
                    }
                }
            }
        };
        let msg = match read {
            Err(_) => {
                return Err(RouteSourceError::recoverable(format!(
                    "hold timer ({} s) expired",
                    hold.as_secs()
                )));
            }
            Ok(Ok(m)) => m,
            Ok(Err(e)) if is_clean_eof(&e) => {
                debug!(messages_parsed, "BGP stream EOF (reader)");
                return Ok(());
            }
            Ok(Err(e)) => {
                return Err(RouteSourceError::recoverable(format!(
                    "read message after {messages_parsed}: {e}"
                )));
            }
        };
        messages_parsed += 1;
        if matches!(msg, BgpMessage::Update(_)) {
            quiet_at = Some(tokio::time::Instant::now() + INIT_COMPLETE_QUIESCENCE);
        }
        if tx.send(Frame::Message(msg)).await.is_err() {
            debug!(messages_parsed, "frame receiver closed; reader exiting");
            return Ok(());
        }
    }
}

/// Read one BGP message off the stream. Reads the 19-byte header,
/// pulls the declared length, reads the rest, and parses with
/// bgpkit-parser. Filters ROUTE-REFRESH (type 5) before parsing
/// because bgpkit-parser doesn't model it.
///
/// `add_path` selects RFC 7911 NLRI decoding for this message. The
/// flag must reflect what was negotiated in OPEN: the BGP wire format
/// for NLRI differs depending on whether path_id is present, so a
/// mismatch desynchronizes the parser and corrupts every subsequent
/// prefix in the UPDATE. The OPEN itself is always read with
/// `add_path = false` (negotiation cannot have completed yet);
/// post-OPEN messages use the value computed by
/// [`walk_open_capabilities`].
async fn read_one_message<R>(stream: &mut R, add_path: bool) -> std::io::Result<BgpMessage>
where
    R: AsyncReadExt + Unpin,
{
    let mut header = [0u8; BGP_HEADER_LEN];
    stream.read_exact(&mut header).await?;

    if header[..16] != BGP_MARKER {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "BGP marker not all 0xFF",
        ));
    }
    let length = u16::from_be_bytes([header[16], header[17]]) as usize;
    let msg_type = header[18];
    if !(BGP_HEADER_LEN..=MAX_BGP_MSG_SIZE).contains(&length) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid BGP message length {length}"),
        ));
    }

    let body_len = length - BGP_HEADER_LEN;
    let mut body = vec![0u8; body_len];
    if body_len > 0 {
        stream.read_exact(&mut body).await?;
    }

    // ROUTE-REFRESH (type 5) is RFC 2918, optional. bgpkit-parser
    // doesn't model it; skip silently, bird shouldn't send refresh
    // requests to us anyway since we don't advertise the capability.
    if msg_type == MSG_TYPE_ROUTE_REFRESH {
        debug!("ignoring ROUTE-REFRESH");
        return Ok(BgpMessage::KeepAlive); // benign placeholder; resets hold
    }

    // Reconstruct full frame for parse_bgp_message.
    let mut full = BytesMut::with_capacity(length);
    full.extend_from_slice(&header);
    full.extend_from_slice(&body);
    let mut bytes: Bytes = full.freeze();

    parse_bgp_message(&mut bytes, add_path, &AsnLength::Bits32)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))
}

fn is_clean_eof(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::UnexpectedEof
}

// --- Wire encoders ----------------------------------------------------------

/// Build the OPEN message. Capabilities advertised:
/// - MP-BGP IPv4 unicast (AFI=1, SAFI=1)
/// - MP-BGP IPv6 unicast (AFI=2, SAFI=1)
/// - ADD-PATH (RFC 7911, capability code 69) for IPv4 unicast and
///   IPv6 unicast, Send/Receive value `1` (Receive). PacketFrame never
///   originates routes, so only the Receive direction is advertised.
///   A peer that also wishes to send multiple paths must advertise
///   capability 69 with Send (value `2`) or both (value `3`) for the
///   matching AFI/SAFI; mutual negotiation is decoded in the OPEN
///   parser (slice 2) and acted on in UPDATE parsing (slice 3).
/// - 4-octet ASN (RFC 6793) carrying the real `local_as`
pub fn encode_open(local_as: u32, hold_time: u16, router_id: Ipv4Addr) -> Vec<u8> {
    // Capabilities (each: code u8, len u8, value [u8])
    let mut caps: Vec<u8> = Vec::with_capacity(32);
    // MP IPv4 unicast: AFI=1, Reserved=0, SAFI=1
    caps.extend_from_slice(&[1, 4, 0x00, 0x01, 0x00, 0x01]);
    // MP IPv6 unicast: AFI=2, Reserved=0, SAFI=1
    caps.extend_from_slice(&[1, 4, 0x00, 0x02, 0x00, 0x01]);
    // ADD-PATH (RFC 7911 §4): code=69, len=8 covers two
    // (AFI:2, SAFI:1, Send/Receive:1) tuples.
    //   tuple #1: AFI=1 (IPv4), SAFI=1 (unicast), 1 = Receive
    //   tuple #2: AFI=2 (IPv6), SAFI=1 (unicast), 1 = Receive
    // RFC 7911 §4 permits multiple tuples in a single capability TLV.
    caps.extend_from_slice(&[69, 8, 0x00, 0x01, 0x01, 0x01, 0x00, 0x02, 0x01, 0x01]);
    // 4-octet ASN
    caps.extend_from_slice(&[65, 4]);
    caps.extend_from_slice(&local_as.to_be_bytes());

    // Capabilities go inside an Optional Parameter of type 2.
    // We emit one such Opt Param whose value is the concatenation
    // of all capability TLVs.
    let opt_params_len = 2 + caps.len(); // [type=2, len=...] + caps
    let mut opt_params: Vec<u8> = Vec::with_capacity(opt_params_len);
    opt_params.push(2); // param type: Capability
                        // Audit Slice 5 hardening: today `caps` is fixed at ~30 bytes
                        // so the u8 fits comfortably, but a future capability that
                        // pushes the total over 255 would silently truncate and emit a
                        // malformed OPEN. Catch the regression at dev-build time.
    debug_assert!(
        caps.len() <= u8::MAX as usize,
        "BGP OPEN capability TLV exceeds 255 bytes; u8 length field truncates"
    );
    opt_params.push(caps.len() as u8);
    opt_params.extend_from_slice(&caps);

    let body_len = 1 /* version */ + 2 /* my_as */ + 2 /* hold */ + 4 /* bgp_id */ + 1 /* opt_param_len */ + opt_params.len();
    let total_len = BGP_HEADER_LEN + body_len;
    debug_assert!(total_len <= 4096, "OPEN > 4096 bytes (RFC 8654 cap)");

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&BGP_MARKER);
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.push(MSG_TYPE_OPEN);
    out.push(4); // version
    let my_as_2 = if local_as > u16::MAX as u32 {
        AS_TRANS
    } else {
        local_as as u16
    };
    out.extend_from_slice(&my_as_2.to_be_bytes());
    out.extend_from_slice(&hold_time.to_be_bytes());
    out.extend_from_slice(&router_id.octets());
    debug_assert!(
        opt_params.len() <= u8::MAX as usize,
        "BGP OPEN opt-params section exceeds 255 bytes; u8 length field truncates"
    );
    out.push(opt_params.len() as u8);
    out.extend_from_slice(&opt_params);
    out
}

/// Build a KEEPALIVE, header only, 19 bytes.
pub fn encode_keepalive() -> Vec<u8> {
    let mut out = Vec::with_capacity(BGP_HEADER_LEN);
    out.extend_from_slice(&BGP_MARKER);
    out.extend_from_slice(&(BGP_HEADER_LEN as u16).to_be_bytes());
    out.push(MSG_TYPE_KEEPALIVE);
    out
}

/// Capabilities mutually negotiated for the current session.
///
/// Populated by [`walk_open_capabilities`] from the peer's OPEN after
/// our OPEN has been sent. For each `add_path_*_recv` flag, `true`
/// means **the peer** advertised RFC 7911 capability 69 with `Send`
/// (value `2`) or `SendReceive` (value `3`) for that AFI/SAFI. The
/// directional flip (peer-Send => we-Receive) reflects that the peer
/// is the side that transmits path-id-prefixed NLRI; PacketFrame
/// never originates routes, so only the receive side matters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct NegotiatedCapabilities {
    /// Peer advertised ADD-PATH Send (or both) for (IPv4, unicast).
    add_path_v4_recv: bool,
    /// Peer advertised ADD-PATH Send (or both) for (IPv6, unicast).
    add_path_v6_recv: bool,
    /// Peer's 4-octet ASN (RFC 6793) if it advertised the capability.
    /// When `Some(_)`, this is the authoritative ASN, the 2-byte
    /// `My AS` field in OPEN carries AS_TRANS (23456) and the real
    /// ASN comes through here. Used by the peer-AS gate in
    /// `handle_connection` (the audit-flagged identity check).
    four_octet_asn: Option<u32>,
}

impl NegotiatedCapabilities {
    /// Whether ADD-PATH NLRI decoding is in effect for this session.
    ///
    /// All-or-nothing across IPv4 unicast + IPv6 unicast.
    /// `bgpkit_parser::parse_bgp_message` takes a single per-message
    /// `add_path: bool`, not a per-AFI flag; if the peer asymmetrically
    /// advertised ADD-PATH for one AFI but not the other, the session
    /// falls back to non-ADD-PATH decoding for both. Symmetric
    /// negotiation is the common case in practice.
    fn add_path_in_effect(&self) -> bool {
        self.add_path_v4_recv && self.add_path_v6_recv
    }
}

/// Walk the peer's OPEN optional parameters and surface mutually
/// negotiated capabilities relevant to PacketFrame.
///
/// Today the only surfaced capability is RFC 7911 ADD-PATH. Extend
/// here as new capabilities become relevant; the struct is the single
/// place call sites consult to decide per-session behavior.
fn walk_open_capabilities(
    opt_params: &[bgpkit_parser::models::OptParam],
) -> NegotiatedCapabilities {
    use bgpkit_parser::models::capabilities::AddPathSendReceive;
    use bgpkit_parser::models::{Afi, CapabilityValue, ParamValue, Safi};
    let mut caps = NegotiatedCapabilities::default();
    for op in opt_params {
        let ParamValue::Capacities(cap_list) = &op.param_value else {
            continue;
        };
        for c in cap_list {
            match &c.value {
                CapabilityValue::AddPath(ap) => {
                    for af in &ap.address_families {
                        // Peer Send => we Receive. Receive-only on the
                        // peer side means the peer wants to receive
                        // multipath from us, which we never originate,
                        // so it is not useful for our decoding state.
                        let peer_sends = matches!(
                            af.send_receive,
                            AddPathSendReceive::Send | AddPathSendReceive::SendReceive
                        );
                        if !peer_sends {
                            continue;
                        }
                        match (af.afi, af.safi) {
                            (Afi::Ipv4, Safi::Unicast) => caps.add_path_v4_recv = true,
                            (Afi::Ipv6, Safi::Unicast) => caps.add_path_v6_recv = true,
                            _ => {}
                        }
                    }
                }
                CapabilityValue::FourOctetAs(foa) => {
                    // RFC 6793: when present, this carries the peer's
                    // real ASN. The 2-byte field in OPEN holds AS_TRANS
                    // (23456) and the audit-flagged peer-AS check in
                    // `handle_connection` compares this value against
                    // the operator-configured `peer_as`.
                    caps.four_octet_asn = Some(foa.asn);
                }
                _ => {}
            }
        }
    }
    caps
}

// --- Helpers ----------------------------------------------------------------

/// The one [`PeerId`] a listener configured with `listen` and `peer_as`
/// files its routes under — the session closes on any other peer AS, so
/// this is every id it can produce. The route ledger checks a BGP
/// record's ids against it: a seeded advertisement under any other id
/// would never be replaced by the live session's re-advertisement.
pub fn session_peer_id(listen: SocketAddr, peer_as: u32) -> PeerId {
    synthetic_peer_id(listen, peer_as)
}

fn synthetic_peer_id(listen: SocketAddr, peer_asn: u32) -> PeerId {
    // Stable across reconnects. We use (listen_ip, peer_asn) so two
    // separately-configured BGP listeners (e.g., listening on
    // different loopback IPs for two different bird instances) get
    // different peer IDs. Through `PeerId::route_source`, never a raw
    // hash: the peer chooses its ASN, so a raw hash could be steered
    // into the resolver's local-ARP namespace, which the reconnect GC
    // exempts.
    PeerId::route_source(&(listen.ip(), peer_asn))
}

/// Bind a `TcpListener` with `SO_REUSEADDR` enabled. v0.2.2 fix for the
/// silent-failure scenario observed in production: when packetframe is
/// killed and quickly restarted, the prior listener's socket can sit
/// in `TIME_WAIT` for ~60 s, and the default `tokio::net::TcpListener::bind`
/// fails the new bind during that window. The error currently propagates
/// out of `BgpListener::run` and the controller's `JoinHandle` swallows
/// it, leaving the rest of packetframe running with a dead BGP feed
/// and no operator-visible signal short of bird's "Connection refused"
/// state. `SO_REUSEADDR` lets the new bind succeed even with lingering
/// TIME_WAIT state.
///
/// Returns the listener on success. Bind failures are still real (port
/// conflict with another process, etc.) and propagate via the `io::Error`.
fn bind_with_reuseaddr(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    // Backlog of 8: only one BGP peer ever connects, but TCP semantics
    // mean we still need a non-zero backlog for the listen queue.
    socket.listen(8)
}

fn network_prefix_to_ip_prefix(np: &NetworkPrefix) -> Option<IpPrefix> {
    use ipnet::IpNet;
    match np.prefix {
        IpNet::V4(n) => Some(IpPrefix::V4 {
            addr: n.addr().octets(),
            prefix_len: n.prefix_len(),
        }),
        IpNet::V6(n) => Some(IpPrefix::V6 {
            addr: n.addr().octets(),
            prefix_len: n.prefix_len(),
        }),
    }
}

fn asn_to_u32(asn: Asn) -> u32 {
    asn.to_string().parse().unwrap_or(0)
}

/// Translate one parsed BGP element (announce or withdraw of a single
/// prefix) into a [`RouteEvent`] for the FibProgrammer. Returns `None`
/// when the element's prefix can't be represented in our [`IpPrefix`]
/// type, graceful skip; bgpkit-parser's [`Elementor`] occasionally
/// emits malformed prefixes from withdraw NLRIs and we don't want
/// those to crash the session.
///
/// **The `fallback_nh` parameter** is the v0.2.1 fix for silently
/// dropping bird's `protocol direct` exports. Direct-origin (and
/// static-origin) routes go out via iBGP without an explicit BGP
/// NEXT_HOP attribute when the bird-side BGP block has no
/// `next hop self` directive, there's no upstream eBGP next-hop
/// to preserve, and bird doesn't synthesize one. bgpkit-parser's
/// `Elementor::bgp_update_to_elems` returns `next_hop = None` for
/// those announces.
///
/// Pre-v0.2.1 we silently `continue`d on `None`, so connected /24s
/// bird was correctly exporting never landed in `FIB_V4` at all
/// the prefix wasn't present for XDP to LPM-match. Operator-visible
/// symptom: `matched_dst_only` inbound to customer /24s all bumped
/// `fib_miss` instead of `fib_no_neigh`, and the FIB
/// integrity check perpetually reported drift between bird's
/// exported-route count and packetframe's mirror count.
///
/// The chosen fallback is the BGP session's listen address (typically
/// `127.0.0.1` for the loopback iBGP setup). The neighbor resolver
/// can't get a useful MAC for loopback, so the route lands with
/// `state=Incomplete`, operationally the same XDP_PASS-to-kernel as
/// the silent-drop, but now the prefix exists in `FIB_V4`, the
/// nexthop counter (`fib_no_neigh`) reflects reality, and
/// integrity drift goes away. Phase B (`local-prefix` ARP-walk)
/// turns those /24s into per-/32 fast-paths.
/// The AS that originated an announced route ([`RouteEvent::Add`]'s
/// `origin_asn`): the last AS of a path that ends naming one, the
/// session's AS for a path with none (the local AS originated it, as for
/// bird's direct and static exports over iBGP), and `None` for a path
/// ending in a set of several. BMP's Loc-RIB elements carry the local AS
/// as their peer AS, so the same reading holds there.
pub(crate) fn origin_asn(elem: &bgpkit_parser::models::BgpElem) -> Option<u32> {
    match &elem.as_path {
        Some(p) if !p.is_empty() => p.get_origin_opt().map(|a| a.to_u32()),
        _ => Some(elem.peer_asn.to_u32()),
    }
}

fn elem_to_route_event(
    elem: &bgpkit_parser::models::BgpElem,
    peer_id: PeerId,
    fallback_nh: IpAddr,
) -> Option<RouteEvent> {
    let prefix = network_prefix_to_ip_prefix(&elem.prefix)?;
    // When ADD-PATH was negotiated for the session, bgpkit-parser
    // populates `prefix.path_id` with the wire-decoded 4-byte ID.
    // Otherwise it remains None, matching the existing single-path
    // semantics expected by non-ADD-PATH sources (BMP, netlink).
    let path_id = elem.prefix.path_id;
    // local_pref is mandatory on iBGP UPDATEs (RFC 4271 §5.1.5) and
    // bgpkit-parser surfaces it. Withdrawals have no attributes so
    // local_pref does not apply to RouteEvent::Del.
    let local_pref = elem.local_pref;
    Some(match elem.elem_type {
        ElemType::ANNOUNCE => {
            let nh = elem.next_hop.unwrap_or(fallback_nh);
            RouteEvent::Add {
                peer_id,
                prefix,
                nexthops: vec![nh],
                path_id,
                local_pref,
                origin_asn: origin_asn(elem),
            }
        }
        ElemType::WITHDRAW => RouteEvent::Del {
            peer_id,
            prefix,
            path_id,
        },
    })
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_encoder_roundtrip() {
        let bytes = encode_open(65551, 90, Ipv4Addr::new(198, 51, 100, 7));
        // Marker check.
        assert_eq!(&bytes[..16], &BGP_MARKER);
        // Length matches buffer.
        let len = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
        assert_eq!(len, bytes.len());
        // Type byte.
        assert_eq!(bytes[18], MSG_TYPE_OPEN);
        // Version.
        assert_eq!(bytes[19], 4);
        // My AS = AS_TRANS because 65551 > 65535.
        assert_eq!(u16::from_be_bytes([bytes[20], bytes[21]]), AS_TRANS);
        // Hold time.
        assert_eq!(u16::from_be_bytes([bytes[22], bytes[23]]), 90);
        // Router ID.
        assert_eq!(&bytes[24..28], &[198, 51, 100, 7]);
        // Parse it back via bgpkit-parser to confirm wire validity.
        let mut b = Bytes::copy_from_slice(&bytes);
        let parsed = parse_bgp_message(&mut b, false, &AsnLength::Bits32).expect("parse");
        match parsed {
            BgpMessage::Open(o) => {
                assert_eq!(o.version, 4);
                assert_eq!(o.hold_time, 90);
                assert_eq!(o.bgp_identifier, Ipv4Addr::new(198, 51, 100, 7));
            }
            other => panic!("expected Open, got {:?}", other.msg_type()),
        }
    }

    #[test]
    fn open_encoder_two_byte_asn() {
        let bytes = encode_open(64512, 90, Ipv4Addr::new(1, 2, 3, 4));
        // For ASN that fits in 16 bits, My AS field is the actual ASN.
        assert_eq!(u16::from_be_bytes([bytes[20], bytes[21]]), 64512);
    }

    #[test]
    fn keepalive_encoder_is_19_bytes() {
        let bytes = encode_keepalive();
        assert_eq!(bytes.len(), 19);
        assert_eq!(&bytes[..16], &BGP_MARKER);
        assert_eq!(u16::from_be_bytes([bytes[16], bytes[17]]) as usize, 19);
        assert_eq!(bytes[18], MSG_TYPE_KEEPALIVE);
        // bgpkit-parser parses it as KeepAlive.
        let mut b = Bytes::copy_from_slice(&bytes);
        let parsed = parse_bgp_message(&mut b, false, &AsnLength::Bits32).expect("parse");
        assert!(matches!(parsed, BgpMessage::KeepAlive));
    }

    #[test]
    fn open_advertises_4byte_asn_and_mp_bgp() {
        let bytes = encode_open(65551, 90, Ipv4Addr::new(1, 2, 3, 4));
        // Walk to opt params: header(19) + version(1) + my_as(2) + hold(2) + router_id(4) = 28
        let opt_param_len = bytes[28] as usize;
        assert!(opt_param_len > 0, "OPEN without opt params");
        let opt_params = &bytes[29..29 + opt_param_len];
        // Single Opt Param of type 2 (Capability) wrapping all caps.
        assert_eq!(opt_params[0], 2, "Opt Param type must be 2 (Capability)");
        let caps = &opt_params[2..];
        // Walk capabilities, count what we see.
        let mut i = 0;
        let mut saw_mp_v4 = false;
        let mut saw_mp_v6 = false;
        let mut saw_4byte_asn = None;
        let mut add_path_v4_recv = false;
        let mut add_path_v6_recv = false;
        while i + 2 <= caps.len() {
            let code = caps[i];
            let clen = caps[i + 1] as usize;
            let value = &caps[i + 2..i + 2 + clen];
            match code {
                1 => {
                    // MP-BGP: AFI(2) + Reserved(1) + SAFI(1)
                    let afi = u16::from_be_bytes([value[0], value[1]]);
                    let safi = value[3];
                    if afi == 1 && safi == 1 {
                        saw_mp_v4 = true;
                    }
                    if afi == 2 && safi == 1 {
                        saw_mp_v6 = true;
                    }
                }
                65 => {
                    saw_4byte_asn =
                        Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
                }
                69 => {
                    // ADD-PATH per RFC 7911 §4: one or more 4-byte
                    // tuples of (AFI:2, SAFI:1, Send/Receive:1). Values
                    // for Send/Receive: 1 = Receive, 2 = Send, 3 = both.
                    let mut j = 0;
                    while j + 4 <= clen {
                        let afi = u16::from_be_bytes([value[j], value[j + 1]]);
                        let safi = value[j + 2];
                        let sr = value[j + 3];
                        let has_recv = sr & 0x01 != 0;
                        if afi == 1 && safi == 1 && has_recv {
                            add_path_v4_recv = true;
                        }
                        if afi == 2 && safi == 1 && has_recv {
                            add_path_v6_recv = true;
                        }
                        j += 4;
                    }
                }
                _ => {}
            }
            i += 2 + clen;
        }
        assert!(saw_mp_v4, "missing MP-BGP IPv4 unicast capability");
        assert!(saw_mp_v6, "missing MP-BGP IPv6 unicast capability");
        assert_eq!(
            saw_4byte_asn,
            Some(65551),
            "missing or wrong 4-octet ASN capability"
        );
        assert!(
            add_path_v4_recv,
            "missing ADD-PATH capability (RFC 7911) with Receive for IPv4 unicast"
        );
        assert!(
            add_path_v6_recv,
            "missing ADD-PATH capability (RFC 7911) with Receive for IPv6 unicast"
        );
    }

    #[test]
    fn open_does_not_advertise_route_refresh() {
        // We never originate routes, so we don't want bird sending us
        // ROUTE-REFRESH. Verify capability code 2 (Route Refresh) is
        // absent from our OPEN.
        let bytes = encode_open(65551, 90, Ipv4Addr::new(1, 2, 3, 4));
        let opt_param_len = bytes[28] as usize;
        let opt_params = &bytes[29..29 + opt_param_len];
        let caps = &opt_params[2..];
        let mut i = 0;
        while i + 2 <= caps.len() {
            let code = caps[i];
            let clen = caps[i + 1] as usize;
            assert_ne!(code, 2, "OPEN must not advertise Route Refresh capability");
            i += 2 + clen;
        }
    }

    #[test]
    fn synthetic_peer_id_stable_for_same_inputs() {
        let a = synthetic_peer_id("127.0.0.1:1179".parse().unwrap(), 65551);
        let b = synthetic_peer_id("127.0.0.1:1179".parse().unwrap(), 65551);
        assert_eq!(a, b);
        let c = synthetic_peer_id("127.0.0.1:1179".parse().unwrap(), 64512);
        assert_ne!(a, c);
    }

    // --- ADD-PATH (RFC 7911) capability negotiation -----------------

    /// Build a single Capability-bearing OptParam holding one ADD-PATH
    /// capability with the provided address-family entries. Mirrors
    /// what bgpkit-parser produces from a peer OPEN.
    fn build_add_path_opt_param(
        entries: Vec<bgpkit_parser::models::capabilities::AddPathAddressFamily>,
    ) -> bgpkit_parser::models::OptParam {
        use bgpkit_parser::models::capabilities::{AddPathCapability, BgpCapabilityType};
        use bgpkit_parser::models::{Capability, CapabilityValue, OptParam, ParamValue};
        let cap = Capability {
            ty: BgpCapabilityType::ADD_PATH_CAPABILITY,
            value: CapabilityValue::AddPath(AddPathCapability::new(entries)),
        };
        OptParam {
            param_type: 2,
            // param_len is informational here; walk_open_capabilities
            // does not consult it (it walks the structured Vec).
            param_len: 0,
            param_value: ParamValue::Capacities(vec![cap]),
        }
    }

    #[test]
    fn walk_open_capabilities_detects_both_afis_when_peer_sends() {
        use bgpkit_parser::models::capabilities::{AddPathAddressFamily, AddPathSendReceive};
        use bgpkit_parser::models::{Afi, Safi};
        let op = build_add_path_opt_param(vec![
            AddPathAddressFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathSendReceive::Send,
            },
            AddPathAddressFamily {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                send_receive: AddPathSendReceive::SendReceive,
            },
        ]);
        let caps = walk_open_capabilities(&[op]);
        assert!(caps.add_path_v4_recv);
        assert!(caps.add_path_v6_recv);
        assert!(caps.add_path_in_effect());
    }

    #[test]
    fn walk_open_capabilities_all_or_nothing_when_only_one_afi_negotiated() {
        use bgpkit_parser::models::capabilities::{AddPathAddressFamily, AddPathSendReceive};
        use bgpkit_parser::models::{Afi, Safi};
        let op = build_add_path_opt_param(vec![AddPathAddressFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            send_receive: AddPathSendReceive::Send,
        }]);
        let caps = walk_open_capabilities(&[op]);
        assert!(caps.add_path_v4_recv);
        assert!(!caps.add_path_v6_recv);
        // bgpkit-parser 0.16's parse_bgp_message takes a single per-
        // message add_path bool; symmetric all-or-nothing avoids the
        // mixed-AFI decoder mismatch.
        assert!(!caps.add_path_in_effect());
    }

    #[test]
    fn walk_open_capabilities_peer_receive_only_does_not_negotiate_recv() {
        use bgpkit_parser::models::capabilities::{AddPathAddressFamily, AddPathSendReceive};
        use bgpkit_parser::models::{Afi, Safi};
        // Peer Receive-only means the peer can RECEIVE multipath from
        // us; PacketFrame never originates, so this does not enable us
        // to receive anything from the peer.
        let op = build_add_path_opt_param(vec![
            AddPathAddressFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                send_receive: AddPathSendReceive::Receive,
            },
            AddPathAddressFamily {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                send_receive: AddPathSendReceive::Receive,
            },
        ]);
        let caps = walk_open_capabilities(&[op]);
        assert!(!caps.add_path_v4_recv);
        assert!(!caps.add_path_v6_recv);
        assert!(!caps.add_path_in_effect());
    }

    #[test]
    fn walk_open_capabilities_ignores_non_unicast_safi() {
        use bgpkit_parser::models::capabilities::{AddPathAddressFamily, AddPathSendReceive};
        use bgpkit_parser::models::{Afi, Safi};
        let op = build_add_path_opt_param(vec![AddPathAddressFamily {
            afi: Afi::Ipv4,
            safi: Safi::Multicast,
            send_receive: AddPathSendReceive::SendReceive,
        }]);
        let caps = walk_open_capabilities(&[op]);
        assert!(!caps.add_path_v4_recv);
        assert!(!caps.add_path_v6_recv);
    }

    #[test]
    fn walk_open_capabilities_empty_opt_params_yields_default() {
        let caps = walk_open_capabilities(&[]);
        assert!(!caps.add_path_v4_recv);
        assert!(!caps.add_path_v6_recv);
        assert!(!caps.add_path_in_effect());
        assert_eq!(caps, NegotiatedCapabilities::default());
    }

    #[test]
    fn walk_open_capabilities_round_trips_our_own_open_as_recv_only() {
        // Our OPEN advertises ADD-PATH with Receive direction (we
        // never originate). If a hypothetical peer ever parsed our
        // OPEN and ran walk_open_capabilities on it, they would see
        // Receive-only on our side and conclude that WE will not Send
        // multipath, so add_path_in_effect must be false. This guards
        // against accidentally flipping the encoded direction to Send.
        let bytes = encode_open(65551, 90, Ipv4Addr::new(1, 2, 3, 4));
        let mut b = Bytes::copy_from_slice(&bytes);
        let parsed =
            parse_bgp_message(&mut b, false, &AsnLength::Bits32).expect("OPEN parses cleanly");
        let open = match parsed {
            BgpMessage::Open(o) => o,
            other => panic!("expected OPEN, got {:?}", other),
        };
        let caps = walk_open_capabilities(&open.opt_params);
        assert!(
            !caps.add_path_v4_recv,
            "our own OPEN encodes Receive; walker must not treat it as peer-Send"
        );
        assert!(!caps.add_path_v6_recv);
        assert!(!caps.add_path_in_effect());
    }

    // --- ADD-PATH (RFC 7911) NLRI decoding --------------------------

    #[test]
    fn parse_update_with_path_id_surfaces_to_elem_and_route_event() {
        use bgpkit_parser::models::Asn;
        use std::net::Ipv4Addr;

        // Synthetic IPv4-unicast UPDATE containing one ADD-PATH
        // announce for 192.0.2.0/24 with path_id=42, NEXT_HOP
        // 10.0.0.1, empty AS_PATH, ORIGIN IGP. NLRI is encoded per
        // RFC 7911 §3 with the 4-byte Path Identifier preceding the
        // length-prefixed prefix.
        #[rustfmt::skip]
        let bytes: [u8; 45] = [
            // BGP header
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x2D, // total length = 45
            0x02,       // type = UPDATE
            // Withdrawn Routes Length = 0
            0x00, 0x00,
            // Total Path Attribute Length = 14
            0x00, 0x0E,
            // ORIGIN (transitive): flags=0x40, type=1, len=1, IGP=0
            0x40, 0x01, 0x01, 0x00,
            // AS_PATH (transitive, empty): flags=0x40, type=2, len=0
            0x40, 0x02, 0x00,
            // NEXT_HOP (transitive): flags=0x40, type=3, len=4, 10.0.0.1
            0x40, 0x03, 0x04, 0x0A, 0x00, 0x00, 0x01,
            // NLRI: path_id=42, prefix_len=24, 192.0.2 (3 bytes)
            0x00, 0x00, 0x00, 0x2A,
            0x18,
            0xC0, 0x00, 0x02,
        ];

        let mut b = Bytes::copy_from_slice(&bytes);
        let parsed = parse_bgp_message(&mut b, true, &AsnLength::Bits32)
            .expect("ADD-PATH UPDATE parses cleanly");
        let update = match parsed {
            BgpMessage::Update(u) => u,
            other => panic!("expected UPDATE, got {:?}", other.msg_type()),
        };

        let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let peer_asn = Asn::new_32bit(65000);
        let elems = Elementor::bgp_update_to_elems(update, 0.0, &peer_ip, &peer_asn);
        assert_eq!(elems.len(), 1, "exactly one elem from the single NLRI");
        let elem = &elems[0];
        assert_eq!(
            elem.prefix.path_id,
            Some(42),
            "path_id round-trips through bgpkit-parser when add_path=true"
        );

        let fallback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ev = elem_to_route_event(elem, PeerId(0), fallback).expect("elem yields a RouteEvent");
        match ev {
            RouteEvent::Add { path_id, .. } => assert_eq!(path_id, Some(42)),
            other => panic!("expected Add, got {:?}", other),
        }
    }

    #[test]
    fn parse_update_without_addpath_leaves_path_id_none() {
        use bgpkit_parser::models::Asn;
        use std::net::Ipv4Addr;

        // Same UPDATE shape as the test above but with no path_id
        // prefix on the NLRI. Length adjusts down by 4 bytes.
        #[rustfmt::skip]
        let bytes: [u8; 41] = [
            // BGP header
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x29, // total length = 41
            0x02,       // type = UPDATE
            // Withdrawn Routes Length = 0
            0x00, 0x00,
            // Total Path Attribute Length = 14
            0x00, 0x0E,
            // ORIGIN (transitive)
            0x40, 0x01, 0x01, 0x00,
            // AS_PATH (transitive, empty)
            0x40, 0x02, 0x00,
            // NEXT_HOP (transitive): 10.0.0.1
            0x40, 0x03, 0x04, 0x0A, 0x00, 0x00, 0x01,
            // NLRI: prefix_len=24, 192.0.2 (3 bytes), no path_id
            0x18,
            0xC0, 0x00, 0x02,
        ];

        let mut b = Bytes::copy_from_slice(&bytes);
        let parsed = parse_bgp_message(&mut b, false, &AsnLength::Bits32)
            .expect("non-ADD-PATH UPDATE parses cleanly");
        let update = match parsed {
            BgpMessage::Update(u) => u,
            other => panic!("expected UPDATE, got {:?}", other.msg_type()),
        };

        let peer_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let peer_asn = Asn::new_32bit(65000);
        let elems = Elementor::bgp_update_to_elems(update, 0.0, &peer_ip, &peer_asn);
        assert_eq!(elems.len(), 1);
        assert!(
            elems[0].prefix.path_id.is_none(),
            "non-ADD-PATH NLRI must yield path_id=None"
        );

        let fallback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ev =
            elem_to_route_event(&elems[0], PeerId(0), fallback).expect("elem yields a RouteEvent");
        match ev {
            RouteEvent::Add { path_id, .. } => assert!(path_id.is_none()),
            other => panic!("expected Add, got {:?}", other),
        }
    }

    /// v0.2.1 regression guard. Pre-fix, `elem_to_route_event` (then
    /// inlined in the read loop) silently `continue`d on
    /// `next_hop = None`, which is exactly what bird's iBGP emits for
    /// `protocol direct` announces without `next hop self`. Result:
    /// connected /24s never reached `FIB_V4`, every inbound
    /// matched_dst_only packet bumped `fib_miss`, and the FIB
    /// integrity check chronically reported drift. The fix makes
    /// `elem_to_route_event` fall back to a caller-supplied address
    /// (the BGP session's listen IP) so the route lands in the FIB
    /// with an unresolvable nexthop. This test pins the new behavior.
    /// Build a minimal BgpElem for the elem_to_route_event tests below.
    /// Uses struct-update syntax (`..Default::default()`) explicitly to
    /// keep clippy happy on the `field_reassign_with_default` lint.
    #[cfg(test)]
    fn make_test_elem(
        elem_type: ElemType,
        prefix_str: &str,
        next_hop: Option<IpAddr>,
    ) -> bgpkit_parser::models::BgpElem {
        use bgpkit_parser::models::{BgpElem, NetworkPrefix};
        use ipnet::IpNet;
        use std::str::FromStr;
        BgpElem {
            elem_type,
            prefix: NetworkPrefix {
                prefix: IpNet::from_str(prefix_str).unwrap(),
                path_id: None,
            },
            next_hop,
            ..BgpElem::default()
        }
    }

    #[test]
    fn the_origin_is_the_paths_last_as_or_the_sessions() {
        use bgpkit_parser::models::{AsPath, AsPathSegment, Asn, ElemType};
        let mut elem = make_test_elem(ElemType::ANNOUNCE, "198.51.100.0/24", None);
        elem.peer_asn = Asn::from(64500u32);
        assert_eq!(origin_asn(&elem), Some(64500), "no path: our own route");
        elem.as_path = Some(AsPath::from_segments(vec![AsPathSegment::sequence([
            64501u32, 64502, 64503,
        ])]));
        assert_eq!(origin_asn(&elem), Some(64503));
        elem.as_path = Some(AsPath::from_segments(vec![
            AsPathSegment::sequence([64501u32]),
            AsPathSegment::set([64504u32, 64505]),
        ]));
        assert_eq!(
            origin_asn(&elem),
            None,
            "an aggregate's set names no one origin"
        );
        let event = elem_to_route_event(&elem, PeerId(1), "127.0.0.1".parse().unwrap()).unwrap();
        assert!(matches!(
            event,
            RouteEvent::Add {
                origin_asn: None,
                ..
            }
        ));
    }

    #[test]
    fn elem_to_route_event_uses_fallback_when_next_hop_missing() {
        use bgpkit_parser::models::ElemType;
        use std::net::Ipv4Addr;
        let elem = make_test_elem(ElemType::ANNOUNCE, "192.0.2.0/24", None);
        let peer_id = PeerId(0xdeadbeef);
        let fallback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let event = elem_to_route_event(&elem, peer_id, fallback)
            .expect("elem with valid prefix must yield an event");
        match event {
            RouteEvent::Add {
                peer_id: pid,
                prefix,
                nexthops,
                path_id: _,
                local_pref: _,
                origin_asn: _,
            } => {
                assert_eq!(pid, peer_id);
                assert!(matches!(
                    prefix,
                    IpPrefix::V4 {
                        addr: [192, 0, 2, 0],
                        prefix_len: 24
                    }
                ));
                assert_eq!(nexthops, vec![fallback]);
            }
            other => panic!("expected Add, got {:?}", other),
        }
    }

    /// Sibling test: when bgpkit-parser does decode a `next_hop`
    /// (the normal case for eBGP-origin routes), we use *that*, not
    /// the fallback. Guards against regressing the fallback into a
    /// "always overwrite" footgun.
    #[test]
    fn elem_to_route_event_prefers_decoded_next_hop_over_fallback() {
        use bgpkit_parser::models::ElemType;
        use std::net::Ipv4Addr;
        let real_nh = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 50)); // transit-style nh
        let elem = make_test_elem(ElemType::ANNOUNCE, "1.1.1.0/24", Some(real_nh));
        let event = elem_to_route_event(&elem, PeerId(0), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .expect("elem with valid prefix must yield an event");
        match event {
            RouteEvent::Add { nexthops, .. } => {
                assert_eq!(nexthops, vec![real_nh]);
            }
            other => panic!("expected Add, got {:?}", other),
        }
    }

    /// Withdraws never look at next_hop; verify the fallback path
    /// doesn't accidentally synthesize one for a Del.
    #[test]
    fn elem_to_route_event_withdraw_unaffected_by_fallback() {
        use bgpkit_parser::models::ElemType;
        use std::net::Ipv4Addr;
        let elem = make_test_elem(ElemType::WITHDRAW, "192.0.2.0/24", None);
        let event = elem_to_route_event(&elem, PeerId(0), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .expect("withdraw with valid prefix must yield an event");
        assert!(matches!(event, RouteEvent::Del { .. }));
    }

    // --- Session liveness: the KEEPALIVE writer and the hold timer ----
    //
    // `handle_connection` against a peer on a real loopback socket, in
    // wall-clock time at the smallest hold it accepts (3 s, so a
    // KEEPALIVE every second). What the peer sees on the wire is the
    // assertion surface: a gap of a hold time between our KEEPALIVEs is
    // what made FRR tear the feed down, and a close is what our
    // hold-timer expiry looks like from the far end.

    use crate::fib::programmer::{gated_recording_handle, recording_handle, RouteEventLog};
    use std::time::Instant;
    use tokio::net::tcp::OwnedReadHalf;
    use tokio::task::JoinHandle;

    const TEST_HOLD: Duration = Duration::from_secs(3);
    const TEST_AS: u32 = 64496;

    /// A one-prefix IPv4 UPDATE: 198.51.100.0/24 via 192.0.2.1.
    fn test_update() -> Vec<u8> {
        #[rustfmt::skip]
        let bytes = vec![
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x29, // total length = 41
            0x02,       // type = UPDATE
            0x00, 0x00, // withdrawn routes length
            0x00, 0x0E, // total path attribute length
            0x40, 0x01, 0x01, 0x00,             // ORIGIN IGP
            0x40, 0x02, 0x00,                   // AS_PATH, empty
            0x40, 0x03, 0x04, 192, 0, 2, 1,     // NEXT_HOP
            0x18, 198, 51, 100,                 // NLRI 198.51.100.0/24
        ];
        bytes
    }

    /// One message off the peer's end of the socket: its type byte.
    async fn read_type<R: AsyncReadExt + Unpin>(rd: &mut R) -> std::io::Result<u8> {
        let mut header = [0u8; BGP_HEADER_LEN];
        rd.read_exact(&mut header).await?;
        let len = u16::from_be_bytes([header[16], header[17]]) as usize;
        let mut body = vec![0u8; len.saturating_sub(BGP_HEADER_LEN)];
        rd.read_exact(&mut body).await?;
        Ok(header[18])
    }

    type Established = (
        TcpStream,
        JoinHandle<Result<(), RouteSourceError>>,
        CancellationToken,
    );

    /// Run `handle_connection` on a loopback connection and complete the
    /// OPEN exchange as the peer. Returns the peer's end and the session.
    async fn establish(prog: FibProgrammerHandle) -> Established {
        establish_with(prog, ReadHold::default()).await
    }

    /// [`establish`], with the reader's [`ReadHold`] in the test's hands.
    async fn establish_with(prog: FibProgrammerHandle, read_hold: ReadHold) -> Established {
        let lst = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = lst.local_addr().expect("local addr");
        let mut cfg = BgpListenerConfig::new(addr, TEST_AS, TEST_AS, Ipv4Addr::new(192, 0, 2, 1));
        cfg.hold_time = TEST_HOLD.as_secs() as u16;
        let shutdown = CancellationToken::new();
        let mut listener = BgpListener::new(cfg, prog, shutdown.clone());
        listener.read_hold = read_hold;
        let listener = Arc::new(listener);
        let mut peer = TcpStream::connect(addr).await.expect("connect");
        let (stream, _) = lst.accept().await.expect("accept");
        let session = tokio::spawn(async move { listener.handle_connection(stream).await });

        assert_eq!(read_type(&mut peer).await.expect("OPEN"), MSG_TYPE_OPEN);
        let open = encode_open(
            TEST_AS,
            TEST_HOLD.as_secs() as u16,
            Ipv4Addr::new(192, 0, 2, 2),
        );
        peer.write_all(&open).await.expect("send OPEN");
        assert_eq!(
            read_type(&mut peer).await.expect("KEEPALIVE"),
            MSG_TYPE_KEEPALIVE,
            "the OPEN-confirming KEEPALIVE comes first"
        );
        (peer, session, shutdown)
    }

    /// What the peer has received from us since [`watch`] started.
    #[derive(Default)]
    struct Seen {
        keepalives: Vec<Instant>,
        /// Anything else we sent. Once established we only ever send
        /// KEEPALIVEs.
        unexpected: Vec<u8>,
        /// When the connection closed (EOF or reset), if it has.
        closed: Option<Instant>,
    }

    fn watch(mut rd: OwnedReadHalf) -> Arc<std::sync::Mutex<Seen>> {
        let seen = Arc::new(std::sync::Mutex::new(Seen::default()));
        let into = seen.clone();
        tokio::spawn(async move {
            loop {
                let read = read_type(&mut rd).await;
                let mut s = into.lock().expect("seen");
                match read {
                    Ok(MSG_TYPE_KEEPALIVE) => s.keepalives.push(Instant::now()),
                    Ok(other) => s.unexpected.push(other),
                    Err(_) => {
                        s.closed = Some(Instant::now());
                        return;
                    }
                }
            }
        });
        seen
    }

    /// The longest stretch within `[from, to]` the peer went without a
    /// KEEPALIVE: what its hold timer is judged on.
    fn longest_gap(keepalives: &[Instant], from: Instant, to: Instant) -> Duration {
        let mut last = from;
        let mut worst = Duration::ZERO;
        for &k in keepalives.iter().filter(|&&k| k > from && k <= to) {
            worst = worst.max(k - last);
            last = k;
        }
        worst.max(to - last)
    }

    /// Where InitiationComplete sits in the log, once it has been applied.
    fn initiation_complete_at(log: &RouteEventLog) -> Option<usize> {
        log.events()
            .iter()
            .position(|e| matches!(e, RouteEvent::InitiationComplete))
    }

    async fn wait_until(what: &str, within: Duration, cond: impl Fn() -> bool) {
        let deadline = Instant::now() + within;
        while !cond() {
            assert!(Instant::now() < deadline, "timed out waiting until {what}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Play a peer that is up but sends no UPDATEs, a KEEPALIVE every
    /// 500 ms to keep our hold timer fed, until `cond` holds or `within`
    /// runs out. Returns when `cond` was first seen to hold.
    async fn quiet_peer_until(
        wr: &mut tokio::net::tcp::OwnedWriteHalf,
        within: Duration,
        cond: impl Fn() -> bool,
    ) -> Option<Instant> {
        let deadline = Instant::now() + within;
        let mut next_keepalive = Instant::now();
        loop {
            if cond() {
                return Some(Instant::now());
            }
            if Instant::now() >= deadline {
                return None;
            }
            if Instant::now() >= next_keepalive {
                wr.write_all(&encode_keepalive()).await.expect("KEEPALIVE");
                next_keepalive += Duration::from_millis(500);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// The 2026-10-07 starvation at test scale: the programmer stalls on
    /// the first UPDATE while the peer goes on streaming, for twice the
    /// hold time. KEEPALIVEs must keep reaching the peer, or its hold
    /// timer tears down a session whose only fault is that we are slow.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn keepalives_keep_flowing_while_route_processing_stalls() {
        let (prog, log, gate) = gated_recording_handle();
        let (peer, session, shutdown) = establish(prog).await;
        let (rd, mut wr) = peer.into_split();
        let seen = watch(rd);

        wr.write_all(&test_update()).await.expect("UPDATE");
        let mut sent = 1;
        wait_until(
            "the first UPDATE is held in the programmer",
            Duration::from_secs(5),
            || gate.arrived() == 1,
        )
        .await;

        // A live peer: an UPDATE every 100 ms and a KEEPALIVE every
        // second. Far fewer frames than the channel holds, so the reader
        // keeps reading and the peer's KEEPALIVEs keep our hold timer
        // satisfied; only our processing is stuck.
        let from = Instant::now();
        while from.elapsed() < 2 * TEST_HOLD {
            for _ in 0..10 {
                wr.write_all(&test_update()).await.expect("UPDATE");
                sent += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            wr.write_all(&encode_keepalive()).await.expect("KEEPALIVE");
        }
        let to = Instant::now();

        assert_eq!(
            gate.arrived(),
            1,
            "premise: the programmer held the first UPDATE for the whole window"
        );
        assert!(log.is_empty(), "premise: nothing was applied in the window");
        {
            let seen = seen.lock().expect("seen");
            assert_eq!(seen.closed, None, "the session closed on a live peer");
            assert!(seen.unexpected.is_empty(), "sent {:?}", seen.unexpected);
            let gap = longest_gap(&seen.keepalives, from, to);
            assert!(
                gap < TEST_HOLD,
                "the peer went {gap:?} without a KEEPALIVE while route processing was \
                 stalled; at a {TEST_HOLD:?} hold its timer tears the session down"
            );
        }
        assert!(!session.is_finished(), "the session ended on a live peer");

        // The stall clears: what queued behind it applies on the same
        // session.
        gate.open();
        wait_until("every UPDATE is applied", Duration::from_secs(5), || {
            log.len() == sent
        })
        .await;
        assert!(!session.is_finished(), "the session ended after the stall");
        shutdown.cancel();
        session
            .await
            .expect("join")
            .expect("shutdown ends a session cleanly");
    }

    /// Backpressure is not peer silence. With the programmer stalled,
    /// the frame channel fills and the reader stops reading while the
    /// peer's messages wait in our socket buffer; the peer then sends
    /// nothing for twice the hold time, as it would with our receive
    /// window closed. Our hold timer must not fire over that. Once the
    /// stall clears and we catch up, a peer that really has gone quiet
    /// expires a hold time later, and our KEEPALIVEs end with the session.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_frame_channel_is_not_peer_silence() {
        // One frame in the held apply, FRAME_CHANNEL_CAPACITY queued and
        // one in the reader's blocked send, with as many again left in
        // the socket buffer: about 21 KB, well inside loopback's buffers.
        const FLOOD: usize = 2 * FRAME_CHANNEL_CAPACITY;
        let (prog, log, gate) = gated_recording_handle();
        let (peer, session, _shutdown) = establish(prog).await;
        let (rd, mut wr) = peer.into_split();
        let seen = watch(rd);

        let flood: Vec<u8> = (0..FLOOD).flat_map(|_| test_update()).collect();
        tokio::time::timeout(Duration::from_secs(5), wr.write_all(&flood))
            .await
            .expect("premise: the flood fits in the socket buffers")
            .expect("flood");
        wait_until(
            "the first UPDATE is held in the programmer",
            Duration::from_secs(5),
            || gate.arrived() == 1,
        )
        .await;

        let from = Instant::now();
        tokio::time::sleep(2 * TEST_HOLD).await;
        let to = Instant::now();

        assert_eq!(gate.arrived(), 1, "premise: the programmer stayed stalled");
        assert!(log.is_empty(), "premise: nothing was applied in the window");
        {
            let seen = seen.lock().expect("seen");
            assert_eq!(
                seen.closed, None,
                "the session closed while the reader was blocked on a full channel: \
                 that is our backlog, not the peer's silence"
            );
            let gap = longest_gap(&seen.keepalives, from, to);
            assert!(gap < TEST_HOLD, "the peer went {gap:?} without a KEEPALIVE");
        }
        assert!(!session.is_finished(), "the session ended on a live peer");

        // The stall clears. We work through the backlog, catch up with
        // the socket, and then wait on it with nothing coming.
        let opened = Instant::now();
        gate.open();
        let ended = tokio::time::timeout(TEST_HOLD + Duration::from_secs(5), session)
            .await
            .expect("a silent peer must still trip the hold timer once we catch up")
            .expect("join");
        let ended_after = opened.elapsed();
        let err = ended.expect_err("a hold-timer expiry is an error");
        assert!(err.cause.contains("hold timer (3 s) expired"), "{err}");
        // Where a hold timer that ran during the backlog shows: the stuck
        // main loop hides its expiry until the stall clears, and then the
        // session ends with the rest of the backlog unread.
        assert_eq!(
            log.len(),
            FLOOD,
            "every UPDATE the peer sent applies before the session ends"
        );
        assert!(
            ended_after >= TEST_HOLD,
            "the hold timer must run from when we caught up, not before: ended {ended_after:?} \
             after the stall cleared"
        );
        wait_until(
            "the peer sees the connection close",
            Duration::from_secs(2),
            || seen.lock().expect("seen").closed.is_some(),
        )
        .await;
    }

    /// A peer that really has gone quiet still trips the hold timer, a
    /// hold time after its last message, while we go on sending ours.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_silent_peer_trips_the_hold_timer() {
        let (prog, log) = recording_handle();
        let (peer, session, _shutdown) = establish(prog).await;
        let (rd, mut wr) = peer.into_split();
        let seen = watch(rd);

        // Taken before the write, so the reader cannot have read it (and
        // armed the timer for the next message) before this instant.
        let last_sent = Instant::now();
        wr.write_all(&test_update()).await.expect("UPDATE");
        let ended = tokio::time::timeout(TEST_HOLD + Duration::from_secs(5), session)
            .await
            .expect("the hold timer must fire on a silent peer")
            .expect("join");
        let silent_for = last_sent.elapsed();
        let err = ended.expect_err("a hold-timer expiry is an error");
        assert!(err.cause.contains("hold timer (3 s) expired"), "{err}");
        assert_eq!(log.len(), 1, "the UPDATE applied");
        assert!(
            silent_for >= TEST_HOLD && silent_for < TEST_HOLD + Duration::from_secs(2),
            "expired after {silent_for:?} of silence, hold {TEST_HOLD:?}"
        );
        wait_until(
            "the peer sees the connection close",
            Duration::from_secs(2),
            || seen.lock().expect("seen").closed.is_some(),
        )
        .await;
        let seen = seen.lock().expect("seen");
        assert!(
            !seen.keepalives.is_empty(),
            "we kept sending KEEPALIVEs while the peer was silent"
        );
        assert!(seen.unexpected.is_empty(), "sent {:?}", seen.unexpected);
    }

    // --- InitiationComplete quiescence -------------------------------

    /// A stall longer than the quiescence window, mid-stream, with the
    /// peer streaming through it and then going quiet while it lasts.
    /// InitiationComplete GCs whatever the session has not re-sent, so
    /// it must come after the last UPDATE is applied, and must time the
    /// quiet from that UPDATE's receipt: once the backlog clears, it
    /// fires sooner than a window timed from processing could.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initiation_complete_waits_for_a_stalled_backlog_and_times_quiet_from_receipt() {
        let (prog, log, gate) = gated_recording_handle();
        let (peer, session, shutdown) = establish(prog).await;
        let (rd, mut wr) = peer.into_split();
        let seen = watch(rd);

        wr.write_all(&test_update()).await.expect("UPDATE");
        let mut sent = 1;
        wait_until(
            "the first UPDATE is held in the programmer",
            Duration::from_secs(5),
            || gate.arrived() == 1,
        )
        .await;

        // Stream through the stall for longer than the window, an UPDATE
        // every 100 ms and a KEEPALIVE every 500 ms...
        let from = Instant::now();
        let mut last_sent = from;
        while from.elapsed() < INIT_COMPLETE_QUIESCENCE + Duration::from_secs(1) {
            for _ in 0..5 {
                // Before the write, so its receipt cannot precede it.
                last_sent = Instant::now();
                wr.write_all(&test_update()).await.expect("UPDATE");
                sent += 1;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            wr.write_all(&encode_keepalive()).await.expect("KEEPALIVE");
        }
        // ...then go quiet for most of another window, still stalled.
        let quiet = INIT_COMPLETE_QUIESCENCE - Duration::from_secs(1);
        assert_eq!(quiet_peer_until(&mut wr, quiet, || false).await, None);
        assert_eq!(
            gate.arrived(),
            1,
            "premise: the programmer held the first UPDATE throughout"
        );
        assert!(
            log.is_empty(),
            "premise: nothing was applied during the stall"
        );

        let opened = Instant::now();
        gate.open();
        let fired_at = quiet_peer_until(&mut wr, 2 * INIT_COMPLETE_QUIESCENCE, || {
            initiation_complete_at(&log).is_some()
        })
        .await
        .expect("InitiationComplete fires once the peer is quiet and the backlog applied");

        assert_eq!(
            initiation_complete_at(&log),
            Some(sent),
            "InitiationComplete must follow all {sent} UPDATEs the peer sent, not run ahead of \
             the backlog the stall was holding"
        );
        assert!(
            fired_at - last_sent >= INIT_COMPLETE_QUIESCENCE,
            "fired {:?} after the last UPDATE was sent",
            fired_at - last_sent
        );
        assert!(
            fired_at - opened < INIT_COMPLETE_QUIESCENCE,
            "fired {:?} after the stall cleared: the window must run from the last UPDATE's \
             receipt, {:?} before the stall cleared, not from when it was applied",
            fired_at - opened,
            opened - last_sent
        );
        assert_eq!(seen.lock().expect("seen").closed, None);
        assert!(!session.is_finished(), "the session ended on a live peer");
        shutdown.cancel();
        session
            .await
            .expect("join")
            .expect("shutdown ends a session cleanly");
    }

    /// The ordinary case still holds: a peer that streams and then goes
    /// quiet gets InitiationComplete a window after its last UPDATE,
    /// behind every UPDATE it sent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initiation_complete_fires_once_the_peer_goes_quiet() {
        let (prog, log) = recording_handle();
        let (peer, session, shutdown) = establish(prog).await;
        let (rd, mut wr) = peer.into_split();
        let seen = watch(rd);

        let mut last_sent = Instant::now();
        for _ in 0..3 {
            last_sent = Instant::now();
            wr.write_all(&test_update()).await.expect("UPDATE");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let fired_at = quiet_peer_until(&mut wr, 2 * INIT_COMPLETE_QUIESCENCE, || {
            initiation_complete_at(&log).is_some()
        })
        .await
        .expect("InitiationComplete fires once the peer goes quiet");

        assert_eq!(initiation_complete_at(&log), Some(3), "after all 3 UPDATEs");
        let quiet = fired_at - last_sent;
        assert!(
            quiet >= INIT_COMPLETE_QUIESCENCE
                && quiet < INIT_COMPLETE_QUIESCENCE + Duration::from_secs(3),
            "fired after {quiet:?} of quiet, window {INIT_COMPLETE_QUIESCENCE:?}"
        );
        assert_eq!(seen.lock().expect("seen").closed, None);
        shutdown.cancel();
        session
            .await
            .expect("join")
            .expect("shutdown ends a session cleanly");
    }

    /// The race only the reader can close. A stall longer than the
    /// window leaves the reader blocked on a full channel with UPDATEs
    /// still unread in the socket. When the stall clears, the reader is
    /// held after its handoff, as one the scheduler has not run yet
    /// would sit, while the main loop applies everything handed over.
    /// Nothing may call the session quiet then: InitiationComplete must
    /// wait for the unread UPDATEs, and for a window after the last of
    /// them is read.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn initiation_complete_waits_for_updates_still_unread_in_the_socket() {
        // The stalled apply, a full channel and one in the reader's
        // hands, with as many again left in the socket buffer.
        const FLOOD: usize = 2 * FRAME_CHANNEL_CAPACITY;
        let (prog, log, gate) = gated_recording_handle();
        let (hold_open, hold_rx) = tokio::sync::watch::channel(true);
        let (peer, session, shutdown) = establish_with(
            prog,
            ReadHold {
                open: Some(hold_rx),
            },
        )
        .await;
        let (rd, mut wr) = peer.into_split();
        let seen = watch(rd);

        let flood: Vec<u8> = (0..FLOOD).flat_map(|_| test_update()).collect();
        tokio::time::timeout(Duration::from_secs(5), wr.write_all(&flood))
            .await
            .expect("premise: the flood fits in the socket buffers")
            .expect("flood");
        wait_until(
            "the first UPDATE is held in the programmer",
            Duration::from_secs(5),
            || gate.arrived() == 1,
        )
        .await;
        // The reader stops at its next read: once the stall clears and it
        // completes the handoff it is blocked in, or sooner.
        hold_open.send_replace(false);

        // A stall longer than the window; the peer stays up, sending no
        // UPDATEs.
        let stall = INIT_COMPLETE_QUIESCENCE + Duration::from_secs(1);
        assert_eq!(quiet_peer_until(&mut wr, stall, || false).await, None);
        assert_eq!(gate.arrived(), 1, "premise: the programmer stayed stalled");
        assert!(
            log.is_empty(),
            "premise: nothing was applied during the stall"
        );

        // The stall clears. The main loop applies all it was handed while
        // the reader stays held, for longer than the old once-a-second
        // check needed to misfire.
        gate.open();
        let held = Duration::from_millis(2500);
        assert_eq!(quiet_peer_until(&mut wr, held, || false).await, None);
        if let Some(after) = initiation_complete_at(&log) {
            panic!(
                "InitiationComplete fired after {after} UPDATEs, with {} still unread in the socket",
                FLOOD - after
            );
        }
        let applied = log.len();
        assert!(
            applied > 0 && applied < FLOOD,
            "premise: what was handed over is applied ({applied}) and UPDATEs remain unread"
        );

        let released = Instant::now();
        hold_open.send_replace(true);
        let fired_at = quiet_peer_until(&mut wr, 2 * INIT_COMPLETE_QUIESCENCE, || {
            initiation_complete_at(&log).is_some()
        })
        .await
        .expect("InitiationComplete fires once the reader has read everything and gone quiet");
        assert_eq!(
            initiation_complete_at(&log),
            Some(FLOOD),
            "after every UPDATE the peer sent"
        );
        let after = fired_at - released;
        assert!(
            after >= INIT_COMPLETE_QUIESCENCE
                && after < INIT_COMPLETE_QUIESCENCE + Duration::from_secs(3),
            "fired {after:?} after the reader was released: the window runs from the last \
             UPDATE it read, which came after the release"
        );
        assert_eq!(seen.lock().expect("seen").closed, None);
        assert!(!session.is_finished(), "the session ended on a live peer");
        shutdown.cancel();
        session
            .await
            .expect("join")
            .expect("shutdown ends a session cleanly");
    }
}
