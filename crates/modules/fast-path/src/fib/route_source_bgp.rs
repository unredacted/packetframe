//! BGP route source — receives bird's selected best paths over an
//! iBGP session and translates UPDATEs into [`RouteEvent`]s for the
//! FibProgrammer.
//!
//! **Why BGP and not BMP for the forwarding feed.** Bird's BMP
//! implementation (as of bird master, April 2026) does not implement
//! RFC 9069 Loc-RIB — only `monitoring rib in pre_policy` /
//! `post_policy`, which deliver per-peer Adj-RIB-In streams. For a
//! prefix announced by N peers, that's N RouteMonitoring frames with
//! N different nexthops, leaving the FibProgrammer to either
//! re-implement bird's best-path selection (drift risk forever) or
//! pick wrong. iBGP, by contrast, has bird's `protocol bgp` export
//! filter run after best-path selection — we receive exactly one
//! UPDATE per prefix, with the path bird picked. See
//! `docs/runbooks/custom-fib.md` "Phase 4 bird config" for the
//! `protocol bgp packetframe { ... }` snippet.
//!
//! **Direction.** This is a *passive* BGP speaker: packetframe
//! listens, bird connects out (configurable via bird's
//! `neighbor 127.0.0.1 port <port> as <asn>`). Same direction as the
//! BMP station so both feeds work the same operationally.
//!
//! **Capabilities advertised in OPEN.**
//! - Multi-Protocol Extensions (RFC 4760) for IPv4 unicast and
//!   IPv6 unicast — without this bird only sends v4 routes over
//!   the session.
//! - Four-octet ASN (RFC 6793) — required for any modern AS
//!   numbering, ours is 401401 which is > 65535.
//! - Route Refresh is **not** advertised. We never originate routes,
//!   so bird has nothing to ask us to refresh.
//!
//! **Hold time.** Proposed at [`DEFAULT_HOLD_TIME`] (90 s); the
//! effective hold is `min(ours, peer's)` after the OPEN exchange.
//! KEEPALIVEs are sent at `effective_hold / 3`.
//!
//! **What we never send.** No UPDATE, no NOTIFICATION (we close on
//! protocol error rather than send a structured NOTIFICATION — bird
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bgpkit_parser::models::{Asn, AsnLength, BgpMessage, ElemType, NetworkPrefix};
use bgpkit_parser::parser::bgp::messages::parse_bgp_message;
use bgpkit_parser::Elementor;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use packetframe_common::fib::{IpPrefix, PeerId, RouteEvent, RouteSourceError};

use crate::fib::programmer::FibProgrammerHandle;
use crate::fib::route_source_bmp::SharedIntegritySnapshot;

// --- Wire constants ---------------------------------------------------------

/// BGP message marker — 16 bytes of 0xFF per RFC 4271 §4.1.
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
/// ours. Real peers respond within milliseconds; 2 minutes is the
/// RFC 4271 ConnectRetry default and a safe upper bound.
const OPEN_TIMEOUT: Duration = Duration::from_secs(120);

// --- BgpListener ------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BgpListenerConfig {
    pub listen_addr: SocketAddr,
    pub local_as: u32,
    pub peer_as: u32,
    pub router_id: Ipv4Addr,
    pub hold_time: u16,
}

impl BgpListenerConfig {
    pub fn new(listen_addr: SocketAddr, local_as: u32, peer_as: u32, router_id: Ipv4Addr) -> Self {
        Self {
            listen_addr,
            local_as,
            peer_as,
            router_id,
            hold_time: DEFAULT_HOLD_TIME,
        }
    }
}

pub struct BgpListener {
    cfg: BgpListenerConfig,
    prog_handle: FibProgrammerHandle,
    shutdown: CancellationToken,
    /// Shared atomic updated on each UPDATE frame. Unix seconds; 0 =
    /// none seen since process start. Read by the same stall monitor
    /// that BmpStation uses — both feeds publish to the same signal.
    last_update_unix: Arc<AtomicI64>,
    stall_gate: Option<SharedIntegritySnapshot>,
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
        }
    }

    pub fn with_stall_gate(mut self, snapshot: SharedIntegritySnapshot) -> Self {
        self.stall_gate = Some(snapshot);
        self
    }

    /// Accept loop. One bird connection at a time; on disconnect emit
    /// `Resync` and re-accept.
    pub async fn run(self) -> Result<(), RouteSourceError> {
        let listener = TcpListener::bind(self.cfg.listen_addr)
            .await
            .map_err(|e| RouteSourceError::fatal(format!("bind {}: {e}", self.cfg.listen_addr)))?;
        info!(addr = %self.cfg.listen_addr, local_as = self.cfg.local_as, peer_as = self.cfg.peer_as, "BGP listener started");

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("BgpListener shutdown requested");
                    return Ok(());
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            info!(%addr, "BGP client connected");
                            if let Err(e) = self.handle_connection(stream).await {
                                warn!(error = %e, "BGP connection handler exited with error");
                            } else {
                                info!("BGP client disconnected cleanly");
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
        let peer_open = tokio::time::timeout(OPEN_TIMEOUT, read_one_message(&mut stream))
            .await
            .map_err(|_| RouteSourceError::recoverable("peer OPEN timeout".to_string()))?
            .map_err(|e| RouteSourceError::recoverable(format!("read peer OPEN: {e}")))?;
        let (effective_hold, peer_asn_observed) = match peer_open {
            BgpMessage::Open(o) => {
                if o.version != 4 {
                    return Err(RouteSourceError::recoverable(format!(
                        "peer BGP version {}; expected 4",
                        o.version
                    )));
                }
                let peer_asn = asn_to_u32(o.asn);
                // bgpkit may decode AS_TRANS (23456) as the 2-byte
                // ASN when the 4-byte ASN capability is present. The
                // real ASN comes via the capability. For an iBGP
                // session with bird, the peer's effective ASN should
                // match our `peer_as` config; if it doesn't, that's
                // a misconfiguration worth surfacing.
                if peer_asn != self.cfg.peer_as && peer_asn != AS_TRANS as u32 {
                    warn!(
                        observed = peer_asn,
                        expected = self.cfg.peer_as,
                        "peer ASN mismatch in OPEN (continuing — capability ASN may override)"
                    );
                }
                let effective_hold = self.cfg.hold_time.min(o.hold_time).max(3);
                info!(
                    peer_asn = peer_asn,
                    peer_router_id = %o.bgp_identifier,
                    effective_hold,
                    "received peer OPEN"
                );
                (effective_hold, peer_asn)
            }
            other => {
                return Err(RouteSourceError::recoverable(format!(
                    "expected OPEN, got {:?}",
                    other.msg_type()
                )));
            }
        };

        // Step 3: send KEEPALIVE to confirm OPEN.
        let keepalive = encode_keepalive();
        stream
            .write_all(&keepalive)
            .await
            .map_err(|e| RouteSourceError::recoverable(format!("send KEEPALIVE: {e}")))?;

        // Step 4: established — drain UPDATEs, send periodic
        // KEEPALIVEs, watch hold timer. Reader/writer split so the
        // main `select!` can interleave the keepalive timer without
        // cancel-safety issues on `read_exact`.
        let (read_half, mut write_half) = stream.into_split();
        let (frame_tx, mut frame_rx) = mpsc::channel::<BgpMessage>(FRAME_CHANNEL_CAPACITY);
        let reader = tokio::spawn(reader_task(read_half, frame_tx));

        let mut keepalive_tick =
            tokio::time::interval(Duration::from_secs(effective_hold.max(3) as u64 / 3));
        keepalive_tick.tick().await; // skip immediate fire
        let mut hold_deadline = Instant::now() + Duration::from_secs(effective_hold as u64);
        let mut last_update: Option<Instant> = None;
        let mut init_complete_fired = false;
        let mut quiescence_tick = tokio::time::interval(Duration::from_secs(1));
        quiescence_tick.tick().await; // skip immediate fire
        let mut updates_seen = 0usize;

        // Synthetic peer_id for an iBGP session: bird is the singular
        // peer here, so PeerId is constant. We hash (peer_ip, peer_asn)
        // for stability across reconnects.
        let peer_id = synthetic_peer_id(self.cfg.listen_addr, peer_asn_observed);

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    reader.abort();
                    return Ok(());
                }
                msg = frame_rx.recv() => {
                    match msg {
                        Some(m) => {
                            // Any inbound traffic resets hold.
                            hold_deadline = Instant::now() + Duration::from_secs(effective_hold as u64);
                            self.process_msg(m, peer_id, peer_asn_observed, &mut last_update, &mut updates_seen).await;
                        }
                        None => {
                            // Reader exited — surface the result.
                            return match reader.await {
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
                _ = keepalive_tick.tick() => {
                    if let Err(e) = write_half.write_all(&keepalive).await {
                        return Err(RouteSourceError::recoverable(format!(
                            "send periodic KEEPALIVE: {e}"
                        )));
                    }
                }
                _ = quiescence_tick.tick() => {
                    // Hold-timer expiry → tear down. RFC 4271: peer
                    // dead, send NOTIFICATION (we skip — close
                    // suffices; bird reconnects).
                    if Instant::now() >= hold_deadline {
                        return Err(RouteSourceError::recoverable(format!(
                            "hold timer ({effective_hold} s) expired"
                        )));
                    }
                    // InitiationComplete heuristic.
                    if !init_complete_fired {
                        if let Some(last) = last_update {
                            if last.elapsed() >= INIT_COMPLETE_QUIESCENCE {
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
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn process_msg(
        &self,
        msg: BgpMessage,
        peer_id: PeerId,
        peer_asn: u32,
        last_update: &mut Option<Instant>,
        updates_seen: &mut usize,
    ) {
        match msg {
            BgpMessage::Open(_) => {
                // Spurious post-handshake OPEN — bird shouldn't do
                // this. Log + ignore.
                warn!("unexpected OPEN after handshake");
            }
            BgpMessage::KeepAlive => {
                // Hold timer reset already happened; no further work.
            }
            BgpMessage::Notification(n) => {
                // BgpError is a typed enum (MessageHeaderError,
                // OpenError, UpdateError, HoldTimerExpired, Cease, ...);
                // log the Debug repr — operator can grep on it.
                warn!(error = ?n.error, "received NOTIFICATION; closing session");
                // Reader will see EOF after bird closes; that path
                // emits Resync via the accept loop.
            }
            BgpMessage::Update(update) => {
                *last_update = Some(Instant::now());
                *updates_seen += 1;
                let now_unix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                self.last_update_unix.store(now_unix, Ordering::Relaxed);

                // Pretend the peer-IP for Elementor is the listen
                // address (bird-side IP isn't carried in BGP UPDATE
                // — we know it from the connection, but Elementor
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
    }
}

// --- Reader task ------------------------------------------------------------

/// Drains the TCP stream, parses BGP messages, and forwards them to
/// the main `select!` loop via a bounded channel. Same cancel-safety
/// pattern as `BmpStation::reader_task`.
async fn reader_task<R>(mut stream: R, tx: mpsc::Sender<BgpMessage>) -> Result<(), RouteSourceError>
where
    R: AsyncReadExt + Unpin + Send,
{
    let mut messages_parsed = 0usize;
    loop {
        let msg = match read_one_message(&mut stream).await {
            Ok(m) => m,
            Err(e) if is_clean_eof(&e) => {
                debug!(messages_parsed, "BGP stream EOF (reader)");
                return Ok(());
            }
            Err(e) => {
                return Err(RouteSourceError::recoverable(format!(
                    "read message after {messages_parsed}: {e}"
                )));
            }
        };
        messages_parsed += 1;
        if tx.send(msg).await.is_err() {
            debug!(messages_parsed, "frame receiver closed; reader exiting");
            return Ok(());
        }
    }
}

/// Read one BGP message off the stream. Reads the 19-byte header,
/// pulls the declared length, reads the rest, and parses with
/// bgpkit-parser. Filters ROUTE-REFRESH (type 5) before parsing
/// because bgpkit-parser doesn't model it.
async fn read_one_message<R>(stream: &mut R) -> std::io::Result<BgpMessage>
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
    // doesn't model it; skip silently — bird shouldn't send refresh
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

    parse_bgp_message(&mut bytes, false, &AsnLength::Bits32)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))
}

fn is_clean_eof(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::UnexpectedEof
}

// --- Wire encoders ----------------------------------------------------------

/// Build the OPEN message. Capabilities advertised:
/// - MP-BGP IPv4 unicast (AFI=1, SAFI=1)
/// - MP-BGP IPv6 unicast (AFI=2, SAFI=1)
/// - 4-octet ASN (RFC 6793) carrying the real `local_as`
pub fn encode_open(local_as: u32, hold_time: u16, router_id: Ipv4Addr) -> Vec<u8> {
    // Capabilities (each: code u8, len u8, value [u8])
    let mut caps: Vec<u8> = Vec::with_capacity(32);
    // MP IPv4 unicast: AFI=1, Reserved=0, SAFI=1
    caps.extend_from_slice(&[1, 4, 0x00, 0x01, 0x00, 0x01]);
    // MP IPv6 unicast: AFI=2, Reserved=0, SAFI=1
    caps.extend_from_slice(&[1, 4, 0x00, 0x02, 0x00, 0x01]);
    // 4-octet ASN
    caps.extend_from_slice(&[65, 4]);
    caps.extend_from_slice(&local_as.to_be_bytes());

    // Capabilities go inside an Optional Parameter of type 2.
    // We emit one such Opt Param whose value is the concatenation
    // of all capability TLVs.
    let opt_params_len = 2 + caps.len(); // [type=2, len=...] + caps
    let mut opt_params: Vec<u8> = Vec::with_capacity(opt_params_len);
    opt_params.push(2); // param type: Capability
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
    out.push(opt_params.len() as u8);
    out.extend_from_slice(&opt_params);
    out
}

/// Build a KEEPALIVE — header only, 19 bytes.
pub fn encode_keepalive() -> Vec<u8> {
    let mut out = Vec::with_capacity(BGP_HEADER_LEN);
    out.extend_from_slice(&BGP_MARKER);
    out.extend_from_slice(&(BGP_HEADER_LEN as u16).to_be_bytes());
    out.push(MSG_TYPE_KEEPALIVE);
    out
}

// --- Helpers ----------------------------------------------------------------

fn synthetic_peer_id(listen: SocketAddr, peer_asn: u32) -> PeerId {
    // Stable across reconnects. We use (listen_ip, peer_asn) so two
    // separately-configured BGP listeners (e.g., listening on
    // different loopback IPs for two different bird instances) get
    // different peer IDs.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    listen.ip().hash(&mut h);
    peer_asn.hash(&mut h);
    PeerId(h.finish())
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
/// type — graceful skip; bgpkit-parser's [`Elementor`] occasionally
/// emits malformed prefixes from withdraw NLRIs and we don't want
/// those to crash the session.
///
/// **The `fallback_nh` parameter** is the v0.2.1 fix for silently
/// dropping bird's `protocol direct` exports. Direct-origin (and
/// static-origin) routes go out via iBGP without an explicit BGP
/// NEXT_HOP attribute when the bird-side BGP block has no
/// `next hop self` directive — there's no upstream eBGP next-hop
/// to preserve, and bird doesn't synthesize one. bgpkit-parser's
/// `Elementor::bgp_update_to_elems` returns `next_hop = None` for
/// those announces.
///
/// Pre-v0.2.1 we silently `continue`d on `None`, so connected /24s
/// bird was correctly exporting never landed in `FIB_V4` at all —
/// the prefix wasn't present for XDP to LPM-match. Operator-visible
/// symptom: `matched_dst_only` inbound to customer /24s all bumped
/// `custom_fib_miss` instead of `custom_fib_no_neigh`, and the FIB
/// integrity check perpetually reported drift between bird's
/// exported-route count and packetframe's mirror count.
///
/// The chosen fallback is the BGP session's listen address (typically
/// `127.0.0.1` for the loopback iBGP setup). The neighbor resolver
/// can't get a useful MAC for loopback, so the route lands with
/// `state=Incomplete` — operationally the same XDP_PASS-to-kernel as
/// the silent-drop, but now the prefix exists in `FIB_V4`, the
/// nexthop counter (`custom_fib_no_neigh`) reflects reality, and
/// integrity drift goes away. Phase B (`local-prefix` ARP-walk)
/// turns those /24s into per-/32 fast-paths.
fn elem_to_route_event(
    elem: &bgpkit_parser::models::BgpElem,
    peer_id: PeerId,
    fallback_nh: IpAddr,
) -> Option<RouteEvent> {
    let prefix = network_prefix_to_ip_prefix(&elem.prefix)?;
    Some(match elem.elem_type {
        ElemType::ANNOUNCE => {
            let nh = elem.next_hop.unwrap_or(fallback_nh);
            RouteEvent::Add {
                peer_id,
                prefix,
                nexthops: vec![nh],
            }
        }
        ElemType::WITHDRAW => RouteEvent::Del { peer_id, prefix },
    })
}

// --- Tests ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_encoder_roundtrip() {
        let bytes = encode_open(401401, 90, Ipv4Addr::new(103, 17, 154, 7));
        // Marker check.
        assert_eq!(&bytes[..16], &BGP_MARKER);
        // Length matches buffer.
        let len = u16::from_be_bytes([bytes[16], bytes[17]]) as usize;
        assert_eq!(len, bytes.len());
        // Type byte.
        assert_eq!(bytes[18], MSG_TYPE_OPEN);
        // Version.
        assert_eq!(bytes[19], 4);
        // My AS = AS_TRANS because 401401 > 65535.
        assert_eq!(u16::from_be_bytes([bytes[20], bytes[21]]), AS_TRANS);
        // Hold time.
        assert_eq!(u16::from_be_bytes([bytes[22], bytes[23]]), 90);
        // Router ID.
        assert_eq!(&bytes[24..28], &[103, 17, 154, 7]);
        // Parse it back via bgpkit-parser to confirm wire validity.
        let mut b = Bytes::copy_from_slice(&bytes);
        let parsed = parse_bgp_message(&mut b, false, &AsnLength::Bits32).expect("parse");
        match parsed {
            BgpMessage::Open(o) => {
                assert_eq!(o.version, 4);
                assert_eq!(o.hold_time, 90);
                assert_eq!(o.bgp_identifier, Ipv4Addr::new(103, 17, 154, 7));
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
        let bytes = encode_open(401401, 90, Ipv4Addr::new(1, 2, 3, 4));
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
                _ => {}
            }
            i += 2 + clen;
        }
        assert!(saw_mp_v4, "missing MP-BGP IPv4 unicast capability");
        assert!(saw_mp_v6, "missing MP-BGP IPv6 unicast capability");
        assert_eq!(
            saw_4byte_asn,
            Some(401401),
            "missing or wrong 4-octet ASN capability"
        );
    }

    #[test]
    fn open_does_not_advertise_route_refresh() {
        // We never originate routes, so we don't want bird sending us
        // ROUTE-REFRESH. Verify capability code 2 (Route Refresh) is
        // absent from our OPEN.
        let bytes = encode_open(401401, 90, Ipv4Addr::new(1, 2, 3, 4));
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
        let a = synthetic_peer_id("127.0.0.1:1179".parse().unwrap(), 401401);
        let b = synthetic_peer_id("127.0.0.1:1179".parse().unwrap(), 401401);
        assert_eq!(a, b);
        let c = synthetic_peer_id("127.0.0.1:1179".parse().unwrap(), 64512);
        assert_ne!(a, c);
    }

    /// v0.2.1 regression guard. Pre-fix, `elem_to_route_event` (then
    /// inlined in the read loop) silently `continue`d on
    /// `next_hop = None`, which is exactly what bird's iBGP emits for
    /// `protocol direct` announces without `next hop self`. Result:
    /// connected /24s never reached `FIB_V4`, every inbound
    /// matched_dst_only packet bumped `custom_fib_miss`, and the FIB
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
    fn elem_to_route_event_uses_fallback_when_next_hop_missing() {
        use bgpkit_parser::models::ElemType;
        use std::net::Ipv4Addr;
        let elem = make_test_elem(ElemType::ANNOUNCE, "23.191.200.0/24", None);
        let peer_id = PeerId(0xdeadbeef);
        let fallback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let event = elem_to_route_event(&elem, peer_id, fallback)
            .expect("elem with valid prefix must yield an event");
        match event {
            RouteEvent::Add {
                peer_id: pid,
                prefix,
                nexthops,
            } => {
                assert_eq!(pid, peer_id);
                assert!(matches!(
                    prefix,
                    IpPrefix::V4 {
                        addr: [23, 191, 200, 0],
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
        let real_nh = IpAddr::V4(Ipv4Addr::new(194, 110, 60, 50)); // Macarne-style nh
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
        let elem = make_test_elem(ElemType::WITHDRAW, "23.191.200.0/24", None);
        let event = elem_to_route_event(&elem, PeerId(0), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .expect("withdraw with valid prefix must yield an event");
        assert!(matches!(event, RouteEvent::Del { .. }));
    }
}
