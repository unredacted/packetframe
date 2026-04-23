//! BMP station — the concrete `RouteSource` that receives bird's
//! Loc-RIB (RFC 9069) over a BMP session and translates it into
//! [`RouteEvent`]s delivered to the FibProgrammer.
//!
//! **RFC 7854 role:** bird is the BMP client, packetframe is the BMP
//! station. Bird dials out to this listener; packetframe accepts.
//! One connection at a time (bird only opens one); on disconnect we
//! emit [`RouteEvent::Resync`] and re-accept.
//!
//! **Loc-RIB (RFC 9069):** bird's `monitoring rib local` emits
//! route-monitoring messages with per-peer-type `LocalRib`
//! (bgpkit-parser's `BmpPeerType::LocalRib`, wire value 3). We
//! hash the per-peer header into an opaque [`PeerId`] so the
//! programmer can scope withdraws; PeerDown for the Loc-RIB instance
//! means bird's local best-path table is gone (unusual but possible).
//!
//! **Wire framing:** BMP's common header carries a 32-bit
//! big-endian message length. Read 6 bytes, extract length, read
//! `length - 6` bytes of body, hand the whole frame to
//! `parse_bmp_msg`. Framing runs in a dedicated task so the main
//! event loop's `select!` can interleave a quiescence timer without
//! cancel-safety issues — `read_exact` isn't cancel-safe, so running
//! it under a `select!` arm would desync the stream whenever the
//! timer arm fired mid-read.
//!
//! **BGP UPDATE → RouteEvent translation:** `Elementor::bgp_to_elems`
//! converts the UPDATE wrapped inside a RouteMonitoring message into
//! per-prefix `BgpElem`s. Announces with a next_hop become
//! `RouteEvent::Add { peer_id, prefix, nexthops: vec![next_hop] }`.
//! Withdraws become `RouteEvent::Del`.
//!
//! **InitiationComplete heuristic.** RFC 7854 doesn't signal "initial
//! dump complete" explicitly. We fire `RouteEvent::InitiationComplete`
//! once per connection, after [`INIT_COMPLETE_QUIESCENCE`] of no
//! incoming RouteMonitoring frames post the first RouteMonitoring.
//! Bird's full-RIB dump normally finishes within a few seconds; a 5 s
//! window of silence is a reasonable proxy for "dump done."
//! False-positive risk: if bird is dumping so slowly that individual
//! peers quiesce for > 5 s between batches, we fire early and GC
//! mid-dump routes. Mitigation: the next Add events after InitComplete
//! simply re-populate them — the programmer mirror gets rewritten.
//! Operationally benign.

#![cfg(target_os = "linux")]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bgpkit_parser::models::{ElemType, NetworkPrefix};
use bgpkit_parser::parser::bmp::messages::*;
use bgpkit_parser::parser::bmp::parse_bmp_msg;
use bgpkit_parser::Elementor;
use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use packetframe_common::fib::{IpPrefix, PeerId, RouteEvent, RouteSourceError};

use crate::fib::programmer::FibProgrammerHandle;

/// Cap on a single BMP message size. Per RFC 7854 §4.1 the
/// `msg_length` is a 32-bit unsigned field; bird in practice emits
/// far smaller messages. 1 MiB is comfortable headroom and cheap
/// defense against a malformed stream claiming 4 GiB per frame.
const MAX_BMP_MSG_SIZE: usize = 1024 * 1024;

/// InitiationComplete quiescence threshold. See the module-level
/// docstring for the rationale. Tune by PR if operators see
/// false-positives on slow full-table dumps.
const INIT_COMPLETE_QUIESCENCE: Duration = Duration::from_secs(5);

/// Bounded channel between the BMP reader task and the main select!
/// loop. 256 absorbs a burst of route-monitoring frames between 1-
/// second tick wakeups without backpressuring bird.
const FRAME_CHANNEL_CAPACITY: usize = 256;

pub struct BmpStation {
    listen_addr: SocketAddr,
    prog_handle: FibProgrammerHandle,
    shutdown: CancellationToken,
    /// Shared atomic updated on each ROUTE MONITORING frame. Unix
    /// seconds; `0` means "never seen one since process start."
    /// Exposed so a stall-monitor task can read it without holding
    /// a reference to the BmpStation itself.
    last_rm_unix: Arc<AtomicI64>,
    /// Optional integrity snapshot. When `Some`, the stall monitor
    /// reads `bird_established_peers`: an alert only fires when bird
    /// thinks there's at least one peer we should be hearing from.
    stall_gate: Option<SharedIntegritySnapshot>,
}

/// Re-export for callers building the station.
pub type SharedIntegritySnapshot = crate::fib::integrity::SharedSnapshot;

/// After this long with no ROUTE MONITORING frame, the stall monitor
/// considers the session stalled. Plan: 5 min.
pub const STALL_THRESHOLD: Duration = Duration::from_secs(300);
/// First alert suppressed for this long after process start so the
/// integrity cache can warm and the initial RIB dump can complete.
pub const STALL_STARTUP_SUPPRESSION: Duration = Duration::from_secs(600);
/// Cadence at which the stall monitor re-evaluates the condition.
pub const STALL_TICK: Duration = Duration::from_secs(30);

impl BmpStation {
    pub fn new(
        listen_addr: SocketAddr,
        prog_handle: FibProgrammerHandle,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            listen_addr,
            prog_handle,
            shutdown,
            last_rm_unix: Arc::new(AtomicI64::new(0)),
            stall_gate: None,
        }
    }

    /// Attach the integrity checker's snapshot so `run()` spawns a
    /// stall monitor alongside the accept loop. Without this, stall
    /// detection is silent — appropriate for test harnesses that
    /// don't care about the alert path.
    pub fn with_stall_gate(mut self, snapshot: SharedIntegritySnapshot) -> Self {
        self.stall_gate = Some(snapshot);
        self
    }

    /// Main loop: bind, accept, handle one connection at a time.
    /// On disconnect (clean or error), emit Resync so the programmer
    /// marks all mirrored routes unseen — the next `RouteEvent::Add`
    /// storm from the reconnect clears the marks; InitiationComplete
    /// (emitted by a quiescence timer inside `handle_connection`)
    /// GCs whatever never reappeared.
    pub async fn run(self) -> Result<(), RouteSourceError> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(|e| RouteSourceError::fatal(format!("bind {}: {e}", self.listen_addr)))?;
        info!(addr = %self.listen_addr, "BMP station listening");

        // Optional stall monitor. Fires a warning log when no ROUTE
        // MONITORING frame arrives for `STALL_THRESHOLD` *and* the
        // integrity check reports ≥1 Established peer. Suppressed for
        // `STALL_STARTUP_SUPPRESSION` so the initial RIB dump has a
        // chance to land.
        let stall_task = self.stall_gate.clone().map(|snap| {
            let last_rm = self.last_rm_unix.clone();
            let shutdown = self.shutdown.clone();
            let start = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            tokio::spawn(async move { stall_monitor(last_rm, snap, shutdown, start).await })
        });

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("BmpStation shutdown requested");
                    if let Some(t) = stall_task {
                        t.abort();
                    }
                    return Ok(());
                }
                accept = listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            info!(%addr, "BMP client connected");
                            if let Err(e) = self.handle_connection(stream).await {
                                warn!(error = %e, "BMP connection handler exited with error");
                            } else {
                                info!("BMP client disconnected cleanly");
                            }
                            // Resync contract: any prior-session mirrored
                            // state is now potentially stale. Programmer
                            // flips seen_this_session=false on all routes;
                            // the next Add storm clears marks; unmarked
                            // entries get GC'd on InitiationComplete.
                            if let Err(e) = self
                                .prog_handle
                                .apply_route_event(RouteEvent::Resync)
                                .await
                            {
                                warn!(error = %e, "Resync dispatch failed");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "TCP accept failed");
                        }
                    }
                }
            }
        }
    }

    /// Handle one BMP connection. Spawns a reader task that pushes
    /// parsed messages into a bounded channel; the main select! loop
    /// below drains that channel alongside a 1-second quiescence tick
    /// that fires InitiationComplete exactly once per connection.
    async fn handle_connection(&self, stream: TcpStream) -> Result<(), RouteSourceError> {
        let (frame_tx, mut frame_rx) = mpsc::channel::<BmpMessage>(FRAME_CHANNEL_CAPACITY);
        let reader = tokio::spawn(async move { reader_task(stream, frame_tx).await });

        let mut last_route_monitoring: Option<std::time::Instant> = None;
        let mut init_complete_fired = false;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        // interval fires immediately the first tick; skip it so the
        // first real quiescence check lands one full period in.
        tick.tick().await;

        let mut frames_parsed = 0usize;
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    reader.abort();
                    return Ok(());
                }
                msg = frame_rx.recv() => {
                    match msg {
                        Some(m) => {
                            frames_parsed += 1;
                            if matches!(m.message_body, BmpMessageBody::RouteMonitoring(_)) {
                                let now = std::time::Instant::now();
                                last_route_monitoring = Some(now);
                                // Publish wall-clock unix seconds so
                                // the stall monitor (a separate task
                                // with no direct reference to this
                                // loop's `Instant`) can evaluate age.
                                let unix = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs() as i64;
                                self.last_rm_unix.store(unix, Ordering::Relaxed);
                            }
                            self.process_msg(m).await;
                        }
                        None => {
                            // Reader task exited — EOF or error. Join it
                            // to surface any error, then return.
                            match reader.await {
                                Ok(Ok(())) => {
                                    debug!(frames_parsed, "BMP stream done");
                                    return Ok(());
                                }
                                Ok(Err(e)) => return Err(e),
                                Err(e) => {
                                    return Err(RouteSourceError::recoverable(format!(
                                        "reader task join: {e}"
                                    )))
                                }
                            }
                        }
                    }
                }
                _ = tick.tick() => {
                    if init_complete_fired {
                        continue;
                    }
                    if let Some(last) = last_route_monitoring {
                        if last.elapsed() >= INIT_COMPLETE_QUIESCENCE {
                            if let Err(e) = self
                                .prog_handle
                                .apply_route_event(RouteEvent::InitiationComplete)
                                .await
                            {
                                warn!(error = %e, "InitiationComplete dispatch failed");
                            } else {
                                info!(
                                    frames_parsed,
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

    /// Dispatch on the BMP message body and fan out the appropriate
    /// RouteEvents. Errors from the programmer are logged, not
    /// propagated — a single bad map write shouldn't kill the BMP
    /// connection when the next route might succeed.
    async fn process_msg(&self, msg: BmpMessage) {
        match msg.message_body {
            BmpMessageBody::InitiationMessage(_) => {
                info!("BMP INITIATION received from bird");
            }
            BmpMessageBody::TerminationMessage(_) => {
                info!("BMP TERMINATION received from bird");
            }
            BmpMessageBody::PeerUpNotification(_) => {
                let pph = match &msg.per_peer_header {
                    Some(p) => p,
                    None => return,
                };
                let peer_id = peer_id_from_header(pph);
                info!(
                    ?peer_id,
                    peer_ip = %pph.peer_ip,
                    peer_asn = %pph.peer_asn,
                    peer_type = ?pph.peer_type,
                    "PeerUp"
                );
                if let Err(e) = self
                    .prog_handle
                    .apply_route_event(RouteEvent::PeerUp {
                        peer_id,
                        peer_ip: pph.peer_ip,
                        peer_asn: asn_to_u32(pph.peer_asn),
                    })
                    .await
                {
                    warn!(?peer_id, error = %e, "PeerUp dispatch failed");
                }
            }
            BmpMessageBody::PeerDownNotification(_) => {
                let pph = match &msg.per_peer_header {
                    Some(p) => p,
                    None => return,
                };
                let peer_id = peer_id_from_header(pph);
                info!(?peer_id, peer_ip = %pph.peer_ip, "PeerDown");
                if let Err(e) = self
                    .prog_handle
                    .apply_route_event(RouteEvent::PeerDown { peer_id })
                    .await
                {
                    warn!(?peer_id, error = %e, "PeerDown dispatch failed");
                }
            }
            BmpMessageBody::RouteMonitoring(rm) => {
                let pph = match &msg.per_peer_header {
                    Some(p) => p,
                    None => {
                        warn!("RouteMonitoring without per-peer header");
                        return;
                    }
                };
                let peer_id = peer_id_from_header(pph);
                // Elementor converts the UPDATE wrapped in this
                // RouteMonitoring into one BgpElem per prefix.
                let elems = Elementor::bgp_to_elems(
                    rm.bgp_message,
                    pph.timestamp,
                    &pph.peer_ip,
                    &pph.peer_asn,
                );
                for elem in elems {
                    let prefix = match network_prefix_to_ip_prefix(&elem.prefix) {
                        Some(p) => p,
                        None => continue,
                    };
                    let event = match elem.elem_type {
                        ElemType::ANNOUNCE => {
                            let nh = match elem.next_hop {
                                Some(h) => h,
                                None => {
                                    debug!(?prefix, "announce without next_hop — skipping");
                                    continue;
                                }
                            };
                            RouteEvent::Add {
                                peer_id,
                                prefix,
                                nexthops: vec![nh],
                            }
                        }
                        ElemType::WITHDRAW => RouteEvent::Del { peer_id, prefix },
                    };
                    if let Err(e) = self.prog_handle.apply_route_event(event).await {
                        warn!(?peer_id, error = %e, "route event dispatch failed");
                    }
                }
            }
            BmpMessageBody::RouteMirroring(_) => {
                debug!("RouteMirroring ignored (not consumed in Option F)");
            }
            BmpMessageBody::StatsReport(_) => {
                debug!("StatsReport ignored");
            }
        }
    }
}

/// Reader task. Reads BMP frames from `stream` and pushes parsed
/// Stall monitor: fires a warning log if no ROUTE MONITORING frame
/// has arrived for [`STALL_THRESHOLD`] *and* the integrity check
/// reports ≥1 Established BGP peer. The cross-check avoids a
/// false-positive during a global bird outage — in that case the
/// alert we'd actually want is "bird down," not "BMP stalled."
///
/// Startup suppression: first [`STALL_STARTUP_SUPPRESSION`] of
/// process life is quiet so the initial RIB dump can complete.
/// The caller passes `process_start_unix` so we don't re-measure
/// here (and because the function has no other access to a clock
/// reference point).
///
/// Evaluation cadence is [`STALL_TICK`] — a real stall sits long
/// enough for any reasonable poll interval.
async fn stall_monitor(
    last_rm_unix: Arc<AtomicI64>,
    integrity: SharedIntegritySnapshot,
    shutdown: CancellationToken,
    process_start_unix: i64,
) {
    let mut tick = tokio::time::interval(STALL_TICK);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tick.tick() => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                // Startup suppression.
                if now - process_start_unix < STALL_STARTUP_SUPPRESSION.as_secs() as i64 {
                    continue;
                }
                let last_rm = last_rm_unix.load(Ordering::Relaxed);
                // `0` means "no RM ever seen." After startup
                // suppression that's itself a stall, but only if bird
                // says it has Established peers.
                let quiet_seconds = if last_rm == 0 {
                    now - process_start_unix
                } else {
                    now - last_rm
                };
                if quiet_seconds < STALL_THRESHOLD.as_secs() as i64 {
                    continue;
                }
                // Gate on bird's cached peer state.
                let established = integrity.read().await.bird_established_peers;
                match established {
                    Some(n) if n > 0 => {
                        warn!(
                            quiet_seconds,
                            bird_established_peers = n,
                            "BMP session appears stalled (no ROUTE MONITORING + bird reports Established peers)"
                        );
                    }
                    Some(0) => {
                        debug!(
                            quiet_seconds,
                            "BMP quiet but bird reports zero Established peers — stall alert suppressed"
                        );
                    }
                    None => {
                        // Integrity cache cold. Can't gate the alert
                        // responsibly; stay quiet rather than risk
                        // false-positives during bird downtime.
                        debug!(
                            quiet_seconds,
                            "BMP quiet but integrity cache is cold — stall alert suppressed"
                        );
                    }
                }
            }
        }
    }
}

/// messages into `tx` until EOF or error. Exits cleanly (`Ok(())`)
/// on EOF; error on anything else. Kept in its own function so the
/// main select! loop never holds a non-cancel-safe `read_exact`
/// future.
async fn reader_task(
    mut stream: TcpStream,
    tx: mpsc::Sender<BmpMessage>,
) -> Result<(), RouteSourceError> {
    let mut frames_parsed = 0usize;
    loop {
        let mut header_buf = [0u8; 6];
        match stream.read_exact(&mut header_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!(frames_parsed, "BMP stream EOF (reader)");
                return Ok(());
            }
            Err(e) => {
                return Err(RouteSourceError::recoverable(format!("read header: {e}")));
            }
        }
        // BMP common header: version(1) + msg_len(4) + msg_type(1).
        // msg_len covers the entire frame including the header.
        let msg_len =
            u32::from_be_bytes([header_buf[1], header_buf[2], header_buf[3], header_buf[4]])
                as usize;
        if !(6..=MAX_BMP_MSG_SIZE).contains(&msg_len) {
            return Err(RouteSourceError::recoverable(format!(
                "invalid msg_len {msg_len} (frames_parsed={frames_parsed})"
            )));
        }
        let body_len = msg_len - 6;
        let mut body_buf = vec![0u8; body_len];
        if body_len > 0 {
            stream
                .read_exact(&mut body_buf)
                .await
                .map_err(|e| RouteSourceError::recoverable(format!("read body: {e}")))?;
        }

        // Reconstruct the full frame. `parse_bmp_msg` expects the
        // header bytes at the front of the buffer — it re-reads
        // them to validate the version / type.
        let mut full = Vec::with_capacity(msg_len);
        full.extend_from_slice(&header_buf);
        full.extend_from_slice(&body_buf);
        let mut bytes = Bytes::from(full);

        match parse_bmp_msg(&mut bytes) {
            Ok(msg) => {
                frames_parsed += 1;
                if tx.send(msg).await.is_err() {
                    // Main loop dropped the receiver — shutdown.
                    debug!(frames_parsed, "frame receiver closed; reader exiting");
                    return Ok(());
                }
            }
            Err(e) => {
                return Err(RouteSourceError::recoverable(format!(
                    "parse_bmp_msg after {frames_parsed}: {e}"
                )));
            }
        }
    }
}

/// Derive a stable [`PeerId`] from a BMP per-peer header.
/// `peer_ip + peer_distinguisher + peer_type` together uniquely
/// identify one peer — two BGP sessions to the same peer IP that
/// differ in RD or peer-type hash to distinct IDs.
fn peer_id_from_header(pph: &BmpPerPeerHeader) -> PeerId {
    let mut hasher = DefaultHasher::new();
    pph.peer_ip.hash(&mut hasher);
    pph.peer_distinguisher.hash(&mut hasher);
    (pph.peer_type as u8).hash(&mut hasher);
    PeerId(hasher.finish())
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

/// Extract a u32 from bgpkit-parser's `Asn`. The struct has a `u32`
/// field `asn`; we reach for it via `Display` so the conversion
/// works across whichever `From` / `Into` impls the version
/// provides.
fn asn_to_u32(asn: bgpkit_parser::models::Asn) -> u32 {
    // `Asn` impls `Display` as the decimal integer.
    asn.to_string().parse().unwrap_or(0)
}
