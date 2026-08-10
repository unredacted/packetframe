//! BMP station, the concrete `RouteSource` that receives bird's
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
//! cancel-safety issues, `read_exact` isn't cancel-safe, so running
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
//! simply re-populate them, the programmer mirror gets rewritten.
//! Operationally benign.

#![cfg(target_os = "linux")]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bgpkit_parser::models::{ElemType, NetworkPrefix};
use bgpkit_parser::parser::bmp::messages::*;
use bgpkit_parser::parser::bmp::parse_bmp_msg;
use bgpkit_parser::Elementor;
use bytes::Bytes;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
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

/// Per-`read_exact` timeout on the BMP TCP stream. The reader task
/// otherwise blocks forever on a peer that completed TCP handshake
/// but never sent bytes (or sent a header but no body), the
/// audit-flagged slowloris primitive (Slice 2). 60 s is comfortable
/// for legitimate bird (which sends initial RIB dumps in < 5 s) and
/// tight enough to give the operator's stuck-session detection a
/// chance to recover.
const BMP_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Cap on per-RouteMonitoring `BgpElem` count. Same rationale as
/// the matching constant in `route_source_bgp.rs`: a single
/// RouteMonitoring frame embeds one BGP UPDATE, which `Elementor`
/// fans out into N elems, each costing one `apply_route_event`
/// `.await`. 8192 is above any realistic bird best-path dump per
/// frame.
const MAX_ELEMS_PER_UPDATE: usize = 8192;

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
    /// Loc-RIB-only safety mode. When true, RouteMonitoring frames
    /// whose per-peer-header carries `peer_type != LocalRib` (RFC
    /// 9069 peer type 3) cause the session to be torn down with an
    /// error rather than silently producing per-peer Adj-RIB-In
    /// programmer writes that race-overwrite per-prefix nexthops.
    /// Required for safe forwarding use against bird 2.x / bird 3.x
    /// (which only emit pre/post-policy frames).
    require_loc_rib: bool,
    /// CIDR ACL applied at `accept()` time. Empty means "loopback
    /// only", the config parser only permits empty when
    /// `listen_addr` is loopback. When non-empty, every accepted
    /// source IP must fall within at least one entry or the
    /// connection is dropped before the BMP framing starts.
    peer_acl: Vec<ipnet::IpNet>,
    /// Session-liveness handle, reported to the second tier. See
    /// [`packetframe_common::fib::FeedSession`].
    session: Option<std::sync::Arc<packetframe_common::fib::FeedSession>>,
    /// Monitored peers currently up on this connection, by BMP PeerUp
    /// and PeerDown. The liveness handle follows THIS set, never the
    /// TCP transport: bird's monitoring connection stays established
    /// while every BGP peer it monitors is down, and PeerDown has
    /// already wiped their routes — reporting "up" on the socket alone
    /// would let a second tier trust a mirror that just lost its feed
    /// (review finding).
    up_peers: std::sync::Mutex<std::collections::HashSet<PeerId>>,
    /// Whether this connection has EVER sent a PeerUp. An emitter that
    /// speaks peer lifecycle gets peer-set semantics both ways: PeerUp
    /// raises, and when the last monitored peer goes down the feed is
    /// down, however many RM frames were streamed before — while a
    /// straggler RM after the last PeerDown raises nothing (review
    /// findings, kept from the epoch era because they are about
    /// SEMANTICS, not settling).
    saw_peer_up: std::sync::atomic::AtomicBool,
    /// Whether a PREVIOUS stream's advertisements may still be in the
    /// mirror — the actual variable every earlier proxy (connection
    /// counts, contributing-stream counts, an ever-announced latch)
    /// was reaching for (review findings, five refinements). It is now
    /// answered by ASKING THE MIRROR at each boundary
    /// ([`Self::mirror_holds_state`]) rather than by tracking what
    /// this connection did: every latch was wrong in one direction or
    /// the other, because what survives a connection is a property of
    /// the mirror, not of the stream that wrote it. A stream that
    /// announced and then withdrew everything leaves nothing, so the
    /// next stream rightly starts fresh; a PeerDown wipe whose FIB
    /// deletes partially FAILED leaves routes the programmer never
    /// retracted from the second tier, so it rightly does not.
    /// While false, a stream's first frame may raise liveness — there
    /// is no stale floor-credit to release against. While true, the
    /// raise waits for InitiationComplete (whose GC destroys exactly
    /// this state, and which therefore clears it by definition) or for
    /// the re-armable quiesced raise.
    stale_state_possible: std::sync::atomic::AtomicBool,
    /// The session pulse count at the last liveness BOUNDARY — a
    /// lowering, or an epoch-opening PeerUp (which consumes any
    /// peerless straggler pulses that preceded it; review finding).
    /// The re-armable raise requires stream evidence newer than this:
    /// elements seen since the boundary, so a later peer epoch can
    /// re-establish the session (a one-shot raise left it down for
    /// the socket's lifetime; review finding) while neither an old
    /// silence nor another peer's stragglers can.
    pulses_at_lower: std::sync::atomic::AtomicU64,
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
            require_loc_rib: false,
            peer_acl: Vec::new(),
            session: None,
            up_peers: std::sync::Mutex::new(std::collections::HashSet::new()),
            saw_peer_up: std::sync::atomic::AtomicBool::new(false),
            stale_state_possible: std::sync::atomic::AtomicBool::new(false),
            pulses_at_lower: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Lower the session and remember how much stream had been seen:
    /// the re-armable raise demands evidence newer than this moment.
    fn lower_session(&self) {
        if let Some(sess) = &self.session {
            self.pulses_at_lower
                .store(sess.pulse_count(), std::sync::atomic::Ordering::Relaxed);
            sess.set_up(false);
        }
    }

    /// Whether the programmer's mirror still holds routes — the direct
    /// answer to what [`Self::stale_state_possible`] must record at a
    /// stream boundary. The mirror is the second tier's own source
    /// (`ResolvedRouteSink` fires on mirror commits), so a non-empty
    /// mirror is precisely "floor credit the next stream would inherit
    /// without having earned it".
    ///
    /// Ordering is free: commands share one channel and every route
    /// dispatch at these sites is awaited, so a count sent afterwards
    /// observes the wipe — including a wipe that only PARTIALLY
    /// succeeded. `drop_routes_for_peer` logs and swallows map and
    /// recompute failures, so "we dispatched PeerDown" is not evidence
    /// the routes are gone (review finding). Counting them is.
    ///
    /// Reading THIS mirror answers for the second tier's because
    /// `FibProgrammer::withdraw_from_mirror` makes removal and
    /// withdrawal one step, and `route_resolved` fires only after the
    /// mirror commit: the second tier's set is a subset of this one,
    /// so empty here means empty there. Before that was true a failed
    /// LPM delete trimmed this mirror while the second tier kept the
    /// route — a count of zero over a stale above-floor table, which
    /// is the exact evidence this function exists to refuse (review
    /// finding).
    ///
    /// It asks for ROUTE-SOURCE advertisements, not for a raw route
    /// count. The mirror is SHARED: the neighbour resolver injects
    /// `local-prefix` /32s and /128s through this same handle, they are
    /// resident for the daemon's life, and they belong to no session —
    /// so counting them meant every reconnect found "prior state", no
    /// stream ever earned its first-frame raise, and a continuously
    /// active feed could stay down indefinitely (review finding). Nor
    /// can they be the stale floor credit this guards: a handful of
    /// local /32s is nowhere near capacity/16.
    ///
    /// Both families count. Only v4 reaches VPP today
    /// (`FamilyPolicy::V4Only`), so a v6-only remnant carries no floor
    /// credit and this over-defers — but the station has no business
    /// knowing the second tier's family policy, and over-deferring is
    /// the safe direction. An unavailable answer reads as "possible"
    /// for the same reason.
    async fn mirror_holds_state(&self) -> bool {
        match self.prog_handle.has_session_routes().await {
            Ok(any) => any,
            Err(e) => {
                warn!(error = %e, "mirror query unavailable; assuming prior-stream state remains");
                true
            }
        }
    }

    /// Report session liveness through `handle`. `None` reports to
    /// nobody, which is every deployment without a second tier.
    pub fn with_feed_session(
        mut self,
        handle: Option<std::sync::Arc<packetframe_common::fib::FeedSession>>,
    ) -> Self {
        self.session = handle;
        self
    }

    /// Attach the integrity checker's snapshot so `run()` spawns a
    /// stall monitor alongside the accept loop. Without this, stall
    /// detection is silent, appropriate for test harnesses that
    /// don't care about the alert path.
    pub fn with_stall_gate(mut self, snapshot: SharedIntegritySnapshot) -> Self {
        self.stall_gate = Some(snapshot);
        self
    }

    /// Enable Loc-RIB-only safety mode: any RouteMonitoring frame
    /// with `peer_type != LocalRib` tears the session down with an
    /// error. Required when running against pre/post-policy emitters
    /// like bird 2.x, see the `require_loc_rib` field doc.
    pub fn with_require_loc_rib(mut self) -> Self {
        self.require_loc_rib = true;
        self
    }

    /// Set the CIDR ACL applied at `accept()` time. Empty (the
    /// default) means loopback-only. The config parser enforces the
    /// "non-loopback listen requires non-empty ACL" invariant; this
    /// builder is the runtime path the controller uses to thread the
    /// parsed ACL through.
    pub fn with_peer_acl(mut self, peer_acl: Vec<ipnet::IpNet>) -> Self {
        self.peer_acl = peer_acl;
        self
    }

    /// Main loop: bind, accept, handle one connection at a time.
    /// On disconnect (clean or error), emit Resync so the programmer
    /// marks all mirrored routes unseen, the next `RouteEvent::Add`
    /// storm from the reconnect clears the marks; InitiationComplete
    /// (emitted by a quiescence timer inside `handle_connection`)
    /// GCs whatever never reappeared.
    pub async fn run(self) -> Result<(), RouteSourceError> {
        let listener = bind_with_reuseaddr(self.listen_addr)
            .map_err(|e| RouteSourceError::fatal(format!("bind {}: {e}", self.listen_addr)))?;
        let loopback_only = self.listen_addr.ip().is_loopback() && self.peer_acl.is_empty();
        info!(
            addr = %self.listen_addr,
            peer_acl_entries = self.peer_acl.len(),
            auth_posture = if loopback_only { "loopback-only" } else { "allow-remote (no TCP-MD5)" },
            "BMP station listening"
        );

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
                            // Source-IP gate runs before any BMP byte
                            // is read. Same audit (May 2026) rationale
                            // as the matching gate in
                            // `route_source_bgp::run`.
                            if !source_ip_permitted(addr.ip(), &self.peer_acl) {
                                warn!(
                                    %addr,
                                    peer_acl_entries = self.peer_acl.len(),
                                    "BMP accept rejected: source IP outside peer-from ACL"
                                );
                                drop(stream);
                                continue;
                            }
                            info!(%addr, "BMP client connected");
                            if let Err(e) = self.handle_connection(stream).await {
                                warn!(error = %e, "BMP connection handler exited with error");
                            } else {
                                info!("BMP client disconnected cleanly");
                            }
                            // The connection ended, and per-peer state
                            // ended with it: whatever PeerUps this
                            // session delivered are no longer evidence.
                            self.up_peers.lock().expect("up_peers lock").clear();
                            self.saw_peer_up
                                .store(false, std::sync::atomic::Ordering::Relaxed);
                            // Whatever this stream left in the mirror
                            // outlives its connection — until the GC or
                            // a wipe says otherwise. Ask the mirror; a
                            // stream that withdrew everything leaves the
                            // next one nothing to inherit.
                            let stale = self.mirror_holds_state().await;
                            self.stale_state_possible
                                .store(stale, std::sync::atomic::Ordering::Relaxed);
                            self.lower_session();
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
                            let is_route_monitoring =
                                matches!(m.message_body, BmpMessageBody::RouteMonitoring(_));
                            // VALIDATE FIRST. `process_msg` rejects a
                            // RouteMonitoring frame outright when
                            // `require-loc-rib` refuses its peer type or
                            // its fan-out exceeds MAX_ELEMS_PER_UPDATE,
                            // and a rejected frame is not stream
                            // evidence of any kind. Raising ahead of it
                            // opened a whole feed EPOCH on a frame the
                            // session was about to be torn down over —
                            // and a runtime that sampled that transient
                            // raise during an adopted deferral baselined
                            // on it, so the next healthy connection read
                            // as a flap and the attested release path
                            // was gone for good (review finding). The
                            // stall-monitor timestamps move with it for
                            // the same reason: a refused frame is not
                            // progress.
                            if let Err(e) = self.process_msg(m).await {
                                reader.abort();
                                return Err(e);
                            }
                            if is_route_monitoring {
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
                                // Pulses are counted in process_msg, in
                                // ROUTE-ELEMENT units — see the pulse
                                // site there for why frames are the
                                // wrong unit.
                                // Raise only when no previous stream's
                                // state can be lingering — see
                                // `stale_state_possible`. The peer-set
                                // arbitration stands: on a peer-speaking
                                // connection a straggler frame after the
                                // last PeerDown raises nothing.
                                let first_stream = !self
                                    .stale_state_possible
                                    .load(std::sync::atomic::Ordering::Relaxed);
                                let peers_speak =
                                    self.saw_peer_up.load(Ordering::Relaxed);
                                let peers_up =
                                    !self.up_peers.lock().expect("up_peers lock").is_empty();
                                if first_stream && (!peers_speak || peers_up) {
                                    if let Some(sess) = &self.session {
                                        sess.set_up(true);
                                        // Reconciled by the same fact
                                        // that permitted the raise:
                                        // `first_stream` IS "no older
                                        // stream's routes remain". Marked
                                        // after the raise so it stamps
                                        // the epoch that raise opened.
                                        sess.mark_reconciled();
                                    }
                                }
                            }
                        }
                        None => {
                            // Reader task exited, EOF or error. Join it
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
                    let quiesced = last_route_monitoring
                        .is_some_and(|last| last.elapsed() >= INIT_COMPLETE_QUIESCENCE);
                    if !quiesced {
                        continue;
                    }
                    // The EVENT is one-shot per connection — the
                    // programmer's GC semantics. The RAISE below is
                    // deliberately not: a one-shot raise left the
                    // session down for the socket's lifetime after any
                    // post-dump last-peer-down, with a healthy later
                    // epoch unable to re-establish it (review finding).
                    if !init_complete_fired {
                        if let Err(e) = self
                            .prog_handle
                            .apply_route_event(RouteEvent::InitiationComplete)
                            .await
                        {
                            warn!(error = %e, "InitiationComplete dispatch failed");
                            continue;
                        }
                        info!(
                            frames_parsed,
                            quiescence_secs = INIT_COMPLETE_QUIESCENCE.as_secs(),
                            "InitiationComplete fired"
                        );
                        init_complete_fired = true;
                        // The GC this event triggers removes every
                        // unseen prior-stream route: whatever staleness
                        // was possible is now gone.
                        self.stale_state_possible
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                    // Re-armable raise: quiescence counts only when the
                    // stream it followed is NEWER than the last
                    // lowering — frames since, not silence since — so a
                    // later peer epoch re-establishes the session while
                    // an old silence cannot (the pulse counter crosses
                    // this boundary; connection-local flags could not,
                    // which is what the epoch machinery kept getting
                    // wrong). Same peer-set guard as everywhere.
                    if let Some(sess) = &self.session {
                        let fresh_stream = sess.pulse_count()
                            > self
                                .pulses_at_lower
                                .load(std::sync::atomic::Ordering::Relaxed);
                        let peers_speak = self
                            .saw_peer_up
                            .load(std::sync::atomic::Ordering::Relaxed);
                        let peers_up = !self
                            .up_peers
                            .lock()
                            .expect("up_peers lock")
                            .is_empty();
                        if fresh_stream && (!peers_speak || peers_up) {
                            sess.set_up(true);
                        }
                        // AFTER the raise, and keyed on the same
                        // variable the raise is: `stale_state_possible`
                        // false means the mirror carries nothing from a
                        // stream older than the current epoch — set by
                        // the GC, and equally by a last-peer PeerDown
                        // whose wipe left nothing behind.
                        //
                        // Not keyed on the GC HAVING JUST RUN, which is
                        // one-shot per connection: a later peer epoch on
                        // the same connection (last peer down, new peer
                        // streams) opens an epoch the GC will never fire
                        // for again, and could then never be marked —
                        // the same permanent demotion one layer in
                        // (review finding). Marking is idempotent and
                        // this pass is once a second, so re-asserting it
                        // costs nothing and cannot go stale: every
                        // epoch that clears the variable gets stamped.
                        if !self
                            .stale_state_possible
                            .load(std::sync::atomic::Ordering::Relaxed)
                        {
                            sess.mark_reconciled();
                        }
                    }
                }
            }
        }
    }

    /// Dispatch on the BMP message body and fan out the appropriate
    /// RouteEvents. Programmer errors are logged but not propagated
    /// a single bad map write shouldn't kill the BMP connection when
    /// the next route might succeed.
    ///
    /// **Returns Err only on session-fatal protocol violations**
    /// today that's a RouteMonitoring frame whose peer_type isn't
    /// `LocalRib` while `require_loc_rib` is set. The caller closes
    /// the session and lets the peer reconnect.
    async fn process_msg(&self, msg: BmpMessage) -> Result<(), RouteSourceError> {
        match msg.message_body {
            BmpMessageBody::InitiationMessage(_) => {
                info!("BMP INITIATION received from bird");
            }
            BmpMessageBody::TerminationMessage(_) => {
                info!("BMP TERMINATION received from bird");
                self.up_peers.lock().expect("up_peers lock").clear();
                self.saw_peer_up
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                let stale = self.mirror_holds_state().await;
                self.stale_state_possible
                    .store(stale, std::sync::atomic::Ordering::Relaxed);
                self.lower_session();
            }
            BmpMessageBody::PeerUpNotification(_) => {
                let pph = match &msg.per_peer_header {
                    Some(p) => p,
                    None => return Ok(()),
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
                self.saw_peer_up
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                let mut up = self.up_peers.lock().expect("up_peers lock");
                let opens_epoch = up.is_empty();
                up.insert(peer_id);
                if opens_epoch {
                    // An epoch-opening PeerUp CONSUMES whatever pulses
                    // preceded it: a peerless straggler frame after the
                    // last PeerDown must not count as this new peer's
                    // stream, or the next quiesced tick would raise
                    // before the peer supplied a single route (review
                    // finding). Freshness now means frames after THIS
                    // peer came up.
                    if let Some(sess) = &self.session {
                        self.pulses_at_lower
                            .store(sess.pulse_count(), std::sync::atomic::Ordering::Relaxed);
                    }
                }
                // Bookkeeping only — no raise. PeerUp precedes the
                // dump, and across a reconnect the mirror still holds
                // the PRIOR session's unseen routes (Resync marks them,
                // InitiationComplete GCs them), so raising here let a
                // stale above-floor mirror pass the gate on fake quiet:
                // quiet because the new dump had not STARTED, not
                // because it finished (review finding). Only the
                // stream itself raises — the first RouteMonitoring
                // frame, exactly the BGP rule (#152) — and the load's
                // own rate then keeps the gate loud until it is
                // genuinely done.
            }
            BmpMessageBody::PeerDownNotification(_) => {
                let pph = match &msg.per_peer_header {
                    Some(p) => p,
                    None => return Ok(()),
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
                // Peer-set semantics: the last monitored peer going
                // down means the feed is down, whatever was streamed
                // before. A connection that never spoke PeerUp (the
                // Loc-RIB shape) never lowers here — its liveness
                // lives and dies with the connection itself.
                // Scoped so the guard is not held across the await.
                let last_peer_down = {
                    let mut up = self.up_peers.lock().expect("up_peers lock");
                    up.remove(&peer_id);
                    up.is_empty() && self.saw_peer_up.load(std::sync::atomic::Ordering::Relaxed)
                };
                if last_peer_down {
                    // The successive PeerDown dispatches were SUPPOSED
                    // to drop every monitored peer's routes; whether
                    // they did is a question for the mirror, not for
                    // the dispatch that swallowed its own failures.
                    let stale = self.mirror_holds_state().await;
                    self.stale_state_possible
                        .store(stale, std::sync::atomic::Ordering::Relaxed);
                    self.lower_session();
                }
            }
            BmpMessageBody::RouteMonitoring(rm) => {
                let pph = match &msg.per_peer_header {
                    Some(p) => p,
                    None => {
                        warn!("RouteMonitoring without per-peer header");
                        return Ok(());
                    }
                };
                if self.require_loc_rib && pph.peer_type != BmpPeerType::LocalRib {
                    return Err(RouteSourceError::recoverable(format!(
                        "rejecting RouteMonitoring with peer_type={:?} \
                         (require-loc-rib is set; only RFC 9069 Loc-RIB peer_type=3 \
                         is safe to drive forwarding from). The emitter (bird 2.x?) \
                         likely needs `monitoring rib in pre_policy` removed; switch \
                         to `route-source bgp` for a safe forwarding feed.",
                        pph.peer_type
                    )));
                }
                let peer_id = peer_id_from_header(pph);
                // The peer-set arbitration applies to the DATA, not
                // only to the raise. On an emitter that speaks peer
                // lifecycle, PeerDown means that peer's routes are
                // gone; a RouteMonitoring frame that arrives after it
                // was in flight when the PeerDown was written and is
                // stale by the emitter's own ordering, BMP being one
                // in-order stream.
                //
                // Installing it puts a dead peer's route in the mirror
                // that nothing will ever remove — PeerDown does not
                // fire twice for a peer already down, and
                // `InitiationComplete` is one-shot per connection — and
                // leaves `stale_state_possible` reading false over it,
                // because the last-peer PeerDown counted the mirror
                // BEFORE this arrived. A later PeerUp then takes the
                // first-frame path, raises, AND marks the new epoch
                // reconciled over state belonging to the old one
                // (review finding). Suppressing the raise while
                // accepting the routes was half a rule.
                if self.saw_peer_up.load(std::sync::atomic::Ordering::Relaxed)
                    && !self
                        .up_peers
                        .lock()
                        .expect("up_peers lock")
                        .contains(&peer_id)
                {
                    debug!(
                        ?peer_id,
                        "RouteMonitoring for a peer that is not up; dropping the frame"
                    );
                    return Ok(());
                }
                // Elementor converts the UPDATE wrapped in this
                // RouteMonitoring into one BgpElem per prefix.
                let elems = Elementor::bgp_to_elems(
                    rm.bgp_message,
                    pph.timestamp,
                    &pph.peer_ip,
                    &pph.peer_asn,
                );
                if elems.len() > MAX_ELEMS_PER_UPDATE {
                    return Err(RouteSourceError::recoverable(format!(
                        "BMP RouteMonitoring fanned out to {} elems (cap {}); closing session",
                        elems.len(),
                        MAX_ELEMS_PER_UPDATE
                    )));
                }
                if let Some(sess) = &self.session {
                    // Stream activity in ROUTE-ELEMENT units, changed or
                    // not: the gate compares activity against
                    // route-scaled quiet rates, and counting frames let
                    // a batched million-route reannouncement dump read
                    // as quiet (review finding). Floored at one unit: an
                    // empty End-of-RIB frame represents no routes but IS
                    // stream evidence, and freshness must advance or a
                    // legitimately empty table can never re-raise after
                    // the GC (review finding) — one unit against
                    // route-scaled rates is noise.
                    sess.pulse_n((elems.len() as u64).max(1));
                }
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
                                    debug!(?prefix, "announce without next_hop, skipping");
                                    continue;
                                }
                            };
                            RouteEvent::Add {
                                peer_id,
                                prefix,
                                nexthops: vec![nh],
                                // BMP Loc-RIB is a post-best-path stream; ADD-PATH
                                // semantics do not apply at this layer.
                                path_id: None,
                                // bgpkit-parser surfaces local_pref on BgpElem
                                // for BMP-derived elements too; propagate so
                                // the FibProgrammer LP-tier filter sees the
                                // same value bird's best-path used.
                                local_pref: elem.local_pref,
                            }
                        }
                        ElemType::WITHDRAW => RouteEvent::Del {
                            peer_id,
                            prefix,
                            path_id: None,
                        },
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
        Ok(())
    }
}

/// Reader task. Reads BMP frames from `stream` and pushes parsed
/// Stall monitor: fires a warning log if no ROUTE MONITORING frame
/// has arrived for [`STALL_THRESHOLD`] *and* the integrity check
/// reports ≥1 Established BGP peer. The cross-check avoids a
/// false-positive during a global bird outage, in that case the
/// alert we'd actually want is "bird down," not "BMP stalled."
///
/// Startup suppression: first [`STALL_STARTUP_SUPPRESSION`] of
/// process life is quiet so the initial RIB dump can complete.
/// The caller passes `process_start_unix` so we don't re-measure
/// here (and because the function has no other access to a clock
/// reference point).
///
/// Evaluation cadence is [`STALL_TICK`], a real stall sits long
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
                    None => {
                        // Integrity cache cold. Can't gate the alert
                        // responsibly; stay quiet rather than risk
                        // false-positives during bird downtime.
                        debug!(
                            quiet_seconds,
                            "BMP quiet but integrity cache is cold, stall alert suppressed"
                        );
                    }
                    Some(0) => {
                        debug!(
                            quiet_seconds,
                            "BMP quiet but bird reports zero Established peers, stall alert suppressed"
                        );
                    }
                    Some(n) => {
                        warn!(
                            quiet_seconds,
                            bird_established_peers = n,
                            "BMP session appears stalled (no ROUTE MONITORING + bird reports Established peers)"
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
        // tokio::time::timeout wrapping read_exact bounds the
        // slowloris primitive: a peer that completes TCP handshake
        // and stops sending bytes can no longer hold the
        // single-connection BMP listener idle forever (audit
        // Slice 2). On timeout we surface a recoverable error so
        // the accept loop closes the stream and re-listens.
        match tokio::time::timeout(BMP_READ_TIMEOUT, stream.read_exact(&mut header_buf)).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!(frames_parsed, "BMP stream EOF (reader)");
                return Ok(());
            }
            Ok(Err(e)) => {
                return Err(RouteSourceError::recoverable(format!("read header: {e}")));
            }
            Err(_) => {
                return Err(RouteSourceError::recoverable(format!(
                    "BMP read header exceeded {BMP_READ_TIMEOUT:?} (peer stalled)"
                )));
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
            match tokio::time::timeout(BMP_READ_TIMEOUT, stream.read_exact(&mut body_buf)).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    return Err(RouteSourceError::recoverable(format!("read body: {e}")));
                }
                Err(_) => {
                    return Err(RouteSourceError::recoverable(format!(
                        "BMP read body exceeded {BMP_READ_TIMEOUT:?} (peer stalled mid-frame)"
                    )));
                }
            }
        }

        // Reconstruct the full frame. `parse_bmp_msg` expects the
        // header bytes at the front of the buffer, it re-reads
        // them to validate the version / type.
        let mut full = Vec::with_capacity(msg_len);
        full.extend_from_slice(&header_buf);
        full.extend_from_slice(&body_buf);
        let mut bytes = Bytes::from(full);

        match parse_bmp_msg(&mut bytes) {
            Ok(msg) => {
                frames_parsed += 1;
                if tx.send(msg).await.is_err() {
                    // Main loop dropped the receiver, shutdown.
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
/// identify one peer, two BGP sessions to the same peer IP that
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

/// Whether `addr` is permitted by the listener's `peer_acl`. Empty
/// ACL means "loopback only", the config parser already enforces
/// that empty + non-loopback listen is rejected, so an empty ACL
/// implies loopback bind. The defensive `is_loopback()` check covers
/// a misconstructed in-process config.
fn source_ip_permitted(addr: IpAddr, peer_acl: &[ipnet::IpNet]) -> bool {
    if peer_acl.is_empty() {
        addr.is_loopback()
    } else {
        peer_acl.iter().any(|net| net.contains(&addr))
    }
}

/// Bind a `TcpListener` with `SO_REUSEADDR` enabled (v0.2.2 fix). See
/// the `bind_with_reuseaddr` doc in `route_source_bgp.rs` for the
/// rationale, same problem class on both listeners.
fn bind_with_reuseaddr(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(8)
}
