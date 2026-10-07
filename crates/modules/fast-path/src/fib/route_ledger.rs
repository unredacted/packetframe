//! The fast-path route ledger: the route mirror a clean stop leaves for
//! the next start, and every check that start runs before it seeds the
//! mirror from it.
//!
//! **Why this exists.** Every start used to reload the mirror from the
//! route source, and on a full-table gateway fed by FRR that reload is
//! paced by bgpd, not by this daemon: ~2,000 routes/s, ~11 minutes for
//! 1.35M routes (measured 2026-10-07: session up at T, 496k routes at
//! T+4 min). For those minutes the eBPF tier forwards on a partial FIB,
//! the completeness authority vetoes, and an unsteered second tier cannot
//! take its first steer. The previous process held the whole table a
//! moment before it exited; this is it telling the next one. vpp-offload
//! solved the same problem for VPP's FIB with
//! `packetframe_vpp_offload::ledger_record`, and this file follows its
//! discipline leg for leg.
//!
//! **What is in it.** Only advertisements from the route source — the
//! BGP listener's peer or the BMP station's peers — each with exactly
//! what rebuilds it: prefix, peer id, path id, nexthops, local-pref.
//! NOT the neighbour resolver's synthetic [`PeerId::local_arp`]
//! advertisements (`fallback-default`, `local-prefix`): the resolver
//! re-injects those at every start from the live kernel state, which is
//! fresher than anything a file can hold. Plus: the format version, the
//! writer's version, the wall-clock write time, the time the OLDEST
//! advertisement in it was last confirmed by a live session (see
//! [`LedgerMeta::confirmed_at_unix`]), the route-source identity, the
//! per-family counts, and a trailing checksum.
//!
//! **What makes it safe to seed from**, leg by leg — each a way the
//! record could describe a table that is not the one the route source
//! will send:
//!
//! - *Which route source.* The record carries the configured
//!   route-source identity
//!   ([`packetframe_common::config::RouteSourceSpec::ledger_identity`]);
//!   any difference refuses it. For BGP, every recorded peer id must also
//!   be the one this build's listener derives for that identity, so a
//!   change in the derivation cannot leave seeded advertisements under a
//!   key no live re-advertisement replaces.
//! - *How old.* The age that counts is since the oldest advertisement was
//!   last confirmed by a live session, not since the write: a stop while
//!   the route source was down (or before a seed was re-advertised)
//!   carries the older time forward, so stale routes cannot ride from
//!   ledger to ledger. Past `max-age` (default 30 min) it is refused; a
//!   write time in the future by more than [`CLOCK_SLACK`] is refused
//!   too, since then no age can be established.
//! - *Which mode.* Only `forwarding-mode packetframe-fib` seeds.
//!   `compare` exists to validate the PacketFrame FIB against the kernel's,
//!   and stale seeded routes would read as disagreements.
//! - *Intact.* A truncated, corrupt or other-version file is refused
//!   whole, never half-seeded; counts are checked against the routes
//!   actually read.
//! - *Used once.* The start removes the file the moment it reads it,
//!   whether or not it is used — a crash loop never re-seeds a stale one.
//!   A file that cannot be removed is refused. A crash, a `kill -9` or a
//!   breaker trip writes nothing, so a stale one is never what a start
//!   finds; `packetframe detach` (a full one) removes it, `detach
//!   --keep-vpp` (the routine restart) keeps it.
//!
//! **How a seed is used.** Every seeded advertisement goes in marked
//! `seen_this_session = false`, exactly as if a session had just been
//! lost (`RouteEvent::Resync`): the live session's re-advertisements mark
//! them seen, and its `InitiationComplete` garbage-collects whatever the
//! route source no longer has. That is the staleness trade-off the
//! programmer already makes on every session loss ("stale forwarding
//! while bird restarts beats an empty table"), with the age bound on top.
//!
//! **Format.** Compact binary, little-endian, one file: ~12 bytes per v4
//! route and ~24 per v6, peers and nexthops interned once, a trailing
//! FNV-1a checksum. Written with the hardened state-directory primitives
//! (component-wise no-follow walk, `O_EXCL|O_NOFOLLOW` temp file, fsync,
//! `renameat`).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use packetframe_common::config::{ForwardingMode, RouteLedgerSpec};
use packetframe_common::fib::{IpPrefix, PeerId};
use packetframe_common::module::{HealthState, SubsystemHealth};

/// The record's file name in `state-dir`.
pub const LEDGER_FILE_NAME: &str = "fast-path-route-ledger.bin";

/// Bump on any layout change. A record of another version is refused,
/// which costs one cold reload and nothing else.
pub const LEDGER_FORMAT_VERSION: u32 = 1;

const MAGIC: &[u8; 8] = b"PFFIBLGR";

/// How far in the future a write time may be before no age can be
/// established. Two hosts' clocks are not in play — the writer and the
/// reader are the same box — so this only has to absorb an NTP slew
/// across the restart.
pub const CLOCK_SLACK: Duration = Duration::from_secs(60);

/// How long a preserving stop waits for the programmer to snapshot the
/// mirror. The same five seconds vpp-offload gives its own ledger: long
/// enough for a 1.35M-route mirror several times over (see the PR's
/// measurement), short enough that a wedged programmer cannot hold a
/// `systemctl stop` hostage. Past it nothing is written, and the next
/// start loads cold.
pub const PRESERVE_BUDGET: Duration = Duration::from_secs(5);

/// Subsystem name on the health surface. Append-safe, rename-unsafe.
pub const SUBSYS_ROUTE_LEDGER: &str = "route-ledger";

/// Flag bits on one encoded advertisement.
const FLAG_PATH_ID: u8 = 1;
const FLAG_LOCAL_PREF: u8 = 1 << 1;
const FLAGS_KNOWN: u8 = FLAG_PATH_ID | FLAG_LOCAL_PREF;

/// What the record says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerMeta {
    /// The fast-path version that wrote it. Informational: the format
    /// version is what a reader checks.
    pub writer_version: String,
    /// Wall-clock seconds since the epoch at the write.
    pub written_at_unix: u64,
    /// Wall-clock seconds since the epoch at which the OLDEST
    /// advertisement in the record was last confirmed by a live route
    /// source session. Equal to `written_at_unix` when every
    /// advertisement had been (re-)advertised by the session that was up
    /// at the stop. Older when some had not: a stop while the route
    /// source was down carries the time it went down, and a stop before
    /// a seed was reconciled carries the seed's own confirmation time.
    /// The age check reads this, so a stale route cannot be carried
    /// from ledger to ledger by restarts that never reconcile it.
    pub confirmed_at_unix: u64,
    /// [`packetframe_common::config::RouteSourceSpec::ledger_identity`]
    /// of the route source the advertisements came from.
    pub identity: String,
}

/// Prefixes and advertisements in one family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FamilyCounts {
    pub prefixes: u32,
    pub advertisements: u32,
}

/// Per-family counts, recorded in the header and checked on read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LedgerCounts {
    pub v4: FamilyCounts,
    pub v6: FamilyCounts,
}

impl LedgerCounts {
    pub fn prefixes(&self) -> u64 {
        u64::from(self.v4.prefixes) + u64::from(self.v6.prefixes)
    }

    pub fn advertisements(&self) -> u64 {
        u64::from(self.v4.advertisements) + u64::from(self.v6.advertisements)
    }
}

/// One advertisement as the programmer holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerAdvert {
    pub peer: PeerId,
    pub path_id: Option<u32>,
    pub local_pref: Option<u32>,
    pub nexthops: Vec<IpAddr>,
}

/// One prefix and every route-source advertisement on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRoute {
    pub prefix: IpPrefix,
    pub adverts: Vec<LedgerAdvert>,
}

/// A borrowed advertisement, for encoding straight out of the mirror
/// without copying it first.
#[derive(Debug, Clone, Copy)]
pub struct AdvertRef<'a> {
    pub peer: PeerId,
    pub path_id: Option<u32>,
    pub local_pref: Option<u32>,
    pub nexthops: &'a [IpAddr],
}

/// Writes a record route by route. All v4 routes first, then all v6;
/// the counts given to [`Self::new`] must match what is written, and
/// [`Self::finish`] refuses otherwise rather than produce a record the
/// reader would refuse anyway.
pub struct LedgerEncoder {
    out: Vec<u8>,
    peer_idx: HashMap<PeerId, u32>,
    nh_idx: HashMap<IpAddr, u32>,
    declared: LedgerCounts,
    written: LedgerCounts,
    in_v6: bool,
}

impl LedgerEncoder {
    /// `peers` and `nexthops` must hold every peer and nexthop the routes
    /// will name: they are interned once, ahead of the routes.
    pub fn new(
        meta: &LedgerMeta,
        counts: LedgerCounts,
        peers: &[PeerId],
        nexthops: &[IpAddr],
    ) -> Self {
        let estimate = 128
            + peers.len() * 8
            + nexthops.len() * 17
            + counts.v4.prefixes as usize * 12
            + counts.v6.prefixes as usize * 24;
        let mut out = Vec::with_capacity(estimate);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&LEDGER_FORMAT_VERSION.to_le_bytes());
        put_str(&mut out, &meta.writer_version);
        out.extend_from_slice(&meta.written_at_unix.to_le_bytes());
        out.extend_from_slice(&meta.confirmed_at_unix.to_le_bytes());
        put_str(&mut out, &meta.identity);
        for c in [counts.v4, counts.v6] {
            out.extend_from_slice(&c.prefixes.to_le_bytes());
            out.extend_from_slice(&c.advertisements.to_le_bytes());
        }
        out.extend_from_slice(&(peers.len() as u32).to_le_bytes());
        let mut peer_idx = HashMap::with_capacity(peers.len());
        for (i, p) in peers.iter().enumerate() {
            out.extend_from_slice(&p.0.to_le_bytes());
            peer_idx.insert(*p, i as u32);
        }
        out.extend_from_slice(&(nexthops.len() as u32).to_le_bytes());
        let mut nh_idx = HashMap::with_capacity(nexthops.len());
        for (i, nh) in nexthops.iter().enumerate() {
            put_addr(&mut out, *nh);
            nh_idx.insert(*nh, i as u32);
        }
        Self {
            out,
            peer_idx,
            nh_idx,
            declared: counts,
            written: LedgerCounts::default(),
            in_v6: false,
        }
    }

    /// Append one prefix. `adverts` must be non-empty and every
    /// advertisement's nexthops non-empty — the programmer holds no
    /// other kind, and a record carrying one could not be seeded.
    pub fn route(&mut self, prefix: IpPrefix, adverts: &[AdvertRef<'_>]) -> Result<(), String> {
        if adverts.is_empty() {
            return Err(format!("{prefix:?}: no advertisements"));
        }
        let fam = match prefix {
            IpPrefix::V4 { addr, prefix_len } => {
                if self.in_v6 {
                    return Err("an IPv4 route after the IPv6 section began".into());
                }
                self.out.push(prefix_len);
                self.out.extend_from_slice(&addr);
                &mut self.written.v4
            }
            IpPrefix::V6 { addr, prefix_len } => {
                if !self.in_v6 {
                    if self.written.v4 != self.declared.v4 {
                        return Err(format!(
                            "the IPv4 section holds {:?}, not the declared {:?}",
                            self.written.v4, self.declared.v4
                        ));
                    }
                    self.in_v6 = true;
                }
                self.out.push(prefix_len);
                self.out.extend_from_slice(&addr);
                &mut self.written.v6
            }
        };
        fam.prefixes += 1;
        fam.advertisements += adverts.len() as u32;
        put_varint(&mut self.out, adverts.len() as u64);
        for a in adverts {
            if a.nexthops.is_empty() {
                return Err(format!("{prefix:?}: an advertisement with no nexthop"));
            }
            let peer = *self
                .peer_idx
                .get(&a.peer)
                .ok_or_else(|| format!("{prefix:?}: peer {:#x} not interned", a.peer.0))?;
            put_varint(&mut self.out, u64::from(peer));
            let mut flags = 0u8;
            if a.path_id.is_some() {
                flags |= FLAG_PATH_ID;
            }
            if a.local_pref.is_some() {
                flags |= FLAG_LOCAL_PREF;
            }
            self.out.push(flags);
            if let Some(p) = a.path_id {
                put_varint(&mut self.out, u64::from(p));
            }
            if let Some(lp) = a.local_pref {
                put_varint(&mut self.out, u64::from(lp));
            }
            put_varint(&mut self.out, a.nexthops.len() as u64);
            for nh in a.nexthops {
                let i = *self
                    .nh_idx
                    .get(nh)
                    .ok_or_else(|| format!("{prefix:?}: nexthop {nh} not interned"))?;
                put_varint(&mut self.out, u64::from(i));
            }
        }
        Ok(())
    }

    /// Close the record: counts checked, checksum appended.
    pub fn finish(mut self) -> Result<Vec<u8>, String> {
        if self.written != self.declared {
            return Err(format!(
                "wrote {:?} where the header declares {:?}",
                self.written, self.declared
            ));
        }
        let sum = fnv1a(&self.out);
        self.out.extend_from_slice(&sum.to_le_bytes());
        Ok(self.out)
    }
}

/// Encode a whole record from owned routes — the tests' path, and a
/// statement of the format in one place. The programmer encodes straight
/// out of its mirror with [`LedgerEncoder`] instead.
pub fn encode(meta: &LedgerMeta, routes: &[LedgerRoute]) -> Result<Vec<u8>, String> {
    let mut peers: Vec<PeerId> = Vec::new();
    let mut nexthops: Vec<IpAddr> = Vec::new();
    let mut seen_p = std::collections::HashSet::new();
    let mut seen_nh = std::collections::HashSet::new();
    let mut counts = LedgerCounts::default();
    for r in routes {
        let c = match r.prefix {
            IpPrefix::V4 { .. } => &mut counts.v4,
            IpPrefix::V6 { .. } => &mut counts.v6,
        };
        c.prefixes += 1;
        c.advertisements += r.adverts.len() as u32;
        for a in &r.adverts {
            if seen_p.insert(a.peer) {
                peers.push(a.peer);
            }
            for nh in &a.nexthops {
                if seen_nh.insert(*nh) {
                    nexthops.push(*nh);
                }
            }
        }
    }
    let mut enc = LedgerEncoder::new(meta, counts, &peers, &nexthops);
    let ordered = routes
        .iter()
        .filter(|r| matches!(r.prefix, IpPrefix::V4 { .. }))
        .chain(
            routes
                .iter()
                .filter(|r| matches!(r.prefix, IpPrefix::V6 { .. })),
        );
    for r in ordered {
        let refs: Vec<AdvertRef<'_>> = r
            .adverts
            .iter()
            .map(|a| AdvertRef {
                peer: a.peer,
                path_id: a.path_id,
                local_pref: a.local_pref,
                nexthops: &a.nexthops,
            })
            .collect();
        enc.route(r.prefix, &refs)?;
    }
    enc.finish()
}

/// A decoded, fully validated record. The routes stay in their encoded
/// form and are decoded again, one at a time, as they are seeded: a
/// 1.35M-route table materialised whole would cost hundreds of
/// megabytes for the few seconds the seed takes.
pub struct RouteLedger {
    pub meta: LedgerMeta,
    pub counts: LedgerCounts,
    peers: Vec<PeerId>,
    nexthops: Vec<IpAddr>,
    bytes: Vec<u8>,
    routes_at: usize,
    routes_end: usize,
}

// Hand-written so a debug print never dumps the encoded routes, which
// run to tens of megabytes at a full table.
impl std::fmt::Debug for RouteLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouteLedger")
            .field("meta", &self.meta)
            .field("counts", &self.counts)
            .field("peers", &self.peers.len())
            .field("nexthops", &self.nexthops.len())
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// Where a seed is in a [`RouteLedger`]. Separate from the ledger so a
/// holder can keep both in one struct and advance one while reading the
/// other.
#[derive(Debug, Clone, Copy)]
pub struct RouteCursor {
    at: usize,
    v4_left: u32,
    v6_left: u32,
}

impl RouteLedger {
    /// Parse and validate a record, refusing anything that is not
    /// exactly one intact record of this version: every route is walked
    /// once here, so a seed never discovers corruption halfway through.
    pub fn decode(bytes: Vec<u8>) -> Result<Self, Refusal> {
        let corrupt = |why: String| Refusal::Corrupt(why);
        if bytes.len() < MAGIC.len() + 4 + 8 {
            return Err(corrupt("the file is too short to be a record".into()));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(corrupt("the file is not a fast-path route ledger".into()));
        }
        let body_len = bytes.len() - 8;
        let mut r = Reader {
            buf: &bytes[..body_len],
            at: MAGIC.len(),
        };
        let version = r.u32().map_err(corrupt)?;
        if version != LEDGER_FORMAT_VERSION {
            return Err(Refusal::FormatVersion { found: version });
        }
        // After the version, so a future layout is named as such rather
        // than as corruption.
        let sum = u64::from_le_bytes(bytes[body_len..].try_into().expect("8 bytes"));
        if fnv1a(&bytes[..body_len]) != sum {
            return Err(corrupt(
                "its checksum does not match — truncated or corrupted since it was written".into(),
            ));
        }
        let parsed = (|| -> Result<_, String> {
            let writer_version = r.string()?;
            let written_at_unix = r.u64()?;
            let confirmed_at_unix = r.u64()?;
            let identity = r.string()?;
            let mut counts = LedgerCounts::default();
            for c in [&mut counts.v4, &mut counts.v6] {
                c.prefixes = r.u32()?;
                c.advertisements = r.u32()?;
            }
            let n = r.count(8)?;
            let mut peers = Vec::with_capacity(n);
            for _ in 0..n {
                let p = PeerId(r.u64()?);
                if p.as_local_arp_ifindex().is_some() {
                    return Err(format!(
                        "it names peer {:#x}, a neighbour-resolver id, which a ledger never \
                         records",
                        p.0
                    ));
                }
                peers.push(p);
            }
            let n = r.count(5)?;
            let mut nexthops = Vec::with_capacity(n);
            for _ in 0..n {
                nexthops.push(r.addr()?);
            }
            Ok((
                LedgerMeta {
                    writer_version,
                    written_at_unix,
                    confirmed_at_unix,
                    identity,
                },
                counts,
                peers,
                nexthops,
            ))
        })();
        let (meta, counts, peers, nexthops) = parsed.map_err(corrupt)?;
        let routes_at = r.at;
        let mut ledger = Self {
            meta,
            counts,
            peers,
            nexthops,
            bytes: Vec::new(),
            routes_at,
            routes_end: body_len,
        };
        // The walk: every route read and checked, the counts compared.
        let mut cursor = ledger.cursor();
        let mut seen = LedgerCounts::default();
        {
            let mut r = Reader {
                buf: &bytes[..body_len],
                at: routes_at,
            };
            while cursor.v4_left > 0 || cursor.v6_left > 0 {
                let v4 = cursor.v4_left > 0;
                let route =
                    read_route(&mut r, v4, &ledger.peers, &ledger.nexthops).map_err(corrupt)?;
                let c = if v4 {
                    cursor.v4_left -= 1;
                    &mut seen.v4
                } else {
                    cursor.v6_left -= 1;
                    &mut seen.v6
                };
                c.prefixes += 1;
                c.advertisements += route.adverts.len() as u32;
            }
            if r.remaining() != 0 {
                return Err(corrupt("trailing bytes after the last route".into()));
            }
        }
        if seen != ledger.counts {
            return Err(corrupt(format!(
                "it holds {seen:?} where its header declares {:?}",
                ledger.counts
            )));
        }
        ledger.bytes = bytes;
        Ok(ledger)
    }

    /// Every distinct peer the record names.
    pub fn peers(&self) -> &[PeerId] {
        &self.peers
    }

    /// A cursor at the first route.
    pub fn cursor(&self) -> RouteCursor {
        RouteCursor {
            at: self.routes_at,
            v4_left: self.counts.v4.prefixes,
            v6_left: self.counts.v6.prefixes,
        }
    }

    /// The route at `cursor`, advancing it; `None` past the last. The
    /// record was walked whole by [`Self::decode`], so a read cannot
    /// fail here — and if it somehow did, the seed stops rather than
    /// guess.
    pub fn next_route(&self, cursor: &mut RouteCursor) -> Option<LedgerRoute> {
        let v4 = if cursor.v4_left > 0 {
            true
        } else if cursor.v6_left > 0 {
            false
        } else {
            return None;
        };
        let mut r = Reader {
            buf: &self.bytes[..self.routes_end],
            at: cursor.at,
        };
        let route = read_route(&mut r, v4, &self.peers, &self.nexthops).ok()?;
        cursor.at = r.at;
        if v4 {
            cursor.v4_left -= 1;
        } else {
            cursor.v6_left -= 1;
        }
        Some(route)
    }

    /// Every route, in record order.
    pub fn routes(&self) -> impl Iterator<Item = LedgerRoute> + '_ {
        let mut cursor = self.cursor();
        std::iter::from_fn(move || self.next_route(&mut cursor))
    }

    /// Bytes the record occupies on disk.
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }
}

fn read_route(
    r: &mut Reader<'_>,
    v4: bool,
    peers: &[PeerId],
    nexthops: &[IpAddr],
) -> Result<LedgerRoute, String> {
    let prefix_len = r.u8()?;
    let prefix = if v4 {
        if prefix_len > 32 {
            return Err(format!("an IPv4 route with length /{prefix_len}"));
        }
        IpPrefix::V4 {
            addr: r.bytes::<4>()?,
            prefix_len,
        }
    } else {
        if prefix_len > 128 {
            return Err(format!("an IPv6 route with length /{prefix_len}"));
        }
        IpPrefix::V6 {
            addr: r.bytes::<16>()?,
            prefix_len,
        }
    };
    // Each advertisement is at least 3 bytes (peer, flags, nexthop count)
    // plus one nexthop index, so a corrupt count cannot ask for more than
    // the record could hold.
    let n = r.varint_count(4)?;
    if n == 0 {
        return Err(format!("{prefix:?} with no advertisements"));
    }
    let mut adverts = Vec::with_capacity(n);
    for _ in 0..n {
        let peer = r.varint()? as usize;
        let peer = *peers
            .get(peer)
            .ok_or_else(|| format!("{prefix:?} names peer {peer} of {}", peers.len()))?;
        let flags = r.u8()?;
        if flags & !FLAGS_KNOWN != 0 {
            return Err(format!(
                "{prefix:?}: unknown advertisement flags {flags:#x}"
            ));
        }
        let path_id = if flags & FLAG_PATH_ID != 0 {
            Some(r.varint_u32()?)
        } else {
            None
        };
        let local_pref = if flags & FLAG_LOCAL_PREF != 0 {
            Some(r.varint_u32()?)
        } else {
            None
        };
        let m = r.varint_count(1)?;
        if m == 0 {
            return Err(format!("{prefix:?}: an advertisement with no nexthop"));
        }
        let mut nhs = Vec::with_capacity(m);
        for _ in 0..m {
            let i = r.varint()? as usize;
            nhs.push(
                *nexthops
                    .get(i)
                    .ok_or_else(|| format!("{prefix:?} names nexthop {i} of {}", nexthops.len()))?,
            );
        }
        adverts.push(LedgerAdvert {
            peer,
            path_id,
            local_pref,
            nexthops: nhs,
        });
    }
    Ok(LedgerRoute { prefix, adverts })
}

// --- Refusal, and the start's decision ---------------------------------

/// Why a start did not seed. Every one of these is a cold reload from
/// the route source — what every start did before the ledger existed —
/// and none fails the attach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// No ledger in `state-dir`: the previous stop was not a clean
    /// preserving exit, or wrote nothing, or was an older build, or a
    /// full `packetframe detach` ran since.
    Missing,
    /// `route-ledger off`, and a ledger from an earlier run was there.
    Disabled,
    /// The forwarding mode is not `packetframe-fib`.
    ForwardingMode(ForwardingMode),
    /// No `route-source` is configured, so no live session could ever
    /// reconcile a seed.
    NoRouteSource,
    /// There was something there and it could not be read (I/O error,
    /// a planted symlink). It is removed too.
    Unreadable(String),
    /// It was read but could not be removed, so it cannot be consumed
    /// once — the next start could read it again after this one has
    /// changed the mirror.
    Unremovable(String),
    /// Truncated, corrupted, or structurally wrong.
    Corrupt(String),
    /// Another format version.
    FormatVersion { found: u32 },
    /// Written for a different route source.
    Identity {
        recorded: String,
        configured: String,
    },
    /// Its oldest advertisement was last confirmed longer ago than
    /// `max-age`.
    TooOld { age_secs: u64, max_age_secs: u64 },
    /// Confirmed or written in the future: the clock moved, and no age
    /// can be established.
    Clock { ahead_secs: u64 },
    /// A BGP ledger names a peer id this build's listener would not use
    /// for this route source.
    PeerId { recorded: u64, expected: u64 },
}

impl Refusal {
    /// Stable code for the event log's `reason` field. Append-only.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Missing => "missing",
            Refusal::Disabled => "disabled",
            Refusal::ForwardingMode(_) => "forwarding-mode",
            Refusal::NoRouteSource => "no-route-source",
            Refusal::Unreadable(_) => "unreadable",
            Refusal::Unremovable(_) => "unremovable",
            Refusal::Corrupt(_) => "corrupt",
            Refusal::FormatVersion { .. } => "format-version",
            Refusal::Identity { .. } => "identity",
            Refusal::TooOld { .. } => "too-old",
            Refusal::Clock { .. } => "clock",
            Refusal::PeerId { .. } => "peer-id",
        }
    }

    /// Whether this is worth a warning, as opposed to an expected
    /// outcome an operator chose or a restart produced.
    pub fn is_warning(&self) -> bool {
        !matches!(
            self,
            Refusal::Missing
                | Refusal::Disabled
                | Refusal::ForwardingMode(_)
                | Refusal::NoRouteSource
                | Refusal::TooOld { .. }
        )
    }

    pub fn describe(&self) -> String {
        match self {
            Refusal::Missing => "no route ledger in state-dir (the previous stop was not a clean \
                                 `systemctl stop`, preserved nothing, predates the ledger, or a \
                                 full `packetframe detach` ran since)"
                .into(),
            Refusal::Disabled => {
                "`route-ledger off`; a ledger an earlier run left was removed unused".into()
            }
            Refusal::ForwardingMode(m) => format!(
                "forwarding-mode is {}, and only packetframe-fib seeds from a ledger \
                 (compare mode validates the PacketFrame FIB against the kernel's, and stale \
                 seeded routes would read as disagreements)",
                mode_name(*m)
            ),
            Refusal::NoRouteSource => {
                "no `route-source` is configured, so nothing could ever reconcile a seed".into()
            }
            Refusal::Unreadable(e) => format!("it could not be read ({e}); removed"),
            Refusal::Unremovable(e) => format!(
                "it could not be removed after reading ({e}), so it cannot be consumed once — \
                 remove {LEDGER_FILE_NAME} from state-dir by hand"
            ),
            Refusal::Corrupt(e) => format!("it is not an intact record: {e}"),
            Refusal::FormatVersion { found } => format!(
                "it is format version {found} and this binary reads {LEDGER_FORMAT_VERSION}"
            ),
            Refusal::Identity {
                recorded,
                configured,
            } => format!(
                "it was written for route source `{recorded}` and this config's is \
                 `{configured}`"
            ),
            Refusal::TooOld {
                age_secs,
                max_age_secs,
            } => format!(
                "its oldest routes were last confirmed by the route source {} ago, past \
                 `route-ledger max-age` ({})",
                human_secs(*age_secs),
                human_secs(*max_age_secs)
            ),
            Refusal::Clock { ahead_secs } => format!(
                "it claims to have been confirmed {} in the future — the clock moved across \
                 the restart, so its age cannot be established",
                human_secs(*ahead_secs)
            ),
            Refusal::PeerId { recorded, expected } => format!(
                "it records advertisements under peer id {recorded:#x} and this build's BGP \
                 listener uses {expected:#x} for the same route source; seeded routes would \
                 never be replaced by the live session's"
            ),
        }
    }
}

fn mode_name(m: ForwardingMode) -> &'static str {
    match m {
        ForwardingMode::KernelFib => "kernel-fib",
        ForwardingMode::PacketframeFib => "packetframe-fib",
        ForwardingMode::Compare => "compare",
    }
}

/// What a start checks a ledger against.
#[derive(Debug, Clone)]
pub struct Expectations<'a> {
    pub spec: RouteLedgerSpec,
    pub forwarding_mode: ForwardingMode,
    /// The configured route source's identity; `None` with no
    /// `route-source`.
    pub identity: Option<&'a str>,
    /// For a BGP source, the one peer id its listener uses. `None` for
    /// BMP, whose peer ids are per-peer and only known once the stream
    /// names them.
    pub single_peer: Option<PeerId>,
    pub now_unix: u64,
}

/// What a start did with the ledger.
#[derive(Debug)]
pub enum Consumed {
    /// Nothing to report: no file, and nothing here would have used one
    /// (`route-ledger off`, or a mode that never seeds). Logged at debug.
    Quiet,
    /// Not used, and why. Logged, and recorded in the event log.
    Refused(Refusal),
    /// Checked; seed the mirror from it.
    Seed(RouteLedger),
}

/// Consume whatever ledger `state_dir` holds and judge it.
///
/// Consumption is unconditional — read, then removed, whatever it holds
/// — because from the moment this start runs, the mirror will move on
/// from what the record describes.
pub fn consume(state_dir: &Path, exp: &Expectations<'_>) -> Consumed {
    let path = path_in(state_dir);
    let read = read_record(&path);
    let bytes = match read {
        Ok(None) => {
            return if !exp.spec.enabled || exp.forwarding_mode != ForwardingMode::PacketframeFib {
                Consumed::Quiet
            } else {
                Consumed::Refused(Refusal::Missing)
            };
        }
        Ok(Some(b)) => Ok(b),
        Err(e) => Err(format!("{}: {e}", path.display())),
    };
    // `unlinkat` removes a planted symlink itself, never its target.
    if let Err(e) = remove(state_dir) {
        return Consumed::Refused(Refusal::Unremovable(e));
    }
    let bytes = match bytes {
        Ok(b) => b,
        Err(e) => return Consumed::Refused(Refusal::Unreadable(e)),
    };
    match judge(bytes, exp) {
        Ok(ledger) => Consumed::Seed(ledger),
        Err(r) => Consumed::Refused(r),
    }
}

/// Every check after the file is consumed, as a pure function of its
/// bytes.
pub fn judge(bytes: Vec<u8>, exp: &Expectations<'_>) -> Result<RouteLedger, Refusal> {
    if !exp.spec.enabled {
        return Err(Refusal::Disabled);
    }
    if exp.forwarding_mode != ForwardingMode::PacketframeFib {
        return Err(Refusal::ForwardingMode(exp.forwarding_mode));
    }
    let Some(identity) = exp.identity else {
        return Err(Refusal::NoRouteSource);
    };
    let ledger = RouteLedger::decode(bytes)?;
    if ledger.counts.prefixes() == 0 {
        // Intact, but no stop writes one: a mirror with nothing to
        // preserve preserves nothing.
        return Err(Refusal::Corrupt(
            "it holds no routes, which no preserving stop writes".into(),
        ));
    }
    if ledger.meta.identity != identity {
        return Err(Refusal::Identity {
            recorded: ledger.meta.identity.clone(),
            configured: identity.to_string(),
        });
    }
    // The newer of the two times is the write; either in the future
    // means the clock moved.
    let newest = ledger
        .meta
        .written_at_unix
        .max(ledger.meta.confirmed_at_unix);
    if newest > exp.now_unix.saturating_add(CLOCK_SLACK.as_secs()) {
        return Err(Refusal::Clock {
            ahead_secs: newest - exp.now_unix,
        });
    }
    let age_secs = exp.now_unix.saturating_sub(
        ledger
            .meta
            .confirmed_at_unix
            .min(ledger.meta.written_at_unix),
    );
    if age_secs > exp.spec.max_age_secs {
        return Err(Refusal::TooOld {
            age_secs,
            max_age_secs: exp.spec.max_age_secs,
        });
    }
    if let Some(expected) = exp.single_peer {
        if let Some(other) = ledger.peers().iter().find(|p| **p != expected) {
            return Err(Refusal::PeerId {
                recorded: other.0,
                expected: expected.0,
            });
        }
    }
    Ok(ledger)
}

// --- Files -----------------------------------------------------------------

pub fn path_in(state_dir: &Path) -> PathBuf {
    state_dir.join(LEDGER_FILE_NAME)
}

/// Write a record atomically into `state_dir`, through the no-follow
/// primitives: temp file `O_EXCL|O_NOFOLLOW`, fsync, `renameat` within
/// the walked directory. A symlink planted at the record, at its `.tmp`,
/// or at any component of the directory is refused or replaced, never
/// written through.
pub fn write(state_dir: &Path, bytes: &[u8]) -> Result<(), String> {
    let path = path_in(state_dir);
    write_record(&path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

/// Remove the record if there is one. `packetframe detach` (a full one)
/// calls this; so does every start, through [`consume`].
pub fn remove(state_dir: &Path) -> Result<(), String> {
    let path = path_in(state_dir);
    match remove_record(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

// The state-dir primitives are Linux-only (they are `openat` walks); the
// dev-laptop build gets plain `std::fs`, the same split vpp-offload's
// ledger and fast-path's coalescing record make. Nothing privileged runs
// off Linux.
#[cfg(target_os = "linux")]
fn write_record(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    packetframe_common::statefile::write_atomic(path, contents)
}

#[cfg(not(target_os = "linux"))]
fn write_record(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("bin.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(target_os = "linux")]
fn read_record(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    packetframe_common::statefile::read_no_follow(path)
}

#[cfg(not(target_os = "linux"))]
fn read_record(path: &Path) -> std::io::Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(r) => Ok(Some(r)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(target_os = "linux")]
fn remove_record(path: &Path) -> std::io::Result<()> {
    packetframe_common::statefile::remove_state_record(path)
}

#[cfg(not(target_os = "linux"))]
fn remove_record(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

/// Seconds since the epoch, now.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// --- What the daemon reports about it --------------------------------------

/// What this daemon's start did with the ledger, and how the seed has
/// fared since. Shared between the attach that decided, the programmer
/// that applies and reconciles the seed, the completeness authorities
/// that must not attest a seed no session has spoken to, and the health
/// and metrics surfaces.
pub type SharedLedgerStatus = Arc<Mutex<LedgerStatus>>;

pub fn shared_status() -> SharedLedgerStatus {
    Arc::new(Mutex::new(LedgerStatus::default()))
}

#[derive(Debug, Clone, Default)]
pub struct LedgerStatus {
    pub start: StartReport,
    /// Set when the start accepted a ledger.
    pub seed: Option<SeedReport>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StartReport {
    /// Before attach decided.
    #[default]
    NotChecked,
    /// `route-ledger off`.
    Off,
    /// Not used; `code` and `detail` as in the event log.
    Refused { code: &'static str, detail: String },
    /// Accepted; see [`LedgerStatus::seed`].
    Seeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedReport {
    pub writer_version: String,
    pub written_at_unix: u64,
    pub confirmed_at_unix: u64,
    pub counts: LedgerCounts,
    /// When the programmer finished applying it; `None` while it is.
    pub applied_at: Option<Instant>,
    pub apply_took: Option<Duration>,
    /// Prefixes whose FIB entry could not be written (capacity, map
    /// errors). They stay in the mirror like any failed install.
    pub failed: u64,
    /// Seeded advertisements the route source has not re-advertised yet.
    /// Falls as the live session replays its table; whatever is left at
    /// its `InitiationComplete` is garbage-collected.
    pub unconfirmed: u64,
    /// When the first route-source advertisement or withdrawal reached
    /// the mirror after the seed: the live session has started speaking.
    /// Set at the first `InitiationComplete` after the seed if nothing
    /// set it earlier — a session whose only UPDATE is an empty
    /// End-of-RIB has spoken too, with an empty table.
    pub stream_started_at: Option<Instant>,
    /// When the first `InitiationComplete` after the seed GC'd the rest,
    /// and how many advertisements that removed.
    pub reconciled: Option<(Instant, u64)>,
}

impl SeedReport {
    /// Whether a live session has spoken to the seed: its first route
    /// arrived, or its `InitiationComplete` reconciled the seed without
    /// one (see [`LedgerStatus::attestation_blocker`]).
    pub fn spoken_for(&self) -> bool {
        self.stream_started_at.is_some() || self.reconciled.is_some()
    }
}

impl LedgerStatus {
    /// Why a completeness authority must not attest this mirror yet, or
    /// `None` if nothing about the seed stands in its way.
    ///
    /// A seeded mirror matches the route source's count from the first
    /// second — that is the point of it — so a count comparison alone
    /// would attest it before any session had spoken to this daemon: a
    /// listener that never came up, an FRR that no longer peers with it,
    /// and the second tier would steer onto a table nothing will ever
    /// update. Once the live session has delivered its first route, the
    /// comparison means what it always meant (count agreement within the
    /// drift bound), and the replay corrects the rest as it arrives.
    ///
    /// A reconciled seed blocks nothing either, whether or not a route
    /// arrived first: an `InitiationComplete` is a live session's whole
    /// table having been delivered, and a session whose only UPDATE was an
    /// empty End-of-RIB (or a BMP stream whose route monitoring carried no
    /// route) reaches it without one. Its GC has removed every seeded
    /// route the session did not confirm, so nothing of the seed is left
    /// unspoken for.
    pub fn attestation_blocker(&self) -> Option<String> {
        let seed = self.seed.as_ref()?;
        if seed.spoken_for() {
            return None;
        }
        Some(if seed.applied_at.is_none() {
            "the route mirror is being seeded from the route ledger and the route source has \
             not started streaming to this daemon yet"
                .into()
        } else {
            "the route mirror was seeded from the route ledger and the route source has not \
             started streaming to this daemon yet; a seed no live session has spoken to is not \
             attested"
                .into()
        })
    }

    /// Whether a seed is waiting for the live session's first route —
    /// the moment a completeness check becomes worth running early.
    pub fn awaiting_stream(&self) -> bool {
        self.seed.as_ref().is_some_and(|s| !s.spoken_for())
    }

    /// Whether a seed exists whose first post-stream check is still
    /// owed: the stream has started, so an authority may check now
    /// rather than at its next interval.
    pub fn stream_started(&self) -> bool {
        self.seed.as_ref().is_some_and(SeedReport::spoken_for)
    }

    /// The `route-ledger` health row. Healthy unless the ledger itself
    /// is in trouble — a refusal is a cold load, which is what every
    /// start used to be, not a fault — with two exceptions: a file that
    /// could not be consumed (it could seed a later start after this one
    /// moved on), and a seed whose installs failed.
    pub fn subsystem_health(&self, now_unix: u64, now: Instant) -> SubsystemHealth {
        let (state, message) = match (&self.start, &self.seed) {
            (StartReport::NotChecked, _) => (HealthState::Healthy, "not checked yet".to_string()),
            (StartReport::Off, _) => (
                HealthState::Healthy,
                "off (`route-ledger off`): every start loads the mirror from the route source"
                    .to_string(),
            ),
            (StartReport::Refused { code, detail }, _) => (
                if *code == "unremovable" {
                    HealthState::Degraded
                } else {
                    HealthState::Healthy
                },
                format!("not used at this start ({code}): {detail}; the mirror loaded cold"),
            ),
            (StartReport::Seeded, None) => (HealthState::Healthy, "seeded".to_string()),
            (StartReport::Seeded, Some(s)) => {
                let written = human_secs(now_unix.saturating_sub(s.written_at_unix));
                let mut m = format!(
                    "seeded {} IPv4 + {} IPv6 routes from a ledger written {written} ago",
                    s.counts.v4.prefixes, s.counts.v6.prefixes
                );
                if s.confirmed_at_unix < s.written_at_unix {
                    m.push_str(&format!(
                        " (oldest routes last confirmed {} ago)",
                        human_secs(now_unix.saturating_sub(s.confirmed_at_unix))
                    ));
                }
                match (s.applied_at, s.stream_started_at, s.reconciled) {
                    (None, _, _) => m.push_str("; applying"),
                    (Some(_), _, Some((at, removed))) => m.push_str(&format!(
                        "; reconciled {} ago — the route source's dump re-advertised the rest \
                         and the GC removed {removed} it no longer has",
                        human_secs(now.saturating_duration_since(at).as_secs())
                    )),
                    (Some(_), None, None) => m.push_str(
                        "; waiting for the route source's first route — forwarding on the seed, \
                         not attested to a second tier until then",
                    ),
                    (Some(_), Some(_), None) => m.push_str(&format!(
                        "; the route source is replaying: {} seeded advertisements not yet \
                         re-advertised (removed at its InitiationComplete if never)",
                        s.unconfirmed
                    )),
                }
                if s.failed > 0 {
                    m.push_str(&format!(
                        "; {} seeded prefixes could not be installed",
                        s.failed
                    ));
                }
                (
                    if s.failed > 0 {
                        HealthState::Degraded
                    } else {
                        HealthState::Healthy
                    },
                    m,
                )
            }
        };
        SubsystemHealth {
            name: SUBSYS_ROUTE_LEDGER.to_string(),
            state,
            message: Some(message),
            last_success_age_seconds: None,
        }
    }

    /// Textfile gauges.
    pub fn render_metrics(&self, out: &mut String) {
        use std::fmt::Write as _;
        let (v4, v6, unconfirmed) = self.seed.as_ref().map_or((0, 0, 0), |s| {
            (s.counts.v4.prefixes, s.counts.v6.prefixes, s.unconfirmed)
        });
        let _ = writeln!(
            out,
            "# HELP packetframe_fib_route_ledger_seeded_routes Prefixes this start seeded into \
             the route mirror from the route ledger (0: no seed)"
        );
        let _ = writeln!(
            out,
            "# TYPE packetframe_fib_route_ledger_seeded_routes gauge"
        );
        let _ = writeln!(
            out,
            "packetframe_fib_route_ledger_seeded_routes{{module=\"fast-path\",family=\"ipv4\"}} {v4}"
        );
        let _ = writeln!(
            out,
            "packetframe_fib_route_ledger_seeded_routes{{module=\"fast-path\",family=\"ipv6\"}} {v6}"
        );
        let _ = writeln!(
            out,
            "# HELP packetframe_fib_route_ledger_unconfirmed Seeded advertisements the route \
             source has not re-advertised yet; 0 once its first dump reconciles the seed"
        );
        let _ = writeln!(out, "# TYPE packetframe_fib_route_ledger_unconfirmed gauge");
        let _ = writeln!(
            out,
            "packetframe_fib_route_ledger_unconfirmed{{module=\"fast-path\"}} {unconfirmed}"
        );
    }
}

/// [`LedgerStatus::attestation_blocker`] through an optional handle — the
/// form both completeness authorities hold it in.
pub fn blocker(status: Option<&SharedLedgerStatus>) -> Option<String> {
    status?
        .lock()
        .expect("ledger status lock")
        .attestation_blocker()
}

/// Whether an authority's next check should run as soon as the route
/// source starts streaming rather than at its interval: a seed is
/// waiting for its first route, or the last check was withheld because
/// of one. The interval exists to keep a converged box cheap; a seeded
/// one's first attestable moment is the reason a second tier is waiting.
pub fn early_check_due(status: Option<&SharedLedgerStatus>, blocked_last: bool) -> bool {
    status.is_some_and(|s| blocked_last || s.lock().expect("ledger status lock").awaiting_stream())
}

/// How often [`stream_started`] looks.
#[cfg(target_os = "linux")]
const STREAM_POLL: Duration = Duration::from_millis(500);

/// Resolves once the route source has delivered its first route after a
/// seed — at once if it already has. Never resolves without a seed or a
/// status handle; callers race it against their interval.
#[cfg(target_os = "linux")]
pub async fn stream_started(status: Option<SharedLedgerStatus>) {
    let Some(status) = status else {
        return std::future::pending().await;
    };
    loop {
        if status.lock().expect("ledger status lock").stream_started() {
            return;
        }
        tokio::time::sleep(STREAM_POLL).await;
    }
}

/// `90` → `1m30s`, for operator-facing text.
pub fn human_secs(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m{:02}s", secs / 60, secs % 60),
        _ => format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60),
    }
}

// --- Encoding primitives ---------------------------------------------------

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    // Versions and identities are tens of bytes. Truncation past the
    // field's limit can only fail the identity check, the safe direction.
    let bytes = &s.as_bytes()[..s.len().min(u16::MAX as usize)];
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn put_addr(out: &mut Vec<u8>, a: IpAddr) {
    match a {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Unsigned LEB128.
fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }

    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        if self.remaining() < n {
            return Err("the record ends mid-field".into());
        }
        let s = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], String> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.bytes::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.bytes()?))
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.bytes()?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err("a varint runs past 64 bits".into())
    }

    fn varint_u32(&mut self) -> Result<u32, String> {
        let v = self.varint()?;
        u32::try_from(v).map_err(|_| format!("{v} does not fit 32 bits"))
    }

    /// A u32 count of items at least `min_item` bytes each, refused when
    /// the rest of the record could not hold that many — so a corrupt
    /// count cannot ask for a multi-gigabyte allocation.
    fn count(&mut self, min_item: usize) -> Result<usize, String> {
        let n = self.u32()? as usize;
        self.fits(n, min_item)
    }

    /// The varint form of [`Self::count`].
    fn varint_count(&mut self, min_item: usize) -> Result<usize, String> {
        let n = usize::try_from(self.varint()?).map_err(|_| "a count overflows".to_string())?;
        self.fits(n, min_item)
    }

    fn fits(&self, n: usize, min_item: usize) -> Result<usize, String> {
        if n.saturating_mul(min_item) > self.remaining() {
            return Err(format!(
                "it claims {n} items where {} bytes remain",
                self.remaining()
            ));
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, String> {
        let n = self.u16()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "a string is not UTF-8".into())
    }

    fn addr(&mut self) -> Result<IpAddr, String> {
        match self.u8()? {
            4 => Ok(IpAddr::V4(self.bytes::<4>()?.into())),
            6 => Ok(IpAddr::V6(self.bytes::<16>()?.into())),
            f => Err(format!("a nexthop names address family {f}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const IDENTITY: &str = "bgp listen 192.0.2.1 port 179 local-as 64512 peer-as 64512 peer-ip any";
    const PEER: PeerId = PeerId(0x5eed_0000_0000_0001);
    const NOW: u64 = 1_790_000_000;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pf-fp-ledger-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn v4nh(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, d))
    }

    fn v6nh(d: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, d))
    }

    fn meta() -> LedgerMeta {
        LedgerMeta {
            writer_version: "0.6.0".into(),
            written_at_unix: NOW - 120,
            confirmed_at_unix: NOW - 120,
            identity: IDENTITY.into(),
        }
    }

    fn advert(nh: IpAddr) -> LedgerAdvert {
        LedgerAdvert {
            peer: PEER,
            path_id: None,
            local_pref: Some(100),
            nexthops: vec![nh],
        }
    }

    /// Every shape the programmer can hold: plain, ADD-PATH, no
    /// local-pref, multi-nexthop, multi-peer, v6 with a v4 nexthop
    /// (RFC 8950), a default route, host routes, and an address with
    /// host bits set beyond its length (kept exactly, because the mirror
    /// keys on the address as the source sent it).
    fn routes() -> Vec<LedgerRoute> {
        vec![
            LedgerRoute {
                prefix: IpPrefix::V4 {
                    addr: [203, 0, 113, 0],
                    prefix_len: 24,
                },
                adverts: vec![advert(v4nh(1))],
            },
            LedgerRoute {
                prefix: IpPrefix::V4 {
                    addr: [0, 0, 0, 0],
                    prefix_len: 0,
                },
                adverts: vec![
                    LedgerAdvert {
                        peer: PEER,
                        path_id: Some(1),
                        local_pref: Some(150),
                        nexthops: vec![v4nh(1)],
                    },
                    LedgerAdvert {
                        peer: PEER,
                        path_id: Some(70_000),
                        local_pref: None,
                        nexthops: vec![v4nh(2), v4nh(3)],
                    },
                ],
            },
            LedgerRoute {
                prefix: IpPrefix::V4 {
                    addr: [192, 0, 2, 77],
                    prefix_len: 30,
                },
                adverts: vec![LedgerAdvert {
                    peer: PeerId(0x7777),
                    path_id: None,
                    local_pref: None,
                    nexthops: vec![v4nh(9)],
                }],
            },
            LedgerRoute {
                prefix: IpPrefix::V6 {
                    addr: Ipv6Addr::new(0x2001, 0xdb8, 0x10, 0, 0, 0, 0, 0).octets(),
                    prefix_len: 48,
                },
                adverts: vec![advert(v6nh(1))],
            },
            LedgerRoute {
                prefix: IpPrefix::V6 {
                    addr: Ipv6Addr::new(0x2001, 0xdb8, 0x20, 0, 0, 0, 0, 5).octets(),
                    prefix_len: 128,
                },
                adverts: vec![advert(v4nh(1))],
            },
        ]
    }

    fn expect() -> Expectations<'static> {
        Expectations {
            spec: RouteLedgerSpec::default(),
            forwarding_mode: ForwardingMode::PacketframeFib,
            identity: Some(IDENTITY),
            single_peer: None,
            now_unix: NOW,
        }
    }

    #[test]
    fn a_record_round_trips_exactly() {
        let bytes = encode(&meta(), &routes()).unwrap();
        let ledger = RouteLedger::decode(bytes.clone()).unwrap();
        assert_eq!(ledger.meta, meta());
        assert_eq!(
            ledger.counts,
            LedgerCounts {
                v4: FamilyCounts {
                    prefixes: 3,
                    advertisements: 4
                },
                v6: FamilyCounts {
                    prefixes: 2,
                    advertisements: 2
                },
            }
        );
        let back: Vec<LedgerRoute> = ledger.routes().collect();
        assert_eq!(back, routes());
        assert_eq!(ledger.encoded_len(), bytes.len());
        // And re-encoding what was read gives the same bytes: nothing
        // was normalised on the way through.
        assert_eq!(encode(&meta(), &back).unwrap(), bytes);
    }

    #[test]
    fn an_empty_record_round_trips() {
        let bytes = encode(&meta(), &[]).unwrap();
        let ledger = RouteLedger::decode(bytes).unwrap();
        assert_eq!(ledger.counts, LedgerCounts::default());
        assert_eq!(ledger.routes().count(), 0);
    }

    #[test]
    fn the_encoder_refuses_what_the_reader_would() {
        let peers = [PEER];
        let nhs = [v4nh(1)];
        let one = LedgerCounts {
            v4: FamilyCounts {
                prefixes: 1,
                advertisements: 1,
            },
            v6: FamilyCounts::default(),
        };
        let p = IpPrefix::V4 {
            addr: [203, 0, 113, 0],
            prefix_len: 24,
        };
        let ok = AdvertRef {
            peer: PEER,
            path_id: None,
            local_pref: None,
            nexthops: &nhs,
        };
        // No nexthop.
        let mut e = LedgerEncoder::new(&meta(), one, &peers, &nhs);
        assert!(e
            .route(
                p,
                &[AdvertRef {
                    nexthops: &[],
                    ..ok
                }]
            )
            .is_err());
        // A peer that was not interned.
        let mut e = LedgerEncoder::new(&meta(), one, &peers, &nhs);
        assert!(e
            .route(
                p,
                &[AdvertRef {
                    peer: PeerId(9),
                    ..ok
                }]
            )
            .is_err());
        // Counts that disagree with the header.
        let mut e = LedgerEncoder::new(&meta(), one, &peers, &nhs);
        e.route(p, &[ok]).unwrap();
        e.route(p, &[ok]).unwrap();
        assert!(e.finish().is_err());
    }

    /// Truncation anywhere, and a flipped bit anywhere, is refused as
    /// corruption — never half-read. Exhaustive over the record's bytes,
    /// which is cheap at this size and is the claim being made.
    #[test]
    fn any_damage_is_refused_whole() {
        let bytes = encode(&meta(), &routes()).unwrap();
        for cut in 0..bytes.len() {
            match RouteLedger::decode(bytes[..cut].to_vec()) {
                Err(Refusal::Corrupt(_)) => {}
                other => panic!("truncated at {cut}: {other:?}"),
            }
        }
        for i in 0..bytes.len() {
            let mut b = bytes.clone();
            b[i] ^= 0x10;
            match RouteLedger::decode(b) {
                // The version field: a flipped bit there reads as another
                // version, which is refused by name.
                Err(Refusal::FormatVersion { .. }) if (8..12).contains(&i) => {}
                Err(Refusal::Corrupt(_)) => {}
                other => panic!("bit flipped at {i}: {other:?}"),
            }
        }
    }

    #[test]
    fn another_format_version_is_refused_by_name() {
        let mut bytes = encode(&meta(), &routes()).unwrap();
        bytes[8..12].copy_from_slice(&(LEDGER_FORMAT_VERSION + 1).to_le_bytes());
        assert_eq!(
            RouteLedger::decode(bytes).unwrap_err(),
            Refusal::FormatVersion {
                found: LEDGER_FORMAT_VERSION + 1
            }
        );
    }

    /// A record that names a resolver peer is not one this writer could
    /// have produced: the resolver's routes are re-injected live, and a
    /// seeded one would compete with them.
    #[test]
    fn a_local_arp_peer_is_refused() {
        let mut r = routes();
        r[0].adverts[0].peer = PeerId::local_arp(7);
        let bytes = encode(&meta(), &r).unwrap();
        match RouteLedger::decode(bytes) {
            Err(Refusal::Corrupt(why)) => assert!(why.contains("neighbour-resolver"), "{why}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_good_record_is_accepted() {
        let bytes = encode(&meta(), &routes()).unwrap();
        let ledger = judge(bytes, &expect()).unwrap();
        assert_eq!(ledger.routes().count(), 5);
    }

    #[test]
    fn every_refusal_is_named() {
        let good = || encode(&meta(), &routes()).unwrap();
        let refused = |bytes: Vec<u8>, exp: Expectations<'_>| judge(bytes, &exp).unwrap_err();

        assert_eq!(
            refused(
                good(),
                Expectations {
                    spec: RouteLedgerSpec {
                        enabled: false,
                        ..RouteLedgerSpec::default()
                    },
                    ..expect()
                }
            ),
            Refusal::Disabled
        );
        for mode in [ForwardingMode::KernelFib, ForwardingMode::Compare] {
            assert_eq!(
                refused(
                    good(),
                    Expectations {
                        forwarding_mode: mode,
                        ..expect()
                    }
                ),
                Refusal::ForwardingMode(mode)
            );
        }
        assert_eq!(
            refused(
                good(),
                Expectations {
                    identity: None,
                    ..expect()
                }
            ),
            Refusal::NoRouteSource
        );
        let other = "bgp listen 192.0.2.1 port 179 local-as 64512 peer-as 64513 peer-ip any";
        assert_eq!(
            refused(
                good(),
                Expectations {
                    identity: Some(other),
                    ..expect()
                }
            ),
            Refusal::Identity {
                recorded: IDENTITY.into(),
                configured: other.into()
            }
        );
        // Too old: by the CONFIRMATION time, not the write.
        let mut m = meta();
        m.written_at_unix = NOW - 60;
        m.confirmed_at_unix = NOW - 1801;
        assert_eq!(
            refused(encode(&m, &routes()).unwrap(), expect()),
            Refusal::TooOld {
                age_secs: 1801,
                max_age_secs: 1800
            }
        );
        // ...and exactly at the bound is fine.
        m.confirmed_at_unix = NOW - 1800;
        assert!(judge(encode(&m, &routes()).unwrap(), &expect()).is_ok());
        // A configured max-age applies.
        assert_eq!(
            refused(
                good(),
                Expectations {
                    spec: RouteLedgerSpec {
                        enabled: true,
                        max_age_secs: 60
                    },
                    ..expect()
                }
            ),
            Refusal::TooOld {
                age_secs: 120,
                max_age_secs: 60
            }
        );
        // The clock moved backwards across the restart.
        let mut m = meta();
        m.written_at_unix = NOW + 3600;
        m.confirmed_at_unix = NOW + 3600;
        assert_eq!(
            refused(encode(&m, &routes()).unwrap(), expect()),
            Refusal::Clock { ahead_secs: 3600 }
        );
        // ...but an NTP slew inside the slack is not a refusal.
        m.written_at_unix = NOW + 30;
        m.confirmed_at_unix = NOW + 30;
        assert!(judge(encode(&m, &routes()).unwrap(), &expect()).is_ok());
        // A BGP source has exactly one peer id; the routes above carry two.
        assert_eq!(
            refused(
                good(),
                Expectations {
                    single_peer: Some(PEER),
                    ..expect()
                }
            ),
            Refusal::PeerId {
                recorded: 0x7777,
                expected: PEER.0
            }
        );
        assert!(matches!(
            refused(b"not a ledger at all".to_vec(), expect()),
            Refusal::Corrupt(_)
        ));
        // Intact but empty: nothing a stop writes, so nothing to seed.
        match refused(encode(&meta(), &[]).unwrap(), expect()) {
            Refusal::Corrupt(why) => assert!(why.contains("no routes"), "{why}"),
            other => panic!("{other:?}"),
        }

        // Every refusal has a distinct, stable code and a sentence.
        let all = [
            Refusal::Missing,
            Refusal::Disabled,
            Refusal::ForwardingMode(ForwardingMode::KernelFib),
            Refusal::NoRouteSource,
            Refusal::Unreadable("x".into()),
            Refusal::Unremovable("x".into()),
            Refusal::Corrupt("x".into()),
            Refusal::FormatVersion { found: 9 },
            Refusal::Identity {
                recorded: "a".into(),
                configured: "b".into(),
            },
            Refusal::TooOld {
                age_secs: 1,
                max_age_secs: 1,
            },
            Refusal::Clock { ahead_secs: 1 },
            Refusal::PeerId {
                recorded: 1,
                expected: 2,
            },
        ];
        let codes: std::collections::HashSet<_> = all.iter().map(Refusal::code).collect();
        assert_eq!(codes.len(), all.len());
        assert!(all.iter().all(|r| !r.describe().is_empty()));
    }

    /// Read once: the file is gone after the first read whether or not
    /// it was used, so a crash loop cannot seed from it twice.
    #[test]
    fn a_ledger_is_consumed_once() {
        let dir = tmpdir("once");
        write(&dir, &encode(&meta(), &routes()).unwrap()).unwrap();
        assert!(matches!(consume(&dir, &expect()), Consumed::Seed(_)));
        assert!(!path_in(&dir).exists());
        assert!(matches!(
            consume(&dir, &expect()),
            Consumed::Refused(Refusal::Missing)
        ));

        // A refused record is consumed too.
        write(&dir, &encode(&meta(), &routes()).unwrap()).unwrap();
        let wrong = Expectations {
            identity: Some("bmp listen 192.0.2.1 port 6543 require-loc-rib on"),
            ..expect()
        };
        assert!(matches!(
            consume(&dir, &wrong),
            Consumed::Refused(Refusal::Identity { .. })
        ));
        assert!(!path_in(&dir).exists());

        // ...and so is one this start would never use: a kernel-fib start
        // removes it, so a later packetframe-fib start cannot seed from a
        // table that went stale while this one ran.
        write(&dir, &encode(&meta(), &routes()).unwrap()).unwrap();
        let kernel = Expectations {
            forwarding_mode: ForwardingMode::KernelFib,
            ..expect()
        };
        assert!(matches!(
            consume(&dir, &kernel),
            Consumed::Refused(Refusal::ForwardingMode(ForwardingMode::KernelFib))
        ));
        assert!(!path_in(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No file is a refusal only where a ledger would have been used.
    #[test]
    fn a_missing_ledger_is_reported_only_where_one_was_wanted() {
        let dir = tmpdir("missing");
        assert!(matches!(
            consume(&dir, &expect()),
            Consumed::Refused(Refusal::Missing)
        ));
        for exp in [
            Expectations {
                spec: RouteLedgerSpec {
                    enabled: false,
                    ..RouteLedgerSpec::default()
                },
                ..expect()
            },
            Expectations {
                forwarding_mode: ForwardingMode::KernelFib,
                ..expect()
            },
        ] {
            assert!(matches!(consume(&dir, &exp), Consumed::Quiet));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = tmpdir("remove");
        remove(&dir).unwrap();
        write(&dir, b"x").unwrap();
        remove(&dir).unwrap();
        assert!(!path_in(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_seed_blocks_attestation_until_the_stream_starts() {
        let mut st = LedgerStatus::default();
        assert!(
            st.attestation_blocker().is_none(),
            "no seed, nothing to block"
        );
        st.start = StartReport::Seeded;
        st.seed = Some(SeedReport {
            writer_version: "0.6.0".into(),
            written_at_unix: NOW - 120,
            confirmed_at_unix: NOW - 120,
            counts: LedgerCounts::default(),
            applied_at: None,
            apply_took: None,
            failed: 0,
            unconfirmed: 5,
            stream_started_at: None,
            reconciled: None,
        });
        assert!(st.attestation_blocker().is_some());
        assert!(st.awaiting_stream());
        let s = st.seed.as_mut().unwrap();
        s.applied_at = Some(Instant::now());
        assert!(st.attestation_blocker().is_some());
        st.seed.as_mut().unwrap().stream_started_at = Some(Instant::now());
        assert!(st.attestation_blocker().is_none());
        assert!(!st.awaiting_stream());
        assert!(st.stream_started());
    }

    /// A session whose only UPDATE is an empty End-of-RIB (or a BMP
    /// stream whose route monitoring carried no route) reconciles the
    /// seed without a single Add or Del. That is still a live session
    /// having delivered its whole table: the reconciled seed must not
    /// block attestation forever.
    #[test]
    fn a_reconciled_seed_blocks_nothing_even_without_a_route() {
        let mut st = LedgerStatus {
            start: StartReport::Seeded,
            seed: Some(SeedReport {
                writer_version: "0.6.0".into(),
                written_at_unix: NOW - 120,
                confirmed_at_unix: NOW - 120,
                counts: LedgerCounts::default(),
                applied_at: Some(Instant::now()),
                apply_took: None,
                failed: 0,
                unconfirmed: 5,
                stream_started_at: None,
                reconciled: None,
            }),
        };
        assert!(st.attestation_blocker().is_some());
        let s = st.seed.as_mut().unwrap();
        s.reconciled = Some((Instant::now(), 5));
        s.unconfirmed = 0;
        assert!(st.attestation_blocker().is_none(), "{st:?}");
        assert!(!st.awaiting_stream());
        assert!(
            st.stream_started(),
            "the authority's early check is owed at reconciliation too"
        );
    }

    #[test]
    fn the_health_row_says_what_happened() {
        let now = Instant::now();
        let row = |st: &LedgerStatus| st.subsystem_health(NOW, now);
        let mut st = LedgerStatus {
            start: StartReport::Refused {
                code: "too-old",
                detail: "old".into(),
            },
            seed: None,
        };
        let r = row(&st);
        assert_eq!(r.name, SUBSYS_ROUTE_LEDGER);
        assert_eq!(r.state, HealthState::Healthy);
        assert!(r.message.unwrap().contains("too-old"));
        st.start = StartReport::Refused {
            code: "unremovable",
            detail: "EPERM".into(),
        };
        assert_eq!(row(&st).state, HealthState::Degraded);

        st.start = StartReport::Seeded;
        st.seed = Some(SeedReport {
            writer_version: "0.6.0".into(),
            written_at_unix: NOW - 240,
            confirmed_at_unix: NOW - 240,
            counts: LedgerCounts {
                v4: FamilyCounts {
                    prefixes: 1_100_000,
                    advertisements: 1_100_000,
                },
                v6: FamilyCounts {
                    prefixes: 250_000,
                    advertisements: 250_000,
                },
            },
            applied_at: Some(now),
            apply_took: Some(Duration::from_secs(3)),
            failed: 0,
            unconfirmed: 900_000,
            stream_started_at: Some(now),
            reconciled: None,
        });
        let m = row(&st).message.unwrap();
        assert!(
            m.contains("seeded 1100000 IPv4 + 250000 IPv6 routes from a ledger written 4m00s ago"),
            "{m}"
        );
        assert!(m.contains("900000 seeded advertisements not yet"), "{m}");
        st.seed.as_mut().unwrap().reconciled = Some((now, 12));
        let m = row(&st).message.unwrap();
        assert!(m.contains("GC removed 12"), "{m}");

        let mut out = String::new();
        st.render_metrics(&mut out);
        assert!(out.contains(
            "packetframe_fib_route_ledger_seeded_routes{module=\"fast-path\",family=\"ipv4\"} 1100000"
        ));
        assert!(
            out.contains("packetframe_fib_route_ledger_unconfirmed{module=\"fast-path\"} 900000")
        );
    }

    #[test]
    fn human_secs_reads_naturally() {
        assert_eq!(human_secs(5), "5s");
        assert_eq!(human_secs(90), "1m30s");
        assert_eq!(human_secs(7260), "2h01m");
    }

    /// One measured run at the production table's size: 1.1M IPv4 and
    /// 250k IPv6 routes, one advertisement each, over the 768 nexthops
    /// RFC 5737 holds (two-byte indexes, like a real table's thousands),
    /// in a temp dir on this machine's disk. Prints the numbers; asserts
    /// only that the result is a usable record. `--ignored` so it is run
    /// once, by hand, not on every `cargo test`.
    ///
    /// The IPv4 prefixes are documentation addresses repeated with varied
    /// lengths: the format neither dedupes nor needs distinct keys, and a
    /// documentation-only test has no 1.1M distinct IPv4 prefixes to use.
    /// Every one encodes exactly as a distinct /24 would.
    #[test]
    #[ignore = "measurement: run once with --ignored --nocapture"]
    fn measure_a_full_table_ledger() {
        let nhs: Vec<IpAddr> = [[192u8, 0, 2], [198, 51, 100], [203, 0, 113]]
            .iter()
            .flat_map(|b| (0..=255u8).map(move |d| IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], d))))
            .collect();
        let mut routes = Vec::with_capacity(1_350_000);
        for i in 0..1_100_000u32 {
            routes.push(LedgerRoute {
                prefix: IpPrefix::V4 {
                    addr: [203, 0, 113, (i % 256) as u8],
                    prefix_len: 24 + (i % 9) as u8,
                },
                adverts: vec![LedgerAdvert {
                    peer: PEER,
                    path_id: None,
                    local_pref: Some(100),
                    nexthops: vec![nhs[i as usize % nhs.len()]],
                }],
            });
        }
        for i in 0..250_000u32 {
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
            a[4..8].copy_from_slice(&i.to_be_bytes());
            routes.push(LedgerRoute {
                prefix: IpPrefix::V6 {
                    addr: a,
                    prefix_len: 48,
                },
                adverts: vec![LedgerAdvert {
                    peer: PEER,
                    path_id: None,
                    local_pref: Some(100),
                    nexthops: vec![nhs[i as usize % nhs.len()]],
                }],
            });
        }
        let dir = tmpdir("measure");
        let t = Instant::now();
        let bytes = encode(&meta(), &routes).unwrap();
        let encode_took = t.elapsed();
        let t = Instant::now();
        write(&dir, &bytes).unwrap();
        let write_took = t.elapsed();
        let t = Instant::now();
        let ledger = match consume(&dir, &expect()) {
            Consumed::Seed(l) => l,
            other => panic!("{other:?}"),
        };
        let read_took = t.elapsed();
        let t = Instant::now();
        let n = ledger.routes().count();
        let walk_took = t.elapsed();
        assert_eq!(n, 1_350_000);
        println!(
            "1.35M-route ledger: {} bytes ({:.1} B/route); encode {:?}, write+fsync+rename {:?}, \
             read+remove+validate {:?}, seed-order walk {:?}",
            bytes.len(),
            bytes.len() as f64 / 1_350_000.0,
            encode_took,
            write_took,
            read_took,
            walk_took
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
