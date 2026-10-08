//! The route ledger a clean `--keep-vpp` stop leaves for the next
//! daemon, and every check that daemon runs before it trusts it.
//!
//! **Why this exists.** An adopted VPP's FIB can only be learned two
//! ways: read it (`ip_route_dump`), or be told it. Reading it is not
//! mp-safe — VPP parks every worker in barrier sync for the whole walk
//! (~5.4 s on the shadow at 1.05M routes, far longer on a starved box) —
//! so a steered adoption had to take traffic OFF VPP first, onto an eBPF
//! tier whose mirror always restarts empty. On the primary (2026-09-26,
//! ~1.09M routes) a `systemctl stop && detach --keep-vpp && start` that
//! KEPT a verified, forwarding VPP cost ~13 minutes unsteered, a
//! teardown and a full reload. The previous process knew exactly what
//! VPP held; this is it telling the next one.
//!
//! **What makes it safe to believe**, leg by leg — each one a way the
//! record could describe a FIB that is not VPP's any more:
//!
//! - *Which VPP.* The record carries the `(pid, start_ticks, boot_id)`
//!   triple the state file uses to recognise its process, and the
//!   adoption compares it with the process it actually adopted. A crash,
//!   a respawn or a reboot all produce a different triple.
//! - *Nobody else took it over since.* A random token is written into
//!   [`crate::resources::ResourceState::ledger_token`] in the same stop.
//!   Every daemon that adopts this VPP rewrites that file on its attach
//!   (the interface record is persisted after every device attach) — and
//!   a build that predates the field drops it on the way — so a record
//!   that outlived a downgrade, or any other adopter, no longer matches.
//! - *Nobody changed VPP's FIB since.* The record carries VPP's own
//!   per-prefix-length route counts (`show ip fib summary`, O(1) per
//!   length inside VPP; under `v6 on` also `show ip6 fib summary`, which
//!   VPP answers by walking its v6 table), read at the stop, and the
//!   adoption re-reads them before seeding. A `vppctl` edit, a second
//!   client, anything that added or removed a route shows up as a count.
//!   Either summary unreadable means the record is not used.
//! - *And the routes are really there, through those paths.* The
//!   adoption's verify probes VPP against the seeded ledger with the
//!   PATHS compared too ([`crate::verify::verify_paths`]); a
//!   disagreement discards the seed and falls back to the dump path.
//! - *Whose.* Its routes are what this root daemon believes VPP holds,
//!   and a record another account could have written is a fabricated
//!   FIB whatever its checksum says (an unkeyed checksum proves
//!   integrity, not provenance). Before a byte is read, the open
//!   descriptors must show a regular file owned by the daemon's uid and
//!   closed to group and others, in a directory likewise, under
//!   ancestors nobody else can rename; anything else is refused
//!   (`untrusted`). See [`packetframe_common::statefile::read_owned_no_follow`].
//! - *How big.* Past [`max_ledger_bytes`] (the widest record this run's
//!   route capacity could encode to) it is refused from `fstat`
//!   (`too-large`), never read.
//! - *Used once.* The adoption removes the file the moment it reads it,
//!   before anything touches VPP, whether or not the record checks out.
//!   A crash or an unclean stop writes no record at all, so a stale one
//!   cannot be what the next start finds.
//!
//! **Format.** Compact binary, little-endian, one file. ~10 bytes a v4
//! route (≈11 MB at 1.1M), path sets interned once, a trailing FNV-1a
//! checksum over everything before it so a truncated or torn file is
//! refused rather than half-seeded. Written with the hardened
//! state-directory primitives ([`packetframe_common::statefile`]):
//! component-wise no-follow walk, `O_EXCL|O_NOFOLLOW` temp file,
//! `renameat` within the walked directory.

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use packetframe_common::events::{self as event_log, kind as event_kind};
use packetframe_common::fib::IpPrefix;

use crate::sink::PathKey;

/// The record's file name, beside `vpp-offload.json` in `state-dir`.
pub const LEDGER_FILE_NAME: &str = "vpp-route-ledger.bin";

/// Bump on any layout change. A record of another version is refused,
/// which costs one dump-path adoption and nothing else.
///
/// **2** since a path records every forwarding attribute (weight,
/// preference, type, flags, proto, labels), not just nexthop and
/// interface — see `sink::PathKey`.
pub const LEDGER_FORMAT_VERSION: u32 = 2;

const MAGIC: &[u8; 8] = b"PFVPPLGR";

/// Path-set index meaning "paths unknown" — a route the previous
/// process held without having observed its paths (a dump adoption it
/// never re-sent). Seeded as installed; never skipped, never path-checked.
const NO_PATHS: u32 = u32::MAX;

/// A length-prefixed string at the format's limit: a `u16` length and
/// that many bytes ([`put_str`] truncates anything longer).
const STR_MAX_BYTES: u64 = 2 + u16::MAX as u64;

/// The wire's MPLS label stack (`fib_path.label_stack`): the most labels
/// a path read off the wire carries, so the most a recorded one can.
const WIRE_LABELS_MAX: u64 = 16;

/// One path at its widest: a v6 nexthop (family byte and address),
/// interface, weight, preference, kind, flags, proto, the label count,
/// and the wire's full label stack at seven bytes a label.
const PATH_MAX_BYTES: u64 = 17 + 4 + 1 + 1 + 4 + 4 + 4 + 1 + WIRE_LABELS_MAX * 7;

/// One entry at its widest: family, length, a v6 address, the path-set
/// index.
const ENTRY_MAX_BYTES: u64 = 1 + 1 + 16 + 4;

/// What one route is charged in [`max_ledger_bytes`]: its entry at its
/// widest, plus a path set of its own (a `u16` count and one path at
/// its widest).
///
/// A set per route because every set a record holds is one some entry
/// names (`ConvergenceEngine::preservable_ledger` writes only the sets
/// its entries reference), so there are never more sets than routes.
/// One path per set is an allowance, not the format's maximum: nothing
/// below the wire's 255 caps an ECMP width. It is a wide one. The paths
/// this module installs carry no labels (`fib_sync::wire_path`), 36
/// bytes at most, so the charge holds four of them per route, and
/// distinct sets are a property of the topology, not the table: 129
/// nexthops and no ECMP group on the reference fleet against a million
/// routes (`feed`'s module docs).
const ROUTE_MAX_BYTES: u64 = ENTRY_MAX_BYTES + 2 + PATH_MAX_BYTES;

/// One interface at its widest: its name and `sw_if_index`.
const INTERFACE_MAX_BYTES: u64 = STR_MAX_BYTES + 4;

/// Fingerprint rows: one per prefix length of the one table per family
/// this module programs (table 0) — 33 for IPv4, 129 for IPv6.
const FINGERPRINT_ROWS_MAX: u64 = 33 + 129;

/// One fingerprint row at its widest: table name, length, count.
const FINGERPRINT_ROW_MAX_BYTES: u64 = STR_MAX_BYTES + 1 + 8;

/// Everything without a per-route or per-interface count, at its widest:
/// magic, format version, pid, start ticks, the boot id, the token, the
/// four counts, every fingerprint row, and the checksum.
const FIXED_MAX_BYTES: u64 = 8
    + 4
    + 4
    + 8
    + STR_MAX_BYTES
    + 8
    + 4 * 4
    + FINGERPRINT_ROWS_MAX * FINGERPRINT_ROW_MAX_BYTES
    + 8;

/// The largest file a start reads as a preserved ledger, judged from
/// `fstat` before a byte of it is read: the widest record an engine
/// admitting `routes` prefixes (both families' high-water marks
/// together) could write against `interfaces` ports. Past it the record
/// is refused (`too-large`) and removed unread.
///
/// `routes` is this run's capacity, and that is the writer's too: an
/// adoption is refused outright unless `expected-routes`, `v6` and the
/// ports are the ones the adopted VPP was started under (`acquire`), and
/// the engine withholds rather than installs past its marks. At the
/// default `expected-routes` with `v6 on` the bound is about 500 MB,
/// against ~11 MB for the reference router's 1.09M-route table — the
/// per-route charge is ~17x a real v4 route's — so no ledger this engine
/// writes meets it, and a huge or sparse file in `state-dir` cannot make
/// a start allocate without limit.
pub fn max_ledger_bytes(routes: u64, interfaces: usize) -> u64 {
    FIXED_MAX_BYTES
        .saturating_add((interfaces as u64).saturating_mul(INTERFACE_MAX_BYTES))
        .saturating_add(routes.saturating_mul(ROUTE_MAX_BYTES))
}

/// VPP's own route count per table and prefix length.
///
/// The cheapest thing VPP can say that changes whenever anyone adds or
/// removes a route: `show ip fib summary` reads a hash's element count
/// per length, no walk and no per-route work. It counts EVERYTHING in
/// the table — connected, local, adj-fib host routes and ours — which
/// is the point: the claim it backs is "nothing changed", not "our
/// routes are there".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FibFingerprint {
    /// `(table, prefix length, count)`, sorted.
    pub counts: Vec<(String, u8, u64)>,
}

impl FibFingerprint {
    /// The CLI command that produces the summary for one family.
    pub fn command(is_ip6: bool) -> &'static str {
        if is_ip6 {
            "show ip6 fib summary"
        } else {
            "show ip fib summary"
        }
    }

    /// Fold one `show ip[6] fib summary` output into the fingerprint.
    ///
    /// Both families' outputs are the same shape, checked against VPP
    /// v26.06's source (`ip4_fib.c` / `ip6_fib.c`): a `%v`-formatted table
    /// header naming the table (`ipv4-VRF:0` / `ipv6-VRF:0`, its
    /// `ft_desc`), a `Prefix length  Count` title, then one row per
    /// populated length — right-aligned `%20d%16d` for v4, centred
    /// `%=20d%=16lld` for v6, which whitespace splitting reads alike. The
    /// v6 command skips the per-interface link-local tables, so no
    /// `IP6-link-local:` header appears to be misattributed.
    ///
    /// Tolerant of layout, strict about meaning: a table header is a
    /// line starting `ipv4-`/`ipv6-` (its name is everything before the
    /// first comma — the rest carries lock counts nobody should compare),
    /// and a count is a line of exactly two integers under a header.
    /// Anything else is skipped. Returns how many counts were added, so a
    /// caller can refuse an answer it could not read at all rather than
    /// fingerprint nothing.
    pub fn absorb(&mut self, text: &str) -> usize {
        let mut table: Option<String> = None;
        let mut added = 0;
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with("ipv4-") || t.starts_with("ipv6-") {
                table = Some(t.split(',').next().unwrap_or(t).to_string());
                continue;
            }
            let Some(name) = table.as_ref() else {
                continue;
            };
            let mut tok = t.split_whitespace();
            let (Some(a), Some(b), None) = (tok.next(), tok.next(), tok.next()) else {
                continue;
            };
            let (Ok(len), Ok(count)) = (a.parse::<u8>(), b.parse::<u64>()) else {
                continue;
            };
            self.counts.push((name.clone(), len, count));
            added += 1;
        }
        self.counts.sort();
        added
    }
}

/// What a preserving stop records about the ledger itself — everything
/// but the identity, which the state file's owner supplies (it is the
/// one that knows which process it recorded).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerBody {
    pub fingerprint: FibFingerprint,
    /// `(port, sw_if_index)` the routes were installed against.
    pub interfaces: Vec<(String, u32)>,
    /// Distinct path sets, each canonical (see `sink::canonical_paths`).
    pub path_sets: Vec<Vec<PathKey>>,
    /// Every installed prefix with its index into `path_sets`, or `None`
    /// where the paths were never observed.
    pub entries: Vec<(IpPrefix, Option<u32>)>,
}

/// A preserved ledger, tied to the exact VPP it describes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRecord {
    pub pid: i32,
    pub start_ticks: u64,
    pub boot_id: String,
    /// Must equal `ResourceState::ledger_token` at adoption.
    pub token: u64,
    pub body: LedgerBody,
}

/// Why a record found at bring-up was not used. Every one of these falls
/// back to the dump path; none fails the adoption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Someone other than this daemon's uid could have written it or put
    /// it there: the file is owned by another uid or writable by group or
    /// others, so is the directory holding it, or an ancestor lets a
    /// third account rename the directories under it (or it is not a
    /// regular file). Never read; removed.
    Untrusted(String),
    /// Larger than [`max_ledger_bytes`] allows this run. Never read;
    /// removed.
    TooLarge { len: u64, max: u64 },
    /// It could not be read: an I/O error, or a symlink at any component.
    Unreadable(String),
    /// It was read but could not be removed, so it cannot be consumed
    /// once.
    Unremovable(String),
    /// Not exactly one intact record: truncated, corrupt, or malformed.
    Corrupt(String),
    /// A record of another layout.
    FormatVersion { found: u32 },
    /// It describes another VPP process than the one adopted.
    Process(String),
    /// The state file's ledger token is missing or another stop's.
    Token(String),
    /// It was installed against other interfaces than the state file
    /// records.
    Interfaces(String),
}

impl Refusal {
    /// The check that refused it — the `stage` field of the
    /// `preserved_ledger_rejected` event, beside the later stages'
    /// `fingerprint`, `seed`, `fingerprint-moved` and `verify`.
    /// Append-only: operators filter on these.
    pub fn code(&self) -> &'static str {
        match self {
            Refusal::Untrusted(_) => "untrusted",
            Refusal::TooLarge { .. } => "too-large",
            Refusal::Unreadable(_) => "unreadable",
            Refusal::Unremovable(_) => "unremovable",
            Refusal::Corrupt(_) => "corrupt",
            Refusal::FormatVersion { .. } => "format-version",
            Refusal::Process(_) => "process",
            Refusal::Token(_) => "token",
            Refusal::Interfaces(_) => "interfaces",
        }
    }

    /// The reason, without the "not used" preamble the journal line
    /// carries ([`std::fmt::Display`]).
    pub fn detail(&self) -> String {
        match self {
            Refusal::Untrusted(why) => format!(
                "untrusted ownership/permissions: {why}. A ledger is read only when this \
                 daemon's own uid wrote it, into a state-dir no other account can write, under \
                 ancestors no other account can rename; removed unread"
            ),
            Refusal::TooLarge { len, max } => format!(
                "it is too large: {len} bytes, past the {max} bytes the widest ledger this \
                 run's route capacity could encode to; removed unread"
            ),
            Refusal::Unreadable(e) => e.clone(),
            Refusal::Unremovable(e) => format!(
                "it could not be removed after reading ({e}), so it cannot be consumed once — \
                 remove {LEDGER_FILE_NAME} from state-dir by hand"
            ),
            Refusal::Corrupt(why) => why.clone(),
            Refusal::FormatVersion { found } => format!(
                "it is format version {found} and this binary reads {LEDGER_FORMAT_VERSION}"
            ),
            Refusal::Process(why) | Refusal::Token(why) | Refusal::Interfaces(why) => why.clone(),
        }
    }

    /// The event this refusal records.
    pub fn event(&self) -> event_log::Event {
        rejected_event(self.code(), &self.detail())
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "preserved route ledger not used: {}", self.detail())
    }
}

fn corrupt(why: impl Into<String>) -> Refusal {
    Refusal::Corrupt(why.into())
}

/// `preserved_ledger_rejected`: the preserved ledger was not used, or was
/// disproved; `stage` names the check that refused it, here at bring-up
/// ([`Refusal::code`]) or later in the adoption (`runtime`). The dump
/// path follows. The one place the event is built, so the two halves
/// cannot drift apart.
pub(crate) fn rejected_event(stage: &'static str, reason: &str) -> event_log::Event {
    event_log::Event::warn(crate::MODULE_NAME, event_kind::PRESERVED_LEDGER_REJECTED)
        .field("stage", stage)
        .field("reason", reason)
        .detail("the preserved route ledger was not used; this adoption reads VPP's FIB instead")
}

impl LedgerRecord {
    pub fn path_in(state_dir: &Path) -> PathBuf {
        state_dir.join(LEDGER_FILE_NAME)
    }

    /// Whether this record describes the process being adopted, under the
    /// state file being adopted. `Err` names the leg that failed.
    pub fn check_adoptee(
        &self,
        pid: i32,
        start_ticks: u64,
        boot_id: &str,
        token: Option<u64>,
        recorded_interfaces: &[(String, u32)],
    ) -> Result<(), Refusal> {
        if (self.pid, self.start_ticks, self.boot_id.as_str()) != (pid, start_ticks, boot_id) {
            return Err(Refusal::Process(format!(
                "it describes VPP pid {} (start {}, boot {}) but the adopted process is pid \
                 {pid} (start {start_ticks}, boot {boot_id})",
                self.pid, self.start_ticks, self.boot_id
            )));
        }
        match token {
            Some(t) if t == self.token => {}
            Some(_) => {
                return Err(Refusal::Token(
                    "the state file's ledger token is a different stop's, so another daemon \
                     wrote this VPP's record after this ledger was preserved"
                        .into(),
                ))
            }
            None => {
                return Err(Refusal::Token(
                    "the state file carries no ledger token — rewritten since the stop that \
                     preserved this ledger (another adopter, or a build that predates it)"
                        .into(),
                ))
            }
        }
        let mut mine = self.body.interfaces.clone();
        let mut theirs = recorded_interfaces.to_vec();
        mine.sort();
        theirs.sort();
        if mine != theirs {
            return Err(Refusal::Interfaces(format!(
                "it was installed against interfaces {mine:?} but the state file records \
                 {theirs:?}"
            )));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let b = &self.body;
        let mut out = Vec::with_capacity(64 + b.entries.len() * 10);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&LEDGER_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.pid.to_le_bytes());
        out.extend_from_slice(&self.start_ticks.to_le_bytes());
        put_str(&mut out, &self.boot_id);
        out.extend_from_slice(&self.token.to_le_bytes());
        out.extend_from_slice(&(b.interfaces.len() as u32).to_le_bytes());
        for (name, idx) in &b.interfaces {
            put_str(&mut out, name);
            out.extend_from_slice(&idx.to_le_bytes());
        }
        out.extend_from_slice(&(b.fingerprint.counts.len() as u32).to_le_bytes());
        for (table, len, count) in &b.fingerprint.counts {
            put_str(&mut out, table);
            out.push(*len);
            out.extend_from_slice(&count.to_le_bytes());
        }
        out.extend_from_slice(&(b.path_sets.len() as u32).to_le_bytes());
        for set in &b.path_sets {
            out.extend_from_slice(&(set.len() as u16).to_le_bytes());
            for p in set {
                put_addr(&mut out, p.nexthop);
                out.extend_from_slice(&p.sw_if_index.to_le_bytes());
                out.push(p.weight);
                out.push(p.preference);
                out.extend_from_slice(&p.kind.to_le_bytes());
                out.extend_from_slice(&p.flags.to_le_bytes());
                out.extend_from_slice(&p.proto.to_le_bytes());
                // At most 16 on the wire (`label_stack`); a u8 holds it.
                out.push(p.labels.len().min(u8::MAX as usize) as u8);
                for (label, ttl, exp, uniform) in p.labels.iter().take(u8::MAX as usize) {
                    out.extend_from_slice(&label.to_le_bytes());
                    out.push(*ttl);
                    out.push(*exp);
                    out.push(*uniform);
                }
            }
        }
        out.extend_from_slice(&(b.entries.len() as u32).to_le_bytes());
        for (prefix, set) in &b.entries {
            match prefix {
                IpPrefix::V4 { addr, prefix_len } => {
                    out.push(4);
                    out.push(*prefix_len);
                    out.extend_from_slice(addr);
                }
                IpPrefix::V6 { addr, prefix_len } => {
                    out.push(6);
                    out.push(*prefix_len);
                    out.extend_from_slice(addr);
                }
            }
            out.extend_from_slice(&set.unwrap_or(NO_PATHS).to_le_bytes());
        }
        let sum = fnv1a(&out);
        out.extend_from_slice(&sum.to_le_bytes());
        out
    }

    /// Parse a record, refusing anything that is not exactly one intact
    /// record of this version.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() < MAGIC.len() + 4 + 8 {
            return Err(corrupt("the file is too short to be a record"));
        }
        let (body, sum) = bytes.split_at(bytes.len() - 8);
        let sum = u64::from_le_bytes(sum.try_into().expect("8 bytes"));
        if &body[..MAGIC.len()] != MAGIC {
            return Err(corrupt("the file is not a preserved route ledger"));
        }
        let mut r = Reader {
            buf: body,
            at: MAGIC.len(),
        };
        let version = r.u32()?;
        if version != LEDGER_FORMAT_VERSION {
            return Err(Refusal::FormatVersion { found: version });
        }
        // Checked after the version, so a future layout is named as such
        // rather than as corruption.
        if fnv1a(body) != sum {
            return Err(corrupt(
                "its checksum does not match — truncated or corrupted since it was written",
            ));
        }
        let pid = r.i32()?;
        let start_ticks = r.u64()?;
        let boot_id = r.string()?;
        let token = r.u64()?;
        let n = r.count(4 + 2)?;
        let mut interfaces = Vec::with_capacity(n);
        for _ in 0..n {
            let name = r.string()?;
            interfaces.push((name, r.u32()?));
        }
        let n = r.count(2 + 1 + 8)?;
        let mut counts = Vec::with_capacity(n);
        for _ in 0..n {
            let table = r.string()?;
            let len = r.u8()?;
            counts.push((table, len, r.u64()?));
        }
        let n = r.count(2)?;
        let mut path_sets = Vec::with_capacity(n);
        for _ in 0..n {
            let m = r.u16()? as usize;
            // The smallest encoded path: v4 nexthop (5) + interface (4) +
            // weight, preference (2) + kind, flags, proto (12) + count (1).
            let mut set = Vec::with_capacity(m.min(r.remaining() / 24));
            for _ in 0..m {
                let nexthop = r.addr()?;
                let sw_if_index = r.u32()?;
                let weight = r.u8()?;
                let preference = r.u8()?;
                let kind = r.u32()?;
                let flags = r.u32()?;
                let proto = r.u32()?;
                let n_labels = r.u8()?;
                let mut labels = Vec::with_capacity(usize::from(n_labels).min(16));
                for _ in 0..n_labels {
                    let label = r.u32()?;
                    labels.push((label, r.u8()?, r.u8()?, r.u8()?));
                }
                set.push(PathKey {
                    nexthop,
                    sw_if_index,
                    weight,
                    preference,
                    kind,
                    flags,
                    proto,
                    labels,
                });
            }
            path_sets.push(set);
        }
        let n = r.count(1 + 1 + 4 + 4)?;
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let fam = r.u8()?;
            let prefix_len = r.u8()?;
            let prefix = match fam {
                4 if prefix_len <= 32 => IpPrefix::V4 {
                    addr: r.bytes::<4>()?,
                    prefix_len,
                },
                6 if prefix_len <= 128 => IpPrefix::V6 {
                    addr: r.bytes::<16>()?,
                    prefix_len,
                },
                _ => {
                    return Err(corrupt(format!(
                        "entry with family {fam} and length {prefix_len} is not a prefix"
                    )))
                }
            };
            let set = r.u32()?;
            let set = if set == NO_PATHS {
                None
            } else if (set as usize) < path_sets.len() {
                Some(set)
            } else {
                return Err(corrupt(format!(
                    "an entry names path set {set} of {}",
                    path_sets.len()
                )));
            };
            entries.push((prefix, set));
        }
        if r.remaining() != 0 {
            return Err(corrupt("trailing bytes after the last entry"));
        }
        Ok(Self {
            pid,
            start_ticks,
            boot_id,
            token,
            body: LedgerBody {
                fingerprint: FibFingerprint { counts },
                interfaces,
                path_sets,
                entries,
            },
        })
    }

    /// Write atomically into `state_dir`, through the no-follow
    /// primitives: a symlink planted at the record, at its `.tmp`, or at
    /// any component of the directory is refused or replaced, never
    /// written through.
    pub fn write(&self, state_dir: &Path) -> Result<(), String> {
        let path = Self::path_in(state_dir);
        write_record(&path, &self.encode()).map_err(|e| format!("write {}: {e}", path.display()))
    }

    /// Read the record and remove it, in that order, whatever it holds.
    ///
    /// Consumption is unconditional because the record's whole claim is
    /// "VPP has not changed since" — and from the moment an adoption
    /// starts, it will. `Ok(None)` = no record. `Err` = there was
    /// something there and it is not a usable record (another account's,
    /// past `max_len`, unreadable, planted symlink, corrupt, another
    /// version); it is removed too — the first two without a byte of them
    /// read.
    pub fn take(state_dir: &Path, max_len: u64) -> Result<Option<Self>, Refusal> {
        let path = Self::path_in(state_dir);
        let read = read_record(&path, max_len);
        if matches!(read, Ok(None)) {
            return Ok(None);
        }
        // `unlinkat` removes a planted symlink itself, never its target.
        let removed = Self::remove(state_dir);
        let parsed = match read {
            Ok(Some(bytes)) => Self::decode(&bytes).map(Some),
            Ok(None) => unreachable!("returned above"),
            Err(ReadFailure::Untrusted(why)) => Err(Refusal::Untrusted(why)),
            Err(ReadFailure::TooLarge { len, max }) => Err(Refusal::TooLarge { len, max }),
            Err(ReadFailure::Io(e)) => Err(Refusal::Unreadable(format!("{}: {e}", path.display()))),
        };
        match removed {
            // A record that cannot be removed can be read again by the
            // next start, after this one has changed VPP — refusing it
            // here is what keeps "used once" true.
            Err(e) => Err(Refusal::Unremovable(e)),
            Ok(()) => parsed,
        }
    }

    /// Remove the record if there is one.
    pub fn remove(state_dir: &Path) -> Result<(), String> {
        let path = Self::path_in(state_dir);
        match remove_record(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove {}: {e}", path.display())),
        }
    }
}

// The state-dir primitives are Linux-only (they are `openat` walks); the
// dev-laptop build gets plain `std::fs`, the same split fast-path's
// coalescing record makes. Nothing privileged runs off Linux.
#[cfg(target_os = "linux")]
fn write_record(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    packetframe_common::statefile::write_atomic(path, contents)
}

#[cfg(not(target_os = "linux"))]
fn write_record(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("bin.tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
}

/// Why the record could not be read, before any check of its contents.
#[derive(Debug)]
enum ReadFailure {
    Io(String),
    // Only the Linux reader judges provenance; see the stub below.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Untrusted(String),
    TooLarge {
        len: u64,
        max: u64,
    },
}

/// Read the record only if this daemon's own uid could have put it
/// there, and only up to `max_len` bytes. Its contents are a FIB this
/// root daemon adopts as VPP's without reading VPP, so a record anyone
/// else could have written is a fabricated FIB; see
/// [`packetframe_common::statefile::read_owned_no_follow`] for exactly
/// what is checked (on the open descriptors, not by path). Ownership
/// rather than a keyed MAC for fast-path's reason (`route_ledger`'s
/// `read_record`): the key would have to live somewhere other accounts
/// cannot write, which is the property checked here directly.
#[cfg(target_os = "linux")]
fn read_record(path: &Path, max_len: u64) -> Result<Option<Vec<u8>>, ReadFailure> {
    use packetframe_common::statefile::{read_owned_no_follow, OwnedReadError};
    read_owned_no_follow(path, max_len).map_err(|e| match e {
        OwnedReadError::Untrusted(why) => ReadFailure::Untrusted(why),
        OwnedReadError::TooLarge { len, max } => ReadFailure::TooLarge { len, max },
        OwnedReadError::Io(e) => ReadFailure::Io(e.to_string()),
    })
}

/// The dev-laptop stub keeps the size bound (it is what keeps a huge
/// file from being read whole) and leaves provenance to the Linux build:
/// nothing privileged runs here.
#[cfg(not(target_os = "linux"))]
fn read_record(path: &Path, max_len: u64) -> Result<Option<Vec<u8>>, ReadFailure> {
    use std::io::Read as _;
    let io = |e: std::io::Error| ReadFailure::Io(e.to_string());
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io(e)),
    };
    let len = f.metadata().map_err(io)?.len();
    if len > max_len {
        return Err(ReadFailure::TooLarge { len, max: max_len });
    }
    let mut buf = Vec::with_capacity(len as usize);
    f.take(max_len.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(io)?;
    if buf.len() as u64 > max_len {
        return Err(ReadFailure::TooLarge {
            len: buf.len() as u64,
            max: max_len,
        });
    }
    Ok(Some(buf))
}

#[cfg(target_os = "linux")]
fn remove_record(path: &Path) -> std::io::Result<()> {
    packetframe_common::statefile::remove_state_record(path)
}

#[cfg(not(target_os = "linux"))]
fn remove_record(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

/// The process an attach is adopting, as the record must name it.
#[derive(Debug, Clone, Copy)]
pub struct Adoptee<'a> {
    pub pid: i32,
    pub start_ticks: u64,
    pub boot_id: &'a str,
}

/// What bring-up did with whatever record `state_dir` held.
#[derive(Debug, PartialEq, Eq)]
pub enum Consumed {
    /// No record.
    Missing,
    /// A record, consumed unjudged: nothing is being adopted, so the VPP
    /// it describes is not the one this daemon will run.
    NotAdopted,
    /// Not used, and why.
    Refused(Refusal),
    /// Checked; seed the adoption from it.
    Usable(LedgerRecord),
}

/// Consume whatever record `state_dir` holds and judge it against
/// `adoptee` (`None` when nothing is being adopted), the state file's
/// `token` and its `recorded` interfaces, reading no more than `max_len`
/// bytes ([`max_ledger_bytes`]). A pure judgement apart from the read and
/// the removal; [`consume_for_adoption`] reports it.
pub fn judge_for_adoption(
    state_dir: &Path,
    max_len: u64,
    adoptee: Option<Adoptee<'_>>,
    token: Option<u64>,
    recorded: &[(String, u32)],
) -> Consumed {
    match (LedgerRecord::take(state_dir, max_len), adoptee) {
        (Ok(None), _) => Consumed::Missing,
        // Refused whether or not anything is adopted: a record another
        // account could have written, or one past any size this run
        // writes, is worth naming even when it would have been moot.
        (Err(r), _) => Consumed::Refused(r),
        (Ok(Some(_)), None) => Consumed::NotAdopted,
        (Ok(Some(rec)), Some(a)) => {
            match rec.check_adoptee(a.pid, a.start_ticks, a.boot_id, token, recorded) {
                Ok(()) => Consumed::Usable(rec),
                Err(r) => Consumed::Refused(r),
            }
        }
    }
}

/// The adoption's half, whole: consume whatever record `state_dir` holds
/// and return it only if it describes `adoptee` under the state file's
/// `token` and `recorded` interfaces. `adoptee` is `None` when nothing is
/// being adopted — a record is then consumed and discarded, because the
/// VPP it describes is not the one this daemon will run.
///
/// Never an error: every refusal is logged with its reason, recorded as
/// `preserved_ledger_rejected` with the check that refused it as its
/// `stage` ([`Refusal::code`]), and answers `None` — the dump path every
/// adoption took before the record existed. That is the whole upgrade
/// story too — a state file an older build wrote has no token and no
/// record beside it.
pub fn consume_for_adoption(
    state_dir: &Path,
    max_len: u64,
    adoptee: Option<Adoptee<'_>>,
    token: Option<u64>,
    recorded: &[(String, u32)],
) -> Option<LedgerRecord> {
    let adopting = adoptee.is_some();
    match judge_for_adoption(state_dir, max_len, adoptee, token, recorded) {
        Consumed::Missing => {
            if adopting {
                tracing::info!(
                    "no preserved route ledger (the previous stop was not a clean preserving \
                     exit, or was an older build); this adoption reads VPP's FIB — on a steered \
                     VPP that means unsteering while it does"
                );
            }
            None
        }
        Consumed::NotAdopted => {
            tracing::info!(
                "preserved route ledger discarded: the VPP it describes is not being adopted"
            );
            None
        }
        Consumed::Refused(r) => {
            tracing::warn!(stage = r.code(), reason = %r, "this adoption reads VPP's FIB instead");
            r.event().emit();
            None
        }
        Consumed::Usable(rec) => Some(rec),
    }
}

/// A token for one preserving stop — see the module docs. Unique, not
/// secret: it only has to differ from every other stop's.
pub fn fresh_token() -> u64 {
    use std::hash::{BuildHasher as _, Hasher as _};
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    // `RandomState` is keyed per process from the OS, so hashing the
    // clock through it gives an unpredictable-enough, collision-free
    // value without a dependency.
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(nanos);
    h.write_u32(std::process::id());
    h.finish()
}

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    // Names and boot ids are tens of bytes. One past the field's limit
    // is a bug upstream; truncated here, it can only ever fail the
    // identity check at adoption, which is the safe direction.
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

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }

    fn take(&mut self, n: usize) -> Result<&[u8], Refusal> {
        if self.remaining() < n {
            return Err(corrupt("the record ends mid-field"));
        }
        let s = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(s)
    }

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Refusal> {
        Ok(self.take(N)?.try_into().expect("N bytes"))
    }

    fn u8(&mut self) -> Result<u8, Refusal> {
        Ok(self.bytes::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Refusal> {
        Ok(u16::from_le_bytes(self.bytes()?))
    }

    fn u32(&mut self) -> Result<u32, Refusal> {
        Ok(u32::from_le_bytes(self.bytes()?))
    }

    fn i32(&mut self) -> Result<i32, Refusal> {
        Ok(i32::from_le_bytes(self.bytes()?))
    }

    fn u64(&mut self) -> Result<u64, Refusal> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }

    /// A count of items at least `min_item` bytes each, refused when the
    /// rest of the record could not possibly hold that many — so a
    /// corrupt count cannot ask for a multi-gigabyte allocation.
    fn count(&mut self, min_item: usize) -> Result<usize, Refusal> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min_item) > self.remaining() {
            return Err(corrupt(format!(
                "it claims {n} items where {} bytes remain",
                self.remaining()
            )));
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, Refusal> {
        let n = self.u16()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| corrupt("a name is not UTF-8"))
    }

    fn addr(&mut self) -> Result<IpAddr, Refusal> {
        match self.u8()? {
            4 => Ok(IpAddr::V4(self.bytes::<4>()?.into())),
            6 => Ok(IpAddr::V6(self.bytes::<16>()?.into())),
            f => Err(corrupt(format!("a path names address family {f}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tmpdir(tag: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let d = std::env::temp_dir().join(format!("pf-ledger-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        // Pinned, not left to the umask: the reader refuses a state-dir
        // group or others can write.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        d
    }

    /// A bound well past the test record, so only the tests about the
    /// bound meet it.
    fn bound() -> u64 {
        max_ledger_bytes(1_000, 1)
    }

    fn ifs() -> Vec<(String, u32)> {
        vec![("eth4".to_string(), 3)]
    }

    fn me() -> Adoptee<'static> {
        Adoptee {
            pid: 4242,
            start_ticks: 99,
            boot_id: "boot-a",
        }
    }

    /// What bring-up makes of `dir` for the adoptee `record()` names.
    fn judge(dir: &Path, max_len: u64) -> Consumed {
        judge_for_adoption(dir, max_len, Some(me()), Some(7), &ifs())
    }

    fn nh(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, d))
    }

    fn pk(d: u8, idx: u32) -> PathKey {
        crate::fib_sync::installed_path_key(nh(d), idx)
    }

    fn record() -> LedgerRecord {
        LedgerRecord {
            pid: 4242,
            start_ticks: 99,
            boot_id: "boot-a".into(),
            token: 7,
            body: LedgerBody {
                fingerprint: FibFingerprint {
                    counts: vec![("ipv4-VRF:0".into(), 24, 3), ("ipv4-VRF:0".into(), 32, 5)],
                },
                interfaces: vec![("eth4".into(), 3)],
                path_sets: vec![
                    vec![pk(1, 3)],
                    vec![
                        pk(1, 3),
                        // A labelled, weighted path, so every field of the
                        // encoding round-trips.
                        PathKey {
                            weight: 3,
                            preference: 1,
                            labels: vec![(16, 64, 0, 1)],
                            ..pk(2, 3)
                        },
                    ],
                ],
                entries: vec![
                    (
                        IpPrefix::V4 {
                            addr: [198, 51, 100, 0],
                            prefix_len: 24,
                        },
                        Some(0),
                    ),
                    (
                        IpPrefix::V4 {
                            addr: [203, 0, 113, 0],
                            prefix_len: 24,
                        },
                        Some(1),
                    ),
                    (
                        IpPrefix::V6 {
                            addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                            prefix_len: 32,
                        },
                        None,
                    ),
                ],
            },
        }
    }

    #[test]
    fn a_record_round_trips_through_the_file() {
        let dir = tmpdir("round");
        let r = record();
        r.write(&dir).unwrap();
        assert_eq!(LedgerRecord::take(&dir, bound()).unwrap(), Some(r));
        assert!(
            !LedgerRecord::path_in(&dir).exists(),
            "taking a record consumes it"
        );
        assert_eq!(
            LedgerRecord::take(&dir, bound()).unwrap(),
            None,
            "used once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Any single-byte corruption anywhere in the record is refused —
    /// the checksum covers every field, and a flipped byte in the
    /// trailer itself fails the same comparison.
    #[test]
    fn every_corrupted_byte_is_refused() {
        let bytes = record().encode();
        for i in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[i] ^= 0x40;
            assert!(LedgerRecord::decode(&bad).is_err(), "byte {i} flipped");
        }
        for cut in 0..bytes.len() {
            assert!(LedgerRecord::decode(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn another_format_version_is_named_as_such() {
        let mut bytes = record().encode();
        bytes[8..12].copy_from_slice(&(LEDGER_FORMAT_VERSION + 1).to_le_bytes());
        let e = LedgerRecord::decode(&bytes).unwrap_err();
        assert_eq!(
            e,
            Refusal::FormatVersion {
                found: LEDGER_FORMAT_VERSION + 1
            }
        );
        assert_eq!(e.code(), "format-version");
        assert!(e.to_string().contains("format version"), "{e}");
    }

    /// A corrupt record is refused AND removed: the next start must not
    /// find it again.
    #[test]
    fn a_corrupt_record_is_refused_and_consumed() {
        let dir = tmpdir("corrupt");
        // This version's magic and header, then junk: the checksum fails.
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&LEDGER_FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(b" not a record");
        std::fs::write(LedgerRecord::path_in(&dir), bytes).unwrap();
        assert!(matches!(
            LedgerRecord::take(&dir, bound()),
            Err(Refusal::Corrupt(_))
        ));
        assert!(!LedgerRecord::path_in(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The planted-symlink case, both directions. Linux-only: it tests
    /// the no-follow primitives, which the dev-laptop build does not use. A symlink at the
    /// record's name is never read through (its target could be any
    /// root-readable file) and is removed as a link; one at the temp
    /// name makes the write fail rather than truncate its target.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_planted_symlink_is_neither_read_nor_written_through() {
        let dir = tmpdir("plant");
        let victim = dir.join("victim");
        std::fs::write(&victim, record().encode()).unwrap();
        let rec = LedgerRecord::path_in(&dir);
        std::os::unix::fs::symlink(&victim, &rec).unwrap();
        assert!(
            matches!(
                LedgerRecord::take(&dir, bound()),
                Err(Refusal::Unreadable(_))
            ),
            "a symlinked record is refused, not followed — even to a valid record"
        );
        assert!(
            std::fs::symlink_metadata(&rec).is_err(),
            "the link is consumed"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), record().encode());

        let tmp = dir.join(format!("{LEDGER_FILE_NAME}.tmp"));
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();
        std::fs::write(&victim, b"do not truncate me").unwrap();
        assert!(record().write(&dir).is_err(), "symlinked temp refused");
        assert_eq!(std::fs::read(&victim).unwrap(), b"do not truncate me");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_identity_leg_is_checked() {
        let r = record();
        let ifs = vec![("eth4".to_string(), 3)];
        r.check_adoptee(4242, 99, "boot-a", Some(7), &ifs)
            .expect("the matching adoptee");
        for (pid, ticks, boot, token, ifs, leg, code) in [
            (4243, 99, "boot-a", Some(7), ifs.clone(), "pid", "process"),
            (4242, 98, "boot-a", Some(7), ifs.clone(), "start", "process"),
            (4242, 99, "boot-b", Some(7), ifs.clone(), "boot", "process"),
            (4242, 99, "boot-a", Some(8), ifs.clone(), "token", "token"),
            (4242, 99, "boot-a", None, ifs.clone(), "no token", "token"),
            (
                4242,
                99,
                "boot-a",
                Some(7),
                vec![("eth4".to_string(), 4)],
                "interfaces",
                "interfaces",
            ),
        ] {
            let r = r
                .check_adoptee(pid, ticks, boot, token, &ifs)
                .expect_err(leg);
            assert_eq!(r.code(), code, "{leg} mismatch must refuse by name");
        }
    }

    /// Every fallback the adoption can take on the record itself, by name
    /// — and in every one the file is consumed, so a second start cannot
    /// find it after this one has changed VPP.
    #[test]
    fn every_record_fallback_answers_none_and_consumes_the_file() {
        let me = me();
        let mut bumped = record().encode();
        bumped[8..12].copy_from_slice(&(LEDGER_FORMAT_VERSION + 1).to_le_bytes());
        let mut corrupt = record().encode();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0xff;
        // (name, file contents, adoptee, the state file's token, the
        // refusal's code — `None` where nothing is refused)
        type Case<'a> = (
            &'a str,
            Option<Vec<u8>>,
            Option<Adoptee<'a>>,
            Option<u64>,
            Option<&'a str>,
        );
        let cases: Vec<Case> = vec![
            ("missing", None, Some(me), Some(7), None),
            (
                "stale pid",
                Some(record().encode()),
                Some(Adoptee { pid: 4243, ..me }),
                Some(7),
                Some("process"),
            ),
            (
                "stale start time",
                Some(record().encode()),
                Some(Adoptee {
                    start_ticks: 100,
                    ..me
                }),
                Some(7),
                Some("process"),
            ),
            ("corrupt", Some(corrupt), Some(me), Some(7), Some("corrupt")),
            (
                "version mismatch",
                Some(bumped),
                Some(me),
                Some(7),
                Some("format-version"),
            ),
            (
                "another stop's token",
                Some(record().encode()),
                Some(me),
                Some(8),
                Some("token"),
            ),
            (
                "state rewritten by an older build",
                Some(record().encode()),
                Some(me),
                None,
                Some("token"),
            ),
            (
                "nothing adopted",
                Some(record().encode()),
                None,
                Some(7),
                None,
            ),
        ];
        for (name, bytes, adoptee, token, code) in cases {
            let dir = tmpdir(&name.replace(' ', "-"));
            let plant = || {
                if let Some(b) = &bytes {
                    std::fs::write(LedgerRecord::path_in(&dir), b).unwrap();
                }
            };
            plant();
            let got = judge_for_adoption(&dir, bound(), adoptee, token, &ifs());
            match (&got, code) {
                (Consumed::Refused(r), Some(code)) => assert_eq!(r.code(), code, "{name}"),
                (Consumed::Missing | Consumed::NotAdopted, None) => {}
                (other, _) => panic!("{name}: {other:?}"),
            }
            assert!(
                !LedgerRecord::path_in(&dir).exists(),
                "{name}: the record must be consumed either way"
            );
            plant();
            assert_eq!(
                consume_for_adoption(&dir, bound(), adoptee, token, &ifs()),
                None,
                "{name}: must fall back to the dump path"
            );
            assert!(!LedgerRecord::path_in(&dir).exists(), "{name}");
            let _ = std::fs::remove_dir_all(&dir);
        }
        // And the one that checks out.
        let dir = tmpdir("usable");
        record().write(&dir).unwrap();
        assert_eq!(
            consume_for_adoption(&dir, bound(), Some(me), Some(7), &ifs()),
            Some(record())
        );
        assert!(!LedgerRecord::path_in(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Larger than the bound: refused by name from the file's size,
    /// never read — the second file is sparse, and reading it whole
    /// would allocate 64 GiB — and consumed like any refusal. A record
    /// within the bound is still adopted.
    #[test]
    fn a_record_past_the_size_bound_is_refused_unread() {
        let dir = tmpdir("too-large");
        let max = record().encode().len() as u64;
        for len in [max + 1, 1 << 36] {
            record().write(&dir).unwrap();
            let f = std::fs::OpenOptions::new()
                .write(true)
                .open(LedgerRecord::path_in(&dir))
                .unwrap();
            f.set_len(len).unwrap();
            drop(f);
            match judge(&dir, max) {
                Consumed::Refused(r @ Refusal::TooLarge { .. }) => {
                    assert_eq!(r, Refusal::TooLarge { len, max });
                    assert_eq!(r.code(), "too-large");
                    assert!(r.detail().contains("too large"), "{}", r.detail());
                }
                other => panic!("{len}: {other:?}"),
            }
            assert!(!LedgerRecord::path_in(&dir).exists(), "{len}: consumed");
        }
        // Exactly at the bound is a record like any other.
        record().write(&dir).unwrap();
        assert_eq!(judge(&dir, max), Consumed::Usable(record()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A record anyone but this daemon's uid could have written is
    /// refused by name and never read, whatever its contents: here a
    /// perfectly good record, made group- or world-writable, or sitting
    /// in a directory others can write. Any uid can run this (it only
    /// chmods its own files).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_record_others_could_have_written_is_refused_unread() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tmpdir("untrusted");
        let path = LedgerRecord::path_in(&dir);
        let untrusted = |dir: &Path| match judge(dir, bound()) {
            Consumed::Refused(r @ Refusal::Untrusted(_)) => {
                assert_eq!(r.code(), "untrusted");
                r.detail()
            }
            other => panic!("{other:?}"),
        };
        for mode in [0o620, 0o602, 0o666] {
            record().write(&dir).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let why = untrusted(&dir);
            assert!(
                why.contains("untrusted ownership/permissions")
                    && why.contains("writable by group or others"),
                "{mode:o}: {why}"
            );
            assert!(!path.exists(), "{mode:o}: consumed");
        }
        for mode in [0o775, 0o757] {
            record().write(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let why = untrusted(&dir);
            assert!(why.contains("the directory"), "{mode:o}: {why}");
            assert!(!path.exists(), "{mode:o}: consumed");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        // The same record, from a trusted place, is adopted.
        record().write(&dir).unwrap();
        assert_eq!(judge(&dir, bound()), Consumed::Usable(record()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Owned by another uid: the record, or the directory holding it.
    /// Needs root to chown; skipped for other users (CI's qemu job and
    /// the Docker harness run it as root).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_record_owned_by_another_uid_is_refused_when_running_as_root() {
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root to chown");
            return;
        }
        const NOBODY: u32 = 65534;
        let dir = tmpdir("foreign");
        let path = LedgerRecord::path_in(&dir);
        record().write(&dir).unwrap();
        std::os::unix::fs::chown(&path, Some(NOBODY), None).unwrap();
        match judge(&dir, bound()) {
            Consumed::Refused(Refusal::Untrusted(why)) => {
                assert!(why.contains("owned by uid 65534"), "{why}")
            }
            other => panic!("{other:?}"),
        }
        assert!(!path.exists(), "consumed");

        record().write(&dir).unwrap();
        std::os::unix::fs::chown(&dir, Some(NOBODY), None).unwrap();
        match judge(&dir, bound()) {
            Consumed::Refused(Refusal::Untrusted(why)) => {
                assert!(
                    why.contains("the directory") && why.contains("owned by uid 65534"),
                    "{why}"
                )
            }
            other => panic!("{other:?}"),
        }
        assert!(!path.exists(), "consumed");
        std::os::unix::fs::chown(&dir, Some(0), None).unwrap();

        record().write(&dir).unwrap();
        assert_eq!(judge(&dir, bound()), Consumed::Usable(record()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The bound is the widest record the format holds for a given
    /// capacity, measured against `encode` itself rather than restated:
    /// the header with every name at the format's limit and a row for
    /// every prefix length, and each route with a path set of its own
    /// holding a path at its widest. Equal, not just within — a field
    /// added to the format without its bound fails here.
    #[test]
    fn the_size_bound_is_the_widest_record_the_format_holds() {
        let long = |c: char| c.to_string().repeat(u16::MAX as usize);
        let interfaces: Vec<(String, u32)> = ['a', 'b', 'c', 'd']
            .into_iter()
            .map(|c| (long(c), u32::MAX))
            .collect();
        let counts = (0..=32u8)
            .chain(0..=128u8)
            .map(|len| (long('t'), len, u64::MAX))
            .collect();
        let header = LedgerRecord {
            pid: i32::MAX,
            start_ticks: u64::MAX,
            boot_id: long('b'),
            token: u64::MAX,
            body: LedgerBody {
                fingerprint: FibFingerprint { counts },
                interfaces,
                path_sets: vec![],
                entries: vec![],
            },
        };
        let n_ifs = header.body.interfaces.len();
        assert_eq!(
            header.encode().len() as u64,
            max_ledger_bytes(0, n_ifs),
            "the header at its widest"
        );

        // A path at its widest: a v6 nexthop and the wire's whole label
        // stack, which is where `WIRE_LABELS_MAX` comes from.
        let wire_labels = crate::vpp_api::generated::FibPath::default()
            .label_stack
            .len();
        assert_eq!(wire_labels as u64, WIRE_LABELS_MAX);
        let v6 = |i: u16| std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i);
        let widest = |i: u16| PathKey {
            nexthop: IpAddr::V6(v6(i)),
            sw_if_index: u32::MAX,
            weight: u8::MAX,
            preference: u8::MAX,
            kind: u32::MAX,
            flags: u32::MAX,
            proto: u32::MAX,
            labels: vec![(u32::MAX, u8::MAX, u8::MAX, u8::MAX); wire_labels],
        };
        let mut full = header.clone();
        for i in 0..3u16 {
            full.body.path_sets.push(vec![widest(i)]);
            full.body.entries.push((
                IpPrefix::V6 {
                    addr: v6(i).octets(),
                    prefix_len: 128,
                },
                Some(u32::from(i)),
            ));
        }
        assert_eq!(
            full.encode().len() as u64,
            max_ledger_bytes(3, n_ifs),
            "three routes, each through a set of its own at its widest"
        );

        // What this module installs is narrower than the charge: an
        // unlabelled path (`fib_sync::wire_path`), so four of them in a
        // set of the route's own still fit it.
        let mut ecmp = header.clone();
        ecmp.body.path_sets.push(
            (1..=4u16)
                .map(|i| crate::fib_sync::installed_path_key(IpAddr::V6(v6(i)), u32::MAX))
                .collect(),
        );
        ecmp.body.entries.push((
            IpPrefix::V6 {
                addr: v6(0).octets(),
                prefix_len: 128,
            },
            Some(0),
        ));
        assert!(ecmp.encode().len() as u64 <= max_ledger_bytes(1, n_ifs));
    }

    /// At the default sizing with `v6 on`, the bound is far past any
    /// table this engine admits in practice (the reference router's
    /// 1.09M-route table preserves to ~11 MB) and still a bound.
    #[test]
    fn the_default_sizing_bounds_the_ledger_far_past_a_full_table() {
        let sizing =
            crate::startup_conf::derive_sizing(crate::DEFAULT_EXPECTED_ROUTES, 4, true).unwrap();
        let routes = crate::startup_conf::route_capacity(&sizing)
            + crate::startup_conf::route_capacity_v6(&sizing);
        let max = max_ledger_bytes(routes, 4);
        assert!(max > 20 * 11_000_000, "{max}");
        assert!(max < 1 << 30, "{max}");
    }

    /// Bring-up's refusals reach the event log as the same event the
    /// later stages record, with the check that refused as its `stage`;
    /// the codes are distinct, and none collides with a later stage's.
    #[test]
    fn a_bring_up_refusal_records_the_check_that_refused_it() {
        let all = [
            Refusal::Untrusted("x".into()),
            Refusal::TooLarge { len: 2, max: 1 },
            Refusal::Unreadable("x".into()),
            Refusal::Unremovable("x".into()),
            Refusal::Corrupt("x".into()),
            Refusal::FormatVersion { found: 0 },
            Refusal::Process("x".into()),
            Refusal::Token("x".into()),
            Refusal::Interfaces("x".into()),
        ];
        let codes: std::collections::BTreeSet<&str> = all.iter().map(Refusal::code).collect();
        assert_eq!(codes.len(), all.len(), "distinct codes");
        for later in ["fingerprint", "seed", "fingerprint-moved", "verify"] {
            assert!(!codes.contains(later), "{later}");
        }
        let r = Refusal::TooLarge { len: 2, max: 1 };
        let ev = r.event();
        assert_eq!(ev.kind(), event_kind::PRESERVED_LEDGER_REJECTED);
        let rec = ev.into_record();
        assert_eq!(rec.level, event_log::Level::Warn);
        assert_eq!(rec.fields["stage"], "too-large");
        assert_eq!(rec.fields["reason"], r.detail().as_str());
        assert!(r
            .to_string()
            .starts_with("preserved route ledger not used: "));
    }

    /// A record of a dual-stack ledger — v6 prefixes through v6 next
    /// hops, beside v4 — round-trips exactly, with both families'
    /// fingerprints.
    #[test]
    fn a_dual_stack_record_round_trips() {
        let dir = tmpdir("dual");
        let v6nh = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1));
        let mut r = record();
        r.body.fingerprint = FibFingerprint {
            counts: vec![
                ("ipv4-VRF:0".into(), 24, 2),
                ("ipv6-VRF:0".into(), 48, 1),
                ("ipv6-VRF:0".into(), 128, 3),
            ],
        };
        r.body
            .path_sets
            .push(vec![crate::fib_sync::installed_path_key(v6nh, 3)]);
        let v6_set = (r.body.path_sets.len() - 1) as u32;
        r.body.entries.push((
            IpPrefix::V6 {
                addr: [
                    0x20, 0x01, 0x0d, 0xb8, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                prefix_len: 48,
            },
            Some(v6_set),
        ));
        r.write(&dir).unwrap();
        let back = LedgerRecord::take(&dir, bound())
            .unwrap()
            .expect("the record");
        assert_eq!(back, r);
        let p = &back.body.path_sets[v6_set as usize][0];
        assert_eq!(p.nexthop, v6nh);
        assert_eq!(
            p.proto,
            crate::vpp_api::generated::FIB_API_PATH_NH_PROTO_IP6
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `show ip6 fib summary` exactly as VPP v26.06 prints it —
    /// `ip6_fib_table_show`'s header, then `%=20s%=16s` and
    /// `%=20d%=16lld` rows (centred, where v4's are right-aligned) — reads
    /// into the same fingerprint shape as v4's.
    #[test]
    fn the_ip6_fib_summary_parses_in_vpps_own_layout() {
        let row = |len: u32, n: u64| format!("{:^20}{:^16}\n", len, n);
        let mut text = String::from(
            "ipv6-VRF:0, fib_index:0, flow hash:[src dst sport dport proto flowlabel ] \
             epoch:0 flags:none locks:[default-route:1, ]\n",
        );
        text.push_str(&format!("{:^20}{:^16}\n", "Prefix length", "Count"));
        text.push_str(&row(128, 12));
        text.push_str(&row(48, 251_000));
        text.push_str(&row(10, 1));
        text.push_str(&row(0, 1));
        let mut fp = FibFingerprint::default();
        assert_eq!(fp.absorb(&text), 4);
        assert_eq!(
            fp.counts,
            vec![
                ("ipv6-VRF:0".into(), 0, 1),
                ("ipv6-VRF:0".into(), 10, 1),
                ("ipv6-VRF:0".into(), 48, 251_000),
                ("ipv6-VRF:0".into(), 128, 12),
            ]
        );
        // Folded after a v4 summary, the two families stay apart.
        let mut both = FibFingerprint::default();
        both.absorb(
            "ipv4-VRF:0, fib_index:0, flow hash:[] epoch:0 flags:none locks:[]\n\
             \x20   Prefix length         Count\n\
             \x20                 24               7\n",
        );
        both.absorb(&text);
        assert_eq!(both.counts.len(), 5);
        assert!(both.counts.contains(&("ipv4-VRF:0".into(), 24, 7)));
    }

    #[test]
    fn the_fib_summary_parses_per_table_and_ignores_the_rest() {
        let text = "\
ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto flowlabel ] epoch:0 flags:none locks:[default-route:1, ]
    Prefix length         Count
                   0               1
                  24          900000
                  32              17
ipv4-VRF:7, fib_index:1, flow hash:[src dst ] epoch:0 flags:none locks:[CLI:1, ]
    Prefix length         Count
                  32               2
";
        let mut fp = FibFingerprint::default();
        assert_eq!(fp.absorb(text), 4);
        assert_eq!(
            fp.counts,
            vec![
                ("ipv4-VRF:0".into(), 0, 1),
                ("ipv4-VRF:0".into(), 24, 900_000),
                ("ipv4-VRF:0".into(), 32, 17),
                ("ipv4-VRF:7".into(), 32, 2),
            ]
        );
        // A lock count moving is not a route changing.
        let relocked = text.replace("default-route:1", "default-route:2");
        let mut again = FibFingerprint::default();
        again.absorb(&relocked);
        assert_eq!(again, fp);
        // An answer with no table in it reads as nothing, not as empty.
        assert_eq!(
            FibFingerprint::default().absorb("unknown input `summary'"),
            0
        );
    }
}
