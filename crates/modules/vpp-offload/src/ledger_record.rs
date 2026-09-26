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
//!   length inside VPP), read at the stop, and the adoption re-reads
//!   them before seeding. A `vppctl` edit, a second client, anything
//!   that added or removed a route shows up as a count.
//! - *And the routes are really there, through those paths.* The
//!   adoption's verify probes VPP against the seeded ledger with the
//!   PATHS compared too ([`crate::verify::verify_paths`]); a
//!   disagreement discards the seed and falls back to the dump path.
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

use packetframe_common::fib::IpPrefix;

use crate::sink::PathKey;

/// The record's file name, beside `vpp-offload.json` in `state-dir`.
pub const LEDGER_FILE_NAME: &str = "vpp-route-ledger.bin";

/// Bump on any layout change. A record of another version is refused,
/// which costs one dump-path adoption and nothing else.
pub const LEDGER_FORMAT_VERSION: u32 = 1;

const MAGIC: &[u8; 8] = b"PFVPPLGR";

/// Path-set index meaning "paths unknown" — a route the previous
/// process held without having observed its paths (a dump adoption it
/// never re-sent). Seeded as installed; never skipped, never path-checked.
const NO_PATHS: u32 = u32::MAX;

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

/// Why a record was not used. Every one of these falls back to the
/// dump path; none fails the adoption.
fn refuse(why: impl std::fmt::Display) -> String {
    format!("preserved route ledger not used: {why}")
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
    ) -> Result<(), String> {
        if (self.pid, self.start_ticks, self.boot_id.as_str()) != (pid, start_ticks, boot_id) {
            return Err(refuse(format!(
                "it describes VPP pid {} (start {}, boot {}) but the adopted process is pid \
                 {pid} (start {start_ticks}, boot {boot_id})",
                self.pid, self.start_ticks, self.boot_id
            )));
        }
        match token {
            Some(t) if t == self.token => {}
            Some(_) => {
                return Err(refuse(
                    "the state file's ledger token is a different stop's, so another daemon \
                     wrote this VPP's record after this ledger was preserved",
                ))
            }
            None => {
                return Err(refuse(
                    "the state file carries no ledger token — rewritten since the stop that \
                     preserved this ledger (another adopter, or a build that predates it)",
                ))
            }
        }
        let mut mine = self.body.interfaces.clone();
        let mut theirs = recorded_interfaces.to_vec();
        mine.sort();
        theirs.sort();
        if mine != theirs {
            return Err(refuse(format!(
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
            for (nh, idx) in set {
                put_addr(&mut out, *nh);
                out.extend_from_slice(&idx.to_le_bytes());
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
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < MAGIC.len() + 4 + 8 {
            return Err(refuse("the file is too short to be a record"));
        }
        let (body, sum) = bytes.split_at(bytes.len() - 8);
        let sum = u64::from_le_bytes(sum.try_into().expect("8 bytes"));
        if &body[..MAGIC.len()] != MAGIC {
            return Err(refuse("the file is not a preserved route ledger"));
        }
        let mut r = Reader {
            buf: body,
            at: MAGIC.len(),
        };
        let version = r.u32()?;
        if version != LEDGER_FORMAT_VERSION {
            return Err(refuse(format!(
                "it is format version {version} and this binary reads \
                 {LEDGER_FORMAT_VERSION}"
            )));
        }
        // Checked after the version, so a future layout is named as such
        // rather than as corruption.
        if fnv1a(body) != sum {
            return Err(refuse(
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
            let mut set = Vec::with_capacity(m.min(r.remaining() / 9));
            for _ in 0..m {
                let nh = r.addr()?;
                set.push((nh, r.u32()?));
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
                    return Err(refuse(format!(
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
                return Err(refuse(format!(
                    "an entry names path set {set} of {}",
                    path_sets.len()
                )));
            };
            entries.push((prefix, set));
        }
        if r.remaining() != 0 {
            return Err(refuse("trailing bytes after the last entry"));
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
    /// something there and it is not a usable record (unreadable,
    /// planted symlink, corrupt, another version); it is removed too.
    pub fn take(state_dir: &Path) -> Result<Option<Self>, String> {
        let path = Self::path_in(state_dir);
        let read = read_record(&path);
        if matches!(read, Ok(None)) {
            return Ok(None);
        }
        // `unlinkat` removes a planted symlink itself, never its target.
        let removed = Self::remove(state_dir);
        let parsed = match read {
            Ok(Some(bytes)) => Self::decode(&bytes).map(Some),
            Ok(None) => unreachable!("returned above"),
            Err(e) => Err(refuse(format!("{}: {e}", path.display()))),
        };
        match removed {
            // A record that cannot be removed can be read again by the
            // next start, after this one has changed VPP — refusing it
            // here is what keeps "used once" true.
            Err(e) => Err(refuse(format!(
                "it could not be removed after reading ({e}), so it cannot be consumed once"
            ))),
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

/// The process an attach is adopting, as the record must name it.
#[derive(Debug, Clone, Copy)]
pub struct Adoptee<'a> {
    pub pid: i32,
    pub start_ticks: u64,
    pub boot_id: &'a str,
}

/// The adoption's half, whole: consume whatever record `state_dir` holds
/// and return it only if it describes `adoptee` under the state file's
/// `token` and `recorded` interfaces. `adoptee` is `None` when nothing is
/// being adopted — a record is then consumed and discarded, because the
/// VPP it describes is not the one this daemon will run.
///
/// Never an error: every refusal is logged with its reason and answers
/// `None`, which is the dump path every adoption took before the record
/// existed. That is the whole upgrade story too — a state file an older
/// build wrote has no token and no record beside it.
pub fn consume_for_adoption(
    state_dir: &Path,
    adoptee: Option<Adoptee<'_>>,
    token: Option<u64>,
    recorded: &[(String, u32)],
) -> Option<LedgerRecord> {
    match (LedgerRecord::take(state_dir), adoptee) {
        (Ok(None), None) => None,
        (Ok(None), Some(_)) => {
            tracing::info!(
                "no preserved route ledger (the previous stop was not a clean preserving \
                 exit, or was an older build); this adoption reads VPP's FIB — on a steered \
                 VPP that means unsteering while it does"
            );
            None
        }
        (Err(why), _) => {
            tracing::warn!(reason = %why, "this adoption reads VPP's FIB instead");
            None
        }
        (Ok(Some(_)), None) => {
            tracing::info!(
                "preserved route ledger discarded: the VPP it describes is not being adopted"
            );
            None
        }
        (Ok(Some(rec)), Some(a)) => {
            match rec.check_adoptee(a.pid, a.start_ticks, a.boot_id, token, recorded) {
                Ok(()) => Some(rec),
                Err(why) => {
                    tracing::warn!(reason = %why, "this adoption reads VPP's FIB instead");
                    None
                }
            }
        }
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

    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        if self.remaining() < n {
            return Err(refuse("the record ends mid-field"));
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

    fn i32(&mut self) -> Result<i32, String> {
        Ok(i32::from_le_bytes(self.bytes()?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.bytes()?))
    }

    /// A count of items at least `min_item` bytes each, refused when the
    /// rest of the record could not possibly hold that many — so a
    /// corrupt count cannot ask for a multi-gigabyte allocation.
    fn count(&mut self, min_item: usize) -> Result<usize, String> {
        let n = self.u32()? as usize;
        if n.saturating_mul(min_item) > self.remaining() {
            return Err(refuse(format!(
                "it claims {n} items where {} bytes remain",
                self.remaining()
            )));
        }
        Ok(n)
    }

    fn string(&mut self) -> Result<String, String> {
        let n = self.u16()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| refuse("a name is not UTF-8"))
    }

    fn addr(&mut self) -> Result<IpAddr, String> {
        match self.u8()? {
            4 => Ok(IpAddr::V4(self.bytes::<4>()?.into())),
            6 => Ok(IpAddr::V6(self.bytes::<16>()?.into())),
            f => Err(refuse(format!("a path names address family {f}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pf-ledger-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn nh(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, d))
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
                path_sets: vec![vec![(nh(1), 3)], vec![(nh(1), 3), (nh(2), 3)]],
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
        assert_eq!(LedgerRecord::take(&dir).unwrap(), Some(r));
        assert!(
            !LedgerRecord::path_in(&dir).exists(),
            "taking a record consumes it"
        );
        assert_eq!(LedgerRecord::take(&dir).unwrap(), None, "used once");
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
        assert!(e.contains("format version"), "{e}");
    }

    /// A corrupt record is refused AND removed: the next start must not
    /// find it again.
    #[test]
    fn a_corrupt_record_is_refused_and_consumed() {
        let dir = tmpdir("corrupt");
        std::fs::write(
            LedgerRecord::path_in(&dir),
            b"PFVPPLGR\x01\0\0\0 not a record",
        )
        .unwrap();
        assert!(LedgerRecord::take(&dir).is_err());
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
            LedgerRecord::take(&dir).is_err(),
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
        for (pid, ticks, boot, token, ifs, leg) in [
            (4243, 99, "boot-a", Some(7), ifs.clone(), "pid"),
            (4242, 98, "boot-a", Some(7), ifs.clone(), "start"),
            (4242, 99, "boot-b", Some(7), ifs.clone(), "boot"),
            (4242, 99, "boot-a", Some(8), ifs.clone(), "token"),
            (4242, 99, "boot-a", None, ifs.clone(), "no token"),
            (
                4242,
                99,
                "boot-a",
                Some(7),
                vec![("eth4".to_string(), 4)],
                "interfaces",
            ),
        ] {
            assert!(
                r.check_adoptee(pid, ticks, boot, token, &ifs).is_err(),
                "{leg} mismatch must refuse"
            );
        }
    }

    /// Every fallback the adoption can take on the record itself — and
    /// in every one the file is consumed, so a second start cannot find
    /// it after this one has changed VPP.
    #[test]
    fn every_record_fallback_answers_none_and_consumes_the_file() {
        let ifs = vec![("eth4".to_string(), 3)];
        let me = Adoptee {
            pid: 4242,
            start_ticks: 99,
            boot_id: "boot-a",
        };
        let mut bumped = record().encode();
        bumped[8..12].copy_from_slice(&(LEDGER_FORMAT_VERSION + 1).to_le_bytes());
        let mut corrupt = record().encode();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0xff;
        // (name, file contents, adoptee, the state file's token)
        type Case<'a> = (&'a str, Option<Vec<u8>>, Option<Adoptee<'a>>, Option<u64>);
        let cases: Vec<Case> = vec![
            ("missing", None, Some(me), Some(7)),
            (
                "stale pid",
                Some(record().encode()),
                Some(Adoptee { pid: 4243, ..me }),
                Some(7),
            ),
            (
                "stale start time",
                Some(record().encode()),
                Some(Adoptee {
                    start_ticks: 100,
                    ..me
                }),
                Some(7),
            ),
            ("corrupt", Some(corrupt), Some(me), Some(7)),
            ("version mismatch", Some(bumped), Some(me), Some(7)),
            (
                "another stop's token",
                Some(record().encode()),
                Some(me),
                Some(8),
            ),
            (
                "state rewritten by an older build",
                Some(record().encode()),
                Some(me),
                None,
            ),
            ("nothing adopted", Some(record().encode()), None, Some(7)),
        ];
        for (name, bytes, adoptee, token) in cases {
            let dir = tmpdir(&name.replace(' ', "-"));
            if let Some(b) = &bytes {
                std::fs::write(LedgerRecord::path_in(&dir), b).unwrap();
            }
            assert_eq!(
                consume_for_adoption(&dir, adoptee, token, &ifs),
                None,
                "{name}: must fall back to the dump path"
            );
            assert!(
                !LedgerRecord::path_in(&dir).exists(),
                "{name}: the record must be consumed either way"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
        // And the one that checks out.
        let dir = tmpdir("usable");
        record().write(&dir).unwrap();
        assert_eq!(
            consume_for_adoption(&dir, Some(me), Some(7), &ifs),
            Some(record())
        );
        assert!(!LedgerRecord::path_in(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
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
