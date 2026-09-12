//! Persisted learned table: one versioned JSON file per bridge,
//! written write-then-rename. The file is a *seed*, not an authority:
//! every entry loads as a candidate for a NUD_STALE install and the
//! kernel confirms or fails it. Portable; the engine calls `save` from
//! a blocking task.
//!
//! Every field has a writer (`to_json`) and a reader (`load`) by
//! construction: `PersistFileV1` derives both `Serialize` and
//! `Deserialize`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use packetframe_common::config::{format_mac, parse_mac_literal};

use crate::frame::Source;
use crate::table::{LearnedEntry, LearnedTable};

pub const PERSIST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistFileV1 {
    pub version: u32,
    /// Cross-checked at load: a file copied from another bridge must
    /// not seed this one.
    pub ifname: String,
    /// Unix seconds.
    pub written_at: u64,
    pub entries: Vec<PersistEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistEntry {
    pub ip: String,
    pub mac: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub source: String,
}

/// What `load` found.
#[derive(Debug)]
pub enum LoadOutcome {
    /// Entries within `max_age`, ready to insert; plus what was dropped.
    Loaded {
        entries: Vec<(IpAddr, LearnedEntry)>,
        expired: usize,
        bad_entries: usize,
        written_at: SystemTime,
    },
    /// No file: a first start.
    Missing,
    /// Present but unusable (unparsable, wrong version, wrong bridge).
    /// The next save overwrites it; nothing is seeded from it.
    Unusable(String),
}

pub fn file_path(dir: &Path, ifname: &str) -> PathBuf {
    dir.join(format!("{ifname}.json"))
}

fn unix_secs(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serialize a table. Entries are sorted by address so two writes of
/// the same table produce byte-identical files.
pub fn to_json(table: &LearnedTable, ifname: &str, now: SystemTime) -> String {
    let mut entries: Vec<PersistEntry> = table
        .iter()
        .map(|(ip, e)| PersistEntry {
            ip: ip.to_string(),
            mac: format_mac(e.mac),
            first_seen: unix_secs(e.first_seen),
            last_seen: unix_secs(e.last_seen),
            source: e.source.label().to_string(),
        })
        .collect();
    entries.sort_by(|a, b| a.ip.cmp(&b.ip));
    let file = PersistFileV1 {
        version: PERSIST_VERSION,
        ifname: ifname.to_string(),
        written_at: unix_secs(now),
        entries,
    };
    // A struct of strings and integers cannot fail to serialize.
    serde_json::to_string_pretty(&file).unwrap_or_default()
}

/// Write-then-rename, creating the directory on first use. Mirrors
/// the guard's `tc_links::save`.
pub fn save(path: &Path, json: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

/// Read and validate a file, dropping entries older than `max_age`.
/// `now_mono` anchors the restored monotonic timestamps so eviction
/// order survives a restart.
pub fn load(
    path: &Path,
    ifname: &str,
    now: SystemTime,
    now_mono: Instant,
    max_age: Duration,
) -> LoadOutcome {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return LoadOutcome::Missing,
        Err(e) => return LoadOutcome::Unusable(format!("read {}: {e}", path.display())),
    };
    let file: PersistFileV1 = match serde_json::from_str(&raw) {
        Ok(f) => f,
        Err(e) => return LoadOutcome::Unusable(format!("parse {}: {e}", path.display())),
    };
    if file.version != PERSIST_VERSION {
        return LoadOutcome::Unusable(format!(
            "unsupported persisted version {} (expected {PERSIST_VERSION}); starting empty",
            file.version
        ));
    }
    if file.ifname != ifname {
        return LoadOutcome::Unusable(format!(
            "file is for bridge `{}`, not `{ifname}`; ignored",
            file.ifname
        ));
    }
    let Some(written_at) = unix_time(file.written_at) else {
        return LoadOutcome::Unusable("written_at is out of range; ignored".into());
    };
    let now_secs = unix_secs(now);
    let cutoff = now_secs.saturating_sub(max_age.as_secs());
    let mut entries = Vec::with_capacity(file.entries.len());
    let mut expired = 0usize;
    let mut bad_entries = 0usize;
    for e in file.entries {
        let (Ok(ip), Ok(mac), Some(source), Some(first_seen), Some(last_seen)) = (
            e.ip.parse::<IpAddr>(),
            parse_mac_literal(&e.mac),
            Source::from_label(&e.source),
            unix_time(e.first_seen),
            unix_time(e.last_seen),
        ) else {
            bad_entries += 1;
            continue;
        };
        if e.last_seen < cutoff {
            expired += 1;
            continue;
        }
        let age = Duration::from_secs(now_secs.saturating_sub(e.last_seen));
        entries.push((
            ip,
            LearnedEntry {
                mac,
                first_seen,
                last_seen,
                last_seen_mono: now_mono.checked_sub(age).unwrap_or(now_mono),
                source,
                last_install: None,
            },
        ));
    }
    LoadOutcome::Loaded {
        entries,
        expired,
        bad_entries,
        written_at,
    }
}

/// A persisted second count as a `SystemTime`, or `None` when it does
/// not fit: the file is input, and `UNIX_EPOCH + Duration` panics on
/// overflow.
fn unix_time(secs: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

/// `(entry count, file age)` for `packetframe status`, which runs
/// without a daemon. `None` when the file is absent or unreadable.
pub fn summarize(path: &Path, now: SystemTime) -> Option<(usize, Duration)> {
    let raw = std::fs::read_to_string(path).ok()?;
    let file: PersistFileV1 = serde_json::from_str(&raw).ok()?;
    let age = Duration::from_secs(unix_secs(now).saturating_sub(file.written_at));
    Some((file.entries.len(), age))
}

/// Refuse a persist directory the daemon could not write to, at load
/// time rather than at the first debounced save minutes later.
pub fn ensure_dir_writable(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let probe = dir.join(format!(".probe-{}", std::process::id()));
    std::fs::write(&probe, b"").map_err(|e| format!("write probe in {}: {e}", dir.display()))?;
    std::fs::remove_file(&probe).map_err(|e| format!("remove probe in {}: {e}", dir.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicU64, Ordering};

    static N: AtomicU64 = AtomicU64::new(0);

    fn scratch() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pf-neigh-snoop-persist-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    const A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
    }

    #[test]
    fn round_trip_and_age_drop() {
        let dir = scratch();
        let path = file_path(&dir, "br0");
        let now = SystemTime::now();
        let mono = Instant::now();
        let mut t = LearnedTable::new(16);
        t.observe(ip(1), A, Source::ArpRequest, now, mono);
        t.observe(
            ip(2),
            A,
            Source::NeighborSolicitation,
            now - Duration::from_secs(20 * 86_400),
            mono,
        );
        save(&path, &to_json(&t, "br0", now)).unwrap();
        assert!(
            !path.with_extension("json.tmp").exists(),
            "tmp renamed away"
        );

        match load(&path, "br0", now, mono, Duration::from_secs(14 * 86_400)) {
            LoadOutcome::Loaded {
                entries,
                expired,
                bad_entries,
                ..
            } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(expired, 1);
                assert_eq!(bad_entries, 0);
                let (rip, e) = &entries[0];
                assert_eq!(*rip, ip(1));
                assert_eq!(e.mac, A);
                assert_eq!(e.source, Source::ArpRequest);
                assert!(e.last_install.is_none());
            }
            other => panic!("expected Loaded, got {other:?}"),
        }
        let (count, age) = summarize(&path, now).unwrap();
        assert_eq!(count, 2);
        assert!(age < Duration::from_secs(5));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deterministic_output() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let mono = Instant::now();
        let mut a = LearnedTable::new(16);
        let mut b = LearnedTable::new(16);
        for i in [3u8, 1, 2] {
            a.observe(ip(i), A, Source::ArpRequest, now, mono);
        }
        for i in [1u8, 2, 3] {
            b.observe(ip(i), A, Source::ArpRequest, now, mono);
        }
        assert_eq!(to_json(&a, "br0", now), to_json(&b, "br0", now));
    }

    #[test]
    fn missing_version_and_ifname_mismatch() {
        let dir = scratch();
        let path = file_path(&dir, "br0");
        let now = SystemTime::now();
        let mono = Instant::now();
        assert!(matches!(
            load(&path, "br0", now, mono, Duration::from_secs(1)),
            LoadOutcome::Missing
        ));
        let mut f = PersistFileV1 {
            version: 2,
            ifname: "br0".into(),
            written_at: 0,
            entries: vec![],
        };
        save(&path, &serde_json::to_string(&f).unwrap()).unwrap();
        match load(&path, "br0", now, mono, Duration::from_secs(1)) {
            LoadOutcome::Unusable(m) => {
                assert!(m.contains("unsupported persisted version 2"), "{m}")
            }
            other => panic!("{other:?}"),
        }
        f.version = PERSIST_VERSION;
        f.ifname = "br9".into();
        save(&path, &serde_json::to_string(&f).unwrap()).unwrap();
        match load(&path, "br0", now, mono, Duration::from_secs(1)) {
            LoadOutcome::Unusable(m) => assert!(m.contains("for bridge `br9`"), "{m}"),
            other => panic!("{other:?}"),
        }
        save(&path, "{not json").unwrap();
        assert!(matches!(
            load(&path, "br0", now, mono, Duration::from_secs(1)),
            LoadOutcome::Unusable(_)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_entries_are_skipped_not_fatal() {
        let dir = scratch();
        let path = file_path(&dir, "br0");
        let now = SystemTime::now();
        let secs = unix_secs(now);
        let f = PersistFileV1 {
            version: PERSIST_VERSION,
            ifname: "br0".into(),
            written_at: secs,
            entries: vec![
                PersistEntry {
                    ip: "192.0.2.1".into(),
                    mac: "02:00:00:00:00:0a".into(),
                    first_seen: secs,
                    last_seen: secs,
                    source: "arp_request".into(),
                },
                PersistEntry {
                    ip: "not-an-ip".into(),
                    mac: "02:00:00:00:00:0a".into(),
                    first_seen: secs,
                    last_seen: secs,
                    source: "arp_request".into(),
                },
                PersistEntry {
                    ip: "192.0.2.2".into(),
                    mac: "zz".into(),
                    first_seen: secs,
                    last_seen: secs,
                    source: "arp_request".into(),
                },
                PersistEntry {
                    ip: "192.0.2.3".into(),
                    mac: "02:00:00:00:00:0a".into(),
                    first_seen: secs,
                    last_seen: secs,
                    source: "carrier_pigeon".into(),
                },
                PersistEntry {
                    ip: "192.0.2.4".into(),
                    mac: "02:00:00:00:00:0a".into(),
                    first_seen: u64::MAX,
                    last_seen: secs,
                    source: "arp_request".into(),
                },
            ],
        };
        save(&path, &serde_json::to_string(&f).unwrap()).unwrap();
        match load(&path, "br0", now, Instant::now(), Duration::from_secs(60)) {
            LoadOutcome::Loaded {
                entries,
                bad_entries,
                ..
            } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(bad_entries, 4);
            }
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn out_of_range_written_at_is_unusable_not_a_panic() {
        let dir = scratch();
        let path = file_path(&dir, "br0");
        let f = PersistFileV1 {
            version: PERSIST_VERSION,
            ifname: "br0".into(),
            written_at: u64::MAX,
            entries: Vec::new(),
        };
        save(&path, &serde_json::to_string(&f).unwrap()).unwrap();
        match load(
            &path,
            "br0",
            SystemTime::now(),
            Instant::now(),
            Duration::from_secs(60),
        ) {
            LoadOutcome::Unusable(why) => assert!(why.contains("written_at"), "{why}"),
            other => panic!("{other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_writable_probe() {
        let dir = scratch();
        ensure_dir_writable(&dir.join("nested")).unwrap();
        assert!(dir.join("nested").is_dir());
        assert!(
            std::fs::read_dir(dir.join("nested"))
                .unwrap()
                .next()
                .is_none(),
            "probe removed"
        );
        // A file where the directory should be is refused.
        let file = dir.join("file");
        std::fs::write(&file, b"x").unwrap();
        assert!(ensure_dir_writable(&file).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
