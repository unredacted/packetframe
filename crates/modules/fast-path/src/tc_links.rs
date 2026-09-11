//! Persistence for tc-datapath filter attachments (Phase T).
//!
//! Netlink cls_bpf filters cannot be pinned as bpf_links: their
//! lifetime is the clsact qdisc's, so the kernel attach survives
//! process exit inherently (the filter holds its own reference to the
//! program). What does NOT survive is aya's in-process
//! `SchedClassifierLink` — it detaches on Drop — so the attach path
//! reads the kernel-assigned `(priority, handle)` pair, persists it
//! here, and forgets the link. `packetframe detach` reconstructs each
//! filter via `SchedClassifierLink::attached()` and detaches it.
//!
//! Sibling of `registry.rs` (`<state-dir>/tc-links.json` next to
//! `attachments.json`); same atomic write-then-rename discipline.
//!
//! Mirror of guard's `tc_links.rs`; when one is updated, the other
//! likely needs the same change (guard's header explains why the two
//! stay separate files).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const TC_LINKS_FILENAME: &str = "tc-links.json";

#[derive(Debug, Error)]
pub enum TcLinksError {
    #[error("I/O error on {path:?}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON error on {path:?}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcLinksFile {
    pub links: Vec<TcLinkRecord>,
}

/// One attached cls_bpf filter: the tuple
/// `SchedClassifierLink::attached()` needs to reconstruct it
/// (attach type is always ingress for the fast-path datapath).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcLinkRecord {
    pub iface: String,
    /// The device's ifindex at attach time. Detach verifies it before
    /// reconstructing the filter: a same-name RECREATED device has a
    /// new ifindex, the recorded filter died with the original
    /// (qdisc lifetime), and `SchedClassifierLink::attached` resolves
    /// by name — a blind delete could remove an unrelated filter on
    /// the replacement whose `(priority, handle)` happens to match
    /// (the first auto-allocated tuple is common). Review finding,
    /// guard PR #205; same hole here.
    ///
    /// `#[serde(default)]` = 0 for records written by builds that
    /// predate this field. 0 is never a real ifindex; detach treats
    /// it as "unknown, skip the recreated-device check" (the
    /// pre-field behavior) rather than refusing to tear down a
    /// legacy deployment's filters.
    #[serde(default)]
    pub ifindex: u32,
    pub priority: u16,
    pub handle: u32,
}

pub fn file_path(state_dir: &Path) -> PathBuf {
    state_dir.join(TC_LINKS_FILENAME)
}

/// Atomic write-then-rename, mirroring `registry::save`.
pub fn save(state_dir: &Path, file: &TcLinksFile) -> Result<(), TcLinksError> {
    let path = file_path(state_dir);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(file).map_err(|source| TcLinksError::Json {
        path: path.clone(),
        source,
    })?;
    std::fs::create_dir_all(state_dir).map_err(|source| TcLinksError::Io {
        path: state_dir.to_path_buf(),
        source,
    })?;
    std::fs::write(&tmp, json).map_err(|source| TcLinksError::Io {
        path: tmp.clone(),
        source,
    })?;
    std::fs::rename(&tmp, &path).map_err(|source| TcLinksError::Io { path, source })
}

/// `Ok(None)` when the file doesn't exist (no tc attaches recorded).
pub fn load(state_dir: &Path) -> Result<Option<TcLinksFile>, TcLinksError> {
    let path = file_path(state_dir);
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(TcLinksError::Io { path, source }),
    };
    serde_json::from_str(&raw)
        .map(Some)
        .map_err(|source| TcLinksError::Json { path, source })
}

/// Missing file is fine (idempotent teardown).
pub fn remove(state_dir: &Path) -> Result<(), TcLinksError> {
    let path = file_path(state_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TcLinksError::Io { path, source }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_idempotent_remove() {
        let dir = std::env::temp_dir().join(format!("pf-tc-links-{}", std::process::id()));
        let file = TcLinksFile {
            links: vec![TcLinkRecord {
                iface: "eth5".into(),
                ifindex: 7,
                priority: 49152,
                handle: 1,
            }],
        };
        save(&dir, &file).unwrap();
        let loaded = load(&dir).unwrap().expect("file present");
        assert_eq!(loaded.links.len(), 1);
        assert_eq!(loaded.links[0].iface, "eth5");
        assert_eq!(loaded.links[0].ifindex, 7);
        assert_eq!(loaded.links[0].priority, 49152);
        assert_eq!(loaded.links[0].handle, 1);
        remove(&dir).unwrap();
        assert!(load(&dir).unwrap().is_none());
        remove(&dir).unwrap(); // second remove is a no-op
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A tc-links.json written by a pre-ifindex build must still load:
    /// deployed routers can carry one across an upgrade, and refusing
    /// to parse it would strand live filters with no teardown metadata.
    #[test]
    fn legacy_record_without_ifindex_loads_as_zero() {
        let raw = r#"{"links":[{"iface":"eth5","priority":49152,"handle":1}]}"#;
        let file: TcLinksFile = serde_json::from_str(raw).expect("legacy record parses");
        assert_eq!(file.links[0].ifindex, 0);
    }
}
