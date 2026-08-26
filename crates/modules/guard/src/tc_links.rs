//! Persistence for the guard's tc-egress filter attachments.
//!
//! Mirror of fast-path's `tc_links.rs`; when one is updated, the other
//! likely needs the same change. Separate file (not a shared helper)
//! because the state filename differs per module — fast-path's
//! `detach` tears down everything in the shared `tc-links.json`
//! unconditionally, so guard records living there would be destroyed
//! by a fast-path-scoped detach. Records here are **always egress**
//! (per-module convention; fast-path's are always ingress), so no
//! direction field is stored.
//!
//! Netlink cls_bpf filters cannot be pinned as bpf_links: their
//! lifetime is the clsact qdisc's, so the kernel attach survives
//! process exit inherently. What does NOT survive is aya's in-process
//! `SchedClassifierLink` — it detaches on Drop — so the attach path
//! reads the kernel-assigned `(priority, handle)` pair, persists it
//! here, and forgets the link. `packetframe detach` reconstructs each
//! filter via `SchedClassifierLink::attached()` and detaches it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const GUARD_TC_LINKS_FILENAME: &str = "guard-tc-links.json";

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
/// (attach type is always egress for the guard).
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
    /// PR #205.
    pub ifindex: u32,
    pub priority: u16,
    pub handle: u32,
}

pub fn file_path(state_dir: &Path) -> PathBuf {
    state_dir.join(GUARD_TC_LINKS_FILENAME)
}

/// Atomic write-then-rename, mirroring fast-path's `tc_links::save`.
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
        let dir = std::env::temp_dir().join(format!("pf-guard-tc-links-{}", std::process::id()));
        let file = TcLinksFile {
            links: vec![TcLinkRecord {
                iface: "br3998".into(),
                ifindex: 42,
                priority: 49152,
                handle: 1,
            }],
        };
        save(&dir, &file).unwrap();
        let loaded = load(&dir).unwrap().expect("file present");
        assert_eq!(loaded.links.len(), 1);
        assert_eq!(loaded.links[0].iface, "br3998");
        assert_eq!(loaded.links[0].ifindex, 42);
        remove(&dir).unwrap();
        assert!(load(&dir).unwrap().is_none());
        remove(&dir).unwrap(); // second remove is a no-op
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The filename must never collide with fast-path's
    /// `tc-links.json` — a fast-path-scoped detach destroys that file.
    #[test]
    fn state_filename_is_guard_scoped() {
        let p = file_path(Path::new("/var/lib/packetframe/state"));
        assert_eq!(
            p,
            Path::new("/var/lib/packetframe/state/guard-tc-links.json")
        );
    }
}
