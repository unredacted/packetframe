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

/// Atomic write-then-rename, mirroring fast-path's `tc_links::save`:
/// through [`write_record`], so a symlink at `guard-tc-links.json.tmp`
/// or at any component of `state-dir` fails the save instead of
/// choosing where this root daemon writes, and a `state-dir` the save
/// creates is never group- or world-writable whatever the umask.
pub fn save(state_dir: &Path, file: &TcLinksFile) -> Result<(), TcLinksError> {
    let path = file_path(state_dir);
    let json = serde_json::to_string_pretty(file).map_err(|source| TcLinksError::Json {
        path: path.clone(),
        source,
    })?;
    write_record(&path, json.as_bytes()).map_err(|source| {
        // Only the temp file's create can collide: something that is not
        // a stale regular file is at the temp name.
        let path = if source.kind() == std::io::ErrorKind::AlreadyExists {
            path.with_extension("json.tmp")
        } else {
            path
        };
        TcLinksError::Io { path, source }
    })
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
    match remove_record(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(TcLinksError::Io { path, source }),
    }
}

// The daemon writing this is root and `state-dir` may be writable by
// someone who is not, so on Linux the write and the unlink go through
// `packetframe_common::statefile`'s no-follow directory walk, as
// fast-path's records do. The non-Linux arms exist for the macOS dev
// loop's unit tests only.
#[cfg(target_os = "linux")]
fn write_record(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    packetframe_common::statefile::write_atomic(path, contents)
}

#[cfg(not(target_os = "linux"))]
fn write_record(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path)
}

#[cfg(target_os = "linux")]
fn remove_record(path: &Path) -> std::io::Result<()> {
    packetframe_common::statefile::remove_state_record(path)
}

#[cfg(not(target_os = "linux"))]
fn remove_record(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path)
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

    #[cfg(target_os = "linux")]
    fn scratch(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("pf-guard-tc-links-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[cfg(target_os = "linux")]
    fn sample() -> TcLinksFile {
        TcLinksFile {
            links: vec![TcLinkRecord {
                iface: "br3998".into(),
                ifindex: 42,
                priority: 49152,
                handle: 1,
            }],
        }
    }

    /// A symlink at the temp name fails the save, naming the temp file,
    /// and nothing is written through it or renamed into place. By
    /// pathname, `fs::write` truncated the link's target and the rename
    /// then moved the link itself to `guard-tc-links.json`.
    #[cfg(target_os = "linux")]
    #[test]
    fn save_refuses_a_symlink_at_the_temp_name() {
        let dir = scratch("tmp-link");
        let victim = dir.join("victim");
        std::fs::write(&victim, "do not truncate me").unwrap();
        let tmp = file_path(&dir).with_extension("json.tmp");
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        let Err(err) = save(&dir, &sample()) else {
            panic!("saved through the link at {}", tmp.display());
        };
        assert!(
            matches!(&err, TcLinksError::Io { path, .. } if *path == tmp),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "do not truncate me"
        );
        assert!(
            std::fs::symlink_metadata(file_path(&dir)).is_err(),
            "something was renamed into place"
        );

        std::fs::remove_file(&tmp).unwrap();
        save(&dir, &sample()).unwrap();
        assert_eq!(load(&dir).unwrap().unwrap().links[0].ifindex, 42);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A symlink at any component of `state-dir` fails `save` before
    /// anything is made or written where it points, and `remove`
    /// deletes nothing through one. By pathname, `create_dir_all`, the
    /// write and the rename all followed an intermediate link.
    #[cfg(target_os = "linux")]
    #[test]
    fn save_and_remove_refuse_a_symlink_in_the_state_dir_path() {
        let base = scratch("dir-link");
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        for state_dir in [link.join("state"), link.join("a").join("b"), link.clone()] {
            let Err(err) = save(&state_dir, &sample()) else {
                panic!("saved through the link at {}", state_dir.display());
            };
            assert!(
                err.to_string().contains("a symlink here is refused"),
                "{}: {err}",
                state_dir.display()
            );
        }
        assert_eq!(
            std::fs::read_dir(&real).unwrap().count(),
            0,
            "something was made or written through the link"
        );

        save(&real, &sample()).unwrap();
        let err = remove(&link).expect_err("remove through the link");
        assert!(
            err.to_string().contains("a symlink here is refused"),
            "{err}"
        );
        assert!(
            file_path(&real).exists(),
            "the record was deleted through the link"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
