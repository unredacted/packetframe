//! Persistence for flow-export's kernel sampler attachments: one cls_bpf
//! filter on each `kernel-sample` interface's clsact **ingress**.
//!
//! Mirror of guard's `tc_links.rs` (itself fast-path's); when one is
//! updated, the others likely need the same change. Its own file, because
//! each module's detach tears down every record in its file: a
//! fast-path- or guard-scoped detach must never remove flow-export's
//! filters, nor the reverse.
//!
//! cls_bpf filters live as long as their clsact qdisc, not the process,
//! so the attach persists the kernel-assigned `(priority, handle)` here
//! and forgets aya's link; `packetframe detach` rebuilds each with
//! `SchedClassifierLink::attached()` and removes it.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const TC_LINKS_FILENAME: &str = "flow-export-tc-links.json";
/// Far past any record of a host's interfaces: a bound on what is read.
const MAX_LINKS_BYTES: u64 = 1 << 20;

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

    /// Not read: another account could have written it, or it is past
    /// [`MAX_LINKS_BYTES`]. Its contents decide which filters root
    /// removes.
    #[error("refusing {path:?}: {why}; remove the filters with `tc filter del dev <iface> ingress`, then the file")]
    Refused { path: PathBuf, why: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcLinksFile {
    pub links: Vec<TcLinkRecord>,
}

/// One attached cls_bpf filter: the tuple
/// `SchedClassifierLink::attached()` needs to reconstruct it (always
/// ingress).
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
    state_dir.join(TC_LINKS_FILENAME)
}

/// Atomic write-then-rename, mirroring fast-path's `tc_links::save`:
/// through [`write_record`], so a symlink at `flow-export-tc-links.json.tmp`
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
/// Read only if this daemon's own uid could have put it there, as
/// [`read_record`] says: a planted record would name the filters a root
/// detach removes.
pub fn load(state_dir: &Path) -> Result<Option<TcLinksFile>, TcLinksError> {
    let path = file_path(state_dir);
    let Some(raw) = read_record(&path)? else {
        return Ok(None);
    };
    serde_json::from_slice(&raw)
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

/// Through [`packetframe_common::statefile::read_owned_no_follow`]: no
/// symlink at any component, owner and mode checked on the open
/// descriptors, a FIFO refused rather than waited on, at most
/// [`MAX_LINKS_BYTES`].
#[cfg(target_os = "linux")]
fn read_record(path: &Path) -> Result<Option<Vec<u8>>, TcLinksError> {
    use packetframe_common::statefile::{read_owned_no_follow, OwnedReadError};
    read_owned_no_follow(path, MAX_LINKS_BYTES).map_err(|e| match e {
        OwnedReadError::Io(source) => TcLinksError::Io {
            path: path.to_owned(),
            source,
        },
        e => TcLinksError::Refused {
            path: path.to_owned(),
            why: e.to_string(),
        },
    })
}

#[cfg(not(target_os = "linux"))]
fn read_record(path: &Path) -> Result<Option<Vec<u8>>, TcLinksError> {
    match std::fs::read(path) {
        Ok(r) => Ok(Some(r)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(TcLinksError::Io {
            path: path.to_owned(),
            source,
        }),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_idempotent_remove() {
        let dir =
            std::env::temp_dir().join(format!("pf-flow-export-tc-links-{}", std::process::id()));
        let file = TcLinksFile {
            links: vec![TcLinkRecord {
                iface: "eth9".into(),
                ifindex: 42,
                priority: 49152,
                handle: 1,
            }],
        };
        save(&dir, &file).unwrap();
        let loaded = load(&dir).unwrap().expect("file present");
        assert_eq!(loaded.links.len(), 1);
        assert_eq!(loaded.links[0].iface, "eth9");
        assert_eq!(loaded.links[0].ifindex, 42);
        remove(&dir).unwrap();
        assert!(load(&dir).unwrap().is_none());
        remove(&dir).unwrap(); // second remove is a no-op
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The filename must never collide with fast-path's `tc-links.json`
    /// or guard's: a detach scoped to either destroys its own file.
    #[test]
    fn state_filename_is_flow_exports() {
        let p = file_path(Path::new("/var/lib/packetframe/state"));
        assert_eq!(
            p,
            Path::new("/var/lib/packetframe/state/flow-export-tc-links.json")
        );
    }

    #[cfg(target_os = "linux")]
    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pf-flow-export-tc-links-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        use std::os::unix::fs::PermissionsExt;
        // Closed whatever the umask: `load` refuses a directory others
        // can write, which would hide what a test means to show.
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        d
    }

    #[cfg(target_os = "linux")]
    fn sample() -> TcLinksFile {
        TcLinksFile {
            links: vec![TcLinkRecord {
                iface: "eth9".into(),
                ifindex: 42,
                priority: 49152,
                handle: 1,
            }],
        }
    }

    /// A symlink at the temp name fails the save, naming the temp file,
    /// and nothing is written through it or renamed into place. By
    /// pathname, `fs::write` truncated the link's target and the rename
    /// then moved the link itself to `flow-export-tc-links.json`.
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

    /// A record another account could have planted is not read: not
    /// through a symlink, and not when the file is writable by others.
    #[cfg(target_os = "linux")]
    #[test]
    fn load_refuses_a_record_it_cannot_trust() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("untrusted");
        let elsewhere = dir.join("elsewhere.json");
        std::fs::write(&elsewhere, serde_json::to_vec(&sample()).unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, file_path(&dir)).unwrap();
        assert!(
            matches!(load(&dir), Err(TcLinksError::Io { .. })),
            "read through a symlink"
        );
        std::fs::remove_file(file_path(&dir)).unwrap();

        save(&dir, &sample()).unwrap();
        std::fs::set_permissions(file_path(&dir), std::fs::Permissions::from_mode(0o666)).unwrap();
        // Refused for the file's mode, not for anything else about the
        // directory.
        match load(&dir) {
            Err(TcLinksError::Refused { why, .. }) => assert!(
                why.contains("tc-links.json is writable by group or others"),
                "{why}"
            ),
            other => panic!("a world-writable record: {other:?}"),
        }
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
