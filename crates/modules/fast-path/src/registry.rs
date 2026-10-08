//! Pin registry persistence for fast-path attachments.
//!
//! SPEC.md §8 requires `detach` / `--all` to tear down every pinned
//! object deterministically. That requires a persistent record of what
//! was attached. We serialize the `Attachment` list to
//! `<state-dir>/attachments.json` after every successful attach; the
//! loader reads it at startup to reconcile, and `packetframe detach`
//! reads it to know what to tear down.

use std::path::{Path, PathBuf};

use packetframe_common::module::{Attachment, HookType};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const REGISTRY_FILENAME: &str = "attachments.json";

#[derive(Debug, Error)]
pub enum RegistryError {
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
pub struct RegistryFile {
    pub module: String,
    pub attachments: Vec<AttachmentRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentRecord {
    pub iface: String,
    pub hook: HookTypeRecord,
    pub prog_id: u32,
    pub pinned_path: PathBuf,
}

/// Serde-compatible mirror of [`HookType`]. Doesn't derive
/// Serialize/Deserialize on the trait type itself, that's
/// `packetframe-common`'s concern, and we'd rather not widen its
/// public surface just for this one consumer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookTypeRecord {
    NativeXdp,
    GenericXdp,
    TcIngress,
    TcEgress,
}

impl From<HookType> for HookTypeRecord {
    fn from(h: HookType) -> Self {
        match h {
            HookType::NativeXdp => Self::NativeXdp,
            HookType::GenericXdp => Self::GenericXdp,
            HookType::TcIngress => Self::TcIngress,
            HookType::TcEgress => Self::TcEgress,
        }
    }
}

impl From<HookTypeRecord> for HookType {
    fn from(h: HookTypeRecord) -> Self {
        match h {
            HookTypeRecord::NativeXdp => Self::NativeXdp,
            HookTypeRecord::GenericXdp => Self::GenericXdp,
            HookTypeRecord::TcIngress => Self::TcIngress,
            HookTypeRecord::TcEgress => Self::TcEgress,
        }
    }
}

impl From<Attachment> for AttachmentRecord {
    fn from(a: Attachment) -> Self {
        Self {
            iface: a.iface,
            hook: a.hook.into(),
            prog_id: a.prog_id,
            pinned_path: a.pinned_path,
        }
    }
}

impl From<AttachmentRecord> for Attachment {
    fn from(r: AttachmentRecord) -> Self {
        Self {
            iface: r.iface,
            hook: r.hook.into(),
            prog_id: r.prog_id,
            pinned_path: r.pinned_path,
        }
    }
}

pub fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join(REGISTRY_FILENAME)
}

/// Write the registry atomically: write-then-rename so readers never
/// see a half-written file.
///
/// Through [`write_record`], so a symlink at `attachments.json.tmp` or
/// at any component of `state-dir` fails the save instead of choosing
/// where this root daemon writes, and a `state-dir` the save creates is
/// never group- or world-writable whatever the umask. The loader saves
/// after each module's attach, so on a fresh install this can be the
/// first writer to make `state-dir`.
pub fn save(state_dir: &Path, file: &RegistryFile) -> Result<(), RegistryError> {
    let final_path = path_for(state_dir);
    let contents = serde_json::to_string_pretty(file).map_err(|source| RegistryError::Json {
        path: final_path.clone(),
        source,
    })?;
    write_record(&final_path, contents.as_bytes()).map_err(|source| {
        // Only the temp file's create can collide: something that is not
        // a stale regular file is at the temp name.
        let path = if source.kind() == std::io::ErrorKind::AlreadyExists {
            final_path.with_extension("json.tmp")
        } else {
            final_path
        };
        RegistryError::Io { path, source }
    })
}

pub fn load(state_dir: &Path) -> Result<Option<RegistryFile>, RegistryError> {
    let path = path_for(state_dir);
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&path).map_err(|source| RegistryError::Io {
        path: path.clone(),
        source,
    })?;
    let file = serde_json::from_str::<RegistryFile>(&raw)
        .map_err(|source| RegistryError::Json { path, source })?;
    Ok(Some(file))
}

pub fn remove(state_dir: &Path) -> Result<(), RegistryError> {
    let path = path_for(state_dir);
    match remove_record(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(RegistryError::Io { path, source }),
    }
}

// The daemon writing this is root and `state-dir` may be writable by
// someone who is not, so on Linux the write and the unlink go through
// `packetframe_common::statefile`'s no-follow directory walk, as
// `coalesce.json` does. The non-Linux arms exist for the macOS dev
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
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tmp_dir() -> PathBuf {
        let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("pf-registry-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn save_load_roundtrip() {
        let dir = tmp_dir();
        let file = RegistryFile {
            module: "fast-path".into(),
            attachments: vec![AttachmentRecord {
                iface: "eth0".into(),
                hook: HookTypeRecord::NativeXdp,
                prog_id: 42,
                pinned_path: PathBuf::from("/sys/fs/bpf/packetframe/fast-path/prog-eth0"),
            }],
        };
        save(&dir, &file).unwrap();
        let loaded = load(&dir).unwrap().unwrap();
        assert_eq!(loaded.module, "fast-path");
        assert_eq!(loaded.attachments.len(), 1);
        assert_eq!(loaded.attachments[0].iface, "eth0");
        assert_eq!(loaded.attachments[0].prog_id, 42);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_missing_returns_none() {
        let dir = tmp_dir();
        let loaded = load(&dir).unwrap();
        assert!(loaded.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_is_idempotent() {
        let dir = tmp_dir();
        remove(&dir).unwrap();
        remove(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    fn sample() -> RegistryFile {
        RegistryFile {
            module: "fast-path".into(),
            attachments: vec![AttachmentRecord {
                iface: "eth0".into(),
                hook: HookTypeRecord::NativeXdp,
                prog_id: 42,
                pinned_path: PathBuf::from("/sys/fs/bpf/packetframe/fast-path/prog-eth0"),
            }],
        }
    }

    /// A symlink at the temp name fails the save, naming the temp file,
    /// and nothing is written through it or renamed into place. By
    /// pathname, `fs::write` truncated the link's target and the rename
    /// then moved the link itself to `attachments.json`.
    #[cfg(target_os = "linux")]
    #[test]
    fn save_refuses_a_symlink_at_the_temp_name() {
        let dir = tmp_dir();
        let victim = dir.join("victim");
        std::fs::write(&victim, "do not truncate me").unwrap();
        let tmp = path_for(&dir).with_extension("json.tmp");
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        let Err(err) = save(&dir, &sample()) else {
            panic!("saved through the link at {}", tmp.display());
        };
        assert!(
            matches!(&err, RegistryError::Io { path, .. } if *path == tmp),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "do not truncate me"
        );
        assert!(
            std::fs::symlink_metadata(path_for(&dir)).is_err(),
            "something was renamed into place"
        );

        std::fs::remove_file(&tmp).unwrap();
        save(&dir, &sample()).unwrap();
        assert_eq!(load(&dir).unwrap().unwrap().attachments[0].prog_id, 42);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A symlink at any component of `state-dir` fails `save` before
    /// anything is made or written where it points, and `remove`
    /// deletes nothing through one. By pathname, `create_dir_all`, the
    /// write and the rename all followed an intermediate link.
    #[cfg(target_os = "linux")]
    #[test]
    fn save_and_remove_refuse_a_symlink_in_the_state_dir_path() {
        let base = tmp_dir();
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
            path_for(&real).exists(),
            "the registry was deleted through the link"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
