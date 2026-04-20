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
/// Serialize/Deserialize on the trait type itself — that's
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
pub fn save(state_dir: &Path, file: &RegistryFile) -> Result<(), RegistryError> {
    let final_path = path_for(state_dir);
    let tmp_path = final_path.with_extension("json.tmp");

    std::fs::create_dir_all(state_dir).map_err(|source| RegistryError::Io {
        path: state_dir.to_path_buf(),
        source,
    })?;

    let contents = serde_json::to_string_pretty(file).map_err(|source| RegistryError::Json {
        path: final_path.clone(),
        source,
    })?;

    std::fs::write(&tmp_path, contents).map_err(|source| RegistryError::Io {
        path: tmp_path.clone(),
        source,
    })?;

    std::fs::rename(&tmp_path, &final_path).map_err(|source| RegistryError::Io {
        path: final_path,
        source,
    })?;

    Ok(())
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
    if path.exists() {
        std::fs::remove_file(&path).map_err(|source| RegistryError::Io { path, source })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn tmp_dir() -> PathBuf {
        let n = TMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("pf-registry-{}-{n}", std::process::id()));
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
}
