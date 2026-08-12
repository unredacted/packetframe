//! Write-then-rename, for every file a *reader outside this process*
//! polls.
//!
//! Two of those now — the Prometheus textfile and the module health
//! snapshot — which is why this is its own module rather than a helper
//! inside one of them. Both readers poll on their own schedule and
//! neither takes a lock, so a partially written file is not a rare race
//! but the ordinary outcome of overlapping a read with a write.
//!
//! On Linux the write happens relative to a directory descriptor
//! obtained by a component-wise no-follow walk (see
//! `crate::loader::create_and_open_dir_no_follow`), and the temp file
//! is opened `O_NOFOLLOW | O_EXCL | O_CREAT | 0600` against it — so
//! neither a symlink at the temp path (the May 2026 audit Slice 4
//! finding) nor one at any intermediate component (review finding on
//! the state writers) can redirect the privileged write.

use std::io::Write as _;
use std::path::Path;

/// Write `contents` to `path` atomically.
///
/// The rename is atomic on POSIX when source and dest are on the same
/// filesystem, which is what node_exporter's textfile collector relies
/// on to never read a half-written file.
//
// Reachable in production only from the Linux daemon paths (the metrics
// exporter and the health publisher), so a non-Linux build sees no
// caller. The lint is cfg'd rather than the code, so the macOS dev loop
// still compiles and still runs the tests that use it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn write(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    // The same filename with `.tmp` appended, so the temp file stays on
    // the same filesystem as the target. `with_extension("tmp")` would
    // drop the `.prom` and stop a second writer distinguishing ours.
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "no file name"))?;
    let tmp_name = format!("{name}.tmp");
    // On Linux everything happens relative to ONE directory descriptor
    // obtained by a component-wise no-follow walk — the same discipline
    // as the state-record writers, for the same reason: `O_NOFOLLOW` on
    // the temp file guards only the final component, so an intermediate
    // symlink in a configured path carried this root writer wherever it
    // pointed (review finding on the state writers; this is the same
    // primitive with different callers). A symlink anywhere in the path
    // fails `ELOOP` and the write is refused.
    #[cfg(target_os = "linux")]
    {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let dir = crate::loader::create_and_open_dir_no_follow(parent)?;
        {
            let mut f = crate::loader::openat_excl_with_retry(&dir, &tmp_name)?;
            f.write_all(contents)?;
            f.sync_all()?;
        }
        crate::loader::renameat_within(&dir, &tmp_name, name)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let tmp = path.with_file_name(&tmp_name);
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
    }
    Ok(())
}
