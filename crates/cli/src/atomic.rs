//! Write-then-rename, for every file a *reader outside this process*
//! polls.
//!
//! Two of those now — the Prometheus textfile and the module health
//! snapshot — which is why this is its own module rather than a helper
//! inside one of them. Both readers poll on their own schedule and
//! neither takes a lock, so a partially written file is not a rare race
//! but the ordinary outcome of overlapping a read with a write.
//!
//! The temp path is opened `O_NOFOLLOW | O_EXCL | O_CREAT | 0600` (see
//! [`crate::loader::create_excl_no_follow`]) so a pre-existing symlink
//! at the temp path cannot redirect the privileged write — the May 2026
//! audit Slice 4 finding.

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
    let tmp = path.with_file_name(format!(
        "{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("packetframe.out"),
    ));
    {
        #[cfg(target_os = "linux")]
        let mut f = crate::loader::create_excl_no_follow(&tmp).or_else(|e| {
            // Symmetry with the loader helper's retry path. On a crashed
            // predecessor the `.tmp` leftover is a regular file: unlink
            // and retry once. A symlink (attacker pre-creation) trips
            // O_NOFOLLOW on the retry too.
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                let meta = std::fs::symlink_metadata(&tmp)?;
                if meta.file_type().is_file() {
                    std::fs::remove_file(&tmp)?;
                    return crate::loader::create_excl_no_follow(&tmp);
                }
            }
            Err(e)
        })?;
        #[cfg(not(target_os = "linux"))]
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
