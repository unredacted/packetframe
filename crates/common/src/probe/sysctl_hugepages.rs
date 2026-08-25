//! Boot-persistent hugepage sysctl detection (`vpp.sysctl-hugepages`).
//!
//! The upstream VPP deb ships `/etc/sysctl.d/80-vpp.conf` with
//! `vm.nr_hugepages=1024`, sized for 2 MiB pages. `VPP_INSTALL_SKIP_SYSCTL=1`
//! skips only the postinst's install-time `sysctl --system`; the file
//! persists and systemd-sysctl re-applies it on every boot. On a 64K-page
//! kernel the default hugepage size is 512 MiB, so the same file is a
//! 512 GiB reservation — on the 64 GB reference EFG the first reboot after
//! install reserved essentially all RAM before userspace came up and
//! recovery required a factory reset (2026-08-21, edge1-mci1-net). Every
//! install-time check passed; only a boot could reveal it. This probe
//! prices the EFFECTIVE boot-time `vm.nr_hugepages` at the RUNNING
//! kernel's default hugepage size so feasibility reveals it without the
//! boot.
//!
//! Only the directory scan and the `/proc/meminfo` read are Linux-gated;
//! the parsing, precedence resolution, and arithmetic are pure so their
//! unit tests run on every host.

// The pure helpers stay outside the platform gate so their unit tests
// run on every host, but their only production caller is the Linux
// collector — on other targets the non-test build sees them as dead.
#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use std::path::{Path, PathBuf};

use super::Capability;

const PROBE_NAME: &str = "vpp.sysctl-hugepages";

/// Both keys size the same default hugepage pool: a write to either
/// sysctl sets the pool, so the last boot-time assignment to either
/// one decides what the kernel reserves.
const HUGEPAGE_KEYS: [&str; 2] = ["vm.nr_hugepages", "vm.nr_hugepages_mempolicy"];

/// Requests above this fraction of MemTotal fail outright: the reboot
/// reserves (essentially) all RAM before userspace comes up.
const FAIL_FRACTION_DENOMINATOR: u64 = 2; // > MemTotal/2 ⇒ Fail

/// A sysctl fragment, already in boot-apply order: where it came from
/// (for the report) plus its text.
struct SysctlSource {
    path: PathBuf,
    contents: String,
}

/// A `*.conf` file found in one of the sysctl.d directories, before
/// shadow resolution. `dir_rank` is the directory's precedence, lower
/// wins (0 = `/etc/sysctl.d`).
struct SysctlCandidate {
    dir_rank: usize,
    basename: String,
    path: PathBuf,
}

/// The last boot-time assignment to a hugepage-pool key: which file
/// set it, with which key, to what.
struct HugepageAssignment {
    path: PathBuf,
    key: String,
    pages: u64,
}

/// systemd's sysctl.d shadowing + ordering rules, on in-memory data:
/// among same-named files only the one from the highest-precedence
/// directory is read at all, and the surviving set applies in
/// lexicographic basename order (directory is irrelevant to ordering).
fn resolve_apply_order(candidates: Vec<SysctlCandidate>) -> Vec<PathBuf> {
    let mut best: Vec<SysctlCandidate> = Vec::new();
    for c in candidates {
        match best.iter_mut().find(|b| b.basename == c.basename) {
            Some(b) => {
                if c.dir_rank < b.dir_rank {
                    *b = c;
                }
            }
            None => best.push(c),
        }
    }
    best.sort_by(|a, b| a.basename.cmp(&b.basename));
    best.into_iter().map(|c| c.path).collect()
}

/// The effective boot value: parse each source in apply order; the
/// last assignment to either pool key wins across all files.
fn last_hugepage_assignment(sources: &[SysctlSource]) -> Option<HugepageAssignment> {
    let mut last = None;
    for src in sources {
        for line in src.contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            // sysctl.d accepts `/` as the separator (including the
            // canonical leading-slash spelling `/vm/nr_hugepages`) and
            // a leading `-` for ignore-errors; normalize all three
            // before matching.
            let key = key
                .trim()
                .trim_start_matches('-')
                .trim_start_matches('/')
                .replace('/', ".");
            if !HUGEPAGE_KEYS.contains(&key.as_str()) {
                continue;
            }
            // A value the kernel would reject at boot reserves nothing,
            // so an unparseable one is not a landmine.
            let Ok(pages) = value.trim().parse::<u64>() else {
                continue;
            };
            last = Some(HugepageAssignment {
                path: src.path.clone(),
                key,
                pages,
            });
        }
    }
    last
}

/// `MemTotal` and `Hugepagesize` from `/proc/meminfo` text, in bytes.
fn parse_meminfo(contents: &str) -> Result<(u64, u64), String> {
    fn kb_line(rest: &str) -> Option<u64> {
        rest.trim()
            .strip_suffix("kB")
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|kb| kb.saturating_mul(1024))
    }
    let mut hugepagesize = None;
    let mut memtotal = None;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            memtotal = kb_line(rest);
        } else if let Some(rest) = line.strip_prefix("Hugepagesize:") {
            hugepagesize = kb_line(rest);
        }
    }
    match (hugepagesize, memtotal) {
        (Some(h), Some(m)) => Ok((h, m)),
        _ => Err("could not parse Hugepagesize/MemTotal from /proc/meminfo".to_string()),
    }
}

fn fmt_bytes(bytes: u64) -> String {
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    if bytes >= GIB && bytes % GIB == 0 {
        format!("{} GiB", bytes / GIB)
    } else if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MiB", bytes / MIB)
    }
}

/// The verdict, from the effective boot value and the RUNNING kernel's
/// sizes. Pass on zero/absent; Fail above MemTotal/2 (the box will not
/// survive the boot); Warn on any other nonzero value, because the
/// vpp-offload module manages hugepages deliberately at attach and a
/// competing boot-time reservation is drift.
fn hugepage_verdict(
    effective: Option<&HugepageAssignment>,
    hugepagesize_bytes: u64,
    memtotal_bytes: u64,
) -> Capability {
    let Some(a) = effective else {
        return Capability::pass(
            PROBE_NAME,
            "no boot-time vm.nr_hugepages in sysctl.d or /etc/sysctl.conf",
            false,
        );
    };
    if a.pages == 0 {
        return Capability::pass(
            PROBE_NAME,
            format!(
                "effective boot value 0 (last set by {}) — nothing reserved",
                a.path.display()
            ),
            false,
        );
    }
    let requested = a.pages.saturating_mul(hugepagesize_bytes);
    if requested > memtotal_bytes / FAIL_FRACTION_DENOMINATOR {
        Capability::fail(
            PROBE_NAME,
            format!(
                "{file} sets {key} = {pages}; at this kernel's default hugepage size \
                 ({size}) that is a {req} boot-time reservation against {total} MemTotal — \
                 the box will NOT survive its next reboot. Fix: delete the {key} line \
                 from {file}, or rm the file when the setting is its only purpose (the \
                 VPP deb's 80-vpp.conf) — hugepages are managed by the vpp-offload \
                 module at attach, never by boot config",
                file = a.path.display(),
                key = a.key,
                pages = a.pages,
                size = fmt_bytes(hugepagesize_bytes),
                req = fmt_bytes(requested),
                total = fmt_bytes(memtotal_bytes),
            ),
            false,
        )
    } else {
        Capability::warn(
            PROBE_NAME,
            format!(
                "{file} sets {key} = {pages} ({req} at {size} pages, MemTotal {total}): \
                 a boot-time hugepage reservation competes with the vpp-offload module, \
                 which manages hugepages at attach; delete the {key} line from {file} \
                 unless the reservation is deliberate",
                file = a.path.display(),
                key = a.key,
                pages = a.pages,
                req = fmt_bytes(requested),
                size = fmt_bytes(hugepagesize_bytes),
                total = fmt_bytes(memtotal_bytes),
            ),
            false,
        )
    }
}

/// Every `*.conf` the boot-time sysctl apply would read, in apply
/// order. Directory precedence is systemd-sysctl's (`/etc` over `/run`
/// over `/usr/local/lib` over `/usr/lib`, with `/lib` for split-usr
/// systems). `/etc/sysctl.conf` is appended last (matching
/// `sysctl --system`) ONLY when no sysctl.d fragment already resolves
/// to it — Debian symlinks it in as `99-sysctl.conf`, and systemd
/// honors the symlink's position, so re-appending it would let it
/// wrongly override a lexicographically later fragment.
///
/// Errs on anything that leaves the scan incomplete: a directory that
/// exists but can't be listed, or a selected fragment that can't be
/// read. Silently skipping either could turn a boot-fatal file into a
/// PASS. Absent directories/files and dangling symlinks reserve
/// nothing at boot, so those are skipped, not errors.
#[cfg(target_os = "linux")]
fn collect_boot_sysctl_sources() -> Result<Vec<SysctlSource>, String> {
    use std::io::ErrorKind;

    const DIRS: [&str; 5] = [
        "/etc/sysctl.d",
        "/run/sysctl.d",
        "/usr/local/lib/sysctl.d",
        "/usr/lib/sysctl.d",
        "/lib/sysctl.d",
    ];
    let mut candidates = Vec::new();
    for (rank, dir) in DIRS.iter().enumerate() {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("could not scan {dir}: {e}")),
        };
        for entry in entries {
            let entry = entry.map_err(|e| format!("could not scan {dir}: {e}"))?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.ends_with(".conf") {
                continue;
            }
            candidates.push(SysctlCandidate {
                dir_rank: rank,
                basename: name.to_string(),
                path,
            });
        }
    }

    let conf = Path::new("/etc/sysctl.conf");
    let conf_canonical = std::fs::canonicalize(conf).ok();
    let mut conf_covered = false;
    let mut sources = Vec::new();
    for path in resolve_apply_order(candidates) {
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            // A dangling symlink applies nothing at boot either.
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("could not read {}: {e}", path.display())),
        };
        if let (Some(canonical_conf), Ok(canonical)) =
            (&conf_canonical, std::fs::canonicalize(&path))
        {
            conf_covered = conf_covered || canonical == *canonical_conf;
        }
        sources.push(SysctlSource { path, contents });
    }
    if !conf_covered {
        match std::fs::read_to_string(conf) {
            Ok(contents) => sources.push(SysctlSource {
                path: conf.to_path_buf(),
                contents,
            }),
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(format!("could not read {}: {e}", conf.display())),
        }
    }
    Ok(sources)
}

#[cfg(target_os = "linux")]
pub fn probe_sysctl_hugepages() -> Capability {
    let (hugepagesize, memtotal) = match std::fs::read_to_string("/proc/meminfo")
        .map_err(|e| format!("could not read /proc/meminfo: {e}"))
        .and_then(|s| parse_meminfo(&s))
    {
        Ok(sizes) => sizes,
        Err(e) => return Capability::unknown(PROBE_NAME, e, false),
    };
    let sources = match collect_boot_sysctl_sources() {
        Ok(sources) => sources,
        // An incomplete scan must not read as "no reservation": the
        // unreadable file is exactly where the landmine could be.
        Err(e) => {
            return Capability::unknown(
                PROBE_NAME,
                format!("boot sysctl scan incomplete ({e}); cannot price the boot-time hugepage request"),
                false,
            );
        }
    };
    hugepage_verdict(
        last_hugepage_assignment(&sources).as_ref(),
        hugepagesize,
        memtotal,
    )
}

#[cfg(not(target_os = "linux"))]
pub fn probe_sysctl_hugepages() -> Capability {
    Capability::unknown(PROBE_NAME, "boot sysctl scan is Linux-only", false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::CapabilityStatus;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    const MEM_64G: u64 = 64 * GIB;

    fn src(path: &str, contents: &str) -> SysctlSource {
        SysctlSource {
            path: PathBuf::from(path),
            contents: contents.to_string(),
        }
    }

    fn cand(rank: usize, dir: &str, basename: &str) -> SysctlCandidate {
        SysctlCandidate {
            dir_rank: rank,
            basename: basename.to_string(),
            path: PathBuf::from(dir).join(basename),
        }
    }

    #[test]
    fn parses_comments_whitespace_and_separators() {
        let s = src(
            "/etc/sysctl.d/80-vpp.conf",
            r#"
# comment
; also a comment
   vm.nr_hugepages = 1024
"#,
        );
        let a = last_hugepage_assignment(&[s]).unwrap();
        assert_eq!(a.pages, 1024);
        assert_eq!(a.key, "vm.nr_hugepages");

        // Slash-separated key, no spaces around `=`, ignore-errors `-`.
        let s = src("/etc/sysctl.d/x.conf", "-vm/nr_hugepages=512\n");
        assert_eq!(last_hugepage_assignment(&[s]).unwrap().pages, 512);

        // The canonical leading-slash spelling systemd also accepts.
        let s = src("/etc/sysctl.d/x.conf", "/vm/nr_hugepages = 128\n");
        assert_eq!(last_hugepage_assignment(&[s]).unwrap().pages, 128);

        // The mempolicy variant sizes the same pool.
        let s = src("/etc/sysctl.d/x.conf", "vm.nr_hugepages_mempolicy = 256\n");
        let a = last_hugepage_assignment(&[s]).unwrap();
        assert_eq!(a.pages, 256);
        assert_eq!(a.key, "vm.nr_hugepages_mempolicy");

        // Unrelated keys and unparseable values are not assignments.
        let s = src(
            "/etc/sysctl.d/x.conf",
            "vm.nr_hugepagesx = 9\nvm.swappiness = 10\nvm.nr_hugepages = lots\n",
        );
        assert!(last_hugepage_assignment(&[s]).is_none());
    }

    #[test]
    fn last_assignment_wins_within_a_file() {
        let s = src(
            "/etc/sysctl.d/one.conf",
            "vm.nr_hugepages = 1024\nvm.nr_hugepages = 16\n",
        );
        assert_eq!(last_hugepage_assignment(&[s]).unwrap().pages, 16);
    }

    #[test]
    fn last_file_in_apply_order_wins() {
        // A later basename (or /etc/sysctl.conf, which the collector
        // appends last) overrides an earlier file's assignment.
        let sources = [
            src("/etc/sysctl.d/10-vpp.conf", "vm.nr_hugepages = 1024\n"),
            src("/etc/sysctl.d/90-fix.conf", "vm.nr_hugepages = 0\n"),
        ];
        let a = last_hugepage_assignment(&sources).unwrap();
        assert_eq!(a.pages, 0);
        assert_eq!(a.path, PathBuf::from("/etc/sysctl.d/90-fix.conf"));
    }

    #[test]
    fn same_basename_shadows_across_directories() {
        // 80-vpp.conf exists in both /usr/lib and /etc: only the /etc
        // one is read at all, regardless of push order.
        let order = resolve_apply_order(vec![
            cand(3, "/usr/lib/sysctl.d", "80-vpp.conf"),
            cand(0, "/etc/sysctl.d", "80-vpp.conf"),
            cand(3, "/usr/lib/sysctl.d", "50-other.conf"),
        ]);
        assert_eq!(
            order,
            vec![
                PathBuf::from("/usr/lib/sysctl.d/50-other.conf"),
                PathBuf::from("/etc/sysctl.d/80-vpp.conf"),
            ]
        );
    }

    #[test]
    fn apply_order_is_lexicographic_by_basename() {
        // Directory does not affect ordering, only shadowing.
        let order = resolve_apply_order(vec![
            cand(0, "/etc/sysctl.d", "99-zz.conf"),
            cand(3, "/usr/lib/sysctl.d", "10-aa.conf"),
            cand(1, "/run/sysctl.d", "50-mm.conf"),
        ]);
        assert_eq!(
            order,
            vec![
                PathBuf::from("/usr/lib/sysctl.d/10-aa.conf"),
                PathBuf::from("/run/sysctl.d/50-mm.conf"),
                PathBuf::from("/etc/sysctl.d/99-zz.conf"),
            ]
        );
    }

    #[test]
    fn the_incident_arithmetic_fails() {
        // 2026-08-21: 1024 pages × 512 MiB default (64K-page kernel)
        // = 512 GiB against 64 GiB MemTotal.
        let a = HugepageAssignment {
            path: PathBuf::from("/etc/sysctl.d/80-vpp.conf"),
            key: "vm.nr_hugepages".into(),
            pages: 1024,
        };
        let cap = hugepage_verdict(Some(&a), 512 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Fail, "{}", cap.detail);
        assert!(!cap.required);
        assert!(cap.detail.contains("/etc/sysctl.d/80-vpp.conf"));
        assert!(cap.detail.contains("1024"));
        assert!(cap.detail.contains("512 GiB"), "detail: {}", cap.detail);
        assert!(
            cap.detail
                .contains("delete the vm.nr_hugepages line from /etc/sysctl.d/80-vpp.conf"),
            "detail: {}",
            cap.detail
        );
    }

    #[test]
    fn survivable_reservation_warns() {
        // Same file on a 4K-page kernel: 1024 × 2 MiB = 2 GiB against
        // 64 GiB — the box boots, but the reservation is drift.
        let a = HugepageAssignment {
            path: PathBuf::from("/etc/sysctl.d/80-vpp.conf"),
            key: "vm.nr_hugepages".into(),
            pages: 1024,
        };
        let cap = hugepage_verdict(Some(&a), 2 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Warn, "{}", cap.detail);
        assert!(cap.detail.contains("2 GiB"), "detail: {}", cap.detail);
    }

    #[test]
    fn fail_threshold_is_half_of_memtotal() {
        let a = |pages| HugepageAssignment {
            path: PathBuf::from("/etc/sysctl.d/x.conf"),
            key: "vm.nr_hugepages".into(),
            pages,
        };
        // Exactly half (16384 × 2 MiB = 32 GiB) still warns; one page
        // past it fails.
        let at_half = hugepage_verdict(Some(&a(16384)), 2 * MIB, MEM_64G);
        assert_eq!(at_half.status, CapabilityStatus::Warn, "{}", at_half.detail);
        let past_half = hugepage_verdict(Some(&a(16385)), 2 * MIB, MEM_64G);
        assert_eq!(
            past_half.status,
            CapabilityStatus::Fail,
            "{}",
            past_half.detail
        );
    }

    #[test]
    fn zero_and_absent_pass() {
        let cap = hugepage_verdict(None, 2 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Pass);

        let a = HugepageAssignment {
            path: PathBuf::from("/etc/sysctl.d/90-fix.conf"),
            key: "vm.nr_hugepages".into(),
            pages: 0,
        };
        let cap = hugepage_verdict(Some(&a), 512 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Pass, "{}", cap.detail);
        assert!(cap.detail.contains("90-fix.conf"));
    }

    #[test]
    fn absurd_values_saturate_instead_of_overflowing() {
        let a = HugepageAssignment {
            path: PathBuf::from("/etc/sysctl.d/x.conf"),
            key: "vm.nr_hugepages".into(),
            pages: u64::MAX,
        };
        let cap = hugepage_verdict(Some(&a), 512 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Fail);
    }

    #[test]
    fn meminfo_parsing() {
        let contents =
            "MemTotal:       67108864 kB\nMemFree:        123 kB\nHugepagesize:     524288 kB\n";
        let (huge, total) = parse_meminfo(contents).unwrap();
        assert_eq!(huge, 512 * MIB);
        assert_eq!(total, MEM_64G);

        assert!(parse_meminfo("MemTotal: 1 kB\n").is_err());
        assert!(parse_meminfo("").is_err());
    }
}
