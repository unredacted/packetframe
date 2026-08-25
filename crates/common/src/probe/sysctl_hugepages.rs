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

use super::{Capability, CapabilityStatus};

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
#[derive(Clone)]
struct SysctlSource {
    path: PathBuf,
    contents: String,
}

/// A `*.conf` file found in one of the sysctl.d directories, before
/// shadow resolution. `dir_rank` is the directory's precedence, lower
/// wins (0 = `/etc/sysctl.d`).
#[derive(Clone)]
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
///
/// `mempolicy_supported` is whether the RUNNING kernel has
/// `/proc/sys/vm/nr_hugepages_mempolicy` (CONFIG_NUMA=y). Without it
/// the boot write to that key fails and applies nothing, so a later
/// mempolicy line must not mask an earlier lethal `vm.nr_hugepages`
/// (review finding on #201).
fn last_hugepage_assignment(
    sources: &[SysctlSource],
    mempolicy_supported: bool,
) -> Option<HugepageAssignment> {
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
            // sysctl.d(5) supports simple globbing, and a glob expands
            // against the live /proc/sys tree at boot — where the pool
            // keys always exist — so a pattern line sets the pool just
            // as an exact line does (review finding on #201).
            let is_glob = key.contains(['*', '?', '[']);
            let matched: Option<&'static str> = HUGEPAGE_KEYS.iter().copied().find(|k| {
                if is_glob {
                    glob_match(&key, k)
                } else {
                    key == *k
                }
            });
            let Some(matched) = matched else {
                continue;
            };
            if !mempolicy_supported && matched == "vm.nr_hugepages_mempolicy" {
                continue;
            }
            let Some(pages) = parse_kernel_ul(value.trim()) else {
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

/// Parse a value the way the kernel's proc handler does: `proc_get_long`
/// calls `simple_strtoul(p, &p, 0)` — base 0, so `0x` followed by a hex
/// digit means hex and any other leading `0` means octal — committing
/// the leading digits of the detected base and stopping at the first
/// invalid character. So `1024 # comment` applies 1024 and `0x400`
/// applies 1024, not 0 (review findings on #201). `None` means no digit
/// commits at all: the boot write fails with EINVAL and reserves
/// nothing. A digit run past u64 saturates so absurd is judged absurd,
/// not skipped.
fn parse_kernel_ul(value: &str) -> Option<u64> {
    let b = value.as_bytes();
    let (radix, digits, zero_committed) = if b.len() >= 3
        && b[0] == b'0'
        && (b[1] == b'x' || b[1] == b'X')
        && b[2].is_ascii_hexdigit()
    {
        (16, &value[2..], false)
    } else if b.first() == Some(&b'0') {
        // Any other leading zero is octal, and that zero is already a
        // committed digit (`0x` with no hex digit after it lands here
        // too: the kernel parses the 0 and stops at the `x`).
        (8, &value[1..], true)
    } else {
        (10, value, false)
    };
    let end = digits
        .find(|c: char| !c.is_digit(radix))
        .unwrap_or(digits.len());
    if end == 0 {
        return zero_committed.then_some(0);
    }
    // The digits are pre-validated for the radix, so the only error
    // left is overflow.
    Some(u64::from_str_radix(&digits[..end], radix).unwrap_or(u64::MAX))
}

/// sysctl.d(5)'s "simple globbing": `*`, `?`, and `[...]` classes with
/// ranges and `!`/`^` negation. An unterminated class matches nothing.
fn glob_match(pattern: &str, text: &str) -> bool {
    fn matches(p: &[char], t: &[char]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some('*') => (0..=t.len()).any(|i| matches(&p[1..], &t[i..])),
            Some('?') => !t.is_empty() && matches(&p[1..], &t[1..]),
            Some('[') => {
                let Some(c) = t.first() else { return false };
                let (negated, start) = match p.get(1) {
                    Some('!') | Some('^') => (true, 2),
                    _ => (false, 1),
                };
                // A `]` in first position is a literal member, so the
                // closing scan begins one past `start`.
                let mut i = start;
                let mut in_class = false;
                while i < p.len() && (p[i] != ']' || i == start) {
                    if p.get(i + 1) == Some(&'-') && i + 2 < p.len() && p[i + 2] != ']' {
                        in_class = in_class || (p[i]..=p[i + 2]).contains(c);
                        i += 3;
                    } else {
                        in_class = in_class || *c == p[i];
                        i += 1;
                    }
                }
                if i >= p.len() {
                    return false;
                }
                (in_class != negated) && matches(&p[i + 1..], &t[1..])
            }
            Some(c) => t.first() == Some(c) && matches(&p[1..], &t[1..]),
        }
    }
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    matches(&p, &t)
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

/// The boot sets the two appliers would read, each in its own apply
/// order. They genuinely differ (review findings on #201):
///
/// - **systemd-sysctl** reads `/etc`, `/run`, `/usr/local/lib`,
///   `/usr/lib` `sysctl.d` directories only (systemd 255's
///   `--cat-config` search path excludes split-usr `/lib/sysctl.d`),
///   reaches `/etc/sysctl.conf` only through a fragment symlink at the
///   symlink's position, and applies a `sysctl.extra` service
///   credential after every fragment.
/// - **procps `sysctl --system`** adds `/lib/sysctl.d` and always
///   applies `/etc/sysctl.conf` last — again, even when a fragment
///   symlink already reached it.
///
/// The probe cannot know which applier this box runs at boot, so the
/// verdict prices both (see [`dual_model_verdict`]).
struct BootModels {
    systemd: Vec<SysctlSource>,
    procps: Vec<SysctlSource>,
}

/// Collect both boot models' sources.
///
/// Errs on anything that leaves the scan incomplete: a directory that
/// exists but can't be listed, or a selected fragment that can't be
/// read. Silently skipping either could turn a boot-fatal file into a
/// PASS. Absent directories/files and dangling symlinks reserve
/// nothing at boot, so those are skipped, not errors.
#[cfg(target_os = "linux")]
fn collect_boot_sysctl_sources() -> Result<BootModels, String> {
    use std::io::ErrorKind;

    /// The directories both appliers read, in shared precedence order.
    const COMMON_DIRS: [&str; 4] = [
        "/etc/sysctl.d",
        "/run/sysctl.d",
        "/usr/local/lib/sysctl.d",
        "/usr/lib/sysctl.d",
    ];
    /// procps-only legacy directory (distinct on split-usr hosts).
    const PROCPS_EXTRA_DIR: &str = "/lib/sysctl.d";
    /// systemd-sysctl parses a `sysctl.extra` credential after the
    /// fragments. The credentials directory is observable only while
    /// the (RemainAfterExit) unit holds it, so this read is
    /// best-effort: present and readable joins the model, present but
    /// unreadable errs into Unknown rather than silently vanishing.
    const SYSTEMD_CREDENTIAL: &str = "/run/credentials/systemd-sysctl.service/sysctl.extra";

    fn scan_dir(dir: &str, rank: usize, out: &mut Vec<SysctlCandidate>) -> Result<(), String> {
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
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
            out.push(SysctlCandidate {
                dir_rank: rank,
                basename: name.to_string(),
                path,
            });
        }
        Ok(())
    }

    fn read_ordered(paths: Vec<PathBuf>) -> Result<Vec<SysctlSource>, String> {
        let mut out = Vec::new();
        for path in paths {
            match std::fs::read_to_string(&path) {
                Ok(contents) => out.push(SysctlSource { path, contents }),
                // A dangling symlink applies nothing at boot either.
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("could not read {}: {e}", path.display())),
            }
        }
        Ok(out)
    }

    fn read_optional(path: &str, out: &mut Vec<SysctlSource>) -> Result<(), String> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                out.push(SysctlSource {
                    path: PathBuf::from(path),
                    contents,
                });
                Ok(())
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("could not read {path}: {e}")),
        }
    }

    let mut common = Vec::new();
    for (rank, dir) in COMMON_DIRS.iter().enumerate() {
        scan_dir(dir, rank, &mut common)?;
    }
    let mut procps_candidates = common.clone();
    scan_dir(PROCPS_EXTRA_DIR, COMMON_DIRS.len(), &mut procps_candidates)?;

    let mut systemd = read_ordered(resolve_apply_order(common))?;
    read_optional(SYSTEMD_CREDENTIAL, &mut systemd)?;

    let mut procps = read_ordered(resolve_apply_order(procps_candidates))?;
    read_optional("/etc/sysctl.conf", &mut procps)?;

    Ok(BootModels { systemd, procps })
}

/// `Fail` outranks `Warn` outranks the rest, for picking the worse of
/// the two boot models.
fn severity(cap: &Capability) -> u8 {
    match cap.status {
        CapabilityStatus::Fail => 2,
        CapabilityStatus::Warn => 1,
        _ => 0,
    }
}

/// Price BOTH boot models and report the worse verdict — a spurious
/// WARN/FAIL for a file one applier skips beats a PASS over a file the
/// other applies. When the models' effective assignments differ and
/// the less-bad one is still not clean, its assignment is named too,
/// so remediation cannot fix one boot path and leave the other lethal
/// (review findings on #201).
fn dual_model_verdict(
    models: &BootModels,
    mempolicy_supported: bool,
    hugepagesize_bytes: u64,
    memtotal_bytes: u64,
) -> Capability {
    let systemd_a = last_hugepage_assignment(&models.systemd, mempolicy_supported);
    let procps_a = last_hugepage_assignment(&models.procps, mempolicy_supported);
    let systemd_cap = hugepage_verdict(systemd_a.as_ref(), hugepagesize_bytes, memtotal_bytes);
    let procps_cap = hugepage_verdict(procps_a.as_ref(), hugepagesize_bytes, memtotal_bytes);

    let same_assignment = match (&systemd_a, &procps_a) {
        (None, None) => true,
        (Some(a), Some(b)) => a.path == b.path && a.key == b.key && a.pages == b.pages,
        _ => false,
    };
    if same_assignment {
        return systemd_cap;
    }
    let procps_worse = severity(&procps_cap) > severity(&systemd_cap);
    let (mut primary, secondary, secondary_a, secondary_name) = if procps_worse {
        (procps_cap, systemd_cap, &systemd_a, "a systemd-sysctl boot")
    } else {
        (
            systemd_cap,
            procps_cap,
            &procps_a,
            "a procps `sysctl --system` boot",
        )
    };
    if severity(&secondary) > 0 {
        let a = secondary_a
            .as_ref()
            .expect("a Warn/Fail verdict always names an assignment");
        primary.detail.push_str(&format!(
            "; {secondary_name} instead applies {} = {} from {} — remediate both, the probe \
             cannot tell which applier this box runs at boot",
            a.key,
            a.pages,
            a.path.display()
        ));
    }
    primary
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
    let models = match collect_boot_sysctl_sources() {
        Ok(models) => models,
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
    let mempolicy_supported = Path::new("/proc/sys/vm/nr_hugepages_mempolicy").exists();
    dual_model_verdict(&models, mempolicy_supported, hugepagesize, memtotal)
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
        let a = last_hugepage_assignment(&[s], true).unwrap();
        assert_eq!(a.pages, 1024);
        assert_eq!(a.key, "vm.nr_hugepages");

        // Slash-separated key, no spaces around `=`, ignore-errors `-`.
        let s = src("/etc/sysctl.d/x.conf", "-vm/nr_hugepages=512\n");
        assert_eq!(last_hugepage_assignment(&[s], true).unwrap().pages, 512);

        // The canonical leading-slash spelling systemd also accepts.
        let s = src("/etc/sysctl.d/x.conf", "/vm/nr_hugepages = 128\n");
        assert_eq!(last_hugepage_assignment(&[s], true).unwrap().pages, 128);

        // The mempolicy variant sizes the same pool.
        let s = src("/etc/sysctl.d/x.conf", "vm.nr_hugepages_mempolicy = 256\n");
        let a = last_hugepage_assignment(&[s], true).unwrap();
        assert_eq!(a.pages, 256);
        assert_eq!(a.key, "vm.nr_hugepages_mempolicy");

        // Unrelated keys and unparseable values are not assignments.
        let s = src(
            "/etc/sysctl.d/x.conf",
            "vm.nr_hugepagesx = 9\nvm.swappiness = 10\nvm.nr_hugepages = lots\n",
        );
        assert!(last_hugepage_assignment(&[s], true).is_none());
    }

    #[test]
    fn last_assignment_wins_within_a_file() {
        let s = src(
            "/etc/sysctl.d/one.conf",
            "vm.nr_hugepages = 1024\nvm.nr_hugepages = 16\n",
        );
        assert_eq!(last_hugepage_assignment(&[s], true).unwrap().pages, 16);
    }

    #[test]
    fn last_file_in_apply_order_wins() {
        // A later basename overrides an earlier file's assignment.
        let sources = [
            src("/etc/sysctl.d/10-vpp.conf", "vm.nr_hugepages = 1024\n"),
            src("/etc/sysctl.d/90-fix.conf", "vm.nr_hugepages = 0\n"),
        ];
        let a = last_hugepage_assignment(&sources, true).unwrap();
        assert_eq!(a.pages, 0);
        assert_eq!(a.path, PathBuf::from("/etc/sysctl.d/90-fix.conf"));
    }

    #[test]
    fn kernel_accepted_value_forms_are_not_skipped() {
        // The kernel's proc parser commits the leading digits and stops
        // at the first non-digit, so an inline comment does not make
        // the line a no-op at boot (review finding on #201).
        let s = src(
            "/etc/sysctl.d/80-vpp.conf",
            "vm.nr_hugepages = 1024 # sized for 2MiB pages\n",
        );
        assert_eq!(last_hugepage_assignment(&[s], true).unwrap().pages, 1024);

        // The kernel parses with base 0 (`simple_strtoul(p, &p, 0)`),
        // so hex and octal literals apply their full value at boot.
        let s = src("/etc/sysctl.d/x.conf", "vm.nr_hugepages = 0x400\n");
        assert_eq!(last_hugepage_assignment(&[s], true).unwrap().pages, 1024);
        let s = src("/etc/sysctl.d/x.conf", "vm.nr_hugepages = 0X400\n");
        assert_eq!(last_hugepage_assignment(&[s], true).unwrap().pages, 1024);
        let s = src("/etc/sysctl.d/x.conf", "vm.nr_hugepages = 010\n");
        assert_eq!(last_hugepage_assignment(&[s], true).unwrap().pages, 8);

        // A digit run past u64 saturates instead of being skipped.
        let s = src(
            "/etc/sysctl.d/x.conf",
            "vm.nr_hugepages = 99999999999999999999999999\n",
        );
        assert_eq!(
            last_hugepage_assignment(&[s], true).unwrap().pages,
            u64::MAX
        );
    }

    #[test]
    fn mempolicy_does_not_mask_on_kernels_without_it() {
        // Without CONFIG_NUMA the boot write to
        // vm.nr_hugepages_mempolicy fails and applies nothing, so a
        // later mempolicy=0 must not mask an earlier lethal
        // vm.nr_hugepages (review finding on #201).
        let sources = [
            src("/etc/sysctl.d/80-vpp.conf", "vm.nr_hugepages = 131072\n"),
            src(
                "/etc/sysctl.d/90-tune.conf",
                "vm.nr_hugepages_mempolicy = 0\n",
            ),
        ];
        let masked = last_hugepage_assignment(&sources, false).unwrap();
        assert_eq!(masked.pages, 131072);
        assert_eq!(masked.key, "vm.nr_hugepages");

        // On a NUMA kernel the same pair really does zero the pool.
        assert_eq!(last_hugepage_assignment(&sources, true).unwrap().pages, 0);
    }

    fn models(systemd: Vec<SysctlSource>, procps: Vec<SysctlSource>) -> BootModels {
        BootModels { systemd, procps }
    }

    #[test]
    fn kernel_base0_value_parsing() {
        assert_eq!(parse_kernel_ul("1024"), Some(1024));
        assert_eq!(parse_kernel_ul("1024 # comment"), Some(1024));
        assert_eq!(parse_kernel_ul("0x400"), Some(1024));
        assert_eq!(parse_kernel_ul("0X400"), Some(1024));
        assert_eq!(parse_kernel_ul("010"), Some(8));
        assert_eq!(parse_kernel_ul("0"), Some(0));
        // Octal commits the leading 0 and stops at the invalid digit;
        // `0x` without a hex digit after it does the same.
        assert_eq!(parse_kernel_ul("09"), Some(0));
        assert_eq!(parse_kernel_ul("0xzz"), Some(0));
        // No digit commits at all: the boot write applies nothing.
        assert_eq!(parse_kernel_ul(""), None);
        assert_eq!(parse_kernel_ul("lots"), None);
        assert_eq!(parse_kernel_ul("-1"), None);
        // Overflow saturates.
        assert_eq!(
            parse_kernel_ul("99999999999999999999999999"),
            Some(u64::MAX)
        );
        assert_eq!(parse_kernel_ul("0xffffffffffffffffff"), Some(u64::MAX));
    }

    #[test]
    fn glob_matching() {
        assert!(glob_match("vm.nr_hugepages*", "vm.nr_hugepages"));
        assert!(glob_match("vm.nr_hugepages*", "vm.nr_hugepages_mempolicy"));
        assert!(glob_match("vm.*", "vm.nr_hugepages"));
        assert!(glob_match("vm.nr_hugepage?", "vm.nr_hugepages"));
        assert!(glob_match("[uv]m.nr_hugepages", "vm.nr_hugepages"));
        assert!(glob_match("[a-z]m.nr_hugepages", "vm.nr_hugepages"));
        assert!(!glob_match("[!v]m.nr_hugepages", "vm.nr_hugepages"));
        assert!(!glob_match("net.*", "vm.nr_hugepages"));
        assert!(!glob_match("vm.nr_hugepage?", "vm.nr_hugepages_mempolicy"));
        // An unterminated class matches nothing.
        assert!(!glob_match("vm.nr_hugepages[", "vm.nr_hugepages"));
    }

    #[test]
    fn glob_assignments_set_the_pool() {
        // sysctl.d(5) "simple globbing": a pattern line expands against
        // the live /proc/sys tree at boot, where the pool key always
        // exists, so it must count (review finding on #201).
        let s = src("/etc/sysctl.d/90-glob.conf", "vm.nr_hugepages* = 1024\n");
        let a = last_hugepage_assignment(&[s], true).unwrap();
        assert_eq!(a.pages, 1024);

        // A glob zeroing later masks an earlier lethal line, exactly
        // like an explicit assignment would.
        let sources = [
            src("/etc/sysctl.d/80-vpp.conf", "vm.nr_hugepages = 131072\n"),
            src("/etc/sysctl.d/90-glob.conf", "vm.nr_hugepage? = 0\n"),
        ];
        assert_eq!(last_hugepage_assignment(&sources, true).unwrap().pages, 0);

        // A glob reaching only the mempolicy key obeys the NUMA gate.
        let s = src("/etc/sysctl.d/x.conf", "*mempolicy = 1024\n");
        assert!(last_hugepage_assignment(std::slice::from_ref(&s), false).is_none());
        assert_eq!(last_hugepage_assignment(&[s], true).unwrap().pages, 1024);
    }

    #[test]
    fn unsymlinked_sysctl_conf_cannot_mask_a_lethal_fragment() {
        // The incident file plus an old-style "fix" in an unsymlinked
        // /etc/sysctl.conf: systemd-sysctl never reads the fix, so the
        // worse of the two boot models (the systemd one) must win —
        // FAIL, not PASS (review finding on #201).
        let lethal = || src("/etc/sysctl.d/80-vpp.conf", "vm.nr_hugepages = 1024\n");
        let m = models(
            vec![lethal()],
            vec![lethal(), src("/etc/sysctl.conf", "vm.nr_hugepages = 0\n")],
        );
        let cap = dual_model_verdict(&m, true, 512 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Fail, "{}", cap.detail);
        assert!(cap.detail.contains("80-vpp.conf"), "{}", cap.detail);

        // The reverse: a lethal value living only in the unsymlinked
        // sysctl.conf is priced under the procps model and still fails.
        let m = models(
            vec![],
            vec![src("/etc/sysctl.conf", "vm.nr_hugepages = 1024\n")],
        );
        let cap = dual_model_verdict(&m, true, 512 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Fail, "{}", cap.detail);
        assert!(cap.detail.contains("/etc/sysctl.conf"), "{}", cap.detail);

        // Nothing anywhere: PASS.
        let cap = dual_model_verdict(&models(vec![], vec![]), true, 512 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Pass, "{}", cap.detail);
    }

    #[test]
    fn procps_reapplies_a_symlink_covered_sysctl_conf() {
        // Debian layout: 99-sysctl.conf → /etc/sysctl.conf sets the
        // lethal value, a later zz-fix.conf zeroes it. systemd honors
        // the symlink position (fixed), but procps `sysctl --system`
        // lists /etc/sysctl.conf AGAIN after every fragment, so its
        // boot re-applies the lethal value — the probe must FAIL, not
        // report systemd's PASS (review finding on #201).
        let symlinked = || src("/etc/sysctl.d/99-sysctl.conf", "vm.nr_hugepages = 1024\n");
        let fix = || src("/etc/sysctl.d/zz-fix.conf", "vm.nr_hugepages = 0\n");
        let m = models(
            vec![symlinked(), fix()],
            vec![
                symlinked(),
                fix(),
                src("/etc/sysctl.conf", "vm.nr_hugepages = 1024\n"),
            ],
        );
        let cap = dual_model_verdict(&m, true, 512 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Fail, "{}", cap.detail);
        assert!(cap.detail.contains("/etc/sysctl.conf"), "{}", cap.detail);
    }

    #[test]
    fn procps_only_lib_fragment_cannot_rescue_a_systemd_boot() {
        // Split-usr: /lib/sysctl.d/zz-fix.conf zeroes the pool, but
        // systemd-sysctl never reads /lib/sysctl.d — its boot still
        // applies the lethal /etc fragment (review finding on #201).
        let lethal = || src("/etc/sysctl.d/80-vpp.conf", "vm.nr_hugepages = 1024\n");
        let m = models(
            vec![lethal()],
            vec![
                lethal(),
                src("/lib/sysctl.d/zz-fix.conf", "vm.nr_hugepages = 0\n"),
            ],
        );
        let cap = dual_model_verdict(&m, true, 512 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Fail, "{}", cap.detail);
        assert!(cap.detail.contains("80-vpp.conf"), "{}", cap.detail);
    }

    #[test]
    fn a_severity_tie_names_both_assignments() {
        // Both models land on FAIL but from different files: fixing
        // only the fragment leaves a procps boot lethal via
        // /etc/sysctl.conf, so the verdict must name both (review
        // finding on #201).
        let fragment = || src("/etc/sysctl.d/80-vpp.conf", "vm.nr_hugepages = 1024\n");
        let m = models(
            vec![fragment()],
            vec![
                fragment(),
                src("/etc/sysctl.conf", "vm.nr_hugepages = 2048\n"),
            ],
        );
        let cap = dual_model_verdict(&m, true, 512 * MIB, MEM_64G);
        assert_eq!(cap.status, CapabilityStatus::Fail, "{}", cap.detail);
        assert!(cap.detail.contains("80-vpp.conf"), "{}", cap.detail);
        assert!(cap.detail.contains("/etc/sysctl.conf"), "{}", cap.detail);
        assert!(cap.detail.contains("remediate both"), "{}", cap.detail);
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
