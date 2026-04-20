//! Kernel capability probes (SPEC.md §2.1).
//!
//! The loader refuses to start if any *required* capability is missing; the
//! feasibility subcommand (`packetframe feasibility`) renders the full
//! report. Per-interface native-XDP trial-attach (§2.3) is deferred to v0.1,
//! since it requires a real program to attach — reported here as Deferred.

pub mod bpf;

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Serialize;

use bpf::{
    call_helper, exit_insn, map_create, mov64_imm, probe_bpf_syscall, prog_load, BpfSyscallStatus,
    BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_DEVMAP_HASH, BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_LPM_TRIE,
    BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_RINGBUF, BPF_PROG_TYPE_SCHED_CLS, BPF_PROG_TYPE_XDP,
    HELPER_FIB_LOOKUP, HELPER_MAP_DELETE_ELEM, HELPER_MAP_LOOKUP_ELEM, HELPER_MAP_UPDATE_ELEM,
    HELPER_REDIRECT_MAP, HELPER_RINGBUF_OUTPUT, HELPER_RINGBUF_RESERVE, HELPER_RINGBUF_SUBMIT,
    HELPER_XDP_ADJUST_HEAD,
};

/// Magic number identifying the bpffs filesystem. `statfs.f_type` equals
/// this value for any path whose parent mount is bpffs.
const BPF_FS_MAGIC: i64 = 0xcafe4a11u32 as i64;

// LPM_TRIE requires BPF_F_NO_PREALLOC at create time.
const BPF_F_NO_PREALLOC: u32 = 0x01;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityStatus {
    Pass,
    Fail,
    Unknown,
    Deferred,
}

#[derive(Debug, Clone, Serialize)]
pub struct Capability {
    pub name: String,
    pub status: CapabilityStatus,
    pub detail: String,
    pub required: bool,
}

impl Capability {
    fn pass(name: impl Into<String>, detail: impl Into<String>, required: bool) -> Self {
        Self {
            name: name.into(),
            status: CapabilityStatus::Pass,
            detail: detail.into(),
            required,
        }
    }

    fn fail(name: impl Into<String>, detail: impl Into<String>, required: bool) -> Self {
        Self {
            name: name.into(),
            status: CapabilityStatus::Fail,
            detail: detail.into(),
            required,
        }
    }

    fn unknown(name: impl Into<String>, detail: impl Into<String>, required: bool) -> Self {
        Self {
            name: name.into(),
            status: CapabilityStatus::Unknown,
            detail: detail.into(),
            required,
        }
    }

    fn deferred(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: CapabilityStatus::Deferred,
            detail: detail.into(),
            required: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FeasibilityReport {
    pub version: &'static str,
    pub passed: bool,
    pub capabilities: Vec<Capability>,
}

impl FeasibilityReport {
    pub fn new(capabilities: Vec<Capability>) -> Self {
        // Pass requires every `required` capability to be Pass. Unknown on a
        // required capability counts as failure (we can't promise the runtime
        // will find what it needs).
        let passed = capabilities
            .iter()
            .filter(|c| c.required)
            .all(|c| c.status == CapabilityStatus::Pass);
        Self {
            version: env!("CARGO_PKG_VERSION"),
            passed,
            capabilities,
        }
    }
}

/// Run every SPEC.md §2.1 probe. `bpffs_root` is the directory the loader
/// will use for pins (matches the `bpffs-root` config directive, default
/// `/sys/fs/bpf/packetframe`).
pub fn run_probes(bpffs_root: &Path) -> FeasibilityReport {
    // Helpers — probed by loading minimal XDP programs and inspecting the
    // verifier log. Any log substring matching "unknown func" /
    // "unrecognized bpf_func_id" / "invalid func" means the helper is not
    // compiled into this kernel.
    let helper_probes: [(&str, i32); 9] = [
        ("helper.bpf_map_lookup_elem", HELPER_MAP_LOOKUP_ELEM),
        ("helper.bpf_map_update_elem", HELPER_MAP_UPDATE_ELEM),
        ("helper.bpf_map_delete_elem", HELPER_MAP_DELETE_ELEM),
        ("helper.bpf_xdp_adjust_head", HELPER_XDP_ADJUST_HEAD),
        ("helper.bpf_redirect_map", HELPER_REDIRECT_MAP),
        ("helper.bpf_fib_lookup", HELPER_FIB_LOOKUP),
        ("helper.bpf_ringbuf_output", HELPER_RINGBUF_OUTPUT),
        ("helper.bpf_ringbuf_reserve", HELPER_RINGBUF_RESERVE),
        ("helper.bpf_ringbuf_submit", HELPER_RINGBUF_SUBMIT),
    ];

    let mut caps = vec![
        probe_kconfig(),
        probe_bpf_syscall_available(),
        probe_prog_type("prog_type.xdp", BPF_PROG_TYPE_XDP, true),
        probe_prog_type("prog_type.sched_cls", BPF_PROG_TYPE_SCHED_CLS, true),
        probe_map_hash(),
        probe_map_array(),
        probe_map_percpu_array(),
        probe_map_lpm_trie(),
        probe_map_devmap_hash(),
        probe_map_ringbuf(),
    ];

    caps.extend(
        helper_probes
            .iter()
            .map(|(name, id)| probe_helper(name, *id, true)),
    );

    caps.push(probe_bpffs(bpffs_root));
    caps.push(probe_sysctl(
        "sysctl.net.ipv4.ip_forward",
        "/proc/sys/net/ipv4/ip_forward",
        "1",
        true,
        "set `net.ipv4.ip_forward = 1` (required for bpf_fib_lookup to match kernel routing)",
    ));
    caps.push(probe_sysctl(
        "sysctl.net.ipv6.conf.all.forwarding",
        "/proc/sys/net/ipv6/conf/all/forwarding",
        "1",
        false,
        "set `net.ipv6.conf.all.forwarding = 1` if IPv6 fast-path is in use",
    ));
    caps.push(probe_memlock());

    // §2.3 per-interface native-XDP trial-attach — deferred. The probe needs
    // a real attachable program, which doesn't exist in v0.0.1.
    caps.push(Capability::deferred(
        "xdp.per_interface_attach_probe",
        "deferred to v0.1 (requires fast-path program to trial-attach)",
    ));

    FeasibilityReport::new(caps)
}

fn probe_kconfig() -> Capability {
    let flags = ["CONFIG_BPF", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_JIT"];
    match read_kconfig() {
        Ok(contents) => {
            let missing: Vec<&str> = flags
                .iter()
                .filter(|f| !kconfig_flag_set(&contents, f))
                .copied()
                .collect();
            if missing.is_empty() {
                Capability::pass(
                    "kconfig",
                    "CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y, CONFIG_BPF_JIT=y all present",
                    true,
                )
            } else {
                Capability::fail(
                    "kconfig",
                    format!("missing or disabled: {}", missing.join(", ")),
                    true,
                )
            }
        }
        Err(e) => Capability::unknown(
            "kconfig",
            format!("could not read kernel config ({e}); rely on behavioral probes"),
            false,
        ),
    }
}

fn read_kconfig() -> std::io::Result<String> {
    // Prefer /proc/config.gz (in-kernel config) → /boot/config-$(uname -r).
    let proc_gz = Path::new("/proc/config.gz");
    if proc_gz.exists() {
        let raw = fs::read(proc_gz)?;
        let mut d = flate2::read::GzDecoder::new(&raw[..]);
        let mut out = String::new();
        d.read_to_string(&mut out)?;
        return Ok(out);
    }

    let uname = uname_release()?;
    let boot = PathBuf::from(format!("/boot/config-{uname}"));
    if boot.exists() {
        return fs::read_to_string(&boot);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "neither /proc/config.gz nor /boot/config-$(uname -r) available",
    ))
}

fn kconfig_flag_set(contents: &str, flag: &str) -> bool {
    contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .any(|l| {
            l == format!("{flag}=y")
                || l == format!("{flag}=m")
                || l.starts_with(&format!("{flag}="))
        })
}

fn uname_release() -> std::io::Result<String> {
    let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::uname(&mut buf) };
    if r != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // release is a fixed-size C string; read up to the first NUL.
    let release = &buf.release;
    let end = release
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(release.len());
    let bytes: Vec<u8> = release[..end].iter().map(|&c| c as u8).collect();
    String::from_utf8(bytes).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("utsname release not UTF-8: {e}"),
        )
    })
}

fn probe_bpf_syscall_available() -> Capability {
    match probe_bpf_syscall() {
        BpfSyscallStatus::Present => Capability::pass(
            "syscall.bpf",
            "bpf() syscall reachable (rejects bogus cmd as expected)",
            true,
        ),
        BpfSyscallStatus::NotImplemented => Capability::fail(
            "syscall.bpf",
            "bpf() syscall not implemented (ENOSYS) — kernel lacks BPF support",
            true,
        ),
        BpfSyscallStatus::Permission => Capability::fail(
            "syscall.bpf",
            "bpf() returned EPERM — run as root (kernel.unprivileged_bpf_disabled likely set)",
            true,
        ),
        BpfSyscallStatus::UnexpectedOk => Capability::unknown(
            "syscall.bpf",
            "bpf() returned OK for a bogus cmd — unexpected, kernel version mismatch?",
            true,
        ),
        BpfSyscallStatus::UnknownError => Capability::unknown(
            "syscall.bpf",
            "bpf() returned an error without errno — unexpected",
            true,
        ),
    }
}

fn probe_prog_type(name: &str, prog_type: u32, required: bool) -> Capability {
    // mov r0, 0; exit — a valid trivial program for any prog_type we care
    // about (XDP returns XDP_ABORTED=0, sched_cls returns TC_ACT_OK=0).
    let insns = [mov64_imm(0, 0), exit_insn()];
    match prog_load(prog_type, &insns, "GPL") {
        Ok(out) => {
            if out.fd.is_some() {
                Capability::pass(name, "loaded trivial program successfully", required)
            } else {
                let log_hint = first_log_line(&out.log);
                Capability::fail(
                    name,
                    format!("prog_load failed with errno {:?}: {log_hint}", out.errno),
                    required,
                )
            }
        }
        Err(e) => Capability::fail(name, format!("prog_load syscall error: {e}"), required),
    }
}

/// Probe a helper by loading a 3-instruction program: `call helper; mov r0,
/// 0; exit`. Any verifier rejection that isn't "unknown func" / "unrecognized
/// bpf_func_id" / "invalid func" means the helper is present (verifier just
/// didn't like our bogus args).
fn probe_helper(name: &str, helper_id: i32, required: bool) -> Capability {
    let insns = [call_helper(helper_id), mov64_imm(0, 0), exit_insn()];
    match prog_load(BPF_PROG_TYPE_XDP, &insns, "GPL") {
        Ok(out) => {
            if out.fd.is_some() {
                return Capability::pass(name, "helper present (program accepted)", required);
            }
            // ENOSYS means the bpf() syscall itself is unavailable — not a
            // helper verdict. Without a verifier run we can't say anything
            // about helper presence; defer to the syscall.bpf cap for the
            // real signal.
            if out.errno == Some(libc::ENOSYS) {
                return Capability::fail(
                    name,
                    "bpf() syscall unavailable (ENOSYS) — see syscall.bpf",
                    required,
                );
            }
            // EPERM typically means we're not root and the kernel is
            // hardened (SPEC.md §2.2 on `unprivileged_bpf_disabled=2`). The
            // verifier doesn't run, so there's no log — we can't tell
            // whether the helper exists or not.
            if out.errno == Some(libc::EPERM) {
                return Capability::unknown(
                    name,
                    "prog_load returned EPERM — run as root to probe helpers",
                    required,
                );
            }
            // If the verifier log is empty but errno is set, the verifier
            // never actually looked at our program. Report Unknown rather
            // than claiming the helper is present.
            if out.log.is_empty() {
                return Capability::unknown(
                    name,
                    format!(
                        "prog_load failed without a verifier log (errno {:?}); cannot determine helper presence",
                        out.errno
                    ),
                    required,
                );
            }
            if log_indicates_unknown_helper(&out.log) {
                Capability::fail(
                    name,
                    format!(
                        "helper not in kernel (verifier: {})",
                        first_log_line(&out.log)
                    ),
                    required,
                )
            } else {
                Capability::pass(
                    name,
                    "helper present (verifier rejected args, which is expected)",
                    required,
                )
            }
        }
        Err(e) => Capability::unknown(name, format!("prog_load syscall error: {e}"), required),
    }
}

fn log_indicates_unknown_helper(log: &str) -> bool {
    // Kernel verifier phrases for "this helper doesn't exist":
    //   - "unknown func bpf_..." / "unknown func #N"   (most 5.x kernels)
    //   - "unrecognized bpf_func_id"                   (older 4.x kernels)
    //   - "invalid func ..."                           (uncommon, some refactors)
    log.contains("unknown func")
        || log.contains("unrecognized bpf_func_id")
        || log.contains("invalid func")
}

fn first_log_line(log: &str) -> String {
    log.lines().next().unwrap_or("").to_string()
}

fn probe_map_hash() -> Capability {
    map_probe("map.hash", BPF_MAP_TYPE_HASH, 4, 4, 1, 0, true)
}

fn probe_map_array() -> Capability {
    map_probe("map.array", BPF_MAP_TYPE_ARRAY, 4, 4, 1, 0, true)
}

fn probe_map_percpu_array() -> Capability {
    map_probe(
        "map.percpu_array",
        BPF_MAP_TYPE_PERCPU_ARRAY,
        4,
        4,
        1,
        0,
        true,
    )
}

fn probe_map_lpm_trie() -> Capability {
    // LPM_TRIE: min key is {prefix_len: u32, data: [u8; N]}. N=1 keeps the
    // map smallest. BPF_F_NO_PREALLOC is mandatory for LPM_TRIE.
    map_probe(
        "map.lpm_trie",
        BPF_MAP_TYPE_LPM_TRIE,
        5,
        4,
        1,
        BPF_F_NO_PREALLOC,
        true,
    )
}

fn probe_map_devmap_hash() -> Capability {
    map_probe(
        "map.devmap_hash",
        BPF_MAP_TYPE_DEVMAP_HASH,
        4,
        4,
        1,
        0,
        true,
    )
}

fn probe_map_ringbuf() -> Capability {
    // RINGBUF max_entries is the buffer size in bytes: must be a power of 2
    // and a multiple of page size. 64 KiB is safe across 4 KiB and 16 KiB
    // page systems (some aarch64 hosts use 16 KiB pages).
    map_probe("map.ringbuf", BPF_MAP_TYPE_RINGBUF, 0, 0, 65536, 0, true)
}

fn map_probe(
    name: &str,
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
    required: bool,
) -> Capability {
    match map_create(map_type, key_size, value_size, max_entries, flags) {
        Ok(_fd) => Capability::pass(name, "map_create succeeded", required),
        Err(e) => {
            let hint = match e.raw_os_error() {
                Some(libc::EPERM) => " (EPERM — run as root)",
                Some(libc::EINVAL) => " (EINVAL — map type likely unsupported)",
                _ => "",
            };
            Capability::fail(name, format!("map_create failed: {e}{hint}"), required)
        }
    }
}

fn probe_bpffs(path: &Path) -> Capability {
    // If the root path itself doesn't exist yet, walk up until we find a
    // parent that does and check that. The loader will mkdir the pin
    // subtree later; what matters now is that *something* bpffs-shaped is
    // mounted underneath.
    let mut probe = path.to_path_buf();
    while !probe.exists() {
        match probe.parent() {
            Some(p) if !p.as_os_str().is_empty() => probe = p.to_path_buf(),
            _ => {
                return Capability::fail(
                    "bpffs",
                    format!("no existing ancestor of {}", path.display()),
                    true,
                );
            }
        }
    }

    let c = match std::ffi::CString::new(probe.as_os_str().as_encoded_bytes()) {
        Ok(c) => c,
        Err(_) => {
            return Capability::fail(
                "bpffs",
                format!("path {} contains NUL byte", probe.display()),
                true,
            );
        }
    };

    let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::statfs(c.as_ptr(), &mut statfs) };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        return Capability::fail(
            "bpffs",
            format!("statfs({}) failed: {e}", probe.display()),
            true,
        );
    }

    let f_type: i64 = statfs.f_type as i64;
    if f_type == BPF_FS_MAGIC {
        Capability::pass(
            "bpffs",
            format!(
                "{} is bpffs (f_type=0x{:x})",
                probe.display(),
                f_type as u32
            ),
            true,
        )
    } else {
        Capability::fail(
            "bpffs",
            format!(
                "{} is not bpffs (f_type=0x{:x}); mount bpffs at {} or set `bpffs-root` in config",
                probe.display(),
                f_type as u32,
                path.display(),
            ),
            true,
        )
    }
}

fn probe_sysctl(
    name: &str,
    path: &str,
    expected: &str,
    required: bool,
    fix_hint: &str,
) -> Capability {
    match fs::read_to_string(path) {
        Ok(raw) => {
            let val = raw.trim();
            if val == expected {
                Capability::pass(name, format!("{path} = {val}"), required)
            } else {
                Capability::fail(
                    name,
                    format!("{path} = {val} (expected {expected}); fix: {fix_hint}"),
                    required,
                )
            }
        }
        Err(e) => Capability::unknown(name, format!("could not read {path}: {e}"), required),
    }
}

fn probe_memlock() -> Capability {
    let mut cur: libc::rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let r = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut cur) };
    if r != 0 {
        let e = std::io::Error::last_os_error();
        return Capability::unknown("rlimit.memlock", format!("getrlimit failed: {e}"), true);
    }
    let before_cur = cur.rlim_cur;

    let target = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let set_r = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &target) };

    // Re-read to see what actually took.
    let mut after: libc::rlimit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let _ = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut after) };

    if set_r == 0 {
        Capability::pass(
            "rlimit.memlock",
            format!("set to infinity (was {before_cur})"),
            true,
        )
    } else {
        let e = std::io::Error::last_os_error();
        // A non-infinity but generous limit is still acceptable for many
        // small programs. Mark Unknown rather than Fail since we can't tell
        // from here whether it's tight enough.
        Capability::unknown(
            "rlimit.memlock",
            format!(
                "could not set RLIM_INFINITY ({e}); current = {}",
                after.rlim_cur
            ),
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kconfig_flag_matching() {
        let sample = r#"
# auto-generated
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
# CONFIG_BPF_UNPRIV_DEFAULT_OFF is not set
CONFIG_BPF_JIT=y
CONFIG_HZ=250
"#;
        assert!(kconfig_flag_set(sample, "CONFIG_BPF"));
        assert!(kconfig_flag_set(sample, "CONFIG_BPF_SYSCALL"));
        assert!(kconfig_flag_set(sample, "CONFIG_BPF_JIT"));
        assert!(!kconfig_flag_set(sample, "CONFIG_BPF_UNPRIV_DEFAULT_OFF"));
        assert!(!kconfig_flag_set(sample, "CONFIG_NONEXISTENT"));
    }

    #[test]
    fn unknown_helper_heuristic() {
        assert!(log_indicates_unknown_helper(
            "12: (85) call unknown\nunknown func #999\n"
        ));
        assert!(log_indicates_unknown_helper("unrecognized bpf_func_id 999"));
        assert!(log_indicates_unknown_helper(
            "invalid func bpf_magic_helper#999"
        ));
        assert!(!log_indicates_unknown_helper(
            "R1 type=inv expected=ctx, ctx_or_null\n"
        ));
    }

    #[test]
    fn report_passes_when_all_required_pass() {
        let caps = vec![
            Capability::pass("a", "ok", true),
            Capability::pass("b", "ok", true),
            Capability::fail("optional", "bad", false),
        ];
        assert!(FeasibilityReport::new(caps).passed);
    }

    #[test]
    fn report_fails_when_required_fails() {
        let caps = vec![
            Capability::pass("a", "ok", true),
            Capability::fail("b", "bad", true),
        ];
        assert!(!FeasibilityReport::new(caps).passed);
    }

    #[test]
    fn report_fails_when_required_unknown() {
        let caps = vec![Capability::unknown("a", "idk", true)];
        assert!(!FeasibilityReport::new(caps).passed);
    }

    #[test]
    fn report_passes_over_deferred() {
        let caps = vec![
            Capability::pass("a", "ok", true),
            Capability::deferred("deferred_probe", "see v0.1"),
        ];
        assert!(FeasibilityReport::new(caps).passed);
    }
}
