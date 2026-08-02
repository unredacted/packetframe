//! Kernel capability probes (SPEC.md §2.1).
//!
//! The loader refuses to start if any *required* capability is missing; the
//! feasibility subcommand (`packetframe feasibility`) renders the full
//! report. Per-interface native-XDP trial-attach (§2.3) is deferred to v0.1,
//! since it requires a real program to attach, reported here as Deferred.

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
    // Helpers, probed by loading minimal XDP programs and inspecting the
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

    // CPU-performance probes (generic-XDP deployments are typically
    // CPU-limited; these surface the host knobs that matter most).
    // None are required: a JIT-off or harden-on host still *works*,
    // just slower, and feasibility gating `packetframe run` on them
    // would brick a functional deployment on restart.
    caps.push(probe_bpf_jit_enable());
    caps.push(probe_sysctl_any(
        "sysctl.net.core.bpf_jit_harden",
        "/proc/sys/net/core/bpf_jit_harden",
        &["0"],
        false,
        "set `net.core.bpf_jit_harden = 0` unless constant blinding is a hard requirement; \
         hardening adds per-instruction cost to every JITed program",
    ));
    caps.push(probe_kernel_version());

    // §2.3 per-interface native-XDP trial-attach, deferred. The probe needs
    // a real attachable program, which doesn't exist in v0.0.1.
    caps.push(Capability::deferred(
        "xdp.per_interface_attach_probe",
        "deferred to v0.1 (requires fast-path program to trial-attach)",
    ));

    FeasibilityReport::new(caps)
}

/// Per-attach-interface performance probes: GRO state and RPS masks.
/// Called by the feasibility subcommand with the config's attach set
/// (mirrors how the trial-attach probes graft in). All informational
/// (`required = false`); see `docs/runbooks/generic-mode-performance.md`
/// for what to do with the answers.
pub fn run_iface_probes(ifaces: &[String]) -> Vec<Capability> {
    let mut caps = Vec::with_capacity(ifaces.len() * 3);
    for iface in ifaces {
        caps.push(probe_iface_gro(iface));
        caps.push(probe_iface_rps(iface));
        caps.push(probe_iface_coalesce(iface));
    }
    caps
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
    // `c_char` is signed on x86_64 but unsigned on aarch64, so this cast
    // is load-bearing on the dev/CI architecture and a no-op on the
    // production one. Clippy only ever sees one of the two. Same
    // targeted-allow pattern as `statfs.f_type` in probe_bpffs.
    #[allow(clippy::unnecessary_cast)]
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
            "bpf() syscall not implemented (ENOSYS), kernel lacks BPF support",
            true,
        ),
        BpfSyscallStatus::Permission => Capability::fail(
            "syscall.bpf",
            "bpf() returned EPERM, run as root (kernel.unprivileged_bpf_disabled likely set)",
            true,
        ),
        BpfSyscallStatus::UnexpectedOk => Capability::unknown(
            "syscall.bpf",
            "bpf() returned OK for a bogus cmd, unexpected, kernel version mismatch?",
            true,
        ),
        BpfSyscallStatus::UnknownError => Capability::unknown(
            "syscall.bpf",
            "bpf() returned an error without errno, unexpected",
            true,
        ),
    }
}

fn probe_prog_type(name: &str, prog_type: u32, required: bool) -> Capability {
    // mov r0, 0; exit, a valid trivial program for any prog_type we care
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
            // ENOSYS means the bpf() syscall itself is unavailable, not a
            // helper verdict. Without a verifier run we can't say anything
            // about helper presence; defer to the syscall.bpf cap for the
            // real signal.
            if out.errno == Some(libc::ENOSYS) {
                return Capability::fail(
                    name,
                    "bpf() syscall unavailable (ENOSYS), see syscall.bpf",
                    required,
                );
            }
            // EPERM typically means we're not root and the kernel is
            // hardened (SPEC.md §2.2 on `unprivileged_bpf_disabled=2`). The
            // verifier doesn't run, so there's no log, we can't tell
            // whether the helper exists or not.
            if out.errno == Some(libc::EPERM) {
                return Capability::unknown(
                    name,
                    "prog_load returned EPERM, run as root to probe helpers",
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
                Some(libc::EPERM) => " (EPERM, run as root)",
                Some(libc::EINVAL) => " (EINVAL, map type likely unsupported)",
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

    // `statfs.f_type` varies by platform/libc: `i64` on glibc Linux x86_64,
    // `u32` on macOS, `u64` on some musl configs. Normalize to `i64` for
    // the comparison; clippy will call this unnecessary on whichever
    // platform already has `i64`, the cast is still correct on every other.
    #[allow(clippy::unnecessary_cast)]
    let f_type = statfs.f_type as i64;
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
    probe_sysctl_any(name, path, &[expected], required, fix_hint)
}

/// Like [`probe_sysctl`] but accepting any of several values, for
/// sysctls where more than one setting is fine (e.g.
/// `bpf_jit_enable` = 1 or 2, both of which mean "JIT on").
fn probe_sysctl_any(
    name: &str,
    path: &str,
    accepted: &[&str],
    required: bool,
    fix_hint: &str,
) -> Capability {
    match fs::read_to_string(path) {
        Ok(raw) => {
            let val = raw.trim();
            if accepted.contains(&val) {
                Capability::pass(name, format!("{path} = {val}"), required)
            } else {
                Capability::fail(
                    name,
                    format!(
                        "{path} = {val} (expected {}); fix: {fix_hint}",
                        accepted.join(" or ")
                    ),
                    required,
                )
            }
        }
        Err(e) => Capability::unknown(name, format!("could not read {path}: {e}"), required),
    }
}

/// `net.core.bpf_jit_enable`: 1 (JIT on) or 2 (JIT on with debug
/// output) both pass; 0 means every BPF program on the box runs in
/// the interpreter, which on a CPU-limited generic-XDP router is the
/// single most expensive misconfiguration possible.
///
/// Kernels built with `CONFIG_BPF_JIT_ALWAYS_ON=y` pin the sysctl to
/// 1, but some hardened/embedded configs hide or restrict the file;
/// when it's unreadable, fall back to the kconfig flag before
/// reporting Unknown.
fn probe_bpf_jit_enable() -> Capability {
    const NAME: &str = "sysctl.net.core.bpf_jit_enable";
    const PATH: &str = "/proc/sys/net/core/bpf_jit_enable";
    match fs::read_to_string(PATH) {
        Ok(raw) => {
            let val = raw.trim();
            if val == "1" || val == "2" {
                Capability::pass(NAME, format!("{PATH} = {val} (JIT on)"), false)
            } else {
                Capability::fail(
                    NAME,
                    format!(
                        "{PATH} = {val}: BPF runs INTERPRETED, expect several-fold higher \
                         per-packet CPU; fix: sysctl -w net.core.bpf_jit_enable=1"
                    ),
                    false,
                )
            }
        }
        Err(read_err) => match read_kconfig() {
            Ok(contents) if kconfig_flag_set(&contents, "CONFIG_BPF_JIT_ALWAYS_ON") => {
                Capability::pass(
                    NAME,
                    "sysctl not readable but CONFIG_BPF_JIT_ALWAYS_ON=y (JIT compiled always-on)",
                    false,
                )
            }
            _ => Capability::unknown(
                NAME,
                format!("could not read {PATH}: {read_err}; JIT state undetermined"),
                false,
            ),
        },
    }
}

/// Informational kernel version report. Never fails; exists so a
/// feasibility report captured from an operator includes the exact
/// kernel without a second command.
fn probe_kernel_version() -> Capability {
    match uname_release() {
        Ok(release) => Capability::pass("kernel.version", release, false),
        Err(e) => Capability::unknown("kernel.version", format!("uname failed: {e}"), false),
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

// --- Per-interface performance probes ----------------------------------

/// GRO state via the `SIOCETHTOOL`/`ETHTOOL_GGRO` ioctl (GRO is not
/// exposed in sysfs). Informational either way: with generic XDP, GRO
/// means the program sees aggregated super-skbs that the kernel must
/// linearize (copy) before the program runs, but disabling it raises
/// the per-packet count for any traffic that still traverses the
/// kernel stack. The runbook covers the trade-off; this probe just
/// reports the state.
fn probe_iface_gro(iface: &str) -> Capability {
    let name = format!("iface.{iface}.gro");
    match iface_gro_state(iface) {
        Ok(true) => Capability::pass(
            &name,
            "GRO on (generic XDP linearizes aggregated skbs; see generic-mode-performance runbook)",
            false,
        ),
        Ok(false) => Capability::pass(&name, "GRO off", false),
        Err(e) => Capability::unknown(&name, e, false),
    }
}

/// RPS masks from `/sys/class/net/<iface>/queues/rx-*/rps_cpus`.
/// Since v5.3, generic XDP runs *after* RPS steering, so a non-zero
/// mask spreads the whole XDP + skb-prep workload across CPUs. An
/// all-zeros mask on every queue is reported as a (non-required)
/// failure because on a CPU-limited generic-XDP box it is the
/// highest-leverage free tuning knob.
fn probe_iface_rps(iface: &str) -> Capability {
    let name = format!("iface.{iface}.rps");
    let queues_dir = PathBuf::from(format!("/sys/class/net/{iface}/queues"));
    let entries = match fs::read_dir(&queues_dir) {
        Ok(e) => e,
        Err(e) => {
            return Capability::unknown(
                &name,
                format!("could not read {}: {e}", queues_dir.display()),
                false,
            );
        }
    };

    let mut masks: Vec<(String, String)> = Vec::new();
    for entry in entries.flatten() {
        let qname = entry.file_name().to_string_lossy().into_owned();
        if !qname.starts_with("rx-") {
            continue;
        }
        if let Ok(raw) = fs::read_to_string(entry.path().join("rps_cpus")) {
            masks.push((qname, raw.trim().to_string()));
        }
    }
    masks.sort();

    if masks.is_empty() {
        return Capability::unknown(&name, "no rx queues with rps_cpus found", false);
    }

    let all_zero = masks.iter().all(|(_, m)| rps_mask_is_zero(m));
    let rendered = masks
        .iter()
        .map(|(q, m)| format!("{q}={m}"))
        .collect::<Vec<_>>()
        .join(", ");
    if all_zero {
        Capability::fail(
            &name,
            format!(
                "rps_cpus all zero ({rendered}): all generic-XDP work runs on the NIC's IRQ \
                 CPUs; set a spread mask, e.g. \
                 `echo <cpumask> > /sys/class/net/{iface}/queues/rx-0/rps_cpus` \
                 (see generic-mode-performance runbook)"
            ),
            false,
        )
    } else {
        Capability::pass(&name, rendered, false)
    }
}

/// An RPS cpumask is zero when every hex digit is `0` (commas are
/// group separators on >32-CPU hosts).
fn rps_mask_is_zero(mask: &str) -> bool {
    mask.chars().all(|c| c == '0' || c == ',')
}

/// IRQ coalescing via `SIOCETHTOOL`/`ETHTOOL_GCOALESCE`. On a
/// generic-XDP box every packet costs a full IRQ + NAPI wakeup when
/// the coalescing timer is effectively off; the reference EFG shipped
/// with `rx-usecs 1 rx-frames 10`, which produced ~1 IRQ per packet
/// (~800k/s at ~800 kpps) and measured −10.5% softirq/packet when
/// raised to 50/32. A timer at or below this threshold cannot
/// aggregate at realistic per-queue packet gaps (tens of µs), so it
/// is reported as a (non-required) failure with the fix inline.
/// See `docs/runbooks/generic-mode-performance.md` §"IRQ coalescing".
const COALESCE_PER_PACKET_USECS: u32 = 2;
/// A frame threshold at or below this coalesces nothing meaningful:
/// the IRQ fires every packet (1) or every other packet (2).
const COALESCE_PER_PACKET_FRAMES: u32 = 2;

/// Does this configuration effectively interrupt per packet?
///
/// The uapi semantics are a DISJUNCTION — the NIC raises an IRQ when
/// `(usecs > 0 && timer elapsed) || (frames > 0 && count reached)` —
/// so judging on `rx_usecs` alone gets both edges wrong: `rx-usecs 0
/// rx-frames 32` coalesces fine but would read as a failure, while
/// `rx-usecs 50 rx-frames 1` interrupts on every packet and would
/// read as a pass. A setting is per-packet only when EVERY armed
/// trigger is tight; a disarmed (0) trigger can't fire at all and so
/// never rescues the other one.
fn coalesce_is_per_packet(rx_usecs: u32, rx_frames: u32) -> bool {
    // Nothing armed at all: the NIC interrupts on every packet.
    if rx_usecs == 0 && rx_frames == 0 {
        return true;
    }
    // Whichever ARMED trigger fires first decides the interrupt rate,
    // so any tight one makes the configuration per-packet and a loose
    // one cannot rescue it. A disarmed (0) trigger never fires and is
    // simply not considered.
    //
    // Calibration: the reference EFG shipped `rx-usecs 1 rx-frames 10`
    // and measured ~800k IRQs/s at ~800 kpps — one per packet —
    // because the 1 µs timer always beat the 10-frame count at ~24 µs
    // per-queue packet gaps. That measurement is what the `||`
    // encodes; an `&&` would have called that configuration healthy.
    let timer_per_packet = rx_usecs > 0 && rx_usecs <= COALESCE_PER_PACKET_USECS;
    let frames_per_packet = rx_frames > 0 && rx_frames <= COALESCE_PER_PACKET_FRAMES;
    timer_per_packet || frames_per_packet
}

fn probe_iface_coalesce(iface: &str) -> Capability {
    let name = format!("iface.{iface}.coalesce");
    match iface_coalesce_state(iface) {
        Ok(st) if st.adaptive_rx => Capability::unknown(
            &name,
            format!(
                "adaptive RX coalescing is enabled (resting rx-usecs {} / rx-frames {}): the \
                 driver varies these by packet rate, so the resting values do not describe \
                 behavior under forwarding load. Measure IRQs/sec directly \
                 (/proc/interrupts) before concluding anything",
                st.rx_usecs, st.rx_frames
            ),
            false,
        ),
        Ok(st) => {
            let (rx_usecs, rx_frames) = (st.rx_usecs, st.rx_frames);
            if coalesce_is_per_packet(rx_usecs, rx_frames) {
                Capability::fail(
                    &name,
                    format!(
                        "rx-usecs {rx_usecs} / rx-frames {rx_frames}: effectively one IRQ per \
                         packet at forwarding rates; \
                         `ethtool -C {iface} rx-usecs 50 rx-frames 32 tx-usecs 50 tx-frames 32` \
                         measured −10.5% softirq/packet on the reference EFG — settings do not \
                         survive reboot, see generic-mode-performance runbook §IRQ coalescing \
                         for persistence"
                    ),
                    false,
                )
            } else {
                Capability::pass(
                    &name,
                    format!("rx-usecs {rx_usecs} / rx-frames {rx_frames}"),
                    false,
                )
            }
        }
        Err(e) => Capability::unknown(&name, e, false),
    }
}

/// The subset of `ethtool_coalesce` the verdict depends on.
#[derive(Debug, Clone, Copy)]
struct CoalesceState {
    rx_usecs: u32,
    rx_frames: u32,
    adaptive_rx: bool,
}

#[cfg(target_os = "linux")]
fn iface_coalesce_state(iface: &str) -> Result<CoalesceState, String> {
    // uapi `struct ethtool_coalesce`: cmd + 22 u32 parameter fields.
    // Only rx_coalesce_usecs and rx_max_coalesced_frames are read;
    // the rest exist so the kernel writes into memory we own.
    const ETHTOOL_GCOALESCE: u32 = 0x0000_000e;
    // Width-neutral for the ioctl request cast; see iface_gro_state.
    const SIOCETHTOOL: u32 = 0x8946;
    #[repr(C)]
    #[derive(Default)]
    struct EthtoolCoalesce {
        cmd: u32,
        rx_coalesce_usecs: u32,
        rx_max_coalesced_frames: u32,
        rx_coalesce_usecs_irq: u32,
        rx_max_coalesced_frames_irq: u32,
        tx_coalesce_usecs: u32,
        tx_max_coalesced_frames: u32,
        tx_coalesce_usecs_irq: u32,
        tx_max_coalesced_frames_irq: u32,
        stats_block_coalesce_usecs: u32,
        /// Non-zero means the driver varies the RX settings by packet
        /// rate, so the resting values above do not describe behavior
        /// under forwarding load (a resting 50 can become 1 at rate).
        use_adaptive_rx_coalesce: u32,
        rest: [u32; 13],
    }

    let name_bytes = iface.as_bytes();
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    if name_bytes.len() >= ifr.ifr_name.len() {
        return Err(format!("interface name `{iface}` exceeds IFNAMSIZ"));
    }
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name_bytes) {
        *dst = *src as libc::c_char;
    }

    let mut value = EthtoolCoalesce {
        cmd: ETHTOOL_GCOALESCE,
        ..Default::default()
    };
    ifr.ifr_ifru.ifru_data = &mut value as *mut EthtoolCoalesce as *mut libc::c_char;

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(format!(
            "socket(AF_INET, SOCK_DGRAM) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    #[allow(clippy::unnecessary_cast)]
    let r = unsafe { libc::ioctl(sock, SIOCETHTOOL as _, &mut ifr) };
    let ioctl_err = std::io::Error::last_os_error();
    unsafe { libc::close(sock) };
    if r != 0 {
        // EOPNOTSUPP is a normal answer (virtual devices, some
        // drivers); the caller renders it as Unknown, not Fail.
        return Err(format!(
            "SIOCETHTOOL/ETHTOOL_GCOALESCE on {iface} failed: {ioctl_err}"
        ));
    }
    Ok(CoalesceState {
        rx_usecs: value.rx_coalesce_usecs,
        rx_frames: value.rx_max_coalesced_frames,
        adaptive_rx: value.use_adaptive_rx_coalesce != 0,
    })
}

#[cfg(not(target_os = "linux"))]
fn iface_coalesce_state(_iface: &str) -> Result<CoalesceState, String> {
    Err("coalescing probe is Linux-only".to_string())
}

#[cfg(target_os = "linux")]
fn iface_gro_state(iface: &str) -> Result<bool, String> {
    // ethtool_value { cmd, data } with ETHTOOL_GGRO. A read-only get;
    // no privileges required.
    const ETHTOOL_GGRO: u32 = 0x0000_002b;
    // Kept target-width-neutral: libc::ioctl's request parameter is
    // `c_ulong` (u64) on glibc but `c_int` (i32) on musl, so the
    // constant is a plain u32 and the call site casts with `as _` to
    // whichever type the target's libc declares (the value fits both).
    // Same targeted-cast pattern as `statfs.f_type` in probe_bpffs.
    const SIOCETHTOOL: u32 = 0x8946;
    #[repr(C)]
    struct EthtoolValue {
        cmd: u32,
        data: u32,
    }

    let name_bytes = iface.as_bytes();
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    if name_bytes.len() >= ifr.ifr_name.len() {
        return Err(format!("interface name `{iface}` exceeds IFNAMSIZ"));
    }
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name_bytes) {
        *dst = *src as libc::c_char;
    }

    let mut value = EthtoolValue {
        cmd: ETHTOOL_GGRO,
        data: 0,
    };
    ifr.ifr_ifru.ifru_data = &mut value as *mut EthtoolValue as *mut libc::c_char;

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(format!(
            "socket(AF_INET, SOCK_DGRAM) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    #[allow(clippy::unnecessary_cast)]
    let r = unsafe { libc::ioctl(sock, SIOCETHTOOL as _, &mut ifr) };
    let ioctl_err = std::io::Error::last_os_error();
    unsafe { libc::close(sock) };
    if r != 0 {
        return Err(format!(
            "SIOCETHTOOL/ETHTOOL_GGRO on {iface} failed: {ioctl_err}"
        ));
    }
    Ok(value.data != 0)
}

#[cfg(not(target_os = "linux"))]
fn iface_gro_state(_iface: &str) -> Result<bool, String> {
    Err("GRO probe is Linux-only".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coalesce_per_packet_threshold() {
        // The EFG shipped at rx-usecs 1 / rx-frames 10 (flagged); the
        // runbook fix is 50/32 (passes).
        assert!(coalesce_is_per_packet(1, 10));
        assert!(!coalesce_is_per_packet(50, 32));

        // Both triggers armed: whichever fires first wins, so a tight
        // timer OR tight frame count is enough to be per-packet.
        assert!(coalesce_is_per_packet(50, 1), "frames=1 fires every packet");
        assert!(coalesce_is_per_packet(2, 64), "usecs=2 fires every packet");
        assert!(!coalesce_is_per_packet(3, 3), "both just past the line");

        // A disarmed (0) trigger cannot fire, so it must not rescue
        // the other one — nor condemn it.
        assert!(
            !coalesce_is_per_packet(0, 32),
            "frame-only threshold of 32 coalesces fine"
        );
        assert!(
            coalesce_is_per_packet(0, 1),
            "frame-only threshold of 1 is per-packet"
        );
        assert!(
            !coalesce_is_per_packet(50, 0),
            "timer-only threshold of 50us coalesces fine"
        );
        assert!(coalesce_is_per_packet(1, 0), "timer-only 1us is per-packet");

        // Nothing armed at all: the NIC interrupts per packet.
        assert!(coalesce_is_per_packet(0, 0));
    }

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

    #[test]
    fn sysctl_any_accepts_each_listed_value() {
        let dir = std::env::temp_dir().join(format!("pf-probe-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("jit");
        let path_str = path.to_str().unwrap();

        for good in ["1", "2"] {
            fs::write(&path, format!("{good}\n")).unwrap();
            let cap = probe_sysctl_any("t", path_str, &["1", "2"], false, "hint");
            assert_eq!(cap.status, CapabilityStatus::Pass, "value {good}");
        }

        fs::write(&path, "0\n").unwrap();
        let cap = probe_sysctl_any("t", path_str, &["1", "2"], false, "hint");
        assert_eq!(cap.status, CapabilityStatus::Fail);
        assert!(cap.detail.contains("1 or 2"), "detail: {}", cap.detail);

        let cap = probe_sysctl_any(
            "t",
            dir.join("absent").to_str().unwrap(),
            &["1"],
            false,
            "h",
        );
        assert_eq!(cap.status, CapabilityStatus::Unknown);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rps_mask_zero_detection() {
        assert!(rps_mask_is_zero("0"));
        assert!(rps_mask_is_zero("00000000"));
        assert!(rps_mask_is_zero("00000000,00000000"));
        assert!(!rps_mask_is_zero("f"));
        assert!(!rps_mask_is_zero("00000000,00000001"));
    }

    /// Loopback GRO smoke test: the probe must produce a clean verdict
    /// (Pass or Unknown), never panic. Runs unprivileged; the get-side
    /// ethtool ioctl needs no capabilities.
    #[test]
    #[cfg(target_os = "linux")]
    fn iface_gro_probe_on_loopback() {
        let cap = probe_iface_gro("lo");
        assert!(
            matches!(
                cap.status,
                CapabilityStatus::Pass | CapabilityStatus::Unknown
            ),
            "unexpected status {:?}: {}",
            cap.status,
            cap.detail
        );
        assert!(!cap.required);
    }

    #[test]
    fn iface_probes_shape() {
        // Three caps per iface, names prefixed with the iface. On
        // non-Linux all come back Unknown, which is fine — the shape
        // is what this asserts.
        let caps = run_iface_probes(&["eth0".to_string(), "eth1".to_string()]);
        assert_eq!(caps.len(), 6);
        assert_eq!(caps[0].name, "iface.eth0.gro");
        assert_eq!(caps[1].name, "iface.eth0.rps");
        assert_eq!(caps[2].name, "iface.eth0.coalesce");
        assert_eq!(caps[3].name, "iface.eth1.gro");
        assert_eq!(caps[4].name, "iface.eth1.rps");
        assert_eq!(caps[5].name, "iface.eth1.coalesce");
        assert!(caps.iter().all(|c| !c.required));
    }
}
