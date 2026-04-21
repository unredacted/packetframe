//! Raw `bpf(2)` syscall wrapper and minimal attr/insn types.
//!
//! Targets kernel 5.15+ (SPEC.md §2.2) and little-endian only (our release
//! targets are all LE). Field layouts mirror `uapi/linux/bpf.h` as of 5.15;
//! unknown trailing fields in the caller-supplied `attr_size` are ignored by
//! older kernels, so padding out with zeros is forward-safe.
//!
//! Most items here only make sense on Linux. Constants and insn builders are
//! universal (handy for macOS-hosted tests that don't actually invoke the
//! kernel); the syscall wrapper and probe primitives are gated behind
//! `#[cfg(target_os = "linux")]` and replaced with `ENOSYS`-returning stubs
//! on other platforms so that `cargo check`/`cargo test` still succeed on
//! developer laptops.

use std::ffi::CString;
use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::ptr;

// bpf() syscall commands (subset)
pub const BPF_MAP_CREATE: u32 = 0;
pub const BPF_PROG_LOAD: u32 = 5;

// Program types we probe
pub const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
pub const BPF_PROG_TYPE_XDP: u32 = 6;

// Map types we probe (SPEC.md §2.1)
pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
pub const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
pub const BPF_MAP_TYPE_DEVMAP_HASH: u32 = 25;
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;

// Helper IDs relevant to SPEC.md §2.1. IDs are stable across kernels; the
// list is from uapi/linux/bpf.h on 5.15.
pub const HELPER_MAP_LOOKUP_ELEM: i32 = 1;
pub const HELPER_MAP_UPDATE_ELEM: i32 = 2;
pub const HELPER_MAP_DELETE_ELEM: i32 = 3;
pub const HELPER_XDP_ADJUST_HEAD: i32 = 44;
pub const HELPER_REDIRECT_MAP: i32 = 51;
pub const HELPER_FIB_LOOKUP: i32 = 69;
pub const HELPER_RINGBUF_OUTPUT: i32 = 130;
pub const HELPER_RINGBUF_RESERVE: i32 = 131;
pub const HELPER_RINGBUF_SUBMIT: i32 = 132;

const BPF_OBJ_NAME_LEN: usize = 16;

/// A single BPF instruction. Layout matches `struct bpf_insn` in
/// `uapi/linux/bpf.h`. The `regs` field packs `dst_reg` in the low nibble
/// and `src_reg` in the high nibble, per the ABI encoding (LE hosts only).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BpfInsn {
    pub code: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

pub fn mov64_imm(dst_reg: u8, imm: i32) -> BpfInsn {
    BpfInsn {
        code: 0xb7, // BPF_ALU64 | BPF_MOV | BPF_K
        regs: dst_reg & 0x0f,
        off: 0,
        imm,
    }
}

pub fn call_helper(helper_id: i32) -> BpfInsn {
    BpfInsn {
        code: 0x85, // BPF_JMP | BPF_CALL
        regs: 0,
        off: 0,
        imm: helper_id,
    }
}

pub fn exit_insn() -> BpfInsn {
    BpfInsn {
        code: 0x95, // BPF_JMP | BPF_EXIT
        regs: 0,
        off: 0,
        imm: 0,
    }
}

/// `union bpf_attr` projection for BPF_MAP_CREATE. Covers fields through 5.15.
#[repr(C)]
pub struct MapCreateAttr {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub inner_map_fd: u32,
    pub numa_node: u32,
    pub map_name: [u8; BPF_OBJ_NAME_LEN],
    pub map_ifindex: u32,
    pub btf_fd: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub btf_vmlinux_value_type_id: u32,
    pub map_extra: u64,
}

impl Default for MapCreateAttr {
    fn default() -> Self {
        Self {
            map_type: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: [0; BPF_OBJ_NAME_LEN],
            map_ifindex: 0,
            btf_fd: 0,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
            btf_vmlinux_value_type_id: 0,
            map_extra: 0,
        }
    }
}

/// `union bpf_attr` projection for BPF_PROG_LOAD. Covers fields through 5.15.
#[repr(C)]
pub struct ProgLoadAttr {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: u64,
    pub kern_version: u32,
    pub prog_flags: u32,
    pub prog_name: [u8; BPF_OBJ_NAME_LEN],
    pub prog_ifindex: u32,
    pub expected_attach_type: u32,
    pub prog_btf_fd: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub func_info_cnt: u32,
    pub line_info_rec_size: u32,
    pub line_info: u64,
    pub line_info_cnt: u32,
    pub attach_btf_id: u32,
    pub attach_prog_fd: u32,
    pub core_relo_cnt: u32,
    pub fd_array: u64,
    pub core_relos: u64,
    pub core_relo_rec_size: u32,
}

impl Default for ProgLoadAttr {
    fn default() -> Self {
        Self {
            prog_type: 0,
            insn_cnt: 0,
            insns: 0,
            license: 0,
            log_level: 0,
            log_size: 0,
            log_buf: 0,
            kern_version: 0,
            prog_flags: 0,
            prog_name: [0; BPF_OBJ_NAME_LEN],
            prog_ifindex: 0,
            expected_attach_type: 0,
            prog_btf_fd: 0,
            func_info_rec_size: 0,
            func_info: 0,
            func_info_cnt: 0,
            line_info_rec_size: 0,
            line_info: 0,
            line_info_cnt: 0,
            attach_btf_id: 0,
            attach_prog_fd: 0,
            core_relo_cnt: 0,
            fd_array: 0,
            core_relos: 0,
            core_relo_rec_size: 0,
        }
    }
}

/// Direct `syscall(SYS_bpf, cmd, attr, size)` wrapper. Linux-only.
///
/// # Safety
/// Caller must provide an `attr` pointer valid for `size` bytes and matching
/// the command's expected layout.
//
// `libc::c_long` is `i64` on 64-bit Linux and `i32` on 32-bit. The
// `as i64` on the return value is a no-op on 64-bit (what we release
// for) but a widening cast on 32-bit; suppress the no-op-cast lint
// rather than diverge the two paths.
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast)]
pub unsafe fn bpf_syscall(cmd: u32, attr: *const u8, size: u32) -> io::Result<i64> {
    let ret = unsafe { libc::syscall(libc::SYS_bpf, cmd as libc::c_long, attr, size) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret as i64)
    }
}

/// Non-Linux stub: returns ENOSYS so higher-level probes report the whole
/// host as unsupported without a build failure on dev laptops.
///
/// # Safety
/// Trivially safe — ignores all arguments.
#[cfg(not(target_os = "linux"))]
#[allow(unused_unsafe)]
pub unsafe fn bpf_syscall(_cmd: u32, _attr: *const u8, _size: u32) -> io::Result<i64> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// Attempt to create a BPF map. Returns the owning FD on success.
pub fn map_create(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
) -> io::Result<OwnedFd> {
    // `mem::zeroed` over struct-literal: the kernel's CHECK_ATTR checks
    // that bytes past the command's last field are zero; struct-literal
    // init leaves Rust's trailing padding uninitialized. Same root cause
    // as the probe/prog_load EINVAL we hit on kernel 6.0+.
    let mut attr: MapCreateAttr = unsafe { std::mem::zeroed() };
    attr.map_type = map_type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    attr.map_flags = map_flags;
    let ret = unsafe {
        bpf_syscall(
            BPF_MAP_CREATE,
            &attr as *const _ as *const u8,
            std::mem::size_of::<MapCreateAttr>() as u32,
        )?
    };
    // Safety: non-negative return from bpf(MAP_CREATE) is a fresh FD owned
    // by us.
    Ok(unsafe { OwnedFd::from_raw_fd(ret as i32) })
}

/// Outcome of a `prog_load` attempt.
pub struct ProgLoadOutcome {
    pub fd: Option<OwnedFd>,
    pub errno: Option<i32>,
    pub log: String,
}

/// Attempt to load a BPF program with a verifier log buffer. Returns outcome
/// including the log content regardless of success — callers use the log to
/// distinguish "helper unknown" vs "other verifier rejection".
pub fn prog_load(prog_type: u32, insns: &[BpfInsn], license: &str) -> io::Result<ProgLoadOutcome> {
    let license_c = CString::new(license).expect("license has no NUL");

    // 16 KiB log is plenty for our 3-5-instruction probes.
    let mut log_buf = vec![0u8; 16 * 1024];

    // `mem::zeroed` rather than struct-literal + `..Default::default()`:
    // the kernel's CHECK_ATTR validates that bytes past the command's
    // last field are zero. Rust's `Default` leaves padding bytes
    // uninitialized; kernel 6.0+ rejects this with EINVAL and no log.
    // Zeroing the whole struct, including padding, fixes the probe
    // on modern kernels.
    let mut attr: ProgLoadAttr = unsafe { std::mem::zeroed() };
    attr.prog_type = prog_type;
    attr.insn_cnt = insns.len() as u32;
    attr.insns = insns.as_ptr() as u64;
    attr.license = license_c.as_ptr() as u64;
    attr.log_level = 1; // BPF_LOG_LEVEL1 — emit verifier log
    attr.log_size = log_buf.len() as u32;
    attr.log_buf = log_buf.as_mut_ptr() as u64;

    let ret = unsafe {
        bpf_syscall(
            BPF_PROG_LOAD,
            &attr as *const _ as *const u8,
            std::mem::size_of::<ProgLoadAttr>() as u32,
        )
    };

    let log_nul = log_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(log_buf.len());
    let log = String::from_utf8_lossy(&log_buf[..log_nul]).into_owned();

    match ret {
        Ok(fd) => Ok(ProgLoadOutcome {
            fd: Some(unsafe { OwnedFd::from_raw_fd(fd as i32) }),
            errno: None,
            log,
        }),
        Err(e) => Ok(ProgLoadOutcome {
            fd: None,
            errno: e.raw_os_error(),
            log,
        }),
    }
}

/// Probe whether `bpf()` is reachable at all. A syscall with a bogus cmd and
/// NULL attr should return EINVAL on a kernel with BPF; ENOSYS means the
/// syscall is absent entirely (no-BPF kernel, or non-Linux host).
#[cfg(target_os = "linux")]
pub fn probe_bpf_syscall() -> BpfSyscallStatus {
    // Cmd 9999 doesn't exist on any kernel. Expected: EINVAL.
    let r = unsafe { bpf_syscall(9999, ptr::null(), 0) };
    match r {
        Ok(_) => BpfSyscallStatus::UnexpectedOk,
        Err(e) => match e.raw_os_error() {
            Some(libc::ENOSYS) => BpfSyscallStatus::NotImplemented,
            Some(libc::EPERM) => BpfSyscallStatus::Permission,
            Some(_) => BpfSyscallStatus::Present,
            None => BpfSyscallStatus::UnknownError,
        },
    }
}

#[cfg(not(target_os = "linux"))]
pub fn probe_bpf_syscall() -> BpfSyscallStatus {
    BpfSyscallStatus::NotImplemented
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfSyscallStatus {
    Present,
    NotImplemented,
    Permission,
    UnexpectedOk,
    UnknownError,
}
