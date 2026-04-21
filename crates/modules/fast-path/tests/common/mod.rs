//! Shared test harness for `bpf_prog_test_run`-backed fixtures.
//!
//! aya 0.13.1 doesn't expose a `test_run` wrapper for XDP programs,
//! so we invoke `bpf(BPF_PROG_TEST_RUN)` directly via `libc::syscall`.
//! The kernel executes the BPF program against a caller-supplied
//! synthetic packet and returns the verdict + any mutated packet bytes.
//!
//! Usage:
//! ```ignore
//! let mut h = Harness::new();
//! h.add_allow_v4("10.0.0.0/8");
//! let (verdict, out) = h.run(&packet);
//! assert_eq!(verdict, xdp_action::XDP_PASS);
//! assert_eq!(h.stat(StatIdx::MatchedV4), 0);
//! ```
//!
//! Requires CAP_BPF + CAP_NET_ADMIN; callers mark tests `#[ignore]`
//! and CI runs them under sudo.

#![cfg(target_os = "linux")]
#![allow(dead_code)] // Used from multiple integration-test files; unused warnings fire per-file.

use std::os::fd::{AsFd, AsRawFd};

use aya::{
    maps::{lpm_trie::Key as LpmKey, Array, LpmTrie, PerCpuArray},
    programs::{ProgramFd, Xdp},
    Ebpf, Pod,
};
use packetframe_fast_path::aligned_bpf_copy;

/// Layout mirror of `FpCfg` in `bpf/src/maps.rs`. Must track
/// `linux_impl::FpCfg` — if you change one, change both (and both's
/// ordering in the StatIdx enum at the same time).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FpCfg {
    pub dry_run: u8,
    pub flags: u8,
    pub _reserved: [u8; 2],
    pub version: u32,
}

unsafe impl Pod for FpCfg {}

pub const FP_CFG_VERSION_V1: u32 = 0;
pub const STATS_COUNT: u32 = 19;

/// Wire-format counter indices (SPEC.md §4.6). Append-only once v0.1
/// ships; never renumber.
#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum StatIdx {
    RxTotal = 0,
    MatchedV4 = 1,
    MatchedV6 = 2,
    MatchedSrcOnly = 3,
    MatchedDstOnly = 4,
    MatchedBoth = 5,
    FwdOk = 6,
    FwdDryRun = 7,
    PassFragment = 8,
    PassLowTtl = 9,
    PassNoNeigh = 10,
    PassNotIp = 11,
    PassFragNeeded = 12,
    DropUnreachable = 13,
    ErrParse = 14,
    ErrFibOther = 15,
    ErrVlan = 16,
    PassNotInDevmap = 17,
    PassComplexHeader = 18,
}

/// Minimum XDP verdict constants. Pulled in locally to avoid a
/// dev-dep on aya-ebpf (nightly-only).
pub mod xdp_action {
    pub const XDP_ABORTED: u32 = 0;
    pub const XDP_DROP: u32 = 1;
    pub const XDP_PASS: u32 = 2;
    pub const XDP_TX: u32 = 3;
    pub const XDP_REDIRECT: u32 = 4;
}

pub struct Harness {
    pub bpf: Ebpf,
}

impl Harness {
    /// Load + verify the fast-path program. Panics if BPF isn't built
    /// or the kernel rejects it.
    pub fn new() -> Self {
        let bytes = aligned_bpf_copy();
        let mut bpf = Ebpf::load(&bytes).expect("aya::Ebpf::load");

        let prog: &mut Xdp = bpf
            .program_mut("fast_path")
            .expect("fast_path program present")
            .try_into()
            .expect("program is XDP-typed");
        prog.load().expect("verifier accepts program");

        // Set a default cfg with dry_run=off and both families enabled.
        let mut harness = Self { bpf };
        harness.set_cfg(FpCfg {
            dry_run: 0,
            flags: 0b11,
            _reserved: [0; 2],
            version: FP_CFG_VERSION_V1,
        });
        harness
    }

    pub fn set_cfg(&mut self, cfg: FpCfg) {
        let map = self.bpf.map_mut("CFG").expect("CFG map");
        let mut arr: Array<_, FpCfg> = Array::try_from(map).expect("CFG try_from");
        arr.set(0, cfg, 0).expect("CFG set");
    }

    pub fn set_dry_run(&mut self, on: bool) {
        self.set_cfg(FpCfg {
            dry_run: u8::from(on),
            flags: 0b11,
            _reserved: [0; 2],
            version: FP_CFG_VERSION_V1,
        });
    }

    /// Insert an IPv4 prefix into the allowlist. `prefix` is
    /// `"A.B.C.D/N"`.
    pub fn add_allow_v4(&mut self, prefix: &str) {
        let (addr, plen) = parse_v4_prefix(prefix);
        let map = self.bpf.map_mut("ALLOW_V4").expect("ALLOW_V4 map");
        let mut trie: LpmTrie<_, [u8; 4], u8> = LpmTrie::try_from(map).expect("LpmTrie try_from");
        let key = LpmKey::new(u32::from(plen), addr);
        trie.insert(&key, 1u8, 0).expect("ALLOW_V4 insert");
    }

    /// Insert an IPv6 prefix into the allowlist.
    pub fn add_allow_v6(&mut self, prefix: &str) {
        let (addr, plen) = parse_v6_prefix(prefix);
        let map = self.bpf.map_mut("ALLOW_V6").expect("ALLOW_V6 map");
        let mut trie: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(map).expect("LpmTrie try_from");
        let key = LpmKey::new(u32::from(plen), addr);
        trie.insert(&key, 1u8, 0).expect("ALLOW_V6 insert");
    }

    /// Run the BPF program against `packet`. Returns (verdict, output
    /// bytes). The kernel may have mutated the packet (L2 rewrite, TTL
    /// decrement) on XDP_REDIRECT; the output buffer reflects that.
    pub fn run(&self, packet: &[u8]) -> (u32, Vec<u8>) {
        let prog: &Xdp = self
            .bpf
            .program("fast_path")
            .expect("fast_path present")
            .try_into()
            .expect("program is XDP");
        let prog_fd: &ProgramFd = prog.fd().expect("program loaded");
        test_run_xdp(prog_fd.as_fd().as_raw_fd(), packet)
    }

    /// Aggregate a PerCpuArray stat across all CPUs.
    pub fn stat(&self, idx: StatIdx) -> u64 {
        let map = self.bpf.map("STATS").expect("STATS map");
        let stats: PerCpuArray<_, u64> = PerCpuArray::try_from(map).expect("PerCpuArray try_from");
        let per_cpu = stats.get(&(idx as u32), 0).expect("STATS get");
        per_cpu.iter().copied().sum()
    }
}

// --- Raw bpf(BPF_PROG_TEST_RUN) ----------------------------------------

/// `bpf(BPF_PROG_TEST_RUN, ...)` struct layout. Matches the kernel's
/// `union bpf_attr` `test` variant through kernel 6.1. 76 meaningful
/// bytes + 4 bytes of trailing padding to hit 8-byte alignment.
#[repr(C)]
struct TestRunAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
}

const BPF_PROG_TEST_RUN: u32 = 10;

fn test_run_xdp(prog_fd: i32, packet: &[u8]) -> (u32, Vec<u8>) {
    // XDP programs may grow the packet (VLAN push: +4). Allocate
    // output with headroom so the kernel doesn't truncate.
    let mut data_out = vec![0u8; packet.len() + 256];

    // `mem::zeroed` over a struct-literal init: the kernel's CHECK_ATTR
    // macro validates that bytes past `batch_size` (the last field of
    // the TEST_RUN variant) are zero. A `#[derive(Default)]` init only
    // zeros named fields — the 4 bytes of trailing padding we carry to
    // hit 8-byte alignment stay uninitialized and land as garbage in
    // the attr buffer → kernel 6.0+ returns EINVAL with no log. Zeroing
    // the whole buffer first is the fix.
    let mut attr: TestRunAttr = unsafe { std::mem::zeroed() };
    attr.prog_fd = prog_fd as u32;
    attr.data_size_in = packet.len() as u32;
    attr.data_size_out = data_out.len() as u32;
    attr.data_in = packet.as_ptr() as u64;
    attr.data_out = data_out.as_mut_ptr() as u64;
    attr.repeat = 1;

    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_TEST_RUN as libc::c_long,
            &mut attr as *mut _ as *const u8,
            std::mem::size_of::<TestRunAttr>() as u32,
        )
    };

    if ret != 0 {
        let e = std::io::Error::last_os_error();
        panic!("BPF_PROG_TEST_RUN returned {ret} (errno {e})");
    }

    data_out.truncate(attr.data_size_out as usize);
    (attr.retval, data_out)
}

// --- Prefix parsing ---------------------------------------------------

fn parse_v4_prefix(s: &str) -> ([u8; 4], u8) {
    let (addr, len) = s.split_once('/').expect("CIDR");
    let addr: std::net::Ipv4Addr = addr.parse().expect("IPv4");
    (addr.octets(), len.parse().expect("prefix_len"))
}

fn parse_v6_prefix(s: &str) -> ([u8; 16], u8) {
    let (addr, len) = s.split_once('/').expect("CIDR");
    let addr: std::net::Ipv6Addr = addr.parse().expect("IPv6");
    (addr.octets(), len.parse().expect("prefix_len"))
}

// --- Packet builders --------------------------------------------------

/// Minimum Ethernet + IPv4 + TCP packet builder. Pads the TCP payload
/// with zeros if you ask for a specific `payload_len`.
pub struct Ipv4TcpBuilder {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub ttl: u8,
    pub tos: u8,
    pub frag_flags: u16, // network byte order: bit 15=res, 14=DF, 13=MF, 12..0=offset
    pub ihl: u8,         // normally 5; set >5 to produce IHL>5 via header option bytes
    pub payload: Vec<u8>,
}

impl Default for Ipv4TcpBuilder {
    fn default() -> Self {
        Self {
            src_mac: [0xaa, 0, 0, 0, 0, 1],
            dst_mac: [0xbb, 0, 0, 0, 0, 2],
            src_ip: [10, 0, 0, 1],
            dst_ip: [10, 0, 0, 2],
            src_port: 1000,
            dst_port: 2000,
            ttl: 64,
            tos: 0,
            frag_flags: 0,
            ihl: 5,
            payload: Vec::new(),
        }
    }
}

/// Wrap a base Ethernet+IP packet with one 802.1Q tag inserted
/// between the MAC pair and the inner ethertype. `vid` is the 12-bit
/// VLAN ID; PCP/DEI are left zero.
pub fn insert_vlan_tag(base: &[u8], vid: u16) -> Vec<u8> {
    assert!(base.len() >= 14, "base packet must have Ethernet header");
    let mut out = Vec::with_capacity(base.len() + 4);
    out.extend_from_slice(&base[0..12]); // MAC pair
    out.extend_from_slice(&[0x81, 0x00]); // 802.1Q TPID
    out.extend_from_slice(&(vid & 0x0fff).to_be_bytes()); // TCI
    out.extend_from_slice(&base[12..]); // inner ethertype + rest
    out
}

impl Ipv4TcpBuilder {
    pub fn build(&self) -> Vec<u8> {
        let ip_header_len = (self.ihl as usize) * 4;
        let total_len = (ip_header_len + 20 + self.payload.len()) as u16; // +TCP hdr
        let mut pkt = Vec::with_capacity(14 + total_len as usize);

        // Ethernet
        pkt.extend_from_slice(&self.dst_mac);
        pkt.extend_from_slice(&self.src_mac);
        pkt.extend_from_slice(&[0x08, 0x00]); // IPv4

        // IPv4
        let vihl_offset = pkt.len();
        pkt.push(0x40 | self.ihl); // version 4 | IHL
        pkt.push(self.tos);
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&[0, 0]); // id
        pkt.extend_from_slice(&self.frag_flags.to_be_bytes());
        pkt.push(self.ttl);
        pkt.push(6); // TCP
        let check_offset = pkt.len();
        pkt.extend_from_slice(&[0, 0]); // checksum placeholder
        pkt.extend_from_slice(&self.src_ip);
        pkt.extend_from_slice(&self.dst_ip);
        // IHL > 5 → stuff option bytes (zero-filled "nop" x4 per extra word).
        for _ in 5..self.ihl {
            pkt.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]); // four NOP options
        }

        // Compute IPv4 checksum over the header we just wrote.
        let ip_header = &pkt[vihl_offset..vihl_offset + ip_header_len];
        let csum = ipv4_checksum(ip_header);
        pkt[check_offset..check_offset + 2].copy_from_slice(&csum.to_be_bytes());

        // TCP (minimal 20-byte header; flags = SYN; no options)
        pkt.extend_from_slice(&self.src_port.to_be_bytes());
        pkt.extend_from_slice(&self.dst_port.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 1]); // seq
        pkt.extend_from_slice(&[0, 0, 0, 0]); // ack
        pkt.push(0x50); // data offset 5 in upper nibble
        pkt.push(0x02); // SYN
        pkt.extend_from_slice(&[0xff, 0xff]); // window
        pkt.extend_from_slice(&[0, 0, 0, 0]); // checksum (zero - bpf doesn't care for fixtures)

        pkt.extend_from_slice(&self.payload);
        pkt
    }
}

/// Minimum Ethernet + IPv6 + TCP packet builder.
pub struct Ipv6TcpBuilder {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub hop_limit: u8,
    pub next_hdr: u8, // 6 TCP, 17 UDP, 44 Fragment, etc.
    pub payload: Vec<u8>,
}

impl Default for Ipv6TcpBuilder {
    fn default() -> Self {
        Self {
            src_mac: [0xaa, 0, 0, 0, 0, 1],
            dst_mac: [0xbb, 0, 0, 0, 0, 2],
            src_ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst_ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            src_port: 1000,
            dst_port: 2000,
            hop_limit: 64,
            next_hdr: 6, // TCP
            payload: Vec::new(),
        }
    }
}

impl Ipv6TcpBuilder {
    pub fn build(&self) -> Vec<u8> {
        // If next_hdr is TCP/UDP, append a minimal L4 header. For other
        // next_hdrs (Fragment, Hop-by-Hop) tests supply payload manually.
        let l4_len = match self.next_hdr {
            6 | 17 => 20 + self.payload.len(),
            _ => self.payload.len(),
        };
        let payload_len = l4_len as u16;

        let mut pkt = Vec::with_capacity(14 + 40 + l4_len);
        // Ethernet
        pkt.extend_from_slice(&self.dst_mac);
        pkt.extend_from_slice(&self.src_mac);
        pkt.extend_from_slice(&[0x86, 0xdd]); // IPv6
                                              // IPv6 header
        pkt.extend_from_slice(&[0x60, 0, 0, 0]); // version=6, traffic class=0, flow=0
        pkt.extend_from_slice(&payload_len.to_be_bytes());
        pkt.push(self.next_hdr);
        pkt.push(self.hop_limit);
        pkt.extend_from_slice(&self.src_ip);
        pkt.extend_from_slice(&self.dst_ip);

        match self.next_hdr {
            6 => {
                // TCP minimal
                pkt.extend_from_slice(&self.src_port.to_be_bytes());
                pkt.extend_from_slice(&self.dst_port.to_be_bytes());
                pkt.extend_from_slice(&[0, 0, 0, 1]);
                pkt.extend_from_slice(&[0, 0, 0, 0]);
                pkt.push(0x50);
                pkt.push(0x02);
                pkt.extend_from_slice(&[0xff, 0xff]);
                pkt.extend_from_slice(&[0, 0, 0, 0]);
                pkt.extend_from_slice(&self.payload);
            }
            17 => {
                // UDP
                pkt.extend_from_slice(&self.src_port.to_be_bytes());
                pkt.extend_from_slice(&self.dst_port.to_be_bytes());
                let udp_len = (8 + self.payload.len()) as u16;
                pkt.extend_from_slice(&udp_len.to_be_bytes());
                pkt.extend_from_slice(&[0, 0]);
                pkt.extend_from_slice(&self.payload);
            }
            _ => {
                // Extension header or unknown — caller-supplied payload only.
                pkt.extend_from_slice(&self.payload);
            }
        }
        pkt
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    assert_eq!(header.len() % 2, 0, "header must be even-length");
    let mut sum: u32 = 0;
    for chunk in header.chunks_exact(2) {
        // Skip the checksum field (bytes 10-11 of a standard IPv4 header).
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    // Subtract the checksum bytes we included (they were zero in practice
    // here since the builder leaves them as 0 before calling us).
    while sum >> 16 > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
