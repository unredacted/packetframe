//! Shared harness for guard BPF tests. Mirror of the fast-path test
//! harness's TEST_RUN machinery (its tests/common/mod.rs); when one is
//! updated, the other likely needs the same change.
//!
//! `BPF_PROG_TEST_RUN` for sched_cls builds a real skb from the bytes
//! (data at the MAC header) against the netns loopback device, so
//! `skb->ifindex == 1` and 5.15's `convert___skb_to_skb` allowlist
//! offers no way to fake it — tests key `GUARD_CFG` at
//! [`LO_IFINDEX`]. It also never lifts an inline 802.1Q tag into skb
//! metadata (which is why the program keeps its inline fallback
//! parse), and `data_size_in < ETH_HLEN` fails the whole syscall with
//! EINVAL, so every crafted frame is ≥ 14 bytes.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

use std::os::fd::{AsFd as _, AsRawFd as _};

use aya::maps::{HashMap as AyaHashMap, PerCpuArray};
use aya::programs::tc::SchedClassifier;
use aya::programs::ProgramFd;

use packetframe_guard::cfg::GuardIfCfg;
use packetframe_guard::metrics::{COUNTER_COUNT, COUNTER_NAMES, STATS_BLOCK_LEN};

/// TEST_RUN skbs resolve against the netns loopback.
pub const LO_IFINDEX: u32 = 1;

/// tc verdicts as the u32 `retval` TEST_RUN reports.
pub const TC_ACT_OK: u32 = 0;
pub const TC_ACT_SHOT: u32 = 2;

/// Counter indices, mirroring the BPF `GuardStatIdx` via
/// `metrics::COUNTER_NAMES` order (the single userspace mirror).
pub mod idx {
    pub const TOTAL_EGRESS: usize = 0;
    pub const PASS_NO_CFG: usize = 1;
    pub const PASS_NO_MATCH: usize = 2;
    pub const ERR_PARSE_L2: usize = 3;
    pub const ERR_PARSE_VLAN: usize = 4;
    pub const ERR_PARSE_ARP: usize = 5;
    pub const ERR_PARSE_NS: usize = 6;
    pub const FOREIGN_DROP: usize = 7;
    pub const LLDP_DROP: usize = 8;
    pub const LLDP_MONITOR: usize = 9;
    pub const ARP_PASS: usize = 10;
    pub const ARP_DROP: usize = 11;
    pub const ARP_MONITOR: usize = 12;
    pub const NS_PASS: usize = 13;
    pub const NS_DROP: usize = 14;
    pub const NS_MONITOR: usize = 15;
    pub const MCAST_PASS: usize = 16;
    pub const MCAST_DROP: usize = 17;
    pub const MCAST_MONITOR: usize = 18;
    pub const FOREIGN_MONITOR: usize = 19;
}

/// The interface MAC every test frame treats as "our own".
pub const OWN_MAC: [u8; 6] = [0x28, 0x70, 0x4e, 0x47, 0x69, 0xc7];
/// A src MAC that is not [`OWN_MAC`].
pub const FOREIGN_MAC: [u8; 6] = [0x58, 0xd6, 0x1f, 0x4f, 0xcd, 0x56];

pub struct Harness {
    pub bpf: aya::Ebpf,
}

impl Harness {
    /// Load the embedded ELF and verifier-load `guard_egress`. Panics
    /// on a stub ELF — callers skip-gate on `GUARD_BPF_AVAILABLE`
    /// first (in CI `PACKETFRAME_BPF_REQUIRED=1` makes a stub
    /// impossible). Each harness owns fresh maps, so tests in one
    /// binary don't share bucket or counter state.
    pub fn new() -> Self {
        let bytes = packetframe_guard::aligned_bpf_copy();
        let mut bpf = aya::Ebpf::load(&bytes).expect("Ebpf::load (BPF ELF built?)");
        {
            let prog: &mut SchedClassifier = bpf
                .program_mut("guard_egress")
                .expect("guard_egress present in ELF")
                .try_into()
                .expect("guard_egress is sched_cls");
            prog.load().expect("verifier accepts guard_egress");
        }
        Harness { bpf }
    }

    pub fn set_guard_cfg(&mut self, ifindex: u32, cfg: GuardIfCfg) {
        let map = self.bpf.map_mut("GUARD_CFG").expect("GUARD_CFG map");
        let mut hm: AyaHashMap<_, u32, GuardIfCfg> =
            AyaHashMap::try_from(map).expect("GUARD_CFG try_from");
        hm.insert(ifindex, cfg, 0).expect("GUARD_CFG insert");
    }

    /// Run `guard_egress` against `packet`; returns (verdict, out).
    pub fn run(&self, packet: &[u8]) -> (u32, Vec<u8>) {
        let prog: &SchedClassifier = self
            .bpf
            .program("guard_egress")
            .expect("guard_egress present")
            .try_into()
            .expect("program is sched_cls");
        let prog_fd: &ProgramFd = prog.fd().expect("program loaded");
        test_run(prog_fd.as_fd().as_raw_fd(), packet)
    }

    /// Aggregate one counter across CPUs.
    pub fn stat(&self, idx: usize) -> u64 {
        self.snapshot()[idx]
    }

    /// All named counters, summed across CPUs.
    pub fn snapshot(&self) -> Vec<u64> {
        let map = self.bpf.map("GUARD_STATS").expect("GUARD_STATS map");
        let stats: PerCpuArray<_, [u64; STATS_BLOCK_LEN]> =
            PerCpuArray::try_from(map).expect("GUARD_STATS try_from");
        let per_cpu = stats.get(&0, 0).expect("GUARD_STATS get");
        let mut out = vec![0u64; COUNTER_COUNT];
        for block in per_cpu.iter() {
            for (slot, v) in out.iter_mut().zip(block.iter()) {
                *slot += *v;
            }
        }
        out
    }

    /// Which named counters moved between two snapshots — the
    /// fast-path breakdown-assertion idiom.
    pub fn moved(before: &[u64], after: &[u64]) -> Vec<&'static str> {
        COUNTER_NAMES
            .iter()
            .enumerate()
            .filter(|(i, _)| after[*i] != before[*i])
            .map(|(_, n)| *n)
            .collect()
    }
}

// --- Raw bpf(BPF_PROG_TEST_RUN) ----------------------------------------
// Mirror of the fast-path harness's wrapper; see its comments for the
// mem::zeroed (kernel 6.0+ CHECK_ATTR trailing-padding EINVAL) and
// output-headroom rationale.

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

fn test_run(prog_fd: i32, packet: &[u8]) -> (u32, Vec<u8>) {
    let mut data_out = vec![0u8; packet.len() + 256];
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

// --- Frame builders -----------------------------------------------------

/// Ethernet/IPv4 ARP request for `target`, broadcast dst, padded to
/// the 60-byte on-wire minimum (matching what arping emits).
pub fn arp_request(src_mac: [u8; 6], target: [u8; 4]) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&src_mac);
    f[12..14].copy_from_slice(&[0x08, 0x06]);
    f[14..16].copy_from_slice(&[0x00, 0x01]); // htype: ethernet
    f[16..18].copy_from_slice(&[0x08, 0x00]); // ptype: IPv4
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&[0x00, 0x01]); // oper: request
    f[22..28].copy_from_slice(&src_mac); // sha
    f[28..32].copy_from_slice(&[192, 0, 2, 1]); // spa
                                                // tha stays zero
    f[38..42].copy_from_slice(&target); // tpa
    f
}

/// Same frame with `oper` = reply (falls through to the catch-all).
pub fn arp_reply(src_mac: [u8; 6], target: [u8; 4]) -> Vec<u8> {
    let mut f = arp_request(src_mac, target);
    f[21] = 0x02;
    f
}

/// ICMPv6 Neighbor Solicitation for `target` to the solicited-node
/// multicast group. Checksum left zero — the classifier never
/// validates it.
pub fn ns_frame(src_mac: [u8; 6], target: [u8; 16]) -> Vec<u8> {
    let mut f = vec![0u8; 14 + 40 + 24];
    f[0..6].copy_from_slice(&[0x33, 0x33, 0xff, target[13], target[14], target[15]]);
    f[6..12].copy_from_slice(&src_mac);
    f[12..14].copy_from_slice(&[0x86, 0xdd]);
    f[14] = 0x60; // version 6
    f[18..20].copy_from_slice(&24u16.to_be_bytes()); // payload len
    f[20] = 58; // next header: ICMPv6
    f[21] = 255; // hop limit
                 // src :: (zeros); dst ff02::1:ff<target[13..16]>
    f[38] = 0xff;
    f[39] = 0x02;
    f[49] = 0x01;
    f[50] = 0xff;
    f[51..54].copy_from_slice(&target[13..16]);
    f[54] = 135; // ICMPv6 type: NS
                 // code, cksum, reserved stay zero
    f[62..78].copy_from_slice(&target); // NS target
    f
}

/// LLDP frame (ethertype 0x88cc) to the nearest-bridge group.
pub fn lldp_frame(src_mac: [u8; 6]) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&[0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e]);
    f[6..12].copy_from_slice(&src_mac);
    f[12..14].copy_from_slice(&[0x88, 0xcc]);
    f
}

/// Plain unicast IPv4 frame — the fast-exit case.
pub fn unicast_ipv4(src_mac: [u8; 6], dst_mac: [u8; 6]) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&dst_mac);
    f[6..12].copy_from_slice(&src_mac);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    f[14] = 0x45; // minimal plausible IPv4 header start
    f
}

/// Broadcast frame with a non-special ethertype (catch-all fodder).
pub fn broadcast_misc(src_mac: [u8; 6]) -> Vec<u8> {
    let mut f = vec![0u8; 60];
    f[0..6].copy_from_slice(&[0xff; 6]);
    f[6..12].copy_from_slice(&src_mac);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    f
}

/// Insert an 802.1Q tag (TPID 0x8100) after the MAC addresses.
/// TEST_RUN never lifts it into skb metadata, so this exercises the
/// inline fallback parse.
pub fn insert_vlan_tag(base: &[u8], vid: u16) -> Vec<u8> {
    let mut f = Vec::with_capacity(base.len() + 4);
    f.extend_from_slice(&base[0..12]);
    f.extend_from_slice(&[0x81, 0x00]);
    f.extend_from_slice(&(vid & 0x0fff).to_be_bytes());
    f.extend_from_slice(&base[12..]);
    f
}
