//! Context-free datapath helpers shared between hook types (Phase T).
//!
//! Everything here is parameterized on `(start, end)` packet-bounds
//! scalars (from `XdpContext::data()/data_end()` today; from a TC
//! classifier's `__sk_buff` data pointers in the tc datapath) instead
//! of a concrete ctx type. Deliberately **no Ctx trait / no generics**:
//! monomorphized abstraction would likely verify, but this codebase's
//! verifier history (SPEC "Inline mandate", the `Option<u16>` spill,
//! the memset-libcall exclusions) argues for the dumbest possible
//! sharing — scalars in, scalars out, everything `#[inline(always)]`.
//!
//! Rules for anything added here:
//! - `#[inline(always)]` on every fn: bpf-to-bpf calls are mutually
//!   exclusive with tail calls on the production kernel.
//! - No map access unless the map is hook-agnostic (STATS via
//!   [`StatsPtr`] is fine — both hook types share the pinned maps).
//! - No XDP- or TC-only helper calls (`bpf_xdp_adjust_head`,
//!   `bpf_skb_vlan_push`, ...); those stay in the per-hook modules.

use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};

use crate::maps::{bump, StatIdx, StatsPtr};

const PROTO_TCP: u8 = IpProto::Tcp as u8;
const PROTO_UDP: u8 = IpProto::Udp as u8;

/// SYN flag in TCP header byte 13.
pub const TCP_FLAG_SYN: u8 = 0x02;

// --- L3 header mutation -------------------------------------------------

/// Decrement IPv4 TTL and patch the header checksum using RFC 1624
/// incremental update: when TTL decreases by 1, the word at bytes 8-9
/// (TTL:proto, network order) decreases by 0x0100 → the checksum
/// increases by 0x0100 in one's-complement arithmetic.
#[inline(always)]
pub fn decrement_ipv4_ttl(ip: *mut Ipv4Hdr) {
    unsafe {
        (*ip).ttl -= 1;
        let mut sum = u16::from_be_bytes((*ip).check) as u32;
        sum = sum.wrapping_add(0x0100);
        sum = (sum & 0xffff).wrapping_add(sum >> 16);
        (*ip).check = (sum as u16).to_be_bytes();
    }
}

#[inline(always)]
pub fn decrement_ipv6_hop_limit(ip: *mut Ipv6Hdr) {
    unsafe {
        (*ip).hop_limit -= 1;
    }
}

// --- Bounds-checked packet readers ---------------------------------------

/// Read sport/dport from the L4 header at `offset`. Returns raw BE
/// network-order u16 bytes (via `read_unaligned`) matching what the
/// kernel's `bpf_fib_lookup` expects for its `__be16` sport/dport
/// fields on an LE host. (0, 0) for ICMP / ICMPv6 or truncated L4.
#[inline(always)]
pub fn l4_ports(start: usize, end: usize, offset: usize, proto: u8) -> (u16, u16) {
    if !matches!(proto, PROTO_TCP | PROTO_UDP) {
        return (0, 0);
    }
    if start + offset + 4 > end {
        return (0, 0);
    }
    unsafe {
        let p = (start + offset) as *const u8;
        let sport = core::ptr::read_unaligned(p as *const u16);
        let dport = core::ptr::read_unaligned(p.add(2) as *const u16);
        (sport, dport)
    }
}

/// Read the ICMPv6 `type` field, the first octet of the ICMPv6 header.
///
/// `None` when the read would run past `end`; callers treat that as
/// "not an NDP message" and fall through to the normal path, which is
/// fail-safe (a truncated ICMPv6 header can't be a valid NS/NA anyway).
/// Bounds-check shape mirrors [`l4_ports`].
#[inline(always)]
pub fn icmpv6_type(start: usize, end: usize, offset: usize) -> Option<u8> {
    // Bounds-check 4 bytes even though only 1 is read, and the 4 is
    // load-bearing — do not "fix" it back to 1. Verifier history
    // (v0.2.8 FIB-cache PR, two failed qemu-5.15 rounds): with k = 1,
    // LLVM strength-reduces `p + 1 > end` (and the equivalent
    // `p >= end`) into the reversed strict compare
    // `if pkt_end > pkt+off goto read`, and the 5.15 verifier's range
    // propagation for exactly that arm is off by one — the taken
    // branch keeps r = off where off+1 is provable, and the 1-byte
    // read at `off` is rejected ("R2 offset is outside of the
    // packet"). `p + 4 > end` cannot collapse into a >= form, so LLVM
    // emits the pkt-on-the-left shape (`if pkt+off+4 > pkt_end goto
    // bail`) whose fall-through range every kernel tracks correctly.
    // Semantically free: 4 bytes (type, code, checksum) is the ICMPv6
    // header minimum, and a message truncated below that cannot be a
    // valid NS/NA — "not NDP" is already the fail-safe answer.
    if start + offset + 4 > end {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned((start + offset) as *const u8) })
}

/// Read TCP header byte 13 (flags) at `tcp_offset` and test SYN.
/// Out-of-bounds → `false` (a truncated TCP header can't be a
/// clampable SYN). Bounds check uses the accepted
/// `start + off + k > end` pattern; callers guarantee `tcp_offset`
/// is `ip_offset + <const HDR>` with `ip_offset` already clamped.
#[inline(always)]
pub fn tcp_syn_flag_set(start: usize, end: usize, tcp_offset: usize) -> bool {
    if start + tcp_offset + 14 > end {
        return false;
    }
    let flags = unsafe { *((start + tcp_offset + 13) as *const u8) };
    flags & TCP_FLAG_SYN != 0
}

/// Assemble a `[u8; 16]` IPv6 address into the `[u32; 4]` shape
/// `bpf_fib_lookup` wants (native-endian word loads of network-order
/// bytes). Usable from any hook type that calls the FIB helper.
#[inline(always)]
pub fn bytes_to_u32x4(b: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        u32::from_ne_bytes([b[8], b[9], b[10], b[11]]),
        u32::from_ne_bytes([b[12], b[13], b[14], b[15]]),
    ]
}

// --- MSS clamp (option walk + checksum patch) -----------------------------

/// Walk the TCP-options block of a matched SYN/SYN-ACK and mutate the MSS
/// option in place if the existing MSS is greater than the clamp value.
/// Recomputes the TCP checksum incrementally (RFC 1624). Bumps
/// `MssClampApplied` on rewrite, `MssClampSkipped` on "policy applies but
/// no rewrite needed."
///
/// Takes a typed `ip_ptr` (already bounds-checked for `ip_hdr_size` bytes)
/// rather than a raw `tcp_offset` scalar. Inside, we recover ip_offset as
/// `(ip_ptr as usize) - start`, which the BPF verifier tracks as a `pkt -
/// pkt` subtraction with `umax = MAX_PACKET_OFF (0xffff)`. That tight bound
/// is what makes subsequent `start + tcp_offset + N > end` checks
/// propagate readable-range to the read site (mirrors v0.2.4's working
/// pattern; passing `tcp_offset` directly as a `usize` from a map read
/// loses verifier tracking and the post-bound-check pkt pointer ends up
/// with `r=0`). `start`/`end` must be the same bounds `ip_ptr` was
/// validated against.
///
/// Bounds-checked at every read against `end`. Options walk is
/// fixed-bound at 8 iterations to keep BPF verifier state-space
/// exploration tractable (a 40-iteration walk hit the verifier's
/// 1M-instruction limit during v0.2.4 development).
#[inline(always)]
pub fn mss_clamp_tcp(
    stats: StatsPtr,
    start: usize,
    end: usize,
    ip_ptr: *const u8,
    ip_hdr_size: usize,
    clamp: u16,
) {
    // pkt-derived scalar; verifier tracks umax tightly.
    let ip_offset = (ip_ptr as usize) - start;
    let tcp_offset = ip_offset + ip_hdr_size;

    // Need 20 bytes for the fixed TCP header before walking options.
    if start + tcp_offset + 20 > end {
        return;
    }

    // Bytes 12-13 of TCP header: data_offset:4 | reserved:4 | flags:8.
    let doff_byte = unsafe { *((start + tcp_offset + 12) as *const u8) };
    let flags = unsafe { *((start + tcp_offset + 13) as *const u8) };
    if flags & TCP_FLAG_SYN == 0 {
        return; // Not SYN/SYN-ACK.
    }
    let doff_words = (doff_byte >> 4) as usize;
    if !(5..=15).contains(&doff_words) {
        return;
    }
    let tcp_hdr_len = doff_words * 4;
    let opts_len = tcp_hdr_len - 20;
    if opts_len == 0 {
        bump(stats, StatIdx::MssClampSkipped);
        return;
    }
    if start + tcp_offset + tcp_hdr_len > end {
        return;
    }

    // Walk options. Cap at 8, real SYN packets put MSS in the first
    // 1-4 options (Linux's tcp_options_write emits MSS very early); 8
    // is comfortable headroom while keeping verifier state-space bounded.
    let opts_start_off = tcp_offset + 20;
    let mut cursor: usize = 0;
    let mut found = false;

    for _ in 0..8 {
        if cursor >= opts_len {
            break;
        }
        let p_addr = start + opts_start_off + cursor;
        if p_addr + 4 > end {
            break;
        }
        let p = p_addr as *const u8;
        let kind = unsafe { *p };
        if kind == 0 {
            break; // EOL.
        }
        if kind == 1 {
            cursor += 1; // NOP.
            continue;
        }
        let length = unsafe { *p.add(1) } as usize;
        if length < 2 || cursor + length > opts_len {
            break; // Malformed.
        }
        if kind == 2 && length == 4 {
            // MSS option: [kind=2, length=4, mss_be:2].
            let mss_be = unsafe { [*p.add(2), *p.add(3)] };
            let mss = u16::from_be_bytes(mss_be);
            if mss > clamp {
                let new_mss_be = clamp.to_be_bytes();
                unsafe {
                    let pmut = p as *mut u8;
                    *pmut.add(2) = new_mss_be[0];
                    *pmut.add(3) = new_mss_be[1];
                }
                // RFC 1624 incremental TCP checksum update.
                let csum_off = tcp_offset + 16;
                if start + csum_off + 2 > end {
                    return;
                }
                let csum_p = (start + csum_off) as *mut u8;
                let old_csum_be = unsafe { [*csum_p, *csum_p.add(1)] };
                let old_csum = u16::from_be_bytes(old_csum_be);
                let new_csum = csum_replace_u16(old_csum, mss, clamp);
                let new_csum_be = new_csum.to_be_bytes();
                unsafe {
                    *csum_p = new_csum_be[0];
                    *csum_p.add(1) = new_csum_be[1];
                }
                bump(stats, StatIdx::MssClampApplied);
            } else {
                bump(stats, StatIdx::MssClampSkipped);
            }
            found = true;
            break;
        }
        cursor += length;
    }

    if !found {
        bump(stats, StatIdx::MssClampSkipped);
    }
}

#[inline(always)]
pub fn csum_replace_u16(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum: u32 = (!old_csum) as u32 + (!old_val) as u32 + new_val as u32;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

// --- Counter bookkeeping ---------------------------------------------------

/// Which side(s) of the allowlist matched. Hook-agnostic: both the XDP
/// and tc datapaths bump the same shared counters.
#[inline(always)]
pub fn bump_match_subset(stats: StatsPtr, src_hit: bool, dst_hit: bool) {
    match (src_hit, dst_hit) {
        (true, true) => bump(stats, StatIdx::MatchedBoth),
        (true, false) => bump(stats, StatIdx::MatchedSrcOnly),
        (false, true) => bump(stats, StatIdx::MatchedDstOnly),
        (false, false) => {}
    }
}
