//! PacketFrame fast-path BPF program (SPEC.md §4.4).
//!
//! Parses Ethernet + IPv4/IPv6, consults the allowlist (src-or-dst match,
//! §4.2), calls `bpf_fib_lookup`, rewrites L2 + TTL, and redirects via
//! `bpf_redirect_map`. Skips any 802.1Q-tagged traffic (`XDP_PASS`) —
//! VLAN push/pop/rewrite (§4.7) lands in PR #5. All counters in
//! [`maps::StatIdx`] are bumped per SPEC.md §4.6. Dry-run mode
//! (cfg.dry_run=1) returns `XDP_PASS` after matched-counter bumps but
//! performs no rewrites.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        bpf_fib_lookup, xdp_action, BPF_FIB_LKUP_RET_BLACKHOLE, BPF_FIB_LKUP_RET_FRAG_NEEDED,
        BPF_FIB_LKUP_RET_NO_NEIGH, BPF_FIB_LKUP_RET_PROHIBIT, BPF_FIB_LKUP_RET_SUCCESS,
        BPF_FIB_LKUP_RET_UNREACHABLE,
    },
    helpers::gen::bpf_fib_lookup as fib_lookup_helper,
    macros::xdp,
    maps::lpm_trie::Key,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EtherType, EthHdr},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
};

mod maps;

use maps::{bump_stat, StatIdx, ALLOW_V4, ALLOW_V6, CFG, REDIRECT_DEVMAP};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

#[xdp]
pub fn fast_path(ctx: XdpContext) -> u32 {
    bump_stat(StatIdx::RxTotal);
    match try_fast_path(&ctx) {
        Ok(action) => action,
        Err(()) => {
            bump_stat(StatIdx::ErrParse);
            xdp_action::XDP_PASS
        }
    }
}

/// Returns Err(()) on bounds-check failure (always counted as
/// `err_parse` → `XDP_PASS`), Ok(action) for everything else.
#[inline(always)]
fn try_fast_path(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *mut EthHdr = ptr_mut_at(ctx, 0)?;
    // `ether_type` is a raw `u16` (packed into the EthHdr struct in
    // network byte order). `EtherType` is an enum that gives named
    // discriminants matching what an LE host reads from the network
    // bytes (Ipv4 = 0x0008, Ipv6 = 0xDD86, Ieee8021q = 0x0081). Cast
    // to u16 for comparison — SPEC.md §3.5 keeps us on stable kernel
    // UAPI only; no CO-RE.
    let ether = unsafe { (*eth).ether_type };

    if ether == EtherType::Ipv4 as u16 {
        handle_ipv4(ctx, eth)
    } else if ether == EtherType::Ipv6 as u16 {
        handle_ipv6(ctx, eth)
    } else if ether == EtherType::Ieee8021q as u16 || ether == EtherType::Ieee8021ad as u16 {
        // Tagged traffic — PR #5 handles VLAN push/pop/rewrite.
        bump_stat(StatIdx::PassNotIp);
        Ok(xdp_action::XDP_PASS)
    } else {
        bump_stat(StatIdx::PassNotIp);
        Ok(xdp_action::XDP_PASS)
    }
}

#[inline(always)]
fn handle_ipv4(ctx: &XdpContext, eth: *mut EthHdr) -> Result<u32, ()> {
    let ip: *mut Ipv4Hdr = ptr_mut_at(ctx, EthHdr::LEN)?;

    // IHL check — packets with IPv4 options (IHL > 5) go to the kernel
    // slow path. SPEC.md §4.4 step 4.
    //
    // `Ipv4Hdr::ihl()` returns the header length in *bytes* (IHL * 4)
    // rather than the raw IHL field — which is a footgun if you're
    // reading SPEC §4.4 and typing `ihl != 5`. A standard IPv4 header
    // with no options is 20 bytes; anything larger means options.
    let ihl_bytes = unsafe { (*ip).ihl() };
    if ihl_bytes != 20 {
        bump_stat(StatIdx::PassComplexHeader);
        return Ok(xdp_action::XDP_PASS);
    }

    // Fragment check. The `frags` field contains flags+offset in the
    // low 13 bits of a network-order u16. network-types exposes a
    // `frag_offset()` helper but we also need the MF flag; read the
    // raw u16 and mask.
    let frags_be = u16::from_be_bytes(unsafe { (*ip).frags });
    // Low 13 bits = offset; bit 13 = MF. Bit 14 = DF (ignored).
    // A non-zero result in those 14 bits means "fragment".
    if (frags_be & 0x3fff) != 0 {
        bump_stat(StatIdx::PassFragment);
        return Ok(xdp_action::XDP_PASS);
    }

    let ttl = unsafe { (*ip).ttl };
    if ttl <= 1 {
        bump_stat(StatIdx::PassLowTtl);
        return Ok(xdp_action::XDP_PASS);
    }

    let src_bytes = unsafe { (*ip).src_addr };
    let dst_bytes = unsafe { (*ip).dst_addr };
    let proto = unsafe { (*ip).proto };

    let src_key = Key::new(32, src_bytes);
    let dst_key = Key::new(32, dst_bytes);
    let src_hit = ALLOW_V4.get(&src_key).is_some();
    let dst_hit = ALLOW_V4.get(&dst_key).is_some();

    if !(src_hit || dst_hit) {
        return Ok(xdp_action::XDP_PASS);
    }

    bump_stat(StatIdx::MatchedV4);
    bump_match_subset(src_hit, dst_hit);

    if is_dry_run() {
        bump_stat(StatIdx::FwdDryRun);
        return Ok(xdp_action::XDP_PASS);
    }

    // L4 ports for the FIB lookup (SPEC.md §4.4 step 7). Required for
    // ECMP routes with L4-hash policy — without sport/dport we'd always
    // hash to the same next-hop and diverge from the kernel slow path.
    let (sport, dport) = l4_ports(ctx, EthHdr::LEN + Ipv4Hdr::LEN, proto);

    // FIB lookup. SPEC.md §4.4 step 8: flags=0 — honors ip-rule policy,
    // uses ingress semantics.
    let mut fib: bpf_fib_lookup = unsafe { mem::zeroed() };
    fib.family = AF_INET;
    fib.l4_protocol = proto as u8;
    fib.sport = sport;
    fib.dport = dport;
    fib.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    fib.__bindgen_anon_1.tot_len = u16::from_be_bytes(unsafe { (*ip).tot_len });
    // `tos` is at offset 1 of the IPv4 header and sits in __bindgen_anon_2
    // of bpf_fib_lookup.
    fib.__bindgen_anon_2.tos = unsafe { (*ip).tos };
    fib.__bindgen_anon_3.ipv4_src = u32::from_ne_bytes(src_bytes);
    fib.__bindgen_anon_4.ipv4_dst = u32::from_ne_bytes(dst_bytes);

    let ret = unsafe {
        fib_lookup_helper(
            ctx.ctx as *mut _,
            &mut fib as *mut _,
            mem::size_of::<bpf_fib_lookup>() as i32,
            0,
        )
    };

    dispatch_fib(ret as u32, ctx, eth, ip as *mut u8, true, &fib)
}

#[inline(always)]
fn handle_ipv6(ctx: &XdpContext, eth: *mut EthHdr) -> Result<u32, ()> {
    let ip: *mut Ipv6Hdr = ptr_mut_at(ctx, EthHdr::LEN)?;

    // Extension-header check (SPEC.md §4.4 step 4): if next_hdr isn't
    // TCP/UDP/ICMPv6, the kernel has to walk the chain — we punt.
    let next = unsafe { (*ip).next_hdr };
    match next {
        IpProto::Tcp | IpProto::Udp | IpProto::Ipv6Icmp => {}
        _ => {
            bump_stat(StatIdx::PassComplexHeader);
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let hop_limit = unsafe { (*ip).hop_limit };
    if hop_limit <= 1 {
        bump_stat(StatIdx::PassLowTtl);
        return Ok(xdp_action::XDP_PASS);
    }

    let src_bytes = unsafe { (*ip).src_addr };
    let dst_bytes = unsafe { (*ip).dst_addr };

    let src_key = Key::new(128, src_bytes);
    let dst_key = Key::new(128, dst_bytes);
    let src_hit = ALLOW_V6.get(&src_key).is_some();
    let dst_hit = ALLOW_V6.get(&dst_key).is_some();

    if !(src_hit || dst_hit) {
        return Ok(xdp_action::XDP_PASS);
    }

    bump_stat(StatIdx::MatchedV6);
    bump_match_subset(src_hit, dst_hit);

    if is_dry_run() {
        bump_stat(StatIdx::FwdDryRun);
        return Ok(xdp_action::XDP_PASS);
    }

    let (sport, dport) = l4_ports(ctx, EthHdr::LEN + Ipv6Hdr::LEN, next);

    let mut fib: bpf_fib_lookup = unsafe { mem::zeroed() };
    fib.family = AF_INET6;
    fib.l4_protocol = next as u8;
    fib.sport = sport;
    fib.dport = dport;
    fib.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    fib.__bindgen_anon_1.tot_len =
        u16::from_be_bytes(unsafe { (*ip).payload_len }) + Ipv6Hdr::LEN as u16;
    // IPv6 flowinfo = vcf field bytes 0-3 (version + tc + flowlabel).
    fib.__bindgen_anon_2.flowinfo = u32::from_be_bytes(unsafe { (*ip).vcf });

    // IPv6 addresses are 4 × u32 in the struct; copy from byte arrays.
    // Safe to access the bindgen unions directly — writing any variant
    // is legal Rust (reads across variants would be the UB we'd avoid).
    fib.__bindgen_anon_3.ipv6_src = bytes_to_u32x4(&src_bytes);
    fib.__bindgen_anon_4.ipv6_dst = bytes_to_u32x4(&dst_bytes);

    let ret = unsafe {
        fib_lookup_helper(
            ctx.ctx as *mut _,
            &mut fib as *mut _,
            mem::size_of::<bpf_fib_lookup>() as i32,
            0,
        )
    };

    dispatch_fib(ret as u32, ctx, eth, ip as *mut u8, false, &fib)
}

/// Common FIB-return dispatch. `is_v4` selects the IPv4 TTL+csum fixup
/// path vs IPv6 hop-limit decrement.
#[inline(always)]
fn dispatch_fib(
    ret: u32,
    _ctx: &XdpContext,
    eth: *mut EthHdr,
    ip: *mut u8,
    is_v4: bool,
    fib: &bpf_fib_lookup,
) -> Result<u32, ()> {
    match ret {
        BPF_FIB_LKUP_RET_SUCCESS => {
            if is_v4 {
                decrement_ipv4_ttl(ip as *mut Ipv4Hdr);
            } else {
                decrement_ipv6_hop_limit(ip as *mut Ipv6Hdr);
            }
            unsafe {
                (*eth).dst_addr = fib.dmac;
                (*eth).src_addr = fib.smac;
            }
            // Defensive devmap pre-check — SPEC.md §4.4 step 9d. Without
            // it, `bpf_redirect_map` with flags=0 silently XDP_ABORTS on
            // miss. We prefer XDP_PASS + counter so the slow path picks
            // up traffic destined to operator-excluded ifindexes.
            if REDIRECT_DEVMAP.get(fib.ifindex).is_none() {
                bump_stat(StatIdx::PassNotInDevmap);
                return Ok(xdp_action::XDP_PASS);
            }
            match REDIRECT_DEVMAP.redirect(fib.ifindex, 0) {
                Ok(_) => {
                    bump_stat(StatIdx::FwdOk);
                    Ok(xdp_action::XDP_REDIRECT)
                }
                Err(_) => {
                    bump_stat(StatIdx::ErrFibOther);
                    Ok(xdp_action::XDP_PASS)
                }
            }
        }
        BPF_FIB_LKUP_RET_NO_NEIGH => {
            bump_stat(StatIdx::PassNoNeigh);
            Ok(xdp_action::XDP_PASS)
        }
        BPF_FIB_LKUP_RET_BLACKHOLE
        | BPF_FIB_LKUP_RET_UNREACHABLE
        | BPF_FIB_LKUP_RET_PROHIBIT => {
            bump_stat(StatIdx::DropUnreachable);
            Ok(xdp_action::XDP_DROP)
        }
        BPF_FIB_LKUP_RET_FRAG_NEEDED => {
            bump_stat(StatIdx::PassFragNeeded);
            Ok(xdp_action::XDP_PASS)
        }
        _ => {
            bump_stat(StatIdx::ErrFibOther);
            Ok(xdp_action::XDP_PASS)
        }
    }
}

/// Decrement IPv4 TTL and patch the header checksum using RFC 1624
/// incremental update. When TTL decreases by 1, the 16-bit word at
/// bytes 8-9 (TTL:proto) decreases by 0x0100 in network byte order.
/// In one's-complement arithmetic that bumps the checksum by +0x0100.
#[inline(always)]
fn decrement_ipv4_ttl(ip: *mut Ipv4Hdr) {
    unsafe {
        (*ip).ttl -= 1;
        let mut sum = u16::from_be_bytes((*ip).check) as u32;
        sum = sum.wrapping_add(0x0100);
        // Fold carry back to 16 bits.
        sum = (sum & 0xffff).wrapping_add(sum >> 16);
        (*ip).check = (sum as u16).to_be_bytes();
    }
}

#[inline(always)]
fn decrement_ipv6_hop_limit(ip: *mut Ipv6Hdr) {
    unsafe {
        (*ip).hop_limit -= 1;
    }
}

#[inline(always)]
fn bump_match_subset(src_hit: bool, dst_hit: bool) {
    match (src_hit, dst_hit) {
        (true, true) => bump_stat(StatIdx::MatchedBoth),
        (true, false) => bump_stat(StatIdx::MatchedSrcOnly),
        (false, true) => bump_stat(StatIdx::MatchedDstOnly),
        (false, false) => {}
    }
}

#[inline(always)]
fn is_dry_run() -> bool {
    CFG.get(0).map(|c| c.dry_run != 0).unwrap_or(false)
}

/// Bounds-checked mutable pointer into the packet at `offset`.
#[inline(always)]
fn ptr_mut_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let size = mem::size_of::<T>();
    if start + offset + size > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

/// Read sport and dport from the L4 header at `offset` in the packet.
/// Returns the raw network-byte-order bytes as `u16`s — matches what
/// the kernel's `bpf_fib_lookup` expects for its `__be16` sport/dport
/// fields. Returns `(0, 0)` for non-port protocols (ICMP, ICMPv6) or
/// when the L4 header would run past the end of data.
///
/// SPEC.md §4.4 step 7: populating these matters for ECMP correctness —
/// routes with L4-hash policy would otherwise collapse to a single
/// next-hop and diverge from the kernel slow path.
#[inline(always)]
fn l4_ports(ctx: &XdpContext, offset: usize, proto: IpProto) -> (u16, u16) {
    if !matches!(proto, IpProto::Tcp | IpProto::Udp) {
        return (0, 0);
    }
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + 4 > end {
        return (0, 0);
    }
    // Read two big-endian u16s as raw packet bytes. The kernel stores
    // `__be16` — on LE hosts (what BPF targets) a direct pointer cast
    // of the raw bytes matches that representation.
    unsafe {
        let p = (start + offset) as *const u8;
        let sport = core::ptr::read_unaligned(p as *const u16);
        let dport = core::ptr::read_unaligned(p.add(2) as *const u16);
        (sport, dport)
    }
}

/// Helper: [u8; 16] → [u32; 4] in network byte order (each 4-byte group
/// as a big-endian u32 matching how the kernel stores `ipv6_src/dst`).
#[inline(always)]
fn bytes_to_u32x4(b: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
        u32::from_ne_bytes([b[4], b[5], b[6], b[7]]),
        u32::from_ne_bytes([b[8], b[9], b[10], b[11]]),
        u32::from_ne_bytes([b[12], b[13], b[14], b[15]]),
    ]
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
