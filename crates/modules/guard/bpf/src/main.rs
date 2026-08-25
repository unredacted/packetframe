//! PacketFrame guard: tc-**egress** frame policer (`guard_egress`).
//!
//! Polices locally-originated L2 frames the platform's firmware emits
//! uncontrollably. Fixed classes, per-interface config (`GUARD_CFG`),
//! each class disabled / monitor / enforce:
//!
//! 1. foreign source MAC (≠ the interface's own) → drop;
//! 2. LLDP (ethertype 0x88cc) → drop;
//! 3. ARP requests → per-target-IP GCRA rate limit;
//! 4. ICMPv6 Neighbor Solicitations → same buckets, v6 targets;
//! 5. any other broadcast/multicast dst → coarse per-interface GCRA.
//!
//! Classification order is cheapest-reject-first, and the load-bearing
//! property is the **unicast fast exit**: a well-formed unicast frame
//! with the interface's own src MAC and a non-special ethertype exits
//! at `PassNoMatch` after ~35-40 instructions and exactly two helper
//! calls (the stats block and the per-ifindex config lookup, both
//! irreducible). IX-facing interfaces carry real peering traffic;
//! everything expensive happens only on broadcast/multicast frames.
//!
//! Fail open everywhere: no config entry, unrecognized config version,
//! or a truncated header ⇒ `TC_ACT_OK`. The frame sources are local
//! firmware daemons, not runt-crafting adversaries, and a policer must
//! never blackhole the control plane on a parse corner.
//!
//! Verifier discipline follows the fast-path BPF crate (its
//! `datapath.rs` header is the rulebook): everything
//! `#[inline(always)]`, scalars in/out, canonical
//! `start + off + K > end` bounds checks, `read_unaligned` for
//! multi-byte loads, no memset/memcpy bait. Single program, no tail
//! call: whole-program state is a handful of scalars (stack well under
//! 64 bytes against the 512-byte budget, even with the vendor
//! verifier's ~120-byte-higher accounting).

#![no_std]
#![no_main]

mod maps;

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    helpers::bpf_ktime_get_ns,
    macros::classifier,
    programs::TcContext,
};
use network_types::eth::{EthHdr, EtherType};

use crate::maps::{
    bucket_slot, bump, gcra_conforms, stats_base, GuardStatIdx, StatsPtr, ACTION_DISABLED,
    ACTION_ENFORCE, ARP_SALT, GUARD_CFG, GUARD_CFG_VERSION, GUARD_MCAST_BUCKETS,
    GUARD_MCAST_BUCKETS_ENTRIES, GUARD_NDP_BUCKETS, GUARD_NDP_BUCKETS_ENTRIES, MCAST_SALT,
    NS_SALT,
};

/// LLDP ethertype in wire byte order. network-types has no LLDP
/// variant; keep the fast-path convention of `.to_be()` consts
/// compared against the raw `ether_type` field.
const ETH_P_LLDP_BE: u16 = 0x88CC_u16.to_be();
/// ARP `ptype` for IPv4, wire order.
const ARP_PTYPE_IPV4_BE: u16 = 0x0800_u16.to_be();
/// ARP `oper` request, wire order.
const ARP_OPER_REQUEST_BE: u16 = 1_u16.to_be();
const VLAN_HDR_LEN: usize = 4;
/// Fixed IPv6 header length; v1 does not walk extension headers (an
/// NS behind one falls through to the catch-all bucket, still
/// bounded).
const IPV6_HDR_LEN: usize = 40;
const PROTO_ICMPV6: u8 = 58;
const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;

#[classifier]
pub fn guard_egress(ctx: TcContext) -> i32 {
    let stats = match stats_base() {
        Some(s) => s,
        None => return TC_ACT_OK as i32,
    };
    bump(stats, GuardStatIdx::TotalEgress);
    match classify(&ctx, stats) {
        Ok(verdict) => verdict,
        // Parse failures bumped their specific counter at the site;
        // fail open.
        Err(()) => TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn classify(ctx: &TcContext, stats: StatsPtr) -> Result<i32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + EthHdr::LEN > end {
        bump(stats, GuardStatIdx::ErrParseL2);
        return Err(());
    }
    let eth = start as *const EthHdr;
    let outer_ether = unsafe { (*eth).ether_type };

    let skb = ctx.skb.skb;
    let ifindex = unsafe { (*skb).ifindex };
    // Held for the whole run; RCU keeps the element alive and
    // internally consistent across a concurrent userspace replace.
    let cfg = match unsafe { GUARD_CFG.get(&ifindex) } {
        Some(c) => c,
        None => {
            bump(stats, GuardStatIdx::PassNoCfg);
            return Ok(TC_ACT_OK as i32);
        }
    };
    if cfg.version != GUARD_CFG_VERSION {
        // Userspace/ELF layout skew: refuse to interpret the bytes,
        // fail open, and let the counter anomaly surface it.
        bump(stats, GuardStatIdx::PassNoCfg);
        return Ok(TC_ACT_OK as i32);
    }

    // VLAN egress: metadata-first, inline single-tag fallback. Mirrors
    // the fast-path tc ingress parse (its tc.rs): the tag usually
    // lives in skb metadata by the time a clsact hook runs, but
    // BPF_PROG_TEST_RUN never lifts an in-band tag, and exotic paths
    // can leave it inline. QinQ outer types fall through as "no VLAN"
    // and land in the catch-all via the I/G bit.
    let meta_present = unsafe { (*skb).vlan_present } != 0;
    let (ether, l2_off) = if meta_present {
        (outer_ether, EthHdr::LEN)
    } else if outer_ether == EtherType::Ieee8021q as u16
        || outer_ether == EtherType::Ieee8021ad as u16
    {
        if start + EthHdr::LEN + VLAN_HDR_LEN > end {
            bump(stats, GuardStatIdx::ErrParseVlan);
            return Err(());
        }
        let inner =
            unsafe { core::ptr::read_unaligned((start + EthHdr::LEN + 2) as *const u16) };
        (inner, EthHdr::LEN + VLAN_HDR_LEN)
    } else {
        (outer_ether, EthHdr::LEN)
    };

    // --- foreign-src: dominant violation first. A foreign-MAC
    // anything is what trips IX port security. src MAC sits at fixed
    // frame offset 6 regardless of VLAN, covered by the EthHdr bounds
    // check above.
    if cfg.act_foreign != ACTION_DISABLED {
        let src_hi = unsafe { core::ptr::read_unaligned((start + 6) as *const u32) };
        let src_lo = unsafe { core::ptr::read_unaligned((start + 10) as *const u16) };
        if src_hi != cfg.mac_hi || src_lo != cfg.mac_lo {
            if cfg.act_foreign == ACTION_ENFORCE {
                bump(stats, GuardStatIdx::ForeignDrop);
                return Ok(TC_ACT_SHOT as i32);
            }
            // Monitor: count and CONTINUE — a foreign-MAC ARP storm
            // must still hit the ARP limiter (the one deliberate
            // non-terminal counter; see GuardStatIdx).
            bump(stats, GuardStatIdx::ForeignMonitor);
        }
    }

    // --- LLDP. With the class disabled, LLDP still lands in the
    // catch-all below (its dst MAC has the I/G bit set).
    if ether == ETH_P_LLDP_BE && cfg.act_lldp != ACTION_DISABLED {
        if cfg.act_lldp == ACTION_ENFORCE {
            bump(stats, GuardStatIdx::LldpDrop);
            return Ok(TC_ACT_SHOT as i32);
        }
        bump(stats, GuardStatIdx::LldpMonitor);
        return Ok(TC_ACT_OK as i32);
    }

    // --- ARP request → per-target GCRA.
    if ether == EtherType::Arp as u16 && cfg.act_arp != ACTION_DISABLED && cfg.ndp_t_ns != 0 {
        // One bounds check covers the whole fixed Ethernet/IPv4 ARP
        // header (28 bytes: htype 0, ptype 2, hlen 4, plen 5, oper 6,
        // sha 8, spa 14, tha 18, tpa 24).
        if start + l2_off + 28 > end {
            bump(stats, GuardStatIdx::ErrParseArp);
            return Err(());
        }
        let ptype = unsafe { core::ptr::read_unaligned((start + l2_off + 2) as *const u16) };
        let plen = unsafe { *((start + l2_off + 5) as *const u8) };
        let oper = unsafe { core::ptr::read_unaligned((start + l2_off + 6) as *const u16) };
        if ptype == ARP_PTYPE_IPV4_BE && plen == 4 && oper == ARP_OPER_REQUEST_BE {
            let tpa = unsafe { core::ptr::read_unaligned((start + l2_off + 24) as *const u32) };
            let word = ifindex ^ ARP_SALT ^ tpa;
            return Ok(ndp_bucket_verdict(stats, cfg.act_arp, cfg, word, true));
        }
        // Replies / GARP / non-IPv4 ARP fall through: the catch-all
        // below is what polices those (broadcast dst).
    }

    // --- ICMPv6 Neighbor Solicitation → same GCRA parameters, v6
    // target domain.
    if ether == EtherType::Ipv6 as u16 && cfg.act_ns != ACTION_DISABLED && cfg.ndp_t_ns != 0 {
        // Fixed header only in v1; a too-short "IPv6" frame is not
        // classifiable as NS and falls through (fail open into the
        // later classes).
        if start + l2_off + IPV6_HDR_LEN <= end {
            let next_hdr = unsafe { *((start + l2_off + 6) as *const u8) };
            if next_hdr == PROTO_ICMPV6
                && icmpv6_type(start, end, l2_off + IPV6_HDR_LEN)
                    == Some(ICMPV6_NEIGHBOR_SOLICITATION)
            {
                // NS target = ICMPv6 bytes 8..24. XOR-fold the full
                // 16 bytes; no stored key means truncated-key aliasing
                // is benign-stricter by construction.
                let icmp = l2_off + IPV6_HDR_LEN;
                if start + icmp + 24 > end {
                    bump(stats, GuardStatIdx::ErrParseNs);
                    return Err(());
                }
                let w0 =
                    unsafe { core::ptr::read_unaligned((start + icmp + 8) as *const u32) };
                let w1 =
                    unsafe { core::ptr::read_unaligned((start + icmp + 12) as *const u32) };
                let w2 =
                    unsafe { core::ptr::read_unaligned((start + icmp + 16) as *const u32) };
                let w3 =
                    unsafe { core::ptr::read_unaligned((start + icmp + 20) as *const u32) };
                let word = ifindex ^ NS_SALT ^ w0 ^ w1 ^ w2 ^ w3;
                return Ok(ndp_bucket_verdict(stats, cfg.act_ns, cfg, word, false));
            }
        }
    }

    // --- catch-all: any remaining frame with the dst-MAC I/G bit set
    // (broadcast included; also LLC/BPDUs, MLD, GARP, ARP replies).
    let dst0 = unsafe { *(start as *const u8) };
    if dst0 & 0x01 != 0 && cfg.act_mcast != ACTION_DISABLED && cfg.mcast_t_ns != 0 {
        let word = ifindex ^ MCAST_SALT;
        let slot_idx = bucket_slot(word, GUARD_MCAST_BUCKETS_ENTRIES);
        let Some(slot) = GUARD_MCAST_BUCKETS.get_ptr_mut(slot_idx) else {
            // Unreachable (masked index into a fixed array); fail open.
            bump(stats, GuardStatIdx::PassNoMatch);
            return Ok(TC_ACT_OK as i32);
        };
        let now = unsafe { bpf_ktime_get_ns() };
        if gcra_conforms(slot, now, cfg.mcast_t_ns, cfg.mcast_tau_ns) {
            bump(stats, GuardStatIdx::McastPass);
            return Ok(TC_ACT_OK as i32);
        }
        if cfg.act_mcast == ACTION_ENFORCE {
            bump(stats, GuardStatIdx::McastDrop);
            return Ok(TC_ACT_SHOT as i32);
        }
        bump(stats, GuardStatIdx::McastMonitor);
        return Ok(TC_ACT_OK as i32);
    }

    // The unicast fast exit.
    bump(stats, GuardStatIdx::PassNoMatch);
    Ok(TC_ACT_OK as i32)
}

/// Shared ARP/NS bucket verdict: look up the per-target slot, run
/// GCRA with the ndp parameters, map the outcome to the class's
/// counters. `is_arp` selects the counter triplet only — both classes
/// deliberately share the bucket array and rate parameters.
#[inline(always)]
fn ndp_bucket_verdict(
    stats: StatsPtr,
    action: u8,
    cfg: &maps::GuardIfCfg,
    word: u32,
    is_arp: bool,
) -> i32 {
    let slot_idx = bucket_slot(word, GUARD_NDP_BUCKETS_ENTRIES);
    let Some(slot) = GUARD_NDP_BUCKETS.get_ptr_mut(slot_idx) else {
        // Unreachable (masked index into a fixed array); fail open.
        bump(stats, GuardStatIdx::PassNoMatch);
        return TC_ACT_OK as i32;
    };
    let now = unsafe { bpf_ktime_get_ns() };
    if gcra_conforms(slot, now, cfg.ndp_t_ns, cfg.ndp_tau_ns) {
        bump(
            stats,
            if is_arp {
                GuardStatIdx::ArpPass
            } else {
                GuardStatIdx::NsPass
            },
        );
        return TC_ACT_OK as i32;
    }
    if action == ACTION_ENFORCE {
        bump(
            stats,
            if is_arp {
                GuardStatIdx::ArpDrop
            } else {
                GuardStatIdx::NsDrop
            },
        );
        return TC_ACT_SHOT as i32;
    }
    bump(
        stats,
        if is_arp {
            GuardStatIdx::ArpMonitor
        } else {
            GuardStatIdx::NsMonitor
        },
    );
    TC_ACT_OK as i32
}

/// Read the ICMPv6 type byte at `offset`. **Verbatim copy of
/// fast-path `datapath.rs::icmpv6_type`, including its load-bearing
/// bounds width — when one is updated, the other likely needs the
/// same change.**
///
/// Bounds-check 4 bytes even though only 1 is read, and the 4 is
/// load-bearing — do not "fix" it back to 1. Verifier history
/// (fast-path v0.2.8 FIB-cache PR, two failed qemu-5.15 rounds): with
/// k = 1, LLVM strength-reduces `p + 1 > end` (and the equivalent
/// `p >= end`) into the reversed strict compare
/// `if pkt_end > pkt+off goto read`, and the 5.15 verifier's range
/// propagation for exactly that arm is off by one — the taken branch
/// keeps r = off where off+1 is provable, and the 1-byte read at
/// `off` is rejected ("R2 offset is outside of the packet").
/// `p + 4 > end` cannot collapse into a >= form, so LLVM emits the
/// pkt-on-the-left shape (`if pkt+off+4 > pkt_end goto bail`) whose
/// fall-through range every kernel tracks correctly. Semantically
/// free: 4 bytes (type, code, checksum) is the ICMPv6 header minimum,
/// and a message truncated below that cannot be a valid NS — "not
/// NDP" is already the fail-safe answer.
#[inline(always)]
fn icmpv6_type(start: usize, end: usize, offset: usize) -> Option<u8> {
    if start + offset + 4 > end {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned((start + offset) as *const u8) })
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
