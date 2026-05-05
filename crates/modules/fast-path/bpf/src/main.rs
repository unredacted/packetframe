//! PacketFrame fast-path BPF program (SPEC.md §4.4 + §4.7).
//!
//! Parses Ethernet (optionally one 802.1Q tag), IPv4 or IPv6, consults
//! the allowlist (src-or-dst match, §4.2), calls `bpf_fib_lookup`,
//! rewrites L2 + TTL, performs any required VLAN push / pop / rewrite
//! per §4.7, and redirects via `bpf_redirect_map`. All counters in
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
    helpers::gen::{
        bpf_fib_lookup as fib_lookup_helper, bpf_xdp_adjust_head, bpf_xdp_adjust_tail,
    },
    macros::xdp,
    maps::lpm_trie::Key,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EtherType, EthHdr},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
};

mod fib;
mod maps;

use maps::{
    bump_stat, StatIdx, ALLOW_V4, ALLOW_V6, BLOCK_V4, BLOCK_V6, CFG, FP_CFG_FLAG_COMPARE_MODE,
    FP_CFG_FLAG_CUSTOM_FIB, FP_CFG_FLAG_HEAD_SHIFT_128, MSS_CLAMP_BY_IFACE, MSS_CLAMP_V4,
    MSS_CLAMP_V6, REDIRECT_DEVMAP, VLAN_RESOLVE,
};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// IANA protocol numbers, materialized as u8 from the `IpProto` enum
// (`#[repr(u8)]`). network-types 0.2.0 changed `Ipv4Hdr.proto` and
// `Ipv6Hdr.next_hdr` from `IpProto` to raw `u8`, so we match against
// these instead of enum variants.
const PROTO_TCP: u8 = IpProto::Tcp as u8;
const PROTO_UDP: u8 = IpProto::Udp as u8;
const PROTO_ICMPV6: u8 = IpProto::Ipv6Icmp as u8;

/// 802.1Q TPID. What we write back on push / rewrite.
const TPID_8021Q: u16 = 0x8100;

/// Sentinel u16 representing "no VLAN" in the VID-passing API below.
/// 802.1Q reserves VID 0 for priority-only tagging, so `vid == 0`
/// means absent from the fast-path's perspective. Using a single u16
/// instead of `Option<u16>` keeps the value in one register across
/// function-call boundaries — the verifier chokes on Option<u16>
/// because the inner-value register is uninitialized on the None
/// branch, failing with `Rn !read_ok` after argument spills.
const VLAN_NONE: u16 = 0;

/// One 802.1Q tag. 4 bytes: TPID (next header after eth src/dst) is
/// already known = 0x8100, then the TCI (PCP:3 | DEI:1 | VID:12), then
/// the inner ethertype. Laid out packed since the tag sits directly
/// after the MAC pair with no padding.
#[repr(C, packed(1))]
struct VlanTag {
    tci: [u8; 2],
    inner_ether_type: u16,
}
const VLAN_HDR_LEN: usize = 4;

#[xdp]
pub fn fast_path(ctx: XdpContext) -> u32 {
    bump_stat(StatIdx::RxTotal);

    // Pre-parse workaround for the pre-Linux-v6.8 rvu-nicpf XDP path
    // bug (SPEC §11.1(c)). The driver passes
    // `xdp_prepare_buff(&xdp, hard_start, data - hard_start, seg_size, false)`
    // with `data` pointing at `buffer_start`, 128 bytes before the
    // actual packet — so `xdp->data` is headroom and `xdp->data_end`
    // is `seg_size` bytes past `buffer_start`, which cuts off the
    // last 128 bytes of the frame. Rebalance both pointers: skip 128
    // bytes of leading headroom and extend the tail 128 bytes to
    // expose the full frame. Upstream commit `04f647c8e456` (Linux
    // v6.8) fixes this; the workaround is a no-op there because the
    // operator leaves the flag clear.
    //
    // Scoped behind a CFG flag so correct drivers pay zero runtime
    // cost. Userspace sets the flag per attach iface's driver
    // (§11.12 compat matrix).
    if unsafe { cfg_has_flag(FP_CFG_FLAG_HEAD_SHIFT_128) } {
        let rc = unsafe { bpf_xdp_adjust_head(ctx.ctx as *mut _, 128) };
        if rc != 0 {
            bump_stat(StatIdx::ErrHeadShift);
            return xdp_action::XDP_PASS;
        }
        // `adjust_tail(+128)` can fail if the current frame is close
        // to `xdp->frame_sz` — unlikely on rvu-nicpf (rbsize is 2048+)
        // for MTU-sized traffic. `XDP_PASS` on failure preserves the
        // invariant that the kernel never sees a frame the fast path
        // has half-mutated (SPEC §11.13).
        let rc = unsafe { bpf_xdp_adjust_tail(ctx.ctx as *mut _, 128) };
        if rc != 0 {
            bump_stat(StatIdx::ErrHeadShift);
            return xdp_action::XDP_PASS;
        }
    }

    match try_fast_path(&ctx) {
        Ok(action) => action,
        Err(()) => {
            bump_stat(StatIdx::ErrParse);
            xdp_action::XDP_PASS
        }
    }
}

/// Read the `FpCfg.flags` byte via the CFG array map and check
/// whether `bit` is set. Returns `false` if the map is somehow empty
/// (shouldn't happen — userspace always populates it before attach).
#[inline(always)]
unsafe fn cfg_has_flag(bit: u8) -> bool {
    CFG.get(0).map(|c| c.flags & bit != 0).unwrap_or(false)
}

/// Returns Err(()) on bounds-check failure (always counted as
/// `err_parse` → `XDP_PASS`), Ok(action) for everything else.
#[inline(always)]
fn try_fast_path(ctx: &XdpContext) -> Result<u32, ()> {
    let eth: *mut EthHdr = ptr_mut_at(ctx, 0)?;
    let outer_ether = unsafe { (*eth).ether_type };

    // 802.1Q ingress parse (SPEC §4.4 step 2). Step past exactly one
    // tag; QinQ is out of scope for v0.1 (§11.6). For `outer_ether ==
    // 0x8100` on our LE host, the enum discriminant is `Ieee8021q as
    // u16 = 0x0081`.
    let (inner_ether, ip_offset, ingress_vid) = if outer_ether == EtherType::Ieee8021q as u16
        || outer_ether == EtherType::Ieee8021ad as u16
    {
        let vlan: *const VlanTag = ptr_at(ctx, EthHdr::LEN)?;
        let tci = u16::from_be_bytes(unsafe { (*vlan).tci });
        // Low 12 bits are the VID. Legal VIDs are 1..4094; 0 and 4095
        // are reserved. A VID of 0 here would collide with VLAN_NONE,
        // so treat it as absent (matches 802.1Q's "priority-only" tag
        // semantics — we don't fast-path those either).
        let vid = tci & 0x0fff;
        let inner = unsafe { (*vlan).inner_ether_type };
        (inner, EthHdr::LEN + VLAN_HDR_LEN, vid)
    } else {
        (outer_ether, EthHdr::LEN, VLAN_NONE)
    };

    if inner_ether == EtherType::Ipv4 as u16 {
        handle_ipv4(ctx, eth, ip_offset, ingress_vid)
    } else if inner_ether == EtherType::Ipv6 as u16 {
        handle_ipv6(ctx, eth, ip_offset, ingress_vid)
    } else {
        bump_stat(StatIdx::PassNotIp);
        Ok(xdp_action::XDP_PASS)
    }
}

#[inline(always)]
fn handle_ipv4(
    ctx: &XdpContext,
    eth: *mut EthHdr,
    ip_offset: usize,
    ingress_vid: u16,
) -> Result<u32, ()> {
    let ip: *mut Ipv4Hdr = ptr_mut_at(ctx, ip_offset)?;

    // `Ipv4Hdr::ihl()` returns bytes (IHL * 4). Standard header = 20;
    // anything else means options → kernel slow path.
    let ihl_bytes = unsafe { (*ip).ihl() };
    if ihl_bytes != 20 {
        bump_stat(StatIdx::PassComplexHeader);
        return Ok(xdp_action::XDP_PASS);
    }

    // Fragment check: MF bit (0x2000) or non-zero offset (low 13 bits).
    let frags_be = u16::from_be_bytes(unsafe { (*ip).frags });
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

    // v0.2.1 issue #33: bogon block. After allowlist match (so we only
    // affect traffic we'd otherwise touch), check if dst falls in any
    // operator-declared `block-prefix`. If so, drop here — saves the
    // skb allocation, netfilter walk, and conntrack entry that this
    // packet would otherwise burn just to be RST'd by upstream. Empty
    // map (default config) → LPM lookup misses cheaply, no perf impact.
    //
    // We block on dst only, not src. Blocking by src would silently
    // drop reply traffic (asymmetric flows where the *other* side is
    // in the bogon range, e.g. Tailscale DERP relay responses) which
    // is worse than the operator's intent.
    if BLOCK_V4.get(&dst_key).is_some() {
        bump_stat(StatIdx::BogonDropped);
        return Ok(xdp_action::XDP_DROP);
    }

    if is_dry_run() {
        bump_stat(StatIdx::FwdDryRun);
        return Ok(xdp_action::XDP_PASS);
    }

    let (sport, dport) = l4_ports(ctx, ip_offset + Ipv4Hdr::LEN, proto);

    // Option F: select between custom-FIB (LPM trie + NEXTHOPS) and
    // kernel-FIB (bpf_fib_lookup) based on runtime flags. Compare mode
    // runs both and forwards via the kernel result.
    //
    // `l4_ports` returns BE-in-memory u16s (read_unaligned of BE wire
    // bytes on an LE host) because that's what bpf_fib_lookup's
    // `__be16` contract wants. Our own hash operates on native u16
    // values so it's byte-order-agnostic between BPF and the userspace
    // reference. Byte-swap once at the handoff.
    let use_custom = unsafe { cfg_has_flag(FP_CFG_FLAG_CUSTOM_FIB) };
    let compare = unsafe { cfg_has_flag(FP_CFG_FLAG_COMPARE_MODE) };
    let sport_h = u16::from_be(sport);
    let dport_h = u16::from_be(dport);

    if use_custom && !compare {
        let custom = fib::lookup_v4(src_bytes, dst_bytes, proto as u8, sport_h, dport_h);
        return dispatch_custom_fib(custom, ctx, eth, ip as *mut u8, true, ingress_vid);
    }

    let mut fib: bpf_fib_lookup = unsafe { mem::zeroed() };
    fib.family = AF_INET;
    fib.l4_protocol = proto as u8;
    fib.sport = sport;
    fib.dport = dport;
    fib.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    fib.__bindgen_anon_1.tot_len = u16::from_be_bytes(unsafe { (*ip).tot_len });
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

    if compare {
        // Compare mode: we also ran above iff `use_custom`; but since
        // `compare` implies `use_custom` (userspace rejects otherwise),
        // both flags set ⇒ we take this else-branch with kernel FIB
        // and additionally run the custom lookup for comparison. If
        // the operator managed to set COMPARE without CUSTOM_FIB (bug
        // or manual map poke), the branch above is unreachable and
        // we still do only the kernel lookup here.
        let custom = fib::lookup_v4(src_bytes, dst_bytes, proto as u8, sport_h, dport_h);
        compare_and_bump(ret as u32, &fib, &custom);
    }

    dispatch_fib(ret as u32, ctx, eth, ip as *mut u8, true, &fib, ingress_vid)
}

#[inline(always)]
fn handle_ipv6(
    ctx: &XdpContext,
    eth: *mut EthHdr,
    ip_offset: usize,
    ingress_vid: u16,
) -> Result<u32, ()> {
    let ip: *mut Ipv6Hdr = ptr_mut_at(ctx, ip_offset)?;

    let next = unsafe { (*ip).next_hdr };
    match next {
        PROTO_TCP | PROTO_UDP | PROTO_ICMPV6 => {}
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

    // v0.2.1 issue #33: bogon block (IPv6 side).
    if BLOCK_V6.get(&dst_key).is_some() {
        bump_stat(StatIdx::BogonDropped);
        return Ok(xdp_action::XDP_DROP);
    }

    if is_dry_run() {
        bump_stat(StatIdx::FwdDryRun);
        return Ok(xdp_action::XDP_PASS);
    }

    let (sport, dport) = l4_ports(ctx, ip_offset + Ipv6Hdr::LEN, next);

    // Option F dispatch — see handle_ipv4 for commentary, including the
    // port byte-swap rationale.
    let use_custom = unsafe { cfg_has_flag(FP_CFG_FLAG_CUSTOM_FIB) };
    let compare = unsafe { cfg_has_flag(FP_CFG_FLAG_COMPARE_MODE) };
    let sport_h = u16::from_be(sport);
    let dport_h = u16::from_be(dport);

    if use_custom && !compare {
        let custom = fib::lookup_v6(src_bytes, dst_bytes, next as u8, sport_h, dport_h);
        return dispatch_custom_fib(custom, ctx, eth, ip as *mut u8, false, ingress_vid);
    }

    let mut fib: bpf_fib_lookup = unsafe { mem::zeroed() };
    fib.family = AF_INET6;
    fib.l4_protocol = next as u8;
    fib.sport = sport;
    fib.dport = dport;
    fib.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    fib.__bindgen_anon_1.tot_len =
        u16::from_be_bytes(unsafe { (*ip).payload_len }) + Ipv6Hdr::LEN as u16;
    fib.__bindgen_anon_2.flowinfo = u32::from_be_bytes(unsafe { (*ip).vcf });
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

    if compare {
        let custom = fib::lookup_v6(src_bytes, dst_bytes, next as u8, sport_h, dport_h);
        compare_and_bump(ret as u32, &fib, &custom);
    }

    dispatch_fib(ret as u32, ctx, eth, ip as *mut u8, false, &fib, ingress_vid)
}

#[inline(always)]
fn dispatch_fib(
    ret: u32,
    ctx: &XdpContext,
    eth: *mut EthHdr,
    ip: *mut u8,
    is_v4: bool,
    fib: &bpf_fib_lookup,
    ingress_vid: u16,
) -> Result<u32, ()> {
    match ret {
        BPF_FIB_LKUP_RET_SUCCESS => {
            forward_success(ctx, eth, ip, is_v4, fib.ifindex, fib.smac, fib.dmac, ingress_vid)
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

/// Success path shared between the kernel-FIB (`dispatch_fib`) and
/// custom-FIB (`dispatch_custom_fib`) code paths. Takes a decided
/// `(egress_ifindex, smac, dmac)` and performs VLAN resolution,
/// devmap pre-check, TTL decrement, L2 rewrite, VLAN choreography,
/// and redirect. Must not be called without a valid forward decision.
#[inline(always)]
fn forward_success(
    ctx: &XdpContext,
    eth: *mut EthHdr,
    ip: *mut u8,
    is_v4: bool,
    ifindex: u32,
    smac: [u8; 6],
    dmac: [u8; 6],
    ingress_vid: u16,
) -> Result<u32, ()> {
    // Resolve the egress port's expected tagging. If `ifindex` is
    // recorded in `vlan_resolve`, it's a VLAN subif — redirect to the
    // physical parent and push/rewrite to the recorded VID. Otherwise
    // the target is physical/untagged.
    let (egress_ifindex, egress_vid) = match unsafe { VLAN_RESOLVE.get(&ifindex) } {
        Some(vi) => (vi.phys_ifindex, vi.vid),
        None => (ifindex, VLAN_NONE),
    };

    // Defensive devmap pre-check (§4.4 step 9d) — **before any packet
    // mutation**. A prior version rewrote L2 + ran VLAN choreography
    // first, then decided to XDP_PASS when the egress ifindex wasn't
    // in REDIRECT_DEVMAP. That handed the kernel a mangled packet
    // (wrong MACs, TTL decremented, maybe pushed/popped tag) and
    // silently black-holed forwarded traffic. Confirmed outage cause
    // on the reference EFG 2026-04-21. If we can't redirect, we must
    // leave the packet pristine.
    if REDIRECT_DEVMAP.get(egress_ifindex).is_none() {
        bump_stat(StatIdx::PassNotInDevmap);
        return Ok(xdp_action::XDP_PASS);
    }

    // MSS clamping (v0.2.4+, closes SPEC §11.4 gap). Mutate the TCP
    // MSS option in SYN/SYN-ACK packets before they're handed to the
    // egress NIC — must happen before `apply_vlan_egress` (which can
    // shift packet bytes via `bpf_xdp_adjust_head`) but is order-
    // independent w.r.t. TTL decrement and L2 rewrite (those edit
    // existing bytes in place). No-op for non-TCP, non-SYN packets,
    // or when no clamp policy applies. Skipped under `is_dry_run()`
    // because dry-run returns XDP_PASS earlier in the flow.
    mss_clamp_inline(ctx, ip, is_v4, egress_ifindex);

    // TTL/hop_limit + csum first — IP header's position in memory
    // doesn't change with adjust_head, only its offset from `data`.
    if is_v4 {
        decrement_ipv4_ttl(ip as *mut Ipv4Hdr);
    } else {
        decrement_ipv6_hop_limit(ip as *mut Ipv6Hdr);
    }
    // L2 rewrite BEFORE push/pop — push moves the current MAC
    // positions into new slots, so the values there need to be the
    // post-FIB MACs.
    unsafe {
        (*eth).dst_addr = dmac;
        (*eth).src_addr = smac;
    }

    // VLAN choreography (SPEC §4.7). On error, XDP_ABORTED +
    // err_vlan per the spec.
    if apply_vlan_egress(ctx, ingress_vid, egress_vid).is_err() {
        bump_stat(StatIdx::ErrVlan);
        return Ok(xdp_action::XDP_ABORTED);
    }

    match REDIRECT_DEVMAP.redirect(egress_ifindex, 0) {
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

/// Dispatch on a [`fib::CustomFibResult`] returned by the custom-FIB
/// path. Maps the four action codes into the same XDP verdicts
/// `dispatch_fib` returns for the equivalent kernel-FIB outcomes —
/// so the allowlist / dry-run / VLAN-resolve plumbing upstream and
/// downstream is unchanged whether we took the kernel or custom path.
#[inline(always)]
fn dispatch_custom_fib(
    result: fib::CustomFibResult,
    ctx: &XdpContext,
    eth: *mut EthHdr,
    ip: *mut u8,
    is_v4: bool,
    ingress_vid: u16,
) -> Result<u32, ()> {
    match result.action {
        fib::FIB_ACTION_FORWARD => forward_success(
            ctx,
            eth,
            ip,
            is_v4,
            result.egress_ifindex,
            result.smac,
            result.dmac,
            ingress_vid,
        ),
        fib::FIB_ACTION_NO_NEIGH => {
            bump_stat(StatIdx::PassNoNeigh);
            Ok(xdp_action::XDP_PASS)
        }
        fib::FIB_ACTION_DROP => {
            bump_stat(StatIdx::DropUnreachable);
            Ok(xdp_action::XDP_DROP)
        }
        // FIB_ACTION_MISS or any unexpected action.
        _ => Ok(xdp_action::XDP_PASS),
    }
}

/// Compare-mode: kernel-FIB is authoritative (its decision drives
/// forwarding), but we've also computed a custom-FIB decision and
/// want to know whether they agree. Agreement is defined as
/// `(egress_ifindex, dst_mac)` match when both forward, or both
/// don't-forward. Transient disagreement during BGP convergence is
/// expected; the userspace alert thresholds are set ratio-based.
#[inline(always)]
fn compare_and_bump(
    kernel_ret: u32,
    kernel_fib: &bpf_fib_lookup,
    custom: &fib::CustomFibResult,
) {
    let kernel_forwards = kernel_ret == BPF_FIB_LKUP_RET_SUCCESS;
    let custom_forwards = custom.action == fib::FIB_ACTION_FORWARD;
    let agree = if kernel_forwards && custom_forwards {
        // Both forward — compare the decision tuple.
        kernel_fib.ifindex == custom.egress_ifindex && kernel_fib.dmac == custom.dmac
    } else {
        // Both non-forward is "agree" (both defer upstream). Any
        // mix — one forwards while the other doesn't — is disagree.
        !kernel_forwards && !custom_forwards
    };
    if agree {
        bump_stat(StatIdx::CompareAgree);
    } else {
        bump_stat(StatIdx::CompareDisagree);
    }
}

// --- VLAN choreography ----------------------------------------------------

/// §4.7's four-case matrix, keyed on VLAN_NONE-sentinel u16s rather
/// than Option<u16> (the verifier rejects the Option-argument spill).
/// Returns Err(()) on any packet-manipulation failure.
#[inline(always)]
fn apply_vlan_egress(ctx: &XdpContext, ingress_vid: u16, egress_vid: u16) -> Result<(), ()> {
    let ingress_present = ingress_vid != VLAN_NONE;
    let egress_present = egress_vid != VLAN_NONE;
    match (ingress_present, egress_present) {
        (false, false) => Ok(()),
        (true, true) if ingress_vid == egress_vid => Ok(()),
        (false, true) => vlan_push(ctx, egress_vid),
        (true, false) => vlan_pop(ctx),
        (true, true) => vlan_rewrite(ctx, egress_vid),
    }
}

/// Untagged → tagged. Grows headroom by 4, shifts the MAC pair left by
/// 4 bytes, writes TPID + TCI into the freed-up slot. SPEC §4.7.
///
/// Uses `core::ptr::copy` (true memmove) not `copy_nonoverlapping` —
/// the source and destination regions overlap. This is the footgun
/// SPEC calls out: on some VID combinations `copy_nonoverlapping`
/// produces wrong bytes on the wire and the verifier does NOT catch it.
#[inline(always)]
fn vlan_push(ctx: &XdpContext, vid: u16) -> Result<(), ()> {
    // Grow headroom by 4 bytes.
    let rc = unsafe { bpf_xdp_adjust_head(ctx.ctx as *mut _, -4) };
    if rc != 0 {
        return Err(());
    }

    let start = ctx.data();
    let end = ctx.data_end();
    if start + 18 > end {
        return Err(());
    }

    // SAFETY: pointers derived from the freshly-re-read data/data_end,
    // both bounds-checked for the 18-byte range we touch.
    unsafe {
        let base = start as *mut u8;
        // Move dst_mac left: [4..10] → [0..6]. 6-byte move, overlapping.
        core::ptr::copy(base.add(4), base, 6);
        // Move src_mac left: [10..16] → [6..12]. Overlapping.
        core::ptr::copy(base.add(10), base.add(6), 6);
        // TPID (0x8100) at [12..14], big-endian.
        let tpid = TPID_8021Q.to_be_bytes();
        *base.add(12) = tpid[0];
        *base.add(13) = tpid[1];
        // TCI at [14..16]: PCP=0 | DEI=0 | VID (12 bits), big-endian.
        let tci = (vid & 0x0fff).to_be_bytes();
        *base.add(14) = tci[0];
        *base.add(15) = tci[1];
        // [16..18] already holds the original inner ethertype —
        // bpf_xdp_adjust_head didn't touch packet bytes, only the
        // data pointer.
    }
    Ok(())
}

/// Tagged → untagged. Shifts the MAC pair right by 4 bytes over the
/// (about-to-be-discarded) TPID+TCI slot, then shrinks headroom by 4.
#[inline(always)]
fn vlan_pop(ctx: &XdpContext) -> Result<(), ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + 18 > end {
        return Err(());
    }
    // SAFETY: bounds-checked 18-byte range.
    unsafe {
        let base = start as *mut u8;
        // Move src_mac right first: [6..12] → [10..16]. Overlapping.
        core::ptr::copy(base.add(6), base.add(10), 6);
        // Move dst_mac right: [0..6] → [4..10]. Overlapping.
        core::ptr::copy(base, base.add(4), 6);
    }
    // Shrink headroom by 4; new data starts 4 bytes later.
    let rc = unsafe { bpf_xdp_adjust_head(ctx.ctx as *mut _, 4) };
    if rc != 0 {
        return Err(());
    }
    Ok(())
}

/// Tagged VID X → tagged VID Y (X ≠ Y). No headroom change; overwrite
/// the TCI bytes in place.
#[inline(always)]
fn vlan_rewrite(ctx: &XdpContext, vid: u16) -> Result<(), ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + 16 > end {
        return Err(());
    }
    let tci = (vid & 0x0fff).to_be_bytes();
    unsafe {
        let base = start as *mut u8;
        *base.add(14) = tci[0];
        *base.add(15) = tci[1];
    }
    Ok(())
}

// --- MSS clamping (v0.2.4+, SPEC §4.x — closes §11.4 gap) -----------------

/// SYN flag in TCP byte 13 (low byte of `doff_flags` over the wire).
const TCP_FLAG_SYN: u8 = 0x02;

/// Walk the TCP-options block of a matched SYN/SYN-ACK and mutate the
/// MSS option in place if a clamp policy applies and the existing MSS
/// is greater than the clamp value. Recomputes the TCP checksum
/// incrementally (RFC 1624). Bumps `MssClampApplied` on rewrite and
/// `MssClampSkipped` on "policy applies but no rewrite needed" — i.e.
/// existing MSS already ≤ clamp, no MSS option present, or malformed
/// options walked past before finding it.
///
/// Bounds-checked at every read against `ctx.data_end()`. The options
/// loop is fixed-bound at 40 iterations (TCP options max 40 bytes;
/// each iteration consumes at least 1 byte) so the BPF verifier
/// accepts it without unrolling concerns.
///
/// Marked `#[inline(always)]` deliberately. Two earlier attempts to
/// split this into a subprogram (for stack budget) ran into the BPF
/// kernel verifier rejecting the bpf2bpf calling convention LLVM
/// emits: even when arguments are scalar, LLVM SROA decomposes
/// `&XdpContext` into `(data, data_end)` packet pointers, and the
/// verifier prohibits pointer-shift instructions on packet pointers
/// (the lift LLVM emits to extend 32-bit→64-bit). Inlining is the
/// only verifier-friendly option for code that touches the packet.
///
/// Stack trim: each LPM key is block-scoped so the compiler can
/// reuse the same stack slot for src and dst keys rather than
/// holding both live; lookup helpers are also `#[inline(always)]`
/// for the same reason; src/dst addresses are read inside their
/// respective LPM blocks rather than at the function top.
#[inline(always)]
fn mss_clamp_inline(ctx: &XdpContext, ip: *mut u8, is_v4: bool, egress_ifindex: u32) {
    let start = ctx.data();
    let end = ctx.data_end();

    // Read protocol byte first — bail early on non-TCP, which is
    // the overwhelmingly common case for fast-pathed traffic.
    let proto = if is_v4 {
        unsafe { (*(ip as *const Ipv4Hdr)).proto }
    } else {
        unsafe { (*(ip as *const Ipv6Hdr)).next_hdr }
    };
    if proto != PROTO_TCP {
        return;
    }

    // Look up clamp value via the precedence chain. Returns 0 if no
    // policy applies. Helper is `#[inline(always)]`; its locals share
    // this function's frame and are block-scoped for slot reuse.
    let clamp = if is_v4 {
        lookup_mss_clamp_v4(ip as *const Ipv4Hdr, egress_ifindex)
    } else {
        lookup_mss_clamp_v6(ip as *const Ipv6Hdr, egress_ifindex)
    };
    if clamp == 0 {
        return;
    }

    // Recover the IP-header offset so we can compute the TCP offset
    // (and bounds-check) without holding `ip` as a separate pointer
    // variable. ip - start is a scalar (pkt_a - pkt_b) per the
    // verifier.
    let ip_offset = (ip as usize) - start;
    let tcp_offset = ip_offset + if is_v4 { Ipv4Hdr::LEN } else { Ipv6Hdr::LEN };

    // Need 20 bytes for the fixed TCP header before walking options.
    if start + tcp_offset + 20 > end {
        return;
    }

    // Bytes 12-13 of TCP header: data_offset:4 | reserved:4 | flags:8.
    // doff is in 32-bit words; valid range [5, 15] = [20, 60] bytes.
    let doff_byte = unsafe { *((start + tcp_offset + 12) as *const u8) };
    let flags = unsafe { *((start + tcp_offset + 13) as *const u8) };
    if flags & TCP_FLAG_SYN == 0 {
        return; // Not SYN/SYN-ACK; clamp doesn't apply.
    }
    let doff_words = (doff_byte >> 4) as usize;
    if !(5..=15).contains(&doff_words) {
        return;
    }
    let tcp_hdr_len = doff_words * 4;
    let opts_len = tcp_hdr_len - 20;
    if opts_len == 0 {
        // SYN with no options — operator policy says "clamp" but
        // there's no MSS field to mutate. Count as skipped.
        bump_stat(StatIdx::MssClampSkipped);
        return;
    }
    if start + tcp_offset + tcp_hdr_len > end {
        return;
    }

    // Walk options. 40 iterations is the absolute upper bound (each
    // iteration consumes ≥1 byte and opts_len ≤ 40). The verifier
    // sees a constant-bound loop with packet-bounds checks at every
    // pointer dereference, which it accepts.
    let opts_start_off = tcp_offset + 20;
    let mut cursor: usize = 0;
    let mut found = false;

    for _ in 0..40 {
        if cursor >= opts_len {
            break;
        }
        let p_addr = start + opts_start_off + cursor;
        if p_addr + 1 > end {
            break;
        }
        let p = p_addr as *const u8;
        let kind = unsafe { *p };
        match kind {
            0 => break,           // EOL
            1 => cursor += 1,     // NOP — single byte
            2 => {
                // MSS option: [kind=2, length=4, mss_be:2].
                if p_addr + 4 > end {
                    break;
                }
                let length = unsafe { *p.add(1) };
                if length != 4 {
                    break;
                }
                let mss_be = unsafe { [*p.add(2), *p.add(3)] };
                let mss = u16::from_be_bytes(mss_be);
                if mss > clamp {
                    let new_mss_be = clamp.to_be_bytes();
                    unsafe {
                        let pmut = p as *mut u8;
                        *pmut.add(2) = new_mss_be[0];
                        *pmut.add(3) = new_mss_be[1];
                    }
                    // TCP csum is at offset 16 of the TCP header; do
                    // an RFC 1624 incremental update.
                    let csum_off = tcp_offset + 16;
                    if start + csum_off + 2 > end {
                        return;
                    }
                    let csum_p = (start + csum_off) as *mut u8;
                    let old_csum_be =
                        unsafe { [*csum_p, *csum_p.add(1)] };
                    let old_csum = u16::from_be_bytes(old_csum_be);
                    let new_csum = csum_replace_u16(old_csum, mss, clamp);
                    let new_csum_be = new_csum.to_be_bytes();
                    unsafe {
                        *csum_p = new_csum_be[0];
                        *csum_p.add(1) = new_csum_be[1];
                    }
                    bump_stat(StatIdx::MssClampApplied);
                } else {
                    bump_stat(StatIdx::MssClampSkipped);
                }
                found = true;
                break;
            }
            _ => {
                // Length-prefixed option. Length byte at offset +1
                // includes the kind+length bytes themselves.
                if p_addr + 2 > end {
                    break;
                }
                let length = unsafe { *p.add(1) } as usize;
                if length < 2 {
                    break; // Malformed.
                }
                cursor += length;
            }
        }
    }

    if !found {
        // Hit EOL or walked past the budget without an MSS option.
        bump_stat(StatIdx::MssClampSkipped);
    }
}

/// Apply RFC 1624 incremental checksum update for a single 16-bit
/// field change: `HC' = ~(~HC + ~m + m')`. Two-iteration end-around
/// carry fold (max 2 needed for adding three 16-bit values into a
/// u32). Verifier-friendly — no loops.
#[inline(always)]
fn csum_replace_u16(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum: u32 = (!old_csum) as u32 + (!old_val) as u32 + new_val as u32;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// Resolve the mss-clamp value for an IPv4 packet, in precedence
/// order: src-prefix → dst-prefix → per-egress → global. Returns 0 if
/// no policy applies. The LPM lookups respect each entry's
/// `iface_filter` (0 = wildcard). Block-scope each Key + addr so LLVM
/// can reuse the same stack slot rather than carrying both keys live
/// — matters for the cumulative BPF 512-byte stack budget. Reads
/// addresses through the IP-header pointer rather than taking them
/// by value so the caller doesn't pre-materialize them on its frame.
#[inline(always)]
fn lookup_mss_clamp_v4(ip: *const Ipv4Hdr, egress_ifindex: u32) -> u16 {
    {
        let key = Key::new(32, unsafe { (*ip).src_addr });
        if let Some(entry) = MSS_CLAMP_V4.get(&key) {
            if entry.iface_filter == 0 || entry.iface_filter == egress_ifindex {
                return entry.mss;
            }
        }
    }
    {
        let key = Key::new(32, unsafe { (*ip).dst_addr });
        if let Some(entry) = MSS_CLAMP_V4.get(&key) {
            if entry.iface_filter == 0 || entry.iface_filter == egress_ifindex {
                return entry.mss;
            }
        }
    }
    if let Some(mss) = unsafe { MSS_CLAMP_BY_IFACE.get(&egress_ifindex) } {
        if *mss != 0 {
            return *mss;
        }
    }
    if let Some(c) = CFG.get(0) {
        return c.mss_clamp_global;
    }
    0
}

/// IPv6 mirror of [`lookup_mss_clamp_v4`] — same precedence, /128 keys.
#[inline(always)]
fn lookup_mss_clamp_v6(ip: *const Ipv6Hdr, egress_ifindex: u32) -> u16 {
    {
        let key = Key::new(128, unsafe { (*ip).src_addr });
        if let Some(entry) = MSS_CLAMP_V6.get(&key) {
            if entry.iface_filter == 0 || entry.iface_filter == egress_ifindex {
                return entry.mss;
            }
        }
    }
    {
        let key = Key::new(128, unsafe { (*ip).dst_addr });
        if let Some(entry) = MSS_CLAMP_V6.get(&key) {
            if entry.iface_filter == 0 || entry.iface_filter == egress_ifindex {
                return entry.mss;
            }
        }
    }
    if let Some(mss) = unsafe { MSS_CLAMP_BY_IFACE.get(&egress_ifindex) } {
        if *mss != 0 {
            return *mss;
        }
    }
    if let Some(c) = CFG.get(0) {
        return c.mss_clamp_global;
    }
    0
}

// --- TTL / csum / helpers -------------------------------------------------

/// Decrement IPv4 TTL and patch the header checksum using RFC 1624
/// incremental update: when TTL decreases by 1, the word at bytes 8-9
/// (TTL:proto, network order) decreases by 0x0100 → the checksum
/// increases by 0x0100 in one's-complement arithmetic.
#[inline(always)]
fn decrement_ipv4_ttl(ip: *mut Ipv4Hdr) {
    unsafe {
        (*ip).ttl -= 1;
        let mut sum = u16::from_be_bytes((*ip).check) as u32;
        sum = sum.wrapping_add(0x0100);
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

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let size = mem::size_of::<T>();
    if start + offset + size > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[inline(always)]
fn ptr_mut_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    Ok(ptr_at::<T>(ctx, offset)? as *mut T)
}

/// Read sport/dport from the L4 header at `offset`. Returns raw BE
/// network-order u16 bytes (via `read_unaligned`) matching what the
/// kernel's `bpf_fib_lookup` expects for its `__be16` sport/dport
/// fields on an LE host. (0, 0) for ICMP / ICMPv6 or truncated L4.
#[inline(always)]
fn l4_ports(ctx: &XdpContext, offset: usize, proto: u8) -> (u16, u16) {
    if !matches!(proto, PROTO_TCP | PROTO_UDP) {
        return (0, 0);
    }
    let start = ctx.data();
    let end = ctx.data_end();
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
