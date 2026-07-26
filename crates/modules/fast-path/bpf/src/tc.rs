//! tc-ingress datapath (Phase T): `tc_fast_path` + `tc_finalize`
//! sched_cls programs, attached via clsact with direct-action.
//!
//! Same forwarding semantics as the XDP pair in `main.rs`/`finalize.rs`
//! — same maps, same counters, same classification and custom-FIB
//! logic (shared via `datapath.rs` and `fib.rs`) — but running on the
//! skb path, which on generic-XDP-only hardware (rvu-nicpf pre-6.8)
//! avoids generic XDP's three per-packet taxes: the 256-byte-headroom
//! `pskb_expand_head` copy, GRO-skb linearization, and the un-bulked
//! `generic_xdp_tx` transmit. GRO super-skbs forward as single units
//! (GSO segmentation happens on egress in `validate_xmit_skb`).
//!
//! The per-hook differences, and only these, live here:
//!
//! - **VLAN ingress is metadata-first.** By clsact time the kernel has
//!   usually untagged the frame into `skb->vlan_tci` (hw offload or
//!   `skb_vlan_untag`); the inline-tag parse is kept as a fallback
//!   because `BPF_PROG_TEST_RUN` does not untag.
//! - **Redirect pre-check is a plain map.** `bpf_redirect()` cannot
//!   pre-check — it always "succeeds" in-program and an invalid target
//!   drops the skb after return — so the §11.13 mutate-only-if-
//!   forwardable invariant is upheld by consulting
//!   `TC_REDIRECT_TARGETS` (a devmap-membership mirror) BEFORE any
//!   mutation.
//! - **MTU is checked pre-mutation.** `dev_queue_xmit` via
//!   `skb_do_redirect` has no `is_skb_forwardable` MTU check, so an
//!   oversize non-GSO packet would reach the driver silently.
//!   `bpf_check_mtu(BPF_MTU_CHK_SEGS)` runs in stage 1, before TTL/L2
//!   rewrite, and exceeds return TC_ACT_OK pristine so the kernel
//!   emits FRAG_NEEDED — which also gives custom-fib mode the
//!   FRAG_NEEDED parity it lacks under XDP.
//! - **Egress VLAN uses the skb helpers.** Manual byte-shifting at TC
//!   would desync `skb->mac_len`/`skb->protocol`, which
//!   `dev_queue_xmit`/GSO rely on; `bpf_skb_vlan_push/pop` keep the
//!   metadata coherent. They invalidate packet pointers, so they run
//!   after every direct packet write, immediately before redirect.
//! - **Separate tail-call table.** PROG_ARRAYs bind to one owner
//!   program type; sched_cls jumps through `TC_MUTATION_PROGS`.
//!
//! Verifier constraints are prog-type-independent and all apply here:
//! everything `#[inline(always)]`, no memset/memcpy bait, two-stage
//! split for the same 512-byte stack budget.

use aya_ebpf::{
    bindings::{bpf_check_mtu_flags::BPF_MTU_CHK_SEGS, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_check_mtu, bpf_redirect, bpf_skb_vlan_pop, bpf_skb_vlan_push},
    macros::classifier,
    maps::lpm_trie::Key,
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

use crate::datapath::{
    bump_match_subset, decrement_ipv4_ttl, decrement_ipv6_hop_limit, icmpv6_type, mss_clamp_tcp,
    tcp_syn_flag_set,
};
use crate::maps::{
    bump, stats_base, StatIdx, StatsPtr, ALLOW_V4, ALLOW_V6, BLOCK_V4, BLOCK_V6, CFG,
    FP_CFG_FLAG_BLOCK_PRESENT, FP_CFG_FLAG_CUSTOM_FIB, FP_CFG_FLAG_MSS_CLAMP_PRESENT,
    FP_CFG_FLAG_VLAN_PRESENT, MUTATION_CTX, TC_MUTATION_PROGS, TC_REDIRECT_TARGETS, VLAN_RESOLVE,
};
use crate::{
    fib, ICMPV6_ND_TYPE_MAX, ICMPV6_ND_TYPE_MIN, PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, VLAN_HDR_LEN,
    VLAN_NONE,
};

/// `bpf_redirect()`'s success return (uapi TC_ACT_REDIRECT). Returned
/// verbatim from the classifier so the kernel performs the redirect.
const TC_ACT_REDIRECT: i32 = 7;

/// 802.1Q TPID for `bpf_skb_vlan_push`'s `__be16 vlan_proto` argument.
const ETH_P_8021Q_BE: u16 = 0x8100u16.to_be();

#[classifier]
pub fn tc_fast_path(ctx: TcContext) -> i32 {
    // Same single-lookup STATS + CFG pattern as the XDP stage; see
    // main.rs. TC additionally bumps the A/B attribution counter.
    let stats = match stats_base() {
        Some(s) => s,
        None => return TC_ACT_OK as i32,
    };
    bump(stats, StatIdx::RxTotal);
    bump(stats, StatIdx::RxTotalTc);

    let (cfg_flags, dry_run, mss_clamp_global) = match CFG.get(0) {
        Some(c) => (c.flags, c.dry_run != 0, c.mss_clamp_global),
        None => (0u8, false, 0u16),
    };
    // No head-shift here: the rvu-nicpf xdp_buff mis-sizing bug lives
    // in the driver's XDP path; by clsact time the skb is normalized.

    match tc_try_fast_path(&ctx, stats, cfg_flags, dry_run, mss_clamp_global) {
        Ok(verdict) => verdict,
        Err(()) => {
            bump(stats, StatIdx::ErrParse);
            TC_ACT_OK as i32
        }
    }
}

#[inline(always)]
fn tc_try_fast_path(
    ctx: &TcContext,
    stats: StatsPtr,
    cfg_flags: u8,
    dry_run: bool,
    mss_clamp_global: u16,
) -> Result<i32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + EthHdr::LEN > end {
        return Err(());
    }
    let eth = start as *mut EthHdr;
    let outer_ether = unsafe { (*eth).ether_type };

    // VLAN ingress: metadata first. cls_bpf runs with `data` pushed
    // back to the MAC header, but the 802.1Q tag itself has usually
    // been lifted into skb metadata (`vlan_tci`) by hw offload or
    // `skb_vlan_untag` before clsact — the inline bytes then hold the
    // untagged frame. The inline parse below only fires when the tag
    // is still in-band (BPF_PROG_TEST_RUN, exotic drivers).
    let skb = ctx.skb.skb;
    let meta_present = unsafe { (*skb).vlan_present } != 0;
    let (inner_ether, ip_offset, ingress_vid) = if meta_present {
        let vid = (unsafe { (*skb).vlan_tci } & 0x0fff) as u16;
        (outer_ether, EthHdr::LEN, vid)
    } else if outer_ether == EtherType::Ieee8021q as u16
        || outer_ether == EtherType::Ieee8021ad as u16
    {
        // Inline-tag fallback; mirrors main.rs's parse (one tag, QinQ
        // out of scope, VID 0 treated as absent).
        if start + EthHdr::LEN + VLAN_HDR_LEN > end {
            return Err(());
        }
        let tci_hi = unsafe { *((start + EthHdr::LEN) as *const u8) };
        let tci_lo = unsafe { *((start + EthHdr::LEN + 1) as *const u8) };
        let vid = u16::from_be_bytes([tci_hi, tci_lo]) & 0x0fff;
        let inner = unsafe { core::ptr::read_unaligned((start + EthHdr::LEN + 2) as *const u16) };
        (inner, EthHdr::LEN + VLAN_HDR_LEN, vid)
    } else {
        (outer_ether, EthHdr::LEN, VLAN_NONE)
    };

    if inner_ether == EtherType::Ipv4 as u16 {
        tc_handle_ipv4(
            ctx,
            stats,
            cfg_flags,
            dry_run,
            mss_clamp_global,
            eth,
            ip_offset,
            ingress_vid,
        )
    } else if inner_ether == EtherType::Ipv6 as u16 {
        tc_handle_ipv6(
            ctx,
            stats,
            cfg_flags,
            dry_run,
            mss_clamp_global,
            eth,
            ip_offset,
            ingress_vid,
        )
    } else {
        bump(stats, StatIdx::PassNotIp);
        Ok(TC_ACT_OK as i32)
    }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn tc_handle_ipv4(
    ctx: &TcContext,
    stats: StatsPtr,
    cfg_flags: u8,
    dry_run: bool,
    mss_clamp_global: u16,
    eth: *mut EthHdr,
    ip_offset: usize,
    ingress_vid: u16,
) -> Result<i32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + ip_offset + Ipv4Hdr::LEN > end {
        return Err(());
    }
    let ip = (start + ip_offset) as *mut Ipv4Hdr;

    // Classification identical to main.rs::handle_ipv4 — same order,
    // same counters, same gates.
    let ihl_bytes = unsafe { (*ip).ihl() };
    if ihl_bytes != 20 {
        bump(stats, StatIdx::PassComplexHeader);
        return Ok(TC_ACT_OK as i32);
    }
    let frags_be = u16::from_be_bytes(unsafe { (*ip).frags });
    if (frags_be & 0x3fff) != 0 {
        bump(stats, StatIdx::PassFragment);
        return Ok(TC_ACT_OK as i32);
    }
    let ttl = unsafe { (*ip).ttl };
    if ttl <= 1 {
        bump(stats, StatIdx::PassLowTtl);
        return Ok(TC_ACT_OK as i32);
    }

    let src_bytes = unsafe { (*ip).src_addr };
    let dst_bytes = unsafe { (*ip).dst_addr };
    let proto = unsafe { (*ip).proto };

    let src_key = Key::new(32, src_bytes);
    let dst_key = Key::new(32, dst_bytes);
    let src_hit = ALLOW_V4.get(&src_key).is_some();
    let dst_hit = ALLOW_V4.get(&dst_key).is_some();
    if !(src_hit || dst_hit) {
        return Ok(TC_ACT_OK as i32);
    }
    bump(stats, StatIdx::MatchedV4);
    bump_match_subset(stats, src_hit, dst_hit);

    if cfg_flags & FP_CFG_FLAG_BLOCK_PRESENT != 0 && BLOCK_V4.get(&dst_key).is_some() {
        bump(stats, StatIdx::BogonDropped);
        return Ok(TC_ACT_SHOT as i32);
    }
    if dry_run {
        bump(stats, StatIdx::FwdDryRun);
        return Ok(TC_ACT_OK as i32);
    }

    // tc datapath is custom-fib only (Phase T scope): kernel-fib
    // deployments have no reason to leave XDP, and skipping the
    // bpf_fib_lookup arm keeps this program's verifier footprint
    // small. Userspace enforces the pairing (attach `tc` requires
    // `forwarding-mode custom-fib`); if the flag is somehow clear,
    // fail open to the kernel path rather than guess.
    if cfg_flags & FP_CFG_FLAG_CUSTOM_FIB == 0 {
        return Ok(TC_ACT_OK as i32);
    }
    let l4_off = ip_offset + Ipv4Hdr::LEN;
    let custom = fib::lookup_v4(stats, start, end, l4_off, src_bytes, dst_bytes, proto);
    tc_dispatch_custom_fib(
        custom,
        ctx,
        stats,
        cfg_flags,
        mss_clamp_global,
        eth,
        ip as *mut u8,
        true,
        ingress_vid,
    )
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn tc_handle_ipv6(
    ctx: &TcContext,
    stats: StatsPtr,
    cfg_flags: u8,
    dry_run: bool,
    mss_clamp_global: u16,
    eth: *mut EthHdr,
    ip_offset: usize,
    ingress_vid: u16,
) -> Result<i32, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + ip_offset + Ipv6Hdr::LEN > end {
        return Err(());
    }
    let ip = (start + ip_offset) as *mut Ipv6Hdr;

    let next = unsafe { (*ip).next_hdr };
    match next {
        PROTO_TCP | PROTO_UDP | PROTO_ICMPV6 => {}
        _ => {
            bump(stats, StatIdx::PassComplexHeader);
            return Ok(TC_ACT_OK as i32);
        }
    }
    // NDP gate: identical rationale to main.rs (RFC 4861 hop-limit-255
    // messages must never be forwarded with a decremented hop limit).
    if next == PROTO_ICMPV6 {
        if let Some(t) = icmpv6_type(start, end, ip_offset + Ipv6Hdr::LEN) {
            if t >= ICMPV6_ND_TYPE_MIN && t <= ICMPV6_ND_TYPE_MAX {
                bump(stats, StatIdx::PassNdp);
                return Ok(TC_ACT_OK as i32);
            }
        }
    }
    let hop_limit = unsafe { (*ip).hop_limit };
    if hop_limit <= 1 {
        bump(stats, StatIdx::PassLowTtl);
        return Ok(TC_ACT_OK as i32);
    }

    let src_bytes = unsafe { (*ip).src_addr };
    let dst_bytes = unsafe { (*ip).dst_addr };
    let src_key = Key::new(128, src_bytes);
    let dst_key = Key::new(128, dst_bytes);
    let src_hit = ALLOW_V6.get(&src_key).is_some();
    let dst_hit = ALLOW_V6.get(&dst_key).is_some();
    if !(src_hit || dst_hit) {
        return Ok(TC_ACT_OK as i32);
    }
    bump(stats, StatIdx::MatchedV6);
    bump_match_subset(stats, src_hit, dst_hit);

    if cfg_flags & FP_CFG_FLAG_BLOCK_PRESENT != 0 && BLOCK_V6.get(&dst_key).is_some() {
        bump(stats, StatIdx::BogonDropped);
        return Ok(TC_ACT_SHOT as i32);
    }
    if dry_run {
        bump(stats, StatIdx::FwdDryRun);
        return Ok(TC_ACT_OK as i32);
    }

    // Custom-fib only; see tc_handle_ipv4.
    if cfg_flags & FP_CFG_FLAG_CUSTOM_FIB == 0 {
        return Ok(TC_ACT_OK as i32);
    }
    let l4_off = ip_offset + Ipv6Hdr::LEN;
    let custom = fib::lookup_v6(stats, start, end, l4_off, src_bytes, dst_bytes, next);
    tc_dispatch_custom_fib(
        custom,
        ctx,
        stats,
        cfg_flags,
        mss_clamp_global,
        eth,
        ip as *mut u8,
        false,
        ingress_vid,
    )
}

/// TC verdict mapping for a [`fib::CustomFibResult`]: same shape as
/// main.rs::dispatch_custom_fib with XDP verdicts swapped for TC
/// actions (PASS→OK, DROP→SHOT).
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn tc_dispatch_custom_fib(
    result: fib::CustomFibResult,
    ctx: &TcContext,
    stats: StatsPtr,
    cfg_flags: u8,
    mss_clamp_global: u16,
    eth: *mut EthHdr,
    ip: *mut u8,
    is_v4: bool,
    ingress_vid: u16,
) -> Result<i32, ()> {
    match result.action {
        fib::FIB_ACTION_FORWARD => tc_forward_success(
            ctx,
            stats,
            cfg_flags,
            mss_clamp_global,
            eth,
            ip,
            is_v4,
            result.egress_ifindex,
            result.smac,
            result.dmac,
            ingress_vid,
        ),
        fib::FIB_ACTION_NO_NEIGH => {
            bump(stats, StatIdx::PassNoNeigh);
            Ok(TC_ACT_OK as i32)
        }
        fib::FIB_ACTION_DROP => {
            bump(stats, StatIdx::DropUnreachable);
            Ok(TC_ACT_SHOT as i32)
        }
        _ => Ok(TC_ACT_OK as i32),
    }
}

/// Success path: VLAN-resolve gate, targets pre-check, MTU pre-check,
/// TTL + L2 rewrite, MUTATION_CTX handoff, tail-call into tc_finalize.
/// The two pre-checks run BEFORE any packet mutation, upholding the
/// §11.13 pristine-pass invariant (the 2026-04-21 outage lesson) —
/// mandatory at TC because a failed `bpf_redirect` DROPS the skb
/// rather than passing it.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn tc_forward_success(
    ctx: &TcContext,
    stats: StatsPtr,
    cfg_flags: u8,
    mss_clamp_global: u16,
    eth: *mut EthHdr,
    ip: *mut u8,
    is_v4: bool,
    ifindex: u32,
    smac: [u8; 6],
    dmac: [u8; 6],
    ingress_vid: u16,
) -> Result<i32, ()> {
    let (egress_ifindex, egress_vid) = if cfg_flags & FP_CFG_FLAG_VLAN_PRESENT != 0 {
        match unsafe { VLAN_RESOLVE.get(&ifindex) } {
            Some(vi) => (vi.phys_ifindex, vi.vid),
            None => (ifindex, VLAN_NONE),
        }
    } else {
        (ifindex, VLAN_NONE)
    };

    if unsafe { TC_REDIRECT_TARGETS.get(&egress_ifindex) }.is_none() {
        bump(stats, StatIdx::PassNotInDevmap);
        return Ok(TC_ACT_OK as i32);
    }

    // MTU pre-check, segment-aware: a GSO super-skb passes if its
    // segments fit. Exceeds return the packet PRISTINE so the kernel
    // slow path emits FRAG_NEEDED (custom-fib gets FRAG_NEEDED parity
    // XDP never had). `skb_do_redirect → dev_queue_xmit` performs no
    // MTU check of its own.
    let mut mtu_len: u32 = 0;
    let mtu_rc = unsafe {
        bpf_check_mtu(
            ctx.skb.skb as *mut core::ffi::c_void,
            egress_ifindex,
            &mut mtu_len,
            0,
            BPF_MTU_CHK_SEGS as u64,
        )
    };
    if mtu_rc != 0 {
        bump(stats, StatIdx::PassFragNeeded);
        return Ok(TC_ACT_OK as i32);
    }

    // Direct packet writes; sched_cls supports them and the verifier
    // has the ranges from the callers' bounds checks.
    if is_v4 {
        decrement_ipv4_ttl(ip as *mut Ipv4Hdr);
    } else {
        decrement_ipv6_hop_limit(ip as *mut Ipv6Hdr);
    }
    unsafe {
        (*eth).dst_addr = dmac;
        (*eth).src_addr = smac;
    }

    let ip_offset = (ip as usize) - ctx.data();
    if let Some(mctx_ptr) = MUTATION_CTX.get_ptr_mut(0) {
        // Same field-by-field store discipline as main.rs (no memset
        // bait). Sharing MUTATION_CTX with the XDP chain is safe: BPF
        // programs run to completion per CPU, so each chain's
        // write→tail_call→read is atomic with respect to the other
        // datapath.
        unsafe {
            (*mctx_ptr).egress_ifindex = egress_ifindex;
            (*mctx_ptr).egress_vid = egress_vid;
            (*mctx_ptr).ingress_vid = ingress_vid;
            (*mctx_ptr).ip_offset = ip_offset as u32;
            (*mctx_ptr).is_v4 = u32::from(u8::from(is_v4));
            (*mctx_ptr).cfg_flags = u16::from(cfg_flags);
            (*mctx_ptr).mss_clamp_global = mss_clamp_global;
        }
    } else {
        bump(stats, StatIdx::ErrMutationCtx);
        return Ok(TC_ACT_OK as i32);
    }

    let _ = unsafe { TC_MUTATION_PROGS.tail_call(ctx, 0) };
    bump(stats, StatIdx::ErrTailCall);
    Ok(TC_ACT_OK as i32)
}

#[classifier]
pub fn tc_finalize(ctx: TcContext) -> i32 {
    let stats = match stats_base() {
        Some(s) => s,
        None => return TC_ACT_OK as i32,
    };
    let mctx = match unsafe { MUTATION_CTX.get(0) } {
        Some(c) => *c,
        None => {
            bump(stats, StatIdx::ErrMutationCtx);
            return TC_ACT_OK as i32;
        }
    };

    let egress_ifindex = mctx.egress_ifindex;
    let egress_vid = mctx.egress_vid;
    let ingress_vid = mctx.ingress_vid;
    let is_v4 = mctx.is_v4 != 0;

    // Same verifier-mandated umax clamp as finalize.rs; same counter.
    let ip_offset = mctx.ip_offset as usize;
    if ip_offset > crate::finalize::MAX_IP_OFFSET {
        bump(stats, StatIdx::ErrCtxOffsetRange);
        return TC_ACT_OK as i32;
    }

    // mss-clamp before the VLAN helpers (which invalidate packet
    // pointers). Gated identically to finalize.rs.
    if mctx.cfg_flags & u16::from(FP_CFG_FLAG_MSS_CLAMP_PRESENT) != 0 {
        tc_mss_clamp_inline(
            &ctx,
            stats,
            ip_offset,
            is_v4,
            egress_ifindex,
            mctx.mss_clamp_global,
        );
    }

    // VLAN egress choreography via the skb helpers, which keep
    // `skb->mac_len`/`skb->protocol` coherent for dev_queue_xmit/GSO.
    // Same-VID passthrough needs nothing: a metadata tag is reinserted
    // by validate_xmit_skb on the egress dev. These calls invalidate
    // every packet pointer — nothing below touches packet data.
    if ingress_vid != egress_vid {
        if ingress_vid != VLAN_NONE {
            let rc = unsafe { bpf_skb_vlan_pop(ctx.skb.skb) };
            if rc != 0 {
                bump(stats, StatIdx::ErrVlan);
                return TC_ACT_SHOT as i32;
            }
        }
        if egress_vid != VLAN_NONE {
            let rc = unsafe { bpf_skb_vlan_push(ctx.skb.skb, ETH_P_8021Q_BE, egress_vid) };
            if rc != 0 {
                bump(stats, StatIdx::ErrVlan);
                return TC_ACT_SHOT as i32;
            }
        }
    }

    // bpf_redirect always "succeeds" from the program's perspective;
    // the actual redirect happens after return via skb_do_redirect.
    // TC_ACT_REDIRECT is the only success value; anything else means
    // the helper rejected the call itself.
    let ret = unsafe { bpf_redirect(egress_ifindex, 0) } as i32;
    if ret == TC_ACT_REDIRECT {
        bump(stats, StatIdx::FwdOk);
        bump(stats, StatIdx::FwdOkTc);
    } else {
        bump(stats, StatIdx::ErrRedirectFailed);
    }
    ret
}

/// TC twin of finalize.rs::mss_clamp_inline: same dispatch, same
/// shared option-walk (`datapath::mss_clamp_tcp`), same clamp-source
/// lookups (`finalize::lookup_mss_clamp_v4/v6` — ip-pointer-based and
/// ctx-free, so shared directly).
#[inline(always)]
fn tc_mss_clamp_inline(
    ctx: &TcContext,
    stats: StatsPtr,
    ip_offset: usize,
    is_v4: bool,
    egress_ifindex: u32,
    global_clamp: u16,
) {
    let start = ctx.data();
    let end = ctx.data_end();
    if is_v4 {
        if start + ip_offset + Ipv4Hdr::LEN > end {
            return;
        }
        let ip = (start + ip_offset) as *const Ipv4Hdr;
        if unsafe { (*ip).proto } != PROTO_TCP {
            return;
        }
        if !tcp_syn_flag_set(start, end, ip_offset + Ipv4Hdr::LEN) {
            return;
        }
        let clamp = crate::finalize::lookup_mss_clamp_v4(ip, egress_ifindex, global_clamp);
        if clamp == 0 {
            return;
        }
        mss_clamp_tcp(stats, start, end, ip as *const u8, Ipv4Hdr::LEN, clamp);
    } else {
        if start + ip_offset + Ipv6Hdr::LEN > end {
            return;
        }
        let ip = (start + ip_offset) as *const Ipv6Hdr;
        if unsafe { (*ip).next_hdr } != PROTO_TCP {
            return;
        }
        if !tcp_syn_flag_set(start, end, ip_offset + Ipv6Hdr::LEN) {
            return;
        }
        let clamp = crate::finalize::lookup_mss_clamp_v6(ip, egress_ifindex, global_clamp);
        if clamp == 0 {
            return;
        }
        mss_clamp_tcp(stats, start, end, ip as *const u8, Ipv6Hdr::LEN, clamp);
    }
}
