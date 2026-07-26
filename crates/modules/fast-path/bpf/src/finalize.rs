//! Finalize stage: tail-called by `fast_path` after classification +
//! L2/TTL mutations. Owns mss-clamp lookup + mutation, VLAN choreography,
//! and the final `bpf_redirect_map` call.
//!
//! Lives in its own XDP program so it gets a fresh 512-byte BPF stack
//! budget. v0.2.4 inlined this work into `fast_path` and ran into UniFi
//! 5.15's stricter stack accounting (rejected at `combined stack size of
//! 3 calls is 544. Too large`). Splitting fixes the budget and provides
//! the pattern for future fast-path-internal stages.
//!
//! Communication from `fast_path` is via two side channels:
//! - The packet itself (preserved across `bpf_tail_call`).
//! - `MUTATION_CTX` per-CPU scratch (egress info, ingress VID, IP offset,
//!   v4/v6 discriminator), written by fast_path, read here.
//!
//! See SPEC.md §4.x "Two-stage BPF datapath" and
//! `docs/runbooks/tail-call-architecture.md`.

use aya_ebpf::{
    bindings::xdp_action, helpers::bpf_xdp_adjust_head, macros::xdp, maps::lpm_trie::Key,
    programs::XdpContext,
};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};

use crate::datapath::{mss_clamp_tcp, tcp_syn_flag_set};
use crate::maps::{
    bump, stats_base, StatIdx, StatsPtr, FP_CFG_FLAG_MSS_CLAMP_PRESENT, MSS_CLAMP_BY_IFACE,
    MSS_CLAMP_V4, MSS_CLAMP_V6, MUTATION_CTX, REDIRECT_DEVMAP,
};

/// 802.1Q TPID. Mirror of `main::TPID_8021Q`; kept local so finalize
/// is self-contained.
const TPID_8021Q: u16 = 0x8100;

/// Sentinel for "no VLAN", mirror of `main::VLAN_NONE`.
const VLAN_NONE: u16 = 0;

/// IANA TCP protocol number, materialized from `IpProto` (network-types
/// 0.2 changed `proto`/`next_hdr` to raw `u8`).
const PROTO_TCP: u8 = IpProto::Tcp as u8;

/// Upper bound on `ip_offset` post-VLAN-parse. Used to give the BPF
/// verifier a tight `umax` so range propagation through packet-pointer
/// arithmetic works, see commentary on the `ip_offset > MAX_IP_OFFSET`
/// check in `finalize`.
pub(crate) const MAX_IP_OFFSET: usize = 64;

#[xdp]
pub fn finalize(ctx: XdpContext) -> u32 {
    // Own STATS lookup: finalize is a separate program stage and the
    // pointer cannot cross the tail-call boundary. Fail open on the
    // unreachable None (index 0 of a 1-entry per-CPU array).
    let stats = match stats_base() {
        Some(s) => s,
        None => return xdp_action::XDP_PASS,
    };

    // Read the per-CPU mutation context written by fast_path right
    // before its tail_call. Always present in production; fail-safe
    // XDP_PASS if missing so traffic falls through to kernel rather
    // than getting dropped silently.
    let mctx = match unsafe { MUTATION_CTX.get(0) } {
        Some(c) => *c,
        None => {
            bump(stats, StatIdx::ErrMutationCtx);
            return xdp_action::XDP_PASS;
        }
    };

    let egress_ifindex = mctx.egress_ifindex;
    let egress_vid = mctx.egress_vid;
    let ingress_vid = mctx.ingress_vid;
    let is_v4 = mctx.is_v4 != 0;

    // Clamp ip_offset to MAX_IP_OFFSET (64). The BPF verifier's
    // `find_good_pkt_pointers` refuses to propagate range information
    // through packet-pointer arithmetic when the scalar offset's
    // umax_value exceeds MAX_PACKET_OFF (0xffff), which is the case
    // for `mctx.ip_offset` since it's read from a map and the verifier
    // sees its full u32 range. Capping the offset gives the verifier
    // a tight umax it can reason about, so the subsequent
    // `pkt + ip_offset + ip_hdr_size > end` bound check actually
    // propagates a usable readable-range back to `pkt + ip_offset`.
    //
    // In practice fast_path writes `EthHdr::LEN` (14) or
    // `EthHdr::LEN + VLAN_HDR_LEN` (18); 64 is comfortable headroom
    // for a future second VLAN tag without having to revisit this.
    let ip_offset = mctx.ip_offset as usize;
    if ip_offset > MAX_IP_OFFSET {
        // Previously an uncounted XDP_PASS — and by finalize time the
        // packet is already mutated (TTL, MACs), so this fail-open is
        // a half-mutated frame handed to the kernel. Unreachable while
        // fast_path writes only 14/18; count it so layout drift screams.
        bump(stats, StatIdx::ErrCtxOffsetRange);
        return xdp_action::XDP_PASS;
    }

    // mss-clamp first, then VLAN choreography (which can shift bytes
    // via bpf_xdp_adjust_head). mss-clamp's TCP-options walk relies on
    // ip_offset being valid relative to ctx.data(), true until VLAN
    // push/pop changes the layout.
    //
    // Gated on MSS_CLAMP_PRESENT (carried across the tail call in
    // mctx.cfg_flags): with no mss-clamp configured, the entire clamp
    // chain — previously 3 LPM/hash lookups + a CFG read for EVERY
    // forwarded TCP packet — costs one register test. The bit is set
    // whenever any clamp source exists, so gating can never skip a
    // configured clamp.
    if mctx.cfg_flags & u16::from(FP_CFG_FLAG_MSS_CLAMP_PRESENT) != 0 {
        mss_clamp_inline(
            &ctx,
            stats,
            ip_offset,
            is_v4,
            egress_ifindex,
            mctx.mss_clamp_global,
        );
    }

    if apply_vlan_egress(&ctx, ingress_vid, egress_vid).is_err() {
        bump(stats, StatIdx::ErrVlan);
        return xdp_action::XDP_ABORTED;
    }

    match REDIRECT_DEVMAP.redirect(egress_ifindex, 0) {
        Ok(_) => {
            bump(stats, StatIdx::FwdOk);
            xdp_action::XDP_REDIRECT
        }
        Err(_) => {
            // Devmap entry vanished between fast_path's pre-check and
            // here, or the kernel refused the redirect. Dedicated
            // counter (v0.2.8): this used to bump ErrFibOther, hiding
            // redirect-time failures inside the FIB-error bucket.
            bump(stats, StatIdx::ErrRedirectFailed);
            xdp_action::XDP_PASS
        }
    }
}

// --- MSS clamping (relocated from main.rs in v0.2.5) ----------------------

/// Top-level entry: dispatch into the v4 or v6 path with a constant-sized
/// bounds check. Splitting upfront (rather than threading `is_v4` through
/// a single function) is what satisfies the BPF verifier, the bounds
/// check needs to use a compile-time-known size so the verifier can
/// track that subsequent reads via `*const Ipv4Hdr` / `*const Ipv6Hdr`
/// stay within the checked region.
///
/// The ergonomic alternative, `let size = if is_v4 { 20 } else { 40 };
/// if start + offset + size > end { ... }; ip_addr as *const Ipv4Hdr`
/// loses the verifier's bound-tracking when the cast is reached: see
/// `R9 offset is outside of the packet` from the v0.2.5 prerelease build.
#[inline(always)]
fn mss_clamp_inline(
    ctx: &XdpContext,
    stats: StatsPtr,
    ip_offset: usize,
    is_v4: bool,
    egress_ifindex: u32,
    global_clamp: u16,
) {
    if is_v4 {
        mss_clamp_v4(ctx, stats, ip_offset, egress_ifindex, global_clamp);
    } else {
        mss_clamp_v6(ctx, stats, ip_offset, egress_ifindex, global_clamp);
    }
}

/// IPv4 path: bounds-check exactly `Ipv4Hdr::LEN` bytes, then cast
/// directly to `*const Ipv4Hdr`. Mirrors the `ptr_at` pattern from
/// main.rs that the verifier accepts.
#[inline(always)]
fn mss_clamp_v4(
    ctx: &XdpContext,
    stats: StatsPtr,
    ip_offset: usize,
    egress_ifindex: u32,
    global_clamp: u16,
) {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + ip_offset + Ipv4Hdr::LEN > end {
        return;
    }
    let ip: *const Ipv4Hdr = (start + ip_offset) as *const Ipv4Hdr;
    let proto = unsafe { (*ip).proto };
    if proto != PROTO_TCP {
        return;
    }
    // SYN hoist: clamp policy only ever applies to SYN/SYN-ACK, and
    // established-flow packets are the overwhelming bulk of TCP. Read
    // the flags byte (2-byte-cheap) BEFORE the up-to-three clamp map
    // lookups; pre-hoist, every established TCP packet paid all of
    // them just to bail at the same flag test inside mss_clamp_tcp.
    // No counter change: non-SYN packets never bumped anything.
    if !tcp_syn_flag_set(start, end, ip_offset + Ipv4Hdr::LEN) {
        return;
    }
    let clamp = lookup_mss_clamp_v4(ip, egress_ifindex, global_clamp);
    if clamp == 0 {
        return;
    }
    mss_clamp_tcp(stats, start, end, ip as *const u8, Ipv4Hdr::LEN, clamp);
}

/// IPv6 path: same pattern as `mss_clamp_v4` but with a 40-byte bound.
#[inline(always)]
fn mss_clamp_v6(
    ctx: &XdpContext,
    stats: StatsPtr,
    ip_offset: usize,
    egress_ifindex: u32,
    global_clamp: u16,
) {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + ip_offset + Ipv6Hdr::LEN > end {
        return;
    }
    let ip: *const Ipv6Hdr = (start + ip_offset) as *const Ipv6Hdr;
    let proto = unsafe { (*ip).next_hdr };
    if proto != PROTO_TCP {
        return;
    }
    // SYN hoist; see mss_clamp_v4.
    if !tcp_syn_flag_set(start, end, ip_offset + Ipv6Hdr::LEN) {
        return;
    }
    let clamp = lookup_mss_clamp_v6(ip, egress_ifindex, global_clamp);
    if clamp == 0 {
        return;
    }
    mss_clamp_tcp(stats, start, end, ip as *const u8, Ipv6Hdr::LEN, clamp);
}

#[inline(always)]
pub(crate) fn lookup_mss_clamp_v4(
    ip: *const Ipv4Hdr,
    egress_ifindex: u32,
    global_clamp: u16,
) -> u16 {
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
    // Global fallback from MutationCtx (fast_path's single CFG read);
    // finalize no longer touches the CFG map. Precedence order among
    // the four sources (prefix-src, prefix-dst, iface, global) is
    // unchanged per SPEC.
    global_clamp
}

#[inline(always)]
pub(crate) fn lookup_mss_clamp_v6(
    ip: *const Ipv6Hdr,
    egress_ifindex: u32,
    global_clamp: u16,
) -> u16 {
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
    // See lookup_mss_clamp_v4: global fallback rides in MutationCtx.
    global_clamp
}

// --- VLAN choreography (relocated from main.rs in v0.2.5) -----------------

/// SPEC §4.7's four-case VLAN matrix, keyed on VLAN_NONE-sentinel u16s
/// rather than `Option<u16>` (the verifier rejects the Option-argument
/// spill across a function boundary).
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
/// 4 bytes, writes TPID + TCI into the freed-up slot.
///
/// Uses **manual byte-by-byte read-then-write** rather than
/// `core::ptr::copy` (memmove). LLVM lowers `core::ptr::copy` into the
/// `@llvm.memmove.*` intrinsic, which the BPF backend emits as a
/// separate bpf-to-bpf `memmove` subprogram. fast_path uses
/// `bpf_tail_call`, and on UniFi 5.15-ui-cn9670 (and any kernel where
/// `bpf_jit_supports_subprog_tailcalls()` returns false) the verifier
/// rejects programs that combine tail-calls with bpf-to-bpf calls.
/// Reading all 12 source bytes into local variables before any store
/// also handles the source/destination overlap that `core::ptr::copy`
/// (memmove) handles for us, without the libcall.
#[inline(always)]
fn vlan_push(ctx: &XdpContext, vid: u16) -> Result<(), ()> {
    let rc = unsafe { bpf_xdp_adjust_head(ctx.ctx as *mut _, -4) };
    if rc != 0 {
        return Err(());
    }
    let start = ctx.data();
    let end = ctx.data_end();
    if start + 18 > end {
        return Err(());
    }
    unsafe {
        let base = start as *mut u8;
        // Read all 12 source bytes (offsets 4..16, the original MAC
        // pair, now shifted right by 4 from adjust_head) before writing
        // anything. Then write to offsets 0..12. No overlap concern
        // source and dest don't co-exist in memory at the same time.
        let m0 = *base.add(4);
        let m1 = *base.add(5);
        let m2 = *base.add(6);
        let m3 = *base.add(7);
        let m4 = *base.add(8);
        let m5 = *base.add(9);
        let m6 = *base.add(10);
        let m7 = *base.add(11);
        let m8 = *base.add(12);
        let m9 = *base.add(13);
        let m10 = *base.add(14);
        let m11 = *base.add(15);
        *base = m0;
        *base.add(1) = m1;
        *base.add(2) = m2;
        *base.add(3) = m3;
        *base.add(4) = m4;
        *base.add(5) = m5;
        *base.add(6) = m6;
        *base.add(7) = m7;
        *base.add(8) = m8;
        *base.add(9) = m9;
        *base.add(10) = m10;
        *base.add(11) = m11;
        let tpid = TPID_8021Q.to_be_bytes();
        *base.add(12) = tpid[0];
        *base.add(13) = tpid[1];
        let tci = (vid & 0x0fff).to_be_bytes();
        *base.add(14) = tci[0];
        *base.add(15) = tci[1];
    }
    Ok(())
}

/// Tagged → untagged. Shifts the MAC pair right by 4 over the about-to-
/// be-discarded TPID+TCI slot, then shrinks headroom by 4. Same
/// byte-by-byte pattern as `vlan_push`, see commentary there for the
/// `core::ptr::copy` libcall avoidance rationale.
#[inline(always)]
fn vlan_pop(ctx: &XdpContext) -> Result<(), ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + 18 > end {
        return Err(());
    }
    unsafe {
        let base = start as *mut u8;
        // Read all 12 source bytes (offsets 0..12, the MAC pair before
        // the 4-byte VLAN tag at offsets 12..16) before writing.
        let m0 = *base;
        let m1 = *base.add(1);
        let m2 = *base.add(2);
        let m3 = *base.add(3);
        let m4 = *base.add(4);
        let m5 = *base.add(5);
        let m6 = *base.add(6);
        let m7 = *base.add(7);
        let m8 = *base.add(8);
        let m9 = *base.add(9);
        let m10 = *base.add(10);
        let m11 = *base.add(11);
        // Write at offsets 4..16; the 4 bytes at offsets 0..4 are about
        // to be reclaimed by adjust_head.
        *base.add(4) = m0;
        *base.add(5) = m1;
        *base.add(6) = m2;
        *base.add(7) = m3;
        *base.add(8) = m4;
        *base.add(9) = m5;
        *base.add(10) = m6;
        *base.add(11) = m7;
        *base.add(12) = m8;
        *base.add(13) = m9;
        *base.add(14) = m10;
        *base.add(15) = m11;
    }
    let rc = unsafe { bpf_xdp_adjust_head(ctx.ctx as *mut _, 4) };
    if rc != 0 {
        return Err(());
    }
    Ok(())
}

/// Tagged VID X → tagged VID Y. No headroom change; overwrite TCI in place.
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
