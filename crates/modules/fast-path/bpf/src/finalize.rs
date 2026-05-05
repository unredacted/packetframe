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
//!   v4/v6 discriminator) — written by fast_path, read here.
//!
//! See SPEC.md §4.x "Two-stage BPF datapath" and
//! `docs/runbooks/tail-call-architecture.md`.

use aya_ebpf::{
    bindings::xdp_action,
    helpers::gen::bpf_xdp_adjust_head,
    macros::xdp,
    maps::lpm_trie::Key,
    programs::XdpContext,
};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};

use crate::maps::{
    bump_stat, StatIdx, CFG, MSS_CLAMP_BY_IFACE, MSS_CLAMP_V4, MSS_CLAMP_V6, MUTATION_CTX,
    REDIRECT_DEVMAP,
};

/// 802.1Q TPID. Mirror of `main::TPID_8021Q`; kept local so finalize
/// is self-contained.
const TPID_8021Q: u16 = 0x8100;

/// Sentinel for "no VLAN" — mirror of `main::VLAN_NONE`.
const VLAN_NONE: u16 = 0;

/// SYN flag in TCP byte 13.
const TCP_FLAG_SYN: u8 = 0x02;

/// IANA TCP protocol number, materialized from `IpProto` (network-types
/// 0.2 changed `proto`/`next_hdr` to raw `u8`).
const PROTO_TCP: u8 = IpProto::Tcp as u8;

/// Upper bound on `ip_offset` post-VLAN-parse. Used to give the BPF
/// verifier a tight `umax` so range propagation through packet-pointer
/// arithmetic works — see commentary on the `ip_offset > MAX_IP_OFFSET`
/// check in `finalize`.
const MAX_IP_OFFSET: usize = 64;

#[xdp]
pub fn finalize(ctx: XdpContext) -> u32 {
    // Read the per-CPU mutation context written by fast_path right
    // before its tail_call. Always present in production; fail-safe
    // XDP_PASS if missing so traffic falls through to kernel rather
    // than getting dropped silently.
    let mctx = match unsafe { MUTATION_CTX.get(0) } {
        Some(c) => *c,
        None => {
            bump_stat(StatIdx::ErrMutationCtx);
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
    // umax_value exceeds MAX_PACKET_OFF (0xffff) — which is the case
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
        return xdp_action::XDP_PASS;
    }

    // mss-clamp first, then VLAN choreography (which can shift bytes
    // via bpf_xdp_adjust_head). mss-clamp's TCP-options walk relies on
    // ip_offset being valid relative to ctx.data() — true until VLAN
    // push/pop changes the layout.
    mss_clamp_inline(&ctx, ip_offset, is_v4, egress_ifindex);

    if apply_vlan_egress(&ctx, ingress_vid, egress_vid).is_err() {
        bump_stat(StatIdx::ErrVlan);
        return xdp_action::XDP_ABORTED;
    }

    match REDIRECT_DEVMAP.redirect(egress_ifindex, 0) {
        Ok(_) => {
            bump_stat(StatIdx::FwdOk);
            xdp_action::XDP_REDIRECT
        }
        Err(_) => {
            bump_stat(StatIdx::ErrFibOther);
            xdp_action::XDP_PASS
        }
    }
}

// --- MSS clamping (relocated from main.rs in v0.2.5) ----------------------

/// Top-level entry: dispatch into the v4 or v6 path with a constant-sized
/// bounds check. Splitting upfront (rather than threading `is_v4` through
/// a single function) is what satisfies the BPF verifier — the bounds
/// check needs to use a compile-time-known size so the verifier can
/// track that subsequent reads via `*const Ipv4Hdr` / `*const Ipv6Hdr`
/// stay within the checked region.
///
/// The ergonomic alternative — `let size = if is_v4 { 20 } else { 40 };
/// if start + offset + size > end { ... }; ip_addr as *const Ipv4Hdr` —
/// loses the verifier's bound-tracking when the cast is reached: see
/// `R9 offset is outside of the packet` from the v0.2.5 prerelease build.
#[inline(always)]
fn mss_clamp_inline(ctx: &XdpContext, ip_offset: usize, is_v4: bool, egress_ifindex: u32) {
    if is_v4 {
        mss_clamp_v4(ctx, ip_offset, egress_ifindex);
    } else {
        mss_clamp_v6(ctx, ip_offset, egress_ifindex);
    }
}

/// IPv4 path: bounds-check exactly `Ipv4Hdr::LEN` bytes, then cast
/// directly to `*const Ipv4Hdr`. Mirrors the `ptr_at` pattern from
/// main.rs that the verifier accepts.
#[inline(always)]
fn mss_clamp_v4(ctx: &XdpContext, ip_offset: usize, egress_ifindex: u32) {
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
    let clamp = lookup_mss_clamp_v4(ip, egress_ifindex);
    if clamp == 0 {
        return;
    }
    mss_clamp_tcp(ctx, ip_offset + Ipv4Hdr::LEN, clamp);
}

/// IPv6 path: same pattern as `mss_clamp_v4` but with a 40-byte bound.
#[inline(always)]
fn mss_clamp_v6(ctx: &XdpContext, ip_offset: usize, egress_ifindex: u32) {
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
    let clamp = lookup_mss_clamp_v6(ip, egress_ifindex);
    if clamp == 0 {
        return;
    }
    mss_clamp_tcp(ctx, ip_offset + Ipv6Hdr::LEN, clamp);
}

/// Walk the TCP-options block of a matched SYN/SYN-ACK and mutate the MSS
/// option in place if the existing MSS is greater than the clamp value.
/// Recomputes the TCP checksum incrementally (RFC 1624). Bumps
/// `MssClampApplied` on rewrite, `MssClampSkipped` on "policy applies but
/// no rewrite needed."
///
/// Bounds-checked at every read against `ctx.data_end()`. Options walk
/// is fixed-bound at 8 iterations to keep BPF verifier state-space
/// exploration tractable (a 40-iteration walk hit the verifier's
/// 1M-instruction limit during v0.2.4 development).
#[inline(always)]
fn mss_clamp_tcp(ctx: &XdpContext, tcp_offset: usize, clamp: u16) {
    let start = ctx.data();
    let end = ctx.data_end();

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
        bump_stat(StatIdx::MssClampSkipped);
        return;
    }
    if start + tcp_offset + tcp_hdr_len > end {
        return;
    }

    // Walk options. Cap at 8 — real SYN packets put MSS in the first
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
                bump_stat(StatIdx::MssClampApplied);
            } else {
                bump_stat(StatIdx::MssClampSkipped);
            }
            found = true;
            break;
        }
        cursor += length;
    }

    if !found {
        bump_stat(StatIdx::MssClampSkipped);
    }
}

#[inline(always)]
fn csum_replace_u16(old_csum: u16, old_val: u16, new_val: u16) -> u16 {
    let mut sum: u32 = (!old_csum) as u32 + (!old_val) as u32 + new_val as u32;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

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
/// 4 bytes, writes TPID + TCI into the freed-up slot. Uses
/// `core::ptr::copy` (memmove) not `copy_nonoverlapping` because source
/// and destination overlap — SPEC calls this out as a footgun.
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
        core::ptr::copy(base.add(4), base, 6);
        core::ptr::copy(base.add(10), base.add(6), 6);
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
/// be-discarded TPID+TCI slot, then shrinks headroom by 4.
#[inline(always)]
fn vlan_pop(ctx: &XdpContext) -> Result<(), ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + 18 > end {
        return Err(());
    }
    unsafe {
        let base = start as *mut u8;
        core::ptr::copy(base.add(6), base.add(10), 6);
        core::ptr::copy(base, base.add(4), 6);
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
