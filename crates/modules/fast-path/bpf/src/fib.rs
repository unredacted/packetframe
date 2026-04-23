//! Custom-FIB lookup path (Option F, Phase 1 Slice 1B).
//!
//! Replaces `bpf_fib_lookup()` with an LPM-trie lookup in `FIB_V4` /
//! `FIB_V6`, followed by a seqlock-aware read of `NEXTHOPS` (and for
//! ECMP, a bounded walk of `ECMP_GROUPS[i].nh_idx`). Gated on
//! `FP_CFG_FLAG_CUSTOM_FIB` by the caller in `main.rs`; this module
//! never runs when the operator is on `forwarding-mode kernel-fib`.
//!
//! **Verifier friendliness.** The ECMP walk is manually unrolled over
//! `MAX_ECMP_PATHS` (8) so the verifier sees a straight-line path. The
//! seqlock read is manually unrolled to 4 attempts for the same reason.
//! The hash function uses only wrapping u32 arithmetic + XOR +
//! rotate_left, which the verifier handles without complaint.
//!
//! **Hash determinism.** Every primitive here has a byte-for-byte
//! twin in `crates/modules/fast-path/src/fib/hash.rs`. The Phase 1
//! `fib_hash_vectors.rs` test runs both through identical inputs and
//! asserts agreement. If the two sides drift, the test fails before
//! any XDP packet is ever forwarded.

use aya_ebpf::maps::lpm_trie::Key;

use crate::maps::{
    bump_stat, EcmpGroup, FibValue, NexthopEntry, StatIdx, ECMP_GROUPS, FIB_KIND_ECMP,
    FIB_KIND_SINGLE, FIB_V4, FIB_V6, MAX_ECMP_PATHS, NEXTHOPS, NH_STATE_RESOLVED,
};

// --- Action codes -----------------------------------------------------
//
// Not using a Rust enum because the verifier handles integer match
// arms more predictably than enum discriminants with niche packing.
// Callers (main.rs) interpret these numerically.

pub const FIB_ACTION_MISS: u8 = 0;
pub const FIB_ACTION_FORWARD: u8 = 1;
pub const FIB_ACTION_NO_NEIGH: u8 = 2;
pub const FIB_ACTION_DROP: u8 = 3;

/// Result of a custom-FIB lookup. `action` is one of `FIB_ACTION_*`.
/// When `action == FIB_ACTION_FORWARD`, `egress_ifindex` / `smac` /
/// `dmac` carry the forwarding decision. Otherwise those fields are
/// undefined and the caller must not consult them.
#[derive(Copy, Clone)]
pub struct CustomFibResult {
    pub action: u8,
    pub egress_ifindex: u32,
    pub smac: [u8; 6],
    pub dmac: [u8; 6],
}

impl CustomFibResult {
    #[inline(always)]
    pub fn miss() -> Self {
        Self {
            action: FIB_ACTION_MISS,
            egress_ifindex: 0,
            smac: [0; 6],
            dmac: [0; 6],
        }
    }

    #[inline(always)]
    pub fn no_neigh() -> Self {
        Self {
            action: FIB_ACTION_NO_NEIGH,
            egress_ifindex: 0,
            smac: [0; 6],
            dmac: [0; 6],
        }
    }

    #[inline(always)]
    pub fn forward(egress_ifindex: u32, smac: [u8; 6], dmac: [u8; 6]) -> Self {
        Self {
            action: FIB_ACTION_FORWARD,
            egress_ifindex,
            smac,
            dmac,
        }
    }
}

// --- Top-level lookup -------------------------------------------------

/// IPv4 custom-FIB lookup. Caller passes the parsed src/dst/proto +
/// L4 ports from the packet. Returns a [`CustomFibResult`] the caller
/// feeds into the existing `dispatch_fib` success / miss paths in
/// `main.rs`.
///
/// `sport` / `dport` are **native-order u16** (host byte order). The
/// caller is responsible for byte-swapping from the BE-in-memory
/// representation that `l4_ports` returns for the kernel-FIB's
/// `__be16` contract. This keeps the hash byte-order-agnostic
/// between BPF and the userspace reference in `src/fib/hash.rs`.
#[inline(always)]
pub fn lookup_v4(
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    sport: u16,
    dport: u16,
) -> CustomFibResult {
    let key = Key::new(32, dst);
    let fib = match FIB_V4.get(&key) {
        Some(v) => *v,
        None => {
            bump_stat(StatIdx::CustomFibMiss);
            return CustomFibResult::miss();
        }
    };

    let nh_idx = match resolve_fib_value_v4(&fib, src, dst, proto, sport, dport) {
        Some(idx) => idx,
        None => {
            // ECMP walked every leg; none resolved.
            bump_stat(StatIdx::CustomFibNoNeigh);
            return CustomFibResult::no_neigh();
        }
    };

    match read_nexthop(nh_idx) {
        Some((ifindex, smac, dmac)) => {
            bump_stat(StatIdx::CustomFibHit);
            CustomFibResult::forward(ifindex, smac, dmac)
        }
        None => {
            bump_stat(StatIdx::CustomFibNoNeigh);
            CustomFibResult::no_neigh()
        }
    }
}

/// IPv6 custom-FIB lookup. See [`lookup_v4`] — same byte-order
/// contract on `sport` / `dport`.
#[inline(always)]
pub fn lookup_v6(
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
    sport: u16,
    dport: u16,
) -> CustomFibResult {
    let key = Key::new(128, dst);
    let fib = match FIB_V6.get(&key) {
        Some(v) => *v,
        None => {
            bump_stat(StatIdx::CustomFibMiss);
            return CustomFibResult::miss();
        }
    };

    let nh_idx = match resolve_fib_value_v6(&fib, src, dst, proto, sport, dport) {
        Some(idx) => idx,
        None => {
            bump_stat(StatIdx::CustomFibNoNeigh);
            return CustomFibResult::no_neigh();
        }
    };

    match read_nexthop(nh_idx) {
        Some((ifindex, smac, dmac)) => {
            bump_stat(StatIdx::CustomFibHit);
            CustomFibResult::forward(ifindex, smac, dmac)
        }
        None => {
            bump_stat(StatIdx::CustomFibNoNeigh);
            CustomFibResult::no_neigh()
        }
    }
}

// --- FibValue → NexthopId ---------------------------------------------

#[inline(always)]
fn resolve_fib_value_v4(
    fib: &FibValue,
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    sport: u16,
    dport: u16,
) -> Option<u32> {
    match fib.kind {
        FIB_KIND_SINGLE => Some(fib.idx),
        FIB_KIND_ECMP => {
            bump_stat(StatIdx::EcmpHashV4);
            let group = ECMP_GROUPS.get(fib.idx)?;
            let h = hash_v4(src, dst, proto, sport, dport, group.hash_mode);
            pick_ecmp_leg(group, h)
        }
        _ => None,
    }
}

#[inline(always)]
fn resolve_fib_value_v6(
    fib: &FibValue,
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
    sport: u16,
    dport: u16,
) -> Option<u32> {
    match fib.kind {
        FIB_KIND_SINGLE => Some(fib.idx),
        FIB_KIND_ECMP => {
            bump_stat(StatIdx::EcmpHashV6);
            let group = ECMP_GROUPS.get(fib.idx)?;
            let h = hash_v6(src, dst, proto, sport, dport, group.hash_mode);
            pick_ecmp_leg(group, h)
        }
        _ => None,
    }
}

/// ECMP walk. Starts at `hash % nh_count`, scans forward up to
/// `MAX_ECMP_PATHS`, picks the first slot whose `NEXTHOPS` entry is
/// `Resolved`. Fully unrolled by the Rust compiler because the loop
/// bound is a compile-time constant; the verifier sees a straight-line
/// walk.
///
/// If the starting slot is resolved, returns immediately (the common
/// case). If we walked past the starting slot, bump
/// `EcmpDeadLegFallback` — that's diagnostic signal that a leg is
/// down and we're compensating.
#[inline(always)]
fn pick_ecmp_leg(group: &EcmpGroup, hash: u32) -> Option<u32> {
    let nh_count = group.nh_count as u32;
    if nh_count == 0 {
        return None;
    }
    let start = hash % nh_count;

    let mut walked = 0u32;
    // Manually unrolled to MAX_ECMP_PATHS so the verifier budget is
    // bounded and predictable. The `if walked >= nh_count` guards
    // early-exit once we've examined every live slot.
    let mut i = 0usize;
    while i < MAX_ECMP_PATHS {
        if walked >= nh_count {
            break;
        }
        let slot = ((start + walked) % nh_count) as usize;
        // Bounds check on `slot` is the modulo above; verifier sees
        // `slot < MAX_ECMP_PATHS` because `nh_count <= MAX_ECMP_PATHS`
        // by construction (userspace invariant).
        if slot < MAX_ECMP_PATHS {
            let nh_idx = group.nh_idx[slot];
            if nh_idx != u32::MAX {
                if let Some(entry) = NEXTHOPS.get(nh_idx) {
                    if entry.state == NH_STATE_RESOLVED {
                        if walked > 0 {
                            bump_stat(StatIdx::EcmpDeadLegFallback);
                        }
                        return Some(nh_idx);
                    }
                }
            }
        }
        walked += 1;
        i += 1;
    }

    None
}

// --- Seqlock-aware nexthop read ---------------------------------------

/// Read `NEXTHOPS[idx]` under the seqlock discipline. Returns
/// `Some((ifindex, smac, dmac))` on a stable even-`seq` read with
/// `state == Resolved`, `None` otherwise.
///
/// **Bounded retry.** Up to 4 attempts, manually unrolled so the
/// verifier sees fixed instruction count. On every attempt:
/// 1. Read `seq_before` volatile. If odd, the writer is in progress;
///    skip to next attempt.
/// 2. Read the fields volatile.
/// 3. Read `seq_after` volatile. If it differs from `seq_before`,
///    the writer mutated mid-read; skip to next attempt.
/// 4. Check `state == NH_STATE_RESOLVED`. If so, return the tuple.
///
/// After 4 attempts, give up. Every retry bumps `NexthopSeqRetry` so
/// sustained-high values expose hot neighbor churn.
#[inline(always)]
fn read_nexthop(idx: u32) -> Option<(u32, [u8; 6], [u8; 6])> {
    let ptr = NEXTHOPS.get_ptr(idx)?;

    // Manual 4-retry unroll. Each block is identical; we could
    // express this as a macro but the verifier reads every instruction
    // so clarity > DRY here.

    if let Some(result) = try_read_seqlock(ptr) {
        return Some(result);
    }
    bump_stat(StatIdx::NexthopSeqRetry);
    if let Some(result) = try_read_seqlock(ptr) {
        return Some(result);
    }
    bump_stat(StatIdx::NexthopSeqRetry);
    if let Some(result) = try_read_seqlock(ptr) {
        return Some(result);
    }
    bump_stat(StatIdx::NexthopSeqRetry);
    if let Some(result) = try_read_seqlock(ptr) {
        return Some(result);
    }
    bump_stat(StatIdx::NexthopSeqRetry);

    bump_stat(StatIdx::NeighCacheMiss);
    None
}

/// One seqlock attempt. Extracted to its own inlined function so the
/// 4-retry unroll above reads cleanly.
#[inline(always)]
fn try_read_seqlock(ptr: *const NexthopEntry) -> Option<(u32, [u8; 6], [u8; 6])> {
    // SAFETY: `ptr` came from `NEXTHOPS.get_ptr(idx)` which bounds-
    // checked the index and returned a pointer into kernel map memory
    // valid for the duration of the program run. `read_volatile`
    // prevents the compiler from CSE'ing reads across the seq checks.
    unsafe {
        let seq_before = core::ptr::read_volatile(&(*ptr).seq);
        if seq_before & 1 != 0 {
            return None;
        }
        let state = core::ptr::read_volatile(&(*ptr).state);
        if state != NH_STATE_RESOLVED {
            return None;
        }
        let ifindex = core::ptr::read_volatile(&(*ptr).ifindex);
        let dmac = core::ptr::read_volatile(&(*ptr).dst_mac);
        let smac = core::ptr::read_volatile(&(*ptr).src_mac);
        let seq_after = core::ptr::read_volatile(&(*ptr).seq);
        if seq_after != seq_before {
            return None;
        }
        Some((ifindex, smac, dmac))
    }
}

// --- Hash (jhash variant) ---------------------------------------------
//
// **Mirror of `crates/modules/fast-path/src/fib/hash.rs`.** Byte-for-byte
// identical: every operation here must appear there. The Phase 1
// `fib_hash_vectors.rs` test runs both through identical inputs and
// asserts byte-for-byte agreement. Changes here require matching
// changes there (and vice versa).
//
// Own well-defined variant; **not** bit-for-bit kernel `fib_multipath_hash()`.
// See plan §"Hash (own, well-defined)" for rationale.

const JHASH_INITVAL: u32 = 0xdeadbeef;

/// Jenkins 3-word mix (the `__jhash_mix` primitive). Six rounds of
/// sub / xor / rot / add on three u32 lanes. Verifier-cost is 18
/// integer ops + register pressure for 3 live values — comfortably
/// under any realistic BPF instruction budget.
#[inline(always)]
fn jhash_mix(mut a: u32, mut b: u32, mut c: u32) -> (u32, u32, u32) {
    a = a.wrapping_sub(c);
    a ^= c.rotate_left(4);
    c = c.wrapping_add(b);
    b = b.wrapping_sub(a);
    b ^= a.rotate_left(6);
    a = a.wrapping_add(c);
    c = c.wrapping_sub(b);
    c ^= b.rotate_left(8);
    b = b.wrapping_add(a);
    a = a.wrapping_sub(c);
    a ^= c.rotate_left(16);
    c = c.wrapping_add(b);
    b = b.wrapping_sub(a);
    b ^= a.rotate_left(19);
    a = a.wrapping_add(c);
    c = c.wrapping_sub(b);
    c ^= b.rotate_left(4);
    b = b.wrapping_add(a);
    (a, b, c)
}

/// Jenkins final avalanche on three u32 lanes. Used to finalize the
/// hash so the bottom bits (which we take via `% nh_count`) see all
/// input bits, not just the last block mixed.
#[inline(always)]
fn jhash_final(mut a: u32, mut b: u32, mut c: u32) -> u32 {
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(24));
    c
}

/// Pack `(proto, sport, dport)` into a single u32 using the portion
/// of the hash input that depends on the mode.
///
/// - mode 3 (L3): just proto (ports omitted; distribution is src+dst+proto).
/// - mode 4: proto + sport high 24 bits (one port in the mix).
/// - mode 5 (L4): proto + sport + dport fully mixed.
///
/// Fragmented / ICMP / non-TCP-UDP callers pass `sport = dport = 0`,
/// which collapses mode 5 to effectively mode 3 for those packets —
/// no port bits to distinguish. The layer above (main.rs) is what
/// actually ensures the ports-zero case for non-L4 packets.
#[inline(always)]
fn pack_ports(proto: u8, sport: u16, dport: u16, mode: u8) -> u32 {
    let proto = proto as u32;
    match mode {
        3 => proto,
        4 => proto | ((sport as u32) << 8),
        5 => proto | ((sport as u32) << 8) | ((dport as u32) << 24),
        _ => proto, // unknown mode → fall back to 3-tuple
    }
}

/// IPv4 flow hash. `mode` is 3 / 4 / 5; any other value falls back to 3.
#[inline(always)]
pub fn hash_v4(
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    sport: u16,
    dport: u16,
    mode: u8,
) -> u32 {
    let a = u32::from_be_bytes(src).wrapping_add(JHASH_INITVAL);
    let b = u32::from_be_bytes(dst).wrapping_add(JHASH_INITVAL);
    let c = pack_ports(proto, sport, dport, mode).wrapping_add(JHASH_INITVAL);
    let (a, b, c) = jhash_mix(a, b, c);
    jhash_final(a, b, c)
}

/// IPv6 flow hash. Absorbs the 8 × u32 words of the v6 addresses
/// through three `jhash_mix` invocations before the final avalanche.
#[inline(always)]
pub fn hash_v6(
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
    sport: u16,
    dport: u16,
    mode: u8,
) -> u32 {
    let s0 = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    let s1 = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
    let s2 = u32::from_be_bytes([src[8], src[9], src[10], src[11]]);
    let s3 = u32::from_be_bytes([src[12], src[13], src[14], src[15]]);
    let d0 = u32::from_be_bytes([dst[0], dst[1], dst[2], dst[3]]);
    let d1 = u32::from_be_bytes([dst[4], dst[5], dst[6], dst[7]]);
    let d2 = u32::from_be_bytes([dst[8], dst[9], dst[10], dst[11]]);
    let d3 = u32::from_be_bytes([dst[12], dst[13], dst[14], dst[15]]);

    // Absorb src words.
    let (a, b, c) = jhash_mix(
        s0.wrapping_add(JHASH_INITVAL),
        s1.wrapping_add(JHASH_INITVAL),
        s2.wrapping_add(JHASH_INITVAL),
    );
    // Absorb s3 + first two dst words.
    let (a, b, c) = jhash_mix(a.wrapping_add(s3), b.wrapping_add(d0), c.wrapping_add(d1));
    // Absorb remaining dst + mode-packed ports.
    let (a, b, c) = jhash_mix(
        a.wrapping_add(d2),
        b.wrapping_add(d3),
        c.wrapping_add(pack_ports(proto, sport, dport, mode)),
    );
    jhash_final(a, b, c)
}
