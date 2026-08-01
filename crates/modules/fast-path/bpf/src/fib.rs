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

use crate::datapath::l4_ports;
use crate::maps::{
    bump, EcmpGroup, FibValue, NexthopEntry, StatIdx, StatsPtr, ECMP_GROUPS, FIB_CACHE_CFG,
    FIB_CACHE_V4, FIB_CACHE_V4_ENTRIES, FIB_CACHE_V6, FIB_CACHE_V6_ENTRIES, FIB_KIND_ECMP,
    FIB_KIND_SINGLE, FIB_V4, FIB_V6, MAX_ECMP_PATHS, NEXTHOPS, NH_STATE_RESOLVED,
};

// --- FIB destination cache probe ---------------------------------------

/// Current cache generation, or 0 when the cache is disabled (0 is a
/// reserved generation the programmer never issues, so "disabled" and
/// "no valid entry can match" collapse into one sentinel).
#[inline(always)]
fn cache_generation() -> u64 {
    match FIB_CACHE_CFG.get(0) {
        Some(cc) if cc.enabled != 0 => cc.generation,
        _ => 0,
    }
}

/// Fibonacci multiplicative hash → slot index. Two ALU ops. This hash
/// is BPF-internal only (cache entries never cross the BPF/userspace
/// boundary), so unlike the ECMP flow hash it deliberately has no
/// userspace mirror in `fib_hash_vectors.rs`.
#[inline(always)]
fn cache_slot(word: u32, entries: u32) -> u32 {
    (word.wrapping_mul(0x9E37_79B1) >> 16) & (entries - 1)
}

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

/// IPv4 custom-FIB lookup. Caller passes the parsed src/dst/proto plus
/// the packet bounds and L4 header offset; **port extraction is
/// deferred** into the ECMP arm (`resolve_fib_value_v4`), because ports
/// feed only the ECMP flow hash — on the single-nexthop path (the
/// common case on deployments with no ECMP groups) no port bytes are
/// read at all. `(start, end)` scalars rather than a ctx type keep the
/// whole module hook-agnostic (shared with the tc datapath, Phase T).
/// Returns a [`CustomFibResult`] the caller feeds into its own
/// dispatch verdict mapping.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn lookup_v4(
    stats: StatsPtr,
    start: usize,
    end: usize,
    l4_off: usize,
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
) -> CustomFibResult {
    // Destination-cache probe (gated; generation 0 = disabled). On a
    // hit the LPM walk is skipped entirely; the FibValue still resolves
    // through NEXTHOPS/ECMP_GROUPS below, so the seqlock read and the
    // per-flow ECMP hash are identical cached or not. Compare-mode
    // caveat: this lookup also serves the compare arm, so during the
    // microscopic window between a generation bump and the packet's
    // gen check, a just-invalidated entry can produce a spurious
    // CompareDisagree blip under BGP churn — compare is a temporary
    // validation mode; tolerated and documented.
    // Register-pressure note: only `cache_gen` + the 8-byte `fib` +
    // `cached` stay live across the LPM call. The dst word and slot
    // index are recomputed at the fill site rather than carried — the
    // first CI round carried them, LLVM spilled the v6 parse's L4
    // offset to make room, and the 5.15-ui verifier rejected the
    // NDP-gate byte read it restructured around the reload (see
    // datapath::icmpv6_type). Cheap ALU beats live registers here.
    let cache_gen = cache_generation();
    let mut fib = FibValue {
        kind: FIB_KIND_SINGLE,
        _pad: [0; 3],
        idx: 0,
    };
    let mut cached = false;
    if cache_gen != 0 {
        let dst_w = u32::from_ne_bytes(dst);
        if let Some(e) = FIB_CACHE_V4.get_ptr_mut(cache_slot(dst_w, FIB_CACHE_V4_ENTRIES)) {
            // SAFETY: bounds-checked map value pointer; per-CPU, and
            // XDP/tc programs run to completion on their CPU, so no
            // concurrent writer exists for this slot.
            unsafe {
                if (*e).dst == dst_w {
                    if (*e).generation == cache_gen {
                        bump(stats, StatIdx::FibCacheHit);
                        fib.kind = (*e).kind as u8;
                        fib.idx = (*e).idx;
                        cached = true;
                    } else {
                        bump(stats, StatIdx::FibCacheStale);
                    }
                } else {
                    bump(stats, StatIdx::FibCacheMiss);
                }
            }
        }
    }
    if !cached {
        let key = Key::new(32, dst);
        fib = match FIB_V4.get(&key) {
            Some(v) => *v,
            None => {
                // No negative caching: a stale "no route" entry is a
                // blackhole-shaped bug, and true misses are rare under
                // a full table.
                bump(stats, StatIdx::CustomFibMiss);
                return CustomFibResult::miss();
            }
        };
        if cache_gen != 0 {
            let dst_w = u32::from_ne_bytes(dst);
            if let Some(e) = FIB_CACHE_V4.get_ptr_mut(cache_slot(dst_w, FIB_CACHE_V4_ENTRIES)) {
                // Field-by-field stores (anti-memset discipline).
                // Ordering within the entry is irrelevant: the sole
                // reader is this CPU's own later invocations.
                unsafe {
                    (*e).dst = dst_w;
                    (*e).kind = fib.kind as u32;
                    (*e).idx = fib.idx;
                    (*e)._pad = 0;
                    (*e).generation = cache_gen;
                }
            }
        }
    }

    let nh_ptr = match resolve_fib_value_v4(stats, start, end, l4_off, &fib, src, dst, proto) {
        Some(p) => p,
        None => {
            // ECMP walked every leg and none resolved, or the single
            // nexthop index was out of range.
            bump(stats, StatIdx::CustomFibNoNeigh);
            return CustomFibResult::no_neigh();
        }
    };

    match read_nexthop_ptr(stats, nh_ptr) {
        Some((ifindex, smac, dmac)) => {
            bump(stats, StatIdx::CustomFibHit);
            CustomFibResult::forward(ifindex, smac, dmac)
        }
        None => {
            bump(stats, StatIdx::CustomFibNoNeigh);
            CustomFibResult::no_neigh()
        }
    }
}

/// IPv6 custom-FIB lookup. See [`lookup_v4`]; same deferred-port and
/// scalar-bounds contracts.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
pub fn lookup_v6(
    stats: StatsPtr,
    start: usize,
    end: usize,
    l4_off: usize,
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
) -> CustomFibResult {
    // Destination-cache probe; see the v4 twin for the full contract
    // and the register-pressure note (nothing but `cache_gen`, `fib`,
    // `cached` may live across the LPM call — the dst words and slot
    // are recomputed per block from `dst`, which is live regardless).
    let cache_gen = cache_generation();
    let mut fib = FibValue {
        kind: FIB_KIND_SINGLE,
        _pad: [0; 3],
        idx: 0,
    };
    let mut cached = false;
    if cache_gen != 0 {
        let d0 = u32::from_ne_bytes([dst[0], dst[1], dst[2], dst[3]]);
        let d1 = u32::from_ne_bytes([dst[4], dst[5], dst[6], dst[7]]);
        let d2 = u32::from_ne_bytes([dst[8], dst[9], dst[10], dst[11]]);
        let d3 = u32::from_ne_bytes([dst[12], dst[13], dst[14], dst[15]]);
        if let Some(e) =
            FIB_CACHE_V6.get_ptr_mut(cache_slot(d0 ^ d1 ^ d2 ^ d3, FIB_CACHE_V6_ENTRIES))
        {
            // SAFETY: as in the v4 twin.
            unsafe {
                if (*e).dst[0] == d0 && (*e).dst[1] == d1 && (*e).dst[2] == d2 && (*e).dst[3] == d3
                {
                    if (*e).generation == cache_gen {
                        bump(stats, StatIdx::FibCacheHit);
                        fib.kind = (*e).kind as u8;
                        fib.idx = (*e).idx;
                        cached = true;
                    } else {
                        bump(stats, StatIdx::FibCacheStale);
                    }
                } else {
                    bump(stats, StatIdx::FibCacheMiss);
                }
            }
        }
    }
    if !cached {
        let key = Key::new(128, dst);
        fib = match FIB_V6.get(&key) {
            Some(v) => *v,
            None => {
                bump(stats, StatIdx::CustomFibMiss);
                return CustomFibResult::miss();
            }
        };
        if cache_gen != 0 {
            let d0 = u32::from_ne_bytes([dst[0], dst[1], dst[2], dst[3]]);
            let d1 = u32::from_ne_bytes([dst[4], dst[5], dst[6], dst[7]]);
            let d2 = u32::from_ne_bytes([dst[8], dst[9], dst[10], dst[11]]);
            let d3 = u32::from_ne_bytes([dst[12], dst[13], dst[14], dst[15]]);
            if let Some(e) =
                FIB_CACHE_V6.get_ptr_mut(cache_slot(d0 ^ d1 ^ d2 ^ d3, FIB_CACHE_V6_ENTRIES))
            {
                // Field-by-field stores; see the v4 twin.
                unsafe {
                    (*e).dst[0] = d0;
                    (*e).dst[1] = d1;
                    (*e).dst[2] = d2;
                    (*e).dst[3] = d3;
                    (*e).kind = fib.kind as u32;
                    (*e).idx = fib.idx;
                    (*e).generation = cache_gen;
                }
            }
        }
    }

    let nh_ptr = match resolve_fib_value_v6(stats, start, end, l4_off, &fib, src, dst, proto) {
        Some(p) => p,
        None => {
            bump(stats, StatIdx::CustomFibNoNeigh);
            return CustomFibResult::no_neigh();
        }
    };

    match read_nexthop_ptr(stats, nh_ptr) {
        Some((ifindex, smac, dmac)) => {
            bump(stats, StatIdx::CustomFibHit);
            CustomFibResult::forward(ifindex, smac, dmac)
        }
        None => {
            bump(stats, StatIdx::CustomFibNoNeigh);
            CustomFibResult::no_neigh()
        }
    }
}

// --- FibValue → NexthopEntry pointer ------------------------------------

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn resolve_fib_value_v4(
    stats: StatsPtr,
    start: usize,
    end: usize,
    l4_off: usize,
    fib: &FibValue,
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
) -> Option<*const NexthopEntry> {
    match fib.kind {
        FIB_KIND_SINGLE => NEXTHOPS.get_ptr(fib.idx),
        FIB_KIND_ECMP => {
            bump(stats, StatIdx::EcmpHashV4);
            let group = ECMP_GROUPS.get(fib.idx)?;
            // Deferred port parse: only ECMP destinations hash on
            // ports. `l4_ports` returns BE-in-memory u16s (the
            // kernel-FIB `__be16` shape); the hash contract is
            // native-order, so swap here — same values the caller
            // used to compute, just only when actually needed.
            let (sport_be, dport_be) = l4_ports(start, end, l4_off, proto);
            let h = hash_v4(
                src,
                dst,
                proto,
                u16::from_be(sport_be),
                u16::from_be(dport_be),
                group.hash_mode,
            );
            pick_ecmp_leg(stats, group, h)
        }
        _ => None,
    }
}

#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn resolve_fib_value_v6(
    stats: StatsPtr,
    start: usize,
    end: usize,
    l4_off: usize,
    fib: &FibValue,
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
) -> Option<*const NexthopEntry> {
    match fib.kind {
        FIB_KIND_SINGLE => NEXTHOPS.get_ptr(fib.idx),
        FIB_KIND_ECMP => {
            bump(stats, StatIdx::EcmpHashV6);
            let group = ECMP_GROUPS.get(fib.idx)?;
            // See resolve_fib_value_v4 for the deferred-port rationale.
            let (sport_be, dport_be) = l4_ports(start, end, l4_off, proto);
            let h = hash_v6(
                src,
                dst,
                proto,
                u16::from_be(sport_be),
                u16::from_be(dport_be),
                group.hash_mode,
            );
            pick_ecmp_leg(stats, group, h)
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
/// Returns the entry *pointer* (from the walk's own `get_ptr`) so the
/// caller's seqlock read doesn't repeat the NEXTHOPS lookup — the walk
/// previously used `.get()` and the caller re-fetched by index, one
/// redundant map op per ECMP packet. The state peek here is a plain
/// racy read; the caller's seqlock discipline is what validates the
/// final tuple.
///
/// If the starting slot is resolved, returns immediately (the common
/// case). If we walked past the starting slot, bump
/// `EcmpDeadLegFallback`, that's diagnostic signal that a leg is
/// down and we're compensating.
#[inline(always)]
fn pick_ecmp_leg(stats: StatsPtr, group: &EcmpGroup, hash: u32) -> Option<*const NexthopEntry> {
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
                if let Some(ptr) = NEXTHOPS.get_ptr(nh_idx) {
                    let state = unsafe { core::ptr::read_volatile(&(*ptr).state) };
                    if state == NH_STATE_RESOLVED {
                        if walked > 0 {
                            bump(stats, StatIdx::EcmpDeadLegFallback);
                        }
                        return Some(ptr);
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

/// Seqlock attempt outcomes. Integer codes rather than an enum for
/// the same verifier-predictability reason as `FIB_ACTION_*`.
const SEQ_OK: u8 = 0;
/// Torn read: writer in progress (odd `seq`) or `seq` changed across
/// the field reads. Retrying can succeed.
const SEQ_RETRY: u8 = 1;
/// Stable read of an entry whose `state != Resolved`. This cannot
/// change within one program invocation — retrying is pointless.
const SEQ_NOT_RESOLVED: u8 = 2;

/// Read a `NEXTHOPS` entry under the seqlock discipline. Returns
/// `Some((ifindex, smac, dmac))` on a stable even-`seq` read with
/// `state == Resolved`, `None` otherwise.
///
/// **Bounded retry, torn reads only.** Up to 4 attempts, manually
/// unrolled so the verifier sees fixed instruction count. A stable
/// read of a not-Resolved entry short-circuits immediately: earlier
/// versions retried (and bumped `NexthopSeqRetry`) on that stable
/// condition too, which burned up to 3 extra attempts per packet on
/// unresolved nexthops and inflated the retry counter to ~4× the
/// `custom_fib_no_neigh` rate — masking the genuine-churn signal the
/// counter is documented to carry. `NexthopSeqRetry` now counts only
/// real torn reads; `NeighCacheMiss` still counts every failed read.
#[inline(always)]
fn read_nexthop_ptr(stats: StatsPtr, ptr: *const NexthopEntry) -> Option<(u32, [u8; 6], [u8; 6])> {
    let mut ifindex = 0u32;
    let mut smac = [0u8; 6];
    let mut dmac = [0u8; 6];

    // Manual 4-attempt unroll; each retry is taken only on SEQ_RETRY.
    let mut status = try_read_seqlock(ptr, &mut ifindex, &mut smac, &mut dmac);
    if status == SEQ_RETRY {
        bump(stats, StatIdx::NexthopSeqRetry);
        status = try_read_seqlock(ptr, &mut ifindex, &mut smac, &mut dmac);
    }
    if status == SEQ_RETRY {
        bump(stats, StatIdx::NexthopSeqRetry);
        status = try_read_seqlock(ptr, &mut ifindex, &mut smac, &mut dmac);
    }
    if status == SEQ_RETRY {
        bump(stats, StatIdx::NexthopSeqRetry);
        status = try_read_seqlock(ptr, &mut ifindex, &mut smac, &mut dmac);
    }
    if status == SEQ_RETRY {
        bump(stats, StatIdx::NexthopSeqRetry);
    }

    if status == SEQ_OK {
        return Some((ifindex, smac, dmac));
    }
    bump(stats, StatIdx::NeighCacheMiss);
    None
}

/// One seqlock attempt. Outputs travel through caller-stack out-params
/// (~16 bytes, well within budget) with a status-code return: the
/// historic `Option<(u32, [u8;6], [u8;6])>` shape is fine, but a
/// three-way outcome needs the RETRY/NOT_RESOLVED distinction and
/// nested enums with niche payloads are exactly what this codebase
/// avoids handing the verifier. Everything stays `#[inline(always)]`,
/// so no argument spill crosses a real call boundary.
#[inline(always)]
fn try_read_seqlock(
    ptr: *const NexthopEntry,
    out_ifindex: &mut u32,
    out_smac: &mut [u8; 6],
    out_dmac: &mut [u8; 6],
) -> u8 {
    // SAFETY: `ptr` came from `NEXTHOPS.get_ptr` which bounds-checked
    // the index and returned a pointer into kernel map memory valid
    // for the duration of the program run. `read_volatile` prevents
    // the compiler from CSE'ing reads across the seq checks.
    unsafe {
        let seq_before = core::ptr::read_volatile(&(*ptr).seq);
        if seq_before & 1 != 0 {
            return SEQ_RETRY;
        }
        let state = core::ptr::read_volatile(&(*ptr).state);
        let ifindex = core::ptr::read_volatile(&(*ptr).ifindex);
        let dmac = core::ptr::read_volatile(&(*ptr).dst_mac);
        let smac = core::ptr::read_volatile(&(*ptr).src_mac);
        let seq_after = core::ptr::read_volatile(&(*ptr).seq);
        if seq_after != seq_before {
            return SEQ_RETRY;
        }
        // Only a seq-stable read can classify the entry: an unstable
        // `state` byte could be mid-write.
        if state != NH_STATE_RESOLVED {
            return SEQ_NOT_RESOLVED;
        }
        *out_ifindex = ifindex;
        *out_smac = smac;
        *out_dmac = dmac;
        SEQ_OK
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
/// integer ops + register pressure for 3 live values, comfortably
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
/// which collapses mode 5 to effectively mode 3 for those packets
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
pub fn hash_v4(src: [u8; 4], dst: [u8; 4], proto: u8, sport: u16, dport: u16, mode: u8) -> u32 {
    let a = u32::from_be_bytes(src).wrapping_add(JHASH_INITVAL);
    let b = u32::from_be_bytes(dst).wrapping_add(JHASH_INITVAL);
    let c = pack_ports(proto, sport, dport, mode).wrapping_add(JHASH_INITVAL);
    let (a, b, c) = jhash_mix(a, b, c);
    jhash_final(a, b, c)
}

/// IPv6 flow hash. Absorbs the 8 × u32 words of the v6 addresses
/// through three `jhash_mix` invocations before the final avalanche.
#[inline(always)]
pub fn hash_v6(src: [u8; 16], dst: [u8; 16], proto: u8, sport: u16, dport: u16, mode: u8) -> u32 {
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
