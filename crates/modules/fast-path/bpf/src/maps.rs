//! §4.5 maps + typed value structs.
//!
//! `vlan_resolve` is deliberately deferred to PR #5 (VLAN choreography).
//! All other §4.5 maps live here; values that cross the userspace/BPF
//! boundary are `#[repr(C)]` and documented. When PR #4 introduces the
//! userspace loader it will duplicate `FpCfg` / `StatIdx` with a
//! `size_of`-asserting test to catch layout drift.

use aya_ebpf::{
    macros::map,
    maps::{Array, DevMapHash, HashMap, LpmTrie, PerCpuArray, RingBuf},
};

/// Runtime flags poked by userspace via the `cfg` map. `version` is a
/// reserved byte carved out now so future fields can be added without
/// breaking userspace reads of older-layout BPF objects (SPEC §4.5 note:
/// the `fp_cfg` struct has `...` — we enumerate exactly the v0.1 fields
/// plus a version discriminator).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FpCfg {
    /// 0 = off, 1 = on. All other bits reserved.
    pub dry_run: u8,
    /// Bit 0 = IPv4 enabled, bit 1 = IPv6 enabled. 0 disables both
    /// (pure dry-run passthrough). Reserved bits must be zero.
    pub flags: u8,
    pub _reserved: [u8; 2],
    /// Layout version. `0` = v0.1 layout (this file). Userspace rejects
    /// loads if this doesn't match what it expects.
    pub version: u32,
}

impl FpCfg {
    pub const VERSION_V1: u32 = 0;

    pub const fn zeroed() -> Self {
        Self {
            dry_run: 0,
            flags: 0b11,
            _reserved: [0; 2],
            version: Self::VERSION_V1,
        }
    }
}

/// §4.6 counters. Discriminants are wire format — they are **append-only**
/// once v0.1 ships, since operator dashboards consume them by index. Do
/// not renumber; add new counters to the end.
#[repr(u32)]
#[derive(Copy, Clone)]
pub enum StatIdx {
    RxTotal = 0,
    MatchedV4 = 1,
    MatchedV6 = 2,
    MatchedSrcOnly = 3,
    MatchedDstOnly = 4,
    MatchedBoth = 5,
    FwdOk = 6,
    FwdDryRun = 7,
    PassFragment = 8,
    PassLowTtl = 9,
    PassNoNeigh = 10,
    PassNotIp = 11,
    PassFragNeeded = 12,
    DropUnreachable = 13,
    ErrParse = 14,
    ErrFibOther = 15,
    ErrVlan = 16,
    PassNotInDevmap = 17,
    PassComplexHeader = 18,
    /// `bpf_xdp_adjust_head` or `bpf_xdp_adjust_tail` failed while
    /// applying the `FP_CFG_FLAG_HEAD_SHIFT_128` workaround (SPEC
    /// §11.1(c)). Typically means the ingress frame is smaller than
    /// the 128-byte shift — e.g. a 64-byte TCP ACK on a buggy-kernel
    /// rvu-nicpf iface, which the workaround can't expose in full
    /// because the driver's `data_end` is 128 bytes short. The packet
    /// returns `XDP_PASS` unmodified; the counter tells operators how
    /// many frames the fast path couldn't touch because of this.
    ErrHeadShift = 19,
    // --- Custom FIB additions (Option F, Phase 1). Append-only. ---
    /// Custom-FIB lookup returned a forward decision for the packet
    /// (LPM hit → resolved nexthop → redirect).
    CustomFibHit = 20,
    /// Custom-FIB lookup missed the LPM trie. No route for this
    /// destination in our map.
    CustomFibMiss = 21,
    /// Custom-FIB lookup hit a route but the resolved nexthop's
    /// state is not `Resolved` (incomplete/stale/failed). Packet
    /// falls to `XDP_PASS` so the kernel can attempt ARP/ND.
    CustomFibNoNeigh = 22,
    /// Compare mode: custom-FIB and kernel-FIB decisions agreed on
    /// `(egress_ifindex, dst_mac)`. Forward path is kernel result.
    CompareAgree = 23,
    /// Compare mode: custom-FIB and kernel-FIB decisions differed.
    /// Forward path is kernel result; disagreement is diagnostic.
    CompareDisagree = 24,
    /// ECMP group dispatch bumped for every IPv4 packet that hit an
    /// ECMP group in custom-FIB (distribution visibility).
    EcmpHashV4 = 25,
    EcmpHashV6 = 26,
    /// ECMP hash selected a dead-leg nexthop; we walked to a live one.
    /// Sustained nonzero indicates nexthop resolution churn.
    EcmpDeadLegFallback = 27,
    /// RouteSource full-resync events (BMP reconnect, `InitiationComplete`
    /// garbage-collect). Userspace-driven; BPF never bumps this.
    RouteSourceResync = 28,
    /// XDP read `NEXTHOPS[idx]` but the entry's state was invalid or
    /// the LPM trie pointed at an out-of-range index. Diagnostic.
    NeighCacheMiss = 29,
    /// Seqlock retry on a `NexthopEntry` read observed a write in
    /// progress (odd `seq` or `seq_before != seq_after`). Sustained
    /// nonzero rate indicates hot neighbor churn.
    NexthopSeqRetry = 30,
    /// BMP station observed a `PEER DOWN` message from bird and the
    /// RouteSource emitted a `PeerDown` event. Userspace-driven.
    BmpPeerDown = 31,
    /// v0.2.1 issue #33: matched packet whose destination fell in
    /// a `block-prefix <cidr>` LPM trie. Program returned `XDP_DROP`.
    /// Diagnostic counter so operators can see which/how many flows
    /// the bogon-block is catching.
    BogonDropped = 32,
}

/// Total counter count. Used as `stats` map `max_entries`. New counters
/// bump this; dashboards keying on indices keep working.
pub const STATS_COUNT: u32 = 33;

/// Flag bits for `FpCfg.flags`. Bits 0-1 are the IPv4/IPv6 enable
/// mask (historical, load-bearing for dashboards). Bit 2 is the
/// rvu-nicpf head-shift workaround (SPEC §11.1(c)). Bits 3-4 gate
/// the custom-FIB lookup path (Option F); see `crates/modules/fast-path/src/fib/`.
/// Higher bits reserved for future per-iface or per-driver quirks.
pub const FP_CFG_FLAG_IPV4: u8 = 0b0000_0001;
pub const FP_CFG_FLAG_IPV6: u8 = 0b0000_0010;
pub const FP_CFG_FLAG_HEAD_SHIFT_128: u8 = 0b0000_0100;
/// Enable the custom-FIB lookup path in place of `bpf_fib_lookup()`.
/// The XDP program consults `FIB_V4` / `FIB_V6` LPM tries and the
/// `NEXTHOPS` array instead of calling into the kernel FIB. Set by
/// userspace when `forwarding-mode custom-fib` or `compare` is
/// configured.
pub const FP_CFG_FLAG_CUSTOM_FIB: u8 = 0b0000_1000;
/// Compare-mode: run both the custom-FIB and kernel-FIB lookups,
/// forward via the kernel result, bump `CompareAgree`/`CompareDisagree`
/// based on whether `(egress_ifindex, dst_mac)` matches. Implies
/// `FP_CFG_FLAG_CUSTOM_FIB`; userspace rejects compare-mode without
/// it. Temporary validation mode; removed in Phase 5.
pub const FP_CFG_FLAG_COMPARE_MODE: u8 = 0b0001_0000;

/// Max prefixes per allowlist trie. Sized generously: SPEC.md §4.5
/// scales to /24-range tries comfortably. `1024` entries covers the
/// reference EFG's single /24 plus headroom for future prefix growth.
const ALLOWLIST_MAX_ENTRIES: u32 = 1024;

/// Max simultaneous redirect targets. Ifindex-keyed, so sized to cover
/// a host's interface count plus transient veth/tunnel churn. `64` is
/// comfortable for any non-container deployment.
const REDIRECT_DEVMAP_MAX_ENTRIES: u32 = 64;

/// Ringbuf size in bytes. Must be a power of two and a multiple of page
/// size; 256 KiB works across 4 KiB and 16 KiB page hosts (some ARM).
const LOG_RINGBUF_BYTES: u32 = 256 * 1024;

/// Max VLAN-subif entries. The reference EFG's agg-switch trunk carries
/// VIDs 1/66/88/99/1337 + 3996..4040 — ~50. 256 is headroom.
const VLAN_RESOLVE_MAX_ENTRIES: u32 = 256;

// --- Custom-FIB map sizes (Option F) -----------------------------------
//
// Sized to accommodate the full IPv4 + IPv6 BGP tables plus headroom.
// Kernel allocates at load time regardless of whether `forwarding-mode
// custom-fib` is selected — the maps live in the same ELF. Approximate
// memory cost at defaults: ~50-80 MB v4 + ~40-50 MB v6 + small NH + ECMP.
// Changing `max_entries` requires an ELF rebuild (aya/kernel limitation);
// config-level `fib-v4-max-entries` directives are accepted but documented
// as "rebuild required" in Phase 1.
//
// Phase 1 keeps these empty — the BPF program never reads them while
// `FP_CFG_FLAG_CUSTOM_FIB` is clear, so the allocation is all the load
// cost. Phase 3's FibProgrammer populates them.

/// Max IPv4 prefixes in the custom FIB. 2²¹ = 2 097 152; covers the
/// full DFZ v4 table (~1.2M as of 2026) with substantial headroom.
const FIB_V4_MAX_ENTRIES: u32 = 2_097_152;

/// Max IPv6 prefixes in the custom FIB. 2²⁰ = 1 048 576; covers the
/// full DFZ v6 table (~230K) with substantial headroom.
const FIB_V6_MAX_ENTRIES: u32 = 1_048_576;

/// Max distinct nexthops. 180K BGP routes typically share a small set
/// of nexthops (one per peer), so 8 192 is ample for any realistic
/// multi-transit + multi-IX topology.
const NEXTHOPS_MAX_ENTRIES: u32 = 8_192;

/// Max ECMP groups. Each group is a deduplicated tuple of nexthop IDs
/// + hash mode; 1 024 covers fan-out well beyond current deployments.
const ECMP_GROUPS_MAX_ENTRIES: u32 = 1_024;

/// Value stored in `vlan_resolve`. Maps an egress VLAN-subif ifindex
/// (the key) to its physical parent + VID so the BPF program can
/// (a) redirect to the physical port and (b) push the right tag.
/// `#[repr(C)]` with explicit 2-byte pad so userspace layout matches.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct VlanResolve {
    pub phys_ifindex: u32,
    pub vid: u16,
    pub _pad: u16,
}

// --- Custom FIB value layouts (Option F) -------------------------------

/// Max nexthops in a single ECMP group. The XDP program walks `nh_idx`
/// starting at `hash % nh_count` to find a resolved leg; unrolling
/// must fit the verifier's path budget. 8 is generous for typical
/// multi-path scenarios (anycast DNS, multi-transit) and keeps the
/// unrolled walk small.
pub const MAX_ECMP_PATHS: usize = 8;

/// `FibValue.kind` discriminant: single-nexthop route.
pub const FIB_KIND_SINGLE: u8 = 0;
/// `FibValue.kind` discriminant: ECMP group reference.
pub const FIB_KIND_ECMP: u8 = 1;

/// Value stored in `FIB_V4` / `FIB_V6` LPM tries. Points at either
/// a single nexthop (`NEXTHOPS[idx]`) or an ECMP group
/// (`ECMP_GROUPS[idx]`). 8 bytes — single aligned write from
/// userspace is torn-read-free.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FibValue {
    /// `FIB_KIND_SINGLE` or `FIB_KIND_ECMP`.
    pub kind: u8,
    pub _pad: [u8; 3],
    /// Index into `NEXTHOPS` (kind=Single) or `ECMP_GROUPS` (kind=Ecmp).
    pub idx: u32,
}

/// `NexthopEntry.state` discriminants.
pub const NH_STATE_INCOMPLETE: u8 = 0;
pub const NH_STATE_RESOLVED: u8 = 1;
pub const NH_STATE_STALE: u8 = 2;
pub const NH_STATE_FAILED: u8 = 3;

/// `NexthopEntry.family` discriminants.
pub const NH_FAMILY_V4: u8 = 4;
pub const NH_FAMILY_V6: u8 = 6;

/// Seqlock-protected nexthop record. 28 bytes, `#[repr(C)]` with
/// explicit padding so the layout matches userspace byte-for-byte.
/// Writer (userspace) flips `seq` odd, writes the rest, flips `seq`
/// to `(odd+1)` even. Reader (XDP) reads `seq` before + after the
/// field reads; mismatch or odd-value retries up to 4 times, then
/// returns `NoNeigh` (treat as incomplete). Bounded retry keeps
/// the verifier happy.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct NexthopEntry {
    /// Sequence counter. Even = stable, odd = write in progress.
    /// Writer: `seq |= 1`, fence, write fields, fence, `seq = (seq | 1) + 1`.
    pub seq: u32,
    /// Egress interface ifindex. For VLAN-subif nexthops the XDP
    /// redirect-path still consults `VLAN_RESOLVE` to swap this for
    /// the phys parent + push the recorded VID (SPEC §4.7).
    pub ifindex: u32,
    /// Destination MAC (nexthop's MAC).
    pub dst_mac: [u8; 6],
    pub _pad0: [u8; 2],
    /// Source MAC (egress iface MAC).
    pub src_mac: [u8; 6],
    pub _pad1: [u8; 2],
    /// One of `NH_STATE_*`.
    pub state: u8,
    /// One of `NH_FAMILY_V4` / `NH_FAMILY_V6`.
    pub family: u8,
    /// Optional per-peer identifier used by the BMP RouteSource for
    /// scoped withdrawals. Zero means "unset." XDP does not consult
    /// this; it's userspace bookkeeping stored alongside the entry
    /// for diagnostic clarity.
    pub bmp_peer_hint: [u8; 2],
}

/// ECMP group: a set of `NEXTHOPS` indices with a per-group hash
/// policy. Unused slots in `nh_idx` are `u32::MAX`. 36 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct EcmpGroup {
    /// `3`, `4`, or `5` — the tuple width the XDP program hashes on
    /// for this group. 3 = (src IP, dst IP, proto); 4 = + one port;
    /// 5 = + src port + dst port. Non-TCP/UDP + ICMP + fragments
    /// fall back to 3 regardless.
    pub hash_mode: u8,
    /// Number of live entries in `nh_idx` (1..=MAX_ECMP_PATHS).
    pub nh_count: u8,
    pub _pad: [u8; 2],
    /// Indices into `NEXTHOPS`. Unused slots = `u32::MAX`.
    pub nh_idx: [u32; MAX_ECMP_PATHS],
}

/// Runtime-tunable FIB parameters. One-entry array; userspace writes
/// index 0. Separate from `FpCfg` so FIB-specific knobs can evolve
/// without touching the core fast-path config struct (SPEC §4.5
/// `FpCfg` stability constraint).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FpFibCfg {
    /// Default ECMP hash mode for groups that don't carry a per-group
    /// override. `3`, `4`, or `5`.
    pub default_hash_mode: u8,
    pub _pad: [u8; 3],
    /// Layout version. `0` = Phase 1 layout. Userspace rejects loads
    /// on mismatch.
    pub version: u32,
}

impl FpFibCfg {
    pub const VERSION_V1: u32 = 0;
    pub const DEFAULT_HASH_MODE: u8 = 5;

    pub const fn default() -> Self {
        Self {
            default_hash_mode: Self::DEFAULT_HASH_MODE,
            _pad: [0; 3],
            version: Self::VERSION_V1,
        }
    }
}

// --- Maps ---------------------------------------------------------------

/// IPv4 allowlist, src-or-dst match (SPEC §4.2). Key is
/// `{prefix_len: u32, addr: [u8;4]}` via `LpmTrie`'s `Key<T>`.
/// Value is the truthiness byte; only presence is consulted.
#[map]
pub static ALLOW_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(ALLOWLIST_MAX_ENTRIES, 0);

/// IPv6 allowlist. Same semantics, 16-byte address.
#[map]
pub static ALLOW_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(ALLOWLIST_MAX_ENTRIES, 0);

/// v0.2.1 issue #33: IPv4 destination block list. Matched packets
/// whose dst falls in this LPM trie return `XDP_DROP` (counter
/// `BogonDropped` bumped). Empty by default — operator opts in by
/// declaring `block-prefix <cidr>` lines in config. Sized the same
/// as the allowlist; expected entries are a handful of bogon ranges
/// (RFC 1918, CGNAT, test-net) so 1024 is generous.
#[map]
pub static BLOCK_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(ALLOWLIST_MAX_ENTRIES, 0);

/// IPv6 destination block list. Same semantics. Currently unused by
/// any common config; ULA (`fc00::/7`) is the obvious entry point but
/// most operators will leave this empty.
#[map]
pub static BLOCK_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(ALLOWLIST_MAX_ENTRIES, 0);

/// Runtime flags. One-entry array; userspace writes index 0.
#[map]
pub static CFG: Array<FpCfg> = Array::with_max_entries(1, 0);

/// Per-CPU counters (SPEC §4.6). Userspace aggregates across CPUs.
#[map]
pub static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STATS_COUNT, 0);

/// Debug event ringbuf (SPEC §3.7). Kept small in v0.1; structured
/// event type lands with the reconfigure flow in PR #6.
#[map]
pub static LOG: RingBuf = RingBuf::with_byte_size(LOG_RINGBUF_BYTES, 0);

/// Redirect target devmap (SPEC §4.5). Hash-keyed by ifindex so size
/// doesn't scale with the host's highest ifindex — matters on container
/// hosts with sparse, high ifindex numbers.
#[map]
pub static REDIRECT_DEVMAP: DevMapHash =
    DevMapHash::with_max_entries(REDIRECT_DEVMAP_MAX_ENTRIES, 0);

/// VLAN-subif → (phys_ifindex, vid) lookup (SPEC §4.5, §4.7). Consulted
/// after `bpf_fib_lookup` returns a subif ifindex: if present, the
/// program redirects to the physical parent and pushes the recorded
/// VID; if absent, the target is treated as physical/untagged.
#[map]
pub static VLAN_RESOLVE: HashMap<u32, VlanResolve> =
    HashMap::with_max_entries(VLAN_RESOLVE_MAX_ENTRIES, 0);

// --- Custom-FIB maps (Option F, Phase 1) -------------------------------
//
// These maps are declared and sized in Phase 1 but neither read nor
// written by the XDP program until Phase 1 Slice 1B gates the custom
// lookup path on `FP_CFG_FLAG_CUSTOM_FIB`. Phase 3 wires up the
// FibProgrammer that populates them from BMP.

/// IPv4 custom FIB. Keyed by `{prefixlen, addr[4]}`; value is a
/// `FibValue` pointing at `NEXTHOPS` (Single) or `ECMP_GROUPS` (Ecmp).
#[map]
pub static FIB_V4: LpmTrie<[u8; 4], FibValue> =
    LpmTrie::with_max_entries(FIB_V4_MAX_ENTRIES, 0);

/// IPv6 custom FIB. Same semantics, 128-bit address key.
#[map]
pub static FIB_V6: LpmTrie<[u8; 16], FibValue> =
    LpmTrie::with_max_entries(FIB_V6_MAX_ENTRIES, 0);

/// Nexthop cache. Seqlock-protected `NexthopEntry` per ID. The FIB
/// trie values hold indices into this array; 180K routes sharing a
/// dozen peers means neighbor churn updates a dozen entries, not
/// 180K trie entries.
#[map]
pub static NEXTHOPS: Array<NexthopEntry> = Array::with_max_entries(NEXTHOPS_MAX_ENTRIES, 0);

/// ECMP groups. Each entry holds up to `MAX_ECMP_PATHS` nexthop IDs
/// and a per-group hash mode. Userspace deduplicates groups by
/// signature (same set of NHs + same hash_mode → same group ID).
#[map]
pub static ECMP_GROUPS: Array<EcmpGroup> = Array::with_max_entries(ECMP_GROUPS_MAX_ENTRIES, 0);

/// FIB-specific runtime config. One-entry array; userspace writes
/// index 0. Separate from `CFG` to avoid evolving `FpCfg`.
#[map]
pub static FIB_CONFIG: Array<FpFibCfg> = Array::with_max_entries(1, 0);

// --- Stat increment helper ---------------------------------------------

/// Bump the per-CPU counter at `idx` by 1. Safe on the hot path — the
/// verifier tolerates the single get_ptr_mut + deref, and on miss we
/// simply skip the increment (a map hit is guaranteed iff `idx <
/// STATS_COUNT`, which we enforce via the [`StatIdx`] enum).
#[inline(always)]
pub fn bump_stat(idx: StatIdx) {
    let k = idx as u32;
    if let Some(slot) = STATS.get_ptr_mut(k) {
        // SAFETY: PerCpuArray with max_entries=STATS_COUNT guarantees
        // that `get_ptr_mut` returns a pointer to our own CPU's slot
        // for the entire NAPI cycle. Non-atomic increment is correct
        // because PerCpuArray serializes per-CPU.
        unsafe {
            *slot = (*slot).saturating_add(1);
        }
    }
}
