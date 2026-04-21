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
}

/// Total counter count. Used as `stats` map `max_entries`. New counters
/// bump this; dashboards keying on indices keep working.
pub const STATS_COUNT: u32 = 19;

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
