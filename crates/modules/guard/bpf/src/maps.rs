//! Guard maps, wire structs, counters, and the GCRA rate limiter.
//!
//! Everything here follows the fast-path BPF crate's verifier
//! discipline (see its `datapath.rs` header): `#[inline(always)]`
//! everywhere, scalars in/out, field-by-field stores (no struct
//! zero-init on the stack), explicit padding only.

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerCpuArray},
};

// --- Per-interface config -------------------------------------------------

/// Layout version currently understood by this program. Entries with
/// any other version are ignored (fail open, counted `PassNoCfg`), so
/// a userspace/ELF layout skew shows up as a counter anomaly instead
/// of misclassification.
pub const GUARD_CFG_VERSION: u32 = 1;

/// Per-class action byte values. Plain consts, not an enum: the
/// userspace writer stores raw bytes and integer match arms verify
/// more predictably than enum discriminants.
pub const ACTION_DISABLED: u8 = 0;
/// Never compared against by the datapath — monitor is the implicit
/// "enabled but not ENFORCE" arm — but kept so the wire contract is
/// spelled out in one place on both sides of the mirror.
#[allow(dead_code)]
pub const ACTION_MONITOR: u8 = 1;
pub const ACTION_ENFORCE: u8 = 2;

/// Per-ifindex guard configuration. 48 bytes, `#[repr(C)]`, zero
/// implicit padding. **Hand-mirrored in the userspace crate's
/// `cfg.rs` (`GuardIfCfg`), which pins size and every field offset in
/// a unit test — any change here must land there in the same commit.**
#[repr(C)]
#[derive(Copy, Clone)]
pub struct GuardIfCfg {
    /// Expected src MAC, wire bytes 0..4 as a native-endian u32. The
    /// datapath compares raw byte loads, so endianness cancels.
    pub mac_hi: u32,
    /// Wire bytes 4..6, same convention.
    pub mac_lo: u16,
    pub act_arp: u8,
    pub act_ns: u8,
    pub act_lldp: u8,
    pub act_foreign: u8,
    pub act_mcast: u8,
    /// Always 0; keeps the layout explicit-padding-only.
    pub _pad0: u8,
    pub version: u32,
    /// GCRA emission interval for the ARP-request/NS buckets, ns per
    /// token. 0 = bucket bypass (class effectively disabled).
    pub ndp_t_ns: u64,
    /// GCRA burst tolerance, precomputed by userspace as
    /// `(burst - 1) * ndp_t_ns` so the datapath does no arithmetic
    /// beyond add/compare.
    pub ndp_tau_ns: u64,
    pub mcast_t_ns: u64,
    pub mcast_tau_ns: u64,
}

const _: () = assert!(core::mem::size_of::<GuardIfCfg>() == 48);

/// Per-ifindex config, keyed by the egress device's ifindex
/// (`skb->ifindex` at the egress hook). A HashMap rather than an
/// Array for two reasons: ifindex space is sparse (same rationale as
/// fast-path's `TC_REDIRECT_TARGETS`), and — decisive for hot reload —
/// hash-map element replace is RCU-atomic (the kernel allocates the
/// new element and swaps the bucket pointer), so a reader never sees
/// a torn config. Array values are memcpy'd in place and can tear.
/// No entry for an ifindex ⇒ the program passes everything (fail
/// open).
#[map]
pub static GUARD_CFG: HashMap<u32, GuardIfCfg> = HashMap::with_max_entries(64, 0);

// --- Token buckets ----------------------------------------------------------
//
// Keyless direct-mapped shared arrays of GCRA deadlines ("theoretical
// arrival time", ns since boot), indexed by a hash of (ifindex, salt,
// target). Three deliberate divergences from the obvious designs,
// each argued once here:
//
// - **Not an LruHashMap.** The fast-path FIB cache's anti-LRU verdict
//   (its maps.rs: "no LRU type is proven on the 5.15-ui verifier, LRU
//   insert is an alloc-under-spinlock helper call per miss, and under
//   adversarial spray LRU degrades to eviction-list thrash") applies
//   in full — and a daemon iterating the neighbor table IS the spray.
//   A rate limiter also doesn't need LRU's one advantage (exact
//   per-key state): a hash collision here means a shared budget,
//   i.e. strictly stricter, which is the failure direction we want on
//   an IX port.
//
// - **Not per-CPU.** The policy is an aggregate wire rate; a per-CPU
//   bucket would multiply the effective limit by up to nr_cpus (18 on
//   the reference hardware). Unlike the FIB cache these buckets are
//   probed only for ARP/NS/broadcast/multicast frames — the low-rate
//   class by construction — so cross-CPU cache-line traffic is
//   negligible. Update races lose at most one token per race and
//   never corrupt state (see `gcra_conforms`).
//
// - **Not key-tagged.** A keyed direct-mapped cache with overwrite-
//   on-collision (the FIB-cache shape) would be WRONG here:
//   alternating colliding targets would reset the bucket to full
//   burst on every overwrite — collision as rate-limit *evasion*.
//   Storing no key inverts that into shared-budget stricter-limiting.
//
// Kernel zero-init (deadline 0) means "conforming since forever" — no
// init pass needed, the FIB cache's generation-0 trick.

pub const GUARD_NDP_BUCKETS_ENTRIES: u32 = 4096;
#[map]
pub static GUARD_NDP_BUCKETS: Array<u64> = Array::with_max_entries(GUARD_NDP_BUCKETS_ENTRIES, 0);

pub const GUARD_MCAST_BUCKETS_ENTRIES: u32 = 256;
#[map]
pub static GUARD_MCAST_BUCKETS: Array<u64> =
    Array::with_max_entries(GUARD_MCAST_BUCKETS_ENTRIES, 0);

/// Domain salts keep the ARP / NS / catch-all hash domains from
/// aliasing systematically (two classes hashing the same target land
/// in unrelated slots). Arbitrary constants.
pub const ARP_SALT: u32 = 0x6172_7071;
pub const NS_SALT: u32 = 0x6e73_5f73;
pub const MCAST_SALT: u32 = 0x6d63_6173;

/// Fibonacci multiplicative hash → bucket slot. Two ALU ops. Copied
/// from the fast-path FIB cache's `cache_slot` (BPF-internal only, no
/// userspace mirror needed). `entries` must be a power of two.
#[inline(always)]
pub fn bucket_slot(word: u32, entries: u32) -> u32 {
    (word.wrapping_mul(0x9E37_79B1) >> 16) & (entries - 1)
}

/// GCRA / virtual-scheduling conformance test — token-bucket semantics
/// with one u64 of state, zero division, zero multiplication:
/// `burst` back-to-back frames conform (`tau_ns = (burst-1)*t_ns`,
/// precomputed by userspace), then sustained 1 per `t_ns`; idle slots
/// decay to full burst via the `max(tat, now)` clamp.
///
/// Plain read/write, deliberately no atomics and no lock:
/// - the `BPF_ATOMIC` fetch family (`cmpxchg`, fetch-add-with-result)
///   is absent from the arm64 JIT until 5.18 — using it risks a
///   load-time failure on the production 5.15 vendor kernel;
/// - `bpf_spin_lock` needs a BTF-declared lock field, unsupported by
///   aya-ebpf's legacy `#[map]` macros.
/// The race is benign and non-compounding: two CPUs conforming on the
/// same slot in the same window lose one `tat + t_ns` write ⇒ at most
/// one extra admitted frame per race, and the surviving write still
/// advances the deadline. The non-conforming path writes nothing, so
/// a storm cannot corrupt state.
///
/// Callers guarantee `t_ns != 0` (0 means "class disabled", checked
/// before the bucket lookup).
#[inline(always)]
pub fn gcra_conforms(slot: *mut u64, now: u64, t_ns: u64, tau_ns: u64) -> bool {
    // SAFETY: `slot` came from `Array::get_ptr_mut` on a bounds-checked
    // index; the map value lives for the whole program run. Volatile
    // read/write keeps the compiler from fusing the RMW across the
    // branch; cross-CPU races are argued benign above.
    let tat = unsafe { core::ptr::read_volatile(slot) };
    let tat = if tat > now { tat } else { now };
    if tat - now <= tau_ns {
        unsafe { core::ptr::write_volatile(slot, tat + t_ns) };
        true
    } else {
        false
    }
}

// --- Counters ---------------------------------------------------------------

/// Counter indices. Discriminants are wire format and **append-only**
/// (the userspace `metrics.rs` mirrors them by index; operator
/// dashboards consume the rendered names). Do not renumber.
///
/// Partition invariant, asserted by the fixture tests: every frame
/// bumps `TotalEgress` plus **exactly one** of indices 1..=18
/// (terminal outcomes). `ForeignMonitor` (19) is the sole deliberate
/// non-terminal counter: a foreign-src frame in monitor mode is
/// counted and then continues through the remaining classes —
/// otherwise turning on foreign-src monitoring would exempt
/// foreign-MAC ARP storms from the ARP limiter.
#[repr(u32)]
#[derive(Copy, Clone)]
pub enum GuardStatIdx {
    /// Every frame the classifier sees, unconditionally.
    TotalEgress = 0,
    /// No (or unrecognized-version) GUARD_CFG entry for this ifindex.
    PassNoCfg = 1,
    /// Unicast (or rule-disabled) frame no class terminated — the
    /// fast exit.
    PassNoMatch = 2,
    /// Runt below the Ethernet header (passed, fail open).
    ErrParseL2 = 3,
    /// Truncated inline 802.1Q tag (passed, fail open).
    ErrParseVlan = 4,
    /// ARP ethertype but truncated header (passed, fail open).
    ErrParseArp = 5,
    /// IPv6/ICMPv6 NS shape but truncated body (passed, fail open).
    ErrParseNs = 6,
    ForeignDrop = 7,
    LldpDrop = 8,
    /// LLDP would-drop, passed (monitor).
    LldpMonitor = 9,
    /// Conforming ARP request through an enabled rule (passed).
    ArpPass = 10,
    /// Non-conforming ARP request, enforced (dropped).
    ArpDrop = 11,
    /// Non-conforming ARP request, monitor (passed).
    ArpMonitor = 12,
    NsPass = 13,
    NsDrop = 14,
    NsMonitor = 15,
    McastPass = 16,
    McastDrop = 17,
    McastMonitor = 18,
    /// Foreign src MAC in monitor mode; frame CONTINUES (non-terminal,
    /// excluded from the partition sum — see the enum doc).
    ForeignMonitor = 19,
}

/// Array size: 20 used, headroom for append-only growth without a
/// map-shape change.
pub const GUARD_STATS_COUNT: u32 = 32;
pub const GUARD_STATS_COUNT_USIZE: usize = GUARD_STATS_COUNT as usize;

/// Per-CPU counter block, one lookup per program run then constant-
/// offset bumps. Mirror of fast-path's `STATS` shape; userspace
/// aggregates across CPUs.
#[map]
pub static GUARD_STATS: PerCpuArray<[u64; GUARD_STATS_COUNT_USIZE]> =
    PerCpuArray::with_max_entries(1, 0);

pub type StatsPtr = *mut [u64; GUARD_STATS_COUNT_USIZE];

/// Fetch this CPU's counter block, once per program run. `None` is
/// unreachable in practice (index 0 of a 1-entry per-CPU array always
/// exists); the caller fails open to `TC_ACT_OK`. Mirror of
/// fast-path's `stats_base`.
#[inline(always)]
pub fn stats_base() -> Option<StatsPtr> {
    GUARD_STATS.get_ptr_mut(0)
}

/// Bump the counter at `idx`. Compiles to a constant-offset
/// load/add/store on the map-value pointer — no helper call. Mirror of
/// fast-path's `bump`; see its safety comment (per-CPU block, index in
/// bounds by enum construction, u64 wrap unreachable).
#[inline(always)]
pub fn bump(stats: StatsPtr, idx: GuardStatIdx) {
    let i = idx as usize;
    // SAFETY: as per fast-path's `bump` — `stats` is a valid map-value
    // pointer for the whole program run, per-CPU so no concurrent
    // writer, and `i < GUARD_STATS_COUNT_USIZE` by enum construction.
    unsafe {
        (*stats)[i] = (*stats)[i].wrapping_add(1);
    }
}
