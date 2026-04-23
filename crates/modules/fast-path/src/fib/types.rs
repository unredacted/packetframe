//! Userspace-side mirrors of the custom-FIB map value types declared in
//! [`bpf/src/maps.rs`](../../bpf/src/maps.rs). Every struct here is
//! `#[repr(C)]` with primitive-only fields and exact trailing padding,
//! so the byte layout matches what the BPF program sees. Compile-time
//! `size_of` assertions catch drift: if either side's definition
//! changes without the other, the assertions here fail the build.
//!
//! `aya::Pod` is implemented for each type so `aya::maps::{Array,
//! LpmTrie}` accepts them as map values. `Pod` requires that every bit
//! pattern is a valid instance; all fields here are primitive integers
//! or fixed-size byte arrays, so that holds.

// --- FibValue ----------------------------------------------------------

/// `FibValue.kind` discriminant: single-nexthop route. Mirrors
/// `FIB_KIND_SINGLE` in bpf/src/maps.rs.
pub const FIB_KIND_SINGLE: u8 = 0;
/// `FibValue.kind` discriminant: ECMP group reference. Mirrors
/// `FIB_KIND_ECMP` in bpf/src/maps.rs.
pub const FIB_KIND_ECMP: u8 = 1;

/// Userspace mirror of `maps::FibValue`. 8 bytes, single aligned
/// write from userspace is torn-read-free on the BPF side.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FibValue {
    pub kind: u8,
    pub _pad: [u8; 3],
    pub idx: u32,
}

impl FibValue {
    pub const fn single(nexthop_id: u32) -> Self {
        Self {
            kind: FIB_KIND_SINGLE,
            _pad: [0; 3],
            idx: nexthop_id,
        }
    }

    pub const fn ecmp(group_id: u32) -> Self {
        Self {
            kind: FIB_KIND_ECMP,
            _pad: [0; 3],
            idx: group_id,
        }
    }
}

// SAFETY: repr(C), 8 bytes of u8/u8/u8/u8/u32, every bit pattern valid.
// aya is Linux-only (see crates/modules/fast-path/Cargo.toml target
// deps); `Pod` only matters on that platform because aya map I/O is
// Linux-only too.
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for FibValue {}

// --- NexthopEntry ------------------------------------------------------

/// `NexthopEntry.state` discriminants. Mirror `NH_STATE_*` in bpf/src/maps.rs.
pub const NH_STATE_INCOMPLETE: u8 = 0;
pub const NH_STATE_RESOLVED: u8 = 1;
pub const NH_STATE_STALE: u8 = 2;
pub const NH_STATE_FAILED: u8 = 3;

/// `NexthopEntry.family` discriminants.
pub const NH_FAMILY_V4: u8 = 4;
pub const NH_FAMILY_V6: u8 = 6;

/// Userspace mirror of `maps::NexthopEntry`. 28 bytes.
///
/// **Seqlock discipline** (see `bpf/src/maps.rs` `NexthopEntry` doc):
/// writers set `seq |= 1` (odd = in progress), write the rest, then
/// set `seq = (seq | 1) + 1` (even = stable). Readers in XDP verify
/// `seq_before == seq_after` and both even; mismatch retries up to 4
/// times. First-time writes start at `seq = 0`, finish at `seq = 2`.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NexthopEntry {
    pub seq: u32,
    pub ifindex: u32,
    pub dst_mac: [u8; 6],
    pub _pad0: [u8; 2],
    pub src_mac: [u8; 6],
    pub _pad1: [u8; 2],
    pub state: u8,
    pub family: u8,
    pub bmp_peer_hint: [u8; 2],
}

impl NexthopEntry {
    pub const fn zeroed() -> Self {
        Self {
            seq: 0,
            ifindex: 0,
            dst_mac: [0; 6],
            _pad0: [0; 2],
            src_mac: [0; 6],
            _pad1: [0; 2],
            state: NH_STATE_INCOMPLETE,
            family: 0,
            bmp_peer_hint: [0; 2],
        }
    }
}

// SAFETY: repr(C), primitive fields with explicit padding, every bit
// pattern valid.
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for NexthopEntry {}

// --- EcmpGroup ---------------------------------------------------------

/// Mirror `MAX_ECMP_PATHS` in bpf/src/maps.rs.
pub const MAX_ECMP_PATHS: usize = 8;

/// Sentinel: unused `nh_idx` slot in an `EcmpGroup`.
pub const ECMP_NH_UNUSED: u32 = u32::MAX;

/// Userspace mirror of `maps::EcmpGroup`. 36 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EcmpGroup {
    pub hash_mode: u8,
    pub nh_count: u8,
    pub _pad: [u8; 2],
    pub nh_idx: [u32; MAX_ECMP_PATHS],
}

impl EcmpGroup {
    pub const fn empty() -> Self {
        Self {
            hash_mode: 5,
            nh_count: 0,
            _pad: [0; 2],
            nh_idx: [ECMP_NH_UNUSED; MAX_ECMP_PATHS],
        }
    }
}

// SAFETY: repr(C), primitive fields, every bit pattern valid.
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for EcmpGroup {}

// --- FpFibCfg ----------------------------------------------------------

/// Userspace mirror of `maps::FpFibCfg`. 8 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FpFibCfg {
    pub default_hash_mode: u8,
    pub _pad: [u8; 3],
    pub version: u32,
}

impl FpFibCfg {
    pub const VERSION_V1: u32 = 0;
    pub const DEFAULT_HASH_MODE: u8 = 5;

    pub const fn default_v1() -> Self {
        Self {
            default_hash_mode: Self::DEFAULT_HASH_MODE,
            _pad: [0; 3],
            version: Self::VERSION_V1,
        }
    }
}

// SAFETY: repr(C), u8+[u8;3]+u32, every bit pattern valid.
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for FpFibCfg {}

// --- Layout assertions -------------------------------------------------
//
// These match the layouts declared in `bpf/src/maps.rs`. Any drift on
// either side breaks the build — safer than waiting for a field
// misalignment to cause an XDP map write to corrupt the wrong bytes.

const _: () = assert!(core::mem::size_of::<FibValue>() == 8);
const _: () = assert!(core::mem::align_of::<FibValue>() == 4);

const _: () = assert!(core::mem::size_of::<NexthopEntry>() == 28);
const _: () = assert!(core::mem::align_of::<NexthopEntry>() == 4);

const _: () = assert!(core::mem::size_of::<EcmpGroup>() == 36);
const _: () = assert!(core::mem::align_of::<EcmpGroup>() == 4);

const _: () = assert!(core::mem::size_of::<FpFibCfg>() == 8);
const _: () = assert!(core::mem::align_of::<FpFibCfg>() == 4);

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn fib_value_single_tags_correctly() {
        let v = FibValue::single(42);
        assert_eq!(v.kind, FIB_KIND_SINGLE);
        assert_eq!(v.idx, 42);
    }

    #[test]
    fn fib_value_ecmp_tags_correctly() {
        let v = FibValue::ecmp(7);
        assert_eq!(v.kind, FIB_KIND_ECMP);
        assert_eq!(v.idx, 7);
    }

    #[test]
    fn fib_value_is_eight_bytes() {
        assert_eq!(size_of::<FibValue>(), 8);
    }

    #[test]
    fn nexthop_entry_is_twenty_eight_bytes() {
        assert_eq!(size_of::<NexthopEntry>(), 28);
    }

    #[test]
    fn nexthop_entry_zeroed_is_incomplete() {
        let nh = NexthopEntry::zeroed();
        assert_eq!(nh.state, NH_STATE_INCOMPLETE);
        assert_eq!(nh.seq, 0);
    }

    #[test]
    fn ecmp_group_is_thirty_six_bytes() {
        assert_eq!(size_of::<EcmpGroup>(), 36);
    }

    #[test]
    fn ecmp_group_empty_has_sentinel_slots() {
        let g = EcmpGroup::empty();
        assert_eq!(g.nh_count, 0);
        assert!(g.nh_idx.iter().all(|&x| x == ECMP_NH_UNUSED));
    }

    #[test]
    fn fp_fib_cfg_is_eight_bytes() {
        assert_eq!(size_of::<FpFibCfg>(), 8);
    }

    #[test]
    fn fp_fib_cfg_default_is_five_tuple() {
        let c = FpFibCfg::default_v1();
        assert_eq!(c.default_hash_mode, 5);
        assert_eq!(c.version, FpFibCfg::VERSION_V1);
    }
}
