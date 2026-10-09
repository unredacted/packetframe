//! Flow-export packet sampling, shared by the XDP and tc datapaths.
//!
//! Selection is a per-CPU countdown kept in this CPU's STATS block
//! (`SampleCountdown`, `SampleArmed`), which every program stage already
//! holds, so a packet that is not sampled costs one load and one store.
//! Each gap is drawn uniformly from [1, 2N−1] (mean N) when the countdown
//! is armed, and the generation and rate it was drawn at go with the
//! sample it selects: a rate change never re-labels a sample selected
//! under the old one.
//!
//! **Exactly once.** [`tick`] runs once per packet and leaves the
//! countdown at 0 when the packet is selected. Every emission point
//! checks [`pending`], and [`emit`] re-arms before it outputs, so a later
//! emission point in the same packet's life (the outer verdict after a
//! failed tail call, say) sees a live countdown and emits nothing.
//!
//! A forwarded packet is emitted where the redirect is decided, after the
//! pristine-packet fallbacks and before any rewrite: the record states
//! the intent and carries the bytes as received. What finalize then makes
//! of it stays in its own counters.

use aya_ebpf::{
    bindings::{__sk_buff, BPF_RB_NO_WAKEUP},
    helpers::{bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_skb_load_bytes},
};

use crate::maps::{bump, SampleEvent, StatIdx, StatsPtr, SAMPLES, SAMPLE_BYTES_MAX, SAMPLE_CFG};

pub const PATH_XDP: u32 = 1;
pub const PATH_TC: u32 = 2;

/// Handed to the kernel.
pub const DISPOSITION_PASS: u32 = 0;
pub const DISPOSITION_DROP: u32 = 1;
/// A redirect was decided; whether it completed is not claimed.
pub const DISPOSITION_REDIRECT: u32 = 2;

/// Packets between re-reads of `SAMPLE_CFG` while sampling is off: how
/// long a CPU takes to notice it was turned on.
const RECHECK: u64 = 1024;

const COUNTDOWN: usize = StatIdx::SampleCountdown as usize;
const ARMED: usize = StatIdx::SampleArmed as usize;

/// Count this packet against the countdown: once per packet, before any
/// emission point.
#[inline(always)]
pub fn tick(stats: StatsPtr) {
    // SAFETY: `stats` is this CPU's STATS block (see `maps::bump`); both
    // offsets are `StatIdx` discriminants below `STATS_COUNT`.
    unsafe {
        let c = (*stats)[COUNTDOWN];
        if c > 1 {
            (*stats)[COUNTDOWN] = c - 1;
        } else if (*stats)[ARMED] as u32 == 0 {
            // Off (or a fresh map): look again.
            rearm(stats);
        } else {
            // Selected. A 0 left by a selected packet that reached no
            // emission point selects this one in its place.
            (*stats)[COUNTDOWN] = 0;
        }
    }
}

/// Whether the packet in hand is selected and not yet emitted.
#[inline(always)]
pub fn pending(stats: StatsPtr) -> bool {
    // SAFETY: as in `tick`.
    unsafe { (*stats)[COUNTDOWN] == 0 }
}

/// Draw the next gap from the current `SAMPLE_CFG` and return its
/// `header_bytes`.
#[inline(always)]
fn rearm(stats: StatsPtr) -> u32 {
    let (armed, header_bytes) = match SAMPLE_CFG.get(0) {
        Some(c) => (c.rate_generation, c.header_bytes),
        None => (0, 0),
    };
    let rate = armed as u32;
    let (gap, armed) = if rate == 0 {
        (RECHECK, 0)
    } else {
        let span = 2 * u64::from(rate) - 1;
        let draw = u64::from(unsafe { bpf_get_prandom_u32() });
        (1 + draw % span, armed)
    };
    // SAFETY: as in `tick`.
    unsafe {
        (*stats)[COUNTDOWN] = gap;
        (*stats)[ARMED] = armed;
    }
    header_bytes
}

/// Emit the selected packet in hand: reserve its record in `SAMPLES`,
/// fill it in place, and submit it without a wakeup (the reader drains on
/// a timer). `copy(dst, want)` puts up to `want` packet bytes at `dst`
/// and says how many it did: each datapath reaches its packet its own
/// way. Callers check [`pending`] first, so the work of describing a
/// packet is spent only on samples.
#[inline(always)]
pub fn emit(
    stats: StatsPtr,
    frame_len: u32,
    ingress_ifindex: u32,
    egress_ifindex: u32,
    meta: u32,
    vlan: u32,
    copy: impl FnOnce(*mut u8, u32) -> u32,
) {
    // SAFETY: as in `tick`.
    let armed = unsafe { (*stats)[ARMED] };
    let header_bytes = rearm(stats);
    bump(stats, StatIdx::SampleSelected);
    let Some(mut entry) = SAMPLES.reserve::<SampleEvent>(0) else {
        bump(stats, StatIdx::SampleEmitFailed);
        return;
    };
    let mut want = if frame_len < header_bytes {
        frame_len
    } else {
        header_bytes
    };
    if want > SAMPLE_BYTES_MAX as u32 {
        want = SAMPLE_BYTES_MAX as u32;
    }
    let ev = entry.as_mut_ptr();
    // SAFETY: `ev` is the reservation, valid and 8-aligned until submit.
    // Raw field pointers, never references, into memory not yet written;
    // field by field, so no aggregate store becomes a memset.
    unsafe {
        let captured = copy(core::ptr::addr_of_mut!((*ev).bytes) as *mut u8, want);
        let rec = core::ptr::addr_of_mut!((*ev).rec);
        (*rec).ktime_ns = bpf_ktime_get_ns();
        (*rec).generation = (armed >> 32) as u32;
        (*rec).rate = armed as u32;
        (*rec).ingress_ifindex = ingress_ifindex;
        (*rec).egress_ifindex = egress_ifindex;
        (*rec).frame_len = frame_len;
        (*rec).captured = captured;
        (*rec).meta = meta;
        (*rec).vlan = vlan;
    }
    entry.submit(BPF_RB_NO_WAKEUP as u64);
}

/// Copy `want` (8 to [`SAMPLE_BYTES_MAX`]) bytes of an XDP frame spanning
/// `[start, end)` to `dst`, eight at a time, every read bounds-checked
/// for the verifier: 5.15 has no `bpf_xdp_load_bytes` (5.18), and generic
/// XDP hands the program a linear frame. Returns the bytes copied, 0 for
/// a `want` out of range (no frame is under 14 bytes, nor `header-bytes`
/// under 64).
///
/// The bytes past the last whole word go as the word ending at `want`,
/// which copies some again: a byte at a time needs a `p + 1 > end`
/// check, which LLVM emits as `p >= end`, a compare the verifier gives
/// too little range. That word's offset varies, so its pointer and offset
/// pass through [`opaque`]: otherwise LLVM folds `start + (want - 8) + 8`
/// into `start + want`, a pointer of another id than the one read, and
/// the verifier cannot tie the check to the read.
#[inline(always)]
pub fn copy_frame(start: usize, end: usize, dst: *mut u8, want: u32) -> u32 {
    const WORDS: usize = SAMPLE_BYTES_MAX / 8;
    if !(8..=SAMPLE_BYTES_MAX as u32).contains(&want) {
        return 0;
    }
    let want = want as usize;
    let mut i = 0;
    while i < WORDS {
        let off = i * 8;
        if off + 8 > want {
            break;
        }
        if start + off + 8 > end {
            return off as u32;
        }
        // SAFETY: `start + off..start + off + 8` is inside the frame
        // (checked above) and `dst + off + 8` inside the reservation's
        // bytes (`off + 8` ≤ `want` ≤ 256).
        unsafe { copy_word(start + off, dst.add(off)) };
        i += 1;
    }
    if want % 8 != 0 {
        // Bounded again past the barrier, for the verifier.
        let off = opaque(want - 8);
        if off > SAMPLE_BYTES_MAX - 8 {
            return (i * 8) as u32;
        }
        let src = opaque(start + off);
        if src + 8 > end {
            return (i * 8) as u32;
        }
        // SAFETY: as above, for the word ending at `want`.
        unsafe { copy_word(src, dst.add(off)) };
    }
    want as u32
}

/// # Safety
/// `src..src + 8` and `dst..dst + 8` are valid.
#[inline(always)]
unsafe fn copy_word(src: usize, dst: *mut u8) {
    core::ptr::write_unaligned(
        dst as *mut u64,
        core::ptr::read_unaligned(src as *const u64),
    );
}

/// Copy `want` (at most [`SAMPLE_BYTES_MAX`]) bytes of the skb to `dst`
/// with `bpf_skb_load_bytes`, which reaches past the linear head. Returns
/// the bytes copied: 0 when the helper refused.
#[inline(always)]
pub fn copy_skb(skb: *mut __sk_buff, dst: *mut u8, want: u32) -> u32 {
    if want == 0 || want > SAMPLE_BYTES_MAX as u32 {
        return 0;
    }
    let len = helper_len(want);
    // SAFETY: the program's own skb, and `dst` holds SAMPLE_BYTES_MAX bytes.
    let rc = unsafe { bpf_skb_load_bytes(skb as *const _, 0, dst as *mut _, len) };
    if rc == 0 {
        len
    } else {
        0
    }
}

/// `want` (1 to [`SAMPLE_BYTES_MAX`]) as a helper's size argument, which
/// the verifier needs to see in [1, 256]. Built to be, since a compare
/// does not show it: LLVM folds the two bounds into one compare and
/// zero-extends after it, and 5.15 learns nothing from `!= 0`.
#[inline(always)]
fn helper_len(want: u32) -> u32 {
    (opaque(want - 1) & (SAMPLE_BYTES_MAX as u32 - 1)) + 1
}

/// `v`, which LLVM can no longer relate to how it was computed: read back
/// through a stack slot, which the verifier follows exactly (a packet
/// pointer keeps its id). libbpf's `barrier_var`, without inline asm.
#[inline(always)]
fn opaque<T: Copy>(v: T) -> T {
    let slot = v;
    // SAFETY: a local, read once.
    unsafe { core::ptr::read_volatile(&slot) }
}
