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
    bindings::BPF_F_CURRENT_CPU,
    helpers::{bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_perf_event_output},
    EbpfContext,
};

use crate::maps::{bump, StatIdx, StatsPtr, SAMPLES, SAMPLE_CFG, SAMPLE_SCRATCH};

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

/// Emit the selected packet in hand. Callers check [`pending`] first, so
/// the work of describing a packet is spent only on samples.
#[inline(always)]
pub fn emit<C: EbpfContext>(
    ctx: &C,
    stats: StatsPtr,
    frame_len: u32,
    ingress_ifindex: u32,
    egress_ifindex: u32,
    meta: u32,
    vlan: u32,
) {
    // SAFETY: as in `tick`.
    let armed = unsafe { (*stats)[ARMED] };
    let header_bytes = rearm(stats);
    bump(stats, StatIdx::SampleSelected);
    let rec = match SAMPLE_SCRATCH.get_ptr_mut(0) {
        Some(r) => r,
        None => {
            bump(stats, StatIdx::SampleEmitFailed);
            return;
        }
    };
    let captured = if frame_len < header_bytes {
        frame_len
    } else {
        header_bytes
    };
    // SAFETY: `rec` is this CPU's scratch slot, valid for the program run.
    // Field by field: no aggregate store for LLVM to turn into memset.
    unsafe {
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
    // The upper 32 bits of the flags (BPF_F_CTXLEN_MASK) ask the kernel to
    // append that many bytes of the packet. The raw helper rather than
    // `PerfEventArray::output`, which drops the return code.
    let rc = unsafe {
        bpf_perf_event_output(
            ctx.as_ptr(),
            &SAMPLES as *const _ as *mut core::ffi::c_void,
            (u64::from(captured) << 32) | BPF_F_CURRENT_CPU as u64,
            rec as *mut core::ffi::c_void,
            core::mem::size_of::<crate::maps::SampleRecord>() as u64,
        )
    };
    if rc != 0 {
        bump(stats, StatIdx::SampleEmitFailed);
    }
}
