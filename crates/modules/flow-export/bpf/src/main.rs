//! flow-export's kernel sampler (`kernel_sample`): tc **ingress** on the
//! interfaces a `kernel-sample` line names, which no fast-path or VPP
//! sampler sees. It only ever looks: every packet goes on with
//! `TC_ACT_UNSPEC`, what the kernel would have done without it.
//!
//! Selection and the record are fast-path's sampler's (its
//! `bpf/src/sample.rs`), so flow export reads both the same way: a
//! per-CPU countdown drawn uniformly from [1, 2N−1] with the generation
//! and rate it was drawn at, a 40-byte record with the frame's leading
//! bytes appended by the kernel, and an offloaded VLAN tag carried in the
//! record. Path 3 marks the kernel sampler's.
//!
//! Verifier discipline follows the fast-path crate: everything
//! `#[inline(always)]`, scalars in and out, field-by-field stores into a
//! per-CPU scratch record (no memset bait). One program, no tail call.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{BPF_F_CURRENT_CPU, TC_ACT_UNSPEC},
    helpers::{bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_perf_event_output},
    macros::{classifier, map},
    maps::{Array, PerCpuArray, PerfEventArray},
    programs::TcContext,
    EbpfContext,
};

/// fast-path's `SampleCfg`: written by flow-export alone.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SampleCfg {
    /// The rate (low 32 bits: mean packets per sample, 0 off) and its
    /// generation (high 32 bits), in one aligned word.
    pub rate_generation: u64,
    pub header_bytes: u32,
    pub _pad: u32,
}

/// fast-path's `SampleRecord`, byte for byte.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SampleRecord {
    pub ktime_ns: u64,
    pub generation: u32,
    pub rate: u32,
    pub ingress_ifindex: u32,
    pub egress_ifindex: u32,
    pub frame_len: u32,
    pub captured: u32,
    /// `path | disposition << 8 | vlan_present << 16`.
    pub meta: u32,
    /// `vlan_tci | vlan_proto << 16`, host order, for an offloaded tag.
    pub vlan: u32,
}

const _: () = assert!(core::mem::size_of::<SampleRecord>() == 40);

/// Per-CPU state: the countdown, what it was armed with, and the two
/// counters flow export reads.
const COUNTDOWN: usize = 0;
const ARMED: usize = 1;
const SELECTED: usize = 2;
const EMIT_FAILED: usize = 3;
pub const STATE_WORDS: usize = 4;

pub const PATH_KERNEL: u32 = 3;

/// Packets between re-reads of `KSAMPLE_CFG` while sampling is off.
const RECHECK: u64 = 1024;

#[map]
pub static KSAMPLE_CFG: Array<SampleCfg> = Array::with_max_entries(1, 0);

#[map]
pub static KSAMPLE_STATE: PerCpuArray<[u64; STATE_WORDS]> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub static KSAMPLES: PerfEventArray<SampleRecord> = PerfEventArray::new(0);

#[map]
pub static KSAMPLE_SCRATCH: PerCpuArray<SampleRecord> = PerCpuArray::with_max_entries(1, 0);

type State = *mut [u64; STATE_WORDS];

#[classifier]
pub fn kernel_sample(ctx: TcContext) -> i32 {
    if let Some(state) = KSAMPLE_STATE.get_ptr_mut(0) {
        if tick(state) {
            emit(&ctx, state);
        }
    }
    TC_ACT_UNSPEC
}

/// Count the packet; true when it is selected.
#[inline(always)]
fn tick(state: State) -> bool {
    // SAFETY: this CPU's state slot, valid for the program run.
    unsafe {
        let c = (*state)[COUNTDOWN];
        if c > 1 {
            (*state)[COUNTDOWN] = c - 1;
            false
        } else if (*state)[ARMED] as u32 == 0 {
            rearm(state);
            false
        } else {
            true
        }
    }
}

/// Draw the next gap from `KSAMPLE_CFG`; return its `header_bytes`.
#[inline(always)]
fn rearm(state: State) -> u32 {
    let (armed, header_bytes) = match KSAMPLE_CFG.get(0) {
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
        (*state)[COUNTDOWN] = gap;
        (*state)[ARMED] = armed;
    }
    header_bytes
}

#[inline(always)]
fn emit(ctx: &TcContext, state: State) {
    // SAFETY: as in `tick`.
    let armed = unsafe { (*state)[ARMED] };
    let header_bytes = rearm(state);
    unsafe { (*state)[SELECTED] += 1 };
    let Some(rec) = KSAMPLE_SCRATCH.get_ptr_mut(0) else {
        unsafe { (*state)[EMIT_FAILED] += 1 };
        return;
    };
    let skb = ctx.skb.skb;
    // SAFETY: the context's skb, valid for the program run.
    let (len, ifindex, tagged, tci, proto) = unsafe {
        (
            (*skb).len,
            (*skb).ifindex,
            (*skb).vlan_present != 0,
            (*skb).vlan_tci,
            (*skb).vlan_proto,
        )
    };
    let vlan = if tagged {
        (tci & 0xffff) | u32::from(u16::from_be(proto as u16)) << 16
    } else {
        0
    };
    let captured = if len < header_bytes { len } else { header_bytes };
    // SAFETY: this CPU's scratch slot. Field by field: no aggregate store
    // for LLVM to turn into memset.
    unsafe {
        (*rec).ktime_ns = bpf_ktime_get_ns();
        (*rec).generation = (armed >> 32) as u32;
        (*rec).rate = armed as u32;
        (*rec).ingress_ifindex = ifindex;
        (*rec).egress_ifindex = 0;
        (*rec).frame_len = len;
        (*rec).captured = captured;
        (*rec).meta = PATH_KERNEL | u32::from(tagged) << 16;
        (*rec).vlan = vlan;
    }
    // The upper 32 bits of the flags (BPF_F_CTXLEN_MASK) append that many
    // packet bytes; the raw helper, for its return code.
    let rc = unsafe {
        bpf_perf_event_output(
            ctx.as_ptr(),
            &KSAMPLES as *const _ as *mut core::ffi::c_void,
            (u64::from(captured) << 32) | BPF_F_CURRENT_CPU as u64,
            rec as *mut core::ffi::c_void,
            core::mem::size_of::<SampleRecord>() as u64,
        )
    };
    if rc != 0 {
        unsafe { (*state)[EMIT_FAILED] += 1 };
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
