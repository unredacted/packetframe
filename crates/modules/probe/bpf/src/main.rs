//! PacketFrame probe BPF program.
//!
//! A minimal XDP program that reads the first 16 bytes of each
//! incoming packet along with a kernel timestamp and the full packet
//! length, publishes the sample to a BPF ring buffer, and returns
//! `XDP_PASS`. The operator-facing `packetframe probe` CLI attaches
//! this program to a given iface for a fixed duration, drains the
//! ringbuf, and prints what was seen.
//!
//! Purpose: SPEC.md §11.1(c). On rvu-nicpf (Marvell CN10K) native XDP,
//! attach succeeds and `bpftool net show` reports `xdpdrv`, but
//! `ctx->data` apparently doesn't point at the standard Ethernet
//! header — every packet classifies as `pass_not_ip` in the fast-path
//! program. The canonical way to answer "what does this driver hand
//! to XDP?" is to dump the raw head bytes, which this tool does
//! without touching the packet or disturbing traffic.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::gen::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{Array, RingBuf},
    programs::XdpContext,
};
use core::mem;

/// One sample published per packet. `#[repr(C)]` so the userspace
/// reader can cast incoming ringbuf bytes directly into this layout;
/// changing the layout requires bumping a version field and updating
/// the userspace `ProbeEvent` in sync. Tail-padded by the compiler to
/// 8-byte alignment (8 + 4 + 16 = 28 → 32 bytes) — the kernel also
/// insists `align_of::<T>() ≤ 8` for `RingBuf::reserve`, which this
/// struct satisfies.
///
/// `pkt_len` is the on-the-wire packet length as observed by the XDP
/// hook (`data_end - data`); useful for distinguishing truncated
/// frames from full ones, and for confirming that a non-conformant
/// head prefix is correlated with a suspicious total length.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProbeEvent {
    pub ts_ns: u64,
    pub pkt_len: u32,
    pub head: [u8; 16],
}

/// 256 KiB works across 4-KiB and 16-KiB page hosts (some ARM
/// kernels use 16K pages; ringbuf size must be a power-of-two page
/// multiple). `#[map]` (aya-ebpf macro) registers the map in the
/// `maps` ELF section; using `#[link_section = "maps"]` by hand would
/// produce a map without the right BTF info for userspace to find it
/// by name.
#[map]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Probe configuration, poked by userspace before attach. Single
/// element. Value layout is `#[repr(C)]` + u16 + `[u8; 6]` padding
/// reserved for future fields; keep the struct a multiple of 8 bytes
/// so the `Array` map's per-CPU alignment rules hold on every target.
///
/// `offset` is the byte offset at which the BPF program samples the
/// 16-byte head. Normally `0`, but some broken drivers point
/// `xdp->data` into headroom instead of at the packet — the CLI
/// surfaces `--offset N` so the operator can confirm where the packet
/// really starts. `OTX2_HEAD_ROOM = 128` is the interesting value for
/// rvu-nicpf on pre-upstream-v6.8 kernels; see SPEC.md §11.1(c).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProbeCfg {
    pub offset: u16,
    pub _reserved: [u8; 6],
}

#[map]
pub static CFG: Array<ProbeCfg> = Array::with_max_entries(1, 0);

/// Upper cap on `offset`. Kept modest to keep the verifier's bounds
/// analysis cheap and to avoid letting a bogus userspace value
/// turn the probe into a distant-memory peek tool. 512 covers every
/// real driver headroom I know of; bump if a pathological case shows
/// up.
const MAX_OFFSET: u16 = 512;

#[xdp]
pub fn probe(ctx: XdpContext) -> u32 {
    // Read the userspace-supplied sample offset. Default 0 (sample at
    // `data`). Clamp at `MAX_OFFSET` so a malformed userspace value
    // can't turn this into an unbounded memory peek, and mask to u16
    // so the verifier's bounds tracker stays tight.
    let offset = CFG
        .get(0)
        .map(|c| c.offset)
        .unwrap_or(0)
        .min(MAX_OFFSET) as usize;

    // Reserve a slot before reading packet bytes — keeps the hot path
    // cheap when the ringbuf is full (no reads, no work). Rust's
    // `#[must_use]` on `RingBufEntry` enforces that we either submit
    // or discard before returning, which is also the BPF verifier's
    // requirement.
    let Some(mut entry) = EVENTS.reserve::<ProbeEvent>(0) else {
        // Ring buffer full; drop the sample and keep forwarding. The
        // operator sees a short trace with a gap, which is the
        // expected behaviour under sustained load.
        return xdp_action::XDP_PASS;
    };

    let start = ctx.data();
    let end = ctx.data_end();

    // Verifier-friendly bounds check for the 16-byte head read at
    // `start + offset`. Short packets (or a too-large offset on a
    // small frame) discard the sample rather than fault — the probe
    // is diagnostic; frames that don't fit just aren't interesting
    // evidence and we keep forwarding.
    if start + offset + mem::size_of::<[u8; 16]>() > end {
        entry.discard(0);
        return xdp_action::XDP_PASS;
    }

    let pkt_len = (end - start) as u32;
    let ts = unsafe { bpf_ktime_get_ns() };

    // SAFETY: `RingBufEntry::as_mut_ptr` gives a valid, 8-aligned,
    // `mem::size_of::<ProbeEvent>()`-sized slot that the kernel has
    // reserved for us. We write every field before calling `submit`;
    // the tail padding stays at whatever the kernel zeroed it to.
    unsafe {
        let e = entry.as_mut_ptr();
        (*e).ts_ns = ts;
        (*e).pkt_len = pkt_len;
        // Bounds-checked 16-byte read at `start + offset`. The
        // verifier has the tight [start, end) range and a clamped
        // `offset ≤ MAX_OFFSET`, so `start + offset` is a
        // well-defined in-range pointer.
        let p = (start + offset) as *const [u8; 16];
        (*e).head = core::ptr::read_unaligned(p);
    }

    entry.submit(0);

    // Diagnostic only — never perturb traffic.
    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
