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
    maps::RingBuf,
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

#[xdp]
pub fn probe(ctx: XdpContext) -> u32 {
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

    // Verifier-friendly bounds check for the 16-byte head read. On
    // frames shorter than 16 bytes the entry is discarded — those
    // are invalid Ethernet anyway and not what the operator is
    // trying to diagnose.
    if start + mem::size_of::<[u8; 16]>() > end {
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
        // Bounds-checked 16-byte read from packet head. `read_unaligned`
        // is safe here because XDP context pointers have no guaranteed
        // alignment and the verifier tracks the read range.
        let p = start as *const [u8; 16];
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
