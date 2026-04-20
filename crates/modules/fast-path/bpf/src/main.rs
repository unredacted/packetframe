//! PacketFrame fast-path BPF program.
//!
//! Incremental state: map definitions + `rx_total` counter on every
//! packet, but still always returns `XDP_PASS`. The §4.4 parse /
//! allowlist / FIB / redirect logic lands in the next commit on this
//! branch.

#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

mod maps;

use maps::{bump_stat, StatIdx};

#[xdp]
pub fn fast_path(_ctx: XdpContext) -> u32 {
    bump_stat(StatIdx::RxTotal);
    xdp_action::XDP_PASS
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SPEC.md §3.5 restricts BPF code to packet headers and stable kernel
    // ABI types. We don't unwind or report panics — the verifier would
    // reject complex panic handlers anyway. Loop so the function never
    // returns.
    loop {}
}
