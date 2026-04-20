//! PacketFrame fast-path BPF program.
//!
//! v0.0.x scaffolding: a trivial XDP program that always returns
//! `XDP_PASS`. The real §4.4 logic (parse → LPM → `bpf_fib_lookup` →
//! redirect) lands incrementally on the PR #3 branch once this scaffold
//! proves the toolchain (nightly + `bpfel-unknown-none` + `bpf-linker`)
//! builds end-to-end in CI.

#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};

#[xdp]
pub fn fast_path(_ctx: XdpContext) -> u32 {
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
