// aya is Linux-only; compile the whole test module out on other hosts.
#![cfg(target_os = "linux")]

//! Integration test: load the fast-path BPF ELF through aya.
//!
//! aya's `Xdp::load()` round-trips the program through the kernel
//! verifier — if it succeeds the verifier accepted our §4.4 program,
//! and that's the single most valuable guard we can ship in PR #3.
//!
//! Packet-level `bpf_prog_test_run` fixtures (for parse errors,
//! fragments, TTL, allowlist-miss, complex-header verdicts) land in
//! PR #4 alongside the netns integration test that can also exercise
//! the FIB-return cases that need real routes.
//!
//! This test:
//! - `#[ignore]`-skips when BPF wasn't built (macOS dev laptops, per
//!   the PR #3 plan: CI-only BPF builds).
//! - Requires CAP_BPF + CAP_NET_ADMIN; CI runs it under `sudo`.

use packetframe_fast_path::{FAST_PATH_BPF, FAST_PATH_BPF_AVAILABLE};

/// Loading a BPF program calls `bpf(BPF_PROG_LOAD)` which requires
/// CAP_BPF + CAP_NET_ADMIN. Default `cargo test` has neither; CI runs
/// this test in a dedicated sudo step (see `.github/workflows/ci.yml`).
/// Marked `#[ignore]` so routine `cargo test` skips it cleanly.
#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn fast_path_passes_verifier() {
    if !FAST_PATH_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping verifier test.");
        return;
    }

    let mut bpf =
        aya::Ebpf::load(FAST_PATH_BPF).expect("load BPF ELF (ensure test runs as root/CAP_BPF)");

    let prog: &mut aya::programs::Xdp = bpf
        .program_mut("fast_path")
        .expect("`fast_path` program present in the ELF")
        .try_into()
        .expect("program is XDP-typed");

    prog.load()
        .expect("kernel verifier accepts the program (§4.4 core logic)");
}
