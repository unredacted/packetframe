//! ns/packet microbenchmarks for the fast_path → finalize chain via
//! `BPF_PROG_TEST_RUN`'s `repeat` + `duration` fields.
//!
//! These measure the BPF program in isolation. They deliberately do
//! NOT capture the kernel-side generic-XDP overhead that dominates
//! per-packet CPU on skb-mode deployments (`pskb_expand_head` for the
//! 256-byte headroom guarantee, skb linearization, the un-bulked
//! `generic_xdp_tx` transmit) — use `perf top` on the router for that.
//! What they DO give is a stable before/after number for hot-path
//! program changes, on any Linux host.
//!
//! Run locally (Linux, CAP_BPF):
//! ```sh
//! sudo -E cargo test --test bench -- --ignored --nocapture
//! ```
//!
//! Run on the reference EFG (or any aarch64 router): download the
//! `hwtest-aarch64-unknown-linux-gnu` artifact from the
//! `hardware-artifacts` workflow — it cross-builds this test binary with
//! the real BPF ELF embedded and stages it alongside an installable .deb
//! and a driver script — then on the router:
//! ```sh
//! sudo ./packetframe-hwtest-aarch64-unknown-linux-gnu/run-tests.sh bench
//! ```
//! `docs/runbooks/generic-mode-performance.md` has the download
//! commands. Cross-building by hand needs the BPF toolchain (nightly +
//! bpf-linker) in the same place as the cross target, which is why the
//! workflow splits the two: a macOS dev box can't build the ELF at all
//! and would silently embed a stub, making every bench here early-return.
//!
//! Confirm `net.core.bpf_jit_enable=1` on the target first (see
//! `packetframe feasibility`), otherwise the numbers measure the BPF
//! interpreter, not what production runs.
//!
//! Regression gating (off by default, not for shared CI runners):
//! `PACKETFRAME_BENCH_BASELINE_NS=<ns>` makes the established-flow
//! forward bench fail if its median exceeds the baseline.
//!
//! **TTL budget:** `BPF_PROG_TEST_RUN` reuses one packet buffer across
//! all `repeat` iterations inside a syscall, and the forward path
//! decrements TTL per pass. Forward benches therefore use `ttl: 255`
//! and `repeat` well below 253, looping the syscall many times and
//! taking the median of the kernel-reported per-iteration averages.
//! A `FwdOk` delta assertion guards against ever silently measuring
//! the `PassLowTtl` path instead.

#![cfg(target_os = "linux")]

mod common;

use common::{xdp_action, Harness, Ipv4TcpBuilder, StatIdx};

/// Loopback ifindex; always 1 on Linux. The redirect never executes
/// under TEST_RUN (the verdict is returned, not acted on), but the
/// devmap pre-check needs a real entry.
const LO_IFINDEX: u32 = 1;

/// Quick mode for CI under emulation. The statistics only matter on
/// real hardware; under qemu TCG the full 1M-execution forward loops
/// (a) take double-digit minutes and (b) trip the kernel's 22-second
/// soft-lockup watchdog inside `bpf_test_run`, whose per-fire ~35-line
/// splat to the emulated serial console compounds the slowdown until
/// the job times out (observed on the v0.2.8 fib-cache PR: 5.15 qemu
/// job dead at 20 min with bench still running). CI's question is
/// "does the bench run and do its sanity asserts hold", which a
/// fraction of the iterations answers identically.
///
/// Quick mode must bound BOTH knobs, and bound them HARD. Two rounds
/// of evidence shaped these numbers:
///
/// 1. The watchdog's unit of concern is one uninterruptible
///    `bpf_test_run` syscall, so dividing the call count alone is not
///    enough: a 10_000-repeat syscall runs ~20 s of kernel time on a
///    slow TCG runner, straddling the 22 s line (PR #81: 6.6 green in
///    11 min, 5.15 watchdog-cascaded into the 20-min timeout on
///    identical code).
/// 2. Capping repeat at 1_000 was still not enough. PR #86's 5.15 job
///    soft-locked in a FORWARD bench, whose repeat is only 200 — the
///    cap never applied. What killed it was total volume: 200 calls ×
///    200 repeats = 40k executions, and TCG is slow enough that the
///    aggregate stalled a CPU past the watchdog anyway.
///
/// So quick mode now targets a few hundred executions per bench, not a
/// few tens of thousands. CI's question is "does the bench run and do
/// its sanity asserts hold" — the `FwdOk`/`RxTotal` delta assertions
/// and the TTL-budget guard are exactly as strong at 400 executions as
/// at 1M, and the ns/pkt figures were never meaningful under emulation
/// anyway (hardware runs full mode via the hwtest bundle).
const QUICK_MAX_REPEAT: u32 = 50;
const QUICK_MAX_CALLS: usize = 8;

fn bench_params(repeat: u32, calls: usize) -> (u32, usize) {
    if std::env::var_os("PACKETFRAME_BENCH_QUICK").is_some() {
        (repeat.min(QUICK_MAX_REPEAT), calls.min(QUICK_MAX_CALLS))
    } else {
        (repeat, calls)
    }
}

/// Iterations per syscall on paths that mutate TTL (must stay < 253
/// with ttl=255; see module docs).
const FWD_REPEAT: u32 = 200;
/// Syscalls per forward bench: 200 × 5000 = 1M program executions.
const FWD_CALLS: usize = 5000;

/// The miss path never mutates the packet, so one syscall can run a
/// large batch.
const MISS_REPEAT: u32 = 10_000;
const MISS_CALLS: usize = 200;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

/// Run `calls` syscalls of `repeat` iterations each and return the
/// median of the kernel-reported mean-ns-per-iteration samples.
/// Panics if any iteration's verdict differs from `expect_verdict`.
fn median_ns(h: &Harness, pkt: &[u8], repeat: u32, calls: usize, expect_verdict: u32) -> u32 {
    let mut samples = Vec::with_capacity(calls);
    for _ in 0..calls {
        let (verdict, ns) = h.run_timed(pkt, repeat);
        assert_eq!(verdict, expect_verdict, "unexpected verdict mid-bench");
        samples.push(ns);
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}

/// Production-profile harness: custom-fib, one allowlisted /8, one
/// resolved single nexthop, egress in the devmap. Mirrors the
/// reference deployment (single-NH custom-fib, no ECMP / clamp /
/// block / VLAN).
fn custom_fib_harness() -> Harness {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8");
    h.set_custom_fib(true, false);
    h.add_nexthop_v4(
        0,
        LO_IFINDEX,
        [0x02, 0, 0, 0, 0, 0xee],
        [0x02, 0, 0, 0, 0, 0xff],
    );
    h.add_fib_v4_single("10.0.0.0/8", 0);
    h.add_devmap_ifindex(LO_IFINDEX);
    h
}

fn fwd_packet(tcp_flags: u8) -> Vec<u8> {
    Ipv4TcpBuilder {
        ttl: 255, // TTL budget for FWD_REPEAT in-syscall decrements
        tcp_flags,
        ..Default::default()
    }
    .build()
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test --test bench -- --ignored --nocapture`"]
fn bench_custom_fib_forward_established() {
    let h = custom_fib_harness();
    let pkt = fwd_packet(TCP_FLAG_ACK);

    let fwd_before = h.stat(StatIdx::FwdOk);
    let low_ttl_before = h.stat(StatIdx::PassLowTtl);

    let (repeat, calls) = bench_params(FWD_REPEAT, FWD_CALLS);
    let ns = median_ns(&h, &pkt, repeat, calls, xdp_action::XDP_REDIRECT);

    // Every iteration must have forwarded; a TTL-budget bug would
    // divert iterations to PassLowTtl and quietly bench the wrong path.
    let executed = (repeat as u64) * (calls as u64);
    assert_eq!(h.stat(StatIdx::FwdOk) - fwd_before, executed);
    assert_eq!(h.stat(StatIdx::PassLowTtl), low_ttl_before);

    eprintln!("bench_custom_fib_forward_established: {ns} ns/pkt (median of {calls} x {repeat})");

    if let Ok(baseline) = std::env::var("PACKETFRAME_BENCH_BASELINE_NS") {
        let baseline: u32 = baseline
            .parse()
            .expect("PACKETFRAME_BENCH_BASELINE_NS must be an integer ns value");
        assert!(
            ns <= baseline,
            "regression: {ns} ns/pkt exceeds baseline {baseline} ns/pkt"
        );
    }
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test --test bench -- --ignored --nocapture`"]
fn bench_custom_fib_forward_syn() {
    let h = custom_fib_harness();
    let pkt = fwd_packet(TCP_FLAG_SYN);

    let fwd_before = h.stat(StatIdx::FwdOk);
    let (repeat, calls) = bench_params(FWD_REPEAT, FWD_CALLS);
    let ns = median_ns(&h, &pkt, repeat, calls, xdp_action::XDP_REDIRECT);
    let executed = (repeat as u64) * (calls as u64);
    assert_eq!(h.stat(StatIdx::FwdOk) - fwd_before, executed);

    eprintln!("bench_custom_fib_forward_syn: {ns} ns/pkt (median of {calls} x {repeat})");
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test --test bench -- --ignored --nocapture`"]
fn bench_allowlist_miss() {
    // No allowlist entries at all: the packet parses, does the two
    // ALLOW_V4 LPM lookups, misses, and XDP_PASSes without mutation,
    // so a single syscall can carry a large repeat.
    let h = Harness::new();
    let pkt = Ipv4TcpBuilder::default().build();

    let rx_before = h.stat(StatIdx::RxTotal);
    let (repeat, calls) = bench_params(MISS_REPEAT, MISS_CALLS);
    let ns = median_ns(&h, &pkt, repeat, calls, xdp_action::XDP_PASS);
    let executed = (repeat as u64) * (calls as u64);
    assert_eq!(h.stat(StatIdx::RxTotal) - rx_before, executed);

    eprintln!("bench_allowlist_miss: {ns} ns/pkt (median of {calls} x {repeat})");
}
