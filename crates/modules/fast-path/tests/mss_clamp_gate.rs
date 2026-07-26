//! Fixtures for the mss-clamp gating changes: the MSS_CLAMP_PRESENT
//! bit carried across the tail call (finalize skips the whole clamp
//! chain when clear), the SYN hoist (established TCP skips the clamp
//! lookups even when configured), and the global-clamp fallback riding
//! in MutationCtx instead of a finalize-side CFG read.
//!
//! Clamp source precedence (prefix > iface > global, SPEC §4.x) is
//! asserted unchanged.

#![cfg(target_os = "linux")]

mod common;

use common::{
    xdp_action, FpCfg, Harness, Ipv4TcpBuilder, StatIdx, FP_CFG_FLAG_CUSTOM_FIB, FP_CFG_FLAG_IPV4,
    FP_CFG_FLAG_IPV6, FP_CFG_FLAG_MSS_CLAMP_PRESENT, FP_CFG_VERSION_V2,
};

const LO_IFINDEX: u32 = 1;
const BASE_FLAGS: u8 = FP_CFG_FLAG_IPV4 | FP_CFG_FLAG_IPV6 | FP_CFG_FLAG_CUSTOM_FIB;

const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;

/// MSS option bytes for a given value: kind=2, len=4, mss_be.
fn mss_option(mss: u16) -> Vec<u8> {
    let be = mss.to_be_bytes();
    vec![2, 4, be[0], be[1]]
}

/// Offset of the MSS value bytes within the output frame: eth(14) +
/// ipv4(20) + tcp fixed(20) + option kind/len(2).
const MSS_VALUE_OFF: usize = 14 + 20 + 20 + 2;

fn forwarding_harness() -> Harness {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8");
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

fn set_flags_and_global(h: &mut Harness, flags: u8, mss_clamp_global: u16) {
    h.set_cfg(FpCfg {
        dry_run: 0,
        flags,
        mss_clamp_global,
        version: FP_CFG_VERSION_V2,
    });
}

fn syn_with_mss(mss: u16) -> Vec<u8> {
    Ipv4TcpBuilder {
        tcp_flags: TCP_FLAG_SYN,
        tcp_options: mss_option(mss),
        ..Default::default()
    }
    .build()
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn clamp_unconfigured_syn_forwards_untouched() {
    // Production profile: no clamp anywhere, presence bit clear. The
    // SYN must forward with its MSS bytes intact and neither clamp
    // counter moving.
    let mut h = forwarding_harness();
    set_flags_and_global(&mut h, BASE_FLAGS, 0);

    let pkt = syn_with_mss(1460);
    let applied = h.stat(StatIdx::MssClampApplied);
    let skipped = h.stat(StatIdx::MssClampSkipped);
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(
        &out[MSS_VALUE_OFF..MSS_VALUE_OFF + 2],
        &1460u16.to_be_bytes()
    );
    assert_eq!(h.stat(StatIdx::MssClampApplied), applied);
    assert_eq!(h.stat(StatIdx::MssClampSkipped), skipped);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn global_clamp_rides_mutation_ctx() {
    // Global clamp only (no prefix/iface entries): the value reaches
    // finalize via MutationCtx.mss_clamp_global — there is no CFG read
    // in finalize anymore, so a wrong/missing carry would leave the
    // MSS unclamped and fail this test.
    let mut h = forwarding_harness();
    set_flags_and_global(&mut h, BASE_FLAGS | FP_CFG_FLAG_MSS_CLAMP_PRESENT, 1300);

    let pkt = syn_with_mss(1460);
    let applied = h.stat(StatIdx::MssClampApplied);
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(
        &out[MSS_VALUE_OFF..MSS_VALUE_OFF + 2],
        &1300u16.to_be_bytes()
    );
    assert_eq!(h.stat(StatIdx::MssClampApplied), applied + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn syn_hoist_established_tcp_bumps_nothing() {
    // Clamp configured, but the packet is an established-flow ACK:
    // the hoisted SYN test must bail before any clamp bookkeeping.
    // Same observable outcome as pre-hoist (no counters, no mutation
    // beyond TTL/L2) — this pins that the hoist didn't change it.
    let mut h = forwarding_harness();
    set_flags_and_global(&mut h, BASE_FLAGS | FP_CFG_FLAG_MSS_CLAMP_PRESENT, 1300);

    let pkt = Ipv4TcpBuilder {
        tcp_flags: TCP_FLAG_ACK,
        ..Default::default()
    }
    .build();
    let applied = h.stat(StatIdx::MssClampApplied);
    let skipped = h.stat(StatIdx::MssClampSkipped);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(h.stat(StatIdx::MssClampApplied), applied);
    assert_eq!(h.stat(StatIdx::MssClampSkipped), skipped);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn prefix_clamp_beats_global() {
    // SPEC precedence: prefix source wins over the global fallback.
    let mut h = forwarding_harness();
    set_flags_and_global(&mut h, BASE_FLAGS | FP_CFG_FLAG_MSS_CLAMP_PRESENT, 1300);
    h.add_mss_clamp_v4("10.0.0.0/8", 1200, 0);

    let pkt = syn_with_mss(1460);
    let applied = h.stat(StatIdx::MssClampApplied);
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(
        &out[MSS_VALUE_OFF..MSS_VALUE_OFF + 2],
        &1200u16.to_be_bytes()
    );
    assert_eq!(h.stat(StatIdx::MssClampApplied), applied + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn syn_with_mss_below_clamp_counts_skipped() {
    // Existing MSS already under the clamp: lower-if-higher semantics
    // leave it alone and count MssClampSkipped, exactly as before.
    let mut h = forwarding_harness();
    set_flags_and_global(&mut h, BASE_FLAGS | FP_CFG_FLAG_MSS_CLAMP_PRESENT, 1300);

    let pkt = syn_with_mss(1200);
    let skipped = h.stat(StatIdx::MssClampSkipped);
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(
        &out[MSS_VALUE_OFF..MSS_VALUE_OFF + 2],
        &1200u16.to_be_bytes()
    );
    assert_eq!(h.stat(StatIdx::MssClampSkipped), skipped + 1);
}
