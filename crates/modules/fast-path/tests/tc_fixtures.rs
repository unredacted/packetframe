//! Packet-level fixtures for the tc-ingress datapath (Phase T) via
//! sched_cls `BPF_PROG_TEST_RUN`: verdict mapping (OK/SHOT/REDIRECT),
//! shared-counter parity with the XDP path plus the A/B attribution
//! counters, the TC_REDIRECT_TARGETS pristine-packet pre-check, and
//! the inline-VLAN-tag fallback parse.
//!
//! The tc datapath is custom-fib only; kernel-fib/compare stay on XDP.
//! Real clsact attach, metadata-VLAN round-trip, and MTU/GSO behavior
//! need a netns + veth (T3's integration test) — TEST_RUN neither
//! untags inline 802.1Q into skb metadata nor executes the redirect.
//!
//! Every test is `#[ignore]`: CAP_BPF + BPF build required; CI runs
//! them under sudo.

#![cfg(target_os = "linux")]

mod common;

use common::{
    tc_action, FpCfg, Harness, Ipv4TcpBuilder, StatIdx, FP_CFG_FLAG_BLOCK_PRESENT,
    FP_CFG_FLAG_CUSTOM_FIB, FP_CFG_FLAG_IPV4, FP_CFG_FLAG_IPV6, FP_CFG_FLAG_MSS_CLAMP_PRESENT,
    FP_CFG_VERSION_V2,
};

/// Real ifindex required: tc's bpf_check_mtu resolves it against the
/// netns even under TEST_RUN (see add_tc_redirect_target docs).
const LO_IFINDEX: u32 = 1;
const EGRESS_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0, 0x01];
const NEXTHOP_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0, 0x02];
const BASE_FLAGS: u8 = FP_CFG_FLAG_IPV4 | FP_CFG_FLAG_IPV6 | FP_CFG_FLAG_CUSTOM_FIB;

fn tc_forwarding_harness() -> Harness {
    let mut h = Harness::new();
    h.set_custom_fib(true, /*compare=*/ false);
    h.add_allow_v4("10.0.0.0/8");
    h.add_nexthop_v4(1, LO_IFINDEX, EGRESS_MAC, NEXTHOP_MAC);
    h.add_fib_v4_single("10.0.0.0/24", 1);
    h.add_tc_redirect_target(LO_IFINDEX);
    h
}

fn matched_pkt() -> Vec<u8> {
    Ipv4TcpBuilder {
        src_ip: [10, 0, 0, 5],
        dst_ip: [10, 0, 0, 42],
        ..Default::default()
    }
    .build()
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn tc_allowlist_miss_returns_ok_and_attributes_rx() {
    let mut h = Harness::new();
    h.set_custom_fib(true, false);
    // No allowlist entries: everything misses.
    let pkt = Ipv4TcpBuilder::default().build();

    let rx_before = h.stat(StatIdx::RxTotal);
    let rx_tc_before = h.stat(StatIdx::RxTotalTc);
    let (verdict, out) = h.run_tc(&pkt);
    assert_eq!(verdict, tc_action::TC_ACT_OK);
    assert_eq!(out, pkt, "miss path must leave the packet pristine");
    // Both the shared counter and the tc attribution counter move.
    assert_eq!(h.stat(StatIdx::RxTotal), rx_before + 1);
    assert_eq!(h.stat(StatIdx::RxTotalTc), rx_tc_before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn tc_custom_fib_hit_redirects_with_rewrites() {
    let h = tc_forwarding_harness();
    let pkt = matched_pkt();

    let fwd_before = h.stat(StatIdx::FwdOk);
    let fwd_tc_before = h.stat(StatIdx::FwdOkTc);
    let hit_before = h.stat(StatIdx::CustomFibHit);
    let (verdict, out) = h.run_tc(&pkt);
    assert_eq!(verdict, tc_action::TC_ACT_REDIRECT);
    assert_eq!(h.stat(StatIdx::CustomFibHit), hit_before + 1);
    assert_eq!(h.stat(StatIdx::FwdOk), fwd_before + 1);
    assert_eq!(h.stat(StatIdx::FwdOkTc), fwd_tc_before + 1);
    // Same mutations as the XDP path: L2 rewrite + TTL decrement.
    assert_eq!(&out[0..6], &NEXTHOP_MAC, "dst MAC not rewritten");
    assert_eq!(&out[6..12], &EGRESS_MAC, "src MAC not rewritten");
    assert_eq!(out[14 + 8], pkt[14 + 8] - 1, "TTL not decremented");
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn tc_targets_miss_passes_pristine() {
    // Same forwarding state but TC_REDIRECT_TARGETS left empty: the
    // pre-check must fire BEFORE any mutation (a bpf_redirect to an
    // unchecked ifindex would DROP the skb after return, and a
    // mutated pass-through would be the §11.13 hazard).
    let mut h = Harness::new();
    h.set_custom_fib(true, false);
    h.add_allow_v4("10.0.0.0/8");
    h.add_nexthop_v4(1, LO_IFINDEX, EGRESS_MAC, NEXTHOP_MAC);
    h.add_fib_v4_single("10.0.0.0/24", 1);
    let pkt = matched_pkt();

    let miss_before = h.stat(StatIdx::PassNotInDevmap);
    let (verdict, out) = h.run_tc(&pkt);
    assert_eq!(verdict, tc_action::TC_ACT_OK);
    assert_eq!(h.stat(StatIdx::PassNotInDevmap), miss_before + 1);
    assert_eq!(out, pkt, "pass-path packet must be pristine (§11.13)");
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn tc_block_gate_drops_with_shot() {
    let mut h = tc_forwarding_harness();
    h.add_block_v4("10.0.0.0/24");
    h.set_cfg(FpCfg {
        dry_run: 0,
        flags: BASE_FLAGS | FP_CFG_FLAG_BLOCK_PRESENT,
        mss_clamp_global: 0,
        version: FP_CFG_VERSION_V2,
    });
    let pkt = matched_pkt();

    let dropped_before = h.stat(StatIdx::BogonDropped);
    let (verdict, _) = h.run_tc(&pkt);
    assert_eq!(verdict, tc_action::TC_ACT_SHOT);
    assert_eq!(h.stat(StatIdx::BogonDropped), dropped_before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn tc_inline_vlan_tag_parse_matches() {
    // TEST_RUN delivers the 802.1Q tag inline (no skb-metadata lift),
    // exercising exactly the fallback parse. The tagged matched packet
    // must classify and forward; egress is untagged (VLAN_RESOLVE
    // empty ⇒ egress_vid none ⇒ ingress tag popped by tc_finalize).
    let h = tc_forwarding_harness();
    let base = matched_pkt();
    let tagged = common::insert_vlan_tag(&base, 66);

    let matched_before = h.stat(StatIdx::MatchedV4);
    let (verdict, _out) = h.run_tc(&tagged);
    assert_eq!(verdict, tc_action::TC_ACT_REDIRECT);
    assert_eq!(h.stat(StatIdx::MatchedV4), matched_before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn tc_mss_clamp_parity_with_xdp() {
    // The tc finalize stage shares the clamp walk + source lookups
    // with XDP; a global clamp must rewrite a SYN's MSS identically.
    let mut h = tc_forwarding_harness();
    h.set_cfg(FpCfg {
        dry_run: 0,
        flags: BASE_FLAGS | FP_CFG_FLAG_MSS_CLAMP_PRESENT,
        mss_clamp_global: 1300,
        version: FP_CFG_VERSION_V2,
    });
    let pkt = Ipv4TcpBuilder {
        src_ip: [10, 0, 0, 5],
        dst_ip: [10, 0, 0, 42],
        tcp_flags: 0x02,                     // SYN
        tcp_options: vec![2, 4, 0x05, 0xb4], // MSS 1460
        ..Default::default()
    }
    .build();

    let applied_before = h.stat(StatIdx::MssClampApplied);
    let (verdict, out) = h.run_tc(&pkt);
    assert_eq!(verdict, tc_action::TC_ACT_REDIRECT);
    assert_eq!(h.stat(StatIdx::MssClampApplied), applied_before + 1);
    // eth(14) + ipv4(20) + tcp fixed(20) + option kind/len(2).
    let mss_off = 14 + 20 + 20 + 2;
    assert_eq!(&out[mss_off..mss_off + 2], &1300u16.to_be_bytes());
}
