//! Packet-level fixtures via `bpf_prog_test_run`. Covers the
//! non-FIB §9 Phase 1 cases — parse errors, fragments, low TTL,
//! allowlist misses, complex headers — deferred from PR #3 where aya
//! 0.13.1 didn't wrap `BPF_PROG_TEST_RUN`. The raw-syscall harness in
//! `tests/common/mod.rs` bridges that gap.
//!
//! FIB-return verdict cases (SUCCESS, NO_NEIGH, BLACKHOLE,
//! FRAG_NEEDED, not-in-devmap) need configured routes and a populated
//! `redirect_devmap`; those belong in a netns-backed integration test,
//! a separate slice.
//!
//! Every test is `#[ignore]` — it needs CAP_BPF + BPF build. CI runs
//! the full set under sudo via `cargo test --tests -- --ignored`.

#![cfg(target_os = "linux")]

mod common;

use common::{xdp_action, Harness, Ipv4TcpBuilder, Ipv6TcpBuilder, StatIdx};

fn rx_total_delta(before: u64, h: &Harness) -> u64 {
    h.stat(StatIdx::RxTotal) - before
}

// ========== Non-IP ========================================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn arp_passes_with_pass_not_ip() {
    let mut h = Harness::new();

    // ARP (ethertype 0x0806) — plausibly-shaped but not IP.
    let mut pkt = vec![0u8; 64];
    pkt[0..6].copy_from_slice(&[0xff; 6]); // dst = broadcast
    pkt[6..12].copy_from_slice(&[0xaa, 0, 0, 0, 0, 1]); // src
    pkt[12..14].copy_from_slice(&[0x08, 0x06]); // ARP

    let before = h.stat(StatIdx::PassNotIp);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::PassNotIp), before + 1);
}

// ========== IPv4: parse / malformed =======================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv4_with_options_passes_with_complex_header() {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8"); // would otherwise match

    let pkt = Ipv4TcpBuilder {
        ihl: 6, // one 32-bit word of options (4 NOPs)
        ..Default::default()
    }
    .build();

    let before = h.stat(StatIdx::PassComplexHeader);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::PassComplexHeader), before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv4_mf_fragment_passes_with_pass_fragment() {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8");

    let pkt = Ipv4TcpBuilder {
        // MF bit set (bit 13 of the flags+offset u16 in network order).
        frag_flags: 0x2000,
        ..Default::default()
    }
    .build();

    let before = h.stat(StatIdx::PassFragment);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::PassFragment), before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv4_non_zero_offset_passes_with_pass_fragment() {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8");

    let pkt = Ipv4TcpBuilder {
        frag_flags: 0x0001, // offset=1 (fragment of a larger packet)
        ..Default::default()
    }
    .build();

    let before = h.stat(StatIdx::PassFragment);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::PassFragment), before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv4_ttl_1_passes_with_pass_low_ttl() {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8");

    let pkt = Ipv4TcpBuilder {
        ttl: 1,
        ..Default::default()
    }
    .build();

    let before = h.stat(StatIdx::PassLowTtl);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::PassLowTtl), before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv4_ttl_0_passes_with_pass_low_ttl() {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8");

    let pkt = Ipv4TcpBuilder {
        ttl: 0,
        ..Default::default()
    }
    .build();

    let before = h.stat(StatIdx::PassLowTtl);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::PassLowTtl), before + 1);
}

// ========== IPv4: allowlist miss ==========================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv4_neither_in_allowlist_passes_silently() {
    let mut h = Harness::new();
    h.add_allow_v4("192.168.1.0/24"); // doesn't match src/dst below

    let pkt = Ipv4TcpBuilder {
        src_ip: [10, 0, 0, 1],
        dst_ip: [10, 0, 0, 2],
        ..Default::default()
    }
    .build();

    let before_matched = h.stat(StatIdx::MatchedV4);
    let before_rx = h.stat(StatIdx::RxTotal);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    // No matched counter bumped.
    assert_eq!(h.stat(StatIdx::MatchedV4), before_matched);
    // But rx_total did bump — every packet is counted at the hook.
    assert_eq!(rx_total_delta(before_rx, &h), 1);
}

// ========== IPv6: parse / malformed =======================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv6_fragment_extension_passes_with_complex_header() {
    let mut h = Harness::new();
    h.add_allow_v6("2001:db8::/32");

    // IPv6 Fragment header next_hdr = 44. Our impl XDP_PASSes on any
    // non-{TCP, UDP, ICMPv6} next_hdr and bumps pass_complex_header —
    // per our interpretation of the SPEC §4.4 step 4 ambiguity (see
    // audit in PR #3).
    let pkt = Ipv6TcpBuilder {
        next_hdr: 44,
        payload: vec![0; 8], // minimum fragment header bytes
        ..Default::default()
    }
    .build();

    let before = h.stat(StatIdx::PassComplexHeader);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::PassComplexHeader), before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv6_hop_by_hop_extension_passes_with_complex_header() {
    let mut h = Harness::new();
    h.add_allow_v6("2001:db8::/32");

    // Hop-by-Hop extension header = 0.
    let pkt = Ipv6TcpBuilder {
        next_hdr: 0,
        payload: vec![0; 8],
        ..Default::default()
    }
    .build();

    let before = h.stat(StatIdx::PassComplexHeader);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::PassComplexHeader), before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv6_hop_limit_1_passes_with_pass_low_ttl() {
    let mut h = Harness::new();
    h.add_allow_v6("2001:db8::/32");

    let pkt = Ipv6TcpBuilder {
        hop_limit: 1,
        ..Default::default()
    }
    .build();

    let before = h.stat(StatIdx::PassLowTtl);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::PassLowTtl), before + 1);
}

// ========== Allowlist match + dry-run =====================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv4_src_match_dry_run_passes_with_matched_and_fwd_dry_run() {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8");
    h.set_dry_run(true);

    let pkt = Ipv4TcpBuilder {
        src_ip: [10, 1, 2, 3],  // matches /8
        dst_ip: [192, 0, 2, 1], // does not match
        ..Default::default()
    }
    .build();

    let before_matched = h.stat(StatIdx::MatchedV4);
    let before_src_only = h.stat(StatIdx::MatchedSrcOnly);
    let before_dry = h.stat(StatIdx::FwdDryRun);
    let (verdict, _) = h.run(&pkt);
    // Dry-run short-circuits to XDP_PASS before FIB.
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::MatchedV4), before_matched + 1);
    assert_eq!(h.stat(StatIdx::MatchedSrcOnly), before_src_only + 1);
    assert_eq!(h.stat(StatIdx::FwdDryRun), before_dry + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv4_dst_match_dry_run_passes_with_matched_dst_only() {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8");
    h.set_dry_run(true);

    let pkt = Ipv4TcpBuilder {
        src_ip: [192, 0, 2, 1],
        dst_ip: [10, 4, 5, 6],
        ..Default::default()
    }
    .build();

    let before_matched = h.stat(StatIdx::MatchedV4);
    let before_dst = h.stat(StatIdx::MatchedDstOnly);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::MatchedV4), before_matched + 1);
    assert_eq!(h.stat(StatIdx::MatchedDstOnly), before_dst + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv4_both_match_dry_run_bumps_matched_both() {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8");
    h.set_dry_run(true);

    let pkt = Ipv4TcpBuilder {
        src_ip: [10, 1, 1, 1],
        dst_ip: [10, 2, 2, 2],
        ..Default::default()
    }
    .build();

    let before = h.stat(StatIdx::MatchedBoth);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::MatchedBoth), before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ipv6_src_match_dry_run_bumps_matched_src_only() {
    let mut h = Harness::new();
    h.add_allow_v6("2001:db8::/32");
    h.set_dry_run(true);

    let pkt = Ipv6TcpBuilder {
        src_ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        dst_ip: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ..Default::default()
    }
    .build();

    let before_v6 = h.stat(StatIdx::MatchedV6);
    let before_src_only = h.stat(StatIdx::MatchedSrcOnly);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::MatchedV6), before_v6 + 1);
    assert_eq!(h.stat(StatIdx::MatchedSrcOnly), before_src_only + 1);
}

// ========== Rx counter always bumped ======================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn every_packet_bumps_rx_total() {
    let mut h = Harness::new();

    // Non-IP.
    let mut arp = vec![0u8; 64];
    arp[0..6].copy_from_slice(&[0xff; 6]);
    arp[12..14].copy_from_slice(&[0x08, 0x06]);
    let before = h.stat(StatIdx::RxTotal);
    h.run(&arp);
    assert_eq!(h.stat(StatIdx::RxTotal), before + 1);

    // IPv4 no match.
    let p = Ipv4TcpBuilder::default().build();
    h.run(&p);
    assert_eq!(h.stat(StatIdx::RxTotal), before + 2);

    // IPv4 match (dry-run off — would try FIB, but that likely NO_NEIGH
    // in our no-netns test env; we only check rx_total).
    h.add_allow_v4("10.0.0.0/8");
    h.run(&p);
    assert_eq!(h.stat(StatIdx::RxTotal), before + 3);
}

