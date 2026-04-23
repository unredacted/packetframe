//! Cross-check that the BPF-side hash in `bpf/src/fib.rs` produces
//! byte-for-byte identical output to the userspace reference in
//! `src/fib/hash.rs`.
//!
//! The two are copy-pasted by design (BPF lives in a separate
//! no-std crate with its own toolchain; no shared module). This
//! test is the guard that keeps them aligned: diverge either and
//! the ECMP leg-selection assertion below fails loudly.
//!
//! **Indirect cross-check via ECMP leg selection.** The BPF program's
//! private `hash_v4` / `hash_v6` are not directly callable from
//! userspace tests, so we exercise them through their only observable
//! effect: which nexthop an ECMP lookup picks. For a given 5-tuple
//! and a known ECMP group with N fully-resolved nexthops, both sides
//! computing the same hash produces the same `hash % N` selection.
//! Any divergence makes a predicted-vs-observed dst MAC mismatch.
//!
//! Requires CAP_BPF + BPF build; CI runs under `sudo -E cargo test
//! ... -- --ignored`.

#![cfg(target_os = "linux")]

mod common;

use common::{xdp_action, Harness, Ipv4TcpBuilder, Ipv6TcpBuilder};
use packetframe_fast_path::fib::hash;

const LO_IFINDEX: u32 = 1;
const EGRESS_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0, 0x01];

/// Fabricate `n` distinct dst MACs so the observed egress MAC after
/// a redirect uniquely identifies which ECMP leg was chosen.
fn distinct_macs(n: usize) -> Vec<[u8; 6]> {
    (0..n)
        .map(|i| [0xaa, 0, 0, 0, 0, i as u8 + 1])
        .collect()
}

/// Build a harness primed for ECMP hash cross-checks: custom-FIB on,
/// hash mode 5, `count` resolved nexthops in one ECMP group (id 0),
/// devmap populated.
fn harness_with_ecmp_group(count: usize, hash_mode: u8) -> (Harness, Vec<[u8; 6]>) {
    let macs = distinct_macs(count);
    let mut h = Harness::new();
    h.set_custom_fib(true, /*compare=*/ false);
    h.set_fib_hash_mode(hash_mode);
    h.add_devmap_ifindex(LO_IFINDEX);
    let nh_ids: Vec<u32> = (1..=count as u32).collect();
    for (i, mac) in macs.iter().enumerate() {
        let id = nh_ids[i];
        h.add_nexthop_v4(id, LO_IFINDEX, EGRESS_MAC, *mac);
    }
    h.add_ecmp_group(0, hash_mode, &nh_ids);
    (h, macs)
}

/// Predict which MAC from `macs` a given 5-tuple should be rewritten
/// to, using the userspace reference hash.
fn predicted_v4_mac(
    macs: &[[u8; 6]],
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    sport: u16,
    dport: u16,
    mode: u8,
) -> [u8; 6] {
    let h = hash::hash_v4(src, dst, proto, sport, dport, mode);
    macs[(h as usize) % macs.len()]
}

fn predicted_v6_mac(
    macs: &[[u8; 6]],
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
    sport: u16,
    dport: u16,
    mode: u8,
) -> [u8; 6] {
    let h = hash::hash_v6(src, dst, proto, sport, dport, mode);
    macs[(h as usize) % macs.len()]
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn v4_hash_matches_userspace_across_many_5tuples() {
    const COUNT: usize = 4;
    const MODE: u8 = 5;
    let (mut h, macs) = harness_with_ecmp_group(COUNT, MODE);
    h.add_allow_v4("10.0.0.0/8");
    h.add_fib_v4_ecmp("10.0.0.0/24", 0);

    let src: [u8; 4] = [10, 0, 0, 5];
    let dst: [u8; 4] = [10, 0, 0, 42];
    let proto: u8 = 6;

    // 48 distinct 5-tuples varying both sport and dport.
    let mut checked = 0usize;
    for sport in (1000u16..1012u16).step_by(1) {
        for dport in (443u16..447u16).step_by(1) {
            let pkt = Ipv4TcpBuilder {
                src_ip: src,
                dst_ip: dst,
                src_port: sport,
                dst_port: dport,
                ..Default::default()
            }
            .build();
            let (verdict, out) = h.run(&pkt);
            assert_eq!(
                verdict,
                xdp_action::XDP_REDIRECT,
                "expected redirect for sport={sport} dport={dport}"
            );
            let observed: [u8; 6] = out[0..6].try_into().unwrap();
            let predicted = predicted_v4_mac(&macs, src, dst, proto, sport, dport, MODE);
            assert_eq!(
                observed, predicted,
                "hash mismatch at sport={sport} dport={dport}: \
                 BPF picked {observed:02x?}, userspace predicted {predicted:02x?}"
            );
            checked += 1;
        }
    }
    assert_eq!(checked, 48);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn v4_hash_matches_mode_3() {
    // Mode 3 (3-tuple) ignores ports; varying src/dst IPs gives us
    // the hash-input variation. 16 distinct src IPs × 1 dst.
    const COUNT: usize = 4;
    const MODE: u8 = 3;
    let (mut h, macs) = harness_with_ecmp_group(COUNT, MODE);
    h.add_allow_v4("10.0.0.0/8");
    h.add_fib_v4_ecmp("10.0.0.0/24", 0);

    let dst: [u8; 4] = [10, 0, 0, 42];
    for i in 1u8..17u8 {
        let src = [10, 0, 0, i];
        let pkt = Ipv4TcpBuilder {
            src_ip: src,
            dst_ip: dst,
            src_port: 12345,
            dst_port: 443,
            ..Default::default()
        }
        .build();
        let (verdict, out) = h.run(&pkt);
        assert_eq!(verdict, xdp_action::XDP_REDIRECT);
        let observed: [u8; 6] = out[0..6].try_into().unwrap();
        let predicted = predicted_v4_mac(&macs, src, dst, 6, 12345, 443, MODE);
        assert_eq!(observed, predicted, "mode-3 hash mismatch at src={src:?}");
    }
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn v6_hash_matches_userspace() {
    const COUNT: usize = 4;
    const MODE: u8 = 5;
    let (mut h, macs) = harness_with_ecmp_group(COUNT, MODE);
    h.add_allow_v6("2001:db8::/32");
    h.add_fib_v6_ecmp("2001:db8::/32", 0);

    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

    for sport in 1000u16..1012u16 {
        let pkt = Ipv6TcpBuilder {
            src_ip: src,
            dst_ip: dst,
            src_port: sport,
            dst_port: 443,
            ..Default::default()
        }
        .build();
        let (verdict, out) = h.run(&pkt);
        assert_eq!(verdict, xdp_action::XDP_REDIRECT);
        let observed: [u8; 6] = out[0..6].try_into().unwrap();
        let predicted = predicted_v6_mac(&macs, src, dst, 6, sport, 443, MODE);
        assert_eq!(observed, predicted, "v6 hash mismatch sport={sport}");
    }
}
