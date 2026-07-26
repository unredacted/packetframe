//! Packet-level fixtures for the Option F custom-FIB XDP path, via
//! `bpf_prog_test_run`. Covers the Phase 1 deliverable cases listed
//! in the plan:
//!
//! - Custom-FIB miss → `CustomFibMiss` + `XDP_PASS`
//! - Custom-FIB single-nexthop hit with resolved nexthop → `CustomFibHit`
//!   + `XDP_REDIRECT` + `FwdOk` to the expected egress ifindex
//! - Custom-FIB hit with `Incomplete` nexthop → `CustomFibNoNeigh` +
//!   `XDP_PASS`
//! - ECMP across 2+ nexthops: distribution ~equal across many 5-tuples
//! - ECMP with dead leg: all packets land on the live leg +
//!   `EcmpDeadLegFallback` bumps
//! - Seqlock torn-read: a permanently-odd `seq` is never observed as
//!   stable and drains the 4-retry budget
//!
//! Compare-mode and VLAN-subif egress tests belong in the netns-backed
//! integration test (a real kernel FIB vs our mocks). They're out of
//! scope here because `bpf_prog_test_run` doesn't run a real
//! `bpf_fib_lookup` against configured kernel routes.
//!
//! Every test is `#[ignore]`, it needs CAP_BPF + a BPF build. CI
//! runs the full set under sudo via `cargo test --tests -- --ignored`.

#![cfg(target_os = "linux")]

mod common;

use aya::maps::Array;
use common::{xdp_action, Harness, Ipv4TcpBuilder, Ipv6TcpBuilder, StatIdx};
use packetframe_fast_path::fib::types::{NexthopEntry, NH_STATE_INCOMPLETE};

/// `lo` is always ifindex 1 on every Linux kernel. Using it as the
/// egress target for `add_nexthop_*` keeps `REDIRECT_DEVMAP` inserts
/// valid without needing a real netdev in the test netns.
const LO_IFINDEX: u32 = 1;
const EGRESS_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0, 0x01];
const NEXTHOP_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0, 0x02];

fn prep_custom_fib_harness() -> Harness {
    let mut h = Harness::new();
    h.set_custom_fib(true, /*compare=*/ false);
    h.set_fib_hash_mode(5);
    h.add_devmap_ifindex(LO_IFINDEX);
    h
}

// ========== Custom-FIB miss ===============================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn custom_fib_v4_miss_returns_pass() {
    let mut h = prep_custom_fib_harness();
    h.add_allow_v4("10.0.0.0/8"); // match the allowlist so we exercise FIB path
                                  // No FIB_V4 entries → every destination misses.

    let pkt = Ipv4TcpBuilder::default().build();

    let before_miss = h.stat(StatIdx::CustomFibMiss);
    let before_fwd = h.stat(StatIdx::FwdOk);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::CustomFibMiss), before_miss + 1);
    assert_eq!(h.stat(StatIdx::FwdOk), before_fwd, "no forward on miss");
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn custom_fib_v6_miss_returns_pass() {
    let mut h = prep_custom_fib_harness();
    h.add_allow_v6("2001:db8::/32");

    let pkt = Ipv6TcpBuilder::default().build();

    let before = h.stat(StatIdx::CustomFibMiss);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::CustomFibMiss), before + 1);
}

// ========== Custom-FIB single-nexthop hit =================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn custom_fib_v4_single_nexthop_hit_redirects() {
    let mut h = prep_custom_fib_harness();
    h.add_allow_v4("10.0.0.0/8");
    h.add_nexthop_v4(1, LO_IFINDEX, EGRESS_MAC, NEXTHOP_MAC);
    h.add_fib_v4_single("10.0.0.0/24", 1);

    let pkt = Ipv4TcpBuilder {
        src_ip: [10, 0, 0, 5],  // matches allow
        dst_ip: [10, 0, 0, 42], // covered by FIB_V4 10.0.0.0/24
        ..Default::default()
    }
    .build();

    let before_hit = h.stat(StatIdx::CustomFibHit);
    let before_fwd = h.stat(StatIdx::FwdOk);
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT, "expected XDP_REDIRECT");
    assert_eq!(h.stat(StatIdx::CustomFibHit), before_hit + 1);
    assert_eq!(h.stat(StatIdx::FwdOk), before_fwd + 1);
    // L2 should have been rewritten with the nexthop's MAC pair.
    assert_eq!(&out[0..6], &NEXTHOP_MAC, "dst MAC not rewritten");
    assert_eq!(&out[6..12], &EGRESS_MAC, "src MAC not rewritten");
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn custom_fib_v6_single_nexthop_hit_redirects() {
    let mut h = prep_custom_fib_harness();
    h.add_allow_v6("2001:db8::/32");
    h.add_nexthop_v6(1, LO_IFINDEX, EGRESS_MAC, NEXTHOP_MAC);
    h.add_fib_v6_single("2001:db8::/32", 1);

    let pkt = Ipv6TcpBuilder::default().build();

    let before_hit = h.stat(StatIdx::CustomFibHit);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(h.stat(StatIdx::CustomFibHit), before_hit + 1);
}

// ========== /128 vs covering route (local-prefix6 premise) ================
//
// The entire premise of `local-prefix6` is that a synthesized /128 for a
// connected host wins the FIB_V6 LPM walk over any covering route from
// the BGP feed. Without that, inbound traffic to the segment would be
// redirected to an upstream nexthop instead of the host's own MAC.

/// MAC behind the covering /64 — stands in for an upstream transit
/// nexthop from the BGP feed.
const COVERING_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0, 0x0c];
/// MAC behind the more-specific /128 — stands in for the connected
/// host's own MAC, learned via NDP.
const HOST_MAC: [u8; 6] = [0xde, 0xad, 0xbe, 0xef, 0, 0x0d];

fn v6_dst(pkt_dst: &str) -> [u8; 16] {
    pkt_dst.parse::<std::net::Ipv6Addr>().unwrap().octets()
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn custom_fib_v6_slash128_beats_covering_routes() {
    let mut h = prep_custom_fib_harness();
    h.add_allow_v6("2001:db8::/32");
    h.add_nexthop_v6(1, LO_IFINDEX, EGRESS_MAC, COVERING_MAC);
    h.add_nexthop_v6(2, LO_IFINDEX, EGRESS_MAC, HOST_MAC);
    h.add_fib_v6_single("2001:db8::/64", 1);
    h.add_fib_v6_single("2001:db8::2/128", 2);

    // 1. The /128'd host: the more specific entry must win.
    let pkt = Ipv6TcpBuilder {
        dst_ip: v6_dst("2001:db8::2"),
        ..Default::default()
    }
    .build();
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(
        &out[0..6],
        &HOST_MAC,
        "/128 must win the LPM walk over the covering /64"
    );

    // 2. Negative control: a sibling address with no /128 falls to the
    //    /64. Proves this is real longest-prefix matching and not
    //    "whichever entry was written last".
    let pkt = Ipv6TcpBuilder {
        dst_ip: v6_dst("2001:db8::3"),
        ..Default::default()
    }
    .build();
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(
        &out[0..6],
        &COVERING_MAC,
        "address without a /128 must fall to the covering /64"
    );

    // 3. Adding a default route must not disturb the /128. Exercises
    //    prefix_len == 0 in the v6 trie.
    h.add_nexthop_v6(3, LO_IFINDEX, EGRESS_MAC, NEXTHOP_MAC);
    h.add_fib_v6_single("::/0", 3);
    let pkt = Ipv6TcpBuilder {
        dst_ip: v6_dst("2001:db8::2"),
        ..Default::default()
    }
    .build();
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(&out[0..6], &HOST_MAC, "/128 must still win over ::/0");
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn custom_fib_v6_slash128_wins_regardless_of_insertion_order() {
    // Same assertion as above with the inserts reversed, ruling out an
    // ordering artifact in the LPM trie.
    let mut h = prep_custom_fib_harness();
    h.add_allow_v6("2001:db8::/32");
    h.add_nexthop_v6(2, LO_IFINDEX, EGRESS_MAC, HOST_MAC);
    h.add_fib_v6_single("2001:db8::2/128", 2);
    h.add_nexthop_v6(1, LO_IFINDEX, EGRESS_MAC, COVERING_MAC);
    h.add_fib_v6_single("2001:db8::/64", 1);

    let pkt = Ipv6TcpBuilder {
        dst_ip: v6_dst("2001:db8::2"),
        ..Default::default()
    }
    .build();
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(&out[0..6], &HOST_MAC);
}

// ========== NDP must never be fast-pathed ================================
//
// RFC 4861 §6.1.1/§7.1.1: receivers silently discard NS/NA/RS/RA whose
// hop limit is not 255. `forward_success` decrements the hop limit and
// rewrites the source MAC, so redirecting NDP breaks neighbor resolution
// on the segment. `local-prefix6` makes this reachable by installing the
// /128s that let host-to-host NDP resolve in FIB_V6.

const ICMPV6: u8 = 58;

/// Build an ICMPv6 packet of `icmp_type` toward `dst`, hop limit 255,
/// from an allowlisted source. Body is a plausible NS/NA shape:
/// 4 reserved bytes + a 16-byte target address.
fn icmpv6_pkt(icmp_type: u8, dst: &str) -> Vec<u8> {
    let mut body = vec![icmp_type, 0, 0, 0]; // type, code, checksum (unchecked by XDP)
    body.extend_from_slice(&[0, 0, 0, 0]); // reserved
    body.extend_from_slice(&v6_dst(dst)); // target address
    Ipv6TcpBuilder {
        dst_ip: v6_dst(dst),
        hop_limit: 255,
        next_hdr: ICMPV6,
        payload: body,
        ..Default::default()
    }
    .build()
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ndp_is_passed_untouched_even_when_fib_would_redirect() {
    let mut h = prep_custom_fib_harness();
    h.add_allow_v6("2001:db8::/32");
    // A /128 for the destination: without the guard this would redirect.
    h.add_nexthop_v6(2, LO_IFINDEX, EGRESS_MAC, HOST_MAC);
    h.add_fib_v6_single("2001:db8::2/128", 2);

    // 135 = Neighbor Solicitation, 136 = Neighbor Advertisement.
    // 133/134 (RS/RA) and 137 (Redirect) take the same path.
    for icmp_type in [133u8, 134, 135, 136, 137] {
        let pkt = icmpv6_pkt(icmp_type, "2001:db8::2");
        let before_ndp = h.stat(StatIdx::PassNdp);
        let before_hit = h.stat(StatIdx::CustomFibHit);
        let before_matched = h.stat(StatIdx::MatchedV6);

        let (verdict, out) = h.run(&pkt);

        assert_eq!(
            verdict,
            xdp_action::XDP_PASS,
            "ICMPv6 type {icmp_type} must be passed to the kernel"
        );
        assert_eq!(
            h.stat(StatIdx::PassNdp),
            before_ndp + 1,
            "type {icmp_type} must bump pass_ndp"
        );
        assert_eq!(
            h.stat(StatIdx::CustomFibHit),
            before_hit,
            "type {icmp_type} must not reach the FIB"
        );
        assert_eq!(
            h.stat(StatIdx::MatchedV6),
            before_matched,
            "type {icmp_type} is gated before the allowlist, so must not count as matched"
        );
        // Byte-identity is the assertion that actually matters: hop
        // limit still 255 and MACs untouched, so the receiver will
        // accept it.
        assert_eq!(out, pkt, "type {icmp_type} must be delivered unmodified");
        assert_eq!(out[21], 255, "hop limit must not be decremented");
    }
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn ndp_guard_does_not_deoptimize_other_icmpv6_or_tcp() {
    let mut h = prep_custom_fib_harness();
    h.add_allow_v6("2001:db8::/32");
    h.add_nexthop_v6(2, LO_IFINDEX, EGRESS_MAC, HOST_MAC);
    h.add_fib_v6_single("2001:db8::2/128", 2);

    // ICMPv6 echo request (128) is not an NDP type; it must still
    // fast-path even at hop limit 255. This is why the guard keys on
    // message type rather than `hop_limit == 255`.
    let pkt = icmpv6_pkt(128, "2001:db8::2");
    let before_ndp = h.stat(StatIdx::PassNdp);
    let (verdict, out) = h.run(&pkt);
    assert_eq!(
        verdict,
        xdp_action::XDP_REDIRECT,
        "echo must still redirect"
    );
    assert_eq!(&out[0..6], &HOST_MAC);
    assert_eq!(
        h.stat(StatIdx::PassNdp),
        before_ndp,
        "echo must not bump pass_ndp"
    );

    // And ordinary TCP to the same destination is unaffected.
    let pkt = Ipv6TcpBuilder {
        dst_ip: v6_dst("2001:db8::2"),
        ..Default::default()
    }
    .build();
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(&out[0..6], &HOST_MAC);
}

// ========== Custom-FIB hit with incomplete neighbor =======================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn custom_fib_v4_incomplete_nexthop_returns_noneigh() {
    let mut h = prep_custom_fib_harness();
    h.add_allow_v4("10.0.0.0/8");
    // Write the nexthop resolved first, then flip to incomplete, this
    // exercises the code path where the seqlock discipline is
    // respected (even `seq`) but `state != Resolved`.
    h.add_nexthop_v4(1, LO_IFINDEX, EGRESS_MAC, NEXTHOP_MAC);
    h.set_nexthop_state(1, NH_STATE_INCOMPLETE);
    h.add_fib_v4_single("10.0.0.0/24", 1);

    let pkt = Ipv4TcpBuilder {
        src_ip: [10, 0, 0, 5],
        dst_ip: [10, 0, 0, 42],
        ..Default::default()
    }
    .build();

    let before_no_neigh = h.stat(StatIdx::CustomFibNoNeigh);
    let before_fwd = h.stat(StatIdx::FwdOk);
    let before_retry = h.stat(StatIdx::NexthopSeqRetry);
    let before_cache_miss = h.stat(StatIdx::NeighCacheMiss);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS, "incomplete → PASS");
    assert_eq!(h.stat(StatIdx::CustomFibNoNeigh), before_no_neigh + 1);
    assert_eq!(h.stat(StatIdx::FwdOk), before_fwd, "no forward on NoNeigh");
    // A stably-unresolved entry is NOT a torn read: the seqlock split
    // must short-circuit without burning the retry budget. Earlier
    // versions bumped NexthopSeqRetry 4× here, inflating the counter
    // to ~4× the custom_fib_no_neigh rate in production and masking
    // genuine churn.
    assert_eq!(
        h.stat(StatIdx::NexthopSeqRetry),
        before_retry,
        "stable not-Resolved read must not count as a seqlock retry"
    );
    assert_eq!(h.stat(StatIdx::NeighCacheMiss), before_cache_miss + 1);
}

// ========== ECMP distribution =============================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn custom_fib_v4_ecmp_splits_across_legs() {
    let mut h = prep_custom_fib_harness();
    h.add_allow_v4("10.0.0.0/8");
    // Two resolved nexthops with distinct MACs; forward verdict reveals
    // which one the program picked via the rewritten dst MAC.
    let dmac_a: [u8; 6] = [0xaa, 0, 0, 0, 0, 0x01];
    let dmac_b: [u8; 6] = [0xbb, 0, 0, 0, 0, 0x02];
    h.add_nexthop_v4(1, LO_IFINDEX, EGRESS_MAC, dmac_a);
    h.add_nexthop_v4(2, LO_IFINDEX, EGRESS_MAC, dmac_b);
    h.add_ecmp_group(0, 5, &[1, 2]);
    h.add_fib_v4_ecmp("10.0.0.0/24", 0);

    // Feed 64 distinct 5-tuples (varying src port) and tally which
    // nexthop each hashed to. With jhash + 2 legs, distribution should
    // be roughly 32:32; we accept anything in [16, 48] as "not
    // degenerate". Tightening this is a statistical test we don't
    // need here.
    let mut a_count = 0u32;
    let mut b_count = 0u32;
    for sport in 1000u16..1064u16 {
        let pkt = Ipv4TcpBuilder {
            src_ip: [10, 0, 0, 5],
            dst_ip: [10, 0, 0, 42],
            src_port: sport,
            ..Default::default()
        }
        .build();
        let (verdict, out) = h.run(&pkt);
        assert_eq!(verdict, xdp_action::XDP_REDIRECT, "sport={sport}");
        let got_dmac: [u8; 6] = out[0..6].try_into().unwrap();
        if got_dmac == dmac_a {
            a_count += 1;
        } else if got_dmac == dmac_b {
            b_count += 1;
        } else {
            panic!("unexpected dst MAC {got_dmac:02x?} for sport={sport}");
        }
    }
    assert_eq!(a_count + b_count, 64);
    assert!(
        (16..=48).contains(&a_count) && (16..=48).contains(&b_count),
        "ECMP distribution degenerate: a={a_count} b={b_count}"
    );
}

// ========== ECMP dead-leg fallover ========================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn custom_fib_v4_ecmp_dead_leg_falls_over() {
    let mut h = prep_custom_fib_harness();
    h.add_allow_v4("10.0.0.0/8");
    let dmac_live: [u8; 6] = [0xaa, 0, 0, 0, 0, 0x01];
    let dmac_dead: [u8; 6] = [0xbb, 0, 0, 0, 0, 0x02];
    h.add_nexthop_v4(1, LO_IFINDEX, EGRESS_MAC, dmac_live);
    h.add_nexthop_v4(2, LO_IFINDEX, EGRESS_MAC, dmac_dead);
    // Mark nexthop 2 as incomplete, fallover should walk to NH 1.
    h.set_nexthop_state(2, NH_STATE_INCOMPLETE);
    h.add_ecmp_group(0, 5, &[1, 2]);
    h.add_fib_v4_ecmp("10.0.0.0/24", 0);

    let before_fallback = h.stat(StatIdx::EcmpDeadLegFallback);

    // Feed 32 5-tuples. With 2 legs and one dead, every packet must
    // land on NH 1 after the fallover. `EcmpDeadLegFallback` bumps
    // only when we *advance past index 0*, i.e. when the hash picked
    // the dead leg first. With uniform hashing, that's ~50% of packets.
    let mut live = 0;
    for sport in 1000u16..1032u16 {
        let pkt = Ipv4TcpBuilder {
            src_ip: [10, 0, 0, 5],
            dst_ip: [10, 0, 0, 42],
            src_port: sport,
            ..Default::default()
        }
        .build();
        let (verdict, out) = h.run(&pkt);
        assert_eq!(verdict, xdp_action::XDP_REDIRECT);
        let got: [u8; 6] = out[0..6].try_into().unwrap();
        assert_eq!(got, dmac_live, "dead leg should never be chosen");
        live += 1;
    }
    assert_eq!(live, 32);
    // At least some packets took the fallover path (hashed to dead
    // leg initially); 32 all mapping to the live leg without ever
    // touching dead would mean the hash is degenerate.
    assert!(
        h.stat(StatIdx::EcmpDeadLegFallback) > before_fallback,
        "expected some dead-leg fallover bumps"
    );
}

// ========== Seqlock torn-read =============================================

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn custom_fib_seqlock_permanent_odd_drains_retries() {
    // If NEXTHOPS[idx].seq is permanently odd, the 4-retry budget
    // exhausts and the XDP program returns NoNeigh. Useful as a
    // regression guard for the verifier-bounded retry unroll.
    let mut h = prep_custom_fib_harness();
    h.add_allow_v4("10.0.0.0/8");
    h.add_nexthop_v4(1, LO_IFINDEX, EGRESS_MAC, NEXTHOP_MAC);
    // Force seq to an odd value and leave it there, no even follow-up.
    set_nexthop_seq_permanent_odd(&mut h, 1);
    h.add_fib_v4_single("10.0.0.0/24", 1);

    let pkt = Ipv4TcpBuilder {
        src_ip: [10, 0, 0, 5],
        dst_ip: [10, 0, 0, 42],
        ..Default::default()
    }
    .build();

    let before_retry = h.stat(StatIdx::NexthopSeqRetry);
    let before_cache_miss = h.stat(StatIdx::NeighCacheMiss);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS, "odd seq → NoNeigh → PASS");
    // 4 retries, each bumping NexthopSeqRetry, then NeighCacheMiss
    // bumps once to close out.
    assert!(
        h.stat(StatIdx::NexthopSeqRetry) >= before_retry + 4,
        "expected 4 retry bumps, got {}",
        h.stat(StatIdx::NexthopSeqRetry) - before_retry
    );
    assert_eq!(
        h.stat(StatIdx::NeighCacheMiss),
        before_cache_miss + 1,
        "expected NeighCacheMiss bump"
    );
}

/// Force `NEXTHOPS[idx].seq` to stay odd across userspace writes
/// simulates a writer that's stuck mid-update. Uses the raw Array
/// handle so we can poke `seq` without the `add_nexthop_*` helpers'
/// odd→even finalization.
fn set_nexthop_seq_permanent_odd(h: &mut Harness, idx: u32) {
    let map = h.bpf.map_mut("NEXTHOPS").expect("NEXTHOPS map");
    let mut arr: Array<_, NexthopEntry> = Array::try_from(map).expect("NEXTHOPS try_from");
    let mut entry: NexthopEntry = arr.get(&idx, 0).expect("NEXTHOPS get");
    entry.seq = 0xdead_beef; // odd (low bit 1)
    arr.set(idx, entry, 0).expect("NEXTHOPS set");
}
