//! TEST_RUN fixtures for `guard_egress`: per-class verdicts, exact
//! counter attribution, GCRA burst/refill behavior, and the partition
//! invariant. No attach, no netns, no interfaces created — SAFE for
//! the on-router hardware-artifacts suite.
//!
//! Every test keys `GUARD_CFG` at `LO_IFINDEX` (TEST_RUN skbs resolve
//! to loopback; 5.15's ctx_in allowlist cannot fake ifindex). Every
//! test builds its own `Harness`, so counters and bucket state never
//! leak between tests.

#![cfg(target_os = "linux")]

mod common;

use std::time::Duration;

use common::{idx, Harness, FOREIGN_MAC, LO_IFINDEX, OWN_MAC, TC_ACT_OK, TC_ACT_SHOT};
use packetframe_guard::cfg::{ActionRule, GuardIfCfg, GuardIfaceRules, RateRule};

/// Skip-gate macro-in-a-fn: stub ELF means no BPF toolchain locally;
/// CI sets PACKETFRAME_BPF_REQUIRED so a stub is impossible there.
fn bpf_or_skip() -> bool {
    if !packetframe_guard::GUARD_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping guard fixture.");
        return false;
    }
    true
}

fn rate(rate: u32, per: Duration, burst: u32, monitor: bool) -> Option<RateRule> {
    Some(RateRule {
        rate,
        per,
        burst,
        monitor,
    })
}

/// Everything enabled, enforce, generous-but-depletable NDP budget.
fn full_enforce_cfg() -> GuardIfCfg {
    GuardIfCfg::compile(
        OWN_MAC,
        &GuardIfaceRules {
            arp_ns: rate(3, Duration::from_secs(60), 3, false),
            bcast_mcast: rate(2, Duration::from_secs(60), 2, false),
            lldp: Some(ActionRule { monitor: false }),
            foreign_src: Some(ActionRule { monitor: false }),
        },
    )
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn unicast_fast_exit_is_pristine_and_attributed() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    h.set_guard_cfg(LO_IFINDEX, full_enforce_cfg());
    let pkt = common::unicast_ipv4(OWN_MAC, [0x02, 0, 0, 0, 0, 9]);
    let before = h.snapshot();
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, TC_ACT_OK);
    assert_eq!(out, pkt, "the pass path must leave the packet pristine");
    let after = h.snapshot();
    assert_eq!(
        Harness::moved(&before, &after),
        vec!["total_egress", "pass_no_match"],
        "before={before:?} after={after:?}"
    );
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn no_cfg_and_version_skew_fail_open() {
    if !bpf_or_skip() {
        return;
    }
    // No entry at all.
    let h = Harness::new();
    let (verdict, _) = h.run(&common::lldp_frame(FOREIGN_MAC));
    assert_eq!(verdict, TC_ACT_OK);
    assert_eq!(h.stat(idx::PASS_NO_CFG), 1);

    // Entry with an unrecognized layout version: same fail-open exit,
    // even though every class says enforce.
    let mut h = Harness::new();
    let mut cfg = full_enforce_cfg();
    cfg.version = 99;
    h.set_guard_cfg(LO_IFINDEX, cfg);
    let (verdict, _) = h.run(&common::lldp_frame(FOREIGN_MAC));
    assert_eq!(verdict, TC_ACT_OK);
    assert_eq!(h.stat(idx::PASS_NO_CFG), 1);
    assert_eq!(h.stat(idx::LLDP_DROP), 0);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn foreign_src_enforce_drops_and_own_mac_passes() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    h.set_guard_cfg(LO_IFINDEX, full_enforce_cfg());
    let (verdict, _) = h.run(&common::unicast_ipv4(FOREIGN_MAC, [0x02, 0, 0, 0, 0, 9]));
    assert_eq!(verdict, TC_ACT_SHOT);
    assert_eq!(h.stat(idx::FOREIGN_DROP), 1);
    let (verdict, _) = h.run(&common::unicast_ipv4(OWN_MAC, [0x02, 0, 0, 0, 0, 9]));
    assert_eq!(verdict, TC_ACT_OK);
    assert_eq!(h.stat(idx::PASS_NO_MATCH), 1);
}

/// The one deliberate non-terminal counter: monitor-mode foreign-src
/// counts AND the frame continues into later classes — a foreign-MAC
/// ARP request must still spend an NDP token.
#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn foreign_monitor_continues_into_the_arp_limiter() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    h.set_guard_cfg(
        LO_IFINDEX,
        GuardIfCfg::compile(
            OWN_MAC,
            &GuardIfaceRules {
                arp_ns: rate(3, Duration::from_secs(60), 3, false),
                foreign_src: Some(ActionRule { monitor: true }),
                ..Default::default()
            },
        ),
    );
    let before = h.snapshot();
    let (verdict, _) = h.run(&common::arp_request(FOREIGN_MAC, [203, 0, 113, 7]));
    assert_eq!(verdict, TC_ACT_OK);
    let after = h.snapshot();
    assert_eq!(
        Harness::moved(&before, &after),
        vec!["total_egress", "arp_pass", "foreign_monitor"],
        "before={before:?} after={after:?}"
    );
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn lldp_enforce_monitor_and_disabled() {
    if !bpf_or_skip() {
        return;
    }
    // Enforce: SHOT.
    let mut h = Harness::new();
    h.set_guard_cfg(LO_IFINDEX, full_enforce_cfg());
    let (verdict, _) = h.run(&common::lldp_frame(OWN_MAC));
    assert_eq!(verdict, TC_ACT_SHOT);
    assert_eq!(h.stat(idx::LLDP_DROP), 1);

    // Monitor: counted, passed.
    let mut h = Harness::new();
    h.set_guard_cfg(
        LO_IFINDEX,
        GuardIfCfg::compile(
            OWN_MAC,
            &GuardIfaceRules {
                lldp: Some(ActionRule { monitor: true }),
                ..Default::default()
            },
        ),
    );
    let (verdict, out) = h.run(&common::lldp_frame(OWN_MAC));
    assert_eq!(verdict, TC_ACT_OK);
    assert_eq!(out, common::lldp_frame(OWN_MAC));
    assert_eq!(h.stat(idx::LLDP_MONITOR), 1);

    // Disabled: LLDP's multicast dst lands in the catch-all budget.
    let mut h = Harness::new();
    h.set_guard_cfg(
        LO_IFINDEX,
        GuardIfCfg::compile(
            OWN_MAC,
            &GuardIfaceRules {
                bcast_mcast: rate(10, Duration::from_secs(1), 10, false),
                ..Default::default()
            },
        ),
    );
    let (verdict, _) = h.run(&common::lldp_frame(OWN_MAC));
    assert_eq!(verdict, TC_ACT_OK);
    assert_eq!(h.stat(idx::MCAST_PASS), 1);
    assert_eq!(h.stat(idx::LLDP_DROP), 0);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn arp_burst_depletes_per_target_and_enforces() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    h.set_guard_cfg(LO_IFINDEX, full_enforce_cfg());
    let target_a = common::arp_request(OWN_MAC, [206, 81, 82, 21]);
    // Burst 3: three conforming requests pass...
    for i in 0..3 {
        let (verdict, _) = h.run(&target_a);
        assert_eq!(verdict, TC_ACT_OK, "burst frame {i} must pass");
    }
    assert_eq!(h.stat(idx::ARP_PASS), 3);
    // ...the fourth is non-conforming and enforced.
    let (verdict, _) = h.run(&target_a);
    assert_eq!(verdict, TC_ACT_SHOT);
    assert_eq!(h.stat(idx::ARP_DROP), 1);
    // A different target has its own budget.
    let (verdict, _) = h.run(&common::arp_request(OWN_MAC, [206, 81, 81, 10]));
    assert_eq!(verdict, TC_ACT_OK);
    assert_eq!(h.stat(idx::ARP_PASS), 4);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn arp_monitor_counts_would_drops_identically() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    h.set_guard_cfg(
        LO_IFINDEX,
        GuardIfCfg::compile(
            OWN_MAC,
            &GuardIfaceRules {
                arp_ns: rate(2, Duration::from_secs(60), 2, true),
                ..Default::default()
            },
        ),
    );
    let pkt = common::arp_request(OWN_MAC, [206, 81, 82, 21]);
    for _ in 0..2 {
        let (verdict, _) = h.run(&pkt);
        assert_eq!(verdict, TC_ACT_OK);
    }
    // Non-conforming under monitor: counted as would-drop, passed —
    // monitor counters exactly predict enforce behavior.
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, TC_ACT_OK);
    assert_eq!(h.stat(idx::ARP_PASS), 2);
    assert_eq!(h.stat(idx::ARP_MONITOR), 1);
    assert_eq!(h.stat(idx::ARP_DROP), 0);
}

/// One coarse refill test, deliberately loose (qemu TCG soft-locks on
/// tight timing; see fast-path bench.rs): 1 token per 100 ms, burst 1
/// — deplete, wait ~3 intervals, conform again.
#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn gcra_refills_after_the_interval() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    h.set_guard_cfg(
        LO_IFINDEX,
        GuardIfCfg::compile(
            OWN_MAC,
            &GuardIfaceRules {
                arp_ns: rate(10, Duration::from_secs(1), 1, false),
                ..Default::default()
            },
        ),
    );
    let pkt = common::arp_request(OWN_MAC, [206, 81, 82, 21]);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, TC_ACT_OK);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, TC_ACT_SHOT, "back-to-back at burst 1 must clamp");
    std::thread::sleep(Duration::from_millis(300));
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, TC_ACT_OK, "3 intervals later a token has accrued");
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn ns_is_classified_and_arp_replies_fall_through() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    h.set_guard_cfg(LO_IFINDEX, full_enforce_cfg());
    let mut target = [0u8; 16];
    target[0] = 0x20;
    target[1] = 0x01;
    target[15] = 0x21;
    let ns = common::ns_frame(OWN_MAC, target);
    for _ in 0..3 {
        let (verdict, _) = h.run(&ns);
        assert_eq!(verdict, TC_ACT_OK);
    }
    assert_eq!(h.stat(idx::NS_PASS), 3);
    let (verdict, _) = h.run(&ns);
    assert_eq!(verdict, TC_ACT_SHOT);
    assert_eq!(h.stat(idx::NS_DROP), 1);

    // An ARP reply is not a request: it lands in the catch-all
    // (broadcast dst), not the NDP buckets.
    let before = h.snapshot();
    let (verdict, _) = h.run(&common::arp_reply(OWN_MAC, [206, 81, 82, 21]));
    assert_eq!(verdict, TC_ACT_OK);
    let after = h.snapshot();
    assert_eq!(
        Harness::moved(&before, &after),
        vec!["total_egress", "mcast_pass"],
        "before={before:?} after={after:?}"
    );
}

/// Inline 802.1Q ARP exercises the fallback VLAN parse (TEST_RUN
/// never lifts the tag into skb metadata).
#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn vlan_tagged_arp_is_still_classified() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    h.set_guard_cfg(LO_IFINDEX, full_enforce_cfg());
    let tagged = common::insert_vlan_tag(&common::arp_request(OWN_MAC, [206, 81, 82, 21]), 3998);
    let (verdict, _) = h.run(&tagged);
    assert_eq!(verdict, TC_ACT_OK);
    assert_eq!(h.stat(idx::ARP_PASS), 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn truncated_arp_fails_open_with_its_own_counter() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    h.set_guard_cfg(LO_IFINDEX, full_enforce_cfg());
    // ARP ethertype, but the header is cut short of the 28-byte
    // minimum. Note the frame still passes foreign-src (own MAC) —
    // fail open means pass, attributed to err_parse_arp.
    let mut runt = common::arp_request(OWN_MAC, [206, 81, 82, 21]);
    runt.truncate(24);
    let (verdict, _) = h.run(&runt);
    assert_eq!(verdict, TC_ACT_OK);
    assert_eq!(h.stat(idx::ERR_PARSE_ARP), 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn mcast_catchall_depletes_and_monitors() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    h.set_guard_cfg(LO_IFINDEX, full_enforce_cfg());
    let pkt = common::broadcast_misc(OWN_MAC);
    for _ in 0..2 {
        let (verdict, _) = h.run(&pkt);
        assert_eq!(verdict, TC_ACT_OK);
    }
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, TC_ACT_SHOT);
    assert_eq!(h.stat(idx::MCAST_PASS), 2);
    assert_eq!(h.stat(idx::MCAST_DROP), 1);

    // Monitor flavor.
    let mut h = Harness::new();
    h.set_guard_cfg(
        LO_IFINDEX,
        GuardIfCfg::compile(
            OWN_MAC,
            &GuardIfaceRules {
                bcast_mcast: rate(1, Duration::from_secs(60), 1, true),
                ..Default::default()
            },
        ),
    );
    let (v1, _) = h.run(&pkt);
    let (v2, _) = h.run(&pkt);
    assert_eq!((v1, v2), (TC_ACT_OK, TC_ACT_OK));
    assert_eq!(h.stat(idx::MCAST_PASS), 1);
    assert_eq!(h.stat(idx::MCAST_MONITOR), 1);
}

/// The partition invariant over a mixed corpus: `total_egress` equals
/// the sum of the terminal counters (indices 1..=18); the sole
/// non-terminal counter (`foreign_monitor`) moves independently.
#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn every_frame_lands_in_exactly_one_terminal_counter() {
    if !bpf_or_skip() {
        return;
    }
    let mut h = Harness::new();
    let mut cfg = full_enforce_cfg();
    // foreign-src in monitor so the corpus exercises the non-terminal
    // counter too.
    cfg.act_foreign = packetframe_guard::cfg::ACTION_MONITOR;
    h.set_guard_cfg(LO_IFINDEX, cfg);

    let corpus: Vec<Vec<u8>> = vec![
        common::unicast_ipv4(OWN_MAC, [0x02, 0, 0, 0, 0, 9]),
        common::unicast_ipv4(FOREIGN_MAC, [0x02, 0, 0, 0, 0, 9]),
        common::lldp_frame(OWN_MAC),
        common::arp_request(OWN_MAC, [206, 81, 82, 21]),
        common::arp_request(OWN_MAC, [206, 81, 82, 21]),
        common::arp_request(OWN_MAC, [206, 81, 82, 21]),
        common::arp_request(OWN_MAC, [206, 81, 82, 21]), // 4th: clamp
        common::arp_request(FOREIGN_MAC, [206, 81, 81, 10]),
        common::arp_reply(OWN_MAC, [206, 81, 82, 21]),
        common::ns_frame(OWN_MAC, [0x20; 16]),
        common::broadcast_misc(OWN_MAC),
        {
            let mut runt = common::arp_request(OWN_MAC, [10, 0, 0, 1]);
            runt.truncate(20);
            runt
        },
    ];
    for pkt in &corpus {
        let _ = h.run(pkt);
    }
    let stats = h.snapshot();
    let terminal: u64 = stats[1..=18].iter().sum();
    assert_eq!(
        stats[idx::TOTAL_EGRESS],
        terminal,
        "partition broken: total={} terminal-sum={terminal} stats={stats:?}",
        stats[idx::TOTAL_EGRESS]
    );
    assert_eq!(stats[idx::TOTAL_EGRESS], corpus.len() as u64);
    assert!(
        stats[idx::FOREIGN_MONITOR] >= 2,
        "foreign frames in monitor must count without terminating: {stats:?}"
    );
}
