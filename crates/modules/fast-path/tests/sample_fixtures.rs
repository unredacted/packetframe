//! Fixtures for the flow-export sampler inside the fast-path ELF
//! (`bpf/src/sample.rs`), via `BPF_PROG_TEST_RUN` with the ring read
//! back: what is selected, what each sample says, and that a packet is
//! emitted exactly once however its forwarding ends.
//!
//! Each test runs on one CPU (the countdown is per-CPU) in a network
//! namespace of its own whose kernel FIB routes 198.51.100.0/24 out of a
//! dummy device, so kernel-fib forwards for real and both FIB modes take
//! the same packet the same way. The tc datapath is packetframe-fib only.
//!
//! finalize and tc_finalize have no emission point, so a failure there
//! (VLAN choreography, the redirect itself) cannot emit a second time;
//! TEST_RUN cannot force those failures, and the empty tail-call slot
//! stands in for all of them: the sample was taken, and nothing after it
//! emits.
//!
//! Every test is `#[ignore]`: CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN and
//! a BPF build; CI runs them under sudo.

#![cfg(target_os = "linux")]

mod common;

use common::{
    enter_routed_netns, insert_vlan_tag, on_one_cpu, parse_sample, tc_action, xdp_action,
    Disposition, Harness, Ipv4TcpBuilder, Ipv6TcpBuilder, Sample, SamplePath, SampleTap, StatIdx,
    FP_CFG_FLAG_BLOCK_PRESENT, FP_CFG_FLAG_IPV4, FP_CFG_FLAG_IPV6, FP_CFG_FLAG_PACKETFRAME_FIB,
    FP_CFG_FLAG_VLAN_PRESENT, TEST_RUN_INGRESS_IFINDEX,
};

const ROUTER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x5e, 0x10];
const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x5e, 0x20];
/// packetframe-fib's source MAC toward the dummy.
const EGRESS_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x5e, 0x30];
/// The routed netns's next hop (`enter_routed_netns`).
const NEXTHOP_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x5e, 0x01];
const HEADER_BYTES: u32 = 64;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fib {
    Kernel,
    Packetframe,
}

const BOTH: [Fib; 2] = [Fib::Kernel, Fib::Packetframe];

/// A harness forwarding 198.51.100.0/24 to `egress` in `fib` mode, every
/// redirect pre-check passing.
fn forwarding(fib: Fib, egress: u32) -> Harness {
    let mut h = unchecked(fib, egress);
    h.add_devmap_ifindex(egress);
    h.add_tc_redirect_target(egress);
    h
}

/// As [`forwarding`] but with neither redirect pre-check's map filled.
fn unchecked(fib: Fib, egress: u32) -> Harness {
    let mut h = Harness::new();
    h.add_rx_mac(TEST_RUN_INGRESS_IFINDEX, ROUTER_MAC);
    h.add_allow_v4("198.51.100.0/24");
    if fib == Fib::Packetframe {
        h.set_packetframe_fib(true, false);
        h.set_fib_hash_mode(5);
        h.add_nexthop_v4(1, egress, EGRESS_MAC, NEXTHOP_MAC);
        h.add_fib_v4_single("198.51.100.0/24", 1);
    }
    h
}

fn base_flags(fib: Fib) -> u8 {
    match fib {
        Fib::Kernel => FP_CFG_FLAG_IPV4 | FP_CFG_FLAG_IPV6,
        Fib::Packetframe => FP_CFG_FLAG_IPV4 | FP_CFG_FLAG_IPV6 | FP_CFG_FLAG_PACKETFRAME_FIB,
    }
}

/// An allowlisted frame to 198.51.100.7, routed.
fn routed(payload: usize) -> Vec<u8> {
    Ipv4TcpBuilder {
        src_mac: PEER_MAC,
        dst_mac: ROUTER_MAC,
        src_ip: [192, 0, 2, 10],
        dst_ip: [198, 51, 100, 7],
        payload: vec![0xa5; payload],
        ..Default::default()
    }
    .build()
}

/// A frame no allowlist entry matches: handed to the kernel untouched,
/// so it is the same on every repeat of one TEST_RUN.
fn unmatched() -> Vec<u8> {
    Ipv4TcpBuilder {
        src_mac: PEER_MAC,
        dst_mac: ROUTER_MAC,
        src_ip: [192, 0, 2, 10],
        dst_ip: [203, 0, 113, 7],
        ..Default::default()
    }
    .build()
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Hook {
    Xdp,
    Tc,
}

fn run(h: &Harness, hook: Hook, pkt: &[u8]) -> (u32, Vec<u8>) {
    match hook {
        Hook::Xdp => h.run(pkt),
        Hook::Tc => h.run_tc(pkt),
    }
}

fn parse(events: &[Vec<u8>]) -> Vec<Sample<'_>> {
    events
        .iter()
        .map(|e| parse_sample(e).expect("well-formed sample"))
        .collect()
}

/// Turn sampling on at 1-in-1 and spend the packet that arms the
/// countdown, so every packet after it is a sample.
fn every_packet(h: &mut Harness, hook: Hook, generation: u32) -> SampleTap {
    let mut tap = h.sample_tap();
    h.set_sample_cfg(1, HEADER_BYTES, generation);
    run(h, hook, &unmatched());
    assert!(tap.events().is_empty(), "the arming packet is not a sample");
    tap
}

/// The cases each test repeats: XDP in both FIB modes, and tc.
fn cases() -> [(Hook, Fib); 3] {
    [
        (Hook::Xdp, Fib::Kernel),
        (Hook::Xdp, Fib::Packetframe),
        (Hook::Tc, Fib::Packetframe),
    ]
}

fn path(hook: Hook) -> SamplePath {
    match hook {
        Hook::Xdp => SamplePath::Xdp,
        Hook::Tc => SamplePath::Tc,
    }
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn nothing_is_sampled_until_flow_export_sets_a_rate() {
    on_one_cpu(|| {
        let egress = enter_routed_netns();
        for fib in BOTH {
            let mut h = forwarding(fib, egress);
            let mut tap = h.sample_tap();
            h.run_timed(&unmatched(), 3000);
            for _ in 0..10 {
                assert_eq!(h.run(&routed(0)).0, xdp_action::XDP_REDIRECT, "{fib:?}");
            }
            assert!(tap.events().is_empty(), "{fib:?}");
            assert_eq!(h.stat(StatIdx::SampleSelected), 0);
            assert_eq!(h.stat(StatIdx::SampleArmed), 0);

            // Turned on, a CPU notices within its re-check interval (64
            // packets) wherever its countdown stood, arms on the next, and
            // samples every one after. 500 more first leave a 1024-packet
            // interval, the old one, far from its end.
            h.run_timed(&unmatched(), 500);
            h.set_sample_cfg(1, HEADER_BYTES, 3);
            let mut waited = 0;
            while tap.events().is_empty() {
                waited += 1;
                assert!(waited <= 65, "{fib:?}: no sample within {waited} packets");
                h.run(&unmatched());
            }
            h.run_timed(&unmatched(), 200);
            assert_eq!(tap.events().len(), 200, "{fib:?}");
            assert_eq!(h.stat(StatIdx::SampleSelected), 201);
        }
    });
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn one_packet_in_n_is_selected_on_average() {
    on_one_cpu(|| {
        let egress = enter_routed_netns();
        for (hook, fib) in cases() {
            let mut h = forwarding(fib, egress);
            let mut tap = h.sample_tap();
            h.set_sample_cfg(10, HEADER_BYTES, 4);
            let pkt = routed(0);
            let mut samples = 0usize;
            // Single runs: a forwarded frame is rewritten, so a repeated
            // TEST_RUN would stop matching after the first pass.
            for i in 0..10_000 {
                run(&h, hook, &pkt);
                if i % 250 == 249 {
                    let events = tap.events();
                    for s in parse(&events) {
                        assert_eq!((s.generation, s.rate), (4, 10));
                        assert_eq!(s.disposition, Disposition::Redirect);
                        assert_eq!(s.egress_ifindex, egress);
                        assert_eq!(s.path, path(hook));
                    }
                    samples += events.len();
                }
            }
            // Gaps uniform on [1, 19]: mean 10, so ~1000 of 10 000, with a
            // standard deviation near 17.
            assert!(
                (900..=1100).contains(&samples),
                "{hook:?}/{fib:?}: {samples}"
            );
            assert_eq!(h.stat(StatIdx::SampleSelected), samples as u64);
            assert_eq!(h.stat(StatIdx::SampleEmitFailed), 0);
        }
    });
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn a_sample_carries_the_rate_it_was_drawn_at() {
    on_one_cpu(|| {
        let egress = enter_routed_netns();
        for (hook, fib) in cases() {
            let mut h = forwarding(fib, egress);
            let mut tap = every_packet(&mut h, hook, 5);
            let pkt = routed(0);
            let mut drawn = Vec::new();
            let mut step = |h: &Harness, tap: &mut SampleTap| {
                run(h, hook, &pkt);
                let events = tap.events();
                drawn.extend(parse(&events).iter().map(|s| (s.generation, s.rate)));
            };
            step(&h, &mut tap);
            // The countdown in flight was drawn at generation 5: its
            // sample says so, and the next one is drawn at 6.
            h.set_sample_cfg(1, HEADER_BYTES, 6);
            step(&h, &mut tap);
            step(&h, &mut tap);
            // Off: the countdown already drawn still delivers its sample,
            // then nothing.
            h.set_sample_cfg(0, HEADER_BYTES, 7);
            for _ in 0..5 {
                step(&h, &mut tap);
            }
            assert_eq!(drawn, [(5, 1), (5, 1), (6, 1), (6, 1)], "{hook:?}/{fib:?}");
        }
    });
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn the_sample_is_the_frame_as_received() {
    on_one_cpu(|| {
        let egress = enter_routed_netns();
        for (hook, fib) in cases() {
            let mut h = forwarding(fib, egress);
            let mut tap = every_packet(&mut h, hook, 1);
            for payload in [200, 0] {
                let pkt = routed(payload);
                let (verdict, out) = run(&h, hook, &pkt);
                let redirected = match hook {
                    Hook::Xdp => xdp_action::XDP_REDIRECT,
                    Hook::Tc => tc_action::TC_ACT_REDIRECT,
                };
                assert_eq!(verdict, redirected, "{hook:?}/{fib:?}");
                assert_eq!(&out[0..6], &NEXTHOP_MAC, "the frame forwarded is rewritten");
                let events = tap.events();
                let s = parse(&events);
                assert_eq!(s.len(), 1);
                let s = &s[0];
                let captured = pkt.len().min(HEADER_BYTES as usize);
                assert_eq!(s.header, &pkt[..captured], "{hook:?}/{fib:?} {payload}");
                assert_eq!(s.frame_len as usize, pkt.len());
                assert_eq!(s.ingress_ifindex, TEST_RUN_INGRESS_IFINDEX);
                assert_eq!(s.egress_ifindex, egress);
                assert_eq!(s.vlan, None);
                assert!(s.ktime_ns > 0);
            }

            // IPv6 the kernel is handed: sampled all the same.
            let v6 = Ipv6TcpBuilder {
                src_mac: PEER_MAC,
                dst_mac: ROUTER_MAC,
                ..Default::default()
            }
            .build();
            run(&h, hook, &v6);
            let events = tap.events();
            let s = parse(&events);
            assert_eq!(s.len(), 1);
            assert_eq!(s[0].header, &v6[..HEADER_BYTES as usize]);
            assert_eq!(s[0].disposition, Disposition::Pass);
            assert_eq!(s[0].egress_ifindex, 0);
        }
    });
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn a_failed_tail_call_does_not_emit_twice() {
    on_one_cpu(|| {
        let egress = enter_routed_netns();
        for (hook, fib) in cases() {
            let mut h = forwarding(fib, egress);
            h.clear_tail_call(match hook {
                Hook::Xdp => "MUTATION_PROGS",
                Hook::Tc => "TC_MUTATION_PROGS",
            });
            let mut tap = every_packet(&mut h, hook, 1);
            let pass = match hook {
                Hook::Xdp => xdp_action::XDP_PASS,
                Hook::Tc => tc_action::TC_ACT_OK,
            };
            let before = h.stat(StatIdx::ErrTailCall);
            for _ in 0..5 {
                assert_eq!(run(&h, hook, &routed(0)).0, pass);
            }
            assert_eq!(h.stat(StatIdx::ErrTailCall), before + 5);
            let events = tap.events();
            let s = parse(&events);
            assert_eq!(s.len(), 5, "{hook:?}/{fib:?}: one sample per packet");
            for s in s {
                // Taken at the redirect decision; the failure after it is
                // `err_tail_call`'s to report.
                assert_eq!(s.disposition, Disposition::Redirect);
                assert_eq!(s.egress_ifindex, egress);
            }
            assert_eq!(h.stat(StatIdx::SampleSelected), 5);
        }
    });
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn a_redirect_refused_before_rewrite_is_sampled_once_as_a_pass() {
    on_one_cpu(|| {
        let egress = enter_routed_netns();
        for (hook, fib) in cases() {
            // The egress is in neither REDIRECT_DEVMAP nor
            // TC_REDIRECT_TARGETS.
            let mut h = unchecked(fib, egress);
            let mut tap = every_packet(&mut h, hook, 1);
            let pkt = routed(0);
            let (_, out) = run(&h, hook, &pkt);
            assert_eq!(out, pkt);
            assert_eq!(h.stat(StatIdx::PassNotInDevmap), 1);
            let events = tap.events();
            let s = parse(&events);
            assert_eq!(s.len(), 1, "{hook:?}/{fib:?}");
            assert_eq!(
                (s[0].disposition, s[0].egress_ifindex),
                (Disposition::Pass, 0)
            );
        }
    });
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn an_mtu_fallback_is_sampled_once_as_a_pass() {
    on_one_cpu(|| {
        let egress = enter_routed_netns();
        // 1400 bytes of IP toward a 1280 MTU.
        let big = routed(1400 - 40);
        for (hook, fib) in cases() {
            let mut h = forwarding(fib, egress);
            let mut tap = every_packet(&mut h, hook, 1);
            let (_, out) = run(&h, hook, &big);
            let events = tap.events();
            let s = parse(&events);
            assert_eq!(s.len(), 1, "{hook:?}/{fib:?}");
            if (hook, fib) == (Hook::Xdp, Fib::Packetframe) {
                // XDP's packetframe-fib has no MTU check: it forwards.
                assert_eq!(s[0].disposition, Disposition::Redirect);
            } else {
                // kernel-fib's lookup and tc's bpf_check_mtu refuse it,
                // and the kernel gets it pristine.
                assert_eq!(out, big);
                assert_eq!(h.stat(StatIdx::PassFragNeeded), 1);
                assert_eq!(
                    (s[0].disposition, s[0].egress_ifindex),
                    (Disposition::Pass, 0)
                );
            }
            assert_eq!(s[0].frame_len as usize, big.len());
        }
    });
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn vlan_frames_are_sampled_once_as_received() {
    on_one_cpu(|| {
        let egress = enter_routed_netns();
        for (hook, fib) in cases() {
            // A tagged ingress frame, forwarded untagged: the sample holds
            // the tag inline, as it arrived (TEST_RUN never lifts a tag
            // into skb metadata; the veth test covers that).
            let mut h = forwarding(fib, egress);
            let mut tap = every_packet(&mut h, hook, 1);
            let tagged = insert_vlan_tag(&routed(0), 100);
            run(&h, hook, &tagged);
            let events = tap.events();
            let s = parse(&events);
            assert_eq!(s.len(), 1, "{hook:?}/{fib:?}");
            assert_eq!(s[0].disposition, Disposition::Redirect);
            assert_eq!(s[0].header, &tagged[..]);
            assert_eq!(s[0].frame_len as usize, tagged.len());
            assert_eq!(s[0].vlan, None);

            // The egress resolves as a VLAN device on a parent the redirect
            // cannot reach: refused before rewrite, sampled once.
            let mut h = forwarding(fib, egress);
            h.set_cfg_flags(base_flags(fib) | FP_CFG_FLAG_VLAN_PRESENT);
            h.add_vlan_resolve(egress, 0x7fff_0000, 100);
            let mut tap = every_packet(&mut h, hook, 1);
            run(&h, hook, &routed(0));
            let events = tap.events();
            let s = parse(&events);
            assert_eq!(s.len(), 1, "{hook:?}/{fib:?}");
            assert_eq!(s[0].disposition, Disposition::Pass);
            assert_eq!(h.stat(StatIdx::PassNotInDevmap), 1);
        }
    });
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn drops_and_unparsed_frames_are_sampled_too() {
    on_one_cpu(|| {
        let egress = enter_routed_netns();
        for (hook, fib) in cases() {
            let mut h = forwarding(fib, egress);
            h.add_block_v4("198.51.100.0/24");
            h.set_cfg_flags(base_flags(fib) | FP_CFG_FLAG_BLOCK_PRESENT);
            let mut tap = every_packet(&mut h, hook, 1);
            run(&h, hook, &routed(0));
            // A parse error, passed: cut inside the IPv4 header for XDP;
            // tc's TEST_RUN refuses that, so a tag with nothing after it.
            let runt = match hook {
                Hook::Xdp => routed(0)[..20].to_vec(),
                Hook::Tc => insert_vlan_tag(&routed(0), 100)[..16].to_vec(),
            };
            run(&h, hook, &runt);
            let events = tap.events();
            let s = parse(&events);
            assert_eq!(s.len(), 2, "{hook:?}/{fib:?}");
            assert_eq!(s[0].disposition, Disposition::Drop);
            assert_eq!(s[1].disposition, Disposition::Pass);
            assert_eq!(s[1].header, &runt[..]);
        }
    });
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn a_full_ring_counts_each_sample_it_refuses() {
    /// What 16 MiB holds: each entry is an 8-byte header and a 296-byte
    /// `SampleEvent`.
    const HOLDS: u32 = (16 << 20) / (8 + 296);
    on_one_cpu(|| {
        let mut h = forwarding(Fib::Packetframe, enter_routed_netns());
        let mut tap = every_packet(&mut h, Hook::Xdp, 1);
        // Passed untouched, so every repeat is the same sample.
        let pkt = unmatched();
        h.run_timed(&pkt, HOLDS + 1000);
        assert_eq!(h.stat(StatIdx::SampleSelected), u64::from(HOLDS) + 1000);
        assert_eq!(h.stat(StatIdx::SampleEmitFailed), 1000);
        let events = tap.events();
        assert_eq!(events.len(), HOLDS as usize);
        assert!(parse(&events).iter().all(|s| s.header == &pkt[..]));
        // Drained: room again.
        run(&h, Hook::Xdp, &pkt);
        assert_eq!(tap.events().len(), 1);
        assert_eq!(h.stat(StatIdx::SampleEmitFailed), 1000);
    });
}
