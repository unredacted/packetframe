//! Behavioral fixtures for the FpCfg feature-presence gate bits
//! (5-7): the XDP program skips BLOCK_V4/V6 and VLAN_RESOLVE lookups
//! when the corresponding bit is clear. These tests prove both
//! directions — bit set behaves exactly like the pre-gate program,
//! and bit clear really does bypass the map (by constructing states
//! where bypassing is observable in the verdict).
//!
//! The bit-clear-with-populated-map cases document the userspace
//! invariant rather than a supported configuration: production always
//! derives the bits from the same config that populates the maps
//! (`feature_flags_from_config` + the VLAN RMW fixups), so these
//! states are unreachable outside a test harness.

#![cfg(target_os = "linux")]

mod common;

use common::{
    xdp_action, Harness, Ipv4TcpBuilder, StatIdx, FP_CFG_FLAG_BLOCK_PRESENT,
    FP_CFG_FLAG_CUSTOM_FIB, FP_CFG_FLAG_IPV4, FP_CFG_FLAG_IPV6, FP_CFG_FLAG_VLAN_PRESENT,
};

const LO_IFINDEX: u32 = 1;
/// A fake VLAN-subif ifindex; deliberately NOT in the devmap so a
/// bypassed VLAN_RESOLVE lookup is observable as PassNotInDevmap.
const SUBIF_IFINDEX: u32 = 4242;
const BASE_FLAGS: u8 = FP_CFG_FLAG_IPV4 | FP_CFG_FLAG_IPV6 | FP_CFG_FLAG_CUSTOM_FIB;

/// Custom-fib forwarding scaffold: allowlisted /8, one resolved
/// nexthop pointing at `nh_ifindex`, loopback in the devmap.
fn forwarding_harness(nh_ifindex: u32) -> Harness {
    let mut h = Harness::new();
    h.add_allow_v4("10.0.0.0/8");
    h.add_nexthop_v4(
        0,
        nh_ifindex,
        [0x02, 0, 0, 0, 0, 0xee],
        [0x02, 0, 0, 0, 0, 0xff],
    );
    h.add_fib_v4_single("10.0.0.0/8", 0);
    h.add_devmap_ifindex(LO_IFINDEX);
    h
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn block_gate_set_drops_blocked_dst() {
    let mut h = forwarding_harness(LO_IFINDEX);
    h.add_block_v4("10.9.0.0/16");
    h.set_cfg_flags(BASE_FLAGS | FP_CFG_FLAG_BLOCK_PRESENT);

    let pkt = Ipv4TcpBuilder {
        dst_ip: [10, 9, 1, 1],
        ..Default::default()
    }
    .build();

    let before = h.stat(StatIdx::BogonDropped);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_DROP);
    assert_eq!(h.stat(StatIdx::BogonDropped), before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn block_gate_clear_bypasses_lookup() {
    // Same populated BLOCK_V4 trie, but the presence bit is clear: the
    // packet must forward as if the trie were empty, proving the gate
    // really skips the lookup rather than post-filtering its result.
    let mut h = forwarding_harness(LO_IFINDEX);
    h.add_block_v4("10.9.0.0/16");
    h.set_cfg_flags(BASE_FLAGS);

    let pkt = Ipv4TcpBuilder {
        dst_ip: [10, 9, 1, 1],
        ..Default::default()
    }
    .build();

    let dropped_before = h.stat(StatIdx::BogonDropped);
    let fwd_before = h.stat(StatIdx::FwdOk);
    let (verdict, _) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(h.stat(StatIdx::BogonDropped), dropped_before);
    assert_eq!(h.stat(StatIdx::FwdOk), fwd_before + 1);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn vlan_gate_set_resolves_subif_to_parent() {
    // Nexthop egress is a VLAN subif; VLAN_RESOLVE maps it to the
    // loopback parent (which IS in the devmap) with VID 66. With the
    // bit set, the packet forwards and finalize pushes the tag.
    let mut h = forwarding_harness(SUBIF_IFINDEX);
    h.add_vlan_resolve(SUBIF_IFINDEX, LO_IFINDEX, 66);
    h.set_cfg_flags(BASE_FLAGS | FP_CFG_FLAG_VLAN_PRESENT);

    let pkt = Ipv4TcpBuilder::default().build();
    let fwd_before = h.stat(StatIdx::FwdOk);
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_REDIRECT);
    assert_eq!(h.stat(StatIdx::FwdOk), fwd_before + 1);
    // VLAN push grew the frame by 4 and the 802.1Q TPID sits after
    // the MAC pair.
    assert_eq!(out.len(), pkt.len() + 4);
    assert_eq!(&out[12..14], &[0x81, 0x00]);
}

#[test]
#[ignore = "needs CAP_BPF + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn vlan_gate_clear_bypasses_resolve() {
    // Same VLAN_RESOLVE entry, bit clear: the program must treat the
    // subif ifindex as the raw egress. It is not in the devmap, so the
    // pre-check fires and the packet passes to the kernel pristine —
    // observable proof the map lookup was skipped.
    let mut h = forwarding_harness(SUBIF_IFINDEX);
    h.add_vlan_resolve(SUBIF_IFINDEX, LO_IFINDEX, 66);
    h.set_cfg_flags(BASE_FLAGS);

    let pkt = Ipv4TcpBuilder::default().build();
    let miss_before = h.stat(StatIdx::PassNotInDevmap);
    let (verdict, out) = h.run(&pkt);
    assert_eq!(verdict, xdp_action::XDP_PASS);
    assert_eq!(h.stat(StatIdx::PassNotInDevmap), miss_before + 1);
    assert_eq!(out, pkt, "pass-path packet must be pristine (§11.13)");
}
