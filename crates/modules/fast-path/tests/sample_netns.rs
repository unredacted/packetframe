//! The flow-export sampler on real traffic: frames injected into a veth,
//! seen by the fast path attached at the other end, read back from the
//! ring. What TEST_RUN cannot show (`sample_fixtures.rs`): samples
//! from a live attach, and the tc hook's view of a tag the kernel has
//! lifted into skb metadata.
//!
//! Each test runs on one CPU in a network namespace of its own
//! (`enter_routed_netns`), so names are fixed and veth delivery happens
//! on the injecting CPU. IPv6 is off on the veths: nothing but the
//! injected frames crosses them.
//!
//! Requires CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN; CI runs it under
//! sudo via `--ignored`.

#![cfg(target_os = "linux")]

mod common;

use std::ffi::CString;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

use aya::programs::{
    tc::{self, SchedClassifier, TcAttachType},
    xdp::XdpFlags,
    Xdp,
};
use common::{
    enter_routed_netns, insert_vlan_tag, on_one_cpu, parse_sample, Disposition, Harness,
    Ipv4TcpBuilder, SamplePath, SampleTap, StatIdx,
};

const HEADER_BYTES: u32 = 128;
const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0x5e, 0x20];

fn ip(args: &[&str]) {
    let st = Command::new("ip").args(args).status().expect("spawn ip");
    assert!(st.success(), "ip {args:?}");
}

/// A veth pair `pfa` (the fast path's port) ↔ `pfb` (where frames are
/// injected), both up, IPv6 off. Returns `(pfa ifindex, pfa MAC, pfb
/// ifindex)`.
fn veth() -> (u32, [u8; 6], u32) {
    for f in ["all", "default"] {
        std::fs::write(format!("/proc/sys/net/ipv6/conf/{f}/disable_ipv6"), "1")
            .expect("disable_ipv6");
    }
    ip(&["link", "add", "pfa", "type", "veth", "peer", "name", "pfb"]);
    ip(&["link", "set", "pfa", "address", "02:00:00:00:5e:10", "up"]);
    ip(&["link", "set", "pfb", "up"]);
    (ifindex("pfa"), [0x02, 0, 0, 0, 0x5e, 0x10], ifindex("pfb"))
}

fn ifindex(name: &str) -> u32 {
    let c = CString::new(name).unwrap();
    let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
    assert_ne!(i, 0, "if_nametoindex({name})");
    i
}

/// A raw socket that sends whole Ethernet frames out of `ifindex`.
fn injector(ifindex: u32) -> OwnedFd {
    let proto = 0x0003u16.to_be(); // ETH_P_ALL
    let fd = unsafe { libc::socket(libc::PF_PACKET, libc::SOCK_RAW, i32::from(proto)) };
    assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = proto;
    sll.sll_ifindex = ifindex as i32;
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind: {}", std::io::Error::last_os_error());
    fd
}

fn send(fd: &OwnedFd, frame: &[u8]) {
    let n = unsafe { libc::send(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
    assert_eq!(
        n,
        frame.len() as isize,
        "send: {}",
        std::io::Error::last_os_error()
    );
}

/// Drain until `want` events arrived or a second passed.
fn collect(tap: &mut SampleTap, want: usize) -> Vec<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut out = Vec::new();
    while out.len() < want && Instant::now() < deadline {
        out.extend(tap.events());
        std::thread::sleep(Duration::from_millis(10));
    }
    out.extend(tap.events());
    out
}

fn frame(port_mac: [u8; 6], dst_ip: [u8; 4], payload: usize) -> Vec<u8> {
    Ipv4TcpBuilder {
        src_mac: PEER_MAC,
        dst_mac: port_mac,
        src_ip: [192, 0, 2, 10],
        dst_ip,
        payload: vec![0x5a; payload],
        ..Default::default()
    }
    .build()
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn xdp_samples_real_traffic_from_a_veth() {
    on_one_cpu(|| {
        let egress = enter_routed_netns();
        let (pfa, pfa_mac, pfb) = veth();
        // kernel-fib: the namespace's route forwards 198.51.100.0/24 to
        // the dummy.
        let mut h = Harness::new();
        h.add_rx_mac(pfa, pfa_mac);
        h.add_allow_v4("198.51.100.0/24");
        h.add_devmap_ifindex(egress);
        {
            let prog: &mut Xdp = h.bpf.program_mut("fast_path").unwrap().try_into().unwrap();
            prog.attach_to_if_index(pfa, XdpFlags::SKB_MODE)
                .expect("attach generic XDP");
        }
        let mut tap = h.sample_tap();
        h.set_sample_cfg(1, HEADER_BYTES, 9);
        let out = injector(pfb);

        let routed = frame(pfa_mac, [198, 51, 100, 7], 400);
        let unmatched = frame(pfa_mac, [203, 0, 113, 7], 0);
        // Generic XDP runs before the kernel lifts a tag into metadata:
        // it sees the tag inline.
        let tagged = insert_vlan_tag(&unmatched, 100);
        // The first frame arms the countdown; every one after is a sample.
        send(&out, &unmatched);
        let mut sent = Vec::new();
        for _ in 0..20 {
            sent.push(routed.clone());
        }
        sent.push(unmatched.clone());
        sent.push(tagged.clone());
        for f in &sent {
            send(&out, f);
        }

        let events = collect(&mut tap, sent.len());
        assert_eq!(
            events.len(),
            sent.len(),
            "one sample per frame after the first"
        );
        assert_eq!(h.stat(StatIdx::SampleSelected), sent.len() as u64);
        assert_eq!(h.stat(StatIdx::SampleEmitFailed), 0);
        let mut redirects = 0;
        for (e, f) in events.iter().zip(&sent) {
            let s = parse_sample(e).unwrap();
            assert_eq!((s.generation, s.rate), (9, 1));
            assert_eq!((s.path, s.ingress_ifindex), (SamplePath::Xdp, pfa));
            assert_eq!(s.frame_len as usize, f.len());
            assert_eq!(s.header, &f[..f.len().min(HEADER_BYTES as usize)]);
            assert_eq!(s.vlan, None);
            if s.disposition == Disposition::Redirect {
                assert_eq!(s.egress_ifindex, egress);
                redirects += 1;
            } else {
                assert_eq!((s.disposition, s.egress_ifindex), (Disposition::Pass, 0));
            }
        }
        assert_eq!(redirects, 20);
        assert_eq!(h.stat(StatIdx::FwdOk), 20, "forwarded, not just sampled");
    });
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn tc_samples_carry_a_tag_the_kernel_lifted() {
    on_one_cpu(|| {
        enter_routed_netns();
        let (pfa, pfa_mac, pfb) = veth();
        let mut h = Harness::new();
        h.set_packetframe_fib(true, false);
        h.add_rx_mac(pfa, pfa_mac);
        let _ = tc::qdisc_add_clsact("pfa");
        {
            let prog: &mut SchedClassifier = h
                .bpf
                .program_mut("tc_fast_path")
                .unwrap()
                .try_into()
                .unwrap();
            prog.attach("pfa", TcAttachType::Ingress)
                .expect("attach tc ingress");
        }
        let mut tap = h.sample_tap();
        h.set_sample_cfg(1, HEADER_BYTES, 2);
        let out = injector(pfb);

        let plain = frame(pfa_mac, [203, 0, 113, 7], 0);
        send(&out, &plain);
        // VID 100 with PCP 3, and a priority tag (VID 0, PCP 5): by tc
        // time both are skb metadata, gone from the bytes.
        let tagged = |tci: u16| {
            let mut f = insert_vlan_tag(&plain, 0);
            f[14..16].copy_from_slice(&tci.to_be_bytes());
            f
        };
        let sent = [tagged(0x6064), tagged(0xa000), plain.clone()];
        for f in &sent {
            send(&out, f);
        }

        let events = collect(&mut tap, sent.len());
        assert_eq!(events.len(), sent.len());
        let s: Vec<_> = events.iter().map(|e| parse_sample(e).unwrap()).collect();
        for s in &s {
            assert_eq!((s.path, s.ingress_ifindex), (SamplePath::Tc, pfa));
            assert_eq!(s.disposition, Disposition::Pass);
            // The bytes are the untagged frame; the tag is in the record.
            assert_eq!(s.header, &plain[..]);
            assert_eq!(s.frame_len as usize, plain.len());
        }
        let tags: Vec<_> = s.iter().map(|s| s.vlan.map(|v| (v.proto, v.tci))).collect();
        assert_eq!(tags, [Some((0x8100, 0x6064)), Some((0x8100, 0xa000)), None]);
    });
}
