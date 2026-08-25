//! End-to-end egress clamp test in a network namespace: attach
//! `guard_egress` on one end of a veth pair, blast ARP requests
//! through it via AF_PACKET (exactly how arping injects), and count
//! what actually reaches the peer.
//!
//! This is the test TEST_RUN cannot be: verdicts here are enforced by
//! the real clsact egress hook on a real device, keyed by the real
//! `skb->ifindex`, against frames a packet socket injected — the
//! production data path end to end.
//!
//! The netns/packet-socket helpers are duplicated from fast-path's
//! tests/netns.rs per that file's per-test-file convention (the
//! shared tests/common holds only the TEST_RUN harness).
//!
//! NOT in the hardware-artifacts SAFE suite: it creates a netns and
//! interfaces.

#![cfg(target_os = "linux")]

mod common;

use std::fs::File;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

use common::{idx, Harness, LO_IFINDEX};
use packetframe_guard::cfg::{GuardIfCfg, GuardIfaceRules, RateRule};
use packetframe_guard::tc_attach_egress;

struct Names {
    netns: String,
    veth_a: String,
    veth_b: String,
}

impl Names {
    fn new() -> Self {
        let suffix = std::process::id() % 10_000;
        Self {
            netns: format!("pfgn{suffix:04}"),
            veth_a: format!("pga{suffix:04}"),
            veth_b: format!("pgb{suffix:04}"),
        }
    }
}

/// RAII netns: Drop deletes the namespace, which destroys the veths
/// and, with them, the qdisc-lifetime egress filter.
struct NetnsGuard {
    name: String,
}

impl NetnsGuard {
    fn setup(names: &Names) -> Self {
        let _ = Command::new("ip")
            .args(["netns", "del", &names.netns])
            .status();
        run(&["ip", "netns", "add", &names.netns]);
        // Quiet the namespace: no IPv6 autoconf chatter (DAD NS, RS,
        // MLD) competing with the frames the test counts. Must run
        // before `ip link add` (default.* templates new ifaces).
        ns_run(
            &names.netns,
            &["sysctl", "-wq", "net.ipv6.conf.all.disable_ipv6=1"],
        );
        ns_run(
            &names.netns,
            &["sysctl", "-wq", "net.ipv6.conf.default.disable_ipv6=1"],
        );
        ns_run(
            &names.netns,
            &[
                "ip",
                "link",
                "add",
                &names.veth_a,
                "type",
                "veth",
                "peer",
                "name",
                &names.veth_b,
            ],
        );
        ns_run(&names.netns, &["ip", "link", "set", &names.veth_a, "up"]);
        ns_run(&names.netns, &["ip", "link", "set", &names.veth_b, "up"]);
        Self {
            name: names.netns.clone(),
        }
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", &self.name])
            .status();
    }
}

fn run(cmd: &[&str]) {
    let status = Command::new(cmd[0])
        .args(&cmd[1..])
        .status()
        .unwrap_or_else(|e| panic!("spawn `{}`: {e}", cmd.join(" ")));
    assert!(status.success(), "`{}` exited {status}", cmd.join(" "));
}

fn ns_run(netns: &str, cmd: &[&str]) {
    let mut args = vec!["netns", "exec", netns];
    args.extend_from_slice(cmd);
    let status = Command::new("ip")
        .args(&args)
        .status()
        .unwrap_or_else(|e| panic!("spawn `ip {}`: {e}", args.join(" ")));
    assert!(status.success(), "`ip {}` exited {status}", args.join(" "));
}

/// Move the current thread into the netns (`setns(2)` re-associates
/// only the calling thread).
fn enter_netns(netns: &str) -> OwnedFd {
    let path = format!("/var/run/netns/{netns}");
    let fd: OwnedFd = File::open(&path)
        .unwrap_or_else(|e| panic!("open {path}: {e}"))
        .into();
    let rc = unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(rc, 0, "setns({path}): {}", std::io::Error::last_os_error());
    fd
}

fn if_nametoindex(name: &str) -> u32 {
    let c = std::ffi::CString::new(name).expect("iface name with NUL");
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    assert!(idx > 0, "if_nametoindex({name}) failed");
    idx
}

fn open_packet_socket(ifindex: u32) -> OwnedFd {
    const ETH_P_ALL: u16 = 0x0003;
    let proto_be: u16 = ETH_P_ALL.to_be();
    let fd = unsafe { libc::socket(libc::PF_PACKET, libc::SOCK_RAW, proto_be as i32) };
    assert!(
        fd >= 0,
        "socket(PF_PACKET): {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: kernel returned a valid fd we now own.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = proto_be;
    sll.sll_ifindex = ifindex as i32;
    let rc = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "bind(PF_PACKET, ifindex={ifindex}): {}",
        std::io::Error::last_os_error()
    );
    owned
}

/// Send one frame. `true` = the device path accepted it; `false` =
/// the send failed with ENOBUFS, which at a guarded interface means
/// **the guard dropped it**: TC_ACT_SHOT at the clsact egress hook
/// makes `dev_queue_xmit` return `NET_XMIT_DROP`, and AF_PACKET's
/// `packet_snd` maps that to ENOBUFS (`net_xmit_errno`) — the drop is
/// reported to the local sender synchronously. This is the guard's
/// operator-visible fingerprint (a clamped daemon's own sendto fails)
/// and this test's own discovery: two earlier CI rounds misread it as
/// queue exhaustion, and a retry-until-accepted loop turned the
/// limiter into a pacer — every frame eventually earned a token and
/// 40/40 were delivered, with the ~680 retries counted as drops.
/// Any errno other than ENOBUFS still panics.
fn send_frame(fd: &OwnedFd, ifindex: u32, frame: &[u8]) -> bool {
    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_ifindex = ifindex as i32;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(&frame[0..6]);
    let sent = unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            frame.as_ptr() as *const _,
            frame.len(),
            0,
            &sll as *const _ as *const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if sent == frame.len() as isize {
        return true;
    }
    let err = std::io::Error::last_os_error();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOBUFS),
        "sendto: {err} (only ENOBUFS means policed)"
    );
    false
}

/// Count frames matching `is_ours` arriving within `window`,
/// discarding everything else the namespace emits.
fn recv_count(fd: &OwnedFd, window: Duration, is_ours: impl Fn(&[u8]) -> bool) -> usize {
    let deadline = Instant::now() + window;
    let mut count = 0usize;
    let mut buf = [0u8; 2048];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return count;
        }
        let remaining_ms = (deadline - now).as_millis().min(1000) as libc::c_int;
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, remaining_ms) };
        if rc <= 0 {
            return count; // timeout (or EINTR-adjacent noise): done
        }
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n > 0 && is_ours(&buf[..n as usize]) {
            count += 1;
        }
    }
}

/// `is_ours` for our crafted ARP requests: ARP ethertype + our tpa.
fn arp_for(target: [u8; 4]) -> impl Fn(&[u8]) -> bool {
    move |f: &[u8]| f.len() >= 42 && f[12..14] == [0x08, 0x06] && f[38..42] == target
}

const SRC_MAC: [u8; 6] = [0xaa, 0x00, 0x00, 0x00, 0x00, 0x01];

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn arp_storm_is_clamped_at_egress_and_monitor_passes() {
    if !packetframe_guard::GUARD_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping guard netns test.");
        return;
    }
    let names = Names::new();
    let _netns = NetnsGuard::setup(&names);
    let _ns_fd = enter_netns(&names.netns);

    let ifindex_a = if_nametoindex(&names.veth_a);
    let ifindex_b = if_nametoindex(&names.veth_b);
    assert_ne!(
        ifindex_a, LO_IFINDEX,
        "sanity: the guarded iface must not be loopback"
    );

    // Only the ARP/NS limiter, enforce: rate 5/1s burst 5 per target.
    // foreign-src stays disabled, so the expected-MAC fields are inert.
    let mut h = Harness::new();
    let rules = GuardIfaceRules {
        arp_ns: Some(RateRule {
            rate: 5,
            per: Duration::from_secs(1),
            burst: 5,
            monitor: false,
        }),
        ..Default::default()
    };
    h.set_guard_cfg(ifindex_a, GuardIfCfg::compile([0; 6], &rules));
    let (_priority, _handle) = tc_attach_egress(&mut h.bpf, &names.veth_a).expect("egress attach");

    let tx = open_packet_socket(ifindex_a);
    let rx = open_packet_socket(ifindex_b);

    // --- enforce: 40 same-target requests, back-to-back. Burst 5 is
    // accepted; every clamped frame is reported to the SENDER as an
    // ENOBUFS sendto failure (see send_frame) and never reaches the
    // peer. The loop takes ~ms against a 200 ms/token refill, so at
    // most a token or two beyond the burst can be legitimately earned.
    let target_a = [206, 81, 82, 21];
    let storm = common::arp_request(SRC_MAC, target_a);
    let accepted = (0..40)
        .filter(|_| send_frame(&tx, ifindex_a, &storm))
        .count() as u64;
    let delivered = recv_count(&rx, Duration::from_secs(2), arp_for(target_a)) as u64;
    // Assert the pipeline stages in order, each with the counter
    // snapshot, so a failure names WHERE it broke: program not in the
    // egress path (total_egress stuck), config lookup missing
    // (pass_no_cfg), or the limiter not clamping.
    let stats = h.snapshot();
    assert!(
        stats[idx::TOTAL_EGRESS] >= 40,
        "guard_egress did not run at real egress: stats={stats:?}"
    );
    assert_eq!(
        stats[idx::PASS_NO_CFG],
        0,
        "GUARD_CFG lookup missed at real egress (skb->ifindex vs written key?): stats={stats:?}"
    );
    assert!(
        (5..=8).contains(&accepted),
        "expected ~burst(5) of 40 sends accepted, got {accepted}; stats={stats:?}"
    );
    // The three views of the clamp must agree exactly: sender-visible
    // accepts == guard's pass counter == frames on the wire, and the
    // ENOBUFS-rejected remainder == the drop counter. The namespace is
    // quiet (no addresses, IPv6 off), so nothing else emits ARP.
    assert_eq!(
        stats[idx::ARP_PASS],
        accepted,
        "arp_pass must equal accepted sends: stats={stats:?}"
    );
    assert_eq!(
        stats[idx::ARP_DROP],
        40 - accepted,
        "arp_drop must equal ENOBUFS-rejected sends: stats={stats:?}"
    );
    assert_eq!(
        delivered, accepted,
        "every accepted frame and nothing else reaches the peer; stats={stats:?}"
    );

    // --- monitor: fresh target (fresh budget), same storm; every send
    // is accepted (no ENOBUFS — monitor never SHOTs), everything is
    // delivered, and the would-drops are counted.
    let rules_mon = GuardIfaceRules {
        arp_ns: Some(RateRule {
            rate: 5,
            per: Duration::from_secs(1),
            burst: 5,
            monitor: true,
        }),
        ..Default::default()
    };
    h.set_guard_cfg(ifindex_a, GuardIfCfg::compile([0; 6], &rules_mon));
    let target_b = [206, 81, 81, 10];
    let storm = common::arp_request(SRC_MAC, target_b);
    let accepted_mon = (0..40)
        .filter(|_| send_frame(&tx, ifindex_a, &storm))
        .count();
    assert_eq!(
        accepted_mon,
        40,
        "monitor mode must never reject a send: stats={:?}",
        h.snapshot()
    );
    let delivered = recv_count(&rx, Duration::from_secs(2), arp_for(target_b));
    assert!(
        delivered >= 35,
        "monitor mode must deliver the storm, got {delivered}/40"
    );
    assert!(
        h.stat(idx::ARP_MONITOR) >= 25,
        "monitor must count the would-drops: stats={:?}",
        h.snapshot()
    );

    // Unicast traffic through the guarded iface is untouched either
    // way (the fast exit): a plain IPv4 frame arrives.
    let unicast = common::unicast_ipv4(SRC_MAC, [0xaa, 0, 0, 0, 0, 2]);
    assert!(
        send_frame(&tx, ifindex_a, &unicast),
        "unicast send accepted"
    );
    let delivered = recv_count(&rx, Duration::from_secs(2), move |f: &[u8]| {
        f.len() >= 14 && f[0..6] == [0xaa, 0, 0, 0, 0, 2] && f[12..14] == [0x08, 0x00]
    });
    assert_eq!(delivered, 1, "unicast must pass untouched");
}
