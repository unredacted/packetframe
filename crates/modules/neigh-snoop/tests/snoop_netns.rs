//! End-to-end: the engine learns from third-party ARP/ND injected on
//! the far end of a veth pair and installs NUD_STALE entries on the
//! near end, honouring the install rules.
//!
//! NOT in the hardware-artifacts SAFE suite: creates a network
//! namespace, veths and neighbour entries. Runs in the qemu-verifier
//! job and under `sudo -E cargo test -p packetframe-neigh-snoop --tests
//! -- --ignored`.
//!
//! This file copies the netns utilities from fast-path's
//! `tests/neigh_resolver_netns.rs` and the AF_PACKET helpers from
//! guard's `tests/guard_netns.rs` rather than depending on them: each
//! `tests/*.rs` is its own crate and cannot import a sibling.
//! Addresses are documentation prefixes; MACs are locally administered.

#![cfg(target_os = "linux")]

use std::fs::File;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use packetframe_common::config::Config;
use packetframe_neigh_snoop::cfg::SnoopConfig;
use packetframe_neigh_snoop::engine::EngineHandle;
use packetframe_neigh_snoop::snapshot::{InstallOutcome, Snapshot};
use packetframe_neigh_snoop::table::SkipReason;

// --- netns plumbing ------------------------------------------------------

struct Names {
    netns: String,
    veth_a: String,
    veth_b: String,
    persist: PathBuf,
}

static NAMES_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

impl Names {
    fn new() -> Self {
        let pid = (std::process::id() % 1000) as u16;
        let n = NAMES_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let suffix = format!("{pid:03}{n:02}");
        Self {
            netns: format!("pfsn{suffix}"),
            veth_a: format!("pfsa{suffix}"),
            veth_b: format!("pfsb{suffix}"),
            persist: std::env::temp_dir().join(format!("pf-snoop-{suffix}")),
        }
    }
}

struct NetnsGuard {
    name: String,
    persist: PathBuf,
}

impl NetnsGuard {
    /// veth A (the "bridge" the engine snoops) with a v4 and a v6
    /// address, DAD off so the namespace stays quiet; veth B is the
    /// injector.
    fn setup(names: &Names) -> Self {
        let _ = Command::new("ip")
            .args(["netns", "del", &names.netns])
            .status();
        let _ = std::fs::remove_dir_all(&names.persist);
        run(&["ip", "netns", "add", &names.netns]);
        ns_run(
            &names.netns,
            &["sysctl", "-wq", "net.ipv6.conf.all.accept_dad=0"],
        );
        ns_run(
            &names.netns,
            &["sysctl", "-wq", "net.ipv6.conf.default.accept_dad=0"],
        );
        ns_run(
            &names.netns,
            &[
                "sysctl",
                "-wq",
                "net.ipv6.conf.default.router_solicitations=0",
            ],
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
        ns_run(&names.netns, &["ip", "link", "set", "lo", "up"]);
        ns_run(&names.netns, &["ip", "link", "set", &names.veth_a, "up"]);
        ns_run(&names.netns, &["ip", "link", "set", &names.veth_b, "up"]);
        ns_run(
            &names.netns,
            &["ip", "addr", "add", "198.51.100.1/24", "dev", &names.veth_a],
        );
        ns_run(
            &names.netns,
            &[
                "ip",
                "-6",
                "addr",
                "add",
                "2001:db8::1/64",
                "dev",
                &names.veth_a,
                "nodad",
            ],
        );
        ns_run(
            &names.netns,
            &["ip", "addr", "add", "198.51.100.2/24", "dev", &names.veth_b],
        );
        Self {
            name: names.netns.clone(),
            persist: names.persist.clone(),
        }
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip")
            .args(["netns", "del", &self.name])
            .status();
        let _ = std::fs::remove_dir_all(&self.persist);
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

fn ns_capture(netns: &str, cmd: &[&str]) -> String {
    let mut args = vec!["netns", "exec", netns];
    args.extend_from_slice(cmd);
    let out = Command::new("ip")
        .args(&args)
        .output()
        .unwrap_or_else(|e| panic!("spawn `ip {}`: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "`ip {}` exited {}",
        args.join(" "),
        out.status
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn enter_netns(netns: &str) -> OwnedFd {
    let path = format!("/var/run/netns/{netns}");
    let fd: OwnedFd = File::open(&path)
        .unwrap_or_else(|e| panic!("open {path}: {e}"))
        .into();
    let rc = unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(rc, 0, "setns({path}): {}", std::io::Error::last_os_error());
    fd
}

/// Read an iface's MAC via SIOCGIFHWADDR, netns-scoped because it goes
/// through a socket (sysfs is not reliably remounted per netns).
fn mac_of(iface: &str) -> [u8; 6] {
    // u32 + `as _`: ioctl's request parameter is `c_ulong` on glibc,
    // `c_int` on musl.
    const SIOCGIFHWADDR: u32 = 0x8927;
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(
        sock >= 0,
        "socket(AF_INET): {}",
        std::io::Error::last_os_error()
    );
    let _owned = unsafe { OwnedFd::from_raw_fd(sock) };
    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    for (i, &b) in iface.as_bytes().iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    #[allow(clippy::unnecessary_cast)]
    let rc = unsafe { libc::ioctl(sock, SIOCGIFHWADDR as _, &mut ifr as *mut libc::ifreq) };
    assert_eq!(
        rc,
        0,
        "SIOCGIFHWADDR({iface}): {}",
        std::io::Error::last_os_error()
    );
    let hw = unsafe { ifr.ifr_ifru.ifru_hwaddr };
    let mut out = [0u8; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = hw.sa_data[i] as u8;
    }
    out
}

fn if_nametoindex(name: &str) -> u32 {
    let c = std::ffi::CString::new(name).expect("iface name with NUL");
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    assert!(idx > 0, "if_nametoindex({name}) failed");
    idx
}

/// `ip neigh show dev <iface> nud all`, one line per entry.
fn neigh_table(netns: &str, iface: &str) -> String {
    ns_capture(netns, &["ip", "neigh", "show", "dev", iface, "nud", "all"])
}

/// The neighbour line for `ip`, if any.
fn neigh_line(netns: &str, iface: &str, ip: &str) -> Option<String> {
    neigh_table(netns, iface)
        .lines()
        .find(|l| l.starts_with(&format!("{ip} ")))
        .map(str::to_string)
}

fn wait_for(deadline: Duration, what: &str, mut cond: impl FnMut() -> Option<String>) -> String {
    let end = Instant::now() + deadline;
    let mut last = String::new();
    loop {
        if let Some(v) = cond() {
            return v;
        }
        if Instant::now() >= end {
            panic!("timed out waiting for {what}; last observation:\n{last}");
        }
        last = format!("(at {:?})", Instant::now());
        std::thread::sleep(Duration::from_millis(100));
    }
}

// --- AF_PACKET injector ---------------------------------------------------

fn open_packet_socket(ifindex: u32) -> OwnedFd {
    let proto_be: u16 = 0x0003u16.to_be();
    let fd = unsafe { libc::socket(libc::PF_PACKET, libc::SOCK_RAW, i32::from(proto_be)) };
    assert!(
        fd >= 0,
        "socket(PF_PACKET): {}",
        std::io::Error::last_os_error()
    );
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
        "bind(PF_PACKET): {}",
        std::io::Error::last_os_error()
    );
    owned
}

fn send_frame(fd: &OwnedFd, ifindex: u32, frame: &[u8]) {
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
    assert_eq!(
        sent,
        frame.len() as isize,
        "sendto: {}",
        std::io::Error::last_os_error()
    );
}

// --- frame builders --------------------------------------------------------

const MAC_X: [u8; 6] = [0x02, 0, 0, 0, 0, 0x77];
const MAC_Y: [u8; 6] = [0x02, 0, 0, 0, 0, 0x78];
const MAC_Z: [u8; 6] = [0x02, 0, 0, 0, 0, 0x79];

fn mac_str(m: [u8; 6]) -> String {
    packetframe_common::config::format_mac(m)
}

fn arp_request(eth_src: [u8; 6], sha: [u8; 6], spa: Ipv4Addr, tpa: Ipv4Addr) -> Vec<u8> {
    let mut f = Vec::with_capacity(60);
    f.extend_from_slice(&[0xff; 6]);
    f.extend_from_slice(&eth_src);
    f.extend_from_slice(&0x0806u16.to_be_bytes());
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    f.push(6);
    f.push(4);
    f.extend_from_slice(&1u16.to_be_bytes());
    f.extend_from_slice(&sha);
    f.extend_from_slice(&spa.octets());
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&tpa.octets());
    while f.len() < 60 {
        f.push(0);
    }
    f
}

fn icmp6(
    eth_src: [u8; 6],
    eth_dst: [u8; 6],
    src: Ipv6Addr,
    dst: Ipv6Addr,
    icmp_type: u8,
    body: &[u8],
) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&eth_dst);
    f.extend_from_slice(&eth_src);
    f.extend_from_slice(&0x86ddu16.to_be_bytes());
    f.extend_from_slice(&[0x60, 0, 0, 0]);
    f.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    f.push(58);
    f.push(255);
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&dst.octets());
    f.push(icmp_type);
    f.push(0);
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(body);
    f
}

fn solicited_node(a: Ipv6Addr) -> Ipv6Addr {
    let o = a.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | u16::from(o[13]),
        u16::from_be_bytes([o[14], o[15]]),
    )
}

fn ns_with_sllao(src_mac: [u8; 6], src: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
    let mut body = vec![0, 0, 0, 0];
    body.extend_from_slice(&target.octets());
    body.extend_from_slice(&[1, 1]);
    body.extend_from_slice(&src_mac);
    let snm = solicited_node(target);
    let mut dst_mac = [0x33, 0x33, 0, 0, 0, 0];
    dst_mac[2..].copy_from_slice(&snm.octets()[12..]);
    icmp6(src_mac, dst_mac, src, snm, 135, &body)
}

fn na_with_tllao(src_mac: [u8; 6], src: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
    let mut body = vec![0x20, 0, 0, 0];
    body.extend_from_slice(&target.octets());
    body.extend_from_slice(&[2, 1]);
    body.extend_from_slice(&src_mac);
    let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
    icmp6(
        src_mac,
        [0x33, 0x33, 0, 0, 0, 1],
        src,
        all_nodes,
        136,
        &body,
    )
}

// --- the engine under test --------------------------------------------------

struct Rig {
    names: Names,
    _guard: NetnsGuard,
    _ns_fd: OwnedFd,
    engine: Option<EngineHandle>,
    injector: OwnedFd,
    b_ifindex: u32,
}

impl Rig {
    /// Enter the netns, start the engine (its runtime threads inherit
    /// the namespace from this thread), open the injector on veth B.
    fn start() -> Self {
        let names = Names::new();
        let guard = NetnsGuard::setup(&names);
        let ns_fd = enter_netns(&names.netns);
        let s = format!(
            "module neigh-snoop\n  bridge {a}\n  prefix {a} 198.51.100.0/24\n  \
             prefix {a} 2001:db8::/64\n  prefix {a} fe80::/10\n  install-rate 500/1s\n  \
             coverage-interval 5s\n",
            a = names.veth_a
        );
        let c = Config::parse(&s).unwrap();
        let cfg = SnoopConfig::from_directives(&c.modules[0].directives).unwrap();
        std::fs::create_dir_all(&names.persist).unwrap();
        let engine = EngineHandle::start(cfg, names.persist.clone()).expect("engine start");
        let b_ifindex = if_nametoindex(&names.veth_b);
        let injector = open_packet_socket(b_ifindex);
        Self {
            names,
            _guard: guard,
            _ns_fd: ns_fd,
            engine: Some(engine),
            injector,
            b_ifindex,
        }
    }

    fn inject(&self, frame: &[u8]) {
        send_frame(&self.injector, self.b_ifindex, frame);
    }

    fn neigh(&self, ip: &str) -> Option<String> {
        neigh_line(&self.names.netns, &self.names.veth_a, ip)
    }

    fn set_neigh(&self, ip: &str, mac: Option<[u8; 6]>, nud: &str) {
        let mut cmd = vec!["ip", "neigh", "replace", ip];
        let m;
        if let Some(mac) = mac {
            m = mac_str(mac);
            cmd.extend_from_slice(&["lladdr", &m]);
        }
        cmd.extend_from_slice(&["dev", &self.names.veth_a, "nud", nud]);
        ns_run(&self.names.netns, &cmd);
    }

    fn snapshot(&self) -> Snapshot {
        self.engine.as_ref().unwrap().snapshot()
    }

    fn wait_neigh(&self, ip: &str, pred: impl Fn(&str) -> bool) -> String {
        wait_for(Duration::from_secs(5), &format!("neighbour {ip}"), || {
            self.neigh(ip).filter(|l| pred(l))
        })
    }

    fn wait_counter(&self, what: &str, mut f: impl FnMut(&Snapshot) -> bool) {
        wait_for(Duration::from_secs(5), what, || {
            let s = self.snapshot();
            f(&s).then(|| format!("{s:?}"))
        });
    }

    fn stop(mut self) {
        let started = Instant::now();
        self.engine.take().unwrap().shutdown();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "shutdown must return inside the detach budget"
        );
    }
}

fn v4(n: u8) -> Ipv4Addr {
    Ipv4Addr::new(198, 51, 100, n)
}
fn v6(last: u16) -> Ipv6Addr {
    Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last)
}
fn ll(last: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last)
}

// --- tests -----------------------------------------------------------------

/// (a) A third-party ARP request — one the kernel ignores because its
/// target is not ours — is learned and installed as STALE with the
/// sender's MAC, and the echo confirms it.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN; run via sudo -E cargo test -p packetframe-neigh-snoop --tests -- --ignored"]
fn learns_third_party_arp_and_installs_stale() {
    let rig = Rig::start();
    assert!(rig.neigh("198.51.100.77").is_none(), "clean start");
    rig.inject(&arp_request(MAC_X, MAC_X, v4(77), v4(200)));
    let line = rig.wait_neigh("198.51.100.77", |l| l.contains("STALE"));
    assert!(line.contains(&mac_str(MAC_X)), "{line}");
    rig.wait_counter("install confirmed", |s| {
        s.bridges[0].counters.installs[InstallOutcome::Confirmed.index()] >= 1
    });
    let s = rig.snapshot();
    assert_eq!(s.bridges[0].table_entries, 1);
    assert!(
        s.bridges[0].promisc_confirmed,
        "kernel reports promiscuity for the device: {s:?}"
    );
    assert_eq!(
        s.bridges[0].counters.frames[0], 1,
        "one arp_request counted"
    );
    rig.stop();
}

/// (b) NS with a source link-layer option teaches its source; an
/// unsolicited NA from a link-local source teaches both the target and
/// the source.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN; run via sudo -E cargo test -p packetframe-neigh-snoop --tests -- --ignored"]
fn learns_ns_and_na_pairs() {
    let rig = Rig::start();
    rig.inject(&ns_with_sllao(MAC_X, v6(0x77), v6(0x200)));
    rig.inject(&na_with_tllao(MAC_Y, ll(0x78), v6(0x78)));
    for (ip, mac) in [
        ("2001:db8::77", MAC_X),
        ("2001:db8::78", MAC_Y),
        ("fe80::78", MAC_Y),
    ] {
        let line = rig.wait_neigh(ip, |l| l.contains("STALE"));
        assert!(line.contains(&mac_str(mac)), "{ip}: {line}");
    }
    // The snapshot is published once per housekeeping tick; wait for it
    // rather than reading the previous tick's.
    rig.wait_counter("three entries", |s| s.bridges[0].table_entries == 3);
    rig.stop();
}

/// (c1)(c3)(c4) The never-downgrade / never-override rules against
/// real kernel state: a REACHABLE entry with the same MAC is left
/// alone; a REACHABLE entry with another MAC is left alone and counted
/// as a conflict; a STALE entry with another MAC is replaced.
///
/// The conflict and override cases use IPv6 solicitations on purpose.
/// For IPv4, Linux itself updates an *existing* neighbour entry from
/// any ARP packet whose sender it already knows (`arp_process`, with a
/// one-second lock time), so an ARP-based version of this test observes
/// the kernel's own update and proves nothing about the engine. The
/// kernel ignores a third-party NS's source unless the target is ours.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN; run via sudo -E cargo test -p packetframe-neigh-snoop --tests -- --ignored"]
fn never_downgrades_or_overrides_confirmed_entries() {
    let rig = Rig::start();
    rig.set_neigh("198.51.100.77", Some(MAC_X), "reachable");
    rig.set_neigh("2001:db8::77", Some(MAC_X), "reachable");
    rig.set_neigh("2001:db8::78", Some(MAC_X), "stale");
    // Let the mirror pick them up via the multicast echo.
    std::thread::sleep(Duration::from_millis(300));

    // Same MAC as a confirmed entry: nothing to do (the kernel also
    // keeps REACHABLE for a same-lladdr non-admin update).
    rig.inject(&arp_request(MAC_X, MAC_X, v4(77), v4(200)));
    rig.wait_counter("same_mac skip", |s| {
        s.bridges[0].counters.installs[InstallOutcome::Skipped(SkipReason::SameMac).index()] >= 1
    });
    let line = rig.neigh("198.51.100.77").unwrap();
    assert!(
        line.contains("REACHABLE") && line.contains(&mac_str(MAC_X)),
        "{line}"
    );

    // Another MAC for a confirmed entry: counted, not installed.
    rig.inject(&ns_with_sllao(MAC_Y, v6(0x77), v6(0x200)));
    rig.wait_counter("mac_conflict", |s| {
        s.bridges[0].counters.installs[InstallOutcome::Skipped(SkipReason::MacConflict).index()]
            >= 1
    });
    std::thread::sleep(Duration::from_millis(200));
    let line = rig.neigh("2001:db8::77").unwrap();
    assert!(
        line.contains("REACHABLE") && line.contains(&mac_str(MAC_X)),
        "a confirmed entry must not be overridden: {line}"
    );

    // Another MAC for a STALE entry: replaced.
    rig.inject(&ns_with_sllao(MAC_Z, v6(0x78), v6(0x200)));
    let line = rig.wait_neigh("2001:db8::78", |l| l.contains(&mac_str(MAC_Z)));
    assert!(line.contains("STALE"), "{line}");
    rig.wait_counter("no install failures", |s| {
        s.bridges[0].counters.installs[InstallOutcome::Confirmed.index()] >= 1
            && s.bridges[0].counters.installs[InstallOutcome::Failed.index()] == 0
    });
    rig.stop();
}

/// (c2) A FAILED entry is repaired from a solicitation. Uses NS on
/// purpose: for ARP the kernel itself would update an existing FAILED
/// entry from a third-party request and mask a regression here.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN; run via sudo -E cargo test -p packetframe-neigh-snoop --tests -- --ignored"]
fn repairs_failed_entry_from_ns() {
    let rig = Rig::start();
    rig.set_neigh("2001:db8::77", None, "failed");
    std::thread::sleep(Duration::from_millis(300));
    let before = rig.neigh("2001:db8::77").unwrap();
    assert!(before.contains("FAILED"), "{before}");
    rig.inject(&ns_with_sllao(MAC_X, v6(0x77), v6(0x200)));
    let line = rig.wait_neigh("2001:db8::77", |l| l.contains("STALE"));
    assert!(line.contains(&mac_str(MAC_X)), "{line}");
    rig.stop();
}

/// (d) An ARP whose sender hardware address disagrees with the
/// Ethernet source is refused and counted; nothing is installed.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN; run via sudo -E cargo test -p packetframe-neigh-snoop --tests -- --ignored"]
fn rejects_sha_mismatch() {
    let rig = Rig::start();
    rig.inject(&arp_request(MAC_X, MAC_Y, v4(77), v4(200)));
    rig.wait_counter("sha_mismatch counted", |s| {
        let idx = packetframe_neigh_snoop::frame::Reject::ShaMismatch.index();
        s.bridges[0].counters.parse_rejects[idx] >= 1
    });
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        rig.neigh("198.51.100.77").is_none(),
        "nothing installed from a forged frame"
    );
    assert_eq!(rig.snapshot().bridges[0].table_entries, 0);
    rig.stop();
}

/// The persisted table is written after a learn, and a fresh engine
/// over the same directory re-seeds the kernel from it.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN; run via sudo -E cargo test -p packetframe-neigh-snoop --tests -- --ignored"]
fn persists_and_reseeds_on_restart() {
    let mut rig = Rig::start();
    rig.inject(&arp_request(MAC_X, MAC_X, v4(77), v4(200)));
    rig.wait_neigh("198.51.100.77", |l| l.contains("STALE"));
    let path = rig.names.persist.join(format!("{}.json", rig.names.veth_a));
    wait_for(Duration::from_secs(6), "persist file", || {
        std::fs::read_to_string(&path)
            .ok()
            .filter(|s| s.contains("198.51.100.77"))
    });
    // Stop, flush the kernel table, restart over the same directory.
    let engine = rig.engine.take().unwrap();
    engine.shutdown();
    ns_run(
        &rig.names.netns,
        &["ip", "neigh", "flush", "dev", &rig.names.veth_a],
    );
    assert!(rig.neigh("198.51.100.77").is_none());
    let s = format!(
        "module neigh-snoop\n  bridge {a}\n  prefix {a} 198.51.100.0/24\n  install-rate 500/1s\n",
        a = rig.names.veth_a
    );
    let c = Config::parse(&s).unwrap();
    let cfg = SnoopConfig::from_directives(&c.modules[0].directives).unwrap();
    rig.engine = Some(EngineHandle::start(cfg, rig.names.persist.clone()).expect("restart"));
    let line = rig.wait_neigh("198.51.100.77", |l| l.contains("STALE"));
    assert!(line.contains(&mac_str(MAC_X)), "{line}");
    rig.wait_counter("seed confirmed", |s| {
        s.bridges[0].counters.seeds
            [packetframe_neigh_snoop::snapshot::SeedOutcome::Confirmed.index()]
            >= 1
    });
    rig.stop();
}

/// Zero emissions in miniature: a tap on the injector side sees no
/// ARP or ND from the snooped interface's MAC across a whole learn
/// cycle. The kernel's own probes would appear here if an installer
/// ever wrote a state that triggers resolution instead of STALE.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN; run via sudo -E cargo test -p packetframe-neigh-snoop --tests -- --ignored"]
fn emits_nothing() {
    let rig = Rig::start();
    let a_mac = mac_of(&rig.names.veth_a);

    let tap = open_packet_socket(rig.b_ifindex);
    rig.inject(&arp_request(MAC_X, MAC_X, v4(77), v4(200)));
    rig.inject(&ns_with_sllao(MAC_Y, v6(0x78), v6(0x200)));
    rig.wait_neigh("198.51.100.77", |l| l.contains("STALE"));
    rig.wait_neigh("2001:db8::78", |l| l.contains("STALE"));
    std::thread::sleep(Duration::from_secs(1));
    // Drain the tap: anything ARP or ICMPv6-ND with A's MAC as source.
    let mut buf = [0u8; 2048];
    let mut ours = 0usize;
    loop {
        let n = unsafe {
            libc::recv(
                tap.as_raw_fd(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n <= 0 {
            break;
        }
        let f = &buf[..n as usize];
        if f.len() >= 14 && f[6..12] == a_mac {
            let ethertype = u16::from_be_bytes([f[12], f[13]]);
            let is_arp = ethertype == 0x0806;
            let is_nd = ethertype == 0x86dd
                && f.len() > 54
                && f[20] == 58
                && (f[54] == 135 || f[54] == 136);
            if is_arp || is_nd {
                ours += 1;
            }
        }
    }
    assert_eq!(
        ours, 0,
        "the snooped interface emitted ARP/ND during a learn cycle"
    );
    rig.stop();
}

// --- FRR gate + route-server coverage, against a stateful fake vtysh ---

/// A `vtysh` stand-in that keeps the two prefix-lists in files, logs
/// every invocation (one line per process, so batching is visible),
/// and serves a canned received-routes JSON. Written by the test into
/// the scratch directory; the engine finds it via `PACKETFRAME_VTYSH`.
fn write_fake_vtysh(state: &std::path::Path) -> PathBuf {
    let script = format!(
        r#"#!/bin/sh
STATE="{state}"
echo "$*" >> "$STATE/log"
show_list() {{
  fam="$1"; name="$2"; f="$STATE/$3"
  if [ -f "$f" ]; then
    echo "$fam prefix-list $name: $(wc -l < "$f" | tr -d ' ') entries"
    sed 's/^/   /' "$f"
  else
    echo "% Can't find specified prefix-list"
  fi
}}
del_line() {{
  f="$STATE/$1"; line="$2"
  grep -v -x -F -- "$line" "$f" > "$f.tmp" || true
  mv "$f.tmp" "$f"
}}
while [ $# -gt 0 ]; do
  if [ "$1" = "-c" ]; then
    shift; cmd="$1"
    case "$cmd" in
      "show version") echo "FRRouting 10.1.2 (fake)";;
      "show ip prefix-list "*) show_list ip "${{cmd##* }}" v4;;
      "show ipv6 prefix-list "*) show_list ipv6 "${{cmd##* }}" v6;;
      "show bgp ipv4 unicast neighbors "*" received-routes json") cat "$STATE/rs4.json";;
      "show bgp ipv6 unicast neighbors "*" received-routes json") echo '{{"receivedRoutes":{{}}}}';;
      "configure terminal") ;;
      "no ip prefix-list "*) del_line v4 "${{cmd#no ip prefix-list * }}";;
      "no ipv6 prefix-list "*) del_line v6 "${{cmd#no ipv6 prefix-list * }}";;
      "ip prefix-list "*) echo "${{cmd#ip prefix-list * }}" >> "$STATE/v4";;
      "ipv6 prefix-list "*) echo "${{cmd#ipv6 prefix-list * }}" >> "$STATE/v6";;
      *) echo "% Unknown command: $cmd" >&2; exit 1;;
    esac
  fi
  shift
done
"#,
        state = state.display()
    );
    let path = state.join("vtysh");
    std::fs::write(&path, script).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

const RS_JSON: &str = r#"{"receivedRoutes":{
  "203.0.113.0/25":{"network":"203.0.113.0/25","nextHop":"198.51.100.77"},
  "203.0.113.128/25":{"network":"203.0.113.128/25","nextHop":"198.51.100.77"},
  "192.0.2.0/24":{"network":"192.0.2.0/24","nextHop":"198.51.100.90"}
}}"#;

/// (k) The gate reconciler against real kernel state and a fake vtysh:
/// a learned, confirmed neighbour lands in the v4 list in one batched
/// invocation with an explicit sequence number; the route-server join
/// counts the prefix behind an unheard next-hop as demoted; an
/// emptied list (FRR reload) is refilled; a deleted neighbour leaves
/// the list only after the removal hysteresis.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN; run via sudo -E cargo test -p packetframe-neigh-snoop --tests -- --ignored"]
fn gate_reconciles_lists_and_measures_route_server_coverage() {
    let names = Names::new();
    let guard = NetnsGuard::setup(&names);
    let ns_fd = enter_netns(&names.netns);
    std::fs::create_dir_all(&names.persist).unwrap();
    std::fs::write(names.persist.join("v4"), "seq 5 deny 0.0.0.0/32\n").unwrap();
    std::fs::write(names.persist.join("v6"), "seq 5 deny ::/128\n").unwrap();
    std::fs::write(names.persist.join("rs4.json"), RS_JSON).unwrap();
    let fake = write_fake_vtysh(&names.persist);
    // Read once, at engine start; the gate tests are serialized through
    // this env var by being one test.
    std::env::set_var("PACKETFRAME_VTYSH", &fake);

    let s = format!(
        "module neigh-snoop\n  bridge {a}\n  prefix {a} 198.51.100.0/24\n  \
         prefix {a} 2001:db8::/64\n  prefix {a} fe80::/10\n  install-rate 500/1s\n  \
         peer {a} 198.51.100.2 route-server\n  \
         frr-gate v4 GATE4 v6 GATE6 interval 5s remove-after 3s\n  \
         rs-coverage-interval 5s\n",
        a = names.veth_a
    );
    let c = Config::parse(&s).unwrap();
    let cfg = SnoopConfig::from_directives(&c.modules[0].directives).unwrap();
    let engine = EngineHandle::start(cfg, names.persist.clone()).expect("engine start");
    let b_ifindex = if_nametoindex(&names.veth_b);
    let injector = open_packet_socket(b_ifindex);
    let rig = Rig {
        names,
        _guard: guard,
        _ns_fd: ns_fd,
        engine: Some(engine),
        injector,
        b_ifindex,
    };
    let v4_file = rig.names.persist.join("v4");
    let log_file = rig.names.persist.join("log");
    let entry = "seq 100 permit 198.51.100.77/32";

    rig.inject(&arp_request(MAC_X, MAC_X, v4(77), v4(200)));
    rig.wait_neigh("198.51.100.77", |l| l.contains("STALE"));
    wait_for(Duration::from_secs(15), "gate add", || {
        std::fs::read_to_string(&v4_file)
            .ok()
            .filter(|s| s.contains(entry))
    });
    let log = std::fs::read_to_string(&log_file).unwrap();
    let batch = log
        .lines()
        .find(|l| l.contains("configure terminal"))
        .expect("one configure invocation");
    assert!(
        batch.contains(entry),
        "the add rides in the configure batch: {batch}"
    );
    assert!(
        !std::fs::read_to_string(&v4_file)
            .unwrap()
            .contains("seq 5 permit"),
        "placeholders untouched"
    );
    rig.wait_counter("gate changed", |s| {
        s.gate.as_ref().is_some_and(|g| {
            g.permitted_v4 == 1
                && g.permitted_v6 == 0
                && g.outcomes[packetframe_neigh_snoop::snapshot::GateOutcome::Changed.index()] >= 1
                && g.last_error.is_none()
        })
    });

    // Route-server join: .77 resolves (two prefixes), .90 was never
    // heard (one prefix demoted).
    wait_for(Duration::from_secs(15), "rs coverage", || {
        let s = rig.snapshot();
        s.rs.first()
            .filter(|r| r.error.is_none() && r.received_prefixes == 3)
            .map(|r| format!("{r:?}"))
    });
    let r = rig.snapshot().rs.remove(0);
    assert_eq!(r.demoted_prefixes, 1, "{r:?}");
    assert_eq!(r.nexthops.total, 2);
    assert_eq!(r.nexthops.resolved, 1);
    assert_eq!(
        r.unresolved_nexthops,
        vec!["198.51.100.90".parse::<std::net::IpAddr>().unwrap()]
    );

    // FRR reload: a bgpd restart empties BOTH lists back to their
    // placeholders; the next tick refills.
    std::fs::write(&v4_file, "seq 5 deny 0.0.0.0/32\n").unwrap();
    std::fs::write(rig.names.persist.join("v6"), "seq 5 deny ::/128\n").unwrap();
    wait_for(Duration::from_secs(15), "reload refill", || {
        std::fs::read_to_string(&v4_file)
            .ok()
            .filter(|s| s.contains(entry))
    });
    rig.wait_counter("reload counted", |s| {
        s.gate.as_ref().is_some_and(|g| {
            g.outcomes[packetframe_neigh_snoop::snapshot::GateOutcome::ReloadRefill.index()] >= 1
        })
    });

    // Removal hysteresis: delete the kernel entry; the list keeps it
    // for remove-after, then drops it in a `no … seq 100 …` command.
    ns_run(
        &rig.names.netns,
        &[
            "ip",
            "neigh",
            "del",
            "198.51.100.77",
            "dev",
            &rig.names.veth_a,
        ],
    );
    wait_for(Duration::from_secs(25), "gate removal", || {
        std::fs::read_to_string(&v4_file)
            .ok()
            .filter(|s| !s.contains(entry))
    });
    let log = std::fs::read_to_string(&log_file).unwrap();
    assert!(
        log.contains(&format!("no ip prefix-list GATE4 {entry}")),
        "removal carries the parsed sequence number: {log}"
    );
    rig.stop();
}

/// (l) One MAC per member port: a MAC learned for one address on a
/// declared `peer` line is installed for its other addresses too.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_NET_RAW + CAP_SYS_ADMIN; run via sudo -E cargo test -p packetframe-neigh-snoop --tests -- --ignored"]
fn derives_sibling_addresses_of_a_declared_peer() {
    let names = Names::new();
    let guard = NetnsGuard::setup(&names);
    let ns_fd = enter_netns(&names.netns);
    let s = format!(
        "module neigh-snoop\n  bridge {a}\n  prefix {a} 198.51.100.0/24\n  \
         prefix {a} 2001:db8::/64\n  install-rate 500/1s\n  \
         peer {a} 198.51.100.77 2001:db8::77\n",
        a = names.veth_a
    );
    let c = Config::parse(&s).unwrap();
    let cfg = SnoopConfig::from_directives(&c.modules[0].directives).unwrap();
    std::fs::create_dir_all(&names.persist).unwrap();
    let engine = EngineHandle::start(cfg, names.persist.clone()).expect("engine start");
    let b_ifindex = if_nametoindex(&names.veth_b);
    let injector = open_packet_socket(b_ifindex);
    let rig = Rig {
        names,
        _guard: guard,
        _ns_fd: ns_fd,
        engine: Some(engine),
        injector,
        b_ifindex,
    };
    rig.inject(&arp_request(MAC_X, MAC_X, v4(77), v4(200)));
    let line = rig.wait_neigh("2001:db8::77", |l| l.contains("STALE"));
    assert!(line.contains(&mac_str(MAC_X)), "{line}");
    rig.wait_counter("derived counted", |s| {
        s.bridges[0].counters.learn
            [packetframe_neigh_snoop::snapshot::LearnOutcome::Derived.index()]
            >= 1
    });
    assert!(
        rig.snapshot().bridges[0]
            .never_heard
            .contains(&"2001:db8::77".parse().unwrap()),
        "derived is installed but not counted as heard"
    );
    rig.stop();
}
