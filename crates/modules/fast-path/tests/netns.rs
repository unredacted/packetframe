// aya, `/proc/sys/kernel/osrelease`, and raw AF_PACKET / setns are
// Linux-only.
#![cfg(target_os = "linux")]

//! Netns-backed integration test for the §11.13 pass-path mutation
//! invariant: whenever the fast path returns `XDP_PASS`, the packet
//! handed back to the kernel must be **byte-identical** to the packet
//! that arrived at the XDP hook. A prior version mutated the packet
//! (TTL decrement + MAC rewrite + VLAN choreography) **before** the
//! `REDIRECT_DEVMAP` pre-check, and on every devmap miss it returned
//! `XDP_PASS` with a mangled frame. On the reference EFG this silently
//! black-holed every matched-and-not-in-devmap packet for several
//! minutes before the rollback. See SPEC.md §11.13.
//!
//! `bpf_prog_test_run` can't reach the bug — it returns verdict and
//! output bytes but doesn't perform a real `bpf_fib_lookup` against
//! configured routes. This test sets up:
//!
//! - a fresh network namespace (one per test run, PID-suffixed)
//! - a veth pair inside it: `vpXXa` (XDP attached, ingress) ↔ `vpXXb`
//!   (peer, where we inject)
//! - a dummy iface `dumXX` with a route `198.51.100.0/24 dev dumXX`
//!   and a permanent neighbor for `198.51.100.1` so the FIB lookup
//!   returns `SUCCESS` with egress=dummy
//!
//! Then:
//!
//! - load fast-path, allowlist the src prefix, leave `REDIRECT_DEVMAP`
//!   empty (crucially: the dummy's ifindex is NOT in it)
//! - attach XDP generic to the veth ingress end
//! - inject a matched IPv4/TCP packet via AF_PACKET on the peer
//! - capture post-XDP bytes via AF_PACKET on the ingress end
//! - assert `pass_not_in_devmap` bumped once and the captured frame is
//!   byte-identical to the injected frame
//!
//! Running without PR #11 would trip the byte-equality assertion: TTL
//! would be 63 (decremented), the IPv4 header checksum patched, and
//! the L2 MAC pair rewritten to the resolved next-hop. With PR #11 in
//! place, the devmap pre-check runs before any mutation and the packet
//! reaches the slow path untouched.
//!
//! Requires CAP_BPF + CAP_NET_ADMIN + CAP_SYS_ADMIN (for netns). CI
//! runs it under sudo via `--ignored`.

use std::ffi::CString;
use std::fs::File;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::{Duration, Instant};

use aya::{
    maps::{lpm_trie::Key as LpmKey, Array, LpmTrie},
    programs::{xdp::XdpFlags, Xdp},
    Ebpf,
};
use packetframe_fast_path::{aligned_bpf_copy, FAST_PATH_BPF_AVAILABLE};

mod common;

use common::{FpCfg, Ipv4TcpBuilder, StatIdx, FP_CFG_VERSION_V1};

// Names are kept short + PID-suffixed so concurrent test runs don't
// collide. Linux caps iface names at IFNAMSIZ=16; we stay well under.
struct Names {
    netns: String,
    veth_a: String,
    veth_b: String,
    dum: String,
}

impl Names {
    fn new() -> Self {
        // PID % 10000 keeps names to 6 chars + prefix. Stable per-process
        // so all helpers in one test share them.
        let suffix = std::process::id() % 10_000;
        Self {
            netns: format!("pfns{suffix:04}"),
            veth_a: format!("pfa{suffix:04}"),
            veth_b: format!("pfb{suffix:04}"),
            dum: format!("pfd{suffix:04}"),
        }
    }
}

// Chosen to not collide with any routable prefix the CI host might
// actually have. `10.77.x.x/16` avoids clashing with Docker's
// 10.{0,1,42}/8 defaults and 198.51.100.0/24 is RFC 5737 TEST-NET-2.
const VETH_A_CIDR: &str = "10.77.0.1/24";
const VETH_B_CIDR: &str = "10.77.0.2/24";
const DUMMY_CIDR: &str = "192.0.2.254/24";
const ROUTED_PREFIX: &str = "198.51.100.0/24";
const ROUTED_NEIGH: &str = "198.51.100.1";
const ROUTED_NEIGH_LLADDR: &str = "de:ad:be:ef:00:01";
const ALLOW_PREFIX: ([u8; 4], u32) = ([10, 77, 0, 0], 16);

/// RAII wrapper around `ip netns add` / `ip netns del`. Drop tears the
/// whole namespace down — that also destroys every iface we made
/// inside it, so we don't need per-iface cleanup.
struct NetnsGuard {
    name: String,
}

impl NetnsGuard {
    fn setup(names: &Names) -> Self {
        // Idempotent: delete any leftover from a prior crashed run.
        let _ = Command::new("ip")
            .args(["netns", "del", &names.netns])
            .status();

        run(&["ip", "netns", "add", &names.netns]);
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
        ns_run(
            &names.netns,
            &["ip", "link", "add", &names.dum, "type", "dummy"],
        );
        ns_run(&names.netns, &["ip", "link", "set", &names.veth_a, "up"]);
        ns_run(&names.netns, &["ip", "link", "set", &names.veth_b, "up"]);
        ns_run(&names.netns, &["ip", "link", "set", &names.dum, "up"]);
        ns_run(
            &names.netns,
            &["ip", "addr", "add", VETH_A_CIDR, "dev", &names.veth_a],
        );
        ns_run(
            &names.netns,
            &["ip", "addr", "add", VETH_B_CIDR, "dev", &names.veth_b],
        );
        ns_run(
            &names.netns,
            &["ip", "addr", "add", DUMMY_CIDR, "dev", &names.dum],
        );
        ns_run(
            &names.netns,
            &["ip", "route", "add", ROUTED_PREFIX, "dev", &names.dum],
        );
        // Permanent neighbor so `bpf_fib_lookup` resolves without
        // triggering kernel ARP/ND — returns SUCCESS with `dmac` set
        // to `ROUTED_NEIGH_LLADDR` directly.
        ns_run(
            &names.netns,
            &[
                "ip",
                "neigh",
                "replace",
                ROUTED_NEIGH,
                "dev",
                &names.dum,
                "lladdr",
                ROUTED_NEIGH_LLADDR,
                "nud",
                "permanent",
            ],
        );
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

/// Run `cmd` inside the given netns via `ip netns exec`. Simpler than
/// calling `setns` for every setup step — only the test thread itself
/// needs to enter the netns (it does so once, below).
fn ns_run(netns: &str, cmd: &[&str]) {
    let mut args = vec!["netns", "exec", netns];
    args.extend_from_slice(cmd);
    let status = Command::new("ip")
        .args(&args)
        .status()
        .unwrap_or_else(|e| panic!("spawn `ip {}`: {e}", args.join(" ")));
    assert!(status.success(), "`ip {}` exited {status}", args.join(" "));
}

/// Move the current thread into the netns. `setns(2)` on a single
/// thread is safe in a multithreaded process — it only re-associates
/// the calling thread, per the man page.
fn enter_netns(netns: &str) -> OwnedFd {
    // `ip netns add` bind-mounts the created ns at this path.
    let path = format!("/var/run/netns/{netns}");
    let fd: OwnedFd = File::open(&path)
        .unwrap_or_else(|e| panic!("open {path}: {e}"))
        .into();
    let rc = unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(rc, 0, "setns({path}): {}", std::io::Error::last_os_error());
    fd
}

fn if_nametoindex(name: &str) -> u32 {
    let c = CString::new(name).expect("iface name with NUL");
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    assert!(idx > 0, "if_nametoindex({name}) failed");
    idx
}

/// Read an iface's MAC via `SIOCGIFHWADDR` ioctl on a scratch socket.
/// `/sys/class/net` would be simpler but isn't reliably re-mounted for
/// the new netns on every distro — the sysfs view is frozen to
/// whichever netns held it at mount time, which is usually init. The
/// ioctl goes through a socket and so is properly netns-scoped.
fn mac_of(iface: &str) -> [u8; 6] {
    const SIOCGIFHWADDR: libc::c_ulong = 0x8927;

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(
        sock >= 0,
        "socket(AF_INET, SOCK_DGRAM): {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: kernel returned fd; we own it and close via OwnedFd drop.
    let _sock_owned = unsafe { OwnedFd::from_raw_fd(sock) };

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    let name_bytes = iface.as_bytes();
    assert!(
        name_bytes.len() < ifr.ifr_name.len(),
        "iface name `{iface}` doesn't fit in ifr_name"
    );
    for (i, &b) in name_bytes.iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    let rc = unsafe { libc::ioctl(sock, SIOCGIFHWADDR, &mut ifr as *mut libc::ifreq) };
    assert_eq!(
        rc,
        0,
        "SIOCGIFHWADDR({iface}): {}",
        std::io::Error::last_os_error()
    );

    // ifr_hwaddr.sa_data is [c_char; 14]; the first 6 bytes are the MAC
    // for Ethernet-family ifaces. c_char is i8 on x86_64 / aarch64.
    let hw = unsafe { ifr.ifr_ifru.ifru_hwaddr };
    let mut out = [0u8; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = hw.sa_data[i] as u8;
    }
    out
}

/// Open a `PF_PACKET` `SOCK_RAW` socket bound to `ifindex` with
/// `ETH_P_ALL`. Used both for injection (send) and capture (recv) — the
/// kernel behavior matches whichever direction we use it for.
fn open_packet_socket(ifindex: u32) -> OwnedFd {
    // Both socket()'s `protocol` arg and sockaddr_ll.sll_protocol are in
    // network byte order for PF_PACKET, per packet(7). `.to_be()` on a
    // u16 swaps once (0x0003 → 0x0300); widening to i32 afterwards keeps
    // the low 16 bits set and the high bits zero, which is what the C
    // macro `htons(ETH_P_ALL)` produces when passed to a `int` arg.
    const ETH_P_ALL: u16 = 0x0003;
    let proto_be: u16 = ETH_P_ALL.to_be();

    let fd = unsafe { libc::socket(libc::PF_PACKET, libc::SOCK_RAW, proto_be as i32) };
    assert!(
        fd >= 0,
        "socket(PF_PACKET): {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: kernel returns a valid fd we now own.
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

fn send_frame(fd: &OwnedFd, ifindex: u32, frame: &[u8]) {
    let mut sll: libc::sockaddr_ll = unsafe { mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_ifindex = ifindex as i32;
    sll.sll_halen = 6;
    // Destination MAC goes in sll_addr for send(); kernel overrides
    // anyway for SOCK_RAW with a full Ethernet header in the buffer,
    // but libc requires a filled struct.
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

/// Poll the capture socket for a frame matching `is_ours` within
/// `timeout`. Discards anything else the netns emits (IPv6 DAD, RAs,
/// ARP) without failing.
fn recv_matching(
    fd: &OwnedFd,
    timeout: Duration,
    is_ours: impl Fn(&[u8]) -> bool,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let mut pfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms: i32 = remaining.as_millis().min(i32::MAX as u128) as i32;
        let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, ms) };
        if rc < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("poll: {e}");
        }
        if rc == 0 {
            return None;
        }
        let n = unsafe {
            libc::recv(
                fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if matches!(e.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                continue;
            }
            panic!("recv: {e}");
        }
        let n = n as usize;
        let slice = &buf[..n];
        if is_ours(slice) {
            return Some(slice.to_vec());
        }
        // Not our packet. Keep polling.
    }
}

/// Recognise our test packet by IPv4 src+dst — these bytes survive
/// the pre-PR #11 mutation (which only touched L2 MACs and TTL/csum),
/// so the filter catches both the correct (unmutated) case and the
/// regression case. We want the byte-equality assertion to fire on
/// mutation, not a capture timeout.
fn is_test_packet(buf: &[u8]) -> bool {
    // Ethernet (14) + IPv4 src at offset 26, dst at 30.
    buf.len() >= 34
        && buf[12..14] == [0x08, 0x00] // inner ethertype = IPv4 (unchanged by fast path)
        && buf[26..30] == [10, 77, 0, 2]
        && buf[30..34] == [198, 51, 100, 1]
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn pass_path_preserves_packet_bytes_on_devmap_miss() {
    if !FAST_PATH_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup/bpf-linker); skipping netns test.");
        return;
    }

    let names = Names::new();
    let _netns = NetnsGuard::setup(&names);

    // Move this thread into the netns. Ifindex, AF_PACKET, and XDP
    // attach are all netns-scoped; aya's bpf() load calls are not but
    // using the same netns for everything keeps the mental model
    // simple. `_ns_fd` stays alive for the whole test so the mount
    // point can't disappear under us mid-run.
    let _ns_fd = enter_netns(&names.netns);

    let ifindex_a = if_nametoindex(&names.veth_a);
    let ifindex_b = if_nametoindex(&names.veth_b);
    let mac_a = mac_of(&names.veth_a);
    let mac_b = mac_of(&names.veth_b);

    // Load fast-path, populate maps, attach.
    let bytes = aligned_bpf_copy();
    let mut bpf = Ebpf::load(&bytes).expect("aya::Ebpf::load");

    {
        let map = bpf.map_mut("ALLOW_V4").expect("ALLOW_V4 map");
        let mut trie: LpmTrie<_, [u8; 4], u8> =
            LpmTrie::try_from(map).expect("LpmTrie::try_from ALLOW_V4");
        let key = LpmKey::new(ALLOW_PREFIX.1, ALLOW_PREFIX.0);
        trie.insert(&key, 1u8, 0).expect("ALLOW_V4 insert");
    }

    {
        let map = bpf.map_mut("CFG").expect("CFG map");
        let mut arr: Array<_, FpCfg> = Array::try_from(map).expect("Array::try_from CFG");
        arr.set(
            0,
            FpCfg {
                dry_run: 0,
                flags: 0b11,
                _reserved: [0; 2],
                version: FP_CFG_VERSION_V1,
            },
            0,
        )
        .expect("CFG set");
    }

    // REDIRECT_DEVMAP intentionally left empty — the dummy ifindex is
    // therefore NOT in it, which is what drives the pre-check miss.

    let prog: &mut Xdp = bpf
        .program_mut("fast_path")
        .expect("fast_path program present")
        .try_into()
        .expect("fast_path is XDP");
    prog.load().expect("verifier accepts program");

    // Generic XDP is enough — veth supports it across every kernel we
    // target, and we're testing logic not performance. Sticking to
    // SKB_MODE also keeps this test from being flaky on kernels where
    // native veth XDP has quirks.
    let link_id = prog
        .attach_to_if_index(ifindex_a, XdpFlags::SKB_MODE)
        .expect("attach XDP generic");

    let cap_fd = open_packet_socket(ifindex_a);
    let inject_fd = open_packet_socket(ifindex_b);

    // Craft a matched packet. Src in the allowlist (10.77.0.2 covered
    // by 10.77.0.0/16), dst routed via dummy (198.51.100.1). TTL is
    // the builder default (64) — the mutation check is easier to read
    // if the ingress TTL is distinctive from 1 (low-ttl branch).
    let frame = Ipv4TcpBuilder {
        src_mac: mac_b,
        dst_mac: mac_a,
        src_ip: [10, 77, 0, 2],
        dst_ip: [198, 51, 100, 1],
        ..Default::default()
    }
    .build();

    let rx_before = bpf_stat(&bpf, StatIdx::RxTotal);
    let matched_before = bpf_stat(&bpf, StatIdx::MatchedV4);
    let miss_before = bpf_stat(&bpf, StatIdx::PassNotInDevmap);
    let fwd_ok_before = bpf_stat(&bpf, StatIdx::FwdOk);

    send_frame(&inject_fd, ifindex_b, &frame);

    // Capture. Filter on IPv4 src+dst (bytes the fast path never
    // touches) so a MAC- or TTL-mutated frame is still captured and
    // then rejected by the byte-equality assertion below — we want
    // the assertion to fire on mutation, not a capture timeout.
    let captured = recv_matching(&cap_fd, Duration::from_millis(1000), is_test_packet).expect(
        "no frame captured on XDP-attached veth within 1s — \
             did the fast path XDP_REDIRECT (devmap leak?) or \
             XDP_DROP the matched frame?",
    );

    // Detach before we poke more assertions so a test abort can't
    // leave the iface XDP-armed. Netns drop would clean up anyway
    // (deleting the netns detaches XDP programs on its ifaces), but
    // it's good hygiene.
    let _ = prog.detach(link_id);

    // Counter assertions first — if these fail, the byte-equality
    // assertion is academic.
    assert_eq!(
        bpf_stat(&bpf, StatIdx::RxTotal) - rx_before,
        1,
        "expected exactly one rx_total increment"
    );
    assert_eq!(
        bpf_stat(&bpf, StatIdx::MatchedV4) - matched_before,
        1,
        "packet should have matched the IPv4 allowlist"
    );
    assert_eq!(
        bpf_stat(&bpf, StatIdx::PassNotInDevmap) - miss_before,
        1,
        "FIB egress (dummy) is not in REDIRECT_DEVMAP; \
         pass_not_in_devmap should bump"
    );
    assert_eq!(
        bpf_stat(&bpf, StatIdx::FwdOk) - fwd_ok_before,
        0,
        "no redirect should have happened"
    );

    // §11.13 invariant: the frame the kernel slow path received must
    // be the frame we injected, byte-for-byte. Mutation before the
    // devmap pre-check would make this assertion trip — captured TTL
    // would be 63, IP checksum patched, L2 MACs rewritten to the
    // neighbor's lladdr.
    assert_eq!(
        captured.len(),
        frame.len(),
        "packet length changed on pass path"
    );
    assert_eq!(
        captured, frame,
        "packet bytes mutated on pass path — §11.13 invariant violation \
         (compare captured[14..] against frame[14..] for the IP+TCP diff)"
    );
}

fn bpf_stat(bpf: &Ebpf, idx: StatIdx) -> u64 {
    use aya::maps::PerCpuArray;
    let map = bpf.map("STATS").expect("STATS map");
    let stats: PerCpuArray<_, u64> = PerCpuArray::try_from(map).expect("PerCpuArray::try_from");
    let per_cpu = stats.get(&(idx as u32), 0).expect("STATS get");
    per_cpu.iter().copied().sum()
}
