//! Netns-backed integration test for the Option F NeighborResolver.
//!
//! Exercises the full resolver path end-to-end against a real kernel:
//!   - RTM_GETLINK dump at startup populates ifindex→MAC cache.
//!   - RTM_NEWNEIGH multicast on an `ip neigh add` translates to
//!     `NeighEvent::Learned { ip, mac, ifindex, src_mac }`.
//!   - `src_mac` matches the veth's actual MAC (validates Phase 3.6A).
//!
//! Not covered here:
//!   - Proactive resolve (`request_resolve`): validating kernel ARP kick
//!     from a netns test is fragile — would require an unresolved
//!     nexthop on an interface with routed connectivity. The existing
//!     best-effort fallback (first-packet kernel ARP) is validated by
//!     the fact that `Add`-without-pre-seeded-neigh test below still
//!     eventually emits Learned when we add the neigh manually.
//!   - FibProgrammer integration: that's Slice 3.7B (BMP mock test).
//!
//! Runs under CAP_NET_ADMIN + CAP_SYS_ADMIN (for netns). Test is
//! `#[ignore]`-gated; CI runs it under `sudo cargo test -- --ignored`
//! inside the qemu VM alongside other netns tests.
//!
//! This file copies the setup utilities (NetnsGuard, enter_netns,
//! mac_of, etc.) from tests/netns.rs rather than depending on them,
//! because each `tests/*.rs` is its own test crate and can't import
//! from peers. Refactoring into tests/common/ is a bigger follow-up.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs::File;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::Duration;

use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use packetframe_common::fib::NeighEvent;
use packetframe_fast_path::fib::netlink_neigh::NetlinkNeighborResolver;

// --- Test setup utilities (copied from tests/netns.rs) -----------------

struct Names {
    netns: String,
    veth_a: String,
    veth_b: String,
}

static NAMES_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

impl Names {
    fn new() -> Self {
        // Disambiguate with (pid, per-invocation counter) so parallel
        // `#[test]` fns in the same binary don't collide on the netns
        // or interface namespace. IFNAMSIZ is 16, so keep prefixes
        // short and the numeric tail ≤ ~8 chars.
        let pid = (std::process::id() % 1000) as u16;
        let n = NAMES_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let suffix = format!("{pid:03}{n:02}");
        Self {
            netns: format!("pfrn{suffix}"),
            veth_a: format!("pfra{suffix}"),
            veth_b: format!("pfrb{suffix}"),
        }
    }
}

struct NetnsGuard {
    name: String,
}

impl NetnsGuard {
    fn setup(names: &Names) -> Self {
        // Idempotent cleanup of any leftover from a prior crashed run.
        let _ = Command::new("ip")
            .args(["netns", "del", &names.netns])
            .status();

        run(&["ip", "netns", "add", &names.netns]);
        // Enable forwarding + loose rp_filter so the resolver's
        // proactive-resolve route lookup (should we trigger it) has a
        // routable interface. Not strictly required for Learned-path
        // tests but cheap.
        ns_run(&names.netns, &["sysctl", "-wq", "net.ipv4.ip_forward=1"]);
        ns_run(
            &names.netns,
            &["sysctl", "-wq", "net.ipv4.conf.all.rp_filter=0"],
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
        ns_run(
            &names.netns,
            &[
                "ip",
                "addr",
                "add",
                "198.51.100.254/24",
                "dev",
                &names.veth_a,
            ],
        );
        ns_run(
            &names.netns,
            &[
                "ip",
                "addr",
                "add",
                "198.51.100.253/24",
                "dev",
                &names.veth_b,
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

fn ns_run(netns: &str, cmd: &[&str]) {
    let mut args = vec!["netns", "exec", netns];
    args.extend_from_slice(cmd);
    let status = Command::new("ip")
        .args(&args)
        .status()
        .unwrap_or_else(|e| panic!("spawn `ip {}`: {e}", args.join(" ")));
    assert!(status.success(), "`ip {}` exited {status}", args.join(" "));
}

/// Move the current thread into the netns and return the owned
/// /var/run/netns/<name> fd. Dropping the fd after the test is fine
/// — the netns itself is torn down via `ip netns del` in NetnsGuard.
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
    let c = CString::new(name).expect("iface name with NUL");
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    assert!(idx > 0, "if_nametoindex({name}) failed");
    idx
}

/// Read an iface's MAC via SIOCGIFHWADDR ioctl — netns-scoped because
/// it goes through a socket (sysfs is not reliably remounted per-netns
/// on every distro).
fn mac_of(iface: &str) -> [u8; 6] {
    const SIOCGIFHWADDR: libc::c_ulong = 0x8927;

    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(
        sock >= 0,
        "socket(AF_INET, SOCK_DGRAM): {}",
        std::io::Error::last_os_error()
    );
    let _sock_owned = unsafe { OwnedFd::from_raw_fd(sock) };

    let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
    for (i, &b) in iface.as_bytes().iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }

    let rc = unsafe { libc::ioctl(sock, SIOCGIFHWADDR, &mut ifr as *mut libc::ifreq) };
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

// --- The actual test ---------------------------------------------------

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn resolver_emits_learned_with_src_mac_and_ifindex() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);

    // Enter the netns on this thread — tokio's current-thread runtime
    // we build below runs on this thread, so all tokio-spawned tasks
    // inherit the netns. `setns` on a single thread is safe in a
    // multithreaded process per `man 2 setns`.
    let _ns_fd = enter_netns(&names.netns);

    let veth_a_ifindex = if_nametoindex(&names.veth_a);
    let veth_a_mac = mac_of(&names.veth_a);
    assert_ne!(
        veth_a_mac, [0; 6],
        "veth_a MAC should be non-zero after `ip link set up`"
    );

    // Tokio current-thread: single-threaded runtime; no risk of a worker
    // spawning in a different netns.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let (resolver, mut events_rx, _resolve_handle) =
            NetlinkNeighborResolver::new(shutdown.clone());
        let resolver_task = tokio::spawn(resolver.run());

        // Give the resolver time to complete its RTM_GETLINK dump
        // + multicast bind. 500ms is generous; on a loaded CI runner
        // the dump completes in a few ms.
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Add a permanent neighbor entry. Kernel broadcasts
        // RTM_NEWNEIGH; resolver's multicast subscription picks it
        // up and emits NeighEvent::Learned.
        let neigh_ip = "198.51.100.7";
        let neigh_mac = "de:ad:be:ef:00:07";
        let status = Command::new("ip")
            .args([
                "-n",
                &names.netns,
                "neigh",
                "replace",
                neigh_ip,
                "dev",
                &names.veth_a,
                "lladdr",
                neigh_mac,
                "nud",
                "permanent",
            ])
            .status()
            .expect("spawn ip neigh replace");
        assert!(status.success(), "ip neigh replace exited {status}");

        // Drain events until we see the one we seeded. The resolver
        // may emit other Learneds for the kernel's self-assigned
        // link-local entries or IPv6 solicited-nodes; skip anything
        // that isn't our test address.
        let deadline = Duration::from_secs(5);
        let expected_ip: IpAddr = neigh_ip.parse().unwrap();
        let mut matched = false;
        let start = tokio::time::Instant::now();
        while start.elapsed() < deadline {
            let remaining = deadline.saturating_sub(start.elapsed());
            let evt = match timeout(remaining, events_rx.recv()).await {
                Ok(Some(e)) => e,
                Ok(None) => panic!("events_rx closed before Learned received"),
                Err(_) => break,
            };
            if let NeighEvent::Learned {
                ip,
                mac,
                ifindex,
                src_mac,
            } = evt
            {
                if ip != expected_ip {
                    continue;
                }
                assert_eq!(mac, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x07], "dst MAC");
                assert_eq!(ifindex, veth_a_ifindex, "ifindex matches veth_a");
                assert_eq!(
                    src_mac, veth_a_mac,
                    "src_mac should be the egress iface's MAC (Phase 3.6A)"
                );
                matched = true;
                break;
            }
        }
        assert!(
            matched,
            "timed out waiting for NeighEvent::Learned for {neigh_ip}"
        );

        shutdown.cancel();
        // Drop the receiver so the resolver's events_tx.send returns
        // err and its loop can exit faster.
        drop(events_rx);
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn resolver_emits_gone_on_neigh_delete() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let (resolver, mut events_rx, _) = NetlinkNeighborResolver::new(shutdown.clone());
        let resolver_task = tokio::spawn(resolver.run());
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Seed + delete the entry; expect Learned then Gone.
        let neigh_ip = "198.51.100.8";
        let neigh_mac = "de:ad:be:ef:00:08";
        Command::new("ip")
            .args([
                "-n",
                &names.netns,
                "neigh",
                "replace",
                neigh_ip,
                "dev",
                &names.veth_a,
                "lladdr",
                neigh_mac,
                "nud",
                "permanent",
            ])
            .status()
            .expect("seed neigh")
            .success()
            .then_some(())
            .expect("seed neigh status");
        // Give the Learned a moment to land.
        tokio::time::sleep(Duration::from_millis(200)).await;
        Command::new("ip")
            .args([
                "-n",
                &names.netns,
                "neigh",
                "del",
                neigh_ip,
                "dev",
                &names.veth_a,
            ])
            .status()
            .expect("del neigh")
            .success()
            .then_some(())
            .expect("del neigh status");

        let expected_ip: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));
        let deadline = Duration::from_secs(5);
        let start = tokio::time::Instant::now();
        let mut seen_gone = false;
        while start.elapsed() < deadline {
            let remaining = deadline.saturating_sub(start.elapsed());
            let evt = match timeout(remaining, events_rx.recv()).await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(_) => break,
            };
            if let NeighEvent::Gone { ip } = evt {
                if ip == expected_ip {
                    seen_gone = true;
                    break;
                }
            }
        }
        assert!(seen_gone, "expected NeighEvent::Gone for {expected_ip}");

        shutdown.cancel();
        drop(events_rx);
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}
