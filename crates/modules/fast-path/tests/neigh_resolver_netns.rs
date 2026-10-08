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
//!     from a netns test is fragile, would require an unresolved
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

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::File;
use std::mem;
use std::net::{IpAddr, Ipv4Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use packetframe_common::fib::{IpPrefix, NeighEvent, RouteEvent};
use packetframe_common::module::HealthState;
use packetframe_fast_path::fib::neigh_supervision::{
    ExitCause, SharedResolverStatus, SupervisionTiming,
};
use packetframe_fast_path::fib::netlink_neigh::{
    LocalPrefixSpec, NetlinkNeighborResolver, TestFaults,
};
use packetframe_fast_path::fib::programmer::{held_handle, recording_handle, RouteEventLog};

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

/// Like [`ns_run`] but captures stdout, for `ip neigh show` assertions.
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

/// Move the current thread into the netns and return the owned
/// /var/run/netns/<name> fd. Dropping the fd after the test is fine
/// the netns itself is torn down via `ip netns del` in NetnsGuard.
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

/// Read an iface's MAC via SIOCGIFHWADDR ioctl, netns-scoped because
/// it goes through a socket (sysfs is not reliably remounted per-netns
/// on every distro).
fn mac_of(iface: &str) -> [u8; 6] {
    // u32 + `as _`: ioctl's request parameter is `c_ulong` on glibc,
    // `c_int` on musl. See the same constant in `netns.rs`.
    const SIOCGIFHWADDR: u32 = 0x8927;

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

// --- The actual test ---------------------------------------------------

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn resolver_emits_learned_with_src_mac_and_ifindex() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);

    // Enter the netns on this thread, tokio's current-thread runtime
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
            if let NeighEvent::Gone { ip, .. } = evt {
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

/// Regression: 2026-08-20 edge1-mci1 loopback poisoning. FRR's iBGP
/// feed carries nexthops that are not neighbors at all — 0.0.0.0 for
/// self-originated routes, and its update-source, an address the box
/// itself owns. Both route-look-up to the loopback local route, and
/// `issue_proactive_resolve` used to write `RTM_NEWNEIGH NUD_NONE`
/// onto `lo` for them, replacing the kernel's implicit NUD_NOARP
/// handling for that key: every subsequent locally-delivered packet
/// to that address queued behind an ARP that can never resolve and
/// was silently dropped (invisible to tcpdump — the drop is before
/// the dev tap — and to `ip neigh show`, which hides NUD_NONE).
///
/// The guard: never probe an unspecified address, and only probe when
/// the route lookup returns RTN_UNICAST. The control probe proves the
/// guard didn't disable proactive resolve for real on-link nexthops.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn proactive_resolve_never_writes_loopback_neighbours() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    // lo up, so the local table has the exact shape of a real box
    // (setup() leaves it down; the poison required live local routes).
    ns_run(&names.netns, &["ip", "link", "set", "lo", "up"]);

    let netns = names.netns.clone();
    let veth_a = names.veth_a.clone();
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let (resolver, events_rx, resolve_handle) = NetlinkNeighborResolver::new(shutdown.clone());
        let resolver_task = tokio::spawn(resolver.run());
        tokio::time::sleep(Duration::from_millis(500)).await;

        // The two incident shapes, then a legitimate probe as control.
        // None of the three is in the startup neigh dump, so all take
        // the cache-miss path into issue_proactive_resolve.
        resolve_handle.request_resolve(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        resolve_handle.request_resolve(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 254)));
        resolve_handle.request_resolve(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)));

        // Wait until the control probe materializes as a kernel
        // neighbour entry on veth_a — `nud all` because the entry may
        // still be in NONE/INCOMPLETE (nobody answers for .77).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let neigh = ns_capture(&netns, &["ip", "neigh", "show", "nud", "all"]);
            if neigh
                .lines()
                .any(|l| l.starts_with("198.51.100.77 ") && l.contains(&veth_a))
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "control probe for 198.51.100.77 never created a neighbour entry \
                 (guard too broad?); last dump:\n{neigh}"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // With the control probe proven through, the incident shapes
        // must have left the table — and `lo` — untouched.
        let neigh = ns_capture(&netns, &["ip", "neigh", "show", "nud", "all"]);
        for line in neigh.lines() {
            assert!(
                !line.contains(" dev lo "),
                "proactive resolve wrote a loopback neighbour entry: {line}"
            );
            assert!(
                !line.starts_with("0.0.0.0 "),
                "proactive resolve probed the unspecified address: {line}"
            );
            assert!(
                !line.starts_with("198.51.100.254 "),
                "proactive resolve probed a box-owned address: {line}"
            );
        }

        shutdown.cancel();
        drop(events_rx);
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}

/// IX mode: a nexthop whose route egresses an interface declared
/// `ix-mode` must not receive the proactive `NUD_NONE` kick — on such a
/// link the kernel's resulting broadcast is dropped upstream and the
/// neigh-snoop module seeds the entry instead. A second veth pair
/// outside IX mode is the control: its nexthop is still kicked, so the
/// suppression is per egress device, not global.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn proactive_resolve_suppressed_on_ix_interfaces() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    // A second pair, C/D, on a different prefix: the non-IX control.
    let veth_c = format!("{}c", names.veth_a);
    let veth_d = format!("{}d", names.veth_a);
    ns_run(
        &names.netns,
        &[
            "ip", "link", "add", &veth_c, "type", "veth", "peer", "name", &veth_d,
        ],
    );
    ns_run(&names.netns, &["ip", "link", "set", &veth_c, "up"]);
    ns_run(&names.netns, &["ip", "link", "set", &veth_d, "up"]);
    ns_run(
        &names.netns,
        &["ip", "addr", "add", "203.0.113.254/24", "dev", &veth_c],
    );

    let netns = names.netns.clone();
    let veth_a = names.veth_a.clone();
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let (resolver, events_rx, resolve_handle) = NetlinkNeighborResolver::new(shutdown.clone());
        let resolver = resolver.with_ix_interfaces(vec![veth_a.clone()]);
        let suppressed = resolver.ix_probe_suppressed_counter();
        let resolver_task = tokio::spawn(resolver.run());
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Neither address is in the startup dump, so both take the
        // cache-miss path. .77 on the IX-mode pair must be suppressed;
        // 203.0.113.77 on the control pair must be kicked.
        resolve_handle.request_resolve(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77)));
        resolve_handle.request_resolve(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let neigh = ns_capture(&netns, &["ip", "neigh", "show", "nud", "all"]);
            if neigh
                .lines()
                .any(|l| l.starts_with("203.0.113.77 ") && l.contains(&veth_c))
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "control probe for 203.0.113.77 never created a neighbour entry \
                 (suppression too broad?); last dump:\n{neigh}"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // The control went through, so ordering is settled: the IX
        // nexthop was handled before it and must have left nothing.
        let neigh = ns_capture(&netns, &["ip", "neigh", "show", "nud", "all"]);
        for line in neigh.lines() {
            assert!(
                !line.starts_with("198.51.100.77 "),
                "proactive resolve kicked a nexthop on an ix-mode interface: {line}"
            );
        }
        assert_eq!(
            suppressed.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "exactly the IX-mode miss is counted as suppressed"
        );

        shutdown.cancel();
        drop(events_rx);
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}

// --- Overruns, stalls and supervision (2026-10-07) ----------------------
//
// On 2026-10-07 a link flush overflowed the resolver's multicast socket,
// a request's reply was dropped with the notifications, and the loop
// waited for it forever: the kernel had the nexthops, the FIB did not,
// and nothing said so. These pin the three behaviours that answer it,
// each asserted on what the programmer receives — the `Learned` that
// turns a nexthop Resolved — rather than on the mechanism.

/// Supervision timing a test can watch in seconds. The stall threshold
/// stays well above the loop's 1 s housekeeping beat, so an idle loop is
/// never mistaken for a stuck one.
fn quick_timing(stall_after: Duration) -> SupervisionTiming {
    SupervisionTiming {
        stall_after,
        check_every: Duration::from_millis(100),
        backoff_initial: Duration::from_millis(200),
        backoff_max: Duration::from_secs(1),
        backoff_reset_after: Duration::from_secs(300),
    }
}

/// Collect `Learned` events until every address in `want` has one or
/// `within` passes; returns the addresses still missing.
async fn await_learned(
    rx: &mut mpsc::Receiver<NeighEvent>,
    mut want: HashSet<IpAddr>,
    within: Duration,
) -> HashSet<IpAddr> {
    let deadline = tokio::time::Instant::now() + within;
    while !want.is_empty() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        match timeout(deadline - now, rx.recv()).await {
            Ok(Some(NeighEvent::Learned { ip, .. })) => {
                want.remove(&ip);
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!(
                "the events channel closed: the programmer's channel must outlive every \
                 incarnation of the resolver"
            ),
            Err(_) => break,
        }
    }
    want
}

/// Poll the resolver's status until `pred` holds, or panic with the last
/// status after `within`.
async fn await_status(
    status: &SharedResolverStatus,
    within: Duration,
    what: &str,
    pred: impl Fn(&packetframe_fast_path::fib::neigh_supervision::ResolverStatus) -> bool,
) {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let s = status.snapshot();
        if pred(&s) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}; status: {s:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn neigh_permanent(netns: &str, ip: &str, mac: &str, dev: &str) {
    ns_run(
        netns,
        &[
            "ip",
            "neigh",
            "replace",
            ip,
            "lladdr",
            mac,
            "dev",
            dev,
            "nud",
            "permanent",
        ],
    );
}

/// An overrun — the kernel dropping notifications on a full multicast
/// socket — is answered by a resync, and every neighbour whose
/// notification was lost still reaches the programmer as a `Learned`.
/// Before the fix the overrun was matched into `_ => {}`: those
/// neighbours stayed unknown until they next changed state, and the
/// nexthops behind them stayed `Incomplete`.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn an_overrun_is_resynced_and_every_lost_neighbour_is_learned() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let netns = names.netns.clone();
    let veth_a = names.veth_a.clone();
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let (resolver, mut events_rx, _resolve_handle) =
            NetlinkNeighborResolver::new(shutdown.clone());
        // The smallest buffer the kernel allows: a few notifications.
        let (nudges_to, nudges): (_, RouteEventLog) = recording_handle();
        let resolver = resolver
            .with_multicast_rcvbuf(4096)
            .with_reprobe_target(nudges_to);
        let status = resolver.status();
        let resolver_task = tokio::spawn(resolver.run());
        await_status(&status, Duration::from_secs(5), "the first loop", |s| {
            s.incarnation == 1
                && s.phase == packetframe_fast_path::fib::neigh_supervision::Phase::Running
        })
        .await;

        let ips: Vec<IpAddr> = (1..=200u8)
            .map(|i| IpAddr::V4(Ipv4Addr::new(198, 51, 100, i)))
            .collect();
        let batch: String = ips
            .iter()
            .enumerate()
            .map(|(i, ip)| {
                format!(
                    "neigh replace {ip} lladdr 02:00:00:00:01:{:02x} dev {veth_a} nud permanent\n",
                    i
                )
            })
            .collect();
        let path = std::env::temp_dir().join(format!("{netns}.neigh-batch"));
        std::fs::write(&path, batch).expect("write batch file");
        // Run SYNCHRONOUSLY, on the runtime's only thread: nothing reads
        // the multicast socket while the kernel delivers 200
        // notifications into a buffer that holds a handful. The
        // incident's condition — a reader starved while a flush floods
        // the groups — made certain rather than likely.
        let st = Command::new("ip")
            .args(["-n", &netns, "-batch"])
            .arg(&path)
            .status()
            .expect("spawn ip -batch");
        let _ = std::fs::remove_file(&path);
        assert!(st.success(), "ip -batch exited {st}");

        let missing = await_learned(
            &mut events_rx,
            ips.iter().copied().collect(),
            Duration::from_secs(15),
        )
        .await;
        let s = status.snapshot();
        assert!(
            s.counters.overruns >= 1,
            "the fixture must overflow the socket, or this test proves nothing: {s:?}"
        );
        assert!(
            missing.is_empty(),
            "{} of 200 neighbours were never announced after the overrun (e.g. {:?}); \
             status: {s:?}",
            missing.len(),
            missing.iter().take(5).collect::<Vec<_>>()
        );
        assert!(s.counters.resyncs >= 1, "announced by a resync: {s:?}");

        // A resynced overrun is history: the row returns to healthy, the
        // counters keep the record.
        await_status(
            &status,
            Duration::from_secs(5),
            "the resync to settle",
            |s| s.resync_owed.is_none(),
        )
        .await;
        let row = status
            .snapshot()
            .subsystem_health(std::time::Instant::now());
        assert_eq!(row.state, HealthState::Healthy, "{:?}", row.message);
        assert!(
            row.message.as_deref().unwrap_or("").contains("overruns"),
            "{:?}",
            row.message
        );
        assert_eq!(status.snapshot().counters.restarts, 0);
        // And the programmer was told to re-probe what it holds
        // unresolved, rather than wait out a backoff.
        assert!(
            nudges.reprobe_nudges() >= 1,
            "a completed resync must nudge the programmer's re-probes"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}

/// A resolver loop stuck in an await — the 2026-10-07 shape, injected
/// here as a resolve request that never completes — is noticed, dropped
/// and replaced. The replacement re-reads the kernel and announces the
/// neighbour that appeared while the stuck one was deaf, on the same
/// event channel; and it serves resolve requests from the same queue.
/// Before the fix nothing restarted the loop: the neighbour stayed
/// unannounced and every request went unanswered until the daemon
/// restarted.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn a_stuck_resolver_is_restarted_and_recovers_what_it_missed() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let netns = names.netns.clone();
    let veth_a = names.veth_a.clone();
    // Known before the resolver starts, so it is in the first view and
    // never notified again: its Learned can only come from a resolve
    // request being served.
    let known: IpAddr = "198.51.100.30".parse().unwrap();
    neigh_permanent(&netns, "198.51.100.30", "02:00:00:00:02:30", &veth_a);
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let hang: IpAddr = "198.51.100.99".parse().unwrap();
        let (resolver, mut events_rx, resolve) = NetlinkNeighborResolver::new(shutdown.clone());
        let (nudges_to, nudges): (_, RouteEventLog) = recording_handle();
        let resolver = resolver
            .with_supervision_timing(quick_timing(Duration::from_secs(3)))
            .with_test_faults(TestFaults {
                hang_on_resolve: Some(hang),
                ..TestFaults::default()
            })
            .with_reprobe_target(nudges_to);
        let status = resolver.status();
        let resolver_task = tokio::spawn(resolver.run());
        await_status(&status, Duration::from_secs(5), "the first loop", |s| {
            s.incarnation == 1
                && s.phase == packetframe_fast_path::fib::neigh_supervision::Phase::Running
        })
        .await;
        assert_eq!(
            nudges.reprobe_nudges(),
            0,
            "a first start has announced nothing, so it nudges nothing"
        );

        // Wedge the loop, then change the kernel behind its back.
        assert!(resolve.request_resolve(hang));
        tokio::time::sleep(Duration::from_millis(300)).await;
        let missed: IpAddr = "198.51.100.42".parse().unwrap();
        neigh_permanent(&netns, "198.51.100.42", "02:00:00:00:02:42", &veth_a);

        await_status(
            &status,
            Duration::from_secs(15),
            "the stuck loop to be replaced",
            |s| {
                s.incarnation == 2
                    && s.phase == packetframe_fast_path::fib::neigh_supervision::Phase::Running
            },
        )
        .await;
        let s = status.snapshot();
        assert_eq!(s.counters.restarts, 1, "{s:?}");
        let restart = s.last_restart.clone().expect("a restart is recorded");
        assert!(
            matches!(restart.cause, ExitCause::Stalled { .. }),
            "restarted for being stuck: {:?}",
            restart.cause
        );
        // The row says so, and why — never healthy straight after.
        let row = s.subsystem_health(std::time::Instant::now());
        assert_eq!(row.state, HealthState::Degraded, "{:?}", row.message);
        let msg = row.message.unwrap_or_default();
        assert!(
            msg.contains("restarted") && msg.contains("made no progress"),
            "{msg}"
        );

        // What the stuck loop never saw reaches the programmer, over the
        // channel it has held all along.
        let missing = await_learned(
            &mut events_rx,
            [missed].into_iter().collect(),
            Duration::from_secs(5),
        )
        .await;
        assert!(
            missing.is_empty(),
            "the replacement must announce the neighbour that appeared while the loop was \
             stuck; status: {:?}",
            status.snapshot()
        );

        // And the resolve queue survived the restart.
        while events_rx.try_recv().is_ok() {}
        assert!(resolve.request_resolve(known));
        let missing = await_learned(
            &mut events_rx,
            [known].into_iter().collect(),
            Duration::from_secs(3),
        )
        .await;
        assert!(
            missing.is_empty(),
            "a resolve request after the restart must be served"
        );
        assert_eq!(status.snapshot().counters.restarts, 1);
        // The restarted incarnation told the programmer to re-probe what
        // it holds unresolved, rather than wait out a backoff.
        assert!(
            nudges.reprobe_nudges() >= 1,
            "a restart must nudge the programmer's re-probes"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}

/// A long wait on the programmer — its queue full during a route-ledger
/// seed or a full-table load — is not a stuck resolver: restarting the
/// resolver could not shorten it, and a new one would wait on the same
/// programmer. The row reports the wait for what it is, and the work goes
/// through once the programmer answers.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn a_long_wait_on_the_programmer_is_not_a_stall() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let netns = names.netns.clone();
    let veth_a = names.veth_a.clone();
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let (prog, held) = held_handle();
        let (resolver, mut events_rx, _resolve) = NetlinkNeighborResolver::new(shutdown.clone());
        let stall_after = Duration::from_secs(2);
        let resolver = resolver
            .with_local_prefixes(
                vec![LocalPrefixSpec {
                    addr: "198.51.100.0".parse().unwrap(),
                    prefix_len: 24,
                    iface: veth_a.clone(),
                    arp_scavenge: false,
                }],
                prog,
            )
            .with_supervision_timing(quick_timing(stall_after));
        let status = resolver.status();
        let resolver_task = tokio::spawn(resolver.run());
        await_status(&status, Duration::from_secs(5), "the first loop", |s| {
            s.phase == packetframe_fast_path::fib::neigh_supervision::Phase::Running
        })
        .await;

        // A host inside the local prefix: its /32 goes to a programmer
        // that answers nothing yet.
        let host: IpAddr = "198.51.100.10".parse().unwrap();
        neigh_permanent(&netns, "198.51.100.10", "02:00:00:00:03:10", &veth_a);
        await_status(
            &status,
            Duration::from_secs(5),
            "the wait on the programmer",
            |s| s.programmer_wait_since.is_some(),
        )
        .await;
        // Hold it well past the stall threshold.
        tokio::time::sleep(stall_after * 3).await;
        let s = status.snapshot();
        assert_eq!(
            s.counters.restarts, 0,
            "a programmer backlog is not a stuck resolver: {s:?}"
        );
        let row = s.subsystem_health(std::time::Instant::now());
        assert_eq!(row.state, HealthState::Degraded, "{:?}", row.message);
        let msg = row.message.unwrap_or_default();
        assert!(msg.contains("FibProgrammer"), "{msg}");
        assert!(!msg.contains("no progress"), "{msg}");

        // The programmer answers; the route and the Learned go through.
        let log = held.release();
        let missing = await_learned(
            &mut events_rx,
            [host].into_iter().collect(),
            Duration::from_secs(3),
        )
        .await;
        assert!(missing.is_empty(), "the Learned follows the route");
        let host_route = IpPrefix::V4 {
            addr: [198, 51, 100, 10],
            prefix_len: 32,
        };
        assert!(
            log.events()
                .iter()
                .any(|e| matches!(e, RouteEvent::Add { prefix, .. } if *prefix == host_route)),
            "{:?}",
            log.events()
        );
        assert_eq!(status.snapshot().counters.restarts, 0);

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}

/// Run an `ip -batch` of `lines` in `netns` SYNCHRONOUSLY. Called from
/// inside a current-thread runtime, that blocks the runtime's only
/// thread, so nothing reads the resolver's multicast socket while the
/// kernel delivers the batch's notifications into it.
fn ip_batch_blocking(netns: &str, lines: &[String]) {
    let path = std::env::temp_dir().join(format!("{netns}.{}.batch", lines.len()));
    std::fs::write(&path, lines.concat()).expect("write batch file");
    let st = Command::new("ip")
        .args(["-n", netns, "-batch"])
        .arg(&path)
        .status()
        .expect("spawn ip -batch");
    let _ = std::fs::remove_file(&path);
    assert!(st.success(), "ip -batch exited {st}");
}

/// Every event received within `within`, in order.
async fn collect_events(rx: &mut mpsc::Receiver<NeighEvent>, within: Duration) -> Vec<NeighEvent> {
    let deadline = tokio::time::Instant::now() + within;
    let mut out = Vec::new();
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return out;
        }
        match timeout(deadline - now, rx.recv()).await {
            Ok(Some(e)) => out.push(e),
            Ok(None) | Err(_) => return out,
        }
    }
}

fn event_ip(e: &NeighEvent) -> IpAddr {
    match e {
        NeighEvent::Learned { ip, .. }
        | NeighEvent::Failed { ip, .. }
        | NeighEvent::Gone { ip, .. } => *ip,
    }
}

/// After an overflow the kernel hands over what it had queued *before*
/// the drop — the oldest notifications — and only then newer ones. A
/// resync that dumps while that backlog is still queued, on the same
/// socket, replays it after the dump: here a neighbour created and then
/// deleted inside one burst, whose creation survived in the backlog and
/// whose deletion was dropped, would be learned as resolved after the
/// dump said it was gone. The resync dumps on a fresh subscription and
/// drops the old one, so the stale creation is never applied. The fault
/// makes the resync run before anything after the overrun is read, so
/// the backlog is certainly still queued at the dump.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn a_resync_never_replays_the_overflowed_backlog_after_its_dump() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let netns = names.netns.clone();
    let veth_a = names.veth_a.clone();
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let (resolver, mut events_rx, resolve) = NetlinkNeighborResolver::new(shutdown.clone());
        let resolver = resolver
            .with_multicast_rcvbuf(4096)
            .with_test_faults(TestFaults {
                resync_at_overrun: true,
                ..TestFaults::default()
            });
        let status = resolver.status();
        let resolver_task = tokio::spawn(resolver.run());
        await_status(&status, Duration::from_secs(5), "the first loop", |s| {
            s.phase == packetframe_fast_path::fib::neigh_supervision::Phase::Running
        })
        .await;

        // First in the burst, so its notification is in the backlog the
        // full socket keeps; its deletion comes last, after the socket
        // has long overflowed, so that notification is dropped.
        let gone: IpAddr = "198.51.100.240".parse().unwrap();
        let fillers: Vec<IpAddr> = (1..=200u8)
            .map(|i| IpAddr::V4(Ipv4Addr::new(198, 51, 100, i)))
            .collect();
        let mut batch = vec![format!(
            "neigh replace {gone} lladdr 02:00:00:00:04:40 dev {veth_a} nud permanent\n"
        )];
        batch.extend(fillers.iter().enumerate().map(|(i, ip)| {
            format!("neigh replace {ip} lladdr 02:00:00:00:05:{i:02x} dev {veth_a} nud permanent\n")
        }));
        batch.push(format!("neigh del {gone} dev {veth_a}\n"));
        ip_batch_blocking(&netns, &batch);

        // The fillers are announced (by the resync), and nothing about
        // `gone` may end up claiming it resolved.
        let mut events = collect_events(&mut events_rx, Duration::from_secs(4)).await;
        let s = status.snapshot();
        assert!(
            s.counters.overruns >= 1 && s.counters.resyncs >= 1,
            "the fixture must overflow the socket and resync, or this test proves nothing: {s:?}"
        );
        let learned: HashSet<IpAddr> = events
            .iter()
            .filter_map(|e| match e {
                NeighEvent::Learned { ip, .. } => Some(*ip),
                _ => None,
            })
            .collect();
        let missing: Vec<&IpAddr> = fillers.iter().filter(|ip| !learned.contains(ip)).collect();
        assert!(missing.is_empty(), "fillers never announced: {missing:?}");

        // And the view must not hold it: a resolve request is a cache
        // miss (a probe nobody answers), not a Learned from a stale entry.
        assert!(resolve.request_resolve(gone));
        events.extend(collect_events(&mut events_rx, Duration::from_millis(1500)).await);
        let about_gone: Vec<&NeighEvent> = events.iter().filter(|e| event_ip(e) == gone).collect();
        assert!(
            !about_gone
                .iter()
                .any(|e| matches!(e, NeighEvent::Learned { .. })),
            "a neighbour the kernel deleted was announced as resolved, from the overflowed \
             socket's backlog replayed after the dump: {about_gone:?}"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}

/// The 2026-10-07 request — one whose reply never comes — end to end, now
/// bounded. The first request socket answers nothing, so the startup's
/// first dump times out: the timeout is counted, the socket retired, and
/// the read owed as a resync, which a fresh socket then completes. A
/// neighbour that existed all along is announced by it, and a probe goes
/// out on the fresh socket. Before the fix the dump (or any request)
/// waited forever and nothing after it ran.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn a_request_that_never_answers_times_out_and_a_fresh_socket_takes_over() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let netns = names.netns.clone();
    let veth_a = names.veth_a.clone();
    let known: IpAddr = "198.51.100.31".parse().unwrap();
    neigh_permanent(&netns, "198.51.100.31", "02:00:00:00:06:31", &veth_a);
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let (resolver, mut events_rx, resolve) = NetlinkNeighborResolver::new(shutdown.clone());
        let resolver = resolver.with_test_faults(TestFaults {
            hang_request_sockets: 1,
            ..TestFaults::default()
        });
        let status = resolver.status();
        let resolver_task = tokio::spawn(resolver.run());

        await_status(
            &status,
            Duration::from_secs(20),
            "the unanswered dump to time out",
            |s| s.counters.request_timeouts >= 1,
        )
        .await;
        let row = status
            .snapshot()
            .subsystem_health(std::time::Instant::now());
        assert_eq!(row.state, HealthState::Degraded, "{:?}", row.message);
        assert!(
            row.message.as_deref().unwrap_or("").contains("timed out"),
            "the row says what is owed and why: {:?}",
            row.message
        );

        // The fresh socket completes the owed read, which announces what
        // the timed-out one never delivered.
        let missing = await_learned(
            &mut events_rx,
            [known].into_iter().collect(),
            Duration::from_secs(15),
        )
        .await;
        assert!(
            missing.is_empty(),
            "the owed read must complete on a fresh socket; status: {:?}",
            status.snapshot()
        );
        await_status(&status, Duration::from_secs(5), "the debt to clear", |s| {
            s.resync_owed.is_none() && s.request_socket_stuck_since.is_none()
        })
        .await;

        // And probes go out again: a kick creates the kernel entry.
        assert!(resolve.request_resolve("198.51.100.78".parse().unwrap()));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let neigh = ns_capture(&netns, &["ip", "neigh", "show", "nud", "all"]);
            if neigh
                .lines()
                .any(|l| l.starts_with("198.51.100.78 ") && l.contains(&veth_a))
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no probe went out after the timeout; status: {:?}",
                status.snapshot()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let s = status.snapshot();
        assert_eq!(s.counters.request_timeouts, 1, "{s:?}");
        assert_eq!(
            s.counters.restarts, 0,
            "a bounded request is not a stall: {s:?}"
        );
        let row = s.subsystem_health(std::time::Instant::now());
        assert_eq!(row.state, HealthState::Healthy, "{:?}", row.message);

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}

/// A dump resumes from a position, and a deletion ahead of it between
/// two of its chunks can skip a live entry. A live neighbour missing
/// from a resync's (here: a restarted incarnation's) dump is confirmed
/// with a single-entry get before anything is done about it, so it is not
/// announced `Gone` — which would take its nexthop off the fast path —
/// and stays resolvable.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn a_live_neighbour_a_dump_skipped_is_not_lost() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let netns = names.netns.clone();
    let veth_a = names.veth_a.clone();
    let skipped: IpAddr = "198.51.100.32".parse().unwrap();
    neigh_permanent(&netns, "198.51.100.32", "02:00:00:00:07:32", &veth_a);
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let hang: IpAddr = "198.51.100.98".parse().unwrap();
        let (resolver, mut events_rx, resolve) = NetlinkNeighborResolver::new(shutdown.clone());
        let resolver = resolver
            .with_supervision_timing(quick_timing(Duration::from_secs(3)))
            .with_test_faults(TestFaults {
                hang_on_resolve: Some(hang),
                dump_skips: vec![skipped],
                ..TestFaults::default()
            });
        let status = resolver.status();
        let resolver_task = tokio::spawn(resolver.run());
        await_status(&status, Duration::from_secs(5), "the first loop", |s| {
            s.incarnation == 1
                && s.phase == packetframe_fast_path::fib::neigh_supervision::Phase::Running
        })
        .await;

        // A restart makes the next incarnation reconcile against a dump
        // that leaves the live neighbour out.
        assert!(resolve.request_resolve(hang));
        await_status(
            &status,
            Duration::from_secs(15),
            "the replacement incarnation",
            |s| {
                s.incarnation == 2
                    && s.phase == packetframe_fast_path::fib::neigh_supervision::Phase::Running
            },
        )
        .await;
        let events = collect_events(&mut events_rx, Duration::from_millis(500)).await;
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, NeighEvent::Gone { ip, .. } if *ip == skipped)),
            "a live neighbour a dump skipped was announced gone: {events:?}"
        );
        // Still in the view: served from it.
        assert!(resolve.request_resolve(skipped));
        let missing = await_learned(
            &mut events_rx,
            [skipped].into_iter().collect(),
            Duration::from_secs(3),
        )
        .await;
        assert!(
            missing.is_empty(),
            "the skipped neighbour must stay resolvable"
        );
        assert!(
            status.snapshot().resync_owed.is_none(),
            "a confirmed entry leaves nothing owed: {:?}",
            status.snapshot()
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}

/// A device deleted while the resolver was not listening (stuck here, or
/// an overrun) takes its neighbours with it, and their `RTM_DELNEIGH`s
/// were lost too. The next read must announce them gone and leave
/// nothing owed. Before the fix the view kept them: no dump listed them,
/// and the single-entry get that was to confirm them answered `ENODEV`,
/// read as "unknown" — a resync owed every 5 s, forever, surviving
/// restarts.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn a_device_deleted_unheard_takes_its_neighbours_and_leaves_no_debt() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let netns = names.netns.clone();
    let doomed = format!("{}x", names.veth_a);
    let doomed_peer = format!("{}y", names.veth_a);
    ns_run(
        &netns,
        &[
            "ip",
            "link",
            "add",
            &doomed,
            "type",
            "veth",
            "peer",
            "name",
            &doomed_peer,
        ],
    );
    ns_run(&netns, &["ip", "link", "set", &doomed, "up"]);
    ns_run(
        &netns,
        &["ip", "addr", "add", "203.0.113.254/24", "dev", &doomed],
    );
    let orphan: IpAddr = "203.0.113.9".parse().unwrap();
    neigh_permanent(&netns, "203.0.113.9", "02:00:00:00:09:09", &doomed);
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let hang: IpAddr = "198.51.100.97".parse().unwrap();
        let (resolver, mut events_rx, resolve) = NetlinkNeighborResolver::new(shutdown.clone());
        let resolver = resolver
            .with_supervision_timing(quick_timing(Duration::from_secs(3)))
            .with_test_faults(TestFaults {
                hang_on_resolve: Some(hang),
                ..TestFaults::default()
            });
        let status = resolver.status();
        let resolver_task = tokio::spawn(resolver.run());
        await_status(&status, Duration::from_secs(5), "the first loop", |s| {
            s.incarnation == 1
                && s.phase == packetframe_fast_path::fib::neigh_supervision::Phase::Running
        })
        .await;

        // Deaf, then the device goes: its notifications are lost with
        // the stuck incarnation's subscription.
        assert!(resolve.request_resolve(hang));
        tokio::time::sleep(Duration::from_millis(300)).await;
        ns_run(&netns, &["ip", "link", "del", &doomed]);

        await_status(
            &status,
            Duration::from_secs(15),
            "the replacement incarnation",
            |s| {
                s.incarnation == 2
                    && s.phase == packetframe_fast_path::fib::neigh_supervision::Phase::Running
            },
        )
        .await;
        let events = collect_events(&mut events_rx, Duration::from_secs(2)).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, NeighEvent::Gone { ip, .. } if *ip == orphan)),
            "a neighbour on a device deleted unheard must be announced gone: {events:?}"
        );

        // And nothing is owed: no resync retrying every 5 s for a
        // neighbour no get can ever find.
        tokio::time::sleep(Duration::from_secs(6)).await;
        let s = status.snapshot();
        assert!(s.resync_owed.is_none(), "nothing may be owed: {s:?}");
        assert_eq!(s.counters.resync_failures, 0, "{s:?}");

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}

/// On an `ix-mode` interface the proactive kick is suppressed (its
/// broadcast is dropped upstream), but a single-entry read of the
/// kernel's entry is unicast to the kernel and puts nothing on the
/// fabric. When the view missed an entry the kernel has — here its
/// notification is dropped, as an overrun drops one — the resolve
/// request must still find it. Before the fix a suppressed probe did
/// nothing, and the nexthop waited for the kernel to next change that
/// neighbour, which on an IX link may be never.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn a_suppressed_probe_reads_back_an_entry_the_view_missed() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let netns = names.netns.clone();
    let veth_a = names.veth_a.clone();
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let missed: IpAddr = "198.51.100.77".parse().unwrap();
        let (resolver, mut events_rx, resolve) = NetlinkNeighborResolver::new(shutdown.clone());
        let resolver = resolver
            .with_ix_interfaces(vec![veth_a.clone()])
            .with_test_faults(TestFaults {
                lose_notifications_for: vec![missed],
                ..TestFaults::default()
            });
        let suppressed = resolver.ix_probe_suppressed_counter();
        let status = resolver.status();
        let resolver_task = tokio::spawn(resolver.run());
        await_status(&status, Duration::from_secs(5), "the first loop", |s| {
            s.phase == packetframe_fast_path::fib::neigh_supervision::Phase::Running
        })
        .await;

        // The kernel learns it (the snooper's job on a real IX bridge);
        // the view does not.
        neigh_permanent(&netns, "198.51.100.77", "02:00:00:00:08:77", &veth_a);
        let early = collect_events(&mut events_rx, Duration::from_millis(500)).await;
        assert!(
            !early
                .iter()
                .any(|e| matches!(e, NeighEvent::Learned { ip, .. } if *ip == missed)),
            "the fixture must keep the view from hearing about it: {early:?}"
        );

        assert!(resolve.request_resolve(missed));
        let missing = await_learned(
            &mut events_rx,
            [missed].into_iter().collect(),
            Duration::from_secs(3),
        )
        .await;
        assert!(
            missing.is_empty(),
            "a suppressed probe must still read the kernel's entry back"
        );
        assert_eq!(
            suppressed.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "and it was suppressed, not kicked"
        );

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), resolver_task).await;
    });
}
