//! Integration coverage for the `local-prefix` / `local-prefix6`
//! connected fast-path against a real kernel neighbour table.
//!
//! Before this file, `NetlinkNeighborResolver::with_local_prefixes` had
//! no integration coverage at **either** family: the two tests in
//! `neigh_resolver_netns.rs` never attach a `FibProgrammerHandle`, so
//! host-route synthesis was only exercised by pure `contains()` unit
//! tests.
//!
//! The obstacle was that driving the real `FibProgrammer` needs CAP_BPF,
//! a bpffs mount and a loaded ELF, none of which the netns harness has.
//! `programmer::recording_handle()` supplies a handle that records
//! `RouteEvent`s instead of writing maps, so these tests need only
//! CAP_NET_ADMIN + CAP_SYS_ADMIN and assert on exactly the events the
//! resolver emits.
//!
//! Setup utilities are copied from `tests/netns.rs` /
//! `neigh_resolver_netns.rs` rather than shared, per the convention
//! documented there: each `tests/*.rs` is its own crate and cannot
//! import from peers.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs::File;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::Command;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use packetframe_common::fib::{IpPrefix, NeighEvent, PeerId, RouteEvent};
use packetframe_fast_path::fib::netlink_neigh::{LocalPrefixSpec, NetlinkNeighborResolver};
use packetframe_fast_path::fib::programmer::{recording_handle, RouteEventLog};

// --- Test setup utilities (copied from tests/netns.rs) -----------------

struct Names {
    netns: String,
    veth_a: String,
    veth_b: String,
}

static NAMES_COUNTER: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

impl Names {
    fn new() -> Self {
        let pid = (std::process::id() % 1000) as u16;
        let n = NAMES_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let suffix = format!("{pid:03}{n:02}");
        Self {
            netns: format!("pfln{suffix}"),
            veth_a: format!("pfla{suffix}"),
            veth_b: format!("pflb{suffix}"),
        }
    }
}

struct NetnsGuard {
    name: String,
}

impl NetnsGuard {
    fn setup(names: &Names) -> Self {
        let _ = Command::new("ip")
            .args(["netns", "del", &names.netns])
            .status();

        run(&["ip", "netns", "add", &names.netns]);
        ns_run(&names.netns, &["sysctl", "-wq", "net.ipv4.ip_forward=1"]);
        ns_run(
            &names.netns,
            &["sysctl", "-wq", "net.ipv4.conf.all.rp_filter=0"],
        );
        ns_run(
            &names.netns,
            &["sysctl", "-wq", "net.ipv6.conf.all.forwarding=1"],
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
        // `nodad` skips duplicate-address detection. Without it the
        // address sits tentative for ~1s and the interface's neighbour
        // state is in flux, which would make these tests need a sleep
        // rather than being deterministic.
        ns_run(
            &names.netns,
            &[
                "ip",
                "-6",
                "addr",
                "add",
                "2001:db8:0:1::254/64",
                "dev",
                &names.veth_a,
                "nodad",
            ],
        );
        ns_run(
            &names.netns,
            &[
                "ip",
                "-6",
                "addr",
                "add",
                "2001:db8:0:1::253/64",
                "dev",
                &names.veth_b,
                "nodad",
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

/// Best-effort variant: some probes are expected to fail (no peer
/// answers), and their failure is not the thing under test.
fn ns_run_ok(netns: &str, cmd: &[&str]) {
    let mut args = vec!["netns", "exec", netns];
    args.extend_from_slice(cmd);
    let _ = Command::new("ip").args(&args).status();
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

fn if_nametoindex(name: &str) -> u32 {
    let c = CString::new(name).expect("iface name with NUL");
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    assert!(idx > 0, "if_nametoindex({name}) failed");
    idx
}

// --- Harness -----------------------------------------------------------

/// Spin up a resolver with `specs` wired to a recording handle, run
/// `body` (which seeds neighbour state), then return the recorded
/// events.
///
/// Uses a current-thread runtime so every spawned task inherits the
/// netns this thread was moved into — the same requirement documented in
/// `neigh_resolver_netns.rs`.
fn collect_events(
    netns: &str,
    specs: Vec<LocalPrefixSpec>,
    body: impl FnOnce(&str),
) -> (Vec<RouteEvent>, Vec<NeighEvent>) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime");

    rt.block_on(async move {
        let shutdown = CancellationToken::new();
        let (resolver, mut events_rx, _resolve_handle) =
            NetlinkNeighborResolver::new(shutdown.clone());
        let (prog, log): (_, RouteEventLog) = recording_handle();
        let resolver = resolver.with_local_prefixes(specs, prog);

        let task = tokio::spawn(async move {
            let _ = resolver.run().await;
        });

        // Let the RTM_GETLINK / RTM_GETNEIGH dumps land and the
        // multicast socket bind before mutating neighbour state.
        tokio::time::sleep(Duration::from_millis(500)).await;

        body(netns);

        // Give the multicast path time to deliver and the emission path
        // time to dispatch into the recording handle.
        tokio::time::sleep(Duration::from_millis(600)).await;

        shutdown.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(2), task).await;

        // Drain whatever NeighEvents the resolver produced. Nothing
        // consumed the channel during the run (the tests replace the
        // programmer with a recording handle), so the buffered backlog
        // is the complete stream — EVENTS_CAPACITY is 8192, far above
        // anything these single-digit-neighbour tests generate.
        let mut neigh_events = Vec::new();
        while let Ok(e) = events_rx.try_recv() {
            neigh_events.push(e);
        }
        (log.events(), neigh_events)
    })
}

fn spec(cidr: &str, prefix_len: u8, iface: &str) -> LocalPrefixSpec {
    LocalPrefixSpec {
        addr: cidr.parse().expect("addr"),
        prefix_len,
        iface: iface.to_string(),
        arp_scavenge: false,
    }
}

/// Every `Add`ed prefix in the log, as `(IpAddr, prefix_len)`.
fn added_prefixes(events: &[RouteEvent]) -> Vec<(IpAddr, u8)> {
    events
        .iter()
        .filter_map(|e| match e {
            RouteEvent::Add { prefix, .. } => Some(prefix_to_ip(prefix)),
            _ => None,
        })
        .collect()
}

fn deleted_prefixes(events: &[RouteEvent]) -> Vec<(IpAddr, u8)> {
    events
        .iter()
        .filter_map(|e| match e {
            RouteEvent::Del { prefix, .. } => Some(prefix_to_ip(prefix)),
            _ => None,
        })
        .collect()
}

fn prefix_to_ip(p: &IpPrefix) -> (IpAddr, u8) {
    match p {
        IpPrefix::V4 { addr, prefix_len } => (IpAddr::from(*addr), *prefix_len),
        IpPrefix::V6 { addr, prefix_len } => (IpAddr::from(*addr), *prefix_len),
    }
}

// --- Tests -------------------------------------------------------------

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn local_prefix6_emits_slash128_for_kernel_neighbour() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let _nsfd = enter_netns(&names.netns);
    let ifindex = if_nametoindex(&names.veth_a);
    let host: IpAddr = "2001:db8:0:1::7".parse().unwrap();

    let veth_a = names.veth_a.clone();
    let (events, _) = collect_events(
        &names.netns,
        vec![spec("2001:db8:0:1::", 64, &names.veth_a)],
        |ns| {
            ns_run(
                ns,
                &[
                    "ip",
                    "-6",
                    "neigh",
                    "replace",
                    "2001:db8:0:1::7",
                    "dev",
                    &veth_a,
                    "lladdr",
                    "de:ad:be:ef:00:07",
                    "nud",
                    "permanent",
                ],
            );
        },
    );

    let adds = added_prefixes(&events);
    assert!(
        adds.contains(&(host, 128)),
        "expected a /128 Add for {host}; got {adds:?}"
    );

    // The Add must name the host as its own nexthop and carry the
    // per-iface local_arp peer. That self-nexthop is what makes NDP
    // resolve to the host's own MAC rather than an upstream gateway.
    let add = events
        .iter()
        .find(
            |e| matches!(e, RouteEvent::Add { prefix, .. } if prefix_to_ip(prefix) == (host, 128)),
        )
        .expect("the /128 Add");
    match add {
        RouteEvent::Add {
            peer_id, nexthops, ..
        } => {
            assert_eq!(*peer_id, PeerId::local_arp(ifindex));
            assert_eq!(nexthops, &vec![host], "nexthop must be the host itself");
        }
        other => panic!("expected Add, got {other:?}"),
    }
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn local_prefix6_withdraws_slash128_on_neigh_delete() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let _nsfd = enter_netns(&names.netns);
    let host: IpAddr = "2001:db8:0:1::8".parse().unwrap();

    let veth_a = names.veth_a.clone();
    let (events, _) = collect_events(
        &names.netns,
        vec![spec("2001:db8:0:1::", 64, &names.veth_a)],
        |ns| {
            ns_run(
                ns,
                &[
                    "ip",
                    "-6",
                    "neigh",
                    "replace",
                    "2001:db8:0:1::8",
                    "dev",
                    &veth_a,
                    "lladdr",
                    "de:ad:be:ef:00:08",
                    "nud",
                    "permanent",
                ],
            );
            std::thread::sleep(Duration::from_millis(200));
            ns_run(
                ns,
                &[
                    "ip",
                    "-6",
                    "neigh",
                    "del",
                    "2001:db8:0:1::8",
                    "dev",
                    &veth_a,
                ],
            );
        },
    );

    assert!(
        added_prefixes(&events).contains(&(host, 128)),
        "expected the /128 to be added first; got {events:?}"
    );
    assert!(
        deleted_prefixes(&events).contains(&(host, 128)),
        "expected a /128 Del after `ip -6 neigh del`; got {events:?}"
    );
}

/// The emission-time gate, proved against the kernel's own neighbour
/// table rather than synthetic events.
///
/// A well-formed `/64` excludes `ff02::` and `fe80::` by containment, so
/// this configures the pathological `::/0` that the config parser
/// rejects — reachable only by constructing `LocalPrefixSpec` directly,
/// which is exactly the belt-and-braces case `may_synthesize` exists for.
/// Multicast entries are `NUD_NOARP` with a derived `33:33:xx` MAC and
/// are never garbage-collected, so without the gate they would install
/// permanent bogus `/128`s.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn local_prefix6_slash0_does_not_harvest_multicast_or_link_local() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let _nsfd = enter_netns(&names.netns);
    let host: IpAddr = "2001:db8:0:1::9".parse().unwrap();

    let veth_a = names.veth_a.clone();
    let (events, _) = collect_events(&names.netns, vec![spec("::", 0, &names.veth_a)], |ns| {
        // Force the kernel to create multicast and link-local neighbour
        // entries on the interface.
        ns_run_ok(
            ns,
            &["ping6", "-c", "1", "-W", "1", "-I", &veth_a, "ff02::1"],
        );
        ns_run_ok(ns, &["ip", "-6", "neigh", "add", "ff02::1", "dev", &veth_a]);
        ns_run_ok(
            ns,
            &[
                "ip",
                "-6",
                "neigh",
                "replace",
                "fe80::dead:beef",
                "dev",
                &veth_a,
                "lladdr",
                "de:ad:be:ef:00:fe",
                "nud",
                "permanent",
            ],
        );
        // A legitimate global-unicast host, which must still be picked up.
        ns_run(
            ns,
            &[
                "ip",
                "-6",
                "neigh",
                "replace",
                "2001:db8:0:1::9",
                "dev",
                &veth_a,
                "lladdr",
                "de:ad:be:ef:00:09",
                "nud",
                "permanent",
            ],
        );
    });

    let adds = added_prefixes(&events);
    for (ip, _len) in &adds {
        let IpAddr::V6(v6) = ip else { continue };
        assert!(
            !v6.is_multicast(),
            "multicast {v6} must never be harvested; adds: {adds:?}"
        );
        let o = v6.octets();
        assert!(
            !(o[0] == 0xfe && (o[1] & 0xc0) == 0x80),
            "link-local {v6} must never be harvested; adds: {adds:?}"
        );
        assert!(!v6.is_unspecified() && !v6.is_loopback());
    }
    assert!(
        adds.contains(&(host, 128)),
        "the global-unicast host must still be harvested; adds: {adds:?}"
    );
}

/// Regression guard: the v6 work removed three `IpAddr::V4` guards that
/// the v4 path shared, so v4 synthesis must be re-proved.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn local_prefix_v4_still_emits_slash32() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let _nsfd = enter_netns(&names.netns);
    let ifindex = if_nametoindex(&names.veth_a);
    let host: IpAddr = "198.51.100.7".parse().unwrap();

    let veth_a = names.veth_a.clone();
    let (events, _) = collect_events(
        &names.netns,
        vec![spec("198.51.100.0", 24, &names.veth_a)],
        |ns| {
            ns_run(
                ns,
                &[
                    "ip",
                    "neigh",
                    "replace",
                    "198.51.100.7",
                    "dev",
                    &veth_a,
                    "lladdr",
                    "de:ad:be:ef:00:07",
                    "nud",
                    "permanent",
                ],
            );
        },
    );

    let adds = added_prefixes(&events);
    assert!(
        adds.contains(&(host, 32)),
        "expected a /32 Add for {host}; got {adds:?}"
    );
    let add = events
        .iter()
        .find(|e| matches!(e, RouteEvent::Add { prefix, .. } if prefix_to_ip(prefix) == (host, 32)))
        .expect("the /32 Add");
    match add {
        RouteEvent::Add { peer_id, .. } => assert_eq!(*peer_id, PeerId::local_arp(ifindex)),
        other => panic!("expected Add, got {other:?}"),
    }
}

/// `RTM_DELLINK` emits one `PeerDown` for the interface, and because the
/// `PeerId` is family-blind that single event withdraws both the v4
/// `/32`s and the v6 `/128`s behind it. `maybe_emit_local_arp_peerdown`
/// was also previously untested.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn local_prefix_peer_down_on_dellink_covers_both_families() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let _nsfd = enter_netns(&names.netns);
    let ifindex = if_nametoindex(&names.veth_a);

    let veth_a = names.veth_a.clone();
    let (events, _) = collect_events(
        &names.netns,
        vec![
            spec("198.51.100.0", 24, &names.veth_a),
            spec("2001:db8:0:1::", 64, &names.veth_a),
        ],
        |ns| {
            ns_run(
                ns,
                &[
                    "ip",
                    "neigh",
                    "replace",
                    "198.51.100.7",
                    "dev",
                    &veth_a,
                    "lladdr",
                    "de:ad:be:ef:00:07",
                    "nud",
                    "permanent",
                ],
            );
            ns_run(
                ns,
                &[
                    "ip",
                    "-6",
                    "neigh",
                    "replace",
                    "2001:db8:0:1::7",
                    "dev",
                    &veth_a,
                    "lladdr",
                    "de:ad:be:ef:01:07",
                    "nud",
                    "permanent",
                ],
            );
            std::thread::sleep(Duration::from_millis(250));
            ns_run(ns, &["ip", "link", "del", &veth_a]);
        },
    );

    // Both families were synthesized under the same peer...
    let adds = added_prefixes(&events);
    assert!(
        adds.contains(&("198.51.100.7".parse().unwrap(), 32)),
        "adds: {adds:?}"
    );
    assert!(
        adds.contains(&("2001:db8:0:1::7".parse().unwrap(), 128)),
        "adds: {adds:?}"
    );

    // ...and one PeerDown for the ifindex tears both down.
    let peer_downs: Vec<PeerId> = events
        .iter()
        .filter_map(|e| match e {
            RouteEvent::PeerDown { peer_id } => Some(*peer_id),
            _ => None,
        })
        .collect();
    assert!(
        peer_downs.contains(&PeerId::local_arp(ifindex)),
        "expected PeerDown for local_arp({ifindex}); got {peer_downs:?}"
    );
}

/// The startup-seed path, as opposed to the incremental RTM_NEWNEIGH
/// path every other test here exercises: the neighbour exists *before*
/// the resolver starts, so it arrives via the RTM_GETNEIGH dump and
/// `seed_local_prefix_routes`.
///
/// Asserts the two halves of seeding independently: the RouteEvent::Add
/// that installs the /128, and the synthetic NeighEvent::Learned that
/// resolves it. The Learned must come directly from the dump snapshot —
/// not via the bounded resolve queue, which nothing drains during
/// seeding, so past RESOLVE_QUEUE_CAPACITY matching neighbours the
/// queue-dependent design left routes Incomplete (flagged by review on
/// PR #72). A stable pre-existing neighbour may never multicast again,
/// making the direct emission the only reliable resolution source.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn local_prefix6_seed_resolves_preexisting_neighbour_without_resolve_queue() {
    let names = Names::new();
    let _guard = NetnsGuard::setup(&names);
    let _nsfd = enter_netns(&names.netns);
    let ifindex = if_nametoindex(&names.veth_a);
    let host: IpAddr = "2001:db8:0:1::42".parse().unwrap();
    let host_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x42];

    // Neighbour exists BEFORE the resolver starts.
    ns_run(
        &names.netns,
        &[
            "ip",
            "-6",
            "neigh",
            "replace",
            "2001:db8:0:1::42",
            "dev",
            &names.veth_a,
            "lladdr",
            "de:ad:be:ef:00:42",
            "nud",
            "permanent",
        ],
    );

    let (events, neigh_events) = collect_events(
        &names.netns,
        vec![spec("2001:db8:0:1::", 64, &names.veth_a)],
        |_ns| {}, // no mutations after startup; everything comes from the seed
    );

    // Half one: the /128 was installed from the dump.
    assert!(
        added_prefixes(&events).contains(&(host, 128)),
        "seed must install the /128 for a pre-existing neighbour; got {events:?}"
    );

    // Half two: the seed itself emitted the synthetic Learned with the
    // kernel-cached MAC, so resolution never depended on the resolve
    // queue round-trip.
    let learned = neigh_events.iter().any(|e| {
        matches!(
            e,
            NeighEvent::Learned { ip, mac, ifindex: ifi, .. }
                if *ip == host && *mac == host_mac && *ifi == ifindex
        )
    });
    assert!(
        learned,
        "seed must emit a synthetic Learned for {host} with {host_mac:02x?}; \
         got {neigh_events:?}"
    );
}
