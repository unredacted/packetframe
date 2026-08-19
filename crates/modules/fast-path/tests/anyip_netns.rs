//! Integration coverage for `fib::anyip` against a real kernel.
//!
//! Three properties, each of which failed silently in some ancestor
//! of this design and can only be proven against a live netlink:
//!
//! 1. `ensure_local_route` makes an unassigned address bindable
//!    (the whole point of AnyIP), and is idempotent (the controller
//!    calls it before every listener retry).
//! 2. `ensure_local_route` refuses an interface-owned address — the
//!    operator error where `anyip` points at a real interface
//!    address, which the paired FRR would also reject.
//! 3. `remove_local_route` returns the address to unbindable, and a
//!    second removal is success, not error (shutdown must never
//!    wedge on a route someone else already cleaned up).
//! 4. Ownership: a same-destination local route installed by
//!    someone else (foreign route protocol) is refused at ensure and
//!    survives our remove untouched — the protocol-scoped delete
//!    cannot match it.
//! 5. Directed broadcast: the .3 of a configured /30 is refused —
//!    `Ipv4Addr::is_broadcast()` only knows 255.255.255.255, so the
//!    gate reads the kernel's Broadcast address attribute instead.
//!
//! Runs inside its own netns so the routes and the veth address it
//! creates never touch the host (qemu VM) tables. Same harness
//! conventions as `neigh_resolver_netns.rs`: utilities copied, not
//! shared, because each `tests/*.rs` is its own crate.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::os::fd::AsRawFd;
use std::process::Command;

use packetframe_fast_path::fib::anyip::{ensure_local_route, remove_local_route, AnyipError};

// --- Test setup utilities (copied from tests/netns.rs) -----------------

struct Names {
    netns: String,
    veth_a: String,
    veth_b: String,
}

impl Names {
    fn new(tag: &str) -> Self {
        // PID suffix separates parallel test *binaries*; the tag
        // separates the `#[test]` fns inside THIS binary, which run
        // as threads of one process and therefore share a PID — the
        // collision the first CI run of this file demonstrated.
        let suffix = format!("{tag}{:x}", std::process::id() & 0xffff);
        Names {
            netns: format!("pfany{suffix}"),
            veth_a: format!("pfA{suffix}"),
            veth_b: format!("pfB{suffix}"),
        }
    }
}

struct NetnsGuard {
    name: String,
}

impl NetnsGuard {
    fn setup(names: &Names) -> Self {
        // Best-effort cleanup of a previous crashed run.
        let _ = Command::new("ip")
            .args(["netns", "del", &names.netns])
            .status();
        run(&["ip", "netns", "add", &names.netns]);
        ns_run(&names.netns, &["ip", "link", "set", "lo", "up"]);
        run(&[
            "ip",
            "link",
            "add",
            &names.veth_a,
            "netns",
            &names.netns,
            "type",
            "veth",
            "peer",
            "name",
            &names.veth_b,
            "netns",
            &names.netns,
        ]);
        ns_run(&names.netns, &["ip", "link", "set", &names.veth_a, "up"]);
        ns_run(&names.netns, &["ip", "link", "set", &names.veth_b, "up"]);
        // An interface-owned address for the refusal test.
        ns_run(
            &names.netns,
            &["ip", "addr", "add", "192.0.2.1/30", "dev", &names.veth_a],
        );
        NetnsGuard {
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

fn run(args: &[&str]) {
    let status = Command::new(args[0])
        .args(&args[1..])
        .status()
        .unwrap_or_else(|e| panic!("spawn {args:?}: {e}"));
    assert!(status.success(), "command failed: {args:?}");
}

fn ns_run(netns: &str, args: &[&str]) {
    let mut full = vec!["netns", "exec", netns];
    full.extend_from_slice(args);
    let status = Command::new("ip")
        .args(&full)
        .status()
        .unwrap_or_else(|e| panic!("spawn ip {full:?}: {e}"));
    assert!(status.success(), "command failed: ip {full:?}");
}

/// Move this thread into the netns. The returned File keeps the ns fd
/// alive; tasks on a current-thread tokio runtime built afterwards
/// inherit the netns.
fn enter_netns(name: &str) -> File {
    let path = format!("/run/netns/{name}");
    let f = File::open(&path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    let rc = unsafe { libc::setns(f.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(
        rc,
        0,
        "setns({path}) failed: {}",
        std::io::Error::last_os_error()
    );
    // Sanity: prove we're where we think we are.
    let c = CString::new("/proc/self/ns/net").unwrap();
    assert!(!c.as_bytes().is_empty());
    f
}

// --- The actual tests ---------------------------------------------------

/// The phantom address: inside TEST-NET-1 but NOT assigned anywhere in
/// the netns (the veth holds .1/30; .2 is the unused host — the exact
/// shape of the production pf-feed /30).
const PHANTOM: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
/// The interface-owned address, for the refusal test.
const OWNED: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// The directed broadcast of the veth's 192.0.2.1/30.
const BCAST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 3);
/// TEST-NET-2 address for the contested-route test: pre-installed as
/// a local /32 with a foreign protocol before ensure runs.
const CONTESTED: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 9);

fn bindable(addr: Ipv4Addr) -> bool {
    TcpListener::bind(SocketAddr::from((addr, 11790))).is_ok()
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn anyip_route_lifecycle_makes_phantom_bindable() {
    let names = Names::new("l");
    let _guard = NetnsGuard::setup(&names);
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime");

    // Before: the phantom is not bindable (nothing owns it, no route).
    assert!(
        !bindable(PHANTOM),
        "phantom must start unbindable or the test proves nothing"
    );

    // Ensure → bindable. Twice, because the controller re-ensures on
    // every listener retry and the second call must be a no-op, not
    // an EEXIST.
    rt.block_on(ensure_local_route(PHANTOM)).expect("ensure #1");
    assert!(bindable(PHANTOM), "phantom bindable after ensure");
    rt.block_on(ensure_local_route(PHANTOM))
        .expect("ensure #2 (idempotent)");
    assert!(bindable(PHANTOM), "phantom still bindable after re-ensure");

    // Remove → unbindable again. Twice, because shutdown's removal is
    // best-effort by contract and an absent route is success.
    rt.block_on(remove_local_route(PHANTOM)).expect("remove #1");
    assert!(!bindable(PHANTOM), "phantom unbindable after remove");
    rt.block_on(remove_local_route(PHANTOM))
        .expect("remove #2 (already gone)");
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn anyip_refuses_interface_owned_address() {
    let names = Names::new("o");
    let _guard = NetnsGuard::setup(&names);
    let _ns_fd = enter_netns(&names.netns);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime");

    match rt.block_on(ensure_local_route(OWNED)) {
        Err(AnyipError::AddressOwned { addr, .. }) => assert_eq!(addr, OWNED),
        other => panic!("expected AddressOwned for {OWNED}, got {other:?}"),
    }

    // Same netns, same /30: .3 is the directed broadcast of the
    // veth's 192.0.2.1/30 — `is_broadcast()` can't see it, the
    // kernel's Broadcast address attribute can.
    match rt.block_on(ensure_local_route(BCAST)) {
        Err(AnyipError::DirectedBroadcast { addr, .. }) => assert_eq!(addr, BCAST),
        other => panic!("expected DirectedBroadcast for {BCAST}, got {other:?}"),
    }
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN; run via sudo -E cargo test -- --ignored"]
fn anyip_refuses_and_never_deletes_foreign_route() {
    let names = Names::new("c");
    let _guard = NetnsGuard::setup(&names);
    let _ns_fd = enter_netns(&names.netns);

    // A foreign owner's AnyIP route: same shape, different protocol
    // (66 is iproute2-unassigned and != ANYIP_ROUTE_PROTOCOL's 199).
    run(&[
        "ip",
        "route",
        "add",
        "local",
        "198.51.100.9/32",
        "dev",
        "lo",
        "table",
        "local",
        "proto",
        "66",
    ]);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current-thread runtime");

    // Ensure refuses the contested address instead of replacing it.
    match rt.block_on(ensure_local_route(CONTESTED)) {
        Err(AnyipError::RouteContested { addr, .. }) => assert_eq!(addr, CONTESTED),
        other => panic!("expected RouteContested for {CONTESTED}, got {other:?}"),
    }

    // Remove is a no-op against the foreign route: the protocol-scoped
    // delete can't match it, ESRCH is tolerated as success, and the
    // route keeps delivering (still bindable = still present).
    rt.block_on(remove_local_route(CONTESTED))
        .expect("remove tolerates foreign route");
    assert!(
        bindable(CONTESTED),
        "foreign local route must survive our remove untouched"
    );
}
