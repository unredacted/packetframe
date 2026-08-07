//! The whole supervision loop against the fake VPP: `Driver` + `Runtime`
//! + a real unix socket, host CI.
//!
//! Every previous test drove one layer with the others faked. This is
//! the first composition of all of them — the driver's tick loop,
//! the runtime's delegation, the engine's transport, the drainer's
//! pipeline — with the only fake being VPP itself, and that fake speaks
//! the real wire format from the same generated types.
//!
//! The loop harness here (`run_until`) is the same shape the attach
//! wiring will use: tick, then drain `take_pending` into
//! `Driver::inject`, then honour `sleep`. If that shape cannot converge
//! a five-route table here, it cannot converge a million-route one on
//! the router.

#[path = "common/fake_vpp.rs"]
mod fake_vpp;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use fake_vpp::{Fake, ASSIGNED_INDEX, MAC};
use packetframe_common::fib::IpPrefix;
use packetframe_vpp_offload::attach::PortAttach;
use packetframe_vpp_offload::driver::Driver;
use packetframe_vpp_offload::engine::{ConvergenceEngine, RouteSource};
use packetframe_vpp_offload::fib_sync::FamilyPolicy;
use packetframe_vpp_offload::runtime::{NoResources, NullStore, Runtime, SteeringUnavailable};
use packetframe_vpp_offload::supervisor::{Event, State};

struct Mirror {
    routes: Vec<IpPrefix>,
}

impl RouteSource for Mirror {
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        for p in &self.routes {
            visit(*p, &[fake_vpp::nh()]);
        }
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(fake_vpp::nh(), "eth4", MAC);
    }
}

fn runtime_with_source(fake: &Fake, source: Box<dyn RouteSource>) -> Runtime {
    let engine = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        }],
        vec!["eth4".into()],
        1_000_000,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    );
    Runtime::new(
        engine,
        source,
        Box::new(SteeringUnavailable),
        Box::new(NullStore),
        Box::new(NoResources),
        "/usr/bin/vpp",
        "/tmp/startup.conf",
    )
}

fn runtime_for(fake: &Fake, n_routes: u8) -> Runtime {
    let mirror = Mirror {
        routes: (0..n_routes).map(|i| fake_vpp::v4(0, i)).collect(),
    };
    runtime_with_source(fake, Box::new(mirror))
}

/// The production loop shape: tick, inject completed work, honour the
/// sleep by advancing the clock. Bounded so a loop that cannot settle
/// fails instead of hanging CI.
fn run_until(
    d: &mut Driver,
    rt: &Runtime,
    mut now: Instant,
    stop: impl Fn(&Driver) -> bool,
) -> (Instant, Vec<Event>) {
    let (mut obs, mut fx) = rt.views();
    let mut seen = Vec::new();
    for _ in 0..256 {
        if stop(d) {
            return (now, seen);
        }
        let t = d.tick(now, &mut obs, &mut fx);
        seen.extend(t.events.clone());
        for e in rt.take_pending() {
            // inject() reports the event back in its own Tick.events,
            // so extending with those alone counts each exactly once.
            let it = d.inject(now, e, &mut fx);
            seen.extend(it.events);
        }
        rt.set_steered(d.supervisor().is_steered());
        // Advance by the permitted sleep, floored so time always moves.
        now += t
            .sleep
            .unwrap_or(Duration::from_millis(100))
            .max(Duration::from_millis(1));
    }
    panic!("loop did not reach the stop condition; events: {seen:?}");
}

/// Adoption → attach → resync → verify → Ready, end to end, with the
/// verdict travelling through `take_pending` exactly as the real loop
/// will carry it.
#[test]
fn the_full_loop_converges_an_adopted_vpp_to_ready() {
    let fake = Fake::start("loop");
    let rt = runtime_for(&fake, 5);
    let mut d = Driver::new();
    let t0 = Instant::now();

    // The attach wiring connects and confirms the API answers before it
    // injects the adoption — an adopted VPP whose socket is dead is not
    // one to adopt. Mirror that here.
    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready(), "the fake must answer the handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(t0, Event::Adopted { steered: false }, &mut fx);
    }
    assert_eq!(d.state(), State::Syncing);

    let (_, events) = run_until(&mut d, &rt, t0, |d| d.state() == State::Ready);

    // The verdict must have arrived through the pending seam.
    assert!(
        events.contains(&Event::SyncComplete),
        "the drain reported completion: {events:?}"
    );
    assert!(
        events.contains(&Event::VerifyPassed),
        "the verdict was injected: {events:?}"
    );
    assert!(
        !d.supervisor().is_steered(),
        "an unsteered adoption waits for the operator's canary"
    );

    // And the table is really in the fake, on the index VPP assigned.
    let status = rt.status();
    assert_eq!(status.counts.installed, 5);
    assert!(!status.counts.blocks_first_steer());
    let routes: Vec<_> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            fake_vpp::Event::Route(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(routes.len(), 5);
    assert!(routes
        .iter()
        .all(|r| r.path_indices == vec![ASSIGNED_INDEX]));
}

/// A drain that dies mid-resync must fail convergence, deliver the
/// abort acknowledgement, and reach a retryable state — not spin, not
/// hang, not absorb the error.
///
/// The retry itself goes through `Spawn`, which host CI cannot perform
/// (there is no VPP binary, and on non-Linux the process handle is an
/// ENOSYS stub) — so this asserts the failure path up to and including
/// the retry *attempt*, and full crash-recovery with a respawn stays
/// hardware territory alongside the failover drills.
#[test]
fn a_broken_socket_mid_resync_fails_convergence_and_retries() {
    // Hang up after 2 route ops, once; later connections behave.
    let fake = Fake::start_with("loop-hangup", 2);
    let rt = runtime_for(&fake, 8);
    let mut d = Driver::new();
    let t0 = Instant::now();

    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready());
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(t0, Event::Adopted { steered: false }, &mut fx);
    }

    let (_, events) = run_until(&mut d, &rt, t0, |d| {
        d.supervisor().failures() > 0 && d.state() != State::Syncing
    });

    assert!(
        events.contains(&Event::ConvergenceFailed),
        "the hangup must be reported, not absorbed: {events:?}"
    );
    assert!(
        events.contains(&Event::ConvergenceStopped),
        "the abort must be acknowledged, or may_restart never clears: {events:?}"
    );

    let first_failures = d.supervisor().failures();
    assert!(first_failures > 0);
    // Drive on from a clock past the backoff deadline until the retry
    // is attempted and itself fails (a second recorded failure). The
    // state is already `Backoff` at entry, so stopping on state would
    // stop before a single tick.
    let (_, more) = run_until(&mut d, &rt, t0 + Duration::from_secs(60), |d| {
        d.supervisor().failures() > first_failures
    });
    let all: Vec<_> = events.iter().chain(more.iter()).cloned().collect();
    assert!(
        more.contains(&Event::BackoffElapsed),
        "the backoff must fire a retry: {all:?}"
    );
    assert!(
        all.contains(&Event::SpawnFailed),
        "host CI has no VPP to spawn, and that must be reported as \
         SpawnFailed — not sat on: {all:?}"
    );

    // Nothing was silently lost: the routes the hangup interrupted are
    // still owed, so a real respawn would converge them.
    let status = rt.status();
    assert!(
        status.pending_ops > 0,
        "unacknowledged work must still be pending after the failure"
    );
    assert!(
        status.counts.installed <= 2,
        "only routes the fake acknowledged before hanging up may count"
    );
}

/// A persist that fails and later succeeds must stop being reported.
///
/// `last_store_error` was set on every failure and never cleared, so one
/// transient failure — a briefly read-only state dir, a full filesystem —
/// kept the module out of `nominal()` for the life of the service even
/// once the record was durable again. Clearing is safe precisely because
/// the save is whole-record: `FileStore` writes the entire
/// `ResourceState` on every observation, so any write that lands makes
/// hugepages, VFs, indices and process identity current together.
///
/// Driven through the real seam (`Effects::attach_devices` against the
/// fake VPP) rather than at the loop level: the loop only re-persists
/// during a fresh convergence, which needs a restart and therefore a real
/// process. Two calls here is the same event the loop would produce.
#[test]
fn a_persist_that_recovers_clears_the_recorded_failure() {
    use packetframe_vpp_offload::executor::Effects as _;
    use packetframe_vpp_offload::runtime::{IdentityStore, ProcessIdentity};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct Flaky(Arc<AtomicBool>);
    impl IdentityStore for Flaky {
        fn process_changed(&mut self, _: Option<ProcessIdentity>) -> Result<(), String> {
            Ok(())
        }
        fn interfaces_attached(&mut self, _: &[(String, u32)]) -> Result<(), String> {
            if self.0.load(Ordering::SeqCst) {
                Err("state dir is read-only".into())
            } else {
                Ok(())
            }
        }
        fn steering_changed(&mut self, _: &[(String, u32)]) -> Result<(), String> {
            Ok(())
        }
    }

    let fake = Fake::start("store-recover");
    let failing = Arc::new(AtomicBool::new(true));
    let engine = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        }],
        vec!["eth4".into()],
        1_000_000,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    );
    let rt = Runtime::new(
        engine,
        Box::new(Mirror {
            routes: vec![fake_vpp::v4(0, 0)],
        }),
        Box::new(SteeringUnavailable),
        Box::new(Flaky(Arc::clone(&failing))),
        Box::new(packetframe_vpp_offload::runtime::NoResources),
        "/usr/bin/vpp",
        "/dev/null",
    );
    {
        use packetframe_vpp_offload::driver::Observe as _;
        let (mut obs, _) = rt.views();
        assert!(obs.api_ready(), "the fake must answer the handshake");
    }

    let (_, mut fx) = rt.views();
    fx.attach_devices()
        .expect("attach succeeds; only the RECORD fails");
    assert!(
        rt.status().store_error.is_some(),
        "the failed persist must be surfaced"
    );

    // The underlying problem goes away; the next successful persist makes
    // the whole record durable, so the degradation must end with it.
    failing.store(false, Ordering::SeqCst);
    fx.attach_devices().expect("attach still succeeds");
    assert!(
        rt.status().store_error.is_none(),
        "a successful persist left the earlier failure reported; health would stay \
         Degraded for the life of the service: {:?}",
        rt.status().store_error
    );
}

/// A successful SPAWN persist clears an earlier store failure too.
///
/// `spawn` kept its own direct `store.process_changed` call while
/// `note_persist`'s doc claimed to be the single recorder — so a store that
/// failed on an exit and recovered before the retry spawn went on reporting
/// "observed state is not durable" until a later device attach happened to
/// succeed, potentially for the whole API startup interval. The class is
/// exactly the one this module keeps producing: prose asserting a single
/// owner, with a writer in the same file going around it.
///
/// Linux-only because it needs a real spawn; `/bin/true` is enough — the
/// child's behaviour is irrelevant, only that a pid was recorded.
#[cfg(target_os = "linux")]
#[test]
fn a_successful_spawn_persist_clears_an_earlier_store_failure() {
    use packetframe_vpp_offload::executor::Effects as _;
    use packetframe_vpp_offload::runtime::{IdentityStore, ProcessIdentity};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct Flaky(Arc<AtomicBool>);
    impl IdentityStore for Flaky {
        fn process_changed(&mut self, _: Option<ProcessIdentity>) -> Result<(), String> {
            if self.0.load(Ordering::SeqCst) {
                Err("state dir is read-only".into())
            } else {
                Ok(())
            }
        }
        fn interfaces_attached(&mut self, _: &[(String, u32)]) -> Result<(), String> {
            Ok(())
        }
        fn steering_changed(&mut self, _: &[(String, u32)]) -> Result<(), String> {
            Ok(())
        }
    }

    let fake = Fake::start("spawn-clears");
    let failing = Arc::new(AtomicBool::new(true));
    let engine = ConvergenceEngine::new(
        &fake.path,
        Vec::new(),
        vec!["eth4".into()],
        1_000,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    );
    let rt = Runtime::new(
        engine,
        Box::new(Mirror { routes: vec![] }),
        Box::new(SteeringUnavailable),
        Box::new(Flaky(Arc::clone(&failing))),
        Box::new(packetframe_vpp_offload::runtime::NoResources),
        // `spawn(binary, conf)` execs `binary -c conf`; /bin/true exits
        // immediately regardless, which is all this needs.
        "/bin/true",
        "/dev/null",
    );

    // First spawn: the child starts, the record fails, and persist-or-kill
    // abandons it — with the failure recorded.
    let (_, mut fx) = rt.views();
    assert!(fx.spawn().is_err(), "persist-or-kill must refuse");
    assert!(
        rt.status().store_error.is_some(),
        "the failed persist must be surfaced"
    );

    // The store recovers, and the retry spawn persists. That success makes
    // the whole record durable again, so the degradation must end with it.
    failing.store(false, Ordering::SeqCst);
    fx.spawn().expect("the retry spawn records cleanly");
    assert!(
        rt.status().store_error.is_none(),
        "a successful spawn persist left the earlier failure reported: {:?}",
        rt.status().store_error
    );
}

/// A route learned **after** convergence reaches VPP.
///
/// The regression this exists for is a silent one. `drain_batch` used to
/// be called only while a resync was in flight, so once the module
/// settled into `Ready` — where it spends its life — nothing pulled the
/// source again. VPP would forward a frozen table, report healthy, and
/// pass readback verification, because verification samples the very
/// mirror it was synced against. Nothing would have said a word.
///
/// So the assertion is deliberately about the wire, not about counters:
/// the fake must actually receive the prefix.
///
/// The port is named after a real local interface, because the feed
/// resolves a neighbour's egress device through `if_indextoname` and the
/// engine matches that name against the configured ports. Inventing
/// "eth4" here would make every route unresolvable for a reason that has
/// nothing to do with what is under test.
#[test]
fn a_route_learned_after_convergence_still_reaches_vpp() {
    use packetframe_common::fib::ResolvedRouteSink as _;
    use packetframe_vpp_offload::driver::Observe as _;
    use packetframe_vpp_offload::feed::RouteFeed;
    use std::sync::Arc;

    let (ifindex, dev) = local_interface();
    let fake = Fake::start("late-route");
    let feed = Arc::new(RouteFeed::new());
    feed.neighbour_resolved(fake_vpp::nh(), MAC, ifindex);
    feed.route_resolved(fake_vpp::v4(0, 1), &[fake_vpp::nh()]);

    let engine = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: dev.clone(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        }],
        vec![dev],
        1_000_000,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    );
    let rt = Runtime::new(
        engine,
        Box::new(feed.clone()),
        Box::new(SteeringUnavailable),
        Box::new(NullStore),
        Box::new(NoResources),
        "/usr/bin/vpp",
        "/tmp/startup.conf",
    );

    let mut d = Driver::new();
    let t0 = Instant::now();
    {
        let (mut obs, _) = rt.views();
        assert!(obs.api_ready(), "the fake must answer the handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(t0, Event::Adopted { steered: false }, &mut fx);
    }
    let (mut now, _) = run_until(&mut d, &rt, t0, |d| d.state() == State::Ready);
    assert_eq!(
        rt.status().counts.installed,
        1,
        "the seeded route converged before the part under test"
    );
    let _ = fake.drain_events();

    // THE POINT: a new route arrives with the module already settled.
    let late_addr = [10u8, 0, 200, 0];
    feed.route_resolved(fake_vpp::v4(0, 200), &[fake_vpp::nh()]);

    // Hand-rolled rather than `run_until`, because the stop condition has
    // to accumulate the fake's events: `drain_events` empties the channel,
    // so a closure that polled it would throw away the very sighting it
    // was waiting for.
    let mut saw_late = false;
    let mut events = Vec::new();
    for _ in 0..64 {
        let t = {
            let (mut obs, mut fx) = rt.views();
            d.tick(now, &mut obs, &mut fx)
        };
        events.extend(t.events.clone());
        // Same seam the real loop uses; without it a completed verify
        // never lands and the module eventually reports a wedge, which
        // would bury this test's actual finding under restart noise.
        for e in rt.take_pending() {
            let (_, mut fx) = rt.views();
            events.extend(d.inject(now, e, &mut fx).events);
        }
        for e in fake.drain_events() {
            if let fake_vpp::Event::Route(r) = e {
                if r.addr == late_addr && r.is_add {
                    saw_late = true;
                }
            }
        }
        if saw_late {
            break;
        }
        now += t
            .sleep
            .unwrap_or(Duration::from_millis(100))
            .max(Duration::from_millis(1));
    }

    assert!(
        saw_late,
        "a route learned after convergence never reached VPP; events: {events:?}"
    );
    assert_eq!(
        d.state(),
        State::Ready,
        "and the module stayed Ready — a live delta is ordinary work, \
         not a reason to resync, unsteer, or re-verify"
    );
}

/// A real (ifindex, name) pair from this host.
///
/// Scanned rather than hard-coded: `lo` on Linux is `lo0` on macOS, and
/// this test runs on both.
fn local_interface() -> (u32, String) {
    for idx in 1..=16u32 {
        let mut buf = [0u8; 16];
        // SAFETY: `buf` is IF_NAMESIZE bytes, as the call requires.
        let rc = unsafe { libc::if_indextoname(idx, buf.as_mut_ptr() as *mut libc::c_char) };
        if rc.is_null() {
            continue;
        }
        let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
        if let Ok(name) = std::str::from_utf8(&buf[..end]) {
            return (idx, name.to_string());
        }
    }
    panic!("no usable interface at index 1..16");
}

/// A nexthop first seen **after** convergence gets its static neighbour
/// programmed, not just its device mapping.
///
/// This is #115's worst finding arriving through a different door. Giving
/// the nexthop a device is enough for `NexthopMap::resolve` to return
/// `Some`, so routes through it classify as resolvable and install — and
/// VPP, which runs without linux-cp and can never ARP for the adjacency,
/// has nothing to send them to. Readback verification does not catch it
/// either: it checks a route exists on an interface we own, deliberately
/// not that its adjacency resolves. Route acks, verify passes, every
/// packet drops.
#[test]
fn a_nexthop_first_seen_after_convergence_gets_its_adjacency() {
    use packetframe_common::fib::ResolvedRouteSink as _;
    use packetframe_vpp_offload::driver::Observe as _;
    use packetframe_vpp_offload::feed::RouteFeed;
    use std::sync::Arc;

    let (ifindex, dev) = local_interface();
    let fake = Fake::start("late-nexthop");
    let feed = Arc::new(RouteFeed::new());
    feed.neighbour_resolved(fake_vpp::nh(), MAC, ifindex);
    feed.route_resolved(fake_vpp::v4(0, 1), &[fake_vpp::nh()]);

    let engine = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: dev.clone(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        }],
        vec![dev],
        1_000_000,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    );
    let rt = Runtime::new(
        engine,
        Box::new(feed.clone()),
        Box::new(SteeringUnavailable),
        Box::new(NullStore),
        Box::new(NoResources),
        "/usr/bin/vpp",
        "/tmp/startup.conf",
    );

    let mut d = Driver::new();
    let t0 = Instant::now();
    {
        let (mut obs, _) = rt.views();
        assert!(obs.api_ready(), "the fake must answer the handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(t0, Event::Adopted { steered: false }, &mut fx);
    }
    let (mut now, _) = run_until(&mut d, &rt, t0, |d| d.state() == State::Ready);
    let _ = fake.drain_events();

    // A nexthop the engine has never seen, arriving with a route through
    // it — the order the feed delivers them in is what the fix depends on.
    let late_nh = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 9));
    let late_mac = [0x02, 0x00, 0x5e, 0x00, 0x00, 0x09];
    feed.neighbour_resolved(late_nh, late_mac, ifindex);
    feed.route_resolved(fake_vpp::v4(0, 201), &[late_nh]);

    let mut saw_neigh = false;
    for _ in 0..64 {
        let t = {
            let (mut obs, mut fx) = rt.views();
            d.tick(now, &mut obs, &mut fx)
        };
        for e in rt.take_pending() {
            let (_, mut fx) = rt.views();
            d.inject(now, e, &mut fx);
        }
        for e in fake.drain_events() {
            if let fake_vpp::Event::Neighbour { mac, .. } = e {
                if mac == late_mac {
                    saw_neigh = true;
                }
            }
        }
        if saw_neigh {
            break;
        }
        now += t
            .sleep
            .unwrap_or(Duration::from_millis(100))
            .max(Duration::from_millis(1));
    }

    assert!(
        saw_neigh,
        "the new nexthop's static neighbour was never programmed — its routes \
         would install, verify clean, and blackhole"
    );
}

/// Drill (d) on the shadow (2026-08-07), pinned end to end.
///
/// A daemon restart adopted a steered VPP forwarding a verified table,
/// and the adopted resync ran ~6 s later — against a route source whose
/// BGP feed had just reconnected and held almost nothing. The diff read
/// "the source is authoritative" literally and queued ~1M withdrawals
/// against the live dataplane; the drain began emptying the forwarding
/// table (5.43 s of measured loss), convergence failed, and the teardown
/// killed the very VPP preserve-on-restart exists to keep.
///
/// The fix under test: the adopted diff is DEFERRED while the source
/// holds less than the floor (`adopted / ADOPTED_SOURCE_FLOOR_DIVISOR`).
/// While deferred, nothing touches VPP — no withdrawals, no upserts, no
/// phase timeout however long bird takes — and the deferral is visible
/// on the status surface. When the source crosses the floor, the diff
/// runs and withdraws exactly what is genuinely gone.
#[test]
fn an_adopted_resync_waits_for_the_source_instead_of_withdrawing_the_table() {
    use std::sync::{Arc, Mutex};

    /// A mirror the test can fill while the runtime holds it — the
    /// route feed mid-reload, as a fixture.
    struct SharedMirror(Arc<Mutex<Vec<IpPrefix>>>);
    impl RouteSource for SharedMirror {
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            for p in self.0.lock().unwrap().iter() {
                visit(*p, &[fake_vpp::nh()]);
            }
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(fake_vpp::nh(), "eth4", MAC);
        }
    }

    // The surviving VPP forwards six routes that look self-installed.
    const EXISTING: &[([u8; 4], u8, u32, bool)] = &[
        ([10, 0, 0, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 1, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 2, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 3, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 4, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 5, 0], 24, ASSIGNED_INDEX, true),
    ];
    let fake = Fake::start_behaving(
        "loop-defer",
        fake_vpp::Behaviour {
            existing_routes: EXISTING,
            ..Default::default()
        },
    );
    // The feed has delivered one route of an eventual five: well below
    // the floor of 6/2 = 3.
    let shared = Arc::new(Mutex::new(vec![fake_vpp::v4(0, 0)]));
    let rt = runtime_with_source(&fake, Box::new(SharedMirror(shared.clone())));
    let mut d = Driver::new();
    let t0 = Instant::now();

    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready(), "the fake must answer the handshake");
    }
    {
        let (_, mut fx) = rt.views();
        // Steered — the case whose blackhole this exists to prevent.
        d.inject(t0, Event::Adopted { steered: true }, &mut fx);
    }
    assert_eq!(d.state(), State::AdoptedResyncing);
    rt.set_steered(true);

    // Hold below the floor for far longer than CONVERGENCE_BUDGET,
    // pacing the clock by each tick's own permitted sleep — jumping it
    // in big steps would outrun the ping cadence and fabricate a wedge
    // the way no wall clock ever does. Nothing may time out and nothing
    // may reach VPP's FIB.
    let mut now = t0;
    let mut held = Vec::new();
    let past_budget = t0 + Duration::from_secs(150);
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..2_000 {
            if now >= past_budget {
                break;
            }
            let t = d.tick(now, &mut obs, &mut fx);
            held.extend(t.events.clone());
            assert!(
                !t.events.contains(&Event::PhaseTimedOut),
                "the convergence budget must time the diff, not bird's reload: {:?}",
                t.events
            );
            assert!(
                !t.events.contains(&Event::SyncComplete),
                "a deferred resync must not report complete: {:?}",
                t.events
            );
            for e in rt.take_pending() {
                held.extend(d.inject(now, e, &mut fx).events);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }
    assert!(
        now >= past_budget,
        "the loop must actually outlast CONVERGENCE_BUDGET for this to prove anything"
    );
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "still converging, still steered, still untouched; saw {held:?}"
    );
    let touched: Vec<_> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            fake_vpp::Event::Route(r) => Some(r),
            _ => None,
        })
        .collect();
    assert!(
        touched.is_empty(),
        "no route op may reach a live table while the source loads: {touched:?}"
    );
    assert_eq!(
        rt.status().resync_deferred,
        Some((1, 3)),
        "the deferral must be visible, not silent"
    );

    // The feed finishes: five routes survive, 10.0.5.0/24 was withdrawn
    // while packetframe was down.
    *shared.lock().unwrap() = (0..5).map(|i| fake_vpp::v4(0, i)).collect();

    let mut seen: Vec<Event> = Vec::new();
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..64 {
            now += Duration::from_millis(100);
            let t = d.tick(now, &mut obs, &mut fx);
            seen.extend(t.events.clone());
            if seen.contains(&Event::SyncComplete) {
                break;
            }
        }
    }
    assert!(
        seen.contains(&Event::SyncComplete),
        "once the source crosses the floor the resync must actually run: {seen:?}"
    );
    assert!(
        rt.status().resync_deferred.is_none(),
        "the deferral must clear when the diff runs"
    );

    // And the diff withdrew exactly the route that is genuinely gone —
    // not the table.
    let deletes: Vec<_> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            fake_vpp::Event::Route(r) if !r.is_add => Some((r.addr, r.len)),
            _ => None,
        })
        .collect();
    assert_eq!(
        deletes,
        vec![([10, 0, 5, 0], 24)],
        "one withdrawal for the one prefix the source really dropped"
    );
}
