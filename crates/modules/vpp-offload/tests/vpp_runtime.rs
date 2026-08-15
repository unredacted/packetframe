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

use fake_vpp::{Behaviour, Fake, ASSIGNED_INDEX, MAC};
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
    fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
        unreachable!("this source hands nothing over, so nothing can come back")
    }
    fn route_count(&self) -> u64 {
        let mut n = 0u64;
        self.for_each_route(&mut |_, _| n += 1);
        n
    }
    fn change_seq(&self) -> u64 {
        self.route_count()
    }

    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        for p in &self.routes {
            visit(*p, &[fake_vpp::nh()]);
        }
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(fake_vpp::nh(), "eth4", MAC);
    }
}

fn runtime_custom(
    fake: &Fake,
    source: Box<dyn RouteSource>,
    steering: Box<dyn packetframe_vpp_offload::runtime::Steering>,
    capacity: u64,
) -> Runtime {
    let engine = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            accept_macs: vec![],
            vlans: vec![],
        }],
        vec!["eth4".into()],
        capacity,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    );
    Runtime::new(
        engine,
        source,
        steering,
        Box::new(NullStore),
        Box::new(NoResources),
        "/usr/bin/vpp",
        "/tmp/startup.conf",
    )
}

fn runtime_with_source(fake: &Fake, source: Box<dyn RouteSource>) -> Runtime {
    runtime_custom(fake, source, Box::new(SteeringUnavailable), 1_000_000)
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
    // An adoption that found an EMPTY FIB has no withdrawal universe to
    // protect, so the source-quiescence gate must not engage — a floor
    // of zero would reduce it to a bare wait that defers an empty
    // dataplane behind a loading feed (review finding on the
    // quiescence PR).
    assert!(
        rt.status().resync_deferred.is_none(),
        "adopting nothing must start the resync immediately"
    );

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
            accept_macs: vec![],
            vlans: vec![],
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
            accept_macs: vec![],
            vlans: vec![],
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

/// A refused neighbour must not cost the batch its route deltas — proved
/// through the production seam, real `RouteFeed` included.
///
/// `RouteFeed::drain_changes` is destructive: it drains `neigh_pending`
/// and removes each route key from `pending`. So a neighbour send that
/// failed mid-batch returned before the route loop and those deltas were
/// gone from both tiers at once — out of the feed's pending map, never
/// into the engine's, retried by nothing. On a STEERED offload that is a
/// stale FIB with no signal: the withdrawn prefix keeps being forwarded
/// and the changed nexthop keeps resolving to its old adjacency, while
/// `installed`/`installing`/`withheld`/`unresolvable` all stay clean and
/// verify cannot see it (it samples prefixes the LEDGER believes
/// installed, and the ledger never learned these existed). Only a full
/// resync recovered.
///
/// Asserted on the wire and on the health surface: the deltas land on the
/// retry, and while they are owed the backlog says so rather than
/// reporting a converged table.
#[test]
fn a_refused_neighbour_does_not_cost_the_batch_its_routes() {
    use packetframe_common::fib::ResolvedRouteSink as _;
    use packetframe_vpp_offload::driver::Observe as _;
    use packetframe_vpp_offload::feed::RouteFeed;
    use std::sync::Arc;

    // VPP already holds the base nexthop, so the one refusal below lands
    // on the delta's adjacency rather than being spent during the resync.
    const EXISTING: &[([u8; 4], u32, [u8; 6], u8)] = &[([192, 0, 2, 1], ASSIGNED_INDEX, MAC, 1)];

    let (ifindex, dev) = local_interface();
    let fake = Fake::start_behaving(
        "refused-neigh-loop",
        Behaviour {
            reject_neighbour_adds: 1,
            existing_neighbours: EXISTING,
            ..Default::default()
        },
    );
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
            accept_macs: vec![],
            vlans: vec![],
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
    assert_eq!(rt.status().counts.installed, 1, "the base table converged");
    let _ = fake.drain_events();

    // One batch: a nexthop VPP will refuse, the withdrawal of the live
    // prefix, and a route through the new nexthop.
    let late_nh = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 23));
    let late_mac = [0x02, 0x00, 0x5e, 0x00, 0x00, 0x17];
    feed.neighbour_resolved(late_nh, late_mac, ifindex);
    feed.route_withdrawn(fake_vpp::v4(0, 1));
    feed.route_resolved(fake_vpp::v4(0, 202), &[late_nh]);

    let mut refusal_seen = false;
    let mut owed_while_refused = 0;
    let mut saw_withdraw = false;
    let mut saw_late_add = false;
    for _ in 0..64 {
        let t = {
            let (mut obs, mut fx) = rt.views();
            d.tick(now, &mut obs, &mut fx)
        };
        for e in rt.take_pending() {
            let (_, mut fx) = rt.views();
            d.inject(now, e, &mut fx);
        }
        let status = rt.status();
        if let Some(why) = &status.drain_error {
            assert!(
                why.contains("refused the static neighbour for 192.0.2.23"),
                "the refusal must be reported as itself: {why}"
            );
            refusal_seen = true;
            owed_while_refused = owed_while_refused.max(status.source_backlog);
        }
        for e in fake.drain_events() {
            if let fake_vpp::Event::Route(r) = e {
                if r.addr == [10, 0, 1, 0] && !r.is_add {
                    saw_withdraw = true;
                }
                if r.addr == [10, 0, 202, 0] && r.is_add {
                    saw_late_add = true;
                }
            }
        }
        if saw_withdraw && saw_late_add {
            break;
        }
        now += t
            .sleep
            .unwrap_or(Duration::from_millis(100))
            .max(Duration::from_millis(1));
    }

    assert!(refusal_seen, "the test never reached the refusal it models");
    assert!(
        owed_while_refused >= 2,
        "the undelivered routes must be visible as owed while the send is \
         failing, not silently absent: backlog peaked at {owed_while_refused}"
    );
    assert!(
        saw_withdraw,
        "the withdrawal the refused batch carried never reached VPP — a \
         steered offload would still be forwarding that prefix"
    );
    assert!(
        saw_late_add,
        "nor did the route learned through the new nexthop"
    );
    assert_eq!(
        rt.status().source_backlog,
        0,
        "and nothing is left owed once the retry lands"
    );
    assert!(
        rt.status().drain_error.is_none(),
        "a recovered delta apply must stop being reported"
    );
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
            accept_macs: vec![],
            vlans: vec![],
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
        fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
            unreachable!("this source hands nothing over, so nothing can come back")
        }
        fn route_count(&self) -> u64 {
            let mut n = 0u64;
            self.for_each_route(&mut |_, _| n += 1);
            n
        }
        fn change_seq(&self) -> u64 {
            self.route_count()
        }

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

/// The floor is not the release condition — quiescence is. Pinned
/// against the second drill-(d) failure (shadow, 2026-08-08): the
/// floor-only gate released the diff at have=527,557 of an eventual
/// 1.05M, withdrew the not-yet-reloaded half from the live steered
/// VPP, and the drill flow measured 12.75 s of blackhole. A loading
/// feed passes through every count on its way to full, so a source
/// that keeps growing must keep deferring — however far past the
/// floor it is.
#[test]
fn a_source_still_growing_past_the_floor_keeps_deferring() {
    use std::sync::{Arc, Mutex};

    struct SharedMirror(Arc<Mutex<Vec<IpPrefix>>>);
    impl RouteSource for SharedMirror {
        fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
            unreachable!("this source hands nothing over, so nothing can come back")
        }
        fn route_count(&self) -> u64 {
            let mut n = 0u64;
            self.for_each_route(&mut |_, _| n += 1);
            n
        }
        fn change_seq(&self) -> u64 {
            self.route_count()
        }

        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            for p in self.0.lock().unwrap().iter() {
                visit(*p, &[fake_vpp::nh()]);
            }
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(fake_vpp::nh(), "eth4", MAC);
        }
    }

    /// A stranger prefix per index, disjoint from the adopted set.
    fn stranger(i: usize) -> IpPrefix {
        IpPrefix::V4 {
            addr: [10, 9, (i / 250) as u8, (i % 250) as u8],
            prefix_len: 32,
        }
    }

    const EXISTING: &[([u8; 4], u8, u32, bool)] = &[
        ([10, 0, 0, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 1, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 2, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 3, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 4, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 5, 0], 24, ASSIGNED_INDEX, true),
    ];
    let fake = Fake::start_behaving(
        "loop-grow",
        fake_vpp::Behaviour {
            existing_routes: EXISTING,
            ..Default::default()
        },
    );
    let shared = Arc::new(Mutex::new(vec![fake_vpp::v4(0, 0)]));
    let rt = runtime_with_source(&fake, Box::new(SharedMirror(shared.clone())));
    let mut d = Driver::new();
    let t0 = Instant::now();

    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready(), "handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(t0, Event::Adopted { steered: true }, &mut fx);
    }
    rt.set_steered(true);

    // The feed loads in big strides: every tick adds 200 routes — far
    // past the floor of 3 within two ticks, and far above the quiet
    // threshold every single tick. The mid-load reality, as a fixture.
    let mut now = t0;
    let mut n_strangers = 0usize;
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..12 {
            {
                let mut g = shared.lock().unwrap();
                for i in n_strangers..n_strangers + 200 {
                    g.push(stranger(i));
                }
            }
            n_strangers += 200;
            let t = d.tick(now, &mut obs, &mut fx);
            assert!(
                !t.events.contains(&Event::SyncComplete),
                "a growing source must keep the diff deferred, however far past the \
                 floor: {:?}",
                t.events
            );
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }
    assert_eq!(d.state(), State::AdoptedResyncing);
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
        "no route op may reach the live table while the feed grows: {touched:?}"
    );

    // The reload finishes: the last stride lands the surviving five of
    // the six adopted prefixes, then the feed goes quiet.
    {
        let mut g = shared.lock().unwrap();
        for i in 0..5u8 {
            g.push(fake_vpp::v4(0, i));
        }
    }
    let mut seen: Vec<Event> = Vec::new();
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..128 {
            let t = d.tick(now, &mut obs, &mut fx);
            seen.extend(t.events.clone());
            if seen.contains(&Event::SyncComplete) {
                break;
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }
    assert!(
        seen.contains(&Event::SyncComplete),
        "a quiet, loaded source must release the diff: {seen:?}"
    );

    // And the withdrawal set is exactly the one genuinely-gone prefix,
    // not the half of the table that happened to load late.
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

/// Quiescence is a rate over elapsed time, never a per-check delta —
/// pinned at production's check cadence.
///
/// The service loop caps its sleeps at 50 ms for stop-responsiveness,
/// so `drain_batch` can be checked twenty times a second. At that
/// cadence an 18k routes/s reload adds only ~900 per check — under any
/// plausible per-check threshold — so a per-check gate calls a
/// full-speed reload "quiet" and releases the diff ~150 ms into it
/// (review finding on this PR). This drives the gate at exactly that
/// cadence with per-check growth small and the RATE unmistakably a
/// reload, and insists the diff stays shut.
#[test]
fn quiescence_is_a_rate_not_a_per_check_delta() {
    use std::sync::{Arc, Mutex};

    struct SharedMirror(Arc<Mutex<Vec<IpPrefix>>>);
    impl RouteSource for SharedMirror {
        fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
            unreachable!("this source hands nothing over, so nothing can come back")
        }
        fn route_count(&self) -> u64 {
            let mut n = 0u64;
            self.for_each_route(&mut |_, _| n += 1);
            n
        }
        fn change_seq(&self) -> u64 {
            self.route_count()
        }

        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            for p in self.0.lock().unwrap().iter() {
                visit(*p, &[fake_vpp::nh()]);
            }
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(fake_vpp::nh(), "eth4", MAC);
        }
    }
    fn stranger(i: usize) -> IpPrefix {
        IpPrefix::V4 {
            addr: [10, 8, (i / 250) as u8, (i % 250) as u8],
            prefix_len: 32,
        }
    }

    const EXISTING: &[([u8; 4], u8, u32, bool)] = &[
        ([10, 0, 0, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 1, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 2, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 3, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 4, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 5, 0], 24, ASSIGNED_INDEX, true),
    ];
    let fake = Fake::start_behaving(
        "loop-cadence",
        fake_vpp::Behaviour {
            existing_routes: EXISTING,
            ..Default::default()
        },
    );
    let shared = Arc::new(Mutex::new(vec![fake_vpp::v4(0, 0)]));
    let rt = runtime_with_source(&fake, Box::new(SharedMirror(shared.clone())));
    let mut d = Driver::new();
    let t0 = Instant::now();

    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready(), "handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(t0, Event::Adopted { steered: true }, &mut fx);
    }
    rt.set_steered(true);

    // 30 routes per 50 ms check: tiny per check, 600/s as a rate —
    // ten times the quiet threshold. The clock advances by the 50 ms
    // production cap regardless of the tick's requested sleep, which
    // is exactly what the service loop does.
    let mut now = t0;
    let mut n = 0usize;
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..80 {
            {
                let mut g = shared.lock().unwrap();
                for i in n..n + 30 {
                    g.push(stranger(i));
                }
            }
            n += 30;
            now += Duration::from_millis(50);
            let t = d.tick(now, &mut obs, &mut fx);
            assert!(
                !t.events.contains(&Event::SyncComplete),
                "a reload checked often enough to look small per-check must still \
                 read as loading: {:?}",
                t.events
            );
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
        }
    }
    assert_eq!(d.state(), State::AdoptedResyncing);
    assert!(
        fake.drain_events()
            .into_iter()
            .all(|e| !matches!(e, fake_vpp::Event::Route(_))),
        "no route op may reach the live table during the reload"
    );

    // The reload ends; the source completes and goes quiet. Release
    // needs SOURCE_QUIET_FOR of sustained quiet, then the diff runs.
    {
        let mut g = shared.lock().unwrap();
        for i in 0..5u8 {
            g.push(fake_vpp::v4(0, i));
        }
    }
    let mut seen: Vec<Event> = Vec::new();
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..128 {
            now += Duration::from_millis(50);
            let t = d.tick(now, &mut obs, &mut fx);
            seen.extend(t.events.clone());
            if seen.contains(&Event::SyncComplete) {
                break;
            }
        }
    }
    assert!(
        seen.contains(&Event::SyncComplete),
        "a quiet, loaded source must release the diff: {seen:?}"
    );
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

/// A dead source never releases a populated adoption — at any scale.
///
/// `adopted = 1` floors to zero under integer division, and a floor of
/// zero is satisfied by an EMPTY source: dead feed, perfectly quiet,
/// gate opens, diff withdraws the one route the VPP is forwarding with
/// (review finding). The floor is clamped to 1 for any populated
/// adoption; this holds a one-route survivor against an empty source
/// far past the quiet window and insists nothing moves.
#[test]
fn a_dead_source_never_releases_a_populated_adoption() {
    const ONE: &[([u8; 4], u8, u32, bool)] = &[([10, 0, 0, 0], 24, ASSIGNED_INDEX, true)];
    let fake = Fake::start_behaving(
        "loop-dead-feed",
        fake_vpp::Behaviour {
            existing_routes: ONE,
            ..Default::default()
        },
    );
    // The feed never delivers anything: the daemon restarted and its
    // route source is dead.
    let rt = runtime_with_source(&fake, Box::new(Mirror { routes: Vec::new() }));
    let mut d = Driver::new();
    let t0 = Instant::now();

    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready(), "handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(t0, Event::Adopted { steered: true }, &mut fx);
    }
    rt.set_steered(true);

    // Far past SOURCE_QUIET_FOR: a dead feed is perfectly quiet, so
    // only the floor stands between it and the diff.
    let mut now = t0;
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..200 {
            now += Duration::from_millis(100);
            let t = d.tick(now, &mut obs, &mut fx);
            assert!(
                !t.events.contains(&Event::SyncComplete),
                "a dead source must never satisfy the gate: {:?}",
                t.events
            );
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
        }
    }
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "still holding, still steered"
    );
    assert!(
        fake.drain_events()
            .into_iter()
            .all(|e| !matches!(e, fake_vpp::Event::Route(_))),
        "the sole live route must not be withdrawn"
    );
}

/// Quiescence is measured on the change counter, not on net table size.
///
/// A source churning in place — every add balanced by a withdrawal —
/// has zero net growth and is anything but quiet; releasing the diff
/// into that turbulence withdraws whatever the churn has not yet
/// restored (review finding). This holds a source whose SIZE never
/// moves while its change counter runs hot, far past the quiet window,
/// and insists the diff stays shut; when the churn stops, it releases.
#[test]
fn balanced_churn_is_not_quiescence() {
    use std::sync::{Arc, Mutex};

    /// Fixed-size route set with an explicit activity counter.
    struct ChurningMirror {
        routes: Vec<IpPrefix>,
        seq: Arc<Mutex<u64>>,
    }
    impl RouteSource for ChurningMirror {
        fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
            unreachable!("this source hands nothing over, so nothing can come back")
        }
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            for p in &self.routes {
                visit(*p, &[fake_vpp::nh()]);
            }
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(fake_vpp::nh(), "eth4", MAC);
        }
        fn route_count(&self) -> u64 {
            self.routes.len() as u64
        }
        fn change_seq(&self) -> u64 {
            *self.seq.lock().unwrap()
        }
    }

    const EXISTING: &[([u8; 4], u8, u32, bool)] = &[
        ([10, 0, 0, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 1, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 2, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 3, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 4, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 5, 0], 24, ASSIGNED_INDEX, true),
    ];
    let fake = Fake::start_behaving(
        "loop-churn",
        fake_vpp::Behaviour {
            existing_routes: EXISTING,
            ..Default::default()
        },
    );
    let seq = Arc::new(Mutex::new(0u64));
    // Above the floor from the first check: five of the six adopted
    // prefixes. Only the churn keeps the gate shut.
    let rt = runtime_with_source(
        &fake,
        Box::new(ChurningMirror {
            routes: (0..5).map(|i| fake_vpp::v4(0, i)).collect(),
            seq: seq.clone(),
        }),
    );
    let mut d = Driver::new();
    let t0 = Instant::now();

    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready(), "handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(t0, Event::Adopted { steered: true }, &mut fx);
    }
    rt.set_steered(true);

    // 100 mutations per 100 ms check = 1000/s, fifteen times the quiet
    // threshold — with the table size frozen throughout.
    let mut now = t0;
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..60 {
            *seq.lock().unwrap() += 100;
            now += Duration::from_millis(100);
            let t = d.tick(now, &mut obs, &mut fx);
            assert!(
                !t.events.contains(&Event::SyncComplete),
                "balanced churn has zero net growth and must still read as \
                 loading: {:?}",
                t.events
            );
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
        }
    }
    assert_eq!(d.state(), State::AdoptedResyncing);
    assert!(
        fake.drain_events()
            .into_iter()
            .all(|e| !matches!(e, fake_vpp::Event::Route(_))),
        "no route op may reach the live table during churn"
    );

    // The churn stops; the gate releases and the diff withdraws exactly
    // the one genuinely-gone prefix.
    let mut seen: Vec<Event> = Vec::new();
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..128 {
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
        "a genuinely quiet source must release the diff: {seen:?}"
    );
    let deletes: Vec<_> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            fake_vpp::Event::Route(r) if !r.is_add => Some((r.addr, r.len)),
            _ => None,
        })
        .collect();
    assert_eq!(deletes, vec![([10, 0, 5, 0], 24)]);
}

/// Fixtures shared by the steered-adoption tests below.
mod steered {
    use super::*;
    use std::sync::{Arc, Mutex};

    pub struct SharedMirror(pub Arc<Mutex<Vec<IpPrefix>>>);
    impl RouteSource for SharedMirror {
        fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
            unreachable!("this source hands nothing over, so nothing can come back")
        }
        fn route_count(&self) -> u64 {
            let mut n = 0u64;
            self.for_each_route(&mut |_, _| n += 1);
            n
        }
        fn change_seq(&self) -> u64 {
            self.route_count()
        }
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            for p in self.0.lock().unwrap().iter() {
                visit(*p, &[fake_vpp::nh()]);
            }
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(fake_vpp::nh(), "eth4", MAC);
        }
    }

    /// A NIC that acknowledges both directions and remembers the order
    /// they happened in — the ordering IS the property under test.
    pub struct RecordingSteering {
        pub rules: Vec<(String, u32)>,
        pub log: Arc<Mutex<Vec<&'static str>>>,
    }
    impl packetframe_vpp_offload::runtime::Steering for RecordingSteering {
        fn missing_from_nic(
            &self,
        ) -> Result<packetframe_vpp_offload::runtime::SteeringAudit, String> {
            // No NIC behind this double, so nothing can be missing from one.
            Ok(packetframe_vpp_offload::runtime::SteeringAudit::clean())
        }
        fn configured_ports(&self) -> usize {
            1
        }
        fn steer(&mut self) -> Result<packetframe_vpp_offload::runtime::SteerOutcome, String> {
            self.log.lock().unwrap().push("steer");
            self.rules = vec![("eth4".into(), 1)];
            Ok(packetframe_vpp_offload::runtime::SteerOutcome::Steered)
        }
        fn unsteer(&mut self) -> Result<(), String> {
            self.log.lock().unwrap().push("unsteer");
            self.rules.clear();
            Ok(())
        }
        fn installed(&self) -> Vec<(String, u32)> {
            self.rules.clone()
        }
        fn retarget(
            &mut self,
            _targets: Vec<(String, u32, packetframe_vpp_offload::steer::RuleSet)>,
        ) {
        }
    }

    /// The surviving VPP forwards six routes.
    pub const EXISTING: &[([u8; 4], u8, u32, bool)] = &[
        ([10, 0, 0, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 1, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 2, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 3, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 4, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 5, 0], 24, ASSIGNED_INDEX, true),
    ];

    pub type Log = Arc<Mutex<Vec<&'static str>>>;
    pub type SharedRoutes = Arc<Mutex<Vec<IpPrefix>>>;
    pub type Session = Arc<packetframe_common::fib::FeedSession>;

    /// A steered adoption over a six-route VPP, mirror starting with
    /// `initial` routes, rules already in the NIC. The pre-dump floor
    /// is `capacity / 16` — and that the floor is capacity-derived and
    /// never 6/2 = 3 is itself evidence the adopted table has not been
    /// READ, which is the stall these tests forbid.
    pub fn fixture(
        name: &str,
        initial: &[IpPrefix],
        capacity: u64,
    ) -> (Fake, SharedRoutes, Log, Runtime, Session) {
        let fake = Fake::start_behaving(
            name,
            fake_vpp::Behaviour {
                existing_routes: EXISTING,
                ..Default::default()
            },
        );
        let shared: SharedRoutes = Arc::new(Mutex::new(initial.to_vec()));
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let rt = runtime_custom(
            &fake,
            Box::new(SharedMirror(shared.clone())),
            Box::new(RecordingSteering {
                rules: vec![("eth4".into(), 1)],
                log: log.clone(),
            }),
            capacity,
        );
        // Down until a test raises it, exactly like the real handle
        // before the listener's first Established.
        let session: Session = Arc::new(packetframe_common::fib::FeedSession::new());
        rt.feed_session(session.clone());
        (fake, shared, log, rt, session)
    }

    /// Adopt-steered, then confirm ticks below the release leave VPP
    /// exactly as found: no route op, no steering transition.
    pub fn adopt_and_hold(
        d: &mut Driver,
        rt: &Runtime,
        fake: &Fake,
        log: &Log,
        t0: Instant,
        ticks: usize,
    ) -> Instant {
        {
            let (mut obs, _) = rt.views();
            use packetframe_vpp_offload::driver::Observe as _;
            assert!(obs.api_ready(), "the fake must answer the handshake");
        }
        {
            let (_, mut fx) = rt.views();
            d.inject(t0, Event::Adopted { steered: true }, &mut fx);
        }
        assert_eq!(d.state(), State::AdoptedResyncing);
        rt.set_steered(true);

        let mut now = t0;
        let (mut obs, mut fx) = rt.views();
        for _ in 0..ticks {
            let t = d.tick(now, &mut obs, &mut fx);
            assert!(
                !t.events.contains(&Event::SyncComplete),
                "nothing may complete while the fallback is unproven: {:?}",
                t.events
            );
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
        assert!(
            log.lock().unwrap().is_empty(),
            "no steering transition below the release: {:?}",
            log.lock().unwrap()
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
            "no route op may reach a steered VPP before the unsteer: {touched:?}"
        );
        now
    }

    /// `run_until` with a caller-chosen bound, for stop conditions that
    /// legitimately need many paced ticks (long deferral holds).
    pub fn run_paced(
        d: &mut Driver,
        rt: &Runtime,
        mut now: Instant,
        max_ticks: usize,
        stop: impl Fn(&Driver) -> bool,
    ) -> (Instant, Vec<Event>) {
        let (mut obs, mut fx) = rt.views();
        let mut seen = Vec::new();
        for _ in 0..max_ticks {
            if stop(d) {
                return (now, seen);
            }
            let t = d.tick(now, &mut obs, &mut fx);
            seen.extend(t.events.clone());
            for e in rt.take_pending() {
                let it = d.inject(now, e, &mut fx);
                seen.extend(it.events);
            }
            rt.set_steered(d.supervisor().is_steered());
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
        panic!("loop did not reach the stop condition; events: {seen:?}");
    }

    /// The withdrawals the fake saw, sorted for a stable comparison.
    pub fn deletes(fake: &Fake) -> Vec<([u8; 4], u8)> {
        let mut v: Vec<_> = fake
            .drain_events()
            .into_iter()
            .filter_map(|e| match e {
                fake_vpp::Event::Route(r) if !r.is_add => Some((r.addr, r.len)),
                _ => None,
            })
            .collect();
        v.sort_unstable();
        v
    }
}

/// The drill-(d10) regression (shadow, 2026-08-09): a steered adoption
/// must not read VPP's FIB while traffic is on it. `ip_route_dump` is
/// not mp-safe, so VPP parks every worker in barrier sync for the whole
/// walk — ~5.4 s at the reference table, dropped at the NIC where no
/// counter sees it, and invariant across six drill runs because every
/// one of them ran the dump at attach. The sequence under test: nothing
/// touches VPP until the source is loaded and quiet; then the
/// supervisor unsteers FIRST; the dump runs against an idle VPP; and
/// steering returns only after the verified resync.
#[test]
fn a_steered_adoption_unsteers_before_reading_vpps_fib() {
    let (fake, shared, log, rt, session) =
        steered::fixture("steered-adopt", &[fake_vpp::v4(0, 0)], 160);
    session.set_up(true);
    let mut d = Driver::new();
    let now = steered::adopt_and_hold(&mut d, &rt, &fake, &log, Instant::now(), 40);
    assert_eq!(
        rt.status().resync_deferred,
        Some((1, 10)),
        "the floor must be capacity-derived (160/16), not adopted-derived (6/2) — \
         an adopted-derived floor means the FIB was read while steered"
    );

    // The feed finishes: twelve routes, two of VPP's six genuinely
    // withdrawn while packetframe was down.
    *shared.lock().unwrap() = (0..4)
        .map(|i| fake_vpp::v4(0, i))
        .chain((0..8).map(|i| fake_vpp::v4(1, i)))
        .collect();

    let (_, events) = steered::run_paced(&mut d, &rt, now, 512, |d| d.state() == State::Steered);

    // The order is the contract: traffic left VPP before its FIB was
    // read, and returned only through the verified path.
    assert_eq!(
        log.lock().unwrap().as_slice(),
        &["unsteer", "steer"],
        "unsteer must precede the dump and the re-steer must be the last transition"
    );
    assert!(
        events.contains(&Event::SyncComplete) && events.contains(&Event::VerifyPassed),
        "the reconciliation must actually run once unsteered: {events:?}"
    );
    assert!(
        rt.status().resync_deferred.is_none(),
        "the deferral must clear when the reconciliation runs"
    );
    // And the diff withdrew exactly the prefixes the source dropped —
    // proof the dump ran and seeded the withdrawal universe.
    assert_eq!(
        steered::deletes(&fake),
        vec![([10, 0, 4, 0], 24), ([10, 0, 5, 0], 24)],
        "two withdrawals for the two prefixes the source really dropped"
    );
}

/// The floor answers SIZE and nothing else, so meeting it must not
/// release alone (review finding): a small `expected-routes` shrinks
/// the floor beneath what neighbour-synthesized local routes supply
/// with the feed dead, and unsteering onto those is the blackhole
/// every round of this gate has been about. Liveness is the session
/// handle to answer, on the floor path too — and turning the session
/// on is exactly what lets the same state release.
#[test]
fn a_met_floor_without_a_live_session_stays_deferred() {
    // Capacity 160 -> floor 10; twelve routes meet it. The session is
    // down: this mirror is a husk, however comfortably it clears the
    // floor.
    let full: Vec<IpPrefix> = (0..4)
        .map(|i| fake_vpp::v4(0, i))
        .chain((0..8).map(|i| fake_vpp::v4(1, i)))
        .collect();
    let (fake, shared, log, rt, session) = steered::fixture("steered-floor-dead", &full, 160);
    let mut d = Driver::new();
    let now = steered::adopt_and_hold(&mut d, &rt, &fake, &log, Instant::now(), 400);
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "a met floor with a dead session must stay deferred"
    );
    let _ = shared;

    // The session comes up. The very same mirror is now evidence — but
    // not INSTANTLY: quiet accumulated while the feed was down attests
    // nothing, so the clock restarts at the up-transition (review
    // finding: without the reset, the first OPEN after an outage
    // released on stale quiet before a single route had arrived).
    session.set_up(true);
    let mut now = now;
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..4 {
            let _t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += Duration::from_millis(100);
        }
    }
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "the up-transition must restart the quiet clock, not release on stale quiet"
    );
    let (_, events) = steered::run_paced(&mut d, &rt, now, 512, |d| d.state() == State::Steered);
    assert_eq!(log.lock().unwrap().as_slice(), &["unsteer", "steer"]);
    assert!(events.contains(&Event::VerifyPassed), "{events:?}");
}

/// The narrowed contract: a below-floor table with no authority NEVER
/// releases — deliberately. The session is up, the mirror loaded and
/// quiet for minutes, and nothing honest can say a 100-route mirror is
/// complete when the operator declared sizing for 4096-route scale.
/// The remedy lives in the health text (size expected-routes within
/// 16x of the real table, or add bird); the small-table heuristic that
/// used to guess here was deleted after ten review rounds of corner
/// cases and a fleet-path wedge (#151/#152 retrospective).
#[test]
fn a_below_floor_table_without_an_authority_defers_forever() {
    // Capacity 4096 -> floor 256. The whole table is 100 routes,
    // session up, quiet far past every window that ever existed.
    let full: Vec<IpPrefix> = (0..4)
        .map(|i| fake_vpp::v4(0, i))
        .chain((0..96).map(|i| fake_vpp::v4(1, i)))
        .collect();
    let (fake, _shared, log, rt, session) = steered::fixture("steered-below-floor", &full, 4096);
    session.set_up(true);
    let mut d = Driver::new();
    let _ = steered::adopt_and_hold(&mut d, &rt, &fake, &log, Instant::now(), 2_000);
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "below the floor with no authority, the deferral is the designed terminal state"
    );
    assert_eq!(
        rt.status().resync_deferred,
        Some((100, 256)),
        "and it is visible, with the floor named"
    );
}

/// A dead source releases nothing, ever - and "dead" means the
/// SESSION is down, not any particular mirror size. Local-prefix ARP
/// scavenging can synthesize hundreds of routes with no bird behind
/// them (review finding: up to 1024 hosts), so the husk left after a
/// session death can dwarf any count threshold. With the session
/// handle down, no amount of quiet releases: unsteering onto a
/// fallback that lost its feed is the original disaster. Held deferred
/// with health degraded - stale-but-verified forwarding plus an alarm
/// beats an outage.
#[test]
fn a_dead_source_never_triggers_the_unsteer() {
    let (fake, shared, log, rt, session) = steered::fixture("steered-dead", &[], 4096);
    let mut d = Driver::new();
    // Far past every quiet window at <=250 ms a tick, empty.
    let mut now = steered::adopt_and_hold(&mut d, &rt, &fake, &log, Instant::now(), 2_000);
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "an empty, silent source must hold the adoption deferred forever"
    );

    // The session died and left a LARGE husk: two hundred synthesized
    // local routes that never came from bird. Quiet past every window,
    // session down, still no release.
    session.set_up(false);
    *shared.lock().unwrap() = (0..200).map(|i| fake_vpp::v4(3, i)).collect();
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..2_000 {
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "a session-less husk must not count as a loaded table, whatever its size"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "no steering transition on a dead source: {:?}",
        log.lock().unwrap()
    );
    assert_eq!(
        rt.status().resync_deferred,
        Some((200, 256)),
        "and the deferral must be visible, not silent"
    );
}

/// A configured authority that says Incomplete VETOES the proxies: a
/// met floor and a live, quiet session must not out-vote a verdict
/// that the mirror is missing more than the drift policy allows
/// (review finding: a load stalling two seconds past the floor would
/// otherwise unsteer onto a table the authority had condemned). The
/// same state releases the moment the authority agrees.
#[test]
fn an_incomplete_verdict_vetoes_every_proxy_release() {
    use packetframe_common::fib::{CompletenessReport, TableCompleteness};

    let full: Vec<IpPrefix> = (0..4)
        .map(|i| fake_vpp::v4(0, i))
        .chain((0..8).map(|i| fake_vpp::v4(1, i)))
        .collect();
    let (fake, _shared, log, rt, session) = steered::fixture("steered-veto", &full, 160);
    session.set_up(true);
    let handle = std::sync::Arc::new(TableCompleteness::new());
    rt.require_table_complete(handle.clone());
    // The authority knows the world is ~1000 routes; the mirror holds
    // twelve. Floor met, session live, quiet - and condemned.
    handle.publish(CompletenessReport {
        authority_routes: 1000,
        mirror_routes: 12,
        at: std::time::Instant::now(),
    });
    let mut d = Driver::new();
    let now = steered::adopt_and_hold(&mut d, &rt, &fake, &log, Instant::now(), 400);
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "an Incomplete verdict must hold every proxy release"
    );

    // The authority agrees: the ordinary release proceeds.
    handle.publish(CompletenessReport {
        authority_routes: 12,
        mirror_routes: 12,
        at: std::time::Instant::now(),
    });
    let (_, events) = steered::run_paced(&mut d, &rt, now, 512, |d| d.state() == State::Steered);
    assert_eq!(log.lock().unwrap().as_slice(), &["unsteer", "steer"]);
    assert!(events.contains(&Event::VerifyPassed), "{events:?}");
}

/// The veto-driven revocation: the authority turns Incomplete after
/// the unsteer landed. The restoration steer must BYPASS the
/// completeness gate - a plain steer refuses on exactly the verdict
/// that caused the revocation, which parked traffic forever on the
/// condemned fallback while the intact adoptee idled (review finding).
#[test]
fn a_condemning_verdict_cannot_block_its_own_revocations_restore() {
    use packetframe_common::fib::{CompletenessReport, TableCompleteness};

    let full: Vec<IpPrefix> = (0..4)
        .map(|i| fake_vpp::v4(0, i))
        .chain((0..8).map(|i| fake_vpp::v4(1, i)))
        .collect();
    let (fake, _shared, log, rt, session) = steered::fixture("steered-veto-restore", &full, 160);
    session.set_up(true);
    let handle = std::sync::Arc::new(TableCompleteness::new());
    rt.require_table_complete(handle.clone());
    handle.publish(CompletenessReport {
        authority_routes: 12,
        mirror_routes: 12,
        at: std::time::Instant::now(),
    });
    let mut d = Driver::new();
    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready(), "the fake must answer the handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(Instant::now(), Event::Adopted { steered: true }, &mut fx);
    }
    rt.set_steered(true);

    // Tick until the unsteer lands, then the authority condemns the
    // mirror before the dump tick.
    let mut now = Instant::now();
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..512 {
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            rt.set_steered(d.supervisor().is_steered());
            let unsteer_landed = log.lock().unwrap().as_slice() == ["unsteer"];
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
            if unsteer_landed {
                break;
            }
        }
    }
    assert_eq!(
        log.lock().unwrap().as_slice(),
        &["unsteer"],
        "window reached"
    );
    handle.publish(CompletenessReport {
        authority_routes: 1000,
        mirror_routes: 12,
        at: std::time::Instant::now(),
    });

    // The veto revokes; the restore must go through DESPITE the
    // verdict - that is the entire point of the ungated action.
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..512 {
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            rt.set_steered(d.supervisor().is_steered());
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
            if log.lock().unwrap().len() == 2 {
                break;
            }
        }
    }
    assert_eq!(
        log.lock().unwrap().as_slice(),
        &["unsteer", "steer"],
        "the condemning verdict must not block the restoration it caused"
    );
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "steered again, still waiting"
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
        "no dump, no diff under the veto: {touched:?}"
    );
}

/// A still-valid Converged report must not carry a mirror that has
/// SINCE shrunk past the drift policy through the floor release: the
/// authority's word is recomputed against the mirror as it is now, on
/// every path, not just the completeness release (review finding: the
/// veto trusted the cached verdict while only `complete` recomputed).
#[test]
fn a_stale_convergence_cannot_carry_a_shrunken_mirror() {
    use packetframe_common::fib::{CompletenessReport, TableCompleteness};

    let full: Vec<IpPrefix> = (0..4)
        .map(|i| fake_vpp::v4(0, i))
        .chain((0..8).map(|i| fake_vpp::v4(1, i)))
        .collect();
    let (fake, shared, log, rt, session) = steered::fixture("steered-shrunk", &full, 160);
    session.set_up(true);
    let handle = std::sync::Arc::new(TableCompleteness::new());
    rt.require_table_complete(handle.clone());
    // The authority saw twelve of twelve — and then the mirror lost
    // one route while the report stayed fresh and Converged. Eleven
    // still clears the floor of ten; the drift (1/12) does not clear
    // the 1% policy, and that must gate the FLOOR path too.
    handle.publish(CompletenessReport {
        authority_routes: 12,
        mirror_routes: 12,
        at: std::time::Instant::now(),
    });
    shared.lock().unwrap().pop();
    let mut d = Driver::new();
    let now = steered::adopt_and_hold(&mut d, &rt, &fake, &log, Instant::now(), 400);
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "a shrunken mirror under a stale Converged must not release"
    );

    // The route returns: the authority's recomputed word agrees again.
    shared.lock().unwrap().push(fake_vpp::v4(1, 7));
    let (_, events) = steered::run_paced(&mut d, &rt, now, 512, |d| d.state() == State::Steered);
    assert_eq!(log.lock().unwrap().as_slice(), &["unsteer", "steer"]);
    assert!(events.contains(&Event::VerifyPassed), "{events:?}");
}

/// A reconnect dump REANNOUNCES an unchanged table: the mirror never
/// moves, so a mutation counter reads quiet while the stream is at
/// full rate (review finding - the no-change early return in the
/// programmer swallows every unchanged route before the tee). The
/// session pulse counter is what keeps the gate loud: frames count,
/// changed or not.
#[test]
fn a_reannouncement_dump_holds_the_gate_loud() {
    let full: Vec<IpPrefix> = (0..4)
        .map(|i| fake_vpp::v4(0, i))
        .chain((0..8).map(|i| fake_vpp::v4(1, i)))
        .collect();
    let (_fake, _shared, log, rt, session) = steered::fixture("steered-reannounce", &full, 160);
    session.set_up(true);
    let mut d = Driver::new();
    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready(), "the fake must answer the handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(Instant::now(), Event::Adopted { steered: true }, &mut fx);
    }
    rt.set_steered(true);

    // Floor met (12 >= 10), session up, mirror frozen - and the stream
    // hammering: 200 pulses per tick stays far above the 64/s quiet
    // rate at any driver cadence. Nothing may release.
    let mut now = Instant::now();
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..100 {
            for _ in 0..200 {
                session.pulse();
            }
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "an actively streaming dump must hold the gate, mirror movement or not"
    );
    assert!(log.lock().unwrap().is_empty(), "{:?}", log.lock().unwrap());

    // The stream ends: quiet is real now, and the cycle proceeds.
    let (_, events) = steered::run_paced(&mut d, &rt, now, 512, |d| d.state() == State::Steered);
    assert_eq!(log.lock().unwrap().as_slice(), &["unsteer", "steer"]);
    assert!(events.contains(&Event::VerifyPassed), "{events:?}");
}

/// The revocation window: the gate released, the unsteer was
/// acknowledged - and the feed dropped before the dump ran. The
/// adopted FIB is still whole, so the traffic goes BACK onto it
/// (review finding: parking here left traffic on a fallback that a
/// BMP PeerDown was simultaneously emptying). When readiness returns,
/// the ordinary cycle resumes from the top.
#[test]
fn a_revoked_fallback_re_steers_the_intact_adopted_vpp() {
    let full: Vec<IpPrefix> = (0..4)
        .map(|i| fake_vpp::v4(0, i))
        .chain((0..8).map(|i| fake_vpp::v4(1, i)))
        .collect();
    let (fake, _shared, log, rt, session) = steered::fixture("steered-revoke", &full, 160);
    session.set_up(true);
    let mut d = Driver::new();
    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready(), "the fake must answer the handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(Instant::now(), Event::Adopted { steered: true }, &mut fx);
    }
    rt.set_steered(true);

    // Tick until the unsteer lands, then IMMEDIATELY drop the session
    // - the dump must not run on the next tick.
    let mut now = Instant::now();
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..512 {
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            rt.set_steered(d.supervisor().is_steered());
            let unsteer_landed = log.lock().unwrap().as_slice() == ["unsteer"];
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
            if unsteer_landed {
                break;
            }
        }
    }
    assert_eq!(
        log.lock().unwrap().as_slice(),
        &["unsteer"],
        "window reached"
    );
    session.set_up(false);

    // The revocation path: traffic back on the intact VPP, no dump —
    // and IMMEDIATELY: the safety restoration must not wait out the
    // preceding unsteer request's pace window (review finding: the
    // shared throttle held it ~5 s while PeerDown emptied the
    // fallback). Three ticks is transport, not throttle.
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..3 {
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            rt.set_steered(d.supervisor().is_steered());
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
            if log.lock().unwrap().len() == 2 {
                break;
            }
        }
    }
    assert_eq!(
        log.lock().unwrap().as_slice(),
        &["unsteer", "steer"],
        "revoked readiness must put traffic back on the adopted VPP"
    );
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "still waiting, steered again"
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
        "the dump and diff must not have run against the revoked window: {touched:?}"
    );

    // Readiness returns: the ordinary cycle completes from the top.
    session.set_up(true);
    let (_, events) = steered::run_paced(&mut d, &rt, now, 512, |d| d.state() == State::Steered);
    // Consecutive duplicates collapse before comparing: the paced
    // RestoreSteer re-ask fires again if the wait outlasts its pace
    // window, and re-asserting a complete set is an idempotent
    // reconcile by design — the ORDER of transitions is the contract,
    // not their repeat count.
    let mut transitions = log.lock().unwrap().clone();
    transitions.dedup();
    assert_eq!(
        transitions.as_slice(),
        &["unsteer", "steer", "unsteer", "steer"],
        "the resumed cycle repeats the full sequence"
    );
    assert!(events.contains(&Event::VerifyPassed), "{events:?}");
}

/// Where a bird exists, completeness is the exact readiness signal -
/// but a report is a snapshot, so it releases only alongside CURRENT
/// session liveness (review finding: a PeerDown wipe inside the
/// report's validity window must not ride a stale Converged onto an
/// empty fallback). With both in hand it releases a table the capacity
/// floor is wrong about without waiting out the hold time.
#[test]
fn completeness_releases_a_below_floor_table_promptly() {
    use packetframe_common::fib::{CompletenessReport, TableCompleteness};

    let (fake, shared, log, rt, session) = steered::fixture("steered-complete", &[], 160);
    let handle = std::sync::Arc::new(TableCompleteness::new());
    rt.require_table_complete(handle.clone());
    let mut d = Driver::new();
    let mut now = steered::adopt_and_hold(&mut d, &rt, &fake, &log, Instant::now(), 20);

    *shared.lock().unwrap() = (0..4).map(|i| fake_vpp::v4(0, i)).collect();
    handle.publish(CompletenessReport {
        authority_routes: 4,
        mirror_routes: 4,
        at: std::time::Instant::now(),
    });

    // A Converged report with the session DOWN is a snapshot of a
    // world that may have ended - it must not release by itself.
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..200 {
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "a cached Converged without current liveness must not release"
    );
    session.set_up(true);

    // The authority is the release for a below-floor table.
    let (_, events) = steered::run_paced(&mut d, &rt, now, 512, |d| d.state() == State::Steered);
    assert_eq!(log.lock().unwrap().as_slice(), &["unsteer", "steer"]);
    assert!(events.contains(&Event::VerifyPassed), "{events:?}");
}

/// A session flap demotes the attested door, and a report published
/// after the flap restores it.
///
/// The demotion is right — a report from before the reconnect cannot
/// attest that routes belong to the current stream — but it has to
/// expire, or an ordinary bird restart during a deferral is terminal:
/// a below-floor table has no other door, so it would never release at
/// all. Both halves are asserted, because a fix that simply stopped
/// demoting would pass a test that only checked the second.
#[test]
fn a_flap_demotes_attestation_only_until_a_newer_report_arrives() {
    use packetframe_common::fib::{CompletenessReport, TableCompleteness};

    let (fake, shared, log, rt, session) = steered::fixture("steered-reflap", &[], 160);
    let handle = std::sync::Arc::new(TableCompleteness::new());
    rt.require_table_complete(handle.clone());
    let mut d = Driver::new();
    let mut now = steered::adopt_and_hold(&mut d, &rt, &fake, &log, Instant::now(), 20);

    *shared.lock().unwrap() = (0..4).map(|i| fake_vpp::v4(0, i)).collect();
    // Raise, then let the deferral OBSERVE the raise: the epoch is
    // baselined at the first live observation, so flapping before any
    // tick would baseline onto the post-flap epoch and there would be
    // no flap to see. Nothing releases in this window — with no report
    // published the authority word is a veto.
    session.set_up(true);
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..40 {
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "no report yet — the authority vetoes, nothing has released"
    );

    // A report lands, and THEN the session bounces, so the report
    // predates the current stream and cannot attest it.
    handle.publish(CompletenessReport {
        authority_routes: 4,
        mirror_routes: 4,
        at: std::time::Instant::now(),
    });
    session.set_up(false);
    session.set_up(true);
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..400 {
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "a report older than the flap cannot attest the current stream"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "nothing may be unsteered on pre-flap evidence: {:?}",
        log.lock().unwrap()
    );

    // A NEWER REPORT IS NOT ENOUGH, and this is the half that matters:
    // the checker compares counts, and a mirror still carrying the
    // previous session's unseen routes keeps the count aligned, so a
    // positive post-flap report can sit over a half-current mirror.
    handle.publish(CompletenessReport {
        authority_routes: 4,
        mirror_routes: 4,
        at: std::time::Instant::now(),
    });
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..400 {
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }
    assert_eq!(
        d.state(),
        State::AdoptedResyncing,
        "a fresher report is a count comparison, not proof the mirror is \
         this session's — it must not restore attestation"
    );

    // The stale-route GC completing for this epoch is what does.
    session.mark_reconciled();
    let (_, events) = steered::run_paced(&mut d, &rt, now, 512, |d| d.state() == State::Steered);
    assert_eq!(
        log.lock().unwrap().as_slice(),
        &["unsteer", "steer"],
        "the current epoch's GC restores the attested release"
    );
    assert!(events.contains(&Event::VerifyPassed), "{events:?}");
}

/// The canary step refused by the completeness gate must steer itself
/// once the mirror catches up — no `packetframe reconfigure`, no
/// restart, no operator.
///
/// The whole loop, because the gap was in the seam between its layers
/// rather than in any one of them. `RuntimeEffects::steer` refuses on
/// the verdict, that becomes `SteerFailed`, and the supervisor settles
/// in `Ready` with `steer_wanted` set — read, before this, by only the
/// health text and the next `VerifyPassed`, which does not recur in
/// steady state. So every layer behaved correctly and the offload
/// stayed down until a human asked again (found reviewing #157).
#[test]
fn a_steer_refused_by_completeness_retries_when_the_mirror_catches_up() {
    use packetframe_common::fib::{CompletenessReport, TableCompleteness};

    let fake = Fake::start("steer-retry");
    let log: steered::Log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let rt = runtime_custom(
        &fake,
        Box::new(Mirror {
            routes: (0..5).map(|i| fake_vpp::v4(0, i)).collect(),
        }),
        // Nothing in the NIC yet: this is the staging state a canary
        // ladder starts from.
        Box::new(steered::RecordingSteering {
            rules: Vec::new(),
            log: log.clone(),
        }),
        1_000_000,
    );
    let handle = std::sync::Arc::new(TableCompleteness::new());
    rt.require_table_complete(handle.clone());
    // Converged at bring-up, so the fresh-resync hold releases and the
    // box reaches `Ready` the honest way (the hold is its own test;
    // this one is about the seam AT Ready).
    handle.publish(CompletenessReport {
        authority_routes: 5,
        mirror_routes: 5,
        at: std::time::Instant::now(),
    });

    let mut d = Driver::new();
    let t0 = Instant::now();
    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready(), "the fake must answer the handshake");
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(t0, Event::Adopted { steered: false }, &mut fx);
    }
    let (mut now, _) = run_until(&mut d, &rt, t0, |d| d.state() == State::Ready);

    // bird bounces and reloads: its count runs ahead of the mirror,
    // and the verdict turns incomplete under a box already at Ready.
    handle.publish(CompletenessReport {
        authority_routes: 1_000,
        mirror_routes: 5,
        at: std::time::Instant::now(),
    });

    // The operator turns the lever. The gate declines it.
    {
        let (_, mut fx) = rt.views();
        let t = d.inject(now, Event::SteerRequested, &mut fx);
        let refusal = t
            .outcome
            .failures
            .iter()
            .map(|(_, why)| why.clone())
            .collect::<Vec<_>>()
            .join("; ");
        assert!(
            refusal.contains("refusing to steer"),
            "the gate must be what declined it: {refusal:?}"
        );
    }
    assert_eq!(d.state(), State::Ready, "verified, not diverting");
    assert!(
        log.lock().unwrap().is_empty(),
        "the refusal is before the NIC: {:?}",
        log.lock().unwrap()
    );
    assert!(d.supervisor().steer_intended(), "but the want is recorded");

    // Minutes pass with the mirror still short. Nothing steers, and
    // nothing hammers the NIC either.
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..2_000 {
            let t = d.tick(now, &mut obs, &mut fx);
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }
    assert!(
        log.lock().unwrap().is_empty(),
        "an incomplete mirror must stay unsteered: {:?}",
        log.lock().unwrap()
    );
    assert_eq!(d.state(), State::Ready);

    // bird finishes its dump. Nothing else happens — no reconfigure,
    // no injected event, no restart.
    handle.publish(CompletenessReport {
        authority_routes: 5,
        mirror_routes: 5,
        at: std::time::Instant::now(),
    });
    // Bounded ticking rather than `run_until`, so a regression reads as
    // "it never steered" instead of "the loop did not settle".
    let mut events = Vec::new();
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..64 {
            let t = d.tick(now, &mut obs, &mut fx);
            events.extend(t.events.clone());
            for e in rt.take_pending() {
                events.extend(d.inject(now, e, &mut fx).events);
            }
            rt.set_steered(d.supervisor().is_steered());
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
    }

    assert_eq!(
        log.lock().unwrap().as_slice(),
        &["steer"],
        "the module knew it wanted to steer and the gate now permits it — nothing \
         should be waiting on an operator"
    );
    assert!(
        events.contains(&Event::SteerUnblocked),
        "and it must be the gate clearing that drove it: {events:?}"
    );
    assert_eq!(d.state(), State::Steered);
    assert!(d.supervisor().is_steered());
}

/// ...and it must not walk past the OTHER gate on the way.
///
/// `VerifyIncomplete` reaches `Ready` with the want intact and emits no
/// steer at all, deliberately: routes are withheld or unresolvable, and
/// diverting traffic into a FIB with known holes blackholes exactly the
/// prefixes that did not fit. The retry lives in `Ready` and reads the
/// want, so a version that consulted only the completeness verdict
/// would undo that arm on the next tick — the gate is on the route
/// ledger, not on bird.
/// Run for BOTH rollback outcomes, because the discriminator between
/// them was where this gate first went wrong. A steer rolls back
/// all-or-nothing, but the rollback itself can fail to delete — so a
/// FIRST steer can leave debris, and "some rules are in the NIC" then
/// stops meaning "this port was steering happily". Reading a non-empty
/// ledger as a reconcile therefore exempted exactly the case that most
/// needs the gate: the retry would install the REST of the allowlist
/// into a holey table and widen the blackhole the debris started
/// (review finding, PR #160).
#[test]
fn the_retry_does_not_steer_into_a_table_with_known_holes() {
    /// Refuses every steer and counts the asking. The count is the
    /// assertion: the gate must stop the retry BEFORE the NIC.
    /// `debris` is what the rollback could not delete.
    struct CountingRefusal {
        asked: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        debris: Vec<(String, u32)>,
    }
    impl packetframe_vpp_offload::runtime::Steering for CountingRefusal {
        fn missing_from_nic(
            &self,
        ) -> Result<packetframe_vpp_offload::runtime::SteeringAudit, String> {
            Ok(packetframe_vpp_offload::runtime::SteeringAudit::clean())
        }
        fn configured_ports(&self) -> usize {
            1
        }
        fn steer(&mut self) -> Result<packetframe_vpp_offload::runtime::SteerOutcome, String> {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err("the NIC would not take it".into())
        }
        fn unsteer(&mut self) -> Result<(), String> {
            Ok(())
        }
        fn installed(&self) -> Vec<(String, u32)> {
            // Empty until a steer has been attempted: debris is what a
            // rollback COULD NOT DELETE, so it cannot predate the
            // attempt. Reporting it from the start would make the
            // attach look like a steered adoption and defer the resync
            // instead.
            if self.asked.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                return Vec::new();
            }
            self.debris.clone()
        }
        fn retarget(
            &mut self,
            _targets: Vec<(String, u32, packetframe_vpp_offload::steer::RuleSet)>,
        ) {
        }
    }

    for (name, debris) in [
        ("steer-retry-holes-clean", Vec::new()),
        ("steer-retry-holes-debris", vec![("eth4".to_string(), 1u32)]),
    ] {
        let left_behind = !debris.is_empty();
        let fake = Fake::start(name);
        let asked = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        // Five routes into a two-route heap: three are withheld, which
        // is what makes the verify incomplete rather than failed.
        let rt = runtime_custom(
            &fake,
            Box::new(Mirror {
                routes: (0..5).map(|i| fake_vpp::v4(0, i)).collect(),
            }),
            Box::new(CountingRefusal {
                asked: std::sync::Arc::clone(&asked),
                debris,
            }),
            2,
        );
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
        let (mut now, events) = run_until(&mut d, &rt, t0, |d| d.state() == State::Ready);
        assert!(
            events.contains(&Event::VerifyIncomplete),
            "{name}: the table must not fit, or this test is about nothing: {events:?}"
        );
        assert!(rt.status().counts.withheld > 0, "{name}");

        // The operator turns the lever anyway and the NIC refuses,
        // leaving a want outstanding over an incomplete table.
        {
            let (_, mut fx) = rt.views();
            d.inject(now, Event::SteerRequested, &mut fx);
        }
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1, "{name}");
        assert_eq!(
            d.supervisor().is_steered(),
            left_behind,
            "{name}: the ledger is what says whether anything is diverted"
        );
        assert!(
            d.supervisor().steer_retry_pending(),
            "{name}: the want is outstanding — only the FIB gate may be holding it"
        );

        {
            let (mut obs, mut fx) = rt.views();
            for _ in 0..2_000 {
                let t = d.tick(now, &mut obs, &mut fx);
                for e in rt.take_pending() {
                    d.inject(now, e, &mut fx);
                }
                rt.set_steered(d.supervisor().is_steered());
                now += t
                    .sleep
                    .unwrap_or(Duration::from_millis(100))
                    .max(Duration::from_millis(1));
            }
        }
        assert_eq!(
            asked.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "{name}: the retry must not re-ask while routes are withheld — that is the \
             arm VerifyIncomplete exists to hold, and rules left by a failed rollback \
             are not a licence to add more"
        );
    }
}

/// The mirror image, and the reason both gates carry an exception
/// rather than being absolute: over the SAME holey table, a target with
/// no port must be permitted — because that "steer" only removes.
///
/// This is the state a `steer off` whose `unsteer` the NIC refused
/// lands in. The rules are diverting traffic for a port the operator
/// turned off; the table having holes is no reason to leave them there,
/// since the reconcile takes traffic OFF VPP rather than putting it on.
/// Held back, the retry would be the thing keeping the rollback
/// unfinished — and a convergence ending `VerifyIncomplete` emits no
/// steer of its own, so nothing else was coming.
///
/// Asserted at the gate, with counts a real engine produced. The unit
/// test beside `steer` cannot: its ledger is empty, so
/// `blocks_first_steer()` is false there and the exception it looks
/// like it exercises is never reached. The sequence that arrives here —
/// refused unsteer, death, re-armed want, reconcile, retired want — is
/// `the_retry_finishes_a_steer_off_and_then_stops` in the supervisor.
#[test]
fn an_empty_target_is_permitted_over_a_table_with_known_holes() {
    /// `configured_ports() == 0`: `steer off`, with rules a refused
    /// `unsteer` left in the NIC.
    struct EmptyTarget(Vec<(String, u32)>);
    impl packetframe_vpp_offload::runtime::Steering for EmptyTarget {
        fn missing_from_nic(
            &self,
        ) -> Result<packetframe_vpp_offload::runtime::SteeringAudit, String> {
            Ok(packetframe_vpp_offload::runtime::SteeringAudit::clean())
        }
        fn configured_ports(&self) -> usize {
            0
        }
        fn steer(&mut self) -> Result<packetframe_vpp_offload::runtime::SteerOutcome, String> {
            self.0.clear();
            Ok(packetframe_vpp_offload::runtime::SteerOutcome::NothingToSteer)
        }
        fn unsteer(&mut self) -> Result<(), String> {
            Err("a rule would not come out".into())
        }
        fn installed(&self) -> Vec<(String, u32)> {
            self.0.clone()
        }
        fn retarget(
            &mut self,
            _targets: Vec<(String, u32, packetframe_vpp_offload::steer::RuleSet)>,
        ) {
        }
    }

    let fake = Fake::start("steer-retry-empty-holes");
    let rt = runtime_custom(
        &fake,
        Box::new(Mirror {
            routes: (0..5).map(|i| fake_vpp::v4(0, i)).collect(),
        }),
        // Five routes into a two-route heap: three withheld.
        Box::new(EmptyTarget(Vec::new())),
        2,
    );
    // Converged at bring-up so the fresh-resync hold releases; the
    // condemning verdict lands AFTER Ready, which is when a rollback
    // actually happens in this weather.
    let handle = std::sync::Arc::new(packetframe_common::fib::TableCompleteness::new());
    rt.require_table_complete(handle.clone());
    handle.publish(packetframe_common::fib::CompletenessReport {
        authority_routes: 5,
        mirror_routes: 5,
        at: std::time::Instant::now(),
    });

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
    let (_, events) = run_until(&mut d, &rt, t0, |d| d.state() == State::Ready);
    assert!(
        events.contains(&Event::VerifyIncomplete),
        "the holey table is the premise: {events:?}"
    );
    let counts = rt.status().counts;
    assert!(
        counts.blocks_first_steer() && counts.withheld > 0,
        "and the FIB gate must really be closed, or this proves nothing: {counts:?}"
    );
    handle.publish(packetframe_common::fib::CompletenessReport {
        authority_routes: 1_000,
        mirror_routes: 5,
        at: std::time::Instant::now(),
    });

    let (mut obs, _) = rt.views();
    use packetframe_vpp_offload::driver::Observe as _;
    assert!(
        obs.steer_permitted(),
        "a reconcile that only removes must not be held by gates describing a table \
         traffic would be diverted INTO — that is what leaves a rollback unfinished"
    );
}

/// The fresh-resync hold, end to end (primary w7, 2026-08-13): a fresh
/// convergence under `require-table-complete on` whose source has not
/// loaded yet must SIT in `Syncing` — installs trickling in as the feed
/// delivers — and verify exactly once, over the full table, after the
/// authority confirms it. The old behaviour was `SyncComplete` on the
/// first momentarily-empty drain, ~1 s after spawn and before bird's
/// session had even opened, then `sampled == 0` riding the
/// restart-worthy verdict: seven kill-respawn cycles in 31 s, each one
/// re-running the octeon driver's port start against the shared LMAC
/// and blacking out the switch0 bridge below the kernel.
///
/// Driven through the adopted-an-empty-FIB door because host CI cannot
/// spawn a real VPP — `adopted == 0` takes the identical fresh arm of
/// `start_resync` (the harness note on `the_full_loop` test explains
/// the constraint).
#[test]
fn a_fresh_convergence_holds_verify_until_the_authority_confirms_the_table() {
    use packetframe_common::fib::{CompletenessReport, TableCompleteness};
    use packetframe_vpp_offload::engine::SourceChanges;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A live-feed stand-in: the mirror fills over time, and new routes
    /// reach the engine through `drain_changes`, exactly like the
    /// production tee.
    struct LoadingFeed {
        mirror: Rc<RefCell<Vec<IpPrefix>>>,
        queued: Rc<RefCell<Vec<IpPrefix>>>,
    }
    impl RouteSource for LoadingFeed {
        fn requeue(&self, changes: SourceChanges) {
            // Fill-if-absent is moot here: the test never fails a send.
            self.queued
                .borrow_mut()
                .extend(changes.routes.into_iter().map(|(p, _)| p));
        }
        fn route_count(&self) -> u64 {
            self.mirror.borrow().len() as u64
        }
        fn change_seq(&self) -> u64 {
            self.mirror.borrow().len() as u64
        }
        fn backlog(&self) -> u64 {
            self.queued.borrow().len() as u64
        }
        fn drain_changes(&self, max: usize) -> SourceChanges {
            let mut q = self.queued.borrow_mut();
            let take = q.len().min(max);
            SourceChanges {
                routes: q
                    .drain(..take)
                    .map(|p| (p, Some(vec![fake_vpp::nh()])))
                    .collect(),
                neighbours: Vec::new(),
            }
        }
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            for p in self.mirror.borrow().iter() {
                visit(*p, &[fake_vpp::nh()]);
            }
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(fake_vpp::nh(), "eth4", MAC);
        }
    }

    let fake = Fake::start("fresh-hold");
    let mirror = Rc::new(RefCell::new(Vec::new()));
    let queued = Rc::new(RefCell::new(Vec::new()));
    let rt = runtime_with_source(
        &fake,
        Box::new(LoadingFeed {
            mirror: Rc::clone(&mirror),
            queued: Rc::clone(&queued),
        }),
    );
    let handle = std::sync::Arc::new(TableCompleteness::new());
    rt.require_table_complete(handle.clone());

    let mut d = Driver::new();
    let mut now = Instant::now();
    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready());
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(now, Event::Adopted { steered: false }, &mut fx);
    }
    assert_eq!(d.state(), State::Syncing);

    // The incident window: the source is empty and the authority has
    // published nothing. Thirty ticks was ~three teardowns' worth of
    // wall time on the primary; here the loop must go NOWHERE.
    let (mut obs, mut fx) = rt.views();
    for _ in 0..30 {
        let t = d.tick(now, &mut obs, &mut fx);
        assert!(
            !t.events.contains(&Event::SyncComplete),
            "an empty pending map is not a complete sync while the authority is silent"
        );
        for e in rt.take_pending() {
            assert!(
                !matches!(e, Event::VerifyFailed),
                "the exact verdict that kill-looped the primary"
            );
            d.inject(now, e, &mut fx);
        }
        now += t
            .sleep
            .unwrap_or(Duration::from_millis(100))
            .max(Duration::from_millis(1));
    }
    assert_eq!(
        d.state(),
        State::Syncing,
        "holding IS the fix: no verify, no teardown, VPP untouched"
    );
    drop((obs, fx));

    // bird's dump lands (through the delta seam, like the live feed)
    // and the authority confirms it.
    let table: Vec<IpPrefix> = (0..5).map(|i| fake_vpp::v4(0, i)).collect();
    mirror.borrow_mut().extend(table.iter().copied());
    queued.borrow_mut().extend(table.iter().copied());
    handle.publish(CompletenessReport {
        authority_routes: 5,
        mirror_routes: 5,
        at: Instant::now(),
    });

    let (_, events) = run_until(&mut d, &rt, now, |d| d.state() == State::Ready);
    assert!(
        events.contains(&Event::SyncComplete),
        "the hold must release once the authority confirms: {events:?}"
    );
    assert!(
        events.contains(&Event::VerifyPassed),
        "and the one verify runs over the FULL table: {events:?}"
    );
    assert!(
        !events.contains(&Event::VerifyFailed),
        "no teardown anywhere in the whole convergence: {events:?}"
    );
    assert_eq!(rt.status().counts.installed, 5);
}

/// The two release conditions are AND, and the verdict backstop holds
/// when the gate cannot: a converged authority word over a feed still
/// HOLDING changes must not release (the mirror-vs-bird comparison
/// cannot see them — the #160 gap), and when the release does come with
/// nothing installed, the empty sample rides `VerifyIncomplete` — reach
/// `Ready`, refuse steering — never the teardown verdict.
#[test]
fn a_backlog_blocks_the_release_and_an_empty_sample_never_tears_down() {
    use packetframe_common::fib::{CompletenessReport, TableCompleteness};
    use packetframe_vpp_offload::engine::SourceChanges;
    use std::cell::Cell;
    use std::rc::Rc;

    /// Claims five routes and a converged-looking count, but has never
    /// handed anything over and still holds a backlog.
    struct Withholding {
        backlog: Rc<Cell<u64>>,
    }
    impl RouteSource for Withholding {
        fn requeue(&self, _: SourceChanges) {
            unreachable!("this source hands nothing over, so nothing can come back")
        }
        fn route_count(&self) -> u64 {
            5
        }
        fn change_seq(&self) -> u64 {
            5
        }
        fn backlog(&self) -> u64 {
            self.backlog.get()
        }
        fn for_each_route(&self, _: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(fake_vpp::nh(), "eth4", MAC);
        }
    }

    let fake = Fake::start("fresh-hold-backlog");
    let backlog = Rc::new(Cell::new(4_096u64));
    let rt = runtime_with_source(
        &fake,
        Box::new(Withholding {
            backlog: Rc::clone(&backlog),
        }),
    );
    let handle = std::sync::Arc::new(TableCompleteness::new());
    rt.require_table_complete(handle.clone());
    handle.publish(CompletenessReport {
        authority_routes: 5,
        mirror_routes: 5,
        at: Instant::now(),
    });

    let mut d = Driver::new();
    let mut now = Instant::now();
    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready());
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(now, Event::Adopted { steered: false }, &mut fx);
    }

    // Authority says converged — but the feed still holds a backlog,
    // and the backlog wins.
    {
        let (mut obs, mut fx) = rt.views();
        for _ in 0..10 {
            let t = d.tick(now, &mut obs, &mut fx);
            assert!(
                !t.events.contains(&Event::SyncComplete),
                "a converged word cannot vouch for changes the feed has not handed over"
            );
            for e in rt.take_pending() {
                d.inject(now, e, &mut fx);
            }
            now += t
                .sleep
                .unwrap_or(Duration::from_millis(100))
                .max(Duration::from_millis(1));
        }
        assert_eq!(d.state(), State::Syncing);
    }

    // Backlog drains; the hold releases — onto a ledger that installed
    // nothing, which is exactly the shape the verdict backstop covers.
    backlog.set(0);
    let (_, events) = run_until(&mut d, &rt, now, |d| d.state() == State::Ready);
    assert!(
        events.contains(&Event::VerifyIncomplete),
        "an empty sample holds: {events:?}"
    );
    assert!(
        !events.contains(&Event::VerifyFailed),
        "and never tears down — a restart cannot conjure routes: {events:?}"
    );
}

/// The kernel rx-mode kick runs once per member port after the device
/// attach — the PF-side half of bringing a VF up on a shared LMAC.
///
/// w8 (primary, 2026-08-13) is the evidence this encodes: a single
/// stable VPP — zero `VerifyFailed`, promisc vote acknowledged — and
/// eth4's `rx_drops` froze within a second of device attach anyway,
/// with the AF's channel-default entries 2004/2005 `enabled: no` at
/// tFAIL. Only a PF-side rx-mode event re-installs them (five-for-five
/// in the w6 kick cycles), so the module must issue that event itself,
/// on every attach, or the first steer-less membership test blacks out
/// the bridge again.
#[test]
fn the_rx_mode_kick_runs_per_member_after_the_device_attach() {
    use packetframe_vpp_offload::runtime::RxModeKick;
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Recording(Rc<RefCell<Vec<String>>>);
    impl RxModeKick for Recording {
        fn kick(&mut self, port: &str) -> Result<(), String> {
            self.0.borrow_mut().push(port.to_string());
            Ok(())
        }
    }

    let fake = Fake::start("rx-kick");
    let rt = runtime_for(&fake, 2);
    let kicks = Rc::new(RefCell::new(Vec::new()));
    rt.rx_mode_kick(Box::new(Recording(Rc::clone(&kicks))));

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
    let (_, _) = run_until(&mut d, &rt, t0, |d| d.state() == State::Ready);
    assert_eq!(
        kicks.borrow().as_slice(),
        ["eth4"],
        "one kick per member port, after the attach, exactly once"
    );
}

/// A failed kick degrades and warns; it must NOT fail the attach.
///
/// A teardown cannot fix a host-side ioctl — escalating this is the
/// #180 defect with a new face. The port may be dark below the kernel,
/// which is why the warning names the by-hand remedy, but the offload
/// still converges and the operator decides.
#[test]
fn a_failed_kick_degrades_without_failing_the_attach() {
    use packetframe_vpp_offload::runtime::RxModeKick;

    struct Refusing;
    impl RxModeKick for Refusing {
        fn kick(&mut self, _port: &str) -> Result<(), String> {
            Err("SIOCSIFFLAGS on eth4: Operation not permitted".into())
        }
    }

    let fake = Fake::start("rx-kick-fail");
    let rt = runtime_for(&fake, 2);
    rt.rx_mode_kick(Box::new(Refusing));

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
    let (_, events) = run_until(&mut d, &rt, t0, |d| d.state() == State::Ready);
    assert!(
        events.contains(&Event::VerifyPassed),
        "the convergence itself is untouched by a kick failure: {events:?}"
    );
}
