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
use packetframe_vpp_offload::runtime::{NullStore, Runtime, SteeringUnavailable};
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

fn runtime_for(fake: &Fake, n_routes: u8) -> Runtime {
    let engine = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
        }],
        vec!["eth4".into()],
        1_000_000,
        FamilyPolicy::V4Only,
    );
    let mirror = Mirror {
        routes: (0..n_routes).map(|i| fake_vpp::v4(0, i)).collect(),
    };
    Runtime::new(
        engine,
        Box::new(mirror),
        Box::new(SteeringUnavailable),
        Box::new(NullStore),
        "/usr/bin/vpp",
        "/tmp/startup.conf",
    )
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
