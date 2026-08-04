//! The supervision service against the fake VPP: real thread, real
//! clock, the exact shape `Module::attach()` will own.
//!
//! `vpp_runtime.rs` proved the loop body composes under a synthetic
//! clock; this proves the SERVICE does — thread lifecycle, stop
//! protocol, and the published status window — with wall-clock sleeps
//! and the factory building the non-`Send` pieces on the loop thread.

#[path = "common/fake_vpp.rs"]
mod fake_vpp;

use std::net::IpAddr;
use std::time::{Duration, Instant};

use fake_vpp::{Fake, MAC};
use packetframe_common::fib::IpPrefix;
use packetframe_common::module::HealthState;
use packetframe_vpp_offload::attach::PortAttach;
use packetframe_vpp_offload::driver::Driver;
use packetframe_vpp_offload::engine::{ConvergenceEngine, RouteSource};
use packetframe_vpp_offload::fib_sync::FamilyPolicy;
use packetframe_vpp_offload::runtime::{NullStore, Runtime, SteeringUnavailable};
use packetframe_vpp_offload::service::SupervisionService;
use packetframe_vpp_offload::supervisor::{Event, State};

struct Mirror(Vec<IpPrefix>);
impl RouteSource for Mirror {
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        for p in &self.0 {
            visit(*p, &[fake_vpp::nh()]);
        }
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(fake_vpp::nh(), "eth4", MAC);
    }
}

#[test]
fn the_service_converges_publishes_health_and_stops_clean() {
    let fake = Fake::start("svc");
    let sock = fake.path.clone();

    let svc = SupervisionService::start(
        "vpp-offload",
        Box::new(move || {
            let engine = ConvergenceEngine::new(
                &sock,
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
            let runtime = Runtime::new(
                engine,
                Box::new(Mirror((0..6).map(|i| fake_vpp::v4(0, i)).collect())),
                Box::new(SteeringUnavailable),
                Box::new(NullStore),
                "/usr/bin/vpp",
                "/tmp/startup.conf",
            );
            // The attach wiring verifies the API answers before it
            // injects an adoption; the factory mirrors that.
            {
                use packetframe_vpp_offload::driver::Observe as _;
                let (mut obs, _) = runtime.views();
                assert!(obs.api_ready(), "fake must answer the handshake");
            }
            Ok((
                Driver::new(),
                runtime,
                vec![Event::Adopted { steered: false }],
            ))
        }),
    )
    .expect("service starts");

    // start() blocked on the first publish, so this is a guarantee,
    // not a race the test happens to win.
    assert!(svc.status().is_some(), "initial snapshot published");

    // Converge on the wall clock, bounded.
    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = loop {
        let s = svc.status().expect("published");
        if s.state == State::Ready {
            break s;
        }
        assert!(
            Instant::now() < deadline,
            "did not reach Ready; last state {:?}, report {:?}",
            s.state,
            s.report.overall
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    // The staging state is the designed resting place: Healthy, with
    // the FIB subsystem verified and the metrics carrying the state
    // one-hot.
    assert_eq!(
        ready.report.overall,
        HealthState::Healthy,
        "{:?}",
        ready.report
    );
    assert!(
        ready
            .metrics
            .contains("packetframe_vpp_state{module=\"vpp-offload\",state=\"ready\"} 1"),
        "{}",
        ready.metrics
    );
    assert!(
        ready
            .metrics
            .contains("packetframe_vpp_fib_verified{module=\"vpp-offload\"} 1"),
        "{}",
        ready.metrics
    );
    assert!(svc.is_alive());

    // Stop: the machine is handed StopRequested, settles in Stopped,
    // and the final snapshot says so — INCLUDING the failures the stop
    // transition produced after the supervisor was already Stopped.
    // The runtime's release_resources refuses by design until the
    // attach wiring exists, and that refusal must reach the caller
    // rather than vanish with a discarded Tick.
    let last = svc.stop().expect("final status");
    assert_eq!(last.state, State::Stopped, "{:?}", last.report);
    assert!(
        last.metrics.contains("state=\"stopped\"} 1"),
        "{}",
        last.metrics
    );
    assert!(
        last.teardown_failures
            .iter()
            .any(|f| f.contains("attach wiring")),
        "the refused resource release must be on the record: {:?}",
        last.teardown_failures
    );
}

/// A VPP speaking a different API version must fail ATTACH, with the
/// skew on the record — not be adopted into a supervision loop that
/// restarts it every 60 s while the explanation sits unread.
///
/// The check lives in the factory because that is where the real attach
/// wiring verifies the API before adopting: adoption injected against a
/// dead transport runs `attach_devices` synchronously, fails
/// `NotConnected`, and lands in backoff without ever polling
/// `api_ready` — so discovering the skew there would be too late to
/// name it. (The loop ALSO checks `api_incompatible` for a VPP that
/// becomes incompatible mid-life, e.g. a respawn into an upgraded
/// binary. That path needs a real spawn and stays hardware territory
/// with the failover drills.)
#[test]
fn an_incompatible_api_fails_attach_with_the_reason() {
    let fake = fake_vpp::Fake::start_behaving(
        "svc-crc",
        fake_vpp::Behaviour {
            hangup_after: None,
            reject_deletes: 0,
            garbage_crcs: true,
        },
    );
    let sock = fake.path.clone();

    let err = SupervisionService::start(
        "vpp-offload",
        Box::new(move || {
            let mut engine = ConvergenceEngine::new(
                &sock,
                Vec::new(),
                vec!["eth4".into()],
                1_000_000,
                FamilyPolicy::V4Only,
            );
            // Exactly what the attach wiring does: confirm the API
            // answers BEFORE committing to adopt it.
            if !engine.api_ready() {
                return Err(format!(
                    "VPP's binary API did not answer usably: {}{}",
                    engine.last_api_error().unwrap_or("(no detail)"),
                    if engine.api_incompatible() {
                        " (permanently incompatible — retrying cannot fix this)"
                    } else {
                        ""
                    }
                ));
            }
            unreachable!("the fake advertises garbage CRCs; the handshake must refuse");
        }),
    )
    .err()
    .expect("attach must fail on a version-skewed VPP");

    assert!(
        err.contains("API mismatch"),
        "the CRC detail must survive: {err}"
    );
    assert!(
        err.contains("permanently incompatible"),
        "and it must be marked terminal, not retryable: {err}"
    );
}
