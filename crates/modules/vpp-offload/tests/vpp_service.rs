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
            (
                Driver::new(),
                runtime,
                vec![Event::Adopted { steered: false }],
            )
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
    // and the final snapshot says so.
    let last = svc.stop().expect("final status");
    assert_eq!(last.state, State::Stopped, "{:?}", last.report);
    assert!(
        last.metrics.contains("state=\"stopped\"} 1"),
        "{}",
        last.metrics
    );
}
