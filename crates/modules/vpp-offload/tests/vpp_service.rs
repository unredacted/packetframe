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
use packetframe_vpp_offload::runtime::{
    IdentityStore, NoResources, NullStore, ProcessIdentity, Runtime, SteeringUnavailable,
};
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
                Box::new(NoResources),
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
    // This runtime holds no resources, so its release seam refuses; that
    // refusal must reach the caller rather than vanish with a discarded
    // Tick, which is the property under test. Asserted on the ACTION,
    // not on the seam's wording: the message belongs to whichever
    // `ResourceRelease` is installed, and a test keyed to one
    // implementation's prose stops checking anything the moment a real
    // one is wired in.
    let last = svc.stop().published.expect("final status");
    assert_eq!(last.state, State::Stopped, "{:?}", last.report);
    assert!(
        last.metrics.contains("state=\"stopped\"} 1"),
        "{}",
        last.metrics
    );
    assert!(
        last.teardown_failures
            .iter()
            .any(|f| f.starts_with("ReleaseResources:")),
        "the refused resource release must be on the record: {:?}",
        last.teardown_failures
    );
    // The teardown killed the process, so the verdict it produced no longer
    // describes anything. The stopped snapshot used to carry it — the
    // invalidation lived inside the main loop, and teardown is a second exit
    // path — so `packetframe_vpp_fib_verified 1` went out for a VPP that had
    // just been killed.
    assert!(
        last.metrics
            .contains("packetframe_vpp_fib_verified{module=\"vpp-offload\"} 0"),
        "the stopped snapshot claims a verified FIB for a killed process: {}",
        last.metrics
    );
    assert!(
        !last.report.subsystems.iter().any(|s| s.name == "fib-synced"
            && s.message
                .as_deref()
                .is_some_and(|m| m.contains("verified on"))),
        "and the report must agree with the gauge: {:?}",
        last.report.subsystems
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
            stall_pings_after: None,
            verify_mismatch: false,
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

/// A store that cannot persist the interface indices.
struct RefusingStore;
impl IdentityStore for RefusingStore {
    fn process_changed(&mut self, _: Option<ProcessIdentity>) -> Result<(), String> {
        Ok(())
    }
    fn interfaces_attached(&mut self, _: &[(String, u32)]) -> Result<(), String> {
        Err("state dir is read-only".into())
    }
}

/// An unpersisted interface identity must DEGRADE health, not pass
/// silently. Convergence continues by design — the interfaces work —
/// but the consequence lands at the worst moment: the next daemon
/// restart cannot adopt, and cycles VPP instead of taking it over.
#[test]
fn an_unpersisted_identity_degrades_health_and_is_named() {
    let fake = Fake::start("svc-store");
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
                Box::new(Mirror((0..3).map(|i| fake_vpp::v4(0, i)).collect())),
                Box::new(SteeringUnavailable),
                Box::new(RefusingStore),
                Box::new(NoResources),
                "/usr/bin/vpp",
                "/tmp/startup.conf",
            );
            {
                use packetframe_vpp_offload::driver::Observe as _;
                let (mut obs, _) = runtime.views();
                assert!(obs.api_ready());
            }
            Ok((
                Driver::new(),
                runtime,
                vec![Event::Adopted { steered: false }],
            ))
        }),
    )
    .expect("service starts");

    let deadline = Instant::now() + Duration::from_secs(10);
    let ready = loop {
        let s = svc.status().expect("published");
        if s.state == State::Ready {
            break s;
        }
        assert!(
            Instant::now() < deadline,
            "did not reach Ready: {:?}",
            s.state
        );
        std::thread::sleep(Duration::from_millis(20));
    };

    // Converged — the interfaces really do work.
    assert!(
        ready
            .store_error
            .as_deref()
            .is_some_and(|e| e.contains("read-only")),
        "the persistence failure must be carried, not dropped: {:?}",
        ready.store_error
    );
    assert_eq!(
        ready.report.overall,
        HealthState::Degraded,
        "Healthy over an unpersisted identity hides a restart that will fail: {:?}",
        ready.report
    );
    assert!(
        ready
            .report
            .subsystems
            .iter()
            .any(|s| s.name == "state-file"
                && s.message
                    .as_deref()
                    .is_some_and(|m| m.contains("refuse adoption"))),
        "and it must name the consequence: {:?}",
        ready.report.subsystems
    );
    // The gauge has to agree with the report. It did not, once: the
    // service patched `report` after building the snapshot, while
    // `render_metrics` rendered from the snapshot — so Prometheus kept
    // reporting healthy through the whole degradation.
    assert!(
        ready
            .metrics
            .contains("packetframe_vpp_health{module=\"vpp-offload\",state=\"degraded\"} 1"),
        "metrics and health_check disagree: {}",
        ready.metrics
    );

    let _ = svc.stop();
}

/// A failing verify's teardown failures must reach the published
/// diagnostics — and stay there until recovery.
///
/// This is the only path in the module where an action's failure exists
/// **solely** inside an injected event. Verify verdicts arrive through
/// `runtime.take_pending()`, and `driver.inject(VerifyFailed)` runs the
/// resulting teardown (`Unsteer` → `Kill` → backoff) synchronously; the
/// loop used to discard that Tick, so `SteeringUnavailable` refusing to
/// unsteer — traffic left pointed at a VPP about to be killed — appeared
/// nowhere at all. Nothing an ordinary tick produces can substitute,
/// because no ordinary tick produces it.
///
/// `Adopted { steered: true }` is what puts an `Unsteer` in the teardown
/// at all: an unsteered VPP has nothing to tear down first.
#[test]
fn a_failing_verifys_teardown_failures_are_published_and_retained() {
    let fake = fake_vpp::Fake::start_behaving(
        "svc-verifyfail",
        fake_vpp::Behaviour {
            hangup_after: None,
            reject_deletes: 0,
            garbage_crcs: false,
            // Routes install and ack; only the readback disagrees.
            stall_pings_after: None,
            verify_mismatch: true,
        },
    );
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
                Box::new(Mirror((0..3).map(|i| fake_vpp::v4(0, i)).collect())),
                // Refuses both directions until slice 5 builds MCAM.
                Box::new(SteeringUnavailable),
                Box::new(NullStore),
                Box::new(NoResources),
                "/usr/bin/vpp",
                "/tmp/startup.conf",
            );
            {
                use packetframe_vpp_offload::driver::Observe as _;
                let (mut obs, _) = runtime.views();
                assert!(obs.api_ready());
            }
            Ok((
                Driver::new(),
                runtime,
                vec![Event::Adopted { steered: true }],
            ))
        }),
    )
    .expect("service starts");

    // The FIRST nonempty failure set is the discriminator, and it has to
    // be: a loop that discarded the injection still reports an `Unsteer`
    // failure eventually, because the backoff's next `Spawn` fails and
    // fails again into the same teardown. What only the injected verdict
    // can produce is a refused `Unsteer` with **no `Spawn` beside it** —
    // the teardown that ran the moment verification failed, before any
    // retry existed.
    let deadline = Instant::now() + Duration::from_secs(10);
    let first = loop {
        let s = svc.status().expect("published");
        if !s.last_failures.is_empty() {
            break s.last_failures;
        }
        assert!(
            Instant::now() < deadline,
            "no failure was ever published; state {:?}",
            s.state
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(
        first.iter().any(|f| f.starts_with("Unsteer:")),
        "the failing verify's teardown must be the first thing reported: {first:?}"
    );
    assert!(
        !first.iter().any(|f| f.starts_with("Spawn:")),
        "this is the retry cycle's teardown, not the verdict's — the injected Tick was \
         discarded and its failures lost: {first:?}"
    );

    // NOTE: the FIB subsystem's reporting of this verdict is deliberately
    // NOT asserted here. `VerifyFailed` injects `Kill`, and `kill`
    // returns early when nothing is supervised — this test has no real
    // process — so `on_process_gone` never runs and the engine's verdict
    // survives. Asserting on it would pass whether or not the loop
    // retains its own copy, which is worse than no assertion: it reads as
    // coverage. The premise the retention defends against is pinned in
    // `engine.rs` (`on_process_gone` clears `last_verify`), and the
    // loop-level consequence needs a real spawn — the failover drills.

    // And it is RETAINED. The teardown is followed by backoff ticks with
    // empty outcomes; republishing those verbatim cleared the reason
    // within one 50 ms poll while the service stayed unwell for seconds,
    // so an operator polling status would essentially always miss it.
    // Held across many times the poll cap here.
    let hold_until = Instant::now() + Duration::from_millis(400);
    while Instant::now() < hold_until {
        let s = svc.status().expect("published");
        assert!(
            !s.last_failures.is_empty(),
            "the reason was dropped by a later tick, leaving only a failure count: {:?}",
            s.state
        );
        assert_ne!(
            s.report.overall,
            HealthState::Healthy,
            "a VPP whose FIB failed verification must not read as healthy: {:?}",
            s.report
        );
        std::thread::sleep(Duration::from_millis(15));
    }

    let _ = svc.stop();
}

/// The INITIAL injection's failures must reach the first published
/// snapshot.
///
/// `attach` hands the loop a `StartRequested` (or an `Adopted`), and its
/// actions run before the first publish. Discarding that Tick meant the
/// snapshot `SupervisionService::start` guarantees to have published came
/// out with an empty `last_failures` — and if the failed spawn left an
/// undead process blocking retries, no later tick could ever reconstruct
/// the reason. The first thing an operator looks at would be blank about
/// the only thing that had happened.
///
/// `/nonexistent/vpp` fails identically on macOS (the Linux-only pidfd
/// stub) and Linux (ENOENT), so the assertion is on the action rather
/// than the platform's wording.
#[test]
fn the_initial_injections_failures_reach_the_first_snapshot() {
    let fake = Fake::start("svc-initial");
    let sock = fake.path.clone();

    let svc = SupervisionService::start(
        "vpp-offload",
        Box::new(move || {
            let engine = ConvergenceEngine::new(
                &sock,
                Vec::new(),
                vec!["eth4".into()],
                1_000_000,
                FamilyPolicy::V4Only,
            );
            let runtime = Runtime::new(
                engine,
                Box::new(Mirror(Vec::new())),
                Box::new(SteeringUnavailable),
                Box::new(NullStore),
                Box::new(NoResources),
                "/nonexistent/vpp",
                "/tmp/startup.conf",
            );
            // StartRequested, not Adopted: the loop does the spawning,
            // exactly as the attach wiring arranges it.
            Ok((Driver::new(), runtime, vec![Event::StartRequested]))
        }),
    )
    .expect("the service starts even though the spawn cannot");

    // `start()` blocked on the first publish, so this is the FIRST
    // snapshot and not a later one that happened to catch a retry.
    let first = svc.status().expect("start guarantees a published snapshot");
    assert!(
        first.last_failures.iter().any(|f| f.starts_with("Spawn:")),
        "the initial injection's failure was discarded; the first snapshot an operator \
         reads says nothing about the only thing that happened: {:?}",
        first.last_failures
    );
    assert_ne!(
        first.report.overall,
        HealthState::Healthy,
        "a VPP that never started must not read as healthy: {:?}",
        first.report
    );

    let _ = svc.stop();
}

/// A verdict must not outlive the process it describes — in either
/// polarity — and the REASON must survive the verdict.
///
/// A passing verdict kept after the process died reported a verified FIB,
/// and `packetframe_vpp_fib_verified 1`, for something that no longer
/// existed. A failing one kept for the same reason then survived into the
/// *replacement*, describing a process it had never seen for the whole
/// startup budget. Both are fixed by tying the verdict's lifetime to
/// `has_process()`; what keeps that from losing information is that the
/// failed verify's summary moves into `last_failures`, the field that
/// exists to retain reasons.
#[test]
fn a_verdict_dies_with_its_process_but_its_reason_does_not() {
    let fake = fake_vpp::Fake::start_behaving(
        "svc-inherit",
        fake_vpp::Behaviour {
            hangup_after: None,
            reject_deletes: 0,
            garbage_crcs: false,
            stall_pings_after: None,
            verify_mismatch: true,
        },
    );
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
                Box::new(Mirror((0..3).map(|i| fake_vpp::v4(0, i)).collect())),
                Box::new(SteeringUnavailable),
                Box::new(NullStore),
                Box::new(NoResources),
                "/nonexistent/vpp",
                "/tmp/startup.conf",
            );
            {
                use packetframe_vpp_offload::driver::Observe as _;
                let (mut obs, _) = runtime.views();
                assert!(obs.api_ready());
            }
            Ok((
                Driver::new(),
                runtime,
                vec![Event::Adopted { steered: false }],
            ))
        }),
    )
    .expect("service starts");

    let fib_msg = |p: &packetframe_vpp_offload::service::Published| {
        p.report
            .subsystems
            .iter()
            .find(|s| s.name == "fib-synced")
            .and_then(|s| s.message.clone())
            .unwrap_or_default()
    };

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let p = svc.status().expect("published");
        if p.state == State::Backoff {
            // The verdict is gone: it described a process that no longer
            // exists, and the FIB subsystem speaks for the current one.
            assert!(
                !fib_msg(&p).contains("verify FAIL"),
                "the verdict outlived its process: {:?}",
                fib_msg(&p)
            );
            // But the reason is not gone.
            assert!(
                p.last_failures
                    .iter()
                    .any(|f| f.starts_with("Verify:") && f.contains("verify FAIL")),
                "the failed verify's summary was dropped with the verdict; nothing now \
                 explains the backoff: {:?}",
                p.last_failures
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "never reached Backoff; state {:?}",
            p.state
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    let _ = svc.stop();
}

/// A loop that panics AFTER its first publish must not read as a clean stop.
///
/// `is_finished()` is true for a panicked thread, so `stop()` reached its
/// success path and returned the last snapshot — which may well say
/// `Ready`/Healthy. Meanwhile the stop transition never ran, and dropping
/// `Runtime` drops the process handle rather than terminating VPP: the
/// process and its VF can still be live while detach reports success.
///
/// Timing is the whole difficulty. Everything that can fail during a SMALL
/// convergence fails inside the initial injection, before the first publish —
/// which makes `start()` return the factory-panicked error instead, a
/// different and already-handled path. So the table here is large enough that
/// the drain spans ticks: the first publish happens mid-drain, and the verify
/// and the steer that follows it land after it. `Adopted { steered: true }` is
/// what makes the machine steer at all.
#[test]
fn a_loop_that_panics_after_publishing_is_not_a_clean_stop() {
    struct PanicOnSteer;
    impl packetframe_vpp_offload::runtime::Steering for PanicOnSteer {
        fn steer(&mut self) -> Result<(), String> {
            panic!("supervision loop panic, on purpose");
        }
        fn unsteer(&mut self) -> Result<(), String> {
            Ok(())
        }
    }

    let fake = Fake::start("svc-panic");
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
                // Large enough that the drain spans several ticks
                // (DRAIN_BATCH bounds one tick's work), so verify and the
                // steer that follows it land AFTER the first publish.
                Box::new(Mirror(
                    (0..12_000u32)
                        .map(|i| fake_vpp::v4((i >> 8) as u8, (i & 0xff) as u8))
                        .collect(),
                )),
                Box::new(PanicOnSteer),
                Box::new(NullStore),
                Box::new(NoResources),
                "/usr/bin/vpp",
                "/tmp/startup.conf",
            );
            {
                use packetframe_vpp_offload::driver::Observe as _;
                let (mut obs, _) = runtime.views();
                assert!(obs.api_ready(), "the fake must answer the handshake");
            }
            Ok((
                Driver::new(),
                runtime,
                vec![Event::Adopted { steered: true }],
            ))
        }),
    )
    .expect("start succeeds: the panic comes later");
    assert!(
        svc.status().is_some(),
        "the first publish must have happened; that is the precondition"
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    while svc.is_alive() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(!svc.is_alive(), "the loop was expected to panic");

    let last = svc.stop().published.expect("a status, even after a panic");
    assert!(
        last.resources_leaked,
        "nothing confirmed a release, so resources must be reported as possibly held: {:?}",
        last.teardown_failures
    );
    assert!(
        last.teardown_failures
            .iter()
            .any(|f| f.contains("PANICKED")),
        "the panic must be named, not swallowed: {:?}",
        last.teardown_failures
    );
    assert_eq!(
        last.report.overall,
        HealthState::Unhealthy,
        "a panicked supervisor reported as healthy: {:?}",
        last.report
    );
    assert!(
        last.metrics.is_empty(),
        "stale gauges outlived the loop that rendered them: {}",
        last.metrics
    );
}

/// An unhealthy episode keeps its ROOT CAUSE, not just its latest symptom.
///
/// A failed verify puts VPP into backoff; the respawn then fails too. An
/// operator needs both — "the FIB did not verify" is why the restart is
/// happening, "cannot spawn" is why it is not finishing. Three writers of
/// `last_failures` used to disagree about this: the verify path appended
/// while the tick paths assigned, so which survived came down to ordering.
#[test]
fn an_episode_keeps_its_root_cause_alongside_the_latest_symptom() {
    let fake = fake_vpp::Fake::start_behaving(
        "svc-episode",
        fake_vpp::Behaviour {
            hangup_after: None,
            reject_deletes: 0,
            garbage_crcs: false,
            stall_pings_after: None,
            // Verification fails, which is the root cause.
            verify_mismatch: true,
        },
    );
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
                Box::new(Mirror((0..3).map(|i| fake_vpp::v4(0, i)).collect())),
                Box::new(SteeringUnavailable),
                Box::new(NullStore),
                Box::new(NoResources),
                // And the respawn cannot succeed, which is the symptom.
                "/nonexistent/vpp",
                "/tmp/startup.conf",
            );
            {
                use packetframe_vpp_offload::driver::Observe as _;
                let (mut obs, _) = runtime.views();
                assert!(obs.api_ready());
            }
            Ok((
                Driver::new(),
                runtime,
                vec![Event::Adopted { steered: false }],
            ))
        }),
    )
    .expect("service starts");

    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let p = svc.status().expect("published");
        let has_verify = p
            .last_failures
            .iter()
            .any(|f| f.starts_with("Verify:") && f.contains("verify FAIL"));
        let has_spawn = p.last_failures.iter().any(|f| f.starts_with("Spawn:"));
        if has_spawn {
            assert!(
                has_verify,
                "the spawn failure replaced the verify failure that caused the restart; \
                 the root cause is gone: {:?}",
                p.last_failures
            );
            // Bounded: a backoff loop must not grow this without limit.
            assert!(
                p.last_failures.len() <= 8,
                "episode reasons grew unbounded: {:?}",
                p.last_failures
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the respawn never failed; state {:?} failures {:?}",
            p.state,
            p.last_failures
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    let _ = svc.stop();
}

/// A teardown that outlives the detach budget stays OBSERVABLE.
///
/// `stop()`'s timeout message tells the operator to check `packetframe
/// status`. That promise was unkeepable: `stop()` consumes the service and
/// dropped the thread handle, leaving the background loop as the only owner
/// of the shared status window — so its eventual final publish, including
/// whether the release finally succeeded, went somewhere nobody could read.
///
/// The loop is held up by a fake that stops answering `control_ping` while
/// keeping the connection open, so a tick sits in its synchronous socket
/// read past the 900 ms budget.
#[test]
fn a_teardown_that_outlives_the_budget_is_still_observable() {
    let fake = fake_vpp::Fake::start_behaving(
        "svc-pending",
        fake_vpp::Behaviour {
            hangup_after: None,
            reject_deletes: 0,
            garbage_crcs: false,
            stall_pings_after: Some(1),
            verify_mismatch: false,
        },
    );
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
                Box::new(Mirror((0..3).map(|i| fake_vpp::v4(0, i)).collect())),
                Box::new(SteeringUnavailable),
                Box::new(NullStore),
                Box::new(NoResources),
                "/usr/bin/vpp",
                "/tmp/startup.conf",
            );
            {
                use packetframe_vpp_offload::driver::Observe as _;
                let (mut obs, _) = runtime.views();
                assert!(obs.api_ready());
            }
            Ok((
                Driver::new(),
                runtime,
                vec![Event::Adopted { steered: false }],
            ))
        }),
    )
    .expect("service starts");

    let report = svc.stop();
    let published = report
        .published
        .clone()
        .expect("a snapshot must come back either way");

    // Whether the budget expires is a race against the stalled ping, so
    // BOTH outcomes assert something — a conditional assertion that can
    // silently do nothing is the shape this PR has produced five times.
    // Locally this takes the pending branch; the settled branch is asserted
    // in case a slower runner beats the stall.
    // When the budget expired, the CORRECTION must already be in the shared
    // window — not only in the returned value. A caller polling the handle
    // (which is what the timeout message tells the operator to do) used to
    // read the stale `Ready`/Healthy snapshot for the rest of
    // `STOP_PATIENCE`.
    if let Some(p) = &report.pending {
        assert_eq!(
            published.report.overall,
            HealthState::Unhealthy,
            "the returned snapshot must carry the correction"
        );
        let via_handle = p.status().expect("the shared window must have a snapshot");
        assert_eq!(
            via_handle.report.overall,
            HealthState::Unhealthy,
            "the shared window still advertises health: {:?}",
            via_handle.report
        );
    }

    let Some(pending) = report.pending else {
        assert_eq!(
            report.published.as_ref().map(|p| p.state),
            Some(State::Stopped),
            "no pending handle, so the teardown must have actually completed"
        );
        return;
    };
    {
        // `settle()` is called WHILE the teardown is still running — that
        // is the case the handle exists for, and waiting for
        // `is_finished()` first is what hid a defect: `settle` read the
        // shared snapshot BEFORE joining, so the loop's real final publish
        // (arriving during the join) was discarded in favour of the
        // timeout snapshot. Waiting first meant the final publish had
        // already landed, and the pre-join read happened to be correct.
        assert!(
            !pending.is_finished(),
            "the teardown finished before settle() was called; this test is not exercising \
             the case it exists for"
        );
        let final_status = pending.settle();
        assert_eq!(
            final_status.state,
            State::Stopped,
            "the FINAL word on the teardown, which used to be destroyed with the thread: \
             {:?}",
            final_status.teardown_failures
        );
    }
}

/// The timeout correction must SURVIVE the tick that was in flight.
///
/// `stop()` sets the flag and writes its corrected snapshot while a tick is
/// blocked in a socket read. When that tick returns — up to a full ping
/// budget later — the loop's ordinary publish overwrote the correction with
/// a snapshot carrying no timeout failure and `resources_leaked = false`, so
/// a caller polling the handle lost the warning until teardown finished.
///
/// Watched until the teardown settles rather than sampled once: a single
/// check right after `stop()` returns happens BEFORE the blocked tick can
/// republish, which is how the first version of this missed it entirely.
#[test]
fn the_timeout_correction_survives_the_in_flight_tick() {
    let fake = fake_vpp::Fake::start_behaving(
        "svc-window",
        fake_vpp::Behaviour {
            hangup_after: None,
            reject_deletes: 0,
            garbage_crcs: false,
            stall_pings_after: Some(1),
            verify_mismatch: false,
        },
    );
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
                Box::new(Mirror((0..3).map(|i| fake_vpp::v4(0, i)).collect())),
                Box::new(SteeringUnavailable),
                Box::new(NullStore),
                Box::new(NoResources),
                "/usr/bin/vpp",
                "/tmp/startup.conf",
            );
            {
                use packetframe_vpp_offload::driver::Observe as _;
                let (mut obs, _) = runtime.views();
                assert!(obs.api_ready());
            }
            Ok((
                Driver::new(),
                runtime,
                vec![Event::Adopted { steered: false }],
            ))
        }),
    )
    .expect("service starts");

    let report = svc.stop();
    let Some(pending) = report.pending else {
        // The loop settled inside the budget; nothing was in flight to
        // overwrite anything, which is also correct.
        return;
    };

    let deadline = Instant::now() + Duration::from_secs(20);
    while !pending.is_finished() && Instant::now() < deadline {
        let s = pending.status().expect("a snapshot");
        assert!(
            s.resources_leaked || !s.teardown_failures.is_empty(),
            "an ordinary publish overwrote the timeout correction; a poller sees no \
             warning while the teardown is still running: {:?} / {:?}",
            s.report.overall,
            s.state
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(pending.is_finished(), "the teardown never settled");
}
