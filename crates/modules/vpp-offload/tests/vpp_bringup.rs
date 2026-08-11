//! `Module::attach()` end to end on a dev laptop: a fixture sysfs, the
//! fake VPP on a real socket, and the real supervision thread.
//!
//! This is the composition nothing had exercised — slices 1–4 were each
//! tested in isolation, and "merged" was never "runs". What it can and
//! cannot prove is worth stating plainly, because the gap is the reason
//! the hardware drills still exist:
//!
//! - **Proven here:** the ordering (pure checks → acquire → render →
//!   supervise), the refusals, rollback on a failure after acquisition,
//!   the state file's contents, the rendered startup.conf matching the
//!   derived core map, health reporting through the real `Module` trait,
//!   and a detach that stops the loop and releases everything.
//! - **Not proven here:** anything requiring a real VPP process. Spawn
//!   is deliberately made to fail (the configured binary is executable,
//!   as `bring_up` insists, but is not a program), so the loop lands in
//!   backoff. That makes the
//!   test deterministic on both macOS — where `VppProcess::spawn` is an
//!   `ENOSYS` stub — and Linux, and it means the convergence path is
//!   exercised by `vpp_service.rs` (which injects an adoption against
//!   the fake) rather than by this one.

use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[path = "common/fake_vpp.rs"]
mod fake_vpp;

use packetframe_common::fib::IpPrefix;
use packetframe_common::module::HealthState;
use packetframe_vpp_offload::acquire::SysPaths;
use packetframe_vpp_offload::bringup::{bring_up, AttachPaths};
use packetframe_vpp_offload::engine::RouteSource;
use packetframe_vpp_offload::resources::ResourceState;
use packetframe_vpp_offload::steer::McamBudget;
use packetframe_vpp_offload::VppOffloadConfig;

/// The allowlist steering would divert. Non-empty so the `steer on`
/// path has something to plan; these tests keep every port `steer off`
/// except the one that exercises it.
const ALLOW: [IpPrefix; 1] = [IpPrefix::V4 {
    addr: [23, 191, 200, 0],
    prefix_len: 24,
}];

/// A mirror with one route and one resolved neighbour. Enough to be a
/// route source; convergence itself is `vpp_service.rs`'s job.
struct Mirror;
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
        visit(fake_vpp::v4(0, 0), &[fake_vpp::nh()]);
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(fake_vpp::nh(), "eth4", fake_vpp::MAC);
    }
}

/// Fixture sysfs + CPU topology + a stand-in VPP binary, on the same
/// conventions as the `acquire` unit tests.
struct Host {
    base: PathBuf,
    paths: AttachPaths,
    vpp_binary: PathBuf,
}

impl Host {
    fn new(tag: &str, ports: &[(&str, &str)], api_socket: PathBuf) -> Self {
        let mut base = std::env::temp_dir();
        base.push(format!("pf-bringup-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let net = base.join("net");
        let devices = base.join("devices");
        let drivers = base.join("drivers");
        let pool = base.join("hugepages-524288kB");
        for d in ["vfio-pci", "rvu_nicvf"] {
            fs::create_dir_all(drivers.join(d)).unwrap();
        }
        fs::create_dir_all(&pool).unwrap();
        fs::write(pool.join("nr_hugepages"), "0").unwrap();
        for (iface, pci) in ports {
            let dev = net.join(iface).join("device");
            fs::create_dir_all(&dev).unwrap();
            fs::write(dev.join("sriov_numvfs"), "0").unwrap();
            // The PF's MAC, which attach gives to the VPP interface so
            // steered frames — addressed to the PF — are accepted rather
            // than punted. Distinct per port, so a test that crossed
            // them would show it.
            let last = iface.as_bytes()[iface.len() - 1];
            fs::write(
                net.join(iface).join("address"),
                format!("58:d6:1f:4f:cd:{last:02x}\n"),
            )
            .unwrap();
            let pci_dev = devices.join(pci);
            fs::create_dir_all(&pci_dev).unwrap();
            std::os::unix::fs::symlink(&pci_dev, dev.join("virtfn0")).unwrap();
        }
        let hugetlbfs = base.join("dev-hugepages");
        fs::create_dir_all(&hugetlbfs).unwrap();
        let cpu = base.join("cpu");
        fs::create_dir_all(&cpu).unwrap();
        // The reference fleet's shape: 18 cores, cpu12 isolated for
        // unifi-core.
        fs::write(cpu.join("online"), "0-17\n").unwrap();
        fs::write(cpu.join("isolated"), "12\n").unwrap();

        // Executable — `bring_up` requires it, and requires it before
        // acquiring anything — but not a program: an exec of a file with
        // no shebang and no ELF header fails ENOEXEC on Linux, and on
        // macOS the process layer is the ENOSYS stub, so the loop's first
        // spawn fails on both without ever producing a process. Keeping
        // the process out of the picture is what makes these tests
        // deterministic.
        let vpp_binary = base.join("vpp");
        fs::write(&vpp_binary, "not really vpp").unwrap();
        fs::set_permissions(&vpp_binary, fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            paths: AttachPaths {
                sys: SysPaths {
                    sysfs_net: net,
                    pci_devices: devices,
                    pci_drivers: drivers,
                    hugepage_pool: pool,
                    hugepage_bytes: 512 << 20,
                    hugetlbfs,
                    state_dir: base.join("state"),
                },
                sysfs_cpu: cpu,
                api_socket,
                startup_conf: base.join("startup.conf"),
            },
            vpp_binary,
            base,
        }
    }

    fn cfg(&self, ports: &[(&str, u16, bool)]) -> VppOffloadConfig {
        VppOffloadConfig {
            ports: ports
                .iter()
                .map(|(i, c, s)| (i.to_string(), *c, *s))
                .collect(),
            vpp_binary: Some(self.vpp_binary.to_string_lossy().into_owned()),
            expected_routes: 1_600_000,
            hugepages: None,
            // These fixtures have no route authority to compare
            // against, and none of them steers; the gate is exercised
            // where it lives, in `runtime`.
            require_table_complete: false,
            loopback_address: Some(packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
                prefix_len: 32,
            }),
        }
    }

    fn state(&self) -> Option<ResourceState> {
        ResourceState::load(&self.paths.sys.state_dir).unwrap()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// The whole sequence, in order, with everything it produced checked
/// against what the next daemon and the next operator will read.
#[test]
fn a_fresh_attach_acquires_renders_and_supervises() {
    let fake = fake_vpp::Fake::start("bringup");
    let host = Host::new(
        "fresh",
        &[("eth4", "0002:07:00.0"), ("eth5", "0002:07:00.1")],
        fake.path.clone(),
    );
    let cfg = host.cfg(&[("eth4", 1, false), ("eth5", 1, false)]);

    let attached = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .expect("bring-up");

    // --- The core map: workers off the top, main below them, cpu0 and
    // the isolated cpu12 untouched.
    assert_eq!(attached.cores.workers, vec![16, 17]);
    assert_eq!(attached.cores.main, 15);

    // --- startup.conf: the rendered file must name that exact map, and
    // must carry the statseg stanza whose absence aborted VPP at gate
    // 0b.
    let conf = fs::read_to_string(&host.paths.startup_conf).expect("startup.conf written");
    assert!(conf.contains("corelist-workers 16,17"), "{conf}");
    assert!(conf.contains("main-core 15"), "{conf}");
    assert!(conf.contains("statseg {"), "no stats segment: {conf}");
    assert!(
        conf.contains(&format!("socket-name {}", fake.path.display())),
        "{conf}"
    );

    // --- The state file: both VFs recorded with the PCI addresses the
    // attach step will use, the hugepage reservation owned, and the
    // sizing recorded so a later adoption can refuse a changed forecast.
    let state = host.state().expect("state file");
    assert_eq!(
        state
            .ports
            .iter()
            .map(|p| p.iface.as_str())
            .collect::<Vec<_>>(),
        vec!["eth4", "eth5"]
    );
    assert_eq!(state.ports[0].vf_pci, "0002:07:00.0");
    assert_eq!(state.expected_routes, 1_600_000);
    assert!(state.hugepage_pages > 0, "reservation not recorded");
    assert_eq!(
        fs::read_to_string(host.paths.sys.hugepage_pool.join("nr_hugepages"))
            .unwrap()
            .trim(),
        state.hugepage_pages.to_string(),
        "the pool must actually hold what the state claims"
    );

    // --- Supervision is running and publishing. The spawn cannot
    // succeed here, so the interesting assertion is that the failure is
    // REPORTED rather than swallowed: this is the diagnostic that tells
    // an operator why a retry loop is looping.
    let deadline = Instant::now() + Duration::from_secs(5);
    let failing = loop {
        let p = attached.service.status().expect("published");
        if !p.last_failures.is_empty() {
            break p;
        }
        assert!(
            Instant::now() < deadline,
            "no spawn failure was ever reported; state {:?}",
            p.state
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    // Asserted on the action, not on the OS's wording: macOS reports the
    // Linux-only stub, Linux reports EACCES on a non-executable file, and
    // both are the same finding — the spawn failed and the reason
    // reached the caller.
    assert!(
        failing
            .last_failures
            .iter()
            .any(|f| f.starts_with("Spawn:")),
        "the spawn failure must be attributed to the action: {:?}",
        failing.last_failures
    );
    // And it degrades health rather than passing silently.
    assert_ne!(
        failing.report.overall,
        HealthState::Healthy,
        "a VPP that will not start read as healthy: {:?}",
        failing.report
    );

    // --- Teardown releases everything: VFs back to the kernel driver,
    // the hugepage pool restored to its prior count, state file gone.
    let last = attached.service.stop().published.expect("final status");
    assert!(
        !last.resources_leaked,
        "nothing was steered and no process exists; the release must proceed: {:?}",
        last.teardown_failures
    );
    assert!(
        host.state().is_none(),
        "the state file must be gone once everything is released"
    );
    assert_eq!(
        fs::read_to_string(host.paths.sys.hugepage_pool.join("nr_hugepages"))
            .unwrap()
            .trim(),
        "0",
        "the hugepage reservation was not restored to its prior count"
    );
}

/// A config that cannot work must cost nothing. The rollback path exists,
/// but it should not be reachable by an ordinary operator typo — so the
/// pure checks all run before the first sysfs write.
#[test]
fn a_config_that_cannot_work_touches_nothing() {
    let fake = fake_vpp::Fake::start("bringup-refuse");
    let host = Host::new("refuse", &[("eth4", "0002:07:00.0")], fake.path.clone());

    // More workers than there are usable CPUs (18 online, cpu0 and cpu12
    // excluded ⇒ 16 usable, so 16 workers plus a main thread cannot fit).
    let mut cfg = host.cfg(&[("eth4", 16, false)]);
    let e = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .err()
    .expect("must fail");
    assert!(e.contains("usable CPU"), "{e}");

    // A VPP binary that is not there.
    cfg = host.cfg(&[("eth4", 1, false)]);
    cfg.vpp_binary = Some(host.base.join("no-such-vpp").to_string_lossy().into_owned());
    let e = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .err()
    .expect("must fail");
    assert!(e.contains("does not exist"), "{e}");

    // A VPP binary that is there but cannot be executed. Distinct from
    // the above, and worth its own case: this one used to pass the check
    // and be discovered by the loop's first spawn — permanent, retried
    // forever, with the VFs and the reservation already taken.
    let unexecutable = host.base.join("vpp-no-x");
    fs::write(&unexecutable, "not really vpp").unwrap();
    fs::set_permissions(&unexecutable, fs::Permissions::from_mode(0o644)).unwrap();
    cfg.vpp_binary = Some(unexecutable.to_string_lossy().into_owned());
    let e = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .err()
    .expect("must fail");
    assert!(e.contains("is not executable"), "{e}");

    // No attempt may have created a VF, a reservation, or a record.
    assert!(host.state().is_none(), "a refused attach left a state file");
    assert_eq!(
        fs::read_to_string(host.paths.sys.hugepage_pool.join("nr_hugepages"))
            .unwrap()
            .trim(),
        "0",
        "a refused attach reserved hugepages"
    );
    assert_eq!(
        fs::read_to_string(
            host.paths
                .sys
                .sysfs_net
                .join("eth4")
                .join("device")
                .join("sriov_numvfs")
        )
        .unwrap()
        .trim(),
        "0",
        "a refused attach created a VF"
    );
    assert!(
        !host.paths.startup_conf.exists(),
        "a refused attach rendered a startup.conf"
    );
}

/// A failure AFTER acquisition must release what it took. Provoked at
/// the last step that can fail before the loop starts: an unwritable
/// startup.conf path.
#[test]
fn a_failure_after_acquisition_releases_what_it_took() {
    let fake = fake_vpp::Fake::start("bringup-rollback");
    let mut host = Host::new("rollback", &[("eth4", "0002:07:00.0")], fake.path.clone());
    // A directory where the file must go: `create_dir_all` succeeds on
    // the parent, and the write then fails with EISDIR.
    host.paths.startup_conf = host.base.join("conf-is-a-dir");
    fs::create_dir_all(&host.paths.startup_conf).unwrap();

    let cfg = host.cfg(&[("eth4", 1, false)]);
    let e = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .err()
    .expect("must fail");
    assert!(e.contains("conf-is-a-dir"), "{e}");
    assert!(
        e.contains("was released"),
        "the rollback must be reported, not silent: {e}"
    );

    assert!(
        host.state().is_none(),
        "acquisition survived a failed attach"
    );
    assert_eq!(
        fs::read_to_string(host.paths.sys.hugepage_pool.join("nr_hugepages"))
            .unwrap()
            .trim(),
        "0",
        "the hugepage reservation was not rolled back"
    );
}

/// The module refuses to attach without a route source, and the refusal
/// happens before anything is touched.
///
/// Not a nicety: a VPP with an empty FIB passes every check this module
/// makes — process alive, API answering, devices attached, verify
/// trivially passing on an empty sample — and blackholes every steered
/// packet. There is no later point at which the mistake becomes visible.
#[test]
fn attaching_without_a_route_source_is_refused() {
    use packetframe_common::config::{GlobalConfig, ModuleSection};
    use packetframe_common::module::{Module, ModuleConfig};
    use packetframe_vpp_offload::VppOffloadModule;

    let mut m = VppOffloadModule::new();
    let section = ModuleSection {
        name: "vpp-offload".into(),
        directives: Vec::new(),
    };
    let global = GlobalConfig::default();
    let e = m
        .attach(&ModuleConfig::new(&section, &global))
        .expect_err("attach without a source must fail");
    let msg = e.to_string();
    assert!(msg.contains("route source"), "{msg}");
    assert!(
        msg.contains("blackhole"),
        "the reason must be stated: {msg}"
    );

    // And health still reads as "loaded, orchestrating nothing" rather
    // than inventing a fault from a failed attach.
    assert_eq!(
        m.health_check(&packetframe_common::module::HealthCtx::new())
            .unwrap()
            .overall,
        HealthState::Healthy
    );

    // With a source wired, that particular refusal is gone — which is
    // what proves the seam is consulted rather than being a setter
    // nothing reads. The attach still fails, now on the next guard: this
    // module was never `load`ed, so it has no state directory. That guard
    // is also what keeps this test from reaching real sysfs.
    m.set_route_source(Box::new(Mirror));
    let msg = m
        .attach(&ModuleConfig::new(&section, &global))
        .expect_err("an unloaded module cannot attach")
        .to_string();
    assert!(
        !msg.contains("route source"),
        "the source was set and still not seen: {msg}"
    );
    assert!(msg.contains("before load()"), "{msg}");
}
/// A `steer on` port whose allowlist yields no rules is refused, in the
/// pure phase.
///
/// Steering exists now, so `steer on` is honoured rather than rejected —
/// but an allowlist that produces nothing steerable must not be accepted
/// quietly. The supervisor would settle in `Ready` with `steer_intended`
/// true and nothing diverted, which is the "requested, not observed"
/// shape this phase keeps producing: an operator who asked for traffic
/// diversion gets a Healthy module that never moved a packet.
///
/// v6-only is the realistic way to get there — `ip6` ntuple is rejected
/// by this NIC's AF, so a v6 allowlist is unsteerable at any size.
#[test]
fn a_steer_on_port_with_nothing_steerable_is_refused() {
    let fake = fake_vpp::Fake::start("bringup-steer");
    let host = Host::new(
        "steer",
        &[("eth4", "0002:07:00.0"), ("eth5", "0002:07:00.1")],
        fake.path.clone(),
    );
    let cfg = host.cfg(&[("eth4", 1, false), ("eth5", 1, true)]);

    let v6_only = [IpPrefix::V6 {
        addr: [0x26, 0x02, 0xf7, 0xd8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        prefix_len: 48,
    }];
    let e = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &v6_only,
        None,
        None,
        &McamBudget::default(),
    )
    .err()
    .expect("steer on with nothing steerable must be refused");
    assert!(e.contains("no steerable"), "{e}");
    assert!(e.contains("steer off"), "and the remedy stated: {e}");

    // Refused BEFORE any mutation: no VF, no reservation, no state file.
    assert!(host.state().is_none(), "a refused config left a state file");
    assert_eq!(
        fs::read_to_string(host.paths.sys.hugepage_pool.join("nr_hugepages"))
            .unwrap()
            .trim(),
        "0",
        "a refused config reserved hugepages"
    );

    // And the SAME config with a steerable allowlist is accepted, so the
    // refusal is about having nothing to steer rather than about `steer
    // on` still being unimplemented.
    let ok = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    );
    assert!(
        ok.is_ok(),
        "a steerable allowlist must now be accepted: {:?}",
        ok.err()
    );
}

/// An incomplete recorded identity must REFUSE, not fall through to a fresh
/// spawn.
///
/// `VppProcess::adopt` returns `Ok(None)` when it cannot verify an identity —
/// not when the process is confirmed gone — so a record with a pid but no
/// boot id used to read as "nothing running" and inject `StartRequested`:
/// a second VPP on the same VF and the same API socket, with the recorded pid
/// overwritten and the first process orphaned holding the hardware.
///
/// Refused before `adopt` is called at all, which is what makes it testable
/// off a router.
#[test]
fn an_incomplete_recorded_identity_refuses_rather_than_spawning() {
    let fake = fake_vpp::Fake::start("bringup-identity");
    let host = Host::new("identity", &[("eth4", "0002:07:00.0")], fake.path.clone());
    let cfg = host.cfg(&[("eth4", 1, false)]);

    // First attach records the ports. DROPPED rather than stopped: `stop()`
    // releases and removes the state file, and dropping deliberately does not
    // tear down (that is preserve-on-exit, §8.5), so the record survives —
    // which is exactly the situation a daemon restart finds.
    let attached = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .expect("first attach");
    drop(attached);

    // Play the kernel's part: a real bind creates the `driver` symlink that
    // adoption verifies against.
    let link = host
        .paths
        .sys
        .pci_devices
        .join("0002:07:00.0")
        .join("driver");
    if !link.exists() {
        std::os::unix::fs::symlink(host.paths.sys.pci_drivers.join("vfio-pci"), &link).unwrap();
    }

    // Plant a record naming a VPP with an unverifiable identity.
    let mut state = host.state().expect("state file");
    state.vpp_pid = Some(4242);
    state.vpp_start_ticks = Some(99_999);
    state.vpp_boot_id = None; // the third leg is missing
    state.save(&host.paths.sys.state_dir).unwrap();

    let e = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .err()
    .expect("an unverifiable identity must refuse");
    assert!(e.contains("4242"), "the pid must be named: {e}");
    assert!(e.contains("boot id"), "and the missing leg: {e}");
    assert!(
        e.contains("second process") || e.contains("second VPP"),
        "and the consequence of spawning anyway: {e}"
    );
    // Marked, so the caller does not roll back and unbind the VF under a
    // process that may still be running.
    assert!(
        e.starts_with("RESOURCES MAY BE HELD"),
        "the rollback must be suppressed: {e}"
    );
}

/// MCAM rules recorded by a VPP that is no longer running must be
/// cleared before a fresh one is spawned.
///
/// They are NIC state, so they survive both the process and the daemon —
/// and with nothing behind the VF they have been blackholing the steered
/// prefixes since that VPP died. A fresh spawn does not fix it: reaching
/// `Ready` takes a full convergence, and the supervisor never steers a
/// first attach on its own. So the rules would keep diverting traffic
/// into a hole under a daemon that reports Healthy.
///
/// Clearing them hands those prefixes back to the eBPF fast-path, which
/// is the entire premise of it being the permanent failover tier.
///
/// The assertion is on the RECORD rather than on the NIC, because these
/// tests have no NIC: on this host the removal fails and the rules stay
/// in the ledger, which is itself the invariant that matters — a rule
/// that would not come out must remain findable by `detach --all`.
#[test]
fn steering_rules_from_a_dead_vpp_are_not_left_unaccounted() {
    let fake = fake_vpp::Fake::start("bringup-stale-steer");
    let host = Host::new(
        "stale-steer",
        &[("eth4", "0002:07:00.0")],
        fake.path.clone(),
    );
    let cfg = host.cfg(&[("eth4", 1, false)]);

    let attached = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .expect("first attach");
    drop(attached);

    // Play the kernel's part: a real bind creates the `driver` symlink
    // adoption verifies against.
    let link = host
        .paths
        .sys
        .pci_devices
        .join("0002:07:00.0")
        .join("driver");
    if !link.exists() {
        std::os::unix::fs::symlink(host.paths.sys.pci_drivers.join("vfio-pci"), &link).unwrap();
    }

    // What a steered VPP leaves behind when it dies: rules on the
    // record, no live process.
    let mut state = host.state().expect("state file");
    state.steer_rules = vec![("eth4".into(), vec![1024, 1025])];
    state.vpp_pid = None;
    state.vpp_start_ticks = None;
    state.vpp_boot_id = None;
    state.save(&host.paths.sys.state_dir).unwrap();

    let attached = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .expect("second attach");
    drop(attached);

    let after = host.state().expect("state file");
    let residual = packetframe_vpp_offload::resources::flatten_steer_rules(&after.steer_rules);
    assert_eq!(
        residual,
        vec![("eth4".to_string(), 1024), ("eth4".to_string(), 1025)],
        "a rule the removal could not clear must stay on the record — dropping it is how \
         a live MCAM rule becomes invisible to every later teardown"
    );
}

/// A recorded ledger is what `unsteer` acts on after a restart.
///
/// Both halves of this shipped in #127 and nothing connected them:
/// `steer_rules` was read by `bring_up` and written by nobody, and
/// `NtupleSteering::adopt_installed` had no production caller. So a
/// daemon restart over a steered VPP believed nothing was diverted,
/// emitted no `Unsteer` on teardown, and released the VF with MCAM
/// still pointing traffic into it.
///
/// Asserted through the teardown that the ledger governs: with rules on
/// the record, the release must be REFUSED, because on this host they
/// cannot be confirmed gone.
#[test]
fn a_recorded_ledger_withholds_the_vf_until_the_rules_are_confirmed_gone() {
    let fake = fake_vpp::Fake::start("bringup-ledger");
    let host = Host::new("ledger", &[("eth4", "0002:07:00.0")], fake.path.clone());
    let cfg = host.cfg(&[("eth4", 1, false)]);

    let attached = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .expect("first attach");
    drop(attached);

    // Play the kernel's part: a real bind creates the `driver` symlink
    // adoption verifies against.
    let link = host
        .paths
        .sys
        .pci_devices
        .join("0002:07:00.0")
        .join("driver");
    if !link.exists() {
        std::os::unix::fs::symlink(host.paths.sys.pci_drivers.join("vfio-pci"), &link).unwrap();
    }

    let mut state = host.state().expect("state file");
    state.steer_rules = vec![("eth4".into(), vec![1024])];
    state.save(&host.paths.sys.state_dir).unwrap();

    let attached = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .expect("attach");
    let report = attached.service.stop();
    let published = report
        .published
        .or_else(|| report.pending.map(|p| p.settle()))
        .expect("a final snapshot");

    assert!(
        published.resources_leaked,
        "an unconfirmed steering removal must withhold the VF; releasing it while MCAM \
         may still target it is the blackhole this ledger exists to prevent. Report: {:?}",
        published.report
    );
    assert!(
        host.state().is_some(),
        "and the state file must survive, or nothing can find the rules later"
    );
}

/// `require-table-complete on` with nothing publishing completeness is
/// refused at attach.
///
/// The gate would never pass — every steer declined with "no check has
/// run yet" — so the operator would be debugging a rollout that cannot
/// proceed. Better to say it once, at the point the configuration is
/// read, and name both ways out.
#[test]
fn requiring_completeness_with_no_publisher_is_refused_at_attach() {
    let fake = fake_vpp::Fake::start("bringup-complete");
    let host = Host::new("complete", &[("eth4", "0002:07:00.0")], fake.path.clone());
    let mut cfg = host.cfg(&[("eth4", 1, false)]);
    cfg.require_table_complete = true;

    let e = bring_up(
        &cfg,
        &host.paths,
        Box::new(Mirror),
        &ALLOW,
        None,
        None,
        &McamBudget::default(),
    )
    .err()
    .expect("must refuse");
    assert!(e.contains("require-table-complete"), "{e}");
    assert!(
        e.contains("refused forever"),
        "the consequence has to be stated, not just the condition: {e}"
    );
    assert!(
        e.contains("bird") && e.contains("off"),
        "and both ways out named: {e}"
    );
    // Nothing was acquired: this is a pure-phase refusal, so a config
    // typo costs no sysfs writes.
    assert!(
        host.state().is_none(),
        "a config refusal must not have touched the box"
    );
}
