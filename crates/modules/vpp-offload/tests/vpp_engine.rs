//! The convergence engine against a fake VPP on a real unix socket.
//!
//! The unit tests in `engine.rs` cover its bookkeeping; this covers the
//! thing that cannot be unit-tested — that attach, resync, drain and
//! verify **compose** over one live transport, in the right order, and
//! that what reaches the wire is what the ledger claims.
//!
//! Assertions are on decoded requests, not on byte offsets. The fake
//! decodes `ip_route_add_del` with the same generated `Decode` impl the
//! client encodes with, and builds reply headers from `MESSAGE_META`
//! rather than assuming `[id][context]` — header geometry is per-message
//! (`dev_create_port_if_reply` carries a `client_index`, its sibling
//! `dev_attach_reply` does not), and a hand-assumed prefix here would
//! quietly match a hand-assumed prefix in the client and prove nothing.
//!
//! What it deliberately does NOT model is forwarding. Whether VPP
//! actually moves packets is gate 0b's job on hardware, and nothing here
//! should be read as evidence about that.

#[path = "common/fake_vpp.rs"]
mod fake_vpp;

use std::net::{IpAddr, Ipv4Addr};

use packetframe_common::fib::IpPrefix;
use packetframe_vpp_offload::attach::{AttachMode, PortAttach};
use packetframe_vpp_offload::engine::{ConvergenceEngine, RouteSource};
use packetframe_vpp_offload::fib_sync::FamilyPolicy;

use fake_vpp::{nh, v4, Behaviour, Event, Fake, WireRoute, ASSIGNED_INDEX, MAC};

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
            visit(*p, &[nh()]);
        }
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(nh(), "eth4", MAC);
    }
}

fn mirror(n: u8) -> Mirror {
    Mirror {
        routes: (0..n).map(|i| v4(0, i)).collect(),
    }
}

fn engine_for(fake: &Fake) -> ConvergenceEngine {
    ConvergenceEngine::new(
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
    )
}

/// Drain until the pending map reports empty, with a bound so a
/// regression that never converges fails instead of hanging CI.
fn drain_to_empty(e: &mut ConvergenceEngine) -> usize {
    for pass in 1..=64 {
        let (done, _) = e.drain_batch().expect("drain succeeds against the fake");
        if done {
            return pass;
        }
    }
    panic!("resync did not converge in 64 drains");
}

/// The composition test: one transport, the whole pipeline, in order.
#[test]
fn the_convergence_pipeline_composes_over_one_transport() {
    let fake = Fake::start("pipeline");
    let mut e = engine_for(&fake);

    assert!(e.api_ready(), "the fake must answer the handshake");
    e.attach_devices(AttachMode::Fresh).expect("attach");
    assert_eq!(e.port_links().len(), 1);

    let m = mirror(10);
    let plan = e.begin_resync(&m);
    assert_eq!(plan.upserts, 10);
    drain_to_empty(&mut e);

    assert_eq!(e.counts().installed, 10, "every route acknowledged");
    assert_eq!(e.counts().installing, 0, "nothing left in flight");
    assert!(e.pending().is_empty());

    let v = e.run_verify().expect("verify");
    assert!(v.outcome.passed(), "{}", v.outcome.summary());
    assert!(v.may_steer, "a complete table may be steered into");

    // Ordering: devices attach before any route is installed. FIB paths
    // reference indices VPP has not assigned yet otherwise, and every
    // route would be deferred — correct, but a wasted cycle.
    let names: Vec<String> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Msg(n) => Some(n),
            _ => None,
        })
        .collect();
    let first_attach = names.iter().position(|n| n == "dev_attach").unwrap();
    let first_route = names.iter().position(|n| n == "ip_route_add_del").unwrap();
    assert!(
        first_attach < first_route,
        "devices must attach before routes: {names:?}"
    );
}

/// Every installed path must carry the index VPP assigned, not one the
/// module guessed. A path on the wrong index forwards nothing while
/// looking perfectly installed.
#[test]
fn routes_install_onto_the_index_vpp_assigned() {
    let fake = Fake::start("index");
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();
    e.begin_resync(&mirror(4));
    drain_to_empty(&mut e);

    let routes: Vec<WireRoute> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Route(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(routes.len(), 4);
    for r in &routes {
        assert!(r.is_add);
        assert_eq!(
            r.path_indices,
            vec![ASSIGNED_INDEX],
            "path must reference the index from dev_create_port_if_reply"
        );
    }
}

/// The diff, observed on the wire. A prefix the source dropped must
/// reach VPP as a delete — an add-only resync leaves it forwarding to a
/// nexthop nobody advertises, and readback verification cannot see it
/// because verification samples what the ledger claims.
#[test]
fn a_prefix_the_source_dropped_reaches_vpp_as_a_delete() {
    let fake = Fake::start("withdraw");
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();

    e.begin_resync(&mirror(5));
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 5);
    let _ = fake.drain_events();

    // Two prefixes disappear from the source.
    let shrunk = Mirror {
        routes: mirror(5).routes[..3].to_vec(),
    };
    let plan = e.begin_resync(&shrunk);
    assert_eq!(plan.withdrawals, 2);
    drain_to_empty(&mut e);

    let deletes: Vec<WireRoute> = fake
        .drain_events()
        .into_iter()
        .filter_map(|ev| match ev {
            Event::Route(r) if !r.is_add => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(deletes.len(), 2, "both dropped prefixes must be deleted");
    let mut got: Vec<(u8, u8, u8)> = deletes
        .iter()
        .map(|r| (r.addr[1], r.addr[2], r.len))
        .collect();
    got.sort_unstable();
    assert_eq!(
        got,
        vec![(0, 3, 24), (0, 4, 24)],
        "the two the source dropped, at their own prefix lengths"
    );

    // And the ledger must no longer claim them.
    assert_eq!(e.counts().installed, 3);
}

/// A connection that dies mid-drain must leave nothing claimed that VPP
/// did not acknowledge, put the unacknowledged work back, and drop the
/// socket so the next attempt reconnects rather than reusing a stream
/// whose framing may be desynchronised.
#[test]
fn a_hangup_mid_drain_requeues_and_disconnects() {
    let fake = Fake::start_with("hangup", 3);
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();
    e.begin_resync(&mirror(20));

    let err = loop {
        match e.drain_batch() {
            Ok((true, _)) => panic!("the fake hung up; this cannot converge"),
            Ok((false, _)) => continue,
            Err(err) => break err,
        }
    };
    let _ = err;

    assert!(
        !e.is_connected(),
        "a broken socket must be dropped, not reused"
    );
    let c = e.counts();
    assert_eq!(c.installing, 0, "nothing may be left claimed in flight");
    assert!(
        c.installed <= 3,
        "only acknowledged routes may count as installed, got {}",
        c.installed
    );
    assert!(
        !e.pending().is_empty(),
        "unacknowledged work must still be owed"
    );

    // A fresh connection can finish the job.
    assert!(e.api_ready(), "must be able to reconnect");
    e.attach_devices(AttachMode::Fresh).unwrap();
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 20);
    let v = e.run_verify().unwrap();
    assert!(v.outcome.passed());
    assert!(v.may_steer);
}

/// A mirror that still advertises the prefix but no longer resolves its
/// nexthop — the shape the rebuilt device map produces when a neighbour
/// disappears.
struct OrphanedMirror {
    routes: Vec<IpPrefix>,
}

impl RouteSource for OrphanedMirror {
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
            visit(*p, &[nh()]);
        }
    }
    /// No neighbours: the nexthop is gone.
    fn for_each_neighbour(&self, _visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {}
}

/// When an advertised prefix loses every VPP-reachable nexthop, the stale
/// route must leave VPP **and** the prefix must be recorded as
/// unresolvable.
///
/// Recording it before the delete was acknowledged meant a successful
/// delete hit `forget`, which erased the state — so `verify` saw
/// `unresolvable == 0`, never sampled the prefix, and the supervisor
/// could steer traffic into a table with a known hole.
#[test]
fn a_prefix_that_loses_its_nexthops_is_deleted_and_recorded_unresolvable() {
    let fake = Fake::start("orphan");
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();

    e.begin_resync(&mirror(3));
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 3);
    let _ = fake.drain_events();

    // Same prefixes, no reachable nexthop.
    e.begin_resync(&OrphanedMirror {
        routes: mirror(3).routes,
    });
    drain_to_empty(&mut e);

    // The stale routes actually left VPP.
    let deletes = fake
        .drain_events()
        .into_iter()
        .filter(|ev| matches!(ev, Event::Route(r) if !r.is_add))
        .count();
    assert_eq!(deletes, 3, "every stale route must be withdrawn");

    // And the hole is on the books.
    let c = e.counts();
    assert_eq!(c.installed, 0);
    assert_eq!(
        c.unresolvable, 3,
        "the prefixes are still advertised and still unreachable"
    );
    assert!(
        c.blocks_first_steer(),
        "a table with a known hole must not be steered into"
    );
    // Verification must agree, not report a clean table.
    let v = e.run_verify().unwrap();
    assert!(!v.outcome.passed(), "{}", v.outcome.summary());
    assert_eq!(v.outcome.unresolvable, 3);
    assert!(!v.may_steer);
}

/// A per-route refusal of that derived delete must be retried, not
/// swallowed.
///
/// Recording `Unresolvable` before the ack left the requeued upsert
/// seeing `was_installed == false`, so it stopped re-sending the delete
/// — a transient refusal became permanent with the stale route still
/// live in VPP and verification failing forever.
#[test]
fn a_refused_derived_delete_is_retried() {
    let fake = Fake::start_behaving(
        "orphan-reject",
        Behaviour {
            hangup_after: None,
            reject_deletes: 1,
            garbage_crcs: false,
            stall_pings_after: None,
            verify_mismatch: false,
            ..Default::default()
        },
    );
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();

    e.begin_resync(&mirror(1));
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 1);
    let _ = fake.drain_events();

    // Nexthop vanishes. The first delete is refused.
    e.begin_resync(&OrphanedMirror {
        routes: mirror(1).routes,
    });
    let (done, stats) = e.drain_batch().unwrap();
    assert_eq!(stats.rejected, 1, "the fake refused the delete");
    assert!(!done, "a refused op stays owed");
    assert_eq!(
        e.counts().installed,
        1,
        "the route is still live in VPP, so the ledger must still say so \
         — otherwise nothing knows to retry the delete"
    );

    // The retry goes out and succeeds.
    drain_to_empty(&mut e);
    let deletes = fake
        .drain_events()
        .into_iter()
        .filter(|ev| matches!(ev, Event::Route(r) if !r.is_add))
        .count();
    assert_eq!(deletes, 2, "one refused delete, one successful retry");
    assert_eq!(e.counts().installed, 0);
    assert_eq!(e.counts().unresolvable, 1);
}

/// Static neighbours must be programmed, on the index VPP assigned, and
/// **before** the routes that depend on them.
///
/// VPP starts without `linux-cp` and MCAM rules match IP fields, so an
/// ARP frame can never be steered to it — VPP physically cannot learn a
/// neighbour. Skip this and route installs are still acknowledged and
/// readback verification still passes (it checks a path exists on an
/// interface we own, not that the adjacency resolves) while every packet
/// is dropped on an incomplete adjacency. Nothing else in the module
/// would report a fault, which is what makes it worth a wire test.
#[test]
fn static_neighbours_are_programmed_before_the_routes_that_need_them() {
    let fake = Fake::start("nbr");
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();

    let m = mirror(4);
    // The mapping has to exist before neighbours can be resolved to an
    // interface, which is what the resync's refresh does.
    e.begin_resync(&m);
    assert_eq!(e.program_neighbours(&m).unwrap(), 1);
    drain_to_empty(&mut e);

    let events = fake.drain_events();
    let neighbours: Vec<_> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Neighbour {
                sw_if_index,
                mac,
                flags,
                ..
            } => Some((*sw_if_index, *mac, *flags)),
            _ => None,
        })
        .collect();
    assert_eq!(neighbours.len(), 1, "the one reachable nexthop");
    assert_eq!(
        neighbours[0].0, ASSIGNED_INDEX,
        "the adjacency must sit on the index VPP assigned"
    );
    assert_eq!(neighbours[0].1, MAC, "the resolved link-layer address");
    assert_eq!(
        neighbours[0].2, 1,
        "STATIC: VPP cannot ARP to refresh it, so an ageing entry would \
         silently become an unresolved adjacency"
    );

    // Ordering, on the wire.
    let names: Vec<&str> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Msg(n) => Some(n.as_str()),
            _ => None,
        })
        .collect();
    let first_nbr = names.iter().position(|n| *n == "ip_neighbor_add_del");
    let first_route = names.iter().position(|n| *n == "ip_route_add_del");
    assert!(
        first_nbr.is_some() && first_nbr < first_route,
        "neighbours before routes: {names:?}"
    );
}

/// A neighbour whose device is not VPP-owned is skipped, not refused —
/// same policy the route mapping applies, for the same reason: a
/// management or tunnel neighbour is not an error, it is not ours.
#[test]
fn neighbours_on_foreign_devices_are_skipped() {
    struct MixedMirror;
    impl RouteSource for MixedMirror {
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
            visit(v4(0, 0), &[nh()]);
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(nh(), "eth4", MAC);
            // Management: excluded by the nexthop mapping.
            visit(
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)),
                "eth0",
                [0x02, 0, 0, 0, 0, 9],
            );
        }
    }

    let fake = Fake::start("fgn");
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).unwrap();
    e.begin_resync(&MixedMirror);
    assert_eq!(
        e.program_neighbours(&MixedMirror).unwrap(),
        1,
        "only the member-port neighbour"
    );
}

/// A VPP advertising different CRCs must be refused as *permanently*
/// incompatible, not as a transient not-ready-yet: the difference is
/// whether the supervisor retries forever or stops and reports.
#[test]
fn a_crc_mismatch_is_recorded_as_permanent() {
    let fake = Fake::start_behaving(
        "crc",
        Behaviour {
            hangup_after: None,
            reject_deletes: 0,
            garbage_crcs: true,
            stall_pings_after: None,
            verify_mismatch: false,
            ..Default::default()
        },
    );
    let mut e = engine_for(&fake);
    assert!(!e.api_ready(), "a CRC mismatch must not read as ready");
    let err = e.last_api_error().expect("the reason is recorded");
    assert!(err.contains("API mismatch"), "{err}");
    assert!(
        e.api_incompatible(),
        "retrying cannot fix a version skew: {err}"
    );
}

/// Adopting a surviving VPP withdraws what the source stopped
/// advertising — and leaves VPP's own routes alone.
///
/// The gap this closes: the resync diff derives withdrawals from the
/// ledger, and on adoption the ledger is empty while the surviving VPP's
/// FIB is not. A prefix withdrawn while packetframe was down therefore
/// stayed installed, where a stale more-specific keeps overriding the
/// live table — and verification could not see it, because it samples
/// only what the ledger knows about.
///
/// The second half is the dangerous one. VPP's FIB also holds routes VPP
/// created: drop routes, connected routes, local `/32`s. Adopting those
/// would hand them to the same diff, and the next convergence would
/// delete the infrastructure VPP needs to resolve any adjacency. So the
/// fake serves three routes and the test asserts on all three.
#[test]
fn adoption_withdraws_stale_routes_without_touching_vpps_own() {
    // 10.0.1.0/24 — ours, and the source still advertises it.
    // 10.0.9.0/24 — ours, withdrawn while we were down. Must go.
    // 10.9.9.0/24 — no nexthop: a connected route's shape. Must stay.
    const EXISTING: &[([u8; 4], u8, u32, bool)] = &[
        ([10, 0, 1, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 9, 0], 24, ASSIGNED_INDEX, true),
        ([10, 9, 9, 0], 24, ASSIGNED_INDEX, false),
    ];
    let fake = Fake::start_behaving(
        "adopt-fib",
        Behaviour {
            existing_routes: EXISTING,
            ..Default::default()
        },
    );
    let mut engine = engine_for(&fake);
    assert!(engine.api_ready(), "handshake");
    engine.attach_devices(AttachMode::Fresh).expect("attach");

    // The source advertises only 10.0.1.0/24 now.
    let mirror = Mirror {
        routes: vec![v4(0, 1)],
    };
    let adopted = engine.adopt_vpp_fib().expect("readback");
    assert_eq!(
        adopted, 2,
        "both nexthop-bearing routes adopted; the connected-shaped one is not"
    );

    let plan = engine.begin_resync(&mirror);
    assert_eq!(
        plan.withdrawals, 1,
        "exactly the prefix the source stopped advertising: {plan:?}"
    );

    while !engine.drain_batch().expect("drain").0 {}
    let deleted: Vec<[u8; 4]> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Route(WireRoute {
                is_add: false,
                addr,
                ..
            }) => Some(addr),
            _ => None,
        })
        .collect();
    assert_eq!(
        deleted,
        vec![[10, 0, 9, 0]],
        "the stale route is withdrawn and nothing else is: {deleted:?}"
    );
}

/// The generated `Encode` and `Decode` must agree on a reply's
/// geometry, proven by round-tripping a ping through the fake.
///
/// `control_ping_reply` carries `client_index` mid-body (after retval —
/// schema fact, not header convention). The decoder consumed it
/// positionally; the encoder skipped it as "transport-owned", so every
/// fake-built ping reply was 4 bytes short of what the client demands.
/// Nothing in production encodes a reply — only the fakes do — which is
/// how EVERY fake-backed test ran its liveness path on a silently
/// failing ping (error, disconnect, reconnect next tick) without one
/// test noticing: they all converge inside the wedge budget. Found the
/// first time a test deliberately sat in a live state for minutes (the
/// adopted-resync deferral), which the wedge detector then "caught".
///
/// The codegen now emits a placeholder for mid-body transport-owned
/// fields, and this pins the symmetry where it was missing.
#[test]
fn a_fakes_ping_reply_is_decodable_not_just_writable() {
    const SIX: &[([u8; 4], u8, u32, bool)] = &[
        ([10, 0, 0, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 1, 0], 24, ASSIGNED_INDEX, true),
        ([10, 0, 2, 0], 24, ASSIGNED_INDEX, true),
    ];
    let fake = Fake::start_behaving(
        "ping-geometry",
        Behaviour {
            existing_routes: SIX,
            ..Default::default()
        },
    );
    let mut engine = engine_for(&fake);
    assert!(engine.api_ready(), "handshake");
    engine.ping().expect("a bare ping must decode");
    engine.attach_devices(AttachMode::Fresh).expect("attach");
    let adopted = engine.adopt_vpp_fib().expect("dump");
    assert_eq!(adopted, 3);
    engine
        .ping()
        .expect("the stream must still be clean after a populated dump");
}

/// Adoption programs only the neighbours VPP is missing or holds wrong.
///
/// Re-adding an existing static neighbour is not a no-op: VPP replaces
/// the entry and walks every dependent FIB entry — ~1M routes hang off
/// ONE adjacency on this topology — and traffic through it goes to
/// null-node for the duration. Measured on the shadow (2026-08-08):
/// 5.51 s of blackhole at the moment of an otherwise perfect adoption,
/// 21,055 blackholed packets across the three drill-(d) runs that
/// re-added it blind.
///
/// Three neighbours, three verdicts: an identical one is left
/// untouched; one whose MAC changed is re-programmed (that walk is the
/// price of correctness); one VPP lacks is programmed.
#[test]
fn adoption_programs_only_missing_or_stale_neighbours() {
    const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0xbb];
    const MAC_B_OLD: [u8; 6] = [0x02, 0, 0, 0, 0, 0xb0];
    const MAC_C: [u8; 6] = [0x02, 0, 0, 0, 0, 0xcc];
    const STATIC: u8 = 1;

    const MAC_D: [u8; 6] = [0x02, 0, 0, 0, 0, 0xdd];

    struct ThreeNeighbours;
    impl RouteSource for ThreeNeighbours {
        fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
            unreachable!("this source hands nothing over, so nothing can come back")
        }
        fn for_each_route(&self, _: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(nh(), "eth4", MAC); // identical in VPP: keep
            visit(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), "eth4", MAC_B); // stale MAC: replace
            visit(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12)), "eth4", MAC_C); // missing: add
            visit(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13)), "eth4", MAC_D); // extra flags: replace
        }
        fn route_count(&self) -> u64 {
            0
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }

    // nh() is 192.0.2.1 (see fake_vpp); VPP already holds it correct,
    // and holds .11 with a MAC the resolver has since replaced.
    const EXISTING_NEIGHBOURS: &[([u8; 4], u32, [u8; 6], u8)] = &[
        ([192, 0, 2, 1], ASSIGNED_INDEX, MAC, STATIC),
        ([192, 0, 2, 11], ASSIGNED_INDEX, MAC_B_OLD, STATIC),
        // Right MAC, extra flag: not the entry we would create, so it
        // must be re-programmed to exactly STATIC, not preserved.
        ([192, 0, 2, 13], ASSIGNED_INDEX, MAC_D, STATIC | 4),
    ];
    let fake = Fake::start_behaving(
        "adopt-neigh",
        Behaviour {
            existing_neighbours: EXISTING_NEIGHBOURS,
            ..Default::default()
        },
    );
    let mut engine = engine_for(&fake);
    assert!(engine.api_ready(), "handshake");
    engine.attach_devices(AttachMode::Fresh).expect("attach");
    // The nexthop->device map is refreshed by the resync walk;
    // program_neighbours resolves against it.
    engine.begin_resync(&ThreeNeighbours);

    let programmed = engine
        .program_neighbours(&ThreeNeighbours)
        .expect("programming");
    assert_eq!(
        programmed, 3,
        "the stale-MAC, missing, and extra-flag neighbours; only the exact match is kept"
    );

    let sent_macs: Vec<[u8; 6]> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Neighbour { mac, .. } => Some(mac),
            _ => None,
        })
        .collect();
    assert!(
        !sent_macs.contains(&MAC),
        "the neighbour VPP already holds correct must not be re-added — \
         re-adding walks every dependent route: {sent_macs:?}"
    );
    assert!(
        sent_macs.contains(&MAC_B) && sent_macs.contains(&MAC_C) && sent_macs.contains(&MAC_D),
        "the stale, missing, and extra-flag neighbours must all be programmed: {sent_macs:?}"
    );
}

/// The nexthop the delta path is about to program, and the MAC it
/// carries. Shared by the two refused-neighbour tests below.
const DELTA_NH: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 22));
const DELTA_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xfe];

/// A source whose delta batches the test queues by hand, and which
/// **models the feed on a requeue**: an undelivered batch goes back on the
/// queue, so the next drain re-serves it intact.
#[derive(Default)]
struct QueuedSource {
    queue: std::sync::Mutex<Vec<packetframe_vpp_offload::engine::SourceChanges>>,
}

impl QueuedSource {
    fn with(changes: packetframe_vpp_offload::engine::SourceChanges) -> Self {
        Self {
            queue: std::sync::Mutex::new(vec![changes]),
        }
    }

    fn queued(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
}

impl RouteSource for QueuedSource {
    fn requeue(&self, changes: packetframe_vpp_offload::engine::SourceChanges) {
        self.queue.lock().unwrap().insert(0, changes);
    }
    fn drain_changes(&self, _max: usize) -> packetframe_vpp_offload::engine::SourceChanges {
        self.queue.lock().unwrap().pop().unwrap_or_default()
    }
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        for i in 0..4u8 {
            visit(v4(0, i), &[nh()]);
        }
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(nh(), "eth4", MAC);
    }
    fn route_count(&self) -> u64 {
        4
    }
    fn change_seq(&self) -> u64 {
        4
    }
}

/// A converged engine against a VPP that will refuse the next `n`
/// neighbour adds. Its own resync neighbour is already in VPP, so the
/// refusal lands on the DELTA's nexthop instead of being spent on setup.
fn refusing_engine(tag: &str, fake: &Fake) -> ConvergenceEngine {
    let mut e = engine_for(fake);
    assert!(e.api_ready(), "handshake for {tag}");
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let src = QueuedSource::default();
    e.begin_resync(&src);
    e.program_neighbours(&src).expect("programming");
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 4, "the base table converges");
    let _ = fake.drain_events();
    e
}

/// VPP already holds the resync's own neighbour, correct and static.
const RESYNC_NEIGHBOUR: &[([u8; 4], u32, [u8; 6], u8)] =
    &[([192, 0, 2, 1], ASSIGNED_INDEX, MAC, 1)];

/// A refused neighbour hands the WHOLE delta batch back, routes included,
/// and the retry lands them.
///
/// `drain_changes` is destructive: the feed removes what it returns. So
/// returning early on the neighbour send left the batch's route half
/// applied nowhere — out of the feed's pending map, never into the
/// engine's, retried by nothing. An already-steered VPP went on
/// forwarding a withdrawn prefix and resolving a changed nexthop to its
/// old adjacency, with `installed`/`installing`/`withheld`/
/// `unresolvable` all unaffected, so health read fine and verify could
/// not see it: verify samples prefixes the LEDGER believes installed, and
/// the ledger never learned these existed. Only a full resync recovered.
///
/// Handing the routes BACK rather than queueing them is the load-bearing
/// half. Queued here they would install through the adjacency VPP just
/// refused, which is #115's worst finding — see the sibling test.
#[test]
fn a_refused_neighbour_hands_the_whole_delta_batch_back() {
    use packetframe_vpp_offload::engine::SourceChanges;

    // Withdrawn while steered: the delta that used to vanish.
    let withdrawn = v4(0, 3);
    // Learned through the nexthop VPP is refusing.
    let learned = v4(0, 200);

    let fake = Fake::start_behaving(
        "delta-refused",
        Behaviour {
            reject_neighbour_adds: 1,
            existing_neighbours: RESYNC_NEIGHBOUR,
            ..Default::default()
        },
    );
    let mut e = refusing_engine("delta-refused", &fake);

    let src = QueuedSource::with(SourceChanges {
        neighbours: vec![(DELTA_NH, Some(("eth4".into(), DELTA_MAC)))],
        routes: vec![(withdrawn, None), (learned, Some(vec![DELTA_NH]))],
    });

    let err = e
        .apply_changes(&src, 64)
        .expect_err("VPP refused the neighbour add");
    assert!(
        format!("{err:?}").contains("NeighbourRefused"),
        "the refusal must surface as itself: {err:?}"
    );
    assert!(
        e.pending().is_empty(),
        "the routes must NOT be queued behind a refused adjacency"
    );
    assert_eq!(
        src.queued(),
        1,
        "the batch must be back at the source, not dropped on the floor"
    );

    // The fake's refusal was count-based and is spent. The retry lands
    // the adjacency and, with it, the deltas that used to be lost.
    e.apply_changes(&src, 64)
        .expect("the retried batch applies");
    drain_to_empty(&mut e);
    assert_eq!(src.queued(), 0, "nothing owed once it lands");

    let events = fake.drain_events();
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Event::Neighbour { mac, .. } if *mac == DELTA_MAC)),
        "the adjacency is programmed on the retry: {events:?}"
    );
    let routes: Vec<&WireRoute> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Route(r) => Some(r),
            _ => None,
        })
        .collect();
    assert!(
        routes.iter().any(|r| !r.is_add && r.addr == [10, 0, 3, 0]),
        "the withdrawal the batch carried must finally reach VPP: {routes:?}"
    );
    assert!(
        routes.iter().any(|r| r.is_add && r.addr == [10, 0, 200, 0]),
        "and so must the route learned through the new nexthop: {routes:?}"
    );
    assert_eq!(
        e.counts().unresolvable,
        0,
        "and the table is complete again"
    );
}

/// A nexthop VPP refused must not become resolvable.
///
/// This is why the fix cannot simply queue the batch's routes and return
/// the error. `set_device` alone makes `resolve` answer `Some`, so every
/// route through the nexthop classifies installable and installs — while
/// VPP, which runs without linux-cp and can never ARP for the adjacency,
/// has nothing to send them to. Readback verification checks that a route
/// exists on an interface we own, deliberately not that its adjacency
/// resolves, so it passes. That is #115's worst finding: "a route through
/// an unprogrammed adjacency installs cleanly, verifies cleanly, and drops
/// every packet".
///
/// Recording the mapping before the send left that door open even on
/// failure — the entry survived the error, so the next drain resolved
/// through an adjacency VPP had refused. `unresolvable` is the honest
/// answer, and it is loud: it blocks the first steer and fails verify.
#[test]
fn a_refused_adjacency_never_becomes_resolvable() {
    use packetframe_vpp_offload::engine::SourceChanges;

    let fake = Fake::start_behaving(
        "delta-unresolvable",
        Behaviour {
            reject_neighbour_adds: 1,
            existing_neighbours: RESYNC_NEIGHBOUR,
            ..Default::default()
        },
    );
    let mut e = refusing_engine("delta-unresolvable", &fake);

    let refused = QueuedSource::with(SourceChanges {
        neighbours: vec![(DELTA_NH, Some(("eth4".into(), DELTA_MAC)))],
        routes: Vec::new(),
    });
    e.apply_changes(&refused, 64).expect_err("refused");
    let _ = fake.drain_events();

    // A later batch — routes only, so nothing re-attempts the adjacency.
    let after = QueuedSource::with(SourceChanges {
        neighbours: Vec::new(),
        routes: vec![(v4(0, 201), Some(vec![DELTA_NH]))],
    });
    e.apply_changes(&after, 64).expect("routes alone apply");
    drain_to_empty(&mut e);

    assert_eq!(
        e.counts().unresolvable,
        1,
        "a route through an unacknowledged adjacency must read unresolvable"
    );
    assert!(
        !fake
            .drain_events()
            .iter()
            .any(|ev| matches!(ev, Event::Route(WireRoute { is_add: true, .. }))),
        "and nothing may reach VPP's FIB for it"
    );
    assert!(
        e.counts().blocks_first_steer(),
        "which is loud: the hole blocks a first steer rather than hiding"
    );
}

/// A converged engine against a VPP that applies the next neighbour op and
/// then goes silent, leaving its outcome unknowable to the client.
fn silent_after_neighbour(tag: &str, fake: &Fake) -> ConvergenceEngine {
    let mut e = engine_for(fake);
    assert!(e.api_ready(), "handshake for {tag}");
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let base = QueuedSource::default();
    e.begin_resync(&base);
    // VPP already holds the neighbour, so nothing is sent here and the
    // swallow stays armed for the delta under test.
    assert_eq!(e.program_neighbours(&base).expect("programming"), 0);
    drain_to_empty(&mut e);
    let _ = fake.drain_events();
    e
}

fn silent_fake(tag: &str) -> Fake {
    Fake::start_behaving(
        tag,
        Behaviour {
            swallow_neighbour_reply: true,
            existing_neighbours: RESYNC_NEIGHBOUR,
            ..Default::default()
        },
    )
}

/// An unacknowledged neighbour ADD is not blindly re-sent.
///
/// A transport error after the write is genuinely ambiguous: VPP may have
/// applied the change. `neighbours_installed` records only
/// acknowledgements, so it comes out of this describing a table VPP may not
/// have — and re-adding an existing static neighbour is not a no-op. VPP
/// replaces the entry and walks every dependent FIB entry: ~1M routes hang
/// off one adjacency here, for a measured 5.51 s of null-node (shadow,
/// 2026-08-08). Requeueing the batch made that retry certain rather than
/// incidental, so the ledger has to be reconciled against VPP first.
///
/// The fake applies the op and then goes silent, which is the only faithful
/// model of the ambiguity: a refused retval is VPP telling us, and a hangup
/// *before* the op is unambiguous the other way.
///
/// See [`an_unacknowledged_neighbour_removal_does_not_strand_the_ledger`]
/// for the opposite direction, which fails worse.
#[test]
fn an_unacknowledged_neighbour_add_is_not_blindly_re_added() {
    use packetframe_vpp_offload::engine::SourceChanges;

    let fake = silent_fake("neigh-unacked-add");
    let mut e = silent_after_neighbour("neigh-unacked-add", &fake);

    // A MAC change on the adjacency every route resolves through — the
    // expensive one to re-add. VPP applies it and never answers.
    const MAC_CHANGED: [u8; 6] = [0x02, 0, 0, 0, 0, 0x77];
    let src = QueuedSource::with(SourceChanges {
        neighbours: vec![(nh(), Some(("eth4".into(), MAC_CHANGED)))],
        routes: Vec::new(),
    });
    e.apply_changes(&src, 64)
        .expect_err("the reply never comes");
    assert_eq!(src.queued(), 1, "the batch is owed, as ever");
    let sent = fake.drain_events();
    assert!(
        sent.iter()
            .any(|ev| matches!(ev, Event::Neighbour { mac, .. } if *mac == MAC_CHANGED)),
        "the add did reach VPP: {sent:?}"
    );

    // Reconnect and retry. The reconciling dump must find VPP already
    // holding the new MAC and absorb the re-add.
    assert!(e.api_ready(), "reconnects");
    e.apply_changes(&src, 64).expect("the retry applies");
    let after = fake.drain_events();
    assert!(
        after
            .iter()
            .any(|ev| matches!(ev, Event::Msg(m) if m == "ip_neighbor_dump")),
        "the only way to know what VPP holds is to have asked: {after:?}"
    );
    assert!(
        !after
            .iter()
            .any(|ev| matches!(ev, Event::Neighbour { mac, .. } if *mac == MAC_CHANGED)),
        "an adjacency VPP already holds must not be re-added — that walk is \
         ~1M dependent routes and 5.5 s of blackhole: {after:?}"
    );
    assert_eq!(
        after
            .iter()
            .filter(|ev| matches!(ev, Event::Msg(m) if m == "ip_neighbor_dump"))
            .count(),
        1,
        "and `V4Only` asks exactly once — the per-family loop must not cost \
         a spare round trip on the policy this NIC actually runs: {after:?}"
    );
}

/// The reconciling dump covers **every family the policy carries**.
///
/// A v4-only dump answers "not present" for a v6 neighbour, and both
/// consumers of that answer read absence as permission to send: the resync
/// walk re-adds a v6 adjacency VPP already holds, and `settle_unacked`
/// drops a v6 claim it could not verify. Either pays the dependent-FIB
/// walk this ledger exists to avoid, so under `FamilyPolicy::Both` the
/// question has to be asked twice (review finding).
///
/// The count is the assertion because that is the whole of the fix. What
/// happens to a v6 entry once found is `settle_unacked`, which the two
/// directional tests above already pin — the fake holds only v4
/// neighbours, so a v6 dump here answers empty exactly as a real v4-only
/// table would.
#[test]
fn the_reconciling_dump_covers_every_carried_family() {
    use packetframe_vpp_offload::engine::SourceChanges;

    let fake = silent_fake("neigh-unacked-v6");
    // Same wiring as `engine_for`, with the one difference under test.
    let mut e = ConvergenceEngine::new(
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
        FamilyPolicy::Both,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    );
    assert!(e.api_ready(), "handshake");
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let base = QueuedSource::default();
    e.begin_resync(&base);
    e.program_neighbours(&base).expect("programming");
    drain_to_empty(&mut e);
    let _ = fake.drain_events();

    // Leave a neighbour in doubt, then let the retry reconcile.
    const MAC_CHANGED: [u8; 6] = [0x02, 0, 0, 0, 0, 0x78];
    let src = QueuedSource::with(SourceChanges {
        neighbours: vec![(nh(), Some(("eth4".into(), MAC_CHANGED)))],
        routes: Vec::new(),
    });
    e.apply_changes(&src, 64)
        .expect_err("the reply never comes");
    let _ = fake.drain_events();
    assert!(e.api_ready(), "reconnects");
    e.apply_changes(&src, 64).expect("the retry applies");

    let dumps = fake
        .drain_events()
        .into_iter()
        .filter(|ev| matches!(ev, Event::Msg(m) if m == "ip_neighbor_dump"))
        .count();
    assert_eq!(
        dumps, 2,
        "both families must be asked about; a v4-only dump reads every v6 \
         adjacency as absent and re-adds it"
    );
}

/// An unacknowledged neighbour REMOVAL must not leave the ledger claiming
/// an adjacency VPP no longer has.
///
/// The dangerous direction, and the one a "don't retransmit adds" fix would
/// miss entirely. `send_neighbour` clears `neighbours_installed` only on an
/// acknowledgement, so a removal VPP applied but never confirmed leaves the
/// ledger asserting the adjacency is installed. The delta path's skip —
/// `neighbours_installed.get(..) != Some(&mac)` — then swallows the next
/// add of that exact MAC, permanently, and every route through it
/// black-holes with the counts clean. Worse than a redundant walk, and in
/// the same silent-hole family as the delta loss this PR fixes.
#[test]
fn an_unacknowledged_neighbour_removal_does_not_strand_the_ledger() {
    use packetframe_vpp_offload::engine::SourceChanges;

    let fake = silent_fake("neigh-unacked-remove");
    let mut e = silent_after_neighbour("neigh-unacked-remove", &fake);

    // VPP applies the removal and goes silent.
    let lost = QueuedSource::with(SourceChanges {
        neighbours: vec![(nh(), None)],
        routes: Vec::new(),
    });
    e.apply_changes(&lost, 64)
        .expect_err("the removal's reply never comes");
    let _ = fake.drain_events();

    // The nexthop comes back, with the very MAC the ledger still remembers.
    assert!(e.api_ready(), "reconnects");
    let back = QueuedSource::with(SourceChanges {
        neighbours: vec![(nh(), Some(("eth4".into(), MAC)))],
        routes: Vec::new(),
    });
    e.apply_changes(&back, 64).expect("the re-add applies");
    let readded = fake.drain_events();
    assert!(
        readded.iter().any(|ev| matches!(
            ev,
            Event::Neighbour { mac, is_add: true, .. } if *mac == MAC
        )),
        "VPP applied the removal, so the adjacency must be programmed again — \
         a ledger that still claims it makes this a silent blackhole: {readded:?}"
    );
}

/// The delta path consults the same acknowledged-neighbour ledger as
/// the resync path — pinned against the second door of the 5.5 s
/// adoption blackhole (shadow, 2026-08-08).
///
/// #146 taught `program_neighbours` to skip neighbours VPP already
/// holds, and the measured gap did not move: the deltas accumulated
/// during the resync deferral re-added the very neighbour the resync
/// walk had just left untouched, through `apply_changes` — a second
/// path to the same message. Both paths now consult one ledger,
/// written only on VPP's acknowledgement or from VPP's own dump.
#[test]
fn the_delta_path_does_not_re_add_an_acknowledged_neighbour() {
    use packetframe_vpp_offload::engine::SourceChanges;
    use std::sync::Mutex;

    const STATIC: u8 = 1;
    const MAC_NEW: [u8; 6] = [0x02, 0, 0, 0, 0, 0xee];

    /// A source whose deltas the test scripts per drain.
    struct ScriptedSource {
        changes: Mutex<Vec<SourceChanges>>,
    }
    impl RouteSource for ScriptedSource {
        fn requeue(&self, changes: SourceChanges) {
            // Back on the stack, so the next drain re-serves it — which
            // is what `RouteFeed` does, refilling its pending maps.
            self.changes.lock().unwrap().push(changes);
        }
        fn for_each_route(&self, _: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(nh(), "eth4", MAC);
        }
        fn drain_changes(&self, _max: usize) -> SourceChanges {
            self.changes.lock().unwrap().pop().unwrap_or_default()
        }
        fn route_count(&self) -> u64 {
            0
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }

    // VPP already holds the neighbour, correct and static.
    const EXISTING_NEIGHBOURS: &[([u8; 4], u32, [u8; 6], u8)] =
        &[([192, 0, 2, 1], ASSIGNED_INDEX, MAC, STATIC)];
    let fake = Fake::start_behaving(
        "delta-neigh",
        Behaviour {
            existing_neighbours: EXISTING_NEIGHBOURS,
            ..Default::default()
        },
    );
    let src = ScriptedSource {
        // Popped in reverse: first drain re-announces the identical
        // neighbour (the daemon-start re-learn), second changes its MAC.
        changes: Mutex::new(vec![
            SourceChanges {
                routes: Vec::new(),
                neighbours: vec![(nh(), Some(("eth4".into(), MAC_NEW)))],
            },
            SourceChanges {
                routes: Vec::new(),
                neighbours: vec![(nh(), Some(("eth4".into(), MAC)))],
            },
        ]),
    };
    let mut engine = engine_for(&fake);
    assert!(engine.api_ready(), "handshake");
    engine.attach_devices(AttachMode::Fresh).expect("attach");
    engine.begin_resync(&src);
    // Seeds the ledger from VPP's dump; sends nothing (kept=1).
    assert_eq!(engine.program_neighbours(&src).expect("programming"), 0);
    let _ = fake.drain_events();

    // Delta 1: identical re-announcement — the ledger must absorb it.
    engine.apply_changes(&src, 64).expect("identical delta");
    let sent: Vec<_> = fake
        .drain_events()
        .into_iter()
        .filter(|e| matches!(e, Event::Neighbour { .. }))
        .collect();
    assert!(
        sent.is_empty(),
        "an identical re-announcement must not reach VPP — re-adding walks \
         every dependent route: {sent:?}"
    );

    // Delta 2: the MAC genuinely changed — that walk is the price of
    // correctness, and the send must happen.
    engine.apply_changes(&src, 64).expect("changed delta");
    let sent: Vec<[u8; 6]> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Neighbour { mac, .. } => Some(mac),
            _ => None,
        })
        .collect();
    assert_eq!(
        sent,
        vec![MAC_NEW],
        "a genuine MAC change must be programmed"
    );
}

/// The neighbour's adj-fib is never adopted — so never withdrawn.
///
/// VPP auto-creates a host route for each neighbour (192.0.2.1/32 via
/// the member port here), and it wears the self-installed signature
/// exactly: NORMAL path, owned interface, non-zero nexthop. Adopting it
/// handed it to the diff, the source never advertises it, and every
/// adoption withdrew the neighbour's own host route — cover churn on
/// the one adjacency the whole table resolves through, a ~1M-entry
/// dependent walk, and a constant ~5.5 s blackhole that survived both
/// neighbour-send fixes because no neighbour message was involved at
/// all (shadow, 2026-08-08). The tell is exact: a host route whose
/// prefix IS its own nexthop, which this module never installs.
#[test]
fn the_neighbours_adj_fib_is_never_adopted_or_withdrawn() {
    const EXISTING: &[([u8; 4], u8, u32, bool)] = &[
        // A route we really installed, still advertised.
        ([10, 0, 1, 0], 24, ASSIGNED_INDEX, true),
        // The neighbour's adj-fib: host route, prefix == its own nexthop.
        ([192, 0, 2, 1], 32, ASSIGNED_INDEX, true),
    ];
    let fake = Fake::start_behaving(
        "adopt-adjfib",
        Behaviour {
            existing_routes: EXISTING,
            ..Default::default()
        },
    );
    let mut engine = engine_for(&fake);
    assert!(engine.api_ready(), "handshake");
    engine.attach_devices(AttachMode::Fresh).expect("attach");

    let mirror = Mirror {
        routes: vec![v4(0, 1)],
    };
    let adopted = engine.adopt_vpp_fib().expect("readback");
    assert_eq!(
        adopted, 1,
        "the real route is adopted; the neighbour's adj-fib is VPP's, not ours"
    );

    let plan = engine.begin_resync(&mirror);
    assert_eq!(
        plan.withdrawals, 0,
        "nothing to withdraw — and above all not the host route covering the \
         adjacency every route in the table resolves through: {plan:?}"
    );

    while !engine.drain_batch().expect("drain").0 {}
    let deletes: Vec<[u8; 4]> = fake
        .drain_events()
        .into_iter()
        .filter_map(|e| match e {
            Event::Route(WireRoute {
                is_add: false,
                addr,
                ..
            }) => Some(addr),
            _ => None,
        })
        .collect();
    assert!(
        deletes.is_empty(),
        "no withdrawal may reach VPP, least of all the adj-fib: {deletes:?}"
    );
}

// ------------------------------------------------------------------
// B1: local delivery. A `local-route` produces three engine behaviours
// — an attached route onto the subif at attach, shadowing of the
// mirror's view inside the prefix (resync AND deltas), and bridge
// neighbours mirrored onto the subif index. Forwarding is w26's job on
// hardware; what these prove is that the right messages, and ONLY the
// right messages, reach the wire.

use fake_vpp::SUBIF_BASE;
use packetframe_vpp_offload::LocalRoute;

fn local_route() -> LocalRoute {
    LocalRoute {
        prefix: packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(23, 191, 200, 0),
            prefix_len: 24,
        },
        port: "eth4".into(),
        vlan: 1337,
        kernel_dev: "br1337".into(),
    }
}

/// A prefix inside the local-route's footprint.
fn svc(last: u8, len: u8) -> IpPrefix {
    IpPrefix::V4 {
        addr: [23, 191, 200, last],
        prefix_len: len,
    }
}

fn engine_with_local_route(fake: &Fake) -> ConvergenceEngine {
    ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            accept_macs: vec![],
            vlans: vec![1337],
        }],
        vec!["eth4".into()],
        1_000_000,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    )
    .with_local_routes(vec![local_route()])
}

/// The attached route goes out at attach, onto the SUBIF's index — a
/// path on the parent would transmit untagged and die on the trunk —
/// and the mirror's view inside the prefix never reaches the wire.
#[test]
fn a_local_route_installs_attached_and_shadows_the_mirror() {
    let fake = Fake::start("local-route");
    let mut e = engine_with_local_route(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");

    let at_attach: Vec<WireRoute> = fake
        .drain_events()
        .into_iter()
        .filter_map(|ev| match ev {
            Event::Route(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(
        at_attach.len(),
        1,
        "exactly the attached route: {at_attach:?}"
    );
    let r = &at_attach[0];
    assert!(r.is_add);
    assert_eq!((r.addr, r.len), ([23, 191, 200, 0], 24));
    assert_eq!(
        r.path_indices,
        vec![SUBIF_BASE],
        "the attached route must land on the subif, not the parent"
    );

    // The mirror carries the poisoned host route (bird's `unreachable`
    // /32, the reference primary's shape) plus three transit routes.
    let m = Mirror {
        routes: vec![svc(7, 32), v4(0, 0), v4(0, 1), v4(0, 2)],
    };
    let plan = e.begin_resync(&m);
    assert_eq!(plan.upserts, 3);
    assert_eq!(plan.shadowed, 1);
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 3);
    assert_eq!(e.shadowed_routes(), 1);
    let after: Vec<WireRoute> = fake
        .drain_events()
        .into_iter()
        .filter_map(|ev| match ev {
            Event::Route(r) => Some(r),
            _ => None,
        })
        .collect();
    assert!(
        after.iter().all(|r| r.addr != [23, 191, 200, 7]),
        "the shadowed host route must never reach the wire: {after:?}"
    );
}

/// Kernel neighbours on the backing bridge become static neighbours on
/// the subif — the mapping `local-route` registers is what turns the
/// device name the feed reports into the subif's own index.
#[test]
fn a_bridge_neighbour_mirrors_onto_the_subif() {
    struct BridgeNeigh;
    impl RouteSource for BridgeNeigh {
        fn for_each_route(&self, _visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(IpAddr::V4(Ipv4Addr::new(23, 191, 200, 7)), "br1337", MAC);
        }
        fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
            unreachable!("static source")
        }
        fn route_count(&self) -> u64 {
            0
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }

    let fake = Fake::start("bridge-neigh");
    let mut e = engine_with_local_route(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    e.begin_resync(&BridgeNeigh);
    e.program_neighbours(&BridgeNeigh).expect("neighbours");

    let neighbours: Vec<(u32, [u8; 6], bool)> = fake
        .drain_events()
        .into_iter()
        .filter_map(|ev| match ev {
            Event::Neighbour {
                sw_if_index,
                mac,
                is_add,
                ..
            } => Some((sw_if_index, mac, is_add)),
            _ => None,
        })
        .collect();
    assert!(
        neighbours
            .iter()
            .any(|&(idx, mac, add)| idx == SUBIF_BASE && mac == MAC && add),
        "the bridge host's neighbour must be programmed on the subif index: {neighbours:?}"
    );
}

/// The delta door shadows exactly like the resync door — w-series
/// history says every filter with two entrances eventually takes a
/// finding through the second one.
#[test]
fn the_delta_path_shadows_local_prefix_routes_too() {
    use std::cell::RefCell;
    struct Deltas(RefCell<Vec<packetframe_vpp_offload::engine::RouteChange>>);
    impl RouteSource for Deltas {
        fn for_each_route(&self, _visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, _visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {}
        fn drain_changes(&self, _max: usize) -> packetframe_vpp_offload::engine::SourceChanges {
            packetframe_vpp_offload::engine::SourceChanges {
                routes: self.0.borrow_mut().drain(..).collect(),
                neighbours: Vec::new(),
            }
        }
        fn requeue(&self, changes: packetframe_vpp_offload::engine::SourceChanges) {
            self.0.borrow_mut().extend(changes.routes);
        }
        fn route_count(&self) -> u64 {
            0
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }

    let fake = Fake::start("delta-shadow");
    let mut e = engine_with_local_route(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    fake.drain_events();

    let src = Deltas(RefCell::new(vec![
        (svc(9, 32), Some(vec![nh()])),
        (v4(1, 0), Some(vec![nh()])),
    ]));
    let n = e.apply_changes(&src, 100).expect("apply");
    assert_eq!(n, 2);
    assert_eq!(e.shadowed_routes(), 1, "the in-prefix delta is suppressed");
    assert_eq!(
        e.pending().len(),
        1,
        "only the transit route may reach the pending map"
    );

    // A withdrawal of the shadowed prefix leaves the count, not a
    // stale entry.
    src.0.borrow_mut().push((svc(9, 32), None));
    e.apply_changes(&src, 100).expect("apply withdraw");
    assert_eq!(e.shadowed_routes(), 0);
}

/// A stale install INSIDE the local prefix — a pre-local-route run's
/// leftover, arriving via adoption — is withdrawn by the resync diff:
/// shadowed prefixes are deliberately absent from `seen`, so the
/// ledger-driven withdrawal loop is what cleans VPP.
#[test]
fn a_stale_install_inside_the_local_prefix_is_withdrawn() {
    let fake = Fake::start_behaving(
        "stale-shadowed",
        Behaviour {
            existing_routes: &[([23, 191, 200, 7], 32, ASSIGNED_INDEX, true)],
            ..Default::default()
        },
    );
    let mut e = engine_with_local_route(&fake);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let adopted = e.adopt_vpp_fib().expect("adopt");
    assert_eq!(adopted, 1, "the stale route looks self-installed");

    // The mirror still carries it (bird does not stop advertising just
    // because we started shadowing) — and it must STILL be withdrawn.
    let m = Mirror {
        routes: vec![svc(7, 32)],
    };
    let plan = e.begin_resync(&m);
    assert_eq!(plan.shadowed, 1);
    assert_eq!(plan.withdrawals, 1);
    drain_to_empty(&mut e);
    let deletes: Vec<WireRoute> = fake
        .drain_events()
        .into_iter()
        .filter_map(|ev| match ev {
            Event::Route(r) if !r.is_add => Some(r),
            _ => None,
        })
        .collect();
    assert!(
        deletes.iter().any(|r| r.addr == [23, 191, 200, 7]),
        "the stale in-prefix install must be withdrawn from VPP: {deletes:?}"
    );
}

/// The null-drop sample end to end: `cli_inband` over the real socket,
/// VPP's text parsed, the total cached — and absent again once the
/// process the counters lived in is gone.
#[test]
fn null_drops_sample_over_cli_inband() {
    let fake = Fake::start_behaving(
        "null-drops",
        Behaviour {
            show_errors: "   Count            Node            Reason        Severity\n\
                          117015         null-node       blackholed packets   error\n\
                          52755       ethernet-input     unknown vlan         error\n",
            ..Default::default()
        },
    );
    let mut e = engine_for(&fake);
    assert!(e.api_ready());
    assert_eq!(e.null_drops(), None, "absent until sampled");
    e.sample_null_drops();
    assert_eq!(e.null_drops(), Some(117_015));
    e.on_process_gone();
    assert_eq!(
        e.null_drops(),
        None,
        "the counters died with the process; a stale total would read as quiet"
    );
}
