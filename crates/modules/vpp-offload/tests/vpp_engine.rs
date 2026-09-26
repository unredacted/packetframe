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
            mtu: None,
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
            mtu: None,
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

use fake_vpp::{BVI_BASE, SUBIF_BASE};
use packetframe_vpp_offload::topology::{BridgeL3, DevKind, FdbSnapshot, PortVlans, Topology};
use packetframe_vpp_offload::LocalRoute;

/// A kernel view for the bridge tests: fixed device shapes, bridge
/// membership and L3 MACs, and an FDB and bridge-port VLAN table the test
/// can change under the engine.
struct Kernel {
    kinds: Vec<(&'static str, DevKind)>,
    /// `Err` = the FDB read fails, as a wedged netlink would.
    fdb: std::sync::Arc<std::sync::Mutex<Result<FdbSnapshot, String>>>,
    vlans: std::sync::Arc<std::sync::Mutex<PortVlans>>,
    /// `(port, bridge)` enslavement.
    masters: Vec<(&'static str, &'static str)>,
    /// `(bridge, vid, mac)`: the router has an L3 device on that VLAN.
    l3: Vec<(&'static str, u16, [u8; 6])>,
}

impl Topology for Kernel {
    fn classify(&self, dev: &str) -> Result<Option<DevKind>, String> {
        Ok(Some(
            self.kinds
                .iter()
                .find(|(d, _)| *d == dev)
                .map_or(DevKind::Plain, |(_, k)| k.clone()),
        ))
    }
    fn fdb(&self) -> Result<FdbSnapshot, String> {
        self.fdb.lock().unwrap().clone()
    }
    fn port_vlans(&self) -> Result<PortVlans, String> {
        Ok(self.vlans.lock().unwrap().clone())
    }
    fn master_of(&self, port: &str) -> Option<String> {
        self.masters
            .iter()
            .find(|(p, _)| *p == port)
            .map(|(_, b)| b.to_string())
    }
    fn bridge_l3(&self, bridge: &str, vid: u16) -> Option<BridgeL3> {
        self.l3
            .iter()
            .find(|(b, v, _)| *b == bridge && *v == vid)
            .map(|(_, _, mac)| BridgeL3 {
                mac: *mac,
                mtu: None,
            })
    }
}

/// The kernel bridge's MAC: what a BVI must send from.
const BRIDGE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0xb0, 0x01];

fn bridge_vlan(vid: u16) -> DevKind {
    DevKind::BridgeVlan {
        bridge: "switch0".into(),
        vid,
    }
}

fn fdb_with(entries: &[(u16, [u8; 6], &str)]) -> FdbSnapshot {
    FdbSnapshot::from_learned(
        entries
            .iter()
            .map(|(vid, mac, port)| ("switch0".to_string(), *vid, *mac, port.to_string())),
    )
}

fn local_route() -> LocalRoute {
    LocalRoute {
        prefix: packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(203, 0, 113, 0),
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
        addr: [203, 0, 113, last],
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
            mtu: None,
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
    .with_topology(Box::new(Kernel {
        kinds: vec![("br1337", bridge_vlan(1337))],
        fdb: std::sync::Arc::new(std::sync::Mutex::new(Ok(fdb_with(&[(1337, MAC, "eth4")])))),
        vlans: Default::default(),
        masters: vec![("eth4", "switch0")],
        l3: vec![("switch0", 1337, BRIDGE_MAC)],
    }))
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

    let events = fake.drain_events();
    // The bridged VLAN's domain: BVI from the kernel bridge's MAC, the
    // trunk subif a split-horizon member with its tag popped.
    let msgs: Vec<String> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Msg(m) => Some(m.clone()),
            _ => None,
        })
        .collect();
    for want in [
        "bd add=true id=1337 learn=false uu_flood=true".to_string(),
        format!("bvi loop1337 mac=02:00:00:00:b0:01 if={BVI_BASE}"),
        format!("l2 bridge if={BVI_BASE} bd=1337 type=1 shg=0"),
        format!("l2 bridge if={SUBIF_BASE} bd=1337 type=0 shg=1"),
        format!("vtr if={SUBIF_BASE} op=3"),
    ] {
        assert!(msgs.contains(&want), "missing `{want}`: {msgs:?}");
    }
    let at_attach: Vec<WireRoute> = events
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
    assert_eq!((r.addr, r.len), ([203, 0, 113, 0], 24));
    assert_eq!(
        r.path_indices,
        vec![BVI_BASE],
        "the attached route lands on the BVI — hosts behind either trunk, the bridge's MAC"
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
        after.iter().all(|r| r.addr != [203, 0, 113, 7]),
        "the shadowed host route must never reach the wire: {after:?}"
    );
}

/// Kernel neighbours on the backing bridge become static neighbours on
/// the subif of the port the FDB places them behind — that is what
/// turns the device name the feed reports into a subif's own index.
#[test]
fn a_bridge_neighbour_mirrors_onto_the_subif() {
    struct BridgeNeigh;
    impl RouteSource for BridgeNeigh {
        fn for_each_route(&self, _visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), "br1337", MAC);
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

    let events = fake.drain_events();
    let neighbours: Vec<(u32, [u8; 6], bool)> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Neighbour {
                sw_if_index,
                mac,
                is_add,
                ..
            } => Some((*sw_if_index, *mac, *is_add)),
            _ => None,
        })
        .collect();
    assert!(
        neighbours
            .iter()
            .any(|&(idx, mac, add)| idx == BVI_BASE && mac == MAC && add),
        "the bridge host's neighbour is programmed on the BVI: {neighbours:?}"
    );
    assert!(
        neighbours.iter().all(|&(idx, _, _)| idx != SUBIF_BASE),
        "never on the subif, which would send from the port's MAC: {neighbours:?}"
    );
    // Placement is the L2FIB entry: the host's MAC behind eth4's subif.
    assert!(
        events.iter().any(|ev| matches!(ev, Event::Msg(m)
            if *m == format!("l2fib add bd=1337 mac=01 if={SUBIF_BASE} static=true"))),
        "{events:?}"
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
            existing_routes: &[([203, 0, 113, 7], 32, ASSIGNED_INDEX, true)],
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
        deletes.iter().any(|r| r.addr == [203, 0, 113, 7]),
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

/// B3 v2 through a BVI: an IX peer's neighbour and routes sit on the
/// bridged VLAN's BVI (frames leave from the bridge's MAC), and the trunk
/// it is behind is an L2FIB entry. When spanning tree moves it, only that
/// entry moves — no neighbour change, no route re-programming. A peer the
/// FDB never saw still resolves and floods, as the kernel bridge would.
#[test]
fn a_bridge_neighbour_follows_the_fdb_between_trunk_ports() {
    use std::cell::RefCell;
    const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 0x55];
    const GHOST: [u8; 6] = [0x02, 0, 0, 0, 0, 0x66];

    struct Ix {
        requeued: RefCell<Vec<IpAddr>>,
    }
    impl RouteSource for Ix {
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            visit(
                IpPrefix::V4 {
                    addr: [203, 0, 113, 0],
                    prefix_len: 24,
                },
                &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))],
            );
            visit(
                IpPrefix::V4 {
                    addr: [203, 0, 113, 128],
                    prefix_len: 25,
                },
                &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 6))],
            );
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)), "br3998", PEER);
            // Known to the resolver, never seen by the bridge.
            visit(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 6)), "br3998", GHOST);
        }
        fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
            unreachable!("static source")
        }
        fn requeue_via(&self, nexthops: &[IpAddr]) {
            self.requeued.borrow_mut().extend_from_slice(nexthops);
        }
        fn route_count(&self) -> u64 {
            2
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }

    let trunk = |port: &str, n: u8| PortAttach {
        port: port.into(),
        pci_addr: format!("0002:07:00.{n}"),
        port_id: 0,
        num_rx_queues: 1,
        pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, n],
        accept_macs: vec![],
        mtu: None,
        vlans: vec![3998],
    };
    let fdb = std::sync::Arc::new(std::sync::Mutex::new(Ok(fdb_with(&[(3998, PEER, "eth5")]))));
    let fake = Fake::start("placement");
    let mut e = ConvergenceEngine::new(
        &fake.path,
        vec![trunk("eth4", 1), trunk("eth5", 2)],
        vec!["eth4".into(), "eth5".into()],
        1_000_000,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    )
    .with_topology(Box::new(Kernel {
        kinds: vec![("br3998", bridge_vlan(3998))],
        fdb: fdb.clone(),
        vlans: Default::default(),
        masters: vec![("eth4", "switch0"), ("eth5", "switch0")],
        l3: vec![("switch0", 3998, BRIDGE_MAC)],
    }));
    // Subifs are created in port order: eth4.3998, then eth5.3998.
    let (eth4_sub, eth5_sub) = (SUBIF_BASE, SUBIF_BASE + 1);
    let src = Ix {
        requeued: RefCell::new(Vec::new()),
    };
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let msgs = |events: &[Event]| -> Vec<String> {
        events
            .iter()
            .filter_map(|ev| match ev {
                Event::Msg(m) => Some(m.clone()),
                _ => None,
            })
            .collect()
    };
    let attach = msgs(&fake.drain_events());
    for sub in [eth4_sub, eth5_sub] {
        assert!(
            attach.contains(&format!("l2 bridge if={sub} bd=3998 type=0 shg=1")),
            "both trunks are split-horizon members: {attach:?}"
        );
    }
    e.begin_resync(&src);
    e.program_neighbours(&src).expect("neighbours");
    drain_to_empty(&mut e);

    let events = fake.drain_events();
    let neighbours: Vec<u32> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Neighbour { sw_if_index, .. } => Some(*sw_if_index),
            _ => None,
        })
        .collect();
    assert!(
        !neighbours.is_empty() && neighbours.iter().all(|i| *i == BVI_BASE),
        "every bridged neighbour on the BVI: {neighbours:?}"
    );
    let routes: Vec<WireRoute> = events
        .iter()
        .filter_map(|ev| match ev {
            Event::Route(r) => Some(r.clone()),
            _ => None,
        })
        .collect();
    assert!(
        routes.iter().all(|r| r.path_indices == vec![BVI_BASE]),
        "{routes:?}"
    );
    assert_eq!(
        e.counts().unresolvable,
        0,
        "the unplaced ghost floods, it does not drop"
    );
    let m = msgs(&events);
    assert!(
        m.contains(&format!(
            "l2fib add bd=3998 mac=55 if={eth5_sub} static=true"
        )),
        "the placed peer pinned behind eth5: {m:?}"
    );
    assert!(
        !m.iter().any(|x| x.contains("mac=66")),
        "no entry for the ghost: it floods to both trunks: {m:?}"
    );
    assert!(e.unplaced_neighbours().is_empty());
    assert_eq!(e.flooding_neighbours(), 1);

    // Spanning tree moves the peer behind eth4: the L2FIB entry moves,
    // and that is all.
    *fdb.lock().unwrap() = Ok(fdb_with(&[(3998, PEER, "eth4")]));
    e.refresh_placement(&src).expect("refresh");
    let events = fake.drain_events();
    assert!(
        events
            .iter()
            .all(|ev| !matches!(ev, Event::Neighbour { .. })),
        "no neighbour change: {events:?}"
    );
    assert!(
        msgs(&events).contains(&format!(
            "l2fib add bd=3998 mac=55 if={eth4_sub} static=true"
        )),
        "{events:?}"
    );
    assert!(src.requeued.borrow().is_empty(), "no route re-programming");
    assert_eq!(e.placement_moves(), 1);

    // The ghost speaks up behind eth5: pinned, no longer flooding.
    *fdb.lock().unwrap() = Ok(fdb_with(&[(3998, PEER, "eth4"), (3998, GHOST, "eth5")]));
    e.refresh_placement(&src).expect("refresh");
    assert!(msgs(&fake.drain_events()).contains(&format!(
        "l2fib add bd=3998 mac=66 if={eth5_sub} static=true"
    )));
    assert_eq!(e.flooding_neighbours(), 0);

    // Entries age out of the FDB: last known ports stand, nothing sent.
    *fdb.lock().unwrap() = Ok(fdb_with(&[]));
    e.refresh_placement(&src).expect("refresh");
    assert!(msgs(&fake.drain_events())
        .iter()
        .all(|m| !m.starts_with("l2fib")));

    // A failing read is surfaced, and the placements hold.
    *fdb.lock().unwrap() = Err("netlink recv: timed out".into());
    e.refresh_placement(&src).expect("refresh");
    assert_eq!(
        e.fdb_unreadable().as_deref(),
        Some("netlink recv: timed out")
    );
    *fdb.lock().unwrap() = Ok(fdb_with(&[(3998, PEER, "eth4")]));
    e.refresh_placement(&src).expect("refresh");
    assert_eq!(e.fdb_unreadable(), None, "cleared by the next good read");
}

/// Trunk mode: a `vlans all` port gains a subif when the kernel bridge
/// starts carrying a VLAN, with no restart — and a neighbour already
/// placed behind it on that VLAN, unreachable until then, is programmed
/// and its routes re-queued.
#[test]
fn a_trunk_follows_a_vlan_added_on_the_switch() {
    use std::cell::RefCell;
    const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 0x77];
    let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    struct Src {
        requeued: RefCell<Vec<IpAddr>>,
    }
    impl RouteSource for Src {
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            visit(
                IpPrefix::V4 {
                    addr: [203, 0, 113, 0],
                    prefix_len: 24,
                },
                &[IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20))],
            );
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), "br200", PEER);
        }
        fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
            unreachable!("static source")
        }
        fn requeue_via(&self, nexthops: &[IpAddr]) {
            self.requeued.borrow_mut().extend_from_slice(nexthops);
        }
        fn route_count(&self) -> u64 {
            1
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }
    let vlans = std::sync::Arc::new(std::sync::Mutex::new(PortVlans::default()));
    let fake = Fake::start("trunk-vlan");
    let mut e = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            accept_macs: vec![],
            mtu: None,
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
    .with_trunk_ports(vec!["eth4".into()])
    .with_topology(Box::new(Kernel {
        kinds: vec![("br200", bridge_vlan(200))],
        fdb: std::sync::Arc::new(std::sync::Mutex::new(Ok(fdb_with(&[(200, PEER, "eth4")])))),
        vlans: vlans.clone(),
        masters: vec![("eth4", "switch0")],
        l3: vec![("switch0", 200, BRIDGE_MAC)],
    }));
    let src = Src {
        requeued: RefCell::new(Vec::new()),
    };
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    e.begin_resync(&src);
    e.program_neighbours(&src).expect("neighbours");
    drain_to_empty(&mut e);
    assert_eq!(e.counts().unresolvable, 1, "no subif for vlan 200 yet");
    assert_eq!(
        e.unplaced_neighbours(),
        vec![(peer, "br200".to_string(), Some("eth4".to_string()))]
    );
    let _ = fake.drain_events();

    // The switch starts carrying VLAN 200 on the trunk.
    *vlans.lock().unwrap() = PortVlans::from_entries([("eth4".to_string(), 200, false)]);
    assert_eq!(e.refresh_placement(&src).expect("refresh"), 1);
    let events = fake.drain_events();
    assert!(
        events
            .iter()
            .any(|ev| matches!(ev, Event::Msg(m) if m.starts_with("create_vlan_subif vlan=200"))),
        "the subif is created while running: {events:?}"
    );
    assert!(
        events.iter().any(|ev| matches!(ev, Event::Msg(m)
            if *m == format!("l2 bridge if={SUBIF_BASE} bd=200 type=0 shg=1"))),
        "the new subif joins the VLAN's new bridge domain: {events:?}"
    );
    assert!(
        events.iter().any(
            |ev| matches!(ev, Event::Neighbour { sw_if_index, is_add: true, .. }
            if *sw_if_index == BVI_BASE)
        ),
        "and the neighbour is programmed on its BVI: {events:?}"
    );
    assert_eq!(*src.requeued.borrow(), vec![peer]);
    assert!(e.unplaced_neighbours().is_empty());

    // Nothing new on the next pass: no second subif, nothing re-queued.
    src.requeued.borrow_mut().clear();
    assert_eq!(e.refresh_placement(&src).expect("refresh"), 0);
    assert!(fake
        .drain_events()
        .iter()
        .all(|ev| !matches!(ev, Event::Msg(m) if m.starts_with("create_vlan_subif"))));
}

/// A neighbour on the port's UNTAGGED VLAN (br0 over switch0.1 on a UniFi
/// box) is programmed on the VF itself, not on a tagged subif.
#[test]
fn an_untagged_vlan_neighbour_lands_on_the_vf() {
    const HOST: [u8; 6] = [0x02, 0, 0, 0, 0, 0x88];
    struct Src;
    impl RouteSource for Src {
        fn for_each_route(&self, _visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), "br0", HOST);
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
    let fake = Fake::start("untagged");
    let mut e = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            accept_macs: vec![],
            mtu: None,
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
    .with_topology(Box::new(Kernel {
        kinds: vec![("br0", bridge_vlan(1))],
        fdb: std::sync::Arc::new(std::sync::Mutex::new(Ok(fdb_with(&[(1, HOST, "eth4")])))),
        vlans: std::sync::Arc::new(std::sync::Mutex::new(PortVlans::from_entries([(
            "eth4".to_string(),
            1,
            true,
        )]))),
        masters: vec![("eth4", "switch0")],
        l3: vec![],
    }));
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    e.begin_resync(&Src);
    e.program_neighbours(&Src).expect("neighbours");
    let events = fake.drain_events();
    assert!(
        events.iter().any(
            |ev| matches!(ev, Event::Neighbour { sw_if_index, mac, is_add: true, .. }
            if *sw_if_index == ASSIGNED_INDEX && *mac == HOST)
        ),
        "on the VF's own index, untagged: {events:?}"
    );
    assert!(e.unplaced_neighbours().is_empty());
}

/// A kernel whose only fact is a port MTU the test can change.
struct MtuKernel(std::sync::Arc<std::sync::Mutex<Option<u32>>>);

impl Topology for MtuKernel {
    fn classify(&self, _dev: &str) -> Result<Option<DevKind>, String> {
        Ok(Some(DevKind::Plain))
    }
    fn fdb(&self) -> Result<FdbSnapshot, String> {
        Ok(FdbSnapshot::default())
    }
    fn port_vlans(&self) -> Result<PortVlans, String> {
        Ok(PortVlans::default())
    }
    fn mtu(&self, _dev: &str) -> Option<u32> {
        *self.0.lock().unwrap()
    }
    fn master_of(&self, _port: &str) -> Option<String> {
        None
    }
    fn bridge_l3(&self, _bridge: &str, _vid: u16) -> Option<BridgeL3> {
        None
    }
}

/// Every attach sends the kernel's MTU as it is at that attach, not as
/// it was at bring-up: the supervisor re-attaches every VPP it restarts,
/// and an MTU changed in between must reach the new one (review
/// finding). An unreadable MTU keeps the last value.
#[test]
fn each_attach_sends_the_current_kernel_mtu() {
    let fake = Fake::start("mtu-refresh");
    let mtu = std::sync::Arc::new(std::sync::Mutex::new(Some(1500)));
    let mut e = engine_for(&fake)
        .with_topology(Box::new(MtuKernel(mtu.clone())))
        .with_recorded_indices(vec![("eth4".into(), 3)]);
    assert!(e.api_ready());
    let sent = |fake: &Fake| -> Vec<String> {
        fake.drain_events()
            .into_iter()
            .filter_map(|ev| match ev {
                Event::Msg(m) if m.starts_with("mtu ") => Some(m),
                _ => None,
            })
            .collect()
    };

    e.attach_devices(AttachMode::Fresh).expect("attach");
    assert_eq!(sent(&fake), vec!["mtu if=3 l3=1500".to_string()]);

    *mtu.lock().unwrap() = Some(9000);
    e.attach_devices(AttachMode::Adopted).expect("re-attach");
    assert_eq!(sent(&fake), vec!["mtu if=3 l3=9000".to_string()]);

    *mtu.lock().unwrap() = None;
    e.attach_devices(AttachMode::Adopted).expect("re-attach");
    assert_eq!(sent(&fake), vec!["mtu if=3 l3=9000".to_string()]);
}

/// An eth4 member engine for the untagged-VLAN tests, over `kernel`.
fn untagged_engine(fake: &Fake, kernel: Kernel) -> ConvergenceEngine {
    ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            accept_macs: vec![],
            mtu: None,
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
    .with_trunk_ports(vec!["eth4".into()])
    .with_topology(Box::new(kernel))
}

/// A VLAN that stops being untagged on the neighbour's port leaves it no
/// interface. Its routes are re-queued to go unresolvable, and its
/// adjacency on the VF is retired once they have — not left forwarding
/// onto a VLAN the port no longer sends bare (review finding).
#[test]
fn a_neighbour_whose_untagged_vlan_goes_is_retired() {
    use std::cell::RefCell;
    const HOST: [u8; 6] = [0x02, 0, 0, 0, 0, 0x88];
    let host = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    struct Src {
        requeued: RefCell<Vec<IpAddr>>,
    }
    impl RouteSource for Src {
        fn for_each_route(&self, _visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), "br0", HOST);
        }
        fn requeue(&self, _: packetframe_vpp_offload::engine::SourceChanges) {
            unreachable!("static source")
        }
        fn requeue_via(&self, nexthops: &[IpAddr]) {
            self.requeued.borrow_mut().extend_from_slice(nexthops);
        }
        fn route_count(&self) -> u64 {
            0
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }
    let vlans = std::sync::Arc::new(std::sync::Mutex::new(PortVlans::from_entries([(
        "eth4".to_string(),
        1,
        true,
    )])));
    let fake = Fake::start("untagged-gone");
    let mut e = untagged_engine(
        &fake,
        Kernel {
            kinds: vec![("br0", bridge_vlan(1))],
            fdb: std::sync::Arc::new(std::sync::Mutex::new(Ok(fdb_with(&[(1, HOST, "eth4")])))),
            vlans: vlans.clone(),
            masters: vec![("eth4", "switch0")],
            l3: vec![],
        },
    );
    let src = Src {
        requeued: RefCell::new(Vec::new()),
    };
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    e.begin_resync(&src);
    e.program_neighbours(&src).expect("neighbours");
    let _ = fake.drain_events();

    // VLAN 1 leaves eth4 altogether; the FDB entry ages out with it.
    *vlans.lock().unwrap() = PortVlans::default();
    assert_eq!(e.refresh_placement(&src).expect("refresh"), 1);
    assert_eq!(*src.requeued.borrow(), vec![host]);
    // Once, not on every pass.
    src.requeued.borrow_mut().clear();
    assert_eq!(e.refresh_placement(&src).expect("refresh"), 0);

    e.settle_moves().expect("settle");
    let events = fake.drain_events();
    assert!(
        events.iter().any(
            |ev| matches!(ev, Event::Neighbour { sw_if_index, is_add: false, .. }
            if *sw_if_index == ASSIGNED_INDEX)
        ),
        "the VF adjacency is retired: {events:?}"
    );
}

/// A `local-route` on a trunk's untagged VLAN lands on the VF: the
/// bridge sends that VLAN bare, so there is no subif to put it on, and
/// attach must not fail looking for one (review finding).
#[test]
fn a_local_route_on_an_untagged_vlan_lands_on_the_vf() {
    const HOST: [u8; 6] = [0x02, 0, 0, 0, 0, 0x88];
    let fake = Fake::start("untagged-local-route");
    let mut e = untagged_engine(
        &fake,
        Kernel {
            kinds: vec![("br0", bridge_vlan(1))],
            fdb: std::sync::Arc::new(std::sync::Mutex::new(Ok(fdb_with(&[(1, HOST, "eth4")])))),
            vlans: std::sync::Arc::new(std::sync::Mutex::new(PortVlans::from_entries([(
                "eth4".to_string(),
                1,
                true,
            )]))),
            masters: vec![("eth4", "switch0")],
            l3: vec![],
        },
    )
    .with_local_routes(vec![LocalRoute {
        prefix: packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(192, 0, 2, 0),
            prefix_len: 24,
        },
        port: "eth4".into(),
        vlan: 1,
        kernel_dev: "br0".into(),
    }]);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let routes: Vec<WireRoute> = fake
        .drain_events()
        .into_iter()
        .filter_map(|ev| match ev {
            Event::Route(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(routes.len(), 1, "{routes:?}");
    assert_eq!((routes[0].addr, routes[0].len), ([192, 0, 2, 0], 24));
    assert_eq!(routes[0].path_indices, vec![ASSIGNED_INDEX]);
}

/// A kernel whose FDB reads but whose port-VLAN table does not.
struct VlansFailKernel;

impl Topology for VlansFailKernel {
    fn classify(&self, _dev: &str) -> Result<Option<DevKind>, String> {
        Ok(Some(DevKind::Plain))
    }
    fn fdb(&self) -> Result<FdbSnapshot, String> {
        Ok(FdbSnapshot::default())
    }
    fn port_vlans(&self) -> Result<PortVlans, String> {
        Err("netlink recv: timed out".into())
    }
    fn master_of(&self, _port: &str) -> Option<String> {
        None
    }
    fn bridge_l3(&self, _bridge: &str, _vid: u16) -> Option<BridgeL3> {
        None
    }
}

/// The two tables are read separately, so a good FDB read must not hide
/// an unreadable VLAN table: `vlans all` stops following the switch
/// while it lasts, and health has to say so (review finding).
#[test]
fn an_unreadable_vlan_table_is_reported_despite_a_good_fdb() {
    let fake = Fake::start("vlans-fail");
    let mut e = engine_for(&fake).with_topology(Box::new(VlansFailKernel));
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    e.refresh_placement(&Mirror { routes: vec![] })
        .expect("refresh");
    assert_eq!(
        e.fdb_unreadable().as_deref(),
        Some("port VLANs: netlink recv: timed out")
    );
}

fn msgs_of(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .filter_map(|ev| match ev {
            Event::Msg(m) => Some(m.clone()),
            _ => None,
        })
        .collect()
}

/// A source with one fixed bridged neighbour and no routes.
struct OneNeighbour {
    nh: IpAddr,
    dev: &'static str,
    mac: [u8; 6],
}

impl RouteSource for OneNeighbour {
    fn for_each_route(&self, _visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(self.nh, self.dev, self.mac);
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

/// A bridged VLAN a port sends UNTAGGED joins the domain with the VF
/// itself, bare — so a neighbour behind that port is pinned to the VF and
/// its frames still leave from the bridge's MAC through the BVI (review
/// finding: routed on the VF, they would leave from the port's). The VF
/// counts as the egress in use for the link gate. When the VLAN stops
/// being untagged there, the VF leaves the domain rather than flooding
/// the VLAN bare onto whatever the port's untagged VLAN is now, and the
/// pin goes with it — retried when VPP refuses the delete, not forgotten.
#[test]
fn an_untagged_port_is_a_bare_member_of_the_bridge_domain() {
    const HOST: [u8; 6] = [0x02, 0, 0, 0, 0, 0x88];
    let vlans = std::sync::Arc::new(std::sync::Mutex::new(PortVlans::from_entries([(
        "eth4".to_string(),
        1,
        true,
    )])));
    let fake = Fake::start_behaving(
        "untagged-member",
        Behaviour {
            reject_l2fib_deletes: 1,
            ..Default::default()
        },
    );
    let mut e = untagged_engine(
        &fake,
        Kernel {
            kinds: vec![("br0", bridge_vlan(1))],
            fdb: std::sync::Arc::new(std::sync::Mutex::new(Ok(fdb_with(&[(1, HOST, "eth4")])))),
            vlans: vlans.clone(),
            masters: vec![("eth4", "switch0")],
            l3: vec![("switch0", 1, BRIDGE_MAC)],
        },
    );
    let src = OneNeighbour {
        nh: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)),
        dev: "br0",
        mac: HOST,
    };
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let attach = msgs_of(&fake.drain_events());
    assert!(
        attach.contains(&format!("l2 bridge if={ASSIGNED_INDEX} bd=1 type=0 shg=1")),
        "the VF joins bare: {attach:?}"
    );
    assert!(
        !attach
            .iter()
            .any(|m| m.starts_with(&format!("vtr if={ASSIGNED_INDEX} "))),
        "no tag to pop on an untagged member: {attach:?}"
    );

    e.begin_resync(&src);
    e.program_neighbours(&src).expect("neighbours");
    let events = fake.drain_events();
    assert!(
        events.iter().any(
            |ev| matches!(ev, Event::Neighbour { sw_if_index, is_add: true, .. }
            if *sw_if_index == BVI_BASE)
        ),
        "the neighbour sits on the BVI: {events:?}"
    );
    let m = msgs_of(&events);
    assert!(
        m.contains(&format!(
            "l2fib add bd=1 mac=88 if={ASSIGNED_INDEX} static=true"
        )),
        "pinned to the VF: {m:?}"
    );
    assert!(e.port_links()[0].in_use, "the VF is the egress in use");

    // VLAN 1 stops being untagged on eth4.
    *vlans.lock().unwrap() = PortVlans::default();
    e.refresh_placement(&src)
        .expect_err("VPP refuses the pin's delete");
    let m = msgs_of(&fake.drain_events());
    assert!(
        m.contains(&format!("l2 leave if={ASSIGNED_INDEX} bd=1")),
        "the VF leaves the domain: {m:?}"
    );
    e.refresh_placement(&src).expect("retry");
    let m = msgs_of(&fake.drain_events());
    assert!(
        m.contains(&format!(
            "l2fib del bd=1 mac=88 if={ASSIGNED_INDEX} static=true"
        )),
        "the refused delete is retried: {m:?}"
    );
    e.refresh_placement(&src).expect("settled");
    assert!(
        !msgs_of(&fake.drain_events())
            .iter()
            .any(|m| m.starts_with("l2")),
        "nothing more once settled"
    );
}

/// A surviving VPP's bridge domain can hold members and static MACs a
/// previous daemon left. Adoption takes out the members this view does
/// not want, and the resync withdraws the static entries its books do
/// not hold — nothing else would ever remove them (review finding).
#[test]
fn a_surviving_domains_strays_are_withdrawn() {
    const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 0x55];
    const STALE: [u8; 6] = [0x02, 0, 0, 0, 0, 0xab];
    let fake = Fake::start_behaving(
        "bd-strays",
        Behaviour {
            existing_l2fib: &[(3998, PEER, SUBIF_BASE), (3998, STALE, SUBIF_BASE)],
            existing_bd_members: &[(3998, SUBIF_BASE), (3998, 999)],
            ..Default::default()
        },
    );
    let mut e = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            accept_macs: vec![],
            mtu: None,
            vlans: vec![3998],
        }],
        vec!["eth4".into()],
        1_000_000,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    )
    .with_topology(Box::new(Kernel {
        kinds: vec![("br3998", bridge_vlan(3998))],
        fdb: std::sync::Arc::new(std::sync::Mutex::new(Ok(fdb_with(&[(3998, PEER, "eth4")])))),
        vlans: Default::default(),
        masters: vec![("eth4", "switch0")],
        l3: vec![("switch0", 3998, BRIDGE_MAC)],
    }));
    let src = OneNeighbour {
        nh: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)),
        dev: "br3998",
        mac: PEER,
    };
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let m = msgs_of(&fake.drain_events());
    assert!(m.contains(&"l2 leave if=999 bd=3998".to_string()), "{m:?}");
    assert!(
        !m.contains(&format!("l2 leave if={SUBIF_BASE} bd=3998")),
        "a wanted member stays: {m:?}"
    );

    e.begin_resync(&src);
    e.program_neighbours(&src).expect("neighbours");
    let m = msgs_of(&fake.drain_events());
    assert!(
        m.contains(&format!(
            "l2fib del bd=3998 mac=ab if={SUBIF_BASE} static=true"
        )),
        "the stale MAC is withdrawn: {m:?}"
    );
    assert!(
        !m.iter()
            .any(|x| x.starts_with("l2fib del") && x.contains("mac=55")),
        "the peer's pin is ours and stays: {m:?}"
    );
}

/// A neighbour delta that moves a nexthop onto another bridged VLAN is
/// pinned in the new domain only by a placement on THAT VLAN. Before the
/// device map moved, the old VLAN's port was used, pinning the MAC in the
/// new domain where the FDB had never seen it (review finding).
#[test]
fn a_neighbour_moved_between_vlans_floods_until_placed_there() {
    const PEER: [u8; 6] = [0x02, 0, 0, 0, 0, 0x55];
    let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5));
    let fake = Fake::start("vlan-move");
    let mut e = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            accept_macs: vec![],
            mtu: None,
            vlans: vec![3998, 3999],
        }],
        vec!["eth4".into()],
        1_000_000,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
            prefix_len: 32,
        },
    )
    .with_topology(Box::new(Kernel {
        kinds: vec![("br3998", bridge_vlan(3998)), ("br3999", bridge_vlan(3999))],
        fdb: std::sync::Arc::new(std::sync::Mutex::new(Ok(fdb_with(&[(3998, PEER, "eth4")])))),
        vlans: Default::default(),
        masters: vec![("eth4", "switch0")],
        l3: vec![("switch0", 3998, BRIDGE_MAC), ("switch0", 3999, BRIDGE_MAC)],
    }));
    let src = OneNeighbour {
        nh: peer,
        dev: "br3998",
        mac: PEER,
    };
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    e.begin_resync(&src);
    e.program_neighbours(&src).expect("neighbours");
    assert!(msgs_of(&fake.drain_events()).contains(&format!(
        "l2fib add bd=3998 mac=55 if={SUBIF_BASE} static=true"
    )));

    let moved = QueuedSource::with(packetframe_vpp_offload::engine::SourceChanges {
        neighbours: vec![(peer, Some(("br3999".into(), PEER)))],
        routes: Vec::new(),
    });
    e.apply_changes(&moved, 64).expect("delta");
    let m = msgs_of(&fake.drain_events());
    assert!(
        !m.iter().any(|x| x.starts_with("l2fib add bd=3999")),
        "not pinned where the FDB has never seen it: {m:?}"
    );
    assert!(
        m.contains(&format!(
            "l2fib del bd=3998 mac=55 if={SUBIF_BASE} static=true"
        )),
        "the old domain's pin goes: {m:?}"
    );
}

/// A surviving VPP's BVI whose MAC is no longer the kernel bridge's is
/// re-asserted — and read back — rather than reused as it stands: the
/// whole point of the BVI is the bridge's MAC on the wire (review
/// finding). One already right is left alone.
#[test]
fn an_adopted_bvi_takes_the_bridges_current_mac() {
    const OLD: [u8; 6] = [0x02, 0, 0, 0, 0xb0, 0x99];
    for (tag, held, expect_set) in [
        ("bvi-stale-mac", OLD, true),
        ("bvi-same-mac", BRIDGE_MAC, false),
    ] {
        let fake = Fake::start_behaving(
            tag,
            Behaviour {
                existing_bvi: Some((3998, 250, held)),
                ..Default::default()
            },
        );
        let mut e = ConvergenceEngine::new(
            &fake.path,
            vec![PortAttach {
                port: "eth4".into(),
                pci_addr: "0002:07:00.1".into(),
                port_id: 0,
                num_rx_queues: 1,
                pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                accept_macs: vec![],
                mtu: None,
                vlans: vec![3998],
            }],
            vec!["eth4".into()],
            1_000_000,
            FamilyPolicy::V4Only,
            packetframe_common::config::Ipv4Prefix {
                addr: std::net::Ipv4Addr::new(198, 51, 100, 1),
                prefix_len: 32,
            },
        )
        .with_topology(Box::new(Kernel {
            kinds: vec![("br3998", bridge_vlan(3998))],
            fdb: std::sync::Arc::new(std::sync::Mutex::new(Ok(FdbSnapshot::default()))),
            vlans: Default::default(),
            masters: vec![("eth4", "switch0")],
            l3: vec![("switch0", 3998, BRIDGE_MAC)],
        }));
        assert!(e.api_ready());
        e.attach_devices(AttachMode::Fresh).expect("attach");
        let m = msgs_of(&fake.drain_events());
        assert!(
            !m.iter().any(|x| x.starts_with("bvi loop3998")),
            "{tag}: reused, not recreated: {m:?}"
        );
        let set = format!("set mac if=250 mac={:02x}", BRIDGE_MAC[5]);
        assert_eq!(m.contains(&set), expect_set, "{tag}: {m:?}");
    }
}

/// A source whose routes each carry their own next hops, and whose delta
/// batches the test queues by hand.
struct NexthopSource {
    routes: Vec<(IpPrefix, Vec<IpAddr>)>,
    queue: std::sync::Mutex<Vec<packetframe_vpp_offload::engine::SourceChanges>>,
}

impl RouteSource for NexthopSource {
    fn requeue(&self, changes: packetframe_vpp_offload::engine::SourceChanges) {
        self.queue.lock().unwrap().insert(0, changes);
    }
    fn drain_changes(&self, _max: usize) -> packetframe_vpp_offload::engine::SourceChanges {
        self.queue.lock().unwrap().pop().unwrap_or_default()
    }
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        for (p, nhs) in &self.routes {
            visit(*p, nhs);
        }
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(nh(), "eth4", MAC);
    }
    fn route_count(&self) -> u64 {
        self.routes.len() as u64
    }
    fn change_seq(&self) -> u64 {
        0
    }
}

fn pfx(a: [u8; 4], len: u8) -> packetframe_common::config::Ipv4Prefix {
    packetframe_common::config::Ipv4Prefix {
        addr: Ipv4Addr::from(a),
        prefix_len: len,
    }
}

/// A routing daemon feeding packetframe over iBGP sends what it
/// originates — `redistribute connected` — with its own session address
/// as NEXT_HOP. The kernel delivers those; VPP never has an adjacency for
/// its own host. A connected subnet stays out of VPP and out of the
/// unresolvable count, which otherwise blocks the first steer forever;
/// one that changes to or from the router as next hop moves in or out,
/// withdrawn on the way out.
///
/// A self next hop alone is not enough: under `next-hop-self` a transit
/// route carries it too, and must stay unresolvable rather than be
/// withdrawn from VPP. And a connected subnet with no covering
/// `steer-exempt` blocks the first steer, since steered traffic for it
/// would find no route in VPP.
#[test]
fn connected_subnets_via_the_router_itself_stay_out_of_vpp() {
    let own = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let fake = Fake::start("self-nexthop");
    let mut e =
        engine_for(&fake).with_self_networks([pfx([198, 51, 100, 1], 30), pfx([10, 66, 1, 1], 24)]);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let connected = v4(66, 1);
    let src = NexthopSource {
        routes: vec![
            (v4(0, 0), vec![nh()]),
            (connected, vec![own]),
            // Transit, rewritten by next-hop-self: not a connected subnet.
            (v4(77, 0), vec![own]),
        ],
        queue: Default::default(),
    };
    let plan = e.begin_resync(&src);
    assert_eq!((plan.upserts, plan.kernel_delivered), (2, 1), "{plan:?}");
    e.program_neighbours(&src).expect("neighbours");
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 1);
    assert_eq!(
        e.counts().unresolvable,
        1,
        "only the next-hop-self transit route is unresolvable; the connected subnet is not"
    );
    assert_eq!(e.kernel_delivered_routes(), 1);
    let installed: Vec<WireRoute> = fake
        .drain_events()
        .into_iter()
        .filter_map(|ev| match ev {
            Event::Route(r) if r.is_add => Some(r),
            _ => None,
        })
        .collect();
    assert!(
        installed
            .iter()
            .all(|r| (r.addr, r.len) != ([10, 66, 1, 0], 24)),
        "the connected subnet never reaches VPP: {installed:?}"
    );

    // The transit route withdrawn, so only the exemption gate is left.
    src.queue
        .lock()
        .unwrap()
        .push(packetframe_vpp_offload::engine::SourceChanges {
            neighbours: Vec::new(),
            routes: vec![(v4(77, 0), None)],
        });
    e.apply_changes(&src, 64).expect("delta");
    drain_to_empty(&mut e);
    assert_eq!(e.counts().unresolvable, 0);
    assert_eq!(e.counts().unexempted_local, 1);
    assert!(
        e.counts().blocks_first_steer(),
        "a connected subnet VPP lacks, with no steer-exempt, must block the first steer"
    );
    // A gateway /32 does not cover the subnet.
    e.set_steer_exempts(vec![pfx([10, 66, 1, 1], 32)]);
    assert!(e.counts().blocks_first_steer());
    e.set_steer_exempts(vec![pfx([10, 66, 1, 1], 32), pfx([10, 66, 0, 0], 16)]);
    assert_eq!(e.counts().unexempted_local, 0);
    assert!(!e.counts().blocks_first_steer(), "{:?}", e.counts());

    // The connected subnet learned through a real next hop: installed.
    src.queue
        .lock()
        .unwrap()
        .push(packetframe_vpp_offload::engine::SourceChanges {
            neighbours: Vec::new(),
            routes: vec![(connected, Some(vec![nh()]))],
        });
    e.apply_changes(&src, 64).expect("delta");
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 2);
    assert_eq!(e.kernel_delivered_routes(), 0);
    let _ = fake.drain_events();

    // And back via the router itself: withdrawn.
    src.queue
        .lock()
        .unwrap()
        .push(packetframe_vpp_offload::engine::SourceChanges {
            neighbours: Vec::new(),
            routes: vec![(connected, Some(vec![own]))],
        });
    e.apply_changes(&src, 64).expect("delta");
    drain_to_empty(&mut e);
    assert_eq!(e.counts().installed, 1);
    assert_eq!(e.kernel_delivered_routes(), 1);
    assert!(fake.drain_events().iter().any(
        |ev| matches!(ev, Event::Route(r) if !r.is_add && (r.addr, r.len) == ([10, 66, 1, 0], 24))
    ));
}

/// A reply that outruns the socket deadline — a starved VPP, as the
/// client sees it — surfaces from the attach as the API LOST, not as a
/// refusal; the socket that may still owe the late reply is gone; and
/// the same step, resumed over a fresh connection, completes.
///
/// A real `EAGAIN` from the real transport, not a classified string:
/// this is the leg the supervision tests fake. Steered, so the deadline
/// is the published 1.5 s and the stall costs this test that much.
#[test]
fn a_reply_that_outruns_the_socket_deadline_is_a_lost_api_and_the_attach_resumes() {
    let fake = Fake::start_behaving(
        "attach-stall",
        Behaviour {
            stall_on: Some(("dev_attach", 0)),
            ..Default::default()
        },
    );
    let mut e = engine_for(&fake);
    e.set_steered(true);
    assert!(e.api_ready(), "handshake");

    let err = e
        .attach_devices(AttachMode::Fresh)
        .expect_err("the reply never comes");
    assert!(
        err.api_lost(),
        "a socket deadline is the API lost, not VPP refusing: {err}"
    );
    assert!(err.to_string().contains("socket I/O"), "{err}");
    assert!(
        !e.is_connected(),
        "a socket that may still owe a late reply must not be reused"
    );

    assert!(e.api_ready(), "the reconnect");
    e.attach_devices(AttachMode::Fresh)
        .expect("the resumed attach completes");
    assert_eq!(
        e.attached_indices(),
        vec![("eth4".to_string(), ASSIGNED_INDEX)]
    );
}

/// The adoption dump is all or nothing across families.
///
/// Adopting as it went, a timeout on the v6 dump left the v4 half in the
/// ledger — and `adopt_vpp_fib` no-ops on a populated ledger, so the
/// resumed `StartResync` would read `0`, take it for an empty FIB and
/// run the diff at once: no deferral for a still-loading source, v4
/// withdrawn against it, v6 never adopted.
#[test]
fn an_adoption_dump_that_times_out_part_way_adopts_nothing() {
    const EXISTING: &[([u8; 4], u8, u32, bool)] = &[
        ([203, 0, 113, 0], 24, ASSIGNED_INDEX, true),
        ([198, 51, 100, 0], 24, ASSIGNED_INDEX, true),
    ];
    let fake = Fake::start_behaving(
        "adopt-stall",
        Behaviour {
            existing_routes: EXISTING,
            // The second dump: v6, after v4 has answered in full.
            stall_on: Some(("ip_route_dump", 1)),
            ..Default::default()
        },
    );
    let mut e = ConvergenceEngine::new(
        &fake.path,
        vec![PortAttach {
            port: "eth4".into(),
            pci_addr: "0002:07:00.1".into(),
            port_id: 0,
            num_rx_queues: 1,
            pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            accept_macs: vec![],
            mtu: None,
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
    e.set_steered(true);
    assert!(e.api_ready(), "handshake");
    e.attach_devices(AttachMode::Fresh).expect("attach");

    let err = e.adopt_vpp_fib().expect_err("the v6 dump never answers");
    assert!(err.api_lost(), "{err}");
    assert_eq!(
        e.counts().installed,
        0,
        "the v4 half must not be adopted on its own"
    );

    assert!(e.api_ready(), "the reconnect");
    let adopted = e.adopt_vpp_fib().expect("the resumed dump");
    assert!(
        adopted > 0,
        "the resume must adopt, not report an empty FIB and diff undeferred"
    );
    assert_eq!(e.counts().installed, 2);
}
