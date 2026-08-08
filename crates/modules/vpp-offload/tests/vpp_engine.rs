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

    struct ThreeNeighbours;
    impl RouteSource for ThreeNeighbours {
        fn for_each_route(&self, _: &mut dyn FnMut(IpPrefix, &[IpAddr])) {}
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(nh(), "eth4", MAC); // identical in VPP: keep
            visit(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)), "eth4", MAC_B); // stale MAC: replace
            visit(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12)), "eth4", MAC_C); // missing: add
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
        programmed, 2,
        "exactly the stale one and the missing one; the identical one is kept"
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
        sent_macs.contains(&MAC_B) && sent_macs.contains(&MAC_C),
        "the stale and missing neighbours must both be programmed: {sent_macs:?}"
    );
}
