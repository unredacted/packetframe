//! `v6 on` — rung 0 of the IPv6 offload — against the fake VPP: VPP
//! carries the v6 table and nothing about v4 changes.
//!
//! Each test states one claim of the rung: v6 routes and neighbours
//! reach VPP under `Both` and never under `V4Only`; ip6 is enabled, with
//! router advertisements suppressed, once per egress interface and before
//! any v6 adjacency needs it, idempotently across an adoption; verify
//! samples both families and only v4 can fail it; the v6 table cannot
//! take a v4 route's slot; a preserved ledger carries v6 across a
//! restart; and under `V4Only` the v6 half of the feed never enters the
//! diff.

#[path = "common/fake_vpp.rs"]
mod fake_vpp;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packetframe_common::fib::IpPrefix;
use packetframe_vpp_offload::attach::{AttachMode, PortAttach};
use packetframe_vpp_offload::engine::{ConvergenceEngine, RouteSource, SourceChanges};
use packetframe_vpp_offload::fib_sync::FamilyPolicy;
use packetframe_vpp_offload::ledger_record::LedgerBody;
use packetframe_vpp_offload::runtime::{NoResources, NullStore, Runtime, SteeringUnavailable};
use packetframe_vpp_offload::supervisor::{Event as SupEvent, State};

use fake_vpp::{Behaviour, Event, Fake, WireRoute, ASSIGNED_INDEX, MAC};

const NH4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const NH6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0xff, 0, 0, 0, 1));
const MAC6: [u8; 6] = [0x02, 0, 0, 0, 0, 0x66];

fn v4(i: u8) -> IpPrefix {
    IpPrefix::V4 {
        addr: [198, 51, 100, i],
        prefix_len: 32,
    }
}

fn v6(i: u8) -> IpPrefix {
    IpPrefix::V6 {
        addr: [0x20, 0x01, 0x0d, 0xb8, 0, i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        prefix_len: 48,
    }
}

/// A dual-stack feed: `n4` v4 routes via a v4 neighbour and `n6` v6
/// routes via a v6 one, both on the member port.
struct DualStack {
    n4: u8,
    n6: u8,
    changes: std::cell::RefCell<Vec<SourceChanges>>,
}

impl DualStack {
    fn new(n4: u8, n6: u8) -> Self {
        Self {
            n4,
            n6,
            changes: Default::default(),
        }
    }
}

impl RouteSource for DualStack {
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        for i in 0..self.n4 {
            visit(v4(i), &[NH4]);
        }
        for i in 0..self.n6 {
            visit(v6(i), &[NH6]);
        }
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(NH4, "eth4", MAC);
        visit(NH6, "eth4", MAC6);
    }
    fn drain_changes(&self, _max: usize) -> SourceChanges {
        self.changes.borrow_mut().pop().unwrap_or_default()
    }
    fn requeue(&self, changes: SourceChanges) {
        self.changes.borrow_mut().push(changes);
    }
    fn route_count(&self) -> u64 {
        u64::from(self.n4) + u64::from(self.n6)
    }
    fn change_seq(&self) -> u64 {
        0
    }
}

fn port() -> PortAttach {
    PortAttach {
        port: "eth4".into(),
        pci_addr: "0002:07:00.1".into(),
        port_id: 0,
        num_rx_queues: 1,
        pf_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
        accept_macs: vec![],
        mtu: None,
        vlans: vec![],
    }
}

fn engine(fake: &Fake, families: FamilyPolicy) -> ConvergenceEngine {
    ConvergenceEngine::new(
        &fake.path,
        vec![port()],
        vec!["eth4".into()],
        1_000_000,
        families,
        packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(198, 51, 100, 254),
            prefix_len: 32,
        },
    )
}

fn drain_to_empty(e: &mut ConvergenceEngine) {
    for _ in 0..64 {
        if e.drain_batch().expect("drain").0 {
            return;
        }
    }
    panic!("did not converge in 64 drains");
}

/// attach → neighbours → resync → drain, as the supervisor orders them.
fn converge(e: &mut ConvergenceEngine, src: &dyn RouteSource, mode: AttachMode) {
    assert!(e.api_ready(), "handshake");
    e.attach_devices(mode).expect("attach");
    e.begin_resync(src);
    e.program_neighbours(src).expect("neighbours");
    drain_to_empty(e);
}

fn msgs(events: &[Event], prefix: &str) -> Vec<String> {
    events
        .iter()
        .filter_map(|ev| match ev {
            Event::Msg(m) if m.starts_with(prefix) => Some(m.clone()),
            _ => None,
        })
        .collect()
}

fn v6_route_adds(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|ev| {
            matches!(
                ev,
                Event::Route(WireRoute {
                    is_add: true,
                    is_ip6: true,
                    ..
                })
            )
        })
        .count()
}

fn v6_neighbour_adds(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|ev| matches!(ev, Event::Neighbour { ip, is_add: true, .. } if ip.is_ipv6()))
        .count()
}

/// `v6 on` programs the v6 routes and neighbours, with ip6 enabled and
/// RAs suppressed on the egress interface first — and the v4 half is
/// exactly what it would have been.
#[test]
fn v6_on_programs_v6_routes_and_neighbours_after_enabling_ip6() {
    let fake = Fake::start_behaving(
        "v6-on",
        Behaviour {
            track_routes: true,
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::Both);
    let src = DualStack::new(3, 4);
    converge(&mut e, &src, AttachMode::Fresh);
    let events = fake.drain_events();

    assert_eq!(
        msgs(&events, "ip6 enable"),
        vec![format!("ip6 enable if={ASSIGNED_INDEX} enable=true")],
        "ip6 enabled once, on the one owned interface"
    );
    assert_eq!(
        msgs(&events, "ra config"),
        vec![format!(
            "ra config if={ASSIGNED_INDEX} suppress=1 is_no=false"
        )],
        "and RAs suppressed on it"
    );
    assert_eq!(e.ip6_interfaces(), vec![ASSIGNED_INDEX]);

    // Ordering: ip6 before the first v6 adjacency and the first v6 route.
    let pos = |pred: &dyn Fn(&Event) -> bool| events.iter().position(pred);
    let enable = pos(&|ev| matches!(ev, Event::Msg(m) if m.starts_with("ip6 enable"))).unwrap();
    let first_nbr6 =
        pos(&|ev| matches!(ev, Event::Neighbour { ip, .. } if ip.is_ipv6())).expect("v6 nbr");
    let first_rt6 =
        pos(&|ev| matches!(ev, Event::Route(WireRoute { is_ip6: true, .. }))).expect("a v6 route");
    assert!(enable < first_nbr6 && enable < first_rt6, "{events:?}");

    assert_eq!(v6_neighbour_adds(&events), 1);
    assert_eq!(v6_route_adds(&events), 4);
    assert_eq!(
        fake.routes6.lock().unwrap().len(),
        4,
        "VPP holds the v6 table"
    );
    assert_eq!(fake.routes.lock().unwrap().len(), 3, "and the v4 one");

    let c = e.counts();
    assert_eq!(
        (c.installed, c.unresolvable, c.withheld),
        (3, 0, 0),
        "v4 counts"
    );
    let v6c = c.v6.expect("v6 carried");
    assert_eq!((v6c.installed, v6c.unresolvable, v6c.withheld), (4, 0, 0));
    assert!(!c.blocks_first_steer());
}

/// `V4Only` sends nothing v6 at all: no ip6 enable, no RA config, no v6
/// neighbour, no v6 route — and reports no v6 counts.
#[test]
fn v4_only_sends_nothing_v6() {
    let fake = Fake::start_behaving(
        "v6-off",
        Behaviour {
            track_routes: true,
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::V4Only);
    let src = DualStack::new(3, 4);
    converge(&mut e, &src, AttachMode::Fresh);
    let events = fake.drain_events();

    assert!(msgs(&events, "ip6 enable").is_empty(), "{events:?}");
    assert!(msgs(&events, "ra config").is_empty(), "{events:?}");
    assert_eq!(v6_neighbour_adds(&events), 0);
    assert_eq!(v6_route_adds(&events), 0);
    assert!(fake.routes6.lock().unwrap().is_empty());
    assert!(e.ip6_interfaces().is_empty());
    assert_eq!(e.counts().installed, 3);
    assert_eq!(e.counts().v6, None, "v6 not loaded is not v6 empty");
}

/// Under `V4Only` the v6 half of the feed never enters the diff: it is
/// counted as out of family, not as upserts, and never held pending —
/// at resync and on the delta door alike.
#[test]
fn v4_only_filters_v6_routes_at_diff_entry() {
    let fake = Fake::start("v6-diff");
    let mut e = engine(&fake, FamilyPolicy::V4Only);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let src = DualStack::new(3, 5);

    let plan = e.begin_resync(&src);
    assert_eq!(plan.upserts, 3, "only v4 is an upsert");
    assert_eq!(plan.out_of_family, 5);
    assert_eq!(e.pending().len(), 3, "and only v4 is pending");

    drain_to_empty(&mut e);
    src.changes.borrow_mut().push(SourceChanges {
        routes: vec![(v6(9), Some(vec![NH6])), (v4(9), Some(vec![NH4]))],
        neighbours: vec![],
    });
    e.apply_changes(&src, 64).expect("deltas");
    assert_eq!(e.pending().len(), 1, "the v6 delta is not queued");

    // Under `Both` the same feed is all upserts.
    let fake = Fake::start("v6-diff-both");
    let mut both = engine(&fake, FamilyPolicy::Both);
    assert!(both.api_ready());
    both.attach_devices(AttachMode::Fresh).expect("attach");
    let plan = both.begin_resync(&src);
    assert_eq!((plan.upserts, plan.out_of_family), (8, 0));
}

/// A new daemon adopting a VPP that already has ip6 on its interfaces
/// re-asserts both halves and is not refused: the re-enable answers
/// VALUE_EXIST, which is success.
#[test]
fn ip6_enable_is_idempotent_across_an_adoption() {
    let fake = Fake::start_behaving(
        "v6-adopt",
        Behaviour {
            track_routes: true,
            ..Default::default()
        },
    );
    let src = DualStack::new(2, 2);
    let mut first = engine(&fake, FamilyPolicy::Both);
    converge(&mut first, &src, AttachMode::Fresh);
    let indices = first.attached_indices();
    drop(first);
    let _ = fake.drain_events();

    let mut second = engine(&fake, FamilyPolicy::Both).with_recorded_indices(indices);
    assert!(second.api_ready());
    second
        .attach_devices(AttachMode::Adopted)
        .expect("an adopted VPP that already has ip6 must not be refused");
    let events = fake.drain_events();
    assert_eq!(msgs(&events, "ip6 enable").len(), 1, "{events:?}");
    assert_eq!(msgs(&events, "ra config").len(), 1, "{events:?}");
    assert_eq!(second.ip6_interfaces(), vec![ASSIGNED_INDEX]);

    // And once enabled, a later pass over the same interfaces sends
    // nothing: the ledger of enabled interfaces is consulted first.
    second.attach_devices(AttachMode::Adopted).expect("again");
    assert!(msgs(&fake.drain_events(), "ip6 enable").is_empty());

    // The dump adoption reads both families' routes back, and the
    // neighbour pass finds the v6 adjacency already held rather than
    // re-adding it (a re-add walks every dependent route).
    assert_eq!(second.adopt_vpp_fib().expect("dump"), 4);
    let c = second.counts();
    assert_eq!((c.installed, c.v6.unwrap().installed), (2, 2));
    second.program_neighbours(&src).expect("neighbours");
    assert_eq!(v6_neighbour_adds(&fake.drain_events()), 0);
}

/// Verify probes IPv6 with its own sample — and a v6 disagreement is
/// reported without failing the pass, which is IPv4's to decide.
#[test]
fn verify_samples_both_families_and_only_v4_gates() {
    let fake = Fake::start_behaving(
        "v6-verify",
        Behaviour {
            track_routes: true,
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::Both);
    let src = DualStack::new(3, 5);
    converge(&mut e, &src, AttachMode::Fresh);
    let _ = fake.drain_events();

    let v = e.run_verify().expect("verify");
    assert_eq!(v.outcome.sampled, 3, "every v4 route probed");
    let v6 = v.outcome.v6.clone().expect("v6 half");
    assert_eq!(v6.sampled, 5, "and every v6 route, in a sample of its own");
    assert!(v6.clean(), "{}", v.outcome.summary());
    assert!(v.outcome.passed(), "{}", v.outcome.summary());
    assert!(
        v.outcome.summary().contains("IPv6"),
        "{}",
        v.outcome.summary()
    );
    let lookups6 = fake
        .drain_events()
        .iter()
        .filter(|ev| matches!(ev, Event::Msg(m) if m == "ip_route_lookup"))
        .count();
    assert_eq!(lookups6, 8, "3 v4 + 5 v6 probes reached VPP");

    // Another client removes a v6 route behind our back: the v6 half
    // reports it, and the v4 pass stands.
    fake.routes6.lock().unwrap().pop_first();
    let v = e.run_verify().expect("verify");
    let v6 = v.outcome.v6.clone().expect("v6 half");
    assert_eq!(v6.mismatches.len(), 1, "{}", v.outcome.summary());
    assert!(v.outcome.passed(), "a v6 hole cannot fail the v4 gate");
    assert!(!v.outcome.restart_worthy(), "nor tear VPP down");
    assert!(v.outcome.any_mismatch(), "but it does disprove a record");
    // And it is retained where health reads it: `fib-v6` degrades on it
    // (the status surface renders `v6.degraded()`), the v4 gate does not.
    let c = e.counts();
    assert_eq!(c.v6.unwrap().verify_mismatches, 1);
    assert!(c.v6.unwrap().degraded());
    assert!(!c.blocks_first_steer());

    // Under V4Only there is no v6 half at all.
    let fake = Fake::start("v6-verify-off");
    let mut off = engine(&fake, FamilyPolicy::V4Only);
    converge(&mut off, &src, AttachMode::Fresh);
    let v = off.run_verify().expect("verify");
    assert!(v.outcome.v6.is_none());
    assert!(!v.outcome.summary().contains("IPv6"));
}

/// The v6 table cannot take a v4 route's slot. With a v6 pool smaller
/// than the v6 table, the overflow is withheld — per family, visible,
/// not blocking the v4 steer — and every v4 route still installs, even
/// ones arriving after v6 filled its pool.
#[test]
fn a_full_v6_pool_cannot_withhold_v4() {
    let fake = Fake::start("v6-cap");
    // Room for 4 v4 routes and 2 v6 ones. A shared pool of 6 would hold
    // the 5 v6 routes loaded first and leave one v4 slot for four
    // routes.
    let mut e = ConvergenceEngine::new(
        &fake.path,
        vec![port()],
        vec!["eth4".into()],
        4,
        FamilyPolicy::Both,
        packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(198, 51, 100, 254),
            prefix_len: 32,
        },
    )
    .with_v6_capacity(2);
    assert_eq!((e.route_capacity(), e.route_capacity_v6()), (4, 2));
    let v6_only = DualStack::new(0, 5);
    converge(&mut e, &v6_only, AttachMode::Fresh);
    let c = e.counts();
    let v6c = c.v6.unwrap();
    assert_eq!(
        (v6c.installed, v6c.withheld),
        (2, 3),
        "v6 stops at its own mark"
    );
    assert_eq!(e.pending().withheld_len(), 3);

    // v4 arrives after v6 filled its pool.
    v6_only.changes.borrow_mut().push(SourceChanges {
        routes: (0..4).map(|i| (v4(i), Some(vec![NH4]))).collect(),
        neighbours: vec![],
    });
    e.apply_changes(&v6_only, 64).expect("deltas");
    let (_, stats) = e.drain_batch().expect("drain");
    assert_eq!(stats.installed, 4, "every v4 route installs");
    assert_eq!(
        stats.released, 0,
        "v4 headroom must not release the parked v6 ops — that would spin"
    );
    let c = e.counts();
    assert_eq!((c.installed, c.withheld), (4, 0));
    assert!(
        !c.blocks_first_steer(),
        "a withheld v6 route says nothing about a steered v4 packet"
    );
    assert!(c.v6.unwrap().degraded(), "but v6 is visibly incomplete");
}

/// A preserved ledger carries both families across a restart: the next
/// daemon seeds v4 and v6 from it, VPP's fingerprint covers both, and
/// the resync diff finds nothing of either family to re-send.
#[test]
fn a_preserved_ledger_carries_v6_across_a_restart() {
    let fake = Fake::start_behaving(
        "v6-ledger",
        Behaviour {
            track_routes: true,
            ..Default::default()
        },
    );
    let src = DualStack::new(3, 4);
    let mut first = engine(&fake, FamilyPolicy::Both);
    converge(&mut first, &src, AttachMode::Fresh);
    let fp = first
        .fib_fingerprint()
        .expect("summary read")
        .expect("both summaries parse");
    assert!(
        fp.counts
            .iter()
            .any(|(t, len, n)| t == "ipv6-VRF:0" && *len == 48 && *n == 4),
        "the v6 summary is in the fingerprint: {fp:?}"
    );
    let (path_sets, entries) = first.preservable_ledger().expect("preservable");
    assert_eq!(entries.len(), 7, "both families recorded");
    let body = LedgerBody {
        fingerprint: fp.clone(),
        interfaces: first.attached_indices(),
        path_sets,
        entries,
    };
    let indices = first.attached_indices();
    drop(first);

    let mut second = engine(&fake, FamilyPolicy::Both).with_recorded_indices(indices);
    assert!(second.api_ready());
    second.attach_devices(AttachMode::Adopted).expect("adopt");
    assert_eq!(
        second.fib_fingerprint().unwrap(),
        Some(fp),
        "nothing changed"
    );
    assert_eq!(second.seed_ledger(&body), Ok(7));
    let c = second.counts();
    assert_eq!((c.installed, c.v6.unwrap().installed), (3, 4));
    second.program_neighbours(&src).expect("neighbours");
    let plan = second.begin_resync(&src);
    assert_eq!(
        (plan.unchanged, plan.upserts),
        (7, 0),
        "neither family is re-sent"
    );
    let _ = fake.drain_events();
    drain_to_empty(&mut second);
    assert_eq!(v6_route_adds(&fake.drain_events()), 0);
    let v = second.run_verify_paths(true).expect("verify");
    assert!(!v.outcome.any_mismatch(), "{}", v.outcome.summary());
}

/// Under `Both`, a VPP whose v6 summary cannot be read yields no
/// fingerprint — the preserved ledger is then refused for the dump path,
/// never matched against a v4-only reading.
#[test]
fn an_unreadable_v6_summary_refuses_the_fingerprint() {
    // Untracked: the fake answers `fib summary` with nothing readable.
    let fake = Fake::start("v6-fp");
    let mut e = engine(&fake, FamilyPolicy::Both);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    assert_eq!(e.fib_fingerprint().expect("answered"), None);
}

/// The router's own connected v6 subnet, fed back with itself as next
/// hop, is kernel-delivered — left out of VPP rather than read as
/// unresolvable — and does not block a v4 steer.
#[test]
fn a_connected_v6_subnet_via_the_router_itself_is_kernel_delivered() {
    const SELF6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0xaa, 0, 0, 0, 1);
    const SELF_LL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    struct Connected;
    impl RouteSource for Connected {
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            visit(v4(0), &[NH4]);
            visit(
                IpPrefix::V6 {
                    addr: [
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0,
                    ],
                    prefix_len: 64,
                },
                &[IpAddr::V6(SELF6), IpAddr::V6(SELF_LL)],
            );
            // Through the router, but NOT inside its subnet: a transit
            // route with next-hop-self stays unresolvable.
            visit(v6(7), &[IpAddr::V6(SELF6)]);
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(NH4, "eth4", MAC);
        }
        fn requeue(&self, _: SourceChanges) {}
        fn route_count(&self) -> u64 {
            3
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }
    let fake = Fake::start("v6-connected");
    let mut e =
        engine(&fake, FamilyPolicy::Both).with_self_networks_v6([(SELF6, 64), (SELF_LL, 64)]);
    converge(&mut e, &Connected, AttachMode::Fresh);
    assert_eq!(e.kernel_delivered_routes(), 1);
    let c = e.counts();
    assert_eq!(c.v6.unwrap().unresolvable, 1, "the transit route");
    assert_eq!(c.v6.unwrap().installed, 0);
    assert!(e.unexempted_local().is_empty(), "v6 needs no steer-exempt");
    assert!(!c.blocks_first_steer());
}

/// A member that is dark and carries only v6 adjacencies is idle to the
/// IPv4 link gate: verify passes, the fresh dead-member scan does not
/// mark it in use, and the v4 steer is not refused. It degrades `fib-v6`
/// and nothing else.
#[test]
fn a_dark_member_carrying_only_v6_does_not_block_v4() {
    struct Split;
    impl RouteSource for Split {
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            visit(v4(0), &[NH4]);
            visit(v6(0), &[NH6]);
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(NH4, "eth4", MAC);
            // The v6 peer sits behind eth5, the dark member.
            visit(NH6, "eth5", MAC6);
        }
        fn requeue(&self, _: SourceChanges) {}
        fn route_count(&self) -> u64 {
            2
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }
    let fake = Fake::start_behaving(
        "v6-dark",
        Behaviour {
            dark_extra_ports: true,
            ..Default::default()
        },
    );
    let mut eth5 = port();
    eth5.port = "eth5".into();
    eth5.pci_addr = "0002:08:00.1".into();
    let mut e = ConvergenceEngine::new(
        &fake.path,
        vec![port(), eth5],
        vec!["eth4".into(), "eth5".into()],
        1_000_000,
        FamilyPolicy::Both,
        packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(198, 51, 100, 254),
            prefix_len: 32,
        },
    );
    converge(&mut e, &Split, AttachMode::Fresh);
    let c = e.counts();
    assert_eq!((c.installed, c.v6.unwrap().installed), (1, 1));

    let v = e.run_verify().expect("verify");
    let dark: Vec<_> = v.outcome.dead_interfaces.iter().collect();
    assert_eq!(dark.len(), 1, "{}", v.outcome.summary());
    assert!(!dark[0].in_use, "v6-only adjacencies do not make it in use");
    assert!(v.outcome.passed(), "{}", v.outcome.summary());
    assert!(v.may_steer);
    let scan = e.dead_members().expect("fresh scan");
    assert!(scan.iter().all(|d| !d.in_use), "{scan:?}");

    let c = e.counts();
    assert_eq!(c.v6.unwrap().dark_egress, 1, "reported against v6");
    assert!(c.v6.unwrap().degraded());
    assert!(!c.blocks_first_steer());

    // The same member under V4Only never had a v6 neighbour at all.
    let fake = Fake::start_behaving(
        "v6-dark-off",
        Behaviour {
            dark_extra_ports: true,
            ..Default::default()
        },
    );
    let mut eth5 = port();
    eth5.port = "eth5".into();
    eth5.pci_addr = "0002:08:00.1".into();
    let mut off = ConvergenceEngine::new(
        &fake.path,
        vec![port(), eth5],
        vec!["eth4".into(), "eth5".into()],
        1_000_000,
        FamilyPolicy::V4Only,
        packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(198, 51, 100, 254),
            prefix_len: 32,
        },
    );
    converge(&mut off, &Split, AttachMode::Fresh);
    assert!(off.run_verify().expect("verify").outcome.passed());
}

/// Link-local next hops are scoped, and the feed keys neighbours by
/// address alone — the same `fe80::1` on two members collapses to one.
/// So nothing is ever installed through one: a v6 route whose only next
/// hop is link-local is refused and counted, one that also names a
/// global next hop installs through that alone, no link-local static
/// neighbour reaches VPP, and a v4 route through one reads unresolvable
/// exactly as it does under `V4Only`.
#[test]
fn link_local_next_hops_are_never_installed_through() {
    const LL: IpAddr = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    struct Scoped;
    impl RouteSource for Scoped {
        fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
            visit(v4(0), &[NH4]);
            visit(v4(1), &[LL]);
            visit(v6(0), &[LL]);
            visit(v6(1), &[NH6, LL]);
        }
        fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
            visit(NH4, "eth4", MAC);
            visit(NH6, "eth4", MAC6);
            // One address, two links: whichever the map kept would be a
            // guess.
            visit(LL, "eth4", [0x02, 0, 0, 0, 0, 0xa1]);
            visit(LL, "eth5", [0x02, 0, 0, 0, 0, 0xa2]);
        }
        fn requeue(&self, _: SourceChanges) {}
        fn route_count(&self) -> u64 {
            4
        }
        fn change_seq(&self) -> u64 {
            0
        }
    }
    let unresolvable_v4 = |families| {
        let fake = Fake::start_behaving(
            "v6-ll",
            Behaviour {
                track_routes: true,
                ..Default::default()
            },
        );
        let mut e = engine(&fake, families);
        converge(&mut e, &Scoped, AttachMode::Fresh);
        (e, fake)
    };

    let (e, fake) = unresolvable_v4(FamilyPolicy::Both);
    let events = fake.drain_events();
    assert!(
        !events
            .iter()
            .any(|ev| matches!(ev, Event::Neighbour { ip, .. } if *ip == LL)),
        "no link-local neighbour reaches VPP: {events:?}"
    );
    let routes6 = fake.routes6.lock().unwrap().clone();
    assert_eq!(routes6.len(), 1, "only the route with a global next hop");
    let (_, paths) = routes6.iter().next().unwrap();
    assert_eq!(
        paths.len(),
        1,
        "installed through the global next hop alone"
    );
    let c = e.counts();
    let v6c = c.v6.unwrap();
    assert_eq!(v6c.link_local_refused, 1);
    assert_eq!(
        v6c.unresolvable, 0,
        "refused is its own state, not unresolvable"
    );
    assert!(v6c.degraded());
    let both_v4 = (c.installed, c.unresolvable);

    let (off, _fake) = unresolvable_v4(FamilyPolicy::V4Only);
    assert_eq!(
        both_v4,
        (off.counts().installed, off.counts().unresolvable),
        "the v4 route through a link-local reads exactly as under V4Only"
    );
    assert_eq!(both_v4, (1, 1));

    // A delta moving the refused route onto a global next hop admits it;
    // one moving the installed route onto link-local only withdraws it.
    let fake = Fake::start_behaving(
        "v6-ll-delta",
        Behaviour {
            track_routes: true,
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::Both);
    let src = DualStack::new(0, 1);
    converge(&mut e, &src, AttachMode::Fresh);
    src.changes.borrow_mut().push(SourceChanges {
        routes: vec![(v6(0), Some(vec![LL]))],
        neighbours: vec![],
    });
    e.apply_changes(&src, 64).expect("deltas");
    drain_to_empty(&mut e);
    assert!(fake.routes6.lock().unwrap().is_empty(), "withdrawn");
    assert_eq!(e.counts().v6.unwrap().link_local_refused, 1);
    src.changes.borrow_mut().push(SourceChanges {
        routes: vec![(v6(0), Some(vec![LL, NH6]))],
        neighbours: vec![],
    });
    e.apply_changes(&src, 64).expect("deltas");
    drain_to_empty(&mut e);
    assert_eq!(fake.routes6.lock().unwrap().len(), 1, "admitted again");
    assert_eq!(e.counts().v6.unwrap().link_local_refused, 0);
}

/// A v6 route VPP refuses every time is parked and counted, not retried
/// on every drain: the drain goes idle, verify passes and the v4 table
/// may be steered. A newer intent for the prefix retries it once and
/// parks it again.
#[test]
fn a_permanently_rejected_v6_route_does_not_stall_v4() {
    let fake = Fake::start_behaving(
        "v6-reject",
        Behaviour {
            track_routes: true,
            reject_v6_routes: true,
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::Both);
    let src = DualStack::new(3, 2);
    converge(&mut e, &src, AttachMode::Fresh);
    assert!(e.pending().is_empty(), "the drain went idle");
    let c = e.counts();
    assert_eq!(c.installed, 3);
    let v6c = c.v6.unwrap();
    assert_eq!((v6c.installed, v6c.rejected), (0, 2));
    assert!(v6c.degraded());
    assert!(!c.blocks_first_steer());
    let v = e.run_verify().expect("verify");
    assert!(v.outcome.passed() && v.may_steer, "{}", v.outcome.summary());

    let _ = fake.drain_events();
    src.changes.borrow_mut().push(SourceChanges {
        routes: vec![(v6(0), Some(vec![NH6]))],
        neighbours: vec![],
    });
    e.apply_changes(&src, 64).expect("deltas");
    assert_eq!(
        e.counts().v6.unwrap().rejected,
        1,
        "superseded by the update"
    );
    drain_to_empty(&mut e);
    assert_eq!(v6_route_adds(&fake.drain_events()), 1, "retried once");
    assert_eq!(e.counts().v6.unwrap().rejected, 2, "and parked again");

    // A resync re-queues them (the bounded retry) and still goes idle.
    e.begin_resync(&src);
    drain_to_empty(&mut e);
    assert_eq!(e.counts().v6.unwrap().rejected, 2);
    // A prefix the source drops leaves the refused lot.
    let fewer = DualStack::new(3, 1);
    e.begin_resync(&fewer);
    drain_to_empty(&mut e);
    assert_eq!(e.counts().v6.unwrap().rejected, 1);
}

/// The whole loop: with every v6 route refused, IPv4 still reaches
/// `SyncComplete`, a passing verify and `Ready`, with the first-steer
/// gate open.
#[test]
fn the_loop_reaches_ready_with_every_v6_route_refused() {
    use packetframe_vpp_offload::driver::Driver;
    use std::time::{Duration, Instant};

    let fake = Fake::start_behaving(
        "v6-reject-loop",
        Behaviour {
            track_routes: true,
            reject_v6_routes: true,
            ..Default::default()
        },
    );
    let rt = Runtime::new(
        engine(&fake, FamilyPolicy::Both),
        Box::new(DualStack::new(4, 3)),
        Box::new(SteeringUnavailable),
        Box::new(NullStore),
        Box::new(NoResources),
        "/usr/bin/vpp",
        "/tmp/startup.conf",
    );
    let mut d = Driver::new();
    let mut now = Instant::now();
    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready());
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(now, SupEvent::Adopted { steered: false }, &mut fx);
    }
    let (mut obs, mut fx) = rt.views();
    let mut seen = Vec::new();
    for _ in 0..256 {
        if d.state() == State::Ready {
            break;
        }
        let t = d.tick(now, &mut obs, &mut fx);
        seen.extend(t.events.clone());
        for ev in rt.take_pending() {
            seen.extend(d.inject(now, ev, &mut fx).events);
        }
        now += t
            .sleep
            .unwrap_or(Duration::from_millis(100))
            .max(Duration::from_millis(1));
    }
    assert_eq!(d.state(), State::Ready, "events: {seen:?}");
    assert!(seen.contains(&SupEvent::SyncComplete), "{seen:?}");
    assert!(seen.contains(&SupEvent::VerifyPassed), "{seen:?}");
    let status = rt.status();
    assert_eq!(status.counts.installed, 4);
    assert_eq!(status.counts.v6.unwrap().rejected, 3);
    assert!(!status.counts.blocks_first_steer(), "v4 may be steered");
}

// --- `loopback-address6`: the global source for VPP's ICMPv6 errors.

use fake_vpp::LOOPBACK_INDEX;

/// The configured error source, RFC 3849.
const LO6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1);
const LO6_OCTETS: [u8; 16] = LO6.octets();

fn lo6_add(events: &[Event]) -> Vec<String> {
    msgs(
        events,
        &format!("address if={LOOPBACK_INDEX} add=true 2001:db8:ffff::1/128"),
    )
}

/// A fresh attach puts the /128 on the loopback, reads it back, and only
/// then reports it as the error source — before any interface is
/// unnumbered to the loopback. Without the directive nothing v6 touches
/// the loopback and there is no source to report.
#[test]
fn loopback6_is_added_to_the_loopback_and_read_back_on_a_fresh_attach() {
    let fake = Fake::start("lo6-fresh");
    let mut e = engine(&fake, FamilyPolicy::Both).with_loopback6(Some(LO6));
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let events = fake.drain_events();

    assert_eq!(lo6_add(&events).len(), 1, "{events:?}");
    assert_eq!(
        fake.addresses6.lock().unwrap().get(&LOOPBACK_INDEX),
        Some(&vec![(LO6_OCTETS, 128)]),
        "VPP holds exactly the /128, on the loopback"
    );
    // Dump, add, dump: the second dump is the readback the source rests on.
    let pos = |pred: &dyn Fn(&Event) -> bool| events.iter().position(pred);
    let dumps: Vec<usize> = events
        .iter()
        .enumerate()
        .filter(|(_, ev)| matches!(ev, Event::Msg(m) if m == "ip_address_dump"))
        .map(|(i, _)| i)
        .collect();
    let add = pos(&|ev| {
        matches!(ev, Event::Msg(m) if m.starts_with("address if=") && m.contains("2001:db8:ffff::1"))
    })
    .unwrap();
    assert_eq!(dumps.len(), 2, "{events:?}");
    assert!(dumps[0] < add && add < dumps[1], "{events:?}");
    let first_unnumbered =
        pos(&|ev| matches!(ev, Event::Msg(m) if m.starts_with("unnumbered if="))).unwrap();
    assert!(add < first_unnumbered, "{events:?}");
    // The member is unnumbered to the loopback holding it — the borrow
    // that makes it the source on that interface.
    assert!(
        msgs(&events, "unnumbered if=").contains(&format!(
            "unnumbered if={ASSIGNED_INDEX} to={LOOPBACK_INDEX} add=true"
        )),
        "{events:?}"
    );
    assert_eq!(e.icmp6_source(), Some(LO6));

    // Unset: no dump, no v6 address, no source.
    let fake = Fake::start("lo6-unset");
    let mut e = engine(&fake, FamilyPolicy::Both);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let events = fake.drain_events();
    assert!(msgs(&events, "ip_address_dump").is_empty(), "{events:?}");
    assert!(
        !events.iter().any(
            |ev| matches!(ev, Event::Msg(m) if m.starts_with("address if=") && m.contains(':'))
        ),
        "{events:?}"
    );
    assert!(fake.addresses6.lock().unwrap().is_empty());
    assert_eq!(e.icmp6_source(), None);
}

/// Adopting a surviving VPP whose loopback already holds the /128 reads
/// it back and sends nothing else — a re-add would answer
/// DUPLICATE_IF_ADDRESS, indistinguishable from a real conflict.
#[test]
fn an_adopted_loopback_holding_the_address_is_verified_not_rewritten() {
    static HELD: [([u8; 16], u8); 1] = [(LO6_OCTETS, 128)];
    let fake = Fake::start_behaving(
        "lo6-adopt",
        Behaviour {
            existing_loopback6: Some(&HELD),
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::Both).with_loopback6(Some(LO6));
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh)
        .expect("adopting an intact loopback");
    let events = fake.drain_events();
    // The premise: the loopback was FOUND, not created.
    assert!(msgs(&events, "create_loopback").is_empty(), "{events:?}");
    assert_eq!(msgs(&events, "ip_address_dump").len(), 1, "{events:?}");
    assert!(lo6_add(&events).is_empty(), "{events:?}");
    assert_eq!(e.icmp6_source(), Some(LO6));
}

/// A previous daemon that died between creating the loopback and adding
/// the /128 leaves a loopback without it. Adoption finds that by reading
/// back, and repairs it rather than trusting the loopback's name.
#[test]
fn an_adopted_loopback_missing_the_address_is_repaired() {
    static NONE: [([u8; 16], u8); 0] = [];
    let fake = Fake::start_behaving(
        "lo6-repair",
        Behaviour {
            existing_loopback6: Some(&NONE),
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::Both).with_loopback6(Some(LO6));
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let events = fake.drain_events();
    assert!(msgs(&events, "create_loopback").is_empty(), "{events:?}");
    assert_eq!(lo6_add(&events).len(), 1, "{events:?}");
    assert_eq!(
        fake.addresses6.lock().unwrap().get(&LOOPBACK_INDEX),
        Some(&vec![(LO6_OCTETS, 128)])
    );
    assert_eq!(e.icmp6_source(), Some(LO6));
}

/// Any other IPv6 address on the loopback refuses the attach, naming it:
/// VPP would source some errors from it (longest match per destination).
/// Nothing is added beside it, and no source is reported.
#[test]
fn a_foreign_v6_address_on_the_loopback_refuses_the_attach() {
    static FOREIGN: [([u8; 16], u8); 1] = [(
        Ipv6Addr::new(0x2001, 0xdb8, 0xeeee, 0, 0, 0, 0, 1).octets(),
        128,
    )];
    let fake = Fake::start_behaving(
        "lo6-foreign",
        Behaviour {
            existing_loopback6: Some(&FOREIGN),
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::Both).with_loopback6(Some(LO6));
    assert!(e.api_ready());
    let err = e
        .attach_devices(AttachMode::Fresh)
        .expect_err("a foreign address must refuse")
        .to_string();
    assert!(err.contains("2001:db8:eeee::1/128"), "{err}");
    assert!(err.contains("detach --all"), "{err}");
    assert!(lo6_add(&fake.drain_events()).is_empty());
    assert_eq!(e.icmp6_source(), None);
}

/// The loopback's link-local, should VPP ever list one in the dump
/// (source says it will not; hardware has not answered yet), is neither
/// foreign nor the configured address: beside the /128 it changes
/// nothing — the attach proceeds and sends no add.
#[test]
fn a_link_local_beside_the_address_is_ignored() {
    static HELD: [([u8; 16], u8); 2] = [
        (
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x11).octets(),
            128,
        ),
        (LO6_OCTETS, 128),
    ];
    let fake = Fake::start_behaving(
        "lo6-ll-held",
        Behaviour {
            existing_loopback6: Some(&HELD),
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::Both).with_loopback6(Some(LO6));
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh)
        .expect("a link-local on the loopback must not refuse the attach");
    let events = fake.drain_events();
    assert!(msgs(&events, "create_loopback").is_empty(), "{events:?}");
    assert!(lo6_add(&events).is_empty(), "{events:?}");
    assert_eq!(e.icmp6_source(), Some(LO6));
}

/// A link-local alone is a loopback WITHOUT the configured address: the
/// /128 is added beside it and read back, and the link-local stays.
#[test]
fn a_link_local_alone_is_not_the_address_and_the_address_is_added() {
    const LL: [u8; 16] = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0xff, 0xfe00, 0x11).octets();
    static HELD: [([u8; 16], u8); 1] = [(LL, 128)];
    let fake = Fake::start_behaving(
        "lo6-ll-only",
        Behaviour {
            existing_loopback6: Some(&HELD),
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::Both).with_loopback6(Some(LO6));
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    let events = fake.drain_events();
    assert!(msgs(&events, "create_loopback").is_empty(), "{events:?}");
    assert_eq!(lo6_add(&events).len(), 1, "{events:?}");
    assert_eq!(
        msgs(&events, "ip_address_dump").len(),
        2,
        "dump, add, read back: {events:?}"
    );
    assert_eq!(
        fake.addresses6.lock().unwrap().get(&LOOPBACK_INDEX),
        Some(&vec![(LL, 128), (LO6_OCTETS, 128)])
    );
    assert_eq!(e.icmp6_source(), Some(LO6));
}

/// VPP acknowledging the add is not VPP holding the address: a readback
/// that does not find it refuses the attach, and reports no source.
#[test]
fn an_acknowledged_add_the_readback_cannot_find_refuses_the_attach() {
    let fake = Fake::start_behaving(
        "lo6-ghost",
        Behaviour {
            drop_v6_address_adds: true,
            ..Default::default()
        },
    );
    let mut e = engine(&fake, FamilyPolicy::Both).with_loopback6(Some(LO6));
    assert!(e.api_ready());
    let err = e
        .attach_devices(AttachMode::Fresh)
        .expect_err("an unheld address must refuse")
        .to_string();
    assert!(err.contains("does not report holding it"), "{err}");
    assert_eq!(e.icmp6_source(), None);
}

/// The source is an observation about ONE VPP: it goes with the process,
/// and the next attach establishes it again by reading back.
#[test]
fn the_error_source_goes_with_the_process() {
    let fake = Fake::start("lo6-gone");
    let mut e = engine(&fake, FamilyPolicy::Both).with_loopback6(Some(LO6));
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    assert_eq!(e.icmp6_source(), Some(LO6));
    e.on_process_gone();
    assert_eq!(
        e.icmp6_source(),
        None,
        "the loopback it was read from is gone"
    );
}

/// Through the whole loop to `Ready`: the runtime's status carries the
/// read-back source to the health surface.
#[test]
fn the_runtime_status_reports_the_read_back_source() {
    use packetframe_vpp_offload::driver::Driver;
    use std::time::{Duration, Instant};

    let fake = Fake::start_behaving(
        "lo6-loop",
        Behaviour {
            track_routes: true,
            ..Default::default()
        },
    );
    let rt = Runtime::new(
        engine(&fake, FamilyPolicy::Both).with_loopback6(Some(LO6)),
        Box::new(DualStack::new(2, 2)),
        Box::new(SteeringUnavailable),
        Box::new(NullStore),
        Box::new(NoResources),
        "/usr/bin/vpp",
        "/tmp/startup.conf",
    );
    assert_eq!(rt.status().icmp6_source, None, "nothing read back yet");
    let mut d = Driver::new();
    let mut now = Instant::now();
    {
        let (mut obs, _) = rt.views();
        use packetframe_vpp_offload::driver::Observe as _;
        assert!(obs.api_ready());
    }
    {
        let (_, mut fx) = rt.views();
        d.inject(now, SupEvent::Adopted { steered: false }, &mut fx);
    }
    let (mut obs, mut fx) = rt.views();
    for _ in 0..256 {
        if d.state() == State::Ready {
            break;
        }
        let t = d.tick(now, &mut obs, &mut fx);
        for ev in rt.take_pending() {
            d.inject(now, ev, &mut fx);
        }
        now += t
            .sleep
            .unwrap_or(Duration::from_millis(100))
            .max(Duration::from_millis(1));
    }
    assert_eq!(d.state(), State::Ready);
    assert_eq!(rt.status().icmp6_source, Some(LO6));
}
