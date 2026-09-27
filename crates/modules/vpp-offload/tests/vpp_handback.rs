//! The IPv6 hand-back path against the fake VPP.
//!
//! Each test states one claim: a fresh VPP gets the host interface, its
//! ip6 and RA settings, the static neighbour and a /128 per router-owned
//! address, in that order and only through the interface created; the
//! host's address changes reach VPP as adds and withdrawals; a surviving
//! VPP's path is re-verified rather than trusted or duplicated; the /128s
//! never enter the route ledger, so adoption's readback and the resync
//! diff leave them alone; a VPP that refuses the host interface leaves
//! the path not ready and IPv4 converging as ever; teardown removes both
//! halves; and at the steer chokepoint the /128s are in VPP before the
//! steering is told the v6 half may go in.

#[path = "common/fake_vpp.rs"]
mod fake_vpp;

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

use packetframe_common::fib::IpPrefix;
use packetframe_vpp_offload::attach::{AttachMode, PortAttach};
use packetframe_vpp_offload::engine::{ConvergenceEngine, RouteSource, SourceChanges};
use packetframe_vpp_offload::fib_sync::FamilyPolicy;
use packetframe_vpp_offload::handback::{
    eui64_link_local, router_owned, AddrReadError, HostAddr, HostCheck, HostFacts, HostSide,
    CHECK_EVERY, RETRY_EVERY, RT_SCOPE_UNIVERSE, VPP_HOST_IF,
};
use packetframe_vpp_offload::runtime::{NoResources, NullStore, Runtime, SteerOutcome};

use fake_vpp::{Behaviour, Event, Fake, WireRoute, AF_PACKET_BASE, AF_PACKET_TX, MAC};

const KERNEL_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xa0];
const VPP_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xa1];
const KERNEL_IFINDEX: u32 = 90;
const VPP_IFINDEX: u32 = 91;

fn addr(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

/// The kernel half, answering from shared state: the host's addresses
/// as RTM_NEWADDR would describe them (filtered by the module's own
/// [`router_owned`], so the exclusions are exercised on this path too),
/// and whether an address event is pending.
#[derive(Clone, Default)]
struct FakeHost(Arc<Mutex<HostState>>);

#[derive(Default)]
struct HostState {
    addrs: Vec<HostAddr>,
    heard: bool,
    ensures: usize,
    torn_down: bool,
    /// Every address read fails while set. `heard` stays set across a
    /// failure, as the kernel side keeps a change pending until a read
    /// succeeds — so the failure is pending exactly when a change was.
    fail_reads: bool,
    /// Report a periodic re-read as due, with nothing heard.
    periodic_due: bool,
}

impl FakeHost {
    fn with(addrs: &[(u32, &str, u8)]) -> Self {
        let h = Self::default();
        h.set(addrs);
        h
    }
    /// Replace the host's addresses — an RTM_NEWADDR/DELADDR burst.
    fn set(&self, addrs: &[(u32, &str, u8)]) {
        let mut s = self.0.lock().unwrap();
        s.addrs = addrs
            .iter()
            .map(|(ifindex, a, scope)| HostAddr {
                ifindex: *ifindex,
                addr: addr(a),
                scope: *scope,
                flags: 0,
            })
            .collect();
        s.heard = true;
    }
}

impl HostSide for FakeHost {
    fn ensure(&mut self) -> Result<HostFacts, String> {
        self.0.lock().unwrap().ensures += 1;
        Ok(HostFacts {
            kernel_ifindex: KERNEL_IFINDEX,
            kernel_mac: KERNEL_MAC,
            vpp_ifindex: VPP_IFINDEX,
            vpp_mac: VPP_MAC,
            mtu: 1500,
        })
    }
    fn check(&mut self, _facts: &HostFacts) -> HostCheck {
        HostCheck {
            veth: true,
            guard: true,
        }
    }
    fn owned_addrs(
        &mut self,
        facts: &HostFacts,
    ) -> Result<Option<BTreeSet<Ipv6Addr>>, AddrReadError> {
        let mut s = self.0.lock().unwrap();
        if !s.heard && !s.periodic_due {
            return Ok(None);
        }
        if s.fail_reads {
            return Err(AddrReadError {
                pending: s.heard,
                why: "netlink recv: EIO".into(),
            });
        }
        s.heard = false;
        s.periodic_due = false;
        Ok(Some(router_owned(
            &s.addrs,
            &[facts.kernel_ifindex, facts.vpp_ifindex],
        )))
    }
    fn teardown(&mut self) -> Result<(), String> {
        self.0.lock().unwrap().torn_down = true;
        Ok(())
    }
}

/// A transit /127, an IX address, the customer gateway and a tunnel /128
/// — plus what must never become a /128: a link-local, and an address on
/// the hand-back veth itself.
fn host() -> FakeHost {
    FakeHost::with(&[
        (2, "2001:db8:ffff::1", RT_SCOPE_UNIVERSE),
        (3, "2001:db8:ee::5", RT_SCOPE_UNIVERSE),
        (4, "2001:db8:100::1", RT_SCOPE_UNIVERSE),
        (7, "2001:db8:7::7", RT_SCOPE_UNIVERSE),
        (2, "fe80::1", 253),
        (KERNEL_IFINDEX, "2001:db8:dead::1", RT_SCOPE_UNIVERSE),
    ])
}

fn owned() -> BTreeSet<Ipv6Addr> {
    [
        "2001:db8:ffff::1",
        "2001:db8:ee::5",
        "2001:db8:100::1",
        "2001:db8:7::7",
    ]
    .iter()
    .map(|s| addr(s))
    .collect()
}

const NH4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

/// A v4-only feed of `n` routes — the hand-back path has nothing to do
/// with the mirror, and these tests show it touches none of it.
struct Mirror(u8);

impl RouteSource for Mirror {
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        for i in 0..self.0 {
            visit(
                IpPrefix::V4 {
                    addr: [198, 51, 100, i],
                    prefix_len: 32,
                },
                &[NH4],
            );
        }
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        visit(NH4, "eth4", MAC);
    }
    fn drain_changes(&self, _max: usize) -> SourceChanges {
        SourceChanges::default()
    }
    fn requeue(&self, _changes: SourceChanges) {}
    fn route_count(&self) -> u64 {
        u64::from(self.0)
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

fn engine(fake: &Fake, host: &FakeHost) -> ConvergenceEngine {
    let mut e = ConvergenceEngine::new(
        &fake.path,
        vec![port()],
        vec!["eth4".into()],
        1_000_000,
        FamilyPolicy::Both,
        packetframe_common::config::Ipv4Prefix {
            addr: Ipv4Addr::new(198, 51, 100, 254),
            prefix_len: 32,
        },
    )
    .with_handback(Box::new(host.clone()));
    e.set_handback_wanted(true);
    e
}

fn converge(e: &mut ConvergenceEngine, src: &dyn RouteSource) {
    assert!(e.api_ready(), "handshake");
    e.attach_devices(AttachMode::Fresh).expect("attach");
    e.begin_resync(src);
    e.program_neighbours(src).expect("neighbours");
    for _ in 0..64 {
        if e.drain_batch().expect("drain").0 {
            return;
        }
    }
    panic!("did not converge");
}

fn behaviour() -> Behaviour {
    Behaviour {
        track_routes: true,
        ..Default::default()
    }
}

/// `(addr, is_add)` for every /128 op the fake saw on the hand-back
/// interface.
fn handback_ops(events: &[Event]) -> Vec<(Ipv6Addr, bool)> {
    events
        .iter()
        .filter_map(|ev| match ev {
            Event::Route(WireRoute {
                is_add,
                is_ip6: true,
                len: 128,
                addr16,
                path_indices,
                ..
            }) if path_indices == &vec![AF_PACKET_BASE] => Some((Ipv6Addr::from(*addr16), *is_add)),
            _ => None,
        })
        .collect()
}

/// The /128s the fake's v6 table routes through the hand-back interface.
fn held(fake: &Fake) -> BTreeSet<Ipv6Addr> {
    fake.routes6
        .lock()
        .unwrap()
        .iter()
        .filter(|((_, len), paths)| {
            *len == 128 && paths.iter().any(|p| p.sw_if_index == AF_PACKET_BASE)
        })
        .map(|((a, _), _)| Ipv6Addr::from(*a))
        .collect()
}

fn position(events: &[Event], pred: impl Fn(&Event) -> bool) -> usize {
    events
        .iter()
        .position(pred)
        .expect("the event is in the stream")
}

/// A fresh VPP: the host interface is created on VPP's veth end wearing
/// that end's MAC, then ip6 with RAs suppressed, then the static
/// neighbour for the kernel veth's link-local — all at device attach, but
/// no /128 until the next pass, so an adopted FIB would reach the
/// preserved-ledger check unchanged. The next pass installs one /128 per
/// router-owned address, through the neighbour, and nothing for the
/// link-local or the veth's own address. Then the path is ready.
#[test]
fn a_fresh_vpp_gets_the_interface_then_the_neighbour_then_every_owned_128() {
    let fake = Fake::start_behaving("hb-fresh", behaviour());
    let host = host();
    let mut e = engine(&fake, &host);
    converge(&mut e, &Mirror(3));

    let events = fake.drain_events();
    let create = position(
        &events,
        |ev| matches!(ev, Event::Msg(m) if m.starts_with("af_packet_create ")),
    );
    let Event::Msg(line) = &events[create] else {
        unreachable!()
    };
    assert_eq!(
        line,
        &format!(
            "af_packet_create {VPP_HOST_IF} mac={:02x} mode=1 flags=1 rx_queues=1",
            VPP_MAC[5]
        )
    );
    let neighbour = position(
        &events,
        |ev| matches!(ev, Event::Neighbour { sw_if_index, .. } if *sw_if_index == AF_PACKET_BASE),
    );
    assert!(create < neighbour, "the interface before its neighbour");
    assert!(
        fake.ip6_enabled.lock().unwrap().contains(&AF_PACKET_BASE),
        "ip6 on the hand-back interface"
    );
    assert!(
        events[create..neighbour]
            .iter()
            .any(|ev| matches!(ev, Event::Msg(m) if m == "sw_interface_ip6nd_ra_config")),
        "RAs suppressed on it, between the create and the neighbour"
    );
    match &events[neighbour] {
        Event::Neighbour {
            ip,
            mac,
            flags,
            is_add,
            ..
        } => {
            assert_eq!(*ip, IpAddr::V6(eui64_link_local(KERNEL_MAC)));
            assert_eq!(*mac, KERNEL_MAC);
            assert_eq!(*flags, 1, "static");
            assert!(is_add);
        }
        _ => unreachable!(),
    }
    assert!(handback_ops(&events).is_empty(), "no /128 at device attach");
    assert!(!e.handback_ready());

    e.service_handback(true).expect("sync");
    let events = fake.drain_events();
    let added: BTreeSet<Ipv6Addr> = handback_ops(&events)
        .into_iter()
        .map(|(a, is_add)| {
            assert!(is_add);
            a
        })
        .collect();
    assert_eq!(added, owned());
    assert_eq!(held(&fake), owned());
    assert!(e.handback_ready());
    let st = e.handback_status().expect("wanted");
    assert!(st.ready && st.veth && st.guard && st.vpp_up, "{st:?}");
    assert_eq!(st.vpp_if.as_deref(), Some("host-pfpunt0-vpp"));
    assert_eq!((st.routes, st.owned), (4, Some(4)));
    assert_eq!(st.tx_packets, Some(AF_PACKET_TX));

    // The mirror's v4 is exactly what it would have been.
    assert_eq!(e.counts().installed, 3);
    // And a pass with nothing heard sends nothing.
    e.service_handback(true).expect("idle");
    assert!(handback_ops(&fake.drain_events()).is_empty());
}

/// An address added to the host becomes a /128 on the next pass, one
/// removed is withdrawn — and only those two ops go out.
#[test]
fn address_events_add_and_withdraw_128s() {
    let fake = Fake::start_behaving("hb-events", behaviour());
    let host = host();
    let mut e = engine(&fake, &host);
    converge(&mut e, &Mirror(1));
    e.service_handback(true).expect("sync");
    let _ = fake.drain_events();

    host.set(&[
        (2, "2001:db8:ffff::1", RT_SCOPE_UNIVERSE),
        (3, "2001:db8:ee::5", RT_SCOPE_UNIVERSE),
        (4, "2001:db8:100::1", RT_SCOPE_UNIVERSE),
        // 2001:db8:7::7 gone; a new tunnel address instead.
        (8, "2001:db8:8::8", RT_SCOPE_UNIVERSE),
    ]);
    e.service_handback(true).expect("sync");
    let mut ops = handback_ops(&fake.drain_events());
    ops.sort();
    assert_eq!(
        ops,
        vec![
            (addr("2001:db8:7::7"), false),
            (addr("2001:db8:8::8"), true)
        ]
    );
    let mut want = owned();
    want.remove(&addr("2001:db8:7::7"));
    want.insert(addr("2001:db8:8::8"));
    assert_eq!(held(&fake), want);
    assert!(e.handback_ready());
}

/// A surviving VPP: the host interface is found by name and reused — no
/// second socket on the veth — the neighbour already there is left alone
/// (a re-add would walk every route through it), a /128 for an address
/// the host dropped while the daemon was down is withdrawn, and the
/// missing ones are added.
#[test]
fn a_surviving_path_is_reverified_not_trusted() {
    type Neighbour6 = ([u8; 16], u32, [u8; 6], u8);
    static NEIGHBOURS: std::sync::OnceLock<[Neighbour6; 1]> = std::sync::OnceLock::new();
    let neighbours = NEIGHBOURS.get_or_init(|| {
        [(
            eui64_link_local(KERNEL_MAC).octets(),
            AF_PACKET_BASE,
            KERNEL_MAC,
            1,
        )]
    });
    let fake = Fake::start_behaving(
        "hb-adopt",
        Behaviour {
            track_routes: true,
            existing_neighbours6: neighbours,
            ..Default::default()
        },
    );
    fake.af_packets
        .lock()
        .unwrap()
        .push((VPP_HOST_IF.into(), AF_PACKET_BASE, VPP_MAC));
    let path = |nh: Ipv6Addr| {
        let mut p = fake_vpp::table_path([0; 4], AF_PACKET_BASE, 1);
        p.proto = 1;
        p.nh.address.0 = nh.octets();
        p
    };
    let nh = eui64_link_local(KERNEL_MAC);
    {
        let mut t = fake.routes6.lock().unwrap();
        t.insert((addr("2001:db8:ffff::1").octets(), 128), vec![path(nh)]);
        t.insert((addr("2001:db8:0:dead::1").octets(), 128), vec![path(nh)]);
    }

    let host = host();
    let mut e = engine(&fake, &host);
    converge(&mut e, &Mirror(1));
    let events = fake.drain_events();
    assert!(
        !events
            .iter()
            .any(|ev| matches!(ev, Event::Msg(m) if m.starts_with("af_packet_create"))),
        "reused, not created"
    );
    assert!(
        !events.iter().any(
            |ev| matches!(ev, Event::Neighbour { sw_if_index, .. } if *sw_if_index == AF_PACKET_BASE)
        ),
        "the neighbour VPP already holds is not re-added"
    );

    e.service_handback(true).expect("sync");
    let mut ops = handback_ops(&fake.drain_events());
    ops.sort();
    let mut want: Vec<(Ipv6Addr, bool)> = vec![(addr("2001:db8:0:dead::1"), false)];
    want.extend(
        owned()
            .into_iter()
            .filter(|a| *a != addr("2001:db8:ffff::1"))
            .map(|a| (a, true)),
    );
    want.sort();
    assert_eq!(ops, want);
    assert_eq!(held(&fake), owned());
    assert!(e.handback_ready());
}

/// A host interface of the right NAME bound to a veth that is gone — here
/// wearing another MAC, as one created on a since-recreated `pfpunt0-vpp`
/// does — is deleted and recreated, never adopted: its socket reads a
/// dead ifindex, and adopting it would re-adopt a down interface forever.
#[test]
fn a_stale_host_interface_is_recreated_not_adopted() {
    let fake = Fake::start_behaving("hb-stale", behaviour());
    fake.af_packets.lock().unwrap().push((
        VPP_HOST_IF.into(),
        AF_PACKET_BASE,
        [0x02, 0, 0, 0, 0, 0xee],
    ));
    let host = host();
    let mut e = engine(&fake, &host);
    converge(&mut e, &Mirror(1));
    let events = fake.drain_events();
    let delete = position(
        &events,
        |ev| matches!(ev, Event::Msg(m) if m == &format!("af_packet_delete {VPP_HOST_IF}")),
    );
    let create = position(
        &events,
        |ev| matches!(ev, Event::Msg(m) if m.starts_with("af_packet_create ")),
    );
    assert!(delete < create, "the stale one goes before the new one");
    assert_eq!(
        *fake.af_packets.lock().unwrap(),
        vec![(VPP_HOST_IF.to_string(), AF_PACKET_BASE, VPP_MAC)],
        "one host interface, on the current veth end"
    );
    e.service_handback(true).expect("sync");
    assert!(e.handback_ready());
}

/// The acknowledgement cache is re-read on every check. A /128 removed
/// from VPP behind the module, one replaced to point elsewhere, and the
/// static neighbour deleted are all noticed: the path reads NOT ready —
/// the v6 gate closed — until the repair, and the next sync puts every
/// piece back.
#[test]
fn the_check_reads_back_the_128s_and_the_neighbour_and_repairs_them() {
    let fake = Fake::start_behaving("hb-revalidate", behaviour());
    let host = host();
    let mut e = engine(&fake, &host);
    converge(&mut e, &Mirror(1));
    e.service_handback(true).expect("sync");
    assert!(e.handback_ready());
    let _ = fake.drain_events();

    let gone = addr("2001:db8:ee::5");
    let hijacked = addr("2001:db8:100::1");
    {
        let mut t = fake.routes6.lock().unwrap();
        t.remove(&(gone.octets(), 128));
        let paths = t.get_mut(&(hijacked.octets(), 128)).expect("installed");
        paths[0].sw_if_index = fake_vpp::ASSIGNED_INDEX;
    }
    fake.neighbours6.lock().unwrap().clear();

    // The check, with no sync yet: noticed, and the gate is shut.
    let later = std::time::Instant::now() + CHECK_EVERY;
    e.service_handback_at(false, later).expect("check");
    assert!(!e.handback_ready(), "a missing piece closes the gate");
    let events = fake.drain_events();
    assert!(
        events.iter().any(|ev| matches!(
            ev,
            Event::Neighbour { sw_if_index, is_add: true, mac, .. }
                if *sw_if_index == AF_PACKET_BASE && *mac == KERNEL_MAC
        )),
        "the neighbour is re-added on the spot"
    );

    // The sync re-installs both /128s, and the path is ready again.
    e.service_handback_at(true, later).expect("sync");
    let mut ops = handback_ops(&fake.drain_events());
    ops.sort();
    let mut want = vec![(gone, true), (hijacked, true)];
    want.sort();
    assert_eq!(ops, want);
    assert_eq!(held(&fake), owned());
    assert!(e.handback_ready());
}

/// An address event whose read then fails leaves the host's address set
/// UNKNOWN — the new address may already be answering with no /128 behind
/// it — so the gate closes until a read succeeds. A failed PERIODIC
/// re-read, with nothing heard, keeps the last good set and the gate open:
/// a flaky read must not churn every v6 rule.
#[test]
fn a_failed_address_read_closes_the_gate_only_when_a_change_was_pending() {
    let fake = Fake::start_behaving("hb-addrs", behaviour());
    let host = host();
    let mut e = engine(&fake, &host);
    converge(&mut e, &Mirror(1));
    e.service_handback(true).expect("sync");
    assert!(e.handback_ready());
    let t0 = std::time::Instant::now();

    // Periodic, nothing heard: the last good set stands.
    {
        let mut s = host.0.lock().unwrap();
        s.fail_reads = true;
        s.periodic_due = true;
    }
    e.service_handback_at(true, t0)
        .expect("a read failure is not a transport one");
    assert!(e.handback_ready(), "{:?}", e.handback_status());
    let st = e.handback_status().unwrap();
    assert!(
        st.error
            .as_deref()
            .is_some_and(|m| m.contains("the last good set stands")),
        "{st:?}"
    );

    // An address added, and the read after it fails: the gate shuts.
    host.set(&[
        (2, "2001:db8:ffff::1", RT_SCOPE_UNIVERSE),
        (3, "2001:db8:ee::5", RT_SCOPE_UNIVERSE),
        (4, "2001:db8:100::1", RT_SCOPE_UNIVERSE),
        (7, "2001:db8:7::7", RT_SCOPE_UNIVERSE),
        (9, "2001:db8:9::9", RT_SCOPE_UNIVERSE),
    ]);
    let t1 = t0 + RETRY_EVERY;
    e.service_handback_at(true, t1).expect("read fails again");
    assert!(
        !e.handback_ready(),
        "a pending change that could not be read"
    );
    assert!(held(&fake).len() == 4, "nothing guessed");

    // The read recovers: the new /128 goes in and the gate opens.
    host.0.lock().unwrap().fail_reads = false;
    e.service_handback_at(true, t1 + RETRY_EVERY).expect("sync");
    assert!(held(&fake).contains(&addr("2001:db8:9::9")));
    assert!(e.handback_ready());
}

/// A surviving path that already holds a /128 for every address the host
/// has is ready from the device attach — with nothing sent to VPP's FIB,
/// so a preserved ledger's fingerprint check sees the table it recorded.
#[test]
fn an_intact_surviving_path_is_ready_at_attach_without_touching_the_fib() {
    type Neighbour6 = ([u8; 16], u32, [u8; 6], u8);
    static NEIGHBOURS: std::sync::OnceLock<[Neighbour6; 1]> = std::sync::OnceLock::new();
    let neighbours = NEIGHBOURS.get_or_init(|| {
        [(
            eui64_link_local(KERNEL_MAC).octets(),
            AF_PACKET_BASE,
            KERNEL_MAC,
            1,
        )]
    });
    let fake = Fake::start_behaving(
        "hb-intact",
        Behaviour {
            track_routes: true,
            existing_neighbours6: neighbours,
            ..Default::default()
        },
    );
    fake.af_packets
        .lock()
        .unwrap()
        .push((VPP_HOST_IF.into(), AF_PACKET_BASE, VPP_MAC));
    let nh = eui64_link_local(KERNEL_MAC);
    {
        let mut t = fake.routes6.lock().unwrap();
        for a in owned() {
            let mut p = fake_vpp::table_path([0; 4], AF_PACKET_BASE, 1);
            p.proto = 1;
            p.nh.address.0 = nh.octets();
            t.insert((a.octets(), 128), vec![p]);
        }
    }
    let host = host();
    let mut e = engine(&fake, &host);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    assert!(e.handback_ready(), "{:?}", e.handback_status());
    let events = fake.drain_events();
    assert!(handback_ops(&events).is_empty(), "nothing sent to the FIB");
    assert!(!events.iter().any(|ev| matches!(
        ev,
        Event::Msg(m) if m.starts_with("af_packet_create") || m == "ip_neighbor_add_del"
    )));
}

/// The /128s are PF-owned topology, not mirror state: a later daemon's
/// readback of VPP's FIB does not adopt them into the ledger (their path
/// is on an interface the engine does not own), and a resync diff
/// against a feed that never carried them withdraws none.
#[test]
fn handback_routes_never_enter_the_ledger() {
    let fake = Fake::start_behaving("hb-ledger", behaviour());
    let host = host();
    {
        let mut e = engine(&fake, &host);
        converge(&mut e, &Mirror(0));
        e.service_handback(true).expect("sync");
        assert_eq!(held(&fake), owned());
    }
    // The next daemon, adopting the same VPP.
    let host2 = FakeHost::default();
    let mut e = engine(&fake, &host2);
    assert!(e.api_ready());
    e.attach_devices(AttachMode::Fresh).expect("attach");
    assert_eq!(e.adopt_vpp_fib().expect("readback"), 0, "none adopted");
    let plan = e.begin_resync(&Mirror(0));
    assert_eq!(plan.withdrawals, 0);
    for _ in 0..8 {
        if e.drain_batch().expect("drain").0 {
            break;
        }
    }
    assert_eq!(held(&fake), owned(), "still in VPP");
    assert!(handback_ops(&fake.drain_events())
        .iter()
        .all(|(_, is_add)| *is_add));
    assert_eq!(e.counts().v6.map_or(0, |v| v.installed), 0);
}

/// A VPP that will not create the host interface (no af_packet plugin)
/// leaves the path not ready, with the refusal named on its status — and
/// the device attach and IPv4 convergence carry on as if nothing were
/// asked of it.
#[test]
fn a_refused_host_interface_leaves_the_path_not_ready_and_v4_converges() {
    let fake = Fake::start_behaving(
        "hb-refused",
        Behaviour {
            track_routes: true,
            reject_af_packet_create: true,
            ..Default::default()
        },
    );
    let host = host();
    let mut e = engine(&fake, &host);
    converge(&mut e, &Mirror(4));
    e.service_handback(true)
        .expect("a refusal is not a transport failure");
    assert_eq!(e.counts().installed, 4);
    assert!(!e.handback_ready());
    let st = e.handback_status().expect("wanted");
    assert!(
        st.error
            .as_deref()
            .is_some_and(|m| m.contains("af_packet_create_v3")),
        "{st:?}"
    );
    assert!(held(&fake).is_empty());
}

/// Teardown takes VPP's half down (every /128, then the host interface)
/// while there is a VPP to ask, and the kernel half always.
#[test]
fn teardown_removes_both_halves() {
    let fake = Fake::start_behaving("hb-teardown", behaviour());
    let host = host();
    let mut e = engine(&fake, &host);
    converge(&mut e, &Mirror(1));
    e.service_handback(true).expect("sync");
    let _ = fake.drain_events();

    e.teardown_handback().expect("teardown");
    let events = fake.drain_events();
    assert!(handback_ops(&events).iter().all(|(_, is_add)| !is_add));
    assert!(held(&fake).is_empty());
    assert!(events
        .iter()
        .any(|ev| matches!(ev, Event::Msg(m) if m == &format!("af_packet_delete {VPP_HOST_IF}"))));
    assert!(fake.af_packets.lock().unwrap().is_empty());
    assert!(host.0.lock().unwrap().torn_down);
}

/// A steering double that records, at the moment `steer` runs, whether it
/// had been told the v6 half may go in — and how many hand-back /128s the
/// fake held right then.
struct GateProbe {
    ready: bool,
    rules: Vec<(String, u32)>,
    seen: Arc<Mutex<Vec<(bool, usize)>>>,
    table: Arc<Mutex<fake_vpp::RouteTable6>>,
}

impl packetframe_vpp_offload::runtime::Steering for GateProbe {
    fn set_v6_ready(&mut self, ready: bool) {
        self.ready = ready;
    }
    fn steer(&mut self) -> Result<SteerOutcome, String> {
        let handed_back = self
            .table
            .lock()
            .unwrap()
            .iter()
            .filter(|((_, len), p)| {
                *len == 128 && p.iter().any(|p| p.sw_if_index == AF_PACKET_BASE)
            })
            .count();
        self.seen.lock().unwrap().push((self.ready, handed_back));
        self.rules = vec![("eth4".into(), 1)];
        Ok(SteerOutcome::Steered)
    }
    fn unsteer(&mut self) -> Result<(), String> {
        self.rules.clear();
        Ok(())
    }
    fn missing_from_nic(&self) -> Result<packetframe_vpp_offload::runtime::SteeringAudit, String> {
        Ok(packetframe_vpp_offload::runtime::SteeringAudit::clean())
    }
    fn installed(&self) -> Vec<(String, u32)> {
        self.rules.clone()
    }
    fn installed_plan(&self) -> Vec<(String, u32, packetframe_vpp_offload::steer::RuleSet)> {
        Vec::new()
    }
    fn retarget(&mut self, _targets: Vec<(String, u32, packetframe_vpp_offload::steer::RuleSet)>) {}
    fn configured_ports(&self) -> usize {
        1
    }
}

fn runtime(fake: &Fake, host: &FakeHost, seen: &Arc<Mutex<Vec<(bool, usize)>>>) -> Runtime {
    Runtime::new(
        engine(fake, host),
        Box::new(Mirror(2)),
        Box::new(GateProbe {
            ready: false,
            rules: Vec::new(),
            seen: seen.clone(),
            table: fake.routes6.clone(),
        }),
        Box::new(NullStore),
        Box::new(NoResources),
        "/nonexistent/vpp",
        "/nonexistent/startup.conf",
    )
}

/// The steer chokepoint services the path first: by the time `steer`
/// runs, every router-owned /128 is in VPP and the steering has been told
/// the v6 half may go in — even straight after a device attach, which
/// installs none. Nothing v6 is ever diverted ahead of the way home.
#[test]
fn at_the_steer_the_128s_are_in_before_the_v6_half_is_permitted() {
    use packetframe_vpp_offload::driver::Observe as _;
    use packetframe_vpp_offload::executor::Effects as _;
    let fake = Fake::start_behaving("hb-gate", behaviour());
    let host = host();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rt = runtime(&fake, &host, &seen);
    let (mut obs, mut fx) = rt.views();
    assert!(obs.api_ready());
    fx.attach_devices().expect("attach");
    assert!(held(&fake).is_empty(), "none at attach");
    fx.steer().expect("steer");
    assert_eq!(*seen.lock().unwrap(), vec![(true, owned().len())]);
    let st = rt.status().handback.expect("wanted");
    assert!(st.ready, "{st:?}");
}

/// IPv4 never waits on the path: with the host interface refused, the
/// steer still runs — told the v6 half is held back.
#[test]
fn a_broken_path_holds_back_only_the_v6_half() {
    use packetframe_vpp_offload::driver::Observe as _;
    use packetframe_vpp_offload::executor::Effects as _;
    let fake = Fake::start_behaving(
        "hb-gate-refused",
        Behaviour {
            track_routes: true,
            reject_af_packet_create: true,
            ..Default::default()
        },
    );
    let host = host();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rt = runtime(&fake, &host, &seen);
    let (mut obs, mut fx) = rt.views();
    assert!(obs.api_ready());
    fx.attach_devices()
        .expect("a refused hand-back does not fail the attach");
    assert_eq!(fx.steer(), Ok(SteerOutcome::Steered));
    assert_eq!(*seen.lock().unwrap(), vec![(false, 0)]);
    let st = rt.status().handback.expect("wanted");
    assert!(!st.ready && st.error.is_some(), "{st:?}");
}

/// A readiness change under installed rules asks the supervisor for a
/// reconcile, so the v6 half goes in once the path is ready without an
/// operator asking again: rules steered with the path not wanted, then a
/// reload that diverts IPv6 — the next tick builds the path, and the
/// changed gate queues exactly one `SteerRequested`.
#[test]
fn a_path_becoming_ready_under_installed_rules_queues_a_reconcile() {
    use packetframe_common::config::VppSteerDirection;
    use packetframe_vpp_offload::driver::Observe as _;
    use packetframe_vpp_offload::executor::Effects as _;
    use packetframe_vpp_offload::steer::{McamBudget, RuleSet, V6Steering};
    use packetframe_vpp_offload::supervisor::Event as SupEvent;
    let fake = Fake::start_behaving("hb-resteer", behaviour());
    let host = host();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let rt = runtime(&fake, &host, &seen);
    // Nothing diverts IPv6 yet.
    rt.retarget(Vec::new());
    let (mut obs, mut fx) = rt.views();
    assert!(obs.api_ready());
    fx.attach_devices().expect("attach");
    fx.steer().expect("steer");
    rt.set_steered(true);
    assert!(rt.take_pending().is_empty());
    assert!(held(&fake).is_empty(), "not wanted, not built");

    let v6 = RuleSet::plan_with_v6(
        &[],
        &[],
        McamBudget::default(),
        VppSteerDirection::Src,
        &[[0x02, 0, 0, 0, 0, 1]],
        &V6Steering {
            vlans: vec![Some(100)],
            keeps: vec![],
        },
    )
    .expect("fits");
    rt.retarget(vec![("eth4".into(), 0, v6)]);
    obs.drain_batch(std::time::Instant::now()).expect("drain");
    assert_eq!(held(&fake), owned(), "built on the tick");
    let pending = rt.take_pending();
    assert_eq!(
        pending
            .iter()
            .filter(|e| matches!(e, SupEvent::SteerRequested))
            .count(),
        1,
        "{pending:?}"
    );
    // Settled: another tick asks for nothing more.
    obs.drain_batch(std::time::Instant::now()).expect("drain");
    assert!(rt.take_pending().is_empty());
}
