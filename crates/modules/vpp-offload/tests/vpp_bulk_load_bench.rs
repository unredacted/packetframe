//! Bulk route load rate against a **scratch VPP**, on hardware.
//!
//! What a fresh VPP's first load costs is the longest step between a
//! router's start and VPP steering, and on a box whose cores are already
//! busy it is several times its idle figure (11-05 on the reference deployment: about
//! 3.5 min under load against about 65 s idle). This measures the step
//! on its own: the production [`Drainer`] and [`Transport`] pushing
//! `ip_route_add_del` at a VPP, timed, with VPP's own barrier trace read
//! around the load, so a change to how routes are sent can be judged by
//! routes/s and by how often VPP stopped its workers to take them.
//!
//! It does not exercise the convergence engine, verify or steering —
//! `vpp_convergence_bench` does that against the real table and ports.
//! Here the routes are synthetic and every one goes via one neighbour on
//! a loopback, so the only variables are the sender and VPP's FIB.
//!
//! Skipped unless `PACKETFRAME_VPP_BENCH_SOCK` is set. **Point it only at
//! a VPP started for the purpose**: the bench adds a loopback, an address,
//! a neighbour and up to millions of routes to table 0, and removes the
//! routes after. It refuses a VPP that has any interface besides `local0`
//! and loopbacks, which is how a production VPP (with its VFs) is told
//! apart.
//!
//! ## Inputs
//!
//! | env | meaning |
//! |---|---|
//! | `PACKETFRAME_VPP_BENCH_SOCK` | the scratch VPP's API socket. **Required**; absent = skip. |
//! | `PACKETFRAME_VPP_BENCH_ROUTES` | routes per load (default 1,000,000 distinct IPv4 /24s, scattered) |
//! | `PACKETFRAME_VPP_BENCH_WINDOWS` | comma-separated drainer windows to compare (default `256`) |
//! | `PACKETFRAME_VPP_BENCH_ROUNDS` | loads per window (default 1) |
//!
//! One line per load is printed, starting `bench:`, with the install and
//! removal rates and VPP's barrier syncs over each.
//!
//! **Removal is slow at scale.** On the lab (cn9670, 2026-11-12) 200,000
//! routes left at about 38,000/s, but a million left at about 3,000/s,
//! so a 1M run spends minutes after the install line is earned. Time a
//! run's install from outside (VPP's `show ip fib summary`) if only the
//! install matters.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use packetframe_common::fib::IpPrefix;
use packetframe_vpp_offload::fib_sync::{to_address, to_prefix, Drainer, PortIndex, ResolvedPath};
use packetframe_vpp_offload::sink::{Capacity, NexthopMap, PendingMap, RouteLedger};
use packetframe_vpp_offload::vpp_api::generated::{
    CliInband, CliInbandReply, CreateLoopback, CreateLoopbackReply, IpNeighbor, IpNeighborAddDel,
    IpNeighborAddDelReply, SwInterfaceAddDelAddress, SwInterfaceAddDelAddressReply,
    SwInterfaceSetFlags, SwInterfaceSetFlagsReply, IF_STATUS_API_FLAG_ADMIN_UP,
    IP_API_NEIGHBOR_FLAG_STATIC,
};
use packetframe_vpp_offload::vpp_api::Transport;

/// Drain batch per call, as production uses (`engine::DRAIN_BATCH`).
const DRAIN_BATCH: usize = 4096;

const PORT: &str = "bench-loop";
const LOCAL: [u8; 4] = [100, 127, 0, 1];
const NEXTHOP: [u8; 4] = [100, 127, 0, 2];

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn cli(t: &mut Transport, cmd: &str) -> String {
    let r: CliInbandReply = t
        .request(CliInband {
            context: 0,
            cmd: cmd.into(),
        })
        .unwrap_or_else(|e| panic!("cli `{cmd}`: {e}"));
    assert_eq!(r.retval, 0, "cli `{cmd}` refused: {}", r.reply);
    r.reply
}

/// `n` distinct IPv4 /24s spread over 1.0.0.0–222.255.255.0 by a
/// multiplicative permutation, so they land across the mtrie the way a
/// real table does rather than as one dense run. Skips 100.127/16 (the
/// bench's own) and 127/8.
fn synthetic_routes(n: usize) -> Vec<IpPrefix> {
    const BASE: u64 = 0x01_0000; // 1.0.0.0 as a /24 index
    const SPAN: u64 = 0xDF_0000 - BASE; // up to 223.0.0.0
    const STEP: u64 = 1_000_003; // prime, coprime with SPAN
    let mut out = Vec::with_capacity(n);
    let mut i = 0u64;
    while out.len() < n {
        assert!(i < SPAN, "asked for more /24s than the span holds");
        let idx = BASE + (i * STEP) % SPAN;
        i += 1;
        let a = (idx >> 16) as u8;
        let b = (idx >> 8) as u8;
        if a == 127 || (a == 100 && b == 127) {
            continue;
        }
        out.push(IpPrefix::V4 {
            addr: [a, b, idx as u8, 0],
            prefix_len: 24,
        });
    }
    out
}

fn setup(t: &mut Transport) -> u32 {
    let ifs = cli(t, "show interface");
    for line in ifs.lines().skip(1) {
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        // Continuation lines of `show interface` start with whitespace and
        // a counter name; only rows that start in column 0 are interfaces.
        if line.starts_with(' ') {
            continue;
        }
        assert!(
            name == "local0" || name.starts_with("loop"),
            "{name} exists: this looks like a production VPP, not a scratch one; refusing"
        );
    }
    let lo: CreateLoopbackReply = t
        .request(CreateLoopback {
            context: 0,
            mac_address: [0x02, 0xfe, 0, 0, 0, 1],
        })
        .expect("create_loopback");
    assert_eq!(lo.retval, 0, "create_loopback refused");
    let sw = lo.sw_if_index;
    let up: SwInterfaceSetFlagsReply = t
        .request(SwInterfaceSetFlags {
            context: 0,
            sw_if_index: sw,
            flags: IF_STATUS_API_FLAG_ADMIN_UP,
        })
        .expect("set flags");
    assert_eq!(up.retval, 0, "admin up refused");
    let addr: SwInterfaceAddDelAddressReply = t
        .request(SwInterfaceAddDelAddress {
            context: 0,
            sw_if_index: sw,
            is_add: true,
            del_all: false,
            prefix: to_prefix(IpPrefix::V4 {
                addr: LOCAL,
                prefix_len: 24,
            }),
        })
        .expect("add address");
    assert_eq!(addr.retval, 0, "address refused");
    let nb: IpNeighborAddDelReply = t
        .request(IpNeighborAddDel {
            context: 0,
            is_add: true,
            neighbor: IpNeighbor {
                sw_if_index: sw,
                flags: IP_API_NEIGHBOR_FLAG_STATIC,
                mac_address: [0x02, 0xfe, 0, 0, 0, 2],
                ip_address: to_address(IpAddr::V4(Ipv4Addr::from(NEXTHOP))),
            },
        })
        .expect("add neighbour");
    assert_eq!(nb.retval, 0, "neighbour refused");
    sw
}

struct Load {
    secs: f64,
    barriers: u64,
    /// Which VPP functions took those barriers, most first.
    callers: String,
}

/// Tally the `bar-trace-<caller>-#<count>` events in the event log by
/// caller, most first, with their total. The log is cleared before each
/// load, so these are the load's, plus the one this `show` takes.
fn barrier_callers(t: &mut Transport) -> (u64, String) {
    let log = cli(t, "show event-logger 20000");
    let mut tally: std::collections::BTreeMap<String, u64> = Default::default();
    for line in log.lines() {
        let Some(at) = line.find("bar-trace-") else {
            continue;
        };
        let rest = &line[at + "bar-trace-".len()..];
        let Some(hash) = rest.rfind("-#") else {
            continue;
        };
        *tally.entry(rest[..hash].to_string()).or_default() += 1;
    }
    let total = tally.values().sum();
    let mut v: Vec<_> = tally.into_iter().collect();
    v.sort_by_key(|e| std::cmp::Reverse(e.1));
    let callers = v
        .iter()
        .map(|(c, n)| format!("{c} {n}"))
        .collect::<Vec<_>>()
        .join(", ");
    (total, callers)
}

fn run_drain(
    t: &mut Transport,
    drainer: &Drainer,
    pending: &mut PendingMap,
    ledger: &mut RouteLedger,
    ports: &PortIndex,
    map: &NexthopMap,
) -> Load {
    let resolve = |nhs: &[IpAddr]| -> Vec<ResolvedPath> {
        nhs.iter()
            .filter_map(|ip| {
                map.resolve(ip).map(|target| ResolvedPath {
                    nexthop: *ip,
                    target,
                })
            })
            .collect()
    };
    cli(t, "event-logger clear");
    let started = Instant::now();
    while !pending.is_empty() {
        let stats = drainer
            .drain(pending, ledger, &resolve, ports, t, DRAIN_BATCH)
            .unwrap_or_else(|(_, e)| panic!("drain: {e}"));
        assert_eq!(
            stats.rejected + stats.unresolvable,
            0,
            "routes not installed: {stats:?}"
        );
    }
    let secs = started.elapsed().as_secs_f64();
    let (barriers, callers) = barrier_callers(t);
    Load {
        secs,
        barriers,
        callers,
    }
}

#[test]
fn bulk_load_rate_against_a_scratch_vpp() {
    let Some(sock) = env("PACKETFRAME_VPP_BENCH_SOCK") else {
        eprintln!("PACKETFRAME_VPP_BENCH_SOCK unset; skipping");
        return;
    };
    let n: usize = env("PACKETFRAME_VPP_BENCH_ROUTES")
        .map(|v| v.parse().expect("PACKETFRAME_VPP_BENCH_ROUTES"))
        .unwrap_or(1_000_000);
    let windows: Vec<usize> = env("PACKETFRAME_VPP_BENCH_WINDOWS")
        .unwrap_or_else(|| "256".into())
        .split(',')
        .map(|w| w.trim().parse().expect("PACKETFRAME_VPP_BENCH_WINDOWS"))
        .collect();
    let rounds: usize = env("PACKETFRAME_VPP_BENCH_ROUNDS")
        .map(|v| v.parse().expect("PACKETFRAME_VPP_BENCH_ROUNDS"))
        .unwrap_or(1);

    let mut t = Transport::connect(&sock, Duration::from_secs(10)).expect("connect");
    t.set_timeout(Duration::from_secs(120)).expect("timeout");
    let sw = setup(&mut t);
    cli(&mut t, "event-logger resize 200000");
    cli(&mut t, "event-logger trace barrier on");

    let mut ports = PortIndex::default();
    ports.insert(PORT, None, sw);
    let mut map = NexthopMap::new(vec![PORT.into()]);
    let nh = IpAddr::V4(Ipv4Addr::from(NEXTHOP));
    map.set_device(nh, PORT);

    let routes = synthetic_routes(n);
    eprintln!(
        "bench: vpp {}; {} routes via {nh} on sw_if_index {sw}",
        cli(&mut t, "show version").trim(),
        routes.len()
    );
    for &window in &windows {
        let drainer = Drainer::new(window);
        for round in 0..rounds {
            let mut pending = PendingMap::new();
            let mut ledger = RouteLedger::new(Capacity::new(n as u64 + 1));
            for &p in &routes {
                pending.upsert(p, vec![nh]);
            }
            let add = run_drain(&mut t, &drainer, &mut pending, &mut ledger, &ports, &map);
            assert_eq!(ledger.counts().installed, n as u64, "every route installed");
            let summary = cli(&mut t, "show ip fib summary");
            let dpo = cli(&mut t, "show dpo memory");
            for &p in &routes {
                pending.withdraw(p);
            }
            let del = run_drain(&mut t, &drainer, &mut pending, &mut ledger, &ports, &map);
            println!(
                "bench: window {window} round {round}: install {n} in {:.2} s = {:.0} routes/s, \
                 {} barrier syncs; remove in {:.2} s = {:.0} routes/s, {} barrier syncs",
                add.secs,
                n as f64 / add.secs,
                add.barriers,
                del.secs,
                n as f64 / del.secs,
                del.barriers,
            );
            println!(
                "bench: barriers by caller: install [{}]; remove [{}]",
                add.callers, del.callers
            );
            if round == 0 {
                eprintln!("bench: fib after install:\n{summary}\n{dpo}");
            }
        }
    }
}
