//! Convergence measurement against a **real VPP**, on hardware.
//!
//! Gate 0b item 10 measured what VPP's *CLI parser* costs to absorb the
//! v4 table: ~35 s for 1,053,360 routes through `vppctl exec`, with one
//! shared path-list. That number was recorded as an encouraging lower
//! bound and explicitly not as the convergence figure, because the
//! production path is 1.05M binary-API round trips against the real
//! nexthop set, driven by [`ConvergenceEngine`]. **The ≤60 s budget in
//! the phase-4 plan has never been measured.** This measures it.
//!
//! Skipped unless `PACKETFRAME_VPP_API_SOCK` is set, so CI and the qemu
//! verifier ignore it entirely. It ships to the router inside the
//! `hardware-artifacts` bundle like every other test binary.
//!
//! ## What it exercises
//!
//! The real code path, not a rehearsal of it: connect and handshake,
//! `attach_devices`, `program_neighbours`, the diffing resync, the
//! bounded drain loop, and readback verification. Everything the last
//! three review rounds argued about runs here against a VPP that can
//! disagree.
//!
//! ## What it does NOT prove
//!
//! That packets move. Nothing here steers traffic, and VPP forwarding is
//! gate 0b's job with a peer. A clean run means the table went in and
//! read back — not that the dataplane works.
//!
//! ## Inputs
//!
//! | env | meaning |
//! |---|---|
//! | `PACKETFRAME_VPP_API_SOCK` | VPP's binary API socket. **Required**; absent = skip. |
//! | `PACKETFRAME_VPP_ROUTES` | `<prefix> <nexthop>[,<nexthop>…]` per line |
//! | `PACKETFRAME_VPP_NEIGH` | `<ip> <dev> <mac>` per line |
//! | `PACKETFRAME_VPP_PORT` | member port name, e.g. `eth3` |
//! | `PACKETFRAME_VPP_PCI` | VF PCI address, e.g. `0002:07:00.1` |
//! | `PACKETFRAME_VPP_BUDGET_S` | override the 60 s budget |
//! | `PACKETFRAME_VPP_ADOPT` | set if VPP already has the interface attached |
//!
//! The runbook carries the commands that produce the two files.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use packetframe_common::fib::IpPrefix;
use packetframe_vpp_offload::attach::{AttachMode, PortAttach};
use packetframe_vpp_offload::engine::{ConvergenceEngine, RouteSource};
use packetframe_vpp_offload::fib_sync::FamilyPolicy;

/// The plan's published convergence budget.
const DEFAULT_BUDGET: Duration = Duration::from_secs(60);

/// Capacity high-water mark for the run. Deliberately generous: this
/// measures convergence, and a withheld route would change what is being
/// timed without saying so.
const HIGH_WATER: u64 = 4_000_000;

struct FileSource {
    routes: Vec<(IpPrefix, Vec<IpAddr>)>,
    neighbours: Vec<(IpAddr, String, [u8; 6])>,
}

impl RouteSource for FileSource {
    fn for_each_route(&self, visit: &mut dyn FnMut(IpPrefix, &[IpAddr])) {
        for (p, nhs) in &self.routes {
            visit(*p, nhs);
        }
    }
    fn for_each_neighbour(&self, visit: &mut dyn FnMut(IpAddr, &str, [u8; 6])) {
        for (ip, dev, mac) in &self.neighbours {
            visit(*ip, dev, *mac);
        }
    }
}

fn parse_prefix(s: &str) -> Option<IpPrefix> {
    let (addr, len) = s.split_once('/')?;
    let len: u8 = len.parse().ok()?;
    match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => (len <= 32).then_some(IpPrefix::V4 {
            addr: v4.octets(),
            prefix_len: len,
        }),
        IpAddr::V6(v6) => (len <= 128).then_some(IpPrefix::V6 {
            addr: v6.octets(),
            prefix_len: len,
        }),
    }
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for byte in s.split(':') {
        if n == 6 {
            return None;
        }
        out[n] = u8::from_str_radix(byte, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

/// Load the route file, collapsing duplicate prefixes into one multipath
/// entry — bird prints one line per path.
fn load_routes(path: &PathBuf) -> FileSource {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("reading routes from {}: {e}", path.display()));

    let mut by_prefix: BTreeMap<String, (IpPrefix, Vec<IpAddr>)> = BTreeMap::new();
    let mut skipped = 0usize;
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (Some(p), Some(nh)) = (f.next(), f.next()) else {
            continue;
        };
        let Some(prefix) = parse_prefix(p) else {
            skipped += 1;
            continue;
        };
        let nexthops: Vec<IpAddr> = nh.split(',').filter_map(|a| a.parse().ok()).collect();
        if nexthops.is_empty() {
            skipped += 1;
            continue;
        }
        by_prefix
            .entry(p.to_string())
            .and_modify(|(_, existing)| {
                for a in &nexthops {
                    if !existing.contains(a) {
                        existing.push(*a);
                    }
                }
            })
            .or_insert((prefix, nexthops));
    }
    assert_eq!(
        skipped, 0,
        "{skipped} route lines did not parse — fix the dump rather than \
         measuring a table that is quietly short"
    );

    FileSource {
        routes: by_prefix.into_values().collect(),
        neighbours: Vec::new(),
    }
}

fn load_neighbours(path: &PathBuf) -> Vec<(IpAddr, String, [u8; 6])> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("reading neighbours from {}: {e}", path.display()));
    let mut out = Vec::new();
    for line in text.lines() {
        let mut f = line.split_whitespace();
        let (Some(ip), Some(dev), Some(mac)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        let (Ok(ip), Some(mac)) = (ip.parse::<IpAddr>(), parse_mac(mac)) else {
            continue;
        };
        out.push((ip, dev.to_string(), mac));
    }
    out
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn required(name: &str) -> String {
    env(name).unwrap_or_else(|| panic!("{name} must be set for this run"))
}

fn secs(d: Duration) -> String {
    format!("{:.2}s", d.as_secs_f64())
}

#[test]
fn full_table_convergence_against_a_real_vpp() {
    let Some(sock) = env("PACKETFRAME_VPP_API_SOCK") else {
        // Not a silent pass: say why, so a run that was meant to measure
        // something and measured nothing is obvious in the log.
        println!(
            "SKIP: PACKETFRAME_VPP_API_SOCK unset — this measures convergence \
             against a live VPP and does nothing without one."
        );
        return;
    };

    let port = env("PACKETFRAME_VPP_PORT").unwrap_or_else(|| "eth3".into());
    let pci = required("PACKETFRAME_VPP_PCI");
    let budget = env("PACKETFRAME_VPP_BUDGET_S")
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_BUDGET);
    let mode = if env("PACKETFRAME_VPP_ADOPT").is_some() {
        AttachMode::Adopted
    } else {
        AttachMode::Fresh
    };

    let mut src = load_routes(&PathBuf::from(required("PACKETFRAME_VPP_ROUTES")));
    src.neighbours = load_neighbours(&PathBuf::from(required("PACKETFRAME_VPP_NEIGH")));

    println!("== convergence bench ==");
    println!("  socket     {sock}");
    println!("  port       {port} ({pci}), mode {mode:?}");
    println!("  routes     {}", src.routes.len());
    println!("  neighbours {}", src.neighbours.len());
    println!("  budget     {}", secs(budget));
    assert!(!src.routes.is_empty(), "an empty table measures nothing");

    let mut e = ConvergenceEngine::new(
        &sock,
        vec![PortAttach {
            port: port.clone(),
            pci_addr: pci,
            port_id: 0,
            num_rx_queues: 1,
        }],
        vec![port.clone()],
        HIGH_WATER,
        FamilyPolicy::V4Only,
    );

    // --- connect
    let t_connect = Instant::now();
    assert!(
        e.api_ready(),
        "no answer on {sock}: {}",
        e.last_api_error().unwrap_or("(no error recorded)")
    );
    let d_connect = t_connect.elapsed();

    // --- attach
    let t_attach = Instant::now();
    e.attach_devices(mode)
        .unwrap_or_else(|err| panic!("attach: {err}"));
    let d_attach = t_attach.elapsed();

    // --- the measured window starts here: everything from this point is
    // what a restart has to redo before traffic can be re-steered.
    let t_total = Instant::now();

    let t_resync = Instant::now();
    let plan = e.begin_resync(&src);
    let d_plan = t_resync.elapsed();

    let t_neigh = Instant::now();
    let programmed = e
        .program_neighbours(&src)
        .unwrap_or_else(|err| panic!("neighbours: {err}"));
    let d_neigh = t_neigh.elapsed();

    // --- drain
    let t_drain = Instant::now();
    let mut passes = 0u64;
    let mut installed = 0u64;
    let mut deferred = 0u64;
    loop {
        let (done, stats) = e
            .drain_batch()
            .unwrap_or_else(|err| panic!("drain (pass {passes}): {err}"));
        passes += 1;
        installed += stats.installed;
        deferred += stats.deferred;
        if done {
            break;
        }
        assert!(
            t_drain.elapsed() < budget * 10,
            "drain has run {} with {installed} installed — not converging",
            secs(t_drain.elapsed())
        );
    }
    let d_drain = t_drain.elapsed();

    // --- verify
    let t_verify = Instant::now();
    let verdict = e.run_verify().unwrap_or_else(|err| panic!("verify: {err}"));
    let d_verify = t_verify.elapsed();

    let d_total = t_total.elapsed();
    let c = e.counts();

    // Print the whole picture BEFORE asserting the budget: a run that
    // blows it is exactly the run whose phase breakdown matters, and a
    // panic that hides it wastes the trip to the hardware.
    println!("-- phases --");
    println!("  connect       {}", secs(d_connect));
    println!("  attach        {}", secs(d_attach));
    println!(
        "  resync plan   {}  ({} upserts, {} withdrawals)",
        secs(d_plan),
        plan.upserts,
        plan.withdrawals
    );
    println!(
        "  neighbours    {}  ({programmed} programmed)",
        secs(d_neigh)
    );
    println!(
        "  drain         {}  ({passes} passes, {installed} acked, {deferred} deferred)",
        secs(d_drain)
    );
    println!(
        "  verify        {}  ({} probes)",
        secs(d_verify),
        verdict.outcome.sampled
    );
    println!(
        "  TOTAL         {}   budget {}",
        secs(d_total),
        secs(budget)
    );
    println!("-- ledger --");
    println!(
        "  installed {} / installing {} / withheld {} / unresolvable {}",
        c.installed, c.installing, c.withheld, c.unresolvable
    );
    println!("  {}", verdict.outcome.summary());
    println!("  may_steer {}", verdict.may_steer);
    if d_drain.as_secs_f64() > 0.0 {
        println!(
            "-- rate --\n  {:.0} routes/s over the drain",
            installed as f64 / d_drain.as_secs_f64()
        );
    }

    // Correctness first: a fast run that installed the wrong table is
    // worse than a slow one that installed the right table.
    assert!(
        verdict.outcome.passed(),
        "readback verification failed: {}",
        verdict.outcome.summary()
    );
    assert_eq!(
        c.installed as usize,
        src.routes.len(),
        "every route in the source must be installed before the number means anything"
    );
    assert!(
        verdict.may_steer,
        "table incomplete — withheld {} / unresolvable {}",
        c.withheld, c.unresolvable
    );
    assert!(
        d_total <= budget,
        "CONVERGENCE OVER BUDGET: {} > {}",
        secs(d_total),
        secs(budget)
    );
}
