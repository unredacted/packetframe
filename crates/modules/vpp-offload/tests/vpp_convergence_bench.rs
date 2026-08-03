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
//! | `PACKETFRAME_VPP_PORT` | member port names, comma-separated: `eth2,eth3` |
//! | `PACKETFRAME_VPP_PCI` | VF PCI addresses, comma-separated, **paired by position** with PORT |
//! | `PACKETFRAME_VPP_SWIFINDEX` | recorded `sw_if_index` per port, required only for adopt |
//! | `PACKETFRAME_VPP_EXPECT_ROUTES` | **required** — distinct prefixes the dump must contain |
//! | `PACKETFRAME_VPP_BUDGET_S` | override the 60 s budget |
//! | `PACKETFRAME_VPP_ADOPT` | adopt interfaces VPP already has (needs SWIFINDEX) |
//!
//! **Every device that appears in the neighbour file must be a member
//! port with its own VF.** The reference `master4` table egresses via two
//! devices, so a single-port run leaves the other device's routes
//! unresolvable and verification fails by design — correctly, since a
//! packet whose best path exits an unowned port would blackhole. If only
//! one VF is available, rewrite the neighbour file's device column onto
//! that port and record the run as a **reduced** measurement: the drain,
//! wire encoding and VPP-side insert are fully exercised, but every
//! adjacency lands on one interface.
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
        if line.trim().is_empty() {
            continue;
        }
        let mut f = line.split_whitespace();
        let (Some(p), Some(nh)) = (f.next(), f.next()) else {
            // A non-blank line that is not `<prefix> <nexthop>` — a
            // truncated dump, most likely. Counted, not skipped past:
            // the assertion below exists so a damaged input cannot
            // produce a trusted measurement, and quietly dropping short
            // lines is exactly how it would.
            skipped += 1;
            continue;
        };
        let Some(prefix) = parse_prefix(p) else {
            skipped += 1;
            continue;
        };
        // Every comma-separated nexthop must parse. Dropping only the
        // bad ones leaves a non-empty vector, so `skipped` stays zero and
        // a silently shortened multipath route sails past the integrity
        // assertion below — the route installs, verification passes, and
        // the measurement is of a table nobody meant to load.
        let parsed: Vec<Option<IpAddr>> = nh.split(',').map(|a| a.parse().ok()).collect();
        if parsed.is_empty() || parsed.iter().any(|a| a.is_none()) {
            skipped += 1;
            continue;
        }
        let nexthops: Vec<IpAddr> = parsed.into_iter().flatten().collect();
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

    let ports: Vec<String> = required("PACKETFRAME_VPP_PORT")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let pcis: Vec<String> = required("PACKETFRAME_VPP_PCI")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(
        ports.len(),
        pcis.len(),
        "PACKETFRAME_VPP_PORT and PACKETFRAME_VPP_PCI pair by position"
    );
    let budget = env("PACKETFRAME_VPP_BUDGET_S")
        .and_then(|v| v.parse().ok())
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_BUDGET);
    let mode = if env("PACKETFRAME_VPP_ADOPT").is_some() {
        AttachMode::Adopted
    } else {
        AttachMode::Fresh
    };
    // Adoption reuses interfaces VPP already has, and `attach_ports`
    // refuses a port whose index it was not told — correctly, since
    // attaching blind would duplicate an interface the live FIB may
    // reference. Without this the documented adopt path panics on every
    // run, so the indices are an input rather than an afterthought.
    let recorded: Vec<(String, u32)> = match env("PACKETFRAME_VPP_SWIFINDEX") {
        Some(list) => {
            let idx: Vec<u32> = list
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            assert_eq!(
                idx.len(),
                ports.len(),
                "PACKETFRAME_VPP_SWIFINDEX must give one index per port \
                 (from `vppctl show interface`)"
            );
            ports.iter().cloned().zip(idx).collect()
        }
        None => {
            assert!(
                mode == AttachMode::Fresh,
                "PACKETFRAME_VPP_ADOPT needs PACKETFRAME_VPP_SWIFINDEX — \
                 adoption cannot attach an interface whose index is unknown"
            );
            Vec::new()
        }
    };

    let mut src = load_routes(&PathBuf::from(required("PACKETFRAME_VPP_ROUTES")));
    src.neighbours = load_neighbours(&PathBuf::from(required("PACKETFRAME_VPP_NEIGH")));

    println!("== convergence bench ==");
    println!("  socket     {sock}");
    println!(
        "  ports      {} / {} , mode {mode:?}",
        ports.join(","),
        pcis.join(",")
    );
    println!("  routes     {}", src.routes.len());
    println!("  neighbours {}", src.neighbours.len());
    println!("  budget     {}", secs(budget));

    // A dump truncated at a line boundary is syntactically perfect and
    // would produce a clean, fast, entirely meaningless "convergence"
    // result for a fraction of the table — and the installed-count
    // assertion later would agree, because it only proves every route in
    // the file went in. This measurement exists to validate the
    // *full-table* budget, so the expected size is an input, not an
    // inference. The runbook shows how to compute it from the dump.
    let expect: usize = required("PACKETFRAME_VPP_EXPECT_ROUTES")
        .parse()
        .expect("PACKETFRAME_VPP_EXPECT_ROUTES must be a number");
    assert_eq!(
        src.routes.len(),
        expect,
        "loaded {} distinct prefixes, expected {expect} — the dump is not \
         the table you think it is",
        src.routes.len()
    );

    // Every nexthop the ROUTES use must land on a member port, or those
    // routes are unresolvable and verification fails — correctly, since a
    // packet whose best path exits a port VPP does not own would
    // blackhole. Checked here rather than discovered 1.05M routes later.
    //
    // Scoped to nexthops the routes actually reference, deliberately. The
    // neighbour dump is the router's whole ARP table and legitimately
    // contains management and tunnel neighbours; `program_neighbours`
    // skips those by design, so asserting on every device in the file
    // would abort the run over entries the engine is built to ignore.
    // An earlier revision did exactly that — the assertion contradicted
    // the policy written one file over.
    let dev_of: std::collections::HashMap<IpAddr, &str> = src
        .neighbours
        .iter()
        .map(|(ip, d, _)| (*ip, d.as_str()))
        .collect();
    let mut unusable: Vec<String> = Vec::new();
    for (prefix, nexthops) in &src.routes {
        for nh in nexthops {
            match dev_of.get(nh) {
                Some(d) if ports.iter().any(|p| p == d) => {}
                Some(d) => unusable.push(format!("{nh} on {d} (used by {prefix:?})")),
                None => unusable.push(format!("{nh} absent from the neighbour file")),
            }
        }
    }
    unusable.sort();
    unusable.dedup();
    assert!(
        unusable.is_empty(),
        "{} route nexthop(s) do not resolve to a member port {ports:?}; first few: {:?} \
         — add a VF per device, or rewrite the neighbour device column onto an owned \
         port and record the run as reduced",
        unusable.len(),
        &unusable[..unusable.len().min(5)]
    );

    let mut e = ConvergenceEngine::new(
        &sock,
        ports
            .iter()
            .zip(&pcis)
            .map(|(port, pci)| PortAttach {
                port: port.clone(),
                pci_addr: pci.clone(),
                port_id: 0,
                num_rx_queues: 1,
            })
            .collect(),
        ports.clone(),
        HIGH_WATER,
        FamilyPolicy::V4Only,
    )
    .with_recorded_indices(recorded);

    // --- connect
    let t_connect = Instant::now();
    assert!(
        e.api_ready(),
        "no answer on {sock}: {}",
        e.last_api_error().unwrap_or("(no error recorded)")
    );
    let d_connect = t_connect.elapsed();

    // --- the measured window starts HERE, before attach.
    //
    // The plan defines convergence as attach → resync → verify, and a
    // restart genuinely has to recreate its interfaces before traffic can
    // be re-steered. Starting the clock after attach would let a slow
    // attach hide a budget overrun: the reported TOTAL could pass at 60 s
    // while the sequence an operator waits through did not.
    let t_total = Instant::now();

    let t_attach = Instant::now();
    e.attach_devices(mode)
        .unwrap_or_else(|err| panic!("attach: {err}"));
    let d_attach = t_attach.elapsed();

    // Emit the port→index mapping an adopted re-run needs.
    //
    // It cannot be reconstructed afterwards: `sw_interface_dump` reports
    // indistinguishable `octeonN/P` names with no PCI identity, so an
    // operator reading `show interface` cannot tell which index belongs
    // to which member port. Getting the order wrong would program
    // neighbours and routes through the opposite VFs — and verification
    // would still pass, because it checks that paths use *an* owned
    // index, not the intended one per path. Printing it here is the only
    // moment the mapping is actually known.
    let idx = e.attached_indices();
    let ordered: Vec<String> = ports
        .iter()
        .map(|p| {
            idx.iter()
                .find(|(name, _)| name == p)
                .map(|(_, i)| i.to_string())
                .unwrap_or_else(|| panic!("attach reported no index for {p}"))
        })
        .collect();
    println!(
        "  to re-run adopted:  PACKETFRAME_VPP_ADOPT=1 PACKETFRAME_VPP_SWIFINDEX={}",
        ordered.join(",")
    );

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
    println!(
        "  connect       {}  (outside the budget: one-time socket setup)",
        secs(d_connect)
    );
    println!("  attach        {}  (inside)", secs(d_attach));
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
