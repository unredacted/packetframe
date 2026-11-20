//! Does a real VPP's CLI text still mean what vpp-offload reads it as?
//!
//! vpp-offload reads a few CLI commands' text over `cli_inband`, and
//! those formats can change between VPP releases with no API or CRC
//! change, so neither the attach handshake nor the binary-API drift
//! check (`.github/scripts/vpp-api-drift.sh`) would notice. Every such
//! read, with the parser the production code runs on it:
//!
//! | command | parser | used for |
//! |---|---|---|
//! | `show ip fib summary`, `show ip6 fib summary` | `FibFingerprint::absorb` | keep-VPP adoption's "nothing changed" check (`ConvergenceEngine::fib_fingerprint`) |
//! | `show errors` | `parse_null_drops`, `parse_glean_counters` | the null-drop and glean gauges (`ConvergenceEngine::sample_error_counters`) |
//! | `show ip neighbor-stats` | `parse_arp_replies_sent` | the ARP-reply gauge (same) |
//! | `show interface <name>` | `handback::parse_tx_packets` | the hand-back path's tx count (`vpp_side_state`) |
//!
//! A new parse site belongs in this table and in a check below.
//!
//! This programs a scratch VPP over the same `Transport` production
//! uses (a packet-generator interface, routes in two tables and both
//! families, glean and null-node traffic), reads each command, and
//! asserts the parsers recover what was programmed. Then it doctors the
//! real output the ways a release could plausibly change it and asserts
//! each check refuses it, so a pass is never one that could not fail.
//!
//! `#[ignore]`d; run by `.github/scripts/vpp-cli-compat.sh`, which
//! starts the VPP. To run by hand against a VPP started for the purpose:
//!
//! ```sh
//! PACKETFRAME_VPP_CLI_SOCK=/run/vpp/api.sock cargo test -p packetframe-vpp-offload \
//!   --test vpp_cli_compat -- --ignored --nocapture
//! ```
//!
//! It refuses a VPP with any interface besides `local0`, which is how a
//! production VPP (with its VFs) is told apart, and it needs one worker
//! (`corelist-workers`), which the packet generator's streams run on.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use packetframe_vpp_offload::engine::{
    parse_arp_replies_sent, parse_glean_counters, parse_null_drops, NeighbourCounters,
};
use packetframe_vpp_offload::handback::parse_tx_packets;
use packetframe_vpp_offload::ledger_record::FibFingerprint;
use packetframe_vpp_offload::vpp_api::generated::{CliInband, CliInbandReply};
use packetframe_vpp_offload::vpp_api::Transport;

const SOCK_ENV: &str = "PACKETFRAME_VPP_CLI_SOCK";
const PG: &str = "pg0";
/// A second table, so the fingerprint's per-table attribution is
/// exercised and not only its row parsing.
const VRF: u32 = 7;

/// Packets per stream. Glean books each one as sent or throttled, and
/// null-node books every one, so these are exact.
const GLEAN4_PKTS: u64 = 50;
const GLEAN6_PKTS: u64 = 40;
const NULL_PKTS: u64 = 7;

/// `(table, prefix length, routes)` added by [`add_routes`]. Tables as
/// VPP names them in the summary header.
const EXPECTED_V4: &[(&str, u8, i64)] = &[
    ("ipv4-VRF:0", 24, 2),
    ("ipv4-VRF:0", 25, 1),
    ("ipv4-VRF:0", 28, 3),
    ("ipv4-VRF:7", 24, 1),
];
const EXPECTED_V6: &[(&str, u8, i64)] = &[
    ("ipv6-VRF:0", 40, 1),
    ("ipv6-VRF:0", 48, 2),
    ("ipv6-VRF:0", 56, 1),
    ("ipv6-VRF:7", 48, 1),
];

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

/// The interface, its addresses and the second table. Before the first
/// snapshot: what these add to the FIB is not what is being counted.
fn setup(t: &mut Transport) {
    let ifs = cli(t, "show interface");
    for line in ifs.lines().skip(1) {
        // Continuation lines start with whitespace; interfaces in column 0.
        if line.starts_with(' ') {
            continue;
        }
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        assert!(
            name == "local0",
            "{name} exists: this looks like a production VPP, not a scratch one; refusing"
        );
    }
    for cmd in [
        format!("create packet-generator interface {PG}"),
        format!("set interface state {PG} up"),
        format!("set interface ip address {PG} 192.0.2.1/26"),
        format!("set interface ip address {PG} 2001:db8::1/64"),
        format!("ip table add {VRF}"),
        format!("ip6 table add {VRF}"),
    ] {
        cli(t, &cmd);
    }
}

fn add_routes(t: &mut Transport) {
    let v4 = |p: &str| format!("ip route add {p} via 192.0.2.2 {PG}");
    let v6 = |p: &str| format!("ip route add {p} via 2001:db8::2 {PG}");
    for cmd in [
        v4("198.51.100.0/24"),
        v4("203.0.113.0/24"),
        v4("192.0.2.128/25"),
        v4("198.51.100.16/28"),
        v4("198.51.100.32/28"),
        v4("198.51.100.48/28"),
        v4(&format!("198.51.100.0/24 table {VRF}")),
        v6("2001:db8:400::/40"),
        v6("2001:db8:100::/48"),
        v6("2001:db8:200::/48"),
        v6("2001:db8:300::/56"),
        v6(&format!("2001:db8:100::/48 table {VRF}")),
    ] {
        cli(t, &cmd);
    }
}

/// Traffic into the attached prefixes with no neighbour (glean, both
/// families) and straight into `null-node`.
fn send_traffic(t: &mut Transport) {
    for (name, limit, size, node, data) in [
        (
            "pf-glean4",
            GLEAN4_PKTS,
            64,
            "ip4-input",
            "UDP: 192.0.2.9 -> 192.0.2.50 UDP: 1024 -> 53 incrementing 30",
        ),
        (
            "pf-glean6",
            GLEAN6_PKTS,
            80,
            "ip6-input",
            "UDP: 2001:db8::9 -> 2001:db8::50 UDP: 1024 -> 53 incrementing 30",
        ),
        ("pf-null", NULL_PKTS, 64, "null-node", "incrementing 64"),
    ] {
        cli(
            t,
            &format!(
                "packet-generator new {{ name {name} limit {limit} rate 1000 size {size}-{size} \
                 worker 0 node {node} interface {PG} data {{ {data} }} }}"
            ),
        );
        cli(t, &format!("packet-generator enable-stream {name}"));
    }
}

/// Everything the checks read, captured once.
#[derive(Clone)]
struct Captured {
    fib4_before: String,
    fib4_after: String,
    fib6_before: String,
    fib6_after: String,
    errors_before: String,
    errors_after: String,
    neighbor_stats: String,
    show_pg: String,
    show_local0: String,
}

impl Captured {
    fn print(&self) {
        for (what, text) in [
            ("show ip fib summary (before)", &self.fib4_before),
            ("show ip fib summary (after)", &self.fib4_after),
            ("show ip6 fib summary (before)", &self.fib6_before),
            ("show ip6 fib summary (after)", &self.fib6_after),
            ("show errors (before)", &self.errors_before),
            ("show errors (after)", &self.errors_after),
            ("show ip neighbor-stats", &self.neighbor_stats),
            ("show interface pg0", &self.show_pg),
            ("show interface local0", &self.show_local0),
        ] {
            println!("---- {what}\n{text}");
        }
    }
}

fn fingerprint(text: &str) -> Result<BTreeMap<(String, u8), i64>, String> {
    let mut fp = FibFingerprint::default();
    // Production refuses an answer it read nothing from (fib_fingerprint).
    if fp.absorb(text) == 0 {
        return Err("FibFingerprint::absorb read no counts".into());
    }
    Ok(fp
        .counts
        .into_iter()
        .map(|(table, len, n)| ((table, len), n as i64))
        .collect())
}

/// Exactly the programmed routes appeared, per table and length, and
/// nothing else moved.
fn check_fib(before: &str, after: &str, expected: &[(&str, u8, i64)]) -> Result<(), String> {
    let (before, after) = (fingerprint(before)?, fingerprint(after)?);
    let mut delta: BTreeMap<(String, u8), i64> = BTreeMap::new();
    for (k, n) in &after {
        *delta.entry(k.clone()).or_default() += n;
    }
    for (k, n) in &before {
        *delta.entry(k.clone()).or_default() -= n;
    }
    delta.retain(|_, n| *n != 0);
    let want: BTreeMap<(String, u8), i64> = expected
        .iter()
        .map(|(t, l, n)| ((t.to_string(), *l), *n))
        .collect();
    if delta != want {
        return Err(format!("fib summary deltas {delta:?}, programmed {want:?}"));
    }
    Ok(())
}

fn glean_delta(before: &str, after: &str) -> NeighbourCounters {
    let (b, a) = (parse_glean_counters(before), parse_glean_counters(after));
    NeighbourCounters {
        arp_requests_sent: a.arp_requests_sent.saturating_sub(b.arp_requests_sent),
        arp_requests_throttled: a
            .arp_requests_throttled
            .saturating_sub(b.arp_requests_throttled),
        ns_sent: a.ns_sent.saturating_sub(b.ns_sent),
        ns_throttled: a.ns_throttled.saturating_sub(b.ns_throttled),
        arp_replies_sent: None,
    }
}

/// Every packet sent shows up in the rows the gauges read.
fn check_errors(before: &str, after: &str) -> Result<(), String> {
    let null = parse_null_drops(after).saturating_sub(parse_null_drops(before));
    if null != NULL_PKTS {
        return Err(format!("null-node drops +{null}, sent {NULL_PKTS}"));
    }
    let g = glean_delta(before, after);
    if g.arp_requests_sent == 0 || g.arp_requests_sent + g.arp_requests_throttled != GLEAN4_PKTS {
        return Err(format!(
            "ip4-glean ARP requests sent +{} throttled +{}, sent {GLEAN4_PKTS} packets",
            g.arp_requests_sent, g.arp_requests_throttled
        ));
    }
    if g.ns_sent == 0 || g.ns_sent + g.ns_throttled != GLEAN6_PKTS {
        return Err(format!(
            "ip6-glean solicitations sent +{} throttled +{}, sent {GLEAN6_PKTS} packets",
            g.ns_sent, g.ns_throttled
        ));
    }
    Ok(())
}

/// The ARP tx line parses. Shape only: an ARP request injected on a pg
/// interface never reached `arp-reply` in v26.10 (ethernet-input passed
/// it to `llc-input`, and VPP crashed on the next stream), so nothing
/// here makes VPP reply, the count is zero, and only that the line
/// parses is asserted.
fn check_neighbor_stats(text: &str) -> Result<(), String> {
    parse_arp_replies_sent(text)
        .map(|_| ())
        .ok_or_else(|| "parse_arp_replies_sent found no `arp: ... tx:[reply:N` line".into())
}

/// Every glean request and solicitation left through the interface, so
/// its tx count is at least their sum; an interface that sent nothing
/// lists no tx row and reads as zero; a name not in the text is no answer.
fn check_interface(show_pg: &str, show_local0: &str, min_tx: u64) -> Result<(), String> {
    match parse_tx_packets(show_pg, PG) {
        Some(n) if n >= min_tx => {}
        other => return Err(format!("{PG} tx packets {other:?}, sent at least {min_tx}")),
    }
    match parse_tx_packets(show_local0, "local0") {
        Some(0) => {}
        other => return Err(format!("local0 tx packets {other:?}, want Some(0)")),
    }
    if let Some(n) = parse_tx_packets(show_local0, PG) {
        return Err(format!("{PG} read as {n} out of another interface's text"));
    }
    Ok(())
}

fn check_all(c: &Captured) -> Result<(), String> {
    check_fib(&c.fib4_before, &c.fib4_after, EXPECTED_V4).map_err(|e| format!("ip4: {e}"))?;
    check_fib(&c.fib6_before, &c.fib6_after, EXPECTED_V6).map_err(|e| format!("ip6: {e}"))?;
    check_errors(&c.errors_before, &c.errors_after)?;
    check_neighbor_stats(&c.neighbor_stats)?;
    let g = glean_delta(&c.errors_before, &c.errors_after);
    check_interface(&c.show_pg, &c.show_local0, g.arp_requests_sent + g.ns_sent)
}

/// Every line, transformed.
fn each_line(text: &str, f: impl Fn(&str) -> String) -> String {
    text.lines().map(f).collect::<Vec<_>>().join("\n")
}

/// Plausible ways a release could reword these outputs, each of which
/// must fail its check. Run against the real text.
fn doctored(c: &Captured) -> Vec<(&'static str, Captured)> {
    let fib = |f: &dyn Fn(&str) -> String| {
        let mut d = c.clone();
        for s in [
            &mut d.fib4_before,
            &mut d.fib4_after,
            &mut d.fib6_before,
            &mut d.fib6_after,
        ] {
            *s = f(s);
        }
        d
    };
    let errors = |f: &dyn Fn(&str) -> String| {
        let mut d = c.clone();
        d.errors_before = f(&d.errors_before);
        d.errors_after = f(&d.errors_after);
        d
    };
    let two_ints = |l: &str| {
        let tok: Vec<&str> = l.split_whitespace().collect();
        tok.len() == 2 && tok.iter().all(|t| t.parse::<u64>().is_ok())
    };
    vec![
        (
            "fib summary: a third column on every count row",
            fib(&|s| {
                each_line(s, |l| {
                    if two_ints(l) {
                        format!("{l}  0")
                    } else {
                        l.into()
                    }
                })
            }),
        ),
        (
            "fib summary: table header renamed",
            fib(&|s| {
                s.replace("ipv4-VRF", "IPv4-VRF")
                    .replace("ipv6-VRF", "IPv6-VRF")
            }),
        ),
        (
            "fib summary: count and length columns swapped",
            fib(&|s| {
                each_line(s, |l| {
                    if two_ints(l) {
                        let t: Vec<&str> = l.split_whitespace().collect();
                        format!("{:>20}{:>16}", t[1], t[0])
                    } else {
                        l.into()
                    }
                })
            }),
        ),
        (
            "show errors: glean reason reworded",
            errors(&|s| s.replace("ARP requests sent", "ARP requests transmitted")),
        ),
        (
            "show errors: null-node renamed",
            errors(&|s| s.replace("null-node", "null-drop")),
        ),
        (
            "show errors: node column before count",
            errors(&|s| {
                each_line(s, |l| {
                    let t: Vec<&str> = l.split_whitespace().collect();
                    if t.len() >= 2 && t[0].parse::<u64>().is_ok() {
                        format!("{} {} {}", t[1], t[0], t[2..].join(" "))
                    } else {
                        l.into()
                    }
                })
            }),
        ),
        ("show ip neighbor-stats: tx bracket spaced", {
            let mut d = c.clone();
            d.neighbor_stats = d.neighbor_stats.replace("tx:[", "tx: [");
            d
        }),
        ("show interface: counter renamed", {
            let mut d = c.clone();
            d.show_pg = d.show_pg.replace("tx packets", "tx-packets");
            d
        }),
    ]
}

/// `show errors`, once every stream's packets are all booked.
fn errors_settled(t: &mut Transport, before: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let now = cli(t, "show errors");
        let g = glean_delta(before, &now);
        let null = parse_null_drops(&now).saturating_sub(parse_null_drops(before));
        let done = null >= NULL_PKTS
            && g.arp_requests_sent + g.arp_requests_throttled >= GLEAN4_PKTS
            && g.ns_sent + g.ns_throttled >= GLEAN6_PKTS;
        if done || Instant::now() > deadline {
            // Past the deadline the check below says what is missing.
            return now;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "needs a scratch VPP: .github/scripts/vpp-cli-compat.sh"]
fn vpp_cli_output_parses() {
    let sock = std::env::var(SOCK_ENV)
        .unwrap_or_else(|_| panic!("{SOCK_ENV} must name a scratch VPP's API socket"));
    let mut t = Transport::connect(&sock, Duration::from_secs(5))
        .unwrap_or_else(|e| panic!("connect {sock}: {e}"));
    println!("{}", cli(&mut t, "show version").trim());

    setup(&mut t);
    let fib4_before = cli(&mut t, FibFingerprint::command(false));
    let fib6_before = cli(&mut t, FibFingerprint::command(true));
    add_routes(&mut t);
    let fib4_after = cli(&mut t, FibFingerprint::command(false));
    let fib6_after = cli(&mut t, FibFingerprint::command(true));

    let errors_before = cli(&mut t, "show errors");
    send_traffic(&mut t);
    let errors_after = errors_settled(&mut t, &errors_before);

    let c = Captured {
        fib4_before,
        fib4_after,
        fib6_before,
        fib6_after,
        errors_before,
        errors_after,
        neighbor_stats: cli(&mut t, "show ip neighbor-stats"),
        show_pg: cli(&mut t, &format!("show interface {PG}")),
        show_local0: cli(&mut t, "show interface local0"),
    };
    c.print();

    if let Err(e) = check_all(&c) {
        panic!("vpp-offload does not read this VPP's CLI output as it means: {e}");
    }
    let mut vacuous = Vec::new();
    for (what, d) in doctored(&c) {
        match check_all(&d) {
            Ok(()) => vacuous.push(what),
            Err(e) => println!("doctored ({what}): refused as it should be: {e}"),
        }
    }
    assert!(
        vacuous.is_empty(),
        "these checks passed output doctored to mean something else: {vacuous:?}"
    );
}
