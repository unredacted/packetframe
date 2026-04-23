//! Offline BMP parser probe (Option F, Phase 3 validation tool).
//!
//! Reads a captured BMP byte stream (file or stdin), parses each
//! message via `bgpkit-parser`, and prints a structured summary.
//! This is the **Phase 1 deferred deliverable** — it proves the
//! library handles bird's wire format (especially RFC 9069 Loc-RIB /
//! peer type 3) before the real RouteSource in Slice 3C builds on it.
//!
//! Usage:
//! ```sh
//! # Against a file captured via tcpdump on the BMP session:
//! cargo run --example bmp_probe -- /path/to/bird.bmp
//!
//! # Against a live stream (e.g. piped from nc while bird dials in):
//! nc -l 127.0.0.1 6543 | cargo run --example bmp_probe -- -
//! ```
//!
//! Output is plain text, one line per message. A closing summary
//! prints message-type counts, per-peer-type counts, and per-peer
//! route-monitoring counts — enough to spot a library regression
//! (e.g., Loc-RIB frames silently misparsed as something else).
//!
//! Not a production binary; not shipped in the release tarball.
//! Lives under `examples/` so `cargo build --release` skips it.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::net::IpAddr;

use bgpkit_parser::parser::bmp::{messages::*, parse_bmp_msg};
use bytes::Bytes;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = match args.get(1).map(String::as_str) {
        Some(p) => p,
        None => {
            eprintln!(
                "usage: bmp_probe <path | -> \n\
                 \n\
                 Reads a captured BMP byte stream and prints parsed messages. \
                 Pass `-` to read from stdin."
            );
            std::process::exit(2);
        }
    };

    let mut raw = Vec::new();
    if path == "-" {
        io::stdin().read_to_end(&mut raw).expect("read stdin");
    } else {
        File::open(path)
            .unwrap_or_else(|e| {
                eprintln!("open {path}: {e}");
                std::process::exit(1);
            })
            .read_to_end(&mut raw)
            .expect("read file");
    }
    eprintln!("probing {} bytes from {path}", raw.len());

    let mut bytes = Bytes::from(raw);
    let mut stats = Stats::default();

    while !bytes.is_empty() {
        // `parse_bmp_msg` advances `bytes` past the message on success.
        // On error we bail — a malformed frame past this point means
        // we've lost sync with the stream framing and further parsing
        // would produce garbage.
        match parse_bmp_msg(&mut bytes) {
            Ok(msg) => {
                stats.msg_count += 1;
                print_message(&msg, &mut stats);
            }
            Err(e) => {
                eprintln!(
                    "parse error after {} messages ({} bytes remaining): {e}",
                    stats.msg_count,
                    bytes.len()
                );
                break;
            }
        }
    }

    stats.print_summary();
}

#[derive(Default)]
struct Stats {
    msg_count: usize,
    /// Per BmpMessageBody variant name.
    by_type: HashMap<&'static str, usize>,
    /// Per BmpPeerType variant name (for messages that carry a
    /// per-peer header).
    by_peer_type: HashMap<&'static str, usize>,
    /// Per-peer route-monitoring count, keyed by `peer_ip`.
    by_peer_rm: HashMap<IpAddr, usize>,
    /// End-of-RIB markers observed (one per peer per AFI/SAFI
    /// typically, per RFC 4724).
    end_of_rib: usize,
}

impl Stats {
    fn print_summary(&self) {
        println!();
        println!("=== Summary ===");
        println!("total BMP messages: {}", self.msg_count);
        println!();
        println!("by message type:");
        let mut by_type: Vec<(&&str, &usize)> = self.by_type.iter().collect();
        by_type.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in &by_type {
            println!("  {kind:<24} {count}");
        }
        println!();
        println!("by per-peer-type (RFC 9069 = LocalRib):");
        let mut by_peer: Vec<(&&str, &usize)> = self.by_peer_type.iter().collect();
        by_peer.sort_by(|a, b| b.1.cmp(a.1));
        for (kind, count) in &by_peer {
            println!("  {kind:<24} {count}");
        }
        println!();
        println!("route-monitoring messages per peer_ip (top 20):");
        let mut per_peer: Vec<(&IpAddr, &usize)> = self.by_peer_rm.iter().collect();
        per_peer.sort_by(|a, b| b.1.cmp(a.1));
        for (peer, count) in per_peer.iter().take(20) {
            println!("  {peer:<40} {count}");
        }
        println!();
        println!("End-of-RIB markers observed: {}", self.end_of_rib);
    }
}

fn print_message(msg: &BmpMessage, stats: &mut Stats) {
    let peer_type_name = msg.per_peer_header.as_ref().map(|pph| match pph.peer_type {
        BmpPeerType::Global => "Global",
        BmpPeerType::RD => "RD",
        BmpPeerType::Local => "Local",
        BmpPeerType::LocalRib => "LocalRib (RFC 9069)",
    });
    if let Some(name) = peer_type_name {
        *stats.by_peer_type.entry(name).or_insert(0) += 1;
    }

    match &msg.message_body {
        BmpMessageBody::InitiationMessage(_) => {
            *stats.by_type.entry("InitiationMessage").or_insert(0) += 1;
            println!("{:>6}  INITIATION", stats.msg_count);
        }
        BmpMessageBody::TerminationMessage(_) => {
            *stats.by_type.entry("TerminationMessage").or_insert(0) += 1;
            println!("{:>6}  TERMINATION", stats.msg_count);
        }
        BmpMessageBody::PeerUpNotification(_) => {
            *stats.by_type.entry("PeerUpNotification").or_insert(0) += 1;
            if let Some(pph) = &msg.per_peer_header {
                println!(
                    "{:>6}  PEER_UP peer_ip={} peer_asn={} type={}",
                    stats.msg_count,
                    pph.peer_ip,
                    pph.peer_asn,
                    peer_type_name.unwrap_or("?")
                );
            }
        }
        BmpMessageBody::PeerDownNotification(_) => {
            *stats.by_type.entry("PeerDownNotification").or_insert(0) += 1;
            if let Some(pph) = &msg.per_peer_header {
                println!(
                    "{:>6}  PEER_DOWN peer_ip={} type={}",
                    stats.msg_count,
                    pph.peer_ip,
                    peer_type_name.unwrap_or("?")
                );
            }
        }
        BmpMessageBody::RouteMonitoring(rm) => {
            *stats.by_type.entry("RouteMonitoring").or_insert(0) += 1;
            if rm.is_end_of_rib() {
                stats.end_of_rib += 1;
            }
            if let Some(pph) = &msg.per_peer_header {
                *stats.by_peer_rm.entry(pph.peer_ip).or_insert(0) += 1;
                // Terse per-frame log; full bgp update dump would be
                // too verbose for a 1M-route file. Flip to `{:?}` on
                // the inner BGP message for deep inspection.
                println!(
                    "{:>6}  ROUTE_MONITORING peer_ip={} type={} eor={}",
                    stats.msg_count,
                    pph.peer_ip,
                    peer_type_name.unwrap_or("?"),
                    rm.is_end_of_rib()
                );
            }
        }
        BmpMessageBody::RouteMirroring(_) => {
            *stats.by_type.entry("RouteMirroring").or_insert(0) += 1;
            println!("{:>6}  ROUTE_MIRRORING", stats.msg_count);
        }
        BmpMessageBody::StatsReport(_) => {
            *stats.by_type.entry("StatsReport").or_insert(0) += 1;
            println!("{:>6}  STATS_REPORT", stats.msg_count);
        }
    }
}
