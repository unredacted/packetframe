//! `packetframe fib` subcommand implementations (Option F, Phase 3.8).
//!
//! Three operations over the pinned custom-FIB maps:
//! - `dump-v4` / `dump-v6`: walk the LPM trie, print every entry.
//! - `lookup <ip>`: resolve a single address end-to-end.
//! - `stats`: print the same FIB occupancy block as `status`.
//!
//! All operations open the bpffs pins directly via
//! `packetframe_fast_path::fib::inspect`; no daemon IPC, no pin-
//! registry dependency. Works as long as the pins are alive —
//! after `systemctl stop packetframe` but before `detach --all`.

#![cfg(all(target_os = "linux", feature = "fast-path"))]

use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Subcommand;
use packetframe_common::config::Config;
use packetframe_fast_path::fib::inspect::{self, FibEntry, FibValueKind, NexthopSummary};

use crate::{config_path_or_default, EXIT_OK, EXIT_RUNTIME_ERROR};

#[derive(Subcommand)]
pub enum FibOp {
    /// Walk FIB_V4 and print every prefix with its resolved nexthop
    /// chain. O(N) in FIB size; on a ~1M-route default-sized map
    /// expect several seconds of output + ~200 MB transient heap.
    DumpV4 {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Walk FIB_V6 and print every prefix with its resolved nexthop
    /// chain.
    DumpV6 {
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// LPM-lookup a single IP and print the FibValue chain
    /// (nexthop or ECMP group + constituent nexthops).
    Lookup {
        #[arg(long)]
        config: Option<PathBuf>,
        /// IPv4 or IPv6 address.
        ip: IpAddr,
    },
    /// Print just the FIB occupancy / hash-mode / forwarding-mode
    /// block from `packetframe status` — useful for scripting.
    Stats {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

pub fn run(op: FibOp) -> ExitCode {
    match op {
        FibOp::DumpV4 { config } => dispatch(config, |bpffs| {
            match inspect::dump_v4(bpffs) {
                Ok(entries) => print_dump("v4", &entries),
                Err(e) => {
                    eprintln!("fib dump-v4 failed: {e}");
                    return ExitCode::from(EXIT_RUNTIME_ERROR);
                }
            }
            ExitCode::from(EXIT_OK)
        }),
        FibOp::DumpV6 { config } => dispatch(config, |bpffs| {
            match inspect::dump_v6(bpffs) {
                Ok(entries) => print_dump("v6", &entries),
                Err(e) => {
                    eprintln!("fib dump-v6 failed: {e}");
                    return ExitCode::from(EXIT_RUNTIME_ERROR);
                }
            }
            ExitCode::from(EXIT_OK)
        }),
        FibOp::Lookup { config, ip } => {
            dispatch(config, |bpffs| match inspect::lookup(bpffs, ip) {
                Ok(Some(entry)) => {
                    println!("MATCH");
                    print_entry(&entry);
                    ExitCode::from(EXIT_OK)
                }
                Ok(None) => {
                    println!("NO MATCH — {ip} has no covering prefix in FIB");
                    ExitCode::from(EXIT_OK)
                }
                Err(e) => {
                    eprintln!("fib lookup failed: {e}");
                    ExitCode::from(EXIT_RUNTIME_ERROR)
                }
            })
        }
        FibOp::Stats { config } => dispatch(config, |bpffs| {
            let snap = packetframe_fast_path::fib_status_from_pin(bpffs);
            print_stats(&snap);
            ExitCode::from(EXIT_OK)
        }),
    }
}

fn dispatch<F>(config: Option<PathBuf>, body: F) -> ExitCode
where
    F: FnOnce(&std::path::Path) -> ExitCode,
{
    let path = config_path_or_default(config);
    let cfg = match Config::from_file(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config parse {}: {e}", path.display());
            return ExitCode::from(EXIT_RUNTIME_ERROR);
        }
    };
    body(&cfg.global.bpffs_root)
}

fn print_dump(family_tag: &str, entries: &[FibEntry]) {
    if entries.is_empty() {
        println!("(FIB_{} empty)", family_tag.to_uppercase());
        return;
    }
    println!(
        "{} entries in FIB_{}",
        entries.len(),
        family_tag.to_uppercase()
    );
    for entry in entries {
        print_entry(entry);
    }
}

fn print_entry(entry: &FibEntry) {
    match entry.kind {
        FibValueKind::Single { nh_id } => {
            println!("{}  single nh_id={nh_id}", entry.prefix);
            for nh in &entry.nexthops {
                println!("  {}", format_nh(nh));
            }
        }
        FibValueKind::Ecmp {
            group_id,
            hash_mode,
        } => {
            println!(
                "{}  ecmp group_id={group_id} hash_mode={hash_mode}-tuple paths={}",
                entry.prefix,
                entry.nexthops.len()
            );
            for nh in &entry.nexthops {
                println!("  {}", format_nh(nh));
            }
        }
    }
}

fn format_nh(nh: &NexthopSummary) -> String {
    format!(
        "nh_id={:>4} state={:<10} family=v{} ifindex={:>3} dst_mac={} src_mac={}",
        nh.id,
        nh.state.to_string(),
        nh.family,
        nh.ifindex,
        mac_fmt(nh.dst_mac),
        mac_fmt(nh.src_mac),
    )
}

fn mac_fmt(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

fn print_stats(snap: &packetframe_fast_path::FibStatusSnapshot) {
    match snap.forwarding_mode {
        Some(mode) => println!("forwarding-mode: {mode}"),
        None => println!("forwarding-mode: <CFG pin not readable>"),
    }
    if let Some(h) = snap.default_hash_mode {
        println!("default-hash-mode: {h}-tuple");
    }
    println!("nexthops:");
    println!("  resolved: {}", snap.nh_resolved);
    println!("  failed:   {}", snap.nh_failed);
    println!("  stale:    {}", snap.nh_stale);
    println!(
        "  unwritten-or-incomplete: {}",
        snap.nh_unwritten_or_incomplete
    );
    println!("  max:      {}", snap.nh_max_entries);
    println!(
        "ecmp-groups: active={} max={}",
        snap.ecmp_active, snap.ecmp_max_entries
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_fmt_pads_zeros() {
        assert_eq!(mac_fmt([0, 0, 0, 0, 0, 0]), "00:00:00:00:00:00");
        assert_eq!(
            mac_fmt([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02]),
            "de:ad:be:ef:01:02"
        );
    }
}
