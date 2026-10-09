//! `packetframe flow-export`: what flow export's collectors need to know
//! that its datagrams do not carry.
//!
//! - `interfaces`: every port flow export samples, by the ifIndex its
//!   samples name (the kernel's ifindex; output 0 is unknown), for a
//!   collector with no SNMP to ask. By default as Akvorado's static
//!   metadata provider, keyed by `source-address`, the address every
//!   collector keys this exporter on.
//!
//! Reads the config and the kernel; the daemon need not be running.

#![cfg(feature = "flow-export")]

use std::fmt::Write as _;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Subcommand, ValueEnum};
use packetframe_common::config::{Config, ModuleDirective};

use crate::{config_path_or_default, EXIT_OK, EXIT_STARTUP_ERROR};

#[derive(Subcommand)]
pub enum FlowExportOp {
    /// The interfaces flow export reports, by the ifIndex its samples
    /// carry, for a collector's interface metadata.
    Interfaces {
        #[arg(long)]
        config: Option<PathBuf>,
        /// `akvorado`: a static metadata provider for Akvorado's
        /// outlet.yaml. `table`: for reading.
        #[arg(long, value_enum, default_value_t = Format::Akvorado)]
        format: Format,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Akvorado,
    Table,
}

pub fn run(op: FlowExportOp) -> ExitCode {
    match op {
        FlowExportOp::Interfaces { config, format } => interfaces(config, format),
    }
}

/// A port flow export samples, as the kernel has it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    /// `None` when the kernel has no such interface.
    pub ifindex: Option<u32>,
    pub speed_mbps: Option<u64>,
    /// What samples it: `fast-path`, `VPP`.
    pub paths: Vec<&'static str>,
}

fn interfaces(config: Option<PathBuf>, format: Format) -> ExitCode {
    let path = config_path_or_default(config);
    let config = match Config::from_file(&path).and_then(|c| {
        c.validate_flow_export()?;
        Ok(c)
    }) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("flow-export interfaces: {}: {e}", path.display());
            return ExitCode::from(EXIT_STARTUP_ERROR);
        }
    };
    let Some(source) = source_address(&config) else {
        eprintln!(
            "flow-export interfaces: {} declares no `module flow-export`",
            path.display()
        );
        return ExitCode::from(EXIT_STARTUP_ERROR);
    };
    let ifaces = sampled(&config)
        .into_iter()
        .map(|(name, paths)| Iface {
            ifindex: ifindex(&name),
            speed_mbps: speed_mbps(&name),
            name,
            paths,
        })
        .collect::<Vec<_>>();
    print!(
        "{}",
        match format {
            Format::Akvorado => akvorado(source, &hostname(), &ifaces),
            Format::Table => table(&ifaces),
        }
    );
    ExitCode::from(EXIT_OK)
}

fn source_address(config: &Config) -> Option<IpAddr> {
    let section = config.modules.iter().find(|m| m.name == "flow-export")?;
    section.directives.iter().find_map(|d| match d {
        ModuleDirective::FlowSourceAddress { addr, .. } => Some(*addr),
        _ => None,
    })
}

/// Every port a path samples, in config order, with the paths on it.
fn sampled(config: &Config) -> Vec<(String, Vec<&'static str>)> {
    let mut out: Vec<(String, Vec<&'static str>)> = Vec::new();
    let mut add = |name: String, path: &'static str| match out.iter_mut().find(|(n, _)| *n == name)
    {
        Some((_, paths)) if !paths.contains(&path) => paths.push(path),
        Some(_) => {}
        None => out.push((name, vec![path])),
    };
    for name in crate::feasibility::attach_ifaces_from_config(config) {
        add(name, "fast-path");
    }
    for name in crate::feasibility::vpp_ports_from_config(config) {
        add(name, "VPP");
    }
    out
}

#[cfg(target_os = "linux")]
fn ifindex(name: &str) -> Option<u32> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: a NUL-terminated name that outlives the call.
    let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (i != 0).then_some(i)
}

/// No kernel ports to report off Linux.
#[cfg(not(target_os = "linux"))]
fn ifindex(_name: &str) -> Option<u32> {
    None
}

/// The link speed the kernel reports, when it knows one (a link that is
/// down, or virtual, reports -1).
fn speed_mbps(name: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/speed"))
        .ok()?
        .trim()
        .parse::<i64>()
        .ok()
        .and_then(|s| u64::try_from(s).ok())
        .filter(|&s| s > 0)
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_owned())
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "packetframe".into())
}

fn description(paths: &[&str]) -> String {
    format!("PacketFrame {}", paths.join(" + "))
}

/// A YAML double-quoted scalar.
fn quoted(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Akvorado's static metadata provider (outlet.yaml), for this exporter.
pub fn akvorado(source: IpAddr, exporter: &str, ifaces: &[Iface]) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Akvorado outlet.yaml: the interfaces PacketFrame's flow export reports,\n\
         # by the kernel ifindex its samples carry (an output of 0 is unknown).\n\
         # Merge into an existing metadata.providers list rather than replacing it."
    );
    for i in ifaces.iter().filter(|i| i.ifindex.is_none()) {
        let _ = writeln!(
            out,
            "# {}: not on this host, so it has no ifindex to report",
            i.name
        );
    }
    let _ = writeln!(
        out,
        "metadata:\n  providers:\n    - type: static\n      exporters:\n        {}:\n          name: {}\n          ifindexes:",
        quoted(&source.to_string()),
        quoted(exporter)
    );
    let mut known: Vec<&Iface> = ifaces.iter().filter(|i| i.ifindex.is_some()).collect();
    known.sort_by_key(|i| i.ifindex);
    if known.is_empty() {
        let _ = writeln!(out, "            {{}}");
    }
    for i in known {
        let _ = writeln!(
            out,
            "            {}:\n              name: {}\n              description: {}",
            i.ifindex.unwrap_or_default(),
            quoted(&i.name),
            quoted(&description(&i.paths))
        );
        if let Some(s) = i.speed_mbps {
            let _ = writeln!(out, "              speed: {s}");
        }
    }
    out
}

pub fn table(ifaces: &[Iface]) -> String {
    let mut out = format!(
        "{:<8} {:<16} {:<12} {}\n",
        "ifindex", "interface", "speed", "paths"
    );
    for i in ifaces {
        let _ = writeln!(
            out,
            "{:<8} {:<16} {:<12} {}{}",
            i.ifindex.map_or("-".into(), |x| x.to_string()),
            i.name,
            i.speed_mbps.map_or("-".into(), |s| format!("{s} Mbps")),
            i.paths.join(", "),
            if i.ifindex.is_none() {
                " (not on this host)"
            } else {
                ""
            }
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ifaces() -> Vec<Iface> {
        vec![
            Iface {
                name: "eth3".into(),
                ifindex: Some(5),
                speed_mbps: Some(10_000),
                paths: vec!["fast-path", "VPP"],
            },
            Iface {
                name: "eth0".into(),
                ifindex: Some(2),
                speed_mbps: None,
                paths: vec!["fast-path"],
            },
            Iface {
                name: "eth9".into(),
                ifindex: None,
                speed_mbps: None,
                paths: vec!["VPP"],
            },
        ]
    }

    #[test]
    fn akvorado_gets_a_static_provider_keyed_by_the_source_address() {
        let y = akvorado("192.0.2.1".parse().unwrap(), "edge1", &ifaces());
        let want = "\
metadata:
  providers:
    - type: static
      exporters:
        \"192.0.2.1\":
          name: \"edge1\"
          ifindexes:
            2:
              name: \"eth0\"
              description: \"PacketFrame fast-path\"
            5:
              name: \"eth3\"
              description: \"PacketFrame fast-path + VPP\"
              speed: 10000
";
        assert!(y.ends_with(want), "{y}");
        assert!(y.contains("# eth9: not on this host"), "{y}");
        assert!(y.lines().all(|l| l.starts_with('#') || !l.contains('\t')));
    }

    #[test]
    fn v6_exporters_and_odd_names_stay_valid_yaml() {
        let y = akvorado("2001:db8::1".parse().unwrap(), "a\"b", &[]);
        assert!(y.contains("        \"2001:db8::1\":\n"), "{y}");
        assert!(y.contains("name: \"a\\\"b\""), "{y}");
        assert!(y.contains("ifindexes:\n            {}\n"), "{y}");
    }

    #[test]
    fn the_table_says_what_is_missing() {
        let t = table(&ifaces());
        assert!(
            t.contains("5        eth3             10000 Mbps   fast-path, VPP"),
            "{t}"
        );
        assert!(
            t.contains("eth9") && t.contains("(not on this host)"),
            "{t}"
        );
    }

    #[test]
    fn every_port_is_listed_once_with_every_path_on_it() {
        let config = Config::parse(
            "module fast-path\n  attach eth0 generic\n  attach eth3 generic\n\
             module vpp-offload\n  port eth3 cores 2 steer on\n  port eth9 cores 2 steer off\n\
             module flow-export\n  source-address 192.0.2.1\n  collector c sflow 192.0.2.2:6343\n",
        )
        .unwrap();
        assert_eq!(
            sampled(&config),
            vec![
                ("eth0".to_string(), vec!["fast-path"]),
                ("eth3".to_string(), vec!["fast-path", "VPP"]),
                ("eth9".to_string(), vec!["VPP"]),
            ]
        );
        assert_eq!(source_address(&config), Some("192.0.2.1".parse().unwrap()));
    }
}
