//! `packetframe flow-export`: what flow export's collectors need to know
//! that its datagrams do not carry.
//!
//! - `interfaces`: every interface flow export's samples can name, by its
//!   ifIndex (the kernel's ifindex; output 0 is unknown): the ports it
//!   samples, and every interface fast-path may redirect to, which a
//!   sample names as its output. For a collector with no SNMP to ask, by
//!   default as Akvorado's static metadata provider, keyed by
//!   `source-address`, the address every collector keys this exporter
//!   on. Akvorado discards a flow naming an interface it has no metadata
//!   for, and requires every interface's speed.
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
        /// An interface's speed in Mbps, over what the kernel reports (it
        /// reports none for a link that is down, or for many virtual
        /// ones). Repeatable: `--speed eth3=10000`.
        #[arg(long = "speed", value_parser = parse_speed)]
        speeds: Vec<(String, u64)>,
        /// The speed in Mbps of an interface with none known, and of a
        /// catch-all entry for any interface not listed (one that comes
        /// up later), so Akvorado keeps flows naming it.
        #[arg(long)]
        default_speed: Option<u64>,
    },
}

fn parse_speed(s: &str) -> Result<(String, u64), String> {
    let (iface, mbps) = s
        .split_once('=')
        .ok_or("expected <interface>=<Mbps>, like eth3=10000")?;
    let mbps: u64 = mbps
        .parse()
        .map_err(|_| format!("`{mbps}` is not a speed in Mbps"))?;
    if iface.is_empty() || mbps == 0 {
        return Err("expected <interface>=<Mbps> with a speed above 0".into());
    }
    Ok((iface.to_owned(), mbps))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Akvorado,
    Table,
}

pub fn run(op: FlowExportOp) -> ExitCode {
    match op {
        FlowExportOp::Interfaces {
            config,
            format,
            speeds,
            default_speed,
        } => interfaces(config, format, &speeds, default_speed),
    }
}

/// An interface a sample can name, as the kernel has it now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iface {
    pub name: String,
    /// `None` when the kernel has no such interface.
    pub ifindex: Option<u32>,
    pub speed_mbps: Option<u64>,
    /// What samples it: `fast-path`, `VPP`. Empty for an interface fast-path
    /// only redirects to.
    pub paths: Vec<&'static str>,
}

fn interfaces(
    config: Option<PathBuf>,
    format: Format,
    speeds: &[(String, u64)],
    default_speed: Option<u64>,
) -> ExitCode {
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
    let mut ifaces = sampled(&config)
        .into_iter()
        .map(|(name, paths)| Iface {
            ifindex: ifindex(&name),
            speed_mbps: speed_mbps(&name),
            name,
            paths,
        })
        .collect::<Vec<_>>();
    // A sample's output: any interface fast-path may redirect to.
    for (name, index) in redirect_targets() {
        if !ifaces.iter().any(|i| i.name == name) {
            ifaces.push(Iface {
                speed_mbps: speed_mbps(&name),
                name,
                ifindex: Some(index),
                paths: Vec::new(),
            });
        }
    }
    for (name, mbps) in speeds {
        match ifaces.iter_mut().find(|i| i.name == *name) {
            Some(i) => i.speed_mbps = Some(*mbps),
            None => {
                eprintln!(
                    "flow-export interfaces: --speed {name}: not an interface flow export reports"
                );
                return ExitCode::from(EXIT_STARTUP_ERROR);
            }
        }
    }
    let out = match format {
        Format::Akvorado => akvorado(source, &hostname(), &ifaces, default_speed),
        Format::Table => Ok(table(&ifaces)),
    };
    match out {
        Ok(text) => {
            print!("{text}");
            ExitCode::from(EXIT_OK)
        }
        Err(e) => {
            eprintln!("flow-export interfaces: {e}");
            ExitCode::from(EXIT_STARTUP_ERROR)
        }
    }
}

#[cfg(target_os = "linux")]
fn redirect_targets() -> Vec<(String, u32)> {
    packetframe_flow_export::redirect_targets()
}

#[cfg(not(target_os = "linux"))]
fn redirect_targets() -> Vec<(String, u32)> {
    Vec::new()
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
    for name in crate::feasibility::kernel_sample_ifaces_from_config(config) {
        add(name, "kernel");
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
    if paths.is_empty() {
        "PacketFrame redirect target".into()
    } else {
        format!("PacketFrame {}", paths.join(" + "))
    }
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

/// Akvorado's static metadata provider (outlet.yaml), for this exporter:
/// every interface listed with a speed (Akvorado requires one), or why
/// not. `default_speed` stands in for an unknown speed, and adds a
/// catch-all entry for any interface not listed.
pub fn akvorado(
    source: IpAddr,
    exporter: &str,
    ifaces: &[Iface],
    default_speed: Option<u64>,
) -> Result<String, String> {
    let mut known: Vec<&Iface> = ifaces.iter().filter(|i| i.ifindex.is_some()).collect();
    known.sort_by_key(|i| i.ifindex);
    let unsped: Vec<&str> = known
        .iter()
        .filter(|i| i.speed_mbps.or(default_speed).is_none())
        .map(|i| i.name.as_str())
        .collect();
    if !unsped.is_empty() {
        return Err(format!(
            "Akvorado requires every interface's speed, and the kernel reports none for {}: \
             pass `--speed <interface>=<Mbps>` for each, or `--default-speed <Mbps>`",
            unsped.join(", ")
        ));
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# Akvorado outlet.yaml: every interface PacketFrame's flow export can name,\n\
         # by the kernel ifindex its samples carry (an output of 0 is unknown).\n\
         # Merge into an existing metadata.providers list rather than replacing it."
    );
    if default_speed.is_none() {
        let _ = writeln!(
            out,
            "# Akvorado discards a flow naming an interface not listed here (one that\n\
             # comes up later): `--default-speed <Mbps>` adds a catch-all entry."
        );
    }
    for i in ifaces.iter().filter(|i| i.ifindex.is_none()) {
        let _ = writeln!(
            out,
            "# {}: not on this host, so it has no ifindex to report",
            i.name
        );
    }
    let _ = writeln!(
        out,
        "metadata:\n  providers:\n    - type: static\n      exporters:\n        {}:\n          name: {}",
        quoted(&source.to_string()),
        quoted(exporter)
    );
    if let Some(speed) = default_speed {
        let _ = writeln!(
            out,
            "          default:\n            name: \"unknown\"\n            description: \
             \"not an interface PacketFrame reports\"\n            speed: {speed}"
        );
    }
    let _ = writeln!(out, "          ifindexes:");
    if known.is_empty() {
        let _ = writeln!(out, "            {{}}");
    }
    for i in known {
        let _ = writeln!(
            out,
            "            {}:\n              name: {}\n              description: {}\n              speed: {}",
            i.ifindex.unwrap_or_default(),
            quoted(&i.name),
            quoted(&description(&i.paths)),
            i.speed_mbps.or(default_speed).unwrap_or_default()
        );
    }
    Ok(out)
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
            if i.paths.is_empty() {
                "redirect target".to_string()
            } else {
                i.paths.join(", ")
            },
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
    fn akvorado_gets_every_interface_a_sample_can_name_with_a_speed() {
        let mut list = ifaces();
        list.push(Iface {
            name: "eth7".into(),
            ifindex: Some(8),
            speed_mbps: Some(1000),
            paths: Vec::new(),
        });
        let y = akvorado("192.0.2.1".parse().unwrap(), "edge1", &list, Some(100)).unwrap();
        let want = "\
metadata:
  providers:
    - type: static
      exporters:
        \"192.0.2.1\":
          name: \"edge1\"
          default:
            name: \"unknown\"
            description: \"not an interface PacketFrame reports\"
            speed: 100
          ifindexes:
            2:
              name: \"eth0\"
              description: \"PacketFrame fast-path\"
              speed: 100
            5:
              name: \"eth3\"
              description: \"PacketFrame fast-path + VPP\"
              speed: 10000
            8:
              name: \"eth7\"
              description: \"PacketFrame redirect target\"
              speed: 1000
";
        assert!(y.ends_with(want), "{y}");
        assert!(y.contains("# eth9: not on this host"), "{y}");
        assert!(!y.contains("--default-speed"), "a catch-all is there: {y}");
        assert!(y.lines().all(|l| l.starts_with('#') || !l.contains('\t')));
    }

    /// Akvorado refuses an interface without a speed: the output is never
    /// one it would refuse.
    #[test]
    fn an_interface_with_no_speed_known_is_refused_with_the_way_out() {
        let e = akvorado("192.0.2.1".parse().unwrap(), "edge1", &ifaces(), None).unwrap_err();
        assert!(
            e.contains("none for eth0") && e.contains("--speed") && e.contains("--default-speed"),
            "{e}"
        );
        let mut sped = ifaces();
        sped[1].speed_mbps = Some(1000);
        let y = akvorado("192.0.2.1".parse().unwrap(), "edge1", &sped, None).unwrap();
        assert!(!y.contains("default:"), "{y}");
        assert!(
            y.contains("`--default-speed <Mbps>` adds a catch-all"),
            "{y}"
        );
    }

    #[test]
    fn v6_exporters_and_odd_names_stay_valid_yaml() {
        let y = akvorado("2001:db8::1".parse().unwrap(), "a\"b", &[], None).unwrap();
        assert!(y.contains("        \"2001:db8::1\":\n"), "{y}");
        assert!(y.contains("name: \"a\\\"b\""), "{y}");
        assert!(y.contains("ifindexes:\n            {}\n"), "{y}");
    }

    #[test]
    fn speeds_are_interface_equals_mbps() {
        assert_eq!(parse_speed("eth3=10000"), Ok(("eth3".into(), 10_000)));
        for bad in ["eth3", "eth3=fast", "=100", "eth3=0"] {
            assert!(parse_speed(bad).is_err(), "{bad}");
        }
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
             module flow-export\n  source-address 192.0.2.1\n  collector c sflow 192.0.2.2:6343\n\
             \x20 kernel-sample tun0\n",
        )
        .unwrap();
        assert_eq!(
            sampled(&config),
            vec![
                ("eth0".to_string(), vec!["fast-path"]),
                ("eth3".to_string(), vec!["fast-path", "VPP"]),
                ("eth9".to_string(), vec!["VPP"]),
                ("tun0".to_string(), vec!["kernel"]),
            ]
        );
        assert_eq!(source_address(&config), Some("192.0.2.1".parse().unwrap()));
    }
}
