//! One-way fast path: connected routes the kernel delivers while the
//! other direction of their flows bypasses it.
//!
//! Under `packetframe-fib` a route-source feed can deliver a connected
//! prefix with a next hop the fast path can never resolve: unspecified
//! (`0.0.0.0` / `::`, which FRR's `redistribute connected` sends over
//! iBGP) or the router's own address. The FIB holds it `Incomplete`, and
//! XDP passes traffic to its hosts to the kernel. When that prefix has no
//! `local-prefix` but another, allowlisted, `local-prefix` exists, a flow
//! between a host in each is split: traffic from the connected prefix to
//! the allowlisted host matches the allowlist on its destination and
//! takes the host route, while the replies go to the kernel. The kernel
//! never saw the SYN, conntrack marks the SYN-ACK INVALID, a stateful
//! firewall drops it, and the connection times out. Under `kernel-fib`
//! nothing of the sort happened, because `bpf_fib_lookup` resolved the
//! kernel's own connected neighbour — so it appears at the move to
//! `packetframe-fib`, on prefixes nobody thought to declare.
//!
//! The fix is a `local-prefix <cidr> via <iface>` for each such prefix,
//! allowlisted or not. Only a prefix whose hosts reach the router
//! through an `attach` interface can be split: on any other interface (a
//! management NIC) their traffic enters the kernel both ways.
//!
//! This module names the prefixes that need one: a
//! `one-way-fast-path` status row (present only with findings, like
//! vpp-offload's drift rows), a gauge, and a WARN when one appears.
//!
//! Which prefixes the mirror holds this way is the programmer's to say
//! (it owns the mirror and knows which next hops are the router's own);
//! which of them are a hazard is config's
//! ([`packetframe_common::config::one_way_fast_path_routes`]). This
//! module holds both, ungated, so the row is tested on every host. The
//! connected-prefix read under it is Linux's.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use packetframe_common::config::{one_way_fast_path_routes, ModuleDirective};
use packetframe_common::fib::IpPrefix;
use packetframe_common::module::{HealthState, SubsystemHealth};

pub const SUBSYS_ONE_WAY: &str = "one-way-fast-path";

/// A connected route the mirror holds with a next hop the fast path can
/// never resolve, and the interface the kernel has it on (for the
/// suggested `local-prefix ... via <iface>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRoute {
    pub prefix: IpPrefix,
    pub iface: String,
}

/// `addr/len` for a prefix.
pub fn show(p: &IpPrefix) -> String {
    match *p {
        IpPrefix::V4 { addr, prefix_len } => {
            format!("{}/{prefix_len}", std::net::Ipv4Addr::from(addr))
        }
        IpPrefix::V6 { addr, prefix_len } => {
            format!("{}/{prefix_len}", std::net::Ipv6Addr::from(addr))
        }
    }
}

/// The connected prefix an interface address with `prefix_len` puts in
/// the kernel's table, as the mirror would key it (host bits cleared).
/// `None` for what can never be a forwarded subnet: host-length
/// prefixes (a loopback /32, a point-to-point /128: traffic to them is
/// the router's own), loopback, link-local, multicast and unspecified
/// addresses, and a nonsense length.
pub fn connected_prefix(addr: IpAddr, prefix_len: u8) -> Option<IpPrefix> {
    match addr {
        IpAddr::V4(a) => {
            if prefix_len >= 32 || a.is_loopback() || a.is_link_local() || a.is_unspecified() {
                return None;
            }
            let mask = u32::MAX
                .checked_shl(32 - u32::from(prefix_len))
                .unwrap_or(0);
            Some(IpPrefix::V4 {
                addr: (u32::from(a) & mask).to_be_bytes(),
                prefix_len,
            })
        }
        IpAddr::V6(a) => {
            let link_local = a.segments()[0] & 0xffc0 == 0xfe80;
            if prefix_len >= 128
                || a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || link_local
            {
                return None;
            }
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix_len))
                .unwrap_or(0);
            Some(IpPrefix::V6 {
                addr: (u128::from(a) & mask).to_be_bytes(),
                prefix_len,
            })
        }
    }
}

/// The connected prefixes an interface-address read puts in the kernel's
/// table, each with the first interface holding it, in read order. An
/// address with no prefix length, or one [`connected_prefix`] skips,
/// contributes nothing.
pub fn connected_routes(
    ifaddrs: impl IntoIterator<Item = (String, IpAddr, Option<u8>)>,
) -> Vec<KernelRoute> {
    let mut out: Vec<KernelRoute> = Vec::new();
    for (iface, addr, len) in ifaddrs {
        let Some(prefix) = len.and_then(|l| connected_prefix(addr, l)) else {
            continue;
        };
        if !out.iter().any(|r| r.prefix == prefix) {
            out.push(KernelRoute { prefix, iface });
        }
    }
    out
}

/// [`connected_routes`] from the kernel's interface addresses. `None` on
/// a failed read; an empty list is a read that found no subnet (the last
/// one's address went away), which clears the findings.
#[cfg(target_os = "linux")]
pub fn kernel_connected_routes() -> Option<Vec<KernelRoute>> {
    crate::fib::local_nexthops::kernel_ifaddrs().map(connected_routes)
}

/// Whether hosts on `dev` reach the router through the fast path: `dev`
/// or a device under it (`lowers`: a VLAN's parent, a bridge's or bond's
/// ports, and theirs) is one of the `attached` interfaces. Hosts on any
/// other interface (a management NIC, say) enter the kernel in both
/// directions, so none of their flows is one-way, whatever the mirror
/// holds for their subnet.
pub fn on_datapath(dev: &str, attached: &[String], lowers: impl Fn(&str) -> Vec<String>) -> bool {
    let mut seen: HashSet<String> = HashSet::new();
    let mut todo = vec![dev.to_string()];
    while let Some(d) = todo.pop() {
        if attached.contains(&d) {
            return true;
        }
        if seen.insert(d.clone()) {
            todo.extend(lowers(&d));
        }
    }
    false
}

/// The devices directly under `dev`, from its `lower_*` links in sysfs.
/// Empty for a device that is gone or has none.
#[cfg(target_os = "linux")]
pub fn sysfs_lowers(dev: &str) -> Vec<String> {
    if dev.is_empty() || dev.contains('/') || dev == "." || dev == ".." {
        return Vec::new();
    }
    let Ok(entries) = std::fs::read_dir(std::path::Path::new("/sys/class/net").join(dev)) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| {
            let name = e.ok()?.file_name();
            name.to_str()?.strip_prefix("lower_").map(str::to_string)
        })
        .collect()
}

/// Whether a route installed over `nexthops` is one the fast path hands
/// to the kernel for good: every next hop unspecified or the router's
/// own (`is_local`). An empty set is not: it is a route being built.
pub fn kernel_only(nexthops: &[IpAddr], is_local: impl Fn(&IpAddr) -> bool) -> bool {
    !nexthops.is_empty()
        && nexthops
            .iter()
            .all(|ip| ip.is_unspecified() || is_local(ip))
}

/// The warning for one finding: what goes wrong and the line that fixes
/// it.
pub fn warning(r: &KernelRoute) -> String {
    let (directive, host) = match r.prefix {
        IpPrefix::V4 { .. } => ("local-prefix", "/32"),
        IpPrefix::V6 { .. } => ("local-prefix6", "/128"),
    };
    let p = show(&r.prefix);
    format!(
        "one-way fast path: connected route {p} (on {iface}) reaches the fast path with a next \
         hop it cannot resolve (unspecified, or the router's own address), so traffic to its \
         hosts is passed to the kernel, while their traffic to hosts in an allowlisted \
         {directive} takes the {host} host routes and never reaches the kernel. The kernel sees \
         one direction of those flows: conntrack marks the replies INVALID, a stateful firewall \
         drops them and connections time out (kernel-fib resolved the connected neighbour \
         itself, so this appears on the move to packetframe-fib). Fix: add `{directive} {p} \
         via {iface}` (no allow entry is needed) and restart",
        iface = r.iface
    )
}

#[derive(Debug, Default)]
struct Inner {
    directives: Vec<ModuleDirective>,
    /// The last set the programmer observed; `None` before its first
    /// check.
    observed: Option<Vec<KernelRoute>>,
    findings: Vec<KernelRoute>,
}

impl Inner {
    /// Re-derive the findings; return a warning for each one that was
    /// not a finding before.
    fn recompute(&mut self) -> Vec<String> {
        let Some(observed) = &self.observed else {
            return Vec::new();
        };
        let prefixes: Vec<IpPrefix> = observed.iter().map(|r| r.prefix).collect();
        let hazards = one_way_fast_path_routes(&self.directives, &prefixes);
        let findings: Vec<KernelRoute> = observed
            .iter()
            .filter(|r| hazards.contains(&r.prefix))
            .cloned()
            .collect();
        let new = findings
            .iter()
            .filter(|r| !self.findings.contains(r))
            .map(warning)
            .collect();
        self.findings = findings;
        new
    }
}

/// The findings, shared between the programmer that observes the
/// mirror, the reload that changes the config, and the status surfaces.
#[derive(Debug, Default)]
pub struct OneWayWatch(Mutex<Inner>);

pub type SharedOneWay = Arc<OneWayWatch>;

impl OneWayWatch {
    pub fn new(directives: Vec<ModuleDirective>) -> Self {
        Self(Mutex::new(Inner {
            directives,
            ..Inner::default()
        }))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A reload: take the allowlist from `directives` and re-judge.
    /// Returns a warning per new finding, for the caller to log at WARN.
    ///
    /// Only the allowlist: it is hot, while `local-prefix` lines are read
    /// at start and a reload does not apply them. Taking a new one from
    /// the reload would clear a finding whose host routes do not exist
    /// until the restart.
    pub fn set_directives(&self, directives: Vec<ModuleDirective>) -> Vec<String> {
        let is_allow = |d: &ModuleDirective| {
            matches!(
                d,
                ModuleDirective::AllowPrefix4(_) | ModuleDirective::AllowPrefix6(_)
            )
        };
        let mut g = self.lock();
        g.directives.retain(|d| !is_allow(d));
        g.directives
            .extend(directives.into_iter().filter(|d| is_allow(d)));
        g.recompute()
    }

    /// The programmer's latest read of the mirror's kernel-only connected
    /// routes. Returns a warning per new finding, for the caller to log at
    /// WARN; a finding that persists is not repeated.
    pub fn observe(&self, routes: Vec<KernelRoute>) -> Vec<String> {
        let mut g = self.lock();
        g.observed = Some(routes);
        g.recompute()
    }

    pub fn findings(&self) -> Vec<KernelRoute> {
        self.lock().findings.clone()
    }

    /// The `attach` interfaces, read at start like the programs they
    /// load: where the fast path sees traffic.
    pub fn attached(&self) -> Vec<String> {
        self.lock()
            .directives
            .iter()
            .filter_map(|d| match d {
                ModuleDirective::Attach { iface, .. } => Some(iface.clone()),
                _ => None,
            })
            .collect()
    }

    /// The `one-way-fast-path` row: Degraded while any finding stands,
    /// absent otherwise. Nothing being one-way is not news, and an
    /// always-present row would read as a check of something it is not
    /// (it sees only the connected routes the feed delivers).
    pub fn subsystem_health(&self) -> Option<SubsystemHealth> {
        let findings = self.findings();
        if findings.is_empty() {
            return None;
        }
        let named: Vec<String> = findings
            .iter()
            .map(|r| format!("{} on {}", show(&r.prefix), r.iface))
            .collect();
        let mut fixes = String::new();
        for r in &findings {
            let d = match r.prefix {
                IpPrefix::V4 { .. } => "local-prefix",
                IpPrefix::V6 { .. } => "local-prefix6",
            };
            let _ = write!(fixes, "; `{d} {} via {}`", show(&r.prefix), r.iface);
        }
        Some(SubsystemHealth {
            name: SUBSYS_ONE_WAY.to_string(),
            state: HealthState::Degraded,
            message: Some(format!(
                "{} connected route(s) with no local-prefix go to the kernel while their \
                 hosts' traffic to an allowlisted local-prefix is fast-pathed: {}. The kernel \
                 sees one direction of those flows, so conntrack marks the replies INVALID and \
                 a stateful firewall drops them. Add, then restart{fixes}",
                findings.len(),
                named.join(", ")
            )),
            last_success_age_seconds: None,
        })
    }

    /// `packetframe_fib_one_way_routes`: the finding count, 0 once the
    /// programmer has checked and found none. Absent before its first
    /// check, so a fresh start does not read as a clean one.
    pub fn render_metrics(&self, out: &mut String) {
        let g = self.lock();
        if g.observed.is_none() {
            return;
        }
        let _ = writeln!(
            out,
            "# HELP packetframe_fib_one_way_routes connected routes the fast path hands to the \
             kernel while their hosts' traffic to an allowlisted local-prefix bypasses it \
             (add a local-prefix for each)"
        );
        let _ = writeln!(out, "# TYPE packetframe_fib_one_way_routes gauge");
        let _ = writeln!(
            out,
            "packetframe_fib_one_way_routes{{module=\"fast-path\"}} {}",
            g.findings.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn p4(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::V4 {
            addr: a,
            prefix_len: len,
        }
    }

    fn route(a: [u8; 4], len: u8, iface: &str) -> KernelRoute {
        KernelRoute {
            prefix: p4(a, len),
            iface: iface.to_string(),
        }
    }

    fn directives(body: &str) -> Vec<ModuleDirective> {
        packetframe_common::config::Config::parse(&format!("module fast-path\n{body}"))
            .expect("config")
            .modules
            .remove(0)
            .directives
    }

    const ARMED: &str = "  allow-prefix 198.51.100.0/24\n  local-prefix 198.51.100.0/24 via lo\n";

    #[test]
    fn connected_prefix_clears_host_bits_and_skips_non_subnets() {
        assert_eq!(
            connected_prefix(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 24),
            Some(p4([192, 0, 2, 0], 24))
        );
        assert_eq!(
            connected_prefix(IpAddr::V6("2001:db8:20::1".parse().unwrap()), 64),
            Some(IpPrefix::V6 {
                addr: "2001:db8:20::".parse::<Ipv6Addr>().unwrap().octets(),
                prefix_len: 64
            })
        );
        for (a, l) in [
            (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32),
            (IpAddr::V4(Ipv4Addr::LOCALHOST), 8),
            (IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), 16),
            (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
            (IpAddr::V6("fe80::1".parse().unwrap()), 64),
            (IpAddr::V6("2001:db8::1".parse().unwrap()), 128),
        ] {
            assert_eq!(connected_prefix(a, l), None, "{a}/{l}");
        }
    }

    #[test]
    fn connected_routes_dedupe_and_skip_what_is_not_a_subnet() {
        let got = connected_routes([
            (
                "br20".to_string(),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                Some(24),
            ),
            // A second address in the same subnet adds nothing.
            (
                "br20".to_string(),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                Some(24),
            ),
            ("lo".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST), Some(8)),
            (
                "lo".to_string(),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                Some(32),
            ),
            (
                "eth9".to_string(),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                None,
            ),
        ]);
        assert_eq!(got, vec![route([192, 0, 2, 0], 24, "br20")]);
    }

    /// The reference shape: an L3 bridge per VLAN over a VLAN device on
    /// the switch bridge, whose ports include the attached NIC.
    fn lowers_of(dev: &str) -> Vec<String> {
        let l: &[&str] = match dev {
            "br100" => &["switch0.100"],
            "switch0.100" => &["switch0"],
            "switch0" => &["eth1", "eth2"],
            "eth0.5" => &["eth0"],
            // A loop the walk must not spin on.
            "loopy" => &["loopy2"],
            "loopy2" => &["loopy"],
            _ => &[],
        };
        l.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn on_datapath_walks_down_to_an_attached_port() {
        let attached = vec!["eth2".to_string()];
        assert!(on_datapath("br100", &attached, lowers_of));
        assert!(on_datapath("eth2", &attached, lowers_of));
        // A management NIC (and a VLAN on it) the fast path never sees.
        assert!(!on_datapath("eth0", &attached, lowers_of));
        assert!(!on_datapath("eth0.5", &attached, lowers_of));
        assert!(!on_datapath("loopy", &attached, lowers_of));
        // A program on the bridge itself sees its hosts' traffic too.
        assert!(on_datapath("br100", &["br100".to_string()], lowers_of));
    }

    #[test]
    fn attached_lists_the_attach_lines() {
        let w = OneWayWatch::new(directives(&format!(
            "  attach eth2 native\n  attach eth3 generic\n{ARMED}"
        )));
        assert_eq!(w.attached(), vec!["eth2".to_string(), "eth3".to_string()]);
    }

    #[test]
    fn an_empty_observation_clears_the_findings() {
        let w = OneWayWatch::new(directives(ARMED));
        assert_eq!(
            w.observe(vec![route([203, 0, 113, 0], 24, "br200")]).len(),
            1
        );
        assert!(w.subsystem_health().is_some());
        assert!(w.observe(Vec::new()).is_empty());
        assert!(w.findings().is_empty());
        assert!(w.subsystem_health().is_none());
        let mut m = String::new();
        w.render_metrics(&mut m);
        assert!(m.contains("packetframe_fib_one_way_routes{module=\"fast-path\"} 0"));
    }

    #[test]
    fn kernel_only_means_every_next_hop_unspecified_or_local() {
        let own = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let is_local = |ip: &IpAddr| *ip == own;
        assert!(kernel_only(&[IpAddr::V4(Ipv4Addr::UNSPECIFIED)], is_local));
        assert!(kernel_only(&[IpAddr::V6(Ipv6Addr::UNSPECIFIED)], is_local));
        assert!(kernel_only(&[own], is_local));
        let neighbour = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        assert!(!kernel_only(&[neighbour], is_local));
        assert!(!kernel_only(&[own, neighbour], is_local));
        assert!(!kernel_only(&[], is_local));
    }

    /// The reference deployment's shape: one finding, a WARN naming the
    /// fix, a Degraded row, a gauge of 1 — then the operator's
    /// `local-prefix` clears all three.
    #[test]
    fn finding_warns_once_degrades_and_clears_on_the_fix() {
        let w = OneWayWatch::new(directives(ARMED));
        assert!(w.subsystem_health().is_none(), "no row before a check");
        let mut m = String::new();
        w.render_metrics(&mut m);
        assert!(m.is_empty(), "no gauge before a check: {m}");

        let observed = vec![
            route([198, 51, 100, 0], 24, "br1337"),
            route([192, 0, 2, 0], 24, "br20"),
        ];
        let warned = w.observe(observed.clone());
        assert_eq!(warned.len(), 1, "{warned:?}");
        assert!(warned[0].contains("192.0.2.0/24"), "{}", warned[0]);
        assert!(
            warned[0].contains("`local-prefix 192.0.2.0/24 via br20`"),
            "{}",
            warned[0]
        );
        assert!(warned[0].contains("INVALID"), "{}", warned[0]);
        assert!(!warned[0].contains("198.51.100.0/24"), "{}", warned[0]);

        let row = w.subsystem_health().expect("row");
        assert_eq!(row.name, SUBSYS_ONE_WAY);
        assert_eq!(row.state, HealthState::Degraded);
        let msg = row.message.unwrap();
        assert!(msg.contains("192.0.2.0/24 on br20"), "{msg}");
        assert!(
            msg.contains("`local-prefix 192.0.2.0/24 via br20`"),
            "{msg}"
        );
        let mut m = String::new();
        w.render_metrics(&mut m);
        assert!(
            m.contains("packetframe_fib_one_way_routes{module=\"fast-path\"} 1"),
            "{m}"
        );

        // The same set again: no repeat WARN, the row stands.
        assert!(w.observe(observed.clone()).is_empty());
        assert!(w.subsystem_health().is_some());

        // The fix (a restart reads it; the watch is built from it).
        let fixed = OneWayWatch::new(directives(&format!(
            "{ARMED}  local-prefix 192.0.2.0/24 via lo\n"
        )));
        assert!(fixed.observe(observed).is_empty());
        assert!(fixed.subsystem_health().is_none());
        let mut m = String::new();
        fixed.render_metrics(&mut m);
        assert!(
            m.contains("packetframe_fib_one_way_routes{module=\"fast-path\"} 0"),
            "{m}"
        );
    }

    /// A reload that removes the last allowlisted local-prefix's allow
    /// entry disarms the check; one that adds it back warns again.
    #[test]
    fn reload_rederives_the_findings() {
        let w = OneWayWatch::new(directives(ARMED));
        assert_eq!(w.observe(vec![route([192, 0, 2, 0], 24, "br20")]).len(), 1);
        let disarmed = w.set_directives(directives("  local-prefix 198.51.100.0/24 via lo\n"));
        assert!(disarmed.is_empty());
        assert!(w.subsystem_health().is_none());
        assert_eq!(w.set_directives(directives(ARMED)).len(), 1);
        assert!(w.subsystem_health().is_some());
    }

    /// A `local-prefix` added by a reload is not running until a restart,
    /// so it must not clear the finding.
    #[test]
    fn reload_does_not_take_a_new_local_prefix() {
        let w = OneWayWatch::new(directives(ARMED));
        assert_eq!(w.observe(vec![route([192, 0, 2, 0], 24, "br20")]).len(), 1);
        w.set_directives(directives(&format!(
            "{ARMED}  local-prefix 192.0.2.0/24 via lo\n"
        )));
        assert!(w.subsystem_health().is_some(), "cleared by a reload");
    }

    /// A reload before the programmer's first check has nothing to judge.
    #[test]
    fn reload_before_a_check_finds_nothing() {
        let w = OneWayWatch::new(Vec::new());
        assert!(w.set_directives(directives(ARMED)).is_empty());
        assert!(w.subsystem_health().is_none());
    }

    #[test]
    fn v6_warning_names_local_prefix6() {
        let w = OneWayWatch::new(directives(
            "  allow-prefix6 2001:db8:1::/48\n  local-prefix6 2001:db8:1:1337::/64 via lo\n",
        ));
        let warned = w.observe(vec![KernelRoute {
            prefix: IpPrefix::V6 {
                addr: "2001:db8:20::".parse::<Ipv6Addr>().unwrap().octets(),
                prefix_len: 64,
            },
            iface: "br20".into(),
        }]);
        assert_eq!(warned.len(), 1);
        assert!(
            warned[0].contains("`local-prefix6 2001:db8:20::/64 via br20`"),
            "{}",
            warned[0]
        );
        assert!(warned[0].contains("/128 host routes"), "{}", warned[0]);
    }
}
