//! Typed neigh-snoop configuration built from the section's
//! directives. Deliberately portable (no cfg gates) so parsing,
//! validation parity and `restart_only_delta` are tested on macOS.
//!
//! `from_directives` re-checks every rule `Config::validate_neigh_snoop`
//! enforces that can be judged from the section alone, so the module
//! gives the same verdict even if a caller skipped the config-level
//! validator. The two rules that need the whole config (`persist-dir`
//! vs `state-dir`, the fast-path requirement) stay in the validator.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use packetframe_common::config::{
    format_mac, ModuleDirective, NEIGH_SNOOP_DEFAULT_COVERAGE_INTERVAL,
    NEIGH_SNOOP_DEFAULT_INSTALL_RATE, NEIGH_SNOOP_DEFAULT_RS_COVERAGE_INTERVAL,
    NEIGH_SNOOP_DEFAULT_SEED_MAX_AGE, NEIGH_SNOOP_DEFAULT_TABLE_MAX, NEIGH_SNOOP_MAX_BRIDGES,
    NEIGH_SNOOP_PERSIST_SUBDIR,
};

/// One router on the fabric: every address it uses there, and whether
/// it is a route server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCfg {
    pub addrs: Vec<IpAddr>,
    pub route_server: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeCfg {
    pub name: String,
    pub ix_mode: bool,
    pub prefixes: Vec<ipnet::IpNet>,
    pub peers: Vec<PeerCfg>,
}

impl BridgeCfg {
    /// Every configured peer address on this bridge.
    pub fn peer_addrs(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.peers.iter().flat_map(|p| p.addrs.iter().copied())
    }

    /// The other addresses of the router that owns `ip`, if `ip` is a
    /// declared peer address.
    pub fn siblings_of(&self, ip: &IpAddr) -> Option<&[IpAddr]> {
        self.peers
            .iter()
            .find(|p| p.addrs.contains(ip))
            .map(|p| p.addrs.as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateCfg {
    pub v4_list: String,
    pub v6_list: String,
    pub interval: Duration,
    pub remove_after: Duration,
}

/// The directives a SIGHUP may change without a restart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotConfig {
    pub seed_max_age: Duration,
    pub install_rate: (u32, Duration),
    pub table_max: u32,
    pub coverage_interval: Duration,
    pub rs_coverage_interval: Duration,
}

impl Default for HotConfig {
    fn default() -> Self {
        Self {
            seed_max_age: NEIGH_SNOOP_DEFAULT_SEED_MAX_AGE,
            install_rate: NEIGH_SNOOP_DEFAULT_INSTALL_RATE,
            table_max: NEIGH_SNOOP_DEFAULT_TABLE_MAX,
            coverage_interval: NEIGH_SNOOP_DEFAULT_COVERAGE_INTERVAL,
            rs_coverage_interval: NEIGH_SNOOP_DEFAULT_RS_COVERAGE_INTERVAL,
        }
    }
}

impl HotConfig {
    /// Time between two kernel installs at the configured rate.
    pub fn install_period(&self) -> Duration {
        let (n, per) = self.install_rate;
        per / n.max(1)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnoopConfig {
    pub bridges: Vec<BridgeCfg>,
    pub deny_macs: Vec<[u8; 6]>,
    pub persist_dir: Option<PathBuf>,
    pub gate: Option<GateCfg>,
    pub hot: HotConfig,
}

impl SnoopConfig {
    pub fn from_directives(directives: &[ModuleDirective]) -> Result<Self, String> {
        let mut bridges: Vec<BridgeCfg> = Vec::new();
        for d in directives {
            if let ModuleDirective::SnoopBridge { iface, ix_mode, .. } = d {
                if bridges.iter().any(|b| b.name == *iface) {
                    return Err(format!("duplicate `bridge {iface}`"));
                }
                bridges.push(BridgeCfg {
                    name: iface.clone(),
                    ix_mode: *ix_mode,
                    prefixes: Vec::new(),
                    peers: Vec::new(),
                });
            }
        }
        if bridges.is_empty() {
            return Err("section declares no `bridge` lines".to_string());
        }
        if bridges.len() > NEIGH_SNOOP_MAX_BRIDGES {
            return Err(format!(
                "{} `bridge` lines exceed the {NEIGH_SNOOP_MAX_BRIDGES} the module supports",
                bridges.len()
            ));
        }

        fn bridge_of<'a>(
            bridges: &'a mut [BridgeCfg],
            iface: &str,
            what: &str,
        ) -> Result<&'a mut BridgeCfg, String> {
            bridges
                .iter_mut()
                .find(|b| b.name == iface)
                .ok_or_else(|| format!("`{what} {iface}` names a bridge with no `bridge` line"))
        }

        let mut deny_macs: Vec<[u8; 6]> = Vec::new();
        let mut persist_dir = None;
        let mut gate = None;
        let mut hot = HotConfig::default();
        let mut seen: Vec<&'static str> = Vec::new();
        let mut singleton = |name: &'static str| -> Result<(), String> {
            if seen.contains(&name) {
                return Err(format!("`{name}` may appear once"));
            }
            seen.push(name);
            Ok(())
        };
        let mut all_peer_addrs: Vec<IpAddr> = Vec::new();

        for d in directives {
            match d {
                ModuleDirective::SnoopPrefix { iface, cidr, .. } => {
                    let b = bridge_of(&mut bridges, iface, "prefix")?;
                    if b.prefixes.contains(cidr) {
                        return Err(format!("duplicate `prefix {iface} {cidr}`"));
                    }
                    b.prefixes.push(*cidr);
                }
                ModuleDirective::SnoopDenyMac { mac, .. } => {
                    if deny_macs.contains(mac) {
                        return Err(format!("duplicate `deny-mac {}`", format_mac(*mac)));
                    }
                    deny_macs.push(*mac);
                }
                ModuleDirective::SnoopPeer {
                    iface,
                    addrs,
                    route_server,
                    ..
                } => {
                    for a in addrs {
                        if all_peer_addrs.contains(a) {
                            return Err(format!("peer address {a} appears twice"));
                        }
                        all_peer_addrs.push(*a);
                    }
                    let b = bridge_of(&mut bridges, iface, "peer")?;
                    b.peers.push(PeerCfg {
                        addrs: addrs.clone(),
                        route_server: *route_server,
                    });
                }
                ModuleDirective::SnoopPersistDir { path, .. } => {
                    singleton("persist-dir")?;
                    persist_dir = Some(path.clone());
                }
                ModuleDirective::SnoopSeedMaxAge { max_age, .. } => {
                    singleton("seed-max-age")?;
                    hot.seed_max_age = *max_age;
                }
                ModuleDirective::SnoopInstallRate { rate, per, .. } => {
                    singleton("install-rate")?;
                    hot.install_rate = (*rate, *per);
                }
                ModuleDirective::SnoopTableMax { max, .. } => {
                    singleton("table-max")?;
                    hot.table_max = *max;
                }
                ModuleDirective::SnoopCoverageInterval { interval, .. } => {
                    singleton("coverage-interval")?;
                    hot.coverage_interval = *interval;
                }
                ModuleDirective::SnoopFrrGate {
                    v4_list,
                    v6_list,
                    interval,
                    remove_after,
                    ..
                } => {
                    singleton("frr-gate")?;
                    gate = Some(GateCfg {
                        v4_list: v4_list.clone(),
                        v6_list: v6_list.clone(),
                        interval: *interval,
                        remove_after: *remove_after,
                    });
                }
                ModuleDirective::SnoopRsCoverageInterval { interval, .. } => {
                    singleton("rs-coverage-interval")?;
                    hot.rs_coverage_interval = *interval;
                }
                // Foreign directives: the namespace is shared.
                _ => {}
            }
        }

        for b in &bridges {
            if b.prefixes.is_empty() {
                return Err(format!("`bridge {}` has no `prefix` lines", b.name));
            }
            for a in b.peer_addrs() {
                if !b.prefixes.iter().any(|p| p.contains(&a)) {
                    return Err(format!("peer {a} is outside every `prefix` of {}", b.name));
                }
            }
            let n = b.peer_addrs().count();
            if n > hot.table_max as usize {
                return Err(format!(
                    "{n} peer addresses on {} exceed `table-max {}`",
                    b.name, hot.table_max
                ));
            }
        }
        if gate.is_none()
            && bridges
                .iter()
                .any(|b| b.peers.iter().any(|p| p.route_server))
        {
            return Err("`peer ... route-server` requires `frr-gate`".to_string());
        }

        Ok(Self {
            bridges,
            deny_macs,
            persist_dir,
            gate,
            hot,
        })
    }

    /// Where the per-bridge JSON files live.
    pub fn resolve_persist_dir(&self, state_dir: &Path) -> PathBuf {
        self.persist_dir
            .clone()
            .unwrap_or_else(|| state_dir.join(NEIGH_SNOOP_PERSIST_SUBDIR))
    }

    /// Bridge names flagged `ix-mode`, for fast-path's resolver.
    pub fn ix_mode_ifaces(&self) -> Vec<String> {
        self.bridges
            .iter()
            .filter(|b| b.ix_mode)
            .map(|b| b.name.clone())
            .collect()
    }

    /// Refuse, by name, the deltas a SIGHUP cannot apply: the bridge
    /// set and each bridge's `ix-mode` (the capture socket, the
    /// persisted file and fast-path's resolver policy are bound at
    /// attach), `persist-dir` (file handles and seed source), and the
    /// presence or list names of `frr-gate` (the reconciler's identity
    /// in FRR). Everything else reconciles live.
    pub fn restart_only_delta(&self, new: &Self) -> Result<(), String> {
        const HOW: &str =
            "Restart the daemon (stop, `packetframe detach`, start) for it to take effect.";
        for b in &self.bridges {
            match new.bridges.iter().find(|n| n.name == b.name) {
                None => {
                    return Err(format!(
                        "`bridge {}` was removed; the bridge set is restart-only. {HOW}",
                        b.name
                    ))
                }
                Some(n) if n.ix_mode != b.ix_mode => {
                    return Err(format!(
                        "`ix-mode` on `bridge {}` changed; fast-path's resolver reads it at \
                         start. {HOW}",
                        b.name
                    ))
                }
                Some(_) => {}
            }
        }
        for n in &new.bridges {
            if !self.bridges.iter().any(|b| b.name == n.name) {
                return Err(format!(
                    "`bridge {}` was added; the bridge set is restart-only. {HOW}",
                    n.name
                ));
            }
        }
        if self.persist_dir != new.persist_dir {
            return Err(format!("`persist-dir` changed; it is restart-only. {HOW}"));
        }
        match (&self.gate, &new.gate) {
            (None, None) => {}
            (Some(a), Some(b)) if a.v4_list == b.v4_list && a.v6_list == b.v6_list => {}
            (Some(_), None) | (None, Some(_)) => {
                return Err(format!(
                    "`frr-gate` was added or removed; its presence is restart-only. {HOW}"
                ))
            }
            (Some(_), Some(_)) => {
                return Err(format!(
                    "`frr-gate` list names changed; they are restart-only. {HOW}"
                ))
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::config::Config;

    fn section(body: &str) -> Vec<ModuleDirective> {
        let s = format!("module fast-path\n  attach eth0 generic\nmodule neigh-snoop\n{body}");
        Config::parse(&s).unwrap().modules.remove(1).directives
    }

    const REFERENCE: &str = "  bridge br0 ix-mode\n  bridge br1\n  prefix br0 192.0.2.0/24\n  \
                             prefix br0 2001:db8:1::/64\n  prefix br1 198.51.100.0/24\n  \
                             deny-mac 02:00:00:00:00:01\n  \
                             peer br0 192.0.2.10 2001:db8:1::10 route-server\n  \
                             peer br1 198.51.100.20\n  \
                             persist-dir /var/lib/packetframe/state/neigh-cache\n  \
                             seed-max-age 7d\n  install-rate 20/1s\n  table-max 512\n  \
                             coverage-interval 120s\n  \
                             frr-gate v4 A v6 B interval 60s remove-after 300s\n  \
                             rs-coverage-interval 600s\n";

    #[test]
    fn from_directives_round_trip() {
        let c = SnoopConfig::from_directives(&section(REFERENCE)).unwrap();
        assert_eq!(c.bridges.len(), 2);
        assert!(c.bridges[0].ix_mode);
        assert_eq!(c.bridges[0].prefixes.len(), 2);
        assert_eq!(c.bridges[0].peers[0].addrs.len(), 2);
        assert!(c.bridges[0].peers[0].route_server);
        assert_eq!(c.bridges[1].peers[0].addrs.len(), 1);
        assert_eq!(c.deny_macs, vec![[0x02, 0, 0, 0, 0, 1]]);
        assert_eq!(
            c.persist_dir.as_deref(),
            Some(Path::new("/var/lib/packetframe/state/neigh-cache"))
        );
        assert_eq!(c.hot.seed_max_age, Duration::from_secs(7 * 86_400));
        assert_eq!(c.hot.install_rate, (20, Duration::from_secs(1)));
        assert_eq!(c.hot.install_period(), Duration::from_millis(50));
        assert_eq!(c.hot.table_max, 512);
        assert_eq!(c.hot.coverage_interval, Duration::from_secs(120));
        assert_eq!(c.hot.rs_coverage_interval, Duration::from_secs(600));
        let g = c.gate.as_ref().unwrap();
        assert_eq!((g.v4_list.as_str(), g.v6_list.as_str()), ("A", "B"));
        assert_eq!(g.interval, Duration::from_secs(60));
        assert_eq!(c.ix_mode_ifaces(), vec!["br0".to_string()]);
        let v4: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(c.bridges[0].siblings_of(&v4).unwrap().len(), 2);
        assert!(c.bridges[0]
            .siblings_of(&"192.0.2.99".parse().unwrap())
            .is_none());
    }

    #[test]
    fn defaults_apply_when_omitted() {
        let c = SnoopConfig::from_directives(&section("  bridge br0\n  prefix br0 192.0.2.0/24\n"))
            .unwrap();
        assert_eq!(c.hot, HotConfig::default());
        assert!(c.persist_dir.is_none());
        assert!(c.gate.is_none());
        assert_eq!(
            c.resolve_persist_dir(Path::new("/var/lib/packetframe/state")),
            PathBuf::from("/var/lib/packetframe/state/neigh-cache")
        );
    }

    /// Every rule the config validator enforces from the section alone
    /// is refused here too, with a recognizable message.
    #[test]
    fn refusals_match_the_config_validator() {
        let ok = "  bridge br0\n  prefix br0 192.0.2.0/24\n";
        let cases = [
            ("  attach eth1 generic\n", "no `bridge` lines"),
            (&format!("{ok}  bridge br0\n"), "duplicate `bridge br0`"),
            (
                &format!("{ok}  prefix br9 192.0.2.0/24\n"),
                "no `bridge` line",
            ),
            (&format!("{ok}  peer br9 192.0.2.5\n"), "no `bridge` line"),
            (
                &format!("{ok}  bridge br1\n"),
                "`bridge br1` has no `prefix` lines",
            ),
            (
                &format!("{ok}  prefix br0 192.0.2.0/24\n"),
                "duplicate `prefix",
            ),
            (
                &format!("{ok}  deny-mac 02:00:00:00:00:01\n  deny-mac 02:00:00:00:00:01\n"),
                "duplicate `deny-mac",
            ),
            (
                &format!("{ok}  peer br0 192.0.2.5\n  peer br0 192.0.2.5\n"),
                "appears twice",
            ),
            (
                &format!("{ok}  peer br0 198.51.100.5\n"),
                "outside every `prefix`",
            ),
            (
                &format!(
                    "{ok}  table-max 16\n{}",
                    (1..=17)
                        .map(|i| format!("  peer br0 192.0.2.{i}\n"))
                        .collect::<String>()
                ),
                "exceed `table-max 16`",
            ),
            (
                &format!("{ok}  table-max 16\n  table-max 32\n"),
                "may appear once",
            ),
            (
                &format!("{ok}  peer br0 192.0.2.5 route-server\n"),
                "requires `frr-gate`",
            ),
        ];
        for (body, want) in cases {
            let e = SnoopConfig::from_directives(&section(body)).expect_err(body);
            assert!(e.contains(want), "for `{body}`: `{e}`");
        }
        let mut s = String::new();
        for i in 0..=NEIGH_SNOOP_MAX_BRIDGES {
            s.push_str(&format!("  bridge b{i}\n  prefix b{i} 192.0.2.0/24\n"));
        }
        let e = SnoopConfig::from_directives(&section(&s)).unwrap_err();
        assert!(e.contains("exceed the 16"), "{e}");
    }

    #[test]
    fn restart_only_delta_matrix() {
        let base = SnoopConfig::from_directives(&section(REFERENCE)).unwrap();
        let ok = |body: &str| SnoopConfig::from_directives(&section(body)).unwrap();
        // Hot changes accepted.
        let hot = ok(&REFERENCE
            .replace("seed-max-age 7d", "seed-max-age 21d")
            .replace("install-rate 20/1s", "install-rate 1/60s")
            .replace("table-max 512", "table-max 64")
            .replace("coverage-interval 120s", "coverage-interval 30s")
            .replace("remove-after 300s", "remove-after 0s")
            .replace("rs-coverage-interval 600s", "rs-coverage-interval 900s")
            .replace("deny-mac 02:00:00:00:00:01", "deny-mac 02:00:00:00:00:09")
            .replace(
                "peer br1 198.51.100.20",
                "peer br1 198.51.100.21 198.51.100.22",
            )
            .replace(
                "prefix br1 198.51.100.0/24",
                "prefix br1 198.51.100.0/24\n  prefix br1 203.0.113.0/24",
            ));
        base.restart_only_delta(&hot).expect("hot deltas accepted");

        let refused = [
            (
                REFERENCE
                    .replace("  bridge br1\n", "")
                    .replace("  prefix br1 198.51.100.0/24\n", "")
                    .replace("  peer br1 198.51.100.20\n", ""),
                "`bridge br1` was removed",
            ),
            (
                REFERENCE.replace(
                    "bridge br1\n",
                    "bridge br1\n  bridge br2\n  prefix br2 203.0.113.0/24\n",
                ),
                "`bridge br2` was added",
            ),
            (
                REFERENCE.replace("bridge br0 ix-mode", "bridge br0"),
                "`ix-mode` on `bridge br0` changed",
            ),
            (
                REFERENCE.replace(
                    "persist-dir /var/lib/packetframe/state/neigh-cache",
                    "persist-dir /data/neigh-cache",
                ),
                "`persist-dir` changed",
            ),
            (
                REFERENCE.replace("frr-gate v4 A v6 B", "frr-gate v4 A v6 C"),
                "list names changed",
            ),
            (
                REFERENCE
                    .replace("  frr-gate v4 A v6 B interval 60s remove-after 300s\n", "")
                    .replace(" route-server", ""),
                "`frr-gate` was added or removed",
            ),
        ];
        for (body, want) in refused {
            let new = ok(&body);
            let e = base.restart_only_delta(&new).expect_err(want);
            assert!(e.contains(want), "{e}");
            assert!(e.contains("packetframe detach"), "{e}");
        }
    }
}
