//! Parsed guard configuration + the BPF wire struct it compiles to.
//!
//! Deliberately portable (no cfg gates): `from_directives`,
//! `restart_only_delta`, and the `GuardIfCfg` layout tests all run on
//! macOS dev laptops. The Linux-only attach path consumes the result.

use std::time::Duration;

use packetframe_common::config::ModuleDirective;

/// Per-class action byte written into [`GuardIfCfg`]. Plain u8 consts
/// rather than an enum: the BPF side compares raw bytes, and an enum
/// would invite a `mem::transmute` on the read path.
pub const ACTION_DISABLED: u8 = 0;
pub const ACTION_MONITOR: u8 = 1;
pub const ACTION_ENFORCE: u8 = 2;

/// Layout version stamped into [`GuardIfCfg::version`]. Bump on any
/// field change; the BPF side ignores entries whose version it does
/// not recognize (fail open), which turns a userspace/ELF skew into a
/// counter anomaly instead of misclassification.
pub const GUARD_CFG_VERSION: u32 = 1;

/// One ratelimit class rule as configured (pre-compilation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateRule {
    pub rate: u32,
    pub per: Duration,
    pub burst: u32,
    pub monitor: bool,
}

/// One drop/monitor class rule as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRule {
    pub monitor: bool,
}

/// The full rule set for one guarded interface.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GuardIfaceRules {
    pub arp_ns: Option<RateRule>,
    pub bcast_mcast: Option<RateRule>,
    pub lldp: Option<ActionRule>,
    pub foreign_src: Option<ActionRule>,
}

/// Parsed `module guard` section: interfaces in config order, each
/// with its class rules.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GuardConfig {
    pub interfaces: Vec<(String, GuardIfaceRules)>,
}

impl GuardConfig {
    /// Build from the section's directives. Re-checks the invariants
    /// `Config::validate_guard` enforces (undeclared interfaces,
    /// duplicates, ruleless interfaces) so the module gives the same
    /// verdict even if a caller skipped the config-level validator.
    /// Foreign directives (the namespace is shared across module
    /// sections) are ignored, matching the other modules.
    pub fn from_directives(directives: &[ModuleDirective]) -> Result<Self, String> {
        let mut interfaces: Vec<(String, GuardIfaceRules)> = Vec::new();
        for d in directives {
            if let ModuleDirective::GuardInterface { iface, .. } = d {
                if interfaces.iter().any(|(i, _)| i == iface) {
                    return Err(format!("duplicate `interface {iface}`"));
                }
                interfaces.push((iface.clone(), GuardIfaceRules::default()));
            }
        }

        fn rules_of<'a>(
            interfaces: &'a mut [(String, GuardIfaceRules)],
            iface: &String,
            class: &str,
        ) -> Result<&'a mut GuardIfaceRules, String> {
            interfaces
                .iter_mut()
                .find(|(i, _)| i == iface)
                .map(|(_, r)| r)
                .ok_or_else(|| {
                    format!("`{class} {iface}` names an interface with no `interface` line")
                })
        }

        for d in directives {
            match d {
                ModuleDirective::GuardArpNsRatelimit {
                    iface,
                    rate,
                    per,
                    burst,
                    monitor,
                    ..
                } => {
                    let r = rules_of(&mut interfaces, iface, "arp-ns-ratelimit")?;
                    if r.arp_ns.is_some() {
                        return Err(format!("duplicate `arp-ns-ratelimit` for {iface}"));
                    }
                    r.arp_ns = Some(RateRule {
                        rate: *rate,
                        per: *per,
                        burst: *burst,
                        monitor: *monitor,
                    });
                }
                ModuleDirective::GuardBcastMcastRatelimit {
                    iface,
                    rate,
                    per,
                    burst,
                    monitor,
                    ..
                } => {
                    let r = rules_of(&mut interfaces, iface, "bcast-mcast-ratelimit")?;
                    if r.bcast_mcast.is_some() {
                        return Err(format!("duplicate `bcast-mcast-ratelimit` for {iface}"));
                    }
                    r.bcast_mcast = Some(RateRule {
                        rate: *rate,
                        per: *per,
                        burst: *burst,
                        monitor: *monitor,
                    });
                }
                ModuleDirective::GuardLldp { iface, monitor, .. } => {
                    let r = rules_of(&mut interfaces, iface, "lldp")?;
                    if r.lldp.is_some() {
                        return Err(format!("duplicate `lldp` for {iface}"));
                    }
                    r.lldp = Some(ActionRule { monitor: *monitor });
                }
                ModuleDirective::GuardForeignSrc { iface, monitor, .. } => {
                    let r = rules_of(&mut interfaces, iface, "foreign-src")?;
                    if r.foreign_src.is_some() {
                        return Err(format!("duplicate `foreign-src` for {iface}"));
                    }
                    r.foreign_src = Some(ActionRule { monitor: *monitor });
                }
                _ => {}
            }
        }

        // ≥1 `interface` line, matching `Config::validate_guard` —
        // the shared directive namespace means a guard section holding
        // only another module's directives parses to an empty attach
        // set here, which would load and report healthy while policing
        // nothing (review finding, PR #204).
        if interfaces.is_empty() {
            return Err("section declares no `interface` lines".to_string());
        }
        // ...and at most GUARD_CFG's capacity, again matching the
        // validator: overrunning the map would fail mid-attach with
        // the first 64 filters already live (review finding, PR #205).
        if interfaces.len() > packetframe_common::config::GUARD_MAX_INTERFACES {
            return Err(format!(
                "{} `interface` lines exceed the {} the datapath's per-interface \
                 config map holds",
                interfaces.len(),
                packetframe_common::config::GUARD_MAX_INTERFACES
            ));
        }
        for (iface, rules) in &interfaces {
            if *rules == GuardIfaceRules::default() {
                return Err(format!("`interface {iface}` declares no rules"));
            }
        }
        Ok(GuardConfig { interfaces })
    }

    /// Refuse the config deltas a SIGHUP cannot apply, by name. The
    /// interface set is attach-time-bound (the tc filter and the
    /// expected-MAC snapshot are created at attach), so adding or
    /// removing an `interface` line needs the restart dance. Everything
    /// else — rates, burst, monitor↔enforce, adding or removing class
    /// rules on an attached interface — is a per-ifindex config-map
    /// rewrite and is accepted.
    pub fn restart_only_delta(&self, new: &Self) -> Result<(), String> {
        let old_set: Vec<&String> = self.interfaces.iter().map(|(i, _)| i).collect();
        let new_set: Vec<&String> = new.interfaces.iter().map(|(i, _)| i).collect();
        for iface in &old_set {
            if !new_set.contains(iface) {
                return Err(format!(
                    "`interface {iface}` was removed; the guard attach set is \
                     restart-only. Restart the daemon (stop, `packetframe detach`, \
                     start) for it to take effect."
                ));
            }
        }
        for iface in &new_set {
            if !old_set.contains(iface) {
                return Err(format!(
                    "`interface {iface}` was added; the guard attach set is \
                     restart-only. Restart the daemon (stop, `packetframe detach`, \
                     start) for it to take effect."
                ));
            }
        }
        Ok(())
    }
}

/// The per-ifindex wire struct written into the BPF `GUARD_CFG` map.
/// 48 bytes, `#[repr(C)]`, zero implicit padding — layout mirrored in
/// the BPF crate; the tests below pin size and offsets so drift is a
/// compile-time/test-time failure, not a misparse on the wire.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct GuardIfCfg {
    /// Expected src MAC, wire bytes 0..4 as a native-endian u32
    /// (`u32::from_ne_bytes(mac[0..4])`). Compared against a
    /// `read_unaligned` load at eth offset 6 — raw-byte equality, so
    /// endianness cancels.
    pub mac_hi: u32,
    /// Wire bytes 4..6, same convention.
    pub mac_lo: u16,
    pub act_arp: u8,
    pub act_ns: u8,
    pub act_lldp: u8,
    pub act_foreign: u8,
    pub act_mcast: u8,
    /// Always written 0; keeps the layout explicit-padding-only.
    pub _pad0: u8,
    pub version: u32,
    /// GCRA emission interval for the ARP-request/NS buckets,
    /// ns per token (`per / rate`). 0 = bucket bypass (pass).
    pub ndp_t_ns: u64,
    /// GCRA burst tolerance: `(burst - 1) * ndp_t_ns`, precomputed
    /// here so the datapath does no arithmetic beyond add/compare.
    pub ndp_tau_ns: u64,
    pub mcast_t_ns: u64,
    pub mcast_tau_ns: u64,
}

impl GuardIfCfg {
    /// Compile one interface's rules + its observed MAC into the wire
    /// struct. `rate`/`per`/`burst` bounds were enforced at config
    /// parse (interval ≤ 3600s, per-token ≥ 1µs, burst ≤ 65535), so
    /// the ns math here cannot overflow u64.
    pub fn compile(mac: [u8; 6], rules: &GuardIfaceRules) -> Self {
        let rate_fields = |r: &Option<RateRule>| -> (u8, u64, u64) {
            match r {
                None => (ACTION_DISABLED, 0, 0),
                Some(r) => {
                    let t_ns = (r.per.as_nanos() / u128::from(r.rate)) as u64;
                    let tau_ns = u64::from(r.burst - 1) * t_ns;
                    let act = if r.monitor {
                        ACTION_MONITOR
                    } else {
                        ACTION_ENFORCE
                    };
                    (act, t_ns, tau_ns)
                }
            }
        };
        let action = |a: &Option<ActionRule>| -> u8 {
            match a {
                None => ACTION_DISABLED,
                Some(ActionRule { monitor: true }) => ACTION_MONITOR,
                Some(ActionRule { monitor: false }) => ACTION_ENFORCE,
            }
        };
        let (ndp_act, ndp_t_ns, ndp_tau_ns) = rate_fields(&rules.arp_ns);
        let (mcast_act, mcast_t_ns, mcast_tau_ns) = rate_fields(&rules.bcast_mcast);
        GuardIfCfg {
            mac_hi: u32::from_ne_bytes([mac[0], mac[1], mac[2], mac[3]]),
            mac_lo: u16::from_ne_bytes([mac[4], mac[5]]),
            act_arp: ndp_act,
            act_ns: ndp_act,
            act_lldp: action(&rules.lldp),
            act_foreign: action(&rules.foreign_src),
            act_mcast: mcast_act,
            _pad0: 0,
            version: GUARD_CFG_VERSION,
            ndp_t_ns,
            ndp_tau_ns,
            mcast_t_ns,
            mcast_tau_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::config::Config;

    fn guard_directives(body: &str) -> Vec<ModuleDirective> {
        let c = Config::parse(&format!("module guard\n{body}")).expect("parse");
        c.modules[0].directives.clone()
    }

    #[test]
    fn wire_layout_is_pinned() {
        use core::mem::{offset_of, size_of};
        // The BPF crate mirrors this struct by hand. Any change here
        // must land there in the same commit, and vice versa.
        assert_eq!(size_of::<GuardIfCfg>(), 48);
        assert_eq!(offset_of!(GuardIfCfg, mac_hi), 0);
        assert_eq!(offset_of!(GuardIfCfg, mac_lo), 4);
        assert_eq!(offset_of!(GuardIfCfg, act_arp), 6);
        assert_eq!(offset_of!(GuardIfCfg, act_ns), 7);
        assert_eq!(offset_of!(GuardIfCfg, act_lldp), 8);
        assert_eq!(offset_of!(GuardIfCfg, act_foreign), 9);
        assert_eq!(offset_of!(GuardIfCfg, act_mcast), 10);
        assert_eq!(offset_of!(GuardIfCfg, version), 12);
        assert_eq!(offset_of!(GuardIfCfg, ndp_t_ns), 16);
        assert_eq!(offset_of!(GuardIfCfg, ndp_tau_ns), 24);
        assert_eq!(offset_of!(GuardIfCfg, mcast_t_ns), 32);
        assert_eq!(offset_of!(GuardIfCfg, mcast_tau_ns), 40);
    }

    #[test]
    fn from_directives_round_trip() {
        let ds = guard_directives(
            "  interface br0\n\
             \x20 arp-ns-ratelimit br0 rate 3/60s burst 3\n\
             \x20 lldp br0 drop\n\
             \x20 foreign-src br0 monitor\n\
             \x20 bcast-mcast-ratelimit br0 rate 50/1s monitor\n",
        );
        let cfg = GuardConfig::from_directives(&ds).expect("valid section");
        assert_eq!(cfg.interfaces.len(), 1);
        let (iface, rules) = &cfg.interfaces[0];
        assert_eq!(iface, "br0");
        let arp = rules.arp_ns.as_ref().expect("arp-ns rule");
        assert_eq!(arp.rate, 3);
        assert_eq!(arp.per, Duration::from_secs(60));
        assert_eq!(arp.burst, 3);
        assert!(!arp.monitor);
        assert!(!rules.lldp.as_ref().unwrap().monitor);
        assert!(rules.foreign_src.as_ref().unwrap().monitor);
        assert!(rules.bcast_mcast.as_ref().unwrap().monitor);
    }

    #[test]
    fn from_directives_refusals_match_the_config_validator() {
        for (body, want) in [
            ("  lldp br0 drop\n", "no `interface` line"),
            // Foreign-namespace directives parse in any section; a
            // guard section containing only them must not become an
            // empty (silent no-op) attach set.
            ("  attach eth0 native\n", "declares no `interface` lines"),
            (
                "  interface br0\n  interface br0\n  lldp br0 drop\n",
                "duplicate `interface br0`",
            ),
            (
                "  interface br0\n  lldp br0 drop\n  lldp br0 monitor\n",
                "duplicate `lldp` for br0",
            ),
            ("  interface br0\n", "declares no rules"),
        ] {
            let e = GuardConfig::from_directives(&guard_directives(body)).expect_err(body);
            assert!(e.contains(want), "for `{body}`: error was `{e}`");
        }
    }

    /// Same cap as the config validator, from the same constant.
    #[test]
    fn interface_count_is_capped_at_the_map_size() {
        let max = packetframe_common::config::GUARD_MAX_INTERFACES;
        let mut body = String::new();
        for i in 0..=max {
            body.push_str(&format!("  interface br{i}\n  lldp br{i} drop\n"));
        }
        let e = GuardConfig::from_directives(&guard_directives(&body))
            .expect_err("one over the cap refused");
        assert!(e.contains(&format!("exceed the {max}")), "{e}");
    }

    #[test]
    fn restart_only_delta_matrix() {
        let base =
            GuardConfig::from_directives(&guard_directives("  interface br0\n  lldp br0 drop\n"))
                .unwrap();

        // Rate/action/rule changes on the same interface set: accepted.
        let hot = GuardConfig::from_directives(&guard_directives(
            "  interface br0\n  lldp br0 monitor\n  arp-ns-ratelimit br0 rate 3/60s\n",
        ))
        .unwrap();
        base.restart_only_delta(&hot).expect("hot delta accepted");

        // Added interface: refused, naming it.
        let added = GuardConfig::from_directives(&guard_directives(
            "  interface br0\n  interface br1\n  lldp br0 drop\n  lldp br1 drop\n",
        ))
        .unwrap();
        let e = base.restart_only_delta(&added).unwrap_err();
        assert!(e.contains("`interface br1` was added"), "{e}");

        // Removed interface: refused, naming it.
        let e = added.restart_only_delta(&base).unwrap_err();
        assert!(e.contains("`interface br1` was removed"), "{e}");
    }

    #[test]
    fn compile_produces_the_documented_wire_values() {
        let rules = GuardIfaceRules {
            arp_ns: Some(RateRule {
                rate: 3,
                per: Duration::from_secs(60),
                burst: 3,
                monitor: false,
            }),
            bcast_mcast: Some(RateRule {
                rate: 50,
                per: Duration::from_secs(1),
                burst: 50,
                monitor: true,
            }),
            lldp: Some(ActionRule { monitor: false }),
            foreign_src: None,
        };
        let mac = [0x28, 0x70, 0x4e, 0x47, 0x69, 0xc7];
        let cfg = GuardIfCfg::compile(mac, &rules);
        assert_eq!(cfg.mac_hi, u32::from_ne_bytes([0x28, 0x70, 0x4e, 0x47]));
        assert_eq!(cfg.mac_lo, u16::from_ne_bytes([0x69, 0xc7]));
        assert_eq!(cfg.act_arp, ACTION_ENFORCE);
        assert_eq!(cfg.act_ns, ACTION_ENFORCE);
        assert_eq!(cfg.act_lldp, ACTION_ENFORCE);
        assert_eq!(cfg.act_foreign, ACTION_DISABLED);
        assert_eq!(cfg.act_mcast, ACTION_MONITOR);
        assert_eq!(cfg.version, GUARD_CFG_VERSION);
        // 60s / 3 = 20s per token; tau = (3-1) * 20s.
        assert_eq!(cfg.ndp_t_ns, 20_000_000_000);
        assert_eq!(cfg.ndp_tau_ns, 40_000_000_000);
        // 1s / 50 = 20ms per token; tau = 49 * 20ms.
        assert_eq!(cfg.mcast_t_ns, 20_000_000);
        assert_eq!(cfg.mcast_tau_ns, 980_000_000);
        // Disabled rate class: t_ns 0 = bucket bypass.
        let none = GuardIfCfg::compile(mac, &GuardIfaceRules::default());
        assert_eq!(none.ndp_t_ns, 0);
        assert_eq!(none.act_arp, ACTION_DISABLED);
    }
}
