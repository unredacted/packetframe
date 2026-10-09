//! The module's configuration, from its section's directives. The rules a
//! section must satisfy are `Config::validate_flow_export`'s, which runs
//! before any of this (startup, SIGHUP, feasibility).

use std::net::{IpAddr, SocketAddr};

use packetframe_common::config::{
    CollectorFormat, CollectorKind, CollectorProfile, ModuleDirective, FLOW_BUDGET_RATE,
    FLOW_DEFAULT_HEADER_BYTES, FLOW_DEFAULT_RATE,
};
use packetframe_common::fib::IpPrefix;

use crate::flows::Limits;
use packetframe_common::module::RESTART_SEQUENCE;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Collector {
    pub name: String,
    pub addr: SocketAddr,
    pub kind: CollectorKind,
    pub format: CollectorFormat,
    pub profile: CollectorProfile,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowExportConfig {
    /// The sFlow agent address, and the exporter's source address.
    pub source: IpAddr,
    /// One packet in `rate`.
    pub rate: u32,
    pub header_bytes: u32,
    pub collectors: Vec<Collector>,
    /// The IPFIX flow cache's bounds.
    pub cache: Limits,
    /// `privacy-local-prefix`: empty means fast-path's allowlist.
    pub local: Vec<IpPrefix>,
}

impl FlowExportConfig {
    pub fn from_directives(directives: &[ModuleDirective]) -> Result<Self, String> {
        let mut source = None;
        let mut rate = FLOW_DEFAULT_RATE;
        let mut header_bytes = FLOW_DEFAULT_HEADER_BYTES;
        let mut collectors = Vec::new();
        let mut cache = Limits::default();
        let mut local = Vec::new();
        for d in directives {
            match d {
                ModuleDirective::FlowSourceAddress { addr, .. } => source = Some(*addr),
                ModuleDirective::FlowSampleRate { rate: r, .. } => rate = *r,
                ModuleDirective::FlowHeaderBytes { bytes, .. } => header_bytes = *bytes,
                ModuleDirective::FlowCollector {
                    name,
                    addr,
                    kind,
                    format,
                    profile,
                    ..
                } => collectors.push(Collector {
                    name: name.clone(),
                    addr: *addr,
                    kind: *kind,
                    format: *format,
                    profile: *profile,
                }),
                ModuleDirective::FlowLocalPrefix { prefix, .. } => local.push(*prefix),
                ModuleDirective::FlowCache {
                    entries,
                    active,
                    inactive,
                    ..
                } => {
                    cache = Limits {
                        entries: *entries,
                        active: *active,
                        inactive: *inactive,
                    }
                }
                _ => {}
            }
        }
        let source = source.ok_or("`source-address` is required")?;
        if collectors.is_empty() {
            return Err("no `collector`".into());
        }
        Ok(Self {
            source,
            rate,
            header_bytes,
            collectors,
            cache,
            local,
        })
    }

    /// The privacy profiles IPFIX collectors take, each once.
    pub fn ipfix_profiles(&self) -> Vec<CollectorProfile> {
        let mut p: Vec<CollectorProfile> = self
            .collectors
            .iter()
            .filter(|c| c.format == CollectorFormat::Ipfix)
            .map(|c| c.profile)
            .collect();
        p.sort();
        p.dedup();
        p
    }

    /// Whether any collector takes IPFIX, so flows are cached at all.
    pub fn ipfix(&self) -> bool {
        self.collectors
            .iter()
            .any(|c| c.format == CollectorFormat::Ipfix)
    }

    /// Denser than the rate the sampler's cost is qualified at.
    pub fn over_budget(&self) -> bool {
        self.rate < FLOW_BUDGET_RATE
    }

    /// Refuse what only a restart can apply: `source-address`, the
    /// exporter's identity to every collector and its socket's address.
    pub fn restart_only_delta(&self, new: &Self) -> Result<(), String> {
        if self.source != new.source {
            return Err(format!(
                "source-address {} → {} is restart-only (the exporter's identity to its \
                 collectors and its socket's address): {RESTART_SEQUENCE}",
                self.source, new.source
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_common::config::Config;

    fn parse(body: &str) -> FlowExportConfig {
        let c = Config::parse(&format!(
            "module fast-path\n  attach eth0 generic\nmodule flow-export\n{body}"
        ))
        .unwrap();
        c.validate_flow_export().unwrap();
        FlowExportConfig::from_directives(&c.modules[1].directives).unwrap()
    }

    #[test]
    fn defaults_and_overrides() {
        let c = parse("  source-address 192.0.2.1\n  collector a sflow 198.51.100.1:6343\n");
        assert_eq!((c.rate, c.header_bytes), (1000, 128));
        assert!(!c.over_budget());
        let c = parse(
            "  source-address 192.0.2.1\n  sample-rate 100\n  header-bytes 64\n  \
             collector a sflow 198.51.100.1:6343 kind ddos\n",
        );
        assert_eq!((c.rate, c.header_bytes), (100, 64));
        assert!(c.over_budget());
        assert_eq!(c.collectors[0].kind, CollectorKind::Ddos);
    }

    #[test]
    fn only_the_source_address_needs_a_restart() {
        let a = parse("  source-address 192.0.2.1\n  collector a sflow 198.51.100.1:6343\n");
        let b = parse(
            "  source-address 192.0.2.1\n  sample-rate 4000\n  collector b sflow 198.51.100.2:6343\n",
        );
        a.restart_only_delta(&b).unwrap();
        let c = parse("  source-address 192.0.2.9\n  collector a sflow 198.51.100.1:6343\n");
        assert!(a
            .restart_only_delta(&c)
            .unwrap_err()
            .contains("restart-only"));
    }
}
