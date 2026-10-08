//! Refuse to attach keepalived's dedicated VRRP link.
//!
//! fast-path forwards allowlisted traffic arriving on an attached port
//! without passing it through netfilter. On an HA pair whose VRRP runs
//! over a link of its own, the standby gateway's own traffic (its route
//! to the internet, its control-plane sessions) arrives on that link and
//! is meant to meet this router's firewall. Attached, the link lets the
//! standby reach every allowlisted prefix past it, and whatever the
//! standby can reach it can act on: a standby that stays reachable to a
//! tailnet's control server can win subnet-router primacy for this
//! router's own LAN prefixes.
//!
//! keepalived's configuration is all this reads. A router without one
//! has no VRRP link, and the check says nothing.

use std::path::{Path, PathBuf};

use packetframe_common::config::ModuleDirective;
use packetframe_common::module::{ModuleConfig, ModuleError, ModuleResult};
use tracing::warn;

use crate::MODULE_NAME;

/// The keepalived configurations read: UniFi OS generates its own at
/// `/run/vrrp/keepalived.conf`, and `/etc/keepalived/keepalived.conf` is
/// keepalived's default. `include` directives are not followed.
pub const KEEPALIVED_CONFIGS: [&str; 2] = [
    "/run/vrrp/keepalived.conf",
    "/etc/keepalived/keepalived.conf",
];

/// One `vrrp_instance` block, as far as the check needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrrpInstance {
    pub name: String,
    /// Its `interface`: the link the advertisements travel on.
    pub interface: Option<String>,
    /// The `dev` of each `virtual_ipaddress` and
    /// `virtual_ipaddress_excluded` entry. `None` for an entry that
    /// names no device, which keepalived puts on `interface`.
    pub vip_devs: Vec<Option<String>>,
}

impl VrrpInstance {
    /// `interface`, when it carries none of the instance's addresses:
    /// every entry names a different device, so the link exists only to
    /// reach the peer. An instance whose addresses sit on its own
    /// interface (the common keepalived gateway, where that interface
    /// is the LAN) is not one, and neither is an instance with no
    /// addresses at all.
    pub fn dedicated_link(&self) -> Option<&str> {
        let iface = self.interface.as_deref()?;
        let elsewhere = |dev: &Option<String>| dev.as_deref().is_some_and(|d| d != iface);
        (!self.vip_devs.is_empty() && self.vip_devs.iter().all(elsewhere)).then_some(iface)
    }
}

enum Frame {
    Instance(VrrpInstance),
    Addresses,
    Other,
}

/// Every `vrrp_instance` in a keepalived configuration.
///
/// The grammar handled is what the check needs: `#` and `!` comments,
/// nested `{ }` blocks with the brace on the opener's line or the next,
/// and one address per line inside the address blocks. Anything else
/// is skipped over as an opaque block or statement.
pub fn parse_instances(text: &str) -> Vec<VrrpInstance> {
    let mut stack: Vec<Frame> = Vec::new();
    let mut out = Vec::new();
    // The last statement, while it may still be a block's opener whose
    // `{` comes on a later line.
    let mut pending: Vec<String> = Vec::new();
    for raw in text.lines() {
        let line = raw.split(['#', '!']).next().unwrap_or_default();
        let spaced = line.replace('{', " { ").replace('}', " } ");
        let toks: Vec<&str> = spaced.split_whitespace().collect();
        let mut i = 0;
        while i < toks.len() {
            match toks[i] {
                "}" => {
                    if let Some(Frame::Instance(inst)) = stack.pop() {
                        out.push(inst);
                    }
                    pending.clear();
                    i += 1;
                }
                "{" => {
                    let frame = open(&stack, &pending);
                    stack.push(frame);
                    pending.clear();
                    i += 1;
                }
                _ => {
                    let end = toks[i..]
                        .iter()
                        .position(|t| *t == "{" || *t == "}")
                        .map_or(toks.len(), |p| i + p);
                    let words: Vec<String> = toks[i..end].iter().map(|t| t.to_string()).collect();
                    if toks.get(end) == Some(&"{") {
                        let frame = open(&stack, &words);
                        stack.push(frame);
                        pending.clear();
                        i = end + 1;
                    } else {
                        statement(&mut stack, &words);
                        pending = words;
                        i = end;
                    }
                }
            }
        }
    }
    out
}

/// A word as keepalived reads it: quote characters removed, so
/// `interface "eth1"` names `eth1`.
fn unquote(word: &str) -> String {
    word.replace('"', "")
}

fn open(stack: &[Frame], words: &[String]) -> Frame {
    match (stack.last(), words.first().map(String::as_str)) {
        (None, Some("vrrp_instance")) => Frame::Instance(VrrpInstance {
            name: words.get(1).map(|w| unquote(w)).unwrap_or_default(),
            interface: None,
            vip_devs: Vec::new(),
        }),
        (Some(Frame::Instance(_)), Some("virtual_ipaddress" | "virtual_ipaddress_excluded")) => {
            Frame::Addresses
        }
        _ => Frame::Other,
    }
}

fn statement(stack: &mut [Frame], words: &[String]) {
    match stack {
        [.., Frame::Instance(inst)] => {
            if words.first().map(String::as_str) == Some("interface") {
                inst.interface = words.get(1).map(|w| unquote(w));
            }
        }
        [.., Frame::Instance(inst), Frame::Addresses] => inst.vip_devs.push(
            words
                .windows(2)
                .find(|w| w[0] == "dev")
                .map(|w| unquote(&w[1])),
        ),
        _ => {}
    }
}

/// A dedicated VRRP link, and where it was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedicatedLink {
    pub iface: String,
    pub instance: String,
    pub config: PathBuf,
}

/// What the configs at a set of paths name.
#[derive(Debug, Default)]
pub struct Found {
    pub links: Vec<DedicatedLink>,
    /// Configs that exist but could not be read.
    pub unreadable: Vec<(PathBuf, std::io::Error)>,
}

/// Every dedicated link the configs at `paths` name. A path with no
/// file contributes nothing: most routers run no keepalived.
pub fn dedicated_links(paths: &[&Path]) -> Found {
    let mut found = Found::default();
    for path in paths {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                for inst in parse_instances(&text) {
                    if let Some(iface) = inst.dedicated_link() {
                        found.links.push(DedicatedLink {
                            iface: iface.to_string(),
                            instance: inst.name.clone(),
                            config: path.to_path_buf(),
                        });
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => found.unreadable.push((path.to_path_buf(), e)),
        }
    }
    found
}

/// One refusal per `attach` (iface, config line) that names a link in
/// `links`; empty when none does.
pub fn attach_refusals(attaches: &[(&str, usize)], links: &[DedicatedLink]) -> Vec<String> {
    attaches
        .iter()
        .filter_map(|(iface, line)| {
            let link = links.iter().find(|l| l.iface == *iface)?;
            Some(format!(
                "`attach {iface}` at line {line}: {iface} is the VRRP link of keepalived \
                 instance `{}` ({}) and carries none of its addresses. On an HA pair it \
                 carries the standby gateway's own traffic, and fast-path forwards \
                 allowlisted traffic arriving on an attached port without passing it \
                 through netfilter, so the standby would reach allowlisted prefixes past \
                 this router's firewall. Remove the `attach {iface}` line",
                link.instance,
                link.config.display(),
            ))
        })
        .collect()
}

/// Refuse a config that attaches a dedicated VRRP link named by any of
/// [`KEEPALIVED_CONFIGS`]. Runs before anything is loaded or pinned, so
/// the refusal costs no `detach --all`.
pub fn check_attach_set(cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
    let attaches: Vec<(&str, usize)> = cfg
        .section
        .directives
        .iter()
        .filter_map(|d| match d {
            ModuleDirective::Attach { iface, line, .. } => Some((iface.as_str(), *line)),
            _ => None,
        })
        .collect();
    let paths: Vec<&Path> = KEEPALIVED_CONFIGS.iter().map(Path::new).collect();
    let found = dedicated_links(&paths);
    for (path, e) in &found.unreadable {
        warn!(
            path = %path.display(),
            error = %e,
            "keepalived config unreadable; attach set not checked against it"
        );
    }
    let refusals = attach_refusals(&attaches, &found.links);
    if refusals.is_empty() {
        Ok(())
    } else {
        Err(ModuleError::other(MODULE_NAME, refusals.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape UniFi OS generates for an HA pair: VRRP unicast over a
    /// link of its own, every address on a LAN bridge.
    const HA_LINK: &str = r#"
global_defs {
    vrrp_version 3
}

track_file failover_trigger {
    file /run/vrrp/failover-trigger.track
}

vrrp_instance eth1v42 {
    state BACKUP
    interface eth1
    virtual_router_id 42
    virtual_ipaddress {
        192.0.2.1/24 dev br0 no_track
        198.51.100.1/24 dev br100 no_track
    }
    track_file {
        failover_trigger
    }
    unicast_src_ip 192.0.2.250
    unicast_peer {
        192.0.2.251
    }
}

vrrp_sync_group vrrpGroup {
    group {
        eth1v42
    }
}
"#;

    #[test]
    fn ha_link_is_dedicated() {
        let insts = parse_instances(HA_LINK);
        assert_eq!(insts.len(), 1);
        assert_eq!(insts[0].name, "eth1v42");
        assert_eq!(insts[0].interface.as_deref(), Some("eth1"));
        assert_eq!(
            insts[0].vip_devs,
            vec![Some("br0".to_string()), Some("br100".to_string())]
        );
        assert_eq!(insts[0].dedicated_link(), Some("eth1"));
    }

    #[test]
    fn addresses_on_the_vrrp_interface_are_not_a_dedicated_link() {
        // The common keepalived gateway: VRRP and its address share the LAN.
        let conf = "vrrp_instance VI_1 {\n  interface eth0\n  virtual_ipaddress {\n    192.0.2.1/24\n  }\n}\n";
        let insts = parse_instances(conf);
        assert_eq!(insts[0].vip_devs, vec![None]);
        assert_eq!(insts[0].dedicated_link(), None);

        let named = "vrrp_instance VI_1 {\n  interface eth0\n  virtual_ipaddress {\n    192.0.2.1/24 dev eth0\n  }\n}\n";
        assert_eq!(parse_instances(named)[0].dedicated_link(), None);
    }

    #[test]
    fn one_address_on_the_link_disqualifies_it() {
        let conf = "vrrp_instance VI_1 {\n  interface eth1\n  virtual_ipaddress {\n    192.0.2.1/24 dev br0\n  }\n  virtual_ipaddress_excluded {\n    198.51.100.1/24\n  }\n}\n";
        assert_eq!(parse_instances(conf)[0].dedicated_link(), None);
    }

    #[test]
    fn an_instance_without_addresses_is_not_a_dedicated_link() {
        let conf = "vrrp_instance VI_1 {\n  interface eth1\n}\n";
        assert_eq!(parse_instances(conf)[0].dedicated_link(), None);
    }

    #[test]
    fn braces_on_their_own_lines_and_comments() {
        let conf = "! keepalived\nvrrp_instance VI_1\n{\n  interface eth1   # the HA link\n  virtual_ipaddress\n  {\n    192.0.2.1/24 dev br0\n  }\n}\n";
        let insts = parse_instances(conf);
        assert_eq!(insts.len(), 1);
        assert_eq!(insts[0].dedicated_link(), Some("eth1"));
    }

    #[test]
    fn quoted_names_match_unquoted() {
        // keepalived strips quote characters, so these name eth1 and br0.
        let conf = "vrrp_instance \"VI_1\" {\n  interface \"eth1\"\n  virtual_ipaddress {\n    192.0.2.1/24 dev \"br0\"\n  }\n}\n";
        let insts = parse_instances(conf);
        assert_eq!(insts[0].name, "VI_1");
        assert_eq!(insts[0].vip_devs, vec![Some("br0".to_string())]);
        assert_eq!(insts[0].dedicated_link(), Some("eth1"));

        let on_link = "vrrp_instance VI_1 {\n  interface \"eth0\"\n  virtual_ipaddress {\n    192.0.2.1/24 dev eth0\n  }\n}\n";
        assert_eq!(parse_instances(on_link)[0].dedicated_link(), None);
    }

    #[test]
    fn one_line_blocks() {
        let conf =
            "vrrp_instance VI_1 { interface eth1\n virtual_ipaddress { 192.0.2.1/24 dev br0 }\n}";
        assert_eq!(parse_instances(conf)[0].dedicated_link(), Some("eth1"));
    }

    #[test]
    fn interface_inside_a_nested_block_is_not_the_instance_interface() {
        let conf = "vrrp_instance VI_1 {\n  track_interface {\n    interface eth3\n  }\n  interface eth1\n  virtual_ipaddress {\n    192.0.2.1/24 dev br0\n  }\n}\n";
        assert_eq!(parse_instances(conf)[0].interface.as_deref(), Some("eth1"));
    }

    #[test]
    fn missing_configs_say_nothing() {
        let dir = std::env::temp_dir().join(format!("pf-vrrp-missing-{}", std::process::id()));
        let found = dedicated_links(&[&dir.join("keepalived.conf")]);
        assert!(found.links.is_empty());
        assert!(found.unreadable.is_empty());
    }

    #[test]
    fn links_are_read_from_the_config_files() {
        let dir = std::env::temp_dir().join(format!("pf-vrrp-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keepalived.conf");
        std::fs::write(&path, HA_LINK).unwrap();
        let found = dedicated_links(&[&dir.join("absent.conf"), &path]);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            found.links,
            vec![DedicatedLink {
                iface: "eth1".into(),
                instance: "eth1v42".into(),
                config: path,
            }]
        );
        assert!(found.unreadable.is_empty());
    }

    #[test]
    fn only_the_dedicated_link_is_refused() {
        let links = vec![DedicatedLink {
            iface: "eth1".into(),
            instance: "eth1v42".into(),
            config: PathBuf::from("/run/vrrp/keepalived.conf"),
        }];
        let refusals = attach_refusals(&[("eth0", 9), ("eth1", 10), ("eth2", 11)], &links);
        assert_eq!(refusals.len(), 1);
        assert!(refusals[0].starts_with("`attach eth1` at line 10: eth1 is the VRRP link"));
        assert!(refusals[0].contains("eth1v42"));
        assert!(attach_refusals(&[("eth0", 9)], &links).is_empty());
        assert!(attach_refusals(&[("eth1", 10)], &[]).is_empty());
    }
}
