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
//! has no VRRP link, and the check says nothing. Where the configuration
//! cannot be read without keepalived's own state, the check warns and
//! refuses nothing: a wrong refusal stops the daemon on a valid router.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

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
    /// Its `unicast_src_ip`. With no `interface`, keepalived runs the
    /// instance on the interface holding this address.
    pub unicast_src_ip: Option<String>,
    /// The `dev` of each `virtual_ipaddress` and
    /// `virtual_ipaddress_excluded` entry. `None` for an entry that
    /// names no device, which keepalived puts on the instance's
    /// interface.
    pub vip_devs: Vec<Option<String>>,
    /// Why the parse cannot stand for what keepalived runs: a line it
    /// evaluates against state this check does not have.
    pub unresolved: Option<String>,
}

/// A keepalived configuration, as far as the check needs it.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub instances: Vec<VrrpInstance>,
    /// Set when the file uses a construct that can create or reshape
    /// instances out of this parser's sight.
    pub unresolved: Option<String>,
}

/// The facts about this host that classifying an instance needs.
pub trait Host {
    /// The devices directly below `dev`: a VLAN's parent, a bridge's or
    /// bond's ports, a macvlan's lower device. `None` when `dev` does not
    /// exist.
    fn lowers(&self, dev: &str) -> Option<Vec<String>>;
    /// The interface holding `addr`, if one does.
    fn holder_of(&self, addr: IpAddr) -> Option<String>;
}

/// What an instance's interface is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// A link that carries none of the instance's addresses, nor any
    /// device stacked on it: it exists only to reach the peer.
    Dedicated(String),
    /// The instance's addresses ride on its interface (the common
    /// keepalived gateway, where that interface is the LAN), or it has
    /// none.
    NotDedicated,
    /// Not decidable without guessing; why.
    Unknown(String),
}

impl VrrpInstance {
    pub fn classify(&self, host: &dyn Host) -> Verdict {
        if let Some(why) = &self.unresolved {
            return Verdict::Unknown(why.clone());
        }
        let iface = match (&self.interface, &self.unicast_src_ip) {
            (Some(iface), _) => iface.clone(),
            (None, Some(src)) => match src.parse().ok().and_then(|a| host.holder_of(a)) {
                Some(iface) => iface,
                None => {
                    return Verdict::Unknown(format!(
                        "no `interface`, and no interface holds unicast_src_ip {src}"
                    ))
                }
            },
            (None, None) => {
                return Verdict::Unknown("no `interface` and no `unicast_src_ip`".into());
            }
        };
        if self.vip_devs.is_empty() {
            return Verdict::NotDedicated;
        }
        let mut missing = None;
        for dev in &self.vip_devs {
            let Some(dev) = dev else {
                return Verdict::NotDedicated;
            };
            match stacked_on(host, dev, &iface) {
                Some(true) => return Verdict::NotDedicated,
                Some(false) => {}
                None => {
                    missing.get_or_insert_with(|| format!("address device {dev} does not exist"));
                }
            }
        }
        match missing {
            Some(why) => Verdict::Unknown(why),
            None => Verdict::Dedicated(iface),
        }
    }
}

/// Whether `iface` is `dev` or lies below it through any depth of lower
/// devices (`eth0` below `eth0.10`, a port below its bridge). `None`
/// when `dev` does not exist.
fn stacked_on(host: &dyn Host, dev: &str, iface: &str) -> Option<bool> {
    let mut seen = HashSet::new();
    let mut todo = vec![dev.to_string()];
    while let Some(d) = todo.pop() {
        if d == iface {
            return Some(true);
        }
        if seen.insert(d.clone()) {
            todo.extend(host.lowers(&d)?);
        }
    }
    Some(false)
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
/// one address per line inside the address blocks, quoted words, and
/// single-line `$NAME=value` definitions substituted as `$NAME` or
/// `${NAME}`. A `@config-id` conditional line marks its instance
/// unresolved (which branch keepalived takes depends on its config id),
/// as does a `$` left unsubstituted in a value the check reads. `~SEQ`
/// marks the whole file unresolved. Anything else is skipped over as an
/// opaque block or statement.
pub fn parse(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    let mut defs: HashMap<String, String> = HashMap::new();
    let mut stack: Vec<Frame> = Vec::new();
    // The last statement and whether its line was conditional, while it
    // may still be a block's opener whose `{` comes on a later line.
    let mut pending: (Vec<String>, bool) = (Vec::new(), false);
    for raw in text.lines() {
        let line = raw.split(['#', '!']).next().unwrap_or_default().trim();
        if line.starts_with('~') {
            parsed
                .unresolved
                .get_or_insert_with(|| "uses `~SEQ`, which this check does not expand".into());
            continue;
        }
        if let Some((name, value)) = definition(line) {
            let value = substitute(value, &defs);
            if value.ends_with('\\') || value.ends_with('{') {
                parsed.unresolved.get_or_insert_with(|| {
                    format!("defines `${name}` over several lines, which this check does not read")
                });
            }
            defs.insert(name.to_string(), value);
            continue;
        }
        let (conditional, line) = match line.strip_prefix('@') {
            Some(rest) => (
                true,
                rest.split_once(char::is_whitespace).map_or("", |(_, l)| l),
            ),
            None => (false, line),
        };
        if conditional {
            if let Some(inst) = innermost_instance(&mut stack) {
                mark_conditional(inst);
            }
        }
        let line = substitute(line, &defs);
        let spaced = line.replace('{', " { ").replace('}', " } ");
        let toks: Vec<&str> = spaced.split_whitespace().collect();
        let mut i = 0;
        while i < toks.len() {
            match toks[i] {
                "}" => {
                    if let Some(Frame::Instance(inst)) = stack.pop() {
                        parsed.instances.push(inst);
                    }
                    pending = (Vec::new(), false);
                    i += 1;
                }
                "{" => {
                    let frame = open(&stack, &pending.0, pending.1 || conditional);
                    stack.push(frame);
                    pending = (Vec::new(), false);
                    i += 1;
                }
                _ => {
                    let end = toks[i..]
                        .iter()
                        .position(|t| *t == "{" || *t == "}")
                        .map_or(toks.len(), |p| i + p);
                    let words: Vec<String> = toks[i..end].iter().map(|t| t.to_string()).collect();
                    if toks.get(end) == Some(&"{") {
                        let frame = open(&stack, &words, conditional);
                        stack.push(frame);
                        pending = (Vec::new(), false);
                        i = end + 1;
                    } else {
                        statement(&mut stack, &words);
                        pending = (words, conditional);
                        i = end;
                    }
                }
            }
        }
    }
    parsed
}

/// `$NAME=value`, split. keepalived allows no space before the `=`.
fn definition(line: &str) -> Option<(&str, &str)> {
    let (name, value) = line.strip_prefix('$')?.split_once('=')?;
    let ident = !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    ident.then(|| (name, value.trim()))
}

/// `line` with each defined `$NAME` and `${NAME}` replaced by its value.
/// An undefined one stays as written.
fn substitute(line: &str, defs: &HashMap<String, String>) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        let (name, len) = match after.strip_prefix('{') {
            Some(inner) => match inner.find('}') {
                Some(end) => (&inner[..end], end + 2),
                None => ("", 0),
            },
            None => {
                let end = after
                    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                    .unwrap_or(after.len());
                (&after[..end], end)
            }
        };
        match defs.get(name) {
            Some(value) => {
                out.push_str(value);
                rest = &after[len..];
            }
            None => {
                out.push('$');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

fn innermost_instance(stack: &mut [Frame]) -> Option<&mut VrrpInstance> {
    stack.iter_mut().rev().find_map(|f| match f {
        Frame::Instance(inst) => Some(inst),
        _ => None,
    })
}

fn mark_conditional(inst: &mut VrrpInstance) {
    inst.unresolved
        .get_or_insert_with(|| "has `@config-id` conditional lines".into());
}

/// A word as keepalived reads it: quote characters removed, so
/// `interface "eth1"` names `eth1`.
fn unquote(word: &str) -> String {
    word.replace('"', "")
}

fn open(stack: &[Frame], words: &[String], conditional: bool) -> Frame {
    match (stack.last(), words.first().map(String::as_str)) {
        (None, Some("vrrp_instance")) => {
            let mut inst = VrrpInstance {
                name: words.get(1).map(|w| unquote(w)).unwrap_or_default(),
                interface: None,
                unicast_src_ip: None,
                vip_devs: Vec::new(),
                unresolved: None,
            };
            if conditional {
                mark_conditional(&mut inst);
            }
            Frame::Instance(inst)
        }
        (Some(Frame::Instance(_)), Some("virtual_ipaddress" | "virtual_ipaddress_excluded")) => {
            Frame::Addresses
        }
        _ => Frame::Other,
    }
}

/// `value`, unquoted, noting on `inst` a `$` substitution left undone.
fn read_value(inst: &mut VrrpInstance, key: &str, value: &str) -> String {
    let value = unquote(value);
    if value.contains('$') {
        inst.unresolved
            .get_or_insert_with(|| format!("`{key} {value}` has an undefined `$` substitution"));
    }
    value
}

fn statement(stack: &mut [Frame], words: &[String]) {
    match stack {
        [.., Frame::Instance(inst)] => match (words.first().map(String::as_str), words.get(1)) {
            (Some("interface"), Some(v)) => inst.interface = Some(read_value(inst, "interface", v)),
            (Some("unicast_src_ip"), Some(v)) => {
                inst.unicast_src_ip = Some(read_value(inst, "unicast_src_ip", v));
            }
            _ => {}
        },
        [.., Frame::Instance(inst), Frame::Addresses] => {
            let dev = words.windows(2).find(|w| w[0] == "dev");
            let dev = dev.map(|w| read_value(inst, "dev", &w[1]));
            inst.vip_devs.push(dev);
        }
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
    /// Instances and files the check could not decide, each with why.
    pub unchecked: Vec<String>,
    /// Configs that exist but could not be read.
    pub unreadable: Vec<(PathBuf, std::io::Error)>,
}

/// Every dedicated link the configs at `paths` name. A path with no
/// file contributes nothing: most routers run no keepalived.
pub fn dedicated_links(paths: &[&Path], host: &dyn Host) -> Found {
    let mut found = Found::default();
    for path in paths {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                found.unreadable.push((path.to_path_buf(), e));
                continue;
            }
        };
        let parsed = parse(&text);
        if let Some(why) = parsed.unresolved {
            found.unchecked.push(format!("{}: {why}", path.display()));
            continue;
        }
        for inst in parsed.instances {
            match inst.classify(host) {
                Verdict::Dedicated(iface) => found.links.push(DedicatedLink {
                    iface,
                    instance: inst.name,
                    config: path.to_path_buf(),
                }),
                Verdict::NotDedicated => {}
                Verdict::Unknown(why) => found.unchecked.push(format!(
                    "{}: instance `{}` {why}",
                    path.display(),
                    inst.name
                )),
            }
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

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use packetframe_common::config::ModuleDirective;
    use packetframe_common::module::{ModuleConfig, ModuleError, ModuleResult};
    use tracing::warn;

    use crate::MODULE_NAME;

    /// This host, read from `/sys/class/net` and `getifaddrs`.
    struct SysHost {
        addrs: Vec<(String, IpAddr)>,
    }

    impl Host for SysHost {
        fn lowers(&self, dev: &str) -> Option<Vec<String>> {
            if dev.is_empty() || dev.contains('/') || dev == "." || dev == ".." {
                return None;
            }
            let entries = std::fs::read_dir(Path::new("/sys/class/net").join(dev)).ok()?;
            Some(
                entries
                    .filter_map(|e| {
                        let name = e.ok()?.file_name();
                        name.to_str()?.strip_prefix("lower_").map(str::to_string)
                    })
                    .collect(),
            )
        }

        fn holder_of(&self, addr: IpAddr) -> Option<String> {
            self.addrs
                .iter()
                .find(|(_, a)| *a == addr)
                .map(|(iface, _)| iface.clone())
        }
    }

    /// Refuse a config that attaches a dedicated VRRP link named by any
    /// of [`KEEPALIVED_CONFIGS`]. Runs before anything is loaded or
    /// pinned, so the refusal costs no `detach --all`.
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
        let host = SysHost {
            addrs: crate::fib::local_nexthops::kernel_addrs_by_iface(),
        };
        let found = dedicated_links(&paths, &host);
        for (path, e) in &found.unreadable {
            warn!(
                path = %path.display(),
                error = %e,
                "keepalived config unreadable; attach set not checked against it"
            );
        }
        for why in &found.unchecked {
            warn!(%why, "keepalived VRRP link undecidable; attach set not checked against it");
        }
        let refusals = attach_refusals(&attaches, &found.links);
        if refusals.is_empty() {
            Ok(())
        } else {
            Err(ModuleError::other(MODULE_NAME, refusals.join("; ")))
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::check_attach_set;

#[cfg(test)]
mod tests {
    use super::*;

    /// A host given as lower-device lists and held addresses.
    #[derive(Default)]
    struct FakeHost {
        lowers: HashMap<&'static str, Vec<&'static str>>,
        addrs: Vec<(&'static str, IpAddr)>,
    }

    impl FakeHost {
        fn dev(mut self, dev: &'static str, lowers: &[&'static str]) -> Self {
            self.lowers.insert(dev, lowers.to_vec());
            self
        }

        fn addr(mut self, iface: &'static str, addr: &str) -> Self {
            self.addrs.push((iface, addr.parse().unwrap()));
            self
        }
    }

    impl Host for FakeHost {
        fn lowers(&self, dev: &str) -> Option<Vec<String>> {
            self.lowers
                .get(dev)
                .map(|l| l.iter().map(|s| s.to_string()).collect())
        }

        fn holder_of(&self, addr: IpAddr) -> Option<String> {
            self.addrs
                .iter()
                .find(|(_, a)| *a == addr)
                .map(|(i, _)| i.to_string())
        }
    }

    /// The UniFi OS HA stack: per-VLAN bridges over VLAN devices over a
    /// trunk bridge over the LAN ports; the HA link stands apart.
    fn ha_host() -> FakeHost {
        FakeHost::default()
            .dev("br0", &["switch0.1"])
            .dev("br100", &["switch0.100"])
            .dev("switch0.1", &["switch0"])
            .dev("switch0.100", &["switch0"])
            .dev("switch0", &["eth0", "eth4", "eth5"])
            .dev("eth0", &[])
            .dev("eth1", &[])
            .dev("eth4", &[])
            .dev("eth5", &[])
    }

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

    fn verdicts(conf: &str, host: &FakeHost) -> Vec<Verdict> {
        let parsed = parse(conf);
        assert_eq!(parsed.unresolved, None);
        parsed.instances.iter().map(|i| i.classify(host)).collect()
    }

    fn instance(body: &str) -> String {
        format!("vrrp_instance VI_1 {{\n{body}\n}}\n")
    }

    #[test]
    fn ha_link_is_dedicated() {
        let parsed = parse(HA_LINK);
        assert_eq!(parsed.instances.len(), 1);
        let inst = &parsed.instances[0];
        assert_eq!(inst.name, "eth1v42");
        assert_eq!(inst.interface.as_deref(), Some("eth1"));
        assert_eq!(inst.unicast_src_ip.as_deref(), Some("192.0.2.250"));
        assert_eq!(
            inst.vip_devs,
            vec![Some("br0".to_string()), Some("br100".to_string())]
        );
        assert_eq!(inst.classify(&ha_host()), Verdict::Dedicated("eth1".into()));
    }

    #[test]
    fn a_lan_port_under_the_address_devices_is_not_dedicated() {
        // VRRP on a LAN trunk port the bridges sit on.
        let conf = HA_LINK.replace("interface eth1", "interface eth4");
        assert_eq!(verdicts(&conf, &ha_host()), vec![Verdict::NotDedicated]);
    }

    #[test]
    fn a_vlan_parent_is_not_dedicated() {
        let host = FakeHost::default()
            .dev("eth0.10", &["eth0"])
            .dev("eth0.20", &["eth0"])
            .dev("eth0", &[]);
        let conf = instance(
            "interface eth0\nvirtual_ipaddress {\n192.0.2.1/24 dev eth0.10\n198.51.100.1/24 dev eth0.20\n}",
        );
        assert_eq!(verdicts(&conf, &host), vec![Verdict::NotDedicated]);
    }

    #[test]
    fn addresses_on_the_vrrp_interface_are_not_a_dedicated_link() {
        // The common keepalived gateway: VRRP and its address share the LAN.
        let host = FakeHost::default().dev("eth0", &[]);
        let bare = instance("interface eth0\nvirtual_ipaddress {\n192.0.2.1/24\n}");
        assert_eq!(parse(&bare).instances[0].vip_devs, vec![None]);
        assert_eq!(verdicts(&bare, &host), vec![Verdict::NotDedicated]);
        let named = instance("interface eth0\nvirtual_ipaddress {\n192.0.2.1/24 dev eth0\n}");
        assert_eq!(verdicts(&named, &host), vec![Verdict::NotDedicated]);
    }

    #[test]
    fn one_address_on_the_link_disqualifies_it() {
        let conf = instance(
            "interface eth1\nvirtual_ipaddress {\n192.0.2.1/24 dev br0\n}\nvirtual_ipaddress_excluded {\n198.51.100.1/24\n}",
        );
        assert_eq!(verdicts(&conf, &ha_host()), vec![Verdict::NotDedicated]);
    }

    #[test]
    fn an_instance_without_addresses_is_not_a_dedicated_link() {
        let conf = instance("interface eth1");
        assert_eq!(verdicts(&conf, &ha_host()), vec![Verdict::NotDedicated]);
    }

    #[test]
    fn a_missing_address_device_is_undecidable() {
        let conf = instance("interface eth1\nvirtual_ipaddress {\n192.0.2.1/24 dev br9\n}");
        assert_eq!(
            verdicts(&conf, &ha_host()),
            vec![Verdict::Unknown("address device br9 does not exist".into())]
        );
        // Unless another address already shows the link carries traffic.
        let conf = instance(
            "interface eth1\nvirtual_ipaddress {\n192.0.2.1/24 dev br9\n198.51.100.1/24\n}",
        );
        assert_eq!(verdicts(&conf, &ha_host()), vec![Verdict::NotDedicated]);
    }

    #[test]
    fn unicast_without_interface_uses_the_source_address_holder() {
        let conf =
            instance("unicast_src_ip 192.0.2.250\nvirtual_ipaddress {\n198.51.100.1/24 dev br0\n}");
        let host = ha_host().addr("eth1", "192.0.2.250");
        assert_eq!(
            verdicts(&conf, &host),
            vec![Verdict::Dedicated("eth1".into())]
        );
        assert!(matches!(
            verdicts(&conf, &ha_host())[0],
            Verdict::Unknown(_)
        ));
        let no_source = instance("virtual_ipaddress {\n198.51.100.1/24 dev br0\n}");
        assert!(matches!(
            verdicts(&no_source, &ha_host())[0],
            Verdict::Unknown(_)
        ));
    }

    #[test]
    fn quoted_names_match_unquoted() {
        // keepalived strips quote characters, so these name eth1 and br0.
        let conf = "vrrp_instance \"VI_1\" {\n  interface \"eth1\"\n  virtual_ipaddress {\n    192.0.2.1/24 dev \"br0\"\n  }\n}\n";
        let parsed = parse(conf);
        assert_eq!(parsed.instances[0].name, "VI_1");
        assert_eq!(parsed.instances[0].vip_devs, vec![Some("br0".to_string())]);
        assert_eq!(
            verdicts(conf, &ha_host()),
            vec![Verdict::Dedicated("eth1".into())]
        );
    }

    #[test]
    fn substitutions_are_expanded() {
        let conf = "$HA_IF=eth1\n$LAN=br0\n".to_string()
            + &instance("interface $HA_IF\nvirtual_ipaddress {\n192.0.2.1/24 dev ${LAN}\n}");
        assert_eq!(
            verdicts(&conf, &ha_host()),
            vec![Verdict::Dedicated("eth1".into())]
        );
    }

    #[test]
    fn an_undefined_substitution_is_undecidable() {
        let conf = instance("interface $HA_IF\nvirtual_ipaddress {\n192.0.2.1/24 dev br0\n}");
        assert!(matches!(
            verdicts(&conf, &ha_host())[0],
            Verdict::Unknown(_)
        ));
    }

    #[test]
    fn conditional_lines_are_undecidable() {
        let inside =
            instance("@node_a interface eth1\nvirtual_ipaddress {\n192.0.2.1/24 dev br0\n}");
        assert!(matches!(
            verdicts(&inside, &ha_host())[0],
            Verdict::Unknown(_)
        ));
        let opener = "@^node_b vrrp_instance VI_1 {\ninterface eth1\nvirtual_ipaddress {\n192.0.2.1/24 dev br0\n}\n}\n";
        assert!(matches!(
            verdicts(opener, &ha_host())[0],
            Verdict::Unknown(_)
        ));
        let address =
            instance("interface eth1\nvirtual_ipaddress {\n@node_a 192.0.2.1/24 dev br0\n}");
        assert!(matches!(
            verdicts(&address, &ha_host())[0],
            Verdict::Unknown(_)
        ));
    }

    #[test]
    fn seq_leaves_the_file_unresolved() {
        let conf = "~SEQ(i, 1, 2) $IF=eth$i\n".to_string() + HA_LINK;
        assert!(parse(&conf).unresolved.is_some());
    }

    #[test]
    fn braces_on_their_own_lines_and_comments() {
        let conf = "! keepalived\nvrrp_instance VI_1\n{\n  interface eth1   # the HA link\n  virtual_ipaddress\n  {\n    192.0.2.1/24 dev br0\n  }\n}\n";
        assert_eq!(
            verdicts(conf, &ha_host()),
            vec![Verdict::Dedicated("eth1".into())]
        );
    }

    #[test]
    fn one_line_blocks() {
        let conf =
            "vrrp_instance VI_1 { interface eth1\n virtual_ipaddress { 192.0.2.1/24 dev br0 }\n}";
        assert_eq!(
            verdicts(conf, &ha_host()),
            vec![Verdict::Dedicated("eth1".into())]
        );
    }

    #[test]
    fn interface_inside_a_nested_block_is_not_the_instance_interface() {
        let conf = instance(
            "track_interface {\ninterface eth3\n}\ninterface eth1\nvirtual_ipaddress {\n192.0.2.1/24 dev br0\n}",
        );
        assert_eq!(parse(&conf).instances[0].interface.as_deref(), Some("eth1"));
    }

    #[test]
    fn missing_configs_say_nothing() {
        let dir = std::env::temp_dir().join(format!("pf-vrrp-missing-{}", std::process::id()));
        let found = dedicated_links(&[&dir.join("keepalived.conf")], &ha_host());
        assert!(found.links.is_empty());
        assert!(found.unchecked.is_empty());
        assert!(found.unreadable.is_empty());
    }

    #[test]
    fn links_are_read_from_the_config_files() {
        let dir = std::env::temp_dir().join(format!("pf-vrrp-read-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keepalived.conf");
        std::fs::write(&path, HA_LINK).unwrap();
        let unresolved = dir.join("seq.conf");
        std::fs::write(&unresolved, "~SEQ(i, 1, 2)\n").unwrap();
        let found = dedicated_links(&[&dir.join("absent.conf"), &path, &unresolved], &ha_host());
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            found.links,
            vec![DedicatedLink {
                iface: "eth1".into(),
                instance: "eth1v42".into(),
                config: path,
            }]
        );
        assert_eq!(found.unchecked.len(), 1);
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
