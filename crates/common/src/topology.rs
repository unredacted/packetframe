//! Kernel link shapes — VLAN devices, bridges, their members — and the
//! destination MACs the router receives on through a given port.
//!
//! Shared by the two modules that must tell a frame addressed to the
//! router from one the kernel is only bridging past it: vpp-offload
//! scopes its NIC divert rules to these MACs, and fast-path consults
//! them before routing a frame (`RX_MACS`).
//!
//! Everything here reads standard Linux structures — `/proc/net/vlan`,
//! `/sys/class/net/*/{bridge,brif,master,address}` — so none of it is
//! specific to UniFi.

use std::collections::HashMap;
use std::path::Path;

/// What a kernel device is, as far as reaching a neighbour through it
/// is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevKind {
    /// No VLAN and no bridge in the way — a member port if it is one.
    Plain,
    /// A VLAN device directly on a port (`eth4.100`, or a bridge whose
    /// single member is one): every neighbour on it is behind `port`,
    /// tagged `vid`.
    PortVlan { port: String, vid: u16 },
    /// A VLAN on a bridge (`switch0.3998`, or `br3998` whose single
    /// member is that): each neighbour is behind whichever of `bridge`'s
    /// ports its MAC is learned on, tagged `vid`.
    BridgeVlan { bridge: String, vid: u16 },
}

/// The link facts classification needs, behind a seam so the shapes are
/// testable without a kernel.
pub trait LinkFacts {
    /// `(vid, lower device)` if `dev` is an 802.1Q device.
    fn vlan(&self, dev: &str) -> Option<(u16, String)>;
    /// Whether `dev` is a bridge master.
    fn is_bridge(&self, dev: &str) -> bool;
    /// The bridge's enslaved devices, sorted.
    fn bridge_ports(&self, dev: &str) -> Vec<String>;
}

/// Classify `dev` by shape. `None` for a shape nothing can place a
/// neighbour behind — a bridge with several members that is not itself
/// a VLAN device, for instance, whose neighbours could be behind
/// anything.
pub fn classify(facts: &dyn LinkFacts, dev: &str) -> Option<DevKind> {
    let through_vlan = |vid: u16, lower: String| {
        if facts.is_bridge(&lower) {
            DevKind::BridgeVlan { bridge: lower, vid }
        } else {
            DevKind::PortVlan { port: lower, vid }
        }
    };
    if let Some((vid, lower)) = facts.vlan(dev) {
        return Some(through_vlan(vid, lower));
    }
    if facts.is_bridge(dev) {
        // The UniFi shape, and a common one: an L3 bridge per VLAN whose
        // only member is the VLAN device carrying it.
        return match facts.bridge_ports(dev).as_slice() {
            [only] => facts
                .vlan(only)
                .map(|(vid, lower)| through_vlan(vid, lower)),
            _ => None,
        };
    }
    Some(DevKind::Plain)
}

/// The destination MACs a frame addressed to the router carries when it
/// arrives on `port`.
///
/// A bridge member receives more than the router's own frames: the
/// kernel bridge forwards between its members, and a member in promisc
/// hands the NIC every frame on the segment. Anything that matches on IP
/// alone would take host-to-host frames the kernel is only bridging —
/// two hosts on one VLAN behind different trunks — for routed traffic.
///
/// - **A bridge member**: the bridge's own MAC, plus the MAC of each L3
///   device on a VLAN the port carries (`carried`; `None` when the
///   membership is unknown, which takes every VLAN — each extra MAC is
///   still one the router owns). "L3 device" means one no bridge has
///   enslaved: `br3998`, not the `switch0.3998` beneath it, which never
///   does L3.
/// - **A plain port**: its own MAC only. A VLAN device there with a MAC
///   of its own is left out: VPP's subif accepts only the VF's MAC, so
///   steering frames addressed to it would drop them, and for the
///   fast path a left-out MAC only means its frames take the kernel
///   path. Either way leaving it out is the safe direction.
///
/// Deduplicated and sorted: on a box whose VLAN bridges share the
/// bridge's MAC (UniFi) this is one MAC. Empty only when no address
/// could be read for the port or its bridge.
pub fn receive_macs(
    facts: &dyn LinkFacts,
    devs: &[String],
    port: &str,
    carried: Option<&[u16]>,
    master_of: impl Fn(&str) -> Option<String>,
    mac_of: impl Fn(&str) -> Option<[u8; 6]>,
) -> Vec<[u8; 6]> {
    let Some(master) = master_of(port) else {
        return mac_of(port).into_iter().collect();
    };
    let mut macs: Vec<[u8; 6]> = mac_of(&master).into_iter().collect();
    for d in devs {
        let on_carried_vlan = match classify(facts, d) {
            Some(DevKind::BridgeVlan { bridge, vid }) => {
                bridge == master && carried.is_none_or(|c| c.contains(&vid))
            }
            _ => false,
        };
        if on_carried_vlan && master_of(d).is_none() {
            macs.extend(mac_of(d));
        }
    }
    macs.sort_unstable();
    macs.dedup();
    macs
}

/// Link facts read from a sysfs `class/net` root, with the VLAN table
/// handed in: the one fact sysfs does not carry.
struct SysfsLinks<'a> {
    root: &'a Path,
    vlans: &'a HashMap<String, (u16, String)>,
}

impl LinkFacts for SysfsLinks<'_> {
    fn vlan(&self, dev: &str) -> Option<(u16, String)> {
        self.vlans.get(dev).cloned()
    }
    fn is_bridge(&self, dev: &str) -> bool {
        self.root.join(dev).join("bridge").is_dir()
    }
    fn bridge_ports(&self, dev: &str) -> Vec<String> {
        let mut out: Vec<String> = std::fs::read_dir(self.root.join(dev).join("brif"))
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        out.sort();
        out
    }
}

/// [`receive_macs`] with every device fact — members, bridges, masters,
/// addresses — read from a sysfs `class/net` root (`/sys/class/net` in
/// production; a fixture in tests) and the VLAN table and the port's
/// VLAN membership handed in.
pub fn sysfs_receive_macs(
    sysfs_net: &Path,
    vlans: &HashMap<String, (u16, String)>,
    carried: Option<&[u16]>,
    port: &str,
) -> Vec<[u8; 6]> {
    let master_of = |dev: &str| {
        let link = std::fs::read_link(sysfs_net.join(dev).join("master")).ok()?;
        Some(link.file_name()?.to_str()?.to_string())
    };
    let mac_of =
        |dev: &str| parse_mac(&std::fs::read_to_string(sysfs_net.join(dev).join("address")).ok()?);
    let mut devs: Vec<String> = std::fs::read_dir(sysfs_net)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    devs.sort();
    let facts = SysfsLinks {
        root: sysfs_net,
        vlans,
    };
    receive_macs(&facts, &devs, port, carried, master_of, mac_of)
}

/// Read and parse `/proc/net/vlan/config` (or a fixture). A missing file
/// means no 8021q module and so no VLANs — an answer; any other read
/// error is not, and callers must not treat it as "no VLANs", which
/// would silently leave out every VLAN L3 device's MAC.
pub fn read_vlan_config(path: &Path) -> Result<HashMap<String, (u16, String)>, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(parse_vlan_config(&text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// `aa:bb:cc:dd:ee:ff` as sysfs writes it.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.trim().split(':');
    for b in &mut out {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// Parse `/proc/net/vlan/config`. Separate from the read so the format
/// is tested on every host.
pub fn parse_vlan_config(text: &str) -> HashMap<String, (u16, String)> {
    text.lines()
        .filter_map(|line| {
            let mut cols = line.split('|').map(str::trim);
            let name = cols.next()?;
            let vid = cols.next()?.parse().ok()?;
            let lower = cols.next()?;
            (!name.is_empty() && !lower.is_empty())
                .then(|| (name.to_string(), (vid, lower.to_string())))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// A reference edge shape, plus the generic ones.
    #[derive(Default)]
    struct Facts {
        vlans: BTreeMap<&'static str, (u16, &'static str)>,
        bridges: BTreeMap<&'static str, Vec<&'static str>>,
    }

    impl LinkFacts for Facts {
        fn vlan(&self, dev: &str) -> Option<(u16, String)> {
            self.vlans.get(dev).map(|(v, l)| (*v, l.to_string()))
        }
        fn is_bridge(&self, dev: &str) -> bool {
            self.bridges.contains_key(dev)
        }
        fn bridge_ports(&self, dev: &str) -> Vec<String> {
            let set: BTreeSet<String> = self
                .bridges
                .get(dev)
                .into_iter()
                .flatten()
                .map(|s| s.to_string())
                .collect();
            set.into_iter().collect()
        }
    }

    fn edge() -> Facts {
        let mut f = Facts::default();
        f.bridges.insert("switch0", vec!["eth4", "eth5"]);
        f.bridges.insert("br3998", vec!["switch0.3998"]);
        f.bridges.insert("br1337", vec!["switch0.1337"]);
        f.bridges.insert("br100", vec!["eth2.100"]);
        f.bridges.insert("brwide", vec!["eth2", "eth3"]);
        f.vlans.insert("switch0.3998", (3998, "switch0"));
        f.vlans.insert("switch0.1337", (1337, "switch0"));
        f.vlans.insert("eth2.100", (100, "eth2"));
        f
    }

    /// A bridge member answers to its bridge's MAC and to the L3 devices
    /// (never an enslaved lower) of the VLANs it carries; a plain port to
    /// its own MAC alone. Each MAC once.
    #[test]
    fn a_port_receives_on_its_l3_devices_macs() {
        let mac = |b: u8| [0x02, 0, 0, 0, 0, b];
        let devs: Vec<String> = [
            "switch0",
            "switch0.3998",
            "switch0.1337",
            "br3998",
            "br1337",
            "eth2",
            "eth2.100",
            "br100",
            "eth3",
            "eth4",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let master_of = |d: &str| match d {
            "eth4" | "eth5" => Some("switch0".to_string()),
            "switch0.3998" => Some("br3998".to_string()),
            "switch0.1337" => Some("br1337".to_string()),
            "eth2.100" => Some("br100".to_string()),
            _ => None,
        };
        let mac_of = |d: &str| {
            Some(match d {
                "br1337" => mac(2),       // a VLAN bridge with its own MAC
                "switch0.1337" => mac(3), // an enslaved lower: never L3
                "switch0" | "switch0.3998" | "br3998" => mac(1),
                "eth2" => mac(0x20),
                "eth2.100" | "br100" => mac(0x21), // a plain port's VLAN MAC
                "eth3" => mac(0x30),
                "eth4" => mac(0x40),
                _ => return None,
            })
        };
        assert_eq!(
            receive_macs(&edge(), &devs, "eth4", None, master_of, mac_of),
            vec![mac(1), mac(2)],
            "the bridge's and its VLAN L3 devices' MACs, not the port's or a lower's"
        );
        assert_eq!(
            receive_macs(&edge(), &devs, "eth4", Some(&[3998]), master_of, mac_of),
            vec![mac(1)],
            "only the VLANs the port carries"
        );
        assert_eq!(
            receive_macs(&edge(), &devs, "eth2", None, master_of, mac_of),
            vec![mac(0x20)],
            "a plain port scopes to its own MAC"
        );
        assert!(receive_macs(&edge(), &devs, "eth9", None, master_of, mac_of).is_empty());
    }

    /// The sysfs-rooted lookup reads every device fact — masters,
    /// bridges and their members, addresses — from the root it is given,
    /// never the host's: a bridge member takes its bridge's MAC and the
    /// L3 bridge of a carried VLAN, and a port with no readable address
    /// gets nothing.
    #[test]
    fn receive_macs_read_from_a_sysfs_root() {
        let root = std::env::temp_dir().join(format!("pf-rxmac-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (dev, mac) in [
            ("switch0", "02:00:00:00:69:c7"),
            ("switch0.100", "02:00:00:00:69:c7"),
            ("br100", "02:00:00:00:01:00"),
            ("eth4", "02:00:00:00:69:ca"),
            ("eth2", "02:00:00:00:69:c8"),
        ] {
            std::fs::create_dir_all(root.join(dev)).unwrap();
            std::fs::write(root.join(dev).join("address"), format!("{mac}\n")).unwrap();
        }
        for bridge in ["switch0", "br100"] {
            std::fs::create_dir_all(root.join(bridge).join("bridge")).unwrap();
        }
        std::fs::create_dir_all(root.join("br100").join("brif").join("switch0.100")).unwrap();
        let link = |dev: &str, master: &str| {
            std::os::unix::fs::symlink(root.join(master), root.join(dev).join("master")).unwrap()
        };
        link("eth4", "switch0");
        link("switch0.100", "br100");
        std::fs::create_dir_all(root.join("eth9")).unwrap();
        let vlans: HashMap<String, (u16, String)> =
            [("switch0.100".to_string(), (100, "switch0".to_string()))].into();

        assert_eq!(
            sysfs_receive_macs(&root, &vlans, None, "eth4"),
            vec![[0x02, 0, 0, 0, 0x01, 0x00], [0x02, 0, 0, 0, 0x69, 0xc7]],
            "the bridge's MAC and VLAN 100's L3 bridge, not the port's own"
        );
        assert_eq!(
            sysfs_receive_macs(&root, &vlans, Some(&[1]), "eth4"),
            vec![[0x02, 0, 0, 0, 0x69, 0xc7]],
            "VLAN 100 is not carried"
        );
        assert_eq!(
            sysfs_receive_macs(&root, &vlans, None, "eth2"),
            vec![[0x02, 0, 0, 0, 0x69, 0xc8]]
        );
        assert!(sysfs_receive_macs(&root, &vlans, None, "eth9").is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_l3_bridge_over_a_vlan_on_a_bridge_is_placed_per_neighbour() {
        assert_eq!(
            classify(&edge(), "br3998"),
            Some(DevKind::BridgeVlan {
                bridge: "switch0".into(),
                vid: 3998
            })
        );
        assert_eq!(
            classify(&edge(), "switch0.1337"),
            Some(DevKind::BridgeVlan {
                bridge: "switch0".into(),
                vid: 1337
            }),
            "the VLAN device itself classifies the same way"
        );
    }

    #[test]
    fn a_vlan_on_a_port_is_that_ports_subinterface() {
        let want = Some(DevKind::PortVlan {
            port: "eth2".into(),
            vid: 100,
        });
        assert_eq!(classify(&edge(), "eth2.100"), want);
        assert_eq!(classify(&edge(), "br100"), want);
    }

    #[test]
    fn plain_devices_and_unreachable_shapes() {
        assert_eq!(classify(&edge(), "eth3"), Some(DevKind::Plain));
        assert_eq!(
            classify(&edge(), "brwide"),
            None,
            "an untagged multi-port bridge: nothing says which VLAN or port"
        );
    }

    #[test]
    fn proc_net_vlan_config_parses() {
        let text = "VLAN Dev name\t | VLAN ID\nName-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD\n\
                    switch0.3998   | 3998  | switch0\nswitch0.1337   | 1337  | switch0\n";
        let v = parse_vlan_config(text);
        assert_eq!(v.len(), 2, "{v:?}");
        assert_eq!(v["switch0.3998"], (3998, "switch0".to_string()));
    }

    /// No 8021q module is an answer (no VLANs); an unreadable table is
    /// not, and must not read as one.
    #[test]
    fn a_missing_vlan_table_is_empty_and_an_unreadable_one_is_an_error() {
        let dir = std::env::temp_dir().join(format!("pf-vlancfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_vlan_config(&dir.join("absent")), Ok(HashMap::new()));
        // A directory where the file should be: exists, cannot be read.
        assert!(read_vlan_config(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sysfs_mac_strings_parse() {
        assert_eq!(
            parse_mac("02:00:5e:10:00:ff\n"),
            Some([0x02, 0, 0x5e, 0x10, 0, 0xff])
        );
        assert_eq!(parse_mac("02:00:5e:10:00"), None);
        assert_eq!(parse_mac("02:00:5e:10:00:ff:01"), None);
    }
}
