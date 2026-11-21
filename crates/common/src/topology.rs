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
///   enslaved (a VRF may have): `br3998`, not the `switch0.3998` beneath it, which never
///   does L3.
/// - **A plain port**, including one enslaved to a master that is not a
///   bridge (a VRF, say, which routes rather than bridges): its own MAC
///   only. A VLAN device there with a MAC
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
    let mut macs: Vec<[u8; 6]> =
        receive_vlan_macs(facts, devs, port, carried, None, master_of, mac_of)
            .into_iter()
            .map(|(_, mac)| mac)
            .collect();
    macs.sort_unstable();
    macs.dedup();
    macs
}

/// [`receive_macs`] with the VLAN each MAC is received on: `(vid, mac)`,
/// vid 0 for untagged. The MACs are the same; what this adds is that a
/// tagged frame is addressed to the router only on a VLAN the router has
/// an L3 device for on that port. A frame tagged with any other VID is
/// one the kernel drops (no VLAN device takes it), so routing it would
/// carry a VLAN the router does not route into one it does.
///
/// - **A plain port**: its own MAC untagged, and on the VID of each L3
///   device on a VLAN of the port (`eth2.100`, or `br100` over it, never
///   an enslaved lower).
/// - **A bridge member**: the bridge's MAC untagged, and on the VID of
///   each L3 device on a VLAN of the bridge the port carries (`carried`,
///   as for [`receive_macs`]), the bridge's MAC and that device's.
/// - **A member of a bridge that filters by VLAN** (`filter`, which then
///   replaces `carried`): the same MACs, keyed by the VID the frame
///   carries on the wire, for the frames [`BridgeVlans::passes_up`] says
///   the bridge admits from the port and passes up. A frame passed up
///   untagged reaches the bridge's own MAC, one passed up on VLAN `v`
///   the MACs of `v` above. `filter` is ignored for a port no bridge
///   has enslaved.
///
/// Sorted and deduplicated.
pub fn receive_vlan_macs(
    facts: &dyn LinkFacts,
    devs: &[String],
    port: &str,
    carried: Option<&[u16]>,
    filter: Option<&BridgeVlans>,
    master_of: impl Fn(&str) -> Option<String>,
    mac_of: impl Fn(&str) -> Option<[u8; 6]>,
) -> Vec<(u16, [u8; 6])> {
    // Only a bridge master makes a port a bridge member; any other
    // master (a VRF) leaves it a routed port with its own MAC.
    let bridge_of = |dev: &str| master_of(dev).filter(|m| facts.is_bridge(m));
    let mut out: Vec<(u16, [u8; 6])> = Vec::new();
    match bridge_of(port) {
        None => {
            let Some(own) = mac_of(port) else {
                return out;
            };
            out.push((0, own));
            for d in devs {
                if let Some(DevKind::PortVlan { port: lower, vid }) = classify(facts, d) {
                    if lower == port && bridge_of(d).is_none() {
                        out.push((vid, own));
                    }
                }
            }
        }
        Some(master) => {
            let bridge_mac = mac_of(&master);
            // Each VLAN of the bridge with an L3 device: the MACs a frame
            // passed up tagged with it is addressed to the router by.
            let mut l3: HashMap<u16, Vec<[u8; 6]>> = HashMap::new();
            for d in devs {
                let Some(DevKind::BridgeVlan { bridge, vid }) = classify(facts, d) else {
                    continue;
                };
                if bridge != master || bridge_of(d).is_some() {
                    continue;
                }
                let macs = l3.entry(vid).or_default();
                macs.extend(bridge_mac);
                macs.extend(mac_of(d));
            }
            match filter {
                None => {
                    out.extend(bridge_mac.map(|m| (0, m)));
                    for (vid, macs) in &l3 {
                        if carried.is_none_or(|c| c.contains(vid)) {
                            out.extend(macs.iter().map(|m| (*vid, *m)));
                        }
                    }
                }
                Some(filter) => {
                    for wire in std::iter::once(0).chain(filter.port.iter().copied()) {
                        match filter.passes_up(wire) {
                            None => {}
                            Some(PassedUp::Untagged) => {
                                out.extend(bridge_mac.map(|m| (wire, m)));
                            }
                            Some(PassedUp::Tagged(vid)) => {
                                let macs = l3.get(&vid).map(Vec::as_slice).unwrap_or_default();
                                out.extend(macs.iter().map(|m| (wire, *m)));
                            }
                        }
                    }
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// One `IFLA_BRIDGE_VLAN_INFO` record of an AF_BRIDGE dump, as `bridge
/// vlan show` prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanRecord {
    pub vid: u16,
    pub pvid: bool,
    /// Egress untagged: for a port, sent out of it without a tag; for a
    /// bridge's own entry, passed up to its stack without one.
    pub untagged: bool,
    pub range_begin: bool,
    pub range_end: bool,
}

/// `(vid, pvid, untagged)` for every VLAN `records` name, a
/// `RANGE_BEGIN`…`RANGE_END` pair expanded into each VID between with the
/// first record's flags. The `RTEXT_FILTER_BRVLAN` dump reports one VLAN
/// per record today (ranges are `RTEXT_FILTER_BRVLAN_COMPRESSED`'s); a
/// range is expanded rather than assumed away, and one left open is
/// dropped, which only leaves VLANs out.
pub fn expand_vlan_records(records: &[VlanRecord]) -> Vec<(u16, bool, bool)> {
    let mut out = Vec::new();
    let mut begin: Option<VlanRecord> = None;
    for r in records {
        match (begin, r.range_end) {
            (Some(b), true) => {
                out.extend((b.vid..=r.vid).map(|vid| (vid, b.pvid && vid == b.vid, b.untagged)));
                begin = None;
            }
            _ if r.range_begin => begin = Some(*r),
            _ => {
                begin = None;
                out.push((r.vid, r.pvid, r.untagged));
            }
        }
    }
    out
}

/// What a bridge that filters by VLAN admits from one of its ports and
/// passes up to its own stack: the port's VLAN table and PVID, and the
/// bridge's own ("self") VLANs. Read from an AF_BRIDGE dump
/// (`crate::bridge_vlan`, Linux).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BridgeVlans {
    /// The port's VLANs, sorted.
    pub port: Vec<u16>,
    /// The VLAN an untagged or priority-tagged frame from the port is
    /// assigned; `None` drops them.
    pub pvid: Option<u16>,
    /// The bridge's own VLANs, sorted, each with whether a frame on it is
    /// passed up untagged.
    pub bridge: Vec<(u16, bool)>,
}

/// How a bridge passes a frame up to its own stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassedUp {
    /// Without a tag: to the bridge device itself.
    Untagged,
    /// Tagged with this VID: to the bridge's VLAN device for it, if any.
    Tagged(u16),
}

impl BridgeVlans {
    /// From the port's and the bridge's records ([`VlanRecord`]).
    pub fn from_records(port: &[VlanRecord], bridge: &[VlanRecord]) -> Self {
        let port_vlans = expand_vlan_records(port);
        let mut out = Self {
            port: port_vlans.iter().map(|(vid, _, _)| *vid).collect(),
            pvid: port_vlans
                .iter()
                .find(|(_, pvid, _)| *pvid)
                .map(|(vid, _, _)| *vid),
            bridge: expand_vlan_records(bridge)
                .into_iter()
                .map(|(vid, _, untagged)| (vid, untagged))
                .collect(),
        };
        out.port.sort_unstable();
        out.port.dedup();
        out.bridge.sort_unstable();
        out.bridge.dedup_by_key(|(vid, _)| *vid);
        out
    }

    /// How a frame from the port carrying `wire` (its 802.1Q VID, 0 for
    /// an untagged or priority-tagged frame) is passed up, or `None` if
    /// the bridge does not pass it up. Ingress assigns an untagged frame
    /// the PVID and admits a VLAN only if it is in the port's table; the
    /// bridge then passes a frame up only on a VLAN of its own, untagged
    /// if that entry says so (`br_allowed_ingress`, `br_pass_frame_up`).
    pub fn passes_up(&self, wire: u16) -> Option<PassedUp> {
        let vid = if wire == 0 { self.pvid? } else { wire };
        if self.port.binary_search(&vid).is_err() {
            return None;
        }
        let i = self.bridge.binary_search_by_key(&vid, |(v, _)| *v).ok()?;
        Some(if self.bridge[i].1 {
            PassedUp::Untagged
        } else {
            PassedUp::Tagged(vid)
        })
    }
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
    let mut macs: Vec<[u8; 6]> = sysfs_receive_vlan_macs(sysfs_net, vlans, carried, None, port)
        .into_iter()
        .map(|(_, mac)| mac)
        .collect();
    macs.sort_unstable();
    macs.dedup();
    macs
}

/// [`receive_vlan_macs`] read from a sysfs `class/net` root, as
/// [`sysfs_receive_macs`], with the bridge's VLAN `filter` handed in.
pub fn sysfs_receive_vlan_macs(
    sysfs_net: &Path,
    vlans: &HashMap<String, (u16, String)>,
    carried: Option<&[u16]>,
    filter: Option<&BridgeVlans>,
    port: &str,
) -> Vec<(u16, [u8; 6])> {
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
    receive_vlan_macs(&facts, &devs, port, carried, filter, master_of, mac_of)
}

/// How `port`'s bridge, if it has one, admits frames from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeVlanMode {
    /// No bridge enslaves the port, or its bridge does not filter by
    /// VLAN: every VLAN passes, and only the VLAN devices decide.
    Unfiltered,
    /// `bridge` filters by 802.1Q VLAN: its VLAN tables decide
    /// ([`BridgeVlans`]).
    Filtering { bridge: String },
    /// `bridge` filters in a way [`BridgeVlans`] does not model: whether
    /// it filters cannot be read, or it filters by 802.1ad S-VLAN, where
    /// a frame's 802.1Q tag is not the VLAN it is admitted on.
    Unsupported { bridge: String, why: String },
}

/// [`BridgeVlanMode`] of `port`, from a sysfs `class/net` root:
/// `bridge/vlan_filtering` and `bridge/vlan_protocol` of its master.
pub fn sysfs_bridge_vlan_mode(sysfs_net: &Path, port: &str) -> BridgeVlanMode {
    let Some(master) = std::fs::read_link(sysfs_net.join(port).join("master"))
        .ok()
        .and_then(|l| Some(l.file_name()?.to_str()?.to_string()))
    else {
        return BridgeVlanMode::Unfiltered;
    };
    let bridge = sysfs_net.join(&master).join("bridge");
    if !bridge.is_dir() {
        return BridgeVlanMode::Unfiltered;
    }
    let unsupported = |why: &str| BridgeVlanMode::Unsupported {
        bridge: master.clone(),
        why: why.to_string(),
    };
    match std::fs::read_to_string(bridge.join("vlan_filtering")).map(|s| s.trim() == "0") {
        Ok(true) => return BridgeVlanMode::Unfiltered,
        Ok(false) => {}
        Err(_) => return unsupported("vlan_filtering unreadable"),
    }
    match std::fs::read_to_string(bridge.join("vlan_protocol")) {
        Ok(p) if p.trim() == "0x8100" => BridgeVlanMode::Filtering { bridge: master },
        Ok(p) => unsupported(&format!("vlan_protocol {}", p.trim())),
        Err(_) => unsupported("vlan_protocol unreadable"),
    }
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

    /// The same MACs, each on the VLANs it is received on: untagged, and
    /// the VID of each L3 device on the port's (or its bridge's) VLANs.
    /// A VID with no L3 device there is on no entry, since the kernel
    /// drops a frame tagged with it.
    #[test]
    fn each_mac_is_received_on_the_vlans_with_an_l3_device() {
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
                "br1337" => mac(2),
                "switch0.1337" => mac(3),
                "switch0" | "switch0.3998" | "br3998" => mac(1),
                "eth2" => mac(0x20),
                "eth2.100" | "br100" => mac(0x21),
                "eth3" => mac(0x30),
                _ => return None,
            })
        };
        let rx = |port: &str, carried: Option<&[u16]>| {
            receive_vlan_macs(&edge(), &devs, port, carried, None, master_of, mac_of)
        };
        assert_eq!(
            rx("eth4", None),
            vec![(0, mac(1)), (1337, mac(1)), (1337, mac(2)), (3998, mac(1))],
            "the bridge's MAC untagged; on each L3 VLAN the bridge's and that device's"
        );
        assert_eq!(
            rx("eth4", Some(&[3998])),
            vec![(0, mac(1)), (3998, mac(1))],
            "only the VLANs the port carries"
        );
        assert_eq!(
            rx("eth2", None),
            vec![(0, mac(0x20)), (100, mac(0x20))],
            "a plain port's own MAC, untagged and on its L3 VLAN"
        );
        assert_eq!(
            rx("eth3", None),
            vec![(0, mac(0x30))],
            "no VLAN, untagged only"
        );
        assert!(rx("eth9", None).is_empty());
        for port in ["eth4", "eth2", "eth3"] {
            let mut macs: Vec<[u8; 6]> = rx(port, None).into_iter().map(|(_, m)| m).collect();
            macs.sort_unstable();
            macs.dedup();
            assert_eq!(
                macs,
                receive_macs(&edge(), &devs, port, None, master_of, mac_of),
                "{port}: the same MACs as receive_macs"
            );
        }
    }

    fn rec(vid: u16, pvid: bool, untagged: bool) -> VlanRecord {
        VlanRecord {
            vid,
            pvid,
            untagged,
            range_begin: false,
            range_end: false,
        }
    }

    /// The UniFi shape, as `bridge vlan show` prints it on a gateway:
    /// each `switch0` port has VLAN 1 as PVID and 3900 tagged, and
    /// `switch0`'s own entries are both tagged, so a frame on either is
    /// passed up to `switch0.1` or `switch0.3900`, each the only member
    /// of an L3 bridge (`br0`, `br3900`).
    fn unifi_switch0() -> BridgeVlans {
        BridgeVlans::from_records(
            &[rec(1, true, true), rec(3900, false, false)],
            &[rec(1, false, false), rec(3900, false, false)],
        )
    }

    #[test]
    fn a_filtering_bridge_admits_by_the_port_table_and_passes_up_by_its_own() {
        let f = unifi_switch0();
        assert_eq!(f.port, vec![1, 3900]);
        assert_eq!(f.pvid, Some(1));
        assert_eq!(
            f.passes_up(0),
            Some(PassedUp::Tagged(1)),
            "untagged takes the PVID"
        );
        assert_eq!(f.passes_up(1), Some(PassedUp::Tagged(1)));
        assert_eq!(f.passes_up(3900), Some(PassedUp::Tagged(3900)));
        assert_eq!(f.passes_up(3901), None, "not in the port's table");

        let no_pvid = BridgeVlans::from_records(&[rec(10, false, false)], &[rec(10, false, true)]);
        assert_eq!(no_pvid.passes_up(0), None, "no PVID drops untagged frames");
        assert_eq!(
            no_pvid.passes_up(10),
            Some(PassedUp::Untagged),
            "the bridge's own entry passes VLAN 10 up untagged"
        );

        let port_only = BridgeVlans::from_records(
            &[rec(1, true, true), rec(20, false, false)],
            &[rec(1, true, true)],
        );
        assert_eq!(
            port_only.passes_up(20),
            None,
            "admitted from the port but not a VLAN of the bridge's own"
        );
        assert_eq!(port_only.passes_up(0), Some(PassedUp::Untagged));
    }

    #[test]
    fn vlan_ranges_are_expanded() {
        let begin = VlanRecord {
            range_begin: true,
            ..rec(10, false, false)
        };
        let end = VlanRecord {
            range_end: true,
            ..rec(12, false, false)
        };
        assert_eq!(
            expand_vlan_records(&[rec(1, true, true), begin, end]),
            vec![
                (1, true, true),
                (10, false, false),
                (11, false, false),
                (12, false, false)
            ]
        );
        assert_eq!(
            expand_vlan_records(&[begin]),
            vec![],
            "a range left open is dropped"
        );
    }

    /// On a filtering bridge, each MAC is keyed by the VID the frame
    /// carries on the wire: an untagged frame on the PVID reaches the
    /// PVID's L3 device, and a VLAN the port is not in, or the bridge
    /// does not pass up, or that has no L3 device, gets nothing.
    #[test]
    fn a_filtering_bridge_member_receives_by_its_vlan_table() {
        let mac = |b: u8| [0x02, 0, 0, 0, 0, b];
        let facts = Facts {
            vlans: [
                ("switch0.1", (1, "switch0")),
                ("switch0.3900", (3900, "switch0")),
                ("switch0.20", (20, "switch0")),
            ]
            .into(),
            bridges: [
                ("switch0", vec!["eth2", "eth3"]),
                ("br0", vec!["switch0.1"]),
                ("br3900", vec!["switch0.3900"]),
                ("br20", vec!["switch0.20"]),
            ]
            .into(),
        };
        let devs: Vec<String> = [
            "switch0",
            "switch0.1",
            "switch0.3900",
            "switch0.20",
            "br0",
            "br3900",
            "br20",
            "eth2",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let master_of = |d: &str| match d {
            "eth2" | "eth3" => Some("switch0".to_string()),
            "switch0.1" => Some("br0".to_string()),
            "switch0.3900" => Some("br3900".to_string()),
            "switch0.20" => Some("br20".to_string()),
            _ => None,
        };
        let mac_of = |d: &str| {
            Some(match d {
                "br20" => mac(0x20),
                d if d.starts_with("eth") => return None,
                _ => mac(1),
            })
        };
        let rx = |filter: &BridgeVlans| {
            receive_vlan_macs(&facts, &devs, "eth2", None, Some(filter), master_of, mac_of)
        };
        assert_eq!(
            rx(&unifi_switch0()),
            vec![(0, mac(1)), (1, mac(1)), (3900, mac(1))],
            "untagged and VLAN 1 reach br0, VLAN 3900 br3900; br20's VLAN is not the port's"
        );

        let with_20 = BridgeVlans::from_records(
            &[rec(1, true, true), rec(20, false, false)],
            &[rec(1, false, false), rec(20, false, false)],
        );
        assert_eq!(
            rx(&with_20),
            vec![(0, mac(1)), (1, mac(1)), (20, mac(1)), (20, mac(0x20))],
            "VLAN 20 reaches br20 by its own MAC and the bridge's"
        );

        let untagged_up = BridgeVlans::from_records(
            &[rec(1, true, true), rec(3900, false, false)],
            &[rec(1, true, true), rec(3900, false, false)],
        );
        assert_eq!(
            rx(&untagged_up),
            vec![(0, mac(1)), (1, mac(1)), (3900, mac(1))],
            "VLAN 1 passed up untagged reaches switch0 itself"
        );

        assert_eq!(
            rx(&BridgeVlans::default()),
            vec![],
            "a port in no VLAN receives nothing"
        );
        assert_eq!(
            receive_vlan_macs(&facts, &devs, "eth2", None, None, master_of, mac_of),
            vec![
                (0, mac(1)),
                (1, mac(1)),
                (20, mac(1)),
                (20, mac(0x20)),
                (3900, mac(1))
            ],
            "without the tables, every L3 VLAN of the bridge"
        );
    }

    /// A master that is not a bridge (a VRF) routes rather than bridges:
    /// a port under it is a routed port with its own MAC, and a VLAN L3
    /// device under it is still an L3 device of its bridge.
    #[test]
    fn a_non_bridge_master_leaves_a_port_routed() {
        let mac = |b: u8| [0x02, 0, 0, 0, 0, b];
        let devs: Vec<String> = ["switch0", "switch0.1337", "br1337", "eth3", "eth4", "vrf-a"]
            .into_iter()
            .map(String::from)
            .collect();
        let master_of = |d: &str| match d {
            "eth3" => Some("vrf-a".to_string()),
            "eth4" => Some("switch0".to_string()),
            "switch0.1337" => Some("br1337".to_string()),
            "br1337" => Some("vrf-a".to_string()),
            _ => None,
        };
        let mac_of = |d: &str| {
            Some(match d {
                "switch0" => mac(1),
                "br1337" => mac(2),
                "switch0.1337" => mac(3),
                "eth3" => mac(0x30),
                "vrf-a" => mac(0x70),
                _ => return None,
            })
        };
        assert_eq!(
            receive_macs(&edge(), &devs, "eth3", None, master_of, mac_of),
            vec![mac(0x30)],
            "a VRF member receives on its own MAC, not the VRF device's"
        );
        assert_eq!(
            receive_macs(&edge(), &devs, "eth4", None, master_of, mac_of),
            vec![mac(1), mac(2)],
            "br1337 in a VRF is still switch0's VLAN 1337 L3 device"
        );
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
        assert_eq!(
            sysfs_receive_vlan_macs(&root, &vlans, None, None, "eth4"),
            vec![
                (0, [0x02, 0, 0, 0, 0x69, 0xc7]),
                (100, [0x02, 0, 0, 0, 0x01, 0x00]),
                (100, [0x02, 0, 0, 0, 0x69, 0xc7]),
            ]
        );

        // A filtering bridge's tables replace the VLAN devices alone:
        // VLAN 100 passed up tagged reaches br100, and VLAN 1, the PVID,
        // has no L3 device.
        let filter = BridgeVlans {
            port: vec![1, 100],
            pvid: Some(1),
            bridge: vec![(1, false), (100, false)],
        };
        assert_eq!(
            sysfs_receive_vlan_macs(&root, &vlans, None, Some(&filter), "eth4"),
            vec![
                (100, [0x02, 0, 0, 0, 0x01, 0x00]),
                (100, [0x02, 0, 0, 0, 0x69, 0xc7]),
            ]
        );

        // The bridge's filtering mode, from its sysfs settings.
        assert_eq!(
            sysfs_bridge_vlan_mode(&root, "eth4"),
            BridgeVlanMode::Unsupported {
                bridge: "switch0".to_string(),
                why: "vlan_filtering unreadable".to_string()
            },
        );
        std::fs::write(root.join("switch0/bridge/vlan_filtering"), "0\n").unwrap();
        assert_eq!(
            sysfs_bridge_vlan_mode(&root, "eth4"),
            BridgeVlanMode::Unfiltered
        );
        std::fs::write(root.join("switch0/bridge/vlan_filtering"), "1\n").unwrap();
        assert_eq!(
            sysfs_bridge_vlan_mode(&root, "eth4"),
            BridgeVlanMode::Unsupported {
                bridge: "switch0".to_string(),
                why: "vlan_protocol unreadable".to_string()
            },
        );
        std::fs::write(root.join("switch0/bridge/vlan_protocol"), "0x88a8\n").unwrap();
        assert_eq!(
            sysfs_bridge_vlan_mode(&root, "eth4"),
            BridgeVlanMode::Unsupported {
                bridge: "switch0".to_string(),
                why: "vlan_protocol 0x88a8".to_string()
            },
            "an 802.1ad bridge admits on the S-tag, which RX_MACS does not key on"
        );
        std::fs::write(root.join("switch0/bridge/vlan_protocol"), "0x8100\n").unwrap();
        assert_eq!(
            sysfs_bridge_vlan_mode(&root, "eth4"),
            BridgeVlanMode::Filtering {
                bridge: "switch0".to_string()
            }
        );
        assert_eq!(
            sysfs_bridge_vlan_mode(&root, "eth2"),
            BridgeVlanMode::Unfiltered
        );
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
