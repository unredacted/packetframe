//! Where a kernel next hop really is: per-neighbour placement.
//!
//! A route's next hop names a kernel device, and for the plain case that
//! device is a member port whose VF VPP owns. The service edge is not
//! the plain case. A neighbour on `br3998` sits behind `switch0.3998`, a
//! VLAN device on the VLAN-aware bridge `switch0`, which has two trunk
//! ports — and which of them the neighbour is behind is decided by the
//! upstream switches' spanning tree, can change under us, and is written
//! down in exactly one place: the kernel bridge's forwarding database.
//!
//! So a device is first **classified** by its shape
//! ([`packetframe_common::topology`], shared with fast-path), and a
//! [`DevKind::BridgeVlan`] neighbour is then **placed** by looking its
//! MAC up in that bridge's FDB for that VLAN ([`FdbSnapshot`]). The
//! result is a `(member port, vid)` subinterface, chosen per neighbour
//! rather than per device — which is what lets IX peers behind one
//! trunk and service hosts behind the other resolve at all, and what
//! lets VPP follow a host when spanning tree moves it (B3 v2; v1 only
//! reported the move).
//!
//! Everything here reads standard Linux structures — `/proc/net/vlan`,
//! `/sys/class/net/*/bridge`, `brif`, and the AF_BRIDGE FDB — so none of
//! it is specific to UniFi.

use std::collections::HashMap;

// Classification and the receive-MAC rule are shared with fast-path's
// destination-MAC check; re-exported so this module stays the one place
// vpp-offload asks about link shapes.
pub use packetframe_common::topology::{classify, receive_macs, DevKind, LinkFacts};
use packetframe_common::topology::{read_vlan_config, sysfs_receive_macs};

/// Devices VPP can forward through without them being member ports:
/// VLAN devices on a member that carries the vid, and bridge VLANs one
/// of whose member ports carries it. For the exemption tripwire, which
/// otherwise reports every route out `br3998` as a path VPP cannot take.
///
/// Reachable, not placed: whether a given neighbour on the device is
/// placed is the placement row's business, not the tripwire's.
pub fn reachable_devices(
    facts: &dyn LinkFacts,
    devs: &[String],
    port_vlans: &[(String, Vec<u16>)],
) -> Vec<String> {
    let carries = |port: &str, vid: u16| {
        port_vlans
            .iter()
            .any(|(p, v)| p == port && v.contains(&vid))
    };
    devs.iter()
        .filter(|dev| match classify(facts, dev) {
            Some(DevKind::PortVlan { port, vid }) => carries(&port, vid),
            Some(DevKind::BridgeVlan { bridge, vid }) => {
                facts.bridge_ports(&bridge).iter().any(|p| carries(p, vid))
            }
            _ => false,
        })
        .cloned()
        .collect()
}

/// [`sysfs_receive_macs`] under `sysfs_net`, with the VLAN table from
/// `vlan_config` (`/proc/net/vlan/config`) and the port's VLAN membership
/// from the kernel bridge. An unreadable VLAN table answers nothing — the planner then
/// refuses to steer the port — rather than a partial set that would
/// leave some of the port's L3 MACs unsteered while it reports steered.
/// An unreadable membership takes every VLAN (extra MACs only cost
/// rules).
pub fn kernel_receive_macs_in(
    sysfs_net: &std::path::Path,
    vlan_config: &std::path::Path,
    port: &str,
) -> Vec<[u8; 6]> {
    let Ok(vlans) = read_vlan_config(vlan_config) else {
        return Vec::new();
    };
    #[cfg(target_os = "linux")]
    let carried: Option<Vec<u16>> = crate::fdb::dump_port_vlans().ok().map(|entries| {
        entries
            .into_iter()
            .filter(|e| e.port == port)
            .map(|e| e.vid)
            .collect()
    });
    #[cfg(not(target_os = "linux"))]
    let carried: Option<Vec<u16>> = None;
    sysfs_receive_macs(sysfs_net, &vlans, carried.as_deref(), port)
}

/// [`kernel_receive_macs_in`] against the live kernel.
pub fn kernel_receive_macs(port: &str) -> Vec<[u8; 6]> {
    kernel_receive_macs_in(
        std::path::Path::new("/sys/class/net"),
        std::path::Path::new("/proc/net/vlan/config"),
        port,
    )
}

/// Every netdev on the box, for [`reachable_devices`].
#[cfg(target_os = "linux")]
pub fn all_netdevs() -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir("/sys/class/net")
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .collect();
    out.sort();
    out
}

/// One bridge's forwarding database, reduced to what placement asks:
/// which port is `(bridge, vid, mac)` learned on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FdbSnapshot {
    ports: HashMap<(String, u16, [u8; 6]), String>,
}

impl FdbSnapshot {
    /// From learned entries only: `(bridge, vid, mac, port)`. Permanent
    /// entries are the bridge's own addresses, not neighbours.
    pub fn from_learned(entries: impl IntoIterator<Item = (String, u16, [u8; 6], String)>) -> Self {
        Self {
            ports: entries
                .into_iter()
                .map(|(bridge, vid, mac, port)| ((bridge, vid, mac), port))
                .collect(),
        }
    }

    /// The port `mac` is learned on in `bridge`'s FDB for `vid`.
    pub fn port_of(&self, bridge: &str, vid: u16, mac: [u8; 6]) -> Option<&str> {
        self.ports
            .get(&(bridge.to_string(), vid, mac))
            .map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.ports.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ports.is_empty()
    }
}

/// Each bridge port's VLANs: `(vid, egress untagged)` — what `bridge vlan
/// show` prints. Decides how a placed neighbour is reached (an untagged
/// VLAN through the port itself, a tagged one through its subif), and
/// which subifs a `vlans all` trunk needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortVlans {
    by_port: HashMap<String, Vec<(u16, bool)>>,
}

impl PortVlans {
    /// From `(port, vid, untagged)` entries.
    pub fn from_entries(entries: impl IntoIterator<Item = (String, u16, bool)>) -> Self {
        let mut by_port: HashMap<String, Vec<(u16, bool)>> = HashMap::new();
        for (port, vid, untagged) in entries {
            by_port.entry(port).or_default().push((vid, untagged));
        }
        for v in by_port.values_mut() {
            v.sort_unstable();
            v.dedup();
        }
        Self { by_port }
    }

    /// The VLANs `port` carries tagged, ascending.
    pub fn tagged(&self, port: &str) -> Vec<u16> {
        self.pick(port, false)
    }

    /// The VLANs `port` sends untagged, ascending.
    pub fn untagged(&self, port: &str) -> Vec<u16> {
        self.pick(port, true)
    }

    fn pick(&self, port: &str, untagged: bool) -> Vec<u16> {
        self.by_port
            .get(port)
            .into_iter()
            .flatten()
            .filter(|(_, u)| *u == untagged)
            .map(|(v, _)| *v)
            .collect()
    }
}

/// The kernel's L3 device for one bridged VLAN: what its frames leave
/// from (a BVI must carry the same MAC) and its MTU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BridgeL3 {
    pub mac: [u8; 6],
    pub mtu: Option<u32>,
}

/// One device classifying to a bridged VLAN, for [`pick_bridge_l3`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L3Candidate {
    pub dev: String,
    /// Holds an IPv4 address, or a global IPv6 one.
    pub addressed: bool,
    /// Enslaved to a bridge — `switch0.3998` under `br3998`: a lower
    /// device, never where the router's frames leave from.
    pub enslaved: bool,
}

/// Which device is a bridged VLAN's L3 device: the addressed one —
/// `br3998` rather than the bare `switch0.3998` beneath it — else one no
/// bridge has enslaved, else the first. The middle rule is what keeps an
/// IPv6-only (or not yet addressed) bridge from losing to its lower
/// device by name order, which would hand the BVI a MAC the kernel does
/// not send from (review finding). Pure, for the tests.
pub fn pick_bridge_l3(candidates: &[L3Candidate]) -> Option<&str> {
    candidates
        .iter()
        .find(|c| c.addressed)
        .or_else(|| candidates.iter().find(|c| !c.enslaved))
        .or_else(|| candidates.first())
        .map(|c| c.dev.as_str())
}

/// Devices holding a global (non-link-local) IPv6 address, from
/// `/proc/net/if_inet6`. Link-local is left out: every up device has
/// one, lower devices included, so it says nothing about L3.
pub fn parse_if_inet6_global(text: &str) -> std::collections::HashSet<String> {
    text.lines()
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // addr, ifindex, prefix len, scope, flags, name
            (cols.len() == 6 && cols[3] == "00").then(|| cols[5].to_string())
        })
        .collect()
}

/// The engine's view of the kernel: classification and the FDB.
///
/// Both answers must be cheap: the engine asks from the supervision
/// loop, which must never block on the kernel (the steered wedge budget
/// is 1.5 s). The live implementation reads the FDB on a thread of its
/// own and serves the latest result.
pub trait Topology {
    /// `Err` when the kernel's answer could not be read — a transient
    /// state (provisioning recreating VLAN devices) that must not be
    /// cached as "this device is plain".
    fn classify(&self, dev: &str) -> Result<Option<DevKind>, String>;
    /// The latest FDB. `Err` = the last read failed; callers keep the
    /// snapshot they had, since an unreadable table is not evidence
    /// anything moved, and say so.
    fn fdb(&self) -> Result<FdbSnapshot, String>;
    /// The latest bridge-port VLAN membership, on the same terms as
    /// [`Self::fdb`].
    fn port_vlans(&self) -> Result<PortVlans, String>;
    /// The bridge `port` is enslaved to, if any.
    fn master_of(&self, port: &str) -> Option<String>;
    /// The kernel's L3 device for `bridge`/`vid`, if the router has one —
    /// a VLAN with no L3 device on the router has no neighbours to reach.
    fn bridge_l3(&self, bridge: &str, vid: u16) -> Option<BridgeL3>;
    /// `dev`'s current MTU, or `None` when it cannot be read. Read at
    /// every VPP attach rather than once at bring-up: a supervised VPP
    /// restart re-attaches with the kernel's MTU as it is then.
    fn mtu(&self, _dev: &str) -> Option<u32> {
        None
    }
}

/// No kernel to ask: every device is [`DevKind::Plain`] and the FDB is
/// empty — the engine's behaviour before placement existed, for non-Linux
/// builds and tests that do not exercise bridges.
pub struct NoTopology;

impl Topology for NoTopology {
    fn classify(&self, _dev: &str) -> Result<Option<DevKind>, String> {
        Ok(Some(DevKind::Plain))
    }
    fn fdb(&self) -> Result<FdbSnapshot, String> {
        Ok(FdbSnapshot::default())
    }
    fn port_vlans(&self) -> Result<PortVlans, String> {
        Ok(PortVlans::default())
    }
    fn master_of(&self, _port: &str) -> Option<String> {
        None
    }
    fn bridge_l3(&self, _bridge: &str, _vid: u16) -> Option<BridgeL3> {
        None
    }
}

/// The live kernel. Classification reads `/proc/net/vlan/config` and the
/// bridge sysfs per call (a few small files); the FDB comes from a
/// background thread dumping it every [`FDB_REFRESH`], so the engine
/// never waits on AF_BRIDGE netlink.
#[cfg(target_os = "linux")]
pub struct KernelTopology {
    fdb: std::sync::Arc<std::sync::Mutex<Result<FdbSnapshot, String>>>,
    vlans: std::sync::Arc<std::sync::Mutex<Result<PortVlans, String>>>,
}

/// How often the background thread re-dumps the FDB.
#[cfg(target_os = "linux")]
pub const FDB_REFRESH: std::time::Duration = std::time::Duration::from_secs(2);

#[cfg(target_os = "linux")]
impl KernelTopology {
    /// Read the FDB and port VLANs once, here — at bring-up, before
    /// supervision starts, so the first resync places neighbours from a
    /// real table — then keep both fresh on a thread that ends when this
    /// is dropped.
    pub fn start() -> Self {
        let fdb = std::sync::Arc::new(std::sync::Mutex::new(Self::read_fdb()));
        let vlans = std::sync::Arc::new(std::sync::Mutex::new(Self::read_vlans()));
        let (wf, wv) = (
            std::sync::Arc::downgrade(&fdb),
            std::sync::Arc::downgrade(&vlans),
        );
        let spawned = std::thread::Builder::new()
            .name("pf-vpp-fdb".into())
            .spawn(move || loop {
                std::thread::sleep(FDB_REFRESH);
                let (Some(fdb), Some(vlans)) = (wf.upgrade(), wv.upgrade()) else {
                    return;
                };
                let read = Self::read_fdb();
                *fdb.lock().unwrap_or_else(|e| e.into_inner()) = read;
                let read = Self::read_vlans();
                *vlans.lock().unwrap_or_else(|e| e.into_inner()) = read;
            });
        if let Err(e) = spawned {
            tracing::warn!(error = %e, "bridge FDB refresh thread would not start; placement uses the bring-up read");
        }
        Self { fdb, vlans }
    }

    fn read_vlans() -> Result<PortVlans, String> {
        Ok(PortVlans::from_entries(
            crate::fdb::dump_port_vlans()?
                .into_iter()
                .map(|e| (e.port, e.vid, e.untagged)),
        ))
    }

    fn read_fdb() -> Result<FdbSnapshot, String> {
        let entries = crate::fdb::dump_bridge_fdb()?;
        Ok(FdbSnapshot::from_learned(entries.into_iter().filter_map(
            |e| {
                if e.permanent {
                    return None;
                }
                Some((
                    crate::fdb::ifname(e.master?),
                    e.vlan?,
                    e.mac,
                    crate::fdb::ifname(e.port),
                ))
            },
        )))
    }
}

/// The link facts one classification needs, read once for it.
#[cfg(target_os = "linux")]
struct KernelLinks {
    vlans: HashMap<String, (u16, String)>,
}

#[cfg(target_os = "linux")]
impl LinkFacts for KernelLinks {
    fn vlan(&self, dev: &str) -> Option<(u16, String)> {
        self.vlans.get(dev).cloned()
    }
    fn is_bridge(&self, dev: &str) -> bool {
        std::path::Path::new("/sys/class/net")
            .join(dev)
            .join("bridge")
            .is_dir()
    }
    fn bridge_ports(&self, dev: &str) -> Vec<String> {
        let dir = std::path::Path::new("/sys/class/net")
            .join(dev)
            .join("brif");
        let mut out: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .collect();
        out.sort();
        out
    }
}

/// The kernel's link facts, or why they could not be read. A missing
/// `/proc/net/vlan/config` means no 8021q module and so no VLANs — an
/// answer; any other read error is not.
#[cfg(target_os = "linux")]
pub fn kernel_links() -> Result<impl LinkFacts, String> {
    let vlans = read_vlan_config(std::path::Path::new("/proc/net/vlan/config"))?;
    Ok(KernelLinks { vlans })
}

#[cfg(target_os = "linux")]
impl Topology for KernelTopology {
    fn classify(&self, dev: &str) -> Result<Option<DevKind>, String> {
        Ok(classify(&kernel_links()?, dev))
    }

    fn fdb(&self) -> Result<FdbSnapshot, String> {
        self.fdb.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn port_vlans(&self) -> Result<PortVlans, String> {
        self.vlans.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn master_of(&self, port: &str) -> Option<String> {
        let link = std::fs::read_link(format!("/sys/class/net/{port}/master")).ok()?;
        Some(link.file_name()?.to_str()?.to_string())
    }

    fn bridge_l3(&self, bridge: &str, vid: u16) -> Option<BridgeL3> {
        let links = kernel_links().ok()?;
        let mut addressed: std::collections::HashSet<String> = crate::bringup::kernel_v4_addrs()
            .into_iter()
            .map(|(dev, _)| dev)
            .collect();
        addressed.extend(parse_if_inet6_global(
            &std::fs::read_to_string("/proc/net/if_inet6").unwrap_or_default(),
        ));
        let want = DevKind::BridgeVlan {
            bridge: bridge.to_string(),
            vid,
        };
        let candidates: Vec<L3Candidate> = all_netdevs()
            .into_iter()
            .filter(|d| classify(&links, d).as_ref() == Some(&want))
            .map(|dev| L3Candidate {
                addressed: addressed.contains(&dev),
                enslaved: self.master_of(&dev).is_some(),
                dev,
            })
            .collect();
        let dev = pick_bridge_l3(&candidates)?;
        let base = std::path::Path::new("/sys/class/net").join(dev);
        let mac = packetframe_common::topology::parse_mac(
            &std::fs::read_to_string(base.join("address")).ok()?,
        )?;
        let mtu = std::fs::read_to_string(base.join("mtu"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        Some(BridgeL3 { mac, mtu })
    }

    fn mtu(&self, dev: &str) -> Option<u32> {
        crate::attach::kernel_mtu(std::path::Path::new("/sys/class/net"), dev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// The reference primary's shape, plus the generic ones.
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

    #[test]
    fn the_fdb_answers_per_bridge_vlan_and_mac() {
        let m = [0x02, 0, 0, 0, 0, 7];
        let fdb = FdbSnapshot::from_learned([
            ("switch0".to_string(), 1337, m, "eth4".to_string()),
            ("switch0".to_string(), 3998, m, "eth5".to_string()),
        ]);
        assert_eq!(fdb.port_of("switch0", 1337, m), Some("eth4"));
        assert_eq!(fdb.port_of("switch0", 3998, m), Some("eth5"));
        assert_eq!(fdb.port_of("switch0", 88, m), None);
        assert_eq!(fdb.port_of("br0", 1337, m), None);
    }

    #[test]
    fn reachable_devices_are_the_vlans_a_member_carries() {
        let devs: Vec<String> = [
            "br3998",
            "br1337",
            "br100",
            "brwide",
            "eth3",
            "switch0.1337",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let vlans = vec![
            ("eth4".to_string(), vec![3998]),
            ("eth2".to_string(), vec![100]),
        ];
        assert_eq!(
            reachable_devices(&edge(), &devs, &vlans),
            vec!["br3998".to_string(), "br100".to_string()],
            "1337 is carried by no member; plain devices are the members' own business"
        );
    }

    #[test]
    fn port_vlans_split_tagged_from_untagged() {
        let v = PortVlans::from_entries([
            ("eth4".to_string(), 1, true),
            ("eth4".to_string(), 1337, false),
            ("eth4".to_string(), 88, false),
            ("eth5".to_string(), 3998, false),
        ]);
        assert_eq!(v.tagged("eth4"), vec![88, 1337]);
        assert_eq!(v.untagged("eth4"), vec![1]);
        assert_eq!(v.tagged("eth5"), vec![3998]);
        assert!(v.tagged("eth9").is_empty());
    }

    #[test]
    fn the_addressed_device_is_a_bridged_vlans_l3_device() {
        let cand = |dev: &str, addressed, enslaved| L3Candidate {
            dev: dev.into(),
            addressed,
            enslaved,
        };
        let c = vec![
            cand("br3998", true, false),
            cand("switch0.3998", false, true),
        ];
        assert_eq!(pick_bridge_l3(&c), Some("br3998"));
        // Unaddressed as far as IPv4 goes (IPv6-only, say): the device no
        // bridge enslaves wins, whatever the name order.
        let c = [cand("abr3998", false, false), cand("aa.3998", false, true)];
        assert_eq!(pick_bridge_l3(&c[..]), Some("abr3998"));
        let c = vec![cand("aa.3998", false, true), cand("br3998", false, false)];
        assert_eq!(pick_bridge_l3(&c), Some("br3998"));
        let c = vec![cand("switch0.3998", false, false)];
        assert_eq!(pick_bridge_l3(&c), Some("switch0.3998"));
        assert_eq!(pick_bridge_l3(&[]), None);
    }

    #[test]
    fn global_ipv6_addresses_mark_a_device_addressed() {
        let text = "\
20010db8000000000000000000000001 0c 40 00 80 br3998
fe800000000000000000000000000001 0d 40 20 80 switch0.3998
fe800000000000000000000000000002 0c 40 20 80 br3998
";
        let got = parse_if_inet6_global(text);
        assert!(got.contains("br3998"), "{got:?}");
        assert!(!got.contains("switch0.3998"), "link-local only: {got:?}");
    }
}
