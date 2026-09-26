//! The destination MACs each attached port receives on, for the XDP
//! program's `RX_MACS` check (see `bpf/src/main.rs`,
//! `addressed_to_router`).
//!
//! What the set is comes from `packetframe_common::topology::
//! receive_macs`, the rule vpp-offload scopes its divert rules by. This
//! module adds what the fast path needs on top: an explicit *unknown* (a
//! port whose state could not be read), the ifindexes a port's frames can
//! arrive under (a bond's slaves), and the plan that turns desired sets
//! into map writes without ever leaving a port's entries emptier than the
//! truth.
//!
//! Policy, because the map fails in one direction only: a port with no
//! entries passes every frame to the kernel, which is correct but is
//! the kernel path. So the map is filled before any XDP attach (no
//! frame meets an empty set at attach), a port's additions are written
//! before its removals and its removals only once every addition landed
//! (a MAC change never has a moment with neither MAC, nor ends with
//! neither when an insert fails), and an unknown answer leaves the
//! port's entries as they are — an unreadable sysfs is not evidence the
//! MACs moved, and the stale entries are all MACs the router owned.

use std::collections::{BTreeSet, HashSet};
use std::path::Path;

/// Layout mirror of `RxMacKey` in `bpf/src/maps.rs`: 12 bytes, the pad
/// explicit and always zero so a userspace key matches the one the
/// program builds byte-for-byte.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RxMacKey {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub _pad: u16,
}

const _: () = assert!(std::mem::size_of::<RxMacKey>() == 12);

impl RxMacKey {
    pub fn new(ifindex: u32, mac: [u8; 6]) -> Self {
        Self {
            ifindex,
            mac,
            _pad: 0,
        }
    }
}

/// The MACs `port` receives on, read from a sysfs `class/net` root and a
/// `/proc/net/vlan/config`. VLAN membership is not read (`carried =
/// None`), so a bridge member takes every VLAN L3 device's MAC on its
/// bridge: each is a MAC the router owns, so the extra entries route
/// only frames addressed to the router.
///
/// `Err` when the answer is not known: the VLAN table could not be read
/// (a partial set would silently leave out VLAN L3 MACs), or no address
/// could be read for the port or its bridge (a port always has one, so
/// an empty set means the read failed, not that the port receives on
/// nothing).
pub fn port_receive_macs(
    sysfs_net: &Path,
    vlan_config: &Path,
    port: &str,
) -> Result<Vec<[u8; 6]>, String> {
    let vlans = packetframe_common::topology::read_vlan_config(vlan_config)?;
    let macs = packetframe_common::topology::sysfs_receive_macs(sysfs_net, &vlans, None, port);
    if macs.is_empty() {
        return Err(format!(
            "{port}: no address readable for the port or its bridge"
        ));
    }
    Ok(macs)
}

/// [`port_receive_macs`] against the live kernel. The VLAN table is the
/// calling thread's (`/proc/thread-self/net`), as `linux_impl::
/// read_vlan_config` reads it and for the same reason: the watcher
/// calls this from its own thread.
pub fn kernel_port_receive_macs(port: &str) -> Result<Vec<[u8; 6]>, String> {
    let vlan_config = if Path::new("/proc/thread-self/net").is_dir() {
        "/proc/thread-self/net/vlan/config"
    } else {
        "/proc/net/vlan/config"
    };
    port_receive_macs(Path::new("/sys/class/net"), Path::new(vlan_config), port)
}

/// The slave ifindexes of `port` if it is a bond (`bonding/slaves` under
/// its sysfs directory), empty if it is not one. `Err` when it is a bond
/// whose slaves cannot be read, or a slave whose ifindex cannot.
pub fn bond_slaves(sysfs_net: &Path, port: &str) -> Result<Vec<u32>, String> {
    let bonding = sysfs_net.join(port).join("bonding");
    if !bonding.is_dir() {
        return Ok(Vec::new());
    }
    let names = std::fs::read_to_string(bonding.join("slaves"))
        .map_err(|e| format!("{port}: bonding/slaves: {e}"))?;
    names
        .split_whitespace()
        .map(|slave| {
            std::fs::read_to_string(sysfs_net.join(slave).join("ifindex"))
                .ok()
                .and_then(|t| t.trim().parse().ok())
                .ok_or_else(|| format!("{port}: slave {slave}: ifindex unreadable"))
        })
        .collect()
}

/// What an attached port receives on: its MACs, and every other ifindex
/// a frame for it can arrive under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRx {
    pub macs: Vec<[u8; 6]>,
    /// A bond's slaves. Native XDP on a bond runs the program on each
    /// slave, where `ingress_ifindex` is the slave's; generic XDP runs it
    /// on the bond itself. Keys for both cost nothing and keep the check
    /// at one lookup.
    pub slaves: Vec<u32>,
}

/// [`kernel_port_receive_macs`] plus [`bond_slaves`].
pub fn kernel_port_rx(port: &str) -> Result<PortRx, String> {
    Ok(PortRx {
        macs: kernel_port_receive_macs(port)?,
        slaves: bond_slaves(Path::new("/sys/class/net"), port)?,
    })
}

/// One attached port's desired state: its [`PortRx`], or why it is
/// unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMacs {
    pub iface: String,
    pub ifindex: u32,
    pub rx: Result<PortRx, String>,
}

/// One known port's share of an [`RxMacPlan`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PortPlan {
    pub iface: String,
    /// Keys to insert, before any of `remove`.
    pub add: Vec<RxMacKey>,
    /// MACs the port no longer receives on. Deleted only once every key
    /// in `add` is in the map: a failed replacement must not leave the
    /// port with neither MAC.
    pub remove: Vec<RxMacKey>,
}

/// What to write to bring `RX_MACS` to the desired sets.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RxMacPlan {
    /// Per known port, in `desired` order.
    pub ports: Vec<PortPlan>,
    /// Keys of an ifindex no attached port claims (a slave that left its
    /// bond). Empty whenever any port is unknown: an unknown bond's
    /// slaves cannot be told from strangers, and a stale key only routes
    /// frames addressed to a MAC the router owned.
    pub stale: Vec<RxMacKey>,
    /// Ports whose state could not be read, with why. Their entries are
    /// left exactly as they are.
    pub unknown: Vec<(String, u32, String)>,
}

/// Plan the writes that take `current` (the map's keys) to `desired`
/// (every attached XDP port). Deterministic: every list sorted.
pub fn plan(current: &[RxMacKey], desired: &[PortMacs]) -> RxMacPlan {
    let current: BTreeSet<RxMacKey> = current.iter().copied().collect();
    let mut claimed: HashSet<u32> = HashSet::new();
    let mut out = RxMacPlan::default();
    for port in desired {
        claimed.insert(port.ifindex);
        let rx = match &port.rx {
            Ok(rx) => rx,
            Err(why) => {
                out.unknown
                    .push((port.iface.clone(), port.ifindex, why.clone()));
                continue;
            }
        };
        let idx: BTreeSet<u32> = std::iter::once(port.ifindex)
            .chain(rx.slaves.iter().copied())
            .collect();
        claimed.extend(idx.iter().copied());
        let want: BTreeSet<RxMacKey> = idx
            .iter()
            .flat_map(|i| rx.macs.iter().map(|m| RxMacKey::new(*i, *m)))
            .collect();
        out.ports.push(PortPlan {
            iface: port.iface.clone(),
            add: want.difference(&current).copied().collect(),
            remove: current
                .iter()
                .filter(|k| idx.contains(&k.ifindex) && !want.contains(k))
                .copied()
                .collect(),
        });
    }
    if out.unknown.is_empty() {
        out.stale = current
            .iter()
            .filter(|k| !claimed.contains(&k.ifindex))
            .copied()
            .collect();
    }
    out
}

/// What [`apply`] wrote, and what it could not.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    pub added: usize,
    pub removed: usize,
    /// `(key, error)` per failed insert or remove.
    pub failed: Vec<(RxMacKey, String)>,
    /// Ports whose removals were withheld because an insert failed.
    pub held: Vec<String>,
}

/// Carry out `plan` through `insert` / `remove`: per port, every
/// addition, then its removals only if every addition landed; stale keys
/// last.
pub fn apply(
    plan: &RxMacPlan,
    mut insert: impl FnMut(&RxMacKey) -> Result<(), String>,
    mut remove: impl FnMut(&RxMacKey) -> Result<(), String>,
) -> Applied {
    let mut out = Applied::default();
    let mut removals: Vec<RxMacKey> = Vec::new();
    for port in &plan.ports {
        let mut all_in = true;
        for k in &port.add {
            match insert(k) {
                Ok(()) => out.added += 1,
                Err(e) => {
                    all_in = false;
                    out.failed.push((*k, e));
                }
            }
        }
        if all_in {
            removals.extend(port.remove.iter().copied());
        } else if !port.remove.is_empty() {
            out.held.push(port.iface.clone());
        }
    }
    removals.extend(plan.stale.iter().copied());
    for k in &removals {
        match remove(k) {
            Ok(()) => out.removed += 1,
            Err(e) => out.failed.push((*k, e)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];
    const C: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0c];

    fn port(name: &str, ifindex: u32, macs: &[[u8; 6]]) -> PortMacs {
        bond(name, ifindex, macs, &[])
    }

    fn bond(name: &str, ifindex: u32, macs: &[[u8; 6]], slaves: &[u32]) -> PortMacs {
        PortMacs {
            iface: name.to_string(),
            ifindex,
            rx: Ok(PortRx {
                macs: macs.to_vec(),
                slaves: slaves.to_vec(),
            }),
        }
    }

    fn unknown(name: &str, ifindex: u32) -> PortMacs {
        PortMacs {
            iface: name.to_string(),
            ifindex,
            rx: Err("sysfs unreadable".to_string()),
        }
    }

    fn adds(p: &RxMacPlan) -> Vec<RxMacKey> {
        p.ports.iter().flat_map(|q| q.add.clone()).collect()
    }

    fn removes(p: &RxMacPlan) -> Vec<RxMacKey> {
        p.ports.iter().flat_map(|q| q.remove.clone()).collect()
    }

    /// Run `plan` against an in-memory map, failing the inserts of
    /// `refuse`.
    fn run(map: &mut BTreeSet<RxMacKey>, p: &RxMacPlan, refuse: &[RxMacKey]) -> Applied {
        let cell = RefCell::new(map);
        apply(
            p,
            |k| {
                if refuse.contains(k) {
                    return Err("map full".into());
                }
                cell.borrow_mut().insert(*k);
                Ok(())
            },
            |k| {
                cell.borrow_mut().remove(k);
                Ok(())
            },
        )
    }

    #[test]
    fn an_empty_map_is_filled() {
        let p = plan(&[], &[port("eth4", 4, &[A, B]), port("eth2", 2, &[C])]);
        assert_eq!(
            adds(&p),
            vec![
                RxMacKey::new(4, A),
                RxMacKey::new(4, B),
                RxMacKey::new(2, C)
            ]
        );
        assert!(removes(&p).is_empty() && p.stale.is_empty() && p.unknown.is_empty());
    }

    #[test]
    fn a_changed_mac_is_added_and_the_old_one_removed() {
        let p = plan(
            &[RxMacKey::new(4, A), RxMacKey::new(4, B)],
            &[port("eth4", 4, &[B, C])],
        );
        assert_eq!(adds(&p), vec![RxMacKey::new(4, C)]);
        assert_eq!(removes(&p), vec![RxMacKey::new(4, A)]);
    }

    #[test]
    fn a_converged_map_plans_nothing() {
        let p = plan(&[RxMacKey::new(4, A)], &[port("eth4", 4, &[A])]);
        assert!(adds(&p).is_empty() && removes(&p).is_empty() && p.stale.is_empty());
    }

    /// An unreadable port keeps what it has — the only alternative that
    /// changes anything is emptying it, which sends all its traffic to
    /// the kernel path on a read error — and is reported by name.
    #[test]
    fn an_unknown_port_keeps_its_entries() {
        let cur = [RxMacKey::new(4, A), RxMacKey::new(2, C)];
        let p = plan(&cur, &[unknown("eth4", 4), port("eth2", 2, &[B])]);
        assert_eq!(adds(&p), vec![RxMacKey::new(2, B)]);
        assert_eq!(removes(&p), vec![RxMacKey::new(2, C)], "eth4's entry stays");
        assert!(p.stale.is_empty());
        assert_eq!(
            p.unknown,
            vec![("eth4".to_string(), 4, "sysfs unreadable".to_string())]
        );
    }

    #[test]
    fn keys_of_unclaimed_ifindexes_are_stale() {
        let p = plan(&[RxMacKey::new(9, A)], &[port("eth4", 4, &[A])]);
        assert_eq!(adds(&p), vec![RxMacKey::new(4, A)]);
        assert_eq!(p.stale, vec![RxMacKey::new(9, A)]);
        // With any port unknown, an unclaimed ifindex may be that port's
        // bond slave: it stays.
        let p = plan(
            &[RxMacKey::new(9, A)],
            &[port("eth4", 4, &[A]), unknown("bond0", 5)],
        );
        assert!(p.stale.is_empty(), "{p:?}");
    }

    /// A bond's MACs are keyed on its slaves too (native XDP reports the
    /// slave's ifindex); a slave that leaves the bond loses its keys.
    #[test]
    fn a_bond_is_keyed_on_its_slaves() {
        let p = plan(&[], &[bond("bond0", 5, &[A], &[6, 7])]);
        assert_eq!(
            adds(&p),
            vec![
                RxMacKey::new(5, A),
                RxMacKey::new(6, A),
                RxMacKey::new(7, A)
            ]
        );
        let cur = [
            RxMacKey::new(5, A),
            RxMacKey::new(6, A),
            RxMacKey::new(7, A),
        ];
        let p = plan(&cur, &[bond("bond0", 5, &[A], &[6])]);
        assert!(adds(&p).is_empty());
        assert_eq!(p.stale, vec![RxMacKey::new(7, A)]);
    }

    /// A replacement MAC that cannot be inserted (map full, a transient
    /// update error) must not cost the port its old MAC: that port's
    /// removals are withheld, other ports proceed.
    #[test]
    fn a_failed_replacement_keeps_the_old_mac() {
        let cur = [RxMacKey::new(4, A), RxMacKey::new(2, A)];
        let p = plan(&cur, &[port("eth4", 4, &[B]), port("eth2", 2, &[C])]);
        let mut map: BTreeSet<RxMacKey> = cur.iter().copied().collect();
        let applied = run(&mut map, &p, &[RxMacKey::new(4, B)]);
        assert_eq!(applied.held, vec!["eth4".to_string()]);
        assert_eq!(applied.failed.len(), 1);
        assert_eq!(
            map,
            BTreeSet::from([RxMacKey::new(4, A), RxMacKey::new(2, C)]),
            "eth4 keeps A; eth2 moves to C"
        );
    }

    /// Every addition lands before any removal.
    #[test]
    fn additions_precede_removals() {
        let p = plan(
            &[RxMacKey::new(4, A), RxMacKey::new(2, A)],
            &[port("eth4", 4, &[B]), port("eth2", 2, &[C])],
        );
        let log = RefCell::new(Vec::new());
        apply(
            &p,
            |k| {
                log.borrow_mut().push(("add", *k));
                Ok(())
            },
            |k| {
                log.borrow_mut().push(("del", *k));
                Ok(())
            },
        );
        assert_eq!(
            log.into_inner(),
            vec![
                ("add", RxMacKey::new(4, B)),
                ("add", RxMacKey::new(2, C)),
                ("del", RxMacKey::new(4, A)),
                ("del", RxMacKey::new(2, A)),
            ]
        );
    }

    /// The live reads on a sysfs fixture: a bridge member takes its
    /// bridge's MAC; a port with nothing readable, or an unreadable VLAN
    /// table, is unknown rather than empty; a bond's slaves resolve to
    /// ifindexes, and an unresolvable slave makes the bond unknown.
    #[test]
    fn sysfs_reads_are_unknown_rather_than_empty() {
        let root = std::env::temp_dir().join(format!("pf-fp-rxmac-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let net = root.join("net");
        for (dev, mac) in [
            ("switch0", "02:00:00:00:00:0a"),
            ("eth4", "02:00:00:00:00:04"),
        ] {
            std::fs::create_dir_all(net.join(dev)).unwrap();
            std::fs::write(net.join(dev).join("address"), format!("{mac}\n")).unwrap();
        }
        std::fs::create_dir_all(net.join("switch0").join("bridge")).unwrap();
        std::os::unix::fs::symlink(net.join("switch0"), net.join("eth4").join("master")).unwrap();
        std::fs::create_dir_all(net.join("eth9")).unwrap();
        let no_vlans = root.join("absent-vlan-config");

        assert_eq!(port_receive_macs(&net, &no_vlans, "eth4"), Ok(vec![A]));
        assert!(port_receive_macs(&net, &no_vlans, "eth9").is_err());
        // A directory where the VLAN table should be: present, unreadable.
        assert!(port_receive_macs(&net, &net, "eth4").is_err());

        assert_eq!(bond_slaves(&net, "eth4"), Ok(vec![]), "not a bond");
        std::fs::create_dir_all(net.join("bond0").join("bonding")).unwrap();
        std::fs::write(
            net.join("bond0").join("bonding").join("slaves"),
            "eth6 eth7\n",
        )
        .unwrap();
        for (dev, idx) in [("eth6", "6"), ("eth7", "7")] {
            std::fs::create_dir_all(net.join(dev)).unwrap();
            std::fs::write(net.join(dev).join("ifindex"), format!("{idx}\n")).unwrap();
        }
        assert_eq!(bond_slaves(&net, "bond0"), Ok(vec![6, 7]));
        std::fs::remove_file(net.join("eth7").join("ifindex")).unwrap();
        assert!(
            bond_slaves(&net, "bond0").is_err(),
            "a slave with no ifindex"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
