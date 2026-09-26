//! The destination MACs each attached port receives on, for the XDP
//! program's `RX_MACS` check (see `bpf/src/main.rs`,
//! `addressed_to_router`).
//!
//! What the set is comes from `packetframe_common::topology::
//! receive_macs`, the rule vpp-offload scopes its divert rules by. This
//! module adds the two things the fast path needs on top: an explicit
//! *unknown* (a port whose MACs could not be read), and the plan that
//! turns desired sets into map writes without ever leaving a port's
//! entries emptier than the truth.
//!
//! Policy, because the map fails in one direction only: a port with no
//! entries passes every frame to the kernel, which is correct but is
//! the kernel path. So the map is filled before any XDP attach (no
//! frame meets an empty set at attach), additions are written before
//! removals (a MAC change never has a moment with neither MAC), and an
//! unknown answer leaves the port's entries as they are — an unreadable
//! sysfs is not evidence the MACs moved, and the stale entries are all
//! MACs the router owned.

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

/// One attached port's desired set: `(iface, ifindex, its MACs or why
/// they are unknown)`.
pub type PortMacs = (String, u32, Result<Vec<[u8; 6]>, String>);

/// What to write to bring `RX_MACS` to the desired sets.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RxMacPlan {
    /// Keys to insert. Applied before `remove`.
    pub add: Vec<RxMacKey>,
    /// Keys to delete: MACs a port no longer receives on, and every key
    /// of an ifindex that is not an attached port.
    pub remove: Vec<RxMacKey>,
    /// Ports whose MACs could not be read, with why. Their entries are
    /// left exactly as they are.
    pub unknown: Vec<(String, u32, String)>,
}

/// Plan the writes that take `current` (the map's keys) to `desired`
/// (every attached XDP port). Deterministic: both lists sorted.
pub fn plan(current: &[RxMacKey], desired: &[PortMacs]) -> RxMacPlan {
    let current: BTreeSet<RxMacKey> = current.iter().copied().collect();
    let mut want: BTreeSet<RxMacKey> = BTreeSet::new();
    // Ifindexes whose entries stay as they are, whatever they hold.
    let mut keep: HashSet<u32> = HashSet::new();
    let mut unknown = Vec::new();
    for (port, ifindex, macs) in desired {
        match macs {
            Ok(macs) => want.extend(macs.iter().map(|m| RxMacKey::new(*ifindex, *m))),
            Err(why) => {
                keep.insert(*ifindex);
                unknown.push((port.clone(), *ifindex, why.clone()));
            }
        }
    }
    RxMacPlan {
        add: want.difference(&current).copied().collect(),
        remove: current
            .difference(&want)
            .filter(|k| !keep.contains(&k.ifindex))
            .copied()
            .collect(),
        unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];
    const C: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0c];

    fn port(name: &str, ifindex: u32, macs: &[[u8; 6]]) -> PortMacs {
        (name.to_string(), ifindex, Ok(macs.to_vec()))
    }

    #[test]
    fn an_empty_map_is_filled() {
        let p = plan(&[], &[port("eth4", 4, &[A, B]), port("eth2", 2, &[C])]);
        assert_eq!(
            p.add,
            vec![
                RxMacKey::new(2, C),
                RxMacKey::new(4, A),
                RxMacKey::new(4, B)
            ]
        );
        assert!(p.remove.is_empty() && p.unknown.is_empty(), "{p:?}");
    }

    /// A bridge MAC change: the new MAC is added, the old removed, and
    /// the caller applies additions first so the port is never without
    /// the MAC its hosts are using.
    #[test]
    fn a_changed_mac_is_added_and_the_old_one_removed() {
        let p = plan(
            &[RxMacKey::new(4, A), RxMacKey::new(4, B)],
            &[port("eth4", 4, &[B, C])],
        );
        assert_eq!(p.add, vec![RxMacKey::new(4, C)]);
        assert_eq!(p.remove, vec![RxMacKey::new(4, A)]);
    }

    #[test]
    fn a_converged_map_plans_nothing() {
        let cur = [RxMacKey::new(4, A)];
        assert_eq!(plan(&cur, &[port("eth4", 4, &[A])]), RxMacPlan::default());
    }

    /// An unreadable port keeps what it has — the only alternative that
    /// changes anything is emptying it, which sends all its traffic to
    /// the kernel path on a read error — and is reported by name.
    #[test]
    fn an_unknown_port_keeps_its_entries() {
        let cur = [RxMacKey::new(4, A), RxMacKey::new(2, C)];
        let p = plan(
            &cur,
            &[
                ("eth4".to_string(), 4, Err("sysfs unreadable".to_string())),
                port("eth2", 2, &[B]),
            ],
        );
        assert_eq!(p.add, vec![RxMacKey::new(2, B)]);
        assert_eq!(p.remove, vec![RxMacKey::new(2, C)], "eth4's entry stays");
        assert_eq!(
            p.unknown,
            vec![("eth4".to_string(), 4, "sysfs unreadable".to_string())]
        );
    }

    /// Entries for an ifindex that is no attached port route nothing
    /// useful and are removed.
    #[test]
    fn keys_of_unattached_ifindexes_are_removed() {
        let p = plan(&[RxMacKey::new(9, A)], &[port("eth4", 4, &[A])]);
        assert_eq!(p.add, vec![RxMacKey::new(4, A)]);
        assert_eq!(p.remove, vec![RxMacKey::new(9, A)]);
    }

    /// The live read on a sysfs fixture: a bridge member takes its
    /// bridge's MAC; a port with nothing readable, or an unreadable VLAN
    /// table, is unknown rather than empty.
    #[test]
    fn port_receive_macs_is_unknown_rather_than_empty() {
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
        let _ = std::fs::remove_dir_all(&root);
    }
}
