//! SIGHUP reconcile: delta-only updates to the §4.5 map set
//! (SPEC.md §4.5, §8.4).
//!
//! Called when the CLI `run` loop receives SIGHUP. The caller
//! re-parses the config out of band and passes it here along with
//! live map handles; this module computes the diff against in-kernel
//! state and applies adds + removes without reloading the BPF
//! program.
//!
//! Map updates aren't transactional — if an individual insert or
//! delete fails we log it and continue. Partial-update state is
//! strictly better than halting mid-reconcile. Attach-set changes
//! (new iface or iface removed from the config) are **not** handled
//! here; operators restart the loader for those.

use std::collections::HashSet;

use aya::maps::{lpm_trie::Key as LpmKey, xdp::DevMapHash, Array, HashMap as AyaHashMap, LpmTrie};
use packetframe_common::{
    config::ModuleDirective,
    module::{ModuleConfig, ModuleError, ModuleResult},
};
use tracing::{info, warn};

use crate::linux_impl::{
    if_nametoindex, read_vlan_config, ActiveState, FpCfg, VlanResolve, FP_CFG_VERSION_V1,
};
use crate::MODULE_NAME;

/// Per-map count of entries added and removed during reconcile.
#[derive(Default, Debug)]
pub struct DeltaCount {
    pub added: usize,
    pub removed: usize,
}

pub fn reconcile(state: &mut ActiveState, cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
    reconcile_cfg(state, cfg)?;
    let v4 = reconcile_allow_v4(state, cfg)?;
    let v6 = reconcile_allow_v6(state, cfg)?;
    let vlan = reconcile_vlan_resolve(state)?;
    let devmap_purged = purge_stale_devmap(state)?;

    info!(
        v4_added = v4.added,
        v4_removed = v4.removed,
        v6_added = v6.added,
        v6_removed = v6.removed,
        vlan_added = vlan.added,
        vlan_removed = vlan.removed,
        devmap_purged = devmap_purged.removed,
        "SIGHUP reconcile applied"
    );
    Ok(())
}

fn reconcile_cfg(state: &mut ActiveState, cfg: &ModuleConfig<'_>) -> ModuleResult<()> {
    let dry_run = cfg
        .section
        .directives
        .iter()
        .find_map(|d| match d {
            ModuleDirective::DryRun(v) => Some(*v),
            _ => None,
        })
        .unwrap_or(false);

    let new_cfg = FpCfg {
        dry_run: u8::from(dry_run),
        flags: 0b11,
        _reserved: [0; 2],
        version: FP_CFG_VERSION_V1,
    };

    let map = state
        .ebpf
        .map_mut("CFG")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "CFG map missing from ELF"))?;
    let mut cfg_arr: Array<_, FpCfg> = Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG Array::try_from: {e}")))?;
    cfg_arr
        .set(0, new_cfg, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG set: {e}")))?;
    info!(dry_run, "CFG reconciled");
    Ok(())
}

fn reconcile_allow_v4(state: &mut ActiveState, cfg: &ModuleConfig<'_>) -> ModuleResult<DeltaCount> {
    let desired: HashSet<(u32, [u8; 4])> = cfg
        .section
        .directives
        .iter()
        .filter_map(|d| match d {
            ModuleDirective::AllowPrefix4(p) => Some((u32::from(p.prefix_len), p.addr.octets())),
            _ => None,
        })
        .collect();

    let map = state
        .ebpf
        .map_mut("ALLOW_V4")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "ALLOW_V4 map missing from ELF"))?;
    let mut trie: LpmTrie<_, [u8; 4], u8> = LpmTrie::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("ALLOW_V4 try_from: {e}")))?;

    let current: HashSet<(u32, [u8; 4])> = trie
        .keys()
        .filter_map(Result::ok)
        .map(|k| (k.prefix_len(), k.data()))
        .collect();

    apply_prefix_delta::<[u8; 4]>(&mut trie, &desired, &current, "ALLOW_V4")
}

fn reconcile_allow_v6(state: &mut ActiveState, cfg: &ModuleConfig<'_>) -> ModuleResult<DeltaCount> {
    let desired: HashSet<(u32, [u8; 16])> = cfg
        .section
        .directives
        .iter()
        .filter_map(|d| match d {
            ModuleDirective::AllowPrefix6(p) => Some((u32::from(p.prefix_len), p.addr.octets())),
            _ => None,
        })
        .collect();

    let map = state
        .ebpf
        .map_mut("ALLOW_V6")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "ALLOW_V6 map missing from ELF"))?;
    let mut trie: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("ALLOW_V6 try_from: {e}")))?;

    let current: HashSet<(u32, [u8; 16])> = trie
        .keys()
        .filter_map(Result::ok)
        .map(|k| (k.prefix_len(), k.data()))
        .collect();

    apply_prefix_delta::<[u8; 16]>(&mut trie, &desired, &current, "ALLOW_V6")
}

/// Insert every entry in `desired \ current`, then delete every entry
/// in `current \ desired`. Adds-first ordering keeps a rename (remove+add
/// of the same prefix) from ever having a window where neither exists.
fn apply_prefix_delta<K>(
    trie: &mut LpmTrie<&mut aya::maps::MapData, K, u8>,
    desired: &HashSet<(u32, K)>,
    current: &HashSet<(u32, K)>,
    map_label: &str,
) -> ModuleResult<DeltaCount>
where
    K: aya::Pod + Eq + std::hash::Hash + std::fmt::Debug,
{
    let mut delta = DeltaCount::default();
    for (len, data) in desired.difference(current) {
        let key = LpmKey::new(*len, *data);
        match trie.insert(&key, 1u8, 0) {
            Ok(()) => delta.added += 1,
            Err(e) => warn!(map = map_label, prefix_len = *len, ?data, error = %e, "insert failed"),
        }
    }
    for (len, data) in current.difference(desired) {
        let key = LpmKey::new(*len, *data);
        match trie.remove(&key) {
            Ok(()) => delta.removed += 1,
            Err(e) => warn!(map = map_label, prefix_len = *len, ?data, error = %e, "remove failed"),
        }
    }
    Ok(delta)
}

fn reconcile_vlan_resolve(state: &mut ActiveState) -> ModuleResult<DeltaCount> {
    // Rebuild the desired set from /proc/net/vlan/config. Missing file
    // means no VLAN subifs — desired is empty, which will remove any
    // stale entries.
    let vlan_entries = match read_vlan_config() {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return Err(ModuleError::other(
                MODULE_NAME,
                format!("read /proc/net/vlan/config: {e}"),
            ));
        }
    };

    let desired: HashSet<(u32, u32, u16)> = vlan_entries
        .iter()
        .filter_map(|(subif, vid, parent)| {
            // Skip entries whose ifindexes don't resolve — the proc
            // file is a snapshot; an iface may have disappeared between
            // read and here.
            let subif_idx = if_nametoindex(subif).ok()?;
            let phys_idx = if_nametoindex(parent).ok()?;
            Some((subif_idx, phys_idx, *vid))
        })
        .collect();

    let map = state
        .ebpf
        .map_mut("VLAN_RESOLVE")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "VLAN_RESOLVE missing from ELF"))?;
    let mut hm: AyaHashMap<_, u32, VlanResolve> = AyaHashMap::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("VLAN_RESOLVE try_from: {e}")))?;

    // Gather current state — value is VlanResolve { phys_ifindex, vid }.
    let current: HashSet<(u32, u32, u16)> = hm
        .iter()
        .filter_map(Result::ok)
        .map(|(subif_idx, v)| (subif_idx, v.phys_ifindex, v.vid))
        .collect();

    let mut delta = DeltaCount::default();
    for (subif_idx, phys_idx, vid) in desired.difference(&current) {
        let value = VlanResolve {
            phys_ifindex: *phys_idx,
            vid: *vid,
            _pad: 0,
        };
        match hm.insert(*subif_idx, value, 0) {
            Ok(()) => {
                delta.added += 1;
                info!(subif_idx, phys_idx, vid, "VLAN_RESOLVE added");
            }
            Err(e) => warn!(subif_idx, error = %e, "VLAN_RESOLVE insert failed"),
        }
    }
    for (subif_idx, _, _) in current.difference(&desired) {
        match hm.remove(subif_idx) {
            Ok(()) => {
                delta.removed += 1;
                info!(subif_idx, "VLAN_RESOLVE removed (subif gone)");
            }
            Err(e) => warn!(subif_idx, error = %e, "VLAN_RESOLVE remove failed"),
        }
    }
    Ok(delta)
}

/// Purge REDIRECT_DEVMAP entries whose ifindex no longer resolves via
/// `if_indextoname` — an iface that disappeared between attach and
/// reconcile. Covers the "stale devmap after hot-unplug" case called
/// out in the SPEC §4.5 reconcile note.
fn purge_stale_devmap(state: &mut ActiveState) -> ModuleResult<DeltaCount> {
    let map = state
        .ebpf
        .map_mut("REDIRECT_DEVMAP")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "REDIRECT_DEVMAP missing from ELF"))?;
    let mut devmap: DevMapHash<_> = DevMapHash::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("REDIRECT_DEVMAP try_from: {e}")))?;

    let stale: Vec<u32> = devmap
        .keys()
        .filter_map(Result::ok)
        .filter(|ifindex| !ifindex_exists(*ifindex))
        .collect();

    let mut delta = DeltaCount::default();
    for ifindex in stale {
        // DevMapHash::remove takes u32 by value, not by reference.
        match devmap.remove(ifindex) {
            Ok(()) => {
                delta.removed += 1;
                info!(ifindex, "REDIRECT_DEVMAP stale entry purged");
            }
            Err(e) => warn!(ifindex, error = %e, "REDIRECT_DEVMAP remove failed"),
        }
    }
    Ok(delta)
}

/// Does the kernel still know this ifindex? Wraps `if_indextoname`;
/// returns false on any error (ENXIO for an unknown index, EINVAL for
/// impossible values, etc.).
fn ifindex_exists(ifindex: u32) -> bool {
    let mut buf = [0u8; libc::IF_NAMESIZE];
    let ptr = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr().cast()) };
    if ptr.is_null() {
        return false;
    }
    let c = unsafe { std::ffi::CStr::from_ptr(ptr) };
    !c.to_bytes().is_empty()
}
