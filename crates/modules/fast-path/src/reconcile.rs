//! SIGHUP reconcile: delta-only updates to the §4.5 map set
//! (SPEC.md §4.5, §8.4).
//!
//! Called when the CLI `run` loop receives SIGHUP. The caller
//! re-parses the config out of band and passes it here along with
//! live map handles; this module computes the diff against in-kernel
//! state and applies adds + removes without reloading the BPF
//! program.
//!
//! Map updates aren't transactional, if an individual insert or
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
    discover_bridge_chains, feature_flags_from_config, fib_flags_from_forwarding_mode,
    if_nametoindex, mss_clamp_global_value, read_vlan_config, set_cfg_flag, ActiveState, FpCfg,
    MssClampValue, VlanResolve, FP_CFG_FLAG_HEAD_SHIFT_128, FP_CFG_FLAG_VLAN_PRESENT,
    FP_CFG_VERSION_V2,
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
    let block_v4 = reconcile_block_v4(state, cfg)?;
    let block_v6 = reconcile_block_v6(state, cfg)?;
    let mss_clamp = reconcile_mss_clamp(state, cfg)?;
    let vlan = reconcile_vlan_resolve(state, cfg)?;
    let devmap = reconcile_devmap(state)?;

    info!(
        v4_added = v4.added,
        v4_removed = v4.removed,
        v6_added = v6.added,
        v6_removed = v6.removed,
        block_v4_added = block_v4.added,
        block_v4_removed = block_v4.removed,
        block_v6_added = block_v6.added,
        block_v6_removed = block_v6.removed,
        mss_v4_added = mss_clamp.0.added,
        mss_v4_removed = mss_clamp.0.removed,
        mss_v6_added = mss_clamp.1.added,
        mss_v6_removed = mss_clamp.1.removed,
        mss_iface_added = mss_clamp.2.added,
        mss_iface_removed = mss_clamp.2.removed,
        vlan_added = vlan.added,
        vlan_removed = vlan.removed,
        devmap_added = devmap.added,
        devmap_removed = devmap.removed,
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

    let forwarding = cfg
        .section
        .directives
        .iter()
        .find_map(|d| match d {
            ModuleDirective::ForwardingMode(m) => Some(*m),
            _ => None,
        })
        .unwrap_or_default();

    let map = state
        .ebpf
        .map_mut("CFG")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "CFG map missing from ELF"))?;
    let mut cfg_arr: Array<_, FpCfg> = Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG Array::try_from: {e}")))?;

    // Preserve bit 2 (HEAD_SHIFT_128) from the current CFG. That bit
    // is set at attach time by apply_driver_quirks_cfg based on
    // driver detection; SIGHUP reconfigure must not wipe it. Without
    // this preservation, a SIGHUP on an rvu-nicpf box would silently
    // disable the head-shift workaround until the next full restart.
    //
    // Bit 6 (VLAN_PRESENT) is preserved for a related reason: it is
    // owned by VLAN *discovery*, not directives, and its only writer
    // is `reconcile_vlan_resolve`'s post-convergence RMW. Recomputing
    // it here from a fresh /proc/net/vlan/config read would clear the
    // gate whenever that read transiently fails (any error maps to
    // "no subifs") — and since the same failure then aborts
    // `reconcile_vlan_resolve` before its fixup, VLAN_RESOLVE would
    // keep its entries while the datapath stopped consulting them,
    // mistagging subif egress until the next successful reconcile.
    // (Found by review on the original recompute-on-SIGHUP version.)
    let current: FpCfg = cfg_arr
        .get(&0, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG get: {e}")))?;
    let head_shift = current.flags & FP_CFG_FLAG_HEAD_SHIFT_128;
    let vlan_present = current.flags & FP_CFG_FLAG_VLAN_PRESENT;

    let mss_clamp_global = mss_clamp_global_value(&cfg.section.directives).unwrap_or(0);

    // Directive-derived presence bits (5, 7) are rebuilt through the
    // same shared helper populate_cfg uses; a bit computed inline here
    // (or forgotten) would be wiped on every SIGHUP — the
    // head-shift-bug pattern the preservation above guards against.
    // `vlan_subifs_present: false` because bit 6 is carried over from
    // the live flags instead (see comment above); OR-ing the preserved
    // bit keeps it exactly as `reconcile_vlan_resolve` last set it.
    let new_cfg = FpCfg {
        dry_run: u8::from(dry_run),
        flags: 0b11
            | head_shift
            | vlan_present
            | fib_flags_from_forwarding_mode(forwarding)
            | feature_flags_from_config(&cfg.section.directives, false),
        mss_clamp_global,
        version: FP_CFG_VERSION_V2,
    };

    cfg_arr
        .set(0, new_cfg, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG set: {e}")))?;
    info!(dry_run, forwarding = ?forwarding, "CFG reconciled");
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

pub(crate) fn reconcile_vlan_resolve(
    state: &mut ActiveState,
    cfg: &ModuleConfig<'_>,
) -> ModuleResult<DeltaCount> {
    // Rebuild the desired set from /proc/net/vlan/config. Missing file
    // means no VLAN subifs, desired is empty, which will remove any
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

    // Bridge egress short-circuits share this map and bit 6: the
    // desired set is the UNION of both sources, and only the single
    // set_cfg_flag below writes the gate. `bridge-resolve off` yields
    // an empty chain set, which purges any previously installed bridge
    // keys via the normal diff — the SIGHUP rollback path. Read errors
    // abort before the flag RMW, same policy as the vlan read above
    // (never clear the gate on a transient failure while the map still
    // holds entries).
    let chains = discover_bridge_chains(&cfg.section.directives)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("bridge topology read: {e}")))?;

    // Same clamp-scoping warning the attach-time population emits: an
    // `mss-clamp via <bridge>` cannot match while that bridge is
    // collapsed (matching keys on the post-resolve egress ifindex).
    // A SIGHUP can introduce either half of the collision — the clamp
    // rule or the alias — so the check has to live here too.
    for (bridge_name, phys_name, _) in &chains {
        for d in &cfg.section.directives {
            if let ModuleDirective::MssClamp {
                iface: Some(clamp_iface),
                ..
            } = d
            {
                if clamp_iface == bridge_name {
                    warn!(
                        bridge = %bridge_name,
                        underlying = %phys_name,
                        "mss-clamp `via {bridge_name}` will NOT match while the bridge \
                         egress short-circuit is installed (clamp matching keys on the \
                         resolved egress ifindex). Scope the clamp `via {phys_name}` or \
                         set `bridge-resolve off`."
                    );
                }
            }
        }
    }

    let desired_subifs: HashSet<(u32, u32, u16)> = vlan_entries
        .iter()
        .filter_map(|(subif, vid, parent)| {
            // Skip entries whose ifindexes don't resolve, the proc
            // file is a snapshot; an iface may have disappeared between
            // read and here.
            let subif_idx = if_nametoindex(subif).ok()?;
            let phys_idx = if_nametoindex(parent).ok()?;
            Some((subif_idx, phys_idx, *vid))
        })
        .collect();
    let desired_bridges: HashSet<(u32, u32, u16)> = chains
        .iter()
        .filter_map(|(bridge, phys, vid)| {
            let bridge_idx = if_nametoindex(bridge).ok()?;
            let phys_idx = if_nametoindex(phys).ok()?;
            Some((bridge_idx, phys_idx, *vid))
        })
        .collect();
    // Union for the diff/removal/gate logic; the ADD pass below runs
    // subif entries before bridge aliases so that under map-capacity
    // pressure the slot that runs out is always the optional
    // optimization's, never a required subif entry (mirrors the
    // attach-time population order).
    let desired: HashSet<(u32, u32, u16)> =
        desired_subifs.union(&desired_bridges).copied().collect();

    let map = state
        .ebpf
        .map_mut("VLAN_RESOLVE")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "VLAN_RESOLVE missing from ELF"))?;
    let mut hm: AyaHashMap<_, u32, VlanResolve> = AyaHashMap::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("VLAN_RESOLVE try_from: {e}")))?;

    // Gather current state, value is VlanResolve { phys_ifindex, vid }.
    let current: HashSet<(u32, u32, u16)> = hm
        .iter()
        .filter_map(Result::ok)
        .map(|(subif_idx, v)| (subif_idx, v.phys_ifindex, v.vid))
        .collect();

    let mut delta = DeltaCount::default();
    let mut to_add: Vec<&(u32, u32, u16)> = desired.difference(&current).collect();
    to_add.sort_by_key(|t| {
        (
            desired_bridges.contains(t) && !desired_subifs.contains(t),
            t.0,
        )
    });
    for (subif_idx, phys_idx, vid) in to_add.into_iter() {
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
    // The diff is over full (key, value) tuples but the map is keyed
    // on ifindex alone, so a key whose VALUE changed (same bridge,
    // re-parented member or new VID) appears in both differences: the
    // add pass above already wrote the new value under the key, and
    // removing the old tuple here would delete that fresh entry —
    // one SIGHUP would leave the key absent until the next reconcile.
    // Skip removals for keys the desired set still contains.
    let desired_keys: HashSet<u32> = desired.iter().map(|(k, _, _)| *k).collect();
    for (subif_idx, _, _) in current.difference(&desired) {
        if desired_keys.contains(subif_idx) {
            continue; // value updated in place by the add pass
        }
        match hm.remove(subif_idx) {
            Ok(()) => {
                delta.removed += 1;
                info!(subif_idx, "VLAN_RESOLVE removed (subif gone)");
            }
            Err(e) => warn!(subif_idx, error = %e, "VLAN_RESOLVE remove failed"),
        }
    }

    // Authoritative post-convergence fix of the VLAN_PRESENT gate bit:
    // set iff the map has (desired) entries. Covers subifs appearing
    // or disappearing between reconcile_cfg's proc read and here.
    set_cfg_flag(
        &mut state.ebpf,
        FP_CFG_FLAG_VLAN_PRESENT,
        !desired.is_empty(),
    )?;
    Ok(delta)
}

/// Reconcile REDIRECT_DEVMAP against the current `/sys/class/net`
/// enumeration of viable Ethernet-type redirect targets. Adds any new
/// ifaces that came up since the last reconcile, purges any whose
/// ifindex no longer resolves via `if_indextoname`. Covers both the
/// new-iface-hot-plug case and the stale-iface-hot-unplug case.
fn reconcile_devmap(state: &mut ActiveState) -> ModuleResult<DeltaCount> {
    use std::collections::HashSet;

    let desired: HashSet<u32> = crate::linux_impl::enumerate_redirect_targets()
        .into_iter()
        .map(|(_, ifindex)| ifindex)
        .collect();

    let map = state
        .ebpf
        .map_mut("REDIRECT_DEVMAP")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "REDIRECT_DEVMAP missing from ELF"))?;
    let mut devmap: DevMapHash<_> = DevMapHash::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("REDIRECT_DEVMAP try_from: {e}")))?;

    let current: HashSet<u32> = devmap.keys().filter_map(Result::ok).collect();

    let mut delta = DeltaCount::default();
    for ifindex in desired.difference(&current) {
        // DevMapHash value is an ifindex u32; for simple forward-to-self
        // the value equals the key.
        match devmap.insert(*ifindex, *ifindex, None, 0) {
            Ok(()) => {
                delta.added += 1;
                info!(ifindex, "REDIRECT_DEVMAP added (iface came up)");
            }
            Err(e) => warn!(ifindex, error = %e, "REDIRECT_DEVMAP insert failed"),
        }
    }
    for ifindex in current.difference(&desired) {
        // Only purge ifaces that the kernel no longer knows about;
        // an iface in `current` but down at enumeration time stays.
        if ifindex_exists(*ifindex) {
            continue;
        }
        match devmap.remove(*ifindex) {
            Ok(()) => {
                delta.removed += 1;
                info!(ifindex, "REDIRECT_DEVMAP stale entry purged");
            }
            Err(e) => warn!(ifindex, error = %e, "REDIRECT_DEVMAP remove failed"),
        }
    }

    // Converge the tc datapath's membership mirror against the same
    // desired set (Phase T; devmaps are XDP-only so tc_fast_path's
    // pristine-packet pre-check reads this plain hash map instead).
    // Same stale-purge policy; deltas fold into the devmap's counts.
    {
        let map = state
            .ebpf
            .map_mut("TC_REDIRECT_TARGETS")
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "TC_REDIRECT_TARGETS missing"))?;
        let mut hm: AyaHashMap<_, u32, u32> = AyaHashMap::try_from(map).map_err(|e| {
            ModuleError::other(MODULE_NAME, format!("TC_REDIRECT_TARGETS try_from: {e}"))
        })?;
        let tc_current: HashSet<u32> = hm.keys().filter_map(Result::ok).collect();
        for ifindex in desired.difference(&tc_current) {
            match hm.insert(*ifindex, *ifindex, 0) {
                Ok(()) => info!(ifindex, "TC_REDIRECT_TARGETS added (iface came up)"),
                Err(e) => warn!(ifindex, error = %e, "TC_REDIRECT_TARGETS insert failed"),
            }
        }
        for ifindex in tc_current.difference(&desired) {
            if ifindex_exists(*ifindex) {
                continue;
            }
            match hm.remove(ifindex) {
                Ok(()) => info!(ifindex, "TC_REDIRECT_TARGETS stale entry purged"),
                Err(e) => warn!(ifindex, error = %e, "TC_REDIRECT_TARGETS remove failed"),
            }
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

// --- v0.2.4 additions: block-prefix + mss-clamp reconcile -----------------

/// IPv4 block-prefix delta. Mirrors `reconcile_allow_v4` against the
/// `BLOCK_V4` LPM trie. Closes the v0.2.1 gap where adding/removing
/// `block-prefix` lines required a full restart.
fn reconcile_block_v4(state: &mut ActiveState, cfg: &ModuleConfig<'_>) -> ModuleResult<DeltaCount> {
    let desired: HashSet<(u32, [u8; 4])> = cfg
        .section
        .directives
        .iter()
        .filter_map(|d| match d {
            ModuleDirective::BlockPrefix { cidr, .. } => {
                Some((u32::from(cidr.prefix_len), cidr.addr.octets()))
            }
            _ => None,
        })
        .collect();

    let map = state
        .ebpf
        .map_mut("BLOCK_V4")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "BLOCK_V4 map missing from ELF"))?;
    let mut trie: LpmTrie<_, [u8; 4], u8> = LpmTrie::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("BLOCK_V4 try_from: {e}")))?;

    let current: HashSet<(u32, [u8; 4])> = trie
        .keys()
        .filter_map(Result::ok)
        .map(|k| (k.prefix_len(), k.data()))
        .collect();

    apply_prefix_delta::<[u8; 4]>(&mut trie, &desired, &current, "BLOCK_V4")
}

/// IPv6 block-prefix delta. Mirrors `reconcile_allow_v6`. Currently
/// the BPF-side `BLOCK_V6` is consulted but the v0.2.1 grammar only
/// has `block-prefix` for IPv4 (no `block-prefix6` directive); this
/// path always converges to "remove anything left over" until the v6
/// directive lands. Cheap to keep wired up so the reconcile flow is
/// symmetric.
fn reconcile_block_v6(
    state: &mut ActiveState,
    _cfg: &ModuleConfig<'_>,
) -> ModuleResult<DeltaCount> {
    let desired: HashSet<(u32, [u8; 16])> = HashSet::new();

    let map = state
        .ebpf
        .map_mut("BLOCK_V6")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "BLOCK_V6 map missing from ELF"))?;
    let mut trie: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("BLOCK_V6 try_from: {e}")))?;

    let current: HashSet<(u32, [u8; 16])> = trie
        .keys()
        .filter_map(Result::ok)
        .map(|k| (k.prefix_len(), k.data()))
        .collect();

    apply_prefix_delta::<[u8; 16]>(&mut trie, &desired, &current, "BLOCK_V6")
}

/// MSS-clamp delta across the three maps: `MSS_CLAMP_V4`, `MSS_CLAMP_V6`,
/// `MSS_CLAMP_BY_IFACE`. Returns three [`DeltaCount`]s for the caller's
/// log line. The value-bearing tries use re-insert-on-key semantics
/// (any change to `mss` or `iface_filter` for an existing prefix
/// re-writes the entry), then drop keys absent from the desired set.
/// The global `mss-clamp <mtu>` form is updated via `reconcile_cfg`,
/// not here.
#[allow(clippy::type_complexity)]
fn reconcile_mss_clamp(
    state: &mut ActiveState,
    cfg: &ModuleConfig<'_>,
) -> ModuleResult<(DeltaCount, DeltaCount, DeltaCount)> {
    use packetframe_common::config::MssClampPrefix;

    // Build desired sets keyed by prefix; values include both mss and
    // iface_filter so we can detect changed-MSS-on-same-prefix.
    let mut desired_v4: std::collections::HashMap<(u32, [u8; 4]), MssClampValue> =
        std::collections::HashMap::new();
    let mut desired_v6: std::collections::HashMap<(u32, [u8; 16]), MssClampValue> =
        std::collections::HashMap::new();
    let mut desired_iface: std::collections::HashMap<u32, u16> = std::collections::HashMap::new();

    for d in &cfg.section.directives {
        let ModuleDirective::MssClamp {
            prefix, iface, mss, ..
        } = d
        else {
            continue;
        };
        let iface_filter: u32 = match iface {
            Some(name) => match if_nametoindex(name) {
                Ok(idx) => idx,
                Err(e) => {
                    warn!(iface = %name, error = %e, "mss-clamp reconcile: iface lookup failed; skipping rule");
                    continue;
                }
            },
            None => 0,
        };
        match (prefix, iface) {
            (Some(MssClampPrefix::V4(p)), _) => {
                desired_v4.insert(
                    (u32::from(p.prefix_len), p.addr.octets()),
                    MssClampValue {
                        mss: *mss,
                        _pad: 0,
                        iface_filter,
                    },
                );
            }
            (Some(MssClampPrefix::V6(p)), _) => {
                desired_v6.insert(
                    (u32::from(p.prefix_len), p.addr.octets()),
                    MssClampValue {
                        mss: *mss,
                        _pad: 0,
                        iface_filter,
                    },
                );
            }
            (None, Some(_)) => {
                desired_iface.insert(iface_filter, *mss);
            }
            (None, None) => {
                // Global, handled by reconcile_cfg.
            }
        }
    }

    let v4_delta = reconcile_mss_lpm::<[u8; 4]>(state, &desired_v4, "MSS_CLAMP_V4")?;
    let v6_delta = reconcile_mss_lpm::<[u8; 16]>(state, &desired_v6, "MSS_CLAMP_V6")?;
    let iface_delta = reconcile_mss_iface(state, &desired_iface)?;

    Ok((v4_delta, v6_delta, iface_delta))
}

/// Generic LPM-trie reconcile for the mss-clamp value type. Differs
/// from `apply_prefix_delta` because the value (`MssClampValue`) is
/// part of the desired-state comparison: re-inserts entries whose
/// value changed even if the key already exists.
fn reconcile_mss_lpm<K>(
    state: &mut ActiveState,
    desired: &std::collections::HashMap<(u32, K), MssClampValue>,
    map_label: &str,
) -> ModuleResult<DeltaCount>
where
    K: aya::Pod + Eq + std::hash::Hash + std::fmt::Debug + Clone + Copy,
{
    let map = state.ebpf.map_mut(map_label).ok_or_else(|| {
        ModuleError::other(MODULE_NAME, format!("{map_label} map missing from ELF"))
    })?;
    let mut trie: LpmTrie<_, K, MssClampValue> = LpmTrie::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("{map_label} try_from: {e}")))?;

    let current_keys: HashSet<(u32, K)> = trie
        .keys()
        .filter_map(Result::ok)
        .map(|k| (k.prefix_len(), k.data()))
        .collect();

    let mut delta = DeltaCount::default();

    // Insert/overwrite desired entries.
    for ((len, data), value) in desired {
        let key = LpmKey::new(*len, *data);
        // Treat any insert as either an add (key not present) or an
        // update (key present, value possibly changed). The delta
        // counts adds only; updates are silent, operators see them
        // as "0 added, 0 removed" and have to look at counters to
        // confirm new values landed.
        let was_present = current_keys.contains(&(*len, *data));
        match trie.insert(&key, *value, 0) {
            Ok(()) => {
                if !was_present {
                    delta.added += 1;
                }
            }
            Err(e) => warn!(
                map = map_label,
                prefix_len = *len,
                ?data,
                error = %e,
                "mss-clamp insert failed"
            ),
        }
    }

    // Remove keys absent from desired.
    for (len, data) in &current_keys {
        if !desired.contains_key(&(*len, *data)) {
            let key = LpmKey::new(*len, *data);
            match trie.remove(&key) {
                Ok(()) => delta.removed += 1,
                Err(e) => warn!(
                    map = map_label,
                    prefix_len = *len,
                    ?data,
                    error = %e,
                    "mss-clamp remove failed"
                ),
            }
        }
    }

    Ok(delta)
}

fn reconcile_mss_iface(
    state: &mut ActiveState,
    desired: &std::collections::HashMap<u32, u16>,
) -> ModuleResult<DeltaCount> {
    let map = state.ebpf.map_mut("MSS_CLAMP_BY_IFACE").ok_or_else(|| {
        ModuleError::other(MODULE_NAME, "MSS_CLAMP_BY_IFACE map missing from ELF")
    })?;
    let mut hm: AyaHashMap<_, u32, u16> = AyaHashMap::try_from(map).map_err(|e| {
        ModuleError::other(MODULE_NAME, format!("MSS_CLAMP_BY_IFACE try_from: {e}"))
    })?;

    let current_keys: HashSet<u32> = hm.keys().filter_map(Result::ok).collect();

    let mut delta = DeltaCount::default();

    for (ifindex, mss) in desired {
        let was_present = current_keys.contains(ifindex);
        match hm.insert(ifindex, mss, 0) {
            Ok(()) => {
                if !was_present {
                    delta.added += 1;
                }
            }
            Err(e) => warn!(
                ifindex = *ifindex,
                error = %e,
                "MSS_CLAMP_BY_IFACE insert failed"
            ),
        }
    }
    for ifindex in &current_keys {
        if !desired.contains_key(ifindex) {
            match hm.remove(ifindex) {
                Ok(()) => delta.removed += 1,
                Err(e) => warn!(
                    ifindex = *ifindex,
                    error = %e,
                    "MSS_CLAMP_BY_IFACE remove failed"
                ),
            }
        }
    }

    Ok(delta)
}
