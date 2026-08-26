//! Linux implementation of the guard lifecycle: ELF load, per-iface
//! tc-egress attach, GUARD_CFG population, teardown, health, stats.
//!
//! The tc attach/detach pair is a mirror of fast-path's
//! `tc_attach_iface` / `tc_detach_one` (its linux_impl.rs) with
//! `TcAttachType::Egress`; when one is updated, the other likely needs
//! the same change. The load-bearing choices are inherited unchanged:
//!
//! - **Netlink cls_bpf on every kernel**, never aya's version-picked
//!   TCX path: netlink filters have qdisc lifetime (the kernel attach
//!   survives process exit) and yield the `(priority, handle)` pair
//!   `SchedClassifierLink::attached()` needs for out-of-process
//!   detach. TCX (≥6.6) would hand us an FD-lifetime link that dies
//!   with the process.
//! - The aya link is `mem::forget`-ed after `(priority, handle)` is
//!   persisted; dropping it would detach the filter.
//! - The state-file record is saved **inside the attach loop, after
//!   every attach** — a mid-loop failure must leave every live filter
//!   findable (fast-path review finding, PR #75).
//! - Detach outcomes keep the `Cleared`/`Failed` split: a record is
//!   dropped only when the filter is provably gone; a failed delete
//!   retains its only teardown metadata.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aya::Ebpf;
use tracing::info;

use packetframe_common::module::{
    HealthReport, HealthState, ModuleError, ModuleResult, SubsystemHealth,
};

use crate::cfg::{GuardConfig, GuardIfCfg};
use crate::{aligned_bpf_copy, metrics, pin, tc_links, GUARD_BPF_AVAILABLE, MODULE_NAME};

// SAFETY: `#[repr(C)]`, no padding holes beyond the explicit `_pad0`
// (layout pinned by the cfg.rs unit test), every field valid for any
// bit pattern.
unsafe impl aya::Pod for GuardIfCfg {}

/// Live module state between `load` and `detach`.
pub(crate) struct ActiveState {
    pub ebpf: Ebpf,
    pub bpffs_root: PathBuf,
    pub state_dir: PathBuf,
    pub config: GuardConfig,
    /// `(iface, ifindex, mac)` per successful attach, in config order.
    /// The MAC is the attach-time snapshot foreign-src enforces — a
    /// deliberate restart-only value.
    pub attached: Vec<(String, u32, [u8; 6])>,
}

/// `Module::load`: embed sanity, no-adoption pin refusal, ELF +
/// program load (the verifier runs here).
pub(crate) fn load(
    config: GuardConfig,
    bpffs_root: &Path,
    state_dir: &Path,
) -> ModuleResult<ActiveState> {
    if !GUARD_BPF_AVAILABLE {
        return Err(ModuleError::other(
            MODULE_NAME,
            "guard BPF ELF is an empty stub (built without the BPF toolchain); \
             refusing to load",
        ));
    }
    if pin::has_existing_pins(bpffs_root) {
        return Err(ModuleError::other(
            MODULE_NAME,
            format!(
                "existing pins under {} from a prior invocation; run \
                 `packetframe detach --all` first (v0.1 does not adopt in place)",
                pin::module_root(bpffs_root).display()
            ),
        ));
    }
    // A leftover state file is prior state even with no pins: attach
    // persists each filter record BEFORE the post-loop pinning, so a
    // crash in that window leaves live qdisc-lifetime filters whose
    // ONLY teardown metadata is this file. Starting fresh would
    // overwrite it and orphan them (review finding, PR #205).
    match tc_links::load(state_dir) {
        Ok(Some(file)) if !file.links.is_empty() => {
            return Err(ModuleError::other(
                MODULE_NAME,
                format!(
                    "existing guard tc-link records in {} from a prior \
                     invocation; run `packetframe detach --all` first",
                    tc_links::file_path(state_dir).display()
                ),
            ));
        }
        Ok(_) => {}
        Err(e) => {
            return Err(ModuleError::other(
                MODULE_NAME,
                format!("read prior guard tc links: {e}"),
            ));
        }
    }
    let bytes = aligned_bpf_copy();
    let mut ebpf = Ebpf::load(&bytes)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("aya::Ebpf::load failed: {e}")))?;
    {
        use aya::programs::tc::SchedClassifier;
        let prog: &mut SchedClassifier = ebpf
            .program_mut(pin::PROGRAM_NAME)
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "guard_egress missing in ELF"))?
            .try_into()
            .map_err(|e| {
                ModuleError::other(MODULE_NAME, format!("guard_egress program type: {e}"))
            })?;
        prog.load().map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("guard_egress load failed (verifier rejection?): {e}"),
            )
        })?;
    }
    Ok(ActiveState {
        ebpf,
        bpffs_root: bpffs_root.to_path_buf(),
        state_dir: state_dir.to_path_buf(),
        config,
        attached: Vec::new(),
    })
}

/// `Module::attach`: per configured interface — config-map entry
/// FIRST (fail-open defaults mean there is never an attached-but-
/// unconfigured window), then clsact + egress filter, then the state-
/// file record. Pins after the loop.
pub(crate) fn attach(state: &mut ActiveState, settle_time: Duration) -> ModuleResult<()> {
    pin::ensure_dirs(&state.bpffs_root)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("create pin dirs: {e}")))?;

    let plan: Vec<(String, crate::cfg::GuardIfaceRules)> = state.config.interfaces.clone();
    let mut records = tc_links::TcLinksFile { links: Vec::new() };
    for (idx, (iface, rules)) in plan.iter().enumerate() {
        if idx > 0 && !settle_time.is_zero() {
            // Symmetric with fast-path's attach pacing. tc attach does
            // not bounce links the way XDP does on rvu-nicpf, but the
            // configured settle time is cheap and keeps multi-bridge
            // attach behavior uniform across modules.
            std::thread::sleep(settle_time);
        }
        let ifindex = ifindex_of(iface)?;
        let mac = mac_of(iface)?;
        write_if_cfg(&mut state.ebpf, ifindex, &GuardIfCfg::compile(mac, rules))?;
        let (priority, handle) = tc_attach_egress(&mut state.ebpf, iface)?;
        records.links.push(tc_links::TcLinkRecord {
            iface: iface.clone(),
            ifindex,
            priority,
            handle,
        });
        // Save inside the loop: a failure attaching iface N must not
        // strand ifaces 0..N as invisible orphans (PR #75 lesson).
        // And when the save itself fails, the just-attached filter is
        // live with NO persisted record — roll it back rather than
        // orphan an active classifier (review finding, PR #205).
        if let Err(e) = tc_links::save(&state.state_dir, &records) {
            let rollback = match tc_detach_one(iface, ifindex, priority, handle) {
                TcDetachOutcome::Cleared => {
                    format!("the just-attached filter on {iface} was rolled back")
                }
                TcDetachOutcome::Failed(msg) => format!(
                    "rollback ALSO failed ({msg}) — a live filter on {iface} has no \
                     persisted record; remove it with `tc filter del dev {iface} egress`"
                ),
            };
            return Err(ModuleError::other(
                MODULE_NAME,
                format!("persist tc links: {e}; {rollback}"),
            ));
        }
        state.attached.push((iface.clone(), ifindex, mac));
        info!(
            iface,
            ifindex, priority, handle, "guard egress filter attached"
        );
    }

    pin_program_and_maps(state)?;
    Ok(())
}

/// `Module::reconfigure`: restart-only delta first (interface set),
/// then an idempotent rewrite of every attached ifindex's config
/// entry. Hash-map element replace is RCU-atomic, so readers never
/// see a torn config; token-bucket state is deliberately left alone
/// (stale deadlines converge within one old-burst window).
pub(crate) fn reconfigure(state: &mut ActiveState, new: GuardConfig) -> ModuleResult<()> {
    state
        .config
        .restart_only_delta(&new)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("module guard: {e}")))?;
    for (iface, ifindex, mac) in &state.attached {
        // restart_only_delta guarantees the interface sets match.
        let rules = new
            .interfaces
            .iter()
            .find(|(i, _)| i == iface)
            .map(|(_, r)| r)
            .ok_or_else(|| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("reconfigure: attached {iface} missing from new config"),
                )
            })?;
        write_if_cfg(&mut state.ebpf, *ifindex, &GuardIfCfg::compile(*mac, rules))?;
    }
    state.config = new;
    Ok(())
}

/// In-process `Module::detach`: delegates to the state-file-driven
/// teardown (netlink filters have qdisc lifetime, so the live loader
/// adds nothing), then forgets the attach list.
pub(crate) fn detach(state: &mut ActiveState) -> ModuleResult<()> {
    detach_from_state_dir(&state.state_dir, &state.bpffs_root)?;
    state.attached.clear();
    Ok(())
}

/// Standalone teardown from persisted state, no live loader required.
/// Used by in-process detach and by the CLI's `detach --all` /
/// `detach` (config-scoped) paths. Returns the number of filters
/// cleared.
///
/// Records whose delete failed with the filter plausibly still live
/// are written back and the call errors — deleting their only
/// teardown metadata would orphan active classifiers while reporting
/// success. Pins are removed only on full success, so a retry sees a
/// consistent world. The clsact qdisc is never deleted: fast-path may
/// share it on the same interface.
pub fn detach_from_state_dir(state_dir: &Path, bpffs_root: &Path) -> ModuleResult<usize> {
    let links = match tc_links::load(state_dir)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("read guard tc links: {e}")))?
    {
        Some(file) => file.links,
        None => Vec::new(),
    };

    let mut cleared = 0usize;
    let mut retained = Vec::new();
    let mut errors = Vec::new();
    for rec in links {
        match tc_detach_one(&rec.iface, rec.ifindex, rec.priority, rec.handle) {
            TcDetachOutcome::Cleared => cleared += 1,
            TcDetachOutcome::Failed(msg) => {
                errors.push(msg);
                retained.push(rec);
            }
        }
    }

    if retained.is_empty() {
        tc_links::remove(state_dir)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("remove guard tc links: {e}")))?;
        pin::remove_all(bpffs_root)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("remove guard pins: {e}")))?;
        Ok(cleared)
    } else {
        tc_links::save(state_dir, &tc_links::TcLinksFile { links: retained })
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("retain guard tc links: {e}")))?;
        Err(ModuleError::other(
            MODULE_NAME,
            format!(
                "{}; records retained — rerun `packetframe detach` or \
                 `tc filter del dev <iface> egress`",
                errors.join("; AND ")
            ),
        ))
    }
}

/// `Module::health_check`: one row per attached interface (an iface
/// that vanished took its qdisc-lifetime filter with it), plus one
/// informational counters row.
///
/// Deliberately does NOT probe filter presence via
/// `SchedClassifierLink::attached()` — dropping the constructed link
/// DETACHES the filter. Presence is asserted indirectly (record +
/// iface + config entry); a read-only netlink filter dump is future
/// work.
pub(crate) fn health(state: &ActiveState) -> HealthReport {
    let mut overall = HealthState::Healthy;
    let mut subsystems = Vec::new();
    for (iface, ifindex, _) in &state.attached {
        // Compare ifindex, not mere name existence: a deleted-and-
        // recreated device keeps its name but took the qdisc-lifetime
        // filter with it — a name-only check would report green while
        // enforcement is silently absent (review finding, PR #205).
        let (hs, message) = match ifindex_of(iface) {
            Err(_) => (
                HealthState::Degraded,
                Some("interface vanished; its egress filter died with it".to_string()),
            ),
            Ok(current) if current != *ifindex => (
                HealthState::Degraded,
                Some(format!(
                    "interface recreated (ifindex {ifindex} → {current}); the egress \
                     filter died with the old device — restart (stop, `packetframe \
                     detach`, start) to re-attach"
                )),
            ),
            Ok(_) => (HealthState::Healthy, None),
        };
        overall = overall.worse_of(hs);
        subsystems.push(SubsystemHealth {
            name: format!("attach:{iface}"),
            state: hs,
            message,
            last_success_age_seconds: None,
        });
    }
    if let Ok(stats) = read_stats(&state.ebpf) {
        let sum = |idxs: &[usize]| -> u64 { idxs.iter().map(|&i| stats[i]).sum() };
        // Indices from metrics::COUNTER_NAMES / the BPF GuardStatIdx.
        let dropped = sum(&[7, 8, 11, 14, 17]);
        let monitored = sum(&[9, 12, 15, 18, 19]);
        subsystems.push(SubsystemHealth {
            name: "enforce".to_string(),
            state: HealthState::Healthy,
            message: Some(format!(
                "dropped={dropped} monitored={monitored} (cumulative since attach)"
            )),
            last_success_age_seconds: None,
        });
    }
    HealthReport {
        overall,
        subsystems,
    }
}

/// `Module::sample_metrics`: render the counter block as Prometheus
/// text into the loader's gauge slot.
pub(crate) fn sample_metrics(state: &ActiveState, out: &mut String) -> ModuleResult<()> {
    let stats = read_stats(&state.ebpf)?;
    metrics::render_textfile(&stats, out);
    Ok(())
}

// --- building blocks --------------------------------------------------------

/// Attach `guard_egress` to `iface`'s clsact **egress** and return the
/// kernel-assigned `(priority, handle)`. Mirror of fast-path's
/// `tc_attach_iface`; see the module doc for the shared rationale.
fn tc_attach_egress(ebpf: &mut Ebpf, iface: &str) -> ModuleResult<(u16, u32)> {
    use aya::programs::tc::{
        qdisc_add_clsact, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType,
    };

    match qdisc_add_clsact(iface) {
        Ok(()) => info!(iface, "clsact qdisc added"),
        // Already present (fast-path's ingress filter on the same
        // iface, another tool, a prior run): attaching to the existing
        // clsact is exactly what we want.
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
            info!(iface, "clsact qdisc already present");
        }
        Err(e) => {
            return Err(ModuleError::other(
                MODULE_NAME,
                format!("qdisc_add_clsact({iface}): {e}"),
            ));
        }
    }

    let prog: &mut SchedClassifier = ebpf
        .program_mut(pin::PROGRAM_NAME)
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "guard_egress missing post-load"))?
        .try_into()
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("guard_egress type: {e}")))?;
    let link_id = prog
        .attach_with_options(
            iface,
            TcAttachType::Egress,
            TcAttachOptions::Netlink(NlOptions::default()),
        )
        .map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("guard tc egress attach on {iface} failed: {e}"),
            )
        })?;
    let link = prog
        .take_link(link_id)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("guard take_link({iface}): {e}")))?;
    let priority = link.priority().map_err(|e| {
        ModuleError::other(MODULE_NAME, format!("guard link priority({iface}): {e}"))
    })?;
    let handle = link
        .handle()
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("guard link handle({iface}): {e}")))?;
    // Keep the kernel attach alive past this scope; see module docs.
    std::mem::forget(link);
    Ok((priority, handle))
}

/// Outcome of one tc-filter detach attempt; mirror of fast-path's
/// `TcDetachOutcome` (see its doc for the record-retention rationale).
enum TcDetachOutcome {
    Cleared,
    Failed(String),
}

fn tc_detach_one(
    iface: &str,
    expected_ifindex: u32,
    priority: u16,
    handle: u32,
) -> TcDetachOutcome {
    use aya::programs::tc::{SchedClassifierLink, TcAttachType, TcError};
    use aya::programs::{Link as _, ProgramError};

    // A same-name device with a DIFFERENT ifindex is a recreated
    // device: the recorded filter died with the original (qdisc
    // lifetime), and `SchedClassifierLink::attached` resolves by name,
    // so deleting here could remove an unrelated filter on the
    // replacement whose (priority, handle) happens to match — the
    // first auto-allocated tuple is common (review finding, PR #205).
    // The check-to-delete race is accepted: it requires the device to
    // be recreated in that instant AND the tuple to collide.
    match ifindex_of(iface) {
        Err(_) => {
            info!(iface, "iface gone; guard tc filter died with it");
            return TcDetachOutcome::Cleared;
        }
        Ok(current) if current != expected_ifindex => {
            info!(
                iface,
                expected_ifindex,
                current,
                "iface recreated; the recorded filter died with the old device"
            );
            return TcDetachOutcome::Cleared;
        }
        Ok(_) => {}
    }

    // `attached()` only resolves the ifindex; failure means the iface
    // is gone, and qdisc-lifetime filters go with their device.
    let link = match SchedClassifierLink::attached(iface, TcAttachType::Egress, priority, handle) {
        Ok(l) => l,
        Err(e) => {
            info!(iface, error = %e, "iface gone; guard tc filter died with it");
            return TcDetachOutcome::Cleared;
        }
    };
    match link.detach() {
        Ok(()) => TcDetachOutcome::Cleared,
        // ENOENT: no such filter; EINVAL: no such qdisc. Either way
        // nothing of ours is attached anymore — goal state.
        Err(ProgramError::TcError(TcError::NetlinkError { io_error }))
            if matches!(
                io_error.raw_os_error(),
                Some(libc::ENOENT) | Some(libc::EINVAL)
            ) =>
        {
            info!(iface, priority, handle, "guard tc filter already absent");
            TcDetachOutcome::Cleared
        }
        Err(e) => TcDetachOutcome::Failed(format!(
            "guard tc detach on {iface} (prio {priority}, handle {handle}): {e}"
        )),
    }
}

/// Write (insert-or-replace) one per-ifindex config entry.
fn write_if_cfg(ebpf: &mut Ebpf, ifindex: u32, cfg: &GuardIfCfg) -> ModuleResult<()> {
    use aya::maps::HashMap;
    let map = ebpf
        .map_mut("GUARD_CFG")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "GUARD_CFG map missing"))?;
    let mut m: HashMap<_, u32, GuardIfCfg> = HashMap::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("GUARD_CFG type: {e}")))?;
    m.insert(ifindex, *cfg, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("GUARD_CFG insert: {e}")))
}

fn pin_program_and_maps(state: &mut ActiveState) -> ModuleResult<()> {
    use aya::programs::tc::SchedClassifier;
    for prog_name in pin::PROGRAM_NAMES {
        let prog_path = pin::program_path_for(&state.bpffs_root, prog_name);
        let prog: &mut SchedClassifier = state
            .ebpf
            .program_mut(prog_name)
            .ok_or_else(|| {
                ModuleError::other(MODULE_NAME, format!("{prog_name} program missing for pin"))
            })?
            .try_into()
            .map_err(|e| {
                ModuleError::other(MODULE_NAME, format!("pin: {prog_name} not sched_cls: {e}"))
            })?;
        prog.pin(&prog_path).map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("pin {prog_name} at {}: {e}", prog_path.display()),
            )
        })?;
    }
    for name in pin::MAP_NAMES {
        let map = state.ebpf.map(name).ok_or_else(|| {
            ModuleError::other(MODULE_NAME, format!("map {name} missing for pin"))
        })?;
        let path = pin::map_path(&state.bpffs_root, name);
        map.pin(&path).map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("pin map {name} at {}: {e}", path.display()),
            )
        })?;
    }
    info!(
        pin_root = %pin::module_root(&state.bpffs_root).display(),
        "guard_egress program + maps pinned"
    );
    Ok(())
}

/// Userspace mirror of the BPF `[u64; GUARD_STATS_COUNT]` block shape.
type StatsBlock = [u64; metrics::STATS_BLOCK_LEN];

/// Sum the per-CPU counter block into `COUNTER_COUNT` totals (headroom
/// slots beyond the named counters are dropped).
fn read_stats(ebpf: &Ebpf) -> ModuleResult<Vec<u64>> {
    use aya::maps::PerCpuArray;
    let map = ebpf
        .map("GUARD_STATS")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "GUARD_STATS map missing"))?;
    let stats: PerCpuArray<_, StatsBlock> = PerCpuArray::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("GUARD_STATS type: {e}")))?;
    let per_cpu = stats
        .get(&0, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("GUARD_STATS get[0]: {e}")))?;
    let mut out = vec![0u64; metrics::COUNTER_COUNT];
    for cpu_block in per_cpu.iter() {
        for (slot, v) in out.iter_mut().zip(cpu_block.iter()) {
            *slot += *v;
        }
    }
    Ok(out)
}

/// Read STATS directly from the bpffs pin, no live module required
/// (`packetframe status` when the loader isn't running). Mirror of
/// fast-path's `stats_from_pin`.
pub fn stats_from_pin(bpffs_root: &Path) -> ModuleResult<Vec<u64>> {
    use aya::maps::{Map, MapData, PerCpuArray};
    let pin_path = pin::map_path(bpffs_root, "GUARD_STATS");
    let map_data = MapData::from_pin(&pin_path).map_err(|e| {
        ModuleError::other(
            MODULE_NAME,
            format!("open GUARD_STATS pin at {}: {e}", pin_path.display()),
        )
    })?;
    let map = Map::PerCpuArray(map_data);
    let stats: PerCpuArray<_, StatsBlock> = PerCpuArray::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("GUARD_STATS PerCpuArray: {e}")))?;
    let per_cpu = stats
        .get(&0, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("GUARD_STATS get[0]: {e}")))?;
    let mut out = vec![0u64; metrics::COUNTER_COUNT];
    for cpu_block in per_cpu.iter() {
        for (slot, v) in out.iter_mut().zip(cpu_block.iter()) {
            *slot += *v;
        }
    }
    Ok(out)
}

fn ifindex_of(iface: &str) -> ModuleResult<u32> {
    let path = format!("/sys/class/net/{iface}/ifindex");
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("read {path}: {e}")))?;
    raw.trim()
        .parse::<u32>()
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("parse {path} (`{raw}`): {e}")))
}

/// The interface's own MAC — the expected src for `foreign-src`.
/// sysfs, not SIOCGIFHWADDR: attach runs in the init netns where
/// sysfs is authoritative, and this avoids the glibc/musl ioctl-type
/// divergence the test tree documents.
fn mac_of(iface: &str) -> ModuleResult<[u8; 6]> {
    let path = format!("/sys/class/net/{iface}/address");
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("read {path}: {e}")))?;
    parse_mac(raw.trim())
        .ok_or_else(|| ModuleError::other(MODULE_NAME, format!("parse {path} (`{raw}`)")))
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut n = 0;
    for part in s.split(':') {
        if n == 6 {
            return None;
        }
        out[n] = u8::from_str_radix(part, 16).ok()?;
        n += 1;
    }
    (n == 6).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::parse_mac;

    #[test]
    fn mac_parses_and_refuses() {
        assert_eq!(
            parse_mac("28:70:4e:47:69:c7"),
            Some([0x28, 0x70, 0x4e, 0x47, 0x69, 0xc7])
        );
        assert_eq!(parse_mac("28:70:4e:47:69"), None);
        assert_eq!(parse_mac("28:70:4e:47:69:c7:00"), None);
        assert_eq!(parse_mac("zz:70:4e:47:69:c7"), None);
        assert_eq!(parse_mac(""), None);
    }
}
