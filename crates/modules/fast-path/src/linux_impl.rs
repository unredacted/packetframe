//! Linux-only loader logic: `aya::Ebpf` lifecycle, XDP attach with
//! trial-attach fallback per SPEC.md §2.3, map population.
//!
//! Kept in a cfg-gated module so `lib.rs` can express the trait impl
//! once and dispatch to either real logic (here) or a NotImplemented
//! stub (`stub_impl.rs`). macOS dev loops compile either way.

use std::ffi::CString;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use aya::{
    maps::{lpm_trie::Key as LpmKey, xdp::DevMapHash, Array, HashMap as AyaHashMap, LpmTrie},
    programs::{
        links::{FdLink, PinnedLink},
        xdp::XdpFlags,
        Xdp,
    },
    Ebpf,
};
use packetframe_common::{
    config::{
        uncovered_local_prefix_warnings, AttachMode, DriverWorkaround, Ipv4Prefix, Ipv6Prefix,
        ModuleDirective, ToggleAutoOnOff,
    },
    module::{Attachment, HookType, LoaderCtx, ModuleConfig, ModuleError, ModuleResult},
};
use tracing::{debug, info, warn};

use crate::{aligned_bpf_copy, pin, FAST_PATH_BPF_AVAILABLE, MODULE_NAME};

/// Layout mirror of `FpCfg` in `bpf/src/maps.rs` (PR #3). `#[repr(C)]`
/// with all-bit-patterns-valid primitive fields, so `aya::Pod` is safe
/// to impl, the marker tells aya the struct is safe to byte-copy into
/// the kernel's map buffer. Bytes-for-bytes match the BPF-side struct.
///
/// Layout V2 (v0.2.4): the formerly-`_reserved [u8; 2]` slot is now
/// `mss_clamp_global: u16`, a global MSS clamp ceiling for matched
/// TCP SYN/SYN-ACK packets. 0 = unset. Per-prefix and per-iface clamp
/// maps take precedence over this fallback.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FpCfg {
    pub dry_run: u8,
    pub flags: u8,
    pub mss_clamp_global: u16,
    pub version: u32,
}

// SAFETY: FpCfg is repr(C), contains only primitive integer types
// (u8/u8/u16/u32 packs exactly into 8 bytes on every target). Every
// bit pattern is valid; aya uses this to byte-copy the struct into
// the kernel's array value slot.
unsafe impl aya::Pod for FpCfg {}

pub(crate) const FP_CFG_VERSION_V2: u32 = 1;

/// Mirror of `bpf/src/maps.rs::FP_CFG_FLAG_HEAD_SHIFT_128`. Enables
/// the pre-Linux-v6.8 rvu-nicpf `xdp_prepare_buff` workaround (SPEC
/// §11.1(c)). Keep in lockstep with the BPF side.
pub(crate) const FP_CFG_FLAG_HEAD_SHIFT_128: u8 = 0b0000_0100;

/// Mirror of `bpf/src/maps.rs::FP_CFG_FLAG_CUSTOM_FIB` (Option F).
/// Set when `forwarding-mode` is `custom-fib` or `compare`; routes
/// the XDP program to consult `FIB_V4`/`FIB_V6` instead of
/// `bpf_fib_lookup()`. Not yet read from the XDP program, Phase 1
/// Slice 1B lands the dispatch gate. Kept in lockstep with the BPF
/// side so userspace writes the right bit.
#[allow(dead_code)]
pub(crate) const FP_CFG_FLAG_CUSTOM_FIB: u8 = 0b0000_1000;

/// Mirror of `bpf/src/maps.rs::FP_CFG_FLAG_COMPARE_MODE` (Option F).
/// Enables compare mode (both lookups run, forward via kernel
/// result, bump disagreement counter). Requires
/// `FP_CFG_FLAG_CUSTOM_FIB`; userspace rejects compare without it.
#[allow(dead_code)]
pub(crate) const FP_CFG_FLAG_COMPARE_MODE: u8 = 0b0001_0000;

/// Mirrors of the `bpf/src/maps.rs` feature-presence bits (keep in
/// lockstep). Each gates a per-packet map lookup the XDP program can
/// skip when the feature is unconfigured; the invariant userspace must
/// uphold is "bit set whenever the corresponding map/config has
/// entries" — the bits are derived from the same directives that
/// populate the maps (via [`feature_flags_from_config`]) so they can't
/// drift, and every writer of CFG.flags goes through that helper (the
/// `reconcile_cfg` flag rebuild included; a bit missing there would be
/// silently wiped on SIGHUP, the head-shift-bug pattern).
pub(crate) const FP_CFG_FLAG_BLOCK_PRESENT: u8 = 0b0010_0000;
pub(crate) const FP_CFG_FLAG_VLAN_PRESENT: u8 = 0b0100_0000;
pub(crate) const FP_CFG_FLAG_MSS_CLAMP_PRESENT: u8 = 0b1000_0000;

/// Compute the feature-presence bits (5-7) of `FpCfg.flags` from the
/// module directives plus the VLAN-subif discovery result. Shared by
/// `populate_cfg` (initial load) and `reconcile::reconcile_cfg`
/// (SIGHUP) so both agree — any new presence bit MUST be added here,
/// never inline at one call site.
///
/// `vlan_subifs_present` comes from `/proc/net/vlan/config` rather
/// than directives (VLAN_RESOLVE is discovery-populated). Ownership of
/// bit 6 differs by caller: `populate_cfg` passes the current proc
/// read (initial seed; a read failure later aborts load in
/// `populate_vlan_resolve` anyway), while `reconcile_cfg` passes
/// `false` and ORs in the bit *preserved from the live flags* — on
/// SIGHUP the bit may only change via `reconcile_vlan_resolve`'s
/// post-convergence RMW, so a transient proc-read failure can never
/// clear the gate while VLAN_RESOLVE still holds entries.
pub(crate) fn feature_flags_from_config(
    directives: &[ModuleDirective],
    vlan_subifs_present: bool,
) -> u8 {
    let mut flags = 0u8;
    if directives
        .iter()
        .any(|d| matches!(d, ModuleDirective::BlockPrefix { .. }))
    {
        flags |= FP_CFG_FLAG_BLOCK_PRESENT;
    }
    if directives
        .iter()
        .any(|d| matches!(d, ModuleDirective::MssClamp { .. }))
    {
        flags |= FP_CFG_FLAG_MSS_CLAMP_PRESENT;
    }
    if vlan_subifs_present {
        flags |= FP_CFG_FLAG_VLAN_PRESENT;
    }
    flags
}

/// Whether `/proc/net/vlan/config` currently lists any VLAN subifs.
/// Unreadable (module not loaded, non-Linux procfs oddity) counts as
/// "none", matching `populate_vlan_resolve`'s NotFound handling.
pub(crate) fn vlan_subifs_present() -> bool {
    read_vlan_config().map(|v| !v.is_empty()).unwrap_or(false)
}

/// Whether the `bridge-resolve` directive enables the bridge egress
/// short-circuit. Default (no directive) is `Auto` = enabled; `On` is
/// a documented synonym for `Auto` (there is nothing to force — an
/// unprovable topology stays on the kernel path either way).
pub(crate) fn bridge_resolve_enabled(directives: &[ModuleDirective]) -> bool {
    let toggle = directives
        .iter()
        .find_map(|d| match d {
            ModuleDirective::BridgeResolve(v) => Some(*v),
            _ => None,
        })
        .unwrap_or_default();
    !matches!(toggle, ToggleAutoOnOff::Off)
}

/// One collapsed bridge egress chain: a bridge whose single forwarding
/// member is a VLAN subif, resolved down to (bridge, underlying device,
/// VID). `br1337` over `switch0.1337` over `switch0` yields
/// `("br1337", "switch0", 1337)`.
pub(crate) type BridgeChain = (String, String, u16);

/// One bridge port as discovery sees it: (member name, eligible).
/// "Eligible" = brport state forwarding AND unicast flooding enabled —
/// both are preconditions for the wire-equivalence argument (see
/// `read_bridge_topology`).
pub(crate) type BridgeMember = (String, bool);

/// Host bridge topology: each bridge with its member ports.
pub(crate) type BridgeTopology = Vec<(String, Vec<BridgeMember>)>;

/// Pure core of bridge-chain discovery: which bridges collapse to a
/// (underlying device, VID) pair the datapath can redirect to directly?
///
/// A bridge qualifies iff it has **exactly one member in total** and
/// that member (a) is in bridge-port state *forwarding* and (b) is a
/// VLAN subinterface. "Exactly one member, counting non-forwarding
/// ones" is deliberate: a second member in STP blocking state can
/// transition to forwarding at any moment, at which point port choice
/// requires the bridge FDB — which the BPF side cannot consult. A
/// bridge that doesn't qualify simply keeps today's kernel path.
///
/// `bridges`: (bridge name, members as (name, is_forwarding)).
/// `vlans`: `/proc/net/vlan/config` rows as (subif, vid, parent).
pub(crate) fn bridge_vlan_chains(
    bridges: &[(String, Vec<BridgeMember>)],
    vlans: &[(String, u16, String)],
) -> Vec<BridgeChain> {
    let mut out = Vec::new();
    for (bridge, members) in bridges {
        let [(member, forwarding)] = members.as_slice() else {
            continue; // zero or multiple members: not provably collapsible
        };
        if !*forwarding {
            continue;
        }
        if let Some((_, vid, parent)) = vlans.iter().find(|(subif, _, _)| subif == member) {
            out.push((bridge.clone(), parent.clone(), *vid));
        }
    }
    out
}

/// Bridge-port STP state "forwarding" (`net/bridge/br_private.h`
/// BR_STATE_FORWARDING). `/sys/class/net/<member>/brport/state` holds
/// the numeric state.
const BR_STATE_FORWARDING: &str = "3";

/// Enumerate every bridge on the host with its members and their
/// forwarding state.
///
/// This is a point-in-time sysfs snapshot, converged at attach and on
/// every SIGHUP — deliberately the same convergence model as every
/// other discovery-populated map here (`/proc/net/vlan/config` entries,
/// redirect-target membership). There is no live topology watcher;
/// membership or STP changes between reconciles keep the previously
/// proven chain until the next `packetframe reconfigure`. Documented
/// in the runbook; a netlink link-watcher would introduce a second
/// writer domain for VLAN_RESOLVE and is out of scope for this slice. A device is a bridge iff
/// `/sys/class/net/<dev>/bridge` exists; members are the entries of
/// `<dev>/brif/`. Per-device read failures are skipped (the sysfs tree
/// is a live snapshot — a device can vanish mid-walk, same tolerance
/// as `enumerate_redirect_targets`); only a failure to list
/// `/sys/class/net` itself is an error.
fn read_bridge_topology() -> std::io::Result<BridgeTopology> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir("/sys/class/net")? {
        let Ok(entry) = entry else { continue };
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let base = format!("/sys/class/net/{name}");
        if !std::path::Path::new(&format!("{base}/bridge")).is_dir() {
            continue;
        }
        // A VLAN-filtering bridge consults its per-port VLAN table on
        // every forward — it can drop, retag, or untag before the
        // member's own 8021q encapsulation. A single forwarding member
        // is NOT wire-equivalence proof under filtering, so such
        // bridges never qualify. (The UniFi brXXXX shape this feature
        // targets is a classic non-filtering bridge; the VLAN work is
        // the subif's.) Unreadable counts as filtering-on: refuse
        // rather than assume.
        let filtering_off = std::fs::read_to_string(format!("{base}/bridge/vlan_filtering"))
            .map(|s| s.trim() == "0")
            .unwrap_or(false);
        if !filtering_off {
            debug!(bridge = %name, "bridge skipped: vlan_filtering enabled (or unreadable)");
            continue;
        }
        let Ok(ports) = std::fs::read_dir(format!("{base}/brif")) else {
            continue;
        };
        let mut members = Vec::new();
        for port in ports.flatten() {
            let Ok(member) = port.file_name().into_string() else {
                continue;
            };
            let brport = format!("/sys/class/net/{member}/brport");
            let forwarding = std::fs::read_to_string(format!("{brport}/state"))
                .map(|s| s.trim() == BR_STATE_FORWARDING)
                .unwrap_or(false);
            // With unicast flooding off, a destination MAC absent from
            // the FDB (e.g. a silent host behind a static neighbor, or
            // right after an FDB flush) is DROPPED by the bridge rather
            // than emitted through the sole port — so "single member"
            // stops implying "the bridge would have sent this frame
            // there". Forwarded frames always carry a resolved unicast
            // dst MAC, so unicast_flood is the only flood control that
            // participates in the equivalence; require it on
            // (unreadable → refuse).
            let unicast_flood = std::fs::read_to_string(format!("{brport}/unicast_flood"))
                .map(|s| s.trim() == "1")
                .unwrap_or(false);
            // A VLAN member with a non-default egress-qos-map encodes
            // the mapped PCP into the tag it emits; the datapath's
            // vlan push writes PCP/DEI 0, so collapsing such a member
            // would silently flatten wire priority. The map is visible
            // in /proc/net/vlan/<member> ("EGRESS priority mappings:"
            // is empty by default) — require it empty. NotFound means
            // the member isn't a VLAN device at all, which is fine
            // (such members never match the VLAN join anyway); any
            // other read failure refuses.
            let egress_qos_default =
                match std::fs::read_to_string(format!("/proc/net/vlan/{member}")) {
                    Ok(content) => content
                        .lines()
                        .find(|l| l.contains("EGRESS priority mappings:"))
                        .map(|l| {
                            l.split("EGRESS priority mappings:")
                                .nth(1)
                                .unwrap_or("")
                                .trim()
                                .is_empty()
                        })
                        .unwrap_or(false),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => true,
                    Err(_) => false,
                };
            members.push((member, forwarding && unicast_flood && egress_qos_default));
        }
        out.push((name, members));
    }
    Ok(out)
}

/// Discover the currently collapsible bridge chains, or an empty list
/// when the directive disables the feature. VLAN-config NotFound means
/// no 8021q subifs exist, so no chain can terminate in one — empty.
/// Other IO errors propagate (same policy as the VLAN path: a broken
/// sysfs/procfs read must not silently produce "no entries" while the
/// gate bit logic runs on).
pub(crate) fn discover_bridge_chains(
    directives: &[ModuleDirective],
) -> std::io::Result<Vec<BridgeChain>> {
    if !bridge_resolve_enabled(directives) {
        return Ok(Vec::new());
    }
    let vlans = match read_vlan_config() {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    if vlans.is_empty() {
        return Ok(Vec::new());
    }
    let bridges = read_bridge_topology()?;
    let mut chains = bridge_vlan_chains(&bridges, &vlans);
    // Wire-equivalence also needs the MTU relation: the uncollapsed
    // path enforces the BRIDGE's MTU (a packet over it gets dropped /
    // PTB'd by the bridge layer, and the tc datapath's bpf_check_mtu
    // would test the bridge device). The short-circuit tests the
    // underlying device instead, so a bridge with a SMALLER MTU than
    // its underlying device would silently forward packets the bridge
    // would have refused. Require mtu(bridge) >= mtu(underlying);
    // anything else keeps the kernel path. Unreadable → refuse.
    chains.retain(|(bridge, phys, _)| {
        let mtu = |dev: &str| -> Option<u32> {
            std::fs::read_to_string(format!("/sys/class/net/{dev}/mtu"))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        match (mtu(bridge), mtu(phys)) {
            (Some(b), Some(p)) if b >= p => true,
            (Some(b), Some(p)) => {
                info!(
                    bridge = %bridge,
                    bridge_mtu = b,
                    underlying = %phys,
                    underlying_mtu = p,
                    "bridge egress short-circuit skipped: bridge MTU below underlying device"
                );
                false
            }
            _ => {
                warn!(bridge = %bridge, underlying = %phys, "bridge short-circuit skipped: MTU unreadable");
                false
            }
        }
    });
    Ok(chains)
}

/// Read-modify-write one `FpCfg.flags` bit on the live CFG map.
/// Same pattern as `apply_driver_quirks_cfg`'s head-shift OR: preserve
/// every other bit and field.
pub(crate) fn set_cfg_flag(ebpf: &mut Ebpf, bit: u8, on: bool) -> ModuleResult<()> {
    let map = ebpf
        .map_mut("CFG")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "CFG map missing from ELF"))?;
    let mut arr: Array<_, FpCfg> = Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG Array::try_from: {e}")))?;
    let mut cur: FpCfg = arr
        .get(&0, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG get: {e}")))?;
    if on {
        cur.flags |= bit;
    } else {
        cur.flags &= !bit;
    }
    arr.set(0, cur, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG set: {e}")))
}

/// Minimum mainline Linux version that ships the rvu-nicpf XDP fix
/// (commit 04f647c8e456). Kernels below this expose both the
/// xdp.data_hard_start offset bug (workaroundable via head-shift) AND
/// the `non_qos_queues` leak at XDP attach/detach (NOT workaroundable
/// from userspace). On such kernels we refuse native-mode attach on
/// rvu-nicpf ifaces unless the operator explicitly opts in via the
/// `driver-workaround rvu-nicpf-head-shift on` override.
const RVU_NICPF_FIXED_IN_KERNEL: (u32, u32) = (6, 8);

/// Kernel driver names that trigger the head-shift workaround.
/// `/sys/class/net/<iface>/device/driver` is a symlink into
/// `/sys/bus/pci/drivers/<module_name>`, for this driver the kernel
/// module is `rvu_nicpf.ko`, so the sysfs leaf is `rvu_nicpf` (with
/// an underscore). `ethtool -i` happens to print the pci_driver's
/// `name` field as `rvu-nicpf` (with a hyphen) on the reference
/// hardware, which had us matching the wrong spelling in v0.1.3
/// confirmed empirically via `readlink /sys/class/net/ethN/device/driver`
/// on 5.15.72-ui-cn9670. Accepting both spellings is cheap and keeps
/// us correct even if a distro one day canonicalises differently.
const RVU_NICPF_DRIVERS: &[&str] = &["rvu_nicpf", "rvu-nicpf"];

/// Layout mirror of `VlanResolve` in `bpf/src/maps.rs`. Hash-map value
/// that tells the BPF program "this subif ifindex really egresses on
/// phys_ifindex with a VID". `#[repr(C)]` + u32/u16/u16 packs to 8
/// bytes; every bit pattern is valid.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct VlanResolve {
    pub phys_ifindex: u32,
    pub vid: u16,
    pub _pad: u16,
}

// SAFETY: repr(C), all primitive fields, every bit pattern valid.
unsafe impl aya::Pod for VlanResolve {}

/// Layout mirror of `MssClampValue` in `bpf/src/maps.rs`. Value type
/// for the `MSS_CLAMP_V4` / `MSS_CLAMP_V6` LPM tries. `#[repr(C)]`
/// with explicit padding so the userspace and BPF layouts match
/// byte-for-byte (8 bytes total).
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MssClampValue {
    pub mss: u16,
    pub _pad: u16,
    /// Egress ifindex required for this rule. 0 = match any.
    pub iface_filter: u32,
}

// SAFETY: repr(C), all primitive fields, no internal padding leaks
// (u16/u16/u32 packs exactly into 8 bytes).
unsafe impl aya::Pod for MssClampValue {}

/// All state required to keep the attached program alive.
///
/// After `attach`, the XDP program, every §4.5 map, and each per-iface
/// link is pinned under `<bpffs-root>/fast-path/`. Dropping
/// `ActiveState` closes our userspace FDs but the bpffs inodes hold
/// the kernel references, SPEC.md §8.5 "exit without detach" works as
/// soon as pinning is in place. `Module::detach` unlinks the pins,
/// which is when the kernel actually tears everything down.
pub struct ActiveState {
    pub ebpf: Ebpf,
    pub links: Vec<LinkRecord>,
    pub state_dir: PathBuf,
    pub bpffs_root: PathBuf,
    /// Option F control plane, started in `attach` when
    /// `forwarding-mode` is `custom-fib` or `compare`. `None` in
    /// `kernel-fib` mode (which is the default and today's behavior).
    /// `detach` shuts it down cooperatively before tearing down pins.
    pub route_controller: Option<crate::fib::controller::RouteController>,
    /// `attach_settle_time` from the config, retained for use in
    /// `detach` so we can pace link-pin removals symmetrically with
    /// the attach path. Removing all link pins inside one STP
    /// reconvergence window has been observed to wedge the bridge
    /// stack on rvu-nicpf hardware (kernel panic, full reboot);
    /// this is the same class of bug §11.8 calls out for attach.
    pub attach_settle_time: std::time::Duration,
}

/// One XDP attach. `effective_mode` records what actually stuck in
/// `Auto` mode so `status` can report it. `link` is either:
///
/// - `Pinned(PinnedLink)`, the happy path; dropping closes the
///   userspace FD but leaves the bpffs inode, so the kernel attach
///   survives process exit (§8.5).
/// - `Transient(FdLink)`, pin syscall was rejected (e.g. EPERM on
///   generic-mode XDP links on some kernels). The attach still works,
///   but dropping the FdLink detaches the kernel-side XDP program.
///   SIGTERM will detach these interfaces; native-mode ones persist.
pub struct LinkRecord {
    pub iface: String,
    pub ifindex: u32,
    pub effective_mode: AttachMode,
    pub link: LinkHandle,
}

pub enum LinkHandle {
    Pinned(PinnedLink),
    Transient(FdLink),
    /// tc datapath (Phase T): a netlink cls_bpf filter on the iface's
    /// clsact ingress. No FD is held — the aya link was deliberately
    /// forgotten after reading the kernel-assigned identifiers (a held
    /// link would detach on Drop), so the kernel attach has qdisc
    /// lifetime and survives process exit, like `Pinned`. Teardown
    /// reconstructs the filter from `(priority, handle)` via
    /// `SchedClassifierLink::attached()`; the same pair is persisted
    /// in `<state-dir>/tc-links.json` for out-of-process `detach`.
    Tc {
        priority: u16,
        handle: u32,
    },
}

impl LinkHandle {
    pub fn is_pinned(&self) -> bool {
        matches!(self, LinkHandle::Pinned(_))
    }

    /// Whether the kernel-side attach outlives this process (bpffs pin
    /// for XDP, qdisc-lifetime filter for tc).
    pub fn persists_across_exit(&self) -> bool {
        matches!(self, LinkHandle::Pinned(_) | LinkHandle::Tc { .. })
    }
}

pub fn load(cfg: &ModuleConfig<'_>, ctx: &LoaderCtx<'_>) -> ModuleResult<ActiveState> {
    if !FAST_PATH_BPF_AVAILABLE {
        return Err(ModuleError::other(
            MODULE_NAME,
            "no BPF ELF embedded in the binary, build with rustup + nightly + bpf-linker (see CLAUDE.md)",
        ));
    }

    // Refuse startup when pins from a prior invocation survive.
    // SPEC.md §8.5 "exit without detach" leaves pins in bpffs after
    // SIGTERM; v0.1 does not adopt those, operator must run
    // `packetframe detach --all` first. Full adoption (zero-disruption
    // restart) is deferred.
    if pin::has_existing_pins(ctx.bpffs_root) {
        return Err(ModuleError::other(
            MODULE_NAME,
            format!(
                "existing pins under {} from a prior invocation, \
                 run `packetframe detach --all` before restarting \
                 (v0.1 does not yet adopt in-place)",
                pin::module_root(ctx.bpffs_root).display()
            ),
        ));
    }

    pin::ensure_dirs(ctx.bpffs_root)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("create bpffs pin dirs: {e}")))?;

    // aya doesn't expose an `Ebpf::load_with_options` that'd let us
    // skip BTF lookup; on the reference EFG (§2.2) BTF is absent but
    // aya handles that path internally. Use an aligned copy, the
    // embedded `include_bytes!` slice is 1-byte-aligned which the
    // object crate's ELF parser rejects.
    let bytes = aligned_bpf_copy();
    let mut ebpf = Ebpf::load(&bytes)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("aya::Ebpf::load failed: {e}")))?;

    populate_cfg(&mut ebpf, cfg)?;
    populate_allowlists(&mut ebpf, cfg)?;
    populate_blocklists(&mut ebpf, cfg)?;
    populate_mss_clamp(&mut ebpf, cfg)?;
    populate_fib_config(&mut ebpf, cfg)?;

    Ok(ActiveState {
        ebpf,
        links: Vec::new(),
        state_dir: ctx.state_dir.to_path_buf(),
        bpffs_root: ctx.bpffs_root.to_path_buf(),
        route_controller: None,
        attach_settle_time: cfg.global.attach_settle_time,
    })
}

/// Translate a [`ForwardingMode`](packetframe_common::config::ForwardingMode)
/// into the bits-3-4 portion of `FpCfg.flags`. Shared between
/// `populate_cfg` (initial load) and `reconcile::reconcile_cfg`
/// (SIGHUP) so both agree on the mode→bit mapping.
///
/// Invariant: `Compare` sets both bits. The BPF program's compare
/// branch assumes bit 3 is set when bit 4 is; never emit bit 4 alone.
pub(crate) fn fib_flags_from_forwarding_mode(
    mode: packetframe_common::config::ForwardingMode,
) -> u8 {
    use packetframe_common::config::ForwardingMode;
    match mode {
        ForwardingMode::KernelFib => 0,
        ForwardingMode::CustomFib => FP_CFG_FLAG_CUSTOM_FIB,
        ForwardingMode::Compare => FP_CFG_FLAG_CUSTOM_FIB | FP_CFG_FLAG_COMPARE_MODE,
    }
}

fn populate_cfg(ebpf: &mut Ebpf, mcfg: &ModuleConfig<'_>) -> ModuleResult<()> {
    let dry_run = mcfg
        .section
        .directives
        .iter()
        .find_map(|d| match d {
            ModuleDirective::DryRun(v) => Some(*v),
            _ => None,
        })
        .unwrap_or(false);

    // Option F forwarding-mode → CFG flag bits 3-4. See
    // fib_flags_from_forwarding_mode for the mapping.
    let forwarding = mcfg
        .section
        .directives
        .iter()
        .find_map(|d| match d {
            ModuleDirective::ForwardingMode(m) => Some(*m),
            _ => None,
        })
        .unwrap_or_default();
    let fib_flags = fib_flags_from_forwarding_mode(forwarding);

    // Global mss-clamp value from `mss-clamp <mtu>` (no prefix, no
    // iface). Per-prefix and per-iface clamps live in their own maps
    // populated by `populate_mss_clamp` and take precedence over this
    // CFG fallback. 0 = unset.
    let mss_clamp_global = mss_clamp_global_value(&mcfg.section.directives).unwrap_or(0);

    let fp_cfg = FpCfg {
        dry_run: u8::from(dry_run),
        // bits 0-1: IPv4/IPv6 enabled (historical, load-bearing for
        // dashboards). bits 3-4: custom-FIB / compare (Option F).
        // bits 5-7: feature-presence gates (block / vlan / mss-clamp).
        // bit 2 (HEAD_SHIFT_128) is OR'd on later in
        // apply_driver_quirks_cfg for rvu-nicpf attaches.
        // The VLAN/bridge presence input is an initial seed only:
        // `populate_vlan_resolve` re-asserts the bit after it actually
        // inserts entries (subifs and bridge chains share bit 6).
        // `discover_bridge_chains` errors count as "none" here for the
        // same reason a vlan read error does in `vlan_subifs_present` —
        // the authoritative pass in populate_vlan_resolve fails loud.
        flags: 0b11
            | fib_flags
            | feature_flags_from_config(
                &mcfg.section.directives,
                vlan_subifs_present()
                    || discover_bridge_chains(&mcfg.section.directives)
                        .map(|c| !c.is_empty())
                        .unwrap_or(false),
            ),
        mss_clamp_global,
        version: FP_CFG_VERSION_V2,
    };

    let map = ebpf
        .map_mut("CFG")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "CFG map missing from ELF"))?;
    let mut cfg_arr: Array<_, FpCfg> = Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG map Array::try_from: {e}")))?;

    cfg_arr
        .set(0, fp_cfg, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG map set: {e}")))?;

    info!(dry_run, forwarding = ?forwarding, "fast-path cfg populated");
    Ok(())
}

/// Populate the `FIB_CONFIG` map with the parsed `ecmp-default-hash-mode`
/// directive (default: 5-tuple). Always runs regardless of forwarding
/// mode so the XDP program reads consistent config even if an
/// operator flips to `custom-fib` via `packetframe reconfigure`
/// later. Fail-soft: if the map is missing from the ELF (older build
/// during development), log and continue, the BPF program reads the
/// map defensively and falls back to built-in defaults.
fn populate_fib_config(ebpf: &mut Ebpf, mcfg: &ModuleConfig<'_>) -> ModuleResult<()> {
    let hash_mode = mcfg
        .section
        .directives
        .iter()
        .find_map(|d| match d {
            ModuleDirective::EcmpDefaultHashMode(m) => Some(m.as_wire()),
            _ => None,
        })
        .unwrap_or(crate::fib::types::FpFibCfg::DEFAULT_HASH_MODE);

    let fib_cfg = crate::fib::types::FpFibCfg {
        default_hash_mode: hash_mode,
        _pad: [0; 3],
        version: crate::fib::types::FpFibCfg::VERSION_V1,
    };

    let map = match ebpf.map_mut("FIB_CONFIG") {
        Some(m) => m,
        None => {
            info!("FIB_CONFIG map missing from ELF, skipping (older build?)");
            return Ok(());
        }
    };
    let mut arr: Array<_, crate::fib::types::FpFibCfg> = Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("FIB_CONFIG Array::try_from: {e}")))?;
    arr.set(0, fib_cfg, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("FIB_CONFIG set: {e}")))?;
    info!(hash_mode, "FIB_CONFIG populated");
    Ok(())
}

fn populate_allowlists(ebpf: &mut Ebpf, mcfg: &ModuleConfig<'_>) -> ModuleResult<()> {
    let (v4_prefixes, v6_prefixes): (Vec<Ipv4Prefix>, Vec<Ipv6Prefix>) = {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for d in &mcfg.section.directives {
            match d {
                ModuleDirective::AllowPrefix4(p) => v4.push(*p),
                ModuleDirective::AllowPrefix6(p) => v6.push(*p),
                _ => {}
            }
        }
        (v4, v6)
    };

    if !v4_prefixes.is_empty() {
        let map = ebpf
            .map_mut("ALLOW_V4")
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "ALLOW_V4 map missing from ELF"))?;
        let mut trie: LpmTrie<_, [u8; 4], u8> = LpmTrie::try_from(map).map_err(|e| {
            ModuleError::other(MODULE_NAME, format!("ALLOW_V4 LpmTrie::try_from: {e}"))
        })?;
        for p in &v4_prefixes {
            let key = LpmKey::new(u32::from(p.prefix_len), p.addr.octets());
            trie.insert(&key, 1u8, 0).map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("ALLOW_V4 insert {}/{}: {e}", p.addr, p.prefix_len),
                )
            })?;
        }
    }

    if !v6_prefixes.is_empty() {
        let map = ebpf
            .map_mut("ALLOW_V6")
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "ALLOW_V6 map missing from ELF"))?;
        let mut trie: LpmTrie<_, [u8; 16], u8> = LpmTrie::try_from(map).map_err(|e| {
            ModuleError::other(MODULE_NAME, format!("ALLOW_V6 LpmTrie::try_from: {e}"))
        })?;
        for p in &v6_prefixes {
            let key = LpmKey::new(u32::from(p.prefix_len), p.addr.octets());
            trie.insert(&key, 1u8, 0).map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("ALLOW_V6 insert {}/{}: {e}", p.addr, p.prefix_len),
                )
            })?;
        }
    }

    info!(
        v4_count = v4_prefixes.len(),
        v6_count = v6_prefixes.len(),
        "allowlists populated"
    );
    Ok(())
}

/// v0.2.1 issue #33: populate `BLOCK_V4` (and `BLOCK_V6`, currently
/// always empty since IPv6 bogon-block has no commonly-blocked range
/// equivalent to RFC 1918) from the operator's `block-prefix`
/// directives. Empty list is a no-op (the BPF trie stays empty,
/// LPM lookup misses cheaply, no per-packet overhead).
fn populate_blocklists(ebpf: &mut Ebpf, mcfg: &ModuleConfig<'_>) -> ModuleResult<()> {
    let v4_blocks: Vec<Ipv4Prefix> = mcfg
        .section
        .directives
        .iter()
        .filter_map(|d| match d {
            ModuleDirective::BlockPrefix { cidr, .. } => Some(*cidr),
            _ => None,
        })
        .collect();
    if v4_blocks.is_empty() {
        return Ok(());
    }
    // Sanity-guard: refuse to start if a block-prefix overlaps an
    // allow-prefix or local-prefix. Operator config bug, they almost
    // certainly didn't mean to block traffic to their own customer
    // /24.
    let allow_v4: Vec<Ipv4Prefix> = mcfg
        .section
        .directives
        .iter()
        .filter_map(|d| match d {
            ModuleDirective::AllowPrefix4(p) => Some(*p),
            _ => None,
        })
        .collect();
    // v4-only by construction: the grammar has no `block-prefix6`, so
    // `BLOCK_V6` is always empty and a `local-prefix6` has nothing to
    // overlap against. TODO: if `block-prefix6` is ever added, this
    // check must grow a v6 arm considering `LocalPrefix6` and
    // `AllowPrefix6`, or v6 declarations will be silently unprotected.
    let local_v4: Vec<Ipv4Prefix> = mcfg
        .section
        .directives
        .iter()
        .filter_map(|d| match d {
            ModuleDirective::LocalPrefix { cidr, .. } => Some(*cidr),
            _ => None,
        })
        .collect();
    for b in &v4_blocks {
        for a in allow_v4.iter().chain(local_v4.iter()) {
            if prefix_contains(b, a) || prefix_contains(a, b) {
                return Err(ModuleError::other(
                    MODULE_NAME,
                    format!(
                        "block-prefix {}/{} overlaps with allow-prefix or local-prefix \
                         {}/{}, refusing to start (operator config bug; would silently \
                         drop traffic to declared customer prefixes)",
                        b.addr, b.prefix_len, a.addr, a.prefix_len
                    ),
                ));
            }
        }
    }

    let map = ebpf
        .map_mut("BLOCK_V4")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "BLOCK_V4 map missing from ELF"))?;
    let mut trie: LpmTrie<_, [u8; 4], u8> = LpmTrie::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("BLOCK_V4 LpmTrie::try_from: {e}")))?;
    for p in &v4_blocks {
        let key = LpmKey::new(u32::from(p.prefix_len), p.addr.octets());
        trie.insert(&key, 1u8, 0).map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("BLOCK_V4 insert {}/{}: {e}", p.addr, p.prefix_len),
            )
        })?;
    }
    info!(
        v4_count = v4_blocks.len(),
        "v0.2.1 block-prefix bogon list populated"
    );
    Ok(())
}

/// True iff `outer` contains `inner` (inner's network is in outer
/// AND inner's prefix_len is >= outer's). Used to detect overlap
/// between block-prefix and allow-/local-prefix at startup.
///
/// Delegates to the shared helper so the mask arithmetic (and its
/// shift-overflow guards) has one implementation.
fn prefix_contains(outer: &Ipv4Prefix, inner: &Ipv4Prefix) -> bool {
    outer.contains_prefix(inner)
}

/// Read `net.<family>.neigh.default.gc_thresh3` from procfs. `None` on
/// any read/parse failure — the caller's check is advisory, so a
/// missing sysctl (containers, exotic kernels) must not block startup.
fn read_gc_thresh3(family: &str) -> Option<u64> {
    std::fs::read_to_string(format!("/proc/sys/net/{family}/neigh/default/gc_thresh3"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Startup capacity warning for the connected fast-path: the kernel's
/// neighbour tables are the feed for local-prefix host routes, and each
/// live neighbour inside a declared prefix consumes one slot in the
/// shared `NEXTHOPS` pool (nexthop == destination, so no sharing).
///
/// On default sysctls (`gc_thresh3` = 1024 per family) the kernel caps
/// the feed well below the pool and this never fires. Routers commonly
/// raise `gc_thresh3`, though — and that moves the ceiling invisibly.
/// Comparing the summed thresholds against the pool turns that cliff
/// into a config-time diagnostic instead of a runtime surprise where
/// dense segments starve BGP nexthops (`ProgrammerError::Full`).
fn gc_thresh3_capacity_warning(v4: Option<u64>, v6: Option<u64>, cap: u32) -> Option<String> {
    let total = v4.unwrap_or(0) + v6.unwrap_or(0);
    if total <= u64::from(cap) {
        return None;
    }
    Some(format!(
        "kernel neighbour tables can hold {total} entries \
         (net.ipv4/ipv6.neigh.default.gc_thresh3 = {} + {}), more than the shared \
         NEXTHOPS pool ({cap}). Each neighbour inside a local-prefix consumes one \
         slot, so dense segments can exhaust the pool and starve BGP nexthops; \
         affected routes fall to the kernel slow path. See \
         docs/runbooks/custom-fib.md (capacity considerations)",
        v4.unwrap_or(0),
        v6.unwrap_or(0),
    ))
}

/// Extract the global `mss-clamp <mtu>` directive (the form with no
/// prefix and no `via <iface>` qualifier). Returns the MSS value or
/// `None` if no such directive exists. Shared between `populate_cfg`
/// (initial load) and `reconcile::reconcile_cfg` (SIGHUP) so both
/// agree on which directive is "the global one." v0.2.4+.
pub(crate) fn mss_clamp_global_value(directives: &[ModuleDirective]) -> Option<u16> {
    directives.iter().find_map(|d| match d {
        ModuleDirective::MssClamp {
            prefix: None,
            iface: None,
            mss,
            ..
        } => Some(*mss),
        _ => None,
    })
}

/// Populate `MSS_CLAMP_V4`, `MSS_CLAMP_V6`, and `MSS_CLAMP_BY_IFACE`
/// from any `mss-clamp` directives in the module config. The global
/// (`mss-clamp <mtu>`) form is handled in `populate_cfg` via the
/// `FpCfg.mss_clamp_global` field; this function handles the three
/// scoped forms, per-prefix, per-iface, and per-prefix-+-iface.
/// Empty / no directives → all maps stay empty (LPM lookups miss
/// cheaply, no per-packet overhead).
fn populate_mss_clamp(ebpf: &mut Ebpf, mcfg: &ModuleConfig<'_>) -> ModuleResult<()> {
    use packetframe_common::config::MssClampPrefix;

    // Collect (prefix, iface_filter, mss) triples, splitting by family.
    let mut v4_entries: Vec<([u8; 4], u8, u32, u16)> = Vec::new();
    let mut v6_entries: Vec<([u8; 16], u8, u32, u16)> = Vec::new();
    let mut iface_entries: Vec<(String, u16)> = Vec::new();

    for d in &mcfg.section.directives {
        let ModuleDirective::MssClamp {
            prefix,
            iface,
            mss,
            line,
        } = d
        else {
            continue;
        };
        // Resolve `via <iface>` to ifindex if present. Missing ifaces
        // are fatal at load, the operator declared a clamp on an
        // iface that doesn't exist, which is almost certainly a typo.
        let iface_filter: u32 = match iface {
            Some(name) => if_nametoindex(name).map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("mss-clamp at line {line}: iface `{name}` lookup failed: {e}",),
                )
            })?,
            None => 0,
        };
        match (prefix, iface) {
            (Some(MssClampPrefix::V4(p)), _) => {
                v4_entries.push((p.addr.octets(), p.prefix_len, iface_filter, *mss));
            }
            (Some(MssClampPrefix::V6(p)), _) => {
                v6_entries.push((p.addr.octets(), p.prefix_len, iface_filter, *mss));
            }
            (None, Some(name)) => {
                iface_entries.push((name.clone(), *mss));
            }
            (None, None) => {
                // Global, handled by populate_cfg; skip here.
            }
        }
    }

    // IPv4 LPM trie.
    if !v4_entries.is_empty() {
        let map = ebpf
            .map_mut("MSS_CLAMP_V4")
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "MSS_CLAMP_V4 map missing from ELF"))?;
        let mut trie: LpmTrie<_, [u8; 4], MssClampValue> = LpmTrie::try_from(map)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("MSS_CLAMP_V4 try_from: {e}")))?;
        for (addr, plen, iface_filter, mss) in &v4_entries {
            let key = LpmKey::new(u32::from(*plen), *addr);
            let value = MssClampValue {
                mss: *mss,
                _pad: 0,
                iface_filter: *iface_filter,
            };
            trie.insert(&key, value, 0).map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!(
                        "MSS_CLAMP_V4 insert {}/{}: {e}",
                        std::net::Ipv4Addr::from(*addr),
                        plen
                    ),
                )
            })?;
        }
    }

    // IPv6 LPM trie.
    if !v6_entries.is_empty() {
        let map = ebpf
            .map_mut("MSS_CLAMP_V6")
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "MSS_CLAMP_V6 map missing from ELF"))?;
        let mut trie: LpmTrie<_, [u8; 16], MssClampValue> = LpmTrie::try_from(map)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("MSS_CLAMP_V6 try_from: {e}")))?;
        for (addr, plen, iface_filter, mss) in &v6_entries {
            let key = LpmKey::new(u32::from(*plen), *addr);
            let value = MssClampValue {
                mss: *mss,
                _pad: 0,
                iface_filter: *iface_filter,
            };
            trie.insert(&key, value, 0).map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!(
                        "MSS_CLAMP_V6 insert {}/{}: {e}",
                        std::net::Ipv6Addr::from(*addr),
                        plen
                    ),
                )
            })?;
        }
    }

    // Per-iface table.
    if !iface_entries.is_empty() {
        let map = ebpf.map_mut("MSS_CLAMP_BY_IFACE").ok_or_else(|| {
            ModuleError::other(MODULE_NAME, "MSS_CLAMP_BY_IFACE map missing from ELF")
        })?;
        let mut hm: AyaHashMap<_, u32, u16> = AyaHashMap::try_from(map).map_err(|e| {
            ModuleError::other(MODULE_NAME, format!("MSS_CLAMP_BY_IFACE try_from: {e}"))
        })?;
        for (name, mss) in &iface_entries {
            let ifindex = if_nametoindex(name).map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("mss-clamp via {name}: ifindex lookup failed: {e}"),
                )
            })?;
            hm.insert(ifindex, mss, 0).map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("MSS_CLAMP_BY_IFACE insert {name}({ifindex}): {e}"),
                )
            })?;
        }
    }

    if !v4_entries.is_empty() || !v6_entries.is_empty() || !iface_entries.is_empty() {
        info!(
            v4_count = v4_entries.len(),
            v6_count = v6_entries.len(),
            iface_count = iface_entries.len(),
            "mss-clamp policy populated"
        );
    }
    Ok(())
}

pub fn attach(state: &mut ActiveState, cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
    // v0.2.5: load `finalize` first so its FD is available for the
    // MUTATION_PROGS[0] population below. Order matters: fast_path's
    // tail_call into MUTATION_PROGS[0] must succeed on every packet
    // from the moment fast_path is attached, so finalize has to be
    // loaded + populated *before* the per-iface attach loop below.
    {
        let finalize_prog: &mut Xdp = state
            .ebpf
            .program_mut(pin::FINALIZE_PROGRAM_NAME)
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "finalize program missing from ELF"))?
            .try_into()
            .map_err(|e| {
                ModuleError::other(MODULE_NAME, format!("finalize program not XDP: {e}"))
            })?;
        finalize_prog.load().map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("Xdp::load(finalize) failed (verifier rejection?): {e}"),
            )
        })?;
    }
    populate_mutation_progs(&mut state.ebpf)?;

    let prog: &mut Xdp = state
        .ebpf
        .program_mut("fast_path")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "fast_path program missing from ELF"))?
        .try_into()
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("fast_path program not XDP: {e}")))?;

    prog.load().map_err(|e| {
        ModuleError::other(
            MODULE_NAME,
            format!("Xdp::load failed (verifier rejection?): {e}"),
        )
    })?;

    let prog_id = prog.info().map(|i| i.id()).unwrap_or(0);

    // Collect attach directives up-front so we can populate redirect_devmap
    // with every ifindex in scope before any packet flows.
    let attach_dirs: Vec<(String, AttachMode, u32)> = cfg
        .section
        .directives
        .iter()
        .filter_map(|d| match d {
            ModuleDirective::Attach { iface, mode, line } => Some((iface, *mode, *line)),
            _ => None,
        })
        .map(|(iface, mode, _line)| {
            let ifindex = if_nametoindex(iface)?;
            Ok::<_, ModuleError>((iface.clone(), mode, ifindex))
        })
        .collect::<Result<_, _>>()?;

    warn_shared_bridge_masters(
        &attach_dirs
            .iter()
            .map(|(i, _, _)| i.as_str())
            .collect::<Vec<_>>(),
        cfg.global.attach_settle_time,
    );

    // Version-gate native-mode attach on rvu-nicpf kernels that lack
    // the upstream fix (commit 04f647c8e456, Linux v6.8). That commit
    // fixes two bugs in one patch: (1) the xdp.data_hard_start offset
    // bug that v0.1.3 worked around via head-shift; (2) a
    // `non_qos_queues` leak at `otx2_xdp_setup` that is *not* fixable
    // from userspace, every native XDP attach leaks the count, and
    // after enough attach/detach cycles the driver's queue sizing
    // drifts and the page allocator's freelist gets a NULL write,
    // producing the `get_page_from_freelist` NULL deref crash signature
    // seen on edge1-mci1-net 2026-04-22 (SPEC §11.1(c)). This
    // preprocessor runs *before* `try_attach_with_fallback` so we
    // don't leak even once.
    //
    // `driver-workaround rvu-nicpf-head-shift = on` bypasses the
    // check: operator takes responsibility. `= off` bypasses both
    // the version check and the head-shift workaround, for operators
    // who have backported the fix into a kernel whose uname still
    // reports pre-v6.8.
    let attach_dirs = rvu_nicpf_version_gate(attach_dirs, cfg)?;

    // Attach each interface with trial-attach per §2.3: Auto → try
    // native first, fall back to generic on error; explicit Native or
    // Generic uses the requested mode directly (no fallback). Each
    // attach tries to pin its link under
    // `<bpffs-root>/fast-path/links/<iface>` so the kernel attach
    // survives process exit (§8.5). If pinning is kernel-rejected
    // (e.g. EPERM on some kernels for generic-XDP links) the attach
    // still succeeds but that specific link won't outlive the process.
    //
    // SPEC.md §11.8, XDP attach on some drivers (rvu-nicpf observed)
    // briefly bounces the link. If multiple attach ifaces share a
    // bridge master, attaching them inside one STP reconvergence
    // window risks an L2 loop and packet storm. Sleep
    // `attach_settle_time` between attaches so each link stabilizes
    // before the next touches the driver. 0s disables (useful on
    // non-bridge topologies).
    // Split tc-datapath attaches from the XDP ones: they use a
    // different program pair, a different attach mechanism (netlink
    // cls_bpf on clsact), and must run after the XDP loop because
    // `prog` mutably borrows `state.ebpf` until its last use here.
    let (tc_dirs, xdp_dirs): (Vec<_>, Vec<_>) = attach_dirs
        .into_iter()
        .partition(|(_, mode, _)| matches!(mode, AttachMode::Tc));

    // The tc datapath is custom-fib only (the classifiers have no
    // kernel-FIB arm; see bpf/src/tc.rs). Reject the pairing up front
    // rather than silently passing all matched traffic to the kernel.
    if !tc_dirs.is_empty()
        && !matches!(
            forwarding_mode_from_cfg(cfg),
            packetframe_common::config::ForwardingMode::CustomFib
        )
    {
        return Err(ModuleError::other(
            MODULE_NAME,
            "`attach <iface> tc` requires `forwarding-mode custom-fib` \
             (the tc datapath has no kernel-fib/compare arm)",
        ));
    }

    let settle_time = cfg.global.attach_settle_time;
    let mut attach_count = 0usize;
    for (iface, mode, ifindex) in xdp_dirs.iter() {
        if attach_count > 0 && !settle_time.is_zero() {
            info!(
                settle_secs = settle_time.as_secs_f64(),
                next_iface = %iface,
                "waiting for link to settle before next attach (§11.8)"
            );
            std::thread::sleep(settle_time);
        }
        attach_count += 1;
        let (effective_mode, link) =
            try_attach_with_fallback(prog, *ifindex, iface, *mode, &state.bpffs_root)?;
        let persist = link.persists_across_exit();
        state.links.push(LinkRecord {
            iface: iface.clone(),
            ifindex: *ifindex,
            effective_mode,
            link,
        });
        info!(
            iface,
            ifindex,
            ?effective_mode,
            persists_across_exit = persist,
            "fast-path attached"
        );
    }

    // tc-datapath attaches. Load + wire the classifier pair first so
    // tc_fast_path's tail_call into TC_MUTATION_PROGS[0] succeeds from
    // the first packet (same ordering contract as finalize above);
    // aya loads programs lazily, so XDP-only deployments never pay
    // for the classifiers.
    if !tc_dirs.is_empty() {
        load_tc_programs(&mut state.ebpf)?;
        populate_tc_mutation_progs(&mut state.ebpf)?;

        let mut tc_records = Vec::with_capacity(tc_dirs.len());
        for (iface, _mode, ifindex) in tc_dirs.iter() {
            if attach_count > 0 && !settle_time.is_zero() {
                info!(
                    settle_secs = settle_time.as_secs_f64(),
                    next_iface = %iface,
                    "waiting for link to settle before next attach (§11.8)"
                );
                std::thread::sleep(settle_time);
            }
            attach_count += 1;
            let (priority, handle) = tc_attach_iface(&mut state.ebpf, iface)?;
            tc_records.push(crate::tc_links::TcLinkRecord {
                iface: iface.clone(),
                priority,
                handle,
            });
            // Persist IMMEDIATELY, not after the loop: the aya link
            // for this filter is already forgotten, so if a later
            // attach in this loop fails and aborts startup, this
            // record is the ONLY way `packetframe detach` can find
            // the live filter. A post-loop save would strand every
            // earlier filter as an invisible orphan (review finding,
            // PR #75).
            crate::tc_links::save(
                &state.state_dir,
                &crate::tc_links::TcLinksFile {
                    links: tc_records.clone(),
                },
            )
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc-links.json save: {e}")))?;
            state.links.push(LinkRecord {
                iface: iface.clone(),
                ifindex: *ifindex,
                effective_mode: AttachMode::Tc,
                link: LinkHandle::Tc { priority, handle },
            });
            info!(
                iface,
                ifindex,
                priority,
                handle,
                persists_across_exit = true,
                "fast-path attached (tc-ingress datapath)"
            );
        }
    }

    // Detect buggy-kernel rvu-nicpf native XDP delivery and flip the
    // head-shift bit in FpCfg so the BPF program applies the
    // `bpf_xdp_adjust_head(+128)` + `bpf_xdp_adjust_tail(+128)`
    // workaround (SPEC §11.1(c)). Runs *after* attach so we have the
    // effective mode (auto-native-fallback-to-generic resolved) and
    // can scope the flag only to actually-native attaches.
    apply_driver_quirks_cfg(state, cfg)?;

    // Populate redirect_devmap with every attach-scope ifindex so the
    // defensive devmap pre-check in the BPF program (§4.4 step 9d)
    // recognizes them as valid redirect targets. The value ifindex
    // matches the key ifindex for a simple "redirect back to the
    // physical port the FIB resolved to", aya accepts this.
    let devmap_map = state
        .ebpf
        .map_mut("REDIRECT_DEVMAP")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "REDIRECT_DEVMAP map missing from ELF"))?;
    let mut devmap: DevMapHash<_> = DevMapHash::try_from(devmap_map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("REDIRECT_DEVMAP try_from: {e}")))?;

    // Populate REDIRECT_DEVMAP with every UP Ethernet-type iface on the
    // host, not just the attach ifaces. The FIB lookup is dynamic, on
    // a BGP edge, routes change and the egress iface for any given
    // packet is determined at lookup time. Hardcoding the attach list
    // as the egress allowlist breaks any topology where ingress ≠
    // egress (classic edge router: trunks in, WAN out).
    //
    // Filter: `/sys/class/net/<iface>/type == 1` (ARPHRD_ETHER, covers
    // physical NICs, bridges, VLAN subifs, veth) AND operstate is `up`
    // or `unknown` (some virtual ifaces never report operstate). Skip
    // loopback (type 772) + tunnels (various non-1 types).
    let targets = enumerate_redirect_targets();
    let mut inserted = 0usize;
    for (iface, ifindex) in &targets {
        if let Err(e) = devmap.insert(*ifindex, *ifindex, None, 0) {
            warn!(iface = %iface, ifindex, error = %e, "REDIRECT_DEVMAP insert skipped");
            continue;
        }
        inserted += 1;
    }
    info!(
        count = inserted,
        "REDIRECT_DEVMAP populated from /sys/class/net (Ethernet-type, UP)"
    );

    // Mirror the same membership into TC_REDIRECT_TARGETS (Phase T).
    // Devmap types are XDP-only, so the tc datapath's pristine-packet
    // pre-check consults this plain hash map instead. Populated
    // unconditionally — it's a handful of entries and keeps reconcile
    // symmetric whether or not any `attach <iface> tc` exists yet.
    {
        let map = state.ebpf.map_mut("TC_REDIRECT_TARGETS").ok_or_else(|| {
            ModuleError::other(MODULE_NAME, "TC_REDIRECT_TARGETS map missing from ELF")
        })?;
        let mut hm: AyaHashMap<_, u32, u32> = AyaHashMap::try_from(map).map_err(|e| {
            ModuleError::other(MODULE_NAME, format!("TC_REDIRECT_TARGETS try_from: {e}"))
        })?;
        for (iface, ifindex) in &targets {
            if let Err(e) = hm.insert(*ifindex, *ifindex, 0) {
                warn!(iface = %iface, ifindex, error = %e, "TC_REDIRECT_TARGETS insert skipped");
            }
        }
    }

    populate_vlan_resolve(state, &cfg.section.directives)?;

    // Pin program + every §4.5 map so `packetframe status` can read
    // counters from a separate process and `packetframe detach` can
    // find what to tear down. Pinning happens after population so a
    // partial-load failure (above) doesn't leave half-initialized maps
    // in bpffs.
    pin_program_and_maps(state)?;

    // Start Option F's RouteController if the operator asked for the
    // custom FIB path. Uses `MapData::from_pin` internally, so it
    // must run after `pin_program_and_maps`. Kernel-fib mode skips
    // this entirely and pays nothing for the feature.
    let forwarding = forwarding_mode_from_cfg(cfg);
    if matches!(
        forwarding,
        packetframe_common::config::ForwardingMode::CustomFib
            | packetframe_common::config::ForwardingMode::Compare
    ) {
        // Translate the operator's `route-source ...` directive into
        // a `RouteSourceConfig` for the controller. None → controller
        // runs without a feed (test harness or pre-production smoke
        // test with manual programmer calls).
        let route_source = cfg.section.directives.iter().find_map(|d| match d {
            ModuleDirective::RouteSource(packetframe_common::config::RouteSourceSpec::Bmp {
                addr,
                port,
                require_loc_rib,
                peer_from,
                // `allow_remote` is informational here, the config
                // parser already rejected the unsafe shape (non-loopback
                // bind without opt-in), so by the time we see the spec
                // the `peer_from` ACL is either non-empty or the listen
                // is loopback.
                allow_remote: _,
            }) => format!("{addr}:{port}")
                .parse::<std::net::SocketAddr>()
                .ok()
                .map(|listen| crate::fib::controller::RouteSourceConfig::Bmp {
                    listen,
                    require_loc_rib: *require_loc_rib,
                    peer_acl: peer_from.clone(),
                }),
            ModuleDirective::RouteSource(packetframe_common::config::RouteSourceSpec::Bgp {
                addr,
                port,
                local_as,
                peer_as,
                router_id,
                peer_from,
                peer_ip,
                allow_remote: _,
            }) => {
                let listen: std::net::SocketAddr = format!("{addr}:{port}").parse().ok()?;
                // Default router-id: lowest 32 bits of the listen
                // address when v4; for v6 listens, fall back to the
                // local_as (uniquely identifies this speaker within
                // the AS).
                let rid = router_id.unwrap_or_else(|| match listen.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    std::net::IpAddr::V6(_) => std::net::Ipv4Addr::from(*local_as),
                });
                Some(crate::fib::controller::RouteSourceConfig::Bgp {
                    listen,
                    local_as: *local_as,
                    peer_as: *peer_as,
                    router_id: rid,
                    peer_acl: peer_from.clone(),
                    expected_peer_ip: *peer_ip,
                })
            }
            _ => None,
        });
        // v0.2.1: collect operator-declared `local-prefix` directives
        // and pass them to the controller. Empty list = feature off
        // (back-compat with v0.2.0 configs that never had this).
        //
        // Both families land in one list; the resolver's spec type is
        // IpAddr-based so its emission path handles them uniformly.
        let local_prefixes: Vec<crate::fib::netlink_neigh::LocalPrefixSpec> = cfg
            .section
            .directives
            .iter()
            .filter_map(|d| match d {
                ModuleDirective::LocalPrefix {
                    cidr,
                    iface,
                    arp_scavenge,
                    ..
                } => Some(crate::fib::netlink_neigh::LocalPrefixSpec {
                    addr: IpAddr::V4(cidr.addr),
                    prefix_len: cidr.prefix_len,
                    iface: iface.clone(),
                    arp_scavenge: *arp_scavenge,
                }),
                ModuleDirective::LocalPrefix6 { cidr, iface, .. } => {
                    Some(crate::fib::netlink_neigh::LocalPrefixSpec {
                        addr: IpAddr::V6(cidr.addr),
                        prefix_len: cidr.prefix_len,
                        iface: iface.clone(),
                        // No v6 scavenge; parse-enforced.
                        arp_scavenge: false,
                    })
                }
                _ => None,
            })
            .collect();
        if !local_prefixes.is_empty() {
            let v6_count = local_prefixes.iter().filter(|s| s.addr.is_ipv6()).count();
            info!(
                v4_count = local_prefixes.len() - v6_count,
                v6_count, "local-prefix connected fast-path enabled"
            );
            // Advisory startup checks for the two ways this feature
            // silently no-ops or over-commits. Warn-only: an operator
            // may stage config deliberately, and neither condition can
            // corrupt anything.
            for w in uncovered_local_prefix_warnings(&cfg.section.directives) {
                warn!("{w}");
            }
            if let Some(w) = gc_thresh3_capacity_warning(
                read_gc_thresh3("ipv4"),
                read_gc_thresh3("ipv6"),
                crate::fib::programmer::NEXTHOPS_CAP,
            ) {
                warn!("{w}");
            }
        }
        // v0.2.1 issue #31: optional synthetic 0.0.0.0/0.
        let fallback_default: Option<crate::fib::netlink_neigh::FallbackDefaultSpec> =
            cfg.section.directives.iter().find_map(|d| match d {
                ModuleDirective::FallbackDefault { iface, nexthop, .. } => {
                    Some(crate::fib::netlink_neigh::FallbackDefaultSpec {
                        iface: iface.clone(),
                        nexthop: *nexthop,
                    })
                }
                _ => None,
            });
        if let Some(fbd) = &fallback_default {
            info!(
                iface = %fbd.iface,
                nexthop = %fbd.nexthop,
                "v0.2.1 fallback-default 0.0.0.0/0 catch-all enabled"
            );
        }

        let ctrl = crate::fib::controller::RouteController::start(
            &state.bpffs_root,
            route_source,
            local_prefixes,
            fallback_default,
        )
        .map_err(|e| {
            ModuleError::other(MODULE_NAME, format!("RouteController start failed: {e}"))
        })?;
        state.route_controller = Some(ctrl);
        info!(
            ?forwarding,
            "RouteController started (NeighborResolver + FibProgrammer active)"
        );
    } else {
        info!(
            ?forwarding,
            "RouteController not started (kernel-fib mode); Option F control plane idle"
        );
    }

    // Build Attachment records for the pin registry. `pinned_path`
    // points at the real link pin, when `packetframe detach` runs,
    // it unlinks this path, which is how the kernel-side attach tears
    // down.
    Ok(state
        .links
        .iter()
        .map(|l| Attachment {
            iface: l.iface.clone(),
            hook: match l.effective_mode {
                AttachMode::Native => HookType::NativeXdp,
                AttachMode::Generic => HookType::GenericXdp,
                AttachMode::Auto => HookType::NativeXdp, // already resolved
                AttachMode::Tc => HookType::TcIngress,
            },
            prog_id,
            // tc attaches have no bpffs link pin; their persistent
            // record is tc-links.json, so point the registry there.
            pinned_path: match l.effective_mode {
                AttachMode::Tc => crate::tc_links::file_path(&state.state_dir),
                _ => pin::link_path(&state.bpffs_root, &l.iface),
            },
        })
        .collect())
}

/// Pin the fast-path program and every §4.5 map under the module's
/// bpffs pin root. Called at the end of `attach` so partial failure
/// in link attach doesn't leak pins.
/// Inspect each attached link's driver + effective mode and set the
/// `FP_CFG_FLAG_HEAD_SHIFT_128` bit in `FpCfg.flags` when any link
/// hits the rvu-nicpf native-mode delivery bug (SPEC §11.1(c),
/// upstream-fixed in Linux v6.8 commit `04f647c8e456` but absent
/// from many downstream kernels). Safe and idempotent on fixed
/// kernels, set `off` via config override once the operator
/// confirms the backport (future PR; for v0.1.3 the detection is
/// purely driver-name-based).
///
/// Called *after* the attach loop so `effective_mode` reflects any
/// auto-fallback (`Auto` → `Generic` on drivers that refuse native).
/// Generic-mode rvu-nicpf does **not** need the workaround because
/// the kernel normalises the frame into an skb before running XDP;
/// applying the shift there would corrupt packet data.
fn apply_driver_quirks_cfg(state: &mut ActiveState, mcfg: &ModuleConfig<'_>) -> ModuleResult<()> {
    // Resolve the operator's override for the head-shift workaround.
    // Default `Auto` matches v0.1.3 behaviour: detect by driver name,
    // apply on native-mode rvu-nicpf attaches.
    let toggle = mcfg
        .section
        .directives
        .iter()
        .find_map(|d| match d {
            ModuleDirective::DriverWorkaround(DriverWorkaround::RvuNicpfHeadShift(v)) => Some(*v),
            _ => None,
        })
        .unwrap_or_default();

    let apply = match toggle {
        ToggleAutoOnOff::Off => false,
        ToggleAutoOnOff::On => true,
        ToggleAutoOnOff::Auto => state.links.iter().any(|l| {
            matches!(l.effective_mode, AttachMode::Native)
                && read_iface_driver(&l.iface)
                    .as_deref()
                    .is_some_and(|d| RVU_NICPF_DRIVERS.contains(&d))
        }),
    };

    if !apply {
        if matches!(toggle, ToggleAutoOnOff::Off) {
            info!(
                "rvu-nicpf head-shift workaround disabled by config (`driver-workaround \
                 rvu-nicpf-head-shift off`), assuming Linux v6.8+ or backported fix"
            );
        }
        return Ok(());
    }

    // Read current FpCfg, OR in the flag, write back. We only set
    // never clear, so we don't clobber the IPv4/IPv6 enable bits
    // that `populate_cfg` wrote at load time.
    let map = state
        .ebpf
        .map_mut("CFG")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "CFG map missing from ELF"))?;
    let mut arr: Array<_, FpCfg> = Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG Array::try_from: {e}")))?;
    let mut current: FpCfg = arr
        .get(&0, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG get: {e}")))?;
    current.flags |= FP_CFG_FLAG_HEAD_SHIFT_128;
    arr.set(0, current, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG set: {e}")))?;

    let reason = match toggle {
        ToggleAutoOnOff::On => "forced on by config",
        ToggleAutoOnOff::Auto => "auto-detected rvu-nicpf on a native-mode attach",
        ToggleAutoOnOff::Off => unreachable!("filtered above"),
    };
    let affected: Vec<&str> = state
        .links
        .iter()
        .filter(|l| matches!(l.effective_mode, AttachMode::Native))
        .map(|l| l.iface.as_str())
        .collect();
    warn!(
        reason,
        ifaces = ?affected,
        upstream_fix_commit = "04f647c8e456",
        fixed_in_kernel = "v6.8",
        "enabling pre-v6.8 rvu-nicpf head-shift workaround (SPEC §11.1(c)), fast-path will \
         bpf_xdp_adjust_head(+128) + bpf_xdp_adjust_tail(+128) on every packet to expose the \
         real frame. Set `driver-workaround rvu-nicpf-head-shift off` in the config once the \
         kernel backport lands."
    );
    Ok(())
}

/// Read `/proc/sys/kernel/osrelease` (= `uname -r`) and parse the
/// leading `major.minor`. Returns `None` if the file is unreadable
/// or the format is unrecognizable, callers treat that as "can't
/// prove the fix is present", i.e. the conservative path.
fn kernel_version() -> Option<(u32, u32)> {
    let osrelease = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let prefix = osrelease.split('-').next().unwrap_or(osrelease.trim());
    let mut parts = prefix.trim().split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Return true if the running kernel's `major.minor` is at least the
/// requested threshold. `None` from [`kernel_version`] returns false
/// (conservative: treat as missing the fix).
fn kernel_at_least(min: (u32, u32)) -> bool {
    kernel_version().map(|v| v >= min).unwrap_or(false)
}

/// Walk the attach directives and decide whether native-mode attach is
/// safe on each rvu-nicpf iface. Downgrades `Auto` to `Generic` with a
/// warning on affected kernels; hard-errors on explicit `Native`
/// unless the operator's `driver-workaround rvu-nicpf-head-shift`
/// toggle opts into the known-unsafe path. Runs *before* any
/// hardware-level XDP attach so the driver's attach-time bugs don't
/// even get one chance to trip.
fn rvu_nicpf_version_gate(
    attach_dirs: Vec<(String, AttachMode, u32)>,
    mcfg: &ModuleConfig<'_>,
) -> ModuleResult<Vec<(String, AttachMode, u32)>> {
    let toggle = mcfg
        .section
        .directives
        .iter()
        .find_map(|d| match d {
            ModuleDirective::DriverWorkaround(DriverWorkaround::RvuNicpfHeadShift(v)) => Some(*v),
            _ => None,
        })
        .unwrap_or_default();

    // `Off` = operator asserts they've backported the fix (or are
    // otherwise certain native is safe). Skip both the version check
    // and the later head-shift application. `On` = operator takes
    // responsibility for the known-unsafe path and opts into both the
    // head-shift workaround and skipping the version refusal.
    if matches!(toggle, ToggleAutoOnOff::Off | ToggleAutoOnOff::On) {
        return Ok(attach_dirs);
    }

    // `Auto` (default): check kernel version and refuse or downgrade.
    let kernel_ok = kernel_at_least(RVU_NICPF_FIXED_IN_KERNEL);
    if kernel_ok {
        // v6.8+; the fix is present; native attach is safe.
        return Ok(attach_dirs);
    }

    let mut out = Vec::with_capacity(attach_dirs.len());
    for (iface, mode, ifindex) in attach_dirs {
        let is_rvu = read_iface_driver(&iface)
            .as_deref()
            .is_some_and(|d| RVU_NICPF_DRIVERS.contains(&d));
        let wants_native = matches!(mode, AttachMode::Native | AttachMode::Auto);
        if !is_rvu || !wants_native {
            out.push((iface, mode, ifindex));
            continue;
        }
        match mode {
            AttachMode::Native => {
                return Err(ModuleError::other(
                    MODULE_NAME,
                    format!(
                        "refusing native XDP attach on rvu-nicpf iface `{iface}`: kernel \
                         {} lacks upstream fix (commit 04f647c8e456, Linux v6.8+) for two \
                         rvu-nicpf bugs that together make native XDP unsafe on this driver \
                         (SPEC §11.1(c)). Either (a) backport 04f647c8e456 into this \
                         kernel, (b) switch `{iface}` to `attach … generic` (no attach-time \
                         queue leak; slightly lower throughput), or (c) override with \
                         `driver-workaround rvu-nicpf-head-shift on` to accept the known \
                         crash risk",
                        kernel_version()
                            .map(|(a, b)| format!("{a}.{b}"))
                            .unwrap_or_else(|| "<unknown>".into())
                    ),
                ));
            }
            AttachMode::Auto => {
                warn!(
                    iface = %iface,
                    kernel = ?kernel_version(),
                    "rvu-nicpf on pre-v6.8 kernel: downgrading `auto` to `generic` \
                     (SPEC §11.1(c)). Upstream fix is commit 04f647c8e456; set \
                     `driver-workaround rvu-nicpf-head-shift on` to force native anyway."
                );
                out.push((iface, AttachMode::Generic, ifindex));
            }
            AttachMode::Generic | AttachMode::Tc => {
                unreachable!("filtered by wants_native check above")
            }
        }
    }
    Ok(out)
}

/// Read the kernel driver name backing a netdev via
/// `/sys/class/net/<iface>/device/driver` (a symlink into
/// `/sys/bus/*/drivers/<driver>`). Returns `None` for netdevs that
/// have no underlying device (veth pairs, bridges, loopback) or when
/// the file isn't present. Doesn't try ethtool, sysfs is
/// netns-aware when mounted per-netns and avoids another
/// capability-gated syscall just for a name.
fn read_iface_driver(iface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{iface}/device/driver");
    let target = std::fs::read_link(&path).ok()?;
    target.file_name().map(|s| s.to_string_lossy().into_owned())
}

fn pin_program_and_maps(state: &mut ActiveState) -> ModuleResult<()> {
    // v0.2.5: pin both `fast_path` (the iface-attached XDP) and
    // `finalize` (the tail-called second stage). Both pins survive
    // SIGTERM per SPEC §8.5; on restart, `pin::has_existing_pins`
    // sees both and refuses to start until operator runs `detach --all`.
    for prog_name in [pin::PROGRAM_NAME, pin::FINALIZE_PROGRAM_NAME] {
        let prog_path = pin::program_path_for(&state.bpffs_root, prog_name);
        let prog: &mut Xdp = state
            .ebpf
            .program_mut(prog_name)
            .ok_or_else(|| {
                ModuleError::other(MODULE_NAME, format!("{prog_name} program missing for pin"))
            })?
            .try_into()
            .map_err(|e| {
                ModuleError::other(MODULE_NAME, format!("pin: {prog_name} not XDP: {e}"))
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
        "fast_path + finalize programs + maps pinned"
    );
    Ok(())
}

/// Populate `MUTATION_PROGS[0]` with `finalize`'s FD so fast_path's
/// `bpf_tail_call(MUTATION_PROGS, 0)` resolves to it. Must run after
/// `finalize.load()` (FD valid) and before `fast_path` attaches to any
/// iface (otherwise an early packet would tail-call into an empty slot,
/// trip ErrTailCall, and slow-path through the kernel).
///
/// v0.2.5+. Single program in slot 0 for now; future stages either
/// replace slot 0 with a chain head or add to subsequent slots.
fn populate_mutation_progs(ebpf: &mut Ebpf) -> ModuleResult<()> {
    use aya::maps::ProgramArray;
    use aya::programs::ProgramFd;

    // Borrow scope: the ProgramFd has to outlive the ProgramArray::set
    // call, but it borrows from `ebpf`. Open the ProgramFd first, then
    // reborrow ebpf for the map.
    let finalize_fd: ProgramFd = {
        let prog: &Xdp = ebpf
            .program(pin::FINALIZE_PROGRAM_NAME)
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "finalize program missing post-load"))?
            .try_into()
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("finalize not XDP: {e}")))?;
        prog.fd()
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("finalize fd: {e}")))?
            .try_clone()
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("finalize fd clone: {e}")))?
    };

    let map = ebpf
        .map_mut("MUTATION_PROGS")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "MUTATION_PROGS map missing"))?;
    let mut prog_array: ProgramArray<_> = ProgramArray::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("MUTATION_PROGS try_from: {e}")))?;
    prog_array.set(0, &finalize_fd, 0).map_err(|e| {
        ModuleError::other(MODULE_NAME, format!("MUTATION_PROGS.set(0, finalize): {e}"))
    })?;
    info!("MUTATION_PROGS[0] populated with finalize program FD");
    Ok(())
}

/// The parsed `forwarding-mode` directive (default `kernel-fib`).
fn forwarding_mode_from_cfg(cfg: &ModuleConfig<'_>) -> packetframe_common::config::ForwardingMode {
    cfg.section
        .directives
        .iter()
        .find_map(|d| match d {
            ModuleDirective::ForwardingMode(m) => Some(*m),
            _ => None,
        })
        .unwrap_or_default()
}

/// tc-datapath program names in the shared BPF ELF (Phase T).
const TC_FAST_PATH_PROGRAM_NAME: &str = "tc_fast_path";
const TC_FINALIZE_PROGRAM_NAME: &str = "tc_finalize";

/// Load the sched_cls pair. `tc_finalize` first, its FD feeds the
/// TC_MUTATION_PROGS population before any tc filter attaches — the
/// same contract as the XDP finalize/MUTATION_PROGS ordering.
fn load_tc_programs(ebpf: &mut Ebpf) -> ModuleResult<()> {
    use aya::programs::tc::SchedClassifier;
    for name in [TC_FINALIZE_PROGRAM_NAME, TC_FAST_PATH_PROGRAM_NAME] {
        let prog: &mut SchedClassifier = ebpf
            .program_mut(name)
            .ok_or_else(|| ModuleError::other(MODULE_NAME, format!("{name} missing from ELF")))?
            .try_into()
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("{name} not sched_cls: {e}")))?;
        prog.load().map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("SchedClassifier::load({name}) failed (verifier rejection?): {e}"),
            )
        })?;
    }
    Ok(())
}

/// Populate TC_MUTATION_PROGS[0] with tc_finalize (mirror of
/// `populate_mutation_progs`; PROG_ARRAYs bind to one owner program
/// type, so the tc chain needs its own jump table).
fn populate_tc_mutation_progs(ebpf: &mut Ebpf) -> ModuleResult<()> {
    use aya::maps::ProgramArray;
    use aya::programs::tc::SchedClassifier;
    use aya::programs::ProgramFd;

    let tc_finalize_fd: ProgramFd = {
        let prog: &SchedClassifier = ebpf
            .program(TC_FINALIZE_PROGRAM_NAME)
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "tc_finalize missing post-load"))?
            .try_into()
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc_finalize type: {e}")))?;
        prog.fd()
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc_finalize fd: {e}")))?
            .try_clone()
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc_finalize fd clone: {e}")))?
    };

    let map = ebpf
        .map_mut("TC_MUTATION_PROGS")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "TC_MUTATION_PROGS map missing"))?;
    let mut prog_array: ProgramArray<_> = ProgramArray::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("TC_MUTATION_PROGS try_from: {e}")))?;
    prog_array.set(0, &tc_finalize_fd, 0).map_err(|e| {
        ModuleError::other(
            MODULE_NAME,
            format!("TC_MUTATION_PROGS.set(0, tc_finalize): {e}"),
        )
    })?;
    info!("TC_MUTATION_PROGS[0] populated with tc_finalize program FD");
    Ok(())
}

/// Attach `tc_fast_path` to `iface`'s clsact ingress and return the
/// kernel-assigned `(priority, handle)` identifying the filter.
///
/// **Explicitly netlink cls_bpf on every kernel** (not aya's
/// version-picked TCX path): netlink filters have qdisc lifetime —
/// the kernel attach survives process exit, matching the pinned-XDP
/// posture — and yield the `(priority, handle)` pair that
/// `SchedClassifierLink::attached()` needs for out-of-process detach.
/// TCX (≥6.6) would hand us an FD-lifetime link that dies with the
/// process; migrating to pinned TCX links is future work once the
/// fleet baseline moves past 6.6.
///
/// The returned aya link is deliberately `mem::forget`-ed: dropping
/// it would detach the filter.
pub fn tc_attach_iface(ebpf: &mut Ebpf, iface: &str) -> ModuleResult<(u16, u32)> {
    use aya::programs::tc::{
        qdisc_add_clsact, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType,
    };

    match qdisc_add_clsact(iface) {
        Ok(()) => info!(iface, "clsact qdisc added"),
        // Already present (another tool, a prior run): attaching a
        // filter to the existing clsact is exactly what we want.
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
        .program_mut(TC_FAST_PATH_PROGRAM_NAME)
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "tc_fast_path missing post-load"))?
        .try_into()
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc_fast_path type: {e}")))?;
    let link_id = prog
        .attach_with_options(
            iface,
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions::default()),
        )
        .map_err(|e| {
            ModuleError::other(MODULE_NAME, format!("tc attach on {iface} failed: {e}"))
        })?;
    let link = prog
        .take_link(link_id)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc take_link({iface}): {e}")))?;
    let priority = link
        .priority()
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc link priority({iface}): {e}")))?;
    let handle = link
        .handle()
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc link handle({iface}): {e}")))?;
    // Keep the kernel attach alive past this scope; see fn docs.
    std::mem::forget(link);
    Ok((priority, handle))
}

/// Outcome of one tc-filter detach attempt. The distinction decides
/// whether the filter's `tc-links.json` record may be dropped — that
/// record is the ONLY teardown metadata for a live filter (review
/// finding, PR #75), so it must survive any failure that leaves the
/// filter plausibly attached.
enum TcDetachOutcome {
    /// Goal state reached: the filter was detached, or is provably
    /// gone already (iface no longer resolvable — the qdisc and its
    /// filters died with the device — or the netlink delete reported
    /// ENOENT/EINVAL, i.e. no such filter/qdisc). Record droppable.
    Cleared,
    /// The delete failed with the filter plausibly still live
    /// (transient netlink error, EPERM, ...). Record must be retained
    /// for retry.
    Failed(String),
}

/// Detach one recorded tc filter. Building block for both the
/// in-process (`detach(state)`) and out-of-process
/// ([`tc_detach_from_state_dir`]) teardown paths.
fn tc_detach_one(iface: &str, priority: u16, handle: u32) -> TcDetachOutcome {
    use aya::programs::tc::{SchedClassifierLink, TcAttachType, TcError};
    use aya::programs::{Link as _, ProgramError};

    // `attached()` only resolves the ifindex; failure means the iface
    // is gone, and qdisc-lifetime filters go with their device.
    let link = match SchedClassifierLink::attached(iface, TcAttachType::Ingress, priority, handle) {
        Ok(l) => l,
        Err(e) => {
            info!(iface, error = %e, "iface gone; tc filter died with it");
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
            info!(iface, priority, handle, "tc filter already absent");
            TcDetachOutcome::Cleared
        }
        Err(e) => TcDetachOutcome::Failed(format!(
            "tc detach on {iface} (prio {priority}, handle {handle}): {e}"
        )),
    }
}

/// Tear down every tc filter recorded in `<state-dir>/tc-links.json`.
/// Used by `packetframe detach` (no live loader required — the
/// filters have qdisc lifetime). Returns the number of filters
/// cleared.
///
/// Records whose detach FAILED with the filter plausibly still live
/// are written back to tc-links.json and the call errors: deleting
/// their only teardown metadata would orphan active classifiers while
/// reporting success (review finding, PR #75). Records for vanished
/// ifaces / already-absent filters are dropped normally.
pub fn tc_detach_from_state_dir(state_dir: &Path) -> ModuleResult<usize> {
    let Some(file) = crate::tc_links::load(state_dir)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc-links.json read: {e}")))?
    else {
        return Ok(0);
    };
    let mut cleared = 0usize;
    let mut retained = Vec::new();
    for rec in file.links {
        match tc_detach_one(&rec.iface, rec.priority, rec.handle) {
            TcDetachOutcome::Cleared => {
                info!(iface = %rec.iface, rec.priority, rec.handle, "tc filter cleared");
                cleared += 1;
            }
            TcDetachOutcome::Failed(e) => {
                warn!(iface = %rec.iface, error = %e, "tc filter detach failed; record retained");
                retained.push(rec);
            }
        }
    }
    if retained.is_empty() {
        crate::tc_links::remove(state_dir)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc-links.json remove: {e}")))?;
        return Ok(cleared);
    }
    let file = crate::tc_links::TcLinksFile { links: retained };
    crate::tc_links::save(state_dir, &file)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("tc-links.json rewrite: {e}")))?;
    let names: Vec<&str> = file.links.iter().map(|r| r.iface.as_str()).collect();
    Err(ModuleError::other(
        MODULE_NAME,
        format!(
            "tc filters still attached on {names:?}; records kept in tc-links.json — \
             rerun `packetframe detach` (or `tc filter del dev <iface> ingress`) to retry"
        ),
    ))
}

/// §2.3: per-interface trial-attach. `Native` and `Generic` are explicit
/// (no fallback); `Auto` tries native first, falls back to generic on
/// any error. The spec calls out that `bpftool feature probe` is
/// unreliable, we find out what works by actually trying. Each
/// successful attach immediately pins its link under
/// `<bpffs-root>/fast-path/links/<iface>` so the kernel attach
/// survives process exit (§8.5).
fn try_attach_with_fallback(
    prog: &mut Xdp,
    ifindex: u32,
    iface: &str,
    mode: AttachMode,
    bpffs_root: &Path,
) -> ModuleResult<(AttachMode, LinkHandle)> {
    match mode {
        // tc attaches are partitioned out before the XDP loop and go
        // through `tc_attach_iface`; reaching here is a caller bug.
        AttachMode::Tc => Err(ModuleError::other(
            MODULE_NAME,
            format!("internal: tc attach for `{iface}` routed to the XDP attach path"),
        )),
        AttachMode::Native => attach_and_pin(
            prog,
            ifindex,
            iface,
            XdpFlags::DRV_MODE,
            bpffs_root,
            "native",
        )
        .map(|p| (AttachMode::Native, p)),
        AttachMode::Generic => attach_and_pin(
            prog,
            ifindex,
            iface,
            XdpFlags::SKB_MODE,
            bpffs_root,
            "generic",
        )
        .map(|p| (AttachMode::Generic, p)),
        AttachMode::Auto => {
            match attach_and_pin(
                prog,
                ifindex,
                iface,
                XdpFlags::DRV_MODE,
                bpffs_root,
                "native",
            ) {
                Ok(p) => Ok((AttachMode::Native, p)),
                Err(native_err) => {
                    warn!(iface, %native_err, "native XDP attach failed; falling back to generic");
                    attach_and_pin(prog, ifindex, iface, XdpFlags::SKB_MODE, bpffs_root, "generic")
                        .map(|p| (AttachMode::Generic, p))
                        .map_err(|generic_err| {
                            ModuleError::other(
                                MODULE_NAME,
                                format!(
                                    "auto XDP attach to {iface}: native failed ({native_err}), generic failed ({generic_err})"
                                ),
                            )
                        })
                }
            }
        }
    }
}

/// Attach + `take_link`, then try to pin. Returns:
///
/// - `LinkHandle::Pinned` on success, the kernel attach survives
///   process exit via the bpffs inode.
/// - `LinkHandle::Transient` if pinning was rejected (EPERM on
///   generic-mode XDP links on some kernels, for instance). The
///   attach still works, but dropping the returned `FdLink` detaches
///   the kernel-side program.
///
/// Hard errors (attach fails, `take_link` fails, link isn't
/// bpf_link_create-backed) remain hard errors, the caller bubbles
/// them up.
fn attach_and_pin(
    prog: &mut Xdp,
    ifindex: u32,
    iface: &str,
    flags: XdpFlags,
    bpffs_root: &Path,
    mode_label: &str,
) -> ModuleResult<LinkHandle> {
    let link_id = prog.attach_to_if_index(ifindex, flags).map_err(|e| {
        ModuleError::other(
            MODULE_NAME,
            format!("{mode_label} XDP attach to {iface} failed: {e}"),
        )
    })?;
    let owned_link = prog.take_link(link_id).map_err(|e| {
        ModuleError::other(
            MODULE_NAME,
            format!("take_link after {mode_label} attach to {iface}: {e}"),
        )
    })?;
    let fd_link: FdLink = owned_link.try_into().map_err(|e| {
        ModuleError::other(
            MODULE_NAME,
            // SPEC.md requires kernel ≥5.15; ≥5.9 gives us bpf_link_create
            // + FdLink. On older kernels aya returns an NlLink which can't
            // pin, that path is reachable only if someone runs on a
            // kernel the probe missed.
            format!(
                "XDP link for {iface} is netlink-backed (kernel too old for bpf_link_create?): {e}",
            ),
        )
    })?;
    let pin_path = pin::link_path(bpffs_root, iface);
    match fd_link.pin(&pin_path) {
        Ok(pinned) => Ok(LinkHandle::Pinned(pinned)),
        Err(err) => {
            // Some kernels reject pinning for specific link types
            // (observed: EPERM on generic-XDP links on 6.12). The
            // attach itself is still valid; we just can't persist it
            // across process exit. Open a fresh FdLink from the
            // program's internal link tracking so we have something
            // to hold (PinnedLink consumed the prior one on failure).
            warn!(
                iface,
                pin_err = %format_error_chain(&err),
                "link pin failed; attach will not survive process exit"
            );
            // Re-attach so we have an FdLink to hold. `attach_to_if_index`
            // was already called; calling it again would double-attach
            // which the kernel rejects. Fortunately `FdLink::pin`
            // consumes `self` even on error, the link FD is already
            // gone. Re-attach from scratch:
            let link_id = prog.attach_to_if_index(ifindex, flags).map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("{mode_label} XDP re-attach to {iface} after pin failure: {e}"),
                )
            })?;
            let owned_link = prog.take_link(link_id).map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("take_link after re-attach to {iface}: {e}"),
                )
            })?;
            let fd_link: FdLink = owned_link.try_into().map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("XDP re-attach link for {iface} not FdLink: {e}"),
                )
            })?;
            Ok(LinkHandle::Transient(fd_link))
        }
    }
}

/// Walk a std::error::Error's source chain and join into one display
/// string, aya's `SyscallError` hides the underlying `io::Error`
/// behind `#[source]`, so plain `{}` drops the errno. This matters on
/// any BPF syscall where the errno is the whole diagnostic.
fn format_error_chain(err: &dyn std::error::Error) -> String {
    let mut out = format!("{err}");
    let mut source = err.source();
    while let Some(s) = source {
        out.push_str(&format!(": {s}"));
        source = s.source();
    }
    out
}

/// Populate `vlan_resolve` from `/proc/net/vlan/config`, plus — when
/// `bridge-resolve` allows — the collapsed bridge egress chains from
/// [`discover_bridge_chains`]. Each VLAN subinterface maps its ifindex
/// → (physical parent ifindex, VID) so the BPF program can
/// push/pop/rewrite per SPEC §4.7 when the FIB resolves to a subif;
/// each qualifying bridge maps its ifindex → (underlying device, VID)
/// so the datapath skips the software bridge traversal entirely (the
/// wire frame is identical to what the bridge would emit). Missing
/// `/proc/net/vlan/config` (no 8021q kernel module loaded) is not an
/// error — and with no VLAN subifs there can be no bridge chains
/// either, so both sets are empty together.
fn populate_vlan_resolve(
    state: &mut ActiveState,
    directives: &[ModuleDirective],
) -> ModuleResult<()> {
    let entries = match read_vlan_config() {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("/proc/net/vlan/config missing, no VLAN subifs to resolve");
            Vec::new()
        }
        Err(e) => {
            return Err(ModuleError::other(
                MODULE_NAME,
                format!("read /proc/net/vlan/config: {e}"),
            ));
        }
    };
    let chains = discover_bridge_chains(directives)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("bridge topology read: {e}")))?;

    if entries.is_empty() && chains.is_empty() {
        info!("no VLAN subifs and no collapsible bridges, VLAN_RESOLVE left empty");
        return Ok(());
    }

    let map = state
        .ebpf
        .map_mut("VLAN_RESOLVE")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "VLAN_RESOLVE map missing from ELF"))?;
    let mut hm: AyaHashMap<_, u32, VlanResolve> = AyaHashMap::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("VLAN_RESOLVE try_from: {e}")))?;

    for (subif_name, vid, parent_name) in entries {
        let subif_idx = if_nametoindex(&subif_name)?;
        let phys_idx = if_nametoindex(&parent_name)?;
        let value = VlanResolve {
            phys_ifindex: phys_idx,
            vid,
            _pad: 0,
        };
        hm.insert(subif_idx, value, 0).map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("VLAN_RESOLVE insert {subif_name}: {e}"),
            )
        })?;
        info!(
            subif = %subif_name,
            subif_idx,
            parent = %parent_name,
            phys_idx,
            vid,
            "vlan_resolve populated"
        );
    }

    // Bridge entries are an optional optimization: failure to install
    // one (map at capacity, iface vanished mid-walk) must degrade to
    // "that bridge keeps the kernel path", never abort attach — unlike
    // the subif entries above, whose absence would mistag real subif
    // egress. Warn-and-continue per entry.
    for (bridge_name, phys_name, vid) in chains {
        let (bridge_idx, phys_idx) =
            match (if_nametoindex(&bridge_name), if_nametoindex(&phys_name)) {
                (Ok(b), Ok(p)) => (b, p),
                _ => {
                    warn!(bridge = %bridge_name, "bridge short-circuit skipped: iface vanished");
                    continue;
                }
            };
        let value = VlanResolve {
            phys_ifindex: phys_idx,
            vid,
            _pad: 0,
        };
        if let Err(e) = hm.insert(bridge_idx, value, 0) {
            warn!(
                bridge = %bridge_name,
                error = %e,
                "bridge short-circuit skipped: VLAN_RESOLVE insert failed (bridge keeps the kernel path)"
            );
            continue;
        }
        info!(
            bridge = %bridge_name,
            bridge_idx,
            phys = %phys_name,
            phys_idx,
            vid,
            "bridge egress short-circuit installed"
        );
        // `mss-clamp via <this bridge>` can no longer match: the clamp
        // lookup keys on the POST-resolve egress ifindex (identical
        // pre-existing semantics for plain VLAN subifs). Detectable
        // here, so say it loudly with the fix.
        for d in directives {
            if let ModuleDirective::MssClamp {
                iface: Some(clamp_iface),
                ..
            } = d
            {
                if *clamp_iface == bridge_name {
                    warn!(
                        bridge = %bridge_name,
                        underlying = %phys_name,
                        "mss-clamp `via {bridge_name}` will NOT match while the bridge                          egress short-circuit is installed (clamp matching keys on the                          resolved egress ifindex). Scope the clamp `via {phys_name}` or                          set `bridge-resolve off`."
                    );
                }
            }
        }
    }

    // Entries landed → make sure the VLAN_PRESENT gate bit is on, even
    // if a subif appeared between populate_cfg's proc read and now.
    // (The reverse case — bit set but map ended empty — is harmless:
    // the gated lookup just misses, exactly like the ungated code did.)
    set_cfg_flag(&mut state.ebpf, FP_CFG_FLAG_VLAN_PRESENT, true)?;
    Ok(())
}

/// Parse `/proc/net/vlan/config`. Format (from Linux net/8021q):
///
/// ```text
/// VLAN Dev name    | VLAN ID
/// Name-Type: VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD
/// eth0.1337        | 1337  | eth0
/// ```
///
/// Skip the two header lines, split each subsequent line on `|`, trim
/// whitespace, and return `(subif_name, vid, parent_name)` tuples.
pub(crate) fn read_vlan_config() -> std::io::Result<Vec<(String, u16, String)>> {
    let content = std::fs::read_to_string("/proc/net/vlan/config")?;
    let mut out = Vec::new();
    for line in content.lines().skip(2) {
        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if parts.len() != 3 {
            continue;
        }
        let subif = parts[0].to_string();
        let vid: u16 = match parts[1].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let parent = parts[2].to_string();
        if subif.is_empty() || parent.is_empty() {
            continue;
        }
        out.push((subif, vid, parent));
    }
    Ok(out)
}

pub fn detach(state: &mut ActiveState) -> ModuleResult<()> {
    // Stop the Option F control plane first. Its tasks hold map
    // handles opened via `MapData::from_pin`; draining them before we
    // remove the pins keeps shutdown ordered and avoids "map removed
    // while programmer was mid-write" races.
    if let Some(ctrl) = state.route_controller.take() {
        info!("shutting down RouteController");
        ctrl.shutdown();
    }

    // Drop every PinnedLink next: this closes our userspace FDs but
    // the kernel keeps the attach alive via the bpffs inodes. tc
    // records hold no FD at all — detach them explicitly via their
    // recorded (priority, handle). Drain in reverse attach order.
    //
    // tc failures must not abort the rest of the teardown (a breaker
    // trip still has to detach XDP + remove pins), but a filter whose
    // delete failed with the iface still alive keeps its record in
    // tc-links.json: that record is the only metadata a later
    // `packetframe detach` retry has (review finding, PR #75).
    let mut had_tc = false;
    let mut tc_retained: Vec<crate::tc_links::TcLinkRecord> = Vec::new();
    while let Some(record) = state.links.pop() {
        info!(iface = %record.iface, "fast-path detaching");
        if let LinkHandle::Tc { priority, handle } = record.link {
            had_tc = true;
            match tc_detach_one(&record.iface, priority, handle) {
                TcDetachOutcome::Cleared => {}
                TcDetachOutcome::Failed(e) => {
                    warn!(iface = %record.iface, error = %e, "tc filter detach failed; record retained");
                    tc_retained.push(crate::tc_links::TcLinkRecord {
                        iface: record.iface.clone(),
                        priority,
                        handle,
                    });
                }
            }
        }
        drop(record);
    }
    if had_tc {
        if tc_retained.is_empty() {
            if let Err(e) = crate::tc_links::remove(&state.state_dir) {
                warn!(error = %e, "tc-links.json remove failed");
            }
        } else {
            warn!(
                count = tc_retained.len(),
                "tc filters still attached; records kept in tc-links.json for `packetframe detach` retry"
            );
            if let Err(e) = crate::tc_links::save(
                &state.state_dir,
                &crate::tc_links::TcLinksFile { links: tc_retained },
            ) {
                warn!(error = %e, "tc-links.json rewrite failed");
            }
        }
    }

    // Unlink every pin under the module's pin root. Pace the link-pin
    // removals by `attach_settle_time` so we don't trigger an STP
    // reconvergence storm on shared bridge masters, same hazard
    // §11.8 calls out for the attach path. Removing all link pins in
    // ~1 ms (the pre-rc5 behavior) wedged the bridge stack on rvu-
    // nicpf with eth0/eth4/eth5 all bridged on switch0, kernel-
    // panicking the EFG during Phase 4 cutover testing.
    pin::remove_all_paced(&state.bpffs_root, state.attach_settle_time)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("remove pins: {e}")))?;
    info!(
        settle_secs = state.attach_settle_time.as_secs_f64(),
        "fast-path pins removed; kernel detached"
    );
    Ok(())
}

/// Walk `/sys/class/net` and return the `(name, ifindex)` of every
/// iface that's a viable XDP redirect target:
///
/// - `type == 1` (ARPHRD_ETHER), covers physical NICs, bridges,
///   VLAN subifs, veth, bonded masters. Excludes loopback (772),
///   PPP, SLIP, tunnels (`ip_vti`, `ip6tnl`, `ip_tunnel`, tailscale,
///   WireGuard, etc. which use ARPHRD_NONE or similar).
/// - operstate is `up` or `unknown`. Some virtual ifaces never
///   transition to `up` even when they're carrying traffic; accept
///   them rather than over-exclude.
///
/// Callers of this must tolerate the returned set changing between
/// invocations (new ifaces come up, old ones go down). Reconcile
/// should re-enumerate on SIGHUP.
pub(crate) fn enumerate_redirect_targets() -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let base = format!("/sys/class/net/{name}");
        // ARPHRD_* type check: "1" == ARPHRD_ETHER.
        let type_ok = std::fs::read_to_string(format!("{base}/type"))
            .map(|s| s.trim() == "1")
            .unwrap_or(false);
        if !type_ok {
            continue;
        }
        // operstate filter: up or unknown.
        let operstate_ok = std::fs::read_to_string(format!("{base}/operstate"))
            .map(|s| matches!(s.trim(), "up" | "unknown"))
            .unwrap_or(false);
        if !operstate_ok {
            continue;
        }
        let ifindex = match if_nametoindex(&name) {
            Ok(i) => i,
            Err(_) => continue,
        };
        out.push((name, ifindex));
    }
    out
}

/// Emit a warning if two or more of the attach ifaces share a bridge
/// master. SPEC.md §11.8, on drivers that bounce the link at attach
/// time, bouncing multiple bridge members inside one STP reconvergence
/// window has been observed to trigger L2 loops. `attach_settle_time`
/// between per-iface attaches mitigates but does not eliminate this.
fn warn_shared_bridge_masters(ifaces: &[&str], settle_time: std::time::Duration) {
    use std::collections::HashMap;
    let mut by_master: HashMap<String, Vec<String>> = HashMap::new();
    for iface in ifaces {
        let master_link = format!("/sys/class/net/{iface}/master");
        let Ok(target) = std::fs::read_link(&master_link) else {
            continue;
        };
        let Some(master) = target.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        by_master
            .entry(master.to_string())
            .or_default()
            .push((*iface).to_string());
    }
    for (master, members) in by_master {
        if members.len() < 2 {
            continue;
        }
        warn!(
            bridge = %master,
            members = ?members,
            settle_secs = settle_time.as_secs_f64(),
            "multiple attach ifaces share bridge master, XDP attach can cause L2 loops \
             during STP reconvergence (§11.8). `attach-settle-time` spaces the attaches; \
             ensure it is long enough for your bridge to reconverge (default 2s)."
        );
    }
}

/// Wrap `libc::if_nametoindex`. Returns a clear error on failure.
pub(crate) fn if_nametoindex(name: &str) -> ModuleResult<u32> {
    let c = CString::new(name).map_err(|_| {
        ModuleError::other(MODULE_NAME, format!("interface name `{name}` has NUL byte"))
    })?;
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if idx == 0 {
        let err = std::io::Error::last_os_error();
        return Err(ModuleError::other(
            MODULE_NAME,
            format!("if_nametoindex(`{name}`): {err}"),
        ));
    }
    Ok(idx)
}

/// Per-interface native-XDP trial-attach probe for the feasibility
/// report (§2.3). Loads a minimal no-op XDP program and tries to
/// attach it to each interface in native mode, reporting per-interface
/// verdict. The no-op program is the `fast_path` program itself
/// any attached program's load/attach path is the same.
pub fn trial_attach_native(iface: &str) -> TrialResult {
    if !FAST_PATH_BPF_AVAILABLE {
        return TrialResult::NoBpfBinary;
    }
    let ifindex = match if_nametoindex(iface) {
        Ok(i) => i,
        Err(e) => return TrialResult::NoSuchInterface(e.to_string()),
    };
    let bytes = aligned_bpf_copy();
    let mut ebpf = match Ebpf::load(&bytes) {
        Ok(e) => e,
        Err(e) => return TrialResult::LoadFailed(e.to_string()),
    };
    let prog: &mut Xdp = match ebpf
        .program_mut("fast_path")
        .and_then(|p| <&mut Xdp>::try_from(p).ok())
    {
        Some(p) => p,
        None => return TrialResult::LoadFailed("fast_path program not present".into()),
    };
    if let Err(e) = prog.load() {
        return TrialResult::LoadFailed(e.to_string());
    }
    match prog.attach_to_if_index(ifindex, XdpFlags::DRV_MODE) {
        Ok(link_id) => {
            // Detach immediately, this was a probe.
            let _ = prog.detach(link_id);
            TrialResult::NativeOk
        }
        Err(native_err) => match prog.attach_to_if_index(ifindex, XdpFlags::SKB_MODE) {
            Ok(link_id) => {
                let _ = prog.detach(link_id);
                TrialResult::GenericOnly {
                    native_error: native_err.to_string(),
                }
            }
            Err(generic_err) => TrialResult::Neither {
                native_error: native_err.to_string(),
                generic_error: generic_err.to_string(),
            },
        },
    }
}

pub enum TrialResult {
    NativeOk,
    GenericOnly {
        native_error: String,
    },
    Neither {
        native_error: String,
        generic_error: String,
    },
    NoSuchInterface(String),
    LoadFailed(String),
    NoBpfBinary,
}

// Helper for status reporting
pub fn snapshot_links(state: &ActiveState) -> Vec<(String, u32, AttachMode)> {
    state
        .links
        .iter()
        .map(|l| (l.iface.clone(), l.ifindex, l.effective_mode))
        .collect()
}

// Read current stats, aggregated across all CPUs.
pub fn snapshot_stats(state: &ActiveState) -> ModuleResult<Vec<u64>> {
    use aya::maps::PerCpuArray;

    let map = state
        .ebpf
        .map("STATS")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "STATS map missing from ELF"))?;
    let stats: PerCpuArray<_, StatsBlock> = PerCpuArray::try_from(map).map_err(|e| {
        ModuleError::other(MODULE_NAME, format!("STATS PerCpuArray::try_from: {e}"))
    })?;

    read_stats(&stats)
}

/// Snapshot of the custom-FIB control-plane state that's readable
/// from a separate process via the bpffs pins, i.e., no live
/// `FibProgrammer` handle required. Used by `packetframe status` to
/// surface an operator-facing summary during and after cutover.
///
/// **Not readable from pins (requires IPC to the live daemon):**
/// - FibProgrammer mpsc queue depth
/// - BMP session state (connected / initiating / stalled)
/// - Last route / neigh update timestamps per peer
///
/// Those land when Phase 3.5 or later wires up a daemon-side
/// control socket. For now the pin-based snapshot is enough to
/// answer "is the control plane populating maps the way I expect."
#[derive(Debug, Clone)]
pub struct FibStatusSnapshot {
    /// Which forwarding mode the live `FpCfg.flags` encodes. Derived
    /// from bits 3-4. `None` if the CFG map is missing (pre-Phase-1
    /// binary left pins behind).
    pub forwarding_mode: Option<&'static str>,
    pub default_hash_mode: Option<u8>,
    /// NEXTHOPS[idx].state distribution. Slots that were never
    /// written read as state=0 which collides with
    /// `NH_STATE_INCOMPLETE`; we can't distinguish those from
    /// actual in-progress entries without programmer-internal
    /// refcount state, so `nh_unwritten_or_incomplete` is reported
    /// as a single bucket.
    pub nh_resolved: u32,
    pub nh_failed: u32,
    pub nh_stale: u32,
    pub nh_unwritten_or_incomplete: u32,
    pub nh_max_entries: u32,
    /// ECMP groups where `nh_count > 0`, a conservative estimate
    /// of "how many groups are actively in use." Slots with nh_count=0
    /// are either unwritten or tombstoned; we can't distinguish
    /// without programmer state.
    pub ecmp_active: u32,
    pub ecmp_max_entries: u32,
}

/// Read the custom-FIB snapshot from the bpffs pins. Best-effort:
/// missing or malformed pins produce warnings and default values
/// rather than hard errors, `packetframe status` should still
/// show whatever it can even if a subset of the custom-FIB maps
/// aren't pinned yet (e.g., kernel-fib mode).
pub fn fib_status_from_pin(bpffs_root: &Path) -> FibStatusSnapshot {
    let mut snapshot = FibStatusSnapshot {
        forwarding_mode: None,
        default_hash_mode: None,
        nh_resolved: 0,
        nh_failed: 0,
        nh_stale: 0,
        nh_unwritten_or_incomplete: 0,
        nh_max_entries: 0,
        ecmp_active: 0,
        ecmp_max_entries: 0,
    };

    // --- CFG flags: forwarding mode ---
    if let Ok(fp_cfg) = read_cfg_map(bpffs_root) {
        let flags = fp_cfg.flags;
        let custom = flags & FP_CFG_FLAG_CUSTOM_FIB != 0;
        let compare = flags & FP_CFG_FLAG_COMPARE_MODE != 0;
        snapshot.forwarding_mode = Some(match (custom, compare) {
            (false, _) => "kernel-fib",
            (true, false) => "custom-fib",
            (true, true) => "compare",
        });
    }

    // --- FIB_CONFIG: default hash mode ---
    if let Ok(mode) = read_fib_config_hash_mode(bpffs_root) {
        snapshot.default_hash_mode = Some(mode);
    }

    // --- NEXTHOPS: walk for state distribution ---
    if let Ok((dist, cap)) = read_nexthops_state_distribution(bpffs_root) {
        snapshot.nh_resolved = dist.resolved;
        snapshot.nh_failed = dist.failed;
        snapshot.nh_stale = dist.stale;
        snapshot.nh_unwritten_or_incomplete = dist.unwritten_or_incomplete;
        snapshot.nh_max_entries = cap;
    }

    // --- ECMP_GROUPS: count active ---
    if let Ok((active, cap)) = read_ecmp_groups_active(bpffs_root) {
        snapshot.ecmp_active = active;
        snapshot.ecmp_max_entries = cap;
    }

    snapshot
}

fn read_cfg_map(bpffs_root: &Path) -> ModuleResult<FpCfg> {
    let pin_path = pin::map_path(bpffs_root, "CFG");
    let map_data = aya::maps::MapData::from_pin(&pin_path)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("open CFG pin: {e}")))?;
    let map = aya::maps::Map::Array(map_data);
    let arr: aya::maps::Array<_, FpCfg> = aya::maps::Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG try_from: {e}")))?;
    arr.get(&0, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG get: {e}")))
}

fn read_fib_config_hash_mode(bpffs_root: &Path) -> ModuleResult<u8> {
    let pin_path = pin::map_path(bpffs_root, "FIB_CONFIG");
    let map_data = aya::maps::MapData::from_pin(&pin_path)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("open FIB_CONFIG pin: {e}")))?;
    let map = aya::maps::Map::Array(map_data);
    let arr: aya::maps::Array<_, crate::fib::types::FpFibCfg> = aya::maps::Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("FIB_CONFIG try_from: {e}")))?;
    let cfg = arr
        .get(&0, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("FIB_CONFIG get: {e}")))?;
    Ok(cfg.default_hash_mode)
}

#[derive(Debug, Default)]
struct NhStateDistribution {
    resolved: u32,
    failed: u32,
    stale: u32,
    unwritten_or_incomplete: u32,
}

fn read_nexthops_state_distribution(bpffs_root: &Path) -> ModuleResult<(NhStateDistribution, u32)> {
    use crate::fib::programmer::NEXTHOPS_CAP;
    use crate::fib::types::{NexthopEntry, NH_STATE_FAILED, NH_STATE_RESOLVED, NH_STATE_STALE};

    let pin_path = pin::map_path(bpffs_root, "NEXTHOPS");
    let map_data = aya::maps::MapData::from_pin(&pin_path)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("open NEXTHOPS pin: {e}")))?;
    let map = aya::maps::Map::Array(map_data);
    let arr: aya::maps::Array<_, NexthopEntry> = aya::maps::Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("NEXTHOPS try_from: {e}")))?;

    let mut dist = NhStateDistribution::default();
    // Walk up to NEXTHOPS_CAP (8192). At ~100ns per Array::get syscall
    // this is ~1ms on a modern box, fine for status on demand.
    for idx in 0..NEXTHOPS_CAP {
        let entry = match arr.get(&idx, 0) {
            Ok(e) => e,
            Err(_) => continue,
        };
        match entry.state {
            NH_STATE_RESOLVED => dist.resolved += 1,
            NH_STATE_FAILED => dist.failed += 1,
            NH_STATE_STALE => dist.stale += 1,
            _ => dist.unwritten_or_incomplete += 1,
        }
    }
    Ok((dist, NEXTHOPS_CAP))
}

fn read_ecmp_groups_active(bpffs_root: &Path) -> ModuleResult<(u32, u32)> {
    use crate::fib::programmer::ECMP_GROUPS_CAP;
    use crate::fib::types::EcmpGroup;

    let pin_path = pin::map_path(bpffs_root, "ECMP_GROUPS");
    let map_data = aya::maps::MapData::from_pin(&pin_path)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("open ECMP_GROUPS pin: {e}")))?;
    let map = aya::maps::Map::Array(map_data);
    let arr: aya::maps::Array<_, EcmpGroup> = aya::maps::Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("ECMP_GROUPS try_from: {e}")))?;

    let mut active = 0u32;
    for idx in 0..ECMP_GROUPS_CAP {
        let group = match arr.get(&idx, 0) {
            Ok(g) => g,
            Err(_) => continue,
        };
        if group.nh_count > 0 {
            active += 1;
        }
    }
    Ok((active, ECMP_GROUPS_CAP))
}

/// Read STATS directly from the bpffs pin, no live module required.
/// Used by `packetframe status` when the loader isn't running.
pub fn stats_from_pin(bpffs_root: &Path) -> ModuleResult<Vec<u64>> {
    use aya::maps::{Map, MapData, PerCpuArray};

    let pin_path = pin::map_path(bpffs_root, "STATS");
    let map_data = MapData::from_pin(&pin_path).map_err(|e| {
        ModuleError::other(
            MODULE_NAME,
            format!("open STATS pin at {}: {e}", pin_path.display()),
        )
    })?;
    // aya's `PerCpuArray::try_from` takes a `Map` enum, not a bare
    // `MapData`; wrap before converting.
    let map = Map::PerCpuArray(map_data);
    let stats: PerCpuArray<_, StatsBlock> = PerCpuArray::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("STATS PerCpuArray: {e}")))?;
    read_stats(&stats)
}

/// Userspace mirror of the BPF side's `[u64; STATS_COUNT]` STATS value
/// (v0.2.8+ single-entry map shape). Sized from
/// `metrics::COUNTER_COUNT`, the single userspace mirror of
/// `STATS_COUNT` in bpf/src/maps.rs — prior versions hardcoded
/// separate lengths and drifted three times (19 hid `err_head_shift`;
/// 33 hid `mss_clamp_*`; 37 hid `pass_ndp`).
pub(crate) type StatsBlock = [u64; crate::metrics::COUNTER_COUNT];

fn read_stats<T: std::borrow::Borrow<aya::maps::MapData>>(
    stats: &aya::maps::PerCpuArray<T, StatsBlock>,
) -> ModuleResult<Vec<u64>> {
    // One BPF_MAP_LOOKUP_ELEM for the whole counter block (previously
    // one syscall per counter, O(counters) per metrics tick).
    let per_cpu = stats
        .get(&0, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("STATS get[0]: {e}")))?;
    let mut out = vec![0u64; crate::metrics::COUNTER_COUNT];
    for cpu_block in per_cpu.iter() {
        for (slot, v) in out.iter_mut().zip(cpu_block.iter()) {
            *slot += *v;
        }
    }
    Ok(out)
}

/// Read `MUTATION_PROGS` from its bpffs pin and return whether slot 0
/// is populated. Status command uses this to confirm the v0.2.5+
/// tail-call chain (`fast_path` → `finalize`) is wired correctly.
/// An empty slot means an attach-time bug in `populate_mutation_progs`;
/// fast_path's `tail_call` will fail and bump `ErrTailCall` on every
/// fast-pathed packet.
///
/// aya 0.13's ProgramArray exposes `indices()` (which keys are set)
/// but not a getter that returns the populated `ProgramFd`/prog_id
/// the BPF_MAP_TYPE_PROG_ARRAY value is a kernel RawFd that becomes
/// invalid outside the loader's process. We just report populated/
/// empty here; operators can confirm prog_id via
/// `bpftool prog show name finalize`.
pub fn tail_call_chain_from_pin(bpffs_root: &Path) -> ModuleResult<bool> {
    use aya::maps::{Map, MapData, ProgramArray};

    let pin_path = pin::map_path(bpffs_root, "MUTATION_PROGS");
    let map_data = MapData::from_pin(&pin_path).map_err(|e| {
        ModuleError::other(
            MODULE_NAME,
            format!("open MUTATION_PROGS pin at {}: {e}", pin_path.display()),
        )
    })?;
    let map = Map::ProgramArray(map_data);
    let prog_array: ProgramArray<_> = ProgramArray::try_from(map).map_err(|e| {
        ModuleError::other(MODULE_NAME, format!("MUTATION_PROGS try_from pin: {e}"))
    })?;
    for idx in prog_array.indices() {
        let key = idx
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("MUTATION_PROGS indices: {e}")))?;
        if key == 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Accessor consumed by the bpffs-pin code in PR #6. For now,
/// exposed so the CLI `status` can report the pin root without
/// the module needing to expose `ActiveState` directly.
#[allow(dead_code)]
pub fn bpffs_pin_root(state: &ActiveState) -> PathBuf {
    state.bpffs_root.join(MODULE_NAME)
}

#[allow(dead_code)]
pub fn state_dir(state: &ActiveState) -> &Path {
    &state.state_dir
}

#[cfg(test)]
mod tests {
    use super::gc_thresh3_capacity_warning;
    use super::{
        bridge_resolve_enabled, bridge_vlan_chains, discover_bridge_chains,
        feature_flags_from_config, if_nametoindex, populate_vlan_resolve, ActiveState, FpCfg,
        VlanResolve, FP_CFG_FLAG_BLOCK_PRESENT, FP_CFG_FLAG_MSS_CLAMP_PRESENT,
        FP_CFG_FLAG_VLAN_PRESENT,
    };
    use aya::maps::Array;
    use packetframe_common::config::{ModuleDirective, ToggleAutoOnOff};

    #[test]
    fn feature_flags_truth_table() {
        let block = ModuleDirective::BlockPrefix {
            cidr: "192.0.2.0/24".parse().unwrap(),
            line: 1,
        };
        let clamp_global = ModuleDirective::MssClamp {
            prefix: None,
            iface: None,
            mss: 1360,
            line: 2,
        };
        let unrelated = ModuleDirective::DryRun(false);

        assert_eq!(feature_flags_from_config(&[], false), 0);
        assert_eq!(
            feature_flags_from_config(std::slice::from_ref(&unrelated), false),
            0,
            "non-feature directives must not set presence bits"
        );
        assert_eq!(
            feature_flags_from_config(std::slice::from_ref(&block), false),
            FP_CFG_FLAG_BLOCK_PRESENT
        );
        assert_eq!(
            feature_flags_from_config(std::slice::from_ref(&clamp_global), false),
            FP_CFG_FLAG_MSS_CLAMP_PRESENT,
            "any mss-clamp grammar (global included) sets the presence bit"
        );
        assert_eq!(
            feature_flags_from_config(&[], true),
            FP_CFG_FLAG_VLAN_PRESENT
        );
        assert_eq!(
            feature_flags_from_config(&[block, clamp_global, unrelated], true),
            FP_CFG_FLAG_BLOCK_PRESENT | FP_CFG_FLAG_MSS_CLAMP_PRESENT | FP_CFG_FLAG_VLAN_PRESENT
        );
    }

    /// The pure core of bridge-chain discovery: only a bridge with
    /// exactly one member, that member forwarding, that member a VLAN
    /// subif, collapses. Everything else stays on the kernel path.
    #[test]
    fn bridge_vlan_chains_truth_table() {
        let vlans = vec![
            ("switch0.1337".to_string(), 1337u16, "switch0".to_string()),
            ("switch0.88".to_string(), 88u16, "switch0".to_string()),
        ];
        let m = |name: &str, fwd: bool| (name.to_string(), fwd);

        // Single forwarding member that is a VLAN subif → collapses.
        let bridges = vec![("br1337".to_string(), vec![m("switch0.1337", true)])];
        assert_eq!(
            bridge_vlan_chains(&bridges, &vlans),
            vec![("br1337".to_string(), "switch0".to_string(), 1337)]
        );

        // Two members — even with one blocked — never collapses: the
        // blocked port can transition to forwarding, and then port
        // choice needs the FDB.
        let bridges = vec![(
            "br1337".to_string(),
            vec![m("switch0.1337", true), m("eth9", false)],
        )];
        assert!(bridge_vlan_chains(&bridges, &vlans).is_empty());

        // Single member but not forwarding (STP blocking/disabled).
        let bridges = vec![("br1337".to_string(), vec![m("switch0.1337", false)])];
        assert!(bridge_vlan_chains(&bridges, &vlans).is_empty());

        // Single forwarding member that is NOT a VLAN subif.
        let bridges = vec![("br0".to_string(), vec![m("eth7", true)])];
        assert!(bridge_vlan_chains(&bridges, &vlans).is_empty());

        // Zero members.
        let bridges = vec![("brempty".to_string(), vec![])];
        assert!(bridge_vlan_chains(&bridges, &vlans).is_empty());

        // Mixed host: qualifying and non-qualifying bridges coexist.
        let bridges = vec![
            ("br1337".to_string(), vec![m("switch0.1337", true)]),
            ("br88".to_string(), vec![m("switch0.88", true)]),
            ("br0".to_string(), vec![m("switch0.1", true)]), // .1 not in vlans
            (
                "brmulti".to_string(),
                vec![m("switch0.88", true), m("switch0.1337", true)],
            ),
        ];
        assert_eq!(
            bridge_vlan_chains(&bridges, &vlans),
            vec![
                ("br1337".to_string(), "switch0".to_string(), 1337),
                ("br88".to_string(), "switch0".to_string(), 88),
            ]
        );
    }

    /// Directive semantics: absent/auto/on enable, off disables.
    #[test]
    fn bridge_resolve_directive_semantics() {
        assert!(bridge_resolve_enabled(&[]), "default is auto = enabled");
        for (toggle, want) in [
            (ToggleAutoOnOff::Auto, true),
            (ToggleAutoOnOff::On, true),
            (ToggleAutoOnOff::Off, false),
        ] {
            let d = ModuleDirective::BridgeResolve(toggle);
            assert_eq!(bridge_resolve_enabled(std::slice::from_ref(&d)), want);
        }
    }

    /// Bits 5-7 must never collide with the established bits 0-4.
    #[test]
    fn presence_bits_are_disjoint_from_legacy_bits() {
        let legacy = 0b0001_1111u8; // ipv4|ipv6|head-shift|custom-fib|compare
        for bit in [
            FP_CFG_FLAG_BLOCK_PRESENT,
            FP_CFG_FLAG_VLAN_PRESENT,
            FP_CFG_FLAG_MSS_CLAMP_PRESENT,
        ] {
            assert_eq!(bit & legacy, 0);
        }
    }

    #[test]
    fn default_sysctls_do_not_warn() {
        // Kernel defaults: 1024 per family, far under the 8192 pool.
        assert_eq!(
            gc_thresh3_capacity_warning(Some(1024), Some(1024), 8192),
            None
        );
    }

    /// End-to-end bridge short-circuit against a real topology:
    /// veth → 802.1Q subif → single-member bridge, then
    /// populate/reconcile against a genuinely loaded BPF object.
    /// Proves the sysfs reader (bridge dir, brif members, brport
    /// state), the VLAN_RESOLVE keying on the bridge ifindex, the
    /// `bridge-resolve off` rollback purge, and re-enable convergence.
    ///
    /// Requires CAP_NET_ADMIN + CAP_BPF + the 8021q module; CI runs it
    /// under sudo in the qemu matrix.
    #[test]
    #[ignore = "needs CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
    fn bridge_short_circuit_populate_and_reconcile() {
        use aya::maps::HashMap as AyaHashMap;

        if !crate::FAST_PATH_BPF_AVAILABLE {
            eprintln!("BPF stub in effect (no rustup); skipping bridge-resolve test.");
            return;
        }

        const VETH_A: &str = "pf-brv0";
        const VETH_B: &str = "pf-brv1";
        const SUBIF: &str = "pf-brv0.42";
        const BRIDGE: &str = "pf-brtst";
        const VID: u16 = 42;

        struct Cleanup;
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // veth del removes the pair + the subif riding on it.
                let _ = std::process::Command::new("ip")
                    .args(["link", "del", VETH_A])
                    .status();
                let _ = std::process::Command::new("ip")
                    .args(["link", "del", BRIDGE])
                    .status();
            }
        }
        fn run(cmd: &[&str]) {
            let st = std::process::Command::new(cmd[0])
                .args(&cmd[1..])
                .status()
                .unwrap_or_else(|e| panic!("spawn `{}`: {e}", cmd.join(" ")));
            assert!(st.success(), "`{}` failed: {st}", cmd.join(" "));
        }

        // Idempotent pre-clean, then build the topology.
        let _ = std::process::Command::new("ip")
            .args(["link", "del", VETH_A])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["link", "del", BRIDGE])
            .status();
        run(&[
            "ip", "link", "add", VETH_A, "type", "veth", "peer", "name", VETH_B,
        ]);
        let _cleanup = Cleanup;
        run(&[
            "ip", "link", "add", "link", VETH_A, "name", SUBIF, "type", "vlan", "id", "42",
        ]);
        // STP off (default) → the port enters forwarding as soon as
        // the link is up.
        run(&["ip", "link", "add", BRIDGE, "type", "bridge"]);
        run(&["ip", "link", "set", SUBIF, "master", BRIDGE]);
        for dev in [VETH_A, VETH_B, SUBIF, BRIDGE] {
            run(&["ip", "link", "set", dev, "up"]);
        }
        // brport/state flips to forwarding asynchronously; poll briefly.
        let state_path = format!("/sys/class/net/{SUBIF}/brport/state");
        for _ in 0..50 {
            if std::fs::read_to_string(&state_path).is_ok_and(|s| s.trim() == "3") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        // Discovery alone must find exactly our chain (the host may
        // have other bridges; filter to ours).
        let auto_cfg =
            packetframe_common::config::Config::parse("module fast-path\n  bridge-resolve auto\n")
                .unwrap();
        let chains =
            discover_bridge_chains(&auto_cfg.modules[0].directives).expect("bridge topology read");
        assert!(
            chains.contains(&(BRIDGE.to_string(), VETH_A.to_string(), VID)),
            "expected {BRIDGE} → ({VETH_A}, {VID}) in {chains:?}"
        );

        // Full populate + reconcile against a real BPF object.
        let bytes = crate::aligned_bpf_copy();
        let ebpf = aya::Ebpf::load(&bytes).expect("Ebpf::load");
        let tmp = std::env::temp_dir().join(format!("pf-brtest-{}", std::process::id()));
        let mut state = ActiveState {
            ebpf,
            links: Vec::new(),
            state_dir: tmp.clone(),
            bpffs_root: tmp,
            route_controller: None,
            attach_settle_time: std::time::Duration::ZERO,
        };

        let bridge_idx = if_nametoindex(BRIDGE).unwrap();
        let veth_idx = if_nametoindex(VETH_A).unwrap();
        let read_entry = |state: &mut ActiveState| -> Option<(u32, u16)> {
            let map = state.ebpf.map_mut("VLAN_RESOLVE").unwrap();
            let hm: AyaHashMap<_, u32, VlanResolve> = AyaHashMap::try_from(map).unwrap();
            hm.get(&bridge_idx, 0).ok().map(|v| (v.phys_ifindex, v.vid))
        };
        let flag_set = |state: &mut ActiveState| -> bool {
            let map = state.ebpf.map_mut("CFG").unwrap();
            let arr: Array<_, FpCfg> = Array::try_from(map).unwrap();
            arr.get(&0, 0).unwrap().flags & FP_CFG_FLAG_VLAN_PRESENT != 0
        };

        populate_vlan_resolve(&mut state, &auto_cfg.modules[0].directives)
            .expect("populate with bridge-resolve auto");
        assert_eq!(
            read_entry(&mut state),
            Some((veth_idx, VID)),
            "bridge key must map to (underlying device, VID)"
        );
        assert!(flag_set(&mut state), "bit 6 must be set after populate");

        // SIGHUP rollback: bridge-resolve off purges the bridge key but
        // keeps the plain subif entry (it's a normal 8021q resolve).
        let off_cfg =
            packetframe_common::config::Config::parse("module fast-path\n  bridge-resolve off\n")
                .unwrap();
        let mcfg =
            packetframe_common::module::ModuleConfig::new(&off_cfg.modules[0], &off_cfg.global);
        crate::reconcile::reconcile_vlan_resolve(&mut state, &mcfg)
            .expect("reconcile with bridge-resolve off");
        assert_eq!(
            read_entry(&mut state),
            None,
            "bridge key must be purged when the directive is off"
        );
        {
            let map = state.ebpf.map_mut("VLAN_RESOLVE").unwrap();
            let hm: AyaHashMap<_, u32, VlanResolve> = AyaHashMap::try_from(map).unwrap();
            let subif_idx = if_nametoindex(SUBIF).unwrap();
            assert!(
                hm.get(&subif_idx, 0).is_ok(),
                "plain 8021q subif entry must survive bridge-resolve off"
            );
        }
        assert!(
            flag_set(&mut state),
            "bit 6 stays set — the subif entries still exist"
        );

        // Re-enable converges the key back.
        let mcfg =
            packetframe_common::module::ModuleConfig::new(&auto_cfg.modules[0], &auto_cfg.global);
        crate::reconcile::reconcile_vlan_resolve(&mut state, &mcfg)
            .expect("reconcile with bridge-resolve auto");
        assert_eq!(read_entry(&mut state), Some((veth_idx, VID)));

        // Same-key value change must converge in ONE reconcile: swap
        // the bridge's member for a different-VID subif. The bridge
        // keeps its ifindex, so the full-tuple diff sees an add and a
        // remove under one key — the remove pass must not delete the
        // freshly written value (the Codex-found off-by-one-reconcile).
        run(&["ip", "link", "del", SUBIF]);
        run(&[
            "ip",
            "link",
            "add",
            "link",
            VETH_A,
            "name",
            "pf-brv0.43",
            "type",
            "vlan",
            "id",
            "43",
        ]);
        run(&["ip", "link", "set", "pf-brv0.43", "master", BRIDGE]);
        run(&["ip", "link", "set", "pf-brv0.43", "up"]);
        let state43 = "/sys/class/net/pf-brv0.43/brport/state";
        for _ in 0..50 {
            if std::fs::read_to_string(state43).is_ok_and(|s| s.trim() == "3") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        crate::reconcile::reconcile_vlan_resolve(&mut state, &mcfg)
            .expect("reconcile after member swap");
        assert_eq!(
            read_entry(&mut state),
            Some((veth_idx, 43)),
            "value change under a stable bridge key must survive one reconcile"
        );

        // A VLAN-filtering bridge must never qualify.
        run(&[
            "ip",
            "link",
            "set",
            BRIDGE,
            "type",
            "bridge",
            "vlan_filtering",
            "1",
        ]);
        let chains =
            discover_bridge_chains(&auto_cfg.modules[0].directives).expect("bridge topology read");
        assert!(
            !chains.iter().any(|(b, _, _)| b == BRIDGE),
            "vlan_filtering bridge must be excluded, got {chains:?}"
        );
    }

    #[test]
    fn raised_thresholds_warn_with_both_values() {
        let w = gc_thresh3_capacity_warning(Some(8192), Some(16384), 8192)
            .expect("must warn when the sum exceeds the pool");
        assert!(w.contains("24576"), "total in message: {w}");
        assert!(w.contains("8192 + 16384"), "per-family values: {w}");
    }

    #[test]
    fn boundary_is_exclusive() {
        // Exactly at the cap is not over-committed; only exceeding warns.
        assert_eq!(
            gc_thresh3_capacity_warning(Some(4096), Some(4096), 8192),
            None
        );
        assert!(gc_thresh3_capacity_warning(Some(4096), Some(4097), 8192).is_some());
    }

    #[test]
    fn unreadable_sysctls_never_warn() {
        // Containers and exotic kernels may not expose the sysctl at
        // all; the advisory check must stay silent rather than guess.
        assert_eq!(gc_thresh3_capacity_warning(None, None, 8192), None);
        // ...but a single readable family that alone exceeds the pool
        // still warns.
        assert!(gc_thresh3_capacity_warning(Some(65536), None, 8192).is_some());
    }
}
