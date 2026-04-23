//! Linux-only loader logic: `aya::Ebpf` lifecycle, XDP attach with
//! trial-attach fallback per SPEC.md §2.3, map population.
//!
//! Kept in a cfg-gated module so `lib.rs` can express the trait impl
//! once and dispatch to either real logic (here) or a NotImplemented
//! stub (`stub_impl.rs`). macOS dev loops compile either way.

use std::ffi::CString;
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
        AttachMode, DriverWorkaround, Ipv4Prefix, Ipv6Prefix, ModuleDirective, ToggleAutoOnOff,
    },
    module::{Attachment, HookType, LoaderCtx, ModuleConfig, ModuleError, ModuleResult},
};
use tracing::{info, warn};

use crate::{aligned_bpf_copy, pin, FAST_PATH_BPF_AVAILABLE, MODULE_NAME};

/// Layout mirror of `FpCfg` in `bpf/src/maps.rs` (PR #3). `#[repr(C)]`
/// with all-bit-patterns-valid primitive fields, so `aya::Pod` is safe
/// to impl — the marker tells aya the struct is safe to byte-copy into
/// the kernel's map buffer. Bytes-for-bytes match the BPF-side struct.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FpCfg {
    pub dry_run: u8,
    pub flags: u8,
    pub _reserved: [u8; 2],
    pub version: u32,
}

// SAFETY: FpCfg is repr(C), contains only primitive integer types and
// a fixed-size byte array — every bit pattern is a valid FpCfg. No
// padding that could leak uninitialized memory (u8/u8/[u8;2]/u32 packs
// exactly into 8 bytes on every target). Aya uses this to byte-copy
// the struct into the kernel's array value slot.
unsafe impl aya::Pod for FpCfg {}

pub(crate) const FP_CFG_VERSION_V1: u32 = 0;

/// Mirror of `bpf/src/maps.rs::FP_CFG_FLAG_HEAD_SHIFT_128`. Enables
/// the pre-Linux-v6.8 rvu-nicpf `xdp_prepare_buff` workaround (SPEC
/// §11.1(c)). Keep in lockstep with the BPF side.
pub(crate) const FP_CFG_FLAG_HEAD_SHIFT_128: u8 = 0b0000_0100;

/// Mirror of `bpf/src/maps.rs::FP_CFG_FLAG_CUSTOM_FIB` (Option F).
/// Set when `forwarding-mode` is `custom-fib` or `compare`; routes
/// the XDP program to consult `FIB_V4`/`FIB_V6` instead of
/// `bpf_fib_lookup()`. Not yet read from the XDP program — Phase 1
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
/// `/sys/bus/pci/drivers/<module_name>` — for this driver the kernel
/// module is `rvu_nicpf.ko`, so the sysfs leaf is `rvu_nicpf` (with
/// an underscore). `ethtool -i` happens to print the pci_driver's
/// `name` field as `rvu-nicpf` (with a hyphen) on the reference
/// hardware, which had us matching the wrong spelling in v0.1.3 —
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

/// All state required to keep the attached program alive.
///
/// After `attach`, the XDP program, every §4.5 map, and each per-iface
/// link is pinned under `<bpffs-root>/fast-path/`. Dropping
/// `ActiveState` closes our userspace FDs but the bpffs inodes hold
/// the kernel references — SPEC.md §8.5 "exit without detach" works as
/// soon as pinning is in place. `Module::detach` unlinks the pins,
/// which is when the kernel actually tears everything down.
pub struct ActiveState {
    pub ebpf: Ebpf,
    pub links: Vec<LinkRecord>,
    pub state_dir: PathBuf,
    pub bpffs_root: PathBuf,
}

/// One XDP attach. `effective_mode` records what actually stuck in
/// `Auto` mode so `status` can report it. `link` is either:
///
/// - `Pinned(PinnedLink)` — the happy path; dropping closes the
///   userspace FD but leaves the bpffs inode, so the kernel attach
///   survives process exit (§8.5).
/// - `Transient(FdLink)` — pin syscall was rejected (e.g. EPERM on
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
}

impl LinkHandle {
    pub fn is_pinned(&self) -> bool {
        matches!(self, LinkHandle::Pinned(_))
    }
}

pub fn load(cfg: &ModuleConfig<'_>, ctx: &LoaderCtx<'_>) -> ModuleResult<ActiveState> {
    if !FAST_PATH_BPF_AVAILABLE {
        return Err(ModuleError::other(
            MODULE_NAME,
            "no BPF ELF embedded in the binary — build with rustup + nightly + bpf-linker (see CLAUDE.md)",
        ));
    }

    // Refuse startup when pins from a prior invocation survive.
    // SPEC.md §8.5 "exit without detach" leaves pins in bpffs after
    // SIGTERM; v0.1 does not adopt those — operator must run
    // `packetframe detach --all` first. Full adoption (zero-disruption
    // restart) is deferred.
    if pin::has_existing_pins(ctx.bpffs_root) {
        return Err(ModuleError::other(
            MODULE_NAME,
            format!(
                "existing pins under {} from a prior invocation — \
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
    // aya handles that path internally. Use an aligned copy — the
    // embedded `include_bytes!` slice is 1-byte-aligned which the
    // object crate's ELF parser rejects.
    let bytes = aligned_bpf_copy();
    let mut ebpf = Ebpf::load(&bytes)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("aya::Ebpf::load failed: {e}")))?;

    populate_cfg(&mut ebpf, cfg)?;
    populate_allowlists(&mut ebpf, cfg)?;

    Ok(ActiveState {
        ebpf,
        links: Vec::new(),
        state_dir: ctx.state_dir.to_path_buf(),
        bpffs_root: ctx.bpffs_root.to_path_buf(),
    })
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

    let fp_cfg = FpCfg {
        dry_run: u8::from(dry_run),
        flags: 0b11, // both IPv4 and IPv6 enabled; bit semantics reserved
        _reserved: [0; 2],
        version: FP_CFG_VERSION_V1,
    };

    let map = ebpf
        .map_mut("CFG")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "CFG map missing from ELF"))?;
    let mut cfg_arr: Array<_, FpCfg> = Array::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG map Array::try_from: {e}")))?;

    cfg_arr
        .set(0, fp_cfg, 0)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("CFG map set: {e}")))?;

    info!(dry_run, "fast-path cfg populated");
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

pub fn attach(state: &mut ActiveState, cfg: &ModuleConfig<'_>) -> ModuleResult<Vec<Attachment>> {
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
    // from userspace — every native XDP attach leaks the count, and
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
    // SPEC.md §11.8 — XDP attach on some drivers (rvu-nicpf observed)
    // briefly bounces the link. If multiple attach ifaces share a
    // bridge master, attaching them inside one STP reconvergence
    // window risks an L2 loop and packet storm. Sleep
    // `attach_settle_time` between attaches so each link stabilizes
    // before the next touches the driver. 0s disables (useful on
    // non-bridge topologies).
    let settle_time = cfg.global.attach_settle_time;
    for (idx, (iface, mode, ifindex)) in attach_dirs.iter().enumerate() {
        if idx > 0 && !settle_time.is_zero() {
            info!(
                settle_secs = settle_time.as_secs_f64(),
                next_iface = %iface,
                "waiting for link to settle before next attach (§11.8)"
            );
            std::thread::sleep(settle_time);
        }
        let (effective_mode, link) =
            try_attach_with_fallback(prog, *ifindex, iface, *mode, &state.bpffs_root)?;
        let persist = link.is_pinned();
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
    // physical port the FIB resolved to" — aya accepts this.
    let devmap_map = state
        .ebpf
        .map_mut("REDIRECT_DEVMAP")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "REDIRECT_DEVMAP map missing from ELF"))?;
    let mut devmap: DevMapHash<_> = DevMapHash::try_from(devmap_map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("REDIRECT_DEVMAP try_from: {e}")))?;

    // Populate REDIRECT_DEVMAP with every UP Ethernet-type iface on the
    // host, not just the attach ifaces. The FIB lookup is dynamic — on
    // a BGP edge, routes change and the egress iface for any given
    // packet is determined at lookup time. Hardcoding the attach list
    // as the egress allowlist breaks any topology where ingress ≠
    // egress (classic edge router: trunks in, WAN out).
    //
    // Filter: `/sys/class/net/<iface>/type == 1` (ARPHRD_ETHER — covers
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

    populate_vlan_resolve(state)?;

    // Pin program + every §4.5 map so `packetframe status` can read
    // counters from a separate process and `packetframe detach` can
    // find what to tear down. Pinning happens after population so a
    // partial-load failure (above) doesn't leave half-initialized maps
    // in bpffs.
    pin_program_and_maps(state)?;

    // Build Attachment records for the pin registry. `pinned_path`
    // points at the real link pin — when `packetframe detach` runs,
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
            },
            prog_id,
            pinned_path: pin::link_path(&state.bpffs_root, &l.iface),
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
/// kernels — set `off` via config override once the operator
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
                 rvu-nicpf-head-shift off`) — assuming Linux v6.8+ or backported fix"
            );
        }
        return Ok(());
    }

    // Read current FpCfg, OR in the flag, write back. We only set —
    // never clear — so we don't clobber the IPv4/IPv6 enable bits
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
        "enabling pre-v6.8 rvu-nicpf head-shift workaround (SPEC §11.1(c)) — fast-path will \
         bpf_xdp_adjust_head(+128) + bpf_xdp_adjust_tail(+128) on every packet to expose the \
         real frame. Set `driver-workaround rvu-nicpf-head-shift off` in the config once the \
         kernel backport lands."
    );
    Ok(())
}

/// Read `/proc/sys/kernel/osrelease` (= `uname -r`) and parse the
/// leading `major.minor`. Returns `None` if the file is unreadable
/// or the format is unrecognizable — callers treat that as "can't
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
            AttachMode::Generic => unreachable!("filtered by wants_native check above"),
        }
    }
    Ok(out)
}

/// Read the kernel driver name backing a netdev via
/// `/sys/class/net/<iface>/device/driver` (a symlink into
/// `/sys/bus/*/drivers/<driver>`). Returns `None` for netdevs that
/// have no underlying device (veth pairs, bridges, loopback) or when
/// the file isn't present. Doesn't try ethtool — sysfs is
/// netns-aware when mounted per-netns and avoids another
/// capability-gated syscall just for a name.
fn read_iface_driver(iface: &str) -> Option<String> {
    let path = format!("/sys/class/net/{iface}/device/driver");
    let target = std::fs::read_link(&path).ok()?;
    target.file_name().map(|s| s.to_string_lossy().into_owned())
}

fn pin_program_and_maps(state: &mut ActiveState) -> ModuleResult<()> {
    let prog_path = pin::program_path(&state.bpffs_root);
    {
        let prog: &mut Xdp = state
            .ebpf
            .program_mut(pin::PROGRAM_NAME)
            .ok_or_else(|| ModuleError::other(MODULE_NAME, "fast_path program missing for pin"))?
            .try_into()
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("pin: program not XDP: {e}")))?;
        prog.pin(&prog_path).map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("pin program at {}: {e}", prog_path.display()),
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
        "program + maps pinned"
    );
    Ok(())
}

/// §2.3: per-interface trial-attach. `Native` and `Generic` are explicit
/// (no fallback); `Auto` tries native first, falls back to generic on
/// any error. The spec calls out that `bpftool feature probe` is
/// unreliable — we find out what works by actually trying. Each
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
/// - `LinkHandle::Pinned` on success — the kernel attach survives
///   process exit via the bpffs inode.
/// - `LinkHandle::Transient` if pinning was rejected (EPERM on
///   generic-mode XDP links on some kernels, for instance). The
///   attach still works, but dropping the returned `FdLink` detaches
///   the kernel-side program.
///
/// Hard errors (attach fails, `take_link` fails, link isn't
/// bpf_link_create-backed) remain hard errors — the caller bubbles
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
            // pin — that path is reachable only if someone runs on a
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
            // consumes `self` even on error — the link FD is already
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
/// string — aya's `SyscallError` hides the underlying `io::Error`
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

/// Populate `vlan_resolve` from `/proc/net/vlan/config`. Each VLAN
/// subinterface maps its ifindex → (physical parent ifindex, VID) so
/// the BPF program can push/pop/rewrite per SPEC §4.7 when the FIB
/// resolves to a subif. Missing `/proc/net/vlan/config` (no 8021q
/// kernel module loaded) is not an error — we just insert nothing.
fn populate_vlan_resolve(state: &mut ActiveState) -> ModuleResult<()> {
    let entries = match read_vlan_config() {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            info!("/proc/net/vlan/config missing — no VLAN subifs to resolve");
            return Ok(());
        }
        Err(e) => {
            return Err(ModuleError::other(
                MODULE_NAME,
                format!("read /proc/net/vlan/config: {e}"),
            ));
        }
    };

    if entries.is_empty() {
        info!("/proc/net/vlan/config empty — no VLAN subifs configured");
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
    // Drop every PinnedLink first: this closes our userspace FDs but
    // the kernel keeps the attach alive via the bpffs inodes. Drain
    // in reverse attach order — no practical consequence here, matches
    // typical lifecycle expectations.
    while let Some(link) = state.links.pop() {
        info!(iface = %link.iface, "fast-path detaching");
        drop(link);
    }

    // Unlink every pin under the module's pin root. Removing link
    // pins triggers the kernel-side detach; removing map + program
    // pins is housekeeping.
    pin::remove_all(&state.bpffs_root)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("remove pins: {e}")))?;
    info!("fast-path pins removed; kernel detached");
    Ok(())
}

/// Walk `/sys/class/net` and return the `(name, ifindex)` of every
/// iface that's a viable XDP redirect target:
///
/// - `type == 1` (ARPHRD_ETHER) — covers physical NICs, bridges,
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
/// master. SPEC.md §11.8 — on drivers that bounce the link at attach
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
            "multiple attach ifaces share bridge master — XDP attach can cause L2 loops \
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
/// verdict. The no-op program is the `fast_path` program itself —
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
            // Detach immediately — this was a probe.
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

// Read current stats — aggregated across all CPUs.
pub fn snapshot_stats(state: &ActiveState) -> ModuleResult<Vec<u64>> {
    use aya::maps::PerCpuArray;

    let map = state
        .ebpf
        .map("STATS")
        .ok_or_else(|| ModuleError::other(MODULE_NAME, "STATS map missing from ELF"))?;
    let stats: PerCpuArray<_, u64> = PerCpuArray::try_from(map).map_err(|e| {
        ModuleError::other(MODULE_NAME, format!("STATS PerCpuArray::try_from: {e}"))
    })?;

    read_stats(&stats)
}

/// Read STATS directly from the bpffs pin — no live module required.
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
    let stats: PerCpuArray<_, u64> = PerCpuArray::try_from(map)
        .map_err(|e| ModuleError::other(MODULE_NAME, format!("STATS PerCpuArray: {e}")))?;
    read_stats(&stats)
}

fn read_stats<T: std::borrow::Borrow<aya::maps::MapData>>(
    stats: &aya::maps::PerCpuArray<T, u64>,
) -> ModuleResult<Vec<u64>> {
    // `STATS_COUNT` in bpf/src/maps.rs is 32 as of Phase 1 (20 core
    // + 12 custom-FIB). Previous versions hardcoded 19 — an off-by-one
    // that hid the `err_head_shift` counter from status readback.
    // Keep this in lockstep with the BPF side or the last counters
    // show zero unfairly.
    const STATS_LEN: usize = 32;
    let mut out = vec![0u64; STATS_LEN];
    for (idx, slot) in out.iter_mut().enumerate() {
        let values = stats
            .get(&(idx as u32), 0)
            .map_err(|e| ModuleError::other(MODULE_NAME, format!("STATS get[{idx}]: {e}")))?;
        *slot = values.iter().copied().sum();
    }
    Ok(out)
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
