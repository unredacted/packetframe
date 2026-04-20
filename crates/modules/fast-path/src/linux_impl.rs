//! Linux-only loader logic: `aya::Ebpf` lifecycle, XDP attach with
//! trial-attach fallback per SPEC.md §2.3, map population.
//!
//! Kept in a cfg-gated module so `lib.rs` can express the trait impl
//! once and dispatch to either real logic (here) or a NotImplemented
//! stub (`stub_impl.rs`). macOS dev loops compile either way.

use std::ffi::CString;
use std::path::{Path, PathBuf};

use aya::{
    maps::{lpm_trie::Key as LpmKey, xdp::DevMapHash, Array, LpmTrie},
    programs::{xdp::XdpFlags, Xdp},
    Ebpf,
};
use packetframe_common::{
    config::{AttachMode, Ipv4Prefix, Ipv6Prefix, ModuleDirective},
    module::{Attachment, HookType, LoaderCtx, ModuleConfig, ModuleError, ModuleResult},
};
use tracing::{info, warn};

use crate::{FAST_PATH_BPF, FAST_PATH_BPF_AVAILABLE, MODULE_NAME};

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

const FP_CFG_VERSION_V1: u32 = 0;

/// All state required to keep the attached program alive.
/// `Drop` on `Ebpf` unloads the program + maps, which is what we want
/// for a clean detach. SPEC.md §8.5 note: the loader can crash and the
/// kernel will keep the program attached via pinning — pinning lands
/// later in this PR; until then, a crash detaches.
pub struct ActiveState {
    pub ebpf: Ebpf,
    pub links: Vec<LinkRecord>,
    pub state_dir: PathBuf,
    pub bpffs_root: PathBuf,
}

/// One XDP attach. `effective_mode` records what actually stuck in
/// `Auto` mode so `status` can report it.
pub struct LinkRecord {
    pub iface: String,
    pub ifindex: u32,
    pub effective_mode: AttachMode,
    pub link_id: aya::programs::xdp::XdpLinkId,
}

pub fn load(cfg: &ModuleConfig<'_>, ctx: &LoaderCtx<'_>) -> ModuleResult<ActiveState> {
    if !FAST_PATH_BPF_AVAILABLE {
        return Err(ModuleError::other(
            MODULE_NAME,
            "no BPF ELF embedded in the binary — build with rustup + nightly + bpf-linker (see CLAUDE.md)",
        ));
    }

    // aya doesn't expose an `Ebpf::load_with_options` that'd let us
    // skip BTF lookup; on the reference EFG (§2.2) BTF is absent but
    // aya handles that path internally.
    let mut ebpf = Ebpf::load(FAST_PATH_BPF)
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

    // Attach each interface with trial-attach per §2.3: Auto → try
    // native first, fall back to generic on error; explicit Native or
    // Generic uses the requested mode directly (no fallback).
    for (iface, mode, ifindex) in &attach_dirs {
        let (effective_mode, link_id) = try_attach_with_fallback(prog, *ifindex, iface, *mode)?;
        state.links.push(LinkRecord {
            iface: iface.clone(),
            ifindex: *ifindex,
            effective_mode,
            link_id,
        });
        info!(iface, ifindex, ?effective_mode, "fast-path attached");
    }

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
    for (iface, _mode, ifindex) in &attach_dirs {
        devmap.insert(*ifindex, *ifindex, None, 0).map_err(|e| {
            ModuleError::other(
                MODULE_NAME,
                format!("REDIRECT_DEVMAP insert {iface} (ifindex {ifindex}): {e}"),
            )
        })?;
    }

    // Build Attachment records for the pin registry. `pinned_path` is
    // advisory in v0.1 — actual bpffs pinning lands with reconcile in
    // PR #6 — but we populate the shape so the registry survives
    // incremental upgrades.
    let pin_root = state.bpffs_root.join(MODULE_NAME);
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
            pinned_path: pin_root.join(format!("prog-{}", l.iface)),
        })
        .collect())
}

/// §2.3: per-interface trial-attach. `Native` and `Generic` are explicit
/// (no fallback); `Auto` tries native first, falls back to generic on
/// any error. The spec calls out that `bpftool feature probe` is
/// unreliable — we find out what works by actually trying.
fn try_attach_with_fallback(
    prog: &mut Xdp,
    ifindex: u32,
    iface: &str,
    mode: AttachMode,
) -> ModuleResult<(AttachMode, aya::programs::xdp::XdpLinkId)> {
    match mode {
        AttachMode::Native => prog
            .attach_to_if_index(ifindex, XdpFlags::DRV_MODE)
            .map(|id| (AttachMode::Native, id))
            .map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("native XDP attach to {iface} failed: {e}"),
                )
            }),
        AttachMode::Generic => prog
            .attach_to_if_index(ifindex, XdpFlags::SKB_MODE)
            .map(|id| (AttachMode::Generic, id))
            .map_err(|e| {
                ModuleError::other(
                    MODULE_NAME,
                    format!("generic XDP attach to {iface} failed: {e}"),
                )
            }),
        AttachMode::Auto => match prog.attach_to_if_index(ifindex, XdpFlags::DRV_MODE) {
            Ok(id) => Ok((AttachMode::Native, id)),
            Err(native_err) => {
                warn!(iface, %native_err, "native XDP attach failed; falling back to generic");
                prog.attach_to_if_index(ifindex, XdpFlags::SKB_MODE)
                    .map(|id| (AttachMode::Generic, id))
                    .map_err(|generic_err| {
                        ModuleError::other(
                            MODULE_NAME,
                            format!(
                                "auto XDP attach to {iface}: native failed ({native_err}), generic failed ({generic_err})"
                            ),
                        )
                    })
            }
        },
    }
}

pub fn detach(state: &mut ActiveState) -> ModuleResult<()> {
    // Drain links in reverse attach order so the last-attached
    // interface is detached first — no practical consequence here but
    // it matches typical lifecycle expectations.
    while let Some(link) = state.links.pop() {
        if let Some(prog) = state
            .ebpf
            .program_mut("fast_path")
            .and_then(|p| <&mut Xdp>::try_from(p).ok())
        {
            if let Err(e) = prog.detach(link.link_id) {
                warn!(iface = %link.iface, error = %e, "detach link failed; continuing");
            }
        }
        info!(iface = %link.iface, "fast-path detached");
    }
    Ok(())
}

/// Wrap `libc::if_nametoindex`. Returns a clear error on failure.
fn if_nametoindex(name: &str) -> ModuleResult<u32> {
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
    let mut ebpf = match Ebpf::load(FAST_PATH_BPF) {
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

    let mut out = vec![0u64; 19];
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
