//! flow-export's kernel sampler (Linux): `kernel_sample` on the clsact
//! ingress of each `kernel-sample` interface, for traffic no fast-path
//! program or VPP sees. It only looks (`TC_ACT_UNSPEC`).
//!
//! The attach/detach pair mirrors guard's (its `linux_impl.rs`, itself
//! fast-path's) with `TcAttachType::Ingress`; when one is updated, the
//! others likely need the same change. The load-bearing choices carry
//! over:
//!
//! - **Netlink cls_bpf**, never TCX: the filter lives as long as its
//!   qdisc and yields the `(priority, handle)` pair a later process
//!   needs to remove it.
//! - aya's link is forgotten once that pair is persisted; dropping it
//!   would detach the filter.
//! - The record file is saved after **every** attach, so a failure part
//!   way leaves each live filter findable; a filter whose record could
//!   not be saved is taken back down.
//! - A record is dropped only when its filter is provably gone.
//!
//! Nothing is pinned: the filters hold the program, and the program its
//! maps, so removing the filters is the whole teardown.

use std::path::Path;

use aya::maps::{Array, Map, MapData, PerCpuArray};
use aya::Ebpf;
use packetframe_fast_path::sample::SampleCfg;
use tracing::info;

use crate::tc_links::{self, TcLinkRecord, TcLinksFile};
use crate::{aligned_kernel_sample_copy, KERNEL_SAMPLE_BPF_AVAILABLE};

pub const PROGRAM: &str = "kernel_sample";
const STATE_WORDS: usize = 4;
const EMIT_FAILED: usize = 3;

/// The running sampler: the object whose program the filters hold, and
/// the maps flow export reads and writes.
pub struct KernelSampler {
    pub ebpf: Ebpf,
    pub cfg: Array<MapData, SampleCfg>,
    pub samples: MapData,
    pub state: PerCpuArray<MapData, [u64; STATE_WORDS]>,
    /// `(iface, ifindex)`, in config order.
    pub attached: Vec<(String, u32)>,
}

/// The program's cumulative count of samples it could not output.
pub fn emit_failed(state: &PerCpuArray<MapData, [u64; STATE_WORDS]>) -> Option<u64> {
    let per_cpu = state.get(&0, 0).ok()?;
    Some(per_cpu.iter().map(|w| w[EMIT_FAILED]).sum())
}

fn ifindex_of(iface: &str) -> Option<u32> {
    let c = std::ffi::CString::new(iface).ok()?;
    // SAFETY: a NUL-terminated name that outlives the call.
    let i = unsafe { libc::if_nametoindex(c.as_ptr()) };
    (i != 0).then_some(i)
}

/// The devices `iface` sits on (`lower_*` in sysfs), and theirs, a few
/// levels down: a VLAN on a bond on a port.
fn lowers(iface: &str, depth: u32) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(Path::new("/sys/class/net").join(iface)) else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if let Some(lower) = name.strip_prefix("lower_") {
            if depth > 0 {
                out.extend(lowers(lower, depth - 1));
            }
            out.push(lower.to_owned());
        }
    }
    out
}

/// Why `iface` may not be sampled by the kernel sampler, if it may not.
/// `sampled`: the ports fast-path's programs or VPP sample. A packet is
/// sampled once, where it is first seen: a device stacked on a sampled
/// port would see those packets a second time.
pub fn refusal(iface: &str, sampled: &[String]) -> Option<String> {
    let base = Path::new("/sys/class/net").join(iface);
    if !base.exists() {
        return Some(format!("{iface} does not exist"));
    }
    let flags = std::fs::read_to_string(base.join("flags"))
        .ok()
        .and_then(|f| u32::from_str_radix(f.trim().trim_start_matches("0x"), 16).ok())
        .unwrap_or(0);
    if flags & libc::IFF_LOOPBACK as u32 != 0 {
        return Some(format!("{iface} is a loopback"));
    }
    if let Some(port) = lowers(iface, 4).into_iter().find(|l| sampled.contains(l)) {
        return Some(format!(
            "{iface} sits on {port}, whose packets are sampled already"
        ));
    }
    None
}

/// Load the sampler and attach it to each of `ifaces`, refusing any
/// [`refusal`] names first. A failure part way takes down what this call
/// attached.
pub fn attach(
    state_dir: &Path,
    ifaces: &[String],
    sampled: &[String],
) -> Result<KernelSampler, String> {
    if !KERNEL_SAMPLE_BPF_AVAILABLE {
        return Err(
            "this build carries no kernel sampler (built without the BPF toolchain)".into(),
        );
    }
    for iface in ifaces {
        if let Some(why) = refusal(iface, sampled) {
            return Err(format!("kernel-sample {iface}: {why}"));
        }
    }
    // A daemon that died left its filters sampling into rings no one
    // reads: gone before ours go on.
    detach_from_state_dir(state_dir)?;
    let mut ebpf = Ebpf::load(&aligned_kernel_sample_copy())
        .map_err(|e| format!("load the kernel sampler: {e}"))?;
    {
        use aya::programs::tc::SchedClassifier;
        let prog: &mut SchedClassifier = ebpf
            .program_mut(PROGRAM)
            .ok_or("kernel_sample missing from the ELF")?
            .try_into()
            .map_err(|e| format!("kernel_sample program type: {e}"))?;
        prog.load()
            .map_err(|e| format!("kernel_sample load (verifier?): {e}"))?;
    }
    let take = |ebpf: &mut Ebpf, name: &str| -> Result<Map, String> {
        ebpf.take_map(name)
            .ok_or_else(|| format!("{name} missing from the ELF"))
    };
    let cfg = Array::try_from(take(&mut ebpf, "KSAMPLE_CFG")?)
        .map_err(|e| format!("KSAMPLE_CFG: {e}"))?;
    let samples = match take(&mut ebpf, "KSAMPLES")? {
        Map::PerfEventArray(m) => m,
        _ => return Err("KSAMPLES is not a perf event array".into()),
    };
    let state = PerCpuArray::try_from(take(&mut ebpf, "KSAMPLE_STATE")?)
        .map_err(|e| format!("KSAMPLE_STATE: {e}"))?;
    let mut sampler = KernelSampler {
        ebpf,
        cfg,
        samples,
        state,
        attached: Vec::new(),
    };
    if let Err(e) = attach_all(&mut sampler, state_dir, ifaces) {
        let cleanup = match detach_from_state_dir(state_dir) {
            Ok(_) => "what was attached is taken down".to_string(),
            Err(de) => format!(
                "taking down what was attached ALSO failed ({de}): run `packetframe detach --all`"
            ),
        };
        return Err(format!("{e}; {cleanup}"));
    }
    Ok(sampler)
}

fn attach_all(
    sampler: &mut KernelSampler,
    state_dir: &Path,
    ifaces: &[String],
) -> Result<(), String> {
    let mut records = TcLinksFile { links: Vec::new() };
    for iface in ifaces {
        let ifindex = ifindex_of(iface).ok_or_else(|| format!("{iface} does not exist"))?;
        let (priority, handle) = tc_attach_ingress(&mut sampler.ebpf, iface)?;
        records.links.push(TcLinkRecord {
            iface: iface.clone(),
            ifindex,
            priority,
            handle,
        });
        if let Err(e) = tc_links::save(state_dir, &records) {
            let rollback = match tc_detach_one(iface, ifindex, priority, handle) {
                Ok(()) => format!("the filter just attached on {iface} is taken down"),
                Err(msg) => format!(
                    "taking it down ALSO failed ({msg}): a filter on {iface} has no record; \
                     remove it with `tc filter del dev {iface} ingress`"
                ),
            };
            return Err(format!("persist tc links: {e}; {rollback}"));
        }
        sampler.attached.push((iface.clone(), ifindex));
        info!(iface, ifindex, priority, handle, "kernel sampler attached");
    }
    Ok(())
}

/// Remove every filter the record file names; the number removed. A
/// filter whose removal failed keeps its record, and the call fails.
pub fn detach_from_state_dir(state_dir: &Path) -> Result<usize, String> {
    let links = tc_links::load(state_dir)
        .map_err(|e| format!("read flow-export tc links: {e}"))?
        .map(|f| f.links)
        .unwrap_or_default();
    let (mut cleared, mut retained, mut errors) = (0, Vec::new(), Vec::new());
    for rec in links {
        match tc_detach_one(&rec.iface, rec.ifindex, rec.priority, rec.handle) {
            Ok(()) => cleared += 1,
            Err(e) => {
                errors.push(e);
                retained.push(rec);
            }
        }
    }
    if retained.is_empty() {
        tc_links::remove(state_dir).map_err(|e| format!("remove flow-export tc links: {e}"))?;
        Ok(cleared)
    } else {
        tc_links::save(state_dir, &TcLinksFile { links: retained })
            .map_err(|e| format!("retain flow-export tc links: {e}"))?;
        Err(format!(
            "{}; records kept: rerun `packetframe detach`, or `tc filter del dev <iface> ingress`",
            errors.join("; AND ")
        ))
    }
}

fn tc_attach_ingress(ebpf: &mut Ebpf, iface: &str) -> Result<(u16, u32), String> {
    use aya::programs::tc::{
        qdisc_add_clsact, NlOptions, SchedClassifier, TcAttachOptions, TcAttachType,
    };
    match qdisc_add_clsact(iface) {
        Ok(()) => info!(iface, "clsact qdisc added"),
        // Already there (guard's egress filter, another tool, a prior
        // run): attaching to it is what we want.
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {}
        Err(e) => return Err(format!("qdisc_add_clsact({iface}): {e}")),
    }
    let prog: &mut SchedClassifier = ebpf
        .program_mut(PROGRAM)
        .ok_or("kernel_sample missing after load")?
        .try_into()
        .map_err(|e| format!("kernel_sample type: {e}"))?;
    let id = prog
        .attach_with_options(
            iface,
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions::default()),
        )
        .map_err(|e| format!("tc ingress attach on {iface}: {e}"))?;
    let link = prog
        .take_link(id)
        .map_err(|e| format!("take_link({iface}): {e}"))?;
    let priority = link
        .priority()
        .map_err(|e| format!("link priority({iface}): {e}"))?;
    let handle = link
        .handle()
        .map_err(|e| format!("link handle({iface}): {e}"))?;
    // The filter outlives this scope; dropping the link would detach it.
    std::mem::forget(link);
    Ok((priority, handle))
}

fn tc_detach_one(
    iface: &str,
    expected_ifindex: u32,
    priority: u16,
    handle: u32,
) -> Result<(), String> {
    use aya::programs::tc::{SchedClassifierLink, TcAttachType, TcError};
    use aya::programs::{Link as _, ProgramError};
    // A same-name device with another ifindex was recreated: the recorded
    // filter died with the old one, and a delete by name could take an
    // unrelated filter with a colliding (priority, handle).
    match ifindex_of(iface) {
        None => return Ok(()),
        Some(i) if i != expected_ifindex => return Ok(()),
        Some(_) => {}
    }
    let Ok(link) = SchedClassifierLink::attached(iface, TcAttachType::Ingress, priority, handle)
    else {
        return Ok(());
    };
    match link.detach() {
        Ok(()) => Ok(()),
        // No such filter, or no such qdisc: nothing of ours is attached.
        Err(ProgramError::TcError(TcError::NetlinkError { io_error }))
            if matches!(
                io_error.raw_os_error(),
                Some(libc::ENOENT) | Some(libc::EINVAL)
            ) =>
        {
            Ok(())
        }
        Err(e) => Err(format!(
            "tc detach on {iface} (priority {priority}, handle {handle}): {e}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_loopback_and_missing_devices_are_refused() {
        assert!(refusal("lo", &[]).unwrap().contains("loopback"));
        assert!(refusal("pf-no-such-dev0", &[])
            .unwrap()
            .contains("does not exist"));
    }
}
