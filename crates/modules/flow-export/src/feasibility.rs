//! flow-export's feasibility probes, grafted into `packetframe
//! feasibility` by the CLI when the config declares the module.
//!
//! All non-required: a failure to start degrades this module and never
//! stops forwarding, so a row here reads "this part of flow export will
//! not work, and why", never "the host is infeasible". The sampler's
//! kernel needs (`bpf_perf_event_output` in XDP and tc, the perf event
//! array) are fast-path's own rows: its ELF carries the sampler.

use std::net::IpAddr;

use packetframe_common::probe::Capability;

/// Where the arm64 package installs VPP's sampler plugin, in the
/// directory vpp-offload adds to VPP's plugin path.
pub const PLUGIN_PATH: &str = "/usr/lib/packetframe/vpp_plugins/pf_sampler_plugin.so";

/// The section VPP's loader reads a plugin's registration from.
const REGISTRATION_SECTION: &str = ".vlib_plugin_registration";

/// The VPP vpp-offload runs without a `vpp-binary`: the `vpp` package's.
pub const DEFAULT_VPP_BINARY: &str = "/usr/bin/vpp";

/// What the probes look at: the module's section, and what else samples.
pub struct ProbeInputs<'a> {
    /// `source-address`.
    pub source: Option<IpAddr>,
    /// Whether the config declares vpp-offload, so VPP's sampler is in
    /// play, and its `vpp-binary` if it names one.
    pub vpp: bool,
    pub vpp_binary: Option<&'a str>,
    /// `kernel-sample` interfaces, and the ports fast-path's programs and
    /// VPP sample, which none of them may sit on.
    pub kernel: &'a [String],
    pub sampled: &'a [String],
}

pub fn run_feasibility_probes(inputs: &ProbeInputs<'_>) -> Vec<Capability> {
    #[cfg(target_os = "linux")]
    {
        linux::run(inputs)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = inputs;
        Vec::new()
    }
}

/// The packages `dpkg-query -S` says own a path. A diversion line names
/// no owner. Portable so it is tested everywhere; only Linux asks dpkg.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn owners(dpkg_s: &str) -> Vec<&str> {
    dpkg_s
        .lines()
        .filter(|l| !l.starts_with("diversion "))
        .filter_map(|l| l.split_once(": "))
        .flat_map(|(packages, _)| packages.split(", "))
        // `vpp:arm64` for a package of one architecture among several.
        .map(|p| p.split(':').next().unwrap_or(p))
        .collect()
}

/// A plugin's registration, as VPP's loader reads it: the version it
/// declares and the VPP version it requires, NUL-padded fixed fields at
/// bytes 1 and 65 of the section (`vlib_plugin_registration_t`, after a
/// one-byte bitfield).
pub fn registration_versions(elf: &[u8]) -> Result<(String, String), String> {
    let section = elf_section(elf, REGISTRATION_SECTION)?;
    let field = |at: usize| -> Result<String, String> {
        let raw = section
            .get(at..at + 64)
            .ok_or("the registration section is too short")?;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        std::str::from_utf8(&raw[..end])
            .map(str::to_owned)
            .map_err(|_| "a registration version is not text".to_string())
    };
    Ok((field(1)?, field(65)?))
}

/// A section's bytes from a little-endian ELF64 file, by name.
fn elf_section<'a>(elf: &'a [u8], name: &str) -> Result<&'a [u8], String> {
    let bad = |why: &str| format!("not a little-endian ELF64 file: {why}");
    if elf.get(..4) != Some(b"\x7fELF") || elf.get(4) != Some(&2) || elf.get(5) != Some(&1) {
        return Err(bad("header"));
    }
    let u16_at = |at: usize| -> Option<usize> {
        Some(usize::from(u16::from_le_bytes(
            elf.get(at..at + 2)?.try_into().ok()?,
        )))
    };
    let u32_at = |at: usize| -> Option<usize> {
        usize::try_from(u32::from_le_bytes(elf.get(at..at + 4)?.try_into().ok()?)).ok()
    };
    let u64_at = |at: usize| -> Option<usize> {
        usize::try_from(u64::from_le_bytes(elf.get(at..at + 8)?.try_into().ok()?)).ok()
    };
    let (shoff, shentsize, shnum, shstrndx) =
        (|| Some((u64_at(0x28)?, u16_at(0x3a)?, u16_at(0x3c)?, u16_at(0x3e)?)))()
            .ok_or_else(|| bad("section header table"))?;
    if shentsize < 64 {
        return Err(bad("section header size"));
    }
    let header = |i: usize| -> Option<(usize, usize, usize)> {
        let at = shoff.checked_add(i.checked_mul(shentsize)?)?;
        Some((u32_at(at)?, u64_at(at + 24)?, u64_at(at + 32)?))
    };
    let bytes = |offset: usize, size: usize| elf.get(offset..offset.checked_add(size)?);
    let (_, str_off, str_size) = header(shstrndx).ok_or_else(|| bad("section names"))?;
    let names = bytes(str_off, str_size).ok_or_else(|| bad("section names"))?;
    for i in 0..shnum {
        let (name_at, offset, size) = header(i).ok_or_else(|| bad("section header"))?;
        let Some(rest) = names.get(name_at..) else {
            continue;
        };
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        if &rest[..end] == name.as_bytes() {
            return bytes(offset, size).ok_or_else(|| bad("section bounds"));
        }
    }
    Err(format!("no {name} section: not a VPP plugin"))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{IpAddr, UdpSocket};
    use std::path::Path;

    use packetframe_common::probe::Capability;
    use packetframe_sampler_shm::fs::{check_dir, is_mount_point};

    use super::{registration_versions, DEFAULT_VPP_BINARY, PLUGIN_PATH};
    use crate::VPP_SAMPLER_DIR;

    pub fn run(i: &super::ProbeInputs<'_>) -> Vec<Capability> {
        let mut caps = Vec::new();
        if let Some(addr) = i.source {
            caps.push(source_address(addr));
        }
        if i.vpp {
            caps.push(sampler_dir(Path::new(VPP_SAMPLER_DIR)));
            let binary = i.vpp_binary.unwrap_or(DEFAULT_VPP_BINARY);
            caps.push(plugin(Path::new(PLUGIN_PATH), version_of(binary)));
        }
        for iface in i.kernel {
            let name = format!("flow-export.kernel-sample.{iface}");
            caps.push(match crate::kernel::refusal(iface, i.sampled, i.kernel) {
                None if crate::KERNEL_SAMPLE_BPF_AVAILABLE => Capability::pass(
                    name,
                    format!("{iface}: the kernel sampler can attach to its ingress"),
                    false,
                ),
                None => Capability::fail(
                    name,
                    "this build carries no kernel sampler (built without the BPF toolchain)",
                    false,
                ),
                Some(why) => Capability::fail(
                    name,
                    format!("{why}: attach will refuse it, and flow export degrade"),
                    false,
                ),
            });
        }
        caps
    }

    fn source_address(addr: IpAddr) -> Capability {
        const NAME: &str = "flow-export.source-address";
        match UdpSocket::bind((addr, 0)) {
            Ok(_) => Capability::pass(NAME, format!("{addr} is an address of this host"), false),
            Err(e) => Capability::fail(
                NAME,
                format!(
                    "no socket at {addr} ({e}): attach will fail and flow export degrade; \
                     `source-address` must be an address of this host"
                ),
                false,
            ),
        }
    }

    fn sampler_dir(dir: &Path) -> Capability {
        const NAME: &str = "flow-export.vpp.sampler-dir";
        match is_mount_point(dir) {
            Ok(true) => match check_dir(dir) {
                Ok(bytes) => Capability::pass(
                    NAME,
                    format!(
                        "{}: a size-limited tmpfs of {} KiB",
                        dir.display(),
                        bytes >> 10
                    ),
                    false,
                ),
                Err(e) => Capability::fail(
                    NAME,
                    format!("the plugin would refuse it, so VPP cannot sample: {e}"),
                    false,
                ),
            },
            // vpp-offload mounts it at attach: what that needs is tmpfs.
            Ok(false) => match std::fs::read_to_string("/proc/filesystems") {
                Ok(fs)
                    if fs
                        .lines()
                        .any(|l| l.split_whitespace().last() == Some("tmpfs")) =>
                {
                    Capability::pass(
                        NAME,
                        format!(
                            "not mounted yet: vpp-offload mounts a size-limited tmpfs at {} \
                             at attach",
                            dir.display()
                        ),
                        false,
                    )
                }
                Ok(_) => Capability::fail(
                    NAME,
                    "this kernel has no tmpfs, so VPP cannot sample",
                    false,
                ),
                Err(e) => Capability::unknown(
                    NAME,
                    format!("/proc/filesystems: {e}; attach will find out"),
                    false,
                ),
            },
            Err(e) => Capability::unknown(NAME, format!("{}: {e}", dir.display()), false),
        }
    }

    /// The version of the VPP at `binary`: the `vpp` package's, when the
    /// binary is that package's. Of any other, nothing installed says.
    fn version_of(binary: &str) -> Result<String, String> {
        let real = std::fs::canonicalize(binary).map_err(|e| format!("{binary}: {e}"))?;
        let out = std::process::Command::new("dpkg-query")
            .arg("-S")
            .arg(&real)
            .output()
            .map_err(|e| format!("dpkg-query: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout);
        if !out.status.success() || !super::owners(&text).contains(&"vpp") {
            return Err(format!(
                "the VPP that runs, {binary}, is not the `vpp` package's, so no installed \
                 package's version is its"
            ));
        }
        installed_vpp_version()
    }

    /// The installed `vpp` package's version, as dpkg has it.
    fn installed_vpp_version() -> Result<String, String> {
        let out = std::process::Command::new("dpkg-query")
            .args(["-W", "-f=${Version}", "vpp"])
            .output()
            .map_err(|e| format!("dpkg-query: {e}"))?;
        if !out.status.success() {
            return Err("no `vpp` package installed (or none dpkg knows)".into());
        }
        String::from_utf8(out.stdout)
            .map(|v| v.trim().to_owned())
            .map_err(|_| "dpkg-query printed something that is not text".into())
    }

    pub(super) fn plugin(path: &Path, installed: Result<String, String>) -> Capability {
        const NAME: &str = "flow-export.vpp.plugin";
        let elf = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) => {
                return Capability::fail(
                    NAME,
                    format!(
                        "{}: {e}: VPP will not sample (the arm64 .deb and the \
                         aarch64-unknown-linux-gnu tarball carry the plugin)",
                        path.display()
                    ),
                    false,
                )
            }
        };
        let built_for = match registration_versions(&elf) {
            Ok((_, required)) => required,
            Err(e) => return Capability::fail(NAME, format!("{}: {e}", path.display()), false),
        };
        match installed {
            // The plugin stays inert on any VPP but the one it was built
            // against: equality, not VPP's loader's prefix match.
            Ok(v) if v == built_for => Capability::pass(
                NAME,
                format!("built for vpp {built_for}, the version installed"),
                false,
            ),
            Ok(v) => Capability::fail(
                NAME,
                format!(
                    "built for vpp {built_for}, but vpp {v} is installed: VPP refuses the \
                     plugin or it stays inert, so VPP will not sample (forwarding is \
                     unaffected)"
                ),
                false,
            ),
            Err(e) => Capability::warn(
                NAME,
                format!("built for vpp {built_for}; the installed VPP's version is unknown: {e}"),
                false,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal ELF64: a NULL section, the names, and a registration.
    pub(crate) fn plugin_elf(version: &str, required: &str) -> Vec<u8> {
        let mut reg = vec![0u8; 1 + 64 + 64 + 256];
        reg[1..1 + version.len()].copy_from_slice(version.as_bytes());
        reg[65..65 + required.len()].copy_from_slice(required.as_bytes());
        let names = b"\0.shstrtab\0.vlib_plugin_registration\0".to_vec();
        let names_at = 64;
        let reg_at = names_at + names.len();
        let shoff = reg_at + reg.len();
        let mut f = vec![0u8; 64];
        f[..6].copy_from_slice(b"\x7fELF\x02\x01");
        f[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        f[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes());
        f[0x3c..0x3e].copy_from_slice(&3u16.to_le_bytes());
        f[0x3e..0x40].copy_from_slice(&1u16.to_le_bytes());
        f.extend_from_slice(&names);
        f.extend_from_slice(&reg);
        let header = |name: u32, offset: usize, size: usize| {
            let mut h = vec![0u8; 64];
            h[..4].copy_from_slice(&name.to_le_bytes());
            h[24..32].copy_from_slice(&(offset as u64).to_le_bytes());
            h[32..40].copy_from_slice(&(size as u64).to_le_bytes());
            h
        };
        f.extend(header(0, 0, 0));
        f.extend(header(1, names_at, names.len()));
        f.extend(header(11, reg_at, reg.len()));
        f
    }

    #[test]
    fn a_binary_is_the_vpp_packages_only_when_dpkg_says_so() {
        assert_eq!(owners("vpp: /usr/bin/vpp\n"), vec!["vpp"]);
        assert_eq!(owners("vpp:arm64: /usr/bin/vpp\n"), vec!["vpp"]);
        assert_eq!(
            owners("vpp, vpp-dbg: /usr/bin/vpp\n"),
            vec!["vpp", "vpp-dbg"]
        );
        assert!(owners("diversion by local from: /usr/bin/vpp\n").is_empty());
        assert!(owners("").is_empty());
    }

    #[test]
    fn the_registration_reads_as_vpps_loader_reads_it() {
        let elf = plugin_elf("0.5.0", "26.06-release");
        assert_eq!(
            registration_versions(&elf).unwrap(),
            ("0.5.0".to_string(), "26.06-release".to_string())
        );
    }

    #[test]
    fn anything_else_is_refused_not_misread() {
        assert!(registration_versions(b"not an elf").is_err());
        let mut elf = plugin_elf("0.5.0", "26.06-release");
        // Rename the section: some other shared object.
        let at = elf.windows(8).position(|w| w == b".vlib_pl").unwrap();
        elf[at + 1] = b'X';
        let e = registration_versions(&elf).unwrap_err();
        assert!(e.contains("not a VPP plugin"), "{e}");
        // A section table pointing past the file.
        let mut elf = plugin_elf("0.5.0", "26.06-release");
        elf[0x28..0x30].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(registration_versions(&elf).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_plugin_row_compares_exactly() {
        use packetframe_common::probe::CapabilityStatus;
        let d = std::env::temp_dir().join(format!("pf-flow-plugin-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("pf_sampler_plugin.so");
        std::fs::write(&p, plugin_elf("0.5.0", "26.06-release")).unwrap();
        let row = |installed: Result<String, String>| linux::plugin(&p, installed);
        assert_eq!(
            row(Ok("26.06-release".into())).status,
            CapabilityStatus::Pass
        );
        let r = row(Ok("26.06-rc2".into()));
        assert_eq!(r.status, CapabilityStatus::Fail);
        assert!(
            r.detail.contains("vpp 26.06-rc2 is installed"),
            "{}",
            r.detail
        );
        assert_eq!(row(Err("no dpkg".into())).status, CapabilityStatus::Warn);
        let missing = linux::plugin(&d.join("absent.so"), Ok("26.06-release".into()));
        assert_eq!(missing.status, CapabilityStatus::Fail);
        assert!(!missing.required);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
