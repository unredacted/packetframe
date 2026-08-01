//! Resource lifecycle for the VPP-on-VF vector (plan v5, slice 2):
//! hugepages, SR-IOV VFs, and vfio binding — acquired at attach,
//! recorded in a state file, **adopted on restart**, and released in
//! the one safe order.
//!
//! Design rules carried in from the campaign's scars:
//!
//! - **Adopt, never crash-loop.** The fast-path's pin story (v0.1
//!   refuses pin adoption → any `systemctl restart` crash-loops with a
//!   frozen FIB; bit production twice on 2026-07-31/08-01) is the
//!   anti-pattern. Attach with an existing state file verifies each
//!   recorded resource and adopts what checks out; only a *mismatch*
//!   (different VF address than recorded, foreign driver bound) is an
//!   error, and it names the manual escape hatch.
//! - **Teardown ordering is load-bearing.** Steering rules die first
//!   (slice 5 owns them; the state file records them so release can
//!   clear them even when the in-memory module never saw them), then
//!   the VPP process (slice 4), then vfio unbind → rebind to the
//!   kernel VF driver → `sriov_numvfs = 0` → hugepage release. The
//!   inverse of acquisition, always.
//! - **Every sysfs mutation takes a base-path parameter** so ordering
//!   and error paths are unit-testable on host CI against a tempdir
//!   (the `validate_interfaces_in` pattern). The `/`-rooted wrappers
//!   are one-liners.
//! - State writes are **write-then-rename** (the reconfigure marker
//!   pattern) so a crash mid-write can't leave a torn file that a
//!   later adopt trusts.
//!
//! Known platform facts encoded here (measured 2026-08-01, reference
//! EFG + shadow): default hugepage size is 512 MiB on the 64K-page
//! vendor kernel and post-boot contiguous reservations can fall short
//! on long-uptime hosts — reservation VERIFIES the resulting count
//! and falls back to the 2 MiB pool with a clear error if neither
//! pool can satisfy the budget. Debian's `dpdk.service` resets
//! reservations (observed live); adoption re-verifies counts rather
//! than trusting history. A killed EAL/VPP leaves `rtemap_*` files
//! pinning pages; release sweeps them.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// State-file schema version. Bump on layout change; adopt refuses a
/// version it doesn't know (upgrade = detach → install → attach, per
/// plan — no cross-version adoption).
pub const STATE_VERSION: u32 = 1;

pub const STATE_FILE_NAME: &str = "vpp-offload.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortState {
    /// PF netdev name (`port eth4 ...`).
    pub iface: String,
    /// The VF's PCI address as recorded at creation (e.g.
    /// `0002:07:00.1`). Adoption verifies the live `virtfn0` link
    /// still resolves to exactly this address.
    pub vf_pci: String,
    /// Worker cores promised for this port (config echo, used by the
    /// startup.conf renderer on adopt without re-parsing config).
    pub cores: u16,
}

/// Everything attach acquired, in acquisition order. Release walks it
/// in reverse. Steering rules are recorded here from slice 5 onward so
/// a crash between "rules installed" and "state updated" stays
/// recoverable (rules are re-derived idempotently from config, but
/// release must be able to clear rules the config no longer names).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceState {
    pub version: u32,
    /// Hugepages reserved at attach: (pool bytes, page count).
    /// `(0, 0)` = attach found a sufficient pre-existing reservation
    /// and owns nothing (release then leaves reservations alone).
    pub hugepage_pool_bytes: u64,
    pub hugepage_pages: u32,
    pub ports: Vec<PortState>,
    /// ntuple rule locations installed per PF iface (slice 5).
    /// Present in the schema from day one so adopting a newer state
    /// file layout never needs a version bump for this field.
    pub steer_rules: Vec<(String, Vec<u32>)>,
    /// VPP pid + pidfd-identity cookie (slice 4). `None` = no process
    /// was running at last state write.
    pub vpp_pid: Option<i32>,
}

impl ResourceState {
    pub fn empty() -> Self {
        Self {
            version: STATE_VERSION,
            hugepage_pool_bytes: 0,
            hugepage_pages: 0,
            ports: Vec::new(),
            steer_rules: Vec::new(),
            vpp_pid: None,
        }
    }

    pub fn path_in(state_dir: &Path) -> PathBuf {
        state_dir.join(STATE_FILE_NAME)
    }

    /// Load the state file. `Ok(None)` = no file (fresh attach).
    /// A parse failure or unknown version is an ERROR, not a fresh
    /// attach: trusting a torn/foreign file could double-acquire or
    /// leak; the message names the manual escape hatch.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, String> {
        let path = Self::path_in(state_dir);
        let raw = match fs::read_to_string(&path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("read {}: {e}", path.display())),
        };
        let state: Self = serde_json::from_str(&raw).map_err(|e| {
            format!(
                "parse {}: {e}; if this file is from a crashed experiment, verify no VFs/\
                 hugepages/rules are live and remove it manually",
                path.display()
            )
        })?;
        if state.version != STATE_VERSION {
            return Err(format!(
                "{} is state version {} but this binary speaks {}; run the previous binary's \
                 `packetframe detach --all` first (no cross-version adoption)",
                path.display(),
                state.version,
                STATE_VERSION
            ));
        }
        Ok(Some(state))
    }

    /// Persist via write-then-rename so a crash mid-write can never
    /// produce a torn file that a later adopt trusts.
    pub fn save(&self, state_dir: &Path) -> Result<(), String> {
        let path = Self::path_in(state_dir);
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_string_pretty(self).expect("state serializes");
        let mut f = fs::File::create(&tmp).map_err(|e| format!("create {}: {e}", tmp.display()))?;
        f.write_all(body.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| format!("write {}: {e}", tmp.display()))?;
        fs::rename(&tmp, &path).map_err(|e| format!("rename to {}: {e}", path.display()))?;
        Ok(())
    }

    pub fn remove(state_dir: &Path) -> Result<(), String> {
        let path = Self::path_in(state_dir);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("remove {}: {e}", path.display())),
        }
    }
}

// --- sysfs primitives, base-path-injected for tests ---------------------

/// Read + trim a small sysfs/procfs file.
fn read_trim(path: &Path) -> Result<String, String> {
    fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|e| format!("read {}: {e}", path.display()))
}

fn write_str(path: &Path, value: &str) -> Result<(), String> {
    fs::write(path, value).map_err(|e| format!("write {} <- {value:?}: {e}", path.display()))
}

/// Reserve `pages` hugepages in the pool whose sysfs dir is
/// `pool_dir` (e.g. `.../hugepages-524288kB`), verifying the kernel
/// actually granted them — on long-uptime hosts a contiguous 512 MiB
/// reservation can silently fall short, which must be an error here,
/// not an EAL mystery later. Returns the verified count.
pub fn reserve_hugepages_in(pool_dir: &Path, pages: u32) -> Result<u32, String> {
    let nr = pool_dir.join("nr_hugepages");
    let current: u32 = read_trim(&nr)?.parse().unwrap_or(0);
    if current >= pages {
        return Ok(current); // pre-existing reservation suffices
    }
    write_str(&nr, &pages.to_string())?;
    let granted: u32 = read_trim(&nr)?.parse().unwrap_or(0);
    if granted < pages {
        return Err(format!(
            "requested {pages} hugepages in {}, kernel granted {granted} (memory too \
             fragmented?); try the 2MiB pool or reboot-time reservation",
            pool_dir.display()
        ));
    }
    Ok(granted)
}

/// Create exactly one VF on `iface` and return its PCI address.
/// Idempotent against a pre-existing single VF (adoption path):
/// `sriov_numvfs == 1` with a resolvable `virtfn0` adopts rather than
/// erroring, because attach-after-crash is the NORMAL path.
pub fn ensure_vf_in(sysfs_net: &Path, iface: &str) -> Result<String, String> {
    let dev = sysfs_net.join(iface).join("device");
    let numvfs_path = dev.join("sriov_numvfs");
    let current: u32 = read_trim(&numvfs_path)?.parse().unwrap_or(0);
    match current {
        0 => {
            write_str(&numvfs_path, "1")?;
        }
        1 => {} // adopt
        n => {
            return Err(format!(
                "{iface} has sriov_numvfs={n}; vpp-offload manages exactly one VF per port \
                 and refuses to guess which of {n} is ours — clear them and re-attach"
            ));
        }
    }
    let vf_link = dev.join("virtfn0");
    let target = fs::read_link(&vf_link).map_err(|e| {
        format!(
            "read {}: {e} (VF creation raced or failed)",
            vf_link.display()
        )
    })?;
    let pci = target
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| format!("unparseable virtfn0 target {}", target.display()))?
        .to_string();
    Ok(pci)
}

/// Remove the port's VFs. Ignores an already-zero count.
pub fn release_vf_in(sysfs_net: &Path, iface: &str) -> Result<(), String> {
    let numvfs_path = sysfs_net.join(iface).join("device").join("sriov_numvfs");
    let current: u32 = read_trim(&numvfs_path)?.parse().unwrap_or(0);
    if current == 0 {
        return Ok(());
    }
    write_str(&numvfs_path, "0")
}

/// Bind `vf_pci` to vfio-pci via driver_override, unbinding from the
/// kernel VF driver if bound. Adoption-aware: already-on-vfio-pci is
/// success; bound to any OTHER driver than the expected kernel one is
/// an error (something else owns this VF).
pub fn bind_vfio_in(
    sysfs_pci_devices: &Path,
    sysfs_pci_drivers: &Path,
    vf_pci: &str,
    kernel_vf_driver: &str,
) -> Result<(), String> {
    let dev = sysfs_pci_devices.join(vf_pci);
    let bound = current_driver(&dev);
    match bound.as_deref() {
        Some("vfio-pci") => return Ok(()), // adopt
        Some(d) if d == kernel_vf_driver => {
            write_str(
                &sysfs_pci_drivers.join(kernel_vf_driver).join("unbind"),
                vf_pci,
            )?;
        }
        Some(other) => {
            return Err(format!(
                "{vf_pci} is bound to `{other}` (expected {kernel_vf_driver} or vfio-pci); \
                 refusing to steal it"
            ));
        }
        None => {} // unbound; proceed straight to override+bind
    }
    write_str(&dev.join("driver_override"), "vfio-pci")?;
    write_str(&sysfs_pci_drivers.join("vfio-pci").join("bind"), vf_pci)?;
    Ok(())
}

/// Return `vf_pci` to the kernel VF driver: unbind from vfio-pci,
/// clear the override, rebind. Tolerates partial prior teardown.
pub fn unbind_vfio_in(
    sysfs_pci_devices: &Path,
    sysfs_pci_drivers: &Path,
    vf_pci: &str,
    kernel_vf_driver: &str,
) -> Result<(), String> {
    let dev = sysfs_pci_devices.join(vf_pci);
    if current_driver(&dev).as_deref() == Some("vfio-pci") {
        write_str(&sysfs_pci_drivers.join("vfio-pci").join("unbind"), vf_pci)?;
    }
    // Clear the override so the kernel driver can claim it again.
    write_str(&dev.join("driver_override"), "\n")?;
    if current_driver(&dev).is_none() {
        // drivers_probe reattaches the default driver without needing
        // to name it; fall back to an explicit bind if probe is absent
        // (tests) or ineffective.
        let probe = sysfs_pci_drivers.parent().map(|b| b.join("drivers_probe"));
        let probed = match probe {
            Some(p) if p.exists() => write_str(&p, vf_pci).is_ok(),
            _ => false,
        };
        if !probed {
            write_str(
                &sysfs_pci_drivers.join(kernel_vf_driver).join("bind"),
                vf_pci,
            )?;
        }
    }
    Ok(())
}

fn current_driver(dev: &Path) -> Option<String> {
    fs::read_link(dev.join("driver"))
        .ok()
        .and_then(|t| t.file_name().map(|s| s.to_string_lossy().into_owned()))
}

/// Verify a recorded port still matches reality (the adoption check):
/// `virtfn0` resolves to the recorded PCI address and the VF is bound
/// to vfio-pci. Returns a human-readable mismatch description.
pub fn verify_port_in(
    sysfs_net: &Path,
    sysfs_pci_devices: &Path,
    port: &PortState,
) -> Result<(), String> {
    let vf_link = sysfs_net.join(&port.iface).join("device").join("virtfn0");
    let live = fs::read_link(&vf_link)
        .ok()
        .and_then(|t| t.file_name().map(|s| s.to_string_lossy().into_owned()));
    match live {
        Some(pci) if pci == port.vf_pci => {}
        Some(pci) => {
            return Err(format!(
                "{}: state records VF {} but live VF is {pci}; a reprovision replaced the VF — \
                 detach fully and re-attach",
                port.iface, port.vf_pci
            ));
        }
        None => {
            return Err(format!(
                "{}: state records VF {} but no VF exists (udapi provision cleared it?); \
                 detach fully and re-attach",
                port.iface, port.vf_pci
            ));
        }
    }
    match current_driver(&sysfs_pci_devices.join(&port.vf_pci)).as_deref() {
        Some("vfio-pci") => Ok(()),
        other => Err(format!(
            "{}: VF {} driver is {:?}, expected vfio-pci; detach fully and re-attach",
            port.iface, port.vf_pci, other
        )),
    }
}

/// Sweep stale EAL/VPP hugepage mappings (`rtemap_*`) left by a killed
/// process — observed live: they pin pages and make the next EAL init
/// fail with "No free hugepages". Only called with VPP known-dead.
pub fn sweep_stale_hugepage_maps(hugetlbfs_dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(hugetlbfs_dir) else {
        return 0;
    };
    let mut swept = 0;
    for e in entries.flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("rtemap_") && fs::remove_file(e.path()).is_ok() {
            swept += 1;
        }
    }
    swept
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "pf-vpp-res-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn state_round_trip_and_torn_file_rejected() {
        let dir = tmpdir();
        assert!(ResourceState::load(&dir).unwrap().is_none());

        let mut st = ResourceState::empty();
        st.hugepage_pool_bytes = 512 << 20;
        st.hugepage_pages = 10;
        st.ports.push(PortState {
            iface: "eth4".into(),
            vf_pci: "0002:07:00.1".into(),
            cores: 1,
        });
        st.steer_rules.push(("eth4".into(), vec![1, 2, 3]));
        st.save(&dir).unwrap();
        assert_eq!(ResourceState::load(&dir).unwrap().unwrap(), st);

        // Torn/garbage file is an error naming the escape hatch — not
        // a silent fresh attach.
        fs::write(ResourceState::path_in(&dir), b"{ torn").unwrap();
        let err = ResourceState::load(&dir).unwrap_err();
        assert!(err.contains("remove it manually"), "{err}");

        // Unknown version refuses adoption.
        fs::write(
            ResourceState::path_in(&dir),
            serde_json::to_string(&serde_json::json!({
                "version": 99, "hugepage_pool_bytes": 0, "hugepage_pages": 0,
                "ports": [], "steer_rules": [], "vpp_pid": null
            }))
            .unwrap(),
        )
        .unwrap();
        let err = ResourceState::load(&dir).unwrap_err();
        assert!(err.contains("no cross-version adoption"), "{err}");

        ResourceState::remove(&dir).unwrap();
        assert!(ResourceState::load(&dir).unwrap().is_none());
        ResourceState::remove(&dir).unwrap(); // idempotent
    }

    #[test]
    fn hugepage_reservation_verifies_grant() {
        let pool = tmpdir();
        // Kernel grants everything: write-then-readback sees the
        // written value (plain file behaves like a granting kernel).
        fs::write(pool.join("nr_hugepages"), "0").unwrap();
        assert_eq!(reserve_hugepages_in(&pool, 4).unwrap(), 4);
        // Pre-existing larger reservation adopted untouched.
        fs::write(pool.join("nr_hugepages"), "16").unwrap();
        assert_eq!(reserve_hugepages_in(&pool, 4).unwrap(), 16);
    }

    #[test]
    fn vf_lifecycle_and_adoption() {
        let net = tmpdir();
        let dev = net.join("eth4").join("device");
        fs::create_dir_all(&dev).unwrap();
        fs::write(dev.join("sriov_numvfs"), "0").unwrap();

        // Fresh create: numvfs 0→1 write happens, then virtfn0 must
        // resolve. Simulate the kernel by pre-creating the symlink
        // (read_link works on dangling symlinks).
        #[cfg(unix)]
        std::os::unix::fs::symlink("../0002:07:00.1", dev.join("virtfn0")).unwrap();
        let pci = ensure_vf_in(&net, "eth4").unwrap();
        assert_eq!(pci, "0002:07:00.1");
        assert_eq!(fs::read_to_string(dev.join("sriov_numvfs")).unwrap(), "1");

        // Adoption: numvfs already 1 → no write, same answer.
        let pci2 = ensure_vf_in(&net, "eth4").unwrap();
        assert_eq!(pci2, pci);

        // Multi-VF confusion refused.
        fs::write(dev.join("sriov_numvfs"), "3").unwrap();
        let err = ensure_vf_in(&net, "eth4").unwrap_err();
        assert!(err.contains("refuses to guess"), "{err}");

        // Release: 3→0 write; 0 is a no-op.
        release_vf_in(&net, "eth4").unwrap();
        assert_eq!(fs::read_to_string(dev.join("sriov_numvfs")).unwrap(), "0");
        release_vf_in(&net, "eth4").unwrap();
    }

    #[test]
    fn vfio_bind_paths_and_refusals() {
        let base = tmpdir();
        let devices = base.join("devices");
        let drivers = base.join("drivers");
        let dev = devices.join("0002:07:00.1");
        fs::create_dir_all(&dev).unwrap();
        for d in ["vfio-pci", "rvu_nicvf"] {
            fs::create_dir_all(drivers.join(d)).unwrap();
        }

        // Unbound → override written + bind written.
        bind_vfio_in(&devices, &drivers, "0002:07:00.1", "rvu_nicvf").unwrap();
        assert_eq!(
            fs::read_to_string(dev.join("driver_override")).unwrap(),
            "vfio-pci"
        );
        assert_eq!(
            fs::read_to_string(drivers.join("vfio-pci").join("bind")).unwrap(),
            "0002:07:00.1"
        );

        // Bound to a foreign driver → refused.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(drivers.join("mlx5_core"), dev.join("driver")).unwrap();
            let err = bind_vfio_in(&devices, &drivers, "0002:07:00.1", "rvu_nicvf").unwrap_err();
            assert!(err.contains("refusing to steal"), "{err}");
            fs::remove_file(dev.join("driver")).unwrap();

            // Bound to vfio-pci already → adopt (no writes needed).
            std::os::unix::fs::symlink(drivers.join("vfio-pci"), dev.join("driver")).unwrap();
            bind_vfio_in(&devices, &drivers, "0002:07:00.1", "rvu_nicvf").unwrap();

            // Unbind path: vfio unbind written, override cleared,
            // explicit rebind (no drivers_probe in the tempdir).
            fs::remove_file(dev.join("driver")).unwrap();
            unbind_vfio_in(&devices, &drivers, "0002:07:00.1", "rvu_nicvf").unwrap();
            assert_eq!(
                fs::read_to_string(dev.join("driver_override")).unwrap(),
                "\n"
            );
            assert_eq!(
                fs::read_to_string(drivers.join("rvu_nicvf").join("bind")).unwrap(),
                "0002:07:00.1"
            );
        }
    }

    #[test]
    fn adoption_verify_detects_drift() {
        let base = tmpdir();
        let net = base.join("net");
        let devices = base.join("devices");
        let dev = net.join("eth4").join("device");
        fs::create_dir_all(&dev).unwrap();
        fs::create_dir_all(devices.join("0002:07:00.1")).unwrap();
        let port = PortState {
            iface: "eth4".into(),
            vf_pci: "0002:07:00.1".into(),
            cores: 1,
        };

        // No VF at all → provision-cleared message.
        let err = verify_port_in(&net, &devices, &port).unwrap_err();
        assert!(err.contains("no VF exists"), "{err}");

        #[cfg(unix)]
        {
            // Wrong VF address → replaced message.
            std::os::unix::fs::symlink("../0002:07:00.2", dev.join("virtfn0")).unwrap();
            let err = verify_port_in(&net, &devices, &port).unwrap_err();
            assert!(err.contains("live VF is 0002:07:00.2"), "{err}");
            fs::remove_file(dev.join("virtfn0")).unwrap();

            // Right VF, right driver → adopt OK.
            std::os::unix::fs::symlink("../0002:07:00.1", dev.join("virtfn0")).unwrap();
            let drv_dir = base.join("drivers").join("vfio-pci");
            fs::create_dir_all(&drv_dir).unwrap();
            std::os::unix::fs::symlink(&drv_dir, devices.join("0002:07:00.1").join("driver"))
                .unwrap();
            verify_port_in(&net, &devices, &port).unwrap();
        }
    }

    #[test]
    fn stale_rtemap_sweep() {
        let dir = tmpdir();
        fs::write(dir.join("rtemap_0"), b"x").unwrap();
        fs::write(dir.join("rtemap_1"), b"x").unwrap();
        fs::write(dir.join("keepme"), b"x").unwrap();
        assert_eq!(sweep_stale_hugepage_maps(&dir), 2);
        assert!(dir.join("keepme").exists());
        assert_eq!(sweep_stale_hugepage_maps(&dir), 0);
    }
}
