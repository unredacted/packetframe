//! Resource acquisition orchestration, and the state file made real.
//!
//! [`crate::resources`] holds the adoption-aware primitives (hugepage
//! reservation, VF creation, vfio binding — each path-parameterised and
//! individually rollback-safe). This module composes them into the
//! attach-time sequence the plan specifies — **hugepages → VF → vfio**,
//! per port in config order — with the two properties the primitives
//! cannot provide alone:
//!
//! - **Rollback of partial acquisition.** A failure at port N releases
//!   ports 0..N and the hugepage reservation, in reverse order, so a
//!   failed attach leaves the box as it found it — or says loudly and
//!   precisely that it could not.
//! - **A state file that never lies about what is held.** State is
//!   saved after every *observed* acquisition, not once at the end: a
//!   daemon crash mid-attach must leave a file describing exactly the
//!   resources a later `detach --all` needs to find.
//!
//! [`FileStore`] is the [`IdentityStore`] the runtime records into —
//! the process identity at spawn, the interface indices at attach —
//! each persisted at the moment it becomes true. This is the piece
//! that makes adoption after a daemon restart possible at all.

use std::path::PathBuf;

use crate::resources::{
    bind_vfio_in, ensure_vf_in, release_vf_in, reserve_hugepages_in, unbind_vfio_in,
    verify_port_in, PortState, ResourceState,
};
use crate::runtime::{IdentityStore, ProcessIdentity};

/// The kernel driver that owns cnxk VFs when vfio does not.
/// Rebinding to it on release is what hands the VF back to the kernel
/// network stack instead of leaving a dead PCI function.
pub const KERNEL_VF_DRIVER: &str = "rvu_nicvf";

/// Every host path the orchestration touches, injectable so the whole
/// sequence — including rollback — runs against a tempdir in tests.
/// Production fills these with the real sysfs/procfs locations.
#[derive(Debug, Clone)]
pub struct SysPaths {
    /// `/sys/class/net`
    pub sysfs_net: PathBuf,
    /// `/sys/bus/pci/devices`
    pub pci_devices: PathBuf,
    /// `/sys/bus/pci/drivers`
    pub pci_drivers: PathBuf,
    /// The hugepage pool dir, e.g.
    /// `/sys/kernel/mm/hugepages/hugepages-524288kB`.
    pub hugepage_pool: PathBuf,
    /// Bytes per page in that pool (512 MiB on the fleet). Recorded in
    /// the state file so release restores the right pool.
    pub hugepage_bytes: u64,
    /// Where the state file lives (`<state-dir>`).
    pub state_dir: PathBuf,
}

/// What acquisition produced, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acquired {
    /// Resources created (or completed) by this call.
    Fresh,
    /// A prior run's resources verified live and taken over. The
    /// caller should attempt process adoption next — the state file
    /// may also name a running VPP.
    Adopted,
}

/// Acquire everything the config asks for, or leave the box untouched.
///
/// If a state file exists, this is an **adoption**: every recorded port
/// is verified against live sysfs (the VF still resolves to the
/// recorded PCI address and is still on vfio-pci), and the recorded
/// port set must match the config exactly. Any mismatch is an error
/// naming `packetframe detach --all` — partially adopting resources
/// would leave the unverified remainder untracked, which is how leaks
/// become permanent.
///
/// Fresh acquisition orders hugepages first (an unwindable sysctl-like
/// write) and VFs after, saving state after each observed step.
pub fn acquire(
    paths: &SysPaths,
    ports: &[(String, u16)],
    pages: u32,
) -> Result<(ResourceState, Acquired), String> {
    if let Some(mut state) = ResourceState::load(&paths.state_dir)? {
        verify_adoptable(paths, &state, ports)?;
        // Hugepages are re-verified, not trusted: `dpdk.service` resets
        // reservations (observed live on the fleet), so the pool the
        // state file remembers may hold nothing by now — and adopting
        // without it lets a replacement VPP spawn straight into an
        // allocation failure loop. `reserve_hugepages_in` is a no-op
        // when the pool still suffices.
        let nr_path = paths.hugepage_pool.join("nr_hugepages");
        let live: u32 = std::fs::read_to_string(&nr_path)
            .map_err(|e| format!("read {}: {e}", nr_path.display()))?
            .trim()
            .parse()
            .unwrap_or(0);
        reserve_hugepages_in(&paths.hugepage_pool, pages)
            .map_err(|e| format!("re-reserving hugepages on adoption: {e}"))?;
        if state.hugepage_pages == 0 && live < pages {
            // The original attach found a sufficient reservation and
            // owned nothing; that reservation has since shrunk and WE
            // just raised it — ownership starts now, from the live
            // prior, and must be durable before anything relies on it.
            state.hugepage_pool_bytes = paths.hugepage_bytes;
            state.hugepage_pages = pages;
            state.hugepage_prior_pages = live;
            state.save(&paths.state_dir)?;
        }
        return Ok((state, Acquired::Adopted));
    }

    let mut state = ResourceState::empty();

    // Hugepages first. Record the PRIOR count before touching the
    // pool: release restores this value, because zeroing the pool is
    // only correct when the reservation was created from nothing.
    let nr_path = paths.hugepage_pool.join("nr_hugepages");
    let prior: u32 = std::fs::read_to_string(&nr_path)
        .map_err(|e| format!("read {}: {e}", nr_path.display()))?
        .trim()
        .parse()
        .unwrap_or(0);
    reserve_hugepages_in(&paths.hugepage_pool, pages)?;
    if prior < pages {
        state.hugepage_pool_bytes = paths.hugepage_bytes;
        state.hugepage_pages = pages;
        state.hugepage_prior_pages = prior;
    } // else: pre-existing reservation suffices; we own nothing.

    // Every save failure from here rolls back. A `?` instead would
    // return with resources acquired but UNRECORDED — the one
    // combination the state file exists to make impossible, since a
    // later `detach --all` can only release what the file describes.
    let save_or_rollback = |state: &ResourceState, what: &str| -> Result<(), String> {
        let Err(e) = state.save(&paths.state_dir) else {
            return Ok(());
        };
        Err(match release(paths, state.clone()) {
            Ok(()) => format!("could not record {what} ({e}); everything acquired was rolled back"),
            Err(re) => format!(
                "could not record {what} ({e}); ROLLBACK ALSO FAILED ({re}) — \
                     resources are held but NOT durably recorded; do not restart the \
                     daemon before releasing them manually"
            ),
        })
    };
    save_or_rollback(&state, "the hugepage reservation")?;

    for (iface, cores) in ports {
        // The two steps are separated because their failure cleanups
        // differ — and because `ensure_vf_in` can fail AFTER creating
        // the VF (the `virtfn0` readlink). The failed port is not yet
        // in `state`, so the shared rollback below cannot see it; it
        // has to be unwound here, or "rolled back" is a false report
        // and the box keeps a VF nothing tracks.
        let unwind = |port_cleanup: Result<(), String>, e: String| -> String {
            let mut msg = match release(paths, state.clone()) {
                Ok(()) => format!("acquiring {iface}: {e} (partial acquisition rolled back)"),
                Err(re) => format!(
                    "acquiring {iface}: {e}; ROLLBACK ALSO FAILED ({re}) — resources \
                     remain held and recorded, run `packetframe detach --all`"
                ),
            };
            if let Err(ce) = port_cleanup {
                msg.push_str(&format!(
                    "; ALSO: the failed port's own VF could not be released ({ce})"
                ));
            }
            msg
        };

        let vf_pci = match ensure_vf_in(&paths.sysfs_net, iface) {
            Ok(p) => p,
            Err(e) => {
                // The VF may exist even though ensure failed (created,
                // then the virtfn0 readlink raced or failed). Releasing
                // is idempotent when it does not.
                let cleanup = release_vf_in(&paths.sysfs_net, iface);
                return Err(unwind(cleanup, e));
            }
        };
        if let Err(e) = bind_vfio_in(
            &paths.pci_devices,
            &paths.pci_drivers,
            &vf_pci,
            KERNEL_VF_DRIVER,
        ) {
            // bind_vfio_in restores the kernel driver on its own
            // failure; the VF itself is this loop's to remove.
            let cleanup = release_vf_in(&paths.sysfs_net, iface);
            return Err(unwind(cleanup, e));
        }
        state.ports.push(PortState {
            iface: iface.clone(),
            vf_pci,
            cores: *cores,
            sw_if_index: None,
        });
        // Saved per port, not once at the end: a crash between ports
        // must leave a file describing exactly what a later
        // `detach --all` has to release.
        save_or_rollback(&state, &format!("port {iface}"))?;
    }

    Ok((state, Acquired::Fresh))
}

/// Release everything `state` records, in reverse acquisition order.
///
/// Continues past individual failures — a port that refuses to unbind
/// must not strand the ports after it — and at the end either removes
/// the state file (everything released) or saves the remainder and
/// reports what is still held. The file tracks reality in both
/// directions: it must not claim resources that are gone, and must not
/// forget resources that are not.
pub fn release(paths: &SysPaths, state: ResourceState) -> Result<(), String> {
    let mut errors: Vec<String> = Vec::new();
    let mut remaining = state.clone();

    for port in state.ports.iter().rev() {
        // A recorded VF whose PCI device no longer exists is already
        // released — PF reprovisioning (udapi cycles do this) and
        // external resets both remove it out from under the record.
        // Trying to unbind it anyway fails on the missing sysfs node,
        // and that failure used to retain the port in state FOREVER:
        // hugepages never released, every later `detach --all`
        // refailing on a device that cannot come back. Gone is
        // released; only the numvfs write below still applies.
        let vf_present = paths.pci_devices.join(&port.vf_pci).exists();
        let freed = if vf_present {
            unbind_vfio_in(
                &paths.pci_devices,
                &paths.pci_drivers,
                &port.vf_pci,
                KERNEL_VF_DRIVER,
            )
        } else {
            Ok(())
        }
        .and_then(|()| release_vf_in(&paths.sysfs_net, &port.iface));
        match freed {
            Ok(()) => remaining.ports.retain(|p| p.iface != port.iface),
            Err(e) => errors.push(format!("{}: {e}", port.iface)),
        }
    }

    // Hugepages last, and only the reservation this state owns — in
    // the pool the STATE names, not whichever pool this invocation was
    // pointed at. A daemon restarted with different pool config (the
    // 2 MiB fallback, a changed default) would otherwise leak the real
    // reservation while shrinking an unrelated pool to the recorded
    // prior count. `hugepage_pool_bytes` was recorded for exactly this
    // check and nothing consulted it.
    if remaining.ports.is_empty() && state.hugepage_pages > 0 {
        if state.hugepage_pool_bytes != paths.hugepage_bytes {
            errors.push(format!(
                "state records a {}-byte-page pool but release was pointed at a {}-byte \
                 one; refusing to touch the wrong pool — re-run detach with the original \
                 hugepage configuration",
                state.hugepage_pool_bytes, paths.hugepage_bytes
            ));
        } else {
            let nr = paths.hugepage_pool.join("nr_hugepages");
            match std::fs::write(&nr, state.hugepage_prior_pages.to_string()) {
                Ok(()) => {
                    remaining.hugepage_pool_bytes = 0;
                    remaining.hugepage_pages = 0;
                    remaining.hugepage_prior_pages = 0;
                }
                Err(e) => errors.push(format!("restore {}: {e}", nr.display())),
            }
        }
    }

    if errors.is_empty() {
        ResourceState::remove(&paths.state_dir)?;
        Ok(())
    } else {
        // Keep the file accurate about what is STILL held. A save
        // failure here compounds the problem and is appended rather
        // than allowed to mask the release errors.
        if let Err(e) = remaining.save(&paths.state_dir) {
            errors.push(format!("saving remaining state: {e}"));
        }
        Err(format!(
            "release incomplete, resources still held: {}",
            errors.join("; ")
        ))
    }
}

/// Adoption checks: every recorded port verifies against live sysfs,
/// and the recorded port set matches the config exactly.
fn verify_adoptable(
    paths: &SysPaths,
    state: &ResourceState,
    ports: &[(String, u16)],
) -> Result<(), String> {
    // The FULL (iface, cores) tuple, not just the name. `cores` is the
    // persisted value the adopted configuration is reconstructed from
    // (rx queues, worker placement), so accepting a name-only match
    // would let a config edit silently keep the OLD sizing on the next
    // restart — and the plan is explicit that port/cores changes are
    // restart-only, meaning a full detach, not a drifted adoption.
    let recorded: Vec<(&str, u16)> = state
        .ports
        .iter()
        .map(|p| (p.iface.as_str(), p.cores))
        .collect();
    let configured: Vec<(&str, u16)> = ports.iter().map(|(i, c)| (i.as_str(), *c)).collect();
    if recorded != configured {
        return Err(format!(
            "state file records ports {recorded:?} but the config says {configured:?}; \
             port membership and core counts cannot change across an adoption — run \
             `packetframe detach --all` under the OLD config first"
        ));
    }
    for port in &state.ports {
        verify_port_in(&paths.sysfs_net, &paths.pci_devices, port).map_err(|e| {
            format!(
                "recorded port {} does not match reality: {e}; adopting the rest anyway \
                 would leave it untracked — run `packetframe detach --all`",
                port.iface
            )
        })?;
    }
    Ok(())
}

/// The [`IdentityStore`] over the real state file.
///
/// Holds the current [`ResourceState`] and persists on every recorded
/// observation. Each method writes through immediately — an identity
/// that exists only in memory is exactly as good as no identity the
/// moment the daemon dies, and the daemon dying is the scenario the
/// whole record exists for.
pub struct FileStore {
    state: ResourceState,
    state_dir: PathBuf,
}

impl FileStore {
    /// Wrap the state `acquire` produced. The store owns it from here;
    /// `into_state` gives it back for release at detach.
    pub fn new(state: ResourceState, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state,
            state_dir: state_dir.into(),
        }
    }

    pub fn state(&self) -> &ResourceState {
        &self.state
    }

    pub fn into_state(self) -> ResourceState {
        self.state
    }
}

impl IdentityStore for FileStore {
    fn process_changed(&mut self, identity: Option<ProcessIdentity>) -> Result<(), String> {
        match identity {
            Some(id) => {
                self.state.vpp_pid = Some(id.pid);
                self.state.vpp_start_ticks = Some(id.start_ticks);
                self.state.vpp_boot_id = id.boot_id;
            }
            None => {
                self.state.vpp_pid = None;
                self.state.vpp_start_ticks = None;
                self.state.vpp_boot_id = None;
                // Interface indices are per-VPP-instance, and the
                // instance is confirmed gone. Leaving them recorded
                // would hand the next daemon indices no live dump can
                // contain: its fresh VPP would be refused as
                // `StaleIndex` — correctly — and recovery would wedge.
                // The engine clears its in-memory copy on process death
                // for the same reason; the file must agree with it.
                for port in &mut self.state.ports {
                    port.sw_if_index = None;
                }
            }
        }
        self.state.save(&self.state_dir)
    }

    fn interfaces_attached(&mut self, indices: &[(String, u32)]) -> Result<(), String> {
        for (iface, idx) in indices {
            let Some(port) = self.state.ports.iter_mut().find(|p| &p.iface == iface) else {
                // Attach reported an interface for a port acquisition
                // never recorded. Refusing keeps the file trustworthy;
                // recording it would invent a resource nothing holds.
                return Err(format!(
                    "attach reported sw_if_index {idx} for `{iface}`, which is not an \
                     acquired port — refusing to record an interface on a port we do \
                     not hold"
                ));
            };
            port.sw_if_index = Some(*idx);
        }
        self.state.save(&self.state_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Minimal sysfs fixture: one netdev per port, PCI device dirs,
    /// driver dirs whose bind/unbind are plain files, and a hugepage
    /// pool. Same conventions as the resources.rs tests.
    struct Fixture {
        base: PathBuf,
        paths: SysPaths,
    }

    impl Fixture {
        fn new(tag: &str, ports: &[(&str, &str)]) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!(
                "pf-acq-{tag}-{}-{:x}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .subsec_nanos()
            ));
            let net = base.join("net");
            let devices = base.join("devices");
            let drivers = base.join("drivers");
            let pool = base.join("hugepages-524288kB");
            for d in ["vfio-pci", KERNEL_VF_DRIVER] {
                fs::create_dir_all(drivers.join(d)).unwrap();
            }
            fs::create_dir_all(&pool).unwrap();
            fs::write(pool.join("nr_hugepages"), "0").unwrap();
            for (iface, pci) in ports {
                let dev = net.join(iface).join("device");
                fs::create_dir_all(&dev).unwrap();
                fs::write(dev.join("sriov_numvfs"), "0").unwrap();
                let pci_dev = devices.join(pci);
                fs::create_dir_all(&pci_dev).unwrap();
                // ensure_vf reads the virtfn0 symlink after writing
                // numvfs; the fixture pre-plants it (sysfs would).
                #[cfg(unix)]
                std::os::unix::fs::symlink(&pci_dev, dev.join("virtfn0")).unwrap();
            }
            let paths = SysPaths {
                sysfs_net: net,
                pci_devices: devices,
                pci_drivers: drivers,
                hugepage_pool: pool,
                hugepage_bytes: 512 << 20,
                state_dir: base.join("state"),
            };
            Self { base, paths }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    fn two_ports() -> Vec<(String, u16)> {
        vec![("eth2".into(), 1), ("eth3".into(), 1)]
    }

    #[test]
    fn fresh_acquisition_records_everything_it_holds() {
        let f = Fixture::new(
            "fresh",
            &[("eth2", "0002:07:00.0"), ("eth3", "0002:07:00.1")],
        );
        let (state, how) = acquire(&f.paths, &two_ports(), 8).unwrap();
        assert_eq!(how, Acquired::Fresh);
        assert_eq!(state.hugepage_pages, 8);
        assert_eq!(state.hugepage_prior_pages, 0);
        assert_eq!(state.ports.len(), 2);
        assert_eq!(state.ports[0].vf_pci, "0002:07:00.0");
        assert!(state.ports.iter().all(|p| p.sw_if_index.is_none()));
        // And the file on disk says the same — not a stale draft.
        let on_disk = ResourceState::load(&f.paths.state_dir).unwrap().unwrap();
        assert_eq!(on_disk, state);
    }

    /// A failure at the second port must leave the box as acquire
    /// found it: first port's VF gone, vfio unbound, hugepages
    /// restored, no state file claiming otherwise.
    #[test]
    fn a_mid_sequence_failure_rolls_back_what_was_acquired() {
        // eth3 has no PCI fixture → ensure_vf's virtfn0 readlink fails.
        let f = Fixture::new("rollback", &[("eth2", "0002:07:00.0")]);
        let dev = f.paths.sysfs_net.join("eth3").join("device");
        fs::create_dir_all(&dev).unwrap();
        fs::write(dev.join("sriov_numvfs"), "0").unwrap(); // no virtfn0

        let err = acquire(&f.paths, &two_ports(), 8).unwrap_err();
        assert!(err.contains("eth3"), "{err}");
        assert!(err.contains("rolled back"), "{err}");

        // eth2's VF released...
        assert_eq!(
            fs::read_to_string(f.paths.sysfs_net.join("eth2/device/sriov_numvfs")).unwrap(),
            "0"
        );
        // ...and the FAILED port's own VF too. ensure_vf created it
        // (numvfs 0→1) before the virtfn0 readlink failed, and the
        // first version of this test never looked: the port was not in
        // `state`, the shared rollback could not see it, and "rolled
        // back" was a false report over a leaked VF.
        assert_eq!(
            fs::read_to_string(f.paths.sysfs_net.join("eth3/device/sriov_numvfs")).unwrap(),
            "0",
            "the failed port's VF must not survive the rollback"
        );
        // ...hugepages restored to the prior count...
        assert_eq!(
            fs::read_to_string(f.paths.hugepage_pool.join("nr_hugepages"))
                .unwrap()
                .trim(),
            "0"
        );
        // ...and no state file survives to claim anything is held.
        assert!(ResourceState::load(&f.paths.state_dir).unwrap().is_none());
    }

    /// Acquire again over a live state file = adoption, verified
    /// against sysfs rather than trusted.
    #[test]
    fn a_second_acquire_adopts_and_verifies() {
        let f = Fixture::new(
            "adopt",
            &[("eth2", "0002:07:00.0"), ("eth3", "0002:07:00.1")],
        );
        let (first, _) = acquire(&f.paths, &two_ports(), 8).unwrap();
        // The fixture's `bind` files are plain files; a real kernel
        // responds to the bind write by creating the `driver` symlink
        // that verify_port_in checks. Play the kernel's part.
        #[cfg(unix)]
        for pci in ["0002:07:00.0", "0002:07:00.1"] {
            std::os::unix::fs::symlink(
                f.paths.pci_drivers.join("vfio-pci"),
                f.paths.pci_devices.join(pci).join("driver"),
            )
            .unwrap();
        }
        let (second, how) = acquire(&f.paths, &two_ports(), 8).unwrap();
        assert_eq!(how, Acquired::Adopted);
        assert_eq!(second, first);

        // A config whose port set changed must be refused, not merged.
        let err = acquire(&f.paths, &[("eth2".into(), 1)], 8).unwrap_err();
        assert!(err.contains("cannot change across an adoption"), "{err}");
    }

    /// Release restores the PRIOR hugepage count, not zero: an
    /// operator's pre-existing partial reservation is not ours to
    /// destroy.
    #[test]
    fn release_restores_the_prior_hugepage_count() {
        let f = Fixture::new(
            "prior",
            &[("eth2", "0002:07:00.0"), ("eth3", "0002:07:00.1")],
        );
        fs::write(f.paths.hugepage_pool.join("nr_hugepages"), "3").unwrap();
        let (state, _) = acquire(&f.paths, &two_ports(), 8).unwrap();
        assert_eq!(state.hugepage_prior_pages, 3);

        release(&f.paths, state).unwrap();
        assert_eq!(
            fs::read_to_string(f.paths.hugepage_pool.join("nr_hugepages"))
                .unwrap()
                .trim(),
            "3",
            "the operator's 3 pages were there before us and must survive us"
        );
        assert!(ResourceState::load(&f.paths.state_dir).unwrap().is_none());
    }

    /// A pre-existing sufficient reservation is not owned, and release
    /// leaves it alone entirely.
    #[test]
    fn a_sufficient_preexisting_reservation_is_never_touched() {
        let f = Fixture::new(
            "preex",
            &[("eth2", "0002:07:00.0"), ("eth3", "0002:07:00.1")],
        );
        fs::write(f.paths.hugepage_pool.join("nr_hugepages"), "10").unwrap();
        let (state, _) = acquire(&f.paths, &two_ports(), 8).unwrap();
        assert_eq!(state.hugepage_pages, 0, "we own nothing");

        release(&f.paths, state).unwrap();
        assert_eq!(
            fs::read_to_string(f.paths.hugepage_pool.join("nr_hugepages"))
                .unwrap()
                .trim(),
            "10"
        );
    }

    /// The FileStore persists every observation at the moment it is
    /// made — the file on disk, not the memory copy, is what a daemon
    /// crash leaves behind.
    #[test]
    fn the_file_store_writes_through_on_every_observation() {
        let f = Fixture::new(
            "store",
            &[("eth2", "0002:07:00.0"), ("eth3", "0002:07:00.1")],
        );
        let (state, _) = acquire(&f.paths, &two_ports(), 8).unwrap();
        let mut store = FileStore::new(state, &f.paths.state_dir);

        store
            .process_changed(Some(ProcessIdentity {
                pid: 4242,
                start_ticks: 987,
                boot_id: Some("abcd".into()),
            }))
            .unwrap();
        let on_disk = ResourceState::load(&f.paths.state_dir).unwrap().unwrap();
        assert_eq!(on_disk.vpp_pid, Some(4242));
        assert_eq!(on_disk.vpp_start_ticks, Some(987));
        assert_eq!(on_disk.vpp_boot_id.as_deref(), Some("abcd"));

        store
            .interfaces_attached(&[("eth2".into(), 1), ("eth3".into(), 2)])
            .unwrap();
        let on_disk = ResourceState::load(&f.paths.state_dir).unwrap().unwrap();
        assert_eq!(on_disk.ports[0].sw_if_index, Some(1));
        assert_eq!(on_disk.ports[1].sw_if_index, Some(2));

        // An interface for a port we never acquired is refused —
        // recording it would invent a resource nothing holds.
        let err = store
            .interfaces_attached(&[("eth9".into(), 7)])
            .unwrap_err();
        assert!(err.contains("not an acquired port"), "{err}");

        store.process_changed(None).unwrap();
        let on_disk = ResourceState::load(&f.paths.state_dir).unwrap().unwrap();
        assert_eq!(on_disk.vpp_pid, None);
        assert!(on_disk.vpp_boot_id.is_none());
        // Indices are per-VPP-instance and the instance is gone —
        // recorded indices no live dump can contain would wedge the
        // next daemon's recovery on `StaleIndex`. The engine clears its
        // in-memory copy on process death; the file must agree.
        assert_eq!(on_disk.ports[0].sw_if_index, None);
        assert_eq!(on_disk.ports[1].sw_if_index, None);
    }

    /// A save failure mid-acquire must roll back, not return with
    /// resources acquired and unrecorded — the one combination the
    /// state file exists to make impossible.
    #[test]
    fn an_unrecordable_acquisition_is_rolled_back() {
        let f = Fixture::new(
            "nosave",
            &[("eth2", "0002:07:00.0"), ("eth3", "0002:07:00.1")],
        );
        // Break SAVE specifically, in a way that also fails under the
        // qemu jobs (which run as root, so permission tricks pass
        // there): a DIRECTORY squatting on the temp-file path collides
        // with save's O_EXCL create, and its remove-stale retry cannot
        // remove_file a directory — root or not. Load still sees no
        // state file, so the fresh path runs and only persistence
        // breaks.
        fs::create_dir_all(f.paths.state_dir.join("vpp-offload.json.tmp")).unwrap();

        let err = acquire(&f.paths, &two_ports(), 8).unwrap_err();
        assert!(err.contains("could not record"), "{err}");
        assert!(err.contains("rolled back"), "{err}");
        // Nothing survives: the hugepage reservation is back to prior.
        assert_eq!(
            fs::read_to_string(f.paths.hugepage_pool.join("nr_hugepages"))
                .unwrap()
                .trim(),
            "0"
        );
    }

    /// Adoption re-verifies the hugepage pool. dpdk.service resets
    /// reservations (observed live on the fleet); trusting the record
    /// would let a replacement VPP spawn straight into an allocation
    /// failure loop.
    #[test]
    fn adoption_re_reserves_a_reset_hugepage_pool() {
        let f = Fixture::new(
            "hpadopt",
            &[("eth2", "0002:07:00.0"), ("eth3", "0002:07:00.1")],
        );
        let (_state, _) = acquire(&f.paths, &two_ports(), 8).unwrap();
        #[cfg(unix)]
        for pci in ["0002:07:00.0", "0002:07:00.1"] {
            std::os::unix::fs::symlink(
                f.paths.pci_drivers.join("vfio-pci"),
                f.paths.pci_devices.join(pci).join("driver"),
            )
            .unwrap();
        }
        // The reset nobody asked for.
        fs::write(f.paths.hugepage_pool.join("nr_hugepages"), "0").unwrap();

        let (_, how) = acquire(&f.paths, &two_ports(), 8).unwrap();
        assert_eq!(how, Acquired::Adopted);
        assert_eq!(
            fs::read_to_string(f.paths.hugepage_pool.join("nr_hugepages"))
                .unwrap()
                .trim(),
            "8",
            "the reservation must be re-established, not trusted from the record"
        );
    }

    /// A cores change across a restart is refused, not silently kept at
    /// the old sizing — port/cores changes are restart-only by plan,
    /// and restart-only means a full detach.
    #[test]
    fn adoption_refuses_a_cores_change() {
        let f = Fixture::new(
            "cores",
            &[("eth2", "0002:07:00.0"), ("eth3", "0002:07:00.1")],
        );
        let _ = acquire(&f.paths, &two_ports(), 8).unwrap();
        let changed = vec![("eth2".to_string(), 1u16), ("eth3".to_string(), 4u16)];
        let err = acquire(&f.paths, &changed, 8).unwrap_err();
        assert!(err.contains("core counts"), "{err}");
    }

    /// Release refuses to restore into a different pool than the state
    /// records — shrinking an unrelated pool while leaking the real
    /// reservation is worse than failing loudly.
    #[test]
    fn release_refuses_the_wrong_hugepage_pool() {
        let f = Fixture::new(
            "wrongpool",
            &[("eth2", "0002:07:00.0"), ("eth3", "0002:07:00.1")],
        );
        let (state, _) = acquire(&f.paths, &two_ports(), 8).unwrap();
        let mut wrong = f.paths.clone();
        wrong.hugepage_bytes = 2 << 20; // detach pointed at the 2 MiB pool
        let err = release(&wrong, state).unwrap_err();
        assert!(err.contains("wrong pool"), "{err}");
        // The pool this invocation pointed at is untouched.
        assert_eq!(
            fs::read_to_string(f.paths.hugepage_pool.join("nr_hugepages"))
                .unwrap()
                .trim(),
            "8"
        );
    }

    /// A recorded VF whose PCI device vanished (PF reprovisioning, an
    /// external reset) is already released. Failing on it forever used
    /// to strand the port in state and block the hugepage release —
    /// every later `detach --all` refailing on a device that cannot
    /// come back.
    #[test]
    fn release_treats_a_vanished_vf_as_already_released() {
        let f = Fixture::new(
            "gonevf",
            &[("eth2", "0002:07:00.0"), ("eth3", "0002:07:00.1")],
        );
        let (state, _) = acquire(&f.paths, &two_ports(), 8).unwrap();
        // eth3's VF disappears out from under the record.
        fs::remove_dir_all(f.paths.pci_devices.join("0002:07:00.1")).unwrap();

        release(&f.paths, state).unwrap();
        assert!(
            ResourceState::load(&f.paths.state_dir).unwrap().is_none(),
            "everything released, nothing stranded"
        );
        assert_eq!(
            fs::read_to_string(f.paths.hugepage_pool.join("nr_hugepages"))
                .unwrap()
                .trim(),
            "0",
            "the hugepage release must not be blocked by the vanished VF"
        );
    }
}
