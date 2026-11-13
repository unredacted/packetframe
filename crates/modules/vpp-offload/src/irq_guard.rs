//! NIC queue IRQs kept off VPP's cores for as long as VPP runs, not only
//! at attach.
//!
//! ## Why
//!
//! Attach moves every NIC's queue IRQs off the cores VPP polls
//! (`cores::clear_irqs_off`): hardirq and NET_RX softirq run wherever an
//! IRQ is delivered, CFS cannot preempt them, and a worker stalled behind
//! them for 1 s at a barrier aborts VPP (`worker thread deadlock`). But a
//! port that is re-opened requests its IRQs again, and the kernel's
//! default spread puts queue N back on CPU N, VPP's cores included. On
//! the lab (2026-11-12) udapi's `sfp-auto-detect` changed an empty SFP
//! port's speed three seconds after attach had moved its IRQs; the driver
//! re-opened it, and its queue IRQs stayed on VPP's main core and both
//! workers. A speed change, a udapi reconfig at boot or a WAN change does
//! the same to a port carrying traffic: during a fresh load, the window
//! the core fence exists for, and at any later barrier.
//!
//! ## What it does
//!
//! Every [`CHECK_EVERY`], whatever state VPP is in, the same move attach
//! makes runs again over every NIC on the host: an IRQ delivered on one
//! of VPP's cores is re-pinned onto the CPUs that are neither VPP's nor
//! isolated. Nothing is written unless something drifted. Moves are
//! logged and recorded (`nic_irqs_moved`) at most once per
//! [`REPORT_EVERY`], with what was moved since the last report, so a
//! port that renegotiates every 20 s does not fill the event log. An IRQ
//! the kernel will not move is a warning, once per set of such IRQs.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::cores;

/// How often the IRQ placement is checked.
pub const CHECK_EVERY: Duration = Duration::from_secs(2);

/// The most often moves are reported, in the journal and the event log.
pub const REPORT_EVERY: Duration = Duration::from_secs(300);

/// The guard: where to read and write, VPP's cores, and what it has not
/// reported yet.
pub struct IrqGuard {
    sysfs_net: PathBuf,
    proc_irq: PathBuf,
    sysfs_cpu: PathBuf,
    /// Every CPU VPP is on: main and workers, derived or observed.
    vpp_cores: Vec<u16>,
    /// The derived map alone: the cores a VPP this loop spawns runs on.
    /// An adopted VPP observed elsewhere adds its own cores to
    /// `vpp_cores`; once it is replaced they are VPP's no more
    /// ([`Self::vpp_spawned`]).
    spawn_cores: Vec<u16>,
    last_check: Option<Instant>,
    last_report: Option<Instant>,
    /// Moves since the last report: how many, and of which ports' IRQs.
    pending_moves: usize,
    pending_ifaces: BTreeSet<String>,
    /// The IRQs last found stuck on VPP's cores, so the warning is said
    /// once per set, not every pass.
    stuck: BTreeSet<u32>,
    /// The last error the check ran into (an affinity write the kernel
    /// refused, no CPU left to move to), so it is warned once per error,
    /// not every pass.
    failing: Option<String>,
}

/// What one check did, for tests and the caller's log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Checked {
    pub moved: usize,
    pub stuck: usize,
    /// Whether this check reported (logged and recorded) its moves.
    pub reported: bool,
    /// Whether the check could not run or a move was refused.
    pub failed: bool,
}

impl IrqGuard {
    /// `vpp_cores`: every core VPP is on now, observed included.
    /// `spawn_cores`: the derived map, what a spawned VPP runs on.
    pub fn new(
        sysfs_net: impl Into<PathBuf>,
        proc_irq: impl Into<PathBuf>,
        sysfs_cpu: impl Into<PathBuf>,
        vpp_cores: Vec<u16>,
        spawn_cores: Vec<u16>,
    ) -> Self {
        let norm = |mut v: Vec<u16>| {
            v.sort_unstable();
            v.dedup();
            v
        };
        let vpp_cores = norm(vpp_cores);
        let spawn_cores = norm(spawn_cores);
        Self {
            sysfs_net: sysfs_net.into(),
            proc_irq: proc_irq.into(),
            sysfs_cpu: sysfs_cpu.into(),
            vpp_cores,
            spawn_cores,
            last_check: None,
            last_report: None,
            pending_moves: 0,
            pending_ifaces: BTreeSet::new(),
            stuck: BTreeSet::new(),
            failing: None,
        }
    }

    /// This loop spawned VPP: it runs on the derived map, and the cores
    /// an adopted predecessor was observed on are free again. Without
    /// this the guard kept excluding them for good, and on a host where
    /// that union left no CPU to move to it could move nothing.
    pub fn vpp_spawned(&mut self) {
        if self.vpp_cores != self.spawn_cores {
            tracing::info!(
                was = %cores::format_cpu_list(&self.vpp_cores),
                now = %cores::format_cpu_list(&self.spawn_cores),
                "IRQ guard: VPP respawned on its derived cores; guarding those"
            );
            self.vpp_cores = self.spawn_cores.clone();
            self.stuck.clear();
        }
    }

    /// Warn once per distinct error; a pass that runs clears it.
    fn note_failure(&mut self, error: String) {
        if self.failing.as_deref() != Some(error.as_str()) {
            tracing::warn!(
                cores = ?self.vpp_cores,
                error = %error,
                "the NIC IRQ check could not move IRQs off VPP's cores; any left there can \
                 stall a worker into VPP's barrier timeout"
            );
            self.failing = Some(error);
        }
    }

    /// Check the placement if [`CHECK_EVERY`] has passed, and move what
    /// drifted back. `None` when not due.
    pub fn tick(&mut self, now: Instant) -> Option<Checked> {
        if self
            .last_check
            .is_some_and(|t| now.saturating_duration_since(t) < CHECK_EVERY)
        {
            return None;
        }
        self.last_check = Some(now);
        let mut out = Checked::default();
        let ifaces = match cores::nic_ifaces(&self.sysfs_net) {
            Ok(i) => i,
            Err(e) => {
                self.note_failure(format!("could not list the host's NICs: {e}"));
                return Some(out);
            }
        };
        let clearing = match cores::clear_irqs_off(
            &self.sysfs_net,
            &self.proc_irq,
            &self.sysfs_cpu,
            &ifaces,
            &self.vpp_cores,
        ) {
            Ok(c) => c,
            Err(e) => {
                // An affinity write the kernel refused lands here, before
                // the `still` set below is built: warned here instead.
                out.failed = true;
                self.note_failure(e);
                return Some(out);
            }
        };
        self.failing = None;
        out.moved = clearing.moved.len();
        for m in &clearing.moved {
            tracing::debug!(iface = %m.iface, irq = m.irq, was = %m.was, now = %m.now, "moved a NIC queue IRQ back off VPP's cores");
            self.pending_ifaces.insert(m.iface.clone());
        }
        self.pending_moves += clearing.moved.len();

        let stuck: BTreeSet<u32> = clearing.still.iter().map(|c| c.irq).collect();
        out.stuck = stuck.len();
        if !stuck.is_empty() && stuck != self.stuck {
            let sample: Vec<String> = clearing
                .still
                .iter()
                .take(8)
                .map(|c| format!("{} irq {} -> cpu {:?}", c.iface, c.irq, c.cpus))
                .collect();
            tracing::warn!(
                cores = ?self.vpp_cores,
                irqs = %sample.join(", "),
                "NIC queue IRQs fire on VPP's cores and the kernel did not move them; \
                 they can stall a worker into VPP's barrier timeout"
            );
        }
        self.stuck = stuck;

        let due = self
            .last_report
            .is_none_or(|t| now.saturating_duration_since(t) >= REPORT_EVERY);
        if self.pending_moves > 0 && due {
            self.report(now);
            out.reported = true;
        }
        Some(out)
    }

    fn report(&mut self, now: Instant) {
        use packetframe_common::events::{self as event_log, kind as event_kind};
        let ifaces = self
            .pending_ifaces
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        tracing::info!(
            irqs = self.pending_moves,
            ifaces = %ifaces,
            cores = ?self.vpp_cores,
            "NIC queue IRQs had been put back on VPP's cores (a port re-opened); moved them off again"
        );
        event_log::Event::info(crate::MODULE_NAME, event_kind::NIC_IRQS_MOVED)
            .field("irqs", self.pending_moves as u64)
            .field("ifaces", ifaces)
            .field("vpp_cores", cores::format_cpu_list(&self.vpp_cores))
            .emit();
        self.pending_moves = 0;
        self.pending_ifaces.clear();
        self.last_report = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        base: PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let mut base = std::env::temp_dir();
            base.push(format!("pf-irqguard-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            let cpu = base.join("cpu");
            std::fs::create_dir_all(&cpu).unwrap();
            std::fs::write(cpu.join("online"), "0-17\n").unwrap();
            std::fs::write(cpu.join("isolated"), "12\n").unwrap();
            std::fs::create_dir_all(base.join("net")).unwrap();
            std::fs::create_dir_all(base.join("irq")).unwrap();
            Self { base }
        }

        fn net(&self) -> PathBuf {
            self.base.join("net")
        }
        fn irq(&self) -> PathBuf {
            self.base.join("irq")
        }

        /// A NIC queue IRQ delivered on `cpu`, read from the mask, as a
        /// kernel that honours the mask shows it.
        fn irq_on(&self, iface: &str, irq: u32, cpu: &str) {
            let msi = self.net().join(iface).join("device").join("msi_irqs");
            std::fs::create_dir_all(&msi).unwrap();
            std::fs::write(msi.join(irq.to_string()), "").unwrap();
            let d = self.irq().join(irq.to_string());
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("smp_affinity_list"), format!("{cpu}\n")).unwrap();
        }

        fn cpu_of(&self, irq: u32) -> String {
            std::fs::read_to_string(self.irq().join(irq.to_string()).join("smp_affinity_list"))
                .unwrap()
                .trim()
                .to_string()
        }

        fn guard(&self) -> IrqGuard {
            IrqGuard::new(
                self.net(),
                self.irq(),
                self.base.join("cpu"),
                vec![15, 16, 17],
                vec![15, 16, 17],
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }

    fn off_vpp(cpu: &str) -> bool {
        let c: u16 = cpu.parse().expect("one CPU");
        !(15..=17).contains(&c) && c != 12
    }

    #[test]
    fn an_irq_put_back_on_a_vpp_core_by_a_port_reopen_is_moved_off_again() {
        let fx = Fixture::new("reopen");
        fx.irq_on("eth3", 688, "3");
        fx.irq_on("eth3", 689, "4");
        let mut g = fx.guard();
        let t0 = Instant::now();
        assert_eq!(g.tick(t0).unwrap().moved, 0, "nothing on VPP's cores yet");

        // The driver re-opens eth3: queue N back on CPU N.
        fx.irq_on("eth3", 688, "16");
        fx.irq_on("eth3", 689, "17");
        assert!(g.tick(t0 + Duration::from_millis(500)).is_none(), "paced");
        let c = g.tick(t0 + CHECK_EVERY).unwrap();
        assert_eq!(c.moved, 2);
        assert!(c.reported, "the first moves are reported at once");
        assert!(off_vpp(&fx.cpu_of(688)), "688 on {}", fx.cpu_of(688));
        assert!(off_vpp(&fx.cpu_of(689)), "689 on {}", fx.cpu_of(689));
    }

    #[test]
    fn a_port_that_keeps_renegotiating_is_moved_every_time_and_reported_once_a_window() {
        let fx = Fixture::new("flap");
        fx.irq_on("eth4", 700, "15");
        let mut g = fx.guard();
        let t0 = Instant::now();
        let first = g.tick(t0).unwrap();
        assert_eq!((first.moved, first.reported), (1, true));

        // Re-opened again 20 s later, and again: moved each time, not
        // reported until REPORT_EVERY has passed.
        for k in 1..=5u32 {
            fx.irq_on("eth4", 700, "15");
            let c = g.tick(t0 + Duration::from_secs(20 * k as u64)).unwrap();
            assert_eq!(c.moved, 1);
            assert!(!c.reported, "pass {k} reported inside the window");
            assert!(off_vpp(&fx.cpu_of(700)));
        }
        fx.irq_on("eth4", 700, "15");
        let c = g.tick(t0 + REPORT_EVERY).unwrap();
        assert!(
            c.reported,
            "the moves since the last report go out together"
        );
        assert_eq!(g.pending_moves, 0);
    }

    #[test]
    fn a_respawned_vpp_frees_the_cores_its_adopted_predecessor_was_on() {
        let fx = Fixture::new("respawn");
        // Adopted on 3 as well as the derived 15-17.
        let mut g = IrqGuard::new(
            fx.net(),
            fx.irq(),
            fx.base.join("cpu"),
            vec![3, 15, 16, 17],
            vec![15, 16, 17],
        );
        fx.irq_on("eth1", 900, "3");
        let t0 = Instant::now();
        assert_eq!(g.tick(t0).unwrap().moved, 1, "3 is the adopted VPP's");
        assert_ne!(fx.cpu_of(900), "3");

        g.vpp_spawned();
        fx.irq_on("eth1", 900, "3");
        let c = g.tick(t0 + CHECK_EVERY).unwrap();
        assert_eq!(c.moved, 0, "3 is no longer VPP's");
        assert_eq!(fx.cpu_of(900), "3");
    }

    #[test]
    fn a_check_that_cannot_move_says_so() {
        let fx = Fixture::new("nocpu");
        // Every online CPU but the isolated one is VPP's: nowhere to go.
        let all: Vec<u16> = (0..=17).filter(|c| *c != 12).collect();
        let mut g = IrqGuard::new(fx.net(), fx.irq(), fx.base.join("cpu"), all.clone(), all);
        fx.irq_on("eth0", 800, "5");
        let c = g.tick(Instant::now()).unwrap();
        assert!(c.failed);
        assert_eq!(fx.cpu_of(800), "5");
        assert!(g.failing.is_some(), "warned, once");
    }

    #[test]
    fn nothing_on_vpps_cores_writes_nothing() {
        let fx = Fixture::new("quiet");
        fx.irq_on("eth0", 826, "1");
        let mut g = fx.guard();
        let c = g.tick(Instant::now()).unwrap();
        assert_eq!(c, Checked::default());
        assert_eq!(fx.cpu_of(826), "1");
    }
}
