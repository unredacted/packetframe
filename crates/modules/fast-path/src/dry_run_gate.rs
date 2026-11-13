//! `dry-run until-seeded`: pass everything to the kernel until the route
//! mirror holds a whole table, then forward.
//!
//! ## Why
//!
//! With `dry-run off` the XDP program forwards on whatever the FIB holds
//! from the first route in. While a route-ledger seed applies, or a cold
//! mirror fills from the route source, that is a partial table, and the
//! upgrade procedure kept `dry-run on` through it and switched it off by
//! hand once the route-ledger row said the seed had applied: one more step
//! with something on the box watching, 1:43 under load on the reference
//! deployment after the 6.0.17 upgrade (2026-11-12). `until-seeded` makes
//! that switch the daemon's own.
//!
//! ## When it lets go
//!
//! The first time the mirror is known whole, once per process:
//!
//! - **`seed-whole`**: a route-ledger seed applied every advertisement it
//!   holds, none failed to install, and the ledger is attested by this
//!   daemon's completeness authority. The seed goes in longest prefix
//!   first, so the table was correct by longest match all along; this is
//!   the point it is also complete.
//! - **`authority-attested`**: otherwise (a cold start, an unattested or
//!   partial seed), with a completeness authority: the first time it
//!   attests the mirror, i.e. the routing daemon's own table and the
//!   mirror agree within the steering drift bound with nothing loading.
//!   Not the route source's End-of-RIB: on the lab rig (2026-11-13) a cold
//!   start's first `InitiationComplete` came with the mirror at 133,699 of
//!   FRR's 161,297 routes, because FRR was still loading its upstream.
//! - **`initiation-complete`**: with no authority, the route source's
//!   first `InitiationComplete` and the GC that follows it, the best a
//!   daemon with nothing to compare against can do. Never BMP's: its
//!   stand-in is a quiet period that can fall mid-dump, so the config
//!   check refuses `until-seeded` with BMP and no authority.
//!
//! None of them while a route is owed a repair (an install or recompute
//! that failed, `FibProgrammer::recompute_owed`): the trigger is kept and
//! the hold ends on the reprobe tick after the last repair.
//!
//! The release is a write of `CFG.dry_run = 0`, made under
//! `CFG_WRITE_LOCK` by whoever learns the mirror is whole, and recorded
//! (`dry_run_released`). A reload computes the byte from the configured
//! mode and the latch, so a reload of the same file never holds again,
//! and an explicit `dry-run on` or `off` still wins.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use packetframe_common::config::ModuleDirective;
use packetframe_common::module::{HealthState, SubsystemHealth};

/// The health row's name. Append-safe, rename-unsafe.
pub const SUBSYS_DRY_RUN: &str = "dry-run";

/// The configured mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DryRunMode {
    Off,
    On,
    UntilSeeded,
}

impl DryRunMode {
    /// The first `dry-run` line wins, as it always has; none is `off`.
    pub fn of(directives: &[ModuleDirective]) -> Self {
        directives
            .iter()
            .find_map(|d| match d {
                ModuleDirective::DryRun(true) => Some(Self::On),
                ModuleDirective::DryRun(false) => Some(Self::Off),
                ModuleDirective::DryRunUntilSeeded => Some(Self::UntilSeeded),
                _ => None,
            })
            .unwrap_or(Self::Off)
    }
}

/// What made the mirror whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    SeedWhole,
    AuthorityAttested,
    InitiationComplete,
}

impl Trigger {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SeedWhole => "seed-whole",
            Self::AuthorityAttested => "authority-attested",
            Self::InitiationComplete => "initiation-complete",
        }
    }
}

/// A hold that ended: why, and how long it was held.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Released {
    pub trigger: Trigger,
    pub held: Duration,
}

#[derive(Debug, Clone)]
struct State {
    mode: DryRunMode,
    /// When `until-seeded` began: the gate's creation at load, or the
    /// reload that switched to it, so `held` never counts time spent
    /// forwarding under `off` before that reload.
    since: Instant,
    /// The mirror was known whole, and how. One-shot, whatever the mode,
    /// so a reload that turns `until-seeded` on after it does not hold for
    /// a trigger that has already passed.
    ready: Option<(Trigger, Instant)>,
    /// When `until-seeded` let go, wall clock for the row.
    released: Option<(Trigger, SystemTime, Duration)>,
    /// A completeness authority decides when a mirror that did not seed
    /// whole is whole; only for the row's "waiting for".
    authority: bool,
    /// Routes whose FIB install or recompute failed and has not been
    /// repaired since. The mirror is not whole while any is owed; only
    /// for the row's "waiting for".
    repairs_owed: usize,
}

/// The gate as it was before a decision, to put back when the `CFG` write
/// that would have made the decision real fails.
#[derive(Debug)]
pub struct Checkpoint(State);

/// Shared by the load, the programmer and the reload.
#[derive(Debug, Clone)]
pub struct DryRunGate(Arc<Mutex<State>>);

impl DryRunGate {
    pub fn new(mode: DryRunMode) -> Self {
        Self(Arc::new(Mutex::new(State {
            mode,
            since: Instant::now(),
            ready: None,
            released: None,
            authority: false,
            repairs_owed: 0,
        })))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn mode(&self) -> DryRunMode {
        self.lock().mode
    }

    /// Whether the mirror has been whole yet.
    pub fn is_ready(&self) -> bool {
        self.lock().ready.is_some()
    }

    /// Whether a completeness authority decides it (see the module docs).
    pub fn set_authority(&self, on: bool) {
        self.lock().authority = on;
    }

    pub fn authority(&self) -> bool {
        self.lock().authority
    }

    /// How many routes are owed a repair (see the field).
    pub fn set_repairs_owed(&self, n: usize) {
        self.lock().repairs_owed = n;
    }

    pub fn repairs_owed(&self) -> usize {
        self.lock().repairs_owed
    }

    /// The latch and the release as they are now. Taken before a decision
    /// under `CFG_WRITE_LOCK`, and handed to [`Self::restore`] if the
    /// write fails, so the row never says forwarding while `CFG` still
    /// holds and a later trigger can still let go.
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint(self.lock().clone())
    }

    /// Put back the mode, the latch and the release from `cp`, as `CFG`
    /// still has them. The row's notes stay as they are now.
    pub fn restore(&self, cp: Checkpoint) {
        let mut s = self.lock();
        s.ready = cp.0.ready;
        s.released = cp.0.released;
        s.since = cp.0.since;
        s.mode = cp.0.mode;
    }

    /// `CFG.dry_run` as the mode and the latch say it should be.
    pub fn byte(&self) -> u8 {
        let s = self.lock();
        match s.mode {
            DryRunMode::On => 1,
            DryRunMode::Off => 0,
            DryRunMode::UntilSeeded => u8::from(s.ready.is_none()),
        }
    }

    /// The mirror is whole. Latches once; returns the release when this
    /// ends an `until-seeded` hold, which the caller makes real by writing
    /// [`Self::byte`]. Call under `CFG_WRITE_LOCK`, with the write.
    pub fn mark_ready(&self, trigger: Trigger) -> Option<Released> {
        let mut s = self.lock();
        if s.ready.is_some() {
            return None;
        }
        let now = Instant::now();
        s.ready = Some((trigger, now));
        Self::release_locked(&mut s, now)
    }

    /// A reload's mode. Returns the release when it turns `until-seeded`
    /// on over a mirror already whole. Call under `CFG_WRITE_LOCK`, then
    /// write [`Self::byte`].
    pub fn set_mode(&self, mode: DryRunMode) -> Option<Released> {
        let mut s = self.lock();
        let now = Instant::now();
        if mode == DryRunMode::UntilSeeded && s.mode != DryRunMode::UntilSeeded {
            // The hold starts here, not at load; over a mirror already
            // whole it ends here too, held for nothing.
            s.since = now;
        }
        s.mode = mode;
        Self::release_locked(&mut s, now)
    }

    fn release_locked(s: &mut State, now: Instant) -> Option<Released> {
        if s.mode != DryRunMode::UntilSeeded || s.released.is_some() {
            return None;
        }
        let (trigger, _) = s.ready?;
        let held = now.saturating_duration_since(s.since);
        s.released = Some((trigger, SystemTime::now(), held));
        Some(Released { trigger, held })
    }

    /// The `dry-run` row: present for `on` and `until-seeded`, absent for
    /// `off`, where there is nothing to say. `waiting_on` names what an
    /// `until-seeded` hold waits for now, from the route-ledger state.
    pub fn health(&self, waiting_on: &str) -> Option<SubsystemHealth> {
        let s = self.lock();
        let message = match (s.mode, s.released) {
            (DryRunMode::Off, _) => return None,
            (DryRunMode::On, _) => "on: every packet passes to the kernel".to_string(),
            (DryRunMode::UntilSeeded, Some((trigger, at, held))) => format!(
                "until-seeded: released at {} ({}) after {}s; forwarding",
                humantime_utc(at),
                trigger.as_str(),
                held.as_secs()
            ),
            (DryRunMode::UntilSeeded, None) => format!(
                "until-seeded: holding for {}s, every packet passes to the kernel; waiting for \
                 {waiting_on}",
                Instant::now().saturating_duration_since(s.since).as_secs()
            ),
        };
        Some(SubsystemHealth {
            name: SUBSYS_DRY_RUN.into(),
            state: HealthState::Healthy,
            message: Some(message),
            last_success_age_seconds: None,
        })
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ`, without a time crate.
fn humantime_utc(t: SystemTime) -> String {
    let secs = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Record a release in the journal and the event log.
pub fn report(r: Released) {
    tracing::info!(
        trigger = r.trigger.as_str(),
        held_ms = r.held.as_millis() as u64,
        "dry-run until-seeded: the route mirror is whole; forwarding"
    );
    packetframe_common::events::Event::info(
        crate::MODULE_NAME,
        packetframe_common::events::kind::DRY_RUN_RELEASED,
    )
    .field("trigger", r.trigger.as_str())
    .field("held_ms", r.held.as_millis() as u64)
    .emit();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mode_is_the_first_dry_run_line_and_off_without_one() {
        use ModuleDirective::*;
        assert_eq!(DryRunMode::of(&[]), DryRunMode::Off);
        assert_eq!(DryRunMode::of(&[DryRun(true)]), DryRunMode::On);
        assert_eq!(
            DryRunMode::of(&[DryRunUntilSeeded, DryRun(false)]),
            DryRunMode::UntilSeeded
        );
        assert_eq!(
            DryRunMode::of(&[DryRun(false), DryRunUntilSeeded]),
            DryRunMode::Off
        );
    }

    #[test]
    fn until_seeded_holds_then_lets_go_once_and_a_reload_never_holds_again() {
        let g = DryRunGate::new(DryRunMode::UntilSeeded);
        assert_eq!(g.byte(), 1);
        let msg = g.health("the seed").unwrap().message.unwrap();
        assert!(
            msg.starts_with("until-seeded: holding") && msg.contains("the seed"),
            "{msg}"
        );

        let r = g.mark_ready(Trigger::SeedWhole).expect("released");
        assert_eq!(r.trigger, Trigger::SeedWhole);
        assert_eq!(g.byte(), 0);
        assert!(
            g.mark_ready(Trigger::InitiationComplete).is_none(),
            "one-shot"
        );
        let msg = g.health("x").unwrap().message.unwrap();
        assert!(
            msg.starts_with("until-seeded: released at") && msg.contains("seed-whole"),
            "{msg}"
        );

        // A reload of the same file: still released.
        assert!(g.set_mode(DryRunMode::UntilSeeded).is_none());
        assert_eq!(g.byte(), 0);
        // An explicit `on` wins, and `until-seeded` again lets go at once.
        assert!(g.set_mode(DryRunMode::On).is_none());
        assert_eq!(g.byte(), 1);
        assert!(
            g.set_mode(DryRunMode::UntilSeeded).is_none(),
            "already released once"
        );
        assert_eq!(g.byte(), 0);
    }

    #[test]
    fn readiness_is_latched_in_every_mode_so_a_later_switch_does_not_wait_for_it() {
        let g = DryRunGate::new(DryRunMode::On);
        assert!(
            g.mark_ready(Trigger::InitiationComplete).is_none(),
            "on: no release"
        );
        assert_eq!(g.byte(), 1);
        let r = g
            .set_mode(DryRunMode::UntilSeeded)
            .expect("released by the reload");
        assert_eq!(r.trigger, Trigger::InitiationComplete);
        assert_eq!(g.byte(), 0);
    }

    #[test]
    fn a_reload_from_off_counts_the_hold_from_the_reload_not_the_load() {
        let g = DryRunGate::new(DryRunMode::Off);
        assert!(g.mark_ready(Trigger::InitiationComplete).is_none());
        std::thread::sleep(Duration::from_millis(30));
        let r = g.set_mode(DryRunMode::UntilSeeded).expect("released");
        assert!(r.held < Duration::from_millis(30), "held {:?}", r.held);
    }

    #[test]
    fn a_failed_write_puts_the_latch_back_so_a_later_trigger_still_lets_go() {
        let g = DryRunGate::new(DryRunMode::UntilSeeded);
        let cp = g.checkpoint();
        assert!(g.mark_ready(Trigger::SeedWhole).is_some());
        g.restore(cp);
        assert!(!g.is_ready());
        assert_eq!(g.byte(), 1);
        let msg = g.health("x").unwrap().message.unwrap();
        assert!(msg.starts_with("until-seeded: holding"), "{msg}");
        let r = g.mark_ready(Trigger::AuthorityAttested).expect("released");
        assert_eq!(r.trigger, Trigger::AuthorityAttested);
    }

    #[test]
    fn off_has_no_row_and_on_says_so() {
        assert!(DryRunGate::new(DryRunMode::Off).health("x").is_none());
        let on = DryRunGate::new(DryRunMode::On).health("x").unwrap();
        assert!(on.message.unwrap().starts_with("on:"));
    }

    #[test]
    fn utc_renders_a_known_instant() {
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_794_528_000);
        assert_eq!(humantime_utc(t), "2026-11-13T00:00:00Z");
    }
}
