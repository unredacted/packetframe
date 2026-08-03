//! Supervision state machine for the VPP child.
//!
//! Pure logic: no processes, no sockets, no clock reads. Everything
//! arrives as an [`Event`] and leaves as an [`Action`], which is what
//! makes the ordering rules below testable at all — the failure modes
//! that matter (a crash while steered, an adoption of a healthy VPP, a
//! restart racing a resync) are exactly the ones that are miserable to
//! reproduce against a live process.
//!
//! Four ordering rules are encoded here, each from a specific way this
//! can go wrong:
//!
//! 1. **Steering is never enabled before a verified resync.** MCAM
//!    diverts by allowlist, not by what we managed to install, so
//!    steering into an unverified FIB blackholes whatever is missing —
//!    and the diverted packet cannot fall back to the eBPF tier
//!    because the hardware already took it.
//! 2. **On process death while steered, steering dies FIRST.** That is
//!    the ≤50 ms number: until the MCAM rules are gone, every steered
//!    packet is going to a VF nothing is servicing. Restart comes
//!    after.
//! 3. **Adoption does NOT unsteer.** A packetframe restart that finds
//!    a healthy VPP still forwarding must resync and verify *while
//!    traffic keeps flowing*; tearing steering down to rebuild it
//!    would create precisely the outage adoption exists to avoid.
//! 4. **No restart while a resync is in flight.** Backoff is measured
//!    against the recovery budget, so a crash loop cannot become a
//!    resync loop that never converges.

use std::time::Duration;

/// Ceiling on restart backoff.
///
/// Deliberately below the published 90 s recovery number: a backoff
/// longer than the recovery budget would mean the *waiting* dominates
/// the outage, and the operator-visible promise would be a function of
/// this constant rather than of how long a resync actually takes.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// First retry delay. Short because the common crash is a transient
/// one and the FIB is still warm in bird's mirror.
pub const BASE_BACKOFF: Duration = Duration::from_millis(250);

/// Where the supervised VPP is in its lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing running; not trying to.
    Stopped,
    /// Waiting out a backoff before the next start attempt.
    Backoff,
    /// Process exists, API not yet answering.
    Starting,
    /// API answering; devices attached; FIB resync in flight.
    Syncing,
    /// Resync drained; readback verification in flight.
    Verifying,
    /// Verified. Steering may be enabled — and only from here.
    Ready,
    /// Traffic is being diverted to VPP.
    Steered,
    /// Adopted a running VPP that is still steered. Resync and verify
    /// run WITHOUT tearing steering down (rule 3), so this is
    /// deliberately distinct from `Syncing`.
    AdoptedResyncing,
}

impl State {
    /// Whether MCAM rules are currently diverting traffic.
    pub fn is_steered(self) -> bool {
        matches!(self, State::Steered | State::AdoptedResyncing)
    }

    /// Whether a supervised process exists that could die or wedge.
    ///
    /// `Backoff` deliberately counts as NO process: the previous one
    /// is already dead and its failure already counted. Without this,
    /// a ping timeout landing just after an exit is handled would
    /// count a second failure and double the backoff for one crash.
    pub fn has_process(self) -> bool {
        !matches!(self, State::Stopped | State::Backoff)
    }

    /// Whether a resync or verify is in flight — the window in which a
    /// restart must not be started (rule 4).
    pub fn is_converging(self) -> bool {
        matches!(
            self,
            State::Syncing | State::Verifying | State::AdoptedResyncing
        )
    }
}

/// Something that happened to the supervised process or its FIB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Operator or module asked for VPP to be running.
    StartRequested,
    /// A child was spawned successfully.
    Spawned,
    /// A pre-existing VPP was adopted from the state file. `steered`
    /// records whether its MCAM rules are still in place, which
    /// decides whether we may keep traffic flowing through it.
    Adopted {
        steered: bool,
    },
    /// The binary API answered.
    ApiUp,
    /// The pending map drained to empty.
    SyncComplete,
    /// Readback verification finished.
    VerifyPassed,
    VerifyFailed,
    /// Steering rules installed.
    Steered,
    /// The process exited — from pidfd, not SIGCHLD, because adoption
    /// reparents the child and SIGCHLD would never arrive.
    ProcessExited {
        status: Option<i32>,
    },
    /// The API ping did not answer within its interval. The process is
    /// alive but not scheduling; treated as death because a wedged
    /// forwarder drops exactly as thoroughly as a dead one.
    Wedged,
    /// Backoff elapsed.
    BackoffElapsed,
    /// Operator asked for a clean stop.
    StopRequested,
}

/// What the caller must do. Ordering within a single transition is
/// significant and given as a `Vec`, because "unsteer then restart"
/// and "restart then unsteer" differ by an outage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Remove MCAM rules. First in any teardown.
    Unsteer,
    /// Kill the process if it is still alive.
    Kill,
    /// Spawn a new VPP.
    Spawn,
    /// Attach devices and create interfaces over the API.
    AttachDevices,
    /// Begin a full FIB resync against the authoritative mirror.
    StartResync,
    /// Begin readback verification.
    StartVerify,
    /// Install MCAM steering rules.
    Steer,
    /// Arm the backoff timer.
    ArmBackoff(Duration),
    /// Release VF/hugepage resources; terminal.
    ReleaseResources,
}

/// Supervision state plus the backoff schedule.
#[derive(Debug, Clone)]
pub struct Supervisor {
    state: State,
    /// Consecutive failures since the last verified-healthy moment.
    failures: u32,
    /// Whether steering was up when the current trouble started —
    /// remembered across the restart so `Ready` knows whether to
    /// re-steer automatically or wait for the operator's canary.
    was_steered: bool,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Supervisor {
    pub fn new() -> Self {
        Self {
            state: State::Stopped,
            failures: 0,
            was_steered: false,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// Backoff for the current failure count: exponential, capped.
    ///
    /// No jitter, deliberately — there is exactly one supervised
    /// process per box and nothing to thunder against, and a
    /// deterministic schedule is one fewer variable when reading a
    /// crash loop out of logs.
    pub fn backoff(&self) -> Duration {
        if self.failures == 0 {
            return BASE_BACKOFF;
        }
        let shift = (self.failures - 1).min(16);
        BASE_BACKOFF
            .checked_mul(1u32 << shift)
            .unwrap_or(MAX_BACKOFF)
            .min(MAX_BACKOFF)
    }

    /// Apply an event, returning the ordered actions to perform.
    pub fn on(&mut self, event: Event) -> Vec<Action> {
        use Event::*;
        use State::*;

        match (self.state, event) {
            // --- starting up ---
            (Stopped, StartRequested) => {
                self.state = Starting;
                vec![Action::Spawn]
            }
            (Backoff, BackoffElapsed) => {
                self.state = Starting;
                vec![Action::Spawn]
            }
            (Starting, Spawned) => vec![],
            (Starting, ApiUp) => {
                self.state = Syncing;
                // Devices first: the FIB paths we are about to install
                // reference interface indices that do not exist until
                // the device is attached and its port interface
                // created.
                vec![Action::AttachDevices, Action::StartResync]
            }

            // --- adoption (rule 3) ---
            (Stopped | Backoff | Starting, Adopted { steered }) => {
                self.was_steered = steered;
                // An adopted VPP is presumed good until proven stale:
                // mark dirty, resync, verify — but do NOT unsteer a
                // correctly-forwarding dataplane to do it.
                self.state = if steered { AdoptedResyncing } else { Syncing };
                vec![Action::AttachDevices, Action::StartResync]
            }

            // --- converging ---
            (Syncing | AdoptedResyncing, SyncComplete) => {
                self.state = Verifying;
                vec![Action::StartVerify]
            }
            (Verifying, VerifyPassed) => {
                self.state = Ready;
                self.failures = 0;
                // Re-steer automatically only if traffic was already
                // flowing before the disruption. A first attach waits
                // for the operator's explicit canary — that is the
                // whole point of `steer on|off` being per port.
                if self.was_steered {
                    self.state = State::Steered;
                    vec![Action::Steer]
                } else {
                    vec![]
                }
            }
            (Verifying, VerifyFailed) => {
                // A FIB we cannot verify is not one to divert traffic
                // into. Treat as a failure and cycle, rather than
                // steering optimistically.
                self.fail()
            }
            (Ready, Event::Steered) => {
                self.state = State::Steered;
                self.was_steered = true;
                vec![]
            }

            // --- death and wedging ---
            (s, ProcessExited { .. }) | (s, Wedged) if s.has_process() => {
                if s.is_steered() {
                    self.was_steered = true;
                }
                self.fail()
            }

            // --- clean stop ---
            (s, StopRequested) => {
                let mut actions = Vec::new();
                if s.is_steered() {
                    actions.push(Action::Unsteer);
                }
                actions.push(Action::Kill);
                actions.push(Action::ReleaseResources);
                self.state = Stopped;
                self.was_steered = false;
                self.failures = 0;
                actions
            }

            // Anything else is a no-op: events can race (a ping
            // timeout arriving just after an exit), and treating a
            // stale event as a state change is how a supervisor
            // restarts something it already restarted.
            _ => vec![],
        }
    }

    /// Common teardown for death, wedging, and failed verification.
    ///
    /// Steering comes down FIRST (rule 2) — until it does, every
    /// steered packet is going to a VF nothing is servicing.
    fn fail(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        if self.state.is_steered() {
            actions.push(Action::Unsteer);
        }
        actions.push(Action::Kill);
        self.failures = self.failures.saturating_add(1);
        let delay = self.backoff();
        self.state = State::Backoff;
        actions.push(Action::ArmBackoff(delay));
        actions
    }

    /// Whether a restart may be started right now (rule 4).
    ///
    /// The caller checks this before acting on a `BackoffElapsed`: a
    /// resync still draining means the previous attempt has not
    /// finished failing, and starting another would stack two loads
    /// onto one VPP.
    pub fn may_restart(&self) -> bool {
        !self.state.is_converging()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn running_and_steered() -> Supervisor {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::Spawned);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        s.on(Event::VerifyPassed);
        s.on(Event::Steered);
        assert_eq!(s.state(), State::Steered);
        s
    }

    #[test]
    fn first_attach_does_not_steer_itself() {
        // Steering is the operator's canary lever; a fresh attach
        // reaching Ready must WAIT rather than divert traffic on its
        // own initiative.
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        let actions = s.on(Event::VerifyPassed);
        assert_eq!(s.state(), State::Ready);
        assert!(
            !actions.contains(&Action::Steer),
            "a first attach must not steer without being asked"
        );
    }

    #[test]
    fn devices_are_attached_before_the_resync() {
        // FIB paths reference interface indices that do not exist
        // until the device is attached — installing first would defer
        // every route.
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        let actions = s.on(Event::ApiUp);
        assert_eq!(
            actions,
            vec![Action::AttachDevices, Action::StartResync],
            "device attach must precede the resync"
        );
    }

    #[test]
    fn steering_is_never_reached_without_a_passing_verify() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        assert_eq!(s.state(), State::Verifying);
        // A Steered event arriving out of order must not promote us.
        s.on(Event::Steered);
        assert_eq!(s.state(), State::Verifying, "verify gates steering");
    }

    #[test]
    fn a_crash_while_steered_unsteers_before_anything_else() {
        // The 50 ms number: until MCAM is torn down, steered packets
        // go to a VF nothing services.
        let mut s = running_and_steered();
        let actions = s.on(Event::ProcessExited { status: Some(139) });
        assert_eq!(actions[0], Action::Unsteer, "unsteer must come first");
        assert!(actions.contains(&Action::Kill));
        assert!(matches!(actions.last(), Some(Action::ArmBackoff(_))));
        assert_eq!(s.state(), State::Backoff);
    }

    #[test]
    fn a_wedge_is_treated_exactly_like_a_death() {
        // A process that is alive but not scheduling drops just as
        // thoroughly as one that exited.
        let mut s = running_and_steered();
        let actions = s.on(Event::Wedged);
        assert_eq!(actions[0], Action::Unsteer);
        assert!(actions.contains(&Action::Kill));
    }

    #[test]
    fn adoption_of_a_steered_vpp_does_not_unsteer_it() {
        // Rule 3, and the reason AdoptedResyncing exists as its own
        // state: tearing steering down to rebuild it would create the
        // outage adoption exists to avoid.
        let mut s = Supervisor::new();
        let actions = s.on(Event::Adopted { steered: true });
        assert_eq!(s.state(), State::AdoptedResyncing);
        assert!(
            !actions.contains(&Action::Unsteer),
            "a correctly-forwarding VPP must keep forwarding"
        );
        assert!(s.state().is_steered());
        assert_eq!(actions, vec![Action::AttachDevices, Action::StartResync]);
    }

    #[test]
    fn adoption_resyncs_and_verifies_then_keeps_steering() {
        let mut s = Supervisor::new();
        s.on(Event::Adopted { steered: true });
        s.on(Event::SyncComplete);
        assert_eq!(s.state(), State::Verifying);
        let actions = s.on(Event::VerifyPassed);
        assert_eq!(s.state(), State::Steered);
        assert!(
            actions.contains(&Action::Steer),
            "re-assert rules after adoption so ours own them"
        );
    }

    #[test]
    fn adoption_of_an_unsteered_vpp_waits_for_the_canary() {
        let mut s = Supervisor::new();
        s.on(Event::Adopted { steered: false });
        assert_eq!(s.state(), State::Syncing);
        s.on(Event::SyncComplete);
        let actions = s.on(Event::VerifyPassed);
        assert_eq!(s.state(), State::Ready);
        assert!(!actions.contains(&Action::Steer));
    }

    #[test]
    fn a_restart_re_steers_only_if_traffic_was_flowing_before() {
        let mut s = running_and_steered();
        s.on(Event::ProcessExited { status: None });
        s.on(Event::BackoffElapsed);
        assert_eq!(s.state(), State::Starting);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        let actions = s.on(Event::VerifyPassed);
        assert_eq!(s.state(), State::Steered);
        assert!(
            actions.contains(&Action::Steer),
            "traffic was flowing before the crash, so restore it"
        );
    }

    #[test]
    fn no_restart_while_a_resync_is_in_flight() {
        // Rule 4: a crash loop must not become a resync loop.
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ApiUp);
        assert_eq!(s.state(), State::Syncing);
        assert!(!s.may_restart(), "a draining resync blocks a restart");
        s.on(Event::SyncComplete);
        assert!(!s.may_restart(), "so does an in-flight verify");
        s.on(Event::VerifyPassed);
        assert!(s.may_restart());
    }

    #[test]
    fn a_failed_verify_cycles_rather_than_steering_optimistically() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        let actions = s.on(Event::VerifyFailed);
        assert_eq!(s.state(), State::Backoff);
        assert!(actions.contains(&Action::Kill));
        assert_eq!(s.failures(), 1);
    }

    #[test]
    fn backoff_grows_then_caps_below_the_recovery_budget() {
        let mut s = Supervisor::new();
        assert_eq!(s.backoff(), BASE_BACKOFF);
        let mut seen = Vec::new();
        for _ in 0..12 {
            s.on(Event::StartRequested);
            s.on(Event::ProcessExited { status: None });
            seen.push(s.backoff());
            s.on(Event::BackoffElapsed);
        }
        assert!(
            seen.windows(2).all(|w| w[1] >= w[0]),
            "backoff must be monotonic: {seen:?}"
        );
        assert_eq!(*seen.last().unwrap(), MAX_BACKOFF);
        assert!(
            MAX_BACKOFF < Duration::from_secs(90),
            "a backoff above the recovery budget would make the published \
             number a function of this constant rather than of resync time"
        );
    }

    #[test]
    fn a_healthy_verify_clears_the_failure_count() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        s.on(Event::ProcessExited { status: None });
        s.on(Event::ProcessExited { status: None });
        assert!(s.failures() >= 1);
        s.on(Event::BackoffElapsed);
        s.on(Event::ApiUp);
        s.on(Event::SyncComplete);
        s.on(Event::VerifyPassed);
        assert_eq!(s.failures(), 0, "a healthy cycle resets the schedule");
        assert_eq!(s.backoff(), BASE_BACKOFF);
    }

    #[test]
    fn a_stale_event_is_a_no_op_not_a_second_restart() {
        // A ping timeout can land just after an exit was handled.
        // Acting on both would restart something already restarting.
        let mut s = running_and_steered();
        s.on(Event::ProcessExited { status: None });
        let failures = s.failures();
        let actions = s.on(Event::Wedged);
        assert!(actions.is_empty(), "the second event must do nothing");
        assert_eq!(s.failures(), failures, "and must not count twice");
    }

    #[test]
    fn stop_unsteers_then_kills_then_releases() {
        let mut s = running_and_steered();
        let actions = s.on(Event::StopRequested);
        assert_eq!(
            actions,
            vec![Action::Unsteer, Action::Kill, Action::ReleaseResources],
            "teardown order is steering, process, resources"
        );
        assert_eq!(s.state(), State::Stopped);
    }

    #[test]
    fn stopping_an_unsteered_supervisor_skips_the_unsteer() {
        let mut s = Supervisor::new();
        s.on(Event::StartRequested);
        let actions = s.on(Event::StopRequested);
        assert!(!actions.contains(&Action::Unsteer));
        assert_eq!(actions, vec![Action::Kill, Action::ReleaseResources]);
    }

    #[test]
    fn events_while_stopped_do_nothing() {
        let mut s = Supervisor::new();
        assert!(s.on(Event::ProcessExited { status: None }).is_empty());
        assert!(s.on(Event::Wedged).is_empty());
        assert_eq!(s.state(), State::Stopped);
        assert_eq!(s.failures(), 0);
    }
}
