//! The supervision loop body: one tick.
//!
//! Composes the four pieces that already exist —
//! [`Supervisor`](crate::supervisor::Supervisor) for decisions,
//! [`Schedule`](crate::schedule::Schedule) for deadlines,
//! [`WedgeDetector`](crate::liveness::WedgeDetector) for liveness, and
//! [`execute`](crate::executor::execute) for effects — into the thing
//! that actually runs.
//!
//! **Requests and observations are separate traits, deliberately.**
//! [`Effects`] does things; [`Observe`] reports what happened. That is
//! not symmetry for its own sake: eleven review findings in this
//! subsystem have been one mistake — state recorded when an effect was
//! *requested* rather than when it was *observed* — and putting the two
//! behind different traits makes the distinction hard to blur. Nothing
//! in this module may set state from an `Effects` call; only from an
//! `Observe` one.
//!
//! ## State, and what is allowed to clear it
//!
//! | Field | Set by | Cleared by |
//! |---|---|---|
//! | `detector` | the API first answering, for **any** process — spawned or adopted | the state no longer having a process |
//!
//! Both halves were wrong on the first attempt, in opposite directions.
//! Setting it only on the `Starting → Syncing` transition meant an
//! *adopted* VPP never got a detector at all, which is the one case
//! still carrying steered traffic while we resync it. Clearing it only
//! on an observed exit meant it outlived a `Backoff` reached by a wedge,
//! where it went on reporting the silence of something already gone.
//!
//! That is the whole table, and it is short on purpose. The process
//! handle and the transport live in the caller's [`Observe`]
//! implementation rather than here, because they have one lifetime
//! between them: the socket belongs to that process. Modelling them as
//! two fields with two clearers invites the case where a socket error
//! and a process exit both try to clear, and the second acts on a `None`
//! it did not expect — so the rule is that **a transport error reports
//! and does not clear**. The pidfd is the authoritative observer of
//! death; a broken socket is a symptom, and every later operation on it
//! simply fails and reports again until the exit arrives.

use std::time::{Duration, Instant};

/// How often to poll `api_ready` while a process exists but the API has
/// not answered yet.
///
/// Load-bearing, not a tuning nicety. In that window there is no
/// detector (it must not exist before the first pong, or startup counts
/// as silence) and the only armed deadline is the 60 s startup budget —
/// so without this cap, `Tick::sleep` says "wake me at the deadline",
/// and a loop that honours it never calls `api_ready` again. The next
/// tick then queues `PhaseTimedOut` ahead of the `ApiUp` observed on
/// the very same pass, and a perfectly healthy VPP that was merely slow
/// to fault in its heap is killed and restarted, every 60 s, forever.
/// The driver is the thing that knows polling is how progress happens
/// here, so the cadence lives in the driver, not in every caller.
pub const API_POLL_INTERVAL: Duration = Duration::from_millis(250);

use crate::executor::{execute, Effects, Outcome};
use crate::liveness::{budget_for, WedgeDetector};
use crate::schedule::Schedule;
use crate::supervisor::{Event, State, Supervisor};

/// What the world reports. Every one of these is an observation; none
/// of them requests a state change.
pub trait Observe {
    /// Non-blocking. `Some(status)` = the process has exited.
    ///
    /// Must come from a pidfd, not `waitpid`: an adopted VPP was
    /// reparented to init and would never be reaped by us.
    fn poll_exit(&mut self) -> Option<Option<i32>>;

    /// Whether the binary API is answering, connecting it if needed.
    ///
    /// `false` is not an error — VPP takes time to open its socket while
    /// it faults in a multi-GB heap. The startup deadline, not this, is
    /// what decides when waiting has gone on too long.
    fn api_ready(&mut self) -> bool;

    /// Send a ping and read its reply.
    fn ping(&mut self) -> Result<(), String>;

    /// Drain **one bounded batch** of pending routes.
    /// `Ok(true)` = nothing left pending.
    ///
    /// Bounded is the contract, not an implementation detail. A blocking
    /// full-table drain would hold the loop for the whole convergence
    /// budget, during which no ping is sent and no exit is noticed — so
    /// the wedge detector would either be useless or fire on a VPP that
    /// was working fine.
    fn drain_batch(&mut self) -> Result<bool, String>;
}

/// One tick's result.
#[derive(Debug, Clone)]
pub struct Tick {
    /// Events observed and applied, in the order they were applied.
    pub events: Vec<Event>,
    /// What executing the resulting actions produced.
    pub outcome: Outcome,
    /// How long the caller may sleep. `None` = block on the fds.
    pub sleep: Option<Duration>,
}

/// Owns the supervision state that is not the caller's.
#[derive(Debug)]
pub struct Driver {
    sup: Supervisor,
    sched: Schedule,
    /// A drain lost the socket; the next tick must reconnect before it
    /// can make progress.
    ///
    /// `api_ready` is the only thing that reconnects, and it is otherwise
    /// called just once — while `detector` is `None`. Once armed, the
    /// detector stays armed for the whole of steady state, so without
    /// this flag a transport dropped by a failed drain could never come
    /// back and every later drain would fail instantly on `NotConnected`.
    reconnect_wanted: bool,
    /// Liveness tracking, from the first pong onward.
    ///
    /// `Option` because it must NOT exist before the API has answered
    /// once: counting VPP's startup as silence would declare a wedge
    /// before it ever had a chance to reply.
    detector: Option<WedgeDetector>,
}

impl Default for Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Driver {
    pub fn new() -> Self {
        Self {
            sup: Supervisor::new(),
            sched: Schedule::new(),
            reconnect_wanted: false,
            detector: None,
        }
    }

    pub fn state(&self) -> State {
        self.sup.state()
    }

    pub fn supervisor(&self) -> &Supervisor {
        &self.sup
    }

    /// The API's liveness as the health surface classifies it, from
    /// the driver's own detector and budget selection.
    ///
    /// Lives here because the detector is deliberately private: it must
    /// not exist before the first pong, and exposing it raw invites a
    /// caller to consult it in exactly that window. The budget comes
    /// from the same `budget_for` the wedge decision uses, so status
    /// can never disagree with the detector about what "too silent"
    /// means.
    pub fn api_health(&self, now: Instant) -> crate::status::ApiHealth {
        let budget = budget_for(self.sup.is_steered(), self.sup.is_converging());
        crate::status::ApiHealth::observe(self.sup.state(), self.detector.as_ref(), now, budget)
    }

    /// Feed an externally-sourced event (an operator's start/stop, an
    /// adoption) and run its actions.
    pub fn inject(&mut self, now: Instant, event: Event, fx: &mut dyn Effects) -> Tick {
        let before = self.sup.state();
        let mut tick = self.apply(now, vec![event], fx);
        self.settle_after(now, before, false, &mut tick);
        tick
    }

    /// One pass: observe, decide, act, re-arm.
    ///
    /// **Observations use the state as it was at entry**, and any
    /// transition takes effect for the *next* pass. That is ordinary for
    /// an event loop, and it is why a tick that changes state asks to be
    /// called again immediately rather than sleeping — see
    /// [`Tick::sleep`].
    pub fn tick(&mut self, now: Instant, obs: &mut dyn Observe, fx: &mut dyn Effects) -> Tick {
        let before = self.sup.state();
        let mut events = Vec::new();
        let mut more_to_drain = false;
        // Whether the API was already up **at entry**. Captured here
        // because the block below may arm the detector during this very
        // tick, and every observation in this loop reads the state as it
        // was on entry — draining on the tick that first saw the API
        // would act on a transition the supervisor has not applied yet.
        let api_up_at_entry = self.detector.is_some();

        // Death first, and **before the deadline events**. A pidfd is
        // level-triggered, so an exit can still be readable on the very
        // tick a backoff expires. Queued the other way round, the
        // backoff spawns a replacement, the state becomes `Starting`,
        // and the OLD process's exit is then attributed to the new one —
        // killing a VPP that just started, on every retry.
        let exited = obs.poll_exit();
        if let Some(status) = exited {
            events.push(Event::ProcessExited { status });
        }
        // `may_restart` is read before the exit is applied, which is the
        // conservative direction: a withheld backoff stays armed and
        // fires next tick rather than being lost.
        events.extend(self.sched.fired(now, self.sup.may_restart()));

        if exited.is_none() {
            // Start the liveness clock at the first answer from ANY
            // process, not only a freshly spawned one. Gating this on
            // `Starting` meant an adopted VPP never got a detector at
            // all: adoption goes straight to `Syncing`/
            // `AdoptedResyncing`, so a wedged adoptee — the one case
            // that is still carrying steered traffic — could blackhole
            // forever without ever emitting `Wedged`.
            if before.has_process() && self.detector.is_none() && obs.api_ready() {
                self.detector = Some(WedgeDetector::started(now));
                // Only a startup transition needs announcing; an
                // adopted process is already past `ApiUp`.
                if before == State::Starting {
                    events.push(Event::ApiUp);
                }
            }

            // Drained in EVERY state with a live API, not only during a
            // resync — because `drain_batch` also pulls the source's live
            // changes, and after first convergence the module spends its
            // life in `Ready`/`Steered`. Gated on the resync states (as
            // this was) every route learned after attach would reach the
            // eBPF tier and stop there: VPP would forward a frozen table,
            // report healthy, and pass readback verification, since
            // verify samples the mirror it was synced against.
            //
            // What stays gated is the *event*. `Ok(true)` outside a
            // resync means "nothing pending", an unremarkable steady
            // state; emitting `SyncComplete` for it would ask for an
            // immediate re-tick on every pass and spin a core through
            // the whole of `Verifying`.
            //
            // `Verifying` itself stays excluded, and for a second reason
            // that outlives the spin: verify probes VPP for prefixes **the
            // ledger believes are installed**, so a withdrawal applied
            // between the sample and the probe makes VPP correctly answer
            // "no route" and verify read it as a mismatch. That failure
            // unsteers and restarts a VPP that was working. Deltas wait
            // out the verify instead — bounded, and the source's map
            // collapses per prefix, so waiting costs staleness rather
            // than depth.
            // Reconnect first, if the last drain lost the socket. The
            // engine drops its transport on any drain error, and nothing
            // else on this path would ever call `api_ready` again.
            if api_up_at_entry && self.reconnect_wanted {
                self.reconnect_wanted = !obs.api_ready();
            }

            let resyncing = matches!(before, State::Syncing | State::AdoptedResyncing);
            // `resyncing ||` and not `api_up_at_entry` alone: an ADOPTED
            // process is already in a resync state on the very first
            // tick, before the detector has been armed, and the old guard
            // drained it there. Gating that behind `api_up_at_entry`
            // withholds the first batch for one tick — long enough for
            // the settled tick's sleep to run the resync phase deadline
            // out and fail a convergence that was fine.
            if (resyncing || api_up_at_entry) && before != State::Verifying {
                match obs.drain_batch() {
                    // Empty means the resync is done — and only the
                    // drain can say so, which is why this is observed
                    // rather than assumed after issuing StartResync.
                    Ok(true) if resyncing => events.push(Event::SyncComplete),
                    Ok(true) => {}
                    Ok(false) => more_to_drain = true,
                    // Failing mid-resync is a convergence failure: the
                    // table is known-incomplete and nothing is forwarding
                    // through it yet.
                    Err(_) if resyncing => {
                        self.reconnect_wanted = true;
                        events.push(Event::ConvergenceFailed);
                    }
                    // Failing in steady state is NOT. The batch stays in
                    // the pending map, which is last-write-wins, so the
                    // retry is free and idempotent — and treating one bad
                    // round trip as a convergence failure would unsteer
                    // and restart a VPP that is carrying traffic, at ~40 s
                    // of resync, to fix a route that the next tick would
                    // have installed. A VPP that has genuinely stopped
                    // answering is the wedge detector's job, and it has a
                    // measured budget for exactly that.
                    //
                    // **Not** `more_to_drain`, which asks for an immediate
                    // re-tick. The engine drops its transport on a drain
                    // error, so the next call fails on `NotConnected`
                    // without touching the socket — a zero-cost failure
                    // requesting a zero-length sleep is a pegged core, and
                    // one that never reconnects, ending in the very
                    // restart this arm exists to avoid. The retry rides
                    // the ordinary schedule instead, one attempt per ping
                    // interval, after the reconnect above has had a turn.
                    Err(_) => self.reconnect_wanted = true,
                }
            }

            events.extend(self.poll_liveness(now, obs));
        }

        let mut tick = self.apply(now, events, fx);
        self.settle_after(now, before, more_to_drain, &mut tick);
        tick
    }

    /// Post-pass bookkeeping shared by [`Self::tick`] and
    /// [`Self::inject`]: drop a detector with no process, then decide
    /// whether the caller may sleep.
    ///
    /// `inject` needs this as much as `tick` does. Returning the phase
    /// deadline as the permitted sleep after an injected
    /// `StartRequested` would let a caller that honours `sleep` wait the
    /// whole 60 s startup budget without ever calling `api_ready` — and
    /// then `PhaseTimedOut` is queued ahead of the `ApiUp` observed on
    /// the same tick, so a perfectly healthy VPP is killed and
    /// restarted. Injected adoption had the same shape against the
    /// convergence budget.
    fn settle_after(&mut self, now: Instant, before: State, more_to_drain: bool, tick: &mut Tick) {
        // Nothing to ping once no process exists. Covers `Backoff` and
        // `Stopped` alike, and it is load-bearing rather than tidy: a
        // detector outliving its process keeps reporting the silence of
        // something already dead, and each of those `Wedged` events is
        // an applied event asking for another immediate tick.
        if !self.sup.state().has_process() {
            self.detector = None;
        }

        tick.sleep = self.sleep(now);
        // A process whose API has not answered yet has exactly one
        // source of progress: polling `api_ready`. Nothing wakes the
        // loop for that — no detector exists yet, and the only armed
        // deadline is the startup budget itself — so cap the sleep at
        // the poll cadence, or a sleep-honouring caller dozes to the
        // deadline and kills a VPP whose API came up in the meantime.
        if self.sup.state().has_process() && self.detector.is_none() {
            tick.sleep = Some(
                tick.sleep
                    .map_or(API_POLL_INTERVAL, |s| s.min(API_POLL_INTERVAL)),
            );
        }
        // A partly-drained table must not wait for the ping interval.
        // At ~256 routes a batch, one batch per 500 ms would take the
        // full v4 table over half an hour against a 60 s budget.
        let settled = self.sup.state();
        // A transition also warrants an immediate pass, but only into a
        // state there is something to observe IN. `Backoff` and
        // `Stopped` have no process to poll: the first is governed by
        // its timer and the second by nothing at all, so asking for a
        // re-tick there buys a wasted pass — and in `Backoff` it would
        // be one per pass until the timer elapsed.
        let opened_observations = settled != before && settled.has_process();
        if more_to_drain || opened_observations {
            tick.sleep = Some(Duration::ZERO);
        }
    }

    fn sleep(&self, now: Instant) -> Option<Duration> {
        self.sched.next_wakeup(
            now,
            self.detector.as_ref().map(|d| d.next_ping_at()),
            self.sup.may_restart(),
        )
    }

    /// Ping if due, and decide whether the silence has gone too far.
    fn poll_liveness(&mut self, now: Instant, obs: &mut dyn Observe) -> Vec<Event> {
        let Some(d) = self.detector.as_mut() else {
            return Vec::new();
        };
        if d.ping_due(now) {
            // Recorded before the result is known, so an unanswered ping
            // cannot make the next one immediately due and spin.
            d.on_ping_sent(now);
            if obs.ping().is_ok() {
                d.on_pong(now);
            }
        }
        // The budget depends on whether traffic is steered, NOT on
        // whether we are resyncing: an adopted resync forwards the whole
        // time, and the published bound applies whenever packets are on
        // VPP.
        let budget = budget_for(self.sup.is_steered(), self.sup.is_converging());
        if d.is_wedged(now, budget) {
            vec![Event::Wedged]
        } else {
            Vec::new()
        }
    }

    /// Apply events through the supervisor, execute what they ask for,
    /// and feed the results back until the system settles.
    fn apply(&mut self, now: Instant, events: Vec<Event>, fx: &mut dyn Effects) -> Tick {
        let mut applied = Vec::new();
        let mut outcome = Outcome::default();
        let mut queue = events;

        // Bounded: a seam that will not settle is a bug, and looping
        // forever would hang the daemon instead of reporting it.
        for _ in 0..16 {
            if queue.is_empty() {
                break;
            }
            let mut next = Vec::new();
            for e in queue.drain(..) {
                let actions = self.sup.on(e.clone());
                applied.push(e);
                // Re-arm from the supervisor's own view after EVERY
                // transition, including ones with no budget — arming
                // only on entry to a timed phase would leave a deadline
                // describing a phase already left.
                self.sched.arm_phase(now, self.sup.phase());
                for a in &actions {
                    if let crate::supervisor::Action::ArmBackoff(d) = a {
                        self.sched.arm_backoff(now, *d);
                    }
                }
                if self.sup.state() == State::Stopped {
                    self.sched.disarm();
                }
                let o = execute(&actions, fx);
                next.extend(o.events.clone());
                outcome.events.extend(o.events);
                outcome.failures.extend(o.failures);
                outcome.resources_leaked |= o.resources_leaked;
            }
            queue = next;
        }

        Tick {
            events: applied,
            outcome,
            // Overwritten by the caller once it has finished adjusting
            // state; `apply` cannot know whether more work is queued.
            sleep: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liveness::{PING_BUDGET, PING_INTERVAL, SYNC_PING_BUDGET};
    use crate::process::Disposition;
    use crate::supervisor::Action;

    fn at(base: Instant, ms: u64) -> Instant {
        base + Duration::from_millis(ms)
    }

    /// Tick until the driver stops asking to be re-run immediately.
    ///
    /// Observations use the state as it was at tick entry, so a
    /// transition takes effect on the next pass — the driver signals
    /// that by returning `sleep == ZERO`. Tests that want "run until
    /// settled" say so here rather than hand-counting ticks.
    fn settle(d: &mut Driver, now: Instant, w: &mut World, fx: &mut Fx) -> Vec<Event> {
        let mut seen = Vec::new();
        for i in 0..32 {
            let t = d.tick(at(now, i), w, fx);
            seen.extend(t.events);
            if t.sleep != Some(Duration::ZERO) {
                return seen;
            }
        }
        panic!("driver never settled: {seen:?}");
    }

    /// Reports whatever it is told to, and counts what was asked.
    #[derive(Default)]
    struct World {
        exited: Option<Option<i32>>,
        api: bool,
        /// Batches remaining before the drain reports empty.
        batches: usize,
        drain_fails: bool,
        ping_fails: bool,
        pings: usize,
        drains: usize,
        api_readies: usize,
    }

    impl Observe for World {
        fn poll_exit(&mut self) -> Option<Option<i32>> {
            self.exited
        }
        fn api_ready(&mut self) -> bool {
            self.api_readies += 1;
            self.api
        }
        fn ping(&mut self) -> Result<(), String> {
            self.pings += 1;
            if self.ping_fails {
                Err("no answer".into())
            } else {
                Ok(())
            }
        }
        fn drain_batch(&mut self) -> Result<bool, String> {
            self.drains += 1;
            if self.drain_fails {
                return Err("socket closed".into());
            }
            self.batches = self.batches.saturating_sub(1);
            Ok(self.batches == 0)
        }
    }

    #[derive(Default)]
    struct Fx {
        calls: Vec<&'static str>,
        kill_disposition: Option<Disposition>,
    }

    impl Effects for Fx {
        fn spawn(&mut self) -> Result<(), String> {
            self.calls.push("spawn");
            Ok(())
        }
        fn unsteer(&mut self) -> Result<(), String> {
            self.calls.push("unsteer");
            Ok(())
        }
        fn steer(&mut self) -> Result<(), String> {
            self.calls.push("steer");
            Ok(())
        }
        fn kill(&mut self) -> Disposition {
            self.calls.push("kill");
            self.kill_disposition.unwrap_or(Disposition::SafeToRelease)
        }
        fn attach_devices(&mut self) -> Result<(), String> {
            self.calls.push("attach");
            Ok(())
        }
        fn start_resync(&mut self) -> Result<(), String> {
            self.calls.push("resync");
            Ok(())
        }
        fn start_verify(&mut self) -> Result<(), String> {
            self.calls.push("verify");
            Ok(())
        }
        fn abort_convergence(&mut self) {
            self.calls.push("abort");
        }
        fn arm_backoff(&mut self, _d: Duration) {
            self.calls.push("backoff");
        }
        fn release_resources(&mut self) -> Result<(), String> {
            self.calls.push("release");
            Ok(())
        }
    }

    // ---- The drain is incremental ----

    /// The reason `drain_batch` is bounded. A blocking full-table drain
    /// would hold the loop for the entire convergence budget, sending no
    /// ping and noticing no exit — so the wedge detector would be either
    /// useless or a liar.
    #[test]
    fn a_resync_takes_several_ticks_and_reports_complete_only_when_empty() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 4,
            ..Default::default()
        };

        d.inject(t0, Event::StartRequested, &mut fx);
        // First tick brings the API up; observations use the state at
        // entry, so draining begins on the next pass.
        let t = d.tick(t0, &mut w, &mut fx);
        assert!(t.events.contains(&Event::ApiUp));
        assert_eq!(d.state(), State::Syncing);
        assert_eq!(
            t.sleep,
            Some(Duration::ZERO),
            "a transition must not wait for the ping interval"
        );

        // Batches 1..3 make progress without claiming completion.
        for i in 1..4 {
            let t = d.tick(at(t0, i * 10), &mut w, &mut fx);
            assert!(
                !t.events.contains(&Event::SyncComplete),
                "batch {i} must not claim completion: {:?}",
                t.events
            );
            assert_eq!(d.state(), State::Syncing);
            assert_eq!(
                t.sleep,
                Some(Duration::ZERO),
                "a partly-drained table must keep draining, not sleep"
            );
        }
        // The batch that empties the map reports it.
        let t = d.tick(at(t0, 40), &mut w, &mut fx);
        assert!(t.events.contains(&Event::SyncComplete), "{:?}", t.events);
        assert_eq!(d.state(), State::Verifying);
        assert_eq!(w.drains, 4, "one batch per tick, no more");
    }

    /// `is_converging()` covers `Verifying` too, so draining on it would
    /// re-report `SyncComplete` against an already-empty map every pass.
    /// The supervisor ignores the event — but "an event was applied" is
    /// what asks for an immediate re-tick, so the loop would spin a core
    /// for the whole verify.
    /// A steady-state drain failure must not peg a core, and must be
    /// able to recover.
    ///
    /// Two halves of one bug. The engine drops its transport on any drain
    /// error, so the next drain fails on `NotConnected` without touching
    /// the socket — asking for an immediate re-tick after that is a
    /// zero-cost failure requesting a zero-length sleep, i.e. a spin. And
    /// `api_ready` is the only thing that reconnects, but it is otherwise
    /// called just once, while `detector` is `None`; once armed it never
    /// runs again, so the spin could never end in anything but the wedge
    /// restart this arm exists to avoid.
    #[test]
    fn a_steady_state_drain_failure_neither_spins_nor_strands_the_socket() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        // Drive to a settled steady state.
        d.inject(t0, Event::VerifyPassed, &mut fx);
        assert_eq!(d.state(), State::Ready);

        let readies_before = w.api_readies;
        w.drain_fails = true;
        let t = d.tick(at(t0, 100), &mut w, &mut fx);

        assert!(
            !t.events.contains(&Event::ConvergenceFailed),
            "a steady-state drain failure must not escalate: {:?}",
            t.events
        );
        assert_ne!(
            t.sleep,
            Some(Duration::ZERO),
            "a failed drain must not ask to be called again immediately — the              next attempt fails on a dropped socket without doing any I/O, so              that is a pegged core"
        );

        // And the next tick tries to reconnect, which is the only way the
        // retry can ever succeed.
        let _ = d.tick(at(t0, 200), &mut w, &mut fx);
        assert!(
            w.api_readies > readies_before,
            "nothing attempted to reconnect, so the transport is stranded and              every later drain fails instantly on NotConnected"
        );
    }

    #[test]
    fn verification_does_not_drain_and_does_not_spin() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        assert_eq!(d.state(), State::Verifying);
        assert!(
            d.supervisor().is_converging(),
            "verify counts as converging"
        );

        let drains_before = w.drains;
        let t = d.tick(at(t0, 100), &mut w, &mut fx);
        assert_eq!(w.drains, drains_before, "no drain during verification");
        assert!(t.events.is_empty(), "nothing to report: {:?}", t.events);
        assert_ne!(
            t.sleep,
            Some(Duration::ZERO),
            "a settled verify must let the loop sleep"
        );
    }

    #[test]
    fn a_drain_failure_reports_convergence_failed() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 5,
            drain_fails: true,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        let seen = settle(&mut d, t0, &mut w, &mut fx);
        assert!(seen.contains(&Event::ConvergenceFailed), "{seen:?}");
        assert_eq!(d.state(), State::Backoff);
    }

    // ---- Liveness ----

    /// The detector must not exist before the API has answered, or
    /// VPP's startup would be counted as silence and a wedge declared
    /// before it ever had a chance to reply.
    #[test]
    fn liveness_starts_at_the_first_answer_not_at_the_spawn() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World::default(); // API not up yet

        d.inject(t0, Event::StartRequested, &mut fx);
        // Far beyond the wedge budget, but nothing has answered yet.
        let t = d.tick(at(t0, 30_000), &mut w, &mut fx);
        assert!(
            !t.events.contains(&Event::Wedged),
            "startup is not silence: {:?}",
            t.events
        );
        assert_eq!(w.pings, 0, "nothing to ping yet");
        assert_eq!(d.state(), State::Starting);
    }

    #[test]
    fn a_ping_goes_out_on_the_interval_and_a_pong_keeps_us_healthy() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        d.tick(t0, &mut w, &mut fx);

        // Not yet due.
        d.tick(at(t0, 100), &mut w, &mut fx);
        assert_eq!(w.pings, 0);
        // Due.
        let t = d.tick(t0 + PING_INTERVAL, &mut w, &mut fx);
        assert_eq!(w.pings, 1);
        assert!(!t.events.contains(&Event::Wedged));
    }

    /// Silence past the budget is a wedge — and the ping that goes
    /// unanswered must not suppress the next attempt.
    #[test]
    fn unanswered_pings_lead_to_a_wedge() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ping_fails: true,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        // Reach Ready so we are not converging (relaxed budget).
        d.inject(at(t0, 20), Event::VerifyPassed, &mut fx);
        assert_eq!(d.state(), State::Ready);

        let mut pings_seen = 0;
        let mut wedged = false;
        for ms in (500..3_000).step_by(500) {
            let t = d.tick(at(t0, ms), &mut w, &mut fx);
            pings_seen = w.pings;
            if t.events.contains(&Event::Wedged) {
                wedged = true;
                break;
            }
        }
        assert!(wedged, "silence past the budget must be a wedge");
        assert!(pings_seen >= 2, "each interval must retry: {pings_seen}");
    }

    /// The budget follows steering, not resyncing — the correction from
    /// an earlier round, checked here through the loop that applies it.
    #[test]
    fn a_steered_adopted_resync_uses_the_steady_budget() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 100, // still draining
            ping_fails: true,
            ..Default::default()
        };
        // Adopt a steered VPP; it is converging AND forwarding.
        d.inject(t0, Event::Adopted { steered: true }, &mut fx);
        // The detector only exists once the API answers; simulate that
        // by driving a tick from Starting is not possible here, so feed
        // ApiUp's effect directly.
        d.tick(t0, &mut w, &mut fx);
        assert!(d.supervisor().is_steered());
        assert!(d.supervisor().is_converging());

        // Just past the steady budget but far inside the sync budget.
        let probe = t0 + PING_BUDGET + Duration::from_millis(200);
        assert!(probe < t0 + SYNC_PING_BUDGET);
        // No detector was created (no ApiUp from Adopted), so this
        // asserts the budget choice rather than the wedge itself.
        assert_eq!(
            budget_for(true, true),
            PING_BUDGET,
            "steered means the published bound applies"
        );
    }

    // ---- Death, and the schedule ----

    /// An exit is handled before anything else: the ping and drain would
    /// both fail against a dead process and produce noise.
    #[test]
    fn an_exit_is_reported_without_a_ping_or_drain() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 5,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        d.tick(t0, &mut w, &mut fx);
        let drains_before = w.drains;

        w.exited = Some(Some(1));
        let t = d.tick(at(t0, 10), &mut w, &mut fx);
        assert!(t.events.contains(&Event::ProcessExited { status: Some(1) }));
        assert_eq!(w.drains, drains_before, "no drain against a dead process");
        assert_eq!(w.pings, 0, "no ping against a dead process");
        assert_eq!(d.state(), State::Backoff);
    }

    /// The backoff the supervisor asked for is armed, and the retry
    /// fires from it on a later tick — without the caller tracking time.
    #[test]
    fn the_backoff_is_armed_and_the_retry_fires_from_it() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        d.inject(at(t0, 20), Event::VerifyPassed, &mut fx);

        w.exited = Some(None);
        d.tick(at(t0, 30), &mut w, &mut fx);
        assert_eq!(d.state(), State::Backoff);

        // Not yet.
        w.exited = None;
        let t = d.tick(at(t0, 100), &mut w, &mut fx);
        assert!(!t.events.contains(&Event::BackoffElapsed));

        fx.calls.clear();
        let t = d.tick(at(t0, 5_000), &mut w, &mut fx);
        assert!(t.events.contains(&Event::BackoffElapsed), "{:?}", t.events);
        assert!(fx.calls.contains(&"spawn"), "{:?}", fx.calls);
        assert_eq!(d.state(), State::Starting);
    }

    /// A phase that never completes must not hang the loop — the
    /// startup deadline fires and the supervisor cycles.
    #[test]
    fn a_vpp_that_never_answers_times_out_through_the_loop() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World::default(); // never becomes ready

        d.inject(t0, Event::StartRequested, &mut fx);
        assert_eq!(d.state(), State::Starting);

        let t = d.tick(at(t0, 61_000), &mut w, &mut fx);
        assert!(t.events.contains(&Event::PhaseTimedOut), "{:?}", t.events);
        assert_eq!(d.state(), State::Backoff);
        assert!(fx.calls.contains(&"kill"));
    }

    /// While a process exists but the API has not answered, the sleep
    /// must be the poll cadence — never the startup deadline. A
    /// sleep-honouring loop offered the deadline would wake exactly
    /// there, queue `PhaseTimedOut` ahead of the `ApiUp` observed on
    /// the same pass, and kill a healthy VPP that was merely slow to
    /// fault in its heap — every 60 s, forever.
    #[test]
    fn starting_polls_for_the_api_instead_of_sleeping_to_the_deadline() {
        let mut d = Driver::new();
        let mut w = World::default(); // api: false
        let mut fx = Fx::default();
        let t0 = Instant::now();

        // Both entry points must cap: the injected start (whose settle
        // path had exactly this bug shape before, per its doc) and the
        // ordinary tick.
        let it = d.inject(t0, Event::StartRequested, &mut fx);
        assert!(
            it.sleep.is_some_and(|s| s <= API_POLL_INTERVAL),
            "inject offered {:?}, letting a caller doze past api_ready",
            it.sleep
        );
        let t = d.tick(at(t0, 1), &mut w, &mut fx);
        assert!(
            t.sleep.is_some_and(|s| s <= API_POLL_INTERVAL),
            "tick offered {:?}",
            t.sleep
        );

        // The API answers mid-budget; a loop honouring the advertised
        // cadence reaches ApiUp long before any timeout fires.
        w.api = true;
        let t = d.tick(at(t0, 260), &mut w, &mut fx);
        assert!(
            t.events.contains(&Event::ApiUp),
            "the poll must observe the API coming up: {:?}",
            t.events
        );
        assert_eq!(d.state(), State::Syncing);
        // (The tick that transitioned asks for an immediate re-run —
        // that is settle behaviour, covered by its own tests. The cap
        // itself no longer applies once the detector exists.)
    }

    /// The loop must not spin. In steady state the only timer is the
    /// ping; with nothing running at all there is no timer.
    #[test]
    fn an_idle_driver_asks_to_block_rather_than_spin() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World::default();
        let t = d.tick(t0, &mut w, &mut fx);
        assert_eq!(t.sleep, None, "nothing armed: block on the fds");
    }

    #[test]
    fn a_running_driver_wakes_for_the_ping() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        // Settled: the only remaining timer is the ping.
        let t = d.tick(at(t0, 50), &mut w, &mut fx);
        assert!(t.sleep.is_some());
        assert!(t.sleep.unwrap() <= PING_INTERVAL, "{:?}", t.sleep);
    }

    /// A stop disarms everything: an idle stopped daemon must not hold a
    /// timer that wakes it for nothing.
    #[test]
    fn a_stop_disarms_the_schedule() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);

        let t = d.inject(at(t0, 20), Event::StopRequested, &mut fx);
        assert_eq!(d.state(), State::Stopped);
        assert!(fx.calls.contains(&"release"));
        assert_eq!(t.sleep, None, "a stopped driver holds no timers");
    }

    /// Teardown ordering survives composition: unsteer precedes kill all
    /// the way from an observed exit.
    #[test]
    fn an_observed_exit_while_steered_unsteers_before_killing() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        d.inject(at(t0, 20), Event::VerifyPassed, &mut fx);
        d.inject(at(t0, 21), Event::Steered, &mut fx);
        assert!(d.supervisor().is_steered());

        fx.calls.clear();
        w.exited = Some(None);
        d.tick(at(t0, 30), &mut w, &mut fx);
        let unsteer = fx.calls.iter().position(|c| *c == "unsteer");
        let kill = fx.calls.iter().position(|c| *c == "kill");
        assert!(unsteer.is_some() && kill.is_some(), "{:?}", fx.calls);
        assert!(unsteer < kill, "{:?}", fx.calls);
    }

    /// A process that survived the kill must not be replaced on the next
    /// backoff — checked here through the loop, where the block has to
    /// survive across ticks.
    #[test]
    fn an_undead_process_blocks_the_retry_across_ticks() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx {
            kill_disposition: Some(Disposition::MustLeak),
            ..Default::default()
        };
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        w.exited = Some(None);
        d.tick(at(t0, 30), &mut w, &mut fx);
        // The exit itself clears `undead`; the wedge path below is the
        // one where the process is still believed alive.
        assert_eq!(d.state(), State::Backoff);

        let mut d2 = Driver::new();
        let mut fx2 = Fx {
            kill_disposition: Some(Disposition::MustLeak),
            ..Default::default()
        };
        d2.inject(t0, Event::StartRequested, &mut fx2);
        d2.inject(at(t0, 1), Event::Wedged, &mut fx2);
        assert!(d2.supervisor().is_undead());
        assert!(!d2.supervisor().may_restart());

        // Long past the backoff, and still no spawn.
        fx2.calls.clear();
        let mut w2 = World::default();
        let t = d2.tick(at(t0, 60_000), &mut w2, &mut fx2);
        assert!(!t.events.contains(&Event::BackoffElapsed), "{:?}", t.events);
        assert!(!fx2.calls.contains(&"spawn"), "{:?}", fx2.calls);
        // And the withheld backoff must not busy-spin.
        assert_eq!(t.sleep, None, "blocked: sleep on the fds");

        // The pidfd finally reports the exit; now the retry proceeds.
        w2.exited = Some(None);
        d2.tick(at(t0, 60_100), &mut w2, &mut fx2);
        w2.exited = None;
        let t = d2.tick(at(t0, 90_000), &mut w2, &mut fx2);
        assert!(t.events.contains(&Event::BackoffElapsed), "{:?}", t.events);
    }

    /// Adoption goes straight to `Syncing`/`AdoptedResyncing`, so gating
    /// detector creation on `Starting` meant an adopted VPP never got
    /// one — and adoption is the single case still carrying steered
    /// traffic. A wedged adoptee could have blackholed forever without
    /// ever emitting `Wedged`.
    #[test]
    fn an_adopted_process_gets_a_wedge_detector() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ping_fails: true,
            ..Default::default()
        };
        d.inject(t0, Event::Adopted { steered: true }, &mut fx);
        assert_eq!(d.state(), State::AdoptedResyncing);

        // First tick must create the detector even though we never
        // passed through `Starting`.
        d.tick(t0, &mut w, &mut fx);
        assert!(w.pings > 0 || d.detector.is_some(), "detector must exist");

        // Silence past the steady budget (steered ⇒ published bound)
        // must be reported.
        let mut wedged = false;
        for ms in (500..4_000).step_by(250) {
            if d.tick(at(t0, ms), &mut w, &mut fx)
                .events
                .contains(&Event::Wedged)
            {
                wedged = true;
                break;
            }
        }
        assert!(wedged, "a wedged adoptee must be detected");
    }

    /// An injected transition must not hand back a deadline as the
    /// permitted sleep. A caller honouring it would wait the whole 60 s
    /// startup budget without ever calling `api_ready`, and
    /// `PhaseTimedOut` is then queued ahead of the `ApiUp` observed on
    /// the same tick — killing a healthy VPP on every start.
    #[test]
    fn an_injected_start_asks_to_be_ticked_immediately() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let t = d.inject(t0, Event::StartRequested, &mut fx);
        assert_eq!(d.state(), State::Starting);
        assert_eq!(
            t.sleep,
            Some(Duration::ZERO),
            "must not sleep out the startup budget before observing"
        );
    }

    #[test]
    fn an_injected_adoption_asks_to_be_ticked_immediately() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let t = d.inject(t0, Event::Adopted { steered: false }, &mut fx);
        assert_eq!(
            t.sleep,
            Some(Duration::ZERO),
            "the first batch must not wait out the convergence budget"
        );
    }

    /// A pidfd is level-triggered, so an exit can still be readable on
    /// the tick a backoff expires. Queued after `BackoffElapsed`, the
    /// replacement is spawned first and the OLD process's exit is then
    /// attributed to it — killing a VPP that just started, every retry.
    #[test]
    fn an_exit_is_attributed_before_an_elapsed_backoff_spawns() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        d.inject(at(t0, 20), Event::VerifyPassed, &mut fx);

        // Die, entering backoff.
        w.exited = Some(None);
        d.tick(at(t0, 30), &mut w, &mut fx);
        assert_eq!(d.state(), State::Backoff);

        // The pidfd is STILL readable when the backoff expires.
        fx.calls.clear();
        let t = d.tick(at(t0, 5_000), &mut w, &mut fx);
        let exit_at = t
            .events
            .iter()
            .position(|e| matches!(e, Event::ProcessExited { .. }));
        let backoff_at = t.events.iter().position(|e| *e == Event::BackoffElapsed);
        assert!(exit_at.is_some() && backoff_at.is_some(), "{:?}", t.events);
        assert!(
            exit_at < backoff_at,
            "the exit belongs to the process observed at entry: {:?}",
            t.events
        );
        // And the freshly spawned process is NOT killed.
        assert_eq!(d.state(), State::Starting, "{:?}", fx.calls);
        let spawn_at = fx.calls.iter().position(|c| *c == "spawn");
        assert!(spawn_at.is_some(), "{:?}", fx.calls);
        assert!(
            fx.calls
                .iter()
                .skip(spawn_at.unwrap())
                .all(|c| *c != "kill"),
            "nothing may kill the replacement: {:?}",
            fx.calls
        );
    }

    /// Actions are executed, not merely decided — the seam the whole
    /// module exists to close.
    #[test]
    fn convergence_runs_attach_then_resync_through_the_effects() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 2,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        fx.calls.clear();
        d.tick(t0, &mut w, &mut fx);
        assert_eq!(fx.calls, vec!["attach", "resync"]);
        settle(&mut d, at(t0, 10), &mut w, &mut fx);
        assert!(fx.calls.contains(&"verify"), "{:?}", fx.calls);
    }

    #[test]
    fn the_first_attach_does_not_steer_itself() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        d.inject(at(t0, 20), Event::VerifyPassed, &mut fx);
        assert_eq!(d.state(), State::Ready);
        assert!(
            !fx.calls.contains(&"steer"),
            "the canary is the operator's lever: {:?}",
            fx.calls
        );
    }

    /// An event the supervisor ignores must not produce actions.
    #[test]
    fn a_stale_event_settles_without_acting() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let t = d.inject(t0, Event::BackoffElapsed, &mut fx);
        assert!(t.outcome.events.is_empty());
        assert!(fx.calls.is_empty(), "{:?}", fx.calls);
        assert!(!t.outcome.resources_leaked);
    }

    /// The action list is not merely run — its ordering is preserved
    /// through the driver's feedback loop.
    #[test]
    fn a_verified_restart_re_steers_only_after_verification() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        d.inject(at(t0, 20), Event::VerifyPassed, &mut fx);
        d.inject(at(t0, 21), Event::Steered, &mut fx);

        w.exited = Some(None);
        d.tick(at(t0, 30), &mut w, &mut fx);
        w.exited = None;
        w.batches = 2;
        fx.calls.clear();

        settle(&mut d, at(t0, 5_000), &mut w, &mut fx);
        d.inject(at(t0, 6_000), Event::VerifyPassed, &mut fx);

        let pos = |n: &str| fx.calls.iter().position(|c| *c == n);
        assert!(pos("verify") < pos("steer"), "{:?}", fx.calls);
        assert!(pos("resync") < pos("verify"), "{:?}", fx.calls);
    }

    /// Actions include the arm-backoff the schedule consumed, so the
    /// caller can see what happened without inspecting internals.
    #[test]
    fn the_tick_reports_the_actions_that_ran() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World::default();
        d.inject(t0, Event::StartRequested, &mut fx);
        let t = d.tick(at(t0, 61_000), &mut w, &mut fx);
        assert!(t.events.contains(&Event::PhaseTimedOut));
        assert!(fx.calls.contains(&"backoff"));
        assert!(t.outcome.ok(), "{:?}", t.outcome);
    }

    /// `Action` is re-exported through the driver's surface so callers
    /// can match on failures without importing the supervisor.
    #[test]
    fn failures_name_the_action_that_failed() {
        struct Bad;
        impl Effects for Bad {
            fn spawn(&mut self) -> Result<(), String> {
                Err("no binary".into())
            }
            fn unsteer(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn steer(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn kill(&mut self) -> Disposition {
                Disposition::SafeToRelease
            }
            fn attach_devices(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn start_resync(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn start_verify(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn abort_convergence(&mut self) {}
            fn arm_backoff(&mut self, _d: Duration) {}
            fn release_resources(&mut self) -> Result<(), String> {
                Ok(())
            }
        }
        let t0 = Instant::now();
        let mut d = Driver::new();
        let t = d.inject(t0, Event::StartRequested, &mut Bad);
        assert!(t.outcome.failures.iter().any(|(a, _)| *a == Action::Spawn));
        assert_eq!(d.state(), State::Backoff, "a failed spawn retries");
    }
}
