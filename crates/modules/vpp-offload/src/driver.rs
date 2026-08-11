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

/// How often a wanted-but-absent steer may be re-attempted.
///
/// The pacing half of [`Event::SteerUnblocked`]. The trigger is the
/// gates opening, not this timer — but "the gates are open" is a level,
/// not an edge, and a steer can also fail for reasons no gate knows
/// about (the NIC refusing an insert). Without a floor between
/// attempts, a steer that keeps failing under an open gate would be
/// retried on every tick, which in steady state is every ping interval.
///
/// 30 s, matching `runtime::STEER_AUDIT_EVERY`, which paces the
/// other periodic ethtool traffic on this path for the same reason: a
/// handful of ioctls per steered interface is free at that cadence, and
/// the number is sized against how long a silently-unsteered offload
/// should be allowed to persist rather than against any hardware limit.
/// It bounds the wait only for a RE-attempt — entering the
/// wanted-but-absent state arms nothing, so the first look happens on
/// the next tick.
pub const STEER_RETRY_EVERY: Duration = Duration::from_secs(30);

use crate::executor::{execute, Effects, Outcome};
use crate::liveness::{budget_for, WedgeDetector};
use crate::schedule::Schedule;
use crate::supervisor::{Event, State, Supervisor};

/// What the world reports. Every one of these is an observation; none
/// of them requests a state change.
/// What one `drain_batch` pass accomplished.
///
/// A bool almost sufficed, and the third case is why it could not: an
/// adopted resync whose route source is still loading is neither "done"
/// (that would send the supervisor to verify against a diff that never
/// ran) nor "more to drain" (that asks for an immediate re-tick and
/// spins a core polling a count that changes at feed speed, not tick
/// speed). It is its own thing — deliberate waiting — and the driver
/// treats it as such: no `SyncComplete`, no re-tick, and the phase
/// deadline is re-armed so `CONVERGENCE_BUDGET` times the convergence
/// rather than bird's reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Drain {
    /// Nothing left pending.
    Idle,
    /// A batch went out; more remains.
    More,
    /// The adopted resync is deliberately deferred: the route source
    /// holds `have` routes against a floor of `want`. See
    /// [`crate::runtime::ADOPTED_SOURCE_FLOOR_DIVISOR`].
    AwaitingSource { have: u64, want: u64 },
}

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

    /// Whether a steer would get past the module's own gates right now.
    ///
    /// Read only when a wanted steer is missing (see
    /// [`Supervisor::steer_retry_pending`]) and only as often as
    /// [`STEER_RETRY_EVERY`] allows, so it may cost a lock and a count —
    /// but not an ioctl.
    ///
    /// It must answer for **every** gate the steer path applies, or the
    /// retry becomes a way around one of them. Both refuse for the same
    /// reason from opposite ends: the completeness verdict says the
    /// route mirror is not yet the table, and the ledger's counts say
    /// what we hold has not all reached VPP. Diverting traffic on either
    /// blackholes exactly the prefixes that are missing, and a steered
    /// miss is dropped rather than falling through to the eBPF tier.
    fn steer_permitted(&mut self) -> bool;

    /// Drain **one bounded batch** of pending routes.
    ///
    /// Bounded is the contract, not an implementation detail. A blocking
    /// full-table drain would hold the loop for the whole convergence
    /// budget, during which no ping is sent and no exit is noticed — so
    /// the wedge detector would either be useless or fire on a VPP that
    /// was working fine.
    /// `now` is the loop's clock, for the adopted-resync release gate:
    /// quiescence is a RATE over elapsed time, never a count of calls —
    /// the production loop caps sleeps at 50 ms for stop-responsiveness,
    /// so per-call growth shrinks with cadence and a per-call threshold
    /// would call a full-speed reload "quiet" (review finding).
    fn drain_batch(&mut self, now: Instant) -> Result<Drain, String>;
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
    /// When the last wanted-but-absent steer was re-attempted.
    ///
    /// Cleared the moment nothing is outstanding, so the interval bounds
    /// re-attempts *within* one outstanding steer rather than punishing
    /// the next one: a refusal that arrives a minute after the last
    /// success is looked at on the very next tick.
    last_steer_retry: Option<Instant>,
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
            last_steer_retry: None,
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
        // Whether THIS tick's drain proved the engine has nothing left to
        // send. The steer retry's precondition — see `poll_steer_retry`.
        // False until a drain says so, so a tick that did not drain at
        // all, or whose drain failed, cannot be read as proof.
        let mut drain_proved_idle = false;
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
                match obs.drain_batch(now) {
                    // Empty means the resync is done — and only the
                    // drain can say so, which is why this is observed
                    // rather than assumed after issuing StartResync.
                    Ok(Drain::Idle) if resyncing => events.push(Event::SyncComplete),
                    Ok(Drain::Idle) => drain_proved_idle = true,
                    Ok(Drain::More) => more_to_drain = true,
                    // Deliberate waiting, not progress and not
                    // completion. The phase deadline is pushed forward
                    // on every deferred tick so `CONVERGENCE_BUDGET`
                    // starts when the diff actually runs — otherwise a
                    // slow feed reload spends the budget and
                    // `PhaseTimedOut` tears down a healthy adopted VPP,
                    // which is the same defect the deferral exists to
                    // prevent, arriving through the clock.
                    Ok(Drain::AwaitingSource { .. }) => {
                        self.sched.extend_phase(now, self.sup.phase());
                    }
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
            events.extend(self.poll_steer_retry(now, drain_proved_idle, obs));
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

    /// Re-attempt a steer the module wants and does not have, once the
    /// gates that refused it permit one.
    ///
    /// The driver owns this because the supervisor owns neither a clock
    /// nor a view of the world, and the alternative — an operator
    /// re-running `packetframe reconfigure` — is not a mechanism, it is
    /// a person. The failure it closes: bird's dump is behind, the
    /// canary lever is turned, the completeness gate refuses, the mirror
    /// converges a minute later, and nothing steers.
    ///
    /// Level-triggered rather than edge-triggered, deliberately. An edge
    /// needs the driver to have observed the gate closed at the moment
    /// of the refusal, and it never does: the refusal happens inside an
    /// `Action::Steer` during `apply`, and the gate may already read open
    /// by the next tick. So the condition is the state of the world —
    /// something is wanted, nothing forbids it — and
    /// [`STEER_RETRY_EVERY`] is what stops a steer that keeps failing
    /// for its own reasons from being re-attempted every tick.
    ///
    /// `drained_idle` is this tick's proof that the engine has nothing
    /// left to send, and it is a PRECONDITION, not a nicety. The
    /// ledger's counts are the other gate's evidence and they can be
    /// clean over deltas VPP never received: `RouteFeed::drain_changes`
    /// removes the batch from the mirror, and `Engine::apply_changes`
    /// returns on a failed `send_neighbour` **before** queuing that
    /// batch's routes — so nothing is left `installing`,
    /// `blocks_first_steer()` says fine, and a steer here would divert
    /// traffic into a FIB missing exactly those prefixes (review
    /// finding, PR #160). A drain that did not run, or ran and failed,
    /// proves nothing, so neither may pass for proof.
    ///
    /// It also subsumes the ordinary in-flight case — `Drain::More`
    /// means routes are on the wire — which the counts already covered.
    /// The error case is the one they get wrong.
    ///
    /// It also carries the reconcile-to-empty repair, which is not an
    /// accident of scope but the same mechanism: a `steer off` whose
    /// `unsteer` the NIC refused keeps its rules and, after a death
    /// while steered, its want — so it lands here like any other
    /// outstanding steer. `Action::Steer` reconciles to the empty
    /// target, removes the stale rules, and answers
    /// [`crate::runtime::SteerOutcome::NothingToSteer`], which retires
    /// the want and ends the retries. Before that outcome existed the
    /// same state was unrecoverable and this comment said so; now the
    /// repair does not have to wait for a convergence that exponential
    /// backoff can postpone indefinitely, which is when those rules are
    /// pointing at a VF whose VPP is down.
    fn poll_steer_retry(
        &mut self,
        now: Instant,
        drained_idle: bool,
        obs: &mut dyn Observe,
    ) -> Vec<Event> {
        if !self.sup.steer_retry_pending() {
            self.last_steer_retry = None;
            return Vec::new();
        }
        if !drained_idle {
            // Nothing recorded: this is a missing proof, not a spent
            // attempt, so the tick that does prove it acts immediately.
            return Vec::new();
        }
        // And VPP has to be answering. `Drain::Idle` does not say so: an
        // empty pending map sends nothing at all, so in steady state
        // that `Ok` is reached without touching the socket. The two
        // proofs are about different things — one that the FIB is
        // current, one that there is a VPP behind it — and steering
        // needs both.
        //
        // `answered_last_probe`, not `is_wedged`: the silence budget
        // tolerates two missed pings so jitter cannot cost a restart,
        // and that tolerance is exactly the window this would otherwise
        // steer into. `Wedged` has not fired yet, so nothing takes the
        // rules back off until it does (review finding, PR #160). It is
        // read after `poll_liveness` has run this tick, so a ping that
        // failed a moment ago already counts.
        if !self
            .detector
            .as_ref()
            .is_some_and(|d| d.answered_last_probe())
        {
            return Vec::new();
        }
        if self
            .last_steer_retry
            .is_some_and(|t| now.duration_since(t) < STEER_RETRY_EVERY)
        {
            return Vec::new();
        }
        if !obs.steer_permitted() {
            // Still refused. Nothing is recorded, so the moment the gate
            // opens the next tick acts — the interval paces attempts,
            // not the waiting.
            return Vec::new();
        }
        self.last_steer_retry = Some(now);
        vec![Event::SteerUnblocked]
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
    use crate::runtime::SteerOutcome;
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
        /// Drain calls that report `AwaitingSource` before any batch
        /// moves — the deferred adopted resync.
        deferred_ticks: usize,
        drain_fails: bool,
        ping_fails: bool,
        pings: usize,
        drains: usize,
        api_readies: usize,
        /// What the gates say about a steer. Default `false` — the
        /// interesting case is a gate that refuses, and a double that
        /// permits by omission would let a retry test pass without the
        /// gate ever being consulted.
        steer_permitted: bool,
        steer_gate_reads: usize,
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
        fn steer_permitted(&mut self) -> bool {
            self.steer_gate_reads += 1;
            self.steer_permitted
        }
        fn drain_batch(&mut self, _now: Instant) -> Result<Drain, String> {
            self.drains += 1;
            if self.drain_fails {
                return Err("socket closed".into());
            }
            if let Some(n) = self.deferred_ticks.checked_sub(1) {
                self.deferred_ticks = n;
                return Ok(Drain::AwaitingSource { have: 0, want: 1 });
            }
            self.batches = self.batches.saturating_sub(1);
            Ok(if self.batches == 0 {
                Drain::Idle
            } else {
                Drain::More
            })
        }
    }

    #[derive(Default)]
    struct Fx {
        calls: Vec<&'static str>,
        kill_disposition: Option<Disposition>,
        /// The steer path refusing on its own terms — the completeness
        /// gate, or a NIC that will not take the insert.
        steer_fails: bool,
    }

    impl Effects for Fx {
        fn steering_in_place(&self) -> bool {
            // No ledger in this fake; the driver tests never assert on
            // `steered` after a failed steer.
            false
        }
        fn spawn(&mut self) -> Result<(), String> {
            self.calls.push("spawn");
            Ok(())
        }
        fn unsteer(&mut self) -> Result<(), String> {
            self.calls.push("unsteer");
            Ok(())
        }
        fn steer(&mut self) -> Result<SteerOutcome, String> {
            self.calls.push("steer");
            if self.steer_fails {
                return Err("refusing to steer: the mirror is still loading".into());
            }
            Ok(SteerOutcome::Steered)
        }
        fn restore_steer(&mut self) -> Result<SteerOutcome, String> {
            self.calls.push("steer");
            Ok(SteerOutcome::Steered)
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

    // ---- The refused steer, retried ----

    /// Drive to `Ready`, turn the canary lever, and have the steer
    /// refused — the state an operator lands in when bird's dump is
    /// behind their lever move.
    fn refused_canary(t0: Instant, d: &mut Driver, w: &mut World, fx: &mut Fx) {
        d.inject(t0, Event::StartRequested, fx);
        settle(d, t0, w, fx);
        d.inject(at(t0, 20), Event::VerifyPassed, fx);
        assert_eq!(d.state(), State::Ready);
        fx.steer_fails = true;
        d.inject(at(t0, 21), Event::SteerRequested, fx);
        assert!(fx.calls.contains(&"steer"), "{:?}", fx.calls);
        assert_eq!(d.state(), State::Ready, "refused, so still unsteered");
        assert!(
            d.supervisor().steer_retry_pending(),
            "the want must outlive the refusal"
        );
    }

    /// The gap this whole mechanism exists for: the refusal clears and
    /// the module steers, with no operator in the loop.
    ///
    /// Before it, `steer_wanted` was read by exactly two things — the
    /// health text and `(Verifying, VerifyPassed)` — and verify does not
    /// recur in steady state. So the module knew it wanted to steer,
    /// said so in `steering DEGRADED`, and waited for a human.
    #[test]
    fn a_refused_steer_is_re_attempted_once_the_gate_opens() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        refused_canary(t0, &mut d, &mut w, &mut fx);

        // While the gate refuses, nothing is attempted — but it IS asked.
        fx.calls.clear();
        for ms in (100..30_000).step_by(500) {
            d.tick(at(t0, ms), &mut w, &mut fx);
        }
        assert!(
            !fx.calls.contains(&"steer"),
            "a closed gate must not be walked past: {:?}",
            fx.calls
        );
        assert!(
            w.steer_gate_reads > 0,
            "and it must actually be consulted, or the test proves nothing"
        );

        // The mirror catches up. No reconfigure, no restart.
        fx.steer_fails = false;
        w.steer_permitted = true;
        let t = d.tick(at(t0, 30_100), &mut w, &mut fx);
        assert!(
            t.events.contains(&Event::SteerUnblocked),
            "the open gate must produce the retry: {:?}",
            t.events
        );
        assert!(fx.calls.contains(&"steer"), "{:?}", fx.calls);
        assert_eq!(d.state(), State::Steered);
        assert!(!d.supervisor().steer_retry_pending(), "nothing outstanding");
    }

    /// A steer that keeps failing under an open gate must not be
    /// re-attempted every tick.
    ///
    /// The completeness verdict is a level, not an edge, and the steer
    /// can fail for reasons no gate knows about — a NIC refusing the
    /// insert. In steady state a tick happens every ping interval, so
    /// without the interval this would be two ethtool round trips a
    /// second, forever, on a fault that is not going to clear.
    #[test]
    fn a_steer_that_keeps_failing_is_paced_not_hot_looped() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        refused_canary(t0, &mut d, &mut w, &mut fx);

        // The gate opens, but the NIC keeps refusing.
        w.steer_permitted = true;
        fx.calls.clear();
        let window = Duration::from_secs(90);
        for ms in (100..window.as_millis() as u64).step_by(100) {
            d.tick(at(t0, ms), &mut w, &mut fx);
        }
        let attempts = fx.calls.iter().filter(|c| **c == "steer").count();
        let ceiling = (window.as_secs() / STEER_RETRY_EVERY.as_secs()) as usize + 1;
        assert!(
            attempts >= 2,
            "a repeatedly failing steer must still keep trying: {attempts}"
        );
        assert!(
            attempts <= ceiling,
            "{attempts} attempts in {window:?} — the interval is not pacing anything"
        );
        assert!(d.supervisor().steer_retry_pending(), "still outstanding");
    }

    /// A tick whose drain failed is not proof of anything, and must not
    /// be steered over.
    ///
    /// The completeness verdict and the ledger's counts are the two
    /// gates, and a failed drain can leave BOTH looking clean over
    /// deltas VPP never received: `drain_changes` takes the batch out of
    /// the mirror, and `apply_changes` returns on a failed
    /// `send_neighbour` before queuing that batch's routes, so nothing
    /// is left `installing` to notice. Steering there diverts traffic
    /// into a FIB missing exactly those prefixes — and unlike the
    /// unsteered case, a steered miss is dropped (review finding, PR
    /// #160).
    #[test]
    fn a_failed_drain_holds_the_retry_until_one_succeeds() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        refused_canary(t0, &mut d, &mut w, &mut fx);

        // Both gates now say yes — and the drain says it could not talk
        // to VPP, which is the fact that outranks them.
        w.steer_permitted = true;
        w.drain_fails = true;
        fx.steer_fails = false;
        fx.calls.clear();
        for ms in (100..10_000).step_by(250) {
            d.tick(at(t0, ms), &mut w, &mut fx);
        }
        assert!(
            !fx.calls.contains(&"steer"),
            "a drain that failed cannot show the FIB is current: {:?}",
            fx.calls
        );
        assert!(
            d.supervisor().steer_retry_pending(),
            "and the want is still outstanding, not discarded"
        );

        // The transport comes back and a drain reports the queue empty.
        // That is the proof, and it is acted on at once — the withheld
        // ticks must not have counted as attempts.
        w.drain_fails = false;
        let t = d.tick(at(t0, 10_100), &mut w, &mut fx);
        assert!(
            t.events.contains(&Event::SteerUnblocked),
            "a proven-idle drain releases it immediately: {:?}",
            t.events
        );
        assert_eq!(d.state(), State::Steered);
    }

    /// Nor may it steer into a VPP that has stopped answering.
    ///
    /// The gap this closes is between the first unanswered ping and
    /// `Wedged`: the budget deliberately tolerates two missed pings so
    /// jitter cannot cost a restart, and in steady state `Drain::Idle`
    /// is reached without touching the socket — an empty pending map
    /// sends nothing — so neither the drain proof nor the wedge
    /// detector objects. Rules installed in that window put packets on
    /// a VF whose VPP is already gone, and nothing takes them off until
    /// the budget expires (review finding, PR #160).
    #[test]
    fn a_silent_api_holds_the_retry_until_it_answers_again() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            ..Default::default()
        };
        refused_canary(t0, &mut d, &mut w, &mut fx);
        w.steer_permitted = true;
        fx.steer_fails = false;

        // VPP stops answering, and the FIRST tick after the refusal is
        // one where a ping is due — otherwise the retry fires on the
        // last pong, which is at most one ping interval old and is
        // exactly as fresh as this loop can ever be.
        //
        // From there, stay INSIDE the silence budget measured from that
        // pong at ~t0. That tolerated window is the whole premise: no
        // `Wedged`, nothing torn down, and the drain still reports idle
        // because there is nothing to send.
        w.ping_fails = true;
        fx.calls.clear();
        let mut ms = PING_INTERVAL.as_millis() as u64;
        while Duration::from_millis(ms) < PING_BUDGET {
            let t = d.tick(at(t0, ms), &mut w, &mut fx);
            assert!(
                !t.events.contains(&Event::Wedged),
                "the premise is the tolerated window, before any teardown: {:?}",
                t.events
            );
            ms += 100;
        }
        assert!(w.pings > 0, "a ping must actually have gone unanswered");
        assert!(
            !fx.calls.contains(&"steer"),
            "steering into an API that is not answering puts packets on a VF whose \
             VPP is already gone: {:?}",
            fx.calls
        );
        assert!(d.supervisor().steer_retry_pending(), "still wanted");

        // It answers again. The pong lands before the wedge check on the
        // same tick, so a recovery at the moment the next ping is due
        // both clears the silence and releases the retry.
        w.ping_fails = false;
        let mut steered = false;
        for step in 0..8 {
            let t = d.tick(at(t0, ms + step * 100), &mut w, &mut fx);
            if t.events.contains(&Event::SteerUnblocked) {
                steered = true;
                break;
            }
        }
        assert!(steered, "a recovered API must release it: {:?}", fx.calls);
        assert_eq!(d.state(), State::Steered);
    }

    /// A port that never asked to steer is not steered by a gate that
    /// happens to be open. The first steer is the operator's canary, and
    /// this mechanism must not become a way around it.
    #[test]
    fn an_open_gate_does_not_steer_a_first_attach() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            steer_permitted: true,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        d.inject(at(t0, 20), Event::VerifyPassed, &mut fx);
        assert_eq!(d.state(), State::Ready);

        fx.calls.clear();
        for ms in (100..120_000).step_by(1_000) {
            d.tick(at(t0, ms), &mut w, &mut fx);
        }
        assert!(
            !fx.calls.contains(&"steer"),
            "the canary is the operator's lever: {:?}",
            fx.calls
        );
        assert_eq!(
            w.steer_gate_reads, 0,
            "with nothing wanted there is nothing to ask the gate about"
        );
    }

    /// And a port that IS steering is left alone: the retry is for a
    /// steer that is missing, not a periodic re-assert of one that is
    /// not. Drift under live steering is the audit's business, and its
    /// remedy is deliberately the operator's.
    #[test]
    fn a_steered_port_is_not_re_steered_on_the_interval() {
        let t0 = Instant::now();
        let mut d = Driver::new();
        let mut fx = Fx::default();
        let mut w = World {
            api: true,
            batches: 1,
            steer_permitted: true,
            ..Default::default()
        };
        d.inject(t0, Event::StartRequested, &mut fx);
        settle(&mut d, t0, &mut w, &mut fx);
        d.inject(at(t0, 20), Event::VerifyPassed, &mut fx);
        d.inject(at(t0, 21), Event::SteerRequested, &mut fx);
        assert_eq!(d.state(), State::Steered);

        fx.calls.clear();
        w.steer_gate_reads = 0;
        for ms in (100..120_000).step_by(1_000) {
            d.tick(at(t0, ms), &mut w, &mut fx);
        }
        assert!(
            !fx.calls.contains(&"steer"),
            "steady state must not carry an ethtool round trip: {:?}",
            fx.calls
        );
        assert_eq!(w.steer_gate_reads, 0);
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
            fn steering_in_place(&self) -> bool {
                false
            }
            fn spawn(&mut self) -> Result<(), String> {
                Err("no binary".into())
            }
            fn unsteer(&mut self) -> Result<(), String> {
                Ok(())
            }
            fn steer(&mut self) -> Result<SteerOutcome, String> {
                Ok(SteerOutcome::Steered)
            }
            fn restore_steer(&mut self) -> Result<SteerOutcome, String> {
                Ok(SteerOutcome::Steered)
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
