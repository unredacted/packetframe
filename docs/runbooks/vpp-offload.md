# vpp-offload operations runbook

The VPP-on-VF forwarding vector: MCAM-bifurcated allowlist traffic
forwarded by a packetframe-supervised VPP on SR-IOV VFs, with the eBPF
fast-path on the PFs as the permanent failover tier.

Companion to [`vpp-offload-spike.md`](vpp-offload-spike.md), which is the
**gate-0b bring-up procedure** — what was measured, how, and what
failed. This document is what you read when it is running, or when it is
running badly.

> ## Read this before the first bring-up
>
> **This module has run against real VPP on the shadow, repeatedly.**
> First bring-up 2026-08-05; first forwarded packet 2026-08-07; the five
> acceptance drills and a restart-over-steered-VPP cycle through
> 2026-08-09; `detach --all`, a cold bring-up and the steering-reconcile
> checks on 2026-08-11. What has NOT happened is any of it on the
> primary, or on more than one VF, or with real customer traffic — the
> shadow's only wired port carries the interconnect, so every packet
> that has ever traversed VPP here was one we generated.
>
> **The MCAM ioctl path has now met a NIC, and it took several rounds.**
> First contact on 2026-08-05 found one real defect — the `loc` space
> sized from `npc/mcam_info` rather than from the driver — plus two
> self-inflicted ones chasing it: a `GRXCLSRLALL` that asked for more
> rules than existed, and a mask "correction" that inverted a field
> which had been right all along. Every one of them failed loudly, as
> designed: nothing was installed, and the all-or-nothing unwind left the
> port with zero rules each time. Everything past installation is now
> proven too, on the shadow: steered frames counted on `octeon0/0`
> (2026-08-07), forwarded end to end through VPP's graph the same day,
> and PMTUD answered correctly through a steered path. What remains
> unproven is scale and reality — one VF, one wired port, and traffic we
> generated ourselves. Every rule
> insert is followed by an `ETHTOOL_GRXCLSRULE` readback and compared
> field by field, precisely so a wrong `ethtool_rx_flow_spec` offset
> fails loudly on first contact instead of installing a rule that
> matches the wrong traffic while both tiers report healthy. Expect that
> check to be the thing that fires first, and treat it as the module
> working, not failing. The same readback now runs every 30 s against
> the ledger, so a rule removed or altered out of band shows up as
> `steering DEGRADED` rather than as nothing at all.
>
> **Native XDP attach panics this vendor kernel.** Not a queue-leak
> question, not something to re-test on an idle port. The version gate
> that forces `auto` to generic is load-bearing safety.

## Contents

- [Architecture at a glance](#architecture-at-a-glance)
- [Healthy state](#healthy-state)
- [Everyday inspection commands](#everyday-inspection-commands)
- [The canary ladder](#the-canary-ladder)
- [Rollback](#rollback)
- [Triage by symptom](#triage-by-symptom)
- [Numbers: measured vs published-on-faith](#numbers-measured-vs-published-on-faith)
- [Install and upgrade on the router](#install-and-upgrade-on-the-router)
- [Constraints worth knowing before you debug](#constraints-worth-knowing-before-you-debug)

## Architecture at a glance

```text
 bird ──iBGP──→ BgpListener ──RouteEvent──→ FibProgrammer ──→ BPF maps   (failover tier)
                NeighborResolver                  │
                                                  └─ResolvedRouteSink──→ RouteFeed
                                                                           │
                                                        vpp-offload engine ─┴─binary API─→ VPP FIB
                                                                                           + static neighbours
 eth4 PF ── MCAM steer (allowlist × {src,dst}) ──→ VF ──→ VPP workers ──→ VF tx (src MAC = MAC-PF)
    └─ everything else ──→ kernel path, eBPF fast-path in front
```

Three things about that picture are load-bearing and easy to get
backwards:

**The second tier hangs off the *programmer*, not off the route
events.** A `RouteEvent::Add` carries one advertisement (`peer_id`,
`path_id`, `local_pref`); turning a prefix's advertisements into the set
that forwards is the programmer's local-pref tiering and ADD-PATH
aggregation. So vpp-offload consumes the programmer's resolved
best-paths. **Consequence: VPP's FIB mirrors what the fast-path
resolved, including its refusals** — which is worth more than mirroring
bird, because it means a failover cannot change forwarding.

**Membership and steering are different things.** A VPP FIB path
resolves through an adjacency on a VPP-owned interface, so VPP must own
a VF on *every possible egress port* before *any* ingress is steered — a
packet steered on eth5 whose best path exits eth4 dies otherwise.
Membership (a `port` line) is all-or-nothing across the forwarding
domain and is validated at config load. Steering (`steer on|off`) is
per-port and is the canary lever.

**VPP never ARPs.** Neighbours are static, from the resolver. ARP
suppression holds by construction rather than by knob: MCAM rules match
IPv4 fields, so ARP frames (0x0806) can never be steered — VPP
physically cannot receive an ARP request.

## Healthy state

Two ports of call. `packetframe status` for the structured view:

```bash
packetframe status
```

Under a healthy, fully steered offload the module-health section reads:

```text
module health (pid 12345, 3s old):
  vpp-offload: healthy
    vpp-process    healthy
    api-ping       healthy (last ok 0s ago)
    fib-synced     healthy — 1053360 routes installed, verified on 64 probes (last ok 41s ago)
    steering       healthy
    ports          healthy
```

Five rows, always. Two more — `route-feed` and `state-file` — appear
**only when they have failed**, deliberately, so the list carries no
permanent "fine" line for an operator to learn to ignore. Seeing either
of them at all is the signal.

Two of the five rows are worth understanding rather than glancing at.

**`module health: STALE`** means the daemon that wrote the snapshot is
gone. The report below it is history. The dataplane may well still be
forwarding — bpffs pins outlive the process by design (SPEC.md §8.5) —
but nothing is supervising VPP.

**`steering healthy — steer off (staging state); traffic is on the eBPF
tier`** is *not* a fault. All
members up, FIB synced and verified, nothing diverted: that is every
canary's waypoint and every rollback's landing zone. Distinguish it from
`steering DEGRADED — steering intended but not in place — traffic is on
the eBPF tier`, which means a steer was attempted and failed, or was torn
down by trouble and not yet restored. From `Ready` that line also names
the module's own retry — a refused steer is re-attempted at most every
30 s once nothing is refusing it — so it is worth reading twice before
reaching for `reconfigure`: if it is still there a minute later, the
refusal is still standing and the reason is what to chase.

And the overall verdict is deliberately **not** the maximum of the
subsystems. Health tracks whether packets are forwarded correctly, not
whether the offload is working — so a crash-looping *unsteered* VPP is
`Degraded` (the eBPF tier has the traffic) while a *steered* VPP that
cannot forward is `Unhealthy`.

For the Prometheus surface, the `packetframe_vpp_*` gauges land in the
same textfile as the fast-path counters:

```bash
grep packetframe_vpp_ /var/lib/node_exporter/textfile/packetframe.prom
```

Both `state` and `health` are emitted **one-hot** — one series per
possible value, exactly one of them `1` — so a dashboard reads the
current value without a mapping table:

| series | alarm when |
|---|---|
| `packetframe_vpp_health{state="healthy"}` | drops to `0` and stays there |
| `packetframe_vpp_state{state="steered"}` | drops to `0` unexpectedly |
| `packetframe_vpp_routes{state="unresolvable"}` | `> 0` at all — steady state is exactly zero |
| `packetframe_vpp_routes{state="withheld"}` | `> 0` — the table outgrew its heap |
| `packetframe_vpp_fib_verified` | `0` while steered |
| `packetframe_vpp_source_backlog` | sustained non-zero — deltas are not draining |
| `packetframe_vpp_drain_failing` | `1` — the steady-state delta apply is retrying |
| `packetframe_vpp_undead` | `1` — a killed VPP survived and blocks the restart |
| `packetframe_vpp_api_silent_seconds` | approaching the wedge budget (1.5 s steered) |

Every series also carries `module="vpp-offload"`.

`unresolvable` and `withheld` are reported separately on purpose. They
page differently: the first is a misconfigured nexthop-device mapping,
the second is the table having outgrown the box.

## Everyday inspection commands

```bash
# Is VPP the process we think it is?
cat /var/lib/packetframe/state/vpp-offload.json | jq '{vpp_pid, vpp_start_ticks, steer_rules}'
```

```bash
# What MCAM rules does the NIC actually hold? (ground truth, not our ledger)
ethtool -n eth5
```

`vppctl` speaks the **CLI** socket, which the renderer places at
`<api-socket>.cli`. Pointing it at the binary API socket connects and
then hangs forever waiting for a protocol the other end does not speak.

```bash
# What does VPP think its FIB looks like? Legitimate non-bulk vppctl.
vppctl -s /run/packetframe/vpp/api.sock.cli show ip fib summary
```

```bash
# The interfaces VPP created, and their link state.
vppctl -s /run/packetframe/vpp/api.sock.cli show interface
```

```bash
# Worker placement — one hot core per worker, permanently. See the heat note.
vppctl -s /run/packetframe/vpp/api.sock.cli show threads
```

## The canary ladder

Traffic moves only when you say so. The module never steers on a first
attach, and a reconfigure that did not change a `steer` flag will not
either, so editing an unrelated line cannot divert traffic by accident.

Each rung is a `steer` edit plus a SIGHUP. There is no restart and no
resync: a restart would cost about 40 seconds with the offload down at
every step, including the step meant to get traffic off a bad VPP
quickly.

**The lever has to travel.** What triggers a steer is the `steer` flag
*changing*, not its value — so a daemon that started with `steer on`
already in the file is sitting in the staging state and a reconfigure
against that same file does nothing. `packetframe status` names this
case: `configured "steer on", awaiting an operator lever move`. To move
it, set the port `steer off`, `packetframe reconfigure`, set it back to
`steer on`, and reconfigure again. This costs one round trip after any
restart of an already-steered deployment, and it is deliberate: a SIGHUP
raised for an unrelated edit must never divert traffic as a side
effect.

**Rung 0 — membership, everything off.** Every fast-path attach port
gets a `port` line; every one is `steer off`.

Decide `require-table-complete` first. On a box running its own bird,
leave it `on` (the default); the first steer then waits until the route
mirror matches bird's route count. On a box without a local bird, attach
refuses to start with `on`, because the check could never pass. Set it
`off` there and compare the counts yourself before turning a lever:
`packetframe status` reports how many routes are installed, and
`birdc show route count` on the box running bird says how many there
should be.

```bash
packetframe reconfigure
```

Wait for `fib-synced healthy` and for
`packetframe_vpp_routes{state="unresolvable"}` to read 0. Soak here for
at least an hour, and through a udapi provision cycle if one is due.
Nothing is diverted in this state: VPP is up, its FIB is synced and
verified, and every packet is still on the XDP path.

**Rung 1 — one port.** Flip the least important port to `steer on`,
SIGHUP, and confirm:

```bash
ethtool -n eth5 | head          # rules exist, at loc >= 1024
packetframe status | grep -A6 'module health'
```

`packetframe reconfigure` reports the outcome synchronously. If it says
the change was refused or withdrawn, **it is not in effect** — that is
deliberate, so "the rollout step succeeded" and "the rollout step is
pending" cannot look the same.

Not in effect is not the same as forgotten. A steer refused by either
gate — the completeness verdict, or a FIB still holding withheld,
unresolvable or in-flight routes — leaves the *ask* recorded, and the
module re-attempts it on its own once the refusal clears, at most every
30 s. The refusal message says so when that is what will happen. What
it never does is report success for something that has not taken
effect, which is the property this rung depends on: read the answer,
then confirm with `ethtool -n` before moving to the next rung.

Then watch actual traffic, not counters: PMTUD in particular. A DF
packet larger than the MTU through a steered path must come back as a
correctly-sourced frag-needed. A silent PMTUD blackhole is a week of
customer debugging.

**Rung 2..N — one port at a time**, with a soak between each. There is
no prize for going faster; the failure you are looking for is the one
that only shows up under real traffic.

## Rollback

Any rung, at any time:

```bash
# Edit the port back to `steer off`, then:
packetframe reconfigure
```

Traffic returns to the eBPF fast-path. Membership stays, the FIB stays
synced, VPP keeps running — you land on rung 0, which is a state you
have already soaked.

One thing about this path is deliberate: an allowlist that has outgrown
the MCAM budget does not block it. The budget check
only applies when rules are about to be installed, because `unsteer`
removes what the ledger names and never consults the plan. An allowlist
growing past the budget is a plausible route to wanting exactly this
rollback, and it must not be the thing that prevents it.

If you need the whole vector gone:

```bash
systemctl stop packetframe
packetframe detach --all
```

`detach --all` takes steering down **first**, then kills VPP, then
unbinds the VFs and restores hugepages. If it refuses, read the message:
a rule the NIC would not delete leaves traffic diverted at a VF the
teardown is about to unbind, so it stops rather than blackholing. The
state file names exactly which rules remain; clear them by hand
(`ethtool -N <iface> delete <loc>`) and re-run.

It reads each recorded location back before deleting it, and a location
the NIC will not describe counts as a refusal — the same message, and
the same remedy. That is deliberate: a slot the record names can hold
somebody else's rule by now, and on a NIC that will not answer, "do not
delete a stranger's rule" and "do not unbind a VF that may still be
steered into" point the same way.

## The adopted-reconciliation release gate: what it needs, and when it refuses

A restart over a steered VPP defers its reconciliation (the FIB dump
freezes every VPP worker — `ip_route_dump` is not mp-safe — so it only
runs against an unsteered VPP). The deferral releases through exactly
**two** doors, both requiring the feed session up (raised when the
stream STARTS — with one deliberate exception. For BGP it is the first
UPDATE of the session. For BMP it is the first RouteMonitoring frame,
but only while **no earlier stream's routes are still in the mirror** —
the station counts the mirror at each stream boundary rather than
guessing from what the connection did. In practice that means the
daemon's first connection raises on its first frame, and an ordinary
RECONNECT (which leaves a full table behind) stays down until
InitiationComplete (~5 s of stream quiet after the dump), because until
its GC runs the mirror still counts the previous session's routes and
would credit the release floor with stale evidence. Two corollaries
worth knowing at 3 a.m.: a predecessor that withdrew everything leaves
nothing, so the next stream raises immediately; and a peer-down wipe
whose FIB deletes partially FAILED leaves routes behind, so the next
stream does NOT — the count, not the intent, decides. So during a
reconnect an operator will see RouteMonitoring traffic flowing while
the gate still reads the feed as down — that is correct, not stuck. PeerUp is bookkeeping and never raises. "Quiet"
means the STREAM went quiet: every frame counts toward the activity
rate whether or not it changed the mirror, so a reannouncement dump
holds the gate loud until it actually ends:

1. **The floor**: the mirror holds ≥ `expected-routes`-derived
   capacity / 16 and has been quiet for **2 s when a completeness
   authority is configured, 5 s without one** — five being both
   listeners' own initiation-complete standard, because an unattested
   release may not claim completion on less evidence than the protocol
   itself requires. And without an authority, quiet means LITERALLY
   still: zero stream elements and zero mirror mutations for the whole
   window, because no rate allowance can distinguish slow churn from a
   throttled reload. Real feeds pause between churn bursts; one that
   never does keeps the deferral, visibly. This is the fleet's door —
   a full-table box with bird releases ~40 s after attach.
2. **The completeness authority** (`require-table-complete on`): bird's
   count agrees with the mirror, recomputed against the mirror as it is
   at release time. A negative verdict vetoes door 1 as well.

**There is no third door, deliberately.** A deployment whose real table
sits below capacity/16 with no bird has nothing honest to release on,
and the gate refuses to guess: the reconciliation defers indefinitely,
`fib-synced` reports Degraded with this exact remedy, and the adopted
FIB keeps forwarding untouched. Fix the configuration, not the gate —
size `expected-routes` within 16× of the real table, or add bird and
enable `require-table-complete`. (A heuristic third door existed for
one day; ten review rounds of corner cases and one fleet-path wedge
later, it was deleted. See PR #151/#152.)

If `fib-synced` shows the deferral persisting on a box that SHOULD
release: check the feed session actually started (`BGP client
connected` + at least one UPDATE in the log), then check the mirror
count against the floor in the health text.

## Triage by symptom

### Steering silently went partial — the NIC holds less than the config asks for

**The module now detects this within 30 s and says so:**

```text
steering  DEGRADED — 1 steering rule(s) this target asks for are missing
                     from the NIC, no longer match what was asked for, or
                     were never installed — that traffic is on the eBPF
                     tier. Something changed them out of band (a UniFi
                     provisioning push does this), or the allowlist grew
                     while the inherited rules stayed as they were;
                     `packetframe reconfigure` re-applies steering, and
                     reports its own reason if it refuses — a table too
                     incomplete to steer into is the usual one
```

It found the drift by asking the NIC, not by inferring it. **Measured on
the shadow 2026-08-11**: `ethtool -N eth1 delete 12` against a steered,
adopted daemon was reported as `steering DEGRADED` within 20 s. Before
the audit existed the same deletion went unnoticed for two minutes with
`steering healthy` and no log line.

**The line names the remedy that fits the situation, and there are
four.** Note it never promises the command will succeed: steering
passes two gates — the lifecycle state, and whether the table is
complete enough to steer into — and `reconfigure` reports which one
stopped it. What the line is for is telling you when the command is the
wrong move entirely. `packetframe reconfigure` reconciles steering only
from `Ready` or `Steered`; during an adopted resync it is refused with
*"vpp-offload is AdoptedResyncing, not converged"*. That is not a rare
corner — a held deferral is exactly when this audit earns its keep, and
on a box with no completeness authority it can hold indefinitely. So in
that state the line points at the convergence instead:

```text
steering  DEGRADED — 1 steering rule(s) ... a convergence re-applies
                     steering only if it verifies clean — one that ends
                     with routes withheld or unresolvable parks in the
                     staging state and emits no steer at all, and a steer
                     that IS emitted can still be refused by the
                     completeness gate. Both settle in the staging state
                     with the want remembered, and from there the module
                     re-attempts the steer by itself once both gates
                     permit. `packetframe reconfigure` asks immediately
                     rather than waiting
```

**Read that second sentence.** There are two ways the automatic path
declines. A verify that ends `VerifyIncomplete` — routes withheld or
unresolvable — parks in the staging state and emits no steer at all,
deliberately: diverting traffic into a FIB with known holes is what
that arm exists to prevent. And a steer that *is* emitted still meets
the completeness gate, which a stale or negative verdict refuses.

Either way the supervisor settles in `Ready` with the want remembered,
and **that is where the retry lives**: from `Ready`, and only where a
want was actually recorded, the module re-attempts the steer at most
every 30 s for as long as either gate refuses. So the drift does clear
itself once the blocker does — what the line will not promise is that
the blocker clears. If it is still there minutes later, read the
refusal: restore completeness (watch `fib-synced`), or find the
withheld and unresolvable counts in `packetframe status`. Running
`packetframe reconfigure` asks immediately instead of waiting out the
interval, and reports the reason if it is refused again.

The retry is **not** a way around the canary. It acts only where a want
was already recorded — a steer that was asked for and failed, an adopted
VPP that came with rules, a death while steered — never on `steer on`
alone, so a first attach still waits for a human.

Nothing is dropping meanwhile — the affected prefix is on the eBPF
tier, which is where it belongs.

**The exception is a stopped daemon, and it is the one that matters.**
If supervision has stopped — a teardown whose `unsteer` was refused,
say — the rules are still in the NIC, the VF is withheld, and *no
convergence is coming*. The line says so and points at cleanup:

```text
steering  DEGRADED — ... supervision has stopped, so nothing will
                     reconcile this on its own: `packetframe detach
                     --all` retries the teardown, and `ethtool -N
                     <iface> delete <loc>` removes a rule by hand
```

Take that one seriously: rules pointing at a VF whose VPP has been
killed are a blackhole, not a lost optimisation.

**A full `steer off` whose removal was refused reads differently**, and
as of the `SteerOutcome::NothingToSteer` fix it does repair itself:

```text
steering  DEGRADED — ... no port is configured to steer, so a convergence
                     that verifies without withheld or unresolvable routes
                     reconciles the NIC to an empty target and removes
                     these. One that ends incomplete parks in the staging
                     state and emits no steer at all, so nothing reconciles
                     and this line outlives the convergence — `packetframe
                     reconfigure` is then the retry, and with no port asking
                     to steer it removes the rules rather than reinstalling
                     any. Do not wait for either if VPP is not forwarding:
                     `ethtool -N <iface> delete <loc>` removes a rule now,
                     and `packetframe detach --all` retries the whole
                     teardown once this daemon has exited
```

`steer` is a reconcile, and a target with no port is a legitimate thing
to reconcile to: the stale-rule removal runs, the rules come out, and the
outcome lands as `Event::NothingToSteer` — which clears `steered` *and*
retires the want, so the module settles in `Ready` with `steer off
(staging state)`.

**Read the second sentence here too.** `Action::Steer` is what carries
that reconcile, and a convergence ending `VerifyIncomplete` parks in
`Ready` and emits none, so the leftover rules stay.

Whether anything then clears them by itself turns on one thing: whether
a *want* is still recorded. A death or wedge while those rules were
installed re-arms one, and from `Ready` the module's own retry
re-attempts the steer — which against a target with no port is exactly
this reconcile, so the rules come out within 30 s and
`NothingToSteer` retires the want. Neither gate holds it up, because
both describe a table traffic would be diverted *into* and this steer
diverts nothing. With no want recorded — a plain `steer off` whose
`unsteer` was refused and nothing since — there is nothing for the retry
to act on, and the repair waits for a convergence or for you.

Either way it is not a stuck state: `Ready` accepts `packetframe
reconfigure`, and with no port configured to steer that reconcile
removes the rules rather than reinstalling any. "Wait for the
convergence" is still the wrong instinct if the line is there once the
module reaches `Ready`.

It did not always. `steer` used to refuse an empty target outright,
before reaching that removal, because `Ok` had no way to say "nothing is
steered" and would have become `Event::Steered` — an offload reported as
carrying traffic it never saw. Meanwhile a refused `unsteer` leaves
`steered` true by design, a death while steered re-arms the want, and
`VerifyPassed` re-steers on the want: so every convergence re-entered the
same refusal and the rules diverted traffic forever, for a port the
operator had turned off.

Do not simply wait for the convergence, though. This line is also
reachable from `Backoff`, where the next one is however long the
exponential schedule says and VPP is not forwarding meanwhile — rules
pointing at a VF whose VPP is down are a blackhole. `detach` refuses
outright while a `packetframe run` daemon exists (it holds the bpf_link
FDs), so under a live module the `ethtool` deletion is the one that
works right now.

**Two directions, one count.** The rules the ledger names are read back
and compared field by field, so a deleted, replaced or narrowed rule is
drift. And the rules the *current* target asks for are checked for a
counterpart, so a rule that was never installed counts too — the shape a
restart produces when the allowlist grew while the daemon was down: the
state file names the old rules, they all read back clean, and the new
prefix has no rule anywhere. One-directional, that read Healthy for as
long as the adopted resync stayed deferred.

If the NIC will not answer the readback at all, that is reported too and
is NOT the same line:

```text
steering  DEGRADED — cannot verify steering: the NIC would not answer a
                     rule readback (EIO: ...). Rules may have been removed
                     or altered without this being visible; `ethtool -n
                     <iface>` is the ground truth until it clears
```

An audit that cannot read keeps its previous count — an unreadable NIC
is not a wrong one — but it must not present that count as current.
"Cannot check" and "checked, fine" are different answers.

The audit also reports the opposite complaint, and names it first:

```text
steering  DEGRADED — 2 location(s) the ledger names are still occupied by
                     rules this config does not ask for — a port it leaves
                     unsteered, or prefixes dropped from the allowlist — so
                     traffic may still be diverted into VPP that should not
                     be. The rules outlived the request to remove them;
                     `ethtool -n <iface>` shows what is there, and
                     <the remedy for the current state, as above>
```

Two ways to arrive here: a port turned `steer off` whose reconcile has
not run, or an allowlist that lost a prefix while its rules stayed
installed. Both mean traffic is being diverted that nobody asked for —
the opposite complaint to the drift line above, and the fix points the
other way: these rules need REMOVING, not reinstalling.

**Do not wait this one out.** A missing rule is a lost optimisation —
its prefix is on the eBPF tier, which forwards. A stray rule is the
reverse: it is pushing traffic *into* VPP. `Supervisor::fail` unsteers
before it kills for exactly this reason ("until the MCAM rules are
gone, every steered packet is going to a VF nothing is servicing"), so
when that unsteer is refused the rules outlive the process and the
affected prefixes are **dropped**, not merely deoptimised. Exponential
backoff can postpone the next convergence indefinitely.

**Identify before deleting, and the VF alone will not identify.** The
line gives a count, never the locations, so `ethtool -n` is on the path
anyway — and after a restart the audit reports an occupied slot without
being able to prove it still holds *our* rule (`installed_as` is set
only by a successful steer in this process).

**Try `packetframe reconfigure` first.** `steer` removes what the
ledger holds and the target no longer wants, so it works from the
recorded locations rather than from your reading of `ethtool -n`, and
you identify nothing by eye. Hand-deletion is the fallback for the two
cases where it will not run: a stopped daemon, or no port configured to
steer (the health line says which).

**`reconfigure` will not delete a rule that is not ours; your own
`ethtool -N` will.** The delete ioctl addresses a **location**, not a
rule, so the module reads each location back first and deletes it only
when its `Action` names the VF this module owns. A slot that has been
taken over by an unrelated classifier rule is left alone, logged, and
dropped from the record — its traffic is not ours to break. Hand
deletion verifies nothing, which is why the identification table below
exists.

The ownership test removal applies is **narrower than the audit's, on
purpose**: the VF the rule targets, not the whole spec. The two answer
different questions. The audit asks *is this our rule*, and a wrong
answer costs a health line. Removal asks *will this still be steering
into the VF we are about to release*, and a wrong answer there is a
blackhole — so a rule pointing at our VF comes out even when nothing can
prove we installed it. What is protected is the rule pointing somewhere
else.

Note "the VF", not "the cookie": a `ring_cookie` is a VF *and* a queue
index within it, so `Direct to VF 0` and `Direct to VF 0 queue 3` are
different cookies naming the same VF. Both come out. If you are reading
a `warn` line, the cookie it prints is the raw value — the VF is its
bits 32-39, and `0` there means the PF rather than any VF of ours.

It is a check, not a lock. The read and the delete are two ioctls and
the ntuple table has no userspace-holdable lock — `ethtool -N` takes
none either — so a rule written into a slot in the gap between them can
still be deleted. Nothing available closes that: `ETHTOOL_SRXCLSRLDEL`
takes a location and no expected value. If you are pushing controller
config at a box while it tears steering down, expect to reconcile
afterwards rather than expecting the module to have won the race.

Two consequences worth knowing before you read a log:

- `unsteer` can return OK with rules still in the table. That is not
  the old "removal was skipped" bug — it means the locations the ledger
  claimed hold nothing of ours, so the VF is safe to hand back. The
  `warn` line names each location and the cookie it found.
- A location the NIC will not answer for (EIO, or a port that has gone
  admin-down) is a **failure**, not a removal. It stays on the record
  and the VF is withheld. Nothing is deleted on a guess.

If you must identify by hand, a rule is this module's when **all** of
these hold, not any one:

| field | what ours looks like |
|---|---|
| `Dest IP addr` / `Src IP addr` | a /24-ish prefix on one side, the other side `0.0.0.0 mask 255.255.255.255` |
| `Action` | `Direct to VF <n>`, the VF this module owns |
| `TOS` / `Protocol` / `L4 bytes` masks | all `0xff` / `0xffffffff` — ours constrain nothing else |

**The current `allow-prefix` list is NOT the test**, and this is the
trap: the commonest stray is a prefix you just *removed* from the
allowlist, whose rules are by definition absent from the config you are
holding. Check the config's previous revision (or your change diff) for
the prefix that was there an hour ago.

The action alone is not proof either: another rule can target the same
VF while matching different traffic, and a *narrowed* copy of one of
ours keeps the cookie. That is why the audit compares the whole spec
rather than the cookie, and why you should — you are answering "is this
ours", which is the audit's question, not removal's. Removal is content
to delete a rule aimed at our VF that it cannot otherwise identify;
you, deleting by hand while the VF stays bound, have no such excuse.

**A cleaner route for a removed prefix**, if the module is live and
accepting: put the prefix back, `reconfigure` so the module owns those
rules again, then remove it and `reconfigure` a second time. The stale
removal in `steer` takes them out properly, and nothing is identified
by eye.

```bash
ethtool -n eth1            # read the fields, compare against the table
ethtool -N eth1 delete 12  # only for locations you recognised
```

Deleting a location that turned out to hold somebody else's classifier
rule breaks its traffic, and unlike a wrong health line that is not
recoverable by reading. If you cannot recognise it, leave it and say so
in the incident notes — a stray rule that is not ours is not ours to
remove.

"May", not "is", and the wording is deliberate. Where the port was
turned off by a live `reconfigure` the audit still holds the outgoing
target and proves ownership field by field. After a *restart* that
dropped the port there is nothing left to check the readback against —
the state file records locations, not what they should contain — so all
that can be established is that the slot is occupied. `ethtool -n
<iface>` settles it.

That is the rollback lever not taking. A `steer off` whose reconcile was
refused (the completeness gate) or whose deletes failed leaves the ledger
naming rules on a port you asked to go quiet — and traffic keeps entering
VPP there. It is a different remedy from the drift line above: those
rules need REMOVING, not reinstalling.

And when both hold — drift was proven, then the NIC stopped answering —
the line says so, because a count read as current sends you to fix that
many rules and stop looking:

```text
steering  DEGRADED — 1 steering rule(s) ... reconfigure reconciles either
                     way. That count is the last answer the NIC gave, not
                     a current one: the NIC would not answer a rule
                     readback (EIO: ...), so rules may be removed or
                     altered without this being visible
```

**Detection only — it does not repair**, deliberately: re-asserting rules from a
background audit would put a second, unsupervised installation path
beside `Action::Steer`, and the repair is one operator command.

Before that audit existed this went entirely unnoticed. Measured
2026-08-11: a rule deleted out of band (`ethtool -N eth1 delete 12`) was
still missing two minutes later, `steering healthy` throughout, not one
line in the log — nothing polled the NIC, and the only thing that
re-emits `Action::Steer` is `VerifyPassed`, which does not recur in
steady state.

What it costs: less than it sounds. Traffic for the stripped rule falls
back to the **eBPF tier**, which is exactly where it belongs — this is a
lost optimisation, not a lost packet. What you lose is the knowledge
that it happened.

**Detect** by comparing the two directly; they should match:

```bash
ethtool -n eth1 | grep -c '^Filter:'
grep -o '"steer_rules".*' /var/lib/packetframe/state/vpp-offload.json
```

**Repair** with a plain reconfigure — no config change, no lever
movement, no restart, no traffic impact:

```bash
packetframe reconfigure
```

That works because `steer` is a reconcile rather than an append: on a
port that is already steered it re-installs whatever the target says is
missing. (A reconfigure will *not* start steering a port that is
unsteered — that still needs the lever.) Verified 2026-08-11: 3 rules →
4, exit 0.

**Run it after every UniFi provisioning push while a port is steered**,
and check the count afterwards. A push on 2026-08-11 did not disturb the
VF, hugepages or VPP — but it reconfigured a different interface, so it
never tested this path.

### A verified FIB is not a complete one

`fib-synced healthy — N routes installed; verified on 64 probes` means
the probes matched the mirror. It does **not** mean the table is whole.

Measured 2026-08-11 on a cold bring-up: `healthy` at **11.4 s with
110,724 routes** — about 10% of the table — with 64 probes passing,
because verify samples the ledger and the ledger was small. The full
table arrived by 61 s.

That is safe on its own, because a first attach never steers itself:
`steer on` in the config is a staging state until an operator moves the
lever. The exposure is the operator who moves it early.

**`require-table-complete on` is what closes it**, and it is not
optional on a box with a bird:

```
module vpp-offload
  require-table-complete on
```

With it, `steer` refuses while the mirror disagrees with bird's count,
reports why, and re-attempts itself — at most every 30 s — once the
mirror converges, so an early lever-move costs a wait rather than a lost
offload. Without it there is no gate at all — the refusal path is
compiled out — and the canary ladder is the only thing between an early
lever-move and traffic diverted into a 10%-loaded FIB. (The retry
itself does not depend on the gate — a steer the NIC refused is
re-attempted either way — but with no verdict to wait on, an early
lever-move steers into whatever is loaded at that instant.) `off` is
the documented opt-out for boxes with no bird to compare against (the
shadow), not a default to leave alone.

### `packetframe status` disagrees with what you just did

`status` reads `module-health.json`, which the loader rewrites every
**5 s** — so it is a snapshot, and the header says how old:
`(pid N, Ms old)`. Read that age before believing a line that
contradicts something you just did.

**After a `reconfigure` it is not stale.** The SIGHUP handler refreshes
the health file *before* writing the acknowledgement marker the CLI
waits on, so by the time `packetframe reconfigure` returns, `status`
already reflects the change. That was not true before 2026-08-11: a
reconfigure returned OK and logged `steering UP`, `ethtool` showed the
rules installed, and `status` still read `steer off (staging state)`
from a five-second-old snapshot.

Two cases where the age still matters:

- **A rejected reload publishes nothing.** A config that fails to parse
  or validate returns without refreshing, so `status` keeps whatever it
  had until the next scheduled poll.
- **Changes the module makes on its own** — a verify completing, a
  process dying, steering torn down by trouble — land on the ordinary
  5 s cadence, because nothing is waiting on them.

Ground truth, when you need it rather than a snapshot: `ethtool -n
<iface>` for what the NIC holds, and the `steering UP:` / `steering
DOWN:` log lines for when it changed.

### `packetframe status` says STALE

The daemon is gone; VPP is not being supervised. Check whether VPP is
still running (`pgrep -a vpp`) and whether MCAM still points at its VF
(`ethtool -n <iface>`). If both are true, traffic is still being
forwarded by an unsupervised process — restart packetframe, which will
**adopt** it rather than restarting it.

### Steering is on but traffic is not arriving at VPP

Check the NIC's ledger against ours. Ours is
`vpp-offload.json:steer_rules`; the NIC's is `ethtool -n <iface>`. If
the NIC has no rules but we believe we are steering, the UniFi
controller has wiped classifier state — a provisioning push does this.
The supervisor re-asserts on every `Ready`, so a `packetframe
reconfigure` (or the next verify) restores them.

If the NIC *has* the rules and traffic still is not arriving, suspect
`ring_cookie`. It must be `(vf + 1) << 32`; `ethtool`'s own `vf N`
keyword mis-encodes it on the rvu driver, so a rule installed by hand
with that keyword lands somewhere else. Gate 0a established this by
inserting both forms and reading back what the NIC stored.

### A steer is refused with "the route mirror holds N of M routes"

The completeness gate. bird's initial dump has not finished, so the
mirror is short of the table and steering into it would blackhole
whatever has not arrived — and a steered miss is dropped, where an
unsteered one falls through to the kernel path.

**It retries on its own** — from `Ready`, at most every 30 s, for as
long as the want stands. The refusal leaves the want set and the module
re-asks the gate on its own tick, so the ordinary outcome is that the
dump finishes and the steer lands a few tens of seconds later with
nobody doing anything.

Read that as a bounded wait, not a guarantee. Until 2026-08-11 it was
not true at all: the only two things that emitted a steer were the
verify at the end of a convergence — which does not recur in steady
state — and an explicit `packetframe reconfigure`, so a lever move that
raced bird's dump left the offload down until a human asked again.
Three operator-facing texts said otherwise, and the retry that made
them true landed afterwards. On a daemon older than that date, the
manual path below is the only one.

Watch the two counts converge:

```bash
birdc show route count
packetframe status | grep -A6 'module health'
```

Once they agree the steer lands by itself within the interval;
`packetframe reconfigure` asks immediately if you would rather not wait
(and it reports the reason if the gate refuses again).

If it persists, the mirror is genuinely not keeping up and that is a
fast-path problem, not a steering one — check the integrity checker's
drift warnings in the log.

Refusals reading **"completeness is unknown"** or **"too old to act on"**
mean something different: no check has run, or the last one is over 15
minutes old. That is `birdc` failing, not the table being incomplete.

### `packetframe_vpp_routes{state="unresolvable"} > 0`

A route whose nexthop device this module cannot map. Steady state is
exactly zero — the live table has only two egress devices, no VLAN
nexthops, no tunnels — so any non-zero value means either a new egress
device appeared in the table or a member port is missing. Check the
`port` lines against every `dev` appearing as a FIB nexthop in bird.

This also **blocks the first steer** on an unsteered port, by design:
if the table cannot be installed, traffic must not be diverted into it.
A lever move refused on those grounds is remembered, and the steer goes
in on its own once the count reaches zero — so fix the mapping and
watch, rather than re-running `reconfigure` on a timer.

### `packetframe_vpp_routes{state="withheld"} > 0`

The table outgrew the heap VPP started with. `expected-routes` sizes
both the main heap and the stats segment, and VPP fixes both **at
start** — so this cannot be fixed by a reconfigure, and `reconfigure`
will refuse the change rather than apply a new ceiling to a VPP running
on the old segments. That refusal is not pedantry: applying it anyway is
the mid-resync OOM abort gate 0b found. Raise `expected-routes`, then
restart.

### `route-feed DEGRADED` / `packetframe_vpp_drain_failing 1`

The last attempt to push route updates into VPP did not land. The work is
**not lost** and is retried every tick — the offload is forwarding a table
that is behind bird, not a wrong one.

**Which queue holds it depends on where it failed, and the two are
different metrics.** The row itself prints both counts; do not read one of
them as the whole answer:

- Work that never reached VPP's FIB because the *drain* broke mid-batch is
  requeued in the engine's pending map → `packetframe_vpp_pending_ops`.
  `source_backlog` can sit at zero throughout.
- Work handed back to the route feed because a *neighbour* send failed
  before its batch's routes were applied → `packetframe_vpp_source_backlog`.

Read the reason on the row. Two shapes matter:

- **A transport error** (`socket closed`, `context mismatch`). The engine
  drops its connection and reconnects on the next tick; one of these in
  isolation is noise. Sustained, it is VPP not answering, and the wedge
  detector owns that. This is the `pending_ops` shape above — unless the
  socket broke on a neighbour message, in which case the batch went back
  to the feed *and* the affected adjacency is reconciled against a fresh
  `ip_neighbor_dump` before anything is re-sent, because a write whose
  reply never arrived may or may not have been applied.
- **`VPP refused the static neighbour for <nexthop> (retval …)`** — VPP
  rejected an adjacency. This one blocks the whole delta stream: routes
  through an unprogrammed adjacency install cleanly, verify cleanly and
  drop every packet, so nothing in the batch is applied until the
  adjacency is. Check that the nexthop's egress device is a configured
  `port` (or a declared VLAN over one) and that `ip neigh` still shows
  the nexthop with a real MAC.

While this is set on an **unsteered** port, the first steer is refused —
the missing prefixes are in none of the `unresolvable`/`withheld`/
`installing` counts, so those reading zero is not enough on its own. It
clears as soon as one update lands; look again rather than reconfiguring
anything.

### The offload restarts repeatedly

`packetframe status` carries the reason on the failing subsystem, and it
is **sticky** — retained across the empty backoff ticks that follow a
failure, so a slow poll cannot miss it. Read it before touching
anything; the counter of failures is not the reason.

If the reason mentions a CRC or version mismatch, supervision has
*ended* rather than looping: the binary API is permanently incompatible
and no retry can fix it. The installed VPP is not the pinned one.

### A steer or unsteer that "cannot be confirmed"

Both directions refuse rather than guess. `Ok` from unsteer is what
releases the VF, so a removal that could not be confirmed keeps the VF
withheld and keeps every later teardown trying.

Where you see it is `detach`, not `status`: the teardown returns
`teardown did not complete; VF/hugepage resources are still held`, and
retries keep returning it until the removal is confirmed. That is the
module declining to unbind a VF that MCAM may still target, which is the
correct choice — a leaked VF is a line in the state file and a reboot's
inconvenience; unbinding under live DMA is memory corruption.

## Numbers: measured vs published-on-faith

Be precise about this when reasoning about an incident.

**Measured, on the shadow:**

| number | value | conditions |
|---|---|---|
| Full v4 table convergence | **40.32 s** (budget ≤ 60 s) | 1,053,360 prefixes, drain 38.42 s at 27,418 routes/s, verify PASS. 2026-08-03, **one VF, fresh attach**. |
| Main heap | 463 B/route over a 337.86 MiB floor | gate 0b item 10 |
| Stats segment | 97 B/route | **at two threads** — counter vectors are per-thread, so every per-route figure is a two-thread figure |
| Live table | 1,053,360 v4 (1,301,000 v4+v6) | 2026-08-02 |
| Nexthop spread | eth3 1,248,508 / eth2 52,492 | the full-table decision rests on this |
| ntuple `loc` space | **16 per port** (0..=15) | measured on the shadow's eth1 2026-08-05, by insert-and-read-back. At 2 rules per prefix → **8 steerable IPv4 prefixes per port**. Production's allowlist is 2. |
| NPC MCAM block | 2048 entries, ~1689 free, 31 allocated per PF | from `npc/mcam_info`. **This is not the `loc` space** and must never be used to size one — doing so is what produced `base: 1024`, an out-of-range slot that failed the first steer this module ever attempted. |
| First steer | **4 rules installed and readback-verified** | 2026-08-06, shadow eth1, locs 15/14/13/12, src+dst × 2 prefixes → VF 0. Installation only: eth1 carries the interconnect, so zero packets match. |
| Steered-idle soak | **5 h 17 m**, rules intact, no restarts | 2026-08-06 overnight. Proves nothing wiped them; does **not** prove they survive a UniFi provisioning push — the re-assert path is still untested. |
| Drill (a) kill -9 under load | teardown **325 ms**, recovery **40.7 s** | 2026-08-08, 500 pps constant-rate flow. The 50 ms teardown target was missed and is documented as a bound; recovery ≤ 90 s holds with margin. |
| Drill (b) route change while down | **PASS** | the changed route was present in VPP before steering resumed. |
| Drill (c) SIGSTOP wedge | detected in **1.81 s** (target ≤ 2 s) | 2026-08-08, ping-interval-bounded as designed. |
| Drill (d) daemon death | **120,000/120,000 frames, zero loss** | 2026-08-08. The dataplane forwards independently of the daemon. |
| Drill (d) restart over a steered VPP | **150,000/150,000 frames, worst gap 0.109 s** | 2026-08-09 (d12). Full cycle inside the window: adopt → defer → unsteer at +40 s → FIB dump against an idle VPP (~7 s of frozen workers, felt by nobody) → diff (2.5 h of churn reconciled) → verify → re-steer at +78 s. The 5.4 s outage of the pre-#151 design is gone. |
| PMTUD through a steered path | **PASS** | frag-needed, mtu 1300, sourced from 169.254.254.3, ×5. Gate 0b item 7 closed. |
| Steered packets reaching VPP | **PASS** | gate 0b item 1 closed 2026-08-07: allowlisted frames counted on octeon0/0, non-allowlisted stayed on the kernel path. |
| Restart health window | Degraded ~40–80 s | see the note below — the deferral and reconcile are visible by design. |
| `detach --all` | **2.814 s** | 2026-08-11 shadow, ONE VF with a live VPP holding 1.05M routes. Misses the published <1 s; see below. Breakdown: pins removed in 1 ms, then 2.80 s terminating VPP + rebinding the VF + restoring hugepages. |
| Interconnect blip during `detach --all` | **none** | same run, 5 Hz ping from the primary across the teardown: zero gaps >0.5 s, one 30 ms spike. Writing `sriov_numvfs=0` does not disturb the PF link. |
| `ip_route_dump` at adoption | **7.04 s** for 1,054,548 routes | 2026-08-11, timed directly rather than inferred from a traffic gap. This is the barrier-sync freeze §the deferral exists to keep away from steered traffic. |
| Adopted restart, UNSTEERED | ~53 s start→verified | 2026-08-11. Dump at +7 s, deferral held 32.8 s waiting for the mirror, diff+verify after. No traffic impact — nothing was steered. |
| Cold bring-up (nothing running) | **11.4 s to `healthy`, ≤61 s to full table** | 2026-08-11. Read the caveat: `healthy` at 11.4 s meant **110,724 routes** — 10% of the table, verified clean. See "A verified FIB is not a complete one". |
| `reconfigure` (lever move) | **0.215 s** | 2026-08-11, exit 0, writes `OK <ns>` to `last-reconfigure.timestamp`. |
| Idle draw with VPP polling one worker | 33.56 W, 38/49/42 °C, fan 3780 RPM | 2026-08-11 shadow, chassis total — NOT a VPP attribution, no VPP-off baseline was taken. |

**Published but never measured:**

| number | status |
|---|---|
| `detach` across **more than one** VF | UNMEASURED — the single-VF case is measured above at 2.814 s. Nothing has torn down N>1 VFs, and the per-VF cost is unknown. |

### A planned restart looks Degraded for 40-80 seconds. Do not page on it.

Restarting packetframe over a **steered** VPP reports:

```
vpp-offload: DEGRADED
  fib-synced   DEGRADED — resync deferred: ... the adopted FIB keeps
                          forwarding untouched
```

for the length of the deferral plus the reconcile, then clears to
`fib-synced healthy` on its own. Measured 2026-08-09 on the shadow
(d12): unsteer at +40 s, re-steer at +78 s, worst forwarding gap
0.109 s.

This is correct and deliberate, and it is DEGRADED rather than
UNHEALTHY on purpose: the adopted VPP is forwarding a FIB the previous
daemon verified, so packets are fine — what is unfinished is this
daemon's reconciliation of it. Overall health tracks whether packets
are forwarded correctly, not whether the offload has caught up.

The shape changed with the deferred-dump design (#151). Before it, the
module dumped VPP's FIB immediately at adoption and reported UNHEALTHY
("traffic steered into an unverified FIB") for ~10 s — and that dump
froze every VPP worker for 5.4 s, which is the outage the deferral
exists to remove. If you are reading a runbook copy that describes the
10 s Unhealthy window, it predates #151.

Consequence for alerting: anything paging on `packetframe_vpp_health`
fires on every planned restart. Alert on a sustained NOT-healthy state
of **two minutes or more** — comfortably past the measured 80 s — or
exclude the window explicitly. Thirty seconds, the pre-#151 guidance,
now fires on every restart.

One case where the wait is legitimately unbounded: if the feed session
flaps DURING the deferral, the completeness authority is demoted until
the source reports its initiation-complete GC, which needs 5 s without
updates and which a live DFZ feed may never give. The deferral message
says so explicitly when that is what is happening — read it before
concluding the checker is broken. Nothing is dropping meanwhile.

### A member port needs two things admin-up does not give it

Both were found by tracing a live VPP on 2026-08-07, each hidden behind
the other, and the module now does both at attach:

1. **The port must carry the PF's MAC.** MCAM redirects frames addressed
   to the *PF*; the VF has its own address, so without this every steered
   frame is punted `ethernet-input: l3 mac mismatch`. It is also what
   makes VPP source MAC-PF on transmit, so the frame leaves the same LMAC
   and the upstream switch never sees the address move ports. The module
   sets it and then **reads it back** — `sw_interface_set_mac_address` can
   return 0 and change nothing, and that failure is invisible in every
   other surface.
2. **IPv4 must be enabled on the port.** A member with a correct FIB and
   no IPv4 drops everything at `ip4-not-enabled`. `loopback-address` in
   the config is the address VPP's loopback holds; members are unnumbered
   to it.

**What this looked like before the fix, and why it matters for the
canary:** with 1,053,960 routes installed and verified on 64 probes,
`packetframe status` reported `fib-synced healthy` while VPP forwarded
**zero** packets. Readback verification samples the FIB, and the FIB was
genuinely right. A verified FIB is not a forwarding dataplane — on a
steered production port that distinction is the difference between a
canary that reveals a problem and one that blackholes traffic with every
gauge green.

### Verification does not re-run in steady state

`fib-synced` reports the **last completed** readback verify, and the
`last ok Ns ago` beside it is not decoration — on a long-lived steered
daemon it legitimately reads hours. Measured: `last ok 18966s ago` after
a 5 h uptime.

Verify runs on first attach and after every resync, then not again. A
periodic verify would have to sample the ledger and probe VPP while
deltas are in flight, and a withdrawal landing between sample and probe
reads as a mismatch — which is why delta draining is excluded during
`Verifying` in the first place. Steady-state divergence is meant to
surface as drain errors and a rising outstanding count instead.

What this means when you are reading a dashboard: a green `fib-synced`
says the FIB was verified *at some point*, not that it is being watched.
Nothing here would notice VPP's FIB drifting for a reason other than this
module's own deltas.

**Failed, and shaping the design:**

- **`ip6` ntuple is rejected by the AF** (error 710) while the v4
  control inserts cleanly — the vendor NPC profile has no v6
  extraction. No IPv6 packet can be MCAM-steered into VPP, so v6 stays
  on the XDP custom-FIB path. Retest at every UniFi kernel bump; the
  MKEX profile ships with the AF driver.
- **`rx-mode adaptive` is unsupported** by the native octeon driver.
  The heat goal is dead: **one hot core per VPP worker, 24/7**, as a
  permanent recorded cost. Budget power and thermals for it.

## Install and upgrade on the router

> **`detach` and `status` can be run from a newly deployed bundle.**
> Until 2026-08-12 they could not: every liveness check asked whether
> some process ran *the CLI's own executable path*, which is false
> whenever a command runs from a new bundle while the old daemon is up
> — the shape every upgrade has. `status` printed `STALE` over a live
> daemon, `reconfigure` refused, and `detach` found no daemon and
> **proceeded**, unlinking pins while the daemon still held the
> `bpf_link` FDs.
>
> The daemon now records `(pid, start_ticks, boot_id)` in
> `packetframe.identity`, beside the pid file, and the checks verify
> against that — so the CLI's own path no longer matters.
> `packetframe.pid` stays a bare pid on purpose: CLIs from other
> bundles parse it whole, and a rollback has to keep working. Limits
> worth knowing:
>
> - A daemon whose pid-file write failed (it is non-fatal, and happens
>   after attach) is found by its **identity sidecar**, which the daemon
>   goes on to write and which names its own pid — so nothing depends on
>   what the binary is called. If that is missing too, a `/proc` scan is
>   the last backstop. The scan matches a binary named `packetframe`
>   running `run`, so an unrelated process named that way will make
>   `detach` refuse and name the pid. That is deliberate — refusing is
>   recoverable, unlinking under a live daemon is not.
>
>   **Residual, deliberate:** a daemon that wrote *neither* file — an
>   unwritable state dir — *and* runs under a binary name sharing no
>   prefix with `packetframe` is invisible to all three checks, and
>   `detach` will proceed. Refusing on every recordless state instead
>   would disable `detach` after every clean stop, since the daemon
>   removes both files on the way out and `detach` is the advertised
>   recovery path. Closing it properly means checking whether any
>   process holds the pinned links, which is evidence that never goes
>   through a pid; that is not built. `status` DOES see such a daemon
>   when its health snapshot matches the live process, and warns
>   explicitly that `detach` would proceed under it — stop the daemon
>   first.
> - **The state directory itself must be root-owned and not group- or
>   world-writable**, or every record in it is treated as plantable and
>   live pids read as CANNOT CONFIRM. Per-file ownership is not enough:
>   `rename` moves a root-owned record between directories without
>   touching its contents, so a writable directory's records could have
>   been replayed whole from another instance's state dir. The daemon
>   clears the group/world-write bits on its state dir whenever it
>   writes a record; if you hand-create a custom `state-dir`, make it
>   `root:root` mode `0755` (or tighter).
>   The same rule runs up the **ancestor chain**: every directory above
>   the state dir must be root-owned and either not group/world-writable
>   or sticky (`/tmp` qualifies) — otherwise the whole state dir could
>   be renamed and another one swapped into its place without touching
>   a file. And the configured `state-dir` path must contain **no
>   symlinks** (a symlinked component is the same swap, done by
>   repointing): on systems where `/var/run` links to `/run`, configure
>   the real `/run/...` path.
> - A sidecar that is present but unreadable or malformed is treated as
>   "cannot tell", never as missing — a torn write is what a live
>   daemon's record looks like mid-trouble. Conversely, a torn *pid
>   file* next to a whole sidecar still identifies the daemon: the
>   sidecar is consulted whenever the pid file cannot answer alone.
> - If the pid file and the sidecar **disagree** and the sidecar's
>   identity matches a live process, everything answers CANNOT CONFIRM
>   ("two authenticated records disagree"). This is what a restart
>   whose pid-file rewrite failed leaves behind: new sidecar, old pid
>   file. Restart the daemon to re-record both, or remove the stale
>   pid file.
> - The scan has to *complete* to count as evidence of absence. If
>   `/proc` cannot be listed, or a process in it cannot be examined
>   (running `detach` as a non-root user is the ordinary cause), the
>   refusal says `the process table could not be searched` and names how
>   many processes were unexaminable. Re-run as root; removing the pid
>   file will not help, because the scan is what the missing record
>   falls back to.
> - A recorded pid whose live identity **does not match** is never
>   resolved either way: the pid was reused, or the record is stale, and
>   nothing in the data separates them. `status` says CANNOT CONFIRM,
>   `reconfigure` and `detach` refuse, and the message says whether a
>   packetframe daemon holds that pid. It is deliberately not resolved
>   by "well, it is *a* daemon" — a `packetframe run` from another
>   bundle and another state dir satisfies that, and signalling it would
>   reload a stranger's config. Restart the daemon to re-record the
>   identity.
>   This is reachable after a rollback to a build that does not write
>   the sidecar, but only if the pids coincide across a reboot; the
>   ordinary rollback leaves a sidecar naming a different pid, which is
>   ignored.
> - **Only a matching identity confirms.** A record that carries no
>   identity — the pid-only file a pre-sidecar build writes — never
>   resolves a *live* pid to "our daemon", even when a packetframe
>   binary holds it: the executable check finds *a* daemon, not *the*
>   one the record describes. The cost lands once, on the first upgrade
>   from a pre-sidecar build: `reconfigure` refuses and `status` says
>   CANNOT CONFIRM until the daemon restarts on a build that records
>   identity. (`status` usually recovers sooner — the health snapshot
>   carries the publisher's own identity, and a match against the live
>   process confirms the report even when every pid record failed or
>   is missing.)
> - `detach` refuses on "cannot tell", not only on "daemon present".
>   When the message names a pid that is **not** a packetframe daemon,
>   and you have established there is none, remove the pid file and the
>   identity sidecar from the state dir.


VPP is **not** bundled in packetframe's .deb — 100 MB against 1.3 MB,
mismatched cadence, and independent rollback, which the failover design
wants anyway. It ships on its own release tag, built from *unmodified*
upstream source (no fd.io bullseye+arm64 package exists at any version).

Pin: **v26.06**, `platform = "octeon9"`, tag
`vpp-v26.06-octeon9-bullseye-arm64`. The platform is mandatory rather
than tuned — it is the only shape that builds the native octeon driver,
and DPDK PMDs inside VPP are measured-dead on this NIC at every version.

Four traps, each of which has cost real time:

```bash
# 1. Mask the service BEFORE install: the deb's postinst starts VPP.
systemctl mask vpp.service
# (on a re-run, stop it first)
systemctl stop vpp.service; systemctl mask vpp.service
```

```bash
# 2. VPP_INSTALL_SKIP_SYSCTL=1 is MANDATORY on routers. The deb writes
#    vm.nr_hugepages=1024 assuming 2 MB pages; on this 64K-page kernel
#    the default pool is 512 MB, so that is a 512 GiB request.
VPP_INSTALL_SKIP_SYSCTL=1 dpkg -i vpp_*.deb
```

```bash
# 3. Extract to /root, never /tmp — /tmp is noexec on UniFi OS, and a
#    binary there fails at execve with EACCES.
```

```bash
# 4. Removing the vpp package UNBINDS the VF from vfio-pci. Re-bind
#    after every purge or upgrade, or the next attach finds the VF on
#    the kernel driver and refuses.
```

Upgrade is `detach → install → attach`. There is no cross-version
adoption: the state file records the VPP version, and a mismatch is
refused rather than adopted.

## Constraints worth knowing before you debug

- **`packetframe feasibility` does not attach anything.** It used to,
  via `--config`, on every configured port — including the native-XDP
  attach that panics this fleet. Fixed in v0.2.7; on an older build, do
  not run it against a live config.
- **`reconfigure` accepts only the `steer` flag.** `port`, `cores`,
  `expected-routes`, `hugepages` and `vpp-binary` are all fixed at VPP's
  start or at VF acquisition, and each is refused **by name** with what
  to do about it. A daemon whose running config silently differed from
  the file you just edited is how the wrong thing gets debugged for an
  hour.
- **Restart ordering is stop → detach --all → start.** This bit
  production twice. A plain `systemctl restart` leaves the previous
  attachment's pins in place and the next start refuses them.
- **The ntuple table holds 16 rules per port, and `npc/mcam_info` will
  not tell you that.** The driver rejects an out-of-range `loc` with
  `EINVAL` rather than assigning one. The module asks the NIC via
  `ETHTOOL_GRXCLSRLALL` and takes the highest free slots; the debugfs
  figures (2048 entries, 1689 available) describe the NPC block across
  all six PFs and govern nothing here. Ceiling: **8 IPv4 prefixes per
  steered port**, and `packetframe feasibility` reports the real free
  count under `vpp.steering.budget`.
- **A port must be administratively UP before it can be steered.**
  `otx2_get_rxnfc` gates on `netif_running`, so a down port answers
  `EOPNOTSUPP` to both the insert and the rule-count query — which reads
  like the NIC lacks ntuple rather than like the link being down.
  `ethtool -k <if> | grep ntuple` says `on` either way and will not
  disambiguate it.
- **`ethtool -n` prints the COMPLEMENT of the mask it stores.** Its CLI
  `m` argument means "bits to ignore" and it inverts on the way in and
  on the way out, so a /24 you typed as `m 0.0.0.255` displays as
  `0.0.0.255` and sits in `ethtool_rx_flow_spec.m_u` as `ff ff ff 00`.
  In the struct a set bit **matches**; zero ignores. Do not infer the
  wire format from the display — read it with `ETHTOOL_GRXCLSRULE`
  (`/root/dumpspec.py` on the shadow does exactly this). Believing the
  display cost one merged PR and one failed steer.
- **`ethtool -N` exits 0 when the insert fails.** It prints
  `rmgr: Cannot insert RX class rule: ...` to stderr and returns success,
  so any check shaped like `if ethtool -N ... >/dev/null 2>&1` reports
  every location as working. Confirm with `ethtool -n <if>` and look for
  the `Filter: <loc>` block.
- **The first steer is guarded against an incomplete table — but only
  where there is a bird.** Verification samples what the *ledger* holds,
  so a table that is merely missing prefixes verifies clean. That is why
  the guard is a separate comparison against bird's own route count,
  published by the fast-path integrity checker and consulted by every
  steer, not by the verify. Where no publisher exists,
  `require-table-complete off` hands the judgement back to you, and rung
  0's soak is what discharges it: the `unresolvable`, `withheld` and
  `installing` counts must all read zero before you turn the first
  lever — **and no `route-feed` row may be present**. Those three counts
  cannot describe an update that never reached VPP at all, which is why
  that row is a separate condition on the same gate.
