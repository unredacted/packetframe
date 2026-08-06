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
> **No part of this module has ever run against a real VPP process.**
> Every layer is unit-tested, `Module::attach` runs end to end against a
> fixture sysfs and a fake VPP on a unix socket, and the convergence
> budget was measured by a bench driving the same engine — but the
> composition has never executed on hardware. Neither has any of the
> three published failover numbers.
>
> **The MCAM ioctl path has now met a NIC, and it took several rounds.**
> First contact on 2026-08-05 found one real defect — the `loc` space
> sized from `npc/mcam_info` rather than from the driver — plus two
> self-inflicted ones chasing it: a `GRXCLSRLALL` that asked for more
> rules than existed, and a mask "correction" that inverted a field
> which had been right all along. Every one of them failed loudly, as
> designed: nothing was installed, and the all-or-nothing unwind left the
> port with zero rules each time. What is *still*
> unproven is everything past installation: no steered packet has ever
> reached VPP, because the only port available to test on carries
> nothing the allowlist matches. Every rule
> insert is followed by an `ETHTOOL_GRXCLSRULE` readback and compared
> field by field, precisely so a wrong `ethtool_rx_flow_spec` offset
> fails loudly on first contact instead of installing a rule that
> matches the wrong traffic while both tiers report healthy. Expect that
> check to be the thing that fires first, and treat it as the module
> working, not failing.
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
down by trouble and not yet restored.

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
the change was refused or withdrawn, **it did not happen** — that is
deliberate, so "the rollout step succeeded" and "the rollout step was
queued" cannot look the same.

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

## Triage by symptom

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

Nothing to do: it retries on its own. The refusal leaves the *want* set,
so the next verify attempts the steer again, and by then the dump has
usually finished. Watch the two counts converge:

```bash
birdc show route count
packetframe status | grep -A6 'module health'
```

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

### `packetframe_vpp_routes{state="withheld"} > 0`

The table outgrew the heap VPP started with. `expected-routes` sizes
both the main heap and the stats segment, and VPP fixes both **at
start** — so this cannot be fixed by a reconfigure, and `reconfigure`
will refuse the change rather than apply a new ceiling to a VPP running
on the old segments. That refusal is not pedantry: applying it anyway is
the mid-resync OOM abort gate 0b found. Raise `expected-routes`, then
restart.

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
| Drill (d) adopt-while-steered | **PASS** | restart under a steered VPP; MCAM rule count sampled at 5 Hz never left 4, VPP never restarted, adoption took `Adopted {{ steered: true }}`. Loss unmeasured (no traffic peer). |
| Restart Unhealthy window | **~10 s** | between adoption and the first verify. See the warning below — it is correct behaviour. |

**Published but never measured:**

| number | status |
|---|---|
| Crash blackhole ≤ 50 ms | UNMEASURED — needs a constant-rate flow |
| Wedge detection ≤ 2 s | UNMEASURED |
| Recovery ≤ 90 s | UNMEASURED |
| `detach` < 1 s across N VFs | UNMEASURED — needs real VFs; relaxes to a documented best-effort bound if hardware says so |
| Steered packets actually reaching VPP | UNMEASURED — gate 0b item 1's second half; needs a traffic peer |
| PMTUD through a steered path | UNMEASURED — gate 0b item 7, unskippable |

### A planned restart looks Unhealthy for ~10 seconds. Do not page on it.

Restarting packetframe over a **steered** VPP reports:

```
vpp-offload: UNHEALTHY
  fib-synced   UNHEALTHY — traffic steered into an unverified FIB
```

for roughly ten seconds, then clears to `fib-synced healthy` on its own.

This is correct and deliberate. An adopted VPP is presumed
good-until-proven-stale: the module resyncs and verifies but does **not**
unsteer first, because unsteering a correctly-forwarding VPP would create
the blackhole the design exists to avoid. So between adoption and the
first completed verify, traffic genuinely is diverted into a FIB this
process has not yet checked — and the health surface refuses to call that
healthy rather than papering over it.

Consequence for alerting: anything paging on `packetframe_vpp_health`
will fire on every planned restart. Either alert on a sustained
Unhealthy (30 s or more) or exclude the window explicitly. Measured
2026-08-06 on the shadow during drill (d).

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
  lever.
