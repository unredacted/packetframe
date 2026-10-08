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
> **This module has forwarded production traffic.** On the lab
> gateway: first bring-up 2026-08-05, first forwarded packet
> 2026-08-07, the five acceptance drills and a restart-over-steered-VPP
> cycle through 2026-08-09, then `detach --all`, a cold bring-up and the
> steering-reconcile checks on 2026-08-11. On the **primary**, across
> 2026-08-13..17: a full-table six-port attach behind bird's live dump,
> then five steers of a live trunk port, ending in a 2 h soak with
> kernel exemptions in place. At rung 1 the steered path beat the XDP
> path by more than 10x under coexistence — ~0.1% remote loss steered
> against 4-7%/min unsteered in the same window.
>
> **Each of those five steers found a defect.** Undeclared trunk VLANs
> punting 8.7M frames; the VF answering to its own MAC instead of the
> bridge's; the bridge MAC as a member's PRIMARY silently capturing
> ~300 kpps from attach with the lever still off; locally-terminating
> traffic dying at `null-node`. The `vlans`, secondary-MAC and
> `steer-exempt` machinery all exist because a rung exposed the need.
> Read that as the ladder working, and as the reason not to skip rungs.
>
> **It is in production now.** After the 2026-08-21 hugepage brick and
> the 2026-08-26 factory reset wiped that first deployment, the ladder
> was walked again from rung 0. The reference router now runs the
> offload **steered on four ports, in both directions, for IPv4 and
> IPv6**: IPv4 by allowlisted prefix, IPv6 by frame (`v6 on` +
> `v6-divert`, with the built-in DNS/BGP keeps, `steer-keep6`, the
> hand-back path and `loopback-address6`), customer delivery through
> `local-route` / `local-route6`, and `detach --keep-vpp` restarts that
> stay steered through the preserved route ledger. Its route feed is
> FRR over iBGP to the AnyIP listener, attested by
> `integrity-authority frr`.
>
> **What that does not settle.** MCAM rules have been observed
> surviving one UniFi provisioning push, on a lab box on one firmware;
> survival across firmware versions is untested. Nothing re-asserts
> wiped rules automatically: the 30 s readback audit (below) reports a
> wiped or altered rule as `steering DEGRADED`, and a plain `packetframe
> reconfigure` while `Steered` re-installs them. And a first attach
> still never steers: every port moves only when you move its lever,
> so a fresh box starts at rung 0 like the reference one did.
>
> **The MCAM ioctl path has now met a NIC, and it took several rounds.**
> First contact on 2026-08-05 found one real defect — the `loc` space
> sized from `npc/mcam_info` rather than from the driver — plus two
> self-inflicted ones chasing it: a `GRXCLSRLALL` that asked for more
> rules than existed, and a mask "correction" that inverted a field
> which had been right all along. Every one of them failed loudly, as
> designed: nothing was installed, and the all-or-nothing unwind left the
> port with zero rules each time. Everything past installation is proven
> too: steered frames counted on `octeon0/0` (2026-08-07), forwarded end
> to end through VPP's graph the same day, PMTUD answered correctly
> through a steered path, and — on the primary — ~500M packets forwarded
> in 27 minutes, split by best path across two upstreams with zero loop
> and no drops on the forwarding path. Every rule
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

- [Supported hardware](#supported-hardware)
- [Architecture at a glance](#architecture-at-a-glance)
- [Healthy state](#healthy-state)
- [Everyday inspection commands](#everyday-inspection-commands)
- [The canary ladder](#the-canary-ladder)
- [Rollback](#rollback)
- [The adopted-reconciliation release gate](#the-adopted-reconciliation-release-gate-what-it-needs-and-when-it-refuses)
- [What a keep-vpp restart costs now](#what-a-keep-vpp-restart-costs-now-the-preserved-route-ledger)
- [Rung 0 for IPv6: `v6 on`](#rung-0-for-ipv6-v6-on)
- [Bidirectional offload: local-route and direction dst](#bidirectional-offload-local-route-and-direction-dst)
- [v6-divert steering](#v6-divert-steering)
- [Triage by symptom](#triage-by-symptom)
- [Numbers: measured vs published-on-faith](#numbers-measured-vs-published-on-faith)
- [Install and upgrade on the router](#install-and-upgrade-on-the-router)
- [The kernel path for exempt traffic](#the-kernel-path-for-exempt-traffic)
- [IRQ affinity before attach](#irq-affinity-before-attach)
- [Constraints worth knowing before you debug](#constraints-worth-knowing-before-you-debug)

## Supported hardware

Marvell OCTEON NICs only: every `port` must be a PF on the `rvu_nicpf`
driver. Steering, VF handling and the VPP device driver (`octeon`) are
all specific to that NIC. The module README's
[Supported hardware](../../crates/modules/vpp-offload/README.md#supported-hardware)
lists how.

Attach checks each port's driver before it touches any NIC and refuses
the whole attach, naming every port that fails:

```text
eth2 is driven by `ixgbe`; br0 has no device driver behind it (…).
vpp-offload supports only Marvell OCTEON NICs (PF driver `rvu_nicpf`): …
```

`packetframe feasibility` gives the same verdict per port as
`vpp.<port>.driver`. On a port that fails it, `vpp.steering.budget`
reads `not planned`, because the rule table it would plan against is
not one this module programs. To see what a port is driven by:

```sh
readlink /sys/class/net/eth2/device/driver
```

On other hardware, remove the `module vpp-offload` section and run the
eBPF fast-path alone.

## Architecture at a glance

```text
 FRR/bird ─iBGP→ BgpListener ──RouteEvent──→ FibProgrammer ──→ BPF maps   (failover tier)
                NeighborResolver                  │
                                                  └─ResolvedRouteSink──→ RouteFeed
                                                                           │
                                                        vpp-offload engine ─┴─binary API─→ VPP FIB
                                                                                           + static neighbours
 eth4 PF ── MCAM steer (allowlist × {src,dst}) ──→ VF ──→ VPP workers ──→ VF tx (src MAC = MAC-PF)
    └─ everything else ──→ kernel path, eBPF fast-path in front
```

The routing daemon is FRR on the reference router (iBGP to the AnyIP
listener, `integrity-authority frr`); bird over loopback with the
`birdc` authority is the other supported pairing. Much of this runbook
was written on bird boxes, so where it says "bird's route count" read
"the completeness authority's": `birdc show route count` on a bird box,
`vtysh -c 'show bgp ipv4 unicast statistics'` (and `ipv6`) on an FRR
one — or just the `fib-integrity` row of `packetframe status`, which
shows the authority's figure beside the mirror's whichever it is.

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

**Neighbours are static, from the resolver — but VPP is not
ARP-silent.** MCAM rules match IP fields, so no ARP frame (0x0806) is
ever *steered* to VPP, and `v6-divert` matches TCP and UDP only, so no
ICMPv6 is either — see [v6-divert steering](#v6-divert-steering). That
is why VPP cannot learn or refresh a neighbour: the unicast answer to
anything it sends goes to a kernel-owned MAC and lands on the kernel.
It does NOT make VPP deaf or mute on ARP:

- **It receives broadcast ARP.** Each member VF keeps a promiscuous
  vote (see "A bridge-member port goes dark right after attach") and the
  NIC replicates broadcast to every function on the LMAC, so the
  bridge domain floods the segment's broadcast ARP to the BVI and on to
  VPP's `arp-reply` node. Nearly all of it is rejected there
  (`IP4 destination address not local to subnet` / `IP4 source address
  not local to subnet` in `show errors`).
- **It replies for its `loopback-address`, and only that.** The reply
  leaves from the receiving interface's MAC — the kernel bridge's, on a
  BVI. Every interface is unnumbered to the loopback, and VPP's
  `arp_unnumbered` skips the sender-subnet check for unnumbered
  interfaces, so it would answer on ANY bridged VLAN, IX VLANs included,
  if someone there asked. Hence the rule to pick a `loopback-address`
  nothing else uses (attach refuses a kernel-held one — "Hosts flap
  between two MACs for the gateway").
- **It sends ARP requests and neighbour solicitations (glean)** for
  unknown hosts inside a `local-route` / `local-route6` prefix, up to
  ~1000/s per address PER WORKER (so ~workers × 1000/s for one silent
  address in aggregate), past the `guard` policer. See
  [Glean and ARP counters](#glean-and-arp-counters).

**IPv6 neighbours are programmed only under `v6 on`.** With `v6 off`
(the default) VPP carries IPv4 routes only, so the resolver's IPv6
neighbours are neither programmed as static neighbours nor pinned in a
bridge domain's L2FIB, and the neighbour gauges
(`packetframe_vpp_neighbours_unplaced`, `packetframe_vpp_neighbours_flooded`,
`packetframe_vpp_neighbour_moves`) count v4 only. `show ip6 neighbors`
listing entries on such a VPP after adoption means an earlier build (or
an earlier `v6 on` run) programmed them; they are inert (no v6 route
references them) and deliberately left until the next VPP restart,
because deleting each one costs the same worker-barrier walk that
programming them did. A v6-only MAC an earlier build pinned in the
L2FIB is withdrawn once, at the next resync, as a stale entry. Under
`v6 on` both families are programmed — see
[Rung 0 for IPv6](#rung-0-for-ipv6-v6-on).

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
of them at all is the signal. The same goes for `fdb`, `exempt-drift`
and `exempt-drift-v6`, which appear only with findings, and
`icmp6-source`, which appears only while IPv6 is diverted with no
`loopback-address6`. The IPv6 offload adds two rows that are present
whenever their feature is: `fib-v6` under `v6 on`, and `v6-handback`
while the hand-back path is wanted or built — so the reference router,
steered for both families, shows seven.

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
| `packetframe_vpp_exempt_drift` | `> 0` — a kernel path VPP cannot take has no `steer-exempt`; steered traffic for it is (or will be) blackholed. ALSO alarm on `absent()` while attached: the gauge is omitted, never zeroed, when the scan cannot read the kernel |
| `packetframe_vpp_exempt_drift_v6` | `> 0` — an IPv6 kernel path VPP cannot take while a port carries `v6-divert`; diverted v6 for it is (or will be) blackholed. Present ONLY while some port carries `v6-divert` under `v6 on`, so alarm on `absent()` only on boxes configured that way: it is omitted, never zeroed, when the v6 scan cannot read. Counts only findings no `drift-accept6` covers |
| `packetframe_vpp_exempt_drift_v6_accepted` | not an alarm — v6 findings a `drift-accept6` covers (still blackholed if diverted). Present exactly when the series above is; a step up means a new route appeared under an accepted prefix |
| `packetframe_vpp_drift_scan_ms` | informational — wall time of the latest drift scan; absent until one finishes. A sustained rise means the kernel's tables grew or its routing lock is contended. See [The exemption tripwire](#the-exemption-tripwire-exempt-drift) |
| `packetframe_vpp_neighbours_unplaced` | `> 0` — a bridge neighbour the kernel FDB has not placed behind any member port; routes through it are unresolvable |
| `packetframe_vpp_neighbour_moves` | a step — spanning tree moved neighbours between trunks and VPP followed; worth correlating with switch events |
| `packetframe_vpp_kernel_path_dropping{port}` | `1` — a steered port's PF is dropping exempt traffic in the kernel's receive (`packetframe_vpp_kernel_rx_drops_per_second` at 100/s or more). See [the kernel path for exempt traffic](#the-kernel-path-for-exempt-traffic) |
| `packetframe_vpp_keep_rss{port}` | `0` is not an alarm by itself — that port's driver declined RSS keeps, so its exempt traffic lands on PF queue 0 (`packetframe_vpp_queue0_irq_cpu` says where that queue's IRQ was placed). Watch `packetframe_vpp_kernel_rx_fps{queue="0"}` against `{queue="all"}` on it |
| `packetframe_vpp_undead` | `1` — a killed VPP survived and blocks the restart |
| `packetframe_vpp_api_silent_seconds` | approaching the wedge budget (1.5 s steered). It can pass the budget without a teardown just after the supervision loop itself stalled, because that time is not counted ([why](#a-teardown-with-causewedged)) |
| `packetframe_vpp_glean_sent{family}` / `packetframe_vpp_glean_throttled{family}` | informational, never a health input — cumulative; watch the RATE. See [Glean and ARP counters](#glean-and-arp-counters) for normal vs a scan |
| `packetframe_vpp_arp_replies_sent` | informational — a step on a box whose `loopback-address` nobody should be asking for |

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
# Can a teardown identify the exemptions? (empty here = it cannot; see
# "A state file with no steer_plans leaves the exemptions behind")
jq '.steer_plans' /var/lib/packetframe/state/vpp-offload.json
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
# What is the VF absorbing? While VPP holds a member VF, the kernel
# PF's `rx_drops` legitimately freezes (w9/w10: the flood the kernel
# used to receive-and-drop diverts to the VF) — these counters are
# where it went. Worth reading before the first steer: flood absorbed
# by poll-mode workers is CPU the canary should account for.
vppctl -s /run/packetframe/vpp/api.sock.cli show interface
```

```bash
# The interfaces VPP created, and their link state.
vppctl -s /run/packetframe/vpp/api.sock.cli show interface
```

```bash
# Worker placement — one hot core per worker, permanently. See the heat note.
vppctl -s /run/packetframe/vpp/api.sock.cli show threads
```

```bash
# Which thread polls which queue: "Polling thread is N" under each port,
# where thread N is worker N-1 (thread 0 is main). Dedicated ports sit
# on their own workers in config order and the first `cores 0` port on
# the last, shared one. NOT `show interface rx-placement`: the octeon
# driver's queues belong to VPP's vnet_dev framework, which that command
# (and `sw_interface_set_rx_placement`) does not know about.
vppctl -s /run/packetframe/vpp/api.sock.cli show device
```

## The canary ladder

Traffic moves only when you say so. The module never steers on a first
attach, and a reconfigure that did not change a `steer` flag will not
either, so editing an unrelated line cannot divert traffic by accident.

**Choose `steer-direction` before the first rung, not during it.** On a
service edge — the reference fleet — the right value is `src`: outbound
traffic (src ∈ the service prefix, arriving from the agg switches)
rides VPP's full-table best path, and inbound stays on the eBPF tier,
whose FDB-pin owns delivery to the bridge-attached hosts VPP has no
path to. The default `both` is for pure transit, and dst-steering a
service prefix diverts inbound flows into a FIB that cannot deliver
them — every steered service flow would blackhole with all gauges
green. The directive is hot-reloadable (the target is a reconcile), so
getting it wrong is recoverable — but the recovery window is however
long it takes to notice.

**Declare `vlans` on every trunk port before it steers.** `src` being
the right direction does not make the port ready: on a trunk (a
bridge/switch0 member carrying tagged VLANs), steered ingress arrives
802.1Q-tagged, and a tagged frame with no matching dot1q subif in VPP
is punted at `ethernet-input` before any MAC, promisc or FIB logic —
the exact all-gauges-green blackhole described above, from the other
side. Measured on the primary (2026-08-14, w20): the first steer of
eth4 punted 8.7M frames in two minutes, zero forwarded. The `vlans`
list on the port line is what creates the subifs, it must name every
VID the steered prefixes ride (on the reference fleet, eth4 needs
`vlans 88,1337` — one per service bridge), and it is restart-only:
declare it before the attach, not at the rung.

**Give egress-only members `cores 0`.** Every VPP worker is a core
polling at 100% whether or not anything arrives, and at the first rung
only one port is steered: the other members only *transmit* (steered
traffic egresses them from the steered port's worker), and with no MCAM
rules their VFs receive ~nothing. `cores 0` gives a port no worker of
its own — ONE shared worker is added for all of them — so a six-port
box at rung 1 runs three VPP threads (main + the steered port's worker
+ the shared worker) instead of seven:

```
  port eth2 cores 0 steer off
  port eth3 cores 1 steer on     # the canary: its own worker
  port eth4 cores 0 steer off
```

A `cores 0` port cannot be steered: load and `packetframe reconfigure`
both refuse `cores 0` + `steer on`, because its whole ingress would
land on a worker shared with every other egress-only member. Before a
port climbs a rung, give it `cores 1` — and that is **restart-only**
(VPP's worker count is fixed at start), so plan the core layout for
the next rung at a restart, not at the rung itself.

Placement comes from creation order, not from a setting. VPP's octeon
driver hands rx queues to workers round-robin as ports are created and
offers no way to move them afterwards (`sw_interface_set_rx_placement`
answers "unknown queue" for every octeon port). So the module creates
dedicated ports first, in config order, and the `cores 0` ports last:
the dedicated ports get consecutive workers from 0 and the first
`cores 0` port gets the shared worker. A second `cores 0` port's queue
wraps onto worker 0, a third onto worker 1, and so on. That's harmless,
since those queues receive ~nothing, but it is not "all on one worker".
The attach log prints the resulting placement (`rx placement (VPP
round-robin, creation order)`); check it with `show device` below.

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

Decide `require-table-complete` first — **it is restart-only**, so
getting it wrong here costs a daemon restart rather than a reload;
`reconfigure` refuses a changed value by name. On a box with a
completeness authority — its own bird (`integrity-authority birdc`, the
default) or FRR (`integrity-authority frr`, as on the reference router)
— leave it `on` (the default); the first steer then waits until the
authority attests the route mirror. With `integrity-authority none`
attach refuses to start with `on`, because the check could never pass.
Set it `off` there and compare the counts yourself before turning a
lever: `packetframe status` reports how many routes are installed, and
the routing daemon on the box that feeds the mirror says how many there
should be.

```bash
packetframe reconfigure
```

Wait for `fib-synced healthy` and for
`packetframe_vpp_routes{state="unresolvable"}` to read 0. Soak here for
at least an hour, and through a udapi provision cycle if one is due.
Nothing is diverted in this state: VPP is up, its FIB is synced and
verified, and every packet is still on the XDP path.

**Verify that last sentence rather than assuming it.** Rung 0's whole
value is that traffic is untouched, and w22 (2026-08-14) showed the
assumption can be false while every gauge agrees with it: a member's
primary MAC pointed at the bridge's address, so the VF's *hardware*
filter captured ~300 kpps of gateway traffic from attach onward, with
no MCAM rule and the lever off. Check it explicitly, a minute after
attach and again before the first steer:

```bash
vppctl -s /run/packetframe/vpp/api.sock.cli show interface | grep -A4 octeon
```

Every member's `rx packets` should be in the low thousands at most —
broadcast and multicast noise. Anything climbing at traffic rate means
the port is receiving frames nothing steered: **stop, do not proceed
up the ladder**, and treat it as an incident — that traffic is
traversing a FIB that may still be converging, and any VLAN on the
port that is not declared in `vlans` is being blackholed. `detach
--all` restores it immediately.

**Schedule this rung off-peak.** Rung 0 is the maximum-cost state: all
of VPP's poll-mode CPU tax with zero forwarding benefit, and at traffic
peak that tax has caused real user-visible loss on the kernel path (see
the coexistence-squeeze section). Plan the rung-0 soak and the first
steer inside one quiet window rather than soaking unsteered through a
peak.

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

"Withdrawn" is the answer when the supervision loop does not pick the
request up within 3 s: a tick mid-convergence can take longer than
that. It applies only to a reload that asks the loop for something. A
reload that changes no steering input — an edit to fast-path's
`dry-run`, say, with `allow-prefix` untouched — is applied unchanged,
without the loop, in every state (converging, adopted resync, backoff
or converged), unless re-sending would do something there: from `Ready`
with a remembered want (the "ask now" retry), from `Steered` (the
repair below), or with every port off while something is still steered
or wanted and a VPP is running to take it off (the rollback's retry).
Before 2026-09-27 a reload during an adopted resync after a keep-VPP
restart also went to the loop — the steered adoption records a want —
and a fast-path `dry-run` flip came back *"vpp-offload is
AdoptedResyncing, not converged"*, exit 2, `reconfigure_failed` for a
module whose configuration had not changed. When a loop pass is running
as the reload arrives — nearly always, during an adopted resync — the
module cannot tell whether that pass has just reached `Ready` with a
want, where the reload is the "ask now" retry. It answers OK anyway and
also posts the unchanged request without waiting for it: if a retry is
due it happens at once, and if the loop is still converging it refuses
the request unseen. After any failed request
the module no longer knows which target the loop holds, so the next
reload goes to the loop whatever it changes. The ones that reach the
loop can still be refused or withdrawn; re-run once `packetframe
status` shows the convergence finished.

**A module failure does not roll the reload back.** The daemon
publishes the allowlist and reconfigures every module in config order,
recording failures and carrying on, so every module the error does not
name is running the new config. `packetframe reconfigure` says so
("every other module applied it, and nothing was rolled back") and
exits 2. A fast-path edit alongside a withdrawn vpp-offload change is
live; re-running the same config re-applies every module, which
changes nothing for the ones that already landed.

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

A successful steer also has a host-side signature worth confirming:
the steered flows leave generic XDP, so the rate of
`packetframe_softnet_time_squeeze_total` should fall (or at worst
hold) as traffic moves — it must never rise on a steer. VPP's own
interface counters (`show interface` via the CLI socket) turning over
at line rate on the member VF is the positive half of the same check.

**Declare `steer-exempt` for every locally-terminating address before
any steer that outlives a short canary.** A `src` steer diverts by
source alone, so traffic from the service prefix **to the router
itself** — the box's own monitoring replies, unicast DHCP renewals,
management SSH from the service net — is diverted into a dataplane
with no local delivery and dies at `null-node` while every gauge stays
green. Measured on the primary (2026-08-14, w23): 110,917 packets in
five steered minutes, plus 3,200 multicast frames (IGMP among them)
RPF-dropped away from the kernel bridge's snooping. The exemptions are
higher-priority MCAM rules that deliver matches to the kernel instead:
broadcast and multicast are built in; each gateway IP of a steered
VLAN needs a `steer-exempt` line.

Every diversion is also scoped to the **destination MAC** the router
receives on for that port: on a bridge member, the bridge's MAC plus
any distinct MAC of an L3 device (the `brX`, never the enslaved VLAN
device under it) on a VLAN the port carries — the MACs VPP's BVIs
carry; on a plain port, the port's own MAC only, since VPP's subif
accepts no other (a VLAN device there with a MAC of its own stays on the
kernel path). A bridge member hands the NIC every frame on the
segment, including frames the kernel is only bridging between two hosts
on one VLAN behind different trunks; an IP-only rule would divert those
into VPP, whose split-horizon group drops them. With the MAC scope they
never match and the kernel bridges them as before. On UniFi every bridge
shares switch0's MAC, so this costs no extra rules; a box whose VLAN
bridges carry different MACs gets one copy of each diversion per MAC.
`ethtool -n <port>` shows the scope as `Dest MAC addr` on each divert
rule. A port whose MACs cannot be read — including an unreadable
`/proc/net/vlan/config` — is refused rather than steered with a partial
or empty scope, and `packetframe feasibility` plans with the same MACs.

Budget math per steered port: (steerable v4 prefixes × directions ×
receive MACs) diversions + 2 built-ins + your `steer-exempt` entries must
fit the port's table — 16 slots by default
on this hardware, more with `steer-capacity` (see "Raising the rule
budget" under "Constraints worth knowing before you debug"). A
re-plan over ports that are already steered — a daemon restart that
adopts a steered VPP, or a reload steering one more port — counts the
module's own installed rules as free, provided the state file records
them and the NIC still holds them; an unchanged plan lands on exactly
the slots it already occupies. The refusal message
itemises exactly this. While steered, `ethtool -n <port>` shows the
exemptions at the LOW locations and the diversions at the high ones —
lower location is higher MCAM priority, which is what makes an
exemption win.

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

"At any time" includes **while a convergence or an adopted deferral is
in flight**, which is the case that matters: a deferral can hold
indefinitely, and it holds with the traffic on VPP. A full `steer off`
is admitted there and does not disturb the convergence; a steer is
still refused until it lands. See the deferral section for the limits
(all-ports-off only, and what a refused removal leaves behind).

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
(`ethtool -N <iface> delete <loc>`) and re-run. A state file it cannot
vouch for (another account could have written it, or it is past the
size bound) is refused before anything is touched; see
[Attach or `detach` refuses](#attach-or-detach-refuses-refusing-vpp-offloadjson-).

It reads each recorded location back before deleting it, and a location
the NIC will not describe counts as a refusal — the same message, and
the same remedy. That is deliberate: a slot the record names can hold
somebody else's rule by now, and on a NIC that will not answer, "do not
delete a stranger's rule" and "do not unbind a VF that may still be
steered into" point the same way.

### A state file with no `steer_plans` leaves the exemptions behind

A diversion identifies itself from the NIC: its `ring_cookie` names our
VF. An exemption does not — `Keep` rules carry cookie 0, meaning
"deliver to the PF", which is what any other classifier rule aimed at
the kernel also says. So a teardown claims a cookie-zero rule only by
matching it against the exemption its own recorded plan put at that
slot, and the state file carries that plan in `steer_plans`.

A file written by a build older than that field has the locations and
nothing else. The teardown still removes the diversions and still
reports honestly, but it **logs a warning naming the locations and
leaves the exemptions in the MCAM** — it cannot tell them from a
stranger's rule, and deleting on a guess is how a teardown breaks
traffic this module never claimed. That warning is the only record: the
locations are dropped from the ledger at the same time, so the state
file written afterwards will not name them either.

If you see it, check the NIC directly and clear what remains:

```bash
ethtool -n eth5
```

```bash
ethtool -N eth5 delete <loc>
```

Only reachable on the first teardown after upgrading a **steered** box.
Once a steer has run under a build that writes `steer_plans`, the record
is complete.

## The adopted-reconciliation release gate: what it needs, and when it refuses

A restart over a steered VPP defers its reconciliation (the FIB dump
freezes every VPP worker — `ip_route_dump` is not mp-safe — so it only
runs against an unsteered VPP; a restart whose previous daemon left a
preserved route ledger skips the dump and the unsteer entirely, and only
its diff waits here — see the next section). The deferral releases
through exactly
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

### The unsteered diff and a seeded mirror

Everything above is the STEERED stages' release. An UNSTEERED adoption
— its dump already ran, harmlessly, because nothing is on VPP — defers
only its diff, behind the floor (half the adopted table) and the same
stream-quiet rule: a reannouncement holds it loud until the stream
ends. That still applies to every mirror that loaded from empty.

When the fast-path seeded the mirror from its [route
ledger](packetframe-fib.md#restarts-the-route-ledger), the diff has a
second door, and it does not wait for the replay to go quiet. It opens
when **all** of these hold:

- the mirror holds a seed no route-source GC has reconciled yet (the
  fast-path marks the feed session when it hands the seed over);
- the feed session is up, and it is still the FIRST session of this
  process — the route source is streaming now and has not dropped and
  reconnected since;
- the completeness authority's current word is yes: its last report
  permits steering and its count is within 1% of the mirror as it is now
  (the fast-path authorities never attest a seed before the route
  source's first route, so in the first session this also proves the
  report was taken while that stream was live);
- the floor.

**A reconnect shuts this door for good.** After it, a cached yes may
predate the new stream, and a newer one proves no more than it does
for the steered stages after a flap (above): counts over a mirror
being re-announced stay aligned whether or not the new stream has
caught up. The replay then has to go quiet, as for any mirror; the
first GC would end the seed anyway.

Whichever door opens, the resync walk drops the route deltas the feed
queued before it (the seed queued one per route) — the walk reads every
route's current state and the diff derives the withdrawals — so VPP is
sent only what differs from what it holds, not the seeded table again.
Changes written after the walk began stay queued and follow as
ordinary updates.

Why that is safe where quiet is not needed: the diff withdraws from VPP
whatever the mirror lacks, so the danger is a mirror still filling from
empty — "~all withdrawals". A seed is the previous process's whole
table, present before the route source connected, and the authority's
agreement rules out a seed that is substantially short of what the
source has now. What the seed has that the source dropped leaves VPP
when the route source's GC withdraws it; what changed reaches VPP as the
replay re-advertises it — the same as on the eBPF tier, which forwards
on the same seed. VPP carries no traffic at this stage either way. With
`require-table-complete off` there is no authority to vouch for the
seed, and only the quiet door exists.

The journal says which door opened: `the route mirror was seeded from
the fast-path route ledger, the route source is streaming and the
completeness authority agrees with it: running the adopted resync diff
now ...`. Verify follows, and then the port is `Ready`. **It does not
steer on its own**: an adoption that was unsteered keeps the canary rule,
so the first steer is still a `steer` flag you move — after `Ready`; a
move while still converging is refused as before.

## What a keep-vpp restart costs now: the preserved route ledger

**The incident this answers (primary, 2026-09-26, ~1.09M v4 routes).**
`systemctl stop packetframe && packetframe detach --keep-vpp &&
systemctl start packetframe` over a steered VPP cost ~13 minutes
UNSTEERED, a teardown and a full reload — for a restart that kept a
verified, forwarding VPP. The new daemon had no idea what VPP held, so
it had to read VPP's FIB, and reading it (`ip_route_dump`) parks every
VPP worker, so it had to unsteer first onto an eBPF tier whose mirror
restarts empty. Then the feed churned during the ~3 minute dump, the
diff was held, and the phase deadline — extended from the start of that
blocking dump rather than its end — fired `PhaseTimedOut` the next tick
and tore VPP down.

**Now a clean stop leaves the ledger for the next start.** When the
daemon exits the preserving way (SIGTERM / `systemctl stop`: the
loader calls `Module::exit_preserving` just before dropping the modules,
and vpp-offload's loop ends WITHOUT the teardown), the loop writes
`<state-dir>/vpp-route-ledger.bin` after its last tick: every installed
prefix with the exact paths VPP acknowledged it through — nexthop,
interface, and every forwarding attribute (weight, preference, type,
flags, labels) — VPP's own per-prefix-length route counts (`show ip fib
summary`), the VPP process identity (pid, start ticks, boot id) and a
fresh token that is also written into `vpp-offload.json`. Compact binary
with a trailing checksum: ~10 bytes a route, ~11 MB at 1.1M, written
through the same no-follow `openat`/`renameat` primitives as every other
state record. The journal says which it was:

```
preserved VPP's route ledger for the next daemon: a `--keep-vpp` start adopts it
  without reading VPP's FIB, and steering stays up across the restart   routes=1090312
# or, with the reason:
VPP's route ledger was not preserved; the next adoption reads VPP's FIB instead ...
```

It is only written for a ledger this daemon can vouch for: the
supervisor `Ready`/`Steered` (or a previous ledger-seeded adoption still
waiting on the feed, untouched), nothing awaiting VPP's acknowledgement,
and VPP's summary readable. A stop during a dump-path deferral, a crash,
a `kill -9`, or anything that is not a clean preserving exit writes
nothing — and "nothing" is simply the dump path below. So does a bare
drop of the supervision service: it cannot tell a process exit from an
accidental drop, so it keeps supervising VPP and preserves nothing.
The stopping daemon also waits at most **5 s** for the loop to finish
writing it: a supervision loop that is slow or wedged at stop is left
behind when the process exits, and if the record was not yet renamed
into place the next start takes the dump path too. That timeout is
diagnosed from the **journal** only — the warning `the supervision loop
did not finish preserving the route ledger in time` — because the loop
that would have recorded `ledger_preserved` never got that far, so the
event log may hold no stop-side event for it at all.

Which path a restart took is in the [event log](event-log.md#event-kinds)
as well as the journal: `ledger_preserved` at the stop when the loop
reached the preserve step (`preserved` true or false, with the reason
when false), `adoption_path` at the start (`path=preserved-ledger`, or
`readback` / `readback-deferred` for the dump path — this one records
the fallback whatever happened at the stop), and
`preserved_ledger_rejected` with the stage and reason when a record was
found but not used.

**The start that finds it** adopts WITHOUT reading VPP's FIB and without
unsteering, in this order:

1. At bring-up, before anything touches VPP, the record is read and
   **removed** — whether or not it is used, so it is consumed once. It
   must name the adopted process (pid + start ticks + boot id), carry the
   token `vpp-offload.json` holds (any other adopter rewrites that file on
   its attach, and an older build drops the field, so a record that
   outlived a downgrade or a second adopter cannot match), and list the
   same interfaces.
2. At `StartResync`, VPP's per-length route counts must equal the
   recorded ones — anything that added or removed a route since (a
   `vppctl` edit, a stray client) shows up here. Then the engine's ledger
   is seeded from the record.
3. The resync diff waits behind the same loaded-and-quiet release the
   dump path uses (feed live, floor = half the seeded table, quiet 2 s
   with a completeness authority / 5 s without), **steered the whole
   time**. At the release VPP's route counts are read AGAIN — the wait
   can be minutes, and a route another client adds or removes in it is
   one the seed knows nothing about — and a change discards the seed for
   the dump path. Then the diff pushes only the differences: a route VPP
   holds through exactly the paths it resolves to now is not sent.
4. Verify runs its 64 probes with the **paths compared** too, still
   steered. Pass → `Ready` → the usual re-assert steer.

**The fast-path tier has its own ledger now.** The same clean stop
leaves the route mirror for the next start (see [the route
ledger](packetframe-fib.md#restarts-the-route-ledger)), so the mirror is
at full size seconds after the start instead of after the route
source's replay: the release floor is met at once, and the
completeness authority attests the seeded mirror at the route source's
first route. The diff described here still waits for the replay to go
quiet — "quiet" counts every streamed element — so a steered adoption
behaves as before. What changes is an UNSTEERED VPP: a fresh one's
convergence hold releases on that first attested check, and an adopted
one's diff takes the seeded-mirror door ([the unsteered diff and a
seeded mirror](#the-unsteered-diff-and-a-seeded-mirror)).

What you see: `fib-synced DEGRADED — resync deferred ... the adopted FIB
keeps forwarding untouched` while the feed reloads (on the primary the
iBGP refill is ~2 minutes), then briefly `resyncing the FIB the previous
process verified and preserved (N routes installed) ...` while the diff
lands, then healthy. `packetframe_vpp_state` stays at
`adopted_resyncing` → `verifying` → `ready`/`steered` with steering never
dropping. **Measured cost of a keep-vpp restart: zero unsteered time and
no dump.** First measured on the reference router on 2026-09-27 with a
~1.09M-route table, and repeated since with IPv4 + IPv6 (~1.34M routes)
and the hand-back path in place: the new daemon adopted VPP's FIB from
the preserved ledger without a dump, and an external probe through VPP
lost 1 of 420 packets across the restart — that one to fast-path's link
bounce, not to VPP. The fallback below (no preserved ledger: the stopping
daemon did not write one, or predates it) measured ~3 minutes
unsteered.

**Every fallback is today's dump path, never a failed attach.** Each is
logged with its reason (`preserved route ledger not used: ...` /
`this adoption reads VPP's FIB instead`):

| Why | When it is caught |
|---|---|
| No record (unclean stop, crash, first start after upgrading, stop mid-convergence) | bring-up |
| Record names a different pid / start time / boot | bring-up |
| Token missing or different (another daemon adopted since, or a downgrade rewrote the state file) | bring-up |
| Corrupt, truncated, planted symlink, or another format version | bring-up (the file is still removed) |
| Interfaces differ from the state file's, or a recorded path egresses an interface this attach does not own | bring-up / seed |
| VPP's route counts differ from the recorded ones, or the summary cannot be read | `StartResync`, and again when the deferred diff is released |
| **Verify disagrees** (a prefix absent, or held through other paths) | the seeded verify |

The last one is `PreservedLedgerRejected`, deliberately not
`VerifyFailed`: it disproves the RECORD, not VPP, so it is not a
teardown. Steering comes off first (the seed traffic was on is now known
wrong, and the eBPF tier is loaded — the seeded diff only ran after the
release), the seed is discarded, and the resync starts over on the same
VPP from a dump. A mismatch on THAT pass is an ordinary `VerifyFailed`.

**The dump path itself changed too.**

- *A dump the feed spoiled is kept.* The journal line is now `the feed
  changed while VPP's FIB was being dumped; the dump is KEPT ...`.
  Nothing changes VPP's FIB while the diff waits (no deltas are applied
  during a deferral, and a restore touches only MCAM), so the retry is a
  diff against the FIB already read: no second dump, and a dump that is
  never re-taken cannot be spoiled twice. The quiet the next release
  needs doubles per spoil (capped at 30 s): the quiet that released the
  spoiled attempt was a lull.
- *Traffic stays on the eBPF tier while the feed is merely busy.*
  Traffic goes back onto the adopted VPP (`FallbackRevoked`) only when
  the fallback is UNFIT — feed down, the authority saying no, or the
  mirror under the floor or collapsed to under half of what it held at
  the unsteer. A live, loaded feed that is churning is the better tier:
  it tracks the mirror, while the adopted FIB is frozen at adoption.
  (Before, any non-release re-steered, flapping MCAM on every burst.)
- *A busy feed never tears VPP down.* A deferral that is still
  deliberately waiting extends the phase deadline from when the drain
  RETURNED, not from when the tick began — a 3-minute dump can no longer
  put the deadline behind the clock.
- *The convergence deadline scales with the table.* The flat 120 s
  became `max(120 s, 2 × (routes ÷ 4000/s, or the slowest dump actually
  observed here))`, capped at 600 s — ~9 minutes for 1.1M routes. It
  bounds the gap between progress signals, so it only bites a genuinely
  stuck step (an interruption that never resolves), and it is widened
  in place the moment a larger budget is known (an adoption's deadline
  is armed before anything has measured the table). The wedge detector's
  liveness budget — is VPP answering — is unchanged.

## Rung 0 for IPv6: `v6 on`

Phase A of the IPv6 offload steers customer IPv6 — frames addressed to
the router's MAC on a VLAN the operator names — into VPP, which routes
them out the transit/IX ports (and, on transit/IX ports, the reverse). That needs VPP to carry the v6
table correctly first. `v6 on` is that and only that: **it steers no
IPv6**. It exists so the v6 table's cost can be measured, and its
correctness verified, while every v6 packet still rides the eBPF tier.

### What it does

- VPP carries **IPv6 routes and static neighbours** as well as IPv4
  (`FamilyPolicy::Both`). The resync, the deltas, the adoption dump,
  the preserved ledger, the neighbour dump and the L2FIB placement of
  bridged neighbours all cover both families.
- **ip6 is enabled on every VPP interface the module owns** — member
  VFs, dot1q subifs and BVIs — so a v6 route or adjacency has an ip6
  rewrite to leave by. Each gets only its EUI-64 **link-local**; no
  global v6 address is added anywhere. The link-local equals the
  kernel's for the same MAC (a VF carries its PF's MAC, a BVI the
  bridge's), with no DAD — harmless, because no ICMPv6 is ever steered
  to VPP (not at rung 0, and not under `v6-divert`, which takes TCP
  and UDP only), so nothing solicits it and the kernel keeps answering
  for the address on the wire. Enabling is idempotent (a re-enable answers
  `VALUE_EXIST`), so an adopted VPP is simply asked again.
- **Router advertisements are suppressed** on each of those interfaces
  (`sw_interface_ip6nd_ra_config suppress`). VPP 26.06 sends none by
  default; the suppression is there so a future default cannot make
  hosts on an IX or service VLAN adopt VPP as their router. It also
  makes VPP refuse router solicitations
  (`ROUTER_SOLICITATION_RADV_NOT_CONFIG` in `show errors`).
- **MLD: one report per interface as it comes up**, from its own MAC,
  for groups the kernel already joins on the same port — there is no
  API to stop it short of disabling ip6, and nothing moves because of
  it. The solicited-node MAC it adds is a secondary address, which the
  octeon driver never programs into hardware.
- **Capacity: one pool per family.** The heap and stats segment grow by
  a fixed v6 budget of **400,000 routes** on top of what
  `expected-routes` sizes, at deliberately conservative per-route costs
  that are **UNMEASURED** (2,048 B heap, 192 B stats segment per VPP
  thread). The route ledger enforces the same split: a v6 route can only
  take a v6 slot, so the v6 table can never withhold a v4 route, and the
  v4 ceiling is exactly what it is under `v6 off`.
- **Every existing gate and gauge keeps meaning IPv4.** The first-steer
  refusal, verify's pass criteria, the empty-table alarms and
  `packetframe_vpp_routes` read v4 counts only — steering diverts v4,
  so whether v4 may be diverted depends on the v4 table. IPv6 is
  reported beside it and gates nothing.

### What to set

1. In `module vpp-offload`, add `v6 on`.
2. Check the sizing before anything restarts:
   `packetframe feasibility --config /etc/packetframe/packetframe.conf`.
   If `hugepages` is set, the startup check names the new minimum
   (`hugepages N ... below the minimum derived from expected-routes`) —
   the v6 allowance adds 400,000 × 2,048 B ≈ 781 MiB of main heap, and
   400,000 × 192 B × (workers + 1) of stats segment (≈ 439 MiB at five
   workers; locked RAM, not hugepages). Raise `hugepages` to the named
   figure.
3. `v6` is restart-only, and **a VPP attached under the other setting is
   not adopted** (its segments and its FIB's families were fixed at
   start), so this is a full restart, not `--keep-vpp`:

   ```sh
   systemctl stop packetframe
   packetframe detach --all
   systemctl start packetframe
   ```

   A reload (`packetframe reconfigure`) refuses the change by name, and
   a `--keep-vpp` start refuses the adoption, naming `v6` (`- → on`).

### What healthy looks like

```sh
packetframe status
#   fib-synced   healthy   N routes installed; last verified on 64 probes   <- IPv4, as before
#   fib-v6       healthy   M IPv6 routes loaded in VPP, not steered
#   steering     ...       (IPv6 routes are loaded in VPP by `v6 on`, but no IPv6 is steered ...)

grep packetframe_vpp_family_routes /var/lib/node_exporter/textfile/packetframe.prom
#   ..._family_routes{module="vpp-offload",family="ipv6",state="installed"} M
#   ..._family_routes{module="vpp-offload",family="ipv6",state="unresolvable"} 0
#   ..._family_routes{module="vpp-offload",family="ipv6",state="withheld"} 0

journalctl -u packetframe | grep 'verify PASS'
#   verify PASS: 64/64 probes matched, unresolvable=0, withheld=0; IPv6 (loaded,
#   not steered — cannot fail the pass): 64/64 probes matched, unresolvable=0, withheld=0

vppctl -s /run/packetframe/vpp/api.sock.cli show ip6 interface          # every member/subif/BVI: link-local only, no global address
vppctl -s /run/packetframe/vpp/api.sock.cli show ip6 fib summary        # the v6 table, ~the fib-v6 installed count
vppctl -s /run/packetframe/vpp/api.sock.cli show ip6 neighbors          # the static v6 neighbours
vppctl -s /run/packetframe/vpp/api.sock.cli show errors | grep -i solicitation   # RADV_NOT_CONFIG counting = RSes refused
```

Also confirm nothing moved for the kernel, since VPP now shares its
link-locals:

- the rung-0 leak check ("Verify that last sentence", in the canary
  ladder: every member's `rx packets` in the low thousands with the
  lever off) reads as it did under `v6 off`;
- from a peer on each VLAN, the router's link-local still answers
  (`ping -6 fe80::<router>%<if>`), and no host has gained a default
  route via VPP (`ip -6 route show default` / `rdisc6 <if>` on a host
  shows only the router's own RAs, if any).

Degraded `fib-v6` names every condition that holds, each with its own
`packetframe_vpp_family_routes{family="ipv6",state=…}` gauge. None of
them affects IPv4 or its steering, none is restart-worthy, and nothing
v6 is dropped — none of it is steered:

| Condition (`state=`) | Meaning | What to do |
|---|---|---|
| `withheld` | the v6 table outgrew its 400k budget | sizing; raise the budget in `startup_conf.rs` once rung 0 has measured |
| `unresolvable` | a v6 next hop VPP has no adjacency for (a neighbour on a port VPP does not own, or one the kernel never resolved) | as for v4: `ip -6 neigh`, the port list |
| `rejected` | VPP refused the route (non-zero `ip_route_add_del`). Parked, not retried every drain — a v6 retry loop would keep the drain from going idle and hold back IPv4's convergence. Retried when the route next changes, and at every resync | the journal's retval; a VPP-side limit or bug |
| `link_local_refused` | every next hop is link-local. Scoped addresses reach the module without their interface (the feed, and the fast path upstream of it, key neighbours by address alone, and the same `fe80::` can be on two links), so VPP is never given one. A route that also names a global next hop installs through that alone | expected for peers announcing link-local-only next hops; the follow-up is carrying `(address, ifindex)` end to end |
| `verify_mismatch` | the last verify's v6 probes found VPP disagreeing with the ledger. Retained until the next verify (which does not re-run in steady state) | `vppctl … show ip6 fib <prefix>` against the ledger; a restart re-derives the v6 table |
| `dark_egress` | a member with no link carries v6 adjacencies. IPv4's link gate counts only interfaces IPv4 routes use, so a dark port with only v6 on it never refuses a v4 steer | the cable / the port, as for any dark member |

### What to measure (the numbers rung 0 exists for)

Take a baseline on the same box under `v6 off` with the full table
loaded, then again under `v6 on` once `fib-v6` is healthy:

```sh
vppctl -s /run/packetframe/vpp/api.sock.cli show memory                  # ALL heaps — never main-heap alone (spike runbook, gate 0b)
#   main heap:      "used" — Δ ÷ fib-v6 installed = heap bytes per v6 route
#   stats segment:  "populated" (not "used") — Δ ÷ fib-v6 installed ÷ (workers + 1)
#                   = stats-segment bytes per v6 route per thread
time vppctl -s /run/packetframe/vpp/api.sock.cli show ip6 fib summary    # this walks the v6 table under VPP's worker barrier;
time vppctl -s /run/packetframe/vpp/api.sock.cli show ip fib summary     # v4's is O(1) per length — compare the two
```

Write the per-route figures into "Numbers: measured vs
published-on-faith", and replace `HEAP_BYTES_PER_V6_ROUTE` /
`STATSEG_BYTES_PER_V6_ROUTE_PER_THREAD` in `startup_conf.rs` with ~2×
the measured values, the way gate 0b replaced the v4 guesses. The
`show ip6 fib summary` time matters because the preserved ledger reads
it (at a preserving stop, at adoption and again at the deferred
release, the last two with steered v4 traffic on VPP): if it holds the
barrier for more than a few milliseconds, that is a per-restart pause
the phase-A rungs must account for.

### Rolling back

`v6 off`, then the same full restart (`systemctl stop packetframe &&
packetframe detach --all && systemctl start packetframe`). The new VPP
starts with no v6 anywhere; `hugepages` can come back down.

## Bidirectional offload: local-route and direction dst

The pieces that carry the offload from `steer-direction src` staging
to both directions. Three config facts, then the surfaces that watch
them.

### local-route: VPP delivers a prefix instead of forwarding it

```
module vpp-offload
  port eth4 cores 1 steer on vlans 88,1337
  local-route 192.0.2.0/24 port eth4 vlan 1337
```

One line does three things at attach:

1. **An attached route** for the prefix onto the VLAN's BVI when it is
   bridged (the BVI of the port's own bridge — a second bridge reusing
   the vid gets none), else the port's VF if the port sends the VLAN
   untagged, else its dot1q subif — `show ip fib 192.0.2.0/24` shows
   that adjacency, not a drop. Installed outside the route ledger
   (module-owned topology, like the loopback), so resyncs never
   withdraw it. The choice is re-made while VPP runs: a BVI built after
   attach (the router had no L3 device on the VLAN yet), or a VLAN that
   turns untagged or tagged on the port, moves the route within seconds
   in one replacing route update (`attached route moved` in the
   journal, with both interface indices). A move VPP refused or never
   answered is re-sent on the next placement pass.
2. **The neighbour mirror**: kernel neighbours on the backing bridge
   (the `via` of the covering fast-path `local-prefix`) become VPP
   static neighbours, each on the subif of the member port the bridge
   FDB learned that host behind (see "Bridge neighbours" below), so
   hosts split across two trunks are all reachable; `port` names only
   where the attached route sits. A host VPP holds no neighbour for
   is **gleaned**: the packet is dropped (where the kernel would
   ARP-queue it) and `ip4-glean` broadcasts an ARP request, sourced
   from `loopback-address` (the attached path has no connected prefix
   to source from) and the BVI's MAC — the bridge's. The host's
   unicast reply therefore lands on the kernel bridge; with neigh-snoop
   watching the bridge (`bridge` + `prefix` for this prefix) it is
   learned, installed, registered by fast-path's `local-prefix`, and
   comes back as a static neighbour, like the IPv6 path below. Without
   neigh-snoop there the reply is discarded and VPP keeps gleaning on
   every packet to that host; ping it from the router once and the
   kernel's own entry feeds the mirror. Rate, cost and counters:
   [Glean and ARP counters](#glean-and-arp-counters).
3. **Shadowing**: mirror routes INSIDE the prefix are skipped, at
   resync and in deltas. The kernel tier delivers to bridge hosts
   before its FIB lookup, so bird's view inside a local prefix (the
   reference primary carries a service host route as `unreachable`)
   describes what bird would do, not what the box does.
   `packetframe_vpp_shadowed_routes` counts what is currently
   suppressed — on the reference primary the expected value is
   exactly its poisoned host route, and a JUMP in it is a mirror
   change worth reading about.

#### Kernel-delivered routes: the router's own, never unresolvable

Separately from `local-route`, routes that are the router's own business
are left out of VPP and counted as **kernel-delivered**, not as
unresolvable. A routing daemon feeding packetframe over iBGP sends what
it originates (`redistribute connected` and `redistribute static` above
all) with its own session address as NEXT_HOP. VPP has no adjacency for
the router itself, so it could only ever count those routes unresolvable,
which blocks the first steer and keeps `fib-synced` Degraded for good.

A route is kernel-delivered in exactly three shapes, each proven from the
router's own state:

1. **A connected subnet via the router itself.** Every next hop is one
   of the router's addresses, and the prefix lies inside a subnet the
   router is addressed on.
2. **One of the router's own addresses.** The prefix is a `/32` or
   `/128` the kernel holds on any device (a dummy or honeypot device, a
   loopback), and no next hop reaches VPP. The kernel's local table
   delivers these ahead of anything in `main`. A host route VPP *can*
   carry through a member port is never touched.
3. **An IPv4 route via the router that the kernel carries elsewhere.**
   Every next hop is one of the router's addresses, and the kernel's own
   FIB entry for exactly that prefix (`ip route get` with `fibmatch`
   semantics) either delivers it locally or leaves only through devices
   VPP cannot reach: not a member port, not a VLAN of one, not a bridge
   a member port is enslaved to, not a `local-route` device. A static
   `/32` via a tunnel is the usual case. Each walk asks the kernel at
   most 1,024 times per resync and 64 per delta batch. It spends at most
   150 ms on the asking in total, and stops at the first lookup the
   kernel fails to answer; the routes it then never asked about stay
   unresolvable, named with why.

IPv6 takes shapes 1 and 2 only. A `v6-divert` rule takes TCP and UDP to
the router's MAC whatever the destination, there is no v6 `steer-exempt`,
and the hand-back path returns only the router's own `/128`s (every global
address, which is why shape 2 is safe for v6). A v6 prefix the kernel
carries out a tunnel would be diverted traffic dropped in VPP, so it stays
unresolvable on `fib-v6`, with a name that says so.

The next hop alone is never enough. Under `next-hop-self` every transit
route carries the router's address; the kernel sends those out member
ports, so shape 3 refuses them and they stay unresolvable (loud, and
blocking the first steer). A kernel entry for a different prefix, a
blackhole or unreachable route, or an unreadable kernel also leaves a
route unresolvable. The router's addresses are read at attach; the kernel
lookup runs when the route is classified.

`packetframe_vpp_kernel_delivered_routes` counts them, and the
`fib-synced` row prints the count beside the unresolvable one. A steady
value equal to what the daemon originates (connected subnets, its own
addresses, statics via tunnels) is normal.

Each v4 one needs a covering `steer-exempt`, and a first steer is refused
until every one has it. VPP has no route for them, so a steered packet
would follow a less-specific route out of the box. The refusal names the
prefixes; add the exemptions and `reconfigure`. A gateway `/32` does not
cover its subnet. The exemption tripwire (`exempt-drift`) names the same
kernel paths independently: the router's own addresses and routes out
devices VPP does not take are exactly what it watches. A kernel-delivered
prefix without an exemption fails verify on its own count
(`N kernel-delivered prefix(es) without a steer-exempt`), never as
unresolvable.

Validation refuses: a port the section does not declare, a vlan
missing from the port's `vlans` list, a prefix outside every
fast-path `local-prefix` (tier agreement — a failover must not change
what is delivered), and overlapping declarations. Restart-only; the
reload names it.

### local-route6: a customer VLAN VPP can deliver IPv6 to

`local-route` is enough for IPv4 service hosts, which are static and
which the kernel has resolved. A customer VLAN's IPv6 hosts are
neither: customers talk to the router from their link-locals, so the
kernel rarely holds their global addresses, and privacy addresses
rotate daily. Before inbound IPv6 for a customer VLAN is steered into
VPP, VPP must be able to reach a host it has never been told about.
Three modules take part, and all three lines are required:

```
module fast-path
  allow-prefix6 2001:db8:0:1337::/64
  local-prefix6 2001:db8:0:1337::/64 via br1337

module vpp-offload
  v6 on
  port eth4 cores 1 steer on vlans 88,1337
  local-route6 2001:db8:0:1337::/64 port eth4 vlan 1337

module neigh-snoop
  bridge br1337                       # not ix-mode
  prefix br1337 2001:db8:0:1337::/64  # the customer /64; no fe80::/10 needed
```

How a never-seen host becomes reachable:

1. **`local-route6`** installs an attached `/64` on the VLAN's BVI (or
   subif / VF, chosen as for `local-route`), and shadows the mirror
   inside it, including a route for the `/64` itself, which would
   otherwise replace the attached route's path. This is also what makes
   customer hosts deliverable in VPP at all, even ones the kernel knows:
   `local-prefix6`'s `/128`s are local-ARP routes and never reach VPP,
   and a static neighbour becomes a usable host route only under an
   attached cover on its own interface.
2. **VPP gleans.** A packet for a host VPP holds no neighbour for hits
   the attached route's glean adjacency, and `ip6-glean` sends a
   neighbour solicitation to the host's solicited-node group out the
   bridge domain. VPP v26.06 always sources it from the interface's
   link-local, so nothing beyond the ip6 enable `v6 on` already does
   is configured: no global address, no connected prefix. The BVI
   carries the kernel bridge's MAC, so its EUI-64 link-local is the
   bridge's own (assuming the bridge uses the default EUI-64 address
   generation) and so is the solicitation's source link-layer address.
   The packet that triggered it is **dropped**: glean does not queue.
3. **The host answers the router**: a solicited NA, unicast to the
   bridge's MAC. It is ICMPv6, which the MCAM never diverts, so it
   reaches the kernel bridge. The kernel discards it: it holds no
   INCOMPLETE entry for the target, and 5.15 has no
   `accept_untracked_na`.
4. **neigh-snoop learns it** (target + target link-layer option; the
   Solicited flag and unicast destination are not consulted) and
   installs it `STALE`, at its `install-rate`.
5. **fast-path's `local-prefix6`** sees the `RTM_NEWNEIGH`, registers
   the host as a `/128` next hop, and the programmer hands the
   neighbour to vpp-offload's feed.
6. **VPP gets a static neighbour** on the BVI, placed per host from the
   bridge FDB like any bridge neighbour. The next packet is delivered.

The known cost: the first packet to an address VPP has never had is
lost, and so is every packet until steps 3-6 finish (not yet measured
on hardware; neigh-snoop's install pacing is one term of it).
IPv4 makes the same trade under `local-route`. TCP retransmits a lost
SYN; a one-shot UDP query to a quiet host can be lost.

**Solicitation rate.** VPP throttles glean per destination and
interface: at most one solicitation per millisecond per worker
(`nd_throttle`, compiled in, with no API to tune it). The kernel, for
comparison, sends `mcast_solicit` (3) solicitations a second apart per
resolution attempt. So a sustained stream to an
address that never answers (a departed host, a typo, a scan) makes VPP
solicit up to ~1000 times a second per worker — roughly workers ×
1000/s in aggregate, since that address's packets can land on every
worker — toward its solicited-node group, and a scan across the `/64` solicits about once
per scanned packet. On a switch without MLD snooping each one floods
the VLAN. That is the price of delivering IPv6 in VPP at all, and it is
not a stall risk: glean runs in VPP's data plane and never reaches the
API, and what comes back is paced by neigh-snoop's `install-rate`
(default 50/s, daemon-wide). A customer host has no routes resolving
through it, so a neighbour add is not the dependent-FIB walk an IX
next hop's is. Watch `ip6-glean`'s counters (below, and
`packetframe_vpp_glean_sent{family="ipv6"}` —
[Glean and ARP counters](#glean-and-arp-counters)). If the rate matters
on a VLAN, the rollback is dropping its `local-route6` (restart).

Entries age out with the kernel's: an unused `STALE` entry is removed
by neighbour GC (`gc_stale_time`, once the table is above
`gc_thresh1`), `RTM_DELNEIGH` reaches VPP as a lost neighbour, and the
next inbound packet gleans again. neigh-snoop's `table-max` (default
4096) bounds what it remembers per bridge. Size it for hosts ×
addresses per host, because privacy addressing keeps several per host
alive at once.

Delivery is designed for bridged VLANs (the BVI case). On a plain
port's subif or an untagged VF the solicitation carries the port's own
MAC, and whether the NA reaches the kernel or the VF on the reference
NIC has not been measured.

Validation refuses `local-route6` without `v6 on`, outside every
fast-path `local-prefix6` (the v4 `local-prefix` is no cover), on a
port or vlan the section does not declare, and overlapping another
`local-route6`. Restart-only on both doors: a reload names it, and a
`--keep-vpp` restart across an added or removed line refuses adoption
and restarts VPP. That restart is what removes an attached route,
since the route is kept outside the ledger. A config without any
`local-route6` records exactly what earlier builds recorded, so an
upgrade still adopts.

The bridge a `local-route6` names is IPv6 reach for the exemption
tripwire, so its connected `/64` is not an `exempt-drift-v6` finding
([IPv6 findings](#ipv6-findings-exempt-drift-v6)). Without the line,
the same connected route is one while a port carries `v6-divert`.

Verifying on the box (`vppctl` is fine for these; they are not bulk
reads):

```sh
# The attached /64, on the BVI (loop1337), and no drop or mirror path.
vppctl show ip6 fib 2001:db8:0:1337::/64
# Static neighbours VPP holds for the VLAN's hosts ("S" flag).
vppctl show ip6 neighbors loop1337
# Glean at work: "neighbor solicitations sent" climbing when new hosts
# are reached; "throttled" is the rate limit; "address overflow drops"
# means link down or ip6 not enabled on the interface; "no source
# address" means it has no link-local (ip6 enable failed).
vppctl show errors | grep -i glean
# What neigh-snoop installed on the kernel side.
ip -6 neigh show dev br1337 nud stale
# The learning side, per bridge.
grep 'neigh_snoop_.*iface="br1337"' /var/lib/node_exporter/textfile/packetframe.prom
```

A healthy VLAN shows solicitations sent roughly tracking new addresses,
`STALE` entries appearing for the customer `/64`, and the same hosts as
static neighbours on `loop1337`. If solicitations climb but no `STALE`
entry appears, the NA is not reaching neigh-snoop: check the `bridge`
and `prefix` lines, and that `frames_total{kind="na"}` counts on the
bridge.

### direction dst: steering inbound

Per-port, because the bidirectional service edge is asymmetric by
nature:

```
  port eth4 cores 1 steer on vlans 88,1337 direction src   # outbound rides VPP
  port eth3 cores 1 steer on direction dst                 # inbound rides VPP
```

A dst rule diverts inbound INTO VPP, so `direction dst` (and the
global `both` default) refuses to load unless every steerable local
prefix is fully covered by `local-route` lines — an uncovered address
would blackhole 100% of its inbound the moment the port steers (the
w20 shape), and that is a load-time refusal, not a canary discovery.
Pure transit needs no local-routes: dst-steered traffic for a
non-local prefix forwards via the full table.

Each direction gets its own rule plan; `packetframe feasibility`
itemises them per direction (divert + keep counts against the free
slots). The exemptions install on every steered port, so
internet→gateway traffic stays kernel-side on the transit ports too.

### Bridge neighbours: placed per neighbour from the FDB

A next hop on a bridge VLAN — an IX peer on `br3998`, a service host on
`br1337`, a switch on an inter-VLAN routing VLAN — is reached through a
member port's dot1q subif, and which port is not a property of the
device. On a box with two trunks into one VLAN-aware bridge, spanning
tree decides which trunk each neighbour is behind, and can change it.
The one place that says is the kernel bridge's FDB.

**Frames on a bridged VLAN must leave from the bridge's MAC.** The
kernel sends `br3998` traffic from the bridge's MAC (switch0's on a
UniFi box), and that is the MAC an IX registers: SIX drops a foreign
source MAC, KCIX shuts the port. VPP transmits from an interface's own
MAC, and a member VF's MAC must stay the port's own (setting the bridge
MAC there captures all gateway traffic into VPP — w22). So a bridged
VLAN is not routed on the trunk subifs at all. Each gets a **bridge
domain and a BVI**: a software loopback (`loop<vid>`) carrying the
kernel bridge's MAC, unnumbered to `loopback-address`, with every trunk
subif carrying the VLAN as a member (split-horizon group 1, so VPP never
bridges trunk to trunk; tag popped on ingress, pushed on egress). A port
that sends the VLAN **untagged** joins with its VF itself, bare — so a
host behind an access-style port still sees the bridge's MAC. Members
follow the kernel bridge's VLANs within seconds, including a port that
stops carrying one leaving the domain. The BVI's MAC is re-asserted on
adoption, so a bridge MAC changed across a restart is picked up; the L3
device is the addressed one (IPv4 or global IPv6), else the bridge
rather than the VLAN device beneath it. Two VLAN-aware bridges sharing a
vid are not supported: only the first gets a BVI, and the second's
neighbours stay unresolvable rather than borrowing it.
Neighbours and routes sit on the BVI; frames leave from the bridge MAC
through the domain. **A tagged bridged VLAN with no BVI — the router has
no L3 device on it — never resolves**, rather than falling back to a
subif that would send from the port's MAC.

Which trunk a neighbour is behind is a **static L2FIB entry** in that
domain, placed from the kernel bridge's FDB: the module classifies the
device (a bridge whose only member is `switch0.3998`, a VLAN device on
the VLAN-aware bridge `switch0`), looks the neighbour's MAC up in
`switch0`'s FDB for VLAN 3998, and pins it to that trunk's subif. A
background thread re-reads the FDB every 2 s (never the supervision
loop, which must not wait on netlink), and placement is checked against
it every 2 s. **A move is one L2FIB update** — the neighbour and every
route through it stay on the BVI. An FDB entry that ages out or is
flushed keeps the last known trunk; a neighbour the FDB has never shown
gets no entry and **floods to every member**, exactly as the kernel
bridge floods an unknown MAC. Every resync withdraws static entries the
module did not make (a previous run's, on an adopted VPP). The link gate
counts the member a neighbour is pinned to — every member, for one that
floods — as in use, so a dark trunk still blocks a steer. If the FDB or the
bridge-port VLAN table stops being readable, placements and VLAN
membership hold at the last good read and the `fdb` row goes Degraded
until a read succeeds.
`vppctl show bridge-domain <vid> detail` and `show l2fib verbose` show
the domain, its BVI and the pinned MACs.

Two things to get right in config:

- **Declare the vid on every trunk that can carry it** — or declare the
  trunks `vlans all`. A neighbour learned behind a port without that
  subif cannot be reached, and its routes stay unresolvable (which
  blocks a first steer, by design). With `port eth4 … vlans all`, the
  port gets a subif for every tagged VLAN the kernel bridge carries on
  it at attach, and the engine adds one within seconds of the switch
  adding a VLAN (`trunk carries new VLAN(s); subinterfaces added` in the
  journal) — a neighbour already placed on it is then programmed and
  its routes re-queued. Add-only: a VLAN removed on the switch leaves an
  idle subif until the next restart. A VLAN the bridge sends untagged on
  the port (its PVID) needs no subif at all: neighbours on it, and a
  `local-route` naming it, are reached through the VF. If it stops being
  untagged on that port, its neighbours' routes go unresolvable and the
  VF adjacency is retired.
- A new VLAN's **connected subnet** is not delivered automatically: VPP
  reaches next hops on it, not arbitrary hosts. The exemption tripwire
  reports the connected route until a `local-route` (with its fast-path
  `local-prefix`) or a `steer-exempt` covers it. Gatewayed routes over
  the new VLAN are covered from the tripwire's next scan: it re-reads
  which VLANs each member carries every time.
- The FDB learns from frames the KERNEL sees. Steered frames go to the
  VF, so a host whose every frame is steered would eventually age out —
  in practice ARP, IPv6 and control traffic keep it fresh. The
  last-known-port rule covers the gap, and the gauges below say when it
  is not enough.

```
fdb: degraded — bridge neighbour(s) the kernel FDB has not placed behind
any member port: 198.51.100.6 on br3998 — VPP cannot reach them, …
```

`packetframe_vpp_neighbours_unplaced` counts neighbours VPP cannot
reach at all (their routes are unresolvable — e.g. a tagged bridged
VLAN with no BVI); `packetframe_vpp_neighbours_flooded` counts bridged
neighbours reached through a BVI but not yet pinned by the FDB; `packetframe_vpp_neighbour_moves` counts
moves VPP followed since start. The exemption tripwire counts a route
out a bridge VLAN some member carries as a path VPP can take.

### Dashboards under-count steered traffic — where it went

The moment a port steers, UniFi's port graphs (and anything else
reading kernel netdev counters) drop by roughly the steered share:
steered ingress is diverted to the VF before the PF counter
increments, and VPP's egress leaves through the egress port's VF,
which the PF counters never see. Measured on the primary (w25,
2026-08-15): eth3's kernel tx fell to ~211 kB/s while `octeon3/0`
carried ~261 MB/s — same wire, different ledger.

The counters to trust while steered: `packetframe_vpp_*` gauges and
`vppctl show interface` for the offloaded share; kernel counters for
the exempt/kernel-side residual. Two-sample rate check:

```sh
vppctl -s /run/packetframe/vpp/api.sock.cli show interface \
  | tr -d '\r' | awk '/^octeon/{i=$1} /tx bytes/{print i, $NF}'
# wait 10s, run again; delta/10 = B/s per VPP interface
```

### Tunnel-bound destinations MUST be steer-exempted

VPP owns member VFs and nothing else. Any destination the kernel
forwards through a device VPP does not own — an IPSec VTI, WireGuard,
any tunnel — has NO path in VPP: the mirror route resolves to no
member and never installs, and a steered packet for it dies at the
default route (a drop in VPP) instead of falling back to the kernel.
The XDP tier PASSed these flows to the kernel, which encrypted and
forwarded them; **steering removes that safety net**, and VPP cannot
do IPSec, so the kernel path is these flows' permanent, correct home:
one `steer-exempt` per tunnel-bound prefix.

Found the hard way on the reference primary (w26, 2026-08-16): the
inter-site IPSec (vti64) carried ord1's prefix plus seven host routes
INSIDE mci1's own service /24, and every steered window since w23 had
been silently dropping ~50+ pps of real inter-site traffic — a
ONE-WAY blackhole (the reverse direction arrives as ESP on unsteered
transit ports and kept working), invisible to every watchdog, visible
only as a steady rate on VPP's default-route drop counter.

Symptom: `show ip fib 0.0.0.0/0` drop counter climbing at a steady
rate while steered; a service host cannot reach a remote-site address
while the remote site can reach it. Diagnosis — profile real traffic
and ask the KERNEL, not bird (policy rules are the oracle; bird's
table misses policy routing entirely):

```sh
# what service hosts actually send (bridge SVIs see it untagged;
# a filter without `vlan` sees NOTHING on the tagged trunk itself)
timeout 60 tcpdump -ni br1337 "src net <svc>/24 and not dst net <svc>/24" \
  | awk '{print $5}' | sed 's/\.[0-9]*:.*$//' | sort | uniq -c | sort -rn | head -25
# the kernel's actual forwarding decision for a candidate dst
ip r get <dst> from <svc-host> iif br1337
```

Anything resolving via a non-member device gets a `steer-exempt`.
**The trap that remains:** tunnel host-route sets are often
bird-managed and DYNAMIC — a new host route at the remote site
re-opens the hole silently until the exempt list catches up. Until an
automated drift check ships, the null-drop gauge's RATE is the
tripwire: re-profile on any step change.

### The exemption tripwire (`exempt-drift`)

The rule above is only as good as the exemption list staying complete,
and the sets that produce it are edited by routing daemons — bird
announces a remote host route and the hole re-opens with nobody
touching packetframe. So it is watched on a clock rather than
validated once: every 60 s the module dumps the kernel's IPv4 routes
from every table a policy rule selects and reports any path VPP cannot take that no
`steer-exempt` covers — and, while a port diverts IPv6, the kernel's
IPv6 routes too ([IPv6 findings](#ipv6-findings-exempt-drift-v6)
below).

```
exempt-drift: degraded — kernel path(s) VPP cannot take, with no
  `steer-exempt` covering them: 203.0.113.128/25 via vti64 (table 100)
  — steered traffic for these dies at VPP's default route instead of
  falling back to the kernel that would deliver it.
```

The scan runs on its **own thread**, not the supervision loop: a full
route dump on a DFZ-carrying box walks a million prefixes, and the
loop it would otherwise sit on is the one that answers liveness
pings, wedge detection and steering changes — including the `steer
off` an operator reaches for when something is wrong. Monitoring must
never be able to delay the thing it monitors, so the loop only ever
reads a completed result. **Detach does not wait for it either:** a
dump in flight is abandoned rather than joined, because a netlink dump
cannot be cancelled and a monitoring scan holds none of the resources
a detach must release. A `detach` that reported "resources may still
be held" while only a scan remained would be a false alarm about the
one thing that alarm must stay trustworthy for.

**It stays out of the way of link churn.** Every chunk of a route dump
is served under the kernel's routing lock (`rtnl_mutex` on 5.15), the
same lock every route and link change needs, and the worst moment to
take thousands of them is right after a link changes state, while the
kernel and the routing daemon flush and reinstall the routes through
it. So the scan watches link up/down transitions (`RTNLGRP_LINK`; not
promiscuity or allmulti toggles): a scan that falls due within 60 s of
one waits until links have been quiet for 60 s, and a scan a transition
catches mid-dump is abandoned and rerun once they settle. Neither
publishes anything, so the last verdict stands meanwhile. The wait is
capped at five minutes from when the scan fell due: under a link that
never stops flapping, the scan runs anyway, to the end. Each case logs
at info: `holding the drift scan until links settle`, `abandoned the
drift scan until links settle`, `running the drift scan anyway`, each
naming the link.

`packetframe_vpp_drift_scan_ms` is how long the latest scan took, rule
and route dumps of both families, whatever it concluded: how long it
contended with route and link changes. At debug level each scan also
logs what it read per family (`drift scan read the kernel's routes`:
routes read, routes kept, ms, and the tables dumped).

`packetframe_vpp_exempt_drift` carries the count; **alarm on `> 0`,
and on `absent()` while the module is attached** — the gauge is
omitted rather than zeroed whenever the scan cannot read the kernel,
so a dashboard cannot mistake a blind check for a clean one.
Each finding names the prefix, the device, and the table, which is
what `ip route show table <n>` needs to find it again. The remedy is
one `steer-exempt` per path (one MCAM slot each — check the budget
line in `packetframe feasibility`), or leaving that port unsteered.

What it reports, and what it deliberately does not:

- **Forwarded routes** are findings when NO nexthop device is a
  member port or a `local-route` bridge. Multipath is judged across
  every nexthop (ECMP hides its devices in `RTA_MULTIPATH`, not
  `RTA_OIF`); one resolvable path is enough for VPP to forward the
  prefix, so only an all-unreachable route is reported.
- **Kernel-delivered destinations** — the router's own addresses, and
  a segment's directed broadcast (`.255`), neither of which VPP can
  reproduce — are findings on the **steered segments** (the
  `local-route` bridges). That is the w23 class: 110,917 packets to a
  gateway address in five minutes. Device reachability is deliberately
  NOT consulted for these, since the interface named on a local route
  owns the address rather than being a path.
- **Out of scope, on purpose:** local addresses elsewhere (transit
  port IPs, mgmt, loopback). The per-port MCAM budget cannot hold an
  exemption for every address on the box, and an alarm with no
  available remedy is one operators learn to ignore. The null-drop
  gauge is the backstop for that remainder.
- **Lightweight-encap routes** (`ip route ... encap mpls|seg6|ip ...
  dev eth3`) are findings **whatever device they leave by**, including
  a member port. The mirror carries prefix, nexthop and interface, and
  has nowhere to put a label stack or a segment list, so VPP would send
  the packet bare out the same port — a different destination, not a
  slower path. The message names the action (`applies MPLS
  encapsulation`) rather than the device, because the device is
  usually fine and reading it as a reachability problem sends the
  operator the wrong way. MPLS and SRv6 deployments see this one;
  bird's classic routes do not.
- **Not reported:** routes the kernel itself drops (blackhole,
  unreachable, prohibit — VPP dropping the same packet is the same
  outcome), and the built-in broadcast/multicast exemptions.
- **Under `direction dst` on every steering port**, the scan is scoped
  to destinations the allowlist can actually divert: a path no packet
  can reach must not cost an exemption slot. Any `src` or `both` port
  anywhere restores the full scope, because a source-matched packet
  reaches VPP whatever it is addressed to.

Coverage is by containment, not overlap: a `/32` exemption does not
silence the `/24` around it. That asymmetry is deliberate — treating
one exempted host as covering its whole prefix is how a hole hides.

One thing it reports about ITSELF: routes installed with **nexthop
objects** (`ip route ... nhid N`) name their devices in a structure
this scan does not read, so it says so — one line naming the count
and `ip nexthop show` — rather than skipping them silently or
guessing. bird's classic routes are unaffected; FRR deployments and
large ECMP setups are the ones that will see it.

Two more things it does not treat as active paths: a route in a table
NO policy rule names (an unreferenced VRF or auxiliary table cannot be
consulted by any packet, so it must not cost an exemption slot), and —
under dst-only steering — anything outside the allowlist. Only table
SELECTION is modelled, never the finer rule predicates (fwmark, iif,
from/to): "no rule names this table" is unconditionally true, while
evaluating the rest would mean reimplementing the kernel's rule walk,
where a permissive mistake re-opens the hole. Over-reporting is the
safe direction and the scan stays on that side of it.

An `exempt-drift` row also appears when a steering change **failed
partway and left rules installed** — the NIC then holds some of one
config and some of another, so the tripwire says it cannot judge
rather than answering from either set (a surviving divert rule may be
blackholing a prefix the new config exempts). `packetframe
reconfigure` reconciles and settles it; `ethtool -n <port>` shows what
is actually installed.

An `exempt-drift` row also appears when the scan **cannot read** the
kernel (netlink refused, or a dump came back interrupted). That is
Degraded too, and deliberately: a check that never ran must not look
like one that ran and found nothing — the same rule as the null-drop
gauge being absent rather than zero. The scan retries every minute,
so a row that persists means the read itself needs looking at.

**On a VRF host the table filter switches itself off.** An l3mdev
rule carries table id 0 and resolves to a VRF's table per packet, so
the enumeration cannot be complete — filtering by the tables that ARE
named would drop every VRF route and report clean while steered
traffic blackholed. A host with one gets every table dumped and
judged (the behaviour before the filter existed), and so does a rule
dump that fails or comes back empty.

Everything the scan judges against is hot: `steer-exempt`, the
allowlist, and both direction knobs are rebuilt on `packetframe
reconfigure`, and the scan's copy is replaced in the same step (then
re-run immediately). So adding the exemption the health line asked
for clears the line on the next status poll rather than a minute
later — and flipping a port to `src`, or widening the allowlist,
widens what the scan watches at the same instant it widens what the
NIC diverts.

It is detection only. Deriving the exemptions automatically was
considered and rejected for v1: it would change forwarding without an
operator asking and could exhaust the MCAM budget silently.

#### IPv6 findings (`exempt-drift-v6`)

A `v6-divert` diversion matches by FRAME (TCP/UDP over IPv6 to the
router's MAC on a listed VLAN), never by address, so once one exists
any IPv6 destination can reach VPP. A kernel-only IPv6 route VPP lacks
— an overlay's ULA via its tunnel device, a static route out an
interface VPP does not own, a route added by hand — is then silently
black-holed there. So the scan also dumps the kernel's IPv6 routes, on
the same thread and cadence, but **only while VPP carries IPv6 (`v6
on`) AND some port line carries `v6-divert`** — from config, not the
lever, so a `v6-divert` staged behind `steer off` is already scanned
(the same reason the v4 scan runs before the canary). Drop
`v6-divert` from every port and the half, its row and its gauge go
away.

```
exempt-drift-v6: degraded — IPv6 kernel path(s) VPP cannot take, while
  a port diverts IPv6 (`v6-divert`): 2001:db8:100::/48 via tun0
  (table 52) — diverted IPv6 for these dies in VPP, or leaves by a less
  specific route VPP holds, instead of taking the kernel path. …
```

It is the same judgement as v4 — a route is covered when some next hop
leaves by a member port, by a bridge VPP delivers this family into, or
via a gateway on a bridge VLAN a member carries — with these
differences:

- **Nothing exempts.** The NIC cannot match a v6 address, so there is
  no IPv6 `steer-exempt` and every finding stands until its cause
  goes, or until you accept it ([`drift-accept6`](#accepting-a-finding-drift-accept6)).
  That is why it has its own row: its remedies are not
  `exempt-drift`'s.
- **A link-local kernel next hop is judged by VPP's table, not the
  kernel's.** Under FRR, a peer that sends both a global and a
  link-local next hop gets its kernel route installed via the `fe80::`
  one ("(used)" in `show bgp`), while the feed also carries the global
  one and VPP installs the prefix through it — VPP refuses only routes
  whose EVERY feed next hop is link-local (`fib-v6` counts those). So a
  kernel route whose owned-device hops are all link-local is covered
  when VPP holds the prefix (installed or in flight), and reported only
  when VPP does not: refused as link-local-only, or never in the feed
  (an RA-learned default via `fe80::1` on a member). Those are **one
  summary line**, counting every such route and naming the first
  three. The check runs when each scan lands, so in the first scan
  after an attach — before the v6 table has loaded — they are reported
  until the next one. A route with any global next hop on an owned
  device is covered by its device. An ECMP route mixing a link-local
  member hop with a hop out a device VPP does not own is, when VPP
  lacks the prefix, an ordinary finding naming that device.
- **A bridge is v6 reach by `local-route6`, not `local-route`.**
  `local-route` delivers an IPv4 subnet; VPP has no route onto that
  bridge for its v6 subnet, so a connected v6 route there is a finding.
  A [`local-route6`](#local-route6-a-customer-vlan-vpp-can-deliver-ipv6-to)
  installs the v6 attached route, so its bridge counts exactly as a
  `local-route` bridge does for v4: by device, any route out it
  covered. Each line counts for its own family only.
- **Not paths, never findings:** link-local destinations (routers
  never forward `fe80::/10`), multicast destinations (a `33:33` frame
  no diversion's unicast MAC matches), and the router's own addresses
  (local and anycast). The v4 scan reports router addresses on the
  steered segments because a `steer-exempt` fixes them; v6 has no
  address rule, and what reaches the router over a diverted VLAN stays
  on the kernel by port (the built-in DNS keeps and `steer-keep6`), a
  match this scan cannot relate to a route.
- **Tables** are filtered by the v6 policy rules (`ip -6 rule`), a set
  separate from the v4 rules; nexthop-object routes and routes the
  kernel drops are handled as for v4.

The remedy depends on which kind of route it is:

- **A route VPP should carry** (it leaves by a device VPP owns or
  should own): fix the feed so VPP learns it with a usable next hop, or
  declare the VLAN on the port (`port … vlans`) so VPP reaches the
  device.
- **A kernel-only route** (a tunnel, an overlay, anything VPP will
  never own): keep that traffic on the kernel by port with
  `steer-keep6`, when it is identifiable by port; or drop `v6-divert`
  from the ports whose hosts reach that destination; or accept the
  black-hole risk knowingly with `drift-accept6` (below).

##### Accepting a finding (`drift-accept6`)

Some findings are examined and then deliberately left standing: an
overlay VPN's ULA routes via its tunnel device when no diverted host
talks to the overlay, an IX LAN /64 VPP deliberately holds no connected
route for, a stale kernel route the routing daemon left behind that
nothing uses. With no v6 exemption to install, such a finding would
keep `exempt-drift-v6` — and overall health — Degraded forever, and a
permanently red row hides the NEXT finding behind it. So:

```
module vpp-offload
  v6 on
  drift-accept6 2001:db8:ff00::/40
```

A v6 finding whose destination prefix equals or lies inside an accepted
prefix is **accepted**: it no longer degrades the row or overall health
and is not counted in `packetframe_vpp_exempt_drift_v6`; it is counted
in `packetframe_vpp_exempt_drift_v6_accepted` instead (same
absent-not-zero rule, so the two always sum to every v6 finding) and
still listed on the row. A finding LESS specific than the accept (a
`::/0` via a tunnel, under an accept for one /48 inside it) is not
covered. Every category is matched per route prefix — paths,
nexthop-object routes, and the link-local summary, whose accepted and
unaccepted routes are counted and summarised separately.

```
exempt-drift-v6: healthy — accepted: 2001:db8:ff00::/48 via tun0
  (table 52) (`drift-accept6` — acknowledged, not fixed: diverted IPv6
  for these still dies in VPP)
```

With unaccepted findings too, the row is Degraded and names them first,
the accepted ones after. An accept that matches no finding at all adds
`drift-accept6 2001:db8:ff00::/40 matches nothing` to the row, without
degrading it: the finding it was written for is gone (the tunnel was
torn down, the feed was fixed), so drop the line before it silently
accepts whatever appears under that prefix next.

**Accept, or fix?** Accept only what you have looked at and decided to
live with, as narrowly as the finding (the finding's own prefix, not a
covering /32). Accepting is an acknowledgement, **not a fix**: diverted
IPv6 to an accepted prefix still dies in VPP, exactly as before the
line — the tripwire just stops shouting about it. If any diverted host
needs that destination, fix it instead: the feed, the port's `vlans`,
a `steer-keep6`, or dropping `v6-divert`. Validation: a valid IPv6
prefix with host bits zero, `v6 on` required, an exact duplicate
refused, and `/0` refused (it would silence the whole v6 half — drop
`v6-divert` instead if that is what you mean). Hot-reloadable without
the supervision loop: a reload takes effect when the next scan lands
(within a minute), in either direction. There is deliberately **no IPv4
form**: a v4 finding has a real remedy, `steer-exempt`, which keeps the
traffic working instead of merely silencing the report.

`packetframe_vpp_exempt_drift_v6` carries the route count, as its own
series: `packetframe_vpp_exempt_drift` keeps its single, unlabelled
series and counts IPv4 alone, so every query written against it reads
exactly as before. The v6 gauge follows the same absent-not-zero rule —
omitted while the v6 dump cannot read, while the tripwire is pending or
cannot tell which config the NIC holds (the `exempt-drift` row speaks
for both halves then), and whenever no port carries `v6-divert`. A v6
dump that fails does not discard the v4 verdict, and the other way
round: a failed v4 dump leaves the v6 half blind too, since it runs
second.

### The null-drop gauge

`packetframe_vpp_null_drops` is VPP's own null-node counter, sampled
over the binary API every 60 s (absent until the first sample, and
after any read trouble — absent is "cannot read", never "zero").

What the steady floor is on the reference primary — measured by
destination profile, not assumed (w26b, 2026-08-17): **~155 pps of
traffic that is undeliverable on ANY path** — service hosts'
misdirected VPN/overlay packets (RFC1918, CGNAT space with no
kernel route), SSDP multicast, benchmark space, address junk. The
kernel forwards the same packets to transit where they die upstream,
invisibly; VPP drops them locally and counts them. Same outcome, one
hop earlier, with a number attached.

That floor is what a box WITHOUT a default route in VPP drops. When
fast-path declares `fallback-default`, VPP carries the same 0.0.0.0/0
through the same upstream, so steered traffic to anything outside the
feed's table follows the kernel path's route instead of dying at
null-node. That includes destinations the kernel reaches only through a
policy-routed default outside the main table (a UniFi WAN table), which
the exemption tripwire cannot see. Before this default reached VPP, the
real destinations among them dropped too. The upstream's neighbour must
resolve on a member port, like any next hop; if it cannot, the default
counts as unresolvable and blocks the first steer. With the default in
place, the floor is whatever the kernel itself drops.

How to read it: the FLOOR is expected and flat (~19k per 2-minute
interval on the reference primary); the signal is a RATE CHANGE. A
step UP after a config or routing change means something real joined
the drop path — a tunnel-bound destination missing its exemption
(section above) or, with local-routes in place, something local that
stopped being delivered. History worth remembering: this counter's
steady rate was misread as harmless for three windows ("spoofed
replies, undeliverable by anyone") until the destination profile
showed ~a third of it was live inter-site traffic. Profile before
declaring a floor harmless.

### Glean and ARP counters

VPP sends ARP and neighbour discovery of its own. The kernel transmits
none of it, so none of it shows up in the kernel's transmit counters or
in `guard`:

- **Glean.** Steered traffic to a host inside a `local-route` (IPv4) or
  `local-route6` (IPv6) prefix that VPP holds no static neighbour for
  hits the attached route's glean adjacency. The packet is dropped and
  `ip4-glean` broadcasts an ARP request (sender address =
  `loopback-address`, sender MAC = the BVI's, i.e. the bridge's) or
  `ip6-glean` multicasts a neighbour solicitation from the BVI's
  link-local. It leaves through the BVI and floods every member port
  on that VLAN. The reply is unicast to the bridge's MAC, reaches the kernel,
  and becomes a static neighbour through neigh-snoop → fast-path →
  vpp-offload (see local-route / local-route6 above).
- **Rate.** VPP throttles glean per destination (and interface) per
  worker at 1 ms, compiled in with no knob: up to ~1000 requests a
  second per silent address PER WORKER. The throttle is per worker, and
  RSS spreads one address's flows across workers, so the aggregate
  ceiling for one silent address is roughly workers × 1000/s — against
  the kernel's ~3 per resolution. Requests past the throttle are counted `throttled`, not
  sent.
- **The `guard` bypass.** `guard`'s `arp-ns-ratelimit` polices frames
  the kernel transmits (tc egress on the bridge). Glean leaves through
  VPP's VF and never meets it. If a VLAN needs a hard ceiling on the
  router's ARP rate, the lever is the `local-route` line, not guard.
- **Replies.** VPP answers ARP for its `loopback-address` only (see
  Architecture). Hosts that saw a glean request carry that address as a
  neighbour and may ARP for it later, so a trickle of replies is
  expected where glean runs; anywhere else, a step means something is
  asking for an address it should not know.

Exported from VPP's own counters (summed across workers), absent until
the first sample and after any read trouble, the null-drop rule. The
sampler makes one API read per 30 s tick, alternating `show errors`
(null-drop and glean) with `show ip neighbor-stats` (replies), so each
refreshes every 60 s and the reply gauge appears one tick after the
glean ones; a tick never blocks the supervision loop longer than a
single read. All cumulative since VPP started; all informational —
no status condition reads them:

| series | source |
|---|---|
| `packetframe_vpp_glean_sent{family="ipv4"}` | `ip4-glean` "ARP requests sent" |
| `packetframe_vpp_glean_throttled{family="ipv4"}` | `ip4-glean` "ARP requests throttled" |
| `packetframe_vpp_glean_sent{family="ipv6"}` | `ip6-glean` "neighbor solicitations sent" |
| `packetframe_vpp_glean_throttled{family="ipv6"}` | `ip6-glean` "throttled" |
| `packetframe_vpp_arp_replies_sent` | `show ip neighbor-stats`, `arp: tx:[reply:N]` summed over interfaces |

The reply gauge deliberately does not use `arp-reply`'s
"ARP replies sent" row from `show errors`: in v26.06 a request dropped
before its error code is reassigned is booked under that row, so it
over-counts by every such drop. `show ip neighbor-stats` is the real
transmit count.

**What normal looks like.** On the reference primary, IPv4 glean runs
at roughly **20-25 requests/s** with a service VLAN under
`local-route` — hosts coming and going, flows to departed addresses —
with `throttled` a small fraction of it. IPv6 glean is rare (a few per
new customer address; proven end to end). Replies: near zero.

**What a scan-driven storm looks like.** A scan across a `local-route`
prefix gleans about once per scanned address, so
`rate(packetframe_vpp_glean_sent{family="ipv4"}[1m])` jumps from tens
to hundreds or thousands per second while `throttled` stays flat — many
distinct addresses, one request each. The other shape is a sustained
flow to one departed or silent host: `sent` near ~1000/s for each
worker that host's traffic lands on (up to workers × 1000/s) and
`throttled` climbing much faster, since every packet after the first in
each millisecond on each worker is throttled. Either way each request is
a broadcast on every member port of that VLAN. A `local-route6` `/64`
behaves the same way per scanned address, toward solicited-node groups.

**When to worry.** A sustained rate in the hundreds per second or more
that does not track a known event, or any storm on a VLAN whose
switches or hosts are fragile to broadcast. Glean is not a stall risk
for PacketFrame (it runs in VPP's data plane and never reaches the
API), and neigh-snoop paces what comes back (`install-rate`). The
rollback is dropping the VLAN's `local-route` / `local-route6`
(restart-only).

On the box:

```sh
# Glean and ARP, summed across workers. ip4-glean / ip6-glean as above;
# arp-reply's "not local to subnet" rows are broadcast ARP VPP received
# and refused (normal, and large); its "ARP replies sent" over-counts.
vppctl show errors | grep -E 'glean|arp-reply'
# The real ARP/ND transmit and receive counts, per interface:
# "arp: ... tx:[reply:N ...]" is the replies VPP actually sent.
vppctl show ip neighbor-stats
# l2-flood counts EVERY packet entering the flood node, in both
# directions: mostly member broadcast/multicast delivered to the BVI,
# plus glean's broadcasts. Routed unicast floods every member port only
# for neighbours counted in packetframe_vpp_neighbours_flooded.
vppctl show errors | grep l2-flood
# The exported gauges.
grep -E 'packetframe_vpp_(glean|arp_replies)' /var/lib/node_exporter/textfile/packetframe.prom
```

Take two readings a minute apart and divide; the counters are
cumulative.

## v6-divert steering

The NIC cannot match an IPv6 **address** — every `ip6`/`tcp6`/`udp6`
rule naming one fails with AF error 710 (spike doc, gate 0b round 4).
What it can match, probed on the production kernel on 2026-09-26, is
the ethertype, the destination MAC, the outer VLAN id and TCP/UDP
(`tcp6`/`udp6` rules, with or without a port). It **cannot** match the
v6 next header: an `ip6 l4proto N` rule inserts, reads back as asked,
and matches every v6 frame (rig, 2026-09-27). That is enough for one
address-free policy: **TCP and UDP over IPv6 addressed to the router's
MAC, on a VLAN you name, goes to VPP.** On a customer VLAN that is the
customers' outbound traffic; on a transit or IX port it is inbound
traffic toward them. Either way the router's own IPv6 on that port
arrives on the same MAC, so it goes to VPP too — and VPP hands it back
to the kernel over the [hand-back path](#the-hand-back-path).

```
module vpp-offload
  v6 on
  port eth4 cores 1 steer on vlans 100,200 direction src v6-divert 100,200
  steer-keep6 udp 123
  steer-keep6 tcp 22
```

### What it diverts

Two rules per (listed VLAN × receive MAC), `tcp6` and `udp6` with no
port: destination MAC = one the router's L3 devices answer to on that
port (the same set the v4 rules are scoped to), outer VLAN id = the
listed VID (PCP and DEI ignored). Into the port's VF. `v6-divert
untagged` drops the VLAN term and is refused on any port that declares
VLANs, because the NIC has no untagged-only match — a rule without a
VLAN term matches every VLAN.

**ICMPv6 is never diverted**, and that is load-bearing, not a nicety.
Proven on the rig with real frames (2026-09-27): a port-less `tcp6`
drop scoped to the router MAC blocked TCP while echo, DNS and the
kernel's own re-resolution of a customer neighbour all passed; the
`udp6` twin blocked DNS and left TCP and echo alone.
Neighbour discovery runs both ways over unicast to the router MAC:
customers' NUD probes of their gateway, and — the one that would hurt
most — the NA a neighbour sends back to the **kernel's** own
solicitation. A diversion that took ICMPv6 would starve the kernel's
neighbour table on that VLAN, and with it every v6 packet the kernel
or the fast path forwards there. Echo to the router, PMTUD's Packet
Too Big, and every other ICMPv6 stay on the kernel path too. So do
other next headers (ESP, GRE, …) and fragments the parser does not
classify as TCP/UDP: they forward as they do today.

Four consequences to decide on before listing a VLAN:

- **The allowlist does not scope it.** Every v6 source on the VLAN rides
  VPP, allowlisted or not — the NIC cannot read the source address that
  would narrow it. The kernel's netfilter never sees that traffic (as
  with anything the fast-path takes), so v6 forward-path firewall policy
  for those VLANs no longer applies to it.
- **New sessions to the router are refused unless kept.** VPP hands the
  router's own traffic back to the kernel through a guard ACL that
  admits only replies (see [the guard](#the-hand-back-path)): replies to
  what the router opened work, a new inbound SSH/NTP/DHCPv6 session does
  not.
  Every service that must accept new inbound connections on a diverted
  VLAN or port needs a `steer-keep6`, so it never enters VPP at all. That
  is the w23 lesson in IPv6 form, refused on purpose instead of lost.
- **BGP never enters VPP.** It is a built-in keep in both directions —
  see the keeps below and the hop-limit note under the hand-back path.
- **VPP must carry v6** (`v6 on`; validation refuses `v6-divert`
  without it). The steer itself checks too, against the policy the
  running engine was BUILT with rather than the config flag: a target
  carrying a v6 diversion into a VPP started without v6 is refused whole,
  before the NIC is touched — v4 included, so the port is never half
  steered — and the row says why. Each VID must be a subinterface VPP has: in the
  port's `vlans` list (validation), or carried tagged by the kernel
  bridge on a `vlans all` trunk (checked when the rules are planned; an
  unreadable bridge refuses the plan).

### The keeps

Kernel-delivery rules (`ring_cookie` 0 — the PF; spread over its queues
by RSS, or on PF queue 0 where the driver declines RSS, see [the kernel
path for exempt traffic](#the-kernel-path-for-exempt-traffic)) at
**lower locations than every diversion** — lower location is higher
priority on this NIC — so they are matched first:

| Keep | Why |
| --- | --- |
| TCP 53, UDP 53 (`dst-port`) — built in | The router's resolver. |
| TCP 179 `dst-port` and `src-port` — built in | BGP, whichever end opened the session. eBGP to a directly connected peer arrives at hop limit 1 (255 under GTSM, which must arrive as 255); the hop VPP's hand-back costs would drop every segment. |
| `steer-keep6 <tcp\|udp> <port> [dst\|src\|both]` | Every other service that accepts NEW sessions: NTP 123, unicast DHCPv6 547, SSH, SNMP. `src` keeps replies to sessions the ROUTER opened when they must not take the hand-back hop. |

A `steer-keep6 tcp 53 …` (dst) or any `steer-keep6 tcp 179 …` restates a
built-in and is refused by validation.

There is **no ICMPv6 keep, and there must never be one**: on this NIC
it would be an `ip6 l4proto 58` rule, which matches every v6 frame and,
sitting above the diversions, would switch them all off without the
readback noticing. ICMPv6 needs no keep anyway — the diversions never
take it. TCP/UDP port keeps were proven port-specific on the rig
(2026-09-27: a `tcp6 dst-port 80` keep left TCP 443 diverted;
`dst-port 443` kept it).

They carry **protocol and port only** — no address, no MAC, no VLAN — so
they apply port-wide and also keep DNS and BGP toward **external**
hosts on the eBPF tier. That is intended: correct, and a
small slice. Two costs to know: they occupy MCAM slots only while some
port diverts v6 (a port with `steer-keep6` lines and no `v6-divert`
plans none), and on a port whose driver declines RSS keeps everything
they match lands on PF queue 0 — all of the port's DNS and BGP, every
VLAN. Where the driver takes RSS (the production firmware does) they
spread like any other kernel traffic.

### Budget

Per port, beside the v4 rules: 2 × (VLANs × receive MACs) diversions +
4 built-in keeps (TCP 53, UDP 53, TCP 179 dst, TCP 179 src) + one per
`steer-keep6` rule (`both` counts two). The example above on a port
with one receive MAC: 4 + 4 + 2 = 10 slots. The refusal text names
every term, and the whole port is refused — v4 and v6 — when the total
does not fit.

### The hand-back path

Whenever VPP carries v6 and the steering target diverts IPv6 on any
port, PacketFrame builds a way back into the kernel for the router's
own traffic:

- **A veth pair.** `pfpunt0` is the kernel's end: up, IPv6 on with only
  its link-local (`accept_ra 0`, `autoconf 0`, no router
  solicitations), no global address, MTU = the largest member port's.
  `pfpunt0-vpp` is VPP's end, opened by VPP as an af_packet host
  interface (`host-pfpunt0-vpp`, wearing that end's MAC); the kernel
  keeps IPv6 off on it. In VPP the interface gets ip6 (link-local only)
  with router advertisements suppressed, like every owned interface.
- **A /128 per router-owned address.** Every global-scope IPv6 address
  the host holds, on any interface but the veth — transit /127s and
  /64s, IX addresses, the customer gateway, a tunnel's /128 — becomes a
  /128 in VPP's IPv6 table via the kernel veth's link-local on
  `host-pfpunt0-vpp`, resolved by a static neighbour (VPP never
  solicits). Link-local addresses and addresses whose DAD failed are
  left out. The set follows the kernel live: an RTM_NEWADDR/DELADDR
  watch triggers a re-read within a tick, and a full re-read runs every
  5 minutes regardless. These routes are PacketFrame's own topology,
  never in the route ledger: adoption does not read them back as mirror
  routes, the resync diff does not withdraw them, verify does not sample
  them and the drift tripwire does not see them.
- **The guard, in VPP.** A stateless ACL (tag `packetframe-handback`)
  bound as `host-pfpunt0-vpp`'s **output** ACL, so it judges everything
  VPP sends the kernel. Per router-owned address `A` — the same set the
  /128s route, so nothing is handed back for any other destination
  (defence in depth: Linux has no per-interface IPv6 forwarding switch):
  1. permit TCP to `A` with **ACK** set, and
  2. permit TCP to `A` with **RST** set — together the classic stateless
     `established` test (the `established` keyword of Cisco and Juniper
     ACLs): every segment of a connection the router opened, SYN+ACK
     included;
  3. permit UDP to `A` **from source port 53 (DNS) or 123 (NTP)** to a
     destination port in the kernel's **ephemeral range**
     (`/proc/sys/net/ipv4/ip_local_port_range`, read at setup and on every
     check — it covers IPv6 sockets too): the classic stateless reply
     rule (`permit udp any eq domain any gt 1023`), one rule per source
     port — answers to the router's own resolver and time-sync queries;

  then deny everything. So a pure SYN — every new inbound TCP
  connection to the router over diverted IPv6 — is refused, and so are
  NULL, FIN-only and Xmas-style probes, and every other UDP datagram.
  Why it exists: what arrives on the veth bypasses the vendor's
  WAN_LOCAL rules, which key on the physical WAN ports. Why in VPP: the
  vendor controller flushes and rewrites the kernel's iptables on every
  config apply, so no kernel rule would stay put, while PacketFrame owns
  VPP outright. Consequences:
  - a service that must accept new sessions over a diverted port needs a
    `steer-keep6` (it then never enters VPP, and stays under the vendor's
    own firewall);
  - an overlay or VPN that relies on direct **inbound UDP over IPv6**
    through a diverted port (its listen port usually sits inside the
    ephemeral range) is refused and falls back — to its relays, or to
    IPv4 — unless its port is kept with `steer-keep6 udp <port>`;
  - the residual risk of a stateless rule: a datagram that SPOOFS source
    port 53 or 123 reaches a UDP listener inside the ephemeral range.
    The source-port list is a fixed constant, not a knob.

**What it needs from the box.** VPP's `af_packet_plugin.so` and
`acl_plugin.so` (the vpp-unifi build loads both by default; the
module's API handshake names `af_packet_create_v3` or `acl_add_replace`
if either is missing, whatever `v6` says), a readable
`/proc/sys/net/ipv4/ip_local_port_range`, and no foreign interface named
`pfpunt0` or `pfpunt0-vpp` — an existing one that is not PacketFrame's
veth pair is refused by name and left untouched. No kernel firewall rule
is added.

**The order is enforced.** The v6 half of steering — every v6 diversion
and keep — is held back until the path is whole: veth up, VPP's
interface up, the guard ACL exactly as rendered and bound, and a /128 in
VPP for every address the host holds. IPv4 steering never waits for it. On a port with IPv4 to
steer, IPv4 installs and the v6 half follows on its own once the path
is ready; a port that diverts only IPv6 refuses the steer (so the want
is kept) and the paced retry installs it once the path is ready. If the
path breaks while steered, the v6 half is taken out and IPv4 stays. A
`--keep-vpp` restart that inherits v6 rules from a daemon that was
steering v6 takes them out at the device attach if this daemon's path is
not ready then (IPv4 untouched); they come back with the adoption's
steer once the path is.

**Hop limit.** VPP decrements the hop limit of what it hands back.
Anything router-owned that arrives at hop limit 1 reaches the kernel at
0 and is dropped. eBGP to a directly connected peer is exactly that,
which is why BGP is a built-in keep. Single-hop BFD would be too — it is
not running on the fleet; add a `steer-keep6 udp 3784` before enabling
it on a diverted port. Nothing else router-owned is known to arrive at
hop limit 1.

**Lifetime.** Built on the first target that diverts IPv6 (at start, or
by the `packetframe reconfigure` that adds `v6-divert`), and kept until
the module stops or `packetframe detach --all`, both of which remove the
/128s, the guard ACL, the VPP host interface and the veth — `detach
--all` even when no state file is left, since the veth can outlive it. A
`--keep-vpp` restart leaves all of it in place, and the next daemon
re-verifies it rather than trusting it: it finds the host interface by
name (never a second socket on the veth), re-asserts its settings,
re-adds the neighbour only if VPP lacks it, reuses the guard ACL it
finds under its tag (rewriting it in place only if it differs), and
brings the /128s to the host's current addresses — counting a surviving
/128 only in exactly the shape it installs (one path, via
`host-pfpunt0-vpp`, to the kernel veth's link-local); any other shape is
replaced, or withdrawn if the host no longer holds the address. One side effect: the first `--keep-vpp`
restart after `v6-divert` is first enabled builds the interface on the
adopted VPP, which can change the FIB summary the preserved ledger is
checked against — that restart may take the dump path.

### Verifying on the box

```bash
# The rules the NIC holds. The diversions read "TCP over IPv6" / "UDP
# over IPv6" with no ports, the router MAC as the destination MAC and
# the VLAN, "Action: Direct to VF 0 queue 0"; the keeps "TCP over IPv6"
# / "UDP over IPv6" with a port and no MAC, "RSS Context ID: 0" (absent
# on a port whose driver declined RSS keeps) and "Action: Direct to
# queue 0" — four built-ins (TCP 53, UDP 53, TCP dst 179, TCP src 179) plus
# yours. No rule may read "Flow Type: Raw Ethernet" or name an L4
# protocol number. Every keep's location must be LOWER than every
# diversion's. Masks print complemented (ethtool shows ignored bits), as
# for the v4 rules.
ethtool -n eth4
```

```bash
# What the teardown will match the keeps against: the plan's v6 rules
# sit in `rules_v6` beside the v4 `rules`.
jq '.steer_plans[] | .[2].rules_v6' /var/lib/packetframe/state/vpp-offload.json
```

```bash
# The hand-back path, kernel side: a veth whose peer is pfpunt0-vpp,
# state UP, no global address; and the range the guard admits UDP to.
ip -d link show pfpunt0
ip -6 addr show dev pfpunt0
cat /proc/sys/net/ipv4/ip_local_port_range

# VPP side: the host interface up, a /128 for each of the router's
# global addresses via host-pfpunt0-vpp, the static neighbour, and the
# tx counter climbing as the router's own replies are handed back.
vppctl show interface host-pfpunt0-vpp
vppctl show ip6 fib 2001:db8:ffff::1/128
vppctl show ip6 neighbors host-pfpunt0-vpp

# The guard: one ACL tagged packetframe-handback — per address a TCP
# rule with "tcpflags 16 mask 16" (ACK), one with "tcpflags 4 mask 4"
# (RST), two UDP rules (sport 53, sport 123) with the ephemeral dport
# range, then one deny — bound as host-pfpunt0-vpp's OUTPUT ACL and
# nothing else.
vppctl show acl-plugin acl
vppctl show acl-plugin interface
```

`packetframe status` names the diverted ports and VLANs on the steering
row ("IPv6 on eth4 vlan 100,200"), read from the installed plan, and
has a `v6-handback` row: `ready — veth up, guard ACL in place, VPP
interface host-pfpunt0-vpp up, N router-owned /128(s) handed back`, or Degraded
with `IPv6 diversion held back` and what is missing. The metrics add
`packetframe_vpp_handback_ready`, `packetframe_vpp_handback_routes` and
`packetframe_vpp_handback_tx_packets` (absent until sampled).

From a customer host on a diverted VLAN: ping the gateway's v6 address
and resolve a name through it (ICMPv6 is never diverted and DNS is
kept, so both must work); `ip -6 neigh` must show the gateway
`REACHABLE`, not `FAILED`; TCP and UDP to an external v6 destination
must work (VPP forwarding). On the router, `ip -6 neigh show dev <the
VLAN's bridge device>` must keep that customer `REACHABLE`/`STALE`
across a few minutes — `FAILED` means ICMPv6 is reaching VPP. From the
router itself, sessions it opens over IPv6 must keep working
(`curl -6` to an external host, a DNS lookup over TCP, the vendor's
cloud session) — they ride the hand-back path, and `vppctl show
interface host-pfpunt0-vpp`'s tx counter moves with them. BGP sessions
on diverted ports must stay Established. Then check the diversion is
real rather than shadowed: a new TCP session to a router port you did
**not** keep (say SSH without a keep) must fail — its SYN refused by the
guard ACL. If it succeeds, something
above the diversions matches all of TCP (safe, but the feature is off)
— or the guard is not in place, which the `v6-handback` row would say.

### What watches it, and what does not

The steering audit reads every v6 rule back like a v4 one: a keep or
diversion removed or altered out of band shows as `steering DEGRADED`,
and the readback compares every field that decides the match (the flow
type — TCP or UDP — MAC, VLAN id and mask, L4 port, the `FLOW_EXT` /
`FLOW_MAC_EXT` bits). A v6 half held back for the hand-back path is not
drift: the audit compares against what may be installed, and the
`v6-handback` row carries the reason. The hand-back path is re-checked
every 30 s and repaired when a part has gone or changed: the veth (its
ifindexes, both MACs and the MTU — a change re-asserts VPP's end: MTU,
neighbour, /128s re-pointed at the new link-local); the
guard ACL, read back with the ACL plugin's dumps and compared rule for
rule, in order, against what the current addresses and port range
render, and checked bound alone as the output ACL (any edit, a widened
range, an unbinding or a second ACL beside it counts as drift, and the
ACL is rewritten in place); VPP's interface
(one bound to a veth that no longer exists — wrong MAC, or no link — is
deleted and recreated, never adopted); and every /128 and the static
neighbour, read back from VPP. While a piece is being repaired the path
reads not ready, so the v6 half is held back. An address event whose
re-read fails holds it back too (the new address may have no /128 yet);
a failed periodic re-read with nothing heard keeps the last good address
set, so one flaky read does not churn the v6 rules.

The **exemption tripwire scans IPv6 too** while
any port carries `v6-divert`: a kernel v6 route VPP cannot take is an
`exempt-drift-v6` finding, counted on `packetframe_vpp_exempt_drift_v6`
(see [IPv6 findings](#ipv6-findings-exempt-drift-v6) for what it
reports and the remedies — there is no v6 exemption). The keeps are
what protect the router's own services; the tripwire does not judge
them. The source of VPP's own ICMPv6 errors is watched by the
`icmp6-source` row, below.

### ICMPv6 errors from VPP: `loopback-address6`

Diverted IPv6 is forwarded by VPP, so VPP is the hop that has to send
the ICMPv6 errors for it: **Time Exceeded** when the hop limit runs out
(every traceroute's hop at this router), **Packet Too Big** when a
packet is larger than the egress MTU (PMTUD — IPv6 routers never
fragment, so without it the sender never learns to shrink), and
**Destination Unreachable**. An error needs a global source address,
and with `v6 on` alone VPP's interfaces have only link-locals. VPP
v26.06 does not send the error from a link-local — it drops it
(`ip6-icmp-error` finds no source and counts `error message dropped`).
So without the directive, diverted IPv6 loses all three: the router's
hop reads `*` in a traceroute, and flows whose path MTU shrinks at VPP
black-hole their large packets.

```
module vpp-offload
  loopback-address 198.51.100.254/32
  loopback-address6 2001:db8:ffff::1
  v6 on
```

It puts one /128 on the same VPP loopback that holds `loopback-address`.
Every interface VPP owns — member VFs, dot1q subifs, BVIs — is already
unnumbered to that loopback, and VPP's unnumbered borrow covers both
families, so all of them source their errors from it. Each keeps its
own link-local for neighbour discovery and MLD.

**Picking the address.** Any /128 from global space you already announce
(so the errors pass uRPF and bogon filters on their way to the sender)
that **no host interface holds**. It does not need announcing on its
own: it only ever sources errors, nothing replies to it, and VPP never
answers for it on a wire (ICMPv6 is never diverted to VPP, so no
neighbour solicitation for it reaches VPP). Refused:

- anything outside global unicast (2000::/3): link-local, ULA
  (`fc00::/7` — not globally routable, so dropped as a bogon before it
  reaches the sender), multicast, `::`, `::1`. At config load.
- an address the kernel holds on any interface. At attach, and as a FAIL
  of `vpp.loopback6` in `packetframe feasibility`: VPP's loopback would
  answer for it too, so diverted TCP/UDP to it would end in VPP instead
  of the kernel.
- without `v6 on`, or on two lines. At config load.

Restart-only, on reload and on adoption. A `--keep-vpp` restart reads the
loopback's IPv6 addresses back rather than trusting them: a missing /128
is added (a previous daemon that died mid-attach), and any other IPv6
address on the loopback refuses the attach — VPP would source some errors
from it. Teardown needs nothing: the address lives only in VPP and goes
with it.

**What it does not do.** VPP routes the error from its own FIB, so the
sender must be reachable in VPP's IPv6 table. Diverted traffic comes
from customers on the diverted VLANs, and their subnets are the
router's connected subnets — which VPP leaves to the kernel
(kernel-delivered) unless a
[`local-route6`](#local-route6-a-customer-vlan-vpp-can-deliver-ipv6-to)
gives VPP an attached route onto that VLAN. Without one, errors to those
customers are sourced correctly and then dropped for want of a route.
The counters below tell the two apart.

`packetframe status` shows an `icmp6-source` row, **Degraded**, while any
port diverts IPv6 and VPP has no source (the directive unset); it is
absent otherwise. Degraded rather than informational because a lost
Packet Too Big is traffic silently lost, the class every other
`nominal` clause refuses. It pages nothing and gates no steering.

Verify on the box:

```bash
# loop0 holds the /128 (alongside loopback-address). No other interface
# holds a global v6 address.
vppctl show interface address
# The receive entry for it.
vppctl show ip6 fib 2001:db8:ffff::1/128
# The error node: "hop limit exceeded response sent" / "packet too big
# response sent" climb once errors are sourced; "error message dropped"
# climbing on its own means no source (or the rate limiter). Neither
# says the error was DELIVERED — a missing route back to the sender is
# counted further on, where VPP drops it.
vppctl show errors | grep -iE 'ip6-icmp-error|hop limit|too big|error message'
```

From a host whose IPv6 VPP forwards and can route back to (a customer on
a diverted VLAN that has a `local-route6`): `traceroute6 <external v6
host>` (UDP probes, which are diverted — `-I` ICMP probes are not) or
`mtr -6 --udp <host>`; the router's hop must show `2001:db8:ffff::1`, not
`*` and not a link-local.

### Rollback

```bash
# Drop `v6-divert` from the port line (or set the port `steer off`),
# then:
packetframe reconfigure
```

Hot, like any steering change: the reconcile removes the v6 diversions
and, with no port left diverting v6, the v6 keeps. `v6-divert` on a
`steer off` port is accepted and inert on purpose, so the one-token
rollback never needs a second edit. The hand-back path stays built (and
harmless: VPP is sent no IPv6 to hand back) until the module stops or
`packetframe detach --all`; to remove it by hand: `ip link del pfpunt0`
(the guard ACL and the host interface go with the VPP process, or by
`vppctl` if VPP is kept).
Turning `v6` itself off comes after (its own rules apply there).

**Before downgrading to a build without v6 steering, roll back first.**
An older build reads the state file (the v6 rules sit in a field it
ignores) and removes the v6 diversions by their VF cookie, but it cannot
recognise the v6 keeps: it disowns them, drops them from its ledger with
a warning, and leaves them in the MCAM — kernel-delivery rules, so
nothing is blackholed, but they hold slots. If that already happened:
`ethtool -n <iface>`, then `ethtool -N <iface> delete <loc>` for each
leftover IPv6 keep. An older build does not know the hand-back path
either: remove it by hand as above.

## Triage by symptom

### Steering silently went partial — the NIC holds less than the config asks for

**The module now detects this within 30 s and says so:**

```text
steering  DEGRADED — 1 steering rule(s) this target asks for are missing
                     from the NIC, no longer match what was asked for, or
                     were never installed — that traffic is on the eBPF
                     tier. Something changed them out of band (a UniFi
                     provisioning push can do this), or the allowlist grew
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
                     permit. Until it converges there is nothing to ask:
                     from here `packetframe reconfigure` changes no
                     steering, and a reload that edits steering answers
                     "not converged"
```

A reload that edits no steering input changes nothing here either, and
answers OK without asking the loop — except right after a failed
request, when the module no longer knows which target the loop holds;
that one goes to the loop and answers "not converged" like any other.

That closing part used to read *"`packetframe reconfigure` asks
immediately rather than waiting"* — which contradicted the paragraph
directly above it, and was wrong on every line it ever printed: the
only states that reach this arm are the ones that refuse steering
changes. It printed on the shadow for 23 hours under a held deferral,
and the reconfigure it named answered *"not converged"* (2026-08-12,
hardware). Fixed, with an invariant test derived from
`accepts_steering_changes()` rather than a list of states.

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
and check the count afterwards. The rules have been observed surviving
one provisioning push on a lab box on one firmware; survival across
firmware versions is untested, and nothing re-installs wiped rules
automatically — this reconfigure is the re-assert.

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
optional on a box with a completeness authority (bird's `birdc`, or
`integrity-authority frr`):

```
module vpp-offload
  require-table-complete on
```

With it, `steer` refuses while the authority does not attest the mirror,
reports why, and re-attempts itself — at most every 30 s — once the
mirror converges, so an early lever-move costs a wait rather than a lost
offload. Without it there is no gate at all — the refusal path is
compiled out — and the canary ladder is the only thing between an early
lever-move and traffic diverted into a 10%-loaded FIB. (The retry
itself does not depend on the gate — a steer the NIC refused is
re-attempted either way — but with no verdict to wait on, an early
lever-move steers into whatever is loaded at that instant.) `off` is
the documented opt-out for boxes with no authority to compare against
(`integrity-authority none`), not a default to leave alone.

### Steering came down by itself: VPP's table emptied

```
WARN VPP's FIB is empty while steered — every steered packet would be dropped there; taking steering down so the eBPF tier carries it
```

If every route drains out of VPP while a port is steered, the module
takes steering down on its own. The usual cause is an FRR session drop,
or the feed's nexthop going away. Steered packets would otherwise be
dropped inside VPP, while the eBPF tier hands the same traffic to the
kernel. `fib-synced` reads Unhealthy for the tick or two this takes,
then Degraded (`0 routes installed — the route source is empty`), and
`steering` reads "steering intended but not in place".

**Steering comes back without anyone touching it.** The want is kept,
and the ordinary steer retry reinstalls the rules once the table has
refilled and every first-steer gate passes. An empty table is one of
those gates, so the retry can't steer back into the same empty table.

Before this, a verify that passed kept `fib-synced` Healthy for good.
Verify does not re-run in steady state, so on the lab rig
(2026-09-24) a drained feed read `healthy — 0 routes installed` with
the port steered and nothing logged. Only a completely empty table
triggers this, so ordinary churn cannot flap it. A partial drain is the
completeness authority's business, which gates the first steer.

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

### Hosts flap between two MACs for the gateway, or duplicate-address warnings appear

VPP's arp node answers requests targeting its loopback's address,
sourcing the receiving interface's MAC (the bridge's, on a BVI; the
member VF's on a plain port). If `loopback-address` is a **live kernel
address** — the gateway being the worst case — VPP and the kernel both
answer, hosts learn whichever replied last, and traffic oscillates
between two delivery paths. Measured on the primary (2026-08-14, w22):
loop0 held the br1337 gateway and VPP sent 105 competing replies in
27 minutes.

Attach now refuses a kernel-owned `loopback-address` outright. The fix
is one line: point it at an announced-but-unassigned host address in
the same prefix (outside any DHCP pool), then restart into it —
`loopback-address` is restart-only. Nothing else changes: ICMP/PMTUD
sourcing works from any routable address, and members unnumber to it
identically.

### Steered traffic reaches VPP and vanishes — `punt` climbing, no `ip4`, no tx

```bash
vppctl -s /run/packetframe/vpp/api.sock.cli show interface
```

The fingerprint: the steered member's `rx packets` climbing at traffic
rate, `punt` climbing with it, and no meaningful `ip4` or tx anywhere.
The frames are real and delivered — VPP is refusing them at
`ethernet-input`, before routing. Both causes have now been measured
on the primary, one window apart, and the counters tell them apart:

1. **Tagged ingress with no dot1q subif** — no subif rows in
   `show interface` at all, every frame punted against the parent.
   This is w20 (2026-08-14): 8.7M frames punted in two minutes, every
   health surface green, the steered prefixes' return path dead. Fix:
   unsteer (the lever, seconds), add `vlans <id>[,<id>...]` to the
   port line, restart into it (the list is restart-only), re-steer.
2. **Wrong answering MAC** — the subif's `rx packets` climbs at
   traffic rate (classification works) while `punt` accrues against
   the **parent** and the subif's `ip4` stays a rounding error. This
   is w21 (2026-08-14): 7.17M frames in 90 s, because the VF answered
   to eth4's own `…:ca` while hosts ARP their gateway and send to
   switch0's `…:c7`. On a bridge-member port the answering MAC must be
   the **bridge master's**, which `answering_mac` now derives from the
   sysfs `master` link; if this fingerprint appears anyway, compare
   `ip link show <bridge>` against what `show hardware` says the
   member answers to.

The user-visible symptom while this runs is total loss for the steered
flow class only — everything unsteered keeps working, which is what
distinguishes it from the coexistence squeeze (partial loss, all
classes).

### Steering is on but traffic is not arriving at VPP

Check the NIC's ledger against ours. Ours is
`vpp-offload.json:steer_rules`; the NIC's is `ethtool -n <iface>`. If
the NIC has no rules but we believe we are steering, the UniFi
controller has wiped classifier state — a provisioning push can do
this. Nothing re-asserts them automatically in steady state (verify does
not re-run there); a plain `packetframe reconfigure` while `Steered`
re-installs them.

If the NIC *has* the rules and traffic still is not arriving, suspect
`ring_cookie`. It must be `(vf + 1) << 32`; `ethtool`'s own `vf N`
keyword mis-encodes it on the rvu driver, so a rule installed by hand
with that keyword lands somewhere else. Gate 0a established this by
inserting both forms and reading back what the NIC stored.

### A bridge-member port goes dark right after attach — hosts behind the bridge unreachable, every status green

The shared-LMAC MCAM disable (found on the primary, w3–w8, 2026-08-13).
On rvu, the AF's channel-default MCAM entries (the promisc/multicast
catch-alls that make the KERNEL PF receive; `Installed by: PF0`,
`Forward to: PF1` in the debugfs dump) cover the whole LMAC, and
bringing the member VF up under VPP disables them. Fingerprint —
**both halves required**: hosts behind any bridge that port is a
member of become unreachable, including from the router itself, while
every host surface stays green (`ip link` still shows `PROMISC,UP`,
nothing in `packetframe status`, VPP, or the kernel log complains).
The authoritative check is the hardware table:
`grep -A12 'mcam entry: <n>' /sys/kernel/debug/octeontx2/npc/mcam_rules`
— the channel's default entries read `enabled: no`.

A frozen `ethtool -S <pf> | grep rx_drops` counter is **NOT** the
fingerprint on its own, and treating it as one will false-alarm every
healthy window. While VPP holds the member VF, `rx_drops` on the
kernel PF legitimately stops counting (w9 and w10, both with entries
enabled and traffic flowing perfectly): the flood the kernel used to
receive-and-drop diverts to the VF instead. It resumes when VPP
releases the VF. Deaf is *frozen counter AND unreachable hosts AND*
`enabled: no` *in the table* — the middle one is what pages.

The module handles this itself: after every device attach it toggles
`IFF_ALLMULTI` on each member's kernel netdev (the "rx-mode kick" —
look for `kernel rx-mode re-asserted` in the attach log), which forces
the PF driver to resend its rx-mode and the AF to re-install its
defaults. The VPP-side `sw_interface_set_promisc` the attach also sends
does NOT re-enable them — only a PF-side event does; that was measured,
not assumed (w6: five kick cycles, ~1 s recovery each; w8: a stable
promisc-voting VPP went dark anyway).

If the attach log shows the kick **failing**, or the port went dark
later without an attach, apply it by hand and confirm the counter moves
again:

```sh
ip link set <port> allmulti on && ip link set <port> allmulti off
ethtool -S <port> | grep rx_drops   # twice, a second apart — must move
```

A port that re-breaks *without* a VPP restart in between is new
behaviour beyond this entry: capture the mcam_rules dump before and
after and treat it as an AF-level finding, not a packetframe one.

The complete evidence chain for the vendor report — the asymmetry,
the reproduction, the w5–w10 forensics index — lives in
`docs/vendor/rvu-af-channel-default-mcam.md`.

### A steer is refused with "the route mirror holds N of M routes"

The completeness gate. The routing daemon's initial dump has not
finished (or, under `integrity-authority frr`, a declared upstream has
not sent End-of-RIB on its current session), so the
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
birdc show route count                              # bird box
vtysh -c 'show bgp ipv4 unicast statistics'         # FRR box (and ipv6)
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

**Read the names first.** Every surface that reports the count also
names up to five of the routes, then `+K more`: the `fib-synced` and
`fib-v6` rows (live), the verify summary (as of that verify), a refused
first steer, and an `unresolvable_routes` event in `packetframe events`
whenever the set changes (at most once a minute; `detail: none` once it
empties). Each name reads

```
<prefix> via <nexthop> [dev <device>] (<why>)
```

where the device is the one the neighbour source reported, and the
reason is the mapping's own decision:

| Reason | Meaning | What to do |
|---|---|---|
| `no neighbour: the kernel has not resolved it` | nothing has reported a neighbour for the next hop | `ip neigh show <nexthop>`; on an IX, the snooper |
| `not a VPP port` | the neighbour is on a device that is not a member port | add the `port`, or the route is not VPP's to carry |
| `VLAN N on P, which is not a VPP port` / `VLAN N is not declared on port P` | a VLAN device over a non-member, or a vid missing from `port … vlans` | the `port` line |
| `bridge neighbour …` | the FDB has not placed it behind a member, or it is behind a non-member or a tagged VLAN with no BVI | see [bridge neighbours](#bridge-neighbours-placed-per-neighbour-from-the-fdb) |
| `… and IPv6 has no steer-exempt, so diverted traffic for it would be dropped in VPP …` | a v6 route via the router outside its subnets and addresses; never left to the kernel (shape 3 is v4 only) | the feed, a `steer-keep6`, or dropping `v6-divert` |
| `the router's own address, which VPP has no adjacency for; …` | every next hop is the router, and none of the kernel-delivered shapes held. The rest of the reason says how the kernel answered for exactly that prefix: `sends this prefix out <dev>, which VPP can reach` (a transit route under `next-hop-self`: the feed is wrong), `drops it (blackhole, unreachable or prohibit)` (an aggregate the router originates; VPP would send its traffic down a less-specific route, so it is not left to the kernel), `has no route of its own for exactly this prefix`, `could not be read`, or `was not asked` (the per-walk lookup budget was spent) | `ip route get <prefix-address> fibmatch` shows the same entry the module read |
| `reachable now; …` | the neighbour arrived after the route was classified | nothing: it is re-programmed with the neighbour |

`packetframe fib dump-v4 --unresolved` is **not** the place to look for
these. That lists routes whose next hop the fast path has not resolved;
a route whose next hop the kernel *has* resolved, on a device VPP does
not own, is resolved there and unresolvable here. And the router's own
connected and static routes show up there as `state=incomplete` (the
fast path labels those next hops `local`) while VPP counts them as
kernel-delivered.

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

### After a reboot: "state records VF … but no VF exists"

Builds before the earlier-boot check refused every attach after a
reboot. A reboot delivers SIGTERM, whose exit keeps
`vpp-offload.json` for adoption, and the reboot then removes
everything the file names: VFs, vfio bindings, the hugepage
reservation, the VPP process and the MCAM rules. The next attach
checked the recorded ports against VFs that no longer existed and
refused. The fast-path stayed up (the degrade path), but VPP stayed
down until someone ran `detach --all`.

The record now carries the `boot_id` it was written under. A record
from an earlier boot is logged (`state file is from an earlier boot`),
discarded, and acquisition starts fresh. Files written before the
field fall back to `vpp_boot_id`, which is present whenever a VPP was
running at shutdown. If neither side's boot is known, the adoption
checks still apply, and they refuse rather than guess. On an older
build, the remedy is the full sequence:

```bash
systemctl stop packetframe && packetframe detach --all && systemctl start packetframe
```

### Attach or `detach` refuses: "refusing …/vpp-offload.json: …"

`vpp-offload.json` decides what this root daemon acts on. It names the
VPP process an attach adopts and a teardown may SIGKILL, the VFs it
unbinds, the hugepage reservation it hands back and the MCAM rules it
deletes. It also holds the token the
[preserved route ledger](#what-a-keep-vpp-restart-costs-now-the-preserved-route-ledger)
must match. So it is read only when no other account could have
written it or put it in place, and only up to 16 MiB. Both are judged
on the open file, before a byte of it is read:

- the file is a regular file owned by the daemon's uid (root) and not
  writable by group or others;
- so is `state-dir`, the directory holding it;
- every directory above `state-dir` is owned by root and is either not
  writable by group or others or sticky (as `/tmp` is), so nobody else
  can rename `state-dir` away and put another in its place;
- no component of the path is a symlink.

**A refusal is never read as "no file".** Attaching fresh over
resources the file records would acquire them twice, so the attach
fails instead. `packetframe detach --all` refuses too (it acts on
nothing it cannot vouch for), and so does the `--keep-vpp` preflight.
The directory is judged even when the file is absent: an account that
can write `state-dir` can delete the record. A **reload** is not
refused, because a reload that turns one port off still re-plans the
others and must stay a rollback lever. It plans without the record
and logs `state file unreadable; this reload plans steering without
reclaiming the module's own recorded rules`. A steer it plans can then
be refused for MCAM budget, because the module's own rules read as
occupied; that refusal comes from the file, not the allowlist.

The message names the check that failed. See what the path holds (the
default `state-dir` shown):

```bash
stat -c '%U:%G %a %F %n' / /var /var/lib /var/lib/packetframe /var/lib/packetframe/state /var/lib/packetframe/state/vpp-offload.json
```

If the file is there, check it is the daemon's before trusting it
again: its `vpp_pid` is the running VPP, and its `vf_pci` addresses are
the VFs bound to `vfio-pci`.

```bash
jq '{vpp_pid, ports: [.ports[] | {iface, vf_pci}], steer_rules}' /var/lib/packetframe/state/vpp-offload.json
```

```bash
pgrep -a vpp
```

```bash
ls -l /sys/class/net/eth4/device/virtfn0 /sys/bus/pci/drivers/vfio-pci/
```

Then make it and `state-dir` root-owned and closed to group and
others, and retry:

```bash
chown root:root /var/lib/packetframe/state /var/lib/packetframe/state/vpp-offload.json
```

```bash
chmod 755 /var/lib/packetframe/state && chmod 600 /var/lib/packetframe/state/vpp-offload.json
```

A directory above `state-dir` that the message names gets the same
`chown root:root` and `chmod go-w`. A symlinked `state-dir` cannot be
made acceptable: point `state-dir` at the real path. If the record is
not the daemon's, or you cannot tell, handle it as the oversized file
below.

**"past the 16777216-byte bound".** A real file is a few KB, and the
widest the module could write is ~12 MB, so this one was not written
by it whole (a sparse or corrupt file). Treat it as a torn file: check
that nothing it could record is live (`pgrep -a vpp`, `ethtool -n
<port>` for rules steering into a VF, `sriov_numvfs` under each
port's `device/` for VFs), release by hand whatever is, then remove
the file.

### VPP is gone after `systemctl stop`, but its steering rules are not

On builds whose unit has `KillMode=mixed`, every stop kills VPP. Look
for this in the journal (on builds with the preserved route ledger the
first line reads `preserved VPP's route ledger for the next daemon` or
`VPP's route ledger was not preserved` instead):

```
packetframe: vpp-offload supervision dropped without stop(); VPP is left running and adoptable
systemd: packetframe.service: Killing process <pid> (vpp_main) with signal SIGKILL.
```

VPP runs in the unit's cgroup, and `mixed` makes systemd SIGKILL
whatever is left there once the daemon exits, so preserve-on-exit never
worked under systemd. Anything steered at that moment keeps its MCAM
rules while the VF behind them is dead, so that traffic is dropped
until `packetframe detach --all` removes the rules. After a crash,
systemd's start limit gives up and nothing removes them. Check with:

```bash
grep KillMode /lib/systemd/system/packetframe.service
```

The unit now ships `KillMode=process`, so VPP outlives the daemon as
designed. The documented teardown (`systemctl stop packetframe &&
packetframe detach --all`) removes steering before it terminates VPP,
so it no longer opens a window where traffic goes nowhere. After
installing a new deb, run `systemctl daemon-reload`, or the old mode
stays in effect.

The unit also sets `LogsDirectory=packetframe`. VPP logs to
`/var/log/packetframe/vpp.log` and does not create the directory, so
on a box without it, VPP ran with no log at all.

### The offload restarts repeatedly

**Two places carry the reason; read both.** `packetframe status` holds
it on the **`last-tick`** row — sticky, retained across the empty
backoff ticks that follow a failure, so a slow poll cannot miss it. Do
not grep status for only the subsystem names you expect: the 2026-08-13
primary incident was diagnosed blind because the status reads filtered
out exactly this row, and the reason died with the daemon. The
**journal** now carries it permanently: every teardown logs
`supervisor ordered VPP teardown` (WARN, with the triggering event and
the state transition) and every failed step logs
`supervised action failed` (WARN, with the action and its error) —
`journalctl -u packetframe | grep -E "teardown|action failed"`
reconstructs a loop after the fact. The counter of failures is not the
reason.

If the reason mentions a CRC or version mismatch, supervision has
*ended* rather than looping: the binary API is permanently incompatible
and no retry can fix it. The installed VPP is not the pinned one.

If the box itself is degraded while the loop runs — climbing load,
sluggish ssh, `birdc` timeouts in the fast-path integrity row — check
NIC queue IRQ affinity against the VPP cores first (see
[IRQ affinity before attach](#irq-affinity-before-attach)); on builds
carrying the check, attach refuses this shape before it can start.

A socket timeout (`Resource temporarily unavailable`) or `binary API is
not connected` during attach, resync or verify no longer restarts
anything on current builds. The section after next covers it. If a loop
like that still shows `event=ConvergenceFailed`, the step was
*refused*, and the error text says by what.

### A teardown with `cause=Wedged`

The wedge detector decided VPP had stopped answering its binary API:
silent past the budget, which is **1.5 s while steered** and 10 s for an
unsteered convergence. Silent means it answered *nothing*: no ping, and
no reply to anything else the module sent, such as a route batch or a
verify probe. A VPP that keeps answering a long route burst is busy,
not wedged, however late a ping queued behind that burst comes back.
On a steered gateway a teardown is expensive. Traffic
returns to the eBPF tier, and the fresh VPP is not steered again until
its table has reloaded and verified. The journal line just before the
teardown gives the evidence, and the `vpp_teardown` event carries the
same fields:

```
WARN VPP's binary API stayed silent past the wedge budget; calling it wedged. ... silent_ms=2004 counted_ms=2004 budget_ms=1500 steered=true unanswered_probes=2 last_probe_error="socket I/O: Resource temporarily unavailable (os error 11)" vpp_wait_ms=1998 loop_gap_ms=48 stalls_excused=0
```

How to read it:

- **`vpp_wait_ms` close to `counted_ms`.** VPP kept the loop waiting.
  The thread that answers the API is VPP's main thread, which is not
  the thread that forwards. The workers may have been forwarding
  throughout, and this detector cannot see them. Look on VPP's side for
  what held the main thread (`/var/log/packetframe/vpp.log`,
  `vppctl show log`). The module's own work is the first suspect. Each
  next hop that loses and regains resolution costs a neighbour delete
  and a neighbour add, and in VPP each of those walks every route that
  resolves through the adjacency, on the main thread and under the
  worker barrier. A bridge next hop that comes back also re-sends every
  route through it. Look for `nexthop lost resolution` and `nexthop
  re-resolved` in the journal around the time, and for
  `packetframe_vpp_pending_ops` climbing. A plugin following the
  kernel's routing table is not a candidate: VPP's `linux_cp` and
  `linux_nl` plugins ship disabled by default and are not loaded on the
  reference build (`vppctl show plugins`).
- **`last_probe_error`.** `Resource temporarily unavailable` means a
  request hit its socket deadline. `reconnect refused: …` means VPP's
  socket would not take a connection or finish the handshake within
  500 ms. `did not accept the connection` means VPP stopped draining
  its socket's backlog.
- **`loop_gap_ms` large and `vpp_wait_ms` small.** The supervision loop
  itself was away: blocked in the kernel, or not scheduled. Such a
  stall is excused (below), so a wedge with this shape had VPP silent
  for a full budget after the loop came back as well.
  `stalls_excused` counts the stalls in that silence.

**A stall of the loop is not VPP's silence.** The loop that pings VPP
also makes kernel calls that wait on `rtnl_lock`: the steering audit's
ethtool ioctls and the hand-back path's netlink reads. When the kernel
holds that lock, the loop sends no pings. On a production gateway, a
bridge going down with a full table appears to have held it for about
40 s. Those 40 s used to count as VPP's silence, so one unanswered
probe after the loop resumed was enough to tear down a steered VPP.
Now a pass that arrives more than the budget after the previous one
restarts the measurement. Time spent waiting on VPP's own
socket does not count toward the gap. The journal says when this
happens:

```
WARN the supervision loop was away longer than the wedge budget, and not waiting on VPP — a stall of this host or of PacketFrame itself. ... loop_gap_ms=40112 budget_ms=1500 steered=true silent_ms=40112
```

From there VPP is called wedged only if it stays silent for the full
budget across fresh probes. For a VPP that really hung, that is at
most 2 s after the loop resumes: the usual bound, measured from the
resume. A broken connection is not counted as silence either. If
something else dropped the socket in the meantime, such as the
error-counter read in the status publish, the probe reconnects
first. A socket the drain loses on the same pass is reconnected at the
start of the next pass, one ping interval into the budget. Two limits
stop this from hiding a dead VPP:

- Time the loop spends blocked on VPP's socket is never excused. A
  hung VPP holds every probe for the full deadline, and that wait is
  the evidence. A reconnect counts the same way. It gives up after
  500 ms, the socket's own connect included, so a VPP that stopped
  accepting connections cannot park the loop inside one.
- Once VPP has missed more probes than the budget tolerates as jitter
  (two, while steered), a later stall no longer erases them. The
  journal then says `VPP had already left more probes unanswered than
  jitter explains`.

A VPP that exits is caught by its pidfd whatever the loop is doing.

### `binary API lost; VPP is not torn down for this` during a convergence

A convergence step (attach, resync start, a resync drain, or verify)
lost the binary API. Either a reply took longer than the socket
deadline, which is `EAGAIN` on the API socket, or the socket closed.
VPP is held as it is and the step is resumed on the same process. It
is not killed, steering is not touched, and no failure is counted.
The journal shows:

```
WARN supervised action failed action=AttachDevices error=socket I/O: Resource temporarily unavailable (os error 11) (binary API lost; VPP is not torn down for this — ...)
WARN convergence step lost the binary API; holding VPP rather than tearing it down — ... step=Attach attempt=1 retry_in=500ms
INFO binary API answering again; resuming the interrupted convergence step
```

A drain that loses the API mid-resync logs `resync drain lost the
binary API; reconnecting, and resuming the drain on the same VPP once
it answers a ping` instead. Those ops were requeued, so the retry is
idempotent. It waits for the same backoff and post-loss ping as a
resumed step, so a persistently starved VPP is not sent a full batch
on every tick.

**Why.** On a CPU-starved host (softirq around 60% during a daemon
restart), an adopted VPP's route dump hit its socket deadline. The
`EAGAIN` was treated as a failed pipeline, and the supervisor killed
the adopted VPP. It then killed three fresh spawns whose attach timed
out the same way, and the fourth re-converged about 1.09M routes from
nothing. VPP was slow, not dead. A teardown is the most expensive
recovery there is. On a steered adoptee it is also a dangerous one:
steering has to come down first, and a respawn restarts the octeon port.

**What resumes it.** The daemon reconnects, and the step is re-issued
only after VPP has answered a ping sent *after* the loss. Reconnecting
alone proves nothing about VPP's main thread. Resumes back off from
500 ms, doubling to an 8 s ceiling. The resume restarts from the
earliest step that did not finish. An attach that lost the API is
re-run together with the resync queued behind it, and nothing is
drained until the attach completes.

**What still tears it down.** The same evidence as always:

- the process exits (pidfd);
- VPP stays silent past the wedge budget: **1.5 s while steered**,
  which is the published bound and applies to a steered adoptee
  exactly as before, or 10 s for an unsteered convergence. It is
  measured while the supervision loop is running; see [A teardown with
  `cause=Wedged`](#a-teardown-with-causewedged);
- the convergence deadline runs out — 120 s on a small table, scaled
  up to 600 s on a big one (see [What a keep-vpp restart costs
  now](#what-a-keep-vpp-restart-costs-now-the-preserved-route-ledger)).
  An interruption never extends it, so a step that keeps losing the API
  while VPP answers pings ends there;
- a *refusal* (VPP answered and said no) is `ConvergenceFailed` at
  once, as before.

**A fresh VPP whose `dev_attach` had already landed** refuses the
resumed `dev_attach`. That refusal is an ordinary `ConvergenceFailed`,
so the fresh case ends where it did before, a few seconds later. An
adopted VPP reuses its recorded interfaces and resumes cleanly.

**The socket deadline during attach now matches the detector.** An
unsteered attach and the adoption's route dump used to run under the
steady 1.5 s deadline, while the wedge detector allowed 10 s for the
same moment. That mismatch is how the dump above timed out: it streams
for about 7 s at the reference table. Both now get the convergence
budget. So a `stop` issued during an unsteered convergence can wait up
to 10 s for a blocked request, the same as during a resync drain.

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
| ntuple `loc` space | **16 per port** (0..=15) at the driver default; up to 256 with `steer-capacity` | measured on the shadow's eth1 2026-08-05, by insert-and-read-back; the default is the driver's `mcam_count`, raised and re-measured on the rig 2026-09-24 (`loc 40` refused at 16, accepted at 256). |
| NPC MCAM block | 2048 entries, ~1689 free, 31 allocated per PF | from `npc/mcam_info`. **This is not the `loc` space** and must never be used to size one — doing so is what produced `base: 1024`, an out-of-range slot that failed the first steer this module ever attempted. |
| First steer | **4 rules installed and readback-verified** | 2026-08-06, shadow eth1, locs 15/14/13/12, src+dst × 2 prefixes → VF 0. Installation only: eth1 carries the interconnect, so zero packets match. |
| Steered-idle soak | **5 h 17 m**, rules intact, no restarts | 2026-08-06 overnight. Proves nothing wiped them. Survival of one UniFi provisioning push was observed later, on a lab box on one firmware; untested across firmware. |
| keep-vpp restart with a preserved ledger | **zero unsteered time, no dump**; external probe through VPP lost 1/420 (fast-path's link bounce) | reference router, first 2026-09-27 at ~1.09M routes, repeated at IPv4+IPv6 ~1.34M with the hand-back path. The fallback (no preserved ledger) measured ~3 min unsteered. |
| Softirq with no bypass (before PacketFrame) | si **~74%** | reference deployment, April 2026: every forwarded packet on the kernel's conntrack + iptables path, full tables, 2–3 Gbps forwarded, `si` across all ksoftirqd threads. The same box reached 90–100% total CPU and locked up at ~4 Gbps. |
| Softirq with the PacketFrame FIB empty | si **71%** | reference deployment, 2026-09-11, box-wide `si` from `top` after a reboot: until the FIB converged every flow fell back to the kernel path, so this is the no-bypass figure again. Load 27. Every empty-FIB window costs this. |
| Softirq, eBPF fast-path only (before VPP) | si **31–62%** | reference deployment, 2026-09-26, box-wide `si` from `top`, off-peak, immediately before the first production steer. |
| Softirq, IPv4 steered into VPP at launch | si **11–19%** | reference deployment, 2026-09-26, box-wide `si` from `top`, off-peak, same window as the row above: four ports, both directions. |
| Softirq, IPv4 steered, IPv6 still on the eBPF tier | si **~15.7%** | reference deployment, 2026-09-27/28, box-wide `si` from `top`, off-peak. The baseline the four rows below are read against. |
| Softirq after `v6-divert` on the customer VLAN only | si **~6–8%** | reference deployment, 2026-09-27/28, box-wide `si` from `top`, off-peak. |
| Softirq after `v6-divert` on all upstream VLANs plus untagged transit | si **~2.2–2.7%** | reference deployment, 2026-09-27/28, box-wide `si` from `top`, off-peak. |
| Softirq, overnight steady state (IPv4 and IPv6 steered) | si **~0.8%** | reference deployment, 2026-09-27/28, box-wide `si` from `top`, off-peak. |
| Softirq after the 0.5.0 RC keep-vpp restart | si **~1.0%** | reference deployment, 2026-09-27/28, box-wide `si` from `top`, off-peak. The CHANGELOG's 0.5.0 highlight is read from this block: no bypass ~74%, eBPF only 31–62%, IPv4 in VPP 11–19%, IPv6 in as well ~1%. **No peak-hour reading exists with IPv4 and IPv6 both in VPP**; every figure after the launch rows is off-peak. |
| Drill (a) kill -9 under load | teardown **325 ms**, recovery **40.7 s** | 2026-08-08, 500 pps constant-rate flow. The 50 ms teardown target was missed and is documented as a bound; recovery ≤ 90 s holds with margin. |
| Drill (b) route change while down | **PASS** | the changed route was present in VPP before steering resumed. |
| Drill (c) SIGSTOP wedge | detected in **1.81 s** (target ≤ 2 s) | 2026-08-08, ping-interval-bounded as designed. |
| Drill (d) daemon death | **120,000/120,000 frames, zero loss** | 2026-08-08. The dataplane forwards independently of the daemon. |
| Drill (d) restart over a steered VPP | **150,000/150,000 frames, worst gap 0.109 s** | 2026-08-09 (d12). Full cycle inside the window: adopt → defer → unsteer at +40 s → FIB dump against an idle VPP (~7 s of frozen workers, felt by nobody) → diff (2.5 h of churn reconciled) → verify → re-steer at +78 s. The 5.4 s outage of the pre-#151 design is gone. |
| PMTUD through a steered path | **PASS** | frag-needed, mtu 1300, sourced from 169.254.254.3, ×5. Gate 0b item 7 closed. |
| Steered packets reaching VPP | **PASS** | gate 0b item 1 closed 2026-08-07: allowlisted frames counted on octeon0/0, non-allowlisted stayed on the kernel path. |
| Restart health window | Degraded ~40–80 s | see the note below — the deferral and reconcile are visible by design. |
| `detach --all` | **2.814 s** with one VF; **4.91 s** with two | One VF: 2026-08-11 shadow, a live VPP holding 1.05M routes. Breakdown: pins removed in 1 ms, then 2.80 s terminating VPP + rebinding the VF + restoring hugepages. Two VFs: the dev rig's D7 run, two steered VFs, timed as `systemctl stop packetframe && packetframe detach --all`. Both miss the published <1 s. **More than two VFs is not measured**: the reference router runs four, and anything said about its teardown time is an extrapolation from these two points, not a measurement. |
| Interconnect blip during `detach --all` | **none** | same run, 5 Hz ping from the primary across the teardown: zero gaps >0.5 s, one 30 ms spike. Writing `sriov_numvfs=0` does not disturb the PF link. |
| `ip_route_dump` at adoption | **7.04 s** for 1,054,548 routes | 2026-08-11, timed directly rather than inferred from a traffic gap. This is the barrier-sync freeze §the deferral exists to keep away from steered traffic. |
| Adopted restart, UNSTEERED | ~53 s start→verified | 2026-08-11. Dump at +7 s, deferral held 32.8 s waiting for the mirror, diff+verify after. No traffic impact — nothing was steered. |
| Cold bring-up (nothing running) | **11.4 s to `healthy`, ≤61 s to full table** | 2026-08-11. Read the caveat: `healthy` at 11.4 s meant **110,724 routes** — 10% of the table, verified clean. See "A verified FIB is not a complete one". |
| Fresh six-port attach on the PRIMARY, behind bird's live dump | **~5 min in `Syncing` (held), then one verify** | 2026-08-13, w9 + w10: the #180 hold engaged at have≈23k and released at have≈1,055k; w10 verified PASS 64/64 on the release. This is the number to expect on every primary fresh attach — the 40.32 s row above is a resync from an already-loaded mirror, a different situation. |
| Load while VPP runs, six workers | **~+7 load permanent** (poll mode), ~22 total during convergence vs ~6 baseline | 2026-08-13 w10. See the load note below. |
| `reconfigure` (lever move) | **0.215 s** | 2026-08-11, exit 0, writes `OK <ns>` to `last-reconfigure.timestamp`. |
| Coexistence squeeze, unsteered at evening peak | `time_squeeze` 7/s → 46/s; **6–8% loss** through the box; every counter clean | 2026-08-13 w13/w17, six workers, steering off. See the coexistence-squeeze section. |
| TX-ring intervention (eth3 4096 → 32768) | loss 0/500 — but avg RTT **678 ms** (bufferbloat) | 2026-08-13 w18. Proof of the silent-drop mechanism, **not a fix**; ring restored. |
| `netdev_budget` ×4 (300→1200, usecs 20000→80000) | `time_squeeze` → 0; loss 1%; local-segment RTT >100 ms on 22% of pings | 2026-08-13 w19. The deficit moved into 80 ms softirq rounds; settings restored. |
| First steer on the primary (eth4, `src`, trunk, no subifs) | MCAM+VF+VPP rx flawless at ~72 kpps; **8.7M frames punted in 2 min, zero forwarded** | 2026-08-14 w20. Tagged ingress, no dot1q subif → punt at ethernet-input. The `vlans` port directive exists because of this window. |
| Second steer (subifs present, VF answering to the port's own MAC) | subif classified 7.19M frames in 90 s (**punt-at-VLAN-layer gone**); 7.17M then punted on dmac — hosts address switch0's `…:c7`, the VF held eth4's `…:ca` | 2026-08-14 w21. Auto-aborted by the harness's 90 s blackhole guard. The secondary-MAC acceptance exists because of this window. |
| Third steer (bridge MAC as the member's PRIMARY) | VPP forwarded **~500M packets in 27 min**, split by best path (266M eth3, 236k eth2), zero loop, no drops on the forwarding path — **but ~300 kpps arrived from ATTACH, with the lever off** | 2026-08-14 w22. Forwarding quality proven; staging isolation broken. The primary MAC is a hardware filter on this NIC, so it must stay the port's own — acceptance belongs in secondary addresses. Undeclared trunk VLANs (`unknown vlan` 180k) were blackholed for the window. |
| Fourth steer (secondary MAC + `.254` loopback — the clean pass) | Leak gate ~50 pps noise (lever off); 95.9M rx / 95.8M tx at +300 s; ARP replies **zero**; steered minutes ~0.1% remote loss vs 4–7%/min on the unsteered rung-0 stretch of the same window | 2026-08-14 w23. Rung 1 validated; **the steered path beat the XDP path by >10× under coexistence**. Residual: 110,917 locally-terminating packets blackholed in 5 min — the number `steer-exempt` exists to zero. |
| Fifth steer (exemptions live — w24) and hours-scale soaks (w25/w26) | w24: `rules-installed=6`, svc-pinger survived the steer for the first time, steered minutes ≈ zero remote loss. w25: 105 min steered, heap flat at 844.6M/2.5G across every snapshot, one daemon pid, SIGHUP auto-rollback exercised live. w26: full 2 h + the B1 delivery gate (`.7/32` via `octeon4/0.1337` before any steer) | 2026-08-14→16. The w25 SSH drop proved the trap rollback unattended; harnesses run detached since. |
| The default-route drop counter under steering — decomposed by destination profile | Pre-exemption ~365 pps; **~50+ pps of it was live inter-site traffic** (vti64-bound: ord1's /24 + seven host routes inside the local /24), silently one-way-blackholed in EVERY steered window w23→w26; the remaining **~155 pps is the junk floor** (misdirected VPN/overlay to RFC1918/CGNAT, SSDP, bogons — dies on the kernel path too, upstream and invisibly) | 2026-08-16/17 w26/w26b. Exemptions zeroed the real-traffic share: w26b held 153–170 pps flat for 30 min with 14 rules, tcpdump proofs 5/5 on eth2 (inter-site) and 5/5 on vti64 (tunnel /32s) WHILE steered. The floor is expected; alarm on rate CHANGE. |
| Idle draw with VPP polling one worker | 33.56 W, 38/49/42 °C, fan 3780 RPM | 2026-08-11 shadow, chassis total — NOT a VPP attribution, no VPP-off baseline was taken. |
| VPP software forwarding cost, one worker | **123 ns/packet** (~8.1 Mpps per core); the same at 64, 750 and 1400 B | 2026-09-28, dev rig (same SoC, 5.15 vendor kernel and VPP 26.06 octeon build as the reference deployment). `packet-generator` into `ip4-input`, 14,643 /24 routes, full 256-packet vectors, active nodes only. **Excludes NIC receive and transmit.** Method: [Per-core forwarding capacity](#per-core-forwarding-capacity-packet-generator-method). |
| Per-node split of the 123 ns | ip4-input **27**, ip4-lookup **27** (14.6k routes), ip4-rewrite **35**, interface output **12**, generator-interface tx **23** (stands in for the NIC) | Same run. Each node is rounded, so the parts sum to 124. |

**Published but never measured:** `detach --all` across **more than
two** VFs. The one-VF (2.814 s) and two-VF (4.91 s) teardowns are
measured above; the reference router's four-VF teardown has not been
timed, so budget for it by extrapolation and measure it on the next
full teardown there rather than quoting a figure.

### Per-core forwarding capacity (packet-generator method)

The two per-core rows above were measured on the dev rig with VPP's
built-in `packet-generator`, so no traffic source and no NIC are
involved. One stream, pinned to worker 0, injects at `ip4-input` on a
generator interface bound to a separate FIB table (99). That table
holds 14,643 /24 routes, all via a static neighbour on a second
generator interface, and the destination address walks the whole range
so every route is used. Run it on the dev rig, never on a forwarding
box: the stream takes worker 0 away from real traffic. Cost is read
from `show runtime` over a 10 s window after `clear runtime`:
confirm the vectors are full (Vectors/Call 256), then add up the
active nodes, leaving out `pg-input` (the generator's own cost).
Packet size does not move the result, because VPP never touches the
payload.

```sh
V="vppctl -s /run/packetframe/vpp/api.sock.cli"
awk 'BEGIN{for(i=0;i<14643;i++) printf "ip route add 100.%d.%d.0/24 table 99 via 198.18.0.2 pg1\n", 64+int(i/256), i%256}' > /root/pg-routes-add.cli
sed 's/^ip route add/ip route del/' /root/pg-routes-add.cli > /root/pg-routes-del.cli
$V create packet-generator interface pg0
$V create packet-generator interface pg1
$V ip table add 99
$V set interface ip table pg0 99
$V set interface ip table pg1 99
$V set interface ip address pg0 192.0.2.1/24
$V set interface ip address pg1 198.18.0.1/24
$V set interface state pg0 up
$V set interface state pg1 up
$V ip neighbor pg1 198.18.0.2 02:00:00:00:00:20 static
$V exec /root/pg-routes-add.cli
$V show ip fib table 99 100.64.0.1/32   # forwarding must read "via 198.18.0.2 pg1", not drop
# one stream per size; the payload is size minus 28 (IPv4 + UDP headers)
$V packet-generator new "{ name pf750 limit 100000000 size 750-750 worker 0 interface pg0 node ip4-input data { UDP: 198.51.100.1 -> 100.64.0.1 - 100.121.50.1 UDP: 1234 -> 5678 incrementing 722 } }"
$V packet-generator enable-stream pf750; sleep 3
$V clear runtime; sleep 10; $V show runtime > /root/pg750.txt
$V packet-generator disable-stream pf750
# cleanup
$V packet-generator delete pf750
$V exec /root/pg-routes-del.cli
$V ip neighbor del pg1 198.18.0.2 02:00:00:00:00:20
$V set interface ip address del pg0 192.0.2.1/24
$V set interface ip address del pg1 198.18.0.1/24
$V set interface state pg0 down
$V set interface state pg1 down
$V set interface ip table pg0 0
$V set interface ip table pg1 0
$V ip table del 99
```

The two generator interfaces stay, down and unaddressed, until VPP next
restarts. The destination steps by one address per packet, so each
256-packet vector falls inside a single /24 and the lookup runs
cache-warm; together with the small table, that is why the 27 ns lookup
is a floor, not the full-table figure.

Pitfalls:

- **A route via a link-down interface resolves to drop.** A first
  attempt used a real port with no cable as the output and measured
  lookup→drop, not forwarding. Output to a generator interface.
- **Never point the generator at a port with carrier.** The stream
  would leave the box onto a real link.
- **`Clocks` is not CPU cycles on this SoC.** It counts ticks of the
  100 MHz system timer, 10 ns each (`show cpu` reports ".1000 GHz").
  Multiply by 10 for nanoseconds.
- **Polling input nodes' clocks include idle polling time.** Take the
  per-packet cost from active nodes only.

**Estimated, not measured: what this means on the reference
deployment.** The rig figure leaves out NIC I/O. At the reference
deployment's production batches of 1–5 packets, the octeon `-tx`
node's cost in its live `show runtime` fits a fixed cost per batch plus
about **70 ns per packet** (7 data points), so NIC transmit at full
batches is estimated at ~70 ns per packet. NIC receive could not be
separated from idle polling and is assumed similar. Add the 1.3M-route
table (the same kind of fit puts ip4-lookup at ~50–70 ns, against 27 on
the rig), the bridged-VLAN layer-2 nodes, and the IPv6 share
(ip6-lookup costs about 2.4× ip4-lookup), and the estimate is **about
300–400 ns per packet, ≈ 2.5–3.3 Mpps per core**: ≈ 15–20 Gbps per core
at a ~750-byte average packet, ≈ 28–37 Gbps at 1400 bytes. For
comparison, the tuned generic-XDP path's measured per-packet CPU is in
[generic-mode-performance.md, IRQ
coalescing](generic-mode-performance.md#irq-coalescing-the-cheapest-measured-win-on-this-fleet).
That figure includes NIC receive and the kernel path, so set it against
this estimate, not against the rig's 123 ns: it is roughly 28–37 times
more CPU per packet.

**What that means for `cores`.** A port has one worker and one receive
queue unless `cores N` says otherwise. At a ~750-byte mix a 25G port's
single worker saturates around 15–20 Gbps by the estimate above, so
give a port `cores 2` as it approaches ~12 Gbps. That is
restart-only, like every `cores` change.

### A fresh attach on a full-table box holds in `Syncing` for minutes. That is the fix working.

A FRESH attach (no VPP to adopt) under `require-table-complete on`
converges *behind* bird's dump: routes install as they arrive, and the
one readback verify waits until the completeness authority confirms
the table. On the primary that is **~5 minutes of `Syncing`**,
measured twice (2026-08-13, w9/w10). The status row says so while it
holds:

```
fib-synced   DEGRADED — fresh convergence: routes install as the
             source loads (mirror holds N of the authority's M) ...
```

and the log brackets it with `fresh resync is idle but the route
source has not converged` and `route source converged and drained;
fresh resync complete — verifying the full table`. Do not restart it,
and do not page on it — the state before this hold existed was seven
kill-respawn cycles in 31 s over an empty table (w7), and a restart
re-enters the same dump from zero.

A verify that ends `INCOMPLETE — steering refused, no restart` is the
same philosophy after the hold releases: the FIB is not fit to divert
traffic into (unresolvable routes, or nothing sampled), but nothing a
teardown fixes is wrong. `FAIL` is reserved for probe mismatches —
the one verdict a restart genuinely repairs — and only `FAIL`
tears down.

`fib-synced` reports it **Degraded, never Unhealthy**, for the same
reason, and prints the verdict's age and the live table beside it:

```
fib-synced   DEGRADED — verify INCOMPLETE — steering refused, no
  restart: 0/0 probes matched, unresolvable=0, withheld=0 (verify ran
  1847s ago and re-runs on its own once the table holds no unresolvable
  route and no unexempted kernel-delivered prefix; the table now holds
  69155 installed, 0 withheld, 0 unresolvable)
```

A verdict that failed only on unresolvable routes, unexempted
kernel-delivered prefixes or an empty sample is **re-run once the table
is clean** (see [the re-run](#the-one-re-run-a-stale-incomplete-verdict)),
so this line no longer outlives its cause by more than a few seconds. One
that failed for any other reason (a dark member carrying routes) says
`does not re-run in steady state` instead.

Read the parenthesis first. Verification is a convergence-time gate, and
**the live steering gates never consult this verdict** — they re-read
the route counts, the source backlog and the authority on every retry.
So a box whose first verify ran before its feed landed recovers and
steers on its own, with this line still quoting the empty-mirror window.
A large installed count next to `0/0 probes matched` is that recovery,
not a contradiction. On the lab rig (2026-09-21) the row paged as
UNHEALTHY while 69,155 routes forwarded; it does not any more.

If the counts in the parenthesis are *also* bad — nonzero
`unresolvable`, or an installed count that never grows — the condition
is live, and it is the counts, not the verdict, that say so.

### Load rises by roughly one core per VPP worker, permanently. That is poll mode, not a fault.

The native octeon driver supports neither interrupt nor adaptive rx
mode (gate 0b item 9), so every VPP worker is a pure poll loop pinned
at 100% — load average counts always-runnable threads, so six member
ports at `cores 1` add ~7 to load (workers + main) for as long as VPP
runs, forwarding or idle. w10 measured ~22 during convergence against
a ~6 baseline: ~7 of that is the permanent poll cost, the rest was
bird's dump plus the daemon feeding two tiers, and it subsides when
convergence ends. Load average here is not starvation: the worker
cores are deliberately vacated (daemon threads restricted away, NIC
IRQs moved off them pre-attach), and w10's own counters showed the
eBPF tier matching and forwarding normally throughout
(`matched_v4` ≈ `rx_total`, `fwd_ok` climbing). Whether ~7 hot cores
buy enough forwarding is exactly what the steering canary measures.
Members that only transmit do not need their own: `cores 0` gives them
no worker of their own (see the canary ladder).

Do not stop reading at "the counters are fine", though — the next
section is about exactly the loss those counters cannot see.

### Loss and latency through the box while VPP runs unsteered — the coexistence squeeze

Root-caused 2026-08-13 (w12–w19) after three windows of "every counter
is clean but users see loss". Symptom set, at traffic peak, with VPP
attached and **steering off**:

- packet loss (measured 6–8%) and multi-hundred-ms latency for traffic
  forwarded *through* the box, reported from outside;
- load average far above the ~+7 poll-mode floor;
- every packetframe counter normal, `fwd_ok` climbing, VPP counters
  near zero, NIC error counters zero.

The mechanism is **not VPP malfunctioning — it is VPP's poll cores
starving the kernel path that still carries 100% of the traffic.** At
the staging rung nothing is steered, so all forwarding is generic XDP
on the CPUs that remain; the squeeze truncates NAPI polls, the egress
TX ring fills, and `generic_xdp_tx` drops frames **silently** — no
counter on this 5.15 kernel, invisible to tcpdump and qdisc stats by
construction, and counted as success by `fwd_ok` (which increments at
redirect *acceptance*). Full mechanism, diagnosis steps, and why every
instrument is blind: `docs/runbooks/generic-mode-performance.md`,
"Silent TX drops under generic XDP".

What to do about it, in order:

1. **Recognize it**: watch `packetframe_softnet_time_squeeze_total`
   (exported since this finding). Baseline on the reference EFG is
   ~7/s; the loss windows ran ~46/s.
2. **Do not reach for kernel knobs as a fix.** All three were
   measured; each just relocates the deficit (drops → ring bufferbloat
   → 80 ms softirq rounds). They are diagnostics.
3. **Shorten the unsteered window.** The staging state is
   maximum-cost-zero-benefit by design — all of VPP's CPU tax, none of
   its forwarding. Schedule attaches and soaks off-peak, and treat
   time-at-rung-0 as a cost to budget, not a neutral holding state.
4. **The durable fixes** are fewer VPP cores while unsteered — give
   every member that is not about to steer `cores 0`, so they add at
   most one worker between them (restart-only) — and climbing to the steered rungs — steering moves
   allowlisted traffic onto VPP's hardware path *and* removes its XDP
   cost from the squeezed CPUs, which is the intended end state, not a
   workaround.

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
0.109 s. That is the DUMP path (on the reference router's full table,
~3 minutes unsteered); a clean `--keep-vpp` restart that left a
preserved route ledger holds the same Degraded line for the deferral but
never unsteers — measured on the reference router at zero unsteered
time, see [What a keep-vpp restart costs
now](#what-a-keep-vpp-restart-costs-now-the-preserved-route-ledger).

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

**A second unbounded case, and this one takes the rollback lever with
it: the completeness authority is VETOING.** `authority_current`
compares the checker's report against the mirror as it is now, and a
`false` there vetoes the release **outright** — no floor, liveness or
quiescence gets past it, and unlike a quiet-wait it does not clear on
its own. It clears when the authority's report agrees with the mirror,
or never.

Measured on the shadow, 2026-08-11 → 2026-08-12: **23 h deferred and
still holding**, floor long since met, feed healthy, nothing dropping.
The cause was mundane once looked at — that box's own bird carries
**13 routes** in `master4` while the mirror holds 1.30M fed from the
primary, so the checker could only ever report a mismatch:

```
$ birdc show route count
13 of 13 routes for 13 networks in table master4      # <- the authority
757074 ... in table rpki4                             # <- NOT routes
```

Two traps in that output, both of which cost time here. The `Total:`
line counts RPKI tables and means nothing for this comparison — read
`master4`. And a box can have bird *running* and still be useless as an
authority, which is not the same as having no bird at all.

**`steer off` works during a deferral. Everything else does not.**

This asymmetry is deliberate and is the rollback lever. A deferral can
hold indefinitely, and for its whole length the traffic is on VPP, not
on the eBPF tier — so an operator has to be able to take it off without
waiting for a convergence that may never land:

```bash
# every port `steer off`, then:
packetframe reconfigure
```

Admitted from `Syncing`, `AdoptedResyncing` and `Verifying`. It removes
the MCAM rules, leaves the convergence in flight alone, and — the part
that matters if the deferral later releases — is not undone by the
verify that eventually lands. A steer, by contrast, is still refused
with "not converged": a diversion that fires mid-convergence may not be
what you asked for by the time it takes effect, while a removal always
is.

Two limits worth knowing before you reach for it:

- **It is all-ports-off, not per-port.** The lever is the whole config
  asking for nothing steered. A reconfigure that still steers some port
  is an ordinary steering change and waits for `Ready`.
- **A removal the NIC refuses leaves the rules in place**, exactly as
  from `Ready`: `steered` stays true so every later teardown keeps
  trying and keeps withholding the VF. `reconfigure` reports the
  failure; re-run it, or clear the slots by hand
  (`ethtool -N <iface> delete <loc>`).

If the daemon is not running at all — `Stopped`, `Backoff`, `Starting` —
this path has no VPP to ask and says so. There the teardown owns it:
stop the daemon, then `packetframe detach --all`.

- **`fib-synced` now names the veto** rather than pointing at
  quiescence. Until this was fixed the line read "the diff runs once the
  source is live and has gone quiet" throughout — sending an operator to
  watch a feed that could never release it, because `AuthorityPosture`
  had no variant for a veto and every surface read `Attesting`.
- **On a box whose bird carries the real table** (the fleet, the
  primary) this does not arise: the report agrees with the mirror and
  the authority releases on its own word.
- **A `birdc` that is temporarily unreachable is NOT this case, and
  needs no intervention.** The integrity checker retries every interval
  (300 s) and publishes a fresh report once it recovers, which releases
  the deferral on its own. Restore bird or the checker and wait one
  interval. Do **not** reach for a restart here — tearing down a
  working VPP to fix a transient read is strictly worse than the
  problem.
  `fib-synced` tells the two apart, and the wording is the tell: *"the
  completeness authority has not attested yet ... releases itself once
  a sample agrees"* is the self-clearing case (no report yet, one aged
  out, a mirror still short — including every startup before the first
  check lands — or a single unconfirmed mismatch, below). Only *"not
  the authority feeding it ... quiescence is never what releases a
  veto"* is the persistent one.
  Fast-path's `fib-integrity` row answers it from the other side, and
  more directly: an unreachable `birdc` shows there as `could not
  complete: <error>`, a bird carrying the wrong table as a drift or
  zero-authority verdict.
- **A veto is only reported after TWO CONSECUTIVE checks say so, and
  that is why the line can be trusted.** A `CompletenessReport` is two
  counts — bird's and the mirror's — and they are taken concurrently
  but not simultaneously. A bulk withdrawal or a bird reload landing in
  that window reads bird low and the mirror high, which is exactly the
  shape of a real mismatch. So the classification requires the same
  fault in two DISTINCT samples (told apart by the report's timestamp,
  not by elapsed time): the first reports the self-clearing line above,
  and a second confirming one within ~300 s escalates it to the veto.
  Release is blocked either way from the first sample — the gate is
  unchanged, and refusing to steer on a doubtful reading is the safe
  direction. What the second sample buys is the right to send someone
  after bird. A `fib-synced` line that flips to the self-clearing
  wording on the next check WAS the transient, and needs nothing; the
  `fib-integrity` row shows the same thing one check earlier, since it
  prints each comparison as it lands.
- **A persistent disagreement is the case that needs a decision**: a
  local bird that does not carry the mirror's table, a bird carrying no
  routes at all, or a mirror fed from a different source than the
  authority measures. Make them agree, or run that box without an
  authority.
  **`require-table-complete off` needs a restart, not a reload.** It is
  read once at bring-up: the attach wiring installs or withholds the
  runtime's completeness handle, and `reconfigure` never touches it. So
  the reload **refuses the change by name** — "`require-table-complete`
  changed (on → off) ... Restart to apply" — rather than answering OK
  and running on the old gate, which is what it used to do. Nothing is
  worth trying first. Since a restart is required regardless, the cold
  sequence below is the same operation: stop the daemon, `packetframe
  detach --all`, start. It tears VPP down and costs a full resync, the
  exact trade the deferral exists to avoid, so it is a last resort and
  not a troubleshooting step.

  The refusal is deliberate rather than a missing feature. Wiring the
  toggle into `reconfigure` would deliver it from `Ready`/`Steered` and
  **not** from here, because `apply_steering` admits changes only from
  those two states — i.e. everywhere except the state this remedy is
  read in. Reaching this state would need a second in-loop request path
  with its own admission rule. Refusing costs nothing here (the restart
  was already required) and fixes the direction that actually bites: an
  operator turning the gate **on** used to get a success while the
  runtime held no handle at all, and believed a safety gate was armed
  when it was not.
- **Before a rollout, check the authority AGREES — not that bird is
  running.** The two are different, and this box proved it: bird was up
  the whole time.

  **Read `fib-integrity` in `packetframe status`.** It is the fast-path
  module's own row and it carries the last comparison verbatim — both
  counts, the drift against the threshold that was actually applied,
  and the age beside it:

  ```
  $ packetframe status                     # message wrapped here; it prints on one line
    fast-path: healthy
      fib-integrity  healthy — bird 1272306 prefixes, mirror 1272281 — drift 0.002%,
                     within the 1.000% warn threshold. A steering gate reads this same
                     comparison and would permit a steer — this is the positive evidence
                     a rollout needs ... (last ok 41s ago)
  ```

  **`would permit a steer` is the pass, and it is the only one.** The
  row carries two separate facts and you want the second:

  - The **drift-catch diagnostic** — `drift N%, within/at or above the
    M% warn threshold` — is fast-path's own alarm against the
    configurable `drift-warn-fraction`. It is a good thing to watch and
    it is **not** the rollout verdict. At a tuned warn fraction the two
    part company by design: 3% drift is "within" a 5% warn threshold
    while the gate, on its own fixed `STEER_MAX_DRIFT`, refuses.
  - The **rollout verdict** — `A steering gate reads this same
    comparison and would permit a steer` / `and REFUSES: <reason>` — is
    produced by calling the gate's own decision function on the same
    report the gate receives, so it cannot disagree with what the steer
    will actually do. On a refusal the reason is the refusal message
    verbatim, remedy included.

  | The row says | What it means |
  | --- | --- |
  | `would permit a steer` | Agreement. Proceed. |
  | `no comparison has completed yet` | The checker has not reached its first interval, or has only just started. **Not agreement** — wait 300 s and read it again. |
  | `no integrity authority on this box (integrity-authority none)` | The operator declared this box is fed from elsewhere, so nothing local attests the mirror. Informational, **not** a pass and **not** an alarm — a steering gate treats the mirror as unattested, which is only valid with `require-table-complete off`. This is the shadow's correct state. |
  | `would refuse: the route mirror holds N of the authority's M routes` | The mirror is short — usually still loading. |
  | `... mismatch, not a drift ... would refuse: ... that is not the authority feeding this mirror` | Bird up, carrying a table that is not this one — the 23 h deferral above. If this box is *meant* to be fed from elsewhere, set `integrity-authority none` and it becomes the informational row above rather than a false alarm. |
  | `would refuse: completeness is unknown: the authority reports zero routes` | The degenerate form of the same thing — bird answering, and answering nothing. |
  | `would refuse: the last completeness check was Ns ago, too old to act on` | Aged past the 900 s window. Comparisons have stopped landing; with no error beside it, they are not being attempted. |
  | `could not complete: <error>` with `HISTORY` | `birdc` or the mirror read is failing. Any numbers shown are the previous comparison, ageing. |
  | no `fib-integrity` row at all | Nothing is checking on this box — kernel-fib mode, or a control plane with no route source. The authority will read `Absent`. |

  > The verdict is **subjunctive** — "would permit" / "would refuse" —
  > because it predicts what a steer would do from this comparison, not
  > something that has happened. On a `require-table-complete off` box no
  > gate consults it at all; the row still tells you what one *would*
  > decide, which is exactly the pre-flight signal you want before
  > turning the gate on.

  The row appears whenever a checker exists, *including before its
  first comparison*, and that is the distinction the check turns on:
  silence used to be equally consistent with the checker never having
  run, `birdc` failing every time, or the log having rotated — and
  would approve a rollout onto a handle that is `Unknown` and will
  refuse.

  `packetframe status` reads a snapshot the daemon publishes every 5 s,
  so the row is at most that stale — but the comparison behind it is up
  to one interval (300 s) old by design, which is what the `last ok Ns
  ago` beside it is for. Its ceiling in normal operation is ~320 s (the
  interval plus two 10 s `birdc` budgets), so an age climbing past that
  with **no** error alongside it means checks have stopped landing
  altogether rather than failing — look for the checker task, not for
  bird.

  You do not have to watch that number to stay safe. Past
  `STEER_MAX_REPORT_AGE` (900 s) the rollout verdict becomes `REFUSES:
  ... too old to act on` on its own — the row asks the gate's own
  decision function rather than re-deriving the rule, so the two cannot
  disagree, and `status` cannot advertise evidence for a rollout the
  gate is already refusing. A parity test pins them across the
  boundary. Reading the age is for catching the problem in the
  ~10 minutes before that, not for avoiding a bad rollout.

  **The other positive evidence is the canary steer itself**, and it
  costs nothing to lean on. With `require-table-complete on`, a steer
  the authority will not support is *refused*, and the refusal names
  the verdict verbatim — "the route mirror holds N routes but the
  authority reports only M — that is not the authority feeding this
  mirror", or "completeness is unknown", or "too old to act on".
  Nothing is steered when it refuses, so rung 0's first `steer on`
  doubles as the test, and a refusal costs a message rather than
  traffic. Read the reason it prints; do not retry past it.

  **Do not hand-roll the comparison from `birdc` output.** Three traps
  make a hand-rolled check pass a box that will veto.

  **The `networks` column, not the `routes` one.** On the line `N of M
  routes for K networks in table master4`, the mirror holds one entry
  per *prefix*, so `K` is the comparable number. `N` counts paths, and
  on a multihomed box it is larger by roughly the number of upstreams —
  measured on the production primary as 2,594,691 routes against a
  1,303,120-entry mirror, a 49.8% "drift" that was pure units (#168).
  Read the wrong column by hand and a converged box looks broken.

  **`master6` counts.** The checker compares `master4` **plus**
  `master6` against the mirror's v4+v6, so a box whose `master4`
  matches while its `master6` is missing or wrong still fails the
  combined comparison, and checking `master4` alone approves a rollout
  the gate will refuse.

  **`fib-synced`'s installed count is not the number to compare** —
  it counts VPP's IPv4 table only (under `v6 on` the IPv6 table is
  reported separately, on the `fib-v6` row), against an authority
  figure that includes v6.

  A box that adopts while steered under a vetoing authority has no fast
  rollback. Worth knowing before the canary rather than during it.

### A member port with no link — reported always, blocking only when routes use it

`packetframe status` shows `fib-synced` carrying a verify line naming
every dark member, annotated one of two ways:

```text
..., octeon5/0 (idx 5) admin_up=true link_up=false (idle: no routes egress here; not blocking)
```

An **idle** dark member decides nothing. This is the normal state of a
dark port — the BGP session that would produce its routes died with
the link, so no installed route can egress it, and a steered packet
cannot choose an egress no route names. The port shows here and in the
`ports` row so it gets fixed, but steering proceeds and the offload is
not held hostage to an uncabled port (the primary's eth5 shipped this
way).

```text
verify FIB OK, IN-USE MEMBER(S) DARK — steering refused, no restart: 64/64
probes matched, ..., octeon3/0 (idx 5) admin_up=true link_up=false CARRIES ROUTES
```

A dark member that **carries routes** — static routes pinned to it, or
a link that died faster than its BGP session withdrew — is the real
blackhole risk, and the response is the designed one: reach `Ready`,
keep the steer want, **refuse to steer**, and do **not** restart,
because a restart cannot plug in a cable. (The first build to meet
this state restart-looped a VPP with a flawless FIB over three
uncabled ports, every ~10 s, indefinitely — shadow repro 2026-08-13.)

Remedy: restore link, or remove the routes that egress the dead port.
Recovery is automatic either way: the steer retry re-reads link state
AND usage fresh from VPP on every attempt, so the next retry after the
fix steers. `packetframe reconfigure` asks immediately instead of
waiting for the retry interval.

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

The same applies to a NON-green one, and it bites harder, because the
condition usually clears while the verdict does not. Every `fib-synced`
line that is not `healthy` therefore carries its own age; compare that
against the counts printed beside it before acting on the verdict.

#### The one re-run: a stale incomplete verdict

One verdict is re-run. A verify that failed **only** because the table
held unresolvable routes, kernel-delivered prefixes without a
`steer-exempt`, or nothing at all is re-run once, after the table has
held none of those for 10 s, and at most once every 5 minutes. A verdict
with a probe mismatch or an in-use dark member is never re-run, since a
clean table does not clear either.

The re-run happens only in `Ready` or `Steered`, on a tick whose drain
proved nothing is pending, with VPP answering its last ping. It also
needs no source backlog, nothing in flight, the last drain to have
landed, and no deferral, fresh hold or unverified preserved ledger. No
delta can land between a probe's sample and its answer, which is the
race that keeps verification out of steady state otherwise.

**It refreshes the verdict and decides nothing.** No supervisor event
comes of it: steering stays with the live gates, which never read the
verdict, and a first attach is still never steered on its own. Only what
`fib-synced` reports changes. The re-run is logged as an ordinary
`verify_passed` / `verify_incomplete` / `verify_failed` event with
`rerun: true`. A `verify_failed` re-run tears nothing down. It reports
VPP disagreeing with the ledger, and a daemon restart rebuilds the FIB.

**Failed, and shaping the design:**

- **`ip6` ntuple naming an address is rejected by the AF** (error 710)
  while the v4 control inserts cleanly — the vendor NPC profile has no
  v6 L3 address extraction. No IPv6 packet can be MCAM-steered by
  prefix, so allowlisted v6 stays on the XDP PacketFrame FIB path except
  where `v6-divert` takes it by frame. Retest at
  every UniFi kernel bump; the MKEX profile ships with the AF driver.
  What the profile does extract (ethertype, MAC, VLAN id, v6 L4
  protocol and ports; probed 2026-09-26) is what the address-free
  IPv6 diversion is built on — see [v6-divert steering](#v6-divert-steering).
- **`rx-mode adaptive` is unsupported** by the native octeon driver.
  The heat goal is dead: **one hot core per VPP worker, 24/7**, as a
  permanent recorded cost. Budget power and thermals for it.

## Install and upgrade on the router

> ## The boot-sysctl audit: run it after every install, before every reboot
>
> **Order matters: install → audit → reboot.** Installing the package is
> what can plant the assignment, so an audit taken before the install
> proves nothing about the boot that follows it.
>
> ```bash
> packetframe feasibility | jq -e '.boot_sysctl_blockers | length == 0' >/dev/null
> ```
>
> **The `-e` is load-bearing — do not drop it.** Without it `jq` exits 0
> whether the array is empty or full, and in the pre-config window
> `packetframe feasibility` also exits 0 (the capability is still
> advisory there), so a gate written as a bare `jq '.boot_sysctl_blockers'`
> passes while printing the blocker that is about to brick the box. With
> `-e` the pipeline exits nonzero when the array is non-empty, and also
> when `feasibility` produced no JSON at all — both are the safe
> direction. To read the blockers rather than gate on them, drop the
> `-e` and the redirect.
>
> `boot_sysctl_blockers` is reported **regardless of whether the
> capability is required**, which is the point: between installing VPP
> and adding the `vpp-offload` block there is no module for the check to
> be gated on, and that gap is exactly when the hazard exists. Once the
> config does declare the module the same check is also promoted to
> `required`, so `packetframe feasibility` stops exiting 0 over it and
> its own summary reads `ROLLOUT BLOCKED` rather than `PASS`.
>
> **Do not substitute `ls /etc/sysctl.d/ | grep -i vpp`.** That answers
> a narrower question than the one that matters. The probe resolves the
> effective assignment across every `sysctl.d` location under both
> appliers — systemd-sysctl and procps order and shadow files
> differently — and reports the worse of the two verdicts, because a
> file one applier skips and the other applies is still lethal. It then
> prices the result at the running kernel's **default hugepage size**
> (`Hugepagesize:` in `/proc/meminfo`), which is where 1024 pages
> becomes a 512 GiB request on this fleet rather than 2 GiB.
>
> **An unknown verdict blocks the reboot.** `Unknown` means the scan
> could not read what boot will do, not that boot is fine.
>
> **After a firmware change, establish that the new kernel's hugepage
> size matches what you audited.** The page count is unchanged across
> the upgrade; the multiplier is not necessarily, and an audit priced on
> the old kernel does not transfer. Re-run the audit on the new kernel
> before the next reboot, including after a recovery-mode restore.

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
wants anyway. For UniFi gateways it ships on its own release tag from
**github.com/unredacted/vpp-unifi**, built from *unmodified* upstream
source (no fd.io bullseye+arm64 package exists at any version). Which
release this build of packetframe was codegen'd against is recorded in
`crates/modules/vpp-offload/vpp-api/SOURCE.json` (and printed into the
hwtest bundle's `vpp-pin.txt` as a ready fetch line); the CRC handshake
refuses any VPP that disagrees at attach. Despite its name, `vpp-pin.txt`
is not a separate pin: the hardware-artifacts workflow generates it
from `SOURCE.json` on every build, so the two cannot disagree.

**Installing VPP on a gateway — including the five traps that have
each cost real time (mask-before-install; `VPP_INSTALL_SKIP_SYSCTL=1`
and the 64K-page hugepage reason; deleting the `/etc/sysctl.d/80-vpp.conf`
the deb ships, because the env var only skips install time while the
file re-applies at EVERY boot and bricked the primary on 2026-08-21;
/tmp noexec; purge-unbinds-the-VF) —
is documented once, in vpp-unifi's README.** It lives with the build
so it cannot drift from what the packages actually do; this runbook
owns what happens after `dpkg -i` succeeds.

The 80-vpp.conf trap also has a check that doesn't require a reboot to
find it: `packetframe feasibility` runs `vpp.sysctl-hugepages`, which
scans the boot sysctl set (`/etc/sysctl.d`, `/run/sysctl.d`, the lib
dirs and `/etc/sysctl.conf`, pricing BOTH the systemd-sysctl and the
procps `sysctl --system` apply models and reporting the worse — the
two disagree about `/lib/sysctl.d` and about when `/etc/sysctl.conf`
applies) for `vm.nr_hugepages`, prices the EFFECTIVE value at the
running kernel's default hugepage size from `/proc/meminfo`, and FAILs
— naming the file and the line to delete — when the request exceeds half of
MemTotal (the incident case: 1024 pages × 512 MiB default on the
64K-page kernel = 512 GiB on a 64 GB router). Any smaller nonzero
boot-time value is a WARN: hugepages are managed by this module at
attach, so a competing boot-time reservation is drift. The probe runs
in the general set, whether or not the config declares
`module vpp-offload` — run feasibility after every VPP install,
before the next reboot. **The verdict is the table row, not the
summary line or the exit code**: the probe is advisory today, so a
boot-fatal FAIL still prints `Result: PASS` and exits 0 — read (or
grep) the `vpp.sysctl-hugepages` row; do not gate a reboot on
`packetframe feasibility && reboot`.

Upgrade is `detach → install → attach`. There is no cross-version
adoption: the state file records the VPP version, and a mismatch is
refused rather than adopted.

The version in `SOURCE.json` is the *attested* VPP; the *compatible*
set is anything whose CRCs match for the messages the module speaks,
and the attach handshake decides that per box, loudly, before any
route is programmed. A new VPP release changes nothing on its own —
adopting one is a deliberate two-repo sequence, and whether it needs a
new packetframe release is answered by the `generated.rs` diff during
the re-vendor. The full compatibility model and bump procedure:
`crates/modules/vpp-offload/vpp-api/README.md`.

## The kernel path for exempt traffic

Steering diverts allowlisted traffic to VPP. Everything a **keep** rule
matches stays on the kernel: the router's own traffic, the built-in
exemptions, every `steer-exempt` prefix and, on a v6-diverting port,
the v6 keeps. Keeps sit above every diversion in the MCAM and hand
their frames to the PF, where the kernel receives them like any
unsteered frame.

That is not control-plane trickle on a real box. Exemptions grow into
bulk traffic: the WAN /31s (the return path of every NAT'd flow), whole
LAN subnets, the IX LANs, another site's /24, a CGNAT /10. **Which PF
queue a keep delivers to is therefore a capacity decision**, and one
queue is one CPU: its IRQ, and the softirq that drains it, run on one
core.

### What happened on 2026-10-07

Until 0.6.0 every keep delivered to **PF queue 0** (`ring_cookie` 0, no
RSS). Every port's queue-0 IRQ defaults to cpu0. On a production gateway
(18 CPUs, 18 queues per port, queue N's IRQ on CPU N), about three
minutes after a lever move that steered, cpu0 sat at 99% softirq and 0%
idle while the other non-VPP CPUs were 50-76% idle. Queue 0 took ~5.8k,
~5.2k and ~6.0k frames/s on three ports, two of them dropping ~3.9k and
~1.6k frames/s (`rx_drops`). A ping to the directly connected transit
next hop lost 30% at 618 ms; transit BGP sessions fell on hold-timer
expiry; the platform's WAN monitor flapped the uplink, and every flap
emptied conntrack, loading cpu0 further. The same config had run steered
for a week without visible trouble: a latent capacity limit with no
warning. Moving the queue-0 IRQs of the three busy ports to CPUs of
their own fixed it within seconds: 0% loss, 0.15 ms RTT, 0 drops/s,
cpu0 74% idle.

### RSS keeps, and the queue-0 fallback

Since 0.6.0 a keep is an **RSS rule on the PF's default context**
(`FLOW_RSS`, context 0; the CLI's `context 0 action 0`): its frames are
hashed across the PF's queues exactly as unsteered traffic is. Whether
the vendor driver takes that is checked at run time, per port, by the
first keep the daemon installs there. It inserts the RSS form and reads
it back:

- accepted, and read back with `FLOW_RSS` and context 0: the port's
  keeps spread over RSS (log line `keep rules on this port spread over
  RSS`);
- refused (`EINVAL`/`EOPNOTSUPP`), or accepted but read back **without**
  the flag or on another context: the same rule is installed in the
  queue-0 form at the same slot, and that port's keeps stay on queue 0
  for the life of the daemon. It says so three ways: a `warn` line
  (`keep rules on this port fall back to PF queue 0`), a
  `keep_queue0_fallback` event naming the driver's answer, and the
  `kernel-path` status row. Other ports are unaffected.

A lab probe on the production firmware (driver `rvu-nicpf`, vendor
5.15) accepted `context 0 action 0` and read it back with `RSS Context
ID: 0`. That proves acceptance and readback only: a driver can echo the
stored spec without programming the action. The proof that frames
actually spread is the per-queue counters below, on a port carrying
many flows.

Keeps from an older daemon are queue-0 keeps. They are recognised as
this module's in either form (audit, slot reuse, teardown), the status
row counts them (`keeps inherited from a previous daemon (… on queue
0)`), and the next steer rewrites them in place as RSS keeps. An
adopted restart steers again at the end of its resync; `packetframe
reconfigure` does it sooner.

### Queue-0 IRQ placement, while keeps pin to queue 0

On a port whose keeps fell back to queue 0, the daemon moves that
port's queue-0 IRQ (the vector named `<port>-rxtx-0`) to **a CPU of its
own**: never one of VPP's cores (main and workers), never an isolated
CPU, never cpu0. Every eligible CPU takes one port's queue 0 before any
takes a second; the published control-plane CPUs (where they exist —
on a box where every CPU takes NIC interrupts there are none) are used
after the others but before any sharing; ties go to the CPU with the
fewest NIC queue IRQs. The prior affinity is
written to `<state-dir>/vpp-queue0-irqs.json` **before** the move, and
put back when the port's keeps stop needing it: a steer that leaves the
port on RSS or unsteered, the module's teardown, or `packetframe
detach`. A record from another boot is dropped unrestored (the reboot
reset the IRQs), and so is one whose IRQ no longer holds the CPU the
daemon wrote: something else moved it since, and its value is kept.
`--keep-vpp` restarts leave the placement and the record in place, and
the next daemon restores the original prior on its teardown. With no
CPU to move to, the port is reported `queue-0 IRQ NOT moved (no CPU
outside VPP's cores …)` and nothing is written. A placement counts only
once `effective_affinity_list` says the IRQ fires there: a kernel that
takes the mask and keeps delivering elsewhere (a kernel-managed or
driver-pinned vector) is reported `queue-0 IRQ NOT moved (cpu N was
written to its mask but the kernel still delivers it on M)`, retried on
every steer, and its mask is still put back on teardown. A write the
kernel refuses leaves the record exactly as it was.

The otx2 PF re-applies its own affinity hint whenever it re-opens a
port (ring resize, link bounce, provisioning push), which puts queue 0
back on cpu0. The row shows where the IRQ is delivered now; the next
steer places it again.

**Does a daemon restart undo a manual placement?** No, unless you
picked one of VPP's cores. The attach-time pass (`crates/modules/
vpp-offload/src/bringup.rs`, the `cores::clear_irqs_off` call before
VPP starts, and again after adopting a VPP observed on other cores)
moves only member IRQs whose effective affinity is on a VPP core; a
queue-0 IRQ moved by hand to any other CPU is left alone. What does
undo it is a port re-open (above), and a reboot.

### How to check

```bash
# The keeps: "RSS Context ID: 0" on an RSS keep, absent on a queue-0
# one; "Action: Direct to queue 0" on both (for an RSS rule the queue is
# an offset into the one the hash picks). Keeps sit at lower locations
# than every diversion ("Direct to VF 0 ...").
ethtool -n <port>

# Where each queue's IRQ fires, and how often. "<port>-rxtx-0" is queue 0.
grep '<port>-rxtx-' /proc/interrupts
cat /proc/irq/<irq>/effective_affinity_list

# Per-queue receive and the port's drops. Twice, ten seconds apart:
# with RSS keeps `rxq0: frames` grows at roughly the others' rate; with
# queue-0 keeps carrying the bulk it outgrows all of them together.
# `rx_drops` should not move at all on a steered port.
ethtool -S <port> | grep -E 'rxq[0-9]+: frames|rx_drops'

# Which core is drowning: softirq per CPU.
mpstat -P ALL 1 5   # or: top, then 1
```

`packetframe status` carries a `kernel-path` row while any port has
rules installed: per port, the keep form (and the driver's answer on a
fallback), the queue-0 IRQ placement, and receive, queue-0 and drop
rates sampled every 10 s from the same counters. It is **Degraded**,
port named, when a port drops 100 frames/s or more — with the remedy for
the form its keeps are in. The `kernel_path_dropping` event records the
start (at most once per port every ten minutes while it lasts) and the
end. Gauges: `packetframe_vpp_keep_rss`, `packetframe_vpp_keeps_observed`,
`packetframe_vpp_queue0_irq_cpu`, `packetframe_vpp_kernel_rx_frames`,
`packetframe_vpp_kernel_rx_drops`, `packetframe_vpp_kernel_rx_fps`,
`packetframe_vpp_kernel_rx_drops_per_second` and
`packetframe_vpp_kernel_path_dropping`.

### Emergency lever: move the IRQ by hand

If a core is saturated and exempt traffic is dropping, do not wait for a
release. Move the hot queue's IRQ to an idle CPU that is not one of
VPP's (the attach log names VPP's cores: `vpp-offload attached`,
`main_core`, `workers`) and not isolated:

```bash
grep '<port>-rxtx-0' /proc/interrupts          # first column is the IRQ
echo <cpu> > /proc/irq/<irq>/smp_affinity_list
cat /proc/irq/<irq>/effective_affinity_list    # must now read <cpu>
```

One port per CPU. It takes effect immediately and lasts until the port
is re-opened or the box reboots. On the incident box it took loss from
30% to 0 within seconds.

### Downgrading below 0.6.0

An older daemon reads an RSS keep as somebody else's rule: its teardown
would leave the keeps in the MCAM and its planner would route around
their slots. Run **this** release's `packetframe detach --all` before
installing an older one.

## IRQ affinity before attach

VPP workers are poll-mode: each one owns its CPU at 100% duty cycle
from the moment it spawns. On the reference NIC every CPU carries an
rx-queue IRQ (18 cores = 18 queues, no idle silicon), so without
operator action some of those IRQs fire on the cores the module derives
for VPP — and production softirq then fights hot pollers for the same
CPUs. The first primary attach (2026-08-13) ran exactly that
experiment, involuntarily: load ~10, management ssh dropped, `birdc`
past its 10 s budget, and VPP itself starved into a supervisor restart
loop. Traffic stayed on the eBPF tier throughout — the fallback design
held — but the box was degraded until the daemon was stopped.

So the overlap is a **checked precondition**, and **attach fixes it
itself**: any member port's queue IRQ whose *effective* affinity is on
a VPP core is re-pinned onto the CPUs that are neither VPP's nor
isolated, keeping whatever of its existing mask survives, and the
attach log says so (`moved a NIC queue IRQ off the cores VPP will
poll`). An IRQ with nothing surviving (the default spread pins one per
core) gets a single CPU, and consecutive ones get different CPUs, cpu0
last — a controller handed a wide mask delivers to one CPU in it, so
writing the same wide mask for each would pile them all onto cpu0.
Attach then re-reads where each IRQ actually fires and **refuses** only
if the kernel did not follow — a kernel-managed or driver-pinned IRQ.
When attach adopts a surviving VPP whose threads are observed on cores
outside the derived map, it runs the same move against those too; there
a kernel that does not follow is a warning, not a refusal, because
refusing after adoption would leave that VPP unsupervised.

`packetframe feasibility` reports a planned move as a non-blocking
**WARN** on `vpp.irq-affinity`, not a pass: whether the kernel honours
the mask is only known once it is written, which a probe never does.
It **fails, required**, only when there is no CPU left to move to.

This used to be a refusal with the fix spelled out for an operator to
apply by hand. On UniFi a hand-written affinity is gone at the next
reboot, provision cycle or ring resize, so the refusal fired after
every one of them. The moves are not undone on detach: putting an IRQ
back on a CPU VPP no longer uses would only re-create the conflict for
the next attach. (The queue-0 placement for keeps that pin to queue 0
is different, and is restored: see [the kernel path for exempt
traffic](#the-kernel-path-for-exempt-traffic).) With a config that
declares the module, the no-CPU-left failure is `required`: it makes
the summary read "vpp-offload attach BLOCKED" (exit non-zero) rather
than PASS. Effective, not
permitted: a `0-17` wildcard mask still delivers to exactly one CPU,
and that CPU either is or is not about to become a hot poller.

Manual remediation is now only for the case attach refuses — the
kernel did not move delivery. Try a CPU by hand to see whether the IRQ
moves at all:

```bash
echo <cpu-list outside the VPP cores> > /proc/irq/<N>/smp_affinity_list
cat /proc/irq/<N>/effective_affinity_list
```

If the effective CPU does not change, the IRQ is not movable from
userspace and VPP cannot share that host's cores with it. The affinity
write does not persist across reboot; attach re-applies it every time.
(udapi provision cycles and ring resizes can also re-spread affinities
**while VPP is running** — attach only corrects them at attach, so a
long-lived VPP can end up sharing a core with a re-spread IRQ until the
next restart.)

**A refusal no longer takes the fast-path down with it.** It used to.
Any module that failed to come up made the loader unwind every module
attached before it and exit, so a vpp-offload refusal removed the eBPF
tier too — the daemon exited, systemd looped on restarts, and the box
forwarded through the kernel with no fast-path at all. The 2026-08-14
primary incident below was fifteen of exactly that; the lab rig
reproduced it on demand (2026-09-23) by moving one member IRQ onto a
VPP core. A reboot of any box with packetframe enabled at boot and
vpp-offload configured would have done it every time.

Now vpp-offload's failure to load or attach **degrades** the daemon
instead: the fast-path stays attached and forwarding, and vpp-offload
is reported, not omitted —

```
  vpp-offload: DEGRADED
    startup  DEGRADED — did not come up at startup: <the refusal>. The eBPF
             fast-path is forwarding on its own and nothing is offloaded ...
```

— and `packetframe reconfigure` names it the same way rather than as
"added to config". `packetframe_vpp_health{state="degraded"}` reads
`1` and `packetframe_vpp_steered` reads `0`, so the healthy-series
alert fires rather than finding no series.

Before running on, the loader releases whatever an earlier daemon left
for adoption, from vpp-offload's state file — the same routine
`packetframe detach` runs: MCAM steering removed, the recorded VPP
killed, VFs and hugepages handed back. A preserved VPP still carrying
steered traffic is exactly what a bring-up that fails before adoption
would otherwise leave behind, unsupervised, on a frozen table. **If
that release fails, the daemon does not degrade**: it aborts as before,
and the error carries both the refusal and why the release failed.

Fix the cause, then run the full sequence — **not** a bare restart:

```bash
systemctl stop packetframe && packetframe detach --all && systemctl start packetframe
```

A reload cannot start a module that failed to attach, and a plain
`systemctl restart` preserves the fast-path's pins on the way down,
which the next start then refuses — turning a degraded daemon into a
stopped one. Every other module keeps the all-or-nothing rule; see
`DEGRADE_ON_START_FAILURE` in the loader for why.

**`ethtool -G` resets it too.** Resizing a ring tears down and
rebuilds the port's queues, and the driver re-spreads the rebuilt
queues' IRQs across all CPUs — silently undoing the pinning. Measured
on the primary (2026-08-14): a diagnostic ring resize on eth3 the
previous evening put all seven of its queue IRQs back on the VPP
cores, and the next attach refused fifteen times under systemd
auto-restart until the operator re-pinned. Attach now re-pins at every
attach, so a resize no longer blocks the next start — but a resize
while VPP is running re-spreads its IRQs under a live VPP until the
next restart, so a window harness that touches ring sizes should still
restart packetframe (stop → `detach --all` → start) afterwards.

**The daemon's control-plane threads go where the interrupts are
not.** Moving member IRQs off VPP's cores concentrates them, and the
softirq of every generic-XDP packet they carry, on the CPUs that
remain. On the primary (2026-09-26) a full reload of ~1.09M routes ran
at 1,773 routes/s, with the busiest daemon threads (`vpp-supervision`,
`pf-drift-scan`, two `packetframe-fib`) on cpu1 and cpu2. A lightly
loaded shadow converges the same table in under 60 s. So after both
IRQ passes attach derives the CPUs that are online, not cpu0, not
isolated, not VPP's (derived or observed), and deliver no queue IRQ of
**any** NIC on the host (effective affinity, read after the moves). It
places those threads there:

```
INFO control-plane threads placed off NIC queue IRQs and VPP's cores cpus=5-9 placed=2 disjoint=0 failed=
```

The line comes only once the attach has succeeded. A failed attach
degrades the daemon, and a placement made on the way to the failure
would outlive the module that justified it. `placed` counts the threads
it narrowed: the fast-path runtime, the supervision loop, the drift
scan and the FDB mirror. Fast-path blocking threads started later
place themselves. Only this process's own threads are touched. Each is
re-identified by its start time around the write, so a thread id that
exited and was reused elsewhere is not narrowed. Placement only narrows
a thread's existing mask. It
never adds a CPU the daemon was not allowed, so a systemd
`CPUAffinity=` survives. A thread whose mask shares nothing with the
set is left alone (`disjoint`), and that is also how to opt out: pin
the daemon away from the set. VPP itself is spawned from the daemon's
unplaced mask, not the supervision thread's: the thread is widened for
the spawn and narrowed again after. Otherwise VPP's unpinned helper
threads would inherit a one- or two-CPU mask that the next adoption
reads back as VPP placement.

**On the reference NIC this is usually a no-op.** Every CPU carries a
queue IRQ of every port (18 cores, 18 queues), so after the moves no
candidate is left, and attach logs this once and leaves the threads to
the scheduler:

```
INFO no CPU is free of NIC queue IRQs outside VPP's cores, cpu0 and the isolated set; control-plane threads left where the scheduler puts them vpp_cores=11,13-17 irq_cpus=0-10,12
```

It is not an error and never blocks attach. To give the control plane
a CPU of its own there, free one of interrupts first: fewer queues
(`ethtool -L`) or an IRQ layout that leaves a CPU empty. Like the IRQ
moves, the placement is computed at attach only. A udapi re-spread
while VPP runs is not followed until the next restart.

## Constraints worth knowing before you debug

- **`packetframe feasibility` does not attach anything.** It used to,
  via `--config`, on every configured port — including the native-XDP
  attach that panics this fleet. Fixed in v0.2.7; on an older build, do
  not run it against a live config.
- **`reconfigure` accepts only the steering inputs and
  `drift-accept6`.** `steer`, `direction` / `steer-direction`,
  `steer-exempt`, `v6-divert` and `steer-keep6` apply as an MCAM
  reconcile, `drift-accept6` at the next drift scan. Everything else —
  `port` membership, `cores`, `vlans`, `expected-routes`, `hugepages`,
  `steer-capacity`, `v6`, `loopback-address` / `loopback-address6`,
  `local-route` / `local-route6`, `require-table-complete` and
  `vpp-binary` — is fixed at VPP's start or at VF acquisition, and each
  is refused **by name** with what to do about it. A daemon whose running config silently differed from
  the file you just edited is how the wrong thing gets debugged for an
  hour.
- **Restart ordering is stop → detach → start.** This bit production
  twice. A plain `systemctl restart` leaves the previous attachment's
  pins in place and the next start refuses them. Two forms, and they are
  different operations:
  - `detach --all` tears **everything** down, VPP included: traffic
    falls back to the eBPF tier and the next start brings VPP up fresh
    (a full resync, then the canary levers again). The safe form, and
    the one every recovery message names.
  - `detach --keep-vpp` tears down every other module's pins and leaves
    VPP, its VFs, hugepages and steering rules running for the next
    start to adopt — steered traffic keeps flowing across the restart.
    The `systemctl stop` leaves a preserved route ledger when VPP was
    converged, and the start that finds it adopts without reading VPP's
    FIB or unsteering at all: measured on the reference router at zero
    unsteered time (1 of 420 probe packets lost, to fast-path's link
    bounce). Without a preserved ledger the adoption falls back to
    reading VPP's FIB, which measured ~3 minutes unsteered — [What a
    keep-vpp restart costs
    now](#what-a-keep-vpp-restart-costs-now-the-preserved-route-ledger).
    The form for a same-version config restart of a steered box (a
    PacketFrame **version upgrade** uses `detach --all` with the old
    binary instead; see the README's "Upgrading"):

    ```bash
    systemctl stop packetframe && packetframe detach --keep-vpp && systemctl start packetframe
    ```

    Every module other than vpp-offload comes down whatever the config
    declares — it is a restart, so a module the edit removed does not
    stay behind. VPP is kept only for a restart that can adopt it, and
    `detach --keep-vpp` checks that before tearing anything down,
    refusing by name when:
    - the edit changed something VPP fixes at attach: `port` lines
      (including `cores`, `vlans` and `vlans all`), `expected-routes`, `hugepages`,
      `steer-capacity`, `v6`, `loopback-address`, `loopback-address6`,
      `vpp-binary`, `local-route` or `local-route6`. Adoption neither applies nor undoes these — a
      dropped VLAN's subif would keep taking steered ingress, unmanaged.
      Steering levers and `steer-direction` are fine; adoption applies
      them;
    - the config no longer has a `vpp-offload` section;
    - there is no vpp-offload record in the config's `state-dir` — no
      VPP running, or a `state-dir` edit the next start would look past.
      The same goes for `bpffs-root`: a path edit needs `detach --all`
      under the **old** config, then start;
    - the record predates this check (first restart after upgrading to
      it).

    The daemon's adoption applies the same checks, so a restart that
    skipped the preflight fails the start rather than adopting.
- **The ntuple table holds 16 rules per port by default, and
  `npc/mcam_info` will not tell you that.** The driver rejects an
  out-of-range `loc` with `EINVAL` rather than assigning one. The module
  asks the NIC via `ETHTOOL_GRXCLSRLALL` and takes the highest free
  slots. The debugfs figures (2,048 entries, ~1,700 available) are the
  classifier pool every PF and VF draws from, not any one port's table.
  `packetframe feasibility` reports the real free count under
  `vpp.steering.budget`.
- **Raising the rule budget: `steer-capacity`.** The 16 is octeontx2's
  default carve-out from that pool, exposed as the runtime devlink
  parameter `mcam_count`. With `steer-capacity N` the module sets it on
  every steerable member at attach, before the budget is read. Verified
  on the EFG (2026-09-24): 32 through 256 accepted, and a rule at
  `loc 40` — refused at the default — inserted afterwards. Three driver
  facts to know: it will not resize a table holding rules (so an
  adopted, steered port keeps its table until it is unsteered and the
  module restarted — the attach log says so); a short allocation is
  silent, so the module judges by reading the table back and restores
  the old size if the table shrank; and the value resets at reboot,
  which is why the module asserts it at every attach rather than
  leaving it as hand state. By hand, on a port holding no rules:
  `devlink dev param show pci/<addr> name mcam_count` (this iproute2
  needs `name`), where `<addr>` is the target of
  `/sys/class/net/<port>/device`.
- **VPP's egress MTU is the kernel port's MTU, mirrored at attach.** VPP
  applies a parent's L3 MTU to its subifs and falls back to 9000 for an
  interface nobody set, so the module sets each VF's L3 MTU from
  `/sys/class/net/<port>/mtu` (re-asserted on adoption). That is what
  makes a jumbo frame from a trunk draw ICMP frag-needed — sourced from
  `loopback-address` — at a 1500-byte transit port instead of leaving
  oversized. One MTU per port: a VLAN on a trunk whose kernel MTU is
  lower than the port's is not mirrored separately. An MTU changed on the
  kernel side takes effect in VPP at the next attach — a supervised VPP
  restart re-reads it — not while VPP keeps running.
  `vppctl show interface` prints each interface's `mtu`.
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
  where there is a completeness authority** (`integrity-authority birdc`
  or `frr`). Verification samples what the *ledger* holds, so a table
  that is merely missing prefixes verifies clean. That is why the guard
  is a separate comparison against the authority — bird's own route
  count, or FRR's counts plus End-of-RIB from every declared upstream —
  published by the fast-path integrity checker and consulted by every
  steer, not by the verify. Where no publisher exists,
  `require-table-complete off` hands the judgement back to you, and rung
  0's soak is what discharges it: the `unresolvable`, `withheld` and
  `installing` counts must all read zero before you turn the first
  lever — **and no `route-feed` row may be present**. Those three counts
  cannot describe an update that never reached VPP at all, which is why
  that row is a separate condition on the same gate.
