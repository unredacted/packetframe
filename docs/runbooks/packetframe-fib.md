# PacketFrame FIB operations runbook

This runbook covers the Option F PacketFrame FIB forwarding path: what the
pieces are, how to tell it's healthy, what to do when it's not, and
how to roll back to the kernel-FIB path if something goes wrong.

## Contents

- [Architecture at a glance](#architecture-at-a-glance)
- [Healthy operation](#healthy-operation)
- [Everyday inspection commands](#everyday-inspection-commands)
- [Connected fast-path (v0.2.1)](#connected-fast-path-v021)
- [WAN egress](#wan-egress)
- [Restarts: the route ledger](#restarts-the-route-ledger)
- [Cutover and rollback](#cutover-and-rollback)
- [Triage by symptom](#triage-by-symptom)
- [Resolved items](#resolved-items)

## Architecture at a glance

```
   bird (BGP RIB)                         kernel FIB
      │                                       │
      │  iBGP over TCP (RFC 4271)             │  local delivery +
      │  bird best-path → packetframe         │  connected + static
      ▼                                       │
   packetframe BgpListener ─┐                 │
                            ▼                 │
                    FibProgrammer             │
                            │                 │
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
       FIB_V4          NEXTHOPS         ECMP_GROUPS   (BPF maps)
          │                 │                 │
          └─────────┬───────┴─────────────────┘
                    ▼
               fast-path XDP (in-kernel)
                    │
                    ▼
             XDP_REDIRECT / XDP_PASS
```

- **BgpListener** (the recommended forwarding feed) accepts the
  routing daemon's iBGP session — FRR on the reference router,
  through a phantom AnyIP listen address (see "Feeding from FRR
  instead of bird"), or bird over loopback. The daemon's export
  policy runs after best-path selection, so we get exactly one
  UPDATE per prefix with its chosen nexthop. Translated to
  `RouteEvent::Add`/`Del`. **BmpStation** is also available behind
  the `RouteSource` trait but bird's BMP doesn't ship RFC 9069
  Loc-RIB. See the section "When to use `route-source bmp`
  instead" near the bottom.
- **FibProgrammer** owns the BPF map write path. Allocates `NexthopId`s
  and `EcmpGroupId`s with refcount + free-list dedup.
- **NeighborResolver** subscribes to kernel neighbor multicast
  (`RTM_NEWNEIGH`/`RTM_DELNEIGH`/`RTM_NEWLINK`/`RTM_DELLINK`) and
  writes MAC + ifindex into `NEXTHOPS[id]` via a seqlock.
- **fast-path XDP program** (in kernel) consults `FIB_V4`/`FIB_V6` LPM
  tries, follows the `FibValue → NEXTHOPS[idx]` chain (or `ECMP_GROUPS`
  for multipath), and redirects with `bpf_redirect_map`. Gated on the
  `FP_CFG_FLAG_PACKETFRAME_FIB` bit in the CFG map; kernel-FIB mode bypasses
  all of the above and calls `bpf_fib_lookup()` as before.

## Healthy operation

Indicators that the PacketFrame FIB path is working:

- `packetframe status` reports `forwarding-mode: packetframe-fib`.
- `fib_hit` counter climbs; `fib_miss` is low relative
  to it (misses indicate prefixes that arrived in XDP before bird
  announced them, or prefixes in the allowlist that bird doesn't cover).
- `fwd_ok` climbs (the shared success counter; custom and kernel FIB
  both increment it on redirect **acceptance** — under generic XDP the
  kernel can still drop the frame silently after the count; see
  `generic-mode-performance.md`, "Silent TX drops under generic XDP").
- `pass_no_neigh` stays below ~1% of matched traffic (`matched_v4 +
  matched_v6`) once the table has converged, and does not trend up.
  Judge it as a rate over 60 s, never from the lifetime total. A
  small floor from neighbours that never answer (dead hosts inside a
  local-prefix, peers that filter ARP/ND) is normal; a sustained climb
  above your converged baseline means nexthops are losing resolution
  and not regaining it — see the triage entry below.
- `packetframe status` shows `nexthops (incomplete)` and `nexthops
  (failed)` at or near zero once the table has converged.
- The fast-path `neigh-resolver` row is healthy and its `last ok` age is a
  few seconds; an idle resolver still makes progress every second.
  `restarts 0` is the norm. Overruns, each matched by a resync, are not
  faults: they are notifications the kernel dropped and the resolver
  recovered. See the triage entry
  [nexthops stuck `incomplete` while the kernel neighbour is
  REACHABLE](#symptom-nexthops-stuck-incomplete-while-the-kernel-neighbour-is-reachable).
- `pass_not_for_us` holds steady as a share of matched traffic. It
  counts allowlisted frames whose destination MAC is not one the router
  receives on at the ingress port: host-to-host frames the kernel is
  bridging past the router on a bridge member, plus every broadcast and
  multicast frame. They go to the kernel untouched, which is correct.
  Near zero on plain routed ports; on a bridge member it tracks how much
  allowlisted traffic stays inside a VLAN. A step change is a triage
  entry below.
- `bmp_peer_down` stays at zero unless a BGP session you expect to
  flap has flapped.
- `nexthop_seq_retry` stays below ~0.01% of `fib_hit` (the
  seqlock retry is ~free on a normal read; sustained retries mean
  the BGP session is churning nexthop MACs nonstop).
- udapi log parse errors: zero (the point of Option F).

Counters live in the `STATS` BPF map. `packetframe status` reads them
out of the pin; no daemon IPC required.

## Everyday inspection commands

### Is packetframe-fib forwarding what you think it's forwarding?

```sh
sudo packetframe status --config /etc/packetframe/packetframe.conf
```

Look at:

- `PacketFrame FIB status:` block: `forwarding-mode`, nexthop resolution
  counts, ECMP group count.
- counter block, especially the `packetframe_fib_*` family.

### Is the route-source session live?

For the recommended iBGP feed:

```sh
ss -Htnp state established "( sport = :1179 )" 2>&1
# Expect one line: the routing daemon ↔ packetframe on the BGP listener port.
birdc show protocols packetframe                    # bird feed
# State should be "Established" with a non-zero "Routes:" count.
vtysh -c 'show bgp neighbor 192.0.2.202'            # FRR feed (the AnyIP address)
# "BGP state = Established", and prefixes sent in the address-family blocks.
```

For BMP (FRR or future bird with Loc-RIB):

```sh
ss -Htnp state established "( sport = :6543 )" 2>&1
birdc show protocols | grep -i bmp
```

If the session is missing:

- `packetframe` daemon is running: `pgrep -a packetframe`
- bird is running: `birdc show status`
- bird's `protocol bgp packetframe { ... }` block is present and
  bird hasn't logged a session-establishment failure: `journalctl
  -u bird | tail -50`

### Feeding from FRR instead of bird (`anyip`)

FRR cannot use the loopback pairing bird uses, for two reasons
diagnosed on a live cutover (2026-08-19):

- zebra treats 127/8 as martian: peer NHT never resolves (`show bgp
  neighbor` reports `Last reset: ... No path to specified Neighbor`,
  zero packets, zero log lines) and even with NHT satisfied,
  `bgp_nexthop_set` finds no interface owning 127.0.0.1 and resets
  the connection before OPEN.
- FRR refuses `neighbor <addr>` for ANY address its host owns, at
  config load: `% Can not configure the local system as neighbor`.

So an FRR-fed packetframe listens on a **phantom address**: pick a
small subnet on an interface that forwards nothing (a bridge with no
member ports works), give FRR the gateway address, and point
packetframe at the unused host address with `anyip`:

```
route-source bgp 192.0.2.202:1179 local-as 65551 peer-as 65551 \
  allow-remote peer-from 192.0.2.201/32 anyip
```

`anyip` makes packetframe install `local 192.0.2.202/32 dev lo`
(kernel AnyIP) before binding and remove it at shutdown, so the
route's lifetime never exceeds the daemon's and no hand-installed
kernel state is needed. The FRR side is an ordinary connected
neighbor:

```
neighbor 192.0.2.202 remote-as <asn>
neighbor 192.0.2.202 port 1179
neighbor 192.0.2.202 update-source 192.0.2.201
neighbor 192.0.2.202 timers connect 10
```

Startup refuses an `anyip` address some interface already owns —
that shape can never establish (FRR would reject the neighbor), so
failing attach loudly beats converging into a dead feed. The session
should report Established, and `ss` one line.
### The completeness authority on an FRR-fed box

`integrity-authority` names the daemon packetframe cross-checks its
mirror against, and on an FRR box that is **`frr`**, not the `birdc`
default and not `none`:

```
integrity-authority frr upstream 192.0.2.1 families v4,v6
```

Where IPv4 and IPv6 arrive over different sessions, say so — `families`
binds to the `upstream` it follows:

```
integrity-authority frr upstream 192.0.2.1 families v4 upstream 2001:db8::1 families v6
```

`none` was the only honest answer before this variant existed — a
`birdc` that is not installed fails blind every 300 s. The reference
router now runs `integrity-authority frr`; a config still saying `none`
on an FRR box should move to it. `none` is also refused alongside
`require-table-complete on`, because a gate waiting on an attestation
nothing produces defers a first steer forever.

`upstream` **and its `families` are both mandatory, and declared,
never inferred.** Only the operator knows which sessions carry the
table as opposed to consuming it, and which families each one carries.
**Do not list packetframe's own session** — that is the thing being
attested, and listing it makes the authority wait on its own answer.

There is deliberately **no default family set**. A default of both is
wrong in both directions and neither is recoverable at runtime: on an
IPv4-only box it makes the authority refuse forever, because FRR
reports no `ipv6Unicast` statistics and an IPv6 End-of-RIB that will
never arrive reads as not-ready; and omitting a family the session does
carry would attest a mirror nobody checked. The families the count
compares are the **union** of what the upstreams carry — derived, not
declared again.

Why upstreams at all, when `birdc` gets by on a count: before an
upstream has finished loading, FRR's table and packetframe's mirror
fill *together*, so the counts agree the whole way up and the
comparison is vacuous. Measured on the lab gateway (FRR 10.1.2,
2026-09-22): two seconds after `clear bgp` the peer read `Established`
with `endOfRibRecv=false`. Session state alone would have called that
table complete. So the authority also requires End-of-RIB from every
declared upstream, scoped to the **current** session.

Three things disqualify the mirror outright, whatever the counts say,
and they report as `Ineligible` rather than as drift:

| Condition | Why counts cannot see it |
|---|---|
| A declared upstream is down, or has not sent End-of-RIB | Both sides fill together; the comparison is vacuous |
| A session re-established since the last check | The previous reading described a session that no longer exists — and on UniFi a session flap is what an FRR config upload looks like, which is the one event that can introduce a filter under a running daemon |
| Something narrows what FRR exports to packetframe — on the peer **or on a peer-group it belongs to** | At a 1% drift tolerance a filter dropping 5,000 prefixes from a million still reads `Converged` |

The export-policy check is a **blacklist**, and its scope is worth
knowing: `route-map`, `prefix-list`, `filter-list` and `distribute-list`
applied **outbound**, plus `unsuppress-map` and `maximum-prefix-out`, on
the peer or on a peer-group it is a member of. Inbound policies and
plain `maximum-prefix` govern what packetframe sends FRR — nothing, on
a passive listener — and are deliberately ignored, since refusing on
them disqualified a valid config over an inbound route-map. An outbound
`route-map` is read rather than refused on sight: it passes when some
entry is `permit` with no `match` and every lower-sequence entry is a
`permit` too (`set` clauses rewrite, they do not drop). A `deny` before
that entry, no such entry, a `call`/`on-match`/`continue`, or a map
name that is not defined (FRR applies it as deny-all) still narrows.
Only the families the authority attests count: a line inside
`address-family ipv6 unicast` does not disqualify a `families v4`
upstream, and lines outside any address-family block count for every
family. A narrowing
directive outside that set would not be caught. Widening it means enumerating FRR's whole
per-neighbor grammar — every directive missing from such a list refuses
a valid config — so it is a measurement task rather than an edit.

One more condition reports as *unknown* rather than disqualified: an
upstream that is Established with End-of-RIB but for which FRR gives no
`peerUptimeEstablishedEpoch`. Readiness with no session generation
behind it cannot be tied to the session running now, so it is not acted
on — but nothing disqualifying was observed either, so a standing
eligibility is retained rather than withdrawn.

How long a disqualification lasts is set by the checker's **interval**:
it clears only on the next clean check, so a session flap costs one to
two intervals. At the default 300 s that is 5–10 minutes (measured on
the lab rig, 2026-09-22), and on UniFi every FRR config upload flaps
every session. `interval <seconds>` (10–300) shortens it:

```
integrity-authority frr upstream 192.0.2.1 families v4 interval 60
```

Each check runs `show bgp <afi> unicast statistics`, which walks the
whole table. Time it on a full-table box before lowering the interval
there — and time it again during a table refill, because that is when
it is slow:

```sh
time vtysh -c 'show bgp ipv4 unicast statistics json' >/dev/null
time vtysh -c 'show running-config' >/dev/null
```

Every `vtysh` call has a **30 s** budget, and a whole check — counts,
every upstream, the running-config, every upstream again — has
**150 s**, however many upstreams are declared. On an idle box these
reads return in well under a second; during a full-table refill they
wait behind the daemons' own update work, and a 10 s budget was
observed to time out on check after check for minutes. A read that
comes back near 30 s under load means the budget is the next thing to
revisit, not the interval.

Upstreams are read twice per check, before and after the
running-config, and an upstream that re-established between the two
readings — or was not loaded at either — disqualifies the check like
any other readiness loss.

A timed-out read is an observation failure — `FRR authority: prefix
count failed` or `eligibility could not be established` with `vtysh
timed out after 30s` or `check budget of 150s spent` — and it changes
nothing: the previous report stands under the age limit and any
disqualification stands with it. What
it does change is pacing: an unreadable check is retried after 10 s,
then 20 s, 40 s and so on back up to the interval, so one slow sample no
longer holds a steering gate's release for a whole interval. A readable
check (clean or disqualified) always waits the full interval.

The ceiling is 300 s, a third of the steering gate's 900 s staleness
limit, and it has to be: assuming a full interval after every attempt,
one failed check means the retained report is next refreshed at about
twice the interval — and that has to land before it goes stale. The
early retry only makes that land sooner; the ceiling does not rely on
it. Slower than the default would only lengthen the flap cost and the
staleness exposure together.

Disqualification is **sticky**: it survives a `vtysh` timeout,
unparseable output, and a clean check whose counts still disagree.
Only a clean, agreeing, non-stale check restores it — "readiness came
back" is not "the mirror is now right". A re-established session
therefore costs exactly one interval, not a latch.

`packetframe feasibility` probes both preconditions before a rollout
window: `fast-path.integrity-authority.vtysh` (is vtysh there and
answering) and `fast-path.integrity-authority.upstreams` (does FRR know
every address you declared). A typo'd upstream is the quiet failure —
it reads as "not Established" on every check, so the authority revokes
forever and nothing ever steers.

**Not supported with a BMP route source**, and config validation
refuses the combination rather than downgrading it. The counts and the
End-of-RIB checks would work, but export-policy validation has no
session to inspect — what narrows a BMP feed is FRR's `bmp targets`
configuration, which this release cannot read — and accepting it would
silently drop the one conjunct the counts cannot substitute for.

Session liveness, unchanged:

```sh
vtysh -c 'show bgp neighbor 192.0.2.202'
```

```sh
ss -Htnp state established "( sport = :1179 )"
```

### Is a specific prefix forwarding through packetframe-fib?

```sh
# What bird says:
birdc show route for 1.2.3.4
# What the kernel says (main table, should be minimal under Option F):
ip route get 1.2.3.4
# What packetframe has in its BPF maps (Phase 3.8+):
sudo packetframe fib lookup 1.2.3.4
# Full dump (O(N) on FIB size; don't do this casually on a 1M-route table):
sudo packetframe fib dump-v4 | head -50
# Just occupancy / mode / hash settings:
sudo packetframe fib stats
```

### Force a route-source resync

Bouncing bird's session to packetframe triggers a Resync + fresh
dump. Same flow for either feed kind:

```sh
# iBGP feed:
birdc disable packetframe
birdc enable packetframe

# BMP feed (FRR / future bird):
birdc disable bmp1   # whatever protocol name is in your pathvector config
birdc enable bmp1
```

packetframe emits `RouteEvent::Resync` on disconnect and receives
the fresh dump on reconnect. Routes the new session does not
re-announce are GC'd at `InitiationComplete`, which fires after 5 s of
post-first-update quiescence. A session that drops before then GCs
nothing; the next session's `InitiationComplete` does.

The GC covers the feed's routes only. The `fallback-default` 0/0 and
the `local-prefix` host routes come from the neighbour resolver, not
the feed, and stay in place in both the FIB and VPP. Before 0.6.0
every reconnect deleted them (and FRR on UniFi reconnects at every
config upload); a host route came back at the kernel's next update
of its neighbour entry, the default only at a daemon restart.

### Inspecting the FIB programmatically

The `packetframe fib` subcommand opens the pinned BPF maps directly.
No daemon IPC. Works as long as the pins exist (i.e., after
`systemctl stop packetframe` but before `detach --all`).

```sh
# LPM-resolve a single IP.
sudo packetframe fib lookup 8.8.8.8

# Walk the whole FIB (O(N); slow on a 1M-route table).
sudo packetframe fib dump-v4

# Occupancy / mode / hash block only (scriptable).
sudo packetframe fib stats
```

### Prometheus metrics for PacketFrame FIB

Alongside the existing counter family, the textfile exporter emits:

- `packetframe_fib_forwarding_mode{mode="kernel-fib|packetframe-fib|compare"}`:
  one-hot gauge; alert on unexpected transitions.
- `packetframe_nexthops{state="resolved|incomplete|failed|stale|freed|unwritten"}`:
  NEXTHOPS slot counts. `incomplete` + `failed` are live nexthops whose
  traffic is on the kernel path — alert on them. `freed` is tombstones
  left by churn (harmless), `unwritten` is untouched capacity. (Replaces
  the former `unwritten_or_incomplete` bucket, which could not separate
  the two and hid the alerting half.)
- `packetframe_nexthops_max`: configured NEXTHOPS capacity.
- `packetframe_ecmp_groups_active`, `packetframe_ecmp_groups_max`.
- `packetframe_fib_default_hash_mode`: 3/4/5-tuple.
- `packetframe_fib_neigh_resolver_*`: the neighbour resolver's overruns,
  resyncs, request timeouts and restarts (counters), whether a resolver
  loop is running, its progress age, and how long it has been waiting on
  the programmer (gauges). See the triage entry
  [nexthops stuck `incomplete` while the kernel neighbour is
  REACHABLE](#symptom-nexthops-stuck-incomplete-while-the-kernel-neighbour-is-reachable).

Example alerts:

```promql
# 80% NEXTHOPS occupancy: every live bucket counts, and the failure
# mode this section describes is precisely thousands of `incomplete`.
sum(packetframe_nexthops{state=~"resolved|incomplete|failed|stale"})
  / packetframe_nexthops_max > 0.8

# Nexthops whose traffic is on the kernel path.
sum(packetframe_nexthops{state=~"incomplete|failed"}) > 0

# The neighbour resolver is stuck, or not running at all. A wait on the
# programmer also stops its progress, and is not its fault.
(packetframe_fib_neigh_resolver_progress_age_seconds > 30
  and packetframe_fib_neigh_resolver_programmer_wait_seconds == 0)
  or packetframe_fib_neigh_resolver_running == 0

# The daemon had to restart its neighbour resolver.
increase(packetframe_fib_neigh_resolver_restarts_total[1h]) > 0

# Unexpected forwarding-mode transition.
changes(packetframe_fib_forwarding_mode{mode="packetframe-fib"}[5m]) > 0
```

### Integrity check + BmpStalled alert

When `route-source bmp` is configured, the daemon runs a 5-minute
periodic job that shells out to `birdc show route count` and
`birdc show protocols`, compares the totals against the
programmer's mirror size, and logs warnings on drift ≥ 1%:

```
WARN integrity drift above threshold bird_prefixes=1048587 packetframe_prefixes=1048501 drift_fraction=0.000082
```

The drift threshold is `IntegrityConfig::drift_warn_fraction`
(default `0.01` = 1%). Below threshold goes to `DEBUG` level only.
A bird reporting **zero** routes in `master4`/`master6` warns on its
own line (`integrity check: bird reports no routes in master4/master6`)
rather than passing silently — an authority with no routes cannot
attest anything, and it used to log nothing at all.

**Read the verdict from `packetframe status`, not from the log.** The
same comparison is the `fib-integrity` subsystem row on the fast-path
module, carrying both counts, the drift against the threshold that was
applied, the sample's age, and any error:

```
  fast-path: healthy
    fib-integrity  healthy — bird 1272306 prefixes, mirror 1272281 — drift 0.002%,
                   within the 1.000% warn threshold. A steering gate reads this same
                   comparison and would permit a steer ... (last ok 41s ago)
```

Two facts, and they are not interchangeable. The drift against the
warn threshold is **this module's** alarm, and `drift-warn-fraction`
tunes it. The sentence after it is what a second tier's steering gate
would decide from the same comparison, obtained by calling that gate's
own decision function — which uses its own fixed threshold and its own
900 s freshness window, so at a tuned warn fraction the two verdicts
legitimately differ. For a rollout, the second one is the one that
matters.

The row is present whenever a checker is running, **including before
its first comparison completes** — "no comparison has completed yet"
and "compared, and they agree" are deliberately different lines,
because a rollout is gated on the difference (see
`docs/runbooks/vpp-offload.md`). No row at all means no checker: either
`kernel-fib` mode or a control plane with no `route-source`.

BmpStalled:

```
WARN BMP session appears stalled (no ROUTE MONITORING + bird reports Established peers) quiet_seconds=312 bird_established_peers=2
```

Fires on: no ROUTE MONITORING for ≥ 5 min AND bird's cached
Established-peer-count ≥ 1 AND process uptime > 10 min. Gated on
the `birdc show protocols` cache to avoid false-positives during
bird outages.

## Connected fast-path (v0.2.1)

### What it solves

Bird's iBGP feed gives us the connected /24 (e.g. `198.51.100.0/24`
on `br1337`) with a self-referential BGP NEXT_HOP (the device's local
IP). The neighbour resolver can't map that to a useful destination
MAC: it's our own IP. Without the connected fast-path, the LPM
lookup hits the /24 with `state=Incomplete` and returns
`fib_no_neigh` (or, pre-v0.2.1, `fib_miss` because the
listener silently dropped the announce). Either way, the packet
falls through XDP_PASS to kernel slow-path: through netfilter,
conntrack, the FIB walk, and finally out the bridge. That's exactly
the load fast-path exists to remove.

The connected fast-path inverts this: NetlinkNeighborResolver walks
the kernel ARP table for hosts within an operator-declared CIDR
+ iface, registers a per-/32 NEXTHOPS entry with the host's real
MAC at `state=Resolved`, and inserts the /32 in FIB_V4. The /32
wins over the /24 in LPM, so XDP redirects directly to the host.

Those /32s put both ends of same-subnet host-to-host traffic in the
FIB. On a bridge member the XDP hook also sees the frames the kernel
bridges between two such hosts. They are addressed to the other host's
MAC, not the router's, so the destination-MAC check passes them to the
kernel to bridge untouched (`pass_not_for_us`). Only frames addressed
to the router take the /32.

### When to enable it

When you're running packetframe-fib (not kernel-fib) and the box has
connected /24s carrying meaningful inbound traffic. Typical case
on the reference EFG: customer LANs (`198.51.100.0/24`), internal
storage networks (Ceph: `203.0.113.64/26`), and other LAN bridges.
On the reference EFG with all peers up, expect the bypass rate
to climb from ~30% to >95% once kernel ARP populates.

### Config

```
module fast-path
  forwarding-mode packetframe-fib
  route-source bgp 127.0.0.1:1179 local-as 65551 peer-as 65551

  # One line per local prefix you want fast-pathed inbound:
  local-prefix 198.51.100.0/24 via br1337    # customer LAN
  local-prefix 203.0.113.64/26    via br88      # Ceph internal
  local-prefix 192.0.2.64/26    via br0       # other LAN

  # IPv6: same idea, one /128 per NDP neighbour. Declare the prefix
  # actually configured on the iface, not the aggregate you announce.
  local-prefix6 2001:db8:0:1337::/64 via br1337
```

The `via <iface>` is required and must match the kernel iface
hosting the prefix. Validate at startup the same way `attach`
directives validate (must exist under `/sys/class/net`); a missing
iface is a startup-fatal error.

The directive set is additive. Declare as many as you have
connected destinations to fast-path. Each adds one hashmap-walk
of the kernel's neighbour table at startup and one match per
multicast neighbour event. Match cost is O(N) over the local-prefix
list, so keep the list to a handful (the reference EFG has 6).

### Verification after enabling

```sh
# 1. Confirm /32s landed in the FIB. Should see one entry per
# kernel ARP entry within each declared local-prefix.
sudo packetframe fib dump-v4 | grep -E '^198\.51\.100\.[0-9]+/32' | head
sudo packetframe fib dump-v4 | grep -E '^203\.0\.113\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])/32' | head

# 2. Lookup a specific host. Should report state=resolved with the
# host's actual MAC and the iface's ifindex.
sudo packetframe fib lookup 198.51.100.10

# 3. Watch the resolver stats. `local_arp_routes_added` climbs as
# the kernel ARPs new hosts; `_removed` climbs on RTM_DELNEIGH
# (typical aging churn).
journalctl -u packetframe -f | grep 'neighbour resolver stats'

# 4. Bypass rate. Compare fib_hit / matched_v4 before vs.
# after enabling. Typical recovery: matched_dst_only flips from
# ~100% miss to ~100% hit. (rate may climb gradually as kernel
# ARP populates the cache for under-trafficked hosts.)
sudo packetframe status | grep -E 'matched_v4|fib_hit|fib_miss|fib_no_neigh'
```

For `local-prefix6`, the same four checks with the v6 tools. Note
`fib lookup` already accepts either family, so only the dump command
differs:

```sh
# 1. One /128 per NDP neighbour inside each declared local-prefix6.
sudo packetframe fib dump-v6 | grep '2001:db8:0:1337'

# 2. A specific host: expect the connected iface's ifindex and that
# host's own MAC, NOT one of your transit nexthops.
sudo packetframe fib lookup 2001:db8:0:1337::7

# 3. v6 has its own counters in the same stats line, kept separate so
# a dual-stack segment stays readable.
journalctl -u packetframe -f | grep 'neighbour resolver stats'
#   ... local_nd_routes_added=12 local_nd_routes_removed=1

# 4. pass_ndp should be non-zero and climbing: neighbor discovery is
# deliberately handed to the kernel (see the NDP note below).
sudo packetframe status | grep -E 'matched_v6|pass_ndp|fib_hit|fib_miss'
```

Cross-check the /128 set against the kernel. These two should agree,
and the packetframe side must contain **no** `fe80::` or `ff02::`
entries:

```sh
ip -6 neigh show dev br1337 | grep -v fe80
sudo packetframe fib dump-v6 | grep '2001:db8:0:1337'
```

### Capacity considerations

Each declared local-prefix can register up to one /32 per active
kernel ARP entry. NEXTHOPS_MAX_ENTRIES is 8192 by default; a typical
EFG with a few dense customer /24s plus internal LANs sits well
under this (the reference EFG configured below uses ~500-1000 of
8192). If you operate a *very* dense LAN where active hosts
approach 8192, plan to either raise the cap (BPF rebuild) or skip
the directive on that prefix and accept the slow-path fallback.

**The pool is shared.** NEXTHOPS is one 8192-entry allocation covering
v4 /32s, v6 /128s, *and* every BGP nexthop. Because these synthesized
routes use nexthop == destination, there is no sharing: each connected
host consumes its own slot. FIB_V6 itself holds 1,048,576 entries, so
NEXTHOPS is always the binding constraint.

**IPv6 multiplies this.** A host has one address in v4 and several in
v6: a stable SLAAC address plus RFC 4941/8981 temporary addresses that
rotate (Linux defaults give up to ~7 concurrently valid), plus possibly
DHCPv6 and static. Only addresses that actually source traffic get
learned, so 2-3 per host is typical and ~9 is the worst case — call it
900-2700 hosts before the pool is the limit.

In practice the kernel bounds this before packetframe does:
`net.ipv6.neigh.default.gc_thresh3` defaults to 1024, and you cannot
harvest more /128s than the kernel holds entries. **If you have raised
`gc_thresh3`** (routers often do), that ceiling moves and the shared
pool becomes reachable. packetframe checks this itself: at startup,
when any local-prefix is configured, it compares the summed thresholds
against the pool and logs a WARN when they exceed it. To check by hand:

```sh
cat /proc/sys/net/ipv4/neigh/default/gc_thresh3
cat /proc/sys/net/ipv6/neigh/default/gc_thresh3
```

Exhaustion degrades cleanly rather than corrupting: the programmer
returns `Full`, unwinds any partially-allocated nexthops, and the route
simply isn't installed — one `WARN` per event, and that destination
falls to the kernel. The risk worth watching is that a dense v6 segment
starves *BGP* nexthops, which matters much more than losing a
connected /128.

### When NOT to enable it

- **kernel-fib mode.** The kernel handles connected destinations
  natively via `bpf_fib_lookup()` + ARP cache, no extra config
  needed. The directive is a no-op in this mode (parsed and
  validated, but the resolver only emits events when both
  packetframe-fib AND a route-source are configured).
- **Operator hasn't declared the customer prefix in `allow-prefix`.**
  XDP filters on allowlist BEFORE the FIB lookup, so a /32 in the
  FIB does nothing if the parent prefix isn't matched. Add the
  customer /24 to `allow-prefix` first. Same for `local-prefix6`:
  it needs a covering `allow-prefix6`, and that is a separate
  directive — declaring only the v4 pair is the common slip.
  packetframe logs a startup WARN for any local-prefix directive
  with no overlapping same-family allow entry.
- **The prefix isn't actually connected.** Declare what is configured
  on the interface (`ip -6 addr show dev <iface>`), not the aggregate
  you announce to the world. The announced aggregate is a null-routed
  static in bird; it is not a connected prefix and must never reach
  the FIB as a forwarding entry.
- **Non-global-unicast v6 prefixes.** `local-prefix6` refuses
  multicast (`ff00::/8`), link-local (`fe80::/10`), `::/0`, `::`,
  `::1` and IPv4-mapped at parse time. None can be a forwarded
  connected-host destination. `fe80::/10` is the tempting one, since
  `ip -6 neigh show` is mostly link-local addresses — but they are
  ambiguous across interfaces (the same `fe80::` address legitimately
  exists on several with different MACs) and would burn a NEXTHOPS
  slot each for routes that can never be used.
- **Tunnels and weirdness.** Don't declare local-prefix on a tunnel
  iface (WireGuard, GRE, IPSec). The BPF program can't redirect
  to non-XDP-capable interfaces, so the /32 just sits unused.
  Stick to physical and bridge interfaces.

### Disabling

Remove (or comment out) the `local-prefix` / `local-prefix6` lines and
restart packetframe. SIGHUP doesn't reconcile these directives in
v0.2.1. A future version may add live add/remove via SIGHUP, but for
now it's a startup-time-only configuration. The /32 and /128 entries
get flushed on detach and don't reappear at next startup without the
directive.

### `arp-scavenge` for quiet LANs (v0.2.1, issue #32)

Some LANs (Ceph clusters, monitoring networks, anything where
hosts only do intra-/24 L2 traffic) never appear in the kernel's
L3 ARP cache. Without entries to feed from, the per-/32 emission
finds nothing.

The optional tail flag forces a one-shot ARP sweep at startup:

```
local-prefix 203.0.113.64/26 via br88 arp-scavenge
```

Capped at /22 (≤ 1024 hosts) at config-parse time. Rate-limited at
500 probes/sec internally. Live hosts respond → kernel ARPs them →
multicast event lands the /32. Operator opt-in (default off) because
it generates noticeable ARP traffic.

**Safety guarantee (v0.2.2+).** ARP probes are issued ONLY on the
operator-declared `via <iface>`. The resolver does NOT consult the
kernel's routing table when picking the egress iface for the probe.
This is a deliberate v0.2.2 safety fix: pre-v0.2.2 the code used
kernel route lookup, which on a multi-VID bridge box (e.g. EFG's
`switch0` carrying customer VIDs alongside IX peering VIDs) could
broadcast ARP probes onto an IX bridge if the declared CIDR
happened to resolve via an IX VLAN subif. The fix scopes the sweep
strictly to the operator's chosen iface; ARP traffic cannot escape
that iface's L2 broadcast domain.

**Critical: do NOT declare `arp-scavenge` on an IX-attached iface.**
Even with the safety scoping, declaring `local-prefix <ix-subnet> via
<ix-bridge> arp-scavenge` would still broadcast ARP into the IX
fabric, which violates IX ToS (MANRS, anti-DoS) on most exchanges.
`arp-scavenge` is for INTERNAL LANs only (storage, management,
customer LAN). For IX peer subnets, rely on bird's natural ARP
behavior: bird already maintains ARP for active BGP peers, so
their /32s will land via the normal nexthop-resolution path.

#### There is no IPv6 equivalent, and there should not be

`local-prefix6` rejects `arp-scavenge` at parse time. This is not a
missing feature; enumeration is the wrong tool for IPv6 at any cap:

- **A /64 is 2^64 addresses.** Even a "safe" cap of /118 (1024 hosts,
  matching the v4 limit) only sweeps the bottom of the range.
- **IPv6 hosts are not at the bottom of the range.** SLAAC (RFC 4862)
  derives the interface identifier from the MAC, and stable-privacy
  addressing (RFC 7217) hashes it. Both scatter hosts across the full
  64-bit identifier space, so a swept range matches essentially no
  autoconfigured host. The only hosts a sweep *could* find are
  hand-numbered `::1..::ff` servers — and those are statically
  configured and actively talking, which means they are already in the
  neighbour table that reactive seeding reads.
- **NS is noisier than ARP per probe.** Neighbor solicitation goes to
  the target's solicited-node multicast group, so an N-address sweep
  hits N *distinct* groups, defeating MLD-snooping caches, and
  `mcast_solicit` retries each unanswered probe.

So IPv6 relies entirely on reactive seeding: the startup neighbour dump
plus `RTM_NEWNEIGH` events. In practice this is sufficient where the v4
case was not, because v6 hosts announce themselves far more readily —
DAD, router solicitation, and neighbor unreachability detection all put
a host in the router's neighbour table without the router asking.

If a v6 host is genuinely missing, force one round of resolution rather
than reaching for a sweep:

```sh
ping6 -c1 -I br1337 ff02::1        # all-nodes on the segment
ip -6 neigh show dev br1337        # then confirm it landed
```

### `fallback-default` synthetic /0 (v0.2.1, issue #31)

PacketFrame FIB only has prefixes bird's iBGP feed advertised. Destinations
bird doesn't have specific routes for (RFC 1918, CGNAT, test-net,
anything outside DFZ) miss LPM, fall to kernel slow path through
netfilter / conntrack, and get dropped upstream anyway, wasting
kernel CPU + conntrack table capacity.

```
fallback-default via eth3 nexthop 203.0.113.1
```

Injects a `0.0.0.0/0` into FIB_V4 at startup. Every more-specific
bird-fed route still wins LPM; the /0 catches bogon-bound traffic.
XDP redirects directly to upstream: same upstream rejection behavior,
just no kernel / conntrack involvement. Measured ~25% reduction in
steady-state conntrack pressure on a busy Tor exit relay.

The /0 follows its interface. It lives under the interface's
`local_arp` peer, like the `local-prefix` host routes, so deleting the
interface withdraws it from the PacketFrame FIB and, through the route
sink, from VPP (`fallback-default iface deleted; 0.0.0.0/0 withdrawn
until its RTM_NEWLINK`). When an interface by that name appears again,
or for the first time if it was absent at startup, its `RTM_NEWLINK`
injects the /0 under the new ifindex (`v0.2.1 fallback-default 0.0.0.0/0
injected`). No restart is needed.

The /0 only ever sees frames addressed to the router. Broadcast,
multicast and bridged host-to-host frames never reach the FIB
(`pass_not_for_us`), so a subnet broadcast or an mDNS packet from an
allowlisted host is not sent upstream.

### `block-prefix` (v0.2.1, issue #33)

Drop bogon-bound traffic at XDP rather than let it traverse the
kernel forwarding path:

```
allow-prefix 198.51.100.0/24
block-prefix 10.0.0.0/8
block-prefix 100.64.0.0/10
block-prefix 192.168.0.0/16
```

After the allowlist match (so we only affect traffic we'd otherwise
fast-path), if dst is in any `block-prefix` the program returns
`XDP_DROP` and bumps `bogon_dropped`. Saves skb allocation +
netfilter walk + conntrack entry per dropped packet.

dst-only match: we never block by src, because that would silently
drop reply traffic for asymmetric flows where the *peer* happens to
be in a bogon range.

Refuses to start if a `block-prefix` overlaps any `allow-prefix` or
`local-prefix` (operator config bug; would silently drop traffic to
declared customer prefixes).

## WAN egress

`wan-egress` is a fast-path directive, but it acts on the kernel's
routing policy rather than on the BPF datapath, and it works in every
forwarding mode (`kernel-fib` included).

### When and why

It is for gateways where all three of these hold:

- the full BGP table is installed into the kernel's `main` table;
- the platform consults `main` (the rule `lookup main`) *before* its own
  WAN policy rules (fwmark rules into per-WAN tables, a catch-all into
  the primary WAN's table);
- the platform's NAT is masquerade on the WAN egress interfaces only.

Then a private (RFC 1918) source whose destination's best BGP path is a
peering interface follows `main` out of that interface with no NAT, and
the flow dies. The platform's own tools do not help: its policy routes
are fwmark rules evaluated after `main`, a source-NAT rule on the
peering interface may be accepted by the UI and never provisioned, and
hand-added `ip rule` or iptables state is wiped by the next provisioning
pass, reboot or firmware upgrade.

```
wan-egress from <cidr> [from <cidr> ...] [keep <cidr> ...]
```

Traffic from each `from` prefix skips `main` and continues with the
rules after it, so the platform picks the WAN and NATs as it would for
any destination it has no BGP route for. Destinations in the keep set
still use `main`. The keep set is always:

- 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 (RFC 1918);
- 100.64.0.0/10 (RFC 6598 shared address space);
- 169.254.0.0/16 (link-local);
- every IPv4 `allow-prefix` and `local-prefix` in the section.

Each `keep` adds to it. Both lists are normalized: host bits cleared,
duplicates and prefixes covered by another entry dropped. IPv4 only
(there is no NAT66 to hand IPv6 to). One `wan-egress` line per section;
a `/0` is refused on either side.

### How it works

Three kinds of policy rule, all tagged `proto 199`, PacketFrame's
protocol number (the same tag the `anyip` route wears):

```
31998:  from <src> to <keep> lookup main     # one per (source, keep) pair
31999:  from <src> goto 32001                # one per source
32000:  from all lookup main                 # the platform's own rule
32001:  from all lookup local                # the anchor, only when 32001 is free
```

(Priorities for a `lookup main` at 32000; on stock Linux, where `main`
is at 32766 and `default` at 32767, the goto targets 32767 and no
anchor is needed.)

- **Where `main` is.** Each pass dumps the IPv4 rules and takes the
  lowest-priority `lookup main` with no selectors and no PacketFrame
  tag. Rules with an fwmark, interface, `suppress_prefixlength` or
  other selector do not count. If there is none, or a second one
  follows the first (the goto would only land on it), nothing is
  written.
- **Keep and goto.** The goto sits at the nearest priority below
  `main` that no foreign rule uses; the keep rules at the nearest free
  one below that, all within 100 of `main`. A priority shared with a
  foreign rule is never used: the kernel orders same-priority rules by
  insertion time, which the platform's next provisioning pass would
  change. A foreign rule that ends up between the goto and `main` is
  skipped for wan-egress sources, as `main` is.
- **Anchor.** The kernel resolves a goto only to a rule that exists at
  its target priority. An unresolved goto is skipped, which would
  quietly put the sources back in `main`. The gotos therefore always
  target `main + 1`, and when nothing foreign sits there PacketFrame
  installs `from all lookup local` there. That lookup always misses:
  the `local` table was already consulted at priority 0 with the same
  flow and missed, or evaluation would not have got this far. So it
  behaves exactly like a `nop`, and evaluation continues into the
  platform's own rules, whatever they are.
- **Why not a `nop`.** UniFi's udapi-server reads every policy rule
  when it starts and aborts (`neither table nor goto is defined for
  routing rule`) on any rule with neither a table nor a goto. It checks
  only at start, so a `nop` anchor sits harmless until udapi-server
  restarts, and then systemd's restarts all fail until the rule is
  deleted. Builds before this change wrote a `nop` anchor; the first
  pass of a newer daemon adds the `lookup local` anchor, then deletes
  the `nop` (the kernel moves the goto to the remaining rule at that
  priority) and logs `32001: from all nop (legacy anchor)` as removed.
- **Ownership.** A rule wearing `proto 199` is PacketFrame's: adopted
  when a new daemon finds it, repaired or removed as the config says.
  A rule without the tag is never modified or deleted.
- **Reconcile.** At start, on every `packetframe reconfigure` (the
  directive is hot-reloadable; editing `allow-prefix` or `local-prefix`
  changes the keep set too), on every IPv4 rule change (1 s debounce),
  and every 30 s. A pass writes only the difference; when everything is
  in place it writes nothing, so it wakes no other daemon that watches
  rule events.
- **Lifetime.** The rules serve kernel forwarding, which runs whether
  or not the XDP datapath does, so only "PacketFrame is leaving this
  box" removes them:

  | Event | Rules |
  |---|---|
  | `systemctl stop` (preserve-attach exit) | Stay; the next start adopts them |
  | `packetframe detach --keep-vpp` (the routine restart) | Stay; the next start adopts them |
  | Circuit-breaker trip | Stay. The breaker stops XDP because XDP was dropping traffic; removing the rules too would send private sources back out the peering interface until an operator restarts |
  | `packetframe detach`, `packetframe detach --all` | Removed (found by their tag in a fresh dump, no state file needed) |
  | Reload whose config drops `wan-egress` | Removed before the reload returns; retried every pass if that fails |
  | Start whose config has no `wan-egress` | Any tagged rules left behind are removed |

  Adoption is a pass like any other: rules already in place are left
  untouched, and nothing is written.

### Status and troubleshooting

`packetframe status` shows a `wan-egress` row whenever the directive is
in force:

| Row | Meaning | What to do |
|---|---|---|
| healthy, `N rules in place; keep at K, goto G -> T past main at M` | Every rule is in place | Nothing |
| degraded, `no unconditional lookup main rule found` | Nothing to skip past; nothing was written, existing rules left as they were | `ip rule show`; the platform may be mid-provisioning. It retries every pass |
| degraded, `priorities ... below main are taken` | Fewer than two free priorities within 100 of `main`; nothing written or changed | `ip rule show` to see what fills the band |
| degraded, `a second unconditional lookup main at S follows the one at F` | Skipping the first `main` would only reach the second; nothing written or changed | Usually a provisioning pass caught half-way; if it persists, find which one the platform meant to keep |
| degraded, `repair failing: X of Y rules in place; ...` | A dump or write failed. Writes stop at the first failed stage (anchor, then keep, then goto), and nothing old is removed until every new rule is in, so a partial pass never leaves a goto without its keep rules | The error names the rule and the netlink error; it retries every pass |
| degraded, `removed from the config, but its rules could not all be removed` | A reload dropped the directive and the removal did not finish | It retries every pass and on the next reload; `packetframe detach` also removes them |

**udapi-server will not start and logs `neither table nor goto is
defined for routing rule`.** List the rules it objects to with
`ip -4 rule show | grep -v -E 'lookup|goto'`. A `from all nop proto 199`
there is the anchor of a PacketFrame build from before the `lookup
local` anchor; delete it with `ip -4 rule del pref <prio> nop`. While
that build is running it puts the rule back within a second, so stop
it first, or remove `wan-egress` from the config and reload. udapi-server
also deletes the wan-egress goto when it starts; a running daemon puts
it back on the rule event, so after starting udapi-server with
PacketFrame stopped, the sources stay in `main` until PacketFrame runs.

The textfile metrics carry `packetframe_wan_egress_rules{state="desired"}`,
`packetframe_wan_egress_rules{state="present"}` and
`packetframe_wan_egress_converged`. A repair (rules put back after they
disappeared under an unchanged config) is logged and recorded in the
event log as `wan_egress_repaired`, at most once every five minutes.

To check the path a flow takes:

```sh
ip -4 rule show
ip -4 route get <dst> from <private-src> iif <lan-iface>
```

Before the fix the second command names the peering interface; after
it, the WAN interface (and a kept destination still names whatever
`main` says).

**The allow-prefix caveat.** The fast path matches the allowlist on
source as well as destination, so a flow from an allowlisted source is
forwarded by XDP (and by VPP when steered) and never reaches kernel
routing, these rules, or the platform's NAT. A `from` prefix that
overlaps an `allow-prefix` is warned about at start and on reload, and
wan-egress cannot affect those flows.

## Restarts: the route ledger

### What a restart cost, and what changed

Every start used to load the route mirror from nothing. On the
reference router the route source is FRR's bgpd over iBGP, and it sets
the pace, not packetframe: measured 2026-10-07, the session came up at
T, the mirror held 496k routes at T+4 min, and the full ~1.35M took
about 11 minutes (~2,000 routes/s, bgpd at 80% CPU, packetframe's
threads at ~7%). For those minutes the eBPF tier forwarded on a partial
FIB (misses fell to `fallback-default` or the kernel), the completeness
authority vetoed, and an unsteered VPP could not take its first steer.

Now a clean stop leaves the mirror for the next start, and the next
start seeds from it **before the route source connects**. The FIB is
full within seconds of the start; the route source's replay then
confirms it route by route instead of building it.

### When it is written, and what is in it

Only at a **clean preserving exit** — SIGTERM / `systemctl stop`, where
the loader calls `Module::exit_preserving` just before it drops the
modules. A crash, a `kill -9` or a circuit-breaker trip writes nothing,
and the next start loads cold, as every start used to.

The snapshot and the write (temp file, fsync, rename) share one **5 s
budget**, so neither a wedged programmer nor a wedged filesystem can
hold the exit. The write runs on a helper thread; past the deadline the
stop gives up and goes on (`reason=... did not finish within its 5000
ms budget ...`), and when the helper's I/O finally returns it removes
its temp file instead of renaming it into place. So a stop that gave up
leaves no ledger, and the next start loads cold. (A temp file left by a
process that exited first is never read: a start opens only the
ledger's own name, and the next write replaces it. The one outcome the
deadline cannot settle is a rename already under way when it passes;
`rename` is atomic, so that ends in a whole ledger or none, and the
reason says so.)

```
preserved the route mirror as the route ledger: the next start seeds from it ...
  prefixes_v4=... prefixes_v6=... bytes=... encode_ms=... write_ms=...
# or
the route mirror was not preserved; the next start loads it cold ... reason=...
```

- **File:** `<state-dir>/fast-path-route-ledger.bin`, ~14 bytes a route
  (~19 MB for 1.1M IPv4 + 250k IPv6), written temp file → fsync →
  rename through the same no-follow state-dir primitives as every other
  record, mode 0600 and owned by the daemon's uid. A trailing checksum
  covers all of it — integrity, not provenance: the next start reads it
  only if its ownership and modes, and those of `state-dir` and its
  ancestors, show no other account could have written it (`untrusted`
  below). A keyed MAC would add nothing: its key would have to live
  where other accounts cannot write, which is the same guarantee, one
  file away.
- **Contents:** every advertisement from the route source — prefix,
  peer id, path id, nexthops, local-pref — and **nothing the neighbour
  resolver injected** (`fallback-default`'s 0/0, the `local-prefix`
  host routes). The resolver re-injects those at every start from the
  live kernel, which is fresher than a file. Plus the format version,
  the writing version, the write time, the route-source identity (mode,
  listen address and port, ASNs, peer pin, and the `peer-from` ACL when
  no pin names the speaker) and per-family counts.
- **How old its routes are**, which is not always the write time. A
  route the live session had not re-advertised by the stop — the session
  was down (a `Resync` with no new session yet), or the stop came before
  a previous seed's replay reached it — carries the time it was **last
  confirmed**. The age check reads that, so a stale route cannot ride
  from ledger to ledger across restarts that never reconcile it. The
  `route_ledger_preserved` event carries `unconfirmed_for_secs` when this
  applies.
- **Cost, measured** (one run each, a Linux VM on Apple silicon; time it
  on the gateway too): building the record from the mirror 340 ms for
  1.35M routes; writing it ~10 ms; reading, removing and validating it
  ~70 ms; seeding 1.35M routes into the real BPF maps 1.55 s.

### What the next start does with it

1. **Consumes it**, in every forwarding mode: read, then removed,
   before anything else looks at it — whether or not it is used. A
   crash loop never seeds from the same file twice, and a kernel-fib run
   cannot leave a table that goes stale under it for a later
   packetframe-fib start to find.
2. **Checks it**, and refuses it by name — journal line
   `route ledger not used; the route mirror loads cold`, event
   `route_ledger_refused` with `reason`, and the `route-ledger` status
   row:

   | `reason` | When |
   |---|---|
   | `missing` | No file: the previous stop was not clean, preserved nothing, predates the ledger, or a full `packetframe detach` ran since |
   | `disabled` | `route-ledger off`, and an earlier run had left one |
   | `forwarding-mode` | Not `packetframe-fib`. `compare` validates the PacketFrame FIB against the kernel's, and stale seeded routes would read as disagreements |
   | `no-route-source` | No `route-source`, so nothing could ever reconcile a seed |
   | `unreadable` | It could not be read (I/O error, planted symlink); removed anyway |
   | `untrusted` | Untrusted ownership/permissions: the file is not owned by the daemon's uid or is group- or world-writable, or so is the directory holding it, or an ancestor directory is owned by someone other than root or is writable by group or others without the sticky bit (so another account could rename `state-dir` away), or it is not a regular file. Judged on the open descriptors before a byte is read; removed unread. Its routes would be installed by root, so a file another account could have written is never trusted, whatever its checksum says. Fix the state-dir's ownership and modes (`chown root:root`, `chmod 755` or tighter) |
   | `too-large` | Larger than the largest ledger a FIB at capacity could encode to (about 585 MB; a full table is ~19 MB). Judged from the file's size before a byte is read; removed unread |
   | `unremovable` | It could not be removed, so it cannot be consumed once. Status degrades; remove it by hand |
   | `corrupt` | Truncated, checksum mismatch, structurally wrong, empty, or naming a resolver peer id |
   | `format-version` | Written by a build with another layout |
   | `identity` | Written for a different route source (mode, address, port, ASNs or peer pin changed, or the `peer-from` ACL wherever no peer pin names the speaker: always for BMP, and for BGP without `peer-ip`). `router-id`, `anyip`, and the ACL under a `peer-ip` pin are not identity |
   | `too-old` | Its oldest routes were last confirmed longer ago than `max-age` (default 30 minutes) |
   | `clock` | Confirmed more than a minute in the future: the clock moved across the restart, so no age can be established |
   | `peer-id` | A BGP ledger names a peer id this build's listener would not use for that route source (the id derivation changed between versions); seeded routes would never be replaced |

3. **Seeds the mirror**, ahead of everything else the programmer does.
   Every seeded advertisement goes in **unseen**, exactly as a session
   loss (`Resync`) leaves the mirror. The route source may connect at
   once: its UPDATEs queue behind the seed, never ahead of it. (Neighbour
   events keep flowing between chunks of the seed, so the nexthops it
   registers resolve while it runs. The resolver's own `fallback-default`
   and `local-prefix` routes wait for it, too.) The second tier hears
   every seeded route like any install. Event `route_ledger_seeded`.
4. **Lets the live session reconcile it.** A re-advertisement of an
   identical route marks it seen and changes nothing else: no FIB
   write, no destination-cache flush, no route delta to VPP. A route
   that changed while the daemon was down is an ordinary update. When
   the session's initial dump goes quiet (`InitiationComplete`, 5 s of
   silence), the GC removes every seeded route it did not re-advertise —
   event `route_ledger_reconciled` with `gc_removed`.

The staleness this accepts is the one a session loss already accepts:
until the replay reaches a route, it forwards where it did when the
daemon stopped. The age bound caps how far behind that can be.

### What it means for the gates

- **The completeness authority** (`integrity-authority frr` or `birdc`)
  does **not** attest a seeded mirror until the route source's first
  route has arrived. Until then FRR's count agrees with the seed by
  construction, which says nothing about whether anything will ever
  update it (a listener that never came up, an FRR that no longer peers
  with this box). `frr` reports it as a disqualification — `the route
  mirror was seeded from the route ledger and the route source has not
  started streaming to this daemon yet` — and `birdc` withholds its
  report. **The check after that runs the moment the first route
  arrives**, not an interval later. From then on it is the ordinary
  comparison: counts within 1% → `Converged`.
- **vpp-offload, fresh VPP** (nothing to adopt — after a reboot, say):
  routes install as the seed lands, and the verify hold releases on that
  first attested check with the source's backlog drained. A first steer
  no longer waits for the replay.
- **vpp-offload, unsteered adopted VPP**: the adopted diff normally
  waits behind the loaded-and-quiet gate, where "quiet" counts every
  element the route source streams, changed or not (deliberately, since
  #153). A seeded mirror has a second door that does not wait for the
  replay: seed unreconciled, feed session up, and the authority's
  current word yes ([the unsteered diff and a seeded
  mirror](vpp-offload.md#the-unsteered-diff-and-a-seeded-mirror)). Verify
  follows and the port is `Ready`; the first steer is then the operator's
  `steer` flag, as always for a port that was not steered.
- **vpp-offload, steered adopted VPP**: unchanged — it stays steered
  through the restart on its own preserved ledger, and its diff waits
  for the replay to go quiet, as before.

### What you see

```
route ledger accepted (consumed: the file is gone); seeding the route mirror ...
route mirror seeded from the route ledger: forwarding on the previous process's table ...
the route source's first route after the ledger seed arrived; its replay now confirms the seeded routes
route ledger seed reconciled: the route source re-advertised the rest of the seeded table  gc_removed=N
```

`packetframe status` carries a `route-ledger` row whenever the
PacketFrame FIB control plane runs: `seeded … from a ledger written … ago`
and then `waiting for the route source's first route`, `the route
source is replaying: N seeded advertisements not yet re-advertised`, and
`reconciled … ago`; or `not used at this start (<reason>)`; or `off`.
Textfile gauges:

```
packetframe_fib_route_ledger_seeded_routes{module="fast-path",family="ipv4|ipv6"}
packetframe_fib_route_ledger_unconfirmed{module="fast-path"}   # falls to 0 as the replay confirms
```

### Turning it off, and `detach`

```
route-ledger off                 # every start loads cold
route-ledger on max-age 600      # refuse ledgers whose routes are older than 10 minutes
```

Default `on`, `max-age 1800` (60..=86400 seconds). Reloadable: the stop
writes according to the setting in force when it runs; the start reads
the config it starts with.

A full `packetframe detach` (and `detach --all`) removes the ledger:
it is the recovery path, and the start after it should trust nothing a
previous process preserved. `detach --keep-vpp` — the routine restart —
keeps it.

### Known limits

- The GC needs the route source to pause for 5 s after its dump. A feed
  that never pauses keeps seeded routes it no longer has until a later
  session's GC — exactly what a session loss does today.
- An ADD-PATH negotiation that differs from the previous run files the
  live paths under different keys than the seeded ones, so both
  contribute nexthops until the GC removes the seeded ones.
- Over `route-source bmp`, the station counts seeded routes as an
  earlier stream's: its feed raises after its first `InitiationComplete`
  rather than on the first frame.

## Cutover and rollback

### Cutover to packetframe-fib

**Pre-flight:**

1. Run the staging soak: packetframe-fib + the iBGP feed live to a bird
   mirror for 24h. Zero `compare_disagree` sustained above 0.01%
   of matched packets, zero `StaleFib`, NEXTHOPS occupancy stable.
2. Pathvector `global-config` injects the `protocol bgp packetframe
   { ... }` block (see "Phase 4 bird + pathvector config" below).
3. Add `forwarding-mode packetframe-fib` + `route-source bgp
   127.0.0.1:1179 local-as <ASN> peer-as <ASN>` under `module
   fast-path` in `/etc/packetframe/packetframe.conf`.
4. Confirm bird's `kernel.export: false` (or equivalent) so no BGP
   routes flow to the kernel FIB. Customer /32s, connected, static
   default still flow via non-BGP mechanisms; udapi parses those
   fine.

**Cutover sequence:**

```sh
# 1. Stop the running packetframe daemon.
sudo systemctl stop packetframe  # or kill -TERM <pid>

# 2. Tear down bpffs pins.
sudo packetframe detach --all --config /etc/packetframe/packetframe.conf

# 3. Start the new daemon.
sudo systemctl start packetframe

# 4. Wait ~2-3 minutes for attach-settle-time × 6 interfaces.
# 5. Verify route-source session up:
#      birdc show protocols packetframe   # or `bmp1`, depending on feed
#      ss -Htnp state established "( sport = :1179 )"   # or 6543 for BMP
# 6. Verify fib_hit climbing.
# 7. Verify udapi log parse errors are zero (journalctl -u ubios-udapi-server).
```

### Rollback to kernel-fib

Any time during the 72-hour post-cutover watch, if something looks
wrong:

```sh
# 1. Stop packetframe.
sudo kill -TERM $(pgrep -f 'packetframe run')

# 2. Detach.
sudo packetframe detach --all --config /etc/packetframe/packetframe.conf

# 3. Edit config: remove `forwarding-mode packetframe-fib` and
#    `route-source bmp` lines (or change forwarding-mode to kernel-fib).
sudo sed -i '/^  forwarding-mode /d; /^  route-source bmp /d' \
    /etc/packetframe/packetframe.conf

# 4. Re-enable bird's kernel export for BGP routes.
#    (pathvector config revert; coordinate with whoever owns it.)

# 5. Restart.
sudo systemctl start packetframe
```

**Rollback re-exposes the original udapi bug.** BGP routes flow to
the kernel FIB again, udapi parses them, parse-error window opens up.
Rollback is "restore service now," not a steady state. Follow it with
same-day diagnosis and a forward-fix plan.

### Phase 4 bird + pathvector config

For a cutover to `forwarding-mode packetframe-fib`, packetframe needs
a feed of bird's selected best paths, and bird's kernel-protocol
export needs to stay off so udapi never sees BGP routes.

**Why iBGP and not BMP for the forwarding feed.** Bird (2.x and
3.x master) does not ship RFC 9069 Loc-RIB BMP, only
`monitoring rib in pre_policy / post_policy`, which deliver
per-peer Adj-RIB-In streams. That's wrong for forwarding: a
prefix announced by N peers becomes N RouteMonitoring frames
with N nexthops, with no signal which one bird actually picked.
iBGP, by contrast, runs bird's `protocol bgp` export filter
*after* best-path selection, so packetframe receives exactly
one UPDATE per prefix carrying bird's chosen path. See
`crates/modules/fast-path/src/fib/route_source_bgp.rs` for the
full design rationale.

**Bird config: inject via pathvector's `global-config`.**
Pathvector ships `global-config` verbatim into the rendered bird
config (no template fork needed). Add to `pathvector.yml`:

```yaml
global-config: |
  # iBGP feed to packetframe's BgpListener. AS 65551 is our own
  # AS; replace with yours. `passive` ensures bird only initiates;
  # we listen on 1179 (NOT 179, to avoid clashing with anyone else
  # who happens to bind 179 on the loopback).
  protocol bgp packetframe {
    local 127.0.0.1 as 65551;
    neighbor 127.0.0.1 port 1179 as 65551;
    multihop;
    hold time 90;
    # We never want bird to reject our session for failing best-
    # path tiebreakers. iBGP treats packetframe as a peer; with
    # no real routes from us this is a no-op.
    ipv4 {
      import none;
      export where source = RTS_BGP;
    };
    ipv6 {
      import none;
      export where source = RTS_BGP;
    };
  }
```

`kernel.export: false` in your existing pathvector config already
keeps BGP routes off the kernel FIB; no further kernel-filter
changes needed.

### Multi-NH ECMP from BGP

PacketFrame supports RFC 7911 ADD-PATH end to end. With ADD-PATH
mutually negotiated on the iBGP session to packetframe, the BGP
daemon transmits one UPDATE per kept path (typically the equal-cost
multipath set from upstream eBGP), each NLRI prefixed with a 4-byte
`path_id`. The FibProgrammer aggregates the resulting per-prefix
advertisements into an ECMP group, dedup'd against any prior group
with the same nexthop set.

**Local-pref-tier filter.** Operator-encoded BGP preferences are
respected client-side. For each prefix the FibProgrammer computes
the maximum LOCAL_PREF across the advertisements it holds and forms
the ECMP group only from advertisements at that top tier. Lower-tier
advertisements are retained but masked while a higher tier is
present. When the top tier is withdrawn, the next-best tier's
advertisements promote into the FIB entry without requiring a fresh
announce.

This means an LP scheme like `IX peers = 150, transit = 100` works
as written: prefixes with any IX coverage forward over IX only (with
within-IX ECMP if more than one IX peer announced); prefixes without
IX coverage fall back to the transit tier (with within-transit ECMP
if multiple transits advertise the same prefix at the same LP and
AS_PATH length). Advertisements without a LOCAL_PREF attribute
(non-BGP sources, malformed UPDATEs) are normalized to the RFC 4271
default of 100.

The session-level decode is all-or-nothing across IPv4 unicast and
IPv6 unicast: if the peer advertises ADD-PATH for only one AFI, the
listener falls back to non-ADD-PATH decoding for both. Symmetric
negotiation is the common case in practice for the BGP daemons this
runbook targets.

**Peer-side configuration.** Two pieces are needed on the daemon
that talks to packetframe: retain alternate paths in the local RIB
so there is more than one to send, and enable transmit-side
ADD-PATH on the channel to packetframe. The example below is bird
syntax expressed against documentation placeholders; substitute
your actual peer names and source addresses.

```
# Upstream eBGP: keep alternate paths in the local RIB instead of
# dropping non-best after best-path selection.
protocol bgp UPSTREAM_A {
  ipv4 {
    secondary on;
  };
}

# iBGP channel to packetframe: transmit all paths with path_ids.
protocol bgp packetframe {
  ipv4 { add paths tx; };
  ipv6 { add paths tx; };
}
```

**Validate after enabling.** After reloading the BGP daemon:

```sh
# Negotiation success: the protocol status should report tx-send
# (or equivalent) for ADD-PATH on the packetframe session.
birdc show protocols all packetframe | grep -i 'add path'

# ECMP groups populate as multi-path prefixes converge. Starts at
# zero before ADD-PATH is enabled; rises when the peer begins
# transmitting per-path UPDATEs.
sudo packetframe fib stats | grep ecmp-groups

# Spot-check a prefix that should have multiple paths.
sudo packetframe fib lookup <addr>
```

**Triage: ADD-PATH negotiated but no ECMP groups appearing.** If
`packetframe fib stats` keeps `ecmp-groups: active=0` after the
peer's session is established with ADD-PATH:

- Confirm the peer is actually retaining multi-path. Compare the
  daemon's total route count against the post-best-path table size;
  on bird this is `birdc show route count` versus
  `birdc show route table master4 primary count`. If they match,
  the daemon has no alternate paths to advertise.
- Confirm `add paths tx` is set on the packetframe-facing channel.
  If `add paths` was set only on the upstream eBGP channel, the
  daemon retains alternates locally but does not transmit them to
  packetframe.
- Confirm capability negotiation succeeded. The listener logs an
  `add_path_in_effect=true` field on the `received peer OPEN`
  message when both AFIs negotiated; if it logs `false`, the peer
  advertised an asymmetric capability or no capability at all.

**Rollback.** Removing `add paths tx` from the iBGP channel returns
to single-best-path semantics with no listener-side changes. The
listener still advertises capability 69 in its OPEN but the
absence of peer-side Send keeps `add_path_in_effect` false and
NLRI decodes without `path_id`.

**Packetframe config:**

```
module fast-path
  forwarding-mode packetframe-fib              # or `compare` for the soak window
  route-source bgp 127.0.0.1:1179 local-as 65551 peer-as 65551 router-id 198.51.100.7
```

`router-id` is optional; defaults to the listen-address (v4) or
the local AS (v6 listen).

**Validate after pushing:**

```sh
birdc show protocols packetframe          # state=Established (after a few seconds)
birdc show route count                    # bird's total
sudo packetframe fib stats                # forwarding-mode=packetframe-fib
sudo packetframe fib lookup 8.8.8.8       # MATCH with sane nexthop
journalctl -u packetframe | grep -i bgp   # "BGP listener started", no errors
```

**Once-per-5-minute integrity check** (when BMP/BGP route source
configured) cross-checks bird's `show route count` against the
programmer mirror; drift ≥ 1% logs a `WARN integrity drift above
threshold`.

### Phase 4 systemd ordering

Packetframe's BGP listener binds before bird dials in, so the
service order must be `packetframe.service` first, `bird.service`
second.

`/etc/systemd/system/packetframe.service.d/bgp-ordering.conf`:

```ini
[Unit]
Before=bird.service
# Optional but recommended: fail the boot if bird can't start, so
# an oncall sees it before traffic reaches a forwarding-without-
# updates window.
Wants=bird.service
```

`/etc/systemd/system/bird.service.d/wait-for-packetframe.conf`:

```ini
[Unit]
After=packetframe.service
# Cheap guard against races at boot: wait up to 30 s for the BGP
# listener to be reachable before dialing.
[Service]
ExecStartPre=/bin/sh -c 'for i in $(seq 1 30); do ss -Htnl sport = :1179 | grep -q . && exit 0; sleep 1; done; exit 0'
```

Reload + restart the units after dropping these files:

```sh
sudo systemctl daemon-reload
sudo systemctl restart bird
# If packetframe was already running attached, a plain restart will
# crash-loop on its own surviving pins (pins are never adopted in place):
sudo systemctl stop packetframe && sudo packetframe detach --all && sudo systemctl start packetframe
```

### Recovering from `failed` after the start limit trips

The unit caps restarts at 3 per 5 minutes (`StartLimitBurst` /
`StartLimitIntervalSec`). That cap exists because a non-clean exit
*after* a successful attach leaves the bpffs pins behind, and every
subsequent start then refuses them — without the cap that is an
infinite loop with the dataplane still forwarding on a frozen FIB.

So `Active: failed (Result: start-limit-hit)` is the guard working, and
the surviving pins are the thing to clear. Restarting harder will not
do it: until the limit is reset systemd will not even try, and once it
does the start fails on the same pins.

```sh
sudo systemctl stop packetframe &&
  sudo packetframe detach --all
sudo systemctl reset-failed packetframe
sudo systemctl start packetframe
```

Read the `detach` output rather than assuming it: it refuses outright
if it cannot confirm the daemon is gone, which is the case where
unlinking pins would leave the program attached through a live
process's open FDs while reporting success. Then confirm forwarding
actually came back (`packetframe status`, and the `fib_hit`
counter moving) — the start limit resetting proves only that systemd
will try again.

### When to use `route-source bmp` instead

The BMP route source is useful when:

- Your routing daemon emits **RFC 9069 Loc-RIB BMP** (peer_type 3).
  FRR has this today; bird does not. Set `require-loc-rib` on the
  `route-source bmp` line; the BmpStation will refuse any
  non-Loc-RIB frame and tear the session down with an error,
  preventing silent wrong-forwarding from pre/post-policy streams:

  ```
  route-source bmp 127.0.0.1:6543 require-loc-rib
  ```

- You want a **pure observability** feed (analytics, anomaly
  detection on per-peer Adj-RIB-In streams) running alongside
  the BGP forwarding feed. This isn't wired into the controller
  yet; the current build accepts exactly one `route-source`
  per fast-path module.

## Triage by symptom

### Symptom: IPv4 is fine, IPv6 is flaky, and `ip -6 neigh` looks normal

What it means: neighbor discovery is being disrupted on the segment.
This is the signature to recognise, because nothing in `ip -6 neigh`
output hints at it — entries look resolved, they just go stale and
re-resolve constantly, and connections stall intermittently.

The mechanism: NDP mandates a hop limit of 255, and RFC 4861 §6.1.1 /
§7.1.1 require receivers to **silently discard** NS/NA/RS/RA that arrive
with anything else. Fast-pathing decrements the hop limit and rewrites
the source MAC, so a redirected neighbor solicitation is dropped by the
host it was sent to. IPv4 never had this exposure: ARP is EtherType
0x0806 and is never dispatched into the IPv4 path at all.

packetframe guards against this by passing ICMPv6 types 133-137 (RS, RA,
NS, NA, Redirect) straight to the kernel, before the allowlist and
before any FIB lookup. Confirm the guard is active:

```sh
sudo packetframe status | grep pass_ndp
```

`pass_ndp` should be non-zero and climbing on any box with a
`local-prefix6`. If it is flat at zero while v6 traffic is flowing and
`matched_v6` is climbing, the running binary predates the guard —
`local-prefix6` is unsafe on that build, and you should roll back to
`forwarding-mode kernel-fib` or remove the `local-prefix6` lines until
you can deploy a build that has it.

Note that other ICMPv6 (echo, errors) is deliberately *not* gated: the
guard keys on message type, not on hop limit, so ordinary ICMPv6 still
fast-paths.

### Symptom: `fib_miss` climbs without `fib_hit` keeping pace

What it means: XDP is finding no route in `FIB_V4`/`FIB_V6` for most
matched packets. Either the FIB isn't populated (programmer not
writing), or the allowlist matches traffic bird doesn't cover.

Check:

- `packetframe status`: is `nexthops (resolved)` ≥ your expected
  peer count?
- `journalctl -u packetframe | grep -iE 'bgp|bmp'`: any errors from
  the route-source handler?
- `birdc show protocols packetframe` (or your BMP protocol name):
  is the session established and propagating routes?

### Symptom: `pass_no_neigh` climbs sustainedly

What it means: FIB matches land on nexthop entries with state ≠
`Resolved`, and every one of those packets takes the kernel path:
netfilter, conntrack, the FIB walk — the load the fast path exists
to remove. Judge it as a **rate**, never from the lifetime total
(`status` twice, 60 s apart), against the same threshold the healthy
list uses: below ~1% of matched traffic (`matched_v4 + matched_v6`)
after convergence, and not trending up.

Why it happens: the kernel only re-resolves a neighbour it sends to
itself, and XDP-redirected traffic never touches the kernel entry.
A nexthop the kernel has no reason to talk to (route-server-learned
IX peers) ages REACHABLE → STALE → garbage-collected; the daemon
sees `Gone`, marks the slot `Incomplete`, and — before this fix —
waited for the kernel to ARP it again, which it only did if its own
FIB happened to forward the fallen-through packets to the same
neighbour. On 2026-09-15 that left a third of the traffic on the
kernel path until a restart. The programmer now re-probes every
unresolved slot itself with 1 s → 60 s backoff, so a live neighbour
recovers within seconds and a dead one costs one probe cycle per
minute.

Check:

- `packetframe status`: `nexthops (incomplete)` and `nexthops
  (failed)` are the live slots whose traffic is on the kernel path.
  `nexthop slots freed` is tombstones from churn and costs nothing.
- `packetframe fib dump-v4 --unresolved` (and `dump-v6`): the
  routes behind those slots and the nexthop each one is stuck on.
  Walks the whole trie: several seconds and ~200 MB on a full table.
- `ip neigh show <nexthop-ip>`: what the kernel thinks, **per
  interface** — the same address can be FAILED on one device and
  REACHABLE on the one the nexthop forwards out of. Events on any
  other device are ignored by design.
- `journalctl -u packetframe | grep -E 'lost resolution|re-resolved|awaiting resolution'`:
  the first 20 losses and slow recoveries are logged, and a once-a-
  minute summary runs while anything is pending.
- If a slot stays `incomplete` with `chronic_over_1min` > 0 in that
  summary, the kernel is not answering the probe: check the route to
  the nexthop (`ip route get <nexthop-ip>` must be a unicast route
  with an egress device), whether that egress is an `ix-mode`
  interface (probes are deliberately suppressed there; the snooper
  seeds them), and whether the peer answers ARP/ND at all.

#### `local` nexthops: the router's own addresses

A routing daemon sends what it originates (`redistribute connected`,
`redistribute static`) with its own session address as the next hop,
and the BGP listener falls back to its listen address when bird sends
none. The kernel never resolves a neighbour for its own address, so such
a slot stays `incomplete` for as long as a route uses it, and XDP passes
its traffic to the kernel (`fib_no_neigh`). That is correct: the kernel
delivers those prefixes, or routes them on.

The programmer labels these nexthops **`local`**. They are never
re-probed and never counted in the `awaiting resolution` summary, so a
healthy box no longer logs `pending=2 chronic_over_1min=2` every minute
for its own addresses. Each is named once in the journal when it is
registered (`nexthop is the router's own address (local)`, with its
`nh_id`), and the set is named again whenever a re-read of the router's
addresses (once a minute) moves a nexthop in or out of it. The summary
line carries `local=N` for context.

Nothing in the datapath changes for these: the slot stays seeded
`incomplete`, the map layout and the stats counters are untouched, and
traffic is passed to the kernel exactly as before. One transition does
write the slot. If a nexthop's address moves onto the router while it is
resolved (an address takeover), the slot is reset to `incomplete` so XDP
stops redirecting to the former neighbour, and neighbour events for that
address are ignored for as long as it is local. When the address leaves
the router, the nexthop resolves like any other. The pinned maps carry no addresses, so
`packetframe status` still counts these slots under
`nexthops (incomplete)`, and `fib dump-v4 --unresolved` still lists
their routes as `state=incomplete ifindex=0`. To tell them apart, match
the dump's `nh_id` against the journal's `local` lines:

```sh
journalctl -u packetframe | grep "router's own address (local)"
```

vpp-offload counts the same routes as kernel-delivered, not unresolvable
(see the vpp-offload runbook, "Kernel-delivered routes").

### Symptom: nexthops stuck `incomplete` while the kernel neighbour is REACHABLE

What it means: the kernel has resolved the nexthops, but the neighbour
resolver is not passing that on, so the FIB holds them `incomplete` and
every packet routed through them takes the kernel path. This is not the
re-probe problem in the previous entry: there, the *kernel* has lost the
neighbour. Here `ip neigh show <nexthop-ip> dev <device>` says REACHABLE
(or STALE, PERMANENT) on the device the nexthop forwards out of, and the
FIB still says `incomplete`.

The fingerprint, from 2026-10-07 (a configuration apply toggled a member
port and an IX bridge to flush routes, and the kernel flushed every
neighbour on them):

- `fib_no_neigh` (the `pass_no_neigh` rate) is close to the whole
  matched rate, and `fwd_ok` is flat. Softirq load is high on every core
  as the kernel path takes everything.
- `packetframe status` shows a handful of `nexthops (resolved)` against
  hundreds `incomplete`.
- No `neighbour resolver stats` line in the journal for minutes; it is
  normally logged every 10 s.
- vpp-offload counts its routes as unresolvable ("no neighbour: the
  kernel has not resolved it"), from the same source.
- `/proc/net/netlink`: the resolver's multicast socket (protocol `0`,
  groups `00000005`, which is RTNLGRP_LINK and RTNLGRP_NEIGH) shows a
  large `Drops` count. The kernel dropped notifications on its full
  receive buffer.

How it happened, and what changed. The resolver's multicast socket
overflowed during the neighbour flush. Its own requests (route lookups,
neighbour kicks, read-backs) went over that same socket with no timeout.
The kernel dropped one request's reply along with the notifications, the
loop waited for it forever, and nothing noticed. The daemon now:

- **Sends requests over a separate socket, and bounds each one**: 5 s for
  a request, 10 s for a dump. A request that times out leaves its nexthop
  to the programmer's next re-probe. Its socket is retired, and no new
  one opens until the kernel has let go of the old one (a request blocked
  on `rtnl_lock` holds a worker thread until the lock is released, and
  the resolver shares a two-thread runtime with the programmer and the
  route source). Probes skipped meanwhile are asked for again as soon as
  requests can go out.
- **Resyncs after an overrun.** When notifications are lost, it re-reads
  the links, the neighbours and the bridge FDB about a second later (at
  most one resync every 5 s) and announces what changed. The dumps are
  taken with a **fresh subscription** already open, and the old socket
  is then dropped with everything still queued on it. After an overflow
  the kernel goes on delivering what it queued *before* the drop, which
  is older than what it dropped; replayed after the dump, it would
  re-learn deleted neighbours or withdraw live ones. (A resync that
  could not apply anything, for example because no request socket was
  free, keeps the old subscription.)

  What the dumps list is applied first. A link or neighbour the dump does
  not list is then asked about individually before it is withdrawn,
  because a dump can skip a live entry. Each outcome is announced as its
  notification would have been:
  - A neighbour the kernel now holds `FAILED` (dumps leave those out) is
    announced `Failed`, not lost, and keeps its local-prefix route.
  - A neighbour that moved to another interface is learned there, and
    its entry on the old one is lost, which withdraws the local-prefix
    host route it had there.
  - A neighbour on a device that no longer exists counts as gone, and
    when a device goes, any neighbours the resolver still held on it go
    with it.

  Confirmations stop as soon as
  the request socket is retired, and take at most 2 s per read. One that
  is not made is left as it is and the resync is retried, so the loop
  never sits behind a blocked socket. The multicast receive buffer is
  also raised to 16 MiB, which makes overruns rarer.
- **Reads back suppressed probes.** A nexthop behind an `ix-mode`
  interface is still never kicked, but its kernel entry is now read back
  (a unicast get, nothing on the fabric). An entry the snooper installed
  but whose notification was lost resolves on the next re-probe instead
  of waiting for the kernel to change it.
- **Restarts a stuck resolver itself.** A loop that exits with an error,
  or makes no progress for 30 s outside a wait on the FIB programmer, is
  dropped and replaced, with restarts backing off from 1 s to 60 s. The
  new loop re-reads the kernel and announces what the old one missed.
  After every resync and restart, the programmer brings every unresolved
  nexthop's next re-probe forward to now. Its backoff keeps counting, so
  a dead neighbour is not solicited every few seconds through a long
  storm.

**Read the `neigh-resolver` row in `packetframe status`.** It is present
whenever the PacketFrame FIB control plane runs, and its `last ok` age is
the loop's progress age; an idle loop still makes progress every second.

| Row reads | Meaning |
|---|---|
| healthy, `running (incarnation N); last progress Ns ago; overruns …` | Working. Non-zero overruns with an equal number of resyncs are history. |
| **unhealthy**, `no progress for …` | The loop is stuck right now. The supervisor restarts it after 30 s. During a long kernel `rtnl_lock` hold the whole control-plane runtime can stall, and this reads unhealthy until the lock is released, without a restart. |
| **unhealthy**, `NOT RUNNING: the resolver <cause>; restart #N in …` | Between a failure and its restart. The cause names the error or the stall. |
| degraded, `restarted … ago (restart #N): the previous loop …` | Recovered by a restart in the last 10 minutes. The text says why the old loop was replaced. |
| degraded, `… notifications were lost … ago (socket overrun); a resync is pending` (or `the resync failed (…) and is retried`) | An overrun is not yet answered. A failed resync is retried every 5 s. |
| degraded, `a read of the kernel's links and neighbours did not complete … ago; the resync failed (…)` | A read failed, for example a dump timed out or an entry missing from a dump could not be confirmed gone. It is retried every 5 s, and the error says what failed. |
| degraded, `waiting … for the FibProgrammer to accept its events` | The **programmer** is not draining, for example during a route-ledger seed or a full-table load. Restarting the resolver cannot help, so it is not restarted. If this lasts, the programmer is the problem. |
| degraded, `the request socket was retired … ago and the kernel still holds it` | A request timed out and its socket is blocked in the kernel, typically on `rtnl_lock`. Proactive probes are skipped until it is released, and the programmer re-probes later. |

The same numbers, as textfile metrics:

```
packetframe_fib_neigh_resolver_overruns_total{module="fast-path"}
packetframe_fib_neigh_resolver_resyncs_total{module="fast-path"}
packetframe_fib_neigh_resolver_resync_failures_total{module="fast-path"}
packetframe_fib_neigh_resolver_request_timeouts_total{module="fast-path"}
packetframe_fib_neigh_resolver_probes_skipped_total{module="fast-path"}
packetframe_fib_neigh_resolver_restarts_total{module="fast-path"}
packetframe_fib_neigh_resolver_running{module="fast-path"}                  # 0 between a failure and its restart
packetframe_fib_neigh_resolver_progress_age_seconds{module="fast-path"}     # above 30 while not waiting on the programmer: stuck
packetframe_fib_neigh_resolver_programmer_wait_seconds{module="fast-path"}  # 0 unless the programmer is not draining
```

Check:

```sh
sudo packetframe status | grep -A3 neigh-resolver
sudo packetframe events --module fast-path --since 1h   # neigh_resolver_restarted, module_health
journalctl -u packetframe --since -1h | grep -E 'neighbour resolver (stats|stopped)|notifications lost|resynced|request timed out|probe skipped'
cat /proc/net/netlink    # protocol 0, groups 00000005: the Drops column
```

Every restart logs `neighbour resolver stopped working; restarting it`
at error, with the cause, and records a `neigh_resolver_restarted` event
(`cause`: `stalled` with `silent_ms`, `failed` with the error in
`detail`, or `returned`). The `neighbour resolver stats` line now carries
`incarnation`, `overruns`, `resyncs`, `resync_failures`,
`request_timeouts`, `probes_skipped` and `restarts`.

If the restart count keeps climbing (`restart #N` with N rising, and the
row unhealthy between restarts), the resolver cannot get going at all.
The cause in the row names the error: a socket that cannot be opened, or
a multicast stream that keeps closing. The last resort is a daemon
restart, and the event log keeps the history for the bug report. Restart
like this, because a plain `systemctl restart` cannot start over the
pins the old process leaves:

```sh
systemctl stop packetframe && packetframe detach --keep-vpp && systemctl start packetframe
```

The same restart is the remedy on a build older than this fix. Before
it, the resolver hung without a sound and only a restart recovered it.

None of this covers a **panic**. The release build aborts on panic, which
ends the whole daemon. `Restart=on-failure` then cannot bring it back,
because fast-path refuses to start over the bpffs pins the dead process
left. The unit's start limit marks it `failed`, and XDP keeps forwarding
on the frozen maps until someone runs the teardown in the header of
`crates/cli/debian/packetframe.service`.

### Symptom: `pass_not_in_devmap` climbs

What it means: the FIB resolved an egress interface that is not in
`REDIRECT_DEVMAP` (or, for the tc datapath, `TC_REDIRECT_TARGETS`),
so the packet took XDP_PASS into the kernel path. The maps are filled
at attach from `/sys/class/net` (Ethernet-type, oper-up or unknown)
and were once refreshed only on SIGHUP; since the 2026-09-15 fix a
watcher thread follows `RTM_NEWLINK`/`RTM_DELLINK` and keeps them
current, so a bridge or VLAN sub-interface the platform re-creates
mid-run is a valid target as soon as it is up. The same refresh
rewrites `VLAN_RESOLVE` (sub-interface → physical port + VID, and the
bridge egress short-circuits) *before* admitting the new link, so a
recreated `switch0.N` is redirected through its parent with the tag,
never to the virtual device itself.

Check:

- `journalctl -u packetframe | grep 'redirect-target'`: the watcher
  logs `live (RTNLGRP_LINK)` at start and every add/remove; a line
  saying it stopped means SIGHUP is again the only refresh —
  `systemctl reload packetframe` reconciles immediately.
- `bpftool map dump pinned /sys/fs/bpf/packetframe/fast-path/maps/REDIRECT_DEVMAP`
  against `ip -br link`: every up Ethernet-type ifindex should be a key.
- `packetframe fib lookup <dst>` for an affected destination: the
  nexthop's `ifindex` names the egress; if it is a non-Ethernet device
  (tunnel, loopback) or oper-down, the miss is correct and the route
  itself is the problem.

### Symptom: `pass_not_for_us` jumps and `fwd_ok` falls with it

What it means: the XDP program routes a matched frame only when its
destination MAC is in `RX_MACS` for the port it arrived on. Everything
else goes to the kernel untouched and counts `pass_not_for_us`. Without
the check, a bridge member's hook routed frames between two hosts on
one VLAN when either address was allowlisted: TTL decremented, source
MAC rewritten to the router's, where the kernel would have bridged them
untouched. Broadcast and multicast frames also went through the FIB,
and a `fallback-default` /0 sent them upstream.

Per port, `RX_MACS` holds the MACs `packetframe_common::topology::
receive_macs` derives, the same rule vpp-offload uses for its divert
rules:

- a bridge member: the bridge's MAC, plus the MAC of each L3 device (a
  VLAN device or VLAN bridge that no bridge has enslaved) on a VLAN of
  that bridge;
- a plain port, including one enslaved to a master that is not a
  bridge (a VRF): its own MAC. A VLAN sub-interface there with a MAC of
  its own is left out, so frames addressed to it take the kernel path;
- a bond: its MACs, keyed on the bond's ifindex and on each slave's
  (native XDP on a bond reports the slave as the ingress interface).

Attach fills the map before the first XDP attach. From then on the
redirect-target watcher refreshes it on every `RTM_NEWLINK`, so a bridge
that takes a new MAC is followed within the watcher's debounce. A SIGHUP
refreshes it too. A port whose MACs cannot be read keeps the entries it
has, and the watcher retries it every debounce interval until the read
succeeds. A replacement MAC that cannot be inserted leaves the port's
old MACs in place. A port with no entries passes every frame, which is
the kernel path: correct, but none of that port's traffic is
fast-pathed.

A step change, with `fwd_ok` falling by about as much, means a port's
router MAC is missing from the map. Check:

- `journalctl -u packetframe | grep -E 'RX_MACS|receive MACs'`: attach
  logs `RX_MACS populated`, the watcher logs `RX_MACS refreshed from
  link events`, and a port whose MACs could not be read logs `receive
  MACs unreadable` by name.
- `bpftool map dump pinned /sys/fs/bpf/packetframe/fast-path/maps/RX_MACS`
  against `ip -br link`. Each key is the port's ifindex (4 bytes,
  little-endian), the MAC and 2 pad bytes. Every attached port should
  have its own MAC (plain port) or its bridge's MAC (bridge member).
- The MAC your hosts actually send to: `ip neigh` on a host for the
  gateway address, or `tcpdump -e` on the port. A MAC that belongs to
  none of the devices above, such as a macvlan or VRRP virtual MAC, is
  not in the map by design, and its frames take the kernel path.

Remedy: `systemctl reload packetframe` re-runs the refresh. If the MACs
are correct in `ip link` but still missing after a reload, collect the
journal lines above before restarting.

### Symptom: `bmp_peer_down` incremented

What it means: bird reported a BGP peer went down; the programmer
withdrew all routes that peer announced. Expected behavior during
maintenance windows; alarming during stable state.

Check:

- `birdc show protocols | grep -v Established`: what's down?
- `journalctl | grep bird`: why?

### Symptom: `nexthop_seq_retry` climbs

What it means: XDP readers are observing seqlock writes in progress
more often than usual. Either the BGP session is churning nexthop
MACs (kernel ARP storms), or something is actively writing NEXTHOPS
outside the programmer.

Check:

- `ip monitor neigh` in a separate terminal: is there a neighbor
  storm?
- No process other than packetframe should be writing to
  `/sys/fs/bpf/packetframe/fast-path/maps/NEXTHOPS`.

### Symptom: route-source session stays up but routes stop flowing

What it means: bird is connected and idle. No new BGP churn, no new
routes. Usually benign; BGP in stable state just doesn't send much.

Check:

- `fib_hit` still climbing (existing routes are still
  forwarding). If yes, this is fine.
- If forwarding has stopped entirely, that's a different problem.
  Look at `fwd_ok`, `pass_not_in_devmap`, `drop_unreachable`.

### Symptom: Daemon won't start, "LPM trie create failed / ENOMEM"

What it means: kernel rejected a 2M-entry LPM trie allocation. Either
`rlimit.memlock` is too low, or the kernel has per-map caps.

Check:

- `ulimit -l`: is it `unlimited`? If not, set it in
  `/etc/systemd/system/packetframe.service.d/memlock.conf`:
  `[Service]\nLimitMEMLOCK=infinity`.
- If `unlimited` and still failing: reduce `FIB_V4_MAX_ENTRIES` in
  `crates/modules/fast-path/bpf/src/maps.rs`, rebuild.

## Resolved items

This section tracks features that landed since the runbook was first
written. They were originally listed as known gaps; the entries are
retained as a changelog of what shipped and when.

- **Proactive resolve** (Phase 3.6). `request_resolve(ip)` now
  issues `RTM_NEWNEIGH NUD_NONE` after looking up the route to find
  the egress ifindex. Best-effort: if route lookup or neighbor add
  fails, first-packet kernel ARP remains the fallback.
- **`src_mac` via RTM_GETLINK** (Phase 3.6). The NeighborResolver
  now caches `ifindex → MAC` from an RTM_GETLINK dump at startup and
  RTM_NEWLINK / RTM_DELLINK multicast events thereafter.
  `NEXTHOPS[id].src_mac` is the egress iface MAC, not zero.
- **InitiationComplete quiescence timer** (Phase 3.5). Fires once
  per BMP connection after 5 s of no RouteMonitoring frames.
- **`packetframe fib` subcommands** (Phase 3.8). `dump-v4 / dump-v6
  / lookup <ip> / stats` ship in the main binary. Opens the pinned
  maps directly; works without the daemon running.
- **PacketFrame FIB Prometheus metrics** (Phase 3.8). The textfile
  exporter now emits `packetframe_fib_forwarding_mode{mode="..."}`,
  `packetframe_nexthops{state="..."}`, `packetframe_nexthops_max`,
  `packetframe_ecmp_groups_active`, `packetframe_ecmp_groups_max`,
  and `packetframe_fib_default_hash_mode` on the usual 15 s cadence.
- **Offline comparison harness** (Phase 3.8). `tests/fib_comparison.rs`
  drives a synthetic RIB through the programmer and asserts the LPM
  lookups resolve correctly. Runs in every qemu-verifier CI job.
- **Integrity check + BmpStalled alert** (Phase 3.8). When BMP is
  configured, the RouteController spawns a 5-minute periodic job
  that cross-checks `birdc show route count` against the mirror size
  and logs a warning on ≥1% drift. BmpStalled fires (warning log)
  when no ROUTE MONITORING in 5 min AND bird reports ≥1 Established
  peer AND process uptime > 10 min.
- **Netns integration test + BMP integration test** (Phase 3.7).
  `tests/neigh_resolver_netns.rs` + `tests/fib_programmer_integration.rs`
  cover the resolver and programmer paths end-to-end under sudo in
  CI's qemu-verifier jobs.
- **BGP route source + BMP Loc-RIB safety mode** (Phase 3.9).
  `route-source bgp <addr>:<port> local-as <asn> peer-as <asn>`
  spawns an iBGP listener that receives bird's selected best paths;
  bird's `protocol bgp` export filter runs after best-path so we
  never see per-peer Adj-RIB-In duplicates. BmpStation gains
  `require-loc-rib` which hard-rejects non-Loc-RIB frames. The
  iBGP feed is the recommended forwarding path for bird; the
  BMP path is for Loc-RIB-emitting daemons (FRR; future bird).
- **BgpListener direct-origin fallback + connected fast-path**
  (v0.2.1). Pre-v0.2.1 the BgpListener silently dropped iBGP UPDATEs
  whose decoded NEXT_HOP was None: exactly what bird emits for
  `protocol direct` (and static-origin) routes when the BGP block has
  no `next hop self`. Connected /24s never landed in FIB_V4, so every
  inbound packet to a customer host bumped `fib_miss` and fell
  through to slow path. v0.2.1 makes the listener fall back to its
  own listen address; the route lands with `state=Incomplete` so
  counters reflect reality. The `local-prefix <cidr> via <iface>`
  directive turns those /24s into per-/32 fast-paths. See the
  [Connected fast-path](#connected-fast-path-v021) section above.
- **`fallback-default` synthetic /0** (v0.2.1, issue #31). Inject
  a catch-all default into the PacketFrame FIB so bogon-bound traffic
  XDP-redirects to upstream instead of slow-pathing.
- **`arp-scavenge` for quiet LANs** (v0.2.1, issue #32). One-shot
  ARP sweep of declared local-prefix CIDRs at startup so storage
  networks (Ceph) get fast-path coverage even when their hosts don't
  voluntarily talk to the gateway.
- **`block-prefix` XDP-time drop** (v0.2.1, issue #33). Bogon
  destinations dropped at XDP instead of forwarded-and-failed.
