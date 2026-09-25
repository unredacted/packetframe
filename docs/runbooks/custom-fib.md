# Custom-FIB operations runbook

This runbook covers the Option F custom-FIB forwarding path: what the
pieces are, how to tell it's healthy, what to do when it's not, and
how to roll back to the kernel-FIB path if something goes wrong.

## Contents

- [Architecture at a glance](#architecture-at-a-glance)
- [Healthy operation](#healthy-operation)
- [Everyday inspection commands](#everyday-inspection-commands)
- [Connected fast-path (v0.2.1)](#connected-fast-path-v021)
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

- **BgpListener** (the recommended forwarding feed) accepts bird's
  iBGP session. Bird's `protocol bgp` export filter runs after
  best-path selection, so we get exactly one UPDATE per prefix
  with bird's chosen nexthop. Translated to
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
  `FP_CFG_FLAG_CUSTOM_FIB` bit in the CFG map; kernel-FIB mode bypasses
  all of the above and calls `bpf_fib_lookup()` as before.

## Healthy operation

Indicators that the custom-FIB path is working:

- `packetframe status` reports `forwarding-mode: custom-fib`.
- `custom_fib_hit` counter climbs; `custom_fib_miss` is low relative
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
- `bmp_peer_down` stays at zero unless a BGP session you expect to
  flap has flapped.
- `nexthop_seq_retry` stays below ~0.01% of `custom_fib_hit` (the
  seqlock retry is ~free on a normal read; sustained retries mean
  the BGP session is churning nexthop MACs nonstop).
- udapi log parse errors: zero (the point of Option F).

Counters live in the `STATS` BPF map. `packetframe status` reads them
out of the pin; no daemon IPC required.

## Everyday inspection commands

### Is custom-fib forwarding what you think it's forwarding?

```sh
sudo packetframe status --config /etc/packetframe/packetframe.conf
```

Look at:

- `custom-FIB status:` block: `forwarding-mode`, nexthop resolution
  counts, ECMP group count.
- counter block, especially the `custom_fib_*` family.

### Is the route-source session live?

For the recommended iBGP feed:

```sh
ss -Htnp state established "( sport = :1179 )" 2>&1
# Expect one line: bird ↔ packetframe on the BGP listener port.
birdc show protocols packetframe
# State should be "Established" with a non-zero "Routes:" count.
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
`birdc` that is not installed fails blind every 300 s — and it is still
what the fleet's configs say. It is also refused alongside
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
them disqualified a valid config over an inbound route-map. A narrowing
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
there:

```sh
time vtysh -c 'show bgp ipv4 unicast statistics json' >/dev/null
```

The ceiling is 300 s, a third of the steering gate's 900 s staleness
limit, and it has to be: the checker sleeps a full interval after every
attempt, so one failed check means the retained report is next
refreshed at about twice the interval — and that has to land before it
goes stale. Slower than the default would only lengthen the flap cost
and the staleness exposure together.

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

### Is a specific prefix forwarding through custom-fib?

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
the fresh dump on reconnect. Stale entries from before the
reconnect are GC'd by `InitiationComplete` (fires after 5 s of
post-first-update quiescence) or the next Resync.

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

### Prometheus metrics for custom-FIB

Alongside the existing counter family, the textfile exporter emits:

- `packetframe_fib_forwarding_mode{mode="kernel-fib|custom-fib|compare"}`:
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

Example alerts:

```promql
# 80% NEXTHOPS occupancy: every live bucket counts, and the failure
# mode this section describes is precisely thousands of `incomplete`.
sum(packetframe_nexthops{state=~"resolved|incomplete|failed|stale"})
  / packetframe_nexthops_max > 0.8

# Nexthops whose traffic is on the kernel path.
sum(packetframe_nexthops{state=~"incomplete|failed"}) > 0

# Unexpected forwarding-mode transition.
changes(packetframe_fib_forwarding_mode{mode="custom-fib"}[5m]) > 0
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
`custom_fib_no_neigh` (or, pre-v0.2.1, `custom_fib_miss` because the
listener silently dropped the announce). Either way, the packet
falls through XDP_PASS to kernel slow-path: through netfilter,
conntrack, the FIB walk, and finally out the bridge. That's exactly
the load fast-path exists to remove.

The connected fast-path inverts this: NetlinkNeighborResolver walks
the kernel ARP table for hosts within an operator-declared CIDR
+ iface, registers a per-/32 NEXTHOPS entry with the host's real
MAC at `state=Resolved`, and inserts the /32 in FIB_V4. The /32
wins over the /24 in LPM, so XDP redirects directly to the host.

### When to enable it

When you're running custom-fib (not kernel-fib) and the box has
connected /24s carrying meaningful inbound traffic. Typical case
on the reference EFG: customer LANs (`198.51.100.0/24`), internal
storage networks (Ceph: `203.0.113.64/26`), and other LAN bridges.
On the reference EFG with all peers up, expect the bypass rate
to climb from ~30% to >95% once kernel ARP populates.

### Config

```
module fast-path
  forwarding-mode custom-fib
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

# 4. Bypass rate. Compare custom_fib_hit / matched_v4 before vs.
# after enabling. Typical recovery: matched_dst_only flips from
# ~100% miss to ~100% hit. (rate may climb gradually as kernel
# ARP populates the cache for under-trafficked hosts.)
sudo packetframe status | grep -E 'matched_v4|custom_fib_hit|custom_fib_miss|custom_fib_no_neigh'
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
sudo packetframe status | grep -E 'matched_v6|pass_ndp|custom_fib_hit|custom_fib_miss'
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
  custom-fib AND a route-source are configured).
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

Custom-FIB only has prefixes bird's iBGP feed advertised. Destinations
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

## Cutover and rollback

### Cutover to custom-fib

**Pre-flight:**

1. Run the staging soak: custom-fib + the iBGP feed live to a bird
   mirror for 24h. Zero `compare_disagree` sustained above 0.01%
   of matched packets, zero `StaleFib`, NEXTHOPS occupancy stable.
2. Pathvector `global-config` injects the `protocol bgp packetframe
   { ... }` block (see "Phase 4 bird + pathvector config" below).
3. Add `forwarding-mode custom-fib` + `route-source bgp
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
# 6. Verify custom_fib_hit climbing.
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

# 3. Edit config: remove `forwarding-mode custom-fib` and
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

For a cutover to `forwarding-mode custom-fib`, packetframe needs
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
  forwarding-mode custom-fib              # or `compare` for the soak window
  route-source bgp 127.0.0.1:1179 local-as 65551 peer-as 65551 router-id 198.51.100.7
```

`router-id` is optional; defaults to the listen-address (v4) or
the local AS (v6 listen).

**Validate after pushing:**

```sh
birdc show protocols packetframe          # state=Established (after a few seconds)
birdc show route count                    # bird's total
sudo packetframe fib stats                # forwarding-mode=custom-fib
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
# crash-loop on its own surviving pins (v0.1 has no pin adoption):
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
actually came back (`packetframe status`, and the `custom_fib_hit`
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

### Symptom: `custom_fib_miss` climbs without `custom_fib_hit` keeping pace

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

- `custom_fib_hit` still climbing (existing routes are still
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
- **Custom-FIB Prometheus metrics** (Phase 3.8). The textfile
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
  inbound packet to a customer host bumped `custom_fib_miss` and fell
  through to slow path. v0.2.1 makes the listener fall back to its
  own listen address; the route lands with `state=Incomplete` so
  counters reflect reality. The `local-prefix <cidr> via <iface>`
  directive turns those /24s into per-/32 fast-paths. See the
  [Connected fast-path](#connected-fast-path-v021) section above.
- **`fallback-default` synthetic /0** (v0.2.1, issue #31). Inject
  a catch-all default into the custom-FIB so bogon-bound traffic
  XDP-redirects to upstream instead of slow-pathing.
- **`arp-scavenge` for quiet LANs** (v0.2.1, issue #32). One-shot
  ARP sweep of declared local-prefix CIDRs at startup so storage
  networks (Ceph) get fast-path coverage even when their hosts don't
  voluntarily talk to the gateway.
- **`block-prefix` XDP-time drop** (v0.2.1, issue #33). Bogon
  destinations dropped at XDP instead of forwarded-and-failed.
