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
- [Known gaps](#known-gaps)

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
  Loc-RIB — see the section "When to use `route-source bmp`
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
- `fwd_ok` climbs (the shared success counter — custom and kernel FIB
  both increment it on redirect).
- `pass_no_neigh` stays below ~0.01% of matched traffic after the
  first few seconds (first-packet ARP is expected; sustained-high
  means a nexthop is genuinely unreachable or the neighbor resolver
  is broken).
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

- `custom-FIB status:` block — `forwarding-mode`, nexthop resolution
  counts, ECMP group count.
- counter block — especially the `custom_fib_*` family.

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

The `packetframe fib` subcommand opens the pinned BPF maps directly
— no daemon IPC. Works as long as the pins exist (i.e., after
`systemctl stop packetframe` but before `detach --all`).

```sh
# LPM-resolve a single IP.
sudo packetframe fib lookup 8.8.8.8

# Walk the whole FIB (O(N); slow on a 1M-route table).
sudo packetframe fib dump-v4

# Occupancy / mode / hash block only — scriptable.
sudo packetframe fib stats
```

### Prometheus metrics for custom-FIB

Alongside the existing counter family, the textfile exporter emits:

- `packetframe_fib_forwarding_mode{mode="kernel-fib|custom-fib|compare"}`
  — one-hot gauge; alert on unexpected transitions.
- `packetframe_nexthops{state="resolved|failed|stale|unwritten_or_incomplete"}`
  — NEXTHOPS state bucket counts.
- `packetframe_nexthops_max` — configured NEXTHOPS capacity.
- `packetframe_ecmp_groups_active`, `packetframe_ecmp_groups_max`.
- `packetframe_fib_default_hash_mode` — 3/4/5-tuple.

Example alerts:

```promql
# 80% NEXTHOPS occupancy.
(packetframe_nexthops{state="resolved"} + packetframe_nexthops{state="failed"})
  / packetframe_nexthops_max > 0.8

# Unexpected forwarding-mode transition.
changes(packetframe_fib_forwarding_mode{mode="custom-fib"}[5m]) > 0
```

### Integrity check + BmpStalled alert

When `route-source bmp` is configured, the daemon runs a 5-minute
periodic job that shells out to `birdc show route count` and
`birdc show protocols`, compares the totals against the
programmer's mirror size, and logs warnings on drift ≥ 1%:

```
WARN integrity drift above threshold bird_routes=1048587 packetframe_routes=1048501 drift_fraction=0.000082
```

The drift threshold is `IntegrityConfig::drift_warn_fraction`
(default `0.01` = 1%). Below threshold goes to `DEBUG` level only.

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

Bird's iBGP feed gives us the connected /24 (e.g. `23.191.200.0/24`
on `br1337`) with a self-referential BGP NEXT_HOP (the device's local
IP). The neighbour resolver can't map that to a useful destination
MAC — it's our own IP. Without the connected fast-path, the LPM
lookup hits the /24 with `state=Incomplete` and returns
`custom_fib_no_neigh` (or, pre-v0.2.1, `custom_fib_miss` because the
listener silently dropped the announce). Either way, the packet
falls through XDP_PASS to kernel slow-path — through netfilter,
conntrack, the FIB walk, and finally out the bridge. That's exactly
the load fast-path was built to remove.

The connected fast-path inverts this: NetlinkNeighborResolver walks
the kernel ARP table for hosts within an operator-declared CIDR
+ iface, registers a per-/32 NEXTHOPS entry with the host's real
MAC at `state=Resolved`, and inserts the /32 in FIB_V4. The /32
wins over the /24 in LPM, so XDP redirects directly to the host.

### When to enable it

When you're running custom-fib (not kernel-fib) and the box has
connected /24s carrying meaningful inbound traffic. Typical case
on the reference EFG: customer LANs (`23.191.200.0/24`), internal
storage networks (Ceph: `10.88.1.0/24`), and other LAN bridges.
On the reference EFG with all peers up, expect the bypass rate
to climb from ~30% to >95% once kernel ARP populates.

### Config

```
module fast-path
  forwarding-mode custom-fib
  route-source bgp 127.0.0.1:1179 local-as 401401 peer-as 401401

  # One line per local prefix you want fast-pathed inbound:
  local-prefix 23.191.200.0/24 via br1337    # customer LAN
  local-prefix 10.88.1.0/24    via br88      # Ceph internal
  local-prefix 10.10.1.0/24    via br0       # other LAN
```

The `via <iface>` is required and must match the kernel iface
hosting the prefix. Validate at startup the same way `attach`
directives validate (must exist under `/sys/class/net`); a missing
iface is a startup-fatal error.

The directive set is additive — declare as many as you have
connected destinations to fast-path. Each adds one hashmap-walk
of the kernel's neighbour table at startup and one match per
multicast neighbour event. Match cost is O(N) over the local-prefix
list, so keep the list to a handful (the reference EFG has 6).

### Verification after enabling

```sh
# 1. Confirm /32s landed in the FIB. Should see one entry per
# kernel ARP entry within each declared local-prefix.
sudo packetframe fib dump-v4 | grep -E '^23\.191\.200\.[0-9]+/32' | head
sudo packetframe fib dump-v4 | grep -E '^10\.88\.1\.[0-9]+/32'   | head

# 2. Lookup a specific host. Should report state=resolved with the
# host's actual MAC and the iface's ifindex.
sudo packetframe fib lookup 23.191.200.10

# 3. Watch the resolver stats — `local_arp_routes_added` climbs as
# the kernel ARPs new hosts; `_removed` climbs on RTM_DELNEIGH
# (typical aging churn).
journalctl -u packetframe -f | grep 'neighbour resolver stats'

# 4. Bypass rate. Compare custom_fib_hit / matched_v4 before vs.
# after enabling. Typical recovery: matched_dst_only flips from
# ~100% miss to ~100% hit. (rate may climb gradually as kernel
# ARP populates the cache for under-trafficked hosts.)
sudo packetframe status | grep -E 'matched_v4|custom_fib_hit|custom_fib_miss|custom_fib_no_neigh'
```

### Capacity considerations

Each declared local-prefix can register up to one /32 per active
kernel ARP entry. NEXTHOPS_MAX_ENTRIES is 8192 by default; a typical
EFG with a few dense customer /24s plus internal LANs sits well
under this (the reference EFG configured below uses ~500-1000 of
8192). If you operate a *very* dense LAN where active hosts
approach 8192, plan to either raise the cap (BPF rebuild) or skip
the directive on that prefix and accept the slow-path fallback.

### When NOT to enable it

- **kernel-fib mode.** The kernel handles connected destinations
  natively via `bpf_fib_lookup()` + ARP cache, no extra config
  needed. The directive is a no-op in this mode (parsed and
  validated, but the resolver only emits events when both
  custom-fib AND a route-source are configured).
- **Operator hasn't declared the customer prefix in `allow-prefix`.**
  XDP filters on allowlist BEFORE the FIB lookup, so a /32 in the
  FIB does nothing if the parent prefix isn't matched. Add the
  customer /24 to `allow-prefix` first.
- **Tunnels and weirdness.** Don't declare local-prefix on a tunnel
  iface (WireGuard, GRE, IPSec) — the BPF program can't redirect
  to non-XDP-capable interfaces, so the /32 just sits unused.
  Stick to physical and bridge interfaces.

### Disabling

Remove (or comment out) the `local-prefix` lines and restart
packetframe. SIGHUP doesn't reconcile this directive in v0.2.1
— a future version may add live add/remove via SIGHUP, but for
now it's a startup-time-only configuration. The /32 entries get
flushed on detach and don't reappear at next startup without the
directive.

### `arp-scavenge` for quiet LANs (v0.2.1, issue #32)

Some LANs — Ceph clusters, monitoring networks, anything where
hosts only do intra-/24 L2 traffic — never appear in the kernel's
L3 ARP cache. Without entries to feed from, the per-/32 emission
finds nothing.

The optional tail flag forces a one-shot ARP sweep at startup:

```
local-prefix 10.88.1.0/24 via br88 arp-scavenge
```

Capped at /22 (≤ 1024 hosts) at config-parse time. Rate-limited at
500 probes/sec internally. Live hosts respond → kernel ARPs them →
multicast event lands the /32. Operator opt-in (default off) because
it generates noticeable ARP traffic.

**Safety guarantee (v0.2.2+).** ARP probes are issued ONLY on the
operator-declared `via <iface>` — the resolver does NOT consult the
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
fabric — which violates IX ToS (MANRS, anti-DoS) on most exchanges.
`arp-scavenge` is for INTERNAL LANs only (storage, management,
customer LAN). For IX peer subnets, rely on bird's natural ARP
behavior — bird already maintains ARP for active BGP peers, so
their /32s will land via the normal nexthop-resolution path.

### `fallback-default` synthetic /0 (v0.2.1, issue #31)

Custom-FIB only has prefixes bird's iBGP feed advertised. Destinations
bird doesn't have specific routes for (RFC 1918, CGNAT, test-net,
anything outside DFZ) miss LPM, fall to kernel slow path through
netfilter / conntrack, and get dropped upstream anyway — wasting
kernel CPU + conntrack table capacity.

```
fallback-default via eth3 nexthop 194.110.60.50
```

Injects a `0.0.0.0/0` into FIB_V4 at startup. Every more-specific
bird-fed route still wins LPM; the /0 catches bogon-bound traffic.
XDP redirects directly to upstream — same upstream rejection behavior,
just no kernel / conntrack involvement. Measured ~25% reduction in
steady-state conntrack pressure on a busy Tor exit relay.

### `block-prefix` (v0.2.1, issue #33)

Drop bogon-bound traffic at XDP rather than let it traverse the
kernel forwarding path:

```
allow-prefix 23.191.200.0/24
block-prefix 10.0.0.0/8
block-prefix 100.64.0.0/10
block-prefix 192.168.0.0/16
```

After the allowlist match (so we only affect traffic we'd otherwise
fast-path), if dst is in any `block-prefix` the program returns
`XDP_DROP` and bumps `bogon_dropped`. Saves skb allocation +
netfilter walk + conntrack entry per dropped packet.

dst-only match — we never block by src, because that would silently
drop reply traffic for asymmetric flows where the *peer* happens to
be in a bogon range.

Refuses to start if a `block-prefix` overlaps any `allow-prefix` or
`local-prefix` (operator config bug — would silently drop traffic to
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
   default still flow via non-BGP mechanisms — udapi parses those
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

**Rollback re-exposes the original udapi bug** — BGP routes flow to
the kernel FIB again, udapi parses them, parse-error window opens up.
Rollback is "restore service now," not a steady state. Follow it with
same-day diagnosis and a forward-fix plan.

### Phase 4 bird + pathvector config

For a cutover to `forwarding-mode custom-fib`, packetframe needs
a feed of bird's selected best paths, and bird's kernel-protocol
export needs to stay off so udapi never sees BGP routes.

**Why iBGP and not BMP for the forwarding feed.** Bird (2.x and
3.x master) does not ship RFC 9069 Loc-RIB BMP — only
`monitoring rib in pre_policy / post_policy`, which deliver
per-peer Adj-RIB-In streams. That's wrong for forwarding: a
prefix announced by N peers becomes N RouteMonitoring frames
with N nexthops, with no signal which one bird actually picked.
iBGP, by contrast, runs bird's `protocol bgp` export filter
*after* best-path selection, so packetframe receives exactly
one UPDATE per prefix carrying bird's chosen path. See
`crates/modules/fast-path/src/fib/route_source_bgp.rs` for the
full design rationale.

**Bird config — inject via pathvector's `global-config`.**
Pathvector ships `global-config` verbatim into the rendered bird
config (no template fork needed). Add to `pathvector.yml`:

```yaml
global-config: |
  # iBGP feed to packetframe's BgpListener. AS 401401 is our own
  # AS — replace with yours. `passive` ensures bird only initiates;
  # we listen on 1179 (NOT 179, to avoid clashing with anyone else
  # who happens to bind 179 on the loopback).
  protocol bgp packetframe {
    local 127.0.0.1 as 401401;
    neighbor 127.0.0.1 port 1179 as 401401;
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

**Packetframe config:**

```
module fast-path
  forwarding-mode custom-fib              # or `compare` for the soak window
  route-source bgp 127.0.0.1:1179 local-as 401401 peer-as 401401 router-id 103.17.154.7
```

`router-id` is optional — defaults to the listen-address (v4) or
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
# Cheap guard against races at boot — wait up to 30 s for the BGP
# listener to be reachable before dialing.
[Service]
ExecStartPre=/bin/sh -c 'for i in $(seq 1 30); do ss -Htnl sport = :1179 | grep -q . && exit 0; sleep 1; done; exit 0'
```

Reload + restart the units after dropping these files:

```sh
sudo systemctl daemon-reload
sudo systemctl restart packetframe bird
```

### When to use `route-source bmp` instead

The BMP route source is useful when:

- Your routing daemon emits **RFC 9069 Loc-RIB BMP** (peer_type 3).
  FRR has this today; bird does not. Set `require-loc-rib` on the
  `route-source bmp` line — the BmpStation will refuse any
  non-Loc-RIB frame and tear the session down with an error,
  preventing silent wrong-forwarding from pre/post-policy streams:

  ```
  route-source bmp 127.0.0.1:6543 require-loc-rib
  ```

- You want a **pure observability** feed (analytics, anomaly
  detection on per-peer Adj-RIB-In streams) running alongside
  the BGP forwarding feed. This isn't wired into the controller
  yet — the current build accepts exactly one `route-source`
  per fast-path module.

## Triage by symptom

### Symptom: `custom_fib_miss` climbs without `custom_fib_hit` keeping pace

What it means: XDP is finding no route in `FIB_V4`/`FIB_V6` for most
matched packets. Either the FIB isn't populated (programmer not
writing), or the allowlist matches traffic bird doesn't cover.

Check:

- `packetframe status` — is `nexthops (resolved)` ≥ your expected
  peer count?
- `journalctl -u packetframe | grep -iE 'bgp|bmp'` — any errors from
  the route-source handler?
- `birdc show protocols packetframe` (or your BMP protocol name)
  — is the session established and propagating routes?

### Symptom: `pass_no_neigh` climbs sustainedly

What it means: FIB matches land on nexthop entries with state ≠
`Resolved`. Either the kernel hasn't ARP'd the nexthop yet (first-
packet; expected briefly), or the nexthop is genuinely unreachable.

Check:

- `ip neigh show <nexthop-ip>` — what state does the kernel report?
- `packetframe status` — is `nexthops (failed)` > 0?
- Proactive resolve is currently relying on first-packet kernel ARP
  (Phase 3.5+ adds proactive `RTM_NEWNEIGH NUD_NONE`). If
  `pass_no_neigh` only spikes for a few packets per new destination
  and then drops, that's expected.

### Symptom: `bmp_peer_down` incremented

What it means: bird reported a BGP peer went down; the programmer
withdrew all routes that peer announced. Expected behavior during
maintenance windows; alarming during stable state.

Check:

- `birdc show protocols | grep -v Established` — what's down?
- `journalctl | grep bird` — why?

### Symptom: `nexthop_seq_retry` climbs

What it means: XDP readers are observing seqlock writes in progress
more often than usual. Either the BGP session is churning nexthop
MACs (kernel ARP storms), or something is actively writing NEXTHOPS
outside the programmer.

Check:

- `ip monitor neigh` in a separate terminal — is there a neighbor
  storm?
- No process other than packetframe should be writing to
  `/sys/fs/bpf/packetframe/fast-path/maps/NEXTHOPS`.

### Symptom: route-source session stays up but routes stop flowing

What it means: bird is connected and idle. No new BGP churn, no new
routes. Usually benign — BGP in stable state just doesn't send much.

Check:

- `custom_fib_hit` still climbing (existing routes are still
  forwarding). If yes, this is fine.
- If forwarding has stopped entirely, that's a different problem —
  look at `fwd_ok`, `pass_not_in_devmap`, `drop_unreachable`.

### Symptom: Daemon won't start — "LPM trie create failed / ENOMEM"

What it means: kernel rejected a 2M-entry LPM trie allocation. Either
`rlimit.memlock` is too low, or the kernel has per-map caps.

Check:

- `ulimit -l` — is it `unlimited`? If not, set it in
  `/etc/systemd/system/packetframe.service.d/memlock.conf`:
  `[Service]\nLimitMEMLOCK=infinity`.
- If `unlimited` and still failing: reduce `FIB_V4_MAX_ENTRIES` in
  `crates/modules/fast-path/bpf/src/maps.rs`, rebuild.

## Known gaps

The following are known limitations. Listed here so you don't spend
time debugging behaviors that are known-missing. Items marked ✅
landed since the runbook was first written.

- ✅ **Proactive resolve** (Phase 3.6). `request_resolve(ip)` now
  issues `RTM_NEWNEIGH NUD_NONE` after looking up the route to find
  the egress ifindex. Best-effort: if route lookup or neighbor add
  fails, first-packet kernel ARP remains the fallback.
- ✅ **`src_mac` via RTM_GETLINK** (Phase 3.6). The NeighborResolver
  now caches `ifindex → MAC` from an RTM_GETLINK dump at startup and
  RTM_NEWLINK / RTM_DELLINK multicast events thereafter.
  `NEXTHOPS[id].src_mac` is the egress iface MAC, not zero.
- ✅ **InitiationComplete quiescence timer** (Phase 3.5). Fires once
  per BMP connection after 5 s of no RouteMonitoring frames.
- ✅ **`packetframe fib` subcommands** (Phase 3.8). `dump-v4 / dump-v6
  / lookup <ip> / stats` ship in the main binary. Opens the pinned
  maps directly; works without the daemon running.
- ✅ **Custom-FIB Prometheus metrics** (Phase 3.8). The textfile
  exporter now emits `packetframe_fib_forwarding_mode{mode="..."}`,
  `packetframe_nexthops{state="..."}`, `packetframe_nexthops_max`,
  `packetframe_ecmp_groups_active`, `packetframe_ecmp_groups_max`,
  and `packetframe_fib_default_hash_mode` on the usual 15 s cadence.
- ✅ **Offline comparison harness** (Phase 3.8). `tests/fib_comparison.rs`
  drives a synthetic RIB through the programmer and asserts the LPM
  lookups resolve correctly — runs in every qemu-verifier CI job.
- ✅ **Integrity check + BmpStalled alert** (Phase 3.8). When BMP is
  configured, the RouteController spawns a 5-minute periodic job
  that cross-checks `birdc show route count` against the mirror size
  and logs a warning on ≥1% drift. BmpStalled fires (warning log)
  when no ROUTE MONITORING in 5 min AND bird reports ≥1 Established
  peer AND process uptime > 10 min.
- ✅ **Netns integration test + BMP integration test** (Phase 3.7).
  `tests/neigh_resolver_netns.rs` + `tests/fib_programmer_integration.rs`
  cover the resolver and programmer paths end-to-end under sudo in
  CI's qemu-verifier jobs.
- ✅ **BGP route source + BMP Loc-RIB safety mode** (Phase 3.9).
  `route-source bgp <addr>:<port> local-as <asn> peer-as <asn>`
  spawns an iBGP listener that receives bird's selected best paths;
  bird's `protocol bgp` export filter runs after best-path so we
  never see per-peer Adj-RIB-In duplicates. BmpStation gains
  `require-loc-rib` which hard-rejects non-Loc-RIB frames. The
  iBGP feed is the recommended forwarding path for bird; the
  BMP path is for Loc-RIB-emitting daemons (FRR; future bird).
- ✅ **BgpListener direct-origin fallback + connected fast-path**
  (v0.2.1). Pre-v0.2.1 the BgpListener silently dropped iBGP UPDATEs
  whose decoded NEXT_HOP was None — exactly what bird emits for
  `protocol direct` (and static-origin) routes when the BGP block has
  no `next hop self`. Connected /24s never landed in FIB_V4, so every
  inbound packet to a customer host bumped `custom_fib_miss` and fell
  through to slow path. v0.2.1 makes the listener fall back to its
  own listen address; the route lands with `state=Incomplete` so
  counters reflect reality. The `local-prefix <cidr> via <iface>`
  directive turns those /24s into per-/32 fast-paths — see the
  [Connected fast-path](#connected-fast-path-v021) section above.
- ✅ **`fallback-default` synthetic /0** (v0.2.1, issue #31). Inject
  a catch-all default into the custom-FIB so bogon-bound traffic
  XDP-redirects to upstream instead of slow-pathing.
- ✅ **`arp-scavenge` for quiet LANs** (v0.2.1, issue #32). One-shot
  ARP sweep of declared local-prefix CIDRs at startup so storage
  networks (Ceph) get fast-path coverage even when their hosts don't
  voluntarily talk to the gateway.
- ✅ **`block-prefix` XDP-time drop** (v0.2.1, issue #33). Bogon
  destinations dropped at XDP instead of forwarded-and-failed.
