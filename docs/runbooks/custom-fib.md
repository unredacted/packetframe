# Custom-FIB operations runbook

This runbook covers the Option F custom-FIB forwarding path: what the
pieces are, how to tell it's healthy, what to do when it's not, and
how to roll back to the kernel-FIB path if something goes wrong.

## Contents

- [Architecture at a glance](#architecture-at-a-glance)
- [Healthy operation](#healthy-operation)
- [Everyday inspection commands](#everyday-inspection-commands)
- [Cutover and rollback](#cutover-and-rollback)
- [Triage by symptom](#triage-by-symptom)
- [Known gaps](#known-gaps)

## Architecture at a glance

```
   bird (BGP RIB)                         kernel FIB
      │                                       │
      │  BMP over TCP                         │  local delivery +
      │  (RFC 7854 + 9069 Loc-RIB)            │  connected + static
      ▼                                       │
   packetframe BmpStation ──┐                 │
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

- **BmpStation** accepts bird's BMP dial-in. Bird sends one route-monitoring
  message per best-path prefix (Loc-RIB mode); we translate each to a
  `RouteEvent::Add`/`Del`.
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

### Is the BMP session live?

```sh
ss -Htnp state established "( sport = :6543 )" 2>&1
# Expect one line: bird ↔ packetframe on the BMP port.
```

If it's missing, check:

- `packetframe` daemon is running: `pgrep -a packetframe`
- bird is running: `birdc show status`
- bird's BMP config is live: `birdc show protocols | grep -i bmp`

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

### Force a BMP resync

Stop bird's BMP session; it will reconnect automatically:

```sh
birdc disable bmp1   # protocol name per your pathvector config
birdc enable bmp1
```

packetframe emits `RouteEvent::Resync` on disconnect and receives the
fresh dump on reconnect. Stale entries from before the reconnect are
GC'd by `InitiationComplete` (Phase 3.5+) or the next Resync.

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

## Cutover and rollback

### Cutover to custom-fib

**Pre-flight:**

1. Run the staging soak: custom-fib + BMP live to a bird mirror for
   24h. Zero `compare_disagree` sustained above 0.01% of matched
   packets, zero `StaleFib`, NEXTHOPS occupancy stable.
2. Confirm bird 2.17 exposes `monitoring rib local` BMP (RFC 9069
   Loc-RIB) and pathvector's template emits the block.
3. Add `forwarding-mode custom-fib` + `route-source bmp 127.0.0.1:6543`
   under `module fast-path` in `/etc/packetframe/packetframe.conf`.
4. Confirm bird's kernel-export filter keeps customer /32s + connected
   + static default only (no BGP routes).

**Cutover sequence:**

```sh
# 1. Stop the running packetframe daemon.
sudo systemctl stop packetframe  # or kill -TERM <pid>

# 2. Tear down bpffs pins.
sudo packetframe detach --all --config /etc/packetframe/packetframe.conf

# 3. Start the new daemon.
sudo systemctl start packetframe

# 4. Wait ~2-3 minutes for attach-settle-time × 6 interfaces.
# 5. Verify BMP session up.
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

For a cutover to `forwarding-mode custom-fib`, bird's BMP protocol
dials the packetframe station, and bird's kernel export drops BGP
routes so udapi stays off the BGP parse path.

Pathvector template addition (inside the appropriate `global:` /
`kernel:` / `templates:` section — adapt to your deployment):

```yaml
# bird 2.17 Loc-RIB BMP export. Station address matches the
# `route-source bmp <addr>:<port>` in packetframe.conf.
bmp:
  bmp1:
    station-address: 127.0.0.1
    station-port: 6543
    monitoring-rib: local   # RFC 9069 Loc-RIB (bird 2.17+).

# Restrict the kernel-export filter so BGP-learned routes stop
# flowing to the kernel FIB. Customer /32s, connected, static
# default still go; udapi parses those fine.
kernel-export-filter: |
  if source = RTS_BGP then reject;
  accept;
```

Validate after pushing:

```sh
birdc show protocols | grep bmp1           # state=up
birdc show route count | head              # count matches packetframe mirror ±convergence noise
sudo packetframe fib stats                 # forwarding-mode=custom-fib
ip route | wc -l                           # kernel FIB should drop ~1M entries
```

### Phase 4 systemd ordering

Packetframe's BMP station binds before bird dials in, so the service
order must be `packetframe.service` first, `bird.service` second.

`/etc/systemd/system/packetframe.service.d/bmp-ordering.conf`:

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
# Cheap guard against races at boot — wait up to 30 s for the BMP
# listener to be reachable before dialing.
[Service]
ExecStartPre=/bin/sh -c 'for i in $(seq 1 30); do ss -Htnl sport = :6543 | grep -q . && exit 0; sleep 1; done; exit 0'
```

Reload + restart the units after dropping these files:

```sh
sudo systemctl daemon-reload
sudo systemctl restart packetframe bird
```

## Triage by symptom

### Symptom: `custom_fib_miss` climbs without `custom_fib_hit` keeping pace

What it means: XDP is finding no route in `FIB_V4`/`FIB_V6` for most
matched packets. Either the FIB isn't populated (programmer not
writing), or the allowlist matches traffic bird doesn't cover.

Check:

- `packetframe status` — is `nexthops (resolved)` ≥ your expected
  peer count?
- `journalctl -u packetframe | grep -i bmp` — any errors from the BMP
  handler?
- `birdc show protocols bmp1` (or whatever protocol name) — is the
  session established?

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

### Symptom: BMP session stays up but routes stop flowing

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
