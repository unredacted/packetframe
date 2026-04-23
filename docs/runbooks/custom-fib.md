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
# What packetframe would do: currently requires tcpdump/BPF-inspect;
# `packetframe-ctl fib lookup` lands in Phase 3.5+.
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

The following are known limitations that will be addressed in Phase
3.5+. Listed here so you don't spend time debugging behaviors that
are known-missing:

- **Proactive resolve is a no-op.** `request_resolve(ip)` logs the
  request but doesn't issue `RTM_NEWNEIGH NUD_NONE`. First-packet
  kernel ARP is the fallback.
- **`src_mac` is zero.** The MAC packetframe writes as the Ethernet
  source address on redirected frames is currently `00:00:00:00:00:00`.
  Switches don't generally care about src_mac for forwarding decisions,
  but any policy-based tooling that does will trip on this. Phase 3.5+
  adds RTM_GETLINK lookup of the egress iface MAC.
- **InitiationComplete doesn't fire autonomously.** The programmer
  receives `Resync` on BMP disconnect and reconcile on reconnect, but
  the InitComplete signal that GCs stale entries is Phase 3.5+.
- **`packetframe-ctl fib dump/lookup/stats`** subcommands are not yet
  implemented. Use `packetframe status` + counter deltas for now.
- **Prometheus metrics** are limited to the existing textfile counters
  in `/var/lib/node_exporter/textfile/packetframe.prom`. Custom-FIB
  occupancy isn't exported yet.
- **Offline comparison harness** isn't wired into CI yet; we rely on
  the staging soak + `compare` mode for pre-cutover validation.
