# neigh-snoop — passive ARP/ND neighbour snooper

Operational runbook for the `neigh-snoop` module: what it learns and
installs, the rollout ladder, counter reading, the FRR next-hop gate it
feeds, acceptance tests, triage, and recovery.

## What it is, in one paragraph

A receive-only listener on IX-facing bridges that learns `(ip, mac)`
pairs from the ARP requests/replies and IPv6 neighbour solicitations /
advertisements every fabric participant floods to every member port,
and installs the ones the kernel is missing as `NUD_STALE` entries. It
exists because a router that may not send broadcast ARP or multicast
NS (a switch ACL drops them, deliberately, because the platform
daemon's neighbour probing cannot be configured) can only reach a peer
whose MAC the kernel already holds — and Linux learns a neighbour only
from a request aimed at one of its own addresses, discarding every
other participant's. After a reboot that meant hours per peering
session, and route-server prefixes behind never-heard next-hops were
blackholed. A STALE entry with a valid MAC forwards immediately; the
kernel then confirms it with a **unicast** probe the ACL permits. The
table is persisted per bridge and re-seeded whenever the bridge comes
back, which on this platform is every controller provision and every
BGP upload. **It never transmits.**

## What it deliberately does NOT cover

- **Answering ARP/ND for anyone.** The kernel does that, unchanged.
- **Installing `PERMANENT` or `REACHABLE` entries.** STALE only; the
  kernel owns the state machine and can still detect a dead peer.
- **Overriding a MAC the kernel has confirmed.** A snooped frame that
  disagrees with a REACHABLE/DELAY/PROBE entry is counted
  (`mac_conflict`) and ignored: a second router leaking on that
  participant's port is more likely than a real move, and NUD will
  fail the entry if the held MAC stops answering — FAILED *is*
  repaired.
- **Participants that never resolve anyone.** Passive learning makes
  an unresolved next-hop rare, not impossible. The FRR next-hop gate
  (below) makes it harmless.
- **The kernel's own probes.** Under kernel-fib nothing in fast-path
  changes; `ix-mode` suppresses only fast-path's proactive kick, and
  seeding is what removes the kernel's dropped broadcasts.
- **The boot window** before `packetframe.service` attaches.

## Config in one screen

```
module neigh-snoop
  bridge br0 ix-mode                                    # RESTART-ONLY
  bridge br1
  prefix br0 192.0.2.0/24                               # hot
  prefix br0 2001:db8:1::/64
  prefix br0 fe80::/10
  prefix br1 198.51.100.0/24
  deny-mac 02:00:00:00:00:01                            # hot
  peer br0 192.0.2.10 2001:db8:1::10 route-server       # hot
  peer br1 198.51.100.20
  persist-dir /var/lib/packetframe/state/neigh-cache    # RESTART-ONLY
  seed-max-age 14d                                      # hot
  install-rate 50/1s                                    # hot, daemon-wide
  table-max 4096                                        # hot
  coverage-interval 60s                                 # hot
  frr-gate v4 IX-RESOLVED-NH v6 IX-RESOLVED-NH6         # presence/names RESTART-ONLY
  rs-coverage-interval 300s                             # hot
```

- `bridge` is the directive (not `interface`, which is guard's; the
  directive namespace is shared across module sections). Bridges are
  tracked by **name**: an absent bridge is a health row, not a startup
  refusal, and a recreated one (same name, new ifindex) gets a fresh
  socket and a re-seed.
- One `peer` line per router, listing every address it uses on the
  fabric. The exchange enforces one MAC per member port, so a MAC
  learned for any address on the line is installed for the others too.
  That is how a route server's v6 global gets a MAC when it only ever
  sources solicitations from link-local.
- Refused at load: a section with no `bridge`; duplicate `bridge`;
  more than 16 bridges; `prefix`/`peer` naming an undeclared bridge; a
  `bridge` with no `prefix` (an empty allowlist learns nothing and
  reports healthy); duplicate prefixes, deny-macs, or a peer address
  on two lines; a peer outside every prefix of its bridge; more peer
  addresses than `table-max`; a repeated singleton; `persist-dir`
  equal to the global `state-dir`; `route-server` without `frr-gate`;
  a `/0` prefix; and, last, a neigh-snoop section without a fast-path
  section.
- Adding or removing the module section is restart-only (the daemon
  cannot construct modules after startup). Restart is the usual dance:
  stop → `packetframe detach` → start.

## Rollout ladder

1. `packetframe feasibility --config …`. Every `neigh-snoop.*` probe
   should pass or warn (an absent bridge warns; the module waits for
   it). A `caps` or `af_packet` failure means attach will refuse.
2. Deploy with `install-rate 1/60s`, no `ix-mode`, no `frr-gate`.
   Watch `packetframe_neigh_snoop_learn_total{outcome="new"}` and
   `table_entries` climb (a peering LAN produces tens of frames per
   second) and `install_total{outcome="confirmed"}` trickle. Check the
   `snoop:<bridge>` health row reads `capturing`.
3. Raise `install-rate` via SIGHUP. Check `install_backlog` drains.
   The rate is one budget for the whole daemon, dispensed round-robin
   across bridges: with N bridges re-seeding at once each gets roughly
   1/N of it, so size the rate for the sum of the bridges' tables.
4. Run the acceptance tests below (T1–T3, T6).
5. Add `ix-mode` (restart). fast-path's stats line gains
   `ix_probe_suppressed`; `custom_fib_no_neigh` should fall.
6. Enable `frr-gate` (restart) once the static FRR half is uploaded.
   Confirm the lists match what a hand-built list would hold, then
   retire any manual seeding of them.
7. Add `peer … route-server` lines. Watch `rs_demoted_prefixes` fall
   over the first day; that number is the real cost of passive
   learning, in prefixes.

## Counters and gauges

All labelled `module="neigh-snoop",iface="<bridge>"`:

- `frames_total{kind}` — learnable frames parsed: `arp_request`,
  `arp_reply`, `ns`, `na`.
- `learn_total{outcome}` — `new`, `refreshed`, `mac_changed`,
  `evicted`, `derived` (installed for another address of a declared
  peer).
- `filter_rejects_total{reason}` — `outside_prefix`, `own_address`,
  `own_mac`, `denied_mac`.
- `parse_rejects_total{reason}` — every way a frame can be refused;
  `sha_mismatch` is the one that means a forged or broken sender.
- `install_total{outcome}` — `confirmed` (the RTM_NEWNEIGH echo carried
  our MAC; **this is the real number**), `requested` (diagnostic),
  `unconfirmed`, `failed`, `overridden`, `skipped_same_mac`,
  `skipped_permanent`, `skipped_noarp`, `skipped_holddown`,
  `skipped_unknown_state`, `mac_conflict`.
- `seed_total{outcome}` — `requested`, `confirmed`, `expired`,
  `bad_entry`.
- `persist_total{outcome}`, `link_events_total{kind}` (`up`, `down`,
  `recreated`), `socket_errors_total`,
  `frames_outgoing_dropped_total`, `frames_backpressure_dropped_total`.
- Gauges: `table_entries`, `link_up`, `promisc_confirmed`,
  `install_backlog`, `peers{state=heard|never_heard}`,
  `participant_addresses{state=resolved|unresolved}`,
  `route_nexthops{state}` (absent until the first sample),
  `nexthop_objects`, `coverage_dump_ms`, `coverage_age_seconds`.

Attribution notes:

- **`confirmed`, not `requested`, is the install count.** Requested is
  when we asked; confirmed is when the kernel echoed our MAC back.
- `refreshed` moves on every sighting of a known pair and marks the
  table dirty; the persist debounce (3 s) coalesces it.
- `mac_conflict` climbing on one address is a participant with two
  routers on its port, or spoofing. Nothing is installed; look at who.
- `frames_outgoing_dropped_total` should be zero. Non-zero means the
  socket filter is not attached.
- `recreated` link events during a provision or BGP upload are normal;
  a re-seed follows each.

## The FRR next-hop gate

The gate is why an unresolved next-hop cannot blackhole. Its static
half is FRR configuration (uploaded once): two prefix-lists that
always exist because each holds a placeholder `deny` at a low sequence
number, and IX route-maps that prefer a route only when its NEXT_HOP is
a bilateral peer or in the runtime list, keeping every other route at
a local-preference below transit. `soft-reconfiguration inbound` on the
IX sessions lets a list change re-evaluate in place with no route
refresh; `set ipv6 next-hop prefer-global` makes the installed v6
next-hop the address the lists hold. The failure direction is
"demote", never "prefer": a bgpd restart empties the runtime entries
and every route-server route drops below transit until PF refills them.

PF owns the dynamic half when `frr-gate` is configured:

- Desired set: addresses on snooped bridges whose kernel entry holds a
  MAC in REACHABLE/STALE/DELAY/PROBE. Added at once; removed only after
  `remove-after` of continuous FAILED/absent, so one lost unicast probe
  does not flap a prefix between IX and transit. Link-locals are never
  listed.
- Actual set: `show ip prefix-list <name>` / `show ipv6 prefix-list
  <name>` through `vtysh`, compared by content. Entries at sequence
  numbers below 100 are the operator's placeholders and are never
  touched; runtime entries are written with explicit sequence numbers
  from 100 upward (FRR's auto-numbering would continue from the
  placeholder into the operator's range).
- One batched `vtysh` invocation per changed tick; a readback that
  matches the desired set is what counts as `changed`.
- A reload (the lists fell back to placeholders only) triggers an
  immediate refill.
- Route-server coverage: each `route-server` peer's received routes
  (available for every path because of soft-reconfiguration) are
  dumped every `rs-coverage-interval`; a prefix whose next-hop is
  neither a bilateral peer nor resolved counts as demoted.

Every BGP upload restarts bgpd and toggles the IX bridge, which
flushes the kernel neighbour table; expect a `recreated`/`down`/`up`
sequence, a re-seed, and a gate refill after each one.

## Acceptance tests

Run as root on the router. Placeholders: `<br>` the bridge, `<peer>` a
bilateral peer whose far side is configured and active (not one whose
session has never been up from their side).

- **T1 learn rate / coverage vs a baseline.** Ten minutes of
  promiscuous capture alongside the running snooper:
  `tcpdump -i <br> -nn -w /tmp/nd.pcap 'arp or (icmp6 and (ip6[40]==135
  or ip6[40]==136))'`, then count distinct sender pairs. The snooper's
  `table_entries` after the same window must be at least that count
  (it is promiscuous too, so the comparison is fair).
- **T2 cold-peer recovery.** `ip neigh del <peer> dev <br>`; the entry
  must return as `STALE` within the peer's learn time plus one
  install interval, with `install_total{outcome="confirmed"}`
  incrementing and no kernel probe from us.
- **T3 zero emissions.** `tcpdump -i <br> -Q out -nn 'arp or (icmp6 and
  (ip6[40]==135 or ip6[40]==136))'` for the whole test window must show
  nothing attributable to the daemon (kernel-originated unicast probes
  to known MACs are expected and permitted; the switch-side broadcast
  counter toward the exchange must not move).
- **T4 reboot recovery.** Reboot with the IX ports left up. Every
  bilateral session that was `Established` must return within a few
  minutes of the bridge coming up; `seed_total{outcome="confirmed"}`
  should be close to `table_entries`.
- **T5 provision survival.** Trigger a controller provision or BGP
  upload. `link_events_total{kind="recreated"}` (or `down`+`up`)
  increments, the socket rebinds, the re-seed runs, no restart needed.
- **T6 wrong MAC self-heals.** `ip neigh replace <ip> lladdr
  02:00:00:00:00:ff dev <br> nud stale`; the next frame from the
  participant replaces it (`mac_changed`, then `confirmed`).
- **T7 route servers.** Only after the gate is live. Enable the
  route-server sessions; `rs_demoted_prefixes` must be the only cost
  and must trend to zero; `ip neigh show dev <br>` must show no
  `INCOMPLETE` or `FAILED` next-hop of an installed route after a few
  minutes.

## Triage by symptom

- **`snoop:<br>` Degraded "link absent"**: no device of that name;
  normal mid-provision. Persisting for minutes means the bridge name in
  config is wrong or the platform dropped the VLAN.
- **`snoop:<br>` Degraded "no learnable frame for N s"**: the link is up
  but nothing arrives. Check `promisc_confirmed` (the kernel must have
  echoed `IFF_PROMISC`), `socket_errors_total`, and whether the
  upstream port still delivers flooded frames.
- **`snoop:<br>` Unhealthy "socket error"**: the capture could not be
  opened — usually capabilities (`CAP_NET_RAW`) or the device vanished
  between dump and bind; the engine retries every second.
- **`install_total{outcome="failed"}` climbing**: `EPERM` → missing
  `CAP_NET_ADMIN`; `ENETDOWN` → the bridge went down mid-batch;
  anything else, read the WARN lines (first 20 are logged).
- **`filter_rejects_total{reason="outside_prefix"}` climbing**: a
  prefix is missing from config (a second range on the fabric, or the
  link-local `fe80::/10` line).
- **`peers` row Degraded**: the named addresses have never been heard.
  A router that never resolves anyone cannot be learned; if it is a
  route server, its bilateral session still comes up because *it*
  initiates and the kernel learns from its solicitation of us.
- **`coverage` row Degraded "routes=unknown"**: the strict-check
  netlink dump is unavailable on this kernel; participant coverage
  stays measured, route coverage is disabled rather than dumping the
  whole table.
- **`evictions` non-zero**: raise `table-max`.
- **Persisted table ignored at start ("file is for bridge …")**: a
  JSON file was copied between bridges; delete it.

## Recovery / teardown

`packetframe detach` prints that neigh-snoop has nothing to tear down.
That is correct: no BPF, no pins, no tc. What it leaves behind, on
purpose:

- the learned `NUD_STALE` neighbours — correct kernel state the kernel
  now owns (`ip neigh flush dev <br> nud stale` removes them if you
  mean it);
- `<persist-dir>/<bridge>.json` — the next start's seed (`rm` it to
  forget a bridge's table; a wrong MAC in it costs one failed unicast
  probe and is corrected on the next sighting).

`packetframe status` prints each bridge's persisted table size and
age without a daemon.

## Coexistence

- **guard** polices the kernel's *own* ARP/NS emission on the same
  bridges; the snooper makes those emissions rarely necessary and never
  adds to them. Both can run on one bridge.
- **fast-path custom-fib**: `ix-mode` bridges get no proactive kick
  from the resolver; the resolver already treats STALE entries as
  resolved, so seeded neighbours flow into the nexthop table.
- **vpp-offload**: VPP's adjacencies are mirrored from the kernel
  neighbour table through the resolver, so seeded entries reach VPP
  too. ARP/ND are not prefix-steered, so the tap keeps seeing them
  under steering.
- **HA standby**: the same config runs on the standby; its bridges are
  down, so the module idles with `link absent`. Its persisted cache is
  **empty on first failover** and fills from the fabric within minutes.

## Implementation notes an operator may need once

- Promiscuous mode, not allmulti, and deliberately: the bridge's
  forwarding code never consults `IFF_ALLMULTI` when deciding what
  reaches the host. Multicast arrives under allmulti only while no MLD
  querier exists on the segment; the day one appears, solicitations for
  other participants stop arriving and IPv6 learning collapses
  silently. On a single-member bridge behind a switch that only
  delivers our frames, promisc admits nothing extra. It is requested as
  a socket membership, so the kernel refcounts it and releases it when
  the socket closes.
- Coverage reads kernel **nexthop objects**: FRR installs routes that
  carry a nexthop id and no gateway, so a plain route dump would read
  zero. Groups are expanded; gateway-less connected objects are
  skipped.
- The persist debounce is 3 s from the first change; a stream of
  refreshes produces one write per window.
- Installs are paced round-robin across bridges, so a boot-time seed on
  one bridge cannot starve live learns on another.
