# guard — tc-egress frame policer

Operational runbook for the `guard` module: what it polices, the
monitor→enforce ladder, counter reading, triage, and recovery.

## What it is, in one paragraph

A tc-**egress** cls_bpf classifier on configured interfaces (in
production: the IX-facing bridges) that polices locally-originated L2
frames the platform's firmware emits uncontrollably. Four fixed
classes, each per-interface and independently `monitor` or enforce:
per-target rate-limited ARP requests / IPv6 Neighbor Solicitations,
dropped LLDP, dropped foreign-source-MAC frames, and a coarse
broadcast/multicast catch-all. It exists because udapi-server's
arping/ndisc6 storms got this fleet blocked from an IX, LLDP/BPDU
leaks and a leaked standby MAC tripped IX port security — and because
**tc egress is the only eBPF hook that can see this traffic**: it is
kernel egress (including AF_PACKET injections like arping's),
invisible to XDP (ingress-only), NIC ntuple/MCAM (RX-only), and VPP
(never carries kernel-originated frames). That stays true at every
stage of the vpp-offload roadmap, so the guard is permanent
architecture, not a stopgap.

## What it deliberately does NOT cover

- **The boot window.** Filters attach when `packetframe.service`
  starts; between kernel-up and attach, firmware daemons can spray.
  Keep the switch-side ACL backstop until the fabric operator agrees
  to relax it.
- **Frames the agg switches originate.** PF runs on the router;
  switch-originated LLDP/BPDUs are the switch-config tooling's job.
- **Ingress traffic.** Dropping inbound attacks is a different module
  (ddos, XDP/MCAM — see the plan history); the guard never inspects
  received frames.

## Config in one screen

```
module guard
  interface br3998                              # RESTART-ONLY
  arp-ns-ratelimit br3998 rate 3/60s burst 3    # hot
  lldp br3998 drop                              # hot
  foreign-src br3998 drop                       # hot
  bcast-mcast-ratelimit br3998 rate 50/1s monitor
```

- `interface` set: restart-only (stop → `packetframe detach` → start).
  Everything else reconciles on SIGHUP with no reattach and no bucket
  reset.
- The rate limiter is per **target address** (ARP tpa / NS target),
  not per frame class: `rate 3/60s burst 3` means each target gets a
  3-frame burst then 1 per 20 s. Burst 3 covers the kernel's full
  resolution cycle (3 probes at 1 s intervals, `mcast_solicit=3`), so
  legitimate neighbor resolution never clamps — the property that
  answers the IX operator's reply-only-mode blackhole objection.
- Refused at load: an empty section, duplicate `interface` lines, a
  class rule naming an undeclared interface, duplicate
  `(class, interface)` pairs, an `interface` with zero rules.

## The monitor→enforce ladder

1. Deploy every class with `monitor`. Confirm
   `packetframe status` shows the module healthy and
   `packetframe_guard_frames_total{verdict="monitored"}` moving where
   you expect (udapi's ARP cadence should show up within minutes).
2. Let it sit long enough to cover a provisioning cycle and a quiet
   night. Anything unexpected in `class="bcast_mcast"` monitored
   counts — identify before enforcing; that class is the blast-radius
   one.
3. Flip `lldp` and `foreign-src` to `drop` first (SIGHUP). Both are
   unambiguous violations; neither has a legitimate emitter on an IX
   port.
4. Flip `arp-ns-ratelimit` to enforce. Watch
   `verdict="dropped"` — it should match what `monitored` predicted
   exactly (the limiter's state advances identically in both modes).
5. Enforce `bcast-mcast-ratelimit` last, with a rate sized from the
   observed monitored baseline plus headroom.

## Counters

Two Prometheus families, both in the standard textfile:

- `packetframe_guard_frames_total{class, verdict}` — class ∈
  `{arp, ns, lldp, foreign_src, bcast_mcast}`, verdict ∈
  `{passed, dropped, monitored}`. `monitored` = would-have-dropped.
- `packetframe_guard_<name>_total` bookkeeping: `total_egress`,
  `pass_no_cfg`, `pass_no_match`, `err_parse_*`.

Attribution notes that will otherwise confuse a 3am reader:

- **`foreign_src` monitored is non-terminal**: the frame is counted
  and continues through the remaining classes, so one frame can move
  `foreign_src/monitored` AND an `arp/*` counter. Every other counter
  is exclusive; `total_egress` equals the sum of the terminal ones.
- With the `lldp` class disabled, LLDP still lands in
  `bcast_mcast` (its dst MAC is multicast). Same for ARP *replies*,
  GARP, and NS behind IPv6 extension headers — the catch-all is the
  backstop for everything ND-shaped the specific classes don't parse.
- `pass_no_cfg` should be ~0 in steady state; sustained movement means
  frames egressing an attached interface whose config-map entry is
  missing or version-skewed — a bug, report it.
- `err_parse_*` count fail-open passes on truncated headers. Local
  daemons don't emit runts; sustained movement is worth a tcpdump.

## Triage by symptom

- **Neighbor resolution slow/failing on an IX** (peers unreachable,
  `ip neigh` stuck in `INCOMPLETE`): check `arp/dropped` +
  `ns/dropped`. If they move in step with the failures, the rate is
  too tight or a legitimate burst pattern exceeds it — flip to
  `monitor` via SIGHUP (instant, no restart) and re-derive the rate.
- **IX operator still sees storms while enforce is on**: confirm the
  filter exists (`tc filter show dev br3998 egress`), the module is
  healthy in `packetframe status`, and `total_egress` is moving. If
  the storm is on a VLAN/interface the guard isn't attached to,
  remember frames the *switch* originates never traverse the router.
- **Module health row `attach:<iface>` Degraded, "interface
  vanished"**: the device was deleted; qdisc-lifetime filters die with
  their device, nothing is leaked. Restart after the interface is
  back.
- **Startup refuses with "existing pins"**: prior invocation's state;
  run the standard recovery (below). v0.1 never adopts in place.

## Recovery / teardown

`packetframe detach` (config-scoped — only when the config has a
guard section) or `packetframe detach --all` tears down the egress
filters from `guard-tc-links.json` and removes the pins under
`<bpffs-root>/guard/`. The clsact qdisc is deliberately left in place
(fast-path may share it on the same interface). A detach that cannot
prove a filter is gone retains its record and errors — rerun it, or
as a last resort `tc filter del dev <iface> egress`.

Manual state check:

```
tc filter show dev br3998 egress          # the classifier
cat /var/lib/packetframe/state/guard-tc-links.json
ls /sys/fs/bpf/packetframe/guard/{progs,maps}
```

## Coexistence with fast-path / vpp-offload

- fast-path (tc ingress on some ports) and guard (tc egress) share one
  clsact qdisc per interface; attach order doesn't matter and each
  module's detach removes only its own filter.
- Guard state lives in `guard-tc-links.json` — **never** in
  fast-path's `tc-links.json`, which fast-path's detach tears down
  unconditionally.
- vpp-offload steering has no interaction: MCAM diverts ingress before
  the kernel; VPP's own egress bypasses kernel tc; the frames guard
  polices never enter either path. Kernel neighbor resolution (which
  VPP's adjacencies are mirrored from) keeps working under enforce by
  design of the per-target rate limit.

## Implementation notes an operator may need once

- Rate limiting is GCRA: one deadline word per bucket, `burst`
  back-to-back then 1 per `interval/rate`, idle targets decay back to
  full burst. Buckets are hash-indexed with **collision = shared
  budget** (strictly stricter, never evasion); 4096 slots for ARP/NS
  targets, 256 for the per-interface catch-all.
- A rate increase applied by SIGHUP can leave a hot target clamped for
  up to one *old* burst window (stale deadlines are not flushed);
  converges on its own.
- The expected MAC for `foreign-src` is snapshotted at attach. If an
  interface's MAC legitimately changes, restart the daemon.
