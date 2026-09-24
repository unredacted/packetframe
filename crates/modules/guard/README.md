# guard

A tc-**egress** frame policer for IX-facing interfaces. It polices the
L2 frames a router's own firmware sends and cannot be configured to
stop: neighbour-probe storms, leaked LLDP, and frames carrying some
other device's source MAC. Any of these can get a member port blocked
by an exchange's port security or broadcast limits.

tc egress is the only eBPF hook that sees this traffic. It is kernel
egress, AF_PACKET injections included, so XDP (ingress only), NIC
ntuple rules (RX only) and VPP (never carries kernel-originated frames)
all miss it. The module is therefore needed whether or not traffic is
offloaded elsewhere.

**Status:** code-complete; the verifier accepts it on CI's 5.15 and 6.6
kernels, and a netns test checks the rate limiter on a real egress hook.
It has not yet been through the monitor→enforce ladder on hardware.

## Frame classes

Each class is set per interface to `monitor` (count what would be
dropped) or enforce:

| Class | Directive | Action |
|---|---|---|
| ARP requests + IPv6 Neighbor Solicitations | `arp-ns-ratelimit` | Rate limit per **target** address |
| LLDP (ethertype `0x88cc`) | `lldp` | Drop |
| Source MAC other than the interface's own | `foreign-src` | Drop |
| Any other broadcast/multicast | `bcast-mcast-ratelimit` | Coarse per-interface rate limit |

The expected source MAC is read from the interface when it is attached,
so no MAC is written into the config. It is a snapshot, though: a
reload keeps the attach-time MAC. **If the interface's MAC changes (an
HA role change that moves MACs, say), restart the daemon**, or
`foreign-src … drop` will drop the interface's own frames.

Rate limiting uses GCRA: one deadline per bucket, in a shared
direct-mapped array with no per-CPU copies and no atomics. Buckets are
keyless. ARP/NS targets hash into 4096 slots, so "per target" is an
approximation: targets (or interfaces) that collide share one budget
and are policed more strictly, never less. Monitor mode runs the same
limiter, so its counts predict exactly what enforce would drop.

## Configuration

```
module guard
  interface br0                              # restart-only
  arp-ns-ratelimit br0 rate 3/60s burst 3
  lldp br0 drop
  foreign-src br0 drop
  bcast-mcast-ratelimit br0 rate 50/1s monitor
```

`burst 3` covers the kernel's full resolution cycle (three probes one
second apart), so normal neighbour resolution is not clamped unless its
target shares a bucket with another busy one. A daemon that re-probes
the same target forever gets one frame per 20 s.

- `interface` lines are **restart-only** (stop → `packetframe detach`
  → start). Class rules are **hot**: rates, bursts and monitor/enforce
  change on SIGHUP without re-attaching or resetting buckets.
- A guard section needs a `fast-path` section. Load refuses an
  `interface` with no rules, a rule naming an undeclared interface,
  duplicates, and more than 64 interfaces.
- The boot window before `packetframe.service` attaches is not
  covered. Keep any switch-side ACL until the counters have earned the
  fabric operator's trust.

Roll out in monitor mode first, then enforce one class at a time:
`lldp` and `foreign-src`, then `arp-ns-ratelimit`, then the catch-all.
The [runbook](../../../docs/runbooks/guard.md) has the full ladder.

## Observability

- `packetframe_guard_frames_total{class, verdict}`, where `verdict` is
  `passed`, `dropped` or `monitored` (would have dropped).
- `packetframe_guard_<name>_total` bookkeeping counters: `total_egress`,
  `pass_no_cfg`, `pass_no_match`, `err_parse_*`.

An enforced drop is visible to the sender. `TC_ACT_SHOT` at egress
makes a local AF_PACKET or raw sender see `ENOBUFS` ("No buffer space
available"). If a daemon starts logging that on a guarded interface
while `verdict="dropped"` moves, the guard is working; it is not a
buffer problem.

## Source layout

| Path | Contents |
|---|---|
| `bpf/` | The tc-egress classifier and its maps (nightly toolchain) |
| `src/cfg.rs` | Config parsing and the `GuardIfCfg` wire struct; portable |
| `src/linux_impl.rs` | Load, attach, `GUARD_CFG` population, detach, health |
| `src/metrics.rs` | Prometheus rendering; portable |
| `src/probe_linux.rs` | Probes added to `packetframe feasibility` |
| `src/pin.rs`, `src/tc_links.rs` | Pins under `<bpffs-root>/guard/` and `guard-tc-links.json` |

The guard shares the clsact qdisc with fast-path and never deletes it.
It keeps its own pins, state file and stats map, so detaching one
module leaves the other alone.

## Tests

```sh
cargo test -p packetframe-guard                                          # portable
sudo -E $(which cargo) test -p packetframe-guard --tests -- --ignored    # BPF + netns
```

The ignored tests cover the verifier, `bpf_prog_test_run` fixtures, tc
attach/detach, and a netns test that sends frames through a real egress
hook.

## Further reading

- [guard.md](../../../docs/runbooks/guard.md): ladder, counter attribution, triage, recovery
