# tc-ingress datapath (Phase T)

Operational guide for `attach <iface> tc`: running the fast-path as
sched_cls classifiers on a clsact qdisc instead of XDP.

## When to use it

On hosts forced into `xdp-generic` (e.g. rvu-nicpf kernels < 6.8), the
dominant per-packet CPU costs are outside the BPF program: the kernel
copies every packet to guarantee 256 bytes of headroom
(`pskb_expand_head`), linearizes GRO super-skbs, and transmits
redirects one at a time. The tc datapath runs the same forwarding
logic after normal skb receive and avoids all three; GRO aggregates
forward as single units and segment on egress. Expected win vs generic
XDP: substantial for TCP-heavy traffic (GRO amortization), meaningful
for small-packet floods. It is strictly slower than *native* XDP —
hosts that can run native should.

`auto` never selects tc. It is a per-interface, explicit opt-in so
canary rollouts stay operator-controlled.

### Measured expectation on rvu-nicpf / otx2

The cost model above is the *documented* generic-XDP behavior — verify it
against your driver before expecting a win. On the reference EFG
(5.15.72-ui-cn9670, otx2/rvu-nicpf, ~640 kpps live), a 2026-07-31 `perf`
profile showed **neither `pskb_expand_head` nor `skb_linearize` anywhere in
the top of the profile** (below 0.5% of samples): this driver evidently
already reserves enough headroom that `netif_receive_generic_xdp` never
reallocates, so the per-packet copy tax that motivates the tc datapath is
not being paid on this hardware. See
`generic-mode-performance.md` §"Measured profile on cn9670 / otx2".

Consequence: **expect ~no CPU change from tc on this fleet.** The reasons
to run it anyway are operational, not performance:

- tcpdump regains ingress visibility (generic XDP consumes packets before
  the capture point; sched_cls runs after it);
- tc attach never calls `otx2_xdp_setup`, which matters **only relative
  to native XDP**: the pre-6.8 rvu-nicpf `non_qos_queues` leak is a
  native-attach (`DRV_MODE`) bug, and the version gate already forces
  `auto` to generic on affected kernels precisely because generic
  attach has no queue leak either. Migrating generic → tc adds no
  queue-leak protection; the point is that tc (like generic) stays
  safe if someone later forces native semantics into the mix.

On a driver that *does* pay the headroom copy (check with `perf` for
`pskb_expand_head` before deciding), the original 1.5–3× estimate stands.

### Measured verdict on the reference EFG (2026-08-01): do not use tc for CPU

A full-scale test (all six interfaces tc, 100% of ingress on the tc
datapath, FIB 97% converged in the measurement window, same night and
traffic profile as the XDP baselines):

| Datapath | total irq+softirq ns/pkt |
|---|---|
| generic XDP (IRQ-coalesced) | 11,173 @ 806 kpps |
| **tc, all interfaces** | **18,951 @ 522 kpps (+70%)** |
| generic XDP after revert | 12,259 @ 651 kpps |

Two mechanisms, both structural on this platform:

- **tc egress re-enters `dev_queue_xmit`**, paying the fq qdisc
  (enqueue/dequeue + locks) *and* the AF_PACKET tap walk
  (`dev_queue_xmit_nit` — ~9% of busy CPU on UniFi OS, see
  generic-mode-performance.md §"Platform taxes") for every forwarded
  packet. Generic XDP's `generic_xdp_tx` bypasses both. Any
  doorbell-batching benefit from qdisc bulk dequeue is buried under
  these two costs.
- **fq's `flow_limit` (100 packets/flow on the EFG) drops forwarded
  traffic** that XDP egress never exposed to a qdisc: `tc -s qdisc`
  `flows_plimit` advanced at ~100+/s on the busy egress port during the
  test. Per-flow caps concentrate loss on the heaviest flows, which is
  exactly what BBR senders back off from — observed as an rx pps drop
  coincident with the cutover.

A quiet single-interface canary cannot see either effect (0.5% share
measured 99.4% forward parity and looked clean). On this fleet the tc
datapath is reserved for **temporary, single-interface tcpdump
visibility**; it is not a CPU optimization and must not be fleet-wide.
Also observed: `err_parse` runs ~0.18% of tc-path traffic (fail-safe —
those packets take the kernel slow path) vs ~zero under XDP. See
[The tc-only `err_parse`](#the-tc-only-err_parse) for the analysis, the
leading hypothesis, and what would confirm it. Diagnose before any
future tc use beyond debugging.

## The tc-only `err_parse`

**Status: analysed, instrumented, not yet measured.** The counters that
would confirm it now exist; no tc canary has been run since they were
added, so the hypothesis below is still a hypothesis.

`err_parse_tc` has exactly four producers, all in `tc.rs`, and they are
all the same shape — a bounds check against `ctx.data_end()`:

| site | condition |
|---|---|
| `tc_try_fast_path` | shorter than `EthHdr` |
| `tc_try_fast_path` | 802.1Q/ad frame shorter than `EthHdr + VLAN_HDR_LEN` |
| `tc_handle_ipv4` | shorter than `EthHdr + Ipv4Hdr` (plus the VLAN offset) |
| `tc_handle_ipv6` | shorter than `EthHdr + Ipv6Hdr` (plus the VLAN offset) |

There is no fifth path, and none of them is a malformed-packet check.
Every one of them says *the bytes I need are not in front of me*.

### Why that is a different statement under tc than under XDP

Under XDP the program sees a linear buffer: `data`..`data_end` is the
whole frame, so a bounds failure really does mean a runt. Under
`cls_bpf` it does not. `data`..`data_end` spans only the **linear** part
of the `sk_buff`, and a non-linear skb — GRO-coalesced, or one whose
driver placed payload in page fragments — can carry its L3 header
outside that window while being a perfectly well-formed packet.

That fits every observation:

- **It is tc-only.** The XDP path cannot produce it, and measures ~zero.
  A cause rooted in malformed traffic would show on both.
- **The rate is small and non-zero** (~0.18%), which is the shape of a
  minority of skbs arriving paged rather than of a traffic class.
- **It is fail-safe today.** Those packets fall to the kernel path and
  forward correctly, which is why this has never been urgent.

The remedy, if confirmed, is `bpf_skb_pull_data(skb, needed)` before the
parse, with `data`/`data_end` re-read afterwards — the pointers are
invalidated by the call. It is not free: a pull can copy.

### The breakdown, and how to read it

Four appended counters now split the sites, bumped **in addition to**
`err_parse` and `err_parse_tc` so both keep their meaning:

| counter | site |
|---|---|
| `err_parse_tc_l2` | shorter than `EthHdr` |
| `err_parse_tc_vlan` | inline-tagged frame shorter than `EthHdr + VLAN_HDR_LEN` |
| `err_parse_tc_l3_v4` | shorter than the IPv4 header at its offset |
| `err_parse_tc_l3_v6` | shorter than the IPv6 header at its offset |

They partition `err_parse_tc` — the four must sum to it, and a test
asserts that so a site added later cannot quietly shrink the total.

What each outcome would mean, decided now rather than after seeing the
numbers:

- **Concentrated in the L3 arms** → the non-linear-skb hypothesis holds.
  L3 sits furthest into the frame, so it is what a short linear window
  truncates first. Proceed to `bpf_skb_pull_data`.
- **Concentrated in `l2`** → genuine runts, and the hypothesis is wrong.
  A frame too short for 14 bytes is malformed however it is stored.
- **Split by FAMILY rather than by depth** (v4 and v6 arms differing by
  much more than their traffic ratio) → also wrong, or at least
  incomplete: the two headers differ in size, so a depth explanation
  predicts they track traffic share while a family explanation does not.
- **`vlan` non-zero at all** → notable on its own. That arm is reachable
  only when the tag is still in-band, which on this fleet should be
  rare, since the driver lifts it into `vlan_tci`.

### The remedy is deliberately NOT applied yet

If the L3 arms dominate, the fix is `bpf_skb_pull_data(skb, needed)`
before the parse, with `data`/`data_end` re-read afterwards — the call
invalidates them — and it is not free, since a pull can copy.

It is not in this change on purpose. Applying a remedy before the
diagnosis confirms the disease is how a correct piece of code gets
"fixed" into a broken one; that happened twice in this repo in one week
(see `docs/runbooks/vpp-offload.md` on the ntuple mask). The counters
cost nothing on the fast path — they are bumps on an already-failing
branch — and they answer the question. Wire them up, run a tc canary on
one interface, read the split, then write the fix the numbers ask for.

Priority, honestly: the tc datapath is a **measured dead end** on this
fleet (+70% ns/pkt, see above) and is reserved for temporary tcpdump
visibility. This matters if tc is ever reconsidered, and not before —
which is why the diagnosis ships and the datapath change waits.

## Prerequisites

- `forwarding-mode custom-fib` with a live `route-source`. The tc
  classifiers have no kernel-fib arm; the loader refuses the pairing
  otherwise.
- Kernel: `CONFIG_NET_SCH_INGRESS` + `CONFIG_NET_CLS_BPF` (verified
  `=y` on the reference EFG's 5.15.72-ui-cn9670).
- No conflicting `ingress` qdisc: `tc qdisc show dev <iface>` must not
  list `qdisc ingress ffff:` from another tool (clsact and the legacy
  ingress qdisc occupy the same handle). A plain `mq`/`fq` root — the
  EFG default — is fine; packetframe adds `clsact` itself and
  tolerates one that already exists.

## Semantics vs the XDP datapath

Identical: allowlist match, custom-FIB lookup (shared code), counters
(same indices), block-prefix (drop is `TC_ACT_SHOT`), dry-run, NDP
gate, mss-clamp, VLAN-subif egress resolution, the
mutate-only-if-forwardable invariant (via `TC_REDIRECT_TARGETS`, the
devmap-membership mirror).

Different, deliberately:

| Aspect | XDP datapath | tc datapath |
|---|---|---|
| Oversize packets | pass, kernel decides | `bpf_check_mtu` pre-check → pristine pass, kernel emits FRAG_NEEDED (parity custom-fib never had under XDP) |
| Egress path | `generic_xdp_tx` direct xmit | `dev_queue_xmit` — traverses the egress qdisc, so `fq` pacing/shaping still applies |
| tcpdump on ingress | blind (XDP runs before taps) | sees ingress traffic again |
| VLAN ingress | inline tag parse | skb metadata first, inline fallback |
| Attach persistence | bpffs-pinned bpf_link | netlink cls_bpf filter (qdisc lifetime), recorded in `<state-dir>/tc-links.json` |

## Canary rollout

0. Get a build that has the tc datapath onto the box. The
   `hardware-artifacts` workflow publishes a statically linked aarch64
   bundle (`packetframe` CLI + test binaries + this runbook) for every
   push to `main`; `docs/runbooks/generic-mode-performance.md` §"Getting
   binaries onto the router" has the `gh run download` commands. Before
   touching the attach set, run the safe test suite on the router —
   `sudo ./run-tests.sh` — which proves this kernel's verifier accepts
   the tc classifiers and that the fixtures produce the expected
   verdicts, without attaching anything to a live interface.

1. Pick the quietest attached interface. Change its attach line:

   ```
   attach eth5 tc
   ```

   Attach-set changes are **restart-only** (not SIGHUP-reloadable),
   and a plain `systemctl restart` is **not sufficient**: bpffs pins
   survive SIGTERM by design (§8.5) and v0.1 never adopts pins from a
   prior invocation, so the restarted daemon exits immediately and
   systemd crash-loops — with the old programs still forwarding but
   the FIB frozen. Verified live twice on the reference EFG. The full
   dance:

   ```sh
   systemctl stop packetframe && packetframe detach --all && systemctl start packetframe
   ```

   Expect a ~30–60 s slow-path window between detach and re-attach;
   traffic falls back to the kernel routing table, so make sure your
   routing daemon exports routes to the kernel.

2. Confirm: `packetframe status` shows `eth5 [tc-ingress]`, and
   `tc filter show dev eth5 ingress` lists a `bpf` filter running
   `tc_fast_path`.

3. Watch, comparing against the XDP interfaces:
   - `rx_total_tc` / `fwd_ok_tc`: the tc datapath's share. During a
     mixed rollout, `fwd_ok - fwd_ok_tc` is the XDP share.
   - `mpstat -P ALL 10 1` `%soft`: the actual CPU verdict.
   - `pass_not_in_devmap`, `err_tail_call`, `err_redirect_failed`,
     `err_vlan`: should stay flat at their pre-canary rates.
   - End-to-end: latency/loss through the canary interface,
     especially VLAN-tagged and near-MTU flows.

4. Expand interface by interface as the numbers hold.

## Rollback

Config revert (`attach eth5 generic`) + restart. `packetframe detach
--all` tears down tc filters from `tc-links.json` alongside the XDP
pins; if the state file is ever lost, the manual fallback is:

```sh
tc filter del dev eth5 ingress
```

(The clsact qdisc itself is harmless to leave in place.)

Records in `tc-links.json` carry the attach-time ifindex; detach uses
it to recognize a deleted-and-recreated interface (same name, new
ifindex) and skip the stale record instead of deleting whatever filter
the replacement device now holds at the recorded `(priority, handle)`.
Records written by builds that predate the field load with ifindex 0
and detach by name alone (the old behavior) — no `detach --all` is
required before upgrading, but if you want the protection on an
already-attached debugging interface, re-attach it once on the new
build so the record is rewritten with its ifindex.

Failure posture mirrors XDP: SIGTERM leaves filters attached
(§8.5 parity — the filter holds its own program reference); a circuit
breaker trip detaches everything explicitly.

## Known gaps

- Hardware validation pending for: VLAN metadata round-trip on tagged
  trunks, egress-qdisc (`fq`) lock cost under load, and real GSO
  forwarding throughput. The canary steps above are the validation.
- No netns end-to-end forwarding test yet (TEST_RUN can't execute the
  redirect); tracked as Phase T follow-up.
- Migrating from netlink cls_bpf to pinned TCX links is future work
  once the fleet baseline is ≥ 6.6.
