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

   Attach-set changes are **restart-only** (not SIGHUP-reloadable):
   `systemctl restart packetframe`.

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
