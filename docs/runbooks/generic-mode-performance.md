# Generic-mode (xdp-generic) CPU performance

Operational guide for deployments forced onto generic XDP (`attach <iface> generic`,
or `auto` downgraded by a driver gate such as rvu-nicpf pre-6.8) that are hitting a
CPU ceiling. Everything here is host tuning and measurement — no PacketFrame config
change forwards more packets by itself.

## Why generic mode costs so much CPU

Native XDP runs in the driver before an skb exists. Generic XDP runs *after* the
kernel has built an skb, and pays three extra per-packet costs that dominate the
profile on a busy box:

1. **Headroom reallocation.** `netif_receive_generic_xdp` requires 256 bytes of skb
   headroom (`XDP_PACKET_HEADROOM`). Most drivers reserve far less, so the kernel
   calls `pskb_expand_head` — an allocation plus a full packet copy — for **every
   packet** the XDP program sees. Community measurements attribute roughly a 2×
   packets-per-second penalty to this alone.
2. **Linearization.** If the skb is nonlinear (fragmented data, or a GRO-aggregated
   super-skb), the kernel linearizes it (another copy) before the program runs.
3. **Un-bulked redirect.** Native XDP batches redirected frames through the devmap
   flush. Generic-mode `XDP_REDIRECT` transmits one packet at a time via
   `generic_xdp_tx` → `netdev_start_xmit`.

The BPF program itself is usually the *smaller* share of per-packet CPU in generic
mode. Optimize the host first.

## Tuning checklist (ordered by expected payoff)

`packetframe feasibility --config /etc/packetframe/packetframe.conf --human` now
reports every knob below (`sysctl.net.core.bpf_jit_enable`, `iface.<if>.gro`,
`iface.<if>.rps`, `kernel.version`).

### 1. Confirm the BPF JIT is on

```sh
sysctl net.core.bpf_jit_enable   # want 1 (or 2); 0 = interpreter
sysctl net.core.bpf_jit_harden   # want 0; 1/2 add constant-blinding cost
```

Interpreted BPF costs several times more CPU per packet than JITed BPF. Kernels
built with `CONFIG_BPF_JIT_ALWAYS_ON=y` pin `bpf_jit_enable` to 1. If it's 0:

```sh
sysctl -w net.core.bpf_jit_enable=1
```

### 2. Spread the work with RPS

Since kernel 5.3, generic XDP runs **after** RPS steering — on the RPS-target CPU,
not the NIC's IRQ CPU. That means `rps_cpus` spreads the entire generic-XDP
workload (headroom copy + program + redirect) across cores. On a CPU-limited box
with all-zero RPS masks this is the highest-leverage free change available.

```sh
# Report current masks:
grep . /sys/class/net/eth*/queues/rx-*/rps_cpus

# Example: spread eth0 across CPUs 0-3 (mask f):
echo f > /sys/class/net/eth0/queues/rx-0/rps_cpus
```

Guidance:
- Set the mask to the CPUs you want doing packet work; excluding the CPU that
  services the NIC IRQ reduces contention on single-queue NICs.
- Make it persistent (systemd-tmpfiles, udev rule, or an rc script) — sysfs resets
  on reboot and on some drivers on link bounce.
- Watch `%soft` per-CPU in `mpstat -P ALL 5` before/after: the win shows up as the
  hot CPU's softirq share dropping and spreading.

### 3. Decide on GRO

GRO interacts with generic XDP two ways, and the right setting depends on traffic:

- **GRO on:** the kernel aggregates TCP segments into super-skbs *before* generic
  XDP. Every aggregated skb is nonlinear → linearized (copied) before the program
  runs. Fewer program invocations, but each one pays a big copy, and the redirect
  path then transmits the aggregate.
- **GRO off:** no linearization copies, but the program (and the per-packet 256B
  headroom copy) runs for every wire packet, and any traffic still handled by the
  kernel stack (allowlist misses, local traffic) loses GRO's benefit.

For a fast-path box where ~99% of traffic is matched+forwarded, try GRO off on the
attach interfaces and A/B the CPU numbers:

```sh
ethtool -K eth0 gro off lro off
```

Measure before committing — on TCP-heavy links the answer is workload-dependent.

### 4. Verify you're not in a diagnostic mode

- `forwarding-mode compare` runs **both** FIB lookups per packet (documented 2×
  FIB cost). It's a cutover-validation mode; don't leave it on.
- `dry-run on` still classifies and FIB-looks-up every matched packet.

## Measuring

### On-box profile (which side is burning CPU?)

```sh
perf top -e cycles:k
```

Symbols to read:

| Symbol | Meaning |
|---|---|
| `pskb_expand_head` | the generic-XDP 256B-headroom copy (cost #1 above) |
| `skb_linearize`, `__pskb_pull_tail` | GRO/nonlinear linearization (cost #2) |
| `bpf_prog_run_generic_xdp`, `bpf_prog_*` | the BPF program itself |
| `generic_xdp_tx`, `netdev_start_xmit` | generic-mode redirect transmit (cost #3) |
| `nf_hook_slow`, `__nf_conntrack_find_get` | traffic that is NOT being fast-pathed |

If `pskb_expand_head` + linearization dwarf `bpf_prog_run_generic_xdp`, host tuning
and datapath placement (not BPF micro-optimization) are where the wins are.

#### Measured profile on cn9670 / otx2 (2026-07-31)

`perf record -F 499 -a -e cycles:k` for 10s on a live EFG at ~640 kpps, 30.6%
idle. Aggregated by area, as a share of *busy* CPU:

| Area | % of busy CPU |
|---|---|
| Marvell driver (`otx2_nix_cq_op_status`, `otx2_napi_handler`, `otx2_sq_append_skb`) | 11.2 |
| **AF_PACKET tap** (`packet_rcv`, `dev_queue_xmit_nit`) | **9.1** |
| skb alloc/free churn (`__kmalloc_node_track_caller`, `kfree`, `kmem_cache_*`) | 6.9 |
| BPF map lookups (`trie_lookup_elem`, `longest_prefix_match`) | 5.9 |
| Transmit (`__dev_queue_xmit`, `skb_push`, `memmove`) | 3.4 |
| BPF programs (`fast_path`, `finalize`) | 2.6 |
| ebtables (`ebt_do_table`) | 1.6 |

**`pskb_expand_head` and `skb_linearize` do not appear at all** (below the 0.5%
cutoff). The generic-XDP headroom-copy cost that the tc-datapath work was designed
to escape is *not being paid* on this driver — otx2 evidently reserves enough
headroom that `netif_receive_generic_xdp` never reallocates. Do not assume the
generic-XDP cost model applies to your hardware without checking this first; on
this fleet it does not, and the expected tc win is correspondingly much smaller
than the 1.5–3× estimated from the model.

Two other things worth acting on before any datapath change:

- **An AF_PACKET tap costs more than the entire BPF datapath.** `packet_rcv` plus
  `dev_queue_xmit_nit` (the transmit-side hook that feeds packet sockets) is 9.1%
  of busy CPU. `dev_queue_xmit_nit` only runs when a tap exists. Find it with
  `ss --packet --processes` and stop it if it isn't needed — a leftover `tcpdump`
  or a monitoring daemon is pure overhead.
- **Inside BPF, the map lookups cost 2.3× the program bodies.** The LPM tries
  dominate: a forwarded packet does three (`ALLOW` src, `ALLOW` dst, `FIB`). Any
  further BPF optimization should target lookup *count*, not instruction count.

**`perf` is not available on UniFi OS.** There is no `perf` package; Debian
bullseye ships `linux-perf` built for its own 5.10 kernel while these boxes run a
UniFi 5.15, so `/usr/bin/perf` fails looking for `perf_5.15`. `apt install
linux-perf` then invoking `perf_5.10` directly works (minor skew is fine for cycle
sampling), but installing it on a forwarding router may not be worth it — the
split below needs nothing that isn't already present.

### Splitting program cost from kernel cost without perf

The microbenchmark gives program ns/packet directly. Total per-packet CPU comes
from `/proc/stat` and the module's own counters, so the kernel-side share is the
difference. Run on a box that is actually forwarding:

```sh
S1=$(awk '/^cpu /{print $8}' /proc/stat); R1=$(packetframe status | awk '$1=="rx_total"{print $2}'); sleep 10; S2=$(awk '/^cpu /{print $8}' /proc/stat); R2=$(packetframe status | awk '$1=="rx_total"{print $2}'); echo "rx pps: $(( (R2-R1)/10 ))"; echo "softirq ns per rx packet: $(( (S2-S1)*10000000 / (R2-R1) ))"
```

Field 8 of `/proc/stat`'s `cpu` line is softirq in USER_HZ, which is always 100 Hz,
so one tick is 10 ms — hence `10000000` ns. Subtract the measured program time
(see the reference figures below) to get the kernel-side share. Softirq covers all
softirq work on the box, not only the XDP receive path, so read it as an upper
bound.

A direct cross-check of program time under live traffic, if `bpftool` is installed
(it is not a PacketFrame dependency):

```sh
sysctl -w kernel.bpf_stats_enabled=1 && sleep 10 && bpftool prog show name fast_path; sysctl -w kernel.bpf_stats_enabled=0
```

`run_time_ns / run_cnt` is the real per-invocation cost. Enabling the stats adds
two timestamp reads per invocation (a few percent), so turn it off afterwards.

### Getting a build onto a test router

Neither the release tarballs nor the CI test runs give you what an on-hardware
session needs: releases only exist for tags, and the test suites run on x86_64
runners and in qemu. The `hardware-artifacts` workflow closes that gap. It runs on
every push to `main` and publishes a `hwtest-aarch64-unknown-linux-gnu` artifact
containing:

- `packetframe_<version>~hwtest<sha>_arm64.deb` — an installable package, same
  contents as a release .deb (binary, systemd unit, `/etc/packetframe`)
- `tests/` — the cross-built test binaries, including `bench`
- `run-tests.sh`, `example.conf`, and both perf runbooks

Everything carries the real BPF ELF — the same bytecode a release would ship, not
a stub.

Download the bundle from the newest `main` run (`gh run download` needs an
explicit run id or it prompts, hence the subshell):

```sh
gh run download -R unredacted/packetframe -n hwtest-aarch64-unknown-linux-gnu -D /tmp/hw "$(gh run list -R unredacted/packetframe -w 'Hardware test artifacts' -b main -s success --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Unpack and copy to the router (swap `router` for the target host). **Not `/tmp`** —
UniFi OS mounts it `noexec`, and since Linux `access(X_OK)` honours mount flags, a
0755 test binary there tests as non-executable and the whole suite looks absent
(`sudo …/run-tests.sh` reports "command not found" for a file that plainly exists).
`run-tests.sh` detects that case and says so, but `/root` avoids it:

```sh
tar xzf /tmp/hw/packetframe-hwtest-aarch64-unknown-linux-gnu.tar.gz -C /tmp/hw && scp -r /tmp/hw/packetframe-hwtest-aarch64-unknown-linux-gnu router:/root/
```

Install it, then run the tests from the same directory:

```sh
dpkg -i /root/packetframe-hwtest-aarch64-unknown-linux-gnu/packetframe_*_arm64.deb && systemctl daemon-reload
```

The `daemon-reload` is not optional: the package ships
`/lib/systemd/system/packetframe.service` but carries **no maintainer scripts**, so
nothing reloads systemd for you and `systemctl start packetframe` can otherwise
fail with "Unit packetframe.service not found". This is true of the release .debs
as well — `[package.metadata.deb.systemd-units]` is configured in
`crates/cli/Cargo.toml`, but the built package contains only `control`,
`conffiles` and `sha256sums`.

The package declares `Depends: libc6 (>= 2.31)`. If the target's libc6 is older,
`dpkg -i` refuses; check with `dpkg -s libc6 | grep ^Version`. That's the case the
musl variant below exists for.

The `~hwtest<sha>` version sorts below every real release and is visible in
`dpkg -l`, so a validation build can't be mistaken for one — and `apt install
packetframe` later upgrades cleanly over it. The sha is the commit the bundle was
built from, so `git show <sha>` tells you exactly what is on the box. To go back,
`dpkg -r packetframe` or install a release .deb over the top.

To take a bundle from a PR instead of `main` — the workflow also runs on PRs that
change it — pass `-b <branch>` in place of `-b main`. For a different target,
dispatch it:

```sh
gh workflow run hardware-artifacts.yml --repo unredacted/packetframe -f target=aarch64-unknown-linux-musl
```

The musl variants are statically linked and produce **no .deb** (dpkg packages
target glibc distros). They exist as an escape hatch: if a router's glibc turns
out to be older than the cross image's and the gnu binaries won't start, a static
musl build has no libc dependency to satisfy.

For a *signed, versioned* package, cut a tag — `release.yml` publishes tarballs
and .debs for all four targets with reproducible timestamps and a signed
`SHA256SUMS`. To rehearse that without publishing, dispatch it; `dry_run` defaults
to true and skips the publish job:

```sh
gh workflow run release.yml --repo unredacted/packetframe --ref main
```

### Program-only microbenchmark

`crates/modules/fast-path/tests/bench.rs` measures ns/packet for the
`fast_path → finalize` chain via `BPF_PROG_TEST_RUN` (kernel-timed, excludes all
generic-XDP skb overhead). It runs on any Linux host, but a number from a CI
runner tells you nothing about cn9670 cores — take the reference figures on the
router itself, from the bundle above:

```sh
/root/packetframe-hwtest-aarch64-unknown-linux-gnu/run-tests.sh bench
```

Confirm `net.core.bpf_jit_enable=1` first (`packetframe feasibility` reports it,
and the driver script warns) — otherwise the bench times the BPF interpreter
rather than what production runs.

#### Reference figures (cn9670)

Measured 2026-07-31 on an EFG-class box (`5.15.72-ui-cn9670`, aarch64, JIT on,
`bpf_jit_harden=0`), build `0.2.7~hwtestdd33ae7` — i.e. with the hot-path map-op
reduction and the tc datapath in place:

| Bench | ns/packet |
|---|---|
| `bench_allowlist_miss` | 85 |
| `bench_custom_fib_forward_syn` | 278 |
| `bench_custom_fib_forward_established` | 282 |

Two things to read off these:

- **~24 ns per map-helper call.** The forward path does 8 more map operations than
  the miss path plus TTL/L2 mutation and a tail call; `(282 − 85) / 8 ≈ 24 ns`
  lands inside the 20–40 ns per `bpf_map_lookup_elem` the optimization work
  assumed, so the cost model the hot-path reduction was designed against holds on
  this silicon.
- **SYN and established cost the same** (278 vs 282 ns, ~1% apart — noise). With no
  `mss-clamp` configured, the clamp lookups are gated out entirely rather than
  being paid and discarded.

**These are cache-hot, small-table numbers.** The bench populates a handful of
FIB entries, so every LPM walk hits L1. On the reference box under live load with
a full BGP-fed FIB, the same perf profile that produced the table above puts the
map lookups alone (`trie_lookup_elem` + `longest_prefix_match`) at ~1.2 µs/packet
and the program bodies at ~0.5 µs — roughly 6× the bench total, almost all of it
LPM-walk cache misses that a small table never pays. Use the bench for
before/after comparisons of code changes (both sides mis-cache equally); use
`kernel.bpf_stats_enabled` + `bpftool` (above) for the absolute live cost.

Note what these figures are *not*: no pre-reduction baseline was ever captured on
this hardware, so the 23→10 map-op change cannot be quantified from them. Scaling
the measured per-op cost suggests roughly 13 × 24 ≈ 310 ns saved, which would put
the old path near 590 ns — but that is arithmetic on one measurement, not a
before/after. Capturing a real baseline means building `bench` from `83badca` (the
commit before the reduction landed) with this workflow grafted on, and is worth
doing before quoting any improvement figure.

At 282 ns of program time, one core sustains ~3.5 Mpps of pure BPF work. On a box
that is CPU-saturated in generic mode, that is the *small* share of per-packet
cost — use `perf top` above to size the kernel-side share before concluding the
program is what needs optimizing.

`run-tests.sh` with no arguments runs the wider correctness suite, which is worth
doing on the box before a tc canary — it proves this kernel's verifier accepts the
classifiers and that the fixtures produce the expected verdicts.

That default selection is deliberately limited to tests that only use
`BPF_PROG_TEST_RUN`: programs are loaded and fed synthetic packets in-kernel,
nothing is attached to a NIC, no route/neighbour/sysctl state is touched, and
nothing is written outside the test process — so it is safe on a forwarding
router. Two groups are excluded and must be named explicitly:

- `attach`, `tc_attach`, `netns`, `local_prefix_netns`, `neigh_resolver_netns` —
  create interfaces or network namespaces.
- `fib_comparison`, `fib_programmer_integration` — pin maps into a scratch
  `/sys/fs/bpf/pftestcmp-<pid>-<n>` directory (removed on exit) and will mount
  bpffs if it isn't already mounted.

All of them clean up after themselves; they're excluded so the default run's
"writes nothing" property holds without caveats. On a box already running
packetframe, bpffs is of course already mounted and the tests leave it alone —
they check before mounting, precisely so a second bpffs can never get stacked
over the live pins.

### Counters that matter (`packetframe status`)

- `rx_total` vs `fwd_ok`: your fast-path hit rate; the difference is traffic paying
  full kernel-stack cost.
- `pass_not_in_devmap`, `err_tail_call`: should be 0; non-zero means matched
  traffic silently falling back to the slow path.
- `custom_fib_miss`: destinations the BGP feed doesn't cover (consider
  `fallback-default`).
- `nexthop_seq_retry`, `custom_fib_no_neigh`: sustained growth means nexthop churn
  or unresolved neighbors, each such packet takes the slow path.

## Platform taxes on UniFi OS

Two fixed per-packet costs on this platform are not PacketFrame's and cannot be
removed — budget for them instead of chasing them:

- **udapi-server neighbor polling.** UniFi's `udapi-server` spawns
  `arping`/`ndisc6` (via `/data/ix-neighbor-poll-wrapper/`) against **every kernel
  neighbor** on a poll cycle, each holding AF_PACKET sockets; on the reference box
  a batch of ~10 concurrent arpings plus lldpd's six per-NIC ETH_P_ALL sockets
  measured ~9% of busy CPU in `packet_rcv` + `dev_queue_xmit_nit`. This is a known,
  non-configurable platform behavior
  (<https://community.ui.com/questions/ubios-udapi-server-runs-arping-ndisc6-against-every-kernel-neighbor-and-is-not-configurable/947bbae1-1625-48f1-b275-61f75d9b313f>).
  **Do not kill the arping processes** — udapi-server respawns them, and fighting
  the platform supervisor buys nothing.
- **The cost scales with kernel neighbor count** — every neighbor is a polling
  target. That interacts with PacketFrame's own `local-prefix ... arp-scavenge`,
  which deliberately populates the neighbor table (254 probes per /24 sweep) so
  quiet hosts get fast-pathed: each host the scavenge discovers is another
  udapi polling target forever after. That trade is usually right (fast-pathing a
  host saves far more than its poll costs) but it belongs in capacity planning,
  not in a surprised `ss --packet` session at 3am.

## Bridge egress short-circuit (`bridge-resolve`)

On gateway-shaped hosts, a routed egress interface is often a Linux bridge whose
only member is a VLAN subif of a lower device (`br1337` → `switch0.1337` →
`switch0`). Nexthops learned there carry the *bridge's* ifindex, so every
forwarded packet the fast path redirects into `br1337` then traverses the
software bridge (FDB lookup, ebtables), the 8021q device (tag insert), and only
then the lower device — three `dev_queue_xmit` layers plus a per-layer AF_PACKET
tap walk, all in softirq. On a live EFG this stack was measured carrying ~53% of
forwarded traffic.

With `bridge-resolve auto` (the default), the loader collapses that chain at
attach/reconcile time: for every bridge whose **single forwarding member** is a
VLAN subif, it installs a `VLAN_RESOLVE` entry keyed on the bridge ifindex, so
the datapath pushes the 802.1Q tag itself and redirects straight to the lower
device. No BPF code changes — the same mechanism that handles plain VLAN subif
egress does the work.

Why this is safe, and when it refuses:

- The wire frame is byte-identical to what the bridge stack emits: same source
  MAC (the bridge's — on UniFi hardware all these devices share one MAC), same
  802.1Q VID, destination MAC from the resolved neighbor entry.
- A single-member bridge has no port choice to make: its FDB could only ever
  pick that member, and unknown-unicast flooding reaches exactly the same port.
- A bridge with **two or more members — even if all but one are blocked by
  STP** — never qualifies: a blocked port can transition to forwarding at any
  time, and then port selection needs the FDB, which the datapath cannot
  consult. Those bridges keep today's kernel path, automatically.
- Member port must be in bridge state *forwarding* (`brport/state == 3`).

Note what is *not* skipped: packets that egress this way bypass the bridge
layer's ebtables hooks for forwarded traffic — consistent with the fast path's
existing netfilter bypass on ingress, but worth knowing if ebtables rules
target forwarded traffic on the bridge.

Three scoping caveats, stated precisely:

- **802.1Q only.** `/proc/net/vlan/config` lists 802.1ad (QinQ) subifs
  indistinguishably from 802.1Q ones, and the datapath's VLAN push always
  writes TPID 0x8100 — this is a standing assumption of the whole
  `VLAN_RESOLVE` mechanism (plain subif entries included), not something the
  bridge feature adds. On an 802.1ad deployment set `bridge-resolve off` and
  don't rely on subif egress resolution either; protocol-aware resolution is
  a named follow-up for the subsystem.
- **`mss-clamp via <bridge>` will not match** while a short-circuit is
  installed: clamp matching keys on the resolved egress ifindex (identical
  pre-existing behavior for `via <subif>` under plain VLAN resolution). The
  loader warns at attach/reconcile with the fix: scope the clamp `via` the
  underlying device, or set `bridge-resolve off`.
- **MTU relation is enforced:** a bridge whose MTU is smaller than its
  underlying device's is skipped (the bridge would have refused packets the
  short-circuit would forward). Equal MTUs — the normal case — qualify.
- **Egress qdiscs on the bridge or subif are bypassed** — collapsed traffic
  traverses only the underlying device's qdisc. This is the standing semantic
  of `VLAN_RESOLVE` (plain subif entries have always redirected to the parent,
  skipping the subif's own qdisc); shape or police on the underlying device,
  or set `bridge-resolve off` for bridges carrying their own qdisc policy.
  (These virtual devices are `noqueue` by default; a configured qdisc on one
  is an operator choice this feature cannot see from procfs/sysfs.)
- **Unicast flooding must be on** (`brport/unicast_flood == 1`, the kernel
  default): with it off, a destination MAC absent from the FDB is dropped by
  the bridge rather than emitted through the sole port, so "single member" no
  longer predicts the bridge's decision. Discovery refuses such ports.

**Convergence model — same as every discovery-populated map.** Chains are
discovered at attach and re-verified on every `packetframe reconfigure`
(SIGHUP); there is no live topology watcher, exactly as with plain VLAN-subif
entries and redirect-target membership. If you change bridge membership (enslave
a second port, move the subif) or flip `vlan_filtering` on a bridge that has a
short-circuit installed, run `packetframe reconfigure` afterwards — until then
the datapath keeps using the previously proven chain. Bridges with
`vlan_filtering=1` never qualify at all (the per-port VLAN table can drop or
retag in ways a static entry can't reproduce).

Rollback is SIGHUP-cheap, no restart and no traffic blip:

```text
bridge-resolve off
```

then `packetframe reconfigure`. The bridge keys are purged from `VLAN_RESOLVE`
on the spot; plain VLAN subif entries are untouched.

What to watch after enabling (canary):

- `/proc/net/dev`: the bridge and subif tx packet counters should collapse to
  ~0 for fast-pathed traffic while the lower device's tx holds steady.
- `mpstat -P ALL 10` `%soft`: the win.
- `packetframe status`: `pass_not_in_devmap` must stay flat (the lower device
  is enumerated into the redirect maps the same way as everything else).
- Attach/reconcile logs: one `bridge egress short-circuit installed` line per
  collapsed chain says discovery proved the shape; absence means the topology
  didn't qualify and nothing changed. (The SIGHUP path logs `VLAN_RESOLVE
  added` per alias instead — count those against your bridge list.)

**Measured result (2026-08-01, reference EFG):** with the short-circuit active,
br1337's tx collapsed 318,491 → 4,382 pps (−98.6%; the residual is
host-originated traffic), switch0 carried the flow directly, and
`pass_not_in_devmap` stayed pinned at 0. Combined with `fib-cache on` and the
v0.2.8 hot-path reductions, box-level softirq fell 15,433 → 11,306 ns/packet
(−26.7%) while throughput rose 640k → 766k pps — stated honestly as the
whole-campaign delta against the pre-v0.2.8 release binary, including diurnal
mix shift; per-feature attribution needs a brief `fib-cache off` window.

## FIB destination cache (`fib-cache`, experiment)

Live profiling showed the custom-FIB LPM walks are the dominant *BPF-side* cost
(~1.2 µs/packet of `trie_lookup_elem` + `longest_prefix_match` on a full table —
the walks miss cache on a 2M-entry trie). `fib-cache on` puts a direct-mapped
per-CPU cache in front of `FIB_V4`/`FIB_V6`: repeat destinations become one array
probe instead of an LPM walk.

What it caches, and why the design is safe:

- **The FIB decision (`FibValue`), never the resolved neighbor.** The per-packet
  seqlock read and the ECMP 5-tuple hash run identically on hits, so neighbor
  MAC/state churn needs no invalidation, and per-flow ECMP placement is preserved.
- **Any route change invalidates the whole cache** via a generation counter the
  FibProgrammer bumps on every LPM insert/remove. The cache refills at line rate;
  under sustained BGP churn it is effectively always cold — `fib_cache_stale`
  measures exactly that.
- **No negative caching**: unroutable destinations are never cached.
- Direct-mapped, fixed memory (~37 MB total across 18 CPUs), no eviction
  machinery: under adversarial destination spray it degrades to baseline cost
  plus two array probes — not the eviction thrash that killed the Linux route
  cache in kernel 3.6, which is why this ships as an experiment anyway.

This is an experiment with a kill criterion, not a recommendation. Canary on one
box (`fib-cache on` + `packetframe reconfigure`, no restart), run ≥24 h across
normal BGP churn, then compute:

```text
hit_rate = fib_cache_hit / (fib_cache_hit + fib_cache_miss + fib_cache_stale)
```

- **≥ 70%** and the LPM share of CPU visibly down → keep it on.
- **30–70%** → marginal; keep only if the CPU delta justifies ~37 MB.
- **< 30%**, or `fib_cache_stale` > ~20% of probes sustained → your destination
  diversity or route churn defeats this cache design; turn it off and leave it
  off. The counters stay (append-only) as a record.

**Preliminary result (2026-08-01, reference EFG, full BGP table, ~770 kpps) —
NOT yet a KEEP verdict.** A steady-state 60 s delta taken ~2 h after enabling
showed **hit 91.2% / miss 2.3% / stale 6.5%** at 772k probes/s. That clears the
≥70% hit-rate leg of the criterion on a short window, and it is early evidence
that the route-cache-thrash fear does not materialize on real internet-edge
traffic — but **both remaining legs are outstanding**, so the cache is on
provisionally, not proven:

- *Sustained churn (≥24 h):* one hour-scale window does not cover a full
  diurnal cycle of BGP churn. Re-run the delta below at several points across a
  day; `fib_cache_stale` is the number that moves if churn is the problem.
- *LPM CPU share visibly down:* not demonstrated. The −26.7% softirq/packet
  above is a whole-campaign figure that also contains the bridge short-circuit,
  the v0.2.8 hot-path reductions, and traffic-mix drift. Isolating the cache
  needs a brief `fib-cache off` window (SIGHUP, no restart) with `perf` before
  and after, comparing the `trie_lookup_elem` + `longest_prefix_match` share.

Until both are recorded here, treat ~37 MB of per-CPU memory as an unproven
cost. If either leg fails, `fib-cache off` is the answer and this section should
say so. Two measurement traps hit live,
recorded so nobody repeats them: snapshots taken during a table (re)load are
meaningless (initial convergence bumps the generation per route write; 51%
stale was observed mid-load), and the cumulative counters embed that window
forever — always judge with a delta over a steady-state interval:

```sh
A=$(packetframe status | awk '/fib_cache_hit/{h=$2}/fib_cache_miss/{m=$2}/fib_cache_stale/{s=$2}END{print h,m,s}'); sleep 60; B=$(packetframe status | awk '/fib_cache_hit/{h=$2}/fib_cache_miss/{m=$2}/fib_cache_stale/{s=$2}END{print h,m,s}'); echo $A $B | awk '{dh=$4-$1; dm=$5-$2; ds=$6-$3; t=dh+dm+ds; printf "cache (last 60s): hit %.1f%%  miss %.1f%%  stale %.1f%%\n", 100*dh/t, 100*dm/t, 100*ds/t}'
```

`fib-cache off` + reconfigure disables it immediately (the BPF probe stops on the
next packet); re-enabling never resurrects pre-disable entries (the generation
advances on every toggle).
