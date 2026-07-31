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

Unpack and copy to the router (swap `router` for the target host):

```sh
tar xzf /tmp/hw/packetframe-hwtest-aarch64-unknown-linux-gnu.tar.gz -C /tmp/hw && scp -r /tmp/hw/packetframe-hwtest-aarch64-unknown-linux-gnu router:/tmp/
```

Install it, then run the tests from the same directory:

```sh
dpkg -i /tmp/packetframe-hwtest-aarch64-unknown-linux-gnu/packetframe_*_arm64.deb && systemctl daemon-reload
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
sudo /tmp/packetframe-hwtest-aarch64-unknown-linux-musl/run-tests.sh bench
```

Confirm `net.core.bpf_jit_enable=1` first (`packetframe feasibility` reports it,
and the driver script warns) — otherwise the bench times the BPF interpreter
rather than what production runs.

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
