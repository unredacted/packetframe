# PacketFrame

**eBPF/XDP fast-path for Linux packet forwarding.** Pure Rust, pluggable, attaches per-interface. Forwards allowlisted traffic directly between NICs at the driver level — bypassing iptables, conntrack, and the kernel routing stack — and falls back to normal kernel forwarding for everything else.

Production-deployed on a UniFi Enterprise Fortress Gateway carrying 1-2 Gbps of customer traffic across a 1.27M-route full-table BGP feed. **~98% of allowlisted flows fast-path**, conntrack table reduced ~85%, customer ping latency cut in half.

GPL-3.0-or-later. Linux ≥ 5.15. Single static binary; no separate libbpf, bpftool, or runtime nightly toolchain.

## What it does

For each interface you attach it to, PacketFrame runs an eBPF program at XDP ingress that:

1. **Filters** by your declared `allow-prefix` / `allow-prefix6` lists. Non-matching packets fall through to the kernel unchanged.
2. **Forwards** matched packets directly to the egress NIC via `bpf_redirect_map` — no `nf_hook_slow`, no conntrack, no iptables walk, no kernel skb allocation in native XDP mode.
3. **Resolves the egress** via either the kernel FIB (`bpf_fib_lookup`) or PacketFrame's own LPM trie populated from a BGP feed (your choice via `forwarding-mode`).

Optional layered features:

- **VLAN push/pop/rewrite** for tagged forwarding
- **Custom-FIB mode**: ingest BGP routes directly via iBGP (production today, with `bird`) or BMP (RFC 7854/9069). No netlink dependency, no race with other daemons subscribed to kernel routes.
- **Per-host fast-path for connected destinations** via `local-prefix` directives + ARP scavenging
- **XDP-time bogon block** (`block-prefix`) for dropping traffic to unrouteable destinations before kernel processing
- **Default-route synthesis** in custom-FIB mode (`fallback-default`) for catching destinations the BGP feed doesn't cover

## Benefits

| Concern | Stock kernel forwarding | PacketFrame fast-path |
|---|---|---|
| Per-packet conntrack lookup | yes — every packet | bypassed for allowlisted flows |
| iptables FORWARD chain walk | yes — every packet, every rule | bypassed |
| skb allocation cost (native XDP) | yes | bypassed |
| BGP route source | netlink from a routing daemon | direct iBGP/BMP, no netlink coupling |
| Kernel features still work | yes | yes (slow path is unchanged) |
| Fallback path | n/a | always: non-matching traffic uses kernel |

Measured on the reference deployment after enabling custom-FIB:

| Metric | Before (kernel-fib) | After (custom-fib + fast-path) |
|---|---|---|
| Bypass rate | n/a | ~98% |
| Active conntrack entries | 1.15M | 168K |
| `%soft` per CPU | 51% | 33% |
| `%idle` per CPU | 31% | 51% |
| Customer ping (avg) | 1.65 ms | 0.71 ms |
| Customer ping (p99 tail) | 61 ms | 27.5 ms |
| udapi parse errors / 24h | nonzero | zero |

Numbers are workload-specific and from a Tor-exit-relay edge serving ~1-2 Gbps. Your traffic mix will differ.

## How it compares

| | PacketFrame | DPDK / VPP | FRR / pure routing daemon | Plain kernel + iptables |
|---|---|---|---|---|
| Bypasses kernel | partially (XDP) | fully (userspace) | no | no |
| Dedicated cores required | no | yes | no | no |
| Kernel features still work | yes | no — replaces stack | yes | yes |
| Has its own BGP daemon | no — pairs with bird | typically not | yes | n/a |
| Memory model | kernel-managed BPF maps | hugepages | kernel | kernel |
| Deploy disruption | per-iface attach, opt-in | replaces network stack | runs alongside | default |

PacketFrame complements existing routing daemons rather than replacing them. The intended pairing is `bird` (BGP) + `pathvector` (config generator) + PacketFrame (fast-path). FRR works similarly via its BMP support.

## Status

| Component | State |
|---|---|
| `fast-path` module — XDP ingress, allowlist, redirect | Production |
| `kernel-fib` forwarding mode (default) | Production |
| `custom-fib` forwarding mode (BGP-fed LPM) | Production (v0.2.0+) |
| iBGP route source (`route-source bgp`) | Production (v0.2.0+) |
| BMP station route source (`route-source bmp`) | Ready, untested in production (no current emitter) |
| Connected-destination fast-path (`local-prefix`) | Production (v0.2.1+) |
| `fallback-default` synthesis | Production (v0.2.1+) |
| `block-prefix` XDP-time drop | Production (v0.2.1+) |
| `probe` module — diagnostic XDP | Production |
| `randomizer` / `ddos` / `sampler` modules | Future — sketched in SPEC, not implemented |

## Install

From a [GitHub release](https://github.com/unredacted/packetframe/releases):

```sh
VERSION=v0.2.2
TARGET=aarch64-unknown-linux-gnu     # or: x86_64-unknown-linux-{gnu,musl}, aarch64-unknown-linux-musl

curl -LO "https://github.com/unredacted/packetframe/releases/download/${VERSION}/packetframe-${VERSION}-${TARGET}.tar.gz"
curl -LO "https://github.com/unredacted/packetframe/releases/download/${VERSION}/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
tar xzf "packetframe-${VERSION}-${TARGET}.tar.gz"

sudo install -m 0755 "packetframe-${VERSION}-${TARGET}/packetframe" /usr/local/bin/
sudo install -m 0644 -D "packetframe-${VERSION}-${TARGET}/conf/example.conf" /etc/packetframe/example.conf
```

Optional GPG verification: download `SHA256SUMS.asc` and `gpg --verify SHA256SUMS.asc SHA256SUMS` (key ID in release notes).

## Quickstart

The reference workflow is **probe → dry-run → live**. It deliberately makes you watch counters before flipping anything that affects production traffic.

### 1. Verify the host

```sh
sudo packetframe feasibility --human
```

Reports kernel capabilities (BPF syscalls, LPM trie, devmap-hash, ringbuf, etc.) and whether bpffs is mounted. Anything `FAIL` is a kernel/host prerequisite to fix before continuing.

### 2. Write a minimal config

`/etc/packetframe/packetframe.conf`:

```
global
  bpffs-root /sys/fs/bpf/packetframe
  state-dir /var/lib/packetframe/state
  metrics-textfile /var/lib/node_exporter/textfile/packetframe.prom

module fast-path
  attach eth0 auto
  allow-prefix 192.0.2.0/24       # your customer / forwarding scope
  allow-prefix6 2001:db8::/48
  dry-run on                       # observe-only — no redirects yet
  circuit-breaker drop-ratio 0.01 of matched window 5s threshold 5
```

`dry-run on` makes the program count matched packets but always return `XDP_PASS` — the kernel handles forwarding as if PacketFrame weren't there. Counters tell you whether your allowlist matches the right traffic before you flip the switch.

### 3. Validate against the host

```sh
sudo packetframe feasibility --config /etc/packetframe/packetframe.conf --human
```

Now also runs a per-interface trial XDP attach to catch driver compatibility issues before live deploy.

### 4. Run

```sh
sudo packetframe run                 # foreground; --config defaults to /etc/...
sudo packetframe status              # in another shell — live counters
```

### 5. Flip dry-run off when match ratios look right

Edit the config, change `dry-run on` to `dry-run off`, then `sudo systemctl reload packetframe` (if running under systemd) or `kill -HUP <pid>` (foreground). The change is delta-only; no detach.

### 6. Tear down

```sh
sudo packetframe detach --all        # removes pins, detaches XDP
```

## Forwarding modes

`forwarding-mode` selects how PacketFrame resolves the egress for a matched packet:

- **`kernel-fib`** (default) — uses `bpf_fib_lookup()` against the kernel's routing table. Same routing decisions as plain Linux. The permanent rollback path.
- **`custom-fib`** — uses PacketFrame's own LPM trie, populated from a BGP feed. Lets routing daemons that consume the kernel route table (UniFi `udapi-server`, etc.) work in parallel without racing on BGP attribute updates.
- **`compare`** — runs both lookups, forwards via the kernel result, bumps a disagreement counter. Pre-cutover validation only.

Custom-fib mode requires a `route-source` directive:

```
route-source bgp 127.0.0.1:1179 local-as 401401 peer-as 401401
```

Bird connects out to PacketFrame as an iBGP peer on this address. Bird's `protocol bgp` export filter runs *after* best-path selection, so PacketFrame receives one UPDATE per prefix.

For BMP emitters that ship RFC 9069 Loc-RIB (FRR; future bird):

```
route-source bmp 127.0.0.1:6543 require-loc-rib
```

`require-loc-rib` rejects pre/post-policy frames at session-init so misconfigured emitters fail loudly rather than silently driving forwarding off the wrong RIB view.

See [`docs/runbooks/custom-fib.md`](docs/runbooks/custom-fib.md) for the full operational guide: cutover sequence, rollback, integrity checking, troubleshooting.

## Attach modes

Each `attach <iface> <mode>` directive picks how XDP binds to the interface:

| Mode | Cost | Use when |
|---|---|---|
| `native` | Lowest — runs in NIC driver before skb alloc | Driver supports native XDP and delivers Ethernet-shaped frames |
| `generic` | Higher — runs after skb alloc | Driver doesn't support native XDP, or has known native-mode bugs |
| `auto` | tries native, falls back to generic | Most cases; downgraded automatically on drivers with known bugs |

### Driver caveats

PacketFrame refuses configurations it has empirical evidence are unsafe:

**Marvell `rvu-nicpf` on kernels < v6.8** — native XDP attach leaks a kernel resource counter (`non_qos_queues`) on every detach. After a handful of attach/detach cycles the kernel page allocator can corrupt. PacketFrame hard-refuses explicit `attach <iface> native` here and downgrades `auto` to `generic`. Fixed upstream in commit `04f647c8e456`; operators with the backport can opt out via `driver-workaround rvu-nicpf-head-shift off`.

**Marvell `rvu-nicpf` on multi-member bridges** — XDP attach AND detach briefly bounce the link, which the bridge stack treats as a port-state change. Two ports flapping inside one STP/RSTP window has caused L2 loops and kernel panics. PacketFrame paces both attach and detach via `attach-settle-time` (default 2 s, raise on slow-converging bridges) when ≥ 2 attached ifaces share a `/sys/class/net/<iface>/master`.

### Diagnosing driver-specific issues

If `packetframe status` shows `rx_total` climbing in lockstep with `pass_not_ip` while `matched_*` stays at zero, the program is running but not parsing frames it receives — usually a driver-specific native-mode delivery quirk. Use `packetframe probe` to inspect what the driver actually hands to XDP:

```sh
sudo packetframe probe --iface eth0 --mode native --duration 2s
sudo packetframe probe --iface eth0 --mode native --duration 2s --offset 128
sudo packetframe probe --iface eth0 --mode generic --duration 2s   # what kernel sees
```

Output dumps the first 16 bytes of a packet sample plus a one-line verdict.

## Configuration reference

`conf/example.conf` ships with the binary as the canonical reference, with every directive commented and explained inline. Read that for the full grammar.

Quick directive index:

**Global**
- `bpffs-root`, `state-dir`, `metrics-textfile`, `log-level`, `attach-settle-time`

**Module fast-path — attach + allowlist**
- `attach <iface> {native|generic|auto}`
- `allow-prefix <ipv4-cidr>`, `allow-prefix6 <ipv6-cidr>` — src-or-dst match
- `dry-run {on|off}`
- `circuit-breaker drop-ratio X of matched window Ys threshold N`

**Module fast-path — forwarding mode**
- `forwarding-mode {kernel-fib|custom-fib|compare}`
- `route-source bgp <addr>:<port> local-as <asn> peer-as <asn> [router-id <ipv4>]`
- `route-source bmp <addr>:<port> [require-loc-rib]`
- `local-prefix <cidr> via <iface> [arp-scavenge]` — per-host fast-path for connected destinations
- `fallback-default via <iface> nexthop <ipv4>` — synthetic 0.0.0.0/0 catch-all
- `block-prefix <cidr>` — XDP-time drop for unrouteable destinations
- `ecmp-default-hash-mode {3|4|5}` — tuple width for ECMP hashing

**Module fast-path — driver opt-ins**
- `driver-workaround rvu-nicpf-head-shift {auto|on|off}`

`SIGHUP` reloads the config and applies delta-only changes to allowlists, VLAN-resolve, and devmap. Adding or removing an `attach` directive requires a restart.

## Operator tools

```sh
sudo packetframe status                # live counters from pinned STATS map
sudo packetframe fib stats             # custom-FIB occupancy / hash mode
sudo packetframe fib lookup <ip>       # "what would XDP do for this dst?"
sudo packetframe fib dump-v4           # walk FIB_V4 LPM trie
sudo packetframe detach --all          # remove all pins, detach XDP
```

Counters export as Prometheus textfile every 15 s when `metrics-textfile` is set. Metrics include per-counter gauges, custom-FIB occupancy by nexthop state, and the active forwarding mode.

## Documentation

- [`conf/example.conf`](conf/example.conf) — annotated reference config
- [`docs/runbooks/custom-fib.md`](docs/runbooks/custom-fib.md) — operational runbook for custom-FIB mode (cutover, rollback, integrity checks, triage by symptom)

## Build from source

```sh
make build        # debug, host target
make release      # release, host target
make release-all  # all four published targets (requires `cross`)

make test         # workspace tests
make lint         # cargo fmt --check + cargo clippy -D warnings
```

Toolchain: stable Rust pinned in `rust-toolchain.toml`. The BPF crates (`crates/modules/*/bpf/`) each have their own pinned nightly toolchain + `bpf-linker`, installed automatically by CI; for local BPF rebuilds, install `rustup` and let it follow the toolchain files.

Cross-compiling to release targets uses [`cross`](https://github.com/cross-rs/cross): `cargo install --locked cross`.

## Project layout

```
packetframe/
├── crates/
│   ├── common/                       # config parser, Module trait, capability probes
│   ├── cli/                          # the `packetframe` binary
│   └── modules/
│       ├── fast-path/                # main forwarding module
│       │   └── bpf/                  # XDP program (nightly toolchain)
│       └── probe/                    # diagnostic XDP probe
│           └── bpf/                  # probe BPF program
├── conf/example.conf                 # annotated reference config
├── docs/runbooks/                    # operational runbooks
└── .github/workflows/                # CI (fmt/clippy/test, cross-build, qemu-verifier, release)
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
