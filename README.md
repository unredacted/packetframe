# PacketFrame

PacketFrame is a modular eBPF data-plane framework written in pure Rust.
It provides a pluggable runtime for discrete datapath modules —
fast-path forwarding, egress randomization, DDoS mitigation, flow
sampling — that can be loaded, attached to network interfaces,
observed, and detached independently.

The MVP module, and the reason the project exists, is `fast-path`:
it takes forwarded packets for allowlisted prefixes off the kernel's
conntrack/netfilter hot path by intercepting them at XDP ingress and
redirecting via `bpf_fib_lookup` + `bpf_redirect_map`. The design
spec lives alongside the project internally; inline code comments
cite section numbers (e.g. `§4.2`) as breadcrumbs.

## Status

v0.1 ships the full fast-path module and a general-purpose `probe`
diagnostic:

- **XDP ingress + allowlist match** per interface, IPv4 and IPv6,
  with LPM-trie prefix lookups.
- **VLAN ingress parse + egress push / pop / rewrite** for VLAN-tagged
  forwarding topologies.
- **`bpf_fib_lookup` + `bpf_redirect_map`** for forwarding decisions.
  The kernel stack is only consulted for packets the fast path
  deliberately passes.
- **bpffs pinning** of programs, maps, and links. SIGTERM exits the
  loader without detaching attached ifaces; `packetframe detach` is
  the explicit teardown.
- **Live counter readback** via the pinned STATS map —
  `packetframe status` works whether or not the loader is running.
- **Prometheus textfile export** at 15 s cadence (atomic
  write-then-rename), one counter per stat plus a
  `packetframe_uptime_seconds` gauge.
- **SIGHUP reconcile** — delta-only updates to allowlists, VLAN-resolve
  map, and redirect devmap. A parse error on SIGHUP never kills the
  running data plane.
- **Circuit breaker** — sampled error/match ratio, sticky trip flag
  in `state-dir`, SIGUSR1-driven detach on trip. Restart refuses to
  re-attach while the flag is present.
- **Feasibility probes** for kernel capabilities and per-interface
  trial attach.
- **`packetframe probe`** — attach a diagnostic-only XDP program to a
  chosen iface for a fixed duration, dump the first 16 bytes of a
  sample of packets, then detach. Useful for answering "what does
  this driver hand to XDP?" without patching BPF.
- **Driver-quirk workarounds** with a `driver-workaround` config
  directive for per-driver opt-ins when a NIC's XDP path deviates
  from the kernel's documented contract.

The reference workflow is: validate the host with
`packetframe feasibility`, attach in `dry-run on` to watch counters
without redirecting, flip to `dry-run off` once the match / drop ratios
look sane.

## Install

From a GitHub Release tarball:

```sh
VERSION=v0.1.5   # check the Releases page for the latest
TARGET=aarch64-unknown-linux-gnu   # also: x86_64-unknown-linux-{gnu,musl}, aarch64-unknown-linux-musl
curl -LO "https://github.com/unredacted/packetframe/releases/download/${VERSION}/packetframe-${VERSION}-${TARGET}.tar.gz"
curl -LO "https://github.com/unredacted/packetframe/releases/download/${VERSION}/SHA256SUMS"
curl -LO "https://github.com/unredacted/packetframe/releases/download/${VERSION}/SHA256SUMS.asc"   # optional

gpg --verify SHA256SUMS.asc SHA256SUMS   # optional; GPG key ID in the release notes
sha256sum -c SHA256SUMS --ignore-missing
tar xzf "packetframe-${VERSION}-${TARGET}.tar.gz"

sudo install -m 0755 "packetframe-${VERSION}-${TARGET}/packetframe" /usr/local/bin/
sudo install -m 0644 -D "packetframe-${VERSION}-${TARGET}/conf/example.conf" /etc/packetframe/example.conf
```

The shipped binaries embed the compiled BPF object; no separate
`libbpf`, `bpftool`, or nightly toolchain is required at runtime.

## Quickstart

Probe the host kernel first:

```sh
sudo packetframe feasibility --human
```

Write a minimal config at `/etc/packetframe/packetframe.conf` (start
with a single low-risk iface + `dry-run on`):

```
global
  bpffs-root /sys/fs/bpf/packetframe
  state-dir /var/lib/packetframe/state
  metrics-textfile /var/lib/node_exporter/textfile/packetframe.prom

module fast-path
  attach eth0 auto
  allow-prefix 192.0.2.0/24
  allow-prefix6 2001:db8::/48
  dry-run on
  circuit-breaker drop-ratio 0.01 of matched window 5s threshold 5
```

Re-run feasibility against the config — this also runs the
per-interface trial attach probe:

```sh
sudo packetframe feasibility --config /etc/packetframe/packetframe.conf --human
```

Run the data plane in the foreground. `--config` defaults to
`/etc/packetframe/packetframe.conf`, so the flag can be omitted on a
standard deploy:

```sh
sudo packetframe run
```

In another shell, inspect live counters:

```sh
sudo packetframe status
```

Tear down — removes bpffs pins and detaches attached ifaces:

```sh
sudo packetframe detach --all
```

## Attach modes

Each `attach <iface> <mode>` directive picks how the XDP program is
bound to the interface:

- `native` — driver-XDP. Lowest overhead. Requires the NIC driver to
  implement XDP natively and to deliver packets to the program with
  the standard Ethernet frame layout.
- `generic` — SKB-XDP. Runs after the kernel allocates an skb, so the
  kernel normalizes the frame before the program sees it. Higher
  per-packet overhead but works on every driver that supports XDP at
  all.
- `auto` — try native first, fall back to generic on attach failure.
  `auto` may also be downgraded at preprocessing on drivers known to
  have native-mode bugs on the running kernel (see below).

### Known driver / kernel interactions

PacketFrame refuses attach configurations it has empirical evidence
are unsafe. Currently tracked:

- **Marvell `rvu-nicpf` (OcteonTX2 / CN10K) on kernels older than
  Linux v6.8**: native XDP attach leaks `non_qos_queues` count on
  every program detach (kernel bug; fixed upstream in commit
  `04f647c8e456`). Over a handful of attach/detach cycles the
  driver's resource bookkeeping drifts and a subsequent page allocation
  corrupts the kernel's freelist. v0.1.5+ hard-refuses explicit
  `attach <iface> native` on this combination and downgrades
  `auto` to `generic`. Operators who have backported the upstream fix
  can opt out via `driver-workaround rvu-nicpf-head-shift off`.

### Diagnosing driver-specific issues

If `packetframe status` shows `rx_total` incrementing in lockstep
with `pass_not_ip` while the `matched_*` counters stay at zero, the
program is running but not parsing the frames it receives — typically
a driver-specific native-mode delivery quirk. Use `packetframe probe`
to inspect what the driver actually hands to XDP:

```sh
# Sample the first 16 bytes at data + 0 on a native-mode attach:
sudo packetframe probe --iface eth0 --mode native --duration 2s

# Sample at a larger offset if data + 0 appears to be headroom zeros:
sudo packetframe probe --iface eth0 --mode native --duration 2s --offset 128

# Compare to the skb-normalized view (what the kernel would see):
sudo packetframe probe --iface eth0 --mode generic --duration 2s
```

The output dumps the raw bytes plus a one-line heuristic verdict
("head bytes look like standard Ethernet" vs. "head bytes DO NOT look
like Ethernet").

## Configuration

`conf/example.conf` ships as the reference. Grammar summary:

- `global` and `module fast-path` blocks.
- `attach <iface> <mode>`, where `mode` is `native` / `generic` /
  `auto`.
- `allow-prefix` / `allow-prefix6` for IPv4 and IPv6 prefixes (LPM,
  src-or-dst match).
- `dry-run on|off` gates actual redirects; when on, the program still
  counts matched packets but returns `XDP_PASS`.
- `circuit-breaker drop-ratio X of matched window Ys threshold N` —
  optional safety valve.
- `metrics-textfile <path>` — Prometheus textfile target, atomically
  rewritten every 15 seconds.
- `attach-settle-time <dur>` (global) — sleep between per-iface
  attaches so each link settles before the next touches the driver.
  Default 2s; raise on bridged topologies whose STP takes longer to
  reconverge.
- `driver-workaround <name> <auto|on|off>` — per-driver opt-ins for
  known kernel-level quirks. See the *Known driver / kernel
  interactions* section above for the catalog.

SIGHUP re-reads the config and applies delta-only changes to
allowlists and VLAN-resolve state without detaching. Attach-set
changes (adding or removing an iface) require a restart.

## Build from source

```sh
make build        # host target, debug
make release      # host target, release
make release-all  # every published target (requires `cross`)

make test         # workspace tests
make lint         # fmt --check + clippy -D warnings
make fmt          # apply rustfmt
```

Dependencies: a stable Rust toolchain (pinned in
`rust-toolchain.toml`). The BPF crates live under
`crates/modules/*/bpf/` and each has its own pinned nightly toolchain
+ `bpf-linker`; CI installs those automatically. Cross-compiling to
every release target uses [`cross`](https://github.com/cross-rs/cross);
install it with `cargo install --locked cross`.

## Project layout

```
packetframe/
├── crates/
│   ├── common/                       # config, Module trait, §2.1 probes
│   ├── cli/                          # the `packetframe` binary
│   └── modules/
│       ├── fast-path/                # fast-path forwarding module
│       │   └── bpf/                  # XDP fast-path BPF program (nightly toolchain)
│       └── probe/                    # diagnostic probe module
│           └── bpf/                  # probe BPF program (nightly toolchain)
├── conf/
│   └── example.conf                  # reference config
└── .github/workflows/
    ├── ci.yml                        # fmt, clippy, test, cross-build
    ├── qemu-verifier.yml             # integration tests on 5.15 + 6.6 kernels
    └── release.yml                   # tag-triggered GitHub Release
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
