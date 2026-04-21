# PacketFrame

PacketFrame is a modular eBPF data-plane framework written in pure Rust. It
provides a pluggable runtime for discrete datapath modules (fast-path
forwarding, egress randomization, DDoS mitigation, flow sampling) that can be
loaded, attached to network interfaces, observed, and detached independently.

The MVP module — and the reason the project exists — is `fast-path`, which
takes forwarded packets for allowlisted prefixes off the kernel's
conntrack/netfilter hot path by intercepting them at XDP ingress and
redirecting them via `bpf_fib_lookup` + `bpf_redirect_map`. The design
spec lives alongside the project internally; inline code comments cite
section numbers (e.g. "SPEC.md §4.2") as breadcrumbs.

## Status

v0.1 ships the full fast-path module:

- **XDP ingress + allowlist match** per interface, IPv4 and IPv6, with
  LPM-trie prefix lookups.
- **VLAN ingress parse + egress push/pop/rewrite** for VLAN-tagged
  forwarding.
- **`bpf_fib_lookup` + `bpf_redirect_map`** for forwarding decisions; the
  kernel stack is only consulted for packets that the fast-path
  deliberately passes.
- **bpffs pinning** of programs, maps, and links — SIGTERM exits the
  loader without detaching attached ifaces; `packetframe detach` is the
  explicit teardown.
- **Live counter readback** via the pinned STATS map — `packetframe
  status` works whether or not the loader is running.
- **Prometheus textfile export** at 15s cadence (atomic write-then-rename)
  with one counter per §4.6 stat plus a `packetframe_uptime_seconds`
  gauge.
- **SIGHUP reconcile** — delta-only updates to allowlists, VLAN resolve
  map, and redirect devmap. A parse error on SIGHUP never kills the
  running data plane.
- **Circuit breaker** — sampled error/match ratio, sticky trip flag in
  `state-dir`, SIGUSR1-driven detach on trip. Restart refuses to
  re-attach while the flag is present.
- **Feasibility probes** for kernel capabilities (`§2.1`) and per-interface
  trial attach (`§2.3`).

The reference workflow is: validate the host with `packetframe
feasibility`, attach in `dry-run on` to observe counters without
redirecting, flip to `dry-run off` once the match/drop ratios look
sane.

## Install

From a GitHub Release tarball:

```sh
VERSION=v0.1.0
TARGET=aarch64-unknown-linux-gnu   # also: x86_64-unknown-linux-{gnu,musl}, aarch64-unknown-linux-musl
curl -LO "https://github.com/unredacted/packetframe/releases/download/${VERSION}/packetframe-${VERSION}-${TARGET}.tar.gz"
curl -LO "https://github.com/unredacted/packetframe/releases/download/${VERSION}/SHA256SUMS"
curl -LO "https://github.com/unredacted/packetframe/releases/download/${VERSION}/SHA256SUMS.asc"

# (optional) verify the signature — GPG key ID in the release notes
gpg --verify SHA256SUMS.asc SHA256SUMS

sha256sum -c SHA256SUMS --ignore-missing
tar xzf "packetframe-${VERSION}-${TARGET}.tar.gz"

sudo install -m 0755 "packetframe-${VERSION}-${TARGET}/packetframe" /usr/local/bin/
sudo install -m 0644 -D "packetframe-${VERSION}-${TARGET}/conf/example.conf" /etc/packetframe/example.conf
```

The shipped binaries embed the compiled BPF object; no separate
`libbpf` or nightly toolchain is required at runtime.

## Quickstart

Probe the host kernel first:

```sh
sudo packetframe feasibility --human
```

Write a minimal config (start with a single low-risk iface + `dry-run
on`):

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

Run the data plane in the foreground:

```sh
sudo packetframe run --config /etc/packetframe/packetframe.conf
```

In another shell, inspect live counters via the pinned STATS map
(works with or without an active loader):

```sh
packetframe status --config /etc/packetframe/packetframe.conf
```

Tear down — removes bpffs pins and detaches attached ifaces:

```sh
sudo packetframe detach --config /etc/packetframe/packetframe.conf
```

## Attach modes

Each `attach <iface> <mode>` directive picks how the XDP program is
bound to the interface:

- `native` — driver-XDP. Lowest overhead. Requires the NIC driver to
  implement XDP natively and to deliver packets to the program with a
  standard Ethernet frame layout.
- `generic` — SKB-XDP. Runs after the kernel allocates an skb, so the
  kernel normalizes the frame before the program sees it. Higher
  per-packet overhead but works on every driver that supports XDP at
  all.
- `auto` — try native first, fall back to generic on attach failure.

**Troubleshooting**: if `packetframe status` shows `rx_total`
incrementing in lockstep with `pass_not_ip` while the `matched_*`
counters stay at zero, the program is running but not parsing the
frames it receives — typically a driver-specific native-mode delivery
quirk. Re-attach with `generic` to confirm, then file an issue
describing the NIC driver and kernel.

## Configuration

`conf/example.conf` ships as the reference. Grammar notes:

- `global` and `module fast-path` blocks.
- `attach <iface> <mode>`, where `mode` is `native` / `generic` / `auto`.
- `allow-prefix` / `allow-prefix6` for IPv4 and IPv6 prefixes (LPM,
  src-or-dst match per §4.2).
- `dry-run on|off` gates actual redirects; when on, the program still
  counts matched packets but returns `XDP_PASS`.
- `circuit-breaker drop-ratio X of matched window Ys threshold N` —
  optional safety valve, see §4.9.
- `metrics-textfile <path>` — Prometheus textfile target, written every
  15 seconds.

SIGHUP re-reads the config and applies delta-only changes to allowlists
and VLAN-resolve state without detaching. Attach-set changes (adding or
removing an iface) require a restart.

## Build from source

```sh
# Host target
make build

# Release build for the current target
make release

# Every published target (requires `cross`)
make release-all

# Tests, lint, format
make test
make lint
make fmt
```

Dependencies: a stable Rust toolchain (pinned in `rust-toolchain.toml`).
The BPF crate lives at `crates/modules/fast-path/bpf/` and has its own
pinned nightly toolchain + `bpf-linker`; CI installs those automatically.
Cross-compiling to every release target uses
[`cross`](https://github.com/cross-rs/cross); install it with
`cargo install --locked cross`.

## Project layout

```
packetframe/
├── crates/
│   ├── common/                       # config, Module trait, §2.1 probes
│   ├── cli/                          # the `packetframe` binary
│   └── modules/
│       └── fast-path/                # fast-path module
│           └── bpf/                  # the BPF program (nightly toolchain)
├── conf/
│   └── example.conf                  # reference config per §4.8
└── .github/workflows/
    ├── ci.yml                        # fmt, clippy, test, cross-build
    ├── qemu-verifier.yml             # §10.2 matrix: 5.15 + 6.6 kernels
    └── release.yml                   # tag-triggered GitHub Release
```

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
