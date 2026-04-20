# PacketFrame

PacketFrame is a modular eBPF data-plane framework written in pure Rust. It
provides a pluggable runtime for discrete datapath modules (fast-path
forwarding, egress randomization, DDoS mitigation, flow sampling) that can be
loaded, attached to network interfaces, observed, and detached independently.

The MVP module — and the reason the project exists — is `fast-path`, which
takes forwarded packets for allowlisted prefixes off the kernel's
conntrack/netfilter hot path by intercepting them at native XDP ingress and
redirecting them via `bpf_fib_lookup` + `bpf_redirect_map`. The design
spec lives alongside the project internally; inline code comments cite
section numbers (e.g. "SPEC.md §4.2") as breadcrumbs.

## Status — v0.0.1

v0.0.1 is the **feasibility slice**: workspace scaffolding, config parser,
the `Module` trait, and a `packetframe feasibility` subcommand that probes
the host kernel for PacketFrame's capability requirements (SPEC.md §2.1). It
**does not yet load any BPF programs.** The fast-path module ships as a stub
whose lifecycle methods return `NotImplemented`. Real BPF loading, XDP
attachment, VLAN choreography, metrics, and the circuit breaker all land in
v0.1.

Use v0.0.1 to:

- Confirm a host has all the kernel capabilities PacketFrame needs.
- Validate a config file's syntax before deploying v0.1.
- Establish the install and release pipeline so v0.1 arrives as a drop-in
  binary upgrade.

## Install

From a GitHub Release tarball:

```sh
VERSION=v0.0.1
TARGET=aarch64-unknown-linux-musl   # or x86_64-unknown-linux-musl, etc.
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

## Quickstart

Probe the kernel:

```sh
sudo packetframe feasibility --human
```

Point it at a config file (validates syntax and checks that referenced
interfaces exist):

```sh
sudo packetframe feasibility --config /etc/packetframe/packetframe.conf --human
```

JSON output for automation:

```sh
sudo packetframe feasibility --config /etc/packetframe/packetframe.conf | jq .
```

Exit codes follow SPEC.md §7.3:

- `0` — all required capabilities present.
- `1` — startup error (config parse failure, missing interface, unsupported
  kernel capability).
- `2` — runtime error / subcommand not implemented in v0.0.1.

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
│       └── fast-path/                # v0.0.1 stub; v0.1 has the real module
├── conf/
│   └── example.conf                  # reference config per SPEC.md §4.8
└── .github/workflows/
    ├── ci.yml                        # fmt, clippy, test, cross-build
    └── release.yml                   # tag-triggered GitHub Release
```

## License

Apache-2.0. See [LICENSE](LICENSE).
