# PacketFrame

PacketFrame is an eBPF forwarding data plane for Linux edge routers. It takes the traffic you allowlist off the kernel's conntrack and netfilter path and forwards it directly between NICs. Everything else keeps the normal kernel forwarding path.

On a stock Linux router, every forwarded packet walks `nf_hook_slow`, a conntrack lookup and the iptables `FORWARD` chain. That happens even when no rule applies to the packet and no state needs to be kept. At full-table edge scale, that per-packet cost is often what saturates softirq. PacketFrame skips it for the prefixes you declare.

- In production on edge routers carrying full IPv4 and IPv6 BGP tables.
- Linux 5.15 or newer. A single binary built with [aya](https://aya-rs.dev/), with the BPF programs embedded. No libbpf, bpftool or BPF toolchain needed on the router.
- Opt-in per interface. `packetframe detach` restores stock forwarding.
- Written in Rust. Licensed GPL-3.0-or-later.

## How it works

PacketFrame is one daemon with one config file. Its features are split into modules, and you enable only the ones you need.

### Fast path (`fast-path`)

An XDP program runs on ingress on every interface you `attach`. For each frame addressed to the router's MAC, it does the following:

1. **Match.** If the source or destination is in an `allow-prefix` / `allow-prefix6` range, the packet is handled here. Otherwise it goes to the kernel with `XDP_PASS`, unchanged.
2. **Look up the egress.** It finds the next hop, the egress device and the destination MAC (see [Forwarding modes](#forwarding-modes)).
3. **Rewrite and redirect.** It rewrites the Ethernet header, decrements the TTL or hop limit, and sends the frame to the egress NIC with `bpf_redirect_map`. The packet never reaches netfilter or conntrack. In native XDP mode, no skb is ever allocated for it.

The datapath is split into two programs chained with `bpf_tail_call`, because the single-program version exceeded the verifier's stack limit on a vendor 5.15 kernel ([why](docs/runbooks/tail-call-architecture.md)). It also handles:

- VLAN push, pop and rewrite, including redirecting straight to the member port under a single-member VLAN bridge (`bridge-resolve`).
- TCP MSS clamping (`mss-clamp`). The iptables `TCPMSS` target never sees redirected traffic, so the clamp has to happen here.
- Early drops of bogon or unroutable destinations (`block-prefix`).
- A per-host /32 and /128 fast path for directly connected destinations (`local-prefix`, `local-prefix6`). Neighbours are learned by ARP scavenging and NDP.

A circuit breaker watches unreachable and FIB-error drops as a share of matched traffic. If the share stays above its threshold, the breaker detaches the program and hands all traffic back to the kernel. Stopping the daemon does **not** detach it. The pinned XDP program keeps forwarding until you run `packetframe detach`.

### Forwarding modes

`forwarding-mode` decides where the egress lookup comes from:

- **`kernel-fib`** (default) calls `bpf_fib_lookup()` against the kernel's routing table. It makes the same decisions as plain Linux, and it is always the rollback path.
- **`packetframe-fib`** looks up PacketFrame's own FIB: LPM tries for IPv4 and IPv6, a nexthop array and ECMP groups, all in BPF maps. PacketFrame fills them from a BGP feed it receives itself. The per-packet lookup never touches the kernel routing table, so it doesn't depend on how or when the routing daemon writes that table. The control plane still uses the kernel for next-hop resolution: it asks the main table (`RTM_GETROUTE`) which interface a BGP next hop is on, then resolves the MAC over netlink. The connected routes that cover your next hops must stay in the kernel. An optional destination cache (`fib-cache`) sits in front of the LPM lookup.
- **`compare`** performs both lookups, forwards using the kernel result, and counts disagreements. Use it to validate before cutover.

In `packetframe-fib`, routes come from one of two sources:

- **A passive iBGP listener** (`route-source bgp`). The routing daemon connects to PacketFrame and exports its best paths to it. PacketFrame negotiates MP-BGP for IPv4 and IPv6 unicast, four-octet ASNs and ADD-PATH receive (for ECMP). It never originates routes. FRR and BIRD are both supported; FRR is the production pairing.
- **A BMP station** (`route-source bmp`, RFC 7854 and RFC 9069). It needs an emitter that sends a Loc-RIB view (FRR can; BIRD 2.x and 3.x cannot).

An **integrity authority** (`integrity-authority birdc` or `frr`) compares PacketFrame's copy of the table against the routing daemon's own table and reports drift. It does not withdraw a partial table from the fast path. vpp-offload uses the result to hold its first steer until the table is complete (`require-table-complete`).

### VPP offload (`vpp-offload`)

This module adds a second forwarding tier. The NIC's hardware classifier (ntuple rules in the MCAM) sends allowlisted traffic to an SR-IOV virtual function. On that VF, a [VPP](https://fd.io/) process that PacketFrame starts and supervises forwards it. Steered traffic bypasses the kernel entirely and uses dedicated worker cores.

- **Routes.** VPP gets fast-path's resolved FIB, including `fallback-default`, over the VPP binary API. PacketFrame reads the routes back to verify them and scans for drift.
- **IPv4** is steered by allowlisted prefix.
- **IPv6** is steered by frame, because the NIC can't match an IPv6 address. `v6-divert` sends TCP and UDP addressed to the router's MAC on the listed VLANs into VPP. Router-owned IPv6 that arrives this way returns to the kernel over a veth, behind a stateless ACL in VPP. Services that must accept new sessions stay on the kernel (`steer-keep6`). DNS and BGP are kept on the kernel by default.
- **Control.** Steering is a per-port lever, off by default, and it reloads without a restart. If VPP stops, steered traffic goes back to the XDP fast path.
- **VPP builds.** The module isn't tied to one VPP build. At attach, it checks the binary API's message CRCs against the vendored definitions in [`vpp-api/`](crates/modules/vpp-offload/vpp-api/). For UniFi gateways, [unredacted/vpp-unifi](https://github.com/unredacted/vpp-unifi) builds unmodified upstream VPP.

### Neighbour snooping (`neigh-snoop`)

This module is for IX-facing bridges. It watches ARP and NDP traffic from a promiscuous, receive-only `AF_PACKET` socket with a classic-BPF filter, and learns third-party IP-to-MAC pairs. Those pairs are installed as `NUD_STALE` kernel neighbours, so the first packet to an IX peer doesn't wait on resolution. The module never overrides a confirmed entry and never transmits. It persists what it learns per bridge. `ix-mode` stops fast-path's resolver from probing through the bridge. `frr-gate` keeps FRR's next-hop prefix-lists in sync with the neighbours that are actually present.

### Guard (`guard`, experimental)

A tc-egress policer for IX-facing interfaces. It enforces GCRA rate limits on ARP and neighbour solicitations per target, and on a broadcast and multicast catch-all. It drops LLDP and frames with a foreign source MAC. Each class runs in `monitor` or enforce mode.

### Probe (`packetframe probe`)

Attaches a diagnostic XDP program and dumps the first bytes of sampled frames. Use it to see what a driver actually hands to XDP.

## Results

Measured on a production edge router after switching from `kernel-fib` to `packetframe-fib`. Your results will depend on traffic mix, NIC, kernel and topology.

| Metric | Change |
|---|---|
| Allowlisted flows taking the fast path | about 98% |
| Active conntrack entries | down about 85% |
| Per-CPU softirq (`%soft`) | down about 18 percentage points |
| Per-CPU idle (`%idle`) | up about 20 percentage points |
| Customer-facing ping, average | down about 57% |
| Customer-facing ping, p99 | down about 55% |

Later, the same router moved IPv6 into VPP alongside IPv4 (four steered ports, full tables). Softirq fell from about 16% of CPU to about 1%.

## What it is not

- **Not a routing daemon.** It receives routes from FRR or BIRD and doesn't replace them.
- **Not a firewall.** Allowlisted traffic bypasses netfilter entirely, iptables and nftables included. Allowlist only traffic that needs no filtering.
- **Not a kernel-bypass stack.** The XDP fast path runs inside the kernel, and non-matching traffic keeps every kernel feature. Only vpp-offload takes traffic out of the kernel, and it uses dedicated cores to do it.

## Status

| Feature | Status |
|---|---|
| Fast path, `kernel-fib` | Production |
| Fast path, `packetframe-fib` with the iBGP listener | Production (fed by FRR) |
| Integrity authority (`birdc`, `frr`) | Production (`frr`) |
| Connected-host fast path (`local-prefix`, `local-prefix6`) | Production |
| Synthetic default route (`fallback-default`) | Production |
| XDP-time drop (`block-prefix`) | Production |
| MSS clamping (`mss-clamp`) | Production |
| Hot reload (`packetframe reconfigure`, SIGHUP) | Production |
| Per-module health and Prometheus textfile | Production |
| Persistent event log (`packetframe events`) | Production |
| `vpp-offload`: IPv4 and IPv6, both directions | Production |
| `neigh-snoop`, including `ix-mode` and `frr-gate` | Production |
| `probe` | Production |
| BMP station (`route-source bmp`) | Supported, not yet in production (no current Loc-RIB emitter) |
| `guard` | Experimental. Verifier behaviour on the reference vendor 5.15 kernel is unconfirmed, and frames that VPP originates bypass it |
| tc-ingress datapath (`attach <iface> tc`) | Not recommended. Measured about 70% more CPU per packet than generic XDP |
| `ddos` (SYN-flood and amplification filter), `sampler` (per-flow ring buffer) | Planned |

## Requirements

- Linux 5.15 or newer, on x86_64 or aarch64.
- Root access.
- The `.deb` needs glibc 2.31 or newer (Debian 11, Ubuntu 20.04 or later). The musl tarballs run on any Linux.
- For `packetframe-fib`: FRR or BIRD, configured to export to PacketFrame over iBGP.
- For vpp-offload: a NIC with SR-IOV and ntuple flow steering to a VF, plus hugepages and spare cores for VPP workers. It has been built and tested only on UniFi gateways with Marvell OCTEON TX2 (`rvu-nicpf`) NICs. Read [the runbook](docs/runbooks/vpp-offload.md) before trying other hardware.

## Install

Releases are on the [releases page](https://github.com/unredacted/packetframe/releases).

**Debian or Ubuntu:**

```sh
VERSION=0.5.0
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
curl -LO "https://github.com/unredacted/packetframe/releases/download/v${VERSION}/packetframe_${VERSION}_${ARCH}.deb"
curl -LO "https://github.com/unredacted/packetframe/releases/download/v${VERSION}/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
sudo apt-get install "./packetframe_${VERSION}_${ARCH}.deb"
sudo systemctl daemon-reload
```

The package doesn't start the service, and it doesn't tell systemd it was installed. **Run `systemctl daemon-reload` after every install or upgrade.** If you skip it, systemd may not find the service, or it may keep using the old unit file.

**Any Linux (tarball):**

```sh
VERSION=0.5.0
TARGET=x86_64-unknown-linux-musl    # or x86_64-unknown-linux-gnu, aarch64-unknown-linux-{gnu,musl}
curl -LO "https://github.com/unredacted/packetframe/releases/download/v${VERSION}/packetframe-v${VERSION}-${TARGET}.tar.gz"
curl -LO "https://github.com/unredacted/packetframe/releases/download/v${VERSION}/SHA256SUMS"
sha256sum -c SHA256SUMS --ignore-missing
tar xzf "packetframe-v${VERSION}-${TARGET}.tar.gz"
sudo install -m 0755 "packetframe-v${VERSION}-${TARGET}/packetframe" /usr/local/bin/
sudo install -m 0644 -D "packetframe-v${VERSION}-${TARGET}/conf/example.conf" /etc/packetframe/example.conf
```

When a release is signed, it also includes `SHA256SUMS.asc`. Check it with `gpg --verify SHA256SUMS.asc SHA256SUMS`.

## Getting started

Start in dry-run mode, watch the counters, then turn forwarding on.

**1. Check the machine.**

```sh
sudo packetframe feasibility --human
```

Anything marked `FAIL` has to be fixed in the kernel or host before you continue.

**2. Write a config** at `/etc/packetframe/packetframe.conf`:

```
global
  bpffs-root /sys/fs/bpf/packetframe
  state-dir /var/lib/packetframe/state
  metrics-textfile /var/lib/packetframe/packetframe.prom

module fast-path
  attach eth0 auto
  attach eth1 auto
  allow-prefix 192.0.2.0/24        # traffic to or from here takes the fast path
  allow-prefix6 2001:db8::/48
  dry-run on                        # count matches, but let the kernel forward everything
  circuit-breaker drop-ratio 0.01 of matched window 5s threshold 5
```

- `attach` names each interface. `auto` tries native XDP and falls back to generic, and picks generic on drivers with known native-mode bugs (see [XDP modes and drivers](#xdp-modes-and-drivers)).
- `dry-run on` counts matches but always returns `XDP_PASS`, so the kernel keeps forwarding everything.
- `circuit-breaker` detaches the fast path when unreachable plus FIB-error drops exceed 1% of matched packets for five consecutive 5-second samples.

[`conf/example.conf`](conf/example.conf) explains every setting.

**3. Check the config against this machine.**

```sh
sudo packetframe feasibility --config /etc/packetframe/packetframe.conf --human
```

This adds a trial XDP attach on each interface to catch driver problems before you go live.

**4. Start it and watch.**

```sh
sudo systemctl enable --now packetframe   # with the .deb
sudo packetframe run                      # or in the foreground, without systemd
sudo packetframe status                   # in another shell
```

Check that the `matched_*` counters are rising and that they account for the traffic you expect.

**5. Turn forwarding on.** Change `dry-run on` to `dry-run off`, then reload:

```sh
sudo packetframe reconfigure
```

`systemctl reload packetframe` does the same thing (both send SIGHUP). Allowlists, `dry-run`, `block-prefix`, `mss-clamp`, `forwarding-mode` between `compare` and `packetframe-fib`, and vpp-offload's steering levers all reload live. Changing the attach set, `route-source` or `local-prefix` needs a restart. [`docs/runbooks/reconfigure.md`](docs/runbooks/reconfigure.md) lists which settings are which.

**To remove PacketFrame from the interfaces:**

```sh
sudo systemctl stop packetframe
sudo packetframe detach --all
```

## Setting up packetframe-fib

Add these lines to the `fast-path` module.

**With FRR:**

```
forwarding-mode packetframe-fib
route-source bgp 192.0.2.202:1179 local-as 65551 peer-as 65551 allow-remote peer-from 192.0.2.201/32 anyip
integrity-authority frr upstream 192.0.2.1 families v4,v6
```

- FRR refuses to peer over loopback or with an address its own host holds. `anyip` installs a phantom listen address (here `192.0.2.202`) on `lo` for as long as the daemon runs, and FRR peers with that.
- `integrity-authority frr` checks through `vtysh` that the mirror holds FRR's full table for each listed family.

**With BIRD:**

```
forwarding-mode packetframe-fib
route-source bgp 127.0.0.1:1179 local-as 65551 peer-as 65551
```

The listener is passive: the routing daemon connects out and exports its best paths, so PacketFrame receives one UPDATE per prefix (or one per path, with ADD-PATH). With BIRD, `integrity-authority` defaults to the local `birdc`.

Run `forwarding-mode compare` first and watch the disagreement counter. To roll back, set `forwarding-mode kernel-fib` and restart.

[`docs/runbooks/packetframe-fib.md`](docs/runbooks/packetframe-fib.md) covers switching over, rolling back, checking the table and troubleshooting. It also covers BMP feeds (`route-source bmp … require-loc-rib`).

## Upgrading and restarting

`systemctl restart` is not enough. The fast path's bpffs pins outlive the process on purpose, and a new daemon refuses to start over them. Tear them down with the binary that created them (the one you are **replacing**), then install:

```sh
sudo systemctl stop packetframe
sudo packetframe detach --all                          # run the OLD binary
sudo apt-get install ./packetframe_<version>_<arch>.deb  # or install the new binary from the tarball
sudo systemctl daemon-reload
sudo systemctl start packetframe
```

Between `detach` and the new daemon's attach, the kernel forwards everything using its own routing table.

A restart without an upgrade works the same way, minus the install step.

With vpp-offload, `detach --all` also stops VPP and removes its MCAM rules. The new daemon steers nothing until you move each port's `steer` lever again. To restart while VPP keeps forwarding, use:

```sh
sudo systemctl stop packetframe && sudo packetframe detach --keep-vpp && sudo systemctl start packetframe
```

The clean stop preserves VPP's route ledger, and the next daemon adopts VPP from it without an unsteered window. `--keep-vpp` refuses the restart if the config change touches something VPP fixes at startup.

Coming from 0.2.7? Read the upgrade notes in [CHANGELOG.md](CHANGELOG.md) first. `bridge-resolve` now defaults to on.

## Everyday commands

```sh
sudo packetframe status                # live counters and per-module health
sudo packetframe events --since 12h    # steering, verify, restarts, reloads, health transitions
sudo packetframe fib lookup 192.0.2.10 # what the XDP lookup returns for this destination
sudo packetframe fib stats             # PacketFrame FIB occupancy and ECMP hash mode
sudo packetframe fib dump-v4           # walk the IPv4 LPM trie
```

`fib` reads the pinned maps directly, and `events` reads the log file, so both work while the daemon is stopped. The event log is newline-delimited JSON at `<state-dir>/events.log`, rotated at `event-log-max`. It exists because a journal capped for the whole box can lose these events within hours. On appliances whose root filesystem is reset by firmware upgrades, point `event-log` at persistent storage.

With `metrics-textfile` set, the daemon rewrites a Prometheus textfile every 15 seconds. It contains per-counter gauges, PacketFrame FIB occupancy by nexthop state, the active forwarding mode, and each module's own gauges.

## XDP modes and drivers

| Mode | Where it runs | Use when |
|---|---|---|
| `native` | In the driver's receive path, before skb allocation | The driver supports native XDP and hands it Ethernet-shaped frames |
| `generic` | After skb allocation | The driver lacks native XDP or has native-mode bugs |
| `auto` | Tries native, falls back to generic | Most cases. Downgrades on drivers with known bugs |
| `tc` | tc ingress (packetframe-fib only) | Not recommended ([why](docs/runbooks/tc-datapath.md)) |

PacketFrame refuses settings it knows to be unsafe:

- **Marvell `rvu-nicpf` before Linux 6.8** (without upstream commit `04f647c8e456`): every native detach leaks the driver's `non_qos_queues` counter, and native attach has panicked the vendor 5.15 kernel. PacketFrame refuses `native` here, and `auto` picks `generic`. If your kernel has the backport, `driver-workaround rvu-nicpf-head-shift off` lifts the refusal.
- **Marvell `rvu-nicpf` ports in one bridge:** XDP attach and detach both bounce the link, which the bridge treats as a port-state change. Two ports flapping inside one STP/RSTP window has caused L2 loops and kernel panics. When two or more attached interfaces share a bridge master, PacketFrame paces them by `attach-settle-time` (2 seconds by default).

If `rx_total` climbs in step with `pass_not_ip` while `matched_*` stays at zero, the program is running but can't parse what the driver delivers. `packetframe probe` dumps the first 16 bytes of sampled frames, with a verdict:

```sh
sudo packetframe probe --iface eth0 --mode native --duration 2s
sudo packetframe probe --iface eth0 --mode native --duration 2s --offset 128   # look past driver headroom
sudo packetframe probe --iface eth0 --mode generic --duration 2s               # what the kernel sees
```

## Documentation

- [`conf/example.conf`](conf/example.conf): every setting, explained
- [`CHANGELOG.md`](CHANGELOG.md): what changed in each release, and how to upgrade
- Module guides: [fast-path](crates/modules/fast-path/README.md), [vpp-offload](crates/modules/vpp-offload/README.md), [neigh-snoop](crates/modules/neigh-snoop/README.md), [guard](crates/modules/guard/README.md), [probe](crates/modules/probe/README.md)

Runbooks, for running PacketFrame in production:

| Runbook | Covers |
|---|---|
| [packetframe-fib](docs/runbooks/packetframe-fib.md) | Switching to PacketFrame's own routing table, rolling back, troubleshooting |
| [vpp-offload](docs/runbooks/vpp-offload.md) | Rolling out VPP offload one port at a time, rolling back, what it costs |
| [neigh-snoop](docs/runbooks/neigh-snoop.md) | Rolling out neighbour snooping, the FRR next-hop feed |
| [guard](docs/runbooks/guard.md) | Moving guard from monitoring to enforcing |
| [reconfigure](docs/runbooks/reconfigure.md) | Which settings reload live and which need a restart |
| [event-log](docs/runbooks/event-log.md) | The event log: where it lives, what it records |
| [mss-clamp](docs/runbooks/mss-clamp.md) | Why fast-pathed TCP needs its own MSS clamping |
| [generic-mode-performance](docs/runbooks/generic-mode-performance.md) | Native vs generic mode, and host tuning that was measured |
| [tail-call-architecture](docs/runbooks/tail-call-architecture.md) | Why the kernel program is split into two stages |
| [tc-datapath](docs/runbooks/tc-datapath.md) | The tc-based datapath, and why it measured slower |
| [vpp-offload-spike](docs/runbooks/vpp-offload-spike.md) | How VPP offload was first brought up on test hardware |

## Building from source

You need Rust 1.98 or newer. The version CI uses is pinned in `rust-toolchain.toml`, and `rustup` installs it for you.

```sh
make build        # debug build
make release      # release build
make test         # run the tests
make lint         # formatting and clippy checks
make release-all  # all four release targets (needs `cargo install --locked cross`)
```

The BPF crates under `crates/modules/*/bpf/` each pin their own nightly toolchain, which rustup installs, and they also need `bpf-linker`, which it doesn't: `cargo install --locked bpf-linker@0.10.3` (the version CI pins in `.github/workflows/ci.yml`). Without it the build still succeeds, but each BPF program is embedded as an empty stub, and the binary fails when it tries to attach. Linux-only code is behind `cfg(target_os = "linux")`, so the workspace builds and tests on macOS against `ENOSYS` stubs. CI runs the BPF integration tests in QEMU on 5.15 and 6.6 kernels.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
