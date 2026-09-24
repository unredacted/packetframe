# fast-path

PacketFrame's forwarding module. An eBPF program at XDP ingress takes
allowlisted traffic off the kernel's conntrack/netfilter path and
redirects it straight to the egress NIC. Anything it does not match, or
cannot forward, gets `XDP_PASS` and goes through normal kernel
forwarding, so the kernel stays the fallback for every packet.

**Status:** production.

## How it works

Per packet, on every attached interface:

1. **Parse** Ethernet (optionally one 802.1Q tag), then IPv4 or IPv6.
2. **Match** the source *or* destination against `allow-prefix` /
   `allow-prefix6`. Non-matching packets pass to the kernel untouched.
3. **Look up the egress**, either through the kernel FIB
   (`bpf_fib_lookup`) or through PacketFrame's own LPM-trie FIB,
   depending on `forwarding-mode`.
4. **Rewrite** L2 and TTL, push/pop/rewrite VLAN tags, clamp TCP MSS if
   configured, and `bpf_redirect_map` to the egress device.

The datapath is split into two XDP programs chained by `bpf_tail_call`
(`fast_path` classifies and rewrites, `finalize` handles MSS, VLAN and
the redirect) so that each gets its own 512-byte BPF stack. See
[tail-call-architecture.md](../../../docs/runbooks/tail-call-architecture.md).

### Forwarding modes

| Mode | Egress comes from | Use |
|---|---|---|
| `kernel-fib` (default) | `bpf_fib_lookup()` against the kernel routing table | Same decisions as plain Linux; the permanent rollback path |
| `custom-fib` | PacketFrame's own FIB, fed by a `route-source` | Full-table boxes where the kernel FIB is the bottleneck |
| `compare` | Both; forwards on the kernel result and counts disagreements | Validation before a cutover only |

In `custom-fib` mode a tokio-driven control plane under
[`src/fib/`](src/fib/) owns the FIB:

- **Route source.** `BgpListener` is a passive iBGP speaker that the
  routing daemon (bird or FRR) dials into; it receives best paths after
  export policy. `BmpStation` accepts RFC 7854/9069 BMP instead, for
  emitters that ship Loc-RIB.
- **`FibProgrammer`** turns route events into the `FIB_V4`/`FIB_V6` LPM
  tries, the `NEXTHOPS` array (seqlock-written) and `ECMP_GROUPS`.
- **`NeighborResolver`** follows the kernel neighbour table over
  netlink and fills in next-hop MACs.
- **Integrity checker** compares the mirror against an authority
  (`birdc` by default, `frr` via vtysh, or `none`) and reports drift.

## Configuration

A minimal, observe-only start:

```
module fast-path
  attach eth0 auto
  attach eth1 auto
  allow-prefix  192.0.2.0/24
  allow-prefix6 2001:db8::/48
  dry-run on
  circuit-breaker drop-ratio 0.01 of matched window 5s threshold 5
```

Cutting over to the custom FIB adds:

```
  forwarding-mode custom-fib
  route-source bgp 127.0.0.1:1179 local-as 64500 peer-as 64500
```

Other directives cover connected hosts (`local-prefix`,
`local-prefix6`), a synthetic default route (`fallback-default`),
XDP-time drops (`block-prefix`), MSS clamping (`mss-clamp`), bridge
short-circuiting (`bridge-resolve`, `fdb-pin`), a destination cache in
front of the FIB (`fib-cache`) and driver workarounds. Every one is
documented inline in [`conf/example.conf`](../../../conf/example.conf).

Attach modes are `native`, `generic`, `auto` (native with a fallback,
downgraded on drivers with known bugs) and `tc`, a tc-ingress variant
that works only with `custom-fib`. `tc` measured slower on the reference
hardware and is kept for reference only
([tc-datapath.md](../../../docs/runbooks/tc-datapath.md)).

**Reloads.** `packetframe reconfigure` (SIGHUP) applies allowlist,
`block-prefix`, `dry-run`, `forwarding-mode`, `mss-clamp` and VLAN
changes as deltas. Changing the attach set, `route-source`,
`circuit-breaker` or `local-prefix` needs a restart. The full list is in
[reconfigure.md](../../../docs/runbooks/reconfigure.md).

## Operating it

```sh
sudo packetframe status             # counters, module health
sudo packetframe fib stats          # custom-FIB occupancy
sudo packetframe fib lookup 192.0.2.1
sudo packetframe detach --all       # remove pins, detach
```

Programs, maps and links are pinned under
`<bpffs-root>/fast-path/`, so forwarding survives a daemon crash and
`packetframe fib` can read the FIB while the daemon is stopped. The
circuit breaker samples the `STATS` map; if unreachable drops plus FIB
errors stay above the configured share of matched traffic, it detaches
the module and leaves a sticky flag in `state-dir` that blocks
re-attach until an operator clears it.
Counters are exported to the Prometheus textfile as `packetframe_*`.

## Source layout

| Path | Contents |
|---|---|
| `bpf/` | The BPF crate (nightly toolchain): `main.rs` XDP entry, `finalize.rs` tail-call stage, `fib.rs` custom-FIB lookup, `tc.rs` tc variant, `maps.rs` map definitions |
| `build.rs` | Builds `bpf/` and embeds the ELF |
| `src/linux_impl.rs` | Load, attach, detach; the `Module` implementation |
| `src/reconcile.rs` | SIGHUP delta application |
| `src/breaker.rs` | Circuit breaker |
| `src/redirect_watch.rs` | Keeps redirect targets and VLAN resolution in step with the link table |
| `src/fib/` | Custom-FIB control plane: route sources, programmer, resolver, integrity, inspection |
| `src/pin.rs`, `src/registry.rs`, `src/tc_links.rs` | Pin paths and persisted attach records for `detach` |

## Tests

`cargo test -p packetframe-fast-path` runs the portable tests on any
host, macOS included. Tests that load BPF, create network namespaces or
need root are `#[ignore]`d. CI runs them under sudo and again inside
the qemu-verifier job on 5.15 and 6.6 kernels:

```sh
sudo -E $(which cargo) test -p packetframe-fast-path --tests -- --ignored
```

`fib_hash_vectors` checks that the userspace ECMP hash
(`src/fib/hash.rs`) agrees byte for byte with the BPF one.

## Further reading

- [custom-fib.md](../../../docs/runbooks/custom-fib.md): cutover, rollback, triage by symptom
- [mss-clamp.md](../../../docs/runbooks/mss-clamp.md): MSS clamping for traffic iptables no longer sees
- [generic-mode-performance.md](../../../docs/runbooks/generic-mode-performance.md): generic vs native XDP cost
