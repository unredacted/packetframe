# MSS clamping (v0.2.4+)

Operator guide for `mss-clamp` directives in `module fast-path`. Closes the [SPEC.md §11.4](../../SPEC.md) gap where iptables `TCPMSS --set-mss` rules don't fire on fast-pathed flows because XDP redirect (`bpf_redirect_map`) bypasses netfilter.

## Contents

- [When to use it](#when-to-use-it)
- [Grammar + lookup precedence](#grammar--lookup-precedence)
- [What gets clamped](#what-gets-clamped)
- [With vpp-offload](#with-vpp-offload)
- [Troubleshooting](#troubleshooting)
- [Why no `from <iface>` (ingress) form?](#why-no-from-iface-ingress-form)
- [Hot-reload semantics](#hot-reload-semantics)

## When to use it

Add `mss-clamp` directives if any of these are true on your edge:

- A downstream peer's path MTU is less than the local link MTU (typical: PPPoE, GRE, IPsec, WireGuard, MPLS overlays). Without clamping, large segments arrive at the bottleneck, get fragmented or PMTUD-discovered-then-dropped, and TCP throughput collapses.
- You currently rely on `iptables -A FORWARD ... TCPMSS --set-mss <N>` rules and one or more of the `-s` / `-d` prefixes overlaps an `allow-prefix`. Those iptables rules do not fire for fast-pathed traffic. Adding a matching `mss-clamp` directive moves the mutation into XDP.
- You deploy onto a host where you don't control upstream MTU but want to defend against MTU-blackhole-induced TCP stalls.

If none of those apply, you don't need this. PacketFrame doesn't insert any clamp by default.

## Grammar + lookup precedence

Four forms accepted, looked up in order of specificity at packet time. The first match wins:

| # | Form | Scope |
|---|---|---|
| 1 | `mss-clamp <cidr> via <iface> <mtu>` | Source-or-dest prefix AND egress iface (most specific) |
| 2 | `mss-clamp <cidr> <mtu>` | Source-or-dest prefix, any egress |
| 3 | `mss-clamp via <iface> <mtu>` | Egress iface, any prefix |
| 4 | `mss-clamp <mtu>` | Global fallback |

Examples for the typical "clamp customer SYNs leaving the WAN" case:

```
mss-clamp via eth2 1360                       # everything leaving eth2
mss-clamp 203.0.113.128/25 via eth2 1360       # only customer 203.0.113.128/25 leaving eth2
mss-clamp 203.0.113.128/25 1360                # customer 203.0.113.128/25, any egress
```

Prefix matches **src OR dst** (same semantic as `allow-prefix`), so one rule covers both directions of a flow.

CIDR ranges work for both IPv4 and IPv6; the parser dispatches on the address family. `mss-clamp 2001:db8::/48 1280` is valid.

`<mtu>` is the clamp ceiling in bytes. Range: 88–65495. The clamp is **lower-if-higher**: if the SYN's existing MSS is already ≤ the configured value, the packet is left untouched and `mss_clamp_skipped` is bumped instead of `mss_clamp_applied`.

## What gets clamped

- Only **matched** traffic (i.e. `allow-prefix` / `allow-prefix6` already hit). Non-matched traffic flows through the kernel where existing iptables `TCPMSS` rules still fire normally.
- Only **TCP SYN and SYN-ACK** packets. Established-connection packets don't carry an MSS option, so there's nothing to mutate.
- Both directions: a SYN egressing eth2 from a clamped prefix, AND the responder's SYN-ACK egressing back into the customer LAN. TCP's per-direction MSS is independent; clamping both ensures both endpoints respect the constraint.
- Only when a clamp value > 0 applies. A packet whose lookup returns no policy is forwarded with no counter activity.

What is **not** touched: the original packet's TCP timestamp, SACK, window-scale, or any other option. Only the MSS option's 2 bytes change. Checksum is recomputed via RFC 1624 incremental update, with no full TCP-segment re-fold.

## With vpp-offload

The clamp runs in XDP. A frame the NIC steers to VPP never reaches XDP,
so VPP forwards it unclamped. vpp-offload therefore refuses, at start and
at reload, a steer that would carry clamped traffic through VPP, and
names the `mss-clamp` line and the port. What counts:

- `mss-clamp <mss>`: anything steered. `mss-clamp via <iface> <mss>`:
  the same, when VPP can send out of `<iface>` (a member port, or the
  device of a `local-prefix` a `local-route` delivers to). A clamp via a
  device VPP never egresses, such as a tunnel, is not judged.
- An IPv4 prefix, on a `direction src` side: the prefix overlaps the
  allowlist, or it is not wholly `steer-exempt`. On a `direction dst`
  side: the allowlisted part of it is not wholly `steer-exempt`, or it
  is remote (in no `local-prefix`) and something allowlisted is not
  exempt.
- An IPv6 prefix: any `v6-divert`, which diverts by frame and cannot be
  scoped by address.

There are two remedies. Clamp in VPP too (below), or keep the prefix on
the kernel path: `steer-exempt` it (that keeps traffic TO it) and leave
its hosts' trunk unsteered or `direction dst`, or take it off the
allowlist.

### Clamping in VPP: `mss-clamp vlan`

```
module vpp-offload
  ...
  port eth4 cores 1 steer on vlans all direction both
  local-route 203.0.113.0/24 port eth4 vlan 1337
  mss-clamp vlan 1337 ip4 1360            # and/or: ip6 <mss> (needs `v6 on`)
```

VPP's `mss_clamp` plugin clamps, both directions, on the VLAN's L3
interface: its BVI when bridged, each member's subinterface on the
VLAN, and the VF of a port that sends it untagged. A customer's SYN
enters VPP there and the SYN-ACK back to it leaves there, so every flow
to or from the VLAN's hosts is clamped. Same lower-if-higher rule as the
fast path, on SYN and SYN-ACK only.

- **Scope is the VLAN, not a prefix.** Every host on it is clamped. A
  fast-path `mss-clamp <cidr> <mss>` counts as covered, and the guard
  above lets the steer through, when `<cidr>` lies inside a
  `local-route` on that VLAN and the VLAN's value is no higher than
  `<mss>`. Keep the fast-path line: it still clamps the same traffic on
  the eBPF tier when steering is off or VPP is gone.
- **Hot-reloadable.** `packetframe reconfigure` applies a new, changed
  or removed line at the next VLAN refresh, within seconds, with no
  restart and no change to steering. VPP holds the clamp itself, so it
  survives a `--keep-vpp` restart, and adoption reads it back and puts
  it right.
- **One IPv4 value across all lines**, for now. VPP 26.10's plugin
  clamps the second packet of each pair it handles at the first one's
  interface value (fixed upstream after 26.10). With one value that
  cannot matter, so validation refuses two.
- **The plugin must be loaded.** It ships in fd.io's `vpp-plugin-core`.
  A VPP without it still attaches; a configured clamp is then reported
  as not in place.
- **Not in place holds the first steer.** A clamp VPP cannot apply (no
  plugin, a VLAN with no interface yet, a refusal) shows on the
  `mss-clamp` row of `packetframe status` as Degraded, naming the VLAN
  and why, and a first steer is refused until it is in place. A port
  already steering keeps steering; the row says what is missing.

```sh
sudo packetframe status | grep mss-clamp
sudo vppctl show interface tcp-mss-clamp     # what VPP holds, per interface
```

To check it on the wire, capture a SYN-ACK leaving toward a host on the
VLAN and look for `mss 1360` in its options. Design notes:
[vpp-mss-clamp-design.md](vpp-mss-clamp-design.md).

## Troubleshooting

The two relevant counters (SPEC §4.6 indices 33–34, exposed via `packetframe status` and the metrics textfile):

- `mss_clamp_applied`: packets where the MSS option was rewritten. Climbs with new TCP sessions on clamped prefixes; flat means either no SYNs are arriving on those prefixes or your existing SYNs already announce ≤ clamp.
- `mss_clamp_skipped`: packets matched + with a clamp policy active, but no rewrite. Common reasons:
  - Existing MSS already ≤ clamp value (working as intended; you can ignore unless you expect *every* SYN to need adjustment).
  - SYN had no MSS option (rare; some old/embedded stacks).
  - Malformed TCP options block (very rare; would also break the kernel's processing).

To confirm the clamp is firing on real traffic:

```sh
sudo packetframe status | grep mss_clamp
# or via Prometheus textfile:
grep packetframe_mss_clamp /var/lib/node_exporter/textfile/packetframe.prom
```

To see the wire MSS that egresses, capture on the egress interface (clamping happens inside the XDP redirect path, so `tcpdump -i <egress>` shows the post-clamp value):

```sh
sudo tcpdump -i eth2 -n 'tcp[tcpflags] & tcp-syn != 0' -c 5 -vv
# Look for: ... [S], options [mss <YOUR_CLAMP_VALUE>, ...
```

If `mss_clamp_applied` is climbing but downstream still shows MTU-blackhole symptoms, the clamp value is probably too high. The standard math: `MSS = MTU - 40` for IPv4, `MSS = MTU - 60` for IPv6 (each subtracts the IP+TCP header overhead).

## Why no `from <iface>` (ingress) form?

PacketFrame's XDP runs at ingress on attached physical NICs. The directional concept that matters operationally is "what egress will this fast-pathed packet take", resolved by `bpf_fib_lookup` before redirect. `via <iface>` always means **egress**, matching the `local-prefix via X` and `fallback-default via X` grammar.

For the cases where iptables operators reach for `-i <iface>` (e.g. "clamp packets coming in on this tunnel"), the realistic need is "clamp this customer's traffic", better expressed via prefix scoping. Prefix scoping is route-stable; ingress-iface scoping depends on which physical bridge member happened to receive the packet.

If a future use case needs strict ingress scoping, the grammar is append-only. Adding `from <iface>` later is straightforward.

## Hot-reload semantics

Changes to `mss-clamp` directives are applied via SIGHUP without re-attaching XDP:

```sh
# Edit /etc/packetframe/packetframe.conf, then:
sudo packetframe reconfigure       # or `systemctl reload packetframe`
```

The reconcile path performs delta updates against the LPM tries (`MSS_CLAMP_V4`, `MSS_CLAMP_V6`) and the per-iface table: adds, removes, and value updates all happen in place. The global `mss-clamp <mtu>` form lives in the `CFG` array and is updated atomically.

A bad config (e.g. value out of range, malformed CIDR) is rejected at parse time; the CLI exits non-zero with the parse error, the running daemon keeps the old policy in effect.
