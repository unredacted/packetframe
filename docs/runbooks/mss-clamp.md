# MSS clamping (v0.2.4+)

Operator guide for `mss-clamp` directives in `module fast-path`. Closes the [SPEC.md §11.4](../../SPEC.md) gap where iptables `TCPMSS --set-mss` rules don't fire on fast-pathed flows because XDP redirect (`bpf_redirect_map`) bypasses netfilter.

## Contents

- [When to use it](#when-to-use-it)
- [Grammar + lookup precedence](#grammar--lookup-precedence)
- [What gets clamped](#what-gets-clamped)
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
mss-clamp 23.191.201.0/24 via eth2 1360       # only customer 23.191.201.0/24 leaving eth2
mss-clamp 23.191.201.0/24 1360                # customer 23.191.201.0/24, any egress
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
