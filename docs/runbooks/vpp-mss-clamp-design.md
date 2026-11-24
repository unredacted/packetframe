# Design: MSS clamping for steered traffic

Status: **decided, being built** (option 0, then option A; see
[Decision](#decision)). This page sets out what each option would change,
what it would cost, and where it stops working.

## The problem

The fast path's `mss-clamp` rewrites the MSS option of TCP SYN and SYN-ACK
packets in XDP ([mss-clamp.md](mss-clamp.md)). A frame the NIC diverts to
VPP never reaches XDP, so it is never clamped. VPP forwards it as it came.

vpp-offload does not know this. Nothing at load, in `feasibility` or in
`status` says that a steered port is taking traffic a configured clamp
covers. The clamp just stops applying to that traffic.

An operator who needs a clamp on one prefix today has two partial tools:

- **`steer-exempt <prefix>`** keeps traffic TO the prefix on the kernel
  path, where the clamp still works. That covers the inbound half on a
  `direction dst` port. It is destination-only, so it cannot keep the
  prefix's own outbound traffic (source in the prefix, destination
  anywhere) off VPP.
- **Leaving the VLAN out of `vlans`** is not an opt-out. A steered frame on
  a VLAN VPP has no subinterface for is punted and dropped
  ([attach.rs](../../crates/modules/vpp-offload/src/attach.rs),
  `ensure_vlan_subifs`).

So a trunk carrying the clamped prefix's hosts cannot steer `direction src`
or `both`. On the reference deployment's second gateway, both trunks wait
on this.

## What VPP offers

VPP ships a `mss_clamp` plugin (`src/plugins/mss_clamp`, in fd.io's
`vpp-plugin-core`). Checked against `stable/2610`:

- **Per interface, per direction, per family.** `set interface
  tcp-mss-clamp <if> ip4 [enable|disable|rx|tx] ip4-mss <n> ip6 [...]
  ip6-mss <n>`, `show interface tcp-mss-clamp`. Binary API:
  `mss_clamp_enable_disable` (`sw_if_index`, `ipv4_mss`, `ipv6_mss`,
  `ipv4_direction`, `ipv6_direction`, where direction is a flag set of
  `RX = 1`, `TX = 2`) and the `mss_clamp_get` / `mss_clamp_details`
  stream for reading it back.
- **Where it runs.** RX is a feature on the `ip4-unicast` / `ip6-unicast`
  arcs, so it sees routed input on that interface before the lookup. TX
  is a feature on `ip4-output` / `ip6-output`, so it sees routed output
  after the rewrite.
- **What it does.** The same thing the fast path does: on any segment with
  SYN set (SYN and SYN-ACK), lower the MSS option to the configured value
  if it is higher, and patch the checksum incrementally. Malformed options
  are left alone. A `clamped` count appears in the node's trace.
- **No prefix scope.** It clamps every TCP SYN on the interface. VPP has no
  prefix-scoped MSS clamp.
- **One upstream bug in 26.10.** The IPv4 dual-packet loop applies the
  first packet's interface value to the second packet as well. It is
  harmless while every clamped interface uses the same IPv4 MSS, and wrong
  otherwise. Fixed upstream on 2026-11-18 (`d3f8893947`, "mss_clamp: fix
  IPv4 vector MSS interface"), after 26.10.

vpp-offload's `startup.conf` disables only the DPDK plugin, so `mss_clamp`
loads wherever the VPP build ships it. Whether a given build ships it is a
packaging question, not one PacketFrame can assume (see Open questions).

## Where a steered packet crosses a VPP interface

To clamp in VPP, the clamp has to sit on an interface every affected SYN
crosses. For a VLAN carrying the clamped prefix's hosts:

- **Outbound** (a customer's SYN): it arrives on the trunk's VF, is
  classified to the `<port>.<vid>` subinterface, and is routed. On a
  bridged VLAN the subinterface is an L2 member and the packet is routed
  from the BVI (`loop<vid>`); otherwise it is routed from the subinterface
  itself. Either way it enters `ip4-unicast` on one known interface: the
  VLAN's **L3 interface**.
- **Return** (the remote's SYN-ACK, or an inbound SYN): it is routed to a
  host on the VLAN and leaves through `ip4-output` on the same L3
  interface.

So RX + TX on the VLAN's L3 interface covers both directions of every
flow to or from hosts on that VLAN, whichever port it entered through.
That holds only while the prefix is bound to a VLAN. For a clamp scoped to
an egress port (`mss-clamp via <iface>`), TX on that port's VPP
interface is the equivalent.

## The options

### 0. A load-time guard (with any option below, or alone)

Refuse a steer plan that would divert traffic a fast-path `mss-clamp`
covers, naming the directive and the remedies. This is the same rule
`direction dst` already follows for uncovered local prefixes: a silent
loss of policy is a load-time refusal, not a canary discovery.

Coverage, per steered port and direction:

| `mss-clamp` form | Diverted, so refused, when |
|---|---|
| `<cidr> <mss>` / `<cidr> via <if> <mss>` | a `src` side diverts an allowlisted prefix overlapping `<cidr>` and no source opt-out covers the overlap; or a `dst` side does and no `steer-exempt` covers it |
| `via <if> <mss>` | `<if>` is a member port (VPP may route out of it), and anything is steered |
| `<mss>` (global) | anything is steered |

IPv6 is judged by `v6-divert`: a v6 clamp prefix on a box that diverts
IPv6 by frame on any VLAN cannot be shown not to cross VPP, so it counts
as covered by that diversion.

The guard would be a pure function in `steer.rs` beside the plan, with a
`feasibility` row and the same refusal text in `packetframe reconfigure`.
It is small, and it is worth shipping first whatever else is chosen: it
turns a silent loss of policy into an error message, which is what the
gateway's config comments currently do by hand.

### A. Clamp in VPP, per VLAN (`mss_clamp` on the VLAN's L3 interface)

New vpp-offload grammar, explicit rather than derived from the fast
path's prefixes, because VPP's scope (an interface) is wider than the
fast path's (a prefix):

```
mss-clamp vlan <vid> <mss> [ip6 <mss>]      # RX + TX on that VLAN's L3 interface
mss-clamp port <port> <mss> [ip6 <mss>]     # TX on a port's VPP interface (`via` forms)
```

The guard (option 0) accepts a fast-path `mss-clamp <cidr>` as covered
when a `local-route` binds `<cidr>` to a VLAN that carries a VPP clamp at
or below the fast path's value. It accepts `via <if>` when a `port` clamp
is configured on `<if>`.

What it takes:

- Vendor `mss_clamp.api.json`. It is a plugin API, so its messages must
  be **optional** in the CRC handshake: looked up only when a clamp is
  configured, and refused by name at attach ("this VPP has no mss_clamp
  plugin") when one is configured and the plugin is missing.
- Attach and adoption: enable the clamp after the subinterface or BVI
  exists. On an adopted VPP, read it back with `mss_clamp_get` and
  re-assert it, as attach already does for up/unnumbered. `vlans all`
  trunks that grow a subinterface at runtime get it there too.
- Hot reload: enable, disable or change the value on `reconfigure`. It is
  one API call per interface and needs no barrier walk.
- Status: one row listing the clamped interfaces and values as VPP
  reports them, and a drift line when VPP's readback disagrees with the
  config.
- Until VPP carries the upstream fix: refuse configs whose IPv4 clamps use
  more than one value (or warn, and say why).

What it does not do:

- **Prefix precision.** Every host on the VLAN is clamped, not just the
  prefix. For a VLAN that carries only the clamped prefix, which is the
  usual case for a customer VLAN, the two are the same thing. Where they
  differ, the guard still refuses unless the operator also gives the
  wider scope.
- **Prefixes not bound to a VLAN.** A clamp on a remote prefix (one
  reached through transit) has no stable VPP interface to sit on. The
  guard keeps refusing those, and option B is the remedy.

Cost: moderate. It adds an optional API, attach and adoption wiring,
reload and status. It is the only option that keeps the clamped prefix's
traffic on VPP.

### B. A source-prefix opt-out (`steer-exempt … src`)

Extend `steer-exempt` with a side:

```
steer-exempt <cidr> [dst|src|both]      # dst stays the default
```

A `src` entry is one more `Keep` rule matching the source address,
`IP_USER_FLOW` like today's exemptions, planned on every port with a
`src` side. Keeps already take the lowest locations, so they outrank
every diversion by construction (`RuleSet::plan`). The clamped prefix's
outbound stays on the kernel path, where the fast path clamps it. With
the existing `dst` exemption for its inbound, the prefix never enters
VPP, and the rest of the trunk steers.

What it takes:

- Grammar (`config.rs`), a `Side` on each exemption, and planning the
  keep on the `src` side. The guard (option 0) counts `src` exemptions as
  cover.
- One MCAM slot per entry per port with a `src` side. The budget message
  already itemises `steer-exempt`.
- Nothing in VPP.

What it does not do:

- **Offload the prefix.** Its traffic stays on the kernel path (with the
  eBPF fast path in front). That is the point of the opt-out, and also
  its price.
- **IPv6.** The NIC cannot match a v6 address (`steer.rs`, "IPv6: by
  frame"), so there is no v6 source opt-out. For a v6 clamp, the remedy
  is leaving that VLAN out of `v6-divert`, which is already per VLAN and
  does not blackhole.

Cost: small. It is the existing exemption machinery with one more side.

### C. A prefix-scoped clamp in PacketFrame's own VPP plugin

PacketFrame already builds a VPP plugin (`pf-sampler`). A node on
`ip4-unicast` / `ip4-output` with an LPM lookup on source or destination
could clamp by prefix, matching the fast path exactly.

Not recommended. It is a new data-plane node, with its own correctness
and performance testing, in a plugin whose job today is sampling. It is
also redundant with A wherever a prefix maps to a VLAN, which is the case
that comes up. It is listed so the choice is explicit.

## Decision

The operator chose **option 0, then option A**. B stays on this page as
the stopgap it would have been.

Why A over B for the reference deployment:

- The clamped prefix is bound to one VLAN by a `local-route`, so a clamp
  on that VLAN's L3 interface covers exactly it.
- It uses one MSS value, so the 26.10 dual-loop bug does not bite. The
  one-value restriction stays until the VPP build carries the fix.
- The VPP build in use ships `vpp-plugin-core`, `mss_clamp` included.
- B would leave that prefix, most of what its trunk carries, on the
  kernel path.

## Open questions

- **Does every VPP build ship `mss_clamp_plugin.so`?** fd.io's packages
  do (`vpp-plugin-core`), and so does the reference deployment's build.
  A build without it is refused at attach only when a clamp is
  configured.
- **Is RX on a BVI the right hook for every bridged layout?** It is by
  VPP's arc layout (routed input on the BVI enters `ip4-unicast` there).
  Before building A, confirm it with a packet trace (`trace add`, a SYN
  from a host on the VLAN) on the reference deployment.
