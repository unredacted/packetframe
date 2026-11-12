# Design: steering a fresh VPP before its table is complete

Status: **proposal, not built.** The go/no-go is the operator's call. This
page sets out what the change would be, what it would cost, and what could
go wrong.

## The problem

After a reboot or upgrade, a fresh VPP's first route load is the longest
step between PacketFrame's start and VPP steering. On edge1-mci1 (11-05)
it took about 3.5 min under load, against about 65 s idle. During that time
every packet goes through the eBPF tier. On that box the tier runs in
xdpgeneric mode, because rvu-nicpf on kernel 5.15 has no native XDP, so it
saves little CPU and every core stays near 100%.

Today steering waits for the whole table, and nothing else is possible:
- verify must vouch for it;
- the fresh hold must release;
- the first-steer hold must find the drain caught up.

A steered packet whose destination VPP has no route for is **dropped**
(`runtime.rs`, the IPv6 handback gate's refusal text). The existing hand-back
path (`handback.rs`) only returns IPv6 addressed to the router itself.

## The proposal

1. **Load longest prefixes first.** A fresh load sends /32 down to /0 for
   IPv4, and /128 down to /0 for IPv6, instead of address order.
2. **Hand every FIB miss back to the kernel.** VPP gets a default route
   (`0.0.0.0/0`, and `::/0` under `v6 on`) whose path leaves through the
   hand-back veth to the kernel. The kernel holds the full table (FRR's
   zebra installs it) and forwards the packet itself.
3. **Steer as soon as the loaded subset passes the door, integrity and
   verify rules**, applied to that subset.

The correctness argument: with longest-first loading, every route VPP holds
has every more-specific route under it already loaded. So a packet either:
- matches a loaded route, which is its true longest match; or
- misses, and the kernel forwards it by the full table.

Live deltas keep that true only if they respect the load's frontier, the
prefix length the load has reached:
- **An addition longer than the frontier** is safe to install at once:
  everything below it is already loaded.
- **An addition at or shorter than the frontier is not.** While the
  frontier is /24, a newly advertised /20 installed at once would capture
  traffic for a /21 beneath it that has not loaded yet, which should still
  miss to the kernel. Such an addition has to wait in the load's queue
  until every more-specific route under it is in, or be installed as a
  hand-back route until then. Today's `ConvergenceEngine::apply_changes`
  has no such filter: it applies every delta as it comes.
- **A withdrawal** removes the route from VPP, and its traffic falls to
  whatever covers it, in VPP or in the kernel.

## Where it breaks, and what each break would need

### 1. A route that is advertised but not installed (unresolvable)

This is the 11-05 case, with 486k routes via 194.110.60.50 unresolvable for
minutes.
- Today such a route is simply absent from VPP.
- Under early steering, its traffic would match a **shorter loaded route**
  through a different next hop, and be forwarded the wrong way, silently.
- Longest-first does not prevent this; it is a hole below a loaded route.

**Needed:** an unresolvable route must be installed as a hand-back route (a
path to the kernel), not left absent, and swapped to its real path once the
next hop resolves. That is a change to the sink's state machine: a new
installed-via-handback state, with verify and the ledger counting it. It is
also the larger part of the work.

### 2. The order loads the least-used routes first

- About 60% of the IPv4 table is /24s, and longer prefixes are a few
  percent.
- Traffic concentrates on the shorter aggregates (content networks' /16 to
  /22s), and those load **last** under longest-first.

So early steering would send most traffic VPP → veth → kernel for most of
the load. That costs **more** than not steering: the kernel still forwards
every packet, and VPP plus the veth come on top.

The benefit begins only when the loaded subset covers most of the traffic.
That needs a coverage gate, for example "the loaded subset matches at least
X% of the flow sampler's recent destinations". Its estimate is noisy
straight after a reboot, when the sampler has little history. Without
traffic data from mci1 the size of the window is unknown. It may be a small
fraction of the load time.

### 3. Handed-back traffic bypasses the vendor firewall

What arrives on `pfpunt0` is not seen by the vendor's WAN rules, which key
on the physical WAN ports. That is why today's hand-back carries a guard ACL
in VPP admitting only replies to the router's own addresses.

A FIB-miss hand-back carries **forwarded** traffic in both directions, so
it needs one of these:
- a guard that reproduces the vendor's forwarding policy, which the vendor
  rewrites on every config apply; or
- an argument that the policy does not apply. On a pure transit box it
  mostly does not. But customer VLANs, the UniFi IPv6 SNAT and any
  `WAN_IN` rules would be bypassed for whatever misses.

### 4. Kernel-side handling of the veth

- **rp_filter:** strict reverse-path filtering on `pfpunt0` drops handed-back
  packets whose source routes out a physical port. It would need loose mode
  on `pfpunt0`.
- **Conntrack and NAT:** rules keyed on the ingress interface (the UniFi
  IPv6 SNAT is one) see `pfpunt0`, not the port the packet came in on.
- **Hop limit:** VPP decrements TTL / hop limit and the kernel decrements
  it again. A traceroute shows an extra hop, and a packet arriving at TTL 2
  dies one hop early. That is minor, but visible.
- **Policy routing keyed on ingress.** The kernel picks a table by its
  rules (RPDB) before it routes. A rule matching the ingress interface
  (`ip rule iif …`), an l3mdev/VRF, or a mark set from the physical
  ingress sees `pfpunt0` instead, with no VRF and no mark, and can choose
  another table: the packet leaves by the wrong egress, silently. UniFi
  installs such rules, and the drift scanner already walks policy-selected
  tables and VRFs because supported hosts use them. The hand-back would
  need either to carry that context (a mark per original port, matched by
  rules mirroring the ingress ones) or a gate that refuses early steering
  on any host whose RPDB depends on ingress. Loose `rp_filter` and
  attention to conntrack/NAT do not cover this.

### 5. Cost of the hand-back path

The hand-back is VPP af_packet → veth → kernel stack forwarding:
- No XDP fast path on the way. `pfpunt0` could take native XDP (veth
  supports it), but `XDP_REDIRECT` onward needs `ndo_xdp_xmit` on rvu-nicpf,
  which it lacks. So every missed packet takes the kernel's slow path, below
  even xdpgeneric.
- af_packet in VPP is one queue on one worker.

At mci1's packet rates this path would saturate a core well before the
eBPF tier does. Early steering would then have to stop at the hand-back
path's own limit. That limit is unmeasured.

### 6. Verify

Today's verify samples routes from the mirror and checks them in VPP
(`verify.rs`). For a subset it would also need to check:
- **The frontier.** Every route longer than the current frontier length is
  installed, and none at the frontier is unresolvable, via the ledger's
  counts per prefix length.
- **The hand-back default.** It is present, and its path is the veth.
- **No stale route below a loaded one.** A sample cannot show this:
  verify draws its probes from the ledger (`RouteLedger::verifiable_prefixes`),
  so a prefix that exists only in VPP is never probed. A stale
  more-specific there would override its loaded covering route and keep
  the hand-back default from ever being chosen. This needs an exhaustive
  check: a dump of VPP's FIB diffed against the ledger at the frontier,
  as the adopted path's readback already does, not a larger sample.

What verify cannot cover is (2) and (5), whether steering early is a net
gain. Those are traffic properties, not table properties.

## Recommendation

**Not yet.** What the load costs is now measured (efg1-lab1-net,
2026-11-12, [#388](https://github.com/unredacted/packetframe/pull/388)):

- **Idle:** a million IPv4 routes take about 30 s (about 33,000/s), and
  the lab's 170,291 take about 5.5 s.
- **What bounds it:** VPP's main thread, at 100% for the whole load.
  Sending faster bought 7% idle and nothing under contention.
- **Under contention:** the load slows in proportion to the main core
  VPP loses. One equal-priority competitor halves it, and six nice -20
  hogs on the main core made it 4× slower.

So on mci1 the 3.5 min under load is mostly VPP's main thread not getting
its core. Keeping other work off that core during the load (cpuset or
AllowedCPUs for the other slices) would bring it toward the idle
figure, about 35 s for mci1's table, with none of the hazards above.
Early steering could save at most a part of that, at the price of (1),
(3) and (4).

If the core isolation lands and the load is still long, the next step is
evidence, not code. Take mci1's traffic split by destination prefix
length from the flow sampler, and measure the hand-back path's packets
per second on the lab. Together they say whether a coverage gate would
ever open early enough to matter.

If the operator wants it built regardless, the order would be:
1. **A forwarding hand-back path.** Today's path exists only under `v6 on`,
   carries IPv6 only, and its guard admits only replies to the router's own
   addresses, so it cannot carry forwarded traffic. This step needs an
   IPv4-capable veth built whatever `v6` says, the kernel settings (4), the
   ingress-context handling or gate for policy routing (4), and a forwarding
   guard (3). Everything below routes into this path, so it comes first.
2. (1), unresolvable → hand-back routes. Useful on its own once step 1
   exists: a late neighbour's routes would forward through the kernel
   instead of being absent.
3. The longest-first fresh load, with additions at or shorter than the
   frontier held back until what is under them has loaded.
4. The hand-back default.
5. The subset verify (6), with the FIB dump.
6. A coverage gate (2).
