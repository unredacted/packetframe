# flow-export — sampled telemetry to flow collectors

How to run the `flow-export` module: what it samples, setting up
Akvorado and FastNetMon, the rate and what it costs, how to read its
coverage, and what to do when a row is not green.

> **Experimental.** Every piece is tested in CI and in root end-to-end
> tests: fast-path's real XDP program, a real sampler tmpfs with a stand-in
> VPP, and veth traffic through the kernel sampler. **None of it has run
> on a router yet.** A combined lab session is owed, and so is the
> hardware cost row for the XDP sampler. Start on a lab box.

## What it is

UniFi's own NetFlow cannot see what PacketFrame forwards. Generic-XDP
redirects bypass conntrack and packet taps, and VPP-steered packets
never reach Linux. flow-export samples **every path PacketFrame runs**
and sends what it samples to flow collectors:

| Path | Sampler | Status row | IPFIX domain |
|---|---|---|---|
| fast-path XDP | inside fast-path's XDP program | `xdp` | 2 |
| fast-path tc | the same, in its tc program | `tc` | 2 |
| VPP | the `pf_sampler` plugin, through a size-limited tmpfs | `vpp` | 3 |
| kernel | flow-export's own tc-ingress program, on `kernel-sample` interfaces | `kernel` | 1 |

Each packet is sampled once, by the path that sees it first. A port
that fast-path and VPP both serve is one sFlow data source: one sample
sequence across both paths, and one pool counting what either could
have sampled.

Two formats:

- **sFlow v5**: each sample's leading packet bytes. Takes every kind of
  collector, and is the only format for `kind ddos`.
- **IPFIX flow records**: samples aggregated per flow, with privacy
  profiles and origin AS numbers. Statistics collectors only.

Telemetry never affects forwarding. A failure to start degrades the
module and leaves the rest running. Every later failure is a status
row. Stopping the module stops every sampler.

## Config in one screen

```
module fast-path            # first: the samplers are fast-path's programs
  ...
module vpp-offload          # if present, also before flow-export
  ...
module flow-export
  source-address 192.0.2.1                 # RESTART-ONLY; must be this host's
  sample-rate 1000                         # hot; 100..16777216, default 1000
  header-bytes 128                         # hot; 64..256
  # collectors: hot; at most 8, each in source-address's family
  collector fnm sflow 198.51.100.10:6343 kind ddos
  collector akv ipfix 198.51.100.11:4739 kind stats profile truncate
  privacy-local-prefix 203.0.113.0/24      # hot; default: fast-path's allowlist
  flow-cache entries 65536 active 60 inactive 15   # hot; IPFIX only
  kernel-sample tun0                       # RESTART-ONLY; repeatable
```

`packetframe feasibility --config …` checks the parts that need the
host:
- `source-address` is this host's;
- VPP's sampler directory and plugin;
- each `kernel-sample` interface;
- fast-path's `helper.bpf_perf_event_output` and `map.perf_event_array`.

## Collectors

**Every collector:** `source-address` is the address it keys this
exporter on. Keep it stable: changing it is a restart, and to the
collector it is a new device.

### Akvorado

- **sFlow or IPFIX.** Both scale exactly once
  (docs/flow-export/collectors.md).
- **IPFIX needs `inlet.kafka.load-balance: by-exporter`.** With the
  default `random`, a data message can be decoded before the one that
  carries its template, and is dropped.
- **Interface names.** With no SNMP, give it a static metadata provider:

  ```
  packetframe flow-export interfaces --config /etc/packetframe/packetframe.conf \
    --default-speed 1000 > /tmp/akvorado-static.yaml
  ```

  - The output lists every port flow export samples (fast-path's, VPP's
    and the `kernel-sample` interfaces), and every interface fast-path
    can redirect to: a redirected sample names its egress interface as
    its output.
  - Akvorado requires a speed for each interface. Where the kernel
    reports none (a link that is down, many virtual ones), pass
    `--speed <iface>=<Mbps>` or `--default-speed`.
  - `--default-speed` also adds a catch-all entry, so an interface that
    comes up later doesn't make Akvorado discard its flows.
  - Merge the output into `outlet.yaml`'s `metadata.providers`.

### FastNetMon (Community)

- **sFlow only** (`kind ddos`). Its 5 s detection window has not been
  qualified against IPFIX records, which arrive only when a flow times
  out.
- **Bytes.** FastNetMon counts sFlow's `frame_length`, which is on the
  wire, FCS included. `sflow_read_packet_length_from_ip_header = on`
  makes it count the IP layer instead, as Akvorado does.
- **It lifts bans when telemetry stops.** It cannot tell silence from
  calm. That is what coverage (below) is for; the withdrawal hold that
  consumes it is Phase 2.

## Rate and cost

- **1:1000 is the qualified rate,** and the default. Down to 1:100 is
  accepted, and reported over budget: in the `sampling` row, and as
  the `over_budget` gauge reading 1.
- **What it costs, measured:**

  | Path | 1:1000 | 1:100 |
  |---|---|---|
  | VPP on octeon (Phase 0) | −3.4% drop path, −2.5% forward path | −4.7%, −5.9% |
  | fast-path XDP | +1.8–3.1% CPU per packet, in a VM | not measured |

  The XDP numbers on hardware are owed.
- **A rate change is a reload,** and the samples carry the rate and
  generation they were drawn at, so nothing in flight is mislabelled.
  - `packetframe reconfigure` returns once fast-path's sampler, and the
    kernel sampler's, run the new values. A change either cannot take
    fails the reload and leaves both as they were.
  - `systemctl reload` only sends the SIGHUP and doesn't wait. Before
    acting on the new rate, read the `sampling` row, which names the
    generation that runs.
  - A worker too busy to answer within a second fails the reload,
    though it may have taken it: the `sampling` row says which.
  - VPP's plugin takes it from the next `desired.conf`, and the `vpp`
    row reads Degraded until it has.
  - IPFIX exports every flow counted at the old rate before it
    announces the new one.

## Pools, GRO and VLANs

- **Pools.** A port's pool is its kernel `rx_packets` while fast-path or
  the kernel sampler is on it, plus VPP's own count of the packets it
  received there. The two don't overlap: steered ingress reaches VPP's
  VF before the kernel counts it. So a collector scales correctly
  whether or not every sample arrives.
- **GRO.** `rx_packets` counts wire packets, while generic XDP and tc
  see GRO aggregates. With GRO on, a sampled aggregate stands for
  several wire packets, and per-flow packet counts read low. For exact
  counts, turn GRO off on the port (`ethtool -K <iface> gro off`). What
  GRO-on looks like in practice is owed from the lab.
- **VLANs.** A tag the NIC offloaded is put back into the exported bytes
  for tc and the kernel sampler, and counted in `frame_length`. A
  priority tag (VID 0) is kept as one. XDP reports what generic XDP is
  given.

## Reading coverage

Coverage is judged per port and path, in 5 s windows. It is
deliberately pessimistic, because the DDoS mitigation will act on it.
The `coverage{iface,path}` gauge reads 3 covered, 2 starting, 1
degraded, 0 uncovered.

| State | Means |
|---|---|
| `starting` | inside the startup grace: 30 s, or 60 s for VPP ports |
| `covered` | samples arrive and nothing was lost |
| `degraded` | samples were lost in the window. Recovery takes 3 clean windows |
| `uncovered` | either more than 1% lost for 3 windows, or a busy port (≥256 sampling gaps' worth of packets) gave no sample at all |

Two more rules sit over those:

- **VPP ports answer to the plugin, after their grace.** Past its 60 s
  startup grace, whatever its own samples show, a VPP port is degraded
  while the plugin is, and uncovered while the plugin is unavailable,
  disabled or incompatible, or its interface is missing from VPP.
  During the grace the port and its gauge read starting, whatever the
  plugin's state, since VPP's interfaces appear after it starts. The
  `vpp` row reads the plugin's state throughout: it is what to watch
  in the first minute.
- **A stalled worker uncovers everything.** If the worker hasn't ticked
  for over 1 s, or it panicked, every port reads uncovered and the
  coverage gauges read 0.

**Collector rows report local submission only:** the send succeeded.
Whether the collector received it is the collector's to know. A
collector reads Degraded for 10 s after a send fails with none
succeeding since, or after datagrams were dropped because a tick's send
budget (512 per collector) ran out.

**For other modules:** the same states are published through a
`FlowCoverage` handle. A snapshot older than 1 s reads as nothing, and
collector results are always marked `receipt: unverified`.

## Privacy profiles and AS numbers (IPFIX)

An address is local when inside `privacy-local-prefix`, which defaults
to fast-path's `allow-prefix` lines. The default changes with a reload
fast-path accepts, never one it refused.

| Profile | Sends |
|---|---|
| `full` (default) | addresses as observed |
| `truncate` | each non-local address cut to /24 or /48 |
| `no-remote` | local addresses only. A transit flow carries none |
| `as-only` | no addresses: the AS pair, ports and protocol |

- **sFlow takes `full` only.** It carries headers as they were. A
  collector is refused rather than sent more than its profile allows.
- **The flow cache.** A flow is exported `inactive` seconds after its
  last sampled packet, or `active` seconds after its first, timed from
  when each packet was sampled rather than when it was read.
  - A full cache exports its oldest flow. Lowering `entries` on a
    reload exports the excess a few thousand flows a tick.
  - A stop sends every flow still counting, for up to half a second;
    what is left then is logged.
- **AS numbers.** Every IPFIX record carries its addresses' origin ASes,
  from fast-path's BGP or BMP route source (`forwarding-mode
  packetframe-fib`, or `compare`, with a `route-source`).
  - The origin comes from the same LOCAL_PREF tier as the forwarding
    nexthops: the route's last AS, or the peer's (this network's own, on
    an iBGP or Loc-RIB feed) for a route with no path.
  - A route whose origin is unknown reads 0, never the AS of a covering
    route: an aggregate whose path ends in an AS set, or a route seeded
    from the ledger at startup until its session announces it again.
  - Without a route source, the AS fields are 0 and `as-only` is
    refused. With one, an IPFIX collector a reload adds gets AS numbers
    at once.

## VPP

- **Ownership.** flow-export owns the plugin's `desired.conf` while it
  runs.
  - `packetframe sampler configure` and `clear` are refused meanwhile
    ("desired.lock is held"), as is `packetframe sampler watch` ("another
    consumer holds consumer.lock").
  - Use `packetframe sampler status`, which only looks.
- **Reading samples.** A sample is read only through the port list of
  the VPP process that wrote it. After a VPP restart, samples before
  the new port list is published are counted as unmapped, and
  degrade VPP coverage.
- **Installing the plugin.** The arm64 `.deb` installs it at
  `/usr/lib/packetframe/vpp_plugins/pf_sampler_plugin.so`, and the arm64
  gnu tarball carries it under `vpp_plugins/`. `packetframe feasibility`
  says whether it was built for the VPP that runs. VPP refuses a
  mismatched plugin without failing to start.

## Kernel sampler

- **What it's for.** `kernel-sample <iface>` is for traffic only the
  kernel handles, such as a tunnel or a port with no fast-path program.
- **Refusals.** It is refused on fast-path ports, VPP ports, `pfpunt0`,
  loopbacks, and any device stacked on a sampled port, another
  `kernel-sample` interface included: a VLAN or bridge over it would see
  those packets a second time.
- **The filters.** They are recorded in
  `<state-dir>/flow-export-tc-links.json`, which is read only if this
  daemon's own account could have written it.
  - Stopping the module, `packetframe detach` and `detach --all` remove
    them. Each interface is found by its ifindex, so one renamed since
    is not missed.
  - A start removes any a daemon that died left, with or without
    `kernel-sample` lines of its own.
  - By hand: `tc filter del dev <iface> ingress`, then the file.

## Triage by symptom

| Row says | Look at |
|---|---|
| `uncovered: N packets and no sample` | The sampler isn't running on that path. For XDP or tc, is fast-path attached to the port? For kernel, is the filter in `tc filter show dev <iface> ingress`? |
| `vpp: sampler unavailable: heartbeat … old` | VPP is down, or the plugin isn't loaded: check `packetframe feasibility`'s `flow-export.vpp.plugin` row, then `show plugins` in vppctl |
| `vpp: … desired generation X, applied Y` | The plugin hasn't taken the newest `desired.conf` yet: transient after a reload or a VPP restart. If it lasts, the plugin isn't reading it. A refusal reads `desired.conf generation N refused (…, line L)` instead |
| `vpp: sampler unavailable: sampler directory: …` | vpp-offload's `sampler-dir` row says why the tmpfs isn't usable |
| `degraded: N samples lost in the last 5 s` | Rings filled faster than the worker drains them. Check the `rate`, and `samples_lost_total{where}` for where |
| collector `sends failing: …` | The send itself was refused: no route to the collector, or `source-address` gone from this host |
| collector `datagrams dropped: the per-tick send budget was spent` | Bursts of more than 512 datagrams a tick. `send_budget_drops_total` counts them |
| `worker: the export worker panicked` | Telemetry stopped and the samplers were turned off. The reason is in the row; restart the daemon |

Metrics are under `packetframe_flow_export_` in the textfile.
`packetframe events` keeps the module's history as it does any
module's: its attach or start failure, reconfigure outcomes and health
transitions.
