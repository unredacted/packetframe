# Changelog

All notable changes to PacketFrame are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The release workflow publishes the section for the tagged version as the
GitHub release notes. It refuses a tag whose version disagrees with
`VERSION` and the workspace `Cargo.toml`, or whose section is missing.
Every section heading must be exactly `## [X.Y.Z] - YYYY-MM-DD` or
`## [X.Y.Z] - UNRELEASED`. A final (non-prerelease) tag needs the dated
form. To cut a release, replace `UNRELEASED` with the date, then push
the tag. Only a pushed `v*` tag publishes; a manual workflow run is
always a dry run. Releases up to 0.2.7 predate this file; their
notes are on the [releases page](https://github.com/unredacted/packetframe/releases).

## [0.5.0] - UNRELEASED

The first release since 0.2.7 (2026-05-20), about 220 commits. It adds
three modules — vpp-offload, neigh-snoop and guard — and a persistent
event log. Code comments cite versions 0.2.8, 0.2.9 and 0.2.10. None of
those shipped; that work is part of 0.5.0, which is the next version
after 0.2.7. Read **Upgrade notes** and **Known limitations** before
installing.

### New modules

#### vpp-offload

This module moves forwarding for the steered ports into a VPP instance
on a NIC virtual function. It runs in production on the reference
deployment, steering IPv4 and IPv6 in both directions. See
`docs/runbooks/vpp-offload.md`.

- It supervises the VPP process: startup config, core placement, and
  moving IRQs off VPP's cores. The binary API is checked by a CRC
  handshake at attach, so the module is not tied to one VPP build.
- The route feed comes from fast-path's resolved FIB, including the
  `fallback-default` route. It has a convergence engine with a measured
  budget, readback verify, and a drift scan.
- NIC MCAM steering (`port … steer on`) with per-port `direction
  src|dst|both`, trunk mode (`vlans all`) and bridged VLANs through a
  BVI. `steer-capacity` asks the driver for a larger rule table. The
  steering lever is hot-reloadable, so traffic can be taken off VPP
  without a restart.
- Kernel exemptions and the exemption tripwire for kernel paths VPP
  cannot take (tunnels, policy routes). `steer-exempt` keeps chosen
  destinations on the kernel path, and the tripwire reports kernel
  routes VPP lacks.
- `local-route` / `local-route6` deliver traffic to hosts on attached
  VLANs. Attached routes follow their VLAN's interface at runtime. VPP
  resolves never-seen neighbours itself (glean), and the glean and
  ARP-reply counters are exported.
- IPv6:
  - `v6 on` loads the IPv6 table into VPP.
  - `v6-divert <vlans>|untagged` on a `port` line diverts TCP and UDP
    over IPv6 addressed to the router's MAC on the listed VLANs.
  - `steer-keep6` keeps services that accept new sessions on the kernel
    path.
  - `loopback-address6` gives VPP a global source address for its
    ICMPv6 errors.
  - `drift-accept6` acknowledges an IPv6 drift finding so it does not
    stay a permanent red row.
  - The IPv6 exemption tripwire.
- The IPv6 hand-back path returns router-owned IPv6 that a `v6-divert`
  rule sent to VPP. It is a veth pair that VPP opens as an af_packet
  host interface, plus a /128 in VPP for each of the host's global
  addresses. It is guarded inside VPP by a stateless ACL, not by
  nftables. The ACL admits only replies: TCP with ACK or RST set, and
  UDP from DNS or NTP servers to the kernel's ephemeral ports. BGP (TCP
  179, both directions) and DNS (TCP/UDP 53) are built-in keeps that
  never enter VPP.
- `packetframe detach --keep-vpp` restarts the daemon while VPP keeps
  forwarding. When the stopping daemon preserves its route ledger, the
  next daemon adopts VPP from that ledger with no FIB dump, and the
  restart stays steered with no unsteered window.
  - There is a fallback, the dump path. The next start reads VPP's FIB
    instead, and traffic moves to the eBPF tier while it does. That
    happens in three cases: the stopping daemon does not finish writing
    the ledger within its 5 s budget (a slow or wedged supervision loop
    at stop), the stopping binary predates the ledger (any upgrade from
    a build without it), or the ledger no longer matches VPP. On the
    reference router with a 1.1M-route table, the readback took about 3
    minutes. Before the ledger existed it took longer.
  - To see which path ran, run `packetframe events`. The
    `ledger_preserved` event at stop shows `preserved=true` or `false`.
    The `adoption_path` event at start shows `path=preserved-ledger`, or
    `readback` / `readback-deferred` for the dump path. A
    `preserved_ledger_rejected` event says why a ledger was not used.
    The journal logs the same.
- The health surface shows per-port rows in `packetframe status`, gauges
  in the metrics textfile, and remedies that name commands the module
  accepts.

#### neigh-snoop

A passive ARP/ND neighbour snooper for IX-facing bridges. It runs in
production on the reference deployment. See `docs/runbooks/neigh-snoop.md`.

- Receive-only AF_PACKET with a cBPF filter. It learns third-party
  address-to-MAC pairs, installs them as `NUD_STALE`, and never
  overrides a confirmed entry.
- The table is persisted per bridge (`persist-dir`, `seed-max-age`), and
  bridges are tracked by name so a recreated device is picked up again.
- `bridge <iface> ix-mode` stops fast-path's resolver from sending
  proactive probes on that bridge.
- `frr-gate` reconciles FRR's next-hop prefix-lists from what was
  learned and measures route-server coverage.

#### guard — EXPERIMENTAL

A tc-egress frame policer for IX-facing interfaces. It rate-limits
ARP requests and neighbour solicitations per target, drops LLDP and
frames with a foreign source MAC, and has a broadcast/multicast
catch-all. Each class can run in `monitor` mode or enforce. **It has
not been validated on the reference vendor kernel.** The hardware
monitor→enforce ladder is still owed. Run every class in `monitor` first.
See `docs/runbooks/guard.md`.

### fast-path

- `integrity-authority birdc [path] | frr upstream <ip> … | none` names
  what attests that the route mirror is complete. The default, when the
  directive is absent, is the local `birdc`, as in 0.2.7. The FRR
  authority reads FRR 10's output through `vtysh`, with a configurable
  `interval`. It is read once at start, so changing it needs a restart.
- `route-source bgp … anyip` uses a phantom listen address, so FRR can
  feed routes over iBGP from a non-loopback address.
- `bridge-resolve auto|on|off` is the bridge egress short-circuit, and
  it is **on by default** (`auto`). When a bridge's only forwarding
  member is a VLAN subinterface, fast-path tags the frame and redirects
  it straight to the underlying device. `off` is the rollback and can be
  applied with a reload.
- `fdb-pin auto|on|off` is FDB-pinned direct-to-port egress through a
  multi-member bridge. It is **opt-in**: only `on` arms it, and `auto`
  means off. Restart-only.
- `fib-cache on|off` puts a destination cache in front of the custom-FIB
  lookups. Default off.
- `coalesce [rx-usecs N] [rx-frames N] [tx-usecs N] [tx-frames N]` sets
  NIC interrupt coalescing at attach. The previous values are restored
  by `detach`. Restart-only.
- `local-prefix6`: the connected fast path for IPv6. NDP stays off it.
- A tc-ingress datapath (`attach <iface> tc`, custom-fib only) was built
  and measured. It costs about 70% more CPU per packet than generic XDP
  on the reference hardware, so it is kept for reference and not
  recommended. See `docs/runbooks/tc-datapath.md`.
- Fixes:
  - Only frames addressed to the router are routed.
  - Lost nexthops are re-probed.
  - Redirect targets are tracked live.
  - `status` no longer hides traffic that takes the kernel path.
  - The anyip reconcile no longer dumps the whole FIB.
  - Failed FIB deletes are repaired.
- New counters: the softnet `time_squeeze` export, and `err_parse_tc`
  split by the bounds check that produced it.

### probe

- `vpp.sysctl-hugepages` is a rollout gate with its own verdict bucket.
  It detects a hugepage sysctl that persists across boots, priced at the
  running kernel's page size.
- A flag for per-packet IRQ coalescing.

### Operations

- A persistent event log, **on by default**, at
  `<state-dir>/events.log` (`/var/lib/packetframe/state/events.log`
  unless `state-dir` is set). It records steering, verify, restarts and
  adoption, reconfigure outcomes and health transitions. Read it with
  `packetframe events`, which works without the daemon running. Use
  `event-log <path>|off` and `event-log-max <size>` to change it. See
  `docs/runbooks/event-log.md`.
- systemd unit changes:
  - `StartLimitIntervalSec=300` / `StartLimitBurst=3` cap the restart
    loop.
  - `KillMode=process` stops systemd from SIGKILLing the VPP that
    preserve-on-exit keeps alive.
  - `LogsDirectory=packetframe` creates the directory VPP logs to.
- Restart-required refusals quote the full restart command.
- A vpp-offload failure degrades that module and leaves fast-path
  running.
- Release artifacts now include `CHANGELOG.md`, `conf/example.conf` and
  the runbooks: in the tarball under `docs/runbooks/`, and in the .deb
  under `/usr/share/doc/packetframe/`.

### Upgrade notes

- **No 0.2.7 directive was removed.** A 0.2.7 config parses unchanged.
- **Upgrade sequence:**
  1. `systemctl stop packetframe`
  2. `packetframe detach --all`, run with the **old** 0.2.7 binary,
     before you install.
  3. Install the 0.5.0 package or tarball.
  4. `systemctl daemon-reload`
  5. `systemctl start packetframe`

  fast-path refuses to start over the pins a previous daemon left, and
  the package runs no maintainer scripts. It neither stops nor restarts
  the daemon on its own, because that would bounce the dataplane.
- **`bridge-resolve` now defaults to on (`auto`).** Add
  `bridge-resolve off` to keep 0.2.7's behaviour. While the
  short-circuit is installed on a bridge, `mss-clamp … via <bridge>`
  **no longer matches**: clamp matching keys on the resolved egress
  device. Scope the clamp `via` the underlying device instead, or set
  `bridge-resolve off`. The daemon logs a warning naming both options
  when it detects this.
- **Main-branch builds only:** `v6-outbound` was renamed to `v6-divert`,
  with no alias. Rename it on any `port` line.
- BGP (TCP 179) is a built-in IPv6 keep. A `steer-keep6 tcp 179 …` (or
  `tcp 53`) restates a built-in and is refused by validation.
- vpp-offload's handshake requires VPP's `af_packet` and `acl` plugins.
  A VPP without them fails at attach, naming the missing message.
- Most vpp-offload directives are restart-only: `port` interfaces, cores
  and VLANs (and which ports are `vlans all`), `v6`, `expected-routes`,
  `hugepages`, `local-route`/`local-route6`, `loopback-address`/
  `loopback-address6`, `steer-capacity` and `vpp-binary`. A reload that
  changes one is refused and names the directive. These can be
  reloaded: the steering lever, `direction`/`steer-direction`,
  `v6-divert`, the allowlist, `steer-exempt`, `steer-keep6` and
  `drift-accept6`.
- Installing the VPP package: follow its README exactly. The package
  ships a boot-time hugepage sysctl file that its skip flag does not
  remove. Delete it and confirm it is gone before you reboot. The probe
  `vpp.sysctl-hugepages` gate detects it. See
  `docs/runbooks/vpp-offload.md`.
- **Downgrade:** run the **0.5.0** binary's `packetframe detach --all`
  before installing 0.2.7. 0.2.7 knows nothing of guard's tc filters,
  VPP's MCAM rules, the IPv6 hand-back veth, tc-ingress attachments, or
  the coalescing values `detach` restores. Its `detach` would leave all
  of them in place.

### Known limitations

- A fast-path restart still bounces the link on drivers where XDP
  attach and detach reset the port. Measured on the reference hardware,
  that is a few lost pings over about two minutes per restart. The cause
  is that fast-path does not adopt existing pins across a restart.
- IPv6 steering works by frame, not by address. Only TCP/UDP arriving on
  a VLAN listed in `v6-divert` is offloaded, so IPv6 arriving on an
  upstream VLAN left out of the list stays on the eBPF/kernel tier. List
  every upstream VLAN. The allowlist does not scope what is diverted,
  and diverted IPv6 bypasses the kernel's forward-path netfilter.
- VPP's own glean output (the ARP requests and neighbour solicitations
  it sends) bypasses guard. Guard polices kernel tc egress, and VPP
  transmits past it.
- Native XDP is refused on rvu-nicpf interfaces on kernels without the
  upstream fix (commit 04f647c8e456, Linux 6.8), which includes the
  reference vendor kernel, where native attach panics. Use `generic` or
  `auto`.
- The .deb installs the systemd unit but runs no maintainer scripts. Run
  `systemctl daemon-reload` yourself after every install.
- It is not proven that MCAM steering rules survive a vendor
  provisioning push. They survived one push on a lab box on one firmware
  release. They have not been tested across firmware releases, and there
  is no automatic re-assert if a push strips them.

[0.5.0]: https://github.com/unredacted/packetframe/compare/v0.2.7...v0.5.0
