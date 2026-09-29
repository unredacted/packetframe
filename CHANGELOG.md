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
Versions 0.2.8, 0.2.9 and 0.2.10, which some code comments cite, never
shipped; that work is part of 0.5.0.

## [0.6.0] - UNRELEASED

### Upgrading from 0.5.0

- **`forwarding-mode custom-fib` is now `forwarding-mode packetframe-fib`.** The old name still parses and logs a deprecation warning naming the line; it will be removed in a later release. Update your config at your next edit.
- **Renamed metrics.** The counters `custom_fib_hit`, `custom_fib_miss` and `custom_fib_no_neigh` are now `fib_hit`, `fib_miss` and `fib_no_neigh`, so the textfile exports `packetframe_fib_hit_total` and so on. The mode label reads `packetframe_fib_forwarding_mode{mode="packetframe-fib"}`. Counter indices are unchanged. Update any alert or dashboard that matches the old names.

### Changes

- **New fast-path directive `wan-egress from <cidr> [from <cidr> ...] [keep <cidr> ...]`** (IPv4). On gateways that install the full BGP table into `main` and consult `main` before their own WAN policy rules, with NAT only on the WAN interfaces, private sources whose destination's best path was a peering interface left un-NATed and died. Traffic from the listed sources now skips `main` and continues with the platform's own WAN rules and NAT, except for kept destinations (RFC 1918, RFC 6598, link-local, every `allow-prefix` and `local-prefix`, plus any `keep`), which still use `main`. PacketFrame installs `ip rule` entries tagged `proto 199` just below `lookup main` (a goto past it, with a `nop` anchor when needed), reconciles them at start, on reload, on rule changes and every 30 s, writes nothing when they are already in place, never touches a rule it did not create, and removes them on `packetframe detach`. New `wan-egress` status row, `packetframe_wan_egress_*` textfile gauges and a `wan_egress_repaired` event. See [WAN egress](docs/runbooks/packetframe-fib.md#wan-egress).
- The custom-FIB runbook moved to [`docs/runbooks/packetframe-fib.md`](docs/runbooks/packetframe-fib.md).

## [0.5.0] - 2026-09-28

The first release since 0.2.7 (2026-05-20). It adds three modules (vpp-offload, neigh-snoop, and guard, which is experimental) and a persistent event log. No directive was removed and a 0.2.7 config parses unchanged, but read **Upgrading from 0.2.7** before installing: the upgrade order matters, and one default changed.

### Upgrading from 0.2.7

1. `systemctl stop packetframe`
2. `packetframe detach --all`, run with the **old** 0.2.7 binary. fast-path refuses to start over the pins a previous daemon left.
3. Install the 0.5.0 package or tarball.
4. `systemctl daemon-reload`. The .deb runs no maintainer scripts, so it neither reloads systemd nor stops or restarts the daemon.
5. `systemctl start packetframe`

- **Behaviour change: `bridge-resolve` now defaults to on (`auto`).** While the bridge short-circuit is installed, `mss-clamp … via <bridge>` no longer matches, because clamp matching keys on the resolved egress device. Scope the clamp `via` the underlying device, or set `bridge-resolve off` to keep 0.2.7's behaviour. The daemon logs a warning naming both when it sees this.
- **Installing the VPP package** (vpp-offload only): follow the [vpp-unifi](https://github.com/unredacted/vpp-unifi) README exactly. It ships a boot-time hugepage sysctl file that its skip flag does not remove. Delete the file and confirm it is gone before you reboot; `packetframe feasibility` flags it as `vpp.sysctl-hugepages`.
- **Downgrading:** run **0.5.0**'s `packetframe detach --all` before installing 0.2.7. 0.2.7's `detach` does not know guard's tc filters, VPP's MCAM rules, the IPv6 hand-back veth, tc-ingress attachments or the saved coalescing values, and leaves them in place.
- **Already on a main-branch build running vpp-offload:** install, `systemctl daemon-reload`, then `systemctl stop packetframe && packetframe detach --keep-vpp && systemctl start packetframe`; VPP keeps forwarding throughout. Before that, rename `v6-outbound` to `v6-divert` on any `port` line and drop any `steer-keep6 tcp 179 …` or destination-port `steer-keep6 tcp|udp 53` line (now built-in keeps); 0.5.0 refuses a config with either.

### Highlights

- **VPP offload, in production.** vpp-offload steers IPv4 and IPv6, in both directions, into a VPP instance on NIC virtual functions, with the eBPF fast-path as the failover tier. On the reference deployment (four steered ports, full IPv4 and IPv6 tables), softirq is about 74% of CPU with no bypass and 31–62% with the eBPF fast-path alone. Steering IPv4 into VPP took it to 11–19%, and moving IPv6 in alongside it took it to about 1%. Every figure from the fast-path-only one on is an off-peak reading. [Runbook](https://github.com/unredacted/packetframe/blob/v0.5.0/docs/runbooks/vpp-offload.md) · [Measurements](https://github.com/unredacted/packetframe/blob/main/docs/runbooks/vpp-offload.md#numbers-measured-vs-published-on-faith)
- **Restarts that stay steered.** `packetframe detach --keep-vpp` leaves VPP forwarding, and the next daemon adopts it from the route ledger the clean stop preserved. Measured on the reference deployment: no unsteered window, and VPP is never restarted. [Runbook](https://github.com/unredacted/packetframe/blob/v0.5.0/docs/runbooks/vpp-offload.md#what-a-keep-vpp-restart-costs-now-the-preserved-route-ledger)
- **neigh-snoop** learns neighbours on IX-facing bridges passively and feeds FRR's next-hop gate. In production on the reference deployment. [Runbook](https://github.com/unredacted/packetframe/blob/v0.5.0/docs/runbooks/neigh-snoop.md)
- **Event log.** `packetframe events` shows steering, verify, restarts and health transitions from a persistent log, with or without the daemon running. [Runbook](https://github.com/unredacted/packetframe/blob/v0.5.0/docs/runbooks/event-log.md)

### Changes

**vpp-offload** (new)

- Supervises a VPP process: startup config, core placement, IRQs moved off VPP's cores. Any VPP whose binary-API CRCs match is accepted at attach. ([#105](https://github.com/unredacted/packetframe/pull/105), [#121](https://github.com/unredacted/packetframe/pull/121), [#238](https://github.com/unredacted/packetframe/pull/238))
- Routes come from fast-path's resolved FIB, `fallback-default` included, with readback verify and a drift scan. ([#123](https://github.com/unredacted/packetframe/pull/123), [#266](https://github.com/unredacted/packetframe/pull/266))
- NIC MCAM steering per port: `port … steer on`, `direction src|dst|both`, trunks with `vlans all`, bridged VLANs through a BVI. `steer-capacity` enlarges the NIC's rule table. The steering lever reloads without a restart. ([#127](https://github.com/unredacted/packetframe/pull/127), [#128](https://github.com/unredacted/packetframe/pull/128), [#190](https://github.com/unredacted/packetframe/pull/190), [#249](https://github.com/unredacted/packetframe/pull/249), [#255](https://github.com/unredacted/packetframe/pull/255), [#258](https://github.com/unredacted/packetframe/pull/258))
- `steer-exempt` keeps chosen destinations on the kernel path; the exemption tripwire reports kernel routes VPP lacks, for IPv4 and IPv6. ([#189](https://github.com/unredacted/packetframe/pull/189), [#192](https://github.com/unredacted/packetframe/pull/192), [#281](https://github.com/unredacted/packetframe/pull/281))
- `local-route` / `local-route6` deliver traffic to hosts on attached VLANs. VPP resolves new neighbours itself (glean); glean and ARP-reply counters are exported. ([#190](https://github.com/unredacted/packetframe/pull/190), [#282](https://github.com/unredacted/packetframe/pull/282), [#287](https://github.com/unredacted/packetframe/pull/287))
- IPv6: `v6 on` loads the IPv6 table into VPP. `v6-divert <vlans>|untagged` on a `port` line diverts TCP and UDP over IPv6 addressed to the router's MAC. `steer-keep6` keeps services that accept new sessions on the kernel path; DNS (destination port 53) and BGP (TCP 179, both directions) are built-in keeps. ([#278](https://github.com/unredacted/packetframe/pull/278), [#279](https://github.com/unredacted/packetframe/pull/279), [#280](https://github.com/unredacted/packetframe/pull/280))
- Router-owned IPv6 that `v6-divert` sends to VPP returns to the kernel over a hand-back veth, guarded by a stateless ACL in VPP that admits only replies. ([#283](https://github.com/unredacted/packetframe/pull/283))
- `loopback-address6` gives VPP a global source for its ICMPv6 errors; `drift-accept6` acknowledges an IPv6 drift finding. ([#285](https://github.com/unredacted/packetframe/pull/285), [#288](https://github.com/unredacted/packetframe/pull/288))
- `packetframe detach --keep-vpp` restarts the daemon while VPP forwards. Without a usable route ledger the next start reads VPP's FIB instead, on the eBPF tier meanwhile (about 3 minutes at 1.1M routes); the `adoption_path` event says which path ran. ([#253](https://github.com/unredacted/packetframe/pull/253), [#277](https://github.com/unredacted/packetframe/pull/277))
- Per-port health rows in `packetframe status`, gauges in the metrics textfile, and remedies that name commands the module accepts. ([#114](https://github.com/unredacted/packetframe/pull/114), [#129](https://github.com/unredacted/packetframe/pull/129))

**neigh-snoop** (new)

- Learns third-party ARP/ND pairs on IX-facing bridges from a receive-only socket, installs them as `NUD_STALE`, and never overrides a confirmed entry. ([#212](https://github.com/unredacted/packetframe/pull/212), [#218](https://github.com/unredacted/packetframe/pull/218), [#215](https://github.com/unredacted/packetframe/pull/215))
- Persists its table per bridge (`persist-dir`, `seed-max-age`) and picks up a recreated bridge by name. ([#217](https://github.com/unredacted/packetframe/pull/217))
- `bridge <iface> ix-mode` stops fast-path's resolver sending proactive probes on that bridge. ([#213](https://github.com/unredacted/packetframe/pull/213))
- `frr-gate` reconciles FRR's next-hop prefix-lists from what was learned and measures route-server coverage. ([#216](https://github.com/unredacted/packetframe/pull/216))

**guard** (new, experimental)

- A tc-egress frame policer for IX-facing interfaces: per-target ARP/NS rate limit, LLDP drop, foreign-source-MAC drop and a broadcast/multicast catch-all, each class `monitor` or enforce. **Not validated on the reference vendor kernel**; run every class in `monitor` first. ([#204](https://github.com/unredacted/packetframe/pull/204)–[#207](https://github.com/unredacted/packetframe/pull/207), [runbook](https://github.com/unredacted/packetframe/blob/v0.5.0/docs/runbooks/guard.md))

**fast-path**

- `integrity-authority birdc [path] | frr upstream <ip> … | none` names what attests the route mirror is complete. The default is the local `birdc`, as in 0.2.7; `frr` reads FRR 10 through `vtysh` on a configurable `interval`. Restart-only. ([#173](https://github.com/unredacted/packetframe/pull/173), [#232](https://github.com/unredacted/packetframe/pull/232), [#236](https://github.com/unredacted/packetframe/pull/236))
- `route-source bgp … anyip` listens on a phantom address, so FRR can feed routes over iBGP from a non-loopback address. ([#196](https://github.com/unredacted/packetframe/pull/196))
- `bridge-resolve auto|on|off`: bridge egress short-circuit, on by default (see Upgrading). ([#78](https://github.com/unredacted/packetframe/pull/78))
- `fdb-pin on`: FDB-pinned direct-to-port egress through a multi-member bridge. Opt-in, restart-only. ([#85](https://github.com/unredacted/packetframe/pull/85))
- `fib-cache on`: a destination cache in front of custom-FIB lookups. Default off. ([#79](https://github.com/unredacted/packetframe/pull/79))
- `coalesce …`: NIC interrupt coalescing at attach, restored by `detach`. Restart-only. ([#269](https://github.com/unredacted/packetframe/pull/269))
- `local-prefix6`: the connected fast path for IPv6, with NDP kept off it. ([#72](https://github.com/unredacted/packetframe/pull/72))
- `attach <iface> tc`: a tc-ingress datapath (custom-fib only). It measured about 70% more CPU per packet than generic XDP on the reference hardware, so it is not recommended. ([#75](https://github.com/unredacted/packetframe/pull/75))
- New counters: the softnet `time_squeeze` export, and `err_parse_tc` split by bounds check. ([#184](https://github.com/unredacted/packetframe/pull/184), [#138](https://github.com/unredacted/packetframe/pull/138))

**probe** (`packetframe feasibility`)

- `vpp.sysctl-hugepages` detects a boot-persistent hugepage sysctl, priced at the running kernel's page size. It is a rollout gate with its own verdict bucket. ([#201](https://github.com/unredacted/packetframe/pull/201), [#225](https://github.com/unredacted/packetframe/pull/225))
- Flags per-packet IRQ coalescing. ([#84](https://github.com/unredacted/packetframe/pull/84))

**CLI and operations**

- The event log (`packetframe events`) is on by default at `<state-dir>/events.log`; `event-log <path>|off` and `event-log-max <size>` change it. ([#289](https://github.com/unredacted/packetframe/pull/289))
- The systemd unit caps the restart loop (`StartLimitBurst=3` in 300 s), sets `KillMode=process` so a stop does not kill a VPP kept for adoption, and adds `LogsDirectory=packetframe`. ([#224](https://github.com/unredacted/packetframe/pull/224), [#242](https://github.com/unredacted/packetframe/pull/242))
- Restart-required refusals quote the full restart command. ([#273](https://github.com/unredacted/packetframe/pull/273))
- Release artifacts include `CHANGELOG.md`, `conf/example.conf` and the runbooks. ([#294](https://github.com/unredacted/packetframe/pull/294))
- Built with Rust 1.98.1; building from source needs 1.98 or later. ([#296](https://github.com/unredacted/packetframe/pull/296))

**Fixes**

- fast-path routes only frames addressed to the router. ([#271](https://github.com/unredacted/packetframe/pull/271))
- fast-path re-probes lost nexthops and tracks redirect targets live, and `status` no longer hides traffic that takes the kernel path. ([#220](https://github.com/unredacted/packetframe/pull/220))
- The anyip reconcile no longer dumps the whole FIB, and failed custom-FIB deletes are repaired. ([#223](https://github.com/unredacted/packetframe/pull/223), [#154](https://github.com/unredacted/packetframe/pull/154))
- A vpp-offload failure degrades that module and leaves fast-path running. ([#237](https://github.com/unredacted/packetframe/pull/237))
- `status`, `reconfigure` and `detach` recognise a running daemon when run from a newly installed binary; `detach` no longer proceeds under a live daemon. ([#164](https://github.com/unredacted/packetframe/pull/164))
- `log-level` takes effect and reloads with SIGHUP; 0.2.7 parsed it and ignored it. ([#169](https://github.com/unredacted/packetframe/pull/169))

### Known limitations

- A fast-path restart still bounces the link on drivers where XDP attach and detach reset the port (a few lost pings over about two minutes on the reference hardware), because fast-path does not adopt pins across a restart.
- IPv6 is steered by frame, not address: only TCP/UDP arriving on a VLAN listed in `v6-divert` is offloaded, so list every upstream VLAN. The allowlist does not scope what is diverted, and diverted IPv6 bypasses the kernel's forward-path netfilter. ([runbook](https://github.com/unredacted/packetframe/blob/v0.5.0/docs/runbooks/vpp-offload.md#v6-divert-steering))
- VPP's own glean output (the ARP requests and neighbour solicitations it sends) bypasses guard, which polices kernel tc egress.
- Native XDP is refused on rvu-nicpf interfaces on kernels without upstream commit 04f647c8e456 (Linux 6.8), including the reference vendor kernel, where native attach panics. Use `generic` or `auto`.
- The .deb runs no maintainer scripts: run `systemctl daemon-reload` after every install.
- MCAM steering rules survived one vendor provisioning push on a lab box on one firmware release. Survival across firmware releases is untested. Nothing re-asserts stripped rules automatically; the 30 s readback reports them as `steering DEGRADED`.

### Install and verify

When upgrading, run steps 1 and 2 above first.

```sh
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
curl -LO "https://github.com/unredacted/packetframe/releases/download/v0.5.0/packetframe_0.5.0_${ARCH}.deb"
curl -LO https://github.com/unredacted/packetframe/releases/download/v0.5.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
dpkg -i "packetframe_0.5.0_${ARCH}.deb" && systemctl daemon-reload
```

Tarballs for `{aarch64,x86_64}-unknown-linux-{gnu,musl}` are attached below.

**Full changelog:** https://github.com/unredacted/packetframe/compare/v0.2.7...v0.5.0

[0.5.0]: https://github.com/unredacted/packetframe/compare/v0.2.7...v0.5.0
