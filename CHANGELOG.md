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

Because a section is published as written, it is written as release
notes and kept to 0.5.0's shape and size: a short introduction, the
upgrade steps and what an operator must know before installing, a few
highlights, the changes grouped by module at one line each with their
PR links, known limitations, and install steps. During a cycle a PR
adds only its line, under its module in the `UNRELEASED` section, and
leaves mechanism, measurements and incident history to the runbooks
and the PR description; the release PR writes the rest. Lines inside a
section are unwrapped, because GitHub renders a release body's single
newlines as hard breaks. `release.sh check`, which CI runs on every
PR, refuses a section over 20,000 bytes or a line in one over 800.

## [0.6.4] - UNRELEASED

### Changes

**Packaging**

- The packaged unit runs the daemon at `Nice=-15`, the priority UniFi gives bgpd, zebra and ubios-udapi-server, from its first instruction; VPP inherits it. At nice 0 the route-ledger seed, the FRR feed and the sender of VPP's fresh load all ran at a fraction of their idle rate on a gateway booting into full traffic. Run `systemctl daemon-reload` after installing. ([#PR](https://github.com/unredacted/packetframe/pull/PR))

## [0.6.3] - 2026-11-12

A point release on 0.6.2 for the first load of a fresh VPP: the step between a gateway's start and VPP steering. On a gateway that boots into full traffic, that load took 3.5 min on 2026-11-05, against about 35 s idle, and VPP died during it on both post-upgrade boots. VPP now has its cores to itself while it loads, stops its workers less often, and every load's length is recorded. A 0.6.2 config and route ledger carry over unchanged.

### Upgrading from 0.6.2

1. Install the 0.6.3 package or tarball. The .deb runs no maintainer scripts, so the running daemon is unaffected.
2. `systemctl daemon-reload`
3. `systemctl stop packetframe && packetframe detach --keep-vpp && systemctl start packetframe`, with or without vpp-offload, as for 0.6.2.

The start seeds from the ledger 0.6.2 wrote at the stop. Neither ledger format changed, so a downgrade to 0.6.2 seeds too.

- **`startup.conf` gains an `l3fib` stanza.** It preallocates VPP's load-balance and fib-entry pools for the routes `expected-routes` budgets, plus the IPv6 budget under `v6 on`. The memory is inside the heap the same budget already sizes. A VPP kept by `--keep-vpp` gets it at its next start.
- **Attach moves every NIC's queue IRQs off VPP's cores,** not only the member ports'. The attach log names each move. An IRQ of a port VPP does not own that the kernel will not move is a warning, not a refusal.
- **The core fence.** While a VPP it spawned loads its table, the daemon writes the `cpuset.cpus` of every top-level cgroup but its own (on a UniFi gateway `os.slice`, `uos.slice`, `app.slice`, `user.slice`, `init.scope`, and UniFi's root cgroups such as `bgpd` and `dpi`), and puts it back when the load is done. A cgroup that started with an empty list gets the online CPUs back, which are the same CPUs, and is empty again after a reboot. The record is `<state-dir>/vpp-core-fence.json`. An adopted VPP is never fenced. [The core fence](https://github.com/unredacted/packetframe/blob/v0.6.3/docs/runbooks/vpp-offload.md#the-core-fence-during-a-fresh-load)
- **New events:** `cores_fenced` and `cores_released` (vpp-offload); `fresh_hold_released` gains `load_ms`. [The event log](https://github.com/unredacted/packetframe/blob/v0.6.3/docs/runbooks/event-log.md)

### Highlights

- **VPP has its cores to itself while it loads.** A fresh VPP's load runs on its main thread at 100%, and slows in step with the main core it loses; UniFi's daemons run on any core, `ubios-udapi-server` at VPP's own priority. From VPP's spawn until it leaves Syncing, every other top-level cgroup is kept off VPP's main and worker cores, and threads that pinned themselves get their affinity back afterwards. On a lab EFG, six nice -20 busy loops on VPP's main core stretched a 170,291-route load from 5.5 s to 22 s; fenced, it took 5.5 s. [The core fence](https://github.com/unredacted/packetframe/blob/v0.6.3/docs/runbooks/vpp-offload.md#the-core-fence-during-a-fresh-load)
- **Fewer worker barriers during a load.** VPP aborts when a worker misses a barrier for 1 s (`worker thread deadlock`), and the lab reproduced that abort mid-load from `load_balance_create` with a 3 s stall on a worker core. Preallocated pools take away the barriers pool growth caused, and the largest holds: from 196 to 167 per million routes, longest 16.7 ms to 6.9 ms. Moving every NIC's interrupts off VPP's cores takes away a source of such stalls: on the lab, `eth0`'s queue IRQs were on VPP's main core and both workers. [IRQ affinity before attach](https://github.com/unredacted/packetframe/blob/v0.6.3/docs/runbooks/vpp-offload.md#irq-affinity-before-attach)
- **Every fresh load is timed.** `fresh_hold_released` carries `load_ms`, and the hwtest bundle carries `vpp_bulk_load_bench`, which times a bulk load into a scratch VPP and counts its barriers by caller.

### Changes

**vpp-offload**

- A fresh VPP stops its workers less often while it loads: `startup.conf` preallocates the FIB's load-balance and fib-entry pools for the routes `expected-routes` budgets (`l3fib`), and attach moves every NIC's queue IRQs off VPP's cores, not only the member ports'. A worker that misses VPP's barrier for 1 s aborts it, which is how a fresh load died after a reboot. ([#387](https://github.com/unredacted/packetframe/pull/387))
- `fresh_hold_released` carries `load_ms`, how long a fresh VPP took to take the whole table. The hwtest bundle carries `vpp_bulk_load_bench`, which times a bulk load into a scratch VPP and counts its barriers by caller. ([#388](https://github.com/unredacted/packetframe/pull/388))
- While a fresh VPP loads its table, every top-level cgroup except the daemon's own (`system.slice` under the packaged unit) is kept off VPP's main and worker cores, and self-pinned threads get their affinity back afterwards (`cores_fenced` / `cores_released`). On the lab, six nice -20 hogs on VPP's main core slowed a 170k-route load from 5.5 s to 22 s; fenced, it took 5.5 s. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.3/docs/runbooks/vpp-offload.md#the-core-fence-during-a-fresh-load), [#390](https://github.com/unredacted/packetframe/pull/390))

### Known limitations

- Barriers remain during a load: about 146 per million routes come from VPP growing its per-route counters, which no startup option presizes. A worker stalled for 1 s across one of them still aborts VPP. A `worker thread deadlock` in `<state-dir>/vpp-diag/` says it happened.
- The fence leaves the daemon's own top-level cgroup alone (`system.slice` under the packaged unit): fencing inside it would unpin VPP's threads on kernel 5.15. On a UniFi gateway it holds only small services.
- A thread that pins itself while the fence is held keeps the full CPU set afterwards; only pins taken before the fence are restored.
- VPP's octeon driver can fail a start under load: a port-creation SIGSEGV and a `device init failed [rv -35]` were each seen on the lab, in about 1 of 40 and 1 of 60 starts. The supervisor restarts VPP within seconds.
- A first load still runs at the main thread's pace, about 33,000 routes a second on the lab's cores: about 35 s for a full table once nothing else takes its core.
- The limitations listed for 0.6.2 otherwise still apply.

### Install and verify

When upgrading, follow steps 1 to 3 above.

```sh
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
curl -LO "https://github.com/unredacted/packetframe/releases/download/v0.6.3/packetframe_0.6.3_${ARCH}.deb"
curl -LO https://github.com/unredacted/packetframe/releases/download/v0.6.3/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
dpkg -i "packetframe_0.6.3_${ARCH}.deb" && systemctl daemon-reload
```

Tarballs for `{aarch64,x86_64}-unknown-linux-{gnu,musl}` are attached below; the `aarch64-unknown-linux-gnu` tarball and the arm64 .deb also carry the VPP sampler plugin.

**Full changelog:** https://github.com/unredacted/packetframe/compare/v0.6.2...v0.6.3

## [0.6.2] - 2026-11-12

A point release on 0.6.1. After a reboot, a next hop that resolves late no longer leaves its routes out of VPP until the route source happens to re-send each one: on 2026-11-05 that held the reference gateway's first steer for over twenty minutes, with 486,318 routes through one transit judged unresolvable. A VPP that dies now leaves its output, the signal and a core behind, and a next hop slow to resolve is recorded in the event log with the likeliest cause. A 0.6.1 config and route ledger carry over unchanged.

### Upgrading from 0.6.1

1. Install the 0.6.2 package or tarball. The .deb runs no maintainer scripts, so the running daemon is unaffected.
2. `systemctl daemon-reload`
3. `systemctl stop packetframe && packetframe detach --keep-vpp && systemctl start packetframe`, with or without vpp-offload, as for 0.6.1.

The start seeds from the ledger 0.6.1 wrote at the stop. Neither ledger format changed, so a downgrade to 0.6.1 seeds too.

- **VPP's diagnostics directory.** A VPP the daemon starts writes its stdout and stderr to `<state-dir>/vpp-diag/` and runs there, with `runtime-dir` and `coredump-size unlimited` added to its `unix` stanza. This happens only if every directory from `/` down is root's and closed to others; otherwise a journal warning says why and VPP starts as before. Either way the stanza no longer sets `full-coredump`. Its stats socket moves there too. A VPP kept by `--keep-vpp` gets this at its next start; then `/proc/$(pidof vpp)/coredump_filter` reads `00000013`, and `/proc/sys/kernel/core_pattern` says where a core goes. [VPP died of a signal](https://github.com/unredacted/packetframe/blob/v0.6.2/docs/runbooks/vpp-offload.md#vpp-died-of-a-signal-its-output-and-its-core)
- **New events:** `vpp_killed` (vpp-offload), and `nexthop_resolve_slow` and `nexthop_resolved_late` (fast-path). [The event log](https://github.com/unredacted/packetframe/blob/v0.6.2/docs/runbooks/event-log.md)
- **Debian 13 gateways.** EFG firmware 6.0.17 moves the gateway to Debian 13, where the Debian 11 VPP build cannot install. vpp-unifi's `vpp-v26.06-octeon9-trixie-arm64` is the same VPP commit PacketFrame binds to (`c3200b88`), with identical API CRCs, and a lab EFG on 6.0.17 ran this release's code with vpp-offload on it: ready, verified, nothing unresolvable. Install that build there instead.

### Highlights

- **A late neighbour no longer holds the steer.** When a neighbour resolves after the drain has judged its routes unresolvable, those routes are queued for VPP again at once, on a plain port as on a bridge. Until now only a bridge neighbour did that; on a plain port, such as a transit's, the routes waited for the route source to change each one. A route VPP already holds through the same paths is not re-sent. [Unresolvable routes](https://github.com/unredacted/packetframe/blob/v0.6.2/docs/runbooks/vpp-offload.md#packetframe_vpp_routesstateunresolvable--0)
- **A VPP crash leaves evidence.** A fresh VPP died of SIGABRT under boot load on 2026-10-30 and again on 2026-11-05, and nothing said why: its output went to `/dev/null`, its backtrace to a RAM journal, and no core could be written. Now its output and backtrace are kept, a core can be written without the hugepage heap, and `vpp_killed` names the fault VPP's own handler caught. [VPP died of a signal](https://github.com/unredacted/packetframe/blob/v0.6.2/docs/runbooks/vpp-offload.md#vpp-died-of-a-signal-its-output-and-its-core)
- **Slow next hops explained.** A next hop still unresolved 30 s after it was registered or lost is recorded, with what each resolve request did, what the kernel answered, the egress link's state and carrier changes, and a `reading` naming the likeliest cause, such as `unanswered`, `probes-skipped` or `link-flapped`. It is recorded again when it resolves. [Slow next hops](https://github.com/unredacted/packetframe/blob/v0.6.2/docs/runbooks/packetframe-fib.md#slow-next-hops-in-the-event-log)

### Changes

**fast-path**

- A next hop still unresolved 30 s after it was registered or lost is recorded in the event log (`nexthop_resolve_slow`), and again when it resolves (`nexthop_resolved_late`). Each event lists what was asked and what the neighbour resolver did with each request, what the kernel reported, the egress link's state and carrier changes, and the likeliest cause (`reading`). At most 16 an hour, those with the most routes first. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.2/docs/runbooks/packetframe-fib.md#slow-next-hops-in-the-event-log), [#382](https://github.com/unredacted/packetframe/pull/382))

**vpp-offload**

- A neighbour that resolves after the routes through it have drained now hands them back to be installed, on a plain port as on a bridge; until now they stayed unresolvable until the route source changed each one. A route VPP already holds through the same paths is not re-sent. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.2/docs/runbooks/vpp-offload.md#packetframe_vpp_routesstateunresolvable--0), [#380](https://github.com/unredacted/packetframe/pull/380))
- A VPP the daemon spawns keeps its stdout and stderr in `<state-dir>/vpp-diag/`, one file per start, and runs there, so a core can land there (`coredump-size unlimited`, with a core filter that leaves out the hugepage heap). This happens only when no other account can change that path. A death by signal is reported (`vpp_killed`): the signal VPP died of, the fault its own handler logged (`vpp_signal`), and whether it dumped core. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.2/docs/runbooks/vpp-offload.md#vpp-died-of-a-signal-its-output-and-its-core), [#381](https://github.com/unredacted/packetframe/pull/381))

**Build**

- The eBPF programs are built with Aya 0.3.0 on the `nightly-2026-10-30` toolchain. ([#385](https://github.com/unredacted/packetframe/pull/385))
- rtnetlink 0.24 and netlink-packet-route 0.34 ([#383](https://github.com/unredacted/packetframe/pull/383)); flate2 1.1.11 and signal-hook 0.4.6 ([#384](https://github.com/unredacted/packetframe/pull/384)).

### Known limitations

- The cause of the SIGABRT is not found; this release makes the next one diagnosable.
- A neighbour that resolves late still costs a pass over every route through it: each is sent to VPP again, one at a time, so a late transit delays the first steer by however long a table's worth of updates takes under the load at the time.
- After VPP's package is removed or reinstalled (a firmware upgrade does this), its removal script hands the port's VF back to the kernel, and adopting the running VPP is refused ("recorded port does not match reality") until `packetframe detach --all`, which costs the route ledger.
- `detach --keep-vpp` refuses when the config newly adds vpp-offload; use `detach --all` for that change, and the next start loads cold.
- After days of uptime the kernel can fail to grant VPP's hugepages: a lab gateway granted none of 4 × 512 MiB after 8 days. Dropping the page cache and compacting memory (`sync; echo 3 > /proc/sys/vm/drop_caches; echo 1 > /proc/sys/vm/compact_memory`) before the start let all four be granted.
- A gateway firmware upgrade can still remove hand-installed packages: reinstall packetframe, and VPP, after one.
- The limitations listed for 0.6.1 otherwise still apply.

### Install and verify

When upgrading, follow steps 1 to 3 above.

```sh
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
curl -LO "https://github.com/unredacted/packetframe/releases/download/v0.6.2/packetframe_0.6.2_${ARCH}.deb"
curl -LO https://github.com/unredacted/packetframe/releases/download/v0.6.2/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
dpkg -i "packetframe_0.6.2_${ARCH}.deb" && systemctl daemon-reload
```

Tarballs for `{aarch64,x86_64}-unknown-linux-{gnu,musl}` are attached below; the `aarch64-unknown-linux-gnu` tarball and the arm64 .deb also carry the VPP sampler plugin.

**Full changelog:** https://github.com/unredacted/packetframe/compare/v0.6.1...v0.6.2

## [0.6.1] - 2026-11-04

A point release on 0.6.0. A reboot, a restart or an FRR reload no longer throws away a route table FRR is still relearning: with `integrity-authority frr`, the GC at FRR's End-of-RIB waits for FRR's own upstreams, both after a route-ledger seed and after a reconnect, and a fresh VPP can take its first steer on a whole seed instead of waiting for every upstream. A box without vpp-offload now restarts onto its route ledger too. A 0.6.0 config and route ledger carry over unchanged.

### Upgrading from 0.6.0

1. Install the 0.6.1 package or tarball. The .deb runs no maintainer scripts, so the running daemon is unaffected.
2. `systemctl daemon-reload`
3. `systemctl stop packetframe && packetframe detach --keep-vpp && systemctl start packetframe`, with **0.6.1**'s `detach`, with or without vpp-offload. 0.6.0's `--keep-vpp` refused on a config without vpp-offload; 0.6.1's is the restart that keeps the route ledger there too.

The start seeds from the ledger 0.6.0 wrote at the stop, so the upgrade does not load the mirror cold.

- **The route GC can wait.** With `integrity-authority frr`, the first GC after a seed or a reconnect waits until the authority reads every declared upstream Established with End-of-RIB, or the routes it would remove reach `route-ledger max-age` (30 minutes by default). Meanwhile routes FRR no longer has keep forwarding. An upstream that stays down counts as loading, so keep the authority's `upstream` list to sessions that are up. New events `feed_gc_held` and `feed_gc_released`; the `route-ledger` status row says when a GC is held. [The held GC](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/packetframe-fib.md#the-gc-over-earlier-routes-waits-for-frrs-upstreams)
- **Route ledger format 2.** It records whether the completeness authority vouched for the mirror, and which authority. A 0.6.0 ledger seeds as unattested. **Downgrading** to 0.6.0 loads cold once: 0.6.0 refuses the new format by name (`format-version`).
- **`detach --keep-vpp` without vpp-offload** now refuses only when a VPP is on record that the config no longer declares, and the `detach` event's `vpp` field reads `none` there.

### Highlights

- **A table that survives FRR relearning it.** After a reboot or a bgpd restart (every UniFi BGP configuration upload is one), FRR can send End-of-RIB while its transits are still loading: at `select-defer-time` in restart mode, within a second of the session in helper mode. Its GC used to remove most of a mirror that was right, from VPP too. With the FRR authority it now waits for the transits, then removes only what FRR no longer has. [The held GC](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/packetframe-fib.md#the-gc-over-earlier-routes-waits-for-frrs-upstreams)
- **A fresh VPP steers on a whole seed.** After the 2026-10-30 reboot of the reference deployment, VPP's first steer came 32.5 minutes after the reboot, waiting for both transits' End-of-RIB with the whole table already in the mirror. Over a whole, attested route-ledger seed it now verifies and steers while the authority's only objection is upstreams still loading. [A fresh VPP and a seeded mirror](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/vpp-offload.md#a-fresh-vpp-and-a-seeded-mirror)
- **Seeded restarts without VPP.** The routine restart keeps the route ledger and the wan-egress rules on a `packetframe-fib` box without vpp-offload, which until now loaded its table cold after every restart. [Restarts and detach](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/packetframe-fib.md#turning-it-off-and-detach)

### Changes

**fast-path**

- With `integrity-authority frr`, the first GC after a route-ledger seed waits until every declared upstream has loaded (at most `max-age`), so an FRR End-of-RIB sent at `select-defer-time` no longer empties the seeded mirror after a reboot. The ledger is format version 2, recording whether the authority vouched for it; a 0.6.0 ledger still seeds, unattested. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/packetframe-fib.md#the-gc-over-earlier-routes-waits-for-frrs-upstreams), [#375](https://github.com/unredacted/packetframe/pull/375))
- With `integrity-authority frr`, the GC after a reconnect is held the same way, so a bgpd restart (every UniFi BGP configuration upload) no longer empties the mirror, and a steered VPP, at FRR's early End-of-RIB. A held GC asks the authority for a check at once, so a reconnect with FRR still up is held for one check. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/packetframe-fib.md#the-gc-over-earlier-routes-waits-for-frrs-upstreams), [#376](https://github.com/unredacted/packetframe/pull/376))

**vpp-offload**

- A fresh VPP over a whole route-ledger seed verifies and takes its first steer while the completeness authority waits only for upstreams to finish loading, rather than after their End-of-RIB. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/vpp-offload.md#a-fresh-vpp-and-a-seeded-mirror), [#375](https://github.com/unredacted/packetframe/pull/375))
- An adopted resync's release walks the table 16,384 routes a pass, so a steered VPP keeps being pinged every 500 ms instead of going about 4.9 s unpinged at 1.35M routes. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/vpp-offload.md#the-steered-diff-and-a-seeded-mirror), [#368](https://github.com/unredacted/packetframe/pull/368))
- An adopted VPP's check for an empty preserved ledger no longer copies the whole table to find out. ([#369](https://github.com/unredacted/packetframe/pull/369))

**CLI and operations**

- `packetframe detach --keep-vpp` works without vpp-offload when no VPP is on record, so a restart on such a box keeps the route ledger and the wan-egress rules instead of loading cold. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/packetframe-fib.md#turning-it-off-and-detach), [#378](https://github.com/unredacted/packetframe/pull/378))
- Development only: three tests in the hardware test bundle no longer misbehave on a router. One ran the live detach path against a real `eth5`, one leaked pinned FIB maps on every run, and one miscounted polls under load. ([#377](https://github.com/unredacted/packetframe/pull/377))
- Built with Rust 1.99.1. ([#372](https://github.com/unredacted/packetframe/pull/372))

### Known limitations

- While the GC is held, routes FRR withdrew while the box or the session was down keep forwarding, in both tiers, until the upstreams load or `max-age` passes. If `max-age` passes first, the held GC runs and removes routes FRR has not re-sent yet until FRR sends them. Size `max-age` for the longest reboot plus upstream load you expect. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/packetframe-fib.md#the-gc-over-earlier-routes-waits-for-frrs-upstreams))
- Without the FRR authority (`birdc`, `none`), a bgpd restart's early End-of-RIB still sweeps the mirror, as in 0.6.0. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.1/docs/runbooks/packetframe-fib.md#graceful-restart-on-the-feed-session))
- A gateway firmware upgrade can remove hand-installed packages: on an EFG, firmware 6.0.17 removed packetframe's and VPP's, so reinstall packetframe after one. That firmware also moves the gateway to Debian 13, where the VPP release vpp-offload pins, a Debian 11 build, cannot be installed (it needs `libssl1.1`). PacketFrame runs there without vpp-offload; do not move a gateway that runs vpp-offload to it until a matching VPP build exists.
- The limitations listed for 0.6.0 otherwise still apply.

### Install and verify

When upgrading, follow steps 1 to 3 above.

```sh
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
curl -LO "https://github.com/unredacted/packetframe/releases/download/v0.6.1/packetframe_0.6.1_${ARCH}.deb"
curl -LO https://github.com/unredacted/packetframe/releases/download/v0.6.1/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
dpkg -i "packetframe_0.6.1_${ARCH}.deb" && systemctl daemon-reload
```

Tarballs for `{aarch64,x86_64}-unknown-linux-{gnu,musl}` are attached below; the `aarch64-unknown-linux-gnu` tarball and the arm64 .deb also carry the VPP sampler plugin.

**Full changelog:** https://github.com/unredacted/packetframe/compare/v0.6.0...v0.6.1

## [0.6.0] - 2026-10-13

The first release since 0.5.0 (2026-09-28). It adds the flow-export module (experimental) and fast-path's `wan-egress`, brings a restart on a full table down from minutes to seconds, and hardens vpp-offload, neigh-snoop and the BGP feed against the failures found in production on 2026-10-07 and 2026-10-12. A 0.5.0 config parses unchanged, but read **Upgrading from 0.5.0** first: a mode and three counters were renamed, an `attach` of keepalived's dedicated VRRP link is refused, and the state files' ownership rules are stricter.

### Upgrading from 0.5.0

1. Install the 0.6.0 package or tarball. The .deb runs no maintainer scripts, so the running daemon is unaffected.
2. `systemctl daemon-reload`
3. `systemctl stop packetframe && packetframe detach --keep-vpp && systemctl start packetframe`, with **0.6.0**'s `detach` (plain `packetframe detach` without vpp-offload). It removes fast-path's pins, whose maps changed, so no `detach --all` is needed, and VPP stays up and steered throughout.

The first start after 0.5.0 loads the route mirror from the route source, because 0.5.0 writes no route ledger: about 2.5 minutes for 1.35M routes on the reference deployment, with steering up throughout. Every later restart seeds the mirror from the ledger.

- **Renamed mode and counters.** `forwarding-mode custom-fib` is now `packetframe-fib`; the old name still parses, with a deprecation warning. `custom_fib_hit`, `custom_fib_miss` and `custom_fib_no_neigh` are now `fib_hit`, `fib_miss` and `fib_no_neigh` (`packetframe_fib_hit_total` and so on), and the mode label reads `mode="packetframe-fib"`. Counter indices are unchanged; update any alert or dashboard that matches the old names.
- **Stricter state files.** vpp-offload's state file and preserved route ledger, and fast-path's and guard's tc filter records, are refused unless they and `state-dir` are root-owned, closed to group and others, and reached through no symlink. The packaged default passes, and so does any `state-dir` where `packetframe reconfigure` works today. [The check and the fix](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/vpp-offload.md#attach-or-detach-refuses-refusing-vpp-offloadjson-)
- **fast-path refuses to attach keepalived's dedicated VRRP link**, on which an HA standby's own traffic would bypass the active gateway's firewall. The error names the line to remove; routers without keepalived are unaffected.
- **The BGP feed advertises Graceful Restart and sends End-of-RIB.** Nothing to configure: FRR's default helper mode handles both. Do not turn on a global `bgp graceful-restart` for this; that puts the whole router in restart mode. [Graceful restart on the feed session](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/packetframe-fib.md#graceful-restart-on-the-feed-session)
- **Downgrading:** run **0.6.0**'s `packetframe detach --all` first. An older daemon does not recognise the new RSS keep rules and would leave them in the NIC. A keep-VPP downgrade keeps steering up but leaves them as unowned duplicates holding MCAM slots until a reboot, or `ethtool -N <iface> delete <loc>` for each rule `ethtool -n <iface>` lists with an `RSS Context ID`.

### Highlights

- **Flow export (experimental).** The new `flow-export` module sends sampled packets as sFlow v5, or flow records as IPFIX with privacy profiles and origin AS numbers, to collectors such as Akvorado and FastNetMon. Samples come from the XDP and tc programs, from VPP's sampler plugin on steered ports, and from a kernel tc sampler on interfaces neither sees. Off until configured. [Runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/flow-export.md)
- **Restarts in seconds.** A clean stop saves the route mirror and the next start seeds it before the route source connects; an adopted VPP then diffs against it once the completeness authority attests it, rather than after the BGP replay. Measured on the reference deployment (1.35M routes, four steered ports): 50 s from start to VPP verified and steering re-asserted, with no BGP session reset. [Runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/vpp-offload.md#the-steered-diff-and-a-seeded-mirror)
- **Exempt traffic spread over RSS.** vpp-offload's keep rules sent every exempt frame to queue 0, and on 2026-10-07 that held one core at 99% softirq while the others idled. Keeps are now RSS rules, with a `kernel-path` status row per steered port. [Runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/vpp-offload.md#rss-keeps-and-the-queue-0-fallback)
- **`wan-egress`** sends private sources past a full-table `main` to the platform's own WAN policy and NAT. [Runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/packetframe-fib.md#wan-egress)
- **A route feed that rides out an FRR reload.** On 2026-10-12 a BGP config upload restarted FRR on a saturated gateway and the feed failed three ways. The listener now keeps the session alive from a thread of its own, ends it at the peer's close, and sweeps stale routes at End-of-RIB rather than after a pause. The longest control-plane hold after a 1M-route sweep fell from 1.06 s to 68 ms on the reference gateway. [Runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/packetframe-fib.md#symptom-the-feed-session-drops-during-a-full-table-load)
- **Recovering in place.** Lost netlink notifications are re-read instead of missed, the neighbour resolver is supervised and restarted, and vpp-offload follows the router's own addresses while it runs.

### Changes

**flow-export** (new, experimental; [runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/flow-export.md))

- Sends sFlow v5 to each `collector` (`kind stats` for Akvorado, `kind ddos` for FastNetMon), one data source per port whichever paths sample it. `sample-rate` (default 1000) and `header-bytes` (default 128) reload without a restart. ([#336](https://github.com/unredacted/packetframe/pull/336))
- fast-path's XDP and tc programs carry the sampler, through a new `SAMPLES` BPF ring buffer; new counters `sample_selected` and `sample_emit_failed`. ([#315](https://github.com/unredacted/packetframe/pull/315), [#347](https://github.com/unredacted/packetframe/pull/347), [#348](https://github.com/unredacted/packetframe/pull/348))
- Steered ports are sampled by the VPP sampler plugin, which the arm64 .deb and the `aarch64-unknown-linux-gnu` tarball now carry; vpp-offload prepares its directory at attach. ([#310](https://github.com/unredacted/packetframe/pull/310), [#311](https://github.com/unredacted/packetframe/pull/311), [#316](https://github.com/unredacted/packetframe/pull/316), [#337](https://github.com/unredacted/packetframe/pull/337), [#350](https://github.com/unredacted/packetframe/pull/350))
- `collector <name> ipfix <ip>:<port>` sends IPFIX flow records from a bounded cache (`flow-cache`), with privacy profiles (`full`, `truncate`, `no-remote`, `as-only`) and origin AS numbers from fast-path's route source. ([#339](https://github.com/unredacted/packetframe/pull/339), [#340](https://github.com/unredacted/packetframe/pull/340))
- `kernel-sample <iface>` samples an interface no fast-path program or VPP is on, such as a tunnel, with a tc-ingress program of its own. ([#341](https://github.com/unredacted/packetframe/pull/341), [#346](https://github.com/unredacted/packetframe/pull/346))
- `path-mtu <bytes>` fits datagrams to a tunnel to the collectors. ([#353](https://github.com/unredacted/packetframe/pull/353))
- `packetframe flow-export interfaces` prints the ifIndex map as an Akvorado metadata provider, and `packetframe feasibility` gains advisory flow-export rows. Coverage per port and path, and a row per collector, are in `status` and under `packetframe_flow_export_`. ([#336](https://github.com/unredacted/packetframe/pull/336), [#338](https://github.com/unredacted/packetframe/pull/338))

**fast-path**

- `wan-egress from <cidr> … [keep <cidr> …]` (IPv4): private sources skip a full-table `main` for the platform's WAN rules and NAT, through `ip rule` entries it reconciles and removes on a full `detach`; new `wan-egress` status row. ([#306](https://github.com/unredacted/packetframe/pull/306), [#318](https://github.com/unredacted/packetframe/pull/318))
- Route ledger: a clean stop writes the route mirror to `<state-dir>/fast-path-route-ledger.bin`, and the next start seeds from it. `route-ledger on|off [max-age <seconds>]` (default on, 30 minutes). ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/packetframe-fib.md#restarts-the-route-ledger), [#323](https://github.com/unredacted/packetframe/pull/323))
- BGP feed: KEEPALIVEs come from a thread of their own, a peer's close ends the session at once, and the stale-route sweep fires on End-of-RIB, with 300 s of silence as a backstop (30 s from a peer without Graceful Restart). The journal names the trigger. ([#331](https://github.com/unredacted/packetframe/pull/331), [#360](https://github.com/unredacted/packetframe/pull/360), [#365](https://github.com/unredacted/packetframe/pull/365))
- A feed's stale-route sweep, `Resync` and a BMP PeerDown walk the mirror in chunks that give the runtime back, and the glibc builds run with malloc fastbins off (`PACKETFRAME_MALLOC_FASTBINS=on` restores them). ([#362](https://github.com/unredacted/packetframe/pull/362), [#364](https://github.com/unredacted/packetframe/pull/364), [#366](https://github.com/unredacted/packetframe/pull/366), [#367](https://github.com/unredacted/packetframe/pull/367))
- The neighbour resolver sends requests on a socket of its own with timeouts, resyncs after a notification overrun, and is supervised and restarted; new `neigh-resolver` status row and `neigh_resolver_restarted` event. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/packetframe-fib.md#symptom-nexthops-stuck-incomplete-while-the-kernel-neighbour-is-reachable), [#334](https://github.com/unredacted/packetframe/pull/334))
- The redirect-target watcher re-reads links after a netlink overrun; new `redirect-watch` status row. ([#332](https://github.com/unredacted/packetframe/pull/332))
- The router's own addresses are named once as `local` nexthops instead of reported pending forever. ([#307](https://github.com/unredacted/packetframe/pull/307))
- The custom-FIB runbook moved to [`docs/runbooks/packetframe-fib.md`](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/packetframe-fib.md). ([#305](https://github.com/unredacted/packetframe/pull/305))

**vpp-offload**

- Keep rules are RSS rules, falling back per port to queue 0 with its IRQ moved to a CPU of its own; new `kernel-path` status row and `kernel_path_dropping` event. ([#325](https://github.com/unredacted/packetframe/pull/325))
- An adopted VPP, steered or not, diffs against a seeded mirror once the completeness authority agrees, not after the replay. A steered diff that would change more than 1% of a family's routes is refused and waits for quiet. ([#324](https://github.com/unredacted/packetframe/pull/324), [#356](https://github.com/unredacted/packetframe/pull/356))
- A steer that diverts more traffic waits until VPP has caught up with the mirror and a clean verify drew from at least 90% of the IPv4 table; the event log records `steer_held`. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/vpp-offload.md#the-first-steer-hold-vpp-caught-up-and-a-verify-that-covers-the-table), [#333](https://github.com/unredacted/packetframe/pull/333))
- With `require-table-complete off`, a steered restart's reconciliation also waits for the route source's InitiationComplete, and `fib-synced` names the tier carrying traffic while it waits. ([#361](https://github.com/unredacted/packetframe/pull/361), [#366](https://github.com/unredacted/packetframe/pull/366))
- Unresolvable routes are named, up to five with the reason, in `status` and an `unresolvable_routes` event; the router's own routes count as kernel-delivered; a stale incomplete verify is re-run once the table is clean. ([#307](https://github.com/unredacted/packetframe/pull/307))
- The router's own addresses are re-read every 2 s, so a subnet added after start no longer reads unresolvable until a restart. ([#355](https://github.com/unredacted/packetframe/pull/355))
- `unresolvable-accept6 <ipv6-prefix>` acknowledges an unresolvable IPv6 route you have examined, such as your own aggregate. ([#357](https://github.com/unredacted/packetframe/pull/357))
- Refuses NICs other than Marvell OCTEON (`rvu_nicpf`) before touching any; `feasibility` reports `vpp.<port>.driver`. ([#313](https://github.com/unredacted/packetframe/pull/313))
- A stall of its own supervision loop is no longer read as VPP wedged, and any reply from VPP counts as proof of life. ([#322](https://github.com/unredacted/packetframe/pull/322))
- The drift scan dumps only the tables the policy rules select, waits out link churn, and publishes its duration as `packetframe_vpp_drift_scan_ms`. ([#320](https://github.com/unredacted/packetframe/pull/320))

**neigh-snoop**

- Re-reads its bridges after a netlink overrun, and an install for an address its mirror holds no row for can no longer overwrite a confirmed MAC; new `netlink` status row. ([#332](https://github.com/unredacted/packetframe/pull/332))

**CLI and operations**

- `packetframe sampler status|watch|configure|clear`: lab tooling for the VPP sampler plugin. ([#312](https://github.com/unredacted/packetframe/pull/312))
- `Module::breaker_tripping()`, an additive trait method with a no-op default, called before a circuit-breaker `detach`. ([#306](https://github.com/unredacted/packetframe/pull/306))
- Development only, off in release builds: the `packetframe-flow-encode` crate and `packetframe flow-synth` behind the `dev-tools` feature. ([#308](https://github.com/unredacted/packetframe/pull/308))
- Built with Rust 1.99.0. ([#314](https://github.com/unredacted/packetframe/pull/314))

**Fixes**

- A route-feed reconnect no longer deletes the `fallback-default` 0/0 or the `local-prefix` host routes. ([#317](https://github.com/unredacted/packetframe/pull/317))
- The `fallback-default` 0/0 is re-injected when its interface returns, instead of staying gone until a restart. ([#319](https://github.com/unredacted/packetframe/pull/319))
- Netlink requests in neigh-snoop, `wan-egress` and `anyip` are bounded instead of able to hang a task for good. ([#332](https://github.com/unredacted/packetframe/pull/332))
- State files are read only when this daemon could have written them, bounded in size, and written without following a symlink in `state-dir`. ([#327](https://github.com/unredacted/packetframe/pull/327), [#328](https://github.com/unredacted/packetframe/pull/328), [#329](https://github.com/unredacted/packetframe/pull/329), [#330](https://github.com/unredacted/packetframe/pull/330), [#343](https://github.com/unredacted/packetframe/pull/343))
- `detach` finds a tc filter by its recorded ifindex, so a renamed interface no longer strands it. ([#343](https://github.com/unredacted/packetframe/pull/343))
- Every control-plane thread is placed, even while others exit. ([#309](https://github.com/unredacted/packetframe/pull/309))

### Known limitations

- flow-export is experimental. A `kind ddos` collector takes sFlow only, and attack-detection timing against FastNetMon has not been qualified.
- IPv6 is steered by frame, not address: only TCP/UDP arriving on a VLAN listed in `v6-divert` is offloaded, so list every upstream VLAN. The allowlist does not scope what is diverted, and diverted IPv6 bypasses the kernel's forward-path netfilter. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/vpp-offload.md#v6-divert-steering))
- VPP's own glean output (the ARP requests and neighbour solicitations it sends) bypasses guard, which polices kernel tc egress.
- Native XDP is refused on rvu-nicpf interfaces on kernels without upstream commit 04f647c8e456 (Linux 6.8), including the reference vendor kernel, where native attach panics. Use `generic` or `auto`.
- A bgpd that restarts can send End-of-RIB within a second of the feed session coming up, over a table it has barely begun to relearn. The End-of-RIB sweep then removes most of the route mirror until FRR's routes come back. ([runbook](https://github.com/unredacted/packetframe/blob/v0.6.0/docs/runbooks/packetframe-fib.md#graceful-restart-on-the-feed-session))
- The .deb runs no maintainer scripts: run `systemctl daemon-reload` after every install.

### Install and verify

When upgrading, follow steps 1 to 3 above.

```sh
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
curl -LO "https://github.com/unredacted/packetframe/releases/download/v0.6.0/packetframe_0.6.0_${ARCH}.deb"
curl -LO https://github.com/unredacted/packetframe/releases/download/v0.6.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
dpkg -i "packetframe_0.6.0_${ARCH}.deb" && systemctl daemon-reload
```

Tarballs for `{aarch64,x86_64}-unknown-linux-{gnu,musl}` are attached below; the `aarch64-unknown-linux-gnu` tarball and the arm64 .deb also carry the VPP sampler plugin.

**Full changelog:** https://github.com/unredacted/packetframe/compare/v0.5.0...v0.6.0

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

[0.6.0]: https://github.com/unredacted/packetframe/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/unredacted/packetframe/compare/v0.2.7...v0.5.0
