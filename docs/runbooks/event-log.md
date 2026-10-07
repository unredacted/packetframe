# Event log: operator guide

PacketFrame keeps its own small, persistent log of the operationally significant things it does — steering up and down, verify results, restarts and the adoption path each one took, reconfigure outcomes, module health transitions, teardowns. Everything else still goes to stdout and the journal.

## Contents

- [Why it exists](#why-it-exists)
- [Where it is](#where-it-is)
- [Reading it](#reading-it)
- [Format](#format)
- [Event kinds](#event-kinds)
- [Rotation and size](#rotation-and-size)
- [When it cannot write](#when-it-cannot-write)

## Why it exists

On appliances where journald is capped for the whole box and another daemon fills it (UniFi OS is the reference case: 80 MB shared, under two hours of history), the journal no longer holds last night by the morning. Neither the cap nor the noisy neighbour can be changed durably — the vendor rewrites both. The event log is a file PacketFrame owns, with only a few events an hour in steady state, so a week of history fits comfortably in its bound.

It carries **transitions and outcomes only**. Periodic stats lines, per-route and per-packet detail stay in the journal; the two are complementary, and the event log's timestamps are what you use to find the right window in the journal while it still has it.

## Where it is

| Config | File |
|---|---|
| nothing | `<state-dir>/events.log` (`/var/lib/packetframe/state/events.log` by default) |
| `event-log /path/to/events.log` | that file |
| `event-log off` | no event log |

`event-log-max <size>` bounds each file (default `10M`; accepts `K`/`M`/`G`, 64K–1G).

**On appliances whose root filesystem is reset by firmware upgrades, point `event-log` at persistent storage.** A log that is wiped with the firmware is gone exactly when you need it — the morning after an upgrade that went wrong. On UniFi OS that means a path under the data partition that survives upgrades rather than the default under `/var/lib`.

**Symlinks in the path.** The daemon writes as root, so it does not follow a symlink an unprivileged user could have planted. A symlinked *directory* in the path is followed only when root alone could have made it: the link is owned by root, and so is the directory holding it, which group and others cannot write. That covers an appliance whose persistent storage is itself a root-owned symlink — `/data` pointing into a storage mount, say — so `event-log /data/packetframe/events.log` works as written. The link's target is checked the same way, hop by hop, up to 8 links (a loop is refused). Any other symlink is refused, and the error on `packetframe status` says why (who owns the link or its directory, or that the directory is group/world-writable) — point `event-log` at the resolved path (`readlink -f`) instead. A symlink at the file itself (or at its `.1`) is never followed. The state files under `state-dir` keep the stricter rule: no symlink anywhere in their path.

Both directives are **restart-only**: the writer owns an open file. A reload that changes them logs a warning and keeps the current file until the next restart; `packetframe status` shows the file the daemon is actually writing.

## Reading it

```sh
sudo packetframe events                         # everything, oldest first
sudo packetframe events --since 12h             # 90s, 30m, 12h, 2d, 1w
sudo packetframe events --since 2026-09-27T06:00:00Z
sudo packetframe events --module vpp-offload    # daemon, vpp-offload, fast-path, guard, neigh-snoop, event-log
sudo packetframe events --json | jq .           # as stored, one object per line
packetframe events --file ./events.log          # a copy pulled off a router
```

It reads the rotated `.1` then the current file, so the output is continuous across a rotation; both are opened before either is read, and re-opened if a rotation lands between the two opens, so a generation is never skipped. Records are streamed and printed as they are read, so memory stays at one record whatever the file sizes; a line longer than 64 KiB is not a record and is skipped and counted. It works without the daemon running. Human output is one line per event: timestamp, level, module, kind, the `detail` sentence, then the remaining fields in brackets.

`packetframe status` ends with a section saying where the log is, how full it is, and — from the daemon's last health snapshot — how many events were written, dropped or lost, and the error if the daemon cannot write it. When a daemon has published a snapshot, the section describes the file that daemon is writing; if the config now names a different one (a restart-only edit, reloaded), that appears on its own line as `after restart: …`.

## Format

Newline-delimited JSON, one object per event:

```json
{"ts":"2026-09-27T06:12:03.412Z","module":"vpp-offload","event":"steering_up","level":"info","detail":"allowlisted traffic is diverted to VPP; the eBPF tier remains the failover"}
{"ts":"2026-09-27T06:14:40.007Z","module":"fast-path","event":"module_health","level":"warn","detail":"bgp-listener: session down","from":"healthy","to":"degraded"}
```

| Key | Meaning |
|---|---|
| `ts` | RFC 3339, UTC, millisecond precision — when the transition happened, not when it was written |
| `module` | The module the event is about; `daemon` for process-level events, `event-log` for the log's own |
| `event` | A stable, machine-readable kind (below) |
| `level` | `info`, `warn` or `error` |
| everything else | The event's fields: usually `detail` (a sentence), plus counts and reasons. String fields are capped at 1024 characters |

## Event kinds

Kinds are stable: scripts and alerts may key on them.

**Process (`module: daemon` unless noted)**

| Kind | When | Fields |
|---|---|---|
| `process_start` | `packetframe run` read its config | `version`, `pid`, `config` |
| `process_stop` | The daemon exits | `reason` (`signal`, `breaker`, `error`), `stage` and `detail` on error |
| `module_attached` | A module came up (`module`: that module) | `attachments` |
| `module_start_failed` | A degrading module did not come up and the daemon ran on without it | `stage`, `degraded`, `detail` |
| `circuit_breaker_tripped` | The breaker fired and every module is being detached | `detail` |
| `reconfigure_refused` | A SIGHUP's config was refused whole; nothing applied | `stage` (`parse`, `validate`), `detail` |
| `reconfigure_applied` | One module applied a SIGHUP's config (`module`: that module) | — |
| `reconfigure_failed` | One module did not (`module`: that module; the others did, nothing rolled back) | `detail` |
| `module_health` | A module's overall health changed and held for two polls (~10 s) (`module`: that module) | `from`, `to` (`healthy`, `degraded`, `unhealthy`, `unknown`), `detail` (the failing subsystems) |
| `detach` | `packetframe detach` finished | `outcome`, `all`, `keep_vpp`, `vpp` (`kept`, `torn-down`, `teardown-failed`, `out-of-scope`), `detail` on failure |

**vpp-offload**

| Kind | When | Fields |
|---|---|---|
| `steering_up` | Allowlisted traffic diverted to VPP | `detail` |
| `steering_down` | Traffic returned to the eBPF tier | `cause` (`unsteer`, `nothing-to-steer`) |
| `steering_restored` | An adopted VPP took the traffic back while the fallback was not ready | `detail` |
| `steer_failed` | A steer or restore-steer failed; repeats of the same failure are recorded once. With `rules_remain: true` the rollback left rules in the NIC and traffic matching them is still on VPP | `action`, `reason`, `rules_remain` |
| `unsteer_failed` | Steering could not be removed; the VF is withheld | `reason` |
| `verify_passed` / `verify_failed` / `verify_incomplete` | A verify finished | `outcome`, `seeded`, `may_steer`; a re-run of a stale incomplete verdict carries `outcome` and `rerun: true` instead, and decides nothing |
| `unresolvable_routes` | The set of named unresolvable routes changed (at most once a minute) | `ipv4`, `ipv6` (`<prefix> via <nexthop> [dev <device>] (<why>)`, `; `-separated, then `+K more`); `detail: none` once the set empties |
| `adoption_path` | How a start took over VPP's FIB | `path` (`preserved-ledger`, `readback`, `readback-deferred`, `fresh`), `routes` |
| `preserved_ledger_rejected` | The preserved route ledger was not used | `stage`: the check that refused it — at bring-up `untrusted`, `too-large`, `unreadable`, `corrupt`, `format-version`, `unremovable`, `process`, `token`, `interfaces`; later `seed`, `fingerprint`, `fingerprint-moved`, `verify` ([table](vpp-offload.md#what-a-keep-vpp-restart-costs-now-the-preserved-route-ledger)) — and `reason` |
| `ledger_preserved` | A preserving stop handed (or failed to hand) the ledger to the next start | `preserved`, `routes` or `reason`, `state` |
| `vpp_teardown` | The supervisor ordered VPP torn down | `cause`, `from_state`, `to_state`; with `cause: Wedged` also the evidence: `silent_ms`, `counted_ms`, `budget_ms`, `steered`, `unanswered_probes`, `last_probe_error`, `vpp_wait_ms`, `loop_gap_ms`, `stalls_excused` ([reading them](vpp-offload.md#a-teardown-with-causewedged)) |
| `handback_ready` / `handback_held_back` | The IPv6 hand-back path changed readiness; the v6 half of steering follows it | `detail` |
| `keep_queue0_fallback` | A port's driver refused an RSS-action keep rule or stored it without RSS, so that port's keeps deliver to PF queue 0. Once per port per daemon | `port`, `detail` (the driver's answer) |
| `kernel_path_dropping` | A steered port's kernel path started dropping frames (`dropping: true`), or stopped (`false`). At most one `true` per port every ten minutes | `port`, `dropping`, `drops_per_second`, `queue0_share`, `keep_form` |

**fast-path**

| Kind | When | Fields |
|---|---|---|
| `wan_egress_repaired` | `wan-egress` put back policy rules that had disappeared from the kernel while the config was unchanged. At most one every five minutes; repairs in between are counted in the next one | `added`, `removed`, `suppressed`, `main_priority` |
| `route_ledger_preserved` | A clean stop wrote (or failed to write) the route mirror as the route ledger. Not emitted with `route-ledger off` or without a `route-source` | `preserved`; when true `routes_v4`, `routes_v6`, `advertisements`, `bytes`, `encode_ms`, `write_ms`, and `unconfirmed_for_secs` when some routes had not been re-confirmed by a live session; when false `reason` |
| `route_ledger_seeded` | A start seeded the route mirror from the ledger | `routes_v4`, `routes_v6`, `advertisements`, `age_secs`, `writer_version`, `took_ms`, `failed` when some prefixes could not be installed |
| `route_ledger_refused` | A start did not seed (warn for the faults, info for the expected outcomes); the mirror loads cold | `reason` (`missing`, `disabled`, `forwarding-mode`, `no-route-source`, `unreadable`, `unremovable`, `corrupt`, `format-version`, `identity`, `too-old`, `clock`, `peer-id`), `detail` |
| `route_ledger_reconciled` | The route source's first completed dump after a seed garbage-collected what it did not re-advertise | `gc_removed` |

**The log itself (`module: event-log`)**

| Kind | When | Fields |
|---|---|---|
| `events_dropped` | The queue was full; recorded ahead of the next event written | `count` |
| `event_log_recovered` | Writes succeed again after a failure | `lost`, `error` |

A restart reads as `route_ledger_preserved` and `ledger_preserved` (both written by the stopping daemon before it records its exit) → `process_stop` → `process_start` → `module_attached` … → `route_ledger_seeded` → `adoption_path` → `verify_passed` → `steering_up` (or `steering_restored`), then `route_ledger_reconciled` once the route source's replay finishes. A crash loop reads as a column of `process_start` / `process_stop` pairs.

## Rotation and size

When the next line would take the file past `event-log-max`, it is renamed to `<file>.1` — replacing the previous `.1` — and a fresh file is started. At most two files exist, so the log never takes more than twice the bound. At a few hundred bytes an event and a few events an hour, the default 10 MiB holds months.

Whenever the writer opens the file — at start, after a rotation, when recovering from a write failure — each generation already over the bound (left by a larger `event-log-max`) is trimmed to its **newest** whole lines within it, streamed through a temp file and renamed over the original. The older lines were already outside what the bound promises; the newest are what the log is read for. So lowering `event-log-max` takes effect at the next restart rather than months later when the old file rotates out.

Each event is one `write(2)` as soon as it arrives; there is no fsync per event (flash wear). The file is synced once on a clean stop. A power cut can lose the last few seconds of events, and at worst tears the last line, which `packetframe events` skips and counts. A line torn by a failed write (ENOSPC part-way through) is **truncated away** when the file is next opened, so the next record starts on a line of its own instead of being welded to the fragment; the fragment was an event already counted as lost.

## When it cannot write

The event log can never block or fail the data plane or a module. Events go through a bounded in-memory queue to one writer thread; a full queue drops the event and counts it (`events_dropped`). A write that fails — disk full, permissions, a symlink where the file should be (refused, never followed), a symlinked directory root did not make (see [Where it is](#where-it-is)) — costs **one** `WARN` in the journal, the error on `packetframe status`, and nothing else. The writer retries every 30 s — on that schedule, whether or not new events arrive; while it is failing, events are counted as lost without touching the disk. When a write succeeds again it records `event_log_recovered` with how many events the outage cost, and logs that in the journal too.
