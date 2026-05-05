# Reconfigure (SIGHUP) — operator guide (v0.2.4+)

What `packetframe reconfigure` and `systemctl reload packetframe` do, what's hot-reloadable, and what still needs a full restart. The wiring landed in v0.2.4; before that, the README's `systemctl reload packetframe` line was aspirational.

## Contents

- [Quick reference](#quick-reference)
- [What's hot-reloadable](#whats-hot-reloadable)
- [What requires a restart](#what-requires-a-restart)
- [How the handshake works](#how-the-handshake-works)
- [Error semantics](#error-semantics)
- [Operating under systemd](#operating-under-systemd)

## Quick reference

```sh
# Edit /etc/packetframe/packetframe.conf, then:
sudo packetframe reconfigure                # synchronous; exits non-zero on parse error
sudo systemctl reload packetframe           # equivalent — both end up sending SIGHUP

# Inspect the latest reconfigure result:
cat /var/lib/packetframe/state/last-reconfigure.timestamp
# OK <unix_ns>                              — config parsed + every module reconciled
# ERR parse: <message>                       — config didn't parse; daemon kept old config
# ERR module: <name>: <message>; ...         — at least one module's reconcile() failed
```

The CLI returns immediately on parse failure (exit non-zero, message on stderr). On success it polls the marker file for up to 5s and returns 0 once the daemon has acknowledged.

## What's hot-reloadable

These directives can be added, removed, or changed under SIGHUP without re-attaching XDP:

| Directive | Map(s) updated | Notes |
|---|---|---|
| `allow-prefix`, `allow-prefix6` | `ALLOW_V4`, `ALLOW_V6` | Delta diff vs in-kernel state |
| `block-prefix` | `BLOCK_V4` | v0.2.4+ — wired up alongside reconfigure |
| `dry-run on/off` | `CFG.dry_run` | Single-byte write |
| `forwarding-mode {kernel-fib\|custom-fib\|compare}` | `CFG.flags` bits 3-4 | Atomic |
| `mss-clamp …` (all four grammars) | `MSS_CLAMP_V4/V6` + `MSS_CLAMP_BY_IFACE` + `CFG.mss_clamp_global` | v0.2.4+ — value changes also pick up |
| (auto) VLAN-subif resolution | `VLAN_RESOLVE` | Re-scanned from `/proc/net/vlan/config` |
| (auto) Redirect devmap | `REDIRECT_DEVMAP` | Re-scanned from `/sys/class/net` |

Adds-before-removes ordering: a renamed prefix (remove + add of the same value) never has a window where neither exists.

## What requires a restart

These need `systemctl restart packetframe` (or stop + run):

- **`attach` directives (interface added or removed).** XDP attach mutates kernel-side state and risks brief link bounce on some drivers (SPEC §11.8). The reconcile path explicitly logs a warning and skips attach-set changes — your delta does not silently apply.
- **`route-source` config (custom-FIB only).** The RouteController's runtime is started at attach. Editing the BGP/BMP listener address or peer-AS requires bringing the runtime down and back up.
- **`circuit-breaker` thresholds.** The breaker sampler thread reads its config at thread start; it doesn't currently observe SIGHUP.
- **`local-prefix` directives (custom-FIB only).** The connected-fast-path resolver is similarly attach-time-bound.
- **`bpffs-root`, `state-dir`.** Used at module load only; baked into the running daemon's pin paths and the metrics file location.

If you change one of these in the config and reload, the daemon keeps using the old value silently (with a `WARN`-level log line for attach-set changes). Restart is the only way through.

## How the handshake works

1. The daemon writes `/var/lib/packetframe/state/packetframe.pid` after attach succeeds and removes it on clean exit.
2. `packetframe reconfigure` (or systemd's `ExecReload=`) reads the PID file and cross-checks `/proc/<pid>/comm == "packetframe"` to defend against stale-PID-after-process-recycle.
3. The CLI snapshots the mtime of the ack-marker file (`last-reconfigure.timestamp`), then sends SIGHUP via `kill(2)`.
4. The daemon's signal loop catches SIGHUP, re-parses the config, and calls `Module::reconfigure()` on each loaded module. Per-module errors are logged but not fatal — partial-update state is strictly better than halting mid-reconcile.
5. The daemon writes `OK <unix_ns>` (or `ERR <reason>`) to the marker file via write-then-rename.
6. The CLI polls every 100 ms for up to 5s. When the marker's mtime advances, it reads the body and exits accordingly.

If the daemon doesn't ack within 5s, the CLI exits with a "wedged daemon" message. In practice this only fires if the SIGHUP was lost (kernel signal queue full — extremely unlikely) or the reconcile path itself hangs (no observed cases).

## Error semantics

| CLI exit | Cause | Daemon state |
|---|---|---|
| 0 | `OK` marker observed | New config in effect |
| non-zero, `parse error: ...` on stderr | Config didn't parse | Daemon is **still running with the old config** |
| non-zero, `daemon rejected: <module>: ...` | At least one module's reconcile failed | Other modules reconciled; the failing module retains old map state |
| non-zero, `daemon not running` | PID file absent or stale | Operator action: start the daemon |
| non-zero, `daemon did not acknowledge ... within 5s` | SIGHUP delivered but no marker update | Investigate via `journalctl -u packetframe` |

The "old config preserved on parse error" semantics matter for operators editing live: a typo in the config does not take down the data plane.

## Operating under systemd

The shipped unit at `/lib/systemd/system/packetframe.service` (installed by the `.deb`) wires `ExecReload=/bin/kill -HUP $MAINPID` and `PIDFile=/var/lib/packetframe/state/packetframe.pid`. So:

```sh
sudo systemctl reload packetframe        # equivalent to `packetframe reconfigure`
journalctl -u packetframe --since '5min ago' | grep -i 'sighup\|reconfigure\|reconcile'
```

systemd's `reload` is fire-and-forget — it doesn't poll the ack marker. If you want exit-code-on-failure semantics for scripted use, prefer `packetframe reconfigure` directly.

The unit ships disabled by default (the `.deb` postinst does not auto-enable). After editing the config the first time you'll want:

```sh
sudo systemctl enable --now packetframe
```
