# neigh-snoop

A passive ARP/ND neighbour snooper for IX-facing bridges. It learns
peers' MAC addresses from the neighbour traffic other participants
flood across the fabric, and seeds them into the kernel so the router
can reach peers it has never resolved itself.

On an exchange fabric, every participant's ARP requests and neighbour
solicitations reach every member port, each carrying the sender's
`(ip, mac)`. Linux ignores them unless they ask about one of its own
addresses. When the router is not allowed to send broadcast ARP or
multicast NS itself (a switch ACL drops them), it can only reach a peer
whose MAC it already holds, and after a reboot that can take hours.

**Status:** code-complete and merged; hardware ladder pending.

## What it does

1. **Listens**, receive-only, on each configured bridge through a
   promiscuous AF_PACKET socket with a classic-BPF filter. It **never
   transmits**.
2. **Learns** `(ip, mac)` pairs from third-party ARP requests/replies
   and ICMPv6 NS/NA inside the configured prefixes. Its own addresses
   and MACs are refused, as is anything on the deny list.
3. **Installs** kernel neighbours as `NUD_STALE`, rate limited: when
   the entry is missing, `NONE`, `INCOMPLETE` or `FAILED`, and also when
   a `STALE` entry holds a different MAC, once a 30-second holddown
   since the last install has passed. A STALE entry forwards
   immediately, and the kernel confirms it with a *unicast* probe that
   the ACL permits. It never overrides a MAC the kernel has confirmed
   (`REACHABLE`, `DELAY`, `PROBE`), never touches `PERMANENT` or
   `NOARP` entries, and never installs anything but STALE.
4. **Persists** the table as one JSON file per bridge and re-seeds the
   kernel on start and whenever the bridge comes back. Bridges are
   tracked **by name**, because platform daemons destroy and recreate
   them.
5. **`ix-mode`** tells fast-path's neighbour resolver to stop issuing
   its own broadcast probes for next-hops via that bridge (custom-fib
   only).
6. **`frr-gate`** (optional) keeps FRR's runtime next-hop prefix-lists
   in step with the kernel's resolved neighbours through `vtysh`, so
   routes whose next-hop is not resolved yet can be demoted. It also
   measures how many route-server prefixes are still demoted.

It is userspace only: no BPF program and no pins. `packetframe detach`
has nothing to tear down, and learned entries and the cache are
deliberately left in place.

## Configuration

```
module neigh-snoop
  bridge br0 ix-mode                                  # restart-only
  prefix br0 192.0.2.0/24
  prefix br0 2001:db8:1::/64
  prefix br0 fe80::/10
  deny-mac 02:00:00:00:00:01
  peer br0 192.0.2.10 2001:db8:1::10 route-server
  install-rate 50/1s
  frr-gate v4 IX-RESOLVED-NH v6 IX-RESOLVED-NH6       # restart-only
```

- A `peer` line lists every address one router uses on the fabric.
  Exchanges enforce one MAC per member port, so a MAC learned for any
  of them is installed for all of them. That is how a route server's
  global v6 address gets a MAC when it only solicits from link-local.
- **Restart-only:** `bridge` (and `ix-mode`), `persist-dir`, and
  whether `frr-gate` is present plus its list names. **Hot (SIGHUP):**
  `prefix`, `deny-mac`, `peer`, `seed-max-age`, `install-rate`,
  `table-max`, and the coverage and `frr-gate` intervals.
- The module requires a `fast-path` section. Load refuses, among other
  things, a bridge with no prefix, a `/0` prefix, a peer outside its
  bridge's prefixes, and `route-server` without `frr-gate`.

Roll out with a low `install-rate` and no `ix-mode`, and watch the
table fill before raising the rate. Add `ix-mode`, then `frr-gate`,
once coverage is stable. [`conf/example.conf`](../../../conf/example.conf)
documents every directive.

## Observability

Metrics are labelled `module="neigh-snoop",iface="<bridge>"`: frames
parsed by kind, learn outcomes (`new`, `refreshed`, `mac_changed`, …),
install outcomes, `table_entries`, `link_up`, next-hop coverage, and
`rs_demoted_prefixes` when route-server peers are declared.
`packetframe status` shows a `snoop:<bridge>` health row per bridge
(`capturing` when healthy) plus `coverage` and `peers` rows.

## Source layout

| Path | Contents |
|---|---|
| `src/capture.rs`, `src/bpf_filter.rs` | AF_PACKET socket and its classic-BPF filter |
| `src/frame.rs` | ARP / NS / NA parsing |
| `src/table.rs` | Learned table, kernel-neighbour mirror, install decisions; portable |
| `src/engine.rs` | The event loop that owns all mutable state, fed by I/O tasks |
| `src/netlink.rs` | Kernel neighbour reads and `NUD_STALE` installs |
| `src/persist.rs` | Per-bridge JSON cache |
| `src/coverage.rs`, `src/rs_coverage.rs` | Next-hop and route-server coverage |
| `src/frr_gate.rs` | FRR prefix-list reconciliation over `vtysh` |
| `src/snapshot.rs`, `src/health.rs`, `src/metrics.rs` | The engine's published view, and the health rows and Prometheus output rendered from it |
| `src/probe_linux.rs` | Probes added to `packetframe feasibility` |

Parsing, learning decisions and metrics are portable and tested on
macOS. The socket, netlink and runtime are Linux-only.

## Tests

```sh
cargo test -p packetframe-neigh-snoop                                          # portable
sudo -E $(which cargo) test -p packetframe-neigh-snoop --tests -- --ignored    # netns
```

## Further reading

- [neigh-snoop.md](../../../docs/runbooks/neigh-snoop.md): rollout, counters, the FRR next-hop gate, acceptance tests, triage
