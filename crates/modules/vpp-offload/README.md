# vpp-offload

A second forwarding path for allowlisted traffic. The NIC's hardware
classifier (MCAM ntuple rules) steers matching packets to an SR-IOV
virtual function, where a VPP process that PacketFrame starts and
supervises forwards them. VPP's FIB is a mirror of the routes the
fast-path already resolved, so both paths make the same decisions, and
the eBPF fast-path on the physical ports stays the permanent fallback.

The module contains no dataplane code. It orchestrates: it acquires
hugepages, VFs and vfio bindings, renders VPP's `startup.conf`, runs
and supervises VPP, programs VPP's FIB over the binary API, and owns
the steering rules.

**Status:** has forwarded production traffic on one steered port, at
the first rung of the canary ladder. It is not deployed in production
today. Before enabling it anywhere, read the opening section of the
[runbook](../../../docs/runbooks/vpp-offload.md), which records exactly
what has and has not been proven on hardware.

## How it works

```text
 routing daemon ─iBGP─→ fast-path FibProgrammer ──→ BPF maps        (fallback tier)
                                 │
                                 └─ resolved best paths ─→ vpp-offload ─binary API─→ VPP FIB
                                                                                      + static neighbours
 PF ── MCAM steer (allowlist × src/dst) ──→ VF ──→ VPP workers ──→ VF tx
  └── everything else ──→ kernel path, with the eBPF fast-path in front
```

Three rules shape the design:

- **VPP mirrors the programmer, not the route feed.** It gets the
  fast-path's resolved best paths, refusals included, so failing over
  between the tiers never changes where a packet goes.
- **Membership and steering are separate.** VPP must own a VF on
  *every* port a best path might leave by before *any* port is steered.
  Membership is all-or-nothing and checked when the config loads.
  `steer on|off` is per port and is the canary lever.
- **VPP never ARPs.** Neighbours are installed statically from the
  fast-path resolver. The steering rules match IPv4 fields only, so ARP
  frames never reach VPP.

VPP keeps running across a PacketFrame restart and is adopted again on
start. The resources it holds are recorded in a state file for that
purpose.

## Configuration

```
module vpp-offload
  loopback-address 198.51.100.1/32
  port eth0 cores 1 steer off
  port eth1 cores 0 steer off
  port eth2 cores 1 steer off vlans 100,200
  steer-exempt 192.0.2.1/32
  expected-routes 1600000
  hugepages 10
```

- `loopback-address` is mandatory. Without it, member ports are up but
  forward nothing. Use an address that is announced but not assigned
  to anything, including the kernel.
- There must be a `port` line for every fast-path `attach` interface.
  `cores 0` puts egress-only members on one shared worker, and such a
  port cannot be steered. Trunk ports need `vlans` before they can be
  steered.
- `steer-exempt` keeps a destination on the kernel path. Nothing is
  exempted automatically beyond broadcast and multicast, so **list
  every one**: each address that terminates on the router for a
  steered VLAN, and every destination the kernel sends through a device
  VPP does not own (VTIs, WireGuard, other tunnels). An unlisted one is
  steered into VPP and blackholed. The `packetframe_vpp_exempt_drift`
  gauge reports kernel paths that are missing an exemption; it does not
  add them.
- `local-route`, `steer-direction`, `require-table-complete` and
  `vpp-binary` cover delivery to local prefixes, which side of a flow
  is steered, the wait for a converged table, and the binary path.

**Reloads.** Only `steer` (and `steer-exempt` / `steer-direction`)
change under a running VPP: a SIGHUP applies them as an MCAM delta,
with no VPP restart and no resync. Everything else is fixed when VPP
starts, and `reconfigure` refuses it by name. All ports as members with
steering off is the safe staging state and where every rollback ends.

The rule budget is small. On the Marvell NIC this was built for, the
ntuple table holds **16 rules per port**. Each steered IPv4 prefix costs
one rule per direction, two go to built-in broadcast/multicast
exemptions, and each `steer-exempt` costs one more. An allowlist that
does not fit is refused as a whole rather than half-steered.
`packetframe feasibility` reads the real free count from the NIC and
reports it as `vpp.steering.budget`. That NIC cannot match IPv6 ntuple
rules, so IPv6 stays on the XDP path.

All of it is documented inline in
[`conf/example.conf`](../../../conf/example.conf).

## Observability

`packetframe status` shows five health rows: `vpp-process`, `api-ping`,
`fib-synced`, `steering` and `ports`. `route-feed` and `state-file`
appear only when they fail. Overall health tracks whether packets are
being forwarded correctly. A crash-looping VPP with nothing steered is
`Degraded`, because the eBPF path is carrying the traffic, while a
steered VPP that cannot forward is `Unhealthy`.

Prometheus gauges are `packetframe_vpp_*`. The runbook lists which ones
to alert on.

## VPP compatibility

The module works with any VPP whose binary-API message CRCs match the
definitions vendored in [`vpp-api/`](vpp-api/); the handshake refuses
any other VPP at attach and names the message that differs. `SOURCE.json`
records the VPP release those definitions came from, and CI checks the
vendored files against that release byte for byte. The bump procedure
is in [`vpp-api/README.md`](vpp-api/README.md). No VPP source lives in
this repo; for UniFi gateways, VPP is built by
[unredacted/vpp-unifi](https://github.com/unredacted/vpp-unifi).

## Source layout

| Path | Contents |
|---|---|
| `src/bringup.rs` | What `Module::attach` does, composed from the layers below |
| `src/resources.rs`, `src/acquire.rs` | Hugepages, VFs, vfio; the state file; adoption on restart |
| `src/startup_conf.rs`, `src/cores.rs` | `startup.conf` rendering, memory sizing from route count, CPU placement |
| `src/supervisor.rs`, `src/process.rs`, `src/liveness.rs`, `src/schedule.rs`, `src/executor.rs`, `src/driver.rs` | Supervision of the VPP process |
| `src/vpp_api/` | Generated wire structs, codec, socket transport, CRC handshake |
| `src/feed.rs`, `src/sink.rs`, `src/fib_sync.rs`, `src/engine.rs` | Route feed from fast-path, route ledger, resync and deltas into VPP |
| `src/attach.rs`, `src/verify.rs` | Device attach and FIB readback verification |
| `src/steer.rs`, `src/ntuple.rs` | Steering plans, and installing and reading back MCAM rules |
| `src/drift.rs`, `src/fdb.rs` | Checks for unexempted kernel paths and misplaced local-route hosts |
| `src/status.rs`, `src/runtime.rs`, `src/service.rs` | Health, metrics, and the runtime thread |

## Tests

```sh
cargo test -p packetframe-vpp-offload
```

The tests need no hardware or root. They run `Module::attach` end to
end against a fixture sysfs and a fake VPP on a real socket, and they
check the generated API against golden vectors. Anything that needs a
real VPP or NIC is covered by the hardware drills in the runbook.

## Further reading

- [vpp-offload.md](../../../docs/runbooks/vpp-offload.md): healthy state, canary ladder, rollback, triage
- [vpp-offload-spike.md](../../../docs/runbooks/vpp-offload-spike.md): how it was first brought up on test hardware
