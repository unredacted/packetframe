# A collector host for flow export

What flow export needs of the two collectors it is built for, run on one VM
with each project's own Docker Compose deployment:
- **Akvorado** receives IPFIX.
- **FastNetMon Community** receives sFlow.

The routers reach the VM over Tailscale.

The versions are Akvorado v2026.10.0, the one flow export was tested against
([collector evidence](collectors.md)), and FastNetMon 1.2.10.

## The host

- **CPU:** x86-64-v3 (AVX2), or ARMv8.2 with `dotprod` and `lrcpc`. ClickHouse
  since 26.6 needs one of these and dies with SIGILL without it.
  - Many hypervisors' default virtual CPU lacks AVX2: give the VM the host's
    CPU type.
  - An EFG's OCTEON cores are too old as well.
- **Size:** 4 vCPU and 8 GB RAM. In the lab, at little load, Akvorado's whole
  stack used about 1.2 GB.
  - Disk: 100 GB SSD to start. After a day of real flows, set ClickHouse's
    retention from what you measure.
- **Docker:** use Docker's default port publishing (iptables). It keeps each
  router's address, which Akvorado keys exporters on. A userland proxy shows
  every router as the bridge's gateway.
  - Publish the collectors on the VM's Tailscale address. Docker must then
    start after tailscaled has that address, or the bind fails.
- **Tailnet policy:** the routers reach the VM on UDP 4739 (IPFIX) and 6343
  (sFlow); whoever reads Akvorado's console reaches its port. tailscaled drops
  whatever the policy does not allow, silently.

## Akvorado

Akvorado's release quickstart (`docker-compose-quickstart.tar.gz`), changed in
its `docker/docker-compose-local.yml`, which its `.env` loads last:
- **The inlet** publishes UDP 4739 on the Tailscale address only.
  - sFlow goes to FastNetMon, so the inlet's 6343 need not be published.
  - The outlet's BMP port is unused.
- **The console** (Traefik's public entrypoint) goes on the Tailscale address,
  behind basic auth: that file carries the example.
  - Without auth, the quickstart serves the console to anyone, as one fixed
    user.
  - Traefik's private entrypoint (8080), which exposes ClickHouse and the
    configuration, stays on loopback.
- **Memory:** cap ClickHouse and Kafka so they cannot starve FastNetMon, for
  example 4 GB and 1.5 GB with a 768 MB Kafka heap. kafka-ui is not needed.

In its configuration:
- **`config/inlet.yaml`:** IPFIX needs Kafka balanced by exporter. With the
  default `random`, template-based records are lost ([why](collectors.md)).
  ```yaml
  kafka:
    load-balance: by-exporter
  ```
- **`config/outlet.yaml`:** a `static` metadata provider in place of the SNMP
  one, since the routers answer no SNMP.
  - Each router's entry is what `packetframe flow-export interfaces
    --default-speed 1000` prints on it.
  - Key each entry by that router's `source-address`:
  ```yaml
  metadata:
    providers:
      - type: static
        exporters:
          "192.0.2.1":            # a router's source-address
            name: "router-a"
            ifindexes:
              3:
                name: "eth1"
                speed: 10000
  ```
- **GeoIP:** the quickstart's IPinfo databases (country, ASN) need no token.

## FastNetMon

The image `ghcr.io/pavel-odintsov/fastnetmon-community:1.2.10`, with UDP 6343
published on the Tailscale address. Its `fastnetmon.conf` changes:
- `sflow = on`;
- `netflow = off`;
- `average_calculation_time = 5`: PacketFrame's coverage windows are 5 s too;
- `networks_list`: the prefixes you protect;
- ban thresholds (`threshold_pps`, `threshold_mbps`, `threshold_flows`) for
  your traffic.

**It lifts a ban when sFlow stops**, although the attack goes on: it reads
silence as calm ([evidence](collectors.md), and the lab again with
PacketFrame's exporter). Mitigation must not rest on its ban alone; that is
what PacketFrame's coverage handle is for.

**The 1.2.10 image carries the same binary as 1.2.9**, without the fix for
[CVE-2026-92698](https://github.com/pavel-odintsov/fastnetmon/security/advisories/GHSA-852r-3wcv-pjx2):
- one crafted sFlow datagram reads out of bounds and can crash it;
- the fix is on master, not yet in a release.

Keep its sFlow port reachable from the routers only. On a tailnet, peers
cannot be spoofed.

## The routers

On each router, in `module flow-export` (the [runbook](../runbooks/flow-export.md)
has every line):

```
module flow-export
  source-address 192.0.2.1                 # this router's Tailscale address
  path-mtu 1280                            # Tailscale's MTU: datagrams of 1232 bytes
  collector akv ipfix 198.51.100.10:4739 kind stats
  collector fnm sflow 198.51.100.10:6343 kind ddos
```

Here `198.51.100.10` stands for the VM's Tailscale address.

## Checking it

| Where | What to read | Expect |
|---|---|---|
| Router | `packetframe status` | each collector row `healthy`. That is submission: the router cannot see receipt |
| Akvorado | in ClickHouse: `SELECT ExporterAddress, count(), max(TimeReceived) FROM flows WHERE TimeReceived > now() - INTERVAL 5 MINUTE GROUP BY ExporterAddress` | each router, by its `source-address` |
| FastNetMon | its Prometheus counter `fastnetmon_sflow_raw_udp_packets_received` | rising |

## Moving FastNetMon later

Once FastNetMon drives mitigation, it belongs on a host Akvorado's ClickHouse
and Kafka cannot starve. Start it there, then change each router's
`collector fnm` line; it is reloadable (`packetframe reconfigure`).
