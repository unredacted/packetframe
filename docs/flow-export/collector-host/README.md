# A collector host for flow export

One Linux VM running the two collectors flow export is built for:
- **Akvorado**, from its release quickstart, receiving IPFIX;
- **FastNetMon Community**, receiving sFlow.

Each runs as a Docker Compose project of its own. The routers reach the VM over
Tailscale.

This directory holds only what differs from upstream:

| File | What it is |
|---|---|
| `akvorado/docker-compose-local.yml` | Replaces the quickstart's own local override |
| `akvorado/metadata.example.yaml` | The shape of the interface map, per router |
| `fastnetmon/compose.yml` | FastNetMon's project |
| `fastnetmon/setup.sh` | Writes its config from the pinned image's own |
| `fastnetmon/notify_about_attack.sh` | Logs bans and unbans |
| `host/docker-after-tailscale.conf` | A systemd drop-in |

Versions are the ones flow export was tested against
([collector evidence](../collectors.md)): Akvorado v2026.10.0 and FastNetMon
1.2.9.

## The host

- **CPU:** x86-64-v3 (AVX2), or ARMv8.2 with `dotprod` and `lrcpc`. ClickHouse
  since 26.6 needs one of these and dies with SIGILL without it.
  - Many hypervisors' default virtual CPU lacks AVX2: give the VM the host's
    CPU type.
  - An EFG's OCTEON cores are too old as well.
- **Size:** 4 vCPU and 8 GB RAM. Disk: 100 GB SSD to start; after a day of real
  flows, set ClickHouse's retention from what you measure.
- **Software:** Docker Engine with the Compose plugin, from Docker's own
  packages; and Tailscale.
- **Docker networking:** keep Docker's default port publishing (iptables). It
  keeps the routers' addresses, which Akvorado keys exporters on. A userland
  proxy shows every router as the bridge's gateway.
- **Start order:** the collectors are published on this host's Tailscale
  address, which must exist when Docker starts them. Install the drop-in:
  ```sh
  sudo install -D -m 0644 host/docker-after-tailscale.conf \
    /etc/systemd/system/docker.service.d/after-tailscale.conf
  sudo systemctl daemon-reload
  ```
- **Tailnet policy:**
  - each router reaches this host on UDP 4739 (IPFIX) and 6343 (sFlow);
  - whoever reads the console reaches TCP 8081.

  tailscaled drops whatever the policy does not allow, silently.

## Akvorado

```sh
mkdir akvorado && cd akvorado
curl -fsSL https://github.com/akvorado/akvorado/releases/download/v2026.10.0/docker-compose-quickstart.tar.gz | tar xz
cp ../packetframe/docs/flow-export/collector-host/akvorado/docker-compose-local.yml docker/
echo "COLLECTOR_ADDR=$(tailscale ip -4)" >> .env
```

Then four edits:

1. **Console login.** In `docker/docker-compose-local.yml`, replace
   `REPLACE_WITH_HTPASSWD_LINE` with the output of `htpasswd -nB <user>`, every
   `$` doubled.
   - Without it, the quickstart serves the console to anyone, as one fixed user.
   - The console is published on the tailnet only. Port 8080, which exposes
     ClickHouse and the configuration, stays on this host's loopback.
2. **IPFIX load balancing.** Append to `config/inlet.yaml`:
   ```yaml
   kafka:
     load-balance: by-exporter
   ```
   With the default `random`, template-based formats lose records
   ([why](../collectors.md)).
3. **Interface names.** Replace the `metadata:` section of `config/outlet.yaml`
   (an SNMP provider; the routers answer no SNMP) with a static one, shaped like
   `akvorado/metadata.example.yaml`.
   - Each router's entry is what `packetframe flow-export interfaces
     --default-speed 1000` prints on it.
   - Key each entry by that router's `source-address`.
4. **GeoIP.** The quickstart's `.env` loads IPinfo's free country and ASN
   databases. Keep that, or remove the line for no geolocation.

```sh
docker compose up -d --wait
```

The caps in `docker-compose-local.yml` fit the 8 GB host: ClickHouse 4 GB, Kafka
1.5 GB with a 768 MB heap. In the lab, at little load, the whole stack used
about 1.2 GB.

## FastNetMon

```sh
cp -r ../packetframe/docs/flow-export/collector-host/fastnetmon . && cd fastnetmon
echo "COLLECTOR_ADDR=$(tailscale ip -4)" > .env
./setup.sh <each prefix you protect>
```

Set the ban thresholds (`threshold_pps`, `threshold_mbps`, `threshold_flows`)
for your traffic in `fastnetmon.conf`, then:

```sh
docker compose up -d
```

`log/actions.log` has a line per ban and unban.

**It lifts a ban when sFlow stops**, although the attack goes on: it reads
silence as calm ([evidence](../collectors.md), and the lab again with
PacketFrame's exporter). Mitigation must not rest on its ban alone. That is
what PacketFrame's coverage handle is for.

## The routers

On each router, in `module flow-export` (the [runbook](../../runbooks/flow-export.md)
has every line):

```
module flow-export
  source-address 192.0.2.1                 # this router's Tailscale address
  path-mtu 1280                            # Tailscale's MTU: datagrams of 1232 bytes
  collector akv ipfix 198.51.100.10:4739 kind stats
  collector fnm sflow 198.51.100.10:6343 kind ddos
```

Here `198.51.100.10` stands for this host's Tailscale address.

## Checking it

| Where | What to run | Expect |
|---|---|---|
| Router | `packetframe status` | each collector row `healthy`. That is submission: the router cannot see receipt |
| Akvorado | `docker compose exec clickhouse clickhouse-client --query "SELECT ExporterAddress, count(), max(TimeReceived) FROM flows WHERE TimeReceived > now() - INTERVAL 5 MINUTE GROUP BY ExporterAddress"` | each router, by its `source-address` |
| FastNetMon | `curl -s 127.0.0.1:9209/metrics \| grep fastnetmon_sflow_raw_udp_packets_received` | rising |

## Moving FastNetMon later

Once FastNetMon drives mitigation, it belongs on a host Akvorado's ClickHouse
and Kafka cannot starve. Copy `fastnetmon/` there, start it, and change each
router's `collector fnm` line. That line is reloadable: `packetframe reconfigure`.
