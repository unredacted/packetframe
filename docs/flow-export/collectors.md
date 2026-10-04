# Flow-export collector evidence

What two collectors actually do with each representation PacketFrame's flow
export could send. This was measured before the exporter existed, so the
exporter is built against evidence rather than documentation.
The records came from `packetframe flow-synth` (`dev-tools` feature), which
models a known packet stream and sends exactly what the exporter will send.

**Bottom line**

- **Scaling:** both collectors apply the sampling rate exactly once for every
  format they accept.
- **Every format works with Akvorado,** provided template-based formats run with
  `load-balance: by-exporter`.
- **FastNetMon Community:**
  - It **ignores the IPFIX in-record sampling interval.**
  - It **cannot attribute records without addresses.**
  - It **lifts bans when telemetry stops.** PacketFrame has to cover that with
    a separate mechanism (see "Telemetry loss").

## Versions (pinned, arm64, 2026-10-04)

| Component | Image | Digest |
|---|---|---|
| Akvorado | `quay.io/akvorado/akvorado:2026.10.0` | `sha256:347e5e94767073722bce67520623c7cf5a25f495acf423dc25084497ade2ccf1` |
| — ClickHouse | `clickhouse/clickhouse-server:26.8` | `sha256:bca86231e6f8e8969f442135843e44105d54fa61babd84b71f6f7c146f207a8e` |
| — Kafka | `apache/kafka:4.3.1` | `sha256:77e3df9054047a88b520d0cc46e16696d3b22022e1d580aeccd2632df6532837` |
| FastNetMon Community | `ghcr.io/pavel-odintsov/fastnetmon-community:1.2.9` | `sha256:c154b5b5fd74286719c1c1b97d02157a559926b7749fb5afa958d5faccbd5a0e` |

**Akvorado** ran its release quickstart stack (`docker-compose.yml`), plus:
- a static metadata provider (no SNMP);
- memory caps;
- no kafka-ui;
- no GeoIP databases.

Steady-state memory was about 2.0 GiB: ClickHouse 1.14, Kafka 0.52, the rest
under 0.2.

**FastNetMon** ran its stock config with these changes, about 90 MiB:
- `sflow = on` and `netflow = on`;
- `threshold_pps = 50000`;
- `ban_time = 120`;
- `networks_list` = `198.51.100.0/24`;
- a notify script that logs ban and unban.

## Method

Each case models **100,000 packets/s** of 1,000-byte frames (FCS excluded;
986-byte IP packets) towards one documentation address, sampled
**1-in-1000**, for 20–30 s.
That is about 100 samples or records per second, deliberately low-rate.
Sources are drawn from `203.0.113.0/24` and AS numbers come from the
documentation range.

**Pass criteria:**
- **Akvorado** stores `Packets × SamplingRate` of about 100,000 per second, i.e.
  2,000,000 per 20 s run. Checked in ClickHouse.
- **FastNetMon** shows about 100,000 pps for the host in its 5-second average
  and bans it, because the rate is above the threshold.

Unscaled telemetry would show 100 pps. Double-scaled would show 10⁸.

```
packetframe flow-synth --to <collector>:<port> --format <sflow|nfv9|ipfix|psamp> \
  --profile <full|no-source|as-only> --sampling-signal <in-record|options> \
  --dst 198.51.100.N --pps 100000 --sampling 1000 --duration 20s
```

## Matrix

| Representation | Akvorado 2026.10.0 | FastNetMon Community 1.2.9 |
|---|---|---|
| sFlow v5, raw headers | ✅ 2,000,000 / 2,000,000 | ✅ about 100k pps, banned |
| NetFlow v9, rate in each record (`SAMPLING_INTERVAL`) | ✅ 2,000,000 | ✅ 98,161 pps |
| NetFlow v9, rate in an options record | ✅ 2,000,000 ¹ | ✅ 97,760 pps |
| IPFIX, rate in each record only (IE 34) | ✅ 2,000,000 ¹ | ❌ **95 pps: never scaled** |
| IPFIX, rate in a selector options record (IE 302/304/305/306/34) | ✅ 2,000,000 ¹ | ✅ 97,760 pps |
| IPFIX PSAMP packet reports (IE 315 frame section) ³ | ✅ 2,000,000 ¹ | ✅ 98,166 pps |
| Profile `no-source` (no source address), v9 and IPFIX | ✅ stored, source unknown | ✅ detected (keys on destination) |
| Profile `as-only` (no addresses), IPFIX | ✅ stored with AS pair | ❌ no host to attribute to: never detected |
| AS numbers from the records | ✅ used (`asn-providers` default starts with `flow`) | not displayed |
| Interfaces without SNMP | ✅ static provider; unknown output ifIndex (0) stored blank, not rejected | n/a |
| Country | ⚠️ derived only from GeoIP on stored addresses ² | n/a |
| Exporter timestamps | ignored by default (`timestamp-source: udp`) | receive time |

¹ Only with `inlet.kafka.load-balance: by-exporter`. With the default `random`,
an outlet can decode a data datagram before the one carrying its template and
drop it. We measured 0–80 records lost per 2,000, always whole datagrams,
template formats only; sFlow lost none. With `by-exporter` all three
template-based cases measured exactly 2,000/2,000. Akvorado documents this under
`load-balance`.

² No standard IPFIX or NetFlow v9 field carries a country. Akvorado computes
country from the address with GeoIP. So `as-only` and `no-source` records cannot
have a remote country in Akvorado. A truncated address (/24, /48) would still
geolocate, but this lab used documentation prefixes, which have no GeoIP
entries, so that case was **not exercised**.

³ Each report carries `selectionSequenceId` (IE 301), announced by a
Selection Sequence Report Interpretation (RFC 5476 §6.5.1), and also its
`selectorId` (IE 302). Akvorado's decoder looks the sampling rate up by the
selectorId in the report itself, so with only IE 301 it would fall back to an
unscaled rate (read from its source, not measured). Both collectors ignore
the sequence's options record, which carries no rate. The template types the
frame section as Ethernet (`dataLinkFrameType`, RFC 7133).

**Re-measured after review (2026-10-04).** The encoding changed in four
ways:
- sFlow `frame_length` now includes the FCS, with `stripped` = 4;
- PSAMP gained the selection sequence and `dataLinkFrameType` (³);
- every datagram is now sized to fit a 1500-byte path MTU;
- TCP and UDP checksums are now valid.

sFlow, PSAMP, IPFIX with an options record, and NetFlow v9 were each rerun
for 20 s, plus a 60-byte TCP SYN case over sFlow. Every run scaled exactly
once:
- Akvorado stored 2,000,000 / 2,000,000 each time, and the TCP case once its
  held batch was flushed;
- FastNetMon banned the host each time, at about 92–94k pps in its 5-second
  average.

**Bytes.** Collectors differ in which length they count for packet samples.
- **Akvorado**, for sFlow and PSAMP, and **FastNetMon**, for PSAMP, take the IP
  header's total length, i.e. the IP layer.
- **FastNetMon counts sFlow's `frame_length`** by default: on the wire, FCS
  included. A 1,000-byte frame read 741 Mbit/s at 92,307 pps, about
  1,004 B/packet, and a 60-byte frame about 64 B/packet.
  `sflow_read_packet_length_from_ip_header = on` switches it to the IP layer.
- **Flow records** must carry IP-layer octets in `octetDeltaCount` /
  `IN_BYTES` (RFC 5102). The first `flow-synth` draft sent frame bytes, and the
  comparison showed the 14-byte-per-packet discrepancy. Fixed: all flow formats
  read 986 B/packet on both collectors.

## Telemetry loss

**FastNetMon lifts bans when telemetry stops.** Observed run:
- the host was banned at 10:55:38;
- the sender stopped at about 10:56:05;
- the host was unbanned at 10:57:44, after `ban_time` (120 s) plus the 60 s
  cleanup tick.

`unban_only_if_attack_finished = on` (the default) did not help, because silence
reads as "attack finished". FastNetMon Community has no input for exporter
health. So PacketFrame needs a **separate mechanism that holds automatic
withdrawals while flow-export coverage is not healthy**. That belongs to the
mitigation integration (plan Phase 2), driven by the exporter's coverage states.

**Akvorado** takes no actions; a stop simply shows as a drop. One display
artefact: the outlet holds its last partial ClickHouse batch until more flows
arrive. After a stream ends, its final seconds can appear only once other
traffic arrives. We measured about 10% of a 20 s stream held back until then.

## Requirements this puts on PacketFrame's exporter

1. **Carry the sampling rate in an options record** for IPFIX, using a selector
   with `samplingPacketInterval`/`samplingPacketSpace` and IE 34. Do not rely on
   the in-record interval, which FastNetMon ignores. In-record may be added as
   well; Akvorado reads either.
2. **Report IP-layer octets** in flow records. For sFlow, report the on-wire
   `frame_length` with the FCS, `stripped` ≥ 4, which is what FastNetMon
   counts by default.
3. **Send templates early and periodically.** Tell Akvorado operators to run
   `load-balance: by-exporter` for v9/IPFIX/PSAMP. sFlow needs neither.
4. **Do not offer `as-only` to a DDoS-detection collector.** It suits statistics
   (Akvorado stores it), not attribution. `no-source` works for both.
5. **PSAMP packet reports carry both IE 301 and IE 302:** the selection
   sequence the RFC requires, and the selectorId Akvorado scales by.
6. **Country is not exportable** in these formats. A country-only privacy profile
   is blocked for both collectors. Truncation preserves geolocation, untested
   here.
7. **Telemetry health must gate automatic withdrawals** (above), because neither
   collector can tell silence from calm.

## Reproducing

- Akvorado: release `docker-compose-quickstart.tar.gz` for v2026.10.0, with:
  - `outlet.yaml` `metadata.providers` set to a `static` provider (exporter
    `::/0`, ifIndexes 3 and 4);
  - `inlet.yaml` `kafka: {load-balance: by-exporter}`;
  - memory caps: ClickHouse 2g, Kafka 1g with `-Xmx512m`.
- Query:
  ```
  SELECT DstAddr, sum(Packets), sum(Packets*SamplingRate), any(SrcAS), any(DstAS),
         any(InIfName), any(OutIfName) FROM flows GROUP BY DstAddr
  ```
- FastNetMon: the four config changes above. Per-host rates are in
  `/tmp/fastnetmon.dat`, parser counters on its Prometheus endpoint
  (`fastnetmon_{sflow,netflow_v9,ipfix}_*`), actions via the notify script.
