# vpp-offload gate 0b: the VPP spike (shadow gateway)

Manual procedure — no packetframe code. Purpose: prove the full VPP
stack on the fleet platform and produce the measured numbers the
implementation slices consume. Prerequisites already proven (2026-08-01,
gate 0a): SMMUv3 active, SR-IOV VF + vfio bind, 512 MiB hugepages,
MCAM PF→VF steering via ntuple, and a DPDK 20.11-era PMD completing the
AF mailbox handshake with packets received in userspace.

Run on the **shadow** (HA twin; same hostname as the primary — confirm
by the `switch0: port ... entered disabled state` standby posture in
dmesg before touching anything).

## 0. The histogram that can re-scope the phase

Before any VPP work, answer "what does the full-table commitment
actually buy" from the live table. **Not from the kernel**: on a
custom-fib box bird's kernel export was dropped at cutover, so
`ip route show table main` is deliberately near-empty (verified live:
2 routes). The authoritative source is bird's RIB:

```sh
# v4 AND v6 — the full-table commitment covers both, and their egress
# distributions can differ. Count EVERY nexthop, not one per route:
# multipath routes list several, and taking only the last would make
# whichever upstream sorts last look dominant and bias the ~99%
# decision below.
for t in master4 master6; do
  echo "--- $t ---"
  birdc "show route primary table $t" \
    | grep -oE '(via [^ ]+ on [A-Za-z0-9._-]+|^\s+via [^ ]+ on [A-Za-z0-9._-]+)' \
    | grep -oE 'on [A-Za-z0-9._-]+$' | sort | uniq -c | sort -rn
done
birdc 'show route count'
```

(Streams ~1M route lines; a few minutes. Bird prints continuation
lines for additional ECMP nexthops, which the pattern above counts
individually — verify against `birdc 'show route all <a-known-ecmp-prefix>'`
if the multipath share looks surprising.) If ~99%
of routes resolve via one egress device, per-prefix best-path is not
load-bearing and the user re-decides the full-table commitment
(plan v5). Record the histogram in this file's results section either
way — it also sizes the nexthop-device mapping (member ports → VF;
VLAN nexthops → VPP subif; everything else → excluded + counted as
unresolvable).

## 1. Build VPP from source (fd.io debs do not exist for this OS)

Verified 2026-08-01, empirically (don't re-litigate — we extracted the
jammy 24.10 arm64 deb on the shadow and checked): fd.io's release repo
carries Ubuntu noble/jammy (arm64) and Debian bookworm (amd64) — **no
bullseye at all**; Debian proper has never packaged VPP. The jammy deb
fails on this fleet three independent ways: bullseye's dpkg 1.20 can't
unpack its zstd members at all, and the binary's symbol floor is
**GLIBC_2.34** (`objdump -T`) vs UniFi OS's 2.31 — a hard loader
failure, the newer-distro-on-older-host direction of the "wrong-distro
debs often work" folklore. The plan's "fd.io deb vs self-build"
decision is therefore made by packaging reality: **source build,
on-box** (18 cores; deps largely present from the gate-0a testpmd
build). This also opens the cn9k-tuned build as a same-pipeline
variant rather than a separate decision.

Version pins, mirroring the gate-0a two-era doctrine (the AF↔VF
mailbox does not follow newer-is-better):

1. **VPP `stable/2306`** first — the last LTS line with Debian 11
   build support, bundling a DPDK with the modern cnxk PMD.
2. Fallback **`stable/2202`** — bundles DPDK 21.11, the last
   `octeontx2`-named PMD era, closest to the 20.11 build that passed
   gate 0a.

```sh
cd /root && git clone --depth 1 --branch stable/2306 https://github.com/FDio/vpp && cd vpp && UNATTENDED=y make install-dep && make build-release
```

(~30–45 min. Binaries land in
`build-root/install-vpp-native/vpp/bin/vpp` with plugins alongside —
run in place for the spike; `make pkg-deb` later for fleet packaging.)
Record the exact tag/commit — it becomes the pin for slice 3's API
codegen (`build-root/install-vpp-native/vpp/share/vpp/api/**/*.api.json`).
Check the bundled PMD family with `strings
build-root/install-vpp-native/vpp/lib/vpp_plugins/dpdk_plugin.so |
grep -m1 -iE 'net_cnxk|net_octeontx2'` — that names which mailbox era
this VPP will present to the AF, and if it fails the handshake the
`stable/2202` fallback is the next build.

## 2. Stage resources + startup.conf

Reuse the gate-0a staging (VF on a quiet port, vfio-bound, hugepages
reserved — see the perf-campaign memory / gate-0a notes for the exact
commands and the rtemap/dpdk.service gotchas). Sizing per the slice-1
renderer's arithmetic: full table wants ~4.4 GiB ⇒ `vm.nr_hugepages=10`
at 512 MiB pages.

startup.conf: generate with the slice-1 renderer
(`packetframe-vpp-offload::startup_conf::render`) or hand-write its
output shape — the load-bearing lines are `main-heap-size` from the
sizing math, `main-heap-page-size default-hugepage` (64K-page kernel),
`socksvr` for the API socket, explicit `corelist-workers`, the VF
`dev` stanzas, and **no linux-cp** (routes come from vppctl in this
spike; the binary-API sink in production).

## 3. Bring-up + the checklist

Start VPP manually (`/usr/bin/vpp -c /path/startup.conf`), then
`vppctl show hardware-interfaces` — link up on the VF with counters
present is the VPP-side mailbox pass.

Work the checklist; each item gets a WORKS / FAILS / N/A in the results
section:

| # | Item | Method |
|---|---|---|
| 1 | MAC-PF delivery to VF | steer a test prefix (ntuple, ring_cookie VF encoding), send from a peer addressed to the PF MAC, watch `show interface` rx |
| 2 | Egress with MAC-PF source | `set interface mac address` / spoofchk off on the PF (`ip link set <pf> vf 0 spoofchk off`), tx a reply, tcpdump on the peer |
| 3 | ip6 ntuple flow types | `ethtool -N <pf> flow-type ip6 dst-ip 2001:db8::1 action -1 loc 2` (+ VF variant); decides v6 scope |
| 4 | VF queue spread | steer, then `show run` per worker: does traffic stay on queue 0? |
| 5 | Interface addressing | loopback + `unnumbered` vs same-IP-as-PF; VPP may refuse overlapping subnets |
| 6 | ARP by construction | confirm no GARP on interface-up (tcpdump on peer); steering rules can't match 0x0806 |
| 7 | **PMTUD positive test** | >MTU DF packet through a steered path → correctly-sourced frag-needed back at the sender. **Do not skip.** |
| 8 | VLAN subif egress | `create sub-interface` + tag 1337 toward the br1337-shaped topology |
| 9 | rx-mode adaptive | `set interface rx-mode <if> adaptive`; watch idle CPU (the heat verdict) |
| 10 | Full-table load | script `ip route add` via vppctl from a table dump; record wall time, `show memory main-heap` (replaces HEAP_BYTES_PER_ROUTE=2048 in startup_conf.rs), and packetframe daemon RSS for the sizing table |
| 11 | pps/core + latency | steered constant-rate flow: pps at 1 worker, p50/p99 vs the kernel path |
| 12 | Watts/thermals | idle + loaded, poll-mode vs adaptive (if 9 works) |

## 4. Pass / kill / record

- **Pass:** items 1, 2, 7, 10 all WORK (delivery, egress, PMTUD,
  full-table capacity). Everything else shapes design rather than
  gating it.
- **Kill:** VPP's PMD can't handshake the AF at any pinnable version →
  phase parks with the verdict recorded (the honest outcome the plan
  endorses).
- Record every number in this file under a Results heading, then update
  `HEAP_BYTES_PER_ROUTE` and the plan's sizing notes from item 10, and
  pin the VPP version for slice 3.

## Cleanup

`pkill vpp`; sweep `/dev/hugepages/rtemap_*`; VF and hugepage teardown
per the gate-0a notes (or leave staged for the next session — the
shadow is the integration environment).
