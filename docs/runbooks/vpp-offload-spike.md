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

### RESULT (2026-08-02, primary)

**These are NEXTHOP counts, not route counts.** The command counts every
`via ... on ...` line by design, so a multipath route contributes once
per path and can appear under both devices. Read every figure below as
"matched nexthops".

| Table | eth3 | eth2 | nexthops | eth3 share |
|---|---:|---:|---:|---:|
| master4 | 1,044,497 | 8,552 | 1,053,049 | **99.19%** |
| master6 | 204,011 | 43,940 | 247,951 | **82.28%** |
| **both** | **1,248,508** | **52,492** | **1,301,000** | **95.97%** |

**Outstanding: `birdc 'show route count'` was not captured.** Until it
is, nexthops-as-prefixes rests on the separate observation that this box
runs **0 ECMP groups**, under which the two are 1:1. Capture it and
record the delta here; if the selected-route total is materially below
1,301,000 then multipath exists after all, the per-device *shares* stay
valid (they are ratios of the same population) but the `expected-routes`
sizing below must be recomputed from routes, and "52,492 prefixes prefer
eth2" must weaken to "52,492 nexthops", since a multipath prefix can sit
in both columns.

Findings, in descending order of consequence:

**1. The ~99% re-scope trigger fires for v4 and does not for v6** —
17.72% of v6 nexthops prefer eth2, which is not noise. Combined, the top
device carries 95.97%, under the trigger. **Verdict: the full-table
commitment stands — CONDITIONALLY.**

> **The condition, and it is load-bearing:** this verdict rests
> *entirely* on v6, because v4 alone (99.19%) already meets the re-scope
> trigger. But whether v6 can be steered into VPP at all is **checklist
> item 3** (`ip6` ntuple flow types on the rvu driver), still unverified.
> If item 3 fails, v6 stays on XDP as the documented per-family split —
> and then VPP carries a v4-only table that *does* meet the trigger, so
> the full-table decision must be re-taken on v4's numbers alone.
> **Re-read this verdict after item 3.**

**2. Only two egress devices appear across the whole table.** No VLAN
nexthops, no management or tunnel devices. Consequences: no VPP
sub-interface is needed for *BGP* nexthops (the br1337/FDB-pin topology
is a connected-route concern, not a FIB-nexthop one), and **steady-state
`unresolvable` should be exactly 0** — which makes it a sharp health
signal rather than a noisy one, and makes "unresolvable blocks
first-attach steering" a safe policy rather than a trip hazard.

> **This does NOT mean membership is `{eth2, eth3}`.**
> `Config::validate_vpp_offload` enforces a deliberately broader
> invariant: once *any* port sets `steer on`, **every fast-path `attach`
> port must be a member** — for `conf/example.conf` that is eth0, eth2,
> eth3, eth4 and eth5, not two ports. The histogram describes where BGP
> best-paths egress *today*; the invariant covers where a packet could
> egress *at all*, including connected routes and a topology that
> changes without anyone re-running this command. Provision membership
> from the attach set; use the histogram only to size the
> nexthop-device *mapping*.

**3. `expected-routes` guidance is now 1,600,000** — the live table is
~1.3M (see the ECMP caveat above) and the DFZ grows ~100k/yr, so 1.6M is
roughly three years. Applied to `DEFAULT_EXPECTED_ROUTES` and
`conf/example.conf`, both of which said 1,400,000; documentation-only
guidance would have left every deployment that omits the directive
rendering VPP's heap for a table barely above today's.

**Caveat: route count says nothing about traffic volume, in either
direction.** The 52,492 eth2-preferring nexthops could carry
disproportionately *many* bytes (an IX/peering port has exactly that
shape) — or disproportionately *few*, or none during any given window.
An earlier revision of this section claimed traffic data could only
strengthen the conclusion; that was unsupported and has been withdrawn.

What keeps the verdict standing without that measurement is that the
full-table-vs-default+exceptions choice **was not decided on traffic
volume**: it was decided on failure behavior (the exception set inverts
when the majority device fails — see the plan). Traffic share changes
how much the full table *buys*, not which design survives an upstream
outage. Measure per-egress bytes if that trade is ever re-opened.

## 1. Build VPP from source (fd.io debs do not exist for this OS)

Verified 2026-08-01/02, empirically — the reason matters, so don't
re-litigate it from a half-memory:

- fd.io publishes per-release repos (`fdio/<YYMM>`, e.g. `fdio/2606`)
  separately from `fdio/release`. Debian **bullseye packages do exist**
  there (e.g. `fdio/2306` carries `vpp_23.06.0-...~b20_amd64.deb`).
- But fd.io's **arm64 builds are Ubuntu-only** (jammy/noble). In
  `fdio/2306`, arm64 appears solely under `ubuntu/jammy`; bullseye is
  amd64 exclusively. Bookworm is likewise amd64-only.
- So the combination we need — **bullseye + arm64 — is published
  nowhere**, at any VPP version. Debian proper has never packaged VPP.
- Cross-distro substitution fails in the direction we'd need it: we
  extracted the jammy 24.10 arm64 deb on the shadow and it fails three
  ways on UniFi OS — bullseye's dpkg 1.20 cannot unpack its zstd
  members, and the binary's symbol floor is **GLIBC_2.34** against our
  2.31 (`objdump -T`). Older-on-newer works; newer-on-older does not.

Hence: **source build, on-box/in-CI** (18 cores; deps largely present
from the gate-0a testpmd build). This also opens the cn9k-tuned build
as a same-pipeline variant rather than a separate decision.

Version pins, mirroring the gate-0a two-era doctrine (the AF↔VF
mailbox does not follow newer-is-better):

1. **`v26.06`** — the latest upstream stable — first. Its Makefile has
   explicit `debian-11` handling, so bullseye is a supported build
   host; fd.io simply doesn't *publish* bullseye arm64 binaries, which
   says nothing about buildability. Default to newest for the security
   fixes and upstream support, and drop back only on a measured
   failure.
2. Fallback ladder, only if 26.06's PMD fails the mailbox handshake:
   `v25.10`/`v24.10` → `v23.06` → `v22.02` (DPDK 21.11, the last
   `octeontx2`-named era, closest to the DPDK 20.11 build that passed
   gate 0a). The AF here is SDK-era on a 5.15 vendor kernel and the
   mailbox does not follow newer-is-better — but that is a reason to
   TEST the newest, not to pre-emptively ship something old.

```sh
cd /root && git clone --depth 1 --branch v26.06 https://github.com/FDio/vpp && cd vpp && UNATTENDED=y make install-dep && make build-release
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
next rung of the fallback ladder is the next build.

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
