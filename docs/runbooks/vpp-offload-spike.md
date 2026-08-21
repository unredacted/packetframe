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

Hence we build it ourselves — **in CI, not on the box.**

> **Do not build VPP on the router.** The obvious `make install-dep`
> route is a dead end there and the failure is not obvious in advance:
> UniFi ships a patched `libnl-3-200 3.4.0-8+ubnt`, while Debian's
> `libnl-3-dev` depends on its runtime sibling at an *exact* version
> (`= 3.4.0-1+b1`). apt cannot resolve that and stops. The apparent fix
> — downgrading `libnl-3-200` — would swap a patched netlink library
> out from under udapi and the rest of UniFi's stack, on a production
> router, to satisfy a build dependency. Don't.
>
> Verified 2026-08-02 on the primary.

The VPP build lives in **github.com/unredacted/vpp-unifi** (it started
as this repo's `vpp-build.yml` and moved out 2026-08-12 — the build is
a property of UniFi hardware, not of packetframe): unmodified upstream
VPP in a clean `debian:bullseye` container on a native arm64 runner,
where none of that applies, published as `.debs` under their own
release tag. It runs when a gateway pin (`pins/efg.toml` there)
changes, or on demand. This also makes the cn9k-tuned build a
same-pipeline variant rather than a separate decision. On this repo's
side, `crates/modules/vpp-offload/vpp-api/SOURCE.json` — the manifest
of the release the vendored API definitions came from — is the single
record of which published VPP packetframe is codegen'd and tested
against; there is deliberately no separate pin file to fall out of
sync with it.

Version pins, mirroring the gate-0a two-era doctrine (the AF↔VF
mailbox does not follow newer-is-better):

1. **`v26.06`** — the latest upstream stable — first, and it **builds
   and packages cleanly** (verified in CI 2026-08-02). fd.io simply
   doesn't *publish* bullseye arm64 binaries, which says nothing about
   buildability. Default to newest for the security fixes and upstream
   support, and drop back only on a measured failure.

   One caveat learned the hard way: `make install-dep` succeeding is
   *not* evidence that bullseye's toolchain is new enough. Dependency
   packaging still targets debian-11, but individual tool floors have
   moved past it — 26.06 needs CMake ≥ 3.19 against bullseye's 3.18.4,
   which the workflow supplements with a pinned upstream CMake. If that
   list of supplements ever grows past a couple of tools, take the
   ladder below rather than keep rebuilding bullseye's toolchain.
2. Fallback ladder, only if 26.06's PMD fails the mailbox handshake:
   `v25.10`/`v24.10` → `v23.06` → `v22.02` (DPDK 21.11, the last
   `octeontx2`-named era, closest to the DPDK 20.11 build that passed
   gate 0a). The AF here is SDK-era on a 5.15 vendor kernel and the
   mailbox does not follow newer-is-better — but that is a reason to
   TEST the newest, not to pre-emptively ship something old.

### RESULT (2026-08-02, shadow): the v26.06 rung fails BEFORE the mailbox

Tested on the shadow with the published artifact. Install, mask,
sysctl-skip and bring-up all held; VPP ran; `-a 0002:07:00.1` reached
EAL (the init.c "Unsupported PCI device" warning is **cosmetic** — it
skips only the uio-bind step and does not blacklist; confirmed in
source and by `show dpdk version` showing the `-a`). The probe then
died at the ROC model check, before any AF contact:

```
CNXK: populate_model():224 Invalid RoC model (impl=0x43, part=0xb2, major=0x3, minor=0x0)
CNXK: cn9k_nix_probe():810 Failed to initialize platform model, rc=-22
```

**The cn9670 reports MIDR variant 3 — a die stepping absent from
`drivers/common/cnxk/roc_model.c` in every public DPDK** (the CN96xx
table stops at variant 2), and unknown MIDR is a hard `-EINVAL` with
no override (no env, no devargs, no default-to-nearest; verified in
v26.03 source). Consequences:

- **The mailbox question is STILL OPEN** — this failure is upstream
  of it.
- **The whole cnxk era is gated identically**: v25.10/v24.10/v23.06
  would fail the same way. The ladder's middle rungs are skipped by
  measurement, not caution.
- **v22.02 (DPDK 21.11) is the active rung**: the octeontx2 driver
  reads no MIDR at probe (verified in v21.11 source), and gate 0a's
  DPDK 20.11 testpmd moved real packets on this exact silicon. 21.11
  ships both PMD families; if its cnxk half hits the same gate, EAL
  falls through to the next matching driver — the gate-free octeontx2.
- **Road back to current VPP**: upstream the one-line MIDR entry to
  DPDK / marvell-octeon-roc. No local patch — the pin stays in the
  octeontx2 era until an upstream release carries the fix.

### RESULT (2026-08-02, shadow, round 2): **THE MAILBOX WORKS** — and the road is the native driver

The v22.02 rung answered gate 0b's central question:

```
EAL: Probe PCI driver: net_octeontx2 (177d:a064) device: 0002:07:00.1 (socket 0)
```

Interface `Ethernet7/0/1` created, MAC assigned, full rx/tx capability
tables enumerated — all of it AF-mailbox conversation, all of it
working through the SDK-era AF. **The phase's architecture-killing
risk is dead**, proven twice (testpmd 20.11 at gate 0a; otx2 21.11
inside VPP here).

It then failed one layer up, and this failure re-routes the phase:

```
PMD: otx2_nix_rx_queue_setup():600 mempool ops should be of octeontx2_npa type
rte_eth_rx_queue_setup[port:0, errno:-22]
```

Both otx2 (21.11) and cnxk (26.03) **hard-require NPA mempool ops**
for packet buffers — no bypass, no devarg (verified in both sources) —
and mainline VPP's buffer manager only provides its own "vpp" mempool
ops. **The DPDK-PMD-inside-VPP path is therefore dead on this NIC at
every version.** Not the hardware, not the kernel, not the era: a
VPP↔PMD buffer-integration wall (Marvell's out-of-tree VPP fork exists
precisely to bridge it; we don't ship forks).

**The mainline road: VPP's native octeon driver**, and every link is
source-verified:

- `src/drivers/octeon` builds only under `VPP_PLATFORM=octeon9|octeon10`
  — which is why the generic artifact never contained it.
- It links marvell-octeon-roc, and **octeon-roc v26.05's model table
  HAS the cn9670's stepping**: MIDR (0x43, 0xB2, 3, 0) = **CN96xx D0**.
  DPDK's copy of the same table is simply stale — that's the whole
  cnxk-era failure, now explained end to end.
- CN9K support is first-class (`roc_model_is_cn9k()` paths,
  `PLATFORM_OCTEON9` defines).

Pin is now `v26.06` + `platform = "octeon9"`. Two consequences for
this runbook:

1. The artifact tag becomes `vpp-v26.06-octeon9-bullseye-arm64`, and
   the driver ships as `vpp_drivers/octeon_driver.so` — probe with
   that name, not `net_*` strings and not `dev_octeon`.
2. **The startup.conf changes shape**: the native driver is configured
   through VPP's vnet/dev `devices {}` stanza, not `dpdk {}`. Replace
   the `dpdk { dev 0002:07:00.1 }` block with:

   ```
   devices {
     dev pci/0002:07:00.1 {
       driver octeon
     }
   }
   ```

   (Exact grammar to be confirmed against the built artifact's
   `vppctl show dev` on first bring-up; unix/socksvr/memory/cpu
   sections carry over unchanged.)

The v22.02 tag stays published as the mailbox-proof artifact.

### RESULT (2026-08-02, shadow, round 3): **BRING-UP COMPLETE** — link up, first packet received

The octeon9 artifact, end to end on mainline unpatched VPP:

```
octeon0/0  up  Link speed: 2.500000 Gbps
rx packets 1 / rx bytes 60 / ip4 1 / drops 1
octeon/queue 0002:07:00.1: NPA pool created, aura_handle = 0xffff93f70000/...
```

Every layer now proven: install (guarded) → CN96xx **D0 model gate
passed** (octeon-roc's table) → AF mailbox → interface `octeon0/0` →
**NPA hardware buffer pools** (the exact allocation the DPDK PMD path
structurally could not do) → link up at 2.5 Gbps → an unsolicited
60-byte IPv4 frame off eth1's wire delivered into VPP's rx node and
correctly dropped by an unconfigured dataplane.

**The working bring-up sequence** (the `devices {}` startup stanza
with an EMPTY options block is rejected — `vnet_dev_config_one_device:
unknown input ''`; use the runtime CLI, which is also the shape the
vpp-offload module wants, since supervision gets runtime attach/detach
for free):

```sh
# VF must be on vfio-pci first (NOTE: vpp package REMOVAL unbinds it —
# postrm "cleans up" the binding; re-bind after any purge):
#   echo vfio-pci > /sys/bus/pci/devices/0002:07:00.1/driver_override
#   echo 0002:07:00.1 > /sys/bus/pci/drivers_probe
# startup.conf: unix/socksvr/memory/buffers/cpu sections as in §2,
# plus: plugins { plugin dpdk_plugin.so { disable } }  — no dpdk{} and
# no devices{} stanza. Then:
vppctl device attach pci/0002:07:00.1 driver octeon
vppctl device create-interface pci/0002:07:00.1 port 0 num-rx-queues 1
vppctl set interface state octeon0/0 up
vppctl show interface octeon0/0     # link, counters
```

Checklist status after round 3: bring-up done; **item 1 half-proven**
(wire → VPP delivery works unsteered; the MCAM-steered variant still
to run) — items 1–12 now execute on this stack.

### RESULT (2026-08-02, shadow, round 4): items 3 and 9 — both answered, one re-opens a decision

**Item 3 — ip6 ntuple: FAILS, and it is the AF, not the driver.**
Both v6 shapes (drop, VF-steer via ring_cookie) rejected with AF
mailbox error 710 (NPC flow family); `ethtool -n` confirms zero rules
landed. The control on the same PF, same slots, same day: **v4 drop
AND v4 VF-steer both insert cleanly** — ethtool decodes the cookie as
`Direct to VF 0 queue 0`. Decoded against the fleet kernel's own enum
(v5.15 `octeontx2/af/mbox.h`): **-710 = `NPC_FLOW_NOT_SUPPORTED`**,
raised by `npc_check_unsupported_flows()` exactly when requested match
fields are absent from the loaded MKEX profile's feature set. Verdict,
now sourced rather than inferred: the vendor firmware's NPC
key-extraction profile does not carry v6 fields. Not a regression,
not fixable from our side. (Beware ethtool's exit code: it printed
the rmgr error and still exited 0 — judge by `ethtool -n`, not `$?`.)

The full shape matrix, so nobody re-probes it: `ip6 src-ip`,
`tcp6 dst-ip`, `udp6 dst-ip`, `tcp6 dst-ip+dst-port` — ALL rejected
with 710. **`ether proto 0x86DD` INSERTS** — L2 ethertype extraction
works, so the wall is precisely "no v6 L3 fields", not "no v6
awareness". The ethertype rule is deliberately NOT used: it is
all-or-nothing v6 — it would steer BGP v6 sessions, NDP and
management into VPP, and a punt-to-kernel path for control traffic is
the linux-cp-shaped complexity this design refuses (a VPP crash would
take the v6 control plane down with it, breaking the failover tier's
premise). Recorded as a door that exists and was not walked through.

Consequences:
- **v6 cannot be MCAM-steered into VPP.** The per-family split from
  the plan activates: v6 stays on the XDP custom-FIB path (already
  correct, ~2% of matched traffic), unless the XDP→AF_XDP side door
  is ever deemed worth its complexity for that 2%.
- **The full-table verdict's condition fired** (§0's conditional
  note said re-read it after item 3). VPP now carries a v4-only
  table, and v4 alone is 99.19% one egress device — which MEETS the
  ~99% re-scope trigger. The full-table-vs-default+exceptions
  decision is re-taken by the user on v4's numbers. Note what does
  NOT change: the failure-behavior argument (default+exceptions
  inverts the exception set when the majority device dies) and the
  FIB-mirrors-bird verifiability argument are family-independent —
  the trigger firing shrinks the steady-state *benefit*, not the
  failure-mode logic. A v4-only full table is also ~20% smaller —
  **~1.05M NEXTHOPS** (=routes only under the 0-ECMP observation; the
  §0 caveat about the uncaptured `show route count` applies to this
  figure and to the resync-speed corollary equally).

  **DECIDED (2026-08-02, user): FULL v4 TABLE.** The failure-behavior
  and verifiability arguments won again on v4-only numbers. v6 stays
  on the XDP custom-FIB path — fully correct forwarding, and the v4
  offload effectively dedicates the entire 18-core kernel path to
  v6's remainder, so v6 can grow ~10x before the split even itches.
  v6 roadmap, recorded not built: (1) retest ip6 ntuple at every
  UniFi kernel bump — the MKEX profile ships with the AF driver;
  (2) kernel >=6.8 unlocks native XDP = 2-3x for v6 on the fallback
  tier with no VPP involvement; (3) the XDP->AF_XDP->VPP side door
  stays documented and deliberately unbuilt until native XDP makes
  AF_XDP zero-copy — while rx is generic-XDP copy mode it buys
  nothing over the custom-FIB path v6 already has.

**Item 9 — rx-mode: FAILS; the heat goal is dead on this driver.**
`set interface rx-mode` (adaptive and interrupt) both answer
`not supported (rx queue interupt mode enable/disable not supported)`
from the native octeon driver, and the worker core measures ~100%
busy in every mode. **VPP worker cores burn 24/7 in poll mode**;
core count is a deliberate, permanent spend, one hot core per worker.
Record in the fleet runbook and thermals watch accordingly. (vppctl
also exits 0 on CLI errors — same exit-code trap as ethtool.)

### Getting the build onto the shadow

Derive the tag from SOURCE.json rather than typing a version —
otherwise working the fallback ladder below re-downloads the build
that just failed, which looks exactly like the fallback not working.
Deriving from provenance also guarantees the box gets the exact
release the running binaries were codegen'd against:

```sh
# From a checkout of this repo (workstation with `gh` authenticated;
# scp to the shadow afterwards, or run on the box if it has both).
src=crates/modules/vpp-offload/vpp-api/SOURCE.json
ref=$(jq -r .vpp_ref "$src"); plat=$(jq -r .platform "$src")
repo=$(jq -r .built_by "$src" | cut -d@ -f1)
gh release download "vpp-${ref}-${plat}-bullseye-arm64" \
  --repo "$repo" --dir /tmp/vpp
```

(Builds published before 2026-08-12 live on unredacted/packetframe's
release page; everything since publishes from unredacted/vpp-unifi,
which is what SOURCE.json's `built_by` names.)

**The install-time libnl question is ANSWERED (2026-08-02, read from
the built deb's control):** `vpp` depends on `libnl-3-200 (>= 3.2.7)`
and `libnl-route-3-200 (>= 3.2.26)` — `>=` constraints, which UniFi's
*newer* `3.4.0-8+ubnt` satisfies. The wall that kills the on-box
*build* (libnl-3-dev's exact-version pin) does not exist at install
time. The check below stays for future pins — an `=` could appear in
any new version. Check **every** package, not just the main one:

```sh
for d in /tmp/vpp/*.deb; do echo "== $d"; dpkg -I "$d" | grep -i '^ *depends'; done
```

### Three traps in the vpp package — two in the postinst, one in its payload

Read from the shipped postinst and the unpacked data.tar, not guessed:

**1. It applies `sysctl --system`, and the deb ships
`vm.nr_hugepages=1024` written for 2 MB pages.** On this fleet's
64K-page kernel the default hugepage size is **512 MB**, so letting it
run asks the kernel for **512 GiB of hugepages on a 64 GB router, at
install time** — the kernel grabs what it can, which is a
memory-eating event on a production box. Upstream ships its own
escape hatch (`VPP_INSTALL_SKIP_SYSCTL`, quoted in the postinst as a
"nerd knob... e.g. during the container installs"); on this fleet it
is **mandatory, always**. Hugepages are managed deliberately — by the
vpp-offload module in production, by hand in this spike — never by a
package hook.

**1b. The env var does NOT defuse the file the deb ships.**
`VPP_INSTALL_SKIP_SYSCTL` gates exactly one postinst line — the
install-time `sysctl --system`. But `/etc/sysctl.d/80-vpp.conf` is
package *content*, and systemd-sysctl applies it on **every
subsequent boot**. On 2026-08-21 this bricked the primary EFG: the
install looked clean (skip honoured, `nr_hugepages` still 0, no vpp
running), and the next reboot reserved ~all 64 GB into 512 MB
hugepages before userspace came up — udapi never configured an
interface, the box answered nothing, and recovery took a factory
reset through Recovery Mode. Delete the file as part of the install
and verify it is gone; a flag that suppresses an installer's side
effect says nothing about where that side effect *lives*.

**2. It STARTS `vpp.service` during install** (`deb-systemd-invoke
start`) on the stock `/etc/vpp/startup.conf`. Masking *after* install
is therefore too late — the daemon has already run once by then. Mask
**first**; the postinst's own unmask only touches masks the packaging
helper itself created, so an operator mask survives install.

The full sequence — stop, then mask, then install, and the install is
gated on the mask having succeeded (`&&`), because installing past a
failed mask is exactly the daemon-starts-during-install trap:

```sh
# Stop tolerates a unit that does not exist yet (first install);
# mask does not get that tolerance — if IT fails, do not install.
# Mask alone is not enough on a rerun: it only blocks future
# activations, and an already-running daemon keeps holding the
# hugepages, VF, and API socket right through the install.
systemctl stop vpp.service 2>/dev/null || true
systemctl mask vpp.service \
  && cd /tmp/vpp && VPP_INSTALL_SKIP_SYSCTL=1 apt-get install -y ./*.deb \
  && rm /etc/sysctl.d/80-vpp.conf \
  && command -v vpp && vpp --version
cat /proc/sys/vm/nr_hugepages        # belt-and-braces: must be UNCHANGED
pgrep -a vpp || echo "no vpp running — correct"
ls /etc/sysctl.d/ | grep -i vpp && echo "BOOT LANDMINE STILL PRESENT" \
  || echo "no vpp sysctl file — correct"   # trap 1b: next BOOT, not now
```

(`apt-get install`, not `dpkg -i`, so an unmet dependency fails loudly
instead of leaving a half-configured package.)

Unmask at cleanup (`systemctl unmask vpp.service`) only if you intend
to leave the box able to run the packaged daemon. For the spike,
staying masked is the safer state — nothing should start VPP except
you, and §3 starting a second instance against a stock-config daemon
reads as a config or mailbox failure rather than what it is.

### What CI already proved, so you needn't re-check

**Publication is gated on verification** — the `publish` job runs only
after `verify-package` passes, so a release tag existing is itself the
evidence that the checks below passed. (This was not always true:
publishing used to be the last step of the build job, which put
unverified `.debs` on the release page. If you are looking at an
artifact published before 2026-08-02, check the run.)

They are recorded here so a failure on the box is read as *new* rather
than re-derived:

- **glibc symbol floor `GLIBC_2.17`** against UniFi OS's 2.31. This is
  the check that killed the fd.io jammy deb, applied to what we ship.
- The Octeon PMD is present, **statically linked into
  `dpdk_plugin.so`** (VPP whole-archives its DPDK and deletes the
  shared driver objects at install — there is no standalone PMD `.so`
  in this build; an earlier revision of this bullet claimed one). And
  check for the **registered driver names, not the library name**: the
  cnxk PMD registers one driver per SoC generation, so

  ```sh
  strings /usr/lib/*/vpp_plugins/dpdk_plugin.so | grep -E 'net_cn9k|net_cn10k|net_cn20k|net_octeontx2'
  ```

  is the probe that means something, while `grep net_cnxk` finds
  nothing in any working build (that miss cost a CI round). The fleet
  is cn9670 = CN9K: **`net_cn9k` is the one that matters** on the
  current pin, and it is also the name to expect in
  `show hardware-interfaces` driver output during this spike.
  `net_octeontx2` is the same silicon's name in the ≤ DPDK 21.11 era —
  it is what a `v22.02` fallback artifact registers instead, so on a
  fallback pin its presence (not net_cn9k's) is the pass condition.
- The `.debs` install into a clean bullseye and the installed binary
  resolves its libraries (the `verify-package` job).

The `.api.json` definitions publish as a separate small asset on the
same release — that is slice 3's codegen input, and the exact
tag/commit in the release manifest is the pin it generates against.

**If the PMD fails the mailbox handshake**, the next rung of the
fallback ladder is a pin edit in unredacted/vpp-unifi
(`pins/efg.toml`), not an on-box rebuild: changing `ref` there re-runs
the build workflow and publishes a new tag; then re-vendor the API
bundle here (procedure: `crates/modules/vpp-offload/vpp-api/README.md`).

## 2. Stage resources + startup.conf

Reuse the gate-0a staging (VF on a quiet port, vfio-bound, hugepages
reserved — see the perf-campaign memory / gate-0a notes for the exact
commands and the rtemap/dpdk.service gotchas). Sizing per the slice-1
renderer's arithmetic, now driven by item 10's **measured** numbers
rather than the pre-measurement guesses: at v4-only ~1.05M routes,
~1.5 GiB heap + 1 GiB buffers ≈ 2.5 GiB ⇒ **5 × 512 MiB pages**, so
`vm.nr_hugepages=8` leaves comfortable margin. (The earlier figures —
~2.2 GiB off a placeholder, ~4.4 GiB from the pre-decision v4+v6
shape — are both superseded.)

**The stats segment is a separate budget line and is not hugepages.**
It is 64 K-page locked RAM, ~193 MiB at this table with one worker, and
it scales with VPP's *thread* count. Reserving hugepages for it would
be wasted; forgetting it entirely aborts VPP mid-load.

startup.conf: **the renderer now emits the post-pivot shape** — it
dropped the `dpdk { dev ... }` stanza, disables `dpdk_plugin.so`, and
carries no device identity at all (devices attach at runtime; see §3).
Its sizing arithmetic was always valid and is unchanged. The hand-
written config below stays here as the reference the renderer is
tested against, and as what to fall back to if you are bringing up a
box without a packetframe build. The canonical working shape, from
round 3:

```
unix {
  nodaemon
  log /var/log/vpp-spike.log
  cli-listen /run/vpp/cli.sock
  full-coredump
}
socksvr { socket-name /run/vpp/api.sock }
memory {
  main-heap-size 1536M
  main-heap-page-size default-hugepage
}
statseg {
  size 256M
}
buffers { buffers-per-numa 16384 default data-size 2048 }
cpu { main-core 16 corelist-workers 17 }
plugins { plugin dpdk_plugin.so { disable } }
```

The two sizing numbers, both from item 10's measurement below:

- `main-heap-size 1536M` — 1.05M v4 routes × 1 KiB/route + a 512 MiB
  floor. (Round 3 ran 4 GiB, which is also fine; this is the derived
  minimum with margin, not the value that was on the box.)
- `statseg 256M` — **not optional.** The 32 MiB default aborts partway
  through a full table, and `show memory main-heap` will not show you
  why. Budget **96 B per route per VPP *thread***: 1.05M routes × 2
  threads (main + the one worker above) ≈ 193 MiB. **Add ~96 MiB per
  additional worker** — VPP replicates every counter per thread, so
  this is the one number here that does not scale the way it looks like
  it does. It is also 64 K-page locked RAM, so it does **not** come out
  of the hugepage reservation.

Load-bearing beyond sizing: `main-heap-page-size default-hugepage`
(64K-page kernel), `socksvr` for the API socket, explicit
`corelist-workers`, **dpdk_plugin disabled**, **no `dpdk {}` stanza, no
`devices {}` stanza** (an empty-block `devices{}` is a parse error; the
device attaches via the runtime CLI in §3), and **no linux-cp** (routes
come from vppctl in this spike; the binary-API sink in production).

## 3. Bring-up + the checklist

Start VPP manually (`/usr/bin/vpp -c /path/startup.conf`), then attach
the VF through the native driver at runtime (the sequence proven in
round 3 — see that RESULT for context):

```sh
vppctl device attach pci/0002:07:00.1 driver octeon
vppctl device create-interface pci/0002:07:00.1 port 0 num-rx-queues 1
vppctl set interface state octeon0/0 up
vppctl show interface octeon0/0
```

Link up on `octeon0/0` with counters present is the bring-up pass
(mailbox, D0 model gate, and NPA pool allocation all sit inside those
four commands and fail loudly in `show log` if anything regresses).

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
| 10 | Full-table load — **v4-ONLY per the round-4 decision** — **DONE, see RESULT below** | dump bird's `master4` ONLY (`birdc 'show route primary table master4'` → script `ip route add` via vppctl); record wall time, `show memory` (**all heaps, not `main-heap`** — see RESULT), and packetframe daemon RSS. Loading v4+v6 would measure a table shape the decision rejected |
| 11 | pps/core + latency | steered constant-rate flow: pps at 1 worker, p50/p99 vs the kernel path |
| 12 | Watts/thermals | idle + loaded, poll-mode vs adaptive (if 9 works) |

### RESULT (2026-08-03, shadow, item 10): **v4 FULL TABLE FITS** — and the stats segment is the constraint nobody was sizing

**1,053,360 v4 prefixes** from the live bird `master4`, loaded into
v26.06/octeon9 via `vppctl exec` in ~35 s. Item 10 **PASSES**.

| | baseline (empty FIB) | full table | Δ | per route |
|---|---|---:|---:|---:|
| main heap (used) | 337.86 MiB | 803.49 MiB | 465.63 MiB | **463 B** |
| stat segment (populated) | 1.19 MiB | 101.94 MiB | 100.75 MiB | **97 B** ‡ |
| hugepages (512 MiB) | 9 | 10 | +1 | — |

‡ **at two VPP threads.** This run was `corelist-workers 17` — one
worker — and VPP replicates counter vectors per thread
(`vec_validate (cm->counters, tm->n_vlib_mains - 1)`), so the statseg
row is a two-thread figure and nothing else here is. Per thread it is
~48.5 B/route. A five-port config runs five workers and needs ~3× this.

**The finding that matters is a first-attempt crash, not the numbers.**
With the default `statseg` (31.94 MiB) VPP **aborted** partway through
the fourth 100k chunk:

```
Out-of-memory, calling os_panic().
os_panic() called, aborting.
```

Per-chunk statseg usage explains it exactly — 22.85 MiB at 300k, 33.84
MiB at 400k, i.e. it crosses the 31.94 MiB default at roughly **380k
routes**. Adding `statseg { size 1G }` loaded the whole table with no
other change.

Consequences, all now in `startup_conf.rs`:

- **`show memory main-heap` is a misleading diagnostic.** During the
  abort it read `used: 470M / 4.00G` — 87% free — while a different
  segment was exhausted. **Always use `show memory` (all heaps).** An
  hour went into suspecting the main heap because of this.
- **Size the stats segment from `populated`, not `used`.** The
  allocator said 75.04 MiB while the OS had backed 101.94 MiB; sizing
  from `used` under-provisions by a third.
- **The stats segment is 64 K-page backed, not hugepages** (`page-size
  64K` in `show memory`). It is locked RAM on a *separate* budget line
  and must NOT inflate the hugepage reservation.
- **`HEAP_BYTES_PER_ROUTE` 2048 → 1024** (measured 463, ~2.2× margin);
  **`HEAP_FLOOR_BYTES` 1 GiB → 512 MiB** (measured 337.86 MiB);
  **`BUFFER_BYTES` 512 MiB → 1 GiB** (10 hugepages in use against a
  4 GiB heap = 1 GiB beyond it, so 512 MiB would have left the
  reservation a page short at full table).
- **New `STATSEG_BYTES_PER_ROUTE_PER_THREAD` = 96** (measured ~48.5
  per thread, ~2×) with a 32 MiB floor, and `render()` now emits the
  stanza. It emitted none before, so the module as merged would have
  killed VPP partway through its first full-table resync.
- **The stats segment scales with VPP's thread count, the main heap's
  route term does not.** `derive_sizing` therefore takes the summed
  `cores` across all ports, and the renderer refuses a core list that
  disagrees with the sizing it was handed — two independent worker
  counts is how a segment gets silently undersized. Sizing off the
  measured aggregate as though it were thread-independent would have
  under-provisioned the five-port `example.conf` shape by ~3× and
  reproduced this same abort at ~1.05M routes.
- **The decomposition is one data point deep.** This run cannot
  separate the fixed per-route cost (statseg directory entries, name
  strings) from the per-thread cost, so all of it is attributed to
  per-thread. That over-provisions multi-worker boxes, which is the
  safe direction. Re-measuring at two different worker counts would
  refine it; nobody should tighten the constant without that.

**Per-chunk increments are not usable as a per-route figure** — they
ranged 82 B to 2,058 B/route because mtrie interior nodes allocate in
blocks. Only the full-table average means anything.

**Still NOT measured — the ≤60 s convergence budget.** The ~35 s load
was VPP's CLI parser with one shared path-list, not 1.05M binary-API
round trips with the real 129 nexthops. Treat 35 s as an encouraging
lower bound on what VPP itself can absorb and nothing more; the real
number needs the module's sink.

Method note: routes were pointed at a single synthetic nexthop
(`10.255.255.2` on `octeon0/0`, static neighbor) rather than the real
129. Path-lists are shared, so 129 versus 1 is ~128 extra objects
against 1.05M prefixes — negligible for the per-prefix slope this
measures.

Also captured, closing a caveat that had been open since §0: the
primary's `birdc 'show route count'` reports **2,105,065 routes for
1,053,380 networks** in `master4`, against the histogram's 1,053,049
best-path nexthops. Those agree to within ~331, confirming **0 ECMP
among selected routes** — so "nexthops as prefixes" is now measured
rather than inferred, and the `expected-routes` sizing stands.

## 3b. Convergence over the binary API (the ≤60 s budget)

**This is the number item 10 explicitly did NOT measure.** Item 10 timed
VPP's *CLI parser* absorbing the table — ~35 s for 1,053,360 routes via
`vppctl exec`, with one shared path-list — and recorded it as a lower
bound only. Production is 1.05M **binary-API round trips** driven by the
module's `ConvergenceEngine`, against the real nexthop set. The plan
publishes ≤60 s; nothing has ever checked it.

Needs **no traffic peer**: nothing is steered, so this can run on the
shadow any time VPP is up.

### Inputs

Two plain files, produced on the **primary** (bird has the table) and
copied to the shadow. Note the source is bird, not the kernel — bird's
kernel export was dropped at custom-fib cutover, so `ip route show` is
deliberately near-empty.

```sh
birdc 'show route table master4 count' | tee /tmp/pf-count.txt
```

Note the `networks` figure. That is **bird's own count, independent of the
extraction below**, and it is what makes the check meaningful — an
expectation derived from the same pipeline it is meant to validate proves
nothing, because a `birdc` that ends cleanly halfway produces a shortened
file and a shortened count that agree with each other perfectly.

Now extract, and reconcile against that independent figure:

```sh
set -o pipefail
birdc 'show route primary table master4' > /tmp/pf-raw.txt
awk '/^[0-9]/ { pfx=$1; nets++ } /via/ { if (!(pfx in seen)) { seen[pfx]=1; vias++ } for (i=1;i<=NF;i++) if ($i=="via") print pfx, $(i+1) } END { print nets, vias > "/tmp/pf-nets.txt" }' /tmp/pf-raw.txt | sort -u > /tmp/pf-routes.txt || echo "EXTRACTION FAILED"
BIRD_NETS=$(awk '{ for (i=1;i<=NF;i++) if ($i=="networks") print $(i-1) }' /tmp/pf-count.txt)
SEEN_NETS=$(awk '{print $1}' /tmp/pf-nets.txt)
VIA_RAW=$(awk '{print $2}' /tmp/pf-nets.txt)
VIA_FILE=$(awk '{print $1}' /tmp/pf-routes.txt | sort -u | wc -l | tr -d ' ')
echo "bird reports    : ${BIRD_NETS} networks"
echo "raw dump had    : ${SEEN_NETS} networks, ${VIA_RAW} with a via"
echo "routes file has : ${VIA_FILE} prefixes  <-- PACKETFRAME_VPP_EXPECT_ROUTES"
echo "excluded        : $((SEEN_NETS - VIA_RAW)) (connected/blackhole/unreachable)"
[ "${BIRD_NETS}" = "${SEEN_NETS}" ] || echo "!! DUMP TRUNCATED — do not measure this"
[ "${VIA_RAW}" = "${VIA_FILE}" ] || echo "!! EXTRACTION LOST RECORDS — do not measure this"
[ "${BIRD_NETS}" = "${SEEN_NETS}" ] && [ "${VIA_RAW}" = "${VIA_FILE}" ] && echo "OK: chain verified"
```

**Stop unless the last line says `OK: chain verified`.** Two separate
things are being checked, and each closes a different way for a partial
table to look complete:

- `BIRD_NETS == SEEN_NETS` — bird's own count against the raw dump, so a
  `birdc` that ends cleanly halfway is caught.
- `VIA_RAW == VIA_FILE` — the via count computed **from the raw dump**
  against the extracted file, so an `awk | sort` that loses records (disk
  full, a failed `sort`) is caught too. `VIA_RAW` is what makes this
  non-circular: it never touches `pf-routes.txt`.

An expectation taken from the file it is meant to validate agrees with a
truncated file perfectly. An earlier revision of this section did that
with `wc -l`, and a revision after it validated only the raw dump.

**This is a via-nexthop measurement, not literally every route class.**
The `excluded` figure is real — `master4` carries connected, blackhole and
unreachable primaries that have no `via`, and the §0 numbers show the gap
(1,053,380 networks against 1,053,049 best-path via-nexthops, so ~331).
Those are exactly the routes the sink would classify unresolvable, since
they present no nexthop that can map to a VPP-owned port, so excluding
them measures what production installs rather than hiding a shortfall.
Record `excluded` alongside the timings so the scope of the number is on
the record rather than implied.

```sh
ip -4 neigh show \
  | awk '$1 !~ /:/ && $5 ~ /:/ && $NF != "FAILED" && $NF != "INCOMPLETE" { print $1, $3, $5 }' \
  > /tmp/pf-neigh-all.txt
awk 'NR==FNR { for (n=split($2,a,","); n>0; n--) want[a[n]]=1; next } want[$1]' \
  /tmp/pf-routes.txt /tmp/pf-neigh-all.txt > /tmp/pf-neigh.txt
wc -l /tmp/pf-neigh-all.txt /tmp/pf-neigh.txt
```

The second step keeps only neighbours the routes actually use. Management
and tunnel entries are harmless to the *bench* — it checks ownership only
for route nexthops — but they matter for the one-VF rewrite below, where
rewriting them onto the member port would make `program_neighbours` treat
them as owned and program them into VPP. Extra work at best, and a
refusal aborts the run.

**Every device carrying a route nexthop must be a member port with its own
VF.** The bench refuses up front if a route nexthop resolves to a device
that is not a member — failing there is correct rather than something to
work around, since a packet whose best path exits a port VPP does not own
would blackhole.

#### If only one VF is bound

Rewrite the device column of the **filtered** neighbour file onto the one
owned port, and record the run as a **reduced** measurement: the drain,
wire encoding and VPP-side insert are all fully exercised, but every
adjacency lands on a single interface, so it does not exercise the
multi-port mapping.

```sh
awk '{ print $1, "eth3", $3 }' /tmp/pf-neigh.txt > /tmp/pf-neigh-one.txt
```

Rewrite `/tmp/pf-neigh.txt` (route-referenced only), never
`/tmp/pf-neigh-all.txt` — the router-wide file carries management and
tunnel neighbours, and relabelling those onto the member port would make
`program_neighbours` treat them as owned and push them into VPP. Then use
`PACKETFRAME_VPP_NEIGH=/tmp/pf-neigh-one.txt` with a single-entry
`PORT`/`PCI` below.

### Run

VPP must already be up with its sized `startup.conf` (§2 — **including
the `statseg` stanza**, or it aborts partway through). The test attaches
the device itself, so do **not** pre-run the §3 `vppctl device attach`
sequence; set `PACKETFRAME_VPP_ADOPT=1` if the interface is already
attached from an earlier run.

`PORT` and `PCI` are comma-separated and **pair by position**; give one
VF per member device.

```sh
PACKETFRAME_VPP_API_SOCK=/run/vpp/api.sock \
PACKETFRAME_VPP_PORT=eth2,eth3 \
PACKETFRAME_VPP_PCI=0002:07:00.0,0002:07:00.1 \
PACKETFRAME_VPP_ROUTES=/tmp/pf-routes.txt \
PACKETFRAME_VPP_NEIGH=/tmp/pf-neigh.txt \
PACKETFRAME_VPP_EXPECT_ROUTES=<the count from above> \
  ./tests/vpp_convergence_bench --include-ignored --nocapture
```

Run the staged binary directly, **not** via `run-tests.sh`: that driver
takes only test names, supplies `--include-ignored --nocapture` itself,
and forwards nothing after a `--` — it would try to execute `--` and
`--nocapture` as test binaries and fail the run even when the bench
succeeded.

Re-running against a VPP that already has the interfaces needs adoption
plus the indices VPP assigned, because attach refuses to reuse an index
it was not told. **Take them from the line the fresh run printed**, not
from `show interface`: the dump reports indistinguishable `octeonN/P`
names with no PCI identity, so it cannot tell you which index belongs to
which member port, and supplying them in the wrong order programs
neighbours and routes through the opposite VFs — which verification will
*not* catch, because it checks that paths use an owned index, not the
intended one. The fresh run prints exactly the line to reuse:

```
  to re-run adopted:  PACKETFRAME_VPP_ADOPT=1 PACKETFRAME_VPP_SWIFINDEX=3,4
```

Restarting VPP between runs is simpler and is what the timings above
assume.

### Reading the result

The phase breakdown prints **before** any budget assertion, deliberately:
a run that blows the budget is exactly the one whose breakdown matters,
and a panic that hid it would waste the trip. Record `connect / attach /
resync plan / neighbours / drain / verify / TOTAL`, the routes/s rate,
and the ledger line.

Failure modes worth recognising rather than debugging from scratch:

- **`unresolvable > 0`** — the neighbour file does not cover every
  nexthop the routes name. Verification fails by design; fix the input,
  do not lower the bar.
- **`deferred` large** — interface indices were not known when the drain
  started, i.e. attach did not land. The attach step failing is louder;
  check `show interface` first.
- **drain not converging** — the run aborts after 10× budget rather than
  hanging.
- **abort with `Out-of-memory, calling os_panic()`** — the `statseg` is
  undersized. Use `show memory` (**all** heaps), never
  `show memory main-heap`, which reads mostly free during exactly this
  failure. See the item-10 RESULT.

### RESULT (2026-08-03, shadow): **CONVERGENCE BUDGET MET — 40.32 s ≤ 60 s**

**1,053,370 v4 prefixes** from the live `master4`, loaded through the
`ConvergenceEngine` over the binary API into v26.06/octeon9. Verify
PASS (64/64 probes), ledger fully installed, `may_steer true`,
`installed == expect`. The chain-verified inputs reconciled exactly:
bird 1,053,404 networks, 34 excluded (no via — connected/blackhole/
unreachable, the real figure for the ~331 §0 estimate), 0 dropped for
missing ARP.

| phase | time | notes |
|---|---:|---|
| connect | 0.18 s | outside the budget (one-time socket setup) |
| attach | 0.39 s | inside |
| resync plan | 1.46 s | 1,053,370 upserts, 0 withdrawals |
| neighbours | 0.00 s | 2 programmed (see below) |
| drain | 38.42 s | 258 passes, all acked, 0 deferred, 0 rejected |
| verify | 0.05 s | 64 probes |
| **TOTAL** | **40.32 s** | **budget 60 s — 33% headroom** |

**27,418 routes/s** over the drain (window 256, batch 4096; 258 × 4096
covers the table). Drain is ~95% of the total; every other phase is
noise, so future tuning has exactly one lever that matters.

Cross-validation against item 10, which is the quiet headline: **main
heap used 803.17M vs item 10's 803.49 MiB; stat segment populated
101.94M — identical.** Two independent load paths (CLI exec, binary
API) landing on the same memory figures makes the sizing constants in
`startup_conf.rs` about as trustworthy as measurement gets.

Also settled by reality: the plan's worry about "1.05M round trips
against the real 129 nexthops" — the route-referenced via set is **2**
(the two upstreams). 129/134 is the ARP table, not the nexthop set, so
item 10's single-synthetic-nexthop method note was closer to production
shape than anyone expected.

Caveats, recorded not buried:
- **REDUCED RUN**: one VF bound, so both upstream adjacencies were
  relabelled onto eth3. The multi-port nexthop mapping is unexercised —
  though with 2 vias, a two-VF run differs only in which sw_if_index
  two adjacencies carry; the drain and wire path are identical.
- **Fresh attach only.** Adoption (`PACKETFRAME_VPP_ADOPT`) not run.
- This validates table *load*, not forwarding — items 1 (steered half)
  and 7 (PMTUD) still need a traffic peer.

## 4. Pass / kill / record

- **Pass:** items 1, 2, 7, 10 all WORK (delivery, egress, PMTUD,
  **v4** full-table capacity — the round-4 decision's shape; a v4+v6
  load would validate a table nobody is shipping). Everything else
  shapes design rather than gating it. Items 3 and 9 are already
  FAILED-and-absorbed: v6 stays on XDP by design, poll-mode heat is a
  recorded cost — neither kills the phase.
- **Kill:** ~~VPP's PMD can't handshake the AF~~ — RETIRED: the
  mailbox is proven (rounds 2–3). No kill criterion remains; what is
  left is measurement.
- Record every number in this file under a Results heading, then update
  `HEAP_BYTES_PER_ROUTE` and the plan's sizing notes from item 10, and
  pin the VPP version for slice 3.

## Cleanup

`pkill vpp`; sweep `/dev/hugepages/rtemap_*`; VF and hugepage teardown
per the gate-0a notes (or leave staged for the next session — the
shadow is the integration environment).

`vpp.service` stays **masked** from §1 unless you deliberately want the
packaged daemon running. Leave it masked between sessions: an
unattended VPP holding hugepages and the VF is exactly the state that
makes the next bring-up fail confusingly. Only `systemctl unmask
vpp.service` when handing the box back to normal use — and note that
`pkill vpp` alone does not survive an unmasked unit's restart policy.
