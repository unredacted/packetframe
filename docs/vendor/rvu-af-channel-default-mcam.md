# RVU AF: a VF coming up disables the PF's channel-default MCAM entries, and nothing VF-side re-enables them

Finding on Marvell CN96xx (CN9670, EFG gateway), vendor 5.15 kernel,
`rvu_af`/`rvu_nicpf`/`rvu_nicvf` drivers. Written up for an upstream /
vendor report; every claim below was measured on hardware between
2026-08-13 windows w3 and w10, with forensics retained (NPC debugfs
dumps, timestamped counters, driver logs).

## Summary

When a VF on a shared LMAC is brought up by a userspace dataplane
(VPP's native octeon driver on a vfio-pci VF), the AF **disables its
channel-default MCAM entries** for that LMAC — the multicast catch-all
and promiscuous entries that make the *kernel PF* receive (observed as
entries 2004/2005 for the channel, `Installed by: PF0`,
`Forward to: PF1`, flipping `enabled: yes → no`). The kernel PF goes
deaf below every software surface: `IFF_PROMISC` still set, link up,
no kernel log, `ethtool -S` `rx_drops` frozen. On a PF that is a
bridge member, that is a silent L2 blackout of everything behind the
bridge.

Two asymmetries make this hard to live with:

1. **The disable propagates from VF-side events; no VF-side action
   re-enables.** Setting promiscuous mode on the VF itself (VPP
   `sw_interface_set_promisc` → `roc_nix_npc_promisc_ena_dis(nix, 1)`,
   acknowledged) does **not** re-enable the PF's channel defaults —
   verified with a single stable VPP holding the promisc setting while
   the entries stayed disabled and the bridge stayed dark (w8).
2. **Only a PF-side rx-mode event restores them.** Any rx-mode
   set on the kernel PF netdev (an `IFF_ALLMULTI` toggle suffices)
   makes the PF driver resend `NIX_RX_MODE`, after which the AF
   re-installs/enables its defaults. Measured five-for-five with ~1 s
   recovery (w6), and confirmed as a durable fix when issued once
   after the VF settles (w9/w10: 420 s and 600 s windows, entries
   enabled in every snapshot).

## Reproduction

EFG (CN9670), eth4 = kernel PF, bridge member (switch0), one VF
(`sriov_numvfs=1`) bound to vfio-pci, VPP v26.06 built with
`VPP_PLATFORM=octeon9` attaching the VF (`device attach pci/...`,
interface up). Within ~1 s of the device attach:

- hosts behind the bridge unreachable (including from the router);
- `ethtool -S eth4 | grep rx_drops` stops advancing;
- `/sys/kernel/debug/octeontx2/npc/mcam_rules`: the channel's default
  entries read `enabled: no`.

Recovery: `ip link set eth4 allmulti on; ip link set eth4 allmulti off`
— reachability returns in ~1 s and the entries read `enabled: yes`.

A control on a non-bridge L3 port (eth1) shows the same table change
without user-visible impact, which is why this survives on most
topologies and bites bridge members.

## Why we believe the trigger is the VF's rx-mode state at the AF

VPP's `oct_port_start` asserts `roc_nix_npc_promisc_ena_dis(nix,
port->promisc)` with `promisc = false` at port start — a VF-side
rx-mode message to the AF. The AF appears to fold every function's
stored rx-mode into the LMAC's channel-default entry state on any
function's rx-mode event, in the disable direction — but the converse
(VF promisc on) does not restore the PF's entries, so the state is
asymmetric: a VF can subtract from the channel defaults and cannot add
them back; only the PF's own `NIX_RX_MODE` refresh can.

This is the same shared-LMAC state family as the CGX flow-control
refusal (which the AF *refuses* loudly) — but here the interaction is
silent and the loser is the kernel PF.

## What we ship as the workaround

packetframe (the supervisor that runs VPP on the VF) issues the
PF-side rx-mode toggle itself after every VF device attach
(`RxModeKick` in `crates/modules/vpp-offload/src/runtime.rs`, PR
#181), and keeps the VF's promisc vote asserted (PR #178) so future AF
re-evaluations land enabled. Operators get the by-hand toggle in
`docs/runbooks/vpp-offload.md` ("A bridge-member port goes dark right
after attach").

## Asks

1. Should a VF's rx-mode state be able to disable the PF's
   channel-default entries at all? If yes, the enable direction should
   be symmetric.
2. If the current behaviour is intended, an AF log line (or debugfs
   event counter) when channel defaults are disabled on behalf of
   another function would have cut days off diagnosing this — the
   kernel PF surfaces nothing today.

## Evidence index (retained on the reference router)

- `/root/w5/`, `/root/w6/`: eth4-only bisection + five kick/re-break
  cycles (re-breaks later explained by a supervisor respawn loop on
  our side — each respawn re-ran `oct_port_start`; the kick's ~1 s
  recovery stands).
- `/root/w8/`: single stable VPP, promisc acknowledged, entries
  `enabled: no`, `rx_drops` frozen 08:42:48–:50 bracketing the attach.
- `/root/w9/`, `/root/w10/`: with the PF-side kick after attach,
  420 s / 600 s windows, entries `enabled: yes` in every snapshot.
