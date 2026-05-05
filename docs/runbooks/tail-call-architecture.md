# Two-stage BPF datapath (v0.2.5+)

PacketFrame's fast-path runs as **two BPF programs** chained by `bpf_tail_call`. This page exists for operators debugging the chain and contributors planning further BPF work.

## Why two programs

The single-program datapath (v0.2.4 and earlier) accumulated mutation, VLAN choreography, and redirect logic in one XDP program. On vanilla 5.15 + 6.6 kernels (CI's qemu test matrix) it loaded fine. On UniFi's `5.15.72-ui-cn9670` (real production hardware), the kernel verifier rejected at:

```
combined stack size of 3 calls is 544. Too large
stack depth 0+480+0+0
```

UniFi's BPF patches plus the aarch64 JIT account stack ~120 bytes higher than vanilla 5.15 on x86_64 — same bytecode, different verifier accounting.

Tail-calling into a second program gives that program its own fresh 512-byte stack. Beyond fixing the immediate budget issue, it establishes the pattern for future fast-path stages without re-bisecting stack bytes every time.

This is **not** the multi-module dispatcher (SPEC §3.4 / §5.0). The dispatcher is for chaining independent modules at the same hook (ddos in front of fast-path, sampler behind it). Tail-call is for splitting one logical pipeline. Both are real and orthogonal; v0.2.5 ships only the latter.

## Chain topology

```
                       packet ingress
                              │
                              ▼
   ┌──────────────────────────────────────────────────┐
   │ fast_path  (XDP, attached to eth0..ethN)         │  Frame A
   │   classification (allow-prefix, block-prefix)     │  fits 512B
   │   FIB lookup  (kernel-fib | custom-fib | compare)│
   │   devmap pre-check                                │
   │   TTL decrement                                   │
   │   L2 rewrite (smac/dmac in place)                 │
   │   write per-CPU MUTATION_CTX                      │
   │   bpf_tail_call(MUTATION_PROGS, 0)  ──────────┐  │
   └────────────────────────────────────────────────│──┘
                                                    │
                                                    ▼
   ┌──────────────────────────────────────────────────┐
   │ finalize  (XDP, tail-called by fast_path)        │  Frame B
   │   read MUTATION_CTX                               │  fresh 512B
   │   mss-clamp lookup + (optional) MSS rewrite       │
   │   VLAN choreography (push / pop / rewrite)        │
   │   bpf_redirect_map(egress_ifindex)                │
   └──────────────────────────────────────────────────┘
                              │
                              ▼
                      egress NIC TX
```

The packet itself is preserved across the tail-call — `bpf_tail_call` doesn't touch `xdp_buff`, so any in-place mutations from fast_path (TTL, L2, etc.) carry over. What does NOT carry are the program's local variables, which is why we need a side channel.

## MUTATION_CTX wire format

`MUTATION_CTX` is a `PerCpuArray<MutationCtx>` with a single element. `fast_path` writes index 0 immediately before its `bpf_tail_call`; `finalize` reads index 0 as its first action.

```rust
#[repr(C)]
pub struct MutationCtx {
    egress_ifindex: u32,   // FIB-resolved egress (pre-VLAN-resolve)
    egress_vid: u16,       // VLAN_RESOLVE result; 0 = untagged
    ingress_vid: u16,      // From packet parse; 0 = untagged
    ip_offset: u32,        // Bytes from ctx.data() to IP header
    is_v4: u8,             // 1 = IPv4, 0 = IPv6
    _pad: [u8; 3],
}
```

16 bytes, naturally aligned. Per-CPU because the NAPI cycle is single-CPU; the read in finalize sees the most recent write in fast_path with no synchronization.

## MUTATION_PROGS jump table

`MUTATION_PROGS` is a `ProgramArray` sized for 8 slots. Slot 0 holds `finalize`'s file descriptor. Slots 1–7 are reserved for future stages (see "Adding new stages" below).

Userspace populates slot 0 at attach time, in `crates/modules/fast-path/src/linux_impl.rs::populate_mutation_progs`. Order is: load `finalize` → populate slot 0 → load + attach `fast_path` to ifaces. If the order is wrong, fast_path's first packet hits an empty slot, `bpf_tail_call` returns an error, and fast_path falls through to `XDP_PASS` (kernel slow-path) while bumping `ErrTailCall`.

## Diagnostic commands

```sh
# Confirm both programs are loaded.
sudo bpftool prog show name fast_path
sudo bpftool prog show name finalize

# Confirm MUTATION_PROGS[0] points at finalize.
sudo bpftool map dump name MUTATION_PROGS
# Expected: key 0x00000000 value <fd of finalize>

# packetframe status reports the same:
sudo packetframe status
# tail-call chain (from /sys/fs/bpf/packetframe):
#   MUTATION_PROGS[0]: populated (finalize) — confirm prog_id via ...

# Watch the diagnostic counters:
sudo packetframe status | grep -E 'err_tail_call|err_mutation_ctx'
# Both should be 0 in steady state.

# Inspect MUTATION_CTX (per-CPU; one entry per CPU):
sudo bpftool map dump name MUTATION_CTX
# Decoded fields are the most recent decision from each CPU's fast-path.
# Useful for confirming the chain is firing on real traffic.
```

## What `ErrTailCall` and `ErrMutationCtx` mean

Two new diagnostic counters at indices 35 and 36:

- `err_tail_call`: fast_path called `MUTATION_PROGS.tail_call(ctx, 0)` and got an error back. Almost always means slot 0 is empty (attach-order bug). fast_path falls through to `XDP_PASS` so traffic still flows via kernel slow-path.
- `err_mutation_ctx`: finalize couldn't read `MUTATION_CTX[0]`. Per-CPU array index 0 is always present, so this should be 0; non-zero indicates a kernel/aya bug worth filing.

Both are append-only per CLAUDE.md guardrail — operator dashboards keying on counter index keep working.

## Pin lifecycle

bpffs layout under `/sys/fs/bpf/packetframe/fast-path/`:

```
progs/
├── fast_path     ← attached to ifaces; pin survives SIGTERM
└── finalize      ← tail-called; pin survives SIGTERM
maps/
├── (existing maps: ALLOW_V*, BLOCK_V*, CFG, STATS, ...)
├── MSS_CLAMP_V4 / MSS_CLAMP_V6 / MSS_CLAMP_BY_IFACE  (v0.2.4+)
├── MUTATION_CTX                                       (v0.2.5+)
└── MUTATION_PROGS                                     (v0.2.5+)
links/
└── eth0, eth1, ...   ← per-iface XDP attachments (fast_path only)
```

`packetframe detach --all` walks both program pins and every map pin. Existing pin lifecycle and SIGTERM-without-detach semantics from SPEC §8.5 apply unchanged: both program pins survive process exit; the bpffs inodes hold kernel references; on restart, `pin::has_existing_pins()` sees them and refuses to start until operator runs `detach --all`.

## Adding new stages

The `MUTATION_PROGS` array has room for 7 future stages (slots 1–7). Two patterns:

**Replace slot 0** if the new stage subsumes finalize's responsibilities. `populate_mutation_progs` decides which program goes in slot 0 based on config. Example: a new `finalize_with_nat` program that does NAT + mss-clamp + VLAN + redirect.

**Chain via subsequent slots** if the new stage runs *between* finalize-equivalent stages. finalize's last action becomes `tail_call(MUTATION_PROGS, 1)` instead of `bpf_redirect_map`; the slot-1 program does redirect. This adds one more 512-byte stack budget.

In both patterns, all stages share the same `MUTATION_CTX` and `STATS` maps (one ELF, automatic map sharing in aya). New stages can introduce their own scratch maps as needed.

## What this isn't

- **Multi-module composition.** ddos / sampler / randomizer (SPEC §5.x) need the libxdp dispatcher, not tail-calls. The dispatcher chains *independent* modules at the same hook based on XDP verdicts; tail-call is one-way control transfer between cooperating stages.
- **A general "anything-goes" tail-call framework.** Tail calls have a depth limit (kernel cap is 33 chained calls; we never approach that) and one-way control flow. They're a tool for stack-budget relief, not a programmability layer.

## See also

- [docs/runbooks/mss-clamp.md](mss-clamp.md) — operator guide for the mss-clamp directive (which now lives inside `finalize`)
- [docs/runbooks/reconfigure.md](reconfigure.md) — SIGHUP / `packetframe reconfigure` semantics; both maps update through the same reconcile path regardless of which program reads them
- SPEC.md §3.2 (priority taxonomy), §3.4 (multi-program composition), §4.x (BPF map layouts), §11.x (kernel compatibility notes)
