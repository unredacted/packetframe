# CLAUDE.md

Project guidance for Claude Code sessions. Keep this file tight: skim it first, then dive in.

## Project overview

PacketFrame is a modular eBPF data plane written in pure Rust (aya + aya-ebpf). The MVP module is **fast-path**, which takes forwarded traffic for allowlisted prefixes off the kernel's conntrack/netfilter path via XDP ingress + `bpf_redirect_map`. Forwarding decisions pick between two modes: `kernel-fib` (`bpf_fib_lookup()`, the default and rollback path) or `packetframe-fib` (Option F: LPM-trie FIB populated from a userspace route source, with `FibProgrammer` + `NeighborResolver` under a tokio runtime). Two route-source implementations live in tree: `BgpListener` (passive iBGP, the production path, since bird 2.x/3.x does not implement RFC 9069 Loc-RIB BMP) and `BmpStation` (RFC 7854 + 9069, ready for emitters that ship Loc-RIB like FRR). The PacketFrame FIB runbook lives at `docs/runbooks/packetframe-fib.md`. The design spec (`SPEC.md`) is deliberately **not** in the repo. Inline code comments cite section numbers ("SPEC.md §4.2") as breadcrumbs for reviewers who have the spec. Don't re-add `SPEC.md`; it's in `.gitignore`.

## Repo layout

- `crates/common/`: config parser (SPEC.md §6), `Module` trait (§3.2), §2.1 capability probes, PacketFrame FIB trait shapes (`fib/mod.rs`)
- `crates/cli/`: the `packetframe` binary (clap subcommands: `feasibility`, `run`, `detach`, `status`, `fib`, `probe`, `sampler`, the VPP sampler's lab reader)
- `crates/flow-encode/`: pure wire encoders for flow export (sFlow v5, NetFlow v9, IPFIX flows and PSAMP packet reports); no sockets or clocks. Driven today by the dev-only `packetframe flow-synth` (`dev-tools` feature, off by default); collector evidence and the requirements it puts on the exporter in `docs/flow-export/collectors.md`
- `crates/modules/fast-path/`: fast-path module including the PacketFrame FIB control plane under `src/fib/`
- `crates/modules/flow-export/`: sampled packets to flow collectors as sFlow v5 or IPFIX flow records (`flows.rs` bounded cache, `ipfix_out.rs` per privacy profile, origin ASes from the `AsnTable` in `common/src/fib/asn.rs`, which fast-path's programmer fills); runbook at `docs/runbooks/flow-export.md`. Reads fast-path's sampler (`SAMPLE_CFG`, the `SAMPLES` BPF ring buffer via `fast-path/src/sample_ring.rs`: a ring buffer because UniFi's kernel lacks CONFIG_BPF_EVENTS, so `bpf_perf_event_output` fails there) and its port registry, and VPP's sampler plugin through sampler-shm (`vpp.rs`: owns `desired.conf`, binds each generation to one VPP process's port snapshot from `common/src/sampler_ports.rs`, reads a sample only through its own generation's binding). One sFlow data source per port; pools from `rx_packets` plus VPP's per-interface counts; a 100 ms worker (`pf-flow-export`, placed with the control plane) behind traits so it runs against fakes on any host; coverage per port and path (`xdp`, `tc`, `vpp`, `kernel`) and per-collector submission rows, also published as `common/src/flow_coverage.rs`'s `FlowCoverage` handle for the DDoS mitigation (Phase 2; stale after 1 s, submission never receipt). `packetframe flow-export interfaces` prints the ifIndex map for collectors; `feasibility.rs` holds its advisory probes (incl. the plugin's `.vlib_plugin_registration` version, which CI's plugin job checks against dpkg). Its own BPF crate `bpf/` is the `kernel-sample` tc-ingress sampler (`kernel.rs`, records in `tc_links.rs`, guard's attach pattern). Degrades rather than aborts on a failed start (`REPORT_RESIDUAL` in the loader). Root end-to-end tests drive fast-path's real XDP program, the kernel sampler over veths, and a real sampler tmpfs with the test process standing in for VPP, into a local UDP collector
- `crates/modules/guard/`: tc-egress frame policer (ARP/NS per-target rate limit, LLDP drop, foreign-src-MAC drop, bcast/mcast catch-all) for the IX-facing bridges; runbook at `docs/runbooks/guard.md`
- `crates/modules/neigh-snoop/`: passive ARP/ND neighbour snooper for the IX-facing bridges (receive-only AF_PACKET + cBPF, learns third-party pairs, installs NUD_STALE, persists per bridge, tracks bridges by name, `ix-mode` into fast-path's resolver, FRR next-hop gate feed); runbook at `docs/runbooks/neigh-snoop.md`. No site-specific addresses in code, tests or docs: RFC 5737/3849 prefixes and `02:…` MACs only
- `crates/sampler-shm/`: the shared-memory protocol between PacketFrame and its VPP sampler plugin (flow export): `desired.conf` and `current` text formats, epoch-file layout, SPSC drop-on-full rings and a seqlocked status, all word-atomic; the Linux file operations (size-limited tmpfs check, epoch create/open/reclaim, locks); and the consumer side every reader shares (`coverage::assess`, `follow::Follower` across VPP restarts). Loom models in `tests/loom.rs` (`RUSTFLAGS="--cfg loom"`), two-process stress and root-only tmpfs tests run on CI's arm64 job
- `crates/vpp-plugins/`: the VPP sampler plugin. `pf-sampler-core` (workspace member) holds all its logic — selection, pool indices, the desired.conf → interfaces → status controller, the epoch-file driver — tested on any host; `pf-sampler` is the cdylib glue (node, features, barrier, process node, CLI), excluded from the workspace because it builds only against one VPP's headers, on `vpp-plugin` pinned to the unredacted fork by commit. CI's `sampler plugin (arm64, VPP)` job builds it in bullseye against the SOURCE.json release and runs it in a real VPP (`pf-sampler/ci/smoke.sh`)
- `conf/example.conf`: reference config per SPEC.md §4.8
- `docs/runbooks/packetframe-fib.md`: Option F operations runbook (healthy state, triage by symptom, cutover + rollback, Phase 4 config snippets)
- `.github/workflows/`: `ci.yml` (fmt/clippy, one test build whose binaries the privileged native and qemu jobs run, 4× cross-build), `qemu-verifier.yml` (called by ci.yml: those binaries in 5.15 + 6.6 guests under KVM), `release.yml` (tag-triggered tarballs), `hardware-artifacts.yml` (per-main-push aarch64 test-binary + CLI bundle for on-router runs)
- `crates/modules/vpp-offload/vpp-api/`: vendored `.api.json` (the binary-API wire format) + `SOURCE.json`, the manifest of the release they came from. There is deliberately no separate pin file — the module is generic over VPPs (CRC handshake at attach), every fetch pointer derives from SOURCE.json, and CI byte-binds the bundle to its release. VPP for UniFi gateways is built by github.com/unredacted/vpp-unifi; bump procedure in that directory's README.md. Installing the VPP deb on a router: follow vpp-unifi's README sequence exactly — the deb ships `/etc/sysctl.d/80-vpp.conf`, which `VPP_INSTALL_SKIP_SYSCTL=1` does NOT remove; left in place it re-applies at every boot (a 512 GiB hugepage request on the 64K-page fleet) and bricked the primary EFG on 2026-08-21. The install is not done until that file is deleted and verified gone

## Build & test

```sh
make test          # cargo test across the workspace
make build         # debug build, host target
make release       # release build, host target
make release-all   # release build for all 4 published targets (requires `cross`)
make lint          # cargo fmt --check + cargo clippy -D warnings
make fmt           # cargo fmt
```

CI runs all of the above plus cross-builds for `{aarch64,x86_64}-unknown-linux-{musl,gnu}`, and the sudo-gated integration tests (`fib_fixtures`, `fib_programmer_integration`, `fib_comparison`, `neigh_resolver_netns`, etc.) natively and in a qemu-verifier matrix (kernels 5.15 + 6.6). Those run from binaries `build` compiles once, never cargo in the guest; what runs where is the table in `.github/scripts/privileged-tests.sh`, and a new privileged test package goes there.

## License

GPL-3.0-or-later. The three surfaces must agree: `LICENSE` (GPLv3 text), `Cargo.toml` workspace `license` field, `README.md` License section.

## Platform constraints

Linux-only code (BPF syscalls, `/proc/config.gz`, `/proc/sys/...`, bpffs, netlink, PacketFrame FIB control plane) is gated behind `#[cfg(target_os = "linux")]`. Non-Linux hosts get `ENOSYS`-returning stubs so `cargo check`/`cargo test` succeed on macOS dev laptops. On macOS, `packetframe feasibility` correctly reports every BPF capability as **Fail**; that's expected behavior, not a bug to chase. Integration tests (`bpf_prog_test_run` fixtures + netns + pinned-map harnesses) run via the qemu-verifier job on CI; host macOS `cargo check` skips the Linux-only modules, so it's easy to accidentally land code that compiles locally but not on Linux. CI catches these in the cross-build matrix.

## Toolchain

Stable Rust is pinned only in root `rust-toolchain.toml`: CI reads it from there (`.github/actions/rust-stable-pin`) and Dependabot proposes the bumps. A second `rust-toolchain.toml` under `crates/modules/fast-path/bpf/` pins nightly for the BPF crate (aya-ebpf needs it). `bpf-linker` is pinned in CI via `cargo install --locked bpf-linker@<version>`. The nightly and bpf-linker stay hand-pinned. Don't unpin any of these; aya has had breaking API changes across minor versions.

## Error handling

Validate at system boundaries (`bpf()` syscall, sysfs/procfs reads, config parse). Trust framework guarantees inside; no fallbacks for conditions that can't occur. No backwards-compat shims for hypothetical future states; change the code directly when requirements change.

## Spec tethering

Comments reference spec sections, they don't restate them. Don't paraphrase the spec in docstrings unless the spec is genuinely unclear on a point. "SPEC.md §4.4 step 9d" is better than a prose recap that will drift. Read the cited section when touching the cited code.

## Clippy policy

CI runs `cargo clippy --workspace --all-targets --all-features -- -D warnings`. Cross-platform casts that are no-ops on one target but load-bearing on another (e.g. `statfs.f_type as i64`: `i64` already on glibc Linux x86_64, but `u32` on macOS) need a targeted `#[allow(clippy::unnecessary_cast)]` with a comment explaining *why* the cast stays. The pattern is established in [crates/common/src/probe/mod.rs](crates/common/src/probe/mod.rs) and [crates/common/src/probe/bpf.rs](crates/common/src/probe/bpf.rs).

## PR workflow

One feature branch per slice. Commit messages explain **why**, not what the diff already shows. CI must be green before asking for review (eleven jobs: fmt+clippy, build+test, privileged tests native, four cross-builds, sampler-shm on arm64, the sampler plugin in VPP on arm64, two qemu kernels). Amending unreviewed commits and `git push --force-with-lease` on a feature branch is fine pre-review; force-push to `main` is never fine. For multi-phase work (e.g. the Option F rollout) the slicing lives in the plan file; keep PRs scoped to a single slice.

## What not to change casually

- `SPEC.md` stays out of the repo; it's in `.gitignore`.
- License stays GPL-3.0-or-later across `LICENSE`, `Cargo.toml`, and `README.md`.
- The `Module` trait in [crates/common/src/module.rs](crates/common/src/module.rs) is the public contract for every future module (randomizer, ddos, sampler); breaking changes need a changelog note and coordinated updates.
- Counter indices in the `stats` map (§4.6) are append-only once v0.1 ships; renumbering breaks operator dashboards.
- Platform cfg gates: don't collapse the Linux-only/non-Linux split without also making the macOS dev loop still work.
