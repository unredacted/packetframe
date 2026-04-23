# CLAUDE.md

Project guidance for Claude Code sessions. Keep this file tight — skim it first, then dive in.

## Project overview

PacketFrame is a modular eBPF data plane written in pure Rust (aya + aya-ebpf). The MVP module is **fast-path**, which takes forwarded traffic for allowlisted prefixes off the kernel's conntrack/netfilter path via XDP ingress + `bpf_redirect_map`. Forwarding decisions pick between two modes: `kernel-fib` (`bpf_fib_lookup()`, the default and rollback path) or `custom-fib` (Option F — LPM-trie FIB populated from bird over BMP + RFC 9069 Loc-RIB, with a userspace `FibProgrammer` + `NeighborResolver` + `BmpStation` under a tokio runtime). The custom-FIB runbook lives at `docs/runbooks/custom-fib.md`. The design spec (`SPEC.md`) is deliberately **not** in the repo — inline code comments cite section numbers ("SPEC.md §4.2") as breadcrumbs for reviewers who have the spec. Don't re-add `SPEC.md`; it's in `.gitignore`.

## Repo layout

- `crates/common/` — config parser (SPEC.md §6), `Module` trait (§3.2), §2.1 capability probes, custom-FIB trait shapes (`fib/mod.rs`)
- `crates/cli/` — the `packetframe` binary (clap subcommands: `feasibility`, `run`, `detach`, `status`, `fib`, `probe`)
- `crates/modules/fast-path/` — fast-path module including the custom-FIB control plane under `src/fib/`
- `conf/example.conf` — reference config per SPEC.md §4.8
- `docs/runbooks/custom-fib.md` — Option F operations runbook (healthy state, triage by symptom, cutover + rollback, Phase 4 config snippets)
- `.github/workflows/` — `ci.yml` (fmt/clippy/test + 4× cross-build), `qemu-verifier.yml` (integration tests on 5.15 + 6.6 kernels), `release.yml` (tag-triggered tarballs)

## Build & test

```sh
make test          # cargo test across the workspace
make build         # debug build, host target
make release       # release build, host target
make release-all   # release build for all 4 published targets (requires `cross`)
make lint          # cargo fmt --check + cargo clippy -D warnings
make fmt           # cargo fmt
```

CI runs all of the above plus cross-builds for `{aarch64,x86_64}-unknown-linux-{musl,gnu}` and a qemu-verifier matrix (kernels 5.15 + 6.6) that executes the sudo-gated integration tests (`fib_fixtures`, `fib_programmer_integration`, `fib_comparison`, `neigh_resolver_netns`, etc.) inside a VM.

## License

GPL-3.0-or-later. The three surfaces must agree: `LICENSE` (GPLv3 text), `Cargo.toml` workspace `license` field, `README.md` License section.

## Platform constraints

Linux-only code — BPF syscalls, `/proc/config.gz`, `/proc/sys/...`, bpffs, netlink, custom-FIB control plane — is gated behind `#[cfg(target_os = "linux")]`. Non-Linux hosts get `ENOSYS`-returning stubs so `cargo check`/`cargo test` succeed on macOS dev laptops. On macOS, `packetframe feasibility` correctly reports every BPF capability as **Fail** — that's expected behavior, not a bug to chase. Integration tests (`bpf_prog_test_run` fixtures + netns + pinned-map harnesses) run via the qemu-verifier job on CI; host macOS `cargo check` skips the Linux-only modules, so it's easy to accidentally land code that compiles locally but not on Linux — CI catches these in the cross-build matrix.

## Toolchain

Stable Rust is pinned via root `rust-toolchain.toml`. A second `rust-toolchain.toml` under `crates/modules/fast-path/bpf/` pins nightly for the BPF crate (aya-ebpf needs it). `bpf-linker` is pinned in CI via `cargo install --locked bpf-linker@<version>`. Don't unpin any of these — aya has had breaking API changes across minor versions.

## Error handling

Validate at system boundaries (`bpf()` syscall, sysfs/procfs reads, config parse). Trust framework guarantees inside — no fallbacks for conditions that can't occur. No backwards-compat shims for hypothetical future states; change the code directly when requirements change.

## Spec tethering

Comments reference spec sections, they don't restate them. Don't paraphrase the spec in docstrings unless the spec is genuinely unclear on a point. "SPEC.md §4.4 step 9d" is better than a prose recap that will drift. Read the cited section when touching the cited code.

## Clippy policy

CI runs `cargo clippy --workspace --all-targets --all-features -- -D warnings`. Cross-platform casts that are no-ops on one target but load-bearing on another (e.g. `statfs.f_type as i64` — `i64` already on glibc Linux x86_64, but `u32` on macOS) need a targeted `#[allow(clippy::unnecessary_cast)]` with a comment explaining *why* the cast stays. The pattern is established in [crates/common/src/probe/mod.rs](crates/common/src/probe/mod.rs) and [crates/common/src/probe/bpf.rs](crates/common/src/probe/bpf.rs).

## PR workflow

One feature branch per slice. Commit messages explain **why**, not what the diff already shows. CI must be green before asking for review (seven jobs: fmt+clippy+test, four cross-builds, two qemu kernels). Amending unreviewed commits and `git push --force-with-lease` on a feature branch is fine pre-review — force-push to `main` is never fine. For multi-phase work (e.g. the Option F rollout) the slicing lives in the plan file; keep PRs scoped to a single slice.

## What not to change casually

- `SPEC.md` stays out of the repo — it's in `.gitignore`.
- License stays GPL-3.0-or-later across `LICENSE`, `Cargo.toml`, and `README.md`.
- The `Module` trait in [crates/common/src/module.rs](crates/common/src/module.rs) is the public contract for every future module (randomizer, ddos, sampler) — breaking changes need a changelog note and coordinated updates.
- Counter indices in the `stats` map (§4.6) are append-only once v0.1 ships — renumbering breaks operator dashboards.
- Platform cfg gates: don't collapse the Linux-only/non-Linux split without also making the macOS dev loop still work.
