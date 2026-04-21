//! Build the BPF crate at `./bpf/` and stage its ELF for `include_bytes!`
//! in the userspace crate.
//!
//! Targeting `bpfel-unknown-none` requires nightly Rust + `bpf-linker` +
//! the `bpfel-unknown-none` target. CI installs all three (see
//! `.github/workflows/ci.yml`); local dev on macOS typically has none of
//! them and that is deliberate per the PR #3 plan ("CI-only BPF builds").
//!
//! If the nested build fails for any reason — no rustup, no nightly, no
//! bpf-linker, missing target, or a real compile error — we emit an
//! empty stub ELF and skip setting the `packetframe_bpf_built` cfg.
//! Userspace code uses that cfg to gate tests and error clearly at
//! runtime if someone tries to load the empty object.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Tell rustc about the custom cfg we conditionally emit, so
    // `#[cfg(packetframe_bpf_built)]` is not flagged as an unknown cfg
    // name by rustc's `unexpected_cfgs` lint (Rust 1.80+).
    println!("cargo::rustc-check-cfg=cfg(packetframe_bpf_built)");

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
    );
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let bpf_dir = manifest_dir.join("bpf");
    let obj_out = out_dir.join("fast-path.bpf.o");

    // Rerun triggers. `src/**/*.rs` is covered by `rerun-if-changed` on
    // the directory — cargo walks it recursively.
    for rel in [
        "src",
        "Cargo.toml",
        "rust-toolchain.toml",
        ".cargo/config.toml",
    ] {
        println!("cargo::rerun-if-changed={}", bpf_dir.join(rel).display());
    }
    println!("cargo::rerun-if-env-changed=PACKETFRAME_SKIP_BPF_BUILD");
    println!("cargo::rerun-if-env-changed=PACKETFRAME_BPF_REQUIRED");
    println!("cargo::rerun-if-env-changed=PACKETFRAME_BPF_OBJ_PATH");

    let bpf_required = std::env::var("PACKETFRAME_BPF_REQUIRED").is_ok();
    let bpf_skip = std::env::var("PACKETFRAME_SKIP_BPF_BUILD").is_ok();
    let bpf_obj_override = std::env::var("PACKETFRAME_BPF_OBJ_PATH").ok();

    if bpf_required && bpf_skip {
        panic!(
            "PACKETFRAME_BPF_REQUIRED=1 and PACKETFRAME_SKIP_BPF_BUILD=1 are mutually exclusive"
        );
    }

    // Pre-built ELF override — used by release.yml to build BPF once on
    // the host runner (where nightly + bpf-linker exist), upload as an
    // artifact, and hand the path to every cross-build job. Cross
    // containers lack rustup entirely, so nested cargo would fail and
    // silently stub; this bypass makes shipped binaries carry the real
    // ELF across all four targets.
    if let Some(path) = bpf_obj_override {
        let src = PathBuf::from(&path);
        if !src.exists() {
            panic!(
                "PACKETFRAME_BPF_OBJ_PATH points at {} which does not exist",
                src.display()
            );
        }
        let bytes = std::fs::read(&src)
            .unwrap_or_else(|e| panic!("read PACKETFRAME_BPF_OBJ_PATH at {}: {e}", src.display()));
        if bytes.len() < 4 || &bytes[..4] != b"\x7fELF" {
            panic!(
                "PACKETFRAME_BPF_OBJ_PATH at {} does not start with ELF magic \
                 (got {:02x?}); refusing to embed a broken object",
                src.display(),
                bytes.iter().take(4).collect::<Vec<_>>()
            );
        }
        std::fs::copy(&src, &obj_out).expect("stage overridden BPF ELF into OUT_DIR");
        println!("cargo::rustc-cfg=packetframe_bpf_built");
        println!(
            "cargo::warning=Using pre-built BPF ELF from PACKETFRAME_BPF_OBJ_PATH ({} bytes) at {}",
            bytes.len(),
            src.display()
        );
        println!("cargo::rustc-env=FAST_PATH_BPF_OBJ={}", obj_out.display());
        return;
    }

    // Explicit opt-out for debugging/local work (or for cross-build CI
    // jobs that only exercise userspace cross-compilation).
    if bpf_skip {
        println!("cargo::warning=PACKETFRAME_SKIP_BPF_BUILD set; writing empty stub BPF ELF");
        write_stub(&obj_out);
        println!("cargo::rustc-env=FAST_PATH_BPF_OBJ={}", obj_out.display());
        return;
    }

    // Nested build. `bpf/rust-toolchain.toml` pins nightly + the
    // bpfel-unknown-none target; `.cargo/config.toml` sets `linker =
    // bpf-linker`. If rustup is installed this works; if not, cargo
    // will fail and we fall through to the stub path.
    //
    // Capture stderr + stdout so we can re-emit the real cargo error
    // as cargo:warning lines on failure — otherwise the outer cargo
    // swallows this build.rs process's output and users see only our
    // opaque "BPF build failed (exit N)" warning, which is useless
    // for diagnosing toolchain or compile errors in the BPF crate.
    //
    // Clear outer-cargo/rustup env vars before spawning so rustup
    // fresh-resolves the toolchain from `bpf/rust-toolchain.toml`.
    // Without this, `CARGO` and `RUSTUP_TOOLCHAIN` inherit from the
    // outer stable build, and cargo links against a precompiled
    // `core` that doesn't exist for `bpfel-unknown-none` (symptom:
    // `error[E0463]: can't find crate for 'core'`) because `build-std`
    // only activates under nightly.
    // Build with `--message-format=json` so we can parse cargo's
    // structured output and locate the compiler-artifact filename.
    // That's more robust than hardcoding the target/ path — cargo and
    // bpf-linker have both moved artifact locations across versions.
    let output = Command::new("cargo")
        .current_dir(&bpf_dir)
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO_BUILD_TARGET")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_MANIFEST_DIR")
        .args([
            "build",
            "--release",
            "--bin",
            "fast-path",
            "--message-format=json",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            match find_artifact(&out.stdout) {
                Some(built) if built.exists() => {
                    std::fs::copy(&built, &obj_out).expect("stage BPF ELF into OUT_DIR");
                    println!("cargo::rustc-cfg=packetframe_bpf_built");
                    // Debug: dump the first 16 bytes + size. ELF magic
                    // is 7f 45 4c 46 ("..ELF"); anything else is not a
                    // parseable ELF and aya will reject it.
                    if let Ok(bytes) = std::fs::read(&built) {
                        let head: Vec<String> =
                            bytes.iter().take(16).map(|b| format!("{b:02x}")).collect();
                        println!(
                            "cargo::warning=BPF ELF built from {} ({} bytes); first 16: {}",
                            built.display(),
                            bytes.len(),
                            head.join(" ")
                        );
                    } else {
                        println!("cargo::warning=BPF ELF built from {}", built.display());
                    }
                }
                Some(built) => {
                    forward_output(&[], &out.stderr);
                    let msg = format!(
                        "BPF build succeeded but artifact at {} does not exist",
                        built.display()
                    );
                    fail_or_stub(&obj_out, bpf_required, &msg);
                }
                None => {
                    // stdout is cargo JSON messages with --message-format=json;
                    // only stderr is human-readable and worth forwarding.
                    forward_output(&[], &out.stderr);
                    let msg = "BPF build succeeded but no compiler-artifact JSON message for `fast-path` bin was emitted";
                    fail_or_stub(&obj_out, bpf_required, msg);
                }
            }
        }
        Ok(out) => {
            // stdout is cargo JSON messages with --message-format=json;
            // only stderr is human-readable and worth forwarding.
            forward_output(&[], &out.stderr);
            let msg = format!(
                "BPF build failed (exit {}) — see cargo:warning lines above for the real error, or run `(cd crates/modules/fast-path/bpf && cargo build --release)` directly",
                out.status.code().unwrap_or(-1)
            );
            fail_or_stub(&obj_out, bpf_required, &msg);
        }
        Err(e) => {
            let msg = format!("could not invoke cargo for BPF build ({e})");
            fail_or_stub(&obj_out, bpf_required, &msg);
        }
    }

    println!("cargo::rustc-env=FAST_PATH_BPF_OBJ={}", obj_out.display());
}

/// Parse cargo's JSON message stream to find the artifact path for
/// the fast-path binary. Looks for `"reason":"compiler-artifact"`
/// lines naming `"fast-path"` and returns the first path inside the
/// `"filenames":["..."]` array.
fn find_artifact(stdout: &[u8]) -> Option<PathBuf> {
    const MARKER: &str = "\"filenames\":[\"";
    for line in String::from_utf8_lossy(stdout).lines() {
        if !line.contains("\"reason\":\"compiler-artifact\"") {
            continue;
        }
        if !line.contains("\"name\":\"fast-path\"") {
            continue;
        }
        let Some(start) = line.find(MARKER) else {
            continue;
        };
        let rest = &line[start + MARKER.len()..];
        let Some(end) = rest.find('"') else {
            continue;
        };
        return Some(PathBuf::from(&rest[..end]));
    }
    None
}

/// When PACKETFRAME_BPF_REQUIRED is set (CI), panic so the whole build
/// fails loudly instead of quietly writing a stub ELF that makes every
/// downstream test vacuously "pass" by early-returning on
/// `FAST_PATH_BPF_AVAILABLE == false`. Otherwise, stub and continue
/// (local dev on macOS without rustup, etc.).
fn fail_or_stub(obj_out: &std::path::Path, required: bool, msg: &str) {
    if required {
        panic!(
            "PACKETFRAME_BPF_REQUIRED is set but {msg}. Refusing to stub the ELF — that would make every BPF-dependent test a silent no-op."
        );
    }
    println!(
        "cargo::warning={msg}; using empty stub ELF. Install rustup + nightly + bpf-linker for local BPF builds; CI does this automatically."
    );
    write_stub(obj_out);
}

/// Re-emit the nested cargo's stdout + stderr as `cargo:warning` lines
/// so the outer cargo shows them. Each source line becomes a separate
/// warning — cargo prints one warning per line anyway, and this way
/// the user doesn't have to `cargo build -vv` to diagnose a BPF build
/// failure.
fn forward_output(stdout: &[u8], stderr: &[u8]) {
    let emit = |label: &str, bytes: &[u8]| {
        for line in String::from_utf8_lossy(bytes).lines() {
            if !line.trim().is_empty() {
                println!("cargo::warning=[bpf {label}] {line}");
            }
        }
    };
    emit("stdout", stdout);
    emit("stderr", stderr);
}

fn write_stub(path: &std::path::Path) {
    std::fs::write(path, []).expect("write stub ELF");
}
