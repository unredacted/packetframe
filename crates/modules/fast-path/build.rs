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

    let bpf_required = std::env::var("PACKETFRAME_BPF_REQUIRED").is_ok();
    let bpf_skip = std::env::var("PACKETFRAME_SKIP_BPF_BUILD").is_ok();

    if bpf_required && bpf_skip {
        panic!(
            "PACKETFRAME_BPF_REQUIRED=1 and PACKETFRAME_SKIP_BPF_BUILD=1 are mutually exclusive"
        );
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
    let output = Command::new("cargo")
        .current_dir(&bpf_dir)
        .args(["build", "--release", "--bin", "fast-path"])
        .output();

    let built_elf = bpf_dir.join("target/bpfel-unknown-none/release/fast-path");

    match output {
        Ok(out) if out.status.success() && built_elf.exists() => {
            std::fs::copy(&built_elf, &obj_out).expect("stage BPF ELF into OUT_DIR");
            println!("cargo::rustc-cfg=packetframe_bpf_built");
        }
        Ok(out) if out.status.success() => {
            forward_output(&out.stdout, &out.stderr);
            let msg = format!(
                "BPF build reported success but ELF not found at {}",
                built_elf.display()
            );
            fail_or_stub(&obj_out, bpf_required, &msg);
        }
        Ok(out) => {
            forward_output(&out.stdout, &out.stderr);
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
