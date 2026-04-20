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

    // Explicit opt-out for debugging/local work.
    if std::env::var("PACKETFRAME_SKIP_BPF_BUILD").is_ok() {
        println!("cargo::warning=PACKETFRAME_SKIP_BPF_BUILD set; writing empty stub BPF ELF");
        write_stub(&obj_out);
        println!("cargo::rustc-env=FAST_PATH_BPF_OBJ={}", obj_out.display());
        return;
    }

    // Nested build. `bpf/rust-toolchain.toml` pins nightly + the
    // bpfel-unknown-none target; `.cargo/config.toml` sets `linker =
    // bpf-linker`. If rustup is installed this works; if not, cargo
    // will fail and we fall through to the stub path.
    let status = Command::new("cargo")
        .current_dir(&bpf_dir)
        .args(["build", "--release", "--bin", "fast-path"])
        .status();

    let built_elf = bpf_dir.join("target/bpfel-unknown-none/release/fast-path");

    match status {
        Ok(s) if s.success() && built_elf.exists() => {
            std::fs::copy(&built_elf, &obj_out).expect("stage BPF ELF into OUT_DIR");
            println!("cargo::rustc-cfg=packetframe_bpf_built");
        }
        Ok(s) if s.success() => {
            println!(
                "cargo::warning=BPF build reported success but ELF not found at {}; using stub",
                built_elf.display()
            );
            write_stub(&obj_out);
        }
        Ok(s) => {
            println!(
                "cargo::warning=BPF build failed (exit {}); using empty stub ELF. Install rustup + nightly + bpf-linker for local BPF builds; CI does this automatically.",
                s.code().unwrap_or(-1)
            );
            write_stub(&obj_out);
        }
        Err(e) => {
            println!(
                "cargo::warning=could not invoke cargo for BPF build ({e}); using empty stub ELF"
            );
            write_stub(&obj_out);
        }
    }

    println!("cargo::rustc-env=FAST_PATH_BPF_OBJ={}", obj_out.display());
}

fn write_stub(path: &std::path::Path) {
    std::fs::write(path, []).expect("write stub ELF");
}
