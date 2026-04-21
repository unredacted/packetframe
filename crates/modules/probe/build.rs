//! Build the probe BPF crate at `./bpf/` and stage its ELF for
//! `include_bytes!` in the userspace crate. Mirror of the fast-path
//! module's build.rs — when one is updated, the other likely needs the
//! same change. Separate file (not a shared helper) because the
//! `PROBE_BPF_OBJ` / `PACKETFRAME_PROBE_BPF_OBJ_PATH` env var names
//! differ per crate and there's not enough other logic to factor out.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(packetframe_probe_bpf_built)");

    let manifest_dir = PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
    );
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR set by cargo"));
    let bpf_dir = manifest_dir.join("bpf");
    let obj_out = out_dir.join("probe.bpf.o");

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
    println!("cargo::rerun-if-env-changed=PACKETFRAME_PROBE_BPF_OBJ_PATH");

    let bpf_required = std::env::var("PACKETFRAME_BPF_REQUIRED").is_ok();
    let bpf_skip = std::env::var("PACKETFRAME_SKIP_BPF_BUILD").is_ok();
    let bpf_obj_override = std::env::var("PACKETFRAME_PROBE_BPF_OBJ_PATH").ok();

    if bpf_required && bpf_skip {
        panic!(
            "PACKETFRAME_BPF_REQUIRED=1 and PACKETFRAME_SKIP_BPF_BUILD=1 are mutually exclusive"
        );
    }

    // Pre-built ELF override — release workflow staging. See fast-path
    // build.rs for the full rationale.
    if let Some(path) = bpf_obj_override {
        let src = PathBuf::from(&path);
        if !src.exists() {
            panic!(
                "PACKETFRAME_PROBE_BPF_OBJ_PATH points at {} which does not exist",
                src.display()
            );
        }
        let bytes = std::fs::read(&src).unwrap_or_else(|e| {
            panic!(
                "read PACKETFRAME_PROBE_BPF_OBJ_PATH at {}: {e}",
                src.display()
            )
        });
        if bytes.len() < 4 || &bytes[..4] != b"\x7fELF" {
            panic!(
                "PACKETFRAME_PROBE_BPF_OBJ_PATH at {} does not start with ELF magic \
                 (got {:02x?}); refusing to embed a broken object",
                src.display(),
                bytes.iter().take(4).collect::<Vec<_>>()
            );
        }
        std::fs::copy(&src, &obj_out).expect("stage overridden probe BPF ELF into OUT_DIR");
        println!("cargo::rustc-cfg=packetframe_probe_bpf_built");
        println!(
            "cargo::warning=Using pre-built probe BPF ELF from PACKETFRAME_PROBE_BPF_OBJ_PATH ({} bytes) at {}",
            bytes.len(),
            src.display()
        );
        println!("cargo::rustc-env=PROBE_BPF_OBJ={}", obj_out.display());
        return;
    }

    if bpf_skip {
        println!("cargo::warning=PACKETFRAME_SKIP_BPF_BUILD set; writing empty stub probe BPF ELF");
        write_stub(&obj_out);
        println!("cargo::rustc-env=PROBE_BPF_OBJ={}", obj_out.display());
        return;
    }

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
            "probe",
            "--message-format=json",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => match find_artifact(&out.stdout) {
            Some(built) if built.exists() => {
                std::fs::copy(&built, &obj_out).expect("stage probe BPF ELF into OUT_DIR");
                println!("cargo::rustc-cfg=packetframe_probe_bpf_built");
                if let Ok(bytes) = std::fs::read(&built) {
                    let head: Vec<String> =
                        bytes.iter().take(16).map(|b| format!("{b:02x}")).collect();
                    println!(
                        "cargo::warning=probe BPF ELF built from {} ({} bytes); first 16: {}",
                        built.display(),
                        bytes.len(),
                        head.join(" ")
                    );
                } else {
                    println!(
                        "cargo::warning=probe BPF ELF built from {}",
                        built.display()
                    );
                }
            }
            Some(built) => {
                forward_output(&[], &out.stderr);
                let msg = format!(
                    "probe BPF build succeeded but artifact at {} does not exist",
                    built.display()
                );
                fail_or_stub(&obj_out, bpf_required, &msg);
            }
            None => {
                forward_output(&[], &out.stderr);
                let msg = "probe BPF build succeeded but no compiler-artifact JSON message for `probe` bin was emitted";
                fail_or_stub(&obj_out, bpf_required, msg);
            }
        },
        Ok(out) => {
            forward_output(&[], &out.stderr);
            let msg = format!(
                "probe BPF build failed (exit {}) — see cargo:warning lines above for the real error, or run `(cd crates/modules/probe/bpf && cargo build --release)` directly",
                out.status.code().unwrap_or(-1)
            );
            fail_or_stub(&obj_out, bpf_required, &msg);
        }
        Err(e) => {
            let msg = format!("could not invoke cargo for probe BPF build ({e})");
            fail_or_stub(&obj_out, bpf_required, &msg);
        }
    }

    println!("cargo::rustc-env=PROBE_BPF_OBJ={}", obj_out.display());
}

fn find_artifact(stdout: &[u8]) -> Option<PathBuf> {
    const MARKER: &str = "\"filenames\":[\"";
    for line in String::from_utf8_lossy(stdout).lines() {
        if !line.contains("\"reason\":\"compiler-artifact\"") {
            continue;
        }
        if !line.contains("\"name\":\"probe\"") {
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

fn forward_output(stdout: &[u8], stderr: &[u8]) {
    let emit = |label: &str, bytes: &[u8]| {
        for line in String::from_utf8_lossy(bytes).lines() {
            if !line.trim().is_empty() {
                println!("cargo::warning=[probe-bpf {label}] {line}");
            }
        }
    };
    emit("stdout", stdout);
    emit("stderr", stderr);
}

fn write_stub(path: &std::path::Path) {
    std::fs::write(path, []).expect("write stub probe ELF");
}
