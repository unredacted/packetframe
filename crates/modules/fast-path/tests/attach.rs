// aya is Linux-only.
#![cfg(target_os = "linux")]

//! Integration test: load the fast-path BPF ELF, create a veth pair,
//! attach to one end (native XDP, falling back to generic — veth
//! supports native on modern kernels), detach, and clean up.
//!
//! This is the lightweight version of a full netns routing test — the
//! point is to exercise the aya attach/detach round-trip against a real
//! ifindex, which `bpf_prog_test_run` can't do. Full end-to-end
//! forwarding (packet in → redirect → packet out) lands in a later PR
//! with a netns harness and synthetic traffic.
//!
//! Requires CAP_NET_ADMIN + CAP_BPF; CI runs this under `sudo`.

use std::process::Command;

use packetframe_fast_path::{aligned_bpf_copy, FAST_PATH_BPF_AVAILABLE};

const PEER_A: &str = "pf-veth0";
const PEER_B: &str = "pf-veth1";

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        // `ip link del <peer>` removes the whole pair.
        let _ = Command::new("ip").args(["link", "del", PEER_A]).status();
    }
}

fn run(cmd: &[&str]) {
    let status = Command::new(cmd[0])
        .args(&cmd[1..])
        .status()
        .unwrap_or_else(|e| panic!("spawning `{}`: {e}", cmd.join(" ")));
    assert!(status.success(), "`{}` failed: {status}", cmd.join(" "));
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn attach_detach_roundtrip_on_veth() {
    if !FAST_PATH_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping attach test.");
        return;
    }

    // Clean any leftover from a prior aborted run. Idempotent.
    let _ = Command::new("ip").args(["link", "del", PEER_A]).status();

    run(&[
        "ip", "link", "add", PEER_A, "type", "veth", "peer", "name", PEER_B,
    ]);
    run(&["ip", "link", "set", PEER_A, "up"]);
    run(&["ip", "link", "set", PEER_B, "up"]);

    // Ensure cleanup even on panic.
    let _cleanup = Cleanup;

    let ifindex = {
        let c = std::ffi::CString::new(PEER_A).unwrap();
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        assert!(idx > 0, "if_nametoindex({PEER_A}) failed");
        idx
    };

    let bytes = aligned_bpf_copy();
    let mut bpf = aya::Ebpf::load(&bytes).expect("aya::Ebpf::load");
    let prog: &mut aya::programs::Xdp = bpf
        .program_mut("fast_path")
        .expect("fast_path program present")
        .try_into()
        .expect("fast_path is XDP");
    prog.load().expect("verifier");

    // Try native first; fall back to generic. veth *should* support
    // native XDP on any remotely modern kernel, but we don't gate on it.
    use aya::programs::xdp::XdpFlags;
    let link_id = prog
        .attach_to_if_index(ifindex, XdpFlags::DRV_MODE)
        .or_else(|native_err| {
            eprintln!("veth native XDP attach failed ({native_err}); trying generic");
            prog.attach_to_if_index(ifindex, XdpFlags::SKB_MODE)
        })
        .expect("attach XDP to veth");

    prog.detach(link_id).expect("detach");
}
