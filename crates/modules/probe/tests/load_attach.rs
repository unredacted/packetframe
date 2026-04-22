// aya + veth via `ip link` are Linux-only.
#![cfg(target_os = "linux")]

//! Integration test: load the probe BPF ELF, create a veth pair,
//! attach the probe XDP program, detach, and clean up. Mirrors
//! `packetframe-fast-path/tests/attach.rs` — we're testing that the
//! ELF has a valid program named `probe` + a ringbuf map named
//! `EVENTS`, that aya accepts it, the verifier accepts it, and the
//! kernel accepts the XDP attach.
//!
//! Does NOT inject packets or drain the ringbuf — the probe's
//! ringbuf consumer is exercised by operators against real interfaces
//! (SPEC §11.1(c)). Extending this test with packet injection would
//! largely duplicate `fast-path/tests/netns.rs`'s AF_PACKET scaffolding
//! for thin incremental coverage; v0.2 can factor a shared helper if
//! warranted.

use std::process::Command;

use aya::{
    maps::RingBuf,
    programs::{xdp::XdpFlags, Xdp},
    Ebpf,
};
use packetframe_probe::{aligned_bpf_copy, PROBE_BPF_AVAILABLE};

const PEER_A: &str = "pf-probe-a";
const PEER_B: &str = "pf-probe-b";

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
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
fn load_attach_detach_roundtrip_on_veth() {
    if !PROBE_BPF_AVAILABLE {
        eprintln!("probe BPF stub in effect; skipping probe attach test.");
        return;
    }

    // Idempotent pre-cleanup.
    let _ = Command::new("ip").args(["link", "del", PEER_A]).status();

    run(&[
        "ip", "link", "add", PEER_A, "type", "veth", "peer", "name", PEER_B,
    ]);
    run(&["ip", "link", "set", PEER_A, "up"]);
    run(&["ip", "link", "set", PEER_B, "up"]);
    let _cleanup = Cleanup;

    let ifindex = {
        let c = std::ffi::CString::new(PEER_A).unwrap();
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        assert!(idx > 0, "if_nametoindex({PEER_A}) failed");
        idx
    };

    // Use the aligned copy, same as production — passing the raw
    // `PROBE_BPF` static trips aya's ELF header alignment check on
    // unlucky placements (see v0.1.1 regression).
    let bytes = aligned_bpf_copy();
    let mut bpf = Ebpf::load(&bytes).expect("aya::Ebpf::load probe");

    // EVENTS map must be present and typed as a ring buffer. This
    // catches the common mis-declaration where a map ends up in the
    // wrong ELF section and userspace can't find it by name.
    {
        let map = bpf.map_mut("EVENTS").expect("EVENTS map present in ELF");
        let _ring: RingBuf<_> = RingBuf::try_from(map).expect("EVENTS is a ring buffer");
    }

    let prog: &mut Xdp = bpf
        .program_mut("probe")
        .expect("probe program present")
        .try_into()
        .expect("probe is XDP-typed");
    prog.load().expect("verifier accepts probe");

    let link_id = prog
        .attach_to_if_index(ifindex, XdpFlags::DRV_MODE)
        .or_else(|native_err| {
            eprintln!("veth native XDP attach failed ({native_err}); trying generic");
            prog.attach_to_if_index(ifindex, XdpFlags::SKB_MODE)
        })
        .expect("attach probe XDP to veth");

    prog.detach(link_id).expect("detach probe");
}
