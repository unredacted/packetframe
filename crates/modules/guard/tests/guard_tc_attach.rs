//! Real tc-egress attach/detach lifecycle on a veth pair. Mirror of
//! fast-path's tests/tc_attach.rs (ingress); when one is updated, the
//! other likely needs the same change.
//!
//! Covers: clsact creation + the EEXIST path (pre-existing qdisc,
//! e.g. fast-path's ingress filter on the same iface), the egress
//! filter landing where `tc filter show ... egress` can see it,
//! `guard-tc-links.json` persistence, out-of-process detach clearing
//! the filter while **leaving clsact in place**, the vanished-iface
//! teardown branch, and a renamed device found by its ifindex.
//!
//! NOT in the hardware-artifacts SAFE suite: it creates interfaces.

#![cfg(target_os = "linux")]

use std::process::Command;

use packetframe_guard::{aligned_bpf_copy, detach_from_state_dir, tc_attach_egress, tc_links};

const PEER_A: &str = "pf-gdv0";
const PEER_B: &str = "pf-gdv1";

struct Cleanup {
    state_dir: std::path::PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", PEER_A]).status();
        let _ = std::fs::remove_dir_all(&self.state_dir);
    }
}

fn run(cmd: &[&str]) {
    let status = Command::new(cmd[0])
        .args(&cmd[1..])
        .status()
        .unwrap_or_else(|e| panic!("spawn `{}`: {e}", cmd.join(" ")));
    assert!(status.success(), "`{}` exited {status}", cmd.join(" "));
}

fn capture(cmd: &[&str]) -> String {
    let out = Command::new(cmd[0])
        .args(&cmd[1..])
        .output()
        .unwrap_or_else(|e| panic!("spawn `{}`: {e}", cmd.join(" ")));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn state_dir(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("pf-guard-tc-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn ifindex_of(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .unwrap_or_else(|e| panic!("read ifindex of {iface}: {e}"))
        .trim()
        .parse()
        .expect("ifindex parses")
}

/// The ELF with `guard_egress` through the verifier, as attach loads it.
fn loaded_guard() -> aya::Ebpf {
    let mut bpf = aya::Ebpf::load(&aligned_bpf_copy()).expect("Ebpf::load");
    let prog: &mut aya::programs::tc::SchedClassifier = bpf
        .program_mut("guard_egress")
        .expect("guard_egress present")
        .try_into()
        .expect("sched_cls");
    prog.load().expect("verifier accepts guard_egress");
    bpf
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn egress_attach_persist_detach_lifecycle() {
    if !packetframe_guard::GUARD_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping guard tc attach test.");
        return;
    }
    let state_dir = state_dir("lifecycle");
    let _cleanup = Cleanup {
        state_dir: state_dir.clone(),
    };
    let _ = Command::new("ip").args(["link", "del", PEER_A]).status();
    run(&[
        "ip", "link", "add", PEER_A, "type", "veth", "peer", "name", PEER_B,
    ]);
    run(&["ip", "link", "set", PEER_A, "up"]);
    run(&["ip", "link", "set", PEER_B, "up"]);

    // Pre-create clsact on PEER_A: the attach must take the EEXIST
    // path (fast-path's ingress filter would have created it in
    // production).
    run(&["tc", "qdisc", "add", "dev", PEER_A, "clsact"]);

    let mut bpf = loaded_guard();

    let (priority, handle) = tc_attach_egress(&mut bpf, PEER_A).expect("egress attach");
    let shown = capture(&["tc", "filter", "show", "dev", PEER_A, "egress"]);
    assert!(
        shown.contains("guard_egress"),
        "egress filter not visible: {shown}"
    );
    // And nothing landed on ingress.
    let ingress = capture(&["tc", "filter", "show", "dev", PEER_A, "ingress"]);
    assert!(
        !ingress.contains("guard_egress"),
        "guard filter leaked onto ingress: {ingress}"
    );

    tc_links::save(
        &state_dir,
        &tc_links::TcLinksFile {
            links: vec![tc_links::TcLinkRecord {
                iface: PEER_A.to_string(),
                ifindex: ifindex_of(PEER_A),
                priority,
                handle,
            }],
        },
    )
    .expect("persist record");

    // The kernel attach must survive the loader: drop the Ebpf (all
    // FDs close) and tear down purely from persisted state.
    drop(bpf);
    let shown = capture(&["tc", "filter", "show", "dev", PEER_A, "egress"]);
    assert!(
        shown.contains("guard_egress"),
        "netlink cls_bpf filter must have qdisc lifetime: {shown}"
    );

    let cleared =
        detach_from_state_dir(&state_dir, &state_dir.join("bpffs")).expect("detach clean");
    assert_eq!(cleared, 1);
    let shown = capture(&["tc", "filter", "show", "dev", PEER_A, "egress"]);
    assert!(
        !shown.contains("guard_egress"),
        "filter must be gone after detach: {shown}"
    );
    // clsact stays: fast-path may share it on the same interface.
    let qdisc = capture(&["tc", "qdisc", "show", "dev", PEER_A]);
    assert!(
        qdisc.contains("clsact"),
        "detach must never delete the shared clsact qdisc: {qdisc}"
    );
    assert!(
        tc_links::load(&state_dir).unwrap().is_none(),
        "state file removed after full success"
    );
    // Idempotent: a second detach over no state is a clean no-op.
    assert_eq!(
        detach_from_state_dir(&state_dir, &state_dir.join("bpffs")).expect("idempotent"),
        0
    );
}

#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn detach_treats_vanished_iface_as_cleared() {
    if !packetframe_guard::GUARD_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping guard tc attach test.");
        return;
    }
    // No iface is created at all — the record names an ifindex no
    // device has, which is exactly the state after a device deletion
    // (qdisc-lifetime filters die with their device). Uses
    // its own state dir and iface name so it can run concurrently
    // with the lifecycle test in the same binary (cargo runs tests in
    // threads; a shared iface-deleting Drop would race).
    let state_dir = state_dir("vanished");
    tc_links::save(
        &state_dir,
        &tc_links::TcLinksFile {
            links: vec![tc_links::TcLinkRecord {
                iface: "pf-gd-gone0".to_string(),
                ifindex: 4242,
                priority: 49152,
                handle: 1,
            }],
        },
    )
    .expect("persist record");
    let cleared =
        detach_from_state_dir(&state_dir, &state_dir.join("bpffs")).expect("vanished = cleared");
    assert_eq!(cleared, 1);
    assert!(tc_links::load(&state_dir).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&state_dir);
}

/// The recreated-device scenario from the #205 review: a record whose
/// device was deleted and recreated under the same name must classify
/// as Cleared WITHOUT touching the replacement — whose own filter
/// commonly lands on the exact same auto-allocated
/// `(priority, handle)` tuple the stale record names.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn detach_spares_filters_on_a_recreated_device() {
    if !packetframe_guard::GUARD_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping guard tc attach test.");
        return;
    }
    const RE_A: &str = "pf-gdr0";
    const RE_B: &str = "pf-gdr1";
    struct ReCleanup;
    impl Drop for ReCleanup {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["link", "del", RE_A]).status();
        }
    }
    let state_dir = state_dir("recreate");
    let _cleanup = ReCleanup;
    let _ = Command::new("ip").args(["link", "del", RE_A]).status();

    // Original device: attach, record (with its ifindex), then delete
    // the device — the filter dies with it, the record goes stale.
    run(&[
        "ip", "link", "add", RE_A, "type", "veth", "peer", "name", RE_B,
    ]);
    let mut bpf = loaded_guard();
    let (priority, handle) = tc_attach_egress(&mut bpf, RE_A).expect("first attach");
    tc_links::save(
        &state_dir,
        &tc_links::TcLinksFile {
            links: vec![tc_links::TcLinkRecord {
                iface: RE_A.to_string(),
                ifindex: ifindex_of(RE_A),
                priority,
                handle,
            }],
        },
    )
    .expect("persist stale-to-be record");
    run(&["ip", "link", "del", RE_A]);

    // Recreate the same name (new ifindex) and give the REPLACEMENT
    // its own guard filter — auto-allocation typically hands back the
    // same (priority, handle) tuple, the collision the ifindex check
    // exists for.
    run(&[
        "ip", "link", "add", RE_A, "type", "veth", "peer", "name", RE_B,
    ]);
    let mut bpf2 = loaded_guard();
    let (p2, h2) = tc_attach_egress(&mut bpf2, RE_A).expect("attach on replacement");
    drop(bpf2);

    // Detach from the STALE record: Cleared (the old filter died with
    // its device), and the replacement's filter survives untouched —
    // even when the tuples collide.
    let cleared =
        detach_from_state_dir(&state_dir, &state_dir.join("bpffs")).expect("recreated = cleared");
    assert_eq!(cleared, 1);
    let shown = capture(&["tc", "filter", "show", "dev", RE_A, "egress"]);
    assert!(
        shown.contains("guard_egress"),
        "the replacement device's filter (prio {p2}, handle {h2}) must survive a \
         stale-record detach: {shown}"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
}

/// A device renamed since attach still holds its filter, under the new
/// name: detach finds it by the recorded ifindex and takes it down,
/// rather than dropping the record of a filter still running. A device
/// made under the OLD name meanwhile, with a filter of its own (likely
/// on the same auto-allocated tuple), is never touched.
/// Mirror of fast-path's `tc_detach_follows_a_renamed_device`.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn detach_follows_a_renamed_device() {
    if !packetframe_guard::GUARD_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping guard tc attach test.");
        return;
    }
    const RN_A: &str = "pf-gdn0";
    const RN_B: &str = "pf-gdn1";
    const RN_C: &str = "pf-gdn2";
    const RENAMED: &str = "pf-gdn0r";
    struct RnCleanup;
    impl Drop for RnCleanup {
        fn drop(&mut self) {
            for dev in [RN_A, RENAMED] {
                let _ = Command::new("ip").args(["link", "del", dev]).status();
            }
        }
    }
    let state_dir = state_dir("rename");
    let _cleanup = RnCleanup;
    for dev in [RN_A, RENAMED] {
        let _ = Command::new("ip").args(["link", "del", dev]).status();
    }

    run(&[
        "ip", "link", "add", RN_A, "type", "veth", "peer", "name", RN_B,
    ]);
    let mut bpf = loaded_guard();
    let (priority, handle) = tc_attach_egress(&mut bpf, RN_A).expect("attach");
    tc_links::save(
        &state_dir,
        &tc_links::TcLinksFile {
            links: vec![tc_links::TcLinkRecord {
                iface: RN_A.to_string(),
                ifindex: ifindex_of(RN_A),
                priority,
                handle,
            }],
        },
    )
    .expect("persist record");
    drop(bpf);

    // A fresh veth is down, so it can take a new name; the filter moves
    // with the device.
    run(&["ip", "link", "set", RN_A, "name", RENAMED]);
    let shown = capture(&["tc", "filter", "show", "dev", RENAMED, "egress"]);
    assert!(
        shown.contains("guard_egress"),
        "the filter must stay on the renamed device: {shown}"
    );
    run(&[
        "ip", "link", "add", RN_A, "type", "veth", "peer", "name", RN_C,
    ]);
    let mut bpf2 = loaded_guard();
    let (p2, h2) = tc_attach_egress(&mut bpf2, RN_A).expect("attach on the new device");
    drop(bpf2);

    let cleared =
        detach_from_state_dir(&state_dir, &state_dir.join("bpffs")).expect("renamed = detached");
    assert_eq!(cleared, 1);
    let shown = capture(&["tc", "filter", "show", "dev", RENAMED, "egress"]);
    assert!(
        !shown.contains("guard_egress"),
        "the renamed device's filter must be taken down: {shown}"
    );
    let shown = capture(&["tc", "filter", "show", "dev", RN_A, "egress"]);
    assert!(
        shown.contains("guard_egress"),
        "the new {RN_A}'s filter (prio {p2}, handle {h2}) must survive: {shown}"
    );
    assert!(tc_links::load(&state_dir).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&state_dir);
}

/// A recorded ifindex now held by another device under another name,
/// with a filter of its own in the recorded slot (classic BPF, which
/// carries no program name): not ours, so detach leaves it and drops
/// the record. `ip link add … index` hands the old index on, as a
/// device moved into the namespace keeps its own when it is free.
/// Mirror of fast-path's `tc_detach_spares_a_device_given_a_recorded_ifindex`.
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn detach_spares_a_device_given_a_recorded_ifindex() {
    if !packetframe_guard::GUARD_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping guard tc attach test.");
        return;
    }
    const RI_A: &str = "pf-gdi0";
    const RI_B: &str = "pf-gdi1";
    const OTHER_A: &str = "pf-gdx0";
    const OTHER_B: &str = "pf-gdx1";
    struct RiCleanup;
    impl Drop for RiCleanup {
        fn drop(&mut self) {
            for dev in [RI_A, OTHER_A] {
                let _ = Command::new("ip").args(["link", "del", dev]).status();
            }
        }
    }
    let state_dir = state_dir("reindex");
    let _cleanup = RiCleanup;
    for dev in [RI_A, OTHER_A] {
        let _ = Command::new("ip").args(["link", "del", dev]).status();
    }

    run(&[
        "ip", "link", "add", RI_A, "type", "veth", "peer", "name", RI_B,
    ]);
    let ifindex = ifindex_of(RI_A);
    let mut bpf = loaded_guard();
    let (priority, handle) = tc_attach_egress(&mut bpf, RI_A).expect("attach");
    tc_links::save(
        &state_dir,
        &tc_links::TcLinksFile {
            links: vec![tc_links::TcLinkRecord {
                iface: RI_A.to_string(),
                ifindex,
                priority,
                handle,
            }],
        },
    )
    .expect("persist record");
    drop(bpf);
    run(&["ip", "link", "del", RI_A]);

    let index = ifindex.to_string();
    run(&[
        "ip", "link", "add", OTHER_A, "index", &index, "type", "veth", "peer", "name", OTHER_B,
    ]);
    assert_eq!(ifindex_of(OTHER_A), ifindex);
    run(&["tc", "qdisc", "add", "dev", OTHER_A, "clsact"]);
    run(&[
        "tc",
        "filter",
        "add",
        "dev",
        OTHER_A,
        "egress",
        "pref",
        &priority.to_string(),
        "handle",
        &handle.to_string(),
        "bpf",
        "bytecode",
        "1,6 0 0 0,",
    ]);
    let shown = capture(&["tc", "filter", "show", "dev", OTHER_A, "egress"]);
    assert!(shown.contains("bpf"), "{shown}");

    let cleared =
        detach_from_state_dir(&state_dir, &state_dir.join("bpffs")).expect("not ours = cleared");
    assert_eq!(cleared, 1);
    let shown = capture(&["tc", "filter", "show", "dev", OTHER_A, "egress"]);
    assert!(
        shown.contains("bpf"),
        "the filter in {OTHER_A}'s (prio {priority}, handle {handle}) is not ours and must \
         survive: {shown}"
    );
    assert!(tc_links::load(&state_dir).unwrap().is_none());
    let _ = std::fs::remove_dir_all(&state_dir);
}
