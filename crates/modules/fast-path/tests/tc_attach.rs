// aya is Linux-only.
#![cfg(target_os = "linux")]

//! Integration test for the tc-datapath attach lifecycle (Phase T,
//! T3): load the shared ELF, create a veth pair, attach `tc_fast_path`
//! to one end via the production helper (`tc_attach_iface`: clsact +
//! netlink cls_bpf, link forgotten), persist the record, then prove
//! the two properties the design depends on:
//!
//! 1. **The filter outlives the attaching context.** The aya link was
//!    forgotten, so nothing in-process holds it; `tc filter show`
//!    still lists the bpf filter afterwards.
//! 2. **Out-of-process teardown works from the persisted record.**
//!    `tc_detach_from_state_dir` reconstructs the filter purely from
//!    tc-links.json `(iface, ifindex, priority, handle)` and detaches
//!    it.
//!
//! Mirror of guard's tests/guard_tc_attach.rs (egress); when one is
//! updated, the other likely needs the same change.
//!
//! Full end-to-end tc forwarding (packet in → bpf_redirect → packet
//! out the peer) needs a netns + AF_PACKET harness like netns.rs and
//! is tracked as Phase T follow-up work.
//!
//! Requires CAP_NET_ADMIN + CAP_BPF; CI runs this under `sudo`.

use std::process::Command;

use packetframe_fast_path::{
    aligned_bpf_copy, tc_attach_iface, tc_detach_from_state_dir, tc_links, FAST_PATH_BPF_AVAILABLE,
};

const PEER_A: &str = "pf-tcv0";
const PEER_B: &str = "pf-tcv1";

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
        .unwrap_or_else(|e| panic!("spawning `{}`: {e}", cmd.join(" ")));
    assert!(status.success(), "`{}` failed: {status}", cmd.join(" "));
}

fn ifindex_of(iface: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .unwrap_or_else(|e| panic!("read ifindex of {iface}: {e}"))
        .trim()
        .parse()
        .expect("ifindex parses")
}

fn tc_filter_listing(iface: &str) -> String {
    let out = Command::new("tc")
        .args(["filter", "show", "dev", iface, "ingress"])
        .output()
        .expect("spawn tc");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn tc_attach_persists_and_detaches_from_state_dir() {
    if !FAST_PATH_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping tc attach test.");
        return;
    }

    // Clean any leftover from a prior aborted run. Idempotent.
    let _ = Command::new("ip").args(["link", "del", PEER_A]).status();

    run(&[
        "ip", "link", "add", PEER_A, "type", "veth", "peer", "name", PEER_B,
    ]);
    run(&["ip", "link", "set", PEER_A, "up"]);
    run(&["ip", "link", "set", PEER_B, "up"]);

    let state_dir = std::env::temp_dir().join(format!("pf-tc-attach-test-{}", std::process::id()));
    let _cleanup = Cleanup {
        state_dir: state_dir.clone(),
    };

    // Load the ELF and the classifier pair the same way attach() does:
    // tc_finalize first (its FD feeds the tail-call table).
    let bytes = aligned_bpf_copy();
    let mut bpf = aya::Ebpf::load(&bytes).expect("aya::Ebpf::load");
    for name in ["tc_finalize", "tc_fast_path"] {
        let prog: &mut aya::programs::tc::SchedClassifier = bpf
            .program_mut(name)
            .unwrap_or_else(|| panic!("{name} present"))
            .try_into()
            .unwrap_or_else(|_| panic!("{name} is sched_cls"));
        prog.load().expect("verifier accepts classifier");
    }

    // Production attach helper: clsact (tolerating pre-existing) +
    // netlink cls_bpf + forget, returning kernel-assigned identifiers.
    let (priority, handle) = tc_attach_iface(&mut bpf, PEER_A).expect("tc attach");
    assert!(priority > 0, "kernel-assigned priority expected");

    // Persist the record exactly as attach() does.
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
    .expect("tc-links.json save");

    // Property 1: the filter is live and held by nothing in-process
    // (the aya link was forgotten inside tc_attach_iface). Dropping
    // the whole Ebpf object must NOT detach it either: the cls_bpf
    // filter holds its own program reference.
    let listing = tc_filter_listing(PEER_A);
    assert!(
        listing.contains("bpf"),
        "expected a bpf filter on {PEER_A} ingress, got:\n{listing}"
    );
    drop(bpf);
    let listing = tc_filter_listing(PEER_A);
    assert!(
        listing.contains("bpf"),
        "filter must survive Ebpf drop (qdisc lifetime), got:\n{listing}"
    );

    // Property 2: out-of-process-style teardown from the persisted
    // record alone.
    let n = tc_detach_from_state_dir(&state_dir).expect("teardown from state dir");
    assert_eq!(n, 1, "one recorded filter should have been detached");
    let listing = tc_filter_listing(PEER_A);
    assert!(
        !listing.contains("bpf"),
        "filter should be gone after detach, got:\n{listing}"
    );
    // Record file removed; a second teardown is a clean no-op.
    assert!(tc_links::load(&state_dir).expect("load").is_none());
    assert_eq!(tc_detach_from_state_dir(&state_dir).expect("idempotent"), 0);
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn tc_detach_clears_records_for_vanished_ifaces() {
    // A recorded filter whose iface no longer exists died with the
    // device (qdisc lifetime): teardown must classify it as cleared —
    // dropping the record and removing the file — rather than either
    // erroring out or, worse, retaining a dead record forever. The
    // opposite case (detach FAILS with the iface alive) retains the
    // record; that branch needs an induced netlink failure and is
    // covered by review-level reasoning rather than a fixture.
    //
    // State-dir-only guard, NOT the shared `Cleanup`: that one also
    // deletes PEER_A, and cargo runs tests in parallel — this test
    // finishing first would yank the veth out from under
    // `tc_attach_persists_and_detaches_from_state_dir` mid-setup.
    struct DirCleanup(std::path::PathBuf);
    impl Drop for DirCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let state_dir =
        std::env::temp_dir().join(format!("pf-tc-vanished-test-{}", std::process::id()));
    let _cleanup = DirCleanup(state_dir.clone());

    tc_links::save(
        &state_dir,
        &tc_links::TcLinksFile {
            links: vec![tc_links::TcLinkRecord {
                iface: "pf-gone0".to_string(), // never created
                ifindex: 4242,
                priority: 49152,
                handle: 1,
            }],
        },
    )
    .expect("tc-links.json save");

    let n = tc_detach_from_state_dir(&state_dir).expect("vanished iface must not error");
    assert_eq!(n, 1, "vanished-iface record counts as cleared");
    assert!(
        tc_links::load(&state_dir).expect("load").is_none(),
        "file must be removed once every record is cleared"
    );
}

/// The recreated-device scenario from the guard #205 review, which
/// fast-path shared: a record whose device was deleted and recreated
/// under the same name must classify as Cleared WITHOUT touching the
/// replacement — whose own filter commonly lands on the exact same
/// auto-allocated `(priority, handle)` tuple the stale record names.
/// Mirror of guard's `detach_spares_filters_on_a_recreated_device`.
#[test]
#[ignore = "needs CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test ... -- --ignored`"]
fn tc_detach_spares_filters_on_a_recreated_device() {
    if !FAST_PATH_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping tc attach test.");
        return;
    }
    const RE_A: &str = "pf-tcr0";
    const RE_B: &str = "pf-tcr1";
    // Own iface pair + state dir so this can run concurrently with the
    // lifecycle test in the same binary (see DirCleanup note above).
    struct ReCleanup(std::path::PathBuf);
    impl Drop for ReCleanup {
        fn drop(&mut self) {
            let _ = Command::new("ip").args(["link", "del", RE_A]).status();
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let state_dir =
        std::env::temp_dir().join(format!("pf-tc-recreate-test-{}", std::process::id()));
    let _cleanup = ReCleanup(state_dir.clone());
    let _ = Command::new("ip").args(["link", "del", RE_A]).status();

    let load_classifiers = |bpf: &mut aya::Ebpf| {
        for name in ["tc_finalize", "tc_fast_path"] {
            let prog: &mut aya::programs::tc::SchedClassifier = bpf
                .program_mut(name)
                .unwrap_or_else(|| panic!("{name} present"))
                .try_into()
                .unwrap_or_else(|_| panic!("{name} is sched_cls"));
            prog.load().expect("verifier accepts classifier");
        }
    };

    // Original device: attach, record (with its ifindex), then delete
    // the device — the filter dies with it, the record goes stale.
    run(&[
        "ip", "link", "add", RE_A, "type", "veth", "peer", "name", RE_B,
    ]);
    let bytes = aligned_bpf_copy();
    let mut bpf = aya::Ebpf::load(&bytes).expect("aya::Ebpf::load");
    load_classifiers(&mut bpf);
    let (priority, handle) = tc_attach_iface(&mut bpf, RE_A).expect("first attach");
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
    // its own filter — auto-allocation typically hands back the same
    // (priority, handle) tuple, the collision the ifindex check
    // exists for.
    run(&[
        "ip", "link", "add", RE_A, "type", "veth", "peer", "name", RE_B,
    ]);
    let mut bpf2 = aya::Ebpf::load(&bytes).expect("aya::Ebpf::load 2");
    load_classifiers(&mut bpf2);
    let (p2, h2) = tc_attach_iface(&mut bpf2, RE_A).expect("attach on replacement");
    drop(bpf2);

    // Detach from the STALE record: Cleared (the old filter died with
    // its device), and the replacement's filter survives untouched —
    // even when the tuples collide.
    let cleared = tc_detach_from_state_dir(&state_dir).expect("recreated = cleared");
    assert_eq!(cleared, 1);
    let listing = tc_filter_listing(RE_A);
    assert!(
        listing.contains("bpf"),
        "the replacement device's filter (prio {p2}, handle {h2}) must survive a \
         stale-record detach, got:\n{listing}"
    );
}
