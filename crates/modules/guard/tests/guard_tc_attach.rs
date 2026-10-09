//! Real tc-egress attach/detach lifecycle on a veth pair. Mirror of
//! fast-path's tests/tc_attach.rs (ingress); when one is updated, the
//! other likely needs the same change.
//!
//! Covers: clsact creation + the EEXIST path (pre-existing qdisc,
//! e.g. fast-path's ingress filter on the same iface), the egress
//! filter landing where `tc filter show ... egress` can see it,
//! `guard-tc-links.json` persistence, out-of-process detach clearing
//! the filter while **leaving clsact in place**, the vanished-iface
//! teardown branch, and a renamed device found by its ifindex, by
//! detach and by health.
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

const BPFFS: &str = "/sys/fs/bpf";
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

/// Once per process, and never over a bpffs already there (it may hold
/// live pins). Mirror of flow-export's end_to_end `ensure_bpffs`.
fn ensure_bpffs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let c = std::ffi::CString::new(BPFFS).unwrap();
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        #[allow(clippy::unnecessary_cast)] // f_type's width differs across libcs
        let mounted =
            unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0 && st.f_type as i64 == BPF_FS_MAGIC;
        if !mounted {
            run(&["mount", "-t", "bpf", "bpf", BPFFS]);
        }
    });
}

/// A `GuardModule` loaded and attached to `iface` (lldp drop), through
/// the loader's own path.
fn attached_guard(
    iface: &str,
    bpffs_root: &std::path::Path,
    state_dir: &std::path::Path,
) -> packetframe_guard::GuardModule {
    use packetframe_common::config::{Config, GlobalConfig};
    use packetframe_common::module::{LoaderCtx, Module, ModuleConfig};

    let config = Config::parse(&format!(
        "module guard\n  interface {iface}\n  lldp {iface} drop\n"
    ))
    .expect("config parses");
    let global = GlobalConfig::default();
    let cfg = ModuleConfig::new(&config.modules[0], &global);
    let mut m = packetframe_guard::GuardModule::new();
    m.load(
        &cfg,
        &LoaderCtx {
            bpffs_root,
            state_dir,
        },
    )
    .expect("load");
    m.attach(&cfg).expect("attach");
    m
}

/// `iface`'s `attach:` health row: state and message.
fn health_row(
    m: &packetframe_guard::GuardModule,
    iface: &str,
) -> (packetframe_common::module::HealthState, String) {
    use packetframe_common::module::{HealthCtx, Module};
    let row = m
        .health_check(&HealthCtx::new())
        .expect("health")
        .subsystems
        .into_iter()
        .find(|s| s.name == format!("attach:{iface}"))
        .expect("one row per configured interface");
    (row.state, row.message.unwrap_or_default())
}

/// Removes the devices and the test's bpffs root, whatever the outcome.
struct HealthCleanup {
    devs: &'static [&'static str],
    bpffs_root: std::path::PathBuf,
}

impl Drop for HealthCleanup {
    fn drop(&mut self) {
        for dev in self.devs {
            let _ = Command::new("ip").args(["link", "del", dev]).status();
        }
        let _ = std::fs::remove_dir_all(&self.bpffs_root);
    }
}

/// Health finds the device by its ifindex, as detach does. Renamed, the
/// filter still enforces under the new name, so the row says that, not
/// "vanished"; nor "recreated" once another device takes the old name.
/// Then the filter deleted by hand: the row says so, not "still
/// enforces".
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn health_follows_a_renamed_device() {
    use packetframe_common::module::{HealthState, Module};

    if !packetframe_guard::GUARD_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping guard tc attach test.");
        return;
    }
    const HL_A: &str = "pf-ghl0";
    const HL_B: &str = "pf-ghl1";
    const HL_C: &str = "pf-ghl2";
    const RENAMED: &str = "pf-ghl0r";
    ensure_bpffs();
    let state_dir = state_dir("health");
    let bpffs_root =
        std::path::Path::new(BPFFS).join(format!("pf-guard-health-{}", std::process::id()));
    let _cleanup = HealthCleanup {
        devs: &[HL_A, RENAMED],
        bpffs_root: bpffs_root.clone(),
    };
    for dev in [HL_A, RENAMED] {
        let _ = Command::new("ip").args(["link", "del", dev]).status();
    }

    run(&[
        "ip", "link", "add", HL_A, "type", "veth", "peer", "name", HL_B,
    ]);
    let mut m = attached_guard(HL_A, &bpffs_root, &state_dir);
    assert_eq!(health_row(&m, HL_A), (HealthState::Healthy, String::new()));

    run(&["ip", "link", "set", HL_A, "name", RENAMED]);
    let shown = capture(&["tc", "filter", "show", "dev", RENAMED, "egress"]);
    assert!(shown.contains("guard_egress"), "still enforcing: {shown}");
    let (state, msg) = health_row(&m, HL_A);
    assert_eq!(state, HealthState::Degraded, "{msg}");
    assert!(
        msg.contains(&format!("renamed to {RENAMED}")) && msg.contains("still enforces"),
        "{msg}"
    );
    assert!(
        msg.contains(&format!("would fail to attach {HL_A}")),
        "{msg}"
    );

    run(&[
        "ip", "link", "add", HL_A, "type", "veth", "peer", "name", HL_C,
    ]);
    let (state, msg) = health_row(&m, HL_A);
    assert_eq!(state, HealthState::Degraded, "{msg}");
    assert!(msg.contains(&format!("renamed to {RENAMED}")), "{msg}");
    assert!(!msg.contains("recreated"), "{msg}");

    run(&["tc", "filter", "del", "dev", RENAMED, "egress"]);
    let (state, msg) = health_row(&m, HL_A);
    assert_eq!(state, HealthState::Degraded, "{msg}");
    assert!(
        msg.contains(&format!("no guard egress filter on {RENAMED}")),
        "{msg}"
    );
    assert!(!msg.contains("still enforces"), "{msg}");

    m.detach().expect("detach");
    let _ = std::fs::remove_dir_all(&state_dir);
}

/// The ifindex handed out again to an unrelated device (here explicitly,
/// `ip link add … index`; a netns move does the same) is not a rename:
/// the original filter died with its device. The row must not say
/// "still enforces", even with another program's egress filter on the
/// replacement, likely at the same auto-allocated (priority, handle).
#[test]
#[ignore = "needs CAP_BPF + CAP_NET_ADMIN + BPF build; run via `sudo -E cargo test -p packetframe-guard --tests -- --ignored`"]
fn health_does_not_take_a_reused_ifindex_for_a_rename() {
    use packetframe_common::module::{HealthState, Module};

    if !packetframe_guard::GUARD_BPF_AVAILABLE {
        eprintln!("BPF stub in effect (no rustup); skipping guard tc attach test.");
        return;
    }
    const RU_A: &str = "pf-ghu0";
    const RU_B: &str = "pf-ghu1";
    const REUSER: &str = "pf-ghu9";
    const REUSER_PEER: &str = "pf-ghu8";
    ensure_bpffs();
    let state_dir = state_dir("reuse");
    let bpffs_root =
        std::path::Path::new(BPFFS).join(format!("pf-guard-reuse-{}", std::process::id()));
    let _cleanup = HealthCleanup {
        devs: &[RU_A, REUSER],
        bpffs_root: bpffs_root.clone(),
    };
    for dev in [RU_A, REUSER] {
        let _ = Command::new("ip").args(["link", "del", dev]).status();
    }

    run(&[
        "ip", "link", "add", RU_A, "type", "veth", "peer", "name", RU_B,
    ]);
    let mut m = attached_guard(RU_A, &bpffs_root, &state_dir);
    let index = ifindex_of(RU_A);
    assert_eq!(health_row(&m, RU_A), (HealthState::Healthy, String::new()));

    run(&["ip", "link", "del", RU_A]);
    let index_arg = index.to_string();
    run(&[
        "ip",
        "link",
        "add",
        REUSER,
        "index",
        &index_arg,
        "type",
        "veth",
        "peer",
        "name",
        REUSER_PEER,
    ]);
    assert_eq!(
        ifindex_of(REUSER),
        index,
        "the ifindex was handed out again"
    );
    let mut other = loaded_guard();
    tc_attach_egress(&mut other, REUSER).expect("another program's filter");
    drop(other);

    let (state, msg) = health_row(&m, RU_A);
    assert_eq!(state, HealthState::Degraded, "{msg}");
    assert!(
        msg.contains(&format!(
            "no guard egress filter on {REUSER} (ifindex {index}, {RU_A} at attach)"
        )),
        "{msg}"
    );
    assert!(!msg.contains("still enforces"), "{msg}");

    // Gone before detach, so detach has nothing to find under the index.
    run(&["ip", "link", "del", REUSER]);
    m.detach().expect("detach");
    let _ = std::fs::remove_dir_all(&state_dir);
}
