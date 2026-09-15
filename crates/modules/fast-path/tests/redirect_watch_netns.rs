//! `RedirectTargetWatcher` against a real kernel: links created and
//! deleted inside a netns must appear in and vanish from the pinned
//! `REDIRECT_DEVMAP` / `TC_REDIRECT_TARGETS` without a SIGHUP.
//!
//! Needs CAP_NET_ADMIN + CAP_SYS_ADMIN (netns) and CAP_BPF + bpffs
//! (pins); runs in the qemu-verifier job via `--ignored`.
//!
//! Only the event-driven path is exercised here. The watcher's start-up
//! reconcile reads `/sys/class/net`, which is not remounted per-netns
//! and so shows the host's links from inside the namespace; that path
//! is the same code the SIGHUP reconcile has always run and is covered
//! there.

#![cfg(target_os = "linux")]

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use aya::maps::{xdp::DevMapHash, HashMap as AyaHashMap, Map, MapData};
use aya::Ebpf;
use packetframe_fast_path::aligned_bpf_copy;
use packetframe_fast_path::pin;
use packetframe_fast_path::redirect_watch::RedirectTargetWatcher;

const BPFFS_ROOT: &str = "/sys/fs/bpf";

fn run(cmd: &[&str]) {
    let status = Command::new(cmd[0])
        .args(&cmd[1..])
        .status()
        .unwrap_or_else(|e| panic!("spawn `{}`: {e}", cmd.join(" ")));
    assert!(status.success(), "`{}` exited {status}", cmd.join(" "));
}

fn ns_run(netns: &str, cmd: &[&str]) {
    let mut args = vec!["netns", "exec", netns];
    args.extend_from_slice(cmd);
    let status = Command::new("ip")
        .args(&args)
        .status()
        .unwrap_or_else(|e| panic!("spawn `ip {}`: {e}", args.join(" ")));
    assert!(status.success(), "`ip {}` exited {status}", args.join(" "));
}

fn enter_netns(netns: &str) -> OwnedFd {
    let path = format!("/var/run/netns/{netns}");
    let fd: OwnedFd = File::open(&path)
        .unwrap_or_else(|e| panic!("open {path}: {e}"))
        .into();
    let rc = unsafe { libc::setns(fd.as_raw_fd(), libc::CLONE_NEWNET) };
    assert_eq!(rc, 0, "setns({path}): {}", std::io::Error::last_os_error());
    fd
}

fn if_nametoindex(name: &str) -> u32 {
    let c = CString::new(name).expect("iface name with NUL");
    let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
    assert!(idx > 0, "if_nametoindex({name}) failed");
    idx
}

struct NetnsGuard(String);

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["netns", "del", &self.0]).status();
    }
}

/// A bpffs root laid out the way production pins are
/// (`<root>/fast-path/maps/<NAME>`), so the watcher's `pin::map_path`
/// lookups find the two maps. Removed on drop.
struct Pins {
    root: PathBuf,
    _ebpf: Ebpf,
}

impl Pins {
    fn setup() -> Self {
        let root = PathBuf::from(BPFFS_ROOT).join(format!("pfrw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(pin::maps_dir(&root)).expect("mkdir pin dirs");
        let bytes = aligned_bpf_copy();
        let ebpf = Ebpf::load(&bytes).expect("Ebpf::load");
        for name in ["REDIRECT_DEVMAP", "TC_REDIRECT_TARGETS"] {
            let path = pin::map_path(&root, name);
            ebpf.map(name)
                .unwrap_or_else(|| panic!("{name} map missing from ELF"))
                .pin(&path)
                .unwrap_or_else(|e| panic!("pin {name} at {}: {e}", path.display()));
        }
        Self { root, _ebpf: ebpf }
    }

    fn devmap_keys(&self) -> HashSet<u32> {
        let dm = MapData::from_pin(pin::map_path(&self.root, "REDIRECT_DEVMAP")).expect("pin");
        let devmap: DevMapHash<MapData> =
            DevMapHash::try_from(Map::DevMapHash(dm)).expect("devmap");
        devmap.keys().filter_map(Result::ok).collect()
    }

    fn tc_keys(&self) -> HashSet<u32> {
        let tm = MapData::from_pin(pin::map_path(&self.root, "TC_REDIRECT_TARGETS")).expect("pin");
        let tc: AyaHashMap<MapData, u32, u32> = AyaHashMap::try_from(Map::HashMap(tm)).expect("tc");
        tc.keys().filter_map(Result::ok).collect()
    }
}

impl Drop for Pins {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Poll `pred` on both maps until it holds or `deadline` passes.
fn wait_for(pins: &Pins, what: &str, deadline: Duration, pred: impl Fn(&HashSet<u32>) -> bool) {
    let start = Instant::now();
    loop {
        let dev = pins.devmap_keys();
        let tc = pins.tc_keys();
        if pred(&dev) && pred(&tc) {
            return;
        }
        assert!(
            start.elapsed() < deadline,
            "{what}: not satisfied within {deadline:?}; devmap={dev:?} tc={tc:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn bpffs_present(root: &Path) -> bool {
    root.exists()
}

#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN + CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn links_created_and_deleted_at_runtime_track_into_the_redirect_maps() {
    if !bpffs_present(Path::new(BPFFS_ROOT)) {
        run(&["mount", "-t", "bpf", "bpf", BPFFS_ROOT]);
    }
    let netns = format!("pfrw{}", std::process::id() % 10000);
    let _ = Command::new("ip").args(["netns", "del", &netns]).status();
    run(&["ip", "netns", "add", &netns]);
    let _guard = NetnsGuard(netns.clone());

    // The watcher spawns its thread from this one, and a new thread
    // inherits the creator's namespaces — so enter the netns first and
    // everything below (pins, netlink subscription, events) is scoped
    // to it.
    let _ns_fd = enter_netns(&netns);
    let pins = Pins::setup();
    let watcher = RedirectTargetWatcher::start(&pins.root).expect("watcher start");

    // Give the subscription a moment to come up; an event before it
    // is live would be a test race, not a product bug.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        !pins.devmap_keys().contains(&1),
        "loopback (ARPHRD_LOOPBACK) must never be a redirect target"
    );

    // A veth pair created down, then brought up. Each end reports
    // `lowerlayerdown` until its peer is up too, so it is the NEWLINK
    // carrying oper-up after the second `set up` that admits both.
    let a = format!("pfrwa{}", std::process::id() % 10000);
    let b = format!("pfrwb{}", std::process::id() % 10000);
    ns_run(
        &netns,
        &["ip", "link", "add", &a, "type", "veth", "peer", "name", &b],
    );
    ns_run(&netns, &["ip", "link", "set", &a, "up"]);
    ns_run(&netns, &["ip", "link", "set", &b, "up"]);
    let (ia, ib) = (if_nametoindex(&a), if_nametoindex(&b));
    wait_for(&pins, "new veths admitted", Duration::from_secs(5), |k| {
        k.contains(&ia) && k.contains(&ib)
    });

    // Deleting one end deletes the pair; both ifindexes must leave
    // both maps.
    ns_run(&netns, &["ip", "link", "del", &a]);
    wait_for(&pins, "deleted veths purged", Duration::from_secs(5), |k| {
        !k.contains(&ia) && !k.contains(&ib)
    });

    watcher.shutdown();
}
