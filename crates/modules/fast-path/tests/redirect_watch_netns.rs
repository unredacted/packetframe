//! `RedirectTargetWatcher` against a real kernel: links created and
//! deleted inside a netns must appear in and vanish from the pinned
//! `REDIRECT_DEVMAP` / `TC_REDIRECT_TARGETS` without a SIGHUP, and a
//! VLAN sub-interface must get its `VLAN_RESOLVE` translation (and the
//! `VLAN_PRESENT` gate) along with its admission.
//!
//! A second test follows `RX_MACS` through a port MAC change and a
//! bridge enslavement, in the host namespace (see its doc for why). The
//! rest shrink the subscription's buffer and stall its reader
//! (`stall_reader`) so a burst of link changes overruns it every time,
//! and check the re-read that makes the lost notifications good; or
//! bring up more links than the maps hold, and check that the ones left
//! out are reported as such and admitted once room is made.
//!
//! Needs CAP_NET_ADMIN + CAP_SYS_ADMIN (netns) and CAP_BPF + bpffs
//! (pins); runs in the qemu-verifier job via `--ignored`.
//!
//! Only the event-driven path is exercised here. The watcher's start-up
//! reconcile reads `/sys/class/net`, which is not remounted per-netns
//! and so shows the host's links from inside the namespace; that path
//! is the same code the SIGHUP reconcile has always run and is covered
//! there. The VLAN table, by contrast, is read through
//! `/proc/thread-self/net`, which follows the watcher thread into the
//! namespace (`/proc/net` would follow the harness's leader thread and
//! stay in the host's — the first CI run of this test proved it).

#![cfg(target_os = "linux")]

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use aya::maps::{xdp::DevMapHash, Array, HashMap as AyaHashMap, Map, MapData};
use aya::Ebpf;
use packetframe_common::module::HealthState;
use packetframe_fast_path::aligned_bpf_copy;
use packetframe_fast_path::linux_impl::{FpCfg, RxMacKey, VlanResolve, FP_CFG_FLAG_VLAN_PRESENT};
use packetframe_fast_path::pin;
use packetframe_fast_path::redirect_watch::{RedirectTargetWatcher, WatchStatus};

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
    fn setup(tag: &str) -> Self {
        let root = PathBuf::from(BPFFS_ROOT).join(format!("pfrw{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(pin::maps_dir(&root)).expect("mkdir pin dirs");
        let bytes = aligned_bpf_copy();
        let ebpf = Ebpf::load(&bytes).expect("Ebpf::load");
        // Only what production pins: pinning a map here that attach
        // never pins is how this test passed while the watcher could not
        // open in production.
        for name in pin::REDIRECT_WATCH_MAPS {
            assert!(
                pin::MAP_NAMES.contains(&name),
                "{name} is opened by the watcher but not pinned by attach"
            );
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

    /// `VLAN_RESOLVE` as `subif_idx → (phys_idx, vid)`.
    fn vlan_entries(&self) -> HashMap<u32, (u32, u16)> {
        let vm = MapData::from_pin(pin::map_path(&self.root, "VLAN_RESOLVE")).expect("pin");
        let vlan: AyaHashMap<MapData, u32, VlanResolve> =
            AyaHashMap::try_from(Map::HashMap(vm)).expect("vlan");
        vlan.iter()
            .filter_map(Result::ok)
            .map(|(k, v)| (k, (v.phys_ifindex, v.vid)))
            .collect()
    }

    /// `RX_MACS` as `(ifindex, mac)` pairs.
    fn rx_macs(&self) -> HashSet<(u32, [u8; 6])> {
        let rm = MapData::from_pin(pin::map_path(&self.root, "RX_MACS")).expect("pin");
        let rx: AyaHashMap<MapData, RxMacKey, u8> =
            AyaHashMap::try_from(Map::HashMap(rm)).expect("rx");
        rx.keys()
            .filter_map(Result::ok)
            .map(|k| (k.ifindex, k.mac))
            .collect()
    }

    fn vlan_present_gate(&self) -> bool {
        let cm = MapData::from_pin(pin::map_path(&self.root, "CFG")).expect("pin");
        let cfg: Array<MapData, FpCfg> = Array::try_from(Map::Array(cm)).expect("cfg");
        cfg.get(&0, 0).expect("CFG[0]").flags & FP_CFG_FLAG_VLAN_PRESENT != 0
    }
}

impl Drop for Pins {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Poll `pred` until it holds or `deadline` passes; on failure print
/// every map so the assertion message says what the watcher did.
fn poll(pins: &Pins, what: &str, deadline: Duration, pred: impl Fn() -> bool) {
    let start = Instant::now();
    loop {
        if pred() {
            return;
        }
        assert!(
            start.elapsed() < deadline,
            "{what}: not satisfied within {deadline:?}; devmap={:?} tc={:?} vlan={:?} gate={} \
             rx_macs={:?}",
            pins.devmap_keys(),
            pins.tc_keys(),
            pins.vlan_entries(),
            pins.vlan_present_gate(),
            pins.rx_macs()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Both redirect maps satisfy `pred`.
fn wait_for(pins: &Pins, what: &str, deadline: Duration, pred: impl Fn(&HashSet<u32>) -> bool) {
    poll(pins, what, deadline, || {
        pred(&pins.devmap_keys()) && pred(&pins.tc_keys())
    });
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
    let pins = Pins::setup("");
    let watcher =
        RedirectTargetWatcher::start(&pins.root, Vec::new(), Vec::new()).expect("watcher start");

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

    // A VLAN sub-interface on top of one end: its translation to
    // (parent, vid) must be in VLAN_RESOLVE with the gate bit set, and
    // the sub-interface itself admitted — this is the recreated
    // `switch0.N` case that motivated the watcher.
    let sub = format!("{a}.100");
    ns_run(
        &netns,
        &[
            "ip", "link", "add", "link", &a, "name", &sub, "type", "vlan", "id", "100",
        ],
    );
    ns_run(&netns, &["ip", "link", "set", &sub, "up"]);
    let isub = if_nametoindex(&sub);
    poll(
        &pins,
        "vlan subif translated and admitted",
        Duration::from_secs(5),
        || {
            pins.vlan_entries().get(&isub) == Some(&(ia, 100))
                && pins.vlan_present_gate()
                && pins.devmap_keys().contains(&isub)
                && pins.tc_keys().contains(&isub)
        },
    );

    // Deleting one end deletes the pair and the sub-interface riding
    // on it; every ifindex must leave both redirect maps and the
    // translation must go with them.
    ns_run(&netns, &["ip", "link", "del", &a]);
    wait_for(&pins, "deleted veths purged", Duration::from_secs(5), |k| {
        !k.contains(&ia) && !k.contains(&ib) && !k.contains(&isub)
    });
    poll(
        &pins,
        "vlan translation purged",
        Duration::from_secs(5),
        || !pins.vlan_entries().contains_key(&isub),
    );

    watcher.shutdown();
}

/// Deletes the named links on drop.
struct LinksGuard(Vec<String>);

impl Drop for LinksGuard {
    fn drop(&mut self) {
        for l in &self.0 {
            let _ = Command::new("ip").args(["link", "del", l]).status();
        }
    }
}

/// `RX_MACS` follows the attached port's receive MACs at runtime: filled
/// at watcher start, then moved by the `RTM_NEWLINK` a MAC change or a
/// bridge enslavement emits — the port's own MAC while it is plain, its
/// bridge's once it is a member.
///
/// Runs in the HOST namespace (of the qemu VM), unlike the test above:
/// `receive_macs` reads `/sys/class/net`, which is not remounted
/// per-netns, so only in the namespace sysfs was mounted in do the
/// netlink events and the sysfs reads describe the same links. The two
/// links it creates are removed on drop; the pins are its own.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn rx_macs_follow_a_port_mac_change_and_its_bridge() {
    if !bpffs_present(Path::new(BPFFS_ROOT)) {
        run(&["mount", "-t", "bpf", "bpf", BPFFS_ROOT]);
    }
    let port = format!("pfrxd{}", std::process::id() % 10000);
    let bridge = format!("pfrxb{}", std::process::id() % 10000);
    let _ = Command::new("ip").args(["link", "del", &port]).status();
    let _ = Command::new("ip").args(["link", "del", &bridge]).status();
    let _links = LinksGuard(vec![port.clone(), bridge.clone()]);
    const FIRST: [u8; 6] = [0x02, 0, 0, 0, 0x5a, 0x01];
    const SECOND: [u8; 6] = [0x02, 0, 0, 0, 0x5a, 0x02];
    const BRIDGE: [u8; 6] = [0x02, 0, 0, 0, 0x5a, 0xb0];
    run(&[
        "ip",
        "link",
        "add",
        &port,
        "address",
        "02:00:00:00:5a:01",
        "type",
        "dummy",
    ]);
    run(&["ip", "link", "set", &port, "up"]);
    let ifindex = if_nametoindex(&port);

    let pins = Pins::setup("rx");
    assert!(
        pins.rx_macs().is_empty(),
        "precondition: RX_MACS starts empty"
    );
    let watcher =
        RedirectTargetWatcher::start(&pins.root, Vec::new(), vec![(port.clone(), ifindex)])
            .expect("watcher start");
    let p = &pins;
    let rx_is = |want: [u8; 6]| move || p.rx_macs() == HashSet::from([(ifindex, want)]);

    poll(
        &pins,
        "filled at watcher start",
        Duration::from_secs(5),
        rx_is(FIRST),
    );

    run(&[
        "ip",
        "link",
        "set",
        "dev",
        &port,
        "address",
        "02:00:00:00:5a:02",
    ]);
    poll(
        &pins,
        "a plain port's MAC change replaces its entry",
        Duration::from_secs(5),
        rx_is(SECOND),
    );

    run(&[
        "ip",
        "link",
        "add",
        &bridge,
        "address",
        "02:00:00:00:5a:b0",
        "type",
        "bridge",
    ]);
    run(&["ip", "link", "set", &port, "master", &bridge]);
    poll(
        &pins,
        "a bridge member receives on its bridge's MAC",
        Duration::from_secs(5),
        rx_is(BRIDGE),
    );

    watcher.shutdown();
}

/// How long a burst's window is: the watcher's thread, and with it the
/// reader of its subscription, is blocked for this long while the burst
/// runs, so the burst overruns the shrunk buffer by construction rather
/// than by racing the reader. Generous, for an `ip` process under a slow
/// TCG guest: a burst that outlasts it fails the test loudly.
const STALL: Duration = Duration::from_secs(10);

/// The subscription buffer [`OverrunRig::start`] asks for when a burst
/// must overrun it: the kernel's minimum, about one message.
const SHRUNK: usize = 1;
/// One no burst here can fill.
const ROOMY: usize = 8 << 20;

/// A namespace with its own pins, a watcher with a `rcvbuf`-byte
/// subscription buffer, and `n` dummies created down in one link group
/// (so none qualifies yet), all from one `ip` process.
struct OverrunRig {
    netns: String,
    pins: Pins,
    watcher: Option<RedirectTargetWatcher>,
    idx: Vec<u32>,
    group: &'static str,
    _ns_fd: OwnedFd,
    _guard: NetnsGuard,
}

impl OverrunRig {
    fn start(tag: &str, n: usize, group: &'static str, rcvbuf: usize) -> Self {
        if !bpffs_present(Path::new(BPFFS_ROOT)) {
            run(&["mount", "-t", "bpf", "bpf", BPFFS_ROOT]);
        }
        let pid = std::process::id() % 10000;
        let netns = format!("pfr{tag}{pid}");
        let _ = Command::new("ip").args(["netns", "del", &netns]).status();
        run(&["ip", "netns", "add", &netns]);
        let guard = NetnsGuard(netns.clone());
        // No IPv6 on the links: less work for the kernel per link.
        ns_run(
            &netns,
            &["sysctl", "-wq", "net.ipv6.conf.default.disable_ipv6=1"],
        );
        let ns_fd = enter_netns(&netns);
        let pins = Pins::setup(tag);
        let watcher =
            RedirectTargetWatcher::start_with_rcvbuf(&pins.root, Vec::new(), Vec::new(), rcvbuf)
                .expect("watcher start");
        std::thread::sleep(Duration::from_millis(500));

        let names: Vec<String> = (0..n).map(|i| format!("pf{tag}{pid}x{i}")).collect();
        let batch = std::env::temp_dir().join(format!("pfr{tag}{pid}.batch"));
        let script: String = names
            .iter()
            .map(|l| format!("link add {l} type dummy\nlink set dev {l} group {group}\n"))
            .collect();
        std::fs::write(&batch, script).expect("write batch");
        ns_run(&netns, &["ip", "-batch", batch.to_str().unwrap()]);
        let _ = std::fs::remove_file(&batch);
        let idx: Vec<u32> = names.iter().map(|l| if_nametoindex(l)).collect();
        let rig = Self {
            netns,
            pins,
            watcher: Some(watcher),
            idx,
            group,
            _ns_fd: ns_fd,
            _guard: guard,
        };
        // Creating them may overrun too; start from nothing owed.
        rig.status_until("creation settled", Duration::from_secs(15), |s| {
            !s.resync_pending
        });
        let keys = rig.pins.devmap_keys();
        assert!(
            rig.idx.iter().all(|i| !keys.contains(i)),
            "precondition: links that are down are not targets"
        );
        rig
    }

    fn watcher(&self) -> &RedirectTargetWatcher {
        self.watcher.as_ref().expect("running")
    }

    /// Wait until the watcher's own status satisfies `pred`; that status,
    /// or a panic naming `what` and the last one seen.
    fn status_until(
        &self,
        what: &str,
        deadline: Duration,
        pred: impl Fn(&WatchStatus) -> bool,
    ) -> WatchStatus {
        let start = Instant::now();
        loop {
            let s = self.watcher().status();
            if pred(&s) {
                return s;
            }
            assert!(
                start.elapsed() < deadline,
                "{what}: not satisfied within {deadline:?}; status={s:?}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Run `ip link <args…> group <group> …` while nobody reads the
    /// subscription, and confirm the kernel reported the loss.
    fn burst(&self, args: &[&str]) -> WatchStatus {
        let before = self.watcher().status();
        self.watcher().stall_reader(STALL);
        let started = Instant::now();
        let mut cmd = vec!["ip", "link"];
        cmd.extend_from_slice(args);
        ns_run(&self.netns, &cmd);
        assert!(
            started.elapsed() < STALL,
            "the burst outlasted the stall ({:?}); raise STALL",
            started.elapsed()
        );
        self.status_until(
            "the burst's overrun reported",
            STALL + Duration::from_secs(5),
            |s| s.overruns > before.overruns,
        );
        before
    }
}

impl Drop for OverrunRig {
    fn drop(&mut self) {
        if let Some(w) = self.watcher.take() {
            w.shutdown();
        }
    }
}

/// Link notifications the kernel drops on a full receive buffer are made
/// good by a re-read of the link table. While nobody reads the shrunk
/// buffer, one `ip link set group … up` brings a whole group of links up
/// inside a single syscall, every `RTM_NEWLINK` back to back, as when a
/// provisioning pass re-creates a batch of links. Without the re-read,
/// each link whose notification was dropped stays out of the redirect
/// maps (its traffic on the kernel path) until a SIGHUP. Deleting the
/// group the same way loses the `RTM_DELLINK`s, which leaves
/// `TC_REDIRECT_TARGETS` holding dead ifindexes (the kernel clears a
/// devmap's entries on unregister, but not a plain hash's).
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN + CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn links_whose_notifications_were_lost_are_re_read() {
    let rig = OverrunRig::start("o", 48, "77", SHRUNK);
    let before = rig.burst(&["set", "group", rig.group, "up"]);
    wait_for(
        &rig.pins,
        "every link brought up admitted",
        Duration::from_secs(15),
        |k| rig.idx.iter().all(|i| k.contains(i)),
    );
    let s = rig.status_until("recovery recorded", Duration::from_secs(5), |s| {
        !s.resync_pending
    });
    assert!(s.resyncs_ok > before.resyncs_ok, "{s:?}");
    assert_eq!(s.subsystem_health().state, HealthState::Healthy, "{s:?}");

    // Down first (they stay targets), so the delete's burst is nothing
    // but `RTM_DELLINK`s and what it loses is deletes.
    ns_run(
        &rig.netns,
        &["ip", "link", "set", "group", rig.group, "down"],
    );
    rig.status_until("down settled", Duration::from_secs(15), |s| {
        !s.resync_pending
    });
    let before = rig.burst(&["del", "group", rig.group]);
    wait_for(
        &rig.pins,
        "every deleted link evicted",
        Duration::from_secs(15),
        |k| rig.idx.iter().all(|i| !k.contains(i)),
    );
    let s = rig.status_until("recovery recorded", Duration::from_secs(5), |s| {
        !s.resync_pending
    });
    assert!(s.resyncs_ok > before.resyncs_ok, "{s:?}");
}

impl OverrunRig {
    /// The rig's links that are not targets: missing from either map.
    fn outside(&self) -> Vec<u32> {
        let (dm, tc) = (self.pins.devmap_keys(), self.pins.tc_keys());
        self.idx
            .iter()
            .copied()
            .filter(|i| !(dm.contains(i) && tc.contains(i)))
            .collect()
    }

    /// Delete `n` of the rig's links that are targets, one request each,
    /// which makes room in the maps. Returns their ifindexes.
    fn delete_admitted(&self, n: usize) -> Vec<u32> {
        let outside = self.outside();
        let doomed: Vec<u32> = self
            .idx
            .iter()
            .copied()
            .filter(|i| !outside.contains(i))
            .take(n)
            .collect();
        for &i in &doomed {
            let mut buf = [0u8; libc::IF_NAMESIZE];
            let name = unsafe { libc::if_indextoname(i, buf.as_mut_ptr().cast()) };
            assert!(!name.is_null(), "if_indextoname({i})");
            let name = unsafe { std::ffi::CStr::from_ptr(name) }
                .to_string_lossy()
                .into_owned();
            ns_run(&self.netns, &["ip", "link", "del", &name]);
        }
        doomed
    }

    /// Every remaining link is a target.
    fn all_admitted_but(&self, gone: &[u32]) {
        let (dm, tc) = (self.pins.devmap_keys(), self.pins.tc_keys());
        assert!(
            self.idx
                .iter()
                .filter(|i| !gone.contains(i))
                .all(|i| dm.contains(i) && tc.contains(i)),
            "every remaining link a target: devmap={dm:?} tc={tc:?}"
        );
    }
}

/// More links qualify than the redirect maps hold (64 each), with no
/// notification lost. The links left out are reported as such — the row
/// is Degraded on capacity, not on overrun history, which here is none —
/// and they are admitted as soon as an eviction makes room, with no
/// timer involved.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN + CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn links_the_maps_cannot_hold_are_reported_and_admitted_when_room_is_made() {
    let rig = OverrunRig::start("c", 72, "79", ROOMY);
    ns_run(&rig.netns, &["ip", "link", "set", "group", rig.group, "up"]);
    let s = rig.status_until("the refused links reported", Duration::from_secs(15), |s| {
        s.map_full > 0
    });
    assert_eq!(s.overruns, 0, "premise: nothing was lost; {s:?}");
    let left = rig.outside();
    assert!(!left.is_empty(), "premise: the maps overflowed");
    // Counted as a full map (E2BIG), not as an insert that is failing.
    let s = rig.status_until("every link left out counted", Duration::from_secs(5), |s| {
        s.map_full == left.len() as u64 && s.insert_failing == 0
    });
    let h = s.subsystem_health();
    assert_eq!(h.state, HealthState::Degraded, "{s:?}");
    let m = h.message.unwrap();
    assert!(
        m.contains("not in the redirect maps") && !m.contains("notifications lost"),
        "{m}"
    );

    let gone = rig.delete_admitted(left.len() + 2);
    let s = rig.status_until("room made, all admitted", Duration::from_secs(15), |s| {
        s.map_full == 0
    });
    assert_eq!(s.subsystem_health().state, HealthState::Healthy, "{s:?}");
    rig.all_admitted_but(&gone);
}

/// A recovery is over when the re-read has been applied, maps full or
/// not. Links come up past the maps' capacity in one overrun burst: the
/// recovery must complete (counted, nothing owed), leaving only the
/// capacity condition on the row, instead of retrying a full map forever
/// and blaming lost notifications for it.
#[test]
#[ignore = "needs CAP_NET_ADMIN + CAP_SYS_ADMIN + CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn a_recovery_completes_though_the_maps_are_full() {
    let rig = OverrunRig::start("f", 72, "78", SHRUNK);
    let before = rig.burst(&["set", "group", rig.group, "up"]);
    let s = rig.status_until("recovery recorded", Duration::from_secs(15), |s| {
        !s.resync_pending && s.resyncs_ok > before.resyncs_ok
    });
    assert!(s.map_full > 0, "premise: the maps overflowed; {s:?}");
    let m = s.subsystem_health().message.unwrap();
    assert!(
        m.contains("not in the redirect maps") && !m.contains("notifications lost"),
        "{m}"
    );
    let left = rig.outside();
    let gone = rig.delete_admitted(left.len() + 2);
    rig.status_until("room made, all admitted", Duration::from_secs(15), |s| {
        s.map_full == 0 && !s.resync_pending
    });
    rig.all_admitted_but(&gone);
}
