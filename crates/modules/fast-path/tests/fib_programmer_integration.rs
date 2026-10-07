//! FibProgrammer integration test (Option F, Phase 3.7 Slice B).
//!
//! Exercises the programmer's route-side write path end-to-end
//! against real BPF maps: Add / Del / PeerDown / ECMP dedup /
//! refcounted nexthop recycling. Not a "BMP mock test" as originally
//! scoped, constructing valid BMP byte streams from scratch is its
//! own sub-project, and the real value is proving the programmer
//! writes the right bits into the BPF maps when fed RouteEvents,
//! which is exactly what the `apply_route_event` handle does.
//!
//! **Map-handle duplication.** The programmer takes ownership of
//! `Array<MapData, _>` handles via `Ebpf::take_map`, after which
//! the test can't read those maps via the same `Ebpf`. Solution:
//! pin each map to a bpffs tempdir first, then have both the
//! programmer and the test open independent `MapData::from_pin`
//! handles for the same pin path. Both FDs reference the same
//! kernel map; writes from one are visible to the other.
//!
//! Runs under CAP_BPF + CAP_NET_ADMIN. `#[ignore]`-gated; CI qemu
//! job runs it via `sudo -E cargo test -- --ignored`.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::time::Duration;

use aya::maps::lpm_trie::Key as LpmKey;
use aya::maps::{Array, LpmTrie, Map, MapData};
use aya::Ebpf;
use packetframe_common::fib::{IpPrefix, NeighEvent, PeerId, ResolvedRouteSink, RouteEvent};
use packetframe_fast_path::aligned_bpf_copy;
use packetframe_fast_path::fib::netlink_neigh::NeighborResolveHandle;
use packetframe_fast_path::fib::programmer::{FibProgrammer, ECMP_GROUPS_CAP};
use packetframe_fast_path::fib::types::{
    EcmpGroup, FibCacheCfg, FibValue, NexthopEntry, NexthopSlotClass, FIB_KIND_ECMP,
    FIB_KIND_SINGLE, NH_FAMILY_V4, NH_FAMILY_V6, NH_STATE_FAILED, NH_STATE_INCOMPLETE,
    NH_STATE_RESOLVED,
};
use tokio_util::sync::CancellationToken;

const BPFFS_ROOT: &str = "/sys/fs/bpf";
const TEST_PREFIX: &str = "pftestprog";

struct PinDirs {
    dir: PathBuf,
}

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static BPFFS_MOUNT: Once = Once::new();

/// bpffs superblock magic (`include/uapi/linux/magic.h`).
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

fn bpffs_already_mounted() -> bool {
    let path = match std::ffi::CString::new(BPFFS_ROOT) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut st) } != 0 {
        return false;
    }
    // `f_type` differs in width and signedness across libc/arch.
    #[allow(clippy::unnecessary_cast)]
    let f_type = st.f_type as i64;
    f_type == BPF_FS_MAGIC
}

/// Ensure `/sys/fs/bpf` exists and has bpffs mounted on it. GitHub's
/// hosted Ubuntu runner already has this; virtme-ng's VM does not, so
/// we mount it ourselves. Best-effort: errors are tolerated, the
/// subsequent `create_dir_all` / `pin` call will surface the real
/// problem with a clearer message.
///
/// Only mounts when bpffs genuinely isn't there. Linux stacks mounts on
/// the same mountpoint, so mounting unconditionally would shadow a live
/// packetframe's pinned maps with an empty instance for the rest of the
/// boot — this test binary ships in the on-router bundle, where that
/// would be a production incident rather than a test failure. Same guard
/// in `fib_comparison.rs` and `route_source_bgp_addpath.rs`; each
/// `tests/*.rs` is its own crate, so the helper can't be shared without
/// the `tests/common/` refactor noted below.
fn ensure_bpffs_mounted() {
    BPFFS_MOUNT.call_once(|| {
        if bpffs_already_mounted() {
            return;
        }
        let _ = std::fs::create_dir_all(BPFFS_ROOT);
        let _ = std::process::Command::new("mount")
            .args(["-t", "bpf", "bpf", BPFFS_ROOT])
            .status();
    });
}

impl PinDirs {
    fn setup() -> Self {
        ensure_bpffs_mounted();
        // Unique per-invocation subdir under bpffs. The test binary PID
        // is shared across parallel #[test] fns, so include an atomic
        // counter to disambiguate concurrent harness instances.
        let unique = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = PathBuf::from(BPFFS_ROOT).join(format!(
            "{TEST_PREFIX}-{}-{}",
            std::process::id(),
            unique
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir bpffs subdir");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }
}

impl Drop for PinDirs {
    fn drop(&mut self) {
        // Remove every file (unpinning each map) then the directory.
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Load the fast-path ELF, pin the four PacketFrame FIB maps under the
/// test's bpffs subdir, and return the pinned `Ebpf` so the maps
/// stay alive after `take_map` hands them to the programmer.
fn load_and_pin(pins: &PinDirs) -> Ebpf {
    let bytes = aligned_bpf_copy();
    let ebpf = Ebpf::load(&bytes).expect("Ebpf::load");
    for name in [
        "NEXTHOPS",
        "FIB_V4",
        "FIB_V6",
        "ECMP_GROUPS",
        "FIB_CACHE_CFG",
    ] {
        let path = pins.path(name);
        ebpf.map(name)
            .unwrap_or_else(|| panic!("{name} map missing from ELF"))
            .pin(&path)
            .unwrap_or_else(|e| panic!("pin {name} at {}: {e}", path.display()));
    }
    ebpf
}

/// Open a typed `Array<MapData, T>` handle by re-opening the pinned
/// map. Each call produces a fresh FD pointing at the same kernel
/// map as every other handle (including the one held by the
/// programmer).
fn open_array<T: aya::Pod>(path: &Path) -> Array<MapData, T> {
    let map_data = MapData::from_pin(path)
        .unwrap_or_else(|e| panic!("MapData::from_pin({}): {e}", path.display()));
    Array::try_from(Map::Array(map_data))
        .unwrap_or_else(|e| panic!("Array::try_from({}): {e}", path.display()))
}

fn open_lpm_v4(path: &Path) -> LpmTrie<MapData, [u8; 4], FibValue> {
    let map_data = MapData::from_pin(path).expect("LpmTrie from_pin");
    LpmTrie::try_from(Map::LpmTrie(map_data)).expect("LpmTrie try_from")
}

fn open_lpm_v6(path: &Path) -> LpmTrie<MapData, [u8; 16], FibValue> {
    let map_data = MapData::from_pin(path).expect("LpmTrie from_pin");
    LpmTrie::try_from(Map::LpmTrie(map_data)).expect("LpmTrie try_from")
}

/// What the second tier was told, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SinkCall {
    Resolved(IpPrefix, Vec<IpAddr>),
    Withdrawn(IpPrefix),
    NeighResolved(IpAddr, [u8; 6], u32),
    NeighLost(IpAddr),
}

/// A [`ResolvedRouteSink`] that records rather than forwards.
///
/// Ordering matters as much as content here — a withdrawal announced
/// before the mirror commit that produced it, or a resolve announced for
/// a set the programmer then failed to install, are the two bugs this
/// seam can have — so the recording is a `Vec`, not a map.
#[derive(Default)]
struct RecordingSink {
    calls: std::sync::Mutex<Vec<SinkCall>>,
}

impl RecordingSink {
    fn calls(&self) -> Vec<SinkCall> {
        self.calls.lock().expect("sink mutex").clone()
    }
}

impl ResolvedRouteSink for RecordingSink {
    fn route_resolved(&self, prefix: IpPrefix, nexthops: &[IpAddr]) {
        self.calls
            .lock()
            .expect("sink mutex")
            .push(SinkCall::Resolved(prefix, nexthops.to_vec()));
    }
    fn route_withdrawn(&self, prefix: IpPrefix) {
        self.calls
            .lock()
            .expect("sink mutex")
            .push(SinkCall::Withdrawn(prefix));
    }
    fn neighbour_resolved(&self, nh: IpAddr, mac: [u8; 6], ifindex: u32) {
        self.calls
            .lock()
            .expect("sink mutex")
            .push(SinkCall::NeighResolved(nh, mac, ifindex));
    }
    fn neighbour_lost(&self, nh: IpAddr) {
        self.calls
            .lock()
            .expect("sink mutex")
            .push(SinkCall::NeighLost(nh));
    }
}

/// Construct a FibProgrammer with handles to the pinned maps, spawn
/// it on a fresh current-thread tokio runtime, return the handle +
/// a shutdown token + a task join handle.
struct ProgrammerHarness {
    pins: PinDirs,
    _ebpf: Ebpf,
    rt: tokio::runtime::Runtime,
    shutdown: CancellationToken,
    handle: packetframe_fast_path::fib::programmer::FibProgrammerHandle,
    task: Option<tokio::task::JoinHandle<()>>,
    /// Retained only by the sink variant, which needs to inject
    /// `NeighEvent`s. `new()`/`new_with_cache()` drop their sender, which
    /// closes the channel — fine for route-only tests, fatal here.
    events_tx: Option<tokio::sync::mpsc::Sender<NeighEvent>>,
}

impl ProgrammerHarness {
    fn new() -> Self {
        let pins = PinDirs::setup();
        let ebpf = load_and_pin(&pins);

        // Programmer opens the maps via from_pin. `FibProgrammer::open_*`
        // hard-codes the production pin layout
        // (`<bpffs>/fast-path/maps/<NAME>`); we pin flat under
        // `<bpffs>/pftestprog-<pid>-<n>/<NAME>` for test isolation, so
        // construct the typed handles directly here.
        let nexthops: Array<MapData, NexthopEntry> = open_array(&pins.path("NEXTHOPS"));
        let fib_v4 = open_lpm_v4(&pins.path("FIB_V4"));
        let fib_v6 = open_lpm_v6(&pins.path("FIB_V6"));
        let ecmp_groups: Array<MapData, EcmpGroup> = open_array(&pins.path("ECMP_GROUPS"));

        let shutdown = CancellationToken::new();
        let (_events_tx, events_rx) = tokio::sync::mpsc::channel(16);
        let (programmer, handle) = FibProgrammer::new(
            nexthops,
            fib_v4,
            fib_v6,
            ecmp_groups,
            events_rx,
            shutdown.clone(),
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let task = rt.spawn(programmer.run());

        Self {
            pins,
            _ebpf: ebpf,
            rt,
            shutdown,
            handle,
            task: Some(task),
            events_tx: None,
        }
    }

    /// Variant wiring the FIB_CACHE_CFG handle into the programmer,
    /// for the destination-cache generation tests. Kept separate so
    /// the existing tests keep exercising the `new()` shortcut
    /// (cache-less construction must stay supported for harnesses).
    fn new_with_cache() -> Self {
        let pins = PinDirs::setup();
        let ebpf = load_and_pin(&pins);
        let nexthops: Array<MapData, NexthopEntry> = open_array(&pins.path("NEXTHOPS"));
        let fib_v4 = open_lpm_v4(&pins.path("FIB_V4"));
        let fib_v6 = open_lpm_v6(&pins.path("FIB_V6"));
        let ecmp_groups: Array<MapData, EcmpGroup> = open_array(&pins.path("ECMP_GROUPS"));
        let cache_cfg: Array<MapData, FibCacheCfg> = open_array(&pins.path("FIB_CACHE_CFG"));
        let shutdown = CancellationToken::new();
        let (_events_tx, events_rx) = tokio::sync::mpsc::channel(16);
        let (programmer, handle) = FibProgrammer::new_with_resolver(
            nexthops,
            fib_v4,
            fib_v6,
            ecmp_groups,
            Some(cache_cfg),
            events_rx,
            shutdown.clone(),
            None,
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let task = rt.spawn(programmer.run());
        Self {
            pins,
            _ebpf: ebpf,
            rt,
            shutdown,
            handle,
            task: Some(task),
            events_tx: None,
        }
    }

    /// Variant with a second-tier sink registered and the neigh-event
    /// sender retained.
    fn with_sink() -> (Self, Arc<RecordingSink>) {
        let pins = PinDirs::setup();
        let ebpf = load_and_pin(&pins);
        let nexthops: Array<MapData, NexthopEntry> = open_array(&pins.path("NEXTHOPS"));
        let fib_v4 = open_lpm_v4(&pins.path("FIB_V4"));
        let fib_v6 = open_lpm_v6(&pins.path("FIB_V6"));
        let ecmp_groups: Array<MapData, EcmpGroup> = open_array(&pins.path("ECMP_GROUPS"));
        let shutdown = CancellationToken::new();
        let (events_tx, events_rx) = tokio::sync::mpsc::channel(16);
        let (mut programmer, handle) = FibProgrammer::new(
            nexthops,
            fib_v4,
            fib_v6,
            ecmp_groups,
            events_rx,
            shutdown.clone(),
        );
        let sink = Arc::new(RecordingSink::default());
        programmer.set_route_sink(sink.clone());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let task = rt.spawn(programmer.run());
        (
            Self {
                pins,
                _ebpf: ebpf,
                rt,
                shutdown,
                handle,
                task: Some(task),
                events_tx: Some(events_tx),
            },
            sink,
        )
    }

    /// `with_sink`, plus a route-ledger status handle and, when given, a
    /// seed applied before the programmer serves anything — the way the
    /// controller starts it.
    fn with_seed(
        seed: Option<packetframe_fast_path::fib::route_ledger::RouteLedger>,
    ) -> (
        Self,
        Arc<RecordingSink>,
        packetframe_fast_path::fib::route_ledger::SharedLedgerStatus,
    ) {
        let pins = PinDirs::setup();
        let ebpf = load_and_pin(&pins);
        let nexthops: Array<MapData, NexthopEntry> = open_array(&pins.path("NEXTHOPS"));
        let fib_v4 = open_lpm_v4(&pins.path("FIB_V4"));
        let fib_v6 = open_lpm_v6(&pins.path("FIB_V6"));
        let ecmp_groups: Array<MapData, EcmpGroup> = open_array(&pins.path("ECMP_GROUPS"));
        let shutdown = CancellationToken::new();
        let (events_tx, events_rx) = tokio::sync::mpsc::channel(16);
        let (mut programmer, handle) = FibProgrammer::new(
            nexthops,
            fib_v4,
            fib_v6,
            ecmp_groups,
            events_rx,
            shutdown.clone(),
        );
        let sink = Arc::new(RecordingSink::default());
        programmer.set_route_sink(sink.clone());
        let status = packetframe_fast_path::fib::route_ledger::shared_status();
        programmer.set_ledger_status(status.clone());
        if let Some(seed) = seed {
            programmer.set_seed(seed);
        }
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let task = rt.spawn(programmer.run());
        (
            Self {
                pins,
                _ebpf: ebpf,
                rt,
                shutdown,
                handle,
                task: Some(task),
                events_tx: Some(events_tx),
            },
            sink,
            status,
        )
    }

    /// `with_sink` plus a detached resolver handle, so a test can watch
    /// the programmer's `request_resolve` traffic: what it asks to have
    /// resolved and when. Nothing answers those requests — the test
    /// plays the resolver by feeding `NeighEvent`s itself.
    fn with_sink_and_resolver() -> (
        Self,
        Arc<RecordingSink>,
        tokio::sync::mpsc::Receiver<IpAddr>,
    ) {
        let pins = PinDirs::setup();
        let ebpf = load_and_pin(&pins);
        let nexthops: Array<MapData, NexthopEntry> = open_array(&pins.path("NEXTHOPS"));
        let fib_v4 = open_lpm_v4(&pins.path("FIB_V4"));
        let fib_v6 = open_lpm_v6(&pins.path("FIB_V6"));
        let ecmp_groups: Array<MapData, EcmpGroup> = open_array(&pins.path("ECMP_GROUPS"));
        let shutdown = CancellationToken::new();
        let (events_tx, events_rx) = tokio::sync::mpsc::channel(16);
        let (resolver, resolve_rx) = NeighborResolveHandle::detached();
        let (mut programmer, handle) = FibProgrammer::new_with_resolver(
            nexthops,
            fib_v4,
            fib_v6,
            ecmp_groups,
            None,
            events_rx,
            shutdown.clone(),
            Some(resolver),
        );
        let sink = Arc::new(RecordingSink::default());
        programmer.set_route_sink(sink.clone());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let task = rt.spawn(programmer.run());
        (
            Self {
                pins,
                _ebpf: ebpf,
                rt,
                shutdown,
                handle,
                task: Some(task),
                events_tx: Some(events_tx),
            },
            sink,
            resolve_rx,
        )
    }

    /// Let the programmer run for `wait`, then return every resolve
    /// request it issued that is sitting in the detached queue. The
    /// wait happens on the harness runtime so the programmer's timers
    /// (`REPROBE_TICK`) actually fire.
    fn drain_resolves(
        &self,
        rx: &mut tokio::sync::mpsc::Receiver<IpAddr>,
        wait: Duration,
    ) -> Vec<IpAddr> {
        self.run(async move {
            tokio::time::sleep(wait).await;
            let mut out = Vec::new();
            while let Ok(ip) = rx.try_recv() {
                out.push(ip);
            }
            out
        })
    }

    /// Push a `NeighEvent` into the programmer and let it drain.
    ///
    /// The settle is a yield-and-wait rather than an ack: neigh events
    /// are a fire-and-forget channel with no reply, so there is nothing
    /// to await. 200 ms against a current-thread runtime whose only other
    /// work is this event is generous by three orders of magnitude.
    fn feed_neigh(&self, evt: NeighEvent) {
        let tx = self.events_tx.as_ref().expect("sink harness only").clone();
        self.run(async move {
            tx.send(evt).await.expect("neigh channel open");
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
    }

    /// Read FIB_CACHE_CFG via a fresh handle.
    fn read_cache_cfg(&self) -> FibCacheCfg {
        let arr: Array<MapData, FibCacheCfg> = open_array(&self.pins.path("FIB_CACHE_CFG"));
        arr.get(&0, 0).expect("FIB_CACHE_CFG get")
    }

    /// Block on an async call against the programmer from sync test code.
    fn run<F, T>(&self, f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        self.rt.block_on(f)
    }

    /// Read FIB_V4 entry via a fresh parallel handle so we don't
    /// contend with the programmer's handle.
    fn read_fib_v4(&self, addr: [u8; 4], prefix_len: u8) -> Option<FibValue> {
        let trie = open_lpm_v4(&self.pins.path("FIB_V4"));
        let key = LpmKey::new(u32::from(prefix_len), addr);
        trie.get(&key, 0).ok()
    }

    /// FIB_V6 counterpart of [`Self::read_fib_v4`]. `open_lpm_v6` and
    /// the `fib_v6` handle were already wired for the programmer; this
    /// is the missing reader that lets tests assert on the v6 half.
    fn read_fib_v6(&self, addr: [u8; 16], prefix_len: u8) -> Option<FibValue> {
        let trie = open_lpm_v6(&self.pins.path("FIB_V6"));
        let key = LpmKey::new(u32::from(prefix_len), addr);
        trie.get(&key, 0).ok()
    }

    /// Whether FIB_V4 holds exactly `addr/prefix_len`.
    ///
    /// [`Self::read_fib_v4`] is the kernel's longest-prefix lookup, so
    /// once a covering route is installed (a default above all) it
    /// answers for every address and cannot tell whether a
    /// more-specific entry is present. This walks the keys instead.
    fn fib_v4_has(&self, addr: [u8; 4], prefix_len: u8) -> bool {
        let trie = open_lpm_v4(&self.pins.path("FIB_V4"));
        trie.keys()
            .map(|k| k.expect("FIB_V4 key walk"))
            .any(|k| k.prefix_len() == u32::from(prefix_len) && k.data() == addr)
    }

    /// FIB_V6 counterpart of [`Self::fib_v4_has`].
    fn fib_v6_has(&self, addr: [u8; 16], prefix_len: u8) -> bool {
        let trie = open_lpm_v6(&self.pins.path("FIB_V6"));
        trie.keys()
            .map(|k| k.expect("FIB_V6 key walk"))
            .any(|k| k.prefix_len() == u32::from(prefix_len) && k.data() == addr)
    }

    fn read_nexthop(&self, id: u32) -> NexthopEntry {
        let arr: Array<MapData, NexthopEntry> = open_array(&self.pins.path("NEXTHOPS"));
        arr.get(&id, 0).expect("NEXTHOPS read")
    }

    fn read_ecmp_group(&self, id: u32) -> EcmpGroup {
        let arr: Array<MapData, EcmpGroup> = open_array(&self.pins.path("ECMP_GROUPS"));
        arr.get(&id, 0).expect("ECMP_GROUPS read")
    }
}

impl Drop for ProgrammerHarness {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            // Construct the timeout future *inside* the runtime context
            // so the timer's reactor lookup succeeds.
            let _ = self
                .rt
                .block_on(async { tokio::time::timeout(Duration::from_secs(2), task).await });
        }
    }
}

// ========== Tests ==========

#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn register_nexthop_seeds_incomplete_entry() {
    let h = ProgrammerHarness::new();
    let id = h
        .run(async {
            h.handle
                .register_nexthop(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
                .await
        })
        .expect("register_nexthop");

    let entry = h.read_nexthop(id);
    assert_eq!(
        entry.state, NH_STATE_INCOMPLETE,
        "fresh nexthop should be Incomplete until neigh resolves"
    );
}

#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_single_nexthop_route_writes_fib_v4() {
    let h = ProgrammerHarness::new();
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let prefix = IpPrefix::V4 {
        addr: [192, 0, 2, 0],
        prefix_len: 24,
    };

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: PeerId(0xaaaa),
                prefix,
                nexthops: vec![nh],
                path_id: None,
                local_pref: None,
            })
            .await
    })
    .expect("apply Add");

    let fib = h
        .read_fib_v4([192, 0, 2, 0], 24)
        .expect("FIB_V4[192.0.2.0/24]");
    assert_eq!(fib.kind, FIB_KIND_SINGLE, "single-nexthop route");
    // idx is whatever NexthopId the programmer allocated; read back
    // NEXTHOPS[idx] to confirm it's our IP's seeded entry.
    let entry = h.read_nexthop(fib.idx);
    assert_eq!(
        entry.state, NH_STATE_INCOMPLETE,
        "nexthop seeded Incomplete; NeighEvent::Learned would flip it"
    );
}

#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_multi_nexthop_route_allocates_ecmp_group() {
    let h = ProgrammerHarness::new();
    let nhs: Vec<IpAddr> = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
    ];
    let prefix = IpPrefix::V4 {
        addr: [198, 51, 100, 0],
        prefix_len: 24,
    };

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: PeerId(0xbbbb),
                prefix,
                nexthops: nhs.clone(),
                path_id: None,
                local_pref: None,
            })
            .await
    })
    .expect("apply Add multi-NH");

    let fib = h
        .read_fib_v4([198, 51, 100, 0], 24)
        .expect("FIB_V4[198.51.100.0/24]");
    assert_eq!(fib.kind, FIB_KIND_ECMP, "multi-nexthop route is ECMP");

    let group = h.read_ecmp_group(fib.idx);
    assert_eq!(
        group.nh_count as usize,
        nhs.len(),
        "ECMP group's nh_count matches nexthop count"
    );
    // Per Phase 3B's `compute_signature`, the nh_idx slots are
    // sorted ascending. Check the slots we populated are non-sentinel.
    let populated: Vec<u32> = group.nh_idx.iter().take(nhs.len()).copied().collect();
    assert!(
        populated.iter().all(|&idx| idx != u32::MAX),
        "populated slots should not be ECMP_NH_UNUSED"
    );
    // Sorted ascending.
    for w in populated.windows(2) {
        assert!(w[0] < w[1], "nh_idx slots not sorted: {populated:?}");
    }
}

#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn del_removes_fib_entry() {
    let h = ProgrammerHarness::new();
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let prefix = IpPrefix::V4 {
        addr: [203, 0, 113, 0],
        prefix_len: 24,
    };
    let peer = PeerId(0xcccc);

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer,
                prefix,
                nexthops: vec![nh],
                path_id: None,
                local_pref: None,
            })
            .await
    })
    .expect("apply Add");

    assert!(
        h.read_fib_v4([203, 0, 113, 0], 24).is_some(),
        "FIB_V4 populated after Add"
    );

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: peer,
                prefix,
                path_id: None,
            })
            .await
    })
    .expect("apply Del");

    assert!(
        h.read_fib_v4([203, 0, 113, 0], 24).is_none(),
        "FIB_V4 entry gone after Del"
    );
}

#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn peer_down_withdraws_all_peer_routes() {
    let h = ProgrammerHarness::new();
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
    let peer = PeerId(0xdddd);

    h.run(async {
        // Add three distinct prefixes from the same peer.
        for addr in [[192, 0, 2, 0], [198, 51, 100, 0], [203, 0, 113, 0]] {
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: peer,
                    prefix: IpPrefix::V4 {
                        addr,
                        prefix_len: 24,
                    },
                    nexthops: vec![nh],
                    path_id: None,
                    local_pref: None,
                })
                .await
                .expect("apply Add");
        }
    });

    // All three present.
    assert!(h.read_fib_v4([192, 0, 2, 0], 24).is_some());
    assert!(h.read_fib_v4([198, 51, 100, 0], 24).is_some());
    assert!(h.read_fib_v4([203, 0, 113, 0], 24).is_some());

    // PeerDown sweeps the whole peer's routes.
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::PeerDown { peer_id: peer })
            .await
    })
    .expect("apply PeerDown");

    assert!(h.read_fib_v4([192, 0, 2, 0], 24).is_none());
    assert!(h.read_fib_v4([198, 51, 100, 0], 24).is_none());
    assert!(h.read_fib_v4([203, 0, 113, 0], 24).is_none());
}

// ========== IPv6 / local-prefix6 ==========
//
// The programmer's v6 write path had no integration coverage at all
// before this, despite `open_lpm_v6` and the `fib_v6` handle being wired.

fn v6(s: &str) -> [u8; 16] {
    s.parse::<std::net::Ipv6Addr>().unwrap().octets()
}

#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_single_nexthop_route_writes_fib_v6() {
    let h = ProgrammerHarness::new();
    let nh = IpAddr::V6("2001:db8::1".parse().unwrap());
    let prefix = IpPrefix::V6 {
        addr: v6("2001:db8:1::"),
        prefix_len: 48,
    };

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: PeerId(0xbbbb),
                prefix,
                nexthops: vec![nh],
                path_id: None,
                local_pref: None,
            })
            .await
    })
    .expect("apply Add");

    let fib = h
        .read_fib_v6(v6("2001:db8:1::"), 48)
        .expect("FIB_V6[2001:db8:1::/48]");
    assert_eq!(fib.kind, FIB_KIND_SINGLE, "single-nexthop route");
    let entry = h.read_nexthop(fib.idx);
    assert_eq!(entry.state, NH_STATE_INCOMPLETE);
    // The family tag is set by the programmer but asserted nowhere else.
    // XDP treats it as diagnostic-only, so a regression here would be
    // invisible without this check.
    assert_eq!(
        entry.family, NH_FAMILY_V6,
        "v6 nexthop must be tagged NH_FAMILY_V6"
    );
}

/// The exact event shape `local-prefix6` emits: a /128 whose nexthop is
/// the destination itself. Nexthop-equals-destination is unique to the
/// connected fast-path and was untested at either family.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn local_prefix6_slash128_self_nexthop_round_trips() {
    let h = ProgrammerHarness::new();
    let host: std::net::Ipv6Addr = "2001:db8:0:1337::7".parse().unwrap();
    let peer = PeerId::local_arp(33);
    let prefix = IpPrefix::V6 {
        addr: host.octets(),
        prefix_len: 128,
    };

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer,
                prefix,
                nexthops: vec![IpAddr::V6(host)],
                path_id: None,
                local_pref: None,
            })
            .await
    })
    .expect("apply Add");

    let fib = h
        .read_fib_v6(host.octets(), 128)
        .expect("FIB_V6 /128 present");
    assert_eq!(fib.kind, FIB_KIND_SINGLE);
    let idx = fib.idx;
    assert_eq!(h.read_nexthop(idx).family, NH_FAMILY_V6);

    // A repeated Add for an unchanged nexthop set must be a no-op
    // rather than churning the map or leaking a slot. The resolver hits
    // this constantly as v6 neighbours go stale and get re-probed.
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer,
                prefix,
                nexthops: vec![IpAddr::V6(host)],
                path_id: None,
                local_pref: None,
            })
            .await
    })
    .expect("apply duplicate Add");
    let fib_again = h
        .read_fib_v6(host.octets(), 128)
        .expect("FIB_V6 /128 still present");
    assert_eq!(fib_again.idx, idx, "duplicate Add must not reallocate");

    // Withdrawal releases the entry.
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: peer,
                prefix,
                path_id: None,
            })
            .await
    })
    .expect("apply Del");
    assert!(
        h.read_fib_v6(host.octets(), 128).is_none(),
        "Del must remove the /128"
    );
}

/// One `PeerId::local_arp(ifindex)` covers both families, so a single
/// PeerDown on RTM_DELLINK must sweep the v4 /32s and the v6 /128s
/// together. This is the only exercise of that design decision.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn peer_down_withdraws_both_families_under_one_local_arp_peer_id() {
    let h = ProgrammerHarness::new();
    let peer = PeerId::local_arp(33);

    let v4_hosts = [[192, 0, 2, 7], [192, 0, 2, 8], [192, 0, 2, 9]];
    let v6_hosts = [
        "2001:db8:0:1337::7",
        "2001:db8:0:1337::8",
        "2001:db8:0:1337::9",
    ];

    h.run(async {
        for octets in v4_hosts {
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: peer,
                    prefix: IpPrefix::V4 {
                        addr: octets,
                        prefix_len: 32,
                    },
                    nexthops: vec![IpAddr::V4(Ipv4Addr::from(octets))],
                    path_id: None,
                    local_pref: None,
                })
                .await
                .expect("apply v4 Add");
        }
        for s in v6_hosts {
            let a: std::net::Ipv6Addr = s.parse().unwrap();
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: peer,
                    prefix: IpPrefix::V6 {
                        addr: a.octets(),
                        prefix_len: 128,
                    },
                    nexthops: vec![IpAddr::V6(a)],
                    path_id: None,
                    local_pref: None,
                })
                .await
                .expect("apply v6 Add");
        }
    });

    for octets in v4_hosts {
        assert!(
            h.read_fib_v4(octets, 32).is_some(),
            "{octets:?} /32 present"
        );
    }
    for s in v6_hosts {
        assert!(h.read_fib_v6(v6(s), 128).is_some(), "{s} /128 present");
    }

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::PeerDown { peer_id: peer })
            .await
    })
    .expect("apply PeerDown");

    for octets in v4_hosts {
        assert!(
            h.read_fib_v4(octets, 32).is_none(),
            "{octets:?} /32 must be withdrawn"
        );
    }
    for s in v6_hosts {
        assert!(
            h.read_fib_v6(v6(s), 128).is_none(),
            "{s} /128 must be withdrawn by the same PeerDown"
        );
    }
}

/// The 8192-entry NEXTHOPS pool is shared across families and every BGP
/// nexthop, and `local-prefix6` consumes one slot per connected host
/// because nexthop == destination. Documents the single-pool invariant
/// that capacity planning rests on.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn nexthop_pool_is_shared_across_families() {
    let h = ProgrammerHarness::new();
    let peer = PeerId(0xcccc);

    h.run(async {
        for i in 0..3u8 {
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: peer,
                    prefix: IpPrefix::V4 {
                        addr: [192, 0, 2, i],
                        prefix_len: 32,
                    },
                    nexthops: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, i))],
                    path_id: None,
                    local_pref: None,
                })
                .await
                .expect("v4 Add");
            let a = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16);
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: peer,
                    prefix: IpPrefix::V6 {
                        addr: a.octets(),
                        prefix_len: 128,
                    },
                    nexthops: vec![IpAddr::V6(a)],
                    path_id: None,
                    local_pref: None,
                })
                .await
                .expect("v6 Add");
        }
    });

    // Six distinct nexthops from one pool: no family partitioning, no
    // id reuse across families.
    let mut ids = Vec::new();
    for i in 0..3u8 {
        ids.push(h.read_fib_v4([192, 0, 2, i], 32).expect("v4 fib").idx);
        let a = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16);
        ids.push(h.read_fib_v6(a.octets(), 128).expect("v6 fib").idx);
    }
    let unique: std::collections::HashSet<u32> = ids.iter().copied().collect();
    assert_eq!(unique.len(), 6, "each host consumes its own slot: {ids:?}");

    // Family tags still discriminate even though the pool is shared.
    for i in 0..3u8 {
        let v4_idx = h.read_fib_v4([192, 0, 2, i], 32).unwrap().idx;
        assert_eq!(h.read_nexthop(v4_idx).family, NH_FAMILY_V4);
        let a = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i as u16);
        let v6_idx = h.read_fib_v6(a.octets(), 128).unwrap().idx;
        assert_eq!(h.read_nexthop(v6_idx).family, NH_FAMILY_V6);
    }
}

#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn ecmp_groups_dedup_by_signature() {
    let h = ProgrammerHarness::new();
    let nhs: Vec<IpAddr> = vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 12)),
    ];

    h.run(async {
        for addr in [[192, 0, 2, 0], [198, 51, 100, 0]] {
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: PeerId(0xeeee),
                    prefix: IpPrefix::V4 {
                        addr,
                        prefix_len: 24,
                    },
                    nexthops: nhs.clone(),
                    path_id: None,
                    local_pref: None,
                })
                .await
                .expect("apply Add");
        }
    });

    // Both prefixes should point at the same ECMP group ID.
    let fib_a = h.read_fib_v4([192, 0, 2, 0], 24).expect("first prefix");
    let fib_b = h.read_fib_v4([198, 51, 100, 0], 24).expect("second prefix");
    assert_eq!(fib_a.kind, FIB_KIND_ECMP);
    assert_eq!(fib_b.kind, FIB_KIND_ECMP);
    assert_eq!(
        fib_a.idx, fib_b.idx,
        "prefixes sharing nexthop set should dedup to same ECMP group"
    );
}

// --- RFC 7911 ADD-PATH aggregation (slice 4) -----------------------

/// Two `RouteEvent::Add`s for the same prefix with distinct
/// `(peer_id, path_id)` and different next-hops should aggregate
/// into one ECMP group on that prefix. The data plane writes a
/// `FIB_KIND_ECMP` entry whose group contains both next-hops; the
/// new path_id-keyed aggregation in `FibProgrammer` is what surfaces
/// this from independent BGP UPDATEs.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_path_two_paths_one_prefix_yields_ecmp() {
    let h = ProgrammerHarness::new();
    let prefix = IpPrefix::V4 {
        addr: [192, 0, 2, 0],
        prefix_len: 24,
    };
    let nh_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let nh_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer = PeerId(0x1111);

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer,
                prefix,
                nexthops: vec![nh_a],
                path_id: Some(1),
                local_pref: None,
            })
            .await
            .expect("apply Add path 1");
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer,
                prefix,
                nexthops: vec![nh_b],
                path_id: Some(2),
                local_pref: None,
            })
            .await
            .expect("apply Add path 2");
    });

    let fib = h.read_fib_v4([192, 0, 2, 0], 24).expect("FIB entry");
    assert_eq!(
        fib.kind, FIB_KIND_ECMP,
        "two distinct (peer, path_id) advertisements should yield ECMP"
    );
    let group = h.read_ecmp_group(fib.idx);
    assert_eq!(group.nh_count, 2);
}

/// Add two ADD-PATH advertisements that result in an ECMP group;
/// withdrawing one should collapse the FIB entry back to a single-NH
/// `FIB_KIND_SINGLE` entry. The ECMP group's slot is freed for reuse.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_path_withdrawal_collapses_to_single_nh() {
    let h = ProgrammerHarness::new();
    let prefix = IpPrefix::V4 {
        addr: [198, 51, 100, 0],
        prefix_len: 24,
    };
    let nh_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 11));
    let nh_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 12));
    let peer = PeerId(0x2222);

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer,
                prefix,
                nexthops: vec![nh_a],
                path_id: Some(1),
                local_pref: None,
            })
            .await
            .expect("apply Add A");
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer,
                prefix,
                nexthops: vec![nh_b],
                path_id: Some(2),
                local_pref: None,
            })
            .await
            .expect("apply Add B");
    });

    let fib_ecmp = h
        .read_fib_v4([198, 51, 100, 0], 24)
        .expect("FIB after both Adds");
    assert_eq!(fib_ecmp.kind, FIB_KIND_ECMP);

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: peer,
                prefix,
                path_id: Some(2),
            })
            .await
            .expect("apply Del B");
    });

    let fib_single = h
        .read_fib_v4([198, 51, 100, 0], 24)
        .expect("FIB after one withdrawal");
    assert_eq!(
        fib_single.kind, FIB_KIND_SINGLE,
        "collapsing to one advertisement should produce single-NH"
    );
}

/// ADD-PATH-style advertisements from two distinct peers contributing
/// one next-hop each should merge into a single ECMP group on the
/// shared prefix. This is the multi-transit aggregation scenario
/// that motivates RFC 7911 in PacketFrame: bird emits separate
/// UPDATEs per upstream peer, each tagged with its own path_id;
/// the programmer composes them into one multi-NH FIB entry.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_path_two_peers_two_paths_merge() {
    let h = ProgrammerHarness::new();
    let prefix = IpPrefix::V4 {
        addr: [203, 0, 113, 0],
        prefix_len: 24,
    };
    let nh_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 21));
    let nh_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 22));
    let peer_a = PeerId(0x3333);
    let peer_b = PeerId(0x4444);

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer_a,
                prefix,
                nexthops: vec![nh_a],
                path_id: Some(1),
                local_pref: None,
            })
            .await
            .expect("apply Add peer_a");
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer_b,
                prefix,
                nexthops: vec![nh_b],
                path_id: Some(1),
                local_pref: None,
            })
            .await
            .expect("apply Add peer_b");
    });

    let fib = h.read_fib_v4([203, 0, 113, 0], 24).expect("FIB entry");
    assert_eq!(
        fib.kind, FIB_KIND_ECMP,
        "advertisements from two peers should merge into ECMP"
    );
    let group = h.read_ecmp_group(fib.idx);
    assert_eq!(group.nh_count, 2);
}

/// `PeerDown` for a peer that contributed multiple ADD-PATH
/// advertisements to a prefix should drop only that peer's
/// contributions. The prefix survives if any other peer still
/// advertises it, with a recomputed NH set; the prefix is torn
/// down only when no advertisements remain.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_path_peer_down_clears_all_paths_for_peer() {
    let h = ProgrammerHarness::new();
    let prefix = IpPrefix::V4 {
        addr: [192, 0, 2, 0],
        prefix_len: 24,
    };
    let nh_a1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 31));
    let nh_a2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 32));
    let nh_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 33));
    let peer_a = PeerId(0x5555);
    let peer_b = PeerId(0x6666);

    h.run(async {
        // peer_a contributes two advertisements; peer_b contributes one.
        for (path_id, nh) in [(Some(1), nh_a1), (Some(2), nh_a2)] {
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: peer_a,
                    prefix,
                    nexthops: vec![nh],
                    path_id,
                    local_pref: None,
                })
                .await
                .expect("apply Add peer_a");
        }
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer_b,
                prefix,
                nexthops: vec![nh_b],
                path_id: Some(1),
                local_pref: None,
            })
            .await
            .expect("apply Add peer_b");
    });

    // Three contributing advertisements; FIB should be a 3-NH ECMP.
    let fib_before = h.read_fib_v4([192, 0, 2, 0], 24).expect("FIB after Adds");
    assert_eq!(fib_before.kind, FIB_KIND_ECMP);
    let group_before = h.read_ecmp_group(fib_before.idx);
    assert_eq!(group_before.nh_count, 3);

    // PeerDown peer_a sweeps both of its advertisements. peer_b's
    // single advertisement survives, so the prefix collapses to
    // single-NH.
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::PeerDown { peer_id: peer_a })
            .await
            .expect("apply PeerDown peer_a");
    });

    let fib_after = h
        .read_fib_v4([192, 0, 2, 0], 24)
        .expect("FIB survives with peer_b's advertisement");
    assert_eq!(
        fib_after.kind, FIB_KIND_SINGLE,
        "remaining single advertisement should be single-NH"
    );
}

/// Back-compat guard: a non-ADD-PATH session emits `path_id: None`
/// on every Add. Two such Adds from the same peer for the same
/// prefix must REPLACE rather than aggregate. This preserves the
/// pre-ADD-PATH semantics for BMP, netlink, and any iBGP session
/// where capability 69 was not mutually negotiated.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn non_add_path_session_still_replaces() {
    let h = ProgrammerHarness::new();
    let prefix = IpPrefix::V4 {
        addr: [198, 51, 100, 0],
        prefix_len: 24,
    };
    let nh_first = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 41));
    let nh_second = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42));
    let peer = PeerId(0x7777);

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer,
                prefix,
                nexthops: vec![nh_first],
                path_id: None,
                local_pref: None,
            })
            .await
            .expect("apply first Add");
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer,
                prefix,
                nexthops: vec![nh_second],
                path_id: None,
                local_pref: None,
            })
            .await
            .expect("apply second Add");
    });

    let fib = h.read_fib_v4([198, 51, 100, 0], 24).expect("FIB entry");
    assert_eq!(
        fib.kind, FIB_KIND_SINGLE,
        "two Adds with path_id=None from same peer must replace, not aggregate"
    );

    // A single Del under the same (peer, None) key should remove the
    // prefix entirely. If the second Add had aggregated instead of
    // replaced, the prefix would still hold the first advertisement
    // after this withdrawal.
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: peer,
                prefix,
                path_id: None,
            })
            .await
            .expect("apply Del");
    });

    assert!(
        h.read_fib_v4([198, 51, 100, 0], 24).is_none(),
        "Del under same (peer, None) key removes the prefix; \
         confirms only one advertisement existed after the replace"
    );

    // Silence unused-binding warnings; the literal values are part
    // of the test's intent even though we no longer read them back
    // from NEXTHOPS to verify identity.
    let _ = (nh_first, nh_second);
}

// --- Local-pref-tier filtering (slice 6) ---------------------------

/// Two advertisements for the same prefix at different local-pref
/// tiers (e.g., an IX peer at 150 and a transit at 100): only the
/// higher-LP advertisement contributes to the installed FIB entry.
/// Lower-tier advertisements stay in the per-prefix mirror so that a
/// subsequent withdrawal of the higher-tier path promotes them
/// without a fresh announce, but they do not affect forwarding while
/// a higher tier is present.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_path_higher_lp_tier_wins_over_lower() {
    let h = ProgrammerHarness::new();
    let prefix = IpPrefix::V4 {
        addr: [192, 0, 2, 0],
        prefix_len: 24,
    };
    let nh_ix = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let nh_transit = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let peer_ix = PeerId(0x8001);
    let peer_transit = PeerId(0x8002);

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer_ix,
                prefix,
                nexthops: vec![nh_ix],
                path_id: Some(1),
                local_pref: Some(150),
            })
            .await
            .expect("apply IX-tier Add");
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer_transit,
                prefix,
                nexthops: vec![nh_transit],
                path_id: Some(1),
                local_pref: Some(100),
            })
            .await
            .expect("apply transit-tier Add");
    });

    let fib = h.read_fib_v4([192, 0, 2, 0], 24).expect("FIB entry");
    assert_eq!(
        fib.kind, FIB_KIND_SINGLE,
        "higher LP-tier (150) wins; transit (100) suppressed under LP filter"
    );
    // Read the NH that's actually installed: the entry's idx points at
    // NEXTHOPS[idx] which we can spot-check is a resolved-state slot.
    let entry = h.read_nexthop(fib.idx);
    assert_eq!(
        entry.state, NH_STATE_INCOMPLETE,
        "single-NH installed (LP filter selected the IX path)"
    );
}

/// Three advertisements: two at the top tier (LP 150) and one at a
/// lower tier (LP 100). The FIB entry must ECMP across the two LP-150
/// next-hops only; the LP-100 path stays masked while the IX tier has
/// any path present.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_path_ecmp_within_top_lp_tier() {
    let h = ProgrammerHarness::new();
    let prefix = IpPrefix::V4 {
        addr: [198, 51, 100, 0],
        prefix_len: 24,
    };
    let nh_ix_a = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let nh_ix_b = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));
    let nh_transit = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let peer_ix_a = PeerId(0x9001);
    let peer_ix_b = PeerId(0x9002);
    let peer_transit = PeerId(0x9003);

    h.run(async {
        for (peer, nh, lp) in [
            (peer_ix_a, nh_ix_a, 150),
            (peer_ix_b, nh_ix_b, 150),
            (peer_transit, nh_transit, 100),
        ] {
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: peer,
                    prefix,
                    nexthops: vec![nh],
                    path_id: Some(1),
                    local_pref: Some(lp),
                })
                .await
                .expect("apply Add");
        }
    });

    let fib = h.read_fib_v4([198, 51, 100, 0], 24).expect("FIB entry");
    assert_eq!(
        fib.kind, FIB_KIND_ECMP,
        "two LP-150 advertisements ECMP; LP-100 advertisement does not contribute"
    );
    let group = h.read_ecmp_group(fib.idx);
    assert_eq!(
        group.nh_count, 2,
        "ECMP group spans only the top-LP-tier paths (2 of 3)"
    );
}

/// LP demotion: when the top-tier advertisement is withdrawn, the
/// next-best tier's advertisements promote into the FIB entry. The
/// LP-100 path that was masked behind LP-150 takes over without
/// requiring a fresh announce; its advertisement record was retained
/// throughout.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_path_lp_demotion_promotes_lower_tier_on_top_tier_withdrawal() {
    let h = ProgrammerHarness::new();
    let prefix = IpPrefix::V4 {
        addr: [203, 0, 113, 0],
        prefix_len: 24,
    };
    let nh_ix = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
    let nh_transit = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1));
    let peer_ix = PeerId(0xa001);
    let peer_transit = PeerId(0xa002);

    h.run(async {
        // Both tiers present; top tier wins.
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer_ix,
                prefix,
                nexthops: vec![nh_ix],
                path_id: Some(1),
                local_pref: Some(150),
            })
            .await
            .expect("apply IX Add");
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer_transit,
                prefix,
                nexthops: vec![nh_transit],
                path_id: Some(1),
                local_pref: Some(100),
            })
            .await
            .expect("apply transit Add");
    });

    let fib_with_ix = h
        .read_fib_v4([203, 0, 113, 0], 24)
        .expect("FIB after both Adds");
    assert_eq!(fib_with_ix.kind, FIB_KIND_SINGLE);

    h.run(async {
        // Withdraw the IX advertisement. The transit advertisement
        // stays in the mirror and now becomes the top tier.
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: peer_ix,
                prefix,
                path_id: Some(1),
            })
            .await
            .expect("apply IX Del");
    });

    let fib_after_demotion = h
        .read_fib_v4([203, 0, 113, 0], 24)
        .expect("FIB still present via transit");
    assert_eq!(
        fib_after_demotion.kind, FIB_KIND_SINGLE,
        "transit advertisement promotes to top tier when IX path is withdrawn"
    );
}

/// Back-compat: `local_pref: None` is treated as the RFC 4271 default
/// of 100. An advertisement with explicit LP 100 and an advertisement
/// with `None` are at the same tier and ECMP together. This guards
/// non-BGP sources (netlink seeding, BMP elements without LOCAL_PREF)
/// from being inadvertently suppressed by the LP filter.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_path_lp_none_treated_as_default_100() {
    let h = ProgrammerHarness::new();
    let prefix = IpPrefix::V4 {
        addr: [192, 0, 2, 0],
        prefix_len: 24,
    };
    let nh_explicit = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let nh_implicit = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let peer_explicit = PeerId(0xb001);
    let peer_implicit = PeerId(0xb002);

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer_explicit,
                prefix,
                nexthops: vec![nh_explicit],
                path_id: None,
                local_pref: Some(100),
            })
            .await
            .expect("apply explicit-100 Add");
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer_implicit,
                prefix,
                nexthops: vec![nh_implicit],
                path_id: None,
                local_pref: None,
            })
            .await
            .expect("apply None-LP Add");
    });

    let fib = h.read_fib_v4([192, 0, 2, 0], 24).expect("FIB entry");
    assert_eq!(
        fib.kind, FIB_KIND_ECMP,
        "LP=None defaults to 100 and ECMPs with explicit-LP=100 advertisement"
    );
    let group = h.read_ecmp_group(fib.idx);
    assert_eq!(group.nh_count, 2);
}

/// Destination-cache generation ownership: every real LPM mutation
/// bumps FIB_CACHE_CFG.generation, no-op recomputes don't, enable /
/// disable transitions bump and publish, and torn-down nexthop slots
/// are grace-deferred (never tombstoned instantly) so a cached
/// FibValue can't observe a freed-and-reused slot.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn fib_cache_generation_semantics() {
    let h = ProgrammerHarness::new_with_cache();
    let prefix = IpPrefix::V4 {
        addr: [203, 0, 113, 0],
        prefix_len: 24,
    };
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 21));
    let peer = PeerId(0x3333);
    let add = RouteEvent::Add {
        peer_id: peer,
        prefix,
        nexthops: vec![nh],
        path_id: None,
        local_pref: None,
    };
    // Awaited no-op used as an ordering barrier behind the
    // fire-and-forget toggle command (the loop is single-threaded, so
    // a replied command proves everything queued before it ran).
    let barrier = RouteEvent::Del {
        peer_id: PeerId(0x9999),
        prefix: IpPrefix::V4 {
            addr: [192, 0, 2, 0],
            prefix_len: 24,
        },
        path_id: None,
    };

    // Before enable: map is kernel-zeroed (off).
    let cfg0 = h.read_cache_cfg();
    assert_eq!(cfg0.enabled, 0);
    assert_eq!(cfg0.generation, 0);

    // Enable: transition bumps (1 → 2) and publishes.
    h.handle.set_cache_enabled_nowait(true);
    h.run(async {
        h.handle.apply_route_event(barrier.clone()).await.unwrap();
    });
    let cfg1 = h.read_cache_cfg();
    assert_eq!(cfg1.enabled, 1);
    assert_eq!(
        cfg1.generation, 2,
        "enable transition bumps past the initial 1"
    );

    // Real Add → write_fib_entry bumps.
    h.run(async {
        h.handle.apply_route_event(add.clone()).await.unwrap();
    });
    let cfg2 = h.read_cache_cfg();
    assert_eq!(cfg2.generation, 3, "LPM insert bumps");

    // Identical re-Add → no-change shortcut, no bump.
    h.run(async {
        h.handle.apply_route_event(add.clone()).await.unwrap();
    });
    assert_eq!(
        h.read_cache_cfg().generation,
        3,
        "no-op recompute must not flush the cache"
    );

    // Capture the nexthop slot before withdrawal.
    let nexthops: Array<MapData, NexthopEntry> = open_array(&h.pins.path("NEXTHOPS"));
    let entry_before: NexthopEntry = nexthops.get(&0, 0).expect("NEXTHOPS[0]");
    assert_ne!(
        entry_before.state,
        packetframe_fast_path::fib::types::NH_STATE_FAILED
    );

    // Del → delete_fib_entry bumps, and the slot is grace-deferred:
    // immediately after the (awaited) Del it must NOT be tombstoned.
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: peer,
                prefix,
                path_id: None,
            })
            .await
            .unwrap();
    });
    assert_eq!(h.read_cache_cfg().generation, 4, "LPM remove bumps");
    let entry_now: NexthopEntry = nexthops.get(&0, 0).expect("NEXTHOPS[0]");
    assert_ne!(
        entry_now.state,
        packetframe_fast_path::fib::types::NH_STATE_FAILED,
        "reclaim must be grace-deferred, not immediate"
    );
    // After the 100 ms grace + a few 50 ms reclaim ticks, the slot is
    // tombstoned.
    h.run(async {
        tokio::time::sleep(Duration::from_millis(350)).await;
    });
    let entry_later: NexthopEntry = nexthops.get(&0, 0).expect("NEXTHOPS[0]");
    assert_eq!(
        entry_later.state,
        packetframe_fast_path::fib::types::NH_STATE_FAILED,
        "grace elapsed → slot tombstoned"
    );

    // Disable: transition bumps and publishes enabled = 0.
    h.handle.set_cache_enabled_nowait(false);
    h.run(async {
        h.handle.apply_route_event(barrier).await.unwrap();
    });
    let cfg_off = h.read_cache_cfg();
    assert_eq!(cfg_off.enabled, 0);
    assert_eq!(cfg_off.generation, 5, "disable transition bumps");

    // Same-value command is a no-op.
    h.handle.set_cache_enabled_nowait(false);
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: PeerId(0x9998),
                prefix: IpPrefix::V4 {
                    addr: [192, 0, 2, 0],
                    prefix_len: 25,
                },
                path_id: None,
            })
            .await
            .unwrap();
    });
    assert_eq!(
        h.read_cache_cfg().generation,
        5,
        "same-value toggle is a no-op"
    );
}

// ========== Second-tier sink (Phase 4) ==========

/// The announcement carries the **resolved** union, not the union of
/// what peers advertised.
///
/// This is the test that pins the seam to the right layer. Two peers
/// advertise the same prefix at different LOCAL_PREF; the programmer's
/// tiering keeps only the winning tier, and the second tier must be told
/// that — not both nexthops. Teeing `RouteEvent`s where they enter the
/// controller would pass this prefix along with `10.0.0.2` included, and
/// the two forwarding tiers would then disagree about where the traffic
/// goes, discovered during a failover.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn the_sink_is_told_the_resolved_union_not_the_advertisements() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let prefix = IpPrefix::V4 {
        addr: [203, 0, 113, 0],
        prefix_len: 24,
    };
    let winner = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let loser = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    h.run(async {
        // Low tier first, so the second Add must *displace* it rather
        // than merely fail to add to it.
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: PeerId(0x1111),
                prefix,
                nexthops: vec![loser],
                path_id: None,
                local_pref: Some(100),
            })
            .await
            .expect("apply low-pref Add");
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: PeerId(0x2222),
                prefix,
                nexthops: vec![winner],
                path_id: None,
                local_pref: Some(150),
            })
            .await
            .expect("apply high-pref Add");
    });

    let calls = sink.calls();
    assert_eq!(
        calls.last(),
        Some(&SinkCall::Resolved(prefix, vec![winner])),
        "the latest announcement must be the winning tier alone; got {calls:?}"
    );
    assert!(
        !calls
            .iter()
            .any(|c| matches!(c, SinkCall::Resolved(_, nhs) if nhs.contains(&loser) && nhs.contains(&winner))),
        "no announcement may ever have merged the two local-pref tiers: {calls:?}"
    );
}

/// Local-ARP routes never reach the second tier as installs.
///
/// They describe LOCAL delivery — hosts behind the switch0 bridges —
/// which VPP deliberately does not do (no VLAN subifs; this tier's
/// FDB-pin owns that path). Announced, they would sit in the sink as
/// routes whose nexthop device is a bridge: permanently unresolvable,
/// failing every readback verify on exactly the boxes that use
/// `local-prefix`. The shadow has none, so only this test and the
/// primary can catch a regression.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn local_arp_routes_do_not_reach_the_sink_as_installs() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let local = IpPrefix::V4 {
        addr: [192, 0, 2, 50],
        prefix_len: 32,
    };
    let transit = IpPrefix::V4 {
        addr: [203, 0, 113, 0],
        prefix_len: 24,
    };
    let host = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: PeerId::local_arp(33),
                prefix: local,
                nexthops: vec![host],
                path_id: None,
                local_pref: None,
            })
            .await
            .expect("apply local-arp Add");
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: PeerId(0x2222),
                prefix: transit,
                nexthops: vec![nh],
                path_id: None,
                local_pref: Some(100),
            })
            .await
            .expect("apply BGP Add");
    });

    let calls = sink.calls();
    assert!(
        !calls
            .iter()
            .any(|c| matches!(c, SinkCall::Resolved(p, _) if *p == local)),
        "a local-arp /32 must never be announced as installable: {calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|c| matches!(c, SinkCall::Resolved(p, _) if *p == transit)),
        "the filter must not eat ordinary BGP routes: {calls:?}"
    );
    // The local-only commit announces as a WITHDRAWAL rather than
    // going quiet — transition safety: a record whose BGP owners left
    // while a local-ARP one remained has been announced before, and
    // silence would leave the second tier holding its last BGP-era
    // state forever. For a from-birth local record it is a designed
    // no-op at the feed.
    assert!(
        calls
            .iter()
            .any(|c| matches!(c, SinkCall::Withdrawn(p) if *p == local)),
        "the local-only commit must withdraw, not go quiet: {calls:?}"
    );
}

/// The `fallback-default` reaches the second tier.
///
/// It is injected under a local-ARP peer like the `local-prefix` /32s,
/// so it scopes with them and never counts as a session route — but it
/// is a gatewayed route via a real upstream, not local delivery.
/// Filtered with the /32s, the second tier's FIB lacked it and dropped
/// every destination only the default covers, which this tier forwards
/// (the primary, 2026-09-26, 167 pps once steering went live).
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn the_fallback_default_reaches_the_sink() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let default = IpPrefix::V4 {
        addr: [0, 0, 0, 0],
        prefix_len: 0,
    };
    let upstream = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: PeerId::local_arp(33),
                prefix: default,
                nexthops: vec![upstream],
                path_id: None,
                local_pref: None,
            })
            .await
            .expect("apply fallback-default Add");
    });

    let calls = sink.calls();
    assert!(
        calls.iter().any(
            |c| matches!(c, SinkCall::Resolved(p, nhs) if *p == default && nhs == &vec![upstream])
        ),
        "the fallback default must be announced via its upstream: {calls:?}"
    );
    assert!(
        !calls
            .iter()
            .any(|c| matches!(c, SinkCall::Withdrawn(p) if *p == default)),
        "and never withdrawn as if it were local delivery: {calls:?}"
    );
}

/// A route-source reconnect garbage-collects the route source's
/// advertisements and nothing else.
///
/// The neighbour resolver injects `fallback-default` and `local-prefix`
/// routes under `PeerId::local_arp`: the 0/0 once at startup, each host
/// route when its neighbour is learned. No session ever re-announces
/// them. `Resync` used to mark every advertisement in the mirror, so the
/// GC at the next `InitiationComplete` deleted the 0/0 and every host
/// route not refreshed in between. That happened after each BGP
/// reconnect, and every FRR config upload restarts bgpd. The same GC
/// withdrew the default from the second tier, whose only view of the
/// FIB is this sink.
///
/// The 0/0 also carries a BGP advertisement that the second session
/// does not repeat. The GC must therefore act on advertisements, not
/// records: it drops the BGP path and keeps the fallback.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn a_reconnect_gc_spares_the_fallback_default_and_local_prefix_routes() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let bgp = PeerId(0x7070);
    let default = IpPrefix::V4 {
        addr: [0, 0, 0, 0],
        prefix_len: 0,
    };
    let fallback_nh = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let bgp_default_nh = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    let bgp_nh = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
    let host = IpPrefix::V4 {
        addr: [192, 0, 2, 50],
        prefix_len: 32,
    };
    let host_nh = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));
    let host6 = IpPrefix::V6 {
        addr: v6("2001:db8::50"),
        prefix_len: 128,
    };
    let host6_nh = IpAddr::V6("2001:db8::50".parse().unwrap());
    // Announced by both sessions, by the first only, by the second only.
    let kept = IpPrefix::V4 {
        addr: [198, 51, 100, 0],
        prefix_len: 24,
    };
    let stale = IpPrefix::V4 {
        addr: [192, 0, 2, 128],
        prefix_len: 25,
    };
    let fresh = IpPrefix::V4 {
        addr: [203, 0, 113, 128],
        prefix_len: 25,
    };

    let add = |peer_id: PeerId, prefix: IpPrefix, nh: IpAddr| RouteEvent::Add {
        peer_id,
        prefix,
        nexthops: vec![nh],
        path_id: None,
        local_pref: None,
    };

    // Startup: the resolver's seeds, then the first session's table.
    h.run(async {
        for event in [
            add(PeerId::local_arp(33), default, fallback_nh),
            add(PeerId::local_arp(34), host, host_nh),
            add(PeerId::local_arp(34), host6, host6_nh),
            add(bgp, default, bgp_default_nh),
            add(bgp, kept, bgp_nh),
            add(bgp, stale, bgp_nh),
        ] {
            h.handle
                .apply_route_event(event)
                .await
                .expect("apply first-session Add");
        }
    });

    // The session drops and a new one dumps its table, without `stale`
    // and without its default this time. The resolver sends nothing:
    // no neighbour changed.
    let gc = h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Resync)
            .await
            .expect("apply Resync");
        for prefix in [kept, fresh] {
            h.handle
                .apply_route_event(add(bgp, prefix, bgp_nh))
                .await
                .expect("apply second-session Add");
        }
        h.handle
            .apply_route_event(RouteEvent::InitiationComplete)
            .await
    });
    assert!(gc.is_ok(), "the GC must complete: {gc:?}");

    // Presence below is checked by exact key: with the default
    // installed, a longest-prefix lookup finds something for every
    // address and would pass for a deleted route.
    let calls = sink.calls();
    // The premise: the GC really ran over this session. Without it every
    // survival below would hold vacuously.
    assert!(
        !h.fib_v4_has([192, 0, 2, 128], 25) && calls.contains(&SinkCall::Withdrawn(stale)),
        "the first session's unrepeated route must be collected: {calls:?}"
    );
    assert!(
        h.fib_v4_has([198, 51, 100, 0], 24) && h.fib_v4_has([203, 0, 113, 128], 25),
        "the second session's routes must be installed"
    );

    // The fallback default survives, in both tiers, through its own
    // upstream alone.
    assert!(
        h.fib_v4_has([0, 0, 0, 0], 0),
        "the GC deleted the fallback default from FIB_V4; sink calls: {calls:?}"
    );
    // A /0 lookup can only match the /0 itself.
    assert_eq!(
        h.read_fib_v4([0, 0, 0, 0], 0).map(|fv| fv.kind),
        Some(FIB_KIND_SINGLE),
        "the default must narrow to the fallback alone once the BGP path is collected"
    );
    assert!(
        !calls.contains(&SinkCall::Withdrawn(default)),
        "the second tier was told to withdraw its default: {calls:?}"
    );
    assert_eq!(
        calls.iter().rev().find(
            |c| matches!(c, SinkCall::Resolved(p, _) | SinkCall::Withdrawn(p) if *p == default)
        ),
        Some(&SinkCall::Resolved(default, vec![fallback_nh])),
        "the second tier's last word on the default must be the fallback upstream: {calls:?}"
    );

    // The local-prefix host routes survive, at both families.
    assert!(
        h.fib_v4_has([192, 0, 2, 50], 32),
        "the GC deleted a local-prefix /32"
    );
    assert!(
        h.fib_v6_has(v6("2001:db8::50"), 128),
        "the GC deleted a local-prefix6 /128"
    );
}

/// A withdrawal reaches the sink, and by the same path for every way a
/// prefix can stop forwarding.
///
/// `Del` and `PeerDown` are asserted together because the claim in the
/// programmer is that they *share* the removal site — that is what makes
/// "one notification site covers every withdrawal" true rather than
/// hopeful. If they ever stop sharing it, one of these two halves fails.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn every_way_a_prefix_stops_forwarding_reaches_the_sink() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let by_del = IpPrefix::V4 {
        addr: [198, 18, 0, 0],
        prefix_len: 24,
    };
    let by_peer_down = IpPrefix::V4 {
        addr: [198, 18, 1, 0],
        prefix_len: 24,
    };
    let peer = PeerId(0x3333);

    h.run(async {
        for prefix in [by_del, by_peer_down] {
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: peer,
                    prefix,
                    nexthops: vec![nh],
                    path_id: None,
                    local_pref: None,
                })
                .await
                .expect("apply Add");
        }
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: peer,
                prefix: by_del,
                path_id: None,
            })
            .await
            .expect("apply Del");
        h.handle
            .apply_route_event(RouteEvent::PeerDown { peer_id: peer })
            .await
            .expect("apply PeerDown");
    });

    let calls = sink.calls();
    assert!(
        calls.contains(&SinkCall::Withdrawn(by_del)),
        "an explicit Del must be announced: {calls:?}"
    );
    assert!(
        calls.contains(&SinkCall::Withdrawn(by_peer_down)),
        "a PeerDown's routes must be announced as withdrawn too — if this \
         fails, PeerDown no longer shares the mirror-removal site: {calls:?}"
    );
    // Ordering, not just presence: a withdrawal announced before its
    // install would leave the second tier forwarding a dead prefix.
    let install = calls
        .iter()
        .position(|c| matches!(c, SinkCall::Resolved(p, _) if *p == by_del))
        .expect("install announced");
    let withdraw = calls
        .iter()
        .position(|c| *c == SinkCall::Withdrawn(by_del))
        .expect("withdrawal announced");
    assert!(install < withdraw, "install must precede withdrawal");
}

/// An entry that has already left the map is a completed withdrawal,
/// not a failure — and the sink hears it either way.
///
/// The mirror and the LPM trie can disagree (a delete that landed while
/// its reply was lost, an out-of-band removal), and the delete's GOAL is
/// "no such entry". Reporting ENOENT as a map fault made that
/// disagreement look like a broken map, and — now that
/// `has_session_routes` counts unrepaired deletions — would hold a
/// second tier's deferral open over a prefix that is already gone. Same
/// rule and reasoning as `ntuple::Removal::AlreadyAbsent`; every other
/// errno still fails loudly.
///
/// The withdrawal reaching the sink is asserted alongside it because the
/// two travel together: `withdraw_from_mirror` removes and notifies as
/// one step, before the fallible delete, precisely so the second tier is
/// never stranded by whatever the map does next.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn an_entry_already_gone_from_the_map_is_a_completed_withdrawal() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let prefix = IpPrefix::V4 {
        addr: [198, 18, 9, 0],
        prefix_len: 24,
    };
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let peer = PeerId(0x4444);

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: peer,
                prefix,
                nexthops: vec![nh],
                path_id: None,
                local_pref: None,
            })
            .await
            .expect("apply Add");
    });

    // Remove the entry behind the programmer's back through a second
    // handle to the same pin (see the module docstring), so its own
    // delete meets ENOENT.
    let mut fib_v4 = open_lpm_v4(&h.pins.path("FIB_V4"));
    fib_v4
        .remove(&LpmKey::new(24, [198, 18, 9, 0]))
        .expect("out-of-band delete of the entry the programmer installed");

    let del = h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: peer,
                prefix,
                path_id: None,
            })
            .await
    });

    assert!(
        del.is_ok(),
        "an entry that is already gone is the outcome a delete wanted: {del:?}"
    );
    let calls = sink.calls();
    assert!(
        calls.contains(&SinkCall::Withdrawn(prefix)),
        "the second tier must hear the withdrawal regardless of what the \
         map did: {calls:?}"
    );
    // Nothing owed either, so a second tier asking whether this session
    // left anything behind gets a clean answer rather than a deferral
    // held open over a prefix that is already gone.
    assert!(
        !h.run(async { h.handle.has_session_routes().await.expect("query") }),
        "an already-absent entry leaves no repair outstanding"
    );
}

/// A GC whose recompute failed keeps reporting failure until it
/// actually reconciles — and then announces the corrected set.
///
/// `gc_unseen` drains the unseen advertisements before recomputing, so
/// its failure is not retryable by re-running the sweep: the victims
/// are gone and the next GC collects none. Reporting `Ok(0)` there is
/// the dangerous answer, because the prefix is still installed with the
/// *withdrawn* stream's nexthops and the second tier reads a successful
/// GC as "the mirror is current" — which is exactly the evidence the
/// BMP station clears its stale-state suspicion on.
///
/// The failure is injected by exhausting the ECMP group pool: after the
/// GC drops one of the target's two advertisements, the remaining
/// nexthop set is a new signature and has nowhere to allocate. Freeing
/// a group afterwards proves the debt clears on reconciliation rather
/// than latching.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn a_failed_gc_recompute_is_owed_until_it_reconciles() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let peer_old = PeerId(0x5150);
    let peer_new = PeerId(0x5151);
    let target = IpPrefix::V4 {
        addr: [198, 18, 20, 0],
        prefix_len: 24,
    };
    let nh_old = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
    let nh_a = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 2));
    let nh_b = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 3));

    let add = |peer: PeerId, prefix: IpPrefix, nexthops: Vec<IpAddr>| RouteEvent::Add {
        peer_id: peer,
        prefix,
        nexthops,
        path_id: None,
        local_pref: None,
    };

    // The target takes a group of its own first, so exhausting the pool
    // below cannot deny it the set it is already installed with.
    h.run(async {
        h.handle
            .apply_route_event(add(peer_old, target, vec![nh_old]))
            .await
            .expect("target via the old stream");
        h.handle
            .apply_route_event(add(peer_new, target, vec![nh_a, nh_b]))
            .await
            .expect("target via the new stream");
    });

    // Fill the ECMP pool with distinct pairs until allocation refuses.
    // Discovered rather than hard-coded: a capacity change must not
    // turn this into a test that exercises the ordinary path.
    let mut filler: Vec<IpPrefix> = Vec::new();
    let exhausted = h.run(async {
        for i in 0..(ECMP_GROUPS_CAP + 8) {
            let prefix = IpPrefix::V4 {
                addr: [100, 64, (i >> 8) as u8, (i & 0xff) as u8],
                prefix_len: 32,
            };
            let n1 = IpAddr::V4(Ipv4Addr::from(0x0a80_0000 + i * 2));
            let n2 = IpAddr::V4(Ipv4Addr::from(0x0a80_0000 + i * 2 + 1));
            if h.handle
                .apply_route_event(add(peer_new, prefix, vec![n1, n2]))
                .await
                .is_err()
            {
                return true;
            }
            filler.push(prefix);
        }
        false
    });
    assert!(
        exhausted,
        "the ECMP pool never filled — this test cannot inject its failure"
    );

    // New session: everything is re-announced except the target's old
    // advertisement, which is what the GC must withdraw.
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Resync)
            .await
            .expect("resync");
        for (i, prefix) in filler.iter().enumerate() {
            let n1 = IpAddr::V4(Ipv4Addr::from(0x0a80_0000 + (i as u32) * 2));
            let n2 = IpAddr::V4(Ipv4Addr::from(0x0a80_0000 + (i as u32) * 2 + 1));
            h.handle
                .apply_route_event(add(peer_new, *prefix, vec![n1, n2]))
                .await
                .expect("re-announce filler");
        }
        h.handle
            .apply_route_event(add(peer_new, target, vec![nh_a, nh_b]))
            .await
            .expect("re-announce target");
    });

    let first = h.run(async {
        h.handle
            .apply_route_event(RouteEvent::InitiationComplete)
            .await
    });
    assert!(
        first.is_err(),
        "the GC recompute was supposed to fail on an exhausted pool"
    );
    assert!(
        !sink
            .calls()
            .contains(&SinkCall::Resolved(target, vec![nh_a, nh_b])),
        "the corrected set cannot have been announced — the recompute failed"
    );

    // The regression: the sweep finds no victims this time, and used to
    // report success over a prefix still carrying the withdrawn
    // stream's nexthop.
    let retry = h.run(async {
        h.handle
            .apply_route_event(RouteEvent::InitiationComplete)
            .await
    });
    assert!(
        retry.is_err(),
        "a GC that collected no victims must not report success while a \
         previous GC's recompute is still owed"
    );

    // Free a group and let the grace queue release it, then the debt
    // must clear and the second tier must hear the corrected set.
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: peer_new,
                prefix: filler[0],
                path_id: None,
            })
            .await
            .expect("free one filler");
        tokio::time::sleep(Duration::from_millis(750)).await;
    });
    let settled = h.run(async {
        h.handle
            .apply_route_event(RouteEvent::InitiationComplete)
            .await
    });
    assert!(
        settled.is_ok(),
        "with a group free the owed recompute must succeed: {settled:?}"
    );
    assert!(
        sink.calls()
            .contains(&SinkCall::Resolved(target, vec![nh_a, nh_b])),
        "the second tier must end up with the post-GC nexthop set: {:?}",
        sink.calls()
    );
}

/// `has_session_routes` answers for route-source peers only.
///
/// The mirror is shared with the neighbour resolver's `local-prefix`
/// /32s, which are resident for the daemon's life and belong to no
/// session. A caller asking "did the previous stream leave anything
/// behind" — the BMP station, at every stream boundary — must see a
/// clean slate when the session's own routes are gone, or no stream
/// ever earns its first-frame liveness raise.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn only_route_source_peers_count_as_session_routes() {
    let h = ProgrammerHarness::new();
    let session_peer = PeerId(0x6060);
    let local_peer = PeerId::local_arp(33);
    let nh = IpAddr::V4(Ipv4Addr::new(10, 3, 0, 1));
    let session_prefix = IpPrefix::V4 {
        addr: [198, 18, 30, 0],
        prefix_len: 24,
    };
    let local_prefix = IpPrefix::V4 {
        addr: [10, 3, 0, 9],
        prefix_len: 32,
    };

    let add = |peer: PeerId, prefix: IpPrefix| RouteEvent::Add {
        peer_id: peer,
        prefix,
        nexthops: vec![nh],
        path_id: None,
        local_pref: None,
    };

    h.run(async {
        assert!(
            !h.handle.has_session_routes().await.expect("query"),
            "a fresh programmer holds no session routes"
        );
        h.handle
            .apply_route_event(add(session_peer, session_prefix))
            .await
            .expect("session route");
        assert!(
            h.handle.has_session_routes().await.expect("query"),
            "a route-source advertisement counts"
        );
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: session_peer,
                prefix: session_prefix,
                path_id: None,
            })
            .await
            .expect("withdraw session route");
        assert!(
            !h.handle.has_session_routes().await.expect("query"),
            "withdrawing the session's last route leaves a clean slate"
        );
        // The local /32 arrives and must not resurrect the answer.
        h.handle
            .apply_route_event(add(local_peer, local_prefix))
            .await
            .expect("local-prefix route");
        assert!(
            !h.handle.has_session_routes().await.expect("query"),
            "a local-prefix /32 belongs to no session — counting it denies \
             every future stream its first-frame raise"
        );
        // ...and does not mask a real one either.
        h.handle
            .apply_route_event(add(session_peer, session_prefix))
            .await
            .expect("session route again");
        assert!(
            h.handle.has_session_routes().await.expect("query"),
            "a session route alongside a local one still counts"
        );
    });
}

/// `session_families` reports what the FEED delivers, not what the
/// mirror holds.
///
/// The FRR authority revokes when the feed carries a family no
/// declared upstream does. It first took that evidence from
/// `mirror_counts()`, which includes the resolver's synthetic
/// `local-prefix` routes — so a single `local-prefix6` /128 on a v4-only
/// box read as "the feed carries v6" and revoked, stickily, a valid
/// deployment (review finding, PR #234). The synthetic route here is
/// v6 and the session route is v4 on purpose: that is exactly the shape
/// that tripped it.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn session_families_ignore_local_prefix_routes() {
    let h = ProgrammerHarness::new();
    let session_peer = PeerId(0x7070);
    let local_peer = PeerId::local_arp(34);
    let nh4 = IpAddr::V4(Ipv4Addr::new(10, 3, 0, 1));
    let nh6 = IpAddr::V6("2001:db8::1".parse().expect("v6"));

    h.run(async {
        assert_eq!(
            h.handle.session_families().await.expect("query"),
            (false, false),
            "a fresh programmer carries no family"
        );

        // A synthetic local-prefix6 /128 — no session owns it.
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: local_peer,
                prefix: IpPrefix::V6 {
                    addr: "2001:db8::9"
                        .parse::<std::net::Ipv6Addr>()
                        .expect("v6")
                        .octets(),
                    prefix_len: 128,
                },
                nexthops: vec![nh6],
                path_id: None,
                local_pref: None,
            })
            .await
            .expect("local-prefix6 route");
        assert_eq!(
            h.handle.session_families().await.expect("query"),
            (false, false),
            "a local-prefix /128 is not a v6 feed"
        );
        let (_, mirror_v6) = h.handle.mirror_counts().await.expect("counts");
        assert_eq!(
            mirror_v6, 1,
            "while the whole mirror DOES count it — which is the difference that matters"
        );

        // The session delivers v4 only.
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: session_peer,
                prefix: IpPrefix::V4 {
                    addr: [198, 18, 31, 0],
                    prefix_len: 24,
                },
                nexthops: vec![nh4],
                path_id: None,
                local_pref: None,
            })
            .await
            .expect("session v4 route");
        assert_eq!(
            h.handle.session_families().await.expect("query"),
            (true, false),
            "v4 from the session, and still no v6 feed despite the synthetic /128"
        );
    });
}

/// Re-advertising an identical nexthop set announces nothing.
///
/// Not an optimisation: under a peering flap the same prefix is
/// re-advertised repeatedly with an unchanged union, and a sink that
/// re-queued each one would turn churn into work for the second tier
/// with nothing to show for it. The programmer already short-circuits
/// this for its own maps; the sink must inherit that, not sit upstream
/// of it.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn an_unchanged_nexthop_set_is_announced_once() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let prefix = IpPrefix::V4 {
        addr: [198, 18, 2, 0],
        prefix_len: 24,
    };
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    h.run(async {
        for _ in 0..3 {
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: PeerId(0x4444),
                    prefix,
                    nexthops: vec![nh],
                    path_id: None,
                    local_pref: None,
                })
                .await
                .expect("apply Add");
        }
    });

    let announcements = sink
        .calls()
        .iter()
        .filter(|c| matches!(c, SinkCall::Resolved(p, _) if *p == prefix))
        .count();
    assert_eq!(
        announcements, 1,
        "three identical Adds must announce once, not three times"
    );
}

/// Neighbour resolution and loss both reach the sink, with the egress
/// ifindex the kernel reported.
///
/// The nexthop has to be registered first: the programmer ignores neigh
/// events for IPs it holds no nexthop for, and that filter is upstream of
/// the announcement — a sink told about every neighbour on the box would
/// be told about ones it has no route through.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn neighbour_resolution_and_loss_reach_the_sink() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
    let mac = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x07];
    let ifindex = 4242;

    h.run(async { h.handle.register_nexthop(nh).await })
        .expect("register_nexthop");
    h.feed_neigh(NeighEvent::Learned {
        ip: nh,
        mac,
        ifindex,
        src_mac: [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
    });
    h.feed_neigh(NeighEvent::Gone {
        ip: nh,
        ifindex: 4242,
    });

    let calls = sink.calls();
    assert_eq!(
        calls,
        vec![
            SinkCall::NeighResolved(nh, mac, ifindex),
            SinkCall::NeighLost(nh),
        ],
        "resolution then loss, in that order and nothing else"
    );

    // An unregistered neighbour is not announced — the programmer's own
    // filter, inherited rather than duplicated.
    let stranger = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8));
    h.feed_neigh(NeighEvent::Gone {
        ip: stranger,
        ifindex: 4242,
    });
    assert_eq!(
        sink.calls().len(),
        2,
        "a neighbour we hold no nexthop for must not be announced"
    );
}

/// A customer host registered by `local-prefix6` reaches the second
/// tier as a neighbour — never as a route.
///
/// The chain a vpp-offload `local-route6` depends on: neigh-snoop writes
/// a STALE entry for a host VPP's glean solicited, the resolver turns it
/// into this `/128` Add (host as its own next hop, which is what
/// registers the host) plus a `Learned` (STALE carries a usable MAC, so
/// it parses as one), and the programmer announces the neighbour. VPP
/// takes it as a static neighbour on the BVI, where the attached `/64`
/// makes it a usable host route; the `/128` itself stays a local-ARP
/// route and is not announced as installable.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn a_local_prefix6_host_reaches_the_sink_as_a_neighbour() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let host = IpAddr::V6("2001:db8:1::51".parse().unwrap());
    let host128 = IpPrefix::V6 {
        addr: [
            0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x51,
        ],
        prefix_len: 128,
    };
    let mac = [0x02, 0, 0, 0, 0xc0, 0x51];
    let ifindex = 1337;

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Add {
                peer_id: PeerId::local_arp(ifindex),
                prefix: host128,
                nexthops: vec![host],
                path_id: None,
                local_pref: None,
            })
            .await
            .expect("apply local-arp /128 Add");
    });
    h.feed_neigh(NeighEvent::Learned {
        ip: host,
        mac,
        ifindex,
        src_mac: [0x02, 0, 0, 0, 0xb0, 0x01],
    });

    let calls = sink.calls();
    assert!(
        calls.contains(&SinkCall::NeighResolved(host, mac, ifindex)),
        "the snooped host must reach the second tier as a neighbour: {calls:?}"
    );
    assert!(
        !calls
            .iter()
            .any(|c| matches!(c, SinkCall::Resolved(p, _) if *p == host128)),
        "and its /128 never as an installable route: {calls:?}"
    );
}

/// Unregistering a nexthop tells the second tier it is gone.
///
/// This is the seam's only exit for an address, and the reason is a
/// filter rather than a policy: `on_neigh_event` ignores events for IPs
/// absent from `by_ip`, so once `unregister` removes the record no
/// future `Gone` can reach the sink. Without a notification here the
/// other tier keeps the adjacency for the life of the process.
///
/// Driven through `unregister_nexthop` rather than through the
/// motivating scenario — a prefix re-advertised from NH-A to NH-B, which
/// releases NH-A through the 100 ms grace queue — because both reach the
/// same notification site and only one of them is deterministic.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn unregistering_a_nexthop_tells_the_sink_it_is_gone() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let mac = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x09];

    h.run(async { h.handle.register_nexthop(nh).await })
        .expect("register_nexthop");
    h.feed_neigh(NeighEvent::Learned {
        ip: nh,
        mac,
        ifindex: 4242,
        src_mac: [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
    });
    assert_eq!(
        sink.calls(),
        vec![SinkCall::NeighResolved(nh, mac, 4242)],
        "resolution reaches the sink first"
    );

    h.run(async { h.handle.unregister_nexthop(nh).await })
        .expect("unregister_nexthop");
    assert_eq!(
        sink.calls().last(),
        Some(&SinkCall::NeighLost(nh)),
        "and its removal must too — nothing else can report it afterwards"
    );

    // The filter really is closed behind it: a kernel event arriving
    // after the unregister is dropped, which is what makes the
    // notification above the only one there will ever be.
    let before = sink.calls().len();
    h.feed_neigh(NeighEvent::Gone {
        ip: nh,
        ifindex: 4242,
    });
    assert_eq!(
        sink.calls().len(),
        before,
        "a post-unregister event is filtered, so it cannot substitute"
    );
}

// ========== Neighbour loss: interface filter, re-probe, tombstones ==========
//
// Background (2026-09-15): a third of the primary's traffic was taking
// the kernel path because nexthops that lost resolution were never
// re-probed, and `status` could not show it because tombstones and
// live failures shared a bucket. These pin the three behaviours that
// fix that.

/// The kernel keys neighbours `(device, address)`. A `Gone` for the
/// nexthop's address on some *other* device is a fact about a different
/// entry and must not take the nexthop off the fast path; the same
/// event on the device it is forwarding out of must.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn neighbour_loss_on_another_interface_is_ignored() {
    let (h, sink) = ProgrammerHarness::with_sink();
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 21));
    let mac = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x21];
    let live_if = 4242;

    let id = h
        .run(async { h.handle.register_nexthop(nh).await })
        .expect("register_nexthop");
    h.feed_neigh(NeighEvent::Learned {
        ip: nh,
        mac,
        ifindex: live_if,
        src_mac: [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
    });
    assert_eq!(h.read_nexthop(id).state, NH_STATE_RESOLVED);

    // Same address deleted on a device we never resolved it through.
    h.feed_neigh(NeighEvent::Gone {
        ip: nh,
        ifindex: live_if + 1,
    });
    let entry = h.read_nexthop(id);
    assert_eq!(
        entry.state, NH_STATE_RESOLVED,
        "foreign-device Gone must not demote"
    );
    assert_eq!(entry.dst_mac, mac);
    assert_eq!(entry.ifindex, live_if);
    assert_eq!(
        sink.calls(),
        vec![SinkCall::NeighResolved(nh, mac, live_if)],
        "and the second tier must not be told the neighbour is lost"
    );

    // A NUD_FAILED on the foreign device is filtered the same way.
    h.feed_neigh(NeighEvent::Failed {
        ip: nh,
        ifindex: live_if + 1,
        reason: "test".into(),
    });
    assert_eq!(h.read_nexthop(id).state, NH_STATE_RESOLVED);

    // On the live device it is the real thing.
    h.feed_neigh(NeighEvent::Gone {
        ip: nh,
        ifindex: live_if,
    });
    assert_eq!(h.read_nexthop(id).state, NH_STATE_INCOMPLETE);
    assert_eq!(sink.calls().last(), Some(&SinkCall::NeighLost(nh)));
}

/// A nexthop that loses resolution is asked about again, with backoff,
/// until the kernel answers — and stops being asked about once it does.
/// Before this the only request ever made was the one at allocation.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn lost_nexthop_is_reprobed_until_it_resolves() {
    let (h, _sink, mut resolves) = ProgrammerHarness::with_sink_and_resolver();
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 22));
    let mac = [0x02, 0x00, 0x5e, 0x10, 0x00, 0x22];
    let learned = NeighEvent::Learned {
        ip: nh,
        mac,
        ifindex: 4242,
        src_mac: [0x02, 0x00, 0x5e, 0x10, 0x00, 0x01],
    };

    h.run(async { h.handle.register_nexthop(nh).await })
        .expect("register_nexthop");
    // Allocation kicks once immediately (pre-existing behaviour).
    let first = h.drain_resolves(&mut resolves, Duration::from_millis(200));
    assert_eq!(
        first,
        vec![nh],
        "allocation issues exactly one immediate request"
    );

    // Resolved promptly: the schedule armed at allocation is cancelled,
    // so nothing further is asked over several ticks.
    h.feed_neigh(learned.clone());
    let quiet = h.drain_resolves(&mut resolves, Duration::from_millis(3500));
    assert!(
        quiet.is_empty(),
        "a resolved nexthop is not re-probed: {quiet:?}"
    );

    // Lost on the live device: the re-probe fires within the first
    // backoff step plus one tick (1 s + 1 s), generous for a TCG guest.
    h.feed_neigh(NeighEvent::Gone {
        ip: nh,
        ifindex: 4242,
    });
    let after_loss = h.drain_resolves(&mut resolves, Duration::from_millis(3500));
    assert!(
        !after_loss.is_empty() && after_loss.iter().all(|ip| *ip == nh),
        "a lost nexthop must be re-probed (got {after_loss:?})"
    );

    // Answered: the schedule is disarmed again. A request already due
    // when the Learned landed may still fire on the same tick; discard
    // that edge before asserting silence over several further ticks.
    h.feed_neigh(learned);
    let _ = h.drain_resolves(&mut resolves, Duration::from_millis(300));
    let settled = h.drain_resolves(&mut resolves, Duration::from_millis(3500));
    assert!(
        settled.is_empty(),
        "re-resolution stops the re-probes: {settled:?}"
    );
}

/// A freed slot and a live nexthop the kernel gave up on both carry
/// `state = FAILED`; `family` is what tells them apart, and the shared
/// classifier is what `status`, the exporter and `fib dump` all read.
/// Pins the write-side half of that contract: the tombstone clears
/// `family`, a live failure keeps it.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn freed_slot_reads_as_tombstone_not_as_failed_nexthop() {
    let (h, _sink) = ProgrammerHarness::with_sink();
    let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 23));

    let id = h
        .run(async { h.handle.register_nexthop(nh).await })
        .expect("register_nexthop");
    let seeded = h.read_nexthop(id);
    assert_eq!(
        NexthopSlotClass::from_entry(seeded.state, seeded.family),
        NexthopSlotClass::Incomplete,
        "the allocation seed is a live, unresolved slot — not untouched capacity"
    );

    h.feed_neigh(NeighEvent::Failed {
        ip: nh,
        ifindex: 4242,
        reason: "test".into(),
    });
    let failed = h.read_nexthop(id);
    assert_eq!(failed.state, NH_STATE_FAILED);
    assert_eq!(
        NexthopSlotClass::from_entry(failed.state, failed.family),
        NexthopSlotClass::Failed,
        "a kernel NUD_FAILED on a referenced nexthop is a live failure"
    );

    h.run(async { h.handle.unregister_nexthop(nh).await })
        .expect("unregister_nexthop");
    let freed = h.read_nexthop(id);
    assert_eq!(
        freed.state, NH_STATE_FAILED,
        "tombstone keeps the fail-closed state"
    );
    assert_eq!(
        NexthopSlotClass::from_entry(freed.state, freed.family),
        NexthopSlotClass::Freed,
        "but reads as a tombstone, so status never counts it as a failed nexthop"
    );
}

// ========== Route ledger ==========
//
// The seed a clean stop leaves for the next start, applied before any
// route event and reconciled by the live session exactly as a `Resync`
// is: re-advertisements confirm, `InitiationComplete` collects the rest.

mod ledger {
    use super::*;
    use packetframe_fast_path::fib::route_ledger::{
        encode, LedgerAdvert, LedgerMeta, LedgerRoute, RouteLedger, SharedLedgerStatus, StartReport,
    };

    pub const PEER: PeerId = PeerId(0x1ed9_e400_0000_0001);
    pub const IDENTITY: &str =
        "bgp listen 192.0.2.10 port 179 local-as 64512 peer-as 64512 peer-ip any";

    pub fn nh_a() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))
    }

    pub fn nh_b() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))
    }

    pub fn nh6() -> IpAddr {
        IpAddr::V6("2001:db8::1".parse().unwrap())
    }

    pub fn quarter(i: u8) -> IpPrefix {
        IpPrefix::V4 {
            addr: [203, 0, 113, i * 64],
            prefix_len: 26,
        }
    }

    pub fn v6_48() -> IpPrefix {
        IpPrefix::V6 {
            addr: v6("2001:db8:a::"),
            prefix_len: 48,
        }
    }

    pub fn now_unix() -> u64 {
        packetframe_fast_path::fib::route_ledger::now_unix()
    }

    pub fn route(prefix: IpPrefix, nh: IpAddr) -> LedgerRoute {
        LedgerRoute {
            prefix,
            adverts: vec![LedgerAdvert {
                peer: PEER,
                path_id: None,
                local_pref: Some(100),
                nexthops: vec![nh],
            }],
        }
    }

    pub fn ledger(routes: &[LedgerRoute], confirmed_at_unix: u64) -> RouteLedger {
        let meta = LedgerMeta {
            writer_version: "test".into(),
            written_at_unix: now_unix(),
            confirmed_at_unix,
            identity: IDENTITY.into(),
        };
        RouteLedger::decode(encode(&meta, routes).expect("encode")).expect("decode")
    }

    pub fn add(prefix: IpPrefix, nh: IpAddr) -> RouteEvent {
        RouteEvent::Add {
            peer_id: PEER,
            prefix,
            nexthops: vec![nh],
            path_id: None,
            local_pref: Some(100),
        }
    }

    pub fn fib_value(h: &ProgrammerHarness, p: IpPrefix) -> Option<FibValue> {
        match p {
            IpPrefix::V4 { addr, prefix_len } => h.read_fib_v4(addr, prefix_len),
            IpPrefix::V6 { addr, prefix_len } => h.read_fib_v6(addr, prefix_len),
        }
    }

    pub fn has(h: &ProgrammerHarness, p: IpPrefix) -> bool {
        fib_value(h, p).is_some()
    }

    pub fn seeded(st: &SharedLedgerStatus) -> bool {
        let st = st.lock().unwrap();
        st.start == StartReport::Seeded && st.seed.as_ref().is_some_and(|s| s.applied_at.is_some())
    }
}

/// The whole life of a seed: installed and announced before any route
/// event; an identical re-advertisement changes nothing anywhere (no FIB
/// write, no second-tier delta — the replay of a full table must read
/// as quiet to everything but the stream counter); a changed one is an
/// ordinary update; and the first `InitiationComplete` removes exactly
/// what the replay did not confirm.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn a_seed_is_confirmed_by_the_replay_and_collected_by_the_gc() {
    use ledger::*;
    let seed = ledger(
        &[
            route(quarter(0), nh_a()),
            route(quarter(1), nh_a()),
            route(quarter(2), nh_a()),
            route(quarter(3), nh_a()),
            route(v6_48(), nh6()),
        ],
        now_unix(),
    );
    let (h, sink, status) = ProgrammerHarness::with_seed(Some(seed));

    // Queued behind the seed, so this observes it whole.
    let counts = h
        .run(async { h.handle.mirror_counts().await })
        .expect("counts");
    assert_eq!(counts, (4, 1));
    // The controller records the start's outcome; here the programmer's
    // own report is what is under test.
    assert!(seeded(&status));
    for p in [quarter(0), quarter(1), quarter(2), quarter(3), v6_48()] {
        assert!(has(&h, p), "{p:?} is in the FIB from the seed alone");
    }
    {
        let st = status.lock().unwrap();
        let s = st.seed.as_ref().unwrap();
        assert_eq!(s.unconfirmed, 5);
        assert!(s.stream_started_at.is_none());
        assert!(
            st.attestation_blocker().is_some(),
            "a seed no session has spoken to is not attestable"
        );
    }
    let after_seed = sink.calls();
    assert_eq!(
        after_seed
            .iter()
            .filter(|c| matches!(c, SinkCall::Resolved(..)))
            .count(),
        5,
        "the second tier hears every seeded route like any install: {after_seed:?}"
    );
    let before = [fib_value(&h, quarter(0)), fib_value(&h, quarter(1))];

    // The replay begins: two routes come back unchanged.
    h.run(async {
        for p in [quarter(0), quarter(1)] {
            h.handle
                .apply_route_event(add(p, nh_a()))
                .await
                .expect("replay");
        }
    });
    assert_eq!(
        sink.calls(),
        after_seed,
        "an identical re-advertisement is no delta for the second tier"
    );
    assert_eq!(
        [fib_value(&h, quarter(0)), fib_value(&h, quarter(1))],
        before,
        "nor a FIB write"
    );
    {
        let st = status.lock().unwrap();
        let s = st.seed.as_ref().unwrap();
        assert_eq!(s.unconfirmed, 3);
        assert!(s.stream_started_at.is_some());
        assert!(st.attestation_blocker().is_none());
    }

    // A route that changed while the daemon was down is an ordinary
    // update.
    h.run(async {
        h.handle
            .apply_route_event(add(quarter(2), nh_b()))
            .await
            .expect("changed route")
    });
    assert_eq!(
        sink.calls().last(),
        Some(&SinkCall::Resolved(quarter(2), vec![nh_b()]))
    );
    assert_eq!(status.lock().unwrap().seed.as_ref().unwrap().unconfirmed, 2);

    // The dump ends: what it never re-advertised is gone.
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::InitiationComplete)
            .await
            .expect("InitiationComplete")
    });
    let counts = h
        .run(async { h.handle.mirror_counts().await })
        .expect("counts");
    assert_eq!(counts, (3, 0));
    assert!(!has(&h, quarter(3)));
    assert!(!has(&h, v6_48()));
    for p in [quarter(0), quarter(1), quarter(2)] {
        assert!(has(&h, p), "{p:?} was confirmed and stays");
    }
    let tail: Vec<_> = sink.calls().split_off(after_seed.len());
    assert!(tail.contains(&SinkCall::Withdrawn(quarter(3))), "{tail:?}");
    assert!(tail.contains(&SinkCall::Withdrawn(v6_48())), "{tail:?}");
    let st = status.lock().unwrap();
    let s = st.seed.as_ref().unwrap();
    assert_eq!(s.unconfirmed, 0);
    assert_eq!(s.reconciled.map(|(_, removed)| removed), Some(2));
}

/// A live session whose only UPDATE is an empty End-of-RIB — or a BMP
/// stream whose route monitoring carried no route — fires
/// `InitiationComplete` without a single Add or Del. That reconciles the
/// seed (the GC takes all of it: the source has nothing) and is proof the
/// session spoke, so the seed must stop blocking attestation, and the
/// authority's early check must be due, rather than both waiting forever
/// on a first route that never comes.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn an_empty_end_of_rib_reconciles_the_seed_and_releases_attestation() {
    use ledger::*;
    let seed = ledger(
        &[route(quarter(0), nh_a()), route(v6_48(), nh6())],
        now_unix(),
    );
    let (h, _sink, status) = ProgrammerHarness::with_seed(Some(seed));
    assert_eq!(
        h.run(async { h.handle.mirror_counts().await })
            .expect("counts"),
        (1, 1)
    );
    assert!(status.lock().unwrap().attestation_blocker().is_some());

    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::InitiationComplete)
            .await
            .expect("InitiationComplete")
    });
    assert_eq!(
        h.run(async { h.handle.mirror_counts().await })
            .expect("counts"),
        (0, 0),
        "the source re-advertised nothing, so the GC took the whole seed"
    );
    let st = status.lock().unwrap();
    let s = st.seed.as_ref().unwrap();
    assert_eq!(s.reconciled.map(|(_, removed)| removed), Some(2));
    assert!(
        s.stream_started_at.is_some(),
        "the reconciliation is the session speaking: {s:?}"
    );
    assert!(
        st.attestation_blocker().is_none(),
        "a reconciled seed blocks nothing: {:?}",
        st.attestation_blocker()
    );
    assert!(st.stream_started(), "and the early check is due");
}

/// No route event overtakes the seed. The seed goes in a chunk at a time
/// and the run loop keeps serving neighbour events between chunks, but
/// never a command — so a live advertisement sent while the seed is
/// still going in lands AFTER it. Were it the other way round, the stale
/// seeded copy would replace the live one, and the GC would then delete a
/// route the source still has.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn a_route_event_never_overtakes_the_seed() {
    use ledger::*;
    // Several chunks' worth, so the seed is still going in when the
    // live advertisement is sent.
    let prefixes: Vec<IpPrefix> = (0..10_000u32)
        .map(|i| {
            let mut a = v6("2001:db8:b::");
            a[6..8].copy_from_slice(&(i as u16).to_be_bytes());
            IpPrefix::V6 {
                addr: a,
                prefix_len: 64,
            }
        })
        .collect();
    let routes: Vec<_> = prefixes.iter().map(|p| route(*p, nh6())).collect();
    let last = *prefixes.last().unwrap();
    let live_nh = IpAddr::V6("2001:db8::2".parse().unwrap());
    let (h, sink, _status) = ProgrammerHarness::with_seed(Some(ledger(&routes, now_unix())));

    h.run(async {
        // The first command sent sees the seed whole — not a count from
        // partway through it.
        assert_eq!(
            h.handle.mirror_counts().await.expect("counts"),
            (0, prefixes.len()),
            "a command was served while the seed was still going in"
        );
        h.handle
            .apply_route_event(add(last, live_nh))
            .await
            .expect("live advertisement");
        h.handle
            .apply_route_event(RouteEvent::InitiationComplete)
            .await
            .expect("InitiationComplete");
    });
    let counts = h
        .run(async { h.handle.mirror_counts().await })
        .expect("counts");
    assert_eq!(
        counts,
        (0, 1),
        "the GC took every seeded route but the one the live session re-advertised"
    );
    assert!(has(&h, last));
    let last_word = sink
        .calls()
        .into_iter()
        .rev()
        .find(|c| matches!(c, SinkCall::Resolved(p, _) | SinkCall::Withdrawn(p) if *p == last));
    assert_eq!(
        last_word,
        Some(SinkCall::Resolved(last, vec![live_nh])),
        "the live nexthop, not the seeded one"
    );
}

/// What a stop writes: the route source's advertisements, and nothing
/// the neighbour resolver injected — not its `local-prefix` host routes,
/// not its `fallback-default`, not even where the fallback shares a
/// prefix with a route-source default.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn the_ledger_holds_route_source_advertisements_only() {
    use ledger::*;
    use packetframe_fast_path::fib::route_ledger::RouteLedger;
    let (h, _sink, _status) = ProgrammerHarness::with_seed(None);
    let resolver = PeerId::local_arp(7);
    let default = IpPrefix::V4 {
        addr: [0, 0, 0, 0],
        prefix_len: 0,
    };
    let host = IpPrefix::V4 {
        addr: [203, 0, 113, 200],
        prefix_len: 32,
    };
    let fallback_nh = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let encoded = h.run(async {
        for ev in [
            add(quarter(0), nh_a()),
            add(default, nh_b()),
            RouteEvent::Add {
                peer_id: resolver,
                prefix: default,
                nexthops: vec![fallback_nh],
                path_id: None,
                local_pref: None,
            },
            RouteEvent::Add {
                peer_id: resolver,
                prefix: host,
                nexthops: vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200))],
                path_id: None,
                local_pref: None,
            },
        ] {
            h.handle.apply_route_event(ev).await.expect("add");
        }
        h.handle
            .encode_ledger(IDENTITY.into(), now_unix())
            .await
            .expect("encode")
    });
    let ledger = RouteLedger::decode(encoded.bytes).expect("decode");
    assert_eq!(ledger.peers(), &[PEER], "no resolver peer is recorded");
    let mut routes: Vec<_> = ledger.routes().collect();
    routes.sort_by_key(|r| format!("{:?}", r.prefix));
    let mut want = vec![route(quarter(0), nh_a()), route(default, nh_b())];
    want.sort_by_key(|r| format!("{:?}", r.prefix));
    assert_eq!(
        routes, want,
        "the default keeps only its route-source advertisement; the host route is absent"
    );
    assert_eq!(ledger.meta.identity, IDENTITY);
}

/// The confirmation time a stop records is the OLDEST unconfirmed
/// route's, so a stale route cannot ride from ledger to ledger.
///
/// - every route confirmed by the session that is up: the write time;
/// - the session lost (`Resync`) and nothing re-advertised: the loss;
/// - re-advertised again: the write time;
/// - a seed nobody replayed yet: the seed's own confirmation time, not
///   this stop's.
#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn a_stop_records_when_its_oldest_route_was_last_confirmed() {
    use ledger::*;
    let later = now_unix() + 100;
    let confirmed = |h: &ProgrammerHarness| {
        h.run(async { h.handle.encode_ledger(IDENTITY.into(), later).await })
            .expect("encode")
            .confirmed_at_unix
    };
    let (h, _sink, _status) = ProgrammerHarness::with_seed(None);
    h.run(async {
        for p in [quarter(0), quarter(1)] {
            h.handle
                .apply_route_event(add(p, nh_a()))
                .await
                .expect("add");
        }
    });
    assert_eq!(confirmed(&h), later);

    let lost_at = now_unix();
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Resync)
            .await
            .expect("Resync")
    });
    let c = confirmed(&h);
    assert!(
        (lost_at..lost_at + 5).contains(&c),
        "the session loss ({lost_at}), not the write ({later}): {c}"
    );

    h.run(async {
        for p in [quarter(0), quarter(1)] {
            h.handle
                .apply_route_event(add(p, nh_a()))
                .await
                .expect("re-add");
        }
    });
    assert_eq!(confirmed(&h), later, "all re-advertised: confirmed now");
    drop(h);

    let old = now_unix() - 600;
    let (h, _sink, _status) =
        ProgrammerHarness::with_seed(Some(ledger(&[route(quarter(0), nh_a())], old)));
    assert_eq!(
        confirmed(&h),
        old,
        "a stop before the replay reached the seed carries the seed's age forward"
    );
}

/// A restart, end to end through the control plane — minus only the
/// process boundary and the route source: a start seeds from a ledger,
/// the preserving stop writes the mirror back out, and the next start's
/// consume hands back the same routes for the same route source.
///
/// The `RouteController` is the production wiring (its own runtime, the
/// netlink resolver, the programmer opened from production pin paths), so
/// this is the one place the seed hand-over and `preserve_route_ledger`
/// are exercised together rather than piece by piece.
#[test]
#[ignore = "needs CAP_BPF + bpffs + netlink; run via sudo -E cargo test -- --ignored"]
fn a_preserving_stop_and_the_next_start_round_trip_the_mirror() {
    use ledger::*;
    use packetframe_fast_path::fib::controller::{
        LedgerWiring, Preserved, ResolverPolicy, RouteController, RouteFeed, SecondTierSignals,
    };
    use packetframe_fast_path::fib::route_ledger::{
        consume, shared_status, Consumed, Expectations,
    };

    // Production pin layout under a private bpffs directory.
    let pins = PinDirs::setup();
    let bytes = aligned_bpf_copy();
    let ebpf = Ebpf::load(&bytes).expect("Ebpf::load");
    let maps = pins.dir.join("fast-path").join("maps");
    std::fs::create_dir_all(&maps).expect("maps dir");
    for name in [
        "NEXTHOPS",
        "FIB_V4",
        "FIB_V6",
        "ECMP_GROUPS",
        "FIB_CACHE_CFG",
    ] {
        ebpf.map(name)
            .unwrap_or_else(|| panic!("{name} map missing from ELF"))
            .pin(maps.join(name))
            .unwrap_or_else(|e| panic!("pin {name}: {e}"));
    }
    let state_dir = std::env::temp_dir().join(format!("pf-ledger-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state_dir);
    std::fs::create_dir_all(&state_dir).unwrap();
    // Pinned, not left to the umask: the reader refuses a state-dir
    // group or others can write.
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let routes = vec![
        route(quarter(0), nh_a()),
        route(quarter(1), nh_b()),
        route(v6_48(), nh6()),
    ];
    let status = shared_status();
    let session = Arc::new(packetframe_common::fib::FeedSession::new());
    let ctrl = RouteController::start(
        &pins.dir,
        RouteFeed {
            // A real listener nothing will dial: with no route source at
            // all the controller declares the feed reconciled by
            // definition, which is not the restart under test.
            source: Some(
                packetframe_fast_path::fib::controller::RouteSourceConfig::Bgp {
                    listen: "127.0.0.1:0".parse().unwrap(),
                    local_as: 64512,
                    peer_as: 64512,
                    router_id: Ipv4Addr::new(192, 0, 2, 10),
                    peer_acl: Vec::new(),
                    expected_peer_ip: None,
                    anyip: false,
                },
            ),
            integrity_authority: packetframe_common::config::IntegrityAuthoritySpec::None,
        },
        ResolverPolicy::default(),
        std::collections::HashMap::new(),
        None,
        SecondTierSignals {
            completeness: None,
            feed_session: Some(session.clone()),
        },
        LedgerWiring {
            seed: Some(ledger(&routes, now_unix())),
            status: status.clone(),
            identity: Some(IDENTITY.into()),
        },
    )
    .expect("RouteController::start");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let prog = ctrl.programmer_handle();
    assert_eq!(
        rt.block_on(prog.mirror_counts()).expect("counts"),
        (2, 1),
        "the seed is in before the first command is served"
    );
    let seen = session.liveness();
    assert!(
        seen.mirror_seeded && !seen.up,
        "the second tier is told the mirror is a seed, not a table loading from empty, \
         before any route source has spoken: {seen:?}"
    );

    let written = ctrl.preserve_route_ledger(&state_dir);
    match &written {
        Preserved::Written { counts, .. } => assert_eq!(counts.prefixes(), 3),
        other => panic!("{other:?}"),
    }
    ctrl.shutdown();

    let exp = Expectations {
        spec: packetframe_common::config::RouteLedgerSpec::default(),
        forwarding_mode: packetframe_common::config::ForwardingMode::PacketframeFib,
        identity: Some(IDENTITY),
        single_peer: None,
        now_unix: now_unix(),
    };
    let again = match consume(&state_dir, &exp) {
        Consumed::Seed(l) => l,
        other => panic!("{other:?}"),
    };
    let mut got: Vec<_> = again.routes().collect();
    got.sort_by_key(|r| format!("{:?}", r.prefix));
    let mut want = routes;
    want.sort_by_key(|r| format!("{:?}", r.prefix));
    assert_eq!(
        got, want,
        "the next start gets back exactly what was seeded"
    );
    assert!(
        !packetframe_fast_path::fib::route_ledger::path_in(&state_dir).exists(),
        "and consumed it"
    );
    let _ = std::fs::remove_dir_all(&state_dir);
    drop(ebpf);
}

/// One measured run of a seed at the production table's size, against
/// real BPF maps: how long a start spends putting 1.35M routes into the
/// FIB before the route source's first route is served, and how long a
/// stop spends snapshotting them. IPv6 /64s from 2001:db8::/32 only
/// (documentation space has no 1.1M distinct IPv4 prefixes), which makes
/// it an upper bound: the v6 trie insert is the dearer one.
///
/// Gated on `PF_MEASURE_LEDGER_SEED=1` as well as `--ignored`, so the qemu
/// job's `--ignored` run does not spend minutes on it.
#[test]
#[ignore = "needs CAP_BPF + bpffs; measurement, also needs PF_MEASURE_LEDGER_SEED=1"]
fn measure_a_full_table_seed() {
    use ledger::*;
    if std::env::var("PF_MEASURE_LEDGER_SEED").is_err() {
        eprintln!("skipped: set PF_MEASURE_LEDGER_SEED=1 to measure");
        return;
    }
    const N: u32 = 1_350_000;
    let nhs: Vec<IpAddr> = (1..=768u16)
        .map(|i| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i)))
        .collect();
    let routes: Vec<_> = (0..N)
        .map(|i| {
            let mut a = v6("2001:db8::");
            a[4..8].copy_from_slice(&i.to_be_bytes());
            route(
                IpPrefix::V6 {
                    addr: a,
                    prefix_len: 64,
                },
                nhs[i as usize % nhs.len()],
            )
        })
        .collect();
    let seed = ledger(&routes, now_unix());
    drop(routes);
    let started = std::time::Instant::now();
    let (h, _sink, status) = ProgrammerHarness::with_seed(Some(seed));
    let counts = h
        .run(async { h.handle.mirror_counts().await })
        .expect("counts");
    let seed_took = started.elapsed();
    assert_eq!(counts, (0, N as usize));
    let applied = status.lock().unwrap().seed.as_ref().unwrap().apply_took;
    let started = std::time::Instant::now();
    let enc = h
        .run(async { h.handle.encode_ledger(IDENTITY.into(), now_unix()).await })
        .expect("encode");
    let encode_took = started.elapsed();
    println!(
        "seed of {N} routes into real BPF maps: {seed_took:?} until the first command was \
         served (programmer's own figure {applied:?}); stop-side snapshot {encode_took:?} \
         ({} bytes)",
        enc.bytes.len()
    );
}
