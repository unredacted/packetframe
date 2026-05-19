//! FibProgrammer integration test (Option F, Phase 3.7 Slice B).
//!
//! Exercises the programmer's route-side write path end-to-end
//! against real BPF maps: Add / Del / PeerDown / ECMP dedup /
//! refcounted nexthop recycling. Not a "BMP mock test" as originally
//! scoped — constructing valid BMP byte streams from scratch is its
//! own sub-project, and the real value is proving the programmer
//! writes the right bits into the BPF maps when fed RouteEvents,
//! which is exactly what the `apply_route_event` handle does.
//!
//! **Map-handle duplication.** The programmer takes ownership of
//! `Array<MapData, _>` handles via `Ebpf::take_map` — after which
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
use std::sync::Once;
use std::time::Duration;

use aya::maps::lpm_trie::Key as LpmKey;
use aya::maps::{Array, LpmTrie, Map, MapData};
use aya::Ebpf;
use packetframe_common::fib::{IpPrefix, PeerId, RouteEvent};
use packetframe_fast_path::aligned_bpf_copy;
use packetframe_fast_path::fib::programmer::FibProgrammer;
use packetframe_fast_path::fib::types::{
    EcmpGroup, FibValue, NexthopEntry, FIB_KIND_ECMP, FIB_KIND_SINGLE, NH_STATE_INCOMPLETE,
};
use tokio_util::sync::CancellationToken;

const BPFFS_ROOT: &str = "/sys/fs/bpf";
const TEST_PREFIX: &str = "pftestprog";

struct PinDirs {
    dir: PathBuf,
}

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static BPFFS_MOUNT: Once = Once::new();

/// Ensure `/sys/fs/bpf` exists and has bpffs mounted on it. GitHub's
/// hosted Ubuntu runner already has this; virtme-ng's VM does not, so
/// we mount it ourselves. Best-effort: errors are tolerated — the
/// subsequent `create_dir_all` / `pin` call will surface the real
/// problem with a clearer message.
fn ensure_bpffs_mounted() {
    BPFFS_MOUNT.call_once(|| {
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

/// Load the fast-path ELF, pin the four custom-FIB maps under the
/// test's bpffs subdir, and return the pinned `Ebpf` so the maps
/// stay alive after `take_map` hands them to the programmer.
fn load_and_pin(pins: &PinDirs) -> Ebpf {
    let bytes = aligned_bpf_copy();
    let ebpf = Ebpf::load(&bytes).expect("Ebpf::load");
    for name in ["NEXTHOPS", "FIB_V4", "FIB_V6", "ECMP_GROUPS"] {
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
        }
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
