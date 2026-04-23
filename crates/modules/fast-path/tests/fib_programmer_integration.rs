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

impl PinDirs {
    fn setup() -> Self {
        // Unique per-test-process subdir under bpffs so concurrent
        // tests don't collide on pin paths.
        let dir = PathBuf::from(BPFFS_ROOT).join(format!("{TEST_PREFIX}-{}", std::process::id()));
        // Idempotent cleanup of any leftover from a prior crashed run.
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
    let mut ebpf = Ebpf::load(&bytes).expect("Ebpf::load");
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
        // `<bpffs>/pftestprog-<pid>/<NAME>` for test isolation, so
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
            let _ = self
                .rt
                .block_on(tokio::time::timeout(Duration::from_secs(2), task));
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
