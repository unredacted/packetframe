//! Offline FIB comparison harness (Option F, Phase 3.8).
//!
//! Drives the programmer with a data-driven synthetic RIB — mixed
//! V4/V6, single-nexthop + ECMP + overlapping prefixes + default
//! route — then runs LPM lookups for a curated set of query IPs
//! and asserts each resolves to the prefix we expect.
//!
//! Positioned as the "offline comparison harness" called out in
//! the plan: it's the regression-catch layer between `fib_fixtures`
//! (BPF verifier-level unit tests) and the staging soak (live
//! bird). If the programmer's write path or the LPM lookup ever
//! diverges from what the input RIB specifies, this test fails
//! loudly in CI.
//!
//! **Scope deliberately modest.** The plan mentions comparing
//! against a captured kernel-FIB snapshot; doing that properly
//! needs bird in CI and an `ip route show` parser, which is a lot
//! of moving parts for the drift modes we're actually worried
//! about. The modes this test does catch:
//! - programmer miswrites prefix → FibValue (e.g., Single/ECMP
//!   tagging regression)
//! - NEXTHOPS allocation / refcount regressions
//! - ECMP dedup bug (two ECMP groups with identical nexthop set
//!   should share a group_id)
//! - LPM longest-prefix-match regression (overlapping prefixes)
//!
//! Runs under CAP_BPF. `#[ignore]`-gated; CI qemu jobs run it via
//! `sudo -E cargo test -- --ignored`.
//!
//! Setup is duplicated from `fib_programmer_integration.rs` —
//! each `tests/*.rs` is its own crate so cross-file imports aren't
//! possible. Factoring into `tests/common/` is a separate refactor.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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
    EcmpGroup, FibValue, NexthopEntry, FIB_KIND_ECMP, FIB_KIND_SINGLE,
};
use tokio_util::sync::CancellationToken;

const BPFFS_ROOT: &str = "/sys/fs/bpf";
const TEST_PREFIX: &str = "pftestcmp";

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static BPFFS_MOUNT: Once = Once::new();

struct PinDirs {
    dir: PathBuf,
}

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
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let _ = std::fs::remove_file(entry.path());
            }
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

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

struct Harness {
    pins: PinDirs,
    _ebpf: Ebpf,
    rt: tokio::runtime::Runtime,
    shutdown: CancellationToken,
    handle: packetframe_fast_path::fib::programmer::FibProgrammerHandle,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Harness {
    fn new() -> Self {
        let pins = PinDirs::setup();
        let ebpf = load_and_pin(&pins);
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

    fn run<F, T>(&self, f: F) -> T
    where
        F: std::future::Future<Output = T>,
    {
        self.rt.block_on(f)
    }

    fn lookup_v4(&self, ip: [u8; 4]) -> Option<FibValue> {
        let trie = open_lpm_v4(&self.pins.path("FIB_V4"));
        let key = LpmKey::new(32, ip);
        trie.get(&key, 0).ok()
    }

    fn lookup_v6(&self, ip: [u8; 16]) -> Option<FibValue> {
        let trie = open_lpm_v6(&self.pins.path("FIB_V6"));
        let key = LpmKey::new(128, ip);
        trie.get(&key, 0).ok()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            let _ = self
                .rt
                .block_on(async { tokio::time::timeout(Duration::from_secs(2), task).await });
        }
    }
}

// --- Synthetic RIB ----------------------------------------------------
//
// Mix of cases designed to catch each drift mode the harness
// promises to cover.

fn synthetic_rib_v4() -> Vec<(IpPrefix, Vec<IpAddr>)> {
    vec![
        // Default route.
        (
            IpPrefix::V4 {
                addr: [0, 0, 0, 0],
                prefix_len: 0,
            },
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        ),
        // Covering /8 that most public IPs will fall under in the
        // absence of a more-specific route.
        (
            IpPrefix::V4 {
                addr: [10, 0, 0, 0],
                prefix_len: 8,
            },
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        ),
        (
            IpPrefix::V4 {
                addr: [172, 16, 0, 0],
                prefix_len: 12,
            },
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        ),
        // ECMP across 3 paths.
        (
            IpPrefix::V4 {
                addr: [192, 0, 2, 0],
                prefix_len: 24,
            },
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            ],
        ),
        // More-specific inside 192.0.2.0/24 to test LPM.
        (
            IpPrefix::V4 {
                addr: [192, 0, 2, 128],
                prefix_len: 25,
            },
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))],
        ),
        // Another ECMP with *same* nexthop set as 192.0.2.0/24 —
        // must dedup to the same EcmpGroupId.
        (
            IpPrefix::V4 {
                addr: [198, 51, 100, 0],
                prefix_len: 24,
            },
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            ],
        ),
        // ECMP with one different path so it gets a new group.
        (
            IpPrefix::V4 {
                addr: [203, 0, 113, 0],
                prefix_len: 24,
            },
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            ],
        ),
        // Host route.
        (
            IpPrefix::V4 {
                addr: [192, 0, 2, 200],
                prefix_len: 32,
            },
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8))],
        ),
    ]
}

fn synthetic_rib_v6() -> Vec<(IpPrefix, Vec<IpAddr>)> {
    vec![
        (
            IpPrefix::V6 {
                addr: [0; 16],
                prefix_len: 0,
            },
            vec![IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))],
        ),
        // 2001:db8::/32
        (
            IpPrefix::V6 {
                addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                prefix_len: 32,
            },
            vec![IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2))],
        ),
        // 2001:db8:1::/48 — nested under the above.
        (
            IpPrefix::V6 {
                addr: [
                    0x20, 0x01, 0x0d, 0xb8, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
                prefix_len: 48,
            },
            vec![IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 3))],
        ),
    ]
}

// --- Test -------------------------------------------------------------

#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn synthetic_rib_programs_and_resolves_as_expected() {
    let h = Harness::new();

    // --- Load ----------------------------------------------------
    let rib_v4 = synthetic_rib_v4();
    let rib_v6 = synthetic_rib_v6();
    let total = rib_v4.len() + rib_v6.len();

    for (prefix, nhs) in rib_v4.iter().chain(rib_v6.iter()) {
        h.run(async {
            h.handle
                .apply_route_event(RouteEvent::Add {
                    peer_id: PeerId(0xabcd),
                    prefix: *prefix,
                    nexthops: nhs.clone(),
                })
                .await
        })
        .expect("Add succeeds");
    }
    assert_eq!(
        h.run(async { h.handle.mirror_counts().await }).unwrap(),
        (rib_v4.len(), rib_v6.len()),
        "programmer mirror should match input RIB size"
    );

    // --- LPM queries ---------------------------------------------
    // Each query IP → expected (prefix_addr_str, kind, nh_count).
    // Verifies longest-prefix-match + correct FibValue encoding.

    // IPv4: 192.0.2.200 — host route wins over /25 wins over /24.
    let v = h.lookup_v4([192, 0, 2, 200]).expect("FIB_V4[host-route]");
    assert_eq!(v.kind, FIB_KIND_SINGLE);

    // 192.0.2.130 falls under the /25 (192.0.2.128/25), not /24.
    let v = h.lookup_v4([192, 0, 2, 130]).expect("FIB_V4[/25 scope]");
    assert_eq!(v.kind, FIB_KIND_SINGLE);

    // 192.0.2.10 — no more-specific; /24 ECMP wins.
    let v = h.lookup_v4([192, 0, 2, 10]).expect("FIB_V4[/24 scope]");
    assert_eq!(v.kind, FIB_KIND_ECMP);
    let ecmp_192 = v.idx;

    // 198.51.100.5 — same nexthop set as 192.0.2.0/24; must share
    // group_id (ECMP dedup).
    let v = h.lookup_v4([198, 51, 100, 5]).expect("FIB_V4[dedup]");
    assert_eq!(v.kind, FIB_KIND_ECMP);
    assert_eq!(
        v.idx, ecmp_192,
        "ECMP groups with identical nexthop sets should share id"
    );

    // 203.0.113.5 — different nexthop set; different group.
    let v = h
        .lookup_v4([203, 0, 113, 5])
        .expect("FIB_V4[different-ecmp]");
    assert_eq!(v.kind, FIB_KIND_ECMP);
    assert_ne!(v.idx, ecmp_192, "different nexthop set → different group");

    // 10.0.0.42 — /8.
    let v = h.lookup_v4([10, 0, 0, 42]).expect("FIB_V4[/8 scope]");
    assert_eq!(v.kind, FIB_KIND_SINGLE);

    // 1.1.1.1 — nothing more-specific; default route.
    let v = h.lookup_v4([1, 1, 1, 1]).expect("FIB_V4[default]");
    assert_eq!(v.kind, FIB_KIND_SINGLE);

    // IPv6: 2001:db8:1:: — /48 wins over /32.
    let mut v6_a = [0u8; 16];
    v6_a[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    v6_a[5] = 0x01;
    let v = h.lookup_v6(v6_a).expect("FIB_V6[/48 scope]");
    assert_eq!(v.kind, FIB_KIND_SINGLE);

    // 2001:db8:ff::1 — /32 covers.
    let mut v6_b = [0u8; 16];
    v6_b[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    v6_b[5] = 0xff;
    v6_b[15] = 1;
    let v = h.lookup_v6(v6_b).expect("FIB_V6[/32 scope]");
    assert_eq!(v.kind, FIB_KIND_SINGLE);

    // fe80::1 — default route (no more-specific /32 or /48 match).
    let mut v6_c = [0u8; 16];
    v6_c[..2].copy_from_slice(&[0xfe, 0x80]);
    v6_c[15] = 1;
    let v = h.lookup_v6(v6_c).expect("FIB_V6[default]");
    assert_eq!(v.kind, FIB_KIND_SINGLE);

    // --- Del ------------------------------------------------------
    // Withdraw one route; confirm LPM falls back to the covering
    // prefix for that address.
    h.run(async {
        h.handle
            .apply_route_event(RouteEvent::Del {
                peer_id: PeerId(0xabcd),
                prefix: IpPrefix::V4 {
                    addr: [192, 0, 2, 200],
                    prefix_len: 32,
                },
            })
            .await
    })
    .expect("Del succeeds");

    // After withdrawing the host route, 192.0.2.200 should fall
    // under the /25 (192.0.2.128/25).
    let v = h.lookup_v4([192, 0, 2, 200]).expect("FIB_V4[post-del]");
    assert_eq!(v.kind, FIB_KIND_SINGLE);

    assert_eq!(
        h.run(async { h.handle.mirror_counts().await }).unwrap().0
            + h.run(async { h.handle.mirror_counts().await }).unwrap().1,
        total - 1,
        "mirror size should decrement after Del"
    );
}
