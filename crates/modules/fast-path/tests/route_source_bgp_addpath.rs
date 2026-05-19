//! End-to-end synthetic-peer test for the RFC 7911 ADD-PATH path:
//! OPEN capability negotiation, NLRI decoding with `path_id`, and
//! the FibProgrammer aggregation that turns multiple advertisements
//! into one ECMP group.
//!
//! The test drives raw BGP wire bytes through a real `BgpListener`
//! over a `TcpStream`; no `bird` process is involved, which keeps the
//! qemu-verifier image small (no `bird2` apt package). The synthetic
//! peer advertises capability 69 with `Send` direction, then sends
//! two UPDATEs for the same prefix carrying distinct `path_id` values
//! and different next-hops. Polls the FIB BPF map until the ECMP
//! aggregation is reflected.
//!
//! Runs under CAP_BPF + CAP_NET_ADMIN. `#[ignore]`-gated; CI's qemu
//! job runs it via `sudo -E cargo test -- --ignored`.

#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Once;
use std::time::{Duration, Instant};

use aya::maps::{lpm_trie::Key as LpmKey, Array, LpmTrie, Map, MapData};
use aya::Ebpf;
use packetframe_fast_path::aligned_bpf_copy;
use packetframe_fast_path::fib::programmer::FibProgrammer;
use packetframe_fast_path::fib::route_source_bgp::{BgpListener, BgpListenerConfig};
use packetframe_fast_path::fib::types::{EcmpGroup, FibValue, NexthopEntry, FIB_KIND_ECMP};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

const BPFFS_ROOT: &str = "/sys/fs/bpf";
const TEST_PREFIX: &str = "pftestbgpaddpath";

// ----- Test-pin scaffolding (mirrors fib_programmer_integration.rs) ---

struct PinDirs {
    dir: PathBuf,
}

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static BPFFS_MOUNT: Once = Once::new();

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

// ----- Wire-format helpers --------------------------------------------

const BGP_MARKER: [u8; 16] = [0xFF; 16];

/// Build a peer-side OPEN advertising capability 69 with `Send`
/// direction for IPv4 unicast + IPv6 unicast (so the listener
/// negotiates ADD-PATH receive on its side). Also carries MP-BGP for
/// both AFIs and the 4-octet ASN capability.
fn build_open_with_addpath_send(local_as: u32, hold_time: u16, router_id: Ipv4Addr) -> Vec<u8> {
    // Capabilities.
    let mut caps: Vec<u8> = Vec::with_capacity(40);
    caps.extend_from_slice(&[1, 4, 0x00, 0x01, 0x00, 0x01]); // MP IPv4 unicast
    caps.extend_from_slice(&[1, 4, 0x00, 0x02, 0x00, 0x01]); // MP IPv6 unicast
    caps.extend_from_slice(&[65, 4]); // 4-octet ASN
    caps.extend_from_slice(&local_as.to_be_bytes());
    // RFC 7911 §4: code=69, len=8, two (AFI, SAFI, Send/Recv) tuples
    // with Send/Recv=2 (Send). The peer is the side that transmits.
    caps.extend_from_slice(&[69, 8, 0x00, 0x01, 0x01, 0x02, 0x00, 0x02, 0x01, 0x02]);

    // Optional Parameter of type 2 wrapping every capability.
    let mut opt_params: Vec<u8> = Vec::with_capacity(2 + caps.len());
    opt_params.push(2);
    opt_params.push(caps.len() as u8);
    opt_params.extend_from_slice(&caps);

    // Header + body.
    let body_len = 1 + 2 + 2 + 4 + 1 + opt_params.len();
    let total_len = 19 + body_len;
    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&BGP_MARKER);
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.push(1); // OPEN
    out.push(4); // version
                 // My AS in 2-byte slot. Use AS_TRANS when > 65535.
    let my_as_2: u16 = if local_as > u16::MAX as u32 {
        23456
    } else {
        local_as as u16
    };
    out.extend_from_slice(&my_as_2.to_be_bytes());
    out.extend_from_slice(&hold_time.to_be_bytes());
    out.extend_from_slice(&router_id.octets());
    out.push(opt_params.len() as u8);
    out.extend_from_slice(&opt_params);
    out
}

fn build_keepalive() -> [u8; 19] {
    let mut out = [0u8; 19];
    out[..16].copy_from_slice(&BGP_MARKER);
    out[16..18].copy_from_slice(&19u16.to_be_bytes());
    out[18] = 4; // KEEPALIVE
    out
}

/// Build an IPv4-unicast UPDATE carrying one ADD-PATH announce:
/// `path_id`, prefix `addr/24`, NEXT_HOP `nh`. Path attributes are
/// the mandatory minimum (ORIGIN IGP, empty AS_PATH, NEXT_HOP). Length
/// computed for a /24 prefix (3-byte address suffix); the helper is
/// /24-only for brevity since the test uses RFC 5737 /24 prefixes.
fn build_update_addpath_v4_slash24(path_id: u32, addr_prefix: [u8; 3], nh: Ipv4Addr) -> Vec<u8> {
    // NLRI: path_id (4 bytes) + length (1) + prefix (3) = 8 bytes.
    let mut nlri: Vec<u8> = Vec::with_capacity(8);
    nlri.extend_from_slice(&path_id.to_be_bytes());
    nlri.push(24);
    nlri.extend_from_slice(&addr_prefix);

    // Path attributes (14 bytes minimum):
    //   ORIGIN: 0x40 0x01 0x01 0x00 -> 4 bytes (IGP)
    //   AS_PATH: 0x40 0x02 0x00 -> 3 bytes (empty)
    //   NEXT_HOP: 0x40 0x03 0x04 <ip> -> 7 bytes
    let mut attrs: Vec<u8> = Vec::with_capacity(14);
    attrs.extend_from_slice(&[0x40, 0x01, 0x01, 0x00]);
    attrs.extend_from_slice(&[0x40, 0x02, 0x00]);
    attrs.extend_from_slice(&[0x40, 0x03, 0x04]);
    attrs.extend_from_slice(&nh.octets());

    // Body: withdrawn_len(2) + attr_len(2) + attrs + NLRI.
    let body_len = 2 + 2 + attrs.len() + nlri.len();
    let total_len = 19 + body_len;
    let mut out: Vec<u8> = Vec::with_capacity(total_len);
    out.extend_from_slice(&BGP_MARKER);
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.push(2); // UPDATE
    out.extend_from_slice(&0u16.to_be_bytes()); // withdrawn routes len
    out.extend_from_slice(&(attrs.len() as u16).to_be_bytes()); // total path attr len
    out.extend_from_slice(&attrs);
    out.extend_from_slice(&nlri);
    out
}

/// Walk an OPEN's capabilities for code 69 with a matching AFI and
/// the Receive bit set, confirming the listener advertised ADD-PATH
/// receive for both AFIs (mirror of `walk_open_capabilities` in
/// production code, kept simple for the test).
fn open_advertises_add_path_recv(open_bytes: &[u8]) -> bool {
    // header(19) + version(1) + my_as(2) + hold(2) + router_id(4) = 28
    if open_bytes.len() < 29 {
        return false;
    }
    let opt_param_len = open_bytes[28] as usize;
    if open_bytes.len() < 29 + opt_param_len || opt_param_len < 2 {
        return false;
    }
    let opt_params = &open_bytes[29..29 + opt_param_len];
    if opt_params[0] != 2 {
        return false;
    }
    let caps = &opt_params[2..];
    let mut i = 0;
    let mut v4_recv = false;
    let mut v6_recv = false;
    while i + 2 <= caps.len() {
        let code = caps[i];
        let clen = caps[i + 1] as usize;
        if i + 2 + clen > caps.len() {
            return false;
        }
        let value = &caps[i + 2..i + 2 + clen];
        if code == 69 {
            let mut j = 0;
            while j + 4 <= clen {
                let afi = u16::from_be_bytes([value[j], value[j + 1]]);
                let safi = value[j + 2];
                let sr = value[j + 3];
                // Receive bit is 0x01 (Recv=1, SendReceive=3 → both set).
                let has_recv = sr & 0x01 != 0;
                if afi == 1 && safi == 1 && has_recv {
                    v4_recv = true;
                }
                if afi == 2 && safi == 1 && has_recv {
                    v6_recv = true;
                }
                j += 4;
            }
        }
        i += 2 + clen;
    }
    v4_recv && v6_recv
}

// ----- The test ----------------------------------------------------------

#[test]
#[ignore = "needs CAP_BPF + bpffs; run via sudo -E cargo test -- --ignored"]
fn add_path_two_updates_yield_ecmp_via_bgp_listener() {
    let pins = PinDirs::setup();
    let _ebpf = load_and_pin(&pins);

    // Programmer + listener share a tokio runtime.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let shutdown = CancellationToken::new();

    // Build the programmer with handles to the pinned maps.
    let nexthops: Array<MapData, NexthopEntry> = open_array(&pins.path("NEXTHOPS"));
    let fib_v4 = open_lpm_v4(&pins.path("FIB_V4"));
    let fib_v6 = open_lpm_v6(&pins.path("FIB_V6"));
    let ecmp_groups: Array<MapData, EcmpGroup> = open_array(&pins.path("ECMP_GROUPS"));
    let (_neigh_tx, neigh_rx) = tokio::sync::mpsc::channel(16);
    let (programmer, prog_handle) = FibProgrammer::new(
        nexthops,
        fib_v4,
        fib_v6,
        ecmp_groups,
        neigh_rx,
        shutdown.clone(),
    );
    let prog_task = rt.spawn(programmer.run());

    // Pick an ephemeral port by binding then dropping a TcpListener;
    // a race window exists but in practice no other process races to
    // claim a brand-new ephemeral port in the ~1 ms gap.
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("probe bind");
    let listen_port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let listen_addr: SocketAddr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    let our_as = 65000u32;
    let peer_as = 65001u32;
    let bgp_cfg = BgpListenerConfig::new(listen_addr, our_as, peer_as, Ipv4Addr::new(127, 0, 0, 1));
    let listener = BgpListener::new(bgp_cfg, prog_handle.clone(), shutdown.clone());
    let listener_task = rt.spawn(listener.run());

    let test_result = rt.block_on(async move {
        // Give the listener a moment to bind.
        for _ in 0..50 {
            if TcpStream::connect(listen_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut peer = TcpStream::connect(listen_addr)
            .await
            .expect("connect to BgpListener");

        // 1) Send our OPEN (peer-side: advertises Send for ADD-PATH).
        let our_open = build_open_with_addpath_send(peer_as, 180, Ipv4Addr::new(127, 0, 0, 2));
        peer.write_all(&our_open).await.expect("send OPEN");

        // 2) Read the listener's OPEN. Header first, then body.
        let mut head = [0u8; 19];
        peer.read_exact(&mut head).await.expect("read OPEN header");
        assert_eq!(&head[..16], &BGP_MARKER, "BGP marker missing");
        let total = u16::from_be_bytes([head[16], head[17]]) as usize;
        assert_eq!(head[18], 1, "expected OPEN message type");
        let mut body = vec![0u8; total - 19];
        peer.read_exact(&mut body).await.expect("read OPEN body");
        let mut full = Vec::with_capacity(total);
        full.extend_from_slice(&head);
        full.extend_from_slice(&body);
        assert!(
            open_advertises_add_path_recv(&full),
            "listener OPEN must advertise ADD-PATH capability with Receive for v4 + v6"
        );

        // 3) Confirm OPEN with KEEPALIVE, exchange with peer's.
        peer.write_all(&build_keepalive())
            .await
            .expect("send KEEPALIVE");
        let mut ka = [0u8; 19];
        peer.read_exact(&mut ka).await.expect("read KEEPALIVE");
        assert_eq!(ka[18], 4, "expected KEEPALIVE");

        // 4) Send two ADD-PATH UPDATEs for the same /24 with different
        //    path_ids and different next-hops.
        let nh_a = Ipv4Addr::new(10, 0, 0, 1);
        let nh_b = Ipv4Addr::new(10, 0, 0, 2);
        let u1 = build_update_addpath_v4_slash24(1, [192, 0, 2], nh_a);
        let u2 = build_update_addpath_v4_slash24(2, [192, 0, 2], nh_b);
        peer.write_all(&u1).await.expect("send UPDATE 1");
        peer.write_all(&u2).await.expect("send UPDATE 2");

        // 5) Poll the FIB until the prefix appears as ECMP with two NHs.
        let key = LpmKey::new(24, [192, 0, 2, 0]);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut last_seen: Option<FibValue> = None;
        let mut last_count: u8 = 0;
        loop {
            // Fresh handle each poll so we observe the programmer's
            // writes via a separate FD.
            let trie = open_lpm_v4(&pins.path("FIB_V4"));
            if let Ok(fv) = trie.get(&key, 0) {
                last_seen = Some(fv);
                if fv.kind == FIB_KIND_ECMP {
                    let groups: Array<MapData, EcmpGroup> = open_array(&pins.path("ECMP_GROUPS"));
                    if let Ok(grp) = groups.get(&fv.idx, 0) {
                        last_count = grp.nh_count;
                        if grp.nh_count == 2 {
                            break;
                        }
                    }
                }
            }
            if Instant::now() > deadline {
                panic!(
                    "FIB did not reflect ADD-PATH aggregation within timeout: \
                     last_seen={last_seen:?} last_nh_count={last_count}"
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Hold the peer connection open so the listener's hold timer
        // does not fire before we return.
        drop(peer);
    });

    // Tear down the listener + programmer.
    shutdown.cancel();
    rt.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(2), listener_task).await;
        let _ = tokio::time::timeout(Duration::from_secs(2), prog_task).await;
    });

    test_result
}
