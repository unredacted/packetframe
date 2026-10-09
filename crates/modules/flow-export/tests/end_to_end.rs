//! flow-export against fast-path's real programs: the ELF loaded and its
//! sampler maps pinned where a daemon pins them, packets through the XDP
//! program by `BPF_PROG_TEST_RUN`, and sFlow datagrams read off a local
//! UDP socket standing in for a collector.
//!
//! Needs root (CAP_BPF, bpffs); CI's sudo step runs it (`--ignored`).

#![cfg(target_os = "linux")]

use std::net::UdpSocket;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use aya::maps::{Array, Map, MapData};
use aya::programs::Xdp;
use aya::Ebpf;
use packetframe_common::config::Config;
use packetframe_common::module::{
    HealthCtx, HealthReport, HealthState, LoaderCtx, MetricsWriter, Module, ModuleConfig,
};
use packetframe_fast_path::registry::{self, AttachmentRecord, HookTypeRecord, RegistryFile};
use packetframe_fast_path::sample::SampleCfg;
use packetframe_fast_path::{aligned_bpf_copy, pin, FAST_PATH_BPF_AVAILABLE};
use packetframe_flow_export::FlowExportModule;

const BPFFS: &str = "/sys/fs/bpf";
const BPF_FS_MAGIC: i64 = 0xcafe_4a11;

/// Once per process: two tests each finding no bpffs would otherwise
/// stack two, the second hiding the first's pins.
fn ensure_bpffs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(mount_bpffs);
}

fn mount_bpffs() {
    let c = std::ffi::CString::new(BPFFS).unwrap();
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    #[allow(clippy::unnecessary_cast)] // f_type's width differs across libcs
    let mounted =
        unsafe { libc::statfs(c.as_ptr(), &mut st) } == 0 && st.f_type as i64 == BPF_FS_MAGIC;
    // Never stack a second bpffs over one that holds live pins.
    if !mounted {
        std::fs::create_dir_all(BPFFS).unwrap();
        let ok = std::process::Command::new("mount")
            .args(["-t", "bpf", "bpf", BPFFS])
            .status()
            .unwrap()
            .success();
        assert!(ok, "mount bpffs");
    }
}

struct Scratch {
    root: PathBuf,
    state: PathBuf,
}

impl Scratch {
    fn new(tag: &str) -> Self {
        ensure_bpffs();
        let root = Path::new(BPFFS).join(format!("pftestfe-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        pin::ensure_dirs(&root).unwrap();
        let state = std::env::temp_dir().join(format!("pftestfe-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&state);
        std::fs::create_dir_all(&state).unwrap();
        std::fs::set_permissions(&state, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .unwrap();
        Self { root, state }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_dir_all(&self.state);
    }
}

/// fast-path's ELF with its program loaded and the sampler's maps pinned.
fn fast_path(s: &Scratch) -> Ebpf {
    let mut bpf = Ebpf::load(&aligned_bpf_copy()).expect("load the fast-path ELF");
    let prog: &mut Xdp = bpf.program_mut("fast_path").unwrap().try_into().unwrap();
    prog.load().expect("verifier accepts fast_path");
    for name in ["SAMPLE_CFG", "SAMPLES", "STATS"] {
        bpf.map(name)
            .unwrap()
            .pin(pin::map_path(&s.root, name))
            .unwrap_or_else(|e| panic!("pin {name}: {e}"));
    }
    bpf
}

/// `lo` attached generic, as fast-path's registry would say.
fn register_lo(s: &Scratch) {
    registry::save(
        &s.state,
        &RegistryFile {
            module: "fast-path".into(),
            attachments: vec![AttachmentRecord {
                iface: "lo".into(),
                hook: HookTypeRecord::GenericXdp,
                prog_id: 0,
                pinned_path: PathBuf::new(),
            }],
        },
    )
    .unwrap();
}

/// An Ethernet + IPv4 + TCP frame nothing will allowlist: passed.
fn frame() -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x08, 0x00];
    f.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0]);
    f.extend_from_slice(&[192, 0, 2, 10, 203, 0, 113, 7]);
    f.extend_from_slice(&[
        0x04, 0xd2, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
    ]);
    f.resize(96, 0xa5);
    f
}

/// `BPF_PROG_TEST_RUN`, `repeat` times in one call.
fn test_run(bpf: &Ebpf, packet: &[u8], repeat: u32) {
    #[repr(C)]
    struct Attr {
        prog_fd: u32,
        retval: u32,
        data_size_in: u32,
        data_size_out: u32,
        data_in: u64,
        data_out: u64,
        repeat: u32,
        duration: u32,
        ctx_size_in: u32,
        ctx_size_out: u32,
        ctx_in: u64,
        ctx_out: u64,
        flags: u32,
        cpu: u32,
        batch_size: u32,
    }
    let prog: &Xdp = bpf.program("fast_path").unwrap().try_into().unwrap();
    let fd = prog.fd().unwrap().as_fd().as_raw_fd();
    let mut out = vec![0u8; packet.len() + 256];
    let mut a: Attr = unsafe { std::mem::zeroed() };
    a.prog_fd = fd as u32;
    a.data_size_in = packet.len() as u32;
    a.data_size_out = out.len() as u32;
    a.data_in = packet.as_ptr() as u64;
    a.data_out = out.as_mut_ptr() as u64;
    a.repeat = repeat;
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            10 as libc::c_long,
            &mut a as *mut Attr,
            std::mem::size_of::<Attr>() as u32,
        )
    };
    assert_eq!(rc, 0, "TEST_RUN: {}", std::io::Error::last_os_error());
}

fn word(d: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(d[at..at + 4].try_into().unwrap())
}

/// The module's health once its worker has published a `row`: a tick
/// sends its datagrams before it publishes, so a collector can hold a
/// tick's samples before the status shows them.
fn health_with(m: &FlowExportModule, row: &str) -> HealthReport {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let h = m.health_check(&HealthCtx::new()).unwrap();
        if h.subsystems.iter().any(|r| r.name == row) || Instant::now() > deadline {
            return h;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn sample_cfg(s: &Scratch) -> SampleCfg {
    let md = MapData::from_pin(pin::map_path(&s.root, "SAMPLE_CFG")).unwrap();
    let a: Array<MapData, SampleCfg> = Array::try_from(Map::Array(md)).unwrap();
    a.get(&0, 0).unwrap()
}

#[test]
#[ignore = "needs root: CAP_BPF and bpffs"]
fn samples_from_the_xdp_program_reach_a_collector_as_sflow() {
    if !FAST_PATH_BPF_AVAILABLE {
        eprintln!("no BPF build in this binary; skipping");
        return;
    }
    let s = Scratch::new("e2e");
    let bpf = fast_path(&s);
    register_lo(&s);
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let config = Config::parse(&format!(
        "module fast-path\n  attach lo generic\nmodule flow-export\n  source-address 127.0.0.1\n  \
         sample-rate 100\n  header-bytes 64\n  collector t sflow {}\n",
        collector.local_addr().unwrap()
    ))
    .unwrap();
    config.validate_flow_export().unwrap();
    let section = config
        .modules
        .iter()
        .find(|m| m.name == "flow-export")
        .unwrap();
    let mc = ModuleConfig::new(section, &config.global);
    let mut m = FlowExportModule::new();
    m.load(
        &mc,
        &LoaderCtx {
            bpffs_root: &s.root,
            state_dir: &s.state,
        },
    )
    .unwrap();
    m.attach(&mc).expect("attach");
    let cfg = sample_cfg(&s);
    assert_eq!(
        cfg,
        SampleCfg::new(100, 64, 1),
        "flow-export configured the sampler"
    );

    // ~200 samples at 1:100; the worker drains every 100 ms.
    let pkt = frame();
    test_run(&bpf, &pkt, 20_000);
    let deadline = Instant::now() + Duration::from_secs(3);
    let (mut samples, mut datagrams) = (0u32, 0u32);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline && samples < 100 {
        let Ok(n) = collector.recv(&mut buf) else {
            continue;
        };
        let d = &buf[..n];
        datagrams += 1;
        assert_eq!(word(d, 0), 5, "sFlow v5");
        assert_eq!(
            (word(d, 4), &d[8..12]),
            (1, &[127, 0, 0, 1][..]),
            "agent 127.0.0.1"
        );
        let count = word(d, 24);
        // The first flow sample's fields.
        let f = 28;
        assert_eq!(word(d, f), 1, "a compact flow sample");
        assert_eq!(word(d, f + 12), 1, "source: lo");
        assert_eq!(word(d, f + 16), 100, "the rate it was drawn at");
        assert_eq!(word(d, f + 28), 1, "input: lo");
        assert_eq!(word(d, f + 32), 0, "passed: no output");
        // Its raw header record: format 1, then protocol, frame length,
        // stripped, header length, header.
        let r = f + 40;
        assert_eq!(word(d, r), 1);
        assert_eq!(word(d, r + 8), 1, "Ethernet");
        assert_eq!(
            word(d, r + 12),
            pkt.len() as u32 + 4,
            "frame length counts the FCS"
        );
        assert_eq!(word(d, r + 16), 4, "stripped: the FCS");
        assert_eq!(word(d, r + 20), 64, "header-bytes");
        assert_eq!(&d[r + 24..r + 24 + 64], &pkt[..64]);
        samples += count;
    }
    assert!(samples >= 100, "{samples} samples in {datagrams} datagrams");

    let h = health_with(&m, "xdp");
    let row = |n: &str| h.subsystems.iter().find(|r| r.name == n).cloned();
    let xdp = row("xdp").unwrap_or_else(|| panic!("no xdp row: {h:#?}"));
    assert!(
        xdp.message.unwrap().starts_with("lo starting"),
        "inside the startup grace"
    );
    assert_eq!(row("collector t").unwrap().state, HealthState::Healthy);
    assert_eq!(
        row("sampling").unwrap().state,
        HealthState::Degraded,
        "1:100 is over budget"
    );
    let mut text = String::new();
    m.sample_metrics(&mut MetricsWriter::new(&mut text, "flow-export"))
        .unwrap();
    assert!(
        text.contains("packetframe_flow_export_samples_total{path=\"xdp\"}"),
        "{text}"
    );

    // The same, as a consumer outside the module reads it.
    let coverage = m.coverage();
    let c = coverage
        .current(Instant::now())
        .expect("fresh while the worker runs");
    assert!(
        c.paths.iter().any(|p| p.port == "lo" && p.path == "xdp"),
        "{:?}",
        c.paths
    );
    assert_eq!(c.rate, 100);

    // Detach stops the sampler, and the module vouches for nothing.
    m.detach().unwrap();
    assert_eq!(
        sample_cfg(&s).rate_generation as u32,
        0,
        "rate 0 after detach"
    );
    assert!(coverage.current(Instant::now()).is_none());
}

/// Without fast-path's maps there is nothing to sample: the attach fails
/// (and the loader degrades the module), and releasing it is a no-op.
#[test]
#[ignore = "needs root: CAP_BPF and bpffs"]
fn without_fast_paths_maps_the_attach_fails_and_release_is_a_no_op() {
    let s = Scratch::new("nomaps");
    let config = Config::parse(
        "module fast-path\n  attach lo generic\nmodule flow-export\n  source-address 127.0.0.1\n  \
         collector t sflow 127.0.0.1:6343\n",
    )
    .unwrap();
    let section = config
        .modules
        .iter()
        .find(|m| m.name == "flow-export")
        .unwrap();
    let mc = ModuleConfig::new(section, &config.global);
    let mut m = FlowExportModule::new();
    m.load(
        &mc,
        &LoaderCtx {
            bpffs_root: &s.root,
            state_dir: &s.state,
        },
    )
    .unwrap();
    let e = m.attach(&mc).expect_err("no maps to sample through");
    assert!(e.to_string().contains("SAMPLES"), "{e}");
    packetframe_flow_export::release_sampler(&s.root, None).unwrap();
    m.detach().unwrap();
}

/// A source-address this host does not have: no socket, so the attach
/// fails (and the loader degrades the module), and the sampler is left
/// off.
#[test]
#[ignore = "needs root: CAP_BPF and bpffs"]
fn a_source_address_the_host_lacks_fails_the_attach() {
    if !FAST_PATH_BPF_AVAILABLE {
        return;
    }
    let s = Scratch::new("nosrc");
    let _bpf = fast_path(&s);
    register_lo(&s);
    let config = Config::parse(
        "module fast-path\n  attach lo generic\nmodule flow-export\n  source-address 192.0.2.77\n  \
         collector t sflow 192.0.2.1:6343\n",
    )
    .unwrap();
    let section = config
        .modules
        .iter()
        .find(|m| m.name == "flow-export")
        .unwrap();
    let mc = ModuleConfig::new(section, &config.global);
    let mut m = FlowExportModule::new();
    m.load(
        &mc,
        &LoaderCtx {
            bpffs_root: &s.root,
            state_dir: &s.state,
        },
    )
    .unwrap();
    let e = m.attach(&mc).expect_err("no such local address");
    assert!(e.to_string().contains("source-address 192.0.2.77"), "{e}");
    assert_eq!(
        sample_cfg(&s).rate_generation,
        0,
        "the sampler was never turned on"
    );
}

/// fast-path's counter `name`, summed across CPUs.
fn stat(s: &Scratch, name: &str) -> u64 {
    let at = packetframe_fast_path::metrics::COUNTER_NAMES
        .iter()
        .position(|n| *n == name)
        .unwrap();
    packetframe_fast_path::stats_from_pin(&s.root).unwrap()[at]
}

/// A reload is applied by the time `reconfigure` returns, and one that
/// needs larger rings swaps them without losing what the old ones held:
/// every sample the program selected reaches the collector, at the rate
/// it was drawn at.
#[test]
#[ignore = "needs root: CAP_BPF and bpffs"]
fn a_reload_to_a_denser_rate_swaps_the_rings_and_loses_nothing() {
    if !FAST_PATH_BPF_AVAILABLE {
        return;
    }
    let s = Scratch::new("reload");
    let bpf = fast_path(&s);
    register_lo(&s);
    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let conf = |rate: u32| {
        Config::parse(&format!(
            "module fast-path\n  attach lo generic\nmodule flow-export\n  source-address 127.0.0.1\n  \
             sample-rate {rate}\n  header-bytes 64\n  collector t sflow {}\n",
            collector.local_addr().unwrap()
        ))
        .unwrap()
    };
    let section = |c: &Config| {
        c.modules
            .iter()
            .find(|m| m.name == "flow-export")
            .unwrap()
            .clone()
    };
    let sparse = conf(1000);
    let sparse_section = section(&sparse);
    let mc = ModuleConfig::new(&sparse_section, &sparse.global);
    let mut m = FlowExportModule::new();
    m.load(
        &mc,
        &LoaderCtx {
            bpffs_root: &s.root,
            state_dir: &s.state,
        },
    )
    .unwrap();
    m.attach(&mc).expect("attach");

    // ~50 samples at 1:1000, most still in the rings when the reload
    // replaces them.
    let pkt = frame();
    test_run(&bpf, &pkt, 50_000);
    let dense = conf(100);
    let dense_section = section(&dense);
    m.reconfigure(&ModuleConfig::new(&dense_section, &dense.global))
        .expect("reload");
    assert_eq!(
        sample_cfg(&s),
        SampleCfg::new(100, 64, 2),
        "applied when reconfigure returned"
    );
    test_run(&bpf, &pkt, 5_000);

    let selected = stat(&s, "sample_selected");
    let mut by_rate = std::collections::BTreeMap::<u32, u64>::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline && by_rate.values().sum::<u64>() < selected {
        let Ok(n) = collector.recv(&mut buf) else {
            continue;
        };
        let d = &buf[..n];
        let mut f = 28;
        for _ in 0..word(d, 24) {
            *by_rate.entry(word(d, f + 16)).or_default() += 1;
            f += 8 + word(d, f + 4) as usize;
        }
    }
    assert_eq!(stat(&s, "sample_emit_failed"), 0, "no swap in flight");
    assert_eq!(
        by_rate.values().sum::<u64>(),
        selected,
        "every selected sample exported: {by_rate:?}"
    );
    assert!(
        by_rate.contains_key(&1000) && by_rate.contains_key(&100),
        "{by_rate:?}"
    );
    m.detach().unwrap();
}

/// This process's start (field 22 of `/proc/self/stat`), so it can stand
/// in for VPP: it maps the epoch file it creates, as VPP would.
fn own_start_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    let after = &stat[stat.rfind(')').unwrap() + 1..];
    after.split_whitespace().nth(19).unwrap().parse().unwrap()
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn realtime_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

/// VPP's path end to end, the plugin played by this test: flow-export
/// claims a real sampler tmpfs, asks for the VPP port vpp-offload
/// published, reads the samples the "plugin" writes through that
/// process's binding, sends them as `lo`'s, and removes `desired.conf`
/// when it stops.
#[test]
#[ignore = "needs root: CAP_BPF, bpffs and a tmpfs mount"]
fn vpp_samples_reach_a_collector_through_the_plugins_rings() {
    use packetframe_common::sampler_ports::{
        SampledPort, VppInstance, VppPortsSnapshot, VppSamplerPorts,
    };
    use packetframe_sampler_shm::desired::Desired;
    use packetframe_sampler_shm::fs::{create_epoch, mount_tmpfs, publish_current, unmount};
    use packetframe_sampler_shm::layout::Layout;
    use packetframe_sampler_shm::ring::{RingWriter, SampleMeta};
    use packetframe_sampler_shm::status::{Interface, State, Status, StatusWriter};
    use packetframe_sampler_shm::Class;

    if !FAST_PATH_BPF_AVAILABLE {
        return;
    }
    let s = Scratch::new("vpp");
    let _bpf = fast_path(&s);
    register_lo(&s);
    let dir = std::env::temp_dir().join(format!("pftestfe-vpp-sampler-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    mount_tmpfs(&dir, 8 << 20).expect("mount the sampler tmpfs");
    struct Unmount(PathBuf);
    impl Drop for Unmount {
        fn drop(&mut self) {
            let _ = unmount(&self.0);
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let _unmount = Unmount(dir.clone());

    // The plugin's epoch, mapped by this process.
    let layout = Layout::new(1, 64, 256).unwrap();
    let epoch = 0x5eed_0000_0000_0001;
    let file = create_epoch(&dir, &layout, epoch, realtime_ns(), monotonic_ns(), "test").unwrap();
    publish_current(&dir, epoch, &layout).unwrap();
    let status = StatusWriter::new(layout.status(file.words()));
    let ring = RingWriter::new(&layout, file.words(), 0);

    let ports = std::sync::Arc::new(VppSamplerPorts::new());
    ports.publish(VppPortsSnapshot {
        instance: VppInstance {
            pid: std::process::id() as i32,
            start_ticks: own_start_ticks(),
            boot_id: None,
        },
        ports: vec![SampledPort {
            port: "lo".into(),
            ifindex: Some(1),
            vpp_name: "loop0".into(),
            sw_if_index: 5,
        }],
    });

    let collector = UdpSocket::bind("127.0.0.1:0").unwrap();
    collector
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let config = Config::parse(&format!(
        "module fast-path\n  attach lo generic\nmodule flow-export\n  source-address 127.0.0.1\n  \
         sample-rate 100\n  header-bytes 64\n  collector t sflow {}\n",
        collector.local_addr().unwrap()
    ))
    .unwrap();
    let section = config
        .modules
        .iter()
        .find(|m| m.name == "flow-export")
        .unwrap();
    let mc = ModuleConfig::new(section, &config.global);
    let mut m = FlowExportModule::new();
    m.set_vpp(ports, dir.clone());
    m.load(
        &mc,
        &LoaderCtx {
            bpffs_root: &s.root,
            state_dir: &s.state,
        },
    )
    .unwrap();
    m.attach(&mc).expect("attach");

    // The plugin: apply what flow-export asks, beat, sample.
    let frame = frame();
    let deadline = Instant::now() + Duration::from_secs(5);
    let (mut applied, mut pushed, mut received) = (0u64, 0u64, Vec::new());
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline && received.len() < 20 {
        status.beat(monotonic_ns());
        if let Some(d) = std::fs::read_to_string(dir.join("desired.conf"))
            .ok()
            .and_then(|t| Desired::parse(&t).ok())
        {
            if d.generation != applied {
                assert_eq!(d.interfaces, vec!["loop0"]);
                assert_eq!((d.rate, d.header_bytes), (100, 64));
                applied = d.generation;
                status.publish(&Status {
                    state: State::Enabled,
                    applied_generation: applied,
                    rate: d.rate,
                    header_bytes: d.header_bytes,
                    classes: Class::Ingress.bit(),
                    changed_ns: realtime_ns(),
                    interfaces: vec![Interface {
                        name: "loop0".into(),
                        sw_if_index: Some(5),
                        pool_index: 0,
                        unresolved_since_ns: 0,
                    }],
                    ..Status::default()
                });
            }
        }
        if applied > 0 && pushed < 20 {
            ring.add_pool(0, Class::Ingress, 100);
            let meta = SampleMeta {
                generation: applied,
                time_ns: realtime_ns(),
                sw_if_index: 5,
                class: Class::Ingress,
                pool_index: 0,
                rate: 100,
                frame_len: frame.len() as u32,
            };
            assert!(ring.push(&meta, &frame[..64]));
            pushed += 1;
        }
        if let Ok(n) = collector.recv(&mut buf) {
            let d = &buf[..n];
            let mut f = 28;
            for _ in 0..word(d, 24) {
                received.push((
                    word(d, f + 8),
                    word(d, f + 12),
                    word(d, f + 16),
                    word(d, f + 20),
                ));
                f += 8 + word(d, f + 4) as usize;
            }
        }
    }
    assert_eq!(applied, 1, "one generation asked for, and applied");
    assert_eq!(received.len(), 20, "{received:?}");
    for (i, &(seq, source, rate, _)) in received.iter().enumerate() {
        assert_eq!(
            (seq, source, rate),
            (i as u32 + 1, 1, 100),
            "lo's, in sequence"
        );
    }
    // VPP's pool, from the plugin's count: it only grows, and holds most
    // of what was counted (a tick may read it before the last add).
    let pools: Vec<u32> = received.iter().map(|r| r.3).collect();
    assert!(pools.windows(2).all(|w| w[0] <= w[1]), "{pools:?}");
    assert!(pools[19] >= 1000, "{pools:?}");
    let h = health_with(&m, "vpp");
    let vpp = h
        .subsystems
        .iter()
        .find(|r| r.name == "vpp")
        .expect("a vpp row");
    let msg = vpp.message.clone().unwrap();
    assert!(
        (msg.contains("sampler healthy") || msg.contains("sampler zero-traffic"))
            && msg.contains("lo starting"),
        "{msg}"
    );

    m.detach().unwrap();
    assert!(
        !dir.join("desired.conf").exists(),
        "the plugin stops with the module"
    );
    assert_eq!(sample_cfg(&s).rate_generation as u32, 0);
    drop(file);
}
