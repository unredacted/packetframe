//! PacketFrame's VPP sampler plugin.
//!
//! VPP glue around `packetframe-sampler-core`, where every decision lives:
//!
//! - **`pf-sampler-rx`**: a feature on `port-rx-eth` (vnet/dev drivers such
//!   as octeon) and `device-input` (everything else, and the packet
//!   generator), enabled and disabled together per interface. Per frame it
//!   counts the sample pool, consumes the selection gap, and copies each
//!   selected packet's leading bytes into this thread's ring; a frame with
//!   nothing selected costs a few comparisons beyond passing it on.
//! - **`pf-sampler-control`**: a process node running the core's control
//!   loop every 100 ms: the epoch file, `desired.conf`, interface
//!   resolution, the heartbeat and the status.
//! - **`show pf-sampler`**.
//!
//! The plugin is built against one VPP's headers, so its struct layouts
//! are only proven for that build. VPP's loader compares the build version
//! by prefix; the plugin also requires an exact match at init and stays
//! inert otherwise. Nothing here can stop VPP from starting or forwarding.

use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::os::raw::c_char;
use std::sync::{Mutex, OnceLock};

use arrayvec::ArrayVec;
use packetframe_sampler_core::control::{NOT_SAMPLED, Vpp, WorkerConfig};
use packetframe_sampler_core::driver::{Driver, Epoch, Host, sampler_dir};
use packetframe_sampler_core::select::Selector;
use packetframe_sampler_shm::Class;
use packetframe_sampler_shm::layout::MAX_WORKERS;
use packetframe_sampler_shm::ring::{RingWriter, SampleMeta};
use vpp_plugin::{
    ErrorCounters, NextNodes,
    bindings::{
        vlib_get_thread_main_not_inline, vlib_helper_unformat_get_input,
        vlib_helper_unformat_vnet_sw_interface, vlib_worker_thread_barrier_release,
        vlib_worker_thread_barrier_sync_int, vnet_feature_is_enabled, vnet_get_main,
    },
    vlib::{
        self, BarrierHeldMainRef, BufferIndex, BufferRef, MainRef, main::sync::BarrierRwLock,
        node::FRAME_SIZE, process_node::sleep,
    },
    vlib_cli_command, vlib_init_function, vlib_node, vlib_plugin_register, vlib_process_node,
    vnet::types::SwIfIndex,
    vnet_feature_init,
    vppinfra::{error::ErrorStack, unformat::UnformatInput},
};

const NODE_NAME: &CStr = c"pf-sampler-rx";
const PORT_RX_ARC: &CStr = c"port-rx-eth";
const DEVICE_INPUT_ARC: &CStr = c"device-input";

unsafe extern "C" {
    /// The running VPP's `VPP_BUILD_VER`, exported by the vpp binary
    /// (libvlib carries a weak empty default).
    static vlib_plugin_app_version: *const c_char;
}

// ---------------------------------------------------------------------------
// What the workers sample with, published under VPP's barrier.

struct Worker {
    cfg: WorkerConfig,
    /// One ring per VPP thread, by thread index; empty until the control
    /// loop has an epoch.
    rings: Vec<RingWriter<'static>>,
    /// Seeds each thread's selector, differently per epoch.
    seed: u64,
}

static WORKER: BarrierRwLock<Worker> = BarrierRwLock::new(Worker {
    cfg: WorkerConfig {
        generation: 0,
        rate: 0,
        header_bytes: 0,
        pools: Vec::new(),
    },
    rings: Vec::new(),
    seed: 0,
});

/// One VPP thread's selection state.
#[repr(align(128))]
struct ThreadState {
    selector: Cell<Selector>,
    /// The configuration generation the selector was set for.
    generation: Cell<u64>,
}

struct PerThread([ThreadState; MAX_WORKERS]);

// SAFETY: element `i` is touched only by the VPP thread whose
// `thread_index()` is `i`; `show pf-sampler` reads the generations with the
// barrier held, when no worker runs.
unsafe impl Sync for PerThread {}

static THREADS: PerThread = PerThread(
    [const {
        ThreadState {
            selector: Cell::new(Selector::new()),
            generation: Cell::new(0),
        }
    }; MAX_WORKERS],
);

// ---------------------------------------------------------------------------
// The sampling node.

#[derive(NextNodes)]
enum SamplerNext {
    #[next_node = "drop"]
    _Drop,
}

#[derive(ErrorCounters)]
enum SamplerCounter {
    #[error_counter(description = "packets sampled", severity = INFO)]
    Sampled,
    #[error_counter(description = "samples dropped: ring full", severity = WARNING)]
    RingFull,
}

static SAMPLER_NODE: SamplerNode = SamplerNode;

#[vlib_node(name = "pf-sampler-rx", instance = SAMPLER_NODE)]
struct SamplerNode;

fn realtime_ns() -> u64 {
    clock_ns(libc::CLOCK_REALTIME)
}

fn monotonic_ns() -> u64 {
    clock_ns(libc::CLOCK_MONOTONIC)
}

fn clock_ns(clock: libc::clockid_t) -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid clock id and a valid out-pointer.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64)
}

fn rx(b: &BufferRef<()>) -> u32 {
    b.vnet_buffer().rx_sw_if_index().into()
}

/// Counts the frame's sample pool and copies out the packets the selector
/// picks; returns (sampled, dropped for a full ring).
#[inline(always)]
fn sample_frame(
    vm: &MainRef,
    b: &mut ArrayVec<&mut BufferRef<()>, FRAME_SIZE>,
    ring: &RingWriter<'static>,
    cfg: &WorkerConfig,
    st: &ThreadState,
) -> (u64, u64) {
    let n = b.len();
    // The pool, per run of one receive interface: a frame on these arcs is
    // one port's, so normally one run.
    let count = |sw: u32, k: usize| {
        let pool = cfg.pool_of(sw);
        if pool != NOT_SAMPLED {
            ring.add_pool(usize::from(pool), Class::Ingress, k as u64);
        }
    };
    let (mut run_start, mut run_sw) = (0, rx(b[0]));
    for (i, b0) in b.iter().enumerate().skip(1) {
        let sw = rx(b0);
        if sw != run_sw {
            count(run_sw, i - run_start);
            (run_start, run_sw) = (i, sw);
        }
    }
    count(run_sw, n - run_start);

    let (mut sampled, mut dropped) = (0, 0);
    let mut sel = st.selector.get();
    sel.frame(n, |i| {
        let b0 = &mut *b[i];
        let sw = rx(b0);
        let pool = cfg.pool_of(sw);
        if pool == NOT_SAMPLED {
            return;
        }
        let len = usize::from(b0.current_length()).min(cfg.header_bytes as usize);
        // SAFETY: the first `current_length` bytes from the current data
        // pointer are the packet's, initialised by the driver.
        let header = unsafe { std::slice::from_raw_parts(b0.current_ptr_mut(), len) };
        let meta = SampleMeta {
            generation: cfg.generation,
            time_ns: realtime_ns(),
            sw_if_index: sw,
            class: Class::Ingress,
            pool_index: pool,
            rate: cfg.rate,
            frame_len: u32::try_from(b0.length_in_chain(vm)).unwrap_or(u32::MAX),
        };
        sampled += 1;
        if !ring.push(&meta, header) {
            dropped += 1;
        }
    });
    st.selector.set(sel);
    if sampled > 0 {
        ring.add_selected(sampled);
    }
    (sampled, dropped)
}

impl vlib::node::Node for SamplerNode {
    type Vector = BufferIndex;
    type Scalar = ();
    type Aux = ();

    type NextNodes = SamplerNext;
    type RuntimeData = ();
    type TraceData = ();
    type Errors = SamplerCounter;
    type FeatureData = ();

    #[inline(always)]
    unsafe fn function(
        &self,
        vm: &mut MainRef,
        node: &mut vlib::NodeRuntimeRef<Self>,
        frame: &mut vlib::FrameRef<Self>,
    ) -> u16 {
        let mut b = ArrayVec::new();
        // SAFETY: invoked by VPP from a feature arc with a valid frame of
        // buffer indices; `()` is this feature's config.
        let from = unsafe { frame.get_buffers::<FRAME_SIZE>(vm, &mut b) };
        let n = b.len();
        if n == 0 {
            return 0;
        }

        let t = usize::from(vm.thread_index());
        let w = WORKER.read(vm);
        if let (Some(ring), Some(st)) = (w.rings.get(t), THREADS.0.get(t)) {
            if st.generation.get() != w.cfg.generation {
                let mut s = Selector::new();
                s.set_rate(
                    w.cfg.rate,
                    w.seed ^ (t as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15),
                );
                st.selector.set(s);
                st.generation.set(w.cfg.generation);
            }
            let (sampled, dropped) = sample_frame(vm, &mut b, ring, &w.cfg, st);
            if sampled > 0 {
                node.increment_error_counter(vm, SamplerCounter::Sampled, sampled);
            }
            if dropped > 0 {
                node.increment_error_counter(vm, SamplerCounter::RingFull, dropped);
            }
        }
        drop(w);

        // On to the next feature. From VPP 26.06 every arc's feature
        // strings share one heap, so equal config indices mean the same
        // next feature: one lookup serves a frame from one interface, and
        // every buffer's index still advances past this node.
        let mut nexts = [MaybeUninit::<u16>::uninit(); FRAME_SIZE];
        let c0 = b[0].current_config_index();
        if b.iter().all(|b0| b0.current_config_index() == c0) {
            // SAFETY: the buffer is on a feature arc this node is part of.
            let next = unsafe { b[0].vnet_feature_next() }.0 as u16;
            let advanced = b[0].current_config_index();
            for b0 in b.iter_mut().skip(1) {
                b0.set_current_config_index(advanced);
            }
            for x in &mut nexts[..n] {
                x.write(next);
            }
        } else {
            for (x, b0) in nexts.iter_mut().zip(b.iter_mut()) {
                // SAFETY: as above.
                x.write(unsafe { b0.vnet_feature_next() }.0 as u16);
            }
        }
        // SAFETY: the first `n` entries were written above; `from` came
        // from this frame, and every next is a node on the arc taking
        // buffer indices.
        unsafe {
            let nexts = std::slice::from_raw_parts(nexts.as_ptr().cast::<u16>(), n);
            vm.buffer_enqueue_to_next(node, from, nexts);
        }
        n as u16
    }
}

vnet_feature_init! {
    identifier: PF_SAMPLER_PORT_RX,
    arc_name: "port-rx-eth",
    node: SamplerNode,
    runs_before: ["ethernet-input"],
}

vnet_feature_init! {
    identifier: PF_SAMPLER_DEVICE_INPUT,
    arc_name: "device-input",
    node: SamplerNode,
    runs_before: ["ethernet-input"],
}

// ---------------------------------------------------------------------------
// The control loop and its view of VPP.

/// Runs `f` with every worker parked at VPP's barrier.
fn with_barrier<R>(vm: &MainRef, f: impl FnOnce(&BarrierHeldMainRef) -> R) -> R {
    // SAFETY: called on the main thread (the control process node or the
    // CLI); sync and release are paired around `f`.
    unsafe {
        vlib_worker_thread_barrier_sync_int(vm.as_ptr(), c"pf-sampler".as_ptr());
        let r = f(BarrierHeldMainRef::from_ptr_mut(vm.as_ptr()));
        vlib_worker_thread_barrier_release(vm.as_ptr());
        r
    }
}

fn feature_enabled(arc: &CStr, sw_if_index: u32) -> bool {
    // SAFETY: both names are NUL-terminated; VPP bounds-checks the index.
    // Only the main thread changes feature state, and this runs on it.
    unsafe { vnet_feature_is_enabled(arc.as_ptr(), NODE_NAME.as_ptr(), sw_if_index) == 1 }
}

struct Glue<'a> {
    vm: &'a MainRef,
}

impl Vpp for Glue<'_> {
    fn resolve(&mut self, name: &str) -> Option<u32> {
        let mut input = UnformatInput::from(name);
        let mut sw: u32 = 0;
        // SAFETY: the variable arguments are what unformat_vnet_sw_interface
        // takes: the vnet main and a u32 to write the index to.
        let parsed = unsafe {
            vlib_helper_unformat_vnet_sw_interface(input.as_ptr(), vnet_get_main(), &mut sw)
        } > 0;
        // VPP's parser stops at the end of a name it knows, so "octeon1/0x"
        // parses as "octeon1/0" with "x" left over: only a name parsed to
        // the end is this interface.
        // SAFETY: `input` is a valid, initialised unformat input.
        let consumed = unsafe { vlib_helper_unformat_get_input(input.as_ptr()) } == !0;
        (parsed && consumed).then_some(sw)
    }

    fn sampling_enabled(&mut self, sw_if_index: u32) -> bool {
        feature_enabled(PORT_RX_ARC, sw_if_index) && feature_enabled(DEVICE_INPUT_ARC, sw_if_index)
    }

    fn apply(&mut self, cfg: &WorkerConfig, enable: &[u32], disable: &[u32]) {
        with_barrier(self.vm, |bvm| {
            let feats = [
                (&PF_SAMPLER_PORT_RX, PORT_RX_ARC),
                (&PF_SAMPLER_DEVICE_INPUT, DEVICE_INPUT_ARC),
            ];
            // Asking VPP before each change makes both idempotent: VPP
            // would otherwise add a feature enabled twice to the arc twice.
            // A failure is retried by the next reconcile, which sees it.
            for &sw in disable {
                for (feat, arc) in feats {
                    if feature_enabled(arc, sw) {
                        let _ = feat.disable(bvm, SwIfIndex::new(sw));
                    }
                }
            }
            for &sw in enable {
                for (feat, arc) in feats {
                    if !feature_enabled(arc, sw) {
                        let _ = feat.enable(bvm, SwIfIndex::new(sw), ());
                    }
                }
            }
            WORKER.write(bvm).cfg = cfg.clone();
        });
    }
}

impl Host for Glue<'_> {
    fn publish_epoch(&mut self, epoch: &'static Epoch) {
        let rings = (0..epoch.layout.workers)
            .map(|r| RingWriter::new(&epoch.layout, epoch.map.words(), r))
            .collect();
        with_barrier(self.vm, |bvm| {
            let mut w = WORKER.write(bvm);
            w.rings = rings;
            w.seed = epoch.id;
        });
    }
}

/// The control loop's state, shared with `show pf-sampler`. Both run on
/// VPP's main thread and the loop never yields while holding it.
static DRIVER: Mutex<Option<Driver>> = Mutex::new(None);

#[derive(NextNodes)]
enum ControlNext {
    #[next_node = "drop"]
    _Drop,
}

#[derive(ErrorCounters)]
enum ControlCounter {
    #[error_counter(description = "unused", severity = INFO)]
    _Unused,
}

static CONTROL_NODE: ControlNode = ControlNode;

// File I/O and formatting need more than the default 32 KiB process stack.
#[vlib_process_node(name = "pf-sampler-control", instance = CONTROL_NODE, log2_stack_bytes = 17)]
struct ControlNode;

impl vlib::ProcessNode for ControlNode {
    type NextNodes = ControlNext;
    type RuntimeData = ();
    type Errors = ControlCounter;

    async fn function(&self, vm: &mut MainRef, _node: &mut vlib::NodeRuntimeRef<Self>) {
        if inert().is_some() {
            return;
        }
        let Ok(dir) = sampler_dir() else {
            return; // made inert at init
        };
        // SAFETY: VPP's thread main is initialised before any process runs.
        let threads = unsafe { (*vlib_get_thread_main_not_inline()).n_vlib_mains } as usize;
        let build = format!(
            "pf-sampler {} vpp {}",
            env!("CARGO_PKG_VERSION"),
            vpp_plugin::VPP_BUILD_VER
        );
        *lock_driver() = Some(Driver::new(dir, threads.clamp(1, MAX_WORKERS), build));
        loop {
            if let Some(d) = lock_driver().as_mut() {
                d.tick(&mut Glue { vm }, realtime_ns(), monotonic_ns());
            }
            sleep(Driver::TICK).await;
        }
    }
}

fn lock_driver() -> std::sync::MutexGuard<'static, Option<Driver>> {
    DRIVER.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// CLI, init and registration.

fn cli_print(vm: &MainRef, s: &str) {
    let Ok(c) = CString::new(s) else { return };
    // SAFETY: `vm` is the CLI's main; "%s" with one NUL-terminated argument.
    unsafe {
        vpp_plugin::bindings::vlib_cli_output(vm.as_ptr(), c"%s".as_ptr().cast_mut(), c.as_ptr());
    }
}

#[vlib_cli_command(path = "show pf-sampler", short_help = "show pf-sampler")]
fn show_cmd(vm: &mut BarrierHeldMainRef, _input: &str) -> Result<(), ErrorStack> {
    let state = match inert() {
        Some(why) => format!("INERT: {why}"),
        None => "active".to_owned(),
    };
    cli_print(
        vm,
        &format!(
            "pf-sampler {} built for vpp {}: {state}",
            env!("CARGO_PKG_VERSION"),
            vpp_plugin::VPP_BUILD_VER
        ),
    );
    match lock_driver().as_ref() {
        Some(d) => d.describe().iter().for_each(|l| cli_print(vm, l)),
        None => cli_print(vm, "control loop not running"),
    }
    let w = WORKER.read(vm);
    // The CLI holds the barrier, so every worker is parked.
    for (t, st) in THREADS.0.iter().enumerate().take(w.rings.len()) {
        cli_print(
            vm,
            &format!("thread {t}: sampling generation {}", st.generation.get()),
        );
    }
    Ok(())
}

/// Why the sampler must stay inert in this process, decided once at init.
static INERT: OnceLock<Option<String>> = OnceLock::new();

fn inert() -> Option<&'static str> {
    INERT.get().and_then(|r| r.as_deref())
}

fn inert_reason() -> Option<String> {
    // SAFETY: VPP points this at a static NUL-terminated string before
    // loading plugins; libvlib's weak default is "".
    let running = unsafe { CStr::from_ptr(vlib_plugin_app_version) }.to_string_lossy();
    if running != vpp_plugin::VPP_BUILD_VER {
        // VPP's loader accepted us because `running` starts with our build
        // (or skipped the check); only equality proves the struct layouts
        // we were compiled against are this VPP's.
        return Some(format!(
            "built for vpp {}, running {running}: struct layouts unproven",
            vpp_plugin::VPP_BUILD_VER
        ));
    }
    sampler_dir().err()
}

#[vlib_init_function]
fn sampler_init(_vm: &mut BarrierHeldMainRef) -> Result<(), ErrorStack> {
    // Never an error: VPP must start and forward whatever this decides.
    let _ = INERT.set(inert_reason());
    Ok(())
}

// A build that could not read VPP_BUILD_VER (no VPP headers, so the
// crate's pre-generated bindings) would load into any VPP and only ever be
// inert: refuse it here instead.
const _: () = assert!(
    !vpp_plugin::VPP_BUILD_VER.is_empty(),
    "vpp-plugin found no VPP_BUILD_VER: build against the VPP's headers (vpp-dev)"
);

/// What VPP's loader is told to require (it compares by prefix): the build
/// compiled against. CI sets `PF_SAMPLER_VERSION_REQUIRED` at build time to
/// prove a refused plugin leaves VPP starting; the exact check at init
/// always uses the real build, so no value here can make the plugin active
/// on any VPP but the one it was compiled for.
const VERSION_REQUIRED: &str = match option_env!("PF_SAMPLER_VERSION_REQUIRED") {
    Some(v) => v,
    None => vpp_plugin::VPP_BUILD_VER,
};

vlib_plugin_register! {
    version: "0.5.0",
    description: "PacketFrame sampler",
    version_required: VERSION_REQUIRED,
}
