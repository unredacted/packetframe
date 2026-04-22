//! PacketFrame probe — userspace wrapper.
//!
//! Embeds the probe BPF ELF (via [`build.rs`](../build.rs)) and
//! exposes a tiny [`run`] helper that attaches the XDP program to an
//! iface, drains the per-packet ringbuf for a fixed duration, and
//! returns the collected samples. The CLI wraps this with output
//! formatting; nothing else in the workspace uses it.
//!
//! Unlike [`crate::fast-path`], the probe is not a [`Module`]
//! implementation. It's a one-shot diagnostic — load, attach, drain,
//! detach — so it never participates in the daemon lifecycle, pin
//! registry, or reconcile flow.

pub const MODULE_NAME: &str = "probe";

/// The compiled probe BPF ELF, staged by `build.rs` and embedded at
/// crate-compile time. Empty (zero bytes) when the BPF toolchain
/// isn't available — see [`PROBE_BPF_AVAILABLE`].
///
/// Note: `include_bytes!` returns a 1-byte-aligned slice. Passing it
/// directly to `aya::Ebpf::load` fails with "Invalid ELF header size
/// or alignment" on every non-8-byte-aligned placement — which is
/// wherever the linker happens to drop a `.rodata` blob of the
/// current size. v0.1.1's probe ELF grew from 1432 → 1608 bytes (CFG
/// map added) and its in-binary address flipped from aligned to
/// unaligned, which is how that release shipped broken. Callers must
/// copy to an aligned buffer — use [`aligned_bpf_copy`].
pub const PROBE_BPF: &[u8] = include_bytes!(env!("PROBE_BPF_OBJ"));

/// `true` when `build.rs` produced a real probe BPF ELF; `false` when
/// the build fell back to the stub. Const-evaluable for use in test
/// early-returns and `#[cfg]`-like branches.
pub const PROBE_BPF_AVAILABLE: bool = !PROBE_BPF.is_empty();

/// Allocate an aligned `Vec<u8>` containing a copy of [`PROBE_BPF`].
/// The system allocator aligns to at least 8 bytes on 64-bit
/// platforms, which is enough for `object`'s ELF parser to read the
/// header without tripping the alignment check (`parse_header` does
/// `u64` reads at offset 0x20, so 1..7-byte offsets trap).
pub fn aligned_bpf_copy() -> Vec<u8> {
    PROBE_BPF.to_vec()
}

/// One packet sample. `#[repr(C)]` and layout-identical to the BPF
/// program's `ProbeEvent` struct — the ringbuf delivers these bytes
/// unchanged. Changing the layout here requires the BPF side to
/// change in lockstep (and vice versa).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct ProbeEvent {
    /// Kernel monotonic timestamp at XDP entry, nanoseconds.
    pub ts_ns: u64,
    /// Full on-the-wire packet length (`data_end - data`), bytes.
    pub pkt_len: u32,
    /// First 16 bytes of the packet as XDP saw them. On conformant
    /// drivers these are the dst MAC, src MAC, and ethertype/first
    /// bytes of the VLAN tag. On non-conformant drivers (e.g.
    /// rvu-nicpf native, §11.1(c)), this is what actually lands and
    /// is the evidence for what to do about it.
    pub head: [u8; 16],
}

#[cfg(target_os = "linux")]
pub use linux_impl::run;

#[cfg(not(target_os = "linux"))]
pub fn run(
    _iface: &str,
    _mode: AttachMode,
    _duration: std::time::Duration,
    _offset: u16,
) -> Result<ProbeOutput, ProbeError> {
    Err(ProbeError::Unsupported(
        "packetframe probe is only supported on Linux".into(),
    ))
}

/// Matches the BPF-side `MAX_OFFSET`. Userspace rejects values above
/// this with [`ProbeError::OffsetTooLarge`] so the operator gets a
/// clear error rather than a silent clamp inside the BPF program.
pub const MAX_OFFSET: u16 = 512;

/// Attach mode the operator requested. Wire-compatible with the
/// fast-path module's SPEC.md §2.3 semantics: `Native` is driver XDP,
/// `Generic` is SKB XDP, `Auto` tries native then falls back. The
/// probe exposes all three so operators can confirm whether a
/// non-conformant head in native mode becomes conformant in generic
/// mode — which it should, since generic runs after the kernel has
/// already built an skb with a standard Ethernet frame.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AttachMode {
    Native,
    Generic,
    Auto,
}

impl AttachMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Generic => "generic",
            Self::Auto => "auto",
        }
    }
}

/// Result of a probe run.
pub struct ProbeOutput {
    /// The attach mode that actually took effect. Interesting when
    /// `AttachMode::Auto` was requested and we fell back to generic.
    pub effective_mode: AttachMode,
    /// Samples collected during the probe window. Ordered by arrival.
    pub samples: Vec<ProbeEvent>,
    /// Offset (bytes) at which the BPF program sampled each packet's
    /// head. Echoed back so the CLI can label the output — e.g. an
    /// rvu-nicpf pre-v6.8 trace at `offset=128` shows the real frame
    /// while `offset=0` shows the headroom zeros.
    pub offset: u16,
    /// Whether the ringbuf went empty before the duration elapsed
    /// (false = probe exited on timer) vs. we kept seeing packets
    /// right up to the end (true). Useful for the CLI to hint at
    /// "bump your duration" vs. "your iface is quiet".
    pub saw_traffic: bool,
    /// Packet count lost to reserve-failures on the BPF side. Always
    /// 0 in v0.1 — the reserve-failure path isn't counted separately
    /// yet. Placeholder so adding a counter doesn't change the API.
    pub dropped_samples: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("no BPF toolchain: the probe was built without nightly + bpf-linker (install via `rustup` + `cargo install --locked bpf-linker`)")]
    NoBpf,
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("--offset {got} exceeds the BPF-side cap of {max}; the program clamps reads to stay verifier-friendly and avoid distant-memory peeks")]
    OffsetTooLarge { got: u16, max: u16 },
    #[error("{0}")]
    Other(String),
}

// ===== Linux-only implementation ==========================================

#[cfg(target_os = "linux")]
mod linux_impl {
    use super::*;

    use std::ffi::CString;
    use std::mem;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    use aya::{
        maps::RingBuf,
        programs::{xdp::XdpFlags, Xdp},
        Ebpf,
    };

    /// Layout mirror of `ProbeCfg` in `bpf/src/main.rs`. Bytes-for-
    /// bytes equal — if you change one, change the other. `u16` +
    /// `[u8; 6]` packs to 8 bytes; `repr(C)` with all-bit-patterns-
    /// valid primitives makes `aya::Pod` safe to impl.
    #[repr(C)]
    #[derive(Copy, Clone, Debug)]
    struct ProbeCfg {
        offset: u16,
        _reserved: [u8; 6],
    }

    // SAFETY: repr(C) + primitive fields + no padding → every bit
    // pattern is valid.
    unsafe impl aya::Pod for ProbeCfg {}

    /// Load the probe BPF ELF, attach it to `iface` in the requested
    /// mode, drain the ringbuf for `duration`, then detach. Returns
    /// samples in arrival order.
    ///
    /// `offset` selects the byte offset at which the BPF program
    /// samples each packet's head — normally `0` (real frame start).
    /// Non-zero values are for diagnosing drivers that point
    /// `xdp->data` into headroom (e.g. `128` on rvu-nicpf pre-v6.8,
    /// see SPEC.md §11.1(c)). Clamped to [`MAX_OFFSET`] — past that,
    /// the function rejects rather than silently truncate.
    ///
    /// Uses a short (~50ms) poll interval on the ringbuf fd so
    /// ctrl-c / duration expiry is responsive even under load.
    pub fn run(
        iface: &str,
        mode: AttachMode,
        duration: Duration,
        offset: u16,
    ) -> Result<ProbeOutput, ProbeError> {
        if !PROBE_BPF_AVAILABLE {
            return Err(ProbeError::NoBpf);
        }
        if offset > MAX_OFFSET {
            return Err(ProbeError::OffsetTooLarge {
                got: offset,
                max: MAX_OFFSET,
            });
        }

        let ifindex = if_nametoindex(iface)?;

        // Heap-copy PROBE_BPF into an aligned `Vec<u8>` — passing the
        // raw `include_bytes!` static to `Ebpf::load` fails on
        // unaligned placements (v0.1.1 regression). The alignment
        // pattern mirrors `packetframe-fast-path::aligned_bpf_copy`.
        let bytes = aligned_bpf_copy();
        let mut bpf = Ebpf::load(&bytes).map_err(|e| {
            ProbeError::Other(format!(
                "load probe BPF ELF via aya::Ebpf::load: {}",
                fmt_error_chain(&e)
            ))
        })?;

        // Populate CFG before attach so the very first packet sees the
        // operator-requested offset, not the default 0.
        {
            use aya::maps::Array;
            let map = bpf
                .map_mut("CFG")
                .ok_or_else(|| ProbeError::Other("CFG map missing from probe ELF".into()))?;
            let mut arr: Array<_, ProbeCfg> = Array::try_from(map)
                .map_err(|e| ProbeError::Other(format!("Array::try_from CFG: {e}")))?;
            arr.set(
                0,
                ProbeCfg {
                    offset,
                    _reserved: [0; 6],
                },
                0,
            )
            .map_err(|e| ProbeError::Other(format!("CFG set: {e}")))?;
        }

        // Attach in the requested mode, with the same "auto" semantics
        // that the fast-path module uses — try native, fall back to
        // generic if the driver refuses the native attach. `Auto` is
        // the operator-friendly default; explicit `native` / `generic`
        // are for deliberate A/B testing of native vs skb delivery.
        let (link_id, effective_mode) = {
            let prog: &mut Xdp = bpf
                .program_mut("probe")
                .ok_or_else(|| {
                    ProbeError::Other("probe program missing from compiled BPF ELF".into())
                })?
                .try_into()
                .map_err(|e| ProbeError::Other(format!("probe program is not XDP-typed: {e}")))?;

            prog.load().map_err(|e| {
                ProbeError::Other(format!(
                    "verifier rejected probe program: {e} — this is a PacketFrame bug; file an issue"
                ))
            })?;

            match mode {
                AttachMode::Native => (
                    prog.attach_to_if_index(ifindex, XdpFlags::DRV_MODE)
                        .map_err(|e| {
                            ProbeError::Other(format!(
                                "native XDP attach on {iface}: {e} — \
                                 driver may not support native XDP; try `--mode generic`"
                            ))
                        })?,
                    AttachMode::Native,
                ),
                AttachMode::Generic => (
                    prog.attach_to_if_index(ifindex, XdpFlags::SKB_MODE)
                        .map_err(|e| {
                            ProbeError::Other(format!("generic XDP attach on {iface}: {e}"))
                        })?,
                    AttachMode::Generic,
                ),
                AttachMode::Auto => match prog.attach_to_if_index(ifindex, XdpFlags::DRV_MODE) {
                    Ok(id) => (id, AttachMode::Native),
                    Err(native_err) => {
                        tracing::info!(
                            iface,
                            error = %native_err,
                            "native XDP attach failed; falling back to generic"
                        );
                        (
                            prog.attach_to_if_index(ifindex, XdpFlags::SKB_MODE)
                                .map_err(|e| {
                                    ProbeError::Other(format!(
                                        "generic XDP fallback attach on {iface}: {e}"
                                    ))
                                })?,
                            AttachMode::Generic,
                        )
                    }
                },
            }
        };

        // Wrap the drain + detach in a closure so a mid-loop error
        // still detaches cleanly. Without this, a panic or early
        // return would leak an XDP attach on the iface; not
        // catastrophic (operator can `ip link set dev X xdp off`)
        // but worth avoiding.
        let drain_result = drain_events(&mut bpf, duration);

        {
            let prog: &mut Xdp = bpf
                .program_mut("probe")
                .expect("program was present at attach")
                .try_into()
                .expect("program was XDP at attach");
            if let Err(e) = prog.detach(link_id) {
                tracing::warn!(iface, error = %e, "probe detach failed (best-effort)");
            }
        }

        let (samples, saw_traffic) = drain_result?;
        Ok(ProbeOutput {
            effective_mode,
            samples,
            offset,
            saw_traffic,
            dropped_samples: 0,
        })
    }

    /// Poll the ringbuf fd for up to `duration`, collecting every
    /// event byte-slice into a `ProbeEvent` via copy-out. 50 ms poll
    /// interval keeps the outer duration timer honest and the loop
    /// cheap when the iface is quiet.
    fn drain_events(
        bpf: &mut Ebpf,
        duration: Duration,
    ) -> Result<(Vec<ProbeEvent>, bool), ProbeError> {
        let mut ring: RingBuf<_> = RingBuf::try_from(
            bpf.map_mut("EVENTS")
                .ok_or_else(|| ProbeError::Other("EVENTS ringbuf missing from ELF".into()))?,
        )
        .map_err(|e| ProbeError::Other(format!("open EVENTS ringbuf: {e}")))?;

        let fd = ring.as_raw_fd();
        let deadline = Instant::now() + duration;
        let mut samples: Vec<ProbeEvent> = Vec::new();
        let mut any = false;

        loop {
            // Drain whatever is already queued before we poll — keeps
            // us from sleeping with samples sitting in the ringbuf.
            while let Some(item) = ring.next() {
                let bytes: &[u8] = &item;
                if bytes.len() < mem::size_of::<ProbeEvent>() {
                    tracing::warn!(
                        got = bytes.len(),
                        want = mem::size_of::<ProbeEvent>(),
                        "probe ringbuf item shorter than ProbeEvent; skipping"
                    );
                    continue;
                }
                // SAFETY: ProbeEvent is `#[repr(C)]` with primitive
                // fields and a fixed-size byte array; every bit pattern
                // is a valid ProbeEvent. We copy-out (not reinterpret)
                // so alignment is irrelevant.
                let ev: ProbeEvent = unsafe {
                    let mut dst = mem::MaybeUninit::<ProbeEvent>::uninit();
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        dst.as_mut_ptr() as *mut u8,
                        mem::size_of::<ProbeEvent>(),
                    );
                    dst.assume_init()
                };
                samples.push(ev);
                any = true;
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            let poll_ms = remaining.as_millis().min(50) as i32;
            let mut pfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let rc = unsafe { libc::poll(&mut pfd as *mut _, 1, poll_ms) };
            if rc < 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(ProbeError::Other(format!("poll EVENTS fd: {e}")));
            }
            // rc == 0 is a timeout; loop and re-check duration.
        }

        Ok((samples, any))
    }

    fn if_nametoindex(name: &str) -> Result<u32, ProbeError> {
        let c = CString::new(name)
            .map_err(|_| ProbeError::Other(format!("iface name `{name}` contains NUL byte")))?;
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        if idx == 0 {
            let e = std::io::Error::last_os_error();
            return Err(ProbeError::Other(format!(
                "if_nametoindex({name}): {e} — iface does not exist in current netns"
            )));
        }
        Ok(idx)
    }

    /// Render an error's full source chain into one string. aya's
    /// `EbpfError::ParseError` display drops the inner `object`
    /// error — so a bare `{e}` emits only `"error parsing ELF data"`
    /// with no indication whether the cause is alignment, a truncated
    /// header, a malformed section, etc. Walking `Error::source()`
    /// picks up what the outer formatter skipped.
    fn fmt_error_chain(e: &dyn std::error::Error) -> String {
        let mut out = e.to_string();
        let mut src = e.source();
        while let Some(s) = src {
            out.push_str(" → ");
            out.push_str(&s.to_string());
            src = s.source();
        }
        out
    }
}
