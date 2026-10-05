//! The reader side of `SAMPLES`: one perf ring per CPU, opened here
//! rather than through aya so the wakeup policy is ours.
//!
//! aya opens each ring with `wakeup_events = 1`, so every sample queues
//! an irq_work to wake a reader: a self-IPI per sample. On the forward
//! path at 1:1000 that measured +8% in a VM, against −0.4% (noise) with
//! the same samples selected and refused for want of a ring. A reader
//! that drains on a timer needs no wakeup, so these rings ask for one
//! per ring-full at most (`watermark`).

// The ring walk serves the Linux reader only, but builds everywhere so
// its tests run on any host.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

/// A perf ring's data area, read by copying out: the kernel writes the
/// rest of it while a drain reads what it published.
pub(crate) trait RingData {
    fn size(&self) -> usize;
    fn copy_out(&self, at: usize, out: &mut [u8]);
}

impl RingData for [u8] {
    fn size(&self) -> usize {
        self.len()
    }
    fn copy_out(&self, at: usize, out: &mut [u8]) {
        out.copy_from_slice(&self[at..at + out.len()]);
    }
}

const PERF_RECORD_LOST: u32 = 2;
const PERF_RECORD_SAMPLE: u32 = 9;

/// Hand the raw payload of each sample published in `[tail, head)` to
/// `f`, and return the samples the kernel reported lost there.
pub(crate) fn walk<R: RingData + ?Sized>(
    ring: &R,
    mut tail: u64,
    head: u64,
    buf: &mut Vec<u8>,
    f: &mut dyn FnMut(&[u8]),
) -> u64 {
    let size = ring.size() as u64;
    let mut lost = 0;
    while tail + 8 <= head {
        let at = (tail % size) as usize;
        let mut hdr = [0u8; 8];
        copy_wrapping(ring, at, &mut hdr);
        let kind = u32::from_ne_bytes(hdr[0..4].try_into().unwrap());
        let len = usize::from(u16::from_ne_bytes(hdr[6..8].try_into().unwrap()));
        if len < 8 || tail + len as u64 > head {
            // Not a record the kernel published; the caller skips to head.
            break;
        }
        buf.resize(len, 0);
        copy_wrapping(ring, at, buf);
        match kind {
            PERF_RECORD_SAMPLE if len >= 12 => {
                let raw = u32::from_ne_bytes(buf[8..12].try_into().unwrap()) as usize;
                if 12 + raw <= len {
                    f(&buf[12..12 + raw]);
                }
            }
            PERF_RECORD_LOST if len >= 24 => {
                lost += u64::from_ne_bytes(buf[16..24].try_into().unwrap());
            }
            _ => {}
        }
        tail += len as u64;
    }
    lost
}

fn copy_wrapping<R: RingData + ?Sized>(ring: &R, at: usize, out: &mut [u8]) {
    let first = out.len().min(ring.size() - at);
    ring.copy_out(at, &mut out[..first]);
    if first < out.len() {
        ring.copy_out(0, &mut out[first..]);
    }
}

#[cfg(target_os = "linux")]
pub use linux::SampleRings;

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{walk, RingData};

    /// `struct perf_event_attr` to `PERF_ATTR_SIZE_VER0`; the kernel
    /// zero-extends the rest.
    #[repr(C)]
    struct PerfEventAttr {
        kind: u32,
        size: u32,
        config: u64,
        sample_period: u64,
        sample_type: u64,
        read_format: u64,
        flags: u64,
        wakeup_watermark: u32,
        bp_type: u32,
        config1: u64,
    }

    const _: () = assert!(std::mem::size_of::<PerfEventAttr>() == 64);

    const PERF_TYPE_SOFTWARE: u32 = 1;
    const PERF_COUNT_SW_BPF_OUTPUT: u64 = 10;
    const PERF_SAMPLE_RAW: u64 = 1 << 10;
    /// `perf_event_attr.watermark`: wake by bytes, not by events.
    const ATTR_WATERMARK: u64 = 1 << 14;
    const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;
    /// `struct perf_event_mmap_page` offsets.
    const DATA_HEAD: usize = 1024;
    const DATA_TAIL: usize = 1032;
    const DATA_OFFSET: usize = 1040;
    const DATA_SIZE: usize = 1048;

    /// The rings flow-export reads `SAMPLES` through. Dropping them
    /// removes them from the map, so the program's output fails fast
    /// (`sample_emit_failed`) instead of filling rings nobody reads.
    pub struct SampleRings {
        map: OwnedFd,
        rings: Vec<Ring>,
        buf: Vec<u8>,
    }

    struct Ring {
        cpu: u32,
        _event: OwnedFd,
        page: *mut u8,
        mapped: usize,
        data: *const u8,
        size: usize,
    }

    // SAFETY: each mapping is owned by its `Ring` and touched only
    // through `&mut SampleRings`.
    unsafe impl Send for SampleRings {}

    impl RingData for Ring {
        fn size(&self) -> usize {
            self.size
        }
        fn copy_out(&self, at: usize, out: &mut [u8]) {
            // SAFETY: `walk` keeps `at + out.len()` within the data area,
            // and reads only bytes the kernel published before `head`.
            unsafe { std::ptr::copy_nonoverlapping(self.data.add(at), out.as_mut_ptr(), out.len()) }
        }
    }

    impl SampleRings {
        /// Open a ring of `pages` pages (a power of two) on each of
        /// `cpus` and install it in `samples`, the `SAMPLES` map.
        pub fn open(samples: BorrowedFd<'_>, cpus: &[u32], pages: usize) -> io::Result<Self> {
            if !pages.is_power_of_two() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{pages} ring pages: not a power of two"),
                ));
            }
            let mut out = Self {
                map: samples.try_clone_to_owned()?,
                rings: Vec::with_capacity(cpus.len()),
                buf: Vec::new(),
            };
            for &cpu in cpus {
                let ring = Ring::open(cpu, pages)?;
                // Pushed before it is installed, so Drop removes it if a
                // later CPU fails.
                let fd = ring._event.as_raw_fd() as u32;
                out.rings.push(ring);
                map_elem(&out.map, BPF_MAP_UPDATE_ELEM, cpu, Some(fd))?;
            }
            Ok(out)
        }

        /// Hand every sample published since the last drain to `f` with
        /// its CPU, and return how many the kernel lost meanwhile.
        pub fn drain(&mut self, mut f: impl FnMut(u32, &[u8])) -> u64 {
            let mut lost = 0;
            for r in &self.rings {
                // SAFETY: both words lie in the mapped control page; the
                // kernel publishes `data_head` with release semantics and
                // reads `data_tail` to know what it may overwrite.
                let (head, tail) = unsafe {
                    (
                        &*(r.page.add(DATA_HEAD) as *const AtomicU64),
                        &*(r.page.add(DATA_TAIL) as *const AtomicU64),
                    )
                };
                let h = head.load(Ordering::Acquire);
                let t = tail.load(Ordering::Relaxed);
                lost += walk(r, t, h, &mut self.buf, &mut |e| f(r.cpu, e));
                tail.store(h, Ordering::Release);
            }
            lost
        }
    }

    impl Ring {
        fn open(cpu: u32, pages: usize) -> io::Result<Self> {
            let page = page_size();
            let attr = PerfEventAttr {
                kind: PERF_TYPE_SOFTWARE,
                size: std::mem::size_of::<PerfEventAttr>() as u32,
                config: PERF_COUNT_SW_BPF_OUTPUT,
                sample_period: 1,
                sample_type: PERF_SAMPLE_RAW,
                read_format: 0,
                flags: ATTR_WATERMARK,
                // Capped by the kernel at the data size: one wakeup per
                // ring-full.
                wakeup_watermark: u32::try_from(pages * page).unwrap_or(u32::MAX),
                bp_type: 0,
                config1: 0,
            };
            // SAFETY: a valid attr for the call's duration.
            let fd = unsafe {
                libc::syscall(
                    libc::SYS_perf_event_open,
                    &attr as *const PerfEventAttr,
                    -1 as libc::pid_t,
                    cpu as libc::c_int,
                    -1 as libc::c_int,
                    PERF_FLAG_FD_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the kernel returned a new fd we own.
            let event = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            let mapped = (pages + 1) * page;
            // SAFETY: mapping the event's ring as perf_event_open(2)
            // describes; unmapped in Drop.
            let base = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    mapped,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    event.as_raw_fd(),
                    0,
                )
            };
            if base == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            let base = base as *mut u8;
            // SAFETY: the control page is mapped; the kernel sets both
            // words before the mapping is returned.
            let (offset, size) = unsafe {
                (
                    *(base.add(DATA_OFFSET) as *const u64) as usize,
                    *(base.add(DATA_SIZE) as *const u64) as usize,
                )
            };
            let (offset, size) = if size == 0 {
                (page, pages * page)
            } else {
                (offset, size)
            };
            Ok(Self {
                cpu,
                _event: event,
                page: base,
                mapped,
                // SAFETY: inside the mapping.
                data: unsafe { base.add(offset) },
                size,
            })
        }
    }

    impl Drop for Ring {
        fn drop(&mut self) {
            // SAFETY: our own mapping, unmapped once.
            unsafe { libc::munmap(self.page.cast(), self.mapped) };
        }
    }

    impl Drop for SampleRings {
        fn drop(&mut self) {
            for r in &self.rings {
                let _ = map_elem(&self.map, BPF_MAP_DELETE_ELEM, r.cpu, None);
            }
        }
    }

    const BPF_MAP_UPDATE_ELEM: libc::c_long = 2;
    const BPF_MAP_DELETE_ELEM: libc::c_long = 3;

    /// `union bpf_attr`'s element-command variant.
    #[repr(C)]
    struct MapElemAttr {
        map_fd: u32,
        _pad: u32,
        key: u64,
        value: u64,
        flags: u64,
    }

    fn map_elem(map: &OwnedFd, cmd: libc::c_long, key: u32, value: Option<u32>) -> io::Result<()> {
        let attr = MapElemAttr {
            map_fd: map.as_raw_fd() as u32,
            _pad: 0,
            key: &key as *const u32 as u64,
            value: value.as_ref().map_or(0, |v| v as *const u32 as u64),
            flags: 0,
        };
        // SAFETY: `attr` and what it points to outlive the call.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                cmd,
                &attr as *const MapElemAttr,
                std::mem::size_of::<MapElemAttr>() as libc::c_uint,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn page_size() -> usize {
        // SAFETY: no preconditions.
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(raw: &[u8]) -> Vec<u8> {
        // header (8) + raw size (4) + raw, padded to 8 as the kernel does.
        let len = (12 + raw.len()).next_multiple_of(8);
        let mut r = Vec::with_capacity(len);
        r.extend_from_slice(&PERF_RECORD_SAMPLE.to_ne_bytes());
        r.extend_from_slice(&0u16.to_ne_bytes());
        r.extend_from_slice(&(len as u16).to_ne_bytes());
        r.extend_from_slice(&((len - 12) as u32).to_ne_bytes());
        r.extend_from_slice(raw);
        r.resize(len, 0);
        r
    }

    fn lost(n: u64) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&PERF_RECORD_LOST.to_ne_bytes());
        r.extend_from_slice(&0u16.to_ne_bytes());
        r.extend_from_slice(&24u16.to_ne_bytes());
        r.extend_from_slice(&7u64.to_ne_bytes());
        r.extend_from_slice(&n.to_ne_bytes());
        r
    }

    /// Lay `records` into a ring of `size` bytes starting at `tail`.
    fn ring(size: usize, tail: u64, records: &[Vec<u8>]) -> (Vec<u8>, u64) {
        let mut ring = vec![0xee; size];
        let mut at = tail;
        for r in records {
            for b in r {
                ring[(at % size as u64) as usize] = *b;
                at += 1;
            }
        }
        (ring, at)
    }

    fn drain(ring: &[u8], tail: u64, head: u64) -> (Vec<Vec<u8>>, u64) {
        let mut out = Vec::new();
        let n = walk(ring, tail, head, &mut Vec::new(), &mut |e| {
            out.push(e.to_vec())
        });
        (out, n)
    }

    #[test]
    fn samples_and_losses_come_out_in_order() {
        let recs = [sample(&[1; 40]), lost(5), sample(&[2; 45])];
        let (r, head) = ring(256, 0, &recs);
        let (out, n) = drain(&r, 0, head);
        assert_eq!(n, 5);
        assert_eq!(out.len(), 2);
        assert_eq!(&out[0][..40], &[1; 40]);
        assert_eq!(&out[1][..45], &[2; 45]);
        assert_eq!(
            out[1].len(),
            52,
            "the ring's padding comes with the payload"
        );
    }

    #[test]
    fn a_record_across_the_ring_end_is_reassembled() {
        let recs = [sample(&[3; 60]), sample(&[4; 60])];
        // Start 24 bytes before the end: the first record wraps.
        let (r, head) = ring(256, 1000 * 256 - 24, &recs);
        let (out, _) = drain(&r, 1000 * 256 - 24, head);
        assert_eq!(out.len(), 2);
        assert_eq!(&out[0][..60], &[3; 60]);
        assert_eq!(&out[1][..60], &[4; 60]);
    }

    #[test]
    fn a_record_past_head_is_not_read() {
        let recs = [sample(&[5; 8]), sample(&[6; 8])];
        let (r, head) = ring(128, 0, &recs);
        let (out, _) = drain(&r, 0, head - 8);
        assert_eq!(out.len(), 1, "the second is not wholly published");
        let (out, _) = drain(&[0; 64], 0, 64);
        assert!(out.is_empty(), "a zero-length header stops the walk");
    }
}
