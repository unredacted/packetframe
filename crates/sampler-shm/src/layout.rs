//! Geometry of an epoch file, and its header.
//!
//! An epoch file is a run of `u64` words:
//!
//! | Region | Writer | Contents |
//! |---|---|---|
//! | header | plugin, once, then `ready` | magic, version, epoch, geometry, build |
//! | status | plugin's main thread | heartbeat, then a seqlocked snapshot ([`crate::status`]) |
//! | producers | one per ring, its worker | `head`, counters, sample pool ([`crate::ring`]) |
//! | slots | one ring per worker | fixed-size samples |
//! | consumer | the one consumer | `tail` per ring |
//!
//! Regions start on 128-byte lines (octeon9's cache line). The consumer
//! region starts on a 64 KiB boundary, the largest page size PacketFrame
//! runs on, so a reader can map just that region writable — on 4 KiB and
//! 64 KiB kernels alike — and everything else read-only.
//!
//! The geometry is a pure function of three parameters (workers, slots per
//! ring, header capacity), so a reader recomputes it and refuses a header
//! whose stored offsets disagree, before trusting any offset in it.

use crate::sync::{AtomicU64, Ordering};

pub const MAGIC: u64 = u64::from_be_bytes(*b"PFSMPLR1");
/// Bumped whenever any offset, word meaning or region changes.
pub const VERSION: u64 = 1;

pub const WORD: usize = 8;
/// Words per 128-byte line.
pub const LINE_WORDS: usize = 16;
/// Alignment of the consumer region, in bytes.
pub const CONSUMER_ALIGN: usize = 64 * 1024;
const CONSUMER_ALIGN_WORDS: usize = CONSUMER_ALIGN / WORD;

pub const MAX_WORKERS: usize = 256;
pub const MAX_SLOTS: usize = 1 << 16;
pub const MAX_INTERFACES: usize = 64;
pub const CLASSES: usize = 3;
/// Longest interface name, in bytes.
pub const NAME_BYTES: usize = 64;
/// Largest per-sample packet-header capacity, in bytes.
pub const HEADER_CAPACITY_MAX: usize = 512;
/// No geometry may describe a file larger than this.
pub const MAX_FILE_BYTES: usize = 1 << 30;

/// Header word indices.
pub(crate) mod hdr {
    pub const MAGIC: usize = 0;
    pub const VERSION: usize = 1;
    /// 0 until every other word of the header, the status and the rings is
    /// initialised; stored with Release, read with Acquire.
    pub const READY: usize = 2;
    pub const EPOCH: usize = 3;
    pub const CREATED_NS: usize = 4;
    pub const WORKERS: usize = 5;
    pub const SLOTS: usize = 6;
    pub const HEADER_CAPACITY: usize = 7;
    pub const SLOT_WORDS: usize = 8;
    pub const STATUS_OFF: usize = 9;
    pub const PRODUCER_OFF: usize = 10;
    pub const PRODUCER_STRIDE: usize = 11;
    pub const SLOTS_OFF: usize = 12;
    pub const RING_STRIDE: usize = 13;
    pub const CONSUMER_OFF: usize = 14;
    pub const FILE_WORDS: usize = 15;
    /// Eight words of text naming the plugin build and the VPP it was
    /// built for.
    pub const BUILD: usize = 16;
    pub const BUILD_WORDS: usize = 8;
    pub const WORDS: usize = 32;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LayoutError {
    #[error("unsupported geometry: {0}")]
    Geometry(&'static str),
    #[error("{actual} bytes is too short for an epoch header")]
    TooShort { actual: u64 },
    #[error("not ready: the plugin has not finished initialising it")]
    NotReady,
    #[error("bad magic {0:#018x}")]
    BadMagic(u64),
    #[error("layout version {found}; this build reads version {VERSION}")]
    Version { found: u64 },
    #[error("header field `{0}` disagrees with the geometry it describes")]
    Inconsistent(&'static str),
    #[error("file is {actual} bytes; its header describes {expected}")]
    FileLen { expected: u64, actual: u64 },
}

/// Where everything is, in words from the start of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Rings, one per VPP worker (or the main thread when there are none).
    pub workers: usize,
    /// Slots per ring, a power of two.
    pub slots: usize,
    /// Packet-header bytes one slot holds.
    pub header_capacity: usize,
    pub slot_words: usize,
    pub status_off: usize,
    pub producer_off: usize,
    pub producer_stride: usize,
    pub slots_off: usize,
    pub ring_stride: usize,
    pub consumer_off: usize,
    pub file_words: usize,
}

fn round_up(n: u64, to: usize) -> u64 {
    n.div_ceil(to as u64) * to as u64
}

impl Layout {
    pub fn new(workers: usize, slots: usize, header_capacity: usize) -> Result<Self, LayoutError> {
        if workers == 0 || workers > MAX_WORKERS {
            return Err(LayoutError::Geometry("workers must be 1..=256"));
        }
        if !(2..=MAX_SLOTS).contains(&slots) || !slots.is_power_of_two() {
            return Err(LayoutError::Geometry(
                "slots per ring must be a power of two in 2..=65536",
            ));
        }
        if header_capacity > HEADER_CAPACITY_MAX {
            return Err(LayoutError::Geometry("header capacity must be <= 512"));
        }
        // In u64, so no target's usize can wrap before the size check (the
        // largest parameters describe about 9 GB); once the file is known
        // to be at most 1 GiB every value fits any usize.
        let (workers64, slots64) = (workers as u64, slots as u64);
        let slot_words = (crate::ring::SLOT_FIXED_WORDS + header_capacity.div_ceil(WORD)) as u64;
        let status_off = round_up(hdr::WORDS as u64, LINE_WORDS);
        let producer_off = round_up(status_off + crate::status::REGION_WORDS as u64, LINE_WORDS);
        let producer_stride = round_up(crate::ring::PRODUCER_WORDS as u64, LINE_WORDS);
        let slots_off = producer_off + workers64 * producer_stride;
        let ring_stride = round_up(slots64 * slot_words, LINE_WORDS);
        let consumer_off = round_up(slots_off + workers64 * ring_stride, CONSUMER_ALIGN_WORDS);
        let file_words =
            consumer_off + round_up(workers64 * LINE_WORDS as u64, CONSUMER_ALIGN_WORDS);
        if file_words * WORD as u64 > MAX_FILE_BYTES as u64 {
            return Err(LayoutError::Geometry("the file would exceed 1 GiB"));
        }
        let n = |v: u64| v as usize;
        Ok(Self {
            workers,
            slots,
            header_capacity,
            slot_words: n(slot_words),
            status_off: n(status_off),
            producer_off: n(producer_off),
            producer_stride: n(producer_stride),
            slots_off: n(slots_off),
            ring_stride: n(ring_stride),
            consumer_off: n(consumer_off),
            file_words: n(file_words),
        })
    }

    pub fn file_len(&self) -> usize {
        self.file_words * WORD
    }

    /// Byte offset of the consumer region: a multiple of [`CONSUMER_ALIGN`].
    pub fn consumer_offset(&self) -> usize {
        self.consumer_off * WORD
    }

    pub fn consumer_len(&self) -> usize {
        (self.file_words - self.consumer_off) * WORD
    }

    pub fn status<'a>(&self, file: &'a [AtomicU64]) -> &'a [AtomicU64] {
        &file[self.status_off..self.status_off + crate::status::REGION_WORDS]
    }

    pub fn producer<'a>(&self, file: &'a [AtomicU64], ring: usize) -> &'a [AtomicU64] {
        assert!(ring < self.workers);
        let at = self.producer_off + ring * self.producer_stride;
        &file[at..at + crate::ring::PRODUCER_WORDS]
    }

    pub fn slots<'a>(&self, file: &'a [AtomicU64], ring: usize) -> &'a [AtomicU64] {
        assert!(ring < self.workers);
        let at = self.slots_off + ring * self.ring_stride;
        &file[at..at + self.slots * self.slot_words]
    }

    /// A ring's `tail`, in the consumer region. `consumer` is that region
    /// alone (the reader maps it separately) or, for the plugin, the
    /// whole file sliced from [`Self::consumer_off`].
    pub fn tail<'a>(&self, consumer: &'a [AtomicU64], ring: usize) -> &'a AtomicU64 {
        assert!(ring < self.workers);
        &consumer[ring * LINE_WORDS]
    }

    /// Writes every header word except `ready` ([`mark_ready`]).
    pub fn write_header(&self, file: &[AtomicU64], epoch: u64, created_ns: u64, build: &str) {
        let set = |i: usize, v: usize| file[i].store(v as u64, Ordering::Relaxed);
        file[hdr::MAGIC].store(MAGIC, Ordering::Relaxed);
        file[hdr::VERSION].store(VERSION, Ordering::Relaxed);
        file[hdr::READY].store(0, Ordering::Relaxed);
        file[hdr::EPOCH].store(epoch, Ordering::Relaxed);
        file[hdr::CREATED_NS].store(created_ns, Ordering::Relaxed);
        set(hdr::WORKERS, self.workers);
        set(hdr::SLOTS, self.slots);
        set(hdr::HEADER_CAPACITY, self.header_capacity);
        set(hdr::SLOT_WORDS, self.slot_words);
        set(hdr::STATUS_OFF, self.status_off);
        set(hdr::PRODUCER_OFF, self.producer_off);
        set(hdr::PRODUCER_STRIDE, self.producer_stride);
        set(hdr::SLOTS_OFF, self.slots_off);
        set(hdr::RING_STRIDE, self.ring_stride);
        set(hdr::CONSUMER_OFF, self.consumer_off);
        set(hdr::FILE_WORDS, self.file_words);
        put_text(&file[hdr::BUILD..hdr::BUILD + hdr::BUILD_WORDS], build);
    }
}

/// Publishes the file to readers: every store before this one, by this
/// thread, is visible to a reader that sees `ready`.
pub fn mark_ready(file: &[AtomicU64]) {
    file[hdr::READY].store(1, Ordering::Release);
}

/// What a reader learns from a valid, ready header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub layout: Layout,
    pub epoch: u64,
    pub created_ns: u64,
    pub build: String,
}

/// Validates the header of a file of `file.len()` words. Nothing in it is
/// trusted until its geometry has been recomputed and matched, so every
/// slice a reader takes afterwards is in bounds.
pub fn read_header(file: &[AtomicU64]) -> Result<Header, LayoutError> {
    let actual = (file.len() * WORD) as u64;
    if file.len() < hdr::WORDS {
        return Err(LayoutError::TooShort { actual });
    }
    let ready = file[hdr::READY].load(Ordering::Acquire);
    let get = |i: usize| file[i].load(Ordering::Relaxed);
    let magic = get(hdr::MAGIC);
    if magic != MAGIC {
        return Err(LayoutError::BadMagic(magic));
    }
    let version = get(hdr::VERSION);
    if version != VERSION {
        return Err(LayoutError::Version { found: version });
    }
    if ready != 1 {
        return Err(LayoutError::NotReady);
    }
    let param = |i: usize| usize::try_from(get(i)).unwrap_or(usize::MAX);
    let layout = Layout::new(
        param(hdr::WORKERS),
        param(hdr::SLOTS),
        param(hdr::HEADER_CAPACITY),
    )?;
    for (i, field, want) in [
        (hdr::SLOT_WORDS, "slot_words", layout.slot_words),
        (hdr::STATUS_OFF, "status_off", layout.status_off),
        (hdr::PRODUCER_OFF, "producer_off", layout.producer_off),
        (
            hdr::PRODUCER_STRIDE,
            "producer_stride",
            layout.producer_stride,
        ),
        (hdr::SLOTS_OFF, "slots_off", layout.slots_off),
        (hdr::RING_STRIDE, "ring_stride", layout.ring_stride),
        (hdr::CONSUMER_OFF, "consumer_off", layout.consumer_off),
        (hdr::FILE_WORDS, "file_words", layout.file_words),
    ] {
        if param(i) != want {
            return Err(LayoutError::Inconsistent(field));
        }
    }
    let expected = layout.file_len() as u64;
    if expected != actual {
        return Err(LayoutError::FileLen { expected, actual });
    }
    Ok(Header {
        layout,
        epoch: get(hdr::EPOCH),
        created_ns: get(hdr::CREATED_NS),
        build: get_text(&file[hdr::BUILD..hdr::BUILD + hdr::BUILD_WORDS]),
    })
}

/// Packs `s` into `words`, truncated to their capacity and NUL-padded.
pub(crate) fn put_text_into(words: &mut [u64], s: &str) {
    let bytes = s.as_bytes();
    for (i, w) in words.iter_mut().enumerate() {
        let mut b = [0u8; WORD];
        let from = (i * WORD).min(bytes.len());
        let to = ((i + 1) * WORD).min(bytes.len());
        b[..to - from].copy_from_slice(&bytes[from..to]);
        *w = u64::from_le_bytes(b);
    }
}

/// The text [`put_text_into`] packed: up to the first NUL, anything outside
/// printable ASCII shown as `?`.
pub(crate) fn get_text_from(words: &[u64]) -> String {
    words
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .take_while(|&b| b != 0)
        .map(|b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '?'
            }
        })
        .collect()
}

fn put_text(words: &[AtomicU64], s: &str) {
    let mut v = vec![0; words.len()];
    put_text_into(&mut v, s);
    for (w, x) in words.iter().zip(v) {
        w.store(x, Ordering::Relaxed);
    }
}

fn get_text(words: &[AtomicU64]) -> String {
    let v: Vec<u64> = words.iter().map(|w| w.load(Ordering::Relaxed)).collect();
    get_text_from(&v)
}

/// A zeroed run of words standing in for a mapped file, for tests here and
/// in the loom suite.
pub fn words(n: usize) -> Box<[AtomicU64]> {
    (0..n).map(|_| AtomicU64::new(0)).collect()
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn regions_are_aligned_and_disjoint() {
        for (workers, slots, cap) in [(1, 2, 0), (2, 4096, 128), (3, 1024, 256), (256, 64, 512)] {
            let l = Layout::new(workers, slots, cap).unwrap();
            assert!(l.status_off >= hdr::WORDS);
            assert!(l.producer_off >= l.status_off + crate::status::REGION_WORDS);
            assert!(l.slots_off >= l.producer_off + workers * crate::ring::PRODUCER_WORDS);
            assert!(l.consumer_off >= l.slots_off + workers * slots * l.slot_words);
            for off in [
                l.status_off,
                l.producer_off,
                l.producer_stride,
                l.slots_off,
                l.ring_stride,
            ] {
                assert_eq!(off % LINE_WORDS, 0, "{workers}/{slots}/{cap}");
            }
            assert_eq!(l.consumer_offset() % CONSUMER_ALIGN, 0);
            assert_eq!(l.file_len() % CONSUMER_ALIGN, 0);
            assert!(l.consumer_len() >= workers * LINE_WORDS * WORD);
            assert!(l.slot_words * WORD >= crate::ring::SLOT_FIXED_WORDS * WORD + cap);
        }
    }

    #[test]
    fn geometry_limits() {
        assert!(Layout::new(0, 4, 0).is_err());
        assert!(Layout::new(257, 4, 0).is_err());
        assert!(Layout::new(1, 3, 0).is_err(), "not a power of two");
        assert!(Layout::new(1, 1, 0).is_err());
        assert!(Layout::new(1, MAX_SLOTS * 2, 0).is_err());
        assert!(Layout::new(1, 4, HEADER_CAPACITY_MAX + 1).is_err());
        assert!(Layout::new(256, MAX_SLOTS, 512).is_err(), "over 1 GiB");
    }

    fn written(l: &Layout) -> Box<[AtomicU64]> {
        let f = words(l.file_words);
        l.write_header(&f, 0xfeed, 42, "pf-sampler 0.6.0 vpp 26.06-release-octeon9");
        f
    }

    #[test]
    fn header_round_trips_once_ready() {
        let l = Layout::new(2, 1024, 128).unwrap();
        let f = written(&l);
        assert_eq!(read_header(&f), Err(LayoutError::NotReady));
        mark_ready(&f);
        let h = read_header(&f).unwrap();
        assert_eq!(h.layout, l);
        assert_eq!((h.epoch, h.created_ns), (0xfeed, 42));
        assert_eq!(h.build, "pf-sampler 0.6.0 vpp 26.06-release-octeon9");
    }

    #[test]
    fn a_header_that_disagrees_with_itself_is_refused() {
        let l = Layout::new(2, 1024, 128).unwrap();
        let f = written(&l);
        mark_ready(&f);

        f[hdr::CONSUMER_OFF].store(64, Ordering::Relaxed);
        assert_eq!(
            read_header(&f),
            Err(LayoutError::Inconsistent("consumer_off"))
        );
        f[hdr::CONSUMER_OFF].store(l.consumer_off as u64, Ordering::Relaxed);

        f[hdr::WORKERS].store(3, Ordering::Relaxed);
        assert!(matches!(read_header(&f), Err(LayoutError::Inconsistent(_))));
        f[hdr::WORKERS].store(9999, Ordering::Relaxed);
        assert!(matches!(read_header(&f), Err(LayoutError::Geometry(_))));
        f[hdr::WORKERS].store(2, Ordering::Relaxed);

        f[hdr::VERSION].store(2, Ordering::Relaxed);
        assert_eq!(read_header(&f), Err(LayoutError::Version { found: 2 }));
        f[hdr::VERSION].store(VERSION, Ordering::Relaxed);

        f[hdr::MAGIC].store(0, Ordering::Relaxed);
        assert_eq!(read_header(&f), Err(LayoutError::BadMagic(0)));
        f[hdr::MAGIC].store(MAGIC, Ordering::Relaxed);

        assert!(read_header(&f).is_ok());
        assert!(matches!(
            read_header(&f[..l.file_words - 1]),
            Err(LayoutError::FileLen { .. })
        ));
        assert!(matches!(
            read_header(&f[..4]),
            Err(LayoutError::TooShort { .. })
        ));
    }

    #[test]
    fn text_truncates_and_sanitises() {
        let w = words(2);
        put_text(&w, "0123456789abcdefOVERFLOW");
        assert_eq!(get_text(&w), "0123456789abcdef");
        put_text(&w, "a\u{7}b");
        assert_eq!(get_text(&w), "a?b");
        put_text(&w, "");
        assert_eq!(get_text(&w), "");
    }
}
