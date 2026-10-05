//! One single-producer, single-consumer ring per VPP worker.
//!
//! Drop-on-full, with the ordering of the kernel's circular-buffer guide:
//!
//! - **Producer** (a VPP worker): load `tail` (Acquire); if the ring is
//!   full count `dropped_full` and return; otherwise write the whole slot,
//!   then store `head + 1` (Release).
//! - **Consumer** (PacketFrame): load `head` (Acquire); copy the slots out
//!   and validate them; store the new `tail` (Release).
//!
//! A slot is rewritten only after the consumer has published a `tail` past
//! it, and both counters only ever grow (`u64`, so they never wrap in
//! practice). Every sample records the configuration generation it was
//! taken under, so queued samples stay interpretable across changes.
//!
//! The producer's counters live beside its `head`, written by that worker
//! alone; the sample pool is counted per configured interface (by the pool
//! index the status names it with) and class.

use crate::layout::{Layout, CLASSES, LINE_WORDS, MAX_INTERFACES, WORD};
use crate::sync::{AtomicU64, Ordering};
use crate::Class;

/// Producer-region words.
mod p {
    pub const HEAD: usize = 0;
    pub const SELECTED: usize = 1;
    pub const WRITTEN: usize = 2;
    pub const DROPPED_FULL: usize = 3;
    pub const POOL: usize = super::LINE_WORDS;
}
pub const PRODUCER_WORDS: usize = p::POOL + MAX_INTERFACES * CLASSES;

/// Slot words.
mod s {
    pub const SEQ: usize = 0;
    pub const GENERATION: usize = 1;
    pub const TIME_NS: usize = 2;
    /// `sw_if_index | class << 32 | pool_index << 40`.
    pub const IDS: usize = 3;
    /// `header_len | frame_len << 32`.
    pub const LENS: usize = 4;
    pub const RATE: usize = 5;
    pub const DATA: usize = 6;
}
pub const SLOT_FIXED_WORDS: usize = s::DATA;

/// What the producer knows about a sampled packet, besides its bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SampleMeta {
    /// The configuration generation the packet was selected under.
    pub generation: u64,
    /// Realtime nanoseconds of the selection.
    pub time_ns: u64,
    pub sw_if_index: u32,
    pub class: Class,
    /// The configured interface's pool index (see the status).
    pub pool_index: u8,
    /// The 1-in-N rate the packet was selected at.
    pub rate: u32,
    /// The packet's length, before any truncation to the header capacity.
    pub frame_len: u32,
}

/// A sample as the consumer copied it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    /// Its position in the ring's stream: consecutive per ring per epoch.
    pub seq: u64,
    pub meta: SampleMeta,
    /// The leading bytes of the packet, at most the header capacity.
    pub header: Vec<u8>,
}

/// What one [`RingReader::drain`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Drained {
    /// Samples copied out.
    pub taken: usize,
    /// Slots that failed validation (a producer bug): consumed, not copied.
    pub corrupt: u64,
    /// Samples skipped because `head` was implausibly far ahead of `tail`
    /// (more than the ring holds): the consumer resynchronised at `head`.
    pub skipped: u64,
}

/// A ring's counters, as the consumer reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Counters {
    pub head: u64,
    pub tail: u64,
    pub selected: u64,
    pub written: u64,
    pub dropped_full: u64,
    /// Packets seen, by pool index then class.
    pub pool: Vec<[u64; CLASSES]>,
}

/// Single-writer increment: only the owning worker stores these words, so
/// a load and a store are enough (and cheaper than a read-modify-write).
fn bump(w: &AtomicU64, n: u64) {
    w.store(w.load(Ordering::Relaxed).wrapping_add(n), Ordering::Relaxed);
}

/// A worker's end of its ring.
pub struct RingWriter<'a> {
    producer: &'a [AtomicU64],
    slots: &'a [AtomicU64],
    tail: &'a AtomicU64,
    slot_words: usize,
    capacity: usize,
    mask: u64,
}

impl<'a> RingWriter<'a> {
    /// Ring `ring` of a whole mapped epoch file.
    pub fn new(layout: &Layout, file: &'a [AtomicU64], ring: usize) -> Self {
        Self::from_parts(
            layout.producer(file, ring),
            layout.slots(file, ring),
            layout.tail(&file[layout.consumer_off..], ring),
            layout.slot_words,
            layout.header_capacity,
        )
    }

    /// A ring over bare regions: `slots` holds a power-of-two number of
    /// `slot_words`-word slots, each carrying at most `header_capacity`
    /// packet bytes — the epoch's declared capacity, not the word-rounded
    /// room a slot has for them. `producer` is [`PRODUCER_WORDS`] long in
    /// an epoch file, shorter (fewer pool entries) in a model.
    pub fn from_parts(
        producer: &'a [AtomicU64],
        slots: &'a [AtomicU64],
        tail: &'a AtomicU64,
        slot_words: usize,
        header_capacity: usize,
    ) -> Self {
        assert!(producer.len() >= p::POOL && producer.len() <= PRODUCER_WORDS);
        assert!(slot_words >= SLOT_FIXED_WORDS);
        assert!(header_capacity <= (slot_words - SLOT_FIXED_WORDS) * WORD);
        let n = slots.len() / slot_words;
        assert!(n.is_power_of_two() && n * slot_words == slots.len());
        Self {
            producer,
            slots,
            tail,
            slot_words,
            capacity: header_capacity,
            mask: n as u64 - 1,
        }
    }

    /// Counts `n` packets seen on the interface with `pool_index`.
    pub fn add_pool(&self, pool_index: usize, class: Class, n: u64) {
        bump(
            &self.producer[p::POOL + pool_index * CLASSES + class.index()],
            n,
        );
    }

    pub fn add_selected(&self, n: u64) {
        bump(&self.producer[p::SELECTED], n);
    }

    /// Queues a sample: `header` truncated to the slot's capacity. `false`
    /// when the ring is full; the sample is dropped and counted.
    pub fn push(&self, m: &SampleMeta, header: &[u8]) -> bool {
        let head = self.producer[p::HEAD].load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head.wrapping_sub(tail) > self.mask {
            bump(&self.producer[p::DROPPED_FULL], 1);
            return false;
        }
        let at = (head & self.mask) as usize * self.slot_words;
        let slot = &self.slots[at..at + self.slot_words];
        let len = header.len().min(self.capacity);
        let set = |i: usize, v: u64| slot[i].store(v, Ordering::Relaxed);
        set(s::SEQ, head);
        set(s::GENERATION, m.generation);
        set(s::TIME_NS, m.time_ns);
        set(
            s::IDS,
            u64::from(m.sw_if_index)
                | (m.class.index() as u64) << 32
                | u64::from(m.pool_index) << 40,
        );
        set(s::LENS, len as u64 | u64::from(m.frame_len) << 32);
        set(s::RATE, u64::from(m.rate));
        for (i, chunk) in header[..len].chunks(WORD).enumerate() {
            let mut b = [0u8; WORD];
            b[..chunk.len()].copy_from_slice(chunk);
            set(s::DATA + i, u64::from_ne_bytes(b));
        }
        self.producer[p::HEAD].store(head.wrapping_add(1), Ordering::Release);
        bump(&self.producer[p::WRITTEN], 1);
        true
    }
}

/// The consumer's end of a ring.
pub struct RingReader<'a> {
    producer: &'a [AtomicU64],
    slots: &'a [AtomicU64],
    tail: &'a AtomicU64,
    slot_words: usize,
    capacity: usize,
    mask: u64,
}

impl<'a> RingReader<'a> {
    /// Ring `ring`: `file` is the whole epoch file (mapped read-only is
    /// enough), `consumer` the consumer region (mapped writable).
    pub fn new(
        layout: &Layout,
        file: &'a [AtomicU64],
        consumer: &'a [AtomicU64],
        ring: usize,
    ) -> Self {
        Self::from_parts(
            layout.producer(file, ring),
            layout.slots(file, ring),
            layout.tail(consumer, ring),
            layout.slot_words,
            layout.header_capacity,
        )
    }

    pub fn from_parts(
        producer: &'a [AtomicU64],
        slots: &'a [AtomicU64],
        tail: &'a AtomicU64,
        slot_words: usize,
        header_capacity: usize,
    ) -> Self {
        let w = RingWriter::from_parts(producer, slots, tail, slot_words, header_capacity);
        Self {
            producer,
            slots,
            tail,
            slot_words,
            capacity: w.capacity,
            mask: w.mask,
        }
    }

    /// Copies up to `max` queued samples onto `out`, then releases their
    /// slots to the producer.
    pub fn drain(&self, out: &mut Vec<Sample>, max: usize) -> Drained {
        let head = self.producer[p::HEAD].load(Ordering::Acquire);
        let tail = self.tail.load(Ordering::Relaxed);
        let queued = head.wrapping_sub(tail);
        let mut d = Drained::default();
        if queued > self.mask + 1 {
            // A sane producer is never more than a ring ahead; skip to its
            // head rather than read slots it has already reused.
            d.skipped = queued;
            self.tail.store(head, Ordering::Release);
            return d;
        }
        let n = queued.min(max as u64);
        for seq in tail..tail + n {
            match self.read_slot(seq) {
                Some(sample) => {
                    out.push(sample);
                    d.taken += 1;
                }
                None => d.corrupt += 1,
            }
        }
        self.tail.store(tail + n, Ordering::Release);
        d
    }

    fn read_slot(&self, seq: u64) -> Option<Sample> {
        let at = (seq & self.mask) as usize * self.slot_words;
        let slot = &self.slots[at..at + self.slot_words];
        let get = |i: usize| slot[i].load(Ordering::Relaxed);
        if get(s::SEQ) != seq {
            return None;
        }
        let ids = get(s::IDS);
        let lens = get(s::LENS);
        let len = (lens & 0xffff_ffff) as usize;
        let class = Class::from_index((ids >> 32) & 0xff)?;
        let pool_index = (ids >> 40) as u8;
        let rate = u32::try_from(get(s::RATE)).ok()?;
        if len > self.capacity || usize::from(pool_index) >= MAX_INTERFACES || ids >> 48 != 0 {
            return None;
        }
        let mut header = Vec::with_capacity(len);
        for i in 0..len.div_ceil(WORD) {
            header.extend_from_slice(&get(s::DATA + i).to_ne_bytes());
        }
        header.truncate(len);
        Some(Sample {
            seq,
            meta: SampleMeta {
                generation: get(s::GENERATION),
                time_ns: get(s::TIME_NS),
                sw_if_index: ids as u32,
                class,
                pool_index,
                rate,
                frame_len: (lens >> 32) as u32,
            },
            header,
        })
    }

    /// The ring's counters. An observer without the consumer region
    /// mapped writable uses [`counters`] instead.
    pub fn counters(&self) -> Counters {
        counters_of(self.producer, self.tail)
    }
}

/// Ring `ring`'s counters from a read-only mapping of the whole file: what
/// a one-shot observer reads, never draining.
pub fn counters(layout: &Layout, file: &[AtomicU64], ring: usize) -> Counters {
    counters_of(
        layout.producer(file, ring),
        layout.tail(&file[layout.consumer_off..], ring),
    )
}

fn counters_of(producer: &[AtomicU64], tail: &AtomicU64) -> Counters {
    let get = |i: usize| producer[i].load(Ordering::Relaxed);
    Counters {
        head: get(p::HEAD),
        tail: tail.load(Ordering::Relaxed),
        selected: get(p::SELECTED),
        written: get(p::WRITTEN),
        dropped_full: get(p::DROPPED_FULL),
        pool: (0..(producer.len() - p::POOL) / CLASSES)
            .map(|i| std::array::from_fn(|c| get(p::POOL + i * CLASSES + c)))
            .collect(),
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::layout::{mark_ready, read_header, words};

    fn meta(generation: u64) -> SampleMeta {
        SampleMeta {
            generation,
            time_ns: 1_790_000_000_000_000_000 + generation,
            sw_if_index: 3,
            class: Class::Ingress,
            pool_index: 1,
            rate: 1000,
            frame_len: 1514,
        }
    }

    /// A 4-slot ring with 16 bytes of header capacity, over bare words.
    struct Bare {
        producer: Box<[AtomicU64]>,
        slots: Box<[AtomicU64]>,
        tail: AtomicU64,
    }

    const SLOT_WORDS: usize = SLOT_FIXED_WORDS + 2;

    impl Bare {
        fn new() -> Self {
            Self {
                producer: words(PRODUCER_WORDS),
                slots: words(4 * SLOT_WORDS),
                tail: AtomicU64::new(0),
            }
        }
        fn writer(&self) -> RingWriter<'_> {
            RingWriter::from_parts(&self.producer, &self.slots, &self.tail, SLOT_WORDS, 16)
        }
        fn reader(&self) -> RingReader<'_> {
            RingReader::from_parts(&self.producer, &self.slots, &self.tail, SLOT_WORDS, 16)
        }
    }

    #[test]
    fn samples_round_trip_in_order_across_wraps() {
        let b = Bare::new();
        let (w, r) = (b.writer(), b.reader());
        let mut out = Vec::new();
        for round in 0..5u64 {
            for k in 0..3 {
                let hdr: Vec<u8> = (0..(5 + k) as u8).collect();
                assert!(w.push(&meta(round * 3 + k), &hdr));
            }
            assert_eq!(r.drain(&mut out, usize::MAX).taken, 3);
        }
        assert_eq!(out.len(), 15);
        for (i, s) in out.iter().enumerate() {
            assert_eq!(s.seq, i as u64);
            assert_eq!(s.meta, meta(i as u64));
            assert_eq!(s.header, (0..(5 + i % 3) as u8).collect::<Vec<_>>());
        }
        let c = r.counters();
        assert_eq!((c.head, c.tail, c.written, c.dropped_full), (15, 15, 15, 0));
    }

    #[test]
    fn a_full_ring_drops_and_counts_then_recovers() {
        let b = Bare::new();
        let (w, r) = (b.writer(), b.reader());
        for k in 0..4 {
            assert!(w.push(&meta(k), b"x"));
        }
        assert!(!w.push(&meta(4), b"x"), "full");
        assert!(!w.push(&meta(5), b"x"));
        let mut out = Vec::new();
        assert_eq!(r.drain(&mut out, 2).taken, 2);
        assert!(w.push(&meta(6), b"x"));
        assert_eq!(r.drain(&mut out, usize::MAX).taken, 3);
        let gens: Vec<u64> = out.iter().map(|s| s.meta.generation).collect();
        assert_eq!(gens, [0, 1, 2, 3, 6]);
        let seqs: Vec<u64> = out.iter().map(|s| s.seq).collect();
        assert_eq!(seqs, [0, 1, 2, 3, 4], "drops leave no gap in seq");
        assert_eq!(r.counters().dropped_full, 2);
    }

    #[test]
    fn headers_are_truncated_to_capacity_and_pool_counts_per_interface() {
        let b = Bare::new();
        let (w, r) = (b.writer(), b.reader());
        let long: Vec<u8> = (0..100).collect();
        assert!(w.push(&meta(0), &long));
        assert!(w.push(&meta(1), &[]));
        w.add_pool(1, Class::Ingress, 1000);
        w.add_pool(1, Class::Ingress, 24);
        w.add_pool(63, Class::Drop, 7);
        w.add_selected(2);
        let mut out = Vec::new();
        r.drain(&mut out, usize::MAX);
        assert_eq!(out[0].header, long[..16]);
        assert_eq!(out[0].meta.frame_len, 1514, "original length kept");
        assert!(out[1].header.is_empty());
        let c = r.counters();
        assert_eq!(c.pool[1], [1024, 0, 0]);
        assert_eq!(c.pool[63], [0, 0, 7]);
        assert_eq!(c.selected, 2);
    }

    #[test]
    fn corrupt_slots_and_a_runaway_head_are_contained() {
        let b = Bare::new();
        let (w, r) = (b.writer(), b.reader());
        assert!(w.push(&meta(0), b"ok"));
        assert!(w.push(&meta(1), b"ok"));
        b.slots[SLOT_WORDS + s::SEQ].store(77, Ordering::Relaxed); // slot 1's seq
        let mut out = Vec::new();
        let d = r.drain(&mut out, usize::MAX);
        assert_eq!((d.taken, d.corrupt), (1, 1));

        assert!(w.push(&meta(2), b"ok"));
        b.slots[2 * SLOT_WORDS + s::LENS].store(17, Ordering::Relaxed); // > 16
        assert_eq!(r.drain(&mut out, usize::MAX).corrupt, 1);

        b.producer[p::HEAD].store(1000, Ordering::Relaxed);
        let d = r.drain(&mut out, usize::MAX);
        assert_eq!((d.taken, d.skipped), (0, 997));
        assert_eq!(r.counters().tail, 1000);
        assert!(w.push(&meta(3), b"ok"), "producing resumes past the skip");
    }

    #[test]
    fn a_replacement_consumer_resumes_at_the_published_tail() {
        let b = Bare::new();
        let w = b.writer();
        for k in 0..3 {
            assert!(w.push(&meta(k), b"x"));
        }
        let mut out = Vec::new();
        b.reader().drain(&mut out, 1);
        let mut rest = Vec::new();
        b.reader().drain(&mut rest, usize::MAX);
        assert_eq!(rest.iter().map(|s| s.seq).collect::<Vec<_>>(), [1, 2]);
    }

    /// A capacity that is not a whole number of words is still the
    /// capacity: the slot's rounding-up room is never used, and a slot
    /// claiming more than the epoch declares is refused.
    #[test]
    fn the_declared_header_capacity_is_exact() {
        let l = Layout::new(1, 4, 1).unwrap();
        assert_eq!(l.slot_words, SLOT_FIXED_WORDS + 1);
        let f = words(l.file_words);
        let consumer = &f[l.consumer_off..];
        let w = RingWriter::new(&l, &f, 0);
        assert!(w.push(&meta(0), &[9; 8]));
        let r = RingReader::new(&l, &f, consumer, 0);
        let mut out = Vec::new();
        r.drain(&mut out, usize::MAX);
        assert_eq!(out[0].header, [9]);

        assert!(w.push(&meta(1), &[9; 8]));
        let at = l.slots_off + l.slot_words + s::LENS;
        f[at].store(8, Ordering::Relaxed); // the slot claims 8 bytes
        assert_eq!(r.drain(&mut out, usize::MAX).corrupt, 1);
    }

    #[test]
    fn rings_in_a_real_layout_are_independent() {
        let l = Layout::new(2, 8, 64).unwrap();
        let f = words(l.file_words);
        l.write_header(&f, 1, 2, "test");
        mark_ready(&f);
        let h = read_header(&f).unwrap();
        let consumer = &f[h.layout.consumer_off..];
        let (w0, w1) = (RingWriter::new(&l, &f, 0), RingWriter::new(&l, &f, 1));
        assert!(w0.push(&meta(10), &[0xaa; 64]));
        assert!(w1.push(&meta(20), &[0xbb; 64]));
        assert!(w1.push(&meta(21), &[0xbb; 70]));
        let mut out = Vec::new();
        RingReader::new(&l, &f, consumer, 0).drain(&mut out, usize::MAX);
        RingReader::new(&l, &f, consumer, 1).drain(&mut out, usize::MAX);
        let got: Vec<(u64, u64, usize)> = out
            .iter()
            .map(|s| (s.seq, s.meta.generation, s.header.len()))
            .collect();
        assert_eq!(got, [(0, 10, 64), (0, 20, 64), (1, 21, 64)]);
        assert!(out[0].header.iter().all(|&b| b == 0xaa));
    }
}
