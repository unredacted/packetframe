//! Model checks of the two lock-free protocols, every interleaving loom can
//! reach under the C++11 memory model:
//!
//! ```sh
//! RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
//!   cargo test -p packetframe-sampler-shm --release --test loom
//! ```
//!
//! Regions are tiny (two slots, a few words) because loom tracks every
//! atomic; the code under test is the same code the epoch files use. The
//! consumer polls with `yield_now`, as the real one does: a consumer that
//! never yields lets loom's reduction skip every schedule in which the
//! producer gets ahead, and a relaxed `head` publish then passes unseen.
//!
//! Each ordering these protect was checked by weakening it: a relaxed
//! `head` store and load (torn sample), and either seqlock fence (torn
//! snapshot) all fail. One cannot be checked here: the producer's Acquire
//! load of `tail`. Weakened, it lets a slot be overwritten while still
//! being read only through load buffering, which loom does not model.
#![cfg(loom)]

use loom::sync::atomic::AtomicBool;
use loom::sync::Arc;
use loom::thread;
use packetframe_sampler_shm::layout::words;
use packetframe_sampler_shm::ring::{RingReader, RingWriter, SampleMeta, SLOT_FIXED_WORDS};
use packetframe_sampler_shm::seqlock;
use packetframe_sampler_shm::sync::{AtomicU64, Ordering};
use packetframe_sampler_shm::Class;

/// A reader racing a writer — including one caught between its odd and
/// even sequence stores — gets the old snapshot, the new one, or nothing;
/// never a mix.
#[test]
fn seqlock_never_yields_a_torn_snapshot() {
    struct Lock {
        seq: AtomicU64,
        payload: Box<[AtomicU64]>,
    }
    loom::model(|| {
        let l = Arc::new(Lock {
            seq: AtomicU64::new(0),
            payload: words(2),
        });
        seqlock::write(&l.seq, &l.payload, &[1, 1]);
        let writer = {
            let l = l.clone();
            thread::spawn(move || seqlock::write(&l.seq, &l.payload, &[2, 2]))
        };
        let mut out = [0; 2];
        if seqlock::read(&l.seq, &l.payload, &mut out, 2) {
            assert!(out == [1, 1] || out == [2, 2], "torn: {out:?}");
        }
        writer.join().unwrap();
        assert!(seqlock::read(&l.seq, &l.payload, &mut out, 1));
        assert_eq!(out, [2, 2]);
    });
}

const SLOT_WORDS: usize = SLOT_FIXED_WORDS + 1;
/// The producer region up to and including one interface's pool counters.
const PRODUCER_WORDS: usize = 16 + 3;

struct Ring {
    producer: Box<[AtomicU64]>,
    slots: Box<[AtomicU64]>,
    tail: AtomicU64,
}

fn meta(generation: u64) -> SampleMeta {
    SampleMeta {
        generation,
        time_ns: generation,
        sw_if_index: 1,
        class: Class::Ingress,
        pool_index: 0,
        rate: 10,
        frame_len: 64,
    }
}

/// A producer pushing three samples into a two-slot ring while the
/// consumer polls it, as PacketFrame's reader does: every delivered sample
/// is whole (its eight header bytes all equal its generation), delivered in
/// order with consecutive sequence numbers, and every sample is either
/// delivered or counted as dropped: none lost, none duplicated.
#[test]
fn ring_delivers_whole_samples_in_order_or_counts_the_drop() {
    loom::model(|| {
        let ring = Arc::new(Ring {
            producer: words(PRODUCER_WORDS),
            slots: words(2 * SLOT_WORDS),
            tail: AtomicU64::new(0),
        });
        let done = Arc::new(AtomicBool::new(false));
        let producer = {
            let (ring, done) = (ring.clone(), done.clone());
            thread::spawn(move || {
                let w =
                    RingWriter::from_parts(&ring.producer, &ring.slots, &ring.tail, SLOT_WORDS, 8);
                let pushed = (1..=3u64)
                    .filter(|&g| w.push(&meta(g), &[g as u8; 8]))
                    .count();
                done.store(true, Ordering::Release);
                pushed
            })
        };
        let r = RingReader::from_parts(&ring.producer, &ring.slots, &ring.tail, SLOT_WORDS, 8);
        let mut out = Vec::new();
        let mut corrupt = 0;
        loop {
            let finished = done.load(Ordering::Acquire);
            let d = r.drain(&mut out, usize::MAX);
            corrupt += d.corrupt + d.skipped;
            if finished {
                break;
            }
            thread::yield_now();
        }
        let pushed = producer.join().unwrap();

        assert_eq!(corrupt, 0);
        assert_eq!(out.len(), pushed, "delivered = pushed");
        let c = r.counters();
        assert_eq!(c.written as usize, pushed);
        assert_eq!(c.written + c.dropped_full, 3, "every push accounted");
        for (i, s) in out.iter().enumerate() {
            assert_eq!(s.seq, i as u64);
            assert_eq!(s.header, [s.meta.generation as u8; 8], "torn sample");
        }
        assert!(out
            .windows(2)
            .all(|p| p[0].meta.generation < p[1].meta.generation));
        assert_eq!(c.tail, c.head);
    });
}
