//! A single-writer seqlock over a payload of atomic words.
//!
//! The payload is atomics, not plain memory, so a reader racing the writer
//! reads stale or mixed values — which the sequence check then rejects —
//! rather than causing a data race. Orderings follow Boehm, "Can Seqlocks
//! Get Along with Programming Language Memory Models?" (2012): the writer's
//! release fence after marking the sequence odd pairs with the reader's
//! acquire fence after loading the payload, so a reader that saw any new
//! payload word also sees the odd (or a later) sequence and retries.

use crate::sync::{fence, AtomicU64, Ordering};

/// Publishes `values` into `payload`. Single writer: concurrent writers
/// corrupt the sequence.
pub fn write(seq: &AtomicU64, payload: &[AtomicU64], values: &[u64]) {
    debug_assert_eq!(payload.len(), values.len());
    let s = seq.load(Ordering::Relaxed);
    seq.store(s.wrapping_add(1) | 1, Ordering::Relaxed);
    fence(Ordering::Release);
    for (w, &v) in payload.iter().zip(values) {
        w.store(v, Ordering::Relaxed);
    }
    seq.store((s.wrapping_add(1) | 1).wrapping_add(1), Ordering::Release);
}

/// Copies a consistent snapshot of `payload` into `out`, trying up to
/// `tries` times. `false` means no consistent snapshot was seen: the writer
/// was mid-write every time (or died there), or nothing was ever written.
pub fn read(seq: &AtomicU64, payload: &[AtomicU64], out: &mut [u64], tries: usize) -> bool {
    debug_assert_eq!(payload.len(), out.len());
    for _ in 0..tries {
        let s1 = seq.load(Ordering::Acquire);
        if s1 == 0 || s1 & 1 == 1 {
            std::hint::spin_loop();
            continue;
        }
        for (o, w) in out.iter_mut().zip(payload) {
            *o = w.load(Ordering::Relaxed);
        }
        fence(Ordering::Acquire);
        if seq.load(Ordering::Relaxed) == s1 {
            return true;
        }
    }
    false
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::layout::words;

    #[test]
    fn reads_what_was_written() {
        let seq = AtomicU64::new(0);
        let p = words(3);
        let mut out = [0; 3];
        assert!(!read(&seq, &p, &mut out, 4), "never written");
        write(&seq, &p, &[1, 2, 3]);
        assert!(read(&seq, &p, &mut out, 4));
        assert_eq!(out, [1, 2, 3]);
        write(&seq, &p, &[4, 5, 6]);
        assert!(read(&seq, &p, &mut out, 4));
        assert_eq!(out, [4, 5, 6]);
        assert_eq!(seq.load(Ordering::Relaxed) % 2, 0);
    }

    #[test]
    fn a_writer_stopped_mid_write_reads_as_unreadable() {
        let seq = AtomicU64::new(0);
        let p = words(2);
        write(&seq, &p, &[1, 1]);
        // As if the writer died between its odd store and its even one.
        seq.store(seq.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
        let mut out = [0; 2];
        assert!(!read(&seq, &p, &mut out, 16));
        // The next complete write recovers it.
        write(&seq, &p, &[2, 2]);
        assert!(read(&seq, &p, &mut out, 16));
        assert_eq!(out, [2, 2]);
    }

    #[test]
    fn concurrent_readers_never_see_a_mixed_snapshot() {
        use std::sync::Arc;
        let seq = Arc::new(AtomicU64::new(0));
        let p: Arc<[AtomicU64]> = words(8).into();
        write(&seq, &p, &[0; 8]);
        let writer = {
            let (seq, p) = (seq.clone(), p.clone());
            std::thread::spawn(move || {
                for k in 1..=20_000u64 {
                    write(&seq, &p, &[k; 8]);
                }
            })
        };
        let mut out = [0; 8];
        let mut seen = 0;
        while !writer.is_finished() {
            if read(&seq, &p, &mut out, 64) {
                assert!(out.iter().all(|&v| v == out[0]), "mixed: {out:?}");
                seen += 1;
            }
        }
        writer.join().unwrap();
        assert!(read(&seq, &p, &mut out, 64));
        assert_eq!(out, [20_000; 8]);
        assert!(seen > 0);
    }
}
