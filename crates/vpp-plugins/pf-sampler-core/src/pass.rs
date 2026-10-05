//! The sampling node's one pass over a frame: every buffer on to the next
//! feature, and counted into its receive interface's pool, each buffer's
//! metadata touched once.
//!
//! From VPP 26.06 every arc's feature strings share one heap, so an equal
//! config index is the same next feature: it is looked up once. A frame on
//! the sampler's arcs is one port's, so normally every buffer matches the
//! first, and the pass only checks and advances each; the frame then goes
//! on whole. Generic over the buffer so that every branch, the mixed frame
//! VPP's generator never makes included, is tested here.

use std::mem::MaybeUninit;

/// What the pass reads and writes of a buffer on a feature arc.
pub trait ArcBuffers<B> {
    /// The receive interface's `sw_if_index`.
    fn rx(&self, b: &B) -> u32;
    /// The buffer's position in its feature config string.
    fn config_index(&self, b: &B) -> u32;
    fn set_config_index(&self, b: &mut B, index: u32);
    /// The next feature's node, advancing `b`'s config index past this one.
    ///
    /// # Safety
    ///
    /// `b` is on a feature arc the calling node is part of.
    unsafe fn feature_next(&self, b: &mut B) -> u16;
}

/// Where a frame's buffers go.
#[derive(Debug, PartialEq, Eq)]
pub enum Next<'a> {
    /// Every buffer to this node.
    Single(u16),
    /// Each buffer to its own, in order.
    Each(&'a [u16]),
}

/// Moves every buffer of a non-empty frame on to its next feature, and
/// calls `add(sw_if_index, packets)` once per run of one receive interface.
///
/// # Safety
///
/// Every buffer is on a feature arc the calling node is part of.
#[inline(always)]
pub unsafe fn advance<'n, B, A: ArcBuffers<B>>(
    a: &A,
    b: &mut [B],
    nexts: &'n mut [MaybeUninit<u16>],
    mut add: impl FnMut(u32, usize),
) -> Next<'n> {
    let n = b.len();
    assert!(
        n > 0 && nexts.len() >= n,
        "a frame of {n} with {} nexts",
        nexts.len()
    );
    let c0 = a.config_index(&b[0]);
    let sw0 = a.rx(&b[0]);
    // SAFETY: the caller's.
    let next0 = unsafe { a.feature_next(&mut b[0]) };
    let advanced = a.config_index(&b[0]);
    let first_other = b[1..].iter_mut().position(|b0| {
        let same = a.config_index(b0) == c0 && a.rx(b0) == sw0;
        if same {
            a.set_config_index(b0, advanced);
        }
        !same
    });
    let Some(k) = first_other.map(|p| p + 1) else {
        add(sw0, n);
        return Next::Single(next0);
    };

    // From buffer `k` on, every buffer on its own.
    for x in &mut nexts[..k] {
        x.write(next0);
    }
    let mut single = true;
    let (mut run_start, mut run_sw) = (0, sw0);
    for (i, (b0, x)) in b.iter_mut().zip(nexts.iter_mut()).enumerate().skip(k) {
        let sw = a.rx(b0);
        if sw != run_sw {
            add(run_sw, i - run_start);
            (run_start, run_sw) = (i, sw);
        }
        if a.config_index(b0) == c0 {
            a.set_config_index(b0, advanced);
            x.write(next0);
        } else {
            // SAFETY: the caller's.
            let next = unsafe { a.feature_next(b0) };
            single &= next == next0;
            x.write(next);
        }
    }
    add(run_sw, n - run_start);
    if single {
        return Next::Single(next0);
    }
    // SAFETY: the first `n` were all written above, the first `k` before
    // the loop and the rest in it.
    Next::Each(unsafe { std::slice::from_raw_parts(nexts.as_ptr().cast::<u16>(), n) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::HashMap;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Buf {
        rx: u32,
        ci: u32,
    }

    /// Config strings: index -> (next node, the index after this node).
    struct Model {
        strings: HashMap<u32, (u16, u32)>,
        lookups: Cell<usize>,
    }

    impl ArcBuffers<Buf> for Model {
        fn rx(&self, b: &Buf) -> u32 {
            b.rx
        }
        fn config_index(&self, b: &Buf) -> u32 {
            b.ci
        }
        fn set_config_index(&self, b: &mut Buf, index: u32) {
            b.ci = index;
        }
        unsafe fn feature_next(&self, b: &mut Buf) -> u16 {
            self.lookups.set(self.lookups.get() + 1);
            let (next, after) = self.strings[&b.ci];
            b.ci = after;
            next
        }
    }

    fn model() -> Model {
        Model {
            // Config 10 goes to node 7 then index 11; config 20 to node 8,
            // then 21; config 30 also to node 7 (another arc), then 31.
            strings: HashMap::from([(10, (7, 11)), (20, (8, 21)), (30, (7, 31))]),
            lookups: Cell::new(0),
        }
    }

    /// What one pass did: config lookups, pool runs, where the frame went.
    struct Outcome {
        lookups: usize,
        runs: Vec<(u32, usize)>,
        /// `Ok` for one next node, else each buffer's.
        next: Result<u16, Vec<u16>>,
    }

    fn run(bufs: &mut [Buf]) -> Outcome {
        let m = model();
        let mut nexts = [MaybeUninit::uninit(); 256];
        let mut runs = Vec::new();
        // SAFETY: the model's buffers are all on its arcs.
        let next = unsafe { advance(&m, bufs, &mut nexts, |sw, k| runs.push((sw, k))) };
        let next = match next {
            Next::Single(x) => Ok(x),
            Next::Each(xs) => Err(xs.to_vec()),
        };
        Outcome {
            lookups: m.lookups.get(),
            runs,
            next,
        }
    }

    fn bufs(spec: &[(u32, u32)]) -> Vec<Buf> {
        spec.iter().map(|&(rx, ci)| Buf { rx, ci }).collect()
    }

    #[test]
    fn a_frame_from_one_port_is_one_lookup_and_one_next() {
        let mut b = bufs(&[(1, 10); 256]);
        let o = run(&mut b);
        assert_eq!(o.next, Ok(7));
        assert_eq!(o.runs, [(1, 256)]);
        assert_eq!(o.lookups, 1);
        assert!(b.iter().all(|b| b.ci == 11), "every buffer advanced");

        let mut one = bufs(&[(4, 20)]);
        let o = run(&mut one);
        assert_eq!((o.runs, o.next, one[0].ci), (vec![(4, 1)], Ok(8), 21));
    }

    #[test]
    fn interfaces_changing_mid_frame_count_each_run() {
        // Same config throughout: still one next, but three runs.
        let mut b = bufs(&[(1, 10), (1, 10), (1, 10), (2, 10), (2, 10), (1, 10)]);
        let o = run(&mut b);
        assert_eq!(o.next, Ok(7));
        assert_eq!(o.runs, [(1, 3), (2, 2), (1, 1)]);
        assert_eq!(o.lookups, 1);
        assert!(b.iter().all(|b| b.ci == 11));
        // The change at the second buffer, the first the fast path checks.
        let mut b = bufs(&[(1, 10), (2, 10), (2, 10)]);
        assert_eq!(run(&mut b).runs, [(1, 1), (2, 2)]);
    }

    #[test]
    fn a_mixed_config_sends_each_buffer_on_its_own() {
        let mut b = bufs(&[(1, 10), (1, 10), (1, 20), (1, 10), (3, 30)]);
        let o = run(&mut b);
        assert_eq!(o.next, Err(vec![7, 7, 8, 7, 7]));
        assert_eq!(o.runs, [(1, 4), (3, 1)]);
        // Looked up for the first buffer and for each one off its config.
        assert_eq!(o.lookups, 3);
        assert_eq!(
            b.iter().map(|b| b.ci).collect::<Vec<_>>(),
            [11, 11, 21, 11, 31]
        );

        // Another config, but the same next node: the frame still goes on
        // whole.
        let mut b = bufs(&[(1, 10), (1, 30), (1, 10)]);
        let o = run(&mut b);
        assert_eq!((o.next, o.lookups), (Ok(7), 2));
        assert_eq!(b.iter().map(|b| b.ci).collect::<Vec<_>>(), [11, 31, 11]);
    }

    #[test]
    #[should_panic(expected = "a frame of 0")]
    fn an_empty_frame_is_the_caller_s_bug() {
        let _ = run(&mut []);
    }
}
