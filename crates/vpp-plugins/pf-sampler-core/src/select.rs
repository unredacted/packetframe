//! 1-in-N packet selection.
//!
//! The gap to the next selected packet is drawn uniformly from [1, 2N-1]
//! (mean N, as sFlow agents draw it), and consumed a frame at a time: a
//! frame holding no selected packet costs one comparison and one
//! subtraction, which is what keeps the sampler's per-packet cost at the
//! floor of an empty feature node.

/// One VPP thread's selection state. Never shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selector {
    rate: u32,
    /// Packets still to pass before the next selected one.
    skip: u64,
    rng: u64,
}

impl Default for Selector {
    fn default() -> Self {
        Self::new()
    }
}

impl Selector {
    /// A selector that selects nothing until [`Self::set_rate`].
    pub const fn new() -> Self {
        Self {
            rate: 0,
            skip: 0,
            rng: 1,
        }
    }

    /// Starts selecting 1 in `rate` (0: none), with a fresh gap. `seed`
    /// only needs to differ between threads.
    pub fn set_rate(&mut self, rate: u32, seed: u64) {
        self.rate = rate;
        self.rng = seed | 1;
        if rate > 0 {
            self.skip = self.draw() - 1;
        }
    }

    pub fn rate(&self) -> u32 {
        self.rate
    }

    fn draw(&mut self) -> u64 {
        // xorshift64*: never zero once seeded odd.
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        let r = x.wrapping_mul(0x2545_f491_4f6c_dd1d);
        1 + r % (2 * u64::from(self.rate) - 1)
    }

    /// Calls `f` with the position of each packet selected among the next
    /// `n`, in order.
    #[inline(always)]
    pub fn frame(&mut self, n: usize, mut f: impl FnMut(usize)) {
        let n = n as u64;
        if self.rate == 0 {
            return;
        }
        if self.skip >= n {
            self.skip -= n;
            return;
        }
        let mut at = self.skip;
        loop {
            f(at as usize);
            at += self.draw();
            if at >= n {
                self.skip = at - n;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same draws applied one packet at a time: the definition the
    /// frame-at-a-time version must reproduce exactly.
    fn per_packet(mut s: Selector, total: u64) -> Vec<u64> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < total {
            s.frame(1, |_| out.push(pos));
            pos += 1;
        }
        out
    }

    #[test]
    fn frames_of_any_size_select_the_same_packets() {
        let mut s = Selector::new();
        s.set_rate(7, 42);
        let reference = per_packet(s, 10_000);
        let mut got = Vec::new();
        let mut base = 0u64;
        let mut sizes = [1usize, 256, 3, 0, 64, 255, 17].iter().cycle();
        while base < 10_000 {
            let n = (*sizes.next().unwrap()).min((10_000 - base) as usize);
            s.frame(n, |i| got.push(base + i as u64));
            base += n as u64;
        }
        assert_eq!(got, reference);
    }

    #[test]
    fn the_rate_is_the_mean() {
        for rate in [1u32, 2, 100, 1000] {
            let mut s = Selector::new();
            s.set_rate(rate, 0xdead_beef);
            let mut n = 0u64;
            let total = 2_000_000u64;
            for _ in 0..total / 250 {
                s.frame(250, |_| n += 1);
            }
            let expected = total as f64 / f64::from(rate);
            // Five standard deviations of a uniform-gap renewal count.
            let tolerance = 5.0 * (expected.max(1.0)).sqrt() + 1.0;
            assert!(
                (n as f64 - expected).abs() <= tolerance,
                "rate {rate}: {n} selected, expected {expected}"
            );
        }
    }

    #[test]
    fn rate_one_selects_everything_and_rate_zero_nothing() {
        let mut s = Selector::new();
        let mut v = Vec::new();
        s.frame(10, |i| v.push(i));
        assert!(v.is_empty(), "nothing before set_rate");
        s.set_rate(1, 3);
        s.frame(5, |i| v.push(i));
        assert_eq!(v, [0, 1, 2, 3, 4]);
        s.set_rate(0, 3);
        s.frame(1000, |i| v.push(i));
        assert_eq!(v.len(), 5);
    }

    #[test]
    fn gaps_stay_within_twice_the_rate() {
        let mut s = Selector::new();
        s.set_rate(10, 9);
        let mut last = None;
        let mut base = 0usize;
        for _ in 0..1000 {
            s.frame(256, |i| {
                let at = base + i;
                if let Some(prev) = last {
                    let gap = at - prev;
                    assert!((1..=19).contains(&gap), "gap {gap}");
                }
                last = Some(at);
            });
            base += 256;
        }
    }
}
