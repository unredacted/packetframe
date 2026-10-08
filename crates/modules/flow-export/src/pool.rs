//! sFlow sample pools: the packets a data source could have sampled,
//! counted whether or not any sample was delivered.
//!
//! For a fast-path port that is the kernel's `rx_packets`: steered
//! ingress goes to VPP's VF before the PF's netdev counts it, so the
//! counter holds exactly the packets the XDP or tc program was eligible
//! to see (docs/runbooks/vpp-offload.md). A source's counter can go back
//! to zero (a device recreated); the accumulator only ever moves forward,
//! so neither a pool nor a sample sequence a collector reads goes back.

/// Deltas of a source counter, accumulated from the first reading.
#[derive(Debug, Default, Clone)]
pub struct Accumulator {
    last: Option<u64>,
    total: u64,
}

impl Accumulator {
    /// Fold in a fresh reading and return the total. A reading below the
    /// last is a counter that restarted from zero: all of it is new.
    pub fn observe(&mut self, counter: u64) -> u64 {
        let delta = match self.last {
            None => 0,
            Some(last) if counter >= last => counter - last,
            Some(_) => counter,
        };
        self.last = Some(counter);
        self.total = self.total.wrapping_add(delta);
        self.total
    }

    pub fn total(&self) -> u64 {
        self.total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_from_the_first_reading_and_never_goes_back() {
        let mut a = Accumulator::default();
        assert_eq!(a.observe(1_000_000), 0, "the first reading is the baseline");
        assert_eq!(a.observe(1_000_500), 500);
        // The device was recreated: its counter restarted.
        assert_eq!(a.observe(20), 520);
        assert_eq!(a.observe(30), 530);
        assert_eq!(a.total(), 530);
    }
}
