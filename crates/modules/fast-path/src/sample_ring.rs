//! The reader side of `SAMPLES` (and the kernel sampler's `KSAMPLES`):
//! one BPF ring buffer every CPU reserves in, drained on the worker's
//! timer. The programs submit with `BPF_RB_NO_WAKEUP`, so a sample costs
//! no wakeup: a perf ring's wakeup per event measured +8% on the forward
//! path at 1:1000. A ring buffer rather than perf rings because
//! `bpf_perf_event_output` needs CONFIG_BPF_EVENTS, which UniFi's kernel
//! lacks: there every output failed.

#[cfg(target_os = "linux")]
pub use linux::SampleRing;

#[cfg(target_os = "linux")]
mod linux {
    use aya::maps::{Map, MapData, RingBuf};

    /// The smallest space an entry takes in the ring: its 8-byte header
    /// and a `SampleEvent`.
    const ENTRY_BYTES: u32 = 8 + 296;

    /// A sample ring and its one reader.
    pub struct SampleRing {
        ring: RingBuf<MapData>,
        /// The most entries the ring holds: one drain's bound, so programs
        /// that keep submitting cannot keep a drain going.
        cap: usize,
    }

    impl SampleRing {
        pub fn new(map: MapData) -> Result<Self, String> {
            let bytes = map.info().map_err(|e| e.to_string())?.max_entries();
            let ring = RingBuf::try_from(Map::RingBuf(map)).map_err(|e| e.to_string())?;
            Ok(Self {
                ring,
                cap: (bytes / ENTRY_BYTES).max(1) as usize,
            })
        }

        /// Hand each entry submitted since the last drain to `f`, up to
        /// what the ring holds, and return how many.
        pub fn drain(&mut self, f: &mut dyn FnMut(&[u8])) -> usize {
            let mut n = 0;
            while n < self.cap {
                let Some(e) = self.ring.next() else { break };
                f(&e);
                n += 1;
            }
            n
        }
    }
}
