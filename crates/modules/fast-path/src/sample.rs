//! The fast-path sampler's userspace contract (`bpf/src/sample.rs`): the
//! `SAMPLE_CFG` value flow-export writes, and the record each `SAMPLES`
//! perf event begins with.

/// Layout mirror of `SampleCfg` in `bpf/src/maps.rs`: build it with
/// [`SampleCfg::new`]. Rate 0 is off.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SampleCfg {
    /// `generation << 32 | rate`, one word so the program never reads a
    /// rate with another rate's generation.
    pub rate_generation: u64,
    pub header_bytes: u32,
    pub _pad: u32,
}

impl SampleCfg {
    pub fn new(rate: u32, header_bytes: u32, generation: u32) -> Self {
        Self {
            rate_generation: u64::from(generation) << 32 | u64::from(rate),
            header_bytes,
            _pad: 0,
        }
    }
}

const _: () = assert!(std::mem::size_of::<SampleCfg>() == 16);

// SAFETY: repr(C), a u64 and two u32s, every bit pattern valid.
#[cfg(target_os = "linux")]
unsafe impl aya::Pod for SampleCfg {}

/// Bytes of `SampleRecord` (bpf/src/maps.rs) ahead of the packet bytes.
pub const RECORD_LEN: usize = 40;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Path {
    Xdp,
    Tc,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Disposition {
    /// Handed to the kernel.
    Pass,
    Drop,
    /// A redirect was decided toward `egress_ifindex`; whether it
    /// completed is not claimed.
    Redirect,
}

/// An offloaded 802.1Q/ad tag (tc), not present in `header`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Vlan {
    pub proto: u16,
    pub tci: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample<'a> {
    /// `CLOCK_MONOTONIC` (`bpf_ktime_get_ns`).
    pub ktime_ns: u64,
    /// The generation and rate the sample was selected at.
    pub generation: u32,
    pub rate: u32,
    pub ingress_ifindex: u32,
    /// 0 unless `disposition` is `Redirect`.
    pub egress_ifindex: u32,
    /// The packet's length as the program saw it: without `vlan`.
    pub frame_len: u32,
    pub path: Path,
    pub disposition: Disposition,
    pub vlan: Option<Vlan>,
    /// The frame's first `min(frame_len, header_bytes)` bytes.
    pub header: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Short(usize),
    Path(u32),
    Disposition(u32),
    /// The record claims more packet bytes than the event carries.
    Captured {
        captured: u32,
        available: usize,
    },
}

/// Decode one `SAMPLES` event. The perf ring pads each event to 8 bytes,
/// so the bytes past `captured` are not the packet's.
pub fn parse(event: &[u8]) -> Result<Sample<'_>, ParseError> {
    if event.len() < RECORD_LEN {
        return Err(ParseError::Short(event.len()));
    }
    let u32_at = |o: usize| u32::from_ne_bytes(event[o..o + 4].try_into().unwrap());
    let captured = u32_at(28);
    let meta = u32_at(32);
    let vlan = u32_at(36);
    let path = match meta & 0xff {
        1 => Path::Xdp,
        2 => Path::Tc,
        p => return Err(ParseError::Path(p)),
    };
    let disposition = match (meta >> 8) & 0xff {
        0 => Disposition::Pass,
        1 => Disposition::Drop,
        2 => Disposition::Redirect,
        d => return Err(ParseError::Disposition(d)),
    };
    let available = event.len() - RECORD_LEN;
    if captured as usize > available {
        return Err(ParseError::Captured {
            captured,
            available,
        });
    }
    Ok(Sample {
        ktime_ns: u64::from_ne_bytes(event[0..8].try_into().unwrap()),
        generation: u32_at(8),
        rate: u32_at(12),
        ingress_ifindex: u32_at(16),
        egress_ifindex: u32_at(20),
        frame_len: u32_at(24),
        path,
        disposition,
        vlan: (meta >> 16 & 1 == 1).then_some(Vlan {
            proto: (vlan >> 16) as u16,
            tci: vlan as u16,
        }),
        header: &event[RECORD_LEN..RECORD_LEN + captured as usize],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(fields: [u32; 8], ktime: u64, bytes: &[u8]) -> Vec<u8> {
        let mut e = ktime.to_ne_bytes().to_vec();
        for f in fields {
            e.extend_from_slice(&f.to_ne_bytes());
        }
        e.extend_from_slice(bytes);
        e
    }

    #[test]
    fn a_tc_redirect_with_an_offloaded_tag() {
        let mut e = event(
            [
                7,
                1000,
                3,
                9,
                1514,
                4,
                2 | 2 << 8 | 1 << 16,
                0x8100 << 16 | 0x2064,
            ],
            42,
            &[1, 2, 3, 4],
        );
        e.extend_from_slice(&[0; 4]); // the ring's padding
        let s = parse(&e).unwrap();
        assert_eq!(
            s,
            Sample {
                ktime_ns: 42,
                generation: 7,
                rate: 1000,
                ingress_ifindex: 3,
                egress_ifindex: 9,
                frame_len: 1514,
                path: Path::Tc,
                disposition: Disposition::Redirect,
                vlan: Some(Vlan {
                    proto: 0x8100,
                    tci: 0x2064
                }),
                header: &[1, 2, 3, 4],
            }
        );
    }

    #[test]
    fn an_xdp_pass_carries_no_tag() {
        let e = event([1, 1, 1, 0, 60, 0, 1, 0], 0, &[]);
        let s = parse(&e).unwrap();
        assert_eq!(
            (s.path, s.disposition, s.vlan),
            (Path::Xdp, Disposition::Pass, None)
        );
        assert!(s.header.is_empty());
    }

    #[test]
    fn malformed_events_are_refused() {
        assert_eq!(parse(&[0; 39]), Err(ParseError::Short(39)));
        assert_eq!(
            parse(&event([0, 0, 0, 0, 0, 0, 3, 0], 0, &[])),
            Err(ParseError::Path(3))
        );
        assert_eq!(
            parse(&event([0, 0, 0, 0, 0, 0, 1 | 3 << 8, 0], 0, &[])),
            Err(ParseError::Disposition(3))
        );
        assert_eq!(
            parse(&event([0, 0, 0, 0, 64, 9, 1, 0], 0, &[0; 8])),
            Err(ParseError::Captured {
                captured: 9,
                available: 8
            })
        );
    }
}
