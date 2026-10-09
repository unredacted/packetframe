//! fast-path samples as sFlow v5 (docs/flow-export/collectors.md has what
//! each collector requires of these fields).

use std::net::IpAddr;

use packetframe_fast_path::sample::Sample;
use packetframe_flow_encode::sflow::{self, Agent, Encoding, FlowSample, COMPACT_IF_LIMIT};
use packetframe_flow_encode::EncodeError;

/// Datagram size: inside a 1500-byte path with room for the IP and UDP
/// headers, so no collector ever sees a fragment.
pub const MAX_DATAGRAM: usize = 1400;

/// Octets a frame's FCS adds on the wire: sFlow's `frame_length` counts
/// them and `stripped` says they are not in the header.
pub const FCS: u32 = 4;

/// A sample ready to encode: everything sFlow says about it, with the
/// header as the wire carried it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    pub sequence: u32,
    pub source_if: u32,
    pub rate: u32,
    pub pool: u32,
    pub drops: u32,
    pub output_if: u32,
    pub frame_length: u32,
    /// Octets `frame_length` counts that `header` does not start with:
    /// an Ethernet frame's FCS, or none for one framed by [`ip_frame`].
    pub stripped: u32,
    pub header: Vec<u8>,
    /// For the IPFIX flow cache, which sFlow has no field for: the path
    /// the sample came by, and the sampler generation it was drawn under.
    pub path: crate::worker::Path,
    pub generation: u64,
    /// How long before the worker read it the packet was sampled, by its
    /// sampler's clock: when the flow cache counts it.
    pub age_ms: u64,
}

/// The frame a sample stands for, as it was on the wire: an offloaded
/// VLAN tag goes back between the MAC addresses, and the length counts it
/// and the FCS. A priority tag (VID 0) goes back as it was.
pub fn wire_frame(s: &Sample<'_>) -> (Vec<u8>, u32) {
    let mut header = Vec::with_capacity(s.header.len() + 4);
    let mut frame_length = s.frame_len + FCS;
    match s.vlan {
        Some(v) if s.header.len() >= 12 => {
            header.extend_from_slice(&s.header[..12]);
            header.extend_from_slice(&v.proto.to_be_bytes());
            header.extend_from_slice(&v.tci.to_be_bytes());
            header.extend_from_slice(&s.header[12..]);
            frame_length += 4;
        }
        _ => header.extend_from_slice(s.header),
    }
    (header, frame_length)
}

/// The frame for a sample from a device with no link-layer header (an IP
/// tunnel, WireGuard, TUN): the IP packet behind an Ethernet header with
/// zero MACs and the packet's ethertype, so sFlow's raw header record
/// (Ethernet) and the IPFIX flow cache read it like any other. Its length
/// counts that header and no FCS, as `stripped` 0 says. `None` when the
/// packet is not IP.
pub fn ip_frame(s: &Sample<'_>) -> Option<(Vec<u8>, u32, u32)> {
    let ethertype: u16 = match s.header.first()? >> 4 {
        4 => 0x0800,
        6 => 0x86dd,
        _ => return None,
    };
    let mut header = Vec::with_capacity(ETH_HEADER + s.header.len());
    header.extend_from_slice(&[0; 12]);
    header.extend_from_slice(&ethertype.to_be_bytes());
    header.extend_from_slice(s.header);
    Some((header, s.frame_len + ETH_HEADER as u32, 0))
}

const ETH_HEADER: usize = 14;

/// The sFlow agent: one per exporter, one sub-agent, its datagram
/// sequence, and its encoding.
pub struct Exporter {
    agent: Agent,
    sequence: u32,
}

impl Exporter {
    pub fn new(address: IpAddr) -> Self {
        Self {
            agent: Agent {
                address,
                sub_agent_id: 0,
                encoding: Encoding::Compact,
            },
            sequence: 0,
        }
    }

    pub fn expanded(&self) -> bool {
        self.agent.encoding == Encoding::Expanded
    }

    /// Encode `ready` into datagrams of at most [`MAX_DATAGRAM`] bytes,
    /// appended to `out`. The first ifIndex past the compact encoding's
    /// 24 bits moves the agent to the expanded one for good. Returns the
    /// samples no datagram could hold (none, at these sizes).
    pub fn encode(&mut self, ready: &[Ready], uptime_ms: u32, out: &mut Vec<Vec<u8>>) -> usize {
        if self.agent.encoding == Encoding::Compact
            && ready
                .iter()
                .any(|r| r.source_if >= COMPACT_IF_LIMIT || r.output_if >= COMPACT_IF_LIMIT)
        {
            tracing::info!("an ifIndex needs the expanded sFlow encoding; switching for good");
            self.agent.encoding = Encoding::Expanded;
        }
        let samples: Vec<FlowSample<'_>> = ready
            .iter()
            .map(|r| FlowSample {
                sequence: r.sequence,
                source_if: r.source_if,
                sampling_rate: r.rate,
                sample_pool: r.pool,
                drops: r.drops,
                input_if: r.source_if,
                output_if: r.output_if,
                frame_length: r.frame_length,
                stripped: r.stripped,
                header: &r.header,
            })
            .collect();
        let mut rest = &samples[..];
        let mut unsent = 0;
        while !rest.is_empty() {
            let mut buf = Vec::with_capacity(MAX_DATAGRAM);
            match sflow::encode_datagram(
                &mut buf,
                &self.agent,
                self.sequence,
                uptime_ms,
                rest,
                MAX_DATAGRAM,
            ) {
                Ok(n) => {
                    self.sequence = self.sequence.wrapping_add(1);
                    out.push(buf);
                    rest = &rest[n..];
                }
                // One sample larger than a datagram: not at these header
                // sizes, but never a loop.
                Err(EncodeError::TooLarge) => {
                    unsent += 1;
                    rest = &rest[1..];
                }
                Err(EncodeError::IfIndexRange(_)) => {
                    self.agent.encoding = Encoding::Expanded;
                }
            }
        }
        unsent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetframe_fast_path::sample::{Disposition, Path, Vlan};

    fn sample<'a>(header: &'a [u8], vlan: Option<Vlan>) -> Sample<'a> {
        Sample {
            ktime_ns: 1,
            generation: 1,
            rate: 1000,
            ingress_ifindex: 3,
            egress_ifindex: 0,
            frame_len: 60,
            path: Path::Tc,
            disposition: Disposition::Pass,
            vlan,
            header,
        }
    }

    /// A tunnel's packet starts at its IP header: framed as Ethernet with
    /// zero MACs and its version's ethertype, its length counting that
    /// header and no FCS. Anything but IP is not framed.
    #[test]
    fn an_ip_devices_packet_is_framed_by_its_version() {
        let v4 = [0x45, 0, 0, 60];
        let (h, len, stripped) = ip_frame(&sample(&v4, None)).unwrap();
        assert_eq!(&h[..12], &[0; 12]);
        assert_eq!(&h[12..14], &[0x08, 0x00]);
        assert_eq!(&h[14..], &v4);
        assert_eq!((len, stripped), (60 + 14, 0));
        let (h, _, _) = ip_frame(&sample(&[0x60, 0, 0, 0], None)).unwrap();
        assert_eq!(&h[12..14], &[0x86, 0xdd]);
        assert!(
            ip_frame(&sample(&[0x02, 0, 0, 0], None)).is_none(),
            "not IP"
        );
        assert!(ip_frame(&sample(&[], None)).is_none(), "nothing captured");
    }

    #[test]
    fn an_offloaded_tag_goes_back_on_the_wire() {
        let frame: Vec<u8> = (0..20).collect();
        let (h, len) = wire_frame(&sample(&frame, None));
        assert_eq!((h.as_slice(), len), (&frame[..], 64), "FCS counted");
        let tag = Vlan {
            proto: 0x8100,
            tci: 0xa000,
        };
        let (h, len) = wire_frame(&sample(&frame, Some(tag)));
        assert_eq!(len, 68);
        assert_eq!(&h[..12], &frame[..12]);
        assert_eq!(
            &h[12..16],
            &[0x81, 0x00, 0xa0, 0x00],
            "VID 0 kept as a priority tag"
        );
        assert_eq!(&h[16..], &frame[12..]);
    }

    fn ready(i: u32, if_: u32) -> Ready {
        Ready {
            sequence: i,
            source_if: if_,
            rate: 1000,
            pool: 1000 * i,
            drops: 0,
            output_if: 0,
            frame_length: 1518,
            stripped: FCS,
            header: vec![0xab; 128],
            path: crate::worker::Path::Xdp,
            generation: 1,
            age_ms: 0,
        }
    }

    #[test]
    fn samples_fill_datagrams_of_at_most_the_limit_in_sequence() {
        let mut x = Exporter::new("192.0.2.1".parse().unwrap());
        let batch: Vec<Ready> = (0..40).map(|i| ready(i, 3)).collect();
        let mut out = Vec::new();
        assert_eq!(x.encode(&batch, 5, &mut out), 0);
        assert!(out.len() > 1);
        assert!(out.iter().all(|d| d.len() <= MAX_DATAGRAM));
        // Each datagram's sequence (word 4 after the v4 agent address).
        let seqs: Vec<u32> = out
            .iter()
            .map(|d| u32::from_be_bytes(d[16..20].try_into().unwrap()))
            .collect();
        assert_eq!(seqs, (0..out.len() as u32).collect::<Vec<_>>());
        // And every sample is in exactly one of them (word 6: count).
        let n: u32 = out
            .iter()
            .map(|d| u32::from_be_bytes(d[24..28].try_into().unwrap()))
            .sum();
        assert_eq!(n, 40);
    }

    #[test]
    fn a_wide_ifindex_moves_the_agent_to_the_expanded_encoding() {
        let mut x = Exporter::new("192.0.2.1".parse().unwrap());
        let mut out = Vec::new();
        x.encode(&[ready(0, 3)], 0, &mut out);
        assert!(!x.expanded());
        x.encode(&[ready(1, COMPACT_IF_LIMIT)], 0, &mut out);
        assert!(x.expanded());
        assert_eq!(out.len(), 2);
    }
}
