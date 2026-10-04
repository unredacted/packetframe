//! sFlow version 5 datagrams of flow samples with raw packet headers.
//!
//! Layout per sflow.org "sFlow Version 5" (2004), XDR encoded: every field
//! big-endian, opaque data padded to four bytes. Only what a packet sampler
//! needs: flow samples (enterprise 0; `flow_sample` format 1, or
//! `flow_sample_expanded` format 3), each holding one `raw_packet_header`
//! record (enterprise 0, format 1).

use std::net::IpAddr;

use crate::{fill, pad4, EncodeError};

/// The agent identity every datagram carries, and its sample encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Agent {
    pub address: IpAddr,
    pub sub_agent_id: u32,
    pub encoding: Encoding,
}

/// Flow-sample encoding. An agent must not mix them: compact when every
/// ifIndex it will ever report is below 2^24, expanded otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `flow_sample`: an ifIndex shares its word with its type or format.
    Compact,
    /// `flow_sample_expanded`: full 32-bit ifIndexes.
    Expanded,
}

/// An agent reporting any ifIndex at or above this must use
/// [`Encoding::Expanded`]: a compact sample has 24 bits for it.
pub const COMPACT_IF_LIMIT: u32 = 1 << 24;

/// `header_protocol` value for an Ethernet frame (ETHERNET-ISO88023).
pub const HEADER_PROTOCOL_ETHERNET: u32 = 1;

/// One sampled packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowSample<'a> {
    /// Per data source, incremented for every sample generated.
    pub sequence: u32,
    /// ifIndex of the data source (source_id type 0).
    pub source_if: u32,
    /// 1-in-N.
    pub sampling_rate: u32,
    /// Packets that could have been sampled: every packet the data source
    /// saw, sampled or not. Lets the collector check the rate it scales by.
    pub sample_pool: u32,
    /// Samples lost for lack of resources since the data source started.
    pub drops: u32,
    pub input_if: u32,
    /// 0 when unknown.
    pub output_if: u32,
    /// Octets of the frame on the wire, FCS included, before truncation.
    pub frame_length: u32,
    /// Octets removed before `header` was taken: at least the 4 FCS octets
    /// for an Ethernet frame, plus any VLAN tag removed with them.
    pub stripped: u32,
    /// Leading bytes of the frame, starting at the Ethernet header.
    pub header: &'a [u8],
}

const FORMAT_FLOW_SAMPLE: u32 = 1;
const FORMAT_FLOW_SAMPLE_EXPANDED: u32 = 3;
const FORMAT_RAW_PACKET_HEADER: u32 = 1;
/// The sFlowDataSource type and the interface format of an ifIndex.
const IFINDEX: u32 = 0;

/// Encodes into `out` (cleared first) a datagram holding the longest prefix
/// of `samples` that fits in `max_len` bytes; returns how many it holds.
///
/// `sequence` counts datagrams from this sub-agent; `uptime_ms` is the
/// agent's uptime when the datagram is sent.
pub fn encode_datagram(
    out: &mut Vec<u8>,
    agent: &Agent,
    sequence: u32,
    uptime_ms: u32,
    samples: &[FlowSample<'_>],
    max_len: usize,
) -> Result<usize, EncodeError> {
    out.clear();
    put(out, 5); // version
    match agent.address {
        IpAddr::V4(a) => {
            put(out, 1);
            out.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            put(out, 2);
            out.extend_from_slice(&a.octets());
        }
    }
    put(out, agent.sub_agent_id);
    put(out, sequence);
    put(out, uptime_ms);
    let count_at = out.len();
    put(out, 0); // samples, backfilled
    if out.len() > max_len {
        out.clear();
        return Err(EncodeError::TooLarge);
    }
    let n = fill(out, max_len, samples, |out, s| {
        encode_flow_sample(out, agent.encoding, s)
    });
    if n == 0 && !samples.is_empty() {
        out.clear();
        return Err(EncodeError::TooLarge);
    }
    if agent.encoding == Encoding::Compact {
        let wide = samples[..n]
            .iter()
            .flat_map(|s| [s.source_if, s.input_if, s.output_if])
            .find(|&i| i >= COMPACT_IF_LIMIT);
        if let Some(i) = wide {
            out.clear();
            return Err(EncodeError::IfIndexRange(i));
        }
    }
    out[count_at..count_at + 4].copy_from_slice(&(n as u32).to_be_bytes());
    Ok(n)
}

fn encode_flow_sample(out: &mut Vec<u8>, encoding: Encoding, s: &FlowSample<'_>) {
    put(
        out,
        match encoding {
            Encoding::Compact => FORMAT_FLOW_SAMPLE,
            Encoding::Expanded => FORMAT_FLOW_SAMPLE_EXPANDED,
        },
    );
    let len_at = out.len();
    put(out, 0); // sample length, backfilled
    let body = out.len();
    put(out, s.sequence);
    match encoding {
        // Type 0 (ifIndex) in the top byte; the caller checks the range.
        Encoding::Compact => put(out, s.source_if),
        Encoding::Expanded => {
            put(out, IFINDEX);
            put(out, s.source_if);
        }
    }
    put(out, s.sampling_rate);
    put(out, s.sample_pool);
    put(out, s.drops);
    for i in [s.input_if, s.output_if] {
        match encoding {
            // Format 0 (a single ifIndex) in the top two bits.
            Encoding::Compact => put(out, i),
            Encoding::Expanded => {
                put(out, IFINDEX);
                put(out, i);
            }
        }
    }
    put(out, 1); // one record

    put(out, FORMAT_RAW_PACKET_HEADER);
    let rec_len_at = out.len();
    put(out, 0); // record length, backfilled
    let rec = out.len();
    put(out, HEADER_PROTOCOL_ETHERNET);
    put(out, s.frame_length);
    put(out, s.stripped);
    put(out, s.header.len() as u32);
    out.extend_from_slice(s.header);
    pad4(out);
    let rec_len = (out.len() - rec) as u32;
    out[rec_len_at..rec_len_at + 4].copy_from_slice(&rec_len.to_be_bytes());

    let len = (out.len() - body) as u32;
    out[len_at..len_at + 4].copy_from_slice(&len.to_be_bytes());
}

fn put(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
    }

    fn agent(encoding: Encoding) -> Agent {
        Agent {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            sub_agent_id: 9,
            encoding,
        }
    }

    fn sample(header: &[u8]) -> FlowSample<'_> {
        FlowSample {
            sequence: 7,
            source_if: 3,
            sampling_rate: 1000,
            sample_pool: 123_456,
            drops: 2,
            input_if: 3,
            output_if: 0,
            frame_length: 1518,
            stripped: 4,
            header,
        }
    }

    #[test]
    fn datagram_layout() {
        let header = [0xaa; 6]; // 6 bytes: forces 2 bytes of padding
        let mut b = Vec::new();
        let n = encode_datagram(
            &mut b,
            &agent(Encoding::Compact),
            42,
            5000,
            &[sample(&header)],
            1500,
        );
        assert_eq!(n, Ok(1));

        assert_eq!(u32_at(&b, 0), 5);
        assert_eq!(u32_at(&b, 4), 1);
        assert_eq!(&b[8..12], &[192, 0, 2, 1]);
        assert_eq!(u32_at(&b, 12), 9);
        assert_eq!(u32_at(&b, 16), 42);
        assert_eq!(u32_at(&b, 20), 5000);
        assert_eq!(u32_at(&b, 24), 1); // samples

        // flow_sample
        assert_eq!(u32_at(&b, 28), FORMAT_FLOW_SAMPLE);
        let sample_len = u32_at(&b, 32) as usize;
        assert_eq!(36 + sample_len, b.len(), "sample length covers the rest");
        assert_eq!(u32_at(&b, 36), 7);
        assert_eq!(u32_at(&b, 40), 3);
        assert_eq!(u32_at(&b, 44), 1000);
        assert_eq!(u32_at(&b, 48), 123_456);
        assert_eq!(u32_at(&b, 52), 2);
        assert_eq!(u32_at(&b, 56), 3);
        assert_eq!(u32_at(&b, 60), 0);
        assert_eq!(u32_at(&b, 64), 1); // records

        // raw_packet_header
        assert_eq!(u32_at(&b, 68), FORMAT_RAW_PACKET_HEADER);
        assert_eq!(u32_at(&b, 72), 16 + 8, "4 words + header padded to 8");
        assert_eq!(u32_at(&b, 76), HEADER_PROTOCOL_ETHERNET);
        assert_eq!(u32_at(&b, 80), 1518);
        assert_eq!(u32_at(&b, 84), 4, "stripped FCS");
        assert_eq!(u32_at(&b, 88), 6);
        assert_eq!(&b[92..98], &header);
        assert_eq!(&b[98..100], &[0, 0]);
        assert_eq!(b.len() % 4, 0);
    }

    #[test]
    fn expanded_layout_carries_full_ifindexes() {
        let header = [1u8; 8];
        let mut s = sample(&header);
        s.source_if = 1 << 24;
        s.input_if = 1 << 24;
        s.output_if = u32::MAX;
        let mut b = Vec::new();
        let n = encode_datagram(&mut b, &agent(Encoding::Expanded), 1, 0, &[s], 1500);
        assert_eq!(n, Ok(1));
        assert_eq!(u32_at(&b, 28), FORMAT_FLOW_SAMPLE_EXPANDED);
        assert_eq!(u32_at(&b, 36), 7); // sequence
        assert_eq!((u32_at(&b, 40), u32_at(&b, 44)), (IFINDEX, 1 << 24));
        assert_eq!(u32_at(&b, 48), 1000);
        assert_eq!((u32_at(&b, 60), u32_at(&b, 64)), (IFINDEX, 1 << 24));
        assert_eq!((u32_at(&b, 68), u32_at(&b, 72)), (IFINDEX, u32::MAX));
        assert_eq!(u32_at(&b, 76), 1); // records
        assert_eq!(u32_at(&b, 80), FORMAT_RAW_PACKET_HEADER);
        // Expanded adds three words: source type, input and output formats.
        assert_eq!(u32_at(&b, 32) as usize, 32 + 12 + 8 + 16 + 8);
    }

    #[test]
    fn compact_refuses_wide_ifindexes() {
        let header = [1u8; 8];
        for wide in [
            FlowSample {
                source_if: 1 << 24,
                ..sample(&header)
            },
            FlowSample {
                input_if: 1 << 24,
                ..sample(&header)
            },
            FlowSample {
                output_if: 1 << 24,
                ..sample(&header)
            },
        ] {
            let mut b = vec![0xff];
            let r = encode_datagram(&mut b, &agent(Encoding::Compact), 1, 0, &[wide], 1500);
            assert_eq!(r, Err(EncodeError::IfIndexRange(1 << 24)));
            assert!(b.is_empty());
        }
    }

    #[test]
    fn length_limit_takes_a_prefix() {
        let header = [1u8; 128];
        let samples = [sample(&header); 10];
        // Each compact sample with a 128-byte header: 8 + 32 + 8 + 16 + 128.
        let each = 192;
        let mut b = Vec::new();
        let a = agent(Encoding::Compact);
        assert_eq!(encode_datagram(&mut b, &a, 1, 0, &samples, 1472), Ok(7));
        assert_eq!(b.len(), 28 + 7 * each);
        assert_eq!(u32_at(&b, 24), 7);
        assert_eq!(
            encode_datagram(&mut b, &a, 1, 0, &samples, 28 + each),
            Ok(1)
        );
        assert_eq!(
            encode_datagram(&mut b, &a, 1, 0, &samples, 28 + each - 1),
            Err(EncodeError::TooLarge)
        );
        assert!(b.is_empty());
        assert_eq!(encode_datagram(&mut b, &a, 1, 0, &[], 28), Ok(0));
        assert_eq!(
            encode_datagram(&mut b, &a, 1, 0, &[], 27),
            Err(EncodeError::TooLarge)
        );
    }

    #[test]
    fn v6_agent_and_many_samples() {
        let header = [1u8; 64];
        let s = FlowSample {
            sequence: 1,
            source_if: 1,
            sampling_rate: 1,
            sample_pool: 1,
            drops: 0,
            input_if: 1,
            output_if: 2,
            frame_length: 68,
            stripped: 4,
            header: &header,
        };
        let agent = Agent {
            address: "2001:db8::1".parse().unwrap(),
            sub_agent_id: 0,
            encoding: Encoding::Compact,
        };
        let mut b = Vec::new();
        assert_eq!(
            encode_datagram(&mut b, &agent, 1, 0, &[s, s, s], 1500),
            Ok(3)
        );
        assert_eq!(u32_at(&b, 4), 2);
        assert_eq!(u32_at(&b, 36), 3); // samples, after a 16-byte address
                                       // Each sample: 8 (format+len) + 32 (fields) + 8 (record hdr) + 16 + 64.
        assert_eq!(b.len(), 40 + 3 * (8 + 32 + 8 + 16 + 64));
    }
}
