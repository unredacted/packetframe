//! sFlow version 5 datagrams of flow samples with raw packet headers.
//!
//! Layout per sflow.org "sFlow Version 5" (2004), XDR encoded: every field
//! big-endian, opaque data padded to four bytes. Only what a packet sampler
//! needs: `flow_sample` (enterprise 0, format 1) holding one
//! `raw_packet_header` record (enterprise 0, format 1).

use std::net::IpAddr;

use crate::pad4;

/// The agent identity every datagram carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Agent {
    pub address: IpAddr,
    pub sub_agent_id: u32,
}

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
    /// Length of the packet on the wire, before any header truncation.
    pub frame_length: u32,
    /// Leading bytes of the frame, starting at the Ethernet header.
    pub header: &'a [u8],
}

const FORMAT_FLOW_SAMPLE: u32 = 1;
const FORMAT_RAW_PACKET_HEADER: u32 = 1;

/// Encodes one datagram into `out` (cleared first).
///
/// `sequence` counts datagrams from this sub-agent; `uptime_ms` is the
/// agent's uptime when the datagram is sent.
pub fn encode_datagram(
    out: &mut Vec<u8>,
    agent: &Agent,
    sequence: u32,
    uptime_ms: u32,
    samples: &[FlowSample<'_>],
) {
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
    put(out, samples.len() as u32);
    for s in samples {
        encode_flow_sample(out, s);
    }
}

fn encode_flow_sample(out: &mut Vec<u8>, s: &FlowSample<'_>) {
    put(out, FORMAT_FLOW_SAMPLE);
    let len_at = out.len();
    put(out, 0); // sample length, backfilled
    let body = out.len();
    put(out, s.sequence);
    put(out, s.source_if & 0x00ff_ffff); // type 0 (ifIndex) in the top byte
    put(out, s.sampling_rate);
    put(out, s.sample_pool);
    put(out, s.drops);
    put(out, s.input_if & 0x3fff_ffff); // format 0: a single ifIndex
    put(out, s.output_if & 0x3fff_ffff);
    put(out, 1); // one record

    put(out, FORMAT_RAW_PACKET_HEADER);
    let rec_len_at = out.len();
    put(out, 0); // record length, backfilled
    let rec = out.len();
    put(out, HEADER_PROTOCOL_ETHERNET);
    put(out, s.frame_length);
    put(out, 0); // stripped: nothing removed before the header was taken
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

    #[test]
    fn datagram_layout() {
        let header = [0xaa; 6]; // 6 bytes: forces 2 bytes of padding
        let sample = FlowSample {
            sequence: 7,
            source_if: 3,
            sampling_rate: 1000,
            sample_pool: 123_456,
            drops: 2,
            input_if: 3,
            output_if: 0,
            frame_length: 1514,
            header: &header,
        };
        let agent = Agent {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            sub_agent_id: 9,
        };
        let mut b = Vec::new();
        encode_datagram(&mut b, &agent, 42, 5000, &[sample]);

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
        assert_eq!(u32_at(&b, 80), 1514);
        assert_eq!(u32_at(&b, 84), 0);
        assert_eq!(u32_at(&b, 88), 6);
        assert_eq!(&b[92..98], &header);
        assert_eq!(&b[98..100], &[0, 0]);
        assert_eq!(b.len() % 4, 0);
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
            frame_length: 64,
            header: &header,
        };
        let agent = Agent {
            address: "2001:db8::1".parse().unwrap(),
            sub_agent_id: 0,
        };
        let mut b = Vec::new();
        encode_datagram(&mut b, &agent, 1, 0, &[s, s, s]);
        assert_eq!(u32_at(&b, 4), 2);
        assert_eq!(u32_at(&b, 36), 3); // samples, after a 16-byte address
                                       // Each sample: 8 (format+len) + 32 (fields) + 8 (record hdr) + 16 + 64.
        assert_eq!(b.len(), 40 + 3 * (8 + 32 + 8 + 16 + 64));
    }
}
