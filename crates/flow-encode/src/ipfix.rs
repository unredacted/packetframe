//! IPFIX messages (RFC 7011): flow records, and PSAMP packet reports
//! (RFC 5476) with selector reporting (information elements from RFC 5477).
//!
//! A message is a header followed by sets: template sets (id 2), options
//! template sets (id 3) and data sets (id = template id >= 256). Times are
//! absolute (Unix epoch milliseconds), unlike NetFlow v9.

use crate::{pad4, put_u16_at, v4, v6, Field, FlowRecord};

/// IANA IPFIX information element ids used here.
mod ie {
    pub const OCTET_DELTA_COUNT: u16 = 1;
    pub const PACKET_DELTA_COUNT: u16 = 2;
    pub const PROTOCOL_IDENTIFIER: u16 = 4;
    pub const SOURCE_TRANSPORT_PORT: u16 = 7;
    pub const SOURCE_IPV4_ADDRESS: u16 = 8;
    pub const INGRESS_INTERFACE: u16 = 10;
    pub const DESTINATION_TRANSPORT_PORT: u16 = 11;
    pub const DESTINATION_IPV4_ADDRESS: u16 = 12;
    pub const EGRESS_INTERFACE: u16 = 14;
    pub const BGP_SOURCE_AS_NUMBER: u16 = 16;
    pub const BGP_DESTINATION_AS_NUMBER: u16 = 17;
    pub const SOURCE_IPV6_ADDRESS: u16 = 27;
    pub const DESTINATION_IPV6_ADDRESS: u16 = 28;
    pub const SAMPLING_INTERVAL: u16 = 34;
    pub const FLOW_START_MILLISECONDS: u16 = 152;
    pub const FLOW_END_MILLISECONDS: u16 = 153;
    pub const SELECTOR_ID: u16 = 302;
    pub const SELECTOR_ALGORITHM: u16 = 304;
    pub const SAMPLING_PACKET_INTERVAL: u16 = 305;
    pub const SAMPLING_PACKET_SPACE: u16 = 306;
    pub const DATA_LINK_FRAME_SIZE: u16 = 312;
    pub const DATA_LINK_FRAME_SECTION: u16 = 315;
    pub const OBSERVATION_TIME_MILLISECONDS: u16 = 323;
}

/// Template length marking a variable-length field (RFC 7011 §7).
const VARIABLE_LENGTH: u16 = 0xffff;

/// `selectorAlgorithm` (RFC 5477 §8.2.1 / IANA): systematic count-based,
/// described by `samplingPacketInterval` (packets selected) and
/// `samplingPacketSpace` (packets skipped) — the encoding collectors read
/// a plain 1-in-N rate from. 1-in-N is interval 1, space N-1.
const SELECTOR_SYSTEMATIC_COUNT: u16 = 1;

const SET_TEMPLATE: u16 = 2;
const SET_OPTIONS_TEMPLATE: u16 = 3;

fn ie_and_len(f: Field) -> (u16, u16) {
    match f {
        Field::Octets => (ie::OCTET_DELTA_COUNT, 8),
        Field::Packets => (ie::PACKET_DELTA_COUNT, 8),
        Field::Protocol => (ie::PROTOCOL_IDENTIFIER, 1),
        Field::SrcPort => (ie::SOURCE_TRANSPORT_PORT, 2),
        Field::DstPort => (ie::DESTINATION_TRANSPORT_PORT, 2),
        Field::SrcIpv4 => (ie::SOURCE_IPV4_ADDRESS, 4),
        Field::DstIpv4 => (ie::DESTINATION_IPV4_ADDRESS, 4),
        Field::SrcIpv6 => (ie::SOURCE_IPV6_ADDRESS, 16),
        Field::DstIpv6 => (ie::DESTINATION_IPV6_ADDRESS, 16),
        Field::InputIf => (ie::INGRESS_INTERFACE, 4),
        Field::OutputIf => (ie::EGRESS_INTERFACE, 4),
        Field::SrcAs => (ie::BGP_SOURCE_AS_NUMBER, 4),
        Field::DstAs => (ie::BGP_DESTINATION_AS_NUMBER, 4),
        Field::Start => (ie::FLOW_START_MILLISECONDS, 8),
        Field::End => (ie::FLOW_END_MILLISECONDS, 8),
        Field::SamplingInterval => (ie::SAMPLING_INTERVAL, 4),
    }
}

/// One exporting process towards one collector, in one observation domain.
#[derive(Debug, Clone)]
pub struct Exporter {
    pub observation_domain_id: u32,
    /// Data records sent so far in this domain, modulo 2^32 (RFC 7011 §3.1:
    /// counts data records, not messages, and excludes the current one).
    pub sequence: u32,
}

/// A flow-record template.
#[derive(Debug, Clone)]
pub struct Template<'a> {
    pub id: u16,
    pub fields: &'a [Field],
}

/// A selector (sampler) to announce in an options record: scoped by its
/// selector id, describing a 1-in-`interval` selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selector {
    pub template_id: u16,
    pub selector_id: u64,
    pub interval: u32,
}

/// One PSAMP packet report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketReport<'a> {
    pub selector_id: u64,
    pub observation_ms: u64,
    pub input_if: u32,
    /// 0 when unknown.
    pub output_if: u32,
    /// Length of the frame on the wire.
    pub frame_size: u16,
    /// Leading bytes of the frame, from the Ethernet header.
    pub frame_section: &'a [u8],
}

/// What one message carries beyond its data records.
#[derive(Debug, Clone, Default)]
pub struct Announce<'a> {
    pub templates: &'a [Template<'a>],
    pub selector: Option<Selector>,
    /// Template id for packet reports, announced with their template.
    pub packet_report_template: Option<u16>,
}

impl Exporter {
    /// Encodes a message of flow records with template `data`.
    pub fn encode_flows(
        &mut self,
        out: &mut Vec<u8>,
        export_time_s: u32,
        announce: &Announce<'_>,
        data: &Template<'_>,
        records: &[FlowRecord],
    ) {
        let options = self.begin(out, export_time_s, announce);
        if !records.is_empty() {
            let set = begin_set(out, data.id);
            for r in records {
                for &f in data.fields {
                    write_field(out, f, r);
                }
            }
            end_set(out, set);
        }
        self.finish(out, records.len() as u32 + options);
    }

    /// Encodes a message of PSAMP packet reports with template `template_id`
    /// (announced with [`Announce::packet_report_template`]).
    pub fn encode_packet_reports(
        &mut self,
        out: &mut Vec<u8>,
        export_time_s: u32,
        announce: &Announce<'_>,
        template_id: u16,
        reports: &[PacketReport<'_>],
    ) {
        let options = self.begin(out, export_time_s, announce);
        if !reports.is_empty() {
            let set = begin_set(out, template_id);
            for p in reports {
                out.extend_from_slice(&p.selector_id.to_be_bytes());
                out.extend_from_slice(&p.observation_ms.to_be_bytes());
                out.extend_from_slice(&p.input_if.to_be_bytes());
                out.extend_from_slice(&p.output_if.to_be_bytes());
                out.extend_from_slice(&p.frame_size.to_be_bytes());
                put_varlen(out, p.frame_section);
            }
            end_set(out, set);
        }
        self.finish(out, reports.len() as u32 + options);
    }

    /// Writes the header and the announced templates and options; returns
    /// the number of options data records written, which count towards
    /// the sequence number like any other data record.
    fn begin(&self, out: &mut Vec<u8>, export_time_s: u32, a: &Announce<'_>) -> u32 {
        out.clear();
        out.extend_from_slice(&10u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // length, backfilled
        out.extend_from_slice(&export_time_s.to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.observation_domain_id.to_be_bytes());

        if !a.templates.is_empty() || a.packet_report_template.is_some() {
            let set = begin_set(out, SET_TEMPLATE);
            for t in a.templates {
                out.extend_from_slice(&t.id.to_be_bytes());
                out.extend_from_slice(&(t.fields.len() as u16).to_be_bytes());
                for &f in t.fields {
                    let (id, len) = ie_and_len(f);
                    put_spec(out, id, len);
                }
            }
            if let Some(id) = a.packet_report_template {
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&6u16.to_be_bytes());
                put_spec(out, ie::SELECTOR_ID, 8);
                put_spec(out, ie::OBSERVATION_TIME_MILLISECONDS, 8);
                put_spec(out, ie::INGRESS_INTERFACE, 4);
                put_spec(out, ie::EGRESS_INTERFACE, 4);
                put_spec(out, ie::DATA_LINK_FRAME_SIZE, 2);
                put_spec(out, ie::DATA_LINK_FRAME_SECTION, VARIABLE_LENGTH);
            }
            end_set(out, set);
        }

        if let Some(s) = a.selector {
            // Options template: scope selectorId, then the algorithm and its
            // parameters (RFC 5476 §6.5.1, Selection Sequence Report
            // Interpretation simplified to one selector).
            let set = begin_set(out, SET_OPTIONS_TEMPLATE);
            out.extend_from_slice(&s.template_id.to_be_bytes());
            out.extend_from_slice(&5u16.to_be_bytes()); // field count
            out.extend_from_slice(&1u16.to_be_bytes()); // scope field count
            put_spec(out, ie::SELECTOR_ID, 8);
            put_spec(out, ie::SELECTOR_ALGORITHM, 2);
            put_spec(out, ie::SAMPLING_PACKET_INTERVAL, 4);
            put_spec(out, ie::SAMPLING_PACKET_SPACE, 4);
            put_spec(out, ie::SAMPLING_INTERVAL, 4);
            end_set(out, set);

            let set = begin_set(out, s.template_id);
            out.extend_from_slice(&s.selector_id.to_be_bytes());
            out.extend_from_slice(&SELECTOR_SYSTEMATIC_COUNT.to_be_bytes());
            out.extend_from_slice(&1u32.to_be_bytes());
            out.extend_from_slice(&s.interval.saturating_sub(1).to_be_bytes());
            out.extend_from_slice(&s.interval.to_be_bytes());
            end_set(out, set);
            return 1;
        }
        0
    }

    /// Backfills the message length and advances the sequence past the
    /// message's data records.
    fn finish(&mut self, out: &mut [u8], data_records: u32) {
        let len = out.len() as u16;
        put_u16_at(out, 2, len);
        self.sequence = self.sequence.wrapping_add(data_records);
    }
}

fn write_field(out: &mut Vec<u8>, f: Field, r: &FlowRecord) {
    match f {
        Field::Octets => out.extend_from_slice(&r.octets.to_be_bytes()),
        Field::Packets => out.extend_from_slice(&r.packets.to_be_bytes()),
        Field::Protocol => out.push(r.protocol),
        Field::SrcPort => out.extend_from_slice(&r.src_port.to_be_bytes()),
        Field::DstPort => out.extend_from_slice(&r.dst_port.to_be_bytes()),
        Field::SrcIpv4 => out.extend_from_slice(&v4(r.src).octets()),
        Field::DstIpv4 => out.extend_from_slice(&v4(r.dst).octets()),
        Field::SrcIpv6 => out.extend_from_slice(&v6(r.src).octets()),
        Field::DstIpv6 => out.extend_from_slice(&v6(r.dst).octets()),
        Field::InputIf => out.extend_from_slice(&r.input_if.to_be_bytes()),
        Field::OutputIf => out.extend_from_slice(&r.output_if.to_be_bytes()),
        Field::SrcAs => out.extend_from_slice(&r.src_as.to_be_bytes()),
        Field::DstAs => out.extend_from_slice(&r.dst_as.to_be_bytes()),
        Field::Start => out.extend_from_slice(&r.start_ms.to_be_bytes()),
        Field::End => out.extend_from_slice(&r.end_ms.to_be_bytes()),
        Field::SamplingInterval => out.extend_from_slice(&r.sampling_interval.to_be_bytes()),
    }
}

fn put_spec(out: &mut Vec<u8>, id: u16, len: u16) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
}

/// Variable-length encoding (RFC 7011 §7): one length byte below 255,
/// otherwise 255 followed by a two-byte length.
fn put_varlen(out: &mut Vec<u8>, v: &[u8]) {
    if v.len() < 255 {
        out.push(v.len() as u8);
    } else {
        out.push(255);
        out.extend_from_slice(&(v.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(v);
}

fn begin_set(out: &mut Vec<u8>, id: u16) -> usize {
    let at = out.len();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    at
}

fn end_set(out: &mut Vec<u8>, at: usize) {
    // IPFIX allows but does not require set padding; pad to four bytes so
    // set boundaries stay aligned for collectors that assume it.
    pad4(out);
    let len = (out.len() - at) as u16;
    put_u16_at(out, at + 2, len);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flow_fields, Family, Profile, SamplingSignal};

    fn u16_at(b: &[u8], at: usize) -> u16 {
        u16::from_be_bytes(b[at..at + 2].try_into().unwrap())
    }
    fn u32_at(b: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(b[at..at + 4].try_into().unwrap())
    }
    fn u64_at(b: &[u8], at: usize) -> u64 {
        u64::from_be_bytes(b[at..at + 8].try_into().unwrap())
    }

    fn sets(b: &[u8]) -> Vec<(u16, usize, usize)> {
        assert_eq!(u16_at(b, 2) as usize, b.len(), "message length");
        let mut at = 16;
        let mut v = Vec::new();
        while at < b.len() {
            let id = u16_at(b, at);
            let len = u16_at(b, at + 2) as usize;
            assert!(len >= 4, "set {id} length {len}");
            v.push((id, at, len));
            at += len;
        }
        assert_eq!(at, b.len());
        v
    }

    fn record() -> FlowRecord {
        FlowRecord {
            src: "2001:db8::7".parse().unwrap(),
            dst: "2001:db8:1::10".parse().unwrap(),
            protocol: 6,
            src_port: 443,
            dst_port: 51000,
            input_if: 4,
            output_if: 5,
            src_as: 64500,
            dst_as: 64501,
            packets: 3,
            octets: 4500,
            start_ms: 1_790_000_000_000,
            end_ms: 1_790_000_001_000,
            sampling_interval: 512,
        }
    }

    #[test]
    fn flows_with_templates_and_selector() {
        let fields = flow_fields(Family::V6, Profile::Full, SamplingSignal::Options);
        let t = Template {
            id: 256,
            fields: &fields,
        };
        let a = Announce {
            templates: std::slice::from_ref(&t),
            selector: Some(Selector {
                template_id: 257,
                selector_id: 1,
                interval: 512,
            }),
            packet_report_template: None,
        };
        let mut e = Exporter {
            observation_domain_id: 9,
            sequence: 100,
        };
        let mut b = Vec::new();
        e.encode_flows(&mut b, 1_790_000_002, &a, &t, &[record(), record()]);

        assert_eq!(u16_at(&b, 0), 10);
        assert_eq!(u32_at(&b, 4), 1_790_000_002);
        assert_eq!(u32_at(&b, 8), 100, "sequence excludes this message");
        assert_eq!(u32_at(&b, 12), 9);
        assert_eq!(e.sequence, 100 + 2 + 1, "two flows and one options record");

        let s = sets(&b);
        assert_eq!(
            s.iter().map(|x| x.0).collect::<Vec<_>>(),
            vec![2, 3, 257, 256]
        );

        // Options data: selector id, algorithm, interval 1, space 511, 512.
        let (_, at, _) = s[2];
        assert_eq!(u64_at(&b, at + 4), 1);
        assert_eq!(u16_at(&b, at + 12), SELECTOR_SYSTEMATIC_COUNT);
        assert_eq!(u32_at(&b, at + 14), 1);
        assert_eq!(u32_at(&b, at + 18), 511);
        assert_eq!(u32_at(&b, at + 22), 512);

        // Flow data: epoch times as 64-bit milliseconds.
        let width: usize = fields.iter().map(|&f| ie_and_len(f).1 as usize).sum();
        let (_, at, len) = s[3];
        assert_eq!(len, (4 + 2 * width).div_ceil(4) * 4);
        let r = at + 4;
        assert_eq!(u64_at(&b, r), 4500);
        assert_eq!(u64_at(&b, r + 8), 3);
        assert_eq!(b[r + 16], 6);
        assert_eq!(u64_at(&b, r + width - 8), 1_790_000_001_000);
        assert_eq!(u64_at(&b, r + width - 16), 1_790_000_000_000);
    }

    #[test]
    fn packet_reports_with_short_and_long_sections() {
        let a = Announce {
            templates: &[],
            selector: None,
            packet_report_template: Some(300),
        };
        let mut e = Exporter {
            observation_domain_id: 1,
            sequence: 0,
        };
        let short = [0x11u8; 64];
        let long = [0x22u8; 300];
        let reports = [
            PacketReport {
                selector_id: 1,
                observation_ms: 5,
                input_if: 2,
                output_if: 0,
                frame_size: 1500,
                frame_section: &short,
            },
            PacketReport {
                selector_id: 1,
                observation_ms: 6,
                input_if: 2,
                output_if: 0,
                frame_size: 1500,
                frame_section: &long,
            },
        ];
        let mut b = Vec::new();
        e.encode_packet_reports(&mut b, 1, &a, 300, &reports);
        assert_eq!(e.sequence, 2);

        let s = sets(&b);
        assert_eq!(s.iter().map(|x| x.0).collect::<Vec<_>>(), vec![2, 300]);
        let (_, at, _) = s[0];
        assert_eq!(u16_at(&b, at + 4), 300);
        assert_eq!(u16_at(&b, at + 6), 6);
        let last_spec = at + 8 + 5 * 4;
        assert_eq!(u16_at(&b, last_spec), ie::DATA_LINK_FRAME_SECTION);
        assert_eq!(u16_at(&b, last_spec + 2), VARIABLE_LENGTH);

        // Fixed part is 8 + 8 + 4 + 4 + 2 = 26 bytes, then the section.
        let (_, at, _) = s[1];
        let r0 = at + 4;
        assert_eq!(u64_at(&b, r0 + 8), 5);
        assert_eq!(b[r0 + 26], 64, "one-byte length");
        let r1 = r0 + 26 + 1 + 64;
        assert_eq!(u64_at(&b, r1 + 8), 6);
        assert_eq!(b[r1 + 26], 255, "three-byte length marker");
        assert_eq!(u16_at(&b, r1 + 27), 300);
        assert_eq!(b[r1 + 29], 0x22);
    }
}
