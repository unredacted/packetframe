//! IPFIX messages (RFC 7011): flow records, and PSAMP packet reports
//! (RFC 5476) with selector reporting (information elements from RFC 5477).
//!
//! A message is a header followed by sets: template sets (id 2), options
//! template sets (id 3) and data sets (id = template id >= 256). Times are
//! absolute (Unix epoch milliseconds), unlike NetFlow v9.

use crate::{fill, pad4, put_u16_at, v4, v6, EncodeError, Field, FlowRecord};

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
    pub const SELECTION_SEQUENCE_ID: u16 = 301;
    pub const SELECTOR_ID: u16 = 302;
    pub const SELECTOR_ALGORITHM: u16 = 304;
    pub const SAMPLING_PACKET_INTERVAL: u16 = 305;
    pub const SAMPLING_PACKET_SPACE: u16 = 306;
    pub const DATA_LINK_FRAME_SIZE: u16 = 312;
    pub const DATA_LINK_FRAME_SECTION: u16 = 315;
    pub const OBSERVATION_TIME_MILLISECONDS: u16 = 323;
    pub const DATA_LINK_FRAME_TYPE: u16 = 408;
}

/// Template length marking a variable-length field (RFC 7011 §7).
const VARIABLE_LENGTH: u16 = 0xffff;

/// `selectorAlgorithm` (RFC 5477 §8.2.1 / IANA): systematic count-based,
/// described by `samplingPacketInterval` (packets selected) and
/// `samplingPacketSpace` (packets skipped) — the encoding collectors read
/// a plain 1-in-N rate from. 1-in-N is interval 1, space N-1.
const SELECTOR_SYSTEMATIC_COUNT: u16 = 1;

/// `dataLinkFrameType` (RFC 7133 §3.2.1) of an IEEE 802.3 frame: the type
/// a `dataLinkFrameSection` is decoded as.
const DATA_LINK_ETHERNET: u16 = 0x0001;

const SET_TEMPLATE: u16 = 2;
const SET_OPTIONS_TEMPLATE: u16 = 3;

/// A message's bytes before its first set (RFC 7011 §3.1), and a set's
/// before its records (§3.3.2); a set is padded to four bytes after them.
pub const MESSAGE_HEADER_LEN: usize = 16;
pub const SET_HEADER_LEN: usize = 4;
pub const SET_PADDING_MAX: usize = 3;

/// The bytes one record of `fields` takes in a data set.
pub fn record_len(fields: &[Field]) -> usize {
    fields.iter().map(|&f| usize::from(ie_and_len(f).1)).sum()
}

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

/// A selector (sampler) to announce in an options record (RFC 5476
/// §6.5.2, Selector Report Interpretation): scoped by its selector id,
/// describing a 1-in-`interval` selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selector {
    pub template_id: u16,
    pub selector_id: u64,
    pub interval: u32,
}

/// A selection sequence (RFC 5476 §6.5.1): the observation point a packet
/// was selected at and the selector that selected it. Every packet report
/// names one by id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectionSequence {
    pub id: u64,
    /// The observation point: the interface packets were sampled on.
    pub ingress_if: u32,
    pub selector_id: u64,
}

/// What announcing packet reports takes: their template, and the selection
/// sequences their reports name (an options template and one record each).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketReporting<'a> {
    pub template_id: u16,
    pub sequence_template_id: u16,
    pub sequences: &'a [SelectionSequence],
}

/// One PSAMP packet report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketReport<'a> {
    /// The selection sequence that selected the packet (RFC 5476 §6.4.1).
    pub selection_sequence_id: u64,
    /// The sequence's selector, repeated in the report: collectors that look
    /// the sampling rate up by a report's own selector id (Akvorado) need it.
    pub selector_id: u64,
    pub observation_ms: u64,
    pub input_if: u32,
    /// 0 when unknown.
    pub output_if: u32,
    /// Length of the Ethernet frame, FCS excluded, before truncation.
    pub frame_size: u16,
    /// Leading bytes of the frame, from the Ethernet header.
    pub frame_section: &'a [u8],
}

/// What one message carries beyond its data records.
#[derive(Debug, Clone, Default)]
pub struct Announce<'a> {
    pub templates: &'a [Template<'a>],
    pub selector: Option<Selector>,
    pub packet_reports: Option<PacketReporting<'a>>,
}

impl Exporter {
    /// Encodes into `out` (cleared first) a message of the announcements
    /// and the longest prefix of `records` (template `data`) that fits in
    /// `max_len` bytes; returns how many records it holds.
    pub fn encode_flows(
        &mut self,
        out: &mut Vec<u8>,
        export_time_s: u32,
        announce: &Announce<'_>,
        data: &Template<'_>,
        records: &[FlowRecord],
        max_len: usize,
    ) -> Result<usize, EncodeError> {
        self.encode(
            out,
            export_time_s,
            announce,
            data.id,
            records,
            max_len,
            |out, r| {
                for &f in data.fields {
                    write_field(out, f, r);
                }
            },
        )
    }

    /// Encodes into `out` (cleared first) a message of the announcements
    /// and the longest prefix of `reports` that fits in `max_len` bytes;
    /// returns how many reports it holds. `template_id` is the one
    /// announced in [`PacketReporting`].
    pub fn encode_packet_reports(
        &mut self,
        out: &mut Vec<u8>,
        export_time_s: u32,
        announce: &Announce<'_>,
        template_id: u16,
        reports: &[PacketReport<'_>],
        max_len: usize,
    ) -> Result<usize, EncodeError> {
        self.encode(
            out,
            export_time_s,
            announce,
            template_id,
            reports,
            max_len,
            |out, p| {
                out.extend_from_slice(&p.selection_sequence_id.to_be_bytes());
                out.extend_from_slice(&p.selector_id.to_be_bytes());
                out.extend_from_slice(&p.observation_ms.to_be_bytes());
                out.extend_from_slice(&p.input_if.to_be_bytes());
                out.extend_from_slice(&p.output_if.to_be_bytes());
                out.extend_from_slice(&DATA_LINK_ETHERNET.to_be_bytes());
                out.extend_from_slice(&p.frame_size.to_be_bytes());
                put_varlen(out, p.frame_section);
            },
        )
    }

    /// Header, announcements, then one data set of as many records as fit.
    /// The limit is capped at the 16-bit message length (RFC 7011 §3.1),
    /// which bounds every set length inside it too.
    #[allow(clippy::too_many_arguments)]
    fn encode<T>(
        &mut self,
        out: &mut Vec<u8>,
        export_time_s: u32,
        announce: &Announce<'_>,
        set_id: u16,
        records: &[T],
        max_len: usize,
        write: impl FnMut(&mut Vec<u8>, &T),
    ) -> Result<usize, EncodeError> {
        let limit = max_len.min(usize::from(u16::MAX));
        let options = self.begin(out, export_time_s, announce);
        if out.len() > limit {
            out.clear();
            return Err(EncodeError::TooLarge);
        }
        let mut n = 0;
        if !records.is_empty() {
            let set = begin_set(out, set_id);
            n = fill(out, limit, records, write);
            if n == 0 {
                out.clear();
                return Err(EncodeError::TooLarge);
            }
            end_set(out, set);
        }
        let len = out.len() as u16;
        put_u16_at(out, 2, len);
        self.sequence = self.sequence.wrapping_add(n as u32 + options);
        Ok(n)
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

        if !a.templates.is_empty() || a.packet_reports.is_some() {
            let set = begin_set(out, SET_TEMPLATE);
            for t in a.templates {
                out.extend_from_slice(&t.id.to_be_bytes());
                out.extend_from_slice(&(t.fields.len() as u16).to_be_bytes());
                for &f in t.fields {
                    let (id, len) = ie_and_len(f);
                    put_spec(out, id, len);
                }
            }
            if let Some(p) = a.packet_reports {
                out.extend_from_slice(&p.template_id.to_be_bytes());
                out.extend_from_slice(&8u16.to_be_bytes());
                put_spec(out, ie::SELECTION_SEQUENCE_ID, 8);
                put_spec(out, ie::SELECTOR_ID, 8);
                put_spec(out, ie::OBSERVATION_TIME_MILLISECONDS, 8);
                put_spec(out, ie::INGRESS_INTERFACE, 4);
                put_spec(out, ie::EGRESS_INTERFACE, 4);
                put_spec(out, ie::DATA_LINK_FRAME_TYPE, 2);
                put_spec(out, ie::DATA_LINK_FRAME_SIZE, 2);
                put_spec(out, ie::DATA_LINK_FRAME_SECTION, VARIABLE_LENGTH);
            }
            end_set(out, set);
        }

        if a.selector.is_some() || a.packet_reports.is_some() {
            let set = begin_set(out, SET_OPTIONS_TEMPLATE);
            if let Some(s) = a.selector {
                // Scope selectorId, then the algorithm and its parameters.
                out.extend_from_slice(&s.template_id.to_be_bytes());
                out.extend_from_slice(&5u16.to_be_bytes()); // field count
                out.extend_from_slice(&1u16.to_be_bytes()); // scope field count
                put_spec(out, ie::SELECTOR_ID, 8);
                put_spec(out, ie::SELECTOR_ALGORITHM, 2);
                put_spec(out, ie::SAMPLING_PACKET_INTERVAL, 4);
                put_spec(out, ie::SAMPLING_PACKET_SPACE, 4);
                put_spec(out, ie::SAMPLING_INTERVAL, 4);
            }
            if let Some(p) = a.packet_reports {
                // Scope selectionSequenceId, then the observation point and
                // the one selector applied there.
                out.extend_from_slice(&p.sequence_template_id.to_be_bytes());
                out.extend_from_slice(&3u16.to_be_bytes()); // field count
                out.extend_from_slice(&1u16.to_be_bytes()); // scope field count
                put_spec(out, ie::SELECTION_SEQUENCE_ID, 8);
                put_spec(out, ie::INGRESS_INTERFACE, 4);
                put_spec(out, ie::SELECTOR_ID, 8);
            }
            end_set(out, set);
        }

        let mut records = 0;
        if let Some(s) = a.selector {
            let set = begin_set(out, s.template_id);
            out.extend_from_slice(&s.selector_id.to_be_bytes());
            out.extend_from_slice(&SELECTOR_SYSTEMATIC_COUNT.to_be_bytes());
            out.extend_from_slice(&1u32.to_be_bytes());
            out.extend_from_slice(&s.interval.saturating_sub(1).to_be_bytes());
            out.extend_from_slice(&s.interval.to_be_bytes());
            end_set(out, set);
            records += 1;
        }
        if let Some(p) = a.packet_reports.filter(|p| !p.sequences.is_empty()) {
            let set = begin_set(out, p.sequence_template_id);
            for q in p.sequences {
                out.extend_from_slice(&q.id.to_be_bytes());
                out.extend_from_slice(&q.ingress_if.to_be_bytes());
                out.extend_from_slice(&q.selector_id.to_be_bytes());
            }
            end_set(out, set);
            records += p.sequences.len() as u32;
        }
        records
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

    fn report(section: &[u8], observation_ms: u64) -> PacketReport<'_> {
        PacketReport {
            selection_sequence_id: 7,
            selector_id: 1,
            observation_ms,
            input_if: 2,
            output_if: 0,
            frame_size: 1500,
            frame_section: section,
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
            packet_reports: None,
        };
        let mut e = Exporter {
            observation_domain_id: 9,
            sequence: 100,
        };
        let mut b = Vec::new();
        let n = e.encode_flows(&mut b, 1_790_000_002, &a, &t, &[record(), record()], 1500);
        assert_eq!(n, Ok(2));

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
    fn packet_reports_with_selection_sequence() {
        let sequences = [SelectionSequence {
            id: 7,
            ingress_if: 2,
            selector_id: 1,
        }];
        let a = Announce {
            templates: &[],
            selector: Some(Selector {
                template_id: 257,
                selector_id: 1,
                interval: 1000,
            }),
            packet_reports: Some(PacketReporting {
                template_id: 300,
                sequence_template_id: 259,
                sequences: &sequences,
            }),
        };
        let mut e = Exporter {
            observation_domain_id: 1,
            sequence: 0,
        };
        let short = [0x11u8; 64];
        let long = [0x22u8; 300];
        let reports = [report(&short, 5), report(&long, 6)];
        let mut b = Vec::new();
        assert_eq!(
            e.encode_packet_reports(&mut b, 1, &a, 300, &reports, 1500),
            Ok(2)
        );
        assert_eq!(e.sequence, 2 + 1 + 1, "reports, selector and sequence");

        let s = sets(&b);
        assert_eq!(
            s.iter().map(|x| x.0).collect::<Vec<_>>(),
            vec![2, 3, 257, 259, 300]
        );

        // Report template: the sequence first, the frame typed as Ethernet.
        let (_, at, _) = s[0];
        assert_eq!(u16_at(&b, at + 4), 300);
        assert_eq!(u16_at(&b, at + 6), 8);
        let spec = |i: usize| (u16_at(&b, at + 8 + 4 * i), u16_at(&b, at + 10 + 4 * i));
        assert_eq!(spec(0), (ie::SELECTION_SEQUENCE_ID, 8));
        assert_eq!(spec(1), (ie::SELECTOR_ID, 8));
        assert_eq!(spec(5), (ie::DATA_LINK_FRAME_TYPE, 2));
        assert_eq!(spec(7), (ie::DATA_LINK_FRAME_SECTION, VARIABLE_LENGTH));

        // Options templates: the selector's, then the sequence's (scope 301).
        let (_, at, _) = s[1];
        let seq_tmpl = at + 4 + 6 + 5 * 4;
        assert_eq!(u16_at(&b, seq_tmpl), 259);
        assert_eq!(u16_at(&b, seq_tmpl + 2), 3);
        assert_eq!(u16_at(&b, seq_tmpl + 4), 1);
        assert_eq!(u16_at(&b, seq_tmpl + 6), ie::SELECTION_SEQUENCE_ID);
        assert_eq!(u16_at(&b, seq_tmpl + 10), ie::INGRESS_INTERFACE);
        assert_eq!(u16_at(&b, seq_tmpl + 14), ie::SELECTOR_ID);

        // Sequence record: id 7 observed on ifIndex 2 by selector 1.
        let (_, at, _) = s[3];
        assert_eq!(u64_at(&b, at + 4), 7);
        assert_eq!(u32_at(&b, at + 12), 2);
        assert_eq!(u64_at(&b, at + 16), 1);

        // Fixed part is 8 + 8 + 8 + 4 + 4 + 2 + 2 = 36 bytes, then the section.
        let (_, at, _) = s[4];
        let r0 = at + 4;
        assert_eq!(u64_at(&b, r0), 7);
        assert_eq!(u64_at(&b, r0 + 8), 1);
        assert_eq!(u64_at(&b, r0 + 16), 5);
        assert_eq!(u16_at(&b, r0 + 32), DATA_LINK_ETHERNET);
        assert_eq!(u16_at(&b, r0 + 34), 1500);
        assert_eq!(b[r0 + 36], 64, "one-byte length");
        let r1 = r0 + 36 + 1 + 64;
        assert_eq!(u64_at(&b, r1 + 16), 6);
        assert_eq!(b[r1 + 36], 255, "three-byte length marker");
        assert_eq!(u16_at(&b, r1 + 37), 300);
        assert_eq!(b[r1 + 39], 0x22);
    }

    #[test]
    fn length_limit_takes_a_prefix_and_keeps_the_sequence() {
        let section = [0u8; 128];
        let reports = [report(&section, 1); 20];
        let mut e = Exporter {
            observation_domain_id: 1,
            sequence: 0,
        };
        let mut b = Vec::new();
        // Header 16, set header 4, each report 36 + 1 + 128 = 165.
        let none = Announce::default();
        assert_eq!(
            e.encode_packet_reports(&mut b, 1, &none, 300, &reports, 1472),
            Ok(8)
        );
        assert_eq!(b.len(), (16 + 4 + 8 * 165usize).next_multiple_of(4));
        assert_eq!(e.sequence, 8);

        // Too small for one report: nothing encoded, sequence untouched.
        assert_eq!(
            e.encode_packet_reports(&mut b, 1, &none, 300, &reports, 16 + 4 + 164),
            Err(EncodeError::TooLarge)
        );
        assert!(b.is_empty());
        assert_eq!(e.sequence, 8);

        // A limit beyond the 16-bit message length is capped to it.
        let huge = [0u8; 70_000];
        let big = [report(&huge, 1)];
        assert_eq!(
            e.encode_packet_reports(&mut b, 1, &none, 300, &big, usize::MAX),
            Err(EncodeError::TooLarge)
        );
        let fields = flow_fields(Family::V6, Profile::Full, SamplingSignal::InRecord);
        let t = Template {
            id: 256,
            fields: &fields,
        };
        let many = vec![record(); 1000];
        let n = e
            .encode_flows(&mut b, 1, &none, &t, &many, usize::MAX)
            .unwrap();
        assert!(n < many.len());
        assert!(b.len() <= usize::from(u16::MAX));
        assert_eq!(usize::from(u16_at(&b, 2)), b.len());
        sets(&b);

        // Announcements alone over the limit.
        let a = Announce {
            templates: std::slice::from_ref(&t),
            ..Announce::default()
        };
        assert_eq!(
            e.encode_flows(&mut b, 1, &a, &t, &[], 40),
            Err(EncodeError::TooLarge)
        );
        assert_eq!(
            e.encode_flows(&mut b, 1, &a, &t, &[], 1500)
                .map(|_| sets(&b).len()),
            Ok(1)
        );
    }
}
