//! NetFlow version 9 export packets (RFC 3954).
//!
//! An export packet is a header followed by FlowSets: template FlowSets
//! (id 0), options template FlowSets (id 1) and data FlowSets (id = the
//! template id they follow). Times in v9 records are milliseconds of the
//! exporter's uptime (`sysUptime`), so [`Exporter`] converts the epoch
//! times a [`FlowRecord`] carries.

use crate::{fill, pad4, put_u16_at, v4, v6, EncodeError, Field, FlowRecord};

/// NetFlow v9 field types used here (RFC 3954 §8).
mod ty {
    pub const IN_BYTES: u16 = 1;
    pub const IN_PKTS: u16 = 2;
    pub const PROTOCOL: u16 = 4;
    pub const L4_SRC_PORT: u16 = 7;
    pub const IPV4_SRC_ADDR: u16 = 8;
    pub const INPUT_SNMP: u16 = 10;
    pub const L4_DST_PORT: u16 = 11;
    pub const IPV4_DST_ADDR: u16 = 12;
    pub const OUTPUT_SNMP: u16 = 14;
    pub const SRC_AS: u16 = 16;
    pub const DST_AS: u16 = 17;
    pub const LAST_SWITCHED: u16 = 21;
    pub const FIRST_SWITCHED: u16 = 22;
    pub const IPV6_SRC_ADDR: u16 = 27;
    pub const IPV6_DST_ADDR: u16 = 28;
    pub const SAMPLING_INTERVAL: u16 = 34;
    pub const SAMPLING_ALGORITHM: u16 = 35;
}

/// Options-template scope type: the whole exporting system.
const SCOPE_SYSTEM: u16 = 1;
/// `SAMPLING_ALGORITHM` value for random sampling.
const SAMPLING_RANDOM: u8 = 2;

fn type_and_len(f: Field) -> (u16, u16) {
    match f {
        Field::Octets => (ty::IN_BYTES, 8),
        Field::Packets => (ty::IN_PKTS, 8),
        Field::Protocol => (ty::PROTOCOL, 1),
        Field::SrcPort => (ty::L4_SRC_PORT, 2),
        Field::DstPort => (ty::L4_DST_PORT, 2),
        Field::SrcIpv4 => (ty::IPV4_SRC_ADDR, 4),
        Field::DstIpv4 => (ty::IPV4_DST_ADDR, 4),
        Field::SrcIpv6 => (ty::IPV6_SRC_ADDR, 16),
        Field::DstIpv6 => (ty::IPV6_DST_ADDR, 16),
        Field::InputIf => (ty::INPUT_SNMP, 4),
        Field::OutputIf => (ty::OUTPUT_SNMP, 4),
        Field::SrcAs => (ty::SRC_AS, 4),
        Field::DstAs => (ty::DST_AS, 4),
        Field::Start => (ty::FIRST_SWITCHED, 4),
        Field::End => (ty::LAST_SWITCHED, 4),
        Field::SamplingInterval => (ty::SAMPLING_INTERVAL, 4),
    }
}

/// One exporter's v9 state: identity, packet sequence and clock origin.
#[derive(Debug, Clone)]
pub struct Exporter {
    /// Identifies this exporter's observation domain to the collector.
    pub source_id: u32,
    /// Export packets sent so far (RFC 3954 §5.1: incremented per packet).
    pub sequence: u32,
    /// Unix epoch milliseconds at which `sysUptime` was zero.
    pub boot_epoch_ms: u64,
}

/// A template FlowSet's content: a template id and its fields.
#[derive(Debug, Clone)]
pub struct Template<'a> {
    pub id: u16,
    pub fields: &'a [Field],
}

/// An options template and record announcing the exporter's sampler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SamplerOptions {
    pub template_id: u16,
    pub interval: u32,
}

impl Exporter {
    fn uptime(&self, epoch_ms: u64) -> u32 {
        epoch_ms.saturating_sub(self.boot_epoch_ms) as u32
    }

    /// Encodes into `out` (cleared first) an export packet of the
    /// announcements and the longest prefix of `records` (template `data`)
    /// that fits in `max_len` bytes, and advances [`Self::sequence`];
    /// returns how many records it holds. The limit is capped at the
    /// 16-bit FlowSet length.
    ///
    /// `templates` and `sampler` are (re)announced in this packet when
    /// given; v9 has no reliable transport, so exporters resend them
    /// periodically.
    #[allow(clippy::too_many_arguments)]
    pub fn encode(
        &mut self,
        out: &mut Vec<u8>,
        now_epoch_ms: u64,
        templates: &[Template<'_>],
        sampler: Option<SamplerOptions>,
        data: &Template<'_>,
        records: &[FlowRecord],
        max_len: usize,
    ) -> Result<usize, EncodeError> {
        let limit = max_len.min(usize::from(u16::MAX));
        out.clear();
        out.extend_from_slice(&9u16.to_be_bytes());
        let count_at = out.len();
        out.extend_from_slice(&0u16.to_be_bytes()); // record count, backfilled
        out.extend_from_slice(&self.uptime(now_epoch_ms).to_be_bytes());
        out.extend_from_slice(&((now_epoch_ms / 1000) as u32).to_be_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.source_id.to_be_bytes());
        let mut count = 0;

        if !templates.is_empty() {
            let set = begin_set(out, 0);
            for t in templates {
                out.extend_from_slice(&t.id.to_be_bytes());
                out.extend_from_slice(&(t.fields.len() as u16).to_be_bytes());
                for &f in t.fields {
                    let (ty, len) = type_and_len(f);
                    out.extend_from_slice(&ty.to_be_bytes());
                    out.extend_from_slice(&len.to_be_bytes());
                }
                count += 1;
            }
            end_set(out, set);
        }

        if let Some(s) = sampler {
            // Options template: scope System (4 bytes), then interval and
            // algorithm (RFC 3954 §6.1).
            let set = begin_set(out, 1);
            out.extend_from_slice(&s.template_id.to_be_bytes());
            out.extend_from_slice(&4u16.to_be_bytes()); // scope length, bytes
            out.extend_from_slice(&8u16.to_be_bytes()); // option length, bytes
            for (ty, len) in [
                (SCOPE_SYSTEM, 4u16),
                (ty::SAMPLING_INTERVAL, 4),
                (ty::SAMPLING_ALGORITHM, 1),
            ] {
                out.extend_from_slice(&ty.to_be_bytes());
                out.extend_from_slice(&len.to_be_bytes());
            }
            end_set(out, set);
            count += 1;

            let set = begin_set(out, s.template_id);
            out.extend_from_slice(&0u32.to_be_bytes()); // scope: system 0
            out.extend_from_slice(&s.interval.to_be_bytes());
            out.push(SAMPLING_RANDOM);
            end_set(out, set);
            count += 1;
        }
        if out.len() > limit {
            out.clear();
            return Err(EncodeError::TooLarge);
        }

        let mut n = 0;
        if !records.is_empty() {
            let set = begin_set(out, data.id);
            n = fill(out, limit, records, |out, r| {
                for &f in data.fields {
                    self.write_field(out, f, r);
                }
            });
            if n == 0 {
                out.clear();
                return Err(EncodeError::TooLarge);
            }
            end_set(out, set);
        }

        put_u16_at(out, count_at, (count + n) as u16);
        self.sequence = self.sequence.wrapping_add(1);
        Ok(n)
    }

    fn write_field(&self, out: &mut Vec<u8>, f: Field, r: &FlowRecord) {
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
            Field::Start => out.extend_from_slice(&self.uptime(r.start_ms).to_be_bytes()),
            Field::End => out.extend_from_slice(&self.uptime(r.end_ms).to_be_bytes()),
            Field::SamplingInterval => out.extend_from_slice(&r.sampling_interval.to_be_bytes()),
        }
    }
}

fn begin_set(out: &mut Vec<u8>, id: u16) -> usize {
    let at = out.len();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // length, backfilled
    at
}

fn end_set(out: &mut Vec<u8>, at: usize) {
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

    fn record() -> FlowRecord {
        FlowRecord {
            src: "203.0.113.7".parse().unwrap(),
            dst: "198.51.100.10".parse().unwrap(),
            protocol: 17,
            src_port: 4444,
            dst_port: 53,
            input_if: 3,
            output_if: 0,
            src_as: 64500,
            dst_as: 64501,
            packets: 5,
            octets: 320,
            start_ms: 1_000_500,
            end_ms: 1_001_000,
            sampling_interval: 1000,
        }
    }

    /// Walks the FlowSets, checking lengths tile the packet exactly.
    fn sets(b: &[u8]) -> Vec<(u16, usize, usize)> {
        let mut at = 20;
        let mut v = Vec::new();
        while at < b.len() {
            let id = u16_at(b, at);
            let len = u16_at(b, at + 2) as usize;
            assert!(len >= 4 && len.is_multiple_of(4), "set {id} length {len}");
            v.push((id, at, len));
            at += len;
        }
        assert_eq!(at, b.len());
        v
    }

    #[test]
    fn template_options_and_data() {
        let fields = flow_fields(Family::V4, Profile::Full, SamplingSignal::InRecord);
        let t = Template {
            id: 256,
            fields: &fields,
        };
        let mut e = Exporter {
            source_id: 7,
            sequence: 41,
            boot_epoch_ms: 1_000_000,
        };
        let mut b = Vec::new();
        let opts = SamplerOptions {
            template_id: 257,
            interval: 1000,
        };
        let n = e.encode(
            &mut b,
            1_002_000,
            std::slice::from_ref(&t),
            Some(opts),
            &t,
            &[record(), record()],
            1500,
        );
        assert_eq!(n, Ok(2));

        assert_eq!(u16_at(&b, 0), 9);
        assert_eq!(
            u16_at(&b, 2),
            1 + 2 + 2,
            "template + options pair + 2 records"
        );
        assert_eq!(u32_at(&b, 4), 2000, "uptime");
        assert_eq!(u32_at(&b, 8), 1002, "unix secs");
        assert_eq!(u32_at(&b, 12), 41);
        assert_eq!(u32_at(&b, 16), 7);
        assert_eq!(e.sequence, 42);

        let s = sets(&b);
        assert_eq!(
            s.iter().map(|x| x.0).collect::<Vec<_>>(),
            vec![0, 1, 257, 256]
        );

        // Template: id, count, then (type, len) pairs.
        let (_, at, _) = s[0];
        assert_eq!(u16_at(&b, at + 4), 256);
        assert_eq!(u16_at(&b, at + 6) as usize, fields.len());
        assert_eq!(u16_at(&b, at + 8), ty::IN_BYTES);
        assert_eq!(u16_at(&b, at + 10), 8);

        // Options data: scope 0, interval, algorithm.
        let (_, at, _) = s[2];
        assert_eq!(u32_at(&b, at + 4), 0);
        assert_eq!(u32_at(&b, at + 8), 1000);
        assert_eq!(b[at + 12], SAMPLING_RANDOM);

        // Data: two records of the template's total width, then padding.
        let width: usize = fields.iter().map(|&f| type_and_len(f).1 as usize).sum();
        let (_, at, len) = s[3];
        assert_eq!(len, (4 + 2 * width).div_ceil(4) * 4);
        let r = at + 4;
        assert_eq!(u64::from_be_bytes(b[r..r + 8].try_into().unwrap()), 320);
        assert_eq!(u64::from_be_bytes(b[r + 8..r + 16].try_into().unwrap()), 5);
        assert_eq!(b[r + 16], 17);
        assert_eq!(&b[r + 17..r + 21], &[203, 0, 113, 7]);
        assert_eq!(&b[r + 21..r + 25], &[198, 51, 100, 10]);
        // First/last switched are uptime-relative; sampling interval last.
        let tail = r + width;
        assert_eq!(u32_at(&b, tail - 4), 1000);
        assert_eq!(u32_at(&b, tail - 8), 1000, "end = 1_001_000 - boot");
        assert_eq!(u32_at(&b, tail - 12), 500, "start = 1_000_500 - boot");
    }

    #[test]
    fn data_only_packet() {
        let fields = flow_fields(Family::V6, Profile::AsOnly, SamplingSignal::Options);
        let t = Template {
            id: 300,
            fields: &fields,
        };
        let mut e = Exporter {
            source_id: 1,
            sequence: u32::MAX,
            boot_epoch_ms: 0,
        };
        let mut b = Vec::new();
        assert_eq!(
            e.encode(&mut b, 5000, &[], None, &t, &[record()], 1500),
            Ok(1)
        );
        assert_eq!(u16_at(&b, 2), 1);
        assert_eq!(e.sequence, 0, "wraps");
        let s = sets(&b);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].0, 300);
    }

    #[test]
    fn length_limit_takes_a_prefix() {
        let fields = flow_fields(Family::V4, Profile::Full, SamplingSignal::InRecord);
        let t = Template {
            id: 256,
            fields: &fields,
        };
        let width: usize = fields.iter().map(|&f| type_and_len(f).1 as usize).sum();
        let mut e = Exporter {
            source_id: 1,
            sequence: 0,
            boot_epoch_ms: 0,
        };
        let mut b = Vec::new();
        let many = vec![record(); 100];
        let fit = (1472 - 20 - 4) / width;
        assert_eq!(e.encode(&mut b, 0, &[], None, &t, &many, 1472), Ok(fit));
        assert_eq!(u16_at(&b, 2) as usize, fit);
        assert!(b.len() <= 1472);
        sets(&b);
        assert_eq!(e.sequence, 1);

        // Too small for one record: nothing encoded, sequence untouched.
        assert_eq!(
            e.encode(&mut b, 0, &[], None, &t, &many, 20 + 4 + width - 1),
            Err(EncodeError::TooLarge)
        );
        assert!(b.is_empty());
        assert_eq!(e.sequence, 1);

        // The FlowSet length caps a limit beyond it.
        let lots = vec![record(); 2000];
        let n = e
            .encode(&mut b, 0, &[], None, &t, &lots, usize::MAX)
            .unwrap();
        assert_eq!(n, (usize::from(u16::MAX) - 20 - 4) / width);
        sets(&b);
    }
}
