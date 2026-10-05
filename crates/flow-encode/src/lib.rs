//! Wire encoders for the flow-telemetry formats PacketFrame exports.
//!
//! - [`sflow`]: sFlow version 5 datagrams of flow samples carrying raw packet
//!   headers (sflow.org, "sFlow Version 5").
//! - [`netflow9`]: NetFlow v9 export packets (RFC 3954) of flow records.
//! - [`ipfix`]: IPFIX messages (RFC 7011) of flow records, and of PSAMP packet
//!   reports (RFC 5476, information elements from RFC 5477).
//!
//! Pure encoding: no sockets, no clocks, no aggregation. Callers own sequence
//! numbers, timestamps and template refresh, because those are export-process
//! state that the formats define per exporter, not per message.
//!
//! Every encoder takes a length limit and encodes the longest prefix of its
//! records that fits, returning how many it took; the caller sends the
//! message and passes the rest to the next one. The limit is the caller's
//! (a datagram that fits the path MTU), further capped by the format's own
//! 16-bit length fields, so an encoded message is never malformed by size.
//!
//! NetFlow v9 and IPFIX share one field model ([`Field`], [`FlowRecord`]):
//! a template is a list of fields, and a record is written field by field in
//! template order, so a privacy profile is just a shorter field list.

#![forbid(unsafe_code)]

pub mod ipfix;
pub mod netflow9;
pub mod sflow;

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Why nothing was encoded. The output buffer is left empty and no
/// sequence number advanced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The header and announcements, or the first record after them, do
    /// not fit the length limit.
    TooLarge,
    /// An sFlow compact sample cannot carry an ifIndex of 2^24 or more; the
    /// agent must use [`sflow::Encoding::Expanded`] for all its samples.
    IfIndexRange(u32),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("message exceeds the length limit"),
            Self::IfIndexRange(i) => write!(f, "ifIndex {i} needs the expanded sFlow encoding"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// One flow, as aggregated from sampled packets.
///
/// Counts are *sampled* counts, not scaled by the sampling rate: the export
/// carries the rate (in the record or an options record) and the collector
/// scales, exactly once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRecord {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// ifIndex the packets arrived on.
    pub input_if: u32,
    /// ifIndex they left by; 0 when unknown (e.g. sampled at ingress).
    pub output_if: u32,
    /// Origin AS of the source address, 0 when unknown.
    pub src_as: u32,
    /// Origin AS of the destination address, 0 when unknown.
    pub dst_as: u32,
    pub packets: u64,
    pub octets: u64,
    /// First packet, Unix epoch milliseconds.
    pub start_ms: u64,
    /// Last packet, Unix epoch milliseconds.
    pub end_ms: u64,
    /// The 1-in-N packet sampling rate the counts were taken at.
    pub sampling_interval: u32,
}

/// A field of a flow-record template, independent of the format.
///
/// Each maps to a NetFlow v9 field type and an IPFIX information element
/// with the same meaning; times differ in representation (see
/// [`netflow9::Exporter`] for v9's uptime-relative times).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Octets,
    Packets,
    Protocol,
    SrcPort,
    DstPort,
    SrcIpv4,
    DstIpv4,
    SrcIpv6,
    DstIpv6,
    InputIf,
    OutputIf,
    SrcAs,
    DstAs,
    Start,
    End,
    SamplingInterval,
}

/// The source address family a template carries, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

/// What a template carries about the remote and local parties.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Source and destination addresses, ports and AS numbers.
    Full,
    /// As `Full` without the source address.
    NoSource,
    /// No addresses at all: AS numbers, ports and protocol only.
    AsOnly,
}

/// Where the sampling rate travels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingSignal {
    /// A sampling-interval field in every flow record.
    InRecord,
    /// An options record describing the exporter's sampler, sent alongside
    /// the templates; flow records carry none.
    Options,
}

/// The flow-record template for a family, profile and sampling signal.
pub fn flow_fields(family: Family, profile: Profile, sampling: SamplingSignal) -> Vec<Field> {
    let (src, dst) = match family {
        Family::V4 => (Field::SrcIpv4, Field::DstIpv4),
        Family::V6 => (Field::SrcIpv6, Field::DstIpv6),
    };
    let mut f = vec![Field::Octets, Field::Packets, Field::Protocol];
    match profile {
        Profile::Full => f.extend([src, dst]),
        Profile::NoSource => f.push(dst),
        Profile::AsOnly => {}
    }
    f.extend([
        Field::SrcPort,
        Field::DstPort,
        Field::InputIf,
        Field::OutputIf,
        Field::SrcAs,
        Field::DstAs,
        Field::Start,
        Field::End,
    ]);
    if sampling == SamplingSignal::InRecord {
        f.push(Field::SamplingInterval);
    }
    f
}

fn v4(a: IpAddr) -> Ipv4Addr {
    match a {
        IpAddr::V4(a) => a,
        IpAddr::V6(a) => a.to_ipv4_mapped().unwrap_or(Ipv4Addr::UNSPECIFIED),
    }
}

fn v6(a: IpAddr) -> Ipv6Addr {
    match a {
        IpAddr::V4(a) => a.to_ipv6_mapped(),
        IpAddr::V6(a) => a,
    }
}

/// Pads `out` with zero bytes to a multiple of four, as XDR and the
/// NetFlow v9 / IPFIX set padding rules require.
fn pad4(out: &mut Vec<u8>) {
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// Appends records with `write` while the message, padded to four bytes,
/// stays within `limit`; returns how many were appended. A record that
/// would cross the limit is removed again and ends the fill.
fn fill<T>(
    out: &mut Vec<u8>,
    limit: usize,
    records: &[T],
    mut write: impl FnMut(&mut Vec<u8>, &T),
) -> usize {
    let mut n = 0;
    for r in records {
        let mark = out.len();
        write(out, r);
        if out.len().next_multiple_of(4) > limit {
            out.truncate(mark);
            break;
        }
        n += 1;
    }
    n
}

/// Backfills a big-endian u16 at `at`.
fn put_u16_at(out: &mut [u8], at: usize, v: u16) {
    out[at..at + 2].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_drop_the_right_addresses() {
        let full = flow_fields(Family::V4, Profile::Full, SamplingSignal::InRecord);
        assert!(full.contains(&Field::SrcIpv4) && full.contains(&Field::DstIpv4));
        assert_eq!(full.last(), Some(&Field::SamplingInterval));

        let nosrc = flow_fields(Family::V4, Profile::NoSource, SamplingSignal::Options);
        assert!(!nosrc.contains(&Field::SrcIpv4) && nosrc.contains(&Field::DstIpv4));
        assert!(!nosrc.contains(&Field::SamplingInterval));

        let asonly = flow_fields(Family::V6, Profile::AsOnly, SamplingSignal::InRecord);
        assert!(!asonly.iter().any(|f| matches!(
            f,
            Field::SrcIpv4 | Field::DstIpv4 | Field::SrcIpv6 | Field::DstIpv6
        )));
        assert!(asonly.contains(&Field::SrcAs) && asonly.contains(&Field::DstAs));
    }
}
