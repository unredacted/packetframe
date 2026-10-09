//! IPFIX flow records (RFC 7011) for the collectors that take them: one
//! exporting process per observation domain, which announces its
//! templates and its selector options record (the domain's rate,
//! docs/flow-export/collectors.md requirement 1) with its first records,
//! every [`ANNOUNCE_EVERY`] after, and with the first records after a
//! rate change.
//!
//! Every IPFIX collector is sent the same messages: their sequence
//! numbers are the domain's, not a collector's.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use packetframe_flow_encode::ipfix::{Announce, Exporter, Selector, Template};
use packetframe_flow_encode::{
    flow_fields, EncodeError, Family, Field, FlowRecord, Profile, SamplingSignal,
};

use crate::flows::{Domain, Export, FlowCache};
use crate::sflow_out::MAX_DATAGRAM;

pub const TEMPLATE_V4: u16 = 256;
pub const TEMPLATE_V6: u16 = 257;
pub const SELECTOR_TEMPLATE: u16 = 258;
/// Templates and the selector, again at least this often while records
/// flow: a collector that restarted learns them within it
/// (requirement 3).
pub const ANNOUNCE_EVERY: Duration = Duration::from_secs(10);
/// Records taken from the cache per tick, across domains: about what the
/// send budget carries.
pub const RECORDS_PER_TICK: usize = 8192;

struct DomainOut {
    exporter: Exporter,
    /// The rate the domain's records are counted at, as last announced
    /// or about to be.
    rate: u32,
    /// When the next announcement is due; `None` makes it due now.
    next_announce: Option<Instant>,
}

pub struct IpfixOut {
    v4: Vec<Field>,
    v6: Vec<Field>,
    domains: BTreeMap<Domain, DomainOut>,
    pub announcements: u64,
    pub records: u64,
    /// Records no message could hold (none, at these sizes).
    pub unencodable: u64,
}

impl Default for IpfixOut {
    fn default() -> Self {
        Self::new()
    }
}

impl IpfixOut {
    pub fn new() -> Self {
        Self {
            v4: flow_fields(Family::V4, Profile::Full, SamplingSignal::Options),
            v6: flow_fields(Family::V6, Profile::Full, SamplingSignal::Options),
            domains: BTreeMap::new(),
            announcements: 0,
            records: 0,
            unencodable: 0,
        }
    }

    /// Announce with every domain's next message: a collector was added
    /// and has seen no templates.
    pub fn reannounce(&mut self) {
        for d in self.domains.values_mut() {
            d.next_announce = None;
        }
    }

    /// Messages for what the cache has ready, appended to `out`, at most
    /// [`RECORDS_PER_TICK`] records.
    pub fn encode(
        &mut self,
        cache: &mut FlowCache,
        now: Instant,
        export_s: u32,
        out: &mut Vec<Vec<u8>>,
    ) {
        self.encode_up_to(cache, now, export_s, out, RECORDS_PER_TICK);
    }

    /// [`Self::encode`], up to `left` records.
    pub fn encode_up_to(
        &mut self,
        cache: &mut FlowCache,
        now: Instant,
        export_s: u32,
        out: &mut Vec<Vec<u8>>,
        mut left: usize,
    ) {
        for domain in cache.pending() {
            if left == 0 {
                break;
            }
            let items = cache.take(domain, left);
            left -= items.len();
            self.domains.entry(domain).or_insert_with(|| DomainOut {
                exporter: Exporter {
                    observation_domain_id: domain.id(),
                    sequence: 0,
                },
                rate: 0,
                next_announce: None,
            });
            let (mut v4, mut v6) = (Vec::new(), Vec::new());
            for item in items {
                match item {
                    Export::Record(r) if r.src.is_ipv4() => v4.push(r),
                    Export::Record(r) => v6.push(r),
                    // What was counted at the old rate goes first, then
                    // the new rate with the next records.
                    Export::Rate(rate) => {
                        self.flush(domain, &mut v4, &mut v6, now, export_s, out);
                        let d = self.domains.get_mut(&domain).expect("inserted above");
                        d.rate = rate;
                        d.next_announce = None;
                    }
                }
            }
            self.flush(domain, &mut v4, &mut v6, now, export_s, out);
        }
    }

    fn flush(
        &mut self,
        domain: Domain,
        v4: &mut Vec<FlowRecord>,
        v6: &mut Vec<FlowRecord>,
        now: Instant,
        export_s: u32,
        out: &mut Vec<Vec<u8>>,
    ) {
        if v4.is_empty() && v6.is_empty() {
            return;
        }
        let Some(d) = self.domains.get_mut(&domain) else {
            return;
        };
        let templates = [
            Template {
                id: TEMPLATE_V4,
                fields: &self.v4,
            },
            Template {
                id: TEMPLATE_V6,
                fields: &self.v6,
            },
        ];
        let mut announce = d.next_announce.is_none_or(|t| now >= t);
        for (template, records) in [(&templates[0], &mut *v4), (&templates[1], &mut *v6)] {
            let mut rest = &records[..];
            while !rest.is_empty() {
                let a = if announce {
                    Announce {
                        templates: &templates,
                        selector: Some(Selector {
                            template_id: SELECTOR_TEMPLATE,
                            selector_id: u64::from(domain.id()),
                            interval: d.rate,
                        }),
                        packet_reports: None,
                    }
                } else {
                    Announce::default()
                };
                let mut buf = Vec::with_capacity(MAX_DATAGRAM);
                match d
                    .exporter
                    .encode_flows(&mut buf, export_s, &a, template, rest, MAX_DATAGRAM)
                {
                    Ok(n) => {
                        if announce {
                            announce = false;
                            self.announcements += 1;
                            d.next_announce = Some(now + ANNOUNCE_EVERY);
                        }
                        self.records += n as u64;
                        rest = &rest[n..];
                        out.push(buf);
                    }
                    // The announcement and a record do not fit together:
                    // the announcement goes alone, then the records.
                    Err(EncodeError::TooLarge) if announce => {
                        let mut alone = Vec::with_capacity(MAX_DATAGRAM);
                        if d.exporter
                            .encode_flows(&mut alone, export_s, &a, template, &[], MAX_DATAGRAM)
                            .is_ok()
                        {
                            out.push(alone);
                            self.announcements += 1;
                            d.next_announce = Some(now + ANNOUNCE_EVERY);
                        }
                        announce = false;
                    }
                    // One record larger than a message: not at these sizes,
                    // but never a loop.
                    Err(_) => {
                        self.unencodable += 1;
                        rest = &rest[1..];
                    }
                }
            }
        }
        v4.clear();
        v6.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flows::{Limits, Now, Packet, Sampled};
    use std::net::IpAddr;

    fn sampled(dst: &str, dport: u16, rate: u32, generation: u64) -> Sampled {
        Sampled {
            packet: Packet {
                src: if dst.contains(':') {
                    "2001:db8::1".parse().unwrap()
                } else {
                    "192.0.2.1".parse().unwrap()
                },
                dst: dst.parse::<IpAddr>().unwrap(),
                protocol: 6,
                src_port: 40000,
                dst_port: dport,
                ip_len: 986,
            },
            generation,
            rate,
            input_if: 3,
            output_if: 5,
        }
    }

    fn word16(d: &[u8], at: usize) -> u16 {
        u16::from_be_bytes([d[at], d[at + 1]])
    }

    fn word32(d: &[u8], at: usize) -> u32 {
        u32::from_be_bytes(d[at..at + 4].try_into().unwrap())
    }

    /// The set ids of a message, in order, and the selector's interval if
    /// it carries one.
    fn sets(d: &[u8]) -> (Vec<u16>, Option<u32>) {
        assert_eq!(word16(d, 0), 10, "IPFIX");
        assert_eq!(usize::from(word16(d, 2)), d.len(), "length");
        let mut at = 16;
        let (mut ids, mut interval) = (Vec::new(), None);
        while at < d.len() {
            let (id, len) = (word16(d, at), usize::from(word16(d, at + 2)));
            if id == SELECTOR_TEMPLATE {
                // selectorId (8), algorithm (2), interval (4), space (4),
                // samplingInterval (4).
                interval = Some(word32(d, at + 4 + 8 + 2 + 4 + 4));
            }
            ids.push(id);
            at += len;
        }
        (ids, interval)
    }

    fn at(ms: u64) -> Now {
        Now {
            ms,
            wall_ms: 1_790_000_000_000 + ms,
        }
    }

    #[test]
    fn records_go_with_the_templates_and_the_domains_rate() {
        let mut cache = FlowCache::new(Limits::default());
        let mut x = IpfixOut::new();
        let t0 = Instant::now();
        cache.ingest(
            Domain::FastPath,
            &[
                sampled("198.51.100.2", 443, 1000, 1),
                sampled("2001:db8::2", 443, 1000, 1),
            ],
            at(0),
        );
        cache.expire(at(15_000), 100);
        let mut out = Vec::new();
        x.encode(&mut cache, t0, 1_790_000_015, &mut out);
        assert_eq!(out.len(), 2, "one message per family");
        let (ids, interval) = sets(&out[0]);
        assert_eq!(ids, vec![2, 3, SELECTOR_TEMPLATE, TEMPLATE_V4]);
        assert_eq!(interval, Some(1000));
        assert_eq!(word32(&out[0], 12), Domain::FastPath.id(), "domain");
        let (ids, _) = sets(&out[1]);
        assert_eq!(ids, vec![TEMPLATE_V6], "announced once");
        // Sequence: the selector record and the v4 record went before.
        assert_eq!(word32(&out[1], 8), 2);
        assert_eq!((x.records, x.announcements), (2, 1));
    }

    #[test]
    fn a_rate_change_is_announced_after_the_old_rates_records() {
        let mut cache = FlowCache::new(Limits::default());
        let mut x = IpfixOut::new();
        let t0 = Instant::now();
        cache.ingest(Domain::Vpp, &[sampled("198.51.100.2", 1, 1000, 1)], at(0));
        cache.ingest(Domain::Vpp, &[sampled("198.51.100.2", 2, 100, 2)], at(100));
        cache.expire(at(15_100), 100);
        let mut out = Vec::new();
        x.encode(&mut cache, t0, 0, &mut out);
        let seen: Vec<(Vec<u16>, Option<u32>)> = out.iter().map(|d| sets(d)).collect();
        assert_eq!(seen[0].1, Some(1000), "{seen:?}");
        assert_eq!(
            seen[1].1,
            Some(100),
            "the new rate before its records: {seen:?}"
        );
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn templates_come_back_every_ten_seconds_and_for_a_new_collector() {
        let mut cache = FlowCache::new(Limits::default());
        let mut x = IpfixOut::new();
        let t0 = Instant::now();
        let mut tick = |x: &mut IpfixOut, ms: u64, port: u16| {
            cache.ingest(
                Domain::FastPath,
                &[sampled("198.51.100.2", port, 1000, 1)],
                at(ms),
            );
            cache.expire(at(ms + 15_000), 100);
            let mut out = Vec::new();
            x.encode(&mut cache, t0 + Duration::from_millis(ms), 0, &mut out);
            sets(&out[0]).0.contains(&2)
        };
        assert!(tick(&mut x, 0, 1));
        assert!(!tick(&mut x, 5_000, 2));
        assert!(tick(&mut x, 10_000, 3));
        assert!(!tick(&mut x, 11_000, 4));
        x.reannounce();
        assert!(tick(&mut x, 12_000, 5));
    }

    #[test]
    fn many_records_fill_messages_of_at_most_the_limit() {
        let mut cache = FlowCache::new(Limits::default());
        let mut x = IpfixOut::new();
        let batch: Vec<Sampled> = (0..500)
            .map(|p| sampled("198.51.100.2", p, 1000, 1))
            .collect();
        cache.ingest(Domain::FastPath, &batch, at(0));
        cache.expire(at(15_000), 1000);
        let mut out = Vec::new();
        x.encode(&mut cache, Instant::now(), 0, &mut out);
        assert!(out.len() > 1);
        assert!(out.iter().all(|d| d.len() <= MAX_DATAGRAM));
        assert_eq!(x.records, 500);
    }
}
