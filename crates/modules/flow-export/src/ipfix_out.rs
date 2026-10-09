//! IPFIX flow records (RFC 7011) for the collectors that take them: one
//! exporting process per privacy profile and observation domain, which
//! announces its templates and its selector options record (the domain's
//! rate, docs/flow-export/collectors.md requirement 1) with its first
//! records, every [`ANNOUNCE_EVERY`] after, and with the first records
//! after a rate change.
//!
//! The collectors of one profile are sent the same messages: their
//! sequence numbers are the profile's domain's, not a collector's.
//!
//! **Profiles.** *Local* is inside the local prefixes. `full` sends
//! addresses as observed; `truncate` cuts each address that is not local
//! to its /24 or /48; `no-remote` sends only local addresses, through the
//! template that leaves the others out; `as-only` sends no address at
//! all. A record carries its addresses' origin ASes whatever the profile,
//! looked up before any truncation.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use packetframe_common::config::CollectorProfile;
use packetframe_common::fib::asn::AsnTable;
use packetframe_common::fib::IpPrefix;
use packetframe_flow_encode::ipfix::{Announce, Exporter, Selector, Template};
use packetframe_flow_encode::{
    flow_fields, EncodeError, Family, Field, FlowRecord, Profile, SamplingSignal,
};

use crate::flows::{Domain, Export};
use crate::sflow_out::MAX_DATAGRAM;

pub const SELECTOR_TEMPLATE: u16 = 258;
/// Templates and the selector, again at least this often while records
/// flow: a collector that restarted learns them within it
/// (requirement 3).
pub const ANNOUNCE_EVERY: Duration = Duration::from_secs(10);
/// Records taken from the cache per tick, across domains: about what the
/// send budget carries.
pub const RECORDS_PER_TICK: usize = 8192;

/// Every template a profile can use, and its id.
const TEMPLATES: [(u16, Family, Profile); 7] = [
    (256, Family::V4, Profile::Full),
    (257, Family::V6, Profile::Full),
    (259, Family::V4, Profile::NoSource),
    (260, Family::V6, Profile::NoSource),
    (261, Family::V4, Profile::NoDestination),
    (262, Family::V6, Profile::NoDestination),
    // No address, so one template serves both families.
    (263, Family::V4, Profile::AsOnly),
];

fn template_id(family: Family, profile: Profile) -> u16 {
    match (profile, family) {
        (Profile::AsOnly, _) => 263,
        _ => TEMPLATES
            .iter()
            .find(|(_, f, p)| *f == family && *p == profile)
            .map_or(256, |(id, _, _)| *id),
    }
}

/// What a profile's records are judged by: the local prefixes, and where
/// origin ASes come from.
pub struct Privacy<'a> {
    pub local: &'a [IpPrefix],
    pub asn: Option<&'a AsnTable>,
}

impl Privacy<'_> {
    fn local(&self, a: IpAddr) -> bool {
        self.local.iter().any(|p| p.contains(a))
    }
}

fn truncated(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V4(v) => IpAddr::V4(Ipv4Addr::from(u32::from(v) & 0xffff_ff00)),
        IpAddr::V6(v) => IpAddr::V6(Ipv6Addr::from(u128::from(v) & !((1u128 << 80) - 1))),
    }
}

fn unspecified(a: IpAddr) -> IpAddr {
    match a {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

/// A record as `profile` sends it, and the template that carries it.
fn shape(profile: CollectorProfile, mut r: FlowRecord, p: &Privacy<'_>) -> (u16, FlowRecord) {
    if let Some(t) = p.asn {
        r.src_as = t.lookup(r.src).unwrap_or(0);
        r.dst_as = t.lookup(r.dst).unwrap_or(0);
    }
    let family = if r.src.is_ipv4() {
        Family::V4
    } else {
        Family::V6
    };
    let template = match profile {
        CollectorProfile::Full => Profile::Full,
        CollectorProfile::Truncate => {
            for a in [&mut r.src, &mut r.dst] {
                if !p.local(*a) {
                    *a = truncated(*a);
                }
            }
            Profile::Full
        }
        CollectorProfile::NoRemote => match (p.local(r.src), p.local(r.dst)) {
            (true, true) => Profile::Full,
            (false, true) => Profile::NoSource,
            (true, false) => Profile::NoDestination,
            (false, false) => Profile::AsOnly,
        },
        CollectorProfile::AsOnly => Profile::AsOnly,
    };
    // Never in a message, and not left in memory meant for one either.
    if !matches!(template, Profile::Full | Profile::NoDestination) {
        r.src = unspecified(r.src);
    }
    if !matches!(template, Profile::Full | Profile::NoSource) {
        r.dst = unspecified(r.dst);
    }
    (template_id(family, template), r)
}

struct DomainOut {
    exporter: Exporter,
    /// The rate the domain's records are counted at, as last announced
    /// or about to be.
    rate: u32,
    /// When the next announcement is due; `None` makes it due now.
    next_announce: Option<Instant>,
}

/// One profile's exporting processes, one per domain.
pub struct IpfixOut {
    profile: CollectorProfile,
    /// The templates this profile announces: (id, fields).
    templates: Vec<(u16, Vec<Field>)>,
    domains: BTreeMap<Domain, DomainOut>,
    pub announcements: u64,
    pub records: u64,
    /// Records no message could hold (none, at these sizes).
    pub unencodable: u64,
}

impl IpfixOut {
    pub fn new(profile: CollectorProfile) -> Self {
        let used: &[u16] = match profile {
            CollectorProfile::Full | CollectorProfile::Truncate => &[256, 257],
            CollectorProfile::NoRemote => &[256, 257, 259, 260, 261, 262, 263],
            CollectorProfile::AsOnly => &[263],
        };
        let templates = TEMPLATES
            .iter()
            .filter(|(id, _, _)| used.contains(id))
            .map(|(id, family, p)| (*id, flow_fields(*family, *p, SamplingSignal::Options)))
            .collect();
        Self {
            profile,
            templates,
            domains: BTreeMap::new(),
            announcements: 0,
            records: 0,
            unencodable: 0,
        }
    }

    pub fn profile(&self) -> CollectorProfile {
        self.profile
    }

    /// Announce with every domain's next message: a collector was added
    /// and has seen no templates.
    pub fn reannounce(&mut self) {
        for d in self.domains.values_mut() {
            d.next_announce = None;
        }
    }

    /// Messages for one domain's exports, in order, appended to `out`.
    pub fn encode(
        &mut self,
        domain: Domain,
        items: &[Export],
        privacy: &Privacy<'_>,
        now: Instant,
        export_s: u32,
        out: &mut Vec<Vec<u8>>,
    ) {
        self.domains.entry(domain).or_insert_with(|| DomainOut {
            exporter: Exporter {
                observation_domain_id: domain.id(),
                sequence: 0,
            },
            rate: 0,
            next_announce: None,
        });
        let mut pending: BTreeMap<u16, Vec<FlowRecord>> = BTreeMap::new();
        for item in items {
            match item {
                Export::Record(r) => {
                    let (template, r) = shape(self.profile, r.clone(), privacy);
                    pending.entry(template).or_default().push(r);
                }
                // What was counted at the old rate goes first, then the
                // new rate with the next records.
                Export::Rate(rate) => {
                    self.flush(domain, &mut pending, now, export_s, out);
                    let d = self.domains.get_mut(&domain).expect("inserted above");
                    d.rate = *rate;
                    d.next_announce = None;
                }
            }
        }
        self.flush(domain, &mut pending, now, export_s, out);
    }

    fn flush(
        &mut self,
        domain: Domain,
        pending: &mut BTreeMap<u16, Vec<FlowRecord>>,
        now: Instant,
        export_s: u32,
        out: &mut Vec<Vec<u8>>,
    ) {
        if pending.values().all(Vec::is_empty) {
            return;
        }
        let Some(d) = self.domains.get_mut(&domain) else {
            return;
        };
        let templates: Vec<Template<'_>> = self
            .templates
            .iter()
            .map(|(id, fields)| Template { id: *id, fields })
            .collect();
        let mut announce = d.next_announce.is_none_or(|t| now >= t);
        for (id, records) in pending.iter_mut() {
            let Some(template) = templates.iter().find(|t| t.id == *id) else {
                continue;
            };
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
            records.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flows::{FlowCache, Limits, Now, Packet, Sampled};

    const TEMPLATE_V4: u16 = 256;
    const TEMPLATE_V6: u16 = 257;

    fn sampled(src: &str, dst: &str, dport: u16, rate: u32, generation: u64) -> Sampled {
        Sampled {
            packet: Packet {
                src: src.parse().unwrap(),
                dst: dst.parse().unwrap(),
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

    const NONE: Privacy<'static> = Privacy {
        local: &[],
        asn: None,
    };

    /// Everything the cache has ready, for one profile.
    fn encode_all(
        cache: &mut FlowCache,
        x: &mut IpfixOut,
        privacy: &Privacy<'_>,
        now: Instant,
    ) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for d in cache.pending() {
            let items = cache.take(d, RECORDS_PER_TICK);
            x.encode(d, &items, privacy, now, 0, &mut out);
        }
        out
    }

    #[test]
    fn records_go_with_the_templates_and_the_domains_rate() {
        let mut cache = FlowCache::new(Limits::default());
        let mut x = IpfixOut::new(CollectorProfile::Full);
        let t0 = Instant::now();
        cache.ingest(
            Domain::FastPath,
            &[
                sampled("192.0.2.1", "198.51.100.2", 443, 1000, 1),
                sampled("2001:db8::1", "2001:db8::2", 443, 1000, 1),
            ],
            at(0),
        );
        cache.expire(at(15_000), 100);
        let out = encode_all(&mut cache, &mut x, &NONE, t0);
        assert_eq!(out.len(), 2, "one message per template");
        let (ids, interval) = sets(&out[0]);
        assert_eq!(ids, vec![2, 3, SELECTOR_TEMPLATE, TEMPLATE_V4]);
        assert_eq!(interval, Some(1000));
        assert_eq!(word32(&out[0], 12), Domain::FastPath.id(), "domain");
        let (ids, _) = sets(&out[1]);
        assert_eq!(ids, vec![TEMPLATE_V6], "announced once");
        assert_eq!(word32(&out[1], 8), 2, "the selector and the v4 record");
        assert_eq!((x.records, x.announcements), (2, 1));
    }

    #[test]
    fn a_rate_change_is_announced_after_the_old_rates_records() {
        let mut cache = FlowCache::new(Limits::default());
        let mut x = IpfixOut::new(CollectorProfile::Full);
        cache.ingest(
            Domain::Vpp,
            &[sampled("192.0.2.1", "198.51.100.2", 1, 1000, 1)],
            at(0),
        );
        cache.ingest(
            Domain::Vpp,
            &[sampled("192.0.2.1", "198.51.100.2", 2, 100, 2)],
            at(100),
        );
        cache.expire(at(15_100), 100);
        let out = encode_all(&mut cache, &mut x, &NONE, Instant::now());
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
        let mut x = IpfixOut::new(CollectorProfile::Full);
        let t0 = Instant::now();
        let mut tick = |x: &mut IpfixOut, ms: u64, port: u16| {
            cache.ingest(
                Domain::FastPath,
                &[sampled("192.0.2.1", "198.51.100.2", port, 1000, 1)],
                at(ms),
            );
            cache.expire(at(ms + 15_000), 100);
            let out = encode_all(&mut cache, x, &NONE, t0 + Duration::from_millis(ms));
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
        let mut x = IpfixOut::new(CollectorProfile::Full);
        let batch: Vec<Sampled> = (0..500)
            .map(|p| sampled("192.0.2.1", "198.51.100.2", p, 1000, 1))
            .collect();
        cache.ingest(Domain::FastPath, &batch, at(0));
        cache.expire(at(15_000), 1000);
        let out = encode_all(&mut cache, &mut x, &NONE, Instant::now());
        assert!(out.len() > 1);
        assert!(out.iter().all(|d| d.len() <= MAX_DATAGRAM));
        assert_eq!(x.records, 500);
    }

    fn record(src: &str, dst: &str) -> FlowRecord {
        FlowRecord {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            protocol: 6,
            src_port: 1,
            dst_port: 2,
            input_if: 3,
            output_if: 5,
            src_as: 0,
            dst_as: 0,
            packets: 1,
            octets: 986,
            start_ms: 0,
            end_ms: 0,
            sampling_interval: 1000,
        }
    }

    fn local() -> Vec<IpPrefix> {
        vec![
            IpPrefix::V4 {
                addr: [192, 0, 2, 0],
                prefix_len: 24,
            },
            IpPrefix::V6 {
                addr: "2001:db8::".parse::<Ipv6Addr>().unwrap().octets(),
                prefix_len: 32,
            },
        ]
    }

    #[test]
    fn truncate_cuts_only_what_is_not_local() {
        let local = local();
        let p = Privacy {
            local: &local,
            asn: None,
        };
        let (id, r) = shape(
            CollectorProfile::Truncate,
            record("192.0.2.9", "198.51.100.77"),
            &p,
        );
        assert_eq!(id, TEMPLATE_V4);
        assert_eq!(r.src, "192.0.2.9".parse::<IpAddr>().unwrap(), "local");
        assert_eq!(r.dst, "198.51.100.0".parse::<IpAddr>().unwrap(), "/24");
        let (_, r) = shape(
            CollectorProfile::Truncate,
            record("2001:db8::9", "3fff:1:2:3::4"),
            &p,
        );
        assert_eq!(r.dst, "3fff:1:2::".parse::<IpAddr>().unwrap(), "/48");
    }

    /// Local addresses are kept, remote ones left out: a transit flow
    /// (neither local) carries neither, through the template without them.
    #[test]
    fn no_remote_keeps_local_addresses_only() {
        let local = local();
        let p = Privacy {
            local: &local,
            asn: None,
        };
        let id = |s: &str, d: &str| shape(CollectorProfile::NoRemote, record(s, d), &p).0;
        assert_eq!(id("192.0.2.1", "192.0.2.2"), 256, "both local");
        assert_eq!(id("198.51.100.1", "192.0.2.2"), 259, "no source");
        assert_eq!(id("192.0.2.1", "198.51.100.2"), 261, "no destination");
        assert_eq!(id("198.51.100.1", "203.0.113.2"), 263, "transit: neither");
        let (_, r) = shape(
            CollectorProfile::NoRemote,
            record("198.51.100.1", "192.0.2.2"),
            &p,
        );
        assert!(r.src.is_unspecified(), "not kept in memory either");
    }

    #[test]
    fn as_only_carries_the_origins_and_no_address() {
        let t = AsnTable::new();
        t.set(
            IpPrefix::V4 {
                addr: [198, 51, 100, 0],
                prefix_len: 24,
            },
            Some(64500),
        );
        t.set(
            IpPrefix::V4 {
                addr: [203, 0, 113, 0],
                prefix_len: 24,
            },
            Some(64501),
        );
        let p = Privacy {
            local: &[],
            asn: Some(&t),
        };
        let (id, r) = shape(
            CollectorProfile::AsOnly,
            record("198.51.100.1", "203.0.113.2"),
            &p,
        );
        assert_eq!(id, 263);
        assert_eq!((r.src_as, r.dst_as), (64500, 64501));
        assert!(r.src.is_unspecified() && r.dst.is_unspecified());
        // The full profile carries them too.
        let (_, r) = shape(
            CollectorProfile::Full,
            record("198.51.100.1", "192.0.2.1"),
            &p,
        );
        assert_eq!((r.src_as, r.dst_as), (64500, 0));
    }

    #[test]
    fn a_no_remote_message_uses_the_variant_templates() {
        let mut cache = FlowCache::new(Limits::default());
        let mut x = IpfixOut::new(CollectorProfile::NoRemote);
        cache.ingest(
            Domain::FastPath,
            &[
                sampled("198.51.100.1", "192.0.2.2", 1, 1000, 1),
                sampled("198.51.100.1", "203.0.113.2", 2, 1000, 1),
            ],
            at(0),
        );
        cache.expire(at(15_000), 100);
        let local = local();
        let p = Privacy {
            local: &local,
            asn: None,
        };
        let out = encode_all(&mut cache, &mut x, &p, Instant::now());
        let data: Vec<u16> = out
            .iter()
            .flat_map(|d| sets(d).0)
            .filter(|id| *id >= 256 && *id != SELECTOR_TEMPLATE)
            .collect();
        assert_eq!(data, vec![259, 263], "{data:?}");
    }
}
