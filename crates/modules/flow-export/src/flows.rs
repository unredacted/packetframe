//! The IPFIX flow cache: sampled packets aggregated into flow records,
//! per observation domain, bounded, and ordered against the rate they
//! were sampled at.
//!
//! IPFIX flow records carry sampled counts, and the rate travels apart
//! from them, in a selector options record per observation domain
//! (docs/flow-export/collectors.md, requirement 1): a collector scales
//! every record after an options record by its rate. So a domain's
//! records are exported in rate order. Samples carry the generation of
//! the sampler configuration they were drawn under. When a newer
//! generation at a new rate arrives, every flow counted at the old rate
//! is queued for export first, then the rate change, then flows at the
//! new rate. A sample of an older generation at a rate superseded since
//! cannot be scaled correctly by anything a collector has seen, and is
//! dropped and counted.
//!
//! Counts are IP-layer octets (requirement 2), from each packet's own IP
//! header, never the frame's length.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use packetframe_flow_encode::FlowRecord;

/// What a flow record is keyed on and carries from one sampled packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
    /// The IP packet's own length: the octets a flow record counts.
    pub ip_len: u32,
}

const ETH_HEADER: usize = 14;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_SCTP: u8 = 132;

/// The IP packet in a sampled Ethernet frame's leading bytes, through any
/// VLAN tags; `None` for anything that is not IP, or too short to say.
pub fn parse(frame: &[u8]) -> Option<Packet> {
    let mut at = 12;
    let mut ethertype = u16::from_be_bytes(frame.get(at..at + 2)?.try_into().ok()?);
    // At most two tags: 802.1ad then 802.1Q.
    for _ in 0..2 {
        if ethertype != 0x8100 && ethertype != 0x88a8 {
            break;
        }
        at += 4;
        ethertype = u16::from_be_bytes(frame.get(at..at + 2)?.try_into().ok()?);
    }
    let ip = frame.get(at + 2..)?;
    debug_assert!(at + 2 >= ETH_HEADER);
    match ethertype {
        0x0800 => ipv4(ip),
        0x86dd => ipv6(ip),
        _ => None,
    }
}

fn ports(protocol: u8, l4: &[u8]) -> (u16, u16) {
    match protocol {
        PROTO_TCP | PROTO_UDP | PROTO_SCTP => match l4.get(..4) {
            Some(p) => (
                u16::from_be_bytes([p[0], p[1]]),
                u16::from_be_bytes([p[2], p[3]]),
            ),
            None => (0, 0),
        },
        _ => (0, 0),
    }
}

fn ipv4(ip: &[u8]) -> Option<Packet> {
    let h = ip.get(..20)?;
    if h[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(h[0] & 0x0f) * 4;
    let total = u16::from_be_bytes([h[2], h[3]]);
    let protocol = h[9];
    // A later fragment carries no transport header.
    let first_fragment = u16::from_be_bytes([h[6], h[7]]) & 0x1fff == 0;
    let (src_port, dst_port) = match (first_fragment, ip.get(ihl.max(20)..)) {
        (true, Some(l4)) => ports(protocol, l4),
        _ => (0, 0),
    };
    Some(Packet {
        src: IpAddr::V4(Ipv4Addr::new(h[12], h[13], h[14], h[15])),
        dst: IpAddr::V4(Ipv4Addr::new(h[16], h[17], h[18], h[19])),
        protocol,
        src_port,
        dst_port,
        ip_len: u32::from(total),
    })
}

fn ipv6(ip: &[u8]) -> Option<Packet> {
    let h = ip.get(..40)?;
    if h[0] >> 4 != 6 {
        return None;
    }
    let addr = |b: &[u8]| -> Ipv6Addr {
        let a: [u8; 16] = b.try_into().unwrap_or([0; 16]);
        Ipv6Addr::from(a)
    };
    let payload = u32::from(u16::from_be_bytes([h[4], h[5]]));
    // Past the extension headers that precede a transport header.
    let mut next = h[6];
    let mut at = 40;
    let mut first_fragment = true;
    for _ in 0..8 {
        match next {
            // Hop-by-hop, routing, destination options.
            0 | 43 | 60 => {
                let Some(e) = ip.get(at..at + 2) else { break };
                next = e[0];
                at += (usize::from(e[1]) + 1) * 8;
            }
            44 => {
                let Some(e) = ip.get(at..at + 8) else { break };
                next = e[0];
                first_fragment = u16::from_be_bytes([e[2], e[3]]) >> 3 == 0;
                at += 8;
            }
            // Authentication: its length is in 4-octet units, less 2
            // (RFC 4302 §2.2), and what it protects follows in the clear.
            51 => {
                let Some(e) = ip.get(at..at + 2) else { break };
                next = e[0];
                at += (usize::from(e[1]) + 2) * 4;
            }
            _ => break,
        }
    }
    let (src_port, dst_port) = match (first_fragment, ip.get(at..)) {
        (true, Some(l4)) => ports(next, l4),
        _ => (0, 0),
    };
    Some(Packet {
        src: IpAddr::V6(addr(&h[8..24])),
        dst: IpAddr::V6(addr(&h[24..40])),
        protocol: next,
        src_port,
        dst_port,
        ip_len: payload + 40,
    })
}

/// An IPFIX observation domain: where packets were observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Domain {
    /// flow-export's kernel sampler.
    Kernel = 1,
    /// fast-path's XDP and tc programs.
    FastPath = 2,
    /// VPP's sampler plugin.
    Vpp = 3,
}

impl Domain {
    pub fn id(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    input_if: u32,
    output_if: u32,
}

#[derive(Debug, Clone)]
struct Flow {
    id: u64,
    packets: u64,
    octets: u64,
    start_wall_ms: u64,
    end_wall_ms: u64,
    start_ms: u64,
    last_ms: u64,
}

/// What a domain exports, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Export {
    Record(FlowRecord),
    /// Every record after this was counted at this 1-in-N rate.
    Rate(u32),
}

/// A sampled packet as the cache takes it.
#[derive(Debug, Clone, Copy)]
pub struct Sampled {
    pub packet: Packet,
    /// The sampler configuration it was drawn under, and its rate.
    pub generation: u64,
    pub rate: u32,
    pub input_if: u32,
    pub output_if: u32,
    /// When it was sampled, not when the worker read it: a backlog
    /// drained late keeps its flows' times and timeouts.
    pub at: Now,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Flows held per domain; a new flow beyond it exports the oldest.
    pub entries: usize,
    /// A flow is exported this long after its first packet...
    pub active: Duration,
    /// ...or this long after its last.
    pub inactive: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            entries: packetframe_common::config::FLOW_CACHE_ENTRIES_DEFAULT,
            active: Duration::from_secs(60),
            inactive: Duration::from_secs(15),
        }
    }
}

/// Why flows left the cache, and samples never reached it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub expired_active: u64,
    pub expired_inactive: u64,
    pub evicted_full: u64,
    /// Exported early by a rate change.
    pub flushed: u64,
    /// Samples of an older generation, at a rate superseded since.
    pub stale: u64,
    /// Records not exported because the export queue was full.
    pub queue_dropped: u64,
}

#[derive(Debug, Default)]
struct DomainCache {
    /// The newest generation seen, and the rate the domain counts at; 0
    /// before its first sample.
    generation: u64,
    rate: u32,
    flows: HashMap<Key, Flow>,
    by_start: BTreeMap<(u64, u64), Key>,
    by_last: BTreeMap<(u64, u64), Key>,
    out: VecDeque<Export>,
}

pub struct FlowCache {
    limits: Limits,
    domains: BTreeMap<Domain, DomainCache>,
    next_id: u64,
    /// Which domain expiry starts with, turn about, so one domain's
    /// backlog cannot hold back another's timeouts.
    turn: usize,
    pub counts: Counts,
}

/// Times as the cache takes them: monotonic milliseconds for its
/// timeouts and order, and the wall clock's for the records it exports.
#[derive(Debug, Clone, Copy)]
pub struct Now {
    pub ms: u64,
    pub wall_ms: u64,
}

impl FlowCache {
    pub fn new(limits: Limits) -> Self {
        Self {
            limits,
            domains: BTreeMap::new(),
            next_id: 0,
            turn: 0,
            counts: Counts::default(),
        }
    }

    /// A smaller `entries` is reached a little at a time, oldest flows
    /// first, by [`Self::expire`] within its budget: never all at once,
    /// which could overrun the smaller export queue in one tick.
    pub fn set_limits(&mut self, limits: Limits) {
        self.limits = limits;
    }

    /// Flows held, across every domain.
    pub fn active(&self) -> usize {
        self.domains.values().map(|d| d.flows.len()).sum()
    }

    /// One tick's samples for a domain, generation by generation, oldest
    /// first, so samples a tick drains from before and after a change
    /// count at their own rates. A newer generation at another rate
    /// replaces the domain's: the flows at the rate before are queued for
    /// export ahead of the change. An older generation counts while its
    /// rate is still the domain's, and is stale once it is not.
    pub fn ingest(&mut self, domain: Domain, batch: &[Sampled]) {
        let mut generations: Vec<(u64, u32)> =
            batch.iter().map(|s| (s.generation, s.rate)).collect();
        generations.sort_unstable();
        generations.dedup_by_key(|g| g.0);
        for (generation, rate) in generations {
            let of = |s: &&Sampled| s.generation == generation;
            let d = self.domains.entry(domain).or_default();
            if generation < d.generation && rate != d.rate {
                self.counts.stale += batch.iter().filter(of).count() as u64;
                continue;
            }
            if generation > d.generation {
                d.generation = generation;
                if rate != d.rate {
                    self.switch(domain, rate);
                }
            }
            for s in batch.iter().filter(of) {
                self.count(domain, s);
            }
        }
    }

    fn switch(&mut self, domain: Domain, rate: u32) {
        let cap = self.queue_cap();
        let d = self.domains.entry(domain).or_default();
        let keys: Vec<Key> = d.by_start.values().cloned().collect();
        for k in keys {
            if Self::export(d, &k, d.rate, &mut self.counts, cap) {
                self.counts.flushed += 1;
            }
        }
        d.out.push_back(Export::Rate(rate));
        d.rate = rate;
    }

    /// At most twice the cache waits for export, so a stalled export
    /// cannot grow without bound.
    fn queue_cap(&self) -> usize {
        2 * self.limits.entries.max(1)
    }

    fn count(&mut self, domain: Domain, s: &Sampled) {
        let now = s.at;
        let entries = self.limits.entries.max(1);
        let cap = self.queue_cap();
        let id = self.next_id;
        let d = self.domains.entry(domain).or_default();
        let key = Key {
            src: s.packet.src,
            dst: s.packet.dst,
            protocol: s.packet.protocol,
            src_port: s.packet.src_port,
            dst_port: s.packet.dst_port,
            input_if: s.input_if,
            output_if: s.output_if,
        };
        if let Some(f) = d.flows.get_mut(&key) {
            f.packets += 1;
            f.octets += u64::from(s.packet.ip_len);
            // Samples from different CPUs' rings arrive out of order.
            if now.ms > f.last_ms {
                d.by_last.remove(&(f.last_ms, f.id));
                f.last_ms = now.ms;
                f.end_wall_ms = now.wall_ms;
                d.by_last.insert((f.last_ms, f.id), key.clone());
            }
            if now.ms < f.start_ms {
                d.by_start.remove(&(f.start_ms, f.id));
                f.start_ms = now.ms;
                f.start_wall_ms = now.wall_ms;
                d.by_start.insert((f.start_ms, f.id), key);
            }
            return;
        }
        // Room for one: a cache over a limit lowered by a reload is
        // brought down by `expire`, a budget at a time.
        if d.flows.len() >= entries {
            if let Some(oldest) = d.by_start.first_key_value().map(|(_, v)| v.clone()) {
                if Self::export(d, &oldest, d.rate, &mut self.counts, cap) {
                    self.counts.evicted_full += 1;
                }
            }
        }
        self.next_id += 1;
        d.by_start.insert((now.ms, id), key.clone());
        d.by_last.insert((now.ms, id), key.clone());
        d.flows.insert(
            key,
            Flow {
                id,
                packets: 1,
                octets: u64::from(s.packet.ip_len),
                start_wall_ms: now.wall_ms,
                end_wall_ms: now.wall_ms,
                start_ms: now.ms,
                last_ms: now.ms,
            },
        );
    }

    /// Remove a flow and queue its record, if the queue has room: whether
    /// it did. A record with no room is counted dropped, and the caller
    /// counts only what was queued, so no record reads as both.
    fn export(d: &mut DomainCache, key: &Key, rate: u32, counts: &mut Counts, cap: usize) -> bool {
        let Some(f) = d.flows.remove(key) else {
            return false;
        };
        d.by_start.remove(&(f.start_ms, f.id));
        d.by_last.remove(&(f.last_ms, f.id));
        if d.out.len() >= cap {
            counts.queue_dropped += 1;
            return false;
        }
        d.out.push_back(Export::Record(FlowRecord {
            src: key.src,
            dst: key.dst,
            protocol: key.protocol,
            src_port: key.src_port,
            dst_port: key.dst_port,
            input_if: key.input_if,
            output_if: key.output_if,
            src_as: 0,
            dst_as: 0,
            packets: f.packets,
            octets: f.octets,
            start_ms: f.start_wall_ms,
            end_ms: f.end_wall_ms,
            sampling_interval: rate,
        }));
        true
    }

    /// Export every flow, timed out or not: the export is stopping.
    pub fn drain(&mut self) {
        let cap = usize::MAX;
        for d in self.domains.values_mut() {
            let keys: Vec<Key> = d.by_start.values().cloned().collect();
            let rate = d.rate;
            for k in keys {
                Self::export(d, &k, rate, &mut self.counts, cap);
            }
        }
    }

    /// Export flows past a timeout, and the oldest of a cache over its
    /// limit, at most `budget` across domains.
    pub fn expire(&mut self, now: Now, budget: usize) {
        let active = self.limits.active.as_millis() as u64;
        let inactive = self.limits.inactive.as_millis() as u64;
        let entries = self.limits.entries.max(1);
        let cap = self.queue_cap();
        let mut left = budget;
        let mut order: Vec<Domain> = self.domains.keys().copied().collect();
        if !order.is_empty() {
            let n = order.len();
            order.rotate_left(self.turn % n);
            self.turn = self.turn.wrapping_add(1);
        }
        for domain in order {
            let Some(d) = self.domains.get_mut(&domain) else {
                continue;
            };
            while left > 0 && d.flows.len() > entries {
                let Some(oldest) = d.by_start.first_key_value().map(|(_, v)| v.clone()) else {
                    break;
                };
                let rate = d.rate;
                if Self::export(d, &oldest, rate, &mut self.counts, cap) {
                    self.counts.evicted_full += 1;
                }
                left -= 1;
            }
            while left > 0 {
                let idle = d
                    .by_last
                    .first_key_value()
                    .filter(|((last, _), _)| last + inactive <= now.ms)
                    .map(|(_, k)| k.clone());
                let old = d
                    .by_start
                    .first_key_value()
                    .filter(|((start, _), _)| start + active <= now.ms)
                    .map(|(_, k)| k.clone());
                let (key, idle) = match (idle, old) {
                    (Some(k), _) => (k, true),
                    (None, Some(k)) => (k, false),
                    (None, None) => break,
                };
                let rate = d.rate;
                if Self::export(d, &key, rate, &mut self.counts, cap) {
                    if idle {
                        self.counts.expired_inactive += 1;
                    } else {
                        self.counts.expired_active += 1;
                    }
                }
                left -= 1;
            }
        }
    }

    /// Up to `max` of a domain's exports, in order.
    pub fn take(&mut self, domain: Domain, max: usize) -> Vec<Export> {
        let Some(d) = self.domains.get_mut(&domain) else {
            return Vec::new();
        };
        let n = d.out.len().min(max);
        d.out.drain(..n).collect()
    }

    /// Exports queued, across every domain.
    pub fn queued(&self) -> usize {
        self.domains.values().map(|d| d.out.len()).sum()
    }

    /// The domains with anything to export.
    pub fn pending(&self) -> Vec<Domain> {
        self.domains
            .iter()
            .filter(|(_, d)| !d.out.is_empty())
            .map(|(k, _)| *k)
            .collect()
    }

    /// The rate a domain counts at; 0 before its first sample.
    pub fn rate(&self, domain: Domain) -> u32 {
        self.domains.get(&domain).map_or(0, |d| d.rate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ethernet, optionally one 802.1Q tag, then `ip`.
    pub(crate) fn frame(vlan: bool, ethertype: u16, ip: &[u8]) -> Vec<u8> {
        let mut f = vec![0x02; 12];
        if vlan {
            f.extend_from_slice(&[0x81, 0x00, 0x00, 0x64]);
        }
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(ip);
        f
    }

    pub(crate) fn v4_tcp(
        src: [u8; 4],
        dst: [u8; 4],
        total: u16,
        sport: u16,
        dport: u16,
    ) -> Vec<u8> {
        let mut h = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, PROTO_TCP, 0, 0];
        h[2..4].copy_from_slice(&total.to_be_bytes());
        h.extend_from_slice(&src);
        h.extend_from_slice(&dst);
        h.extend_from_slice(&sport.to_be_bytes());
        h.extend_from_slice(&dport.to_be_bytes());
        h.extend_from_slice(&[0; 16]);
        h
    }

    #[test]
    fn ipv4_through_a_vlan_tag_with_its_own_length_and_ports() {
        let p = parse(&frame(
            true,
            0x0800,
            &v4_tcp([192, 0, 2, 1], [198, 51, 100, 2], 986, 40000, 443),
        ))
        .unwrap();
        assert_eq!(p.src, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(p.dst, "198.51.100.2".parse::<IpAddr>().unwrap());
        assert_eq!(
            (p.protocol, p.src_port, p.dst_port),
            (PROTO_TCP, 40000, 443)
        );
        assert_eq!(p.ip_len, 986, "the IP layer's, not the frame's");
    }

    #[test]
    fn a_later_fragment_has_no_ports_and_non_ip_is_none() {
        let mut ip = v4_tcp([192, 0, 2, 1], [198, 51, 100, 2], 100, 1, 2);
        ip[6..8].copy_from_slice(&0x0010u16.to_be_bytes());
        let p = parse(&frame(false, 0x0800, &ip)).unwrap();
        assert_eq!((p.src_port, p.dst_port), (0, 0));
        assert!(parse(&frame(false, 0x0806, &[0; 28])).is_none(), "ARP");
        assert!(parse(&[0; 10]).is_none());
        assert!(
            parse(&frame(false, 0x0800, &[0x45; 10])).is_none(),
            "cut short"
        );
    }

    #[test]
    fn ipv6_past_extension_headers() {
        let mut ip = vec![0x60, 0, 0, 0, 0, 0, 0 /* hop-by-hop */, 64];
        ip[4..6].copy_from_slice(&(8u16 + 8).to_be_bytes());
        ip.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        ip.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        ip.extend_from_slice(&[PROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        ip.extend_from_slice(&[0x13, 0x88, 0x00, 0x35, 0, 8, 0, 0]);
        let p = parse(&frame(false, 0x86dd, &ip)).unwrap();
        assert_eq!((p.protocol, p.src_port, p.dst_port), (PROTO_UDP, 5000, 53));
        assert_eq!(p.ip_len, 56);
    }

    fn sampled(dport: u16, rate: u32) -> Sampled {
        sampled_at(dport, rate, u64::from(rate == 100) + 1)
    }

    fn sampled_at(dport: u16, rate: u32, generation: u64) -> Sampled {
        Sampled {
            generation,
            packet: Packet {
                src: "192.0.2.1".parse().unwrap(),
                dst: "198.51.100.2".parse().unwrap(),
                protocol: PROTO_TCP,
                src_port: 40000,
                dst_port: dport,
                ip_len: 1000,
            },
            rate,
            input_if: 3,
            output_if: 5,
            at: at(0),
        }
    }

    /// `batch`, every sample observed at `now`.
    fn ingest(c: &mut FlowCache, domain: Domain, batch: &[Sampled], now: Now) {
        let batch: Vec<Sampled> = batch.iter().map(|s| Sampled { at: now, ..*s }).collect();
        c.ingest(domain, &batch);
    }

    fn at(ms: u64) -> Now {
        Now {
            ms,
            wall_ms: 1_790_000_000_000 + ms,
        }
    }

    fn records(out: &[Export]) -> Vec<&FlowRecord> {
        out.iter()
            .filter_map(|e| match e {
                Export::Record(r) => Some(r),
                Export::Rate(_) => None,
            })
            .collect()
    }

    #[test]
    fn packets_of_a_flow_aggregate_until_a_timeout() {
        let mut c = FlowCache::new(Limits::default());
        ingest(
            &mut c,
            Domain::FastPath,
            &[sampled(443, 1000), sampled(443, 1000)],
            at(0),
        );
        ingest(&mut c, Domain::FastPath, &[sampled(443, 1000)], at(5_000));
        assert_eq!(c.active(), 1);
        assert_eq!(c.take(Domain::FastPath, 10), vec![Export::Rate(1000)]);
        c.expire(at(19_999), 100);
        assert!(c.take(Domain::FastPath, 10).is_empty(), "idle 14.999 s");
        c.expire(at(20_000), 100);
        let out = c.take(Domain::FastPath, 10);
        let r = records(&out);
        assert_eq!((r[0].packets, r[0].octets), (3, 3000));
        assert_eq!(r[0].end_ms - r[0].start_ms, 5_000);
        assert_eq!(r[0].sampling_interval, 1000);
        assert_eq!(c.counts.expired_inactive, 1);
        assert_eq!(c.active(), 0);
    }

    #[test]
    fn a_busy_flow_is_exported_at_the_active_timeout() {
        let mut c = FlowCache::new(Limits::default());
        for s in 0..=60 {
            ingest(&mut c, Domain::Vpp, &[sampled(80, 1000)], at(s * 1000));
            c.expire(at(s * 1000), 100);
        }
        assert_eq!(c.counts.expired_active, 1);
        // A tick counts its samples before it expires flows: 0 s to 60 s.
        assert_eq!(records(&c.take(Domain::Vpp, 10))[0].packets, 61);
    }

    #[test]
    fn a_full_cache_exports_its_oldest_flow() {
        let mut c = FlowCache::new(Limits {
            entries: 2,
            ..Limits::default()
        });
        for (i, port) in [1u16, 2, 3].into_iter().enumerate() {
            ingest(
                &mut c,
                Domain::FastPath,
                &[sampled(port, 1000)],
                at(i as u64),
            );
        }
        assert_eq!((c.active(), c.counts.evicted_full), (2, 1));
        let out = c.take(Domain::FastPath, 10);
        assert_eq!(records(&out)[0].dst_port, 1, "the oldest");
    }

    /// A collector scales every record after an options record by its
    /// rate: the old rate's flows go first, then the change, then the
    /// new rate's, even with both in one tick's samples.
    #[test]
    fn a_rate_change_exports_the_old_rates_flows_before_announcing_it() {
        let mut c = FlowCache::new(Limits::default());
        ingest(&mut c, Domain::FastPath, &[sampled(1, 1000)], at(0));
        ingest(
            &mut c,
            Domain::FastPath,
            &[sampled(2, 100), sampled(1, 1000), sampled(2, 100)],
            at(100),
        );
        let out = c.take(Domain::FastPath, 10);
        assert_eq!(out[0], Export::Rate(1000));
        let Export::Record(old) = &out[1] else {
            panic!("{out:?}")
        };
        assert_eq!(
            (old.dst_port, old.packets, old.sampling_interval),
            (1, 2, 1000)
        );
        assert_eq!(out[2], Export::Rate(100));
        assert_eq!(out.len(), 3, "the new flow is still counting");
        assert_eq!(c.counts.flushed, 1);
        assert_eq!(c.rate(Domain::FastPath), 100);
        // VPP's domain is its own.
        assert_eq!(c.rate(Domain::Vpp), 0);
    }

    #[test]
    fn a_late_sample_counts_at_its_rate_or_not_at_all() {
        let mut c = FlowCache::new(Limits::default());
        ingest(&mut c, Domain::Vpp, &[sampled_at(1, 1000, 1)], at(0));
        // Generation 2 changed only the ports: generation 1's samples
        // still scale right.
        ingest(&mut c, Domain::Vpp, &[sampled_at(1, 1000, 2)], at(1));
        ingest(&mut c, Domain::Vpp, &[sampled_at(1, 1000, 1)], at(2));
        assert_eq!(c.active(), 1);
        assert_eq!(c.counts.stale, 0);
        // Generation 3 changed the rate; one of generation 2's arrives.
        ingest(&mut c, Domain::Vpp, &[sampled_at(2, 500, 3)], at(3));
        ingest(&mut c, Domain::Vpp, &[sampled_at(1, 1000, 2)], at(4));
        assert_eq!(c.counts.stale, 1, "no options record says 1:1000 now");
        let out = c.take(Domain::Vpp, 10);
        assert_eq!(
            out.iter().filter(|e| matches!(e, Export::Rate(_))).count(),
            2,
            "{out:?}"
        );
        assert_eq!(records(&out)[0].packets, 3);
    }

    #[test]
    fn a_domain_exports_at_most_what_is_asked() {
        let mut c = FlowCache::new(Limits::default());
        let batch: Vec<Sampled> = (0..5).map(|p| sampled(p, 1000)).collect();
        ingest(&mut c, Domain::FastPath, &batch, at(0));
        c.expire(at(15_000), 3);
        assert_eq!(c.active(), 2, "the budget bounds a tick's expiry");
        assert_eq!(c.take(Domain::FastPath, 2).len(), 2);
        assert_eq!(c.pending(), vec![Domain::FastPath]);
        assert_eq!(c.take(Domain::FastPath, 10).len(), 2);
        assert!(c.pending().is_empty());
    }

    /// AH protects what follows it in the clear: the flow is the TCP
    /// connection inside, not every AH packet between two hosts.
    #[test]
    fn ipv6_past_an_authentication_header() {
        let mut ip = vec![0x60, 0, 0, 0, 0, 0, 51 /* AH */, 64];
        ip[4..6].copy_from_slice(&(24u16 + 20).to_be_bytes());
        ip.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        ip.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        // Next header TCP, length 4: (4 + 2) * 4 = 24 octets with a
        // 96-bit ICV.
        ip.extend_from_slice(&[PROTO_TCP, 4, 0, 0]);
        ip.extend_from_slice(&[0; 20]);
        ip.extend_from_slice(&[0x9c, 0x40, 0x01, 0xbb]);
        ip.extend_from_slice(&[0; 16]);
        let p = parse(&frame(false, 0x86dd, &ip)).unwrap();
        assert_eq!(
            (p.protocol, p.src_port, p.dst_port),
            (PROTO_TCP, 40000, 443)
        );
        assert_eq!(p.ip_len, 84);
    }

    /// Samples read late keep the time they were taken: a flow spans
    /// what its samples saw, whatever order they arrive in, and times out
    /// from its last packet, not from when the worker got to it.
    #[test]
    fn samples_count_at_the_time_they_were_taken() {
        let mut c = FlowCache::new(Limits::default());
        let batch = [
            Sampled {
                at: at(3_000),
                ..sampled(443, 1000)
            },
            Sampled {
                at: at(1_000),
                ..sampled(443, 1000)
            },
            Sampled {
                at: at(2_000),
                ..sampled(443, 1000)
            },
        ];
        c.ingest(Domain::FastPath, &batch);
        c.expire(at(17_999), 100);
        assert_eq!(c.active(), 1, "idle 14.999 s since the last sample");
        c.expire(at(18_000), 100);
        let out = c.take(Domain::FastPath, 10);
        let r = records(&out)[0];
        assert_eq!(r.start_ms, at(1_000).wall_ms, "the earliest, read second");
        assert_eq!(r.end_ms, at(3_000).wall_ms);
    }

    /// A record the full queue drops is counted dropped, not also as
    /// exported.
    #[test]
    fn a_record_the_queue_drops_is_not_counted_exported() {
        let mut c = FlowCache::new(Limits {
            entries: 1,
            ..Limits::default()
        });
        // The queue holds two: the rate, then the first eviction.
        for port in 1..=3 {
            ingest(&mut c, Domain::FastPath, &[sampled(port, 1000)], at(0));
        }
        assert_eq!((c.counts.evicted_full, c.counts.queue_dropped), (1, 1));
        assert_eq!(records(&c.take(Domain::FastPath, 10)).len(), 1);
        c.expire(at(15_000), 100);
        assert_eq!(c.counts.expired_inactive, 1, "room again");
    }

    /// A reload that lowers `entries` evicts the excess a budget at a
    /// time, oldest first; a new flow meanwhile makes room for itself
    /// alone.
    #[test]
    fn a_lowered_limit_is_reached_a_budget_at_a_time() {
        let mut c = FlowCache::new(Limits::default());
        let batch: Vec<Sampled> = (0..10).map(|p| sampled(p, 1000)).collect();
        for (i, s) in batch.iter().enumerate() {
            ingest(&mut c, Domain::FastPath, &[*s], at(i as u64));
        }
        c.set_limits(Limits {
            entries: 4,
            ..Limits::default()
        });
        ingest(&mut c, Domain::FastPath, &[sampled(99, 1000)], at(20));
        assert_eq!((c.active(), c.counts.evicted_full), (10, 1));
        c.expire(at(21), 3);
        assert_eq!((c.active(), c.counts.evicted_full), (7, 4));
        c.expire(at(22), 100);
        assert_eq!((c.active(), c.counts.evicted_full), (4, 7));
        let out = c.take(Domain::FastPath, 100);
        let ports: Vec<u16> = records(&out).iter().map(|r| r.dst_port).collect();
        assert_eq!(ports, (0..7).collect::<Vec<u16>>(), "oldest first");
    }

    /// One domain's backlog of timeouts cannot hold back another's.
    #[test]
    fn expiry_takes_the_domains_turn_about() {
        let mut c = FlowCache::new(Limits::default());
        for domain in [Domain::FastPath, Domain::Vpp] {
            let batch: Vec<Sampled> = (0..3).map(|p| sampled(p, 1000)).collect();
            ingest(&mut c, domain, &batch, at(0));
        }
        let records_of = |c: &mut FlowCache, d| records(&c.take(d, 10)).len();
        c.expire(at(15_000), 2);
        assert_eq!(records_of(&mut c, Domain::FastPath), 2);
        c.expire(at(15_000), 2);
        assert_eq!(
            records_of(&mut c, Domain::Vpp),
            2,
            "VPP first, though fast-path has one left"
        );
    }
}
