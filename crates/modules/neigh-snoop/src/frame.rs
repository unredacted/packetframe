//! Wire parser for the four frame types the snooper learns from.
//!
//! Deliberately portable (no cfg gates, no netlink types): the parser
//! is a pure function over bytes and every vector below runs on a
//! macOS dev laptop. Offsets are from the start of the Ethernet
//! header; frames arrive on the bridge device untagged.
//!
//! What is learned (handoff §7):
//! - ARP request / reply: `(spa, sha)`, requiring `sha == eth.src`.
//! - ICMPv6 Neighbor Solicitation (135): `(ip6.src, SLLAO)`, skipping
//!   `::` (duplicate address detection carries no usable source).
//! - ICMPv6 Neighbor Advertisement (136): `(target, TLLAO)`, plus
//!   `(ip6.src, TLLAO)` when the source is a link-local address other
//!   than the target — one router, two addresses, one frame.
//!
//! The ICMPv6 checksum is not validated: a forged pair costs one
//! failed unicast probe and is corrected on the next genuine sighting,
//! and the exchange enforces one MAC per member port.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ETH_HLEN: usize = 14;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88a8;
const ARP_LEN: usize = 42;
const IP6_HDR_END: usize = 54;
const ICMP6_HDR_END: usize = 58;
const ND_OPTIONS_START: usize = 78;
const IPPROTO_ICMPV6: u8 = 58;
const ICMP6_NS: u8 = 135;
const ICMP6_NA: u8 = 136;
const ND_OPT_SOURCE_LL: u8 = 1;
const ND_OPT_TARGET_LL: u8 = 2;

/// Which frame taught us a pair. The label set is closed; the metrics
/// family `frames_total{kind}` and the persisted `source` field both
/// key on [`Source::LABELS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    ArpRequest,
    ArpReply,
    NeighborSolicitation,
    NeighborAdvertisement,
}

impl Source {
    pub const COUNT: usize = 4;
    pub const LABELS: [&'static str; Self::COUNT] = ["arp_request", "arp_reply", "ns", "na"];

    pub fn index(self) -> usize {
        match self {
            Self::ArpRequest => 0,
            Self::ArpReply => 1,
            Self::NeighborSolicitation => 2,
            Self::NeighborAdvertisement => 3,
        }
    }

    pub fn label(self) -> &'static str {
        Self::LABELS[self.index()]
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "arp_request" => Some(Self::ArpRequest),
            "arp_reply" => Some(Self::ArpReply),
            "ns" => Some(Self::NeighborSolicitation),
            "na" => Some(Self::NeighborAdvertisement),
            _ => None,
        }
    }
}

/// One `(ip, mac)` pair extracted from a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Learned {
    pub ip: IpAddr,
    pub mac: [u8; 6],
    pub source: Source,
}

/// Why a sender MAC is unusable as a learned hardware address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacClass {
    Zero,
    Broadcast,
    Multicast,
}

/// Every way a frame can be refused. Each variant maps to one
/// `parse_rejects_total{reason}` label via [`Reject::label`], so the
/// operator sees *why* frames are being dropped, not just that they
/// are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Too short at the named layer: `eth`, `arp`, `ip6`, `icmp6`,
    /// `ns`, `na`, `opt`.
    Truncated(&'static str),
    /// 802.1Q / 802.1ad tag present. Frames on the bridge device are
    /// untagged; a tagged one is not ours to learn from.
    VlanTagged,
    /// Neither ARP nor IPv6. The socket filter should have dropped
    /// it; counted, never panics.
    EtherType(u16),
    Ip6Version(u8),
    ArpHtype(u16),
    ArpPtype(u16),
    ArpLens(u8, u8),
    ArpOp(u16),
    /// ARP sender hardware address disagrees with the Ethernet source.
    ShaMismatch,
    /// Extension headers are deliberately not walked: NS/NA are sent
    /// without them.
    Ip6NextHeader(u8),
    /// Valid ND has hop limit 255 (RFC 4861 §7.1).
    Ip6HopLimit(u8),
    Icmp6Type(u8),
    Icmp6Code(u8),
    /// NS from `::` — duplicate address detection.
    DadSource,
    /// NS without a Source LL option / NA without a Target LL option,
    /// including an options walk that ended on a zero-length option.
    NoLinkLayerOption,
    /// The LL option had a length other than 1 (8 bytes).
    OptionBadLen,
    /// Zero, broadcast or multicast sender MAC.
    SenderMac(MacClass),
}

impl Reject {
    pub const COUNT: usize = 17;
    pub const LABELS: [&'static str; Self::COUNT] = [
        "truncated",
        "vlan_tagged",
        "ethertype",
        "ip6_version",
        "arp_htype",
        "arp_ptype",
        "arp_lens",
        "arp_op",
        "sha_mismatch",
        "ip6_next_header",
        "ip6_hop_limit",
        "icmp6_type",
        "icmp6_code",
        "dad_source",
        "no_ll_option",
        "option_bad_len",
        "sender_mac",
    ];

    pub fn index(&self) -> usize {
        match self {
            Self::Truncated(_) => 0,
            Self::VlanTagged => 1,
            Self::EtherType(_) => 2,
            Self::Ip6Version(_) => 3,
            Self::ArpHtype(_) => 4,
            Self::ArpPtype(_) => 5,
            Self::ArpLens(..) => 6,
            Self::ArpOp(_) => 7,
            Self::ShaMismatch => 8,
            Self::Ip6NextHeader(_) => 9,
            Self::Ip6HopLimit(_) => 10,
            Self::Icmp6Type(_) => 11,
            Self::Icmp6Code(_) => 12,
            Self::DadSource => 13,
            Self::NoLinkLayerOption => 14,
            Self::OptionBadLen => 15,
            Self::SenderMac(_) => 16,
        }
    }

    pub fn label(&self) -> &'static str {
        Self::LABELS[self.index()]
    }
}

/// Classify a MAC as a usable unicast hardware address or not.
pub fn classify_mac(mac: [u8; 6]) -> Option<MacClass> {
    if mac == [0u8; 6] {
        Some(MacClass::Zero)
    } else if mac == [0xff; 6] {
        Some(MacClass::Broadcast)
    } else if mac[0] & 1 != 0 {
        Some(MacClass::Multicast)
    } else {
        None
    }
}

fn mac_at(f: &[u8], off: usize) -> [u8; 6] {
    let mut m = [0u8; 6];
    m.copy_from_slice(&f[off..off + 6]);
    m
}

fn be16(f: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([f[off], f[off + 1]])
}

fn ip6_at(f: &[u8], off: usize) -> Ipv6Addr {
    let mut b = [0u8; 16];
    b.copy_from_slice(&f[off..off + 16]);
    Ipv6Addr::from(b)
}

/// Parse one Ethernet frame into the pairs it teaches. `Ok` is never
/// empty; an NA can teach two pairs.
pub fn parse_frame(f: &[u8]) -> Result<Vec<Learned>, Reject> {
    if f.len() < ETH_HLEN {
        return Err(Reject::Truncated("eth"));
    }
    let eth_src = mac_at(f, 6);
    match be16(f, 12) {
        ETHERTYPE_VLAN | ETHERTYPE_QINQ => Err(Reject::VlanTagged),
        ETHERTYPE_ARP => parse_arp(f, eth_src),
        ETHERTYPE_IPV6 => parse_nd(f),
        other => Err(Reject::EtherType(other)),
    }
}

fn parse_arp(f: &[u8], eth_src: [u8; 6]) -> Result<Vec<Learned>, Reject> {
    if f.len() < ARP_LEN {
        return Err(Reject::Truncated("arp"));
    }
    let htype = be16(f, 14);
    if htype != 1 {
        return Err(Reject::ArpHtype(htype));
    }
    let ptype = be16(f, 16);
    if ptype != 0x0800 {
        return Err(Reject::ArpPtype(ptype));
    }
    let (hlen, plen) = (f[18], f[19]);
    if hlen != 6 || plen != 4 {
        return Err(Reject::ArpLens(hlen, plen));
    }
    let source = match be16(f, 20) {
        1 => Source::ArpRequest,
        2 => Source::ArpReply,
        op => return Err(Reject::ArpOp(op)),
    };
    let sha = mac_at(f, 22);
    if sha != eth_src {
        return Err(Reject::ShaMismatch);
    }
    if let Some(class) = classify_mac(sha) {
        return Err(Reject::SenderMac(class));
    }
    let spa = Ipv4Addr::new(f[28], f[29], f[30], f[31]);
    Ok(vec![Learned {
        ip: IpAddr::V4(spa),
        mac: sha,
        source,
    }])
}

fn parse_nd(f: &[u8]) -> Result<Vec<Learned>, Reject> {
    if f.len() < IP6_HDR_END {
        return Err(Reject::Truncated("ip6"));
    }
    let version = f[14] >> 4;
    if version != 6 {
        return Err(Reject::Ip6Version(version));
    }
    let nexthdr = f[20];
    if nexthdr != IPPROTO_ICMPV6 {
        return Err(Reject::Ip6NextHeader(nexthdr));
    }
    let hop_limit = f[21];
    if hop_limit != 255 {
        return Err(Reject::Ip6HopLimit(hop_limit));
    }
    let src = ip6_at(f, 22);
    if f.len() < ICMP6_HDR_END {
        return Err(Reject::Truncated("icmp6"));
    }
    let icmp_type = f[54];
    let code = f[55];
    if code != 0 {
        return Err(Reject::Icmp6Code(code));
    }
    match icmp_type {
        ICMP6_NS => {
            if f.len() < ND_OPTIONS_START {
                return Err(Reject::Truncated("ns"));
            }
            if src.is_unspecified() {
                return Err(Reject::DadSource);
            }
            let mac = find_ll_option(&f[ND_OPTIONS_START..], ND_OPT_SOURCE_LL)?;
            if let Some(class) = classify_mac(mac) {
                return Err(Reject::SenderMac(class));
            }
            Ok(vec![Learned {
                ip: IpAddr::V6(src),
                mac,
                source: Source::NeighborSolicitation,
            }])
        }
        ICMP6_NA => {
            if f.len() < ND_OPTIONS_START {
                return Err(Reject::Truncated("na"));
            }
            let target = ip6_at(f, 62);
            let mac = find_ll_option(&f[ND_OPTIONS_START..], ND_OPT_TARGET_LL)?;
            if let Some(class) = classify_mac(mac) {
                return Err(Reject::SenderMac(class));
            }
            let mut out = vec![Learned {
                ip: IpAddr::V6(target),
                mac,
                source: Source::NeighborAdvertisement,
            }];
            if src != target && src.is_unicast_link_local() {
                out.push(Learned {
                    ip: IpAddr::V6(src),
                    mac,
                    source: Source::NeighborAdvertisement,
                });
            }
            Ok(out)
        }
        other => Err(Reject::Icmp6Type(other)),
    }
}

/// Walk ND options `[type, len/8, data...]` for the wanted link-layer
/// option. A zero length ends the walk (malformed, RFC 4861 §4.6);
/// an option running past the frame is a truncation.
fn find_ll_option(opts: &[u8], want: u8) -> Result<[u8; 6], Reject> {
    let mut off = 0;
    while off + 2 <= opts.len() {
        let (t, l8) = (opts[off], opts[off + 1]);
        if l8 == 0 {
            break;
        }
        let l = l8 as usize * 8;
        if off + l > opts.len() {
            return Err(Reject::Truncated("opt"));
        }
        if t == want {
            if l8 != 1 {
                return Err(Reject::OptionBadLen);
            }
            return Ok(mac_at(opts, off + 2));
        }
        off += l;
    }
    Err(Reject::NoLinkLayerOption)
}

/// Frame builders shared by this module's tests and the socket-filter
/// interpreter test. Documentation addresses only.
#[cfg(test)]
pub(crate) mod testframes {
    use std::net::{Ipv4Addr, Ipv6Addr};

    pub const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    pub const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];
    pub const BCAST: [u8; 6] = [0xff; 6];
    pub const V4_A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    pub const V4_B: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 11);

    pub fn v6(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, last)
    }
    pub fn ll(last: u16) -> Ipv6Addr {
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last)
    }
    /// Solicited-node multicast for `a`.
    pub fn snm(a: Ipv6Addr) -> Ipv6Addr {
        let o = a.octets();
        Ipv6Addr::new(
            0xff02,
            0,
            0,
            0,
            0,
            1,
            0xff00 | u16::from(o[13]),
            u16::from_be_bytes([o[14], o[15]]),
        )
    }

    pub fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16) -> Vec<u8> {
        let mut f = Vec::with_capacity(64);
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f
    }

    /// ARP with independently settable Ethernet source and sha.
    pub fn arp(
        eth_src: [u8; 6],
        op: u16,
        sha: [u8; 6],
        spa: Ipv4Addr,
        tha: [u8; 6],
        tpa: Ipv4Addr,
    ) -> Vec<u8> {
        let dst = if op == 1 { BCAST } else { tha };
        let mut f = eth(dst, eth_src, 0x0806);
        f.extend_from_slice(&1u16.to_be_bytes());
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        f.push(6);
        f.push(4);
        f.extend_from_slice(&op.to_be_bytes());
        f.extend_from_slice(&sha);
        f.extend_from_slice(&spa.octets());
        f.extend_from_slice(&tha);
        f.extend_from_slice(&tpa.octets());
        f
    }

    pub fn arp_request(src: [u8; 6], spa: Ipv4Addr, tpa: Ipv4Addr) -> Vec<u8> {
        arp(src, 1, src, spa, [0; 6], tpa)
    }

    /// IPv6 + ICMPv6 skeleton; `body` is everything after the 4-byte
    /// ICMPv6 header. Checksum left zero (not validated). One argument
    /// per header field the tests need to vary, on purpose.
    #[allow(clippy::too_many_arguments)]
    pub fn icmp6(
        eth_src: [u8; 6],
        eth_dst: [u8; 6],
        src: Ipv6Addr,
        dst: Ipv6Addr,
        hop_limit: u8,
        nexthdr: u8,
        icmp_type: u8,
        code: u8,
        body: &[u8],
    ) -> Vec<u8> {
        let mut f = eth(eth_dst, eth_src, 0x86dd);
        f.extend_from_slice(&[0x60, 0, 0, 0]);
        let payload_len = (4 + body.len()) as u16;
        f.extend_from_slice(&payload_len.to_be_bytes());
        f.push(nexthdr);
        f.push(hop_limit);
        f.extend_from_slice(&src.octets());
        f.extend_from_slice(&dst.octets());
        f.push(icmp_type);
        f.push(code);
        f.extend_from_slice(&[0, 0]);
        f.extend_from_slice(body);
        f
    }

    pub fn ll_option(t: u8, mac: [u8; 6]) -> Vec<u8> {
        let mut o = vec![t, 1];
        o.extend_from_slice(&mac);
        o
    }

    /// NS for `target` from `src` with the given raw options.
    pub fn ns(src_mac: [u8; 6], src: Ipv6Addr, target: Ipv6Addr, options: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0, 0, 0];
        body.extend_from_slice(&target.octets());
        body.extend_from_slice(options);
        let mut dst_mac = [0x33, 0x33, 0, 0, 0, 0];
        dst_mac[2..].copy_from_slice(&snm(target).octets()[12..]);
        icmp6(src_mac, dst_mac, src, snm(target), 255, 58, 135, 0, &body)
    }

    pub fn ns_with_sllao(src_mac: [u8; 6], src: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
        ns(src_mac, src, target, &ll_option(1, src_mac))
    }

    /// Unsolicited NA to all-nodes for `target` from `src`.
    pub fn na(src_mac: [u8; 6], src: Ipv6Addr, target: Ipv6Addr, options: &[u8]) -> Vec<u8> {
        let mut body = vec![0x20, 0, 0, 0]; // Override flag
        body.extend_from_slice(&target.octets());
        body.extend_from_slice(options);
        let all_nodes = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        icmp6(
            src_mac,
            [0x33, 0x33, 0, 0, 0, 1],
            src,
            all_nodes,
            255,
            58,
            136,
            0,
            &body,
        )
    }

    pub fn na_with_tllao(src_mac: [u8; 6], src: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
        na(src_mac, src, target, &ll_option(2, src_mac))
    }

    /// An IPv6 TCP SYN-shaped frame (not ND) for negative tests.
    pub fn ip6_tcp(src_mac: [u8; 6]) -> Vec<u8> {
        let mut f = eth(MAC_B, src_mac, 0x86dd);
        f.extend_from_slice(&[0x60, 0, 0, 0, 0, 20, 6, 64]);
        f.extend_from_slice(&v6(1).octets());
        f.extend_from_slice(&v6(2).octets());
        f.extend_from_slice(&[0u8; 20]);
        f
    }

    pub fn insert_vlan_tag(frame: &[u8], vid: u16) -> Vec<u8> {
        let mut f = frame[..12].to_vec();
        f.extend_from_slice(&0x8100u16.to_be_bytes());
        f.extend_from_slice(&vid.to_be_bytes());
        f.extend_from_slice(&frame[12..]);
        f
    }

    pub fn pad_to(mut f: Vec<u8>, len: usize) -> Vec<u8> {
        while f.len() < len {
            f.push(0);
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::testframes::*;
    use super::*;

    fn one(f: &[u8]) -> Learned {
        let v = parse_frame(f).expect("parses");
        assert_eq!(v.len(), 1, "expected one pair, got {v:?}");
        v[0]
    }

    #[test]
    fn arp_request_learns_sender() {
        let l = one(&arp_request(MAC_A, V4_A, V4_B));
        assert_eq!(l.ip, IpAddr::V4(V4_A));
        assert_eq!(l.mac, MAC_A);
        assert_eq!(l.source, Source::ArpRequest);
    }

    #[test]
    fn gratuitous_arp_is_a_request() {
        let l = one(&arp_request(MAC_A, V4_A, V4_A));
        assert_eq!(l.ip, IpAddr::V4(V4_A));
        assert_eq!(l.source, Source::ArpRequest);
    }

    #[test]
    fn arp_reply_learns_sender() {
        let l = one(&arp(MAC_A, 2, MAC_A, V4_A, MAC_B, V4_B));
        assert_eq!(l.mac, MAC_A);
        assert_eq!(l.source, Source::ArpReply);
    }

    #[test]
    fn arp_sha_must_match_ethernet_source() {
        let f = arp(MAC_A, 1, MAC_B, V4_A, [0; 6], V4_B);
        assert_eq!(parse_frame(&f), Err(Reject::ShaMismatch));
    }

    #[test]
    fn arp_header_field_refusals() {
        let mut f = arp_request(MAC_A, V4_A, V4_B);
        f[15] = 6;
        assert_eq!(parse_frame(&f), Err(Reject::ArpHtype(6)));
        let mut f = arp_request(MAC_A, V4_A, V4_B);
        f[16..18].copy_from_slice(&0x86ddu16.to_be_bytes());
        assert_eq!(parse_frame(&f), Err(Reject::ArpPtype(0x86dd)));
        let mut f = arp_request(MAC_A, V4_A, V4_B);
        f[18] = 8;
        assert_eq!(parse_frame(&f), Err(Reject::ArpLens(8, 4)));
        let mut f = arp_request(MAC_A, V4_A, V4_B);
        f[21] = 3;
        assert_eq!(parse_frame(&f), Err(Reject::ArpOp(3)));
    }

    #[test]
    fn arp_sender_mac_classes_are_refused() {
        for (mac, class) in [
            ([0u8; 6], MacClass::Zero),
            ([0xff; 6], MacClass::Broadcast),
            ([0x01, 0x00, 0x5e, 0, 0, 1], MacClass::Multicast),
        ] {
            let f = arp(mac, 1, mac, V4_A, [0; 6], V4_B);
            assert_eq!(parse_frame(&f), Err(Reject::SenderMac(class)), "{mac:?}");
        }
    }

    #[test]
    fn padded_and_oversized_arp_parse() {
        let f = pad_to(arp_request(MAC_A, V4_A, V4_B), 60);
        assert_eq!(one(&f).ip, IpAddr::V4(V4_A));
        let f = pad_to(arp_request(MAC_A, V4_A, V4_B), 1500);
        assert_eq!(one(&f).ip, IpAddr::V4(V4_A));
    }

    #[test]
    fn vlan_tagged_is_refused() {
        let f = insert_vlan_tag(&arp_request(MAC_A, V4_A, V4_B), 100);
        assert_eq!(parse_frame(&f), Err(Reject::VlanTagged));
    }

    #[test]
    fn foreign_ethertype_is_refused() {
        let mut f = arp_request(MAC_A, V4_A, V4_B);
        f[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert_eq!(parse_frame(&f), Err(Reject::EtherType(0x0800)));
    }

    #[test]
    fn ns_with_sllao_learns_source() {
        let l = one(&ns_with_sllao(MAC_A, v6(0x10), v6(0x20)));
        assert_eq!(l.ip, IpAddr::V6(v6(0x10)));
        assert_eq!(l.mac, MAC_A);
        assert_eq!(l.source, Source::NeighborSolicitation);
    }

    #[test]
    fn ns_from_unspecified_is_dad() {
        let f = ns_with_sllao(MAC_A, Ipv6Addr::UNSPECIFIED, v6(0x20));
        assert_eq!(parse_frame(&f), Err(Reject::DadSource));
    }

    #[test]
    fn ns_without_option_is_refused() {
        let f = ns(MAC_A, v6(0x10), v6(0x20), &[]);
        assert_eq!(parse_frame(&f), Err(Reject::NoLinkLayerOption));
        // A TLLAO on an NS is not an SLLAO.
        let f = ns(MAC_A, v6(0x10), v6(0x20), &ll_option(2, MAC_A));
        assert_eq!(parse_frame(&f), Err(Reject::NoLinkLayerOption));
    }

    #[test]
    fn na_with_tllao_learns_target() {
        let l = one(&na_with_tllao(MAC_A, v6(0x10), v6(0x10)));
        assert_eq!(l.ip, IpAddr::V6(v6(0x10)));
        assert_eq!(l.mac, MAC_A);
        assert_eq!(l.source, Source::NeighborAdvertisement);
    }

    #[test]
    fn na_from_global_source_other_than_target_learns_only_target() {
        let v = parse_frame(&na_with_tllao(MAC_A, v6(0x11), v6(0x10))).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].ip, IpAddr::V6(v6(0x10)));
    }

    #[test]
    fn na_from_link_local_source_learns_two_pairs() {
        let v = parse_frame(&na_with_tllao(MAC_A, ll(0x10), v6(0x10))).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].ip, IpAddr::V6(v6(0x10)));
        assert_eq!(v[1].ip, IpAddr::V6(ll(0x10)));
        assert!(v.iter().all(|l| l.mac == MAC_A));
    }

    #[test]
    fn na_option_walk_skips_other_options() {
        // Nonce option (type 14, len 1) first, then the TLLAO.
        let mut opts = vec![14, 1, 1, 2, 3, 4, 5, 6];
        opts.extend(ll_option(2, MAC_A));
        let v = parse_frame(&na(MAC_A, v6(0x10), v6(0x10), &opts)).unwrap();
        assert_eq!(v[0].mac, MAC_A);
    }

    #[test]
    fn option_walk_ends_on_zero_length() {
        let mut opts = vec![14, 0, 1, 2, 3, 4, 5, 6];
        opts.extend(ll_option(2, MAC_A));
        let f = na(MAC_A, v6(0x10), v6(0x10), &opts);
        assert_eq!(parse_frame(&f), Err(Reject::NoLinkLayerOption));
    }

    #[test]
    fn option_running_past_frame_is_truncated() {
        let opts = [2, 2, 1, 2, 3, 4, 5, 6]; // claims 16 bytes, has 8
        let f = na(MAC_A, v6(0x10), v6(0x10), &opts);
        assert_eq!(parse_frame(&f), Err(Reject::Truncated("opt")));
    }

    #[test]
    fn ll_option_with_wrong_length_is_refused() {
        let opts = [2, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
        let f = na(MAC_A, v6(0x10), v6(0x10), &opts);
        assert_eq!(parse_frame(&f), Err(Reject::OptionBadLen));
    }

    #[test]
    fn nd_header_refusals() {
        let body = {
            let mut b = vec![0, 0, 0, 0];
            b.extend_from_slice(&v6(0x20).octets());
            b.extend(ll_option(1, MAC_A));
            b
        };
        let hop64 = icmp6(MAC_A, MAC_B, v6(0x10), snm(v6(0x20)), 64, 58, 135, 0, &body);
        assert_eq!(parse_frame(&hop64), Err(Reject::Ip6HopLimit(64)));
        let hbh = icmp6(MAC_A, MAC_B, v6(0x10), snm(v6(0x20)), 255, 0, 135, 0, &body);
        assert_eq!(parse_frame(&hbh), Err(Reject::Ip6NextHeader(0)));
        let echo = icmp6(MAC_A, MAC_B, v6(0x10), v6(0x20), 255, 58, 128, 0, &body);
        assert_eq!(parse_frame(&echo), Err(Reject::Icmp6Type(128)));
        let code = icmp6(
            MAC_A,
            MAC_B,
            v6(0x10),
            snm(v6(0x20)),
            255,
            58,
            135,
            1,
            &body,
        );
        assert_eq!(parse_frame(&code), Err(Reject::Icmp6Code(1)));
        let mut v4 = ns_with_sllao(MAC_A, v6(0x10), v6(0x20));
        v4[14] = 0x45;
        assert_eq!(parse_frame(&v4), Err(Reject::Ip6Version(4)));
        assert_eq!(parse_frame(&ip6_tcp(MAC_A)), Err(Reject::Ip6NextHeader(6)));
    }

    #[test]
    fn nd_sender_mac_classes_are_refused() {
        let f = ns(MAC_A, v6(0x10), v6(0x20), &ll_option(1, [0xff; 6]));
        assert_eq!(parse_frame(&f), Err(Reject::SenderMac(MacClass::Broadcast)));
        let f = na(MAC_A, v6(0x10), v6(0x10), &ll_option(2, [0; 6]));
        assert_eq!(parse_frame(&f), Err(Reject::SenderMac(MacClass::Zero)));
    }

    #[test]
    fn truncation_at_every_boundary() {
        let arp_f = arp_request(MAC_A, V4_A, V4_B);
        assert_eq!(parse_frame(&arp_f[..13]), Err(Reject::Truncated("eth")));
        assert_eq!(parse_frame(&arp_f[..41]), Err(Reject::Truncated("arp")));
        let ns_f = ns_with_sllao(MAC_A, v6(0x10), v6(0x20));
        assert_eq!(parse_frame(&ns_f[..21]), Err(Reject::Truncated("ip6")));
        assert_eq!(parse_frame(&ns_f[..53]), Err(Reject::Truncated("ip6")));
        assert_eq!(parse_frame(&ns_f[..57]), Err(Reject::Truncated("icmp6")));
        assert_eq!(parse_frame(&ns_f[..61]), Err(Reject::Truncated("ns")));
        assert_eq!(parse_frame(&ns_f[..77]), Err(Reject::Truncated("ns")));
        let na_f = na_with_tllao(MAC_A, v6(0x10), v6(0x10));
        assert_eq!(parse_frame(&na_f[..77]), Err(Reject::Truncated("na")));
    }

    #[test]
    fn labels_are_closed_and_distinct() {
        let mut l = Reject::LABELS.to_vec();
        l.sort_unstable();
        l.dedup();
        assert_eq!(l.len(), Reject::COUNT);
        for (i, s) in Source::LABELS.iter().enumerate() {
            assert_eq!(Source::from_label(s).map(Source::index), Some(i));
        }
        assert_eq!(Source::from_label("bogus"), None);
    }
}
