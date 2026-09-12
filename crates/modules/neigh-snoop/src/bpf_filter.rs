//! The classic-BPF socket filter attached to each capture socket
//! **before** it is bound, so no unfiltered frame is ever queued to
//! userspace. The bridge also carries the kernel-path IX traffic (BGP
//! sessions, non-fast-pathed forwarding); without this filter every
//! one of those frames would be copied up.
//!
//! Equivalent tcpdump expression, plus a pkttype guard:
//! `arp or (icmp6 and (ip6[40]==135 or ip6[40]==136))`. Hop-limit and
//! DAD checks stay in userspace so they can be counted by reason.
//!
//! The instruction table is portable (and interpreted in the tests);
//! only attaching it is Linux.

/// `struct sock_filter` layout (`linux/filter.h`): identical to
/// `libc::sock_filter`, defined here so the program is a portable
/// constant.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const fn op(code: u16, jt: u8, jf: u8, k: u32) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

// BPF_LD | BPF_B | BPF_ABS, BPF_LD | BPF_H | BPF_ABS,
// BPF_JMP | BPF_JEQ | BPF_K, BPF_RET | BPF_K.
pub const LDB_ABS: u16 = 0x30;
pub const LDH_ABS: u16 = 0x28;
pub const JEQ_K: u16 = 0x15;
pub const RET_K: u16 = 0x06;

/// `SKF_AD_OFF + SKF_AD_PKTTYPE`: loads `skb->pkt_type`.
pub const SKF_AD_PKTTYPE: u32 = 0xffff_f004;
/// `PACKET_OUTGOING` (`linux/if_packet.h`).
pub const PKTTYPE_OUTGOING: u32 = 4;
pub const ACCEPT: u32 = 0x40000;
pub const DROP: u32 = 0;

/// Frame-relative offsets. For SOCK_RAW packet sockets the filter
/// sees the frame from the Ethernet header.
const OFF_ETHERTYPE: u32 = 12;
const OFF_IP6_NEXTHDR: u32 = 20;
const OFF_ICMP6_TYPE: u32 = 54;

/// Twelve instructions; jump targets are relative to the *next*
/// instruction. Annotated with absolute targets for review.
pub const PROG: [SockFilter; 12] = [
    op(LDB_ABS, 0, 0, SKF_AD_PKTTYPE),  // 0: A = pkt_type
    op(JEQ_K, 9, 0, PKTTYPE_OUTGOING),  // 1: outgoing → 11 (drop)
    op(LDH_ABS, 0, 0, OFF_ETHERTYPE),   // 2: A = ethertype
    op(JEQ_K, 6, 0, 0x0806),            // 3: ARP → 10 (accept)
    op(JEQ_K, 0, 6, 0x86dd),            // 4: not IPv6 → 11 (drop)
    op(LDB_ABS, 0, 0, OFF_IP6_NEXTHDR), // 5: A = next header
    op(JEQ_K, 0, 4, 58),                // 6: not ICMPv6 → 11 (drop)
    op(LDB_ABS, 0, 0, OFF_ICMP6_TYPE),  // 7: A = icmp6 type
    op(JEQ_K, 1, 0, 135),               // 8: NS → 10 (accept)
    op(JEQ_K, 0, 1, 136),               // 9: NA → 10, else → 11
    op(RET_K, 0, 0, ACCEPT),            // 10
    op(RET_K, 0, 0, DROP),              // 11
];

/// The filter verdict for one frame, computed by interpreting [`PROG`]
/// with the same semantics the kernel applies (out-of-range loads
/// terminate with a drop). Used by tests and available to the engine
/// for a belt-and-braces check.
pub fn evaluate(prog: &[SockFilter], frame: &[u8], pkt_type: u8) -> u32 {
    let mut pc = 0usize;
    let mut a: u32 = 0;
    while pc < prog.len() {
        let i = prog[pc];
        match i.code {
            LDB_ABS => {
                if i.k == SKF_AD_PKTTYPE {
                    a = u32::from(pkt_type);
                } else {
                    match frame.get(i.k as usize) {
                        Some(b) => a = u32::from(*b),
                        None => return DROP,
                    }
                }
                pc += 1;
            }
            LDH_ABS => {
                let k = i.k as usize;
                match (frame.get(k), frame.get(k + 1)) {
                    (Some(hi), Some(lo)) => a = u32::from(u16::from_be_bytes([*hi, *lo])),
                    _ => return DROP,
                }
                pc += 1;
            }
            JEQ_K => {
                let off = if a == i.k { i.jt } else { i.jf };
                pc += 1 + usize::from(off);
            }
            RET_K => return i.k,
            _ => return DROP,
        }
    }
    DROP
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::parse_frame;
    use crate::frame::testframes::*;

    const PKT_HOST: u8 = 0;
    const PKT_BROADCAST: u8 = 1;
    const PKT_MULTICAST: u8 = 2;

    #[test]
    fn layout_matches_sock_filter() {
        assert_eq!(std::mem::size_of::<SockFilter>(), 8);
        assert_eq!(std::mem::align_of::<SockFilter>(), 4);
    }

    #[test]
    fn jump_targets_stay_inside_the_program() {
        for (pc, i) in PROG.iter().enumerate() {
            if i.code == JEQ_K {
                assert!(pc + 1 + usize::from(i.jt) < PROG.len(), "jt at {pc}");
                assert!(pc + 1 + usize::from(i.jf) < PROG.len(), "jf at {pc}");
            }
        }
        assert_eq!(PROG[10].k, ACCEPT);
        assert_eq!(PROG[11].k, DROP);
    }

    /// The filter accepts exactly what the parser can learn from.
    #[test]
    fn accepts_every_learnable_frame() {
        let frames = [
            (arp_request(MAC_A, V4_A, V4_B), PKT_BROADCAST),
            (arp(MAC_A, 2, MAC_A, V4_A, MAC_B, V4_B), PKT_HOST),
            (ns_with_sllao(MAC_A, v6(0x10), v6(0x20)), PKT_MULTICAST),
            (na_with_tllao(MAC_A, ll(0x10), v6(0x10)), PKT_MULTICAST),
            (pad_to(arp_request(MAC_A, V4_A, V4_B), 60), PKT_BROADCAST),
        ];
        for (f, t) in frames {
            assert!(parse_frame(&f).is_ok());
            assert_eq!(evaluate(&PROG, &f, t), ACCEPT, "{f:02x?}");
        }
    }

    #[test]
    fn drops_what_the_snooper_never_wants() {
        // Our own transmissions, whatever they are.
        assert_eq!(
            evaluate(
                &PROG,
                &arp_request(MAC_A, V4_A, V4_B),
                PKTTYPE_OUTGOING as u8
            ),
            DROP
        );
        // IPv6 that is not ICMPv6.
        assert_eq!(evaluate(&PROG, &ip6_tcp(MAC_A), PKT_HOST), DROP);
        // ICMPv6 that is not ND.
        let echo = icmp6(MAC_A, MAC_B, v6(1), v6(2), 64, 58, 128, 0, &[0; 8]);
        assert_eq!(evaluate(&PROG, &echo, PKT_HOST), DROP);
        // Router advertisement (134): deliberately not learned from.
        let ra = icmp6(MAC_A, MAC_B, ll(1), v6(2), 255, 58, 134, 0, &[0; 12]);
        assert_eq!(evaluate(&PROG, &ra, PKT_MULTICAST), DROP);
        // IPv4.
        let mut v4 = arp_request(MAC_A, V4_A, V4_B);
        v4[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert_eq!(evaluate(&PROG, &v4, PKT_HOST), DROP);
        // Runt: the load past the end drops.
        assert_eq!(
            evaluate(&PROG, &arp_request(MAC_A, V4_A, V4_B)[..13], PKT_HOST),
            DROP
        );
        // VLAN-tagged reaches userspace (ethertype 0x8100 ≠ ARP/IPv6 →
        // drop), so the parser's VlanTagged reject is defence in depth.
        let tagged = insert_vlan_tag(&arp_request(MAC_A, V4_A, V4_B), 5);
        assert_eq!(evaluate(&PROG, &tagged, PKT_BROADCAST), DROP);
    }
}
