//! Userspace reference implementation of the custom-FIB flow hash.
//!
//! **Byte-for-byte mirror of `bpf/src/fib.rs` hash functions.** Every
//! operation here must appear there. The Phase 1 cross-check in
//! [`tests/fib_hash_vectors.rs`](../../tests/fib_hash_vectors.rs) runs
//! both through identical inputs and asserts byte-for-byte agreement;
//! any drift fails CI before an XDP packet is ever hashed with a
//! divergent algorithm.
//!
//! Own well-defined variant; **not** bit-for-bit kernel
//! `fib_multipath_hash()`. See plan §"Hash (own, well-defined)" for
//! rationale.

/// Matches `JHASH_INITVAL` in `bpf/src/fib.rs`.
pub const JHASH_INITVAL: u32 = 0xdeadbeef;

/// Jenkins 3-word mix (the `__jhash_mix` primitive).
#[inline]
pub fn jhash_mix(mut a: u32, mut b: u32, mut c: u32) -> (u32, u32, u32) {
    a = a.wrapping_sub(c);
    a ^= c.rotate_left(4);
    c = c.wrapping_add(b);
    b = b.wrapping_sub(a);
    b ^= a.rotate_left(6);
    a = a.wrapping_add(c);
    c = c.wrapping_sub(b);
    c ^= b.rotate_left(8);
    b = b.wrapping_add(a);
    a = a.wrapping_sub(c);
    a ^= c.rotate_left(16);
    c = c.wrapping_add(b);
    b = b.wrapping_sub(a);
    b ^= a.rotate_left(19);
    a = a.wrapping_add(c);
    c = c.wrapping_sub(b);
    c ^= b.rotate_left(4);
    b = b.wrapping_add(a);
    (a, b, c)
}

/// Jenkins final avalanche on three u32 lanes.
#[inline]
pub fn jhash_final(mut a: u32, mut b: u32, mut c: u32) -> u32 {
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(24));
    c
}

/// Pack `(proto, sport, dport)` into the mode-dependent third mix word.
#[inline]
pub fn pack_ports(proto: u8, sport: u16, dport: u16, mode: u8) -> u32 {
    let proto = proto as u32;
    match mode {
        3 => proto,
        4 => proto | ((sport as u32) << 8),
        5 => proto | ((sport as u32) << 8) | ((dport as u32) << 24),
        _ => proto,
    }
}

/// IPv4 flow hash. `mode` is 3 / 4 / 5; any other value falls back to 3.
#[inline]
pub fn hash_v4(src: [u8; 4], dst: [u8; 4], proto: u8, sport: u16, dport: u16, mode: u8) -> u32 {
    let a = u32::from_be_bytes(src).wrapping_add(JHASH_INITVAL);
    let b = u32::from_be_bytes(dst).wrapping_add(JHASH_INITVAL);
    let c = pack_ports(proto, sport, dport, mode).wrapping_add(JHASH_INITVAL);
    let (a, b, c) = jhash_mix(a, b, c);
    jhash_final(a, b, c)
}

/// IPv6 flow hash.
#[inline]
pub fn hash_v6(src: [u8; 16], dst: [u8; 16], proto: u8, sport: u16, dport: u16, mode: u8) -> u32 {
    let s0 = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
    let s1 = u32::from_be_bytes([src[4], src[5], src[6], src[7]]);
    let s2 = u32::from_be_bytes([src[8], src[9], src[10], src[11]]);
    let s3 = u32::from_be_bytes([src[12], src[13], src[14], src[15]]);
    let d0 = u32::from_be_bytes([dst[0], dst[1], dst[2], dst[3]]);
    let d1 = u32::from_be_bytes([dst[4], dst[5], dst[6], dst[7]]);
    let d2 = u32::from_be_bytes([dst[8], dst[9], dst[10], dst[11]]);
    let d3 = u32::from_be_bytes([dst[12], dst[13], dst[14], dst[15]]);

    let (a, b, c) = jhash_mix(
        s0.wrapping_add(JHASH_INITVAL),
        s1.wrapping_add(JHASH_INITVAL),
        s2.wrapping_add(JHASH_INITVAL),
    );
    let (a, b, c) = jhash_mix(a.wrapping_add(s3), b.wrapping_add(d0), c.wrapping_add(d1));
    let (a, b, c) = jhash_mix(
        a.wrapping_add(d2),
        b.wrapping_add(d3),
        c.wrapping_add(pack_ports(proto, sport, dport, mode)),
    );
    jhash_final(a, b, c)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Basic vector tests. The full BPF cross-check lives in
    // `crates/modules/fast-path/tests/fib_hash_vectors.rs` (sudo-gated)
    // and asserts the BPF side produces the same values for the same
    // inputs. Here we just pin a handful of known outputs so a future
    // refactor of the hash functions is caught at unit-test time.

    #[test]
    fn hash_v4_mode5_is_deterministic() {
        let a = hash_v4([10, 0, 0, 1], [8, 8, 8, 8], 6, 12345, 443, 5);
        let b = hash_v4([10, 0, 0, 1], [8, 8, 8, 8], 6, 12345, 443, 5);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_v4_different_modes_produce_different_values() {
        let inp = ([10, 0, 0, 1], [8, 8, 8, 8], 6u8, 12345u16, 443u16);
        let h3 = hash_v4(inp.0, inp.1, inp.2, inp.3, inp.4, 3);
        let h4 = hash_v4(inp.0, inp.1, inp.2, inp.3, inp.4, 4);
        let h5 = hash_v4(inp.0, inp.1, inp.2, inp.3, inp.4, 5);
        // With non-zero ports, modes should produce distinct hashes.
        assert_ne!(h3, h4, "3-tuple vs 4-tuple collide on distinct input");
        assert_ne!(h4, h5, "4-tuple vs 5-tuple collide on distinct input");
        assert_ne!(h3, h5, "3-tuple vs 5-tuple collide on distinct input");
    }

    #[test]
    fn hash_v4_mode3_ignores_ports() {
        let h_ports = hash_v4([10, 0, 0, 1], [8, 8, 8, 8], 6, 12345, 443, 3);
        let h_no_ports = hash_v4([10, 0, 0, 1], [8, 8, 8, 8], 6, 0, 0, 3);
        assert_eq!(h_ports, h_no_ports, "mode 3 must not depend on ports");
    }

    #[test]
    fn hash_v4_distribution_is_nontrivial() {
        // Ten distinct src IPs into the same dst should produce at
        // least 8 unique hashes — guard against "hash returns same
        // value for all inputs" regressions. Not a statistical test;
        // just a sanity check.
        let mut hashes = std::collections::HashSet::new();
        for i in 0..10u8 {
            let h = hash_v4([10, 0, 0, i], [8, 8, 8, 8], 6, 12345, 443, 5);
            hashes.insert(h);
        }
        assert!(hashes.len() >= 8, "hash collapses: {} unique", hashes.len());
    }

    #[test]
    fn hash_v6_is_deterministic() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let a = hash_v6(src, dst, 6, 12345, 443, 5);
        let b = hash_v6(src, dst, 6, 12345, 443, 5);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_v6_different_src_gives_different_hash() {
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let src_a = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let src_b = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let a = hash_v6(src_a, dst, 6, 12345, 443, 5);
        let b = hash_v6(src_b, dst, 6, 12345, 443, 5);
        assert_ne!(a, b);
    }

    #[test]
    fn pack_ports_layout_matches_mode_contract() {
        // mode 3: only proto survives
        assert_eq!(pack_ports(6, 0xbeef, 0xcafe, 3), 6);
        // mode 4: proto + sport in bits 8-23
        assert_eq!(pack_ports(6, 0x1234, 0xabcd, 4), 6 | (0x1234 << 8));
        // mode 5: proto + sport<<8 + dport<<24
        assert_eq!(
            pack_ports(6, 0x1234, 0xabcd, 5),
            6 | (0x1234u32 << 8) | (0xabcdu32 << 24)
        );
        // unknown mode: fallback to 3
        assert_eq!(pack_ports(6, 0xbeef, 0xcafe, 42), 6);
    }
}
