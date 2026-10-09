//! Origin ASNs by prefix: what flow export fills a flow record's AS
//! fields from. The FibProgrammer publishes each prefix's origin as it
//! programs the prefix, from the LOCAL_PREF tier its nexthops come from;
//! flow export looks addresses up, longest match first.
//!
//! One hash map per prefix length, so a lookup is at most 33 (or 129)
//! probes and skips every length nothing was published at.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::RwLock;

use super::IpPrefix;

#[derive(Debug)]
struct Tables {
    v4: Vec<HashMap<u32, u32>>,
    v6: Vec<HashMap<u128, u32>>,
}

#[derive(Debug)]
pub struct AsnTable {
    inner: RwLock<Tables>,
}

impl Default for AsnTable {
    fn default() -> Self {
        Self::new()
    }
}

fn mask_v4(a: u32, len: usize) -> u32 {
    if len == 0 {
        0
    } else {
        a & (u32::MAX << (32 - len))
    }
}

fn mask_v6(a: u128, len: usize) -> u128 {
    if len == 0 {
        0
    } else {
        a & (u128::MAX << (128 - len))
    }
}

impl AsnTable {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(Tables {
                v4: vec![HashMap::new(); 33],
                v6: vec![HashMap::new(); 129],
            }),
        }
    }

    /// Set (`Some`) or clear (`None`) a prefix's origin AS.
    pub fn set(&self, prefix: IpPrefix, asn: Option<u32>) {
        let mut t = self.inner.write().unwrap_or_else(|e| e.into_inner());
        match prefix {
            IpPrefix::V4 { addr, prefix_len } => {
                let len = usize::from(prefix_len);
                let Some(m) = t.v4.get_mut(len) else { return };
                let key = mask_v4(u32::from_be_bytes(addr), len);
                match asn {
                    Some(a) => m.insert(key, a),
                    None => m.remove(&key),
                };
            }
            IpPrefix::V6 { addr, prefix_len } => {
                let len = usize::from(prefix_len);
                let Some(m) = t.v6.get_mut(len) else { return };
                let key = mask_v6(u128::from_be_bytes(addr), len);
                match asn {
                    Some(a) => m.insert(key, a),
                    None => m.remove(&key),
                };
            }
        }
    }

    /// The origin AS of the longest prefix holding `ip` that has one.
    pub fn lookup(&self, ip: IpAddr) -> Option<u32> {
        let t = self.inner.read().unwrap_or_else(|e| e.into_inner());
        match ip {
            IpAddr::V4(a) => {
                let a = u32::from(a);
                (0..=32)
                    .rev()
                    .filter(|&len| !t.v4[len].is_empty())
                    .find_map(|len| t.v4[len].get(&mask_v4(a, len)).copied())
            }
            IpAddr::V6(a) => {
                let a = u128::from(a);
                (0..=128)
                    .rev()
                    .filter(|&len| !t.v6[len].is_empty())
                    .find_map(|len| t.v6[len].get(&mask_v6(a, len)).copied())
            }
        }
    }

    /// Prefixes with an origin.
    pub fn len(&self) -> usize {
        let t = self.inner.read().unwrap_or_else(|e| e.into_inner());
        t.v4.iter().map(HashMap::len).sum::<usize>() + t.v6.iter().map(HashMap::len).sum::<usize>()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: [u8; 4], len: u8) -> IpPrefix {
        IpPrefix::V4 {
            addr: a,
            prefix_len: len,
        }
    }

    #[test]
    fn the_longest_prefix_with_an_origin_answers() {
        let t = AsnTable::new();
        t.set(v4([198, 51, 100, 0], 22), Some(64500));
        t.set(v4([198, 51, 100, 0], 24), Some(64501));
        t.set(v4([0, 0, 0, 0], 0), Some(64502));
        let at = |s: &str| t.lookup(s.parse().unwrap());
        assert_eq!(at("198.51.100.9"), Some(64501));
        assert_eq!(at("198.51.101.9"), Some(64500));
        assert_eq!(at("192.0.2.1"), Some(64502), "the default");
        t.set(v4([198, 51, 100, 0], 24), None);
        assert_eq!(
            at("198.51.100.9"),
            Some(64500),
            "withdrawn: the covering one"
        );
        assert_eq!(t.len(), 2);
        assert_eq!(at("2001:db8::1"), None);
    }

    #[test]
    fn v6_and_host_bits_set_in_the_prefix() {
        let t = AsnTable::new();
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        a[15] = 1; // host bits a source may leave set
        t.set(
            IpPrefix::V6 {
                addr: a,
                prefix_len: 32,
            },
            Some(64510),
        );
        assert_eq!(t.lookup("2001:db8:ffff::1".parse().unwrap()), Some(64510));
        assert_eq!(t.lookup("2001:db9::1".parse().unwrap()), None);
        t.set(v4([1, 2, 3, 4], 40), Some(1));
        assert_eq!(t.len(), 1, "an impossible length is ignored");
    }
}
