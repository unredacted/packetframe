//! Read-side inspection helpers for the custom-FIB maps.
//! Powers `packetframe fib dump / lookup / stats`.
//!
//! All functions open the bpffs pins directly so they work
//! without the daemon running — an operator can query the FIB
//! state any time the pins are alive, including after `systemctl
//! stop packetframe` as long as `detach --all` hasn't removed
//! them.
//!
//! **Scope.** These are diagnostic helpers, not a feed path.
//! Building a `Vec<FibEntry>` for `dump` is O(N) in memory on the
//! FIB size; at a ~1M-route default, expect ~200 MB of transient
//! allocation. Acceptable for an ad-hoc operator tool; not
//! suitable for 15 s scrape cadence (use `packetframe status` +
//! counter deltas for that).

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use aya::maps::lpm_trie::Key as LpmKey;

use super::programmer::FibProgrammer;
use super::types::{
    EcmpGroup, FibValue, NexthopEntry, ECMP_NH_UNUSED, FIB_KIND_ECMP, FIB_KIND_SINGLE,
    NH_STATE_FAILED, NH_STATE_INCOMPLETE, NH_STATE_RESOLVED, NH_STATE_STALE,
};

/// One resolved FIB entry: the prefix, what kind of lookup value
/// was stored, and the full nexthop chain (single-entry for
/// `kind=single`, up to `MAX_ECMP_PATHS` for `kind=ecmp`).
#[derive(Debug, Clone)]
pub struct FibEntry {
    pub prefix: IpPrefix,
    pub kind: FibValueKind,
    pub nexthops: Vec<NexthopSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPrefix {
    V4 { addr: Ipv4Addr, prefix_len: u8 },
    V6 { addr: Ipv6Addr, prefix_len: u8 },
}

impl std::fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpPrefix::V4 { addr, prefix_len } => write!(f, "{addr}/{prefix_len}"),
            IpPrefix::V6 { addr, prefix_len } => write!(f, "{addr}/{prefix_len}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FibValueKind {
    Single { nh_id: u32 },
    Ecmp { group_id: u32, hash_mode: u8 },
}

#[derive(Debug, Clone, Copy)]
pub struct NexthopSummary {
    pub id: u32,
    pub state: NexthopState,
    pub family: u8,
    pub ifindex: u32,
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NexthopState {
    Incomplete,
    Resolved,
    Stale,
    Failed,
    Unknown(u8),
}

impl NexthopState {
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            NH_STATE_INCOMPLETE => Self::Incomplete,
            NH_STATE_RESOLVED => Self::Resolved,
            NH_STATE_STALE => Self::Stale,
            NH_STATE_FAILED => Self::Failed,
            other => Self::Unknown(other),
        }
    }
}

impl std::fmt::Display for NexthopState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete => f.write_str("incomplete"),
            Self::Resolved => f.write_str("resolved"),
            Self::Stale => f.write_str("stale"),
            Self::Failed => f.write_str("failed"),
            Self::Unknown(n) => write!(f, "unknown({n})"),
        }
    }
}

/// Walk FIB_V4. Returns one `FibEntry` per prefix with the
/// complete resolved nexthop chain.
pub fn dump_v4(bpffs_root: &Path) -> Result<Vec<FibEntry>, String> {
    let trie = FibProgrammer::open_fib_v4(bpffs_root).map_err(|e| e.to_string())?;
    let nexthops = FibProgrammer::open_nexthops(bpffs_root).map_err(|e| e.to_string())?;
    let ecmp = FibProgrammer::open_ecmp_groups(bpffs_root).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for res in trie.iter() {
        let (key, value) = res.map_err(|e| format!("FIB_V4 iter: {e}"))?;
        let prefix = IpPrefix::V4 {
            addr: Ipv4Addr::from(*key.data()),
            prefix_len: key.prefix_len() as u8,
        };
        out.push(resolve_fib_entry(prefix, value, &nexthops, &ecmp)?);
    }
    Ok(out)
}

/// Walk FIB_V6. Returns one `FibEntry` per prefix.
pub fn dump_v6(bpffs_root: &Path) -> Result<Vec<FibEntry>, String> {
    let trie = FibProgrammer::open_fib_v6(bpffs_root).map_err(|e| e.to_string())?;
    let nexthops = FibProgrammer::open_nexthops(bpffs_root).map_err(|e| e.to_string())?;
    let ecmp = FibProgrammer::open_ecmp_groups(bpffs_root).map_err(|e| e.to_string())?;

    let mut out = Vec::new();
    for res in trie.iter() {
        let (key, value) = res.map_err(|e| format!("FIB_V6 iter: {e}"))?;
        let prefix = IpPrefix::V6 {
            addr: Ipv6Addr::from(*key.data()),
            prefix_len: key.prefix_len() as u8,
        };
        out.push(resolve_fib_entry(prefix, value, &nexthops, &ecmp)?);
    }
    Ok(out)
}

/// LPM-lookup a single IP. `Ok(None)` means the trie is open and
/// readable but has no covering prefix — i.e., the data plane
/// would have XDP_PASS'd this address.
pub fn lookup(bpffs_root: &Path, ip: IpAddr) -> Result<Option<FibEntry>, String> {
    let nexthops = FibProgrammer::open_nexthops(bpffs_root).map_err(|e| e.to_string())?;
    let ecmp = FibProgrammer::open_ecmp_groups(bpffs_root).map_err(|e| e.to_string())?;

    match ip {
        IpAddr::V4(v4) => {
            let trie = FibProgrammer::open_fib_v4(bpffs_root).map_err(|e| e.to_string())?;
            let key = LpmKey::new(32, v4.octets());
            match trie.get(&key, 0) {
                Ok(value) => {
                    let prefix = IpPrefix::V4 {
                        addr: v4,
                        prefix_len: 32,
                    };
                    Ok(Some(resolve_fib_entry(prefix, value, &nexthops, &ecmp)?))
                }
                Err(_) => Ok(None),
            }
        }
        IpAddr::V6(v6) => {
            let trie = FibProgrammer::open_fib_v6(bpffs_root).map_err(|e| e.to_string())?;
            let key = LpmKey::new(128, v6.octets());
            match trie.get(&key, 0) {
                Ok(value) => {
                    let prefix = IpPrefix::V6 {
                        addr: v6,
                        prefix_len: 128,
                    };
                    Ok(Some(resolve_fib_entry(prefix, value, &nexthops, &ecmp)?))
                }
                Err(_) => Ok(None),
            }
        }
    }
}

fn resolve_fib_entry<T>(
    prefix: IpPrefix,
    value: FibValue,
    nexthops: &aya::maps::Array<T, NexthopEntry>,
    ecmp: &aya::maps::Array<T, EcmpGroup>,
) -> Result<FibEntry, String>
where
    T: std::borrow::Borrow<aya::maps::MapData>,
{
    match value.kind {
        FIB_KIND_SINGLE => {
            let nh_id = value.idx;
            let nh = read_nexthop(nexthops, nh_id)?;
            Ok(FibEntry {
                prefix,
                kind: FibValueKind::Single { nh_id },
                nexthops: vec![nh],
            })
        }
        FIB_KIND_ECMP => {
            let group_id = value.idx;
            let group = ecmp
                .get(&group_id, 0)
                .map_err(|e| format!("ECMP_GROUPS[{group_id}]: {e}"))?;
            let mut nhs = Vec::with_capacity(group.nh_count as usize);
            for &slot in group.nh_idx.iter().take(group.nh_count as usize) {
                if slot == ECMP_NH_UNUSED {
                    continue;
                }
                nhs.push(read_nexthop(nexthops, slot)?);
            }
            Ok(FibEntry {
                prefix,
                kind: FibValueKind::Ecmp {
                    group_id,
                    hash_mode: group.hash_mode,
                },
                nexthops: nhs,
            })
        }
        other => Err(format!("unknown FibValue.kind={other}")),
    }
}

fn read_nexthop<T>(
    nexthops: &aya::maps::Array<T, NexthopEntry>,
    id: u32,
) -> Result<NexthopSummary, String>
where
    T: std::borrow::Borrow<aya::maps::MapData>,
{
    let entry = nexthops
        .get(&id, 0)
        .map_err(|e| format!("NEXTHOPS[{id}]: {e}"))?;
    Ok(NexthopSummary {
        id,
        state: NexthopState::from_raw(entry.state),
        family: entry.family,
        ifindex: entry.ifindex,
        dst_mac: entry.dst_mac,
        src_mac: entry.src_mac,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nexthop_state_round_trips() {
        for raw in [
            NH_STATE_INCOMPLETE,
            NH_STATE_RESOLVED,
            NH_STATE_STALE,
            NH_STATE_FAILED,
        ] {
            assert!(!matches!(NexthopState::from_raw(raw), NexthopState::Unknown(_)));
        }
        assert!(matches!(
            NexthopState::from_raw(99),
            NexthopState::Unknown(99)
        ));
    }

    #[test]
    fn prefix_display() {
        let v4 = IpPrefix::V4 {
            addr: Ipv4Addr::new(192, 0, 2, 0),
            prefix_len: 24,
        };
        assert_eq!(format!("{v4}"), "192.0.2.0/24");
        let v6 = IpPrefix::V6 {
            addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
            prefix_len: 32,
        };
        assert_eq!(format!("{v6}"), "2001:db8::/32");
    }
}
