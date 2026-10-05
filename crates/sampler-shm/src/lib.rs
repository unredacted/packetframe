//! The shared-memory protocol between PacketFrame and its VPP sampler plugin.
//!
//! Both ends link this crate: the plugin (in VPP's process) produces samples
//! and status, PacketFrame consumes them and owns the configuration. Nothing
//! crosses as a VPP API message; everything is files in one directory, a
//! dedicated size-limited tmpfs:
//!
//! - `desired.conf` ([`desired`]): PacketFrame's configuration, replaced
//!   atomically under `desired.lock`, read and never modified by the plugin.
//! - `epoch-<epoch>.shm` ([`layout`], [`ring`], [`status`]): one per VPP run,
//!   created and sized once by the plugin, then shared: a header, a status
//!   snapshot, and one single-producer ring per VPP worker.
//! - `current` ([`current`]): names the epoch file to read, replaced
//!   atomically once that file is fully initialised.
//! - `consumer.lock`: held by the one consumer, across epochs.
//!
//! **Every word in an epoch file is accessed atomically** — header,
//! counters, status and packet bytes alike — so a misbehaving or crashed
//! peer can corrupt values but never cause a data race in the other
//! process. Readers validate everything they decode.
//!
//! The file operations ([`fs`]) are Linux-only; the formats and the
//! lock-free protocols build everywhere, and under `--cfg loom` run against
//! loom's model checker instead of std's atomics (`tests/loom.rs`).

pub mod current;
pub mod desired;
#[cfg(all(target_os = "linux", not(loom)))]
pub mod fs;
pub mod layout;
pub mod ring;
pub mod seqlock;
pub mod status;

/// The atomics every shared word is accessed through: std's, or loom's in a
/// model-checking build.
pub mod sync {
    #[cfg(loom)]
    pub use loom::sync::atomic::{fence, AtomicU64, Ordering};
    #[cfg(not(loom))]
    pub use std::sync::atomic::{fence, AtomicU64, Ordering};
}

/// The sampled traffic class. Only ingress is sampled today; egress and
/// drop are reserved in the layout so adding them moves no offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Ingress = 0,
    Egress = 1,
    Drop = 2,
}

impl Class {
    pub const ALL: [Class; layout::CLASSES] = [Class::Ingress, Class::Egress, Class::Drop];

    pub fn from_index(i: u64) -> Option<Class> {
        Self::ALL.get(usize::try_from(i).ok()?).copied()
    }

    pub fn index(self) -> usize {
        self as usize
    }

    pub fn name(self) -> &'static str {
        match self {
            Class::Ingress => "ingress",
            Class::Egress => "egress",
            Class::Drop => "drop",
        }
    }

    /// This class's bit in a [`Classes`] set.
    pub fn bit(self) -> Classes {
        1 << self.index()
    }
}

/// A set of classes, as a bitmask of [`Class::bit`].
pub type Classes = u64;

/// FNV-1a, 64-bit: the checksum of the text files. It catches a truncated
/// or hand-edited file; the files are replaced by rename, so it never has
/// to catch a torn write.
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// An interface name as VPP prints it (`octeon1/0`,
/// `GigabitEthernet0/8/0.100`): 1 to [`layout::NAME_BYTES`] printable ASCII
/// bytes, no spaces.
pub fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= layout::NAME_BYTES
        && name.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a64_matches_reference_vectors() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
    }

    #[test]
    fn interface_names() {
        assert!(valid_interface_name("octeon1/0"));
        assert!(valid_interface_name("GigabitEthernet0/8/0.100"));
        assert!(!valid_interface_name(""));
        assert!(!valid_interface_name("eth 0"));
        assert!(!valid_interface_name(&"x".repeat(layout::NAME_BYTES + 1)));
        assert!(!valid_interface_name("ethé"));
    }

    #[test]
    fn classes_round_trip() {
        for c in Class::ALL {
            assert_eq!(Class::from_index(c.index() as u64), Some(c));
        }
        assert_eq!(Class::from_index(3), None);
    }
}
