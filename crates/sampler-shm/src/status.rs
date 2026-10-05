//! The plugin's status: a heartbeat, and a seqlocked snapshot of what it
//! has applied.
//!
//! The heartbeat is a lone word the plugin's main thread stores every
//! 100 ms whether or not packets flow (CLOCK_MONOTONIC nanoseconds), so a
//! stale heartbeat means the plugin or VPP has stopped, never that traffic
//! has. Everything else changes rarely and is read as one snapshot.

use crate::layout::{get_text_from, put_text_into, LINE_WORDS, MAX_INTERFACES, NAME_BYTES, WORD};
use crate::sync::{AtomicU64, Ordering};
use crate::{seqlock, valid_interface_name, Classes};

const HEARTBEAT: usize = 0;
const SEQ: usize = LINE_WORDS;
const PAYLOAD: usize = SEQ + 1;

mod w {
    pub const STATE: usize = 0;
    pub const REASON: usize = 1;
    pub const APPLIED_GENERATION: usize = 2;
    pub const REJECTED_GENERATION: usize = 3;
    pub const REJECTED_REASON: usize = 4;
    pub const REJECTED_LINE: usize = 5;
    pub const RATE: usize = 6;
    pub const HEADER_BYTES: usize = 7;
    pub const CLASSES: usize = 8;
    pub const INTERFACES: usize = 9;
    pub const CHANGED_NS: usize = 10;
    pub const FIXED: usize = 16;
}

const NAME_WORDS: usize = NAME_BYTES / WORD;
/// Name, then `sw_if_index | resolved << 32 | pool_index << 40`, then
/// unresolved-since.
const IFACE_WORDS: usize = NAME_WORDS + 2;
const RESOLVED: u64 = 1 << 32;

pub const PAYLOAD_WORDS: usize = w::FIXED + MAX_INTERFACES * IFACE_WORDS;
/// Words the status region occupies in an epoch file.
pub const REGION_WORDS: usize = PAYLOAD + PAYLOAD_WORDS;

/// Snapshot attempts before a reader reports the status unreadable. A
/// write takes about a microsecond, so exhausting these means the writer
/// stopped mid-write.
pub const READ_TRIES: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum State {
    /// The file exists but no configuration has been considered yet.
    #[default]
    Initializing = 1,
    /// A valid configuration is applied and lists at least one interface.
    Enabled = 2,
    /// Nothing is sampled; [`Status::reason`] says why.
    Disabled = 3,
}

impl State {
    fn from_word(v: u64) -> Option<Self> {
        match v {
            1 => Some(State::Initializing),
            2 => Some(State::Enabled),
            3 => Some(State::Disabled),
            _ => None,
        }
    }
}

/// Why the plugin is [`State::Disabled`].
pub mod reason {
    pub const NONE: u64 = 0;
    /// There is no `desired.conf`.
    pub const NO_CONFIG: u64 = 1;
    /// `desired.conf` exists but no version of it has ever been valid.
    pub const NO_VALID_CONFIG: u64 = 2;
    /// The applied configuration lists no interfaces.
    pub const NO_INTERFACES: u64 = 3;

    pub fn describe(code: u64) -> &'static str {
        match code {
            NONE => "none",
            NO_CONFIG => "no desired.conf",
            NO_VALID_CONFIG => "no valid desired.conf yet",
            NO_INTERFACES => "the configuration lists no interfaces",
            _ => "unknown reason",
        }
    }
}

/// One configured interface, by the name the configuration gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    /// `None` while VPP has no interface by that name.
    pub sw_if_index: Option<u32>,
    /// Where its sample pool is counted in every ring, and what its samples
    /// carry ([`crate::ring::SampleMeta::pool_index`]). The plugin keeps it
    /// for as long as the interface stays configured in this epoch.
    pub pool_index: u8,
    /// Realtime nanoseconds since when it has been unresolved; 0 when
    /// resolved.
    pub unresolved_since_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Status {
    pub state: State,
    pub reason: u64,
    /// The generation of the configuration in force: published to the
    /// workers under VPP's barrier, so every worker uses it from its next
    /// frame. A worker that has seen no frame since is idle, not stale.
    pub applied_generation: u64,
    /// The newest generation refused, 0 if none; with why
    /// ([`crate::desired::ErrorKind::code`]) and the line it was found on.
    pub rejected_generation: u64,
    pub rejected_reason: u64,
    pub rejected_line: u64,
    pub rate: u32,
    pub header_bytes: u32,
    pub classes: Classes,
    /// Realtime nanoseconds of the last change to any of the above.
    pub changed_ns: u64,
    pub interfaces: Vec<Interface>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatusError {
    #[error("status unreadable: the writer never finished a snapshot")]
    Unreadable,
    #[error("status invalid: {0}")]
    Invalid(&'static str),
}

impl Status {
    /// The snapshot as payload words. Interfaces beyond
    /// [`MAX_INTERFACES`] are dropped (a valid configuration has no more).
    pub fn encode(&self) -> Vec<u64> {
        let mut v = vec![0u64; PAYLOAD_WORDS];
        v[w::STATE] = self.state as u64;
        v[w::REASON] = self.reason;
        v[w::APPLIED_GENERATION] = self.applied_generation;
        v[w::REJECTED_GENERATION] = self.rejected_generation;
        v[w::REJECTED_REASON] = self.rejected_reason;
        v[w::REJECTED_LINE] = self.rejected_line;
        v[w::RATE] = u64::from(self.rate);
        v[w::HEADER_BYTES] = u64::from(self.header_bytes);
        v[w::CLASSES] = self.classes;
        v[w::CHANGED_NS] = self.changed_ns;
        let n = self.interfaces.len().min(MAX_INTERFACES);
        v[w::INTERFACES] = n as u64;
        for (i, f) in self.interfaces[..n].iter().enumerate() {
            let at = w::FIXED + i * IFACE_WORDS;
            put_text_into(&mut v[at..at + NAME_WORDS], &f.name);
            v[at + NAME_WORDS] = u64::from(f.pool_index) << 40
                | match f.sw_if_index {
                    Some(i) => RESOLVED | u64::from(i),
                    None => 0,
                };
            v[at + NAME_WORDS + 1] = f.unresolved_since_ns;
        }
        v
    }

    pub fn decode(v: &[u64]) -> Result<Self, StatusError> {
        if v.len() != PAYLOAD_WORDS {
            return Err(StatusError::Invalid("payload length"));
        }
        let state = State::from_word(v[w::STATE]).ok_or(StatusError::Invalid("state"))?;
        let n = usize::try_from(v[w::INTERFACES]).unwrap_or(usize::MAX);
        if n > MAX_INTERFACES {
            return Err(StatusError::Invalid("interface count"));
        }
        let small = |i: usize, what| u32::try_from(v[i]).map_err(|_| StatusError::Invalid(what));
        let mut interfaces = Vec::with_capacity(n);
        for i in 0..n {
            let at = w::FIXED + i * IFACE_WORDS;
            let name = get_text_from(&v[at..at + NAME_WORDS]);
            if !valid_interface_name(&name) {
                return Err(StatusError::Invalid("interface name"));
            }
            let idx = v[at + NAME_WORDS];
            let pool_index = (idx >> 40) as u8;
            if usize::from(pool_index) >= MAX_INTERFACES || idx >> 48 != 0 {
                return Err(StatusError::Invalid("pool index"));
            }
            interfaces.push(Interface {
                name,
                sw_if_index: (idx & RESOLVED != 0).then_some(idx as u32),
                pool_index,
                unresolved_since_ns: v[at + NAME_WORDS + 1],
            });
        }
        Ok(Self {
            state,
            reason: v[w::REASON],
            applied_generation: v[w::APPLIED_GENERATION],
            rejected_generation: v[w::REJECTED_GENERATION],
            rejected_reason: v[w::REJECTED_REASON],
            rejected_line: v[w::REJECTED_LINE],
            rate: small(w::RATE, "rate")?,
            header_bytes: small(w::HEADER_BYTES, "header bytes")?,
            classes: v[w::CLASSES],
            changed_ns: v[w::CHANGED_NS],
            interfaces,
        })
    }
}

/// The plugin's side: one writer, its main thread.
pub struct StatusWriter<'a> {
    region: &'a [AtomicU64],
}

impl<'a> StatusWriter<'a> {
    /// `region` is [`crate::layout::Layout::status`] of the file.
    pub fn new(region: &'a [AtomicU64]) -> Self {
        assert_eq!(region.len(), REGION_WORDS);
        Self { region }
    }

    pub fn publish(&self, s: &Status) {
        seqlock::write(&self.region[SEQ], &self.region[PAYLOAD..], &s.encode());
    }

    pub fn beat(&self, monotonic_ns: u64) {
        self.region[HEARTBEAT].store(monotonic_ns, Ordering::Release);
    }
}

/// A reader's side; any number of them.
pub struct StatusReader<'a> {
    region: &'a [AtomicU64],
}

impl<'a> StatusReader<'a> {
    pub fn new(region: &'a [AtomicU64]) -> Self {
        assert_eq!(region.len(), REGION_WORDS);
        Self { region }
    }

    pub fn read(&self) -> Result<Status, StatusError> {
        let mut v = vec![0u64; PAYLOAD_WORDS];
        if !seqlock::read(
            &self.region[SEQ],
            &self.region[PAYLOAD..],
            &mut v,
            READ_TRIES,
        ) {
            return Err(StatusError::Unreadable);
        }
        Status::decode(&v)
    }

    /// CLOCK_MONOTONIC nanoseconds of the last beat; 0 before the first.
    pub fn heartbeat(&self) -> u64 {
        self.region[HEARTBEAT].load(Ordering::Acquire)
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;
    use crate::layout::words;
    use crate::Class;

    fn sample() -> Status {
        Status {
            state: State::Enabled,
            reason: reason::NONE,
            applied_generation: 7,
            rejected_generation: 8,
            rejected_reason: 2,
            rejected_line: 5,
            rate: 1000,
            header_bytes: 128,
            classes: Class::Ingress.bit(),
            changed_ns: 1_790_000_000_000_000_000,
            interfaces: vec![
                Interface {
                    name: "octeon1/0".into(),
                    sw_if_index: Some(3),
                    pool_index: 0,
                    unresolved_since_ns: 0,
                },
                Interface {
                    name: "x".repeat(NAME_BYTES),
                    sw_if_index: None,
                    pool_index: 5,
                    unresolved_since_ns: 99,
                },
                Interface {
                    name: "pg0".into(),
                    sw_if_index: Some(0),
                    pool_index: 63,
                    unresolved_since_ns: 0,
                },
            ],
        }
    }

    #[test]
    fn snapshots_round_trip_through_the_region() {
        let r = words(REGION_WORDS);
        let reader = StatusReader::new(&r);
        assert_eq!(reader.read(), Err(StatusError::Unreadable), "never written");
        assert_eq!(reader.heartbeat(), 0);
        let writer = StatusWriter::new(&r);
        writer.publish(&sample());
        writer.beat(12345);
        assert_eq!(reader.read().unwrap(), sample());
        assert_eq!(reader.heartbeat(), 12345);
    }

    #[test]
    fn invalid_snapshots_are_refused() {
        let mut v = sample().encode();
        v[w::STATE] = 9;
        assert_eq!(Status::decode(&v), Err(StatusError::Invalid("state")));
        let mut v = sample().encode();
        v[w::INTERFACES] = MAX_INTERFACES as u64 + 1;
        assert_eq!(
            Status::decode(&v),
            Err(StatusError::Invalid("interface count"))
        );
        let mut v = sample().encode();
        v[w::FIXED] = 0; // first name now starts with NUL: empty
        assert_eq!(
            Status::decode(&v),
            Err(StatusError::Invalid("interface name"))
        );
        let mut v = sample().encode();
        v[w::FIXED + NAME_WORDS] = 64 << 40;
        assert_eq!(Status::decode(&v), Err(StatusError::Invalid("pool index")));
        let mut v = sample().encode();
        v[w::RATE] = u64::MAX;
        assert_eq!(Status::decode(&v), Err(StatusError::Invalid("rate")));
    }
}
